//! `d07_harness_test.go` — one isolated acceptance world per scenario:
//! fixture (or production-tier) roots, a sealed backup, a grant store,
//! the full handler set on a real Unix socket, and the spawned
//! `central` CLI pointed at it through `CENTRAL_HELPER_SOCKET`.
//!
//! Upstream swaps the command package's in-process clients for helper
//! clients; the port instead spawns the real binary, so the grammar,
//! client codecs, envelope shape, and evidence writes under the
//! working directory are all production code. The one client upstream
//! fakes in-process (`d07BackupCreate`) lands server-side here — the
//! socket, matrix, peer admission, and deny-safe gate all stay real.

use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use central_adapter_linux::backup::{Repository, inspect_repository_descriptor};
use central_adapter_linux::backup_repository::initialize_repository_binding;
use central_adapter_linux::helper::audit::{AuditHandlerImpl, Roots as AuditRoots};
use central_adapter_linux::helper::delete::{
    DeleteHandlerImpl, DeleteRoots, UnavailableDeleteRefs, UnavailableDeleteSource,
};
use central_adapter_linux::helper::export::{
    ExportHandlerImpl, ExportRoots, RepositoryExportSource,
};
use central_adapter_linux::helper::grant::{
    CeremonyScope, ConsumedGrant, GrantKind, GrantScope, GrantStore,
};
use central_adapter_linux::helper::import::{ImportHandlerImpl, ImportRoots};
use central_adapter_linux::helper::pam_ceremony::PamConfirmer;
use central_adapter_linux::helper::prune::PruneHandlerImpl;
use central_adapter_linux::helper::rescue::{RescueHandlerImpl, RescueRoots};
use central_adapter_linux::helper::wipe::{AppArmorDeps, WipeHandlerImpl, WipeRoots};
use central_adapter_linux::helper::{Matrix, PeerPolicy, Server, read_boot_id};
use central_adapter_linux::infra::advisory_fetch::FileDenySafeStore;
use central_backup::backup::capacity::default_recovery_profile;
use central_backup::backup::inventory::InventoryChunk;
use central_backup::backup::manifest::new_seal_root_manifest;
use central_backup::backup::operation::{
    BackupPhase, new_backup_accepted_facts, new_backup_operation,
};
use central_backup::domain::TargetIdentity;
use central_backup::repository::BackupSealCompanion;
use central_foundation::failure::Failure;
use central_infra::advisory::{Outcome, State};
use rustix::fs::{Mode, OFlags};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use time::Duration as TimeDuration;
use time::macros::datetime;
use uuid::Uuid;

use crate::seams::{
    D07BackupCreate, D07CandidateState, D07Checkpoint, D07Cleanup, D07Evaluator, D07InstalledState,
};
use crate::{d07_tier, hex_lower, mkdir_mode, write_mode};

/// `helperCeremonyInstanceID` / `helperCeremonyTargetID` — the
/// installed composition's ceremony identities, shared with the grant
/// scope every handler confirms against.
const CEREMONY_INSTANCE_ID: &str = "default";
const CEREMONY_TARGET_ID: &str = "postgres:central";

fn ceremony_scope() -> CeremonyScope {
    CeremonyScope {
        instance_id: CEREMONY_INSTANCE_ID.to_owned(),
        target_id: CEREMONY_TARGET_ID.to_owned(),
    }
}

/// `FixtureTree` — `t.TempDir`: the path lives as long as the Arc; the
/// verdict clone keeps it alive until the runner's evidence copy.
#[derive(Debug)]
pub(crate) struct FixtureTree {
    pub path: PathBuf,
}

impl FixtureTree {
    fn fresh(tag: &str) -> Arc<Self> {
        let path = std::env::temp_dir().join(format!(
            "central-{tag}-{}-{}",
            std::process::id(),
            Uuid::now_v7()
        ));
        mkdir_mode(&path, 0o700).expect("create fixture tree");
        Arc::new(Self { path })
    }
}

impl Drop for FixtureTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// `d07Env` — one acceptance world.
pub(crate) struct D07Env {
    pub(crate) tier: &'static str,
    pub(crate) tree: Arc<FixtureTree>,
    pub(crate) base: PathBuf,
    pub(crate) instances: PathBuf,
    pub(crate) protected: PathBuf,
    pub(crate) runtime: PathBuf,
    pub(crate) repo: PathBuf,
    pub(crate) staging: PathBuf,
    pub(crate) grant_dir: PathBuf,
    pub(crate) work: PathBuf,
    pub(crate) instance_id: String,
    pub(crate) socket: PathBuf,
    boot_id: String,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    store: GrantStore,
    server: Arc<Mutex<Server>>,
    pub(crate) evaluator: D07Evaluator,
    pub(crate) installed: D07InstalledState,
    pub(crate) candidate: D07CandidateState,
    pub(crate) cleanup_calls: Arc<AtomicI32>,
    stop: Arc<AtomicBool>,
    accept: Option<std::thread::JoinHandle<()>>,
}

impl Drop for D07Env {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.accept.take() {
            let _ = handle.join();
        }
    }
}

/// `d07Envelope` — the operator-visible stdout shape. `reason` and
/// `details` are `omitempty` in the wire shape: absent maps to the
/// empty value, never a decode failure.
#[derive(Debug, Deserialize)]
pub(crate) struct Envelope {
    pub exit_code: i64,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub details: serde_json::Value,
}

fn central_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_central"))
}

/// `d07SourceConfig` — binds the committed complete-config fixture the
/// way upstream's fixture builder does: identity + paths substitution,
/// provider budget fill, re-sign, JCS. The committed fixture alone
/// carries no B09 budget fields, and a config that cannot be rebound
/// is a reseed that cannot complete.
fn source_config(instance_id: &str, state_root: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/capabilities/central-infra/src/config/testdata/complete-config.json");
    let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let mut document: serde_json::Value = serde_json::from_slice(&raw).expect("fixture decodes");
    document["instance_id"] = serde_json::Value::String(instance_id.to_owned());
    let paths = document["paths"]
        .as_object_mut()
        .expect("fixture has no paths object");
    paths.insert(
        "authoritative_state_root".to_owned(),
        serde_json::Value::String(state_root.to_owned()),
    );
    paths.insert(
        "instance_data_root".to_owned(),
        serde_json::Value::String(format!("{state_root}/data")),
    );
    paths.insert(
        "backup_repository_root".to_owned(),
        serde_json::Value::String(format!("{state_root}/backups")),
    );
    let provider = document["provider"]
        .as_object_mut()
        .expect("fixture has no provider object");
    for (budget_name, values) in [
        (
            "default_budget",
            [
                ("input_tokens", 10_000u64),
                ("output_tokens", 1_000),
                ("tool_calls_per_step", 5),
                ("tool_calls_per_run", 20),
                ("wall_time_seconds", 900),
            ],
        ),
        (
            "hard_budget",
            [
                ("input_tokens", 2_000_000u64),
                ("output_tokens", 200_000),
                ("tool_calls_per_step", 20),
                ("tool_calls_per_run", 100),
                ("wall_time_seconds", 86_400),
            ],
        ),
    ] {
        let budget = provider
            .get_mut(budget_name)
            .and_then(serde_json::Value::as_object_mut)
            .unwrap_or_else(|| panic!("fixture has no provider.{budget_name} object"));
        for (field, value) in values {
            budget.insert(field.to_owned(), serde_json::Value::from(value));
        }
    }
    provider.insert(
        "input_token_price_micros".to_owned(),
        serde_json::Value::from(1u64),
    );
    provider.insert(
        "output_token_price_micros".to_owned(),
        serde_json::Value::from(4u64),
    );
    provider.insert(
        "local_grant_ttl_seconds".to_owned(),
        serde_json::Value::from(900u64),
    );
    let profile: central_infra::config::ProviderProfile =
        serde_json::from_value(serde_json::Value::Object(provider.clone()))
            .expect("provider profile decodes");
    provider.insert(
        "signature".to_owned(),
        serde_json::Value::String(profile.canonical_digest()),
    );
    let out = central_foundation::jcs::canonicalize(&document).expect("canonicalize");
    central_infra::config::parse(&out).expect("source config does not parse");
    out
}

/// `d07OpenRepoRO` — opens an already-bound repository read-only
/// through the production inspect + descriptor admission path.
pub(crate) fn open_repo_ro(root: &Path) -> Result<Repository, Failure> {
    let fd = rustix::fs::open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Failure::unavailable("repo_ro", "repository root unreadable"))?;
    let binding = inspect_repository_descriptor(&fd)?;
    Repository::read_only_from_descriptor(&fd, &binding)
}

fn unavailable_look_path(name: &str) -> Result<PathBuf, Failure> {
    Err(Failure::unavailable(
        "look_path",
        format!("{name}: not on the fixture PATH"),
    ))
}

fn unavailable_run(name: &str, _args: &[&str]) -> Result<(), Failure> {
    Err(Failure::unavailable(
        "apparmor_run",
        format!("{name}: fixture runner unavailable"),
    ))
}

/// `d07StandUp` — build one isolated acceptance world. Returns `None`
/// in production tier: upstream's `d07InstallProductionInstance`
/// skips with "root install not yet rehearsed", which the port
/// surfaces as the scenario-level skip the caller records.
pub(crate) fn stand_up() -> Option<D07Env> {
    let tier = d07_tier();
    if tier == "production" {
        // `d07InstallProductionInstance` — the tier-2 install is
        // intentionally narrower than C06's: D07 needs layout,
        // ownership, and a resolvable composition, not a rendered
        // compose stack. Upstream has not rehearsed it; honest skip.
        return None;
    }
    let uid = rustix::process::geteuid().as_raw();
    let gid = rustix::process::getegid().as_raw();

    let tree = FixtureTree::fresh("d07");
    let base = tree.path.clone();
    let instance_id = Uuid::now_v7().to_string();
    let instances = base.join("instances");
    let protected = base.join("protected");
    let runtime = base.join("run");
    let repo = base.join("backups");
    let staging = base.join("staging");
    let grant_dir = base.join("grants");
    let work = base.join("work");
    let socket_dir = base.join("sock");
    for dir in [
        &instances,
        &protected,
        &runtime,
        &repo,
        &staging,
        &grant_dir,
        &work,
        &socket_dir,
    ] {
        mkdir_mode(dir, 0o700).expect("create fixture dir");
    }
    // The instance state root the wipe targets: config.json present,
    // not live (no runtime entry).
    let state_root = instances.join(&instance_id);
    mkdir_mode(&state_root, 0o700).expect("create state root");
    let state_root_str = state_root.to_str().expect("state root utf8").to_owned();
    write_mode(
        state_root.join("config.json"),
        &source_config(&instance_id, &state_root_str),
        0o600,
    )
    .expect("write source config");
    // Protected content the audit hashes and the export collects.
    let protected_dir = protected.join(&instance_id).join("protected");
    mkdir_mode(&protected_dir, 0o700).expect("create protected dir");
    write_mode(
        protected_dir.join("tls-authority.json"),
        br#"{"ca_cert":"eA==","leaf_cert":"eQ=="}"#,
        0o600,
    )
    .expect("write protected fixture");
    // AppArmor fixture: unconfined, no profile — the container shape.
    let attr_current = base.join("attr-current");
    write_mode(&attr_current, b"unconfined", 0o600).expect("write attr-current");

    let boot_id = read_boot_id().expect("boot id unreadable");
    let store = GrantStore::open(grant_dir.to_str().expect("grant dir utf8"), uid, gid)
        .expect("open grant store");

    let evaluator = D07Evaluator::new(State::Current);
    let installed = D07InstalledState::new(State::Current);
    let candidate = D07CandidateState::new(Outcome::current());
    let cleanup_calls = Arc::new(AtomicI32::new(0));

    // Upstream's harness hands every handler the same confirmer
    // instance; `clone` shares the one-use ledger and grant store.
    let pam = PamConfirmer::with_grants(
        GrantStore::open(grant_dir.to_str().expect("grant dir utf8"), uid, gid)
            .expect("reopen grant store"),
        CEREMONY_INSTANCE_ID,
        CEREMONY_TARGET_ID,
    );

    let apparmor = AppArmorDeps {
        attr_current_path: attr_current.to_string_lossy().into_owned(),
        profile_path: base.join("no-such-profile").to_string_lossy().into_owned(),
        look_path: unavailable_look_path,
        run: unavailable_run,
    };
    let wipe = WipeHandlerImpl::new(
        Some(Box::new(pam.clone())),
        Some(Box::new(evaluator.clone())),
        Some(Box::new(D07Checkpoint { repo: repo.clone() })),
        ceremony_scope(),
        WipeRoots {
            instances_root: instances.to_string_lossy().into_owned(),
            protected_parent: protected.to_string_lossy().into_owned(),
            runtime_base: runtime.to_string_lossy().into_owned(),
            parent_uid: uid,
            parent_gid: gid,
            instance_uid: uid,
            instance_gid: gid,
        },
        apparmor,
    );
    let export = ExportHandlerImpl::new(
        Some(Box::new(pam.clone())),
        ceremony_scope(),
        ExportRoots {
            instance_id: instance_id.clone(),
            state_root: state_root_str.clone(),
            broker_protected_dir: protected_dir.to_string_lossy().into_owned(),
            instances_parent_uid: uid,
            instances_parent_gid: gid,
            instance_uid: uid,
            instance_gid: gid,
            staging_parent: staging.to_string_lossy().into_owned(),
        },
        Some(Box::new(RepositoryExportSource {
            root: repo.clone(),
            instance_id: instance_id.clone(),
            profile: default_recovery_profile(),
        })),
    );
    let import = ImportHandlerImpl::new(
        Some(Box::new(pam.clone())),
        ceremony_scope(),
        ImportRoots {
            instance_id: instance_id.clone(),
            state_root: state_root_str.clone(),
            broker_protected_dir: protected_dir.to_string_lossy().into_owned(),
            staging_parent: staging.to_string_lossy().into_owned(),
            instance_uid: uid,
            instance_gid: gid,
            parent_uid: uid,
            parent_gid: gid,
        },
    );
    let delete = DeleteHandlerImpl::new(
        Some(Box::new(pam.clone())),
        Some(Box::new(evaluator.clone())),
        Some(Box::new(UnavailableDeleteSource)),
        Some(Box::new(UnavailableDeleteRefs)),
        ceremony_scope(),
        DeleteRoots {
            journal_dir: base.to_string_lossy().into_owned(),
            journal_uid: uid,
            journal_gid: gid,
        },
    );
    let prune = PruneHandlerImpl::new(
        Some(Box::new(pam.clone())),
        Some(Box::new(evaluator.clone())),
        None,
        ceremony_scope(),
    );
    let audit = AuditHandlerImpl {
        pam: Some(Box::new(pam.clone())),
        advisory: Some(Box::new(evaluator.clone())),
        scope: ceremony_scope(),
        roots: AuditRoots {
            protected_dir: protected_dir.to_string_lossy().into_owned(),
            audit_dir: protected_dir.join("audit").to_string_lossy().into_owned(),
            instance_id: instance_id.clone(),
            audit_uid: uid,
            audit_gid: gid,
        },
    };
    let rescue = RescueHandlerImpl {
        pam: Some(Box::new(pam.clone())),
        installed: Some(Box::new(installed.clone())),
        candidate: Some(Box::new(candidate.clone())),
        cleanup: Some(Box::new(D07Cleanup::new(cleanup_calls.clone()))),
        store: Some(FileDenySafeStore::new(&protected_dir, uid, gid)),
        scope: ceremony_scope(),
        roots: RescueRoots {
            deny_safe_dir: protected_dir.to_string_lossy().into_owned(),
            deny_safe_uid: uid,
            deny_safe_gid: gid,
        },
    };

    let mut server = Server::new();
    server.matrix = Matrix::new();
    // The operator peer is this process; the daemon identity is
    // deliberately someone else (root in the fixture tier too),
    // because the operator arm requires uid != DaemonUID — the same
    // split production enforces.
    server.peer_policy = Some(PeerPolicy {
        daemon_uid: if uid == 0 { 1 } else { 0 },
        operator_uid: uid,
        operator_gid: gid,
    });
    server.wipe = Some(Box::new(wipe));
    server.export = Some(Box::new(export));
    server.import = Some(Box::new(import));
    server.delete = Some(Box::new(delete));
    server.prune = Some(Box::new(prune));
    server.audit = Some(Box::new(audit));
    server.rescue = Some(Box::new(rescue));
    server.deny_safe_dir = Some(protected_dir.to_string_lossy().into_owned());

    let server = Arc::new(Mutex::new(server));
    let socket = socket_dir.join("helper.sock");
    let listener = UnixListener::bind(&socket).expect("listen helper socket");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let stop = Arc::new(AtomicBool::new(false));
    let accept = {
        let server = server.clone();
        let stop = stop.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let guard = server.lock().unwrap_or_else(|e| e.into_inner());
                        let _ = guard.handle_conn(stream);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        })
    };

    Some(D07Env {
        tier,
        tree,
        base,
        instances,
        protected,
        runtime,
        repo,
        staging,
        grant_dir,
        work,
        instance_id,
        socket,
        boot_id,
        uid,
        gid,
        store,
        server,
        evaluator,
        installed,
        candidate,
        cleanup_calls,
        stop,
        accept: Some(accept),
    })
}

/// `d07Env` methods — the harness verbs the scenarios call.
impl D07Env {
    /// The fixture's per-handler `PamConfirmer` — each wraps its own
    /// `GrantStore::open` on the shared grant directory (the key and
    /// the consumed records live on disk, so every confirmer sees the
    /// same authority).
    fn pam(&self) -> PamConfirmer {
        PamConfirmer::with_grants(
            GrantStore::open(
                self.grant_dir.to_str().expect("grant dir utf8"),
                self.uid,
                self.gid,
            )
            .expect("reopen grant store"),
            CEREMONY_INSTANCE_ID,
            CEREMONY_TARGET_ID,
        )
    }

    /// `SetBackupCreateClientForProcess(d07BackupCreate{backupID})` —
    /// the port's server-side equivalent: the `backup-create` handler
    /// answers the wipe checkpoint step with the fixture-sealed id.
    pub(crate) fn install_backup_create(&self, backup_id: &str) {
        self.server.lock().unwrap().backup_create = Some(Box::new(D07BackupCreate {
            backup_id: backup_id.to_owned(),
        }));
    }

    /// `issue` — one root-issued one-use grant of `kind`, bound to the
    /// operation when the kind requires it and unbound otherwise.
    pub(crate) fn issue(&self, kind: GrantKind, operation_id: &str) {
        self.store
            .issue(
                &GrantScope {
                    kind,
                    instance_id: CEREMONY_INSTANCE_ID.to_owned(),
                    target_id: CEREMONY_TARGET_ID.to_owned(),
                    operation_id: operation_id.to_owned(),
                },
                &self.boot_id,
                "d07-acceptance",
                Duration::from_secs(3600),
            )
            .unwrap_or_else(|e| panic!("issue {} grant: {e:?}", kind.as_str()));
    }

    /// `consumed` — the consumption records beside the spent grants.
    pub(crate) fn consumed(&self) -> Vec<ConsumedGrant> {
        self.store.consumed().expect("list consumed grants")
    }

    /// `rebindImport` — re-resolves the import handler onto the given
    /// instance, the fixture's model of production's per-invocation
    /// composition resolution: after a wipe-reseed the live instance
    /// is the new one, not the wiped one the server was composed with.
    pub(crate) fn rebind_import(&self, new_instance_id: &str) {
        let handler = ImportHandlerImpl::new(
            Some(Box::new(self.pam())),
            ceremony_scope(),
            ImportRoots {
                instance_id: new_instance_id.to_owned(),
                state_root: self
                    .instances
                    .join(new_instance_id)
                    .to_string_lossy()
                    .into_owned(),
                broker_protected_dir: self
                    .protected
                    .join(new_instance_id)
                    .join("protected")
                    .to_string_lossy()
                    .into_owned(),
                staging_parent: self.staging.to_string_lossy().into_owned(),
                instance_uid: self.uid,
                instance_gid: self.gid,
                parent_uid: self.uid,
                parent_gid: self.gid,
            },
        );
        self.server.lock().unwrap().import = Some(Box::new(handler));
    }

    /// `initRepo` — creates a fresh repository bound to the env's
    /// instance ID through the production binding APIs.
    fn init_repo(&self) -> Repository {
        let fd = rustix::fs::open(
            &self.repo,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open repo root");
        rustix::fs::fchmod(&fd, Mode::from_raw_mode(0o700)).expect("chmod repo root");
        let binding =
            initialize_repository_binding(&fd, &self.instance_id).expect("init repo binding");
        Repository::from_descriptor(&fd, &binding).expect("admit repo descriptor")
    }

    /// `openRepoRO` — the env's already-bound repository, read-only.
    pub(crate) fn open_repo_ro(&self) -> Repository {
        open_repo_ro(&self.repo).expect("open repo")
    }

    /// `sealBackup` — writes one dump-only sealed backup into the
    /// env's repository through the production repository APIs:
    /// binding, dump, manifest, seal companion. Returns the backup ID.
    pub(crate) fn seal_backup(&self) -> String {
        let repository = self.init_repo();
        let backup_id = Uuid::now_v7();
        let created = datetime!(2026-09-01 0:00 UTC);
        let operation = new_backup_operation(
            Uuid::now_v7(),
            backup_id,
            TargetIdentity {
                system_id: "system".to_owned(),
                database_oid: "1".to_owned(),
                database: "central".to_owned(),
                config_hash: "sha256:config".to_owned(),
                epoch: 1,
            },
            created,
        )
        .expect("new backup operation");
        let fingerprint =
            |value: &str| format!("sha256:{}", hex_lower(Sha256::digest(value.as_bytes())));
        let facts = new_backup_accepted_facts(
            created + TimeDuration::seconds(1),
            &fingerprint("target"),
            &fingerprint("config"),
            Uuid::now_v7(),
            repository.binding_id(),
            &fingerprint("lock-proof"),
        )
        .expect("accepted facts");
        let operation = operation.accept(facts).expect("accept");
        let operation = operation
            .advance(BackupPhase::Dumping, created + TimeDuration::seconds(2))
            .expect("advance dumping");
        let operation = operation
            .advance(BackupPhase::Inventory, created + TimeDuration::seconds(3))
            .expect("advance inventory");
        repository.bind_backup(&operation).expect("bind backup");
        let dump = b"d07 sealed dump: the bytes the export must carry";
        let dump_evidence = repository
            .write_dump(
                backup_id,
                &mut &dump[..],
                default_recovery_profile().max_database_bytes as i64,
            )
            .expect("write dump");
        let manifest = new_seal_root_manifest(&operation, dump_evidence, &[] as &[InventoryChunk])
            .expect("seal root manifest");
        let file_tree = repository
            .write_manifest(&manifest)
            .expect("write manifest");
        let envelope_digest = Sha256::digest(b"d07 authority envelope");
        let hmac_digest = Sha256::digest(b"d07 companion hmac");
        let mut companion = BackupSealCompanion {
            authority_envelope_id: format!("sha256:{}", hex_lower(envelope_digest)),
            backup_id: manifest.backup_id,
            operation_id: manifest.operation_id,
            repository_binding_id: manifest.repository_binding_id,
            target_fingerprint: manifest.accepted_facts.target_fingerprint.clone(),
            config_fingerprint: manifest.accepted_facts.config_fingerprint.clone(),
            payload_epoch_id: manifest.accepted_facts.payload_epoch_id,
            root_manifest_digest: manifest.digest,
            file_tree_digest: file_tree.digest,
            sealed_at: manifest.accepted_facts.database_time + TimeDuration::seconds(1),
            hmac: hex_lower(hmac_digest),
            digest: [0u8; 32],
        };
        let payload = companion
            .canonical_json()
            .expect("companion canonical json");
        companion.digest = Sha256::digest(&payload).into();
        repository
            .write_seal_companion(&companion)
            .expect("write seal companion");
        repository
            .verify_backup(backup_id, &default_recovery_profile())
            .expect("fixture backup does not verify");
        repository.close().expect("close repository");
        backup_id.to_string()
    }

    /// `run` — executes one CLI invocation with the working directory
    /// set to the env's work dir (where evidence artifacts land) and
    /// returns the parsed envelope.
    pub(crate) fn run(&self, args: &[&str]) -> Envelope {
        let output = Command::new(central_bin())
            .args(args)
            .current_dir(&self.work)
            .env("CENTRAL_HELPER_SOCKET", &self.socket)
            .env_remove("CENTRAL_D07_RUN")
            .env_remove("CENTRAL_D07_EVIDENCE_DIR")
            .output()
            .unwrap_or_else(|e| panic!("spawn central {args:?}: {e}"));
        let stdout = String::from_utf8_lossy(&output.stdout);
        serde_json::from_str::<Envelope>(stdout.trim()).unwrap_or_else(|e| {
            panic!(
                "decode {args:?} output: {e}; stdout={stdout} stderr={}",
                String::from_utf8_lossy(&output.stderr)
            )
        })
    }

    /// `readFile` — a declared evidence artifact must be readable.
    pub(crate) fn read_file(&self, name: &str) -> Vec<u8> {
        std::fs::read(self.work.join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"))
    }
}
