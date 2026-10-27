//! `cmd/central/main.go`'s `runBrokerDaemon` and `broker_serve.go`'s
//! `runBrokerServe` — the `--broker` and `broker serve` protected-mode
//! bodies after the mode gates, each composing exactly one
//! [`Service`] and nothing else.
//!
//! `run_broker_daemon` ports the production composition verbatim:
//! `resolveProductionInstanceComposition` (the authoritative
//! `/var/lib/central-state/v1/instances` hierarchy, descriptor-
//! relative every hop — `O_DIRECTORY|O_NOFOLLOW`, exact owner+mode
//! `fstat` gates, one instance entry, a `0600` nlink-1 `config.json`
//! whose declared instance id and `paths.*` match the directory it
//! was read from) → `resolveProductionBrokerRoot` (the matching
//! `/var/lib/central-protected/v1/instances/<id>/protected` chain)
//! → `NewService` → `LISTEN_FDS` → `Harden()` → `Serve` on fd 3.
//!
//! The composition carries upstream's `RoleRoots` — derived by
//! `infra::capacity_roles`, never read from the config — and threads
//! it into the service (`NewServiceWithRoleRoots`) so the restore
//! capacity gate's precondition 4 can reach each device's reserve
//! object. Upstream's digest fields stay unported: no consumer exists
//! for them yet.

use std::io::Write;
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use central_foundation::identity::InstanceId;
use central_infra::authority::{CENTRAL_RUNTIME_GID, CENTRAL_RUNTIME_UID};
use rustix::fs::{FileType, Mode, OFlags, fstat, open, openat};

use super::server::{Service, serve, serve_on_path};

/// Upstream `productionAuthoritativeInstancesRoot`.
pub const PRODUCTION_STATE_INSTANCES: &str = "/var/lib/central-state/v1/instances";

/// Upstream `productionProtectedInstancesRoot`.
pub const PRODUCTION_PROTECTED_INSTANCES: &str = "/var/lib/central-protected/v1/instances";

/// Upstream `maximumAuthoritativeConfigBytes`.
const MAX_CONFIG_BYTES: u64 = 1 << 20;

/// Upstream's single refusal for every composition violation —
/// deliberately uninformative to the caller's journal.
const INSTANCE_UNAVAILABLE: &str = "production instance authority unavailable";

/// `resolveProductionBrokerRoot`'s refusal.
const BROKER_UNAVAILABLE: &str = "production broker authority unavailable";

/// `productionInstanceComposition` — the fields the broker daemon
/// and the helper's restore-capacity sweep consume. Upstream carries
/// the full config-bound topology snapshot; the port carries the
/// validated instance id, the state/dependency roots, and the derived
/// capacity-role roots — the policy digests remain without a consumer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionInstanceComposition {
    /// The instance's validated identity — the directory name,
    /// `InstanceId`-parsed and config-verified.
    pub instance_id: String,
    /// `<instances_root>/<instance_id>` — upstream
    /// `productionInstanceComposition.AuthoritativeStateRoot`.
    pub authoritative_state_root: String,
    /// `<authoritative_state_root>/dependencies` — upstream's
    /// `DependencyRoot`, where the active dependency receipt lives.
    pub dependency_root: String,
    /// The host directories backing the four capacity-reserve roles —
    /// upstream `productionInstanceComposition.RoleRoots`. Derived,
    /// never accepted: `infra::capacity_roles::role_roots` is the same
    /// derivation the Compose mount renderer uses, so the helper and
    /// the broker daemon cannot disagree about where an instance's
    /// payload directories live.
    pub role_roots: central_backup::backup::capacity::RoleRoots,
    /// `cfg.paths.backup_repository_root` —
    /// `<authoritative_state_root>/backups`, config-verified.
    pub backup_repository_root: String,
    /// `/run/central-infra/<instance_id>/docker-compose.yaml` — the
    /// one rendered compose file the preparers may run.
    pub compose_path: String,
    /// `cfg.object_store.bucket` — the fixed `central-artifacts-v1`
    /// bucket the recovery purposes bind.
    pub object_store_bucket: String,
    /// `cfg.object_store.policy_digests.backup`.
    pub backup_policy_digest: String,
    /// `cfg.object_store.policy_digests.restore`.
    pub restore_policy_digest: String,
    /// `cfg.object_store.policy_digests.import`.
    pub import_policy_digest: String,
}

/// `filepath.IsAbs(path) && filepath.Clean(path) == path` — absolute
/// and already clean (no `.`/`..`/empty mid components, no trailing
/// slash). `"/"` itself is clean (`Clean("/") == "/"` upstream).
fn is_abs_clean(path: &str) -> bool {
    if path == "/" {
        return true;
    }
    path.starts_with('/')
        && path
            .split('/')
            .skip(1)
            .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

/// `exactOwnedDirectory` — `fstat` on the descriptor: a directory of
/// exactly `mode`, owned by `uid:gid`.
fn exact_owned_directory<Fd: AsFd>(fd: Fd, uid: u32, gid: u32, mode: u32) -> bool {
    let Ok(st) = fstat(fd) else {
        return false;
    };
    FileType::from_raw_mode(st.st_mode).is_dir()
        && st.st_uid == uid
        && st.st_gid == gid
        && st.st_mode & 0o7777 == mode
}

const OPEN_DIR: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

const OPEN_FILE: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

/// `loadProductionInstanceCompositionForOwner` — the authoritative
/// composition, validated hop by hop: the instances root is an
/// `0700` `parent_uid:parent_gid` directory holding exactly one
/// non-symlink directory entry whose name is a valid instance id;
/// `<root>/<id>` is `0700` `instance_uid:instance_gid`; its
/// `config.json` is a `0600` nlink-1 regular file ≤ 1 MiB whose
/// parsed `instance_id` and `paths.*` match the directory it was
/// read from.
///
/// # Errors
/// `INSTANCE_UNAVAILABLE` for every violation, upstream's single
/// refusal string.
pub fn load_production_instance_composition_for_owner(
    instances_root: &str,
    parent_uid: u32,
    parent_gid: u32,
    instance_uid: u32,
    instance_gid: u32,
) -> Result<ProductionInstanceComposition, &'static str> {
    if !is_abs_clean(instances_root) {
        return Err(INSTANCE_UNAVAILABLE);
    }
    let root_fd =
        open(instances_root, OPEN_DIR, Mode::empty()).map_err(|_| INSTANCE_UNAVAILABLE)?;
    if !exact_owned_directory(&root_fd, parent_uid, parent_gid, 0o700) {
        return Err(INSTANCE_UNAVAILABLE);
    }
    // Exactly one entry — a real directory, never a symlink — whose
    // name is a canonical instance id.
    let mut names = Vec::new();
    for entry in rustix::fs::Dir::read_from(&root_fd).map_err(|_| INSTANCE_UNAVAILABLE)? {
        let entry = entry.map_err(|_| INSTANCE_UNAVAILABLE)?;
        let name_bytes = entry.file_name().to_bytes();
        if name_bytes == b"." || name_bytes == b".." {
            continue;
        }
        let ty = entry.file_type();
        if !ty.is_dir() || ty.is_symlink() {
            return Err(INSTANCE_UNAVAILABLE);
        }
        let Ok(name) = std::str::from_utf8(name_bytes) else {
            return Err(INSTANCE_UNAVAILABLE);
        };
        names.push(name.to_owned());
        if names.len() > 1 {
            return Err(INSTANCE_UNAVAILABLE);
        }
    }
    if names.len() != 1 {
        return Err(INSTANCE_UNAVAILABLE);
    }
    let instance_id = names[0].clone();
    let parsed = InstanceId::parse(&instance_id).map_err(|_| INSTANCE_UNAVAILABLE)?;
    if parsed.to_string() != instance_id {
        return Err(INSTANCE_UNAVAILABLE);
    }
    let instance_fd = openat(&root_fd, &instance_id, OPEN_DIR, Mode::empty())
        .map_err(|_| INSTANCE_UNAVAILABLE)?;
    if !exact_owned_directory(&instance_fd, instance_uid, instance_gid, 0o700) {
        return Err(INSTANCE_UNAVAILABLE);
    }
    let config_fd = openat(&instance_fd, "config.json", OPEN_FILE, Mode::empty())
        .map_err(|_| INSTANCE_UNAVAILABLE)?;
    let stat = fstat(&config_fd).map_err(|_| INSTANCE_UNAVAILABLE)?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_uid != instance_uid
        || stat.st_gid != instance_gid
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
        || stat.st_size <= 0
        || stat.st_size > MAX_CONFIG_BYTES as i64
    {
        return Err(INSTANCE_UNAVAILABLE);
    }
    let mut raw = Vec::new();
    use std::io::Read as _;
    {
        let mut file =
            std::fs::File::from(config_fd.try_clone().map_err(|_| INSTANCE_UNAVAILABLE)?);
        let mut limited = (&mut file).take(MAX_CONFIG_BYTES + 1);
        limited
            .read_to_end(&mut raw)
            .map_err(|_| INSTANCE_UNAVAILABLE)?;
    }
    if raw.is_empty() || raw.len() as u64 > MAX_CONFIG_BYTES {
        return Err(INSTANCE_UNAVAILABLE);
    }
    let cfg = central_infra::config::parse(&raw).map_err(|_| INSTANCE_UNAVAILABLE)?;
    let state_root = format!("{instances_root}/{instance_id}");
    if cfg.instance_id.to_string() != instance_id
        || cfg.paths.authoritative_state_root != state_root
        || cfg.paths.instance_data_root != format!("{state_root}/data")
        || cfg.paths.backup_repository_root != format!("{state_root}/backups")
    {
        return Err(INSTANCE_UNAVAILABLE);
    }
    let role_roots =
        crate::infra::capacity_roles::role_roots(&instance_id).map_err(|_| INSTANCE_UNAVAILABLE)?;
    Ok(ProductionInstanceComposition {
        instance_id: instance_id.clone(),
        authoritative_state_root: state_root.clone(),
        dependency_root: format!("{state_root}/dependencies"),
        role_roots,
        backup_repository_root: cfg.paths.backup_repository_root.clone(),
        compose_path: format!("/run/central-infra/{instance_id}/docker-compose.yaml"),
        object_store_bucket: cfg.object_store.bucket.clone(),
        backup_policy_digest: cfg.object_store.policy_digests.backup.clone(),
        restore_policy_digest: cfg.object_store.policy_digests.restore.clone(),
        import_policy_digest: cfg.object_store.policy_digests.import.clone(),
    })
}

/// `resolveProductionInstanceComposition` — the production owners
/// pinned: root:0 for the instances root, 501:501 (the runtime
/// identity) for the instance and its config.
pub fn resolve_production_instance_composition()
-> Result<ProductionInstanceComposition, &'static str> {
    load_production_instance_composition_for_owner(
        PRODUCTION_STATE_INSTANCES,
        0,
        0,
        CENTRAL_RUNTIME_UID,
        CENTRAL_RUNTIME_GID,
    )
}

/// `productionBrokerRootAt` — `<protected_root>/<instance_id>/
/// protected`, every hop `O_NOFOLLOW`-opened and `0700` `uid:gid`-
/// exact. The instance id comes only from the resolved authoritative
/// composition.
///
/// # Errors
/// `BROKER_UNAVAILABLE` for every violation.
pub fn production_broker_root_at(
    composition: &ProductionInstanceComposition,
    protected_root: &str,
    uid: u32,
    gid: u32,
) -> Result<PathBuf, &'static str> {
    if !is_abs_clean(protected_root) {
        return Err(BROKER_UNAVAILABLE);
    }
    let parsed = InstanceId::parse(&composition.instance_id).map_err(|_| BROKER_UNAVAILABLE)?;
    if parsed.to_string() != composition.instance_id {
        return Err(BROKER_UNAVAILABLE);
    }
    let parent_fd =
        open(protected_root, OPEN_DIR, Mode::empty()).map_err(|_| BROKER_UNAVAILABLE)?;
    if !exact_owned_directory(&parent_fd, uid, gid, 0o700) {
        return Err(BROKER_UNAVAILABLE);
    }
    let instance_fd = openat(
        &parent_fd,
        &composition.instance_id,
        OPEN_DIR,
        Mode::empty(),
    )
    .map_err(|_| BROKER_UNAVAILABLE)?;
    if !exact_owned_directory(&instance_fd, uid, gid, 0o700) {
        return Err(BROKER_UNAVAILABLE);
    }
    let protected_fd = openat(&instance_fd, "protected", OPEN_DIR, Mode::empty())
        .map_err(|_| BROKER_UNAVAILABLE)?;
    if !exact_owned_directory(&protected_fd, uid, gid, 0o700) {
        return Err(BROKER_UNAVAILABLE);
    }
    Ok(Path::new(protected_root)
        .join(&composition.instance_id)
        .join("protected"))
}

/// `signal.NotifyContext(SIGINT, SIGTERM)` — a `static` flag an
/// `rt_sigaction` handler flips. tokio's `signal` needs a socketpair
/// copier (`socketpair`/`poll` are not on the broker's seccomp
/// allow-list); a plain handler installed before `harden()` keeps
/// working under the filter — `rt_sigaction` itself is allow-listed
/// (ADR 0044). `SA_RESTART` plus the accept loop's `EAGAIN` poll
/// matches upstream's `ctx`-cancel + `listener.Close` cadence.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn mark_shutdown(_signum: libc::c_int) {
    SHUTDOWN.store(true, Ordering::Release);
}

fn shutdown_flag() -> &'static AtomicBool {
    // The install is idempotent — `sigaction` twice is the same
    // disposition; the `let _ =` mirrors upstream's "NotifyContext
    // always succeeds" shape (EINVAL is unreachable for
    // SIGINT/SIGTERM).
    let _ = crate::sys::audited::install_signal_handler(libc::SIGINT, mark_shutdown);
    let _ = crate::sys::audited::install_signal_handler(libc::SIGTERM, mark_shutdown);
    &SHUTDOWN
}

/// `runBrokerDaemon` — the `--broker` mode body. `instances_root` and
/// `protected_root` are parameters so the resolution tests can place
/// the authoritative hierarchy on a test filesystem (upstream's
/// `loadProductionInstanceCompositionForOwner` shape); production
/// pins the two constants below. `env` is the `LISTEN_FDS` seam;
/// `stderr` the journal writer; returns the process exit code.
pub fn run_broker_daemon_at(
    instances_root: &str,
    protected_root: &str,
    env: &dyn Fn(&str) -> Option<String>,
    stderr: &mut dyn Write,
) -> u8 {
    let composition = match load_production_instance_composition_for_owner(
        instances_root,
        0,
        0,
        CENTRAL_RUNTIME_UID,
        CENTRAL_RUNTIME_GID,
    ) {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(stderr, "broker: production instance: {e}");
            return 6;
        }
    };
    let root_path = match production_broker_root_at(&composition, protected_root, 0, 0) {
        Ok(p) => p,
        Err(e) => {
            let _ = writeln!(stderr, "broker: production authority: {e}");
            return 6;
        }
    };
    let mut svc = match Service::new(root_path, CENTRAL_RUNTIME_UID) {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(stderr, "broker: new service: {}", e.message());
            return 6;
        }
    };
    // `NewServiceWithRoleRoots` — the composition's `role_roots` is
    // threaded into the service here so that the capacity gate's
    // precondition 4 can reach each device's reserve object.
    svc.set_role_roots(composition.role_roots);
    // Upstream checks LISTEN_FDS after the service is built (the
    // composition resolution must precede hardening — see
    // SC-DEF-07's comment upstream carried in modes.rs).
    let raw = env("LISTEN_FDS").unwrap_or_default();
    let count = raw.parse::<i64>().unwrap_or(-1);
    if count < 1 {
        let _ = writeln!(stderr, "broker: no socket fd (LISTEN_FDS={raw:?})");
        return 3;
    }
    if let Err(e) = crate::sys::hardening::harden() {
        let _ = writeln!(stderr, "broker: harden: {}", e.message());
        return 6;
    }
    // `activation.Listeners`-equivalent: the full activation contract
    // (LISTEN_PID names this process, LISTEN_FDS covers index 0) plus
    // the audited fd claim — not a bare `fd 3` grab (R5 T9 P3).
    let listen = match super::server::activated_listener_at(0, env) {
        Ok(fd) => fd,
        Err(e) => {
            let _ = writeln!(stderr, "broker: {}", e.message());
            return 3;
        }
    };
    if let Err(e) = serve(listen, &svc, shutdown_flag()) {
        let _ = writeln!(stderr, "broker: {}", e.message());
        return 3;
    }
    0
}

/// `runBrokerDaemon` with the production roots pinned.
pub fn run_broker_daemon(env: &dyn Fn(&str) -> Option<String>, stderr: &mut dyn Write) -> u8 {
    run_broker_daemon_at(
        PRODUCTION_STATE_INSTANCES,
        PRODUCTION_PROTECTED_INSTANCES,
        env,
        stderr,
    )
}

/// `runBrokerServe` after the arg/path checks (which `modes.rs` owns,
/// verbatim upstream): `NewService(state_root, 501)` → `ServeOnPath`
/// until SIGINT/SIGTERM. `shutdown` is the test seam — production
/// passes [`shutdown_flag`]'s live flag. Returns the exit code (6 on
/// service/serve failure, 0 on a clean shutdown).
pub fn run_broker_serve_at(
    state_root: &str,
    socket_path: &str,
    shutdown: &AtomicBool,
    stderr: &mut dyn Write,
) -> u8 {
    let svc = match Service::new(PathBuf::from(state_root), CENTRAL_RUNTIME_UID) {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(stderr, "broker serve: new service: {}", e.message());
            return 6;
        }
    };
    let _ = writeln!(
        stderr,
        "broker serve: listening on {socket_path} (state {state_root})"
    );
    match serve_on_path(Path::new(socket_path), &svc, shutdown) {
        // Upstream `broker_serve.go`: `err != nil && !errors.Is(err,
        // context.Canceled)` — a signal-cancelled serve is a clean
        // operator exit 0, while the hardened daemon maps the same
        // `ctx.Err()` to exit 3 (`main.go`'s `runBrokerDaemon`).
        Err(e) if e.kind() == central_foundation::failure::FailureKind::Cancelled => 0,
        Err(e) => {
            let _ = writeln!(stderr, "broker serve: {}", e.message());
            6
        }
        Ok(()) => 0,
    }
}

/// The production entry — the live signal flag.
pub fn run_broker_serve(state_root: &str, socket_path: &str, stderr: &mut dyn Write) -> u8 {
    run_broker_serve_at(state_root, socket_path, shutdown_flag(), stderr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| map.get(k).cloned()
    }

    fn dir(path: &Path, mode: u32) {
        std::fs::DirBuilder::new()
            .mode(mode)
            .recursive(true)
            .create(path)
            .expect("mkdir");
    }

    fn euid() -> u32 {
        rustix::process::geteuid().as_raw()
    }
    fn egid() -> u32 {
        rustix::process::getegid().as_raw()
    }

    /// The upstream `authoritativeConfigFixture` — the committed
    /// `complete-config.json` fixture, completed with the B09
    /// authority fields, re-signed, rebound to `id`/`state_root`, and
    /// JCS-canonicalized so `schema::parse` accepts it.
    const COMPLETE_CONFIG_FIXTURE: &str = include_str!(
        "../../../../capabilities/central-infra/src/config/testdata/complete-config.json"
    );

    fn authoritative_config(instances_root: &str, id: &str) -> Vec<u8> {
        let state_root = format!("{instances_root}/{id}");
        let mut document: serde_json::Value =
            serde_json::from_str(COMPLETE_CONFIG_FIXTURE).expect("fixture decodes");
        document["instance_id"] = serde_json::Value::from(id);
        document["paths"]["authoritative_state_root"] = serde_json::Value::from(state_root.clone());
        document["paths"]["instance_data_root"] =
            serde_json::Value::from(format!("{state_root}/data"));
        document["paths"]["backup_repository_root"] =
            serde_json::Value::from(format!("{state_root}/backups"));
        let provider = document
            .get_mut("provider")
            .and_then(serde_json::Value::as_object_mut)
            .expect("provider object");
        for (obj, entries) in [
            (
                "default_budget",
                [
                    ("input_tokens", 10_000u64),
                    ("output_tokens", 1_000),
                    ("tool_calls_per_step", 5),
                    ("tool_calls_per_run", 20),
                    ("wall_time_seconds", 900),
                ]
                .as_slice(),
            ),
            (
                "hard_budget",
                [
                    ("input_tokens", 2_000_000u64),
                    ("output_tokens", 200_000),
                    ("tool_calls_per_step", 20),
                    ("tool_calls_per_run", 100),
                    ("wall_time_seconds", 86_400),
                ]
                .as_slice(),
            ),
        ] {
            let budget = provider
                .get_mut(obj)
                .and_then(serde_json::Value::as_object_mut)
                .expect("budget object");
            for (k, v) in entries {
                budget.insert((*k).to_owned(), serde_json::Value::from(*v));
            }
        }
        provider.insert(
            "input_token_price_micros".to_owned(),
            serde_json::Value::from(1),
        );
        provider.insert(
            "output_token_price_micros".to_owned(),
            serde_json::Value::from(4),
        );
        provider.insert(
            "local_grant_ttl_seconds".to_owned(),
            serde_json::Value::from(900),
        );
        let profile: central_infra::config::ProviderProfile =
            serde_json::from_value(serde_json::Value::Object(provider.clone()))
                .expect("provider decodes");
        provider.insert(
            "signature".to_owned(),
            serde_json::Value::String(profile.canonical_digest()),
        );
        central_foundation::jcs::canonicalize(&document).expect("canonical fixture")
    }

    /// `prepareReferenceAuthoritativeInstance` — root 0700, one
    /// instance dir 0700, `config.json` 0600.
    fn prepare_instance(base: &Path, id: &str) -> PathBuf {
        let root = base.join("instances");
        dir(&root, 0o700);
        let inst = root.join(id);
        dir(&inst, 0o700);
        let cfg = authoritative_config(root.to_str().unwrap(), id);
        std::fs::write(inst.join("config.json"), cfg).expect("config");
        std::fs::set_permissions(
            inst.join("config.json"),
            std::fs::Permissions::from_mode(0o600),
        )
        .expect("chmod");
        root
    }

    /// `exactOwnedDirectory` — mode/owner/type all must match.
    #[test]
    fn exact_owned_directory_checks_every_field() {
        let root = std::env::temp_dir().join(format!("central-bd-{}", std::process::id()));
        dir(&root, 0o700);
        let fd = open(&root, OPEN_DIR, Mode::empty()).expect("open");
        assert!(exact_owned_directory(&fd, euid(), egid(), 0o700));
        assert!(!exact_owned_directory(&fd, euid() + 1, egid(), 0o700));
        assert!(!exact_owned_directory(&fd, euid(), egid(), 0o600));
        let file = root.join("f");
        std::fs::write(&file, b"x").expect("file");
        let ffd = open(&file, OPEN_FILE, Mode::empty()).expect("open file");
        assert!(!exact_owned_directory(&ffd, euid(), egid(), 0o700));
        std::fs::remove_dir_all(&root).ok();
    }

    /// `is_abs_clean` — the `IsAbs && Clean == path` gate.
    #[test]
    fn abs_clean_gate() {
        for good in ["/var/lib/x", "/", "/a/b/c"] {
            assert!(is_abs_clean(good), "{good}");
        }
        for bad in ["", "relative", "/a//b", "/a/./b", "/a/../b", "/a/", "//a"] {
            assert!(!is_abs_clean(bad), "{bad}");
        }
    }

    /// An empty/missing root collapses to the single refusal — the
    /// error text `runBrokerDaemon` journals.
    #[test]
    fn empty_root_is_unavailable() {
        let root = std::env::temp_dir().join(format!("central-bd2-{}", std::process::id()));
        dir(&root, 0o700);
        let err = load_production_instance_composition_for_owner(
            root.to_str().unwrap(),
            euid(),
            egid(),
            euid(),
            egid(),
        )
        .unwrap_err();
        assert_eq!(err, INSTANCE_UNAVAILABLE);
        std::fs::remove_dir_all(&root).ok();
    }

    /// The full happy path: one properly-owned instance hierarchy
    /// with a bound config resolves to the instance's id.
    #[test]
    fn instance_composition_resolves() {
        let base = std::env::temp_dir().join(format!("central-bd4-{}", std::process::id()));
        let id = InstanceId::new().to_string();
        let root = prepare_instance(&base, &id);
        let comp = load_production_instance_composition_for_owner(
            root.to_str().unwrap(),
            euid(),
            egid(),
            euid(),
            egid(),
        )
        .expect("resolves");
        assert_eq!(comp.instance_id, id);
        std::fs::remove_dir_all(&base).ok();
    }

    /// The denial matrix of `loadProductionInstanceCompositionForOwner`
    /// — every single deviation lands on the one refusal string.
    #[test]
    fn instance_composition_denies_deviations() {
        // Two instance entries.
        let base = std::env::temp_dir().join(format!("central-bd5-{}", std::process::id()));
        let root = base.join("instances");
        for id in [InstanceId::new().to_string(), InstanceId::new().to_string()] {
            dir(&root.join(&id), 0o700);
        }
        assert_eq!(
            load_production_instance_composition_for_owner(
                root.to_str().unwrap(),
                euid(),
                egid(),
                euid(),
                egid()
            ),
            Err(INSTANCE_UNAVAILABLE),
            "two instances admitted"
        );
        std::fs::remove_dir_all(&base).ok();

        // A non-UUID directory name.
        let base = std::env::temp_dir().join(format!("central-bd6-{}", std::process::id()));
        let root = base.join("instances");
        dir(&root.join("not-an-instance"), 0o700);
        assert_eq!(
            load_production_instance_composition_for_owner(
                root.to_str().unwrap(),
                euid(),
                egid(),
                euid(),
                egid()
            ),
            Err(INSTANCE_UNAVAILABLE)
        );
        std::fs::remove_dir_all(&base).ok();

        // A symlinked instance entry.
        let base = std::env::temp_dir().join(format!("central-bd7-{}", std::process::id()));
        let root = base.join("instances");
        dir(&root, 0o700);
        let id = InstanceId::new().to_string();
        let real = base.join("real");
        dir(&real, 0o700);
        std::os::unix::fs::symlink(&real, root.join(&id)).expect("symlink");
        assert_eq!(
            load_production_instance_composition_for_owner(
                root.to_str().unwrap(),
                euid(),
                egid(),
                euid(),
                egid()
            ),
            Err(INSTANCE_UNAVAILABLE),
            "symlinked instance admitted"
        );
        std::fs::remove_dir_all(&base).ok();

        // A symlinked config.json — O_NOFOLLOW refuses the open.
        let base = std::env::temp_dir().join(format!("central-bd8-{}", std::process::id()));
        let id = InstanceId::new().to_string();
        let root = prepare_instance(&base, &id);
        let inst = root.join(&id);
        std::fs::remove_file(inst.join("config.json")).expect("rm");
        std::os::unix::fs::symlink(base.join("elsewhere"), inst.join("config.json"))
            .expect("symlink");
        std::fs::write(base.join("elsewhere"), b"{}").expect("target");
        assert_eq!(
            load_production_instance_composition_for_owner(
                root.to_str().unwrap(),
                euid(),
                egid(),
                euid(),
                egid()
            ),
            Err(INSTANCE_UNAVAILABLE),
            "symlinked config admitted"
        );
        std::fs::remove_dir_all(&base).ok();

        // A config whose declared instance id != directory name.
        let base = std::env::temp_dir().join(format!("central-bd9-{}", std::process::id()));
        let root = base.join("instances");
        dir(&root, 0o700);
        let dir_id = InstanceId::new().to_string();
        let cfg_id = InstanceId::new().to_string();
        let inst = root.join(&dir_id);
        dir(&inst, 0o700);
        // Config bound to a *different* id — but then paths won't
        // match the directory either way; bind paths to dir_id while
        // instance_id says cfg_id.
        let mut raw = authoritative_config(root.to_str().unwrap(), &cfg_id);
        // rewrite the paths back to the dir's name so only the id
        // mismatches
        let mut doc: serde_json::Value = serde_json::from_slice(&raw).expect("doc");
        let state_root = format!("{}/{}", root.display(), dir_id);
        doc["paths"]["authoritative_state_root"] = serde_json::Value::from(state_root.clone());
        doc["paths"]["instance_data_root"] = serde_json::Value::from(format!("{state_root}/data"));
        doc["paths"]["backup_repository_root"] =
            serde_json::Value::from(format!("{state_root}/backups"));
        raw = central_foundation::jcs::canonicalize(&doc).expect("canonical");
        std::fs::write(inst.join("config.json"), raw).expect("config");
        std::fs::set_permissions(
            inst.join("config.json"),
            std::fs::Permissions::from_mode(0o600),
        )
        .expect("chmod");
        assert_eq!(
            load_production_instance_composition_for_owner(
                root.to_str().unwrap(),
                euid(),
                egid(),
                euid(),
                egid()
            ),
            Err(INSTANCE_UNAVAILABLE),
            "config instance mismatch admitted"
        );
        std::fs::remove_dir_all(&base).ok();
    }

    /// `run_broker_daemon_at` on an empty tree exits 6 with
    /// upstream's production-instance line — the arm every non-
    /// reference host takes.
    #[test]
    fn broker_daemon_empty_root_exits_6() {
        let root = std::env::temp_dir().join(format!("central-bd3-{}", std::process::id()));
        dir(&root, 0o700);
        let env = env_of(&[]);
        let mut stderr = Vec::new();
        let code = run_broker_daemon_at(
            root.to_str().unwrap(),
            "/var/lib/central-protected/v1/instances",
            &env,
            &mut stderr,
        );
        assert_eq!(code, 6);
        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            "broker: production instance: production instance authority unavailable\n"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// `runBrokerServe`'s inner flow against a real state root +
    /// socket in a test dir: service builds, the socket binds, the
    /// pre-set shutdown flag returns 0 — and the "listening on" line
    /// is upstream's verbatim.
    #[test]
    fn broker_serve_binds_and_returns_on_shutdown() {
        let root = std::env::temp_dir().join(format!("central-bs-{}", std::process::id()));
        dir(&root, 0o700);
        let sock = root.join("broker.sock");
        let flag = AtomicBool::new(true);
        let mut stderr = Vec::new();
        let code = run_broker_serve_at(
            root.to_str().unwrap(),
            sock.to_str().unwrap(),
            &flag,
            &mut stderr,
        );
        assert_eq!(code, 0);
        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            format!(
                "broker serve: listening on {} (state {})\n",
                sock.display(),
                root.display()
            )
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// A state root the service constructor refuses (a file, not a
    /// dir) exits 6 with upstream's `new service` prefix.
    #[test]
    fn broker_serve_new_service_failure_exits_6() {
        let root = std::env::temp_dir().join(format!("central-bs2-{}", std::process::id()));
        std::fs::write(&root, b"x").expect("file");
        let sock = root.with_file_name("bs2.sock");
        let flag = AtomicBool::new(true);
        let mut stderr = Vec::new();
        let code = run_broker_serve_at(
            root.to_str().unwrap(),
            sock.to_str().unwrap(),
            &flag,
            &mut stderr,
        );
        assert_eq!(code, 6);
        let line = String::from_utf8(stderr).unwrap();
        assert!(
            line.starts_with("broker serve: new service: "),
            "stderr: {line}"
        );
        std::fs::remove_file(&root).ok();
    }

    /// The `production_broker_root_at` hop chain: every missing or
    /// wrong-owner directory is the single broker refusal; a fully
    /// euid-owned three-level chain resolves the protected path.
    #[test]
    fn broker_root_hops() {
        let base = std::env::temp_dir().join(format!("central-br-{}", std::process::id()));
        let id = InstanceId::new().to_string();
        let comp = ProductionInstanceComposition {
            instance_id: id.clone(),
            authoritative_state_root: String::new(),
            dependency_root: String::new(),
            role_roots: Default::default(),
            backup_repository_root: String::new(),
            compose_path: String::new(),
            object_store_bucket: String::new(),
            backup_policy_digest: String::new(),
            restore_policy_digest: String::new(),
            import_policy_digest: String::new(),
        };
        // Missing root.
        let err =
            production_broker_root_at(&comp, base.to_str().unwrap(), euid(), egid()).unwrap_err();
        assert_eq!(err, BROKER_UNAVAILABLE);
        // Build the chain: <root>/<id>/protected, all 0700 self-owned.
        dir(&base.join(&id).join("protected"), 0o700);
        let root = production_broker_root_at(&comp, base.to_str().unwrap(), euid(), egid())
            .expect("resolved");
        assert_eq!(root, base.join(&id).join("protected"));
        // Wrong owner refuses.
        let err = production_broker_root_at(&comp, base.to_str().unwrap(), euid() + 1, egid())
            .unwrap_err();
        assert_eq!(err, BROKER_UNAVAILABLE);
        std::fs::remove_dir_all(&base).ok();
    }
}
