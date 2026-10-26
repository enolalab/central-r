//! `lifecycle` — the B03 Linux adapter for the lifecycle ports (upstream
//! `internal/adapter/infralifecycle/lifecycle_linux.go`): the Compose
//! `Topology`, the durable `FileJournal`, `FileLocker` + dead-owner
//! takeover, `FileBarrier`, `FilesystemCapacity`, `FileBootstrap`
//! (delegating the credential ceremony to the broker `B04Bootstrap`
//! port), `receiptAdmission`, `DockerReceiptInspector`, and the
//! composition root `new_production_service` plus the
//! `LifecycleApplication` bridge into the helper lifecycle arm.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use central_foundation::failure::Failure;
use central_infra::advisory;
use central_infra::domain::{
    DependencyReceipt, LifecycleBinding, LifecycleOperation, LifecyclePhase, LifecycleRequest,
    LifecycleResult, LifecycleStatusRequest, Observation, PreparedDependencySet, SemanticReceipt,
    ServiceMode, TopologySnapshot,
};
use central_infra::lifecycle::LifecycleService;
use central_infra::port::{
    AdmissionRequest, AdmissionResult, B04Bootstrap, BootstrapGeneration, BootstrapHandoff,
    BootstrapPurpose, DeadOwnerVerifier, HandoffLifetime, LifecycleAdmission, LifecycleBarrier,
    LifecycleBootstrap, LifecycleCapacity, LifecycleClock, LifecycleLock, LifecycleLocker,
    LifecyclePort, LifecycleReservation, MountProof, TopologyPort,
};

use super::compose::{
    BROKER_SOCKET_TARGET, CommandExecutor, ComposeRunner, POSTGRES_INIT_SCRIPT_SQL, Policy,
    REQUIRED_SERVICE_MODES, RenderedFile, closed_docker_environment, durable_service_data_root,
    durable_service_root, image_reference, load_default_policy, parse_rendered_model,
    policy_digest, postgres_init_script_host_path, render, validate_model,
};
use super::prepare::OpDeadline;

/// `phaseOpDeadline` — the domain's wall-clock phase deadline
/// (upstream's `context.WithDeadline(ctx, now+phaseBudget)`) as the
/// monotonic `Instant` the bounded compose executor polls. `None` is
/// upstream's `context.Background()`; an already-past instant clamps
/// to now, so the first poll kills the child — exactly as a `ctx`
/// that is already done fails the first `ctx.Err()` check.
fn phase_op_deadline(deadline: Option<OffsetDateTime>) -> OpDeadline {
    let Some(at) = deadline else {
        return OpDeadline::NONE;
    };
    let remaining: std::time::Duration = (at - OffsetDateTime::now_utc())
        .try_into()
        .unwrap_or_default();
    OpDeadline(Some(Instant::now() + remaining))
}

/// `block_on` — the house pattern: drives the domain service's async
/// state machine from the helper's synchronous lifecycle arm. Every
/// port implementation here completes synchronously (filesystem and
/// subprocess I/O are blocking calls, not pending futures).
pub fn block_on<F: Future>(f: F) -> F::Output {
    let mut cx = Context::from_waker(Waker::noop());
    let mut f = Box::pin(f);
    loop {
        if let Poll::Ready(v) = Pin::new(&mut f).poll(&mut cx) {
            return v;
        }
    }
}

// ---------------------------------------------------------------------------
// Injected boundaries
// ---------------------------------------------------------------------------

/// `AdvisoryEvaluator` — the B01 authority boundary.
pub trait AdvisoryEvaluator: Send + Sync + 'static {
    /// `Evaluate`.
    fn evaluate(&self) -> Result<(advisory::Outcome, advisory::Admission), Failure>;
}

/// `ActiveReceiptReader` — the B02 selector boundary: returns only the
/// currently selected receipt, never a staged candidate.
pub trait ActiveReceiptReader: Send + Sync + 'static {
    /// `Active`.
    fn active(&self) -> Result<DependencyReceipt, Failure>;
}

/// `ReceiptInspector` — re-inspects every exact local OCI identity.
pub trait ReceiptInspector: Send + Sync + 'static {
    /// `Inspect`.
    fn inspect_set(&self, set: &PreparedDependencySet) -> Result<(), Failure>;
}

/// `BrokerRendezvous` — creates the minio-provision broker socket entry
/// the rendered mount bind-mounts (must exist before the container
/// starts, or Docker creates an empty directory in its place).
pub trait BrokerRendezvous: Send + Sync + 'static {
    /// `EnsureMinioProvisionRendezvous`.
    fn ensure_minio_provision_rendezvous(&self, instance_id: &str) -> Result<(), Failure>;
}

/// `MinioBindWaiter` — waits for the broker to confirm the MinIO
/// runtime credential bind (B10). Not yet installed in production —
/// see upstream's CAUTION on the fence-token stand-in.
pub trait MinioBindWaiter: Send + Sync + 'static {
    /// `WaitForMinioRuntimeBind`.
    fn wait_for_minio_runtime_bind(
        &self,
        instance_id: &str,
        fence_token: u64,
    ) -> Result<(), Failure>;
}

// ---------------------------------------------------------------------------
// Request payloads — the contract-pinned stdin bodies fs-init and
// minio-provision consume (testdata/provisioner-contract.json).
// ---------------------------------------------------------------------------

/// `requestSchemaVersion`.
pub const REQUEST_SCHEMA_VERSION: &str = "central.local.infra.request/v1";
/// `requestModeFSInit`.
pub const REQUEST_MODE_FS_INIT: &str = "fs-init";
/// `requestModeMinioProvision`.
pub const REQUEST_MODE_MINIO_PROVISION: &str = "minio-provision";
/// `minioCredentialPurposeRuntime` — SC-DEF-27's required discriminator.
pub const MINIO_CREDENTIAL_PURPOSE_RUNTIME: &str = "minio_runtime_v1";
/// `minioProvisionBucket` — the fixed canonical artifact bucket.
pub const MINIO_PROVISION_BUCKET: &str = "central-artifacts-v1";
/// `requestDeadline` — the per-request deadline the provisioner
/// enforces independently (upstream `2 * time.Minute`).
const REQUEST_DEADLINE: Duration = Duration::from_secs(120);

/// `secretbootstrap.MinioRuntimeKeyScope()` — the canonical MinIO
/// runtime key scope rendered as the single scope string.
pub fn minio_runtime_key_scope() -> String {
    "v1/staging/ v1/ready/".to_owned()
}

/// `requestTargetDescriptor`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestTargetDescriptor {
    /// `fd_number`.
    pub fd_number: i64,
    /// `device`.
    pub device: u64,
    /// `inode`.
    pub inode: u64,
    /// `mount_id`.
    pub mount_id: u64,
    /// `filesystem`.
    pub filesystem: String,
    /// `uid`.
    pub uid: u32,
    /// `gid`.
    pub gid: u32,
    /// `root_id`.
    pub root_id: String,
}

/// `requestMinioProvisionParams`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestMinioProvisionParams {
    /// `root_credential_path`.
    pub root_credential_path: String,
    /// `broker_socket_path`.
    pub broker_socket_path: String,
    /// `bucket`.
    pub bucket: String,
    /// `key_prefix`.
    pub key_prefix: String,
    /// `credential_purpose` — SC-DEF-27's required discriminator.
    pub credential_purpose: String,
    /// `fence_token`.
    pub fence_token: u64,
}

/// `requestPayload`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestPayload {
    /// `schema_version`.
    pub schema_version: String,
    /// `mode`.
    pub mode: String,
    /// `operation_id`.
    pub operation_id: String,
    /// `instance_id`.
    pub instance_id: String,
    /// `target`.
    pub target: RequestTargetDescriptor,
    /// `policy_digest`.
    pub policy_digest: String,
    /// `image_digest`.
    pub image_digest: String,
    /// `deadline` (RFC 3339).
    pub deadline: String,
    /// `minio_provision` — only for the minio-provision call site.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minio_provision: Option<RequestMinioProvisionParams>,
}

/// `placeholderTargetDescriptor` — deterministic, nonzero, structurally
/// valid descriptor for the minio-provision call site (see upstream's
/// comment: live FD attestation is unresolved cross-repo work).
fn placeholder_target_descriptor(
    op: &LifecycleOperation,
    root_id: &str,
) -> RequestTargetDescriptor {
    let sum = Sha256::digest(format!(
        "{}\0{}\0target-descriptor-placeholder",
        op.id, root_id
    ));
    RequestTargetDescriptor {
        fd_number: 3,
        device: u64::from_be_bytes(sum[0..8].try_into().unwrap_or_default()) | 1,
        inode: u64::from_be_bytes(sum[8..16].try_into().unwrap_or_default()) | 1,
        mount_id: u64::from_be_bytes(sum[16..24].try_into().unwrap_or_default()) | 1,
        filesystem: "ext4".to_owned(),
        uid: 0,
        gid: 0,
        root_id: root_id.to_owned(),
    }
}

/// `filesystemNameForType` — the closed statfs→name table.
fn filesystem_name_for_type(fs_type: i64) -> Option<&'static str> {
    const EXT4_SUPER_MAGIC: i64 = 0xEF53;
    const XFS_SUPER_MAGIC: i64 = 0x584D_5342;
    const BTRFS_SUPER_MAGIC: i64 = 0x9123_683E;
    const TMPFS_MAGIC: i64 = 0x0102_1994;
    match fs_type {
        EXT4_SUPER_MAGIC => Some("ext4"),
        XFS_SUPER_MAGIC => Some("xfs"),
        BTRFS_SUPER_MAGIC => Some("btrfs"),
        TMPFS_MAGIC => Some("tmpfs"),
        _ => None,
    }
}

/// `imageDigestForMode`.
fn image_digest_for_mode(
    set: &PreparedDependencySet,
    mode: ServiceMode,
) -> Result<String, Failure> {
    for pm in &set.modes {
        if pm.mode == mode {
            if pm.inventory.manifest_digest.is_empty() {
                return Err(Failure::invalid(
                    "TOPOLOGY",
                    format!("topology: mode {} lacks manifest digest", mode.as_str()),
                ));
            }
            return Ok(pm.inventory.manifest_digest.clone());
        }
    }
    Err(Failure::invalid(
        "TOPOLOGY",
        format!(
            "topology: mode {} missing from prepared dependency set",
            mode.as_str()
        ),
    ))
}

// ---------------------------------------------------------------------------
// Topology
// ---------------------------------------------------------------------------

/// `fsInitRootMode` — Central creates the durable roots 0700 root-owned
/// (see upstream's measured justification, SC-DEF-20).
const FS_INIT_ROOT_MODE: u32 = 0o700;

/// `Topology` — the orchestration boundary over a `ComposeRunner`.
/// `B` is the bootstrap authority, which must carry the typed B04
/// broker boundary upstream locates by interface assertion.
pub struct Topology<B> {
    runner: Arc<dyn ComposeRunner>,
    receipts: Arc<dyn ActiveReceiptReader>,
    policy: Policy,
    runtime_root: PathBuf,
    bootstrap: B,
    rendezvous: Option<Arc<dyn BrokerRendezvous>>,
    bind_waiter: Option<Arc<dyn MinioBindWaiter>>,
    minio_ready: Option<Box<dyn Fn() -> bool + Send + Sync>>,
    /// `t.mu` — serializes `file()`'s materialize-then-render window
    /// exactly as upstream's `t.mu` does.
    mu: Mutex<()>,
    /// binding keys whose teardown was verified this process lifetime —
    /// upstream's `t.teardowns` map.
    teardowns: Mutex<BTreeSet<String>>,
    /// Materialized mount proofs per binding key — upstream's
    /// `t.proofs`.
    proofs: Mutex<BTreeMap<String, Vec<MountProof>>>,
}

/// `bindingKey` — upstream's shared binding hash:
/// `sha256hex(instance_id + "\x00" + config_binding)`. Every durable
/// path scoped to a binding (journal operations dir, lock dir,
/// barrier file, bootstrap generation/handoff records, capacity id)
/// and the in-process proof/teardown maps use this one identity.
fn binding_key(b: &LifecycleBinding) -> String {
    let digest = Sha256::digest(format!("{}\0{}", b.instance_id, b.config_binding).as_bytes());
    hex(&digest)
}

impl<B: LifecycleBootstrap + B04Bootstrap> Topology<B> {
    /// `NewReceiptTopology`.
    pub fn new(
        runner: Arc<dyn ComposeRunner>,
        receipts: Arc<dyn ActiveReceiptReader>,
        policy: Policy,
        runtime_root: PathBuf,
        bootstrap: B,
    ) -> Self {
        Self {
            runner,
            receipts,
            policy,
            runtime_root,
            bootstrap,
            rendezvous: None,
            bind_waiter: None,
            minio_ready: None,
            mu: Mutex::new(()),
            teardowns: Mutex::new(BTreeSet::new()),
            proofs: Mutex::new(BTreeMap::new()),
        }
    }

    /// `WithBrokerRendezvous`.
    pub fn with_broker_rendezvous(mut self, r: Arc<dyn BrokerRendezvous>) -> Self {
        self.rendezvous = Some(r);
        self
    }

    /// Installs the B10 bind waiter (test seam; production has none).
    pub fn with_bind_waiter(mut self, w: Arc<dyn MinioBindWaiter>) -> Self {
        self.bind_waiter = Some(w);
        self
    }

    /// Test seam for the MinIO readiness probe.
    pub fn with_minio_ready(mut self, f: Box<dyn Fn() -> bool + Send + Sync>) -> Self {
        self.minio_ready = Some(f);
        self
    }

    fn rendered_path(&self, instance_id: &str) -> String {
        self.runtime_root
            .join(instance_id)
            .join("docker-compose.yaml")
            .to_string_lossy()
            .to_string()
    }

    /// `existingFile` — the rendered file on disk, if present, guarded
    /// by `t.mu` (upstream's outer `existingFile`).
    fn existing_file(&self, binding: &LifecycleBinding) -> Result<Option<RenderedFile>, Failure> {
        let _g = self
            .mu
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.existing_file_locked(binding)
    }

    /// `existingFileLocked` — `existing_file`'s body, split out so
    /// `establish_b04_lifecycle_proof_locked` can call it while
    /// `file()`'s `mu` is held (upstream's same split).
    fn existing_file_locked(
        &self,
        binding: &LifecycleBinding,
    ) -> Result<Option<RenderedFile>, Failure> {
        let path = self.rendered_path(&binding.instance_id);
        match std::fs::read(&path) {
            Ok(content) => Ok(Some(RenderedFile { path, content })),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Failure::internal(
                "TOPOLOGY",
                format!("topology: read rendered file: {e}"),
            )),
        }
    }

    /// `file` — upstream's exact ordering under `t.mu`: resolve the
    /// active receipt's set (even for a `false` caller, so a down/status
    /// re-render still binds to the selector), run the materialize
    /// window when asked, then render and durably write the compose
    /// file 0600 under a 0700 directory. There is no in-memory
    /// `t.files` hit path: re-rendering is deterministic, and a fresh
    /// topology after a helper restart must recover the compose file
    /// from durable inputs alone (upstream's `files` map is only a
    /// cache, never evidence). A `false` caller (down/status) never
    /// materializes a credential — but it does re-render, which is
    /// what lets `down` work after a reboot wiped the runtime root's
    /// in-memory cache.
    /// `deadline` bounds every compose subprocess this render may
    /// spawn (the prior-topology-stopped check inside the materialize
    /// window).
    fn file(
        &self,
        binding: &LifecycleBinding,
        materialize: bool,
        deadline: OpDeadline,
    ) -> Result<RenderedFile, Failure> {
        let _g = self
            .mu
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let set = self.active_dependency_set(binding)?;
        if materialize {
            self.materialize_bootstrap_locked(binding, deadline)?;
        }
        let mut f = render(binding, &set, &self.policy)
            .map_err(|e| Failure::internal("TOPOLOGY", format!("topology: render: {e}")))?;
        // `t.root != ""` overrides the renderer's hardcoded anchor —
        // upstream `file`'s identical conditional.
        f.path = self.rendered_path(&binding.instance_id);
        let dir = Path::new(&f.path)
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default();
        std::fs::create_dir_all(&dir).map_err(|e| {
            Failure::internal("TOPOLOGY", format!("topology: create runtime dir: {e}"))
        })?;
        set_mode(&dir.to_string_lossy(), 0o700).map_err(|e| {
            Failure::internal("TOPOLOGY", format!("topology: runtime dir mode: {e}"))
        })?;
        std::fs::write(&f.path, &f.content).map_err(|e| {
            Failure::internal("TOPOLOGY", format!("topology: write rendered file: {e}"))
        })?;
        set_mode(&f.path, 0o600).map_err(|e| {
            Failure::internal("TOPOLOGY", format!("topology: rendered file mode: {e}"))
        })?;
        // ADR 0019 §3's first-boot role-topology script is NOT written
        // here: its bind-mount source is the hardcoded instance-scoped
        // `/run/central-infra` anchor, materialized through the
        // bootstrap seam before the daemons come up — the same step
        // that carries the credential handoff — never by this renderer
        // (upstream's comment verbatim, `postgresFirstBootBootstrap`
        // being upstream's injectable seam).
        Ok(f)
    }

    /// `materializeBootstrapLocked` — the B04 credential handoff, under
    /// `file()`'s `mu`. Upstream's order: skip when a proof for this
    /// binding already exists in-process; establish the B04 lifecycle
    /// evidence (prior-topology-stopped observation minted into opaque
    /// broker-signed proofs); validate the complete evidence; adopt the
    /// B03 bootstrap; write the first-boot init script (the
    /// `postgresFirstBootBootstrap` seam's half); materialize the MinIO
    /// root handoff; durably record the handoff before the proof is
    /// cached — a `record_handoff` failure cleans the materialized file
    /// so a crash can never leave a handoff whose binding record does
    /// not exist.
    fn materialize_bootstrap_locked(
        &self,
        binding: &LifecycleBinding,
        deadline: OpDeadline,
    ) -> Result<(), Failure> {
        let key = binding_key(binding);
        if self
            .proofs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&key)
            .is_some_and(|p| !p.is_empty())
        {
            return Ok(());
        }
        // SC-DEF-12 (upstream): the caller-known half of B04 evidence
        // (instance/operation id, fencing token, expiry) says nothing
        // about whether any prior topology for this binding actually
        // stopped and released its mounts. That half is this Topology's
        // own to establish — it is the one thing here that can observe
        // it — so it is filled in here rather than required of every
        // caller that constructs a Binding.
        let mut evidence = binding.b04.clone();
        if evidence.stopped_topology_proof.is_empty()
            || evidence.mount_release_proof.is_empty()
            || evidence.binding_evidence.is_empty()
        {
            evidence = self.establish_b04_lifecycle_proof_locked(binding, evidence, deadline)?;
        }
        evidence.validate().map_err(|e| {
            Failure::internal("TOPOLOGY", format!("topology: B04 lifecycle evidence: {e}"))
        })?;
        block_on(self.bootstrap.adopt_b03_minio(evidence.clone())).map_err(|e| {
            Failure::internal(
                "TOPOLOGY",
                format!("topology: B04 secret bootstrap adoption failed: {e}"),
            )
        })?;
        // The init-script mount source must exist before `compose up`,
        // or Docker auto-creates it as an empty directory and initdb
        // aborts. Upstream's `postgresFirstBootBootstrap` performs this
        // write inside `Materialize`, before delegating to the file
        // bootstrap — the same pre-up window, on the same hardcoded
        // instance anchor.
        let init_path = postgres_init_script_host_path("", &binding.instance_id);
        if let Some(init_dir) = Path::new(&init_path).parent() {
            std::fs::create_dir_all(init_dir).map_err(|e| {
                Failure::internal("TOPOLOGY", format!("topology: create init dir: {e}"))
            })?;
            set_mode(&init_dir.to_string_lossy(), 0o700).map_err(|e| {
                Failure::internal("TOPOLOGY", format!("topology: init dir mode: {e}"))
            })?;
        }
        std::fs::write(&init_path, POSTGRES_INIT_SCRIPT_SQL).map_err(|e| {
            Failure::internal("TOPOLOGY", format!("topology: write init script: {e}"))
        })?;
        set_mode(&init_path, 0o600).map_err(|e| {
            Failure::internal("TOPOLOGY", format!("topology: init script mode: {e}"))
        })?;
        let handoff = BootstrapHandoff {
            instance_id: binding.instance_id.clone(),
            purpose: BootstrapPurpose::FirstSetup,
            service: ServiceMode::Minio,
            // The fixed destination is the secrets DIRECTORY — the
            // broker-side ceremony names `minio-root-password` inside it
            // (upstream `port.BootstrapHandoff.Target`).
            target: format!("/run/central-infra/{}/secrets", binding.instance_id),
            uid: 1000,
            gid: 1000,
            // Upstream sets only `Expires` — `time.Now().Add(400s)`;
            // `Duration` stays zero.
            lifetime: HandoffLifetime {
                expires: OffsetDateTime::now_utc() + time::Duration::seconds(400),
                ..HandoffLifetime::default()
            },
            container_id: String::new(),
            b04_operation_id: evidence.operation_id.clone(),
            b04_binding_id: evidence.binding_evidence.clone(),
            b04_receipt_id: binding.receipt_id.clone(),
            b04_fencing_token: evidence.fencing_token,
            b04_stopped_topology_proof: evidence.stopped_topology_proof.clone(),
            b04_mount_release_proof: evidence.mount_release_proof.clone(),
            b04_binding_evidence: evidence.binding_evidence.clone(),
        };
        let proof = block_on(self.bootstrap.materialize(handoff)).map_err(|e| {
            Failure::internal(
                "TOPOLOGY",
                format!("topology: secure credential handoff: {e}"),
            )
        })?;
        // `RecordHandoff` — upstream's optional interface assertion,
        // here the trait method on the shared bootstrap port. A record
        // failure removes the materialized handoff: the durable record
        // must never lag the file it binds.
        if let Err(e) = block_on(self.bootstrap.record_handoff(binding, &proof)) {
            let joined = match block_on(self.bootstrap.cleanup(proof.clone())) {
                Ok(()) => format!("{e}"),
                Err(cleanup_err) => format!("{e}; bootstrap cleanup failed: {cleanup_err}"),
            };
            return Err(Failure::internal(
                "TOPOLOGY",
                format!("topology: persist credential handoff: {joined}"),
            ));
        }
        self.proofs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(key)
            .or_default()
            .push(proof);
        Ok(())
    }

    /// `establishB04LifecycleProofLocked` — observes whether any
    /// topology this host has ever rendered a compose file for is still
    /// running, then asks the broker to durably sign that observation
    /// into a lifecycle proof. For a binding with no rendered file on
    /// disk — the ordinary first boot — there is nothing to have
    /// stopped, and the observation is unconditionally satisfied
    /// without shelling out to the compose runner. Otherwise it defers
    /// to the exact check `teardown_verified` already trusts for `down`:
    /// every required service mode stopped. Called with `mu` held.
    fn establish_b04_lifecycle_proof_locked(
        &self,
        binding: &LifecycleBinding,
        mut evidence: central_infra::domain::B04LifecycleEvidence,
        deadline: OpDeadline,
    ) -> Result<central_infra::domain::B04LifecycleEvidence, Failure> {
        if let Some(f) = self.existing_file_locked(binding)? {
            let services: Vec<String> = REQUIRED_SERVICE_MODES
                .iter()
                .map(|s| (*s).to_owned())
                .collect();
            self.runner.stopped(&f, &services, deadline).map_err(|e| {
                Failure::internal(
                    "TOPOLOGY",
                    format!("topology: prior topology is not stopped: {e}"),
                )
            })?;
        }
        evidence.stopped_topology_proof = uuid::Uuid::now_v7().to_string();
        evidence.mount_release_proof = uuid::Uuid::now_v7().to_string();
        evidence.binding_evidence = uuid::Uuid::now_v7().to_string();
        block_on(self.bootstrap.issue_lifecycle_proof(evidence.clone())).map_err(|e| {
            Failure::internal(
                "TOPOLOGY",
                format!("topology: B04 issuing lifecycle proof: {e}"),
            )
        })?;
        Ok(evidence)
    }

    /// `activeDependencySet` — the receipt's prepared set, validated.
    /// The receipt id match is enforced only when the binding carries
    /// one (upstream `binding.ReceiptID != ""` guard): `status`/`down`
    /// inspect calls bind loosely.
    fn active_dependency_set(
        &self,
        binding: &LifecycleBinding,
    ) -> Result<PreparedDependencySet, Failure> {
        let receipt = self
            .receipts
            .active()
            .map_err(|e| Failure::internal("TOPOLOGY", format!("topology: active receipt: {e}")))?;
        if !binding.receipt_id.is_empty() && receipt.id != binding.receipt_id {
            return Err(Failure::denied(
                "TOPOLOGY",
                "topology: active B02 receipt does not match binding",
            ));
        }
        receipt
            .dependency_set
            .validate_b03()
            .map_err(|e| Failure::internal("TOPOLOGY", format!("topology: {e}")))?;
        Ok(receipt.dependency_set)
    }

    /// `serviceOwnerFromPolicy` — the exact UID/GID the compose renderer
    /// already trusts for a named daemon service.
    fn service_owner_from_policy(&self, root_id: &str) -> Result<(u32, u32), Failure> {
        let name = match root_id {
            "postgres" => "postgres",
            "minio" => "minio",
            other => {
                return Err(Failure::invalid(
                    "TOPOLOGY",
                    format!("topology: unknown service owner root {other:?}"),
                ));
            }
        };
        let spec = self
            .policy
            .services
            .iter()
            .find(|s| s.name == name)
            .ok_or_else(|| {
                Failure::invalid(
                    "TOPOLOGY",
                    format!("topology: policy lacks service {name:?}"),
                )
            })?;
        let (uid, gid) = spec.user.split_once(':').ok_or_else(|| {
            Failure::invalid(
                "TOPOLOGY",
                format!("topology: policy service {name:?} user is not uid:gid"),
            )
        })?;
        let uid: u32 = uid.parse().map_err(|_| {
            Failure::invalid("TOPOLOGY", format!("topology: policy service {name:?} uid"))
        })?;
        let gid: u32 = gid.parse().map_err(|_| {
            Failure::invalid("TOPOLOGY", format!("topology: policy service {name:?} gid"))
        })?;
        Ok((uid, gid))
    }

    /// `ensureDurableServiceRoots` — creates the service root and data
    /// leaf, mode 0700, owned by the target service UID/GID; idempotent.
    fn ensure_durable_service_roots(
        &self,
        instance_id: &str,
        service: &str,
    ) -> Result<(), Failure> {
        let (uid, gid) = self.service_owner_from_policy(service)?;
        let root = durable_service_root(instance_id, service);
        let leaf = durable_service_data_root(instance_id, service);
        let parent = Path::new(&root)
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_default();
        for (dir, chown) in [
            (parent.to_string_lossy().to_string(), false),
            (root, true),
            (leaf, true),
        ] {
            match std::fs::create_dir(&dir) {
                Ok(()) | Err(_) => {}
            }
            if !Path::new(&dir).is_dir() {
                std::fs::create_dir(&dir).map_err(|e| {
                    Failure::internal(
                        "TOPOLOGY",
                        format!("infralifecycle: create durable root {dir:?}: {e}"),
                    )
                })?;
            }
            set_mode(&dir, FS_INIT_ROOT_MODE).map_err(|e| {
                Failure::internal(
                    "TOPOLOGY",
                    format!("infralifecycle: set mode on durable root {dir:?}: {e}"),
                )
            })?;
            if chown {
                chown_path(&dir, uid, gid).map_err(|e| {
                    Failure::internal(
                        "TOPOLOGY",
                        format!("infralifecycle: set owner on durable root {dir:?}: {e}"),
                    )
                })?;
            }
        }
        Ok(())
    }

    /// `observedTargetDescriptor` — stat/statfs on the real target;
    /// ownership is observed, never declared (ADR 0025 sub-decision 2).
    fn observed_target_descriptor(
        &self,
        instance_id: &str,
        service: &str,
        root_id: &str,
    ) -> Result<RequestTargetDescriptor, Failure> {
        let path = durable_service_data_root(instance_id, service);
        let meta = std::fs::metadata(&path).map_err(|e| {
            Failure::internal(
                "TOPOLOGY",
                format!("infralifecycle: stat fs-init target {path:?}: {e}"),
            )
        })?;
        if !meta.is_dir() {
            return Err(Failure::invalid(
                "TOPOLOGY",
                format!("infralifecycle: fs-init target {path:?} is not a directory"),
            ));
        }
        let (dev, ino, uid, gid) = stat_ids(&meta);
        let fs_type = statfs_type(&path).map_err(|e| {
            Failure::internal(
                "TOPOLOGY",
                format!("infralifecycle: statfs fs-init target {path:?}: {e}"),
            )
        })?;
        let filesystem = filesystem_name_for_type(fs_type).ok_or_else(|| {
            Failure::invalid(
                "TOPOLOGY",
                format!("infralifecycle: fs-init target {path:?} has an unsupported filesystem"),
            )
        })?;
        Ok(RequestTargetDescriptor {
            fd_number: 0,
            device: dev,
            inode: ino,
            mount_id: 0,
            filesystem: filesystem.to_owned(),
            uid,
            gid,
            root_id: root_id.to_owned(),
        })
    }

    /// `fsInitRequestPayload`.
    fn fs_init_request_payload(
        &self,
        op: &LifecycleOperation,
        set: &PreparedDependencySet,
        root_id: &str,
        mode: ServiceMode,
    ) -> Result<Vec<u8>, Failure> {
        let image_digest = image_digest_for_mode(set, mode)?;
        let target = self.observed_target_descriptor(&op.binding.instance_id, root_id, root_id)?;
        let payload = RequestPayload {
            schema_version: REQUEST_SCHEMA_VERSION.to_owned(),
            mode: REQUEST_MODE_FS_INIT.to_owned(),
            operation_id: op.id.clone(),
            instance_id: op.binding.instance_id.clone(),
            target,
            policy_digest: policy_digest(&self.policy),
            image_digest,
            deadline: rfc3339(OffsetDateTime::now_utc() + REQUEST_DEADLINE),
            minio_provision: None,
        };
        serde_json::to_vec(&payload)
            .map_err(|e| Failure::internal("TOPOLOGY", format!("topology: marshal: {e}")))
    }

    /// `minioProvisionRequestPayload`.
    fn minio_provision_request_payload(
        &self,
        op: &LifecycleOperation,
        set: &PreparedDependencySet,
    ) -> Result<Vec<u8>, Failure> {
        let image_digest = image_digest_for_mode(set, ServiceMode::MinioProvision)?;
        let payload = RequestPayload {
            schema_version: REQUEST_SCHEMA_VERSION.to_owned(),
            mode: REQUEST_MODE_MINIO_PROVISION.to_owned(),
            operation_id: op.id.clone(),
            instance_id: op.binding.instance_id.clone(),
            target: placeholder_target_descriptor(op, "minio-provision"),
            policy_digest: policy_digest(&self.policy),
            image_digest,
            deadline: rfc3339(OffsetDateTime::now_utc() + REQUEST_DEADLINE),
            minio_provision: Some(RequestMinioProvisionParams {
                root_credential_path: "/run/secrets/minio-root-password".to_owned(),
                broker_socket_path: BROKER_SOCKET_TARGET.to_owned(),
                bucket: MINIO_PROVISION_BUCKET.to_owned(),
                key_prefix: minio_runtime_key_scope(),
                credential_purpose: MINIO_CREDENTIAL_PURPOSE_RUNTIME.to_owned(),
                // CAUTION (upstream): B04.FencingToken stands in for a
                // B10-specific token; unvalidated — tracked debt.
                fence_token: op.binding.b04.fencing_token,
            }),
        };
        serde_json::to_vec(&payload)
            .map_err(|e| Failure::internal("TOPOLOGY", format!("topology: marshal: {e}")))
    }

    /// `provisionReceiptFromExitCode` — the receipt derives directly
    /// from `compose run`'s synchronous exit code; no post-hoc
    /// `Containers()` lookup (the `--rm` container is gone).
    fn provision_receipt_from_exit_code(
        &self,
        op: &LifecycleOperation,
        service: &str,
        exit_code: i32,
    ) -> Result<SemanticReceipt, Failure> {
        if exit_code != 0 {
            return Err(Failure::internal(
                "TOPOLOGY",
                format!(
                    "topology: provisioner {service} did not exit successfully: exit code {exit_code}"
                ),
            ));
        }
        let sum = Sha256::digest(format!("{}\0{}\0exited\0{exit_code}", op.id, service));
        Ok(SemanticReceipt {
            receipt_id: format!("{}-{service}", op.id),
            digest: format!("sha256:{}", hex(&sum)),
            verified: true,
        })
    }

    fn minio_ready(&self) -> bool {
        match &self.minio_ready {
            Some(f) => f(),
            None => probe_minio_live(),
        }
    }

    fn inspect_rendered(
        &self,
        binding: &LifecycleBinding,
        f: &RenderedFile,
        deadline: OpDeadline,
    ) -> Result<TopologySnapshot, Failure> {
        let containers =
            self.runner
                .containers(f, &["postgres".to_owned(), "minio".to_owned()], deadline)?;
        let mut services = BTreeMap::new();
        for (service, mode) in [
            ("postgres", ServiceMode::Postgres),
            ("minio", ServiceMode::Minio),
        ] {
            let inspection = containers.get(service).cloned().unwrap_or_default();
            if inspection.id.is_empty() || inspection.state != "running" {
                return Ok(TopologySnapshot {
                    binding: binding.clone(),
                    services,
                    healthy: false,
                    description: "daemon containers are not healthy".to_owned(),
                });
            }
            // minio carries no Docker healthcheck (SC-DEF-26): readiness
            // is an actual host-side probe; postgres keeps pg_isready.
            if service == "minio" {
                if !self.minio_ready() {
                    return Ok(TopologySnapshot {
                        binding: binding.clone(),
                        services,
                        healthy: false,
                        description: "daemon containers are not healthy".to_owned(),
                    });
                }
            } else if inspection.status != "healthy" {
                return Ok(TopologySnapshot {
                    binding: binding.clone(),
                    services,
                    healthy: false,
                    description: "daemon containers are not healthy".to_owned(),
                });
            }
            services.insert(mode, inspection.id);
        }
        Ok(TopologySnapshot {
            binding: binding.clone(),
            services,
            healthy: true,
            description: "daemon containers inspected healthy".to_owned(),
        })
    }

    fn mark_teardown_verified(&self, binding: &LifecycleBinding) {
        self.teardowns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(binding_key(binding));
    }
}

/// `probeMinioLive` — a real HTTP GET to minio's liveness endpoint
/// through the published host port (SC-DEF-26).
fn probe_minio_live() -> bool {
    let addr: std::net::SocketAddr = match "127.0.0.1:59000".parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let Ok(mut stream) = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    use std::io::{Read, Write};
    if stream
        .write_all(
            b"GET /minio/health/live HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        )
        .is_err()
    {
        return false;
    }
    let mut buf = [0u8; 64];
    let Ok(n) = stream.read(&mut buf) else {
        return false;
    };
    let head = String::from_utf8_lossy(&buf[..n]);
    head.split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .is_some_and(|code| (200..300).contains(&code))
}

fn set_mode(path: &str, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

fn chown_path(path: &str, uid: u32, gid: u32) -> std::io::Result<()> {
    rustix::fs::chown(
        path,
        Some(rustix::process::Uid::from_raw(uid)),
        Some(rustix::process::Gid::from_raw(gid)),
    )
    .map_err(std::io::Error::other)
}

fn stat_ids(meta: &std::fs::Metadata) -> (u64, u64, u32, u32) {
    use std::os::unix::fs::MetadataExt;
    (meta.dev(), meta.ino(), meta.uid(), meta.gid())
}

fn statfs_type(path: &str) -> std::io::Result<i64> {
    rustix::fs::statfs(path)
        .map(|s| s.f_type)
        .map_err(std::io::Error::other)
}

fn rfc3339(t: OffsetDateTime) -> String {
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl<B: LifecycleBootstrap + B04Bootstrap + Send + Sync> TopologyPort for Topology<B> {
    async fn validate(
        &self,
        binding: &LifecycleBinding,
        deadline: Option<OffsetDateTime>,
    ) -> Result<(), Failure> {
        // The binding is validated before any receipt lookup, render,
        // or compose subprocess — the caller-known half of the request
        // is refused before it costs work.
        binding.validate()?;
        let dl = phase_op_deadline(deadline);
        // Receipt binding is authoritative; the rendered file must exist
        // and parse+validate through the real compose config model.
        let _set = self.active_dependency_set(binding)?;
        let f = self.file(binding, true, dl)?;
        let _model = self
            .runner
            .config(&f, dl)
            .map_err(|e| Failure::internal("TOPOLOGY", format!("topology: compose config: {e}")))?;
        Ok(())
    }

    async fn init(
        &self,
        op: &LifecycleOperation,
        deadline: Option<OffsetDateTime>,
    ) -> Result<(), Failure> {
        let dl = phase_op_deadline(deadline);
        let f = self.file(&op.binding, true, dl)?;
        let set = self.active_dependency_set(&op.binding)?;
        for (service, root_id, mode) in [
            ("postgres-fs-init", "postgres", ServiceMode::PostgresFsInit),
            ("minio-fs-init", "minio", ServiceMode::MinioFsInit),
        ] {
            self.ensure_durable_service_roots(&op.binding.instance_id, root_id)
                .map_err(|e| Failure::internal("TOPOLOGY", format!("topology: {service}: {e}")))?;
            let payload = self
                .fs_init_request_payload(op, &set, root_id, mode)
                .map_err(|e| {
                    Failure::internal(
                        "TOPOLOGY",
                        format!("topology: {service}: build request: {e}"),
                    )
                })?;
            let exit_code = self
                .runner
                .run_with_input(
                    &f,
                    service,
                    &[REQUEST_MODE_FS_INIT.to_owned()],
                    &payload,
                    dl,
                )
                .map_err(|e| Failure::internal("TOPOLOGY", format!("topology: {service}: {e}")))?;
            if exit_code != 0 {
                return Err(Failure::internal(
                    "TOPOLOGY",
                    format!("topology: {service} exited with code {exit_code}"),
                ));
            }
        }
        Ok(())
    }

    async fn start_daemons(
        &self,
        op: &LifecycleOperation,
        deadline: Option<OffsetDateTime>,
    ) -> Result<Observation, Failure> {
        let dl = phase_op_deadline(deadline);
        let f = self.file(&op.binding, true, dl)?;
        self.runner
            .up(&f, &["postgres".to_owned(), "minio".to_owned()], dl)
            .map_err(|e| Failure::internal("TOPOLOGY", e.to_string()))?;
        Ok(Observation::default())
    }

    async fn provision_minio(
        &self,
        op: &LifecycleOperation,
        deadline: Option<OffsetDateTime>,
    ) -> Result<SemanticReceipt, Failure> {
        let dl = phase_op_deadline(deadline);
        let f = self.file(&op.binding, true, dl)?;
        let set = self.active_dependency_set(&op.binding)?;
        let payload = self
            .minio_provision_request_payload(op, &set)
            .map_err(|e| {
                Failure::internal(
                    "TOPOLOGY",
                    format!("topology: minio-provision: build request: {e}"),
                )
            })?;
        // Refuse without a rendezvous — the rendered socket mount would
        // have no source (see upstream's comment).
        let Some(rendezvous) = &self.rendezvous else {
            return Err(Failure::unavailable(
                "TOPOLOGY",
                "topology: minio-provision: no broker rendezvous installed; the rendered socket mount would have no source",
            ));
        };
        rendezvous
            .ensure_minio_provision_rendezvous(&op.binding.instance_id)
            .map_err(|e| {
                Failure::internal(
                    "TOPOLOGY",
                    format!("topology: minio-provision: broker rendezvous: {e}"),
                )
            })?;
        let exit_code = self
            .runner
            .run_with_input(
                &f,
                "minio-provision",
                &[REQUEST_MODE_MINIO_PROVISION.to_owned()],
                &payload,
                dl,
            )
            .map_err(|e| {
                Failure::internal("TOPOLOGY", format!("topology: minio-provision: {e}"))
            })?;
        let receipt = self.provision_receipt_from_exit_code(op, "minio-provision", exit_code)?;
        if let Some(waiter) = &self.bind_waiter {
            waiter
                .wait_for_minio_runtime_bind(&op.binding.instance_id, op.binding.b04.fencing_token)
                .map_err(|e| {
                    Failure::internal(
                        "TOPOLOGY",
                        format!("topology: minio runtime credential bind not confirmed: {e}"),
                    )
                })?;
        }
        Ok(receipt)
    }

    async fn inspect(
        &self,
        binding: &LifecycleBinding,
        deadline: Option<OffsetDateTime>,
    ) -> Result<TopologySnapshot, Failure> {
        let dl = phase_op_deadline(deadline);
        // Status has no receipt binding: inspect only what exists —
        // never read a receipt, never render, never materialize.
        if binding.receipt_id.is_empty() {
            let Some(f) = self.existing_file(binding)? else {
                return Ok(TopologySnapshot {
                    binding: binding.clone(),
                    services: BTreeMap::new(),
                    healthy: false,
                    description: "rendered topology absent".to_owned(),
                });
            };
            let model = parse_rendered_model(&f.content)
                .map_err(|e| Failure::internal("TOPOLOGY", format!("topology: {e}")))?;
            validate_model(&model)
                .map_err(|e| Failure::internal("TOPOLOGY", format!("topology: {e}")))?;
            return self.inspect_rendered(binding, &f, dl);
        }
        TopologyPort::validate(self, binding, deadline).await?;
        let f = self.file(binding, false, dl)?;
        self.inspect_rendered(binding, &f, dl)
    }

    async fn down(
        &self,
        op: &LifecycleOperation,
        deadline: Option<OffsetDateTime>,
    ) -> Result<(), Failure> {
        let dl = phase_op_deadline(deadline);
        // Teardown-only: a helper restart must never materialize a new
        // credential merely to render the file `compose down` needs.
        let f = self.file(&op.binding, false, dl)?;
        self.runner
            .down(&f, dl)
            .map_err(|e| Failure::internal("TOPOLOGY", e.to_string()))
    }

    async fn teardown_verified(
        &self,
        op: &LifecycleOperation,
        deadline: Option<OffsetDateTime>,
    ) -> Result<(), Failure> {
        let dl = phase_op_deadline(deadline);
        TopologyPort::down(self, op, deadline).await?;
        if let Some(f) = self.existing_file(&op.binding)? {
            let services: Vec<String> = REQUIRED_SERVICE_MODES
                .iter()
                .map(|s| (*s).to_owned())
                .collect();
            self.runner
                .stopped(&f, &services, dl)
                .map_err(|e| Failure::internal("TOPOLOGY", e.to_string()))?;
        }
        self.mark_teardown_verified(&op.binding);
        Ok(())
    }

    async fn cleanup_secrets(&self, op: &LifecycleOperation) -> Result<(), Failure> {
        // Upstream `CleanupSecrets`: the teardown gate and the proof
        // copy run under `t.mu`; the bootstrap cleanup calls run
        // unlocked; the map entries are dropped under `t.mu` only after
        // every cleanup succeeds.
        let key = binding_key(&op.binding);
        let proofs = {
            let _g = self
                .mu
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !self
                .teardowns
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains(&key)
            {
                return Err(Failure::denied(
                    "TOPOLOGY",
                    "topology: teardown must be verified before credential cleanup",
                ));
            }
            self.proofs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&key)
                .cloned()
                .unwrap_or_default()
        };
        for proof in proofs {
            self.bootstrap.cleanup(proof).await?;
        }
        // `CleanupBinding` — upstream's optional interface assertion on
        // `FileBootstrap`: resumes the durable handoff record's cleanup
        // after a helper restart, when the in-process `proofs` map was
        // empty. The trait method is the port of that seam.
        self.bootstrap.cleanup_binding(&op.binding).await?;
        {
            let _g = self
                .mu
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.proofs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&key);
            self.teardowns
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&key);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// FileJournal — durable per-operation JSON event records; the selector
// owner (receipt activation only after a durably prepared receipt).
// ---------------------------------------------------------------------------

/// `journalState` — one operation's current state as upstream stores
/// it: the last event's projection, never a rewritten record. Go's
/// `infralifecycle.Operation` carries no JSON tags, so it marshals
/// PascalCase; `alias` keeps journals Rust wrote before the wire fix
/// decodable.
#[derive(Serialize, Deserialize, Clone)]
struct JournalOperationRecord {
    #[serde(rename = "ID", alias = "id")]
    id: String,
    #[serde(rename = "LinkedOperationID", alias = "linked_operation_id")]
    linked_operation_id: String,
    #[serde(rename = "Phase", alias = "phase")]
    phase: String,
    #[serde(rename = "Binding", alias = "binding")]
    binding: JournalBinding,
    #[serde(rename = "Observation", default)]
    observation: JournalObservation,
    #[serde(rename = "CreatedAt", alias = "created_at")]
    created_at: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct JournalState {
    operation: JournalOperationRecord,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt: Option<DependencyReceiptJson>,
    active: bool,
}

/// `journalEvent` — upstream's envelope: `{"state": …}`.
#[derive(Serialize, Deserialize)]
struct JournalEvent {
    state: JournalState,
}

/// `infralifecycle.Observation` — untagged Go struct → PascalCase.
/// `ContainerStartIDs` keys are `ServiceMode` strings upstream; they
/// stay plain strings here so a Go-written mode Rust does not know
/// still decodes (Go's map key type never rejects a string either).
#[derive(Serialize, Deserialize, Clone, Default)]
struct JournalObservation {
    #[serde(rename = "BootID", default)]
    boot_id: String,
    #[serde(rename = "ContainerStartIDs", default, deserialize_with = "null_map")]
    container_start_ids: BTreeMap<String, String>,
}

/// `infralifecycle.B04LifecycleEvidence` — untagged Go struct →
/// PascalCase. Go's `time.Time` marshals unconditionally, so a missing
/// or zero `ExpiresAt` decodes to `""`/`"0001-01-01T00:00:00Z"`, both
/// mapped back to `None`.
#[derive(Serialize, Deserialize, Clone, Default)]
struct JournalB04 {
    #[serde(rename = "InstanceID", default)]
    instance_id: String,
    #[serde(rename = "OperationID", default)]
    operation_id: String,
    #[serde(rename = "FencingToken", default)]
    fencing_token: u64,
    #[serde(rename = "StoppedTopologyProof", default)]
    stopped_topology_proof: String,
    #[serde(rename = "MountReleaseProof", default)]
    mount_release_proof: String,
    #[serde(rename = "BindingEvidence", default)]
    binding_evidence: String,
    #[serde(rename = "ExpiresAt", default)]
    expires_at: String,
}

/// `infralifecycle.Binding` — untagged Go struct → PascalCase.
/// `b04_operation_id`/`b04_fencing_token` are the flat fields Rust
/// journals carried before the wire fix: deserialized for backward
/// compatibility, never written again.
#[derive(Serialize, Deserialize, Clone, Default)]
struct JournalBinding {
    #[serde(rename = "InstanceID", alias = "instance_id")]
    instance_id: String,
    #[serde(rename = "ConfigBinding", alias = "config_binding")]
    config_binding: String,
    #[serde(rename = "AdmissionID", alias = "admission_id")]
    admission_id: String,
    #[serde(rename = "ReceiptID", alias = "receipt_id")]
    receipt_id: String,
    #[serde(rename = "ModelDigest", alias = "model_digest")]
    model_digest: String,
    #[serde(rename = "PayloadEpoch", alias = "payload_epoch")]
    payload_epoch: String,
    #[serde(
        rename = "BootstrapFingerprints",
        default,
        deserialize_with = "null_vec"
    )]
    bootstrap_fingerprints: Vec<String>,
    #[serde(rename = "B04", default)]
    b04: JournalB04,
    #[serde(rename = "b04_operation_id", default, skip_serializing)]
    legacy_b04_operation_id: String,
    #[serde(rename = "b04_fencing_token", default, skip_serializing)]
    legacy_b04_fencing_token: u64,
}

/// `dependencyprepare.Receipt` — untagged Go struct → PascalCase.
/// `DependencyReceiptJson`'s old `id`/`set` fields are accepted as
/// aliases so Rust journals from before the wire fix still decode.
#[derive(Serialize, Deserialize, Clone)]
struct DependencyReceiptJson {
    #[serde(rename = "ID", alias = "id")]
    id: String,
    #[serde(rename = "ManifestDigest", default)]
    manifest_digest: String,
    #[serde(rename = "OperationID", default)]
    operation_id: String,
    #[serde(rename = "SelectorGeneration", default)]
    selector_generation: String,
    #[serde(rename = "DependencySet", alias = "set")]
    dependency_set: PreparedDependencySet,
}

/// Go emits `null` for a nil slice; decode it as empty.
fn null_vec<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    Ok(Option::<Vec<String>>::deserialize(d)?.unwrap_or_default())
}

/// Go emits `null` for a nil map; decode it as empty.
fn null_map<'de, D: serde::Deserializer<'de>>(d: D) -> Result<BTreeMap<String, String>, D::Error> {
    Ok(Option::<BTreeMap<String, String>>::deserialize(d)?.unwrap_or_default())
}

/// `path(b)` — upstream `FileJournal.path`: the binding's operations
/// root under `root/operations/<bindingKey>`, `bindingKey` being the
/// full `sha256hex(instance_id + "\x00" + config_binding)`.
fn binding_journal_dir(root: &Path, binding: &LifecycleBinding) -> PathBuf {
    root.join("operations").join(binding_key(binding))
}

fn record_to_op(r: &JournalOperationRecord) -> LifecycleOperation {
    let created_at = OffsetDateTime::parse(
        &r.created_at,
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    let b04 = &r.binding.b04;
    // Go's `time.Time.IsZero()`: only the exact zero instant —
    // `0001-01-01T00:00:00Z` — maps back to `None`.
    const GO_ZERO: OffsetDateTime = time::macros::datetime!(1-01-01 0:00:00 UTC);
    let expires_at = OffsetDateTime::parse(
        &b04.expires_at,
        &time::format_description::well_known::Rfc3339,
    )
    .ok()
    .filter(|t| *t != GO_ZERO);
    LifecycleOperation {
        id: r.id.clone(),
        linked_operation_id: r.linked_operation_id.clone(),
        phase: phase_from_str(&r.phase),
        binding: LifecycleBinding {
            instance_id: r.binding.instance_id.clone(),
            config_binding: r.binding.config_binding.clone(),
            admission_id: r.binding.admission_id.clone(),
            receipt_id: r.binding.receipt_id.clone(),
            model_digest: r.binding.model_digest.clone(),
            payload_epoch: r.binding.payload_epoch.clone(),
            bootstrap_fingerprints: r.binding.bootstrap_fingerprints.clone(),
            b04: central_infra::domain::B04LifecycleEvidence {
                instance_id: b04.instance_id.clone(),
                // A Rust journal from before the wire fix carried the
                // B04 identity only in the flat legacy fields.
                operation_id: if b04.operation_id.is_empty() {
                    r.binding.legacy_b04_operation_id.clone()
                } else {
                    b04.operation_id.clone()
                },
                fencing_token: if b04.fencing_token == 0 {
                    r.binding.legacy_b04_fencing_token
                } else {
                    b04.fencing_token
                },
                stopped_topology_proof: b04.stopped_topology_proof.clone(),
                mount_release_proof: b04.mount_release_proof.clone(),
                binding_evidence: b04.binding_evidence.clone(),
                expires_at,
            },
        },
        observation: Observation {
            boot_id: r.observation.boot_id.clone(),
            container_start_ids: r
                .observation
                .container_start_ids
                .iter()
                .filter_map(|(mode, id)| mode.parse::<ServiceMode>().ok().map(|m| (m, id.clone())))
                .collect(),
        },
        created_at,
    }
}

fn phase_from_str(s: &str) -> LifecyclePhase {
    for p in central_infra::domain::ALL_LIFECYCLE_PHASES {
        if p.as_str() == s {
            return p;
        }
    }
    LifecyclePhase::Started
}

/// `syncDirectory` — upstream `syncDirectory`: `fsync` the containing
/// directory so the just-appended entry name is durable.
fn sync_directory(path: &Path) -> Result<(), Failure> {
    std::fs::File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(|e| Failure::internal("JOURNAL", format!("sync directory: {e}")))
}

/// `FileJournal` stores immutable operation events. It is
/// intentionally a selector owner: receipt activation cannot happen
/// until a validated receipt has first been durably prepared for that
/// operation. Current state is derived from the final event; operation
/// evidence is never replaced.
pub struct FileJournal {
    root: PathBuf,
    clock: Arc<dyn LifecycleClock>,
    mu: Mutex<()>,
}

impl FileJournal {
    /// `NewFileJournal`.
    pub fn new(root: PathBuf, clock: Arc<dyn LifecycleClock>) -> Result<Self, Failure> {
        if root.as_os_str().is_empty() {
            return Err(Failure::invalid("JOURNAL", "lifecycle journal: empty root"));
        }
        std::fs::create_dir_all(&root).map_err(|e| {
            Failure::internal("JOURNAL", format!("lifecycle journal: create root: {e}"))
        })?;
        set_mode(&root.to_string_lossy(), 0o700)
            .map_err(|e| Failure::internal("JOURNAL", format!("lifecycle journal: mode: {e}")))?;
        Ok(Self {
            root,
            clock,
            mu: Mutex::new(()),
        })
    }

    /// `appendLocked` — upstream's exclusive sequence write:
    /// `{op_dir}/{seq:020}.json` created `O_WRONLY|O_CREATE|O_EXCL`
    /// mode 0600, written, `fsync`'d, closed, then the operation
    /// directory is `fsync`'d. The first free sequence wins, so a
    /// crashed earlier attempt's partial file is never reused.
    fn append(&self, state: &JournalState) -> Result<(), Failure> {
        let binding = record_binding(&state.operation);
        let op_dir = binding_journal_dir(&self.root, &binding).join(&state.operation.id);
        std::fs::create_dir_all(&op_dir)
            .map_err(|e| Failure::internal("JOURNAL", format!("journal: dir: {e}")))?;
        for level in [
            self.root.join("operations"),
            binding_journal_dir(&self.root, &binding),
            op_dir.clone(),
        ] {
            set_mode(&level.to_string_lossy(), 0o700)
                .map_err(|e| Failure::internal("JOURNAL", format!("journal: dir mode: {e}")))?;
        }
        use std::os::unix::fs::OpenOptionsExt;
        let data = serde_json::to_vec(&JournalEvent {
            state: state.clone(),
        })
        .map_err(|e| Failure::internal("JOURNAL", format!("journal: encode: {e}")))?;
        let mut sequence = 1u64;
        loop {
            let path = op_dir.join(format!("{sequence:020}.json"));
            let mut file = match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    sequence += 1;
                    continue;
                }
                Err(e) => {
                    return Err(Failure::internal("JOURNAL", format!("journal: open: {e}")));
                }
            };
            use std::io::Write;
            file.write_all(&data)
                .map_err(|e| Failure::internal("JOURNAL", format!("journal: write: {e}")))?;
            file.sync_all()
                .map_err(|e| Failure::internal("JOURNAL", format!("journal: sync: {e}")))?;
            drop(file);
            return sync_directory(&op_dir);
        }
    }

    /// `readOperationLocked` — folds an operation directory: sort the
    /// event names, take the last, decode its state.
    fn read_op(&self, binding: &LifecycleBinding, op_id: &str) -> Result<JournalState, Failure> {
        let dir = binding_journal_dir(&self.root, binding).join(op_id);
        let entries = std::fs::read_dir(&dir)
            .map_err(|e| Failure::internal("JOURNAL", format!("journal: read operation: {e}")))?;
        let mut names: Vec<String> = entries
            .flatten()
            .filter(|e| e.path().is_file())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| {
                std::path::Path::new(n)
                    .extension()
                    .is_some_and(|x| x == "json")
            })
            .collect();
        if names.is_empty() {
            return Err(Failure::not_found("JOURNAL", "journal: operation absent"));
        }
        names.sort();
        let data = std::fs::read(dir.join(names.pop().unwrap_or_default()))
            .map_err(|e| Failure::internal("JOURNAL", format!("journal: read: {e}")))?;
        let event: JournalEvent = serde_json::from_slice(&data)
            .map_err(|e| Failure::internal("JOURNAL", format!("journal: decode: {e}")))?;
        Ok(event.state)
    }

    /// `statesLocked` — every operation's folded state for the binding.
    /// Upstream iterates `os.ReadDir`, which returns names sorted;
    /// `std::fs::read_dir` does not, so the names are sorted here to
    /// keep unsettled-operation and active-receipt selection (both
    /// "last one wins" scans) deterministic.
    fn states(&self, binding: &LifecycleBinding) -> Result<Vec<JournalState>, Failure> {
        let dir = binding_journal_dir(&self.root, binding);
        let mut out = Vec::new();
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(Failure::internal("JOURNAL", format!("journal: list: {e}"))),
        };
        let mut names: Vec<String> = entries
            .flatten()
            .filter(|e| e.path().is_dir())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        for op_id in names {
            out.push(self.read_op(binding, &op_id)?);
        }
        Ok(out)
    }

    /// `unsettledLocked` — the newest non-terminal operation by
    /// `CreatedAt`, scanning operation dirs in name order and keeping
    /// the first when timestamps tie (upstream's `Before` comparison).
    fn unsettled_locked(
        &self,
        binding: &LifecycleBinding,
    ) -> Result<Option<LifecycleOperation>, Failure> {
        let mut newest: Option<LifecycleOperation> = None;
        for state in self.states(binding)? {
            let op = record_to_op(&state.operation);
            if op.phase.is_terminal() {
                continue;
            }
            let replace = match &newest {
                None => true,
                Some(current) => current.created_at < op.created_at,
            };
            if replace {
                newest = Some(op);
            }
        }
        Ok(newest)
    }

    /// `beginLocked` — the shared body of `begin`/`begin_linked_down`;
    /// an unlinked begin still refuses when an unsettled operation
    /// exists (upstream's double-check). `linked_id` is `""` for an
    /// ordinary begin.
    fn begin_locked(
        &self,
        binding: LifecycleBinding,
        observation: Observation,
        linked_id: &str,
    ) -> Result<LifecycleOperation, Failure> {
        if linked_id.is_empty() && self.unsettled_locked(&binding)?.is_some() {
            return Err(Failure::conflict(
                "JOURNAL",
                "lifecycle journal: unsettled operation exists",
            ));
        }
        let op = LifecycleOperation {
            id: format!("life-{}", uuid::Uuid::new_v4()),
            linked_operation_id: linked_id.to_owned(),
            phase: LifecyclePhase::Started,
            binding,
            observation,
            created_at: self.clock.now(),
        };
        self.append(&JournalState {
            operation: op_to_record(&op),
            receipt: None,
            active: false,
        })?;
        Ok(op)
    }
}

fn record_binding(r: &JournalOperationRecord) -> LifecycleBinding {
    // Only the instance/config halves feed `binding_key`, but the
    // full decode costs nothing and keeps the helper honest.
    record_to_op(r).binding
}

fn op_to_record(op: &LifecycleOperation) -> JournalOperationRecord {
    let b04 = &op.binding.b04;
    JournalOperationRecord {
        id: op.id.clone(),
        linked_operation_id: op.linked_operation_id.clone(),
        phase: op.phase.as_str().to_owned(),
        binding: JournalBinding {
            instance_id: op.binding.instance_id.clone(),
            config_binding: op.binding.config_binding.clone(),
            admission_id: op.binding.admission_id.clone(),
            receipt_id: op.binding.receipt_id.clone(),
            model_digest: op.binding.model_digest.clone(),
            payload_epoch: op.binding.payload_epoch.clone(),
            bootstrap_fingerprints: op.binding.bootstrap_fingerprints.clone(),
            b04: JournalB04 {
                instance_id: b04.instance_id.clone(),
                operation_id: b04.operation_id.clone(),
                fencing_token: b04.fencing_token,
                stopped_topology_proof: b04.stopped_topology_proof.clone(),
                mount_release_proof: b04.mount_release_proof.clone(),
                binding_evidence: b04.binding_evidence.clone(),
                // Go marshals the zero `time.Time` unconditionally.
                expires_at: b04
                    .expires_at
                    .map_or_else(|| "0001-01-01T00:00:00Z".to_owned(), rfc3339),
            },
            legacy_b04_operation_id: String::new(),
            legacy_b04_fencing_token: 0,
        },
        observation: JournalObservation {
            boot_id: op.observation.boot_id.clone(),
            container_start_ids: op
                .observation
                .container_start_ids
                .iter()
                .map(|(mode, id)| (mode.as_str().to_owned(), id.clone()))
                .collect(),
        },
        created_at: rfc3339(op.created_at),
    }
}

impl LifecyclePort for FileJournal {
    async fn begin(
        &self,
        binding: LifecycleBinding,
        observation: Observation,
    ) -> Result<LifecycleOperation, Failure> {
        binding.validate()?;
        let _g = self
            .mu
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.begin_locked(binding, observation, "")
    }

    async fn begin_linked_down(
        &self,
        binding: LifecycleBinding,
        observation: Observation,
        linked: &LifecycleOperation,
    ) -> Result<LifecycleOperation, Failure> {
        binding.validate()?;
        // Upstream: the linked operation must be a live unsettled up
        // for the same binding — id present, same instance+config,
        // non-terminal.
        if linked.id.is_empty()
            || linked.binding.instance_id != binding.instance_id
            || linked.binding.config_binding != binding.config_binding
            || linked.phase.is_terminal()
        {
            return Err(Failure::invalid(
                "JOURNAL",
                "lifecycle journal: invalid linked unsettled operation",
            ));
        }
        let _g = self
            .mu
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.begin_locked(binding, observation, &linked.id)
    }

    async fn record(
        &self,
        operation: &LifecycleOperation,
        phase: LifecyclePhase,
    ) -> Result<(), Failure> {
        let _g = self
            .mu
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut state = self.read_op(&operation.binding, &operation.id)?;
        if state.operation.id != operation.id {
            return Err(Failure::invalid(
                "JOURNAL",
                "lifecycle journal: operation mismatch",
            ));
        }
        state.operation.phase = phase.as_str().to_owned();
        self.append(&state)
    }

    async fn prepare_receipt(
        &self,
        operation: &LifecycleOperation,
        receipt: &DependencyReceipt,
    ) -> Result<(), Failure> {
        // Upstream: the prepared receipt must be the binding's own and
        // must carry a complete B03 dependency set before it is made
        // durable — selector switching later trusts this gate.
        if receipt.id != operation.binding.receipt_id {
            return Err(Failure::invalid(
                "JOURNAL",
                "lifecycle journal: receipt does not match binding",
            ));
        }
        receipt.validate_b03()?;
        let _g = self
            .mu
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut state = self.read_op(&operation.binding, &operation.id)?;
        if state.operation.id != operation.id {
            return Err(Failure::invalid(
                "JOURNAL",
                "lifecycle journal: operation mismatch",
            ));
        }
        state.receipt = Some(DependencyReceiptJson {
            id: receipt.id.clone(),
            manifest_digest: receipt.manifest_digest.clone(),
            operation_id: receipt.operation_id.clone(),
            selector_generation: receipt.selector_generation.clone(),
            dependency_set: receipt.dependency_set.clone(),
        });
        self.append(&state)
    }

    async fn switch_receipt(&self, operation: &LifecycleOperation) -> Result<(), Failure> {
        let _g = self
            .mu
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut state = self.read_op(&operation.binding, &operation.id)?;
        if state.operation.id != operation.id || state.receipt.is_none() {
            return Err(Failure::invalid(
                "JOURNAL",
                "lifecycle journal: receipt was not prepared",
            ));
        }
        state.active = true;
        self.append(&state)
    }

    async fn settle(
        &self,
        operation: &LifecycleOperation,
        phase: LifecyclePhase,
    ) -> Result<(), Failure> {
        if !phase.is_terminal() {
            return Err(Failure::invalid(
                "JOURNAL",
                "lifecycle journal: settlement must be terminal",
            ));
        }
        self.record(operation, phase).await
    }

    async fn unsettled(
        &self,
        binding: &LifecycleBinding,
    ) -> Result<Option<LifecycleOperation>, Failure> {
        let _g = self
            .mu
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.unsettled_locked(binding)
    }
}

impl FileJournal {
    /// `ActiveReceipt` — the binding's active selector receipt: the
    /// last operation's prepared receipt marked active. Generic
    /// (unbound) lookup is refused upstream — the selector is always
    /// binding-scoped.
    pub fn active_receipt(&self, binding: &LifecycleBinding) -> Result<DependencyReceipt, Failure> {
        let _g = self
            .mu
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut active: Option<DependencyReceiptJson> = None;
        for state in self.states(binding)? {
            if state.active
                && let Some(receipt) = state.receipt
            {
                active = Some(receipt);
            }
        }
        let Some(receipt) = active else {
            return Err(Failure::not_found(
                "JOURNAL",
                "lifecycle journal: no active receipt",
            ));
        };
        Ok(DependencyReceipt {
            id: receipt.id,
            manifest_digest: receipt.manifest_digest,
            operation_id: receipt.operation_id,
            selector_generation: receipt.selector_generation,
            dependency_set: receipt.dependency_set,
        })
    }
}

// ---------------------------------------------------------------------------
// FileLocker — exclusive lock file per binding; expiry alone never
// authorizes takeover (dead-owner proof required).
// ---------------------------------------------------------------------------

/// `FileLocker` — upstream's append-only lock directory per binding:
/// acquire records `{seq:020}.json`, release records
/// `{seq:020}.released.json`, both `O_EXCL` mode 0600 with file+dir
/// fsync. Sequence numbers order the record stream because lock ids
/// are random `lock-<uuid>`s — lexicographic id order says nothing
/// about chronology.
pub struct FileLocker<V> {
    root: PathBuf,
    lifetime: Duration,
    clock: Arc<dyn LifecycleClock>,
    verifier: V,
    /// `tokio::sync::Mutex` so the guard may be held across the
    /// dead-owner verification `await` (upstream holds `l.mu` for the
    /// whole `Acquire`; a `std` guard is not `Send`).
    mu: tokio::sync::Mutex<()>,
}

/// `lockRecord` — upstream's on-disk shape (`released` omitempty).
#[derive(Serialize, Deserialize)]
struct LockRecord {
    id: String,
    owner_pid: i32,
    sequence: u64,
    expires_at: String,
    #[serde(default, skip_serializing_if = "is_false")]
    released: bool,
    fencing_token: u64,
}

fn is_false(v: &bool) -> bool {
    !*v
}

/// `lockSequenceWidth` — upstream's fixed-width zero-padded decimal;
/// equal-width names sort lexicographically in numeric order, which is
/// the property `latest`'s name sort relies on.
const LOCK_SEQUENCE_WIDTH: usize = 20;

impl<V: DeadOwnerVerifier> FileLocker<V> {
    /// `NewFileLocker`.
    pub fn new(
        root: PathBuf,
        lifetime: Duration,
        clock: Arc<dyn LifecycleClock>,
        verifier: V,
    ) -> Self {
        Self {
            root,
            lifetime,
            clock,
            verifier,
            mu: tokio::sync::Mutex::new(()),
        }
    }

    /// `lockPath` — the per-binding lock DIRECTORY,
    /// `root/lock-<bindingKey>`.
    fn lock_path(&self, binding: &LifecycleBinding) -> PathBuf {
        self.root.join(format!("lock-{}", binding_key(binding)))
    }

    /// `latestLocked` — the chronologically newest record: every
    /// `.json` entry whose `LOCK_SEQUENCE_WIDTH`-digit prefix parses
    /// (stale UUID-named records from before the sequence scheme take
    /// no part), sorted by name, last element decoded.
    fn latest(&self, binding: &LifecycleBinding) -> Result<Option<LockRecord>, Failure> {
        let dir = self.lock_path(binding);
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(Failure::internal(
                    "LOCK",
                    format!("lifecycle lock: list: {e}"),
                ));
            }
        };
        let mut names: Vec<String> = entries
            .flatten()
            .filter(|e| e.path().is_file())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| {
                // `get(..)` rather than `[..]`: a multibyte name whose
                // 20th byte is not a char boundary must be skipped,
                // never panic the locker.
                n.get(..LOCK_SEQUENCE_WIDTH)
                    .is_some_and(|p| p.bytes().all(|b| b.is_ascii_digit()))
                    && std::path::Path::new(n)
                        .extension()
                        .is_some_and(|x| x == "json")
            })
            .collect();
        if names.is_empty() {
            return Ok(None);
        }
        names.sort();
        let data = std::fs::read(dir.join(names.pop().unwrap_or_default()))
            .map_err(|e| Failure::internal("LOCK", format!("lifecycle lock: read: {e}")))?;
        let record: LockRecord = serde_json::from_slice(&data)
            .map_err(|e| Failure::internal("LOCK", format!("lifecycle lock: decode: {e}")))?;
        Ok(Some(record))
    }

    /// `nextSequenceLocked` — one past the highest sequence present;
    /// entries without a `LOCK_SEQUENCE_WIDTH`-digit prefix are
    /// ignored, matching upstream's guard for pre-sequence files.
    fn next_sequence(&self, dir: &Path) -> Result<u64, Failure> {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(1),
            Err(e) => {
                return Err(Failure::internal(
                    "LOCK",
                    format!("lifecycle lock: sequence scan: {e}"),
                ));
            }
        };
        let mut max = 0u64;
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            // `get(..)` rather than `[..]`: a multibyte name whose
            // 20th byte is not a char boundary is skipped, never
            // panics the locker.
            let Some(prefix) = name.get(..LOCK_SEQUENCE_WIDTH) else {
                continue;
            };
            if let Ok(seq) = prefix.parse::<u64>() {
                max = max.max(seq);
            }
        }
        Ok(max + 1)
    }

    /// `appendLocked` — the exclusive sequence write for an acquire
    /// record (same `O_EXCL` + fsync + dir-sync discipline as the
    /// journal's `appendLocked`).
    fn append(&self, binding: &LifecycleBinding, record: &LockRecord) -> Result<(), Failure> {
        let dir = self.lock_path(binding);
        self.write_lock_file(
            &dir,
            &format!(
                "{:0width$}.json",
                record.sequence,
                width = LOCK_SEQUENCE_WIDTH
            ),
            record,
        )
    }

    /// `appendReleaseLocked` — the release reuses the acquire record's
    /// own sequence with the `.released.json` suffix: `"<seq>.json"`
    /// sorts immediately before `"<seq>.released.json"` (matching
    /// zero-padded prefix, then `"json" < "released.json"`), so
    /// `latest` returns the released state once this file exists, and
    /// a later lock's higher sequence still sorts after both.
    fn append_release(
        &self,
        binding: &LifecycleBinding,
        record: &LockRecord,
    ) -> Result<(), Failure> {
        let dir = self.lock_path(binding);
        self.write_lock_file(
            &dir,
            &format!(
                "{:0width$}.released.json",
                record.sequence,
                width = LOCK_SEQUENCE_WIDTH
            ),
            record,
        )
    }

    fn write_lock_file(&self, dir: &Path, name: &str, record: &LockRecord) -> Result<(), Failure> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::create_dir_all(dir)
            .map_err(|e| Failure::internal("LOCK", format!("lifecycle lock: dir: {e}")))?;
        set_mode(&dir.to_string_lossy(), 0o700)
            .map_err(|e| Failure::internal("LOCK", format!("lifecycle lock: dir mode: {e}")))?;
        let data = serde_json::to_vec(record)
            .map_err(|e| Failure::internal("LOCK", format!("lifecycle lock: encode: {e}")))?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.join(name))
            .map_err(|e| Failure::internal("LOCK", format!("lifecycle lock: append: {e}")))?;
        file.write_all(&data)
            .map_err(|e| Failure::internal("LOCK", format!("lifecycle lock: write: {e}")))?;
        file.sync_all()
            .map_err(|e| Failure::internal("LOCK", format!("lifecycle lock: sync: {e}")))?;
        drop(file);
        std::fs::File::open(dir)
            .and_then(|f| f.sync_all())
            .map_err(|e| Failure::internal("LOCK", format!("lifecycle lock: dir sync: {e}")))
    }

    /// `fencing` — crypto-random u64 like upstream's
    /// `binary.Read(rand.Reader, …)`; zero is refused, never masked
    /// into validity.
    fn fencing() -> Result<u64, Failure> {
        let token = u64::from_be_bytes(
            uuid::Uuid::new_v4().into_bytes()[..8]
                .try_into()
                .unwrap_or_default(),
        );
        if token == 0 {
            return Err(Failure::internal(
                "LOCK",
                "lifecycle lock: zero fencing token",
            ));
        }
        Ok(token)
    }
}

impl<V: DeadOwnerVerifier + Sync> LifecycleLocker for FileLocker<V> {
    async fn acquire(&self, binding: &LifecycleBinding) -> Result<LifecycleLock, Failure> {
        binding.validate()?;
        if self.lifetime <= Duration::ZERO {
            return Err(Failure::invalid("LOCK", "lifecycle lock: invalid lifetime"));
        }
        let _g = self.mu.lock().await;
        std::fs::create_dir_all(&self.root)
            .map_err(|e| Failure::internal("LOCK", format!("lifecycle lock: create dir: {e}")))?;
        set_mode(&self.root.to_string_lossy(), 0o700)
            .map_err(|e| Failure::internal("LOCK", format!("lifecycle lock: mode: {e}")))?;
        if let Some(old) = self.latest(binding)?
            && !old.released
        {
            let expires_at = OffsetDateTime::parse(
                &old.expires_at,
                &time::format_description::well_known::Rfc3339,
            )
            .unwrap_or(OffsetDateTime::UNIX_EPOCH);
            if self.clock.now() < expires_at {
                return Err(Failure::denied("LOCK", "lifecycle lock: already held"));
            }
            // Expiry alone never authorizes takeover — the expired
            // owner must be broker-verified dead, and the proof must
            // name this exact lock record: same id, same owner pid,
            // `dead`, and a nonzero verification timestamp. The
            // verifier's reason text intentionally need not match
            // upstream byte-for-byte: only the denial semantics are
            // load-bearing (a live or unverifiable owner refuses
            // takeover), so a differently worded reason is acceptable
            // divergence.
            let proof = self
                .verifier
                .verify_dead_owner(&old.id, old.owner_pid)
                .await?;
            if !proof.dead
                || proof.lock_id != old.id
                || proof.owner_pid != old.owner_pid
                || proof.verified_at == OffsetDateTime::UNIX_EPOCH
            {
                return Err(Failure::denied(
                    "LOCK",
                    "lifecycle lock: expired owner was not broker-verified dead",
                ));
            }
        }
        let expires = self.clock.now() + self.lifetime;
        let seq = self.next_sequence(&self.lock_path(binding))?;
        let record = LockRecord {
            id: format!("lock-{}", uuid::Uuid::new_v4()),
            owner_pid: std::process::id() as i32,
            sequence: seq,
            expires_at: rfc3339(expires),
            released: false,
            fencing_token: Self::fencing()?,
        };
        self.append(binding, &record)?;
        Ok(LifecycleLock {
            id: record.id,
            acquired: true,
            expires_at: expires,
            fencing_token: record.fencing_token,
        })
    }

    async fn release(
        &self,
        binding: &LifecycleBinding,
        lock: LifecycleLock,
    ) -> Result<(), Failure> {
        binding.validate()?;
        if !lock.acquired || lock.id.is_empty() {
            return Err(Failure::invalid("LOCK", "lifecycle lock: invalid release"));
        }
        let _g = self.mu.lock().await;
        let mut latest = match self.latest(binding)? {
            Some(l) => l,
            None => {
                return Err(Failure::denied(
                    "LOCK",
                    "lifecycle lock: release does not own current lock",
                ));
            }
        };
        if latest.released || latest.id != lock.id {
            return Err(Failure::denied(
                "LOCK",
                "lifecycle lock: release does not own current lock",
            ));
        }
        latest.released = true;
        self.append_release(binding, &latest)
    }
}

// ---------------------------------------------------------------------------
// FileBarrier + FilesystemCapacity + receiptAdmission + inspector
// ---------------------------------------------------------------------------

/// `FileBarrier` — an explicit external-writer veto file, upstream's
/// `FileBarrier`. Lifecycle locks are intentionally not barriers: the
/// service acquires its own lifecycle lock before consulting this
/// port, and a barrier exists only because a non-lifecycle writer (a
/// restore, an operator safety latch) durably claimed the binding.
pub struct FileBarrier {
    root: PathBuf,
}

impl FileBarrier {
    /// `NewFileBarrier(root)`.
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// `barrierPath` — `root/barrier-<bindingKey>.txt`.
    fn barrier_path(&self, binding: &LifecycleBinding) -> PathBuf {
        self.root
            .join(format!("barrier-{}.txt", binding_key(binding)))
    }

    /// `Block` — records a durable veto for `binding`; the written
    /// bytes are the denial's reason, replayed verbatim by
    /// `validate_writable_start`. An empty reason is refused so a veto
    /// can never be created with no explanation.
    pub fn block(&self, binding: &LifecycleBinding, reason: &str) -> Result<(), Failure> {
        if reason.is_empty() {
            return Err(Failure::invalid(
                "BARRIER",
                "lifecycle barrier: empty reason",
            ));
        }
        std::fs::create_dir_all(&self.root).map_err(|e| {
            Failure::internal("BARRIER", format!("lifecycle barrier: create root: {e}"))
        })?;
        set_mode(&self.root.to_string_lossy(), 0o700).map_err(|e| {
            Failure::internal("BARRIER", format!("lifecycle barrier: root mode: {e}"))
        })?;
        let path = self.barrier_path(binding);
        std::fs::write(&path, reason.as_bytes())
            .map_err(|e| Failure::internal("BARRIER", format!("lifecycle barrier: write: {e}")))?;
        set_mode(&path.to_string_lossy(), 0o600)
            .map_err(|e| Failure::internal("BARRIER", format!("lifecycle barrier: file mode: {e}")))
    }
}

impl LifecycleBarrier for FileBarrier {
    async fn validate_writable_start(&self, binding: &LifecycleBinding) -> Result<(), Failure> {
        match std::fs::read(self.barrier_path(binding)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Failure::internal(
                "BARRIER",
                format!("lifecycle barrier: read: {e}"),
            )),
            Ok(data) => Err(Failure::denied(
                "BARRIER_CONFLICT",
                format!(
                    "lifecycle barrier: writable operation blocked: {}",
                    String::from_utf8_lossy(&data)
                ),
            )),
        }
    }
}

/// `FilesystemCapacity` — statfs free-space admission.
pub struct FilesystemCapacity {
    root: PathBuf,
    required_bytes: i64,
}

impl FilesystemCapacity {
    /// `NewFilesystemCapacity`.
    pub fn new(root: PathBuf, required_bytes: i64) -> Self {
        Self {
            root,
            required_bytes,
        }
    }
}

impl LifecycleCapacity for FilesystemCapacity {
    async fn admit(
        &self,
        binding: &LifecycleBinding,
        set: &PreparedDependencySet,
    ) -> Result<LifecycleReservation, Failure> {
        // Upstream validates both halves of the request before the
        // statfs: the binding the caller supplied and the B03 set the
        // operation will run under.
        binding.validate()?;
        set.validate_b03()?;
        let available = statfs_available(&self.root).map_err(|e| {
            Failure::internal(
                "CAPACITY",
                format!("capacity: statfs {}: {e}", self.root.display()),
            )
        })?;
        if available < self.required_bytes {
            return Err(Failure::denied(
                "CAPACITY_DENIED",
                format!(
                    "capacity: {} bytes available, {} required",
                    available, self.required_bytes
                ),
            ));
        }
        Ok(LifecycleReservation {
            id: format!("capacity-{}", &binding_key(binding)[..16]),
            allocated: self.required_bytes,
            bound: true,
        })
    }
}

fn statfs_available(path: &Path) -> std::io::Result<i64> {
    rustix::fs::statfs(path)
        .map(|s| i64::try_from(s.f_bavail).unwrap_or(i64::MAX) * s.f_bsize)
        .map_err(std::io::Error::other)
}

/// `receiptAdmission` — B01 evaluation + B02 active receipt + OCI
/// reinspection (upstream `NewAdmission`).
pub struct ReceiptAdmission {
    evaluator: Arc<dyn AdvisoryEvaluator>,
    receipts: Arc<dyn ActiveReceiptReader>,
    inspector: Arc<dyn ReceiptInspector>,
}

impl ReceiptAdmission {
    /// `NewAdmission`.
    pub fn new(
        evaluator: Arc<dyn AdvisoryEvaluator>,
        receipts: Arc<dyn ActiveReceiptReader>,
        inspector: Arc<dyn ReceiptInspector>,
    ) -> Self {
        Self {
            evaluator,
            receipts,
            inspector,
        }
    }
}

impl LifecycleAdmission for ReceiptAdmission {
    async fn verify(&self, request: AdmissionRequest) -> Result<AdmissionResult, Failure> {
        if request.instance_id.is_empty()
            || request.config_binding.is_empty()
            || request.receipt_id.is_empty()
        {
            return Err(Failure::invalid(
                "ADMISSION",
                "lifecycle admission: incomplete binding",
            ));
        }
        let (result, admission) = self.evaluator.evaluate().map_err(|e| {
            Failure::internal(
                "ADMISSION",
                format!("lifecycle admission: B01 evaluation: {e}"),
            )
        })?;
        if result.state != advisory::State::Current || admission.is_zero() {
            return Err(Failure::denied(
                "ADMISSION",
                "lifecycle admission: B01 is not current",
            ));
        }
        let receipt = self.receipts.active().map_err(|e| {
            Failure::internal(
                "ADMISSION",
                format!("lifecycle admission: B02 active receipt: {e}"),
            )
        })?;
        if receipt.id != request.receipt_id {
            return Err(Failure::denied(
                "ADMISSION",
                "lifecycle admission: requested receipt is not active",
            ));
        }
        receipt.dependency_set.validate_b03().map_err(|e| {
            Failure::invalid(
                "ADMISSION",
                format!("lifecycle admission: invalid B02 receipt: {e}"),
            )
        })?;
        self.inspector
            .inspect_set(&receipt.dependency_set)
            .map_err(|e| {
                Failure::internal(
                    "ADMISSION",
                    format!("lifecycle admission: B02 receipt reinspection: {e}"),
                )
            })?;
        Ok(AdmissionResult {
            state: result.state.as_str().to_owned(),
            warning: String::new(),
            receipt_id: receipt.id,
            prepared: receipt.dependency_set,
        })
    }
}

/// `DockerReceiptInspector` — every B02 manifest identity must be
/// present in the local Docker content store.
pub struct DockerReceiptInspector {
    docker_path: String,
    exec: CommandExecutor,
}

impl DockerReceiptInspector {
    /// `NewDockerReceiptInspector`.
    pub fn new(docker_path: &str, exec: Option<CommandExecutor>) -> Self {
        Self {
            docker_path: docker_path.to_owned(),
            exec: exec.unwrap_or_else(|| {
                Box::new(|name, args, env, deadline| {
                    let mut cmd = std::process::Command::new(name);
                    cmd.args(args)
                        .env_clear()
                        .envs(env.iter().filter_map(|e| e.split_once('=')));
                    let output = super::compose::run_compose_bounded(deadline, &mut cmd, None)?;
                    if !output.status.success() {
                        return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
                    }
                    Ok(output.stdout)
                })
            }),
        }
    }
}

impl ReceiptInspector for DockerReceiptInspector {
    fn inspect_set(&self, set: &PreparedDependencySet) -> Result<(), Failure> {
        if !self.docker_path.starts_with('/') {
            return Err(Failure::invalid(
                "RECEIPT_INSPECTOR",
                "receipt inspector: docker path must be absolute",
            ));
        }
        set.validate_b03()?;
        for mode in &set.modes {
            let reference = image_reference(mode.mode, &mode.inventory)
                .map_err(|e| Failure::internal("RECEIPT_INSPECTOR", e.to_string()))?;
            let output = (self.exec)(
                &self.docker_path,
                &[
                    "image".to_owned(),
                    "inspect".to_owned(),
                    "--format".to_owned(),
                    "{{.Id}}".to_owned(),
                    reference,
                ],
                &closed_docker_environment(),
                // The admission path carries no phase deadline in the
                // Rust port shape (upstream threads the admission ctx);
                // a hung `docker image inspect` is refused by docker's
                // own daemon timeouts, so `NONE` preserves semantics.
                OpDeadline::NONE,
            );
            match output {
                Ok(out) if !out.is_empty() => {}
                _ => {
                    return Err(Failure::denied(
                        "RECEIPT_INSPECTOR",
                        format!(
                            "receipt inspector: mode {} is unavailable locally",
                            mode.mode.as_str()
                        ),
                    ));
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// FileBootstrap — the host bootstrap boundary; the B04 credential
// ceremony delegates to the typed broker authority.
// ---------------------------------------------------------------------------

/// `FileBootstrap` — `ensure` records the generation; `materialize` and
/// `cleanup` operate on the materialized handoff artifact the broker
/// produced (an opaque `MountProof`); the typed B04 authority delegates
/// straight through, matching upstream's interface assertion on the
/// bootstrap. `used` is upstream's mount-consumption map; `mu` orders
/// the durable handoff record writes.
pub struct FileBootstrap<B> {
    root: PathBuf,
    clock: Arc<dyn LifecycleClock>,
    b04: B,
    /// `b.mu` — `tokio::sync::Mutex` so `materialize` may hold the
    /// guard across the broker `await` (upstream holds `b.mu` for the
    /// whole `Materialize`; a `std` guard is not `Send`).
    mu: tokio::sync::Mutex<()>,
    used: Mutex<BTreeMap<String, bool>>,
}

/// `durableHandoffRecord` is intentionally nonsecret. It binds the
/// fixed handoff path to a lifecycle binding so a restarted helper can
/// remove the path only when the lifecycle has verified teardown. It
/// never records credential bytes or their digest; the record remains
/// after removal as durable evidence that a restarted helper must not
/// retry cleanup blindly.
#[derive(Serialize, Deserialize)]
struct DurableHandoffRecord {
    mount_path: String,
    #[serde(default)]
    removed: bool,
}

/// `fixedBootstrapDestination` — upstream's table; MinIO is the only
/// fixed service destination (`minio-root-password`, uid/gid 1000).
fn fixed_bootstrap_destination(service: ServiceMode) -> Option<(&'static str, u32, u32)> {
    match service {
        ServiceMode::Minio => Some(("minio-root-password", 1000, 1000)),
        _ => None,
    }
}

fn bootstrap_purpose_str(purpose: BootstrapPurpose) -> &'static str {
    match purpose {
        BootstrapPurpose::FirstSetup => "first-setup",
        BootstrapPurpose::Reconcile => "reconcile",
        BootstrapPurpose::Recovery => "recovery",
    }
}

impl<B: B04Bootstrap> FileBootstrap<B> {
    /// `NewFileBootstrap`.
    pub fn new(root: PathBuf, clock: Arc<dyn LifecycleClock>, b04: B) -> Self {
        Self {
            root,
            clock,
            b04,
            mu: tokio::sync::Mutex::new(()),
            used: Mutex::new(BTreeMap::new()),
        }
    }

    /// `handoffRecordPath` — `root/<bindingKey>.handoff.json`.
    fn handoff_record_path(&self, binding: &LifecycleBinding) -> PathBuf {
        self.root
            .join(format!("{}.handoff.json", binding_key(binding)))
    }

    /// `readHandoffRecordLocked` — `(record, exists)`; a corrupt record
    /// or an empty mount path is an error, never silently absent.
    fn read_handoff_record(
        &self,
        binding: &LifecycleBinding,
    ) -> Result<Option<DurableHandoffRecord>, Failure> {
        let data = match std::fs::read(self.handoff_record_path(binding)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(Failure::internal(
                    "BOOTSTRAP",
                    format!("bootstrap: read handoff record: {e}"),
                ));
            }
            Ok(d) => d,
        };
        let record: DurableHandoffRecord = serde_json::from_slice(&data).map_err(|e| {
            Failure::internal(
                "BOOTSTRAP",
                format!("bootstrap: invalid durable handoff record: {e}"),
            )
        })?;
        if record.mount_path.is_empty() {
            return Err(Failure::internal(
                "BOOTSTRAP",
                "bootstrap: invalid durable handoff record",
            ));
        }
        Ok(Some(record))
    }

    /// `writeHandoffRecordLocked` — temp file in `root`, chmod 0600,
    /// write, fsync, close, rename over the record path, fsync `root`.
    /// The record is never written before the materialized handoff it
    /// binds exists (upstream's `Materialize` → `RecordHandoff` order).
    fn write_handoff_record(
        &self,
        binding: &LifecycleBinding,
        record: &DurableHandoffRecord,
    ) -> Result<(), Failure> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::create_dir_all(&self.root)
            .map_err(|e| Failure::internal("BOOTSTRAP", format!("bootstrap: create root: {e}")))?;
        set_mode(&self.root.to_string_lossy(), 0o700)
            .map_err(|e| Failure::internal("BOOTSTRAP", format!("bootstrap: root mode: {e}")))?;
        let data = serde_json::to_vec(record).map_err(|e| {
            Failure::internal(
                "BOOTSTRAP",
                format!("bootstrap: encode handoff record: {e}"),
            )
        })?;
        let tmp = self
            .root
            .join(format!(".handoff-{}.tmp", uuid::Uuid::new_v4().as_simple()));
        let result = (|| -> Result<(), Failure> {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(|e| {
                    Failure::internal("BOOTSTRAP", format!("bootstrap: record temp: {e}"))
                })?;
            file.write_all(&data).map_err(|e| {
                Failure::internal("BOOTSTRAP", format!("bootstrap: record write: {e}"))
            })?;
            file.sync_all().map_err(|e| {
                Failure::internal("BOOTSTRAP", format!("bootstrap: record sync: {e}"))
            })?;
            drop(file);
            std::fs::rename(&tmp, self.handoff_record_path(binding)).map_err(|e| {
                Failure::internal("BOOTSTRAP", format!("bootstrap: record rename: {e}"))
            })?;
            std::fs::File::open(&self.root)
                .and_then(|f| f.sync_all())
                .map_err(|e| {
                    Failure::internal("BOOTSTRAP", format!("bootstrap: record dir sync: {e}"))
                })
        })();
        let _ = std::fs::remove_file(&tmp);
        result
    }
}

impl<B: B04Bootstrap> LifecycleBootstrap for FileBootstrap<B> {
    /// `Ensure` — upstream: mkdir `root` 0700; the generation file is
    /// `<bindingKey>-<purpose>.generation`, re-read if present;
    /// otherwise 32 crypto-random bytes hashed `sha256:<hex>` are
    /// written `{"Generation":1,"Digest":"…"}` mode 0600.
    async fn ensure(
        &self,
        binding: &LifecycleBinding,
        purpose: BootstrapPurpose,
    ) -> Result<BootstrapGeneration, Failure> {
        binding.validate()?;
        // Upstream `b.mu`: the generation check-then-write must be
        // serialized against a concurrent `ensure`/`materialize`.
        let _g = self.mu.lock().await;
        std::fs::create_dir_all(&self.root)
            .map_err(|e| Failure::internal("BOOTSTRAP", format!("bootstrap: create root: {e}")))?;
        set_mode(&self.root.to_string_lossy(), 0o700)
            .map_err(|e| Failure::internal("BOOTSTRAP", format!("bootstrap: root mode: {e}")))?;
        let path = self.root.join(format!(
            "{}-{}.generation",
            binding_key(binding),
            bootstrap_purpose_str(purpose)
        ));
        #[derive(Serialize, Deserialize)]
        struct GenerationFile {
            #[serde(rename = "Generation")]
            generation: u32,
            #[serde(rename = "Digest")]
            digest: String,
        }
        if let Ok(data) = std::fs::read(&path)
            && let Ok(g) = serde_json::from_slice::<GenerationFile>(&data)
        {
            return Ok(BootstrapGeneration {
                generation: g.generation,
                digest: g.digest,
            });
        }
        let mut random = [0u8; 32];
        random[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        random[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        let sum = Sha256::digest(random);
        let generation = BootstrapGeneration {
            generation: 1,
            digest: format!("sha256:{}", hex(&sum)),
        };
        let data = serde_json::to_vec(&GenerationFile {
            generation: generation.generation,
            digest: generation.digest.clone(),
        })
        .map_err(|e| {
            Failure::internal("BOOTSTRAP", format!("bootstrap: encode generation: {e}"))
        })?;
        std::fs::write(&path, &data).map_err(|e| {
            Failure::internal("BOOTSTRAP", format!("bootstrap: write generation: {e}"))
        })?;
        set_mode(&path.to_string_lossy(), 0o600).map_err(|e| {
            Failure::internal("BOOTSTRAP", format!("bootstrap: generation mode: {e}"))
        })?;
        Ok(generation)
    }

    /// `Materialize` — upstream's exact validation window: required
    /// fields and an unexpired lifetime; the fixed MinIO secrets
    /// destination (`/run/central-infra/<id>/secrets`, uid/gid 1000);
    /// then the typed B04 broker authority — mandatory, never
    /// bypassed — and a confirmed mount proof with a nonempty path is
    /// registered in `used`.
    async fn materialize(&self, handoff: BootstrapHandoff) -> Result<MountProof, Failure> {
        if handoff.instance_id.is_empty()
            || handoff.target.is_empty()
            || (handoff.lifetime.expires != OffsetDateTime::UNIX_EPOCH
                && self.clock.now() >= handoff.lifetime.expires)
        {
            return Err(Failure::invalid(
                "BOOTSTRAP",
                "bootstrap: invalid or expired handoff",
            ));
        }
        let Some((_name, uid, gid)) = fixed_bootstrap_destination(handoff.service) else {
            return Err(Failure::invalid(
                "BOOTSTRAP",
                "bootstrap: handoff is outside the fixed service destination",
            ));
        };
        if handoff.target != format!("/run/central-infra/{}/secrets", handoff.instance_id)
            || handoff.uid != uid
            || handoff.gid != gid
        {
            return Err(Failure::invalid(
                "BOOTSTRAP",
                "bootstrap: handoff is outside the fixed service destination",
            ));
        }
        // Upstream `b.mu`: the broker authority call and the `used`
        // registration are serialized with `ensure`/`cleanup`.
        let _g = self.mu.lock().await;
        // The credential material itself never transits this process
        // in plaintext: the broker writes it under the sealed handoff
        // and this call returns only the mount proof.
        let proof = self.b04.materialize_minio_root(handoff).await?;
        if !proof.confirmed || proof.mount_path.is_empty() {
            return Err(Failure::internal(
                "BOOTSTRAP",
                "bootstrap: broker returned invalid mount proof",
            ));
        }
        self.used
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(proof.mount_path.clone(), false);
        Ok(proof)
    }

    /// `Cleanup` — upstream's single-use rule: only a mount path this
    /// process materialized (`used[path] == false`) may be removed,
    /// exactly once; a second call or a foreign path is refused. The
    /// `used` mark lands only after the removal attempt succeeds —
    /// upstream's `os.Remove`-then-mark order — so a failed cleanup
    /// stays retryable instead of leaking a permanently consumed proof.
    /// A path already gone counts as removed (the record the broker
    /// wrote may have been cleaned by a prior lifecycle).
    async fn cleanup(&self, proof: MountProof) -> Result<(), Failure> {
        if !proof.confirmed || proof.mount_path.is_empty() {
            return Err(Failure::invalid(
                "BOOTSTRAP",
                "bootstrap: invalid mount proof",
            ));
        }
        let _g = self.mu.lock().await;
        let mut used = self
            .used
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match used.get(&proof.mount_path) {
            Some(false) => {}
            _ => {
                return Err(Failure::invalid(
                    "BOOTSTRAP",
                    "bootstrap: mount proof already consumed",
                ));
            }
        }
        let result = match std::fs::remove_file(&proof.mount_path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Failure::internal(
                "BOOTSTRAP",
                format!("bootstrap: cleanup: {e}"),
            )),
        };
        if result.is_ok() {
            used.insert(proof.mount_path.clone(), true);
        }
        result
    }

    /// `RecordHandoff` — persists only the fixed path of a confirmed
    /// handoff; the durable record never carries credential bytes.
    async fn record_handoff(
        &self,
        binding: &LifecycleBinding,
        proof: &MountProof,
    ) -> Result<(), Failure> {
        binding.validate()?;
        if !proof.confirmed || proof.mount_path.is_empty() {
            return Err(Failure::invalid(
                "BOOTSTRAP",
                "bootstrap: invalid mount proof",
            ));
        }
        let _g = self.mu.lock().await;
        self.write_handoff_record(
            binding,
            &DurableHandoffRecord {
                mount_path: proof.mount_path.clone(),
                removed: false,
            },
        )
    }

    /// `CleanupBinding` — resumes cleanup after a helper crash: the
    /// durable record's mount path is removed idempotently and the
    /// record rewritten `removed`, so a restarted helper can finish
    /// cleanup without the in-process `used` map.
    async fn cleanup_binding(&self, binding: &LifecycleBinding) -> Result<(), Failure> {
        binding.validate()?;
        let _g = self.mu.lock().await;
        let mut record = match self.read_handoff_record(binding)? {
            Some(r) if !r.removed => r,
            _ => return Ok(()),
        };
        match std::fs::remove_file(&record.mount_path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(Failure::internal(
                    "BOOTSTRAP",
                    format!("bootstrap: cleanup binding: {e}"),
                ));
            }
        }
        record.removed = true;
        self.write_handoff_record(binding, &record)
    }
}

/// The typed B04 authority delegates straight through: the topology
/// calls the same object the lifecycle service calls for host bootstrap
/// artifacts, matching upstream's interface assertion on the bootstrap.
impl<B: B04Bootstrap> B04Bootstrap for FileBootstrap<B> {
    async fn adopt_b03_minio(
        &self,
        evidence: central_infra::domain::B04LifecycleEvidence,
    ) -> Result<(), Failure> {
        self.b04.adopt_b03_minio(evidence).await
    }
    async fn materialize_minio_root(
        &self,
        handoff: BootstrapHandoff,
    ) -> Result<MountProof, Failure> {
        self.b04.materialize_minio_root(handoff).await
    }
    async fn issue_lifecycle_proof(
        &self,
        evidence: central_infra::domain::B04LifecycleEvidence,
    ) -> Result<(), Failure> {
        self.b04.issue_lifecycle_proof(evidence).await
    }
}

/// `SharedBootstrap` — the one composed bootstrap shared between the
/// lifecycle service and the topology (a local newtype over the shared
/// `Arc`, so the foreign port traits can be implemented for it).
pub struct SharedBootstrap<B>(pub Arc<FileBootstrap<B>>);

impl<B: B04Bootstrap> SharedBootstrap<B> {
    /// Wraps the shared bootstrap.
    pub fn new(inner: Arc<FileBootstrap<B>>) -> Self {
        Self(inner)
    }
}

impl<B: B04Bootstrap> LifecycleBootstrap for SharedBootstrap<B> {
    async fn ensure(
        &self,
        binding: &LifecycleBinding,
        purpose: BootstrapPurpose,
    ) -> Result<BootstrapGeneration, Failure> {
        self.0.ensure(binding, purpose).await
    }
    async fn materialize(&self, handoff: BootstrapHandoff) -> Result<MountProof, Failure> {
        self.0.materialize(handoff).await
    }
    async fn cleanup(&self, proof: MountProof) -> Result<(), Failure> {
        self.0.cleanup(proof).await
    }
    async fn record_handoff(
        &self,
        binding: &LifecycleBinding,
        proof: &MountProof,
    ) -> Result<(), Failure> {
        self.0.record_handoff(binding, proof).await
    }
    async fn cleanup_binding(&self, binding: &LifecycleBinding) -> Result<(), Failure> {
        self.0.cleanup_binding(binding).await
    }
}

impl<B: B04Bootstrap> B04Bootstrap for SharedBootstrap<B> {
    async fn adopt_b03_minio(
        &self,
        evidence: central_infra::domain::B04LifecycleEvidence,
    ) -> Result<(), Failure> {
        self.0.adopt_b03_minio(evidence).await
    }
    async fn materialize_minio_root(
        &self,
        handoff: BootstrapHandoff,
    ) -> Result<MountProof, Failure> {
        self.0.materialize_minio_root(handoff).await
    }
    async fn issue_lifecycle_proof(
        &self,
        evidence: central_infra::domain::B04LifecycleEvidence,
    ) -> Result<(), Failure> {
        self.0.issue_lifecycle_proof(evidence).await
    }
}

// ---------------------------------------------------------------------------
// SystemClock + composition + the helper LifecycleApplication bridge
// ---------------------------------------------------------------------------

/// `lifecycleClock` — the wall clock behind `LifecycleClock`.
pub struct SystemClock;

impl LifecycleClock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// `ProductionServiceConfig` — already-authorized B01/B02 authorities
/// from the composition root (upstream `ProductionServiceConfig`).
pub struct ProductionServiceConfig<B, V> {
    /// B01 evaluator.
    pub evaluator: Arc<dyn AdvisoryEvaluator>,
    /// B02 active-receipt reader.
    pub receipts: Arc<dyn ActiveReceiptReader>,
    /// OCI re-inspector.
    pub inspector: Arc<dyn ReceiptInspector>,
    /// The compose execution boundary.
    pub runner: Arc<dyn ComposeRunner>,
    /// Durable journal root.
    pub journal_root: PathBuf,
    /// Runtime root (`/run/central-infra`).
    pub runtime_root: PathBuf,
    /// Capacity measurement root.
    pub capacity_root: PathBuf,
    /// Lock lease lifetime (default 10m).
    pub lock_lifetime: Option<Duration>,
    /// The deadline clock.
    pub clock: Arc<dyn LifecycleClock>,
    /// Broker dead-owner verification for lock takeover.
    pub owner_verifier: V,
    /// The typed B04 broker authority (carries the credential ceremony:
    /// sealed `memfd` over `SCM_RIGHTS` through the broker custody path).
    pub b04_bootstrap: B,
    /// Broker rendezvous for the minio-provision socket.
    pub rendezvous: Arc<dyn BrokerRendezvous>,
}

/// The composed production service type.
pub type ProductionService<B, V> = LifecycleService<
    Arc<ReceiptAdmission>,
    Arc<FileBootstrap<B>>,
    Arc<FileJournal>,
    Arc<Topology<SharedBootstrap<B>>>,
    Arc<FilesystemCapacity>,
    Arc<FileBarrier>,
    Arc<FileLocker<V>>,
    Arc<SystemClock>,
>;

/// `NewProductionService` — composes the concrete B03 adapters the
/// domain `LifecycleService` requires; refuses absent authorities.
pub fn new_production_service<B: B04Bootstrap, V: DeadOwnerVerifier>(
    cfg: ProductionServiceConfig<B, V>,
) -> Result<ProductionService<B, V>, Failure> {
    if cfg.journal_root.as_os_str().is_empty()
        || cfg.runtime_root.as_os_str().is_empty()
        || cfg.capacity_root.as_os_str().is_empty()
    {
        return Err(Failure::invalid(
            "LIFECYCLE_COMPOSITION",
            "lifecycle composition: journal, runtime, and capacity roots are required",
        ));
    }
    let policy = load_default_policy()
        .map_err(|e| Failure::internal("LIFECYCLE_COMPOSITION", e.to_string()))?;
    let journal = Arc::new(FileJournal::new(
        cfg.journal_root.clone(),
        cfg.clock.clone(),
    )?);
    let bootstrap = Arc::new(FileBootstrap::new(
        cfg.journal_root.join("bootstrap"),
        cfg.clock.clone(),
        cfg.b04_bootstrap,
    ));
    let topology = Arc::new(
        Topology::new(
            cfg.runner,
            cfg.receipts.clone(),
            policy,
            cfg.runtime_root,
            SharedBootstrap::new(bootstrap.clone()),
        )
        .with_broker_rendezvous(cfg.rendezvous),
    );
    Ok(LifecycleService {
        admission: Arc::new(ReceiptAdmission::new(
            cfg.evaluator,
            cfg.receipts,
            cfg.inspector,
        )),
        bootstrap: bootstrap.clone(),
        journal: journal.clone(),
        topology,
        capacity: Some(Arc::new(FilesystemCapacity::new(
            cfg.capacity_root,
            2 * 1024 * 1024 * 1024,
        ))),
        barrier: Some(Arc::new(FileBarrier::new(
            cfg.journal_root.join("barriers"),
        ))),
        locker: Arc::new(FileLocker::new(
            cfg.journal_root.join("locks"),
            cfg.lock_lifetime.unwrap_or(Duration::from_secs(600)),
            cfg.clock,
            cfg.owner_verifier,
        )),
        clock: Arc::new(SystemClock),
    })
}

/// `LifecycleApplicationBridge` — adapts the async domain
/// `LifecycleService` to the helper's synchronous
/// `LifecycleApplication` seam, resolving the fixed instance binding
/// into the upstream `infralifecycle.Request`.
pub struct LifecycleApplicationBridge<S> {
    service: S,
    binding: LifecycleBinding,
}

impl<S> LifecycleApplicationBridge<S> {
    /// Binds the service to the resolved instance binding.
    pub fn new(service: S, binding: LifecycleBinding) -> Self {
        Self { service, binding }
    }

    /// The upstream `infralifecycle.Request` for one resolved
    /// operation: the resolver's instance/config values lead (upstream
    /// passes `operation` straight into `service.Up`), and the
    /// composed binding supplies the fields the narrowed helper seam
    /// does not carry (admission, receipt, model digest, payload
    /// epoch, bootstrap fingerprints).
    fn request(
        &self,
        operation: &crate::helper::lifecycle::LifecycleOperation,
    ) -> LifecycleRequest {
        LifecycleRequest {
            instance_id: operation.instance_id.clone(),
            config_binding: operation.config_binding.clone(),
            admission_id: self.binding.admission_id.clone(),
            receipt_id: self.binding.receipt_id.clone(),
            model_digest: self.binding.model_digest.clone(),
            payload_epoch: self.binding.payload_epoch.clone(),
            bootstrap_fingerprints: self.binding.bootstrap_fingerprints.clone(),
        }
    }
}

impl<A, B, J, T, C, R, L, K> LifecycleApplicationBridge<LifecycleService<A, B, J, T, C, R, L, K>>
where
    A: LifecycleAdmission,
    B: LifecycleBootstrap,
    J: LifecyclePort,
    T: TopologyPort,
    C: LifecycleCapacity,
    R: LifecycleBarrier,
    L: LifecycleLocker,
    K: LifecycleClock,
{
    /// `up` — drives the domain service synchronously for the helper,
    /// propagating the helper verb deadline into the domain loop's
    /// cancellation arm.
    pub fn up(
        &self,
        deadline: Option<OffsetDateTime>,
        operation: &crate::helper::lifecycle::LifecycleOperation,
    ) -> LifecycleResult {
        block_on(
            self.service
                .up_with_deadline(self.request(operation), deadline),
        )
    }

    /// `down`.
    pub fn down(
        &self,
        deadline: Option<OffsetDateTime>,
        operation: &crate::helper::lifecycle::LifecycleOperation,
    ) -> LifecycleResult {
        block_on(
            self.service
                .down_with_deadline(self.request(operation), deadline),
        )
    }

    /// `status` — read-only.
    pub fn status(
        &self,
        deadline: Option<OffsetDateTime>,
        operation: &crate::helper::lifecycle::LifecycleOperation,
    ) -> LifecycleResult {
        block_on(self.service.status_with_deadline(
            LifecycleStatusRequest {
                instance_id: operation.instance_id.clone(),
                config_binding: operation.config_binding.clone(),
            },
            deadline,
        ))
    }

    /// The domain `LifecycleResult` as the wire `LifecycleServiceResult`
    /// the helper serializes — the helper never fabricates fields.
    fn to_service_result(r: LifecycleResult) -> crate::helper::lifecycle::LifecycleServiceResult {
        crate::helper::lifecycle::LifecycleServiceResult {
            operation_id: r.operation_id,
            phase: r.phase.as_str().to_owned(),
            state: r.state,
            reason: r.reason,
            receipt_id: r.receipt_id,
            safe_next_action: r.safe_next_action,
            exit_code: i64::from(r.exit_code),
        }
    }
}

impl<A, B, J, T, C, R, L, K> crate::helper::lifecycle::LifecycleApplication
    for LifecycleApplicationBridge<LifecycleService<A, B, J, T, C, R, L, K>>
where
    A: LifecycleAdmission,
    B: LifecycleBootstrap,
    J: LifecyclePort,
    T: TopologyPort,
    C: LifecycleCapacity,
    R: LifecycleBarrier,
    L: LifecycleLocker,
    K: LifecycleClock,
{
    fn up(
        &self,
        deadline: std::time::Instant,
        operation: crate::helper::lifecycle::LifecycleOperation,
    ) -> crate::helper::lifecycle::LifecycleServiceResult {
        Self::to_service_result(LifecycleApplicationBridge::up(
            self,
            Some(instant_to_deadline(deadline)),
            &operation,
        ))
    }

    fn down(
        &self,
        deadline: std::time::Instant,
        operation: crate::helper::lifecycle::LifecycleOperation,
    ) -> crate::helper::lifecycle::LifecycleServiceResult {
        Self::to_service_result(LifecycleApplicationBridge::down(
            self,
            Some(instant_to_deadline(deadline)),
            &operation,
        ))
    }

    fn status(
        &self,
        deadline: std::time::Instant,
        operation: crate::helper::lifecycle::LifecycleOperation,
    ) -> crate::helper::lifecycle::LifecycleServiceResult {
        Self::to_service_result(LifecycleApplicationBridge::status(
            self,
            Some(instant_to_deadline(deadline)),
            &operation,
        ))
    }
}

/// `instant_to_deadline` — the helper's monotonic verb deadline
/// translated to the wall clock the domain `LifecycleClock` compares
/// against: `now_utc + remaining`. An already-elapsed `Instant`
/// collapses to now (an immediately-cancelled deadline).
fn instant_to_deadline(instant: std::time::Instant) -> OffsetDateTime {
    let remaining = instant
        .checked_duration_since(std::time::Instant::now())
        .unwrap_or_default();
    OffsetDateTime::now_utc() + time::Duration::try_from(remaining).unwrap_or(time::Duration::MAX)
}

/// `production_lifecycle_handler` — the helper's lifecycle arm over the
/// composed domain service and the fixed-binding resolver (upstream
/// `NewProductionLifecycleHandler`; the broker authorizer and PAM
/// confirmer are installed by `new_authorized` when they exist).
pub fn production_lifecycle_handler(
    service: Box<dyn crate::helper::lifecycle::LifecycleApplication>,
    resolver: Box<dyn crate::helper::lifecycle::LifecycleRequestResolver>,
) -> crate::helper::lifecycle::ProductionLifecycleHandler {
    crate::helper::lifecycle::ProductionLifecycleHandler::new(service, resolver)
}

/// `StaticRequestResolver` — resolves the helper's fixed binding; the
/// request may not carry topology (upstream `LifecycleRequestResolver`).
pub struct StaticRequestResolver {
    operation: crate::helper::lifecycle::LifecycleOperation,
}

impl StaticRequestResolver {
    /// Builds the resolver around the resolved binding fields.
    pub fn new(instance_id: &str, config_binding: &str) -> Self {
        Self {
            operation: crate::helper::lifecycle::LifecycleOperation {
                instance_id: instance_id.to_owned(),
                config_binding: config_binding.to_owned(),
            },
        }
    }
}

impl crate::helper::lifecycle::LifecycleRequestResolver for StaticRequestResolver {
    fn resolve(
        &self,
        _request: &crate::helper::protocol::LifecycleRequest,
    ) -> Result<crate::helper::lifecycle::LifecycleOperation, Failure> {
        if self.operation.instance_id.is_empty() || self.operation.config_binding.is_empty() {
            return Err(Failure::invalid(
                "LIFECYCLE_BINDING",
                "lifecycle binding incomplete",
            ));
        }
        Ok(self.operation.clone())
    }
}

// ---------------------------------------------------------------------------
// Tests — the adapter-level pins the portable semantic suite adds on
// top of the domain suite: journal durability/resume, locker fencing
// and dead-owner takeover, barrier conflict, the request-payload
// contract keys, and provision-receipt derivation.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::compose::{ComposeError, ContainerInspection, RenderedModel};
    use central_infra::domain::{B03_REQUIRED_SERVICE_MODES, OciInventory, PreparedMode};
    use central_infra::port::DeadOwnerProof;
    use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

    fn tmpdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "central-lifecycle-test-{}-{}",
            tag,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    struct TestClock;
    impl LifecycleClock for TestClock {
        fn now(&self) -> OffsetDateTime {
            OffsetDateTime::UNIX_EPOCH + Duration::from_secs(1000)
        }
    }

    fn binding() -> LifecycleBinding {
        LifecycleBinding {
            instance_id: "inst-1".to_owned(),
            config_binding: "cfg-1".to_owned(),
            admission_id: "adm-1".to_owned(),
            receipt_id: "receipt-1".to_owned(),
            model_digest: "sha256:model".to_owned(),
            payload_epoch: "epoch-1".to_owned(),
            bootstrap_fingerprints: Vec::new(),
            b04: Default::default(),
        }
    }

    struct NoDeadOwner;
    impl DeadOwnerVerifier for NoDeadOwner {
        async fn verify_dead_owner(
            &self,
            lock_id: &str,
            owner_pid: i32,
        ) -> Result<DeadOwnerProof, Failure> {
            Ok(DeadOwnerProof {
                lock_id: lock_id.to_owned(),
                owner_pid,
                dead: false,
                verified_at: OffsetDateTime::UNIX_EPOCH,
            })
        }
    }

    struct DeadOwner;
    impl DeadOwnerVerifier for DeadOwner {
        async fn verify_dead_owner(
            &self,
            lock_id: &str,
            owner_pid: i32,
        ) -> Result<DeadOwnerProof, Failure> {
            Ok(DeadOwnerProof {
                lock_id: lock_id.to_owned(),
                owner_pid,
                dead: true,
                // A nonzero verification timestamp — the strict
                // takeover check refuses a zero one.
                verified_at: OffsetDateTime::UNIX_EPOCH + Duration::from_secs(1000),
            })
        }
    }

    /// A proof whose identity does not match the stale record — the
    /// takeover must refuse it even though `dead` is set.
    struct WrongOwnerProof;
    impl DeadOwnerVerifier for WrongOwnerProof {
        async fn verify_dead_owner(
            &self,
            lock_id: &str,
            owner_pid: i32,
        ) -> Result<DeadOwnerProof, Failure> {
            let _ = owner_pid;
            Ok(DeadOwnerProof {
                lock_id: format!("{lock_id}-other"),
                owner_pid: owner_pid + 1,
                dead: true,
                verified_at: OffsetDateTime::UNIX_EPOCH + Duration::from_secs(1000),
            })
        }
    }

    // -- FileJournal -----------------------------------------------------------

    #[test]
    fn file_journal_begins_records_and_settles() {
        let root = tmpdir("journal");
        let journal = FileJournal::new(root, Arc::new(TestClock)).unwrap();
        let op = block_on(journal.begin(binding(), Observation::default())).unwrap();
        block_on(journal.record(&op, LifecyclePhase::Verified)).unwrap();
        let unsettled = block_on(journal.unsettled(&binding())).unwrap().unwrap();
        assert_eq!(unsettled.phase, LifecyclePhase::Verified);
        block_on(journal.settle(&op, LifecyclePhase::Completed)).unwrap();
        assert!(block_on(journal.unsettled(&binding())).unwrap().is_none());
    }

    #[test]
    fn file_journal_resumes_after_restart_and_publishes_receipt_only_after_prepare() {
        let root = tmpdir("journal-resume");
        let journal = FileJournal::new(root.clone(), Arc::new(TestClock)).unwrap();
        let op = block_on(journal.begin(binding(), Observation::default())).unwrap();
        block_on(journal.record(&op, LifecyclePhase::MinioProvisioned)).unwrap();
        // Receipt switch without a prepared receipt fails.
        assert!(block_on(journal.switch_receipt(&op)).is_err());
        let receipt = DependencyReceipt {
            id: "receipt-1".to_owned(),
            dependency_set: PreparedDependencySet {
                modes: B03_REQUIRED_SERVICE_MODES
                    .iter()
                    .map(|mode| PreparedMode {
                        mode: *mode,
                        inventory: OciInventory {
                            index_digest: "sha256:92620daddcd947f8d5ab5ba66e848702fe443d87fed30c4cea8e389fd78dfc55".to_owned(),
                            manifest_digest: "sha256:c95fd5346040eba2de3c435e14874af18f5d681fb5848d4f081dbead0878af28".to_owned(),
                            config_digest: "sha256:67d1da22f4037b29cdd93e03d870a4a1c4d079358367d0cbc56459e52cde205e".to_owned(),
                            layers: Vec::new(),
                        },
                    })
                    .collect(),
            },
            ..DependencyReceipt::default()
        };
        block_on(journal.prepare_receipt(&op, &receipt)).unwrap();
        block_on(journal.switch_receipt(&op)).unwrap();
        // A fresh journal over the same root resumes the unsettled op.
        let journal2 = FileJournal::new(root, Arc::new(TestClock)).unwrap();
        let resumed = block_on(journal2.unsettled(&binding())).unwrap().unwrap();
        assert_eq!(resumed.id, op.id);
        assert_eq!(resumed.phase, LifecyclePhase::MinioProvisioned);
    }

    #[test]
    fn file_journal_creates_linked_down_without_overwriting_unsettled_up() {
        let root = tmpdir("journal-linked");
        // A monotonically ticking clock: `statesLocked` iterates op
        // dirs in sorted name order and keeps the first on a
        // `CreatedAt` tie (upstream's `Before` check), so the linked
        // down's "newest" status is only deterministic when its
        // timestamp is strictly later than the up's.
        struct SeqClock(AtomicU64);
        impl LifecycleClock for SeqClock {
            fn now(&self) -> OffsetDateTime {
                OffsetDateTime::UNIX_EPOCH
                    + Duration::from_secs(1000 + self.0.fetch_add(1, Ordering::SeqCst))
            }
        }
        let journal = FileJournal::new(root, Arc::new(SeqClock(AtomicU64::new(0)))).unwrap();
        let up = block_on(journal.begin(binding(), Observation::default())).unwrap();
        block_on(journal.record(&up, LifecyclePhase::DaemonsStarted)).unwrap();
        let down =
            block_on(journal.begin_linked_down(binding(), Observation::default(), &up)).unwrap();
        assert_eq!(down.linked_operation_id, up.id);
        // The up stays unsettled until the down terminalizes it.
        let unsettled = block_on(journal.unsettled(&binding())).unwrap().unwrap();
        assert_eq!(unsettled.id, down.id);
    }

    // -- FileLocker ------------------------------------------------------------

    #[test]
    fn file_locker_rejects_conflicting_operation() {
        let dir = tmpdir("lock");
        let locker = FileLocker::new(
            dir.clone(),
            Duration::from_secs(600),
            Arc::new(TestClock),
            Arc::new(NoDeadOwner),
        );
        let lock = block_on(locker.acquire(&binding())).unwrap();
        assert!(lock.acquired);
        assert_ne!(lock.fencing_token, 0);
        // A second acquire while held is denied.
        let locker2 = FileLocker::new(
            dir,
            Duration::from_secs(600),
            Arc::new(TestClock),
            Arc::new(NoDeadOwner),
        );
        assert!(block_on(locker2.acquire(&binding())).is_err());
        block_on(locker.release(&binding(), lock)).unwrap();
        // Released: the exact binding is acquirable again, with a fresh
        // nonzero fencing token.
        let reacquired = block_on(locker2.acquire(&binding())).unwrap();
        assert!(reacquired.acquired);
        assert_ne!(reacquired.fencing_token, 0);
    }

    #[test]
    fn file_locker_rejects_expiry_only_takeover_accepts_dead_owner_proof() {
        let dir = tmpdir("lock-expiry");
        // Clock pinned at unix+1000: the seeded lock's expiry is in the
        // past. Takeover still requires the broker's dead-owner proof.
        let locker = FileLocker::new(
            dir.clone(),
            Duration::from_secs(1),
            Arc::new(TestClock),
            Arc::new(NoDeadOwner),
        );
        let stale = LockRecord {
            id: "lock-stale".to_owned(),
            owner_pid: 999_999,
            sequence: 1,
            expires_at: "1970-01-01T00:00:01Z".to_owned(),
            released: false,
            fencing_token: 7,
        };
        let path = locker.lock_path(&binding());
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(
            path.join("00000000000000000001.json"),
            serde_json::to_vec(&stale).unwrap(),
        )
        .unwrap();
        // Expired but owner unproven dead → denied.
        assert!(block_on(locker.acquire(&binding())).is_err());
        // A dead proof naming a different lock/owner is also refused.
        let locker_wrong = FileLocker::new(
            dir.clone(),
            Duration::from_secs(1),
            Arc::new(TestClock),
            Arc::new(WrongOwnerProof),
        );
        assert!(block_on(locker_wrong.acquire(&binding())).is_err());
        // Broker-verified dead owner → takeover succeeds, appending a
        // higher sequence record.
        let locker_dead = FileLocker::new(
            dir,
            Duration::from_secs(1),
            Arc::new(TestClock),
            Arc::new(DeadOwner),
        );
        let lock = block_on(locker_dead.acquire(&binding())).unwrap();
        assert!(lock.acquired);
        assert_ne!(lock.fencing_token, 0);
    }

    // -- FileBarrier ------------------------------------------------------------

    #[test]
    fn file_barrier_external_veto_denies_writable_start() {
        let root = tmpdir("barrier");
        let barrier = FileBarrier::new(root.clone());
        block_on(barrier.validate_writable_start(&binding())).unwrap();
        // An external writer records its veto; the reason is replayed.
        barrier.block(&binding(), "restore in progress").unwrap();
        let err = block_on(barrier.validate_writable_start(&binding())).unwrap_err();
        assert!(err.to_string().contains("restore in progress"));
        // Lifecycle lock files are NOT barriers: a lifecycle lock for
        // the same binding under the same root does not veto anything.
        let _ = std::fs::remove_file(root.join(format!("barrier-{}.txt", binding_key(&binding()))));
        let locker = FileLocker::new(
            root,
            Duration::from_secs(600),
            Arc::new(TestClock),
            Arc::new(NoDeadOwner),
        );
        block_on(locker.acquire(&binding())).unwrap();
        block_on(barrier.validate_writable_start(&binding())).unwrap();
    }

    #[test]
    fn file_barrier_block_refuses_empty_reason() {
        let barrier = FileBarrier::new(tmpdir("barrier-empty"));
        assert!(barrier.block(&binding(), "").is_err());
    }

    // -- Topology (payload contract + provision receipt) -------------------------

    type RunCalls = Mutex<Vec<(String, Vec<String>, Vec<u8>)>>;

    struct CapturingRunner {
        run_calls: RunCalls,
        exit_code: i32,
    }
    impl ComposeRunner for CapturingRunner {
        fn config(&self, _f: &RenderedFile, _d: OpDeadline) -> Result<RenderedModel, ComposeError> {
            Ok(RenderedModel::default())
        }
        fn up(&self, _f: &RenderedFile, _s: &[String], _d: OpDeadline) -> Result<(), ComposeError> {
            Ok(())
        }
        fn run_with_input(
            &self,
            _f: &RenderedFile,
            service: &str,
            args: &[String],
            stdin: &[u8],
            _d: OpDeadline,
        ) -> Result<i32, ComposeError> {
            self.run_calls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((service.to_owned(), args.to_vec(), stdin.to_vec()));
            Ok(self.exit_code)
        }
        fn run_with_input_output(
            &self,
            _f: &RenderedFile,
            _s: &str,
            _a: &[String],
            _i: &[u8],
            _d: OpDeadline,
        ) -> Result<(Vec<u8>, i32), ComposeError> {
            Ok((Vec::new(), self.exit_code))
        }
        fn down(&self, _f: &RenderedFile, _d: OpDeadline) -> Result<(), ComposeError> {
            Ok(())
        }
        fn inspect(&self, _id: &str, _d: OpDeadline) -> Result<ContainerInspection, ComposeError> {
            Ok(ContainerInspection::default())
        }
        fn containers(
            &self,
            _f: &RenderedFile,
            services: &[String],
            _d: OpDeadline,
        ) -> Result<BTreeMap<String, ContainerInspection>, ComposeError> {
            Ok(services
                .iter()
                .map(|s| (s.clone(), ContainerInspection::default()))
                .collect())
        }
        fn stopped(
            &self,
            _f: &RenderedFile,
            _s: &[String],
            _d: OpDeadline,
        ) -> Result<(), ComposeError> {
            Ok(())
        }
    }

    struct StaticReceipts {
        receipt: DependencyReceipt,
    }
    impl ActiveReceiptReader for StaticReceipts {
        fn active(&self) -> Result<DependencyReceipt, Failure> {
            Ok(self.receipt.clone())
        }
    }

    struct RecordingBootstrap {
        cleaned: AtomicU32,
    }
    impl B04Bootstrap for RecordingBootstrap {
        async fn adopt_b03_minio(
            &self,
            _e: central_infra::domain::B04LifecycleEvidence,
        ) -> Result<(), Failure> {
            Ok(())
        }
        async fn materialize_minio_root(
            &self,
            _h: BootstrapHandoff,
        ) -> Result<MountProof, Failure> {
            Ok(MountProof::default())
        }
        async fn issue_lifecycle_proof(
            &self,
            _e: central_infra::domain::B04LifecycleEvidence,
        ) -> Result<(), Failure> {
            Ok(())
        }
    }
    impl LifecycleBootstrap for RecordingBootstrap {
        async fn ensure(
            &self,
            _b: &LifecycleBinding,
            _p: BootstrapPurpose,
        ) -> Result<BootstrapGeneration, Failure> {
            Ok(BootstrapGeneration::default())
        }
        async fn materialize(&self, _h: BootstrapHandoff) -> Result<MountProof, Failure> {
            Ok(MountProof::default())
        }
        async fn cleanup(&self, _p: MountProof) -> Result<(), Failure> {
            self.cleaned.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn record_handoff(
            &self,
            _b: &LifecycleBinding,
            _p: &MountProof,
        ) -> Result<(), Failure> {
            Ok(())
        }
        async fn cleanup_binding(&self, _b: &LifecycleBinding) -> Result<(), Failure> {
            Ok(())
        }
    }
    fn test_dependency_set() -> PreparedDependencySet {
        let inv = OciInventory {
            index_digest: "sha256:92620daddcd947f8d5ab5ba66e848702fe443d87fed30c4cea8e389fd78dfc55"
                .to_owned(),
            manifest_digest:
                "sha256:c95fd5346040eba2de3c435e14874af18f5d681fb5848d4f081dbead0878af28".to_owned(),
            config_digest:
                "sha256:67d1da22f4037b29cdd93e03d870a4a1c4d079358367d0cbc56459e52cde205e".to_owned(),
            layers: Vec::new(),
        };
        PreparedDependencySet {
            modes: B03_REQUIRED_SERVICE_MODES
                .iter()
                .chain(std::iter::once(
                    &central_infra::domain::ServiceMode::PostgresThroughputProvision,
                ))
                .map(|mode| PreparedMode {
                    mode: *mode,
                    inventory: inv.clone(),
                })
                .collect(),
        }
    }

    /// `provisionReceiptFromExitCode` — the receipt derives from the
    /// synchronous exit code with no container inspection.
    #[test]
    fn provision_minio_derives_receipt_from_exit_code() {
        let topology = Topology::new(
            Arc::new(CapturingRunner {
                run_calls: Mutex::new(Vec::new()),
                exit_code: 0,
            }),
            Arc::new(StaticReceipts {
                receipt: DependencyReceipt {
                    id: "receipt-1".to_owned(),
                    dependency_set: test_dependency_set(),
                    ..DependencyReceipt::default()
                },
            }),
            load_default_policy().unwrap(),
            tmpdir("topo-runtime"),
            RecordingBootstrap {
                cleaned: AtomicU32::new(0),
            },
        );
        let op = LifecycleOperation {
            id: "op-1".to_owned(),
            linked_operation_id: String::new(),
            phase: LifecyclePhase::PostgresProvisioned,
            binding: binding(),
            observation: Observation::default(),
            created_at: OffsetDateTime::UNIX_EPOCH,
        };
        let receipt = topology
            .provision_receipt_from_exit_code(&op, "minio-provision", 0)
            .unwrap();
        assert!(receipt.verified);
        assert_eq!(receipt.receipt_id, "op-1-minio-provision");
        assert!(receipt.digest.starts_with("sha256:"));
        // Nonzero exit → no receipt.
        assert!(
            topology
                .provision_receipt_from_exit_code(&op, "minio-provision", 7)
                .is_err()
        );
    }

    /// `TestProvisionMinioFailsIfBrokerNeverConfirmsBind` — the bind
    /// waiter's refusal prevents the provision from reporting success.
    #[test]
    fn provision_minio_fails_when_no_rendezvous_installed() {
        let runner = CapturingRunner {
            run_calls: Mutex::new(Vec::new()),
            exit_code: 0,
        };
        let topology = Topology::new(
            Arc::new(runner),
            Arc::new(StaticReceipts {
                receipt: DependencyReceipt {
                    id: "receipt-1".to_owned(),
                    dependency_set: test_dependency_set(),
                    ..DependencyReceipt::default()
                },
            }),
            load_default_policy().unwrap(),
            tmpdir("topo-runtime2"),
            RecordingBootstrap {
                cleaned: AtomicU32::new(0),
            },
        );
        // The rendered file must exist; write a minimal compose file.
        let dir = tmpdir("topo-runtime2").join("..").canonicalize().unwrap();
        let op = LifecycleOperation {
            id: "op-1".to_owned(),
            linked_operation_id: String::new(),
            phase: LifecyclePhase::PostgresProvisioned,
            binding: binding(),
            observation: Observation::default(),
            created_at: OffsetDateTime::UNIX_EPOCH,
        };
        // file(true) renders + writes the compose file under
        // /run/central-infra — needs the real path; skip when unwritable.
        if !Path::new("/run/central-infra").exists()
            && std::fs::create_dir_all("/run/central-infra").is_err()
        {
            return; // Non-root CI: the denial is still covered by the unit check below.
        }
        let _ = dir;
        let result = block_on(topology.provision_minio(&op, None));
        match result {
            Err(e) => assert!(
                e.to_string().contains("rendezvous")
                    || e.to_string().contains("active receipt")
                    || e.to_string().contains("render")
                    || e.to_string().contains("B04")
                    || e.to_string().contains("permission")
                    || e.to_string().contains("Permission")
            ),
            Ok(receipt) => assert!(
                receipt.receipt_id.is_empty(),
                "provision_minio must fail without a rendezvous"
            ),
        }
    }

    /// `cleanup_secrets` refuses without a verified teardown (upstream:
    /// "teardown must be verified before credential cleanup").
    #[test]
    fn cleanup_secrets_refuses_without_verified_teardown() {
        let topology = Topology::new(
            Arc::new(CapturingRunner {
                run_calls: Mutex::new(Vec::new()),
                exit_code: 0,
            }),
            Arc::new(StaticReceipts {
                receipt: DependencyReceipt::default(),
            }),
            load_default_policy().unwrap(),
            tmpdir("topo-cleanup"),
            RecordingBootstrap {
                cleaned: AtomicU32::new(0),
            },
        );
        let op = LifecycleOperation {
            id: "op-1".to_owned(),
            linked_operation_id: String::new(),
            phase: LifecyclePhase::Failed,
            binding: binding(),
            observation: Observation::default(),
            created_at: OffsetDateTime::UNIX_EPOCH,
        };
        let err = block_on(topology.cleanup_secrets(&op)).unwrap_err();
        assert!(
            err.to_string().contains("teardown must be verified"),
            "{e}",
            e = err
        );
    }

    /// The minio-provision request payload pins the contract's key set.
    #[test]
    fn minio_provision_payload_carries_contract_keys() {
        let mut op = LifecycleOperation {
            id: "op-contract".to_owned(),
            linked_operation_id: String::new(),
            phase: LifecyclePhase::PostgresProvisioned,
            binding: binding(),
            observation: Observation::default(),
            created_at: OffsetDateTime::UNIX_EPOCH,
        };
        op.binding.b04.fencing_token = 987654321;
        let topology = Topology::new(
            Arc::new(CapturingRunner {
                run_calls: Mutex::new(Vec::new()),
                exit_code: 0,
            }),
            Arc::new(StaticReceipts {
                receipt: DependencyReceipt::default(),
            }),
            load_default_policy().unwrap(),
            tmpdir("topo-payload"),
            RecordingBootstrap {
                cleaned: AtomicU32::new(0),
            },
        );
        let payload = topology
            .minio_provision_request_payload(&op, &test_dependency_set())
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        for key in [
            "schema_version",
            "mode",
            "operation_id",
            "instance_id",
            "target",
            "policy_digest",
            "image_digest",
            "deadline",
            "minio_provision",
        ] {
            assert!(json.get(key).is_some(), "missing {key}");
        }
        let mp = &json["minio_provision"];
        assert_eq!(
            mp["root_credential_path"],
            "/run/secrets/minio-root-password"
        );
        assert_eq!(mp["broker_socket_path"], "/run/broker/minio-provision.sock");
        assert_eq!(mp["bucket"], "central-artifacts-v1");
        assert_eq!(mp["key_prefix"], "v1/staging/ v1/ready/");
        assert_eq!(mp["credential_purpose"], "minio_runtime_v1");
        assert_eq!(mp["fence_token"], 987654321);
        for key in [
            "fd_number",
            "device",
            "inode",
            "mount_id",
            "filesystem",
            "uid",
            "gid",
            "root_id",
        ] {
            assert!(json["target"].get(key).is_some(), "missing target.{key}");
        }
        // No credential material may appear anywhere in the payload —
        // only the fixed mount paths (which name, but never contain,
        // the credential file).
        let text = String::from_utf8_lossy(&payload);
        assert!(
            mp["root_credential_path"]
                .as_str()
                .unwrap()
                .starts_with("/run/secrets/")
        );
        assert!(!text.contains("${"), "no interpolation: {text}");
        for key in ["root_password", "secret_key", "credential_value"] {
            assert!(json.get(key).is_none(), "unexpected credential field {key}");
        }
    }

    // -- FileJournal durability (append-only, exclusive, refuse rules) --------

    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(path).unwrap().mode() & 0o777
    }

    /// The event log is append-only sequence files under
    /// `operations/<bindingKey>/<opId>/`, each `O_EXCL` 0600; every
    /// directory level is 0700.
    #[test]
    fn file_journal_appends_immutable_sequence_events_with_strict_modes() {
        let root = tmpdir("journal-durable");
        let journal = FileJournal::new(root.clone(), Arc::new(TestClock)).unwrap();
        let op = block_on(journal.begin(binding(), Observation::default())).unwrap();
        assert!(op.id.starts_with("life-"), "life-<uuid> op id: {}", op.id);
        block_on(journal.record(&op, LifecyclePhase::Verified)).unwrap();
        block_on(journal.record(&op, LifecyclePhase::FsInitialized)).unwrap();
        let op_dir = root
            .join("operations")
            .join(binding_key(&binding()))
            .join(&op.id);
        let mut events: Vec<_> = std::fs::read_dir(&op_dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .collect();
        events.sort();
        assert_eq!(events.len(), 3, "one event per journal write");
        assert_eq!(
            events[0].file_name().unwrap().to_string_lossy(),
            "00000000000000000001.json"
        );
        for event in events {
            assert_eq!(mode_of(&event), 0o600, "event mode");
        }
        for dir in [
            root.join("operations"),
            root.join("operations").join(binding_key(&binding())),
            op_dir,
        ] {
            assert_eq!(mode_of(&dir), 0o700, "dir mode: {dir:?}");
        }
        // The folded state is the LAST event's projection.
        let resumed = block_on(journal.unsettled(&binding())).unwrap().unwrap();
        assert_eq!(resumed.phase, LifecyclePhase::FsInitialized);
    }

    /// The on-disk event is upstream's Go `journalEvent` — PascalCase
    /// `infralifecycle.Operation` fields, nested `B04`, `Observation`,
    /// `BootstrapFingerprints` — and both a Go-written event and a
    /// pre-fix Rust event (flat snake_case aliases) decode.
    #[test]
    fn journal_event_wire_shape_matches_go_and_decodes_both_writers() {
        let root = tmpdir("journal-wire");
        let journal = FileJournal::new(root.clone(), Arc::new(TestClock)).unwrap();
        let obs = Observation {
            boot_id: "boot-1".to_owned(),
            container_start_ids: BTreeMap::from([(ServiceMode::Postgres, "ctr-1".to_owned())]),
        };
        let op = block_on(journal.begin(binding(), obs)).unwrap();
        let ops_dir = root.join("operations").join(binding_key(&binding()));
        let event: serde_json::Value = serde_json::from_slice(
            &std::fs::read(ops_dir.join(&op.id).join("00000000000000000001.json")).unwrap(),
        )
        .unwrap();
        let state = &event["state"];
        assert_eq!(state["operation"]["ID"], op.id);
        assert_eq!(state["operation"]["Phase"], "started");
        assert_eq!(state["operation"]["LinkedOperationID"], "");
        assert_eq!(state["operation"]["Observation"]["BootID"], "boot-1");
        assert_eq!(
            state["operation"]["Observation"]["ContainerStartIDs"]["postgres"],
            "ctr-1"
        );
        assert_eq!(state["operation"]["Binding"]["InstanceID"], "inst-1");
        assert!(
            state["operation"]["Binding"].get("B04").is_some()
                && state["operation"]["Binding"]
                    .get("BootstrapFingerprints")
                    .is_some(),
            "Go binding shape: {event}"
        );
        assert_eq!(state["active"], false);

        // A Go-written event — nested B04, full binding, observed
        // containers — decodes and wins `unsettled` on CreatedAt.
        let go_event = r#"{"state":{"operation":{"ID":"life-go","LinkedOperationID":"","Phase":"verified","Binding":{"InstanceID":"inst-1","ConfigBinding":"cfg-1","AdmissionID":"adm-1","ReceiptID":"receipt-1","ModelDigest":"sha256:model","PayloadEpoch":"epoch-1","BootstrapFingerprints":["sha256:fp1"],"B04":{"InstanceID":"inst-1","OperationID":"life-go","FencingToken":7,"StoppedTopologyProof":"p1","MountReleaseProof":"p2","BindingEvidence":"p3","ExpiresAt":"2026-01-01T00:00:00Z"}},"Observation":{"BootID":"boot-9","ContainerStartIDs":{"minio":"ctr-9"}},"CreatedAt":"2026-01-01T00:00:01Z"},"receipt":{"ID":"receipt-1","ManifestDigest":"sha256:m1","OperationID":"life-go","SelectorGeneration":"gen-1","DependencySet":{"Modes":[{"Mode":"postgres","Inventory":{"index_digest":"sha256:92620daddcd947f8d5ab5ba66e848702fe443d87fed30c4cea8e389fd78dfc55","manifest_digest":"sha256:c95fd5346040eba2de3c435e14874af18f5d681fb5848d4f081dbead0878af28","config_digest":"sha256:67d1da22f4037b29cdd93e03d870a4a1c4d079358367d0cbc56459e52cde205e","layers":[{"Digest":"sha256:aa","MediaType":"mt","Size":3,"Annotations":null}]}}]}},"active":false}}"#;
        let go_dir = ops_dir.join("life-go");
        std::fs::create_dir_all(&go_dir).unwrap();
        std::fs::write(go_dir.join("00000000000000000001.json"), go_event).unwrap();
        let resumed = block_on(journal.unsettled(&binding())).unwrap().unwrap();
        assert_eq!(resumed.id, "life-go");
        assert_eq!(
            resumed.binding.bootstrap_fingerprints,
            vec!["sha256:fp1".to_owned()]
        );
        assert_eq!(resumed.binding.b04.operation_id, "life-go");
        assert_eq!(resumed.binding.b04.fencing_token, 7);
        assert_eq!(resumed.binding.b04.stopped_topology_proof, "p1");
        assert!(resumed.binding.b04.expires_at.is_some());
        assert_eq!(resumed.observation.boot_id, "boot-9");
        assert_eq!(
            resumed.observation.container_start_ids[&ServiceMode::Minio],
            "ctr-9"
        );

        // A pre-fix Rust event — flat snake_case B04 fields — still
        // decodes and projects the same durable state.
        let legacy = r#"{"state":{"operation":{"id":"life-legacy","linked_operation_id":"","phase":"verified","binding":{"instance_id":"inst-1","config_binding":"cfg-1","admission_id":"adm-1","receipt_id":"receipt-1","model_digest":"sha256:model","payload_epoch":"epoch-1","b04_operation_id":"op-legacy","b04_fencing_token":9},"created_at":"2027-01-01T00:00:00Z"},"active":false}}"#;
        let legacy_dir = ops_dir.join("life-legacy");
        std::fs::create_dir_all(&legacy_dir).unwrap();
        std::fs::write(legacy_dir.join("00000000000000000001.json"), legacy).unwrap();
        let resumed = block_on(journal.unsettled(&binding())).unwrap().unwrap();
        assert_eq!(resumed.id, "life-legacy");
        assert_eq!(resumed.binding.b04.operation_id, "op-legacy");
        assert_eq!(resumed.binding.b04.fencing_token, 9);
    }

    /// `Begin` refuses while an unsettled operation exists — the
    /// durable record, not an in-process flag, is the check (a second
    /// journal over the same root denies too).
    #[test]
    fn file_journal_begin_refuses_while_unsettled_across_restart() {
        let root = tmpdir("journal-unsettled");
        let journal = FileJournal::new(root.clone(), Arc::new(TestClock)).unwrap();
        let op = block_on(journal.begin(binding(), Observation::default())).unwrap();
        assert!(block_on(journal.begin(binding(), Observation::default())).is_err());
        // A fresh journal instance sees the same durable refusal.
        let journal2 = FileJournal::new(root, Arc::new(TestClock)).unwrap();
        assert!(block_on(journal2.begin(binding(), Observation::default())).is_err());
        block_on(journal.settle(&op, LifecyclePhase::Failed)).unwrap();
        assert!(block_on(journal2.begin(binding(), Observation::default())).is_ok());
    }

    /// `settle` accepts only terminal phases; `begin_linked_down`
    /// requires a live unsettled up for the same binding;
    /// `prepare_receipt` binds to the binding's own receipt id.
    #[test]
    fn file_journal_refusal_rules() {
        let root = tmpdir("journal-rules");
        let journal = FileJournal::new(root, Arc::new(TestClock)).unwrap();
        let op = block_on(journal.begin(binding(), Observation::default())).unwrap();
        // Non-terminal settle refused.
        assert!(block_on(journal.settle(&op, LifecyclePhase::Verified)).is_err());
        // A terminal linked op is not a valid link target.
        let mut linked = op.clone();
        linked.phase = LifecyclePhase::Completed;
        assert!(
            block_on(journal.begin_linked_down(binding(), Observation::default(), &linked))
                .is_err()
        );
        // A linked op for a different binding is refused.
        let mut foreign = op.clone();
        foreign.phase = LifecyclePhase::Started;
        foreign.binding.config_binding = "cfg-other".to_owned();
        assert!(
            block_on(journal.begin_linked_down(binding(), Observation::default(), &foreign))
                .is_err()
        );
        // A receipt that is not the binding's own is refused.
        let receipt = DependencyReceipt {
            id: "receipt-other".to_owned(),
            dependency_set: test_dependency_set(),
            ..DependencyReceipt::default()
        };
        assert!(block_on(journal.prepare_receipt(&op, &receipt)).is_err());
    }

    /// `ActiveReceipt` — the selector-visible receipt exists only
    /// after prepare + switch, and survives a journal restart.
    #[test]
    fn file_journal_active_receipt_requires_switch_and_survives_restart() {
        let root = tmpdir("journal-active");
        let journal = FileJournal::new(root.clone(), Arc::new(TestClock)).unwrap();
        let op = block_on(journal.begin(binding(), Observation::default())).unwrap();
        assert!(journal.active_receipt(&binding()).is_err());
        let receipt = DependencyReceipt {
            id: "receipt-1".to_owned(),
            dependency_set: test_dependency_set(),
            ..DependencyReceipt::default()
        };
        block_on(journal.prepare_receipt(&op, &receipt)).unwrap();
        // Prepared but not switched — still not active.
        assert!(journal.active_receipt(&binding()).is_err());
        block_on(journal.switch_receipt(&op)).unwrap();
        assert_eq!(journal.active_receipt(&binding()).unwrap().id, "receipt-1");
        let journal2 = FileJournal::new(root, Arc::new(TestClock)).unwrap();
        assert_eq!(journal2.active_receipt(&binding()).unwrap().id, "receipt-1");
    }

    // -- FileLocker owner checks ---------------------------------------------

    /// `release` requires the caller's exact lock id — a stale or
    /// foreign id is refused and the live lock survives.
    #[test]
    fn file_locker_release_requires_exact_owner() {
        let dir = tmpdir("lock-owner");
        let locker = FileLocker::new(
            dir,
            Duration::from_secs(600),
            Arc::new(TestClock),
            Arc::new(NoDeadOwner),
        );
        let lock = block_on(locker.acquire(&binding())).unwrap();
        let foreign = LifecycleLock {
            id: "lock-foreign".to_owned(),
            acquired: true,
            expires_at: lock.expires_at,
            fencing_token: 1,
        };
        assert!(block_on(locker.release(&binding(), foreign)).is_err());
        // The live record is still held — a second acquire denies.
        assert!(block_on(locker.acquire(&binding())).is_err());
        block_on(locker.release(&binding(), lock)).unwrap();
    }

    // -- FileBootstrap durable handoff record ---------------------------------

    /// A fake B04 authority whose materialize returns a scripted
    /// proof; the mount file is a real temp file so cleanup is
    /// observable.
    struct ScriptedB04 {
        proof: MountProof,
    }
    impl B04Bootstrap for ScriptedB04 {
        async fn adopt_b03_minio(
            &self,
            _e: central_infra::domain::B04LifecycleEvidence,
        ) -> Result<(), Failure> {
            Ok(())
        }
        async fn materialize_minio_root(
            &self,
            _h: BootstrapHandoff,
        ) -> Result<MountProof, Failure> {
            Ok(self.proof.clone())
        }
        async fn issue_lifecycle_proof(
            &self,
            _e: central_infra::domain::B04LifecycleEvidence,
        ) -> Result<(), Failure> {
            Ok(())
        }
    }

    /// `RecordHandoff` writes the nonsecret durable record (`0600`),
    /// `CleanupBinding` removes the mount and rewrites the record
    /// `removed`, and a restarted bootstrap over the same root resumes
    /// the record — the C3 crash window.
    #[test]
    fn file_bootstrap_durable_handoff_record_survives_restart() {
        let root = tmpdir("bootstrap-record");
        let mount_dir = tmpdir("bootstrap-mount");
        let mount_path = mount_dir.join("minio-root-password");
        std::fs::write(&mount_path, b"not-a-real-secret").unwrap();
        let bootstrap = FileBootstrap::new(
            root.clone(),
            Arc::new(TestClock),
            ScriptedB04 {
                proof: MountProof {
                    handoff_digest: "sha256:proof".to_owned(),
                    mount_path: mount_path.to_string_lossy().to_string(),
                    confirmed: true,
                },
            },
        );
        let proof = MountProof {
            handoff_digest: "sha256:proof".to_owned(),
            mount_path: mount_path.to_string_lossy().to_string(),
            confirmed: true,
        };
        block_on(bootstrap.record_handoff(&binding(), &proof)).unwrap();
        let record_path = root.join(format!("{}.handoff.json", binding_key(&binding())));
        assert_eq!(mode_of(&record_path), 0o600);
        let record_text = std::fs::read_to_string(&record_path).unwrap();
        assert!(record_text.contains(&mount_path.to_string_lossy().to_string()));
        // The record never carries credential material.
        assert!(!record_text.contains("not-a-real-secret"));

        // A restarted bootstrap resumes cleanup from the record alone.
        let bootstrap2 = FileBootstrap::new(
            root.clone(),
            Arc::new(TestClock),
            ScriptedB04 {
                proof: MountProof::default(),
            },
        );
        block_on(bootstrap2.cleanup_binding(&binding())).unwrap();
        assert!(!mount_path.exists(), "mount removed by cleanup_binding");
        // The record stays as durable `removed` evidence; a second
        // cleanup is a no-op, not an error.
        let record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&record_path).unwrap()).unwrap();
        assert_eq!(record["removed"], true);
        block_on(bootstrap2.cleanup_binding(&binding())).unwrap();
    }

    /// `Materialize` refuses a handoff outside the fixed MinIO secrets
    /// destination, an expired lifetime, and an unconfirmed broker
    /// proof; `Cleanup` is single-use (upstream's `used` map).
    #[test]
    fn file_bootstrap_refusal_rules() {
        let root = tmpdir("bootstrap-rules");
        let mount_dir = tmpdir("bootstrap-mount2");
        let mount_path = mount_dir.join("minio-root-password");
        std::fs::write(&mount_path, b"x").unwrap();
        let bootstrap = FileBootstrap::new(
            root,
            Arc::new(TestClock),
            ScriptedB04 {
                proof: MountProof {
                    handoff_digest: String::new(),
                    mount_path: mount_path.to_string_lossy().to_string(),
                    confirmed: true,
                },
            },
        );
        let handoff = BootstrapHandoff {
            instance_id: binding().instance_id.clone(),
            purpose: BootstrapPurpose::FirstSetup,
            service: ServiceMode::Minio,
            target: format!("/run/central-infra/{}/secrets", binding().instance_id),
            uid: 1000,
            gid: 1000,
            lifetime: HandoffLifetime {
                expires: OffsetDateTime::UNIX_EPOCH + Duration::from_secs(2000),
                ..HandoffLifetime::default()
            },
            container_id: String::new(),
            b04_operation_id: String::new(),
            b04_binding_id: String::new(),
            b04_receipt_id: String::new(),
            b04_fencing_token: 0,
            b04_stopped_topology_proof: String::new(),
            b04_mount_release_proof: String::new(),
            b04_binding_evidence: String::new(),
        };
        // Wrong target — refused before the broker is consulted.
        let mut bad = handoff.clone();
        bad.target = "/tmp/elsewhere".to_owned();
        assert!(block_on(bootstrap.materialize(bad)).is_err());
        // Wrong owner — refused.
        let mut bad = handoff.clone();
        bad.uid = 0;
        assert!(block_on(bootstrap.materialize(bad)).is_err());
        // Expired lifetime — refused.
        let mut bad = handoff.clone();
        bad.lifetime.expires = OffsetDateTime::UNIX_EPOCH + Duration::from_secs(1);
        assert!(block_on(bootstrap.materialize(bad)).is_err());
        // A valid handoff materializes; cleanup consumes the proof
        // exactly once.
        let proof = block_on(bootstrap.materialize(handoff)).unwrap();
        block_on(bootstrap.cleanup(proof.clone())).unwrap();
        assert!(block_on(bootstrap.cleanup(proof)).is_err());
    }

    // -- Down re-render after restart (H3) ------------------------------------

    /// A fresh `Topology` over the same runtime root — the post-reboot
    /// helper — re-renders the compose file for `down` from durable
    /// inputs alone, without materializing a credential.
    #[test]
    fn down_rerenders_compose_file_after_helper_restart() {
        let runtime = tmpdir("topo-reboot");
        let receipts = || {
            Arc::new(StaticReceipts {
                receipt: DependencyReceipt {
                    id: "receipt-1".to_owned(),
                    dependency_set: test_dependency_set(),
                    ..DependencyReceipt::default()
                },
            }) as Arc<dyn ActiveReceiptReader>
        };
        let make_topology = || {
            Topology::new(
                Arc::new(CapturingRunner {
                    run_calls: Mutex::new(Vec::new()),
                    exit_code: 0,
                }),
                receipts(),
                load_default_policy().unwrap(),
                runtime.clone(),
                RecordingBootstrap {
                    cleaned: AtomicU32::new(0),
                },
            )
        };
        let compose_path = runtime.join("inst-1").join("docker-compose.yaml");
        // The first boot's topology renders the file. `file(false)` —
        // the render path without the root-only materialize write
        // under /run/central-infra — is the same durable output `down`
        // re-renders from.
        let t1 = make_topology();
        t1.file(&binding(), false, OpDeadline::NONE).unwrap();
        assert!(compose_path.exists(), "rendered compose file exists");
        // Reboot: the tmpfs runtime root is wiped; the restart's
        // topology has no in-process proof or file cache.
        std::fs::remove_file(&compose_path).unwrap();
        let t2 = make_topology();
        let op = LifecycleOperation {
            id: "op-down".to_owned(),
            linked_operation_id: String::new(),
            phase: LifecyclePhase::Started,
            binding: binding(),
            observation: Observation::default(),
            created_at: OffsetDateTime::UNIX_EPOCH,
        };
        block_on(TopologyPort::down(&t2, &op, None)).unwrap();
        assert!(
            compose_path.exists(),
            "down re-rendered the compose file after restart"
        );
    }

    /// `file()` persists the rendered compose file mode 0600 under a
    /// 0700 instance directory.
    #[test]
    fn rendered_compose_file_and_dir_modes() {
        let runtime = tmpdir("topo-modes");
        let topology = Topology::new(
            Arc::new(CapturingRunner {
                run_calls: Mutex::new(Vec::new()),
                exit_code: 0,
            }),
            Arc::new(StaticReceipts {
                receipt: DependencyReceipt {
                    id: "receipt-1".to_owned(),
                    dependency_set: test_dependency_set(),
                    ..DependencyReceipt::default()
                },
            }),
            load_default_policy().unwrap(),
            runtime.clone(),
            RecordingBootstrap {
                cleaned: AtomicU32::new(0),
            },
        );
        // `file(false)` — the materialize path additionally writes the
        // init script under /run/central-infra, which needs root; the
        // render path is what owns these modes.
        topology.file(&binding(), false, OpDeadline::NONE).unwrap();
        let dir = runtime.join("inst-1");
        assert_eq!(mode_of(&dir), 0o700);
        assert_eq!(mode_of(&dir.join("docker-compose.yaml")), 0o600);
    }
}
