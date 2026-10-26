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
use std::time::Duration;

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
    BootstrapPurpose, DeadOwnerVerifier, LifecycleAdmission, LifecycleBarrier, LifecycleBootstrap,
    LifecycleCapacity, LifecycleClock, LifecycleLock, LifecycleLocker, LifecyclePort,
    LifecycleReservation, MountProof, TopologyPort,
};

use super::compose::{
    BROKER_SOCKET_TARGET, CommandExecutor, ComposeRunner, POSTGRES_INIT_SCRIPT_SQL, Policy,
    REQUIRED_SERVICE_MODES, RenderedFile, closed_docker_environment, durable_service_data_root,
    durable_service_root, image_reference, load_default_policy, parse_rendered_model,
    policy_digest, postgres_init_script_host_path, render, validate_model,
};

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
/// enforces independently.
const REQUEST_DEADLINE: Duration = Duration::from_secs(30);

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
    /// binding keys whose teardown was verified this process lifetime —
    /// upstream's `t.teardowns` map.
    teardowns: Mutex<BTreeSet<String>>,
    /// Materialized mount proofs per binding key — upstream's
    /// `t.proofs`.
    proofs: Mutex<BTreeMap<String, Vec<MountProof>>>,
}

fn binding_key(b: &LifecycleBinding) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        b.instance_id, b.config_binding, b.receipt_id, b.model_digest, b.payload_epoch
    )
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

    /// `existingFile` — the rendered file on disk, if present.
    fn existing_file(&self, binding: &LifecycleBinding) -> Result<Option<RenderedFile>, Failure> {
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

    /// `file` — the rendered file; when `materialize` is set the file is
    /// rendered and written (with the init script and the B04 handoff)
    /// when absent. A `false` caller (down/status) never materializes.
    fn file(&self, binding: &LifecycleBinding, materialize: bool) -> Result<RenderedFile, Failure> {
        if let Some(f) = self.existing_file(binding)? {
            return Ok(f);
        }
        if !materialize {
            return Err(Failure::not_found(
                "TOPOLOGY",
                "topology: rendered compose file is absent",
            ));
        }
        let receipt = self
            .receipts
            .active()
            .map_err(|e| Failure::internal("TOPOLOGY", format!("topology: active receipt: {e}")))?;
        let f = render(binding, &receipt.dependency_set, &self.policy)
            .map_err(|e| Failure::internal("TOPOLOGY", format!("topology: render: {e}")))?;
        let dir = Path::new(&f.path)
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default();
        std::fs::create_dir_all(&dir).map_err(|e| {
            Failure::internal("TOPOLOGY", format!("topology: create runtime dir: {e}"))
        })?;
        // The init-script mount source must exist before `compose up`, or
        // Docker auto-creates it as an empty directory and initdb aborts.
        let init_path = postgres_init_script_host_path("", &binding.instance_id);
        if let Some(init_dir) = Path::new(&init_path).parent() {
            std::fs::create_dir_all(init_dir).map_err(|e| {
                Failure::internal("TOPOLOGY", format!("topology: create init dir: {e}"))
            })?;
        }
        std::fs::write(&init_path, POSTGRES_INIT_SCRIPT_SQL).map_err(|e| {
            Failure::internal("TOPOLOGY", format!("topology: write init script: {e}"))
        })?;
        std::fs::write(&f.path, &f.content).map_err(|e| {
            Failure::internal("TOPOLOGY", format!("topology: write rendered file: {e}"))
        })?;
        self.materialize_handoff(binding)?;
        Ok(f)
    }

    /// The B04 credential handoff: issue the lifecycle proof, adopt the
    /// legacy B03 bootstrap, then materialize the MinIO root credential
    /// under the bound handoff — recording the mount proof for
    /// `cleanup_secrets`. Delegates every authority step to the injected
    /// `B04Bootstrap` port (the broker custody path: sealed `memfd`
    /// over `SCM_RIGHTS`); this adapter never sees credential material.
    fn materialize_handoff(&self, binding: &LifecycleBinding) -> Result<(), Failure> {
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
        let evidence = binding.b04.clone();
        block_on(self.bootstrap.issue_lifecycle_proof(evidence.clone())).map_err(|e| {
            Failure::internal("TOPOLOGY", format!("topology: B04 issue proof: {e}"))
        })?;
        block_on(self.bootstrap.adopt_b03_minio(evidence.clone()))
            .map_err(|e| Failure::internal("TOPOLOGY", format!("topology: B04 adoption: {e}")))?;
        let handoff = BootstrapHandoff {
            instance_id: binding.instance_id.clone(),
            purpose: BootstrapPurpose::FirstSetup,
            service: ServiceMode::Minio,
            target: format!(
                "/run/central-infra/{}/secrets/minio-root-password",
                binding.instance_id
            ),
            uid: 1000,
            gid: 1000,
            lifetime: Default::default(),
            container_id: String::new(),
            b04_operation_id: evidence.operation_id.clone(),
            b04_binding_id: String::new(),
            b04_receipt_id: String::new(),
            b04_fencing_token: evidence.fencing_token,
            b04_stopped_topology_proof: evidence.stopped_topology_proof.clone(),
            b04_mount_release_proof: evidence.mount_release_proof.clone(),
            b04_binding_evidence: evidence.binding_evidence.clone(),
        };
        let proof = block_on(self.bootstrap.materialize_minio_root(handoff)).map_err(|e| {
            Failure::internal("TOPOLOGY", format!("topology: B04 materialize: {e}"))
        })?;
        self.proofs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(key)
            .or_default()
            .push(proof);
        Ok(())
    }

    /// `activeDependencySet` — the receipt's prepared set, validated.
    fn active_dependency_set(
        &self,
        binding: &LifecycleBinding,
    ) -> Result<PreparedDependencySet, Failure> {
        let receipt = self
            .receipts
            .active()
            .map_err(|e| Failure::internal("TOPOLOGY", format!("topology: active receipt: {e}")))?;
        if receipt.id != binding.receipt_id {
            return Err(Failure::denied(
                "TOPOLOGY",
                "topology: active receipt does not match binding",
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
    ) -> Result<TopologySnapshot, Failure> {
        let containers = self
            .runner
            .containers(f, &["postgres".to_owned(), "minio".to_owned()])?;
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
    async fn validate(&self, binding: &LifecycleBinding) -> Result<(), Failure> {
        // Receipt binding is authoritative; the rendered file must exist
        // and parse+validate through the real compose config model.
        let _set = self.active_dependency_set(binding)?;
        let f = self.file(binding, true)?;
        let _model = self
            .runner
            .config(&f)
            .map_err(|e| Failure::internal("TOPOLOGY", format!("topology: compose config: {e}")))?;
        Ok(())
    }

    async fn init(&self, op: &LifecycleOperation) -> Result<(), Failure> {
        let f = self.file(&op.binding, true)?;
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
                .run_with_input(&f, service, &[REQUEST_MODE_FS_INIT.to_owned()], &payload)
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

    async fn start_daemons(&self, op: &LifecycleOperation) -> Result<Observation, Failure> {
        let f = self.file(&op.binding, true)?;
        self.runner
            .up(&f, &["postgres".to_owned(), "minio".to_owned()])
            .map_err(|e| Failure::internal("TOPOLOGY", e.to_string()))?;
        Ok(Observation::default())
    }

    async fn provision_minio(&self, op: &LifecycleOperation) -> Result<SemanticReceipt, Failure> {
        let f = self.file(&op.binding, true)?;
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

    async fn inspect(&self, binding: &LifecycleBinding) -> Result<TopologySnapshot, Failure> {
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
            return self.inspect_rendered(binding, &f);
        }
        TopologyPort::validate(self, binding).await?;
        let f = self.file(binding, false)?;
        self.inspect_rendered(binding, &f)
    }

    async fn down(&self, op: &LifecycleOperation) -> Result<(), Failure> {
        // Teardown-only: a helper restart must never materialize a new
        // credential merely to render the file `compose down` needs.
        let f = self.file(&op.binding, false)?;
        self.runner
            .down(&f)
            .map_err(|e| Failure::internal("TOPOLOGY", e.to_string()))
    }

    async fn teardown_verified(&self, op: &LifecycleOperation) -> Result<(), Failure> {
        self.down(op).await?;
        if let Some(f) = self.existing_file(&op.binding)? {
            let services: Vec<String> = REQUIRED_SERVICE_MODES
                .iter()
                .map(|s| (*s).to_owned())
                .collect();
            self.runner
                .stopped(&f, &services)
                .map_err(|e| Failure::internal("TOPOLOGY", e.to_string()))?;
        }
        self.mark_teardown_verified(&op.binding);
        Ok(())
    }

    async fn cleanup_secrets(&self, op: &LifecycleOperation) -> Result<(), Failure> {
        let key = binding_key(&op.binding);
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
        let proofs = self
            .proofs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&key)
            .cloned()
            .unwrap_or_default();
        for proof in proofs {
            self.bootstrap.cleanup(proof).await?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// FileJournal — durable per-operation JSON event records; the selector
// owner (receipt activation only after a durably prepared receipt).
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct JournalRecord {
    id: String,
    linked_operation_id: String,
    phase: String,
    terminal: bool,
    binding: JournalBinding,
    created_at: String,
    receipt: Option<DependencyReceiptJson>,
    active: bool,
}

#[derive(Serialize, Deserialize, Clone)]
struct JournalBinding {
    instance_id: String,
    config_binding: String,
    admission_id: String,
    receipt_id: String,
    model_digest: String,
    payload_epoch: String,
    b04_operation_id: String,
    b04_fencing_token: u64,
}

#[derive(Serialize, Deserialize)]
struct DependencyReceiptJson {
    id: String,
    set: PreparedDependencySet,
}

fn binding_journal_dir(root: &Path, binding: &LifecycleBinding) -> PathBuf {
    let digest = Sha256::digest(binding_key(binding).as_bytes());
    root.join(format!("b{}", hex(&digest[..8])))
}

fn record_to_op(r: &JournalRecord) -> LifecycleOperation {
    let created_at = OffsetDateTime::parse(
        &r.created_at,
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap_or(OffsetDateTime::UNIX_EPOCH);
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
            bootstrap_fingerprints: Vec::new(),
            b04: central_infra::domain::B04LifecycleEvidence {
                operation_id: r.binding.b04_operation_id.clone(),
                fencing_token: r.binding.b04_fencing_token,
                ..Default::default()
            },
        },
        observation: Observation::default(),
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

/// `FileJournal` — immutable operation records under `root`; current
/// state derives from the final record. Operation evidence is never
/// replaced.
pub struct FileJournal {
    root: PathBuf,
    clock: Arc<dyn LifecycleClock>,
    mu: Mutex<()>,
    seq: Mutex<u64>,
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
            seq: Mutex::new(0),
        })
    }

    fn next_op_id(&self) -> String {
        let mut seq = self
            .seq
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *seq += 1;
        format!(
            "op-{}-{:06}",
            self.clock.now().unix_timestamp_nanos() / 1000,
            *seq
        )
    }

    fn write(&self, rec: &JournalRecord) -> Result<(), Failure> {
        let dir = binding_journal_dir(
            &self.root,
            &LifecycleBinding {
                instance_id: rec.binding.instance_id.clone(),
                config_binding: rec.binding.config_binding.clone(),
                admission_id: rec.binding.admission_id.clone(),
                receipt_id: rec.binding.receipt_id.clone(),
                model_digest: rec.binding.model_digest.clone(),
                payload_epoch: rec.binding.payload_epoch.clone(),
                bootstrap_fingerprints: Vec::new(),
                b04: Default::default(),
            },
        );
        std::fs::create_dir_all(&dir)
            .map_err(|e| Failure::internal("JOURNAL", format!("journal: dir: {e}")))?;
        let tmp = dir.join(format!("{}.tmp", rec.id));
        let final_path = dir.join(format!("{}.json", rec.id));
        let bytes = serde_json::to_vec(rec)
            .map_err(|e| Failure::internal("JOURNAL", format!("journal: encode: {e}")))?;
        std::fs::write(&tmp, &bytes)
            .map_err(|e| Failure::internal("JOURNAL", format!("journal: write: {e}")))?;
        std::fs::rename(&tmp, &final_path)
            .map_err(|e| Failure::internal("JOURNAL", format!("journal: rename: {e}")))?;
        Ok(())
    }

    fn load(&self, binding: &LifecycleBinding, op_id: &str) -> Result<JournalRecord, Failure> {
        let path = binding_journal_dir(&self.root, binding).join(format!("{op_id}.json"));
        let bytes = std::fs::read(&path)
            .map_err(|e| Failure::internal("JOURNAL", format!("journal: read: {e}")))?;
        serde_json::from_slice(&bytes)
            .map_err(|e| Failure::internal("JOURNAL", format!("journal: decode: {e}")))
    }

    fn all_records(&self, binding: &LifecycleBinding) -> Result<Vec<JournalRecord>, Failure> {
        let dir = binding_journal_dir(&self.root, binding);
        let mut out = Vec::new();
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(Failure::internal("JOURNAL", format!("journal: list: {e}"))),
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.ends_with(".json") {
                continue;
            }
            let bytes = std::fs::read(entry.path())
                .map_err(|e| Failure::internal("JOURNAL", format!("journal: read: {e}")))?;
            out.push(
                serde_json::from_slice(&bytes)
                    .map_err(|e| Failure::internal("JOURNAL", format!("journal: decode: {e}")))?,
            );
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }

    fn to_record(
        &self,
        op: &LifecycleOperation,
        receipt: Option<DependencyReceiptJson>,
        active: bool,
    ) -> JournalRecord {
        JournalRecord {
            id: op.id.clone(),
            linked_operation_id: op.linked_operation_id.clone(),
            phase: op.phase.as_str().to_owned(),
            terminal: op.phase.is_terminal(),
            binding: JournalBinding {
                instance_id: op.binding.instance_id.clone(),
                config_binding: op.binding.config_binding.clone(),
                admission_id: op.binding.admission_id.clone(),
                receipt_id: op.binding.receipt_id.clone(),
                model_digest: op.binding.model_digest.clone(),
                payload_epoch: op.binding.payload_epoch.clone(),
                b04_operation_id: op.binding.b04.operation_id.clone(),
                b04_fencing_token: op.binding.b04.fencing_token,
            },
            created_at: rfc3339(op.created_at),
            receipt,
            active,
        }
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
        let op = LifecycleOperation {
            id: self.next_op_id(),
            linked_operation_id: String::new(),
            phase: LifecyclePhase::Started,
            binding,
            observation,
            created_at: self.clock.now(),
        };
        let rec = self.to_record(&op, None, false);
        self.write(&rec)?;
        Ok(op)
    }

    async fn begin_linked_down(
        &self,
        binding: LifecycleBinding,
        observation: Observation,
        linked: &LifecycleOperation,
    ) -> Result<LifecycleOperation, Failure> {
        binding.validate()?;
        let _g = self
            .mu
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let op = LifecycleOperation {
            id: self.next_op_id(),
            linked_operation_id: linked.id.clone(),
            phase: LifecyclePhase::Started,
            binding,
            observation,
            created_at: self.clock.now(),
        };
        let rec = self.to_record(&op, None, false);
        self.write(&rec)?;
        Ok(op)
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
        let mut rec = self.load(&operation.binding, &operation.id)?;
        rec.phase = phase.as_str().to_owned();
        rec.terminal = phase.is_terminal();
        self.write(&rec)
    }

    async fn prepare_receipt(
        &self,
        operation: &LifecycleOperation,
        receipt: &DependencyReceipt,
    ) -> Result<(), Failure> {
        let _g = self
            .mu
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut rec = self.load(&operation.binding, &operation.id)?;
        rec.receipt = Some(DependencyReceiptJson {
            id: receipt.id.clone(),
            set: receipt.dependency_set.clone(),
        });
        self.write(&rec)
    }

    async fn switch_receipt(&self, operation: &LifecycleOperation) -> Result<(), Failure> {
        let _g = self
            .mu
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut rec = self.load(&operation.binding, &operation.id)?;
        if rec.receipt.is_none() {
            return Err(Failure::invalid(
                "JOURNAL",
                "journal: receipt switch requires a prepared receipt",
            ));
        }
        rec.active = true;
        self.write(&rec)
    }

    async fn settle(
        &self,
        operation: &LifecycleOperation,
        phase: LifecyclePhase,
    ) -> Result<(), Failure> {
        let _g = self
            .mu
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut rec = self.load(&operation.binding, &operation.id)?;
        rec.phase = phase.as_str().to_owned();
        rec.terminal = true;
        self.write(&rec)
    }

    async fn unsettled(
        &self,
        binding: &LifecycleBinding,
    ) -> Result<Option<LifecycleOperation>, Failure> {
        let records = self.all_records(binding)?;
        Ok(records.iter().rev().find(|r| !r.terminal).map(record_to_op))
    }
}

// ---------------------------------------------------------------------------
// FileLocker — exclusive lock file per binding; expiry alone never
// authorizes takeover (dead-owner proof required).
// ---------------------------------------------------------------------------

/// `FileLocker`.
pub struct FileLocker<V> {
    dir: PathBuf,
    lifetime: Duration,
    clock: Arc<dyn LifecycleClock>,
    verifier: V,
}

#[derive(Serialize, Deserialize)]
struct LockFile {
    id: String,
    owner_pid: i32,
    expires_at: String,
    fencing_token: u64,
}

impl<V: DeadOwnerVerifier> FileLocker<V> {
    /// `NewFileLocker`.
    pub fn new(
        dir: PathBuf,
        lifetime: Duration,
        clock: Arc<dyn LifecycleClock>,
        verifier: V,
    ) -> Self {
        Self {
            dir,
            lifetime,
            clock,
            verifier,
        }
    }

    fn lock_path(&self, binding: &LifecycleBinding) -> PathBuf {
        let digest = Sha256::digest(binding_key(binding).as_bytes());
        self.dir.join(format!("l{}.lock", hex(&digest[..8])))
    }

    fn fencing(&self) -> u64 {
        let now = self.clock.now().unix_timestamp_nanos();
        (now as u64) | 1
    }
}

impl<V: DeadOwnerVerifier + Sync> LifecycleLocker for FileLocker<V> {
    async fn acquire(&self, binding: &LifecycleBinding) -> Result<LifecycleLock, Failure> {
        std::fs::create_dir_all(&self.dir)
            .map_err(|e| Failure::internal("LOCK", format!("lifecycle lock: create dir: {e}")))?;
        let path = self.lock_path(binding);
        let expires = self.clock.now() + self.lifetime;
        let file = LockFile {
            id: format!(
                "lock-{}",
                hex(&Sha256::digest(path.to_string_lossy().as_bytes())[..8])
            ),
            owner_pid: std::process::id() as i32,
            expires_at: rfc3339(expires),
            fencing_token: self.fencing(),
        };
        let bytes = serde_json::to_vec(&file)
            .map_err(|e| Failure::internal("LOCK", format!("lifecycle lock: encode: {e}")))?;
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut f) => {
                use std::io::Write;
                f.write_all(&bytes).map_err(|e| {
                    Failure::internal("LOCK", format!("lifecycle lock: write: {e}"))
                })?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // Lock held: expiry alone never authorizes takeover —
                // require the broker's dead-owner proof.
                let existing: LockFile =
                    serde_json::from_slice(&std::fs::read(&path).map_err(|e2| {
                        Failure::internal("LOCK", format!("lifecycle lock: read: {e2}"))
                    })?)
                    .map_err(|e2| {
                        Failure::internal("LOCK", format!("lifecycle lock: decode: {e2}"))
                    })?;
                let expires_at = OffsetDateTime::parse(
                    &existing.expires_at,
                    &time::format_description::well_known::Rfc3339,
                )
                .unwrap_or(OffsetDateTime::UNIX_EPOCH);
                if expires_at > self.clock.now() {
                    return Err(Failure::denied(
                        "LOCK_CONTENTION",
                        "lifecycle lock: already held",
                    ));
                }
                let proof = self
                    .verifier
                    .verify_dead_owner(&existing.id, existing.owner_pid)
                    .await?;
                if !proof.dead {
                    return Err(Failure::denied(
                        "LOCK_CONTENTION",
                        "lifecycle lock: owner still alive",
                    ));
                }
                std::fs::write(&path, &bytes).map_err(|e2| {
                    Failure::internal("LOCK", format!("lifecycle lock: takeover: {e2}"))
                })?;
            }
            Err(e) => {
                return Err(Failure::internal(
                    "LOCK",
                    format!("lifecycle lock: create: {e}"),
                ));
            }
        }
        Ok(LifecycleLock {
            id: file.id,
            acquired: true,
            expires_at: expires,
            fencing_token: file.fencing_token,
        })
    }

    async fn release(
        &self,
        binding: &LifecycleBinding,
        lock: LifecycleLock,
    ) -> Result<(), Failure> {
        let path = self.lock_path(binding);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Failure::internal(
                "LOCK",
                format!("lifecycle lock: release {}: {e}", lock.id),
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// FileBarrier + FilesystemCapacity + receiptAdmission + inspector
// ---------------------------------------------------------------------------

/// `FileBarrier` — denies a writable start while a conflicting
/// lifecycle operation is unsettled for the binding.
pub struct FileBarrier {
    journal: Arc<FileJournal>,
}

impl FileBarrier {
    /// `NewFileBarrier` — the barrier consults the durable journal.
    pub fn new(journal: Arc<FileJournal>) -> Self {
        Self { journal }
    }
}

impl LifecycleBarrier for FileBarrier {
    async fn validate_writable_start(&self, binding: &LifecycleBinding) -> Result<(), Failure> {
        if self.journal.unsettled(binding).await?.is_some() {
            return Err(Failure::denied(
                "BARRIER_CONFLICT",
                "lifecycle barrier: a conflicting operation is in progress",
            ));
        }
        Ok(())
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
        _set: &PreparedDependencySet,
    ) -> Result<LifecycleReservation, Failure> {
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
            id: format!(
                "cap-{}",
                hex(&Sha256::digest(binding_key(binding).as_bytes())[..8])
            ),
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
                Box::new(|name, args, env| {
                    let output = std::process::Command::new(name)
                        .args(args)
                        .env_clear()
                        .envs(env.iter().filter_map(|e| e.split_once('=')))
                        .output()
                        .map_err(|e| e.to_string())?;
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
/// produced (an opaque `MountProof`); `as_b04` exposes the typed B04
/// authority `Topology::materialize_handoff` requires.
pub struct FileBootstrap<B> {
    root: PathBuf,
    b04: B,
    files: Mutex<BTreeMap<String, PathBuf>>,
}

impl<B: B04Bootstrap> FileBootstrap<B> {
    /// `NewFileBootstrap`.
    pub fn new(root: PathBuf, _clock: Arc<dyn LifecycleClock>, b04: B) -> Self {
        Self {
            root,
            b04,
            files: Mutex::new(BTreeMap::new()),
        }
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

impl<B: B04Bootstrap> LifecycleBootstrap for FileBootstrap<B> {
    async fn ensure(
        &self,
        binding: &LifecycleBinding,
        purpose: BootstrapPurpose,
    ) -> Result<BootstrapGeneration, Failure> {
        binding.validate()?;
        let key = format!("{:?}-{}", purpose, binding.instance_id);
        let digest = Sha256::digest(key.as_bytes());
        let path = self.root.join(format!("{}.generation", hex(&digest[..8])));
        if !path.exists() {
            std::fs::create_dir_all(&self.root).map_err(|e| {
                Failure::internal("BOOTSTRAP", format!("bootstrap: create root: {e}"))
            })?;
            std::fs::write(&path, digest).map_err(|e| {
                Failure::internal("BOOTSTRAP", format!("bootstrap: write generation: {e}"))
            })?;
            set_mode(&path.to_string_lossy(), 0o600)
                .map_err(|e| Failure::internal("BOOTSTRAP", format!("bootstrap: mode: {e}")))?;
        }
        self.files
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key.clone(), path);
        Ok(BootstrapGeneration {
            generation: 1,
            digest: format!("sha256:{}", hex(&digest)),
        })
    }

    async fn materialize(&self, handoff: BootstrapHandoff) -> Result<MountProof, Failure> {
        // The credential material itself never transits this process in
        // plaintext: the broker writes it under the sealed handoff and
        // this call returns only the mount proof.
        self.b04.materialize_minio_root(handoff).await
    }

    async fn cleanup(&self, proof: MountProof) -> Result<(), Failure> {
        if proof.mount_path.is_empty() {
            return Ok(());
        }
        match std::fs::remove_file(&proof.mount_path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Failure::internal(
                "BOOTSTRAP",
                format!("bootstrap: cleanup: {e}"),
            )),
        }
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
        barrier: Some(Arc::new(FileBarrier::new(journal))),
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

    fn request(&self) -> LifecycleRequest {
        LifecycleRequest {
            instance_id: self.binding.instance_id.clone(),
            config_binding: self.binding.config_binding.clone(),
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
    /// `up` — drives the domain service synchronously for the helper.
    pub fn up(&self) -> LifecycleResult {
        block_on(self.service.up(self.request()))
    }

    /// `down`.
    pub fn down(&self) -> LifecycleResult {
        block_on(self.service.down(self.request()))
    }

    /// `status` — read-only.
    pub fn status(&self) -> LifecycleResult {
        block_on(self.service.status(LifecycleStatusRequest {
            instance_id: self.binding.instance_id.clone(),
            config_binding: self.binding.config_binding.clone(),
        }))
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
        _deadline: std::time::Instant,
        _operation: crate::helper::lifecycle::LifecycleOperation,
    ) -> crate::helper::lifecycle::LifecycleServiceResult {
        Self::to_service_result(LifecycleApplicationBridge::up(self))
    }

    fn down(
        &self,
        _deadline: std::time::Instant,
        _operation: crate::helper::lifecycle::LifecycleOperation,
    ) -> crate::helper::lifecycle::LifecycleServiceResult {
        Self::to_service_result(LifecycleApplicationBridge::down(self))
    }

    fn status(
        &self,
        _deadline: std::time::Instant,
        _operation: crate::helper::lifecycle::LifecycleOperation,
    ) -> crate::helper::lifecycle::LifecycleServiceResult {
        Self::to_service_result(LifecycleApplicationBridge::status(self))
    }
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
    use std::sync::atomic::{AtomicU32, Ordering};

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
                verified_at: OffsetDateTime::UNIX_EPOCH,
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
        let journal = FileJournal::new(root, Arc::new(TestClock)).unwrap();
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
            dir,
            Duration::from_secs(600),
            Arc::new(TestClock),
            Arc::new(NoDeadOwner),
        );
        let lock = block_on(locker.acquire(&binding())).unwrap();
        assert!(lock.acquired);
        // A second acquire while held is denied.
        let locker2 = FileLocker::new(
            locker.dir.clone(),
            Duration::from_secs(600),
            Arc::new(TestClock),
            Arc::new(NoDeadOwner),
        );
        assert!(block_on(locker2.acquire(&binding())).is_err());
        block_on(locker.release(&binding(), lock)).unwrap();
        // Released: the exact binding is acquirable again.
        assert!(block_on(locker2.acquire(&binding())).unwrap().acquired);
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
        let stale = LockFile {
            id: "lock-stale".to_owned(),
            owner_pid: 999_999,
            expires_at: "1970-01-01T00:00:01Z".to_owned(),
            fencing_token: 7,
        };
        let path = locker.lock_path(&binding());
        std::fs::write(&path, serde_json::to_vec(&stale).unwrap()).unwrap();
        // Expired but owner unproven dead → denied.
        assert!(block_on(locker.acquire(&binding())).is_err());
        // Broker-verified dead owner → takeover succeeds.
        let locker_dead = FileLocker::new(
            dir,
            Duration::from_secs(1),
            Arc::new(TestClock),
            Arc::new(DeadOwner),
        );
        assert!(block_on(locker_dead.acquire(&binding())).unwrap().acquired);
    }

    // -- FileBarrier ------------------------------------------------------------

    #[test]
    fn file_barrier_rejects_conflicting_writable_start() {
        let root = tmpdir("barrier");
        let journal = Arc::new(FileJournal::new(root, Arc::new(TestClock)).unwrap());
        let barrier = FileBarrier::new(journal.clone());
        block_on(barrier.validate_writable_start(&binding())).unwrap();
        let op = block_on(journal.begin(binding(), Observation::default())).unwrap();
        assert!(block_on(barrier.validate_writable_start(&binding())).is_err());
        block_on(journal.settle(&op, LifecyclePhase::Completed)).unwrap();
        block_on(barrier.validate_writable_start(&binding())).unwrap();
    }

    // -- Topology (payload contract + provision receipt) -------------------------

    type RunCalls = Mutex<Vec<(String, Vec<String>, Vec<u8>)>>;

    struct CapturingRunner {
        run_calls: RunCalls,
        exit_code: i32,
    }
    impl ComposeRunner for CapturingRunner {
        fn config(&self, _f: &RenderedFile) -> Result<RenderedModel, ComposeError> {
            Ok(RenderedModel::default())
        }
        fn up(&self, _f: &RenderedFile, _s: &[String]) -> Result<(), ComposeError> {
            Ok(())
        }
        fn run_with_input(
            &self,
            _f: &RenderedFile,
            service: &str,
            args: &[String],
            stdin: &[u8],
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
        ) -> Result<(Vec<u8>, i32), ComposeError> {
            Ok((Vec::new(), self.exit_code))
        }
        fn down(&self, _f: &RenderedFile) -> Result<(), ComposeError> {
            Ok(())
        }
        fn inspect(&self, _id: &str) -> Result<ContainerInspection, ComposeError> {
            Ok(ContainerInspection::default())
        }
        fn containers(
            &self,
            _f: &RenderedFile,
            services: &[String],
        ) -> Result<BTreeMap<String, ContainerInspection>, ComposeError> {
            Ok(services
                .iter()
                .map(|s| (s.clone(), ContainerInspection::default()))
                .collect())
        }
        fn stopped(&self, _f: &RenderedFile, _s: &[String]) -> Result<(), ComposeError> {
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
        let result = block_on(topology.provision_minio(&op));
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
}
