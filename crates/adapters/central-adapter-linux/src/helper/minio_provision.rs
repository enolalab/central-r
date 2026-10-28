//! `cmd/central/backup_minio_composition.go` +
//! `cmd/central/restore_minio_composition.go` — the production MinIO
//! credential preparers. Both run the separately delivered
//! `minio-provision` container while the native worker stays paused;
//! all path, image, policy, scope and credential-purpose choices are
//! fixed by this composition root. No request field can select bucket,
//! path, policy, or credentials.
//!
//! `ProductionRestoreMinioPreparer` mints the operation-bound,
//! read-only MinIO identity `VerifyInventory` needs (ADR 0017 option
//! B), with two differences from backup: no payload-epoch genesis
//! (restore creates no archive, so there is nothing to seal a
//! generation for, and calling it would be a protected-state write
//! this preparer has no business making), and `expires_at` is the
//! operation-absolute `restoreMinioHandoffExpiry` value, identical
//! across apply and any later resume.

use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Instant;

use central_foundation::failure::Failure;
use central_foundation::identity::InstanceId;
use central_infra::authority::{RecoveryMinioHandoffReceipt, RecoveryMinioHandoffRequest};
use central_infra::domain::{
    DependencyReceipt, Purpose, ServiceMode, minio_recovery_key_scope, minio_recovery_policy_digest,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::infra::compose::{
    CommandComposeRunner, ComposeRunner, Policy, RenderedFile, RenderedModel, load_default_policy,
    policy_digest,
};
use crate::infra::prepare::OpDeadline;
use crate::infra::prepare::store::CandidateStore;

/// `backupMinioBucket` — the fixed object-store bucket.
pub(crate) const BACKUP_MINIO_BUCKET: &str = "central-artifacts-v1";
/// `backupMinioRootCredentialPath`.
const BACKUP_MINIO_ROOT_CREDENTIAL_PATH: &str = "/run/secrets/minio-root-password";
/// `backupMinioBrokerSocketPath`.
const BACKUP_MINIO_BROKER_SOCKET_PATH: &str = "/run/broker/minio-provision.sock";
/// `backupMinioDockerPath`.
const BACKUP_MINIO_DOCKER_PATH: &str = "/usr/bin/docker";

fn unavailable(msg: &str) -> Failure {
    Failure::denied("minio_provision", msg.to_owned())
}

/// `backupDependencyReceiptSource` — the active dependency receipt.
pub(crate) trait BackupDependencyReceiptSource: Send + Sync {
    /// `Active`.
    fn active(&self, deadline: OpDeadline) -> Result<DependencyReceipt, Failure>;
}

impl BackupDependencyReceiptSource for CandidateStore {
    fn active(&self, deadline: OpDeadline) -> Result<DependencyReceipt, Failure> {
        self.active(deadline)
    }
}

/// `backupMinioComposeRunner` — the purpose-agnostic compose boundary.
pub(crate) trait BackupMinioComposeRunner: Send + Sync {
    /// `Config`.
    fn config(
        &self,
        f: &RenderedFile,
        deadline: OpDeadline,
    ) -> Result<RenderedModel, crate::infra::compose::ComposeError>;
    /// `RunWithInputOutput`.
    fn run_with_input_output(
        &self,
        f: &RenderedFile,
        service: &str,
        args: &[String],
        stdin: &[u8],
        deadline: OpDeadline,
    ) -> Result<(Vec<u8>, i32), crate::infra::compose::ComposeError>;
}

impl BackupMinioComposeRunner for CommandComposeRunner {
    fn config(
        &self,
        f: &RenderedFile,
        deadline: OpDeadline,
    ) -> Result<RenderedModel, crate::infra::compose::ComposeError> {
        ComposeRunner::config(self, f, deadline)
    }
    fn run_with_input_output(
        &self,
        f: &RenderedFile,
        service: &str,
        args: &[String],
        stdin: &[u8],
        deadline: OpDeadline,
    ) -> Result<(Vec<u8>, i32), crate::infra::compose::ComposeError> {
        ComposeRunner::run_with_input_output(self, f, service, args, stdin, deadline)
    }
}

/// `backupMinioHandoffIssuer` — the broker handoff seam.
pub(crate) trait BackupMinioHandoffIssuer: Send + Sync {
    /// `IssueRecoveryMinioHandoff`.
    fn issue_recovery_minio_handoff(
        &self,
        request: &RecoveryMinioHandoffRequest,
    ) -> Result<RecoveryMinioHandoffReceipt, Failure>;
}

impl BackupMinioHandoffIssuer for crate::broker::backup_authority::BackupMinioHandoffIssuer {
    fn issue_recovery_minio_handoff(
        &self,
        request: &RecoveryMinioHandoffRequest,
    ) -> Result<RecoveryMinioHandoffReceipt, Failure> {
        crate::broker::backup_authority::BackupMinioHandoffIssuer::issue_recovery_minio_handoff(
            self, request,
        )
    }
}

/// `backupPayloadEpochGenesis` — the clean-instance genesis seam.
/// Restore never installs one.
pub(crate) trait BackupPayloadEpochGenesis: Send + Sync {
    /// `EnsureGenesis`.
    fn ensure_genesis(&self, deadline: Instant, operation_id: Uuid) -> Result<Uuid, Failure>;
}

/// `BackupPayloadEpochAuthority` — the root-helper client for
/// `backup_ensure_payload_epoch`. It never rotates an existing epoch:
/// restore reset remains the sole rotation authority.
pub(crate) struct BackupPayloadEpochAuthority {
    client: crate::broker::lifecycle_client::LifecycleClient,
}

impl BackupPayloadEpochAuthority {
    /// `NewBackupPayloadEpochAuthority`.
    pub(crate) fn new(socket_path: PathBuf) -> Self {
        Self {
            client: crate::broker::lifecycle_client::LifecycleClient::new(socket_path),
        }
    }
}

impl BackupPayloadEpochGenesis for BackupPayloadEpochAuthority {
    fn ensure_genesis(&self, _deadline: Instant, operation_id: Uuid) -> Result<Uuid, Failure> {
        #[derive(serde::Deserialize)]
        struct GenesisResult {
            payload_epoch_id: Uuid,
        }
        if operation_id.is_nil() || operation_id.get_version_num() != 7 {
            return Err(unavailable("broker backup payload epoch: denied"));
        }
        let result: GenesisResult = self
            .client
            .call_with_operation_id(
                &operation_id.to_string(),
                crate::broker::protocol::BACKUP_ENSURE_PAYLOAD_EPOCH_RPC,
                &serde_json::json!({}),
            )
            .map_err(|_| unavailable("broker backup payload epoch: denied"))?;
        if result.payload_epoch_id.is_nil() || result.payload_epoch_id.get_version_num() != 7 {
            return Err(unavailable("broker backup payload epoch: denied"));
        }
        Ok(result.payload_epoch_id)
    }
}

/// The fixed rendered-compose path upstream derives once per
/// instance: `/run/central-infra/<instance>/docker-compose.yaml`.
pub(crate) fn expected_compose_path(instance_id: &str) -> String {
    format!("/run/central-infra/{instance_id}/docker-compose.yaml")
}

/// `backupMinioImageDigest` — the pinned `minio-provision` image's
/// manifest digest out of the active receipt's dependency set.
pub(crate) fn backup_minio_image_digest(
    set: &central_infra::domain::PreparedDependencySet,
) -> Result<String, Failure> {
    let inventory = set
        .lookup(ServiceMode::MinioProvision)
        .map_err(|_| unavailable("missing minio-provision image"))?;
    if inventory.manifest_digest.is_empty() {
        return Err(unavailable("missing minio-provision image"));
    }
    Ok(inventory.manifest_digest.clone())
}

/// `exactBackupMinioComposeModel` — the rendered model must hold
/// exactly the provisioner service, mounts, and environment this
/// composition pins; anything else is a foreign model.
pub(crate) fn exact_backup_minio_compose_model(
    model: &RenderedModel,
    instance_id: &str,
    image_digest: &str,
) -> bool {
    let Some(service) = model.services.get("minio-provision") else {
        return false;
    };
    if service.image != format!("ghcr.io/enolalab/central-local-infra@{image_digest}")
        || service.user != "1000:1000"
        || service.network_mode == "host"
        || service.network_mode == "none"
    {
        return false;
    }
    let want_root = format!(
        "/run/central-infra/{instance_id}/secrets/minio-root-password:{BACKUP_MINIO_ROOT_CREDENTIAL_PATH}:ro"
    );
    let want_broker = format!(
        "/run/central-infra/{instance_id}/broker/minio-provision.sock:{BACKUP_MINIO_BROKER_SOCKET_PATH}"
    );
    service.volumes.contains(&want_root)
        && service.volumes.contains(&want_broker)
        && service.env.get("CENTRAL_LOCAL_INFRA_MINIO_ADMIN_ENDPOINT")
            == Some(&"minio:9000".to_owned())
        && service.env.get("MINIO_ROOT_PASSWORD_FILE")
            == Some(&BACKUP_MINIO_ROOT_CREDENTIAL_PATH.to_owned())
}

/// `localInfraBackupMinioTarget` — the opaque fence descriptor the
/// provisioner binds its handoff receipt to.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub(crate) struct LocalInfraMinioTarget {
    fd_number: i64,
    device: u64,
    inode: u64,
    mount_id: u64,
    filesystem: String,
    uid: u32,
    gid: u32,
    root_id: String,
}

/// `localInfraBackupMinioParams`.
#[derive(Serialize)]
struct LocalInfraMinioParams {
    root_credential_path: String,
    broker_socket_path: String,
    bucket: String,
    key_prefix: String,
    policy_digest: String,
    credential_purpose: String,
    handoff_receipt_id: String,
    fence_token: u64,
}

/// `localInfraBackupMinioRequest` — the closed provision request;
/// field order is the exact Go marshal order.
#[derive(Serialize)]
struct LocalInfraMinioRequest {
    schema_version: String,
    mode: String,
    operation_id: String,
    instance_id: String,
    target: LocalInfraMinioTarget,
    policy_digest: String,
    image_digest: String,
    #[serde(with = "crate::broker::wire::rfc3339")]
    deadline: OffsetDateTime,
    minio_provision: LocalInfraMinioParams,
}

fn minio_fence(domain: &str, operation_id: Uuid) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0u8]);
    hasher.update(operation_id.as_bytes());
    let digest = hasher.finalize();
    let value = u64::from_be_bytes(digest[..8].try_into().unwrap_or([0; 8]));
    if value == 0 { 1 } else { value }
}

/// `backupMinioFence`.
pub(crate) fn backup_minio_fence(operation_id: Uuid) -> u64 {
    minio_fence("central.backup-minio-fence/v1", operation_id)
}

/// `restoreMinioFence` — its own domain separator so a restore
/// operation's fence can never collide with or replay against a
/// backup operation's, even though both derive from the same
/// operation ID shape.
fn restore_minio_fence(operation_id: Uuid) -> u64 {
    minio_fence("central.restore-minio-fence/v1", operation_id)
}

fn minio_target_descriptor(domain: &str, operation_id: Uuid) -> LocalInfraMinioTarget {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0u8]);
    hasher.update(operation_id.as_bytes());
    let digest = hasher.finalize();
    LocalInfraMinioTarget {
        fd_number: 3,
        device: u64::from_be_bytes(digest[0..8].try_into().unwrap_or([0; 8])) | 1,
        inode: u64::from_be_bytes(digest[8..16].try_into().unwrap_or([0; 8])) | 1,
        mount_id: u64::from_be_bytes(digest[16..24].try_into().unwrap_or([0; 8])) | 1,
        filesystem: "ext4".to_owned(),
        uid: 0,
        gid: 0,
        root_id: "minio-provision".to_owned(),
    }
}

/// `backupMinioTargetDescriptor`.
pub(crate) fn backup_minio_target_descriptor(operation_id: Uuid) -> LocalInfraMinioTarget {
    minio_target_descriptor("central.backup-minio-target/v1", operation_id)
}

/// `restoreMinioTargetDescriptor` — the restore-domain target.
fn restore_minio_target_descriptor(operation_id: Uuid) -> LocalInfraMinioTarget {
    minio_target_descriptor("central.restore-minio-target/v1", operation_id)
}

/// `localInfraProvisionReceipt` — the strict decoded half.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalInfraProvisionReceipt {
    schema_version: String,
    mode: String,
    operation_id: String,
    instance_id: String,
    outcome: String,
    reason: String,
    #[serde(with = "crate::broker::wire::rfc3339")]
    started_at: OffsetDateTime,
    #[serde(with = "crate::broker::wire::rfc3339")]
    completed_at: OffsetDateTime,
    minio_throughput_fixture: Option<serde_json::Value>,
}

/// `validBackupMinioProvisionReceipt` — decode-strict, single object,
/// no trailing bytes, the exact completed/delivered contract.
fn valid_backup_minio_provision_receipt(
    raw: &[u8],
    operation_id: &str,
    instance_id: &str,
    now: OffsetDateTime,
) -> bool {
    let mut stream = serde_json::Deserializer::from_slice(raw).into_iter::<serde_json::Value>();
    let (Some(Ok(value)), None) = (stream.next(), stream.next()) else {
        return false;
    };
    let Ok(receipt) = serde_json::from_value::<LocalInfraProvisionReceipt>(value) else {
        return false;
    };
    receipt.schema_version == "central.local.infra.receipt/v1"
        && receipt.mode == "minio-provision"
        && receipt.operation_id == operation_id
        && receipt.instance_id == instance_id
        && receipt.outcome == "completed"
        && receipt.reason == "delivered"
        && receipt.minio_throughput_fixture.is_none()
        && receipt.started_at != crate::broker::wire::go_zero_time()
        && receipt.completed_at >= receipt.started_at
        && receipt.completed_at <= now + time::Duration::minutes(1)
}

/// `ensureBackupMinioBrokerRendezvous` — links the root-owned broker
/// socket into the instance-scoped mount source; an unexpected
/// non-socket or non-root-owned entry is never replaced. The shared
/// inode's mode is widened to 0666 before linking (SC-DEF-29): the
/// provisioner runs as 1000:1000 and connect(2) needs write access on
/// the socket file; admission stays SO_PEERCRED-checked inside
/// `Service::handle_conn` per frame.
pub(crate) fn ensure_backup_minio_broker_rendezvous(
    source_socket: &str,
    instance_id: &str,
) -> Result<(), Failure> {
    let parsed = InstanceId::parse(instance_id);
    if source_socket.is_empty()
        || !source_socket.starts_with('/')
        || parsed.is_err()
        || parsed.map(|p| p.to_string()).as_deref() != Ok(instance_id)
    {
        return Err(unavailable("invalid broker rendezvous"));
    }
    let source = std::fs::symlink_metadata(source_socket)
        .map_err(|_| unavailable("untrusted broker socket"))?;
    if !source.file_type().is_socket() || source.uid() != 0 {
        return Err(unavailable("untrusted broker socket"));
    }
    std::fs::set_permissions(source_socket, std::fs::Permissions::from_mode(0o666))
        .map_err(|_| unavailable("broker rendezvous: widen socket mode"))?;
    let parent = format!("/run/central-infra/{instance_id}/broker");
    std::fs::create_dir_all(&parent).map_err(|_| unavailable("broker rendezvous: mkdir"))?;
    for dir in [
        "/run/central-infra".to_owned(),
        Path::new(&parent)
            .parent()
            .map_or_else(|| parent.clone(), |p| p.to_string_lossy().into_owned()),
        parent.clone(),
    ] {
        let stat = std::fs::symlink_metadata(&dir)
            .map_err(|_| unavailable("untrusted broker rendezvous directory"))?;
        if !stat.is_dir() || stat.uid() != 0 || stat.mode() & 0o022 != 0 {
            return Err(unavailable("untrusted broker rendezvous directory"));
        }
    }
    let destination = format!("{parent}/minio-provision.sock");
    match std::fs::symlink_metadata(&destination) {
        Ok(existing) => {
            if !existing.file_type().is_socket() || existing.uid() != 0 {
                return Err(unavailable("untrusted broker rendezvous entry"));
            }
            if existing.dev() == source.dev() && existing.ino() == source.ino() {
                return Ok(());
            }
            std::fs::remove_file(&destination)
                .map_err(|_| unavailable("broker rendezvous: unlink"))?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(unavailable("broker rendezvous: stat")),
    }
    std::fs::hard_link(source_socket, &destination)
        .map_err(|_| unavailable("broker rendezvous: link"))
}

// ---------------------------------------------------------------------------
// The restore preparer — `productionRestoreMinioPreparer`.
// ---------------------------------------------------------------------------

/// `productionRestoreMinioPreparer` — see the module doc for why it
/// carries no payload-epoch genesis and why `expires_at` is the
/// operation-absolute value.
pub(crate) struct ProductionRestoreMinioPreparer {
    instance_id: String,
    bucket: String,
    policy_hash: String,
    policy: Policy,
    receipts: Box<dyn BackupDependencyReceiptSource>,
    issuer: Box<dyn BackupMinioHandoffIssuer>,
    runner: Box<dyn BackupMinioComposeRunner>,
    rendered: RenderedFile,
    broker_socket: PathBuf,
    now: fn() -> OffsetDateTime,
}

impl ProductionRestoreMinioPreparer {
    /// `newProductionRestoreMinioPreparer`.
    pub(crate) fn new_production(
        composition: &crate::broker::daemon::ProductionInstanceComposition,
        broker_socket: &Path,
    ) -> Result<Self, Failure> {
        let parsed = InstanceId::parse(&composition.instance_id);
        if parsed.is_err()
            || parsed.map(|p| p.to_string()).as_deref() != Ok(composition.instance_id.as_str())
            || composition.dependency_root.is_empty()
            || composition.compose_path != expected_compose_path(&composition.instance_id)
            || composition.object_store_bucket != BACKUP_MINIO_BUCKET
            || composition.restore_policy_digest.is_empty()
        {
            return Err(unavailable("restore MinIO composition unavailable"));
        }
        let policy =
            load_default_policy().map_err(|_| unavailable("restore MinIO policy unavailable"))?;
        Ok(Self {
            instance_id: composition.instance_id.clone(),
            bucket: composition.object_store_bucket.clone(),
            policy_hash: composition.restore_policy_digest.clone(),
            policy,
            receipts: Box::new(CandidateStore::new(
                None,
                composition.dependency_root.clone(),
            )),
            issuer: Box::new(
                crate::broker::backup_authority::BackupMinioHandoffIssuer::new(
                    broker_socket.to_path_buf(),
                ),
            ),
            runner: Box::new(CommandComposeRunner::new(
                BACKUP_MINIO_DOCKER_PATH,
                None,
                None,
            )),
            rendered: RenderedFile {
                path: composition.compose_path.clone(),
                content: Vec::new(),
            },
            broker_socket: broker_socket.to_path_buf(),
            now: OffsetDateTime::now_utc,
        })
    }
}

impl super::restore_launcher::RestoreMinioCredentialPreparer for ProductionRestoreMinioPreparer {
    /// `PrepareRestoreMinio`.
    fn prepare_restore_minio(
        &self,
        deadline: Instant,
        operation_id: Uuid,
        expires_at: OffsetDateTime,
    ) -> Result<(), Failure> {
        let op_deadline = OpDeadline(Some(deadline));
        let now = (self.now)();
        if operation_id.is_nil()
            || operation_id.get_version_num() != 7
            || self.bucket != BACKUP_MINIO_BUCKET
            || self.rendered.path != expected_compose_path(&self.instance_id)
            || expires_at == crate::broker::wire::go_zero_time()
            || now >= expires_at
        {
            return Err(unavailable("restore MinIO preparation unavailable"));
        }
        let parsed = InstanceId::parse(&self.instance_id);
        if parsed.is_err()
            || parsed.map(|p| p.to_string()).as_deref() != Ok(self.instance_id.as_str())
        {
            return Err(unavailable("restore MinIO preparation unavailable"));
        }
        let receipt = self
            .receipts
            .active(op_deadline)
            .map_err(|_| unavailable("restore MinIO dependency identity unavailable"))?;
        if receipt.validate_b03().is_err() {
            return Err(unavailable("restore MinIO dependency identity unavailable"));
        }
        let image_digest = backup_minio_image_digest(&receipt.dependency_set)
            .map_err(|_| unavailable("restore MinIO dependency identity unavailable"))?;
        let model = self
            .runner
            .config(&self.rendered, op_deadline)
            .map_err(|_| unavailable("restore MinIO topology unavailable"))?;
        if !exact_backup_minio_compose_model(&model, &self.instance_id, &image_digest) {
            return Err(unavailable("restore MinIO topology unavailable"));
        }
        ensure_backup_minio_broker_rendezvous(
            &self.broker_socket.to_string_lossy(),
            &self.instance_id,
        )
        .map_err(|_| unavailable("restore MinIO broker rendezvous unavailable"))?;
        let scope = minio_recovery_key_scope(Purpose::MinioRestore)
            .map_err(|_| unavailable("restore MinIO scope unavailable"))?;
        let policy_digest_value = minio_recovery_policy_digest(Purpose::MinioRestore, &self.bucket)
            .map_err(|_| unavailable("restore MinIO policy unavailable"))?;
        if policy_digest_value.trim_start_matches("sha256:") != self.policy_hash {
            return Err(unavailable("restore MinIO policy unavailable"));
        }
        let fence = restore_minio_fence(operation_id);
        let expires_at = expires_at.to_offset(time::UtcOffset::UTC);
        let request = RecoveryMinioHandoffRequest {
            operation_id: operation_id.to_string(),
            instance_id: self.instance_id.clone(),
            purpose: Purpose::MinioRestore.as_str().to_owned(),
            bucket: self.bucket.clone(),
            key_prefix: scope.to_owned(),
            policy_digest: policy_digest_value.clone(),
            expires_at,
            fence_token: fence,
        };
        let handoff = self
            .issuer
            .issue_recovery_minio_handoff(&request)
            .map_err(|_| unavailable("restore MinIO broker handoff unavailable"))?;
        if handoff.operation_id != request.operation_id
            || handoff.instance_id != request.instance_id
            || handoff.purpose != request.purpose
            || handoff.bucket != request.bucket
            || handoff.key_prefix != request.key_prefix
            || handoff.policy_digest != request.policy_digest
            || handoff.receipt_id.is_empty()
            || handoff.fence_token != fence
            || handoff.expires_at != expires_at
        {
            return Err(unavailable("restore MinIO broker handoff unavailable"));
        }
        if handoff.bound {
            return Ok(());
        }
        let payload = serde_json::to_vec(&LocalInfraMinioRequest {
            schema_version: "central.local.infra.request/v1".to_owned(),
            mode: "minio-provision".to_owned(),
            operation_id: operation_id.to_string(),
            instance_id: self.instance_id.clone(),
            target: restore_minio_target_descriptor(operation_id),
            policy_digest: policy_digest(&self.policy),
            image_digest,
            deadline: expires_at,
            minio_provision: LocalInfraMinioParams {
                root_credential_path: BACKUP_MINIO_ROOT_CREDENTIAL_PATH.to_owned(),
                broker_socket_path: BACKUP_MINIO_BROKER_SOCKET_PATH.to_owned(),
                bucket: self.bucket.clone(),
                key_prefix: scope.to_owned(),
                policy_digest: policy_digest_value,
                credential_purpose: Purpose::MinioRestore.as_str().to_owned(),
                handoff_receipt_id: handoff.receipt_id,
                fence_token: fence,
            },
        })
        .map_err(|_| unavailable("restore MinIO request unavailable"))?;
        let (output, exit_code) = self
            .runner
            .run_with_input_output(
                &self.rendered,
                "minio-provision",
                &["minio-provision".to_owned()],
                &payload,
                op_deadline,
            )
            .map_err(|_| unavailable("restore MinIO provisioner failed"))?;
        if exit_code != 0
            || !valid_backup_minio_provision_receipt(
                &output,
                &operation_id.to_string(),
                &self.instance_id,
                now,
            )
        {
            return Err(unavailable("restore MinIO provisioner failed"));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The import preparer — `productionImportMinioPreparer`.
// ---------------------------------------------------------------------------

/// `central.import-minio-fence/v1` — the import operation's fence
/// domain separator; can never collide with or replay against the
/// backup or restore values even though all three derive from the
/// same identity shape.
fn import_minio_fence(operation_id: Uuid) -> u64 {
    minio_fence("central.import-minio-fence/v1", operation_id)
}

/// `importMinioTargetDescriptor` — see [`import_minio_fence`].
fn import_minio_target_descriptor(operation_id: Uuid) -> LocalInfraMinioTarget {
    minio_target_descriptor("central.import-minio-target/v1", operation_id)
}

/// `productionImportMinioPreparer` mints the operation-bound
/// `minio_import_v1` writer the import engine uploads staged bodies
/// through (ADR 0034). It mirrors [`ProductionRestoreMinioPreparer`]
/// — same provisioner container, same broker-mediated handoff
/// protocol, same compose model and receipt validation — with two
/// differences: the purpose is `minio_import_v1` (whose policy grants
/// `PutObject` on the ready prefix alongside `GetObject`), and
/// `expires_at` is the operation-absolute `importMinioHandoffExpiry`
/// value identical across retried launches.
pub(crate) struct ProductionImportMinioPreparer {
    instance_id: String,
    bucket: String,
    policy_hash: String,
    policy: Policy,
    receipts: Box<dyn BackupDependencyReceiptSource>,
    issuer: Box<dyn BackupMinioHandoffIssuer>,
    runner: Box<dyn BackupMinioComposeRunner>,
    rendered: RenderedFile,
    broker_socket: PathBuf,
    now: fn() -> OffsetDateTime,
}

impl ProductionImportMinioPreparer {
    /// `newProductionImportMinioPreparer`.
    pub(crate) fn new_production(
        composition: &crate::broker::daemon::ProductionInstanceComposition,
        broker_socket: &Path,
    ) -> Result<Self, Failure> {
        let parsed = InstanceId::parse(&composition.instance_id);
        if parsed.is_err()
            || parsed.map(|p| p.to_string()).as_deref() != Ok(composition.instance_id.as_str())
            || composition.dependency_root.is_empty()
            || composition.compose_path != expected_compose_path(&composition.instance_id)
            || composition.object_store_bucket != BACKUP_MINIO_BUCKET
            || composition.import_policy_digest.is_empty()
        {
            return Err(unavailable("import MinIO composition unavailable"));
        }
        let policy =
            load_default_policy().map_err(|_| unavailable("import MinIO policy unavailable"))?;
        Ok(Self {
            instance_id: composition.instance_id.clone(),
            bucket: composition.object_store_bucket.clone(),
            policy_hash: composition.import_policy_digest.clone(),
            policy,
            receipts: Box::new(CandidateStore::new(
                None,
                composition.dependency_root.clone(),
            )),
            issuer: Box::new(
                crate::broker::backup_authority::BackupMinioHandoffIssuer::new(
                    broker_socket.to_path_buf(),
                ),
            ),
            runner: Box::new(CommandComposeRunner::new(
                BACKUP_MINIO_DOCKER_PATH,
                None,
                None,
            )),
            rendered: RenderedFile {
                path: composition.compose_path.clone(),
                content: Vec::new(),
            },
            broker_socket: broker_socket.to_path_buf(),
            now: OffsetDateTime::now_utc,
        })
    }
}

impl super::restore_launcher::ImportMinioCredentialPreparer for ProductionImportMinioPreparer {
    /// `PrepareImportMinio`.
    fn prepare_import_minio(
        &self,
        deadline: Instant,
        operation_id: Uuid,
        expires_at: OffsetDateTime,
    ) -> Result<(), Failure> {
        let op_deadline = OpDeadline(Some(deadline));
        let now = (self.now)();
        if operation_id.is_nil()
            || operation_id.get_version_num() != 7
            || self.bucket != BACKUP_MINIO_BUCKET
            || self.rendered.path != expected_compose_path(&self.instance_id)
            || expires_at == crate::broker::wire::go_zero_time()
            || now >= expires_at
        {
            return Err(unavailable("import MinIO preparation unavailable"));
        }
        let parsed = InstanceId::parse(&self.instance_id);
        if parsed.is_err()
            || parsed.map(|p| p.to_string()).as_deref() != Ok(self.instance_id.as_str())
        {
            return Err(unavailable("import MinIO preparation unavailable"));
        }
        let receipt = self
            .receipts
            .active(op_deadline)
            .map_err(|_| unavailable("import MinIO dependency identity unavailable"))?;
        if receipt.validate_b03().is_err() {
            return Err(unavailable("import MinIO dependency identity unavailable"));
        }
        let image_digest = backup_minio_image_digest(&receipt.dependency_set)
            .map_err(|_| unavailable("import MinIO dependency identity unavailable"))?;
        let model = self
            .runner
            .config(&self.rendered, op_deadline)
            .map_err(|_| unavailable("import MinIO topology unavailable"))?;
        if !exact_backup_minio_compose_model(&model, &self.instance_id, &image_digest) {
            return Err(unavailable("import MinIO topology unavailable"));
        }
        ensure_backup_minio_broker_rendezvous(
            &self.broker_socket.to_string_lossy(),
            &self.instance_id,
        )
        .map_err(|_| unavailable("import MinIO broker rendezvous unavailable"))?;
        let scope = minio_recovery_key_scope(Purpose::MinioImport)
            .map_err(|_| unavailable("import MinIO scope unavailable"))?;
        let policy_digest_value = minio_recovery_policy_digest(Purpose::MinioImport, &self.bucket)
            .map_err(|_| unavailable("import MinIO policy unavailable"))?;
        if policy_digest_value.trim_start_matches("sha256:") != self.policy_hash {
            return Err(unavailable("import MinIO policy unavailable"));
        }
        let fence = import_minio_fence(operation_id);
        let expires_at = expires_at.to_offset(time::UtcOffset::UTC);
        let request = RecoveryMinioHandoffRequest {
            operation_id: operation_id.to_string(),
            instance_id: self.instance_id.clone(),
            purpose: Purpose::MinioImport.as_str().to_owned(),
            bucket: self.bucket.clone(),
            key_prefix: scope.to_owned(),
            policy_digest: policy_digest_value.clone(),
            expires_at,
            fence_token: fence,
        };
        let handoff = self
            .issuer
            .issue_recovery_minio_handoff(&request)
            .map_err(|_| unavailable("import MinIO broker handoff unavailable"))?;
        if handoff.operation_id != request.operation_id
            || handoff.instance_id != request.instance_id
            || handoff.purpose != request.purpose
            || handoff.bucket != request.bucket
            || handoff.key_prefix != request.key_prefix
            || handoff.policy_digest != request.policy_digest
            || handoff.receipt_id.is_empty()
            || handoff.fence_token != fence
            || handoff.expires_at != expires_at
        {
            return Err(unavailable("import MinIO broker handoff unavailable"));
        }
        if handoff.bound {
            return Ok(());
        }
        let payload = serde_json::to_vec(&LocalInfraMinioRequest {
            schema_version: "central.local.infra.request/v1".to_owned(),
            mode: "minio-provision".to_owned(),
            operation_id: operation_id.to_string(),
            instance_id: self.instance_id.clone(),
            target: import_minio_target_descriptor(operation_id),
            policy_digest: policy_digest(&self.policy),
            image_digest,
            deadline: expires_at,
            minio_provision: LocalInfraMinioParams {
                root_credential_path: BACKUP_MINIO_ROOT_CREDENTIAL_PATH.to_owned(),
                broker_socket_path: BACKUP_MINIO_BROKER_SOCKET_PATH.to_owned(),
                bucket: self.bucket.clone(),
                key_prefix: scope.to_owned(),
                policy_digest: policy_digest_value,
                credential_purpose: Purpose::MinioImport.as_str().to_owned(),
                handoff_receipt_id: handoff.receipt_id,
                fence_token: fence,
            },
        })
        .map_err(|_| unavailable("import MinIO request unavailable"))?;
        let (output, exit_code) = self
            .runner
            .run_with_input_output(
                &self.rendered,
                "minio-provision",
                &["minio-provision".to_owned()],
                &payload,
                op_deadline,
            )
            .map_err(|_| unavailable("import MinIO provisioner failed"))?;
        if exit_code != 0
            || !valid_backup_minio_provision_receipt(
                &output,
                &operation_id.to_string(),
                &self.instance_id,
                now,
            )
        {
            return Err(unavailable("import MinIO provisioner failed"));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The backup preparer — `productionBackupMinioPreparer`.
// ---------------------------------------------------------------------------

/// `productionBackupMinioPreparer` runs the separately delivered
/// provisioner while the native backup worker remains paused.
pub(crate) struct ProductionBackupMinioPreparer {
    instance_id: String,
    bucket: String,
    policy_hash: String,
    policy: Policy,
    receipts: Box<dyn BackupDependencyReceiptSource>,
    epoch: Box<dyn BackupPayloadEpochGenesis>,
    issuer: Box<dyn BackupMinioHandoffIssuer>,
    runner: Box<dyn BackupMinioComposeRunner>,
    rendered: RenderedFile,
    broker_socket: PathBuf,
    now: fn() -> OffsetDateTime,
}

impl ProductionBackupMinioPreparer {
    /// `newProductionBackupMinioPreparer`.
    pub(crate) fn new_production(
        composition: &crate::broker::daemon::ProductionInstanceComposition,
        broker_socket: &Path,
    ) -> Result<Self, Failure> {
        let parsed = InstanceId::parse(&composition.instance_id);
        if parsed.is_err()
            || parsed.map(|p| p.to_string()).as_deref() != Ok(composition.instance_id.as_str())
            || composition.dependency_root.is_empty()
            || composition.compose_path != expected_compose_path(&composition.instance_id)
            || composition.object_store_bucket != BACKUP_MINIO_BUCKET
            || composition.backup_policy_digest.is_empty()
        {
            return Err(unavailable("backup MinIO composition unavailable"));
        }
        let policy =
            load_default_policy().map_err(|_| unavailable("backup MinIO policy unavailable"))?;
        Ok(Self {
            instance_id: composition.instance_id.clone(),
            bucket: composition.object_store_bucket.clone(),
            policy_hash: composition.backup_policy_digest.clone(),
            policy,
            receipts: Box::new(CandidateStore::new(
                None,
                composition.dependency_root.clone(),
            )),
            epoch: Box::new(BackupPayloadEpochAuthority::new(
                broker_socket.to_path_buf(),
            )),
            issuer: Box::new(
                crate::broker::backup_authority::BackupMinioHandoffIssuer::new(
                    broker_socket.to_path_buf(),
                ),
            ),
            runner: Box::new(CommandComposeRunner::new(
                BACKUP_MINIO_DOCKER_PATH,
                None,
                None,
            )),
            rendered: RenderedFile {
                path: composition.compose_path.clone(),
                content: Vec::new(),
            },
            broker_socket: broker_socket.to_path_buf(),
            now: OffsetDateTime::now_utc,
        })
    }

    /// `prepareBackupMinioOperation` — the shared body behind
    /// `PrepareBackupMinio` and `PrepareBackupThroughputMinio`.
    /// Returns the payload epoch identity like upstream.
    fn prepare_backup_minio_operation(
        &self,
        deadline: Instant,
        operation_id: Uuid,
        expires_at: OffsetDateTime,
    ) -> Result<Uuid, Failure> {
        let op_deadline = OpDeadline(Some(deadline));
        let now = (self.now)();
        if operation_id.is_nil()
            || operation_id.get_version_num() != 7
            || self.bucket != BACKUP_MINIO_BUCKET
            || self.rendered.path != expected_compose_path(&self.instance_id)
            || expires_at == crate::broker::wire::go_zero_time()
            || now >= expires_at
        {
            return Err(unavailable("backup MinIO preparation unavailable"));
        }
        let parsed = InstanceId::parse(&self.instance_id);
        if parsed.is_err()
            || parsed.map(|p| p.to_string()).as_deref() != Ok(self.instance_id.as_str())
        {
            return Err(unavailable("backup MinIO preparation unavailable"));
        }
        let epoch_id = self
            .epoch
            .ensure_genesis(deadline, operation_id)
            .map_err(|_| unavailable("backup payload epoch unavailable"))?;
        if epoch_id.is_nil() || epoch_id.get_version_num() != 7 {
            return Err(unavailable("backup payload epoch unavailable"));
        }
        let receipt = self
            .receipts
            .active(op_deadline)
            .map_err(|_| unavailable("backup MinIO dependency identity unavailable"))?;
        if receipt.validate_b03().is_err() {
            return Err(unavailable("backup MinIO dependency identity unavailable"));
        }
        let image_digest = backup_minio_image_digest(&receipt.dependency_set)
            .map_err(|_| unavailable("backup MinIO dependency identity unavailable"))?;
        let model = self
            .runner
            .config(&self.rendered, op_deadline)
            .map_err(|_| unavailable("backup MinIO topology unavailable"))?;
        if !exact_backup_minio_compose_model(&model, &self.instance_id, &image_digest) {
            return Err(unavailable("backup MinIO topology unavailable"));
        }
        ensure_backup_minio_broker_rendezvous(
            &self.broker_socket.to_string_lossy(),
            &self.instance_id,
        )
        .map_err(|_| unavailable("backup MinIO broker rendezvous unavailable"))?;
        let scope = minio_recovery_key_scope(Purpose::MinioBackup)
            .map_err(|_| unavailable("backup MinIO scope unavailable"))?;
        let policy_digest_value = minio_recovery_policy_digest(Purpose::MinioBackup, &self.bucket)
            .map_err(|_| unavailable("backup MinIO policy unavailable"))?;
        if policy_digest_value.trim_start_matches("sha256:") != self.policy_hash {
            return Err(unavailable("backup MinIO policy unavailable"));
        }
        let fence = backup_minio_fence(operation_id);
        let expires_at = expires_at.to_offset(time::UtcOffset::UTC);
        let request = RecoveryMinioHandoffRequest {
            operation_id: operation_id.to_string(),
            instance_id: self.instance_id.clone(),
            purpose: Purpose::MinioBackup.as_str().to_owned(),
            bucket: self.bucket.clone(),
            key_prefix: scope.to_owned(),
            policy_digest: policy_digest_value.clone(),
            expires_at,
            fence_token: fence,
        };
        let handoff = self
            .issuer
            .issue_recovery_minio_handoff(&request)
            .map_err(|_| unavailable("backup MinIO broker handoff unavailable"))?;
        if handoff.operation_id != request.operation_id
            || handoff.instance_id != request.instance_id
            || handoff.purpose != request.purpose
            || handoff.bucket != request.bucket
            || handoff.key_prefix != request.key_prefix
            || handoff.policy_digest != request.policy_digest
            || handoff.receipt_id.is_empty()
            || handoff.fence_token != fence
            || handoff.expires_at != expires_at
        {
            return Err(unavailable("backup MinIO broker handoff unavailable"));
        }
        if handoff.bound {
            return Ok(epoch_id);
        }
        let payload = serde_json::to_vec(&LocalInfraMinioRequest {
            schema_version: "central.local.infra.request/v1".to_owned(),
            mode: "minio-provision".to_owned(),
            operation_id: operation_id.to_string(),
            instance_id: self.instance_id.clone(),
            target: backup_minio_target_descriptor(operation_id),
            policy_digest: policy_digest(&self.policy),
            image_digest,
            deadline: expires_at,
            minio_provision: LocalInfraMinioParams {
                root_credential_path: BACKUP_MINIO_ROOT_CREDENTIAL_PATH.to_owned(),
                broker_socket_path: BACKUP_MINIO_BROKER_SOCKET_PATH.to_owned(),
                bucket: self.bucket.clone(),
                key_prefix: scope.to_owned(),
                policy_digest: policy_digest_value,
                credential_purpose: Purpose::MinioBackup.as_str().to_owned(),
                handoff_receipt_id: handoff.receipt_id,
                fence_token: fence,
            },
        })
        .map_err(|_| unavailable("backup MinIO request unavailable"))?;
        let (output, exit_code) = self
            .runner
            .run_with_input_output(
                &self.rendered,
                "minio-provision",
                &["minio-provision".to_owned()],
                &payload,
                op_deadline,
            )
            .map_err(|_| unavailable("backup MinIO provisioner failed"))?;
        if exit_code != 0
            || !valid_backup_minio_provision_receipt(
                &output,
                &operation_id.to_string(),
                &self.instance_id,
                now,
            )
        {
            return Err(unavailable("backup MinIO provisioner failed"));
        }
        Ok(epoch_id)
    }
}

impl ProductionBackupMinioPreparer {
    /// `PrepareBackupThroughputMinio` — the same read-only,
    /// operation-bound backup identity for a C02 probe. A throughput
    /// operation has no `BackupID` and cannot call the normal
    /// launch-shaped method, but its policy, bucket, scope, payload
    /// epoch, dependency receipt, expiry and broker handoff are
    /// identical.
    pub(crate) fn prepare_backup_throughput_minio(
        &self,
        deadline: Instant,
        operation_id: Uuid,
        expires_at: OffsetDateTime,
    ) -> Result<Uuid, Failure> {
        if operation_id.is_nil() || operation_id.get_version_num() != 7 {
            return Err(unavailable(
                "backup throughput MinIO preparation unavailable",
            ));
        }
        self.prepare_backup_minio_operation(deadline, operation_id, expires_at)
    }
}

impl super::backup::BackupMinioCredentialPreparer for ProductionBackupMinioPreparer {
    /// `PrepareBackupMinio`.
    fn prepare_backup_minio(
        &self,
        deadline: Instant,
        authority: &crate::broker::backup_launch::BackupLaunchAuthority,
        expires_at: OffsetDateTime,
    ) -> Result<(), Failure> {
        if authority.launch_evidence_id.is_nil()
            || authority.operation_id.is_nil()
            || authority.backup_id.is_nil()
        {
            return Err(unavailable("backup MinIO preparation unavailable"));
        }
        self.prepare_backup_minio_operation(deadline, authority.operation_id, expires_at)
            .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `TestImportMinioFenceAndTargetAreDomainSeparated` — the import
    /// fence and target descriptor can never collide with, or be
    /// replayed against, the backup or restore values for the same
    /// operation id.
    #[test]
    fn import_fence_and_target_are_domain_separated() {
        for _ in 0..8 {
            let op = Uuid::now_v7();
            let import_fence = import_minio_fence(op);
            assert_ne!(import_fence, backup_minio_fence(op));
            assert_ne!(import_fence, restore_minio_fence(op));
            assert_ne!(import_fence, 0);
            let target = import_minio_target_descriptor(op);
            assert_ne!(target, backup_minio_target_descriptor(op));
            assert_ne!(target, restore_minio_target_descriptor(op));
        }
    }

    /// `TestNewProductionImportMinioPreparerRejectsIncomplete` — an
    /// empty composition produces no preparer, so the wrapper's `None`
    /// narrows only the import launch.
    #[test]
    fn import_preparer_rejects_incomplete_composition() {
        let empty = crate::broker::daemon::ProductionInstanceComposition {
            instance_id: String::new(),
            authoritative_state_root: String::new(),
            dependency_root: String::new(),
            role_roots: central_backup::backup::capacity::RoleRoots::default(),
            backup_repository_root: String::new(),
            compose_path: String::new(),
            object_store_bucket: String::new(),
            backup_policy_digest: String::new(),
            restore_policy_digest: String::new(),
            import_policy_digest: String::new(),
        };
        assert!(
            ProductionImportMinioPreparer::new_production(&empty, Path::new("/nonexistent.sock"))
                .is_err()
        );
    }
}
