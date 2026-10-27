//! `cmd/central/backup_throughput_gate.go` +
//! `cmd/central/backup_throughput_binding.go` +
//! `cmd/central/backup_throughput_postgres.go` +
//! `cmd/central/backup_throughput_minio.go` +
//! `cmd/central/backup_throughput_cleanup_census.go` +
//! `internal/adapter/authority/broker/backup_throughput_rpc.go` +
//! `internal/adapter/authority/broker/backup_throughput_launch_rpc.go`
//! (the client halves) — C02's complete root-helper throughput gate.
//!
//! The gate admits a normal `backup create` only after fresh probe
//! evidence has been verified or produced for the exact helper-opened
//! repository: reconcile any stale attempt, accept a fresh probe
//! operation, prepare its operation-bound MinIO identity, build the
//! static binding, launch the native `throughput-probe` worker
//! behind commit, wait for its target lock, run the disposable
//! PostgreSQL and MinIO fixtures, attest fixture load, reap the
//! worker, assert the lock stayed retained, census every residual
//! resource class to zero, complete-pending, release, activate.
//! Every step fails closed — a refusal, never a made-up success.

use std::io::Read;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use central_backup::backup::capacity::{
    MAXIMUM_DUMP_PROBE_ARCHIVE_BYTES, MAXIMUM_THROUGHPUT_PROBE_ELAPSED,
    MINIMUM_DUMP_PROBE_ARCHIVE_BYTES, OBJECT_PROBE_PAYLOAD_BYTES,
};
use central_backup::backup::operation::PINNED_BACKUP_CONFIGURATION;
use central_backup::recovery::profile::{BACKUP_TRANSFER_ENVELOPE_VERSION, ThroughputEvidence};
use central_foundation::failure::Failure;
use central_foundation::identity::InstanceId;
use central_infra::domain::{DependencyReceipt, ServiceMode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::broker::backup_throughput_launch::{
    BackupThroughputFixtureLoadAttestation, BackupThroughputLaunchAuthority,
    BackupThroughputLaunchEvidence, BackupThroughputLaunchStatus, BackupThroughputStaticBinding,
};
use crate::broker::lifecycle_client::LifecycleClient;
use crate::broker::throughput_journal::{ThroughputCleanupCounts, evidence_from_wire};
use crate::helper::backup::{
    BackupProcessLauncher, BackupProcessMode, BackupProcessSpec, BackupRepositoryDescriptor,
    BackupThroughputGate, CENTRAL_RUNTIME_GID, CENTRAL_RUNTIME_UID, NativeBackupProcessLauncher,
};
use crate::helper::minio_provision::{
    BACKUP_MINIO_BUCKET, BackupDependencyReceiptSource, BackupMinioComposeRunner,
    backup_minio_fence, backup_minio_target_descriptor,
};
use crate::helper::pg_credentials::{
    PostgresSuperuserRotator, ProductionPostgresAdminCredentialManager,
    ProductionPostgresSuperuserCredentialStore,
};
use crate::infra::compose::{
    CommandComposeRunner, Policy, RenderedFile, load_default_policy, policy_digest,
};
use crate::infra::prepare::OpDeadline;
use crate::infra::prepare::store::CandidateStore;

// ---------------------------------------------------------------------------
// Phase/vocabulary constants — `backup_throughput_gate.go`'s header.
// ---------------------------------------------------------------------------

const BACKUP_THROUGHPUT_TARGET_LOCKED_PHASE: &str = "target_locked";
const BACKUP_THROUGHPUT_MEASUREMENT_STAGED_PHASE: &str = "measurement_staged";
const BACKUP_THROUGHPUT_POLL_INTERVAL: Duration = Duration::from_millis(25);
const BACKUP_THROUGHPUT_CLEANUP_TIMEOUT: Duration = Duration::from_secs(30);
const BACKUP_THROUGHPUT_PROVISION_RECEIPT_SCHEMA: &str =
    "central.backup-throughput-provision-receipt/v1";

const LOCAL_INFRA_REQUEST_SCHEMA: &str = "central.local.infra.request/v1";
const LOCAL_INFRA_RECEIPT_SCHEMA: &str = "central.local.infra.receipt/v1";

fn unavailable(msg: &str) -> Failure {
    Failure::denied("backup_throughput", msg.to_owned())
}

fn is_v7(id: Uuid) -> bool {
    !id.is_nil() && id.get_version_num() == 7
}

/// `validThroughputSHA256` — `sha256:` + 64 lowercase hex.
pub(crate) fn valid_throughput_sha256(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// `canonicalThroughputDigest` — `sha256:` + hex of the canonical
/// `{schema, value}` envelope marshal.
fn canonical_throughput_digest<T: serde::Serialize>(
    schema: &str,
    value: &T,
) -> Result<String, Failure> {
    #[derive(Serialize)]
    struct Envelope<'a, T: Serialize> {
        schema: &'a str,
        value: &'a T,
    }
    if schema.is_empty() {
        return Err(unavailable("canonical throughput identity unavailable"));
    }
    let payload = serde_json::to_vec(&Envelope { schema, value })
        .map_err(|_| unavailable("canonical throughput identity unavailable"))?;
    Ok(format!("sha256:{}", hex_encode(&Sha256::digest(&payload))))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

// ---------------------------------------------------------------------------
// `backupThroughputAttemptStatus` — the root reconciliation view.
// ---------------------------------------------------------------------------

/// `BackupThroughputAttemptStatus` — mirrors the broker's
/// `BackupThroughputAttemptStatus` (PascalCase-free snake_case wire).
/// `omitempty` fields carry `default` exactly like Go's zero-value
/// decode; `found=false` answers come back as the empty struct.
/// `activated_at`/`repository_binding_id` are strict-decode parity
/// fields: the broker always emits them and the decode validates the
/// full response shape even though reconcile reads only a subset.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct BackupThroughputAttemptStatus {
    pub found: bool,
    pub operation_id: Uuid,
    pub phase: String,
    pub selector_phase: String,
    pub accepted_at: OffsetDateTime,
    pub deadline: OffsetDateTime,
    pub activated_at: OffsetDateTime,
    pub cleanup_resolved_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub cleanup_attested: bool,
    pub supervisor_launch_id: Uuid,
    pub launch_evidence_id: Uuid,
    pub repository_binding_id: Uuid,
    pub target_lock_proof: [u8; 32],
    pub minio_seed_binding: String,
}

impl Default for BackupThroughputAttemptStatus {
    fn default() -> Self {
        let zero = crate::broker::wire::go_zero_time();
        Self {
            found: false,
            operation_id: Uuid::nil(),
            phase: String::new(),
            selector_phase: String::new(),
            accepted_at: zero,
            deadline: zero,
            activated_at: zero,
            cleanup_resolved_at: zero,
            expires_at: zero,
            cleanup_attested: false,
            supervisor_launch_id: Uuid::nil(),
            launch_evidence_id: Uuid::nil(),
            repository_binding_id: Uuid::nil(),
            target_lock_proof: [0u8; 32],
            minio_seed_binding: String::new(),
        }
    }
}

#[derive(Deserialize)]
struct AttemptStatusWire {
    #[serde(default)]
    found: bool,
    #[serde(default)]
    operation_id: Uuid,
    #[serde(default)]
    phase: String,
    #[serde(default)]
    selector_phase: String,
    #[serde(with = "crate::broker::wire::rfc3339")]
    accepted_at: OffsetDateTime,
    #[serde(with = "crate::broker::wire::rfc3339")]
    deadline: OffsetDateTime,
    #[serde(with = "crate::broker::wire::rfc3339")]
    activated_at: OffsetDateTime,
    #[serde(with = "crate::broker::wire::rfc3339")]
    cleanup_resolved_at: OffsetDateTime,
    #[serde(with = "crate::broker::wire::rfc3339")]
    expires_at: OffsetDateTime,
    #[serde(default)]
    cleanup_attested: bool,
    #[serde(default)]
    supervisor_launch_id: Uuid,
    #[serde(default)]
    launch_evidence_id: Uuid,
    #[serde(default)]
    repository_binding_id: Uuid,
    #[serde(default)]
    target_lock_proof_sha256: [u8; 32],
    #[serde(default)]
    minio_seed_binding: String,
}

// ---------------------------------------------------------------------------
// `BackupThroughputAuthority` — the root-helper client for the
// protected C02 operation (upstream's client half of
// `backup_throughput_rpc.go`). Transports only measurements, opaque
// bindings, safe timing, and cleanup census fields.
// ---------------------------------------------------------------------------

pub(crate) struct BackupThroughputAuthority {
    client: LifecycleClient,
}

impl BackupThroughputAuthority {
    /// `NewBackupThroughputAuthority`.
    pub(crate) fn new(socket_path: PathBuf) -> Self {
        Self {
            client: LifecycleClient::new(socket_path),
        }
    }

    /// `Accept`.
    fn accept(
        &self,
        operation_id: Uuid,
        accepted_at: OffsetDateTime,
        deadline: OffsetDateTime,
    ) -> Result<(), Failure> {
        #[derive(Serialize)]
        struct Request {
            #[serde(with = "crate::broker::wire::rfc3339")]
            accepted_at: OffsetDateTime,
            #[serde(with = "crate::broker::wire::rfc3339")]
            deadline: OffsetDateTime,
        }
        #[derive(Deserialize)]
        struct Result_ {
            accepted: bool,
        }
        if operation_id.is_nil() {
            return Err(unavailable("broker backup throughput authority: denied"));
        }
        let result: Result_ = self
            .client
            .call_with_operation_id(
                &operation_id.to_string(),
                crate::broker::protocol::BACKUP_THROUGHPUT_ACCEPT_RPC,
                &Request {
                    accepted_at,
                    deadline,
                },
            )
            .map_err(|_| unavailable("broker backup throughput authority: denied"))?;
        if !result.accepted {
            return Err(unavailable("broker backup throughput authority: denied"));
        }
        Ok(())
    }

    /// `Current` — the strict-validating reconciliation read.
    fn current(&self, request_id: Uuid) -> Result<BackupThroughputAttemptStatus, Failure> {
        if !is_v7(request_id) {
            return Err(unavailable("broker backup throughput authority: denied"));
        }
        let wire: AttemptStatusWire = self
            .client
            .call_with_operation_id(
                &request_id.to_string(),
                crate::broker::protocol::BACKUP_THROUGHPUT_CURRENT_RPC,
                &serde_json::json!({}),
            )
            .map_err(|_| unavailable("broker backup throughput authority: denied"))?;
        let result = BackupThroughputAttemptStatus {
            found: wire.found,
            operation_id: wire.operation_id,
            phase: wire.phase,
            selector_phase: wire.selector_phase,
            accepted_at: wire.accepted_at,
            deadline: wire.deadline,
            activated_at: wire.activated_at,
            cleanup_resolved_at: wire.cleanup_resolved_at,
            expires_at: wire.expires_at,
            cleanup_attested: wire.cleanup_attested,
            supervisor_launch_id: wire.supervisor_launch_id,
            launch_evidence_id: wire.launch_evidence_id,
            repository_binding_id: wire.repository_binding_id,
            target_lock_proof: wire.target_lock_proof_sha256,
            minio_seed_binding: wire.minio_seed_binding,
        };
        if !result.found {
            return Ok(result);
        }
        if result.operation_id.is_nil()
            || result.operation_id.get_version_num() != 7
            || result.phase.is_empty()
            || result.accepted_at == crate::broker::wire::go_zero_time()
            || result.deadline == crate::broker::wire::go_zero_time()
        {
            return Err(unavailable("broker backup throughput authority: denied"));
        }
        if result.phase == "failed"
            && result.cleanup_resolved_at == crate::broker::wire::go_zero_time()
        {
            return Err(unavailable("broker backup throughput authority: denied"));
        }
        Ok(result)
    }

    /// `CompletePending`.
    #[allow(clippy::too_many_arguments)]
    fn complete_pending(
        &self,
        operation_id: Uuid,
        launch_evidence_id: Uuid,
        retained_target_lock_proof: [u8; 32],
        worker_tree_reaped: bool,
        counts: ThroughputCleanupCounts,
        parent_elapsed: time::Duration,
        attested_at: OffsetDateTime,
    ) -> Result<(), Failure> {
        #[derive(Serialize)]
        struct Request {
            launch_evidence_id: Uuid,
            retained_target_lock_proof_sha256: [u8; 32],
            worker_tree_reaped: bool,
            counts: ThroughputCleanupCounts,
            #[serde(serialize_with = "ser_duration_ns")]
            parent_elapsed: time::Duration,
            #[serde(with = "crate::broker::wire::rfc3339")]
            attested_at: OffsetDateTime,
        }
        #[derive(Deserialize)]
        struct Result_ {
            pending: bool,
        }
        if operation_id.is_nil()
            || launch_evidence_id.is_nil()
            || retained_target_lock_proof == [0u8; 32]
        {
            return Err(unavailable("broker backup throughput authority: denied"));
        }
        let result: Result_ = self
            .client
            .call_with_operation_id(
                &operation_id.to_string(),
                crate::broker::protocol::BACKUP_THROUGHPUT_COMPLETE_PENDING_RPC,
                &Request {
                    launch_evidence_id,
                    retained_target_lock_proof_sha256: retained_target_lock_proof,
                    worker_tree_reaped,
                    counts,
                    parent_elapsed,
                    attested_at,
                },
            )
            .map_err(|_| unavailable("broker backup throughput authority: denied"))?;
        if !result.pending {
            return Err(unavailable("broker backup throughput authority: denied"));
        }
        Ok(())
    }

    /// `Activate` — returns the published evidence; a retry after an
    /// ambiguous response is safe (activation is persisted before
    /// publication).
    fn activate(
        &self,
        operation_id: Uuid,
        activated_at: OffsetDateTime,
    ) -> Result<ThroughputEvidence, Failure> {
        #[derive(Serialize)]
        struct Request {
            #[serde(with = "crate::broker::wire::rfc3339")]
            activated_at: OffsetDateTime,
        }
        if operation_id.is_nil() || activated_at == crate::broker::wire::go_zero_time() {
            return Err(unavailable("broker backup throughput authority: denied"));
        }
        let wire: crate::broker::throughput_journal::ThroughputEvidenceWire = self
            .client
            .call_with_operation_id(
                &operation_id.to_string(),
                crate::broker::protocol::BACKUP_THROUGHPUT_ACTIVATE_RPC,
                &Request { activated_at },
            )
            .map_err(|_| unavailable("broker backup throughput authority: denied"))?;
        let evidence = evidence_from_wire(&wire);
        if evidence.probe_operation_id != operation_id {
            return Err(unavailable("broker backup throughput authority: denied"));
        }
        Ok(evidence)
    }

    /// `MarkFailed` — `cleanupRequired` picks upstream's RPC pair:
    /// the counts-attested failure record or the bare terminal
    /// `cleanup_required` mark.
    fn mark_failed(
        &self,
        operation_id: Uuid,
        at: OffsetDateTime,
        cleanup_required: bool,
        counts: ThroughputCleanupCounts,
    ) -> Result<(), Failure> {
        #[derive(Serialize)]
        struct ResolutionRequest {
            counts: ThroughputCleanupCounts,
            #[serde(with = "crate::broker::wire::rfc3339")]
            at: OffsetDateTime,
        }
        #[derive(Serialize)]
        struct TerminalRequest {
            #[serde(with = "crate::broker::wire::rfc3339")]
            at: OffsetDateTime,
        }
        #[derive(Deserialize)]
        struct Result_ {
            terminal: bool,
        }
        if operation_id.is_nil() {
            return Err(unavailable("broker backup throughput authority: denied"));
        }
        let result: Result_ = if cleanup_required {
            self.client
                .call_with_operation_id(
                    &operation_id.to_string(),
                    crate::broker::protocol::BACKUP_THROUGHPUT_CLEANUP_REQUIRED_RPC,
                    &TerminalRequest { at },
                )
                .map_err(|_| unavailable("broker backup throughput authority: denied"))?
        } else {
            self.client
                .call_with_operation_id(
                    &operation_id.to_string(),
                    crate::broker::protocol::BACKUP_THROUGHPUT_FAILED_RPC,
                    &ResolutionRequest { counts, at },
                )
                .map_err(|_| unavailable("broker backup throughput authority: denied"))?
        };
        if !result.terminal {
            return Err(unavailable("broker backup throughput authority: denied"));
        }
        Ok(())
    }

    /// `ResolveCleanup`.
    fn resolve_cleanup(
        &self,
        operation_id: Uuid,
        counts: ThroughputCleanupCounts,
        at: OffsetDateTime,
    ) -> Result<(), Failure> {
        #[derive(Serialize)]
        struct Request {
            counts: ThroughputCleanupCounts,
            #[serde(with = "crate::broker::wire::rfc3339")]
            at: OffsetDateTime,
        }
        #[derive(Deserialize)]
        struct Result_ {
            terminal: bool,
        }
        if operation_id.is_nil() {
            return Err(unavailable("broker backup throughput authority: denied"));
        }
        let result: Result_ = self
            .client
            .call_with_operation_id(
                &operation_id.to_string(),
                crate::broker::protocol::BACKUP_THROUGHPUT_CLEANUP_RESOLVED_RPC,
                &Request { counts, at },
            )
            .map_err(|_| unavailable("broker backup throughput authority: denied"))?;
        if !result.terminal {
            return Err(unavailable("broker backup throughput authority: denied"));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// `BackupThroughputLaunchIssuer` — the root-helper client for one
// already-accepted, helper-observed throughput worker.
// ---------------------------------------------------------------------------

pub(crate) struct BackupThroughputLaunchIssuer {
    client: LifecycleClient,
}

impl BackupThroughputLaunchIssuer {
    /// `NewBackupThroughputLaunchIssuer`.
    pub(crate) fn new(socket_path: PathBuf) -> Self {
        Self {
            client: LifecycleClient::new(socket_path),
        }
    }

    /// `Issue`.
    fn issue(
        &self,
        evidence: &BackupThroughputLaunchEvidence,
    ) -> Result<BackupThroughputLaunchAuthority, Failure> {
        if !is_v7(evidence.operation_id) {
            return Err(unavailable("broker backup throughput launch: denied"));
        }
        let result: BackupThroughputLaunchAuthority = self
            .client
            .call_with_operation_id(
                &evidence.operation_id.to_string(),
                crate::broker::protocol::BACKUP_THROUGHPUT_ISSUE_LAUNCH_RPC,
                evidence,
            )
            .map_err(|_| unavailable("broker backup throughput launch: denied"))?;
        if result.launch_evidence_id.is_nil()
            || result.operation_id != evidence.operation_id
            || result.deadline != evidence.deadline.to_offset(time::UtcOffset::UTC)
        {
            return Err(unavailable("broker backup throughput launch: denied"));
        }
        Ok(result)
    }

    /// `ReadState`.
    fn read_state(
        &self,
        operation_id: Uuid,
        launch_evidence_id: Uuid,
    ) -> Result<BackupThroughputLaunchStatus, Failure> {
        #[derive(Serialize)]
        struct Request {
            launch_evidence_id: Uuid,
        }
        if operation_id.is_nil() || launch_evidence_id.is_nil() {
            return Err(unavailable("broker backup throughput launch: denied"));
        }
        let result: BackupThroughputLaunchStatus = self
            .client
            .call_with_operation_id(
                &operation_id.to_string(),
                crate::broker::protocol::BACKUP_THROUGHPUT_READ_LAUNCH_RPC,
                &Request { launch_evidence_id },
            )
            .map_err(|_| unavailable("broker backup throughput launch: denied"))?;
        if result.operation_id != operation_id
            || result.launch_evidence_id != launch_evidence_id
            || result.phase.is_empty()
        {
            return Err(unavailable("broker backup throughput launch: denied"));
        }
        Ok(result)
    }

    /// `MarkFixtureLoaded`.
    fn mark_fixture_loaded(
        &self,
        operation_id: Uuid,
        launch_evidence_id: Uuid,
        attestation: &BackupThroughputFixtureLoadAttestation,
    ) -> Result<(), Failure> {
        #[derive(Serialize)]
        struct Request<'a> {
            launch_evidence_id: Uuid,
            attestation: &'a BackupThroughputFixtureLoadAttestation,
        }
        #[derive(Deserialize)]
        struct Result_ {
            loaded: bool,
        }
        if operation_id.is_nil() || launch_evidence_id.is_nil() {
            return Err(unavailable("broker backup throughput fixture: denied"));
        }
        let result: Result_ = self
            .client
            .call_with_operation_id(
                &operation_id.to_string(),
                crate::broker::protocol::BACKUP_THROUGHPUT_FIXTURE_LOADED_RPC,
                &Request {
                    launch_evidence_id,
                    attestation,
                },
            )
            .map_err(|_| unavailable("broker backup throughput fixture: denied"))?;
        if !result.loaded {
            return Err(unavailable("broker backup throughput fixture: denied"));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Duration serde helper — `time.Duration` is integer nanoseconds on
// the wire (upstream `backup_authority.rs`'s identical shape).
// ---------------------------------------------------------------------------

fn ser_duration_ns<S: serde::Serializer>(d: &time::Duration, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_i64(d.whole_nanoseconds() as i64)
}

// ---------------------------------------------------------------------------
// `backupThroughputPostgresFixtureProvisioner` — the disposable-
// database lifecycle (`backup_throughput_postgres.go`). The wire
// shapes mirror central-local-infra's `internal/request/
// postgres_provision.go` and `internal/receipt/receipt.go` exactly:
// field names, JSON key order, and the schema-prefixed raw-byte
// digest domain, because the provisioner recomputes every binding
// byte-for-byte.
// ---------------------------------------------------------------------------

const POSTGRES_THROUGHPUT_PROTOCOL_IDENTITY: &str = "central.postgres-throughput-protocol/v2";
const POSTGRES_THROUGHPUT_PROVISION_SCHEMA: &str = "central.postgres-throughput-provision/v2";
const POSTGRES_THROUGHPUT_FIXTURE_SCHEMA: &str = "central.postgres-throughput-fixture/v2";
const POSTGRES_THROUGHPUT_FIXTURE_REQUEST_SCHEMA: &str =
    "central.postgres-throughput-fixture-request/v3";
const POSTGRES_THROUGHPUT_RECEIPT_SCHEMA: &str = "central.postgres-throughput-fixture-receipt/v2";
const POSTGRES_THROUGHPUT_FIXTURE_ROWS: u64 = 512;
const POSTGRES_THROUGHPUT_FIXTURE_CHUNK_BYTES: u64 = 1024 * 1024;
const POSTGRES_THROUGHPUT_FIXTURE_BYTES: u64 =
    POSTGRES_THROUGHPUT_FIXTURE_ROWS * POSTGRES_THROUGHPUT_FIXTURE_CHUNK_BYTES;
const POSTGRES_THROUGHPUT_FIXTURE_SHA256: &str =
    "sha256:70ce3760edb849d0e79f7b6c4e6c5df63b469257be7d98920bc47986303f0690";
const POSTGRES_REASON_COMPLETED: &str = "postgres throughput fixture operation completed";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum PostgresFixtureOperation {
    #[serde(rename = "create_load_v1")]
    CreateLoad,
    #[serde(rename = "verify_v1")]
    Verify,
    #[serde(rename = "drop_v1")]
    Drop,
}

impl PostgresFixtureOperation {
    fn as_str(self) -> &'static str {
        match self {
            Self::CreateLoad => "create_load_v1",
            Self::Verify => "verify_v1",
            Self::Drop => "drop_v1",
        }
    }
}

/// `backupThroughputPostgresFixtureLoad`/`Census`/`Observation`.
#[derive(Debug, Clone, Default)]
struct PostgresFixtureLoad {
    fixture_load_elapsed: time::Duration,
    provision_receipt_binding: String,
}

#[derive(Debug, Clone, Copy, Default)]
struct PostgresFixtureCensus {
    postgres_sessions: u32,
    disposable_databases: u32,
}

#[derive(Debug, Clone, Copy, Default)]
struct PostgresObservation {
    database_count: u64,
    session_count: u64,
}

/// `backupThroughputPostgresFixtureProvisioner`.
trait PostgresFixtureProvisioner: Send + Sync {
    fn create_and_load(
        &self,
        op_deadline: OpDeadline,
        operation_id: Uuid,
        deadline_wall: OffsetDateTime,
    ) -> Result<PostgresFixtureLoad, Failure>;
    fn verify(
        &self,
        op_deadline: OpDeadline,
        operation_id: Uuid,
        creation_binding: &str,
        deadline_wall: OffsetDateTime,
    ) -> Result<(), Failure>;
    fn drop_and_census(
        &self,
        op_deadline: OpDeadline,
        operation_id: Uuid,
        deadline_wall: OffsetDateTime,
    ) -> Result<PostgresFixtureCensus, Failure>;
}

/// `postgresThroughputFence` — a stable, non-zero, operation-scoped
/// fence, namespaced separately from `backup_minio_fence`'s domain.
fn postgres_throughput_fence(operation_id: Uuid) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"central.postgres-throughput-fence/v1");
    hasher.update([0u8]);
    hasher.update(operation_id.as_bytes());
    let digest = hasher.finalize();
    let value = u64::from_be_bytes(digest[..8].try_into().unwrap_or([0; 8]));
    if value == 0 { 1 } else { value }
}

/// `postgresProbeDatabaseName`.
fn postgres_probe_database_name(operation_id: &str) -> Result<String, Failure> {
    let parsed = Uuid::parse_str(operation_id)
        .map_err(|_| unavailable("operation_id must be canonical UUIDv7"))?;
    if parsed.get_version_num() != 7 || parsed.to_string() != operation_id {
        return Err(unavailable("operation_id must be canonical UUIDv7"));
    }
    Ok(format!("central_probe_{}", operation_id.replace('-', "")))
}

/// `postgresProbeDatabaseDigest`.
fn postgres_probe_database_digest(operation_id: &str) -> Result<String, Failure> {
    let database = postgres_probe_database_name(operation_id)?;
    let mut hasher = Sha256::new();
    hasher.update(b"central.postgres-throughput-database/v2");
    hasher.update([0u8]);
    hasher.update(database.as_bytes());
    Ok(format!("sha256:{}", hex_encode(&hasher.finalize())))
}

/// `postgresThroughputFixtureBindingDigest` — replicates
/// central-local-infra's
/// `request.PostgresThroughputFixtureBindingDigest` byte-for-byte:
/// same field set, same declaration order, same schema-prefixed raw
/// byte concatenation. Deadline is deliberately excluded (SC-DEF-44).
fn postgres_fixture_binding_digest(
    operation_id: &str,
    instance_id: &str,
    operation: PostgresFixtureOperation,
    fence_token: u64,
    candidate_manifest_digest: &str,
    candidate_config_digest: &str,
    compose_policy_digest: &str,
) -> Result<String, Failure> {
    #[derive(Serialize)]
    struct Canonical<'a> {
        candidate_config_digest: &'a str,
        candidate_manifest_digest: &'a str,
        compose_policy_digest: &'a str,
        database_identity_digest: &'a str,
        fence_token: u64,
        fixture_bytes: u64,
        fixture_rows: u64,
        fixture_schema: &'a str,
        fixture_sha256: &'a str,
        instance_id: &'a str,
        operation: PostgresFixtureOperation,
        operation_id: &'a str,
        protocol_identity: &'a str,
        schema_version: &'a str,
    }
    let database_digest = postgres_probe_database_digest(operation_id)?;
    let canonical = serde_json::to_vec(&Canonical {
        candidate_config_digest,
        candidate_manifest_digest,
        compose_policy_digest,
        database_identity_digest: &database_digest,
        fence_token,
        fixture_bytes: POSTGRES_THROUGHPUT_FIXTURE_BYTES,
        fixture_rows: POSTGRES_THROUGHPUT_FIXTURE_ROWS,
        fixture_schema: POSTGRES_THROUGHPUT_FIXTURE_SCHEMA,
        fixture_sha256: POSTGRES_THROUGHPUT_FIXTURE_SHA256,
        instance_id,
        operation,
        operation_id,
        protocol_identity: POSTGRES_THROUGHPUT_PROTOCOL_IDENTITY,
        schema_version: POSTGRES_THROUGHPUT_FIXTURE_REQUEST_SCHEMA,
    })
    .map_err(|_| unavailable("postgres throughput fixture binding unavailable"))?;
    let mut hasher = Sha256::new();
    hasher.update(POSTGRES_THROUGHPUT_FIXTURE_REQUEST_SCHEMA.as_bytes());
    hasher.update([0u8]);
    hasher.update(&canonical);
    Ok(format!("sha256:{}", hex_encode(&hasher.finalize())))
}

#[derive(Serialize)]
struct LocalInfraPostgresFixtureOperation {
    operation: PostgresFixtureOperation,
    request_binding_digest: String,
}

#[derive(Serialize)]
struct LocalInfraPostgresProvisionParams {
    schema_version: String,
    protocol_identity: String,
    fence_token: u64,
    candidate_config_digest: String,
    throughput_fixture: LocalInfraPostgresFixtureOperation,
}

#[derive(Serialize)]
struct LocalInfraPostgresProvisionRequest {
    schema_version: String,
    mode: String,
    operation_id: String,
    instance_id: String,
    policy_digest: String,
    image_digest: String,
    #[serde(with = "crate::broker::wire::rfc3339")]
    deadline: OffsetDateTime,
    postgres_provision: LocalInfraPostgresProvisionParams,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PostgresThroughputFixtureReceipt {
    schema_version: String,
    protocol_identity: String,
    operation: String,
    fence_token: u64,
    #[serde(with = "crate::broker::wire::rfc3339")]
    deadline: OffsetDateTime,
    candidate_manifest_digest: String,
    candidate_config_digest: String,
    compose_policy_digest: String,
    request_binding_digest: String,
    database_identity_digest: String,
    fixture_sha256: String,
    fixture_rows: u64,
    fixture_bytes: u64,
    database_count: u64,
    session_count: u64,
    elapsed_ms: u64,
    receipt_binding_digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalInfraPostgresReceipt {
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
    postgres_throughput_fixture: Option<PostgresThroughputFixtureReceipt>,
}

/// `decodePostgresThroughputFixtureReceipt` — validates every field
/// this adapter can independently derive or expects verbatim, and
/// requires `ReceiptBindingDigest` to be a well-formed digest without
/// recomputing central-local-infra's internal self-consistency hash
/// (the same lighter-touch approach the MinIO leg takes).
#[allow(clippy::too_many_arguments)]
fn decode_postgres_fixture_receipt(
    raw: &[u8],
    operation_id: &str,
    instance_id: &str,
    operation: PostgresFixtureOperation,
    request_binding: &str,
    manifest_digest: &str,
    config_digest: &str,
    policy_digest: &str,
    fence: u64,
    deadline: OffsetDateTime,
    now: OffsetDateTime,
) -> Result<PostgresObservation, Failure> {
    let mut stream = serde_json::Deserializer::from_slice(raw).into_iter::<serde_json::Value>();
    let (Some(Ok(value)), None) = (stream.next(), stream.next()) else {
        return Err(unavailable(
            "postgres throughput fixture receipt denied: invalid fixture receipt",
        ));
    };
    let receipt: LocalInfraPostgresReceipt = serde_json::from_value(value).map_err(|_| {
        unavailable("postgres throughput fixture receipt denied: invalid fixture receipt")
    })?;
    if receipt.schema_version != LOCAL_INFRA_RECEIPT_SCHEMA
        || receipt.mode != "postgres-provision"
        || receipt.operation_id != operation_id
        || receipt.instance_id != instance_id
        || receipt.outcome != "completed"
        || receipt.reason != POSTGRES_REASON_COMPLETED
        || receipt.started_at == crate::broker::wire::go_zero_time()
        || receipt.completed_at < receipt.started_at
        || receipt.completed_at > now + time::Duration::minutes(1)
    {
        return Err(unavailable(
            "postgres throughput fixture receipt denied: invalid fixture receipt",
        ));
    }
    let Some(fixture) = receipt.postgres_throughput_fixture else {
        return Err(unavailable(
            "postgres throughput fixture receipt denied: invalid fixture receipt",
        ));
    };
    if fixture.schema_version != POSTGRES_THROUGHPUT_RECEIPT_SCHEMA
        || fixture.protocol_identity != POSTGRES_THROUGHPUT_PROTOCOL_IDENTITY
        || fixture.operation != operation.as_str()
        || fixture.fence_token != fence
        || fixture.deadline != deadline.to_offset(time::UtcOffset::UTC)
        || fixture.candidate_manifest_digest != manifest_digest
        || fixture.candidate_config_digest != config_digest
        || fixture.compose_policy_digest != policy_digest
        || fixture.request_binding_digest != request_binding
        || !valid_throughput_sha256(&fixture.database_identity_digest)
        || fixture.fixture_sha256 != POSTGRES_THROUGHPUT_FIXTURE_SHA256
        || !valid_throughput_sha256(&fixture.receipt_binding_digest)
        || fixture.elapsed_ms == 0
        || fixture.elapsed_ms > 300_000
    {
        return Err(unavailable(
            "postgres throughput fixture receipt denied: invalid fixture receipt",
        ));
    }
    match operation {
        PostgresFixtureOperation::CreateLoad | PostgresFixtureOperation::Verify => {
            if fixture.fixture_rows != POSTGRES_THROUGHPUT_FIXTURE_ROWS
                || fixture.fixture_bytes != POSTGRES_THROUGHPUT_FIXTURE_BYTES
                || fixture.database_count != 1
                || fixture.session_count != 0
            {
                return Err(unavailable(
                    "postgres throughput fixture receipt denied: invalid fixture receipt",
                ));
            }
        }
        PostgresFixtureOperation::Drop => {
            if fixture.fixture_rows != 0
                || fixture.fixture_bytes != 0
                || fixture.database_count != 0
                || fixture.session_count != 0
            {
                return Err(unavailable(
                    "postgres throughput fixture receipt denied: invalid fixture receipt",
                ));
            }
        }
    }
    Ok(PostgresObservation {
        database_count: fixture.database_count,
        session_count: fixture.session_count,
    })
}

/// `postgresThroughputImageDigests` — the prepared
/// `postgres-throughput-provision` candidate's manifest/config
/// digests.
fn postgres_throughput_image_digests(
    receipt: &DependencyReceipt,
) -> Result<(String, String), Failure> {
    let inventory = receipt
        .dependency_set
        .lookup(ServiceMode::PostgresThroughputProvision)
        .map_err(|_| unavailable("postgres throughput fixture image identity unavailable"))?;
    if !valid_throughput_sha256(&inventory.manifest_digest)
        || !valid_throughput_sha256(&inventory.config_digest)
    {
        return Err(unavailable(
            "postgres throughput fixture image identity unavailable",
        ));
    }
    Ok((
        inventory.manifest_digest.clone(),
        inventory.config_digest.clone(),
    ))
}

/// `productionPostgresThroughputFixtureProvisioner` runs the
/// separately delivered postgres-throughput-provision candidate for
/// C02's disposable-database fixture lifecycle, mirroring
/// `productionMinioThroughputFixtureManager`'s shape.
pub(crate) struct ProductionPostgresThroughputFixtureProvisioner {
    instance_id: String,
    policy: Policy,
    receipts: Box<dyn BackupDependencyReceiptSource>,
    runner: Box<dyn BackupMinioComposeRunner>,
    rendered: RenderedFile,
    credential: ProductionPostgresAdminCredentialManager,
    /// `superuser` — ADR 0019 §5's rotate-then-sync seam: before the
    /// container starts, the live `central` role's password rotates
    /// to the value the container passfile carries.
    superuser: Box<dyn PostgresSuperuserRotator>,
    now: fn() -> OffsetDateTime,
}

impl ProductionPostgresThroughputFixtureProvisioner {
    /// `newProductionPostgresThroughputFixtureProvisioner`.
    pub(crate) fn new_production(
        composition: &crate::broker::daemon::ProductionInstanceComposition,
    ) -> Result<Self, Failure> {
        let policy = load_default_policy()
            .map_err(|_| unavailable("postgres throughput fixture policy unavailable"))?;
        let credential = ProductionPostgresAdminCredentialManager::new_production(composition)?;
        let superuser = ProductionPostgresSuperuserCredentialStore::new_production(composition)?;
        Ok(Self {
            instance_id: composition.instance_id.clone(),
            policy,
            receipts: Box::new(CandidateStore::new(
                None,
                composition.dependency_root.clone(),
            )),
            runner: Box::new(CommandComposeRunner::new("/usr/bin/docker", None, None)),
            rendered: RenderedFile {
                path: composition.compose_path.clone(),
                content: Vec::new(),
            },
            credential,
            superuser: Box::new(superuser),
            now: OffsetDateTime::now_utc,
        })
    }

    /// `run` — one closed postgres-provision request/response round
    /// trip: the single-use admin passfile is materialized
    /// immediately before the container starts and removed
    /// unconditionally afterward.
    fn run(
        &self,
        op_deadline: OpDeadline,
        operation_id: Uuid,
        operation: PostgresFixtureOperation,
        deadline_wall: OffsetDateTime,
    ) -> Result<(PostgresObservation, String), Failure> {
        let now = (self.now)();
        if !is_v7(operation_id)
            || deadline_wall == crate::broker::wire::go_zero_time()
            || now >= deadline_wall
        {
            return Err(unavailable(
                "postgres throughput fixture authority unavailable",
            ));
        }
        let receipt = self.receipts.active(op_deadline).map_err(|_| {
            unavailable("postgres throughput fixture dependency identity unavailable")
        })?;
        if receipt.validate_b03().is_err() {
            return Err(unavailable(
                "postgres throughput fixture dependency identity unavailable",
            ));
        }
        let (manifest_digest, config_digest) = postgres_throughput_image_digests(&receipt)?;
        let fence = postgres_throughput_fence(operation_id);
        let policy_digest_value = policy_digest(&self.policy);

        // The "creation binding" is always computed with
        // `create_load_v1`, independent of which lifecycle phase is
        // actually running — central-local-infra's `Service.Run`
        // derives the identical value the same way.
        let creation_binding = postgres_fixture_binding_digest(
            &operation_id.to_string(),
            &self.instance_id,
            PostgresFixtureOperation::CreateLoad,
            fence,
            &manifest_digest,
            &config_digest,
            &policy_digest_value,
        )?;
        let request_binding = postgres_fixture_binding_digest(
            &operation_id.to_string(),
            &self.instance_id,
            operation,
            fence,
            &manifest_digest,
            &config_digest,
            &policy_digest_value,
        )?;

        let rotated = self
            .superuser
            .rotate_for_operation()
            .map_err(|_| unavailable("postgres superuser rotation unavailable"))?;
        self.credential
            .materialize_with_password(operation_id, &rotated)
            .map_err(|_| unavailable("postgres admin credential unavailable"))?;
        // Unconditional cleanup — upstream's `defer credential.Cleanup
        // (context.WithoutCancel(ctx))`: a failed or crashed run never
        // leaves the credential mounted.
        let cleanup_result = (|| {
            let payload = serde_json::to_vec(&LocalInfraPostgresProvisionRequest {
                schema_version: LOCAL_INFRA_REQUEST_SCHEMA.to_owned(),
                mode: "postgres-provision".to_owned(),
                operation_id: operation_id.to_string(),
                instance_id: self.instance_id.clone(),
                policy_digest: policy_digest_value.clone(),
                image_digest: manifest_digest.clone(),
                deadline: deadline_wall.to_offset(time::UtcOffset::UTC),
                postgres_provision: LocalInfraPostgresProvisionParams {
                    schema_version: POSTGRES_THROUGHPUT_PROVISION_SCHEMA.to_owned(),
                    protocol_identity: POSTGRES_THROUGHPUT_PROTOCOL_IDENTITY.to_owned(),
                    fence_token: fence,
                    candidate_config_digest: config_digest.clone(),
                    throughput_fixture: LocalInfraPostgresFixtureOperation {
                        operation,
                        request_binding_digest: request_binding.clone(),
                    },
                },
            })
            .map_err(|_| unavailable("postgres throughput fixture request unavailable"))?;
            let (output, exit_code) = self
                .runner
                .run_with_input_output(
                    &self.rendered,
                    "postgres-throughput-provision",
                    &["postgres-provision".to_owned()],
                    &payload,
                    op_deadline,
                )
                .map_err(|_| unavailable("postgres throughput fixture operation failed"))?;
            if exit_code != 0 {
                return Err(unavailable("postgres throughput fixture operation failed"));
            }
            let observation = decode_postgres_fixture_receipt(
                &output,
                &operation_id.to_string(),
                &self.instance_id,
                operation,
                &request_binding,
                &manifest_digest,
                &config_digest,
                &policy_digest_value,
                fence,
                deadline_wall,
                (self.now)(),
            )?;
            Ok(observation)
        })();
        let cleanup_err = self.credential.cleanup(operation_id).err();
        match (cleanup_result, cleanup_err) {
            (Ok(observation), _) => Ok((observation, creation_binding)),
            (Err(e), Some(_)) => Err(Failure::denied(
                "backup_throughput",
                format!("{}; postgres admin credential cleanup failed", e.message()),
            )),
            (Err(e), None) => Err(e),
        }
    }
}

impl PostgresFixtureProvisioner for ProductionPostgresThroughputFixtureProvisioner {
    /// `CreateAndLoad`.
    fn create_and_load(
        &self,
        op_deadline: OpDeadline,
        operation_id: Uuid,
        deadline_wall: OffsetDateTime,
    ) -> Result<PostgresFixtureLoad, Failure> {
        let started = (self.now)();
        let (observation, creation_binding) = self.run(
            op_deadline,
            operation_id,
            PostgresFixtureOperation::CreateLoad,
            deadline_wall,
        )?;
        let elapsed = (self.now)() - started;
        if elapsed <= time::Duration::ZERO || observation.database_count != 1 {
            return Err(unavailable("postgres throughput fixture create failed"));
        }
        Ok(PostgresFixtureLoad {
            fixture_load_elapsed: elapsed,
            provision_receipt_binding: creation_binding,
        })
    }

    /// `Verify`.
    fn verify(
        &self,
        op_deadline: OpDeadline,
        operation_id: Uuid,
        creation_binding: &str,
        deadline_wall: OffsetDateTime,
    ) -> Result<(), Failure> {
        let (observation, recomputed) = self.run(
            op_deadline,
            operation_id,
            PostgresFixtureOperation::Verify,
            deadline_wall,
        )?;
        if creation_binding.is_empty()
            || recomputed != creation_binding
            || observation.database_count != 1
        {
            return Err(unavailable("postgres throughput fixture verify failed"));
        }
        Ok(())
    }

    /// `DropAndCensus` — idempotent; reports exact remaining
    /// sessions/databases without returning a database locator.
    fn drop_and_census(
        &self,
        op_deadline: OpDeadline,
        operation_id: Uuid,
        deadline_wall: OffsetDateTime,
    ) -> Result<PostgresFixtureCensus, Failure> {
        let (observation, _) = self.run(
            op_deadline,
            operation_id,
            PostgresFixtureOperation::Drop,
            deadline_wall,
        )?;
        if observation.database_count != 0 || observation.session_count != 0 {
            return Err(unavailable(
                "postgres throughput fixture drop left residual state",
            ));
        }
        Ok(PostgresFixtureCensus {
            postgres_sessions: u32::try_from(observation.session_count).unwrap_or(u32::MAX),
            disposable_databases: u32::try_from(observation.database_count).unwrap_or(u32::MAX),
        })
    }
}

// ---------------------------------------------------------------------------
// `productionMinioThroughputFixtureManager` — the privileged
// lifecycle for the single fixed object C02 uses (`backup_throughput_
// minio.go`). The request has no endpoint, key, size, checksum,
// credential purpose, broker socket, or policy field a caller can
// select.
// ---------------------------------------------------------------------------

const MINIO_THROUGHPUT_FIXTURE_SCHEMA: &str = "central.minio-throughput-fixture-receipt/v1";
const MINIO_THROUGHPUT_FIXTURE_REQUEST_DOMAIN: &str = "central.minio-throughput-fixture-request/v1";
const MINIO_THROUGHPUT_FIXTURE_KEY: &str = "v1/system/backup-throughput-fixture-v1";
const MINIO_THROUGHPUT_FIXTURE_BYTES: i64 = 512 * 1024 * 1024;
const MINIO_THROUGHPUT_FIXTURE_SHA256: &str =
    "sha256:21134f507d39ce301dca4d0f44ca3d2f56b1b2d2fbca4171ec1751193ca0f276";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
enum MinioFixtureOperation {
    #[serde(rename = "seed_v1")]
    Seed,
    #[serde(rename = "verify_v1")]
    Verify,
    #[serde(rename = "delete_v1")]
    Delete,
}

impl MinioFixtureOperation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Seed => "seed_v1",
            Self::Verify => "verify_v1",
            Self::Delete => "delete_v1",
        }
    }
}

/// `minioThroughputFixtureResult`.
#[derive(Debug, Clone, Default)]
struct MinioFixtureResult {
    request_binding_digest: String,
    seed_binding_digest: String,
    object_present: bool,
}

/// `backupThroughputMinioFixtureProvisioner`.
trait MinioFixtureProvisioner: Send + Sync {
    fn seed(
        &self,
        op_deadline: OpDeadline,
        operation_id: Uuid,
        fence: u64,
        deadline_wall: OffsetDateTime,
    ) -> Result<MinioFixtureResult, Failure>;
    fn verify(
        &self,
        op_deadline: OpDeadline,
        operation_id: Uuid,
        fence: u64,
        deadline_wall: OffsetDateTime,
    ) -> Result<MinioFixtureResult, Failure>;
    fn delete(
        &self,
        op_deadline: OpDeadline,
        operation_id: Uuid,
        fence: u64,
        deadline_wall: OffsetDateTime,
    ) -> Result<MinioFixtureResult, Failure>;
}

/// `productionMinioThroughputFixtureManager`.
pub(crate) struct ProductionMinioThroughputFixtureManager {
    instance_id: String,
    policy: Policy,
    image_digest: String,
    runner: Box<dyn BackupMinioComposeRunner>,
    rendered: RenderedFile,
    now: fn() -> OffsetDateTime,
}

impl ProductionMinioThroughputFixtureManager {
    /// `newProductionMinioThroughputFixtureManager` — resolves the
    /// MinIO leg's image digest once, at composition time, matching
    /// upstream's `imageDigest` field (unlike the per-operation
    /// preparer which re-reads the receipt on every call).
    pub(crate) fn new_production(
        composition: &crate::broker::daemon::ProductionInstanceComposition,
    ) -> Result<Self, Failure> {
        let policy = load_default_policy()
            .map_err(|_| unavailable("minio throughput fixture policy unavailable"))?;
        let receipts = CandidateStore::new(None, composition.dependency_root.clone());
        let receipt = receipts
            .active(OpDeadline(None))
            .map_err(|_| unavailable("minio throughput fixture dependency identity unavailable"))?;
        if receipt.validate_b03().is_err() {
            return Err(unavailable(
                "minio throughput fixture dependency identity unavailable",
            ));
        }
        let image_digest =
            crate::helper::minio_provision::backup_minio_image_digest(&receipt.dependency_set)
                .map_err(|_| unavailable("minio throughput fixture image identity unavailable"))?;
        Ok(Self {
            instance_id: composition.instance_id.clone(),
            policy,
            image_digest,
            runner: Box::new(CommandComposeRunner::new("/usr/bin/docker", None, None)),
            rendered: RenderedFile {
                path: composition.compose_path.clone(),
                content: Vec::new(),
            },
            now: OffsetDateTime::now_utc,
        })
    }

    /// `run` — one closed fixture operation: exact compose model →
    /// binding digest → request → container → strict receipt.
    fn run(
        &self,
        op_deadline: OpDeadline,
        operation_id: Uuid,
        operation: MinioFixtureOperation,
        fence: u64,
        deadline_wall: OffsetDateTime,
    ) -> Result<MinioFixtureResult, Failure> {
        let now = (self.now)();
        if !is_v7(operation_id)
            || self.instance_id.is_empty()
            || self.image_digest.is_empty()
            || self.rendered.path.is_empty()
            || fence == 0
            || deadline_wall == crate::broker::wire::go_zero_time()
            || now >= deadline_wall
        {
            return Err(unavailable(
                "backup throughput fixture authority unavailable",
            ));
        }
        let model = self
            .runner
            .config(&self.rendered, op_deadline)
            .map_err(|_| unavailable("backup throughput fixture topology unavailable"))?;
        if !crate::helper::minio_provision::exact_backup_minio_compose_model(
            &model,
            &self.instance_id,
            &self.image_digest,
        ) {
            return Err(unavailable(
                "backup throughput fixture topology unavailable",
            ));
        }
        let binding = minio_fixture_binding_digest(
            &operation_id.to_string(),
            &self.instance_id,
            operation,
            fence,
        )?;
        let payload = serde_json::to_vec(&LocalInfraMinioFixtureRequest {
            schema_version: LOCAL_INFRA_REQUEST_SCHEMA.to_owned(),
            mode: "minio-provision".to_owned(),
            operation_id: operation_id.to_string(),
            instance_id: self.instance_id.clone(),
            target: backup_minio_target_descriptor(operation_id),
            policy_digest: policy_digest(&self.policy),
            image_digest: self.image_digest.clone(),
            deadline: deadline_wall.to_offset(time::UtcOffset::UTC),
            minio_provision: LocalInfraMinioFixtureParams {
                root_credential_path: "/run/secrets/minio-root-password".to_owned(),
                bucket: BACKUP_MINIO_BUCKET.to_owned(),
                fence_token: fence,
                throughput_fixture: LocalInfraMinioFixtureOperation {
                    operation,
                    request_binding_digest: binding.clone(),
                },
            },
        })
        .map_err(|_| unavailable("backup throughput fixture request unavailable"))?;
        let (output, exit_code) = self
            .runner
            .run_with_input_output(
                &self.rendered,
                "minio-provision",
                &["minio-provision".to_owned()],
                &payload,
                op_deadline,
            )
            .map_err(|_| unavailable("backup throughput fixture operation failed"))?;
        if exit_code != 0 {
            return Err(unavailable("backup throughput fixture operation failed"));
        }
        decode_minio_fixture_receipt(
            &output,
            &operation_id.to_string(),
            &self.instance_id,
            operation,
            &binding,
            (self.now)(),
        )
        .map_err(|_| unavailable("backup throughput fixture receipt denied"))
    }
}

impl MinioFixtureProvisioner for ProductionMinioThroughputFixtureManager {
    fn seed(
        &self,
        op_deadline: OpDeadline,
        operation_id: Uuid,
        fence: u64,
        deadline_wall: OffsetDateTime,
    ) -> Result<MinioFixtureResult, Failure> {
        self.run(
            op_deadline,
            operation_id,
            MinioFixtureOperation::Seed,
            fence,
            deadline_wall,
        )
    }

    fn verify(
        &self,
        op_deadline: OpDeadline,
        operation_id: Uuid,
        fence: u64,
        deadline_wall: OffsetDateTime,
    ) -> Result<MinioFixtureResult, Failure> {
        self.run(
            op_deadline,
            operation_id,
            MinioFixtureOperation::Verify,
            fence,
            deadline_wall,
        )
    }

    fn delete(
        &self,
        op_deadline: OpDeadline,
        operation_id: Uuid,
        fence: u64,
        deadline_wall: OffsetDateTime,
    ) -> Result<MinioFixtureResult, Failure> {
        self.run(
            op_deadline,
            operation_id,
            MinioFixtureOperation::Delete,
            fence,
            deadline_wall,
        )
    }
}

#[derive(Serialize)]
struct LocalInfraMinioFixtureOperation {
    operation: MinioFixtureOperation,
    request_binding_digest: String,
}

#[derive(Serialize)]
struct LocalInfraMinioFixtureParams {
    root_credential_path: String,
    bucket: String,
    fence_token: u64,
    throughput_fixture: LocalInfraMinioFixtureOperation,
}

#[derive(Serialize)]
struct LocalInfraMinioFixtureRequest {
    schema_version: String,
    mode: String,
    operation_id: String,
    instance_id: String,
    target: crate::helper::minio_provision::LocalInfraMinioTarget,
    policy_digest: String,
    image_digest: String,
    #[serde(with = "crate::broker::wire::rfc3339")]
    deadline: OffsetDateTime,
    minio_provision: LocalInfraMinioFixtureParams,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalInfraMinioFixtureReceipt {
    schema_version: String,
    operation: String,
    request_binding_digest: String,
    bucket: String,
    object_key: String,
    size_bytes: i64,
    payload_sha256: String,
    #[serde(default)]
    seed_binding_digest: String,
    preexisting: bool,
    verified: bool,
    mutated: bool,
    object_present: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalInfraMinioReceipt {
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
    minio_throughput_fixture: LocalInfraMinioFixtureReceipt,
}

/// `decodeMinioThroughputFixtureReceipt` — strict single-object
/// decode plus the full operation-shaped field contract.
fn decode_minio_fixture_receipt(
    raw: &[u8],
    operation_id: &str,
    instance_id: &str,
    operation: MinioFixtureOperation,
    binding: &str,
    now: OffsetDateTime,
) -> Result<MinioFixtureResult, Failure> {
    let invalid = || unavailable("invalid fixture receipt");
    let mut stream = serde_json::Deserializer::from_slice(raw).into_iter::<serde_json::Value>();
    let (Some(Ok(value)), None) = (stream.next(), stream.next()) else {
        return Err(invalid());
    };
    let receipt: LocalInfraMinioReceipt = serde_json::from_value(value).map_err(|_| invalid())?;
    if receipt.schema_version != LOCAL_INFRA_RECEIPT_SCHEMA
        || receipt.mode != "minio-provision"
        || receipt.operation_id != operation_id
        || receipt.instance_id != instance_id
        || receipt.outcome != "completed"
        || receipt.reason != "throughput fixture operation completed"
        || receipt.started_at == crate::broker::wire::go_zero_time()
        || receipt.completed_at < receipt.started_at
        || receipt.completed_at > now + time::Duration::minutes(1)
    {
        return Err(invalid());
    }
    let fixture = receipt.minio_throughput_fixture;
    if fixture.schema_version != MINIO_THROUGHPUT_FIXTURE_SCHEMA
        || fixture.operation != operation.as_str()
        || fixture.request_binding_digest != binding
        || fixture.bucket != BACKUP_MINIO_BUCKET
        || fixture.object_key != MINIO_THROUGHPUT_FIXTURE_KEY
        || fixture.size_bytes != MINIO_THROUGHPUT_FIXTURE_BYTES
        || fixture.payload_sha256 != MINIO_THROUGHPUT_FIXTURE_SHA256
    {
        return Err(invalid());
    }
    let present_state =
        operation == MinioFixtureOperation::Seed || operation == MinioFixtureOperation::Verify;
    if present_state {
        if !fixture.verified
            || !fixture.object_present
            || !valid_throughput_sha256(&fixture.seed_binding_digest)
            || (operation == MinioFixtureOperation::Verify
                && (!fixture.preexisting || fixture.mutated))
            || (operation == MinioFixtureOperation::Seed && fixture.mutated == fixture.preexisting)
        {
            return Err(invalid());
        }
    } else if fixture.object_present
        || fixture.preexisting != fixture.verified
        || fixture.verified != fixture.mutated
        || (fixture.verified && !valid_throughput_sha256(&fixture.seed_binding_digest))
        || (!fixture.verified && !fixture.seed_binding_digest.is_empty())
    {
        return Err(invalid());
    }
    Ok(MinioFixtureResult {
        request_binding_digest: binding.to_owned(),
        seed_binding_digest: fixture.seed_binding_digest,
        object_present: fixture.object_present,
    })
}

/// `minioThroughputFixtureBindingDigest` — schema-prefixed raw-byte
/// digest; deadline deliberately excluded (same SC-DEF-44 reason as
/// the postgres leg: create/verify/delete spans the operation's
/// lifetime).
fn minio_fixture_binding_digest(
    operation_id: &str,
    instance_id: &str,
    operation: MinioFixtureOperation,
    fence: u64,
) -> Result<String, Failure> {
    #[derive(Serialize)]
    struct Canonical<'a> {
        operation_id: &'a str,
        instance_id: &'a str,
        operation: MinioFixtureOperation,
        fence_token: u64,
        bucket: &'a str,
        object_key: &'a str,
        size_bytes: i64,
        payload_sha256: &'a str,
    }
    if operation_id.is_empty() || instance_id.is_empty() || fence == 0 {
        return Err(unavailable("invalid fixture binding"));
    }
    let canonical = serde_json::to_vec(&Canonical {
        operation_id,
        instance_id,
        operation,
        fence_token: fence,
        bucket: BACKUP_MINIO_BUCKET,
        object_key: MINIO_THROUGHPUT_FIXTURE_KEY,
        size_bytes: MINIO_THROUGHPUT_FIXTURE_BYTES,
        payload_sha256: MINIO_THROUGHPUT_FIXTURE_SHA256,
    })
    .map_err(|_| unavailable("invalid fixture binding"))?;
    let mut hasher = Sha256::new();
    hasher.update(MINIO_THROUGHPUT_FIXTURE_REQUEST_DOMAIN.as_bytes());
    hasher.update([0u8]);
    hasher.update(&canonical);
    Ok(format!("sha256:{}", hex_encode(&hasher.finalize())))
}

// ---------------------------------------------------------------------------
// `productionBackupThroughputCleanupCensus` — measures the residual
// resources the fixture provisioners do not own: native supervisor
// process/permit state (the CBL1 `Census`) plus two independent
// checks this process makes directly — open descriptors into the
// backup repository, and unexpected `.tmp` files at its root.
// ---------------------------------------------------------------------------

/// `backupThroughputResidualCleanupCounts`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ResidualCleanupCounts {
    live_probe_processes: u32,
    open_probe_descriptors: u32,
    repository_temporary_files: u32,
    held_permits: u32,
}

/// `backupThroughputCleanupCensus`.
trait CleanupCensus: Send + Sync {
    /// `CensusExcludingRetainedLaunch` — `exclude_fd` is the current
    /// operation's own repository descriptor (SC-DEF-34/35); `None`
    /// when there is none to exclude.
    fn census_excluding_retained_launch(
        &self,
        op_deadline: OpDeadline,
        operation_id: Uuid,
        launch_id: Uuid,
        deadline_wall: OffsetDateTime,
        exclude_fd: Option<BorrowedFd<'_>>,
    ) -> Result<ResidualCleanupCounts, Failure>;
}

pub(crate) struct ProductionBackupThroughputCleanupCensus {
    launcher: Box<dyn BackupProcessLauncher>,
    backup_repository_root: PathBuf,
}

impl ProductionBackupThroughputCleanupCensus {
    /// `newProductionBackupThroughputCleanupCensus`.
    pub(crate) fn new_production(
        composition: &crate::broker::daemon::ProductionInstanceComposition,
        launcher: Box<dyn BackupProcessLauncher>,
    ) -> Result<Self, Failure> {
        if composition.backup_repository_root.is_empty()
            || !composition.backup_repository_root.starts_with('/')
        {
            return Err(unavailable("backup throughput cleanup census unavailable"));
        }
        Ok(Self {
            launcher,
            backup_repository_root: PathBuf::from(&composition.backup_repository_root),
        })
    }
}

impl CleanupCensus for ProductionBackupThroughputCleanupCensus {
    /// A nil launch id means "nothing was ever launched to query"
    /// (SC-DEF-34): the native supervisor census is skipped while the
    /// two independent checks still run.
    fn census_excluding_retained_launch(
        &self,
        op_deadline: OpDeadline,
        operation_id: Uuid,
        launch_id: Uuid,
        deadline_wall: OffsetDateTime,
        exclude_fd: Option<BorrowedFd<'_>>,
    ) -> Result<ResidualCleanupCounts, Failure> {
        let _ = deadline_wall;
        if !is_v7(operation_id) || self.backup_repository_root.as_os_str().is_empty() {
            return Err(unavailable("backup throughput cleanup census unavailable"));
        }
        let mut native = crate::helper::backup::BackupProcessCensus {
            live_processes: 0,
            held_permits: 0,
        };
        if !launch_id.is_nil() {
            native = self
                .launcher
                .census(
                    op_deadline
                        .0
                        .unwrap_or_else(|| Instant::now() + Duration::from_secs(30)),
                    launch_id,
                )
                .map_err(|_| unavailable("backup throughput cleanup census: native"))?;
        }
        let temporary_files = count_repository_temporary_files(&self.backup_repository_root)
            .map_err(|_| unavailable("backup throughput cleanup census: repository"))?;
        let descriptors =
            count_open_repository_descriptors(&self.backup_repository_root, exclude_fd)
                .map_err(|_| unavailable("backup throughput cleanup census: descriptors"))?;
        Ok(ResidualCleanupCounts {
            live_probe_processes: native.live_processes,
            held_permits: native.held_permits,
            repository_temporary_files: temporary_files,
            open_probe_descriptors: descriptors,
        })
    }
}

/// `countRepositoryTemporaryFiles` — top-level entries whose name
/// contains `.tmp` (the repository's own temp-file convention,
/// `.repository-manifest-<nonce>.tmp`). A probe writes nothing
/// persistent, so any match is unexpected residue.
fn count_repository_temporary_files(root: &Path) -> Result<u32, Failure> {
    let mut count = 0u32;
    let entries = std::fs::read_dir(root).map_err(|_| unavailable("repository directory"))?;
    for entry in entries {
        let entry = entry.map_err(|_| unavailable("repository directory"))?;
        if entry.file_name().to_string_lossy().contains(".tmp") {
            count = count.saturating_add(1);
        }
    }
    Ok(count)
}

/// `countOpenRepositoryDescriptors` — this process's own open
/// descriptors whose resolved target falls inside the repository
/// root, excluding `exclude_fd` (SC-DEF-35). A vanished entry is a
/// table race, not residue.
fn count_open_repository_descriptors(
    root: &Path,
    exclude_fd: Option<BorrowedFd<'_>>,
) -> Result<u32, Failure> {
    let root_text = root.to_string_lossy();
    let prefix = format!("{}/", root_text.trim_end_matches('/'));
    let exclude_name = exclude_fd.map(|fd| fd.as_raw_fd().to_string());
    let mut count = 0u32;
    let entries =
        std::fs::read_dir("/proc/self/fd").map_err(|_| unavailable("proc fd enumeration"))?;
    for entry in entries {
        let entry = entry.map_err(|_| unavailable("proc fd enumeration"))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if Some(&name) == exclude_name.as_ref() {
            continue;
        }
        let Ok(target) = std::fs::read_link(entry.path()) else {
            continue;
        };
        let target_text = target.to_string_lossy();
        if target_text == root_text.trim_end_matches('/') || target_text.starts_with(&prefix) {
            count = count.saturating_add(1);
        }
    }
    Ok(count)
}

// ---------------------------------------------------------------------------
// `productionThroughputStaticBindingBuilder` —
// `backup_throughput_binding.go`. Every static receipt identity is
// derived from the immutable composition and the already-open
// repository descriptor; `TargetFingerprint` stays absent — the live
// probe worker supplies it under the exclusion lock.
// ---------------------------------------------------------------------------

const PRODUCTION_PG_DUMP_PATH: &str = "/usr/lib/postgresql/16/bin/pg_dump";
const MAXIMUM_PG_DUMP_TOOL_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Serialize)]
struct ThroughputHostProfile {
    logical_cpus: u32,
    ram_bytes: u64,
}

/// `backupThroughputStaticBindingBuilder`.
trait StaticBindingBuilder: Send + Sync {
    fn build(
        &self,
        op_deadline: OpDeadline,
        descriptor: &BackupRepositoryDescriptor,
        payload_epoch_id: Uuid,
    ) -> Result<BackupThroughputStaticBinding, Failure>;
}

pub(crate) struct ProductionThroughputStaticBindingBuilder {
    composition: crate::broker::daemon::ProductionInstanceComposition,
    receipts: Box<dyn BackupDependencyReceiptSource>,
    pg_dump_path: String,
}

impl ProductionThroughputStaticBindingBuilder {
    /// `newProductionThroughputStaticBindingBuilder`.
    pub(crate) fn new_production(
        composition: &crate::broker::daemon::ProductionInstanceComposition,
    ) -> Result<Self, Failure> {
        let parsed = InstanceId::parse(&composition.instance_id);
        if parsed.is_err()
            || parsed.map(|p| p.to_string()).as_deref() != Ok(composition.instance_id.as_str())
            || composition.authoritative_state_root.is_empty()
            || composition.backup_repository_root.is_empty()
            || composition.dependency_root.is_empty()
        {
            return Err(unavailable(
                "backup throughput binding authority unavailable",
            ));
        }
        Ok(Self {
            composition: composition.clone(),
            receipts: Box::new(CandidateStore::new(
                None,
                composition.dependency_root.clone(),
            )),
            pg_dump_path: PRODUCTION_PG_DUMP_PATH.to_owned(),
        })
    }

    /// `deviceMountSetDigest` — the sorted mount identities of the
    /// postgres/minio data directories plus the repository's own fd.
    fn device_mount_set_digest(
        &self,
        descriptor: &BackupRepositoryDescriptor,
    ) -> Result<String, Failure> {
        let root_fd = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.composition.authoritative_state_root)
            .map_err(|_| unavailable("backup throughput device identity unavailable"))?;
        let mut entries = Vec::with_capacity(3);
        for (role, relative) in [("postgres", "data/postgres"), ("minio", "data/minio")] {
            let fd = rustix::fs::openat2(
                &root_fd,
                relative,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
                rustix::fs::ResolveFlags::BENEATH
                    | rustix::fs::ResolveFlags::NO_SYMLINKS
                    | rustix::fs::ResolveFlags::NO_MAGICLINKS,
            )
            .map_err(|_| unavailable("backup throughput device identity unavailable"))?;
            entries.push(mount_identity_from_fd(role, &fd)?);
        }
        entries.push(mount_identity_from_fd("repository", &descriptor.fd)?);
        entries.sort_by(|a, b| a.role.cmp(&b.role));
        canonical_throughput_digest("central.backup-device-mount-set/v1", &entries)
            .map_err(|_| unavailable("backup throughput device identity unavailable"))
    }
}

/// `throughputMountIdentity` — Go declaration order is the JSON key
/// order.
#[derive(Serialize)]
struct ThroughputMountIdentity {
    role: String,
    device_major: u32,
    device_minor: u32,
    mount_id: u64,
    root_inode: u64,
}

/// `throughputMountIdentityFromFD` — `statx(fd, "", AT_EMPTY_PATH|
/// AT_SYMLINK_NOFOLLOW, TYPE|INO|MNT_ID|BASIC_STATS)`.
fn mount_identity_from_fd<Fd: AsFd>(
    role: &str,
    fd: Fd,
) -> Result<ThroughputMountIdentity, Failure> {
    if role.is_empty() {
        return Err(unavailable("invalid throughput mount"));
    }
    let stat = rustix::fs::statx(
        fd,
        "",
        rustix::fs::AtFlags::EMPTY_PATH | rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        rustix::fs::StatxFlags::TYPE
            | rustix::fs::StatxFlags::INO
            | rustix::fs::StatxFlags::MNT_ID
            | rustix::fs::StatxFlags::BASIC_STATS,
    )
    .map_err(|_| unavailable("invalid throughput mount"))?;
    if !rustix::fs::FileType::from_raw_mode(u32::from(stat.stx_mode)).is_dir()
        || stat.stx_ino == 0
        || stat.stx_mnt_id == 0
    {
        return Err(unavailable("invalid throughput mount"));
    }
    Ok(ThroughputMountIdentity {
        role: role.to_owned(),
        device_major: stat.stx_dev_major,
        device_minor: stat.stx_dev_minor,
        mount_id: stat.stx_mnt_id,
        root_inode: stat.stx_ino,
    })
}

/// `currentThroughputHostProfile` — `unix.Sysinfo` totalram*unit and
/// `runtime.NumCPU` (the affinity-adjusted logical count, identical
/// to `std::thread::available_parallelism`).
fn current_throughput_host_profile() -> Result<ThroughputHostProfile, Failure> {
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(0);
    let mut ram_kb = 0u64;
    if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
        for line in meminfo.lines() {
            if let Some(value) = line.strip_prefix("MemTotal:") {
                ram_kb = value
                    .trim()
                    .trim_end_matches("kB")
                    .trim()
                    .parse()
                    .unwrap_or(0);
                break;
            }
        }
    }
    if cpus == 0 || ram_kb == 0 {
        return Err(unavailable("host profile unavailable"));
    }
    Ok(ThroughputHostProfile {
        logical_cpus: cpus,
        ram_bytes: ram_kb.saturating_mul(1024),
    })
}

/// `hashPinnedPGDumpTool` — root-owned, non-writable regular file,
/// ≤128 MiB; the digest covers the file bytes.
fn hash_pinned_pg_dump_tool(path: &str) -> Result<String, Failure> {
    if path.is_empty() || !path.starts_with('/') {
        return Err(unavailable("tool identity unavailable"));
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| unavailable("tool identity unavailable"))?;
    let stat = file
        .metadata()
        .map_err(|_| unavailable("tool identity unavailable"))?;
    if !stat.file_type().is_file()
        || stat.uid() != 0
        || stat.gid() != 0
        || stat.mode() & 0o022 != 0
        || stat.size() == 0
        || stat.size() > MAXIMUM_PG_DUMP_TOOL_BYTES
    {
        return Err(unavailable("tool identity unavailable"));
    }
    let mut hasher = Sha256::new();
    let mut reader = std::io::BufReader::new(file.take(stat.size() + 1));
    let mut buf = [0u8; 65536];
    let mut written = 0u64;
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|_| unavailable("tool identity unavailable"))?;
        if n == 0 {
            break;
        }
        written += n as u64;
        hasher.update(&buf[..n]);
    }
    if written != stat.size() {
        return Err(unavailable("tool identity unavailable"));
    }
    Ok(format!("sha256:{}", hex_encode(&hasher.finalize())))
}

/// `throughputDependencyDigests` — the provisioning-set identity
/// plus the postgres/minio daemon manifest digests.
fn throughput_dependency_digests(
    receipt: &DependencyReceipt,
) -> Result<(String, String, String), Failure> {
    if receipt.validate_b03().is_err()
        || receipt.id.is_empty()
        || receipt.selector_generation.is_empty()
        || !valid_throughput_sha256(&receipt.manifest_digest)
    {
        return Err(unavailable("dependency receipt unavailable"));
    }
    let mut modes = receipt.dependency_set.modes.clone();
    modes.sort_by(|a, b| a.mode.as_str().cmp(b.mode.as_str()));
    let mut postgres_digest = String::new();
    let mut minio_digest = String::new();
    for mode in &modes {
        match mode.mode {
            ServiceMode::Postgres => postgres_digest = mode.inventory.manifest_digest.clone(),
            ServiceMode::Minio => minio_digest = mode.inventory.manifest_digest.clone(),
            _ => {}
        }
    }
    #[derive(Serialize)]
    struct Canonical<'a> {
        receipt_id: &'a str,
        manifest_digest: &'a str,
        operation_id: &'a str,
        selector_generation: &'a str,
        modes: &'a [central_infra::domain::PreparedMode],
    }
    let digest = canonical_throughput_digest(
        "central.backup-dependency-provisioning/v1",
        &Canonical {
            receipt_id: &receipt.id,
            manifest_digest: &receipt.manifest_digest,
            operation_id: &receipt.operation_id,
            selector_generation: &receipt.selector_generation,
            modes: &modes,
        },
    )
    .map_err(|_| unavailable("dependency receipt unavailable"))?;
    if !valid_throughput_sha256(&postgres_digest) || !valid_throughput_sha256(&minio_digest) {
        return Err(unavailable("dependency receipt unavailable"));
    }
    Ok((digest, postgres_digest, minio_digest))
}

impl StaticBindingBuilder for ProductionThroughputStaticBindingBuilder {
    /// `Build` — SC-DEF-50: `config_digest` is the exact fingerprint
    /// the real backup worker's `AcceptedFacts.ConfigFingerprint`
    /// derives (`sha256(PinnedBackupConfiguration)`), not the
    /// instance composition digest.
    fn build(
        &self,
        op_deadline: OpDeadline,
        descriptor: &BackupRepositoryDescriptor,
        payload_epoch_id: Uuid,
    ) -> Result<BackupThroughputStaticBinding, Failure> {
        if descriptor.binding.verify().is_err()
            || descriptor.binding.instance_id != self.composition.instance_id
            || !is_v7(payload_epoch_id)
        {
            return Err(unavailable(
                "backup throughput binding authority unavailable",
            ));
        }
        let instance_id = Uuid::parse_str(&self.composition.instance_id)
            .map_err(|_| unavailable("backup throughput binding authority unavailable"))?;
        if instance_id.get_version_num() != 7 {
            return Err(unavailable(
                "backup throughput binding authority unavailable",
            ));
        }
        let receipt = self
            .receipts
            .active(op_deadline)
            .map_err(|_| unavailable("backup throughput dependency identity unavailable"))?;
        if receipt.validate_b03().is_err() {
            return Err(unavailable(
                "backup throughput dependency identity unavailable",
            ));
        }
        let (dependency_digest, postgres_digest, minio_digest) =
            throughput_dependency_digests(&receipt)?;
        let device_digest = self.device_mount_set_digest(descriptor)?;
        let host = current_throughput_host_profile()?;
        if host.logical_cpus == 0 || host.ram_bytes == 0 {
            return Err(unavailable("backup throughput host identity unavailable"));
        }
        let host_digest = canonical_throughput_digest("central.backup-host-profile/v1", &host)
            .map_err(|_| unavailable("backup throughput host identity unavailable"))?;
        let tool_digest = hash_pinned_pg_dump_tool(&self.pg_dump_path)
            .map_err(|_| unavailable("backup throughput tool identity unavailable"))?;
        #[derive(Serialize)]
        struct TransferParams {
            dump_archive_minimum_bytes: u64,
            dump_archive_maximum_bytes: u64,
            dump_work_factor: u64,
            object_payload_bytes: u64,
            object_work_factor: u64,
            synchronized_reread: &'static str,
        }
        let transfer_digest = canonical_throughput_digest(
            BACKUP_TRANSFER_ENVELOPE_VERSION,
            &TransferParams {
                dump_archive_minimum_bytes: MINIMUM_DUMP_PROBE_ARCHIVE_BYTES,
                dump_archive_maximum_bytes: MAXIMUM_DUMP_PROBE_ARCHIVE_BYTES,
                dump_work_factor: 2,
                object_payload_bytes: OBJECT_PROBE_PAYLOAD_BYTES,
                object_work_factor: 3,
                synchronized_reread: "full-fdatasync-reread-sha256/v1",
            },
        )
        .map_err(|_| unavailable("backup throughput transfer identity unavailable"))?;
        let config_digest = format!(
            "sha256:{}",
            hex_encode(&Sha256::digest(PINNED_BACKUP_CONFIGURATION.as_bytes()))
        );
        let mut policy_digest = self.composition.backup_policy_digest.clone();
        if !policy_digest.starts_with("sha256:") {
            policy_digest = format!("sha256:{policy_digest}");
        }
        let binding = BackupThroughputStaticBinding {
            instance_id,
            payload_epoch_id,
            repository_binding_id: descriptor.binding.binding_id,
            device_mount_set_digest: device_digest,
            host_profile_digest: host_digest,
            dependency_provisioning_digest: dependency_digest,
            postgres_image_digest: postgres_digest,
            minio_image_digest: minio_digest,
            pg_dump_tool_digest: tool_digest,
            pg_dump_tool_version: "16.14".to_owned(),
            config_digest,
            minio_backup_policy_digest: policy_digest,
            fixture_digest: MINIO_THROUGHPUT_FIXTURE_SHA256.to_owned(),
            transfer_envelope_version: BACKUP_TRANSFER_ENVELOPE_VERSION.to_owned(),
            transfer_envelope_digest: transfer_digest,
        };
        if binding.validate().is_err() {
            return Err(unavailable(
                "backup throughput binding authority unavailable",
            ));
        }
        Ok(binding)
    }
}

// ---------------------------------------------------------------------------
// `productionBackupThroughputGate` — owns the root side of the
// complete C02 probe lifecycle. Its dependencies expose no credential
// strings or disposable database/object locators.
// ---------------------------------------------------------------------------

/// `backupThroughputGateRun` — the mutable attempt state the
/// defer-equivalent cleanup paths consult.
struct GateRun {
    operation_id: Uuid,
    launch_evidence_id: Uuid,
    deadline: OffsetDateTime,
    process_launch_id: Uuid,
    process_launched: bool,
    committed: bool,
    target_locked: bool,
    fixture_loaded: bool,
    worker_reaped: bool,
    retained: bool,
    fixtures_cleaned: bool,
    minio_seed_binding: String,
    target_lock_proof: [u8; 32],
    completion_pending: bool,
    completed: bool,
    released: bool,
}

/// `productionBackupThroughputGate`.
pub(crate) struct ProductionBackupThroughputGate {
    mu: Mutex<()>,
    authority: BackupThroughputAuthority,
    launches: BackupThroughputLaunchIssuer,
    minio_prepare: crate::helper::minio_provision::ProductionBackupMinioPreparer,
    binding: ProductionThroughputStaticBindingBuilder,
    postgres: ProductionPostgresThroughputFixtureProvisioner,
    minio_fixture: ProductionMinioThroughputFixtureManager,
    cleanup_census: ProductionBackupThroughputCleanupCensus,
    launcher: Box<dyn BackupProcessLauncher>,
    now: fn() -> OffsetDateTime,
    poll_interval: Duration,
}

impl ProductionBackupThroughputGate {
    /// `newProductionBackupThroughputGate` — composes all non-Docker
    /// authorities. Like upstream, production stays fail-closed until
    /// the concrete fixture/census roots are supplied; the two-level
    /// constructor keeps test seam parity.
    pub(crate) fn new_production(
        composition: &crate::broker::daemon::ProductionInstanceComposition,
        broker_socket: &Path,
        postgres: ProductionPostgresThroughputFixtureProvisioner,
        minio_fixture: ProductionMinioThroughputFixtureManager,
        cleanup_census: ProductionBackupThroughputCleanupCensus,
    ) -> Result<Self, Failure> {
        let minio_prepare =
            crate::helper::minio_provision::ProductionBackupMinioPreparer::new_production(
                composition,
                broker_socket,
            )?;
        let binding = ProductionThroughputStaticBindingBuilder::new_production(composition)?;
        Ok(Self {
            mu: Mutex::new(()),
            authority: BackupThroughputAuthority::new(broker_socket.to_path_buf()),
            launches: BackupThroughputLaunchIssuer::new(broker_socket.to_path_buf()),
            minio_prepare,
            binding,
            postgres,
            minio_fixture,
            cleanup_census,
            launcher: Box::new(NativeBackupProcessLauncher::new()),
            now: OffsetDateTime::now_utc,
            poll_interval: BACKUP_THROUGHPUT_POLL_INTERVAL,
        })
    }

    /// `newProductionBackupThroughputGateForComposition` — the
    /// full-Docker production root: the concrete PostgreSQL/MinIO
    /// fixture and cleanup-census adapters wired from the same
    /// composition.
    pub(crate) fn new_production_for_composition(
        composition: &crate::broker::daemon::ProductionInstanceComposition,
        broker_socket: &Path,
    ) -> Result<Self, Failure> {
        let postgres = ProductionPostgresThroughputFixtureProvisioner::new_production(composition)?;
        let minio_fixture = ProductionMinioThroughputFixtureManager::new_production(composition)?;
        let launcher: Box<dyn BackupProcessLauncher> = Box::new(NativeBackupProcessLauncher::new());
        let cleanup_census =
            ProductionBackupThroughputCleanupCensus::new_production(composition, launcher)?;
        Self::new_production(
            composition,
            broker_socket,
            postgres,
            minio_fixture,
            cleanup_census,
        )
    }

    /// `waitForLaunchPhase`.
    fn wait_for_launch_phase(
        &self,
        deadline: Instant,
        operation_id: Uuid,
        launch_evidence_id: Uuid,
        phase: &str,
    ) -> Result<BackupThroughputLaunchStatus, Failure> {
        loop {
            if Instant::now() >= deadline {
                return Err(unavailable(
                    "backup throughput launch phase deadline exceeded",
                ));
            }
            let status = self.launches.read_state(operation_id, launch_evidence_id)?;
            if status.phase == phase {
                return Ok(status);
            }
            if phase == BACKUP_THROUGHPUT_TARGET_LOCKED_PHASE
                && status.phase != "issued"
                && status.phase != "active"
            {
                return Err(unavailable(
                    "backup throughput launch advanced out of order",
                ));
            }
            if phase == BACKUP_THROUGHPUT_MEASUREMENT_STAGED_PHASE
                && status.phase != "fixture_loaded"
            {
                return Err(unavailable(
                    "backup throughput launch advanced out of order",
                ));
            }
            std::thread::sleep(self.poll_interval);
        }
    }

    /// `cleanupCompletedRun` — drop the disposable fixtures and
    /// census every residual class; returns the attested counts plus
    /// the all-clean verdict.
    fn cleanup_completed_run(
        &self,
        op_deadline: OpDeadline,
        run: &mut GateRun,
        exclude_fd: BorrowedFd<'_>,
    ) -> (ThroughputCleanupCounts, bool) {
        let postgres = self
            .postgres
            .drop_and_census(op_deadline, run.operation_id, run.deadline);
        let deleted = self.minio_fixture.delete(
            op_deadline,
            run.operation_id,
            backup_minio_fence(run.operation_id),
            run.deadline,
        );
        let residual = self.cleanup_census.census_excluding_retained_launch(
            op_deadline,
            run.operation_id,
            run.process_launch_id,
            run.deadline,
            Some(exclude_fd),
        );
        let (postgres_counts, postgres_ok) = match postgres {
            Ok(c) => (c, true),
            Err(_) => (PostgresFixtureCensus::default(), false),
        };
        let (deleted_result, minio_ok) = match deleted {
            Ok(d) => (d, true),
            Err(_) => (MinioFixtureResult::default(), false),
        };
        let (residual_counts, census_ok) = match residual {
            Ok(c) => (c, true),
            Err(_) => (ResidualCleanupCounts::default(), false),
        };
        let mut counts = ThroughputCleanupCounts {
            live_probe_processes: residual_counts.live_probe_processes,
            open_probe_descriptors: residual_counts.open_probe_descriptors,
            postgres_sessions: postgres_counts.postgres_sessions,
            disposable_databases: postgres_counts.disposable_databases,
            probe_objects: 0,
            repository_temporary_files: residual_counts.repository_temporary_files,
            held_permits: residual_counts.held_permits,
        };
        if deleted_result.object_present {
            counts.probe_objects = 1;
        }
        let zero = counts.live_probe_processes == 0
            && counts.open_probe_descriptors == 0
            && counts.postgres_sessions == 0
            && counts.disposable_databases == 0
            && counts.probe_objects == 0
            && counts.repository_temporary_files == 0
            && counts.held_permits == 0;
        let clean = postgres_ok
            && minio_ok
            && census_ok
            && valid_throughput_sha256(&deleted_result.request_binding_digest)
            && !run.minio_seed_binding.is_empty()
            && deleted_result.seed_binding_digest == run.minio_seed_binding
            && !deleted_result.object_present
            && zero;
        if clean {
            run.fixtures_cleaned = true;
        }
        (counts, clean)
    }

    /// `cleanupFailedRun` — the failure-path counterpart: abort or
    /// release the worker, drop whatever fixtures exist, census, and
    /// report. SC-DEF-46: `delete_proven` requires only a valid
    /// request binding plus `!object_present` — the seed binding can
    /// never be non-empty at this point on a retry after an earlier
    /// attempt already deleted the object.
    fn cleanup_failed_run(
        &self,
        op_deadline: OpDeadline,
        run: &mut GateRun,
        cleanup_deadline: OffsetDateTime,
        exclude_fd: Option<BorrowedFd<'_>>,
    ) -> (ThroughputCleanupCounts, bool) {
        let mut process_clean = true;
        if run.process_launched && !run.released {
            let deadline = op_deadline
                .0
                .unwrap_or_else(|| Instant::now() + BACKUP_THROUGHPUT_CLEANUP_TIMEOUT);
            let result = if run.worker_reaped && run.retained {
                self.launcher
                    .release_and_reap(deadline, run.process_launch_id)
            } else {
                self.launcher.abort(deadline, run.process_launch_id)
            };
            if run.worker_reaped && run.retained {
                run.released = result.is_ok();
            }
            process_clean = result.is_ok();
        }
        let postgres =
            self.postgres
                .drop_and_census(op_deadline, run.operation_id, cleanup_deadline);
        let deleted = self.minio_fixture.delete(
            op_deadline,
            run.operation_id,
            backup_minio_fence(run.operation_id),
            cleanup_deadline,
        );
        let residual = self.cleanup_census.census_excluding_retained_launch(
            op_deadline,
            run.operation_id,
            run.process_launch_id,
            cleanup_deadline,
            exclude_fd,
        );
        let (postgres_counts, postgres_ok) = match postgres {
            Ok(c) => (c, true),
            Err(_) => (PostgresFixtureCensus::default(), false),
        };
        let (deleted_result, minio_ok) = match deleted {
            Ok(d) => (d, true),
            Err(_) => (MinioFixtureResult::default(), false),
        };
        let (residual_counts, census_ok) = match residual {
            Ok(c) => (c, true),
            Err(_) => (ResidualCleanupCounts::default(), false),
        };
        let mut counts = ThroughputCleanupCounts {
            live_probe_processes: residual_counts.live_probe_processes,
            open_probe_descriptors: residual_counts.open_probe_descriptors,
            postgres_sessions: postgres_counts.postgres_sessions,
            disposable_databases: postgres_counts.disposable_databases,
            probe_objects: 0,
            repository_temporary_files: residual_counts.repository_temporary_files,
            held_permits: residual_counts.held_permits,
        };
        if deleted_result.object_present {
            counts.probe_objects = 1;
        }
        let zero = counts.live_probe_processes == 0
            && counts.open_probe_descriptors == 0
            && counts.postgres_sessions == 0
            && counts.disposable_databases == 0
            && counts.probe_objects == 0
            && counts.repository_temporary_files == 0
            && counts.held_permits == 0;
        let delete_proven = valid_throughput_sha256(&deleted_result.request_binding_digest)
            && !deleted_result.object_present;
        (
            counts,
            process_clean && postgres_ok && minio_ok && census_ok && delete_proven && zero,
        )
    }

    /// `reconcileCurrentAttempt` — bring any stale selector state to
    /// a terminal resolution before admitting a fresh probe.
    fn reconcile_current_attempt(
        &self,
        deadline: Instant,
        request_id: Uuid,
        current_descriptor_fd: BorrowedFd<'_>,
    ) -> Result<(), Failure> {
        let current = self
            .authority
            .current(request_id)
            .map_err(|_| unavailable("backup throughput current attempt unavailable"))?;
        if !current.found {
            return Ok(());
        }
        match current.phase.as_str() {
            "failed" => {
                if current.cleanup_resolved_at == crate::broker::wire::go_zero_time()
                    || self
                        .authority
                        .resolve_cleanup(
                            current.operation_id,
                            ThroughputCleanupCounts::default(),
                            current.cleanup_resolved_at,
                        )
                        .is_err()
                {
                    return Err(unavailable(
                        "backup throughput failed selector reconciliation failed",
                    ));
                }
                Ok(())
            }
            "completed" => {
                if current.selector_phase == "completed" {
                    return Ok(());
                }
                if current.expires_at == crate::broker::wire::go_zero_time()
                    || (self.now)() >= current.expires_at
                {
                    return Err(unavailable(
                        "backup throughput unpublished completion expired",
                    ));
                }
                // Replays both an already-published completion and the
                // cutpoint where the completed operation fsync won but
                // its active selector did not.
                if self
                    .authority
                    .activate(current.operation_id, (self.now)())
                    .is_err()
                {
                    return Err(unavailable(
                        "backup throughput completed attempt reconciliation failed",
                    ));
                }
                Ok(())
            }
            "completion_pending" => {
                if current.supervisor_launch_id.is_nil()
                    || current.launch_evidence_id.is_nil()
                    || current.target_lock_proof == [0u8; 32]
                {
                    return Err(unavailable(
                        "backup throughput pending release identity unavailable",
                    ));
                }
                if self
                    .launcher
                    .release_and_reap(deadline, current.supervisor_launch_id)
                    .is_err()
                {
                    return self.reconcile_unclean_attempt(
                        current,
                        true,
                        Some(current_descriptor_fd),
                    );
                }
                if current.expires_at == crate::broker::wire::go_zero_time()
                    || (self.now)() >= current.expires_at
                {
                    if self
                        .authority
                        .mark_failed(
                            current.operation_id,
                            (self.now)(),
                            true,
                            ThroughputCleanupCounts::default(),
                        )
                        .is_err()
                    {
                        return Err(unavailable(
                            "backup throughput expired pending cleanup state unknown",
                        ));
                    }
                    return Err(unavailable("backup throughput pending completion expired"));
                }
                if self
                    .authority
                    .activate(current.operation_id, (self.now)())
                    .is_err()
                {
                    return Err(unavailable("backup throughput pending activation failed"));
                }
                Ok(())
            }
            "accepted" | "measurement_pending" => {
                self.reconcile_unclean_attempt(current, false, Some(current_descriptor_fd))
            }
            "cleanup_required" => {
                self.reconcile_cleanup_required(current, Some(current_descriptor_fd))
            }
            _ => Err(unavailable("backup throughput current phase unavailable")),
        }
    }

    /// `reconcileUncleanAttempt`.
    fn reconcile_unclean_attempt(
        &self,
        current: BackupThroughputAttemptStatus,
        force_cleanup_required: bool,
        current_descriptor_fd: Option<BorrowedFd<'_>>,
    ) -> Result<(), Failure> {
        let cleanup_deadline = (self.now)() + BACKUP_THROUGHPUT_CLEANUP_TIMEOUT;
        let cleanup_instant = Instant::now() + BACKUP_THROUGHPUT_CLEANUP_TIMEOUT;
        let mut run = GateRun {
            operation_id: current.operation_id,
            launch_evidence_id: current.launch_evidence_id,
            deadline: current.deadline,
            process_launch_id: current.supervisor_launch_id,
            process_launched: !current.supervisor_launch_id.is_nil(),
            committed: false,
            target_locked: false,
            fixture_loaded: false,
            worker_reaped: false,
            retained: false,
            fixtures_cleaned: current.cleanup_attested,
            minio_seed_binding: current.minio_seed_binding.clone(),
            target_lock_proof: [0u8; 32],
            completion_pending: false,
            completed: false,
            released: false,
        };
        let (counts, clean) = self.cleanup_failed_run(
            OpDeadline(Some(cleanup_instant)),
            &mut run,
            cleanup_deadline,
            current_descriptor_fd,
        );
        let cleanup_required = force_cleanup_required || !clean;
        if self
            .authority
            .mark_failed(current.operation_id, (self.now)(), cleanup_required, counts)
            .is_err()
        {
            return Err(unavailable(
                "backup throughput stale attempt terminal state unknown",
            ));
        }
        if cleanup_required {
            return Err(unavailable(
                "backup throughput stale attempt requires cleanup",
            ));
        }
        Ok(())
    }

    /// `reconcileCleanupRequired`.
    fn reconcile_cleanup_required(
        &self,
        current: BackupThroughputAttemptStatus,
        current_descriptor_fd: Option<BorrowedFd<'_>>,
    ) -> Result<(), Failure> {
        let cleanup_deadline = (self.now)() + BACKUP_THROUGHPUT_CLEANUP_TIMEOUT;
        let cleanup_instant = Instant::now() + BACKUP_THROUGHPUT_CLEANUP_TIMEOUT;
        let mut run = GateRun {
            operation_id: current.operation_id,
            launch_evidence_id: current.launch_evidence_id,
            deadline: current.deadline,
            process_launch_id: current.supervisor_launch_id,
            process_launched: !current.supervisor_launch_id.is_nil(),
            committed: false,
            target_locked: false,
            fixture_loaded: false,
            worker_reaped: false,
            retained: false,
            fixtures_cleaned: current.cleanup_attested,
            minio_seed_binding: current.minio_seed_binding.clone(),
            target_lock_proof: [0u8; 32],
            completion_pending: false,
            completed: false,
            released: false,
        };
        let (counts, clean) = self.cleanup_failed_run(
            OpDeadline(Some(cleanup_instant)),
            &mut run,
            cleanup_deadline,
            current_descriptor_fd,
        );
        if !clean {
            return Err(unavailable("backup throughput cleanup remains unresolved"));
        }
        if self
            .authority
            .resolve_cleanup(current.operation_id, counts, (self.now)())
            .is_err()
        {
            return Err(unavailable("backup throughput cleanup resolution unknown"));
        }
        Ok(())
    }
}

impl BackupThroughputGate for ProductionBackupThroughputGate {
    /// `RequireBackupThroughput`.
    fn require_backup_throughput(
        &self,
        deadline: Instant,
        normal_operation_id: Uuid,
        descriptor: &BackupRepositoryDescriptor,
    ) -> Result<(), Failure> {
        if !is_v7(normal_operation_id)
            || descriptor.binding.verify().is_err()
            || descriptor.binding.owner_uid != CENTRAL_RUNTIME_UID
            || descriptor.binding.owner_gid != CENTRAL_RUNTIME_GID
            || self.poll_interval.is_zero()
        {
            return Err(unavailable("backup throughput gate unavailable"));
        }
        if Instant::now() >= deadline {
            return Err(unavailable("backup throughput gate unavailable"));
        }
        let _guard = self
            .mu
            .lock()
            .map_err(|_| unavailable("backup throughput gate unavailable"))?;
        self.reconcile_current_attempt(deadline, normal_operation_id, descriptor.fd.as_fd())?;

        let probe_operation_id = Uuid::now_v7();
        if !is_v7(probe_operation_id) || probe_operation_id == normal_operation_id {
            return Err(unavailable(
                "backup throughput operation identity unavailable",
            ));
        }
        let accepted_at = (self.now)();
        if accepted_at == crate::broker::wire::go_zero_time() {
            return Err(unavailable("backup throughput clock unavailable"));
        }
        let deadline_wall = accepted_at + MAXIMUM_THROUGHPUT_PROBE_ELAPSED;
        let probe_instant = Instant::now()
            + MAXIMUM_THROUGHPUT_PROBE_ELAPSED
                .unsigned_abs()
                .min(Duration::from_secs(3600));
        let op_deadline = OpDeadline(Some(probe_instant));
        if self
            .authority
            .accept(probe_operation_id, accepted_at, deadline_wall)
            .is_err()
        {
            return Err(unavailable("backup throughput acceptance denied"));
        }

        let mut run = GateRun {
            operation_id: probe_operation_id,
            launch_evidence_id: Uuid::nil(),
            deadline: deadline_wall,
            process_launch_id: Uuid::nil(),
            process_launched: false,
            committed: false,
            target_locked: false,
            fixture_loaded: false,
            worker_reaped: false,
            retained: false,
            fixtures_cleaned: false,
            minio_seed_binding: String::new(),
            target_lock_proof: [0u8; 32],
            completion_pending: false,
            completed: false,
            released: false,
        };

        // The body runs under `catch_unwind`-free explicit error
        // plumbing: `attempt` returns the result, the outer block
        // performs upstream's deferred cleanup/mark-failed exactly.
        let attempt = self.require_probe_body(
            op_deadline,
            probe_instant,
            probe_operation_id,
            accepted_at,
            deadline_wall,
            descriptor,
            &mut run,
        );

        if run.completed {
            if run.process_launched && !run.released {
                let cleanup_instant = Instant::now() + BACKUP_THROUGHPUT_CLEANUP_TIMEOUT;
                if self
                    .launcher
                    .release_and_reap(cleanup_instant, run.process_launch_id)
                    .is_err()
                {
                    return Err(unavailable("backup throughput target lock release unknown"));
                }
                run.released = true;
            }
            return attempt;
        }
        let cleanup_deadline = (self.now)() + BACKUP_THROUGHPUT_CLEANUP_TIMEOUT;
        let cleanup_instant = Instant::now() + BACKUP_THROUGHPUT_CLEANUP_TIMEOUT;
        let (counts, clean) = self.cleanup_failed_run(
            OpDeadline(Some(cleanup_instant)),
            &mut run,
            cleanup_deadline,
            Some(descriptor.fd.as_fd()),
        );
        if self
            .authority
            .mark_failed(
                run.operation_id,
                (self.now)(),
                !clean || run.completion_pending,
                counts,
            )
            .is_err()
        {
            return Err(unavailable("backup throughput terminal state unknown"));
        }
        attempt
    }
}

impl ProductionBackupThroughputGate {
    /// The `RequireBackupThroughput` body between `Accept` and
    /// `Activate` — separated so the outer method can run upstream's
    /// deferred cleanup/mark-failed block verbatim.
    #[allow(clippy::too_many_arguments)]
    fn require_probe_body(
        &self,
        op_deadline: OpDeadline,
        probe_instant: Instant,
        probe_operation_id: Uuid,
        accepted_at: OffsetDateTime,
        deadline_wall: OffsetDateTime,
        descriptor: &BackupRepositoryDescriptor,
        run: &mut GateRun,
    ) -> Result<(), Failure> {
        let payload_epoch_id = self
            .minio_prepare
            .prepare_backup_throughput_minio(probe_instant, probe_operation_id, deadline_wall)
            .map_err(|_| unavailable("backup throughput MinIO preparation failed"))?;
        if !is_v7(payload_epoch_id) {
            return Err(unavailable("backup throughput MinIO preparation failed"));
        }
        let static_binding = self
            .binding
            .build(op_deadline, descriptor, payload_epoch_id)
            .map_err(|_| unavailable("backup throughput binding unavailable"))?;
        if static_binding.validate().is_err()
            || static_binding.payload_epoch_id != payload_epoch_id
            || static_binding.repository_binding_id != descriptor.binding.binding_id
        {
            return Err(unavailable("backup throughput binding unavailable"));
        }
        const THROUGHPUT_ENV: &[&str] =
            &["PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"];
        let process = self
            .launcher
            .launch(&BackupProcessSpec {
                executable: "/usr/lib/central/central-backup",
                mode: BackupProcessMode::ThroughputProbe,
                operation_id: probe_operation_id,
                repository_fd: descriptor.fd.as_fd(),
                uid: CENTRAL_RUNTIME_UID,
                gid: CENTRAL_RUNTIME_GID,
                deadline: deadline_wall,
                env: THROUGHPUT_ENV,
            })
            .map_err(|_| unavailable("backup throughput worker launch failed"))?;
        run.process_launch_id = process.launch_id;
        run.process_launched = true;
        if process.launch_id.is_nil()
            || process.pid <= 0
            || process.process_start.is_empty()
            || process.executable != "/usr/lib/central/central-backup"
        {
            return Err(unavailable("backup throughput worker identity unavailable"));
        }
        let launch = self
            .launches
            .issue(&BackupThroughputLaunchEvidence {
                supervisor_launch_id: process.launch_id,
                operation_id: probe_operation_id,
                pid: process.pid,
                process_start: process.process_start.clone(),
                executable: process.executable.clone(),
                mode: BackupProcessMode::ThroughputProbe.as_str().to_owned(),
                repository_binding: crate::broker::backup_launch::binding_to_wire(
                    &descriptor.binding,
                ),
                static_binding,
                deadline: deadline_wall,
            })
            .map_err(|_| unavailable("backup throughput launch evidence failed"))?;
        if launch.launch_evidence_id.is_nil()
            || launch.operation_id != probe_operation_id
            || launch.deadline != deadline_wall.to_offset(time::UtcOffset::UTC)
        {
            return Err(unavailable("backup throughput launch evidence failed"));
        }
        run.launch_evidence_id = launch.launch_evidence_id;
        if self
            .launcher
            .commit(probe_instant, process.launch_id, launch.launch_evidence_id)
            .is_err()
        {
            return Err(unavailable("backup throughput launch commit failed"));
        }
        run.committed = true;
        let locked = self
            .wait_for_launch_phase(
                probe_instant,
                probe_operation_id,
                launch.launch_evidence_id,
                BACKUP_THROUGHPUT_TARGET_LOCKED_PHASE,
            )
            .map_err(|_| unavailable("backup throughput target lock unavailable"))?;
        if locked.target_lock_proof_sha256 == [0u8; 32]
            || locked.target_fingerprint.is_empty()
            || locked.target_locked_at == crate::broker::wire::go_zero_time()
        {
            return Err(unavailable("backup throughput target lock unavailable"));
        }
        run.target_lock_proof = locked.target_lock_proof_sha256;
        run.target_locked = true;

        let loaded = self
            .postgres
            .create_and_load(op_deadline, probe_operation_id, deadline_wall);
        let loaded_at = (self.now)();
        let loaded = match loaded {
            Ok(l) => l,
            Err(_) => {
                return Err(unavailable(
                    "backup throughput PostgreSQL fixture load failed",
                ));
            }
        };
        if loaded.fixture_load_elapsed <= time::Duration::ZERO
            || loaded_at < locked.target_locked_at
            || loaded_at >= deadline_wall
            || loaded.fixture_load_elapsed > loaded_at - accepted_at
            || !valid_throughput_sha256(&loaded.provision_receipt_binding)
        {
            return Err(unavailable(
                "backup throughput PostgreSQL fixture load failed",
            ));
        }
        if self
            .postgres
            .verify(
                op_deadline,
                probe_operation_id,
                &loaded.provision_receipt_binding,
                deadline_wall,
            )
            .is_err()
        {
            return Err(unavailable(
                "backup throughput PostgreSQL fixture verification failed",
            ));
        }
        let fence = backup_minio_fence(probe_operation_id);
        let seed = self
            .minio_fixture
            .seed(op_deadline, probe_operation_id, fence, deadline_wall)
            .map_err(|_| unavailable("backup throughput MinIO fixture seed failed"))?;
        if !seed.object_present
            || !valid_throughput_sha256(&seed.request_binding_digest)
            || !valid_throughput_sha256(&seed.seed_binding_digest)
        {
            return Err(unavailable("backup throughput MinIO fixture seed failed"));
        }
        run.minio_seed_binding = seed.seed_binding_digest.clone();
        let verified = self
            .minio_fixture
            .verify(op_deadline, probe_operation_id, fence, deadline_wall)
            .map_err(|_| unavailable("backup throughput MinIO fixture verification failed"))?;
        if !verified.object_present
            || verified.seed_binding_digest != seed.seed_binding_digest
            || !valid_throughput_sha256(&verified.request_binding_digest)
        {
            return Err(unavailable(
                "backup throughput MinIO fixture verification failed",
            ));
        }
        #[derive(Serialize)]
        struct ProvisionReceipt {
            postgres_receipt_binding: String,
            minio_seed_binding: String,
        }
        let provision_binding = canonical_throughput_digest(
            BACKUP_THROUGHPUT_PROVISION_RECEIPT_SCHEMA,
            &ProvisionReceipt {
                postgres_receipt_binding: loaded.provision_receipt_binding,
                minio_seed_binding: verified.seed_binding_digest.clone(),
            },
        )
        .map_err(|_| unavailable("backup throughput provision receipt unavailable"))?;
        let attestation = BackupThroughputFixtureLoadAttestation {
            fixture_load_elapsed: loaded.fixture_load_elapsed,
            provision_receipt_binding: provision_binding,
            minio_seed_binding: seed.seed_binding_digest,
            loaded_at,
        };
        if self
            .launches
            .mark_fixture_loaded(probe_operation_id, launch.launch_evidence_id, &attestation)
            .is_err()
        {
            return Err(unavailable("backup throughput fixture admission failed"));
        }
        run.fixture_loaded = true;

        let outcome = self
            .launcher
            .wait_and_reap(probe_instant, process.launch_id)
            .map_err(|_| unavailable("backup throughput worker failed"))?;
        if !outcome.succeeded
            || outcome.target_lock_proof == [0u8; 32]
            || outcome.target_lock_proof != locked.target_lock_proof_sha256
        {
            return Err(unavailable("backup throughput worker failed"));
        }
        run.worker_reaped = true;
        run.target_lock_proof = outcome.target_lock_proof;
        let retained = self
            .launcher
            .assert_target_lock_retained(probe_instant, process.launch_id)
            .map_err(|_| unavailable("backup throughput target lock retention lost"))?;
        if retained == [0u8; 32] || retained != locked.target_lock_proof_sha256 {
            return Err(unavailable("backup throughput target lock retention lost"));
        }
        run.retained = true;
        if self
            .wait_for_launch_phase(
                probe_instant,
                probe_operation_id,
                launch.launch_evidence_id,
                BACKUP_THROUGHPUT_MEASUREMENT_STAGED_PHASE,
            )
            .is_err()
        {
            return Err(unavailable("backup throughput measurement staging failed"));
        }

        let (counts, clean) = self.cleanup_completed_run(op_deadline, run, descriptor.fd.as_fd());
        if !clean
            || counts.live_probe_processes != 0
            || counts.open_probe_descriptors != 0
            || counts.postgres_sessions != 0
            || counts.disposable_databases != 0
            || counts.probe_objects != 0
            || counts.repository_temporary_files != 0
            || counts.held_permits != 0
        {
            return Err(unavailable("backup throughput cleanup verification failed"));
        }
        let attested_at = (self.now)();
        let parent_elapsed = attested_at - accepted_at;
        if attested_at >= deadline_wall
            || parent_elapsed <= time::Duration::ZERO
            || parent_elapsed > MAXIMUM_THROUGHPUT_PROBE_ELAPSED
        {
            return Err(unavailable(
                "backup throughput completion deadline exceeded",
            ));
        }
        run.completion_pending = true;
        let mut pending_err: Result<(), Failure> = Err(unavailable("unreached"));
        for _ in 0..2 {
            pending_err = self.authority.complete_pending(
                probe_operation_id,
                launch.launch_evidence_id,
                retained,
                true,
                counts,
                parent_elapsed,
                attested_at,
            );
            if pending_err.is_ok() || Instant::now() >= probe_instant {
                break;
            }
        }
        if pending_err.is_err() {
            return Err(unavailable(
                "backup throughput evidence completion pending failed",
            ));
        }
        if self
            .launcher
            .release_and_reap(probe_instant, process.launch_id)
            .is_err()
        {
            return Err(unavailable("backup throughput target lock release unknown"));
        }
        run.released = true;
        let activated_at = (self.now)();
        let mut evidence: Option<ThroughputEvidence> = None;
        let mut activate_err: Result<(), Failure> = Ok(());
        for _ in 0..2 {
            match self.authority.activate(probe_operation_id, activated_at) {
                Ok(e) => {
                    evidence = Some(e);
                    activate_err = Ok(());
                    break;
                }
                Err(e) => {
                    activate_err = Err(e);
                    if Instant::now() >= probe_instant {
                        break;
                    }
                }
            }
        }
        let evidence = match (activate_err, evidence) {
            (Ok(()), Some(e)) => e,
            _ => return Err(unavailable("backup throughput evidence activation failed")),
        };
        if evidence.probe_operation_id != probe_operation_id
            || evidence.receipt_id.is_nil()
            || evidence.cleanup_state
                != central_backup::recovery::profile::BACKUP_THROUGHPUT_CLEANUP_CLEAN
        {
            return Err(unavailable("backup throughput evidence activation failed"));
        }
        run.completed = true;
        Ok(())
    }
}
