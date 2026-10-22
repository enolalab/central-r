//! Native PostgreSQL migration engine — port of
//! `internal/adapter/postgres/migrate/`.
//!
//! The module replays the compile-time-embedded, trusted static SQL corpus
//! ([`manifest::MIGRATIONS`]) verbatim through `sqlx::raw_sql`, preserving
//! every file's own `begin`/`commit`/`SET LOCAL` transaction boundaries and
//! its durable dirty-intent → DDL → clean-marker ledger protocol. There is
//! no `sqlx::migrate!` and no `_sqlx_migrations` table.
//!
//! The migration-domain types below are owned locally by this adapter for
//! now — they mirror `internal/backup/migration.go` and
//! `internal/backup/port/migration_port.go` field-for-field so a later
//! task can lift them into a shared port crate without a semantic change.

pub mod baseline;
pub mod grants;
pub mod inspector;
pub mod manifest;
pub mod reset_runner;
pub mod runner;
mod shape_spec;
pub mod verify_shape;

pub use baseline::BaselineInstaller;
pub use grants::reapply_runtime_grants;
pub use inspector::Inspector;
pub use manifest::{
    B10_FORWARD_CORRECTION_CHECKSUM, B10_FORWARD_CORRECTION_VERSION, LATEST_VERSION, MIGRATIONS,
    MigrationEntry, REAPPLY_RUNTIME_GRANTS_SQL, WITH_V15_CHAIN, WITHOUT_V15_CHAIN,
};
pub use reset_runner::ResetRunner;
pub use runner::Runner;

use central_foundation::failure::Failure;

/// Result alias for all adapter entry points: a sanitized
/// [`central_foundation::failure::Failure`], never a raw `sqlx` error.
pub type Result<T> = core::result::Result<T, Failure>;

/// Canonical advisory-lock acquisition order (upstream
/// `backup.CanonicalLockOrder`). Sessions take `pg_advisory_lock` in this
/// order and release in reverse.
pub const CANONICAL_LOCK_ORDER: [&str; 3] = ["lock-common", "lock-opstate", "lock-migration"];

/// The sole B05 workspace used by the local bootstrap and the session
/// capability (upstream `migrate.SentinelWorkspaceID`). Fixed UUIDv7 —
/// never the nil UUID — so `WorkspaceID::is_zero`'s "never set" invariant
/// cannot alias the one real workspace.
pub const SENTINEL_WORKSPACE_ID: &str = "019fdc8d-e33a-76ed-9ef0-a0d9fe92e54a";

/// A one-PostgreSQL-session binding: backend PID, postmaster start time,
/// and a boot identity (cluster name, or the postmaster start as the local
/// boot identity on stock clusters). Ports `backup.SessionBinding`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionBinding {
    /// `pg_backend_pid()` — differs across reconnects; excluded from
    /// [`SessionBinding::same_instance`].
    pub backend_pid: i32,
    /// `pg_postmaster_start_time()` text — the instance start identity.
    pub backend_start: String,
    /// `cluster_name` setting, or `"postmaster:<start>"` when unset.
    pub boot_id: String,
    /// The three canonical lock identities, in [`CANONICAL_LOCK_ORDER`].
    pub lock_identities: Vec<String>,
}

impl SessionBinding {
    /// Ports `backup.SameInstance`: same postmaster start and same boot ID;
    /// `BackendPID` is intentionally excluded. A zero `expected` value skips
    /// the check (returns `true`).
    #[must_use]
    pub fn same_instance(&self, expected: &Self) -> bool {
        if expected.backend_start.is_empty() && expected.boot_id.is_empty() {
            return true;
        }
        self.backend_start == expected.backend_start && self.boot_id == expected.boot_id
    }

    /// Ports `completeSessionBinding`: nonzero PID, populated start/boot,
    /// and the canonical lock identity set.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.backend_pid > 0
            && !self.backend_start.is_empty()
            && !self.boot_id.is_empty()
            && self.lock_identities
                == CANONICAL_LOCK_ORDER
                    .iter()
                    .map(|s| (*s).to_owned())
                    .collect::<Vec<_>>()
    }
}

/// Stable PostgreSQL target identity bound at every authorization fence.
/// Ports `backup.TargetIdentity`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TargetIdentity {
    /// PostgreSQL system identifier.
    pub system_id: String,
    /// `pg_database.oid` for `current_database()`.
    pub database_oid: String,
    /// Database name.
    pub database: String,
    /// Content-addressed config binding.
    pub config_hash: String,
    /// Target epoch.
    pub epoch: u64,
}

impl TargetIdentity {
    /// The complete stable binding required at a mutation fence.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.system_id.is_empty()
            && !self.database_oid.is_empty()
            && !self.database.is_empty()
            && !self.config_hash.is_empty()
    }
}

/// One-use broker-signed proof that a target is empty (expires 60 s after
/// issuance upstream). Ports `backup.VerifiedEmptyTarget`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEmptyTarget {
    /// Operation the proof binds to.
    pub operation_id: uuid::Uuid,
    /// Session binding the proof was issued under.
    pub session_binding: SessionBinding,
    /// SHA-256 of target identity + empty state.
    pub empty_fingerprint: String,
    /// Baseline digest the proof binds.
    pub baseline_digest: String,
    /// Issuance time.
    pub issued_at: time::OffsetDateTime,
    /// Expiry time.
    pub expires_at: time::OffsetDateTime,
    /// Broker signature (one use).
    pub hmac: String,
}

/// Broker reset confirmation for the destructive version-zero reset.
/// Ports `backup.ResetConfirmation`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResetConfirmation {
    /// Operation the confirmation binds to.
    pub operation_id: uuid::Uuid,
    /// Target fingerprint binding.
    pub target_fingerprint: String,
    /// Broker nonce.
    pub nonce: Vec<u8>,
    /// Expiry time.
    pub expires_at: time::OffsetDateTime,
    /// Broker signature.
    pub hmac: String,
}

/// Broker proof service — the authorization boundary between the migration
/// runner/reset runner and the broker that signs one-use proofs. Ports
/// `port.BrokerProofService`. `#[trait_variant::make(Send)]` per the task
/// brief; upstream ships no in-crate implementation, so this adapter only
/// defines the contract (tests use fakes exactly as upstream does).
#[trait_variant::make(Send)]
pub trait BrokerProofService {
    /// Issue an empty-target proof for `req`.
    async fn issue_empty_target_proof(
        &self,
        req: IssueEmptyTargetProofRequest,
    ) -> Result<VerifiedEmptyTarget>;
    /// Verify (without consuming) `proof` against `target`.
    async fn verify_empty_target(
        &self,
        target: &TargetIdentity,
        proof: &VerifiedEmptyTarget,
    ) -> Result<()>;
    /// Consume `proof` once.
    async fn consume_empty_proof(&self, proof: VerifiedEmptyTarget) -> Result<()>;
    /// Verify and consume `proof` against `target` in one step.
    async fn consume_verified_empty_target(
        &self,
        target: &TargetIdentity,
        proof: VerifiedEmptyTarget,
    ) -> Result<()>;
    /// Issue a reset confirmation for `req`.
    async fn issue_reset_confirmation(
        &self,
        req: IssueResetConfirmationRequest,
    ) -> Result<ResetConfirmation>;
    /// Verify (without consuming) `confirmation`.
    async fn verify_reset_confirmation(&self, confirmation: &ResetConfirmation) -> Result<()>;
    /// Consume `confirmation` once.
    async fn consume_reset_confirmation(&self, confirmation: ResetConfirmation) -> Result<()>;
    /// Verify and consume `confirmation` against `target` in one step.
    async fn consume_verified_reset_confirmation(
        &self,
        target: &TargetIdentity,
        confirmation: ResetConfirmation,
    ) -> Result<()>;
}

pub(crate) type BoxFuture<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Object-safe erase of [`BrokerProofService`] for the runners' stored
/// `Arc<dyn …>` — `#[trait_variant::make(Send)]` keeps async methods as
/// return-position `impl Future`, which cannot build a vtable. Runners
/// only consume proofs, so the erased surface is exactly the two
/// consume-verified calls.
pub(crate) trait DynProofService: Send + Sync {
    /// Verify + consume `proof` once against `target`.
    fn consume_verified_empty_target<'a>(
        &'a self,
        target: &'a TargetIdentity,
        proof: VerifiedEmptyTarget,
    ) -> BoxFuture<'a, Result<()>>;
    /// Verify + consume `confirmation` once against `target`.
    fn consume_verified_reset_confirmation<'a>(
        &'a self,
        target: &'a TargetIdentity,
        confirmation: ResetConfirmation,
    ) -> BoxFuture<'a, Result<()>>;
}

impl<T: BrokerProofService + Send + Sync> DynProofService for T {
    fn consume_verified_empty_target<'a>(
        &'a self,
        target: &'a TargetIdentity,
        proof: VerifiedEmptyTarget,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(BrokerProofService::consume_verified_empty_target(
            self, target, proof,
        ))
    }
    fn consume_verified_reset_confirmation<'a>(
        &'a self,
        target: &'a TargetIdentity,
        confirmation: ResetConfirmation,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(BrokerProofService::consume_verified_reset_confirmation(
            self,
            target,
            confirmation,
        ))
    }
}

/// `port.UpRequest`.
#[derive(Debug, Clone)]
pub struct UpRequest {
    /// Operation identity.
    pub operation_id: uuid::Uuid,
    /// Target the proof binds to.
    pub target: TargetIdentity,
    /// SHA-256 of the checksum manifest.
    pub embedded_baseline_digest: String,
    /// Broker-issued empty-target proof.
    pub proof: VerifiedEmptyTarget,
}

/// `port.PrepareUpRequest`.
#[derive(Debug, Clone)]
pub struct PrepareUpRequest {
    /// Operation identity.
    pub operation_id: uuid::Uuid,
    /// Target identity.
    pub target: TargetIdentity,
}

/// `port.PrepareUpResult`.
#[derive(Debug, Clone)]
pub struct PrepareUpResult {
    /// Operation identity.
    pub operation_id: uuid::Uuid,
    /// Captured session binding for the commit phase.
    pub session_binding: SessionBinding,
}

/// `port.CommitUpRequest`.
#[derive(Debug, Clone)]
pub struct CommitUpRequest {
    /// Operation identity.
    pub operation_id: uuid::Uuid,
    /// Target identity.
    pub target: TargetIdentity,
    /// Binding captured by `prepare_up`.
    pub session_binding: SessionBinding,
    /// Broker-issued empty-target proof.
    pub proof: VerifiedEmptyTarget,
}

/// `port.UpResult`.
#[derive(Debug, Clone)]
pub struct UpResult {
    /// Operation identity.
    pub operation_id: uuid::Uuid,
    /// External record state after commit.
    pub record_state: ExternalRecordState,
    /// Session binding the mutation ran under.
    pub session_binding: SessionBinding,
}

/// `port.ResumeRequest`.
#[derive(Debug, Clone)]
pub struct ResumeRequest {
    /// Operation identity.
    pub operation_id: uuid::Uuid,
    /// Target identity.
    pub target: TargetIdentity,
    /// Binding recorded when the operation started.
    pub expected_session_binding: SessionBinding,
    /// Binding captured for a fresh install leg.
    pub session_binding: SessionBinding,
    /// Broker proof (required only on the fresh-install leg).
    pub proof: VerifiedEmptyTarget,
}

/// `port.ResumeResult`.
#[derive(Debug, Clone)]
pub struct ResumeResult {
    /// Operation identity.
    pub operation_id: uuid::Uuid,
    /// External record state after resume.
    pub record_state: ExternalRecordState,
    /// Terminal provisioning phase.
    pub final_phase: ProvisioningPhase,
}

/// `port.ResetRequest`.
#[derive(Debug, Clone)]
pub struct ResetRequest {
    /// Target identity.
    pub target: TargetIdentity,
    /// Broker reset confirmation.
    pub confirmation: ResetConfirmation,
}

/// `port.IssueEmptyTargetProofRequest`.
#[derive(Debug, Clone)]
pub struct IssueEmptyTargetProofRequest {
    /// Operation identity.
    pub operation_id: uuid::Uuid,
    /// Target identity.
    pub target: TargetIdentity,
    /// Session binding to bind the proof to.
    pub session_binding: SessionBinding,
    /// Baseline digest to bind.
    pub baseline_digest: String,
}

/// `port.IssueResetConfirmationRequest`.
#[derive(Debug, Clone)]
pub struct IssueResetConfirmationRequest {
    /// Operation identity.
    pub operation_id: uuid::Uuid,
    /// Target fingerprint to bind.
    pub target_fingerprint: String,
}

/// `backup.ExternalRecordState` — only the ready state the migration
/// runner produces is modeled here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalRecordState {
    /// `backup.ExternalRecordReady`.
    Ready,
}

/// `backup.ProvisioningPhase` — the terminal phase reported by `resume`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisioningPhase {
    /// `backup.ProvisioningCandidateActive`.
    CandidateActive,
}

/// `port.VersionChecksum` — one `schema_migrations` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionChecksum {
    /// Migration version.
    pub version: i32,
    /// Ledger checksum.
    pub checksum: String,
}

/// `port.DirtyEvidence` — a dirty migration record.
#[derive(Debug, Clone)]
pub struct DirtyEvidence {
    /// Dirty version.
    pub version: i32,
    /// Reason text (the dirty record's checksum).
    pub reason: String,
    /// Detection time.
    pub detected_at: time::OffsetDateTime,
}

/// `port.EpochMarker`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EpochMarker {
    /// Epoch number.
    pub epoch: u64,
    /// Epoch digest.
    pub digest: String,
}

/// `port.EpochMarkers`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EpochMarkers {
    /// Migration (restore) epoch.
    pub migration: EpochMarker,
    /// Security epoch.
    pub security: EpochMarker,
}

/// `port.PostgresMigrationFacts` — the inspector's read-only findings.
#[derive(Debug, Clone)]
pub struct PostgresMigrationFacts {
    /// `central` schema exists and carries applied versions.
    pub initialized: bool,
    /// Applied `(version, checksum)` rows in version order.
    pub applied_versions: Vec<VersionChecksum>,
    /// Dirty evidence, when a dirty record exists.
    pub dirty: Option<DirtyEvidence>,
    /// Latest epoch markers.
    pub epochs: EpochMarkers,
}

/// Read-only facts behind the version-zero reset gate
/// (`backup.VersionZeroEligibility`-equivalent facts the reset runner
/// exposes to the broker).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionZeroEligibility {
    /// The `central` schema exists.
    pub installed: bool,
    /// Any `schema_migrations` ownership records exist.
    pub has_schema_ownership: bool,
    /// Records are exactly the clean `baseline-zero` v0 row.
    pub clean_version_zero_only: bool,
}

/// `backup.BaselineManifest` — the installer asserts the latest applied
/// version and every known checksum so checksum drift reads as repair
/// required. `checksums` maps each ledger checksum to itself, as upstream.
#[derive(Debug, Clone)]
pub struct BaselineManifest {
    /// Latest applied migration version (37).
    pub version: i32,
    /// `checksum → checksum` for all known ledger checksums.
    pub checksums: std::collections::BTreeMap<String, String>,
}

impl BaselineManifest {
    /// Content digest of the manifest (upstream `BaselineManifest.Digest`):
    /// sha256 over `version:N` + sorted `file:sha` pairs.
    #[must_use]
    pub fn digest(&self) -> String {
        use sha2::Digest as _;
        let mut h = sha2::Sha256::new();
        h.update(format!("version:{}", self.version));
        for (file, sha) in &self.checksums {
            h.update(format!("|{file}:{sha}"));
        }
        manifest::sha256_hex(&h.finalize())
    }
}
