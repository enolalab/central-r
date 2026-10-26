//! Backup/migration ports (ports `internal/backup/port/migration_port.go`;
//! rust-application-boundaries.md §2.3).
//!
//! The migration-domain contracts live here, owned by the
//! backup/lifecycle capability — not by the PostgreSQL adapter that
//! implements them. `sqlx` types never appear; the adapter maps its
//! session/row types at the boundary.

use central_foundation::failure::Failure;

use crate::domain::{ExternalRecordState, ProvisioningPhase};
use crate::domain::{ResetConfirmation, SessionBinding, TargetIdentity, VerifiedEmptyTarget};

/// Broker proof service — the authorization boundary between the migration
/// runner/reset runner and the broker that signs one-use proofs. Ports
/// `port.BrokerProofService`; upstream ships no in-crate implementation,
/// so this crate only defines the contract (tests use fakes exactly as
/// upstream does).
#[trait_variant::make(Send)]
pub trait BrokerProofService {
    /// Issue an empty-target proof for `req`.
    async fn issue_empty_target_proof(
        &self,
        req: IssueEmptyTargetProofRequest,
    ) -> Result<VerifiedEmptyTarget, Failure>;
    /// Verify (without consuming) `proof` against `target`.
    async fn verify_empty_target(
        &self,
        target: &TargetIdentity,
        proof: &VerifiedEmptyTarget,
    ) -> Result<(), Failure>;
    /// Consume `proof` once.
    async fn consume_empty_proof(&self, proof: VerifiedEmptyTarget) -> Result<(), Failure>;
    /// Verify and consume `proof` against `target` in one step.
    async fn consume_verified_empty_target(
        &self,
        target: &TargetIdentity,
        proof: VerifiedEmptyTarget,
    ) -> Result<(), Failure>;
    /// Issue a reset confirmation for `req`.
    async fn issue_reset_confirmation(
        &self,
        req: IssueResetConfirmationRequest,
    ) -> Result<ResetConfirmation, Failure>;
    /// Verify (without consuming) `confirmation`.
    async fn verify_reset_confirmation(
        &self,
        confirmation: &ResetConfirmation,
    ) -> Result<(), Failure>;
    /// Consume `confirmation` once.
    async fn consume_reset_confirmation(
        &self,
        confirmation: ResetConfirmation,
    ) -> Result<(), Failure>;
    /// Verify and consume `confirmation` against `target` in one step.
    async fn consume_verified_reset_confirmation(
        &self,
        target: &TargetIdentity,
        confirmation: ResetConfirmation,
    ) -> Result<(), Failure>;
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

/// Object-safe boxed future the erased port traits return.
/// `#[trait_variant]` traits are not object-safe (return-position
/// `impl Future` cannot build a vtable), so the operator-facing seams
/// are written in this form directly. The futures are deliberately
/// **not** `Send`: the coordinator drives them on the one task that
/// owns the `&mut` session (upstream's conn-bound flow), and rustc
/// cannot prove the sqlx adapters' `async fn` futures `Send` across
/// all captured lifetimes. The trait *objects* stay `Send`/`Sync` —
/// they may be shared in `Arc`; their futures just may not migrate
/// threads mid-await.
pub type BoxFuture<'a, T> = core::pin::Pin<Box<dyn core::future::Future<Output = T> + 'a>>;

/// `port.MigrationRunner` — the single-session two-phase driver
/// contract, object-safe. The concrete
/// `central-adapter-postgres::migrate::Runner` implements it over the
/// one non-rebinding `central_migration` session.
pub trait MigrationRunner: Send {
    /// `PrepareUp` — locks + session binding + stock-target check.
    fn prepare_up<'a>(
        &'a mut self,
        req: &'a PrepareUpRequest,
    ) -> BoxFuture<'a, Result<PrepareUpResult, Failure>>;
    /// `CommitUp` — same-session binding + proof consume + install.
    fn commit_up<'a>(
        &'a mut self,
        req: &'a CommitUpRequest,
    ) -> BoxFuture<'a, Result<UpResult, Failure>>;
    /// `Up` — prepare then commit.
    fn up<'a>(&'a mut self, req: &'a UpRequest) -> BoxFuture<'a, Result<UpResult, Failure>>;
    /// `Resume` — repair leg or fresh-install leg.
    fn resume<'a>(
        &'a mut self,
        req: &'a ResumeRequest,
    ) -> BoxFuture<'a, Result<ResumeResult, Failure>>;
}

/// `port.MigrationInspector` — the read-only facts surface.
pub trait MigrationInspector: Send {
    /// `Inspect` — `central` schema facts; dirty evidence and a
    /// non-terminal chain are failures, not facts.
    fn inspect<'a>(&'a mut self) -> BoxFuture<'a, Result<PostgresMigrationFacts, Failure>>;
}

/// `port.ProtectedOperatorStateInspector` — the protected provisioning
/// record read the coordinator's status path needs. The inspector is
/// bound to one target at composition time (upstream `Inspect(ctx)`
/// takes no target); an absent record answers [`ProtectedOperatorState`]
/// with [`ExternalRecordState::Absent`], never an error.
pub trait ProtectedOperatorStateInspector: Send + Sync {
    /// `Inspect` — the bound target's protected record projection.
    fn inspect_operator_state<'a>(
        &'a self,
    ) -> BoxFuture<'a, Result<ProtectedOperatorState, Failure>>;
}

/// `port.ResetRunner` — the version-zero-only reset driver.
pub trait ResetRunner: Send {
    /// `DeleteSchema` — locked, confirmation-bound, version-zero-only.
    fn delete_schema<'a>(&'a mut self, req: &'a ResetRequest)
    -> BoxFuture<'a, Result<(), Failure>>;
}

/// Object-safe erase of [`BrokerProofService`] for the coordinator's
/// stored seam — the broker authority client (R6 task 2) implements
/// the `trait_variant` surface; this is its object-safe twin with the
/// identical method set.
pub trait DynBrokerProofService: Send + Sync {
    /// `IssueEmptyTargetProof`.
    fn issue_empty_target_proof<'a>(
        &'a self,
        req: &'a IssueEmptyTargetProofRequest,
    ) -> BoxFuture<'a, Result<VerifiedEmptyTarget, Failure>>;
    /// `VerifyEmptyTarget`.
    fn verify_empty_target<'a>(
        &'a self,
        target: &'a TargetIdentity,
        proof: &'a VerifiedEmptyTarget,
    ) -> BoxFuture<'a, Result<(), Failure>>;
    /// `ConsumeEmptyProof`.
    fn consume_empty_proof<'a>(
        &'a self,
        proof: VerifiedEmptyTarget,
    ) -> BoxFuture<'a, Result<(), Failure>>;
    /// `ConsumeVerifiedEmptyTarget`.
    fn consume_verified_empty_target<'a>(
        &'a self,
        target: &'a TargetIdentity,
        proof: VerifiedEmptyTarget,
    ) -> BoxFuture<'a, Result<(), Failure>>;
    /// `IssueResetConfirmation`.
    fn issue_reset_confirmation<'a>(
        &'a self,
        req: &'a IssueResetConfirmationRequest,
    ) -> BoxFuture<'a, Result<ResetConfirmation, Failure>>;
    /// `VerifyResetConfirmation`.
    fn verify_reset_confirmation<'a>(
        &'a self,
        confirmation: &'a ResetConfirmation,
    ) -> BoxFuture<'a, Result<(), Failure>>;
    /// `ConsumeResetConfirmation`.
    fn consume_reset_confirmation<'a>(
        &'a self,
        confirmation: ResetConfirmation,
    ) -> BoxFuture<'a, Result<(), Failure>>;
    /// `ConsumeVerifiedResetConfirmation`.
    fn consume_verified_reset_confirmation<'a>(
        &'a self,
        target: &'a TargetIdentity,
        confirmation: ResetConfirmation,
    ) -> BoxFuture<'a, Result<(), Failure>>;
}

impl<T: BrokerProofService + Send + Sync> DynBrokerProofService for T {
    fn issue_empty_target_proof<'a>(
        &'a self,
        req: &'a IssueEmptyTargetProofRequest,
    ) -> BoxFuture<'a, Result<VerifiedEmptyTarget, Failure>> {
        Box::pin(BrokerProofService::issue_empty_target_proof(
            self,
            req.clone(),
        ))
    }
    fn verify_empty_target<'a>(
        &'a self,
        target: &'a TargetIdentity,
        proof: &'a VerifiedEmptyTarget,
    ) -> BoxFuture<'a, Result<(), Failure>> {
        Box::pin(BrokerProofService::verify_empty_target(self, target, proof))
    }
    fn consume_empty_proof<'a>(
        &'a self,
        proof: VerifiedEmptyTarget,
    ) -> BoxFuture<'a, Result<(), Failure>> {
        Box::pin(BrokerProofService::consume_empty_proof(self, proof))
    }
    fn consume_verified_empty_target<'a>(
        &'a self,
        target: &'a TargetIdentity,
        proof: VerifiedEmptyTarget,
    ) -> BoxFuture<'a, Result<(), Failure>> {
        Box::pin(BrokerProofService::consume_verified_empty_target(
            self, target, proof,
        ))
    }
    fn issue_reset_confirmation<'a>(
        &'a self,
        req: &'a IssueResetConfirmationRequest,
    ) -> BoxFuture<'a, Result<ResetConfirmation, Failure>> {
        Box::pin(BrokerProofService::issue_reset_confirmation(
            self,
            req.clone(),
        ))
    }
    fn verify_reset_confirmation<'a>(
        &'a self,
        confirmation: &'a ResetConfirmation,
    ) -> BoxFuture<'a, Result<(), Failure>> {
        Box::pin(BrokerProofService::verify_reset_confirmation(
            self,
            confirmation,
        ))
    }
    fn consume_reset_confirmation<'a>(
        &'a self,
        confirmation: ResetConfirmation,
    ) -> BoxFuture<'a, Result<(), Failure>> {
        Box::pin(BrokerProofService::consume_reset_confirmation(
            self,
            confirmation,
        ))
    }
    fn consume_verified_reset_confirmation<'a>(
        &'a self,
        target: &'a TargetIdentity,
        confirmation: ResetConfirmation,
    ) -> BoxFuture<'a, Result<(), Failure>> {
        Box::pin(BrokerProofService::consume_verified_reset_confirmation(
            self,
            target,
            confirmation,
        ))
    }
}

/// `port.ProtectedOperatorState` — the broker's projection of the
/// protected provisioning record; the coordinator keys every mutating
/// decision on it.
#[derive(Debug, Clone, Default)]
pub struct ProtectedOperatorState {
    /// External record state.
    pub record_state: ExternalRecordState,
    /// In-flight provisioning phase, if any.
    pub provisioning_phase: ProvisioningPhase,
    /// Target the record binds.
    pub target: TargetIdentity,
    /// Operation identity recorded on the target.
    pub operation_id: uuid::Uuid,
    /// Optimistic-concurrency revision.
    pub revision: u64,
    /// Session binding captured when the operation started.
    pub session_binding: SessionBinding,
    /// Last record update.
    pub detected_at: Option<time::OffsetDateTime>,
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
