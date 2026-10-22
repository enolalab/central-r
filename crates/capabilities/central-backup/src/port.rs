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
