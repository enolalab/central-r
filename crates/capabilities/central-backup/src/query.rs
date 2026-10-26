//! Bounded read projections for the backup/recovery capability.
//!
//! Every projection is the locator-free shape an operator surface may
//! mirror: phases, checkpoints, counts, digests, and opaque
//! identities — never object keys, repository paths, ticket nonces,
//! or credential material. `*Query` traits are implemented by the
//! read-side adapter; `*View` structs are the projected rows.

use central_foundation::failure::Failure;
use uuid::Uuid;

use crate::backup::operation::BackupPhase;
use crate::recovery::operation::{RestoreCheckpoint, RestorePhase};
use crate::recovery::quarantine::QuarantineReason;

/// Maximum page a projection query may return in one read.
pub const MAXIMUM_PROJECTION_PAGE: usize = 1_000;

/// `BackupOperationView` — the bounded read projection of a durable
/// backup operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupOperationView {
    /// Operation identity.
    pub operation_id: Uuid,
    /// Backup identity.
    pub backup_id: Uuid,
    /// Journal CAS fence.
    pub revision: u64,
    /// Lifecycle phase.
    pub phase: BackupPhase,
    /// Closed failure reason, if failed.
    pub failure_reason: Option<String>,
    /// Accepted consistent point, once admitted.
    pub accepted_at: Option<time::OffsetDateTime>,
    /// Last update.
    pub updated_at: time::OffsetDateTime,
}

/// `SealedBackupView` — one manifest-catalogue entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedBackupView {
    /// Backup identity.
    pub backup_id: Uuid,
    /// Accepted consistent point.
    pub accepted_at: time::OffsetDateTime,
    /// `sha256:`-prefixed root manifest digest.
    pub root_manifest_digest: String,
    /// `sha256:`-prefixed file-tree digest.
    pub file_tree_digest: String,
}

/// `RepositoryCensusView` — the bounded census the admission checks
/// consume.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RepositoryCensusView {
    /// Sealed backup count.
    pub sealed_backups: u64,
    /// Repository byte total.
    pub repository_bytes: u64,
    /// Sealed entries, canonically ordered.
    pub sealed: Vec<SealedBackupView>,
}

/// `RestoreOperationView` — the bounded read projection of the
/// protected restore record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreOperationView {
    /// Operation identity.
    pub operation_id: Uuid,
    /// Backup identity.
    pub backup_id: Uuid,
    /// Journal CAS fence.
    pub revision: u64,
    /// Current phase.
    pub phase: RestorePhase,
    /// Last durable checkpoint.
    pub last_checkpoint: RestoreCheckpoint,
    /// Whether the operation may resume.
    pub resumable: bool,
    /// Whether serving is currently permitted.
    pub serving_allowed: bool,
    /// Last update.
    pub updated_at: time::OffsetDateTime,
}

/// `QuarantineFindingView` — one durable finding's safe projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantineFindingView {
    /// Finding identity.
    pub quarantine_id: Uuid,
    /// Bound artifact.
    pub artifact_id: Uuid,
    /// Closed reason.
    pub reason: QuarantineReason,
    /// Creation instant.
    pub created_at: time::OffsetDateTime,
}

/// Read-side port for backup operations and the repository census.
pub trait BackupQuery: Send + Sync {
    /// Load one operation projection by identity.
    fn get_backup_operation(
        &self,
        operation_id: Uuid,
    ) -> Result<Option<BackupOperationView>, Failure>;

    /// List operation projections, newest first, bounded to `limit`
    /// (clamped to [`MAXIMUM_PROJECTION_PAGE`]).
    fn list_backup_operations(&self, limit: usize) -> Result<Vec<BackupOperationView>, Failure>;

    /// The bounded repository census.
    fn repository_census(&self) -> Result<RepositoryCensusView, Failure>;
}

/// Read-side port for restore operations and quarantine findings.
pub trait RestoreQuery: Send + Sync {
    /// Load one operation projection by identity.
    fn get_restore_operation(
        &self,
        operation_id: Uuid,
    ) -> Result<Option<RestoreOperationView>, Failure>;

    /// The resumable operation bound to a target epoch, if any.
    fn get_resumable_restore(&self) -> Result<Option<RestoreOperationView>, Failure>;

    /// Count unresolved quarantine findings for an operation — the
    /// number [`crate::recovery::operation::RestoreOperation::resume_verification`]
    /// requires to be zero.
    fn unresolved_quarantine_count(&self, operation_id: Uuid) -> Result<u64, Failure>;

    /// List an operation's durable findings, bounded to `limit`.
    fn list_quarantine_findings(
        &self,
        operation_id: Uuid,
        limit: usize,
    ) -> Result<Vec<QuarantineFindingView>, Failure>;
}

/// Clamp a caller-supplied page bound.
#[must_use]
pub fn clamp_page(limit: usize) -> usize {
    limit.min(MAXIMUM_PROJECTION_PAGE)
}
