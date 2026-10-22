//! Bounded read contract for `central-checkpoint`:
//! `RunCheckpointRead` — the per-run recovery snapshot
//! (`checkpoints_run_id_idx`, `checkpoints_recovery_idx`).
//!
//! Checkpoints are immutable evidence; the read returns the newest
//! records of one Run, bounded, newest-first. Startup recovery
//! additionally scopes by the `step_boundary`/`external_effect` kinds
//! covered by `checkpoints_recovery_idx`.

use central_foundation::failure::Failure;
use central_foundation::identity::{RunId, WorkspaceId};
use serde::{Deserialize, Serialize};

use crate::domain::{Checkpoint, CheckpointKind, codes};

/// Maximum records one read returns (adapter-mapping §4.2: the run
/// checkpoint read is bounded at ≤ 50).
pub const MAX_CHECKPOINT_PAGE: usize = 50;
/// Default when the request leaves `limit` unset.
pub const DEFAULT_CHECKPOINT_PAGE: usize = 50;

/// The bounded request: one Run's checkpoints, optionally narrowed to
/// the recovery kinds, with an exclusive `created_before` seek — the
/// ordering is `created_at DESC`, so the seek key is the oldest
/// returned `created_at` of the previous page (never an offset).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunCheckpointRequest {
    /// Owning Workspace — mandatory isolation scope.
    pub workspace_id: WorkspaceId,
    /// The Run whose recovery snapshot is read.
    pub run_id: RunId,
    /// Restrict to specific kinds (`step_boundary`/`external_effect`
    /// for startup recovery). Empty = all kinds.
    pub kinds: Vec<CheckpointKind>,
    /// Seek boundary: rows strictly older than this instant.
    pub created_before: Option<time::OffsetDateTime>,
    /// Page size; `None` → [`DEFAULT_CHECKPOINT_PAGE`], bounded
    /// [`MAX_CHECKPOINT_PAGE`].
    pub limit: Option<usize>,
}

impl RunCheckpointRequest {
    /// Validates scope, kind vocabulary, and the page bound.
    pub fn validate(&self) -> Result<usize, Failure> {
        let limit = self.limit.unwrap_or(DEFAULT_CHECKPOINT_PAGE);
        if limit == 0 || limit > MAX_CHECKPOINT_PAGE {
            return Err(Failure::invalid(
                codes::CHECKPOINT_INVALID,
                "the page size must be within 1..=50",
            ));
        }
        if self.kinds.len() > 5 {
            return Err(Failure::invalid(
                codes::CHECKPOINT_INVALID,
                "the kind filter cannot exceed the closed vocabulary",
            ));
        }
        Ok(limit)
    }
}

/// One recovery-snapshot page, newest-first.
#[derive(Debug, Clone, PartialEq)]
pub struct RunCheckpointPage {
    /// The records, `created_at DESC`.
    pub checkpoints: Vec<Checkpoint>,
    /// Seek boundary for the next page — the oldest `created_at` of
    /// this page; `None` when the page is empty or exhausted.
    pub next_boundary: Option<time::OffsetDateTime>,
}

/// The read contract. No mutation path exists — checkpoints are
/// immutable.
#[trait_variant::make(Send)]
pub trait RunCheckpointRead: Send + Sync + 'static {
    /// Reads one bounded newest-first page.
    async fn read_page(&self, request: &RunCheckpointRequest)
    -> Result<RunCheckpointPage, Failure>;
}
