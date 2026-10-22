//! Execution query surface — typed reads and the claimability
//! decorator. Ported from
//! `central/internal/execution/app/query/turn_activity.go` and
//! `central/internal/task/app/query/claimability_decorator.go` (the
//! decorator lives here, not in `central-task`, to keep the crate
//! graph acyclic).

use central_foundation::failure::{Failure, FailureKind};
use central_foundation::identity::{RunId, TaskId, WorkspaceId};
use time::OffsetDateTime;

use crate::domain::{Step, StepAttempt, TrustedScope};
use crate::port::RecoveryClaimabilityReader;
use crate::resume::recovery_claimability;

fn failure(kind: FailureKind, reason: &'static str) -> Failure {
    Failure::new(kind, reason, "execution query refused")
}

// ---------------------------------------------------------------------------
// Turn activity (upstream query/turn_activity.go) — the per-attempt
// activity projection the UI renders.
// ---------------------------------------------------------------------------

/// `RunTurnActivityRequest` — page the turn-activity projection for a
/// run.
#[derive(Debug, Clone, PartialEq)]
pub struct RunTurnActivityRequest {
    /// The authenticated scope.
    pub scope: TrustedScope,
    pub workspace_id: WorkspaceId,
    pub task_id: TaskId,
    pub run_id: RunId,
    /// Opaque page cursor; empty for the first page.
    pub cursor: String,
    /// Requested page size — normalized to [`normalize_page_size`].
    pub page_size: u32,
}

/// Default turn-activity page size.
pub const DEFAULT_TURN_ACTIVITY_PAGE_SIZE: u32 = 50;
/// Max turn-activity page size.
pub const MAX_TURN_ACTIVITY_PAGE_SIZE: u32 = 200;

/// `normalizePageSize` — clamps to `[1, MAX]` and defaults on `0`.
#[must_use]
pub fn normalize_page_size(page_size: u32) -> u32 {
    if page_size == 0 {
        DEFAULT_TURN_ACTIVITY_PAGE_SIZE
    } else {
        page_size.min(MAX_TURN_ACTIVITY_PAGE_SIZE)
    }
}

/// One attempt's activity row (upstream `TurnActivity`).
#[derive(Debug, Clone, PartialEq)]
pub struct TurnActivity {
    /// The step the attempt belongs to.
    pub step: Step,
    /// The attempt.
    pub attempt: StepAttempt,
    /// Whether the attempt is the run's latest.
    pub latest: bool,
}

/// `RunTurnActivityResult` — a page of turn activity.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RunTurnActivityResult {
    /// Activity rows, oldest first.
    pub activities: Vec<TurnActivity>,
    /// Resume cursor; empty at the end.
    pub next_cursor: String,
}

/// Validates a turn-activity request (upstream `Validate`).
pub fn validate_turn_activity_request(req: &RunTurnActivityRequest) -> Result<u32, Failure> {
    if req.scope.principal_id.trim().is_empty()
        || req.scope.workspace_id.is_nil()
        || req.scope.workspace_id != req.workspace_id
        || req.workspace_id.is_nil()
        || req.task_id.is_nil()
        || req.run_id.is_nil()
    {
        return Err(failure(FailureKind::Invalid, "INVALID_ACTIVITY_REQUEST"));
    }
    Ok(normalize_page_size(req.page_size))
}

// ---------------------------------------------------------------------------
// Claimability decorator (upstream task/app/query/claimability_decorator.go,
// relocated here to keep central-task free of a dependency on
// central-execution).
// ---------------------------------------------------------------------------

/// A claimable-run row the decorator annotates.
#[derive(Debug, Clone, PartialEq)]
pub struct ClaimableRun {
    /// The workspace the run belongs to.
    pub workspace_id: WorkspaceId,
    /// The run.
    pub run_id: RunId,
    /// When the run row was created (recovery watermark comparison).
    pub created_at: OffsetDateTime,
    /// The task's current claimability as the task query reported it.
    pub claimable: bool,
    /// Machine reason when not claimable.
    pub reason: Option<String>,
}

/// `ClaimabilityDecorator` — wraps a run-listing query and marks runs
/// quarantined by a failed recovery epoch. On any reader failure it
/// fails closed with `RECOVERY_STATUS_UNAVAILABLE`.
pub struct ClaimabilityDecorator<R: RecoveryClaimabilityReader> {
    reader: R,
}

impl<R: RecoveryClaimabilityReader> ClaimabilityDecorator<R> {
    /// Builds the decorator around the recovery reader.
    pub const fn new(reader: R) -> Self {
        Self { reader }
    }

    /// `Decorate` — annotates each row in place.
    pub async fn decorate(
        &self,
        scope: &TrustedScope,
        runs: &mut [ClaimableRun],
    ) -> Result<(), Failure> {
        for run in runs.iter_mut() {
            match self
                .reader
                .recovery_claimability_for(scope.clone(), run.workspace_id, run.run_id)
                .await
            {
                Err(_) => {
                    run.claimable = false;
                    run.reason = Some("RECOVERY_STATUS_UNAVAILABLE".to_string());
                }
                Ok(Some((epoch, work, reconciled_generation))) => {
                    let claimability = recovery_claimability(
                        &epoch,
                        &work,
                        run.created_at,
                        run.run_id,
                        reconciled_generation,
                    );
                    if !claimability.claimable {
                        run.claimable = false;
                        run.reason = claimability.reason;
                    }
                }
                Ok(None) => {}
            }
        }
        Ok(())
    }
}
