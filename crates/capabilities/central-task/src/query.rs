//! Task read contracts (ports `internal/task/app/query/`;
//! rust-application-boundaries.md §2.3/§7.5 rows 2–3).
//!
//! Declaration-only consumer-side read traits with typed seek cursors —
//! no offset pagination, no unbounded reads. Projections carry only
//! safe display facts.
//!
//! Cyclic-edge inversion (§2.2): the upstream `RunSummary.Claimability`
//! field and the `claimability_decorator.go` decorator are NOT ported
//! here — `central-execution::query` owns the decoration that augments
//! these projections, so this crate never imports `central-execution`.

use central_foundation::failure::Failure;
use central_foundation::identity::{ArtifactId, RunId, TaskId, WorkspaceId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::domain::{Budget, PermissionPolicy, RunStatus, TaskStatus, WaitingReason, codes};

/// Default and maximum page sizes for task projections.
pub const DEFAULT_TASK_LIST_PAGE_SIZE: u32 = 100;
/// Hard ceiling on one task list page.
pub const MAX_TASK_LIST_PAGE_SIZE: u32 = 250;
/// Default page size for the detail projection's run list.
pub const DEFAULT_TASK_DETAIL_RUN_PAGE_SIZE: u32 = 10;
/// Hard ceiling on one run page inside the detail projection.
pub const MAX_TASK_DETAIL_RUN_PAGE_SIZE: u32 = 25;
/// Default page size for the task event log.
pub const DEFAULT_TASK_EVENT_LOG_PAGE_SIZE: u32 = 50;
/// Hard ceiling on one event log page.
pub const MAX_TASK_EVENT_LOG_PAGE_SIZE: u32 = 200;
/// Bounds [`TaskDetail::artifacts`] (harness phase 3b decision 13).
pub const MAX_TASK_DETAIL_ARTIFACTS: usize = 20;

/// The typed seek cursor for task listing (§7.5 row 2 —
/// `TaskListCursor{ task_id, status, updated_at }`). `None` on the
/// request asks for the head page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskSeekCursor {
    /// The task identity at the page boundary.
    pub task_id: TaskId,
    /// The task status at the page boundary.
    pub status: TaskStatus,
    /// The task `updated_at` at the page boundary.
    pub updated_at: OffsetDateTime,
}

/// A Workspace-scoped keyset list request.
#[derive(Debug, Clone, PartialEq)]
pub struct TaskListRequest {
    /// The owning workspace — mandatory isolation scope.
    pub workspace_id: WorkspaceId,
    /// Continuation boundary; `None` requests the head page.
    pub cursor: Option<TaskSeekCursor>,
    /// Requested page size; `0` normalizes to
    /// [`DEFAULT_TASK_LIST_PAGE_SIZE`].
    pub page_size: u32,
}

/// Validates workspace scope for task list reads.
pub fn validate_task_list_request(req: &TaskListRequest) -> Result<(), Failure> {
    if req.workspace_id.is_nil() {
        return Err(Failure::invalid(codes::INVALID, "missing workspace id"));
    }
    Ok(())
}

/// Clamps a requested page size into
/// `[DEFAULT_TASK_LIST_PAGE_SIZE, MAX_TASK_LIST_PAGE_SIZE]`.
#[must_use]
pub const fn normalize_task_list_page_size(v: u32) -> u32 {
    if v == 0 {
        DEFAULT_TASK_LIST_PAGE_SIZE
    } else if v > MAX_TASK_LIST_PAGE_SIZE {
        MAX_TASK_LIST_PAGE_SIZE
    } else {
        v
    }
}

/// A safe, immutable task-run projection row.
///
/// The upstream `Claimability` field is intentionally absent (§2.2
/// cyclic-edge inversion): `central-execution::query` augments the
/// projection with the restart/reconciliation barrier.
#[derive(Debug, Clone, PartialEq)]
pub struct RunSummary {
    /// The run identity.
    pub run_id: RunId,
    /// The owning task.
    pub task_id: TaskId,
    /// The owning workspace.
    pub workspace_id: WorkspaceId,
    /// The current run status.
    pub status: RunStatus,
    /// The run attempt index within the task.
    pub index: i64,
    /// The wait classification while `status` is
    /// [`RunStatus::Waiting`].
    pub waiting_reason: Option<WaitingReason>,
    /// The terminal failure summary (`""` = none).
    pub failure_reason: String,
    /// Persistence timestamps.
    pub updated_at: OffsetDateTime,
    /// Persistence timestamps.
    pub created_at: OffsetDateTime,
}

/// A safe, immutable task projection row.
#[derive(Debug, Clone, PartialEq)]
pub struct TaskSummary {
    /// The task identity.
    pub task_id: TaskId,
    /// The owning workspace.
    pub workspace_id: WorkspaceId,
    /// The current lifecycle status.
    pub status: TaskStatus,
    /// The active non-terminal run when present.
    pub current_run_id: Option<RunId>,
    /// The wait classification while `status` is
    /// [`TaskStatus::Waiting`].
    pub waiting_reason: Option<WaitingReason>,
    /// Persisted terminal run failures.
    pub retry_count: i64,
    /// The user-facing label.
    pub title: String,
    /// The terminal failure summary (`""` = none).
    pub failure_reason: String,
    /// When a scheduled whole-run retry becomes eligible.
    pub retry_eligible_at: Option<OffsetDateTime>,
    /// Persistence timestamps.
    pub updated_at: OffsetDateTime,
    /// Persistence timestamps.
    pub created_at: OffsetDateTime,
}

/// The bounded list response payload.
#[derive(Debug, Clone, PartialEq)]
pub struct TaskListProjection {
    /// One page of task summaries.
    pub tasks: Vec<TaskSummary>,
    /// Forward-only continuation; `None` = end of list.
    pub next_cursor: Option<TaskSeekCursor>,
}

/// The typed seek cursor for task detail run pagination — a stable
/// `(created_at, run_id)` descending boundary (`runs_task_id_idx`).
/// `None` on the request asks for the first run page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunSeekCursor {
    /// The run `created_at` at the page boundary.
    pub created_at: OffsetDateTime,
    /// The run identity at the page boundary.
    pub run_id: RunId,
}

/// A bounded task detail snapshot request.
#[derive(Debug, Clone, PartialEq)]
pub struct TaskDetailRequest {
    /// The owning workspace — mandatory isolation scope.
    pub workspace_id: WorkspaceId,
    /// The task whose detail is requested.
    pub task_id: TaskId,
    /// Run-page continuation; `None` loads the first run page.
    pub run_cursor: Option<RunSeekCursor>,
    /// Requested run page size; `0` normalizes to
    /// [`DEFAULT_TASK_DETAIL_RUN_PAGE_SIZE`].
    pub run_page_size: u32,
}

/// Validates workspace + task scope for task detail reads.
pub fn validate_task_detail_request(req: &TaskDetailRequest) -> Result<(), Failure> {
    if req.workspace_id.is_nil() {
        return Err(Failure::invalid(codes::INVALID, "missing workspace id"));
    }
    if req.task_id.is_nil() {
        return Err(Failure::invalid(codes::INVALID, "missing task id"));
    }
    Ok(())
}

/// Clamps a requested run page size into
/// `[DEFAULT_TASK_DETAIL_RUN_PAGE_SIZE, MAX_TASK_DETAIL_RUN_PAGE_SIZE]`.
#[must_use]
pub const fn normalize_task_detail_run_page_size(v: u32) -> u32 {
    if v == 0 {
        DEFAULT_TASK_DETAIL_RUN_PAGE_SIZE
    } else if v > MAX_TASK_DETAIL_RUN_PAGE_SIZE {
        MAX_TASK_DETAIL_RUN_PAGE_SIZE
    } else {
        v
    }
}

/// One ready Artifact of a Task's current run: its ID, its required
/// role (`""` when it has none) and its verified size in bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactRef {
    /// The artifact identity.
    pub id: ArtifactId,
    /// The artifact role (`""` when none).
    pub role: String,
    /// Verified size in bytes.
    pub verified_size: i64,
}

/// The canonical safe task detail envelope for read models.
#[derive(Debug, Clone, PartialEq)]
pub struct TaskDetail {
    /// The task identity.
    pub task_id: TaskId,
    /// The owning workspace.
    pub workspace_id: WorkspaceId,
    /// The current lifecycle status.
    pub status: TaskStatus,
    /// The user-facing label.
    pub title: String,
    /// The submission payload summary/reference.
    pub input: String,
    /// The active non-terminal run when present.
    pub current_run_id: Option<RunId>,
    /// Persisted terminal run failures.
    pub retry_count: i64,
    /// The terminal failure summary (`""` = none).
    pub failure_reason: String,
    /// The wait classification while `status` is
    /// [`TaskStatus::Waiting`].
    pub waiting_reason: Option<WaitingReason>,
    /// Persistence timestamps.
    pub updated_at: OffsetDateTime,
    /// Persistence timestamps.
    pub created_at: OffsetDateTime,
    /// The source Task's ID when this Task was created by
    /// `rerun_cancelled_task`; `None` means no rerun lineage (b11).
    pub parent_task_id: Option<TaskId>,
    /// The Task's harness permission policy (harness phase 3c
    /// decision 4), shown on the detail page.
    pub permission_policy: PermissionPolicy,
    /// The harness budget requested at submission (harness phase 3d
    /// decision 2); a zero field means the serve default applied.
    pub budget: Budget,
    /// The durable ID of the ready, required-report Artifact produced
    /// by this Task's current run, most-recently-updated first when
    /// more than one exists. `None` means no ready Artifact has been
    /// linked yet — the preview/download links must never render from
    /// it. Read-projection convenience only: the actual
    /// authorization/delivery guard is `central-artifact`'s delivery
    /// service, which revalidates from a fresh durable read.
    pub required_artifact_id: Option<ArtifactId>,
    /// Every ready, not-delete-pending Artifact of the current run
    /// (harness phase 3b decision 13): the harness report, patch and
    /// commits first, in that order, then any other role by creation
    /// time, at most [`MAX_TASK_DETAIL_ARTIFACTS`]. Read-projection
    /// convenience; delivery re-validates each Artifact.
    pub artifacts: Vec<ArtifactRef>,
    /// The Task's own optimistic-concurrency `version`
    /// (`central.tasks.version`, the same value the change-set commit
    /// CAS-checks via `expected_task_version`): it increments on every
    /// durable Task-row change this projection reads from. Client-side
    /// adaptive polling compares this value across polls — unchanged
    /// means "no projected Task-row state change since the last poll".
    pub projection_revision: i64,
    /// The highest `central.events.event_sequence` recorded for this
    /// Task (workspace-scoped, monotonic), or zero when no event has
    /// been recorded yet. A genuine signal independent of
    /// `projection_revision`: a change set can append an event without
    /// being observable as a different coarse Task field.
    pub event_revision: i64,
}

/// The bounded detail response payload.
#[derive(Debug, Clone, PartialEq)]
pub struct TaskDetailProjection {
    /// The task envelope.
    pub task: TaskDetail,
    /// One page of run summaries.
    pub runs: Vec<RunSummary>,
    /// Continuation for additional runs; `None` = no further runs.
    pub next_run_cursor: Option<RunSeekCursor>,
}

/// One durable lifecycle event projected from `central.events` for
/// display. It carries only bounded, non-sensitive fields — the event
/// sequence, which task/run it concerns, the kind and resulting task
/// state, and when it occurred. The event payload is deliberately NOT
/// projected: it may carry command inputs or provider content, and the
/// activity feed never needs it.
#[derive(Debug, Clone, PartialEq)]
pub struct TaskEvent {
    /// The workspace-scoped event sequence.
    pub sequence: i64,
    /// The task the event concerns.
    pub task_id: TaskId,
    /// The run when the event is run-scoped.
    pub run_id: Option<RunId>,
    /// The lifecycle event kind. Upstream `task.EventKind` is an open
    /// `string` type, and the feed deliberately surfaces every
    /// producer's kind — `task.*` lifecycle intents, `harness.*`
    /// milestones, and `attempt_*`/`checkpoint_*` execution evidence —
    /// filtering only [`mod@crate::query`]'s hidden kinds. The closed
    /// [`crate::domain::EventKind`] enum stays the write-intent
    /// vocabulary; the projection carries the raw kind text.
    pub kind: String,
    /// The resulting task state when the event carried one.
    pub state: Option<TaskStatus>,
    /// When the event occurred.
    pub at: OffsetDateTime,
}

/// The keyset cursor for the task event log, seeking by descending
/// event sequence (newest first). `None` requests the head page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventCursor {
    /// The sequence at the page boundary.
    pub sequence: i64,
}

/// A workspace-scoped, bounded request for the lifecycle event log.
/// `task_id` is optional: `None` requests the whole workspace's
/// activity; `Some` scopes the log to one task.
#[derive(Debug, Clone, PartialEq)]
pub struct TaskEventLogRequest {
    /// The owning workspace — mandatory isolation scope.
    pub workspace_id: WorkspaceId,
    /// Optional single-task scope.
    pub task_id: Option<TaskId>,
    /// Continuation boundary; `None` requests the head page.
    pub cursor: Option<EventCursor>,
    /// Requested page size; `0` normalizes to
    /// [`DEFAULT_TASK_EVENT_LOG_PAGE_SIZE`].
    pub page_size: u32,
}

/// Validates workspace scope for event-log reads.
pub fn validate_task_event_log_request(req: &TaskEventLogRequest) -> Result<(), Failure> {
    if req.workspace_id.is_nil() {
        return Err(Failure::invalid(codes::INVALID, "missing workspace id"));
    }
    Ok(())
}

/// Clamps a requested page size into
/// `[DEFAULT_TASK_EVENT_LOG_PAGE_SIZE, MAX_TASK_EVENT_LOG_PAGE_SIZE]`.
#[must_use]
pub const fn normalize_task_event_log_page_size(v: u32) -> u32 {
    if v == 0 {
        DEFAULT_TASK_EVENT_LOG_PAGE_SIZE
    } else if v > MAX_TASK_EVENT_LOG_PAGE_SIZE {
        MAX_TASK_EVENT_LOG_PAGE_SIZE
    } else {
        v
    }
}

/// The bounded event-log response payload, newest first.
/// `next_cursor` is `Some` only when a further (older) page exists.
#[derive(Debug, Clone, PartialEq)]
pub struct TaskEventLogProjection {
    /// One page of lifecycle events.
    pub events: Vec<TaskEvent>,
    /// Continuation toward older events.
    pub next_cursor: Option<EventCursor>,
}

/// Bounded task summaries for a workspace (§7.5 row 2):
/// `central-task::app` → `list_tasks` after the caller's
/// authenticated-session + workspace-owner decision.
///
/// Adapter notes: ≤ 2 round trips, ≤ 250 rows examined/returned per
/// page, descending `(updated_at, task_id)` seek on
/// `tasks_workspace_status_created_idx`.
#[trait_variant::make(Send)]
pub trait TaskListRead: Send + Sync + 'static {
    /// Reads one bounded page of task summaries.
    async fn read(&self, req: TaskListRequest) -> Result<TaskListProjection, Failure>;
}

/// A bounded task detail projection for one task (§7.5 row 3):
/// `central-task::app` → `task_detail`. `NotFound` for a missing or
/// cross-workspace task — no existence oracle.
#[trait_variant::make(Send)]
pub trait TaskDetailRead: Send + Sync + 'static {
    /// Reads one bounded task detail projection.
    async fn read(&self, req: TaskDetailRequest) -> Result<TaskDetailProjection, Failure>;
}

/// A bounded, workspace-scoped page of lifecycle events, newest
/// first, optionally scoped to a single task.
#[trait_variant::make(Send)]
pub trait TaskEventLogRead: Send + Sync + 'static {
    /// Reads one bounded event-log page.
    async fn read(&self, req: TaskEventLogRequest) -> Result<TaskEventLogProjection, Failure>;
}

// ---------------------------------------------------------------------------
// Tests — port of internal/task/app/query/{contracts_test,
// event_log_test}.go.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_task_list_page_size_clamps() {
        assert_eq!(
            normalize_task_list_page_size(0),
            DEFAULT_TASK_LIST_PAGE_SIZE
        );
        // Go's `int` admitted negative sizes; `u32` makes them
        // unrepresentable — the zero/default arm covers "unset".
        assert_eq!(normalize_task_list_page_size(1000), MAX_TASK_LIST_PAGE_SIZE);
        assert_eq!(normalize_task_list_page_size(87), 87);
    }

    #[test]
    fn normalize_task_detail_run_page_size_clamps() {
        assert_eq!(
            normalize_task_detail_run_page_size(0),
            DEFAULT_TASK_DETAIL_RUN_PAGE_SIZE
        );
        assert_eq!(normalize_task_detail_run_page_size(10), 10);
        assert_eq!(
            normalize_task_detail_run_page_size(999),
            MAX_TASK_DETAIL_RUN_PAGE_SIZE
        );
    }

    #[test]
    fn normalize_task_event_log_page_size_clamps() {
        assert_eq!(
            normalize_task_event_log_page_size(0),
            DEFAULT_TASK_EVENT_LOG_PAGE_SIZE
        );
        assert_eq!(normalize_task_event_log_page_size(10), 10);
        assert_eq!(
            normalize_task_event_log_page_size(MAX_TASK_EVENT_LOG_PAGE_SIZE),
            MAX_TASK_EVENT_LOG_PAGE_SIZE
        );
        assert_eq!(
            normalize_task_event_log_page_size(MAX_TASK_EVENT_LOG_PAGE_SIZE + 1000),
            MAX_TASK_EVENT_LOG_PAGE_SIZE
        );
    }

    #[test]
    fn run_summary_uses_canonical_fields() {
        let summary = RunSummary {
            run_id: RunId::new(),
            task_id: TaskId::new(),
            workspace_id: WorkspaceId::new(),
            status: RunStatus::Running,
            index: 1,
            waiting_reason: None,
            failure_reason: String::new(),
            updated_at: OffsetDateTime::UNIX_EPOCH,
            created_at: OffsetDateTime::UNIX_EPOCH,
        };
        assert!(!summary.task_id.is_nil());
        // The claimability field upstream carried is absent by design —
        // the type has no `central-execution` dependency.
    }

    #[test]
    fn task_detail_request_can_carry_run_cursor() {
        let req = TaskDetailRequest {
            task_id: TaskId::new(),
            workspace_id: WorkspaceId::new(),
            run_cursor: None,
            run_page_size: 0,
        };
        assert_eq!(req.run_page_size, 0);
        assert!(req.run_cursor.is_none());
    }

    #[test]
    fn validate_task_list_request_requires_workspace() {
        let req = TaskListRequest {
            workspace_id: WorkspaceId::from_trusted_db_bytes([0; 16]),
            cursor: None,
            page_size: 0,
        };
        validate_task_list_request(&req).unwrap_err();
        let req = TaskListRequest {
            workspace_id: WorkspaceId::new(),
            ..req
        };
        validate_task_list_request(&req).unwrap();
    }

    #[test]
    fn validate_task_detail_request_requires_workspace_and_task_id() {
        let mut req = TaskDetailRequest {
            workspace_id: WorkspaceId::from_trusted_db_bytes([0; 16]),
            task_id: TaskId::from_trusted_db_bytes([0; 16]),
            run_cursor: None,
            run_page_size: 0,
        };
        validate_task_detail_request(&req).unwrap_err();
        req.workspace_id = WorkspaceId::new();
        validate_task_detail_request(&req).unwrap_err();
        req.task_id = TaskId::new();
        validate_task_detail_request(&req).unwrap();
    }

    #[test]
    fn validate_task_event_log_request_requires_workspace() {
        let req = TaskEventLogRequest {
            workspace_id: WorkspaceId::from_trusted_db_bytes([0; 16]),
            task_id: None,
            cursor: None,
            page_size: 0,
        };
        validate_task_event_log_request(&req).unwrap_err();
        let req = TaskEventLogRequest {
            workspace_id: WorkspaceId::new(),
            ..req
        };
        validate_task_event_log_request(&req).unwrap();
    }
}
