//! `central-runview` domain — the read-projection types the operator UI
//! renders (upstream `internal/runview/domain.go`): the workspace run
//! list, the per-run DAG, attempt history, checkpoint records, and the
//! fleet observability surface. Every type is a pure read model — no
//! sqlx, no adapter types, no write path; stores already own commands
//! and the UI never writes outside them.
//!
//! The crate is deliberately not a closed domain root: its read port
//! returns the canonical [`central_eventjournal::domain::RunEvent`]
//! envelope verbatim so the run view drives
//! [`central_eventjournal::fold`] and `compare_fold` directly (the
//! approved DAG edge).

use std::collections::BTreeMap;

use central_foundation::identity::{
    ArtifactId, ResumeCheckpointId, RunEventId, RunId, SessionAttemptId, TaskId, WorkerId,
    WorkflowNodeId, WorkspaceId,
};
use time::OffsetDateTime;

/// The `NOT_FOUND` failure code every scoped projection lookup answers
/// when the named run or node does not exist — or exists in another
/// workspace, since the scoped lookups never distinguish the two
/// (upstream `runview.ErrNotFound`, the same non-disclosure the task
/// detail read applies).
pub const RUNVIEW_NOT_FOUND: &str = "RUNVIEW_NOT_FOUND";

// ---------------------------------------------------------------------------
// Run list (keyset-paginated)
// ---------------------------------------------------------------------------

/// One row of the workspace run list (upstream `runview.RunSummary`).
///
/// `started_at`/`ended_at` are journal-derived: `central.runs` carries
/// no lifecycle timestamps of its own (`created_at`/`updated_at` only),
/// so the projection exposes the run's first and last
/// `run_events.recorded_at` as the observable begin/end marks. Both are
/// `None` for a run that has journaled nothing. `deadline` is the v37
/// caller-supplied run deadline; `None` means none was declared.
/// `node_counts` maps node state (the v33 `workflow_nodes_state_check`
/// vocabulary) to the run's node count in that state; a run with no
/// nodes reports an empty map.
#[derive(Debug, Clone)]
pub struct RunSummary {
    pub id: RunId,
    pub task_id: TaskId,
    pub workspace_id: WorkspaceId,
    pub index: i64,
    /// The persisted `runs.status` token verbatim — unknown statuses
    /// fail open through the projection rather than erroring.
    pub status: String,
    pub run_key: Option<String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub started_at: Option<OffsetDateTime>,
    pub ended_at: Option<OffsetDateTime>,
    pub deadline: Option<OffsetDateTime>,
    pub node_counts: BTreeMap<String, i64>,
}

/// The `list_runs` keyset cursor (upstream `runview.RunCursor`): the
/// `(created_at, id)` pair of the last row of the previous page. The
/// ordering is newest first — `(created_at DESC, id DESC)` — matching
/// the task adapter's run listing and the
/// `runs_workspace_created_id_idx` index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunCursor {
    pub created_at: OffsetDateTime,
    pub id: RunId,
}

// ---------------------------------------------------------------------------
// Graph projection
// ---------------------------------------------------------------------------

/// The materialized state of one workflow node projected for the DAG
/// view (upstream `runview.GraphNode`). `key` is the run-unique
/// `node_key`; `status` carries the v33 state vocabulary verbatim;
/// `reason` is the node's most recently journaled `reason_code` (the
/// "why" of the current state — parked, refused, cancelled), empty when
/// no event carried one. `parent_key` is the parent's `node_key` for
/// nesting; `None` for roots.
#[derive(Debug, Clone)]
pub struct GraphNode {
    pub id: WorkflowNodeId,
    pub run_id: RunId,
    pub key: String,
    pub status: String,
    pub reason: String,
    pub attempt_count: i32,
    pub max_attempts: i32,
    pub not_before: Option<OffsetDateTime>,
    pub parent_key: Option<String>,
    pub created_at: OffsetDateTime,
}

/// One dependency edge of the run's DAG expressed in node keys
/// (upstream `runview.GraphEdge`): the dependent (`to_key`) waits on
/// the prerequisite (`from_key`). `kind` is the v33 edge vocabulary —
/// `ordering` waits for success, `artifact` waits for a finalized
/// artifact and declares the read. `artifact_id` is `Some` exactly on
/// `artifact` edges.
#[derive(Debug, Clone)]
pub struct GraphEdge {
    pub from_key: String,
    pub to_key: String,
    pub kind: String,
    pub artifact_id: Option<ArtifactId>,
}

/// The whole materialized DAG of one run (upstream `runview.RunGraph`):
/// the node and edge sets the fold-check compares against (the same
/// rows `eventjournal::fold` reconstructs from the journal).
#[derive(Debug, Clone, Default)]
pub struct RunGraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

// ---------------------------------------------------------------------------
// Attempt history
// ---------------------------------------------------------------------------

/// What the write side actually persisted about one attempt's
/// provenance (upstream `runview.Versions`, the degraded-versions note
/// of the slice plan): `session_attempts` carries NO
/// spec_version/adapter/model/digest/prompt_ref columns, so the only
/// real sources are `harness_attempts.adapter_version`/
/// `harness_version` (joined via `session_attempts.harness_attempt_id`)
/// and the node's spec JSONB. `adapter_version`/`harness_version` are
/// `None` when the attempt never started a harness attempt or the
/// column was NULL. `spec_extras` flattens the scalar members of the
/// spec's `"versions"` object when the emission recorded one.
/// `prompt_ref_artifact_id` is the artifact id the spec's prompt_ref
/// pair names when present; the write side recorded none, so it is
/// `None` almost everywhere and the view renders "not recorded" rather
/// than fabricating.
#[derive(Debug, Clone, Default)]
pub struct Versions {
    pub adapter_version: Option<String>,
    pub harness_version: Option<String>,
    pub spec_extras: BTreeMap<String, String>,
    pub prompt_ref_artifact_id: Option<ArtifactId>,
}

/// One `session_attempts` row projected for the attempt-history table
/// (upstream `runview.AttemptRow`), joined with its node's key so
/// run-scope listings render without a second lookup. `reason_code` is
/// the attempt's `dispatch_reason_code` (`None` while none was
/// recorded). `claimed_at` is the row's NOT NULL `claimed_at`;
/// `started_at`/`ended_at` stay `None` until the dispatch path stamps
/// them.
#[derive(Debug, Clone)]
pub struct AttemptRow {
    pub id: SessionAttemptId,
    pub node_id: WorkflowNodeId,
    pub node_key: String,
    pub seq: i32,
    pub state: String,
    pub reason_code: Option<String>,
    pub worker_id: Option<WorkerId>,
    pub claimed_at: OffsetDateTime,
    pub started_at: Option<OffsetDateTime>,
    pub ended_at: Option<OffsetDateTime>,
    pub versions: Versions,
}

// ---------------------------------------------------------------------------
// Checkpoints
// ---------------------------------------------------------------------------

/// One `resume_checkpoints` row projected for the run view (upstream
/// `runview.CheckpointRow`): the caller-supplied idempotency coordinate
/// (`seq`, the v37 `checkpoint_seq`), the retention class, the anchor's
/// `node_key`, and the write timestamp.
#[derive(Debug, Clone)]
pub struct CheckpointRow {
    pub id: ResumeCheckpointId,
    pub seq: i64,
    pub gc_class: String,
    pub anchor_node_key: String,
    pub created_at: OffsetDateTime,
}

// ---------------------------------------------------------------------------
// Fleet observability
// ---------------------------------------------------------------------------

/// One `worker_registrations` row projected for the fleet view
/// (upstream `runview.WorkerRow`), with the last-beat age computed
/// server-side (the suspect/lost banner thresholds are the scheduler
/// domain's `MISSED_BEATS_SUSPECT`/`MISSED_BEATS_LOST` — the view
/// renders, the domain judges).
#[derive(Debug, Clone)]
pub struct WorkerRow {
    pub id: WorkerId,
    pub workspace_id: WorkspaceId,
    pub protocol_version: i32,
    pub harness_kinds: Vec<String>,
    pub workspace_kinds: Vec<String>,
    pub max_concurrent_attempts: i32,
    pub state: String,
    pub registered_at: OffsetDateTime,
    pub last_seen_at: Option<OffsetDateTime>,
    /// `now() - last_seen_at` measured in the database; `None` when the
    /// worker never heartbeated.
    pub beat_age_seconds: Option<i64>,
    pub deregistered_at: Option<OffsetDateTime>,
}

/// One live (`released_at IS NULL`) `node_leases` row projected for the
/// fleet view (upstream `runview.LeaseRow`), joined to the node's key
/// and the attempt's coordinates so a lease row renders its subject
/// without lookups. `heartbeat_age_seconds` is the server-side
/// `now() - last_heartbeat_at` age the suspect/lost banner thresholds
/// evaluate.
#[derive(Debug, Clone)]
pub struct LeaseRow {
    pub id: central_foundation::identity::NodeLeaseId,
    pub run_id: RunId,
    pub node_id: WorkflowNodeId,
    pub node_key: String,
    pub attempt_id: SessionAttemptId,
    pub attempt_seq: i32,
    pub worker_id: WorkerId,
    pub issued_at: OffsetDateTime,
    pub last_heartbeat_at: OffsetDateTime,
    pub heartbeat_age_seconds: i64,
    pub expires_at: OffsetDateTime,
    pub heartbeat_interval_sec: i32,
}

/// One journaled `admission_deferred` event (upstream
/// `runview.DeferredRow`; the `CAPACITY_ADMISSION_DEFERRED` detail lives
/// in `reason_code`) projected with its node's current claim-queue
/// position evidence. No stored queue position exists — ordering is the
/// claim FIFO itself: `COALESCE(ready_at, created_at)` then `node_key`.
#[derive(Debug, Clone)]
pub struct DeferredRow {
    pub event_id: RunEventId,
    pub run_id: RunId,
    pub seq: i64,
    pub node_id: WorkflowNodeId,
    pub node_key: String,
    pub reason_code: Option<String>,
    pub ready_at: Option<OffsetDateTime>,
    pub recorded_at: OffsetDateTime,
}

/// The transactional-outbox stall probe (upstream
/// `runview.OutboxHealth`): the unpublished depth and the oldest
/// unpublished row's age anchor. `oldest_unpublished` is `None` when
/// the backlog is empty. Values come from the eventjournal adapter's
/// `unpublished_backlog` — the same probe the publisher's stall
/// detector reads.
#[derive(Debug, Clone, Copy, Default)]
pub struct OutboxHealth {
    pub unpublished_depth: i64,
    pub oldest_unpublished: Option<OffsetDateTime>,
}

/// The assembled fleet page projection (upstream `runview.FleetView`):
/// registered workers, the live lease set, and the outbox health card.
/// Deferred admissions arrive per run via `deferred_admissions` and
/// group here by the page.
#[derive(Debug, Clone, Default)]
pub struct FleetView {
    pub workers: Vec<WorkerRow>,
    pub leases: Vec<LeaseRow>,
    pub deferred: Vec<DeferredRow>,
    pub outbox: OutboxHealth,
}
