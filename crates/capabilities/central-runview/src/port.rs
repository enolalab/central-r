//! `central-runview` port — the domain-facing read seams over the
//! Phase-2 orchestration tables the operator UI renders (upstream
//! `internal/runview/port/port.go`). Every method is read-only — stores
//! already own the write paths and the views never write outside them.
//! No adapter types cross this boundary; `events_for_run` returns the
//! canonical [`RunEvent`] envelope verbatim so callers can drive
//! [`central_eventjournal::fold::fold`]/`compare_fold` without a second
//! projection.

use std::collections::BTreeMap;

use central_eventjournal::domain::RunEvent;
use central_foundation::failure::Failure;
use central_foundation::identity::{RunId, WorkflowNodeId, WorkspaceId};

use crate::domain::{
    AttemptRow, CheckpointRow, DeferredRow, GraphNode, LeaseRow, OutboxHealth, RunCursor, RunGraph,
    RunSummary, WorkerRow,
};

/// The read-projection seam backing the run, graph, node, lineage and
/// fleet views (upstream `runview/port.Reader`). All reads are plain
/// queries over the materialized tables plus the journal — no locks, no
/// writes, no journaled side effects.
///
/// Scoped lookups (`run_for_id`, `node_for_id`) answer a [`Failure`]
/// with kind `not_found` and code [`crate::domain::RUNVIEW_NOT_FOUND`]
/// for absent **and** cross-workspace rows — the two cases are
/// indistinguishable from the caller (the same non-disclosure the task
/// detail read applies).
#[trait_variant::make(Send)]
pub trait Reader: Send + Sync + 'static {
    /// The workspace's run list newest-first (`created_at DESC, id
    /// DESC`), keyset-paginated: `after` is the previous page's last
    /// `(created_at, id)` cursor, `None` for the first page, and
    /// `limit` bounds the page. Each row carries the run's node-state
    /// counts and the journal-derived begin/end marks.
    async fn list_runs(
        &self,
        workspace_id: WorkspaceId,
        after: Option<RunCursor>,
        limit: i64,
    ) -> Result<Vec<RunSummary>, Failure>;

    /// The workspace-scoped summary of one run — the run detail page's
    /// header row and the caller's existence/scope check in one.
    async fn run_for_id(
        &self,
        workspace_id: WorkspaceId,
        run_id: RunId,
    ) -> Result<RunSummary, Failure>;

    /// The workspace-scoped projection of one workflow node — the node
    /// detail page's header and the run it belongs to (`run_id`) in one
    /// row.
    async fn node_for_id(
        &self,
        workspace_id: WorkspaceId,
        node_id: WorkflowNodeId,
    ) -> Result<GraphNode, Failure>;

    /// The materialized DAG of one run: every `workflow_nodes` row
    /// projected with its latest journaled reason and every
    /// `workflow_edges` row in node keys. This is the same materialized
    /// state `compare_fold` is evaluated against. The caller
    /// scope-checks the run first (`run_for_id`); absent runs yield an
    /// empty graph, not an error.
    async fn graph_for_run(&self, run_id: RunId) -> Result<RunGraph, Failure>;

    /// The run's journaled events in seq order as the canonical
    /// [`RunEvent`] envelope. Feeds both the per-node timeline and
    /// `fold`/`compare_fold`.
    async fn events_for_run(&self, run_id: RunId) -> Result<Vec<RunEvent>, Failure>;

    /// The node's session-attempt ledger ordered by `attempt_seq`, each
    /// row carrying its degraded [`crate::domain::Versions`] record.
    async fn attempts_for_node(&self, node_id: WorkflowNodeId) -> Result<Vec<AttemptRow>, Failure>;

    /// Every session attempt of the run ordered by `(node_key,
    /// attempt_seq)` — the run view's attempt table.
    async fn attempts_for_run(&self, run_id: RunId) -> Result<Vec<AttemptRow>, Failure>;

    /// The materialized `{node_key: state}` map of one run — the
    /// `compare_fold` input.
    async fn nodes_current(&self, run_id: RunId) -> Result<BTreeMap<String, String>, Failure>;

    /// The workspace's registered workers with their last-beat ages,
    /// ordered by registration time.
    async fn workers(&self, workspace_id: WorkspaceId) -> Result<Vec<WorkerRow>, Failure>;

    /// The workspace's live leases (`released_at IS NULL`) with
    /// heartbeat ages, ordered by issue time.
    async fn live_leases(&self, workspace_id: WorkspaceId) -> Result<Vec<LeaseRow>, Failure>;

    /// The run's journaled `admission_deferred` events in claim-FIFO
    /// order (`COALESCE(ready_at, created_at)`, `node_key`) — the queue
    /// position is the FIFO order itself, no stored position exists.
    async fn deferred_admissions(&self, run_id: RunId) -> Result<Vec<DeferredRow>, Failure>;

    /// The run's resume checkpoints newest first, each projected with
    /// its anchor's `node_key`.
    async fn checkpoints_for_run(&self, run_id: RunId) -> Result<Vec<CheckpointRow>, Failure>;

    /// The workspace one run belongs to — the workspace scope check
    /// every run-scoped view applies before rendering anything about
    /// the run. `Ok(None)` when no run carries the id (upstream's
    /// `found = false`).
    async fn run_scope(&self, run_id: RunId) -> Result<Option<WorkspaceId>, Failure>;

    /// The transactional outbox's unpublished depth and
    /// oldest-unpublished anchor — the same probe the publisher's stall
    /// detector reads.
    async fn outbox_health(&self) -> Result<OutboxHealth, Failure>;
}
