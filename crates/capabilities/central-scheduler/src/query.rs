//! Read contract for `central-scheduler`: `SchedulerRead` — the
//! keyed projections over the b35 scheduler tables
//! (`worker_registrations`, `session_attempts`, `node_leases`).
//!
//! Declaration-only: the durable rows project verbatim as
//! [`crate::domain::Worker`], [`crate::domain::SessionAttempt`], and
//! [`crate::domain::Lease`] — the reads exist so operator surfaces and
//! reconciliation audits can inspect the registered-worker ladder, a
//! node's attempt ledger, and a node's live lease without touching the
//! claim/expiry write paths. No locks, no writes, no journaled side
//! effects; the caller scope-checks the workspace/run/node through its
//! own projection first, matching the read-side convention the run
//! views apply.
//!
//! Upstream declares no `internal/scheduler` read port — the fleet
//! view's richer `WorkerRow`/`LeaseRow` projections are
//! `central-runview`'s own (they join node keys and compute
//! server-side beat ages); this contract carries only the rows this
//! capability owns.

use central_foundation::failure::Failure;
use central_foundation::identity::{SessionAttemptId, WorkerId, WorkflowNodeId, WorkspaceId};

use crate::domain::{Lease, SessionAttempt, Worker};

/// The read contract behind scheduler observability and audit
/// surfaces. Implemented by `central-adapter-postgres`; consumed by
/// operator views and the reconciler's evidence checks.
#[trait_variant::make(Send)]
pub trait SchedulerRead: Send + Sync + 'static {
    /// Every `worker_registrations` row in the workspace, most recent
    /// first — the fleet-style ladder view. Bounded by the host's
    /// worker count (one row per process start).
    async fn list_workers(&self, workspace_id: WorkspaceId) -> Result<Vec<Worker>, Failure>;

    /// The single registration row for `worker_id`; `None` when no
    /// such registration exists (or it belongs to another workspace —
    /// the caller scopes first).
    async fn load_worker(&self, worker_id: WorkerId) -> Result<Option<Worker>, Failure>;

    /// The node's per-attempt ledger — every `session_attempts` row for
    /// the node ordered by `attempt_seq`. This is the durable evidence
    /// the retry budget counts aggregate and the ambiguous-resolution
    /// surface renders. Bounded by the node's attempt budget in
    /// practice.
    async fn list_node_attempts(
        &self,
        node_id: WorkflowNodeId,
    ) -> Result<Vec<SessionAttempt>, Failure>;

    /// The node's live lease — the `node_leases` row with
    /// `released_at IS NULL` under `node_leases_live_node_idx`. `None`
    /// while the node is unclaimed; at most one row can ever match.
    async fn live_lease(&self, node_id: WorkflowNodeId) -> Result<Option<Lease>, Failure>;

    /// The single attempt row for `attempt_id`; `None` when no such
    /// attempt exists.
    async fn load_attempt(
        &self,
        attempt_id: SessionAttemptId,
    ) -> Result<Option<SessionAttempt>, Failure>;
}
