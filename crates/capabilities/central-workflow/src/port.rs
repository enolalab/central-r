//! The domain-facing seam to the append-only workflow graph — the port
//! of `central/internal/workflow/port/port.go` (`GraphStore`), renamed
//! `WorkflowStore` per the crate's boundary row
//! (rust-application-boundaries.md §2). No adapter types cross this
//! boundary.
//!
//! Lock anchor (spec-6 OQ-1 serialization point): every mutating method
//! commits its state change and its canonical `run_events` rows in ONE
//! transaction whose first write-side statement is
//! `SELECT … FROM central.runs WHERE id = $1 FOR UPDATE` — the same
//! serialization point the event journal shares. Lock order is run row
//! then node row(s), everywhere; committed rows are append-only — the
//! only UPDATE targets `workflow_nodes.state`/`ready_at`, and
//! `ON CONFLICT` clauses make re-emission and replay exact-replay
//! successes rather than failures. A [`GraphChangeSet`] the domain
//! planners produced is applied under that lock: each
//! [`crate::domain::NodeTransition::expected_state`] is re-verified on
//! the locked row before any write lands.
//!
//! The emit path's validation seams — [`crate::validate::HarnessRegistry`],
//! [`crate::validate::ArtifactFinalizedChecker`], and the effective
//! [`crate::domain::Caps`] — are injected into the implementing store
//! at construction (upstream `NewStore` + fields), not threaded through
//! this trait; unset seams are fail-closed inside the transaction.
//!
//! OWNING PACKET: P2A01/P2A02/P2A03. SLICE: 2A.

use central_foundation::failure::Failure;
use central_foundation::identity::{RunId, WorkflowNodeId};

use crate::domain::{ChildSpec, Edge, EmitResult, Node, NodeStatus};

/// The domain-facing seam to the append-only workflow graph (upstream
/// `GraphStore`). Every mutating method commits its state change and
/// its canonical journal event in one transaction anchored on the
/// run-row lock; there is exactly one journal append path.
#[trait_variant::make(Send)]
pub trait WorkflowStore: Send + Sync + 'static {
    /// Validates one `central.child-spec/v1` emission and appends its
    /// nodes and edges atomically (upstream `EmitBatch`) in one
    /// transaction anchored on the run-row lock. The commit sequence is
    /// contract, in order:
    ///
    /// 1. **Lock + parent resolution.** `SELECT workspace_id FROM
    ///    central.runs WHERE id = $1 FOR UPDATE`; a missing run row is
    ///    `INVALID`/`WORKFLOW_RUN_NOT_FOUND`. `parent_id: None` emits
    ///    the run's roots: the depth base is `-1` (batch roots land at
    ///    absolute depth 0) and `parent_remaining` is unbounded. A
    ///    `Some` parent reads its `run_id`, absolute `depth`, and
    ///    remaining budget ceilings from `central.workflow_nodes`
    ///    inside the same transaction; a missing parent row is
    ///    `INVALID`/`WORKFLOW_PARENT_NOT_FOUND`, and a parent whose
    ///    `run_id` differs is `DENIED`/`WORKFLOW_PARENT_RUN_MISMATCH`.
    /// 2. **Dedup partition precedes validation.** Each child whose
    ///    `(run_id, node_key)` is already recorded compares the
    ///    recorded `spec_fingerprint`: an equal fingerprint dedupes to
    ///    the committed node, a different one rejects the whole batch
    ///    as `CONFLICT`/`DUPLICATE_IDEMPOTENCY_KEY` with the recorded
    ///    row standing. [`crate::validate::validate_batch`] is called
    ///    with ONLY the novel children (as a `ChildSpec` carrying the
    ///    batch's `version`) while `existing_keys` still contains every
    ///    committed key — feeding it the full batch would falsely
    ///    reject an exact replay on the unique-key rule. Validation is
    ///    skipped only when the novel set is empty AND
    ///    `batch.version == CHILD_SPEC_VERSION`: the fully-deduped
    ///    replay of an on-version batch is the one path that skips it;
    ///    an off-version envelope validates even with zero novel
    ///    children.
    /// 3. **Effective caps.** The store's configured
    ///    [`crate::domain::Caps`] applies; a zero `Caps` falls back to
    ///    [`crate::domain::Caps::locked`]. The validator
    ///    sees `max_depth` shifted by the parent's absolute depth
    ///    (`caps.max_depth - parent_depth`), because it evaluates
    ///    batch-internal depth where batch roots are 1.
    /// 4. **Commit.** Novel children insert at absolute depth
    ///    `parent_depth + batch_depth` ([`crate::validate::batch_depths`],
    ///    batch roots = 1); a child omitting `budget` inherits
    ///    `parent_remaining`, recorded explicitly on the row.
    ///    `ON CONFLICT (run_id, node_key) DO NOTHING` plus re-select is
    ///    the second idempotency line and resolves to the committed
    ///    row. Each `depends_on` inserts an `ordering` edge
    ///    dependent→prerequisite; each `input_artifact_refs` entry
    ///    resolves its producer via `central.artifact_produce_edges`
    ///    `(run_id, artifact_id)` and, when an in-run producer exists,
    ///    inserts an `artifact` edge dependent→producer carrying the
    ///    artifact id — a ref with no in-run producer inserts no edge
    ///    and stays declared on the node's `input_artifact_refs` (the
    ///    read-scope union reads both sources; this is the RTM-14
    ///    declared-read edge). Edge lookups resolve through the
    ///    batch-wide node_key→id map covering committed, deduped, and
    ///    just-inserted nodes; edge inserts dedupe on their key.
    ///    `node_declared` journals (actor `leader`) for newly inserted
    ///    nodes only; each replayed child journals `command_deduped`.
    ///
    /// On violation it journals `child_spec_rejected` (reason_code
    /// `SPEC_VALIDATION_FAILED`, `node_id` bound to the emitting
    /// parent) in the same commit and returns
    /// `EmitResult{rejected: Some(..)}` without error — rejection is
    /// data, not a crash. `EmitResult.nodes` lists every batch child in
    /// emission order — the inserted node, or the committed node a
    /// replay deduped to.
    async fn emit_batch(
        &self,
        run_id: RunId,
        parent_id: Option<WorkflowNodeId>,
        batch: ChildSpec,
    ) -> Result<EmitResult, Failure>;

    /// Moves one node along the declared state machine and journals the
    /// matching event in the same commit (upstream `Transition`). An
    /// illegal transition returns a `DENIED`/`INVALID_NODE_TRANSITION`
    /// failure and leaves the graph unchanged; a `→ ready` write stamps
    /// `ready_at`.
    async fn transition(
        &self,
        node_id: WorkflowNodeId,
        to: NodeStatus,
        actor: &str,
        reason: Option<&str>,
    ) -> Result<(), Failure>;

    /// Flips every `declared` node of the run whose `ordering` in-edges
    /// all lead to `succeeded` prerequisites, whose `artifact` in-edges
    /// all name finalized artifacts, and whose `not_before` gate has
    /// passed — journaling `node_ready` per node in the same commit
    /// (upstream `RecomputeReady`). It is invoked by callers after node
    /// transitions and artifact finalizations — it never polls. The
    /// return value lists the newly-ready node ids.
    async fn recompute_ready(&self, run_id: RunId) -> Result<Vec<WorkflowNodeId>, Failure>;

    /// Cascades cancellation over the node's non-terminal descendants
    /// in one commit (spec-1 default policy: cascade — upstream
    /// `CancelNode`). `declared`/`ready` nodes transition to `cancelled`
    /// with a `node_cancelled` event each; `dispatched`/`running` nodes
    /// keep their state and receive a `cancel_requested` intent event
    /// the harness control layer consumes; `attempt_ambiguous` nodes
    /// park untouched while the cascade flows past them to their own
    /// descendants. Cancelling an already-cancelled node is an
    /// idempotent replay success; a `succeeded`/`failed_terminal` root
    /// is a `DENIED` failure. The return value lists every node the
    /// cascade reached — immediate, signalled, and blocked — in the
    /// plan's group order (upstream's doc comment says "BFS order" but
    /// `CancelNode` returns `immediate ++ signal ++ blocked`, each group
    /// internally BFS-ordered — the implementation is authoritative).
    async fn cancel_node(
        &self,
        node_id: WorkflowNodeId,
        actor: &str,
    ) -> Result<Vec<WorkflowNodeId>, Failure>;

    /// Records the operator's decision on an `attempt_ambiguous` node
    /// (upstream `ResolveAmbiguous`): `central.attempt_decisions` is
    /// one-row-ever per parked attempt (spec-5's key table), an
    /// `attempt_decision` event is journaled, and a `rerun` decision
    /// additionally returns the node to `ready` via `node_ready`. A
    /// `resume` decision leaves the node parked for Slice 2B's
    /// harness-native resume. `fingerprint` is the SHA-256 payload
    /// fingerprint the replay compare binds; replaying the recorded
    /// decision and fingerprint dedupes to `command_deduped`, a
    /// differing decision or fingerprint is `DENIED`, and a node that
    /// is not `attempt_ambiguous` is `DENIED`.
    async fn resolve_ambiguous(
        &self,
        node_id: WorkflowNodeId,
        decision: &str,
        fingerprint: [u8; 32],
        actor: &str,
    ) -> Result<(), Failure>;

    /// One node by id; `INVALID`/`WORKFLOW_NODE_NOT_FOUND` when absent.
    async fn node(&self, id: WorkflowNodeId) -> Result<Node, Failure>;

    /// Every committed node of a run, ordered by `(created_at, id)`.
    async fn nodes_for_run(&self, run_id: RunId) -> Result<Vec<Node>, Failure>;

    /// Every committed edge of a run, ordered by `(created_at, id)`.
    async fn edges_for_run(&self, run_id: RunId) -> Result<Vec<Edge>, Failure>;
}
