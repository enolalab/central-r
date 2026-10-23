//! Workflow domain — pure synchronous port of
//! `central/internal/workflow/domain.go` (Phase-2 Slice 2A, b33).
//!
//! Owns the node state machine, the edge and workspace vocabularies, the
//! `central.child-spec/v1` envelope, the locked Phase-2 concurrency caps,
//! the workflow-domain [`Failure`] taxonomy, and the [`GraphChangeSet`]
//! write unit every graph mutation produces. Migration b33 pins the same
//! vocabularies in `workflow_nodes_state_check`,
//! `workflow_nodes_workspace_kind_check`, and `workflow_edges_kind_check`
//! — the tests below keep the two sides in step.
//!
//! It contains no persistence, transport, or adapter types: every
//! timestamp arrives as caller-supplied durable evidence and this module
//! never reads a clock.
//!
//! OWNING PACKET: P2A01/P2A02. SLICE: 2A.

use std::collections::BTreeMap;
use std::fmt;

use central_foundation::failure::{Failure as FoundationFailure, FailureKind};
use central_foundation::identity::{
    ArtifactId, RunId, SessionAttemptId, WorkflowEdgeId, WorkflowNodeId, WorkspaceId,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

// ---------------------------------------------------------------------------
// Node status machine
// ---------------------------------------------------------------------------

/// The state of one workflow node inside the
/// `declared → ready → dispatched → running → succeeded` machine with the
/// `failed_terminal`, `attempt_ambiguous`, and `cancelled` branches the
/// Phase-2 workflow spec declares. Migration b33 pins the same vocabulary
/// in `workflow_nodes_state_check`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NodeStatus {
    /// `declared` — the node exists but its prerequisites are not all
    /// satisfied.
    Declared,
    /// `ready` — every ordering prerequisite has succeeded and every
    /// artifact prerequisite is finalized; the node may be claimed.
    Ready,
    /// `dispatched` — the scheduler claimed the node and is preparing or
    /// launching its session attempt.
    Dispatched,
    /// `running` — an attempt is live against the node.
    Running,
    /// `succeeded` — the terminal success state.
    Succeeded,
    /// `failed_terminal` — the terminal failure state: no automatic
    /// rerun.
    FailedTerminal,
    /// `attempt_ambiguous` — parked for an operator decision: the
    /// attempt's outcome is unknown and Phase 2 never auto-reruns.
    AttemptAmbiguous,
    /// `cancelled` — the terminal cancelled state.
    Cancelled,
}

impl NodeStatus {
    /// Every status in declaration order. The set must equal migration
    /// b33's `workflow_nodes_state_check` list.
    pub const ALL: [Self; 8] = [
        Self::Declared,
        Self::Ready,
        Self::Dispatched,
        Self::Running,
        Self::Succeeded,
        Self::FailedTerminal,
        Self::AttemptAmbiguous,
        Self::Cancelled,
    ];

    /// The persisted/journaled text form (upstream `String()`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Declared => "declared",
            Self::Ready => "ready",
            Self::Dispatched => "dispatched",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::FailedTerminal => "failed_terminal",
            Self::AttemptAmbiguous => "attempt_ambiguous",
            Self::Cancelled => "cancelled",
        }
    }

    /// Parses the persisted text form; `None` on anything outside the
    /// declared vocabulary.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|status| status.as_str() == s)
    }

    /// Whether the status is terminal for a node (upstream
    /// `IsTerminal`).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::FailedTerminal | Self::Cancelled
        )
    }

    /// The legal forward transitions for a node status per the spec-1
    /// state machine (upstream `ValidTransitions`): the happy path plus
    /// the failure branches. A failed attempt returns a
    /// dispatched/running node to `ready` only through the retry policy;
    /// an ambiguous attempt is resolved by the operator — harness-native
    /// resume returns it to `running`, a fresh rerun returns it to
    /// `ready`, and abandonment ends it `failed_terminal` or `cancelled`.
    /// `failed_terminal` from `ready` is the Slice-2D (spec-4 decision 5)
    /// node-timeout landing: the node's aggregate bound covers backoff
    /// waits, so a bound that expires while the node waits `ready` for
    /// `not_before` still lands terminal. Terminal states admit no
    /// transition.
    #[must_use]
    pub fn valid_transitions(self) -> &'static [NodeStatus] {
        match self {
            Self::Declared => &[Self::Ready, Self::Cancelled],
            Self::Ready => &[Self::Dispatched, Self::FailedTerminal, Self::Cancelled],
            Self::Dispatched => &[
                Self::Running,
                Self::Ready,
                Self::FailedTerminal,
                Self::AttemptAmbiguous,
                Self::Cancelled,
            ],
            Self::Running => &[
                Self::Succeeded,
                Self::Ready,
                Self::FailedTerminal,
                Self::AttemptAmbiguous,
                Self::Cancelled,
            ],
            Self::AttemptAmbiguous => &[
                Self::Running,
                Self::Ready,
                Self::FailedTerminal,
                Self::Cancelled,
            ],
            Self::Succeeded | Self::FailedTerminal | Self::Cancelled => &[],
        }
    }

    /// Whether `to` is a legal forward transition (upstream
    /// `CanTransition`).
    #[must_use]
    pub fn can_transition(self, to: NodeStatus) -> bool {
        self.valid_transitions().contains(&to)
    }
}

impl fmt::Display for NodeStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Edge and workspace vocabularies
// ---------------------------------------------------------------------------

/// Classifies a dependency edge. Migration b33 pins the same vocabulary
/// in `workflow_edges_kind_check`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EdgeKind {
    /// `ordering` — the dependent may dispatch only after the
    /// prerequisite node reaches `succeeded`.
    Ordering,
    /// `artifact` — the dependent waits for a specific artifact to be
    /// finalized; the edge also declares the read for lineage.
    Artifact,
}

impl EdgeKind {
    /// Every edge kind in declaration order.
    pub const ALL: [Self; 2] = [Self::Ordering, Self::Artifact];

    /// The persisted text form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ordering => "ordering",
            Self::Artifact => "artifact",
        }
    }

    /// Parses the persisted text form; `None` on anything else.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|kind| kind.as_str() == s)
    }
}

impl fmt::Display for EdgeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The workspace isolation a node runs under. Migration b33 pins the
/// same vocabulary in `workflow_nodes_workspace_kind_check`; spec-1
/// calls them "code" and "plain" work — the schema names the mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum WorkspaceKind {
    /// `worktree` — a dedicated git worktree for code work.
    Worktree,
    /// `directory` — a private scratch directory for non-code work.
    Directory,
}

impl WorkspaceKind {
    /// Every workspace kind in declaration order.
    pub const ALL: [Self; 2] = [Self::Worktree, Self::Directory];

    /// The persisted text form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Worktree => "worktree",
            Self::Directory => "directory",
        }
    }

    /// Parses the persisted text form; `None` on anything else — the
    /// validation-side equivalent of upstream `Known()` on the declared
    /// input string.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|kind| kind.as_str() == s)
    }
}

impl fmt::Display for WorkspaceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Graph value objects
// ---------------------------------------------------------------------------

/// A declared artifact reference: the artifact's identity plus the
/// checksum the reader must observe. Payloads and lineage rows carry
/// `(artifact_id, checksum)` pairs only — bodies stay in object storage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRef {
    /// The artifact identity.
    pub artifact_id: ArtifactId,
    /// The checksum the declared read binds.
    pub checksum: String,
}

/// One unit of orchestrated work — the `central.workflow_nodes` row.
/// Its stable identity is `(run_id, node_key)`: the idempotency key a
/// re-emitted spec dedupes on.
#[derive(Debug, Clone, PartialEq)]
pub struct Node {
    /// The node identity.
    pub id: WorkflowNodeId,
    /// The owning run.
    pub run_id: RunId,
    /// The owning workspace.
    pub workspace_id: WorkspaceId,
    /// The leader-chosen slug — half of the emission idempotency key.
    pub node_key: String,
    /// The emitting parent node; `None` for run-root nodes.
    pub parent_id: Option<WorkflowNodeId>,
    /// The harness adapter name the node dispatches under.
    pub harness: String,
    /// The `workspace_kind` column verbatim (`worktree` | `directory`)
    /// — carried as raw text because a row recorded by a build with a
    /// different vocabulary must project without re-validation;
    /// [`WorkspaceKind::parse`] is the declared-input check.
    pub workspace_kind: String,
    /// The absolute depth: `0` for a batch emitted without a parent,
    /// otherwise the emitting parent's depth plus the batch-internal
    /// depth [`crate::validate::batch_depths`] computes.
    pub depth: i32,
    /// The current node state.
    pub state: NodeStatus,
    /// The node's wall-clock ceiling (seconds); `None` is unbounded.
    pub budget_wall_clock_sec: Option<i64>,
    /// The node's cost ceiling (micro-USD); `None` is unbounded.
    pub budget_cost_micro_usd: Option<i64>,
    /// The per-node attempt ceiling (`max_attempts >= 1`).
    pub max_attempts: i32,
    /// Attempts consumed so far.
    pub attempt_count: i32,
    /// The retry/backoff eligibility gate: a `ready` node whose
    /// `not_before` is in the future is not yet claimable (Slice-2D
    /// `retry_at` lands here).
    pub not_before: Option<OffsetDateTime>,
    /// The declared input refs the node reads.
    pub input_artifact_refs: Vec<ArtifactRef>,
    /// The child's `central.child-spec/v1` spec JSON as recorded.
    pub spec: serde_json::Value,
    /// The SHA-256 of the canonical child-spec JSON the emit path
    /// recorded — the spec-5 replay-compare value (b37 column); `None`
    /// on rows predating it.
    pub spec_fingerprint: Option<Vec<u8>>,
    /// The node's aggregate bound measured from first dispatch (spec-4
    /// decision 5; b37 column) — a duration, never an absolute deadline,
    /// so queue time cannot count against it.
    pub node_timeout_seconds: Option<i64>,
    /// When the node last entered `ready` — the claim queue's FIFO key
    /// (b35 column); `None` until first ready.
    pub ready_at: Option<OffsetDateTime>,
    /// Durable creation timestamp.
    pub created_at: OffsetDateTime,
}

/// One committed dependency edge: dependent waits on prerequisite.
/// `Artifact` edges additionally carry the artifact the dependent
/// reads — the `central.workflow_edges` row.
#[derive(Debug, Clone, PartialEq)]
pub struct Edge {
    /// The edge identity.
    pub id: WorkflowEdgeId,
    /// The owning run.
    pub run_id: RunId,
    /// The dependent (waiting) node.
    pub dependent_node_id: WorkflowNodeId,
    /// The prerequisite node.
    pub prerequisite_node_id: WorkflowNodeId,
    /// The edge kind.
    pub kind: EdgeKind,
    /// The artifact an `Artifact` edge waits on; `None` is malformed
    /// and blocks readiness exactly like an unfinalized artifact.
    pub artifact_id: Option<ArtifactId>,
    /// Durable creation timestamp.
    pub created_at: OffsetDateTime,
}

/// Bounds one node's session wall-clock and reported cost. A `None`
/// field is unset: at validation a child omitting a ceiling inherits the
/// parent's remaining budget for that bound (concurrency spec decision
/// 3); `None` on the parent side means unbounded.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetCeiling {
    /// Wall-clock bound in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wall_clock_seconds: Option<i64>,
    /// Cost bound in micro-USD.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_micro_usd: Option<i64>,
}

/// The locked Phase-2 concurrency defaults (OQ-3, user approved):
/// global parallel sessions, the deepest node level a run may reach,
/// and the node-count ceiling per run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Caps {
    /// Global parallel session bound.
    pub max_parallel_sessions: u32,
    /// The deepest level a run's graph may reach.
    pub max_depth: u32,
    /// The per-run node-count ceiling.
    pub max_nodes_per_run: u32,
}

impl Caps {
    /// The user-approved defaults: 4 parallel sessions, depth 3, 64
    /// nodes per run (upstream `DefaultCaps`).
    #[must_use]
    pub const fn locked() -> Self {
        Self {
            max_parallel_sessions: 4,
            max_depth: 3,
            max_nodes_per_run: 64,
        }
    }
}

// ---------------------------------------------------------------------------
// central.child-spec/v1 envelope
// ---------------------------------------------------------------------------

/// The only child-spec schema version Phase 2 admits (upstream
/// `ChildSpecVersion`).
pub const CHILD_SPEC_VERSION: &str = "central.child-spec/v1";

/// A leader-emitted batch of proposed child nodes. Validation is atomic:
/// any violation rejects the whole batch (`child_spec_rejected`) before
/// any node exists.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChildSpec {
    /// The envelope version — must equal [`CHILD_SPEC_VERSION`].
    pub version: String,
    /// The proposed children.
    pub children: Vec<ChildSpecNode>,
}

/// One proposed child in a [`ChildSpec`] batch.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChildSpecNode {
    /// The leader-chosen idempotency slug; unique within the run.
    pub node_key: String,
    /// Node keys this child orders behind.
    #[serde(default)]
    pub depends_on: Vec<String>,
    /// The harness adapter name.
    pub harness: String,
    /// The workspace isolation kind (`worktree` | `directory`).
    pub workspace_kind: String,
    /// Declared artifact inputs — `(artifact_id, checksum)` pairs only.
    #[serde(default)]
    pub input_artifact_refs: Vec<ArtifactRef>,
    /// Declared ceilings; an omitted ceiling inherits the parent's
    /// remaining budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<BudgetCeiling>,

    // The Slice-2D retry/timeout fields below are optional and additive:
    // a `central.child-spec/v1` batch that omits them is unchanged. All
    // persist inside the node's spec jsonb; `node_timeout_seconds`
    // additionally lands in its own column for the timeout sweep.
    /// The compensation hook evaluated once when the node lands
    /// `failed_terminal` (spec-4 decision 6): the Central-managed values
    /// `cleanup_workspace` and `retain_artifacts` execute; anything else
    /// is journaled `compensation_requested`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub on_terminal_failure: String,
    /// Bounds the node's elapsed time across all its attempts and
    /// backoff waits, measured from first dispatch — a bound, not a
    /// retryable class; expiry is `failed_terminal`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_timeout_seconds: Option<i64>,
    /// The spec-hint input to the dispatch-time effective session
    /// ceiling — `min(spec_hint, node_remaining, workflow_remaining)`;
    /// it may tighten, never loosen, parent bounds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_timeout_seconds: Option<i64>,
    /// Overrides the per-retryable-class attempt limits (spec-4
    /// decision 3). Keys name retryable classes
    /// (`transient`/`dispatch_infra`/`session_timeout`); values must be
    /// `>= 1` and no higher than the policy defaults — declared limits
    /// may tighten, never inflate, the run ceiling.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub max_attempts: BTreeMap<String, i64>,
    /// Overrides the absolute per-node attempt ceiling (default 5),
    /// bounded the same way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_attempts_total: Option<i64>,
}

// ---------------------------------------------------------------------------
// Emit result
// ---------------------------------------------------------------------------

/// The outcome of one `WorkflowStore::emit_batch` call (upstream
/// `EmitResult`). `nodes` lists the committed nodes of the batch in
/// emission order — newly inserted nodes and, for an idempotent
/// re-emission, the existing nodes the batch deduped to. `rejected` is
/// `Some` exactly when the batch failed validation: then `nodes` is
/// empty, the graph is unchanged, and the store has journaled the
/// matching `child_spec_rejected` event in the same commit.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EmitResult {
    /// The batch's committed nodes in emission order.
    pub nodes: Vec<Node>,
    /// The atomic validation refusal, when the batch failed.
    pub rejected: Option<crate::validate::Rejection>,
}

// ---------------------------------------------------------------------------
// Graph change set — the atomic write unit
// ---------------------------------------------------------------------------

/// All durable graph mutations one workflow command produces. The
/// adapter commits a change set in ONE transaction anchored on the
/// run-row lock (`SELECT … FROM central.runs … FOR UPDATE` — the spec-6
/// OQ-1 serialization point): [`Self::node_inserts`] and
/// [`Self::edge_inserts`] append idempotently on their unique keys,
/// [`Self::transitions`] apply only while each row still carries its
/// expected state, and [`Self::event_intents`] journal in order. There
/// is no `workflow_nodes.version` column — the expected node state IS
/// the version guard (see [`NodeTransition::expected_state`]).
#[derive(Debug, Clone, PartialEq)]
pub struct GraphChangeSet {
    /// The run whose row anchors the commit lock.
    pub run_id: RunId,
    /// New `declared` node rows the emit path appends; deduped on
    /// `(run_id, node_key)` — the key itself is the idempotency guard,
    /// so inserts carry no expected version.
    pub node_inserts: Vec<Node>,
    /// New edge rows the emit path appends; deduped on
    /// `(dependent_node_id, prerequisite_node_id, kind, artifact_id)`.
    pub edge_inserts: Vec<Edge>,
    /// Expected-state-guarded node transitions.
    pub transitions: Vec<NodeTransition>,
    /// The `run_events` intents to journal in order.
    pub event_intents: Vec<GraphEventIntent>,
}

impl GraphChangeSet {
    /// An empty change set anchored on `run_id` — there is no `Default`
    /// because the run-row lock anchor is never zero.
    #[must_use]
    pub const fn new(run_id: RunId) -> Self {
        Self {
            run_id,
            node_inserts: Vec::new(),
            edge_inserts: Vec::new(),
            transitions: Vec::new(),
            event_intents: Vec::new(),
        }
    }
}

/// One expected-state-guarded node transition: the change set was
/// planned against `expected_state` — the optimistic version — and the
/// commit applies the update only while the row still carries it under
/// the run-row lock, so a stale plan fails rather than overwriting a
/// concurrent transition. A transition into [`NodeStatus::Ready`] also
/// stamps `ready_at = now()` for the claim queue's FIFO ordering (b35);
/// all other transitions leave it untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeTransition {
    /// The node to move.
    pub node_id: WorkflowNodeId,
    /// The state the plan observed — the expected version the commit
    /// re-verifies.
    pub expected_state: NodeStatus,
    /// The state to land.
    pub next_state: NodeStatus,
}

/// The journaled `run_events` kind vocabulary the workflow domain emits
/// (the same strings upstream reads from `eventjournal.Kind*` —
/// `central-eventjournal` owns the canonical envelope; this restates
/// the producer-side subset per the boundary doc's restatement
/// precedent so the domain can name its intents without importing the
/// journal crate).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GraphEventKind {
    /// `node_declared` — a child-spec node committed.
    NodeDeclared,
    /// `node_ready` — a node entered `ready`.
    NodeReady,
    /// `node_dispatched` — a node entered `dispatched`.
    NodeDispatched,
    /// `attempt_started` — a node entered `running` (attempt scope).
    AttemptStarted,
    /// `node_succeeded` — a node reached terminal success.
    NodeSucceeded,
    /// `node_failed_terminal` — a node reached terminal failure.
    NodeFailedTerminal,
    /// `attempt_ambiguous` — a node parked for an operator decision.
    AttemptAmbiguous,
    /// `node_cancelled` — a node reached terminal cancel.
    NodeCancelled,
    /// `child_spec_rejected` — an atomic batch refusal.
    ChildSpecRejected,
    /// `cancel_requested` — cancel intent for a live node the harness
    /// control layer must confirm.
    CancelRequested,
    /// `attempt_decision` — the operator's resume/rerun decision.
    AttemptDecision,
    /// `command_deduped` — an idempotent replay of a recorded command.
    CommandDeduped,
}

impl GraphEventKind {
    /// Every kind in declaration order.
    pub const ALL: [Self; 12] = [
        Self::NodeDeclared,
        Self::NodeReady,
        Self::NodeDispatched,
        Self::AttemptStarted,
        Self::NodeSucceeded,
        Self::NodeFailedTerminal,
        Self::AttemptAmbiguous,
        Self::NodeCancelled,
        Self::ChildSpecRejected,
        Self::CancelRequested,
        Self::AttemptDecision,
        Self::CommandDeduped,
    ];

    /// The journaled text form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NodeDeclared => "node_declared",
            Self::NodeReady => "node_ready",
            Self::NodeDispatched => "node_dispatched",
            Self::AttemptStarted => "attempt_started",
            Self::NodeSucceeded => "node_succeeded",
            Self::NodeFailedTerminal => "node_failed_terminal",
            Self::AttemptAmbiguous => "attempt_ambiguous",
            Self::NodeCancelled => "node_cancelled",
            Self::ChildSpecRejected => "child_spec_rejected",
            Self::CancelRequested => "cancel_requested",
            Self::AttemptDecision => "attempt_decision",
            Self::CommandDeduped => "command_deduped",
        }
    }

    /// Parses the journaled text form; `None` on anything else.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|kind| kind.as_str() == s)
    }
}

impl fmt::Display for GraphEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The journal `actor` for emission-path events (`node_declared`,
/// `child_spec_rejected`, emission `command_deduped`): the batch is
/// leader output, validated and committed by Central.
pub const ACTOR_EMIT: &str = "leader";

/// The journal `actor` for readiness recomputation (`node_ready`
/// produced by [`crate::readiness::evaluate_readiness`]): the scheduler
/// domain owns `declared → ready`.
pub const ACTOR_SCHEDULER: &str = "scheduler";

/// One `run_events` intent inside a [`GraphChangeSet`]: the domain owns
/// the kind, actor, optional reason code, and the already-shaped JSON
/// payload; the adapter assigns `seq`, the event id, and `recorded_at`
/// inside the commit transaction.
#[derive(Debug, Clone, PartialEq)]
pub struct GraphEventIntent {
    /// The node the event is about; `None` for run-scoped rows.
    pub node_id: Option<WorkflowNodeId>,
    /// The parked attempt a decision/dedup event binds; `None`
    /// otherwise.
    pub attempt_id: Option<SessionAttemptId>,
    /// The journaled kind.
    pub kind: GraphEventKind,
    /// The actor the journal records (upstream free-form `actor`).
    pub actor: String,
    /// The optional `reason_code` (e.g. `SPEC_VALIDATION_FAILED` on a
    /// `child_spec_rejected` row).
    pub reason_code: Option<String>,
    /// The event payload JSON — shaped by the domain producers, never
    /// carrying secrets, spec text, or unsanitized names.
    pub payload: serde_json::Value,
}

impl GraphEventIntent {
    /// The `node_declared` event for one committed child (upstream
    /// `marshalNodeDeclared`).
    #[must_use]
    pub fn node_declared(node: &Node, child: &ChildSpecNode) -> Self {
        Self {
            node_id: Some(node.id),
            attempt_id: None,
            kind: GraphEventKind::NodeDeclared,
            actor: ACTOR_EMIT.to_string(),
            reason_code: None,
            payload: serde_json::json!({
                "node_key": node.node_key,
                "parent_node_id": node.parent_id.map(|id| id.to_string()),
                "depends_on": child.depends_on,
                "harness": node.harness,
                "workspace_kind": node.workspace_kind,
                "depth": node.depth,
                "input_artifact_refs": child.input_artifact_refs,
            }),
        }
    }

    /// The `command_deduped` event for an emission replay (spec-5):
    /// `{"command": "emit_batch", "node_key": …}`.
    #[must_use]
    pub fn emit_deduped(node_id: WorkflowNodeId, node_key: &str) -> Self {
        Self {
            node_id: Some(node_id),
            attempt_id: None,
            kind: GraphEventKind::CommandDeduped,
            actor: ACTOR_EMIT.to_string(),
            reason_code: None,
            payload: serde_json::json!({"command": "emit_batch", "node_key": node_key}),
        }
    }

    /// The `attempt_decision` event the operator's decision journals:
    /// `{"decision": …}`.
    #[must_use]
    pub fn attempt_decision(node_id: WorkflowNodeId, decision: &str, actor: &str) -> Self {
        Self {
            node_id: Some(node_id),
            attempt_id: None,
            kind: GraphEventKind::AttemptDecision,
            actor: actor.to_string(),
            reason_code: None,
            payload: serde_json::json!({"decision": decision}),
        }
    }

    /// The `command_deduped` event for a decision replay bound to the
    /// parked attempt: `{"command": "attempt_decision", "decision": …}`.
    #[must_use]
    pub fn decision_deduped(
        node_id: WorkflowNodeId,
        attempt_id: SessionAttemptId,
        decision: &str,
        actor: &str,
    ) -> Self {
        Self {
            node_id: Some(node_id),
            attempt_id: Some(attempt_id),
            kind: GraphEventKind::CommandDeduped,
            actor: actor.to_string(),
            reason_code: None,
            payload: serde_json::json!({
                "command": "attempt_decision",
                "decision": decision,
            }),
        }
    }
}

/// The journal kind matching a target node state (upstream
/// `eventKindForStatus`). `Running` pairs with attempt-scope events, so
/// it journals `attempt_started`; `Declared` is never a transition
/// target and maps to `None`.
#[must_use]
pub fn event_kind_for_status(to: NodeStatus) -> Option<GraphEventKind> {
    match to {
        NodeStatus::Ready => Some(GraphEventKind::NodeReady),
        NodeStatus::Dispatched => Some(GraphEventKind::NodeDispatched),
        NodeStatus::Running => Some(GraphEventKind::AttemptStarted),
        NodeStatus::Succeeded => Some(GraphEventKind::NodeSucceeded),
        NodeStatus::FailedTerminal => Some(GraphEventKind::NodeFailedTerminal),
        NodeStatus::AttemptAmbiguous => Some(GraphEventKind::AttemptAmbiguous),
        NodeStatus::Cancelled => Some(GraphEventKind::NodeCancelled),
        NodeStatus::Declared => None,
    }
}

// ---------------------------------------------------------------------------
// Failure
// ---------------------------------------------------------------------------

/// A stable, safe workflow-domain error category (upstream
/// `FailureClass`). It never carries node payloads, spec text, or other
/// sensitive input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FailureClass {
    /// `INVALID` — malformed input or a reference to a node or run that
    /// does not exist.
    Invalid,
    /// `CONFLICT` — a lost-update or consistency conflict.
    Conflict,
    /// `DENIED` — a denied node state transition.
    Denied,
}

impl FailureClass {
    /// The persisted upstream text form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Invalid => "INVALID",
            Self::Conflict => "CONFLICT",
            Self::Denied => "DENIED",
        }
    }
}

impl fmt::Display for FailureClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The typed workflow-domain failure returned at store boundaries
/// (upstream `workflow.Failure`). `reason` is a closed machine-readable
/// value; `Display` deliberately excludes node keys, spec payloads, and
/// driver detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failure {
    /// The error category.
    pub class: FailureClass,
    /// The closed machine-readable reason (upstream `Reason`).
    pub reason: &'static str,
}

impl Failure {
    /// Builds a domain failure from a closed class and reason.
    #[must_use]
    pub const fn new(class: FailureClass, reason: &'static str) -> Self {
        Self { class, reason }
    }
}

impl fmt::Display for Failure {
    /// `"workflow-failure class=\"{class}\" reason=\"{reason}\""` —
    /// upstream `Error()`'s shape, closed tokens only.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "workflow-failure class={:?} reason={:?}",
            self.class.as_str(),
            self.reason
        )
    }
}

impl std::error::Error for Failure {}

/// Maps a domain failure onto the shared foundation taxonomy: `class`
/// becomes the `FailureKind`, `reason` the stable machine `code`, and
/// the message is the domain failure's already-redacted `Display`.
impl From<Failure> for FoundationFailure {
    fn from(failure: Failure) -> Self {
        let kind = match failure.class {
            FailureClass::Invalid => FailureKind::Invalid,
            FailureClass::Conflict => FailureKind::Conflict,
            FailureClass::Denied => FailureKind::Denied,
        };
        FoundationFailure::new(kind, failure.reason, failure.to_string())
    }
}

// ---------------------------------------------------------------------------
// Failure reasons — the closed workflow-domain set
// ---------------------------------------------------------------------------

/// `WORKFLOW_RUN_NOT_FOUND` — the run row a mutation anchors on does
/// not exist.
pub const REASON_RUN_NOT_FOUND: &str = "WORKFLOW_RUN_NOT_FOUND";
/// `WORKFLOW_PARENT_NOT_FOUND` — the emitting parent node is unknown.
pub const REASON_PARENT_NOT_FOUND: &str = "WORKFLOW_PARENT_NOT_FOUND";
/// `WORKFLOW_PARENT_RUN_MISMATCH` — the parent belongs to another run.
pub const REASON_PARENT_RUN_MISMATCH: &str = "WORKFLOW_PARENT_RUN_MISMATCH";
/// `WORKFLOW_NODE_NOT_FOUND` — the named node row does not exist.
pub const REASON_NODE_NOT_FOUND: &str = "WORKFLOW_NODE_NOT_FOUND";
/// `INVALID_NODE_TRANSITION` — a transition or cancel the state machine
/// denies.
pub const REASON_INVALID_NODE_TRANSITION: &str = "INVALID_NODE_TRANSITION";
/// `WORKFLOW_UNKNOWN_TARGET_STATUS` — a transition target with no
/// journaled kind (`declared` is never a target).
pub const REASON_UNKNOWN_TARGET_STATUS: &str = "WORKFLOW_UNKNOWN_TARGET_STATUS";
/// `WORKFLOW_UNKNOWN_DECISION` — an ambiguous-resolution decision
/// outside the declared vocabulary.
pub const REASON_UNKNOWN_DECISION: &str = "WORKFLOW_UNKNOWN_DECISION";
/// `WORKFLOW_NODE_NOT_AMBIGUOUS` — an operator decision offered on a
/// node that is not `attempt_ambiguous`.
pub const REASON_NODE_NOT_AMBIGUOUS: &str = "WORKFLOW_NODE_NOT_AMBIGUOUS";
/// `WORKFLOW_AMBIGUOUS_ATTEMPT_MISSING` — an ambiguous node carrying no
/// parked attempt to decide.
pub const REASON_AMBIGUOUS_ATTEMPT_MISSING: &str = "WORKFLOW_AMBIGUOUS_ATTEMPT_MISSING";
/// `ATTEMPT_DECISION_CONFLICT` — a recorded decision differing from the
/// replayed one.
pub const REASON_ATTEMPT_DECISION_CONFLICT: &str = "ATTEMPT_DECISION_CONFLICT";
/// `WORKFLOW_DECISION_FINGERPRINT_INVALID` — a decision payload
/// fingerprint that is not a SHA-256. The domain port takes `[u8; 32]`
/// so the class is unrepresentable inside it; the constant stands for
/// the commit layer's pre-lock wire check.
pub const REASON_DECISION_FINGERPRINT_INVALID: &str = "WORKFLOW_DECISION_FINGERPRINT_INVALID";
/// `DUPLICATE_IDEMPOTENCY_KEY` — spec-5's replay verdict: a retried
/// command keyed on an already-recorded coordinate whose payload
/// fingerprint differs from the recorded one. The recorded row stands.
pub const REASON_DUPLICATE_IDEMPOTENCY_KEY: &str = "DUPLICATE_IDEMPOTENCY_KEY";

#[cfg(test)]
mod tests {
    use super::*;

    // -- upstream domain_test.go: TestNodeStatusTransitions -----------

    /// Pins the spec-1 state machine: the happy path
    /// `declared → ready → dispatched → running → succeeded`, the
    /// failure branches, the retry-policy return to `ready`, and the
    /// operator-resolved ambiguous exits.
    #[test]
    fn node_status_transitions() {
        use NodeStatus::*;
        let cases: &[(&str, NodeStatus, NodeStatus, bool)] = &[
            (
                "declared becomes ready when prerequisites hold",
                Declared,
                Ready,
                true,
            ),
            ("declared may be cancelled", Declared, Cancelled, true),
            (
                "declared never jumps to dispatched",
                Declared,
                Dispatched,
                false,
            ),
            ("declared never jumps to running", Declared, Running, false),
            ("declared never succeeds", Declared, Succeeded, false),
            ("ready is claimed into dispatched", Ready, Dispatched, true),
            ("ready may be cancelled", Ready, Cancelled, true),
            (
                "ready expires terminal on the node bound",
                Ready,
                FailedTerminal,
                true,
            ),
            ("ready never runs without dispatch", Ready, Running, false),
            ("ready never goes back to declared", Ready, Declared, false),
            ("dispatched starts running", Dispatched, Running, true),
            (
                "dispatch failure retries via ready",
                Dispatched,
                Ready,
                true,
            ),
            (
                "dispatch failure may end terminal",
                Dispatched,
                FailedTerminal,
                true,
            ),
            (
                "lost launch is ambiguous",
                Dispatched,
                AttemptAmbiguous,
                true,
            ),
            ("dispatched may be cancelled", Dispatched, Cancelled, true),
            (
                "dispatched never skips running to succeed",
                Dispatched,
                Succeeded,
                false,
            ),
            ("running completes", Running, Succeeded, true),
            ("attempt failure retries via ready", Running, Ready, true),
            (
                "attempt failure may end terminal",
                Running,
                FailedTerminal,
                true,
            ),
            ("lost session is ambiguous", Running, AttemptAmbiguous, true),
            ("running may be cancelled", Running, Cancelled, true),
            (
                "running never redispatches directly",
                Running,
                Dispatched,
                false,
            ),
            (
                "operator resume returns to running",
                AttemptAmbiguous,
                Running,
                true,
            ),
            (
                "operator rerun returns to ready",
                AttemptAmbiguous,
                Ready,
                true,
            ),
            (
                "operator abandonment ends terminal",
                AttemptAmbiguous,
                FailedTerminal,
                true,
            ),
            (
                "ambiguous may be cancelled",
                AttemptAmbiguous,
                Cancelled,
                true,
            ),
            (
                "ambiguous never succeeds silently",
                AttemptAmbiguous,
                Succeeded,
                false,
            ),
        ];
        for &(name, from, to, allowed) in cases {
            assert_eq!(
                from.can_transition(to),
                allowed,
                "{name}: {from}.can_transition({to})"
            );
        }
    }

    // -- upstream domain_test.go: TestNodeStatusTerminalAreClosed -----

    /// Terminal statuses are closed: nothing leaves `succeeded`,
    /// `failed_terminal`, or `cancelled`; non-terminal statuses are not
    /// terminal.
    #[test]
    fn node_status_terminal_are_closed() {
        use NodeStatus::*;
        for terminal in [Succeeded, FailedTerminal, Cancelled] {
            assert!(terminal.is_terminal(), "{terminal} should be terminal");
            for to in NodeStatus::ALL {
                assert!(
                    !terminal.can_transition(to),
                    "terminal {terminal} admitted transition to {to}"
                );
            }
        }
        for open in [Declared, Ready, Dispatched, Running, AttemptAmbiguous] {
            assert!(!open.is_terminal(), "{open} should not be terminal");
        }
    }

    // -- upstream domain_test.go: TestNodeStatusVocabularyMatchesSchema

    /// Pins the exact string set migration b33 checks in
    /// `workflow_nodes_state_check`.
    #[test]
    fn node_status_vocabulary_matches_schema() {
        let want = [
            "declared",
            "ready",
            "dispatched",
            "running",
            "succeeded",
            "failed_terminal",
            "attempt_ambiguous",
            "cancelled",
        ];
        let got: Vec<&str> = NodeStatus::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(got, want);
        for (status, text) in NodeStatus::ALL.iter().zip(want.iter()) {
            assert_eq!(NodeStatus::parse(text), Some(*status));
        }
        assert_eq!(NodeStatus::parse("bogus"), None);
        assert_eq!(NodeStatus::parse(""), None);
    }

    // -- upstream domain_test.go: TestEdgeKindVocabularyMatchesSchema -

    /// Pins `workflow_edges_kind_check`.
    #[test]
    fn edge_kind_vocabulary_matches_schema() {
        let want = ["ordering", "artifact"];
        let got: Vec<&str> = EdgeKind::ALL.iter().map(|k| k.as_str()).collect();
        assert_eq!(got, want);
        for (kind, text) in EdgeKind::ALL.iter().zip(want.iter()) {
            assert_eq!(EdgeKind::parse(text), Some(*kind));
        }
        assert_eq!(EdgeKind::parse("priority"), None);
    }

    // -- upstream domain_test.go: TestWorkspaceKindVocabularyMatchesSchema

    /// Pins `workflow_nodes_workspace_kind_check`; spec-1's "code" and
    /// "plain" names are not the mechanism vocabulary.
    #[test]
    fn workspace_kind_vocabulary_matches_schema() {
        let want = ["worktree", "directory"];
        let got: Vec<&str> = WorkspaceKind::ALL.iter().map(|k| k.as_str()).collect();
        assert_eq!(got, want);
        for (kind, text) in WorkspaceKind::ALL.iter().zip(want.iter()) {
            assert_eq!(WorkspaceKind::parse(text), Some(*kind));
        }
        for alien in ["code", "plain", "volume", ""] {
            assert_eq!(
                WorkspaceKind::parse(alien),
                None,
                "undeclared {alien} admitted"
            );
        }
    }

    // -- upstream domain_test.go: TestDefaultCapsPinsLockedDefaults ---

    /// Keeps the user-approved OQ-3 numbers honest: 4 parallel sessions,
    /// depth 3, 64 nodes per run.
    #[test]
    fn default_caps_pins_locked_defaults() {
        let caps = Caps::locked();
        assert_eq!(caps.max_parallel_sessions, 4);
        assert_eq!(caps.max_depth, 3);
        assert_eq!(caps.max_nodes_per_run, 64);
    }

    // -- Rust-side additions: event-kind vocabulary + failure ---------

    /// `event_kind_for_status` mirrors upstream `eventKindForStatus`:
    /// `running` journals `attempt_started` and `declared` is never a
    /// transition target.
    #[test]
    fn event_kind_for_status_maps_targets() {
        use GraphEventKind::*;
        let cases: &[(NodeStatus, Option<GraphEventKind>)] = &[
            (NodeStatus::Ready, Some(NodeReady)),
            (NodeStatus::Dispatched, Some(NodeDispatched)),
            (NodeStatus::Running, Some(AttemptStarted)),
            (NodeStatus::Succeeded, Some(NodeSucceeded)),
            (NodeStatus::FailedTerminal, Some(NodeFailedTerminal)),
            (NodeStatus::AttemptAmbiguous, Some(AttemptAmbiguous)),
            (NodeStatus::Cancelled, Some(NodeCancelled)),
            (NodeStatus::Declared, None),
        ];
        for &(status, want) in cases {
            assert_eq!(event_kind_for_status(status), want, "{status}");
        }
        let got: Vec<&str> = GraphEventKind::ALL.iter().map(|k| k.as_str()).collect();
        assert_eq!(
            got,
            [
                "node_declared",
                "node_ready",
                "node_dispatched",
                "attempt_started",
                "node_succeeded",
                "node_failed_terminal",
                "attempt_ambiguous",
                "node_cancelled",
                "child_spec_rejected",
                "cancel_requested",
                "attempt_decision",
                "command_deduped",
            ]
        );
    }

    /// The domain failure keeps closed tokens only and maps onto the
    /// foundation taxonomy by class.
    #[test]
    fn failure_maps_to_foundation_taxonomy() {
        let failure = Failure::new(FailureClass::Denied, REASON_INVALID_NODE_TRANSITION);
        assert_eq!(
            failure.to_string(),
            "workflow-failure class=\"DENIED\" reason=\"INVALID_NODE_TRANSITION\""
        );
        let foundation: FoundationFailure = failure.into();
        assert_eq!(foundation.kind(), FailureKind::Denied);
        assert_eq!(foundation.code(), "INVALID_NODE_TRANSITION");
    }

    /// `NodeTransition` carries the observed state as the expected
    /// version the commit re-verifies under the run-row lock.
    #[test]
    fn node_transition_carries_expected_state() {
        let transition = NodeTransition {
            node_id: WorkflowNodeId::new(),
            expected_state: NodeStatus::Declared,
            next_state: NodeStatus::Ready,
        };
        assert!(
            transition
                .expected_state
                .can_transition(transition.next_state)
        );
    }
}
