//! Node readiness, cancel-cascade planning, and the single-node
//! transition/resolution planners — the pure port of
//! `central/internal/workflow/readiness.go` plus the domain half of the
//! upstream store's `Transition`/`RecomputeReady`/`ResolveAmbiguous`
//! (the parts upstream sequences inside the locked transaction; the
//! crate keeps them pure functions over caller-supplied committed
//! rows).
//!
//! Every function produces a [`GraphChangeSet`] the store commits in
//! one transaction anchored on the run-row lock; every [`NodeTransition`]
//! carries the observed state as its expected-version guard.
//!
//! OWNING PACKET: P2A03. SLICE: 2A.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use central_foundation::identity::{ArtifactId, RunId, WorkflowNodeId};
use time::OffsetDateTime;

use crate::domain::{
    ACTOR_SCHEDULER, Edge, EdgeKind, Failure, FailureClass, GraphChangeSet, GraphEventIntent,
    GraphEventKind, Node, NodeStatus, NodeTransition, REASON_INVALID_NODE_TRANSITION,
    REASON_NODE_NOT_AMBIGUOUS, REASON_NODE_NOT_FOUND, REASON_UNKNOWN_DECISION,
    REASON_UNKNOWN_TARGET_STATUS, event_kind_for_status,
};

// ---------------------------------------------------------------------------
// Ambiguous-resolution decisions
// ---------------------------------------------------------------------------

/// The decisions the operator may record on a parked
/// `attempt_ambiguous` node (upstream `DecisionResume`/`DecisionRerun`).
/// Spec-1 names exactly two: harness-native resume and a fresh rerun —
/// never automatic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AmbiguousDecision {
    /// `resume` — parks the node until Slice 2B's harness-native resume
    /// reattaches the recorded attempt; the node stays
    /// `attempt_ambiguous` and the decision alone is journaled.
    Resume,
    /// `rerun` — abandons the ambiguous attempt and returns the node to
    /// `ready` for a fresh attempt.
    Rerun,
}

impl AmbiguousDecision {
    /// Every decision in declaration order.
    pub const ALL: [Self; 2] = [Self::Resume, Self::Rerun];

    /// The journaled text form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Resume => "resume",
            Self::Rerun => "rerun",
        }
    }

    /// Parses the journaled text form; `None` on anything else.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|d| d.as_str() == s)
    }
}

/// Whether `decision` is a declared ambiguous-resolution decision
/// (upstream `AmbiguousDecisionKnown`).
#[must_use]
pub fn ambiguous_decision_known(decision: &str) -> bool {
    AmbiguousDecision::parse(decision).is_some()
}

// ---------------------------------------------------------------------------
// plan_cancel_cascade — the three-way partition
// ---------------------------------------------------------------------------

/// Partitions the non-terminal nodes a cancel of one root reaches
/// (upstream `CascadePlan`). Every list preserves BFS order from the
/// root so the journal reads top-down. A node appears in exactly one
/// list; terminal descendants appear in none.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CascadePlan {
    /// `declared` and `ready` nodes (the cancel root itself included
    /// when it qualifies): no session ever existed for them, so they
    /// transition straight to `cancelled`.
    pub immediate: Vec<WorkflowNodeId>,
    /// `dispatched` and `running` nodes: a session may be live, so the
    /// store journals `cancel_requested` intent for the harness control
    /// layer and leaves the state untouched — Slice 2B delivers the
    /// control and settles the node.
    pub signal: Vec<WorkflowNodeId>,
    /// `attempt_ambiguous` nodes: the attempt outcome is unknown, so
    /// the node parks for an operator decision. The cascade still flows
    /// through to its descendants — only the ambiguous node itself is
    /// exempt from auto-transition.
    pub blocked: Vec<WorkflowNodeId>,
}

impl CascadePlan {
    /// The number of nodes the plan reaches (upstream `Total`).
    #[must_use]
    pub fn total(&self) -> usize {
        self.immediate.len() + self.signal.len() + self.blocked.len()
    }

    /// Every node the cascade reached — immediate, then signal, then
    /// blocked (upstream `CancelNode`'s concatenated `affected`; each
    /// group is internally BFS-ordered).
    #[must_use]
    pub fn affected(&self) -> Vec<WorkflowNodeId> {
        let mut out = Vec::with_capacity(self.total());
        out.extend_from_slice(&self.immediate);
        out.extend_from_slice(&self.signal);
        out.extend_from_slice(&self.blocked);
        out
    }
}

/// Walks the dependency graph from `root_id` and partitions every
/// reachable non-terminal node — the root included — by the action its
/// state admits (upstream `PlanCancelCascade`). Edges point
/// dependent → prerequisite; the cascade walks
/// prerequisite → dependents (reverse adjacency), so cancelling a node
/// reaches exactly its transitive dependents. Traversal flows through
/// terminal and ambiguous intermediates: the default Phase-2 policy is
/// cascade (OQ-4), so a descendant is cancelled regardless of the
/// states between it and the root. The function is pure — it reads
/// nothing the caller did not pass and returns an empty plan for an
/// unknown root.
#[must_use]
pub fn plan_cancel_cascade(nodes: &[Node], edges: &[Edge], root_id: WorkflowNodeId) -> CascadePlan {
    let by_id: BTreeMap<WorkflowNodeId, &Node> = nodes.iter().map(|n| (n.id, n)).collect();

    // Reverse adjacency: prerequisite -> dependents, sorted by
    // (node_key, id) so the BFS visit order is deterministic across
    // equivalent inputs.
    let mut dependents: BTreeMap<WorkflowNodeId, Vec<WorkflowNodeId>> = BTreeMap::new();
    for edge in edges {
        dependents
            .entry(edge.prerequisite_node_id)
            .or_default()
            .push(edge.dependent_node_id);
    }
    for list in dependents.values_mut() {
        list.sort_by(|a, b| {
            let key = |id: &WorkflowNodeId| by_id.get(id).map_or("", |n| n.node_key.as_str());
            key(a).cmp(key(b)).then_with(|| a.cmp(b))
        });
    }

    let mut plan = CascadePlan::default();
    let mut seen: BTreeSet<WorkflowNodeId> = BTreeSet::from([root_id]);
    let mut queue: VecDeque<WorkflowNodeId> = VecDeque::from([root_id]);
    while let Some(id) = queue.pop_front() {
        let Some(node) = by_id.get(&id) else { continue };
        match node.state {
            NodeStatus::Declared | NodeStatus::Ready => plan.immediate.push(id),
            NodeStatus::Dispatched | NodeStatus::Running => plan.signal.push(id),
            NodeStatus::AttemptAmbiguous => plan.blocked.push(id),
            _ => {
                // Terminal descendants admit no transition; the cascade
                // still walks past them to their own dependents.
            }
        }
        if let Some(deps) = dependents.get(&id) {
            for dep in deps {
                if seen.insert(*dep) {
                    queue.push_back(*dep);
                }
            }
        }
    }
    plan
}

// ---------------------------------------------------------------------------
// evaluate_readiness — the event-driven declared -> ready flip
// ---------------------------------------------------------------------------

/// The readiness rule of spec-1 (upstream `RecomputeReady`'s update
/// predicate) evaluated over caller-supplied committed rows: every
/// `declared` node whose `ordering` in-edges all lead to `succeeded`
/// prerequisites, whose `artifact` in-edges all name finalized
/// artifacts, and whose `not_before` gate has passed flips to `ready`
/// and journals `node_ready` under actor `scheduler`.
///
/// `artifact_finalized` is the probe an `artifact` edge consults — it
/// reports `true` exactly when the artifact's persisted state is
/// `ready` (the `IS DISTINCT FROM 'ready'` check means an unknown or
/// missing artifact blocks). Nodes are evaluated in the caller's
/// (committed) order; the flip order is the journal order.
///
/// Every produced [`NodeTransition`] carries `expected_state:
/// Declared` — the commit applies each flip only while the row is still
/// `declared` under the run-row lock.
#[must_use]
pub fn evaluate_readiness(
    run_id: RunId,
    nodes: &[Node],
    edges: &[Edge],
    artifact_finalized: &dyn Fn(ArtifactId) -> bool,
    now: OffsetDateTime,
) -> GraphChangeSet {
    let by_id: BTreeMap<WorkflowNodeId, &Node> = nodes.iter().map(|n| (n.id, n)).collect();
    let mut in_edges: BTreeMap<WorkflowNodeId, Vec<&Edge>> = BTreeMap::new();
    for edge in edges {
        in_edges
            .entry(edge.dependent_node_id)
            .or_default()
            .push(edge);
    }

    let mut change_set = GraphChangeSet::new(run_id);
    for node in nodes {
        if node.state != NodeStatus::Declared {
            continue;
        }
        if node.not_before.is_some_and(|not_before| not_before > now) {
            continue;
        }
        let ready = in_edges.get(&node.id).is_none_or(|deps| {
            deps.iter().all(|edge| match edge.kind {
                EdgeKind::Ordering => by_id
                    .get(&edge.prerequisite_node_id)
                    .is_some_and(|prerequisite| prerequisite.state == NodeStatus::Succeeded),
                EdgeKind::Artifact => edge.artifact_id.is_some_and(artifact_finalized),
            })
        });
        if !ready {
            continue;
        }
        change_set.transitions.push(NodeTransition {
            node_id: node.id,
            expected_state: NodeStatus::Declared,
            next_state: NodeStatus::Ready,
        });
        change_set.event_intents.push(GraphEventIntent {
            node_id: Some(node.id),
            attempt_id: None,
            kind: GraphEventKind::NodeReady,
            actor: ACTOR_SCHEDULER.to_string(),
            reason_code: None,
            payload: serde_json::json!({"node_key": node.node_key}),
        });
    }
    change_set
}

// ---------------------------------------------------------------------------
// cancel_cascade — the spec-1 cancel command's domain half
// ---------------------------------------------------------------------------

/// What [`cancel_cascade`] decided: the three-way partition plus the
/// write unit to commit. `affected()` on the plan lists every reached
/// node in upstream's returned order (immediate, then signal, then
/// blocked).
#[derive(Debug, Clone, PartialEq)]
pub struct CascadeOutcome {
    /// The BFS partition the cancel reached.
    pub plan: CascadePlan,
    /// The change set to commit: `cancelled` transitions for
    /// `immediate` nodes, `node_cancelled` events, `cancel_requested`
    /// intent for `signal` nodes. `blocked` nodes produce no writes.
    pub change_set: GraphChangeSet,
}

/// Applies the spec-1 cascade policy (upstream `CancelNode`'s domain
/// half): the run-row lock serializes the writer,
/// [`plan_cancel_cascade`] partitions the reachable non-terminal
/// descendants, `declared`/`ready` nodes transition to `cancelled` with
/// a `node_cancelled` event each, `dispatched`/`running` nodes keep
/// their state and receive a `cancel_requested` intent the harness
/// control layer consumes, and `attempt_ambiguous` nodes park untouched
/// while the cascade flows past them. Repeating a committed cancel is
/// an idempotent success (empty outcome); a `succeeded`/
/// `failed_terminal` root refuses `DENIED`.
pub fn cancel_cascade(
    nodes: &[Node],
    edges: &[Edge],
    root_id: WorkflowNodeId,
    actor: &str,
) -> Result<CascadeOutcome, Failure> {
    let by_id: BTreeMap<WorkflowNodeId, &Node> = nodes.iter().map(|n| (n.id, n)).collect();
    let Some(root) = by_id.get(&root_id) else {
        return Err(Failure::new(FailureClass::Invalid, REASON_NODE_NOT_FOUND));
    };
    if root.state.is_terminal() {
        if root.state == NodeStatus::Cancelled {
            // Idempotent replay of a committed cancel.
            return Ok(CascadeOutcome {
                plan: CascadePlan::default(),
                change_set: GraphChangeSet::new(root.run_id),
            });
        }
        return Err(Failure::new(
            FailureClass::Denied,
            REASON_INVALID_NODE_TRANSITION,
        ));
    }

    let plan = plan_cancel_cascade(nodes, edges, root_id);
    let mut change_set = GraphChangeSet::new(root.run_id);

    // Immediate: declared/ready nodes cancel outright — no session ever
    // existed, so the state and its event commit together.
    for &id in &plan.immediate {
        let Some(node) = by_id.get(&id) else { continue };
        let from = node.state;
        if !from.can_transition(NodeStatus::Cancelled) {
            return Err(Failure::new(
                FailureClass::Denied,
                REASON_INVALID_NODE_TRANSITION,
            ));
        }
        change_set.transitions.push(NodeTransition {
            node_id: id,
            expected_state: from,
            next_state: NodeStatus::Cancelled,
        });
        change_set.event_intents.push(GraphEventIntent {
            node_id: Some(id),
            attempt_id: None,
            kind: GraphEventKind::NodeCancelled,
            actor: actor.to_string(),
            reason_code: None,
            payload: serde_json::json!({
                "from": from.as_str(),
                "to": NodeStatus::Cancelled.as_str(),
                "cascade_root": root_id.to_string(),
            }),
        });
    }

    // Signal: live nodes keep their state — the dispatch layer owns it.
    // The cancel_requested event is the journaled intent Slice 2B
    // delivers to the harness cancel control.
    for &id in &plan.signal {
        change_set.event_intents.push(GraphEventIntent {
            node_id: Some(id),
            attempt_id: None,
            kind: GraphEventKind::CancelRequested,
            actor: actor.to_string(),
            reason_code: None,
            payload: serde_json::json!({"cascade_root": root_id.to_string()}),
        });
    }
    // Blocked nodes stay attempt_ambiguous for the operator decision —
    // nothing is written for them here.

    Ok(CascadeOutcome { plan, change_set })
}

// ---------------------------------------------------------------------------
// plan_transition — the single-node transition's domain half
// ---------------------------------------------------------------------------

/// Evaluates one node transition and produces its write unit (upstream
/// `Transition`'s domain half): `DENIED`/`INVALID_NODE_TRANSITION` when
/// the state machine refuses, `INVALID`/`WORKFLOW_UNKNOWN_TARGET_STATUS`
/// when the target has no journaled kind (`declared` is never a
/// target). The produced [`NodeTransition`] carries the observed state
/// as its expected version; a `→ ready` write stamps `ready_at` at
/// commit.
pub fn plan_transition(
    node: &Node,
    to: NodeStatus,
    actor: &str,
    reason: Option<&str>,
) -> Result<GraphChangeSet, Failure> {
    let from = node.state;
    if !from.can_transition(to) {
        return Err(Failure::new(
            FailureClass::Denied,
            REASON_INVALID_NODE_TRANSITION,
        ));
    }
    let Some(kind) = event_kind_for_status(to) else {
        return Err(Failure::new(
            FailureClass::Invalid,
            REASON_UNKNOWN_TARGET_STATUS,
        ));
    };
    let mut change_set = GraphChangeSet::new(node.run_id);
    change_set.transitions.push(NodeTransition {
        node_id: node.id,
        expected_state: from,
        next_state: to,
    });
    change_set.event_intents.push(GraphEventIntent {
        node_id: Some(node.id),
        attempt_id: None,
        kind,
        actor: actor.to_string(),
        reason_code: reason.map(str::to_string),
        payload: serde_json::json!({"from": from.as_str(), "to": to.as_str()}),
    });
    Ok(change_set)
}

// ---------------------------------------------------------------------------
// resolve_ambiguous — the operator decision's domain half
// ---------------------------------------------------------------------------

/// Evaluates the operator's decision on an `attempt_ambiguous` node and
/// produces its write unit (upstream `ResolveAmbiguous`'s domain half):
/// `INVALID`/`WORKFLOW_UNKNOWN_DECISION` for a decision outside the
/// declared vocabulary, `DENIED`/`WORKFLOW_NODE_NOT_AMBIGUOUS` when the
/// node is not parked. The set journals `attempt_decision`; a `rerun`
/// decision additionally returns the node to `ready` via `node_ready`,
/// while `resume` leaves it parked for Slice 2B's harness-native
/// resume. The `attempt_decisions` one-row-ever record and the
/// replay/dedup verdicts are the commit layer's — this produces the
/// non-replay write.
pub fn resolve_ambiguous(
    node: &Node,
    decision: &str,
    actor: &str,
) -> Result<GraphChangeSet, Failure> {
    let Some(parsed) = AmbiguousDecision::parse(decision) else {
        return Err(Failure::new(FailureClass::Invalid, REASON_UNKNOWN_DECISION));
    };
    if node.state != NodeStatus::AttemptAmbiguous {
        return Err(Failure::new(
            FailureClass::Denied,
            REASON_NODE_NOT_AMBIGUOUS,
        ));
    }
    let mut change_set = GraphChangeSet::new(node.run_id);
    change_set
        .event_intents
        .push(GraphEventIntent::attempt_decision(node.id, decision, actor));
    if parsed == AmbiguousDecision::Rerun {
        // attempt_ambiguous -> ready is a legal transition by
        // construction; the guard stays for parity with upstream's
        // CanTransition check.
        if !node.state.can_transition(NodeStatus::Ready) {
            return Err(Failure::new(
                FailureClass::Denied,
                REASON_INVALID_NODE_TRANSITION,
            ));
        }
        change_set.transitions.push(NodeTransition {
            node_id: node.id,
            expected_state: node.state,
            next_state: NodeStatus::Ready,
        });
        change_set.event_intents.push(GraphEventIntent {
            node_id: Some(node.id),
            attempt_id: None,
            kind: GraphEventKind::NodeReady,
            actor: actor.to_string(),
            reason_code: None,
            payload: serde_json::json!({
                "from": node.state.as_str(),
                "to": NodeStatus::Ready.as_str(),
            }),
        });
    }
    Ok(change_set)
}

#[cfg(test)]
mod tests {
    use central_foundation::identity::{RunId, WorkflowEdgeId, WorkspaceId};
    use time::Duration;

    use super::*;

    fn cascade_node(
        run_id: RunId,
        workspace_id: WorkspaceId,
        key: &str,
        state: NodeStatus,
    ) -> Node {
        Node {
            id: WorkflowNodeId::new(),
            run_id,
            workspace_id,
            node_key: key.to_string(),
            parent_id: None,
            harness: "claude-code".to_string(),
            workspace_kind: "worktree".to_string(),
            depth: 0,
            state,
            budget_wall_clock_sec: None,
            budget_cost_micro_usd: None,
            max_attempts: 1,
            attempt_count: 0,
            not_before: None,
            input_artifact_refs: vec![],
            spec: serde_json::json!({}),
            spec_fingerprint: None,
            node_timeout_seconds: None,
            ready_at: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn cascade_edge(run_id: RunId, dependent: &Node, prerequisite: &Node) -> Edge {
        Edge {
            id: WorkflowEdgeId::new(),
            run_id,
            dependent_node_id: dependent.id,
            prerequisite_node_id: prerequisite.id,
            kind: EdgeKind::Ordering,
            artifact_id: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    struct Fixture {
        run_id: RunId,
        workspace_id: WorkspaceId,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                run_id: RunId::new(),
                workspace_id: WorkspaceId::new(),
            }
        }
        fn node(&self, key: &str, state: NodeStatus) -> Node {
            cascade_node(self.run_id, self.workspace_id, key, state)
        }
        fn edge(&self, dependent: &Node, prerequisite: &Node) -> Edge {
            cascade_edge(self.run_id, dependent, prerequisite)
        }
    }

    // -- upstream readiness_test.go: TestPlanCancelCascadePartitionsByState

    /// The three-way partition: declared/ready cancel immediately, live
    /// nodes get the signal, ambiguous parks, terminal nodes are exempt
    /// — while the walk reaches through ambiguous and terminal
    /// intermediates to their own dependents.
    ///
    /// Graph:
    ///
    /// root(ready) → b(running) → c(ready)
    ///       |----→ d(ambiguous) → e(ready)
    ///       |----→ f(succeeded) → g(declared)
    ///       |----→ h(cancelled)
    #[test]
    fn plan_cancel_cascade_partitions_by_state() {
        let fx = Fixture::new();
        let root = fx.node("root", NodeStatus::Ready);
        let b = fx.node("b", NodeStatus::Running);
        let c = fx.node("c", NodeStatus::Ready);
        let d = fx.node("d", NodeStatus::AttemptAmbiguous);
        let e = fx.node("e", NodeStatus::Ready);
        let f = fx.node("f", NodeStatus::Succeeded);
        let g = fx.node("g", NodeStatus::Declared);
        let h = fx.node("h", NodeStatus::Cancelled);
        let nodes = [
            root.clone(),
            b.clone(),
            c.clone(),
            d.clone(),
            e.clone(),
            f.clone(),
            g.clone(),
            h.clone(),
        ];
        let edges = [
            fx.edge(&b, &root),
            fx.edge(&c, &b),
            fx.edge(&d, &root),
            fx.edge(&e, &d),
            fx.edge(&f, &root),
            fx.edge(&g, &f),
            fx.edge(&h, &root),
        ];

        let plan = plan_cancel_cascade(&nodes, &edges, root.id);

        assert_eq!(plan.immediate, [root.id, c.id, e.id, g.id], "Immediate");
        assert_eq!(plan.signal, [b.id], "Signal");
        assert_eq!(plan.blocked, [d.id], "Blocked");
        assert_eq!(plan.total(), 6);
    }

    // -- upstream: TestPlanCancelCascadeSignalRoot ---------------------

    /// A running root itself lands in `Signal` while its ready
    /// descendant cancels immediately.
    #[test]
    fn plan_cancel_cascade_signal_root() {
        let fx = Fixture::new();
        let root = fx.node("root", NodeStatus::Running);
        let child = fx.node("child", NodeStatus::Ready);
        let plan = plan_cancel_cascade(
            &[root.clone(), child.clone()],
            &[fx.edge(&child, &root)],
            root.id,
        );
        assert_eq!(plan.signal, [root.id]);
        assert_eq!(plan.immediate, [child.id]);
        assert!(plan.blocked.is_empty());
    }

    // -- upstream: TestPlanCancelCascadeIsolatesSubtree ----------------

    /// A mid-graph cancel reaches only the target's own descendants,
    /// never its ancestors or siblings.
    #[test]
    fn plan_cancel_cascade_isolates_subtree() {
        let fx = Fixture::new();
        let root = fx.node("root", NodeStatus::Ready);
        let mid = fx.node("mid", NodeStatus::Ready);
        let leaf = fx.node("leaf", NodeStatus::Declared);
        let sibling = fx.node("sibling", NodeStatus::Ready);
        let plan = plan_cancel_cascade(
            &[root.clone(), mid.clone(), leaf.clone(), sibling.clone()],
            &[
                fx.edge(&mid, &root),
                fx.edge(&leaf, &mid),
                fx.edge(&sibling, &root),
            ],
            mid.id,
        );
        assert_eq!(plan.immediate, [mid.id, leaf.id]);
        assert_eq!(plan.total(), 2, "root and sibling untouched");
    }

    // -- upstream: TestPlanCancelCascadeDegenerateInputs ---------------

    /// The planner is total: unknown root and node-less input both
    /// yield an empty plan.
    #[test]
    fn plan_cancel_cascade_degenerate_inputs() {
        assert_eq!(
            plan_cancel_cascade(&[], &[], WorkflowNodeId::new()).total(),
            0,
            "empty graph plan"
        );
        let fx = Fixture::new();
        let node = fx.node("a", NodeStatus::Ready);
        let plan = plan_cancel_cascade(&[node], &[], WorkflowNodeId::new());
        assert_eq!(plan.total(), 0, "unknown-root plan");
    }

    // -- upstream: TestAmbiguousDecisionKnown --------------------------

    /// The declared decision vocabulary.
    #[test]
    fn ambiguous_decision_known() {
        for d in [AmbiguousDecision::Resume, AmbiguousDecision::Rerun] {
            assert!(super::ambiguous_decision_known(d.as_str()), "{d:?}");
            assert_eq!(AmbiguousDecision::parse(d.as_str()), Some(d));
        }
        for d in ["", "abandon", "RESUME"] {
            assert!(!super::ambiguous_decision_known(d), "{d:?} wrongly known");
        }
    }

    // -- Rust-side: evaluate_readiness (the RecomputeReady predicate) --

    /// RTM-14: a dependent is not `ready` until every ordering
    /// prerequisite is `succeeded` AND every `artifact` in-edge names a
    /// finalized artifact; `not_before` still gates.
    #[test]
    fn evaluate_readiness_flips_only_fully_unblocked_declared() {
        let fx = Fixture::new();
        let now = OffsetDateTime::UNIX_EPOCH + Duration::seconds(100);
        let artifact = ArtifactId::new();

        let no_edges = fx.node("no-edges", NodeStatus::Declared);
        let waiting_order = fx.node("waiting-order", NodeStatus::Declared);
        let waiting_artifact = fx.node("waiting-artifact", NodeStatus::Declared);
        let gated = fx.node("gated", NodeStatus::Declared);
        let mut not_yet = fx.node("not-yet", NodeStatus::Declared);
        not_yet.not_before = Some(now + Duration::seconds(60));
        let prereq_live = fx.node("prereq-live", NodeStatus::Running);
        let prereq_done = fx.node("prereq-done", NodeStatus::Succeeded);
        let already_ready = fx.node("already-ready", NodeStatus::Ready);

        let artifact_edge = |dependent: &Node, prerequisite: &Node| {
            let mut edge = fx.edge(dependent, prerequisite);
            edge.kind = EdgeKind::Artifact;
            edge.artifact_id = Some(artifact);
            edge
        };
        let edges = [
            fx.edge(&waiting_order, &prereq_live),
            artifact_edge(&waiting_artifact, &prereq_done),
            artifact_edge(&gated, &prereq_done),
            fx.edge(&not_yet, &prereq_done),
        ];
        let nodes = [
            no_edges.clone(),
            waiting_order.clone(),
            waiting_artifact.clone(),
            gated.clone(),
            not_yet.clone(),
            prereq_live.clone(),
            prereq_done.clone(),
            already_ready.clone(),
        ];

        // Nothing finalized: only the edge-less declared node flips —
        // the ordering prerequisite still runs, both artifact edges
        // wait, and not_yet's not_before is in the future.
        let change_set = evaluate_readiness(fx.run_id, &nodes, &edges, &|_| false, now);
        assert_eq!(change_set.run_id, fx.run_id);
        assert_eq!(change_set.transitions.len(), 1);
        assert_eq!(
            change_set.transitions[0],
            NodeTransition {
                node_id: no_edges.id,
                expected_state: NodeStatus::Declared,
                next_state: NodeStatus::Ready,
            }
        );
        assert_eq!(change_set.event_intents.len(), 1);
        assert_eq!(change_set.event_intents[0].kind, GraphEventKind::NodeReady);
        assert_eq!(change_set.event_intents[0].actor, ACTOR_SCHEDULER);
        assert_eq!(
            change_set.event_intents[0].payload,
            serde_json::json!({"node_key": "no-edges"})
        );

        // With the artifact finalized, the artifact-waiting nodes flip
        // (waiting_artifact + gated); not_yet still waits on not_before
        // and waiting_order's prerequisite never succeeded.
        let finalized = |id: ArtifactId| id == artifact;
        let change_set = evaluate_readiness(fx.run_id, &nodes, &edges, &finalized, now);
        let flipped: Vec<WorkflowNodeId> =
            change_set.transitions.iter().map(|t| t.node_id).collect();
        assert_eq!(flipped, [no_edges.id, waiting_artifact.id, gated.id]);
        assert_eq!(change_set.event_intents.len(), 3);
    }

    /// An `artifact` edge carrying no artifact id blocks exactly like
    /// an unfinalized artifact (`IS DISTINCT FROM 'ready'`).
    #[test]
    fn evaluate_readiness_blocks_on_missing_artifact_id() {
        let fx = Fixture::new();
        let now = OffsetDateTime::UNIX_EPOCH;
        let child = fx.node("child", NodeStatus::Declared);
        let prereq = fx.node("prereq", NodeStatus::Succeeded);
        let mut edge = fx.edge(&child, &prereq);
        edge.kind = EdgeKind::Artifact;
        edge.artifact_id = None;
        let change_set = evaluate_readiness(fx.run_id, &[child, prereq], &[edge], &|_| true, now);
        assert!(change_set.transitions.is_empty());
        assert!(change_set.event_intents.is_empty());
    }

    // -- Rust-side: cancel_cascade command half ------------------------

    /// The cancel command's change set: `cancelled` transitions guarded
    /// on the observed state, `node_cancelled` + `cancel_requested`
    /// intents, blocked nodes untouched.
    #[test]
    fn cancel_cascade_produces_guarded_change_set() {
        let fx = Fixture::new();
        let root = fx.node("root", NodeStatus::Ready);
        let b = fx.node("b", NodeStatus::Running);
        let c = fx.node("c", NodeStatus::Ready);
        let nodes = [root.clone(), b.clone(), c.clone()];
        let edges = [fx.edge(&b, &root), fx.edge(&c, &b)];

        let outcome = cancel_cascade(&nodes, &edges, root.id, "operator:ops").unwrap();
        // affected() reports group order (immediate → signal →
        // blocked), not BFS order: root+c cancel immediately, b is
        // signalled while running.
        assert_eq!(outcome.plan.affected(), [root.id, c.id, b.id]);
        let set = &outcome.change_set;
        assert_eq!(set.run_id, fx.run_id);
        assert_eq!(
            set.transitions,
            [
                NodeTransition {
                    node_id: root.id,
                    expected_state: NodeStatus::Ready,
                    next_state: NodeStatus::Cancelled,
                },
                NodeTransition {
                    node_id: c.id,
                    expected_state: NodeStatus::Ready,
                    next_state: NodeStatus::Cancelled,
                },
            ]
        );
        let kinds: Vec<GraphEventKind> = set.event_intents.iter().map(|e| e.kind).collect();
        assert_eq!(
            kinds,
            [
                GraphEventKind::NodeCancelled,
                GraphEventKind::NodeCancelled,
                GraphEventKind::CancelRequested
            ]
        );
        assert_eq!(set.event_intents[2].node_id, Some(b.id));
        assert_eq!(
            set.event_intents[2].payload,
            serde_json::json!({"cascade_root": root.id.to_string()})
        );
    }

    /// Cancelling an already-cancelled root is an idempotent replay
    /// success; a `succeeded`/`failed_terminal` root is `DENIED`; an
    /// unknown root is `INVALID`.
    #[test]
    fn cancel_cascade_terminal_root_verdicts() {
        let fx = Fixture::new();
        let cancelled = fx.node("c", NodeStatus::Cancelled);
        let outcome =
            cancel_cascade(std::slice::from_ref(&cancelled), &[], cancelled.id, "op").unwrap();
        assert_eq!(outcome.plan.total(), 0);
        assert!(outcome.change_set.transitions.is_empty());
        assert!(outcome.change_set.event_intents.is_empty());

        for state in [NodeStatus::Succeeded, NodeStatus::FailedTerminal] {
            let root = fx.node("root", state);
            let failure =
                cancel_cascade(std::slice::from_ref(&root), &[], root.id, "op").unwrap_err();
            assert_eq!(failure.class, FailureClass::Denied);
            assert_eq!(failure.reason, REASON_INVALID_NODE_TRANSITION);
        }
        let failure = cancel_cascade(&[], &[], WorkflowNodeId::new(), "op").unwrap_err();
        assert_eq!(failure.class, FailureClass::Invalid);
        assert_eq!(failure.reason, REASON_NODE_NOT_FOUND);
    }

    // -- Rust-side: plan_transition ------------------------------------

    /// A legal transition produces the guarded update plus the
    /// matching journal intent carrying `{from, to}` and the reason
    /// code; an illegal one is `DENIED` and leaves the graph unchanged.
    #[test]
    fn plan_transition_legal_and_denied() {
        let fx = Fixture::new();
        let node = fx.node("n", NodeStatus::Ready);
        let set = plan_transition(&node, NodeStatus::Dispatched, "scheduler", None).unwrap();
        assert_eq!(
            set.transitions,
            [NodeTransition {
                node_id: node.id,
                expected_state: NodeStatus::Ready,
                next_state: NodeStatus::Dispatched,
            }]
        );
        assert_eq!(set.event_intents[0].kind, GraphEventKind::NodeDispatched);
        assert_eq!(
            set.event_intents[0].payload,
            serde_json::json!({"from": "ready", "to": "dispatched"})
        );

        // Running journals attempt_started; a reason rides the row.
        let running = fx.node("r", NodeStatus::Dispatched);
        let set =
            plan_transition(&running, NodeStatus::Running, "worker:w1", Some("RETRY")).unwrap();
        assert_eq!(set.event_intents[0].kind, GraphEventKind::AttemptStarted);
        assert_eq!(set.event_intents[0].reason_code.as_deref(), Some("RETRY"));

        let failure = plan_transition(&node, NodeStatus::Succeeded, "scheduler", None).unwrap_err();
        assert_eq!(failure.class, FailureClass::Denied);
        assert_eq!(failure.reason, REASON_INVALID_NODE_TRANSITION);
    }

    // -- Rust-side: resolve_ambiguous ----------------------------------

    /// The operator decision's write unit: `attempt_decision` journaled;
    /// `rerun` additionally returns the node to `ready`; `resume` leaves
    /// it parked.
    #[test]
    fn resolve_ambiguous_resume_and_rerun() {
        let fx = Fixture::new();
        let node = fx.node("n", NodeStatus::AttemptAmbiguous);

        let set = resolve_ambiguous(&node, "resume", "operator:ops").unwrap();
        assert!(set.transitions.is_empty());
        assert_eq!(set.event_intents.len(), 1);
        assert_eq!(set.event_intents[0].kind, GraphEventKind::AttemptDecision);
        assert_eq!(
            set.event_intents[0].payload,
            serde_json::json!({"decision": "resume"})
        );

        let set = resolve_ambiguous(&node, "rerun", "operator:ops").unwrap();
        assert_eq!(
            set.transitions,
            [NodeTransition {
                node_id: node.id,
                expected_state: NodeStatus::AttemptAmbiguous,
                next_state: NodeStatus::Ready,
            }]
        );
        assert_eq!(set.event_intents.len(), 2);
        assert_eq!(set.event_intents[1].kind, GraphEventKind::NodeReady);

        let failure = resolve_ambiguous(&node, "abandon", "operator:ops").unwrap_err();
        assert_eq!(failure.class, FailureClass::Invalid);
        assert_eq!(failure.reason, REASON_UNKNOWN_DECISION);

        let ready = fx.node("r", NodeStatus::Ready);
        let failure = resolve_ambiguous(&ready, "rerun", "operator:ops").unwrap_err();
        assert_eq!(failure.class, FailureClass::Denied);
        assert_eq!(failure.reason, REASON_NODE_NOT_AMBIGUOUS);
    }
}
