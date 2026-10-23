//! The `central.workflow_nodes` / `workflow_edges` store — port of
//! `internal/adapter/postgres/workflow/store.go`.
//!
//! Every mutating method opens one transaction through
//! [`crate::store_support::begin_tx`] and takes the run-row lock —
//! `SELECT … FROM central.runs WHERE id = $1 FOR UPDATE`, the spec-6
//! OQ-1 serialization point shared with the event journal — before any
//! other write-side statement. Lock order is run row then node row(s),
//! everywhere. Graph mutations and their journal rows commit
//! atomically because the journal append runs inside the same
//! transaction ([`crate::eventjournal::append_tx`]); rows are
//! append-only except `workflow_nodes.state`/`ready_at`, and the
//! `ON CONFLICT` idempotency lines make re-emission and replay
//! exact-replay successes rather than failures.
//!
//! [`crate::validate::validate_batch`]-family purity is preserved:
//! the store reads committed rows, feeds them to the domain planners
//! ([`crate::readiness::plan_transition`], `evaluate_readiness`,
//! `cancel_cascade`, `resolve_ambiguous`), and applies the produced
//! [`GraphChangeSet`] — each [`NodeTransition::expected_state`]
//! re-verified on the guarded `UPDATE` even though the row lock
//! already serialized the plan.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use central_eventjournal::domain::RunEvent;
use central_foundation::failure::Failure;
use central_foundation::identity::{
    ArtifactId, RunEventId, RunId, SessionAttemptId, WorkflowEdgeId, WorkflowNodeId, WorkspaceId,
};
use central_workflow::domain::{
    self as wf, BudgetCeiling, CHILD_SPEC_VERSION, Caps, ChildSpec, ChildSpecNode, Edge, EdgeKind,
    EmitResult, GraphChangeSet, GraphEventIntent, Node, NodeStatus, NodeTransition,
    REASON_AMBIGUOUS_ATTEMPT_MISSING, REASON_ATTEMPT_DECISION_CONFLICT,
    REASON_DUPLICATE_IDEMPOTENCY_KEY, REASON_INVALID_NODE_TRANSITION, REASON_NODE_NOT_FOUND,
    REASON_PARENT_NOT_FOUND, REASON_PARENT_RUN_MISMATCH, REASON_RUN_NOT_FOUND,
    REASON_UNKNOWN_DECISION,
};
use central_workflow::port::WorkflowStore;
use central_workflow::query::{
    GraphPage, GraphPageRequest, NodeSeekCursor, WorkflowGraphRead, normalize_graph_page_size,
    validate_graph_page_request,
};
use central_workflow::readiness::resolve_ambiguous as plan_resolution;
use central_workflow::readiness::{
    ambiguous_decision_known, cancel_cascade, evaluate_readiness, plan_transition,
};
use central_workflow::validate::{
    ArtifactFinalizedChecker, HarnessRegistry, batch_depths, validate_batch,
};
use sqlx::{PgPool, Postgres, Transaction};
use time::OffsetDateTime;

use crate::error::SqlxContext;
use crate::eventjournal::append_tx;
use crate::execution::go_json_escapes;
use crate::store_support::{PG_DATA_CORRUPT, begin_tx, opt_uuid_of, uuid_of};

/// A stored `workflow_nodes.state` value outside the migration-pinned
/// vocabulary (or any other durable-row invariant violation) is
/// `pg_data_corrupt`, never a caller error.
fn corrupt(what: &'static str) -> Failure {
    Failure::internal(PG_DATA_CORRUPT, what)
}

/// [`wf::Failure`] (the closed domain failure) → the shared taxonomy;
/// the `From` impl carries class→kind and reason→code.
fn domain(failure: wf::Failure) -> Failure {
    Failure::from(failure)
}

/// One `workflow_nodes` row (`query_as!` target shared by every
/// node-selecting call site).
struct NodeRow {
    id: uuid::Uuid,
    run_id: uuid::Uuid,
    workspace_id: uuid::Uuid,
    node_key: String,
    parent_node_id: Option<uuid::Uuid>,
    harness: String,
    workspace_kind: String,
    depth: i32,
    state: String,
    budget_wall_clock_seconds: Option<i64>,
    budget_cost_micro_usd: Option<i64>,
    max_attempts: i32,
    attempt_count: i32,
    not_before: Option<OffsetDateTime>,
    input_artifact_refs: serde_json::Value,
    spec: serde_json::Value,
    spec_fingerprint: Option<Vec<u8>>,
    node_timeout_seconds: Option<i64>,
    ready_at: Option<OffsetDateTime>,
    created_at: OffsetDateTime,
}

impl NodeRow {
    fn decode(self) -> Result<Node, Failure> {
        let state = NodeStatus::parse(&self.state)
            .ok_or_else(|| corrupt("a stored workflow_nodes.state is outside the vocabulary"))?;
        let input_artifact_refs = serde_json::from_value::<Vec<wf::ArtifactRef>>(
            self.input_artifact_refs,
        )
        .map_err(|_| corrupt("a stored input_artifact_refs is not an artifact-ref array"))?;
        Ok(Node {
            id: WorkflowNodeId::from_trusted_db_bytes(*self.id.as_bytes()),
            run_id: RunId::from_trusted_db_bytes(*self.run_id.as_bytes()),
            workspace_id: WorkspaceId::from_trusted_db_bytes(*self.workspace_id.as_bytes()),
            node_key: self.node_key,
            parent_id: self
                .parent_node_id
                .map(|id| WorkflowNodeId::from_trusted_db_bytes(*id.as_bytes())),
            harness: self.harness,
            workspace_kind: self.workspace_kind,
            depth: self.depth,
            state,
            budget_wall_clock_sec: self.budget_wall_clock_seconds,
            budget_cost_micro_usd: self.budget_cost_micro_usd,
            max_attempts: self.max_attempts,
            attempt_count: self.attempt_count,
            not_before: self.not_before,
            input_artifact_refs,
            spec: self.spec,
            spec_fingerprint: self.spec_fingerprint,
            node_timeout_seconds: self.node_timeout_seconds,
            ready_at: self.ready_at,
            created_at: self.created_at,
        })
    }
}

/// One `workflow_edges` row.
struct EdgeRow {
    id: uuid::Uuid,
    run_id: uuid::Uuid,
    dependent_node_id: uuid::Uuid,
    prerequisite_node_id: uuid::Uuid,
    kind: String,
    artifact_id: Option<uuid::Uuid>,
    created_at: OffsetDateTime,
}

impl EdgeRow {
    fn decode(self) -> Result<Edge, Failure> {
        let kind = EdgeKind::parse(&self.kind)
            .ok_or_else(|| corrupt("a stored workflow_edges.kind is outside the vocabulary"))?;
        Ok(Edge {
            id: WorkflowEdgeId::from_trusted_db_bytes(*self.id.as_bytes()),
            run_id: RunId::from_trusted_db_bytes(*self.run_id.as_bytes()),
            dependent_node_id: WorkflowNodeId::from_trusted_db_bytes(
                *self.dependent_node_id.as_bytes(),
            ),
            prerequisite_node_id: WorkflowNodeId::from_trusted_db_bytes(
                *self.prerequisite_node_id.as_bytes(),
            ),
            kind,
            artifact_id: self
                .artifact_id
                .map(|id| ArtifactId::from_trusted_db_bytes(*id.as_bytes())),
            created_at: self.created_at,
        })
    }
}

/// `childSpecFingerprint` — the spec-5 replay-compare value: SHA-256
/// over the same canonical spec bytes the `spec` jsonb column records
/// (Go `json.Marshal(child)` → [`go_json_escapes`] applies its string
/// escapes so the hashed bytes match upstream).
fn child_spec_fingerprint(child: &ChildSpecNode) -> Result<([u8; 32], serde_json::Value), Failure> {
    let spec_bytes = serde_json::to_vec(child).map_err(|_| {
        Failure::internal(
            "workflow_spec_encode",
            "a child spec could not be JSON-encoded",
        )
    })?;
    let spec_bytes = go_json_escapes(&spec_bytes);
    let fingerprint = crate::execution::sha256(&spec_bytes);
    let spec = serde_json::from_slice::<serde_json::Value>(&spec_bytes)
        .map_err(|_| corrupt("re-encoded spec JSON failed to parse"))?;
    Ok((fingerprint, spec))
}

/// A [`GraphEventIntent`] as the canonical journal envelope the tx
/// append consumes: the adapter assigns the event id; `seq` and
/// `recorded_at` are allocated/stamped inside the append.
fn intent_event(workspace_id: WorkspaceId, run_id: RunId, intent: &GraphEventIntent) -> RunEvent {
    RunEvent {
        id: RunEventId::new(),
        workspace_id,
        run_id,
        seq: 0,
        node_id: intent.node_id,
        attempt_id: intent.attempt_id,
        kind: intent.kind.as_str().to_string(),
        actor: intent.actor.clone(),
        reason_code: intent.reason_code.clone(),
        payload: intent.payload.clone(),
        recorded_at: OffsetDateTime::UNIX_EPOCH,
    }
}

/// PostgreSQL-backed workflow graph store — a `PgPool` holder with the
/// emit-time validation seams upstream carries as `Store` fields
/// (`HarnessLaunchable`, `ArtifactFinalized`, `Caps`). Unset seams are
/// fail-closed; a zero `Caps` falls back to [`Caps::locked`].
pub struct Store {
    pool: PgPool,
    /// Emit-time validator seam: whether a harness name is launchable.
    pub harness_registry: Option<Arc<dyn HarnessRegistry>>,
    /// Emit-time validator seam: whether an `(artifact, checksum)` ref
    /// names a finalized artifact.
    pub artifact_finalized: Option<Arc<dyn ArtifactFinalizedChecker>>,
    /// The effective concurrency caps; the zero value means
    /// [`Caps::locked`].
    pub caps: Caps,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("harness_registry", &self.harness_registry.is_some())
            .field("artifact_finalized", &self.artifact_finalized.is_some())
            .field("caps", &self.caps)
            .finish_non_exhaustive()
    }
}

impl Store {
    /// Binds the store to a `central_runtime`-authorized pool with the
    /// locked Phase-2 caps (upstream `NewStore` defaults
    /// `Caps: DefaultCaps()`); the validation seams stay unset — the
    /// composition site fills them, and an unset seam is fail-closed.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            harness_registry: None,
            artifact_finalized: None,
            caps: Caps::locked(),
        }
    }

    /// Locks the run row (the shared spec-6 OQ-1 serialization point)
    /// and returns its `workspace_id`; a missing row is the
    /// `WORKFLOW_RUN_NOT_FOUND` invalid.
    async fn lock_run(
        tx: &mut Transaction<'_, Postgres>,
        run_id: RunId,
    ) -> Result<WorkspaceId, Failure> {
        let workspace = sqlx::query_scalar!(
            "SELECT workspace_id FROM central.runs WHERE id = $1 FOR UPDATE",
            uuid_of(run_id.as_bytes()),
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("workflow: lock run row")?
        .ok_or_else(|| {
            domain(wf::Failure::new(
                wf::FailureClass::Invalid,
                REASON_RUN_NOT_FOUND,
            ))
        })?;
        Ok(WorkspaceId::from_trusted_db_bytes(*workspace.as_bytes()))
    }

    /// The node's `(run_id, workspace_id)` — the pre-lock read upstream
    /// performs to learn which run row serializes the mutation; the
    /// row is re-read under the lock before any plan consumes it.
    async fn node_scope(
        tx: &mut Transaction<'_, Postgres>,
        node_id: WorkflowNodeId,
    ) -> Result<(RunId, WorkspaceId), Failure> {
        let row = sqlx::query!(
            "SELECT run_id, workspace_id FROM central.workflow_nodes WHERE id = $1",
            uuid_of(node_id.as_bytes()),
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("workflow: read node scope")?
        .ok_or_else(|| {
            domain(wf::Failure::new(
                wf::FailureClass::Invalid,
                REASON_NODE_NOT_FOUND,
            ))
        })?;
        Ok((
            RunId::from_trusted_db_bytes(*row.run_id.as_bytes()),
            WorkspaceId::from_trusted_db_bytes(*row.workspace_id.as_bytes()),
        ))
    }

    /// The full node row under `FOR UPDATE` — lock order is run row
    /// first, so callers take [`Store::lock_run`] before this.
    async fn lock_node(
        tx: &mut Transaction<'_, Postgres>,
        node_id: WorkflowNodeId,
    ) -> Result<Node, Failure> {
        let row = sqlx::query_as!(
            NodeRow,
            "SELECT id, run_id, workspace_id, node_key, parent_node_id, \
                    harness, workspace_kind, depth, state, \
                    budget_wall_clock_seconds, budget_cost_micro_usd, \
                    max_attempts, attempt_count, not_before, input_artifact_refs, spec, \
                    spec_fingerprint, node_timeout_seconds, ready_at, created_at \
             FROM central.workflow_nodes WHERE id = $1 FOR UPDATE",
            uuid_of(node_id.as_bytes()),
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("workflow: lock node row")?
        .ok_or_else(|| corrupt("a locked workflow_nodes row vanished"))?;
        row.decode()
    }

    /// Every committed node of the run in `(created_at, id)` order —
    /// upstream `selectNodesTx`.
    async fn nodes_in_tx(
        tx: &mut Transaction<'_, Postgres>,
        run_id: RunId,
    ) -> Result<Vec<Node>, Failure> {
        let rows = sqlx::query_as!(
            NodeRow,
            "SELECT id, run_id, workspace_id, node_key, parent_node_id, \
                    harness, workspace_kind, depth, state, \
                    budget_wall_clock_seconds, budget_cost_micro_usd, \
                    max_attempts, attempt_count, not_before, input_artifact_refs, spec, \
                    spec_fingerprint, node_timeout_seconds, ready_at, created_at \
             FROM central.workflow_nodes WHERE run_id = $1 \
             ORDER BY created_at, id",
            uuid_of(run_id.as_bytes()),
        )
        .fetch_all(&mut **tx)
        .await
        .ctx("workflow: select nodes")?;
        rows.into_iter().map(NodeRow::decode).collect()
    }

    /// Every committed edge of the run in `(created_at, id)` order —
    /// upstream `selectEdgesTx`.
    async fn edges_in_tx(
        tx: &mut Transaction<'_, Postgres>,
        run_id: RunId,
    ) -> Result<Vec<Edge>, Failure> {
        let rows = sqlx::query_as!(
            EdgeRow,
            "SELECT id, run_id, dependent_node_id, prerequisite_node_id, kind, \
                    artifact_id, created_at \
             FROM central.workflow_edges WHERE run_id = $1 \
             ORDER BY created_at, id",
            uuid_of(run_id.as_bytes()),
        )
        .fetch_all(&mut **tx)
        .await
        .ctx("workflow: select edges")?;
        rows.into_iter().map(EdgeRow::decode).collect()
    }

    /// One committed node by `(run_id, node_key)` — the
    /// `ON CONFLICT`-reselect path upstream calls `selectNodeByKeyTx`;
    /// the row must exist because the conflict fired.
    async fn node_by_key_in_tx(
        tx: &mut Transaction<'_, Postgres>,
        run_id: RunId,
        node_key: &str,
    ) -> Result<Node, Failure> {
        let row = sqlx::query_as!(
            NodeRow,
            "SELECT id, run_id, workspace_id, node_key, parent_node_id, \
                    harness, workspace_kind, depth, state, \
                    budget_wall_clock_seconds, budget_cost_micro_usd, \
                    max_attempts, attempt_count, not_before, input_artifact_refs, spec, \
                    spec_fingerprint, node_timeout_seconds, ready_at, created_at \
             FROM central.workflow_nodes WHERE run_id = $1 AND node_key = $2",
            uuid_of(run_id.as_bytes()),
            node_key,
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("workflow: select node by key")?
        .ok_or_else(|| corrupt("a conflicted workflow_nodes row vanished"))?;
        row.decode()
    }

    /// `insertNodeTx` — writes one validated child. A `None` child
    /// budget inherits the parent's remaining envelope, recorded
    /// explicitly on the row. The bool reports whether the
    /// `(run_id, node_key)` row already existed — the
    /// idempotent-dedupe path that re-selects instead of inserting.
    ///
    /// The b37 columns persist alongside the spec jsonb:
    /// `spec_fingerprint`, the SHA-256 of the canonical spec bytes (the
    /// spec-5 replay-compare value dedup reads back), and
    /// `node_timeout_seconds`, the aggregate bound measured from first
    /// dispatch (a duration column, never an absolute deadline).
    async fn insert_node_tx(
        tx: &mut Transaction<'_, Postgres>,
        run_id: RunId,
        workspace_id: WorkspaceId,
        parent_id: Option<WorkflowNodeId>,
        child: &ChildSpecNode,
        depth: i32,
        parent_remaining: BudgetCeiling,
    ) -> Result<(Node, bool), Failure> {
        let (fingerprint, spec) = child_spec_fingerprint(child)?;
        let refs_json = serde_json::to_value(&child.input_artifact_refs).map_err(|_| {
            Failure::internal(
                "workflow_spec_encode",
                "input artifact refs could not be encoded",
            )
        })?;
        let (wall, cost) = child.budget.map_or(
            (
                parent_remaining.wall_clock_seconds,
                parent_remaining.cost_micro_usd,
            ),
            |budget| (budget.wall_clock_seconds, budget.cost_micro_usd),
        );

        let node_id = WorkflowNodeId::new();
        let inserted = sqlx::query!(
            "INSERT INTO central.workflow_nodes \
                (id, run_id, workspace_id, node_key, parent_node_id, harness, \
                 workspace_kind, depth, state, \
                 budget_wall_clock_seconds, budget_cost_micro_usd, \
                 input_artifact_refs, spec, spec_fingerprint, node_timeout_seconds) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'declared', $9, $10, $11, $12, $13, $14) \
             ON CONFLICT (run_id, node_key) DO NOTHING \
             RETURNING id, created_at",
            uuid_of(node_id.as_bytes()),
            uuid_of(run_id.as_bytes()),
            uuid_of(workspace_id.as_bytes()),
            child.node_key.as_str(),
            opt_uuid_of(parent_id, |i| i.as_bytes()),
            child.harness.as_str(),
            child.workspace_kind.as_str(),
            depth,
            wall,
            cost,
            refs_json,
            spec.clone(),
            fingerprint.as_slice(),
            child.node_timeout_seconds,
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("workflow emit: insert node")?;

        let Some(inserted) = inserted else {
            // The (run_id, node_key) constraint fired: re-read the
            // recorded fingerprint. Equal means exact replay;
            // different is the DUPLICATE_IDEMPOTENCY_KEY verdict and
            // the recorded row stands.
            let node = Self::node_by_key_in_tx(tx, run_id, &child.node_key).await?;
            if node.spec_fingerprint.as_deref() != Some(fingerprint.as_slice()) {
                return Err(domain(wf::Failure::new(
                    wf::FailureClass::Conflict,
                    REASON_DUPLICATE_IDEMPOTENCY_KEY,
                )));
            }
            return Ok((node, true));
        };

        // The recorded spec bytes, decoded once — upstream stores the
        // marshaled child verbatim in `spec`.
        let node = Node {
            id: WorkflowNodeId::from_trusted_db_bytes(*inserted.id.as_bytes()),
            run_id,
            workspace_id,
            node_key: child.node_key.clone(),
            parent_id,
            harness: child.harness.clone(),
            workspace_kind: child.workspace_kind.clone(),
            depth,
            state: NodeStatus::Declared,
            budget_wall_clock_sec: wall,
            budget_cost_micro_usd: cost,
            max_attempts: 1,
            attempt_count: 0,
            not_before: None,
            input_artifact_refs: child.input_artifact_refs.clone(),
            spec,
            spec_fingerprint: Some(fingerprint.to_vec()),
            node_timeout_seconds: child.node_timeout_seconds,
            ready_at: None,
            created_at: inserted.created_at,
        };
        Ok((node, false))
    }

    /// Applies a domain-planned [`GraphChangeSet`] inside `tx`:
    /// expected-state-guarded transitions (a `→ ready` write stamps
    /// `ready_at`) then the journal intents in order. A guard that
    /// fires zero rows means the plan went stale — `DENIED`/
    /// `INVALID_NODE_TRANSITION`, the same verdict the state machine
    /// gives.
    async fn apply_change_set(
        tx: &mut Transaction<'_, Postgres>,
        workspace_id: WorkspaceId,
        run_id: RunId,
        change_set: &GraphChangeSet,
    ) -> Result<(), Failure> {
        for transition in &change_set.transitions {
            Self::apply_transition_tx(tx, transition).await?;
        }
        for intent in &change_set.event_intents {
            append_tx(tx, &intent_event(workspace_id, run_id, intent)).await?;
        }
        Ok(())
    }

    /// One guarded node transition — the commit applies the update only
    /// while the row still carries `expected_state`, stamping
    /// `ready_at` when landing `ready`.
    async fn apply_transition_tx(
        tx: &mut Transaction<'_, Postgres>,
        transition: &NodeTransition,
    ) -> Result<(), Failure> {
        let node = uuid_of(transition.node_id.as_bytes());
        let next = transition.next_state.as_str();
        let expected = transition.expected_state.as_str();
        let tag = if transition.next_state == NodeStatus::Ready {
            sqlx::query!(
                "UPDATE central.workflow_nodes SET state = $2, ready_at = now() \
                 WHERE id = $1 AND state = $3",
                node,
                next,
                expected,
            )
            .execute(&mut **tx)
            .await
            .ctx("workflow: transition node")?
        } else {
            sqlx::query!(
                "UPDATE central.workflow_nodes SET state = $2 WHERE id = $1 AND state = $3",
                node,
                next,
                expected,
            )
            .execute(&mut **tx)
            .await
            .ctx("workflow: transition node")?
        };
        if tag.rows_affected() != 1 {
            return Err(domain(wf::Failure::new(
                wf::FailureClass::Denied,
                REASON_INVALID_NODE_TRANSITION,
            )));
        }
        Ok(())
    }
}

impl WorkflowStore for Store {
    /// `EmitBatch` — the refined four-step contract of
    /// [`WorkflowStore::emit_batch`]: lock+parent resolution, dedup
    /// partition before validation, novel-only validation against the
    /// full committed key set, then the atomic commit of nodes, derived
    /// edges, and journal events.
    async fn emit_batch(
        &self,
        run_id: RunId,
        parent_id: Option<WorkflowNodeId>,
        batch: ChildSpec,
    ) -> Result<EmitResult, Failure> {
        let mut tx = begin_tx(&self.pool).await?;

        // Step 1 — lock + parent resolution. The run-row lock
        // serializes every writer of this run's graph and journal. A
        // `None` parent emits the run's roots: depth base -1 (batch
        // roots land at absolute depth 0) and an unbounded remaining
        // budget envelope.
        let workspace_id = Self::lock_run(&mut tx, run_id).await?;
        let mut parent_depth: i64 = -1;
        let mut parent_remaining = BudgetCeiling::default();
        if let Some(parent_id) = parent_id {
            let parent = sqlx::query!(
                "SELECT run_id, depth, budget_wall_clock_seconds, budget_cost_micro_usd \
                 FROM central.workflow_nodes WHERE id = $1",
                uuid_of(parent_id.as_bytes()),
            )
            .fetch_optional(&mut *tx)
            .await
            .ctx("workflow emit: read parent node")?
            .ok_or_else(|| {
                domain(wf::Failure::new(
                    wf::FailureClass::Invalid,
                    REASON_PARENT_NOT_FOUND,
                ))
            })?;
            if parent.run_id != uuid_of(run_id.as_bytes()) {
                return Err(domain(wf::Failure::new(
                    wf::FailureClass::Denied,
                    REASON_PARENT_RUN_MISMATCH,
                )));
            }
            parent_depth = i64::from(parent.depth);
            parent_remaining = BudgetCeiling {
                wall_clock_seconds: parent.budget_wall_clock_seconds,
                cost_micro_usd: parent.budget_cost_micro_usd,
            };
        }

        let committed = Self::nodes_in_tx(&mut tx, run_id).await?;
        let edges = Self::edges_in_tx(&mut tx, run_id).await?;
        let mut existing_keys = BTreeSet::new();
        let mut by_key = BTreeMap::new();
        for node in committed {
            existing_keys.insert(node.node_key.clone());
            by_key.insert(node.node_key.clone(), node);
        }

        // Step 2 — dedup partition on the spec-5 idempotency key
        // (run_id, node_key) BEFORE validation: an equal recorded
        // spec_fingerprint dedupes to the committed node; a different
        // one rejects the whole batch as
        // CONFLICT/DUPLICATE_IDEMPOTENCY_KEY with the recorded row
        // standing.
        let mut deduped: BTreeMap<String, Node> = BTreeMap::new();
        let mut novel = ChildSpec {
            version: batch.version.clone(),
            children: Vec::new(),
        };
        for child in &batch.children {
            let Some(existing) = by_key.get(&child.node_key) else {
                novel.children.push(child.clone());
                continue;
            };
            let (fingerprint, _) = child_spec_fingerprint(child)?;
            if existing.spec_fingerprint.as_deref() != Some(fingerprint.as_slice()) {
                return Err(domain(wf::Failure::new(
                    wf::FailureClass::Conflict,
                    REASON_DUPLICATE_IDEMPOTENCY_KEY,
                )));
            }
            deduped.insert(child.node_key.clone(), existing.clone());
        }

        // Step 3 — validate ONLY the novel children while
        // `existing_keys` still names every committed key: feeding the
        // full batch would falsely reject an exact replay on the
        // unique-key rule. Validation is skipped only when the novel
        // set is empty AND the envelope is on-version — the
        // fully-deduped replay of an on-version batch is the one path
        // that skips it.
        let mut rejection = None;
        if !novel.children.is_empty() || batch.version != CHILD_SPEC_VERSION {
            let mut caps = self.caps;
            if caps == Caps::default() {
                caps = Caps::locked();
            }
            // The validator evaluates batch-internal depth (batch roots
            // = 1); absolute depth is parent_depth + batch-internal, so
            // the cap it checks against is shifted by the parent's
            // absolute depth (upstream `effective.MaxDepth =
            // caps.MaxDepth - parentDepth`; a parent at or beyond the
            // cap shifts to 0, which rejects any child).
            let effective = Caps {
                max_depth: (i64::from(caps.max_depth) - parent_depth).clamp(0, i64::from(u32::MAX))
                    as u32,
                ..caps
            };
            rejection = validate_batch(
                &existing_keys,
                &edges,
                &novel,
                effective,
                parent_remaining,
                self.harness_registry.as_deref(),
                self.artifact_finalized.as_deref(),
            );
        }
        if let Some(rejection) = rejection {
            // Rejection is data, not a crash: the child_spec_rejected
            // event must survive even though the graph is unchanged.
            let intent = rejection.to_event_intent(parent_id);
            append_tx(&mut tx, &intent_event(workspace_id, run_id, &intent)).await?;
            tx.commit().await.ctx("workflow emit: commit rejection")?;
            return Ok(EmitResult {
                nodes: Vec::new(),
                rejected: Some(rejection),
            });
        }

        // Step 4 — commit. Novel children insert at absolute depth
        // parent_depth + batch-internal depth; (run_id, node_key)
        // ON CONFLICT is the second idempotency line and resolves to
        // the committed row either way. The node-key→id map covers
        // committed, deduped, and just-inserted nodes so depends_on
        // resolves across the batch boundary.
        let depths = batch_depths(&novel);
        let mut inserted: BTreeMap<String, Node> = BTreeMap::new();
        let mut node_ids: BTreeMap<String, WorkflowNodeId> = by_key
            .iter()
            .map(|(key, node)| (key.clone(), node.id))
            .collect();
        for child in &novel.children {
            let depth = i32::try_from(parent_depth + i64::from(depths[&child.node_key]))
                .map_err(|_| corrupt("a batch depth overflowed the depth column"))?;
            let (node, was_present) = Self::insert_node_tx(
                &mut tx,
                run_id,
                workspace_id,
                parent_id,
                child,
                depth,
                parent_remaining,
            )
            .await?;
            node_ids.insert(child.node_key.clone(), node.id);
            if was_present {
                deduped.insert(child.node_key.clone(), node);
            } else {
                inserted.insert(child.node_key.clone(), node);
            }
        }

        // Edges for the novel children: depends_on becomes an ordering
        // in-edge per prerequisite; each input_artifact_ref whose
        // artifact was produced inside this run becomes an artifact
        // in-edge from the producer node (the declared-read edge). Refs
        // produced outside the run stay declared on the node's
        // input_artifact_refs — the read-scope union reads both
        // sources.
        for child in &novel.children {
            let Some(&dependent_id) = node_ids.get(&child.node_key) else {
                return Err(corrupt("a committed node key lost its id mapping"));
            };
            for dep in &child.depends_on {
                let Some(&prerequisite) = node_ids.get(dep.as_str()) else {
                    return Err(corrupt("a validated depends_on key has no committed node"));
                };
                sqlx::query!(
                    "INSERT INTO central.workflow_edges \
                        (id, run_id, dependent_node_id, prerequisite_node_id, kind, artifact_id) \
                     VALUES ($1, $2, $3, $4, 'ordering', NULL) \
                     ON CONFLICT DO NOTHING",
                    uuid_of(WorkflowEdgeId::new().as_bytes()),
                    uuid_of(run_id.as_bytes()),
                    uuid_of(dependent_id.as_bytes()),
                    uuid_of(prerequisite.as_bytes()),
                )
                .execute(&mut *tx)
                .await
                .ctx("workflow emit: insert ordering edge")?;
            }
            for artifact_ref in &child.input_artifact_refs {
                let producer = sqlx::query_scalar!(
                    "SELECT node_id FROM central.artifact_produce_edges \
                     WHERE run_id = $1 AND artifact_id = $2",
                    uuid_of(run_id.as_bytes()),
                    uuid_of(artifact_ref.artifact_id.as_bytes()),
                )
                .fetch_optional(&mut *tx)
                .await
                .ctx("workflow emit: resolve artifact producer")?;
                let Some(producer) = producer else {
                    continue;
                };
                sqlx::query!(
                    "INSERT INTO central.workflow_edges \
                        (id, run_id, dependent_node_id, prerequisite_node_id, kind, artifact_id) \
                     VALUES ($1, $2, $3, $4, 'artifact', $5) \
                     ON CONFLICT DO NOTHING",
                    uuid_of(WorkflowEdgeId::new().as_bytes()),
                    uuid_of(run_id.as_bytes()),
                    uuid_of(dependent_id.as_bytes()),
                    producer,
                    uuid_of(artifact_ref.artifact_id.as_bytes()),
                )
                .execute(&mut *tx)
                .await
                .ctx("workflow emit: insert artifact edge")?;
            }
        }

        // node_declared journals for newly inserted nodes only — a
        // deduped node already carries its declaration in the journal.
        for child in &novel.children {
            let Some(node) = inserted.get(&child.node_key) else {
                continue;
            };
            let intent = GraphEventIntent::node_declared(node, child);
            append_tx(&mut tx, &intent_event(workspace_id, run_id, &intent)).await?;
        }
        // Each replayed child journals command_deduped (spec-5 replay
        // semantics): a re-emission of an already-recorded key is
        // observable in the journal rather than silent.
        for child in &batch.children {
            let Some(node) = deduped.get(&child.node_key) else {
                continue;
            };
            let intent = GraphEventIntent::emit_deduped(node.id, &child.node_key);
            append_tx(&mut tx, &intent_event(workspace_id, run_id, &intent)).await?;
        }

        tx.commit().await.ctx("workflow emit: commit batch")?;
        Ok(EmitResult {
            nodes: batch
                .children
                .iter()
                .map(|child| {
                    inserted
                        .get(&child.node_key)
                        .or_else(|| deduped.get(&child.node_key))
                        .cloned()
                        .ok_or_else(|| corrupt("a batch child lost its node mapping"))
                })
                .collect::<Result<Vec<_>, _>>()?,
            rejected: None,
        })
    }

    /// `Transition` — one node along the declared state machine with
    /// its journal event in the same commit. Lock order is run row
    /// then node row, matching `emit_batch`.
    async fn transition(
        &self,
        node_id: WorkflowNodeId,
        to: NodeStatus,
        actor: &str,
        reason: Option<&str>,
    ) -> Result<(), Failure> {
        let mut tx = begin_tx(&self.pool).await?;
        let (run_id, workspace_id) = Self::node_scope(&mut tx, node_id).await?;
        Self::lock_run(&mut tx, run_id).await?;
        let node = Self::lock_node(&mut tx, node_id).await?;

        let change_set = plan_transition(&node, to, actor, reason).map_err(domain)?;
        Self::apply_change_set(&mut tx, workspace_id, run_id, &change_set).await?;
        tx.commit().await.ctx("workflow transition: commit")?;
        Ok(())
    }

    /// `RecomputeReady` — flips every declared node of the run whose
    /// ordering prerequisites all succeeded, whose artifact
    /// prerequisites all name finalized (`ready`) artifacts, and whose
    /// `not_before` gate has passed, journaling `node_ready` per node.
    /// The domain planner evaluates the committed rows; the artifact
    /// probe is a pre-fetched `state = 'ready'` set — the same
    /// `IS DISTINCT FROM 'ready'` predicate upstream evaluates in SQL
    /// (a missing artifact row blocks either way).
    async fn recompute_ready(&self, run_id: RunId) -> Result<Vec<WorkflowNodeId>, Failure> {
        let mut tx = begin_tx(&self.pool).await?;
        let workspace_id = Self::lock_run(&mut tx, run_id).await?;
        let nodes = Self::nodes_in_tx(&mut tx, run_id).await?;
        let edges = Self::edges_in_tx(&mut tx, run_id).await?;

        let artifact_ids: Vec<uuid::Uuid> = edges
            .iter()
            .filter_map(|edge| edge.artifact_id)
            .map(|id| uuid_of(id.as_bytes()))
            .collect();
        let mut finalized = BTreeSet::new();
        if !artifact_ids.is_empty() {
            let rows = sqlx::query_scalar!(
                "SELECT id FROM central.artifacts WHERE state = 'ready' AND id = ANY($1)",
                artifact_ids.as_slice(),
            )
            .fetch_all(&mut *tx)
            .await
            .ctx("workflow recompute: read artifact states")?;
            finalized = rows
                .into_iter()
                .map(|id| ArtifactId::from_trusted_db_bytes(*id.as_bytes()))
                .collect();
        }

        let change_set = evaluate_readiness(
            run_id,
            &nodes,
            &edges,
            &|artifact_id| finalized.contains(&artifact_id),
            OffsetDateTime::now_utc(),
        );
        let ready: Vec<WorkflowNodeId> = change_set
            .transitions
            .iter()
            .map(|transition| transition.node_id)
            .collect();
        Self::apply_change_set(&mut tx, workspace_id, run_id, &change_set).await?;
        tx.commit().await.ctx("workflow recompute: commit")?;
        Ok(ready)
    }

    /// `CancelNode` — the spec-1 cascade in one commit: `declared`/
    /// `ready` nodes transition to `cancelled` with a `node_cancelled`
    /// event each, `dispatched`/`running` nodes keep their state and
    /// receive `cancel_requested` intent, `attempt_ambiguous` nodes
    /// park while the cascade flows past them. Re-cancelling a
    /// cancelled node is an idempotent success; a `succeeded`/
    /// `failed_terminal` root refuses `DENIED`. Returns every reached
    /// node — immediate, signal, blocked — in plan order.
    async fn cancel_node(
        &self,
        node_id: WorkflowNodeId,
        actor: &str,
    ) -> Result<Vec<WorkflowNodeId>, Failure> {
        let mut tx = begin_tx(&self.pool).await?;
        let (run_id, workspace_id) = Self::node_scope(&mut tx, node_id).await?;
        Self::lock_run(&mut tx, run_id).await?;
        let root = Self::lock_node(&mut tx, node_id).await?;

        // Upstream's early terminal check on the locked root: the
        // replay of a committed cancel is an idempotent success; any
        // other terminal root is denied.
        if root.state.is_terminal() {
            if root.state == NodeStatus::Cancelled {
                tx.commit().await.ctx("workflow cancel: commit replay")?;
                return Ok(Vec::new());
            }
            return Err(domain(wf::Failure::new(
                wf::FailureClass::Denied,
                REASON_INVALID_NODE_TRANSITION,
            )));
        }

        let nodes = Self::nodes_in_tx(&mut tx, run_id).await?;
        let edges = Self::edges_in_tx(&mut tx, run_id).await?;
        let outcome = cancel_cascade(&nodes, &edges, node_id, actor).map_err(domain)?;
        let affected = outcome.plan.affected();
        Self::apply_change_set(&mut tx, workspace_id, run_id, &outcome.change_set).await?;
        tx.commit().await.ctx("workflow cancel: commit")?;
        Ok(affected)
    }

    /// `ResolveAmbiguous` — journals the operator's `attempt_decision`
    /// on an `attempt_ambiguous` node and applies the decision:
    /// `rerun` returns the node to `ready` via `node_ready`, `resume`
    /// leaves it parked for the harness-native resume. The decision is
    /// one-row-ever per parked attempt (`attempt_decisions`' primary
    /// key, spec-5's key table): a replay of the recorded decision and
    /// fingerprint dedupes to `command_deduped`; a differing decision
    /// or fingerprint is `DENIED` and the recorded row stands.
    async fn resolve_ambiguous(
        &self,
        node_id: WorkflowNodeId,
        decision: &str,
        fingerprint: [u8; 32],
        actor: &str,
    ) -> Result<(), Failure> {
        if !ambiguous_decision_known(decision) {
            return Err(domain(wf::Failure::new(
                wf::FailureClass::Invalid,
                REASON_UNKNOWN_DECISION,
            )));
        }
        let mut tx = begin_tx(&self.pool).await?;
        let (run_id, workspace_id) = Self::node_scope(&mut tx, node_id).await?;
        Self::lock_run(&mut tx, run_id).await?;
        let node = Self::lock_node(&mut tx, node_id).await?;
        let change_set = plan_resolution(&node, decision, actor).map_err(domain)?;

        // The decision binds the parked attempt the ambiguity parked —
        // the latest ambiguous attempt on the node.
        let attempt = sqlx::query_scalar!(
            "SELECT id FROM central.session_attempts \
             WHERE node_id = $1 AND state = 'ambiguous' \
             ORDER BY attempt_seq DESC LIMIT 1",
            uuid_of(node_id.as_bytes()),
        )
        .fetch_optional(&mut *tx)
        .await
        .ctx("workflow resolve: resolve parked attempt")?
        .ok_or_else(|| {
            domain(wf::Failure::new(
                wf::FailureClass::Invalid,
                REASON_AMBIGUOUS_ATTEMPT_MISSING,
            ))
        })?;
        let attempt_id = SessionAttemptId::from_trusted_db_bytes(*attempt.as_bytes());

        // attempt_decisions is one-row-ever per parked attempt
        // (spec-5): replay of the recorded decision journals
        // command_deduped and succeeds; a differing decision or
        // fingerprint refuses DENIED.
        let scope = DecisionScope {
            workspace_id,
            run_id,
            node_id,
            attempt_id,
        };
        if self
            .replay_decision_if_recorded(&mut tx, &scope, decision, &fingerprint, actor)
            .await?
        {
            tx.commit().await.ctx("workflow resolve: commit replay")?;
            return Ok(());
        }
        let tag = sqlx::query!(
            "INSERT INTO central.attempt_decisions \
                (attempt_id, run_id, node_id, decision, payload_fingerprint, decided_by) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (attempt_id) DO NOTHING",
            uuid_of(attempt_id.as_bytes()),
            uuid_of(run_id.as_bytes()),
            uuid_of(node_id.as_bytes()),
            decision,
            fingerprint.as_slice(),
            actor,
        )
        .execute(&mut *tx)
        .await
        .ctx("workflow resolve: record decision")?;
        if tag.rows_affected() == 0 {
            // A writer outside the run-lock discipline recorded the row
            // between probe and insert; the re-read applies the same
            // replay-vs-conflict verdict.
            if self
                .replay_decision_if_recorded(&mut tx, &scope, decision, &fingerprint, actor)
                .await?
            {
                tx.commit().await.ctx("workflow resolve: commit replay")?;
                return Ok(());
            }
            return Err(corrupt("decision row conflicted without a recorded row"));
        }

        Self::apply_change_set(&mut tx, workspace_id, run_id, &change_set).await?;
        tx.commit().await.ctx("workflow resolve: commit")?;
        Ok(())
    }

    /// `Node` — one node by id; `INVALID`/`WORKFLOW_NODE_NOT_FOUND`
    /// when absent.
    async fn node(&self, id: WorkflowNodeId) -> Result<Node, Failure> {
        let row = sqlx::query_as!(
            NodeRow,
            "SELECT id, run_id, workspace_id, node_key, parent_node_id, \
                    harness, workspace_kind, depth, state, \
                    budget_wall_clock_seconds, budget_cost_micro_usd, \
                    max_attempts, attempt_count, not_before, input_artifact_refs, spec, \
                    spec_fingerprint, node_timeout_seconds, ready_at, created_at \
             FROM central.workflow_nodes WHERE id = $1",
            uuid_of(id.as_bytes()),
        )
        .fetch_optional(&self.pool)
        .await
        .ctx("workflow: read node")?
        .ok_or_else(|| {
            domain(wf::Failure::new(
                wf::FailureClass::Invalid,
                REASON_NODE_NOT_FOUND,
            ))
        })?;
        row.decode()
    }

    /// `NodesForRun` — every committed node of a run, ordered by
    /// `(created_at, id)`.
    async fn nodes_for_run(&self, run_id: RunId) -> Result<Vec<Node>, Failure> {
        let rows = sqlx::query_as!(
            NodeRow,
            "SELECT id, run_id, workspace_id, node_key, parent_node_id, \
                    harness, workspace_kind, depth, state, \
                    budget_wall_clock_seconds, budget_cost_micro_usd, \
                    max_attempts, attempt_count, not_before, input_artifact_refs, spec, \
                    spec_fingerprint, node_timeout_seconds, ready_at, created_at \
             FROM central.workflow_nodes WHERE run_id = $1 \
             ORDER BY created_at, id",
            uuid_of(run_id.as_bytes()),
        )
        .fetch_all(&self.pool)
        .await
        .ctx("workflow: read run nodes")?;
        rows.into_iter().map(NodeRow::decode).collect()
    }

    /// `EdgesForRun` — every committed edge of a run, ordered by
    /// `(created_at, id)`.
    async fn edges_for_run(&self, run_id: RunId) -> Result<Vec<Edge>, Failure> {
        let rows = sqlx::query_as!(
            EdgeRow,
            "SELECT id, run_id, dependent_node_id, prerequisite_node_id, kind, \
                    artifact_id, created_at \
             FROM central.workflow_edges WHERE run_id = $1 \
             ORDER BY created_at, id",
            uuid_of(run_id.as_bytes()),
        )
        .fetch_all(&self.pool)
        .await
        .ctx("workflow: read run edges")?;
        rows.into_iter().map(EdgeRow::decode).collect()
    }
}

/// The run/node/attempt scope a parked-attempt decision binds — the
/// four coordinates `attempt_decisions` and its journal rows key on.
struct DecisionScope {
    workspace_id: WorkspaceId,
    run_id: RunId,
    node_id: WorkflowNodeId,
    attempt_id: SessionAttemptId,
}

impl Store {
    /// `replayDecisionIfRecordedTx` — inspects the `attempt_decisions`
    /// row bound to the parked attempt. Three verdicts: no row reports
    /// `false` so the caller inserts; a row matching the retried
    /// decision AND payload fingerprint journals `command_deduped` and
    /// reports `true` (the caller commits and returns success); any
    /// differing value raises the `DENIED` failure and the recorded
    /// row stands.
    async fn replay_decision_if_recorded(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        scope: &DecisionScope,
        decision: &str,
        fingerprint: &[u8; 32],
        actor: &str,
    ) -> Result<bool, Failure> {
        let recorded = sqlx::query!(
            "SELECT decision, payload_fingerprint FROM central.attempt_decisions \
             WHERE attempt_id = $1",
            uuid_of(scope.attempt_id.as_bytes()),
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("workflow resolve: read recorded decision")?;
        let Some(recorded) = recorded else {
            return Ok(false);
        };
        if recorded.decision == decision && recorded.payload_fingerprint == fingerprint {
            let intent = GraphEventIntent::decision_deduped(
                scope.node_id,
                scope.attempt_id,
                decision,
                actor,
            );
            append_tx(tx, &intent_event(scope.workspace_id, scope.run_id, &intent)).await?;
            return Ok(true);
        }
        if recorded.decision != decision {
            return Err(domain(wf::Failure::new(
                wf::FailureClass::Denied,
                REASON_ATTEMPT_DECISION_CONFLICT,
            )));
        }
        Err(domain(wf::Failure::new(
            wf::FailureClass::Denied,
            REASON_DUPLICATE_IDEMPOTENCY_KEY,
        )))
    }
}

impl WorkflowGraphRead for Store {
    /// The bounded `(created_at, id)` keyset page of run nodes plus the
    /// in-edges attached to them — every edge lands on exactly the page
    /// carrying its dependent; a `prerequisite_node_id` may point
    /// outside the page.
    async fn graph_page(&self, request: &GraphPageRequest) -> Result<GraphPage, Failure> {
        validate_graph_page_request(request)?;
        let page_size = normalize_graph_page_size(request.page_size);
        let cursor_created = request.cursor.map(|cursor| cursor.created_at);
        let cursor_id = request
            .cursor
            .map(|cursor| uuid_of(cursor.node_id.as_bytes()));

        let rows = sqlx::query_as!(
            NodeRow,
            "SELECT id, run_id, workspace_id, node_key, parent_node_id, \
                    harness, workspace_kind, depth, state, \
                    budget_wall_clock_seconds, budget_cost_micro_usd, \
                    max_attempts, attempt_count, not_before, input_artifact_refs, spec, \
                    spec_fingerprint, node_timeout_seconds, ready_at, created_at \
             FROM central.workflow_nodes \
             WHERE run_id = $1 \
               AND ($2::timestamptz IS NULL OR (created_at, id) > ($2, $3::uuid)) \
             ORDER BY created_at, id \
             LIMIT $4",
            uuid_of(request.run_id.as_bytes()),
            cursor_created,
            cursor_id,
            i64::from(page_size),
        )
        .fetch_all(&self.pool)
        .await
        .ctx("workflow graph page: nodes")?;
        let nodes: Vec<Node> = rows
            .into_iter()
            .map(NodeRow::decode)
            .collect::<Result<_, _>>()?;

        let page_node_ids: Vec<uuid::Uuid> = nodes
            .iter()
            .map(|node| uuid_of(node.id.as_bytes()))
            .collect();
        let edges = if page_node_ids.is_empty() {
            Vec::new()
        } else {
            sqlx::query_as!(
                EdgeRow,
                "SELECT id, run_id, dependent_node_id, prerequisite_node_id, kind, \
                        artifact_id, created_at \
                 FROM central.workflow_edges \
                 WHERE run_id = $1 AND dependent_node_id = ANY($2) \
                 ORDER BY created_at, id",
                uuid_of(request.run_id.as_bytes()),
                page_node_ids.as_slice(),
            )
            .fetch_all(&self.pool)
            .await
            .ctx("workflow graph page: edges")?
            .into_iter()
            .map(EdgeRow::decode)
            .collect::<Result<Vec<_>, _>>()?
        };

        let next_cursor = (nodes.len() == usize::try_from(page_size).unwrap_or(usize::MAX))
            .then(|| nodes.last())
            .flatten()
            .map(|boundary| NodeSeekCursor {
                created_at: boundary.created_at,
                node_id: boundary.id,
            });
        Ok(GraphPage {
            nodes,
            edges,
            next_cursor,
        })
    }
}
