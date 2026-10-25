//! The PostgreSQL adapter for the operator-UI read projections
//! (upstream `internal/adapter/postgres/runview/store.go`). It is
//! strictly read-only: plain SELECTs over the materialized Phase-2
//! tables plus the `run_events` journal — no locks, no writes, no
//! journaled side effects.
//!
//! Two deliberate shape notes carried from upstream:
//!
//! - `outbox_health` delegates to the eventjournal adapter's
//!   `unpublished_backlog` over the same pool (spec-5's stall probe), so
//!   the fleet page reads exactly what the publisher's detector sees.
//! - `checkpoints_for_run` reads `resume_checkpoints` JOINed to
//!   `workflow_nodes` directly rather than delegating to the checkpoint
//!   store's `list_checkpoints`: the projection needs the anchor's
//!   `node_key`, which the checkpoint row model does not carry, and one
//!   join beats a list-then-lookup.
//!
//! `events_for_run` returns the canonical [`RunEvent`] envelope
//! verbatim — it feeds both the node timeline and
//! `central_eventjournal::fold`/`compare_fold`.
//!
//! Compile-time-checked SQL only (`sqlx::query_as!` literals): the three
//! shared projections (`list_runs`/`run_for_id`,
//! `node_for_id`/`graph_for_run`, `attempts_for_*`) repeat their column
//! text verbatim per call site — the hard constraint forbids dynamic
//! SQL, so the shared text lives as duplicated literals, each verified.

use std::collections::BTreeMap;

use central_eventjournal::app::publisher::DrainStore;
use central_eventjournal::domain::RunEvent;
use central_foundation::failure::Failure;
use central_foundation::identity::{
    ArtifactId, NodeLeaseId, ResumeCheckpointId, RunEventId, RunId, SessionAttemptId, TaskId,
    WorkerId, WorkflowNodeId, WorkspaceId,
};
use central_runview::domain::{
    self, AttemptRow, CheckpointRow, DeferredRow, GraphEdge, GraphNode, LeaseRow, OutboxHealth,
    RunCursor, RunGraph, RunSummary, Versions, WorkerRow,
};
use central_runview::port::Reader;
use sqlx::PgPool;

use crate::error::SqlxContext;
use crate::store_support::uuid_of;

/// The read-projection store against one pool. `journal` shares the
/// pool so `outbox_health` reads the same store the publisher uses
/// (upstream `runview.Store.journal`).
pub struct Store {
    pool: PgPool,
    journal: crate::eventjournal::Store,
}

impl Store {
    /// `NewStore` — builds the runview reader over `pool`.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            journal: crate::eventjournal::Store::new(pool.clone()),
            pool,
        }
    }
}

/// The `RUNVIEW_NOT_FOUND` scoped-lookup answer — absent and
/// cross-workspace rows collapse to the same `not_found` failure, the
/// non-disclosure upstream's `runview.ErrNotFound` encodes.
fn not_found(what: &'static str) -> Failure {
    Failure::not_found(domain::RUNVIEW_NOT_FOUND, what)
}

/// `decodeSpecVersions` — extracts the degraded provenance record the
/// write side may have embedded in the node's spec JSONB: the scalar
/// members of a `"versions"` object land in `spec_extras` (numbers and
/// booleans render decimally/verbatim; nested values are skipped), and
/// a `"prompt_ref"` object inside versions or at top level contributes
/// its artifact id (`"artifact_id"`, tolerating `"id"` — the same
/// leniency the fold's `collectRefs` applies). Absent or malformed
/// members are skipped, never fabricated.
fn decode_spec_versions(spec: &serde_json::Value, versions: &mut Versions) {
    let Some(obj) = spec.as_object() else { return };
    if let Some(versions_obj) = obj.get("versions").and_then(|v| v.as_object()) {
        for (key, raw) in versions_obj {
            if key == "prompt_ref" {
                versions.prompt_ref_artifact_id = prompt_ref_artifact_id(raw);
                continue;
            }
            if let Some(text) = scalar_json(raw) {
                versions.spec_extras.insert(key.clone(), text);
            }
        }
    }
    if versions.prompt_ref_artifact_id.is_none()
        && let Some(raw) = obj.get("prompt_ref")
    {
        versions.prompt_ref_artifact_id = prompt_ref_artifact_id(raw);
    }
}

/// `scalarJSON` — renders a JSON scalar as text; compound values report
/// `None` and are skipped. Numbers render like Go's
/// `strconv.FormatFloat(f, 'f', -1, 64)`: integral values carry no
/// decimal point, fractional values the shortest exact decimal.
fn scalar_json(raw: &serde_json::Value) -> Option<String> {
    match raw {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// `promptRefArtifactID` — resolves the artifact id a prompt_ref pair
/// names (`"artifact_id"`, tolerating `"id"`). A non-object or
/// unparseable value contributes `None`.
fn prompt_ref_artifact_id(raw: &serde_json::Value) -> Option<ArtifactId> {
    let obj = raw.as_object()?;
    let text = obj
        .get("artifact_id")
        .or_else(|| obj.get("id"))
        .and_then(|v| v.as_str())?;
    ArtifactId::parse(text).ok()
}

// ---------------------------------------------------------------------------
// Row projections — `query_as!` maps onto named structs so the two run
// queries and the two attempt queries each share one domain conversion.
// ---------------------------------------------------------------------------

/// The `list_runs`/`run_for_id` select shape (the LATERAL joins folded
/// into plain columns).
struct RunSummaryRow {
    id: uuid::Uuid,
    task_id: uuid::Uuid,
    workspace_id: uuid::Uuid,
    run_index: i64,
    status: String,
    run_key: Option<String>,
    created_at: time::OffsetDateTime,
    updated_at: time::OffsetDateTime,
    deadline: Option<time::OffsetDateTime>,
    started_at: Option<time::OffsetDateTime>,
    ended_at: Option<time::OffsetDateTime>,
    counts: serde_json::Value,
}

impl RunSummaryRow {
    /// One row → the [`RunSummary`] domain projection. The `counts`
    /// jsonb decodes into the state map; a malformed aggregate is an
    /// internal failure, not a hidden zero.
    fn into_summary(self) -> Result<RunSummary, Failure> {
        let node_counts: BTreeMap<String, i64> =
            serde_json::from_value(self.counts).map_err(|_| {
                Failure::internal(
                    crate::store_support::PG_DATA_CORRUPT,
                    "runview: decode node counts",
                )
            })?;
        Ok(RunSummary {
            id: RunId::from_trusted_db_bytes(*self.id.as_bytes()),
            task_id: TaskId::from_trusted_db_bytes(*self.task_id.as_bytes()),
            workspace_id: WorkspaceId::from_trusted_db_bytes(*self.workspace_id.as_bytes()),
            index: self.run_index,
            status: self.status,
            run_key: self.run_key,
            created_at: self.created_at,
            updated_at: self.updated_at,
            started_at: self.started_at,
            ended_at: self.ended_at,
            deadline: self.deadline,
            node_counts,
        })
    }
}

/// The `node_for_id`/`graph_for_run` node select shape.
struct GraphNodeRow {
    id: uuid::Uuid,
    run_id: uuid::Uuid,
    node_key: String,
    state: String,
    attempt_count: i32,
    max_attempts: i32,
    not_before: Option<time::OffsetDateTime>,
    created_at: time::OffsetDateTime,
    parent_key: Option<String>,
    reason: String,
}

impl GraphNodeRow {
    /// One row → the [`GraphNode`] domain projection.
    fn into_node(self) -> GraphNode {
        GraphNode {
            id: WorkflowNodeId::from_trusted_db_bytes(*self.id.as_bytes()),
            run_id: RunId::from_trusted_db_bytes(*self.run_id.as_bytes()),
            key: self.node_key,
            status: self.state,
            reason: self.reason,
            attempt_count: self.attempt_count,
            max_attempts: self.max_attempts,
            not_before: self.not_before,
            parent_key: self.parent_key,
            created_at: self.created_at,
        }
    }
}

/// The `attempts_for_*` select shape — the ledger row joined to its
/// node's key and spec plus the harness attempt's version pair.
struct AttemptRowRaw {
    id: uuid::Uuid,
    node_id: uuid::Uuid,
    node_key: String,
    attempt_seq: i32,
    state: String,
    dispatch_reason_code: Option<String>,
    worker_id: Option<uuid::Uuid>,
    claimed_at: time::OffsetDateTime,
    started_at: Option<time::OffsetDateTime>,
    ended_at: Option<time::OffsetDateTime>,
    adapter_version: Option<String>,
    harness_version: Option<String>,
    spec: serde_json::Value,
}

impl AttemptRowRaw {
    /// One row → the [`AttemptRow`] domain projection, with the
    /// degraded [`Versions`] record decoded from the spec JSONB.
    fn into_attempt(self) -> AttemptRow {
        let mut versions = Versions {
            adapter_version: self.adapter_version,
            harness_version: self.harness_version,
            ..Versions::default()
        };
        decode_spec_versions(&self.spec, &mut versions);
        AttemptRow {
            id: SessionAttemptId::from_trusted_db_bytes(*self.id.as_bytes()),
            node_id: WorkflowNodeId::from_trusted_db_bytes(*self.node_id.as_bytes()),
            node_key: self.node_key,
            seq: self.attempt_seq,
            state: self.state,
            reason_code: self.dispatch_reason_code,
            worker_id: self
                .worker_id
                .map(|id| WorkerId::from_trusted_db_bytes(*id.as_bytes())),
            claimed_at: self.claimed_at,
            started_at: self.started_at,
            ended_at: self.ended_at,
            versions,
        }
    }
}

impl Reader for Store {
    /// `ListRuns` — pages the workspace's runs newest-first under the
    /// `(created_at, id)` keyset cursor — the same ordering
    /// `runs_workspace_created_id_idx` covers. Each row carries a
    /// LATERAL node-state count aggregation (`jsonb_object_agg` over
    /// `GROUP BY state`) and the journal-derived begin/end marks:
    /// `central.runs` records no lifecycle timestamps, so the first and
    /// last `run_events.recorded_at` of the run are the observable
    /// started/ended evidence. `node_counts` is empty (never `None`)
    /// for a run with no workflow nodes.
    async fn list_runs(
        &self,
        workspace_id: WorkspaceId,
        after: Option<RunCursor>,
        limit: i64,
    ) -> Result<Vec<RunSummary>, Failure> {
        if limit <= 0 {
            return Ok(Vec::new());
        }
        let rows = sqlx::query_as!(
            RunSummaryRow,
            "SELECT r.id, r.task_id, r.workspace_id, r.run_index, \
                    r.status, r.run_key, r.created_at, r.updated_at, r.deadline, \
                    ev.started_at, ev.ended_at, \
                    COALESCE(nc.counts, '{}'::jsonb) AS \"counts!\" \
             FROM central.runs r \
             LEFT JOIN LATERAL ( \
                 SELECT MIN(e.recorded_at) AS started_at, MAX(e.recorded_at) AS ended_at \
                   FROM central.run_events e \
                  WHERE e.run_id = r.id \
             ) ev ON true \
             LEFT JOIN LATERAL ( \
                 SELECT jsonb_object_agg(state, cnt) AS counts \
                   FROM ( \
                       SELECT n.state, COUNT(*) AS cnt \
                         FROM central.workflow_nodes n \
                        WHERE n.run_id = r.id \
                        GROUP BY n.state \
                   ) counted \
             ) nc ON true \
             WHERE r.workspace_id = $1 \
               AND ($2::timestamptz IS NULL OR (r.created_at, r.id) < ($2::timestamptz, $3::uuid)) \
             ORDER BY r.created_at DESC, r.id DESC \
             LIMIT $4",
            uuid_of(workspace_id.as_bytes()),
            after.map(|c| c.created_at),
            after.map(|c| uuid_of(c.id.as_bytes())),
            limit,
        )
        .fetch_all(&self.pool)
        .await
        .ctx("runview list runs")?;

        rows.into_iter().map(RunSummaryRow::into_summary).collect()
    }

    /// `RunForID` — the `list_runs` projection scoped to one run.
    /// `RUNVIEW_NOT_FOUND` covers absent and cross-workspace rows
    /// alike — the WHERE clause never distinguishes them.
    async fn run_for_id(
        &self,
        workspace_id: WorkspaceId,
        run_id: RunId,
    ) -> Result<RunSummary, Failure> {
        let row = sqlx::query_as!(
            RunSummaryRow,
            "SELECT r.id, r.task_id, r.workspace_id, r.run_index, \
                    r.status, r.run_key, r.created_at, r.updated_at, r.deadline, \
                    ev.started_at, ev.ended_at, \
                    COALESCE(nc.counts, '{}'::jsonb) AS \"counts!\" \
             FROM central.runs r \
             LEFT JOIN LATERAL ( \
                 SELECT MIN(e.recorded_at) AS started_at, MAX(e.recorded_at) AS ended_at \
                   FROM central.run_events e \
                  WHERE e.run_id = r.id \
             ) ev ON true \
             LEFT JOIN LATERAL ( \
                 SELECT jsonb_object_agg(state, cnt) AS counts \
                   FROM ( \
                       SELECT n.state, COUNT(*) AS cnt \
                         FROM central.workflow_nodes n \
                        WHERE n.run_id = r.id \
                        GROUP BY n.state \
                   ) counted \
             ) nc ON true \
             WHERE r.workspace_id = $1 AND r.id = $2",
            uuid_of(workspace_id.as_bytes()),
            uuid_of(run_id.as_bytes()),
        )
        .fetch_optional(&self.pool)
        .await
        .ctx("runview run for id")?
        .ok_or_else(|| not_found("runview: run not found"))?;
        row.into_summary()
    }

    /// `NodeForID` — the graph-node projection scoped to one node, on
    /// the same most-recent-reason lateral join the DAG view uses.
    async fn node_for_id(
        &self,
        workspace_id: WorkspaceId,
        node_id: WorkflowNodeId,
    ) -> Result<GraphNode, Failure> {
        let row = sqlx::query_as!(
            GraphNodeRow,
            "SELECT n.id, n.run_id, n.node_key, n.state, \
                    n.attempt_count, n.max_attempts, n.not_before, n.created_at, \
                    p.node_key AS \"parent_key?\", COALESCE(r.reason_code, '') AS \"reason!\" \
             FROM central.workflow_nodes n \
             LEFT JOIN central.workflow_nodes p ON p.id = n.parent_node_id \
             LEFT JOIN LATERAL ( \
                 SELECT e.reason_code \
                   FROM central.run_events e \
                  WHERE e.run_id = n.run_id AND e.node_id = n.id AND e.reason_code IS NOT NULL \
                  ORDER BY e.seq DESC \
                  LIMIT 1 \
             ) r ON true \
             WHERE n.workspace_id = $1 AND n.id = $2",
            uuid_of(workspace_id.as_bytes()),
            uuid_of(node_id.as_bytes()),
        )
        .fetch_optional(&self.pool)
        .await
        .ctx("runview node for id")?
        .ok_or_else(|| not_found("runview: node not found"))?;
        Ok(row.into_node())
    }

    /// `GraphForRun` — the materialized DAG of one run: nodes ordered
    /// `(depth, created_at, node_key)` (the fold's reconstruction
    /// order), edges projected in node keys (`from_key` the
    /// prerequisite, `to_key` the dependent).
    async fn graph_for_run(&self, run_id: RunId) -> Result<RunGraph, Failure> {
        let node_rows = sqlx::query_as!(
            GraphNodeRow,
            "SELECT n.id, n.run_id, n.node_key, n.state, \
                    n.attempt_count, n.max_attempts, n.not_before, n.created_at, \
                    p.node_key AS \"parent_key?\", COALESCE(r.reason_code, '') AS \"reason!\" \
             FROM central.workflow_nodes n \
             LEFT JOIN central.workflow_nodes p ON p.id = n.parent_node_id \
             LEFT JOIN LATERAL ( \
                 SELECT e.reason_code \
                   FROM central.run_events e \
                  WHERE e.run_id = n.run_id AND e.node_id = n.id AND e.reason_code IS NOT NULL \
                  ORDER BY e.seq DESC \
                  LIMIT 1 \
             ) r ON true \
             WHERE n.run_id = $1 \
             ORDER BY n.depth, n.created_at, n.node_key",
            uuid_of(run_id.as_bytes()),
        )
        .fetch_all(&self.pool)
        .await
        .ctx("runview graph nodes")?;

        let edge_rows = sqlx::query!(
            "SELECT prereq.node_key AS from_key, dep.node_key AS to_key, \
                    e.kind, e.artifact_id \
             FROM central.workflow_edges e \
             JOIN central.workflow_nodes dep ON dep.id = e.dependent_node_id \
             JOIN central.workflow_nodes prereq ON prereq.id = e.prerequisite_node_id \
             WHERE e.run_id = $1 \
             ORDER BY dep.node_key, prereq.node_key, e.kind",
            uuid_of(run_id.as_bytes()),
        )
        .fetch_all(&self.pool)
        .await
        .ctx("runview graph edges")?;

        Ok(RunGraph {
            nodes: node_rows.into_iter().map(GraphNodeRow::into_node).collect(),
            edges: edge_rows
                .into_iter()
                .map(|row| GraphEdge {
                    from_key: row.from_key,
                    to_key: row.to_key,
                    kind: row.kind,
                    artifact_id: row
                        .artifact_id
                        .map(|id| ArtifactId::from_trusted_db_bytes(*id.as_bytes())),
                })
                .collect(),
        })
    }

    /// `EventsForRun` — the run's journaled events in `seq` order as
    /// the canonical [`RunEvent`] envelope.
    async fn events_for_run(&self, run_id: RunId) -> Result<Vec<RunEvent>, Failure> {
        let rows = sqlx::query!(
            "SELECT id, workspace_id, run_id, seq, node_id, attempt_id, kind, \
                    actor, reason_code, payload, recorded_at \
             FROM central.run_events \
             WHERE run_id = $1 \
             ORDER BY seq",
            uuid_of(run_id.as_bytes()),
        )
        .fetch_all(&self.pool)
        .await
        .ctx("runview events")?;

        rows.into_iter()
            .map(|row| {
                Ok(RunEvent {
                    id: RunEventId::from_trusted_db_bytes(*row.id.as_bytes()),
                    workspace_id: WorkspaceId::from_trusted_db_bytes(*row.workspace_id.as_bytes()),
                    run_id: RunId::from_trusted_db_bytes(*row.run_id.as_bytes()),
                    seq: row.seq,
                    node_id: row
                        .node_id
                        .map(|id| WorkflowNodeId::from_trusted_db_bytes(*id.as_bytes())),
                    attempt_id: row
                        .attempt_id
                        .map(|id| SessionAttemptId::from_trusted_db_bytes(*id.as_bytes())),
                    kind: row.kind,
                    actor: row.actor,
                    reason_code: row.reason_code,
                    payload: row.payload,
                    recorded_at: row.recorded_at,
                })
            })
            .collect()
    }

    /// `AttemptsForNode` — the node's session-attempt ledger ordered by
    /// `attempt_seq`. The shared attempt projection joins the ledger
    /// row to its node's key and spec plus the harness attempt's
    /// version pair — the versions envelope degrades exactly as the
    /// plan's note declares: `session_attempts` carries no
    /// spec_version/adapter/model/digest columns, so the
    /// `harness_attempts` LEFT JOIN and the spec JSONB are the only
    /// provenance sources.
    async fn attempts_for_node(&self, node_id: WorkflowNodeId) -> Result<Vec<AttemptRow>, Failure> {
        let rows = sqlx::query_as!(
            AttemptRowRaw,
            "SELECT a.id, a.node_id, n.node_key, a.attempt_seq, a.state, \
                    a.dispatch_reason_code, a.worker_id, \
                    a.claimed_at, a.started_at, a.ended_at, \
                    h.adapter_version AS \"adapter_version?\", h.harness_version, n.spec \
             FROM central.session_attempts a \
             JOIN central.workflow_nodes n ON n.id = a.node_id \
             LEFT JOIN central.harness_attempts h ON h.id = a.harness_attempt_id \
             WHERE a.node_id = $1 \
             ORDER BY a.attempt_seq",
            uuid_of(node_id.as_bytes()),
        )
        .fetch_all(&self.pool)
        .await
        .ctx("runview attempts for node")?;
        Ok(rows.into_iter().map(AttemptRowRaw::into_attempt).collect())
    }

    /// `AttemptsForRun` — every session attempt of the run ordered by
    /// `(node_key, attempt_seq)` — the run view's attempt table.
    async fn attempts_for_run(&self, run_id: RunId) -> Result<Vec<AttemptRow>, Failure> {
        let rows = sqlx::query_as!(
            AttemptRowRaw,
            "SELECT a.id, a.node_id, n.node_key, a.attempt_seq, a.state, \
                    a.dispatch_reason_code, a.worker_id, \
                    a.claimed_at, a.started_at, a.ended_at, \
                    h.adapter_version AS \"adapter_version?\", h.harness_version, n.spec \
             FROM central.session_attempts a \
             JOIN central.workflow_nodes n ON n.id = a.node_id \
             LEFT JOIN central.harness_attempts h ON h.id = a.harness_attempt_id \
             WHERE a.run_id = $1 \
             ORDER BY n.node_key, a.attempt_seq",
            uuid_of(run_id.as_bytes()),
        )
        .fetch_all(&self.pool)
        .await
        .ctx("runview attempts for run")?;
        Ok(rows.into_iter().map(AttemptRowRaw::into_attempt).collect())
    }

    /// `NodesCurrent` — the materialized `{node_key: state}` map of one
    /// run, the `compare_fold` input.
    async fn nodes_current(&self, run_id: RunId) -> Result<BTreeMap<String, String>, Failure> {
        let rows = sqlx::query!(
            "SELECT node_key, state FROM central.workflow_nodes WHERE run_id = $1",
            uuid_of(run_id.as_bytes()),
        )
        .fetch_all(&self.pool)
        .await
        .ctx("runview nodes current")?;
        Ok(rows.into_iter().map(|r| (r.node_key, r.state)).collect())
    }

    /// `Workers` — the workspace's registered workers with the
    /// server-side last-beat age the suspect/lost banner thresholds
    /// evaluate, ordered by registration time.
    async fn workers(&self, workspace_id: WorkspaceId) -> Result<Vec<WorkerRow>, Failure> {
        let rows = sqlx::query!(
            "SELECT id, workspace_id, protocol_version, harness_kinds, workspace_kinds, \
                    max_concurrent_attempts, state, registered_at, last_seen_at, \
                    (EXTRACT(EPOCH FROM (now() - last_seen_at)))::bigint AS beat_age_seconds, \
                    deregistered_at \
             FROM central.worker_registrations \
             WHERE workspace_id = $1 \
             ORDER BY registered_at, id",
            uuid_of(workspace_id.as_bytes()),
        )
        .fetch_all(&self.pool)
        .await
        .ctx("runview workers")?;

        Ok(rows
            .into_iter()
            .map(|row| WorkerRow {
                id: WorkerId::from_trusted_db_bytes(*row.id.as_bytes()),
                workspace_id: WorkspaceId::from_trusted_db_bytes(*row.workspace_id.as_bytes()),
                protocol_version: row.protocol_version,
                harness_kinds: row.harness_kinds,
                workspace_kinds: row.workspace_kinds,
                max_concurrent_attempts: row.max_concurrent_attempts,
                state: row.state,
                registered_at: row.registered_at,
                last_seen_at: row.last_seen_at,
                beat_age_seconds: row.beat_age_seconds,
                deregistered_at: row.deregistered_at,
            })
            .collect())
    }

    /// `LiveLeases` — the workspace's live leases (`released_at IS
    /// NULL` — the partial unique index's live predicate) joined to
    /// their node key and attempt coordinates, ordered by issue time.
    async fn live_leases(&self, workspace_id: WorkspaceId) -> Result<Vec<LeaseRow>, Failure> {
        let rows = sqlx::query!(
            "SELECT l.id, a.run_id, l.node_id, n.node_key, \
                    l.attempt_id, a.attempt_seq, l.worker_id, \
                    l.issued_at, l.last_heartbeat_at, \
                    (EXTRACT(EPOCH FROM (now() - l.last_heartbeat_at)))::bigint AS \"heartbeat_age_seconds!\", \
                    l.expires_at, l.heartbeat_interval_seconds \
             FROM central.node_leases l \
             JOIN central.session_attempts a ON a.id = l.attempt_id \
             JOIN central.workflow_nodes n ON n.id = l.node_id \
             WHERE a.workspace_id = $1 AND l.released_at IS NULL \
             ORDER BY l.issued_at, l.id",
            uuid_of(workspace_id.as_bytes()),
        )
        .fetch_all(&self.pool)
        .await
        .ctx("runview live leases")?;

        Ok(rows
            .into_iter()
            .map(|row| LeaseRow {
                id: NodeLeaseId::from_trusted_db_bytes(*row.id.as_bytes()),
                run_id: RunId::from_trusted_db_bytes(*row.run_id.as_bytes()),
                node_id: WorkflowNodeId::from_trusted_db_bytes(*row.node_id.as_bytes()),
                node_key: row.node_key,
                attempt_id: SessionAttemptId::from_trusted_db_bytes(*row.attempt_id.as_bytes()),
                attempt_seq: row.attempt_seq,
                worker_id: WorkerId::from_trusted_db_bytes(*row.worker_id.as_bytes()),
                issued_at: row.issued_at,
                last_heartbeat_at: row.last_heartbeat_at,
                heartbeat_age_seconds: row.heartbeat_age_seconds,
                expires_at: row.expires_at,
                heartbeat_interval_sec: row.heartbeat_interval_seconds,
            })
            .collect())
    }

    /// `DeferredAdmissions` — the run's journaled `admission_deferred`
    /// events (`CAPACITY_ADMISSION_DEFERRED` lives in `reason_code`) in
    /// the claim FIFO order itself — `COALESCE(ready_at, created_at)`
    /// then `node_key`; deferral never rewrites `ready_at`, so no
    /// stored queue position exists.
    async fn deferred_admissions(&self, run_id: RunId) -> Result<Vec<DeferredRow>, Failure> {
        let rows = sqlx::query!(
            "SELECT e.id, e.run_id, e.seq, e.node_id, n.node_key, \
                    e.reason_code, n.ready_at, e.recorded_at \
             FROM central.run_events e \
             JOIN central.workflow_nodes n ON n.id = e.node_id \
             WHERE e.run_id = $1 AND e.kind = 'admission_deferred' \
             ORDER BY COALESCE(n.ready_at, n.created_at), n.node_key",
            uuid_of(run_id.as_bytes()),
        )
        .fetch_all(&self.pool)
        .await
        .ctx("runview deferred admissions")?;

        rows.into_iter()
            .map(|row| {
                let Some(node_id) = row.node_id else {
                    return Err(Failure::internal(
                        crate::store_support::PG_DATA_CORRUPT,
                        "runview deferred admissions: admission_deferred row carries no node id",
                    ));
                };
                Ok(DeferredRow {
                    event_id: RunEventId::from_trusted_db_bytes(*row.id.as_bytes()),
                    run_id: RunId::from_trusted_db_bytes(*row.run_id.as_bytes()),
                    seq: row.seq,
                    node_id: WorkflowNodeId::from_trusted_db_bytes(*node_id.as_bytes()),
                    node_key: row.node_key,
                    reason_code: row.reason_code,
                    ready_at: row.ready_at,
                    recorded_at: row.recorded_at,
                })
            })
            .collect()
    }

    /// `CheckpointsForRun` — the run's resume checkpoints newest first,
    /// each projected with its anchor's `node_key`.
    async fn checkpoints_for_run(&self, run_id: RunId) -> Result<Vec<CheckpointRow>, Failure> {
        let rows = sqlx::query!(
            "SELECT c.checkpoint_id, c.checkpoint_seq, c.gc_class, n.node_key, c.created_at \
             FROM central.resume_checkpoints c \
             JOIN central.workflow_nodes n ON n.id = c.node_id \
             WHERE c.run_id = $1 \
             ORDER BY c.created_at DESC, c.checkpoint_id DESC",
            uuid_of(run_id.as_bytes()),
        )
        .fetch_all(&self.pool)
        .await
        .ctx("runview checkpoints")?;

        Ok(rows
            .into_iter()
            .map(|row| CheckpointRow {
                id: ResumeCheckpointId::from_trusted_db_bytes(*row.checkpoint_id.as_bytes()),
                seq: row.checkpoint_seq,
                gc_class: row.gc_class,
                anchor_node_key: row.node_key,
                created_at: row.created_at,
            })
            .collect())
    }

    /// `RunScope` — the workspace one run belongs to; `Ok(None)` when
    /// no run carries the id.
    async fn run_scope(&self, run_id: RunId) -> Result<Option<WorkspaceId>, Failure> {
        let row = sqlx::query!(
            "SELECT workspace_id FROM central.runs WHERE id = $1",
            uuid_of(run_id.as_bytes()),
        )
        .fetch_optional(&self.pool)
        .await
        .ctx("runview run scope")?;
        Ok(row.map(|r| WorkspaceId::from_trusted_db_bytes(*r.workspace_id.as_bytes())))
    }

    /// `OutboxHealth` — delegates to the eventjournal adapter's
    /// `unpublished_backlog` over the same pool, the same probe the
    /// publisher's stall detector reads.
    async fn outbox_health(&self) -> Result<OutboxHealth, Failure> {
        let backlog = self.journal.unpublished_backlog().await?;
        Ok(OutboxHealth {
            unpublished_depth: i64::try_from(backlog.depth).unwrap_or(i64::MAX),
            oldest_unpublished: backlog.oldest,
        })
    }
}
