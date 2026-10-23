//! PostgreSQL store for `central-checkpoint`: [`CheckpointStore`]
//! (immutable `central.checkpoints` append + ordered loads),
//! [`RunCheckpointRead`] (the bounded newest-first recovery page),
//! and [`ResumeCheckpointStore`] (the b36/b37 subtree-anchored
//! `central.resume_checkpoints` port: idempotent insert, load, GC
//! selection, delete).
//!
//! Immutability (adapter-mapping §5): `central.checkpoints` is
//! INSERT/SELECT only — no update path exists here or anywhere.
//!
//! Dedupe discipline (spec-5 OQ-2, upstream checkpoint `Store`):
//! `insert_deduplicated` probes the `(attempt_id, checkpoint_seq)`
//! unique coordinate inside one transaction; an identical
//! `payload_fingerprint` returns the recorded row, a different one
//! conflicts with `DUPLICATE_IDEMPOTENCY_KEY`, and the row constraint
//! still backs writers that race outside the probe.
//!
//! Persisted/in-memory split (domain `Checkpoint` doc): the columns
//! written below are the complete durable legs —
//! `policy_fingerprint`, `agent_revision_fingerprint`, and
//! `source_checkpoint_id` have no columns and are deliberately not
//! persisted; a reloaded record reports them as empty/`None`.

use std::sync::Arc;

use central_checkpoint::domain::{
    Checkpoint, CheckpointKind, CheckpointPayload, GcClass, MAX_CHECKPOINT_PAYLOAD_BYTES,
    ResumeCheckpoint, boundary_legal, codes, decode_resume_token, gc_pick,
    resume_format_compatible,
};
use central_checkpoint::port::{
    CheckpointStore, CollectOutcome, CollectStore, Digester, ResumeCheckpointStore, ResumeStore,
};
use central_checkpoint::query::{
    MAX_CHECKPOINT_PAGE, RunCheckpointPage, RunCheckpointRead, RunCheckpointRequest,
};
use central_eventjournal::domain::{EventKind, RunEvent};
use central_eventjournal::port::Writer;
use central_foundation::failure::Failure;
use central_foundation::identity::{
    ArtifactId, CheckpointId, ResumeCheckpointId, RunEventId, RunId, SessionAttemptId,
    StepAttemptId, StepId, TaskId, WorkflowNodeId, WorkspaceId,
};
use central_workflow::domain::NodeStatus as WorkflowNodeStatus;
use sqlx::{PgPool, Postgres, Transaction};
use time::OffsetDateTime;

use crate::error::{SqlxContext, classify_sqlx};
use crate::eventjournal::append_tx;
use crate::store_support::{
    PG_DATA_CORRUPT, begin_tx, i64_as_u64, u64_as_i64, usize_as_i64, uuid_of,
};

/// Conflict code for a duplicate `central.checkpoints` identity.
const CHECKPOINT_ALREADY_EXISTS: &str = "checkpoint_already_exists";

/// PostgreSQL-backed checkpoint store. The workspace digester is
/// injected at construction (upstream `NewStore(conn, digester)`) so
/// the adapter never imports a workspace-digest implementation — a
/// store without one fails only when an anchor attempt actually opened
/// a workspace.
#[derive(Clone)]
pub struct Store {
    pool: PgPool,
    digester: Option<Arc<dyn Digester>>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("pool", &self.pool)
            .field("digester", &self.digester.is_some())
            .finish()
    }
}

impl Store {
    /// Binds the store to a `central_runtime`-authorized pool with no
    /// digester — digest-bound writes/preflights fail closed only when
    /// an anchor attempt actually opened a workspace (upstream's nil-
    /// digester rule).
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            digester: None,
        }
    }

    /// Binds the store with the workspace digester injected (upstream
    /// `NewStore(conn, digester)`).
    #[must_use]
    pub fn with_digester(pool: PgPool, digester: Arc<dyn Digester>) -> Self {
        Self {
            pool,
            digester: Some(digester),
        }
    }
}

fn corrupt(what: &'static str) -> Failure {
    Failure::internal(PG_DATA_CORRUPT, what)
}

// ---------------------------------------------------------------------------
// central.checkpoints (Phase-1 immutable record)
// ---------------------------------------------------------------------------

struct CheckpointRow {
    id: uuid::Uuid,
    workspace_id: uuid::Uuid,
    run_id: uuid::Uuid,
    step_id: Option<uuid::Uuid>,
    version: i64,
    checkpoint_kind: Option<String>,
    metadata: Option<serde_json::Value>,
    created_at: OffsetDateTime,
    task_id: uuid::Uuid,
    step_attempt_id: Option<uuid::Uuid>,
    producer_id: String,
    producer_version: String,
    schema_version: i64,
    checksum: Vec<u8>,
    payload: Vec<u8>,
    resume_compatible: bool,
    validated: bool,
    policy_version: i64,
    recorded_at: OffsetDateTime,
    eligible_after: OffsetDateTime,
    legal_hold: bool,
}

impl TryFrom<CheckpointRow> for Checkpoint {
    type Error = Failure;

    fn try_from(row: CheckpointRow) -> Result<Self, Self::Error> {
        let kind = row
            .checkpoint_kind
            .ok_or_else(|| corrupt("a stored checkpoint carries no kind"))?;
        let checksum: [u8; 32] = row
            .checksum
            .as_slice()
            .try_into()
            .map_err(|_| corrupt("a stored checkpoint checksum is not 32 bytes"))?;
        Ok(Self {
            id: CheckpointId::from_trusted_db_bytes(row.id.into_bytes()),
            workspace_id: WorkspaceId::from_trusted_db_bytes(row.workspace_id.into_bytes()),
            task_id: TaskId::from_trusted_db_bytes(row.task_id.into_bytes()),
            run_id: RunId::from_trusted_db_bytes(row.run_id.into_bytes()),
            step_id: row
                .step_id
                .map(|u| StepId::from_trusted_db_bytes(u.into_bytes())),
            step_attempt_id: row
                .step_attempt_id
                .map(|u| StepAttemptId::from_trusted_db_bytes(u.into_bytes())),
            version: i64_as_u64(row.version, "version")?,
            kind: CheckpointKind::parse(&kind)
                .map_err(|_| corrupt("a stored checkpoint kind is malformed"))?,
            producer_id: row.producer_id,
            producer_version: row.producer_version,
            schema_version: i64_as_u64(row.schema_version, "schema_version")?,
            policy_version: i64_as_u64(row.policy_version, "policy_version")?,
            // In-memory-only legs: central.checkpoints persists no
            // columns for them (see the struct-level persistence note).
            policy_fingerprint: String::new(),
            agent_revision_fingerprint: String::new(),
            payload: CheckpointPayload::from_canonical(&row.payload, MAX_CHECKPOINT_PAYLOAD_BYTES)
                .map_err(|_| corrupt("a stored checkpoint payload fails re-validation"))?,
            checksum,
            metadata: row.metadata,
            recorded_at: row.recorded_at,
            created_at: row.created_at,
            resume_compatible: row.resume_compatible,
            validated: row.validated,
            eligible_after: row.eligible_after,
            legal_hold: row.legal_hold,
            source_checkpoint_id: None,
        })
    }
}

impl CheckpointStore for Store {
    async fn append_checkpoint(&self, checkpoint: Checkpoint) -> Result<(), Failure> {
        let schema_version = u64_as_i64(checkpoint.schema_version, codes::CHECKPOINT_INVALID)?;
        let policy_version = u64_as_i64(checkpoint.policy_version, codes::CHECKPOINT_INVALID)?;
        sqlx::query!(
            "INSERT INTO central.checkpoints \
             (id, workspace_id, task_id, run_id, step_id, step_attempt_id, \
              producer_id, producer_version, schema_version, checkpoint_kind, \
              checksum, payload, resume_compatible, validated, policy_version, \
              recorded_at, eligible_after, legal_hold, created_at, metadata, \
              version) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, \
                     $14, $15, clock_timestamp(), $16, $17, \
                     clock_timestamp(), $18, $19)",
            uuid_of(checkpoint.id.as_bytes()),
            uuid_of(checkpoint.workspace_id.as_bytes()),
            uuid_of(checkpoint.task_id.as_bytes()),
            uuid_of(checkpoint.run_id.as_bytes()),
            checkpoint.step_id.map(|i| uuid_of(i.as_bytes())),
            checkpoint.step_attempt_id.map(|i| uuid_of(i.as_bytes())),
            checkpoint.producer_id,
            checkpoint.producer_version,
            schema_version,
            checkpoint.kind.as_str(),
            &checkpoint.checksum[..],
            checkpoint.payload.as_bytes(),
            checkpoint.resume_compatible,
            checkpoint.validated,
            policy_version,
            checkpoint.eligible_after,
            checkpoint.legal_hold,
            checkpoint.metadata,
            u64_as_i64(checkpoint.version, codes::CHECKPOINT_INVALID)?,
        )
        .execute(&self.pool)
        .await
        .map_err(|err| {
            let failure = classify_sqlx(&err);
            if failure.code() == crate::error::codes::PG_UNIQUE_VIOLATION {
                // Immutable evidence: a duplicate identity is a
                // domain-visible conflict, not a raw constraint leak.
                return Failure::conflict(
                    CHECKPOINT_ALREADY_EXISTS,
                    "a checkpoint with this identity already exists",
                );
            }
            failure
        })?;
        Ok(())
    }

    async fn load_run_checkpoints(
        &self,
        workspace_id: WorkspaceId,
        run_id: RunId,
        limit: usize,
    ) -> Result<Vec<Checkpoint>, Failure> {
        if limit == 0 || limit > MAX_CHECKPOINT_PAGE {
            return Err(Failure::invalid(
                codes::CHECKPOINT_INVALID,
                "the checkpoint page size must be within 1..=50",
            ));
        }
        let rows = sqlx::query_as!(
            CheckpointRow,
            "SELECT id, workspace_id, run_id, step_id, version, \
             checkpoint_kind, metadata, created_at, task_id, step_attempt_id, \
             producer_id, producer_version, schema_version, checksum, payload, \
             resume_compatible, validated, policy_version, recorded_at, \
             eligible_after, legal_hold \
             FROM central.checkpoints \
             WHERE workspace_id = $1 AND run_id = $2 \
             ORDER BY created_at DESC, id DESC \
             LIMIT $3",
            uuid_of(workspace_id.as_bytes()),
            uuid_of(run_id.as_bytes()),
            usize_as_i64(limit),
        )
        .fetch_all(&self.pool)
        .await
        .ctx("checkpoint: load run checkpoints")?;
        rows.into_iter().map(Checkpoint::try_from).collect()
    }

    async fn load_checkpoint(
        &self,
        workspace_id: WorkspaceId,
        checkpoint_id: CheckpointId,
    ) -> Result<Option<Checkpoint>, Failure> {
        let row = sqlx::query_as!(
            CheckpointRow,
            "SELECT id, workspace_id, run_id, step_id, version, \
             checkpoint_kind, metadata, created_at, task_id, step_attempt_id, \
             producer_id, producer_version, schema_version, checksum, payload, \
             resume_compatible, validated, policy_version, recorded_at, \
             eligible_after, legal_hold \
             FROM central.checkpoints \
             WHERE workspace_id = $1 AND id = $2",
            uuid_of(workspace_id.as_bytes()),
            uuid_of(checkpoint_id.as_bytes()),
        )
        .fetch_optional(&self.pool)
        .await
        .ctx("checkpoint: load checkpoint")?;
        row.map(Checkpoint::try_from).transpose()
    }
}

impl RunCheckpointRead for Store {
    async fn read_page(
        &self,
        request: &RunCheckpointRequest,
    ) -> Result<RunCheckpointPage, Failure> {
        let limit = request.validate()?;
        // An empty kind filter reads the whole vocabulary — `= ANY`
        // against the expanded set keeps the statement static.
        const ALL_KINDS: [&str; 5] = [
            "run_start",
            "run_complete",
            "step_boundary",
            "external_effect",
            "recovery",
        ];
        let kinds: Vec<String> = if request.kinds.is_empty() {
            ALL_KINDS.iter().map(|k| (*k).to_owned()).collect()
        } else {
            request
                .kinds
                .iter()
                .map(|k| k.as_str().to_owned())
                .collect()
        };
        let rows = sqlx::query_as!(
            CheckpointRow,
            "SELECT id, workspace_id, run_id, step_id, version, \
             checkpoint_kind, metadata, created_at, task_id, step_attempt_id, \
             producer_id, producer_version, schema_version, checksum, payload, \
             resume_compatible, validated, policy_version, recorded_at, \
             eligible_after, legal_hold \
             FROM central.checkpoints \
             WHERE workspace_id = $1 AND run_id = $2 \
               AND checkpoint_kind = ANY($3::text[]) \
               AND ($4::timestamptz IS NULL OR created_at < $4) \
             ORDER BY created_at DESC, id DESC \
             LIMIT $5",
            uuid_of(request.workspace_id.as_bytes()),
            uuid_of(request.run_id.as_bytes()),
            &kinds[..],
            request.created_before,
            usize_as_i64(limit) + 1,
        )
        .fetch_all(&self.pool)
        .await
        .ctx("checkpoint: read run checkpoint page")?;

        let has_more = rows.len() > limit;
        let mut checkpoints = Vec::with_capacity(limit.min(rows.len()));
        for row in rows.into_iter().take(limit) {
            checkpoints.push(Checkpoint::try_from(row)?);
        }
        // `next_boundary` exists only when a further page exists —
        // `None` when the page is empty or the read is exhausted.
        let next_boundary = if has_more {
            checkpoints.last().map(|c| c.created_at)
        } else {
            None
        };
        Ok(RunCheckpointPage {
            checkpoints,
            next_boundary,
        })
    }
}

// ---------------------------------------------------------------------------
// central.resume_checkpoints (b36/b37 subtree-anchored records)
// ---------------------------------------------------------------------------

struct ResumeCheckpointRow {
    checkpoint_id: uuid::Uuid,
    workspace_id: uuid::Uuid,
    run_id: uuid::Uuid,
    node_id: uuid::Uuid,
    attempt_id: uuid::Uuid,
    format_version: String,
    graph_schema_version: String,
    event_watermark: i64,
    harness_session_id: Option<String>,
    workspace_digest: Option<String>,
    workspace_path: Option<String>,
    completed_nodes: Vec<String>,
    finalized_artifacts: Vec<uuid::Uuid>,
    in_flight_nodes: Vec<String>,
    gc_class: String,
    created_at: OffsetDateTime,
    expires_at: Option<OffsetDateTime>,
    content_digest: String,
    checkpoint_seq: i64,
}

impl TryFrom<ResumeCheckpointRow> for ResumeCheckpoint {
    type Error = Failure;

    fn try_from(row: ResumeCheckpointRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: ResumeCheckpointId::from_trusted_db_bytes(row.checkpoint_id.into_bytes()),
            workspace_id: WorkspaceId::from_trusted_db_bytes(row.workspace_id.into_bytes()),
            run_id: RunId::from_trusted_db_bytes(row.run_id.into_bytes()),
            node_id: WorkflowNodeId::from_trusted_db_bytes(row.node_id.into_bytes()),
            attempt_id: SessionAttemptId::from_trusted_db_bytes(row.attempt_id.into_bytes()),
            checkpoint_seq: row.checkpoint_seq,
            format_version: row.format_version,
            graph_schema_version: row.graph_schema_version,
            event_watermark: row.event_watermark,
            harness_session_id: row.harness_session_id,
            workspace_digest: row.workspace_digest,
            workspace_path: row.workspace_path,
            completed_nodes: row.completed_nodes,
            finalized_artifacts: row
                .finalized_artifacts
                .into_iter()
                .map(|u| ArtifactId::from_trusted_db_bytes(u.into_bytes()))
                .collect(),
            in_flight_nodes: row.in_flight_nodes,
            gc_class: GcClass::parse(&row.gc_class)
                .map_err(|_| corrupt("a stored gc class is malformed"))?,
            created_at: row.created_at,
            expires_at: row.expires_at,
            content_digest: row.content_digest,
        })
    }
}

async fn load_by_coordinate(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    attempt_id: uuid::Uuid,
    checkpoint_seq: i64,
) -> Result<ResumeCheckpoint, Failure> {
    let row = sqlx::query_as!(
        ResumeCheckpointRow,
        "SELECT checkpoint_id, workspace_id, run_id, node_id, \
         attempt_id, format_version, graph_schema_version, event_watermark, \
         harness_session_id, workspace_digest, workspace_path, completed_nodes, \
         finalized_artifacts, in_flight_nodes, gc_class, created_at, expires_at, \
         content_digest, checkpoint_seq \
         FROM central.resume_checkpoints \
         WHERE attempt_id = $1 AND checkpoint_seq = $2",
        attempt_id,
        checkpoint_seq,
    )
    .fetch_one(&mut **tx)
    .await
    .ctx("checkpoint: reload deduplicated row")?;
    ResumeCheckpoint::try_from(row)
}

impl ResumeCheckpointStore for Store {
    async fn insert_deduplicated(
        &self,
        checkpoint: ResumeCheckpoint,
    ) -> Result<ResumeCheckpoint, Failure> {
        // The persisted digest must be the digest recomputable from the
        // record's legs — a caller that supplies anything else is a
        // write-path defect, caught before the row exists.
        let content_digest = checkpoint.digest();
        if checkpoint.content_digest != content_digest {
            return Err(Failure::invalid(
                codes::CHECKPOINT_INVALID,
                "the supplied content digest does not match the record",
            ));
        }
        let fingerprint = checkpoint.fingerprint();
        let attempt_id = uuid_of(checkpoint.attempt_id.as_bytes());

        let mut tx = begin_tx(&self.pool).await?;
        let stored: Option<Vec<u8>> = sqlx::query_scalar!(
            "SELECT payload_fingerprint FROM central.resume_checkpoints \
             WHERE attempt_id = $1 AND checkpoint_seq = $2",
            attempt_id,
            checkpoint.checkpoint_seq,
        )
        .fetch_optional(&mut *tx)
        .await
        .ctx("checkpoint: probe idempotency coordinate")?
        .flatten();

        match stored {
            Some(stored) if stored == fingerprint => {
                // Identical retry — return the recorded row.
                let row =
                    load_by_coordinate(&mut tx, attempt_id, checkpoint.checkpoint_seq).await?;
                tx.commit().await.ctx("checkpoint: commit dedupe reload")?;
                Ok(row)
            }
            Some(_) => Err(Failure::conflict(
                codes::DUPLICATE_IDEMPOTENCY,
                "the checkpoint_seq already carries a different payload fingerprint",
            )),
            None => {
                let artifact_ids: Vec<uuid::Uuid> = checkpoint
                    .finalized_artifacts
                    .iter()
                    .map(|i| uuid_of(i.as_bytes()))
                    .collect();
                let created_at = sqlx::query_scalar!(
                    "INSERT INTO central.resume_checkpoints \
                     (checkpoint_id, workspace_id, run_id, node_id, attempt_id, \
                      checkpoint_seq, format_version, graph_schema_version, \
                      event_watermark, harness_session_id, workspace_digest, \
                      workspace_path, completed_nodes, finalized_artifacts, \
                      in_flight_nodes, gc_class, expires_at, content_digest, \
                      payload_fingerprint) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, \
                             $12, $13::text[], $14::uuid[], $15::text[], $16, \
                             $17, $18, $19) \
                     RETURNING created_at",
                    uuid_of(checkpoint.id.as_bytes()),
                    uuid_of(checkpoint.workspace_id.as_bytes()),
                    uuid_of(checkpoint.run_id.as_bytes()),
                    uuid_of(checkpoint.node_id.as_bytes()),
                    attempt_id,
                    checkpoint.checkpoint_seq,
                    checkpoint.format_version.as_str(),
                    checkpoint.graph_schema_version.as_str(),
                    checkpoint.event_watermark,
                    checkpoint.harness_session_id.as_deref(),
                    checkpoint.workspace_digest.as_deref(),
                    checkpoint.workspace_path.as_deref(),
                    &checkpoint.completed_nodes[..],
                    &artifact_ids[..],
                    &checkpoint.in_flight_nodes[..],
                    checkpoint.gc_class.as_str(),
                    checkpoint.expires_at,
                    content_digest,
                    &fingerprint[..],
                )
                .fetch_one(&mut *tx)
                .await
                .map_err(|err| {
                    let failure = classify_sqlx(&err);
                    if failure.code() == crate::error::codes::PG_UNIQUE_VIOLATION {
                        // A writer outside the probe won the key race —
                        // the coordinate stands and this write conflicts.
                        return Failure::conflict(
                            codes::DUPLICATE_IDEMPOTENCY,
                            "the checkpoint_seq is already recorded for the anchor attempt",
                        );
                    }
                    failure
                })?;
                tx.commit()
                    .await
                    .ctx("checkpoint: commit insert deduplicated")?;
                Ok(ResumeCheckpoint {
                    created_at,
                    ..checkpoint
                })
            }
        }
    }

    async fn load_resume_checkpoint(
        &self,
        workspace_id: WorkspaceId,
        checkpoint_id: ResumeCheckpointId,
    ) -> Result<Option<ResumeCheckpoint>, Failure> {
        let row = sqlx::query_as!(
            ResumeCheckpointRow,
            "SELECT checkpoint_id, workspace_id, run_id, node_id, \
             attempt_id, format_version, graph_schema_version, event_watermark, \
             harness_session_id, workspace_digest, workspace_path, completed_nodes, \
             finalized_artifacts, in_flight_nodes, gc_class, created_at, expires_at, \
             content_digest, checkpoint_seq \
             FROM central.resume_checkpoints \
             WHERE workspace_id = $1 AND checkpoint_id = $2",
            uuid_of(workspace_id.as_bytes()),
            uuid_of(checkpoint_id.as_bytes()),
        )
        .fetch_optional(&self.pool)
        .await
        .ctx("checkpoint: load resume checkpoint")?;
        row.map(ResumeCheckpoint::try_from).transpose()
    }

    async fn list_gc_candidates(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<ResumeCheckpoint>, Failure> {
        let rows = sqlx::query_as!(
            ResumeCheckpointRow,
            "SELECT checkpoint_id, workspace_id, run_id, node_id, \
             attempt_id, format_version, graph_schema_version, event_watermark, \
             harness_session_id, workspace_digest, workspace_path, completed_nodes, \
             finalized_artifacts, in_flight_nodes, gc_class, created_at, expires_at, \
             content_digest, checkpoint_seq \
             FROM central.resume_checkpoints \
             WHERE workspace_id = $1 \
             ORDER BY run_id, node_id, created_at, checkpoint_id",
            uuid_of(workspace_id.as_bytes()),
        )
        .fetch_all(&self.pool)
        .await
        .ctx("checkpoint: list gc candidates")?;
        rows.into_iter().map(ResumeCheckpoint::try_from).collect()
    }

    async fn delete_checkpoints(
        &self,
        workspace_id: WorkspaceId,
        ids: &[ResumeCheckpointId],
    ) -> Result<usize, Failure> {
        if ids.is_empty() {
            return Ok(0);
        }
        let uuids: Vec<uuid::Uuid> = ids.iter().map(|i| uuid_of(i.as_bytes())).collect();
        let result = sqlx::query!(
            "DELETE FROM central.resume_checkpoints \
             WHERE workspace_id = $1 AND checkpoint_id = ANY($2::uuid[])",
            uuid_of(workspace_id.as_bytes()),
            &uuids[..],
        )
        .execute(&self.pool)
        .await
        .ctx("checkpoint: delete gc selections")?;
        Ok(usize::try_from(result.rows_affected()).unwrap_or(usize::MAX))
    }
}

// ---------------------------------------------------------------------------
// Phase-2C orchestration — the port of upstream
// internal/adapter/postgres/checkpoint/store.go: quiescent-boundary
// writes, token resolution + all-or-nothing preflight, the subtree
// resume transaction, retention-class GC, and the operator surface.
//
// Lock order inside a transaction is run-row THEN node-row THEN
// attempt-row — the invariant workflow/store.rs documents and
// `append_tx` relies on (the journal append itself takes the run-row
// lock first). Every mutating method commits its state change and its
// canonical run_events rows in ONE transaction; a refused checkpoint
// still commits its checkpoint_refused row alone (the refuseTx pattern)
// so the refusal is durable and actionable, and every preflight
// violation journals resume_failed while leaving run state untouched.
//
// The subtree an anchor covers is the anchor node plus every descendant
// through workflow_nodes.parent_node_id (spec locked input 3: children
// spawn children; a root anchor captures the whole run).
//
// The workspace digest is computed BEFORE the write transaction opens —
// filesystem work must not run under the run-row lock, and a quiescent
// workspace is stable (spec D2) — then bound inside it: if the
// in-transaction anchor attempt is not the row the digest was computed
// for, the write refuses rather than record a stale digest.
// ---------------------------------------------------------------------------

/// The default journaled actor for operator-invoked checkpoint/resume
/// calls that pass none (upstream `actorOperator`).
const ACTOR_OPERATOR: &str = "operator";

/// The journaled actor for retention deletions — the scheduled janitor
/// and the manual `central checkpoint gc` verb run the same pass, so
/// the event names the mechanism, not the invoker (upstream `actorGC`).
const ACTOR_GC: &str = "checkpoint-gc";

/// Adapter-level failure reason — a lost row, a failed query (upstream
/// `reasonStoreError`). NOT a spec-3 reason code and never journaled:
/// the six spec codes describe domain verdicts, not infrastructure
/// outcomes.
const REASON_STORE_ERROR: &str = "CHECKPOINT_STORE_ERROR";
/// The artifacts lifecycle states that mean "mid-finalization" for the
/// boundary probe (B10's pre-ready leg: reserved → staging → verifying
/// → ready). `ready` is the finalized vocabulary; rejected,
/// delete_pending, deleted and quarantined are terminal or post-final.
const MID_FINALIZATION_ARTIFACT_STATES: [&str; 3] = ["reserved", "staging", "verifying"];
/// b35's `session_attempts_live_node_idx` set restated for SQL —
/// [`AttemptState::is_live`] in array form.
const LIVE_ATTEMPT_STATES: [&str; 3] = ["claimed", "provisioning", "started"];

/// `recorded_at` stays NULL → `now()` inside the journal insert (the
/// eventjournal adapter's own sentinel convention).
const NO_RECORDED_AT: OffsetDateTime = OffsetDateTime::UNIX_EPOCH;

fn store_failure(detail: impl Into<String>) -> Failure {
    Failure::invalid(REASON_STORE_ERROR, detail.into())
}

/// The run-scoped identity envelope every journaled checkpoint event
/// carries — the `(workspace, run, node, attempt)` provenance. Bundling
/// it keeps `journal_event`/`refuse_tx` inside the argument-count
/// budget and makes the shared scope explicit at call sites.
#[derive(Clone, Copy)]
struct JournalCtx {
    workspace_id: WorkspaceId,
    run_id: RunId,
    node_id: Option<WorkflowNodeId>,
    attempt_id: Option<SessionAttemptId>,
}

impl JournalCtx {
    /// A run-scoped context (no node/attempt leg).
    const fn new(workspace_id: WorkspaceId, run_id: RunId) -> Self {
        Self {
            workspace_id,
            run_id,
            node_id: None,
            attempt_id: None,
        }
    }

    /// Binds the node leg (checkpoint/node-scoped events).
    const fn node(mut self, node_id: WorkflowNodeId) -> Self {
        self.node_id = Some(node_id);
        self
    }

    /// Binds the attempt leg (attempt-scoped events).
    const fn attempt(mut self, attempt_id: SessionAttemptId) -> Self {
        self.attempt_id = Some(attempt_id);
        self
    }
}

fn journal_event(
    ctx: &JournalCtx,
    kind: EventKind,
    actor: &str,
    reason_code: Option<String>,
    payload: serde_json::Value,
) -> RunEvent {
    RunEvent {
        id: RunEventId::new(),
        workspace_id: ctx.workspace_id,
        run_id: ctx.run_id,
        seq: 0,
        node_id: ctx.node_id,
        attempt_id: ctx.attempt_id,
        kind: kind.as_str().to_owned(),
        actor: actor.to_owned(),
        reason_code,
        payload,
        recorded_at: NO_RECORDED_AT,
    }
}

// ---------------------------------------------------------------------------
// Anchor attempt resolution
// ---------------------------------------------------------------------------

/// The anchor node's latest session attempt — the row whose harness
/// session and workspace the checkpoint record carries (spec D1).
/// `workspace_path`/`workspace_kind` drive the workspace digest; a NULL
/// `workspace_path` means the attempt never opened a workspace and the
/// digest stays NULL (spec D2).
struct AnchorAttempt {
    id: uuid::Uuid,
    state: String,
    workspace_path: Option<String>,
    workspace_kind: String,
    harness_session_id: Option<String>,
}

async fn latest_attempt(pool: &PgPool, node_id: uuid::Uuid) -> Result<AnchorAttempt, Failure> {
    sqlx::query_as!(
        AnchorAttempt,
        "SELECT id, state, workspace_path, workspace_kind, harness_session_id \
         FROM central.session_attempts WHERE node_id = $1 \
         ORDER BY attempt_seq DESC LIMIT 1",
        node_id,
    )
    .fetch_optional(pool)
    .await
    .ctx("checkpoint: resolve anchor attempt")?
    .ok_or_else(|| {
        Failure::invalid(
            "CHECKPOINT_ANCHOR_MISSING",
            "the anchor node has no session attempt to carry",
        )
    })
}

async fn latest_attempt_tx(
    tx: &mut Transaction<'_, Postgres>,
    node_id: uuid::Uuid,
) -> Result<AnchorAttempt, Failure> {
    sqlx::query_as!(
        AnchorAttempt,
        "SELECT id, state, workspace_path, workspace_kind, harness_session_id \
         FROM central.session_attempts WHERE node_id = $1 \
         ORDER BY attempt_seq DESC LIMIT 1 FOR UPDATE",
        node_id,
    )
    .fetch_optional(&mut **tx)
    .await
    .ctx("checkpoint: lock anchor attempt")?
    .ok_or_else(|| {
        Failure::invalid(
            "CHECKPOINT_ANCHOR_MISSING",
            "the anchor node has no session attempt to carry",
        )
    })
}

// ---------------------------------------------------------------------------
// WriteCheckpoint — the quiescent-boundary write path (P2C02, spec D2)
// ---------------------------------------------------------------------------

impl Store {
    /// Journals `checkpoint_refused` inside the caller's transaction
    /// (upstream `refuseTx`); the commit that follows carries the event
    /// only.
    async fn refuse_tx(
        tx: &mut Transaction<'_, Postgres>,
        ctx: JournalCtx,
        node_key: &str,
        actor: &str,
        refusal: &Failure,
    ) -> Result<(), Failure> {
        let event = journal_event(
            &ctx,
            EventKind::CheckpointRefused,
            actor,
            Some(refusal.code().to_owned()),
            serde_json::json!({
                "node_key": node_key,
                "detail": refusal.message(),
            }),
        );
        append_tx(tx, &event).await.map(|_| ())
    }

    /// The node_keys of the subtree's `succeeded` nodes, key-sorted for
    /// a deterministic record (upstream `subtreeNodeKeysTx`).
    async fn subtree_completed_keys_tx(
        tx: &mut Transaction<'_, Postgres>,
        node_id: uuid::Uuid,
    ) -> Result<Vec<String>, Failure> {
        sqlx::query_scalar!(
            "WITH RECURSIVE subtree AS (\
                SELECT id FROM central.workflow_nodes WHERE id = $1::uuid \
                UNION ALL \
                SELECT n.id FROM central.workflow_nodes n JOIN subtree s ON n.parent_node_id = s.id \
             ) \
             SELECT n.node_key FROM central.workflow_nodes n \
             WHERE n.id IN (SELECT id FROM subtree) AND n.state = 'succeeded' \
             ORDER BY n.node_key",
            node_id,
        )
        .fetch_all(&mut **tx)
        .await
        .ctx("checkpoint: list subtree completed nodes")
    }

    /// The checkpoint's `finalized_artifacts` leg (upstream
    /// `subtreeReadSetTx`): the union of `artifact` kind in-edges and
    /// `input_artifact_refs` declared by the subtree's UNFINISHED nodes
    /// (succeeded/cancelled need no readable set), filtered to
    /// artifacts currently `ready` — spec D1 lineage read-set
    /// semantics. Ordering edges carry `artifact_id` NULL and
    /// contribute nothing.
    async fn subtree_read_set_tx(
        tx: &mut Transaction<'_, Postgres>,
        node_id: uuid::Uuid,
    ) -> Result<Vec<uuid::Uuid>, Failure> {
        sqlx::query_scalar!(
            "WITH RECURSIVE subtree AS (\
                SELECT id FROM central.workflow_nodes WHERE id = $1::uuid \
                UNION ALL \
                SELECT n.id FROM central.workflow_nodes n JOIN subtree s ON n.parent_node_id = s.id \
             ) \
             SELECT ref FROM (\
                SELECT e.artifact_id AS ref \
                  FROM central.workflow_edges e \
                  JOIN central.workflow_nodes d ON d.id = e.dependent_node_id \
                 WHERE e.kind = 'artifact' \
                   AND d.id IN (SELECT id FROM subtree) \
                   AND d.state NOT IN ('succeeded', 'cancelled')\
                UNION \
                SELECT (r->>'artifact_id')::uuid \
                  FROM central.workflow_nodes n \
                  CROSS JOIN LATERAL jsonb_array_elements(n.input_artifact_refs) r \
                 WHERE n.id IN (SELECT id FROM subtree) \
                   AND n.state NOT IN ('succeeded', 'cancelled')\
             ) refs \
             WHERE ref IN (SELECT id FROM central.artifacts WHERE state = 'ready') \
             ORDER BY 1",
            node_id,
        )
        .fetch_all(&mut **tx)
        .await
        .ctx("checkpoint: compute subtree read set")?
        .into_iter()
        .map(|id| id.ok_or_else(|| corrupt("a subtree read-set artifact id is NULL")))
        .collect()
    }

    /// The node_keys of subtree nodes whose latest attempt is live —
    /// the b35 live set (upstream `subtreeInFlightTx`). They record per
    /// spec D2 and resume treats them as ambiguous.
    async fn subtree_in_flight_tx(
        tx: &mut Transaction<'_, Postgres>,
        node_id: uuid::Uuid,
    ) -> Result<Vec<String>, Failure> {
        sqlx::query_scalar!(
            "WITH RECURSIVE subtree AS (\
                SELECT id FROM central.workflow_nodes WHERE id = $1::uuid \
                UNION ALL \
                SELECT n.id FROM central.workflow_nodes n JOIN subtree s ON n.parent_node_id = s.id \
             ) \
             SELECT n.node_key FROM central.workflow_nodes n \
             WHERE n.id IN (SELECT id FROM subtree) \
               AND EXISTS (\
                SELECT 1 FROM central.session_attempts a \
                WHERE a.node_id = n.id AND a.state = ANY($2::text[])) \
             ORDER BY n.node_key",
            node_id,
            &LIVE_ATTEMPT_STATES[..] as &[&str],
        )
        .fetch_all(&mut **tx)
        .await
        .ctx("checkpoint: list in-flight subtree nodes")
    }
}

// ---------------------------------------------------------------------------
// Preflight / resume internals shared by `resolve_token`,
// `resume_preflight` and `resume_subtree`
// ---------------------------------------------------------------------------

impl Store {
    /// The one-row read every checkpoint path shares (upstream
    /// `loadCheckpoint`); `None` when the id names no row.
    async fn load_row(
        &self,
        checkpoint_id: ResumeCheckpointId,
    ) -> Result<Option<ResumeCheckpoint>, Failure> {
        let row = sqlx::query_as!(
            ResumeCheckpointRow,
            "SELECT checkpoint_id, workspace_id, run_id, node_id, \
             attempt_id, format_version, graph_schema_version, event_watermark, \
             harness_session_id, workspace_digest, workspace_path, completed_nodes, \
             finalized_artifacts, in_flight_nodes, gc_class, created_at, expires_at, \
             content_digest, checkpoint_seq \
             FROM central.resume_checkpoints \
             WHERE checkpoint_id = $1",
            uuid_of(checkpoint_id.as_bytes()),
        )
        .fetch_optional(&self.pool)
        .await
        .ctx("checkpoint: load resume checkpoint row")?;
        row.map(ResumeCheckpoint::try_from).transpose()
    }

    /// Journals `resume_failed` for one spec violation and returns the
    /// Failure the caller propagates (upstream `failPreflight`). The
    /// journal rides its own transaction (`Writer::append` takes the
    /// run lock itself); a journal error never rescues the verdict —
    /// it folds into the message.
    async fn fail_preflight(
        &self,
        checkpoint: &ResumeCheckpoint,
        actor: &str,
        failure: Failure,
        extra: serde_json::Map<String, serde_json::Value>,
    ) -> Failure {
        let mut payload = serde_json::json!({
            "checkpoint_id": checkpoint.id.to_string(),
            "detail": failure.message(),
        });
        if let (serde_json::Value::Object(map), extra) = (&mut payload, extra) {
            map.extend(extra);
        }
        let event = journal_event(
            &JournalCtx::new(checkpoint.workspace_id, checkpoint.run_id).node(checkpoint.node_id),
            EventKind::ResumeFailed,
            actor,
            Some(failure.code().to_owned()),
            payload,
        );
        let journal = crate::eventjournal::Store::new(self.pool.clone());
        if let Err(err) = journal.append(event).await {
            return Failure::new(
                failure.kind(),
                failure.code(),
                format!(
                    "{} (journal resume_failed: {})",
                    failure.message(),
                    err.message()
                ),
            );
        }
        failure
    }

    /// The spec-D3 check ladder shared by `resume_preflight` and
    /// `resume_subtree` (upstream `preflight`). Every spec violation
    /// journals `resume_failed` and leaves run state untouched; checks
    /// that resolve no row cannot journal — a run-scoped envelope
    /// needs a `run_id`.
    async fn preflight(&self, token: &str, actor: &str) -> Result<ResumeCheckpoint, Failure> {
        let stale = |detail: &'static str| Failure::denied(codes::RESUME_TOKEN_STALE, detail);

        let decoded = decode_resume_token(token)?;
        let checkpoint = match self.load_row(decoded.checkpoint_id).await? {
            Some(checkpoint) => checkpoint,
            None => {
                return Err(stale("no live checkpoint exists for the token id"));
            }
        };
        if checkpoint
            .expires_at
            .is_some_and(|expires| expires <= OffsetDateTime::now_utc())
        {
            let failure = stale("the checkpoint has expired");
            return Err(self
                .fail_preflight(&checkpoint, actor, failure, Default::default())
                .await);
        }
        if !checkpoint.token_matches(&decoded.digest_prefix) {
            let failure = stale("the token digest does not match the recorded content");
            return Err(self
                .fail_preflight(&checkpoint, actor, failure, Default::default())
                .await);
        }

        // Check 2: this build must read the record's format and
        // graph-schema versions.
        if let Err(failure) =
            resume_format_compatible(&checkpoint.format_version, &checkpoint.graph_schema_version)
        {
            return Err(self
                .fail_preflight(&checkpoint, actor, failure, Default::default())
                .await);
        }

        // Check 3: the recorded workspace path must still digest to the
        // recorded digest. A NULL recorded digest means the anchor
        // attempt never opened a workspace and there is nothing to
        // re-verify.
        if let Some(recorded) = &checkpoint.workspace_digest {
            let mismatch =
                |detail: String| Failure::denied(codes::WORKSPACE_DIGEST_MISMATCH, detail);
            let Some(path) = &checkpoint.workspace_path else {
                let failure =
                    mismatch("recorded a workspace digest without a workspace path".to_owned());
                return Err(self
                    .fail_preflight(&checkpoint, actor, failure, Default::default())
                    .await);
            };
            let Some(digester) = &self.digester else {
                return Err(store_failure(
                    "workspace digest verification needs a digester",
                ));
            };
            let workspace_kind: String = sqlx::query_scalar!(
                "SELECT workspace_kind FROM central.session_attempts WHERE id = $1",
                uuid_of(checkpoint.attempt_id.as_bytes()),
            )
            .fetch_one(&self.pool)
            .await
            .ctx("checkpoint: load anchor attempt workspace kind")?;
            let current = match digester.digest(path, &workspace_kind).await {
                Ok(current) => current,
                Err(err) => {
                    let failure = mismatch(format!(
                        "the recorded workspace path could not be re-digested: {}",
                        err.message()
                    ));
                    return Err(self
                        .fail_preflight(&checkpoint, actor, failure, Default::default())
                        .await);
                }
            };
            if &current != recorded {
                let failure =
                    mismatch("the workspace changed since the checkpoint was written".to_owned());
                return Err(self
                    .fail_preflight(&checkpoint, actor, failure, Default::default())
                    .await);
            }
        }

        // Check 4: every recorded readable artifact must still exist
        // and be finalized ('ready').
        if !checkpoint.finalized_artifacts.is_empty() {
            let artifact_ids: Vec<uuid::Uuid> = checkpoint
                .finalized_artifacts
                .iter()
                .map(|id| uuid_of(id.as_bytes()))
                .collect();
            let missing = sqlx::query_scalar!(
                "SELECT u.id FROM unnest($1::uuid[]) AS u(id) \
                 WHERE NOT EXISTS (\
                    SELECT 1 FROM central.artifacts a \
                    WHERE a.id = u.id AND a.state = 'ready') \
                 ORDER BY 1",
                &artifact_ids[..],
            )
            .fetch_all(&self.pool)
            .await
            .ctx("checkpoint: check finalized artifacts")?;
            if !missing.is_empty() {
                let mut extra = serde_json::Map::new();
                extra.insert(
                    "missing".to_owned(),
                    serde_json::json!(
                        missing
                            .iter()
                            .flatten()
                            .map(uuid::Uuid::to_string)
                            .collect::<Vec<_>>()
                    ),
                );
                let failure = Failure::denied(
                    codes::RESUME_ARTIFACT_MISSING,
                    format!(
                        "{} readable artifact(s) are missing or no longer finalized",
                        missing.len()
                    ),
                );
                return Err(self
                    .fail_preflight(&checkpoint, actor, failure, extra)
                    .await);
            }
        }

        Ok(checkpoint)
    }
}

// ---------------------------------------------------------------------------
// CollectStore + ResumeStore — the orchestration surface
// ---------------------------------------------------------------------------

impl CollectStore for Store {
    /// One garbage-collection pass over `central.resume_checkpoints`
    /// (upstream `Collect`, spec D5). Every distinct
    /// `(run_id, node_id)` anchor gets its own transaction: the
    /// anchor's rows lock `FOR UPDATE`, [`gc_pick`] selects on that
    /// locked set, and each picked row deletes + journals
    /// `checkpoint_gc_collected` in the same commit. Per-anchor
    /// transactions are deliberate — spec-3 makes partial passes
    /// harmless, so one anchor's failure never starves the rest; the
    /// next janitor tick retries the group. GC deletes checkpoint rows
    /// only — never attempts, events, or artifacts.
    async fn collect(&self, now: OffsetDateTime) -> Result<CollectOutcome, Failure> {
        let anchors = sqlx::query!(
            "SELECT DISTINCT run_id, node_id FROM central.resume_checkpoints \
             ORDER BY 1, 2"
        )
        .fetch_all(&self.pool)
        .await
        .ctx("checkpoint gc: list anchors")?;

        let mut outcome = CollectOutcome::default();
        for anchor in anchors {
            match self
                .collect_anchor(anchor.run_id, anchor.node_id, now)
                .await
            {
                Ok(collected) => outcome.collected += collected,
                Err(failure) => outcome.failures.push(Failure::new(
                    failure.kind(),
                    failure.code(),
                    format!(
                        "anchor run={} node={}: {}",
                        anchor.run_id,
                        anchor.node_id,
                        failure.message()
                    ),
                )),
            }
        }
        Ok(outcome)
    }
}

impl Store {
    /// The GC pass for one anchor inside its own transaction (upstream
    /// `collectAnchor`): lock the anchor's rows, `gc_pick` on the
    /// locked set, then delete + journal each pick atomically. The
    /// `FOR UPDATE` lock serializes against a concurrent pin/unpin — a
    /// row pinned before the lock is seen with its new class and
    /// survives.
    async fn collect_anchor(
        &self,
        run_id: uuid::Uuid,
        node_id: uuid::Uuid,
        now: OffsetDateTime,
    ) -> Result<usize, Failure> {
        let mut tx = begin_tx(&self.pool).await?;
        let rows = sqlx::query!(
            "SELECT c.checkpoint_id, c.workspace_id, c.gc_class, c.created_at, \
             c.expires_at, n.node_key \
             FROM central.resume_checkpoints c \
             JOIN central.workflow_nodes n ON n.id = c.node_id \
             WHERE c.run_id = $1 AND c.node_id = $2 \
             FOR UPDATE OF c",
            run_id,
            node_id,
        )
        .fetch_all(&mut *tx)
        .await
        .ctx("checkpoint gc: lock anchor rows")?;

        let mut candidates: Vec<ResumeCheckpoint> = Vec::with_capacity(rows.len());
        let mut node_keys: std::collections::HashMap<ResumeCheckpointId, String> =
            std::collections::HashMap::new();
        for row in rows {
            let id = ResumeCheckpointId::from_trusted_db_bytes(row.checkpoint_id.into_bytes());
            node_keys.insert(id, row.node_key);
            candidates.push(ResumeCheckpoint {
                id,
                workspace_id: WorkspaceId::from_trusted_db_bytes(row.workspace_id.into_bytes()),
                run_id: RunId::from_trusted_db_bytes(run_id.into_bytes()),
                node_id: WorkflowNodeId::from_trusted_db_bytes(node_id.into_bytes()),
                // The GC selection reads only id/workspace/run/node,
                // gc_class, created_at, expires_at — the remaining
                // legs stay at their zero values exactly as upstream's
                // partial-row candidates do.
                attempt_id: SessionAttemptId::from_trusted_db_bytes(uuid::Uuid::nil().into_bytes()),
                checkpoint_seq: 0,
                format_version: String::new(),
                graph_schema_version: String::new(),
                event_watermark: 0,
                harness_session_id: None,
                workspace_digest: None,
                workspace_path: None,
                completed_nodes: Vec::new(),
                finalized_artifacts: Vec::new(),
                in_flight_nodes: Vec::new(),
                gc_class: GcClass::parse(&row.gc_class)
                    .map_err(|_| corrupt("a stored gc class is malformed"))?,
                created_at: row.created_at,
                expires_at: row.expires_at,
                content_digest: String::new(),
            });
        }

        let picks = gc_pick(&candidates, now);
        if picks.is_empty() {
            tx.commit().await.ctx("checkpoint gc: commit empty pass")?;
            return Ok(0);
        }
        let by_id: std::collections::HashMap<ResumeCheckpointId, &ResumeCheckpoint> =
            candidates.iter().map(|c| (c.id, c)).collect();
        for id in &picks {
            let candidate = by_id[id];
            sqlx::query!(
                "DELETE FROM central.resume_checkpoints WHERE checkpoint_id = $1",
                uuid_of(id.as_bytes()),
            )
            .execute(&mut *tx)
            .await
            .ctx("checkpoint gc: delete picked checkpoint")?;
            let event = journal_event(
                &JournalCtx::new(candidate.workspace_id, candidate.run_id).node(candidate.node_id),
                EventKind::CheckpointGcCollected,
                ACTOR_GC,
                None,
                serde_json::json!({
                    "checkpoint_id": id.to_string(),
                    "node_key": node_keys[id],
                    "gc_class": candidate.gc_class.as_str(),
                }),
            );
            append_tx(&mut tx, &event).await?;
        }
        tx.commit().await.ctx("checkpoint gc: commit anchor pass")?;
        Ok(picks.len())
    }
}

impl ResumeStore for Store {
    async fn anchor_for(&self, run_id: RunId, node_key: &str) -> Result<WorkflowNodeId, Failure> {
        let anchor_missing =
            |detail: &'static str| Failure::invalid("CHECKPOINT_ANCHOR_MISSING", detail);
        let run = uuid_of(run_id.as_bytes());
        if !node_key.is_empty() {
            let id = sqlx::query_scalar!(
                "SELECT id FROM central.workflow_nodes \
                 WHERE run_id = $1 AND node_key = $2",
                run,
                node_key,
            )
            .fetch_optional(&self.pool)
            .await
            .ctx("checkpoint anchor: resolve node key")?
            .ok_or_else(|| anchor_missing("the run has no node with that key"))?;
            return Ok(WorkflowNodeId::from_trusted_db_bytes(id.into_bytes()));
        }

        let roots = sqlx::query_scalar!(
            "SELECT id FROM central.workflow_nodes \
             WHERE run_id = $1 AND depth = 0 ORDER BY id",
            run,
        )
        .fetch_all(&self.pool)
        .await
        .ctx("checkpoint anchor: list depth-0 roots")?;
        match roots.len() {
            1 => Ok(WorkflowNodeId::from_trusted_db_bytes(roots[0].into_bytes())),
            0 => {
                let run_exists = sqlx::query_scalar!(
                    "SELECT EXISTS(SELECT 1 FROM central.runs WHERE id = $1)",
                    run,
                )
                .fetch_one(&self.pool)
                .await
                .ctx("checkpoint anchor: probe run")?;
                if !run_exists.unwrap_or(false) {
                    return Err(Failure::invalid(
                        "CHECKPOINT_RUN_MISSING",
                        "the anchor run does not exist",
                    ));
                }
                Err(Failure::invalid(
                    "CHECKPOINT_ANCHOR_AMBIGUOUS",
                    "the run has no depth-0 root; pass --node",
                ))
            }
            many => Err(Failure::invalid(
                "CHECKPOINT_ANCHOR_AMBIGUOUS",
                format!("the run has {many} depth-0 roots; pass --node"),
            )),
        }
    }

    /// Writes one durable checkpoint at the `(run_id, node_id)` anchor
    /// (upstream `WriteCheckpoint`, P2C02 spec D2). `expires_at` is
    /// written NULL for every class: supersedeable collection is
    /// driven by keep-latest-N and `run_terminal` by
    /// `created_at + RUN_TERMINAL_RETENTION` inside [`gc_pick`], so
    /// neither needs a stored deadline; the column is reserved for an
    /// operator-set expiry the janitor still honors.
    async fn write_checkpoint(
        &self,
        run_id: RunId,
        node_id: WorkflowNodeId,
        actor: &str,
        gc_class: GcClass,
        checkpoint_seq: i64,
    ) -> Result<ResumeCheckpoint, Failure> {
        let actor = if actor.is_empty() {
            ACTOR_OPERATOR
        } else {
            actor
        };
        if checkpoint_seq < 1 {
            return Err(Failure::invalid(
                "CHECKPOINT_SEQ_INVALID",
                "checkpoint_seq must be a positive caller-supplied sequence",
            ));
        }
        let run = uuid_of(run_id.as_bytes());
        let node = uuid_of(node_id.as_bytes());

        // Pre-transaction anchor resolution feeds the digest, which is
        // the only workspace read: the transaction re-resolves the
        // anchor under the run-row lock and refuses if a different
        // attempt became latest.
        let anchor = latest_attempt(&self.pool, node).await?;
        let workspace_digest = match &anchor.workspace_path {
            Some(path) => {
                let digester = self
                    .digester
                    .as_ref()
                    .ok_or_else(|| store_failure("checkpoint store: digester is not configured"))?;
                // A digest failure aborts the write pre-commit (P2C02):
                // no journal, no checkpoint row, the caller retries.
                Some(digester.digest(path, &anchor.workspace_kind).await?)
            }
            None => None,
        };

        let mut tx = begin_tx(&self.pool).await?;
        let workspace_id = sqlx::query_scalar!(
            "SELECT workspace_id FROM central.runs WHERE id = $1 FOR UPDATE",
            run,
        )
        .fetch_optional(&mut *tx)
        .await
        .ctx("checkpoint write: lock run row")?
        .ok_or_else(|| {
            Failure::invalid("CHECKPOINT_RUN_MISSING", "the anchor run does not exist")
        })?;
        let workspace_id = WorkspaceId::from_trusted_db_bytes(workspace_id.into_bytes());

        let node_row = sqlx::query!(
            "SELECT run_id, state, node_key FROM central.workflow_nodes \
             WHERE id = $1 FOR UPDATE",
            node,
        )
        .fetch_optional(&mut *tx)
        .await
        .ctx("checkpoint write: lock node row")?
        .ok_or_else(|| {
            Failure::invalid(
                "CHECKPOINT_ANCHOR_MISSING",
                "the anchor node does not exist",
            )
        })?;
        if node_row.run_id != run {
            return Err(Failure::invalid(
                "CHECKPOINT_ANCHOR_MISSING",
                "the anchor node is not a member of the run",
            ));
        }
        let node_key = node_row.node_key;
        let node_state = node_row.state;

        let locked = latest_attempt_tx(&mut tx, node).await?;
        let locked_id = SessionAttemptId::from_trusted_db_bytes(locked.id.into_bytes());
        if locked.id != anchor.id {
            // The attempt the digest binds is no longer latest; the
            // snapshot would record a stale workspace. This is a
            // boundary legality verdict, not an error — journal the
            // refusal like any other.
            let refusal = Failure::denied(
                codes::BOUNDARY_ILLEGAL,
                "anchor attempt advanced while the workspace digest was computed",
            );
            Self::refuse_tx(
                &mut tx,
                JournalCtx::new(workspace_id, run_id)
                    .node(node_id)
                    .attempt(locked_id),
                &node_key,
                actor,
                &refusal,
            )
            .await?;
            tx.commit().await.ctx("checkpoint write: commit refusal")?;
            return Err(refusal);
        }

        // The mid-finalization probe is subtree-scoped: an artifact
        // the subtree produced that sits in a pre-final lifecycle
        // state means finalization bytes are still moving — refuse
        // the boundary.
        let finalizing = sqlx::query_scalar!(
            "WITH RECURSIVE subtree AS (\
                SELECT id FROM central.workflow_nodes WHERE id = $1::uuid \
                UNION ALL \
                SELECT n.id FROM central.workflow_nodes n JOIN subtree s ON n.parent_node_id = s.id \
             ) \
             SELECT EXISTS(\
                SELECT 1 FROM central.artifact_produce_edges pe \
                JOIN central.artifacts a ON a.id = pe.artifact_id \
                WHERE pe.node_id IN (SELECT id FROM subtree) \
                  AND a.state = ANY($2::text[]))",
            node,
            &MID_FINALIZATION_ARTIFACT_STATES[..] as &[&str],
        )
        .fetch_one(&mut *tx)
        .await
        .ctx("checkpoint write: probe subtree finalization")?
        .unwrap_or(false);

        if let Err(refusal) = boundary_legal(&locked.state, &node_state, finalizing) {
            Self::refuse_tx(
                &mut tx,
                JournalCtx::new(workspace_id, run_id)
                    .node(node_id)
                    .attempt(locked_id),
                &node_key,
                actor,
                &refusal,
            )
            .await?;
            tx.commit().await.ctx("checkpoint write: commit refusal")?;
            return Err(refusal);
        }

        let completed = Self::subtree_completed_keys_tx(&mut tx, node).await?;
        let finalized = Self::subtree_read_set_tx(&mut tx, node).await?;
        let in_flight = Self::subtree_in_flight_tx(&mut tx, node).await?;

        let mut record = ResumeCheckpoint {
            id: ResumeCheckpointId::new(),
            workspace_id,
            run_id,
            node_id,
            attempt_id: locked_id,
            checkpoint_seq,
            format_version: central_checkpoint::domain::RESUME_FORMAT_VERSION.to_owned(),
            graph_schema_version: central_checkpoint::domain::GRAPH_SCHEMA_VERSION.to_owned(),
            event_watermark: 0, // the checkpoint_written seq below IS the watermark
            harness_session_id: locked.harness_session_id.clone(),
            workspace_digest,
            workspace_path: locked.workspace_path.clone(),
            completed_nodes: completed,
            finalized_artifacts: finalized
                .iter()
                .map(|u| ArtifactId::from_trusted_db_bytes(u.into_bytes()))
                .collect(),
            in_flight_nodes: in_flight,
            gc_class,
            created_at: OffsetDateTime::UNIX_EPOCH, // RETURNING overwrites
            expires_at: None,
            content_digest: String::new(),
        };

        // Spec-5 dedupe on UNIQUE (attempt_id, checkpoint_seq): the
        // probe runs before checkpoint_written is journaled so a replay
        // never advances the watermark. The run-row lock serializes
        // writers on this run, so a hit here is authoritative; the
        // INSERT below still relies on the constraint for writers
        // outside the lock discipline.
        let fingerprint = record.fingerprint();
        let stored: Option<Vec<u8>> = sqlx::query_scalar!(
            "SELECT payload_fingerprint FROM central.resume_checkpoints \
             WHERE attempt_id = $1 AND checkpoint_seq = $2",
            locked.id,
            checkpoint_seq,
        )
        .fetch_optional(&mut *tx)
        .await
        .ctx("checkpoint write: probe dedup key")?
        .flatten();

        match stored {
            Some(stored) if stored == fingerprint => {
                // Replay: return the recorded row and journal
                // command_deduped so the re-issue is observable
                // (spec-5 replay semantics).
                let existing = load_by_coordinate(&mut tx, locked.id, checkpoint_seq).await?;
                let event = journal_event(
                    &JournalCtx::new(workspace_id, run_id)
                        .node(node_id)
                        .attempt(locked_id),
                    EventKind::CommandDeduped,
                    actor,
                    None,
                    serde_json::json!({
                        "command": "write_checkpoint",
                        "node_key": node_key,
                        "checkpoint_id": existing.id.to_string(),
                        "checkpoint_seq": checkpoint_seq,
                    }),
                );
                append_tx(&mut tx, &event).await?;
                tx.commit().await.ctx("checkpoint write: commit dedup")?;
                return Ok(existing);
            }
            Some(_) => {
                // Same key, different payload fingerprint: the
                // recorded row stands and the write is refused
                // (spec-5).
                let refusal = Failure::denied(
                    codes::DUPLICATE_IDEMPOTENCY,
                    format!(
                        "checkpoint_seq {checkpoint_seq} already carries a checkpoint \
                         with a different payload fingerprint"
                    ),
                );
                Self::refuse_tx(
                    &mut tx,
                    JournalCtx::new(workspace_id, run_id)
                        .node(node_id)
                        .attempt(locked_id),
                    &node_key,
                    actor,
                    &refusal,
                )
                .await?;
                tx.commit().await.ctx("checkpoint write: commit refusal")?;
                return Err(refusal);
            }
            None => {}
        }

        // checkpoint_written lands first: its allocated seq IS the
        // snapshot's event_watermark (spec D1). Both commit in this
        // transaction.
        let written = journal_event(
            &JournalCtx::new(workspace_id, run_id)
                .node(node_id)
                .attempt(locked_id),
            EventKind::CheckpointWritten,
            actor,
            None,
            serde_json::json!({
                "checkpoint_id": record.id.to_string(),
                "node_key": node_key,
                "gc_class": gc_class.as_str(),
            }),
        );
        record.event_watermark = append_tx(&mut tx, &written).await?;
        record.content_digest = record.digest();

        let created_at = sqlx::query_scalar!(
            "INSERT INTO central.resume_checkpoints \
             (checkpoint_id, workspace_id, run_id, node_id, attempt_id, \
              checkpoint_seq, format_version, graph_schema_version, \
              event_watermark, harness_session_id, workspace_digest, \
              workspace_path, completed_nodes, finalized_artifacts, \
              in_flight_nodes, gc_class, expires_at, content_digest, \
              payload_fingerprint) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, \
                     $12, $13::text[], $14::uuid[], $15::text[], $16, \
                     NULL, $17, $18) \
             RETURNING created_at",
            uuid_of(record.id.as_bytes()),
            uuid_of(workspace_id.as_bytes()),
            run,
            node,
            locked.id,
            record.checkpoint_seq,
            record.format_version.as_str(),
            record.graph_schema_version.as_str(),
            record.event_watermark,
            record.harness_session_id.as_deref(),
            record.workspace_digest.as_deref(),
            record.workspace_path.as_deref(),
            &record.completed_nodes[..],
            &finalized[..],
            &record.in_flight_nodes[..],
            record.gc_class.as_str(),
            record.content_digest,
            &fingerprint[..],
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|err| {
            let failure = classify_sqlx(&err);
            if failure.code() == crate::error::codes::PG_UNIQUE_VIOLATION {
                // A writer outside the run-lock discipline won the key
                // race; the constraint makes the write fail closed and
                // the caller's retry dedupes on the probe above.
                return Failure::denied(
                    codes::DUPLICATE_IDEMPOTENCY,
                    format!(
                        "checkpoint_seq {checkpoint_seq} is already recorded \
                         for the anchor attempt"
                    ),
                );
            }
            failure
        })?;
        record.created_at = created_at;

        tx.commit().await.ctx("checkpoint write: commit")?;
        Ok(record)
    }

    async fn resolve_token(&self, token: &str) -> Result<ResumeCheckpoint, Failure> {
        let stale = |detail: &'static str| Failure::denied(codes::RESUME_TOKEN_STALE, detail);
        let decoded = decode_resume_token(token)?;
        let checkpoint = self
            .load_row(decoded.checkpoint_id)
            .await?
            .ok_or_else(|| stale("no live checkpoint exists for the token id"))?;
        if checkpoint
            .expires_at
            .is_some_and(|expires| expires <= OffsetDateTime::now_utc())
        {
            return Err(stale("the checkpoint has expired"));
        }
        if !checkpoint.token_matches(&decoded.digest_prefix) {
            return Err(stale(
                "the token digest does not match the recorded content",
            ));
        }
        Ok(checkpoint)
    }

    async fn resume_preflight(&self, token: &str) -> Result<ResumeCheckpoint, Failure> {
        self.preflight(token, ACTOR_OPERATOR).await
    }

    /// The all-or-nothing subtree resume inside one transaction
    /// (upstream `ResumeSubtree`, P2C04 spec D4): preflight runs first
    /// (its failures are returned unchanged, already journaled), then
    /// under the run-row lock it journals `resume_started`, applies the
    /// per-node state matrix, and journals `resume_completed` carrying
    /// `{dispatched_count, parked, terminal_held}`. Nodes returned to
    /// `ready` are picked up by the existing claim loop — resume never
    /// dispatches directly, so unfinished work relaunches as fresh
    /// session attempts with new `attempt_seq` values.
    ///
    /// The matrix (spec D4):
    ///   - `completed_nodes` members, `cancelled`, `succeeded`,
    ///     `failed_terminal`: untouched; terminal-not-completed keys
    ///     record in `terminal_held`;
    ///   - latest attempt in-flight at the watermark
    ///     (`in_flight_nodes`), a live attempt right now, or an
    ///     already-parked `attempt_ambiguous` node: park — the live
    ///     attempt closes `ambiguous` (`dispatch_reason_code`
    ///     `RESUME_REQUIRES_OPERATOR_DECISION`), its live lease
    ///     releases, the node goes `attempt_ambiguous` where the
    ///     machine admits it, and `attempt_ambiguous` journals once
    ///     when something changed;
    ///   - `declared`/`ready`/`dispatched`/`running` with a quiescent
    ///     or absent attempt: `ready` (`ready_at` stamped,
    ///     `node_ready` journaled) when the subtree-scoped readiness
    ///     predicate holds — every ordering in-edge `succeeded`, every
    ///     artifact in-edge `ready`, `not_before` passed — else
    ///     `declared`.
    ///
    /// Replay is idempotent: a second resume re-journals the
    /// `resume_started`/`resume_completed` pair (the re-invocation is
    /// itself a fact) but changes no state.
    async fn resume_subtree(&self, token: &str, actor: &str) -> Result<(), Failure> {
        let actor = if actor.is_empty() {
            ACTOR_OPERATOR
        } else {
            actor
        };
        let checkpoint = self.preflight(token, actor).await?;

        let mut tx = begin_tx(&self.pool).await?;
        let workspace = sqlx::query_scalar!(
            "SELECT workspace_id FROM central.runs WHERE id = $1 FOR UPDATE",
            uuid_of(checkpoint.run_id.as_bytes()),
        )
        .fetch_optional(&mut *tx)
        .await
        .ctx("checkpoint resume: lock run row")?
        .ok_or_else(|| store_failure("the checkpoint's run no longer exists"))?;
        let workspace_id = WorkspaceId::from_trusted_db_bytes(workspace.into_bytes());

        let anchor = uuid_of(checkpoint.node_id.as_bytes());
        let started = journal_event(
            &JournalCtx::new(workspace_id, checkpoint.run_id).node(checkpoint.node_id),
            EventKind::ResumeStarted,
            actor,
            None,
            serde_json::json!({"checkpoint_id": checkpoint.id.to_string()}),
        );
        append_tx(&mut tx, &started).await?;

        // Lock the whole subtree in key order (the run lock is already
        // held, so no concurrent claim or transition can interleave).
        let nodes = sqlx::query!(
            "WITH RECURSIVE subtree AS (\
                SELECT id FROM central.workflow_nodes WHERE id = $1::uuid \
                UNION ALL \
                SELECT n.id FROM central.workflow_nodes n JOIN subtree s ON n.parent_node_id = s.id \
             ) \
             SELECT n.id, n.node_key, n.state, n.not_before \
             FROM central.workflow_nodes n \
             WHERE n.id IN (SELECT id FROM subtree) \
             ORDER BY n.node_key FOR UPDATE",
            anchor,
        )
        .fetch_all(&mut *tx)
        .await
        .ctx("checkpoint resume: lock subtree")?;

        // A live attempt is unique per node
        // (session_attempts_live_node_idx), so it is necessarily the
        // node's latest attempt.
        let live_rows = sqlx::query!(
            "WITH RECURSIVE subtree AS (\
                SELECT id FROM central.workflow_nodes WHERE id = $1::uuid \
                UNION ALL \
                SELECT n.id FROM central.workflow_nodes n JOIN subtree s ON n.parent_node_id = s.id \
             ) \
             SELECT a.node_id, a.id FROM central.session_attempts a \
             WHERE a.node_id IN (SELECT id FROM subtree) \
               AND a.state = ANY($2::text[])",
            anchor,
            &LIVE_ATTEMPT_STATES[..] as &[&str],
        )
        .fetch_all(&mut *tx)
        .await
        .ctx("checkpoint resume: list live attempts")?;
        let live_attempts: std::collections::HashMap<uuid::Uuid, uuid::Uuid> = live_rows
            .into_iter()
            .map(|row| (row.node_id, row.id))
            .collect();

        let completed: std::collections::HashSet<&str> = checkpoint
            .completed_nodes
            .iter()
            .map(String::as_str)
            .collect();
        let in_flight: std::collections::HashSet<&str> = checkpoint
            .in_flight_nodes
            .iter()
            .map(String::as_str)
            .collect();

        let mut parked: Vec<String> = Vec::new();
        let mut terminal_held: Vec<String> = Vec::new();
        let mut dispatched = 0usize;
        let now = OffsetDateTime::now_utc();
        for node in nodes {
            // Terminal or recorded-complete: untouched. A terminal
            // node the checkpoint did not record complete (it
            // finished after the watermark) is reported to the
            // operator in resume_completed.
            if completed.contains(node.node_key.as_str()) {
                continue;
            }
            match node.state.as_str() {
                "succeeded" | "failed_terminal" | "cancelled" => {
                    terminal_held.push(node.node_key.clone());
                    continue;
                }
                _ => {}
            }

            let live = live_attempts.get(&node.id).copied();
            if node.state == "attempt_ambiguous"
                || in_flight.contains(node.node_key.as_str())
                || live.is_some()
            {
                // Ambiguous parking: the operator decides
                // harness-native resume or fresh rerun — resume never
                // auto-decides (spec locked input 2).
                let mut changed = false;
                if let Some(attempt) = live {
                    sqlx::query!(
                        "UPDATE central.session_attempts \
                            SET state = 'ambiguous', dispatch_reason_code = $2 \
                          WHERE id = $1 AND state = ANY($3::text[])",
                        attempt,
                        codes::RESUME_REQUIRES_OPERATOR,
                        &LIVE_ATTEMPT_STATES[..] as &[&str],
                    )
                    .execute(&mut *tx)
                    .await
                    .ctx("checkpoint resume: park live attempt")?;
                    sqlx::query!(
                        "UPDATE central.node_leases SET released_at = now() \
                          WHERE attempt_id = $1 AND released_at IS NULL",
                        attempt,
                    )
                    .execute(&mut *tx)
                    .await
                    .ctx("checkpoint resume: release parked attempt lease")?;
                    changed = true;
                }
                let ambiguous = WorkflowNodeStatus::parse(&node.state)
                    .is_some_and(|from| from.can_transition(WorkflowNodeStatus::AttemptAmbiguous));
                if node.state != "attempt_ambiguous" && ambiguous {
                    sqlx::query!(
                        "UPDATE central.workflow_nodes SET state = 'attempt_ambiguous' \
                         WHERE id = $1",
                        node.id,
                    )
                    .execute(&mut *tx)
                    .await
                    .ctx("checkpoint resume: park node")?;
                    changed = true;
                }
                if changed {
                    let node_id = WorkflowNodeId::from_trusted_db_bytes(node.id.into_bytes());
                    let event = journal_event(
                        &JournalCtx::new(workspace_id, checkpoint.run_id).node(node_id),
                        EventKind::AttemptAmbiguous,
                        actor,
                        Some(codes::RESUME_REQUIRES_OPERATOR.to_owned()),
                        serde_json::json!({
                            "node_key": node.node_key,
                            "checkpoint_id": checkpoint.id.to_string(),
                        }),
                    );
                    append_tx(&mut tx, &event).await?;
                }
                parked.push(node.node_key.clone());
                continue;
            }

            // Quiescent unfinished node: rebuild the ready set per the
            // subtree-scoped readiness predicate — all ordering
            // in-edges succeeded, all artifact in-edges finalized,
            // not_before passed.
            let unready = sqlx::query_scalar!(
                "SELECT EXISTS(\
                    SELECT 1 FROM central.workflow_edges e \
                    JOIN central.workflow_nodes p ON p.id = e.prerequisite_node_id \
                    WHERE e.dependent_node_id = $1 \
                      AND e.kind = 'ordering' AND p.state <> 'succeeded')\
                 OR EXISTS(\
                    SELECT 1 FROM central.workflow_edges e \
                    LEFT JOIN central.artifacts a ON a.id = e.artifact_id \
                    WHERE e.dependent_node_id = $1 \
                      AND e.kind = 'artifact' AND a.state IS DISTINCT FROM 'ready')",
                node.id,
            )
            .fetch_one(&mut *tx)
            .await
            .ctx("checkpoint resume: readiness probe")?
            .unwrap_or(false);
            let gated = node.not_before.is_some_and(|bound| bound > now);
            if !unready && !gated {
                if node.state != "ready" {
                    sqlx::query!(
                        "UPDATE central.workflow_nodes \
                         SET state = 'ready', ready_at = now() WHERE id = $1",
                        node.id,
                    )
                    .execute(&mut *tx)
                    .await
                    .ctx("checkpoint resume: ready node")?;
                    let node_id = WorkflowNodeId::from_trusted_db_bytes(node.id.into_bytes());
                    let event = journal_event(
                        &JournalCtx::new(workspace_id, checkpoint.run_id).node(node_id),
                        EventKind::NodeReady,
                        actor,
                        None,
                        serde_json::json!({"node_key": node.node_key}),
                    );
                    append_tx(&mut tx, &event).await?;
                }
                dispatched += 1;
                continue;
            }
            // Readiness does not hold: the node returns to (or stays
            // in) 'declared' — the resume rebuild is the documented
            // exception to the live-transition machine, which has no
            // ->declared edge; a stale ready_at clears so a later flip
            // restarts FIFO ordering.
            if node.state != "declared" {
                sqlx::query!(
                    "UPDATE central.workflow_nodes \
                     SET state = 'declared', ready_at = NULL WHERE id = $1",
                    node.id,
                )
                .execute(&mut *tx)
                .await
                .ctx("checkpoint resume: demote node")?;
            }
        }

        parked.sort();
        terminal_held.sort();
        let completed_event = journal_event(
            &JournalCtx::new(workspace_id, checkpoint.run_id).node(checkpoint.node_id),
            EventKind::ResumeCompleted,
            actor,
            None,
            serde_json::json!({
                "checkpoint_id": checkpoint.id.to_string(),
                "dispatched_count": dispatched,
                "parked": parked,
                "terminal_held": terminal_held,
            }),
        );
        append_tx(&mut tx, &completed_event).await?;

        tx.commit().await.ctx("checkpoint resume: commit")?;
        Ok(())
    }

    async fn update_gc_class(
        &self,
        checkpoint_id: ResumeCheckpointId,
        class: GcClass,
    ) -> Result<(), Failure> {
        let result = sqlx::query!(
            "UPDATE central.resume_checkpoints SET gc_class = $2 \
             WHERE checkpoint_id = $1",
            uuid_of(checkpoint_id.as_bytes()),
            class.as_str(),
        )
        .execute(&self.pool)
        .await
        .ctx("checkpoint gc-class update")?;
        if result.rows_affected() == 0 {
            return Err(Failure::invalid(
                "CHECKPOINT_NOT_FOUND",
                "no checkpoint exists for the given id",
            ));
        }
        Ok(())
    }

    async fn list_by_anchor(
        &self,
        run_id: RunId,
        node_id: WorkflowNodeId,
    ) -> Result<Vec<ResumeCheckpoint>, Failure> {
        let rows = sqlx::query_as!(
            ResumeCheckpointRow,
            "SELECT checkpoint_id, workspace_id, run_id, node_id, \
             attempt_id, format_version, graph_schema_version, event_watermark, \
             harness_session_id, workspace_digest, workspace_path, completed_nodes, \
             finalized_artifacts, in_flight_nodes, gc_class, created_at, expires_at, \
             content_digest, checkpoint_seq \
             FROM central.resume_checkpoints \
             WHERE run_id = $1 AND node_id = $2 \
             ORDER BY created_at DESC, checkpoint_id DESC",
            uuid_of(run_id.as_bytes()),
            uuid_of(node_id.as_bytes()),
        )
        .fetch_all(&self.pool)
        .await
        .ctx("checkpoint: list anchor checkpoints")?;
        rows.into_iter().map(ResumeCheckpoint::try_from).collect()
    }

    async fn list_checkpoints(&self, run_id: RunId) -> Result<Vec<ResumeCheckpoint>, Failure> {
        let rows = sqlx::query_as!(
            ResumeCheckpointRow,
            "SELECT checkpoint_id, workspace_id, run_id, node_id, \
             attempt_id, format_version, graph_schema_version, event_watermark, \
             harness_session_id, workspace_digest, workspace_path, completed_nodes, \
             finalized_artifacts, in_flight_nodes, gc_class, created_at, expires_at, \
             content_digest, checkpoint_seq \
             FROM central.resume_checkpoints \
             WHERE run_id = $1 \
             ORDER BY created_at DESC, checkpoint_id DESC",
            uuid_of(run_id.as_bytes()),
        )
        .fetch_all(&self.pool)
        .await
        .ctx("checkpoint: list run checkpoints")?;
        rows.into_iter().map(ResumeCheckpoint::try_from).collect()
    }

    async fn load_resume_checkpoint_by_id(
        &self,
        checkpoint_id: ResumeCheckpointId,
    ) -> Result<ResumeCheckpoint, Failure> {
        self.load_row(checkpoint_id).await?.ok_or_else(|| {
            Failure::invalid(
                "CHECKPOINT_NOT_FOUND",
                "no checkpoint exists for the given id",
            )
        })
    }
}
