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

use central_checkpoint::domain::{
    Checkpoint, CheckpointKind, CheckpointPayload, GcClass, MAX_CHECKPOINT_PAYLOAD_BYTES,
    ResumeCheckpoint, codes,
};
use central_checkpoint::port::{CheckpointStore, ResumeCheckpointStore};
use central_checkpoint::query::{
    MAX_CHECKPOINT_PAGE, RunCheckpointPage, RunCheckpointRead, RunCheckpointRequest,
};
use central_foundation::failure::Failure;
use central_foundation::identity::{
    ArtifactId, CheckpointId, ResumeCheckpointId, RunId, SessionAttemptId, StepAttemptId, StepId,
    TaskId, WorkflowNodeId, WorkspaceId,
};
use sqlx::PgPool;
use time::OffsetDateTime;

use crate::error::{SqlxContext, classify_sqlx};
use crate::store_support::{
    PG_DATA_CORRUPT, begin_tx, i64_as_u64, u64_as_i64, usize_as_i64, uuid_of,
};

/// Conflict code for a duplicate `central.checkpoints` identity.
const CHECKPOINT_ALREADY_EXISTS: &str = "checkpoint_already_exists";

/// PostgreSQL-backed checkpoint store.
#[derive(Debug, Clone)]
pub struct Store {
    pool: PgPool,
}

impl Store {
    /// Binds the store to a `central_runtime`-authorized pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
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
