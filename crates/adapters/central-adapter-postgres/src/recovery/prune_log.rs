//! `central.prune_log` (b29) — the durable D04 prune journal. One row per
//! `(plan_id, batch_seq, artifact_id)` carries the retention age and
//! reference count the delete-time checks proved, plus the batch state
//! machine the crash resume reads: `pending` rows were never attempted,
//! `applying` rows were interrupted mid-batch, `done` rows must never be
//! re-executed.
//!
//! Upstream ships no production `PruneJournal` (`cmd/central` installs
//! `unavailablePruneEngine`); this store implements the
//! `destructive.PruneJournal` contract against the b29 table so the port
//! has a real PostgreSQL backend. The domain types live here because the
//! `destructive` capability itself is not yet ported — they mirror
//! `internal/destructive` field-for-field and move when that crate lands.
//!
//! Per-body resume is tombstone-driven, exactly like upstream:
//! `prune_log.state` tracks the *batch*, while `artifact_tombstones`
//! presence decides whether an interrupted body's settlement is replayed.

use std::collections::HashMap;

use central_foundation::failure::{Failure, FailureKind};
use sqlx::{Connection as _, PgConnection};
use uuid::Uuid;

use crate::error::SqlxContext as _;
use crate::store_support::{BlockingConn, PG_DATA_CORRUPT};

fn prune_invalid(message: &'static str) -> Failure {
    Failure::invalid("recovery_prune", message)
}

fn prune_conflict(message: &'static str) -> Failure {
    Failure::new(FailureKind::Conflict, "recovery_prune_conflict", message)
}

fn corrupt(message: &'static str) -> Failure {
    Failure::internal(PG_DATA_CORRUPT, message)
}

/// `destructive.PruneRowState` — the prune_log state vocabulary,
/// mirroring the v29 CHECK constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PruneRowState {
    /// Never attempted.
    Pending,
    /// Interrupted mid-batch; re-execution is idempotent via tombstones.
    Applying,
    /// Settled; must never be re-executed.
    Done,
}

impl PruneRowState {
    /// The CHECK-constraint text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Applying => "applying",
            Self::Done => "done",
        }
    }

    fn parse(value: &str) -> Result<Self, Failure> {
        match value {
            "pending" => Ok(Self::Pending),
            "applying" => Ok(Self::Applying),
            "done" => Ok(Self::Done),
            _ => Err(corrupt("a stored prune_log state is unknown")),
        }
    }
}

/// `destructive.PruneCandidate` — one artifact body eligible for
/// deletion: old enough and unreferenced at plan time. `retention_age_days`
/// and `reference_count` are the proof the checks produced, journaled
/// verbatim into `prune_log`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruneCandidate {
    /// Artifact identity.
    pub artifact_id: Uuid,
    /// Workspace identity.
    pub workspace_id: Uuid,
    /// The ready object key (adapter-internal; never crosses a port).
    pub object_key: String,
    /// Staging generation for the tombstone.
    pub staging_generation: Uuid,
    /// Body size.
    pub size: i64,
    /// Proven retention age at plan time.
    pub retention_age_days: i32,
    /// Proven reference count at plan time.
    pub reference_count: i32,
}

/// `destructive.PruneBatch` — one checkpoint unit of an apply run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruneBatch {
    /// Plan identity.
    pub plan_id: Uuid,
    /// Zero-based batch ordinal.
    pub batch_seq: i32,
    /// The batch's bodies.
    pub bodies: Vec<PruneCandidate>,
}

/// `destructive.PruneJournal` — the write port for `prune_log` rows,
/// tombstones, and the artifact metadata transition. Production runs as
/// `central_migration` in one transaction per call; the metadata mark is
/// `state='deleted'`, matching the artifact lifecycle settlement.
pub trait PruneJournal: Send + Sync {
    /// `MarkBatchApplying` — journals the batch's rows as `applying`.
    /// Idempotent: replays refresh `checkpoint_at`, never resurrect a
    /// `done` row.
    fn mark_batch_applying(&self, batch: &PruneBatch) -> Result<(), Failure>;
    /// `RecordBodyDeleted` — atomically persists the tombstone, the
    /// artifact `deleted` transition, and the workspace quota release
    /// for one body. Idempotent under an already-deleted artifact.
    fn record_body_deleted(
        &self,
        batch: &PruneBatch,
        body: &PruneCandidate,
        tombstone_id: Uuid,
    ) -> Result<(), Failure>;
    /// `MarkBatchDone` — the batch's terminal mark.
    fn mark_batch_done(&self, plan_id: Uuid, batch_seq: i32) -> Result<(), Failure>;
    /// `BatchStates` — every journaled batch state for the plan; a
    /// missing batch is `pending` by omission.
    fn batch_states(&self, plan_id: Uuid) -> Result<HashMap<i32, PruneRowState>, Failure>;
    /// `HasTombstone` — the tombstone-existence probe resume consults.
    fn has_tombstone(&self, workspace_id: Uuid, artifact_id: Uuid) -> Result<bool, Failure>;
}

/// `PruneLogStore` — the production `central_migration` journal.
pub struct PruneLogStore {
    conn: BlockingConn,
}

impl PruneLogStore {
    /// Binds the dedicated `central_migration` session.
    ///
    /// # Errors
    /// `pg_adapter_error` when the bridge runtime cannot be built.
    pub fn new(conn: PgConnection) -> Result<Self, Failure> {
        Ok(Self {
            conn: BlockingConn::new(conn)?,
        })
    }
}

fn validate_batch(batch: &PruneBatch) -> Result<(), Failure> {
    if batch.plan_id.is_nil()
        || batch.batch_seq < 0
        || batch.bodies.is_empty()
        || batch
            .bodies
            .iter()
            .any(|b| b.artifact_id.is_nil() || b.workspace_id.is_nil() || b.size < 0)
    {
        return Err(prune_invalid("prune batch is invalid"));
    }
    Ok(())
}

impl PruneJournal for PruneLogStore {
    fn mark_batch_applying(&self, batch: &PruneBatch) -> Result<(), Failure> {
        validate_batch(batch)?;
        if batch
            .bodies
            .iter()
            .any(|b| b.retention_age_days < 0 || b.reference_count < 0)
        {
            return Err(prune_invalid("prune candidate proof is invalid"));
        }
        let batch = batch.clone();
        self.conn.run(|conn| {
            Box::pin(async move {
                let mut tx = conn.begin().await.ctx("prune journal begin")?;
                for body in &batch.bodies {
                    sqlx::query!(
                        "INSERT INTO central.prune_log (
                            plan_id, batch_seq, artifact_id, workspace_id,
                            retention_age_days, reference_count, state, checkpoint_at
                        ) VALUES ($1::uuid, $2, $3::uuid, $4::uuid, $5, $6,
                            'applying', clock_timestamp())
                        ON CONFLICT (plan_id, batch_seq, artifact_id) DO UPDATE
                            SET state='applying', checkpoint_at=EXCLUDED.checkpoint_at
                            WHERE prune_log.state <> 'done'",
                        batch.plan_id,
                        batch.batch_seq,
                        body.artifact_id,
                        body.workspace_id,
                        body.retention_age_days,
                        body.reference_count,
                    )
                    .execute(&mut *tx)
                    .await
                    .ctx("prune journal mark applying")?;
                }
                tx.commit().await.ctx("prune journal commit")
            })
        })
    }

    fn record_body_deleted(
        &self,
        batch: &PruneBatch,
        body: &PruneCandidate,
        tombstone_id: Uuid,
    ) -> Result<(), Failure> {
        validate_batch(batch)?;
        if tombstone_id.is_nil()
            || body.artifact_id.is_nil()
            || body.workspace_id.is_nil()
            || body.size < 0
        {
            return Err(prune_invalid("prune body settlement is invalid"));
        }
        let batch = batch.clone();
        let body = body.clone();
        self.conn.run(|conn| {
            Box::pin(async move {
                let mut tx = conn.begin().await.ctx("prune settlement begin")?;
                struct RawArtifact {
                    object_key: String,
                    staging_generation: uuid::Uuid,
                    checksum_algorithm: Option<String>,
                    checksum_value: Option<Vec<u8>>,
                    size: i64,
                    state: String,
                }
                let row = sqlx::query_as!(
                    RawArtifact,
                    "SELECT object_key, staging_generation, checksum_algorithm,
                        checksum_value, size, state
                    FROM central.artifacts
                    WHERE id=$1::uuid AND workspace_id=$2::uuid FOR UPDATE",
                    body.artifact_id,
                    body.workspace_id,
                )
                .fetch_optional(&mut *tx)
                .await
                .ctx("prune settlement lock artifact")?;
                let Some(row) = row else {
                    return Err(prune_conflict("prune body artifact is absent"));
                };
                if row.state != "deleted" {
                    // The tombstone journal is append-exactly-once
                    // (`artifact_tombstones_artifact_id_unique`).
                    sqlx::query!(
                        "INSERT INTO central.artifact_tombstones (
                            id, workspace_id, artifact_id, object_key,
                            staging_generation, checksum_algorithm, checksum_value,
                            size_at_deletion, deletion_reason
                        ) VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5::uuid, $6, $7, $8, 'pruned')
                        ON CONFLICT (workspace_id, artifact_id) DO NOTHING",
                        tombstone_id,
                        body.workspace_id,
                        body.artifact_id,
                        row.object_key,
                        row.staging_generation,
                        row.checksum_algorithm,
                        row.checksum_value,
                        row.size,
                    )
                    .execute(&mut *tx)
                    .await
                    .ctx("prune settlement insert tombstone")?;
                    let done = sqlx::query!(
                        "UPDATE central.artifacts
                            SET state='deleted', deleted_at=clock_timestamp(),
                                version=version+1, updated_at=clock_timestamp()
                            WHERE workspace_id=$1::uuid AND id=$2::uuid
                              AND state <> 'deleted'",
                        body.workspace_id,
                        body.artifact_id,
                    )
                    .execute(&mut *tx)
                    .await
                    .ctx("prune settlement transition artifact")?
                    .rows_affected();
                    if done != 1 {
                        return Err(prune_conflict("prune body artifact changed concurrently"));
                    }
                    // Same quota release as the lifecycle settlement —
                    // exactly once, only on the non-replayed arm.
                    sqlx::query!(
                        "UPDATE central.workspaces
                            SET quota_ready_bytes = GREATEST(0, quota_ready_bytes - $2),
                                quota_ready_count = GREATEST(0, quota_ready_count - 1),
                                updated_at = clock_timestamp()
                            WHERE id=$1::uuid",
                        body.workspace_id,
                        row.size,
                    )
                    .execute(&mut *tx)
                    .await
                    .ctx("prune settlement release quota")?;
                } else {
                    // A deleted row without its journaled tombstone
                    // violates the pairing invariant — corrupt durable
                    // state, not a replay.
                    let exists = sqlx::query_scalar!(
                        "SELECT EXISTS(
                            SELECT 1 FROM central.artifact_tombstones
                            WHERE workspace_id=$1::uuid AND artifact_id=$2::uuid
                        ) AS \"exists!\"",
                        body.workspace_id,
                        body.artifact_id,
                    )
                    .fetch_one(&mut *tx)
                    .await
                    .ctx("prune settlement probe tombstone")?;
                    if !exists {
                        return Err(corrupt(
                            "a deleted artifacts row is missing its artifact_tombstones journal",
                        ));
                    }
                }
                // The checkpoint advance is per-body evidence inside the
                // still-applying batch.
                sqlx::query!(
                    "UPDATE central.prune_log SET checkpoint_at=clock_timestamp()
                        WHERE plan_id=$1::uuid AND batch_seq=$2 AND artifact_id=$3::uuid
                          AND state='applying'",
                    batch.plan_id,
                    batch.batch_seq,
                    body.artifact_id,
                )
                .execute(&mut *tx)
                .await
                .ctx("prune settlement journal checkpoint")?;
                tx.commit().await.ctx("prune settlement commit")
            })
        })
    }

    fn mark_batch_done(&self, plan_id: Uuid, batch_seq: i32) -> Result<(), Failure> {
        if plan_id.is_nil() || batch_seq < 0 {
            return Err(prune_invalid("prune batch identity is invalid"));
        }
        self.conn.run(|conn| {
            Box::pin(async move {
                sqlx::query!(
                    "UPDATE central.prune_log
                        SET state='done', checkpoint_at=clock_timestamp()
                        WHERE plan_id=$1::uuid AND batch_seq=$2 AND state <> 'done'",
                    plan_id,
                    batch_seq,
                )
                .execute(&mut *conn)
                .await
                .ctx("prune journal mark done")?;
                Ok::<(), Failure>(())
            })
        })
    }

    fn batch_states(&self, plan_id: Uuid) -> Result<HashMap<i32, PruneRowState>, Failure> {
        if plan_id.is_nil() {
            return Err(prune_invalid("prune plan identity is invalid"));
        }
        self.conn.run(|conn| {
            Box::pin(async move {
                let rows = sqlx::query!(
                    "SELECT batch_seq, state FROM central.prune_log
                        WHERE plan_id=$1::uuid ORDER BY batch_seq",
                    plan_id,
                )
                .fetch_all(&mut *conn)
                .await
                .ctx("prune journal read states")?;
                // Aggregate to one state per batch: `done` only when every
                // row is done (a `done` batch is skipped entirely);
                // `applying` when any row was attempted; else `pending`.
                let mut states: HashMap<i32, (bool, bool)> = HashMap::new();
                for row in &rows {
                    let state = PruneRowState::parse(&row.state)?;
                    let entry = states.entry(row.batch_seq).or_insert((true, false));
                    entry.0 &= state == PruneRowState::Done;
                    entry.1 |= state == PruneRowState::Applying;
                }
                Ok::<HashMap<i32, PruneRowState>, Failure>(
                    states
                        .into_iter()
                        .map(|(batch_seq, (all_done, any_applying))| {
                            (
                                batch_seq,
                                if all_done {
                                    PruneRowState::Done
                                } else if any_applying {
                                    PruneRowState::Applying
                                } else {
                                    PruneRowState::Pending
                                },
                            )
                        })
                        .collect(),
                )
            })
        })
    }

    fn has_tombstone(&self, workspace_id: Uuid, artifact_id: Uuid) -> Result<bool, Failure> {
        if workspace_id.is_nil() || artifact_id.is_nil() {
            return Err(prune_invalid("prune tombstone probe is invalid"));
        }
        self.conn.run(|conn| {
            Box::pin(async move {
                let exists = sqlx::query_scalar!(
                    "SELECT EXISTS(
                        SELECT 1 FROM central.artifact_tombstones
                        WHERE workspace_id=$1::uuid AND artifact_id=$2::uuid
                    ) AS \"exists!\"",
                    workspace_id,
                    artifact_id,
                )
                .fetch_one(&mut *conn)
                .await
                .ctx("prune journal tombstone probe")?;
                Ok::<bool, Failure>(exists)
            })
        })
    }
}
