//! `central-artifact::port::Store`, `TwoPhaseDeleteStore`, and
//! `query::ArtifactSummaryRead` implementations — the port of
//! `internal/adapter/postgres/artifact/store.go`'s non-completion
//! surface (`ReserveArtifact` … `RecordRejection`, `LoadArtifact`) plus
//! the Rust two-phase deletion commits (`docs/artifacts/lifecycle.md`
//! §Delete intent and tombstone; adapter-mapping §3.9–§3.10).
//!
//! Every command method opens one bounded transaction through
//! `store_support::begin_tx` (the shared `READ COMMITTED` opener with
//! the advisory lock/statement/idle timeouts), checks the command
//! receipt before touching durable state, and commits the transition,
//! any paired capacity release, and the receipt in the same commit.
//! An exact replay under a retained receipt re-reads the stored row
//! and returns it rather than re-transitioning.

use central_artifact::domain::{
    Artifact, ArtifactTombstone, BeginUploadResult, Outcome, OutcomeKind, PromotionResult,
    RejectResult, ReserveResult, State, VerifiedResult,
};
use central_artifact::port::{Store as ArtifactStore, TwoPhaseDeleteResult, TwoPhaseDeleteStore};
use central_artifact::query::{
    ArtifactListProjection, ArtifactListRequest, ArtifactSeekCursor, ArtifactSummaryRead,
    ArtifactSummaryView, normalize_artifact_page_size, validate_artifact_list_request,
};
use central_foundation::failure::Failure;
use central_foundation::identity::{ArtifactId, WorkspaceId};
use sqlx::PgPool;

use super::queries::{
    active_capacity_sum, command_receipt_key, fingerprint_mismatch, insert_artifact_receipt,
    lock_workspace_quota, lookup_artifact_receipt, outcome_from_row, read_artifact,
    read_artifact_for_update, read_tombstone, release_capacity_reservation, to_domain_artifact,
};
use super::{conflict, corrupt, denied, invalid};
use crate::error::{SqlxContext, classify_sqlx};
use crate::store_support::{begin_tx, opt_uuid_of, usize_as_i64, uuid_of};

/// PostgreSQL artifact store — a thin `PgPool` holder; every port
/// method opens its own bounded transaction.
pub struct Store {
    pub(crate) pool: PgPool,
}

impl Store {
    /// `New`.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn stage_payload(stage: &'static str) -> serde_json::Value {
    serde_json::json!({"stage": stage})
}

/// The Go `Outcome` JSON form for a journaled rejection (`{"Kind":...,
/// "FailureCode":...}` — exported-field names, no tags).
pub(crate) fn outcome_payload(outcome: &Outcome) -> serde_json::Value {
    serde_json::json!({
        "Kind": outcome.kind.as_str(),
        "FailureCode": outcome.failure_code.as_str(),
    })
}

impl ArtifactStore for Store {
    /// `ReserveArtifact` — receipt replay, quota admission under the
    /// `FOR NO KEY UPDATE` workspace lock, then the artifact row, the
    /// `2 * max_bytes` capacity reservation, and the receipt in one
    /// commit.
    async fn reserve_artifact(&self, result: ReserveResult) -> Result<ReserveResult, Failure> {
        // `reserve` already enforces non-zero fields; this defensive
        // re-check guards a ReserveResult built by hand (upstream's own
        // comment).
        let artifact = &result.artifact;
        if artifact.workspace_id.is_nil()
            || artifact.artifact_id.is_nil()
            || artifact.task_id.is_nil()
            || artifact.run_id.is_nil()
            || artifact.step_id.is_nil()
            || artifact.step_attempt_id.is_nil()
            || artifact.producer_id.is_empty()
        {
            return Err(invalid("INVALID_RESERVE_RESULT"));
        }
        let (key, fingerprint) = command_receipt_key(&result.identity);
        let workspace_id = artifact.workspace_id;
        let artifact_id = artifact.artifact_id;

        let mut tx = begin_tx(&self.pool).await?;
        let existing = lookup_artifact_receipt(&mut tx, workspace_id, "reserve", &key).await?;
        if existing.found {
            if existing.fingerprint != fingerprint {
                return Err(fingerprint_mismatch());
            }
            let row = read_artifact(&mut *tx, workspace_id, artifact_id).await?;
            let stored = to_domain_artifact(&row);
            tx.commit().await.map_err(|e| classify_sqlx(&e))?;
            return Ok(ReserveResult {
                artifact: stored,
                identity: result.identity,
            });
        }

        // 1. Lock the quota ledger — `FOR NO KEY UPDATE` so the FK
        //    key-share probe on `central.tasks`/`central.runs` cannot
        //    deadlock this commit against a concurrent execution commit
        //    (upstream harness phase 3b).
        let Some((ready_bytes, max_bytes)) = lock_workspace_quota(&mut tx, workspace_id).await?
        else {
            return Err(invalid("WORKSPACE_NOT_FOUND"));
        };
        let reserved_sum = active_capacity_sum(&mut tx, workspace_id).await?;
        // Staging body plus promotion peak: the ready copy exists
        // alongside the staged body until staging cleanup — the
        // reservation accounts for the peak.
        let needed = artifact.limits.max_bytes.saturating_mul(2);
        if ready_bytes + reserved_sum + needed > max_bytes {
            return Err(denied("QUOTA_EXCEEDED"));
        }

        let limits_snapshot = serde_json::json!({"max_bytes": artifact.limits.max_bytes});
        // `object_key`/`staging_generation` are the deprecated legacy
        // baseline columns B10 keeps NOT NULL for compatibility; they
        // carry only the same opaque staging key/generation, never
        // caller-controlled data.
        sqlx::query!(
            "INSERT INTO central.artifacts (\
             id, workspace_id, task_id, run_id, version, state, size, \
             staging_generation, object_key, sensitivity, disposition, \
             staging_key, step_id, step_attempt_id, tool_call_attempt_id, \
             producer_id, required_role, limits_snapshot) \
             VALUES ($1, $2, $3, $4, 1, 'reserved', 0, \
             $5, $6, 'restricted', 'attachment', \
             $7, $8, $9, $10, $11, NULLIF($12, ''), $13::jsonb)",
            uuid_of(artifact_id.as_bytes()),
            uuid_of(workspace_id.as_bytes()),
            uuid_of(artifact.task_id.as_bytes()),
            uuid_of(artifact.run_id.as_bytes()),
            uuid_of(artifact.staging_generation.as_bytes()),
            artifact.staging_key.as_str(),
            artifact.staging_key.as_str(),
            opt_uuid_of(
                (!artifact.step_id.is_nil()).then_some(artifact.step_id),
                |id| id.as_bytes()
            ),
            opt_uuid_of(
                (!artifact.step_attempt_id.is_nil()).then_some(artifact.step_attempt_id),
                |id| id.as_bytes()
            ),
            opt_uuid_of(artifact.tool_call_attempt_id, |id| id.as_bytes()),
            artifact.producer_id.as_str(),
            artifact.required_role.as_str(),
            limits_snapshot,
        )
        .execute(&mut *tx)
        .await
        .ctx("artifact: insert artifact")?;

        sqlx::query!(
            "INSERT INTO central.capacity_reservations (\
             id, workspace_id, run_id, artifact_id, staging_generation, \
             reserved_bytes, state) \
             VALUES ($1, $2, $3, $4, $5, $6, 'reserved')",
            uuid::Uuid::now_v7(),
            uuid_of(workspace_id.as_bytes()),
            uuid_of(artifact.run_id.as_bytes()),
            uuid_of(artifact_id.as_bytes()),
            uuid_of(artifact.staging_generation.as_bytes()),
            needed,
        )
        .execute(&mut *tx)
        .await
        .ctx("artifact: insert capacity reservation")?;

        insert_artifact_receipt(
            &mut tx,
            workspace_id,
            artifact_id,
            "reserve",
            &key,
            fingerprint,
            stage_payload("reserve"),
        )
        .await?;

        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(result)
    }

    /// `RecordBeginUpload` — receipt replay, then the `reserved` →
    /// `staging` transition under the expected-version guard.
    async fn record_begin_upload(
        &self,
        result: BeginUploadResult,
    ) -> Result<BeginUploadResult, Failure> {
        let (key, fingerprint) = command_receipt_key(&result.identity);
        let workspace_id = result.artifact.workspace_id;
        let artifact_id = result.artifact.artifact_id;

        let mut tx = begin_tx(&self.pool).await?;
        let existing = lookup_artifact_receipt(&mut tx, workspace_id, "begin_upload", &key).await?;
        if existing.found {
            if existing.fingerprint != fingerprint {
                return Err(fingerprint_mismatch());
            }
            let row = read_artifact(&mut *tx, workspace_id, artifact_id).await?;
            let stored = to_domain_artifact(&row);
            tx.commit().await.map_err(|e| classify_sqlx(&e))?;
            return Ok(BeginUploadResult {
                artifact: stored,
                identity: result.identity,
            });
        }

        let row = read_artifact_for_update(&mut tx, workspace_id, artifact_id).await?;
        if row.version != result.identity.expected_version {
            return Err(conflict("VERSION_CONFLICT"));
        }
        if row.state != State::Reserved {
            return Err(conflict("INVALID_TRANSITION"));
        }

        let done = sqlx::query!(
            "UPDATE central.artifacts \
             SET version = $3, state = $4, updated_at = clock_timestamp() \
             WHERE workspace_id = $1 AND id = $2 AND version = $5",
            uuid_of(workspace_id.as_bytes()),
            uuid_of(artifact_id.as_bytes()),
            result.artifact.version,
            result.artifact.state.as_str(),
            row.version,
        )
        .execute(&mut *tx)
        .await
        .ctx("artifact: update artifact begin upload")?
        .rows_affected();
        if done != 1 {
            return Err(conflict("VERSION_CONFLICT"));
        }

        insert_artifact_receipt(
            &mut tx,
            workspace_id,
            artifact_id,
            "begin_upload",
            &key,
            fingerprint,
            stage_payload("begin_upload"),
        )
        .await?;
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(result)
    }

    /// `RecordVerification` — persists the verifying evidence or the
    /// terminal rejection. A rejection releases the capacity
    /// reservation in the same commit, exactly once.
    async fn record_verification(&self, result: VerifiedResult) -> Result<VerifiedResult, Failure> {
        let (key, fingerprint) = command_receipt_key(&result.identity);
        let workspace_id = result.artifact.workspace_id;
        let artifact_id = result.artifact.artifact_id;

        let mut tx = begin_tx(&self.pool).await?;
        let existing = lookup_artifact_receipt(&mut tx, workspace_id, "verify", &key).await?;
        if existing.found {
            if existing.fingerprint != fingerprint {
                return Err(fingerprint_mismatch());
            }
            let row = read_artifact(&mut *tx, workspace_id, artifact_id).await?;
            let outcome = outcome_from_row(&row);
            let stored = to_domain_artifact(&row);
            tx.commit().await.map_err(|e| classify_sqlx(&e))?;
            return Ok(VerifiedResult {
                artifact: stored,
                identity: result.identity,
                outcome,
            });
        }

        let row = read_artifact_for_update(&mut tx, workspace_id, artifact_id).await?;
        if row.version != result.identity.expected_version {
            return Err(conflict("VERSION_CONFLICT"));
        }
        if row.state != State::Staging {
            return Err(conflict("INVALID_TRANSITION"));
        }

        let checksum: Option<&[u8]> = (result.artifact.state == State::Verifying)
            .then_some(&result.artifact.verified_checksum[..]);
        let rejection: Option<serde_json::Value> =
            (result.artifact.state == State::Rejected).then(|| {
                serde_json::json!({
                    "code": result
                        .outcome
                        .as_ref()
                        .map_or("", |outcome| outcome.failure_code.as_str()),
                })
            });
        let done = sqlx::query!(
            "UPDATE central.artifacts \
             SET version = $3, state = $4, size = $5, \
             checksum_value = $6, \
             checksum_algorithm = CASE WHEN $6::bytea IS NULL \
               THEN checksum_algorithm ELSE 'sha256' END, \
             rejection = COALESCE($7::jsonb, rejection), \
             updated_at = clock_timestamp() \
             WHERE workspace_id = $1 AND id = $2 AND version = $8",
            uuid_of(workspace_id.as_bytes()),
            uuid_of(artifact_id.as_bytes()),
            result.artifact.version,
            result.artifact.state.as_str(),
            result.artifact.verified_size,
            checksum,
            rejection,
            row.version,
        )
        .execute(&mut *tx)
        .await
        .ctx("artifact: update artifact verification")?
        .rows_affected();
        if done != 1 {
            return Err(conflict("VERSION_CONFLICT"));
        }

        if result.artifact.state == State::Rejected {
            release_capacity_reservation(&mut tx, workspace_id, artifact_id).await?;
        }

        insert_artifact_receipt(
            &mut tx,
            workspace_id,
            artifact_id,
            "verify",
            &key,
            fingerprint,
            stage_payload("verify"),
        )
        .await?;
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(result)
    }

    /// `RecordPromotion` — binds the content generation and ready key
    /// under the `verifying` + empty-`ready_key` guard.
    async fn record_promotion(&self, result: PromotionResult) -> Result<PromotionResult, Failure> {
        let (key, fingerprint) = command_receipt_key(&result.identity);
        let workspace_id = result.artifact.workspace_id;
        let artifact_id = result.artifact.artifact_id;

        let mut tx = begin_tx(&self.pool).await?;
        let existing = lookup_artifact_receipt(&mut tx, workspace_id, "promote", &key).await?;
        if existing.found {
            if existing.fingerprint != fingerprint {
                return Err(fingerprint_mismatch());
            }
            let row = read_artifact(&mut *tx, workspace_id, artifact_id).await?;
            let stored = to_domain_artifact(&row);
            tx.commit().await.map_err(|e| classify_sqlx(&e))?;
            return Ok(PromotionResult {
                artifact: stored,
                identity: result.identity,
            });
        }

        let row = read_artifact_for_update(&mut tx, workspace_id, artifact_id).await?;
        if row.version != result.identity.expected_version {
            return Err(conflict("VERSION_CONFLICT"));
        }
        if row.state != State::Verifying {
            return Err(conflict("INVALID_TRANSITION"));
        }
        if !row.ready_key.is_empty() {
            return Err(conflict("READY_KEY_ALREADY_ASSIGNED"));
        }

        let done = sqlx::query!(
            "UPDATE central.artifacts \
             SET version = $3, content_generation = $4, ready_key = $5, \
             updated_at = clock_timestamp() \
             WHERE workspace_id = $1 AND id = $2 AND version = $6",
            uuid_of(workspace_id.as_bytes()),
            uuid_of(artifact_id.as_bytes()),
            result.artifact.version,
            opt_uuid_of(result.artifact.content_generation, |id| id.as_bytes()),
            result.artifact.ready_key.as_str(),
            row.version,
        )
        .execute(&mut *tx)
        .await
        .ctx("artifact: update artifact promotion")?
        .rows_affected();
        if done != 1 {
            return Err(conflict("VERSION_CONFLICT"));
        }

        insert_artifact_receipt(
            &mut tx,
            workspace_id,
            artifact_id,
            "promote",
            &key,
            fingerprint,
            stage_payload("promote"),
        )
        .await?;
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(result)
    }

    /// `RecordRejection` — persists an already pure-evaluated reject and
    /// releases the reservation exactly once, following the same
    /// receipt-replay discipline as every other command stage.
    async fn record_rejection(&self, result: RejectResult) -> Result<RejectResult, Failure> {
        if result.artifact.state != State::Rejected
            || result.identity.stage != central_artifact::domain::CommandStage::Reject
            || result.identity.failure_code.is_empty()
            || result.identity.failure_code != result.outcome.failure_code
        {
            return Err(invalid("INVALID_REJECT_RESULT"));
        }
        let (key, fingerprint) = command_receipt_key(&result.identity);
        let workspace_id = result.artifact.workspace_id;
        let artifact_id = result.artifact.artifact_id;

        let mut tx = begin_tx(&self.pool).await?;
        let existing = lookup_artifact_receipt(&mut tx, workspace_id, "reject", &key).await?;
        if existing.found {
            if existing.fingerprint != fingerprint {
                return Err(fingerprint_mismatch());
            }
            let row = read_artifact(&mut *tx, workspace_id, artifact_id).await?;
            let outcome = outcome_from_row(&row).unwrap_or(Outcome {
                kind: OutcomeKind::Terminal,
                failure_code: String::new(),
            });
            let stored = to_domain_artifact(&row);
            tx.commit().await.map_err(|e| classify_sqlx(&e))?;
            return Ok(RejectResult {
                artifact: stored,
                identity: result.identity,
                outcome,
            });
        }

        let row = read_artifact_for_update(&mut tx, workspace_id, artifact_id).await?;
        if row.version != result.identity.expected_version {
            return Err(conflict("VERSION_CONFLICT"));
        }
        if row.state != State::Reserved && row.state != State::Staging {
            return Err(conflict("INVALID_TRANSITION"));
        }

        // The version guard makes the rejection — and therefore the
        // single capacity release paired with it — exactly-once: a
        // replayed call finds the version already advanced and affects
        // zero rows. The state predicate is defence in depth.
        let rejection = serde_json::json!({"code": result.outcome.failure_code.as_str()});
        let done = sqlx::query!(
            "UPDATE central.artifacts \
             SET version = $3, state = 'rejected', rejection = $4::jsonb, \
             updated_at = clock_timestamp() \
             WHERE workspace_id = $1 AND id = $2 AND version = $5 \
             AND state IN ('reserved', 'staging')",
            uuid_of(workspace_id.as_bytes()),
            uuid_of(artifact_id.as_bytes()),
            result.artifact.version,
            rejection,
            row.version,
        )
        .execute(&mut *tx)
        .await
        .ctx("artifact: reject artifact")?
        .rows_affected();
        if done != 1 {
            return Err(conflict("VERSION_CONFLICT"));
        }
        release_capacity_reservation(&mut tx, workspace_id, artifact_id).await?;

        insert_artifact_receipt(
            &mut tx,
            workspace_id,
            artifact_id,
            "reject",
            &key,
            fingerprint,
            outcome_payload(&result.outcome),
        )
        .await?;
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(result)
    }

    /// `LoadArtifact` — the current durable snapshot for one Artifact.
    /// A plain unlocked read: it takes no row lock and applies no
    /// transition; callers still submit intended transitions through the
    /// command-stage methods, which re-read the row `FOR UPDATE`.
    async fn load_artifact(
        &self,
        workspace_id: WorkspaceId,
        artifact_id: ArtifactId,
    ) -> Result<Artifact, Failure> {
        if workspace_id.is_nil() || artifact_id.is_nil() {
            return Err(invalid("INVALID_ARTIFACT_SELECTOR"));
        }
        let row = read_artifact(&self.pool, workspace_id, artifact_id).await?;
        Ok(to_domain_artifact(&row))
    }
}

impl TwoPhaseDeleteStore for Store {
    /// Persists the domain-evaluated `delete_pending` snapshot. The
    /// version-and-state revalidation under the row lock is what makes
    /// delete intent win any uncommitted finalization; a retry of the
    /// same intent returns the durable snapshot, never a second
    /// transition.
    async fn mark_delete_pending(&self, next: Artifact) -> Result<Artifact, Failure> {
        let workspace_id = next.workspace_id;
        let artifact_id = next.artifact_id;
        let mut tx = begin_tx(&self.pool).await?;
        let row = read_artifact_for_update(&mut tx, workspace_id, artifact_id).await?;

        // Replay: the intent already committed at this version — return
        // the durable snapshot rather than transitioning again.
        let replayed = row.state == State::DeletePending && row.version == next.version;
        if !replayed {
            if row.version != next.version - 1 {
                return Err(conflict("VERSION_CONFLICT"));
            }
            if row.state != State::Ready {
                return Err(conflict("INVALID_TRANSITION"));
            }
            // `COALESCE(delete_intent_at, clock_timestamp())` keeps the
            // first durable intent stamp if one was ever written.
            let done = sqlx::query!(
                "UPDATE central.artifacts \
                 SET state = 'delete_pending', \
                 delete_intent_at = COALESCE(delete_intent_at, clock_timestamp()), \
                 version = version + 1, updated_at = clock_timestamp() \
                 WHERE workspace_id = $1 AND id = $2 AND version = $3 \
                 AND state = 'ready'",
                uuid_of(workspace_id.as_bytes()),
                uuid_of(artifact_id.as_bytes()),
                row.version,
            )
            .execute(&mut *tx)
            .await
            .ctx("artifact: mark artifact delete pending")?
            .rows_affected();
            if done != 1 {
                return Err(conflict("VERSION_CONFLICT"));
            }
        }
        let stored = to_domain_artifact(&read_artifact(&mut *tx, workspace_id, artifact_id).await?);
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(stored)
    }

    /// Atomically persists the `deleted` transition and its tombstone in
    /// one commit. A replay under the same artifact identity returns the
    /// journaled settlement (`replayed`) — never a second tombstone or a
    /// second quota release. The tombstone INSERT deliberately runs
    /// under owner authority: `central_runtime` holds only `SELECT` on
    /// `central.artifact_tombstones`.
    async fn complete_deletion_with_tombstone(
        &self,
        next: Artifact,
        tombstone: ArtifactTombstone,
    ) -> Result<TwoPhaseDeleteResult, Failure> {
        let workspace_id = next.workspace_id;
        let artifact_id = next.artifact_id;
        let mut tx = begin_tx(&self.pool).await?;

        // 1. Lock the quota ledger before the artifact row — the same
        //    order the completion commit takes them.
        if lock_workspace_quota(&mut tx, workspace_id).await?.is_none() {
            return Err(invalid("WORKSPACE_NOT_FOUND"));
        }
        // 2. Lock the artifact row.
        let row = read_artifact_for_update(&mut tx, workspace_id, artifact_id).await?;

        if row.state == State::Deleted {
            // Replay: the settlement already committed; return the
            // journaled tombstone rather than writing a second one. A
            // deleted record without its tombstone violates the pairing
            // invariant — corrupt durable state, not a conflict.
            let Some(journaled) = read_tombstone(&mut tx, workspace_id, artifact_id).await? else {
                return Err(corrupt(
                    "a deleted artifacts row is missing its artifact_tombstones journal",
                ));
            };
            let stored =
                to_domain_artifact(&read_artifact(&mut *tx, workspace_id, artifact_id).await?);
            tx.commit().await.map_err(|e| classify_sqlx(&e))?;
            return Ok(TwoPhaseDeleteResult {
                artifact: stored,
                tombstone: journaled,
                replayed: true,
            });
        }
        if row.version != next.version - 1 {
            return Err(conflict("VERSION_CONFLICT"));
        }
        if row.state != State::DeletePending && row.state != State::Ready {
            return Err(conflict("INVALID_TRANSITION"));
        }

        // `artifact_tombstones_artifact_id_unique` makes the journal
        // append exactly-once: `DO NOTHING` on a same-identity retry,
        // then the existing row is the journaled settlement.
        let inserted = sqlx::query!(
            "INSERT INTO central.artifact_tombstones (\
             id, workspace_id, artifact_id, object_key, staging_generation, \
             checksum_algorithm, checksum_value, size_at_deletion, deletion_reason) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (workspace_id, artifact_id) DO NOTHING",
            uuid_of(tombstone.id.as_bytes()),
            uuid_of(workspace_id.as_bytes()),
            uuid_of(artifact_id.as_bytes()),
            tombstone.object_key.as_str(),
            uuid_of(tombstone.staging_generation.as_bytes()),
            tombstone.checksum_algorithm.as_deref(),
            tombstone.checksum_value.as_ref().map(|value| &value[..]),
            tombstone.size_at_deletion,
            tombstone.deletion_reason.as_str(),
        )
        .execute(&mut *tx)
        .await
        .ctx("artifact: insert artifact tombstone")?
        .rows_affected();
        let journaled = if inserted == 1 {
            tombstone
        } else {
            read_tombstone(&mut tx, workspace_id, artifact_id)
                .await?
                .ok_or_else(|| corrupt("artifact_tombstones conflict left no journaled row"))?
        };

        let done = sqlx::query!(
            "UPDATE central.artifacts \
             SET state = 'deleted', deleted_at = clock_timestamp(), \
             version = version + 1, updated_at = clock_timestamp() \
             WHERE workspace_id = $1 AND id = $2 AND version = $3 \
             AND state <> 'deleted'",
            uuid_of(workspace_id.as_bytes()),
            uuid_of(artifact_id.as_bytes()),
            row.version,
        )
        .execute(&mut *tx)
        .await
        .ctx("artifact: transition artifact to deleted")?
        .rows_affected();
        if done != 1 {
            return Err(conflict("VERSION_CONFLICT"));
        }

        // Release the retained quota exactly once — this arm is reached
        // only on the non-replayed settlement.
        sqlx::query!(
            "UPDATE central.workspaces \
             SET quota_ready_bytes = GREATEST(0, quota_ready_bytes - $2), \
             quota_ready_count = GREATEST(0, quota_ready_count - 1), \
             updated_at = clock_timestamp() \
             WHERE id = $1",
            uuid_of(workspace_id.as_bytes()),
            journaled.size_at_deletion,
        )
        .execute(&mut *tx)
        .await
        .ctx("artifact: release workspace quota")?;

        let stored = to_domain_artifact(&read_artifact(&mut *tx, workspace_id, artifact_id).await?);
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(TwoPhaseDeleteResult {
            artifact: stored,
            tombstone: journaled,
            replayed: false,
        })
    }

    /// `SELECT EXISTS` — the tombstone-existence probe a retried
    /// settlement consults before attempting a second commit.
    async fn has_tombstone(
        &self,
        workspace_id: WorkspaceId,
        artifact_id: ArtifactId,
    ) -> Result<bool, Failure> {
        let row = sqlx::query!(
            "SELECT EXISTS(\
             SELECT 1 FROM central.artifact_tombstones \
             WHERE workspace_id = $1 AND artifact_id = $2\
             ) AS \"exists!\"",
            uuid_of(workspace_id.as_bytes()),
            uuid_of(artifact_id.as_bytes()),
        )
        .fetch_one(&self.pool)
        .await
        .ctx("artifact: probe tombstone")?;
        Ok(row.exists)
    }
}

impl ArtifactSummaryRead for Store {
    /// Bounded `(updated_at DESC, id DESC)` keyset page over
    /// `artifacts_task_id_idx` — `LIMIT page_size + 1` prices
    /// `next_cursor` in one round trip (the adapter's convention from
    /// `authorization::read_page`).
    async fn list_artifacts(
        &self,
        request: &ArtifactListRequest,
    ) -> Result<ArtifactListProjection, Failure> {
        validate_artifact_list_request(request)?;
        let limit = usize_as_i64(normalize_artifact_page_size(request.page_size) as usize);
        let cursor_at = request.cursor.map(|cursor| cursor.updated_at);
        let cursor_id = request
            .cursor
            .map(|cursor| uuid_of(cursor.artifact_id.as_bytes()));

        let mut rows = sqlx::query!(
            "SELECT id, task_id, run_id, state, sensitivity, disposition, \
             detected_media_type, size, \
             COALESCE(required_role, '') AS \"required_role!\", \
             COALESCE(producer_id, '') AS \"producer_id!\", \
             created_at, updated_at, ready_at \
             FROM central.artifacts \
             WHERE workspace_id = $1 AND task_id = $2 \
             AND ($3::timestamptz IS NULL OR (updated_at, id) < ($3, $4::uuid)) \
             ORDER BY updated_at DESC, id DESC \
             LIMIT $5",
            uuid_of(request.workspace_id.as_bytes()),
            uuid_of(request.task_id.as_bytes()),
            cursor_at,
            cursor_id,
            limit + 1,
        )
        .fetch_all(&self.pool)
        .await
        .ctx("artifact: list artifact summaries")?;

        let has_more = rows.len() > limit as usize;
        if has_more {
            rows.pop();
        }
        let mut artifacts = Vec::with_capacity(rows.len());
        for row in rows {
            let state = State::parse(&row.state)
                .ok_or_else(|| corrupt("an artifacts.state is outside the closed vocabulary"))?;
            let sensitivity = central_artifact::domain::Sensitivity::parse(&row.sensitivity)
                .ok_or_else(|| corrupt("an artifacts.sensitivity is outside the closed set"))?;
            let disposition = central_artifact::domain::Disposition::parse(&row.disposition)
                .ok_or_else(|| corrupt("an artifacts.disposition is outside the closed set"))?;
            artifacts.push(ArtifactSummaryView {
                artifact_id: ArtifactId::from_trusted_db_bytes(*row.id.as_bytes()),
                task_id: central_foundation::identity::TaskId::from_trusted_db_bytes(
                    *row.task_id.as_bytes(),
                ),
                run_id: central_foundation::identity::RunId::from_trusted_db_bytes(
                    *row.run_id.as_bytes(),
                ),
                state,
                sensitivity,
                disposition,
                media_type: row.detected_media_type,
                verified_size: row.size,
                required_role: row.required_role,
                producer_id: row.producer_id,
                created_at: row.created_at,
                updated_at: row.updated_at,
                ready_at: row.ready_at,
            });
        }
        let next_cursor = if has_more {
            artifacts.last().map(|last| ArtifactSeekCursor {
                updated_at: last.updated_at,
                artifact_id: last.artifact_id,
            })
        } else {
            None
        };
        Ok(ArtifactListProjection {
            artifacts,
            next_cursor,
        })
    }
}
