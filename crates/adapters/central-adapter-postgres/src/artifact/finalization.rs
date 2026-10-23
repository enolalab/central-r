//! `central-artifact::port::AttemptFinalizationStore` — the spec-5
//! §5 single visibility boundary, ported from
//! `internal/adapter/postgres/artifact/finalize.go`
//! (`FinalizeAttemptArtifact`).
//!
//! The object-store write and the checksum verify have already
//! happened upstream of this call — this method's ONE transaction is
//! step (c) of the contract: the `artifact_finalizations` key row, the
//! artifacts row's `verifying` → `ready` transition, the journaled
//! produce edge, and the `artifact_finalized` run event with its
//! `event_outbox` row, committed atomically.
//!
//! This is deliberately NOT the B10 `CompletionContributor` path:
//! `CommitArtifact` is the Phase-1 receipt-dedup finalize keyed
//! `(workspace, finalize, receipt key)` that also settles
//! `ExecutionChangeSet`s. `finalize_attempt_artifact` is keyed
//! `(attempt_id, artifact_name)` on `central.artifact_finalizations`
//! and touches no Phase-1 execution rows; both converge on the same
//! `artifacts.ready` transition `artifacts_ready_requires_metadata_b10_check`
//! pins (`ready_key`, `content_generation`, `checksum_value` all
//! present — the B10 verify+promote stages must already have recorded
//! them).
//!
//! The capability hands over an [`AttemptFinalization`] change set —
//! the artifact, attempt, run, and node identities plus the bound
//! `content_generation` — and this adapter re-validates every
//! coordinate against durable state inside the transaction (the
//! attempt's durable `run_id`/`node_id` against the claimed ones; the
//! artifact row's `workspace_id`/`run_id`/`required_role`/
//! `content_generation`/`checksum_value` against the attempt's
//! coordinates and the caller's binding). The run-event envelopes are
//! built from `central-eventjournal` domain types here, at the adapter
//! boundary — `central-artifact` itself imports no journal types.

use central_artifact::domain::State;
use central_artifact::lineage::AttemptFinalization;
use central_artifact::port::AttemptFinalizationStore;
use central_eventjournal::domain::{EventKind, RunEvent};
use central_foundation::failure::Failure;
use central_foundation::identity::{ArtifactId, ProduceEdgeId, RunEventId};
use sqlx::{Postgres, Transaction};
use time::OffsetDateTime;

use super::store::Store;
use super::{conflict, denied, invalid};
use crate::error::SqlxContext;
use crate::store_support::{begin_tx, uuid_of};

/// `actorFinalize` — the `artifact_finalized` event journals under the
/// scheduler actor class: the finalize boundary is driven by the
/// attempt-outcome path the scheduler owns (the spec-6 actor vocabulary
/// has no artifact-domain emitter).
const ACTOR_FINALIZE: &str = "scheduler";

/// `OffsetDateTime::UNIX_EPOCH` is the domain envelope's documented
/// "no timestamp" sentinel: the writer's `COALESCE($10, now())` stamps
/// the commit-time `recorded_at` — the same contract
/// `eventjournal::append_tx` documents.
const NO_RECORDED_AT: OffsetDateTime = OffsetDateTime::UNIX_EPOCH;

/// The attempt row's durable coordinates — `run_id`, `node_id`,
/// `workspace_id` are immutable (`attempt_seq` is the only identity a
/// retry changes), so a plain read suffices; the run-row lock taken
/// right after is what serializes this run's finalize against every
/// other journal writer.
struct AttemptCoordinates {
    run_id: sqlx::types::Uuid,
    node_id: sqlx::types::Uuid,
    workspace_id: sqlx::types::Uuid,
}

/// Locks and returns the producing attempt's durable coordinates;
/// `ATTEMPT_NOT_FOUND` when no `session_attempts` row names the id
/// (upstream `queryLockSessionAttempt` + the `pgx.ErrNoRows` branch).
async fn attempt_coordinates(
    tx: &mut Transaction<'_, Postgres>,
    change: &AttemptFinalization,
) -> Result<AttemptCoordinates, Failure> {
    let row = sqlx::query!(
        "SELECT run_id, node_id, workspace_id \
         FROM central.session_attempts \
         WHERE id = $1",
        uuid_of(change.attempt_id.as_bytes()),
    )
    .fetch_optional(&mut **tx)
    .await
    .ctx("artifact: read session attempt")?;
    let Some(row) = row else {
        return Err(conflict("ATTEMPT_NOT_FOUND"));
    };
    // The change set carries the caller's claim of the attempt's
    // run/node so the commit can re-validate it against durable state:
    // a mid-flight snapshot that disagrees with the durable attempt row
    // is the same closed verdict upstream assigns the artifact-side
    // producer chain (`PRODUCER_CHAIN_MISMATCH`).
    if row.run_id != uuid_of(change.run_id.as_bytes())
        || row.node_id != uuid_of(change.node_id.as_bytes())
    {
        return Err(denied("PRODUCER_CHAIN_MISMATCH"));
    }
    Ok(AttemptCoordinates {
        run_id: row.run_id,
        node_id: row.node_id,
        workspace_id: row.workspace_id,
    })
}

/// The `(attempt_id, artifact_name)` idempotency gate (upstream
/// `queryInsertFinalization`): a fresh insert returns `None` for the
/// caller to continue the fresh-finalize path; a conflict selects the
/// recorded row, where an equal checksum replays to the recorded
/// artifact id and a different checksum is
/// `ARTIFACT_ALREADY_FINALIZED`.
enum FinalizationKey {
    /// The key row was inserted by this transaction; continue.
    Fresh,
    /// The key row already existed with an equal checksum — the
    /// replayed commit journals `command_deduped` and returns the
    /// recorded artifact id.
    Replay(ArtifactId),
}

/// Inserts the `artifact_finalizations` key row, resolving a PK
/// conflict to the recorded row (upstream `queryInsertFinalization` +
/// `querySelectFinalization`).
async fn insert_finalization_key(
    tx: &mut Transaction<'_, Postgres>,
    change: &AttemptFinalization,
) -> Result<FinalizationKey, Failure> {
    let inserted = sqlx::query_scalar!(
        "INSERT INTO central.artifact_finalizations \
            (attempt_id, artifact_name, artifact_id, checksum, payload_fingerprint) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (attempt_id, artifact_name) DO NOTHING \
         RETURNING artifact_id",
        uuid_of(change.attempt_id.as_bytes()),
        change.artifact_name,
        uuid_of(change.artifact_id.as_bytes()),
        &change.checksum[..],
        &change.payload_fingerprint[..],
    )
    .fetch_optional(&mut **tx)
    .await
    .ctx("artifact: insert finalization key")?;
    if inserted.is_some() {
        return Ok(FinalizationKey::Fresh);
    }

    let recorded = sqlx::query!(
        "SELECT artifact_id, checksum \
         FROM central.artifact_finalizations \
         WHERE attempt_id = $1 AND artifact_name = $2",
        uuid_of(change.attempt_id.as_bytes()),
        change.artifact_name,
    )
    .fetch_one(&mut **tx)
    .await
    .ctx("artifact: read recorded finalization")?;
    if recorded.checksum != change.checksum.as_slice() {
        // A different checksum under the same key is the spec's
        // ARTIFACT_ALREADY_FINALIZED verdict — nothing new becomes
        // visible and the recorded row stands.
        return Err(conflict("ARTIFACT_ALREADY_FINALIZED"));
    }
    Ok(FinalizationKey::Replay(ArtifactId::from_trusted_db_bytes(
        *recorded.artifact_id.as_bytes(),
    )))
}

/// The metadata the ready transition needs, read under the artifact
/// row lock (upstream `queryLockArtifactForFinalize`): state, version,
/// the stored checksum the caller must match, the promotion fields the
/// ready CHECK requires, and the producer chain the finalize verifies
/// against the attempt's own coordinates.
struct LockedArtifact {
    workspace_id: sqlx::types::Uuid,
    run_id: sqlx::types::Uuid,
    state: String,
    version: i64,
    checksum_value: Option<Vec<u8>>,
    ready_key: String,
    content_generation: Option<sqlx::types::Uuid>,
    required_role: String,
    size: i64,
}

/// Locks the artifact row `FOR UPDATE` and re-validates every bound
/// coordinate of the change set — `ARTIFACT_NOT_FOUND`,
/// `PRODUCER_CHAIN_MISMATCH`, `INVALID_TRANSITION`, and
/// `ARTIFACT_CHECKSUM_MISMATCH` are the upstream verdicts; the
/// `content_generation` equality check is the change-set binding
/// revalidation the Rust port adds (a stale promotion binding can never
/// legitimately finalize, and the recorded generation cannot change
/// post-promotion under the row lock).
async fn lock_and_validate_artifact(
    tx: &mut Transaction<'_, Postgres>,
    coordinates: &AttemptCoordinates,
    change: &AttemptFinalization,
) -> Result<LockedArtifact, Failure> {
    let row = sqlx::query!(
        "SELECT workspace_id, run_id, state, version, \
                checksum_value, COALESCE(ready_key, '') AS \"ready_key!\", \
                content_generation, COALESCE(required_role, '') AS \"required_role!\", size \
         FROM central.artifacts \
         WHERE id = $1 \
         FOR UPDATE",
        uuid_of(change.artifact_id.as_bytes()),
    )
    .fetch_optional(&mut **tx)
    .await
    .ctx("artifact: lock artifact row")?;
    let Some(row) = row else {
        return Err(conflict("ARTIFACT_NOT_FOUND"));
    };
    let artifact = LockedArtifact {
        workspace_id: row.workspace_id,
        run_id: row.run_id,
        state: row.state,
        version: row.version,
        checksum_value: row.checksum_value,
        ready_key: row.ready_key,
        content_generation: row.content_generation,
        required_role: row.required_role,
        size: row.size,
    };
    if artifact.workspace_id != coordinates.workspace_id
        || artifact.run_id != coordinates.run_id
        || artifact.required_role != change.artifact_name
    {
        return Err(denied("PRODUCER_CHAIN_MISMATCH"));
    }
    if artifact.state != State::Verifying.as_str() {
        return Err(conflict("INVALID_TRANSITION"));
    }
    if artifact.ready_key.is_empty() || artifact.content_generation.is_none() {
        return Err(conflict("INVALID_TRANSITION"));
    }
    if artifact.content_generation != Some(uuid_of(change.content_generation.as_bytes())) {
        return Err(conflict("INVALID_TRANSITION"));
    }
    if artifact.checksum_value.as_deref() != Some(change.checksum.as_slice()) {
        return Err(conflict("ARTIFACT_CHECKSUM_MISMATCH"));
    }
    Ok(artifact)
}

impl AttemptFinalizationStore for Store {
    /// `FinalizeAttemptArtifact` — one transaction, in the upstream
    /// lock order (attempt read → run lock → artifact exists → key row
    /// → artifact row lock → ready transition → produce edge → journal
    /// append → commit).
    async fn finalize_attempt_artifact(
        &self,
        change: AttemptFinalization,
    ) -> Result<ArtifactId, Failure> {
        // The adapter re-validates the already pure-evaluated change
        // set — the same guard the capability ran, closing the
        // untrusted-caller path around the service.
        if change.attempt_id.is_nil()
            || change.artifact_id.is_nil()
            || change.run_id.is_nil()
            || change.node_id.is_nil()
            || change.artifact_name.is_empty()
            || change.content_generation.is_nil()
        {
            return Err(invalid("INVALID_FINALIZE_INPUT"));
        }

        let mut tx = begin_tx(&self.pool).await?;

        let coordinates = attempt_coordinates(&mut tx, &change).await?;

        // Lock the run row before any other mutation — the same first
        // lock `eventjournal::append_tx` takes, so this path's order
        // (run → artifact → key row) never inverts against the
        // scheduler's run → node → attempt ladder.
        sqlx::query_scalar!(
            "SELECT id FROM central.runs WHERE id = $1 FOR UPDATE",
            coordinates.run_id
        )
        .fetch_one(&mut *tx)
        .await
        .ctx("artifact: lock run row")?;

        // Existence pre-check so the key row's artifacts FK never
        // surfaces as a bare 23503: a missing artifact is the typed
        // ARTIFACT_NOT_FOUND.
        let exists = sqlx::query_scalar!(
            "SELECT 1 FROM central.artifacts WHERE id = $1",
            uuid_of(change.artifact_id.as_bytes()),
        )
        .fetch_optional(&mut *tx)
        .await
        .ctx("artifact: check artifact exists")?;
        if exists.is_none() {
            return Err(conflict("ARTIFACT_NOT_FOUND"));
        }

        match insert_finalization_key(&mut tx, &change).await? {
            FinalizationKey::Fresh => {}
            FinalizationKey::Replay(recorded_id) => {
                // The replay is observable (OQ-4): `command_deduped`
                // joins this same transaction, then the recorded
                // artifact id answers.
                crate::eventjournal::append_tx(
                    &mut tx,
                    &RunEvent {
                        id: RunEventId::new(),
                        workspace_id:
                            central_foundation::identity::WorkspaceId::from_trusted_db_bytes(
                                *coordinates.workspace_id.as_bytes(),
                            ),
                        run_id: central_foundation::identity::RunId::from_trusted_db_bytes(
                            *coordinates.run_id.as_bytes(),
                        ),
                        seq: 0,
                        node_id: Some(
                            central_foundation::identity::WorkflowNodeId::from_trusted_db_bytes(
                                *coordinates.node_id.as_bytes(),
                            ),
                        ),
                        attempt_id: Some(change.attempt_id),
                        kind: EventKind::CommandDeduped.as_str().to_owned(),
                        actor: ACTOR_FINALIZE.to_owned(),
                        reason_code: None,
                        payload: serde_json::json!({
                            "command": "finalize_artifact",
                            "artifact_name": change.artifact_name,
                            "attempt_id": change.attempt_id.to_string(),
                            "artifact_id": recorded_id.to_string(),
                        }),
                        recorded_at: NO_RECORDED_AT,
                    },
                )
                .await?;
                tx.commit().await.ctx("artifact: commit finalize replay")?;
                return Ok(recorded_id);
            }
        }

        // Fresh finalize: verify the artifact row this key now names
        // (the row lock serializes against any concurrent transition
        // attempt).
        let artifact = lock_and_validate_artifact(&mut tx, &coordinates, &change).await?;

        // `queryFinalizeAttemptArtifact` — the B10 ready invariants in
        // the WHERE clause, not just in Rust: the version guard makes
        // the transition exactly-once, the state + checksum predicates
        // make a concurrent or mismatched caller affect zero rows, and
        // `artifacts_ready_requires_metadata_b10_check` still
        // independently verifies the promotion fields the caller proved
        // non-empty above.
        let done = sqlx::query!(
            "UPDATE central.artifacts \
             SET version = version + 1, state = 'ready', \
                 ready_at = clock_timestamp(), updated_at = clock_timestamp() \
             WHERE id = $1 AND version = $2 \
               AND state = 'verifying' AND checksum_value = $3",
            uuid_of(change.artifact_id.as_bytes()),
            artifact.version,
            &change.checksum[..],
        )
        .execute(&mut *tx)
        .await
        .ctx("artifact: finalize artifact")?
        .rows_affected();
        if done != 1 {
            return Err(conflict("VERSION_CONFLICT"));
        }

        // The produce edge joins this same transaction (the plan's T5
        // note: `insert_produce_edge`'s own-commit form cannot, so this
        // is its tx-scoped equivalent). A conflicting `artifact_id`
        // means the artifact was already finalized under a different
        // attempt — the finalization key rolls back with the
        // transaction.
        let edge_inserted = sqlx::query_scalar!(
            "INSERT INTO central.artifact_produce_edges \
                (id, run_id, node_id, attempt_id, artifact_id) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (artifact_id) DO NOTHING \
             RETURNING id",
            uuid_of(ProduceEdgeId::new().as_bytes()),
            coordinates.run_id,
            coordinates.node_id,
            uuid_of(change.attempt_id.as_bytes()),
            uuid_of(change.artifact_id.as_bytes()),
        )
        .fetch_optional(&mut *tx)
        .await
        .ctx("artifact: insert produce edge")?;
        if edge_inserted.is_none() {
            let edge_attempt = sqlx::query_scalar!(
                "SELECT attempt_id FROM central.artifact_produce_edges WHERE artifact_id = $1",
                uuid_of(change.artifact_id.as_bytes()),
            )
            .fetch_one(&mut *tx)
            .await
            .ctx("artifact: read recorded produce edge")?;
            if edge_attempt != uuid_of(change.attempt_id.as_bytes()) {
                return Err(conflict("ARTIFACT_ALREADY_FINALIZED"));
            }
        }

        // `artifact_finalized` — the spec-7 declared row: the event and
        // its `event_outbox` row land in this commit via the shared
        // journal append.
        crate::eventjournal::append_tx(
            &mut tx,
            &RunEvent {
                id: RunEventId::new(),
                workspace_id: central_foundation::identity::WorkspaceId::from_trusted_db_bytes(
                    *coordinates.workspace_id.as_bytes(),
                ),
                run_id: central_foundation::identity::RunId::from_trusted_db_bytes(
                    *coordinates.run_id.as_bytes(),
                ),
                seq: 0,
                node_id: Some(
                    central_foundation::identity::WorkflowNodeId::from_trusted_db_bytes(
                        *coordinates.node_id.as_bytes(),
                    ),
                ),
                attempt_id: Some(change.attempt_id),
                kind: EventKind::ArtifactFinalized.as_str().to_owned(),
                actor: ACTOR_FINALIZE.to_owned(),
                reason_code: None,
                payload: serde_json::json!({
                    "payload_version": 1,
                    "artifact_id": change.artifact_id.to_string(),
                    "artifact_name": change.artifact_name,
                    "run_id": change.run_id.to_string(),
                    "node_id": change.node_id.to_string(),
                    "attempt_id": change.attempt_id.to_string(),
                    "checksum": hex_checksum(&change.checksum),
                    "size": artifact.size,
                }),
                recorded_at: NO_RECORDED_AT,
            },
        )
        .await?;

        tx.commit().await.ctx("artifact: commit finalize")?;
        Ok(change.artifact_id)
    }
}

/// `hex.EncodeToString` — the payload's lowercase hex body digest.
fn hex_checksum(checksum: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    checksum
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}
