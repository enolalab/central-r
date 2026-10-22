//! `central-artifact::port::CompletionContributor` — the atomic
//! finalize-plus-execution-completion transaction, ported from
//! `internal/adapter/postgres/artifact/store.go`'s `CommitArtifact`.
//!
//! One PostgreSQL transaction applies, in the documented lock order:
//! `workspace_event_counters` → `workspaces` quota (`FOR NO KEY
//! UPDATE`) → `tasks` → `runs` → `execution_ownership` (the B08 lease
//! fence) → `steps` → `step_attempts` → `artifacts` →
//! `capacity_reservations`, then the artifact's `ready` transition, the
//! reservation settle, the quota charge, the task/run/step/attempt
//! mutations, every event + outbox row, and the `"finalize"` receipt.
//! An exact replay under a retained receipt returns `replayed` with no
//! duplicate effects; a superseded lease fails `STALE_LEASE_FENCE` and
//! commits nothing.
//!
//! `b10_supported_execution_change` bounds the execution change set
//! this path will apply: B10's finalize contribution only ever settles
//! one existing `StepAttempt`/`Step` and advances the owning
//! Task/Run — it never prepares, claims, or settles Tool calls,
//! records Approvals or Checkpoints, grants Leases, or resolves
//! Reconciliation. A settlement requires exactly one lease release
//! naming the settled run (the only fence this path can check — the
//! B12 SB-G5 live observation); a change set with no settlement is the
//! reconciler's artifact-only finalize and must carry no release.

use std::collections::{BTreeMap, BTreeSet};

use central_artifact::domain::{Outcome, OutcomeKind, State};
use central_artifact::port::{ArtifactChangeSet, CommitResult, CompletionContributor};
use central_execution::domain::{ExecutionChangeSet, Settlement, build_execution_change_set};
use central_foundation::failure::Failure;
use central_foundation::identity::{StepAttemptId, WorkspaceId};
use central_task::domain::TaskChangeSet;
use sqlx::{Postgres, Transaction};

use super::queries::{
    canonical_identity_hash, fingerprint_mismatch, insert_artifact_receipt,
    lock_capacity_reservation, lock_workspace_quota, lookup_artifact_receipt,
    read_artifact_for_update,
};
use super::store::{Store, outcome_payload};
use super::{conflict, denied, invalid};
use crate::error::{SqlxContext, classify_sqlx};
use crate::execution::{
    self, go_json_escapes, go_rfc3339_local, invocation_generation, lock_event_counter,
    opt_attempt_uuid, opt_run_uuid, opt_step_uuid, reserve_event_sequence, sha256,
    uuid_for_invocation, wait_reason_value,
};
use crate::store_support::{opt_uuid_of, uuid_of};

/// `b10SupportedExecutionChange` — the closed shape gate. See the
/// module doc: settling shapes need exactly one settlement + one
/// lease release in the same `(workspace_id, run_id)`; empty is the
/// reconciler's artifact-only finalize.
fn b10_supported_execution_change(change: &ExecutionChangeSet) -> Result<(), Failure> {
    if !change.tool_calls.is_empty()
        || !change.tool_attempts.is_empty()
        || !change.tool_settlements.is_empty()
        || !change.approvals.is_empty()
        || !change.checkpoints.is_empty()
        || !change.leases.is_empty()
        || !change.lease_assertions.is_empty()
        || !change.reconciliations.is_empty()
        || !change.attempt_assertions.is_empty()
    {
        return Err(invalid("UNSUPPORTED_EXECUTION_CHANGE"));
    }
    if change.attempts.len() != change.settlements.len() {
        return Err(invalid("UNSUPPORTED_EXECUTION_CHANGE"));
    }
    if change.settlements.is_empty() {
        if !change.lease_releases.is_empty() {
            return Err(invalid("UNSUPPORTED_EXECUTION_CHANGE"));
        }
        return Ok(());
    }
    // Exactly one settlement, so the scope comparison below covers
    // every settlement this change set carries rather than only the
    // first (upstream: executionapp already refuses non-1 cardinality).
    if change.settlements.len() != 1 {
        return Err(invalid("UNSUPPORTED_EXECUTION_CHANGE"));
    }
    if change.lease_releases.len() != 1 {
        return Err(invalid("COMPLETION_LEASE_FENCE_REQUIRED"));
    }
    let release = &change.lease_releases[0];
    let settlement = &change.settlements[0];
    if release.workspace_id != settlement.workspace_id || release.run_id != settlement.run_id {
        return Err(denied("PRODUCER_CHAIN_MISMATCH"));
    }
    Ok(())
}

/// `fenceCompletionLease` — releases the completing pass's B08 lease
/// under its own fence: byte-for-byte the predicate the execution
/// adapter's own `queryReleaseLease` uses — stored token hash, fencing
/// generation, and an unexpired lease all have to match. Zero rows
/// affected means "you are not the current owner" — exactly the
/// refusal a superseded pass must get.
async fn fence_completion_lease(
    tx: &mut Transaction<'_, Postgres>,
    change: &ExecutionChangeSet,
) -> Result<(), Failure> {
    if change.lease_releases.is_empty() {
        return Ok(());
    }
    let release = &change.lease_releases[0];
    let verifier = sha256(&release.credential.0);
    let done = sqlx::query!(
        "UPDATE central.execution_ownership \
         SET claimed_run_id = run_id, claimed_step_id = NULL, \
         claimed_step_attempt_id = NULL, owner_scope = NULL, owner_identity = NULL, \
         heartbeat_at = clock_timestamp(), lease_expires_at = clock_timestamp(), \
         updated_at = clock_timestamp() \
         WHERE workspace_id = $1 AND run_id = $2 \
         AND lease_token_hash = $3 AND fencing_generation = $4 \
         AND lease_expires_at > clock_timestamp()",
        uuid_of(release.workspace_id.as_bytes()),
        uuid_of(release.run_id.as_bytes()),
        &verifier[..],
        release.generation,
    )
    .execute(&mut **tx)
    .await
    .ctx("artifact: fence completion lease")?
    .rows_affected();
    if done != 1 {
        return Err(conflict("STALE_LEASE_FENCE"));
    }
    Ok(())
}

/// `applyTaskChangeSet` — the Task/Run mutation legs under their
/// expected-version guards (`TASK_VERSION_CONFLICT` /
/// `RUN_VERSION_CONFLICT`, upstream's artifact-scoped codes).
async fn apply_task_change_set(
    tx: &mut Transaction<'_, Postgres>,
    change: Option<&TaskChangeSet>,
    workspace_id: WorkspaceId,
) -> Result<(), Failure> {
    let Some(change) = change else {
        return Ok(());
    };
    if change.task.id.is_nil() {
        return Ok(());
    }
    let task = &change.task;
    let done = sqlx::query!(
        "UPDATE central.tasks \
         SET version = $3, status = $4, current_run_id = $5, \
         last_run_index = $6, retry_count = $7, retry_eligible_at = $8, \
         waiting_reason = NULLIF($9, ''), failure_reason = NULLIF($10, ''), \
         updated_at = clock_timestamp() \
         WHERE workspace_id = $1 AND id = $2 AND version = $11",
        uuid_of(workspace_id.as_bytes()),
        uuid_of(task.id.as_bytes()),
        task.version,
        task.status.as_str(),
        opt_uuid_of(task.current_run_id, |id| id.as_bytes()),
        task.last_run_index,
        task.retry_count,
        task.retry_eligible_at,
        wait_reason_value(task.waiting_reason),
        task.failure_reason.as_str(),
        change.expected_task_version,
    )
    .execute(&mut **tx)
    .await
    .ctx("artifact: update task")?
    .rows_affected();
    if done != 1 {
        return Err(conflict("TASK_VERSION_CONFLICT"));
    }
    for run in &change.runs {
        let Some(expected) = change.run_expected_versions.get(&run.id).copied() else {
            return Err(invalid("MISSING_RUN_EXPECTED_VERSION"));
        };
        let done = sqlx::query!(
            "UPDATE central.runs \
             SET version = $4, status = $5, run_index = $6, \
             waiting_reason = NULLIF($7, ''), failure_reason = NULLIF($8, ''), \
             ownership_token = NULLIF($9, ''), updated_at = clock_timestamp() \
             WHERE workspace_id = $1 AND task_id = $2 AND id = $3 AND version = $10",
            uuid_of(workspace_id.as_bytes()),
            uuid_of(run.task_id.as_bytes()),
            uuid_of(run.id.as_bytes()),
            run.version,
            run.status.as_str(),
            run.index,
            wait_reason_value(run.waiting_reason),
            run.failure_reason.as_str(),
            run.ownership_token.as_str(),
            expected,
        )
        .execute(&mut **tx)
        .await
        .ctx("artifact: update run")?
        .rows_affected();
        if done != 1 {
            return Err(conflict("RUN_VERSION_CONFLICT"));
        }
    }
    Ok(())
}

/// `applyStepsAndAttempts` — version-guarded Step updates and the
/// settlement-bound Attempt update (outcome/context JSONB side-channels,
/// invocation binding), one attempt per settlement.
async fn apply_steps_and_attempts(
    tx: &mut Transaction<'_, Postgres>,
    change: &ExecutionChangeSet,
) -> Result<(), Failure> {
    for step in &change.steps {
        let done = sqlx::query!(
            "UPDATE central.steps \
             SET version = $5, state = $6, sequence = $7, updated_at = clock_timestamp() \
             WHERE workspace_id = $1 AND task_id = $2 AND run_id = $3 AND id = $4 \
             AND version = $8",
            uuid_of(step.workspace_id.as_bytes()),
            uuid_of(step.task_id.as_bytes()),
            uuid_of(step.run_id.as_bytes()),
            uuid_of(step.id.as_bytes()),
            step.version,
            step.state.as_str(),
            step.sequence,
            step.version - 1,
        )
        .execute(&mut **tx)
        .await
        .ctx("artifact: update step")?
        .rows_affected();
        if done != 1 {
            return Err(conflict("STEP_VERSION_CONFLICT"));
        }
    }
    let settlement_by_attempt: BTreeMap<StepAttemptId, &Settlement> = change
        .settlements
        .iter()
        .map(|settlement| (settlement.attempt_id, settlement))
        .collect();
    for attempt in &change.attempts {
        let Some(settlement) = settlement_by_attempt.get(&attempt.id) else {
            return Err(invalid("SETTLEMENT_ATTEMPT_MISMATCH"));
        };
        // Upstream binds `[]byte(settlement.Outcome)`/`nullBytes(
        // settlement.Context)` as jsonb. `build_execution_change_set`
        // already validated the JSON shape and bounds; the
        // `unwrap_or_default` arm is unreachable on a validated set.
        let outcome: serde_json::Value =
            serde_json::from_slice(&settlement.outcome).unwrap_or_default();
        let context: Option<serde_json::Value> = if settlement.context.is_empty() {
            None
        } else {
            Some(serde_json::from_slice(&settlement.context).unwrap_or_default())
        };
        let done = sqlx::query!(
            "UPDATE central.step_attempts \
             SET version = $6, invocation_id = $7::uuid, \
             invocation_generation = CASE WHEN $7::uuid IS NULL THEN NULL ELSE $8::bigint END, \
             state = $9, outcome = COALESCE($10::jsonb, outcome), \
             context = COALESCE($11::jsonb, context), \
             updated_at = clock_timestamp() \
             WHERE workspace_id = $1 AND task_id = $2 AND run_id = $3 \
             AND step_id = $4 AND id = $5 AND version = $12",
            uuid_of(attempt.workspace_id.as_bytes()),
            uuid_of(attempt.task_id.as_bytes()),
            uuid_of(attempt.run_id.as_bytes()),
            uuid_of(attempt.step_id.as_bytes()),
            uuid_of(attempt.id.as_bytes()),
            attempt.version,
            uuid_for_invocation(&attempt.invocation_id),
            invocation_generation(&attempt.invocation_id),
            attempt.state.as_str(),
            outcome,
            context,
            attempt.version - 1,
        )
        .execute(&mut **tx)
        .await
        .ctx("artifact: persist settlement")?
        .rows_affected();
        if done != 1 {
            return Err(conflict("ATTEMPT_VERSION_CONFLICT"));
        }
    }
    Ok(())
}

/// `persistTaskEvents` — each task-transition event plus its
/// `task.lifecycle` outbox intent. The deduplication key formats an
/// absent `run_id` as `""`, matching upstream `zeroRun`.
async fn persist_task_events(
    tx: &mut Transaction<'_, Postgres>,
    workspace_id: WorkspaceId,
    change: Option<&TaskChangeSet>,
    task_version: i64,
) -> Result<(), Failure> {
    let Some(change) = change else {
        return Ok(());
    };
    let mut wrote_outbox = false;
    for task_event in &change.events {
        let sequence = reserve_event_sequence(tx, workspace_id).await?;
        let id = uuid::Uuid::now_v7();
        let mut payload = serde_json::json!({
            "schema_version": 1,
            "type": task_event.kind.as_str(),
            "occurred_at": go_rfc3339_local(task_event.occurred_at),
        });
        if let Some(reason) = task_event.reason {
            payload["reason"] = serde_json::Value::from(reason.as_str());
        }
        if !task_event.detail.is_empty() {
            payload["detail"] = serde_json::Value::from(task_event.detail.as_str());
        }
        let run = task_event.run_id.and_then(opt_run_uuid);
        sqlx::query!(
            "INSERT INTO central.events (\
             id, workspace_id, event_sequence, event_type, aggregate_id, \
             aggregate_version, command_id, run_id, payload, occurred_at, \
             task_id, step_id, attempt_id, kind, state, producer_id, \
             policy_version, eligible_after, legal_hold) \
             VALUES ($1, $2, $3, $4, $5, $6, $1, $7, $8::jsonb, \
             clock_timestamp(), $5, NULL, NULL, $4, 'recorded', $9, 1, \
             clock_timestamp() + interval '90 days', false)",
            id,
            uuid_of(workspace_id.as_bytes()),
            sequence,
            task_event.kind.as_str(),
            uuid_of(task_event.task_id.as_bytes()),
            task_version,
            run,
            payload,
            "artifact-store",
        )
        .execute(&mut **tx)
        .await
        .ctx("artifact: insert task event")?;
        // `zeroRun`: a task-level (no-run) event's dedup key ends in "".
        let run_text = task_event
            .run_id
            .map_or_else(String::new, |run_id| run_id.to_string());
        let dedup = format!(
            "task:{}:{}:{}:{}",
            task_event.task_id,
            task_version,
            task_event.kind.as_str(),
            run_text
        );
        let outbox_payload = serde_json::json!({
            "schema_version": 1,
            "event_id": id,
            "catalog_type": "task.lifecycle",
            "deduplication_key": dedup,
        });
        sqlx::query!(
            "INSERT INTO central.outbox (\
             id, workspace_id, event_id, delivery_state, due_at, attempt_count, \
             created_at, updated_at, catalog_type, deduplication_key, \
             producer_id, payload, visible_at, policy_version, \
             eligible_after, legal_hold) \
             VALUES ($1, $2, $3, 'pending', clock_timestamp(), 0, \
             clock_timestamp(), clock_timestamp(), 'task.lifecycle', $4, $5, \
             $6::jsonb, clock_timestamp(), 1, \
             clock_timestamp() + interval '7 days', false)",
            uuid::Uuid::now_v7(),
            uuid_of(workspace_id.as_bytes()),
            id,
            dedup,
            "artifact-store",
            outbox_payload,
        )
        .execute(&mut **tx)
        .await
        .ctx("artifact: insert task outbox")?;
        wrote_outbox = true;
    }
    if wrote_outbox {
        execution::Store::upsert_outbox_workspace_work(tx, workspace_id).await?;
    }
    Ok(())
}

/// `persistExecutionEvents` — the execution event + outbox intents.
/// The outbox workspace-work nudge runs once per touched workspace
/// (the Rust scheduler's wake-up lane; upstream's poller needed none).
async fn persist_execution_events(
    tx: &mut Transaction<'_, Postgres>,
    change: &ExecutionChangeSet,
    task_version: i64,
) -> Result<(), Failure> {
    for event in &change.events {
        let sequence = reserve_event_sequence(tx, event.workspace_id).await?;
        sqlx::query!(
            "INSERT INTO central.events (\
             id, workspace_id, event_sequence, event_type, aggregate_id, \
             aggregate_version, command_id, run_id, payload, occurred_at, \
             task_id, step_id, attempt_id, kind, state, producer_id, \
             policy_version, eligible_after, legal_hold) \
             VALUES ($1, $2, $3, $4, $5, $6, $1, $7, $8::jsonb, \
             clock_timestamp(), $5, $9, $10, $4, 'recorded', $11, 1, \
             clock_timestamp() + interval '90 days', false)",
            uuid_of(event.id.as_bytes()),
            uuid_of(event.workspace_id.as_bytes()),
            sequence,
            event.kind,
            uuid_of(event.task_id.as_bytes()),
            task_version,
            opt_run_uuid(event.run_id),
            serde_json::from_slice::<serde_json::Value>(&go_json_escapes(&event.payload))
                .unwrap_or_default(),
            opt_step_uuid(event.step_id),
            opt_attempt_uuid(event.attempt_id),
            "artifact-store",
        )
        .execute(&mut **tx)
        .await
        .ctx("artifact: insert event")?;
    }
    let mut touched = BTreeSet::new();
    for outbox in &change.outbox {
        sqlx::query!(
            "INSERT INTO central.outbox (\
             id, workspace_id, event_id, delivery_state, due_at, attempt_count, \
             created_at, updated_at, catalog_type, deduplication_key, \
             producer_id, payload, visible_at, policy_version, \
             eligible_after, legal_hold) \
             VALUES ($1, $2, $3, 'pending', clock_timestamp(), 0, \
             clock_timestamp(), clock_timestamp(), $4, $5, $6, $7::jsonb, \
             clock_timestamp(), 1, clock_timestamp() + interval '7 days', false)",
            uuid_of(outbox.id.as_bytes()),
            uuid_of(outbox.workspace_id.as_bytes()),
            uuid_of(outbox.event_id.as_bytes()),
            outbox.catalog_type,
            outbox.deduplication_key.as_str(),
            outbox.producer_id.as_str(),
            serde_json::from_slice::<serde_json::Value>(&go_json_escapes(&outbox.payload))
                .unwrap_or_default(),
        )
        .execute(&mut **tx)
        .await
        .ctx("artifact: insert outbox")?;
        touched.insert(outbox.workspace_id);
    }
    for workspace in touched {
        execution::Store::upsert_outbox_workspace_work(tx, workspace).await?;
    }
    Ok(())
}

impl CompletionContributor for Store {
    /// `CommitArtifact` — receipt replay, the eight-step lock order,
    /// then every mutation + the finalize receipt in one commit.
    async fn commit_artifact(
        &self,
        change: ArtifactChangeSet,
        exec_change: ExecutionChangeSet,
    ) -> Result<CommitResult, Failure> {
        if change.receipt.idempotency_key.is_empty()
            || change.receipt.identity != change.finalize.identity
        {
            return Err(invalid("INVALID_RECEIPT_BINDING"));
        }
        if change.finalize.outcome.kind != OutcomeKind::Ready {
            return Err(invalid("INVALID_FINALIZE_OUTCOME"));
        }
        b10_supported_execution_change(&exec_change)?;
        let exec_change = build_execution_change_set(exec_change)?;

        let workspace_id = change.finalize.artifact.workspace_id;
        let artifact_id = change.finalize.artifact.artifact_id;
        let fingerprint = canonical_identity_hash(&change.finalize.identity);

        // `execution::begin` — the commit transaction opener with
        // `synchronous_commit = on` and the advisory timeouts.
        let mut tx = execution::begin(&self.pool).await?;

        let existing = lookup_artifact_receipt(
            &mut tx,
            workspace_id,
            "finalize",
            &change.receipt.idempotency_key,
        )
        .await?;
        if existing.found {
            if existing.fingerprint != fingerprint {
                return Err(fingerprint_mismatch());
            }
            tx.commit().await.map_err(|e| classify_sqlx(&e))?;
            return Ok(CommitResult {
                outcome: Outcome {
                    kind: OutcomeKind::Ready,
                    failure_code: String::new(),
                },
                replayed: true,
            });
        }

        let task_change = exec_change.task_transition.as_ref().map(|t| &t.change_set);
        let has_task = task_change.is_some_and(|c| !c.task.id.is_nil());

        // 0. Lock the Workspace event counter first when this commit
        //    persists events, as every execution commit does
        //    (EventCounter -> Task -> ...). Taking it only when the
        //    events are written, after the Task lock, deadlocked a
        //    completion commit against a concurrent execution command
        //    such as the harness lease heartbeat (harness phase 3b).
        if has_task || !exec_change.events.is_empty() {
            lock_event_counter(&mut tx, workspace_id).await?;
        }

        // 1. Lock the quota ledger (`FOR NO KEY UPDATE`).
        let Some((ready_bytes, max_bytes)) = lock_workspace_quota(&mut tx, workspace_id).await?
        else {
            return Err(invalid("WORKSPACE_NOT_FOUND"));
        };

        // 2. Lock Task.
        if let Some(change_set) = task_change.filter(|c| !c.task.id.is_nil()) {
            let row = sqlx::query!(
                "SELECT version FROM central.tasks \
                 WHERE workspace_id = $1 AND id = $2 FOR UPDATE",
                uuid_of(workspace_id.as_bytes()),
                uuid_of(change_set.task.id.as_bytes()),
            )
            .fetch_optional(&mut *tx)
            .await
            .ctx("artifact: lock task")?;
            let Some(row) = row else {
                return Err(conflict("TASK_NOT_FOUND"));
            };
            if row.version != change_set.expected_task_version {
                return Err(conflict("TASK_VERSION_CONFLICT"));
            }
        }

        // 3. Lock Run(s).
        if let Some(change_set) = task_change {
            for run in &change_set.runs {
                let Some(expected) = change_set.run_expected_versions.get(&run.id).copied() else {
                    return Err(invalid("MISSING_RUN_EXPECTED_VERSION"));
                };
                let row = sqlx::query!(
                    "SELECT version FROM central.runs \
                     WHERE workspace_id = $1 AND task_id = $2 AND id = $3 FOR UPDATE",
                    uuid_of(workspace_id.as_bytes()),
                    uuid_of(run.task_id.as_bytes()),
                    uuid_of(run.id.as_bytes()),
                )
                .fetch_optional(&mut *tx)
                .await
                .ctx("artifact: lock run")?;
                let Some(row) = row else {
                    return Err(conflict("RUN_NOT_FOUND"));
                };
                if row.version != expected {
                    return Err(conflict("RUN_VERSION_CONFLICT"));
                }
            }
        }

        // 4. Fence the completing pass's B08 lease — after the Run lock
        //    and before the Step lock, the same order the execution
        //    adapter's own commit takes the ownership row.
        fence_completion_lease(&mut tx, &exec_change).await?;

        // 5. Lock Step(s) and their Attempt(s).
        for step in &exec_change.steps {
            let row = sqlx::query!(
                "SELECT version FROM central.steps \
                 WHERE workspace_id = $1 AND task_id = $2 AND run_id = $3 AND id = $4 \
                 FOR UPDATE",
                uuid_of(step.workspace_id.as_bytes()),
                uuid_of(step.task_id.as_bytes()),
                uuid_of(step.run_id.as_bytes()),
                uuid_of(step.id.as_bytes()),
            )
            .fetch_optional(&mut *tx)
            .await
            .ctx("artifact: lock step")?;
            let Some(row) = row else {
                return Err(conflict("STEP_NOT_FOUND"));
            };
            if row.version != step.version - 1 {
                return Err(conflict("STEP_VERSION_CONFLICT"));
            }
        }
        for attempt in &exec_change.attempts {
            let row = sqlx::query!(
                "SELECT version FROM central.step_attempts \
                 WHERE workspace_id = $1 AND task_id = $2 AND run_id = $3 \
                 AND step_id = $4 AND id = $5 FOR UPDATE",
                uuid_of(attempt.workspace_id.as_bytes()),
                uuid_of(attempt.task_id.as_bytes()),
                uuid_of(attempt.run_id.as_bytes()),
                uuid_of(attempt.step_id.as_bytes()),
                uuid_of(attempt.id.as_bytes()),
            )
            .fetch_optional(&mut *tx)
            .await
            .ctx("artifact: lock attempt")?;
            let Some(row) = row else {
                return Err(conflict("ATTEMPT_NOT_FOUND"));
            };
            if row.version != attempt.version - 1 {
                return Err(conflict("ATTEMPT_VERSION_CONFLICT"));
            }
        }

        // 6. Lock Artifact — version, verifying state, and the
        //    ready-key/content-generation pair the Finalize identity
        //    binds, then the producer-chain match against every
        //    Task/Run/Step/Attempt this completion names.
        let row = read_artifact_for_update(&mut tx, workspace_id, artifact_id).await?;
        if row.version != change.finalize.identity.expected_version {
            return Err(conflict("VERSION_CONFLICT"));
        }
        if row.state != State::Verifying {
            return Err(conflict("INVALID_TRANSITION"));
        }
        if row.ready_key != change.finalize.identity.ready_key
            || row.content_generation != change.finalize.identity.content_generation
        {
            return Err(conflict("FINALIZE_IDENTITY_MISMATCH"));
        }
        for step in &exec_change.steps {
            if step.workspace_id != workspace_id
                || (!row.step_id.is_nil() && step.id != row.step_id)
                || (!row.task_id.is_nil() && step.task_id != row.task_id)
                || (!row.run_id.is_nil() && step.run_id != row.run_id)
            {
                return Err(denied("PRODUCER_CHAIN_MISMATCH"));
            }
        }
        for attempt in &exec_change.attempts {
            if attempt.workspace_id != workspace_id
                || (!row.step_attempt_id.is_nil() && attempt.id != row.step_attempt_id)
            {
                return Err(denied("PRODUCER_CHAIN_MISMATCH"));
            }
        }
        if let Some(change_set) = task_change
            && !change_set.task.id.is_nil()
            && !row.task_id.is_nil()
            && change_set.task.id != row.task_id
        {
            return Err(denied("PRODUCER_CHAIN_MISMATCH"));
        }

        // 7. Lock the capacity reservation.
        let Some(reservation_state) =
            lock_capacity_reservation(&mut tx, workspace_id, artifact_id).await?
        else {
            return Err(conflict("CAPACITY_RESERVATION_NOT_FOUND"));
        };
        if reservation_state != "reserved" {
            return Err(conflict("CAPACITY_ALREADY_SETTLED"));
        }

        // Defensive quota-peak re-check: never allow a ready transition
        // that would push the Workspace over its ceiling.
        if ready_bytes + change.finalize.artifact.verified_size > max_bytes {
            return Err(denied("QUOTA_EXCEEDED"));
        }

        // --- mutate ---
        let done = sqlx::query!(
            "UPDATE central.artifacts \
             SET version = $3, state = 'ready', ready_at = clock_timestamp(), \
             updated_at = clock_timestamp(), \
             ready_object_version = COALESCE($6, ready_object_version) \
             WHERE workspace_id = $1 AND id = $2 AND version = $5 \
             AND checksum_value = $4",
            uuid_of(workspace_id.as_bytes()),
            uuid_of(artifact_id.as_bytes()),
            change.finalize.artifact.version,
            &change.finalize.artifact.verified_checksum[..],
            row.version,
            (!change.finalize.artifact.ready_object_version.is_empty()).then(|| change
                .finalize
                .artifact
                .ready_object_version
                .as_str()),
        )
        .execute(&mut *tx)
        .await
        .ctx("artifact: finalize artifact")?
        .rows_affected();
        if done != 1 {
            return Err(conflict("VERSION_CONFLICT"));
        }

        let done = sqlx::query!(
            "UPDATE central.capacity_reservations \
             SET state = 'settled', settled_at = clock_timestamp() \
             WHERE workspace_id = $1 AND artifact_id = $2 AND state = 'reserved'",
            uuid_of(workspace_id.as_bytes()),
            uuid_of(artifact_id.as_bytes()),
        )
        .execute(&mut *tx)
        .await
        .ctx("artifact: settle capacity reservation")?
        .rows_affected();
        if done != 1 {
            return Err(conflict("CAPACITY_ALREADY_SETTLED"));
        }

        sqlx::query!(
            "UPDATE central.workspaces \
             SET quota_ready_bytes = quota_ready_bytes + $2, \
             quota_ready_count = quota_ready_count + 1, \
             updated_at = clock_timestamp() \
             WHERE id = $1",
            uuid_of(workspace_id.as_bytes()),
            change.finalize.artifact.verified_size,
        )
        .execute(&mut *tx)
        .await
        .ctx("artifact: charge workspace quota")?;

        apply_task_change_set(&mut tx, task_change, workspace_id).await?;
        apply_steps_and_attempts(&mut tx, &exec_change).await?;
        let task_version_for_events = task_change.map_or(0, |c| {
            if c.task.id.is_nil() {
                c.expected_task_version
            } else {
                c.task.version
            }
        });
        persist_task_events(&mut tx, workspace_id, task_change, task_version_for_events).await?;
        persist_execution_events(&mut tx, &exec_change, task_version_for_events).await?;

        insert_artifact_receipt(
            &mut tx,
            workspace_id,
            artifact_id,
            "finalize",
            &change.receipt.idempotency_key,
            fingerprint,
            outcome_payload(&change.finalize.outcome),
        )
        .await?;

        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(CommitResult {
            outcome: change.finalize.outcome,
            replayed: false,
        })
    }
}
