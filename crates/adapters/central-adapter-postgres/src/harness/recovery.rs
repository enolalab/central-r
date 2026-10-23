//! The lease-dead recovery lane — port of upstream `recovery.go`:
//! `ListRecoveryCandidates`' `(prepared_at, id)` keyset scan and
//! `RecoverAttempt`, the recovery-authorized write that replaces the
//! fence with a live-lease check over the attempt's linked
//! StepAttempt.

use central_foundation::failure::Failure;
use central_harness::attempt::Attempt;
use central_harness::domain::{ResolutionKind, State, ZERO_TIME, codes};
use central_harness::port::{
    LinkedStepAttemptState, MAX_RECOVERY_CANDIDATES, RecoveryCandidate, RecoveryCursor,
    RecoveryStore, supersedes_approvals,
};
use sqlx::{Postgres, Transaction};
use time::OffsetDateTime;

use super::approval::ApprovalWrite;
use super::queries::{AttemptRow, stored_time};
use super::store::{AttemptLock, PgHarnessStore, compare_and_swap, lock_attempt, prepare_write};
use crate::error::classify_sqlx;
use crate::store_support::{usize_as_i64, uuid_of};

/// The candidate row — the 38 `attemptColumns` plus the linked
/// StepAttempt's reported state (`""` when there is none) and whether
/// an unexpired lease claims it.
pub(crate) struct CandidateRow {
    workspace_id: uuid::Uuid,
    id: uuid::Uuid,
    run_id: uuid::Uuid,
    kind: String,
    adapter_version: String,
    harness_version: Option<String>,
    harness_session_id: Option<String>,
    resume_of: Option<uuid::Uuid>,
    resume_session_id: Option<String>,
    workspace_path: String,
    base_sha: String,
    permission: String,
    sandbox_scope_id: Option<String>,
    fence_generation: i64,
    version: i64,
    state: String,
    pending_permission: Option<String>,
    terminal_status: Option<String>,
    terminal_reason: Option<String>,
    terminal_exit_code: Option<i64>,
    resolution_kind: Option<String>,
    resolution_decided_by: Option<String>,
    ambiguity_reason: Option<String>,
    last_event_seq: i64,
    usage_tokens_in: i64,
    usage_tokens_out: i64,
    usage_cache_read: i64,
    usage_cache_write: i64,
    usage_cost_micro_usd: i64,
    usage_scope: Option<String>,
    usage_estimated: bool,
    prepared_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    ended_at: Option<OffsetDateTime>,
    budget_cost_micro_usd: i64,
    budget_wall_clock_seconds: i32,
    budget_cost_defaulted: bool,
    budget_wall_clock_defaulted: bool,
    step_state: Option<String>,
    lease_live: Option<bool>,
}

impl CandidateRow {
    /// Upstream `scanAttemptWith(&stepState, &leaseLive)`: rebuilds the
    /// attempt and carries the two linked columns through.
    fn into_candidate(self) -> Result<RecoveryCandidate, Failure> {
        let step_state =
            LinkedStepAttemptState::parse(self.step_state.as_deref().unwrap_or_default());
        let lease_live = self.lease_live.unwrap_or(false);
        let attempt = super::queries::attempt_from_row(AttemptRow {
            workspace_id: self.workspace_id,
            id: self.id,
            run_id: self.run_id,
            kind: self.kind,
            adapter_version: self.adapter_version,
            harness_version: self.harness_version,
            harness_session_id: self.harness_session_id,
            resume_of: self.resume_of,
            resume_session_id: self.resume_session_id,
            workspace_path: self.workspace_path,
            base_sha: self.base_sha,
            permission: self.permission,
            sandbox_scope_id: self.sandbox_scope_id,
            fence_generation: self.fence_generation,
            version: self.version,
            state: self.state,
            pending_permission: self.pending_permission,
            terminal_status: self.terminal_status,
            terminal_reason: self.terminal_reason,
            terminal_exit_code: self.terminal_exit_code,
            resolution_kind: self.resolution_kind,
            resolution_decided_by: self.resolution_decided_by,
            ambiguity_reason: self.ambiguity_reason,
            last_event_seq: self.last_event_seq,
            usage_tokens_in: self.usage_tokens_in,
            usage_tokens_out: self.usage_tokens_out,
            usage_cache_read: self.usage_cache_read,
            usage_cache_write: self.usage_cache_write,
            usage_cost_micro_usd: self.usage_cost_micro_usd,
            usage_scope: self.usage_scope,
            usage_estimated: self.usage_estimated,
            prepared_at: self.prepared_at,
            updated_at: self.updated_at,
            ended_at: self.ended_at,
            budget_cost_micro_usd: self.budget_cost_micro_usd,
            budget_wall_clock_seconds: self.budget_wall_clock_seconds,
            budget_cost_defaulted: self.budget_cost_defaulted,
            budget_wall_clock_defaulted: self.budget_wall_clock_defaulted,
        })?;
        Ok(RecoveryCandidate {
            attempt,
            step_state,
            lease_live,
        })
    }
}

/// Upstream `recoveryTarget` — whether `next` is a state recovery may
/// write.
fn recovery_target(next: &Attempt) -> bool {
    match next.state {
        State::Ambiguous
        | State::Succeeded
        | State::Failed
        | State::Interrupted
        | State::Killed
        | State::BudgetExhausted => true,
        // resolved(resume) is further bound to a Resumed StepAttempt,
        // and resolved(rerun) to a failed StepAttempt of a replaced
        // run, in `recover_attempt` once the linked state is read.
        State::Resolved => matches!(
            next.resolution.kind,
            ResolutionKind::Abandon | ResolutionKind::Resume | ResolutionKind::Rerun
        ),
        _ => false,
    }
}

/// The linked StepAttempt's lock row — upstream
/// `queryLockLinkedStepAttempt`'s three computed columns.
struct LinkedLock {
    step_state: Option<String>,
    lease_live: Option<bool>,
    run_replaced: Option<bool>,
}

/// Upstream `queryLockLinkedStepAttempt` — share-locks the execution
/// StepAttempt linked to a harness attempt (the same id) and reports
/// its linked state (a failed StepAttempt that a StepAttempt of the
/// same run names as predecessor reads as `resumed`, harness phase 3g
/// decision 6; `step_attempts_one_successor_idx` serves the lookup),
/// whether an unexpired lease still claims it, and whether its task
/// now names another run as current (a retry replaced the run,
/// harness phase 3k decision 4).
async fn lock_linked_step_attempt(
    tx: &mut Transaction<'static, Postgres>,
    expected: &Attempt,
) -> Result<Option<LinkedLock>, Failure> {
    sqlx::query!(
        "SELECT CASE WHEN step_attempt.state = 'failed' AND EXISTS (
                    SELECT 1 FROM central.step_attempts successor
                    WHERE successor.workspace_id = step_attempt.workspace_id
                      AND successor.run_id = step_attempt.run_id
                      AND successor.predecessor_id = step_attempt.id
                ) THEN 'resumed' ELSE step_attempt.state END AS step_state,
                EXISTS (
                    SELECT 1 FROM central.execution_ownership ownership
                    WHERE ownership.workspace_id = step_attempt.workspace_id
                      AND ownership.run_id = step_attempt.run_id
                      AND ownership.claimed_step_attempt_id = step_attempt.id
                      AND ownership.lease_expires_at > clock_timestamp()
                ) AS lease_live,
                EXISTS (
                    SELECT 1 FROM central.tasks task
                    WHERE task.workspace_id = step_attempt.workspace_id
                      AND task.id = step_attempt.task_id
                      AND task.current_run_id <> step_attempt.run_id
                ) AS run_replaced
         FROM central.step_attempts step_attempt
         WHERE step_attempt.workspace_id = $1 AND step_attempt.id = $2
           AND step_attempt.run_id = $3
         FOR SHARE OF step_attempt",
        uuid_of(expected.workspace_id.as_bytes()),
        uuid_of(expected.id.as_bytes()),
        uuid_of(expected.run_id.as_bytes()),
    )
    .fetch_optional(&mut **tx)
    .await
    .map(|row| {
        row.map(|r| LinkedLock {
            step_state: r.step_state,
            lease_live: r.lease_live,
            run_replaced: r.run_replaced,
        })
    })
    .map_err(|e| classify_sqlx(&e))
}

impl PgHarnessStore {
    /// Upstream `ListRecoveryCandidates` — up to `limit` non-terminal
    /// attempts across every workspace after `after`, ordered by
    /// `(prepared_at, id)`, with their linked StepAttempt's state and
    /// lease liveness. Keyset-ordered bounded pages, never `OFFSET`.
    async fn list_recovery_candidates_inner(
        &self,
        after: RecoveryCursor,
        limit: usize,
    ) -> Result<Vec<RecoveryCandidate>, Failure> {
        if !(1..=MAX_RECOVERY_CANDIDATES).contains(&limit) {
            return Err(Failure::invalid(
                codes::INVALID_ATTEMPT,
                format!("recovery page must hold 1..{MAX_RECOVERY_CANDIDATES} attempts"),
            ));
        }
        let (after_at, after_id): (Option<OffsetDateTime>, Option<uuid::Uuid>) =
            if after.prepared_at == ZERO_TIME && after.id.is_nil() {
                (None, None)
            } else if after.prepared_at == ZERO_TIME || after.id.is_nil() {
                return Err(Failure::invalid(
                    codes::INVALID_ATTEMPT,
                    "recovery cursor needs both time and id",
                ));
            } else {
                (
                    Some(stored_time(after.prepared_at)),
                    Some(uuid_of(after.id.as_bytes())),
                )
            };
        let mut tx = self.begin().await?;
        let rows = sqlx::query_as!(
            CandidateRow,
            "SELECT workspace_id, id, run_id, kind, adapter_version, harness_version, harness_session_id,
                    resume_of, resume_session_id, workspace_path, base_sha, permission, sandbox_scope_id,
                    fence_generation, version, state, pending_permission, terminal_status, terminal_reason,
                    terminal_exit_code, resolution_kind, resolution_decided_by, ambiguity_reason, last_event_seq,
                    usage_tokens_in, usage_tokens_out, usage_cache_read, usage_cache_write, usage_cost_micro_usd,
                    usage_scope, usage_estimated, prepared_at, updated_at, ended_at,
                    budget_cost_micro_usd, budget_wall_clock_seconds, budget_cost_defaulted,
                    budget_wall_clock_defaulted,
                    (SELECT CASE WHEN step_attempt.state = 'failed' AND EXISTS (
                                SELECT 1 FROM central.step_attempts successor
                                WHERE successor.workspace_id = step_attempt.workspace_id
                                  AND successor.run_id = step_attempt.run_id
                                  AND successor.predecessor_id = step_attempt.id
                            ) THEN 'resumed' ELSE step_attempt.state END
                     FROM central.step_attempts step_attempt
                     WHERE step_attempt.workspace_id = harness_attempts.workspace_id
                       AND step_attempt.id = harness_attempts.id
                       AND step_attempt.run_id = harness_attempts.run_id
                    ) AS step_state,
                    EXISTS (
                        SELECT 1 FROM central.execution_ownership ownership
                        WHERE ownership.workspace_id = harness_attempts.workspace_id
                          AND ownership.run_id = harness_attempts.run_id
                          AND ownership.claimed_step_attempt_id = harness_attempts.id
                          AND ownership.lease_expires_at > clock_timestamp()
                    ) AS lease_live
             FROM central.harness_attempts
             WHERE state IN ('prepared','launching','running','awaiting_permission','ambiguous')
               AND ($1::timestamptz IS NULL OR (prepared_at, id) > ($1::timestamptz, $2::uuid))
             ORDER BY prepared_at, id
             LIMIT $3",
            after_at,
            after_id,
            usize_as_i64(limit),
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        let out = rows
            .into_iter()
            .map(CandidateRow::into_candidate)
            .collect::<Result<Vec<_>, _>>()?;
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(out)
    }

    /// Upstream `RecoverAttempt` — the recovery-authorized write
    /// (harness phase 3a decision 9). It uses no fence: it checks in
    /// one transaction that the attempt's linked StepAttempt (the
    /// same id, same run) is `reconciliation`, settled, `resumed` or
    /// `cancelled` and that no unexpired lease claims it
    /// (`resolved(resume)` further requires it resumed;
    /// `resolved(rerun)` requires it failed and its run replaced by a
    /// newer current run of the task), then applies `save`'s version
    /// compare-and-swap. Every recovery target is terminal or
    /// ambiguous, so the attempt's pending approval is superseded in
    /// the same transaction (decision 11).
    async fn recover_attempt_inner(
        &self,
        expected: &Attempt,
        next: &Attempt,
    ) -> Result<Attempt, Failure> {
        if next.last_event_seq != expected.last_event_seq || next.usage != expected.usage {
            return Err(Failure::invalid(
                codes::INVALID_EVENT,
                "recovery must not move the event cursor or usage",
            ));
        }
        if next.fence != expected.fence {
            return Err(Failure::conflict(
                codes::FENCE_MISMATCH,
                "recovery never rotates the fence",
            ));
        }
        if !recovery_target(next) || !expected.state.can_transition(next.state) {
            return Err(Failure::conflict(
                codes::INVALID_TRANSITION,
                format!(
                    "recovery cannot write {} -> {}",
                    expected.state.as_str(),
                    next.state.as_str()
                ),
            ));
        }
        let stored = prepare_write(expected, next)?;
        let mut tx = self.begin().await?;
        let lock: AttemptLock = lock_attempt(&mut tx, expected).await?;
        let Some(linked_lock) = lock_linked_step_attempt(&mut tx, expected).await? else {
            return Err(Failure::conflict(
                codes::RECOVERY_NOT_AUTHORIZED,
                format!("attempt {} has no linked StepAttempt", expected.id),
            ));
        };
        let linked_text = linked_lock.step_state.as_deref().unwrap_or_default();
        let linked = LinkedStepAttemptState::parse(linked_text);
        match linked {
            LinkedStepAttemptState::Reconciliation
            | LinkedStepAttemptState::Succeeded
            | LinkedStepAttemptState::Failed
            | LinkedStepAttemptState::Cancelled
            | LinkedStepAttemptState::Resumed => {}
            _ => {
                return Err(Failure::conflict(
                    codes::RECOVERY_NOT_AUTHORIZED,
                    format!("linked StepAttempt is {linked_text}"),
                ));
            }
        }
        // Harness phase 3g decision 6: resolved(resume) records an
        // operator's Resume, so it is written only for a failed
        // StepAttempt that a resume successor names as predecessor;
        // confirm_failed alone still means abandon.
        if next.state == State::Resolved
            && next.resolution.kind == ResolutionKind::Resume
            && linked != LinkedStepAttemptState::Resumed
        {
            return Err(Failure::conflict(
                codes::INVALID_TRANSITION,
                format!(
                    "resolved(resume) needs a resumed StepAttempt, linked StepAttempt is {linked_text}"
                ),
            ));
        }
        // Harness phase 3k decision 4: resolved(rerun) records "Mark
        // failed and rerun", so it is written only for a failed
        // StepAttempt (no resume successor) whose task already names a
        // newer run as current: the retry has committed. The task row
        // is read without a lock: a retry only ever moves the current
        // run on to a new run, never back, so a replaced run stays
        // replaced.
        let run_replaced = linked_lock.run_replaced.unwrap_or(false);
        if next.state == State::Resolved
            && next.resolution.kind == ResolutionKind::Rerun
            && (linked != LinkedStepAttemptState::Failed || !run_replaced)
        {
            return Err(Failure::conflict(
                codes::INVALID_TRANSITION,
                format!(
                    "resolved(rerun) needs a failed StepAttempt of a replaced Run, linked StepAttempt is {linked_text} (Run replaced: {run_replaced})"
                ),
            ));
        }
        if linked_lock.lease_live.unwrap_or(false) {
            return Err(Failure::conflict(
                codes::RECOVERY_NOT_AUTHORIZED,
                "a live lease still claims the linked StepAttempt",
            ));
        }
        compare_and_swap(&mut tx, expected, &lock, &stored).await?;
        ApprovalWrite {
            open: None,
            supersede: supersedes_approvals(next),
            at: stored_time(next.updated_at),
        }
        .apply(&mut tx, next)
        .await?;
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(stored)
    }
}

impl RecoveryStore for PgHarnessStore {
    fn list_recovery_candidates<'a>(
        &'a self,
        after: RecoveryCursor,
        limit: usize,
    ) -> central_harness::port::PortFuture<'a, Result<Vec<RecoveryCandidate>, Failure>> {
        Box::pin(async move { self.list_recovery_candidates_inner(after, limit).await })
    }

    fn recover_attempt<'a>(
        &'a self,
        expected: &'a Attempt,
        next: &'a Attempt,
    ) -> central_harness::port::PortFuture<'a, Result<Attempt, Failure>> {
        Box::pin(async move { self.recover_attempt_inner(expected, next).await })
    }
}
