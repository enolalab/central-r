//! The attempt store — port of upstream `store.go`: create/load, the
//! version+fence compare-and-swap `save`, the atomic `append_event`
//! (bounded metadata only), `expire_permission`/`load_approval`, the
//! `LeaseBinder` live-lease check, and the read projections upstream
//! attaches to the same `Store` (`LatestAttemptForRun`,
//! `AttemptsForRun`, `CostForTask`) plus the Rust
//! [`HarnessEventRead`] keyset page.

use central_foundation::failure::Failure;
use central_foundation::identity::{HarnessAttemptId, RunId, TaskId, WorkspaceId};
use central_harness::attempt::Attempt;
use central_harness::domain::codes;
use central_harness::port::{ApprovalOpen, AttemptStore, ExecutionLease, LeaseBinder, PortFuture};
use central_harness::query::{
    AttemptSummaryRead, BudgetUsageRead, HarnessEventPage, HarnessEventRead, HarnessEventRequest,
    MAX_ATTEMPTS_FOR_RUN, normalize_harness_event_page_size, validate_harness_event_request,
};
use central_harness::record::EventRecord;
use sqlx::{PgPool, Postgres, Transaction};

use super::approval::plan_approval_write;
use super::queries::{
    ApprovalRow, AttemptRow, CONSTRAINT_LIVE_ATTEMPT, EventRecordRow, approval_from_row,
    attempt_from_row, budget_wall_clock_seconds, corrupt, cursor_as_i64, db_constraint,
    db_sqlstate, event_record_from_row, is_invalid_value_sqlstate, nonempty, seq_as_i64,
    stored_time,
};
use crate::error::classify_sqlx;
use crate::execution::sha256;
use crate::store_support::{begin_tx, opt_uuid_of, usize_as_i64, uuid_of};

/// The PostgreSQL harness store — upstream `harness.Store`. A store
/// returned by [`LeaseBinder::with_lease`] re-validates every write
/// against the run's live execution lease inside the write's
/// transaction (harness phase 3a decision 3); the plain store keeps the
/// phase 1b fence-only compare-and-swap.
#[derive(Clone)]
pub struct PgHarnessStore {
    pool: PgPool,
    lease: Option<ExecutionLease>,
}

impl PgHarnessStore {
    /// Upstream `NewStore` — a store over `pool`, which should
    /// authenticate as `central_runtime`.
    pub fn new(pool: PgPool) -> Self {
        Self { pool, lease: None }
    }

    /// Upstream `s.begin` — a bounded READ COMMITTED transaction with
    /// the advisory timeouts.
    pub(crate) async fn begin(&self) -> Result<Transaction<'static, Postgres>, Failure> {
        begin_tx(&self.pool).await
    }

    /// Upstream `assertLease`: inside `tx`, checks that the run's
    /// execution ownership row is the live lease this store is bound to
    /// and that it claims the StepAttempt linked to `a` (same id), at
    /// `a`'s fence generation. The row is share-locked so a concurrent
    /// reclaim cannot commit between the check and the write.
    pub(crate) async fn assert_lease(
        &self,
        tx: &mut Transaction<'static, Postgres>,
        a: &Attempt,
    ) -> Result<(), Failure> {
        let Some(lease) = self.lease else {
            return Ok(());
        };
        lease.validate()?;
        if a.fence.generation != lease.generation {
            return Err(Failure::conflict(
                codes::FENCE_MISMATCH,
                format!(
                    "attempt fence {} is not the bound lease generation",
                    a.fence.generation
                ),
            ));
        }
        let verifier = sha256(&lease.credential);
        sqlx::query_scalar!(
            "SELECT fencing_generation FROM central.execution_ownership
             WHERE workspace_id = $1 AND run_id = $2
               AND claimed_step_attempt_id = $3
               AND fencing_generation = $4 AND lease_token_hash = $5
               AND lease_expires_at > clock_timestamp()
             FOR SHARE",
            uuid_of(a.workspace_id.as_bytes()),
            uuid_of(a.run_id.as_bytes()),
            uuid_of(a.id.as_bytes()),
            lease.generation,
            &verifier[..],
        )
        .fetch_optional(&mut **tx)
        .await
        .map_err(|e| classify_sqlx(&e))?
        .ok_or_else(|| {
            Failure::conflict(codes::FENCE_MISMATCH, "execution lease is not current")
        })?;
        Ok(())
    }

    /// Upstream `Create` — inserts a new attempt at `version` 0. A
    /// retried create of an `equal` attempt succeeds (idempotent); a
    /// different attempt under a taken id is `VERSION_CONFLICT`, a
    /// second live attempt for the run `LIVE_ATTEMPT_EXISTS`, and an
    /// unknown run or resume target `INVALID_ATTEMPT`.
    async fn create_attempt(&self, a: &Attempt) -> Result<(), Failure> {
        a.validate()?;
        if a.version != 0 {
            return Err(Failure::invalid(
                codes::INVALID_ATTEMPT,
                "create requires version 0",
            ));
        }
        let budget_seconds = budget_wall_clock_seconds(&a.budget)?;
        let last_event_seq = cursor_as_i64(a.last_event_seq)?;
        let mut tx = self.begin().await?;
        if let Err(e) = self.assert_lease(&mut tx, a).await {
            let _ = tx.rollback().await;
            return Err(e);
        }
        let inserted = sqlx::query!(
            "INSERT INTO central.harness_attempts (
                workspace_id, id, run_id, kind, adapter_version, harness_version, harness_session_id,
                resume_of, resume_session_id, workspace_path, base_sha, permission, sandbox_scope_id,
                fence_generation, version, state, pending_permission, terminal_status, terminal_reason,
                terminal_exit_code, resolution_kind, resolution_decided_by, ambiguity_reason, last_event_seq,
                usage_tokens_in, usage_tokens_out, usage_cache_read, usage_cache_write, usage_cost_micro_usd,
                usage_scope, usage_estimated, prepared_at, updated_at, ended_at,
                budget_cost_micro_usd, budget_wall_clock_seconds, budget_cost_defaulted, budget_wall_clock_defaulted
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19,
                $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38
            )",
            uuid_of(a.workspace_id.as_bytes()),
            uuid_of(a.id.as_bytes()),
            uuid_of(a.run_id.as_bytes()),
            a.kind.as_str(),
            a.adapter_version.as_str(),
            nonempty(&a.harness_version),
            nonempty(&a.harness_session_id),
            opt_uuid_of(a.resume_of, |i| i.as_bytes()),
            nonempty(&a.resume_session_id),
            a.workspace.path.as_str(),
            a.workspace.base_sha.as_str(),
            a.permission.as_str(),
            nonempty(&a.sandbox_scope_id),
            a.fence.generation,
            a.version,
            a.state.as_str(),
            nonempty(&a.pending_permission),
            nonempty(a.terminal.status.as_str()),
            nonempty(&a.terminal.reason),
            a.terminal.exit_code.map(i64::from),
            nonempty(a.resolution.kind.as_str()),
            nonempty(&a.resolution.decided_by),
            nonempty(&a.ambiguity_reason),
            last_event_seq,
            a.usage.tokens_in,
            a.usage.tokens_out,
            a.usage.cache_read,
            a.usage.cache_write,
            a.usage.cost_micro_usd,
            nonempty(a.usage.scope.as_str()),
            a.usage.estimated,
            stored_time(a.prepared_at),
            stored_time(a.updated_at),
            a.ended_at.map(stored_time),
            a.budget.cost_micro_usd,
            budget_seconds,
            a.budget.cost_defaulted,
            a.budget.wall_clock_defaulted,
        )
        .execute(&mut *tx)
        .await;
        if let Err(e) = inserted {
            let _ = tx.rollback().await;
            return self.create_failure(a, &e).await;
        }
        tx.commit().await.map_err(|e| classify_sqlx(&e))
    }

    /// Upstream `createFailure` — classifies the insert failure; a
    /// unique violation either replays (an `equal` stored attempt) or
    /// distinguishes `LIVE_ATTEMPT_EXISTS` from `VERSION_CONFLICT` by
    /// which constraint fired.
    async fn create_failure(&self, a: &Attempt, cause: &sqlx::Error) -> Result<(), Failure> {
        let Some(state) = db_sqlstate(cause) else {
            return Err(classify_sqlx(cause));
        };
        match state.as_str() {
            "23505" => match self.load_attempt(a.workspace_id, a.id).await {
                Ok(stored) if stored.equal(a) => Ok(()),
                Ok(_) => Err(Failure::conflict(
                    codes::VERSION_CONFLICT,
                    format!("attempt {} already exists with different content", a.id),
                )),
                Err(e) if e.code() != codes::ATTEMPT_NOT_FOUND => Err(e),
                Err(_) if db_constraint(cause).as_deref() == Some(CONSTRAINT_LIVE_ATTEMPT) => Err(
                    Failure::conflict(codes::LIVE_ATTEMPT_EXISTS, format!("run {}", a.run_id)),
                ),
                Err(_) => Err(Failure::conflict(
                    codes::VERSION_CONFLICT,
                    format!("attempt id {} is taken", a.id),
                )),
            },
            "23503" => Err(Failure::invalid(
                codes::INVALID_ATTEMPT,
                "unknown run or resumed attempt in workspace",
            )),
            _ if is_invalid_value_sqlstate(&state) => Err(Failure::invalid(
                codes::INVALID_ATTEMPT,
                "attempt value violates a stored constraint",
            )),
            _ => Err(classify_sqlx(cause)),
        }
    }

    /// Upstream `Load` — the stored attempt, or `ATTEMPT_NOT_FOUND`.
    async fn load_attempt(
        &self,
        workspace_id: WorkspaceId,
        id: HarnessAttemptId,
    ) -> Result<Attempt, Failure> {
        if workspace_id.is_nil() || id.is_nil() {
            return Err(Failure::invalid(
                codes::INVALID_ATTEMPT,
                "load requires workspace and attempt ids",
            ));
        }
        let mut tx = self.begin().await?;
        let row = sqlx::query_as!(
            AttemptRow,
            "SELECT workspace_id, id, run_id, kind, adapter_version, harness_version, harness_session_id,
                    resume_of, resume_session_id, workspace_path, base_sha, permission, sandbox_scope_id,
                    fence_generation, version, state, pending_permission, terminal_status, terminal_reason,
                    terminal_exit_code, resolution_kind, resolution_decided_by, ambiguity_reason, last_event_seq,
                    usage_tokens_in, usage_tokens_out, usage_cache_read, usage_cache_write, usage_cost_micro_usd,
                    usage_scope, usage_estimated, prepared_at, updated_at, ended_at,
                    budget_cost_micro_usd, budget_wall_clock_seconds, budget_cost_defaulted,
                    budget_wall_clock_defaulted
             FROM central.harness_attempts
             WHERE workspace_id = $1 AND id = $2",
            uuid_of(workspace_id.as_bytes()),
            uuid_of(id.as_bytes()),
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        let Some(row) = row else {
            return Err(Failure::not_found(
                codes::ATTEMPT_NOT_FOUND,
                format!("attempt {id}"),
            ));
        };
        let a = attempt_from_row(row)?;
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(a)
    }

    /// Upstream `LiveAttemptForRun` — the run's live (non-terminal)
    /// attempt, if any.
    async fn live_attempt_for_run_inner(
        &self,
        workspace_id: WorkspaceId,
        run: RunId,
    ) -> Result<Option<Attempt>, Failure> {
        if workspace_id.is_nil() || run.is_nil() {
            return Err(Failure::invalid(
                codes::INVALID_ATTEMPT,
                "live lookup requires workspace and run ids",
            ));
        }
        let mut tx = self.begin().await?;
        let row = sqlx::query_as!(
            AttemptRow,
            "SELECT workspace_id, id, run_id, kind, adapter_version, harness_version, harness_session_id,
                    resume_of, resume_session_id, workspace_path, base_sha, permission, sandbox_scope_id,
                    fence_generation, version, state, pending_permission, terminal_status, terminal_reason,
                    terminal_exit_code, resolution_kind, resolution_decided_by, ambiguity_reason, last_event_seq,
                    usage_tokens_in, usage_tokens_out, usage_cache_read, usage_cache_write, usage_cost_micro_usd,
                    usage_scope, usage_estimated, prepared_at, updated_at, ended_at,
                    budget_cost_micro_usd, budget_wall_clock_seconds, budget_cost_defaulted,
                    budget_wall_clock_defaulted
             FROM central.harness_attempts
             WHERE workspace_id = $1 AND run_id = $2
               AND state IN ('prepared','launching','running','awaiting_permission','ambiguous')",
            uuid_of(workspace_id.as_bytes()),
            uuid_of(run.as_bytes()),
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        let a = row.map(attempt_from_row).transpose()?;
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(a)
    }

    /// Upstream `LatestAttemptForRun` — the run's most recently prepared
    /// attempt (`prepared_at DESC, id DESC`), live or terminal.
    async fn latest_attempt_for_run_inner(
        &self,
        workspace_id: WorkspaceId,
        run: RunId,
    ) -> Result<Option<Attempt>, Failure> {
        if workspace_id.is_nil() || run.is_nil() {
            return Err(Failure::invalid(
                codes::INVALID_ATTEMPT,
                "run lookup requires workspace and run ids",
            ));
        }
        let mut tx = self.begin().await?;
        let row = sqlx::query_as!(
            AttemptRow,
            "SELECT workspace_id, id, run_id, kind, adapter_version, harness_version, harness_session_id,
                    resume_of, resume_session_id, workspace_path, base_sha, permission, sandbox_scope_id,
                    fence_generation, version, state, pending_permission, terminal_status, terminal_reason,
                    terminal_exit_code, resolution_kind, resolution_decided_by, ambiguity_reason, last_event_seq,
                    usage_tokens_in, usage_tokens_out, usage_cache_read, usage_cache_write, usage_cost_micro_usd,
                    usage_scope, usage_estimated, prepared_at, updated_at, ended_at,
                    budget_cost_micro_usd, budget_wall_clock_seconds, budget_cost_defaulted,
                    budget_wall_clock_defaulted
             FROM central.harness_attempts
             WHERE workspace_id = $1 AND run_id = $2
             ORDER BY prepared_at DESC, id DESC
             LIMIT 1",
            uuid_of(workspace_id.as_bytes()),
            uuid_of(run.as_bytes()),
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        let a = row.map(attempt_from_row).transpose()?;
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(a)
    }

    /// Upstream `AttemptsForRun` — every attempt of the run, oldest
    /// prepared first; more than `MAX_ATTEMPTS_FOR_RUN` is refused
    /// (never truncated).
    async fn attempts_for_run_inner(
        &self,
        workspace_id: WorkspaceId,
        run: RunId,
    ) -> Result<Vec<Attempt>, Failure> {
        if workspace_id.is_nil() || run.is_nil() {
            return Err(Failure::invalid(
                codes::INVALID_ATTEMPT,
                "run attempts read requires workspace and run ids",
            ));
        }
        let mut tx = self.begin().await?;
        let rows = sqlx::query_as!(
            AttemptRow,
            "SELECT workspace_id, id, run_id, kind, adapter_version, harness_version, harness_session_id,
                    resume_of, resume_session_id, workspace_path, base_sha, permission, sandbox_scope_id,
                    fence_generation, version, state, pending_permission, terminal_status, terminal_reason,
                    terminal_exit_code, resolution_kind, resolution_decided_by, ambiguity_reason, last_event_seq,
                    usage_tokens_in, usage_tokens_out, usage_cache_read, usage_cache_write, usage_cost_micro_usd,
                    usage_scope, usage_estimated, prepared_at, updated_at, ended_at,
                    budget_cost_micro_usd, budget_wall_clock_seconds, budget_cost_defaulted,
                    budget_wall_clock_defaulted
             FROM central.harness_attempts
             WHERE workspace_id = $1 AND run_id = $2
             ORDER BY prepared_at, id
             LIMIT $3",
            uuid_of(workspace_id.as_bytes()),
            uuid_of(run.as_bytes()),
            usize_as_i64(MAX_ATTEMPTS_FOR_RUN + 1),
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        if rows.len() > MAX_ATTEMPTS_FOR_RUN {
            return Err(Failure::invalid(
                codes::INVALID_ATTEMPT,
                format!("run {run} has more than {MAX_ATTEMPTS_FOR_RUN} attempts"),
            ));
        }
        let out = rows
            .into_iter()
            .map(attempt_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(out)
    }

    /// Upstream `CostForTask` — the recorded cost of every attempt of
    /// every run of the task within the workspace, in micro-USD,
    /// saturating at `i64::MAX` in SQL (`LEAST`), never overflowing.
    async fn cost_for_task_inner(
        &self,
        workspace_id: WorkspaceId,
        task: TaskId,
    ) -> Result<i64, Failure> {
        if workspace_id.is_nil() || task.is_nil() {
            return Err(Failure::invalid(
                codes::INVALID_ATTEMPT,
                "task cost read requires workspace and task ids",
            ));
        }
        let mut tx = self.begin().await?;
        let used = sqlx::query_scalar!(
            "SELECT LEAST(COALESCE(SUM(a.usage_cost_micro_usd), 0), 9223372036854775807)::bigint
             FROM central.runs r
             JOIN central.harness_attempts a ON a.workspace_id = r.workspace_id AND a.run_id = r.id
             WHERE r.workspace_id = $1 AND r.task_id = $2",
            uuid_of(workspace_id.as_bytes()),
            uuid_of(task.as_bytes()),
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(used.unwrap_or(0))
    }

    /// Upstream `Save` — replaces `expected` with `next` under a
    /// compare-and-swap on `expected`'s version and fence; returns the
    /// stored attempt at `version + 1`. `save` never moves the event
    /// cursor or usage; the approval side follows `plan_approval_write`.
    async fn save_attempt(
        &self,
        expected: &Attempt,
        next: &Attempt,
        open: &[ApprovalOpen],
    ) -> Result<Attempt, Failure> {
        if next.last_event_seq != expected.last_event_seq || next.usage != expected.usage {
            return Err(Failure::invalid(
                codes::INVALID_EVENT,
                "save must not move the event cursor or usage; use append_event",
            ));
        }
        let stored = prepare_write(expected, next)?;
        let approvals = plan_approval_write(expected, next, open)?;
        let mut tx = self.begin().await?;
        let lock = lock_attempt(&mut tx, expected).await?;
        if let Err(e) = self.assert_lease(&mut tx, next).await {
            let _ = tx.rollback().await;
            return Err(e);
        }
        compare_and_swap(&mut tx, expected, &lock, &stored).await?;
        approvals.apply(&mut tx, next).await?;
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(stored)
    }

    /// Upstream `AppendEvent` — records `rec` and applies `save`'s
    /// compare-and-swap in one transaction, so the event cursor can
    /// never run ahead of, or behind, the recorded events. A replay of
    /// an already-recorded `(attempt_id, seq)` returns the stored
    /// attempt and writes nothing; the same seq under another frame
    /// digest is `EVENT_CONFLICT`.
    async fn append_event_inner(
        &self,
        expected: &Attempt,
        next: &Attempt,
        rec: &EventRecord,
        open: &[ApprovalOpen],
    ) -> Result<Attempt, Failure> {
        let stored = prepare_write(expected, next)?;
        let approvals = plan_approval_write(expected, next, open)?;
        rec.validate()?;
        if rec.attempt != next.id {
            return Err(Failure::invalid(
                codes::INVALID_EVENT,
                "record belongs to another attempt",
            ));
        }
        if next.last_event_seq != rec.seq || rec.seq <= expected.last_event_seq {
            return Err(Failure::invalid(
                codes::INVALID_EVENT,
                "record seq must be the next cursor, after the expected one",
            ));
        }
        let seq = seq_as_i64(rec.seq)?;
        let mut tx = self.begin().await?;
        let lock = lock_attempt(&mut tx, expected).await?;
        if let Err(e) = self.assert_lease(&mut tx, next).await {
            let _ = tx.rollback().await;
            return Err(e);
        }
        let tag = sqlx::query!(
            "INSERT INTO central.harness_events (
                workspace_id, attempt_id, seq, kind, at, harness_session_id, raw_size, raw_sha256,
                tool_call_id, tool_name, tool_status, permission_request_id, permission_outcome, terminal_status
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14
            )
            ON CONFLICT (attempt_id, seq) DO NOTHING",
            uuid_of(next.workspace_id.as_bytes()),
            uuid_of(rec.attempt.as_bytes()),
            seq,
            rec.kind.as_str(),
            stored_time(rec.at),
            nonempty(&rec.harness_session_id),
            rec.raw_size,
            &rec.raw_sha256[..],
            nonempty(&rec.tool_call_id),
            nonempty(&rec.tool_name),
            nonempty(rec.tool_status.as_str()),
            nonempty(&rec.permission_request_id),
            nonempty(rec.permission_outcome.as_str()),
            nonempty(rec.terminal_status.as_str()),
        )
        .execute(&mut *tx)
        .await;
        let tag = match tag {
            Ok(tag) => tag,
            Err(e) => {
                let state = db_sqlstate(&e);
                if state
                    .as_deref()
                    .is_some_and(|c| is_invalid_value_sqlstate(c) || c == "23503")
                {
                    return Err(Failure::invalid(
                        codes::INVALID_EVENT,
                        "event value violates a stored constraint",
                    ));
                }
                return Err(classify_sqlx(&e));
            }
        };
        if tag.rows_affected() == 0 {
            let current = replay_event(&mut tx, next, rec, seq, lock.last_event_seq).await?;
            tx.commit().await.map_err(|e| classify_sqlx(&e))?;
            return Ok(current);
        }
        compare_and_swap(&mut tx, expected, &lock, &stored).await?;
        approvals.apply(&mut tx, next).await?;
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(stored)
    }

    /// Upstream `LoadApproval` — one approval of the workspace in its
    /// current state, or `NO_PENDING_APPROVAL` when there is none.
    pub(crate) async fn load_approval_inner(
        &self,
        workspace_id: WorkspaceId,
        id: central_foundation::identity::HarnessPermissionApprovalId,
    ) -> Result<central_harness::approval::PermissionApproval, Failure> {
        if workspace_id.is_nil() || id.is_nil() {
            return Err(Failure::invalid(
                codes::INVALID_APPROVAL,
                "load needs workspace and approval ids",
            ));
        }
        let mut tx = self.begin().await?;
        let row = sqlx::query_as!(
            ApprovalRow,
            "SELECT approval.workspace_id, approval.id, approval.attempt_id, approval.task_id,
                    approval.run_id, approval.request_id, approval.tool_call_id, approval.tool_name,
                    approval.input_mac, approval.input_size, approval.state, approval.requested_at,
                    approval.expires_at, approval.decided_at, approval.decided_by, approval.version
             FROM central.harness_permission_approvals approval
             WHERE approval.workspace_id = $1 AND approval.id = $2",
            uuid_of(workspace_id.as_bytes()),
            uuid_of(id.as_bytes()),
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        let Some(row) = row else {
            return Err(Failure::not_found(
                codes::NO_PENDING_APPROVAL,
                format!("approval {id}"),
            ));
        };
        let a = approval_from_row(row)?;
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(a)
    }
}

// ---------------------------------------------------------------------------
// The write pipeline's pure halves — prepareWrite, lockAttempt,
// compareAndSwap, replayEvent (upstream store.go).
// ---------------------------------------------------------------------------

/// The row `lock_attempt` reads — what the compare-and-swap and the
/// replay check compare against.
pub(crate) struct AttemptLock {
    pub version: i64,
    pub fence_generation: i64,
    pub last_event_seq: i64,
}

/// Upstream `prepareWrite`: checks `next` against `expected` and returns
/// the attempt as it will be stored (`version + 1`, times at storage
/// precision).
pub(crate) fn prepare_write(expected: &Attempt, next: &Attempt) -> Result<Attempt, Failure> {
    if expected.id != next.id
        || expected.workspace_id != next.workspace_id
        || expected.run_id != next.run_id
    {
        return Err(Failure::invalid(
            codes::INVALID_ATTEMPT,
            "next must keep the attempt, workspace and run ids",
        ));
    }
    if next.version != expected.version {
        return Err(Failure::conflict(
            codes::VERSION_CONFLICT,
            "next must carry the expected version",
        ));
    }
    // The budget is recorded once, at prepare, and never changes
    // (harness phase 3d decision 2): the update statement does not even
    // write it, so a `next` carrying another budget is refused, never
    // dropped.
    if next.budget != expected.budget {
        return Err(Failure::invalid(
            codes::INVALID_ATTEMPT,
            "the budget cannot change after prepare",
        ));
    }
    if next.equal(expected) {
        return Err(Failure::invalid(
            codes::INVALID_ATTEMPT,
            "next changes nothing",
        ));
    }
    next.validate()?;
    let mut stored = next.clone();
    stored.version = expected.version + 1;
    stored.prepared_at = stored_time(stored.prepared_at);
    stored.updated_at = stored_time(stored.updated_at);
    stored.ended_at = stored.ended_at.map(stored_time);
    Ok(stored)
}

/// Upstream `lockAttempt` — locks the attempt row and returns its
/// version, fence generation and event cursor.
pub(crate) async fn lock_attempt(
    tx: &mut Transaction<'static, Postgres>,
    expected: &Attempt,
) -> Result<AttemptLock, Failure> {
    sqlx::query!(
        "SELECT version, fence_generation, last_event_seq
         FROM central.harness_attempts
         WHERE workspace_id = $1 AND id = $2
         FOR UPDATE",
        uuid_of(expected.workspace_id.as_bytes()),
        uuid_of(expected.id.as_bytes()),
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| classify_sqlx(&e))?
    .map(|r| AttemptLock {
        version: r.version,
        fence_generation: r.fence_generation,
        last_event_seq: r.last_event_seq,
    })
    .ok_or_else(|| Failure::not_found(codes::ATTEMPT_NOT_FOUND, format!("attempt {}", expected.id)))
}

/// Upstream `compareAndSwap` — distinguishes the two conflict kinds
/// from the locked row, then writes `stored` under the version and
/// fence predicate.
pub(crate) async fn compare_and_swap(
    tx: &mut Transaction<'static, Postgres>,
    expected: &Attempt,
    lock: &AttemptLock,
    stored: &Attempt,
) -> Result<(), Failure> {
    if lock.version != expected.version {
        return Err(Failure::conflict(
            codes::VERSION_CONFLICT,
            format!(
                "attempt {} is at version {}, not {}",
                expected.id, lock.version, expected.version
            ),
        ));
    }
    if lock.fence_generation != expected.fence.generation {
        return Err(Failure::conflict(
            codes::FENCE_MISMATCH,
            format!("attempt {}", expected.id),
        ));
    }
    let done = sqlx::query!(
        "UPDATE central.harness_attempts SET
            kind = $4, adapter_version = $5, harness_version = $6, harness_session_id = $7,
            resume_of = $8, resume_session_id = $9, workspace_path = $10, base_sha = $11,
            permission = $12, sandbox_scope_id = $13, fence_generation = $14, version = $15,
            state = $16, pending_permission = $17, terminal_status = $18, terminal_reason = $19,
            terminal_exit_code = $20, resolution_kind = $21, resolution_decided_by = $22,
            ambiguity_reason = $23, last_event_seq = $24, usage_tokens_in = $25,
            usage_tokens_out = $26, usage_cache_read = $27, usage_cache_write = $28,
            usage_cost_micro_usd = $29, usage_scope = $30, usage_estimated = $31,
            prepared_at = $32, updated_at = $33, ended_at = $34
        WHERE workspace_id = $1 AND id = $2 AND run_id = $3
          AND version = $35 AND fence_generation = $36",
        uuid_of(stored.workspace_id.as_bytes()),
        uuid_of(stored.id.as_bytes()),
        uuid_of(stored.run_id.as_bytes()),
        stored.kind.as_str(),
        stored.adapter_version.as_str(),
        nonempty(&stored.harness_version),
        nonempty(&stored.harness_session_id),
        opt_uuid_of(stored.resume_of, |i| i.as_bytes()),
        nonempty(&stored.resume_session_id),
        stored.workspace.path.as_str(),
        stored.workspace.base_sha.as_str(),
        stored.permission.as_str(),
        nonempty(&stored.sandbox_scope_id),
        stored.fence.generation,
        stored.version,
        stored.state.as_str(),
        nonempty(&stored.pending_permission),
        nonempty(stored.terminal.status.as_str()),
        nonempty(&stored.terminal.reason),
        stored.terminal.exit_code.map(i64::from),
        nonempty(stored.resolution.kind.as_str()),
        nonempty(&stored.resolution.decided_by),
        nonempty(&stored.ambiguity_reason),
        seq_as_i64(stored.last_event_seq)?,
        stored.usage.tokens_in,
        stored.usage.tokens_out,
        stored.usage.cache_read,
        stored.usage.cache_write,
        stored.usage.cost_micro_usd,
        nonempty(stored.usage.scope.as_str()),
        stored.usage.estimated,
        stored.prepared_at,
        stored.updated_at,
        stored.ended_at,
        expected.version,
        expected.fence.generation,
    )
    .execute(&mut **tx)
    .await;
    let tag = match done {
        Ok(tag) => tag,
        Err(e) => {
            let state = db_sqlstate(&e);
            if state.as_deref() == Some("23505")
                && db_constraint(&e).as_deref() == Some(CONSTRAINT_LIVE_ATTEMPT)
            {
                return Err(Failure::conflict(
                    codes::LIVE_ATTEMPT_EXISTS,
                    format!("run {}", expected.run_id),
                ));
            }
            if state
                .as_deref()
                .is_some_and(|c| is_invalid_value_sqlstate(c) || c == "23503")
            {
                return Err(Failure::invalid(
                    codes::INVALID_ATTEMPT,
                    "attempt value violates a stored constraint",
                ));
            }
            return Err(classify_sqlx(&e));
        }
    };
    if tag.rows_affected() != 1 {
        return Err(Failure::conflict(
            codes::VERSION_CONFLICT,
            format!("attempt {} changed under the lock", expected.id),
        ));
    }
    Ok(())
}

/// Upstream `replayEvent` — resolves an insert that found
/// `(attempt_id, seq)` already recorded: the stored digest must match
/// (else `EVENT_CONFLICT`), the recorded seq must not run ahead of the
/// attempt's cursor, and the answer is the attempt as stored now.
async fn replay_event(
    tx: &mut Transaction<'static, Postgres>,
    next: &Attempt,
    rec: &EventRecord,
    seq: i64,
    last_seq: i64,
) -> Result<Attempt, Failure> {
    let digest = sqlx::query_scalar!(
        "SELECT raw_sha256 FROM central.harness_events
         WHERE workspace_id = $1 AND attempt_id = $2 AND seq = $3",
        uuid_of(next.workspace_id.as_bytes()),
        uuid_of(rec.attempt.as_bytes()),
        seq,
    )
    .fetch_one(&mut **tx)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    if digest != rec.raw_sha256 {
        return Err(Failure::conflict(
            codes::EVENT_CONFLICT,
            format!(
                "attempt {} seq {} was recorded with another frame",
                rec.attempt, rec.seq
            ),
        ));
    }
    if last_seq < seq {
        return Err(Failure::conflict(
            codes::EVENT_CONFLICT,
            format!(
                "attempt {} seq {} is recorded ahead of the attempt's cursor",
                rec.attempt, rec.seq
            ),
        ));
    }
    let row = sqlx::query_as!(
        AttemptRow,
        "SELECT workspace_id, id, run_id, kind, adapter_version, harness_version, harness_session_id,
                resume_of, resume_session_id, workspace_path, base_sha, permission, sandbox_scope_id,
                fence_generation, version, state, pending_permission, terminal_status, terminal_reason,
                terminal_exit_code, resolution_kind, resolution_decided_by, ambiguity_reason, last_event_seq,
                usage_tokens_in, usage_tokens_out, usage_cache_read, usage_cache_write, usage_cost_micro_usd,
                usage_scope, usage_estimated, prepared_at, updated_at, ended_at,
                budget_cost_micro_usd, budget_wall_clock_seconds, budget_cost_defaulted,
                budget_wall_clock_defaulted
         FROM central.harness_attempts
         WHERE workspace_id = $1 AND id = $2",
        uuid_of(next.workspace_id.as_bytes()),
        uuid_of(next.id.as_bytes()),
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    let Some(row) = row else {
        return Err(corrupt("the locked attempt row is missing"));
    };
    attempt_from_row(row)
}

// ---------------------------------------------------------------------------
// The port trait impls — hand-written `PortFuture`s (dyn-compatible).
// ---------------------------------------------------------------------------

impl AttemptStore for PgHarnessStore {
    fn create<'a>(&'a self, attempt: &'a Attempt) -> PortFuture<'a, Result<(), Failure>> {
        Box::pin(async move { self.create_attempt(attempt).await })
    }

    fn load<'a>(
        &'a self,
        workspace_id: WorkspaceId,
        id: HarnessAttemptId,
    ) -> PortFuture<'a, Result<Attempt, Failure>> {
        Box::pin(async move { self.load_attempt(workspace_id, id).await })
    }

    fn live_attempt_for_run<'a>(
        &'a self,
        workspace_id: WorkspaceId,
        run: RunId,
    ) -> PortFuture<'a, Result<Option<Attempt>, Failure>> {
        Box::pin(async move { self.live_attempt_for_run_inner(workspace_id, run).await })
    }

    fn save<'a>(
        &'a self,
        expected: &'a Attempt,
        next: &'a Attempt,
        open: &'a [ApprovalOpen],
    ) -> PortFuture<'a, Result<Attempt, Failure>> {
        Box::pin(async move { self.save_attempt(expected, next, open).await })
    }

    fn append_event<'a>(
        &'a self,
        expected: &'a Attempt,
        next: &'a Attempt,
        rec: &'a EventRecord,
        open: &'a [ApprovalOpen],
    ) -> PortFuture<'a, Result<Attempt, Failure>> {
        Box::pin(async move { self.append_event_inner(expected, next, rec, open).await })
    }

    fn expire_permission<'a>(
        &'a self,
        attempt: &'a Attempt,
        id: central_foundation::identity::HarnessPermissionApprovalId,
    ) -> PortFuture<'a, Result<central_harness::approval::PermissionApproval, Failure>> {
        Box::pin(async move { self.expire_permission_inner(attempt, id).await })
    }

    fn load_approval<'a>(
        &'a self,
        workspace_id: WorkspaceId,
        id: central_foundation::identity::HarnessPermissionApprovalId,
    ) -> PortFuture<'a, Result<central_harness::approval::PermissionApproval, Failure>> {
        Box::pin(async move { self.load_approval_inner(workspace_id, id).await })
    }
}

impl LeaseBinder for PgHarnessStore {
    /// Upstream `WithLease` — synchronous: binding performs no I/O; the
    /// lease is re-checked inside every write's transaction.
    fn with_lease(&self, lease: ExecutionLease) -> Box<dyn AttemptStore> {
        Box::new(PgHarnessStore {
            pool: self.pool.clone(),
            lease: Some(lease),
        })
    }
}

// ---------------------------------------------------------------------------
// The query.rs read projections.
// ---------------------------------------------------------------------------

impl AttemptSummaryRead for PgHarnessStore {
    async fn latest_attempt_for_run(
        &self,
        workspace_id: WorkspaceId,
        run: RunId,
    ) -> Result<Option<Attempt>, Failure> {
        self.latest_attempt_for_run_inner(workspace_id, run).await
    }

    async fn attempts_for_run(
        &self,
        workspace_id: WorkspaceId,
        run: RunId,
    ) -> Result<Vec<Attempt>, Failure> {
        self.attempts_for_run_inner(workspace_id, run).await
    }
}

impl BudgetUsageRead for PgHarnessStore {
    async fn cost_for_task(&self, workspace_id: WorkspaceId, task: TaskId) -> Result<i64, Failure> {
        self.cost_for_task_inner(workspace_id, task).await
    }
}

impl HarnessEventRead for PgHarnessStore {
    /// The seek-cursor read over `central.harness_events` — `seq`
    /// ascending, strictly after the cursor, never `OFFSET`. An
    /// out-of-range page returns empty.
    async fn read_page(&self, req: HarnessEventRequest) -> Result<HarnessEventPage, Failure> {
        validate_harness_event_request(&req)?;
        let limit = normalize_harness_event_page_size(req.page_size);
        let take = usize::try_from(limit).unwrap_or(usize::MAX);
        let cursor_seq = match req.cursor {
            Some(c) => seq_as_i64(c.seq)?,
            None => 0,
        };
        let mut tx = self.begin().await?;
        let rows = sqlx::query_as!(
            EventRecordRow,
            "SELECT attempt_id, seq, kind, at, harness_session_id, raw_size, raw_sha256,
                    tool_call_id, tool_name, tool_status, permission_request_id,
                    permission_outcome, terminal_status
             FROM central.harness_events
             WHERE workspace_id = $1 AND attempt_id = $2 AND seq > $3
             ORDER BY seq
             LIMIT $4",
            uuid_of(req.workspace_id.as_bytes()),
            uuid_of(req.attempt_id.as_bytes()),
            cursor_seq,
            i64::from(limit) + 1,
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        let has_more = rows.len() > take;
        let rows: Vec<EventRecordRow> = rows.into_iter().take(take).collect();
        let mut records: Vec<EventRecord> = Vec::with_capacity(rows.len());
        for row in rows {
            records.push(event_record_from_row(row)?);
        }
        let next_cursor = if has_more {
            records
                .last()
                .map(|r| central_harness::query::HarnessEventCursor {
                    attempt_id: r.attempt,
                    seq: r.seq,
                })
        } else {
            None
        };
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(HarnessEventPage {
            records,
            next_cursor,
        })
    }
}
