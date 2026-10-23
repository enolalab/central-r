//! The permission-approval side of the harness stores — port of
//! upstream `approval.go`: the write plan (`approvalWrite`/
//! `planApprovalWrite`), the operator's compare-and-set
//! `DecidePermission`, the timeout's `ExpirePermission`, and the
//! workspace-scoped approval reads (`LoadApproval`,
//! `PendingApprovalForRun`, `PendingApprovals`, `ApprovalHistory`).

use central_foundation::failure::Failure;
use central_foundation::identity::{HarnessPermissionApprovalId, RunId, TaskId, WorkspaceId};
use central_harness::approval::{
    ApprovalState, MAX_DECIDED_BY_BYTES, PermissionApproval, is_operator_decider,
};
use central_harness::attempt::Attempt;
use central_harness::domain::codes;
use central_harness::port::{
    ApprovalOpen, ApprovalStore, DecidePermissionRequest, MAX_APPROVAL_HISTORY,
    PendingApprovalSummary, PortFuture, opens_approval, supersedes_approvals,
};
use central_harness::query::PendingApprovalRead;
use sqlx::{Postgres, Transaction};
use time::OffsetDateTime;

use super::queries::{
    ApprovalRow, approval_from_row, corrupt, db_sqlstate, is_invalid_value_sqlstate, nonempty,
    stored_time,
};
use super::store::{PgHarnessStore, lock_attempt};
use crate::error::classify_sqlx;
use crate::store_support::{usize_as_i64, uuid_of};

// ---------------------------------------------------------------------------
// approvalWrite — the approval side of one attempt write (harness phase 3c
// decision 16): the pending approval it opens, if any, and whether it
// supersedes the attempt's pending approval.
// ---------------------------------------------------------------------------

/// Upstream `approvalWrite`.
pub(crate) struct ApprovalWrite {
    pub open: Option<PermissionApproval>,
    pub supersede: bool,
    pub at: OffsetDateTime,
}

/// Upstream `planApprovalWrite`: validates an attempt write's approval
/// side. At most one `ApprovalOpen` is accepted, and only when `next`
/// enters `awaiting_permission` with its request id as a new
/// `pending_permission`.
pub(crate) fn plan_approval_write(
    expected: &Attempt,
    next: &Attempt,
    opens: &[ApprovalOpen],
) -> Result<ApprovalWrite, Failure> {
    let mut plan = ApprovalWrite {
        open: None,
        supersede: supersedes_approvals(next),
        at: stored_time(next.updated_at),
    };
    let [o] = opens else {
        if opens.is_empty() {
            return Ok(plan);
        }
        return Err(Failure::invalid(
            codes::INVALID_APPROVAL,
            "a write opens at most one approval",
        ));
    };
    if !opens_approval(expected, next, &o.request_id) {
        return Err(Failure::invalid(
            codes::INVALID_APPROVAL,
            "an approval opens only as the attempt starts awaiting its request",
        ));
    }
    let mut stored = next.clone();
    stored.updated_at = plan.at;
    let mut a = o.approval(&stored)?;
    a.expires_at = stored_time(a.expires_at);
    a.validate()?;
    plan.open = Some(a);
    Ok(plan)
}

impl ApprovalWrite {
    /// Upstream `approvalWrite.apply` — writes the approval side inside
    /// the attempt write's transaction, after the attempt's
    /// compare-and-swap.
    pub(crate) async fn apply(
        &self,
        tx: &mut Transaction<'static, Postgres>,
        next: &Attempt,
    ) -> Result<(), Failure> {
        if self.supersede {
            sqlx::query!(
                "UPDATE central.harness_permission_approvals
                 SET state = 'superseded', decided_by = 'system:superseded',
                     decided_at = GREATEST(requested_at, $3), version = version + 1
                 WHERE workspace_id = $1 AND attempt_id = $2 AND state = 'pending'",
                uuid_of(next.workspace_id.as_bytes()),
                uuid_of(next.id.as_bytes()),
                self.at,
            )
            .execute(&mut **tx)
            .await
            .map_err(|e| classify_sqlx(&e))?;
        }
        let Some(a) = &self.open else {
            return Ok(());
        };
        // A replayed event never reaches this insert (append_event's
        // replay path writes nothing), so a conflict is a real
        // duplicate and fails the write. The row is written only when
        // `task_id` is the task of `run_id` in the workspace (upstream
        // review M5-4): no row inserted means the approval names
        // another task.
        let tag = sqlx::query!(
            "INSERT INTO central.harness_permission_approvals (
                workspace_id, id, attempt_id, task_id, run_id, request_id, tool_call_id, tool_name,
                input_mac, input_size, state, requested_at, expires_at, version
            )
            SELECT
                $1, $2, $3, run.task_id, run.id, $6, $7, $8,
                $9, $10, 'pending', $11, $12, 0
            FROM central.runs run
            WHERE run.workspace_id = $1 AND run.id = $5 AND run.task_id = $4",
            uuid_of(a.workspace_id.as_bytes()),
            uuid_of(a.id.as_bytes()),
            uuid_of(a.attempt_id.as_bytes()),
            uuid_of(a.task_id.as_bytes()),
            uuid_of(a.run_id.as_bytes()),
            a.request_id.as_str(),
            nonempty(&a.tool_call_id),
            a.tool_name.as_str(),
            &a.input_mac.0[..],
            a.input_size,
            a.requested_at,
            a.expires_at,
        )
        .execute(&mut **tx)
        .await;
        let tag = match tag {
            Ok(tag) => tag,
            Err(e) => {
                let state = db_sqlstate(&e);
                if state
                    .as_deref()
                    .is_some_and(|c| c == "23505" || c == "23503" || is_invalid_value_sqlstate(c))
                {
                    return Err(Failure::invalid(
                        codes::INVALID_APPROVAL,
                        "approval violates a stored constraint",
                    ));
                }
                return Err(classify_sqlx(&e));
            }
        };
        if tag.rows_affected() != 1 {
            // The failure rolls back the whole write, the attempt's
            // included.
            return Err(Failure::invalid(
                codes::INVALID_APPROVAL,
                "the approval's task is not its run's task",
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The store's approval methods — DecidePermission, ExpirePermission, and
// the reads.
// ---------------------------------------------------------------------------

impl PgHarnessStore {
    /// Upstream `DecidePermission` — the operator's compare-and-set
    /// (decision 8). A decision that no longer applies matches no row:
    /// `NO_PENDING_APPROVAL`, and nothing is written.
    pub(crate) async fn decide_permission_inner(
        &self,
        req: DecidePermissionRequest,
    ) -> Result<PermissionApproval, Failure> {
        if req.workspace_id.is_nil() || req.approval_id.is_nil() {
            return Err(Failure::invalid(
                codes::INVALID_APPROVAL,
                "a decision needs workspace and approval ids",
            ));
        }
        if !is_operator_decider(&req.decided_by) || req.decided_by.len() > MAX_DECIDED_BY_BYTES {
            return Err(Failure::invalid(
                codes::INVALID_APPROVAL,
                "a decision needs an operator decider",
            ));
        }
        if req.input_mac.is_zero() {
            return Err(Failure::invalid(
                codes::INVALID_APPROVAL,
                "a decision needs the input MAC",
            ));
        }
        let state = if req.allow {
            ApprovalState::Allowed
        } else {
            ApprovalState::Denied
        };
        let mut tx = self.begin().await?;
        // pending -> $4 by $5, only while the approval is unexpired, its
        // MAC is $3, the attempt awaits exactly its request, and an
        // unexpired execution lease claims the run's StepAttempt linked
        // to the attempt at the attempt's fence (the ownership join,
        // without the bearer). The lease and attempt rows are
        // share-locked, so a reclaim cannot commit between the check
        // and the decision.
        let row = sqlx::query_as!(
            ApprovalRow,
            "WITH live AS (
                SELECT approval.id
                FROM central.harness_permission_approvals approval
                JOIN central.harness_attempts attempt
                  ON attempt.workspace_id = approval.workspace_id AND attempt.id = approval.attempt_id
                JOIN central.execution_ownership ownership
                  ON ownership.workspace_id = attempt.workspace_id AND ownership.run_id = attempt.run_id
                 AND ownership.claimed_step_attempt_id = attempt.id
                 AND ownership.fencing_generation = attempt.fence_generation
                WHERE approval.workspace_id = $1 AND approval.id = $2
                  AND approval.state = 'pending' AND approval.expires_at > clock_timestamp()
                  AND approval.input_mac = $3
                  AND attempt.state = 'awaiting_permission' AND attempt.pending_permission = approval.request_id
                  AND ownership.lease_expires_at > clock_timestamp()
                FOR SHARE OF attempt, ownership
            )
            UPDATE central.harness_permission_approvals approval
            SET state = $4, decided_by = $5,
                decided_at = GREATEST(approval.requested_at, clock_timestamp()),
                version = approval.version + 1
            FROM live
            WHERE approval.id = live.id AND approval.workspace_id = $1 AND approval.state = 'pending'
            RETURNING approval.workspace_id, approval.id, approval.attempt_id, approval.task_id,
                      approval.run_id, approval.request_id, approval.tool_call_id, approval.tool_name,
                      approval.input_mac, approval.input_size, approval.state, approval.requested_at,
                      approval.expires_at, approval.decided_at, approval.decided_by, approval.version",
            uuid_of(req.workspace_id.as_bytes()),
            uuid_of(req.approval_id.as_bytes()),
            &req.input_mac.0[..],
            state.as_str(),
            req.decided_by.as_str(),
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        let Some(row) = row else {
            return Err(Failure::not_found(
                codes::NO_PENDING_APPROVAL,
                format!("approval {}", req.approval_id),
            ));
        };
        let a = approval_from_row(row)?;
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(a)
    }

    /// Upstream `ExpirePermission` — the timeout's compare-and-set
    /// (decision 9). It runs under `attempt`'s fence and, for a
    /// lease-bound store, the bound lease: a fenced-out orchestrator
    /// can never expire an approval. Not due yet, or decided first:
    /// the row as it stands answers.
    pub(crate) async fn expire_permission_inner(
        &self,
        attempt: &Attempt,
        id: HarnessPermissionApprovalId,
    ) -> Result<PermissionApproval, Failure> {
        if attempt.workspace_id.is_nil() || attempt.id.is_nil() || id.is_nil() {
            return Err(Failure::invalid(
                codes::INVALID_APPROVAL,
                "expiry needs workspace, attempt and approval ids",
            ));
        }
        let mut tx = self.begin().await?;
        let lock = lock_attempt(&mut tx, attempt).await?;
        if lock.fence_generation != attempt.fence.generation {
            return Err(Failure::conflict(
                codes::FENCE_MISMATCH,
                format!("attempt {}", attempt.id),
            ));
        }
        if let Err(e) = self.assert_lease(&mut tx, attempt).await {
            let _ = tx.rollback().await;
            return Err(e);
        }
        let row = sqlx::query_as!(
            ApprovalRow,
            "UPDATE central.harness_permission_approvals approval
             SET state = 'expired', decided_by = 'policy:timeout',
                 decided_at = GREATEST(approval.requested_at, clock_timestamp()),
                 version = approval.version + 1
             WHERE approval.workspace_id = $1 AND approval.id = $2 AND approval.attempt_id = $3
               AND approval.state = 'pending' AND approval.expires_at <= clock_timestamp()
             RETURNING approval.workspace_id, approval.id, approval.attempt_id, approval.task_id,
                       approval.run_id, approval.request_id, approval.tool_call_id, approval.tool_name,
                       approval.input_mac, approval.input_size, approval.state, approval.requested_at,
                       approval.expires_at, approval.decided_at, approval.decided_by, approval.version",
            uuid_of(attempt.workspace_id.as_bytes()),
            uuid_of(id.as_bytes()),
            uuid_of(attempt.id.as_bytes()),
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        let approval = match row {
            Some(row) => approval_from_row(row)?,
            None => {
                // Not due yet, or decided first: the row as it stands
                // answers.
                let current = sqlx::query_as!(
                    ApprovalRow,
                    "SELECT approval.workspace_id, approval.id, approval.attempt_id, approval.task_id,
                            approval.run_id, approval.request_id, approval.tool_call_id, approval.tool_name,
                            approval.input_mac, approval.input_size, approval.state, approval.requested_at,
                            approval.expires_at, approval.decided_at, approval.decided_by, approval.version
                     FROM central.harness_permission_approvals approval
                     WHERE approval.workspace_id = $1 AND approval.id = $2",
                    uuid_of(attempt.workspace_id.as_bytes()),
                    uuid_of(id.as_bytes()),
                )
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| classify_sqlx(&e))?;
                match current {
                    Some(row) => {
                        let cur = approval_from_row(row)?;
                        if cur.attempt_id != attempt.id {
                            return Err(Failure::not_found(
                                codes::NO_PENDING_APPROVAL,
                                format!("approval {id}"),
                            ));
                        }
                        cur
                    }
                    None => {
                        return Err(Failure::not_found(
                            codes::NO_PENDING_APPROVAL,
                            format!("approval {id}"),
                        ));
                    }
                }
            }
        };
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(approval)
    }

    /// Upstream `PendingApprovalForRun` — the run's pending approval,
    /// if any.
    pub(crate) async fn pending_approval_for_run_inner(
        &self,
        workspace_id: WorkspaceId,
        run: RunId,
    ) -> Result<Option<PermissionApproval>, Failure> {
        if workspace_id.is_nil() || run.is_nil() {
            return Err(Failure::invalid(
                codes::INVALID_APPROVAL,
                "read needs workspace and run ids",
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
             WHERE approval.workspace_id = $1 AND approval.run_id = $2 AND approval.state = 'pending'
             ORDER BY approval.requested_at DESC, approval.id DESC
             LIMIT 1",
            uuid_of(workspace_id.as_bytes()),
            uuid_of(run.as_bytes()),
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        let a = row.map(approval_from_row).transpose()?;
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(a)
    }

    /// Upstream `PendingApprovals` — counts the workspace's pending
    /// approvals and names the oldest one's task (the banner, decision
    /// 13).
    pub(crate) async fn pending_approvals_inner(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<PendingApprovalSummary, Failure> {
        if workspace_id.is_nil() {
            return Err(Failure::invalid(
                codes::INVALID_APPROVAL,
                "read needs a workspace id",
            ));
        }
        let mut tx = self.begin().await?;
        let row = sqlx::query!(
            "SELECT count(*) AS count,
                (SELECT oldest.task_id
                 FROM central.harness_permission_approvals oldest
                 WHERE oldest.workspace_id = $1 AND oldest.state = 'pending'
                 ORDER BY oldest.requested_at, oldest.id
                 LIMIT 1) AS oldest_task_id
             FROM central.harness_permission_approvals approval
             WHERE approval.workspace_id = $1 AND approval.state = 'pending'",
            uuid_of(workspace_id.as_bytes()),
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        let out = PendingApprovalSummary {
            count: usize::try_from(row.count.unwrap_or(0))
                .map_err(|_| corrupt("a stored pending-approval count is negative"))?,
            oldest_task_id: row
                .oldest_task_id
                .map(|u| TaskId::from_trusted_db_bytes(*u.as_bytes())),
        };
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(out)
    }

    /// Upstream `ApprovalHistory` — up to `limit` of the run's
    /// approvals, newest first.
    pub(crate) async fn approval_history_inner(
        &self,
        workspace_id: WorkspaceId,
        run: RunId,
        limit: usize,
    ) -> Result<Vec<PermissionApproval>, Failure> {
        if workspace_id.is_nil() || run.is_nil() || !(1..=MAX_APPROVAL_HISTORY).contains(&limit) {
            return Err(Failure::invalid(
                codes::INVALID_APPROVAL,
                format!("history needs workspace and run ids and 1..{MAX_APPROVAL_HISTORY} rows"),
            ));
        }
        let mut tx = self.begin().await?;
        let rows = sqlx::query_as!(
            ApprovalRow,
            "SELECT approval.workspace_id, approval.id, approval.attempt_id, approval.task_id,
                    approval.run_id, approval.request_id, approval.tool_call_id, approval.tool_name,
                    approval.input_mac, approval.input_size, approval.state, approval.requested_at,
                    approval.expires_at, approval.decided_at, approval.decided_by, approval.version
             FROM central.harness_permission_approvals approval
             WHERE approval.workspace_id = $1 AND approval.run_id = $2
             ORDER BY approval.requested_at DESC, approval.id DESC
             LIMIT $3",
            uuid_of(workspace_id.as_bytes()),
            uuid_of(run.as_bytes()),
            usize_as_i64(limit),
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        let out = rows
            .into_iter()
            .map(approval_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// The port trait impls.
// ---------------------------------------------------------------------------

impl ApprovalStore for PgHarnessStore {
    fn decide_permission<'a>(
        &'a self,
        request: DecidePermissionRequest,
    ) -> PortFuture<'a, Result<PermissionApproval, Failure>> {
        Box::pin(async move { self.decide_permission_inner(request).await })
    }

    fn load_approval<'a>(
        &'a self,
        workspace_id: WorkspaceId,
        id: HarnessPermissionApprovalId,
    ) -> PortFuture<'a, Result<PermissionApproval, Failure>> {
        Box::pin(async move { self.load_approval_inner(workspace_id, id).await })
    }

    fn pending_approval_for_run<'a>(
        &'a self,
        workspace_id: WorkspaceId,
        run: RunId,
    ) -> PortFuture<'a, Result<Option<PermissionApproval>, Failure>> {
        Box::pin(async move { self.pending_approval_for_run_inner(workspace_id, run).await })
    }

    fn pending_approvals<'a>(
        &'a self,
        workspace_id: WorkspaceId,
    ) -> PortFuture<'a, Result<PendingApprovalSummary, Failure>> {
        Box::pin(async move { self.pending_approvals_inner(workspace_id).await })
    }

    fn approval_history<'a>(
        &'a self,
        workspace_id: WorkspaceId,
        run: RunId,
        limit: usize,
    ) -> PortFuture<'a, Result<Vec<PermissionApproval>, Failure>> {
        Box::pin(async move { self.approval_history_inner(workspace_id, run, limit).await })
    }
}

impl PendingApprovalRead for PgHarnessStore {
    async fn load_approval(
        &self,
        workspace_id: WorkspaceId,
        id: HarnessPermissionApprovalId,
    ) -> Result<PermissionApproval, Failure> {
        self.load_approval_inner(workspace_id, id).await
    }

    async fn pending_approval_for_run(
        &self,
        workspace_id: WorkspaceId,
        run: RunId,
    ) -> Result<Option<PermissionApproval>, Failure> {
        self.pending_approval_for_run_inner(workspace_id, run).await
    }

    async fn pending_approvals(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<PendingApprovalSummary, Failure> {
        self.pending_approvals_inner(workspace_id).await
    }

    async fn approval_history(
        &self,
        workspace_id: WorkspaceId,
        run: RunId,
        limit: usize,
    ) -> Result<Vec<PermissionApproval>, Failure> {
        self.approval_history_inner(workspace_id, run, limit).await
    }
}
