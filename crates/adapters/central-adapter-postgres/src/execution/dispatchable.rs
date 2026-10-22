//! `ListDispatchableRuns` — port of upstream `dispatchable.go`
//! (`queryListDispatchableRuns`): harness phase 3a decision 1, oldest
//! Task first. Case (a) is a queued Task whose queued current Run has
//! no Step yet; case (b) is a running Task whose current Run holds a
//! prepared successor attempt (`predecessor_id` set) and no live
//! lease. Runs quarantined by the workspace's latest non-completed
//! recovery epoch are excluded (review T-I2) — the commit path
//! re-decides admission under its locks regardless.
//!
//! Upstream binds uuid text and compares `run_id` as `"C"`-collated
//! text; Postgres uuid ordering is the same byte order, so the Rust
//! port keeps the columns typed `uuid`.

use central_execution::domain::LogicalOperationId;
use central_execution::harness_run::ListDispatchableRunsRequest;
use central_execution::harness_run::{DispatchCase, DispatchableRun};
use central_execution::port::DispatchableRunReader;
use central_foundation::failure::Failure;
use central_foundation::identity::{RunId, StepAttemptId, StepId, TaskId, WorkspaceId};
use time::OffsetDateTime;

use super::store::Store;
use super::{begin, invalid};
use crate::error::SqlxContext;

struct DispatchableRow {
    dispatch_case: String,
    workspace_id: uuid::Uuid,
    task_id: uuid::Uuid,
    run_id: uuid::Uuid,
    step_id: Option<uuid::Uuid>,
    attempt_id: Option<uuid::Uuid>,
    logical_operation_id: Option<uuid::Uuid>,
    task_created_at: OffsetDateTime,
}

impl DispatchableRunReader for Store {
    /// `ListDispatchableRuns`.
    async fn list_dispatchable_runs(
        &self,
        request: ListDispatchableRunsRequest,
    ) -> Result<Vec<DispatchableRun>, Failure> {
        request.validate()?;
        let mut tx = begin(&self.pool).await?;
        let rows = sqlx::query_as!(
            DispatchableRow,
            "SELECT dispatch_case AS \"dispatch_case!\", workspace_id AS \"workspace_id!\", \
             task_id AS \"task_id!\", run_id AS \"run_id!\", step_id, \
             attempt_id, logical_operation_id, \
             task_created_at AS \"task_created_at!\" FROM ( \
             SELECT 'queued' AS dispatch_case, \
               task.workspace_id AS workspace_id, task.id AS task_id, \
               run.id AS run_id, NULL::uuid AS step_id, NULL::uuid AS attempt_id, \
               NULL::uuid AS logical_operation_id, task.created_at AS task_created_at, \
               run.created_at AS run_created_at, run.reconciled_epoch AS run_reconciled_epoch \
             FROM central.tasks task \
             JOIN central.runs run \
               ON run.workspace_id = task.workspace_id AND run.task_id = task.id \
              AND run.id = task.current_run_id \
             WHERE task.status = 'queued' AND run.status = 'queued' \
               AND task.created_at >= $1 \
               AND NOT EXISTS ( \
                 SELECT 1 FROM central.steps step \
                 WHERE step.workspace_id = run.workspace_id AND step.run_id = run.id) \
             UNION ALL \
             SELECT 'prepared_successor', \
               task.workspace_id, task.id, run.id, \
               attempt.step_id, attempt.id, \
               attempt.logical_operation_id, task.created_at, \
               run.created_at, run.reconciled_epoch \
             FROM central.tasks task \
             JOIN central.runs run \
               ON run.workspace_id = task.workspace_id AND run.task_id = task.id \
              AND run.id = task.current_run_id \
             JOIN central.step_attempts attempt \
               ON attempt.workspace_id = run.workspace_id AND attempt.run_id = run.id \
              AND attempt.state = 'prepared' AND attempt.predecessor_id IS NOT NULL \
             WHERE task.status = 'running' AND run.status = 'running' \
               AND task.created_at >= $1 \
               AND NOT EXISTS ( \
                 SELECT 1 FROM central.execution_ownership ownership \
                 WHERE ownership.workspace_id = run.workspace_id \
                   AND ownership.run_id = run.id \
                   AND ownership.lease_expires_at > clock_timestamp()) \
             ) dispatchable \
             WHERE NOT EXISTS ( \
               SELECT 1 FROM ( \
                 SELECT epoch.epoch_generation, epoch.state \
                 FROM central.recovery_epochs epoch \
                 WHERE EXISTS ( \
                   SELECT 1 FROM central.recovery_epoch_workspaces scoped \
                   WHERE scoped.epoch_generation = epoch.epoch_generation \
                     AND scoped.workspace_id = dispatchable.workspace_id) \
                 ORDER BY epoch.epoch_generation DESC LIMIT 1 \
               ) latest \
               JOIN central.recovery_epoch_workspaces work \
                 ON work.epoch_generation = latest.epoch_generation \
                AND work.workspace_id = dispatchable.workspace_id \
               WHERE latest.state <> 'completed' \
                 AND work.delivery_state <> 'completed' \
                 AND dispatchable.run_reconciled_epoch < latest.epoch_generation \
                 AND (dispatchable.run_created_at < work.watermark_created_at \
                      OR (dispatchable.run_created_at = work.watermark_created_at \
                          AND dispatchable.run_id <= work.watermark_run_id)) \
             ) \
             ORDER BY task_created_at, run_id LIMIT $2",
            request.eligible_after,
            i64::from(request.limit),
        )
        .fetch_all(&mut *tx)
        .await
        .ctx("execution: list dispatchable runs")?;
        tx.commit()
            .await
            .ctx("execution: commit dispatchable list")?;
        rows.into_iter()
            .map(|row| {
                let case = DispatchCase::parse(&row.dispatch_case)
                    .ok_or_else(|| invalid("pg_data_corrupt"))?;
                Ok(DispatchableRun {
                    case,
                    workspace_id: WorkspaceId::from_trusted_db_bytes(*row.workspace_id.as_bytes()),
                    task_id: TaskId::from_trusted_db_bytes(*row.task_id.as_bytes()),
                    run_id: RunId::from_trusted_db_bytes(*row.run_id.as_bytes()),
                    step_id: row.step_id.map_or_else(
                        || StepId::from_trusted_db_bytes([0; 16]),
                        |u| StepId::from_trusted_db_bytes(*u.as_bytes()),
                    ),
                    attempt_id: row.attempt_id.map_or_else(
                        || StepAttemptId::from_trusted_db_bytes([0; 16]),
                        |u| StepAttemptId::from_trusted_db_bytes(*u.as_bytes()),
                    ),
                    logical_operation: row.logical_operation_id.map_or_else(
                        || LogicalOperationId([0; 16]),
                        |u| LogicalOperationId(*u.as_bytes()),
                    ),
                    task_created_at: row.task_created_at,
                })
            })
            .collect()
    }
}
