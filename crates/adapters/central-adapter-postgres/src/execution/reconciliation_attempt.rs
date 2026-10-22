//! `ReconciliationAttempt` / `PreparedAttempt` — port of upstream
//! `reconciliation_attempt.go`. Both name the Run's newest StepAttempt
//! in one state (`reconciliation` for the phase-3a operator resolve
//! path, `prepared` for the never-invoked cancel path); an absent row
//! is `None`, not an error.

use central_foundation::failure::Failure;
use central_foundation::identity::{RunId, StepAttemptId, StepId, WorkspaceId};

use super::store::Store;
use super::{begin, invalid};
use crate::error::SqlxContext;

impl Store {
    /// `ReconciliationAttempt` — the Step and StepAttempt waiting in
    /// reconciliation (B08 moves at most one per Run there).
    pub async fn reconciliation_attempt(
        &self,
        ws: WorkspaceId,
        run: RunId,
    ) -> Result<Option<(StepId, StepAttemptId)>, Failure> {
        self.run_attempt_in(ws, run, "reconciliation").await
    }

    /// `PreparedAttempt` — the Run's newest prepared StepAttempt: a
    /// claimed attempt stopped before `MarkInvoked`, or the prepared
    /// successor B08 recovery keeps for it (harness phase 3f d.10).
    pub async fn prepared_attempt(
        &self,
        ws: WorkspaceId,
        run: RunId,
    ) -> Result<Option<(StepId, StepAttemptId)>, Failure> {
        self.run_attempt_in(ws, run, "prepared").await
    }

    /// `runAttemptIn` — newest attempt of the run in `state`.
    async fn run_attempt_in(
        &self,
        ws: WorkspaceId,
        run: RunId,
        state: &'static str,
    ) -> Result<Option<(StepId, StepAttemptId)>, Failure> {
        if ws.is_nil() || run.is_nil() {
            return Err(invalid("INVALID_ATTEMPT_READ"));
        }
        let mut tx = begin(&self.pool).await?;
        // Both variants stay literal so sqlx checks each.
        let row = if state == "reconciliation" {
            sqlx::query!(
                "SELECT step_id, id FROM central.step_attempts \
                 WHERE workspace_id = $1 AND run_id = $2 AND state = 'reconciliation' \
                 ORDER BY sequence DESC, id DESC LIMIT 1",
                super::uuid_of(ws.as_bytes()),
                super::uuid_of(run.as_bytes()),
            )
            .fetch_optional(&mut *tx)
            .await
            .ctx("execution: read reconciliation attempt")?
            .map(|r| (r.step_id, r.id))
        } else {
            sqlx::query!(
                "SELECT step_id, id FROM central.step_attempts \
                 WHERE workspace_id = $1 AND run_id = $2 AND state = 'prepared' \
                 ORDER BY sequence DESC, id DESC LIMIT 1",
                super::uuid_of(ws.as_bytes()),
                super::uuid_of(run.as_bytes()),
            )
            .fetch_optional(&mut *tx)
            .await
            .ctx("execution: read prepared attempt")?
            .map(|r| (r.step_id, r.id))
        };
        tx.commit().await.ctx("execution: commit attempt read")?;
        Ok(row.map(|(step_id, id)| {
            (
                StepId::from_trusted_db_bytes(*step_id.as_bytes()),
                StepAttemptId::from_trusted_db_bytes(*id.as_bytes()),
            )
        }))
    }
}
