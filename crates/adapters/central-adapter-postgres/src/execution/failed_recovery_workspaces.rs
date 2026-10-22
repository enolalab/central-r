//! `list_failed_recovery_workspaces` — port of upstream
//! `failed_recovery_workspaces.go` (harness phase 3f decision 5).
//! Read-only: no coordinator lease, no lock, no write.

use central_execution::port::{FailedRecoveryWorkspaces, MAX_FAILED_RECOVERY_WORKSPACES};
use central_foundation::failure::Failure;
use central_foundation::identity::WorkspaceId;

use super::store::Store;
use super::{begin, invalid};
use crate::error::SqlxContext;

impl Store {
    /// `ListFailedRecoveryWorkspaces` — the first page of the epoch's
    /// failed workspace rows in ascending workspace-id order plus the
    /// total failed-row count for the epoch.
    pub(crate) async fn list_failed_recovery_workspaces_page(
        &self,
        epoch_generation: i64,
        limit: u32,
    ) -> Result<FailedRecoveryWorkspaces, Failure> {
        if epoch_generation <= 0 || limit == 0 || limit > MAX_FAILED_RECOVERY_WORKSPACES {
            return Err(invalid("INVALID_RECOVERY_READ"));
        }
        struct Row {
            workspace_id: uuid::Uuid,
            total: Option<i64>,
        }
        let mut tx = begin(&self.pool).await?;
        let rows = sqlx::query_as!(
            Row,
            "SELECT workspace_id, count(*) OVER () AS total \
             FROM central.recovery_epoch_workspaces \
             WHERE epoch_generation = $1 AND delivery_state = 'failed' \
             ORDER BY workspace_id LIMIT $2",
            epoch_generation,
            i64::from(limit),
        )
        .fetch_all(&mut *tx)
        .await
        .ctx("execution: list failed recovery workspaces")?;
        tx.commit()
            .await
            .ctx("execution: commit failed-workspace list")?;
        let mut out = FailedRecoveryWorkspaces::default();
        for row in rows {
            out.total = row.total.unwrap_or(0);
            out.ids.push(WorkspaceId::from_trusted_db_bytes(
                *row.workspace_id.as_bytes(),
            ));
        }
        Ok(out)
    }
}
