//! `ExecutionMetrics` — the bounded aggregate read the serving
//! execution monitor consumes (upstream `queryExecutionMetrics`).
//!
//! The snapshot is deliberately identifier-free: only row counts and
//! age durations leave the adapter. Upstream additionally measures
//! in-process counters (`recoveryBatchNanos`, `recoveredRows`,
//! `recoveryLockNanos`, `poolWaitNanos`) on the shared store; the Rust
//! store creates a fresh `Store` value per composition site, so those
//! measured fields read `0` until the store grows shared metric
//! atomics — the queried aggregates are identical.

use sqlx::Row;

use super::Store;
use crate::error::SqlxContext;
use central_execution::port::ExecutionMetricsSnapshot;
use central_foundation::failure::Failure;

impl Store {
    /// `ExecutionMetrics` — one bounded read of the six aggregate
    /// queries plus the oldest-retained-record age; the in-process
    /// counters upstream measures read `0` here (see the module
    /// comment).
    ///
    /// # Errors
    /// `Failure::unavailable` when the metrics read fails.
    pub async fn execution_metrics(&self) -> Result<ExecutionMetricsSnapshot, Failure> {
        let row = sqlx::query(
            "SELECT
              (SELECT count(*) FROM central.outbox_workspace_work
               WHERE next_visible_at <= clock_timestamp()
                 AND (claim_expires_at IS NULL OR claim_expires_at <= clock_timestamp())),
              ((SELECT count(*) FROM central.events) + (SELECT count(*) FROM central.outbox) +
               (SELECT count(*) FROM central.execution_command_receipts) +
               (SELECT count(*) FROM central.execution_completion_receipts)),
              ((SELECT count(*) FROM central.events WHERE legal_hold) +
               (SELECT count(*) FROM central.outbox WHERE legal_hold) +
               (SELECT count(*) FROM central.execution_command_receipts WHERE legal_hold) +
               (SELECT count(*) FROM central.execution_completion_receipts WHERE legal_hold)),
              (SELECT count(*) FROM central.outbox WHERE delivery_state IN ('pending','claimed')),
              (SELECT count(*) FROM central.step_attempts WHERE state = 'reconciliation') +
              (SELECT count(*) FROM central.tool_call_attempts WHERE state = 'reconciliation'),
              COALESCE((SELECT (extract(epoch FROM (clock_timestamp() - min(recorded_at))) * 1000000000)::bigint FROM (
                 SELECT occurred_at AS recorded_at FROM central.events
                 UNION ALL SELECT created_at FROM central.outbox
                 UNION ALL SELECT created_at FROM central.execution_command_receipts
                 UNION ALL SELECT created_at FROM central.execution_completion_receipts
               ) retained), 0)",
        )
        .fetch_one(&self.pool)
        .await
        .ctx("execution: read metrics")?;
        let oldest_nanos: i64 = row.get(5);
        Ok(ExecutionMetricsSnapshot {
            scheduler_queue_depth: row.get(0),
            table_row_count: row.get(1),
            held_record_count: row.get(2),
            pending_outbox_count: row.get(3),
            reconciliation_backlog: row.get(4),
            oldest_record_nanos: oldest_nanos.max(0),
            ..ExecutionMetricsSnapshot::default()
        })
    }
}
