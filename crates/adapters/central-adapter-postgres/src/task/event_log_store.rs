//! The task lifecycle event-log read store — the port of
//! `internal/adapter/postgres/task/event_log_store.go`.
//!
//! Newest-first keyset pages over `central.events`, optionally scoped
//! to one task through `aggregate_id` (functionally identical to
//! `task_id` — see the write path — so the read rides the
//! `events_aggregate_idx` index). The seek predicate is
//! `event_sequence < cursor`, which is unique per workspace. The
//! `payload` column is deliberately never selected: it may carry
//! command inputs the activity feed must not expose.
//! [`HIDDEN_TASK_EVENT_KINDS`] is filtered inside the query, so a
//! page stays full and the cursor still advances past hidden rows
//! (harness phase 3a decision 16 — the attempt lease heartbeat fires
//! every 10 s and must not bump the feed).

use central_foundation::failure::Failure;
use central_foundation::identity::{RunId, TaskId};
use central_task::domain::TaskStatus;
use central_task::query::{
    EventCursor, TaskEvent, TaskEventLogProjection, TaskEventLogRead, TaskEventLogRequest,
    normalize_task_event_log_page_size, validate_task_event_log_request,
};
use sqlx::PgPool;

use crate::error::SqlxContext;
use crate::store_support::{begin_tx, uuid_of};

/// Event kinds the task detail and activity views never show.
pub const HIDDEN_TASK_EVENT_KINDS: [&str; 1] = ["attempt_heartbeat"];

/// PostgreSQL-backed task event-log read store.
#[derive(Debug, Clone)]
pub struct EventLogStore {
    pool: PgPool,
}

/// The `scanTaskEvent` projection row — no payload, by contract.
struct TaskEventRow {
    event_sequence: i64,
    task_id: uuid::Uuid,
    run_id: Option<uuid::Uuid>,
    kind: String,
    state: String,
    occurred_at: time::OffsetDateTime,
}

impl EventLogStore {
    /// Binds the store to a `central_runtime`-authorized pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl TaskEventLogRead for EventLogStore {
    async fn read(&self, req: TaskEventLogRequest) -> Result<TaskEventLogProjection, Failure> {
        validate_task_event_log_request(&req)?;
        let mut tx = begin_tx(&self.pool).await?;

        let page_size = i64::from(normalize_task_event_log_page_size(req.page_size));
        let hidden: Vec<String> = HIDDEN_TASK_EVENT_KINDS
            .iter()
            .map(|k| (*k).to_owned())
            .collect();
        let rows = sqlx::query_as!(
            TaskEventRow,
            "SELECT event_sequence, \
             COALESCE(task_id, aggregate_id) AS \"task_id!\", \
             run_id, kind, \
             COALESCE(state, '') AS \"state!\", occurred_at \
             FROM central.events \
             WHERE workspace_id = $1 \
               AND ($3::uuid IS NULL OR aggregate_id = $3) \
               AND ($4::bigint IS NULL OR event_sequence < $4) \
               AND kind <> ALL($5::text[]) \
             ORDER BY event_sequence DESC \
             LIMIT $2",
            uuid_of(req.workspace_id.as_bytes()),
            page_size,
            req.task_id.map(|t| uuid_of(t.as_bytes())),
            req.cursor.map(|c| c.sequence),
            &hidden[..],
        )
        .fetch_all(&mut *tx)
        .await
        .ctx("task: read task event log")?;

        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            events.push(TaskEvent {
                sequence: row.event_sequence,
                task_id: TaskId::from_trusted_db_bytes(*row.task_id.as_bytes()),
                run_id: row
                    .run_id
                    .map(|u| RunId::from_trusted_db_bytes(*u.as_bytes())),
                // The kind is open producer text — `harness.*`
                // milestones and `attempt_*` evidence surface
                // verbatim; only the hidden list is filtered.
                kind: row.kind,
                // `state` is the event-state column ('recorded' for
                // lifecycle rows); only task-status text projects.
                state: TaskStatus::parse(&row.state).ok(),
                at: row.occurred_at,
            });
        }
        // Upstream cursor rule: a full page emits a seek cursor.
        let next_cursor = if events.len() as i64 == page_size {
            events.last().map(|e| EventCursor {
                sequence: e.sequence,
            })
        } else {
            None
        };
        tx.commit().await.ctx("task: commit task event log read")?;
        Ok(TaskEventLogProjection {
            events,
            next_cursor,
        })
    }
}
