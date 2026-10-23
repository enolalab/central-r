//! Outbox drain surface of the event journal adapter (issue #95 slice
//! 2D, packet P2D06; spec-5 section 3) — port of
//! `internal/adapter/postgres/eventjournal/outbox.go`.
//!
//! [`super::Store::append_tx`] already lands the `central.event_outbox`
//! row in the same transaction as its `run_events` row, so this file
//! owns only the read/mark/GC side the in-process publisher drives:
//! claim unpublished rows in per-run `seq` order under
//! `FOR UPDATE SKIP LOCKED`, deliver each through the caller's
//! consumer fan-out, mark `published_at` (or bump `publish_attempts`
//! on a failed delivery), report the unpublished backlog for stall
//! detection, and delete published rows past their retention.
//!
//! Delivery runs INSIDE the claim transaction: a marked-published row
//! has provably been delivered to every registered consumer, and a
//! crash or rollback leaves it unpublished for redelivery — the
//! at-least-once side of spec-5's boundary map. Consumers are
//! therefore required to be fast and idempotent (dedup on
//! `event_id`); readiness recomputation stays synchronous elsewhere —
//! consumers are feeds, never correctness.

use central_eventjournal::app::publisher::{DrainStore, EventDelivery, UnpublishedBacklog};
use central_eventjournal::domain::RunEvent;
use central_foundation::failure::Failure;
use central_foundation::identity::{
    RunEventId, RunId, SessionAttemptId, WorkflowNodeId, WorkspaceId,
};
use time::OffsetDateTime;

use super::Store;
use crate::error::SqlxContext;
use crate::store_support::{begin_tx, i64_as_u64, uuid_of};

impl DrainStore for Store {
    /// `DrainPending` — claims up to `limit` unpublished outbox rows in
    /// `(run_id, seq)` order and calls `deliver` once per event; an
    /// `Ok` delivery stamps `published_at` with one more
    /// `publish_attempt`, an `Err` leaves `published_at` NULL and still
    /// counts the attempt, so a wedged consumer leaves the row for the
    /// next pass while the attempt count records the stall. The claim,
    /// the marks, and the delivery run in one transaction; a commit
    /// failure unpublishes nothing and returns the error. Returns the
    /// count of rows marked published.
    async fn drain_pending<D: EventDelivery>(
        &self,
        limit: u32,
        deliver: &mut D,
    ) -> Result<u64, Failure> {
        if limit == 0 {
            return Ok(0);
        }
        let mut tx = begin_tx(&self.pool).await?;

        // Claim unpublished rows, oldest first in (run_id, seq) order —
        // per-run monotonic drain with runs interleaved rather than
        // starved. FOR UPDATE OF the outbox alias (never the joined
        // run_events row) with SKIP LOCKED so a second publisher drains
        // disjoint rows instead of serializing behind this one's
        // in-flight delivery.
        let rows = sqlx::query!(
            "SELECT o.run_id, o.seq, o.event_id, \
                    e.workspace_id, e.node_id, e.attempt_id, \
                    e.kind, e.actor, e.reason_code, e.payload, e.recorded_at \
             FROM central.event_outbox o \
             JOIN central.run_events e ON e.id = o.event_id \
             WHERE o.published_at IS NULL \
             ORDER BY o.run_id, o.seq \
             FOR UPDATE OF o SKIP LOCKED \
             LIMIT $1",
            i64::from(limit),
        )
        .fetch_all(&mut *tx)
        .await
        .ctx("event journal outbox: claim batch")?;

        let mut delivered = 0u64;
        for row in rows {
            let event = RunEvent {
                id: RunEventId::from_trusted_db_bytes(*row.event_id.as_bytes()),
                workspace_id: WorkspaceId::from_trusted_db_bytes(*row.workspace_id.as_bytes()),
                run_id: RunId::from_trusted_db_bytes(*row.run_id.as_bytes()),
                seq: row.seq,
                node_id: row
                    .node_id
                    .map(|id| WorkflowNodeId::from_trusted_db_bytes(*id.as_bytes())),
                attempt_id: row
                    .attempt_id
                    .map(|id| SessionAttemptId::from_trusted_db_bytes(*id.as_bytes())),
                kind: row.kind,
                actor: row.actor,
                reason_code: row.reason_code,
                payload: row.payload,
                recorded_at: row.recorded_at,
            };
            let run = uuid_of(event.run_id.as_bytes());
            match deliver.deliver(&event).await {
                Ok(()) => {
                    sqlx::query!(
                        "UPDATE central.event_outbox \
                         SET published_at = clock_timestamp(), \
                             publish_attempts = publish_attempts + 1 \
                         WHERE run_id = $1 AND seq = $2",
                        run,
                        event.seq,
                    )
                    .execute(&mut *tx)
                    .await
                    .ctx("event journal outbox: mark published")?;
                    delivered += 1;
                }
                Err(_) => {
                    sqlx::query!(
                        "UPDATE central.event_outbox \
                         SET publish_attempts = publish_attempts + 1 \
                         WHERE run_id = $1 AND seq = $2",
                        run,
                        event.seq,
                    )
                    .execute(&mut *tx)
                    .await
                    .ctx("event journal outbox: record publish miss")?;
                }
            }
        }
        tx.commit()
            .await
            .ctx("event journal outbox: commit drain")?;
        Ok(delivered)
    }

    /// `UnpublishedBacklog` — the drain-visible depth and the oldest
    /// unpublished row's `created_at`; the publisher's stall detector
    /// compares them against its thresholds. `oldest` is `None` when
    /// the backlog is empty (upstream's zero `time.Time`).
    async fn unpublished_backlog(&self) -> Result<UnpublishedBacklog, Failure> {
        let row = sqlx::query!(
            "SELECT COUNT(*) AS depth, MIN(created_at) AS oldest \
             FROM central.event_outbox \
             WHERE published_at IS NULL",
        )
        .fetch_one(&self.pool)
        .await
        .ctx("event journal outbox: read backlog")?;
        Ok(UnpublishedBacklog {
            depth: i64_as_u64(row.depth.unwrap_or(0), "outbox backlog depth")?,
            oldest: row.oldest,
        })
    }

    /// `CollectPublished` — deletes published outbox rows older than
    /// `cutoff` (the OQ-3 7-day retention the publisher applies each
    /// tick) and returns the deleted count. `event_outbox` carries the
    /// schema's second runtime DELETE grant (after
    /// `resume_checkpoints`) for exactly this pass.
    async fn collect_published(&self, cutoff: OffsetDateTime) -> Result<u64, Failure> {
        let tag = sqlx::query!(
            "DELETE FROM central.event_outbox \
             WHERE published_at IS NOT NULL AND published_at < $1",
            cutoff,
        )
        .execute(&self.pool)
        .await
        .ctx("event journal outbox: collect published")?;
        Ok(tag.rows_affected())
    }
}
