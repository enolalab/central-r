//! The adapter-owned harness milestone append — the port of
//! `internal/adapter/postgres/task/milestone_store.go`.
//!
//! A milestone is one bounded `central.events` row whose id is the
//! UUID v5 of its caller-chosen key, so a retried append of the same
//! milestone is recognised and written exactly once: the existence
//! probe short-circuits, and a concurrent insert that loses the race
//! is folded back to success (the `23505` arm). One event sequence is
//! reserved inside the same transaction as the insert, so a rolled-
//! back append consumes no sequence.
//!
//! The payload holds only the two fixed status/reason codes — never
//! free text — and `producer_id` is [`MILESTONE_PRODUCER`]. Milestone
//! kinds are arbitrary `harness.*` text: they are stored and read
//! back verbatim as open kind text, not through the task domain's
//! closed [`central_task::domain::EventKind`].

use central_foundation::failure::Failure;
use central_foundation::identity::{RunId, StepAttemptId, TaskId, WorkspaceId};
use sqlx::PgPool;
use time::OffsetDateTime;

use crate::error::{SqlxContext, classify_sqlx};
use crate::store_support::{begin_tx, opt_uuid_of, uuid_of};
use crate::task::invalid;

/// The `producer_id` stamped on every harness milestone event.
pub const MILESTONE_PRODUCER: &str = "central.harness.milestone.v1";

/// The UUID-v5 namespace a milestone's event id is derived from, so a
/// retried append of the same key maps to the same row
/// (`milestoneNamespace` upstream — the value is part of the durable
/// identity and must never change).
const MILESTONE_NAMESPACE: uuid::Uuid =
    uuid::Uuid::from_u128(0x6f1d2a4e_8b0c_5d7e_9a3f_1c2b3d4e5f60);

/// `MilestoneEventID` — the event id a milestone key maps to: the
/// RFC 4122 §4.3 name-based (SHA-1) UUID of `key` under
/// [`MILESTONE_NAMESPACE`]. Implemented locally because the
/// workspace's `uuid` pin carries no `v5` feature; the algorithm is
/// the standard one: `SHA-1(namespace_bytes ‖ name_utf8)` truncated
/// to 128 bits with the version/variant fields stamped.
#[must_use]
pub fn milestone_event_id(key: &str) -> uuid::Uuid {
    use sha1::Digest;
    let mut hasher = sha1::Sha1::new();
    hasher.update(MILESTONE_NAMESPACE.as_bytes());
    hasher.update(key.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50; // version 5
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // RFC 4122 variant
    uuid::Uuid::from_bytes(bytes)
}

/// One bounded harness milestone for the task event log. `kind` is a
/// `harness.*` event kind; `status`/`reason` are fixed codes, never
/// free text. `attempt_id` names the StepAttempt when the milestone
/// is attempt-scoped (`None` for a dispatcher milestone).
#[derive(Debug, Clone, PartialEq)]
pub struct Milestone {
    /// The dedup key the event id derives from.
    pub key: String,
    /// The `harness.*` kind stored on the row.
    pub kind: String,
    /// The owning workspace.
    pub workspace_id: WorkspaceId,
    /// The task the milestone concerns (also `aggregate_id`).
    pub task_id: TaskId,
    /// The run the milestone concerns.
    pub run_id: RunId,
    /// The StepAttempt when attempt-scoped.
    pub attempt_id: Option<StepAttemptId>,
    /// The fixed status code carried in the payload.
    pub status: String,
    /// The fixed reason code carried in the payload.
    pub reason: String,
    /// When the milestone occurred.
    pub at: OffsetDateTime,
}

/// PostgreSQL-backed milestone append store.
#[derive(Debug, Clone)]
pub struct MilestoneStore {
    pool: PgPool,
}

/// The milestone payload — `omitempty` on both legs, exactly the Go
/// `struct{ Status, Reason string }` shape upstream marshals.
#[derive(serde::Serialize)]
struct MilestonePayload<'a> {
    #[serde(skip_serializing_if = "str::is_empty")]
    status: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    reason: &'a str,
}

impl MilestoneStore {
    /// Binds the store to a `central_runtime`-authorized pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// `Append` — records `m` once; a second append of the same
    /// `key` is a no-op, including a concurrent loser of the unique
    /// race.
    ///
    /// # Errors
    /// - `invalid` for an incomplete milestone (empty key/kind, nil
    ///   workspace/task/run);
    /// - `conflict`/`ambiguous`/… from the classified database call.
    pub async fn append(&self, m: &Milestone) -> Result<(), Failure> {
        if m.key.is_empty()
            || m.kind.is_empty()
            || m.workspace_id.is_nil()
            || m.task_id.is_nil()
            || m.run_id.is_nil()
        {
            return Err(invalid("incomplete milestone"));
        }
        let payload = serde_json::to_value(MilestonePayload {
            status: &m.status,
            reason: &m.reason,
        })
        .map_err(|_| invalid("milestone payload"))?;
        let id = milestone_event_id(&m.key);
        let workspace = uuid_of(m.workspace_id.as_bytes());

        let mut tx = begin_tx(&self.pool).await?;
        let exists = sqlx::query_scalar!(
            "SELECT EXISTS( \
             SELECT 1 FROM central.events \
             WHERE workspace_id = $1 AND id = $2)",
            workspace,
            id,
        )
        .fetch_one(&mut *tx)
        .await
        .ctx("task: check milestone")?
        .unwrap_or(false);
        if exists {
            // Upstream returns before Commit — the transaction's
            // rollback frees the probe read cleanly.
            return Ok(());
        }

        let sequence = sqlx::query_scalar!(
            "INSERT INTO central.workspace_event_counters \
             (workspace_id, last_event_sequence) \
             VALUES ($1, 1) \
             ON CONFLICT (workspace_id) DO UPDATE \
             SET last_event_sequence = \
                 central.workspace_event_counters.last_event_sequence + 1 \
             RETURNING last_event_sequence",
            workspace,
        )
        .fetch_one(&mut *tx)
        .await
        .ctx("task: reserve milestone sequence")?;

        let inserted = sqlx::query!(
            "INSERT INTO central.events (\
             id, workspace_id, event_sequence, event_type, aggregate_id, \
             aggregate_version, run_id, payload, occurred_at, task_id, \
             attempt_id, kind, state, producer_id, policy_version, \
             eligible_after, legal_hold) \
             VALUES ($1, $2, $3, $4, $5, 0, $6, $7, $8, $5, $9, $4, \
                     'recorded', $10, 1, \
                     clock_timestamp() + interval '90 days', false)",
            id,
            workspace,
            sequence,
            m.kind,
            uuid_of(m.task_id.as_bytes()),
            uuid_of(m.run_id.as_bytes()),
            payload,
            m.at,
            opt_uuid_of(m.attempt_id, |i| i.as_bytes()),
            MILESTONE_PRODUCER,
        )
        .execute(&mut *tx)
        .await;
        if let Err(err) = inserted {
            let failure = classify_sqlx(&err);
            if failure.code() != crate::error::codes::PG_UNIQUE_VIOLATION {
                return Err(Failure::new(
                    failure.kind(),
                    failure.code(),
                    format!("task: insert milestone: {}", failure.message()),
                ));
            }
            // A concurrent append of the same milestone key won — the
            // duplicate append is a no-op by contract. The aborted
            // transaction cannot commit, so roll it back and report
            // success: the recorded row already carries the key.
            return Ok(());
        }

        tx.commit().await.ctx("task: commit milestone")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn milestone_event_id_is_deterministic_v5() {
        // RFC 4122 §B.2-style self-check: same key ⇒ same id, and the
        // version/variant fields are stamped.
        let a = milestone_event_id("harness.session_started:run-1");
        let b = milestone_event_id("harness.session_started:run-1");
        let c = milestone_event_id("harness.session_started:run-2");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.get_version_num(), 5);
    }
}
