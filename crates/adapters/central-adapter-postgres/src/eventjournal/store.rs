//! The `central.run_events` writer — port of
//! `internal/adapter/postgres/eventjournal/store.go`.
//!
//! Every append takes the run-row lock first —
//! `SELECT id FROM central.runs ... FOR UPDATE`, the spec-6 OQ-1
//! serialization point shared with the workflow store — then performs
//! the seq-allocating `INSERT ... SELECT COALESCE(MAX(seq),0)+1` inside
//! the same transaction. A conflicting `event_id` returns the existing
//! row's `seq` (`DUPLICATE_EVENT_ID`, idempotent). There is no update
//! or delete path.
//!
//! The resolved seq's `event_outbox` row lands in the same transaction
//! either way (spec-5 section 3), so the publisher's drain only ever
//! sees committed events.

use central_eventjournal::domain::RunEvent;
use central_eventjournal::port::Writer;
use central_eventjournal::query::RunJournalRead;
use central_foundation::failure::Failure;
use central_foundation::identity::{
    RunEventId, RunId, SessionAttemptId, WorkflowNodeId, WorkspaceId,
};
use sqlx::{PgPool, Postgres, Transaction};
use time::OffsetDateTime;

use crate::error::SqlxContext;
use crate::store_support::{begin_tx, opt_uuid_of, uuid_of};

/// `OffsetDateTime::UNIX_EPOCH` is the domain envelope's documented
/// "no timestamp" sentinel (the deserialize-side fallback for an
/// absent `recorded_at`) — the Rust-side equivalent of upstream's
/// `ev.RecordedAt.IsZero()`: it binds SQL NULL so the column's
/// `COALESCE($10, now())` stamps the writer time.
const NO_RECORDED_AT: OffsetDateTime = OffsetDateTime::UNIX_EPOCH;

/// The `RUN_NOT_FOUND` verdict of the run-row lock (upstream
/// `errors.New("event journal: run not found")` — a plain error in Go;
/// here an `invalid` failure with a stable code).
const CODE_RUN_NOT_FOUND: &str = "EVENT_JOURNAL_RUN_NOT_FOUND";

/// PostgreSQL-backed run journal — a thin `PgPool` holder; every method
/// opens its own bounded transaction (upstream `NewStore` over a
/// `transactionBeginner`: a pool in serve composition).
#[derive(Debug, Clone)]
pub struct Store {
    /// The pool outbox draining also rides (`outbox.rs` is the same
    /// store's other trait surface).
    pub(crate) pool: PgPool,
}

impl Store {
    /// Binds the store to a `central_runtime`-authorized pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// `AppendTx` — the tx-scoped append a caller's own transaction
    /// composes so a state change and its journal row commit atomically
    /// (the workflow store's node transitions; upstream
    /// `s.journal.AppendTx`). There is exactly one journal append path.
    ///
    /// Takes the run-row `FOR UPDATE` lock inside `tx`, performs the
    /// seq-allocating insert, dedupes on `event_id`, and lands the
    /// `event_outbox` row — all inside the caller's transaction.
    ///
    /// Public (not `pub(crate)`) because the port's contract names it:
    /// "the postgres adapter additionally exposes a tx-scoped append";
    /// `sqlx::Transaction` in the signature is the same accepted
    /// adapter-internal surface [`crate::migrate::BaselineInstaller`]'s
    /// `PgConnection` parameter sets.
    pub async fn append_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        event: &RunEvent,
    ) -> Result<i64, Failure> {
        append_tx(tx, event).await
    }
}

/// The shared append body — [`Store::append_tx`] and the free
/// `pub(crate)` entry point [`crate::eventjournal::append_tx`] the
/// workflow store calls without constructing a journal handle
/// (upstream composes `s.journal.AppendTx` off the shared conn; here
/// the transaction is the share).
pub(crate) async fn append_tx(
    tx: &mut Transaction<'_, Postgres>,
    event: &RunEvent,
) -> Result<i64, Failure> {
    // The run-row lock serializes writers of this run's journal
    // (spec-6 OQ-1): seq is allocated under the lock, never by
    // conflict-retry.
    let run = uuid_of(event.run_id.as_bytes());
    let locked = sqlx::query_scalar!("SELECT id FROM central.runs WHERE id = $1 FOR UPDATE", run,)
        .fetch_optional(&mut **tx)
        .await
        .ctx("event journal: lock run row")?;
    if locked.is_none() {
        return Err(Failure::invalid(
            CODE_RUN_NOT_FOUND,
            "event journal: run not found",
        ));
    }

    // Upstream `len(payload) == 0 → "{}"` — the envelope's `Value::Null`
    // is the same "no payload" case, and `payload` is NOT NULL.
    let payload = if event.payload.is_null() {
        serde_json::json!({})
    } else {
        event.payload.clone()
    };
    let recorded_at = (event.recorded_at != NO_RECORDED_AT).then_some(event.recorded_at);

    let seq = sqlx::query_scalar!(
        "INSERT INTO central.run_events \
            (id, workspace_id, run_id, seq, node_id, attempt_id, kind, actor, \
             reason_code, payload, recorded_at) \
         SELECT $1, $2, $3, COALESCE(MAX(e.seq), 0) + 1, $4, $5, $6, $7, $8, $9, \
            COALESCE($10, now()) \
         FROM central.run_events e WHERE e.run_id = $3 \
         ON CONFLICT (id) DO NOTHING \
         RETURNING seq",
        uuid_of(event.id.as_bytes()),
        uuid_of(event.workspace_id.as_bytes()),
        run,
        opt_uuid_of(event.node_id, |i| i.as_bytes()),
        opt_uuid_of(event.attempt_id, |i| i.as_bytes()),
        event.kind.as_str(),
        event.actor.as_str(),
        event.reason_code.as_deref(),
        payload,
        recorded_at,
    )
    .fetch_optional(&mut **tx)
    .await
    .ctx("event journal: insert event")?;

    let seq = match seq {
        // Fresh append: seq was allocated under the run-row lock.
        Some(seq) => seq,
        // The event_id already exists: ingest dedupe returns the
        // committed row's seq (DUPLICATE_EVENT_ID — idempotent, not an
        // error).
        None => sqlx::query_scalar!(
            "SELECT seq FROM central.run_events WHERE id = $1 AND run_id = $2",
            uuid_of(event.id.as_bytes()),
            run,
        )
        .fetch_one(&mut **tx)
        .await
        .ctx("event journal: read deduped event seq")?,
    };

    // The outbox row joins the SAME transaction (spec-5 section 3): a
    // crash between the state change and its publication row is
    // impossible by construction. seq here is always the resolved,
    // committed seq, so the row the publisher drains keys
    // (run_id, seq) of an event row that actually exists. ON CONFLICT
    // DO NOTHING covers the deduped path, whose outbox row already
    // exists, and heals a row a published-row GC pass removed before a
    // redelivery deduped.
    sqlx::query!(
        "INSERT INTO central.event_outbox (run_id, seq, event_id) \
         VALUES ($1, $2, $3) \
         ON CONFLICT (run_id, seq) DO NOTHING",
        run,
        seq,
        uuid_of(event.id.as_bytes()),
    )
    .execute(&mut **tx)
    .await
    .ctx("event journal: insert outbox row")?;
    Ok(seq)
}

impl Writer for Store {
    /// `Append` — one event in its own transaction, returning the
    /// allocated per-run `seq`. Workflow and scheduler callers that must
    /// commit a state change and its journal row atomically use
    /// [`Store::append_tx`] inside their own transaction instead.
    async fn append(&self, event: RunEvent) -> Result<i64, Failure> {
        let mut tx = begin_tx(&self.pool).await?;
        let seq = append_tx(&mut tx, &event).await?;
        tx.commit().await.ctx("event journal: commit append")?;
        Ok(seq)
    }
}

impl RunJournalRead for Store {
    /// `EventsForRun` (upstream runview) — the run's journaled events in
    /// `seq` order as the canonical [`RunEvent`] envelope.
    async fn events_for_run(&self, run_id: RunId) -> Result<Vec<RunEvent>, Failure> {
        let rows = sqlx::query!(
            "SELECT id, workspace_id, run_id, seq, node_id, attempt_id, kind, \
                    actor, reason_code, payload, recorded_at \
             FROM central.run_events \
             WHERE run_id = $1 \
             ORDER BY seq",
            uuid_of(run_id.as_bytes()),
        )
        .fetch_all(&self.pool)
        .await
        .ctx("runview events")?;

        rows.into_iter()
            .map(|row| {
                Ok(RunEvent {
                    id: RunEventId::from_trusted_db_bytes(*row.id.as_bytes()),
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
                })
            })
            .collect()
    }
}
