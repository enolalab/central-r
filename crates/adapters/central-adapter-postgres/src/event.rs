//! PostgreSQL store for `central-event`: [`EventJournal`] (atomic
//! workspace-local sequence allocation + immutable append) and
//! [`EventFeedRead`] (seek-paginated feed over
//! `(workspace_id, event_sequence)`).
//!
//! Sequence discipline (adapter-mapping §3.2/§3.11, upstream
//! `queryReserveEventSequenceBlock`): one `INSERT … ON CONFLICT DO
//! UPDATE` on `central.workspace_event_counters` reserves the whole
//! batch's range inside the same transaction as the `central.events`
//! inserts — a rollback restores the counter, so a rejected command
//! never consumes sequence. The `events_workspace_sequence_unique`
//! constraint backs the allocation; a conflict there means the
//! allocator skipped a value and surfaces as `internal`, never a
//! silent retry against changed state.
//!
//! The payload column carries the complete §2 v1 envelope — the
//! durable record; the indexed columns are projections of it, so the
//! read path rebuilds the domain Event from the envelope (the only
//! source that carries `aggregate_type`, `actor`, and the state
//! transition).
//!
//! Denylisted-key sanitization is enforced domain-side at
//! [`domain::EventPayload`] construction; the adapter persists the
//! validated payload verbatim.

use central_event::domain::{
    ActorKind, Event, EventActor, EventIntent, EventPayload, StateTransition, codes,
};
use central_event::port::{EventJournal, MAX_APPEND_BATCH};
use central_event::query::{EventFeedPage, EventFeedRead, EventFeedRequest, SeekCursor};
use central_foundation::failure::Failure;
use central_foundation::identity::{
    AggregateId, CausationId, CommandId, CorrelationId, EventId, RunId, StepAttemptId, StepId,
    TaskId, WorkspaceId,
};
use sqlx::PgPool;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::error::{SqlxContext, classify_sqlx};
use crate::store_support::{
    PG_DATA_CORRUPT, begin_tx, i64_as_u64, opt_uuid_of, u64_as_i64, usize_as_i64, uuid_of,
};

/// The b08 writer identity stamped on every v1-envelope row —
/// `producer_id` is a required evidence column but the domain Event
/// carries no producer leg; the Phase-1 journal producer is this
/// adapter (the envelope `schema_version` it writes is `v1`).
const EVENT_PRODUCER_ID: &str = "central.event.v1";

/// PostgreSQL-backed event store.
#[derive(Debug, Clone)]
pub struct Store {
    pool: PgPool,
}

impl Store {
    /// Binds the store to a `central_runtime`-authorized pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

// ---------------------------------------------------------------------------
// Envelope decode — the inverse of `domain::Event::envelope_json`.
// ---------------------------------------------------------------------------

/// The §2 v1 envelope as stored in `central.events.payload`.
#[derive(serde::Deserialize)]
struct Envelope {
    event_id: String,
    #[allow(dead_code)]
    event_sequence: Option<u64>,
    schema_version: String,
    #[serde(rename = "type")]
    event_type: String,
    occurred_at: String,
    workspace_id: String,
    aggregate_type: String,
    aggregate_id: String,
    aggregate_version: u64,
    #[serde(default)]
    correlation_id: Option<String>,
    #[serde(default)]
    causation_id: Option<String>,
    #[serde(default)]
    command_id: Option<String>,
    #[serde(default)]
    run_id: Option<String>,
    #[serde(default)]
    task_id: Option<String>,
    #[serde(default)]
    step_id: Option<String>,
    #[serde(default)]
    attempt_id: Option<String>,
    #[serde(default)]
    prior_state: Option<String>,
    next_state: String,
    #[serde(default)]
    reason: Option<String>,
    actor: EnvelopeActor,
    payload: serde_json::Value,
}

#[derive(serde::Deserialize)]
struct EnvelopeActor {
    actor_id: String,
    actor_kind: String,
}

fn corrupt(what: &'static str) -> Failure {
    Failure::internal(PG_DATA_CORRUPT, what)
}

/// Parses an optional envelope UUID leg; a malformed stored identity
/// is corrupt durable state.
fn opt_id<T: core::str::FromStr>(text: Option<&str>) -> Result<Option<T>, Failure> {
    text.map(|t| {
        t.parse::<T>()
            .map_err(|_| corrupt("a stored event identity is malformed"))
    })
    .transpose()
}

/// Rebuilds one domain Event from its stored row: the envelope for the
/// semantic legs, the indexed columns for the committed ordering.
fn event_from_row(sequence: i64, payload: serde_json::Value) -> Result<Event, Failure> {
    let envelope: Envelope = serde_json::from_value(payload)
        .map_err(|_| corrupt("a stored event envelope is not the v1 shape"))?;
    if envelope.schema_version != central_event::domain::SCHEMA_VERSION_V1 {
        return Err(corrupt("a stored event envelope is not schema v1"));
    }
    let payload_bytes = serde_json::to_vec(&envelope.payload)
        .map_err(|_| corrupt("a stored event payload cannot be re-encoded"))?;
    let occurred_at = OffsetDateTime::parse(&envelope.occurred_at, &Rfc3339)
        .map_err(|_| corrupt("a stored event occurred_at is not RFC 3339"))?;
    Ok(Event {
        id: envelope
            .event_id
            .parse::<EventId>()
            .map_err(|_| corrupt("a stored event id is malformed"))?,
        workspace_id: envelope
            .workspace_id
            .parse::<WorkspaceId>()
            .map_err(|_| corrupt("a stored event workspace id is malformed"))?,
        sequence: Some(i64_as_u64(sequence, "event_sequence")?),
        event_type: envelope.event_type,
        aggregate_type: envelope.aggregate_type,
        aggregate_id: envelope
            .aggregate_id
            .parse::<AggregateId>()
            .map_err(|_| corrupt("a stored event aggregate id is malformed"))?,
        aggregate_version: envelope.aggregate_version,
        occurred_at,
        correlation_id: opt_id::<CorrelationId>(envelope.correlation_id.as_deref())?,
        causation_id: opt_id::<CausationId>(envelope.causation_id.as_deref())?,
        command_id: opt_id::<CommandId>(envelope.command_id.as_deref())?,
        run_id: opt_id::<RunId>(envelope.run_id.as_deref())?,
        context: central_event::domain::EventContext {
            task_id: opt_id::<TaskId>(envelope.task_id.as_deref())?,
            step_id: opt_id::<StepId>(envelope.step_id.as_deref())?,
            attempt_id: opt_id::<StepAttemptId>(envelope.attempt_id.as_deref())?,
        },
        actor: EventActor::new(
            envelope.actor.actor_id,
            ActorKind::parse(&envelope.actor.actor_kind)
                .map_err(|_| corrupt("a stored event actor kind is malformed"))?,
        )
        .map_err(|_| corrupt("a stored event actor is malformed"))?,
        transition: StateTransition::new(
            envelope.prior_state,
            envelope.next_state,
            envelope.reason,
        )
        .map_err(|_| corrupt("a stored event transition is malformed"))?,
        payload: EventPayload::from_canonical(&payload_bytes)
            .map_err(|_| corrupt("a stored event payload fails re-validation"))?,
    })
}

impl EventJournal for Store {
    async fn append_events(
        &self,
        workspace_id: WorkspaceId,
        intents: Vec<EventIntent>,
    ) -> Result<Vec<Event>, Failure> {
        if intents.len() > MAX_APPEND_BATCH {
            return Err(Failure::invalid(
                codes::EVENT_INVALID,
                "a single append may carry at most 8 events",
            ));
        }
        if intents.is_empty() {
            return Ok(Vec::new());
        }
        let workspace = uuid_of(workspace_id.as_bytes());
        let count = i64::try_from(intents.len()).map_err(|_| {
            Failure::invalid(
                codes::EVENT_INVALID,
                "the append batch is not representable",
            )
        })?;

        let mut tx = begin_tx(&self.pool).await?;

        // Atomic range reservation — lock order: workspace_event_counters
        // → events (mapping §6.1, the counter row lock serializes all
        // writers of this workspace's feed).
        let first_sequence = sqlx::query_scalar!(
            "INSERT INTO central.workspace_event_counters \
             (workspace_id, last_event_sequence) \
             VALUES ($1, $2) \
             ON CONFLICT (workspace_id) DO UPDATE \
             SET last_event_sequence = \
                 central.workspace_event_counters.last_event_sequence + \
                 EXCLUDED.last_event_sequence \
             RETURNING last_event_sequence - $2 + 1",
            workspace,
            count,
        )
        .fetch_one(&mut *tx)
        .await
        .ctx("event: reserve sequence block")?
        .ok_or_else(|| corrupt("the sequence reservation returned NULL"))?;

        let mut events = Vec::with_capacity(intents.len());
        for (offset, intent) in intents.into_iter().enumerate() {
            let sequence = first_sequence + usize_as_i64(offset);
            let event = intent.seal(i64_as_u64(sequence, "event_sequence")?)?;
            let envelope = event.envelope_json()?;
            let payload: serde_json::Value = serde_json::from_slice(&envelope)
                .map_err(|_| Failure::internal(codes::EVENT_INVALID, "envelope re-parse failed"))?;
            // A conflict on events_workspace_sequence_unique is an
            // allocation defect — internal, per the port contract.
            sqlx::query!(
                "INSERT INTO central.events \
                 (id, workspace_id, event_sequence, event_type, \
                  aggregate_id, aggregate_version, command_id, run_id, \
                  payload, correlation_id, causation_id, occurred_at, \
                  task_id, step_id, attempt_id, kind, state, \
                  producer_id, policy_version, eligible_after, legal_hold) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, \
                         $13, $14, $15, $4, 'recorded', $16, 1, \
                         clock_timestamp() + interval '90 days', false)",
                uuid_of(event.id.as_bytes()),
                workspace,
                sequence,
                event.event_type,
                uuid_of(event.aggregate_id.as_bytes()),
                u64_as_i64(event.aggregate_version, codes::EVENT_INVALID)?,
                opt_uuid_of(event.command_id, |i| i.as_bytes()),
                opt_uuid_of(event.run_id, |i| i.as_bytes()),
                payload,
                opt_uuid_of(event.correlation_id, |i| i.as_bytes()),
                opt_uuid_of(event.causation_id, |i| i.as_bytes()),
                event.occurred_at,
                opt_uuid_of(event.context.task_id, |i| i.as_bytes()),
                opt_uuid_of(event.context.step_id, |i| i.as_bytes()),
                opt_uuid_of(event.context.attempt_id, |i| i.as_bytes()),
                EVENT_PRODUCER_ID,
            )
            .execute(&mut *tx)
            .await
            .map_err(|err| {
                let failure = classify_sqlx(&err);
                if failure.code() == crate::error::codes::PG_UNIQUE_VIOLATION {
                    return Failure::internal(
                        crate::error::codes::PG_UNIQUE_VIOLATION,
                        "the allocated event sequence conflicts with a stored row",
                    );
                }
                failure
            })?;
            events.push(event);
        }
        tx.commit().await.ctx("event: commit append transaction")?;
        Ok(events)
    }
}

impl EventFeedRead for Store {
    async fn read_page(&self, request: &EventFeedRequest) -> Result<EventFeedPage, Failure> {
        let limit = request.validate()?;
        let after = request
            .after
            .map(|c| {
                i64::try_from(c.event_sequence).map_err(|_| {
                    Failure::invalid(
                        codes::CURSOR_INVALID,
                        "the cursor sequence is not representable",
                    )
                })
            })
            .transpose()?
            .unwrap_or(0);

        // One bounded seek: strict `>` on the cursor sequence, limit+1
        // rows so `has_more` costs no second round trip.
        let rows = sqlx::query!(
            "SELECT event_sequence, payload \
             FROM central.events \
             WHERE workspace_id = $1 \
               AND event_sequence > $2 \
               AND ($3::uuid IS NULL OR aggregate_id = $3) \
               AND ($4::uuid IS NULL OR run_id = $4) \
             ORDER BY event_sequence ASC \
             LIMIT $5",
            uuid_of(request.workspace_id.as_bytes()),
            after,
            opt_uuid_of(request.aggregate_id, |i| i.as_bytes()),
            opt_uuid_of(request.run_id, |i| i.as_bytes()),
            usize_as_i64(limit) + 1,
        )
        .fetch_all(&self.pool)
        .await
        .ctx("event: read feed page")?;

        let has_more = rows.len() > limit;
        let mut events = Vec::with_capacity(limit.min(rows.len()));
        for row in rows.into_iter().take(limit) {
            events.push(event_from_row(row.event_sequence, row.payload)?);
        }
        let next_cursor = events.last().and_then(|e| {
            e.sequence.map(|sequence| SeekCursor {
                workspace_id: request.workspace_id,
                event_sequence: sequence,
            })
        });
        Ok(EventFeedPage {
            events,
            next_cursor,
            has_more,
        })
    }

    async fn has_events_after(
        &self,
        workspace_id: WorkspaceId,
        event_sequence: u64,
    ) -> Result<bool, Failure> {
        let exists = sqlx::query_scalar!(
            "SELECT EXISTS( \
             SELECT 1 FROM central.events \
             WHERE workspace_id = $1 AND event_sequence > $2)",
            uuid_of(workspace_id.as_bytes()),
            u64_as_i64(event_sequence, codes::EVENT_INVALID)?,
        )
        .fetch_one(&self.pool)
        .await
        .ctx("event: check events after")?;
        Ok(exists.unwrap_or(false))
    }
}
