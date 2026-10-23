//! PostgreSQL adapter for the canonical per-run orchestration journal
//! (P2A04, spec-6) — port of `internal/adapter/postgres/eventjournal/`.
//!
//! [`Store`] implements the `central-eventjournal` seams:
//!
//! - [`central_eventjournal::port::Writer`] — append-only `run_events`
//!   writes; the per-run `seq` is allocated inside the write transaction
//!   under the run-row `FOR UPDATE` lock (spec-6 OQ-1), and a
//!   redelivered `event_id` dedupes to the existing row's `seq`.
//! - [`central_eventjournal::query::RunJournalRead`] — the verbatim,
//!   seq-ordered journal read (upstream `runview.EventsForRun`).
//! - [`central_eventjournal::app::publisher::DrainStore`] — the
//!   `event_outbox` claim/mark/backlog/GC surface the in-process
//!   publisher drains (spec-5 section 3).
//!
//! Every append additionally lands its `event_outbox` row in the SAME
//! transaction (spec-5's transactional-outbox atomicity), so the
//! publisher only ever sees committed events. Kinds are stored
//! verbatim — [`central_eventjournal::domain::known`] is the caller's
//! catalog check, never the writer's.

mod outbox;
mod store;

pub use store::Store;
pub(crate) use store::append_tx;
