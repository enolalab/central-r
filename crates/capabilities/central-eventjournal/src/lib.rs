//! `central-eventjournal` — the Phase-2 Slice-2A (b33) canonical
//! `run_events` journal: the spec-6 event envelope and catalog, the
//! fold/reconstruction projection, the append-only `Writer` seam, and
//! the in-process transactional-outbox `Publisher` — pure port of
//! `central/internal/eventjournal` (+ its `app` and `port` packages).
//! No `sqlx`, no `tokio`, no `uuid`.
//!
//! Four-layer capability crate (rust-application-boundaries.md §2):
//!
//! - [`domain`] — the closed [`domain::EventKind`] catalog (30 declared
//!   kinds across owning specs 1–8), the spec-6 fold/ingest
//!   [`domain::ReasonCode`] vocabulary, and the canonical
//!   [`domain::RunEvent`] envelope whose serde is byte-identical to
//!   upstream `json.Marshal(eventjournal.Event)` (Go's untagged-struct
//!   field names, verbatim `payload` inline, RFC 3339 `recorded_at`).
//! - [`fold`] — [`fold::fold`]/[`fold::compare_fold`]: the read-only
//!   reconstruction projection. Every anomaly — `EVENT_SEQUENCE_GAP`,
//!   `UNKNOWN_EVENT_KIND`, `INVALID_EVENT_PAYLOAD`, `ORPHAN_EVENT`,
//!   `RECONSTRUCTION_DIVERGED` — is a [`fold::Finding`], never a silent
//!   correction and never an error return (upstream `Fold` cannot
//!   fail).
//! - [`port`] — [`port::Writer`] (the append-only seam allocating
//!   per-run `seq` inside the write transaction, `DUPLICATE_EVENT_ID`
//!   dedupe on `event_id`) and [`port::Consumer`] (the at-least-once
//!   outbox delivery seam; consumers must dedupe on `event_id`).
//! - [`query`] — [`query::RunJournalRead`]: the verbatim seq-ordered
//!   journal read that feeds `fold`/`compare_fold` and the run-view
//!   timeline.
//! - [`app`] — the process-level components:
//!   [`app::publisher::Publisher`] (the `central.event_outbox` drain:
//!   claim batch → fan out to consumers → mark published →
//!   `OUTBOX_PUBLISH_STALLED` probe → published-row GC) and
//!   [`app::consumers`] (the `LoggingConsumer` feed plus the
//!   `event_id` dedup decorator).

pub mod app;
pub mod domain;
pub mod fold;
pub mod port;
pub mod query;

#[cfg(test)]
pub(crate) mod testkit;
