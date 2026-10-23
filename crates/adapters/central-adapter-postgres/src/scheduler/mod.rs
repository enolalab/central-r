//! The PostgreSQL scheduler store — port of upstream
//! `internal/adapter/postgres/scheduler/{store,outcome}.go`: the b35
//! worker/attempt/lease substrate, the dispatch-phase fenced writes,
//! and the b37 outcome ledger + timeout sweep + compensation hooks.
//!
//! Upstream carries both surfaces on one `Store` struct; the Rust port
//! keeps that single-writer invariant by implementing every trait on
//! [`PgSchedulerStore`], with [`PgOutcomeStore`] as the named
//! retry-facing handle over the same struct.
//!
//! - [`store`] — `central_scheduler::port::Store` (15 methods),
//!   `central_scheduler::query::SchedulerRead`.
//! - [`outcome`] — `central_retry::port::Store` (5 methods),
//!   `central_retry::query::AttemptHistoryRead`.
//!
//! Every mutating method commits its state change plus `run_events` +
//! `event_outbox` rows in ONE transaction via
//! [`crate::eventjournal::append_tx`]; lock order is run row → node
//! row → attempt row → lease re-check throughout.

mod outcome;
mod store;

pub use outcome::PgOutcomeStore;
pub use store::PgSchedulerStore;
