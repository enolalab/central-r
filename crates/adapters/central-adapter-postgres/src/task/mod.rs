//! PostgreSQL stores for `central-task` (port of
//! `internal/adapter/postgres/task/`).
//!
//! - [`Store`] — [`central_task::port::ChangeSetStore`] (the atomic
//!   change-set commit: task-row CAS, per-run CAS, workspace event
//!   sequence reservation + `central.events` append, and the
//!   `(workspace_id, command_scope, idempotency_key)` command receipt,
//!   all in one bounded transaction) plus
//!   [`central_task::port::AggregateLoader`].
//! - [`ListStore`] — [`central_task::query::TaskListRead`].
//! - [`DetailStore`] — [`central_task::query::TaskDetailRead`].
//! - [`EventLogStore`] — [`central_task::query::TaskEventLogRead`].
//! - [`MilestoneStore`] — the adapter-owned harness milestone append
//!   (`central.events` with a deterministic UUID-v5 event id derived
//!   from the milestone key, so a retried append is written once).
//!
//! Transaction discipline mirrors upstream: every coordinator opens a
//! bounded transaction through [`crate::store_support::begin_tx`]
//! (`lock_timeout = 2s`, `statement_timeout = 5s`,
//! `idle_in_transaction_session_timeout = 10s`).
//!
//! Lock-order discipline (postgresql-adapter-mapping §6, upstream
//! `CommitTaskChangeSet`): `workspace_event_counters` → `tasks` →
//! `runs` → `events` → `command_receipts`. The idempotent-replay
//! receipt *read* ahead of the counter reservation takes no
//! conflicting lock; `workspaces` itself is never locked here (task
//! row locks serialize the workspace's aggregate writes).
//!
//! Row reconstruction rejects drifted vocabularies as
//! [`store_support::PG_DATA_CORRUPT`] — a stored row a validated
//! writer could not have produced is corrupt durable state, never a
//! caller error.
//!
//! Upstream divergence note: upstream binds `zeroableRunID` — the
//! empty string — into `::uuid` parameters when an intent carries no
//! run, which PostgreSQL rejects as malformed (and the b08
//! `events_workspace_run_b08_fkey` would reject the zero UUID anyway).
//! [`central_task::domain::TaskEventIntent::run_id`] is `Option`, so
//! `None` binds SQL `NULL` — the representation the schema and the
//! read projections already use for "no run".

mod event_log_store;
mod milestone_store;
mod queries;
mod store;

pub use event_log_store::{EventLogStore, HIDDEN_TASK_EVENT_KINDS};
pub use milestone_store::{MILESTONE_PRODUCER, Milestone, MilestoneStore, milestone_event_id};
pub use store::{DetailStore, ListStore, Store};

use central_foundation::failure::Failure;
use central_task::domain::codes;

/// `conflict` code for the `(workspace_id, run_key)` submit-dedup
/// collision — upstream's `conflictFailure("DUPLICATE_IDEMPOTENCY_KEY")`.
pub const DUPLICATE_IDEMPOTENCY_KEY: &str = "duplicate_idempotency_key";

/// `conflict` code for a stored `(workspace, scope, key)` receipt the
/// commit path cannot replay — upstream's
/// `conflictFailure("idempotent replay is unavailable")` /
/// `conflictFailure("idempotent request fingerprint mismatch")`.
pub const IDEMPOTENCY_CONFLICT: &str = "idempotency_conflict";

fn invalid(reason: &'static str) -> Failure {
    Failure::invalid(codes::INVALID, reason)
}

fn conflict(code: &'static str, reason: &'static str) -> Failure {
    Failure::conflict(code, reason)
}
