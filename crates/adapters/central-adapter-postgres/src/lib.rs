//! `central-adapter-postgres` — the PostgreSQL infrastructure adapter.
//!
//! The [`migrate`] module ports `internal/adapter/postgres/migrate/` from the
//! Go tree: a native, self-contained migration engine that replays the
//! trusted, compile-time-embedded SQL corpus under `migrations/` verbatim
//! (via `sqlx::raw_sql`, preserving each file's own `begin`/`commit` and
//! `SET LOCAL` transaction boundaries and its durable dirty-intent /
//! clean-marker ledger protocol) instead of `sqlx::migrate!` or
//! `_sqlx_migrations`.
//!
//! Contents:
//!
//! - [`migrate::BaselineInstaller`] — idempotent `v0..v37` install,
//!   `verify_stock_target`, `verify_shape`, `baseline_manifest`.
//! - [`migrate::Runner`] — single-session two-phase advisory-lock
//!   `prepare_up`/`commit_up`/`resume` bound to a
//!   [`migrate::SessionBinding`] (backend PID + postmaster start + boot ID).
//! - [`migrate::Inspector`] — read-only [`migrate::PostgresMigrationFacts`]
//!   plus `verify_serve_baseline` (the serve-readiness shape audit).
//! - [`migrate::ResetRunner`] — version-zero-only destructive reset under
//!   advisory locks and a broker reset-confirmation proof.
//! - [`migrate::reapply_runtime_grants`] — the post-`pg_restore`
//!   grant/column-grant/revoke convergence replay.

pub mod artifact;
pub mod authorization;
pub mod checkpoint;
pub mod error;
pub mod event;
pub mod eventjournal;
pub mod execution;
pub mod migrate;
mod store_support;
pub mod task;
pub mod workflow;
pub mod workspace;
