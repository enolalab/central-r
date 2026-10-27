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
pub mod backup;
pub mod checkpoint;
pub mod error;
pub mod event;
pub mod eventjournal;
pub mod execution;
pub mod harness;
pub mod migrate;
pub mod recovery;
pub mod runview;
pub mod scheduler;
pub mod serve_support;
pub mod session;
/// `BlockingConn` is `pub` because the backup/restore worker
/// composition shares one dedicated `central_runtime` session across
/// the exclusion lease, accepted-facts, census, and ready-artifact
/// readers — upstream's single `connection` threaded through every
/// C01 constructor.
pub mod store_support;
pub mod task;
pub mod workflow;
pub mod workspace;
