//! `central-retry` — the Phase-2 Slice-2D (b37) retry/timeout domain:
//! the fail-closed failure-class taxonomy, the journaled backoff policy,
//! the per-class and absolute attempt budgets, the three-level timeout
//! hierarchy, and the compensation-hook vocabulary. Pure port of
//! `central/internal/retry` — no `sqlx`, no `tokio`, no `uuid`.
//!
//! Four-layer capability crate (rust-application-boundaries.md §2):
//!
//! - [`domain`] — pure synchronous evaluation: reason codes, classes,
//!   [`domain::RetryPolicy`], [`domain::compute_delay`],
//!   [`domain::budget_remaining`], the [`domain::TimeoutHierarchy`]
//!   composition and deadline predicates, [`domain::decide`], and
//!   [`domain::parse_compensation`]. Every timestamp arrives as
//!   caller-supplied durable evidence — the domain never reads a clock.
//! - [`port`] — the durable retry substrate seam (upstream
//!   `internal/retry/port`): the atomic conditional outcome ledger,
//!   budget reads, the timeout sweep, the compensation executor, and
//!   the clock/jitter determinism seams.
//! - [`query`] — the attempt outcome/decision history projection over
//!   `attempt_outcomes` and `attempt_decisions`.

pub mod domain;
pub mod port;
pub mod query;
