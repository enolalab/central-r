//! `central-scheduler` — the Phase-2 Slice-2B (b35) worker-protocol
//! domain: the session-attempt state machine, the worker registration
//! and missed-beat ladder, the fencing node leases, the spec-8
//! concurrency/admission policy, and the app-level worker / claim-loop
//! / dispatch / sweeper / reconciler passes. Pure port of
//! `central/internal/scheduler` — no `sqlx`, no `tokio`, no `uuid`.
//!
//! Four-layer capability crate (rust-application-boundaries.md §2):
//!
//! - [`domain`] — pure synchronous evaluation: [`domain::AttemptState`]
//!   and [`domain::WorkerState`] vocabularies (pinned by b35's CHECK
//!   constraints), the locked protocol constants (15 s heartbeats, 3×
//!   lease TTL, suspect at 2 / lost at 5 missed beats),
//!   [`domain::missed_beats`]/[`domain::ladder`],
//!   [`domain::capability_match`],
//!   [`domain::registration_failure`], the durable
//!   [`domain::Worker`]/[`domain::Lease`]/[`domain::SessionAttempt`]/
//!   [`domain::ClaimedAttempt`] rows, [`domain::expiry_decision`], the
//!   spec-2 reason-code vocabulary, and the domain
//!   [`domain::Failure`]/[`domain::FailureClass`] taxonomy. Every
//!   timestamp arrives as caller-supplied durable evidence — the domain
//!   never reads a clock.
//! - [`admission`] — the spec-8 concurrency cap table
//!   ([`admission::ConcurrencyProfile`], narrowable but never widened
//!   past the compiled `SUPPORTED_*` bounds),
//!   [`admission::check_dispatch_admission`], and the mid-session
//!   [`admission::ceiling_breach`] predicate.
//! - [`port`] — the durable scheduler substrate seam
//!   ([`port::Store`]: single-commit claim/renew/expire/ladder/fenced
//!   dispatch writes), [`port::Provisioner`], [`port::NodeLauncher`]
//!   (the R4-plan name for upstream's `Launcher`; the kernel wires it
//!   to the harness session layer in Task 12), and the
//!   [`port::Clock`] determinism seam.
//! - [`query`] — [`query::SchedulerRead`]: the keyed worker / attempt
//!   ledger / live-lease projections for observability surfaces.
//! - [`app`] — the component passes the kernel supervisor ticks:
//!   [`app::worker::Worker`] (registration + per-beat lease renewal +
//!   deregistration), [`app::claim_loop::ClaimLoop`],
//!   [`app::dispatch::Dispatcher`],
//!   [`app::sweeper::Sweeper`], and
//!   [`app::reconciler::Reconciler`] — with
//!   [`app::dispatch::StubLauncher`] behind the development gate.
//!   Upstream's ticker/`Run`/`Shutdown` plumbing is the kernel's;
//!   cancellation is future-drop.

pub mod admission;
pub mod app;
pub mod domain;
pub mod port;
pub mod query;

#[cfg(test)]
pub(crate) mod testkit;
