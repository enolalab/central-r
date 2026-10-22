//! `central-execution` — the B08 execution capability crate.
//!
//! Ports `central/internal/execution` (domain, harness-run transitions,
//! resume/recovery transitions), `internal/execution/port`,
//! `internal/execution/app`, and `internal/execution/app/query`, plus
//! the claimability decorator that upstream lives in `internal/task`
//! (moved here to invert the cyclic dependency edge — see
//! `docs/architecture/rust-application-boundaries.md`).
//!
//! Layer structure:
//!
//! - [`domain`] — pure, synchronous evaluators: step/attempt/tool-call
//!   lifecycles, lease fencing, evidence construction, and
//!   [`domain::ExecutionChangeSet`] validation.
//! - [`harness_run`] — fused harness transitions
//!   ([`harness_run::StartHarnessRunCommand`],
//!   [`harness_run::AbandonPreparedCommand`],
//!   [`harness_run::SettleCancellationCommand`]) and recovery
//!   evaluators
//!   ([`harness_run::evaluate_recovery`],
//!   [`harness_run::evaluate_recovery_cancellation`],
//!   [`harness_run::evaluate_recovery_completion`]).
//! - [`resume`] — the resume half-lifecycle
//!   ([`resume::ResumeReconciledAttemptCommand`],
//!   [`resume::ResumeRecoveryEpochCommand`]) and recovery-epoch /
//!   claimability policies.
//! - [`port`] — async storage/external contracts including the single
//!   composite-commit seam (`CompositeStore`).
//! - [`query`] — typed read contracts and the claimability decorator.
//! - [`app`] — orchestration-only services that evaluate domain
//!   commands, enforce the command fence policy, and commit through
//!   `CompositeStore`.

pub mod app;
pub mod domain;
pub mod harness_run;
pub mod port;
pub mod query;
pub mod resume;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

#[cfg(test)]
#[path = "app_tests.rs"]
mod app_tests;
