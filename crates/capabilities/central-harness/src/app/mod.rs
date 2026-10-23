//! The harness application layer — the port of `internal/harness/app`:
//! the orchestrator that drives a claimed Run's attempt to a durable
//! terminal settlement, the dispatcher that claims Runs under a
//! bounded concurrency, the reconciler that aligns non-terminal
//! attempts with their linked StepAttempts at serve start, and the
//! permission bridge that carries a harness's permission request to an
//! operator.
//!
//! Split: [`ports`] holds the consumer-side ports and value types;
//! [`orchestrator`] the run machinery; [`dispatcher`] the claim loop;
//! [`reconciler`] the startup pass and the operator `Resolver`;
//! [`bridge`] the approval registry and decider vocabulary shared
//! between them.

pub mod bridge;
pub mod dispatcher;
pub mod orchestrator;
pub mod ports;
pub mod reconciler;

#[cfg(test)]
pub(crate) mod testkit;
#[cfg(test)]
mod tests;

pub use dispatcher::{
    AttemptRunner, DEFAULT_PAUSE_RETRY, DEFAULT_POLL_INTERVAL, DEFAULT_SHUTDOWN_BUDGET, DiscardLog,
    DispatchLog, Dispatcher, DispatcherConfig, DispatcherDeps, DispatcherState, MAX_CONCURRENCY,
    PauseReason, Round, Spawned, Status,
};
pub use orchestrator::{Orchestrator, OrchestratorConfig, OrchestratorDeps, PendingRequest};
pub use ports::{
    ArtifactOutcome, ArtifactOutcomeKind, ArtifactRole, ArtifactSink, CancelSignal, Capture,
    ClaimedRun, Clock, DispatchCase, DispatchableRun, FailureCode, HarnessResult, Milestone,
    MilestoneKind, NeverCancelled, Outcome, RealTicker, ResolveStore, ResumeFrom, ResumeSource,
    RunLifecycle, Settlement, TaskEventSink, Ticker, WorkspaceCapture, WorkspaceProvisioner, codes,
    launch_env, milestone_kinds,
};
pub use reconciler::{
    AMBIGUITY_RESTART, DECIDED_BY_OPERATOR_RESUME, DECIDED_BY_RECOVERY,
    REASON_RECOVERED_SETTLEMENT, ReconcileSummary, Reconciler, Resolver,
};
