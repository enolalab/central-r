//! The harness application layer — the port of `internal/harness/app`:
//! the orchestrator that drives a claimed Run's attempt to a durable
//! terminal settlement, and the permission bridge that carries a
//! harness's permission request to an operator.
//!
//! Split: [`ports`] holds the consumer-side ports and value types;
//! [`orchestrator`] the run machinery; [`bridge`] the approval registry
//! and decider vocabulary shared between them.

pub mod bridge;
pub mod orchestrator;
pub mod ports;

#[cfg(test)]
pub(crate) mod testkit;
#[cfg(test)]
mod tests;

pub use orchestrator::{Orchestrator, OrchestratorConfig, OrchestratorDeps, PendingRequest};
pub use ports::{
    ArtifactOutcome, ArtifactOutcomeKind, ArtifactRole, ArtifactSink, CancelSignal, Capture,
    ClaimedRun, Clock, DispatchCase, DispatchableRun, FailureCode, HarnessResult, Milestone,
    MilestoneKind, NeverCancelled, Outcome, RealTicker, ResolveStore, ResumeFrom, ResumeSource,
    RunLifecycle, Settlement, TaskEventSink, Ticker, WorkspaceCapture, WorkspaceProvisioner, codes,
    launch_env, milestone_kinds,
};
