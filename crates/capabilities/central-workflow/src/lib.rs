//! `central-workflow` — the Phase-2 Slice-2A (b33) workflow-graph
//! domain: the node state machine, the `central.child-spec/v1`
//! batch-atomic validation, the event-driven readiness evaluator, and
//! the cancel cascade — pure port of `central/internal/workflow`. No
//! `sqlx`, no `tokio`, no `uuid`.
//!
//! Four-layer capability crate (rust-application-boundaries.md §2):
//!
//! - [`domain`] — pure synchronous vocabulary and write unit:
//!   [`domain::NodeStatus`], [`domain::EdgeKind`],
//!   [`domain::WorkspaceKind`], [`domain::Node`], [`domain::Edge`],
//!   [`domain::ChildSpec`]/[`domain::ChildSpecNode`],
//!   [`domain::Caps`], the [`domain::GraphChangeSet`] /
//!   [`domain::NodeTransition`] expected-state-guarded write unit,
//!   [`domain::GraphEventIntent`], and the domain
//!   [`domain::Failure`]/[`domain::FailureClass`] taxonomy.
//! - [`validate`] — [`validate::validate_batch`]: the ordered,
//!   atomic `SPEC_VALIDATION_FAILED` refusal of a malformed
//!   child-spec emission, plus [`validate::batch_depths`] for the
//!   emit-time depth composition. `None`/`Option` seams are
//!   fail-closed.
//! - [`readiness`] — [`readiness::evaluate_readiness`] (the
//!   `declared → ready` flip: ordering prerequisites `succeeded`,
//!   `artifact` in-edges finalized, `not_before` elapsed),
//!   [`readiness::plan_cancel_cascade`] /
//!   [`readiness::cancel_cascade`], [`readiness::plan_transition`],
//!   and [`readiness::resolve_ambiguous`]. Every timestamp arrives as
//!   caller-supplied durable evidence — the domain never reads a
//!   clock.
//! - [`port`] — [`port::WorkflowStore`]: the append-only graph seam
//!   whose mutating methods commit change + `run_events` in one
//!   transaction anchored on the run-row `FOR UPDATE` lock.
//! - [`query`] — [`query::WorkflowGraphRead`]: the bounded
//!   `(created_at, id)` keyset page over a run's nodes plus the
//!   in-edges attached to them.

pub mod domain;
pub mod port;
pub mod query;
pub mod readiness;
pub mod validate;
