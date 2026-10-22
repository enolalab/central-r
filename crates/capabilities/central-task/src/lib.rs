//! `central-task` — the B07 task lifecycle capability.
//!
//! Four-layer capability crate (rust-application-boundaries.md §2);
//! ports `central/internal/task`.
//!
//! - [`domain`] — the lifecycle vocabularies ([`domain::TaskStatus`],
//!   [`domain::RunStatus`], [`domain::WaitingReason`],
//!   [`domain::PermissionPolicy`], [`domain::Budget`]), the
//!   [`domain::Task`]/[`domain::Run`] durable aggregates, the
//!   [`domain::TaskAggregate`] consistency rules, the
//!   [`domain::TaskChangeSet`] command result, and every transition
//!   evaluator (`submit_task` … `rerun_cancelled_task`). Pure
//!   synchronous Rust: no `async fn`, no `tokio`, no I/O, no clock
//!   reads — every command carries its `now`.
//! - [`execution_facade`] — the sealed [`execution_facade::ExecutionTransition`]
//!   commands `central-execution` evaluates inside its own composite
//!   commits (ports `execution_facade.go`). Non-committing: it only
//!   routes to the domain evaluators and returns change sets.
//! - [`port`] — command-persistence traits the PostgreSQL adapter
//!   implements: [`port::ChangeSetStore`] (atomic change-set commit)
//!   and [`port::AggregateLoader`] (typed aggregate + version load).
//! - [`query`] — declaration-only bounded read contracts
//!   (`TaskListRead`, `TaskDetailRead`, `TaskEventLogRead`) with typed
//!   seek cursors; no offset pagination. The upstream claimability
//!   decorator is intentionally absent: per the §2.2 cyclic-edge rule
//!   `central-execution::query` owns claimability decoration, and this
//!   crate never imports `central-execution`.
//! - [`app`] — [`app::TaskService`]: orchestration only. Evaluates the
//!   domain command, stamps the command scope, commits through the
//!   store.

pub mod app;
pub mod domain;
pub mod execution_facade;
pub mod port;
pub mod query;
