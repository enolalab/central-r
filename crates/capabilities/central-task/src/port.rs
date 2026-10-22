//! Task command-persistence ports (ports `internal/task/port/port.go`;
//! rust-application-boundaries.md §2.3/§7.6).
//!
//! Operation-oriented traits only — no CRUD, no table mirrors, no
//! transaction handles. The PostgreSQL adapter implements them inside
//! its own bounded transactions; `sqlx` types never appear here.
//!
//! Contract notes (adapter-mapping §3.3/§3.4):
//!
//! - [`ChangeSetStore::commit_task_change_set`] commits a
//!   domain-approved [`crate::domain::TaskChangeSet`] atomically:
//!   task-row CAS on `expected_task_version`, per-run CAS via
//!   `run_expected_versions` ([`crate::domain::NO_EXISTING_VERSION`]
//!   names an INSERT), the constraint checks, event-intent append, and
//!   the `(workspace_id, scope, idempotency_key)` command-receipt
//!   dedup — all in one transaction. A stale guard surfaces as a
//!   `Conflict`-kind failure; a replayed key carrying a different
//!   payload conflicts rather than silently deduping.
//! - [`AggregateLoader::load_aggregate`] is the read side of the
//!   load/decide/commit discipline: it returns the durable aggregate
//!   plus the exact versions the caller must echo back as
//!   `expected_task_version`/`expected_run_version`. It answers
//!   `NotFound` (`codes::TASK_NOT_FOUND`) for a missing or
//!   cross-workspace task, exactly like `TaskDetailRead`.

use central_foundation::failure::Failure;
use central_foundation::identity::{CausationId, CorrelationId, TaskId, WorkspaceId};

use crate::domain::{CommitResult, TaskAggregate, TaskChangeSet};

/// The durable Task change-set plus the command identity fields the
/// adapter-level idempotency guards consume (`central.command_receipts`).
#[derive(Debug, Clone, PartialEq)]
pub struct CommitTaskChangeSetRequest {
    /// The workspace the change set commits under; repeats the scope
    /// predicate as defense in depth.
    pub workspace_id: WorkspaceId,
    /// The domain-approved change set.
    pub change_set: TaskChangeSet,
    /// The command scope recorded on the receipt (one of
    /// [`crate::app`]'s `task.*` scope constants).
    pub command_scope: &'static str,
    /// The caller's dedup key; `None` issues no receipt.
    pub idempotency_key: Option<String>,
    /// The scope-wide correlation identity (`correlation_id` column).
    pub correlation_id: Option<CorrelationId>,
    /// The immediate-cause identity (`causation_id` column).
    pub causation_id: Option<CausationId>,
}

/// Atomic Task domain change-set commits.
#[trait_variant::make(Send)]
pub trait ChangeSetStore: Send + Sync + 'static {
    /// Commits the change set atomically (task CAS, per-run CAS,
    /// event append, receipt) and returns the committed facts.
    async fn commit_task_change_set(
        &self,
        req: CommitTaskChangeSetRequest,
    ) -> Result<CommitResult, Failure>;
}

/// A [`TaskAggregate`] plus the version numbers the caller must
/// present unchanged to `request_cancellation`, `retry_failed_task`,
/// `rerun_cancelled_task`, or `settle_cancellation`.
#[derive(Debug, Clone, PartialEq)]
pub struct LoadedAggregate {
    /// The durable aggregate.
    pub aggregate: TaskAggregate,
    /// The task row version.
    pub task_version: i64,
    /// The current run row version; `None` when
    /// `aggregate.current_run` is `None`.
    pub run_version: Option<i64>,
}

/// Loads the current durable Task aggregate and the exact
/// optimistic-lock versions a caller must echo back as
/// `MutationInput.expected_task_version`/`expected_run_version`. It
/// never mutates state.
#[trait_variant::make(Send)]
pub trait AggregateLoader: Send + Sync + 'static {
    /// Loads the aggregate for `task_id` inside `workspace_id`.
    /// Missing or cross-workspace tasks answer
    /// `codes::TASK_NOT_FOUND`.
    async fn load_aggregate(
        &self,
        workspace_id: WorkspaceId,
        task_id: TaskId,
    ) -> Result<LoadedAggregate, Failure>;
}
