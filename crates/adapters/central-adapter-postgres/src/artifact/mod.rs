//! PostgreSQL artifact lifecycle store — port of
//! `internal/adapter/postgres/artifact/` (B10 store, two-phase
//! workspace-scoped deletion, `ArtifactSummaryRead`, and the atomic
//! `CompletionContributor`).
//!
//! [`Store`] keeps every `sqlx` type inside the adapter and implements
//! the `central-artifact` ports:
//!
//! - [`port::Store`] — reservation admission, the command-stage
//!   lifecycle transitions, receipt replay, and `load_artifact`.
//! - [`port::TwoPhaseDeleteStore`] — the `delete_pending` intent, the
//!   atomic `deleted` + tombstone settlement, and `has_tombstone`.
//! - [`query::ArtifactSummaryRead`] — bounded `(updated_at DESC, id
//!   DESC)` keyset pagination on `artifacts_task_id_idx`.
//! - [`port::CompletionContributor`] — the single
//!   finalize-plus-execution-completion transaction: the B08 lease
//!   fence, capacity settle, quota charge, and every event/outbox row
//!   commit or roll back together.
//!
//! Completion lock ordering (postgresql-adapter-mapping §6, upstream
//! `CommitArtifact`): `workspace_event_counters` → `workspaces` quota
//! (`FOR NO KEY UPDATE` — never `FOR UPDATE`, so a foreign-key check's
//! `FOR KEY SHARE` can still run) → `tasks` → `runs` →
//! `execution_ownership` → `steps` → `step_attempts` → `artifacts` →
//! `capacity_reservations`.
//!
//! Upstream divergence notes:
//!
//! - `pgx` binds text that is cast to `uuid`; `sqlx` binds `Uuid`
//!   values directly. Upstream's `''` sentinel on `NULLIF($n,'')::uuid`
//!   parameters becomes a bound `Option<Uuid>` — `None` is SQL `NULL`.
//! - `Option<ContentGeneration>` binds the promote/finalize content
//!   generation; `None` is SQL `NULL`.
//! - Tombstone settlement (`central.artifact_tombstones` INSERT) is
//!   intentionally withheld from `central_runtime`: the settlement runs
//!   under migration/owner authority in tests and the R6 prune lane.

use central_foundation::failure::{Failure, FailureKind};

mod commit;
mod queries;
mod store;

pub use store::Store;

// ---------------------------------------------------------------------------
// Failure constructors — the adapter mirrors upstream `failure(Class, Reason)`
// with FailureKind::{Invalid, Conflict, Denied} plus a corruption classifier.
// ---------------------------------------------------------------------------

pub(crate) fn failure(kind: FailureKind, code: &'static str) -> Failure {
    Failure::new(kind, code, "artifact store refused")
}

pub(crate) fn invalid(code: &'static str) -> Failure {
    failure(FailureKind::Invalid, code)
}

pub(crate) fn conflict(code: &'static str) -> Failure {
    failure(FailureKind::Conflict, code)
}

pub(crate) fn denied(code: &'static str) -> Failure {
    failure(FailureKind::Denied, code)
}

pub(crate) fn corrupt(what: &'static str) -> Failure {
    Failure::internal(crate::store_support::PG_DATA_CORRUPT, what)
}
