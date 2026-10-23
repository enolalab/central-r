//! PostgreSQL store for harness session attempts — the port of
//! `internal/adapter/postgres/harness` (ADR 0035; harness phase 1b design
//! §7, phase 3a decisions 3 and 9, phase 3c decisions 8/9/11/13/16, phase
//! 3g decisions 6 and 9, phase 3k decision 4).
//!
//! [`PgHarnessStore`] keeps every `sqlx` type inside the adapter and
//! implements the `central-harness` durable ports and read projections:
//!
//! - `central_harness::port::AttemptStore` — `create`/`load`/
//!   `live_attempt_for_run`, the version+fence compare-and-swap `save`,
//!   the atomic bounded-metadata event append `append_event` (a raw
//!   frame never reaches the table), `expire_permission` and
//!   `load_approval` over `central.harness_attempts`,
//!   `central.harness_events` and `central.harness_permission_approvals`
//!   (migrations b30–b32);
//! - `central_harness::port::LeaseBinder` — `with_lease` binds an
//!   execution lease; every write of the bound store re-checks the
//!   run's live `central.execution_ownership` row inside the write's
//!   transaction (generation, expiry, bearer SHA-256, claimed
//!   StepAttempt);
//! - `central_harness::port::ApprovalStore` — the operator decision
//!   compare-and-set and the workspace-scoped approval reads;
//! - `central_harness::port::RecoveryStore` — the lease-dead recovery
//!   lane and the `(prepared_at, id)` keyset candidate scan;
//! - the read projections `central_harness::query::AttemptSummaryRead`,
//!   `central_harness::query::HarnessEventRead`,
//!   `central_harness::query::PendingApprovalRead` and
//!   `central_harness::query::BudgetUsageRead`.
//!
//! Upstream divergence notes:
//!
//! - `pgx` binds uuid text; `sqlx` binds `Uuid`/`Option<Uuid>` (SQL
//!   `NULL`) directly, so upstream's `::uuid` casts, `nullText` and
//!   `zeroX` sentinels collapse into typed binds.
//! - A stored row the domain refuses is `pg_data_corrupt`/`internal`
//!   (the adapter-wide convention), where upstream wraps
//!   `ErrInvalidAttempt`/`ErrInvalidApproval` — corrupt durable state is
//!   never a caller error.
//! - The `tasks.permission_policy` column (b31) is not consulted by the
//!   approval gate: upstream's decision/expire SQL checks the live
//!   lease, matching the port contract.
//! - Upstream `NewStore` accepts an open `pgx.Tx` so a caller can run
//!   harness writes inside its own atomic unit (savepoints); this store
//!   is pool-bound like the rest of the adapter family — no upstream
//!   production caller uses the capability, and a tx-taking
//!   constructor can be added if a composed-write flow ever needs it.
//! - Port futures carry no `Context`; the upstream
//!   `TestStoreHonoursCancellation` guarantee now rests on sqlx
//!   `Transaction` drop-rollback.
//!
//! Lock ordering inside every write transaction: the attempt row is
//! locked `FOR UPDATE` first, then `central.execution_ownership` and
//! `central.step_attempts` are share-locked, then
//! `central.harness_permission_approvals` is written — consistent with
//! `execution`'s ordering (ownership → step_attempts → approvals);
//! `central.harness_attempts`/`central.harness_events` have no other
//! writer.

mod approval;
mod queries;
mod recovery;
mod store;

pub use store::PgHarnessStore;
