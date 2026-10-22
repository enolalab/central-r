//! `central-workspace` — workspace lifecycle, quotas, and security/restore
//! epochs.
//!
//! Four-layer capability crate (rust-application-boundaries.md §2):
//!
//! - [`domain`] — the [`domain::WorkspaceSnapshot`] durable decision
//!   snapshot mirroring `central.workspaces` (adapter-mapping §3.1), the
//!   `active`/`deleted` state machine, quota-ledger predicates, and the
//!   forward-only security/restore epoch transitions. Pure synchronous
//!   Rust; no I/O, no `tokio`, no `async fn`.
//! - [`port`] — command-persistence traits the PostgreSQL adapter
//!   implements: typed snapshot loads and domain-approved change-set
//!   commits.
//! - [`query`] — declaration-only bounded read contracts
//!   (`query::WorkspaceStatusRead`) consumed by [`app::WorkspaceService`]
//!   after the caller's authority decision.
//! - [`app`] — the orchestration Service: loads snapshots through ports,
//!   invokes domain decisions, commits change sets.

pub mod app;
pub mod domain;
pub mod port;
pub mod query;
