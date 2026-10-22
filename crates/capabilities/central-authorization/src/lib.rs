//! `central-authorization` — capability evaluation and durable Approval
//! recording (ADR 0003, capability-policy.md).
//!
//! Four-layer capability crate (rust-application-boundaries.md §2):
//!
//! - [`domain`] — the `resource × effect × scope` capability taxonomy,
//!   the Phase-1 default policy matrix evaluation
//!   (`allow`/`require_approval`/`deny` with strictest-composition and
//!   task-bounded ≤ 24 h grant ceilings), the `central.approvals`
//!   capability-grant record lifecycle (§3.18), effective-grant
//!   derivation bound to the post-restore security epoch, secret-use
//!   audit evidence, and the genesis authority records
//!   (`internal/authority/genesis.go`). Pure synchronous Rust.
//! - [`port`] — command-persistence and evidence ports: approval
//!   change-set commits (C7 `ResolveApproval`), secret-use evidence
//!   append (§3.19), and the genesis binding/receipt store.
//! - [`query`] — `query::ApprovalSummaryRead` (Q5), a bounded
//!   Task-scoped summary read.
//! - [`app`] — the orchestration Service.

pub mod app;
pub mod domain;
pub mod port;
pub mod query;
