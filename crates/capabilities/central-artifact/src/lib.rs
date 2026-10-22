//! `central-artifact` — Artifact lifecycle: reserve, stage, verify,
//! promote, finalize; workspace-scoped two-phase deletion with
//! tombstones; content-policy delivery and preview disposition;
//! b34 produce/read lineage (ADR 0005, `docs/artifacts/lifecycle.md`,
//! `docs/artifacts/content-policy.md`, phase-2 artifact lineage spec).
//!
//! Four-layer capability crate (rust-application-boundaries.md §2).
//! `classifier` / `reconciler` / `app` land in a later R2 task.

pub mod domain;
pub mod lineage;
pub mod port;
pub mod query;
