//! `central-artifact` — Artifact lifecycle: reserve, stage, verify,
//! promote, finalize; workspace-scoped two-phase deletion with
//! tombstones; content-policy delivery and preview disposition;
//! b34 produce/read lineage (ADR 0005, `docs/artifacts/lifecycle.md`,
//! `docs/artifacts/content-policy.md`, phase-2 artifact lineage spec).
//!
//! Four-layer capability crate (rust-application-boundaries.md §2):
//! `domain` owns the pure lifecycle state machine, `port` the
//! adapter-neutral traits, `query` the read projections, `classifier`
//! the bounded content policy, `app` the orchestrating services, and
//! `reconciler` the bounded fenced recovery pass.

pub mod app;
pub mod classifier;
pub mod domain;
pub mod lineage;
pub mod port;
pub mod query;
pub mod reconciler;

#[cfg(test)]
mod testkit;
