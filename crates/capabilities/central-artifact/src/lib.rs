//! `central-artifact` — Artifact lifecycle: reserve, stage, verify,
//! promote, finalize; workspace-scoped two-phase deletion with
//! tombstones; content-policy delivery and preview disposition
//! (ADR 0005, `docs/artifacts/lifecycle.md`,
//! `docs/artifacts/content-policy.md`).
//!
//! Four-layer capability crate (rust-application-boundaries.md §2).
//! Only [`domain`] exists so far; `lineage` / `port` / `query` /
//! `classifier` / `reconciler` / `app` land in later R2 tasks.

pub mod domain;
