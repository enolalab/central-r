//! `central-checkpoint` — immutable verified continuation evidence
//! (`docs/runtime/checkpoints.md`) plus the b36 resume-checkpoint
//! domain (`internal/checkpoint/domain.go`) this crate must be ready
//! to serve in R4.
//!
//! Four-layer capability crate (rust-application-boundaries.md §2):
//!
//! - [`domain`] — the Phase-1 `central.checkpoints` record (§3.20 +
//!   b08 columns): the closed `checkpoint_kind` vocabulary, the
//!   continuation-payload schema (`schema_version`, `producer_version`,
//!   `continuation{state,cursor,sequence,summary,metadata}`,
//!   `metadata`), the 256 KiB default / 1 MiB hard-max size policy, the
//!   SHA-256 checksum binding, the ordered compatibility verification
//!   and the supported-migration rule (CM-1) — and, for Phase-2
//!   readiness, the b36 subtree-anchored resume record: boundary
//!   legality (D2), format/graph-schema compatibility (D3), the
//!   digest-bound resume token, and retention-class GC selection (D5).
//!   Pure synchronous Rust.
//! - [`port`] — append + ordered-read + GC-commit ports.
//! - [`query`] — `query::RunCheckpointRead`, bounded per-run recovery
//!   snapshots (≤ 50, `checkpoints_run_id_idx`).
//! - [`app`] — the orchestration Service.

pub mod app;
pub mod domain;
pub mod port;
pub mod query;
