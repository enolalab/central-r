//! `central-event` — the Phase-1 immutable Event envelope and the
//! seek-paginated Workspace event feed (`docs/events/v1.md`,
//! adapter-mapping §3.11).
//!
//! Four-layer capability crate (rust-application-boundaries.md §2):
//!
//! - [`domain`] — the v1 envelope (identity, Workspace-local sequence,
//!   `schema_version = "v1"`, type/aggregate/state-transition metadata,
//!   correlation/causation, allowlisted actor, bounded sanitized
//!   payload), the producer-side validation every append must pass
//!   (≤ 32 KiB serialized, depth ≤ 8, payload-internal depth ≤ 3,
//!   sensitive keys denied), and pure synchronous rules.
//! - [`port`] — the append port; Events enter durable state only inside
//!   change-set commits with workspace-counter sequence allocation.
//! - [`query`] — `query::EventFeedRead` (Q3), forward-only seek
//!   pagination over `(workspace_id, event_sequence)` — never offsets.
//! - [`app`] — the orchestration Service.

pub mod app;
pub mod domain;
pub mod port;
pub mod query;
