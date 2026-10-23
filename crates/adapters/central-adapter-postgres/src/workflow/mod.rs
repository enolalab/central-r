//! PostgreSQL adapter for the Phase-2 workflow graph (b33/b37) — port
//! of `internal/adapter/postgres/workflow/store.go`.
//!
//! [`Store`] implements `central-workflow`'s seams:
//!
//! - [`central_workflow::port::WorkflowStore`] — `emit_batch`,
//!   `transition`, `recompute_ready`, `cancel_node`,
//!   `resolve_ambiguous`, and the `node`/`nodes_for_run`/`edges_for_run`
//!   reads. Every mutating method commits its state change and its
//!   canonical `run_events` rows in ONE transaction anchored on the
//!   run-row `FOR UPDATE` lock (spec-6 OQ-1) — the same serialization
//!   point the event journal shares, so the two stores compose through
//!   [`crate::eventjournal::append_tx`].
//! - [`central_workflow::query::WorkflowGraphRead`] — the bounded
//!   `(created_at, id)` keyset graph page.
//!
//! The emit path's validation seams — harness launchability, artifact
//! finalization, and the effective `Caps` — are store fields set at
//! composition (upstream `Store.HarnessLaunchable`/`ArtifactFinalized`/
//! `Caps`); an unset seam is fail-closed inside the transaction.

mod store;

pub use store::Store;
