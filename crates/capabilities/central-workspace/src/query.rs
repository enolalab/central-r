//! Workspace read contracts (rust-application-boundaries.md §2.3/§7.4).
//!
//! Declaration-only consumer-side read traits, bounded request types,
//! safe projection types. No pagination applies — workspace status is a
//! singleton read by primary key, so no `SeekCursor` exists here.
//!
//! Projections expose only safe display facts: the workspace identity,
//! lifecycle state, and quota-ledger counters. Owner identity, epochs,
//! and timestamps stay beneath the projection boundary (the status
//! surface never displays them, and epochs are authority-bearing —
//! capability-policy.md §Post-restore authority reset).

use central_foundation::failure::Failure;
use central_foundation::identity::WorkspaceId;
use serde::{Deserialize, Serialize};

use crate::domain::WorkspaceState;

/// Singleton workspace-status request — scoped to exactly one
/// workspace by identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceStatusRequest {
    /// The workspace whose status is requested.
    pub workspace_id: WorkspaceId,
}

/// Safe workspace status projection — display facts only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceStatusProjection {
    /// Workspace identity.
    pub workspace_id: WorkspaceId,
    /// Lifecycle state.
    pub state: WorkspaceState,
    /// Ready-artifact bytes settled against the quota.
    pub quota_ready_bytes: u64,
    /// Ready-artifact count settled against the quota.
    pub quota_ready_count: u64,
    /// Configured ready-byte ceiling.
    pub quota_max_bytes: u64,
}

/// `WorkspaceStatusRead` — singleton status read consumed by
/// [`crate::app::WorkspaceService::workspace_status`] after the
/// caller's authenticated-session + workspace-owner authority
/// decision (§7.5).
///
/// Adapter notes: one round trip, at most one row examined and
/// returned, `central_runtime` / serving-data pool, `READ COMMITTED`.
/// A missing workspace answers `NotFound`; cross-workspace reads are
/// impossible by construction because the request carries the exact
/// workspace identity and the query repeats the workspace predicate.
#[trait_variant::make(Send)]
pub trait WorkspaceStatusRead: Send + Sync + 'static {
    /// Reads the bounded status projection for one workspace.
    async fn status(
        &self,
        req: WorkspaceStatusRequest,
    ) -> Result<WorkspaceStatusProjection, Failure>;
}
