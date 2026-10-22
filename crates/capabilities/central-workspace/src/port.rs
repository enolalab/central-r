//! Workspace command-persistence ports (rust-application-boundaries.md
//! §2.3/§7.6).
//!
//! Operation-oriented traits only — no CRUD, no table mirrors, no
//! transaction handles. The PostgreSQL adapter implements them inside
//! its own bounded transactions; `sqlx` types never appear here.
//!
//! Contract notes (adapter-mapping §3.1–§3.2):
//!
//! - Workspace lookup is always by primary key; the store load is a
//!   single-point read.
//! - Change-set commits evaluate the [`domain::WorkspaceGuard`] at the
//!   linearization point: `Absent` maps to a plain insert (duplicate key
//!   = conflict), `Present` maps to a conditional update pinning
//!   `state`, `security_epoch`, and `restore_epoch`.
//! - The quota-ledger row lock for capacity reserve/settle/release is
//!   owned by `central-artifact`'s atomic conditional port (mapping
//!   §3.1 boundary note, §5.2 A5–A7); this crate owns only the shared
//!   domain arithmetic in [`domain::QuotaLedger`].
//! - `workspace_event_counters` sequence allocation is internal to
//!   other capabilities' change-set commits (mapping §3.2); it is
//!   deliberately absent from this port surface.

use central_foundation::failure::Failure;
use central_foundation::identity::WorkspaceId;

use crate::domain::{WorkspaceChangeSet, WorkspaceSnapshot};

/// Typed durable-snapshot load plus domain-approved change-set commit
/// for `central.workspaces`.
#[trait_variant::make(Send)]
pub trait WorkspaceStore: Send + Sync + 'static {
    /// Loads the current durable snapshot for `workspace_id`.
    /// `Ok(None)` means the workspace does not exist — the caller
    /// maps that to `workspace_not_found`; the port does not guess.
    async fn load_snapshot(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Option<WorkspaceSnapshot>, Failure>;

    /// Commits a domain-approved change set atomically.
    ///
    /// The adapter evaluates [`domain::WorkspaceGuard`] at commit
    /// time: a stale guard returns a `Conflict`-kind failure
    /// (`workspace_state_conflict` / `workspace_already_exists`), and
    /// application code does not blind-retry a business decision
    /// against newly changed state (§7.2). On success the committed
    /// row facts (including database-stamped `updated_at`) are
    /// returned.
    async fn commit_change_set(
        &self,
        change_set: WorkspaceChangeSet,
    ) -> Result<WorkspaceSnapshot, Failure>;
}
