//! Append port for `central-event`.
//!
//! Events enter durable state only inside change-set commits
//! (adapter-mapping §3.11: "Events are never created through a
//! standalone port"). The port is therefore deliberately narrow: the
//! caller hands over validated [`EventIntent`]s and the adapter —
//! inside the caller's change-set transaction — allocates
//! Workspace-local sequences from `workspace_event_counters`, seals
//! the intents, and inserts the immutable rows. `central_runtime` and
//! `central_outbox` may INSERT; nothing may UPDATE or DELETE.

use central_foundation::failure::Failure;
use central_foundation::identity::WorkspaceId;

use crate::domain::{Event, EventIntent};

/// The maximum intents one append call may carry — mirrors the
/// change-set commit bound (≤ 8 Events per command receipt,
/// adapter-mapping §5 C1).
pub const MAX_APPEND_BATCH: usize = 8;

/// The append contract. Sequence allocation happens inside the port
/// implementation's transaction — the domain never assigns sequences.
#[trait_variant::make(Send)]
pub trait EventJournal: Send + Sync + 'static {
    /// Atomically allocates the next `intents.len()` sequences for the
    /// Workspace and appends the sealed Events. Empty input appends
    /// nothing; more than [`MAX_APPEND_BATCH`] intents is an
    /// `invalid` failure — a single command never produces more.
    ///
    /// Sequence allocation and insert are atomic with the caller's
    /// change-set commit; a conflict on
    /// `events_workspace_sequence_unique` indicates an allocation bug
    /// and surfaces as `FailureKind::Internal` (adapter-mapping §5).
    async fn append_events(
        &self,
        workspace_id: WorkspaceId,
        intents: Vec<EventIntent>,
    ) -> Result<Vec<Event>, Failure>;
}
