//! Read contract for `central-eventjournal`: `RunJournalRead` — the
//! verbatim, seq-ordered journal read over `central.run_events` (the
//! read side upstream serves from `internal/runview`'s
//! `EventsForRun`). The DAG places the contract here because the
//! events are this crate's envelope: `central-runview` depends on
//! `central-eventjournal` for [`crate::fold`] types, and the fold
//! needs the canonical rows, not a second projection.
//!
//! Declaration-only: one run-scoped read returning the canonical
//! [`RunEvent`] envelope verbatim in `seq` order. No locks, no
//! writes, no journaled side effects; the caller scope-checks the run
//! through its own projection first, matching the read-side
//! convention the run views apply.

use central_foundation::failure::Failure;
use central_foundation::identity::RunId;

use crate::domain::RunEvent;

/// The read contract behind the journal-verbatim projection.
/// Implemented by `central-adapter-postgres`; consumed by
/// [`crate::fold::fold`]/[`crate::fold::compare_fold`] and by run-view
/// surfaces rendering the per-run timeline.
#[trait_variant::make(Send)]
pub trait RunJournalRead: Send + Sync + 'static {
    /// The run's journaled events in `seq` order as the canonical
    /// [`RunEvent`] envelope — feeding the per-node timeline and
    /// [`crate::fold::fold`]/[`crate::fold::compare_fold`] alike
    /// (upstream `EventsForRun`).
    async fn events_for_run(&self, run_id: RunId) -> Result<Vec<RunEvent>, Failure>;
}
