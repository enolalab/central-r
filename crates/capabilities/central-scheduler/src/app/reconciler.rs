//! The startup reconcile-before-reinvoke gate — port of
//! `central/internal/scheduler/app/reconciler.go` (spec-2 decision 9):
//! after a Central restart, expired leases follow the expiry path and
//! live leases whose `worker_id` has no current registration are
//! treated as lost — all before any post-restart dispatch.
//!
//! Upstream makes it a `kernel.Preflight`, deliberately NOT a
//! `kernel.Component`: serve composition runs it in the preflight gate
//! before the claim loop may accept work, and a `Component` whose
//! `Run` returns at once would read as an unexpected termination to
//! the kernel. The Rust shape keeps that: [`Reconciler::run`] is one
//! pass the kernel's preflight stage awaits.

use central_foundation::failure::Failure;

use crate::port::Store;

/// The startup reconcile gate (upstream `app.Reconciler`).
pub struct Reconciler<S: Store> {
    /// The durable scheduler substrate.
    pub store: S,
    /// Journals the reconcile pass's events; empty lets the store
    /// apply its own default.
    pub actor: String,
}

impl<S: Store> Reconciler<S> {
    /// Builds a reconciler over `store` with the store-default actor.
    pub fn new(store: S) -> Self {
        Self {
            store,
            actor: String::new(),
        }
    }

    /// Performs the single reconcile pass and returns its outcome
    /// (upstream `Run`). The pass is idempotent, so a rerun after an
    /// aborted startup converges on the same state.
    pub async fn run(&self) -> Result<(), Failure> {
        self.store.reconcile(&self.actor).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::fakes::RecordingStore;
    use crate::testkit::block_on;

    // -- upstream components_test.go: TestReconcilerRunsOnce ---------

    /// One run performs exactly one reconcile pass under the
    /// configured actor.
    #[test]
    fn reconciler_runs_once() {
        let store = RecordingStore::default();
        let mut r = Reconciler::new(store);
        r.actor = "serve-preflight".to_string();

        block_on(r.run()).unwrap();
        assert_eq!(r.store.reconcile_calls(), 1);
        assert_eq!(r.store.reconcile_actor(), "serve-preflight");
    }

    // -- upstream components_test.go: TestReconcilerPropagatesStoreError

    /// A store failure propagates verbatim — reconcile failure blocks
    /// startup, it is never swallowed.
    #[test]
    fn reconciler_propagates_store_error() {
        let cause = Failure::unavailable("STORE_UNAVAILABLE", "pg down");
        let store = RecordingStore::default();
        store.set_reconcile_err(cause.clone());
        let r = Reconciler::new(store);

        let err = block_on(r.run()).unwrap_err();
        assert_eq!(err, cause);
    }

    // -- upstream components_test.go: unconfigured reconciler --------
    // Unconfigured is unrepresentable: `Reconciler::new` requires the
    // store.
}
