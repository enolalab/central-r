//! The in-process scheduler worker — port of
//! `central/internal/scheduler/app/worker.go` (spec-2 decisions 2, 4, 7
//! and 8). [`Worker::register`] performs the registration handshake;
//! the kernel supervisor then calls [`Worker::heartbeat_once`] once at
//! component start and again per `tick_interval` (upstream `Run`'s
//! `heartbeat()` before the ticker, worker.go:102), and
//! [`Worker::deregister`] on shutdown, releasing never-started leases
//! back to `ready` in the store's single transaction.
//!
//! The heartbeat IS the lease renewal (decision 4): a worker holding
//! no leases has no deadlines to miss and stays active. A renewal
//! rejected `LEASE_RENEWAL_STALE` means the lease is expired, released,
//! or superseded — the store already journaled
//! `lease_renewal_rejected`, so the worker drops that lease from its
//! renewal set rather than journal a fresh rejection every beat; it no
//! longer owns the node. Other renewal errors are transient and retry
//! on the next beat.

use std::collections::HashSet;
use std::sync::Mutex;

use central_foundation::failure::Failure;
use central_foundation::identity::{NodeLeaseId, WorkerId, WorkspaceId};
use time::Duration;

use crate::domain;
use crate::port::Store;

/// Journals the clean deregistration's events — the worker's own
/// shutdown is the actor (spec-6 actor vocabulary; the store falls
/// back only when actor is empty). Upstream `actorWorker`.
pub const ACTOR_WORKER: &str = "worker";

/// The in-process worker component state guarded for the register →
/// heartbeat → deregister lifecycle.
#[derive(Default)]
struct WorkerInner {
    /// The registered worker id — `Some` only after a successful
    /// handshake (upstream `w.id`/`registered`).
    registered: Option<WorkerId>,
    /// Leases dropped from the renewal set after a
    /// `LEASE_RENEWAL_STALE` rejection (upstream `dead`).
    dead: HashSet<NodeLeaseId>,
}

/// The in-process scheduler worker (upstream `app.Worker`). The fields
/// are the spec-2 registration facts; `inner` is the runtime state the
/// handshake establishes.
///
/// Upstream's `Run`/`Shutdown` (ticker + cancel/done plumbing) is the
/// kernel supervisor's job — this type carries the passes and the
/// `tick_interval` cadence contract. Cancellation is future-drop: a
/// heartbeat abandoned mid-await simply renews nothing further.
pub struct Worker<S: Store> {
    /// The durable scheduler substrate.
    pub store: S,
    /// Pins the registration's `worker_id`. `None` generates a fresh
    /// V7 id inside [`register`](Self::register) (OQ-7: fresh
    /// `worker_id` per process start). Composition sets it explicitly
    /// when sibling components — the claim loop — must know the id
    /// before `register` executes.
    pub worker_id: Option<WorkerId>,
    /// The workspace the worker registers into.
    pub workspace_id: WorkspaceId,
    /// The harness kinds this worker can launch.
    pub harness_kinds: Vec<String>,
    /// The workspace kinds this worker can execute in.
    pub workspace_kinds: Vec<String>,
    /// The worker's live-attempt ceiling.
    pub max_concurrent_attempts: i32,
    /// The renewal cadence the supervisor ticks on; `<= ZERO` uses
    /// [`domain::heartbeat_interval`] (the locked 15s).
    pub interval: Duration,
    /// Journals the deregistration's events; empty uses
    /// [`ACTOR_WORKER`].
    pub actor: String,

    inner: Mutex<WorkerInner>,
}

impl<S: Store> Worker<S> {
    /// Builds a worker over `store` scoped to `workspace_id`; all other
    /// config fields start at their zero/default-resolving values.
    pub fn new(store: S, workspace_id: WorkspaceId) -> Self {
        Self {
            store,
            worker_id: None,
            workspace_id,
            harness_kinds: Vec::new(),
            workspace_kinds: Vec::new(),
            max_concurrent_attempts: 0,
            interval: Duration::ZERO,
            actor: String::new(),
            inner: Mutex::new(WorkerInner::default()),
        }
    }

    /// The effective worker id (upstream `ID()`): the registered id
    /// once the handshake has run, else the configured `worker_id`,
    /// else `None` — `None` is the Rust shape of upstream's nil UUID
    /// for a worker that never registered. Serve composition hands the
    /// result to the sibling claim loop.
    #[must_use]
    pub fn id(&self) -> Option<WorkerId> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .registered
            .or(self.worker_id)
    }

    /// The heartbeat cadence the supervisor ticks [`heartbeat_once`]
    /// on; resolves `interval <= ZERO` to the locked
    /// [`domain::heartbeat_interval`].
    ///
    /// TICK CONTRACT (upstream `Run`, worker.go:102): the supervisor
    /// runs one [`heartbeat_once`] pass at component start — after a
    /// successful [`register`](Self::register) — BEFORE the ticker
    /// begins, then ticks every `tick_interval`. A naive interval-only
    /// loop delays the first renewal by a full beat (15 s by
    /// default).
    #[must_use]
    pub fn tick_interval(&self) -> Duration {
        if self.interval <= Duration::ZERO {
            domain::heartbeat_interval()
        } else {
            self.interval
        }
    }

    /// Performs the spec-2 registration handshake (upstream `Run`'s
    /// head). A refused handshake —
    /// `WORKER_REGISTRATION_REJECTED` on a protocol-version mismatch
    /// or empty capability intersection — returns the failure: the
    /// worker exits rather than claiming (spec-2 decision 2), and the
    /// kernel reads the component exit as fatal.
    pub async fn register(&self) -> Result<WorkerId, Failure> {
        let id = self.worker_id.unwrap_or_else(WorkerId::new);
        self.store
            .register_worker(domain::Worker {
                id,
                workspace_id: self.workspace_id,
                protocol_version: domain::PROTOCOL_VERSION,
                harness_kinds: self.harness_kinds.clone(),
                workspace_kinds: self.workspace_kinds.clone(),
                max_concurrent_attempts: self.max_concurrent_attempts,
                state: domain::WorkerState::Active,
                registered_at: None,
                last_seen_at: None,
            })
            .await?;
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .registered = Some(id);
        Ok(id)
    }

    /// Renews every live lease the worker holds once (upstream
    /// `heartbeat`). This is the run-once pass: the supervisor calls
    /// it once at component start, then again on every
    /// [`tick_interval`](Self::tick_interval) tick. The renewal set
    /// comes from the store each beat rather than from the claim
    /// loop, so leases claimed between beats join the set at the next
    /// beat and released leases drop out on their own. A worker that
    /// never registered has no leases to renew and the pass is a
    /// no-op.
    pub async fn heartbeat_once(&self) {
        let Some(id) = self.registered_id() else {
            return;
        };
        let Ok(leases) = self.store.worker_leases(id).await else {
            return;
        };
        for lease in leases {
            if self.is_dead(lease.id) {
                continue;
            }
            match self.store.renew_lease(lease.id, id).await {
                Ok(()) => {}
                Err(failure) if failure.code() == domain::REASON_LEASE_RENEWAL_STALE => {
                    self.mark_dead(lease.id);
                }
                Err(_) => {}
            }
        }
    }

    /// The clean-shutdown release (upstream `Shutdown`'s store act —
    /// spec-2 decision 8): never-started leases release and their
    /// nodes requeue, started attempts keep their leases for outcome
    /// persistence or ambiguous expiry. A worker that never
    /// registered has nothing to release. Cancelling the heartbeat
    /// and draining the loop are the supervisor's half.
    pub async fn deregister(&self) -> Result<(), Failure> {
        let Some(id) = self.registered_id() else {
            return Ok(());
        };
        let actor = if self.actor.is_empty() {
            ACTOR_WORKER
        } else {
            self.actor.as_str()
        };
        self.store.deregister_worker(id, actor).await
    }

    fn registered_id(&self) -> Option<WorkerId> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .registered
    }

    fn is_dead(&self, lease_id: NodeLeaseId) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .dead
            .contains(&lease_id)
    }

    fn mark_dead(&self, lease_id: NodeLeaseId) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .dead
            .insert(lease_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::fakes::{RecordingStore, test_lease};
    use crate::testkit::block_on;

    fn test_worker(store: RecordingStore, worker_id: WorkerId) -> Worker<RecordingStore> {
        let mut w = Worker::new(store, WorkspaceId::new());
        w.worker_id = Some(worker_id);
        w.harness_kinds = vec!["claude-code".to_string()];
        w.workspace_kinds = vec!["directory".to_string(), "worktree".to_string()];
        w.max_concurrent_attempts = 4;
        w.interval = Duration::milliseconds(5);
        w
    }

    // -- upstream components_test.go: TestWorkerRegistersRenewsAndDeregisters
    // The ticker loop is the supervisor's half; this pins the per-tick
    // acts: handshake persists the declared capabilities, each beat
    // renews every live lease, shutdown deregisters once under the
    // worker actor.
    #[test]
    fn worker_registers_renews_and_deregisters() {
        let worker_id = WorkerId::new();
        let lease_a = test_lease(worker_id);
        let lease_b = test_lease(worker_id);
        let store = RecordingStore::default();
        store.set_leases(vec![lease_a.clone(), lease_b.clone()]);
        let w = test_worker(store, worker_id);

        block_on(w.register()).unwrap();
        // Two beats renew each live lease twice — upstream waits for
        // >= 2 renewals under a 5ms ticker; here each call IS a beat.
        block_on(w.heartbeat_once());
        block_on(w.heartbeat_once());
        assert!(w.store.renew_count(lease_a.id) >= 2);
        assert!(w.store.renew_count(lease_b.id) >= 2);

        block_on(w.deregister()).unwrap();

        let reg = w.store.registered().expect("worker registered");
        assert_eq!(reg.id, worker_id);
        assert_eq!(reg.protocol_version, domain::PROTOCOL_VERSION);
        assert_eq!(reg.max_concurrent_attempts, 4);
        assert_eq!(reg.harness_kinds, ["claude-code"]);
        assert_eq!(w.store.deregister_calls(), 1);
        assert_eq!(w.store.deregistered().0, Some(worker_id));
        assert_eq!(w.store.deregistered().1, ACTOR_WORKER);
        assert_eq!(w.id(), Some(worker_id));
    }

    // -- upstream components_test.go: TestWorkerStaleRenewalDropsOnlyThatLease

    /// The stale lease rejects once and must never be renewed again —
    /// a second attempt would journal a second
    /// `lease_renewal_rejected`.
    #[test]
    fn worker_stale_renewal_drops_only_that_lease() {
        let worker_id = WorkerId::new();
        let lease_a = test_lease(worker_id);
        let lease_b = test_lease(worker_id);
        let store = RecordingStore::default();
        store.set_leases(vec![lease_a.clone(), lease_b.clone()]);
        store.set_renew_err(
            lease_a.id,
            Failure::denied(
                domain::REASON_LEASE_RENEWAL_STALE,
                "lease expired, released, or superseded",
            ),
        );
        let w = test_worker(store, worker_id);

        block_on(w.register()).unwrap();
        // Three beats: lease_a rejects once and drops out; lease_b
        // renews on every beat.
        for _ in 0..3 {
            block_on(w.heartbeat_once());
        }
        assert!(
            w.store.renew_count(lease_b.id) >= 3,
            "healthy lease renewed every beat"
        );
        assert_eq!(
            w.store.renew_count(lease_a.id),
            1,
            "stale lease must see exactly one renewal attempt"
        );
    }

    // -- upstream components_test.go: TestWorkerRefusedRegistrationExits

    /// A refused handshake propagates the failure and a later
    /// deregister is a no-op — the worker never registered.
    #[test]
    fn worker_refused_registration_exits() {
        let refused = Failure::denied(
            domain::REASON_WORKER_REGISTRATION_REJECTED,
            "handshake refused",
        );
        let store = RecordingStore::default();
        store.set_register_err(refused.clone());
        let w = test_worker(store, WorkerId::new());

        let err = block_on(w.register()).unwrap_err();
        assert_eq!(err, refused);
        block_on(w.deregister()).unwrap();
        assert_eq!(w.store.deregister_calls(), 0);
    }

    // -- upstream components_test.go: TestWorkerGeneratesFreshID ------

    /// `worker_id = None` mints a fresh V7 identity at registration.
    #[test]
    fn worker_generates_fresh_id() {
        let store = RecordingStore::default();
        let mut w = Worker::new(store, WorkspaceId::new());
        w.worker_id = None;
        assert_eq!(w.id(), None);

        block_on(w.register()).unwrap();
        let generated = w.id().expect("registered id");
        assert_eq!(w.store.registered().expect("registered").id, generated);
    }

    // -- upstream components_test.go: TestWorkerUnconfiguredFails -----
    // An unconfigured upstream `Worker{}` is a nil store; in Rust the
    // store is a construction parameter so the shape is
    // unrepresentable (the eventjournal `Publisher::new` precedent).
    // The remaining edge — heartbeat before registration — is the
    // no-op pin below.
    #[test]
    fn worker_heartbeat_before_registration_is_noop() {
        let w = test_worker(RecordingStore::default(), WorkerId::new());
        block_on(w.heartbeat_once());
        assert!(w.store.sequence().is_empty());
    }
}
