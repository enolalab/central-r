//! The domain-facing seams over the durable scheduler substrate
//! (worker registrations, session attempts, node leases) and the
//! workspace-provisioning and harness-launch boundaries dispatch
//! crosses — port of `central/internal/scheduler/port`.
//!
//! No adapter types cross this boundary; the PostgreSQL implementation
//! is `central-adapter-postgres::scheduler`. Every trait is
//! `#[trait_variant::make(Send)]` with `Send + Sync + 'static` so trait
//! objects and `Arc` handles compose with multi-threaded
//! `tokio`/`axum` handlers (rust-application-boundaries.md §2.3); every
//! error is the workspace-wide [`central_foundation::failure::Failure`]
//! — domain refusals arrive as their [`crate::domain::Failure`]
//! converted form, so the spec-2 reason code rides
//! [`Failure::code`](central_foundation::failure::Failure::code)
//! verbatim.
//!
//! OWNING PACKET: P2B01/P2B02/P2B03/P2B04/P2B05. SLICE: 2B.

use std::sync::Arc;

use central_foundation::failure::Failure;
use central_foundation::identity::{
    NodeLeaseId, RunId, SessionAttemptId, WorkerId, WorkflowNodeId,
};
use time::OffsetDateTime;

use crate::domain::{ClaimedAttempt, ExpiryResult, Lease, SessionAttempt, Worker};

// ---------------------------------------------------------------------------
// Store — the durable scheduler substrate
// ---------------------------------------------------------------------------

/// The domain-facing seam to the durable scheduler substrate (upstream
/// `port.Store`). Every mutating method commits its state change and
/// its canonical journal event (the eventjournal adapter's tx-scoped
/// append) in ONE transaction — claim, renewal rejection, expiry,
/// ladder transition, and deregistration all obey spec-2's
/// single-commit rule. Plain heartbeat row updates are never journaled;
/// only rejections and state transitions are.
#[trait_variant::make(Send)]
pub trait Store: Send + Sync + 'static {
    /// Performs the spec-2 registration handshake for one worker
    /// process. [`crate::domain::registration_failure`] is the
    /// accept/refuse rule; a refused registration is journaled with
    /// `WORKER_REGISTRATION_REJECTED` and returned as a `DENIED`
    /// failure — the worker exits rather than claiming. An accepted
    /// registration persists the declared capabilities under a fresh
    /// worker id.
    async fn register_worker(&self, worker: Worker) -> Result<WorkerId, Failure>;

    /// Performs clean-shutdown release (spec-2 decision 8): the worker
    /// row closes `deregistered` with a `worker_deregistered` event,
    /// every never-started lease it holds releases (`released_at =
    /// now`, `WORKER_SHUTDOWN_LEASE_RELEASED`) and its node returns to
    /// `ready` — all in one transaction. A started attempt may not be
    /// cleanly released: the worker persists its outcome first or
    /// leaves the lease to expire into the ambiguous path.
    async fn deregister_worker(&self, worker_id: WorkerId, actor: &str) -> Result<(), Failure>;

    /// Atomically claims up to `limit` ready nodes for the worker. Per
    /// node, one transaction moves `ready → dispatched`, inserts the
    /// `session_attempt` row (next `attempt_seq` under the node lock)
    /// and the lease (`expires_at = now + lease_ttl()`), and journals
    /// `node_dispatched`. Candidates honor `not_before`, must
    /// capability-match the worker's declared `(harness,
    /// workspace_kind)` lists, order FIFO by `COALESCE(ready_at,
    /// created_at)` then `node_key`, and the worker's
    /// `max_concurrent_attempts` bounds its live leases. The same
    /// transaction runs the spec-8 admission check
    /// ([`crate::admission::check_dispatch_admission`] over the
    /// installed `ConcurrencyProfile`): a refused candidate commits an
    /// `admission_deferred` event carrying
    /// `CAPACITY_ADMISSION_DEFERRED` and stays `ready` with `ready_at`
    /// untouched — deferral keeps FIFO position and is never a claim
    /// error. Lock order inside the transaction is run-row THEN
    /// node-row — the run-row `FOR UPDATE` ordering the workflow store
    /// already relies on.
    async fn claim_ready(
        &self,
        worker_id: WorkerId,
        limit: u32,
    ) -> Result<Vec<ClaimedAttempt>, Failure>;

    /// Conditionally extends a live lease's `last_heartbeat_at` and
    /// `expires_at` (= now + `lease_ttl()`) under a `(lease_id,
    /// worker_id)` match on a live lease. A renewal matching nothing —
    /// expired, released, or superseded — is rejected with a `DENIED`
    /// failure carrying `LEASE_RENEWAL_STALE` and journals
    /// `lease_renewal_rejected`; the worker must abort that attempt
    /// locally.
    async fn renew_lease(&self, lease_id: NodeLeaseId, worker_id: WorkerId) -> Result<(), Failure>;

    /// Lists the worker's live leases (`released_at IS NULL`) — the
    /// heartbeat set the worker renews each interval. A lease that
    /// stays listed but is already fencing-dead (expired or superseded
    /// server-side) surfaces through [`renew_lease`](Self::renew_lease)'s
    /// `LEASE_RENEWAL_STALE` rejection; the read itself takes no lock
    /// and journals nothing.
    async fn worker_leases(&self, worker_id: WorkerId) -> Result<Vec<Lease>, Failure>;

    /// Asserts the lease-as-fence durable-write guard (spec-2 decision
    /// 7): the presented `(node_id, attempt_id, lease_id)` must match
    /// the node's live, unexpired lease, or the call fails carrying
    /// `LEASE_FENCE_STALE`. Every durable write on a node — artifact
    /// finalization, terminal attempt state, node transition — passes
    /// through this check.
    async fn fence(
        &self,
        node_id: WorkflowNodeId,
        attempt_id: SessionAttemptId,
        lease_id: NodeLeaseId,
    ) -> Result<(), Failure>;

    /// Closes every live lease whose `expires_at` has passed at `now`,
    /// splitting each per [`crate::domain::expiry_decision`]: a
    /// never-started attempt closes `failed`
    /// (`LEASE_EXPIRED_NOT_STARTED`) with its node back to `ready`; a
    /// started attempt parks ambiguous
    /// (`ATTEMPT_AMBIGUOUS_LEASE_EXPIRED`, or
    /// `ATTEMPT_AMBIGUOUS_WORKER_LOST` when expiry rides worker loss)
    /// with its node `attempt_ambiguous`. Each expiry commits attempt +
    /// node + lease release + events (the attempt-scope event plus
    /// `lease_expired`) in one transaction.
    async fn expire_leases(&self, now: OffsetDateTime) -> Result<Vec<ExpiryResult>, Failure>;

    /// The startup reconcile-before-reinvoke pass (spec-2 decision 9):
    /// expired leases follow the `expire_leases` path, and live leases
    /// whose `worker_id` has no current registration are treated as
    /// lost. It runs to completion before any post-restart dispatch.
    async fn reconcile(&self, actor: &str) -> Result<(), Failure>;

    /// Applies the missed-beat ladder at `now` (spec-2 decision 5):
    /// `MISSED_BEATS_SUSPECT` missed beats journal `worker_suspect`
    /// once (observable only), `MISSED_BEATS_LOST` mark the worker
    /// lost — worker state + `worker_lost` event carrying
    /// `WORKER_LOST_GRACE_EXPIRED` + expiry of every lease it holds,
    /// all in one transaction.
    async fn sweep_suspects(&self, now: OffsetDateTime) -> Result<(), Failure>;

    // -----------------------------------------------------------------
    // Dispatch outcome persistence (P2B02)
    // -----------------------------------------------------------------
    // The four dispatch-phase writes below each open ONE transaction
    // that (a) fences: the lease the claim issued for `attempt_id` must
    // still be live — `node_leases` row with `released_at IS NULL` and
    // `expires_at` in the future; at most one lease per attempt ever
    // exists, so `attempt_id` identifies it — rejecting with
    // `LEASE_FENCE_STALE` otherwise, and (b) commits attempt row + node
    // row + journaled event atomically. The dispatcher holds no
    // transaction across calls: provisioning, the out-of-transaction
    // launcher invoke, and the outcome persist are separate commits
    // per spec-1's dispatch shape.

    /// Moves the claimed attempt to `provisioning` and records
    /// `workspace_path`. It journals no event — the catalog has no
    /// provisioning-scope kind; `node_dispatched` already covered the
    /// claim.
    async fn mark_provisioning(
        &self,
        attempt_id: SessionAttemptId,
        workspace_path: &str,
    ) -> Result<(), Failure>;

    /// Moves the provisioning attempt to `started` with `started_at`
    /// and `harness_session_id` set, moves the node to `running`, and
    /// journals `attempt_started`. The lease stays live — the worker
    /// heartbeats it for the session's duration.
    async fn mark_started(
        &self,
        attempt_id: SessionAttemptId,
        harness_session_id: &str,
    ) -> Result<(), Failure>;

    /// The definite dispatch-failure path: the attempt's `failed`
    /// outcome commits through the Slice-2D durable outcome path
    /// (`attempt_outcomes` ledger row, attempt close, lease release —
    /// one transaction). The retry taxonomy classifies the reason
    /// (`WORKSPACE_PROVISION_FAILED` / `LAUNCHER_REFUSED` are
    /// dispatch_infra, retryable): inside budget the node returns to
    /// `ready` with `not_before` = the journaled `retry_at` backoff; a
    /// terminal class or exhausted budget lands `failed_terminal`. A
    /// replay under the recorded key dedupes per spec-5.
    async fn fail_dispatch(
        &self,
        attempt_id: SessionAttemptId,
        reason_code: &str,
    ) -> Result<(), Failure>;

    /// The unknown-outcome path: the attempt parks `ambiguous` with
    /// `dispatch_reason_code`, the lease releases (the dispatcher
    /// hands the parked attempt to the operator; a rerun is a NEW
    /// `attempt_seq` under a fresh lease), the node moves to
    /// `attempt_ambiguous`, and `attempt_ambiguous` journals the code.
    /// The attempt is never auto-relaunched (locked input 1).
    async fn ambiguate_dispatch(
        &self,
        attempt_id: SessionAttemptId,
        reason_code: &str,
    ) -> Result<(), Failure>;

    // -----------------------------------------------------------------
    // Mid-session ceilings (P2B06)
    // -----------------------------------------------------------------

    /// The detection input of spec-8's cancel-then-close flow: the
    /// `started` attempts whose session age at `now` crossed the
    /// installed profile's wall-clock ceiling. The caller delivers the
    /// harness cancel control first; the outcome then commits through
    /// [`record_ceiling_breach`](Self::record_ceiling_breach)
    /// (confirmed cancel) or
    /// [`ambiguate_dispatch`](Self::ambiguate_dispatch) (unknowable
    /// outcome). Read-only — no lock, no journal.
    async fn list_wall_clock_breaches(
        &self,
        now: OffsetDateTime,
    ) -> Result<Vec<SessionAttempt>, Failure>;

    /// Commits a confirmed mid-session ceiling breach: the attempt
    /// closes `failed` through the Slice-2D durable outcome path under
    /// the spec-8 `SESSION_WALL_CLOCK_REACHED` /
    /// `SESSION_COST_CEILING_REACHED` /
    /// `WORKSPACE_DISK_BUDGET_EXCEEDED` code. `SESSION_*` codes
    /// classify `session_timeout` (retryable — the node requeues under
    /// backoff while budget remains);
    /// `WORKSPACE_DISK_BUDGET_EXCEEDED` is unclassified and fails
    /// closed to `failed_terminal`. A code outside the spec-8 set
    /// rejects with `INVALID_BREACH_CODE`; an unconfirmed cancel takes
    /// `ambiguate_dispatch`, never this path.
    async fn record_ceiling_breach(
        &self,
        attempt_id: SessionAttemptId,
        reason_code: &str,
    ) -> Result<(), Failure>;
}

/// `Arc` of any [`Store`] is itself a store — the kernel wires one
/// `Arc<PgSchedulerStore>` into the worker, claim loop, sweeper, and
/// reconciler simultaneously (upstream shares the same `*Store`).
impl<S: Store + ?Sized> Store for Arc<S> {
    async fn register_worker(&self, worker: Worker) -> Result<WorkerId, Failure> {
        (**self).register_worker(worker).await
    }

    async fn deregister_worker(&self, worker_id: WorkerId, actor: &str) -> Result<(), Failure> {
        (**self).deregister_worker(worker_id, actor).await
    }

    async fn claim_ready(
        &self,
        worker_id: WorkerId,
        limit: u32,
    ) -> Result<Vec<ClaimedAttempt>, Failure> {
        (**self).claim_ready(worker_id, limit).await
    }

    async fn renew_lease(&self, lease_id: NodeLeaseId, worker_id: WorkerId) -> Result<(), Failure> {
        (**self).renew_lease(lease_id, worker_id).await
    }

    async fn worker_leases(&self, worker_id: WorkerId) -> Result<Vec<Lease>, Failure> {
        (**self).worker_leases(worker_id).await
    }

    async fn fence(
        &self,
        node_id: WorkflowNodeId,
        attempt_id: SessionAttemptId,
        lease_id: NodeLeaseId,
    ) -> Result<(), Failure> {
        (**self).fence(node_id, attempt_id, lease_id).await
    }

    async fn expire_leases(&self, now: OffsetDateTime) -> Result<Vec<ExpiryResult>, Failure> {
        (**self).expire_leases(now).await
    }

    async fn reconcile(&self, actor: &str) -> Result<(), Failure> {
        (**self).reconcile(actor).await
    }

    async fn sweep_suspects(&self, now: OffsetDateTime) -> Result<(), Failure> {
        (**self).sweep_suspects(now).await
    }

    async fn mark_provisioning(
        &self,
        attempt_id: SessionAttemptId,
        workspace_path: &str,
    ) -> Result<(), Failure> {
        (**self).mark_provisioning(attempt_id, workspace_path).await
    }

    async fn mark_started(
        &self,
        attempt_id: SessionAttemptId,
        harness_session_id: &str,
    ) -> Result<(), Failure> {
        (**self).mark_started(attempt_id, harness_session_id).await
    }

    async fn fail_dispatch(
        &self,
        attempt_id: SessionAttemptId,
        reason_code: &str,
    ) -> Result<(), Failure> {
        (**self).fail_dispatch(attempt_id, reason_code).await
    }

    async fn ambiguate_dispatch(
        &self,
        attempt_id: SessionAttemptId,
        reason_code: &str,
    ) -> Result<(), Failure> {
        (**self).ambiguate_dispatch(attempt_id, reason_code).await
    }

    async fn list_wall_clock_breaches(
        &self,
        now: OffsetDateTime,
    ) -> Result<Vec<SessionAttempt>, Failure> {
        (**self).list_wall_clock_breaches(now).await
    }

    async fn record_ceiling_breach(
        &self,
        attempt_id: SessionAttemptId,
        reason_code: &str,
    ) -> Result<(), Failure> {
        (**self)
            .record_ceiling_breach(attempt_id, reason_code)
            .await
    }
}

// ---------------------------------------------------------------------------
// Provisioner — dispatch-time workspace isolation
// ---------------------------------------------------------------------------

/// Owns dispatch-time workspace isolation (spec-2 locked input 3;
/// upstream `port.Provisioner`): `'worktree'` work gets a dedicated git
/// worktree at `base_ref`, `'directory'` work a fresh private directory
/// under the instance scratch root. Provisioning is keyed `(run_id,
/// node_id, attempt_id)` and idempotent — a re-prepare dedupes on the
/// recorded `workspace_path`. `kind` carries the v33 workspace-kind
/// vocabulary.
#[trait_variant::make(Send)]
pub trait Provisioner: Send + Sync + 'static {
    /// Prepares the attempt's isolated workspace and returns its path.
    /// A `FailureKind::Cancelled` failure reports an interrupted
    /// prepare: the dispatcher returns without a durable write and
    /// leaves the attempt to the lease-expiry ladder.
    async fn provision(
        &self,
        run_id: RunId,
        node_id: WorkflowNodeId,
        attempt_id: SessionAttemptId,
        kind: &str,
        base_ref: &str,
    ) -> Result<String, Failure>;

    /// Releases a provisioned workspace (upstream `Free` — a local
    /// cleanup act with no store interaction, hence synchronous).
    fn free(&self, path: &str) -> Result<(), Failure>;
}

/// `Arc` of any [`Provisioner`] is itself a provisioner.
impl<P: Provisioner + ?Sized> Provisioner for Arc<P> {
    async fn provision(
        &self,
        run_id: RunId,
        node_id: WorkflowNodeId,
        attempt_id: SessionAttemptId,
        kind: &str,
        base_ref: &str,
    ) -> Result<String, Failure> {
        (**self)
            .provision(run_id, node_id, attempt_id, kind, base_ref)
            .await
    }

    fn free(&self, path: &str) -> Result<(), Failure> {
        (**self).free(path)
    }
}

// ---------------------------------------------------------------------------
// NodeLauncher — the harness-invoke boundary
// ---------------------------------------------------------------------------

/// The whole invoke payload the dispatcher hands the launcher for one
/// claimed attempt (upstream `port.LaunchSpec`): the attempt bundle
/// itself (attempt row + fencing lease + node harness), the provisioned
/// workspace path that becomes the harness's workdir, and the complete
/// set of Central-injected env entries — `CENTRAL_ATTEMPT_SCOPE` today,
/// joined by the attempt-scoped `central artifact read` credential once
/// the 2A06 injection wiring lands. The closed launch-argv grammar
/// (ADR 0036) means nothing outside this spec reaches the child.
#[derive(Debug, Clone, PartialEq)]
pub struct LaunchSpec {
    /// The claimed attempt bundle.
    pub attempt: ClaimedAttempt,
    /// The provisioned workspace path — the harness's workdir.
    pub workspace_path: String,
    /// The complete Central-injected env entries.
    pub env: Vec<String>,
}

/// The invoke verdict (upstream's `(sessionID, confirmed, err)`
/// triple): a confirmed live session, a confirmed refusal — nothing
/// ran — or an outcome that is unknowable.
///
/// - [`Started`](Self::Started) means the harness session is live and
///   the value names it. A confirmed success returning an empty id is a
///   contract breach the dispatcher treats as unknown outcome.
/// - [`Refused`](Self::Refused) is a definite refusal — journaled
///   `attempt_failed` with `LAUNCHER_REFUSED`.
/// - [`Unknown`](Self::Unknown) means the launch may or may not have
///   happened (the process could be live while the reply was lost);
///   the dispatcher must park the attempt `attempt_ambiguous` for an
///   operator decision, never auto-relaunch (locked input 1).
#[derive(Debug, Clone, PartialEq)]
pub enum LaunchVerdict {
    /// Confirmed: the session is live under the returned id.
    Started(String),
    /// Confirmed refusal — nothing ran; the failure is diagnostic.
    Refused(Failure),
    /// Unconfirmed: the outcome is unknowable.
    Unknown,
}

/// Invokes the existing harness launch machinery for one claimed
/// attempt — the R4 plan's `NodeLauncher` port (upstream
/// `port.Launcher`), so named because kernel wiring (R4 Task 12)
/// binds it to the harness session layer. The dispatcher calls it
/// OUTSIDE any open transaction; the outcome is then persisted under
/// the lease fence.
#[trait_variant::make(Send)]
pub trait NodeLauncher: Send + Sync + 'static {
    /// Invokes the launch and reports the verdict. The verdict is
    /// infallible by construction: an invoke failure is either a
    /// [`LaunchVerdict::Refused`] (confirmed nothing ran) or
    /// [`LaunchVerdict::Unknown`] (outcome unknowable) — the certainty,
    /// not the error, is what the dispatcher persists.
    async fn launch(&self, spec: LaunchSpec) -> LaunchVerdict;
}

/// `Arc` of any [`NodeLauncher`] is itself a launcher.
impl<L: NodeLauncher + ?Sized> NodeLauncher for Arc<L> {
    async fn launch(&self, spec: LaunchSpec) -> LaunchVerdict {
        (**self).launch(spec).await
    }
}

// ---------------------------------------------------------------------------
// Clock — deterministic evaluation instants
// ---------------------------------------------------------------------------

/// Supplies application-owned timestamps for lease evaluation
/// (upstream `port.Clock`). PostgreSQL remains authoritative for
/// timestamps committed inside the store's transactions; the clock
/// feeds sweep/reconcile evaluation only.
pub trait Clock: Send + Sync + 'static {
    /// The current evaluation instant.
    fn now(&self) -> OffsetDateTime;
}

/// The default real [`Clock`]: UTC wall time (upstream
/// `SystemClock`).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// Any `Fn() -> OffsetDateTime` is a [`Clock`] — the closure form of
/// upstream's `Now func() time.Time` field.
impl<F> Clock for F
where
    F: Fn() -> OffsetDateTime + Send + Sync + 'static,
{
    fn now(&self) -> OffsetDateTime {
        self()
    }
}
