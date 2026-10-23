//! `PgSchedulerStore` — the b35 worker/attempt/lease substrate and the
//! dispatch-phase fenced writes (port of upstream
//! `internal/adapter/postgres/scheduler/store.go`).
//!
//! One struct carries the shared config the outcome half
//! (`outcome.rs`) also reads — upstream has a single `Store` type; the
//! file split is organizational only. Lock order everywhere is the
//! run-row `FOR UPDATE` serialization point first, then the node row,
//! then the attempt row, then the lease re-check — the order claim and
//! the workflow store already take. Every mutating path commits its
//! state change plus its `run_events`/`event_outbox` rows in ONE
//! transaction through [`crate::eventjournal::append_tx`].
//!
//! Domain failures surface as their [`Failure`] converted form: the
//! class maps to the `FailureKind` and the spec-2 reason code rides
//! `Failure::code` verbatim; diagnostic detail stays inside closed
//! vocabulary tokens (states, ids are fine — upstream's `WithCause`).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use central_eventjournal::domain::{EventKind, RunEvent};
use central_foundation::failure::Failure;
use central_foundation::identity::{
    NodeLeaseId, RunEventId, RunId, SessionAttemptId, WorkerId, WorkflowNodeId, WorkspaceId,
};
use central_retry::domain::{OutcomeKind, RetryPolicy};
use central_retry::port::{Clock, CompensationExecutor, Killer, Outcome, Rand};
use central_scheduler::admission::{
    self, AdmissionSnapshot, ConcurrencyProfile, REASON_INVALID_BREACH_CODE,
};
use central_scheduler::domain::{
    self as sched, AttemptState, ClaimedAttempt, ExpiryResult, Lease, SessionAttempt, Worker,
    WorkerState,
};
use central_workflow::domain::NodeStatus;
use sqlx::{PgPool, Postgres, Transaction};
use time::OffsetDateTime;

use crate::error::SqlxContext;
use crate::eventjournal::append_tx;
use crate::store_support::{PG_DATA_CORRUPT, begin_tx, uuid_of};

/// `actor` for scheduler-authored journal rows (claim, sweep, expiry,
/// dispatch writes) — upstream `actorScheduler`.
pub(crate) const ACTOR_SCHEDULER: &str = "scheduler";
/// Fallback actor for `reconcile` when the caller passes "" — upstream
/// `actorReconciler`.
pub(crate) const ACTOR_RECONCILER: &str = "reconciler";
/// PostgreSQL `55P03` — `FOR UPDATE NOWAIT` refusal or `lock_timeout`
/// expiry: a claim candidate lost to a concurrent claimer is skipped,
/// never an error.
pub(crate) const PG_LOCK_NOT_AVAILABLE: &str = "55P03";

/// Whether `err` is PostgreSQL `55P03` (upstream `isLockNotAvailable`).
pub(crate) fn is_lock_not_available(err: &sqlx::Error) -> bool {
    matches!(err, sqlx::Error::Database(db) if db.code().as_deref() == Some(PG_LOCK_NOT_AVAILABLE))
}

/// A boxed `Send` future — the object-safe call shape the injected
/// seams need (`trait_variant` desugars `async fn` to RPITIT, which is
/// not `dyn`-compatible, so the store injects boxed-future shims).
pub type BoxedCall<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The object-safe injection face of [`Killer`] — every `Killer`
/// implementation coerces here, so callers wire `Arc<K>` and the store
/// holds `Arc<dyn DynKiller>` (upstream's `Killer` field).
pub trait DynKiller: Send + Sync + 'static {
    /// Kills the attempt; the boolean is kill confirmation, not
    /// success — `Ok(false)` leaves the outcome unknowable.
    fn kill<'a>(&'a self, attempt_id: SessionAttemptId) -> BoxedCall<'a, Result<bool, Failure>>;
}

impl<T: Killer> DynKiller for T {
    fn kill<'a>(&'a self, attempt_id: SessionAttemptId) -> BoxedCall<'a, Result<bool, Failure>> {
        Box::pin(Killer::kill(self, attempt_id))
    }
}

/// The object-safe injection face of [`CompensationExecutor`] —
/// Central-managed `on_terminal_failure` hooks only.
pub trait DynCompensationExecutor: Send + Sync + 'static {
    /// Removes the node's worktree/private dir.
    fn cleanup_workspace<'a>(
        &'a self,
        node_id: WorkflowNodeId,
    ) -> BoxedCall<'a, Result<(), Failure>>;

    /// Marks the node's declared artifacts kept for inspection.
    fn retain_artifacts<'a>(
        &'a self,
        node_id: WorkflowNodeId,
    ) -> BoxedCall<'a, Result<(), Failure>>;
}

impl<T: CompensationExecutor> DynCompensationExecutor for T {
    fn cleanup_workspace<'a>(
        &'a self,
        node_id: WorkflowNodeId,
    ) -> BoxedCall<'a, Result<(), Failure>> {
        Box::pin(CompensationExecutor::cleanup_workspace(self, node_id))
    }

    fn retain_artifacts<'a>(
        &'a self,
        node_id: WorkflowNodeId,
    ) -> BoxedCall<'a, Result<(), Failure>> {
        Box::pin(CompensationExecutor::retain_artifacts(self, node_id))
    }
}

/// The domain refusal → boundary failure conversion: the scheduler
/// `FailureClass` maps to the `FailureKind` and the closed reason code
/// carries verbatim; `detail` is closed-vocabulary diagnostic text.
pub(crate) fn domain_failure(
    class: sched::FailureClass,
    reason: &'static str,
    detail: impl Into<String>,
) -> Failure {
    match class {
        sched::FailureClass::Invalid => Failure::invalid(reason, detail),
        sched::FailureClass::Conflict => Failure::conflict(reason, detail),
        sched::FailureClass::Denied => Failure::denied(reason, detail),
    }
}

/// `worker_registrations` row the claim path needs (upstream
/// `workerRow`).
struct WorkerRow {
    workspace_id: WorkspaceId,
    harness_kinds: Vec<String>,
    workspace_kinds: Vec<String>,
    max_concurrent_attempts: i32,
    state: WorkerState,
}

/// A ready-node candidate from the phase-1 lock-free scan (upstream
/// `claimCandidate` — the locked row re-read in the claim transaction
/// supplies the detail fields, so only the identity columns travel).
struct ClaimCandidate {
    node_id: WorkflowNodeId,
    run_id: RunId,
    workspace_id: WorkspaceId,
}

/// The dispatch-write subject: the attempt row joined to its live
/// fencing lease (upstream `fencedAttempt`). The node-row lock in
/// [`PgSchedulerStore::fenced_begin_tx`] fills the `node_*` fields so
/// outcome writes evaluate budgets/deadlines/hooks under one read.
pub(crate) struct FencedAttempt {
    pub(crate) attempt_id: SessionAttemptId,
    pub(crate) node_id: WorkflowNodeId,
    pub(crate) run_id: RunId,
    pub(crate) workspace_id: WorkspaceId,
    pub(crate) state: AttemptState,
    pub(crate) attempt_seq: i32,
    pub(crate) lease_id: NodeLeaseId,
    pub(crate) worker_id: WorkerId,
    pub(crate) node_spec: serde_json::Value,
    pub(crate) node_timeout_sec: Option<i64>,
    pub(crate) node_not_before: Option<OffsetDateTime>,
}

/// The run binding a worker-scope event requires (upstream
/// `workerRunContext`): the run/node/attempt of the worker's most
/// recently issued lease.
struct WorkerRunContext {
    run_id: RunId,
    workspace_id: WorkspaceId,
    node_id: WorkflowNodeId,
}

/// The PostgreSQL scheduler store — the single implementer of
/// `central_scheduler::port::Store`, `central_scheduler::query::SchedulerRead`,
/// `central_retry::port::Store`, and `central_retry::query::AttemptHistoryRead`.
/// Construct over a `central_runtime`-authorized pool.
#[derive(Clone)]
pub struct PgSchedulerStore {
    /// Shared pool the outcome file's paths also transact on.
    pub(crate) pool: PgPool,
    /// This instance's launchable harness set the registration
    /// handshake intersects against. Empty is fail-closed: every
    /// registration refuses (upstream `LaunchableHarnesses`).
    pub launchable_harnesses: Vec<String>,
    /// The installed spec-8 cap envelope the claim transaction
    /// enforces. `None` resolves [`ConcurrencyProfile::default`] —
    /// claim never runs unadmitted (upstream `AdmissionProfile`; the
    /// zero-value fallback collapses into `None` here).
    pub admission_profile: Option<ConcurrencyProfile>,
    /// The injected session-kill boundary the timeout sweep drives.
    /// `None` is fail-closed: every kill evaluates unconfirmed
    /// (upstream `Killer`).
    pub killer: Option<Arc<dyn DynKiller>>,
    /// The injected executor for managed `on_terminal_failure` hooks;
    /// `None` still journals `executor_unavailable` (upstream
    /// `Compensation`).
    pub compensation: Option<Arc<dyn DynCompensationExecutor>>,
    /// The installed retry/backoff envelope. The [`RetryPolicy::zero`]
    /// value resolves [`RetryPolicy::default`] at use — per-node spec
    /// fields may tighten, never loosen (upstream `RetryPolicy`).
    pub retry_policy: RetryPolicy,
    /// The pre-commit evaluation clock; `None` reads UTC wall time
    /// (upstream `Clock`/`SystemClock`).
    pub clock: Option<Arc<dyn Clock>>,
    /// The full-jitter draw `compute_delay` applies; `None` draws a
    /// uniform `[0,1)` sample (upstream `Jitter`/`math/rand`).
    pub jitter: Option<Arc<dyn Rand>>,
}

impl PgSchedulerStore {
    /// `NewStore` — `launchable_harnesses` names the harnesses this
    /// instance can launch (empty refuses every registration).
    #[must_use]
    pub fn new(pool: PgPool, launchable_harnesses: Vec<String>) -> Self {
        Self {
            pool,
            launchable_harnesses,
            admission_profile: None,
            killer: None,
            compensation: None,
            retry_policy: RetryPolicy::zero(),
            clock: None,
            jitter: None,
        }
    }

    /// The installed cap envelope; `None` defaults to the compiled
    /// profile (upstream `admissionProfile()` zero-value fallback).
    pub(crate) fn admission_profile(&self) -> ConcurrencyProfile {
        self.admission_profile.unwrap_or_default()
    }

    /// The evaluation instant — the injected clock or UTC now
    /// (upstream `evalNow`).
    pub(crate) fn eval_now(&self) -> OffsetDateTime {
        self.clock
            .as_deref()
            .map_or_else(OffsetDateTime::now_utc, Clock::now)
    }

    /// One `[0,1)` jitter sample for `compute_delay` — the injected
    /// draw or a uniform random (upstream `jitterFloat()`).
    pub(crate) fn jitter_draw(&self) -> f64 {
        self.jitter.as_deref().map_or_else(rand::random, Rand::draw)
    }

    /// The policy one outcome evaluates: the installed envelope (or
    /// the default when [`RetryPolicy::zero`]), then the node spec's
    /// declared caps applied verbatim — emit validation already rejects
    /// non-positive or ceiling-exceeding values, so persisted values
    /// may only ever tighten (upstream `retryPolicyFor`).
    pub(crate) fn retry_policy_for(&self, spec: &serde_json::Value) -> RetryPolicy {
        let mut policy = self.retry_policy.clone();
        if policy.max_attempts_total == 0
            && policy.per_class_limits.is_empty()
            && policy.base_delay <= time::Duration::ZERO
        {
            policy = RetryPolicy::default();
        }
        // The tolerant projection mirrors upstream's `json.Unmarshal`
        // into the node struct: fields absent from `spec` evaluate to
        // zero values rather than failing the whole outcome commit.
        let node: NodeSpecCaps = serde_json::from_value(spec.clone()).unwrap_or_default();
        if let Some(total) = node.max_attempts_total
            && total > 0
            && let Ok(total) = u32::try_from(total)
        {
            policy.max_attempts_total = total;
        }
        if !node.max_attempts.is_empty() {
            let mut merged = policy.per_class_limits;
            for (name, value) in &node.max_attempts {
                if *value > 0
                    && let (Some(class), Ok(limit)) = (
                        central_retry::domain::FailureClass::parse(name),
                        u32::try_from(*value),
                    )
                {
                    merged.insert(class, limit);
                }
            }
            policy.per_class_limits = merged;
        }
        policy
    }

    /// A `set_config`-bounded transaction — the shared
    /// [`begin_tx`] with the upstream 2s/5s/10s timeouts.
    pub(crate) async fn begin(&self) -> Result<Transaction<'static, Postgres>, Failure> {
        begin_tx(&self.pool).await
    }

    /// The non-transactional append (`upstream s.journal.Append`) — its
    /// own bounded transaction, used for rows that commit alone (the
    /// renewal-rejection and compensation-result journals).
    pub(crate) async fn append_solo(&self, event: &RunEvent) -> Result<i64, Failure> {
        let mut tx = self.begin().await?;
        let seq = append_tx(&mut tx, event).await?;
        tx.commit().await.ctx("scheduler: commit solo journal")?;
        Ok(seq)
    }

    /// Journals one attempt-free node/run-scope event inside `tx`
    /// (upstream `appendWorkerEventTx`'s shape, shared with the
    /// outcome helpers).
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn append_node_event_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        workspace_id: WorkspaceId,
        run_id: RunId,
        node_id: WorkflowNodeId,
        kind: &str,
        actor: &str,
        reason_code: Option<&str>,
        payload: serde_json::Value,
    ) -> Result<(), Failure> {
        append_tx(
            tx,
            &RunEvent {
                id: RunEventId::new(),
                workspace_id,
                run_id,
                seq: 0,
                node_id: Some(node_id),
                attempt_id: None,
                kind: kind.to_owned(),
                actor: actor.to_owned(),
                reason_code: reason_code.map(str::to_owned),
                payload,
                recorded_at: OffsetDateTime::UNIX_EPOCH,
            },
        )
        .await?;
        Ok(())
    }

    /// The same shape with `attempt_id` on the envelope (upstream
    /// `appendAttemptEventTx`).
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn append_attempt_event_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        workspace_id: WorkspaceId,
        run_id: RunId,
        node_id: WorkflowNodeId,
        attempt_id: SessionAttemptId,
        kind: &str,
        actor: &str,
        reason_code: Option<&str>,
        payload: serde_json::Value,
    ) -> Result<(), Failure> {
        append_tx(
            tx,
            &RunEvent {
                id: RunEventId::new(),
                workspace_id,
                run_id,
                seq: 0,
                node_id: Some(node_id),
                attempt_id: Some(attempt_id),
                kind: kind.to_owned(),
                actor: actor.to_owned(),
                reason_code: reason_code.map(str::to_owned),
                payload,
                recorded_at: OffsetDateTime::UNIX_EPOCH,
            },
        )
        .await?;
        Ok(())
    }

    /// Resolves the run a worker-scope event binds to: the run of the
    /// worker's most recently issued lease (upstream
    /// `resolveWorkerRunContext`). `None` when the worker never held a
    /// lease — its worker-scope event is skipped.
    async fn resolve_worker_run_context(
        tx: &mut Transaction<'_, Postgres>,
        worker_id: WorkerId,
    ) -> Result<Option<WorkerRunContext>, Failure> {
        let row = sqlx::query!(
            "SELECT a.run_id, a.workspace_id, l.node_id \
             FROM central.node_leases l \
             JOIN central.session_attempts a ON a.id = l.attempt_id \
             WHERE l.worker_id = $1 \
             ORDER BY l.issued_at DESC LIMIT 1",
            uuid_of(worker_id.as_bytes()),
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("scheduler: resolve worker run context")?;
        Ok(row.map(|r| WorkerRunContext {
            run_id: RunId::from_trusted_db_bytes(*r.run_id.as_bytes()),
            workspace_id: WorkspaceId::from_trusted_db_bytes(*r.workspace_id.as_bytes()),
            node_id: WorkflowNodeId::from_trusted_db_bytes(*r.node_id.as_bytes()),
        }))
    }

    /// Journals one worker-scope event inside `tx`, bound to the
    /// resolved run context; `worker_id` travels in the payload
    /// (upstream `appendWorkerEventTx`).
    async fn append_worker_event_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        wctx: &WorkerRunContext,
        kind: &str,
        actor: &str,
        reason_code: Option<&str>,
        payload: serde_json::Value,
    ) -> Result<(), Failure> {
        self.append_node_event_tx(
            tx,
            wctx.workspace_id,
            wctx.run_id,
            wctx.node_id,
            kind,
            actor,
            reason_code,
            payload,
        )
        .await
    }

    /// Expires one live lease inside the caller's transaction
    /// (upstream `expireLeaseTx`). Lock order: run row, node row,
    /// attempt row, then the conditional release. `None` means the
    /// lease was already closed by a concurrent closer.
    pub(crate) async fn expire_lease_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        lease_id: NodeLeaseId,
        via_worker_loss: bool,
        actor: &str,
    ) -> Result<Option<ExpiryResult>, Failure> {
        let row = sqlx::query!(
            "SELECT l.node_id, l.attempt_id, l.worker_id, a.run_id, a.workspace_id \
             FROM central.node_leases l \
             JOIN central.session_attempts a ON a.id = l.attempt_id \
             WHERE l.id = $1 AND l.released_at IS NULL",
            uuid_of(lease_id.as_bytes()),
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("scheduler expire: read lease")?;
        let Some(row) = row else {
            return Ok(None);
        };
        let node_id = WorkflowNodeId::from_trusted_db_bytes(*row.node_id.as_bytes());
        let attempt_id = SessionAttemptId::from_trusted_db_bytes(*row.attempt_id.as_bytes());
        let worker_id = WorkerId::from_trusted_db_bytes(*row.worker_id.as_bytes());
        let run_id = RunId::from_trusted_db_bytes(*row.run_id.as_bytes());
        let workspace_id = WorkspaceId::from_trusted_db_bytes(*row.workspace_id.as_bytes());

        let locked = sqlx::query_scalar!(
            "SELECT id FROM central.runs WHERE id = $1 FOR UPDATE",
            uuid_of(run_id.as_bytes()),
        )
        .fetch_one(&mut **tx)
        .await
        .ctx("scheduler expire: lock run row")?;
        let _ = locked;
        let node_state = sqlx::query_scalar!(
            "SELECT state FROM central.workflow_nodes WHERE id = $1 FOR UPDATE",
            uuid_of(node_id.as_bytes()),
        )
        .fetch_one(&mut **tx)
        .await
        .ctx("scheduler expire: lock node row")?;
        let attempt = sqlx::query!(
            "SELECT state, started_at FROM central.session_attempts WHERE id = $1 FOR UPDATE",
            uuid_of(attempt_id.as_bytes()),
        )
        .fetch_one(&mut **tx)
        .await
        .ctx("scheduler expire: lock attempt row")?;

        // The conditional release is the idempotency guard against a
        // concurrent closer — one released_at write wins.
        let released = sqlx::query!(
            "UPDATE central.node_leases SET released_at = now() \
             WHERE id = $1 AND released_at IS NULL",
            uuid_of(lease_id.as_bytes()),
        )
        .execute(&mut **tx)
        .await
        .ctx("scheduler expire: release lease")?;
        if released.rows_affected() == 0 {
            return Ok(None);
        }

        let outcome = sched::expiry_decision(attempt.started_at.is_some(), via_worker_loss);
        let from = AttemptState::parse(&attempt.state).ok_or_else(|| {
            Failure::internal(
                PG_DATA_CORRUPT,
                "a stored attempt state is outside the vocabulary",
            )
        })?;
        if from.can_transition(outcome.attempt_state) {
            if outcome.attempt_state.is_terminal() {
                sqlx::query!(
                    "UPDATE central.session_attempts \
                     SET state = $2, dispatch_reason_code = $3, ended_at = now() \
                     WHERE id = $1",
                    uuid_of(attempt_id.as_bytes()),
                    outcome.attempt_state.as_str(),
                    outcome.reason_code,
                )
                .execute(&mut **tx)
                .await
                .ctx("scheduler expire: close attempt")?;
            } else {
                // 'ambiguous' is non-terminal: ended_at stays NULL for
                // the operator decision to close.
                sqlx::query!(
                    "UPDATE central.session_attempts \
                     SET state = $2, dispatch_reason_code = $3 \
                     WHERE id = $1",
                    uuid_of(attempt_id.as_bytes()),
                    outcome.attempt_state.as_str(),
                    outcome.reason_code,
                )
                .execute(&mut **tx)
                .await
                .ctx("scheduler expire: close attempt")?;
            }
        }

        let node_from = NodeStatus::parse(&node_state).ok_or_else(|| {
            Failure::internal(
                PG_DATA_CORRUPT,
                "a stored node state is outside the vocabulary",
            )
        })?;
        let node_to = NodeStatus::parse(outcome.node_state).ok_or_else(|| {
            Failure::internal(
                PG_DATA_CORRUPT,
                "an expiry node state is outside the vocabulary",
            )
        })?;
        let mut node_moved = false;
        if node_from.can_transition(node_to) {
            if node_to == NodeStatus::Ready {
                sqlx::query!(
                    "UPDATE central.workflow_nodes SET state = 'ready', ready_at = now() \
                     WHERE id = $1",
                    uuid_of(node_id.as_bytes()),
                )
                .execute(&mut **tx)
                .await
                .ctx("scheduler expire: move node")?;
            } else {
                sqlx::query!(
                    "UPDATE central.workflow_nodes SET state = $2 WHERE id = $1",
                    uuid_of(node_id.as_bytes()),
                    node_to.as_str(),
                )
                .execute(&mut **tx)
                .await
                .ctx("scheduler expire: move node")?;
            }
            node_moved = true;
        }

        let payload = serde_json::json!({
            "lease_id": lease_id.to_string(),
            "worker_id": worker_id.to_string(),
        });
        self.append_attempt_event_tx(
            tx,
            workspace_id,
            run_id,
            node_id,
            attempt_id,
            outcome.event_kind,
            actor,
            Some(outcome.reason_code),
            payload.clone(),
        )
        .await?;
        if node_moved && node_to == NodeStatus::Ready {
            // Fold parity: the spec-6 reconstruction table moves a node
            // to 'ready' only via node_ready — the attempt_failed record
            // alone leaves the folded node dispatched.
            self.append_node_event_tx(
                tx,
                workspace_id,
                run_id,
                node_id,
                EventKind::NodeReady.as_str(),
                actor,
                Some(outcome.reason_code),
                payload.clone(),
            )
            .await?;
        }
        self.append_attempt_event_tx(
            tx,
            workspace_id,
            run_id,
            node_id,
            attempt_id,
            EventKind::LeaseExpired.as_str(),
            actor,
            Some(outcome.reason_code),
            payload,
        )
        .await?;
        Ok(Some(ExpiryResult {
            lease_id,
            node_id,
            attempt_id,
            worker_id,
            outcome,
        }))
    }

    /// Every live lease of one worker expires in a single transaction
    /// through the worker-loss path, without touching the worker row's
    /// state (upstream `expireWorkerLeasesTx`).
    async fn expire_worker_leases_tx(
        &self,
        worker_id: WorkerId,
        actor: &str,
    ) -> Result<(), Failure> {
        let mut tx = self.begin().await?;
        let rows = sqlx::query!(
            "SELECT l.id \
             FROM central.node_leases l \
             JOIN central.session_attempts a ON a.id = l.attempt_id \
             WHERE l.worker_id = $1 AND l.released_at IS NULL \
             ORDER BY a.run_id, l.id",
            uuid_of(worker_id.as_bytes()),
        )
        .fetch_all(&mut *tx)
        .await
        .ctx("scheduler reconcile: list worker leases")?;
        for row in rows {
            let lease_id = NodeLeaseId::from_trusted_db_bytes(*row.id.as_bytes());
            self.expire_lease_tx(&mut tx, lease_id, true, actor).await?;
        }
        tx.commit()
            .await
            .ctx("scheduler reconcile: commit worker lease expiry")?;
        Ok(())
    }

    /// Marks one worker suspect and journals `worker_suspect` once —
    /// the UPDATE's state guard makes a repeat pass a no-op.
    async fn mark_suspect_tx(&self, worker_id: WorkerId) -> Result<(), Failure> {
        let mut tx = self.begin().await?;
        let tag = sqlx::query!(
            "UPDATE central.worker_registrations SET state = 'suspect' \
             WHERE id = $1 AND state = 'active'",
            uuid_of(worker_id.as_bytes()),
        )
        .execute(&mut *tx)
        .await
        .ctx("scheduler sweep: mark suspect")?;
        if tag.rows_affected() == 0 {
            return Ok(());
        }
        if let Some(wctx) = Self::resolve_worker_run_context(&mut tx, worker_id).await? {
            self.append_worker_event_tx(
                &mut tx,
                &wctx,
                EventKind::WorkerSuspect.as_str(),
                ACTOR_SCHEDULER,
                None,
                serde_json::json!({"worker_id": worker_id.to_string()}),
            )
            .await?;
        }
        tx.commit().await.ctx("scheduler sweep: commit suspect")?;
        Ok(())
    }

    /// Marks one worker lost and expires every live lease it holds, all
    /// in one transaction (upstream `markLostTx`, spec-2 decision 5).
    async fn mark_lost_tx(&self, worker_id: WorkerId) -> Result<(), Failure> {
        let mut tx = self.begin().await?;
        let tag = sqlx::query!(
            "UPDATE central.worker_registrations SET state = 'lost' \
             WHERE id = $1 AND state IN ('active', 'suspect')",
            uuid_of(worker_id.as_bytes()),
        )
        .execute(&mut *tx)
        .await
        .ctx("scheduler sweep: mark lost")?;
        if tag.rows_affected() == 0 {
            return Ok(());
        }
        if let Some(wctx) = Self::resolve_worker_run_context(&mut tx, worker_id).await? {
            self.append_worker_event_tx(
                &mut tx,
                &wctx,
                EventKind::WorkerLost.as_str(),
                ACTOR_SCHEDULER,
                Some(sched::REASON_WORKER_LOST_GRACE_EXPIRED),
                serde_json::json!({"worker_id": worker_id.to_string()}),
            )
            .await?;
        }
        // Leases order by run so run-row locks acquire in stable order.
        let rows = sqlx::query!(
            "SELECT l.id \
             FROM central.node_leases l \
             JOIN central.session_attempts a ON a.id = l.attempt_id \
             WHERE l.worker_id = $1 AND l.released_at IS NULL \
             ORDER BY a.run_id, l.id",
            uuid_of(worker_id.as_bytes()),
        )
        .fetch_all(&mut *tx)
        .await
        .ctx("scheduler sweep: list lost-worker leases")?;
        for row in rows {
            let lease_id = NodeLeaseId::from_trusted_db_bytes(*row.id.as_bytes());
            self.expire_lease_tx(&mut tx, lease_id, true, ACTOR_SCHEDULER)
                .await?;
        }
        tx.commit().await.ctx("scheduler sweep: commit lost")?;
        Ok(())
    }

    /// Loads the attempt joined to its live lease — the spec-2
    /// decision-7 fence every dispatch write passes (upstream
    /// `fencedAttemptTx` + the `fencedWriteTx` lock phase). The returned
    /// transaction holds run row → node row → attempt row → live lease
    /// locks, in the store's order.
    pub(crate) async fn fenced_begin_tx(
        &self,
        attempt_id: SessionAttemptId,
    ) -> Result<(Transaction<'static, Postgres>, FencedAttempt, NodeStatus), Failure> {
        let mut tx = self.begin().await?;
        let row = sqlx::query!(
            "SELECT a.id, a.node_id, a.run_id, a.workspace_id, a.state, a.attempt_seq, \
                    l.id AS lease_id, l.worker_id \
             FROM central.session_attempts a \
             JOIN central.node_leases l ON l.attempt_id = a.id \
             WHERE a.id = $1 AND l.released_at IS NULL AND l.expires_at > now()",
            uuid_of(attempt_id.as_bytes()),
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| crate::error::classify_sqlx(&e))?;
        let Some(row) = row else {
            return Err(domain_failure(
                sched::FailureClass::Denied,
                sched::REASON_LEASE_FENCE_STALE,
                "no live lease fences this attempt",
            ));
        };
        let mut f = FencedAttempt {
            attempt_id,
            node_id: WorkflowNodeId::from_trusted_db_bytes(*row.node_id.as_bytes()),
            run_id: RunId::from_trusted_db_bytes(*row.run_id.as_bytes()),
            workspace_id: WorkspaceId::from_trusted_db_bytes(*row.workspace_id.as_bytes()),
            state: AttemptState::parse(&row.state).ok_or_else(|| {
                Failure::internal(
                    PG_DATA_CORRUPT,
                    "a stored attempt state is outside the vocabulary",
                )
            })?,
            attempt_seq: row.attempt_seq,
            lease_id: NodeLeaseId::from_trusted_db_bytes(*row.lease_id.as_bytes()),
            worker_id: WorkerId::from_trusted_db_bytes(*row.worker_id.as_bytes()),
            node_spec: serde_json::Value::Null,
            node_timeout_sec: None,
            node_not_before: None,
        };

        // Lock order: run row, then node row, then attempt row, then
        // the lease re-check — the same order claim and expiry take.
        sqlx::query_scalar!(
            "SELECT id FROM central.runs WHERE id = $1 FOR UPDATE",
            uuid_of(f.run_id.as_bytes()),
        )
        .fetch_one(&mut *tx)
        .await
        .ctx("scheduler dispatch write: lock run row")?;
        let node = sqlx::query!(
            "SELECT state, spec, node_timeout_seconds, not_before \
             FROM central.workflow_nodes WHERE id = $1 FOR UPDATE",
            uuid_of(f.node_id.as_bytes()),
        )
        .fetch_one(&mut *tx)
        .await
        .ctx("scheduler dispatch write: lock node row")?;
        f.node_spec = node.spec;
        f.node_timeout_sec = node.node_timeout_seconds;
        f.node_not_before = node.not_before;
        let node_state = NodeStatus::parse(&node.state).ok_or_else(|| {
            Failure::internal(
                PG_DATA_CORRUPT,
                "a stored node state is outside the vocabulary",
            )
        })?;
        let attempt_state = sqlx::query_scalar!(
            "SELECT state FROM central.session_attempts WHERE id = $1 FOR UPDATE",
            uuid_of(f.attempt_id.as_bytes()),
        )
        .fetch_one(&mut *tx)
        .await
        .ctx("scheduler dispatch write: lock attempt row")?;
        f.state = AttemptState::parse(&attempt_state).ok_or_else(|| {
            Failure::internal(
                PG_DATA_CORRUPT,
                "a stored attempt state is outside the vocabulary",
            )
        })?;
        let live = sqlx::query_scalar!(
            "SELECT 1 AS one FROM central.node_leases \
             WHERE id = $1 AND released_at IS NULL AND expires_at > now() \
             FOR UPDATE",
            uuid_of(f.lease_id.as_bytes()),
        )
        .fetch_optional(&mut *tx)
        .await
        .ctx("scheduler dispatch write: re-check lease")?;
        if live.is_none() {
            return Err(domain_failure(
                sched::FailureClass::Denied,
                sched::REASON_LEASE_FENCE_STALE,
                "the fencing lease is released or expired",
            ));
        }
        Ok((tx, f, node_state))
    }

    /// Commits the transaction a `fenced_begin_tx` caller produced.
    pub(crate) async fn commit_fenced(tx: Transaction<'static, Postgres>) -> Result<(), Failure> {
        tx.commit().await.ctx("scheduler dispatch write: commit")
    }
}

// ---------------------------------------------------------------------------
// central_scheduler::port::Store — the 15-method write surface
// ---------------------------------------------------------------------------

impl central_scheduler::port::Store for PgSchedulerStore {
    /// `RegisterWorker` — the spec-2 handshake. A refused registration
    /// returns the `WORKER_REGISTRATION_REJECTED` failure and writes
    /// nothing (upstream deviation: no run context exists at
    /// registration time, so the refusal event cannot journal).
    async fn register_worker(&self, worker: Worker) -> Result<WorkerId, Failure> {
        if let Some(failure) = sched::registration_failure(
            worker.protocol_version,
            &worker.harness_kinds,
            &self.launchable_harnesses,
        ) {
            return Err(Failure::from(failure));
        }
        let id = if worker.id.is_nil() {
            WorkerId::new()
        } else {
            worker.id
        };
        let mut tx = self.begin().await?;
        sqlx::query!(
            "INSERT INTO central.worker_registrations \
             (id, workspace_id, protocol_version, harness_kinds, workspace_kinds, \
              max_concurrent_attempts, state, registered_at, last_seen_at) \
             VALUES ($1, $2, $3, $4, $5, $6, 'active', now(), now())",
            uuid_of(id.as_bytes()),
            uuid_of(worker.workspace_id.as_bytes()),
            worker.protocol_version,
            worker.harness_kinds.as_slice(),
            worker.workspace_kinds.as_slice(),
            worker.max_concurrent_attempts,
        )
        .execute(&mut *tx)
        .await
        .ctx("scheduler register worker: insert registration")?;
        tx.commit().await.ctx("scheduler register worker: commit")?;
        Ok(id)
    }

    /// `DeregisterWorker` — spec-2 clean-shutdown release in one
    /// transaction (upstream `DeregisterWorker`): the worker row closes
    /// `deregistered`, every live lease on a NEVER-STARTED attempt
    /// releases and its node returns to `ready` (with `node_ready`
    /// journaled for fold parity). Started attempts keep their lease.
    async fn deregister_worker(&self, worker_id: WorkerId, actor: &str) -> Result<(), Failure> {
        let mut tx = self.begin().await?;
        let row = sqlx::query!(
            "SELECT workspace_id, state FROM central.worker_registrations \
             WHERE id = $1 FOR UPDATE",
            uuid_of(worker_id.as_bytes()),
        )
        .fetch_optional(&mut *tx)
        .await
        .ctx("scheduler deregister: lock worker row")?;
        let Some(row) = row else {
            return Err(domain_failure(
                sched::FailureClass::Invalid,
                sched::REASON_WORKER_NOT_FOUND,
                "no such worker registration",
            ));
        };
        let worker_state = WorkerState::parse(&row.state).ok_or_else(|| {
            Failure::internal(
                PG_DATA_CORRUPT,
                "a stored worker state is outside the vocabulary",
            )
        })?;
        if worker_state == WorkerState::Deregistered {
            // Re-deregistration is an idempotent replay success.
            tx.commit()
                .await
                .ctx("scheduler deregister: commit replay")?;
            return Ok(());
        }
        sqlx::query!(
            "UPDATE central.worker_registrations \
             SET state = 'deregistered', deregistered_at = now() WHERE id = $1",
            uuid_of(worker_id.as_bytes()),
        )
        .execute(&mut *tx)
        .await
        .ctx("scheduler deregister: close worker row")?;

        // Resolve the worker-scope event binding before releases mutate
        // state; a lease-less worker journals nothing.
        let wctx = Self::resolve_worker_run_context(&mut tx, worker_id).await?;

        // Live leases ordered by run so run-row locks acquire in a
        // stable order across the multi-run case.
        let held = sqlx::query!(
            "SELECT l.id AS lease_id, l.node_id, l.attempt_id, a.run_id, a.workspace_id, \
                    a.state AS attempt_state, a.started_at \
             FROM central.node_leases l \
             JOIN central.session_attempts a ON a.id = l.attempt_id \
             WHERE l.worker_id = $1 AND l.released_at IS NULL \
             ORDER BY a.run_id, l.id",
            uuid_of(worker_id.as_bytes()),
        )
        .fetch_all(&mut *tx)
        .await
        .ctx("scheduler deregister: list live leases")?;

        for h in &held {
            // A started attempt may not be cleanly released — its lease
            // stays live for outcome persistence or ambiguous expiry.
            if h.started_at.is_some() {
                continue;
            }
            let lease_id = NodeLeaseId::from_trusted_db_bytes(*h.lease_id.as_bytes());
            let node_id = WorkflowNodeId::from_trusted_db_bytes(*h.node_id.as_bytes());
            let attempt_id = SessionAttemptId::from_trusted_db_bytes(*h.attempt_id.as_bytes());
            let run_id = RunId::from_trusted_db_bytes(*h.run_id.as_bytes());
            let ws_id = WorkspaceId::from_trusted_db_bytes(*h.workspace_id.as_bytes());
            // Run-row lock then node-row lock — the documented order.
            sqlx::query_scalar!(
                "SELECT id FROM central.runs WHERE id = $1 FOR UPDATE",
                uuid_of(run_id.as_bytes()),
            )
            .fetch_one(&mut *tx)
            .await
            .ctx("scheduler deregister: lock run row")?;
            let node_state = sqlx::query_scalar!(
                "SELECT state FROM central.workflow_nodes WHERE id = $1 FOR UPDATE",
                uuid_of(node_id.as_bytes()),
            )
            .fetch_one(&mut *tx)
            .await
            .ctx("scheduler deregister: lock node row")?;
            sqlx::query!(
                "UPDATE central.node_leases SET released_at = now() \
                 WHERE id = $1 AND released_at IS NULL",
                uuid_of(lease_id.as_bytes()),
            )
            .execute(&mut *tx)
            .await
            .ctx("scheduler deregister: release lease")?;

            // 'cancelled' is the clean-shutdown state where the machine
            // allows it; a 'provisioning' attempt cannot reach cancelled
            // (claimed-only edge), so it closes 'failed'.
            let from = AttemptState::parse(&h.attempt_state).ok_or_else(|| {
                Failure::internal(
                    PG_DATA_CORRUPT,
                    "a stored attempt state is outside the vocabulary",
                )
            })?;
            let target = if from.can_transition(AttemptState::Cancelled) {
                AttemptState::Cancelled
            } else if from.can_transition(AttemptState::Failed) {
                AttemptState::Failed
            } else {
                return Err(domain_failure(
                    sched::FailureClass::Conflict,
                    sched::REASON_WORKER_SHUTDOWN_LEASE_RELEASED,
                    format!("attempt state {} admits no shutdown release", from.as_str()),
                ));
            };
            sqlx::query!(
                "UPDATE central.session_attempts \
                 SET state = $2, dispatch_reason_code = $3, ended_at = now() \
                 WHERE id = $1",
                uuid_of(attempt_id.as_bytes()),
                target.as_str(),
                sched::REASON_WORKER_SHUTDOWN_LEASE_RELEASED,
            )
            .execute(&mut *tx)
            .await
            .ctx("scheduler deregister: close attempt")?;

            let node_from = NodeStatus::parse(&node_state).ok_or_else(|| {
                Failure::internal(
                    PG_DATA_CORRUPT,
                    "a stored node state is outside the vocabulary",
                )
            })?;
            if node_from.can_transition(NodeStatus::Ready) {
                sqlx::query!(
                    "UPDATE central.workflow_nodes SET state = 'ready', ready_at = now() \
                     WHERE id = $1",
                    uuid_of(node_id.as_bytes()),
                )
                .execute(&mut *tx)
                .await
                .ctx("scheduler deregister: requeue node")?;
                self.append_node_event_tx(
                    &mut tx,
                    ws_id,
                    run_id,
                    node_id,
                    EventKind::NodeReady.as_str(),
                    actor,
                    Some(sched::REASON_WORKER_SHUTDOWN_LEASE_RELEASED),
                    serde_json::json!({
                        "worker_id": worker_id.to_string(),
                        "attempt_id": attempt_id.to_string(),
                    }),
                )
                .await?;
            }
        }

        if let Some(wctx) = wctx {
            self.append_worker_event_tx(
                &mut tx,
                &wctx,
                EventKind::WorkerDeregistered.as_str(),
                actor,
                None,
                serde_json::json!({"worker_id": worker_id.to_string()}),
            )
            .await?;
        }
        tx.commit().await.ctx("scheduler deregister: commit")?;
        Ok(())
    }

    /// `ClaimReady` — the two-phase atomic claim (upstream
    /// `ClaimReady`): a lock-free FIFO candidate scan, then one
    /// transaction per candidate under the run→node lock order.
    async fn claim_ready(
        &self,
        worker_id: WorkerId,
        limit: u32,
    ) -> Result<Vec<ClaimedAttempt>, Failure> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let row = sqlx::query!(
            "SELECT workspace_id, harness_kinds, workspace_kinds, max_concurrent_attempts, state \
             FROM central.worker_registrations WHERE id = $1",
            uuid_of(worker_id.as_bytes()),
        )
        .fetch_optional(&self.pool)
        .await
        .ctx("scheduler claim: read worker")?;
        let Some(row) = row else {
            return Err(domain_failure(
                sched::FailureClass::Invalid,
                sched::REASON_WORKER_NOT_FOUND,
                "no such worker registration",
            ));
        };
        let worker = WorkerRow {
            workspace_id: WorkspaceId::from_trusted_db_bytes(*row.workspace_id.as_bytes()),
            harness_kinds: row.harness_kinds,
            workspace_kinds: row.workspace_kinds,
            max_concurrent_attempts: row.max_concurrent_attempts,
            state: WorkerState::parse(&row.state).ok_or_else(|| {
                Failure::internal(
                    PG_DATA_CORRUPT,
                    "a stored worker state is outside the vocabulary",
                )
            })?,
        };
        match worker.state {
            // suspect is observable only — it neither revokes leases
            // nor blocks claims (spec-2 decision 5).
            WorkerState::Active | WorkerState::Suspect => {}
            _ => {
                return Err(domain_failure(
                    sched::FailureClass::Denied,
                    sched::REASON_WORKER_NOT_ACTIVE,
                    format!("worker state {} admits no claims", worker.state.as_str()),
                ));
            }
        }

        let inflight: Option<i64> = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM central.node_leases \
             WHERE worker_id = $1 AND released_at IS NULL",
            uuid_of(worker_id.as_bytes()),
        )
        .fetch_one(&self.pool)
        .await
        .ctx("scheduler claim: count live leases")?;
        let mut take = i64::from(worker.max_concurrent_attempts) - inflight.unwrap_or(0);
        take = take.min(i64::from(limit));
        if take <= 0 {
            return Ok(Vec::new());
        }

        // Phase 1: candidate scan — no row locks.
        let candidates = sqlx::query!(
            "SELECT id, run_id, workspace_id \
             FROM central.workflow_nodes \
             WHERE state = 'ready' \
               AND workspace_id = $1 \
               AND (not_before IS NULL OR not_before <= now()) \
               AND harness = ANY($2::text[]) \
               AND workspace_kind = ANY($3::text[]) \
             ORDER BY COALESCE(ready_at, created_at), node_key \
             LIMIT $4",
            uuid_of(worker.workspace_id.as_bytes()),
            worker.harness_kinds.as_slice(),
            worker.workspace_kinds.as_slice(),
            take,
        )
        .fetch_all(&self.pool)
        .await
        .ctx("scheduler claim: scan ready nodes")?;

        // Phase 2: one transaction per candidate.
        let profile = self.admission_profile();
        let mut claimed = Vec::with_capacity(candidates.len());
        for c in candidates {
            let cand = ClaimCandidate {
                node_id: WorkflowNodeId::from_trusted_db_bytes(*c.id.as_bytes()),
                run_id: RunId::from_trusted_db_bytes(*c.run_id.as_bytes()),
                workspace_id: WorkspaceId::from_trusted_db_bytes(*c.workspace_id.as_bytes()),
            };
            match self
                .claim_candidate_tx(&worker, worker_id, &cand, &profile)
                .await?
            {
                ClaimOutcome::Claimed(attempt) => claimed.push(*attempt),
                ClaimOutcome::Deferred(admission::Admission {
                    detail: Some("max_parallel_sessions"),
                    ..
                }) => break,
                ClaimOutcome::Deferred(_) | ClaimOutcome::Skipped => {}
            }
        }
        Ok(claimed)
    }

    /// `RenewLease` — conditional `last_heartbeat_at`/`expires_at`
    /// extension under the `(lease_id, worker_id)` live-lease match; a
    /// stale match journals `lease_renewal_rejected` in its own commit
    /// and returns `DENIED`/`LEASE_RENEWAL_STALE`.
    async fn renew_lease(&self, lease_id: NodeLeaseId, worker_id: WorkerId) -> Result<(), Failure> {
        let mut tx = self.begin().await?;
        let tag = sqlx::query!(
            "UPDATE central.node_leases \
             SET last_heartbeat_at = now(), \
                 expires_at = now() + make_interval(secs => $3) \
             WHERE id = $1 AND worker_id = $2 \
               AND released_at IS NULL AND expires_at > now()",
            uuid_of(lease_id.as_bytes()),
            uuid_of(worker_id.as_bytes()),
            sched::lease_ttl().as_seconds_f64(),
        )
        .execute(&mut *tx)
        .await
        .ctx("scheduler renew lease: conditional update")?;
        if tag.rows_affected() == 1 {
            tx.commit().await.ctx("scheduler renew lease: commit")?;
            return Ok(());
        }
        drop(tx);

        // Stale renewal: journal the rejection when the lease row still
        // resolves a run; a lease row gone entirely leaves the failure.
        let failure = || {
            Failure::denied(
                sched::REASON_LEASE_RENEWAL_STALE,
                "the lease is expired, released, or superseded",
            )
        };
        let row = sqlx::query!(
            "SELECT l.node_id, l.attempt_id, a.run_id, a.workspace_id \
             FROM central.node_leases l \
             JOIN central.session_attempts a ON a.id = l.attempt_id \
             WHERE l.id = $1",
            uuid_of(lease_id.as_bytes()),
        )
        .fetch_optional(&self.pool)
        .await;
        let row = match row {
            Ok(Some(r)) => r,
            Ok(None) => return Err(failure()),
            Err(err) => {
                let classified = crate::error::classify_sqlx(&err);
                return Err(Failure::new(
                    classified.kind(),
                    sched::REASON_LEASE_RENEWAL_STALE,
                    format!(
                        "scheduler renew lease: resolve rejection context: {}",
                        classified.message()
                    ),
                ));
            }
        };
        let event = RunEvent {
            id: RunEventId::new(),
            workspace_id: WorkspaceId::from_trusted_db_bytes(*row.workspace_id.as_bytes()),
            run_id: RunId::from_trusted_db_bytes(*row.run_id.as_bytes()),
            seq: 0,
            node_id: Some(WorkflowNodeId::from_trusted_db_bytes(
                *row.node_id.as_bytes(),
            )),
            attempt_id: Some(SessionAttemptId::from_trusted_db_bytes(
                *row.attempt_id.as_bytes(),
            )),
            kind: EventKind::LeaseRenewalRejected.as_str().to_owned(),
            actor: ACTOR_SCHEDULER.to_owned(),
            reason_code: Some(sched::REASON_LEASE_RENEWAL_STALE.to_owned()),
            payload: serde_json::json!({
                "lease_id": lease_id.to_string(),
                "worker_id": worker_id.to_string(),
            }),
            recorded_at: OffsetDateTime::UNIX_EPOCH,
        };
        if let Err(err) = self.append_solo(&event).await {
            // The rejection stands even if its journal row fails to
            // commit; the cause surfaces through the message.
            return Err(Failure::denied(
                sched::REASON_LEASE_RENEWAL_STALE,
                format!(
                    "the lease is stale and its rejection failed to journal: {}",
                    err.message()
                ),
            ));
        }
        Err(failure())
    }

    /// `Fence` — the spec-2 decision-7 durable-write guard.
    async fn fence(
        &self,
        node_id: WorkflowNodeId,
        attempt_id: SessionAttemptId,
        lease_id: NodeLeaseId,
    ) -> Result<(), Failure> {
        let found = sqlx::query_scalar!(
            "SELECT 1 AS one FROM central.node_leases \
             WHERE id = $1 AND node_id = $2 AND attempt_id = $3 \
               AND released_at IS NULL AND expires_at > now()",
            uuid_of(lease_id.as_bytes()),
            uuid_of(node_id.as_bytes()),
            uuid_of(attempt_id.as_bytes()),
        )
        .fetch_optional(&self.pool)
        .await
        .ctx("scheduler fence: check lease")?;
        if found.is_none() {
            return Err(domain_failure(
                sched::FailureClass::Denied,
                sched::REASON_LEASE_FENCE_STALE,
                "the presented lease is not live for this node/attempt",
            ));
        }
        Ok(())
    }

    /// `WorkerLeases` — the worker's live leases in stable order (the
    /// heartbeat set); no lock, no journal.
    async fn worker_leases(&self, worker_id: WorkerId) -> Result<Vec<Lease>, Failure> {
        let rows = sqlx::query!(
            "SELECT id, node_id, attempt_id, worker_id, issued_at, last_heartbeat_at, \
                    expires_at, heartbeat_interval_seconds, released_at \
             FROM central.node_leases \
             WHERE worker_id = $1 AND released_at IS NULL \
             ORDER BY id",
            uuid_of(worker_id.as_bytes()),
        )
        .fetch_all(&self.pool)
        .await
        .ctx("scheduler worker leases: query")?;
        rows.iter()
            .map(|r| {
                Ok(Lease {
                    id: NodeLeaseId::from_trusted_db_bytes(*r.id.as_bytes()),
                    node_id: WorkflowNodeId::from_trusted_db_bytes(*r.node_id.as_bytes()),
                    attempt_id: SessionAttemptId::from_trusted_db_bytes(*r.attempt_id.as_bytes()),
                    worker_id: WorkerId::from_trusted_db_bytes(*r.worker_id.as_bytes()),
                    issued_at: r.issued_at,
                    last_heartbeat_at: r.last_heartbeat_at,
                    expires_at: r.expires_at,
                    heartbeat_interval_sec: r.heartbeat_interval_seconds,
                    released_at: r.released_at,
                })
            })
            .collect()
    }

    /// `ExpireLeases` — every live lease whose `expires_at` has passed
    /// at `now`, one transaction per lease, split per
    /// [`sched::expiry_decision`].
    async fn expire_leases(&self, now: OffsetDateTime) -> Result<Vec<ExpiryResult>, Failure> {
        let rows = sqlx::query!(
            "SELECT id FROM central.node_leases \
             WHERE released_at IS NULL AND expires_at <= $1 \
             ORDER BY id",
            now,
        )
        .fetch_all(&self.pool)
        .await
        .ctx("scheduler expire: scan expired leases")?;
        let mut results = Vec::with_capacity(rows.len());
        for row in rows {
            let lease_id = NodeLeaseId::from_trusted_db_bytes(*row.id.as_bytes());
            let mut tx = self.begin().await?;
            let res = self
                .expire_lease_tx(&mut tx, lease_id, false, ACTOR_SCHEDULER)
                .await?;
            if let Some(result) = res {
                tx.commit().await.ctx("scheduler expire: commit lease")?;
                results.push(result);
            }
            // A `None` result rolls back on drop — a concurrent closer won.
        }
        Ok(results)
    }

    /// `Reconcile` — the startup reconcile-before-reinvoke pass:
    /// expired leases follow the plain expiry path, then live leases of
    /// ladder-terminal workers expire through the worker-loss path.
    async fn reconcile(&self, actor: &str) -> Result<(), Failure> {
        let actor = if actor.is_empty() {
            ACTOR_RECONCILER
        } else {
            actor
        };
        // Pass 1: expired live leases.
        let expired = sqlx::query!(
            "SELECT id FROM central.node_leases \
             WHERE released_at IS NULL AND expires_at <= now() \
             ORDER BY id",
        )
        .fetch_all(&self.pool)
        .await
        .ctx("scheduler reconcile: scan expired leases")?;
        for row in expired {
            let lease_id = NodeLeaseId::from_trusted_db_bytes(*row.id.as_bytes());
            let mut tx = self.begin().await?;
            let res = self
                .expire_lease_tx(&mut tx, lease_id, false, actor)
                .await?;
            if res.is_some() {
                tx.commit()
                    .await
                    .ctx("scheduler reconcile: commit lease expiry")?;
            }
        }
        // Pass 2: live leases of ladder-terminal workers.
        let orphans = sqlx::query!(
            "SELECT DISTINCT l.worker_id \
             FROM central.node_leases l \
             JOIN central.worker_registrations w ON w.id = l.worker_id \
             WHERE l.released_at IS NULL AND w.state IN ('lost', 'deregistered') \
             ORDER BY l.worker_id",
        )
        .fetch_all(&self.pool)
        .await
        .ctx("scheduler reconcile: list orphan workers")?;
        for row in orphans {
            let worker_id = WorkerId::from_trusted_db_bytes(*row.worker_id.as_bytes());
            self.expire_worker_leases_tx(worker_id, actor).await?;
        }
        Ok(())
    }

    /// `SweepSuspects` — the missed-beat ladder at `now` (spec-2
    /// decision 5): workers holding live leases only; suspect journals
    /// once, lost expires every held lease in one transaction.
    async fn sweep_suspects(&self, now: OffsetDateTime) -> Result<(), Failure> {
        let rows = sqlx::query!(
            "SELECT w.id, w.state, MAX(l.last_heartbeat_at) AS last_beat \
             FROM central.worker_registrations w \
             JOIN central.node_leases l ON l.worker_id = w.id AND l.released_at IS NULL \
             WHERE w.state IN ('active', 'suspect') \
             GROUP BY w.id, w.state \
             ORDER BY w.id",
        )
        .fetch_all(&self.pool)
        .await
        .ctx("scheduler sweep: list beating workers")?;
        for row in rows {
            let worker_id = WorkerId::from_trusted_db_bytes(*row.id.as_bytes());
            let state = WorkerState::parse(&row.state).ok_or_else(|| {
                Failure::internal(
                    PG_DATA_CORRUPT,
                    "a stored worker state is outside the vocabulary",
                )
            })?;
            let Some(last_beat) = row.last_beat else {
                continue;
            };
            match sched::ladder(sched::missed_beats(now, last_beat)) {
                WorkerState::Suspect if state == WorkerState::Active => {
                    self.mark_suspect_tx(worker_id).await?;
                }
                WorkerState::Lost => {
                    self.mark_lost_tx(worker_id).await?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// `MarkProvisioning` — claimed → `provisioning` under the fence;
    /// journals nothing (the catalog has no provisioning-scope kind).
    async fn mark_provisioning(
        &self,
        attempt_id: SessionAttemptId,
        workspace_path: &str,
    ) -> Result<(), Failure> {
        let (tx, f, _node_state) = self.fenced_begin_tx(attempt_id).await?;
        if !f.state.can_transition(AttemptState::Provisioning) {
            return Err(domain_failure(
                sched::FailureClass::Denied,
                sched::REASON_INVALID_ATTEMPT_TRANSITION,
                format!(
                    "attempt state {} admits no provisioning mark",
                    f.state.as_str()
                ),
            ));
        }
        let mut tx = tx;
        sqlx::query!(
            "UPDATE central.session_attempts \
             SET state = 'provisioning', workspace_path = $2 WHERE id = $1",
            uuid_of(f.attempt_id.as_bytes()),
            workspace_path,
        )
        .execute(&mut *tx)
        .await
        .ctx("scheduler mark provisioning: update attempt")?;
        Self::commit_fenced(tx).await
    }

    /// `MarkStarted` — provisioning → `started` (started_at +
    /// harness_session_id), node → `running`, `attempt_started`
    /// journaled; the lease stays live.
    async fn mark_started(
        &self,
        attempt_id: SessionAttemptId,
        harness_session_id: &str,
    ) -> Result<(), Failure> {
        let (mut tx, f, node_state) = self.fenced_begin_tx(attempt_id).await?;
        if !f.state.can_transition(AttemptState::Started) {
            return Err(domain_failure(
                sched::FailureClass::Denied,
                sched::REASON_INVALID_ATTEMPT_TRANSITION,
                format!("attempt state {} admits no start", f.state.as_str()),
            ));
        }
        sqlx::query!(
            "UPDATE central.session_attempts \
             SET state = 'started', started_at = now(), harness_session_id = $2 \
             WHERE id = $1",
            uuid_of(f.attempt_id.as_bytes()),
            harness_session_id,
        )
        .execute(&mut *tx)
        .await
        .ctx("scheduler mark started: update attempt")?;
        if !node_state.can_transition(NodeStatus::Running) {
            return Err(domain_failure(
                sched::FailureClass::Denied,
                sched::REASON_INVALID_ATTEMPT_TRANSITION,
                format!("node state {} admits no running mark", node_state.as_str()),
            ));
        }
        sqlx::query!(
            "UPDATE central.workflow_nodes SET state = 'running' WHERE id = $1",
            uuid_of(f.node_id.as_bytes()),
        )
        .execute(&mut *tx)
        .await
        .ctx("scheduler mark started: move node")?;
        self.append_attempt_event_tx(
            &mut tx,
            f.workspace_id,
            f.run_id,
            f.node_id,
            f.attempt_id,
            EventKind::AttemptStarted.as_str(),
            ACTOR_SCHEDULER,
            None,
            serde_json::json!({
                "worker_id": f.worker_id.to_string(),
                "lease_id": f.lease_id.to_string(),
                "harness_session_id": harness_session_id,
            }),
        )
        .await?;
        Self::commit_fenced(tx).await
    }

    /// `FailDispatch` — the definite dispatch-failure path through
    /// [`record_outcome`](central_retry::port::Store::record_outcome)
    /// with the derived `(attempt_id, kind, reason)` fingerprint.
    async fn fail_dispatch(
        &self,
        attempt_id: SessionAttemptId,
        reason_code: &str,
    ) -> Result<(), Failure> {
        let _ = central_retry::port::Store::record_outcome(
            self,
            Outcome {
                attempt_id,
                kind: OutcomeKind::Failed,
                reason_code: reason_code.to_owned(),
                fingerprint: crate::scheduler::outcome::derived_outcome_fingerprint(
                    attempt_id,
                    OutcomeKind::Failed,
                    reason_code,
                ),
                retry_after: None,
            },
        )
        .await?;
        Ok(())
    }

    /// `AmbiguateDispatch` — the unknown-outcome park: attempt
    /// `ambiguous` + reason, lease released, node `attempt_ambiguous`,
    /// `attempt_ambiguous` journaled (locked input 1 — never
    /// auto-relaunch).
    async fn ambiguate_dispatch(
        &self,
        attempt_id: SessionAttemptId,
        reason_code: &str,
    ) -> Result<(), Failure> {
        let (mut tx, f, node_state) = self.fenced_begin_tx(attempt_id).await?;
        if !f.state.can_transition(AttemptState::Ambiguous) {
            return Err(domain_failure(
                sched::FailureClass::Denied,
                sched::REASON_INVALID_ATTEMPT_TRANSITION,
                format!(
                    "attempt state {} admits no ambiguous park",
                    f.state.as_str()
                ),
            ));
        }
        sqlx::query!(
            "UPDATE central.session_attempts \
             SET state = 'ambiguous', dispatch_reason_code = $2 \
             WHERE id = $1",
            uuid_of(f.attempt_id.as_bytes()),
            reason_code,
        )
        .execute(&mut *tx)
        .await
        .ctx("scheduler ambiguate dispatch: update attempt")?;
        sqlx::query!(
            "UPDATE central.node_leases SET released_at = now() \
             WHERE id = $1 AND released_at IS NULL",
            uuid_of(f.lease_id.as_bytes()),
        )
        .execute(&mut *tx)
        .await
        .ctx("scheduler ambiguate dispatch: release lease")?;
        if node_state.can_transition(NodeStatus::AttemptAmbiguous) {
            sqlx::query!(
                "UPDATE central.workflow_nodes SET state = 'attempt_ambiguous' WHERE id = $1",
                uuid_of(f.node_id.as_bytes()),
            )
            .execute(&mut *tx)
            .await
            .ctx("scheduler ambiguate dispatch: park node")?;
        }
        self.append_attempt_event_tx(
            &mut tx,
            f.workspace_id,
            f.run_id,
            f.node_id,
            f.attempt_id,
            EventKind::AttemptAmbiguous.as_str(),
            ACTOR_SCHEDULER,
            Some(reason_code),
            serde_json::json!({
                "worker_id": f.worker_id.to_string(),
                "lease_id": f.lease_id.to_string(),
            }),
        )
        .await?;
        Self::commit_fenced(tx).await
    }

    /// `ListWallClockBreaches` — `started` attempts whose session age
    /// at `now` crossed the installed profile's wall-clock ceiling
    /// (unset ceiling → empty). Read-only.
    async fn list_wall_clock_breaches(
        &self,
        now: OffsetDateTime,
    ) -> Result<Vec<SessionAttempt>, Failure> {
        let profile = self.admission_profile();
        if profile.wall_clock_ceiling <= time::Duration::ZERO {
            return Ok(Vec::new());
        }
        let rows = sqlx::query!(
            "SELECT id, workspace_id, run_id, node_id, attempt_seq, worker_id, \
                    workspace_kind, state, claimed_at, started_at \
             FROM central.session_attempts \
             WHERE state = 'started' AND started_at IS NOT NULL \
               AND started_at + make_interval(secs => $2) <= $1 \
             ORDER BY id",
            now,
            profile.wall_clock_ceiling.as_seconds_f64(),
        )
        .fetch_all(&self.pool)
        .await
        .ctx("scheduler ceilings: list breaches")?;
        rows.iter()
            .map(|r| {
                Ok(SessionAttempt {
                    id: SessionAttemptId::from_trusted_db_bytes(*r.id.as_bytes()),
                    workspace_id: WorkspaceId::from_trusted_db_bytes(*r.workspace_id.as_bytes()),
                    run_id: RunId::from_trusted_db_bytes(*r.run_id.as_bytes()),
                    node_id: WorkflowNodeId::from_trusted_db_bytes(*r.node_id.as_bytes()),
                    attempt_seq: r.attempt_seq,
                    worker_id: r
                        .worker_id
                        .map(|id| WorkerId::from_trusted_db_bytes(*id.as_bytes())),
                    harness_attempt_id: None,
                    workspace_path: None,
                    workspace_kind: r.workspace_kind.clone(),
                    state: AttemptState::parse(&r.state).ok_or_else(|| {
                        Failure::internal(
                            PG_DATA_CORRUPT,
                            "a stored attempt state is outside the vocabulary",
                        )
                    })?,
                    dispatch_reason_code: None,
                    reservation_id: None,
                    harness_session_id: None,
                    claimed_at: r.claimed_at,
                    started_at: r.started_at,
                    ended_at: None,
                })
            })
            .collect()
    }

    /// `RecordCeilingBreach` — a confirmed mid-session breach commits
    /// through `fail_dispatch`; codes outside the spec-8 set reject
    /// `INVALID_BREACH_CODE`.
    async fn record_ceiling_breach(
        &self,
        attempt_id: SessionAttemptId,
        reason_code: &str,
    ) -> Result<(), Failure> {
        if !admission::ceiling_breach_reason(reason_code) {
            return Err(domain_failure(
                sched::FailureClass::Invalid,
                REASON_INVALID_BREACH_CODE,
                format!("{reason_code} is outside the spec-8 breach set"),
            ));
        }
        self.fail_dispatch(attempt_id, reason_code).await
    }
}

/// The retry/compensation-relevant projection of a node `spec` —
/// upstream `json.Unmarshal`s the whole document into `*workflow.Node`
/// and ignores the error, so absent fields evaluate to zero values.
/// Deserializing the full `ChildSpecNode` would reject `{:}` specs, so
/// the adapter projects the fields it consumes with serde defaults.
#[derive(Debug, Default, serde::Deserialize)]
pub(crate) struct NodeSpecCaps {
    /// `max_attempts` — per-class limits.
    #[serde(default)]
    pub max_attempts: std::collections::BTreeMap<String, i64>,
    /// `max_attempts_total` — the all-class aggregate bound.
    #[serde(default)]
    pub max_attempts_total: Option<i64>,
    /// `on_terminal_failure` — the compensation hook.
    #[serde(default)]
    pub on_terminal_failure: String,
}

/// What one per-candidate claim transaction settled (upstream's
/// `(*ClaimedAttempt, *Admission, error)` triple).
enum ClaimOutcome {
    /// The node dispatched under a fresh attempt + lease.
    Claimed(Box<ClaimedAttempt>),
    /// Admission refused; `admission_deferred` committed, node stays
    /// `ready` with `ready_at` untouched.
    Deferred(admission::Admission),
    /// The candidate was lost to a concurrent claim (NOWAIT refusal or
    /// a moved state) or no longer matches.
    Skipped,
}

impl PgSchedulerStore {
    /// `claimCandidateTx` — one claim transaction: run-row lock first,
    /// node row `FOR UPDATE NOWAIT`, state/capability re-verify, the
    /// spec-8 admission gate (host count is a snapshot; the per-run
    /// count is exact under the run-row lock), then node `dispatched`
    /// + attempt row (attempt_seq = attempt_count + 1) + lease +
    ///   the `node_dispatched` event, atomically.
    async fn claim_candidate_tx(
        &self,
        worker: &WorkerRow,
        worker_id: WorkerId,
        cand: &ClaimCandidate,
        profile: &ConcurrencyProfile,
    ) -> Result<ClaimOutcome, Failure> {
        let mut tx = self.begin().await?;

        // Run-row lock FIRST, then the node row: append_tx's run-row
        // FOR UPDATE is the serialization point, so the node lock must
        // never precede it.
        let run_lock = sqlx::query_scalar!(
            "SELECT id FROM central.runs WHERE id = $1 FOR UPDATE",
            uuid_of(cand.run_id.as_bytes()),
        )
        .fetch_optional(&mut *tx)
        .await;
        match run_lock {
            Err(err) if is_lock_not_available(&err) => return Ok(ClaimOutcome::Skipped),
            Err(err) => return Err(crate::error::classify_sqlx(&err)),
            Ok(None) => return Ok(ClaimOutcome::Skipped),
            Ok(Some(_)) => {}
        }
        let node = sqlx::query!(
            "SELECT state, node_key, harness, workspace_kind, attempt_count, workspace_id \
             FROM central.workflow_nodes WHERE id = $1 FOR UPDATE NOWAIT",
            uuid_of(cand.node_id.as_bytes()),
        )
        .fetch_optional(&mut *tx)
        .await;
        let node = match node {
            Err(err) if is_lock_not_available(&err) => return Ok(ClaimOutcome::Skipped),
            Err(err) => return Err(crate::error::classify_sqlx(&err)),
            Ok(None) => return Ok(ClaimOutcome::Skipped),
            Ok(Some(n)) => n,
        };
        let caps = Worker {
            id: worker_id,
            workspace_id: worker.workspace_id,
            protocol_version: sched::PROTOCOL_VERSION,
            harness_kinds: worker.harness_kinds.clone(),
            workspace_kinds: worker.workspace_kinds.clone(),
            max_concurrent_attempts: worker.max_concurrent_attempts,
            state: WorkerState::Active,
            registered_at: None,
            last_seen_at: None,
        };
        if node.state != NodeStatus::Ready.as_str()
            || !sched::capability_match(&caps, &node.harness, &node.workspace_kind)
        {
            return Ok(ClaimOutcome::Skipped);
        }

        // Admission gate (spec-8 decisions 2 and 6): the claim
        // transaction is the enforcement point.
        let host_inflight: Option<i64> = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM central.session_attempts \
             WHERE state IN ('claimed', 'provisioning', 'started')",
        )
        .fetch_one(&mut *tx)
        .await
        .ctx("scheduler claim: count inflight sessions")?;
        let run_inflight: Option<i64> = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM central.session_attempts \
             WHERE run_id = $1 AND state IN ('claimed', 'provisioning', 'started')",
            uuid_of(cand.run_id.as_bytes()),
        )
        .fetch_one(&mut *tx)
        .await
        .ctx("scheduler claim: count run inflight")?;
        let admission = admission::check_dispatch_admission(
            profile,
            &AdmissionSnapshot {
                inflight_sessions: i32::try_from(host_inflight.unwrap_or(0)).unwrap_or(i32::MAX),
                run_inflight_nodes: i32::try_from(run_inflight.unwrap_or(0)).unwrap_or(i32::MAX),
                disk_budget_bytes: profile.session_ceilings(&node.workspace_kind).disk_bytes,
                ..AdmissionSnapshot::default()
            },
        );
        if !admission.admit {
            self.journal_deferral_tx(&mut tx, cand, &node.node_key, worker_id, &admission)
                .await?;
            tx.commit().await.ctx("scheduler claim: commit deferral")?;
            return Ok(ClaimOutcome::Deferred(admission));
        }

        let attempt_seq = node.attempt_count.checked_add(1).ok_or_else(|| {
            Failure::internal(PG_DATA_CORRUPT, "a stored attempt_count overflowed i32")
        })?;
        sqlx::query!(
            "UPDATE central.workflow_nodes \
             SET state = 'dispatched', attempt_count = attempt_count + 1 WHERE id = $1",
            uuid_of(cand.node_id.as_bytes()),
        )
        .execute(&mut *tx)
        .await
        .ctx("scheduler claim: dispatch node")?;

        let attempt_id = SessionAttemptId::new();
        let node_ws = WorkspaceId::from_trusted_db_bytes(*node.workspace_id.as_bytes());
        let claimed_at = sqlx::query_scalar!(
            "INSERT INTO central.session_attempts \
             (id, workspace_id, run_id, node_id, attempt_seq, worker_id, workspace_kind, \
              state, claimed_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, 'claimed', now()) \
             RETURNING claimed_at",
            uuid_of(attempt_id.as_bytes()),
            uuid_of(node_ws.as_bytes()),
            uuid_of(cand.run_id.as_bytes()),
            uuid_of(cand.node_id.as_bytes()),
            attempt_seq,
            uuid_of(worker_id.as_bytes()),
            &node.workspace_kind,
        )
        .fetch_one(&mut *tx)
        .await
        .ctx("scheduler claim: insert session attempt")?;

        let lease_id = NodeLeaseId::new();
        const HEARTBEAT_SEC: i32 = sched::HEARTBEAT_INTERVAL_SEC as i32;
        let lease = sqlx::query!(
            "INSERT INTO central.node_leases \
             (id, node_id, attempt_id, worker_id, issued_at, last_heartbeat_at, \
              expires_at, heartbeat_interval_seconds) \
             VALUES ($1, $2, $3, $4, now(), now(), now() + make_interval(secs => $5), $6) \
             RETURNING issued_at, last_heartbeat_at, expires_at",
            uuid_of(lease_id.as_bytes()),
            uuid_of(cand.node_id.as_bytes()),
            uuid_of(attempt_id.as_bytes()),
            uuid_of(worker_id.as_bytes()),
            sched::lease_ttl().as_seconds_f64(),
            HEARTBEAT_SEC,
        )
        .fetch_one(&mut *tx)
        .await
        .ctx("scheduler claim: insert node lease")?;

        self.append_attempt_event_tx(
            &mut tx,
            node_ws,
            cand.run_id,
            cand.node_id,
            attempt_id,
            EventKind::NodeDispatched.as_str(),
            ACTOR_SCHEDULER,
            None,
            serde_json::json!({
                "node_key": node.node_key,
                "attempt_seq": attempt_seq,
                "worker_id": worker_id.to_string(),
                "lease_id": lease_id.to_string(),
                "harness": node.harness,
                "workspace_kind": node.workspace_kind,
            }),
        )
        .await?;
        tx.commit().await.ctx("scheduler claim: commit")?;
        Ok(ClaimOutcome::Claimed(Box::new(ClaimedAttempt {
            attempt: SessionAttempt {
                id: attempt_id,
                workspace_id: node_ws,
                run_id: cand.run_id,
                node_id: cand.node_id,
                attempt_seq,
                worker_id: Some(worker_id),
                harness_attempt_id: None,
                workspace_path: None,
                workspace_kind: node.workspace_kind.clone(),
                state: AttemptState::Claimed,
                dispatch_reason_code: None,
                reservation_id: None,
                harness_session_id: None,
                claimed_at,
                started_at: None,
                ended_at: None,
            },
            lease: Lease {
                id: lease_id,
                node_id: cand.node_id,
                attempt_id,
                worker_id,
                issued_at: lease.issued_at,
                last_heartbeat_at: lease.last_heartbeat_at,
                expires_at: lease.expires_at,
                heartbeat_interval_sec: HEARTBEAT_SEC,
                released_at: None,
            },
            harness: node.harness.clone(),
        })))
    }

    /// `journalDeferralTx` — journals `admission_deferred` for a
    /// still-ready candidate inside the open claim transaction. A node
    /// whose newest journal row is already `admission_deferred` is not
    /// re-journaled (spec-8 decision 6 — the event records entry into
    /// the deferred condition, not the wait).
    async fn journal_deferral_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        cand: &ClaimCandidate,
        node_key: &str,
        worker_id: WorkerId,
        admission: &admission::Admission,
    ) -> Result<(), Failure> {
        let last = sqlx::query_scalar!(
            "SELECT kind FROM central.run_events WHERE node_id = $1 ORDER BY seq DESC LIMIT 1",
            uuid_of(cand.node_id.as_bytes()),
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("scheduler claim: read last node event")?;
        if last.as_deref() == Some(EventKind::AdmissionDeferred.as_str()) {
            return Ok(());
        }
        self.append_node_event_tx(
            tx,
            cand.workspace_id,
            cand.run_id,
            cand.node_id,
            EventKind::AdmissionDeferred.as_str(),
            ACTOR_SCHEDULER,
            admission.reason_code,
            serde_json::json!({
                "node_key": node_key,
                "worker_id": worker_id.to_string(),
                "detail": admission.detail.unwrap_or_default(),
            }),
        )
        .await
    }
}
