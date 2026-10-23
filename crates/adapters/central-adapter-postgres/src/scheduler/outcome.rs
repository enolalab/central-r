//! `PgOutcomeStore` — the b37 durable outcome ledger, timeout sweep and
//! compensation hooks (port of upstream
//! `internal/adapter/postgres/scheduler/outcome.go`).
//!
//! Upstream carries this surface on the same `Store` struct as
//! `store.rs`; here the retry-facing name is `PgOutcomeStore`, a
//! newtype over [`PgSchedulerStore`] — every method delegates to the
//! same code path so `attempt_outcomes` keeps exactly one writer.
//! [`PgSchedulerStore`] itself also implements
//! `central_retry::port::Store` for the kernel's single-`Arc` wiring
//! (upstream shares the same `*Store`).

use std::collections::BTreeMap;
use std::ops::{Deref, DerefMut};

use central_eventjournal::domain::EventKind;
use central_foundation::failure::{Failure, FailureKind};
use central_foundation::identity::{
    HarnessAttemptId, NodeLeaseId, RunId, SessionAttemptId, WorkerId, WorkflowNodeId, WorkspaceId,
};
use central_retry::domain::{
    self as retry_domain, AttemptCounts, FailureClass, OutcomeKind, ReasonCode,
};
use central_retry::port::{
    Outcome, OutcomeResult, SkippedScope, Store as RetryStore, SweepSummary,
};
use central_retry::query::{
    AttemptDecision, AttemptDecisionView, AttemptHistoryRead, AttemptOutcomeView,
};
use central_scheduler::domain::{self as sched, AttemptState};
use central_scheduler::query::SchedulerRead;
use central_workflow::domain::NodeStatus;
use sha2::Digest;
use sqlx::{Postgres, Transaction};
use time::{Duration, OffsetDateTime};

use crate::error::SqlxContext;
use crate::store_support::{PG_DATA_CORRUPT, uuid_of};

use super::store::{ACTOR_SCHEDULER, PgSchedulerStore, domain_failure};

/// `epoch` anchors the absolute-deadline form of
/// `workflow_deadline_exceeded`: `started_at = epoch` makes the
/// predicate evaluate `now >= deadline`.
const EPOCH: OffsetDateTime = OffsetDateTime::UNIX_EPOCH;

/// The attempt states a timeout bound may still act on: claimed through
/// started. `ambiguous` is deliberately absent — an unresolved ambiguous
/// attempt BLOCKS timers (locked input 3), it is never itself timed out.
const LIVE_ATTEMPT_STATES: [&str; 3] = ["claimed", "provisioning", "started"];

/// Whether `state` is still sweep-actionable (upstream
/// `isLiveAttemptState`).
fn is_live_attempt_state(state: &str) -> bool {
    LIVE_ATTEMPT_STATES.contains(&state)
}

/// The `text[]` bind form of [`LIVE_ATTEMPT_STATES`] — sqlx binds
/// `&[String]` for `text[]` parameters, not `&[&str]`.
fn live_attempt_states_bind() -> Vec<String> {
    LIVE_ATTEMPT_STATES
        .iter()
        .map(|s| (*s).to_owned())
        .collect()
}

/// Whether the run's status is already terminal (upstream
/// `runStatusTerminal`).
fn run_status_terminal(status: &str) -> bool {
    matches!(
        status,
        "succeeded" | "failed" | "failed_terminal" | "cancelled"
    )
}

/// One attempt's fully locked evaluation scope (upstream
/// `lockedOutcome`): the attempt, its node row and its run
/// serialization point are all held; `lease_id`/`worker_id` carry the
/// fencing lease when one exists — `None` on scheduler-authorized
/// sweep writes, whose authority is the sweep itself.
pub(crate) struct LockedOutcome {
    pub(crate) attempt_id: SessionAttemptId,
    pub(crate) node_id: WorkflowNodeId,
    pub(crate) run_id: RunId,
    pub(crate) workspace_id: WorkspaceId,
    pub(crate) attempt_state: AttemptState,
    pub(crate) attempt_seq: i32,
    pub(crate) node_state: NodeStatus,
    pub(crate) node_spec: serde_json::Value,
    pub(crate) node_timeout_sec: Option<i64>,
    pub(crate) node_not_before: Option<OffsetDateTime>,
    pub(crate) first_dispatch: Option<OffsetDateTime>,
    pub(crate) attempt_total: i64,
    pub(crate) lease_id: Option<central_foundation::identity::NodeLeaseId>,
    pub(crate) worker_id: Option<central_foundation::identity::WorkerId>,
}

impl LockedOutcome {
    /// `loadStatsTx` — first dispatch instant (the node-bound epoch)
    /// and the node's total attempt count under the outcome
    /// transaction's locks.
    async fn load_stats_tx(&mut self, tx: &mut Transaction<'_, Postgres>) -> Result<(), Failure> {
        let row = sqlx::query!(
            "SELECT MIN(claimed_at) AS first_dispatch, COUNT(*) AS total \
             FROM central.session_attempts WHERE node_id = $1",
            uuid_of(self.node_id.as_bytes()),
        )
        .fetch_one(&mut **tx)
        .await
        .ctx("scheduler outcome: count node attempts")?;
        self.first_dispatch = row.first_dispatch;
        self.attempt_total = row.total.unwrap_or(0);
        Ok(())
    }

    /// `nodeBoundExpired` — the spec-4 decision-5 node aggregate bound:
    /// first dispatch plus `node_timeout_seconds` elapsed at `eval_now`.
    /// A NULL `node_timeout_seconds` declares no bound — the predicate
    /// must not fire on a zero duration.
    fn node_bound_expired(&self, eval_now: OffsetDateTime) -> bool {
        self.node_timeout_sec.is_some()
            && retry_domain::node_deadline_exceeded(
                self.first_dispatch,
                self.node_timeout_sec
                    .map(Duration::seconds)
                    .unwrap_or(Duration::ZERO),
                eval_now,
            )
    }
}

/// The deterministic fingerprint the internal close paths
/// (`fail_dispatch`, ceiling breaches, sweep closes) use when no
/// caller-supplied payload exists: SHA-256 over the command name, the
/// attempt key, the kind and the reason (upstream
/// `derivedOutcomeFingerprint`). Identical replays hash identically and
/// dedupe; a same-key report under a different reason conflicts.
pub(crate) fn derived_outcome_fingerprint(
    attempt_id: SessionAttemptId,
    kind: OutcomeKind,
    reason_code: &str,
) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(
        format!(
            "central/record-outcome|{attempt_id}|{}|{reason_code}",
            kind.as_str()
        )
        .as_bytes(),
    );
    hasher.finalize().into()
}

/// Whether `err` is the spec-5 replay conflict — a recorded outcome
/// under the same key with a different fingerprint (upstream
/// `isOutcomeConflict`). A sweep-derived close treats it as "the close
/// already stands".
fn is_outcome_conflict(err: &Failure) -> bool {
    err.kind() == FailureKind::Conflict
        && err.code() == ReasonCode::DuplicateIdempotencyKey.as_str()
}

/// Whether `err` is the fence rejection — `DENIED`/`LEASE_FENCE_STALE`.
fn is_fence_stale(err: &Failure) -> bool {
    err.kind() == FailureKind::Denied && err.code() == sched::REASON_LEASE_FENCE_STALE
}

/// The reason_code persisted on the ledger row: a `failed` report
/// carries its spec-4 code; `succeeded`/`cancelled` carry their
/// declared reason or fall back to the kind itself so the NOT NULL
/// column never stores "".
fn outcome_ledger_reason(outcome: &Outcome) -> String {
    if outcome.reason_code.is_empty() {
        outcome.kind.as_str().to_owned()
    } else {
        outcome.reason_code.clone()
    }
}

/// The failure_class persisted on the ledger row: `classify`'s verdict
/// for `failed`, `"none"` for the non-failure kinds — the taxonomy
/// classes describe failures, and success/cancel have none (upstream
/// `outcomeFailureClass` returns `retry.FailureClass("none")` — a
/// non-enumerated class text; the Rust port keeps the text out of the
/// [`FailureClass`] enum and carries it as the ledger string).
fn outcome_failure_class_text(outcome: &Outcome) -> String {
    if outcome.kind != OutcomeKind::Failed {
        return "none".to_owned();
    }
    retry_domain::classify(&outcome.reason_code)
        .as_str()
        .to_owned()
}

/// Maps a ledger outcome kind to the terminal attempt state it closes
/// the attempt into (upstream `outcomeAttemptState`).
fn outcome_attempt_state(kind: OutcomeKind) -> AttemptState {
    match kind {
        OutcomeKind::Succeeded => AttemptState::Succeeded,
        OutcomeKind::Cancelled => AttemptState::Cancelled,
        OutcomeKind::Failed => AttemptState::Failed,
    }
}

/// The shared event-payload base (upstream `outcomeEventPayload`):
/// `attempt_seq` always; `worker_id`/`lease_id` when the close ran
/// under a fencing lease (or a sweep close of an attempt that had one).
fn outcome_event_payload(o: &LockedOutcome, extra: serde_json::Value) -> serde_json::Value {
    let mut payload = serde_json::json!({"attempt_seq": o.attempt_seq});
    if let Some(worker_id) = o.worker_id {
        payload["worker_id"] = serde_json::json!(worker_id.to_string());
    }
    if let Some(lease_id) = o.lease_id {
        payload["lease_id"] = serde_json::json!(lease_id.to_string());
    }
    if let Some(map) = extra.as_object() {
        for (k, v) in map {
            payload[k.clone()] = v.clone();
        }
    }
    payload
}

/// A managed hook claimed inside the landing transaction (upstream
/// `pendingCompensation`): the request row committed; the executor call
/// runs after commit; the result journals as a second
/// `compensation_requested` row.
struct PendingCompensation {
    node_id: WorkflowNodeId,
    run_id: RunId,
    workspace_id: WorkspaceId,
    hook: String,
    kind: retry_domain::CompensationKind,
}

impl PgSchedulerStore {
    /// `recordOutcomeTx` — ledger row, attempt close, live-lease
    /// release, attempt-scope event: in that order, so a duplicate-key
    /// conflict surfaces before any transition. Returns `Ok(true)` when
    /// the row already exists under the same fingerprint (dedupe:
    /// `command_deduped` journals).
    async fn record_outcome_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        o: &mut LockedOutcome,
        outcome: &Outcome,
    ) -> Result<bool, Failure> {
        let stored = sqlx::query!(
            "SELECT reason_code, failure_class, payload_fingerprint \
             FROM central.attempt_outcomes \
             WHERE attempt_id = $1 AND outcome_kind = $2",
            uuid_of(o.attempt_id.as_bytes()),
            outcome.kind.as_str(),
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("scheduler outcome: read ledger")?;
        if let Some(stored) = stored {
            if stored.payload_fingerprint.as_slice() != outcome.fingerprint.as_slice() {
                return Err(domain_failure(
                    sched::FailureClass::Conflict,
                    ReasonCode::DuplicateIdempotencyKey.as_str(),
                    format!(
                        "attempt {} outcome {:?} recorded under a different payload fingerprint",
                        o.attempt_id,
                        outcome.kind.as_str()
                    ),
                ));
            }
            self.append_node_event_tx(
                tx,
                o.workspace_id,
                o.run_id,
                o.node_id,
                EventKind::CommandDeduped.as_str(),
                ACTOR_SCHEDULER,
                None,
                serde_json::json!({
                    "command": "record_outcome",
                    "outcome_kind": outcome.kind.as_str(),
                }),
            )
            .await?;
            return Ok(true);
        }

        let to = outcome_attempt_state(outcome.kind);
        if !o.attempt_state.can_transition(to) {
            return Err(domain_failure(
                sched::FailureClass::Denied,
                sched::REASON_INVALID_ATTEMPT_TRANSITION,
                format!(
                    "attempt state {} admits no {} outcome",
                    o.attempt_state.as_str(),
                    outcome.kind.as_str()
                ),
            ));
        }

        let reason = outcome_ledger_reason(outcome);
        let class_text = outcome_failure_class_text(outcome);
        sqlx::query!(
            "INSERT INTO central.attempt_outcomes \
             (attempt_id, outcome_kind, reason_code, failure_class, payload_fingerprint) \
             VALUES ($1, $2, $3, $4, $5)",
            uuid_of(o.attempt_id.as_bytes()),
            outcome.kind.as_str(),
            reason,
            class_text,
            &outcome.fingerprint[..],
        )
        .execute(&mut **tx)
        .await
        .ctx("scheduler outcome: insert ledger row")?;

        if outcome.kind == OutcomeKind::Succeeded {
            sqlx::query!(
                "UPDATE central.session_attempts \
                 SET state = $2, ended_at = now(), outcome_fingerprint = $3 \
                 WHERE id = $1",
                uuid_of(o.attempt_id.as_bytes()),
                to.as_str(),
                &outcome.fingerprint[..],
            )
            .execute(&mut **tx)
            .await
            .ctx("scheduler outcome: close attempt")?;
        } else {
            sqlx::query!(
                "UPDATE central.session_attempts \
                 SET state = $2, ended_at = now(), dispatch_reason_code = $3, \
                     outcome_fingerprint = $4 \
                 WHERE id = $1",
                uuid_of(o.attempt_id.as_bytes()),
                to.as_str(),
                reason,
                &outcome.fingerprint[..],
            )
            .execute(&mut **tx)
            .await
            .ctx("scheduler outcome: close attempt")?;
        }
        o.attempt_state = to;

        // The live-lease release is part of every outcome close —
        // required, or the live-lease partial index wedges the node's
        // next claim.
        sqlx::query!(
            "UPDATE central.node_leases SET released_at = now() \
             WHERE attempt_id = $1 AND released_at IS NULL",
            uuid_of(o.attempt_id.as_bytes()),
        )
        .execute(&mut **tx)
        .await
        .ctx("scheduler outcome: release lease")?;

        match outcome.kind {
            OutcomeKind::Succeeded => {
                self.append_attempt_event_tx(
                    tx,
                    o.workspace_id,
                    o.run_id,
                    o.node_id,
                    o.attempt_id,
                    EventKind::AttemptSucceeded.as_str(),
                    ACTOR_SCHEDULER,
                    None,
                    outcome_event_payload(o, serde_json::json!({})),
                )
                .await?;
            }
            OutcomeKind::Failed => {
                self.append_attempt_event_tx(
                    tx,
                    o.workspace_id,
                    o.run_id,
                    o.node_id,
                    o.attempt_id,
                    EventKind::AttemptFailed.as_str(),
                    ACTOR_SCHEDULER,
                    Some(&reason),
                    outcome_event_payload(o, serde_json::json!({})),
                )
                .await?;
            }
            // 'cancelled' has no attempt-scope kind in the catalog.
            OutcomeKind::Cancelled => {}
        }
        Ok(false)
    }

    /// `transitionNodeTx` — moves the locked node, stamping the
    /// lifecycle columns the state carries: `ready_at` on every
    /// →`ready`, `not_before` on a scheduled retry (cleared on any
    /// other landing).
    async fn transition_node_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        o: &mut LockedOutcome,
        to: NodeStatus,
        not_before: Option<OffsetDateTime>,
    ) -> Result<(), Failure> {
        if to == NodeStatus::Ready {
            sqlx::query!(
                "UPDATE central.workflow_nodes \
                 SET state = $2, ready_at = now(), not_before = $3 WHERE id = $1",
                uuid_of(o.node_id.as_bytes()),
                to.as_str(),
                not_before,
            )
            .execute(&mut **tx)
            .await
            .ctx("scheduler outcome: node transition")?;
        } else {
            sqlx::query!(
                "UPDATE central.workflow_nodes \
                 SET state = $2, not_before = NULL WHERE id = $1",
                uuid_of(o.node_id.as_bytes()),
                to.as_str(),
            )
            .execute(&mut **tx)
            .await
            .ctx("scheduler outcome: node transition")?;
        }
        o.node_state = to;
        o.node_not_before = not_before;
        Ok(())
    }

    /// `landNodeFailedTerminalTx` — lands the locked node
    /// `failed_terminal`, journals `node_failed_terminal` carrying the
    /// reason and the failing attempt, and evaluates the spec's
    /// `on_terminal_failure` hook for post-commit execution. A node
    /// already terminal or without a legal edge keeps its state and
    /// evaluates no compensation.
    async fn land_node_failed_terminal_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        o: &mut LockedOutcome,
        reason_code: &str,
        detail: &str,
    ) -> Result<Option<PendingCompensation>, Failure> {
        let from = o.node_state;
        if !from.can_transition(NodeStatus::FailedTerminal) {
            return Ok(None);
        }
        self.transition_node_tx(tx, o, NodeStatus::FailedTerminal, None)
            .await?;
        let mut payload = serde_json::json!({
            "from": from.as_str(),
            "to": NodeStatus::FailedTerminal.as_str(),
            "detail": detail,
        });
        if let Some(map) = outcome_event_payload(o, serde_json::json!(null)).as_object() {
            for (k, v) in map {
                payload[k.clone()] = v.clone();
            }
        }
        self.append_node_event_tx(
            tx,
            o.workspace_id,
            o.run_id,
            o.node_id,
            EventKind::NodeFailedTerminal.as_str(),
            ACTOR_SCHEDULER,
            Some(reason_code),
            payload,
        )
        .await?;
        self.evaluate_compensation_tx(tx, o).await
    }

    /// `decideAfterFailureTx` — spec-4 decisions 1–5 inside the outcome
    /// transaction: the node bound dominates (`NODE_TIMEOUT`),
    /// non-retryable classes and exhausted budgets land
    /// `failed_terminal`, and a retryable failure inside budget returns
    /// the node to `ready` under `compute_delay`'s journaled
    /// `retry_at`. Returns `(pending, node_status, retry_at)`.
    async fn decide_after_failure_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        o: &mut LockedOutcome,
        outcome: &Outcome,
        eval_now: OffsetDateTime,
    ) -> Result<(Option<PendingCompensation>, String, Option<OffsetDateTime>), Failure> {
        let class = retry_domain::classify(&outcome.reason_code);
        let node_from = o.node_state;

        // The node aggregate bound dominates every other decision.
        if o.node_bound_expired(eval_now) {
            let p = self
                .land_node_failed_terminal_tx(
                    tx,
                    o,
                    ReasonCode::NodeTimeout.as_str(),
                    "node_timeout_seconds bound elapsed",
                )
                .await?;
            return Ok((p, o.node_state.as_str().to_owned(), None));
        }
        if !class.retryable() {
            let p = self
                .land_node_failed_terminal_tx(
                    tx,
                    o,
                    &outcome.reason_code,
                    &format!("failure class {} is not retryable", class.as_str()),
                )
                .await?;
            return Ok((p, o.node_state.as_str().to_owned(), None));
        }

        let per_class = Self::per_class_counts_tx(tx, o.node_id).await?;
        let policy = self.retry_policy_for(&o.node_spec);
        let counts = AttemptCounts {
            per_class,
            total: u32::try_from(o.attempt_total).unwrap_or(u32::MAX),
        };
        if let Some(bound) = retry_domain::budget_remaining(&policy, &counts, class) {
            let p = self
                .land_node_failed_terminal_tx(
                    tx,
                    o,
                    ReasonCode::RetryBudgetExhausted.as_str(),
                    &format!("exhausted_by={}", bound.as_str()),
                )
                .await?;
            return Ok((p, o.node_state.as_str().to_owned(), None));
        }

        // Retryable inside budget: the node returns to 'ready' under
        // not_before = the journaled retry_at. A node already terminal
        // keeps its state — the attempt close and ledger row still
        // committed.
        if !node_from.can_transition(NodeStatus::Ready) {
            return Ok((None, o.node_state.as_str().to_owned(), None));
        }
        let retry_after = (outcome.reason_code == ReasonCode::RateLimited.as_str())
            .then_some(outcome.retry_after)
            .flatten();
        let mut draw = || self.jitter_draw();
        let delay = retry_domain::compute_delay(
            &policy,
            class,
            u32::try_from(o.attempt_seq).unwrap_or(1).max(1),
            retry_after,
            Some(&mut draw),
        );
        let retry_at = eval_now + delay;
        self.transition_node_tx(tx, o, NodeStatus::Ready, Some(retry_at))
            .await?;
        self.append_node_event_tx(
            tx,
            o.workspace_id,
            o.run_id,
            o.node_id,
            EventKind::NodeReady.as_str(),
            ACTOR_SCHEDULER,
            Some(&outcome.reason_code),
            outcome_event_payload(o, serde_json::json!({"retry_at": retry_at})),
        )
        .await?;
        self.append_attempt_event_tx(
            tx,
            o.workspace_id,
            o.run_id,
            o.node_id,
            o.attempt_id,
            EventKind::AttemptRetryScheduled.as_str(),
            ACTOR_SCHEDULER,
            Some(&outcome.reason_code),
            outcome_event_payload(
                o,
                serde_json::json!({
                    "retry_at": retry_at,
                    "next_attempt_seq": o.attempt_seq + 1,
                    "failure_class": class.as_str(),
                }),
            ),
        )
        .await?;
        Ok((None, NodeStatus::Ready.as_str().to_owned(), Some(retry_at)))
    }

    /// `applyOutcomeTx` — the in-transaction outcome application shared
    /// by the fenced `record_outcome` path and the scheduler-authorized
    /// sweep closes: ledger row and attempt close first, then the node
    /// decision.
    async fn apply_outcome_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        o: &mut LockedOutcome,
        outcome: &Outcome,
        eval_now: OffsetDateTime,
    ) -> Result<(OutcomeResult, Option<PendingCompensation>), Failure> {
        let deduped = self.record_outcome_tx(tx, o, outcome).await?;
        if deduped {
            return Ok((
                OutcomeResult {
                    deduped: true,
                    class: outcome_failure_class(outcome),
                    node_status: o.node_state.as_str().to_owned(),
                    retry_at: o.node_not_before,
                },
                None,
            ));
        }

        let mut res = OutcomeResult {
            deduped: false,
            class: outcome_failure_class(outcome),
            node_status: o.node_state.as_str().to_owned(),
            retry_at: None,
        };
        match outcome.kind {
            OutcomeKind::Succeeded => {
                if o.node_state.can_transition(NodeStatus::Succeeded) {
                    self.transition_node_tx(tx, o, NodeStatus::Succeeded, None)
                        .await?;
                    res.node_status = NodeStatus::Succeeded.as_str().to_owned();
                    self.append_node_event_tx(
                        tx,
                        o.workspace_id,
                        o.run_id,
                        o.node_id,
                        EventKind::NodeSucceeded.as_str(),
                        ACTOR_SCHEDULER,
                        None,
                        outcome_event_payload(o, serde_json::json!({})),
                    )
                    .await?;
                }
            }
            OutcomeKind::Cancelled => {
                let reason = outcome_ledger_reason(outcome);
                if o.node_state.can_transition(NodeStatus::Cancelled) {
                    let from = o.node_state;
                    self.transition_node_tx(tx, o, NodeStatus::Cancelled, None)
                        .await?;
                    res.node_status = NodeStatus::Cancelled.as_str().to_owned();
                    self.append_node_event_tx(
                        tx,
                        o.workspace_id,
                        o.run_id,
                        o.node_id,
                        EventKind::NodeCancelled.as_str(),
                        ACTOR_SCHEDULER,
                        Some(&reason),
                        outcome_event_payload(
                            o,
                            serde_json::json!({
                                "from": from.as_str(),
                                "to": NodeStatus::Cancelled.as_str(),
                            }),
                        ),
                    )
                    .await?;
                }
            }
            OutcomeKind::Failed => {
                let (p, status, retry_at) = self
                    .decide_after_failure_tx(tx, o, outcome, eval_now)
                    .await?;
                res.node_status = status;
                res.retry_at = retry_at;
                return Ok((res, p));
            }
        }
        Ok((res, None))
    }

    /// `resolveOutcomeReplayTx` — a fenced report whose lease rejected:
    /// re-read under the run-row serialization point. A committed
    /// ledger row dedupes (same fingerprint) or conflicts (different
    /// fingerprint); no row means the outcome genuinely never recorded
    /// and the fence verdict stands — fail-closed.
    async fn resolve_outcome_replay_tx(&self, outcome: &Outcome) -> Result<OutcomeResult, Failure> {
        let mut tx = self.begin().await?;
        // Read the attempt unlocked only to learn its run/node; the
        // locks then land in the store's order.
        let row = sqlx::query!(
            "SELECT node_id, run_id, workspace_id FROM central.session_attempts WHERE id = $1",
            uuid_of(outcome.attempt_id.as_bytes()),
        )
        .fetch_optional(&mut *tx)
        .await
        .ctx("scheduler outcome replay: read attempt")?;
        let Some(row) = row else {
            return Err(domain_failure(
                sched::FailureClass::Denied,
                sched::REASON_LEASE_FENCE_STALE,
                "the attempt does not exist",
            ));
        };
        let mut o = LockedOutcome {
            attempt_id: outcome.attempt_id,
            node_id: WorkflowNodeId::from_trusted_db_bytes(*row.node_id.as_bytes()),
            run_id: RunId::from_trusted_db_bytes(*row.run_id.as_bytes()),
            workspace_id: WorkspaceId::from_trusted_db_bytes(*row.workspace_id.as_bytes()),
            attempt_state: AttemptState::Claimed, // replaced by the locked read below
            attempt_seq: 0,
            node_state: NodeStatus::Declared,
            node_spec: serde_json::Value::Null,
            node_timeout_sec: None,
            node_not_before: None,
            first_dispatch: None,
            attempt_total: 0,
            lease_id: None,
            worker_id: None,
        };
        sqlx::query_scalar!(
            "SELECT id FROM central.runs WHERE id = $1 FOR UPDATE",
            uuid_of(o.run_id.as_bytes()),
        )
        .fetch_one(&mut *tx)
        .await
        .ctx("scheduler outcome replay: lock run row")?;
        let node = sqlx::query!(
            "SELECT state, spec, node_timeout_seconds, not_before \
             FROM central.workflow_nodes WHERE id = $1 FOR UPDATE",
            uuid_of(o.node_id.as_bytes()),
        )
        .fetch_one(&mut *tx)
        .await
        .ctx("scheduler outcome replay: lock node row")?;
        o.node_state = NodeStatus::parse(&node.state).ok_or_else(|| {
            Failure::internal(
                PG_DATA_CORRUPT,
                "a stored node state is outside the vocabulary",
            )
        })?;
        o.node_spec = node.spec;
        o.node_timeout_sec = node.node_timeout_seconds;
        o.node_not_before = node.not_before;
        let attempt = sqlx::query!(
            "SELECT state, attempt_seq, worker_id \
             FROM central.session_attempts WHERE id = $1 FOR UPDATE",
            uuid_of(outcome.attempt_id.as_bytes()),
        )
        .fetch_one(&mut *tx)
        .await
        .ctx("scheduler outcome replay: lock attempt row")?;
        o.attempt_state = AttemptState::parse(&attempt.state).ok_or_else(|| {
            Failure::internal(
                PG_DATA_CORRUPT,
                "a stored attempt state is outside the vocabulary",
            )
        })?;
        o.attempt_seq = attempt.attempt_seq;
        o.worker_id = attempt.worker_id.map(|id| {
            central_foundation::identity::WorkerId::from_trusted_db_bytes(*id.as_bytes())
        });

        let stored = sqlx::query!(
            "SELECT failure_class, payload_fingerprint \
             FROM central.attempt_outcomes \
             WHERE attempt_id = $1 AND outcome_kind = $2",
            uuid_of(outcome.attempt_id.as_bytes()),
            outcome.kind.as_str(),
        )
        .fetch_optional(&mut *tx)
        .await
        .ctx("scheduler outcome replay: read ledger")?;
        let Some(stored) = stored else {
            return Err(domain_failure(
                sched::FailureClass::Denied,
                sched::REASON_LEASE_FENCE_STALE,
                "the outcome was never recorded; the lease is fencing-dead",
            ));
        };
        if stored.payload_fingerprint.as_slice() != outcome.fingerprint.as_slice() {
            return Err(domain_failure(
                sched::FailureClass::Conflict,
                ReasonCode::DuplicateIdempotencyKey.as_str(),
                "the outcome recorded under a different payload fingerprint",
            ));
        }
        self.append_node_event_tx(
            &mut tx,
            o.workspace_id,
            o.run_id,
            o.node_id,
            EventKind::CommandDeduped.as_str(),
            ACTOR_SCHEDULER,
            None,
            serde_json::json!({
                "command": "record_outcome",
                "outcome_kind": outcome.kind.as_str(),
            }),
        )
        .await?;
        tx.commit().await.ctx("scheduler outcome replay: commit")?;
        Ok(OutcomeResult {
            deduped: true,
            class: FailureClass::parse(&stored.failure_class).unwrap_or(FailureClass::Terminal),
            node_status: o.node_state.as_str().to_owned(),
            retry_at: o.node_not_before,
        })
    }

    /// `perClassCountsTx` — the node's recorded `failed` outcomes
    /// grouped by `failure_class` (the `budget_remaining` per-class
    /// input). Unknown persisted class texts are skipped — they cannot
    /// match a classify() output anyway.
    async fn per_class_counts_tx(
        tx: &mut Transaction<'_, Postgres>,
        node_id: WorkflowNodeId,
    ) -> Result<BTreeMap<FailureClass, u32>, Failure> {
        let rows = sqlx::query!(
            "SELECT o.failure_class, COUNT(*) AS n \
             FROM central.attempt_outcomes o \
             JOIN central.session_attempts a ON a.id = o.attempt_id \
             WHERE a.node_id = $1 AND o.outcome_kind = 'failed' \
             GROUP BY o.failure_class",
            uuid_of(node_id.as_bytes()),
        )
        .fetch_all(&mut **tx)
        .await
        .ctx("scheduler outcome: count by class")?;
        let mut out = BTreeMap::new();
        for row in rows {
            if let Some(class) = FailureClass::parse(&row.failure_class) {
                out.insert(class, u32::try_from(row.n.unwrap_or(0)).unwrap_or(u32::MAX));
            }
        }
        Ok(out)
    }

    /// `lockLiveAttemptTx` — an attempt under the run → node → attempt
    /// lock order the sweep uses. Scheduler-authorized writes do not
    /// require the live lease — that fence fences stale workers, and a
    /// timed-out attempt's lease is exactly what may be dead.
    /// `Ok(None)` means no such attempt row.
    async fn lock_live_attempt_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        attempt_id: SessionAttemptId,
    ) -> Result<Option<LockedOutcome>, Failure> {
        let row = sqlx::query!(
            "SELECT node_id, run_id, workspace_id, state, attempt_seq, worker_id \
             FROM central.session_attempts WHERE id = $1",
            uuid_of(attempt_id.as_bytes()),
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("scheduler sweep: read attempt")?;
        let Some(row) = row else {
            return Ok(None);
        };
        let mut o = LockedOutcome {
            attempt_id,
            node_id: WorkflowNodeId::from_trusted_db_bytes(*row.node_id.as_bytes()),
            run_id: RunId::from_trusted_db_bytes(*row.run_id.as_bytes()),
            workspace_id: WorkspaceId::from_trusted_db_bytes(*row.workspace_id.as_bytes()),
            attempt_state: AttemptState::parse(&row.state).ok_or_else(|| {
                Failure::internal(
                    PG_DATA_CORRUPT,
                    "a stored attempt state is outside the vocabulary",
                )
            })?,
            attempt_seq: row.attempt_seq,
            node_state: NodeStatus::Declared,
            node_spec: serde_json::Value::Null,
            node_timeout_sec: None,
            node_not_before: None,
            first_dispatch: None,
            attempt_total: 0,
            lease_id: None,
            worker_id: row.worker_id.map(|id| {
                central_foundation::identity::WorkerId::from_trusted_db_bytes(*id.as_bytes())
            }),
        };
        sqlx::query_scalar!(
            "SELECT id FROM central.runs WHERE id = $1 FOR UPDATE",
            uuid_of(o.run_id.as_bytes()),
        )
        .fetch_one(&mut **tx)
        .await
        .ctx("scheduler sweep: lock run row")?;
        let node = sqlx::query!(
            "SELECT state, spec, node_timeout_seconds, not_before \
             FROM central.workflow_nodes WHERE id = $1 FOR UPDATE",
            uuid_of(o.node_id.as_bytes()),
        )
        .fetch_one(&mut **tx)
        .await
        .ctx("scheduler sweep: lock node row")?;
        o.node_state = NodeStatus::parse(&node.state).ok_or_else(|| {
            Failure::internal(
                PG_DATA_CORRUPT,
                "a stored node state is outside the vocabulary",
            )
        })?;
        o.node_spec = node.spec;
        o.node_timeout_sec = node.node_timeout_seconds;
        o.node_not_before = node.not_before;
        let locked = sqlx::query!(
            "SELECT state, worker_id FROM central.session_attempts WHERE id = $1 FOR UPDATE",
            uuid_of(attempt_id.as_bytes()),
        )
        .fetch_one(&mut **tx)
        .await
        .ctx("scheduler sweep: lock attempt row")?;
        o.attempt_state = AttemptState::parse(&locked.state).ok_or_else(|| {
            Failure::internal(
                PG_DATA_CORRUPT,
                "a stored attempt state is outside the vocabulary",
            )
        })?;
        o.worker_id = locked.worker_id.map(|id| {
            central_foundation::identity::WorkerId::from_trusted_db_bytes(*id.as_bytes())
        });
        Ok(Some(o))
    }

    /// `findLiveAttemptTx` — the node's highest-seq live attempt, if
    /// any.
    async fn find_live_attempt_tx(
        tx: &mut Transaction<'_, Postgres>,
        node_id: WorkflowNodeId,
    ) -> Result<Option<SessionAttemptId>, Failure> {
        let live_states = live_attempt_states_bind();
        let row = sqlx::query_scalar!(
            "SELECT a.id FROM central.session_attempts a \
             WHERE a.node_id = $1 AND a.state = ANY($2) \
             ORDER BY a.attempt_seq DESC LIMIT 1",
            uuid_of(node_id.as_bytes()),
            live_states.as_slice(),
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("scheduler sweep: find live attempt")?;
        Ok(row.map(|id| SessionAttemptId::from_trusted_db_bytes(*id.as_bytes())))
    }

    /// `existsUnresolvedAmbiguousTx` over the attempt's node — locked
    /// input 3's timer blocker at node scope.
    async fn node_has_unresolved_ambiguous_tx(
        tx: &mut Transaction<'_, Postgres>,
        node_id: WorkflowNodeId,
    ) -> Result<bool, Failure> {
        let exists = sqlx::query_scalar!(
            "SELECT EXISTS(SELECT 1 FROM central.session_attempts a \
              WHERE a.node_id = $1 AND a.state = 'ambiguous' \
                AND NOT EXISTS (SELECT 1 FROM central.attempt_decisions d \
                                WHERE d.attempt_id = a.id))",
            uuid_of(node_id.as_bytes()),
        )
        .fetch_one(&mut **tx)
        .await
        .ctx("scheduler sweep: ambiguous check")?;
        Ok(exists.unwrap_or(false))
    }

    /// The same blocker at run scope (`a.run_id = $1`).
    async fn run_has_unresolved_ambiguous_tx(
        tx: &mut Transaction<'_, Postgres>,
        run_id: RunId,
    ) -> Result<bool, Failure> {
        let exists = sqlx::query_scalar!(
            "SELECT EXISTS(SELECT 1 FROM central.session_attempts a \
              WHERE a.run_id = $1 AND a.state = 'ambiguous' \
                AND NOT EXISTS (SELECT 1 FROM central.attempt_decisions d \
                                WHERE d.attempt_id = a.id))",
            uuid_of(run_id.as_bytes()),
        )
        .fetch_one(&mut **tx)
        .await
        .ctx("scheduler sweep: ambiguous check")?;
        Ok(exists.unwrap_or(false))
    }

    /// `killAttempt` — the injected Killer; a `None` killer is
    /// fail-closed (every kill evaluates unconfirmed).
    async fn kill_attempt(&self, attempt_id: SessionAttemptId) -> Result<bool, Failure> {
        match &self.killer {
            None => Ok(false),
            Some(killer) => killer.kill(attempt_id).await,
        }
    }

    /// `parkAttemptAmbiguousTx` — the sweep's ambiguous landing:
    /// attempt `ambiguous` + reason, lease released, node
    /// `attempt_ambiguous`, `attempt_ambiguous` journaled.
    async fn park_attempt_ambiguous_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        o: &mut LockedOutcome,
        reason_code: &str,
    ) -> Result<(), Failure> {
        if !o.attempt_state.can_transition(AttemptState::Ambiguous) {
            return Err(domain_failure(
                sched::FailureClass::Denied,
                sched::REASON_INVALID_ATTEMPT_TRANSITION,
                format!(
                    "attempt state {} admits no ambiguous park",
                    o.attempt_state.as_str()
                ),
            ));
        }
        sqlx::query!(
            "UPDATE central.session_attempts \
             SET state = 'ambiguous', dispatch_reason_code = $2 WHERE id = $1",
            uuid_of(o.attempt_id.as_bytes()),
            reason_code,
        )
        .execute(&mut **tx)
        .await
        .ctx("scheduler sweep: park attempt")?;
        o.attempt_state = AttemptState::Ambiguous;
        sqlx::query!(
            "UPDATE central.node_leases SET released_at = now() \
             WHERE attempt_id = $1 AND released_at IS NULL",
            uuid_of(o.attempt_id.as_bytes()),
        )
        .execute(&mut **tx)
        .await
        .ctx("scheduler sweep: release lease")?;
        if o.node_state.can_transition(NodeStatus::AttemptAmbiguous) {
            self.transition_node_tx(tx, o, NodeStatus::AttemptAmbiguous, None)
                .await?;
        }
        self.append_attempt_event_tx(
            tx,
            o.workspace_id,
            o.run_id,
            o.node_id,
            o.attempt_id,
            EventKind::AttemptAmbiguous.as_str(),
            ACTOR_SCHEDULER,
            Some(reason_code),
            outcome_event_payload(o, serde_json::json!({})),
        )
        .await?;
        Ok(())
    }

    /// `closeCancelledTx` — the attempt's definite `cancelled` outcome
    /// (ledger row + attempt close + lease release) plus the node
    /// cancel — the run-timeout cascade's per-attempt landing.
    async fn close_cancelled_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        o: &mut LockedOutcome,
        reason_code: &str,
    ) -> Result<(), Failure> {
        let outcome = Outcome {
            attempt_id: o.attempt_id,
            kind: OutcomeKind::Cancelled,
            reason_code: reason_code.to_owned(),
            fingerprint: derived_outcome_fingerprint(
                o.attempt_id,
                OutcomeKind::Cancelled,
                reason_code,
            ),
            retry_after: None,
        };
        if let Err(err) = self.record_outcome_tx(tx, o, &outcome).await {
            // A same-key conflict means another committer already
            // recorded the close; it stands and the node cancel still
            // owes its journal row.
            if !is_outcome_conflict(&err) {
                return Err(err);
            }
        }
        if o.node_state.can_transition(NodeStatus::Cancelled) {
            let from = o.node_state;
            self.transition_node_tx(tx, o, NodeStatus::Cancelled, None)
                .await?;
            self.append_node_event_tx(
                tx,
                o.workspace_id,
                o.run_id,
                o.node_id,
                EventKind::NodeCancelled.as_str(),
                ACTOR_SCHEDULER,
                Some(reason_code),
                outcome_event_payload(
                    o,
                    serde_json::json!({
                        "from": from.as_str(),
                        "to": NodeStatus::Cancelled.as_str(),
                    }),
                ),
            )
            .await?;
        }
        Ok(())
    }

    /// `sweepSessionBreachTx` — closes one started attempt whose
    /// wall-clock ceiling passed: a confirmed kill lands the definite
    /// `SESSION_WALL_CLOCK_REACHED` failure through the normal retry
    /// decision; an unconfirmed kill parks ambiguous. `skipped` reports
    /// an unresolved ambiguous descendant blocked the timer.
    async fn sweep_session_breach_tx(
        &self,
        attempt_id: SessionAttemptId,
        now: OffsetDateTime,
    ) -> Result<bool, Failure> {
        let mut tx = self.begin().await?;
        let Some(mut o) = self.lock_live_attempt_tx(&mut tx, attempt_id).await? else {
            tx.commit()
                .await
                .ctx("scheduler sweep: commit session breach")?;
            return Ok(false);
        };
        if o.attempt_state != AttemptState::Started {
            tx.commit()
                .await
                .ctx("scheduler sweep: commit session breach")?;
            return Ok(false);
        }
        o.load_stats_tx(&mut tx).await?;
        // The node bound dominates: a session breach on a node whose
        // own bound already fired is the node pass's job.
        if o.node_bound_expired(now) {
            tx.commit()
                .await
                .ctx("scheduler sweep: commit session breach")?;
            return Ok(false);
        }
        if Self::node_has_unresolved_ambiguous_tx(&mut tx, o.node_id).await? {
            tx.commit()
                .await
                .ctx("scheduler sweep: commit session breach")?;
            return Ok(true);
        }

        let confirmed = self.kill_attempt(attempt_id).await?;
        if !confirmed {
            self.park_attempt_ambiguous_tx(
                &mut tx,
                &mut o,
                sched::REASON_ATTEMPT_AMBIGUOUS_KILL_UNCONFIRMED,
            )
            .await?;
            tx.commit()
                .await
                .ctx("scheduler sweep: commit session breach")?;
            // The park just created an unresolved ambiguous descendant —
            // the node's timers are blocked until an operator decides,
            // which is exactly what skipped_ambiguous reports.
            return Ok(true);
        }
        let outcome = Outcome {
            attempt_id,
            kind: OutcomeKind::Failed,
            reason_code: ReasonCode::SessionWallClockReached.as_str().to_owned(),
            fingerprint: derived_outcome_fingerprint(
                attempt_id,
                OutcomeKind::Failed,
                ReasonCode::SessionWallClockReached.as_str(),
            ),
            retry_after: None,
        };
        // A same-key conflict means a concurrent commit already
        // recorded this attempt's 'failed' outcome — the close stands.
        let apply = self.apply_outcome_tx(&mut tx, &mut o, &outcome, now).await;
        let pending = match apply {
            Ok((_, pending)) => pending,
            Err(err) if is_outcome_conflict(&err) => None,
            Err(err) => return Err(err),
        };
        tx.commit()
            .await
            .ctx("scheduler sweep: commit session breach")?;
        if let Some(pending) = pending {
            self.execute_compensation(&pending).await?;
        }
        Ok(false)
    }

    /// `sweepNodeTimeoutTx` — lands one node whose aggregate bound
    /// expired: `failed_terminal`/`NODE_TIMEOUT` regardless of
    /// remaining retry budget. A live attempt underneath is cancelled
    /// outright when it never started (claimed) or killed first
    /// (provisioning/started).
    async fn sweep_node_timeout_tx(
        &self,
        node_id: WorkflowNodeId,
        now: OffsetDateTime,
    ) -> Result<(bool, bool), Failure> {
        let mut tx = self.begin().await?;
        let row = sqlx::query!(
            "SELECT run_id, workspace_id FROM central.workflow_nodes WHERE id = $1",
            uuid_of(node_id.as_bytes()),
        )
        .fetch_optional(&mut *tx)
        .await
        .ctx("scheduler sweep: read node")?;
        let Some(row) = row else {
            tx.commit()
                .await
                .ctx("scheduler sweep: commit node timeout")?;
            return Ok((false, false));
        };
        let mut o = LockedOutcome {
            attempt_id: SessionAttemptId::new(), // unused on the node-scope landing
            node_id,
            run_id: RunId::from_trusted_db_bytes(*row.run_id.as_bytes()),
            workspace_id: WorkspaceId::from_trusted_db_bytes(*row.workspace_id.as_bytes()),
            attempt_state: AttemptState::Claimed,
            attempt_seq: 0,
            node_state: NodeStatus::Declared,
            node_spec: serde_json::Value::Null,
            node_timeout_sec: None,
            node_not_before: None,
            first_dispatch: None,
            attempt_total: 0,
            lease_id: None,
            worker_id: None,
        };
        sqlx::query_scalar!(
            "SELECT id FROM central.runs WHERE id = $1 FOR UPDATE",
            uuid_of(o.run_id.as_bytes()),
        )
        .fetch_one(&mut *tx)
        .await
        .ctx("scheduler sweep: lock run row")?;
        let node = sqlx::query!(
            "SELECT state, spec, node_timeout_seconds, not_before \
             FROM central.workflow_nodes WHERE id = $1 FOR UPDATE",
            uuid_of(node_id.as_bytes()),
        )
        .fetch_one(&mut *tx)
        .await
        .ctx("scheduler sweep: lock node row")?;
        o.node_state = NodeStatus::parse(&node.state).ok_or_else(|| {
            Failure::internal(
                PG_DATA_CORRUPT,
                "a stored node state is outside the vocabulary",
            )
        })?;
        o.node_spec = node.spec;
        o.node_timeout_sec = node.node_timeout_seconds;
        o.node_not_before = node.not_before;
        o.load_stats_tx(&mut tx).await?;
        // Re-verify under the lock: the candidate scan was advisory.
        if o.node_timeout_sec.is_none()
            || !o.node_bound_expired(now)
            || o.node_state.is_terminal()
            || o.node_state == NodeStatus::Declared
        {
            tx.commit()
                .await
                .ctx("scheduler sweep: commit node timeout")?;
            return Ok((false, false));
        }
        if Self::node_has_unresolved_ambiguous_tx(&mut tx, o.node_id).await? {
            tx.commit()
                .await
                .ctx("scheduler sweep: commit node timeout")?;
            return Ok((false, true));
        }

        if let Some(live_id) = Self::find_live_attempt_tx(&mut tx, node_id).await?
            && let Some(mut attempt_o) = self.lock_live_attempt_tx(&mut tx, live_id).await?
            && is_live_attempt_state(attempt_o.attempt_state.as_str())
        {
            // The state re-read under the lock may show the attempt
            // already closed — another writer beat the lock wait.
            attempt_o.node_spec = o.node_spec.clone();
            attempt_o.node_timeout_sec = o.node_timeout_sec;
            if attempt_o.attempt_state == AttemptState::Claimed {
                // Never started: a definite cancel, no kill needed.
                let cancel = Outcome {
                    attempt_id: live_id,
                    kind: OutcomeKind::Cancelled,
                    reason_code: ReasonCode::NodeTimeout.as_str().to_owned(),
                    fingerprint: derived_outcome_fingerprint(
                        live_id,
                        OutcomeKind::Cancelled,
                        ReasonCode::NodeTimeout.as_str(),
                    ),
                    retry_after: None,
                };
                if let Err(err) = self
                    .record_outcome_tx(&mut tx, &mut attempt_o, &cancel)
                    .await
                    && !is_outcome_conflict(&err)
                {
                    return Err(err);
                }
            } else {
                let confirmed = self.kill_attempt(live_id).await?;
                if !confirmed {
                    self.park_attempt_ambiguous_tx(
                        &mut tx,
                        &mut attempt_o,
                        sched::REASON_ATTEMPT_AMBIGUOUS_KILL_UNCONFIRMED,
                    )
                    .await?;
                    tx.commit()
                        .await
                        .ctx("scheduler sweep: commit node timeout")?;
                    return Ok((false, true));
                }
                let failed = Outcome {
                    attempt_id: live_id,
                    kind: OutcomeKind::Failed,
                    reason_code: ReasonCode::SessionWallClockReached.as_str().to_owned(),
                    fingerprint: derived_outcome_fingerprint(
                        live_id,
                        OutcomeKind::Failed,
                        ReasonCode::SessionWallClockReached.as_str(),
                    ),
                    retry_after: None,
                };
                if let Err(err) = self
                    .record_outcome_tx(&mut tx, &mut attempt_o, &failed)
                    .await
                    && !is_outcome_conflict(&err)
                {
                    return Err(err);
                }
            }
        }
        let pending = self
            .land_node_failed_terminal_tx(
                &mut tx,
                &mut o,
                ReasonCode::NodeTimeout.as_str(),
                "first dispatch + node_timeout_seconds elapsed",
            )
            .await?;
        tx.commit()
            .await
            .ctx("scheduler sweep: commit node timeout")?;
        if let Some(pending) = pending {
            self.execute_compensation(&pending).await?;
        }
        Ok((true, false))
    }

    /// `sweepRunTimeoutTx` — fires one run whose deadline passed:
    /// `cancel_requested` on every live attempt first, then the
    /// kill/park split, then the spec-1 cascade and the run lands
    /// `failed_terminal`/`WORKFLOW_TIMEOUT`. An unconfirmed kill parks
    /// its attempt ambiguous and blocks the run landing (the committed
    /// partial closes persist; the next pass re-evaluates).
    async fn sweep_run_timeout_tx(
        &self,
        run_id: RunId,
        now: OffsetDateTime,
    ) -> Result<(bool, bool), Failure> {
        let mut tx = self.begin().await?;
        let row = sqlx::query!(
            "SELECT status, workspace_id, deadline FROM central.runs WHERE id = $1 FOR UPDATE",
            uuid_of(run_id.as_bytes()),
        )
        .fetch_optional(&mut *tx)
        .await
        .ctx("scheduler sweep: lock run row")?;
        let Some(row) = row else {
            tx.commit()
                .await
                .ctx("scheduler sweep: commit run timeout")?;
            return Ok((false, false));
        };
        let workspace_id = WorkspaceId::from_trusted_db_bytes(*row.workspace_id.as_bytes());
        // runs.deadline is the ABSOLUTE bound — anchoring the
        // predicate's started_at at the epoch evaluates exactly
        // now >= deadline.
        let deadline_bound = row.deadline.map(|d| d - EPOCH).unwrap_or(Duration::ZERO);
        if row.deadline.is_none()
            || run_status_terminal(&row.status)
            || !retry_domain::workflow_deadline_exceeded(Some(EPOCH), deadline_bound, now)
        {
            tx.commit()
                .await
                .ctx("scheduler sweep: commit run timeout")?;
            return Ok((false, false));
        }
        if Self::run_has_unresolved_ambiguous_tx(&mut tx, run_id).await? {
            tx.commit()
                .await
                .ctx("scheduler sweep: commit run timeout")?;
            return Ok((false, true));
        }

        // Live attempts, node-key order: the per-attempt node lock
        // lands run → node → attempt, the store's order everywhere.
        let live_states = live_attempt_states_bind();
        let lives = sqlx::query!(
            "SELECT a.id, a.node_id FROM central.session_attempts a \
             WHERE a.run_id = $1 AND a.state = ANY($2) \
             ORDER BY a.node_id, a.attempt_seq",
            uuid_of(run_id.as_bytes()),
            live_states.as_slice(),
        )
        .fetch_all(&mut *tx)
        .await
        .ctx("scheduler sweep: list live attempts")?;
        let reason = ReasonCode::WorkflowTimeout.as_str();
        let mut blocked = false;
        for live in &lives {
            let live_id = SessionAttemptId::from_trusted_db_bytes(*live.id.as_bytes());
            let Some(mut o) = self.lock_live_attempt_tx(&mut tx, live_id).await? else {
                continue;
            };
            if !is_live_attempt_state(o.attempt_state.as_str()) {
                continue;
            }
            // The cancel signal precedes every forced close.
            self.append_node_event_tx(
                &mut tx,
                o.workspace_id,
                o.run_id,
                o.node_id,
                EventKind::CancelRequested.as_str(),
                ACTOR_SCHEDULER,
                Some(reason),
                outcome_event_payload(&o, serde_json::json!({})),
            )
            .await?;
            if o.attempt_state == AttemptState::Claimed {
                self.close_cancelled_tx(&mut tx, &mut o, reason).await?;
                continue;
            }
            let confirmed = self.kill_attempt(live_id).await?;
            if !confirmed {
                self.park_attempt_ambiguous_tx(
                    &mut tx,
                    &mut o,
                    sched::REASON_ATTEMPT_AMBIGUOUS_KILL_UNCONFIRMED,
                )
                .await?;
                blocked = true;
                continue;
            }
            self.close_cancelled_tx(&mut tx, &mut o, reason).await?;
        }
        if blocked {
            tx.commit()
                .await
                .ctx("scheduler sweep: commit run timeout")?;
            return Ok((false, true));
        }

        // Spec-1 cascade: every remaining non-terminal node cancels.
        let cascade = sqlx::query!(
            "SELECT id, state FROM central.workflow_nodes \
             WHERE run_id = $1 AND state NOT IN ('succeeded', 'failed_terminal', 'cancelled') \
             ORDER BY id FOR UPDATE",
            uuid_of(run_id.as_bytes()),
        )
        .fetch_all(&mut *tx)
        .await
        .ctx("scheduler sweep: list run nodes")?;
        for n in &cascade {
            let state = NodeStatus::parse(&n.state).ok_or_else(|| {
                Failure::internal(
                    PG_DATA_CORRUPT,
                    "a stored node state is outside the vocabulary",
                )
            })?;
            if !state.can_transition(NodeStatus::Cancelled) {
                continue;
            }
            let mut no = LockedOutcome {
                attempt_id: SessionAttemptId::new(), // unused on node-scope rows
                node_id: WorkflowNodeId::from_trusted_db_bytes(*n.id.as_bytes()),
                run_id,
                workspace_id,
                attempt_state: AttemptState::Claimed,
                attempt_seq: 0,
                node_state: state,
                node_spec: serde_json::Value::Null,
                node_timeout_sec: None,
                node_not_before: None,
                first_dispatch: None,
                attempt_total: 0,
                lease_id: None,
                worker_id: None,
            };
            self.transition_node_tx(&mut tx, &mut no, NodeStatus::Cancelled, None)
                .await?;
            self.append_node_event_tx(
                &mut tx,
                workspace_id,
                run_id,
                no.node_id,
                EventKind::NodeCancelled.as_str(),
                ACTOR_SCHEDULER,
                Some(reason),
                serde_json::json!({
                    "from": state.as_str(),
                    "to": NodeStatus::Cancelled.as_str(),
                }),
            )
            .await?;
        }
        sqlx::query!(
            "UPDATE central.runs \
             SET status = 'failed_terminal', failure_reason = $2, updated_at = now() \
             WHERE id = $1",
            uuid_of(run_id.as_bytes()),
            reason,
        )
        .execute(&mut *tx)
        .await
        .ctx("scheduler sweep: land run terminal")?;
        tx.commit()
            .await
            .ctx("scheduler sweep: commit run timeout")?;
        Ok((true, false))
    }

    /// `evaluateCompensationTx` — resolves the locked terminal node's
    /// hook and claims its once-only execution: a prior
    /// `compensation_requested` on the node dedupes outright, otherwise
    /// the request row lands in this transaction and a managed kind
    /// returns the pending execution.
    async fn evaluate_compensation_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        o: &LockedOutcome,
    ) -> Result<Option<PendingCompensation>, Failure> {
        // Upstream unmarshals the spec tolerantly — absent fields
        // evaluate to zero values rather than failing the close.
        let spec: super::store::NodeSpecCaps =
            serde_json::from_value(o.node_spec.clone()).unwrap_or_default();
        let kind = retry_domain::parse_compensation(&spec.on_terminal_failure);
        if kind == retry_domain::CompensationKind::None {
            return Ok(None);
        }
        let claimed = sqlx::query_scalar!(
            "SELECT EXISTS(SELECT 1 FROM central.run_events \
              WHERE node_id = $1 AND kind = $2)",
            uuid_of(o.node_id.as_bytes()),
            EventKind::CompensationRequested.as_str(),
        )
        .fetch_one(&mut **tx)
        .await
        .ctx("scheduler compensation: dedupe read")?;
        if claimed.unwrap_or(false) {
            return Ok(None);
        }
        let execution = if kind.managed() {
            "managed"
        } else {
            "unmanaged"
        };
        let reason = format!("compensation {}", spec.on_terminal_failure);
        self.append_node_event_tx(
            tx,
            o.workspace_id,
            o.run_id,
            o.node_id,
            EventKind::CompensationRequested.as_str(),
            ACTOR_SCHEDULER,
            Some(&reason),
            serde_json::json!({"hook": spec.on_terminal_failure, "execution": execution}),
        )
        .await?;
        if !kind.managed() {
            return Ok(None);
        }
        Ok(Some(PendingCompensation {
            node_id: o.node_id,
            run_id: o.run_id,
            workspace_id: o.workspace_id,
            hook: spec.on_terminal_failure,
            kind,
        }))
    }

    /// `executeCompensation` — runs a claimed managed hook through the
    /// injected executor and journals the outcome as a second
    /// `compensation_requested` row (`executed`, `failed` carrying the
    /// detail, or `executor_unavailable`). The request row's prior
    /// commit makes a retry of this call dedupe before execution: the
    /// hook is at-most-once.
    async fn execute_compensation(&self, p: &PendingCompensation) -> Result<(), Failure> {
        let mut result = "executed";
        let mut detail = String::new();
        match &self.compensation {
            None => result = "executor_unavailable",
            Some(exec) if p.kind == retry_domain::CompensationKind::CleanupWorkspace => {
                if let Err(err) = exec.cleanup_workspace(p.node_id).await {
                    result = "failed";
                    detail = err.message().to_owned();
                }
            }
            Some(exec) if p.kind == retry_domain::CompensationKind::RetainArtifacts => {
                if let Err(err) = exec.retain_artifacts(p.node_id).await {
                    result = "failed";
                    detail = err.message().to_owned();
                }
            }
            Some(_) => {}
        }
        let mut payload = serde_json::json!({
            "hook": p.hook,
            "execution": "managed",
            "result": result,
        });
        if !detail.is_empty() {
            payload["detail"] = serde_json::json!(detail);
        }
        let reason = format!("compensation {} {}", p.hook, result);
        let mut tx = self.begin().await?;
        self.append_node_event_tx(
            &mut tx,
            p.workspace_id,
            p.run_id,
            p.node_id,
            EventKind::CompensationRequested.as_str(),
            ACTOR_SCHEDULER,
            Some(&reason),
            payload,
        )
        .await?;
        tx.commit()
            .await
            .ctx("scheduler compensation: journal result")?;
        Ok(())
    }
}

/// The `failure_class` an [`OutcomeResult`] reports: `classify` for a
/// `failed` report, [`FailureClass::Terminal`] for the non-failure kinds
/// — upstream returns the non-enumerated text `"none"` there; the Rust
/// enum cannot carry it, so the result side reports `Terminal` (the
/// class taxonomy describes failures; the LEDGER row keeps the verbatim
/// `"none"` text via [`outcome_failure_class_text`]). Callers inspect
/// `class` only on `failed` outcomes — the field is inert otherwise.
fn outcome_failure_class(outcome: &Outcome) -> FailureClass {
    if outcome.kind != OutcomeKind::Failed {
        return FailureClass::Terminal;
    }
    retry_domain::classify(&outcome.reason_code)
}

// ---------------------------------------------------------------------------
// central_retry::port::Store — the b37 durable outcome surface
// ---------------------------------------------------------------------------

impl RetryStore for PgSchedulerStore {
    /// `RecordOutcome` — one definite outcome under the lease fence:
    /// the ledger row, classified `failure_class`, attempt close, lease
    /// release, node transition and journaled events commit in ONE
    /// transaction. Replay under the same key+fingerprint dedupes with
    /// `command_deduped`; a same-key/different-fingerprint report
    /// conflicts `DUPLICATE_IDEMPOTENCY_KEY`. A report whose lease
    /// already fenced falls through to replay resolution — a recorded
    /// row still dedupes, an unrecorded one stays `LEASE_FENCE_STALE`.
    ///
    /// The Rust `Outcome` type validates by construction (closed
    /// `OutcomeKind`, fixed `[u8; 32]` fingerprint); the surviving
    /// check is the `failed`-report reason gate.
    async fn record_outcome(&self, outcome: Outcome) -> Result<OutcomeResult, Failure> {
        if outcome.kind == OutcomeKind::Failed && outcome.reason_code.is_empty() {
            return Err(domain_failure(
                sched::FailureClass::Invalid,
                sched::REASON_OUTCOME_REASON_MISSING,
                "a failed outcome must carry a spec-4 reason code",
            ));
        }

        let eval_now = self.eval_now();
        let fenced = self.fenced_begin_tx(outcome.attempt_id).await;
        let (mut tx, f, node_state) = match fenced {
            Ok(ok) => ok,
            Err(err) if is_fence_stale(&err) => {
                // The fence rejected before any mutation: the outcome
                // may be a late replay of a commit that already closed
                // the attempt. Resolve it idempotently instead.
                return self.resolve_outcome_replay_tx(&outcome).await;
            }
            Err(err) => return Err(err),
        };
        let mut o = LockedOutcome {
            attempt_id: f.attempt_id,
            node_id: f.node_id,
            run_id: f.run_id,
            workspace_id: f.workspace_id,
            attempt_state: f.state,
            attempt_seq: f.attempt_seq,
            node_state,
            node_spec: f.node_spec,
            node_timeout_sec: f.node_timeout_sec,
            node_not_before: f.node_not_before,
            first_dispatch: None,
            attempt_total: 0,
            lease_id: Some(f.lease_id),
            worker_id: Some(f.worker_id),
        };
        o.load_stats_tx(&mut tx).await?;
        let (result, pending) = self
            .apply_outcome_tx(&mut tx, &mut o, &outcome, eval_now)
            .await?;
        PgSchedulerStore::commit_fenced(tx).await?;
        if let Some(pending) = pending {
            self.execute_compensation(&pending).await?;
        }
        Ok(result)
    }

    /// `AttemptCounts` — the node's journaled attempt consumption:
    /// total `session_attempts` rows plus the per-class split of
    /// recorded `failed` outcomes (spec-4 decision 3).
    async fn attempt_counts(&self, node_id: WorkflowNodeId) -> Result<AttemptCounts, Failure> {
        let total: Option<i64> = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM central.session_attempts WHERE node_id = $1",
            uuid_of(node_id.as_bytes()),
        )
        .fetch_one(&self.pool)
        .await
        .ctx("scheduler outcome: count attempts")?;
        let mut tx = self.begin().await?;
        let per_class = Self::per_class_counts_tx(&mut tx, node_id).await?;
        tx.commit().await.ctx("scheduler outcome: commit counts")?;
        Ok(AttemptCounts {
            per_class,
            total: u32::try_from(total.unwrap_or(0)).unwrap_or(u32::MAX),
        })
    }

    /// `FirstDispatchAt` — `MIN(claimed_at)` for the node; `None` means
    /// no bound is running.
    async fn first_dispatch_at(
        &self,
        node_id: WorkflowNodeId,
    ) -> Result<Option<OffsetDateTime>, Failure> {
        sqlx::query_scalar!(
            "SELECT MIN(claimed_at) FROM central.session_attempts WHERE node_id = $1",
            uuid_of(node_id.as_bytes()),
        )
        .fetch_one(&self.pool)
        .await
        .ctx("scheduler outcome: first dispatch")
    }

    /// `SweepTimeouts` — the three-level deadline evaluation, innermost
    /// first (session breaches → node bounds → workflow bounds), each
    /// landing committing state + journal atomically; ambiguous
    /// descendants block timers per locked input 3.
    async fn sweep_timeouts(&self, now: OffsetDateTime) -> Result<SweepSummary, Failure> {
        let mut sum = SweepSummary::default();

        // Level 1 — session breaches.
        let breaches = central_scheduler::port::Store::list_wall_clock_breaches(self, now).await?;
        for b in breaches {
            if self.sweep_session_breach_tx(b.id, now).await? {
                sum.skipped_ambiguous.push(SkippedScope::Node(b.node_id));
            }
        }

        // Level 2 — node aggregate bounds.
        let node_ids = sqlx::query!(
            "SELECT n.id FROM central.workflow_nodes n \
             WHERE n.node_timeout_seconds IS NOT NULL \
               AND n.state IN ('ready', 'dispatched', 'running', 'attempt_ambiguous') \
               AND (SELECT MIN(a.claimed_at) FROM central.session_attempts a \
                    WHERE a.node_id = n.id) \
                   + make_interval(secs => n.node_timeout_seconds) <= $1 \
             ORDER BY n.id",
            now,
        )
        .fetch_all(&self.pool)
        .await
        .ctx("scheduler sweep: list node candidates")?;
        for row in node_ids {
            let node_id = WorkflowNodeId::from_trusted_db_bytes(*row.id.as_bytes());
            let (landed, skipped) = self.sweep_node_timeout_tx(node_id, now).await?;
            if landed {
                sum.node_timeouts.push(node_id);
            }
            if skipped {
                sum.skipped_ambiguous.push(SkippedScope::Node(node_id));
            }
        }

        // Level 3 — workflow bounds (runs.deadline is the absolute bound).
        let run_ids = sqlx::query!(
            "SELECT id FROM central.runs \
             WHERE deadline IS NOT NULL AND deadline <= $1 \
               AND status IN ('queued', 'running', 'waiting', 'cancelling') \
             ORDER BY id",
            now,
        )
        .fetch_all(&self.pool)
        .await
        .ctx("scheduler sweep: list run candidates")?;
        for row in run_ids {
            let run_id = RunId::from_trusted_db_bytes(*row.id.as_bytes());
            let (landed, skipped) = self.sweep_run_timeout_tx(run_id, now).await?;
            if landed {
                sum.workflow_timeouts.push(run_id);
            }
            if skipped {
                sum.skipped_ambiguous.push(SkippedScope::Run(run_id));
            }
        }
        Ok(sum)
    }

    /// `RunCompensation` — the node's `spec.on_terminal_failure` hook
    /// evaluated at most once, keyed on the node: managed kinds execute
    /// post-commit through the injected executor; every other declared
    /// value journals `compensation_requested` only.
    async fn run_compensation(&self, node_id: WorkflowNodeId) -> Result<(), Failure> {
        let mut tx = self.begin().await?;
        let row = sqlx::query!(
            "SELECT run_id, workspace_id FROM central.workflow_nodes WHERE id = $1",
            uuid_of(node_id.as_bytes()),
        )
        .fetch_optional(&mut *tx)
        .await
        .ctx("scheduler compensation: read node")?;
        let Some(row) = row else {
            return Err(domain_failure(
                sched::FailureClass::Invalid,
                sched::REASON_NODE_NOT_FOUND,
                "no such workflow node",
            ));
        };
        let mut o = LockedOutcome {
            attempt_id: SessionAttemptId::new(), // unused on the node-scope eval
            node_id,
            run_id: RunId::from_trusted_db_bytes(*row.run_id.as_bytes()),
            workspace_id: WorkspaceId::from_trusted_db_bytes(*row.workspace_id.as_bytes()),
            attempt_state: AttemptState::Claimed,
            attempt_seq: 0,
            node_state: NodeStatus::Declared,
            node_spec: serde_json::Value::Null,
            node_timeout_sec: None,
            node_not_before: None,
            first_dispatch: None,
            attempt_total: 0,
            lease_id: None,
            worker_id: None,
        };
        sqlx::query_scalar!(
            "SELECT id FROM central.runs WHERE id = $1 FOR UPDATE",
            uuid_of(o.run_id.as_bytes()),
        )
        .fetch_one(&mut *tx)
        .await
        .ctx("scheduler compensation: lock run row")?;
        let node = sqlx::query!(
            "SELECT state, spec FROM central.workflow_nodes WHERE id = $1 FOR UPDATE",
            uuid_of(node_id.as_bytes()),
        )
        .fetch_one(&mut *tx)
        .await
        .ctx("scheduler compensation: lock node row")?;
        o.node_state = NodeStatus::parse(&node.state).ok_or_else(|| {
            Failure::internal(
                PG_DATA_CORRUPT,
                "a stored node state is outside the vocabulary",
            )
        })?;
        o.node_spec = node.spec;

        let mut pending = None;
        if o.node_state == NodeStatus::FailedTerminal {
            pending = self.evaluate_compensation_tx(&mut tx, &o).await?;
        }
        tx.commit().await.ctx("scheduler compensation: commit")?;
        if let Some(pending) = pending {
            return self.execute_compensation(&pending).await;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// central_retry::query::AttemptHistoryRead — the ledger projection
// ---------------------------------------------------------------------------

impl AttemptHistoryRead for PgSchedulerStore {
    /// The node's journaled outcome ledger ordered by `attempt_seq` —
    /// the durable evidence `attempt_counts` aggregates. Reason and
    /// class project verbatim (a row from another build's vocabulary
    /// still reads — the projection is evidence, not a decision).
    async fn list_node_outcomes(
        &self,
        node_id: WorkflowNodeId,
    ) -> Result<Vec<AttemptOutcomeView>, Failure> {
        let rows = sqlx::query!(
            "SELECT o.attempt_id, a.attempt_seq, o.outcome_kind, o.reason_code, \
                    o.failure_class, o.payload_fingerprint, o.recorded_at \
             FROM central.attempt_outcomes o \
             JOIN central.session_attempts a ON a.id = o.attempt_id \
             WHERE a.node_id = $1 \
             ORDER BY a.attempt_seq",
            uuid_of(node_id.as_bytes()),
        )
        .fetch_all(&self.pool)
        .await
        .ctx("scheduler outcome: list node outcomes")?;
        rows.iter()
            .map(|r| {
                let fingerprint: [u8; 32] =
                    r.payload_fingerprint.as_slice().try_into().map_err(|_| {
                        Failure::internal(
                            PG_DATA_CORRUPT,
                            "a stored outcome fingerprint is not 32 bytes",
                        )
                    })?;
                Ok(AttemptOutcomeView {
                    attempt_id: SessionAttemptId::from_trusted_db_bytes(*r.attempt_id.as_bytes()),
                    attempt_seq: i64::from(r.attempt_seq),
                    kind: OutcomeKind::parse(&r.outcome_kind).ok_or_else(|| {
                        Failure::internal(
                            PG_DATA_CORRUPT,
                            "a stored outcome kind is outside the vocabulary",
                        )
                    })?,
                    reason_code: r.reason_code.clone(),
                    failure_class: r.failure_class.clone(),
                    payload_fingerprint: fingerprint,
                    recorded_at: r.recorded_at,
                })
            })
            .collect()
    }

    /// The one-row-ever operator decision for a parked ambiguous
    /// attempt; `None` while unresolved — the same probe the sweep's
    /// locked-input-3 blocker evaluates.
    async fn load_attempt_decision(
        &self,
        attempt_id: SessionAttemptId,
    ) -> Result<Option<AttemptDecisionView>, Failure> {
        let row = sqlx::query!(
            "SELECT attempt_id, run_id, node_id, decision, payload_fingerprint, \
                    decided_by, decided_at \
             FROM central.attempt_decisions WHERE attempt_id = $1",
            uuid_of(attempt_id.as_bytes()),
        )
        .fetch_optional(&self.pool)
        .await
        .ctx("scheduler outcome: load attempt decision")?;
        row.map(|r| {
            let fingerprint: [u8; 32] =
                r.payload_fingerprint.as_slice().try_into().map_err(|_| {
                    Failure::internal(
                        PG_DATA_CORRUPT,
                        "a stored decision fingerprint is not 32 bytes",
                    )
                })?;
            Ok(AttemptDecisionView {
                attempt_id: SessionAttemptId::from_trusted_db_bytes(*r.attempt_id.as_bytes()),
                run_id: RunId::from_trusted_db_bytes(*r.run_id.as_bytes()),
                node_id: WorkflowNodeId::from_trusted_db_bytes(*r.node_id.as_bytes()),
                decision: AttemptDecision::parse(&r.decision).ok_or_else(|| {
                    Failure::internal(
                        PG_DATA_CORRUPT,
                        "a stored decision is outside the vocabulary",
                    )
                })?,
                payload_fingerprint: fingerprint,
                decided_by: r.decided_by,
                decided_at: r.decided_at,
            })
        })
        .transpose()
    }
}

// ---------------------------------------------------------------------------
// central_scheduler::query::SchedulerRead — the read projections
// ---------------------------------------------------------------------------

impl SchedulerRead for PgSchedulerStore {
    /// Every `worker_registrations` row in the workspace, most recent
    /// first.
    async fn list_workers(&self, workspace_id: WorkspaceId) -> Result<Vec<sched::Worker>, Failure> {
        let rows = sqlx::query_as!(
            WorkerRec,
            "SELECT id, workspace_id, protocol_version, harness_kinds, workspace_kinds, \
                    max_concurrent_attempts, state, registered_at, last_seen_at \
             FROM central.worker_registrations \
             WHERE workspace_id = $1 ORDER BY registered_at DESC, id",
            uuid_of(workspace_id.as_bytes()),
        )
        .fetch_all(&self.pool)
        .await
        .ctx("scheduler read: list workers")?;
        rows.into_iter().map(decode_worker).collect()
    }

    /// The single registration row; `None` when absent.
    async fn load_worker(&self, worker_id: WorkerId) -> Result<Option<sched::Worker>, Failure> {
        let row = sqlx::query_as!(
            WorkerRec,
            "SELECT id, workspace_id, protocol_version, harness_kinds, workspace_kinds, \
                    max_concurrent_attempts, state, registered_at, last_seen_at \
             FROM central.worker_registrations WHERE id = $1",
            uuid_of(worker_id.as_bytes()),
        )
        .fetch_optional(&self.pool)
        .await
        .ctx("scheduler read: load worker")?;
        row.map(decode_worker).transpose()
    }

    /// The node's per-attempt ledger ordered by `attempt_seq`.
    async fn list_node_attempts(
        &self,
        node_id: WorkflowNodeId,
    ) -> Result<Vec<sched::SessionAttempt>, Failure> {
        let rows = sqlx::query_as!(
            AttemptRec,
            "SELECT id, workspace_id, run_id, node_id, attempt_seq, worker_id, \
                    harness_attempt_id, workspace_path, workspace_kind, state, \
                    dispatch_reason_code, reservation_id, harness_session_id, \
                    claimed_at, started_at, ended_at \
             FROM central.session_attempts WHERE node_id = $1 ORDER BY attempt_seq",
            uuid_of(node_id.as_bytes()),
        )
        .fetch_all(&self.pool)
        .await
        .ctx("scheduler read: list node attempts")?;
        rows.into_iter().map(decode_attempt).collect()
    }

    /// The node's live lease (`released_at IS NULL` under the partial
    /// index); `None` while unclaimed.
    async fn live_lease(&self, node_id: WorkflowNodeId) -> Result<Option<sched::Lease>, Failure> {
        let row = sqlx::query_as!(
            LeaseRec,
            "SELECT id, node_id, attempt_id, worker_id, issued_at, last_heartbeat_at, \
                    expires_at, heartbeat_interval_seconds, released_at \
             FROM central.node_leases \
             WHERE node_id = $1 AND released_at IS NULL",
            uuid_of(node_id.as_bytes()),
        )
        .fetch_optional(&self.pool)
        .await
        .ctx("scheduler read: live lease")?;
        row.map(decode_lease).transpose()
    }

    /// The single attempt row; `None` when absent.
    async fn load_attempt(
        &self,
        attempt_id: SessionAttemptId,
    ) -> Result<Option<sched::SessionAttempt>, Failure> {
        let row = sqlx::query_as!(
            AttemptRec,
            "SELECT id, workspace_id, run_id, node_id, attempt_seq, worker_id, \
                    harness_attempt_id, workspace_path, workspace_kind, state, \
                    dispatch_reason_code, reservation_id, harness_session_id, \
                    claimed_at, started_at, ended_at \
             FROM central.session_attempts WHERE id = $1",
            uuid_of(attempt_id.as_bytes()),
        )
        .fetch_optional(&self.pool)
        .await
        .ctx("scheduler read: load attempt")?;
        row.map(decode_attempt).transpose()
    }
}

/// `query_as!` record for `worker_registrations` — sqlx types stay
/// inside the adapter and the decode re-validates the vocabulary.
struct WorkerRec {
    id: uuid::Uuid,
    workspace_id: uuid::Uuid,
    protocol_version: i32,
    harness_kinds: Vec<String>,
    workspace_kinds: Vec<String>,
    max_concurrent_attempts: i32,
    state: String,
    registered_at: OffsetDateTime,
    last_seen_at: Option<OffsetDateTime>,
}

/// `query_as!` record for `session_attempts`.
struct AttemptRec {
    id: uuid::Uuid,
    workspace_id: uuid::Uuid,
    run_id: uuid::Uuid,
    node_id: uuid::Uuid,
    attempt_seq: i32,
    worker_id: Option<uuid::Uuid>,
    harness_attempt_id: Option<uuid::Uuid>,
    workspace_path: Option<String>,
    workspace_kind: String,
    state: String,
    dispatch_reason_code: Option<String>,
    reservation_id: Option<String>,
    harness_session_id: Option<String>,
    claimed_at: OffsetDateTime,
    started_at: Option<OffsetDateTime>,
    ended_at: Option<OffsetDateTime>,
}

/// `query_as!` record for `node_leases`.
struct LeaseRec {
    id: uuid::Uuid,
    node_id: uuid::Uuid,
    attempt_id: uuid::Uuid,
    worker_id: uuid::Uuid,
    issued_at: OffsetDateTime,
    last_heartbeat_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    heartbeat_interval_seconds: i32,
    released_at: Option<OffsetDateTime>,
}

/// A stored value outside the domain vocabulary is `PG_DATA_CORRUPT`
/// internal, never a caller error.
fn decode_worker(r: WorkerRec) -> Result<sched::Worker, Failure> {
    Ok(sched::Worker {
        id: WorkerId::from_trusted_db_bytes(*r.id.as_bytes()),
        workspace_id: WorkspaceId::from_trusted_db_bytes(*r.workspace_id.as_bytes()),
        protocol_version: r.protocol_version,
        harness_kinds: r.harness_kinds,
        workspace_kinds: r.workspace_kinds,
        max_concurrent_attempts: r.max_concurrent_attempts,
        state: sched::WorkerState::parse(&r.state).ok_or_else(|| {
            Failure::internal(
                PG_DATA_CORRUPT,
                "a stored worker state is outside the vocabulary",
            )
        })?,
        registered_at: Some(r.registered_at),
        last_seen_at: r.last_seen_at,
    })
}

fn decode_attempt(r: AttemptRec) -> Result<sched::SessionAttempt, Failure> {
    Ok(sched::SessionAttempt {
        id: SessionAttemptId::from_trusted_db_bytes(*r.id.as_bytes()),
        workspace_id: WorkspaceId::from_trusted_db_bytes(*r.workspace_id.as_bytes()),
        run_id: RunId::from_trusted_db_bytes(*r.run_id.as_bytes()),
        node_id: WorkflowNodeId::from_trusted_db_bytes(*r.node_id.as_bytes()),
        attempt_seq: r.attempt_seq,
        worker_id: r
            .worker_id
            .map(|id| WorkerId::from_trusted_db_bytes(*id.as_bytes())),
        harness_attempt_id: r
            .harness_attempt_id
            .map(|id| HarnessAttemptId::from_trusted_db_bytes(*id.as_bytes())),
        workspace_path: r.workspace_path,
        workspace_kind: r.workspace_kind,
        state: AttemptState::parse(&r.state).ok_or_else(|| {
            Failure::internal(
                PG_DATA_CORRUPT,
                "a stored attempt state is outside the vocabulary",
            )
        })?,
        dispatch_reason_code: r.dispatch_reason_code,
        reservation_id: r.reservation_id,
        harness_session_id: r.harness_session_id,
        claimed_at: r.claimed_at,
        started_at: r.started_at,
        ended_at: r.ended_at,
    })
}

fn decode_lease(r: LeaseRec) -> Result<sched::Lease, Failure> {
    Ok(sched::Lease {
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
}

// ---------------------------------------------------------------------------
// PgOutcomeStore — the retry-facing name of the same store
// ---------------------------------------------------------------------------

/// The b37 outcome/decision-ledger face of the scheduler store.
///
/// Upstream is one `Store` struct implementing both ports; the Rust
/// port splits the retry surface onto a named handle so call sites that
/// only need the ledger name it — `PgOutcomeStore` delegates every
/// method to its inner [`PgSchedulerStore`], so `attempt_outcomes`
/// still has exactly one writer code path.
#[derive(Clone)]
pub struct PgOutcomeStore {
    inner: PgSchedulerStore,
}

impl PgOutcomeStore {
    /// Wraps the scheduler store; the same pool and config apply.
    #[must_use]
    pub fn new(inner: PgSchedulerStore) -> Self {
        Self { inner }
    }

    /// The underlying scheduler store (the same struct upstream).
    #[must_use]
    pub fn scheduler(&self) -> &PgSchedulerStore {
        &self.inner
    }

    /// Unwraps back to the scheduler store.
    #[must_use]
    pub fn into_inner(self) -> PgSchedulerStore {
        self.inner
    }
}

impl Deref for PgOutcomeStore {
    type Target = PgSchedulerStore;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for PgOutcomeStore {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl RetryStore for PgOutcomeStore {
    async fn record_outcome(&self, outcome: Outcome) -> Result<OutcomeResult, Failure> {
        RetryStore::record_outcome(&self.inner, outcome).await
    }
    async fn attempt_counts(&self, node_id: WorkflowNodeId) -> Result<AttemptCounts, Failure> {
        RetryStore::attempt_counts(&self.inner, node_id).await
    }
    async fn first_dispatch_at(
        &self,
        node_id: WorkflowNodeId,
    ) -> Result<Option<OffsetDateTime>, Failure> {
        RetryStore::first_dispatch_at(&self.inner, node_id).await
    }
    async fn sweep_timeouts(&self, now: OffsetDateTime) -> Result<SweepSummary, Failure> {
        RetryStore::sweep_timeouts(&self.inner, now).await
    }
    async fn run_compensation(&self, node_id: WorkflowNodeId) -> Result<(), Failure> {
        RetryStore::run_compensation(&self.inner, node_id).await
    }
}

impl AttemptHistoryRead for PgOutcomeStore {
    async fn list_node_outcomes(
        &self,
        node_id: WorkflowNodeId,
    ) -> Result<Vec<AttemptOutcomeView>, Failure> {
        AttemptHistoryRead::list_node_outcomes(&self.inner, node_id).await
    }
    async fn load_attempt_decision(
        &self,
        attempt_id: SessionAttemptId,
    ) -> Result<Option<AttemptDecisionView>, Failure> {
        AttemptHistoryRead::load_attempt_decision(&self.inner, attempt_id).await
    }
}
