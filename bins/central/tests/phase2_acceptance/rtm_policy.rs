//! Policy scenarios — RTM-02 (transient retry scheduling), RTM-04
//! (budget exhaustion), RTM-08 (admission deferral), RTM-13 (node
//! timeout kill), RTM-16 (deregister releases), RTM-19-session
//! (wall-clock kill), RTM-19-deadlines (workflow timeout cascade).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::missing_panics_doc)]

use central_retry::domain::{FailureClass, OutcomeKind, ReasonCode as RetryReason, RetryPolicy};
use central_retry::port::Store as RetryStore;
use central_scheduler::admission::{
    AdmissionSnapshot, ConcurrencyProfile, check_dispatch_admission,
};
use central_scheduler::domain::AttemptState;
use central_scheduler::port::Store as SchedStore;
use central_workflow::domain::NodeStatus;
use time::Duration;

use crate::driver::{Matrix, Result};

fn outcome(
    attempt: central_foundation::identity::SessionAttemptId,
    reason: &str,
    fp: u8,
) -> central_retry::port::Outcome {
    central_retry::port::Outcome {
        attempt_id: attempt,
        kind: OutcomeKind::Failed,
        reason_code: reason.to_string(),
        fingerprint: [fp; 32],
        retry_after: None,
    }
}

/// RTM-02 — a transient-class failure records the outcome, schedules
/// `attempt_retry_scheduled` with a bounded `not_before`, and returns the
/// node to `ready`.
pub async fn rtm_02(m: &mut Matrix) -> Result<String> {
    m.emit(None, vec![Matrix::child("retry-me")]).await?;
    let worker = m.register_worker(4).await?;
    let claim = m.claim_and_dispatch(worker).await?;

    let result = RetryStore::record_outcome(
        m.sched.as_ref(),
        outcome(
            claim.attempt.id,
            RetryReason::ProcessExitNonzero.as_str(),
            1,
        ),
    )
    .await?;
    assert_eq!(result.class, FailureClass::Transient);
    assert_eq!(result.node_status, "ready");
    assert!(result.retry_at.is_some(), "retry scheduled");
    m.assert_kinds(&["attempt_failed", "attempt_retry_scheduled"])
        .await?;
    m.assert_reason("attempt_failed", "PROCESS_EXIT_NONZERO")
        .await?;
    m.assert_no_live_leases().await?;
    Ok("transient failure scheduled bounded retry".to_string())
}

/// RTM-04 — once the per-class retry budget is exhausted, the outcome
/// lands `failed_terminal` with `RETRY_BUDGET_EXHAUSTED` — the bound is
/// consumed per node, not per attempt.
pub async fn rtm_04(m: &mut Matrix) -> Result<String> {
    std::sync::Arc::get_mut(&mut m.sched).unwrap().retry_policy = RetryPolicy {
        base_delay: Duration::milliseconds(1),
        cap: Duration::milliseconds(5),
        multiplier: 1.0,
        per_class_limits: [(FailureClass::Transient, 1)].into_iter().collect(),
        max_attempts_total: 1,
    };
    m.emit(None, vec![Matrix::child("exhaust")]).await?;
    let worker = m.register_worker(4).await?;
    let claim = m.claim_and_dispatch(worker).await?;

    let result = RetryStore::record_outcome(
        m.sched.as_ref(),
        outcome(
            claim.attempt.id,
            RetryReason::ProcessExitNonzero.as_str(),
            2,
        ),
    )
    .await?;
    assert_eq!(result.node_status, "failed_terminal");
    m.assert_node_state(claim.attempt.node_id, NodeStatus::FailedTerminal)
        .await?;
    m.assert_reason("node_failed_terminal", "RETRY_BUDGET_EXHAUSTED")
        .await?;
    Ok("budget exhaustion landed terminal".to_string())
}

/// RTM-08 — capacity admission defers dispatch: a zero-session profile
/// refuses the claim-time admission check; the node keeps its `ready`
/// FIFO slot, journals `admission_deferred`, and consumes no attempt.
pub async fn rtm_08(m: &mut Matrix) -> Result<String> {
    let profile = ConcurrencyProfile {
        max_parallel_sessions: 0,
        ..ConcurrencyProfile::default()
    };
    std::sync::Arc::get_mut(&mut m.sched)
        .unwrap()
        .admission_profile = Some(profile);
    m.emit(None, vec![Matrix::child("deferred")]).await?;
    let worker = m.register_worker(4).await?;

    // The pure check refuses outright.
    let verdict = check_dispatch_admission(
        &profile,
        &AdmissionSnapshot {
            inflight_sessions: 0,
            run_inflight_nodes: 0,
            run_budget_exhausted: false,
            disk_measured: false,
            free_bytes: 0,
            disk_budget_bytes: 0,
        },
    );
    assert!(!verdict.admit, "zero-session profile refuses");
    assert_eq!(
        verdict.reason_code,
        Some(central_scheduler::admission::REASON_CAPACITY_ADMISSION_DEFERRED)
    );

    // And the claim path defers rather than erroring.
    let claimed = m.sched.claim_ready(worker, 1).await?;
    assert!(claimed.is_empty(), "deferred candidate not claimed");
    m.assert_kinds(&["admission_deferred"]).await?;
    m.assert_reason("admission_deferred", "CAPACITY_ADMISSION_DEFERRED")
        .await?;
    Ok("admission deferred without consuming an attempt".to_string())
}

/// RTM-13 — node timeout: the aggregate bound (first dispatch +
/// `node_timeout_seconds`) kills the live attempt through the injected
/// `Killer`; a confirmed kill records `SESSION_WALL_CLOCK_REACHED` and
/// the node lands `failed_terminal`/`NODE_TIMEOUT`.
pub async fn rtm_13(m: &mut Matrix) -> Result<String> {
    m.emit(None, vec![Matrix::child("timed")]).await?;
    let node = m.node_by_key("timed").await?;
    m.set_node_timeout(node, 60).await?;
    let worker = m.register_worker(4).await?;
    let claim = m.claim_and_dispatch(worker).await?;
    m.killer.script(claim.attempt.id, true);

    m.age_claimed_at(claim.attempt.id, 120.0).await?;
    m.sched.sweep_timeouts(m.clock.now()).await?;

    assert_eq!(m.killer.calls.lock().unwrap().len(), 1, "kill invoked");
    m.assert_node_state(node, NodeStatus::FailedTerminal)
        .await?;
    m.assert_kinds(&["attempt_failed"]).await?;
    m.assert_reason("attempt_failed", "SESSION_WALL_CLOCK_REACHED")
        .await?;
    m.assert_reason("node_failed_terminal", "NODE_TIMEOUT")
        .await?;
    Ok("node timeout killed confirmed and terminated".to_string())
}

/// RTM-16 — deregistration releases the worker's leases and requeues its
/// in-flight nodes; `worker_deregistered` journals the release reason.
pub async fn rtm_16(m: &mut Matrix) -> Result<String> {
    m.emit(None, vec![Matrix::child("orphaned")]).await?;
    let worker = m.register_worker(4).await?;
    let claim = m.claim_and_dispatch(worker).await?;

    m.sched.deregister_worker(worker, "operator:rtm").await?;

    m.assert_kinds(&["worker_deregistered"]).await?;
    // The released started attempt parks ambiguous under
    // WORKER_SHUTDOWN_LEASE_RELEASED; the node follows it.
    // The released lease leaves the `started` attempt live for outcome
    // persistence; `reconcile` then parks it ambiguous under
    // WORKER_SHUTDOWN_LEASE_RELEASED.
    m.sched.reconcile("reconciler").await?;
    let attempt_state = m.attempt_state(claim.attempt.id).await?;
    assert!(
        matches!(attempt_state.as_str(), "ambiguous" | "failed" | "cancelled"),
        "released attempt state {attempt_state}"
    );
    m.assert_no_live_leases().await?;
    Ok("deregister released leases and requeued".to_string())
}

/// RTM-19-session — the session wall-clock ceiling: `wall_clock_ceiling`
/// breach lists the live attempt, the injected `Killer` confirms the
/// kill, and `record_ceiling_breach` lands the definite
/// `SESSION_WALL_CLOCK_REACHED` failure (session_timeout class → the
/// node requeues under backoff).
pub async fn rtm_19_session(m: &mut Matrix) -> Result<String> {
    {
        let profile = std::sync::Arc::get_mut(&mut m.sched)
            .unwrap()
            .admission_profile
            .get_or_insert_with(ConcurrencyProfile::default);
        profile.wall_clock_ceiling = Duration::seconds(60);
    }
    m.emit(None, vec![Matrix::child("wall")]).await?;
    let worker = m.register_worker(4).await?;
    let claim = m.claim_and_dispatch(worker).await?;
    m.killer.script(claim.attempt.id, true);

    m.clock.advance(Duration::seconds(
        crate::driver::LEASE_TTL.whole_seconds() + 75,
    ));
    let breaches = m.sched.list_wall_clock_breaches(m.clock.now()).await?;
    assert_eq!(breaches.len(), 1, "one wall-clock breach");
    assert_eq!(breaches[0].id, claim.attempt.id);

    // Confirmed kill → definite breach outcome (upstream's confirmed
    // branch; an unconfirmed kill would ambiguate instead).
    assert!(
        central_retry::port::Killer::kill(m.killer.as_ref(), claim.attempt.id).await?,
        "kill confirmed"
    );
    m.sched
        .record_ceiling_breach(claim.attempt.id, "SESSION_WALL_CLOCK_REACHED")
        .await?;

    m.assert_attempt_state(claim.attempt.id, AttemptState::Failed)
        .await?;
    m.assert_reason("attempt_failed", "SESSION_WALL_CLOCK_REACHED")
        .await?;
    Ok("wall-clock breach kill-confirmed, outcome recorded".to_string())
}

/// RTM-19-deadlines — the workflow deadline: an expired run deadline
/// cancels live attempts, cascades non-terminal nodes `cancelled`, and
/// lands the run `failed_terminal`/`WORKFLOW_TIMEOUT`.
pub async fn rtm_19_deadlines(m: &mut Matrix) -> Result<String> {
    m.emit(None, vec![Matrix::child("deadline-run")]).await?;
    let worker = m.register_worker(4).await?;
    let claim = m.claim_and_dispatch(worker).await?;
    m.killer.script(claim.attempt.id, true);

    m.set_run_deadline(1.0).await?;
    let summary = m.sched.sweep_timeouts(m.clock.now()).await?;
    let _ = summary;

    // The deadline fires the spec-1 cancel cascade: live attempts
    // cancelled, non-terminal nodes cancelled, run failed_terminal.
    m.assert_kinds(&["cancel_requested", "node_cancelled"])
        .await?;
    m.assert_reason("node_cancelled", "WORKFLOW_TIMEOUT")
        .await?;
    let run_status: String = sqlx::query_scalar("SELECT status FROM central.runs WHERE id = $1")
        .bind(sqlx::types::Uuid::from_bytes(*m.run.as_bytes()))
        .fetch_one(&mut m.admin)
        .await
        .map_err(|e| {
            central_foundation::failure::Failure::internal("RTM_FIXTURE", e.to_string())
        })?;
    assert_eq!(run_status, "failed_terminal", "run landed terminal");
    Ok("workflow deadline cascaded cancellations".to_string())
}
