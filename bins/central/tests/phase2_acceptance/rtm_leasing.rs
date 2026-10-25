//! Leasing scenarios — RTM-03 (kill mid-attempt → ambiguous), RTM-05
//! (unconfirmed launch parks), RTM-06 (never-started lease expiry →
//! requeue), RTM-07 (suspect/lost ladder), RTM-15 (outbox stall
//! detection), RTM-17 (restart reconcile).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::missing_panics_doc)]

use std::sync::Arc;

use central_adapter_postgres::eventjournal::Store as PgJournalStore;
use central_eventjournal::app::publisher::{DrainStore, Publisher, UnpublishedBacklog};
use central_eventjournal::domain::RunEvent;
use central_eventjournal::port::{Consumer, ConsumerFuture};
use central_foundation::failure::Failure;
use central_scheduler::domain::AttemptState;
use central_scheduler::port::{LaunchVerdict, Store as SchedStore};
use central_workflow::domain::NodeStatus;
use central_workflow::port::WorkflowStore;
use time::OffsetDateTime;

use crate::driver::{Matrix, Result};

/// RTM-03 — process kill mid-attempt: a `started` attempt's lease expiry
/// marks it `attempt_ambiguous` (`ATTEMPT_AMBIGUOUS_LEASE_EXPIRED`), the
/// node parks for an operator decision, siblings survive.
pub async fn rtm_03(m: &mut Matrix) -> Result<String> {
    m.emit(
        None,
        vec![Matrix::child("victim"), Matrix::child("sibling")],
    )
    .await?;
    let worker = m.register_worker(4).await?;
    let victim = m.claim_and_dispatch(worker).await?;
    m.assert_attempt_state(victim.attempt.id, AttemptState::Started)
        .await?;

    m.force_expire(victim.lease.id).await?;
    m.sched.expire_leases(m.clock.now()).await?;

    m.assert_attempt_state(victim.attempt.id, AttemptState::Ambiguous)
        .await?;
    m.assert_node_state(victim.attempt.node_id, NodeStatus::AttemptAmbiguous)
        .await?;
    m.assert_reason("attempt_ambiguous", "ATTEMPT_AMBIGUOUS_LEASE_EXPIRED")
        .await?;
    m.assert_kinds(&["lease_expired", "attempt_ambiguous"])
        .await?;
    Ok("started attempt parked ambiguous on lease expiry".to_string())
}

/// RTM-05 — unconfirmed launch: the scripted `Unknown` verdict persists
/// `attempt_ambiguous` certainty; the scheduler must never auto-relaunch
/// (exactly one launch call, node parked for operator).
pub async fn rtm_05(m: &mut Matrix) -> Result<String> {
    m.emit(None, vec![Matrix::child("lost-launch")]).await?;
    let worker = m.register_worker(4).await?;
    let mut claimed = m.sched.claim_ready(worker, 1).await?;
    let claim = claimed.swap_remove(0);
    m.launcher.script(claim.attempt.id, LaunchVerdict::Unknown);
    central_scheduler::app::dispatch::Dispatcher::new(
        m.sched.clone(),
        m.provisioner.clone(),
        m.launcher.clone(),
    )
    .dispatch(claim.clone())
    .await?;

    assert_eq!(m.launcher.calls().len(), 1, "no auto-relaunch");
    m.assert_attempt_state(claim.attempt.id, AttemptState::Ambiguous)
        .await?;
    m.assert_node_state(claim.attempt.node_id, NodeStatus::AttemptAmbiguous)
        .await?;
    m.assert_kinds(&["attempt_ambiguous"]).await?;
    Ok("unconfirmed launch parked ambiguous; single launch call".to_string())
}

/// RTM-06 — never-started lease expiry: the claimed-not-started attempt
/// fails `LEASE_EXPIRED_NOT_STARTED` and the node requeues `ready`.
pub async fn rtm_06(m: &mut Matrix) -> Result<String> {
    m.emit(None, vec![Matrix::child("no-start")]).await?;
    let worker = m.register_worker(4).await?;
    let claim = m.claim(worker).await?;

    m.force_expire(claim.lease.id).await?;
    m.sched.expire_leases(m.clock.now()).await?;

    m.assert_attempt_state(claim.attempt.id, AttemptState::Failed)
        .await?;
    m.assert_node_state(claim.attempt.node_id, NodeStatus::Ready)
        .await?;
    m.assert_reason("lease_expired", "LEASE_EXPIRED_NOT_STARTED")
        .await?;
    m.assert_no_live_leases().await?;
    Ok("never-started expiry failed + requeued".to_string())
}

/// RTM-07 — the missed-beat ladder: 2 missed heartbeats mark the worker
/// `worker_suspect`; 5 mark it `worker_lost` and park its live attempts
/// `attempt_ambiguous` (`ATTEMPT_AMBIGUOUS_WORKER_LOST`).
pub async fn rtm_07(m: &mut Matrix) -> Result<String> {
    m.emit(None, vec![Matrix::child("lost-worker")]).await?;
    let worker = m.register_worker(4).await?;
    let claim = m.claim_and_dispatch(worker).await?;

    // Two missed beats → suspect; five → lost.
    m.age_worker(
        worker,
        (crate::driver::HEARTBEAT.whole_seconds() * 2 + 1) as f64,
    )
    .await?;
    m.sched.sweep_suspects(m.clock.now()).await?;
    m.assert_kinds(&["worker_suspect"]).await?;

    m.age_worker(
        worker,
        (crate::driver::HEARTBEAT.whole_seconds() * 5 + 5) as f64,
    )
    .await?;
    m.force_expire(claim.lease.id).await?;
    m.sched.sweep_suspects(m.clock.now()).await?;
    m.sched.expire_leases(m.clock.now()).await?;

    m.assert_kinds(&["worker_lost"]).await?;
    m.assert_attempt_state(claim.attempt.id, AttemptState::Ambiguous)
        .await?;
    m.assert_reason("attempt_ambiguous", "ATTEMPT_AMBIGUOUS_WORKER_LOST")
        .await?;
    Ok("suspect→lost ladder parked the live attempt".to_string())
}

/// A consumer that always fails — leaves outbox rows unpublished so the
/// stall probe sees a real backlog.
struct FailingConsumer;
impl Consumer for FailingConsumer {
    fn consume<'a>(&'a self, _event: &'a RunEvent) -> ConsumerFuture<'a> {
        Box::pin(async { Err(Failure::unavailable("RTM_SINK_DOWN", "consumer down")) })
    }
}

/// RTM-15 — outbox publish stall: pending rows older than `stalled_age`
/// with a failing consumer flip the publisher's `stalled` flag
/// (`OUTBOX_PUBLISH_STALLED` warn path) deterministically — no sleeps.
pub async fn rtm_15(m: &mut Matrix) -> Result<String> {
    m.emit(None, vec![Matrix::child("stalled")]).await?;

    // Age every outbox row past the probe threshold.
    sqlx::query(
        "UPDATE central.event_outbox SET created_at = now() - interval '1 hour' \
         WHERE published_at IS NULL",
    )
    .execute(&mut m.admin)
    .await
    .map_err(|e| Failure::internal("RTM_FIXTURE", e.to_string()))?;

    let mut publisher = Publisher::new(PgJournalStore::new(m.pool.clone()));
    publisher.consumers.push(Arc::new(FailingConsumer));
    publisher.stalled_age = time::Duration::minutes(1);
    publisher.stalled_depth = 1;
    publisher.now = Some(Box::new(OffsetDateTime::now_utc));
    publisher.publish_once().await;

    assert!(publisher.stalled(), "stalled flag after aged backlog");
    let backlog: UnpublishedBacklog = publisher.store.unpublished_backlog().await?;
    assert!(backlog.depth >= 1, "backlog pending");
    Ok("aged unpublished backlog flagged stalled".to_string())
}

/// RTM-17 — restart reconcile: after a "process restart" (a fresh store
/// over the same database), `reconcile` rebuilds readiness and releases
/// orphaned claims exactly like upstream's crash-recovery pass.
pub async fn rtm_17(m: &mut Matrix) -> Result<String> {
    m.emit(None, vec![Matrix::child("survivor")]).await?;
    let worker = m.register_worker(4).await?;
    let claim = m.claim_and_dispatch(worker).await?;
    m.assert_attempt_state(claim.attempt.id, AttemptState::Started)
        .await?;

    // Simulate restart-side expiry: force the lease stale, expire it,
    // then reconcile rebuilds the durable view.
    m.force_expire(claim.lease.id).await?;
    m.sched.expire_leases(m.clock.now()).await?;
    m.sched.reconcile("reconciler").await?;

    m.assert_node_state(claim.attempt.node_id, NodeStatus::AttemptAmbiguous)
        .await?;
    // Operator decision resolves the parked node deterministically.
    m.wf.resolve_ambiguous(claim.attempt.node_id, "rerun", [1; 32], "operator:rtm")
        .await?;
    m.assert_kinds(&["attempt_decision"]).await?;
    Ok("reconcile + operator decision converged the run".to_string())
}
