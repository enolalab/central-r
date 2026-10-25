//! RTM-03/05/06/07/15/17 — the crash/leasing + capacity scenarios
//! (upstream `scenarioRTM03`, `scenarioRTM05`, `scenarioRTM06`,
//! `scenarioRTM07`, `scenarioRTM15`, `scenarioRTM17`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::missing_panics_doc)]

use central_foundation::identity::{ArtifactId, ContentGeneration};
use central_retry::domain::OutcomeKind;
use central_retry::port::Outcome;
use central_workflow::domain::NodeStatus;
use time::Duration;

use crate::driver::{HEARTBEAT, Matrix, Result};

fn fp(tag: &str) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(tag.as_bytes()).into()
}

/// RTM-03 — kill mid-attempt: a completed sibling's artifact survives;
/// the started attempt parks ambiguous; restart reconcile precedes the
/// next dispatch (upstream `scenarioRTM03`).
pub async fn rtm_03(m: &mut Matrix) -> Result<String> {
    let worker = m.register_worker(8).await?;
    // Upstream emits two INDEPENDENT siblings and claims both in one
    // FIFO sweep — no ordering edge between them.
    let mut a_spec = Matrix::child("rtm03-a");
    a_spec.workspace_kind = "directory".to_string();
    let mut b_spec = Matrix::child("rtm03-b");
    b_spec.workspace_kind = "directory".to_string();
    m.emit(None, vec![a_spec, b_spec]).await?;
    let a = m.node_by_key("rtm03-a").await?;
    let b = m.node_by_key("rtm03-b").await?;
    let claims = m.claim_n(worker, 2).await?;
    let a_claim = claims
        .iter()
        .find(|c| c.attempt.node_id == a)
        .cloned()
        .expect("claim sweep covered rtm03-a");
    let b_claim = claims
        .iter()
        .find(|c| c.attempt.node_id == b)
        .cloned()
        .expect("claim sweep covered rtm03-b");

    // A runs, completes, and finalizes its report — the completed
    // output a kill must never lose.
    m.launcher.script(
        a_claim.attempt.id,
        central_scheduler::port::LaunchVerdict::Started(format!("sess-{}", a_claim.attempt.id)),
    );
    m.dispatch(&a_claim).await?;
    m.note_kind("attempt_started");
    let sum = fp("rtm03-a-body");
    let artifact = ArtifactId::new();
    let generation = ContentGeneration::new();
    m.seed_verifying_artifact(artifact, sum, generation, "report")
        .await?;
    m.record_outcome(Outcome {
        attempt_id: a_claim.attempt.id,
        kind: OutcomeKind::Succeeded,
        reason_code: String::new(),
        fingerprint: fp("rtm03 a"),
        retry_after: None,
    })
    .await?;
    m.note_kind("attempt_succeeded");
    m.note_kind("node_succeeded");
    m.finalize_artifact(artifact, a_claim.attempt.id, a, "report", sum, generation)
        .await?;
    m.note_kind("artifact_finalized");

    // B dispatches + starts, then the "kill": its lease lapses mid-
    // flight — the started attempt parks ambiguous (upstream's killed-
    // attempt leg).
    m.launcher.script(
        b_claim.attempt.id,
        central_scheduler::port::LaunchVerdict::Started(format!("sess-{}", b_claim.attempt.id)),
    );
    m.dispatch(&b_claim).await?;
    m.assert_node_state(b, NodeStatus::Running).await?;
    m.force_expire(b_claim.lease.id).await?;
    m.note_kind("attempt_ambiguous");
    m.note_kind("lease_expired");
    m.note_reason("ATTEMPT_AMBIGUOUS_LEASE_EXPIRED");

    // A's completed artifact survives untouched — identical checksum.
    m.assert_artifact_checksum(artifact, sum).await?;

    // Restart: reopen the stores; the production reconcile pass itself
    // expires B's stale lease and parks it ambiguous BEFORE the next
    // dispatch — upstream `Reconciler.Run` ordering gate (no separate
    // expiry call: reconcile pass 1 scans expired live leases).
    m.reopen().await?;
    let marker = m.max_event_seq().await?;
    m.reconcile().await?;
    m.assert_node_state(a, NodeStatus::Succeeded).await?;
    m.assert_node_state(b, NodeStatus::AttemptAmbiguous).await?;
    m.assert_attempt_state(
        b_claim.attempt.id,
        central_scheduler::domain::AttemptState::Ambiguous,
    )
    .await?;
    m.assert_reason("attempt_ambiguous", "ATTEMPT_AMBIGUOUS_LEASE_EXPIRED")
        .await?;
    // A fresh probe node dispatches strictly after the reconcile
    // pass — the worker row survived the restart.
    let mut c_spec = Matrix::child("rtm03-c");
    c_spec.workspace_kind = "directory".to_string();
    m.emit(None, vec![c_spec]).await?;
    let c = m.node_by_key("rtm03-c").await?;
    let claim = m.claim_and_dispatch(worker).await?;
    assert_eq!(claim.attempt.node_id, c);
    m.note_kind("node_dispatched");
    let dispatch_seq = m.node_event_seq(c).await?;
    assert!(dispatch_seq > marker, "dispatch must follow reconcile");
    // Hygiene: close the probe attempt so no live lease survives.
    m.record_outcome(Outcome {
        attempt_id: claim.attempt.id,
        kind: OutcomeKind::Succeeded,
        reason_code: String::new(),
        fingerprint: fp("rtm03 c"),
        retry_after: None,
    })
    .await?;
    Ok("A succeeded with identical artifact checksum; B ambiguous/\
        attempt_ambiguous; post-restart node_dispatched ordered after \
        reconcile"
        .to_string())
}

/// RTM-05 — the missed-beat ladder: suspect at 2 missed beats is
/// observable-only; lost at 5 expires every held lease; quiet-worker
/// deregistration releases cleanly (upstream `scenarioRTM05`).
pub async fn rtm_05(m: &mut Matrix) -> Result<String> {
    let worker = m.register_worker(8).await?;
    m.emit(
        None,
        vec![Matrix::child("rtm05-idle"), Matrix::child("rtm05-live")],
    )
    .await?;
    let idle = m.node_by_key("rtm05-idle").await?;
    let live = m.node_by_key("rtm05-live").await?;

    // Upstream claims both in one sweep: idle never starts; live
    // dispatches + starts.
    let claims = m.claim_n(worker, 2).await?;
    assert_eq!(claims.len(), 2, "claims must cover both nodes");
    let idle_claim = claims
        .iter()
        .find(|c| c.attempt.node_id == idle)
        .cloned()
        .expect("claim sweep covered rtm05-idle");
    let live_claim = claims
        .iter()
        .find(|c| c.attempt.node_id == live)
        .cloned()
        .expect("claim sweep covered rtm05-live");
    m.launcher.script(
        live_claim.attempt.id,
        central_scheduler::port::LaunchVerdict::Started("sess-live".to_string()),
    );
    m.dispatch(&live_claim).await?;
    m.assert_node_state(live, NodeStatus::Running).await?;
    assert_eq!(idle_claim.attempt.node_id, idle);

    // 2 missed beats → worker_suspect journaled ONCE across a replay
    // pass with every lease still live (observable only). The ages are
    // computed off the lease heartbeat interval (upstream reads
    // `liveClaim.Lease.HeartbeatIntervalSec`; the pinned default is the
    // HEARTBEAT const).
    let suspect_at = (HEARTBEAT.whole_seconds() * 2 + 1) as f64;
    m.age_worker(worker, suspect_at).await?;
    m.sweep_suspects().await?;
    m.sweep_suspects().await?;
    assert_eq!(
        m.count_kind("worker_suspect").await?,
        1,
        "suspect must journal exactly once"
    );
    m.note_kind("worker_suspect");
    assert_eq!(
        m.worker_leases(worker).await?.len(),
        2,
        "suspect must be observable-only"
    );

    // Clean shutdown on a second worker (upstream interleaves this leg
    // between suspect and lost): a never-started lease releases, the
    // node requeues, the attempt consumed no retry budget.
    let quiet_worker = m.register_worker(4).await?;
    m.emit(None, vec![Matrix::child("rtm05-quiet")]).await?;
    let quiet = m.node_by_key("rtm05-quiet").await?;
    let quiet_claim = m.claim(quiet_worker).await?;
    assert_eq!(quiet_claim.attempt.node_id, quiet);
    m.deregister_worker(quiet_worker).await?;
    m.assert_node_state(quiet, NodeStatus::Ready).await?;
    assert_eq!(
        m.node_attempt_reason(quiet, 1).await?.as_deref(),
        Some("WORKER_SHUTDOWN_LEASE_RELEASED"),
        "quiet attempt reason"
    );
    m.assert_reason("node_ready", "WORKER_SHUTDOWN_LEASE_RELEASED")
        .await?;
    m.note_reason("WORKER_SHUTDOWN_LEASE_RELEASED");
    m.note_kind("worker_deregistered");
    m.note_kind("node_ready");

    // 5 missed beats → worker_lost expires BOTH of the loud worker's
    // leases: idle (never started) fails LEASE_EXPIRED_NOT_STARTED and
    // requeues ready; live (started) parks ATTEMPT_AMBIGUOUS_WORKER_LOST.
    let lost_at = (HEARTBEAT.whole_seconds() * 5 + 1) as f64;
    m.age_worker(worker, lost_at).await?;
    m.sweep_suspects().await?;
    assert_eq!(
        m.count_kind("worker_lost").await?,
        1,
        "worker_lost must journal exactly once"
    );
    m.note_kind("worker_lost");
    m.note_reason("WORKER_LOST_GRACE_EXPIRED");
    assert!(
        m.worker_leases(worker).await?.is_empty(),
        "lost expires every held lease"
    );
    m.assert_node_state(idle, NodeStatus::Ready).await?;
    assert_eq!(
        m.node_attempt_reason(idle, 1).await?.as_deref(),
        Some("LEASE_EXPIRED_NOT_STARTED"),
        "idle attempt reason"
    );
    m.assert_reason("lease_expired", "LEASE_EXPIRED_NOT_STARTED")
        .await?;
    m.note_reason("LEASE_EXPIRED_NOT_STARTED");
    m.assert_node_state(live, NodeStatus::AttemptAmbiguous)
        .await?;
    m.assert_attempt_state(
        live_claim.attempt.id,
        central_scheduler::domain::AttemptState::Ambiguous,
    )
    .await?;
    m.assert_reason("attempt_ambiguous", "ATTEMPT_AMBIGUOUS_WORKER_LOST")
        .await?;
    m.note_reason("ATTEMPT_AMBIGUOUS_WORKER_LOST");
    m.note_kind("lease_expired");
    m.note_kind("attempt_failed");
    m.note_kind("attempt_ambiguous");
    assert!(
        m.live_lease_ids().await?.is_empty(),
        "clean shutdown must release"
    );
    Ok(
        "worker_suspect once at 2 beats with leases live; worker_lost at 5 \
        beats expired both leases (idle ready, live ambiguous); shutdown \
        released the quiet lease"
            .to_string(),
    )
}

/// RTM-06 — never-started lease expiry: `LEASE_EXPIRED_NOT_STARTED`
/// fails the attempt and requeues the node; the reclaim lands as
/// attempt_seq 2 (upstream `scenarioRTM06`).
pub async fn rtm_06(m: &mut Matrix) -> Result<String> {
    let worker = m.register_worker(4).await?;
    m.emit(None, vec![Matrix::child("rtm06")]).await?;
    let node = m.node_by_key("rtm06").await?;
    let claim = m.claim(worker).await?; // claimed, never started
    m.force_expire(claim.lease.id).await?;
    let expired = m.expire_leases().await?;
    // Upstream asserts the expiry RESULT itself: our lease, landed once,
    // with the never-started reason.
    assert_eq!(expired.len(), 1, "expired: {expired:?}");
    assert_eq!(expired[0].lease_id, claim.lease.id);
    assert_eq!(
        expired[0].outcome.reason_code, "LEASE_EXPIRED_NOT_STARTED",
        "expiry outcome: {:?}",
        expired[0].outcome
    );
    m.assert_reason("lease_expired", "LEASE_EXPIRED_NOT_STARTED")
        .await?;
    m.note_reason("LEASE_EXPIRED_NOT_STARTED");
    m.note_kind("lease_expired");
    m.note_kind("node_ready");
    m.assert_attempt_state(
        claim.attempt.id,
        central_scheduler::domain::AttemptState::Failed,
    )
    .await?;
    m.assert_node_state(node, NodeStatus::Ready).await?;

    // The requeue is claimable as attempt_seq 2 under a fresh lease.
    let again = m.claim(worker).await?;
    assert_eq!(again.attempt.node_id, node);
    assert_eq!(again.attempt.attempt_seq, 2, "reclaim must take seq 2");
    m.deregister_worker(worker).await?;
    Ok("expired 1 never-started lease; node ready; reclaimed as \
        attempt_seq 2; lease_expired+node_ready journaled"
        .to_string())
}

/// RTM-07 — mid-flight expiry: a started attempt parks ambiguous with
/// NO automatic requeue; the stale lease fences renewals and durable
/// writes (upstream `scenarioRTM07`).
pub async fn rtm_07(m: &mut Matrix) -> Result<String> {
    let worker = m.register_worker(4).await?;
    m.emit(None, vec![Matrix::child("rtm07")]).await?;
    let node = m.node_by_key("rtm07").await?;
    let claim = m.claim_and_dispatch(worker).await?;

    // The lease TTL lapses mid-flight — `expire_leases` parks the
    // started attempt ambiguous (upstream's expiry path; the stale-
    // lease detection rides the fence, not a pre-expired row).
    m.force_expire(claim.lease.id).await?;
    let expired = m.expire_leases().await?;
    // Upstream's "fault did not land" idiom: our lease is among the
    // expiries with the ambiguous-park reason.
    let landed = expired
        .iter()
        .find(|r| r.lease_id == claim.lease.id)
        .expect("own lease must be among the expiries");
    assert_eq!(
        landed.outcome.reason_code, "ATTEMPT_AMBIGUOUS_LEASE_EXPIRED",
        "expiry outcome: {:?}",
        landed.outcome
    );
    m.assert_node_state(node, NodeStatus::AttemptAmbiguous)
        .await?;
    m.assert_attempt_state(
        claim.attempt.id,
        central_scheduler::domain::AttemptState::Ambiguous,
    )
    .await?;
    m.note_kind("attempt_ambiguous");
    m.note_kind("lease_expired");
    m.note_reason("ATTEMPT_AMBIGUOUS_LEASE_EXPIRED");

    // No automatic requeue: the node stays parked and a claim finds
    // nothing.
    assert!(
        m.claim_n(worker, 1).await?.is_empty(),
        "ambiguous must not requeue"
    );

    // The stale lease fences durable writes and renewals — upstream
    // requires the DENIED class on both.
    let err = m
        .fence(node, claim.attempt.id, claim.lease.id)
        .await
        .expect_err("stale lease must fence writes");
    m.expect_denied(&err, "LEASE_FENCE_STALE");
    let err = m
        .renew_lease(claim.lease.id, worker)
        .await
        .expect_err("stale lease must refuse renewal");
    m.expect_denied(&err, "LEASE_RENEWAL_STALE");
    m.assert_reason("lease_renewal_rejected", "LEASE_RENEWAL_STALE")
        .await?;
    m.note_kind("lease_renewal_rejected");
    Ok(
        "started lease expired to ambiguous/attempt_ambiguous; reclaim empty; \
        Fence+RenewLease refused stale with lease_renewal_rejected journaled"
            .to_string(),
    )
}

/// The stall leg's failing consumer — upstream `matrixFailingConsumer`:
/// every delivery errors, so nothing ever marks published.
struct FailingConsumer;

impl central_eventjournal::port::Consumer for FailingConsumer {
    fn consume<'a>(
        &'a self,
        _event: &'a central_eventjournal::domain::RunEvent,
    ) -> central_eventjournal::port::ConsumerFuture<'a> {
        Box::pin(async {
            Err(central_foundation::failure::Failure::internal(
                "MATRIX_CONSUMER",
                "consumer down",
            ))
        })
    }
}

/// The `EventLog` double capturing `(level, message, fields)` records —
/// the OUTBOX_PUBLISH_STALLED log-line assertion rides it.
#[derive(Debug, Default)]
struct CapturedLog {
    warns: std::sync::Mutex<Vec<String>>,
}

impl central_eventjournal::app::EventLog for CapturedLog {
    fn info(&self, _message: &'static str, _fields: &[(&'static str, String)]) {}
    fn warn(&self, message: &'static str, fields: &[(&'static str, String)]) {
        self.warns
            .lock()
            .unwrap()
            .push(format!("{message} {fields:?}"));
    }
}

/// RTM-15 — admission: the disk floor denies at the pure gate, the
/// session cap defers B with its FIFO stamp untouched and no attempt
/// row, freeing capacity dispatches B, and a stalled outbox raises
/// OUTBOX_PUBLISH_STALLED via flag+log+health while B's mid-stall
/// outcome commits correctly (upstream `scenarioRTM15`).
pub async fn rtm_15(m: &mut Matrix) -> Result<String> {
    let worker = m.register_worker(4).await?;

    // Disk-floor half: the claim path leaves disk unmeasured until
    // composition wires a device-capacity port, so the matrix drives
    // the pure gate directly with a measured snapshot (upstream parity).
    let profile = central_scheduler::admission::ConcurrencyProfile {
        max_parallel_sessions: 1,
        max_inflight_nodes: 1,
        ..Default::default()
    };
    profile
        .validate()
        .map_err(|e| central_foundation::failure::Failure::internal("RTM15", e.to_string()))?;
    let denied = central_scheduler::admission::check_dispatch_admission(
        &profile,
        &central_scheduler::admission::AdmissionSnapshot {
            disk_measured: true,
            free_bytes: 1,
            disk_budget_bytes: 1 << 30,
            ..central_scheduler::admission::AdmissionSnapshot::default()
        },
    );
    assert!(
        !denied.admit && denied.reason_code == Some("CAPACITY_ADMISSION_DEFERRED"),
        "disk-floor verdict = {denied:?}, want deferral"
    );
    let admitted = central_scheduler::admission::check_dispatch_admission(
        &profile,
        &central_scheduler::admission::AdmissionSnapshot {
            disk_measured: true,
            free_bytes: 1 << 40,
            disk_budget_bytes: 1 << 30,
            ..central_scheduler::admission::AdmissionSnapshot::default()
        },
    );
    assert!(admitted.admit, "disk gate admits nothing: {admitted:?}");

    // Install the bounded profile on the composed store.
    let mut sched = central_adapter_postgres::scheduler::PgSchedulerStore::new(
        m.pool.clone(),
        vec!["claude-code".to_string()],
    );
    sched.clock = Some(m.clock.clone());
    sched.killer = Some(m.killer.clone());
    sched.compensation = Some(m.compensation.clone());
    sched.jitter = Some(std::sync::Arc::new(|| 0.0_f64));
    sched.admission_profile = Some(profile);
    m.sched = std::sync::Arc::new(sched);

    // Session-cap half: A wins the single slot; B defers with its FIFO
    // stamp untouched and no attempt row.
    m.emit(
        None,
        vec![Matrix::child("rtm15-a"), Matrix::child("rtm15-b")],
    )
    .await?;
    let a = m.node_by_key("rtm15-a").await?;
    let b = m.node_by_key("rtm15-b").await?;
    let b_ready_at = m
        .ready_at(b)
        .await?
        .expect("deferred node carries a ready_at stamp");
    let claims = m.claim_n(worker, 2).await?;
    assert_eq!(
        claims.len(),
        1,
        "capped claim landed {claims:?}, want A only"
    );
    assert_eq!(claims[0].attempt.node_id, a);
    m.assert_node_state(b, NodeStatus::Ready).await?;
    assert_eq!(
        m.ready_at(b).await?,
        Some(b_ready_at),
        "deferred ready_at moved"
    );
    assert_eq!(
        m.node_attempt_states(b).await?.len(),
        0,
        "a deferred node carries zero attempt rows"
    );
    // The deferral row is node-scoped on B, carries NO attempt id, and
    // journals the one deferral code.
    let deferrals: Vec<_> = m
        .events()
        .await?
        .into_iter()
        .filter(|(kind, node, _, _)| {
            kind == "admission_deferred" && node.as_deref() == Some(b.to_string().as_str())
        })
        .collect();
    assert_eq!(
        deferrals.len(),
        1,
        "admission_deferred rows for B: {deferrals:?}"
    );
    assert!(
        deferrals[0].2.is_none(),
        "deferral carries an attempt id — none may exist: {:?}",
        deferrals[0]
    );
    assert_eq!(
        deferrals[0].3.as_deref(),
        Some("CAPACITY_ADMISSION_DEFERRED"),
        "deferral reason: {:?}",
        deferrals[0]
    );
    m.note_reason("CAPACITY_ADMISSION_DEFERRED");
    m.note_kind("admission_deferred");

    // Completing A re-evaluates: B dispatches.
    m.launcher.script(
        claims[0].attempt.id,
        central_scheduler::port::LaunchVerdict::Started("sess-a".to_string()),
    );
    m.dispatch(&claims[0]).await?;
    m.record_outcome(Outcome {
        attempt_id: claims[0].attempt.id,
        kind: OutcomeKind::Succeeded,
        reason_code: String::new(),
        fingerprint: fp("rtm15 a"),
        retry_after: None,
    })
    .await?;
    let second = m.claim(worker).await?;
    assert_eq!(second.attempt.node_id, b, "re-evaluation must claim B");
    m.launcher.script(
        second.attempt.id,
        central_scheduler::port::LaunchVerdict::Started("sess-b".to_string()),
    );
    m.dispatch(&second).await?;
    m.note_kind("node_dispatched");

    // Stall half: a real outbox publisher with a failing consumer over a
    // second pool handle — the drain keeps failing, the tight depth
    // threshold raises the stall, and a transition committed mid-stall
    // stays correct (upstream's bounded `Publisher.Run` window is three
    // sequential `publish_once` passes here).
    let log = std::sync::Arc::new(CapturedLog::default());
    let mut publisher = central_eventjournal::app::publisher::Publisher::new(
        central_adapter_postgres::eventjournal::Store::new(m.pool.clone()),
    );
    publisher.consumers = vec![std::sync::Arc::new(FailingConsumer)];
    publisher.log = Some(log.clone());
    publisher.stalled_depth = 1;
    publisher.stalled_age = Duration::hours(1);
    for _ in 0..3 {
        publisher.publish_once().await;
    }
    assert!(publisher.stalled(), "publisher did not raise the stall");
    assert!(
        log.warns
            .lock()
            .unwrap()
            .iter()
            .any(|w| w.contains("OUTBOX_PUBLISH_STALLED")),
        "stall log lacks the code: {:?}",
        log.warns.lock().unwrap()
    );
    let health = m.outbox_health().await?;
    assert!(
        health.unpublished_depth > 0 && health.oldest_unpublished.is_some(),
        "outbox health = {health:?}, want depth with an oldest row"
    );
    // B's outcome commits mid-stall — publication state never gates
    // transitions.
    m.record_outcome(Outcome {
        attempt_id: second.attempt.id,
        kind: OutcomeKind::Succeeded,
        reason_code: String::new(),
        fingerprint: fp("rtm15 b"),
        retry_after: None,
    })
    .await?;
    m.assert_node_state(b, NodeStatus::Succeeded).await?;
    assert_eq!(
        m.count_node_kind(b, "node_succeeded").await?,
        1,
        "B node_succeeded rows"
    );
    m.note_kind("node_succeeded");
    assert!(m.worker_leases(worker).await?.is_empty(), "cleanup leases");
    m.assert_run_clean().await?;
    Ok(
        "disk floor deferred directly (and admits a healthy snapshot); A \
        claimed while B deferred with ready_at untouched and no attempt \
        row; completing A dispatched B; stalled drain raised \
        OUTBOX_PUBLISH_STALLED via flag+log+health while B's outcome \
        committed correct"
            .to_string(),
    )
}

/// RTM-17 — the starvation bound: ten saturated claims leave B ready
/// with an unchanged ready_at and exactly one entry-only deferral;
/// freeing the slot dispatches B (upstream `scenarioRTM17`).
pub async fn rtm_17(m: &mut Matrix) -> Result<String> {
    let worker = m.register_worker(4).await?;
    // One parallel session + one inflight node — the caps the
    // saturation leg sits behind (the worker itself has headroom, so
    // only admission defers).
    let mut sched = central_adapter_postgres::scheduler::PgSchedulerStore::new(
        m.pool.clone(),
        vec!["claude-code".to_string()],
    );
    sched.clock = Some(m.clock.clone());
    sched.killer = Some(m.killer.clone());
    sched.compensation = Some(m.compensation.clone());
    sched.jitter = Some(std::sync::Arc::new(|| 0.0_f64));
    let profile = central_scheduler::admission::ConcurrencyProfile {
        max_parallel_sessions: 1,
        max_inflight_nodes: 1,
        ..Default::default()
    };
    profile
        .validate()
        .map_err(|e| central_foundation::failure::Failure::internal("RTM17", e.to_string()))?;
    sched.admission_profile = Some(profile);
    m.sched = std::sync::Arc::new(sched);
    m.emit(
        None,
        vec![Matrix::child("rtm17-a"), Matrix::child("rtm17-b")],
    )
    .await?;
    let b = m.node_by_key("rtm17-b").await?;
    // A holds the single slot as a live session for the whole window.
    let holding = m.claim(worker).await?;
    m.launcher.script(
        holding.attempt.id,
        central_scheduler::port::LaunchVerdict::Started("sess-17a".to_string()),
    );
    m.dispatch(&holding).await?;
    let ready_before = m
        .ready_at(b)
        .await?
        .expect("deferred node carries a ready_at stamp");

    // Sustained saturation: ten re-evaluations never starve B's FIFO
    // position — state and ready_at hold on EVERY pass and the
    // deferral journals entry-only.
    for i in 0..10 {
        assert!(
            m.claim_n(worker, 1).await?.is_empty(),
            "saturated claim {i} admitted work"
        );
        m.assert_node_state(b, NodeStatus::Ready).await?;
        assert_eq!(
            m.ready_at(b).await?,
            Some(ready_before),
            "deferred ready_at moved on pass {i}"
        );
    }
    assert_eq!(
        m.count_node_kind(b, "admission_deferred").await?,
        1,
        "exactly one entry-only admission_deferred"
    );
    m.note_kind("admission_deferred");
    m.note_reason("CAPACITY_ADMISSION_DEFERRED");

    // Freeing capacity dispatches B within the bound: the next claim.
    m.record_outcome(Outcome {
        attempt_id: holding.attempt.id,
        kind: OutcomeKind::Succeeded,
        reason_code: String::new(),
        fingerprint: fp("rtm17 a"),
        retry_after: None,
    })
    .await?;
    let freed = m.claim(worker).await?;
    assert_eq!(freed.attempt.node_id, b, "B must dispatch within the bound");
    m.launcher.script(
        freed.attempt.id,
        central_scheduler::port::LaunchVerdict::Started("sess-17b".to_string()),
    );
    m.dispatch(&freed).await?;
    m.note_kind("node_dispatched");
    m.record_outcome(Outcome {
        attempt_id: freed.attempt.id,
        kind: OutcomeKind::Succeeded,
        reason_code: String::new(),
        fingerprint: fp("rtm17 b"),
        retry_after: None,
    })
    .await?;
    m.note_kind("node_succeeded");
    assert!(m.worker_leases(worker).await?.is_empty(), "cleanup leases");
    m.assert_run_clean().await?;
    Ok(
        "B held ready_at across 10 saturated re-evaluations with one \
        entry-only deferral; freeing the slot dispatched B on the next \
        claim"
            .to_string(),
    )
}
