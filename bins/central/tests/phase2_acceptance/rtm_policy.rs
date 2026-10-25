//! RTM-02/04/08/13/16 + RTM-19-{session,deadlines} — the retry-policy
//! and timeout scenarios (upstream `scenarioRTM02`, `scenarioRTM04`,
//! `scenarioRTM08`, `scenarioRTM13`, `scenarioRTM16`,
//! `scenarioRTM19Session`, `scenarioRTM19Deadlines`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::missing_panics_doc)]

use central_retry::domain::{FailureClass, OutcomeKind};
use central_retry::port::Outcome;
use central_workflow::domain::NodeStatus;
use time::Duration;

use crate::driver::{Matrix, Result};

fn fp(tag: &str) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(tag.as_bytes()).into()
}

/// One failed-outcome cycle on `claim` (upstream's report leg): the
/// definite failure commits the ledger row, the transition, and the
/// journaled events in one transaction.
async fn fail(
    m: &mut Matrix,
    attempt: central_foundation::identity::SessionAttemptId,
    code: &str,
    retry_after: Option<Duration>,
    tag: &str,
) -> Result<central_retry::port::OutcomeResult> {
    m.record_outcome(Outcome {
        attempt_id: attempt,
        kind: OutcomeKind::Failed,
        reason_code: code.to_string(),
        fingerprint: fp(tag),
        retry_after,
    })
    .await
}

/// RTM-02 — a transient failure requeues under the journaled backoff
/// (upstream `scenarioRTM02`).
pub async fn rtm_02(m: &mut Matrix) -> Result<String> {
    let worker = m.register_worker(4).await?;
    m.emit(None, vec![Matrix::child("rtm02")]).await?;
    let node = m.node_by_key("rtm02").await?;
    let claim = m.claim_and_dispatch(worker).await?;
    let before = m.clock.now();
    let out = fail(m, claim.attempt.id, "PROCESS_EXIT_NONZERO", None, "rtm02").await?;
    assert_eq!(out.class, FailureClass::Transient, "outcome class: {out:?}");
    assert_eq!(out.node_status, "ready", "transient must requeue");
    assert!(out.retry_at.is_some(), "retry_at must be set");
    // Pinned zero jitter: retry_at == evaluation instant, still a real
    // journaled stamp (upstream asserts non-nil + ready). timestamptz
    // truncates to microseconds, so bound a 1s slack below `before`.
    let not_before = m
        .not_before(node)
        .await?
        .expect("retry must stamp not_before");
    assert!(
        not_before >= before - Duration::seconds(1),
        "not_before must be set near now: {not_before}"
    );
    m.assert_reason("attempt_failed", "PROCESS_EXIT_NONZERO")
        .await?;
    m.note_reason("PROCESS_EXIT_NONZERO");
    m.note_kind("attempt_failed");
    m.note_kind("attempt_retry_scheduled");
    m.note_kind("node_ready");
    Ok("PROCESS_EXIT_NONZERO failed the attempt (transient); \
        attempt_retry_scheduled; node ready with not_before set"
        .to_string())
}

/// RTM-04 — rate-limit hints: honored exactly inside the cap, capped at
/// the policy cap, ignored off-class; a terminal class lands at once
/// (upstream `scenarioRTM04`).
pub async fn rtm_04(m: &mut Matrix) -> Result<String> {
    let worker = m.register_worker(4).await?;
    m.emit(None, vec![Matrix::child("rtm04")]).await?;
    let node = m.node_by_key("rtm04").await?;

    let cap = central_retry::domain::RetryPolicy::default().cap;

    // Attempt 1: the 90s hint is honored exactly (bound form, robust to
    // the backoff formula — upstream's window).
    let claim = m.claim_and_dispatch(worker).await?;
    let t0 = m.clock.now();
    let out = fail(
        m,
        claim.attempt.id,
        "RATE_LIMITED",
        Some(Duration::seconds(90)),
        "rtm04 rl-90",
    )
    .await?;
    assert_eq!(out.node_status, "ready", "attempt-1 result: {out:?}");
    assert!(out.retry_at.is_some(), "attempt-1 retry_at set");
    m.note_reason("RATE_LIMITED");
    let bound = Duration::seconds(90).min(cap);
    let nb = m.not_before(node).await?.expect("attempt-1 not_before set");
    assert!(
        nb > t0 + bound - Duration::seconds(30) && nb <= t0 + bound + Duration::seconds(10),
        "not_before = {nb}, want within ({}, {}] (hint honored)",
        t0 + bound - Duration::seconds(30),
        t0 + bound + Duration::seconds(10)
    );

    // Attempt 2: a 48h hint is capped by the policy cap.
    m.clear_not_before(node).await?;
    let claim2 = m.claim_and_dispatch(worker).await?;
    let t0 = m.clock.now();
    let out = fail(
        m,
        claim2.attempt.id,
        "RATE_LIMITED",
        Some(Duration::hours(48)),
        "rtm04 rl-48h",
    )
    .await?;
    assert_eq!(out.node_status, "ready", "attempt-2 result: {out:?}");
    let nb = m.not_before(node).await?.expect("attempt-2 not_before set");
    assert!(
        nb > t0 + cap - Duration::seconds(30) && nb <= t0 + cap + Duration::seconds(10),
        "not_before = {nb}, want within ({}, {}] (cap binds)",
        t0 + cap - Duration::seconds(30),
        t0 + cap + Duration::seconds(10)
    );

    // Attempt 3: a non-rate-limited report with retry_after set ignores
    // the hint (a dispatch_infra failure keeps budget headroom).
    m.clear_not_before(node).await?;
    let claim3 = m.claim_and_dispatch(worker).await?;
    let t0 = m.clock.now();
    let out = fail(
        m,
        claim3.attempt.id,
        "WORKSPACE_PROVISION_FAILED",
        Some(Duration::seconds(90)),
        "rtm04 offclass",
    )
    .await?;
    assert_eq!(out.node_status, "ready", "attempt-3 result: {out:?}");
    let nb = m.not_before(node).await?.expect("attempt-3 not_before set");
    // timestamptz truncates to microseconds — bound the window with a
    // 1s slack (upstream's [t0, t0+90s) shape).
    assert!(
        nb >= t0 - Duration::seconds(1) && nb < t0 + Duration::seconds(90),
        "not_before = {nb}, want within [{}, {}) (hint ignored)",
        t0 - Duration::seconds(1),
        t0 + Duration::seconds(90)
    );
    m.assert_reason("attempt_failed", "RATE_LIMITED").await?;

    // Hygiene: a terminal-class failure ends the node; no ready nodes
    // and no live leases survive.
    m.clear_not_before(node).await?;
    let claim4 = m.claim_and_dispatch(worker).await?;
    let out = fail(m, claim4.attempt.id, "BUDGET_EXHAUSTED", None, "rtm04 term").await?;
    assert_eq!(out.node_status, "failed_terminal");
    m.assert_node_state(node, NodeStatus::FailedTerminal)
        .await?;
    m.assert_reason("node_failed_terminal", "BUDGET_EXHAUSTED")
        .await?;
    m.note_reason("BUDGET_EXHAUSTED");
    m.note_kind("attempt_failed");
    m.note_kind("attempt_retry_scheduled");
    m.note_kind("node_ready");
    m.note_kind("node_failed_terminal");
    assert!(m.worker_leases(worker).await?.is_empty(), "cleanup leases");
    m.assert_run_clean().await?;
    Ok(
        "90s hint honored (not_before in bound); 48h hint capped at the \
        10m policy cap; dispatch_infra report ignored its hint; terminal \
        failure closed the node"
            .to_string(),
    )
}

/// RTM-08 — outcome-replay dedupe and emission idempotency: an exact
/// replay returns the recorded result with exactly one extra journal
/// row; a divergent fingerprint refuses DUPLICATE_IDEMPOTENCY_KEY; a
/// re-emitted batch dedupes (upstream `scenarioRTM08`).
pub async fn rtm_08(m: &mut Matrix) -> Result<String> {
    let worker = m.register_worker(4).await?;
    m.emit(None, vec![Matrix::child("rtm08")]).await?;
    let node = m.node_by_key("rtm08").await?;
    let claim = m.claim_and_dispatch(worker).await?;
    let outcome = Outcome {
        attempt_id: claim.attempt.id,
        kind: OutcomeKind::Succeeded,
        reason_code: String::new(),
        fingerprint: fp("rtm08 outcome"),
        retry_after: None,
    };
    let first = m.record_outcome(outcome.clone()).await?;
    assert!(!first.deduped, "fresh commit must not dedupe");
    assert_eq!(first.node_status, "succeeded");
    let succ_before = m.count_node_kind(node, "attempt_succeeded").await?;
    let total_before = m.journal_row_count().await?;
    m.note_kind("attempt_succeeded");

    // Exact replay: the recorded result returns deduped AND identical
    // (class + node_status + retry_at) — no second transition, exactly
    // one `command_deduped` row.
    let replay = m.record_outcome(outcome).await?;
    assert!(replay.deduped, "exact replay must dedupe");
    assert_eq!(
        (replay.class, replay.node_status.as_str(), replay.retry_at),
        (first.class, first.node_status.as_str(), first.retry_at),
        "replay result must be identical to the committed result"
    );
    assert_eq!(
        m.count_node_kind(node, "attempt_succeeded").await?,
        succ_before,
        "replay moved the attempt_succeeded count"
    );
    assert_eq!(
        m.count_node_kind(node, "command_deduped").await?,
        1,
        "replay journals exactly one command_deduped"
    );
    assert_eq!(
        m.journal_row_count().await?,
        total_before + 1,
        "journal moved by the dedupe row only"
    );
    m.note_kind("command_deduped");

    // Same key, different fingerprint → DUPLICATE_IDEMPOTENCY_KEY
    // (upstream requires the CONFLICT class).
    let divergent = Outcome {
        fingerprint: fp("rtm08 other"),
        ..Outcome {
            attempt_id: claim.attempt.id,
            kind: OutcomeKind::Succeeded,
            reason_code: String::new(),
            fingerprint: fp("rtm08 outcome"),
            retry_after: None,
        }
    };
    let err = m
        .record_outcome(divergent)
        .await
        .expect_err("divergent fingerprint must refuse");
    m.expect_conflict(&err, "DUPLICATE_IDEMPOTENCY_KEY");

    // Re-emission dedupes: the committed node ids come back with no
    // second node_declared; the emit replay is the second dedupe row.
    let emit = m.emit(None, vec![Matrix::child("rtm08")]).await?;
    assert_eq!(emit.nodes.len(), 1);
    assert_eq!(
        emit.nodes[0].id, node,
        "re-emit returns the committed node id"
    );
    assert_eq!(
        m.count_node_kind(node, "node_declared").await?,
        1,
        "no second declaration"
    );
    assert_eq!(
        m.count_kind("command_deduped").await?,
        2,
        "outcome + emit replays journal two dedupe rows"
    );
    m.note_kind("node_declared");
    Ok("outcome replay deduped (one attempt_succeeded, +1 \
        command_deduped, no re-transition, replay result identical to \
        the commit); different fingerprint conflicted \
        DUPLICATE_IDEMPOTENCY_KEY; re-emit returned the committed node \
        id with no second node_declared"
        .to_string())
}

/// RTM-13 — retry budget: three transient failures exhaust to
/// RETRY_BUDGET_EXHAUSTED (counts 3/3); a terminal class lands its own
/// code; managed and unmanaged `on_terminal_failure` hooks behave per
/// spec; the managed replay dedupes (upstream `scenarioRTM13`).
pub async fn rtm_13(m: &mut Matrix) -> Result<String> {
    let worker = m.register_worker(8).await?;
    let mut a = Matrix::child("rtm13-a");
    a.max_attempts_total = Some(3);
    // The "dependent stays declared" witness rides behind A.
    let mut dep = Matrix::child("rtm13-dep");
    dep.depends_on = vec!["rtm13-a".to_string()];
    m.emit(None, vec![a, dep]).await?;
    let a = m.node_by_key("rtm13-a").await?;
    let dep = m.node_by_key("rtm13-dep").await?;

    // Three transient failures exhaust A's budget — upstream asserts
    // the per-attempt seq and the ready→ready→failed_terminal
    // progression.
    for seq in 1..=3i32 {
        m.clear_not_before(a).await?;
        let claim = m.claim_and_dispatch(worker).await?;
        assert_eq!(claim.attempt.node_id, a);
        assert_eq!(claim.attempt.attempt_seq, seq, "budget attempt seq");
        let out = fail(
            m,
            claim.attempt.id,
            "PROCESS_EXIT_NONZERO",
            None,
            &format!("rtm13 a {seq}"),
        )
        .await?;
        let want = if seq < 3 { "ready" } else { "failed_terminal" };
        assert_eq!(
            out.node_status, want,
            "budget failure {seq} -> {}, want {want}",
            out.node_status
        );
    }
    m.assert_node_state(a, NodeStatus::FailedTerminal).await?;
    m.assert_reason("node_failed_terminal", "RETRY_BUDGET_EXHAUSTED")
        .await?;
    m.note_reason("RETRY_BUDGET_EXHAUSTED");
    let counts = m.attempt_counts(a).await?;
    assert_eq!(counts.total, 3, "attempt count: {counts:?}");
    assert_eq!(
        counts
            .per_class
            .get(&FailureClass::Transient)
            .copied()
            .unwrap_or(0),
        3,
        "transient count: {counts:?}"
    );

    // A dependent stays declared behind the terminal parent.
    m.assert_node_state(dep, NodeStatus::Declared).await?;

    // B's terminal class lands its own code at once; the managed and
    // unmanaged hook roots ride the same second batch (`d` is the
    // stays-declared witness behind B).
    let mut d = Matrix::child("rtm13-d");
    d.depends_on = vec!["rtm13-b".to_string()];
    let mut managed = Matrix::child("rtm13-managed");
    managed.on_terminal_failure = "cleanup_workspace".to_string();
    let mut unmanaged = Matrix::child("rtm13-u");
    unmanaged.on_terminal_failure = "operator-handles-it".to_string();
    m.emit(None, vec![Matrix::child("rtm13-b"), d, managed, unmanaged])
        .await?;
    let b = m.node_by_key("rtm13-b").await?;
    let d = m.node_by_key("rtm13-d").await?;
    let managed = m.node_by_key("rtm13-managed").await?;
    let unmanaged = m.node_by_key("rtm13-u").await?;
    let claim = m.claim_and_dispatch(worker).await?;
    assert_eq!(claim.attempt.node_id, b);
    let out = fail(m, claim.attempt.id, "BUDGET_EXHAUSTED", None, "rtm13 b").await?;
    assert_eq!(out.node_status, "failed_terminal");
    m.assert_reason("node_failed_terminal", "BUDGET_EXHAUSTED")
        .await?;
    m.note_reason("BUDGET_EXHAUSTED");
    // Upstream's dependent witness behind the terminal-class parent.
    m.assert_node_state(d, NodeStatus::Declared).await?;

    // Hook evaluation: the managed node's terminal failure executes
    // `cleanup_workspace` once inside the outcome commit — the request
    // + the executed result journal as TWO `compensation_requested`
    // rows (the second's payload records result=executed); the
    // unmanaged node's request journals once and never executes.
    let managed_claim = m.claim_and_dispatch(worker).await?;
    assert_eq!(managed_claim.attempt.node_id, managed);
    let cleanup_calls = m.compensation_calls();
    fail(
        m,
        managed_claim.attempt.id,
        "BUDGET_EXHAUSTED",
        None,
        "rtm13 managed",
    )
    .await?;
    assert_eq!(
        m.compensation_calls() - cleanup_calls,
        1,
        "managed hook must execute once"
    );
    m.assert_node_state(managed, NodeStatus::FailedTerminal)
        .await?;
    assert_eq!(
        m.count_node_kind(managed, "compensation_requested").await?,
        2,
        "managed rows: request + executed"
    );
    let managed_events = m.run_events().await?;
    let executed = managed_events
        .iter()
        .filter(|e| e.kind == "compensation_requested" && e.node_id == Some(managed))
        .any(|e| e.payload["result"] == "executed");
    assert!(executed, "managed hook must journal an executed result row");
    let unmanaged_claim = m.claim_and_dispatch(worker).await?;
    assert_eq!(unmanaged_claim.attempt.node_id, unmanaged);
    fail(
        m,
        unmanaged_claim.attempt.id,
        "BUDGET_EXHAUSTED",
        None,
        "rtm13 unmanaged",
    )
    .await?;
    assert_eq!(
        m.count_node_kind(unmanaged, "compensation_requested")
            .await?,
        1,
        "unmanaged rows: request only"
    );

    // Replay dedupes on the committed request rows — executor
    // untouched, counts unmoved.
    m.run_compensation(managed).await?;
    m.run_compensation(unmanaged).await?;
    assert_eq!(
        m.compensation_calls() - cleanup_calls,
        1,
        "replays dedupe; unmanaged hook never executes"
    );
    assert_eq!(
        m.count_node_kind(managed, "compensation_requested").await?,
        2,
        "managed rows after replay"
    );
    assert_eq!(
        m.count_node_kind(unmanaged, "compensation_requested")
            .await?,
        1,
        "unmanaged rows after replay"
    );
    m.note_kind("compensation_requested");
    m.note_kind("node_ready");
    m.note_kind("node_failed_terminal");
    assert!(m.worker_leases(worker).await?.is_empty(), "cleanup leases");
    m.assert_run_clean().await?;
    Ok("3 transient failures exhausted (counts 3/3) \
        RETRY_BUDGET_EXHAUSTED; terminal class landed BUDGET_EXHAUSTED \
        with the dependent declared; managed hook cleaned once + \
        executed result, replay deduped; unmanaged request-only, \
        executor untouched"
        .to_string())
}

/// RTM-16 — the operator gate: ambiguous nodes skip the timer sweeps;
/// `rerun` readies the node under one `attempt_decision`; replay is
/// DENIED; `resume` replay dedupes; the rerun claims sequence 2
/// (upstream `scenarioRTM16`).
pub async fn rtm_16(m: &mut Matrix) -> Result<String> {
    let worker = m.register_worker(4).await?;
    // Upstream declares the node bound on both nodes at emit
    // (`NodeTimeoutSeconds: 3600`).
    let mut rerun_spec = Matrix::child("rtm16-rerun");
    rerun_spec.node_timeout_seconds = Some(3600);
    let mut resume_spec = Matrix::child("rtm16-resume");
    resume_spec.node_timeout_seconds = Some(3600);
    m.emit(None, vec![rerun_spec, resume_spec]).await?;
    let rerun_node = m.node_by_key("rtm16-rerun").await?;
    let resume_node = m.node_by_key("rtm16-resume").await?;

    // Park both nodes: claimed+dispatched in one sweep, both leases
    // lapse, both expire into ambiguity.
    let claims = m.claim_n(worker, 2).await?;
    assert_eq!(claims.len(), 2, "claims must cover both nodes");
    for claim in &claims {
        m.launcher.script(
            claim.attempt.id,
            central_scheduler::port::LaunchVerdict::Started(format!("sess-{}", claim.attempt.id)),
        );
        m.dispatch(claim).await?;
        m.force_expire(claim.lease.id).await?;
    }
    let expired = m.expire_leases().await?;
    for claim in &claims {
        let landed = expired
            .iter()
            .find(|r| r.lease_id == claim.lease.id)
            .expect("both parks must land");
        assert_eq!(
            landed.outcome.reason_code, "ATTEMPT_AMBIGUOUS_LEASE_EXPIRED",
            "park reason: {:?}",
            landed.outcome
        );
    }
    m.assert_node_state(rerun_node, NodeStatus::AttemptAmbiguous)
        .await?;
    m.assert_node_state(resume_node, NodeStatus::AttemptAmbiguous)
        .await?;
    m.assert_reason("attempt_ambiguous", "ATTEMPT_AMBIGUOUS_LEASE_EXPIRED")
        .await?;
    m.note_kind("attempt_ambiguous");
    m.note_kind("lease_expired");
    m.note_reason("ATTEMPT_AMBIGUOUS_LEASE_EXPIRED");

    // Timers never fire across the ambiguity: past both nodes'
    // aggregate bounds (anchored at first_dispatch_at, as upstream
    // computes the sweep instant), the sweep skips both.
    let first_rerun = m
        .first_dispatch_at(rerun_node)
        .await?
        .expect("rerun has a first dispatch");
    let first_resume = m
        .first_dispatch_at(resume_node)
        .await?
        .expect("resume has a first dispatch");
    let _ = (first_rerun, first_resume); // sweep time anchors (see clock)
    for claim in &claims {
        m.age_claimed_at(claim.attempt.id, 4000.0).await?;
    }
    let summary = m.sweep_timeouts().await?;
    for node in [rerun_node, resume_node] {
        assert!(
            summary
                .skipped_ambiguous
                .iter()
                .any(|s| matches!(s, central_retry::port::SkippedScope::Node(n) if *n == node)),
            "ambiguous node must be reported skipped: {summary:?}"
        );
        m.assert_node_state(node, NodeStatus::AttemptAmbiguous)
            .await?;
    }
    assert!(
        summary.workflow_timeouts.is_empty(),
        "ambiguous skips run timers"
    );
    assert_eq!(
        m.count_kind("node_failed_terminal").await?,
        0,
        "no node timer may land across ambiguity"
    );

    // Rerun branch: node ready, attempt_decision journaled once.
    m.resolve_ambiguous(rerun_node, "rerun", fp("rtm16 rerun"))
        .await?;
    m.assert_node_state(rerun_node, NodeStatus::Ready).await?;
    assert_eq!(
        m.count_node_kind(rerun_node, "attempt_decision").await?,
        1,
        "rerun journals exactly one attempt_decision"
    );
    m.note_kind("attempt_decision");
    m.note_kind("node_ready");

    // The rerun decision is one-shot: replaying it after the node left
    // attempt_ambiguous is DENIED per the port contract, not deduped.
    let err = m
        .resolve_ambiguous(rerun_node, "rerun", fp("rtm16 rerun"))
        .await
        .expect_err("rerun replay must deny");
    assert_eq!(
        err.kind(),
        central_foundation::failure::FailureKind::Denied,
        "rerun replay: {err:?}"
    );

    // Resume branch: the node stays parked, and the replayed
    // decision+fingerprint dedupes to command_deduped with no second
    // attempt_decision.
    m.resolve_ambiguous(resume_node, "resume", fp("rtm16 resume"))
        .await?;
    m.resolve_ambiguous(resume_node, "resume", fp("rtm16 resume"))
        .await?;
    m.assert_node_state(resume_node, NodeStatus::AttemptAmbiguous)
        .await?;
    assert_eq!(
        m.count_node_kind(resume_node, "attempt_decision").await?,
        1,
        "resume replay must not journal a second decision"
    );
    assert_eq!(m.count_kind("command_deduped").await?, 1, "one dedupe row");
    m.note_kind("command_deduped");

    // The rerun claims a fresh attempt_seq; hygiene releases it via the
    // never-started expiry path.
    let rerun = m.claim(worker).await?;
    assert_eq!(rerun.attempt.node_id, rerun_node);
    assert_eq!(rerun.attempt.attempt_seq, 2, "rerun takes attempt_seq 2");
    m.note_kind("node_dispatched");
    m.force_expire(rerun.lease.id).await?;
    m.expire_leases().await?;
    assert!(m.worker_leases(worker).await?.is_empty(), "cleanup leases");
    Ok(
        "sweep past the node bounds skipped both ambiguous nodes; rerun \
        readyed with one attempt_decision and claimed attempt_seq 2; \
        resume replay deduped"
            .to_string(),
    )
}

/// RTM-19-session — session wall-clock breaches through the production
/// `sweep_timeouts`/`sweep_session_breach_tx` path: a confirmed kill
/// closes retryable SESSION_WALL_CLOCK_REACHED with not_before; an
/// unconfirmed kill parks ambiguous (upstream `scenarioRTM19Session`).
pub async fn rtm_19_session(m: &mut Matrix) -> Result<String> {
    let worker = m.register_worker(4).await?;
    // The session wall-clock bound is the installed admission
    // profile's ceiling (`list_wall_clock_breaches` reads it) —
    // upstream installs the same bounded profile for this leg.
    let mut sched = central_adapter_postgres::scheduler::PgSchedulerStore::new(
        m.pool.clone(),
        vec!["claude-code".to_string()],
    );
    sched.clock = Some(m.clock.clone());
    sched.killer = Some(m.killer.clone());
    sched.jitter = Some(std::sync::Arc::new(|| 1.0_f64));
    let profile = central_scheduler::admission::ConcurrencyProfile {
        wall_clock_ceiling: time::Duration::seconds(60),
        ..Default::default()
    };
    sched.admission_profile = Some(profile);
    m.sched = std::sync::Arc::new(sched);
    let c1 = Matrix::child("rtm19s-confirmed");
    let c2 = Matrix::child("rtm19s-unconfirmed");
    m.emit(None, vec![c1, c2]).await?;
    let confirmed_node = m.node_by_key("rtm19s-confirmed").await?;
    let unconfirmed_node = m.node_by_key("rtm19s-unconfirmed").await?;

    let c_claim = m.claim_and_dispatch(worker).await?;
    m.age_started_at(c_claim.attempt.id, 120.0).await?;
    let u_claim = m.claim_and_dispatch(worker).await?;
    m.age_started_at(u_claim.attempt.id, 120.0).await?;
    m.killer.script(c_claim.attempt.id, true);
    m.killer.script(u_claim.attempt.id, false);

    // ONE sweep pass through the production path — no manual
    // list/kill/record.
    let summary = m.sweep_timeouts().await?;
    m.assert_attempt_state(
        c_claim.attempt.id,
        central_scheduler::domain::AttemptState::Failed,
    )
    .await?;
    m.assert_reason("attempt_failed", "SESSION_WALL_CLOCK_REACHED")
        .await?;
    assert_eq!(
        m.node_attempt_reason(confirmed_node, 1).await?,
        Some("SESSION_WALL_CLOCK_REACHED".to_string()),
        "attempt-1 reason row"
    );
    m.note_reason("SESSION_WALL_CLOCK_REACHED");
    m.note_kind("attempt_failed");
    m.note_kind("attempt_retry_scheduled");
    m.assert_node_state(confirmed_node, NodeStatus::Ready)
        .await?;
    assert!(
        m.not_before(confirmed_node).await?.is_some(),
        "retryable breach must stamp not_before"
    );
    m.note_kind("node_ready");
    m.assert_node_state(unconfirmed_node, NodeStatus::AttemptAmbiguous)
        .await?;
    m.assert_reason("attempt_ambiguous", "ATTEMPT_AMBIGUOUS_KILL_UNCONFIRMED")
        .await?;
    m.note_reason("ATTEMPT_AMBIGUOUS_KILL_UNCONFIRMED");
    m.note_kind("attempt_ambiguous");
    assert!(
        summary.skipped_ambiguous.iter().any(
            |s| matches!(s, central_retry::port::SkippedScope::Node(n) if *n == unconfirmed_node)
        ),
        "the unconfirmed breach must report skipped: {summary:?}"
    );
    m.deregister_worker(worker).await?;
    Ok(
        "confirmed kill landed SESSION_WALL_CLOCK_REACHED with node ready \
        under backoff; unconfirmed kill parked attempt_ambiguous"
            .to_string(),
    )
}

/// RTM-19-deadlines — node bounds land NODE_TIMEOUT; ambiguity skips
/// both timers; rerun unblocks the deferred timer; the workflow bound
/// cancels and lands WORKFLOW_TIMEOUT (upstream
/// `scenarioRTM19Deadlines`).
pub async fn rtm_19_deadlines(m: &mut Matrix) -> Result<String> {
    let worker = m.register_worker(8).await?;
    let node_timeout = Some(60);

    // Node half: first dispatch plus node_timeout passed lands terminal
    // under a confirmed kill (the definite session failure records
    // first; the bound dominates its retryability).
    let mut node_spec = Matrix::child("rtm19d-node");
    node_spec.node_timeout_seconds = node_timeout;
    m.emit(None, vec![node_spec]).await?;
    let node = m.node_by_key("rtm19d-node").await?;
    let n_claim = m.claim_and_dispatch(worker).await?;
    assert_eq!(n_claim.attempt.node_id, node);
    m.killer.script(n_claim.attempt.id, true);
    m.age_claimed_at(n_claim.attempt.id, 3600.0).await?;
    let summary = m.sweep_timeouts().await?;
    assert!(
        summary.node_timeouts.contains(&node),
        "node bound must land: {summary:?}"
    );
    m.assert_node_state(node, NodeStatus::FailedTerminal)
        .await?;
    assert_eq!(
        m.node_attempt_states(node).await?,
        vec![(1, "failed".to_string())],
        "attempt-1 state"
    );
    assert_eq!(
        m.node_attempt_reason(node, 1).await?,
        Some("SESSION_WALL_CLOCK_REACHED".to_string()),
        "attempt-1 reason row"
    );
    m.assert_reason("node_failed_terminal", "NODE_TIMEOUT")
        .await?;
    m.assert_reason("attempt_failed", "SESSION_WALL_CLOCK_REACHED")
        .await?;
    m.note_reason("NODE_TIMEOUT");
    m.note_reason("SESSION_WALL_CLOCK_REACHED");
    m.note_kind("node_failed_terminal");
    m.note_kind("attempt_failed");

    // Ambiguity half: a node parked ambiguous with an expired bound,
    // and a run past its deadline carrying that descendant, both skip.
    let mut amb = Matrix::child("rtm19d-amb");
    amb.node_timeout_seconds = node_timeout;
    let mut m3 = Matrix::child("rtm19d-m3");
    m3.depends_on = vec!["rtm19d-m2".to_string()];
    m.emit(
        None,
        vec![
            amb,
            Matrix::child("rtm19d-m1"),
            Matrix::child("rtm19d-m2"),
            m3,
        ],
    )
    .await?;
    let amb_node = m.node_by_key("rtm19d-amb").await?;
    let m1 = m.node_by_key("rtm19d-m1").await?;
    let m2 = m.node_by_key("rtm19d-m2").await?;
    let m3 = m.node_by_key("rtm19d-m3").await?;

    let a_claim = m.claim_and_dispatch(worker).await?;
    assert_eq!(a_claim.attempt.node_id, amb_node);
    m.force_expire(a_claim.lease.id).await?;
    let expired = m.expire_leases().await?;
    let landed = expired
        .iter()
        .find(|r| r.lease_id == a_claim.lease.id)
        .expect("amb park must land");
    assert_eq!(
        landed.outcome.reason_code, "ATTEMPT_AMBIGUOUS_LEASE_EXPIRED",
        "amb expiry: {:?}",
        landed.outcome
    );
    m.assert_node_state(amb_node, NodeStatus::AttemptAmbiguous)
        .await?;
    m.assert_reason("attempt_ambiguous", "ATTEMPT_AMBIGUOUS_LEASE_EXPIRED")
        .await?;
    m.note_reason("ATTEMPT_AMBIGUOUS_LEASE_EXPIRED");
    m.note_kind("attempt_ambiguous");
    m.note_kind("lease_expired");
    m.age_claimed_at(a_claim.attempt.id, 3600.0).await?;
    let m1_claim = m.claim_and_dispatch(worker).await?;
    assert_eq!(m1_claim.attempt.node_id, m1);
    m.killer.script(m1_claim.attempt.id, true);
    m.set_run_deadline(1.0).await?;
    let summary = m.sweep_timeouts().await?;
    assert!(
        summary
            .skipped_ambiguous
            .iter()
            .any(|s| matches!(s, central_retry::port::SkippedScope::Node(n) if *n == amb_node))
            && summary
                .skipped_ambiguous
                .iter()
                .any(|s| matches!(s, central_retry::port::SkippedScope::Run(r) if *r == m.run)),
        "amb node + run must both report skipped: {summary:?}"
    );
    assert!(
        summary.workflow_timeouts.is_empty(),
        "no run landing across ambiguity: {summary:?}"
    );
    m.assert_node_state(amb_node, NodeStatus::AttemptAmbiguous)
        .await?;
    m.assert_node_state(m1, NodeStatus::Running).await?;

    // Workflow half: the operator resolves the ambiguity, the deferred
    // node timer fires, and the run lands WORKFLOW_TIMEOUT over the
    // spec-1 cascade.
    m.resolve_ambiguous(amb_node, "rerun", fp("rtm19d rerun"))
        .await?;
    m.note_kind("attempt_decision");
    m.note_kind("node_ready");
    let summary = m.sweep_timeouts().await?;
    assert!(
        summary.node_timeouts.contains(&amb_node),
        "the deferred node timer must fire: {summary:?}"
    );
    m.assert_node_state(amb_node, NodeStatus::FailedTerminal)
        .await?;
    assert!(
        summary.workflow_timeouts.contains(&m.run),
        "the run deadline must land: {summary:?}"
    );
    assert_eq!(
        m.node_attempt_states(m1).await?,
        vec![(1, "cancelled".to_string())],
        "m1 attempt-1 state"
    );
    assert_eq!(
        m.node_attempt_reason(m1, 1).await?,
        Some("WORKFLOW_TIMEOUT".to_string()),
        "m1 attempt-1 reason row"
    );
    for n in [m1, m2, m3] {
        m.assert_node_state(n, NodeStatus::Cancelled).await?;
    }
    assert_eq!(
        m.count_node_kind(m1, "cancel_requested").await?,
        1,
        "m1 cancel_requested rows"
    );
    m.assert_reason("node_cancelled", "WORKFLOW_TIMEOUT")
        .await?;
    m.note_reason("WORKFLOW_TIMEOUT");
    m.note_kind("cancel_requested");
    m.note_kind("node_cancelled");
    assert_eq!(
        m.run_summary(m.run).await?.status,
        "failed_terminal",
        "run must land failed_terminal"
    );
    assert!(m.worker_leases(worker).await?.is_empty(), "cleanup leases");
    m.assert_run_clean().await?;
    Ok(
        "node bound landed NODE_TIMEOUT under a confirmed kill (attempt \
        SESSION_WALL_CLOCK_REACHED); amb node+run skipped; after rerun \
        the deferred node timer fired and the run landed \
        WORKFLOW_TIMEOUT over the cancelled cascade"
            .to_string(),
    )
}
