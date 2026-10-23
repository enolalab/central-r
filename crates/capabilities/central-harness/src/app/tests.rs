//! The ported upstream application tests — one `#[test]` per
//! `TestX` of `internal/harness/app/*_test.go`, keeping the upstream
//! names in snake_case.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use central_foundation::failure::Failure;
use central_foundation::identity::{HarnessAttemptId, StepAttemptId, StepId, TaskId};
use time::Duration;

use crate::attempt::{Attempt, PrepareInput};
use crate::budget::Budget;
use crate::capability::Capabilities;
use crate::domain::{
    self, Fence, Kind, PermissionPolicy, Resolution, ResolutionKind, State, Terminal,
    TerminalStatus, Workspace,
};
use crate::event::{self, EventKind, EventPayload, MessageRole, ToolStatus, Usage, UsageScope};
use crate::port::{self, LinkedStepAttemptState};
use crate::recovery::REASON_NOT_LAUNCHED;
use sha2::Digest;

use super::bridge::decided_by_code;
use super::dispatcher::{DispatcherConfig, DispatcherState, PauseReason};
use super::orchestrator::{Orchestrator, OrchestratorConfig, billed_tokens};
use super::ports::{
    ArtifactOutcome, ArtifactOutcomeKind, ArtifactRole, DispatchCase, DispatchableRun, FailureCode,
    MilestoneKind, Outcome, Settlement, codes,
};
use super::reconciler::{
    AMBIGUITY_RESTART, DECIDED_BY_OPERATOR_RESUME, DECIDED_BY_RECOVERY,
    REASON_RECOVERED_SETTLEMENT, Reconciler, Resolver,
};
use super::testkit::*;

/// `finalReport` — the last assistant message of `succeededScript`.
const FINAL_REPORT: &str = "# Done\n\nCreated hello.txt and committed it.";

/// `succeededScript`.
fn succeeded_script(extra: Vec<EventPayload>) -> Script {
    let mut payloads = vec![EventPayload::SessionStarted(event::SessionStarted {
        harness_session_id: "session-1".to_string(),
        harness_version: "2.1.283".to_string(),
        model: String::new(),
        tools: Vec::new(),
        reported_capabilities: Vec::new(),
    })];
    payloads.extend(extra);
    payloads.push(EventPayload::Message(event::Message {
        role: MessageRole::Assistant,
        text: FINAL_REPORT.to_string(),
        partial: false,
    }));
    Script {
        session_id: "session-1".to_string(),
        payloads,
        terminal: Terminal {
            status: TerminalStatus::Succeeded,
            ..Terminal::default()
        },
        ..Script::default()
    }
}

/// `failedScript`.
fn failed_script(reason: &str) -> Script {
    let mut s = succeeded_script(Vec::new());
    s.terminal = Terminal {
        status: TerminalStatus::Failed,
        reason: reason.to_string(),
        ..Terminal::default()
    };
    s
}

/// `blockingScript` — a session waiting on a permission request nobody
/// can answer (no bridge); only Interrupt/Kill ends it.
fn blocking_script() -> Script {
    let mut s = succeeded_script(vec![EventPayload::PermissionRequested(
        event::PermissionRequested {
            request_id: "req-1".to_string(),
            tool_call_id: String::new(),
            tool: "Bash".to_string(),
            resources: Vec::new(),
            options: Vec::new(),
            input: Vec::new(),
        },
    )]);
    s.wait_for_permission = true;
    s
}

/// `requireCancelled` (cancel_test.go) — the cancellation settled and
/// nothing else.
fn require_cancelled(w: &World, res: &super::ports::HarnessResult) {
    assert!(
        res.outcome == Outcome::Cancelled && res.err.is_none(),
        "result = {res:?}"
    );
    assert_eq!(
        w.life.cancellations.load(Ordering::SeqCst),
        1,
        "SettleCancellation calls"
    );
    for call in w.tr.all() {
        assert!(
            call != "lifecycle.Settle"
                && call != "lifecycle.RecordCompletion"
                && !call.starts_with("lifecycle.AbandonPrepared"),
            "a cancelled run was settled otherwise: {:?}",
            w.tr.all()
        );
    }
    let (completion, settled, abandoned) = w.life.snapshot();
    assert!(
        completion.is_empty() && settled.is_empty() && abandoned.is_empty(),
        "completion={completion:?} settled={settled:?} abandoned={abandoned:?}"
    );
    let m = w.sink.of(MilestoneKind::Terminal);
    assert!(
        m.len() == 1 && m[0].reason == super::ports::MILESTONE_REASON_CANCELLED,
        "terminal milestones = {m:?}"
    );
}

fn is_code(e: Option<&Failure>, code: &str) -> bool {
    e.map(|e| e.code() == code).unwrap_or(false)
}

/// `permanentErr` — a write failure the orchestrator does not retry.
fn permanent_err(msg: &str) -> Failure {
    Failure::invalid("permanent", msg.to_string())
}

// ---------------------------------------------------------------------------
// orchestrator_test.go
// ---------------------------------------------------------------------------

#[test]
fn orchestrator_runs_the_decision2_order_and_projects_milestones() {
    let w = new_world(
        default_cfg(),
        Capabilities::default(),
        vec![succeeded_script(vec![
            EventPayload::Message(event::Message {
                role: MessageRole::Assistant,
                text: "working".to_string(),
                partial: false,
            }),
            EventPayload::ToolCall(event::ToolCall {
                id: "t1".to_string(),
                parent_id: String::new(),
                name: "Bash".to_string(),
                input: br#"{"command":"git commit"}"#.to_vec(),
            }),
            EventPayload::ToolResult(event::ToolResult {
                id: "t1".to_string(),
                status: ToolStatus::Denied,
                output: Vec::new(),
            }),
            EventPayload::Retry(event::Retry {
                reason: "overloaded".to_string(),
            }),
            EventPayload::UsageReport(event::UsageReport {
                usage: event::Usage {
                    tokens_in: 10,
                    tokens_out: 5,
                    scope: UsageScope::SessionCumulative,
                    ..event::Usage::default()
                },
            }),
        ])],
    );
    let res = w.run();
    assert!(
        res.outcome == Outcome::Succeeded && res.err.is_none(),
        "result = {res:?}"
    );
    // Harness phase 3b decision 8: capture, the patch, the commits, then the
    // report with the completion; no receipt and no Settle.
    let order = [
        "lifecycle.Start",
        "provisioner.CheckFreeSpace",
        "provisioner.Provision",
        "store.Create",
        "lifecycle.MarkInvoked",
        "store.Save:launching",
        "adapter.Start",
        "store.AppendEvent:session_started",
        "store.AppendEvent:terminal_reported",
        "capture.Capture",
        "artifacts.Store:harness.patch",
        "artifacts.Store:harness.commits",
        "lifecycle.CompleteWithReport",
        "capture.Release",
    ];
    let mut last: i64 = -1;
    for call in order {
        let i = w.tr.index(call);
        assert!(
            i > last,
            "{call} at {i}, not after {last}: {:?}",
            w.tr.all()
        );
        last = i;
    }
    let a = w.st.only();
    assert!(
        a.state == domain::State::Succeeded
            && a.last_event_seq == 8
            && a.harness_session_id == "session-1"
            && a.permission == PermissionPolicy::Deny
            && a.workspace.base_sha == BASE_SHA
            && a.usage.tokens_in == 10,
        "attempt = {a:?}"
    );
    let claimed = &w.life.started()[0];
    assert_eq!(claimed.run_id, a.run_id);
    assert_eq!(w.st.record_kinds().len(), 8, "event records");
    let (completion, settled, abandoned) = w.life.snapshot();
    assert!(
        completion.is_empty() && settled.is_empty() && abandoned.is_empty(),
        "completion={completion:?} settled={settled:?} abandoned={abandoned:?}"
    );
    // The report is the last complete assistant message, not an earlier one.
    assert_eq!(w.life.reported(), vec![FINAL_REPORT.to_string()]);
    let paths = capture_paths(a.run_id);
    assert_eq!(w.arts.stored(ArtifactRole::Patch), vec![paths.patch]);
    assert_eq!(w.arts.stored(ArtifactRole::Commits), vec![paths.commits]);
    let (_, spec, _) = &w.ad.calls()[0];
    assert!(
        spec.permission == PermissionPolicy::Deny
            && spec.env.sandbox_scope_id == a.id.to_string()
            && spec.attempt == a.id
            && spec.fence == a.fence
            && !spec.prompt.is_empty()
            && spec.env.vars.get("PATH").map(String::as_str)
                == test_env().get("PATH").map(String::as_str)
            && spec.workspace == a.workspace,
        "start spec = {spec:?}"
    );
    let want = vec![
        MilestoneKind::AttemptLaunched,
        MilestoneKind::SessionStarted,
        MilestoneKind::PermissionDenied,
        MilestoneKind::Retry,
        MilestoneKind::ArtifactsCaptured,
        MilestoneKind::Terminal,
    ];
    assert_eq!(w.sink.kinds(), want, "milestones");
    let term = &w.sink.of(MilestoneKind::Terminal)[0];
    assert!(
        term.status == "succeeded"
            && term.reason.is_empty()
            && term.step_attempt_id.to_string() == a.id.to_string(),
        "terminal milestone = {term:?}"
    );
}

#[test]
fn orchestrator_maps_every_terminal_to_its_settlement() {
    for tc in [
        (
            Terminal {
                status: TerminalStatus::Failed,
                reason: "harness_api_error".to_string(),
                ..Terminal::default()
            },
            domain::State::Failed,
            FailureCode::new("harness_api_error"),
        ),
        (
            Terminal {
                status: TerminalStatus::Failed,
                reason: "harness_not_authenticated".to_string(),
                ..Terminal::default()
            },
            domain::State::Failed,
            FailureCode::new("harness_not_authenticated"),
        ),
        (
            Terminal {
                status: TerminalStatus::Failed,
                ..Terminal::default()
            },
            domain::State::Failed,
            FailureCode::EXECUTION_FAILED,
        ),
        (
            Terminal {
                status: TerminalStatus::MaxTurns,
                reason: "harness_max_turns".to_string(),
                ..Terminal::default()
            },
            domain::State::Failed,
            FailureCode::MAX_TURNS,
        ),
        (
            Terminal {
                status: TerminalStatus::MaxTurns,
                ..Terminal::default()
            },
            domain::State::Failed,
            FailureCode::MAX_TURNS,
        ),
        (
            Terminal {
                status: TerminalStatus::Interrupted,
                ..Terminal::default()
            },
            domain::State::Interrupted,
            FailureCode::ABORTED,
        ),
        (
            Terminal {
                status: TerminalStatus::Killed,
                ..Terminal::default()
            },
            domain::State::Killed,
            FailureCode::ABORTED,
        ),
        (
            Terminal {
                status: TerminalStatus::Budget,
                reason: "harness_budget".to_string(),
                ..Terminal::default()
            },
            domain::State::BudgetExhausted,
            FailureCode::BUDGET,
        ),
        (
            Terminal {
                status: TerminalStatus::Budget,
                ..Terminal::default()
            },
            domain::State::BudgetExhausted,
            FailureCode::BUDGET,
        ),
    ] {
        let mut script = succeeded_script(Vec::new());
        script.terminal = tc.0.clone();
        let w = new_world(default_cfg(), Capabilities::default(), vec![script]);
        let res = w.run();
        assert!(
            res.outcome == Outcome::Failed && res.reason == tc.2,
            "{:?}: result = {res:?}",
            tc.0.status
        );
        let a = w.st.only();
        assert_eq!(a.state, tc.1, "{:?}", tc.0.status);
        let (completion, settled, _) = w.life.snapshot();
        let want = vec![super::ports::Settlement {
            succeeded: false,
            reason: tc.2.clone(),
        }];
        assert_eq!(completion, want, "{:?}", tc.0.status);
        assert_eq!(settled, want, "{:?}", tc.0.status);
        assert!(
            w.tr.index("lifecycle.RecordCompletion") <= w.tr.index("lifecycle.Settle"),
            "receipt recorded after Settle"
        );
        let m = w.sink.of(MilestoneKind::Terminal);
        assert!(
            m.len() == 1 && m[0].status == tc.1.as_str() && m[0].reason == tc.2.as_str(),
            "terminal milestone = {m:?}"
        );
    }
}

#[test]
fn orchestrator_abandons_prelaunch_failures() {
    struct Case {
        name: &'static str,
        setup: fn(&World),
        reason: FailureCode,
        low_disk: bool,
        row: bool,
    }
    for tc in [
        Case {
            name: "source missing",
            setup: |w| {
                w.prov.set_err(Some(Failure::internal(
                    codes::WORKSPACE_UNAVAILABLE,
                    "source missing",
                )))
            },
            reason: FailureCode::WORKSPACE_UNAVAILABLE,
            low_disk: false,
            row: false,
        },
        Case {
            name: "low disk",
            setup: |w| {
                w.prov
                    .set_space_err(Some(Failure::internal(codes::LOW_DISK, "1 GiB free")))
            },
            reason: FailureCode::WORKSPACE_UNAVAILABLE,
            low_disk: true,
            row: false,
        },
        Case {
            name: "low disk while cloning",
            setup: |w| {
                w.prov
                    .set_err(Some(Failure::internal(codes::LOW_DISK, "1 GiB free")))
            },
            reason: FailureCode::WORKSPACE_UNAVAILABLE,
            low_disk: true,
            row: false,
        },
        Case {
            name: "no instruction",
            setup: |w| w.life.set_prompt(""),
            reason: FailureCode::EXECUTION_FAILED,
            low_disk: false,
            row: false,
        },
        Case {
            name: "live attempt exists",
            setup: |w| {
                w.st.set_create_err(Some(Failure::conflict(
                    domain::codes::LIVE_ATTEMPT_EXISTS,
                    "live attempt",
                )))
            },
            reason: FailureCode::EXECUTION_FAILED,
            low_disk: false,
            row: false,
        },
        Case {
            name: "mark invoked refused",
            setup: |w| {
                w.life
                    .set_invoke_err(Some(Failure::invalid("IMMUTABLE_ATTEMPT", "immutable")))
            },
            reason: FailureCode::EXECUTION_FAILED,
            low_disk: false,
            row: true,
        },
    ] {
        let w = new_world(
            default_cfg(),
            Capabilities::default(),
            vec![succeeded_script(Vec::new())],
        );
        (tc.setup)(&w);
        let res = w.run();
        assert!(
            res.outcome == Outcome::Abandoned
                && res.reason == tc.reason
                && res.low_disk == tc.low_disk,
            "{}: result = {res:?}",
            tc.name
        );
        let (_, settled, abandoned) = w.life.snapshot();
        assert!(
            abandoned == vec![tc.reason.clone()] && settled.is_empty(),
            "{}: abandoned={abandoned:?} settled={settled:?}",
            tc.name
        );
        assert_eq!(w.tr.count("adapter.Start"), 0, "{}", tc.name);
        if tc.row {
            let a = w.st.only();
            assert!(
                a.state == domain::State::Failed && a.terminal.reason == REASON_NOT_LAUNCHED,
                "{}: harness row = {}/{}",
                tc.name,
                a.state.as_str(),
                a.terminal.reason
            );
            assert!(
                w.tr.index("store.Save:failed") < w.tr.index("lifecycle.AbandonPrepared")
                    && w.tr.index("store.Save:failed") >= 0,
                "{}: harness row closed after the lease was released",
                tc.name
            );
        }
        let m = w.sink.of(MilestoneKind::Terminal);
        assert!(
            m.len() == 1 && m[0].reason == tc.reason.as_str(),
            "{}: terminal milestone = {m:?}",
            tc.name
        );
    }
}

#[test]
fn orchestrator_settles_a_launcher_error_after_mark_invoked() {
    let w = new_world(
        default_cfg(),
        Capabilities::default(),
        vec![Script {
            start_err: Some(Failure::internal("launcher", "launcher refused")),
            ..Script::default()
        }],
    );
    let res = w.run();
    assert!(
        res.outcome == Outcome::Failed && res.reason == FailureCode::LAUNCH_FAILED,
        "result = {res:?}"
    );
    assert!(w.tr.index("lifecycle.MarkInvoked") < w.tr.index("adapter.Start"));
    let a = w.st.only();
    assert!(
        a.state == domain::State::Failed
            && a.terminal.reason == FailureCode::LAUNCH_FAILED.as_str(),
        "attempt = {:?}/{:?}",
        a.state,
        a.terminal.reason
    );
    let (completion, settled, abandoned) = w.life.snapshot();
    let want = vec![super::ports::Settlement {
        succeeded: false,
        reason: FailureCode::LAUNCH_FAILED,
    }];
    assert_eq!(completion, want);
    assert_eq!(settled, want);
    assert!(abandoned.is_empty());
}

#[test]
fn orchestrator_wall_clock_interrupts_and_ends_budget_exhausted() {
    let w = new_world(
        OrchestratorConfig {
            default_wall_clock: Duration::milliseconds(50),
            interrupt_grace: Duration::seconds(1),
            ..default_cfg()
        },
        Capabilities {
            interrupt: true,
            ..Capabilities::default()
        },
        vec![blocking_script()],
    );
    let res = w.run();
    assert!(
        res.outcome == Outcome::Failed && res.reason == FailureCode::BUDGET_WALL_CLOCK,
        "result = {res:?}"
    );
    let a = w.st.only();
    assert!(
        a.state == domain::State::BudgetExhausted
            && a.terminal.reason == FailureCode::BUDGET_WALL_CLOCK.as_str(),
        "attempt = {:?}/{:?}",
        a.state,
        a.terminal.reason
    );
    let (interrupts, _) = w.ad.session_counts(0).unwrap_or_default();
    assert_eq!(interrupts, 1);
}

#[test]
fn orchestrator_wall_clock_kills_a_harness_that_ignores_the_interrupt() {
    let w = new_world(
        OrchestratorConfig {
            default_wall_clock: Duration::milliseconds(30),
            interrupt_grace: Duration::milliseconds(30),
            ..default_cfg()
        },
        Capabilities {
            interrupt: true,
            ..Capabilities::default()
        },
        vec![blocking_script()],
    );
    w.ad.set_swallow_interrupt(true);
    let res = w.run();
    assert!(
        res.outcome == Outcome::Failed && res.reason == FailureCode::BUDGET_WALL_CLOCK,
        "result = {res:?}"
    );
    let (interrupts, kills) = w.ad.session_counts(0).unwrap_or_default();
    assert_eq!((interrupts, kills), (1, 1));
    assert_eq!(w.st.only().state, domain::State::BudgetExhausted);
}

#[test]
fn orchestrator_lease_loss_closes_the_lifeline_and_stops_writing() {
    let w = new_world(
        OrchestratorConfig {
            heartbeat_interval: Duration::milliseconds(10),
            ..default_cfg()
        },
        Capabilities::default(),
        vec![blocking_script()],
    );
    let done = std::thread::scope(|scope| {
        let h = scope.spawn(|| w.run());
        wait_for("the permission request to be persisted", || {
            w.tr.count("store.AppendEvent:permission_requested") == 1
        });
        let writes_before = w.tr.all().len();
        w.life.lease_lost.store(true, Ordering::SeqCst);
        w.st.lease_lost.store(true, Ordering::SeqCst);
        (
            h.join().unwrap_or_else(|e| std::panic::resume_unwind(e)),
            writes_before,
        )
    });
    let (res, writes_before) = done;
    assert!(
        res.outcome == Outcome::Lost && is_code(res.err.as_ref(), codes::LEASE_LOST),
        "result = {res:?}"
    );
    let (_, kills) = w.ad.session_counts(0).unwrap_or_default();
    assert_eq!(kills, 1, "lifeline not closed");
    for call in &w.tr.all()[writes_before..] {
        assert!(
            call == "lifecycle.Heartbeat" || call == "session.Kill",
            "wrote {call} after the lease was lost"
        );
    }
    assert_eq!(
        w.st.only().state,
        domain::State::AwaitingPermission,
        "want the last persisted state"
    );
    assert!(w.sink.of(MilestoneKind::Terminal).is_empty());
}

#[test]
fn orchestrator_fence_conflict_on_a_write_is_a_lost_lease() {
    let w = new_world(
        default_cfg(),
        Capabilities::default(),
        vec![blocking_script()],
    );
    w.st.set_append_err(Some(Failure::conflict(
        domain::codes::FENCE_MISMATCH,
        "fenced",
    )));
    let res = w.run();
    assert_eq!(res.outcome, Outcome::Lost, "result = {res:?}");
    let (_, kills) = w.ad.session_counts(0).unwrap_or_default();
    assert_eq!(kills, 1, "lifeline not closed on a fence conflict");
    assert_eq!(
        w.tr.count("lifecycle.Settle") + w.tr.count("lifecycle.RecordCompletion"),
        0
    );
}

#[test]
fn orchestrator_stop_before_mark_invoked_writes_nothing() {
    let w = new_world(
        OrchestratorConfig {
            heartbeat_interval: Duration::milliseconds(10),
            ..default_cfg()
        },
        Capabilities::default(),
        vec![succeeded_script(Vec::new())],
    );
    w.prov.set_block(true);
    let res = std::thread::scope(|scope| {
        let h = scope.spawn(|| w.run());
        wait_for("provisioning to start", || {
            w.tr.count("provisioner.Provision") == 1
        });
        w.stop.cancel();
        h.join().unwrap_or_else(|e| std::panic::resume_unwind(e))
    });
    assert_eq!(res.outcome, Outcome::Stopped, "result = {res:?}");
    for call in [
        "store.Create",
        "lifecycle.MarkInvoked",
        "lifecycle.AbandonPrepared",
        "adapter.Start",
        "lifecycle.Settle",
    ] {
        assert_eq!(w.tr.count(call), 0, "{call} after a stop");
    }
    let beats = w.life.heartbeats.load(Ordering::SeqCst);
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert_eq!(
        w.life.heartbeats.load(Ordering::SeqCst),
        beats,
        "heartbeat continued after the stop"
    );
}

#[test]
fn orchestrator_stop_after_launch_closes_the_lifeline() {
    let w = new_world(
        default_cfg(),
        Capabilities::default(),
        vec![blocking_script()],
    );
    let res = std::thread::scope(|scope| {
        let h = scope.spawn(|| w.run());
        wait_for("the session to wait", || {
            w.tr.count("store.AppendEvent:permission_requested") == 1
        });
        w.stop.cancel();
        h.join().unwrap_or_else(|e| std::panic::resume_unwind(e))
    });
    assert_eq!(res.outcome, Outcome::Stopped, "result = {res:?}");
    let (_, kills) = w.ad.session_counts(0).unwrap_or_default();
    assert_eq!(kills, 1, "lifeline not closed on stop");
    assert_eq!(
        w.tr.count("lifecycle.Settle")
            + w.tr.count("lifecycle.RecordCompletion")
            + w.tr.count("store.AppendEvent:terminal_reported"),
        0,
        "wrote after stop: {:?}",
        w.tr.all()
    );
}

#[test]
fn orchestrator_slow_provisioning_keeps_the_lease_alive() {
    let w = new_world(
        OrchestratorConfig {
            heartbeat_interval: Duration::milliseconds(10),
            ..default_cfg()
        },
        Capabilities::default(),
        vec![succeeded_script(Vec::new())],
    );
    w.prov.set_delay(Duration::milliseconds(120));
    let res = w.run();
    assert_eq!(res.outcome, Outcome::Succeeded, "result = {res:?}");
    let mut beats_before_invoke = 0;
    for call in w.tr.all() {
        if call == "lifecycle.MarkInvoked" {
            break;
        }
        if call == "lifecycle.Heartbeat" {
            beats_before_invoke += 1;
        }
    }
    assert!(
        beats_before_invoke >= 3,
        "heartbeats before MarkInvoked = {beats_before_invoke}"
    );
}

#[test]
fn orchestrator_answers_a_bridged_permission_request_with_deny() {
    let mut script = succeeded_script(vec![EventPayload::PermissionRequested(
        event::PermissionRequested {
            request_id: "req-1".to_string(),
            tool_call_id: String::new(),
            tool: "Bash".to_string(),
            resources: Vec::new(),
            options: Vec::new(),
            input: Vec::new(),
        },
    )]);
    script.wait_for_permission = true;
    let w = new_world(default_cfg(), bridge_caps(), vec![script]);
    let res = w.run();
    assert_eq!(res.outcome, Outcome::Succeeded, "result = {res:?}");
    let want = vec![
        EventKind::SessionStarted,
        EventKind::PermissionRequested,
        EventKind::PermissionResolved,
        EventKind::Message,
        EventKind::TerminalReported,
    ];
    assert_eq!(w.st.record_kinds(), want, "records");
    let m = w.sink.of(MilestoneKind::PermissionDenied);
    assert!(
        m.len() == 1 && m[0].status == "deny",
        "permission milestones = {m:?}"
    );
}

#[test]
fn orchestrator_retries_a_transient_write() {
    let w = new_world(
        default_cfg(),
        Capabilities::default(),
        vec![succeeded_script(Vec::new())],
    );
    let calls = Arc::new(AtomicI64::new(0));
    let calls2 = calls.clone();
    w.life.set_on_mark_invoked(move || {
        if calls2.load(Ordering::SeqCst) < 2 {
            calls2.fetch_add(1, Ordering::SeqCst);
            return Some(err_transient());
        }
        None
    });
    let orch = w.orchestrator_over(w.life.clone(), default_cfg());
    let res = block_on(orch.run_dispatchable(w.life_run(), "2.1.283", &*w.stop));
    assert_eq!(res.outcome, Outcome::Succeeded, "result = {res:?}");
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn new_orchestrator_rejects_a_forbidden_launch_env() {
    let tr = Trace::default();
    let life = Arc::new(Lifecycle::new(&tr, Vec::new()));
    let st = FakeStore::new(&tr);
    let prov = Arc::new(Provisioner::new(&tr, Arc::new(super::ports::RealTicker)));
    let cap = Arc::new(Capturer::new(&tr));
    let arts = Arc::new(Artifacts::new(&tr));
    let ad = Arc::new(FakeAdapter::new(
        &tr,
        "claude-code",
        Capabilities::default(),
        Vec::new(),
    ));
    let err = Orchestrator::new(super::orchestrator::OrchestratorDeps {
        lifecycle: life,
        attempts: st,
        adapter: ad,
        workspaces: prov,
        capture: cap,
        artifacts: arts,
        clock: Arc::new(RealClock),
        ticker: Arc::new(super::ports::RealTicker),
        cfg: OrchestratorConfig {
            adapter_version: "v".to_string(),
            launch_env: [("ANTHROPIC_API_KEY".to_string(), "x".to_string())]
                .into_iter()
                .collect(),
            ..default_cfg()
        },
    })
    .err();
    assert!(
        is_code(err.as_ref(), domain::codes::FORBIDDEN_LAUNCH_ENV),
        "err = {err:?}"
    );
}

#[test]
fn claimed_run_never_prints_the_prompt_or_bearer() {
    let mut r = super::ports::ClaimedRun {
        prompt: "secret prompt".to_string(),
        ..queued_claimed()
    };
    r.lease.credential[0] = 0xAB;
    for s in [format!("{r}"), format!("{r:?}"), format!("{r:#?}")] {
        assert!(
            !s.contains("secret prompt") && !s.contains("Credential:["),
            "leaked: {s}"
        );
    }
}

fn queued_claimed() -> super::ports::ClaimedRun {
    super::ports::ClaimedRun {
        workspace_id: central_foundation::identity::WorkspaceId::new(),
        task_id: central_foundation::identity::TaskId::new(),
        run_id: central_foundation::identity::RunId::new(),
        step_id: central_foundation::identity::StepId::new(),
        step_attempt_id: central_foundation::identity::StepAttemptId::new(),
        prompt: String::new(),
        permission: PermissionPolicy::Unset,
        budget: crate::budget::Budget::default(),
        lease: crate::port::ExecutionLease {
            generation: 1,
            credential: [1; 32],
        },
    }
}

#[test]
fn orchestrator_reports_a_failed_settlement_write() {
    struct Case {
        name: &'static str,
        completion_err: bool,
        settle_err: Option<Failure>,
        calls: usize,
    }
    for tc in [
        Case {
            name: "completion receipt refused",
            completion_err: true,
            settle_err: None,
            calls: 1,
        },
        Case {
            name: "settle refused",
            completion_err: false,
            settle_err: Some(permanent_err("settlement refused")),
            calls: 1,
        },
        Case {
            name: "settle failing after its retries",
            completion_err: false,
            settle_err: Some(err_transient()),
            calls: 3,
        },
    ] {
        let w = new_world(
            default_cfg(),
            Capabilities::default(),
            vec![failed_script("harness_api_error")],
        );
        if tc.completion_err {
            w.life
                .set_on_record_completion(|| Some(permanent_err("settlement refused")));
        }
        if tc.settle_err.is_some() {
            let permanent = tc.name == "settle refused";
            w.life.set_on_settle(move || {
                Some(if permanent {
                    permanent_err("settlement refused")
                } else {
                    err_transient()
                })
            });
        }
        let orch = w.orchestrator_over(w.life.clone(), default_cfg());
        let res = block_on(orch.run_dispatchable(w.life_run(), "2.1.283", &*w.stop));
        assert!(
            res.outcome == Outcome::Failed && res.settle_failed && res.err.is_some(),
            "{}: result = {res:?}",
            tc.name
        );
        let mut failing = "lifecycle.Settle";
        if tc.completion_err {
            failing = "lifecycle.RecordCompletion";
            assert_eq!(
                w.tr.count("lifecycle.Settle"),
                0,
                "{}: settled without a completion receipt",
                tc.name
            );
        }
        assert_eq!(
            w.tr.count(failing),
            tc.calls,
            "{}: {failing} calls",
            tc.name
        );
        assert!(
            w.sink.of(MilestoneKind::Terminal).is_empty(),
            "{}: terminal milestone before the settlement was written",
            tc.name
        );
        let m = w.sink.of(MilestoneKind::SettleFailed);
        assert!(
            m.len() == 1 && m[0].status == "failed" && m[0].reason == "harness_api_error",
            "{}: settle-failed milestones = {m:?}",
            tc.name
        );
    }
}

#[test]
fn orchestrator_reports_a_failed_abandon() {
    let w = new_world(
        default_cfg(),
        Capabilities::default(),
        vec![succeeded_script(Vec::new())],
    );
    w.life.set_prompt("");
    w.life
        .set_on_abandon(|| Some(permanent_err("abandon refused")));
    let orch = w.orchestrator_over(w.life.clone(), default_cfg());
    let res = block_on(orch.run_dispatchable(w.life_run(), "2.1.283", &*w.stop));
    assert!(
        res.outcome == Outcome::Abandoned
            && res.settle_failed
            && res.reason == FailureCode::EXECUTION_FAILED
            && res.err.is_some(),
        "result = {res:?}"
    );
    assert!(w.sink.of(MilestoneKind::Terminal).is_empty());
    let m = w.sink.of(MilestoneKind::SettleFailed);
    assert!(
        m.len() == 1 && m[0].reason == FailureCode::EXECUTION_FAILED.as_str(),
        "settle-failed milestones = {m:?}"
    );
}

#[test]
fn orchestrator_reports_a_failed_cancellation_settlement() {
    let w = new_world(
        default_cfg(),
        Capabilities::default(),
        vec![succeeded_script(Vec::new())],
    );
    w.life.cancelling.store(true, Ordering::SeqCst);
    w.life
        .set_on_cancel(|| Some(permanent_err("cancellation refused")));
    let orch = w.orchestrator_over(w.life.clone(), default_cfg());
    let res = block_on(orch.run_dispatchable(w.life_run(), "2.1.283", &*w.stop));
    assert!(
        res.outcome == Outcome::Cancelled && res.settle_failed && res.err.is_some(),
        "result = {res:?}"
    );
    assert!(w.sink.of(MilestoneKind::Terminal).is_empty());
    let m = w.sink.of(MilestoneKind::SettleFailed);
    assert!(
        m.len() == 1 && m[0].reason == super::ports::MILESTONE_REASON_CANCELLED,
        "settle-failed milestones = {m:?}"
    );
}

#[test]
fn orchestrator_records_the_terminal_milestone_after_the_settlement() {
    for tc in [
        (
            "succeeded",
            succeeded_script(Vec::new()),
            Outcome::Succeeded,
            "lifecycle.CompleteWithReport",
        ),
        (
            "failed",
            failed_script("harness_api_error"),
            Outcome::Failed,
            "lifecycle.Settle",
        ),
    ] {
        let w = new_world_with_sink(default_cfg(), Capabilities::default(), vec![tc.1], true);
        let res = w.run();
        assert!(
            res.outcome == tc.2 && !res.settle_failed,
            "{}: result = {res:?}",
            tc.0
        );
        let term =
            w.tr.index(&format!("sink.Record:{}", MilestoneKind::Terminal.as_str()));
        let settle = w.tr.index(tc.3);
        assert!(
            term > settle && settle >= 0,
            "{}: terminal milestone at {term}, {} at {settle}: {:?}",
            tc.0,
            tc.3,
            w.tr.all()
        );
        assert!(
            w.sink.of(MilestoneKind::SettleFailed).is_empty(),
            "{}: settle-failed milestone on a settled run",
            tc.0
        );
    }
}

#[test]
fn orchestrator_treats_an_invalid_claimed_lease_as_lost() {
    let w = new_world(
        default_cfg(),
        Capabilities::default(),
        vec![succeeded_script(Vec::new())],
    );
    w.life.zero_lease.store(true, Ordering::SeqCst);
    let orch = w.orchestrator_over(
        w.life.clone(),
        OrchestratorConfig {
            heartbeat_interval: Duration::milliseconds(5),
            ..default_cfg()
        },
    );
    let res = block_on(orch.run_dispatchable(w.life_run(), "2.1.283", &*w.stop));
    assert!(
        res.outcome == Outcome::Lost
            && is_code(res.err.as_ref(), codes::LEASE_LOST)
            && !res.settle_failed,
        "result = {res:?}"
    );
    std::thread::sleep(std::time::Duration::from_millis(20));
    let calls = w.tr.all();
    assert!(
        calls.len() == 1 && calls[0] == "lifecycle.Start",
        "calls after an invalid lease = {calls:?}, want only the claim"
    );
}

#[test]
fn orchestrator_joins_a_heartbeat_blocked_in_flight() {
    let w = new_world(
        default_cfg(),
        Capabilities::default(),
        vec![succeeded_script(Vec::new())],
    );
    w.prov.set_delay(Duration::milliseconds(50)); // first heartbeat in flight before the settlement
    w.life.heartbeat_block.store(true, Ordering::SeqCst);
    let orch = w.orchestrator_over(
        w.life.clone(),
        OrchestratorConfig {
            heartbeat_interval: Duration::milliseconds(5),
            ..default_cfg()
        },
    );
    let res = std::thread::scope(|scope| {
        let h = scope.spawn(|| block_on(orch.run_dispatchable(w.life_run(), "2.1.283", &*w.stop)));
        let start = std::time::Instant::now();
        loop {
            if h.is_finished() {
                break h.join().unwrap_or_else(|e| std::panic::resume_unwind(e));
            }
            assert!(
                start.elapsed() <= std::time::Duration::from_secs(3),
                "Run did not return: the heartbeat join is unbounded"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    });
    assert_eq!(
        res.outcome,
        Outcome::Succeeded,
        "result = {res:?} trace={:?}",
        w.tr.all()
    );
    assert!(
        w.life.hb_entered.load(Ordering::SeqCst),
        "no heartbeat was in flight"
    );
}

#[test]
fn orchestrator_retries_an_event_write_through_a_store_outage() {
    let w = new_world(
        default_cfg(),
        Capabilities::default(),
        vec![succeeded_script(Vec::new())],
    );
    w.st.append_failures.store(3, Ordering::SeqCst);
    let res = w.run();
    assert!(
        res.outcome == Outcome::Succeeded && res.err.is_none(),
        "result = {res:?}"
    );
    assert_eq!(
        w.tr.count("store.AppendEvent:session_started"),
        4,
        "want 3 failures then 1 success"
    );
    let (_, kills) = w.ad.session_counts(0).unwrap_or_default();
    assert_eq!(kills, 0, "a healthy session was killed");
    assert_eq!(w.st.only().state, domain::State::Succeeded);
}

#[test]
fn orchestrator_fails_execution_failed_when_the_store_stays_unavailable() {
    let w = new_world(
        OrchestratorConfig {
            event_write_budget: Duration::milliseconds(250),
            ..default_cfg()
        },
        Capabilities::default(),
        vec![succeeded_script(Vec::new())],
    );
    w.st.append_failing.store(true, Ordering::SeqCst);
    let res = w.run();
    assert!(
        res.outcome == Outcome::Failed
            && res.reason == FailureCode::EXECUTION_FAILED
            && is_code(res.err.as_ref(), "transient"),
        "result = {res:?}"
    );
    let (_, kills) = w.ad.session_counts(0).unwrap_or_default();
    assert_eq!(kills, 1, "want the session killed");
    let a = w.st.only();
    assert!(
        a.state == domain::State::Failed
            && a.terminal.reason == FailureCode::EXECUTION_FAILED.as_str(),
        "attempt = {:?}/{:?}",
        a.state,
        a.terminal.reason
    );
    let (completion, settled, _) = w.life.snapshot();
    let want = vec![super::ports::Settlement {
        succeeded: false,
        reason: FailureCode::EXECUTION_FAILED,
    }];
    assert_eq!(completion, want);
    assert_eq!(settled, want);
}

#[test]
fn orchestrator_loses_the_attempt_when_the_lease_goes_during_a_store_outage() {
    for tc in ["heartbeat reports the lease lost", "no heartbeat succeeds"] {
        let w = new_world(
            OrchestratorConfig {
                heartbeat_interval: Duration::milliseconds(10),
                event_write_budget: Duration::minutes(1),
                ..default_cfg()
            },
            Capabilities::default(),
            vec![succeeded_script(Vec::new())],
        );
        w.st.append_failing.store(true, Ordering::SeqCst);
        let res = std::thread::scope(|scope| {
            let h = scope.spawn(|| w.run());
            wait_for("the event write to fail", || {
                w.tr.count("store.AppendEvent:session_started") >= 1
            });
            let start = std::time::Instant::now();
            match tc {
                "heartbeat reports the lease lost" => {
                    w.life.lease_lost.store(true, Ordering::SeqCst)
                }
                _ => w.life.heartbeat_failing.store(true, Ordering::SeqCst),
            }
            let res = h.join().unwrap_or_else(|e| std::panic::resume_unwind(e));
            (res, start.elapsed())
        });
        let (res, elapsed) = res;
        assert!(
            res.outcome == Outcome::Lost && is_code(res.err.as_ref(), codes::LEASE_LOST),
            "{tc}: result = {res:?}"
        );
        assert!(
            elapsed <= std::time::Duration::from_secs(10),
            "{tc}: the outage was retried past the lease"
        );
        let (_, kills) = w.ad.session_counts(0).unwrap_or_default();
        assert_eq!(kills, 1, "{tc}: lifeline not closed");
        assert_eq!(
            w.tr.count("lifecycle.Settle") + w.tr.count("lifecycle.RecordCompletion"),
            0,
            "{tc}: settled after the lease was lost"
        );
    }
}

#[test]
fn orchestrator_settles_an_event_the_domain_refuses_as_a_protocol_error() {
    let w = new_world(
        default_cfg(),
        Capabilities::default(),
        vec![succeeded_script(Vec::new())],
    );
    w.st.set_append_err(Some(Failure::invalid(
        domain::codes::INVALID_EVENT,
        "seq gap",
    )));
    let res = w.run();
    assert!(
        res.outcome == Outcome::Failed && res.reason == FailureCode::PROTOCOL_ERROR,
        "result = {res:?}"
    );
    assert_eq!(
        w.tr.count("store.AppendEvent:session_started"),
        1,
        "a domain refusal was retried"
    );
    let (_, kills) = w.ad.session_counts(0).unwrap_or_default();
    assert_eq!(kills, 1);
}

#[test]
fn orchestrator_reports_a_start_with_an_unknown_outcome_as_lost() {
    let w = new_world(
        default_cfg(),
        Capabilities::default(),
        vec![succeeded_script(Vec::new())],
    );
    w.life.set_start_err(Some(Failure::internal(
        codes::START_OUTCOME_UNKNOWN,
        "connection reset at commit",
    )));
    let res = w.run();
    assert!(
        res.outcome == Outcome::Lost
            && res.reason == FailureCode::LEASE_LOST
            && is_code(res.err.as_ref(), codes::START_OUTCOME_UNKNOWN),
        "result = {res:?}"
    );
    w.life.set_start_err(Some(Failure::internal(
        codes::NOT_STARTABLE,
        "another start won",
    )));
    let res = w.run();
    assert_eq!(
        res.outcome,
        Outcome::NotStarted,
        "a refused start = {res:?}"
    );
}

// ---------------------------------------------------------------------------
// bridge_test.go
// ---------------------------------------------------------------------------

const BASH_INPUT: &str = r#"{"command":"echo hi > hello.txt"}"#;

fn bash_request(id: &str) -> EventPayload {
    EventPayload::PermissionRequested(event::PermissionRequested {
        request_id: id.to_string(),
        tool_call_id: format!("toolu_{id}"),
        tool: "Bash".to_string(),
        resources: Vec::new(),
        options: Vec::new(),
        input: BASH_INPUT.as_bytes().to_vec(),
    })
}

/// `bridgeScript` — a succeeded session that pauses on each request.
fn bridge_script(requests: Vec<EventPayload>) -> Script {
    let mut s = succeeded_script(requests);
    s.wait_for_permission = true;
    s
}

/// `bridgeWorld` — a world whose claimed Run's Task has the bridge policy.
fn bridge_world(cfg: OrchestratorConfig, scripts: Vec<Script>) -> World {
    let w = new_world(cfg, bridge_caps(), scripts);
    w.life.set_permission(PermissionPolicy::Bridge);
    w
}

/// `awaitPending` — waits for the n-th opened approval to be pending.
fn await_pending(w: &World, n: usize) -> crate::approval::PermissionApproval {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let list = w.st.approval_list();
        if list.len() >= n && list[n - 1].state == crate::approval::ApprovalState::Pending {
            return list[n - 1].clone();
        }
        assert!(
            std::time::Instant::now() <= deadline,
            "approval {n} pending"
        );
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
}

/// `decide` — the operator's decision: the durable compare-and-set,
/// then the registry signal.
fn decide(w: &World, a: &crate::approval::PermissionApproval, allow: bool) {
    w.st.decide(a.id, allow).expect("decide");
    w.orch.signal_decision(a.workspace_id, a.id);
}

/// `resolvedEvents` — the persisted permission_resolved records.
fn resolved_events(w: &World) -> Vec<(String, event::PermissionOutcome)> {
    w.st.records()
        .iter()
        .filter(|r| r.kind == EventKind::PermissionResolved)
        .map(|r| (r.permission_request_id.clone(), r.permission_outcome))
        .collect()
}

/// `requireBridgeFailure` — the attempt failed closed.
fn require_bridge_failure(w: &World, res: super::ports::HarnessResult) {
    assert!(
        res.outcome == Outcome::Failed && res.reason == FailureCode::PERMISSION_BRIDGE_UNAVAILABLE,
        "result = {res:?}, want failed permission_bridge_unavailable"
    );
    let a = w.st.only();
    assert!(
        a.state == domain::State::Failed
            && a.terminal.reason == FailureCode::PERMISSION_BRIDGE_UNAVAILABLE.as_str(),
        "attempt = {:?}/{:?}",
        a.state,
        a.terminal.reason
    );
    let (_, kills) = w.ad.session_counts(0).unwrap_or_default();
    assert!(kills > 0, "the session was not killed");
    for a in w.st.approval_list() {
        assert_ne!(
            a.state,
            crate::approval::ApprovalState::Pending,
            "approval {} left pending after the terminal write",
            a.id
        );
    }
    let (_, settled, _) = w.life.snapshot();
    assert!(
        settled.len() == 1 && settled[0].reason == FailureCode::PERMISSION_BRIDGE_UNAVAILABLE,
        "settled = {settled:?}"
    );
}

#[test]
fn the_task_policy_reaches_the_attempt_and_the_start_spec() {
    for policy in [
        PermissionPolicy::Deny,
        PermissionPolicy::Bridge,
        PermissionPolicy::AutoAllow,
    ] {
        let w = new_world(
            default_cfg(),
            bridge_caps(),
            vec![succeeded_script(Vec::new())],
        );
        w.life.set_permission(policy);
        let res = w.run();
        assert_eq!(res.outcome, Outcome::Succeeded, "{policy:?}: {res:?}");
        assert_eq!(w.st.only().permission, policy, "{policy:?}");
        let (_, spec, _) = &w.ad.calls()[0];
        assert_eq!(spec.permission, policy, "{policy:?}");
    }
    let w = new_world(
        default_cfg(),
        bridge_caps(),
        vec![succeeded_script(Vec::new())],
    );
    let res = w.run();
    assert!(
        res.outcome == Outcome::Succeeded && w.st.only().permission == PermissionPolicy::Deny,
        "a claim without a policy did not run with deny: {res:?}"
    );
}

#[test]
fn bridged_allow_reaches_the_harness_bound_to_the_shown_input() {
    let w = bridge_world(
        default_cfg(),
        vec![bridge_script(vec![bash_request("req-1")])],
    );
    std::thread::scope(|scope| {
        let h = scope.spawn(|| w.run());
        let a = await_pending(&w, 1);
        assert!(
            a.request_id == "req-1"
                && a.tool_call_id == "toolu_req-1"
                && a.tool_name == "Bash"
                && a.input_size == BASH_INPUT.len() as i64
                && a.task_id == w.life_run().task_id,
            "approval = {a:?}"
        );
        let got = w.st.only();
        assert!(
            got.state == domain::State::AwaitingPermission && got.pending_permission == "req-1",
            "attempt = {:?}/{:?}",
            got.state,
            got.pending_permission
        );
        let held = w.orch.pending_request(a.workspace_id, a.id);
        assert!(
            held.as_ref().map(|h| h.input.as_slice()) == Some(BASH_INPUT.as_bytes()),
            "registry input = {held:?}"
        );
        assert!(
            w.orch
                .pending_request(w.life_run().workspace_id, a.id)
                .is_some(),
            "the registry lost the input"
        );
        decide(&w, &a, true);
        let res = h.join().unwrap_or_else(|e| std::panic::resume_unwind(e));
        assert_eq!(res.outcome, Outcome::Succeeded, "result = {res:?}");
        assert_eq!(
            resolved_events(&w),
            vec![("req-1".to_string(), event::PermissionOutcome::Allowed)]
        );
        assert_eq!(
            w.st.approval_list()[0].state,
            crate::approval::ApprovalState::Allowed
        );
        assert!(
            w.orch.pending_request(a.workspace_id, a.id).is_none(),
            "an answered approval's input stayed in memory"
        );
        let m = w.sink.of(MilestoneKind::PermissionRequested);
        assert!(
            m.len() == 1 && m[0].reason == "Bash" && m[0].status == "pending",
            "requested milestones = {m:?}"
        );
        let m = w.sink.of(MilestoneKind::PermissionAllowed);
        assert!(
            m.len() == 1 && m[0].reason == "operator",
            "allowed milestones = {m:?}"
        );
    });
}

#[test]
fn bridged_deny_is_recorded_and_the_run_continues() {
    let w = bridge_world(
        default_cfg(),
        vec![bridge_script(vec![bash_request("req-1")])],
    );
    std::thread::scope(|scope| {
        let h = scope.spawn(|| w.run());
        let a = await_pending(&w, 1);
        decide(&w, &a, false);
        let res = h.join().unwrap_or_else(|e| std::panic::resume_unwind(e));
        assert_eq!(res.outcome, Outcome::Succeeded, "result = {res:?}");
        assert_eq!(
            resolved_events(&w),
            vec![("req-1".to_string(), event::PermissionOutcome::Denied)]
        );
        let m = w.sink.of(MilestoneKind::PermissionDenied);
        assert!(
            m.len() == 1 && m[0].reason == "operator",
            "denied milestones = {m:?}"
        );
    });
}

#[test]
fn an_unanswered_request_expires_to_a_denial() {
    let w = bridge_world(
        OrchestratorConfig {
            approval_timeout: Duration::milliseconds(80),
            approval_recheck: Duration::hours(1),
            ..default_cfg()
        },
        vec![bridge_script(vec![bash_request("req-1")])],
    );
    let res = w.run();
    assert_eq!(res.outcome, Outcome::Succeeded, "result = {res:?}");
    let final_a = &w.st.approval_list()[0];
    assert!(
        final_a.state == crate::approval::ApprovalState::Expired
            && final_a.decided_by == crate::approval::DECIDED_BY_TIMEOUT,
        "approval = {final_a:?}"
    );
    assert_eq!(
        resolved_events(&w),
        vec![("req-1".to_string(), event::PermissionOutcome::Denied)]
    );
    let m = w.sink.of(MilestoneKind::PermissionDenied);
    assert!(
        m.len() == 1 && m[0].reason == "timeout",
        "denied milestones = {m:?}"
    );
}

#[test]
fn a_failed_expiry_is_retried_at_the_next_reread() {
    let w = bridge_world(
        OrchestratorConfig {
            approval_timeout: Duration::milliseconds(50),
            approval_recheck: Duration::milliseconds(20),
            ..default_cfg()
        },
        vec![bridge_script(vec![bash_request("req-1")])],
    );
    w.st.set_expire_err(Some(err_transient()));
    std::thread::scope(|scope| {
        let h = scope.spawn(|| w.run());
        wait_for("failed expiry attempts", || {
            w.tr.count("store.ExpirePermission") >= 3
        });
        w.st.set_expire_err(None);
        let res = h.join().unwrap_or_else(|e| std::panic::resume_unwind(e));
        assert_eq!(res.outcome, Outcome::Succeeded, "result = {res:?}");
        assert_eq!(
            w.st.approval_list()[0].state,
            crate::approval::ApprovalState::Expired
        );
    });
}

#[test]
fn a_lost_signal_is_recovered_by_the_reread() {
    let w = bridge_world(
        OrchestratorConfig {
            approval_recheck: Duration::milliseconds(30),
            ..default_cfg()
        },
        vec![bridge_script(vec![bash_request("req-1")])],
    );
    std::thread::scope(|scope| {
        let h = scope.spawn(|| w.run());
        let a = await_pending(&w, 1);
        // The durable decision lands without SignalDecision.
        w.st.decide(a.id, true).expect("decide");
        let res = h.join().unwrap_or_else(|e| std::panic::resume_unwind(e));
        assert_eq!(res.outcome, Outcome::Succeeded, "result = {res:?}");
        let got = resolved_events(&w);
        assert!(
            got.len() == 1 && got[0].1 == event::PermissionOutcome::Allowed,
            "resolved = {got:?}"
        );
    });
}

#[test]
fn concurrent_requests_are_queued_and_answered_in_order() {
    let mut script = bridge_script(vec![bash_request("req-1"), bash_request("req-2")]);
    script.concurrent_permissions = true;
    let w = bridge_world(default_cfg(), vec![script]);
    std::thread::scope(|scope| {
        let h = scope.spawn(|| w.run());
        let first = await_pending(&w, 1);
        wait_for("both requests recorded", || {
            w.tr.count("store.AppendEvent:permission_requested") == 2
        });
        let list = w.st.approval_list();
        assert!(
            list.len() == 1 && list[0].request_id == "req-1",
            "a queued request opened an approval: {list:?}"
        );
        decide(&w, &first, false);
        let second = await_pending(&w, 2);
        assert!(
            second.request_id == "req-2" && w.tr.count("store.Save:awaiting_permission") == 1,
            "second = {second:?}, promotion saves = {}",
            w.tr.count("store.Save:awaiting_permission")
        );
        decide(&w, &second, true);
        let res = h.join().unwrap_or_else(|e| std::panic::resume_unwind(e));
        assert_eq!(res.outcome, Outcome::Succeeded, "result = {res:?}");
        let want = vec![
            ("req-1".to_string(), event::PermissionOutcome::Denied),
            ("req-2".to_string(), event::PermissionOutcome::Allowed),
        ];
        assert_eq!(resolved_events(&w), want);
    });
}

#[test]
fn an_approval_that_cannot_be_written_fails_closed() {
    for (name, err) in [
        (
            "permanent",
            Failure::invalid(domain::codes::INVALID_APPROVAL, "refused"),
        ),
        ("transient", err_transient()),
    ] {
        let w = bridge_world(
            OrchestratorConfig {
                event_write_budget: Duration::milliseconds(50),
                ..default_cfg()
            },
            vec![bridge_script(vec![bash_request("req-1")])],
        );
        w.st.set_open_err(Some(err));
        require_bridge_failure(&w, w.run());
        assert!(
            w.st.approval_list().is_empty(),
            "{name}: an approval was opened"
        );
    }
}

#[test]
fn a_failed_answer_fails_closed() {
    let mut script = bridge_script(vec![bash_request("req-1")]);
    script.respond_err = Some(Failure::internal("pipe", "write |1: broken pipe"));
    let w = bridge_world(default_cfg(), vec![script]);
    std::thread::scope(|scope| {
        let h = scope.spawn(|| w.run());
        let a = await_pending(&w, 1);
        decide(&w, &a, true);
        require_bridge_failure(
            &w,
            h.join().unwrap_or_else(|e| std::panic::resume_unwind(e)),
        );
    });
}

#[test]
fn an_allow_whose_mac_does_not_match_the_held_input_fails_closed() {
    let w = bridge_world(
        default_cfg(),
        vec![bridge_script(vec![bash_request("req-1")])],
    );
    std::thread::scope(|scope| {
        let h = scope.spawn(|| w.run());
        let a = await_pending(&w, 1);
        w.st.decide(a.id, true).expect("decide");
        w.st.tamper(a.id, |p| p.input_mac.0[0] ^= 0xff);
        w.orch.signal_decision(a.workspace_id, a.id);
        require_bridge_failure(
            &w,
            h.join().unwrap_or_else(|e| std::panic::resume_unwind(e)),
        );
        assert!(resolved_events(&w).is_empty(), "the harness was answered");
    });
}

#[test]
fn a_queue_overflow_fails_closed() {
    let requests: Vec<EventPayload> = (0..super::bridge::MAX_QUEUED_PERMISSIONS + 2)
        .map(|i| bash_request(&format!("req-{i}")))
        .collect();
    let mut script = bridge_script(requests);
    script.concurrent_permissions = true;
    let w = bridge_world(default_cfg(), vec![script]);
    require_bridge_failure(&w, w.run());
    assert_eq!(
        w.tr.count("store.AppendEvent:permission_requested"),
        super::bridge::MAX_QUEUED_PERMISSIONS + 1,
        "want the open one and a full queue"
    );
}

#[test]
fn an_out_of_bounds_request_fails_closed() {
    let bad = match bash_request("req-1") {
        EventPayload::PermissionRequested(mut p) => {
            p.tool = "Bash\x1b[2J".to_string();
            EventPayload::PermissionRequested(p)
        }
        x => x,
    };
    let w = bridge_world(default_cfg(), vec![bridge_script(vec![bad])]);
    require_bridge_failure(&w, w.run());
}

#[test]
fn no_pending_after_the_session_ended_is_benign() {
    let mut script = bridge_script(vec![bash_request("req-1")]);
    script.respond_err = Some(Failure::invalid(
        port::codes::NO_PENDING_PERMISSION,
        "claude: no pending permission",
    ));
    let w = bridge_world(
        OrchestratorConfig {
            default_wall_clock: Duration::milliseconds(300),
            interrupt_grace: Duration::seconds(1),
            ..default_cfg()
        },
        vec![script],
    );
    std::thread::scope(|scope| {
        let h = scope.spawn(|| w.run());
        let a = await_pending(&w, 1);
        decide(&w, &a, true);
        let res = h.join().unwrap_or_else(|e| std::panic::resume_unwind(e));
        assert!(
            res.outcome == Outcome::Failed && res.reason == FailureCode::BUDGET_WALL_CLOCK,
            "result = {res:?}, want the wall clock's own status"
        );
        assert_eq!(w.st.only().state, domain::State::BudgetExhausted);
    });
}

#[test]
fn cancel_while_pending_supersedes_the_approval_through_the_terminal_write() {
    let w = new_world(
        OrchestratorConfig {
            heartbeat_interval: Duration::milliseconds(10),
            interrupt_grace: Duration::seconds(1),
            ..default_cfg()
        },
        Capabilities {
            interrupt: true,
            permission_bridge: true,
            ..Capabilities::default()
        },
        vec![bridge_script(vec![bash_request("req-1")])],
    );
    w.life.set_permission(PermissionPolicy::Bridge);
    std::thread::scope(|scope| {
        let h = scope.spawn(|| w.run());
        let a = await_pending(&w, 1);
        w.life.cancelling.store(true, Ordering::SeqCst);
        let res = h.join().unwrap_or_else(|e| std::panic::resume_unwind(e));
        require_cancelled(&w, &res);
        let final_a = &w.st.approval_list()[0];
        assert!(
            final_a.state == crate::approval::ApprovalState::Superseded
                && final_a.decided_by == crate::approval::DECIDED_BY_SUPERSEDED,
            "approval = {final_a:?}"
        );
        assert!(
            w.orch.pending_request(a.workspace_id, a.id).is_none(),
            "the registry kept the input"
        );
    });
}

#[test]
fn the_wall_clock_while_pending_supersedes_the_approval() {
    let w = new_world(
        OrchestratorConfig {
            default_wall_clock: Duration::milliseconds(100),
            interrupt_grace: Duration::seconds(1),
            ..default_cfg()
        },
        Capabilities {
            interrupt: true,
            permission_bridge: true,
            ..Capabilities::default()
        },
        vec![bridge_script(vec![bash_request("req-1")])],
    );
    w.life.set_permission(PermissionPolicy::Bridge);
    let res = w.run();
    assert!(
        res.outcome == Outcome::Failed && res.reason == FailureCode::BUDGET_WALL_CLOCK,
        "result = {res:?}"
    );
    assert_eq!(
        w.st.approval_list()[0].state,
        crate::approval::ApprovalState::Superseded
    );
}

#[test]
fn stop_and_lease_loss_write_nothing_and_drop_the_registry() {
    // stop
    {
        let w = bridge_world(
            default_cfg(),
            vec![bridge_script(vec![bash_request("req-1")])],
        );
        std::thread::scope(|scope| {
            let h = scope.spawn(|| w.run());
            let a = await_pending(&w, 1);
            w.stop.cancel();
            let res = h.join().unwrap_or_else(|e| std::panic::resume_unwind(e));
            assert_eq!(res.outcome, Outcome::Stopped, "result = {res:?}");
            assert_eq!(
                w.st.approval_list()[0].state,
                crate::approval::ApprovalState::Pending,
                "a stop wrote the approval"
            );
            assert!(
                w.orch.pending_request(a.workspace_id, a.id).is_none(),
                "the registry kept the input after a stop"
            );
        });
    }
    // lease loss
    {
        let w = bridge_world(
            OrchestratorConfig {
                heartbeat_interval: Duration::milliseconds(10),
                ..default_cfg()
            },
            vec![bridge_script(vec![bash_request("req-1")])],
        );
        std::thread::scope(|scope| {
            let h = scope.spawn(|| w.run());
            let a = await_pending(&w, 1);
            w.st.lease_lost.store(true, Ordering::SeqCst);
            w.life.lease_lost.store(true, Ordering::SeqCst);
            let res = h.join().unwrap_or_else(|e| std::panic::resume_unwind(e));
            assert_eq!(res.outcome, Outcome::Lost, "result = {res:?}");
            assert_eq!(
                w.st.approval_list()[0].state,
                crate::approval::ApprovalState::Pending,
                "a lost lease wrote the approval"
            );
            assert!(
                w.orch.pending_request(a.workspace_id, a.id).is_none(),
                "the registry kept the input after a lost lease"
            );
            let err = w.st.decide(a.id, true).err();
            assert!(
                is_code(err.as_ref(), domain::codes::NO_PENDING_APPROVAL),
                "a lease-less approval was decidable: {err:?}"
            );
        });
    }
}

#[test]
fn deny_and_auto_allow_create_no_approval() {
    for policy in [PermissionPolicy::Deny, PermissionPolicy::AutoAllow] {
        let w = new_world(
            default_cfg(),
            bridge_caps(),
            vec![bridge_script(vec![bash_request("req-1")])],
        );
        w.life.set_permission(policy);
        let res = w.run();
        assert_eq!(res.outcome, Outcome::Succeeded, "{policy:?}: {res:?}");
        assert!(w.st.approval_list().is_empty(), "{policy:?}");
        let got = resolved_events(&w);
        assert!(
            got.len() == 1 && got[0].1 == event::PermissionOutcome::Denied,
            "{policy:?}: resolved = {got:?}"
        );
    }
}

#[test]
fn an_input_too_large_denial_projects_its_reason() {
    let w = bridge_world(
        default_cfg(),
        vec![succeeded_script(vec![EventPayload::PermissionResolved(
            event::PermissionResolved {
                request_id: "big-1".to_string(),
                decision: event::PermissionOutcome::Denied,
                decided_by: crate::approval::DECIDED_BY_INPUT_TOO_LARGE.to_string(),
            },
        )])],
    );
    let res = w.run();
    assert_eq!(res.outcome, Outcome::Succeeded, "result = {res:?}");
    let m = w.sink.of(MilestoneKind::PermissionDenied);
    assert!(
        m.len() == 1 && m[0].reason == "input_too_large",
        "denied milestones = {m:?}"
    );
    assert!(w.st.approval_list().is_empty());
}

#[test]
fn the_input_mac_key_is_validated() {
    let tr = Trace::default();
    let life = Arc::new(Lifecycle::new(&tr, vec![queued_run()]));
    let st = FakeStore::new(&tr);
    let prov = Arc::new(Provisioner::new(&tr, Arc::new(super::ports::RealTicker)));
    let cap = Arc::new(Capturer::new(&tr));
    let arts = Arc::new(Artifacts::new(&tr));
    let ad = Arc::new(FakeAdapter::new(
        &tr,
        "claude-code",
        bridge_caps(),
        Vec::new(),
    ));
    let err = Orchestrator::new(super::orchestrator::OrchestratorDeps {
        lifecycle: life,
        attempts: st,
        adapter: ad,
        workspaces: prov,
        capture: cap,
        artifacts: arts,
        clock: Arc::new(RealClock),
        ticker: Arc::new(super::ports::RealTicker),
        cfg: OrchestratorConfig {
            adapter_version: "v".to_string(),
            launch_env: test_env(),
            input_mac_key: b"short".to_vec(),
            ..default_cfg()
        },
    })
    .err();
    assert!(err.is_some(), "a short input MAC key was accepted");
}

#[test]
fn a_stopping_run_drops_its_approvals_before_the_terminal_write() {
    for tc in [
        (
            "cancel",
            OrchestratorConfig {
                heartbeat_interval: Duration::milliseconds(10),
                interrupt_grace: Duration::seconds(1),
                ..default_cfg()
            },
            true,
        ),
        (
            "wall clock",
            OrchestratorConfig {
                default_wall_clock: Duration::milliseconds(300),
                interrupt_grace: Duration::seconds(1),
                ..default_cfg()
            },
            false,
        ),
    ] {
        let w = new_world(
            tc.1,
            Capabilities {
                interrupt: true,
                permission_bridge: true,
                ..Capabilities::default()
            },
            vec![bridge_script(vec![bash_request("req-1")])],
        );
        w.life.set_permission(PermissionPolicy::Bridge);
        let saw = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let held = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let saw2 = saw.clone();
        let held2 = held.clone();
        let st2 = w.st.clone();
        let approvals = w.orch.approvals_handle();
        w.st.set_before_write(move |next| {
            if !next.state.is_terminal() || saw2.load(Ordering::SeqCst) {
                return;
            }
            let Some(first) = st2.approval_list().into_iter().next() else {
                return;
            };
            saw2.store(true, Ordering::SeqCst);
            held2.store(
                approvals
                    .pending_request(first.workspace_id, first.id)
                    .is_some(),
                Ordering::SeqCst,
            );
        });
        std::thread::scope(|scope| {
            let h = scope.spawn(|| w.run());
            let a = await_pending(&w, 1);
            assert!(
                w.orch.pending_request(a.workspace_id, a.id).is_some(),
                "the pending request is not held"
            );
            if tc.2 {
                w.life.cancelling.store(true, Ordering::SeqCst);
            }
            let res = h.join().unwrap_or_else(|e| std::panic::resume_unwind(e));
            assert!(
                res.outcome == Outcome::Cancelled || res.reason == FailureCode::BUDGET_WALL_CLOCK,
                "{}: result = {res:?}",
                tc.0
            );
        });
        assert!(
            saw.load(Ordering::SeqCst) && !held.load(Ordering::SeqCst),
            "{}: terminal write seen = {}, request still held then = {}",
            tc.0,
            saw.load(Ordering::SeqCst),
            held.load(Ordering::SeqCst)
        );
        assert_eq!(
            w.st.approval_list()[0].state,
            crate::approval::ApprovalState::Superseded,
            "{}",
            tc.0
        );
        assert!(
            resolved_events(&w).is_empty(),
            "{}: a stopping run answered",
            tc.0
        );
    }
}

#[test]
fn a_superseded_approval_is_never_a_bridge_failure() {
    let w = bridge_world(
        OrchestratorConfig {
            approval_recheck: Duration::milliseconds(20),
            ..default_cfg()
        },
        vec![bridge_script(vec![bash_request("req-1")])],
    );
    std::thread::scope(|scope| {
        let h = scope.spawn(|| w.run());
        let a = await_pending(&w, 1);
        w.st.tamper(a.id, |p| {
            p.state = crate::approval::ApprovalState::Superseded;
            p.decided_by = crate::approval::DECIDED_BY_SUPERSEDED.to_string();
            p.decided_at = Some(time::OffsetDateTime::now_utc());
        });
        w.orch.signal_decision(a.workspace_id, a.id);
        wait_for("re-reads of the superseded approval", || {
            w.tr.count("store.LoadApproval") >= 1
        });
        std::thread::sleep(std::time::Duration::from_millis(60));
        assert!(
            w.orch.pending_request(a.workspace_id, a.id).is_none(),
            "a superseded approval's input stayed held"
        );
        w.stop.cancel();
        let res = h.join().unwrap_or_else(|e| std::panic::resume_unwind(e));
        assert!(
            res.outcome == Outcome::Stopped
                && res.reason != FailureCode::PERMISSION_BRIDGE_UNAVAILABLE,
            "result = {res:?}, want a plain stop"
        );
        assert!(
            resolved_events(&w).is_empty(),
            "a superseded approval was answered"
        );
        assert_eq!(
            w.st.only().state,
            domain::State::AwaitingPermission,
            "want it left for reconciliation"
        );
    });
}

#[test]
fn permission_records_key_the_raw_frame_digest() {
    let key = b"bridge-test-input-mac-key-012345".to_vec();
    let w = bridge_world(
        OrchestratorConfig {
            input_mac_key: key.clone(),
            ..default_cfg()
        },
        vec![bridge_script(vec![bash_request("req-1")])],
    );
    std::thread::scope(|scope| {
        let h = scope.spawn(|| w.run());
        let a = await_pending(&w, 1);
        decide(&w, &a, false);
        let res = h.join().unwrap_or_else(|e| std::panic::resume_unwind(e));
        assert_eq!(res.outcome, Outcome::Succeeded, "result = {res:?}");
        let frame = serde_json::to_vec(&bash_request("req-1")).unwrap_or_default();
        let want = crate::approval::compute_input_mac(&key, &frame)
            .unwrap_or(crate::approval::InputMac([0; 32]));
        let plain: [u8; 32] = sha2::Sha256::digest(&frame).into();
        let mut found = false;
        for rec in w.st.records() {
            assert_ne!(
                rec.raw_sha256,
                plain,
                "{}: the stored digest is the frame's plain SHA-256",
                rec.kind.as_str()
            );
            if rec.kind == EventKind::PermissionRequested {
                found = true;
                assert_eq!(
                    rec.raw_sha256, want.0,
                    "stored digest, want HMAC(key, frame)"
                );
            }
        }
        assert!(found, "no permission_requested record");
    });
}

#[test]
fn a_resolution_the_orchestrator_never_answered_fails_closed() {
    let w = bridge_world(
        default_cfg(),
        vec![succeeded_script(vec![
            bash_request("req-1"),
            EventPayload::PermissionResolved(event::PermissionResolved {
                request_id: "req-1".to_string(),
                decision: event::PermissionOutcome::Allowed,
                decided_by: "operator-session:mallory".to_string(),
            }),
        ])],
    );
    let orphaned = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let orphaned2 = orphaned.clone();
    let st2 = w.st.clone();
    w.st.set_before_write(move |next| {
        if next.state != domain::State::Running {
            return;
        }
        let st = &*st2;
        for a in st.approval_list() {
            if a.attempt_id == next.id && a.state == crate::approval::ApprovalState::Pending {
                orphaned2.store(true, Ordering::SeqCst);
            }
        }
    });
    require_bridge_failure(&w, w.run());
    assert!(
        !orphaned.load(Ordering::SeqCst),
        "a running-state write happened while the approval was pending"
    );
    let list = w.st.approval_list();
    assert!(
        list.len() == 1 && list[0].state == crate::approval::ApprovalState::Superseded,
        "approvals = {list:?}, want the one superseded"
    );
    assert_eq!(
        w.tr.count("store.AppendEvent:permission_resolved"),
        0,
        "the unanswered resolution was recorded"
    );
    assert!(w.sink.of(MilestoneKind::PermissionAllowed).is_empty());
}

#[test]
fn an_answered_request_is_no_longer_held() {
    let mut script = bridge_script(vec![bash_request("req-1")]);
    script.respond_err = Some(Failure::invalid(
        port::codes::NO_PENDING_PERMISSION,
        "claude: no pending permission",
    ));
    let w = bridge_world(default_cfg(), vec![script]);
    std::thread::scope(|scope| {
        let h = scope.spawn(|| w.run());
        let a = await_pending(&w, 1);
        decide(&w, &a, true);
        wait_for("the answered input dropped", || {
            w.orch.pending_request(a.workspace_id, a.id).is_none()
        });
        assert!(
            !h.is_finished(),
            "the input was dropped only when the orchestration ended"
        );
        w.stop.cancel();
        let res = h.join().unwrap_or_else(|e| std::panic::resume_unwind(e));
        assert_eq!(res.outcome, Outcome::Stopped, "result = {res:?}");
    });
}

#[test]
fn a_request_outside_running_fails_closed() {
    let script = Script {
        session_id: "session-1".to_string(),
        payloads: vec![
            bash_request("req-1"),
            EventPayload::SessionStarted(event::SessionStarted {
                harness_session_id: "session-1".to_string(),
                harness_version: "2.1.283".to_string(),
                model: String::new(),
                tools: Vec::new(),
                reported_capabilities: Vec::new(),
            }),
        ],
        terminal: Terminal {
            status: TerminalStatus::Succeeded,
            ..Terminal::default()
        },
        wait_for_permission: true,
        ..Script::default()
    };
    let w = bridge_world(default_cfg(), vec![script]);
    std::thread::scope(|scope| {
        let h = scope.spawn(|| w.run());
        require_bridge_failure(
            &w,
            h.join().unwrap_or_else(|e| std::panic::resume_unwind(e)),
        );
    });
    assert!(w.st.approval_list().is_empty());
}

#[test]
fn a_queued_request_write_failure_is_an_event_write_failure() {
    let mut script = bridge_script(vec![bash_request("req-1"), bash_request("req-2")]);
    script.concurrent_permissions = true;
    let w = bridge_world(
        OrchestratorConfig {
            event_write_budget: Duration::milliseconds(50),
            ..default_cfg()
        },
        vec![script],
    );
    let st2 = w.st.clone();
    w.st.set_before_write(move |next| {
        if next.state == domain::State::AwaitingPermission {
            // Every event write after the one that opens req-1's
            // approval fails, past the write budget.
            st2.set_append_err(Some(err_transient()));
        }
    });
    std::thread::scope(|scope| {
        let h = scope.spawn(|| w.run());
        let res = h.join().unwrap_or_else(|e| std::panic::resume_unwind(e));
        assert!(
            res.outcome == Outcome::Failed && res.reason == FailureCode::EXECUTION_FAILED,
            "result = {res:?}, want failed execution_failed"
        );
    });
    assert!(
        w.tr.count("store.AppendEvent:permission_requested") >= 2,
        "want the open one and the queued one's tries"
    );
    let list = w.st.approval_list();
    assert!(
        list.len() == 1 && list[0].state == crate::approval::ApprovalState::Superseded,
        "approvals = {list:?}, want req-1's superseded"
    );
}

// ---------------------------------------------------------------------------
// cancel_test.go
// ---------------------------------------------------------------------------

#[test]
fn orchestrator_cancel_interrupts_a_running_harness() {
    let w = new_world(
        OrchestratorConfig {
            heartbeat_interval: Duration::milliseconds(10),
            interrupt_grace: Duration::minutes(1),
            ..default_cfg()
        },
        Capabilities {
            interrupt: true,
            ..Capabilities::default()
        },
        vec![blocking_script()],
    );
    std::thread::scope(|scope| {
        let h = scope.spawn(|| w.run());
        wait_for("the running harness", || {
            w.tr.count("store.AppendEvent:permission_requested") == 1
        });
        w.life.cancelling.store(true, Ordering::SeqCst);
        let res = h.join().unwrap_or_else(|e| std::panic::resume_unwind(e));
        require_cancelled(&w, &res);
        let (interrupts, kills) = w.ad.session_counts(0).unwrap_or_default();
        assert_eq!((interrupts, kills), (1, 0));
        assert_eq!(
            w.st.only().state,
            domain::State::Interrupted,
            "want interrupted"
        );
        assert!(
            w.tr.index("store.AppendEvent:terminal_reported")
                < w.tr.index("lifecycle.SettleCancellation"),
            "cancellation settled before the terminal was persisted: {:?}",
            w.tr.all()
        );
        assert_eq!(
            w.sink.of(MilestoneKind::Terminal)[0].status,
            domain::State::Interrupted.as_str()
        );
    });
}

#[test]
fn orchestrator_cancel_kills_a_harness_that_ignores_the_interrupt() {
    let w = new_world(
        OrchestratorConfig {
            heartbeat_interval: Duration::milliseconds(10),
            interrupt_grace: Duration::milliseconds(30),
            ..default_cfg()
        },
        Capabilities {
            interrupt: true,
            ..Capabilities::default()
        },
        vec![blocking_script()],
    );
    w.ad.set_swallow_interrupt(true);
    std::thread::scope(|scope| {
        let h = scope.spawn(|| w.run());
        wait_for("the running harness", || {
            w.tr.count("store.AppendEvent:permission_requested") == 1
        });
        w.life.cancelling.store(true, Ordering::SeqCst);
        let res = h.join().unwrap_or_else(|e| std::panic::resume_unwind(e));
        require_cancelled(&w, &res);
        let (interrupts, kills) = w.ad.session_counts(0).unwrap_or_default();
        assert_eq!((interrupts, kills), (1, 1));
        assert_eq!(w.st.only().state, domain::State::Killed);
    });
}

#[test]
fn orchestrator_cancel_during_the_clone_closes_the_prepared_attempt() {
    let w = new_world(
        OrchestratorConfig {
            heartbeat_interval: Duration::milliseconds(10),
            ..default_cfg()
        },
        Capabilities::default(),
        vec![succeeded_script(Vec::new())],
    );
    w.prov.set_block(true);
    std::thread::scope(|scope| {
        let h = scope.spawn(|| w.run());
        wait_for("the clone", || w.tr.count("provisioner.Provision") == 1);
        w.life.cancelling.store(true, Ordering::SeqCst);
        let res = h.join().unwrap_or_else(|e| std::panic::resume_unwind(e));
        require_cancelled(&w, &res);
    });
    for call in ["store.Create", "lifecycle.MarkInvoked", "adapter.Start"] {
        assert_eq!(w.tr.count(call), 0, "{call} after the cancellation");
    }
    assert_eq!(
        w.sink.of(MilestoneKind::Terminal)[0].status,
        super::ports::MILESTONE_REASON_CANCELLED
    );
}

#[test]
fn orchestrator_cancel_seen_by_mark_invoked_never_launches() {
    // No heartbeat fires before MarkInvoked: the lifecycle's refusal
    // alone must stop the launch.
    let w = new_world(
        OrchestratorConfig {
            heartbeat_interval: Duration::hours(1),
            ..default_cfg()
        },
        Capabilities::default(),
        vec![succeeded_script(Vec::new())],
    );
    w.life.cancelling.store(true, Ordering::SeqCst);
    let res = w.run();
    require_cancelled(&w, &res);
    assert_eq!(w.tr.count("adapter.Start"), 0, "launched a cancelled task");
    let a = w.st.only();
    assert!(
        a.state == domain::State::Failed && !a.terminal.reason.is_empty(),
        "attempt = {:?}/{:?}, want the never-launched terminal",
        a.state,
        a.terminal.reason
    );
}

#[test]
fn orchestrator_cancel_seen_by_settle_settles_the_cancellation() {
    let w = new_world(
        OrchestratorConfig {
            heartbeat_interval: Duration::hours(1),
            ..default_cfg()
        },
        Capabilities::default(),
        vec![failed_script("harness_api_error")],
    );
    w.life.cancel_at_settle.store(true, Ordering::SeqCst);
    let res = w.run();
    assert!(
        res.outcome == Outcome::Cancelled
            && res.err.is_none()
            && w.life.cancellations.load(Ordering::SeqCst) == 1,
        "result = {res:?}"
    );
    assert_eq!(
        w.st.only().state,
        domain::State::Failed,
        "the harness terminal must stay as reported"
    );
    assert!(
        w.tr.index("lifecycle.Settle") < w.tr.index("lifecycle.SettleCancellation"),
        "order: {:?}",
        w.tr.all()
    );
}

// `successorWorld` — a re-claimed prepared successor: the earlier claim
// created the harness row before a stop.
fn successor_world(
    change: impl FnOnce(crate::attempt::Attempt) -> crate::attempt::Attempt,
) -> (World, DispatchableRun, crate::attempt::Attempt) {
    let w = new_world(
        default_cfg(),
        Capabilities::default(),
        vec![succeeded_script(Vec::new())],
    );
    let run = DispatchableRun {
        case: super::ports::DispatchCase::PreparedSuccessor,
        workspace_id: central_foundation::identity::WorkspaceId::new(),
        task_id: central_foundation::identity::TaskId::new(),
        run_id: central_foundation::identity::RunId::new(),
        step_id: central_foundation::identity::StepId::new(),
        step_attempt_id: central_foundation::identity::StepAttemptId::new(),
    };
    let id = crate::recovery::attempt_id_for_step_attempt(run.step_attempt_id).expect("attempt id");
    let prior = crate::attempt::Attempt::prepare(crate::attempt::PrepareInput {
        id,
        workspace_id: run.workspace_id,
        run_id: run.run_id,
        kind: crate::domain::Kind::new("claude-code"),
        adapter_version: "claudecode/3a".to_string(),
        workspace: crate::domain::Workspace {
            path: format!(
                "/var/lib/central-harness/worktrees/runs/{}/repo",
                run.run_id
            ),
            base_sha: BASE_SHA.to_string(),
        },
        permission: PermissionPolicy::Deny,
        fence: crate::domain::Fence { generation: 1 },
        budget: crate::budget::Budget {
            cost_micro_usd: 5_000_000,
            wall_clock: Duration::minutes(30),
            cost_defaulted: false,
            wall_clock_defaulted: false,
        },
        at: time::OffsetDateTime::now_utc() - Duration::minutes(1),
    })
    .expect("prepare");
    let prior = change(prior);
    w.st.seed_attempt(prior.clone());
    w.life.set_generation(1); // the next claim takes generation 2
    (w, run, prior)
}

#[test]
fn orchestrator_adopts_the_prepared_row_of_a_reclaimed_successor() {
    let (w, run, prior) = successor_world(|a| a);
    let res = block_on(w.orch.run_dispatchable(run, "2.1.283", &*w.stop));
    assert!(
        res.outcome == Outcome::Succeeded && res.err.is_none(),
        "result = {res:?} ({:?})",
        w.tr.all()
    );
    let a = w.st.only();
    assert!(
        a.id == prior.id
            && a.state == domain::State::Succeeded
            && a.fence.generation == 2
            && a.prepared_at == prior.prepared_at,
        "attempt = {:?} fence {} prepared {:?}",
        a.state,
        a.fence.generation,
        a.prepared_at
    );
    let order = [
        "store.Create",
        "store.Save:prepared",
        "lifecycle.MarkInvoked",
        "adapter.Start",
        "lifecycle.CompleteWithReport",
    ];
    let mut last: i64 = -1;
    for call in order {
        let i = w.tr.index(call);
        assert!(
            i > last,
            "{call} at {i}, not after {last}: {:?}",
            w.tr.all()
        );
        last = i;
    }
    assert_eq!(
        w.tr.count("lifecycle.AbandonPrepared"),
        0,
        "the re-claimed successor was abandoned"
    );
}

#[test]
fn orchestrator_abandons_a_successor_row_it_cannot_adopt() {
    for tc in [
        (
            "the source moved",
            Box::new(|mut a: crate::attempt::Attempt| {
                a.workspace.base_sha = "89abcdef0123456789abcdef0123456789abcdef".to_string();
                a
            }) as Box<dyn FnOnce(crate::attempt::Attempt) -> crate::attempt::Attempt>,
            FailureCode::WORKSPACE_UNAVAILABLE,
            codes::WORKSPACE_UNAVAILABLE,
        ),
        (
            "a newer fence",
            Box::new(|mut a: crate::attempt::Attempt| {
                a.fence = crate::domain::Fence { generation: 5 };
                a
            }) as Box<dyn FnOnce(crate::attempt::Attempt) -> crate::attempt::Attempt>,
            FailureCode::EXECUTION_FAILED,
            domain::codes::VERSION_CONFLICT,
        ),
        (
            "already launched",
            Box::new(|a: crate::attempt::Attempt| {
                a.launch(a.fence, &a.id.to_string(), "2.1.283", a.updated_at)
                    .expect("launch")
            }) as Box<dyn FnOnce(crate::attempt::Attempt) -> crate::attempt::Attempt>,
            FailureCode::EXECUTION_FAILED,
            domain::codes::VERSION_CONFLICT,
        ),
    ] {
        let (w, run, _) = successor_world(|a| (tc.1)(a));
        let res = block_on(w.orch.run_dispatchable(run, "2.1.283", &*w.stop));
        assert!(
            res.outcome == Outcome::Abandoned && res.reason == tc.2,
            "{}: result = {res:?}",
            tc.0
        );
        assert!(
            w.tr.count("adapter.Start") == 0 && w.tr.count("lifecycle.MarkInvoked") == 0,
            "{}: launched: {:?}",
            tc.0,
            w.tr.all()
        );
        let ok = is_code(res.err.as_ref(), tc.3)
            || is_code(res.err.as_ref(), codes::WORKSPACE_UNAVAILABLE);
        assert!(ok, "{}: cause = {:?}", tc.0, res.err);
    }
}

// ===== budget_test.rs =====

/// `costCaps` — a live-usage adapter without a native cost limit.
fn cost_caps() -> Capabilities {
    Capabilities {
        interrupt: true,
        cost_usd: true,
        usage_scope: UsageScope::SessionCumulative,
        ..Capabilities::default()
    }
}

/// `costReport`.
fn cost_report(micro: i64) -> EventPayload {
    EventPayload::UsageReport(event::UsageReport {
        usage: Usage {
            tokens_in: 100,
            tokens_out: 20,
            cost_micro_usd: micro,
            scope: UsageScope::SessionCumulative,
            estimated: true,
            ..Usage::default()
        },
    })
}

/// `liveUsageScript` — reports usage live, then waits on a permission
/// request nobody answers, so only Central's stop ends it.
fn live_usage_script(micro: i64) -> Script {
    let mut s = succeeded_script(vec![
        cost_report(micro),
        EventPayload::PermissionRequested(event::PermissionRequested {
            request_id: "req-1".to_string(),
            tool: "Bash".to_string(),
            ..event::PermissionRequested::default()
        }),
    ]);
    s.wait_for_permission = true;
    s
}

/// `resultScript` — usage arrives with the final result.
fn result_script(micro: i64, terminal: Terminal) -> Script {
    let mut s = succeeded_script(vec![cost_report(micro)]);
    s.terminal = terminal;
    s
}

fn session_ended_err() -> Failure {
    Failure::invalid(crate::port::codes::SESSION_ENDED, "adapter: session ended")
}

#[test]
fn prepare_records_the_claimed_budget() {
    let w = new_world(
        OrchestratorConfig {
            default_wall_clock: Duration::minutes(45),
            ..default_cfg()
        },
        Capabilities::default(),
        vec![succeeded_script(Vec::new())],
    );
    let claimed = Budget {
        cost_micro_usd: 750_000,
        wall_clock: Duration::minutes(20),
        ..Budget::default()
    };
    w.life.set_budget(claimed);
    let res = w.run();
    assert!(res.outcome == Outcome::Succeeded, "result = {res:?}");
    assert_eq!(w.st.only().budget, claimed, "attempt budget");
}

#[test]
fn prepare_fills_unset_bounds_with_the_defaults_and_flags_them() {
    for (claimed, want) in [
        (
            Budget::default(),
            Budget {
                cost_micro_usd: 5_000_000,
                wall_clock: Duration::minutes(45),
                cost_defaulted: true,
                wall_clock_defaulted: true,
            },
        ),
        (
            Budget {
                cost_micro_usd: 10_000,
                ..Budget::default()
            },
            Budget {
                cost_micro_usd: 10_000,
                wall_clock: Duration::minutes(45),
                cost_defaulted: false,
                wall_clock_defaulted: true,
            },
        ),
        (
            Budget {
                wall_clock: Duration::minutes(1),
                ..Budget::default()
            },
            Budget {
                cost_micro_usd: 5_000_000,
                wall_clock: Duration::minutes(1),
                cost_defaulted: true,
                wall_clock_defaulted: false,
            },
        ),
    ] {
        let w = new_world(
            OrchestratorConfig {
                default_wall_clock: Duration::minutes(45),
                ..default_cfg()
            },
            Capabilities::default(),
            vec![succeeded_script(Vec::new())],
        );
        w.life.set_budget(claimed);
        let res = w.run();
        assert!(res.outcome == Outcome::Succeeded, "result = {res:?}");
        assert_eq!(w.st.only().budget, want, "attempt budget");
    }
    assert_eq!(
        default_cfg().default_cost_micro_usd,
        5_000_000,
        "DefaultMaxCostMicroUSD"
    );
}

/// `TestTheAttemptsWallClockArmsTheTimer` — the recorded wall clock, not
/// the configured default, stops the Run.
#[test]
fn the_attempts_wall_clock_arms_the_timer() {
    let w = new_world(
        OrchestratorConfig {
            default_wall_clock: Duration::hours(1),
            interrupt_grace: Duration::seconds(1),
            ..default_cfg()
        },
        Capabilities {
            interrupt: true,
            ..Capabilities::default()
        },
        vec![blocking_script()],
    );
    w.life.set_budget(Budget {
        cost_micro_usd: 1_000_000,
        wall_clock: Duration::milliseconds(50),
        ..Budget::default()
    });
    let res = std::thread::scope(|scope| scope.spawn(|| w.run()).join().unwrap());
    assert!(
        res.outcome == Outcome::Failed && res.reason == FailureCode::BUDGET_WALL_CLOCK,
        "result = {res:?}"
    );
    let a = w.st.only();
    assert!(
        a.state == domain::State::BudgetExhausted
            && a.terminal.reason == FailureCode::BUDGET_WALL_CLOCK.as_str()
            && a.budget.wall_clock == Duration::milliseconds(50)
            && !a.budget.wall_clock_defaulted,
        "attempt = {}/{} budget {:?}",
        a.state.as_str(),
        a.terminal.reason,
        a.budget
    );
}

/// `TestALiveUsageReportAtTheLimitStopsTheRunBudgetCost` — Central's
/// backstop: a report at the limit while live stops via the kill ladder.
#[test]
fn a_live_usage_report_at_the_limit_stops_the_run_budget_cost() {
    let w = new_world(
        OrchestratorConfig {
            interrupt_grace: Duration::seconds(1),
            ..default_cfg()
        },
        cost_caps(),
        vec![live_usage_script(500_000)],
    );
    w.life.set_budget(Budget {
        cost_micro_usd: 500_000,
        wall_clock: Duration::hours(1),
        ..Budget::default()
    });
    let res = w.run();
    assert!(
        res.outcome == Outcome::Failed && res.reason == FailureCode::BUDGET_COST,
        "result = {res:?}"
    );
    let a = w.st.only();
    assert!(
        a.state == domain::State::BudgetExhausted
            && a.terminal.reason == FailureCode::BUDGET_COST.as_str()
            && a.usage.cost_micro_usd == 500_000,
        "attempt = {}/{} usage {:?}",
        a.state.as_str(),
        a.terminal.reason,
        a.usage
    );
    let (interrupts, kills) = w.ad.session_counts(0).unwrap_or_default();
    assert!(
        interrupts == 1 && kills == 0,
        "interrupts={interrupts} kills={kills}"
    );
    for call in [
        "capture.Capture",
        "artifacts.Store:harness.patch",
        "artifacts.Store:harness.commits",
    ] {
        assert!(
            w.tr.index(call) >= 0,
            "a budget stop did not run {call}: {:?}",
            w.tr.all()
        );
    }
    let (_, settled, _) = w.life.snapshot();
    assert!(
        settled.len() == 1 && settled[0].reason == FailureCode::BUDGET_COST,
        "settled = {settled:?}"
    );
}

#[test]
fn a_live_usage_report_below_the_limit_does_not_stop_the_run() {
    let w = new_world(
        default_cfg(),
        cost_caps(),
        vec![succeeded_script(vec![cost_report(499_999)])],
    );
    w.life.set_budget(Budget {
        cost_micro_usd: 500_000,
        wall_clock: Duration::hours(1),
        ..Budget::default()
    });
    let res = w.run();
    assert!(res.outcome == Outcome::Succeeded, "result = {res:?}");
    let (interrupts, _) = w.ad.session_counts(0).unwrap_or_default();
    assert_eq!(interrupts, 0);
}

/// `TestTheHarnesssOwnBudgetStopKeepsHarnessBudget` — outcome rule 1.
#[test]
fn the_harnesss_own_budget_stop_keeps_harness_budget() {
    let w = new_world(
        OrchestratorConfig {
            interrupt_grace: Duration::minutes(1),
            ..default_cfg()
        },
        cost_caps(),
        vec![result_script(
            600_000,
            Terminal {
                status: TerminalStatus::Budget,
                reason: FailureCode::BUDGET.as_str().to_string(),
                ..Terminal::default()
            },
        )],
    );
    w.ad.set_interrupt_err(Some(session_ended_err()));
    w.life.set_budget(Budget {
        cost_micro_usd: 500_000,
        wall_clock: Duration::hours(1),
        ..Budget::default()
    });
    let res = w.run();
    assert!(
        res.outcome == Outcome::Failed && res.reason == FailureCode::BUDGET,
        "result = {res:?}, want harness_budget"
    );
    let a = w.st.only();
    assert!(
        a.state == domain::State::BudgetExhausted
            && a.terminal.reason == FailureCode::BUDGET.as_str(),
        "attempt = {}/{}",
        a.state.as_str(),
        a.terminal.reason
    );
    let (_, kills) = w.ad.session_counts(0).unwrap_or_default();
    assert_eq!(kills, 0, "a session that already ended was killed");
}

/// `TestASuccessOverTheLimitStaysSucceeded` — outcome rule 2.
#[test]
fn a_success_over_the_limit_stays_succeeded() {
    let w = new_world(
        OrchestratorConfig {
            interrupt_grace: Duration::minutes(1),
            ..default_cfg()
        },
        cost_caps(),
        vec![result_script(
            900_000,
            Terminal {
                status: TerminalStatus::Succeeded,
                ..Terminal::default()
            },
        )],
    );
    w.ad.set_interrupt_err(Some(session_ended_err()));
    w.life.set_budget(Budget {
        cost_micro_usd: 500_000,
        wall_clock: Duration::hours(1),
        ..Budget::default()
    });
    let res = w.run();
    assert!(res.outcome == Outcome::Succeeded, "result = {res:?}");
    let a = w.st.only();
    assert!(
        a.state == domain::State::Succeeded
            && a.usage.cost_micro_usd == 900_000
            && a.budget.cost_micro_usd == 500_000,
        "attempt = {} usage {:?} budget {:?}",
        a.state.as_str(),
        a.usage,
        a.budget
    );
    let (_, kills) = w.ad.session_counts(0).unwrap_or_default();
    assert_eq!(kills, 0);
}

/// `TestAHarnessFailureOverTheLimitKeepsItsReason` — outcome rule 3's
/// exception.
#[test]
fn a_harness_failure_over_the_limit_keeps_its_reason() {
    let w = new_world(
        OrchestratorConfig {
            interrupt_grace: Duration::minutes(1),
            ..default_cfg()
        },
        cost_caps(),
        vec![result_script(
            900_000,
            Terminal {
                status: TerminalStatus::Failed,
                reason: "harness_api_error".to_string(),
                ..Terminal::default()
            },
        )],
    );
    w.ad.set_interrupt_err(Some(session_ended_err()));
    w.life.set_budget(Budget {
        cost_micro_usd: 500_000,
        wall_clock: Duration::hours(1),
        ..Budget::default()
    });
    let res = w.run();
    assert!(
        res.outcome == Outcome::Failed && res.reason.as_str() == "harness_api_error",
        "result = {res:?}, want the harness's own harness_api_error"
    );
    assert_eq!(w.st.only().state, domain::State::Failed);
}

/// `TestASessionThatEndedButHangsIsStillReapedAfterTheGrace`.
#[test]
fn a_session_that_ended_but_hangs_is_still_reaped_after_the_grace() {
    let w = new_world(
        OrchestratorConfig {
            interrupt_grace: Duration::milliseconds(200),
            ..default_cfg()
        },
        cost_caps(),
        vec![live_usage_script(1)],
    );
    w.ad.set_interrupt_err(Some(session_ended_err()));
    w.life.set_budget(Budget {
        cost_micro_usd: 500_000,
        wall_clock: Duration::milliseconds(30),
        ..Budget::default()
    });
    let res = std::thread::scope(|scope| {
        let h = scope.spawn(|| w.run());
        wait_for("the wall clock's interrupt", || {
            w.ad.session_counts(0).map(|(i, _)| i >= 1).unwrap_or(false)
        });
        let (_, kills) = w.ad.session_counts(0).unwrap_or_default();
        assert_eq!(kills, 0, "an ErrSessionEnded interrupt killed at once");
        wait_for("the kill after the grace", || {
            w.ad.session_counts(0).map(|(_, k)| k >= 1).unwrap_or(false)
        });
        h.join().unwrap()
    });
    assert!(
        res.outcome == Outcome::Failed && res.reason == FailureCode::BUDGET_WALL_CLOCK,
        "result = {res:?}"
    );
}

/// `TestTheLimitIsPassedOnlyWithTheCapability` — governing §13.
#[test]
fn the_limit_is_passed_only_with_the_capability() {
    for (caps, want) in [
        (
            Capabilities {
                native_cost_limit: true,
                ..Capabilities::default()
            },
            750_000,
        ),
        (Capabilities::default(), 0),
    ] {
        let w = new_world(default_cfg(), caps, vec![succeeded_script(Vec::new())]);
        w.life.set_budget(Budget {
            cost_micro_usd: 750_000,
            wall_clock: Duration::hours(1),
            ..Budget::default()
        });
        let res = w.run();
        assert!(res.outcome == Outcome::Succeeded, "result = {res:?}");
        let calls = w.ad.calls();
        assert!(
            calls.len() == 1 && calls[0].1.limits.max_cost_micro_usd == want,
            "calls = {calls:?}, want MaxCostMicroUSD {want}"
        );
    }
}

/// `TestAUsageReportDuringACancelLeavesTheCancelsTerminal`.
#[test]
fn a_usage_report_during_a_cancel_leaves_the_cancels_terminal() {
    let w = new_world(
        OrchestratorConfig {
            heartbeat_interval: Duration::milliseconds(10),
            interrupt_grace: Duration::minutes(1),
            ..default_cfg()
        },
        cost_caps(),
        vec![live_usage_script(1)],
    );
    w.ad.set_inject_on_interrupt(Some(cost_report(900_000)));
    w.life.set_budget(Budget {
        cost_micro_usd: 500_000,
        wall_clock: Duration::hours(1),
        ..Budget::default()
    });
    let res = std::thread::scope(|scope| {
        let h = scope.spawn(|| w.run());
        wait_for("the running harness", || {
            w.tr.count("store.AppendEvent:permission_requested") == 1
        });
        w.life.cancelling.store(true, Ordering::SeqCst);
        h.join().unwrap()
    });
    require_cancelled(&w, &res);
    let a = w.st.only();
    assert!(
        a.state == domain::State::Interrupted
            && a.terminal.reason != FailureCode::BUDGET_COST.as_str()
            && a.usage.cost_micro_usd == 900_000,
        "attempt = {}/{} usage {:?}, want the cancel's interrupted terminal",
        a.state.as_str(),
        a.terminal.reason,
        a.usage
    );
    let (interrupts, kills) = w.ad.session_counts(0).unwrap_or_default();
    assert!(
        interrupts == 1 && kills == 0,
        "interrupts={interrupts} kills={kills}"
    );
}

/// `TestPrepareDefaultsANegativeClaimedBound`.
#[test]
fn prepare_defaults_a_negative_claimed_bound() {
    let w = new_world(
        OrchestratorConfig {
            default_wall_clock: Duration::minutes(45),
            ..default_cfg()
        },
        Capabilities::default(),
        vec![succeeded_script(Vec::new())],
    );
    w.life.set_budget(Budget {
        cost_micro_usd: -1,
        wall_clock: Duration::seconds(-1),
        ..Budget::default()
    });
    let res = w.run();
    assert!(res.outcome == Outcome::Succeeded, "result = {res:?}");
    let want = Budget {
        cost_micro_usd: 5_000_000,
        wall_clock: Duration::minutes(45),
        cost_defaulted: true,
        wall_clock_defaulted: true,
    };
    assert_eq!(w.st.only().budget, want, "attempt budget");
}

// ===== token_ceiling_test.rs =====

const TOKEN_CEILING: i64 = 100_000;

/// `tokenReport` — a live session-cumulative report of billed tokens;
/// the cache read, which never counts, is far over the ceiling.
fn token_report(tokens_in: i64, tokens_out: i64, cache_write: i64) -> EventPayload {
    EventPayload::UsageReport(event::UsageReport {
        usage: Usage {
            tokens_in,
            tokens_out,
            cache_read: 5_000_000,
            cache_write,
            scope: UsageScope::SessionCumulative,
            estimated: true,
            ..Usage::default()
        },
    })
}

/// `overTheCeiling` — 100,000 billed tokens.
fn over_the_ceiling() -> EventPayload {
    token_report(10, 40_000, 59_990)
}

/// `liveTokenScript`.
fn live_token_script(report: EventPayload) -> Script {
    let mut s = succeeded_script(vec![
        report,
        EventPayload::PermissionRequested(event::PermissionRequested {
            request_id: "req-1".to_string(),
            tool: "Bash".to_string(),
            ..event::PermissionRequested::default()
        }),
    ]);
    s.wait_for_permission = true;
    s
}

/// `ceilingWorld` — the token ceiling and a US$5.00 budget, so the cost
/// never fires unless a test says.
fn ceiling_world(cfg: OrchestratorConfig, script: Script) -> World {
    let w = new_world(
        OrchestratorConfig {
            max_tokens: TOKEN_CEILING,
            ..cfg
        },
        cost_caps(),
        vec![script],
    );
    w.life.set_budget(Budget {
        cost_micro_usd: 5_000_000,
        wall_clock: Duration::seconds(10),
        ..Budget::default()
    });
    w
}

/// `TestALiveTokenReportAtTheCeilingStopsTheRunBudgetTokens`.
#[test]
fn a_live_token_report_at_the_ceiling_stops_the_run_budget_tokens() {
    let w = ceiling_world(
        OrchestratorConfig {
            interrupt_grace: Duration::milliseconds(30),
            ..default_cfg()
        },
        live_token_script(over_the_ceiling()),
    );
    w.ad.set_swallow_interrupt(true);
    let res = w.run();
    assert!(
        res.outcome == Outcome::Failed && res.reason == FailureCode::BUDGET_TOKENS,
        "result = {res:?}"
    );
    let a = w.st.only();
    let EventPayload::UsageReport(r) = over_the_ceiling() else {
        unreachable!()
    };
    assert!(
        a.state == domain::State::BudgetExhausted
            && a.terminal.reason == FailureCode::BUDGET_TOKENS.as_str()
            && a.usage == r.usage,
        "attempt = {}/{} usage {:?}",
        a.state.as_str(),
        a.terminal.reason,
        a.usage
    );
    let (interrupts, kills) = w.ad.session_counts(0).unwrap_or_default();
    assert!(
        interrupts == 1 && kills == 1,
        "interrupts={interrupts} kills={kills}"
    );
    for call in [
        "capture.Capture",
        "artifacts.Store:harness.patch",
        "artifacts.Store:harness.commits",
    ] {
        assert!(
            w.tr.index(call) >= 0,
            "a token stop did not run {call}: {:?}",
            w.tr.all()
        );
    }
    let (_, settled, _) = w.life.snapshot();
    assert!(
        settled.len() == 1 && settled[0].reason == FailureCode::BUDGET_TOKENS,
        "settled = {settled:?}"
    );
}

/// `TestALiveTokenReportBelowTheCeilingDoesNotStopTheRun`.
#[test]
fn a_live_token_report_below_the_ceiling_does_not_stop_the_run() {
    let w = ceiling_world(
        default_cfg(),
        succeeded_script(vec![token_report(10, 40_000, 59_989)]),
    );
    let res = w.run();
    assert!(res.outcome == Outcome::Succeeded, "result = {res:?}");
    let (interrupts, _) = w.ad.session_counts(0).unwrap_or_default();
    assert_eq!(interrupts, 0);
}

/// `TestWithoutATokenCeilingTokensNeverStopTheRun`.
#[test]
fn without_a_token_ceiling_tokens_never_stop_the_run() {
    let w = new_world(
        default_cfg(),
        cost_caps(),
        vec![succeeded_script(vec![token_report(
            1 << 40,
            1 << 40,
            1 << 40,
        )])],
    );
    w.life.set_budget(Budget {
        cost_micro_usd: 5_000_000,
        wall_clock: Duration::hours(1),
        ..Budget::default()
    });
    let res = w.run();
    assert!(res.outcome == Outcome::Succeeded, "result = {res:?}");
    let (interrupts, _) = w.ad.session_counts(0).unwrap_or_default();
    assert_eq!(interrupts, 0);
}

/// `TestASuccessOverTheTokenCeilingStaysSucceeded` — outcome rule 2.
#[test]
fn a_success_over_the_token_ceiling_stays_succeeded() {
    let w = ceiling_world(
        OrchestratorConfig {
            interrupt_grace: Duration::minutes(1),
            ..default_cfg()
        },
        succeeded_script(vec![token_report(10, 90_000, 90_000)]),
    );
    w.ad.set_interrupt_err(Some(session_ended_err()));
    let res = w.run();
    assert!(res.outcome == Outcome::Succeeded, "result = {res:?}");
    let a = w.st.only();
    assert!(
        a.state == domain::State::Succeeded && a.usage.tokens_out == 90_000,
        "attempt = {} usage {:?}",
        a.state.as_str(),
        a.usage
    );
    let (interrupts, kills) = w.ad.session_counts(0).unwrap_or_default();
    assert_eq!(interrupts, 1, "the token stop never fired");
    assert_eq!(kills, 0);
}

/// `TestTheHarnesssOwnBudgetStopKeepsItsReasonOverTheTokenCeiling` —
/// outcome rule 1.
#[test]
fn the_harnesss_own_budget_stop_keeps_its_reason_over_the_token_ceiling() {
    let mut s = succeeded_script(vec![over_the_ceiling()]);
    s.terminal = Terminal {
        status: TerminalStatus::Budget,
        reason: FailureCode::BUDGET.as_str().to_string(),
        ..Terminal::default()
    };
    let w = ceiling_world(
        OrchestratorConfig {
            interrupt_grace: Duration::minutes(1),
            ..default_cfg()
        },
        s,
    );
    w.ad.set_interrupt_err(Some(session_ended_err()));
    let res = w.run();
    assert!(
        res.outcome == Outcome::Failed && res.reason == FailureCode::BUDGET,
        "result = {res:?}, want harness_budget"
    );
    let a = w.st.only();
    assert!(
        a.state == domain::State::BudgetExhausted
            && a.terminal.reason == FailureCode::BUDGET.as_str(),
        "attempt = {}/{}",
        a.state.as_str(),
        a.terminal.reason
    );
    let (interrupts, _) = w.ad.session_counts(0).unwrap_or_default();
    assert_eq!(interrupts, 1, "the token stop never fired");
}

/// `TestAHarnessFailureOverTheTokenCeilingKeepsItsReason` — outcome
/// rule 3's exception.
#[test]
fn a_harness_failure_over_the_token_ceiling_keeps_its_reason() {
    let mut s = succeeded_script(vec![over_the_ceiling()]);
    s.terminal = Terminal {
        status: TerminalStatus::Failed,
        reason: "harness_api_error".to_string(),
        ..Terminal::default()
    };
    let w = ceiling_world(
        OrchestratorConfig {
            interrupt_grace: Duration::minutes(1),
            ..default_cfg()
        },
        s,
    );
    w.ad.set_interrupt_err(Some(session_ended_err()));
    let res = w.run();
    assert!(
        res.outcome == Outcome::Failed && res.reason.as_str() == "harness_api_error",
        "result = {res:?}, want the harness's own harness_api_error"
    );
    let (interrupts, _) = w.ad.session_counts(0).unwrap_or_default();
    assert_eq!(interrupts, 1, "the token stop never fired");
}

/// `TestTheTokenCeilingFiringFirstWinsOverALaterCost`.
#[test]
fn the_token_ceiling_firing_first_wins_over_a_later_cost() {
    let w = ceiling_world(
        OrchestratorConfig {
            interrupt_grace: Duration::minutes(1),
            ..default_cfg()
        },
        live_token_script(over_the_ceiling()),
    );
    w.life.set_budget(Budget {
        cost_micro_usd: 500_000,
        wall_clock: Duration::seconds(10),
        ..Budget::default()
    });
    let EventPayload::UsageReport(mut later) = over_the_ceiling() else {
        unreachable!()
    };
    later.usage.cost_micro_usd = 900_000;
    w.ad.set_inject_on_interrupt(Some(EventPayload::UsageReport(later)));
    let res = w.run();
    assert!(
        res.outcome == Outcome::Failed && res.reason == FailureCode::BUDGET_TOKENS,
        "result = {res:?}, want budget_tokens"
    );
    let a = w.st.only();
    assert!(
        a.terminal.reason == FailureCode::BUDGET_TOKENS.as_str()
            && a.usage.cost_micro_usd == 900_000,
        "attempt = {}/{} usage {:?}",
        a.state.as_str(),
        a.terminal.reason,
        a.usage
    );
    let (interrupts, kills) = w.ad.session_counts(0).unwrap_or_default();
    assert!(
        interrupts == 1 && kills == 0,
        "interrupts={interrupts} kills={kills}"
    );
}

/// `TestTheTokenCeilingFiringFirstWinsOverALaterWallClock`.
#[test]
fn the_token_ceiling_firing_first_wins_over_a_later_wall_clock() {
    let w = ceiling_world(
        OrchestratorConfig {
            interrupt_grace: Duration::seconds(1),
            ..default_cfg()
        },
        live_token_script(over_the_ceiling()),
    );
    w.ad.set_swallow_interrupt(true); // only the kill after the grace ends it
    w.life.set_budget(Budget {
        cost_micro_usd: 5_000_000,
        wall_clock: Duration::milliseconds(200),
        ..Budget::default()
    });
    let res = w.run();
    assert!(
        res.outcome == Outcome::Failed && res.reason == FailureCode::BUDGET_TOKENS,
        "result = {res:?}, want budget_tokens"
    );
    let (interrupts, kills) = w.ad.session_counts(0).unwrap_or_default();
    assert!(
        interrupts == 1 && kills == 1,
        "interrupts={interrupts} kills={kills}"
    );
}

/// `TestAReportOverTheCostAndTheTokenCeilingFailsBudgetCost` — the cost
/// is checked first.
#[test]
fn a_report_over_the_cost_and_the_token_ceiling_fails_budget_cost() {
    let EventPayload::UsageReport(mut both) = over_the_ceiling() else {
        unreachable!()
    };
    both.usage.cost_micro_usd = 600_000;
    let w = ceiling_world(
        OrchestratorConfig {
            interrupt_grace: Duration::seconds(1),
            ..default_cfg()
        },
        live_token_script(EventPayload::UsageReport(both)),
    );
    w.life.set_budget(Budget {
        cost_micro_usd: 500_000,
        wall_clock: Duration::seconds(10),
        ..Budget::default()
    });
    let res = w.run();
    assert!(
        res.outcome == Outcome::Failed && res.reason == FailureCode::BUDGET_COST,
        "result = {res:?}, want budget_cost"
    );
}

/// `TestACancelWinsOverTheTokenCeiling`.
#[test]
fn a_cancel_wins_over_the_token_ceiling() {
    let w = ceiling_world(
        OrchestratorConfig {
            heartbeat_interval: Duration::milliseconds(10),
            interrupt_grace: Duration::minutes(1),
            ..default_cfg()
        },
        live_token_script(token_report(10, 10, 10)),
    );
    w.ad.set_inject_on_interrupt(Some(over_the_ceiling()));
    let res = std::thread::scope(|scope| {
        let h = scope.spawn(|| w.run());
        wait_for("the running harness", || {
            w.tr.count("store.AppendEvent:permission_requested") == 1
        });
        w.life.cancelling.store(true, Ordering::SeqCst);
        h.join().unwrap()
    });
    require_cancelled(&w, &res);
    let a = w.st.only();
    let EventPayload::UsageReport(r) = over_the_ceiling() else {
        unreachable!()
    };
    assert!(
        a.state == domain::State::Interrupted
            && a.terminal.reason != FailureCode::BUDGET_TOKENS.as_str()
            && a.usage == r.usage,
        "attempt = {}/{} usage {:?}, want the cancel's interrupted terminal",
        a.state.as_str(),
        a.terminal.reason,
        a.usage
    );
    let (interrupts, kills) = w.ad.session_counts(0).unwrap_or_default();
    assert!(
        interrupts == 1 && kills == 0,
        "interrupts={interrupts} kills={kills}"
    );
}

// ===== capture_test.rs =====

use super::ports::HarnessResult;

/// `requireEachRoleStoredAtMostOnce` — no Artifact is materialized twice
/// in-process (review T-I1).
fn require_each_role_stored_at_most_once(w: &World) {
    for (role, name) in [
        (ArtifactRole::Patch, "harness.patch"),
        (ArtifactRole::Commits, "harness.commits"),
    ] {
        let n = w.tr.count(&format!("artifacts.Store:{name}"));
        assert!(n <= 1, "{role:?} stored {n} times");
    }
    let n = w.tr.count("lifecycle.CompleteWithReport");
    assert!(n <= 1, "report completed {n} times");
}

/// `requireFailedWith` — a Run failed for an Artifact reason: the receipt
/// and Settle carry it, the harness row keeps its succeeded terminal, and
/// the capture files are released.
fn require_failed_with(w: &World, res: &HarnessResult, reason: FailureCode) {
    assert!(
        res.outcome == Outcome::Failed && res.reason == reason && !res.settle_failed,
        "result = {res:?} ({:?})",
        w.tr.all()
    );
    let (completion, settled, _) = w.life.snapshot();
    let want = vec![Settlement {
        succeeded: false,
        reason: reason.clone(),
    }];
    assert!(
        completion == want && settled == want,
        "completion={completion:?} settled={settled:?}"
    );
    let a = w.st.only();
    assert_eq!(
        a.state,
        domain::State::Succeeded,
        "harness row keeps its succeeded terminal"
    );
    let m = w.sink.of(MilestoneKind::Terminal);
    assert!(
        m.len() == 1
            && m[0].status == domain::State::Succeeded.as_str()
            && m[0].reason == reason.as_str(),
        "terminal milestones = {m:?}"
    );
    assert_eq!(
        w.tr.count("lifecycle.Reconcile"),
        0,
        "a certain failure was reconciled"
    );
    if w.tr.count("capture.Capture") > 0 {
        assert_eq!(w.cap.released.load(Ordering::SeqCst), 1, "capture released");
    }
    require_each_role_stored_at_most_once(w);
}

#[test]
fn orchestrator_succeeds_only_through_the_report_commit() {
    let w = new_world(
        default_cfg(),
        Capabilities::default(),
        vec![succeeded_script(Vec::new())],
    );
    let res = w.run();
    assert!(
        res.outcome == Outcome::Succeeded && res.err.is_none(),
        "result = {res:?}"
    );
    for never in [
        "lifecycle.RecordCompletion",
        "lifecycle.Settle",
        "lifecycle.Reconcile",
    ] {
        assert_eq!(w.tr.count(never), 0, "{never} on the success path");
    }
    let patch = w.tr.index("artifacts.Store:harness.patch");
    let commits = w.tr.index("artifacts.Store:harness.commits");
    let report = w.tr.index("lifecycle.CompleteWithReport");
    assert!(
        w.tr.index("store.AppendEvent:terminal_reported") < w.tr.index("capture.Capture")
            && w.tr.index("capture.Capture") < patch
            && patch < commits
            && commits < report
            && report < w.tr.index("capture.Release"),
        "order: {:?}",
        w.tr.all()
    );
    require_each_role_stored_at_most_once(&w);
    let m = w.sink.of(MilestoneKind::ArtifactsCaptured);
    assert!(
        m.len() == 1 && m[0].status == domain::State::Succeeded.as_str(),
        "artifacts milestones = {m:?}"
    );
}

#[test]
fn orchestrator_maps_each_artifact_failure_to_its_reason() {
    let rejected = ArtifactOutcome {
        kind: ArtifactOutcomeKind::Terminal,
        reason: FailureCode::ARTIFACT_REJECTED,
    };
    for tc in [
        // (name, setup, reason, stored_roles, report_called)
        (
            "capture failed",
            0,
            FailureCode::ARTIFACT_CAPTURE_FAILED,
            vec![],
            false,
        ),
        (
            "capture over its cap",
            1,
            FailureCode::ARTIFACT_TOO_LARGE,
            vec![],
            false,
        ),
        (
            "an unclassified capture error",
            2,
            FailureCode::ARTIFACT_CAPTURE_FAILED,
            vec![],
            false,
        ),
        (
            "patch rejected",
            3,
            FailureCode::ARTIFACT_REJECTED,
            vec!["harness.patch"],
            false,
        ),
        (
            "commits over quota",
            4,
            FailureCode::ARTIFACT_QUOTA_EXCEEDED,
            vec!["harness.patch", "harness.commits"],
            false,
        ),
        (
            "a terminal outcome without a reason",
            5,
            FailureCode::ARTIFACT_CAPTURE_FAILED,
            vec!["harness.patch"],
            false,
        ),
        (
            "report rejected",
            6,
            FailureCode::ARTIFACT_REJECTED,
            vec!["harness.patch", "harness.commits"],
            true,
        ),
        (
            "report over the limit at the Artifact",
            7,
            FailureCode::ARTIFACT_TOO_LARGE,
            vec!["harness.patch", "harness.commits"],
            true,
        ),
    ] {
        let (name, setup, reason, stored_roles, report_called) = tc;
        let w = new_world(
            default_cfg(),
            Capabilities::default(),
            vec![succeeded_script(Vec::new())],
        );
        match setup {
            0 => w.cap.set_err(Some(Failure::internal(
                codes::CAPTURE_FAILED,
                "git exited 128",
            ))),
            1 => w
                .cap
                .set_err(Some(Failure::internal(codes::CAPTURE_TOO_LARGE, "patch"))),
            2 => w
                .cap
                .set_err(Some(Failure::internal("cap", "disk on fire"))),
            3 => w.arts.set_outcome(ArtifactRole::Patch, rejected.clone()),
            4 => w.arts.set_outcome(
                ArtifactRole::Commits,
                ArtifactOutcome {
                    kind: ArtifactOutcomeKind::Retryable,
                    reason: FailureCode::ARTIFACT_QUOTA_EXCEEDED,
                },
            ),
            5 => w.arts.set_outcome(
                ArtifactRole::Patch,
                ArtifactOutcome {
                    kind: ArtifactOutcomeKind::Terminal,
                    ..ArtifactOutcome::default()
                },
            ),
            6 => w.life.set_report(Some(rejected.clone()), None),
            _ => w.life.set_report(
                Some(ArtifactOutcome {
                    kind: ArtifactOutcomeKind::Terminal,
                    reason: FailureCode::ARTIFACT_TOO_LARGE,
                }),
                None,
            ),
        }
        let res = w.run();
        require_failed_with(&w, &res, reason);
        for (role, name) in [
            (ArtifactRole::Patch, "harness.patch"),
            (ArtifactRole::Commits, "harness.commits"),
        ] {
            let want = if stored_roles.contains(&name) { 1 } else { 0 };
            assert_eq!(
                w.tr.count(&format!("artifacts.Store:{name}")),
                want,
                "{name}: {role:?} stored wrong ({name}) — {:?}",
                w.tr.all()
            );
        }
        assert_eq!(
            w.tr.count("lifecycle.CompleteWithReport") == 1,
            report_called,
            "{name}: report completion"
        );
        let (i, j) = (
            w.tr.index("lifecycle.RecordCompletion"),
            w.tr.index("lifecycle.Settle"),
        );
        assert!(i >= 0 && i <= j, "{name}: receipt at {i}, Settle at {j}");
    }
}

#[test]
fn orchestrator_fails_a_missing_or_oversized_report() {
    for (last, replaces, reason) in [
        (
            EventPayload::Message(event::Message {
                role: MessageRole::User,
                text: "just a user turn".to_string(),
                partial: false,
            }),
            true,
            FailureCode::HARNESS_REPORT_MISSING,
        ),
        (
            EventPayload::Message(event::Message {
                role: MessageRole::Assistant,
                text: " \n\t".to_string(),
                partial: false,
            }),
            true,
            FailureCode::HARNESS_REPORT_MISSING,
        ),
        (
            EventPayload::Message(event::Message {
                role: MessageRole::Assistant,
                text: "still typing".to_string(),
                partial: true,
            }),
            false,
            FailureCode::default(),
        ),
        (
            EventPayload::Message(event::Message {
                role: MessageRole::Assistant,
                text: "x".repeat(super::ports::MAX_REPORT_BYTES + 1),
                partial: false,
            }),
            true,
            FailureCode::ARTIFACT_TOO_LARGE,
        ),
    ] {
        let mut script = succeeded_script(Vec::new());
        if replaces {
            *script.payloads.last_mut().unwrap() = last;
        } else {
            script.payloads.push(last);
        }
        let w = new_world(default_cfg(), Capabilities::default(), vec![script]);
        let res = w.run();
        if reason.as_str().is_empty() {
            // A partial message never replaces the last complete one.
            assert!(
                res.outcome == Outcome::Succeeded && w.life.reported() == vec![FINAL_REPORT],
                "result = {res:?}, reports = {:?}",
                w.life.reported()
            );
            continue;
        }
        require_failed_with(&w, &res, reason);
        assert_eq!(
            w.tr.count("lifecycle.CompleteWithReport"),
            0,
            "a missing or oversized report reached the Artifact"
        );
        assert!(
            w.tr.count("artifacts.Store:harness.patch") == 1
                && w.tr.count("artifacts.Store:harness.commits") == 1,
            "supporting artifacts: {:?}",
            w.tr.all()
        );
    }
}

#[test]
fn orchestrator_reconciles_an_ambiguous_artifact_outcome() {
    // Upstream's "report outcome missing" (a bogus Go kind) is
    // unrepresentable in Rust: the vocab enum has only valid kinds.
    for (name, setup) in [
        ("report reconciliation", 0),
        ("report commit error", 1),
        ("patch store error", 2),
        ("commits reconciliation", 3),
    ] {
        let w = new_world(
            default_cfg(),
            Capabilities::default(),
            vec![succeeded_script(Vec::new())],
        );
        match setup {
            0 => w.life.set_report(
                Some(ArtifactOutcome {
                    kind: ArtifactOutcomeKind::Reconciliation,
                    ..ArtifactOutcome::default()
                }),
                None,
            ),
            1 => w.life.set_report(
                None,
                Some(Failure::internal("report", "connection reset at COMMIT")),
            ),
            2 => w.arts.set_err(
                ArtifactRole::Patch,
                Failure::internal("arts", "unclassified"),
            ),
            _ => w.arts.set_outcome(
                ArtifactRole::Commits,
                ArtifactOutcome {
                    kind: ArtifactOutcomeKind::Reconciliation,
                    ..ArtifactOutcome::default()
                },
            ),
        }
        let res = w.run();
        assert!(
            res.outcome == Outcome::Reconciliation && !res.settle_failed && res.err.is_some(),
            "{name}: result = {res:?}"
        );
        assert_eq!(
            w.life.reconciled.load(Ordering::SeqCst),
            1,
            "{name}: Reconcile calls"
        );
        for never in [
            "lifecycle.RecordCompletion",
            "lifecycle.Settle",
            "lifecycle.SettleCancellation",
        ] {
            assert_eq!(
                w.tr.count(never),
                0,
                "{name}: {never} after an ambiguous outcome"
            );
        }
        let m = w.sink.of(MilestoneKind::Terminal);
        assert!(
            m.len() == 1 && m[0].reason == super::ports::MILESTONE_REASON_RECONCILIATION,
            "{name}: terminal milestones = {m:?}"
        );
        assert_eq!(
            w.cap.released.load(Ordering::SeqCst),
            1,
            "{name}: capture files not released"
        );
        require_each_role_stored_at_most_once(&w);
    }
}

#[test]
fn orchestrator_reports_a_failed_reconcile() {
    let w = new_world(
        default_cfg(),
        Capabilities::default(),
        vec![succeeded_script(Vec::new())],
    );
    w.life.set_report(
        Some(ArtifactOutcome {
            kind: ArtifactOutcomeKind::Reconciliation,
            ..ArtifactOutcome::default()
        }),
        None,
    );
    w.life
        .set_reconcile_err(Some(Failure::invalid("permanent", "reconcile refused")));
    let res = w.run();
    assert!(
        res.outcome == Outcome::Reconciliation && res.settle_failed,
        "result = {res:?}"
    );
    let m = w.sink.of(MilestoneKind::SettleFailed);
    assert!(
        m.len() == 1 && m[0].reason == super::ports::MILESTONE_REASON_RECONCILIATION,
        "settle-failed milestones = {m:?}"
    );
}

#[test]
fn orchestrator_loses_the_run_when_the_report_commit_is_fenced_out() {
    let w = new_world(
        default_cfg(),
        Capabilities::default(),
        vec![succeeded_script(Vec::new())],
    );
    w.life.set_report(
        None,
        Some(Failure::internal(codes::LEASE_LOST, "STALE_LEASE_FENCE")),
    );
    let res = w.run();
    assert!(
        res.outcome == Outcome::Lost && is_code(res.err.as_ref(), codes::LEASE_LOST),
        "result = {res:?}"
    );
    for never in [
        "lifecycle.Reconcile",
        "lifecycle.RecordCompletion",
        "lifecycle.Settle",
    ] {
        assert_eq!(w.tr.count(never), 0, "{never} after a lost lease");
    }
}

#[test]
fn orchestrator_captures_a_failed_run_best_effort_and_keeps_its_reason() {
    for (name, setup, partial, stored) in [
        ("all stored", 0, FailureCode::default(), 2),
        ("capture failed", 1, FailureCode::ARTIFACT_CAPTURE_FAILED, 0),
        ("patch rejected", 2, FailureCode::ARTIFACT_REJECTED, 2),
        (
            "commits ambiguous",
            3,
            FailureCode::ARTIFACT_CAPTURE_FAILED,
            2,
        ),
    ] {
        let w = new_world(
            default_cfg(),
            Capabilities::default(),
            vec![failed_script("harness_api_error")],
        );
        match setup {
            1 => w
                .cap
                .set_err(Some(Failure::internal(codes::CAPTURE_FAILED, "sealing"))),
            2 => w.arts.set_outcome(
                ArtifactRole::Patch,
                ArtifactOutcome {
                    kind: ArtifactOutcomeKind::Terminal,
                    reason: FailureCode::ARTIFACT_REJECTED,
                },
            ),
            3 => w.arts.set_err(
                ArtifactRole::Commits,
                Failure::internal("arts", "unclassified"),
            ),
            _ => {}
        }
        let res = w.run();
        assert!(
            res.outcome == Outcome::Failed
                && res.reason.as_str() == "harness_api_error"
                && !res.settle_failed,
            "{name}: result = {res:?}"
        );
        let (completion, settled, _) = w.life.snapshot();
        let want = vec![Settlement {
            succeeded: false,
            reason: FailureCode::new("harness_api_error"),
        }];
        assert!(
            completion == want && settled == want,
            "{name}: completion={completion:?} settled={settled:?}"
        );
        assert_eq!(
            w.tr.count("artifacts.Store:"),
            stored,
            "{name}: stores — {:?}",
            w.tr.all()
        );
        assert_eq!(
            w.tr.count("lifecycle.CompleteWithReport") + w.tr.count("lifecycle.Reconcile"),
            0,
            "{name}: a failed run materialized a report or reconciled"
        );
        assert!(
            w.tr.index("capture.Capture") <= w.tr.index("lifecycle.RecordCompletion"),
            "{name}: captured after the receipt: {:?}",
            w.tr.all()
        );
        let (partial_m, captured_m) = (
            w.sink.of(MilestoneKind::ArtifactsPartial),
            w.sink.of(MilestoneKind::ArtifactsCaptured),
        );
        if partial.as_str().is_empty() {
            assert!(
                partial_m.is_empty() && captured_m.len() == 1,
                "{name}: artifact milestones partial={partial_m:?} captured={captured_m:?}"
            );
        } else {
            assert!(
                partial_m.len() == 1
                    && partial_m[0].reason == partial.as_str()
                    && captured_m.is_empty(),
                "{name}: artifact milestones partial={partial_m:?} captured={captured_m:?}"
            );
        }
        let m = w.sink.of(MilestoneKind::Terminal);
        assert!(
            m.len() == 1 && m[0].reason == "harness_api_error",
            "{name}: terminal milestones = {m:?}"
        );
        assert_eq!(
            w.cap.released.load(Ordering::SeqCst),
            1,
            "{name}: capture files not released"
        );
        require_each_role_stored_at_most_once(&w);
    }
}

#[test]
fn orchestrator_captures_nothing_for_a_cancelled_or_unlaunched_run() {
    // cancelled while running
    {
        let w = new_world(
            OrchestratorConfig {
                heartbeat_interval: Duration::milliseconds(10),
                interrupt_grace: Duration::minutes(1),
                ..default_cfg()
            },
            Capabilities {
                interrupt: true,
                ..Capabilities::default()
            },
            vec![blocking_script()],
        );
        let res = std::thread::scope(|scope| {
            let h = scope.spawn(|| w.run());
            wait_for("the running harness", || {
                w.tr.count("store.AppendEvent:permission_requested") == 1
            });
            w.life.cancelling.store(true, Ordering::SeqCst);
            h.join().unwrap()
        });
        require_cancelled(&w, &res);
        assert_eq!(
            w.tr.count("capture.") + w.tr.count("artifacts.Store"),
            0,
            "a cancelled run captured: {:?}",
            w.tr.all()
        );
    }
    // launch failed
    {
        let s = Script {
            start_err: Some(Failure::internal("launcher", "launcher refused")),
            ..Script::default()
        };
        let w = new_world(default_cfg(), Capabilities::default(), vec![s]);
        let res = w.run();
        assert!(
            res.outcome == Outcome::Failed && res.reason == FailureCode::LAUNCH_FAILED,
            "result = {res:?}"
        );
        assert_eq!(
            w.tr.count("capture.") + w.tr.count("artifacts.Store"),
            0,
            "an unlaunched run captured: {:?}",
            w.tr.all()
        );
    }
}

#[test]
fn orchestrator_settles_a_cancel_seen_during_capture() {
    for name in [
        "during capture",
        "seen by the heartbeat while storing the patch",
        "refused at the report",
    ] {
        let w = new_world(
            OrchestratorConfig {
                heartbeat_interval: Duration::milliseconds(5),
                ..default_cfg()
            },
            Capabilities::default(),
            vec![succeeded_script(Vec::new())],
        );
        match name {
            "during capture" => {
                let life = w.life.clone();
                w.cap.set_on_call(move || {
                    life.cancelling.store(true, Ordering::SeqCst);
                });
            }
            "seen by the heartbeat while storing the patch" => {
                // Go's heartbeat goroutine sees the cancellation while the
                // store runs; in Rust the single in-place future means the
                // heartbeat catches it on the pipeline's next await.
                let life = w.life.clone();
                w.arts.set_on_store(move |role| {
                    if role == ArtifactRole::Patch {
                        life.cancelling.store(true, Ordering::SeqCst);
                        std::thread::sleep(std::time::Duration::from_millis(30));
                    }
                });
            }
            _ => w.life.cancel_at_report.store(true, Ordering::SeqCst),
        }
        let res = std::thread::scope(|scope| {
            let h = scope.spawn(|| w.run());
            match h.join() {
                Ok(r) => r,
                Err(e) => std::panic::resume_unwind(e),
            }
        });
        require_cancelled(&w, &res);
        assert_eq!(
            w.tr.count("lifecycle.Reconcile"),
            0,
            "{name}: a cancellation was reconciled"
        );
        assert_eq!(
            w.st.only().state,
            domain::State::Succeeded,
            "{name}: attempt state"
        );
        require_each_role_stored_at_most_once(&w);
    }
}

#[test]
fn orchestrator_stop_during_capture_writes_nothing() {
    let w = new_world(
        default_cfg(),
        Capabilities::default(),
        vec![succeeded_script(Vec::new())],
    );
    w.cap.set_block(true);
    let res = std::thread::scope(|scope| {
        let h = scope.spawn(|| w.run());
        wait_for("capture to start", || w.tr.count("capture.Capture") == 1);
        w.stop.cancel();
        h.join().unwrap()
    });
    assert_eq!(res.outcome, Outcome::Stopped, "result = {res:?}");
    for never in [
        "artifacts.Store",
        "lifecycle.CompleteWithReport",
        "lifecycle.RecordCompletion",
        "lifecycle.Settle",
        "lifecycle.Reconcile",
    ] {
        assert_eq!(w.tr.count(never), 0, "{never} after a stop during capture");
    }
    assert_eq!(
        w.cap.released.load(Ordering::SeqCst),
        1,
        "capture files of a stopped run not released"
    );
}

/// `TestOrchestratorCapturesOnlyAfterAConfirmedExit` — the capture gate:
/// a session whose Wait returns no exit code may leave harness processes
/// behind, so its clone is never captured.
#[test]
fn orchestrator_captures_only_after_a_confirmed_exit() {
    let mut succeeded = succeeded_script(Vec::new());
    succeeded.no_exit_status = true;
    let w = new_world(default_cfg(), Capabilities::default(), vec![succeeded]);
    let res = w.run();
    require_failed_with(&w, &res, FailureCode::ARTIFACT_CAPTURE_FAILED);
    assert_eq!(
        w.tr.count("capture.")
            + w.tr.count("artifacts.Store")
            + w.tr.count("lifecycle.CompleteWithReport"),
        0,
        "captured without a confirmed exit: {:?}",
        w.tr.all()
    );

    let mut failed = failed_script("harness_api_error");
    failed.no_exit_status = true;
    let w = new_world(default_cfg(), Capabilities::default(), vec![failed]);
    let res = w.run();
    assert!(
        res.outcome == Outcome::Failed && res.reason.as_str() == "harness_api_error",
        "result = {res:?}"
    );
    assert_eq!(
        w.tr.count("capture.") + w.tr.count("artifacts.Store"),
        0,
        "captured without a confirmed exit: {:?}",
        w.tr.all()
    );
    assert!(
        w.sink.of(MilestoneKind::ArtifactsPartial).is_empty(),
        "artifacts_partial for a capture that never ran"
    );
    assert!(
        w.sink.of(MilestoneKind::ArtifactsCaptured).is_empty(),
        "artifacts_captured for a capture that never ran"
    );
}

// ===== result_report_test.rs =====

/// `TestTheReportIsTheResultFramesTextAfterASubagentsMessage` — the last
/// complete assistant message is the report, so a subagent's earlier text
/// never becomes it.
#[test]
fn the_report_is_the_result_frames_text_after_a_subagents_message() {
    let mut script = succeeded_script(Vec::new());
    script.payloads = vec![
        EventPayload::SessionStarted(event::SessionStarted {
            harness_session_id: "session-1".to_string(),
            harness_version: "2.1.283".to_string(),
            ..event::SessionStarted::default()
        }),
        EventPayload::Message(event::Message {
            role: MessageRole::Assistant,
            text: "Let me delegate this.".to_string(),
            partial: false,
        }),
        EventPayload::ToolCall(event::ToolCall {
            id: "toolu_task".to_string(),
            name: "Task".to_string(),
            input: br#"{"prompt":"look around"}"#.to_vec(),
            ..event::ToolCall::default()
        }),
        EventPayload::Message(event::Message {
            role: MessageRole::Assistant,
            text: "SUBAGENT".to_string(),
            partial: false,
        }),
        EventPayload::ToolResult(event::ToolResult {
            id: "toolu_task".to_string(),
            status: ToolStatus::Ok,
            ..event::ToolResult::default()
        }),
        EventPayload::UsageReport(event::UsageReport {
            usage: Usage {
                tokens_in: 10,
                tokens_out: 20,
                cost_micro_usd: 1000,
                scope: UsageScope::SessionCumulative,
                estimated: true,
                ..Usage::default()
            },
        }),
        EventPayload::Message(event::Message {
            role: MessageRole::Assistant,
            text: FINAL_REPORT.to_string(),
            partial: false,
        }),
    ];
    let w = new_world(default_cfg(), Capabilities::default(), vec![script]);
    let res = w.run();
    assert!(
        res.outcome == Outcome::Succeeded,
        "result = {res:?} ({:?})",
        w.tr.all()
    );
    assert_eq!(
        w.life.reported(),
        vec![FINAL_REPORT],
        "want the result frame's text"
    );
}

// ===== polish_test.rs =====

/// `TestTheWallClockDuringACancelLeavesTheCancelsTerminal` — decision 9:
/// once a cancel is under way the wall clock no longer stops the session
/// for its budget (the mirror of
/// `a_usage_report_during_a_cancel_leaves_the_cancels_terminal`).
#[test]
fn the_wall_clock_during_a_cancel_leaves_the_cancels_terminal() {
    let w = new_world(
        OrchestratorConfig {
            heartbeat_interval: Duration::milliseconds(10),
            interrupt_grace: Duration::milliseconds(1200),
            ..default_cfg()
        },
        Capabilities {
            interrupt: true,
            ..Capabilities::default()
        },
        vec![blocking_script()],
    );
    w.ad.set_swallow_interrupt(true); // only the kill after the grace ends it
    w.life.set_budget(Budget {
        cost_micro_usd: 500_000,
        wall_clock: Duration::milliseconds(400),
        ..Budget::default()
    });
    let res = std::thread::scope(|scope| {
        let h = scope.spawn(|| w.run());
        wait_for("the running harness", || {
            w.tr.count("store.AppendEvent:permission_requested") == 1
        });
        w.life.cancelling.store(true, Ordering::SeqCst);
        wait_for("the cancel's interrupt", || {
            w.ad.session_counts(0).map(|(i, _)| i == 1).unwrap_or(false)
        });
        h.join().unwrap() // the wall clock fired while the grace ran
    });
    require_cancelled(&w, &res);
    let a = w.st.only();
    assert!(
        a.state == domain::State::Killed
            && a.terminal.reason != FailureCode::BUDGET_WALL_CLOCK.as_str(),
        "attempt = {}/{}, want the cancel's killed terminal",
        a.state.as_str(),
        a.terminal.reason
    );
    let (interrupts, kills) = w.ad.session_counts(0).unwrap_or_default();
    assert!(
        interrupts == 1 && kills == 1,
        "interrupts={interrupts} kills={kills}"
    );
}

/// `TestTheReconcileMilestoneRecordsTheIntendedTerminal` — decision 10.
#[test]
fn the_reconcile_milestone_records_the_intended_terminal() {
    let w = new_world(
        default_cfg(),
        Capabilities::default(),
        vec![succeeded_script(Vec::new())],
    );
    w.ad.set_drop_terminal(true);
    w.st.set_save_err(|next| {
        if next.state.is_terminal() {
            Some(Failure::internal("store", "disk full"))
        } else {
            None
        }
    });
    w.life.set_report(
        Some(ArtifactOutcome {
            kind: ArtifactOutcomeKind::Reconciliation,
            ..ArtifactOutcome::default()
        }),
        None,
    );
    let res = w.run();
    assert_eq!(
        res.outcome,
        Outcome::Reconciliation,
        "result = {res:?} ({:?})",
        w.tr.all()
    );
    assert!(
        !w.st.only().state.is_terminal(),
        "the terminal was written after all"
    );
    let m = w.sink.of(MilestoneKind::Terminal);
    assert!(
        m.len() == 1
            && m[0].status == domain::State::Succeeded.as_str()
            && m[0].reason == super::ports::MILESTONE_REASON_RECONCILIATION,
        "terminal milestones = {m:?}, want succeeded/reconciliation"
    );
}

// ===== budget_internal_test.rs / bridge_internal_test.rs (pure parts) =====

/// `TestBilledTokensCountsInOutAndCacheWrite` — 3l decision 1: cache
/// reads are not billed tokens, and the sum saturates.
#[test]
fn billed_tokens_counts_in_out_and_cache_write() {
    for (usage, want) in [
        (Usage::default(), 0),
        (
            Usage {
                tokens_in: 10,
                tokens_out: 31,
                cache_read: 13689,
                cache_write: 34951,
                ..Usage::default()
            },
            34992,
        ),
        (
            Usage {
                cache_read: i64::MAX,
                ..Usage::default()
            },
            0,
        ),
        (
            Usage {
                tokens_in: i64::MAX,
                tokens_out: 1,
                ..Usage::default()
            },
            i64::MAX,
        ),
        (
            Usage {
                tokens_in: i64::MAX - 5,
                tokens_out: 5,
                ..Usage::default()
            },
            i64::MAX,
        ),
        (
            Usage {
                tokens_out: i64::MAX / 2,
                cache_write: i64::MAX / 2,
                ..Usage::default()
            },
            i64::MAX - 1,
        ),
        (
            Usage {
                tokens_in: -3,
                tokens_out: 4,
                ..Usage::default()
            },
            4,
        ),
    ] {
        assert_eq!(billed_tokens(&usage), want, "billedTokens({usage:?})");
    }
}

/// `TestDecidedByCodesAreFixed` — a milestone reason is one of a fixed
/// set of codes, never text the harness reported.
#[test]
fn decided_by_codes_are_fixed() {
    for (decided_by, want) in [
        ("operator-session:alice", "operator"),
        (crate::approval::DECIDED_BY_TIMEOUT, "timeout"),
        (
            crate::approval::DECIDED_BY_INPUT_TOO_LARGE,
            "input_too_large",
        ),
        (super::bridge::DECIDED_BY_POLICY_DENY, "deny"),
        ("policy:\u{1b}[2Jrm -rf / free text", "policy"),
        ("policy:", "policy"),
        (crate::approval::DECIDED_BY_SUPERSEDED, "policy"),
        ("", "policy"),
        ("harness says: allowed by the user!", "policy"),
    ] {
        assert_eq!(
            decided_by_code(decided_by),
            want,
            "decidedByCode({decided_by:?})"
        );
    }
}

// ===========================================================================
// resume_test.go — the resuming-claim path (harness phase 3g decisions
// 4, 5, 7, 13): a claimed attempt that continues an earlier harness
// session resumes it in the Run's existing clone, and never calls
// Provision (which would delete the clone), including when it adopts
// the attempt's own prepared row after a restart.
// ===========================================================================

const RESUME_PROMPT: &str =
    "Continue the task from where the previous run stopped. When finished, give the final report.";
const RESUMED_SESSION: &str = "session-resumed";
const RESUME_COST_LIMIT: i64 = 3_000_000;

/// `resumedScript` — a succeeded session that reveals the resumed
/// session id.
fn resumed_script() -> Script {
    Script {
        session_id: RESUMED_SESSION.to_string(),
        payloads: vec![
            EventPayload::SessionStarted(event::SessionStarted {
                harness_session_id: RESUMED_SESSION.to_string(),
                harness_version: "2.1.283".to_string(),
                model: String::new(),
                tools: Vec::new(),
                reported_capabilities: Vec::new(),
            }),
            EventPayload::Message(event::Message {
                role: MessageRole::Assistant,
                text: FINAL_REPORT.to_string(),
                partial: false,
            }),
        ],
        terminal: Terminal {
            status: TerminalStatus::Succeeded,
            ..Terminal::default()
        },
        ..Script::default()
    }
}

fn resume_caps() -> Capabilities {
    Capabilities {
        resume_by_id: true,
        native_cost_limit: true,
        ..Capabilities::default()
    }
}

/// `resumeFixture` — a world whose next claim is the prepared resume
/// attempt of a Run whose earlier attempt, `source`, is
/// resolved(resume).
struct ResumeFixture {
    w: World,
    src: Arc<ScriptedResume>,
    run: DispatchableRun,
    source: Attempt,
    from: super::ports::ResumeFrom,
    /// The harness attempt id of the claimed StepAttempt.
    id: HarnessAttemptId,
}

fn resume_fixture(
    cfg: OrchestratorConfig,
    caps: Capabilities,
    scripts: Vec<Script>,
) -> ResumeFixture {
    let src = Arc::new(ScriptedResume::new(None, None));
    let mut cfg = cfg;
    cfg.resume = src.clone();
    let w = new_world(cfg, caps, scripts);
    let run = DispatchableRun {
        case: DispatchCase::PreparedSuccessor,
        workspace_id: central_foundation::identity::WorkspaceId::new(),
        task_id: TaskId::new(),
        run_id: central_foundation::identity::RunId::new(),
        step_id: StepId::new(),
        step_attempt_id: StepAttemptId::new(),
    };
    let id = crate::recovery::attempt_id_for_step_attempt(run.step_attempt_id).expect("attempt id");
    let f = Fence { generation: 1 };
    let at = w.clock.now() - Duration::HOUR;
    let mut source = Attempt::prepare(PrepareInput {
        id: HarnessAttemptId::new(),
        workspace_id: run.workspace_id,
        run_id: run.run_id,
        kind: Kind::new("claude-code"),
        adapter_version: "claudecode/3a".to_string(),
        workspace: Workspace {
            path: format!(
                "/var/lib/central-harness/worktrees/runs/{}/repo",
                run.run_id
            ),
            base_sha: BASE_SHA.to_string(),
        },
        permission: PermissionPolicy::Deny,
        fence: f,
        at,
        budget: Budget {
            cost_micro_usd: 5_000_000,
            wall_clock: Duration::minutes(30),
            cost_defaulted: false,
            wall_clock_defaulted: false,
        },
    })
    .expect("prepare");
    source = source
        .launch(f, &source.id.to_string(), "2.1.283", at + Duration::SECOND)
        .expect("launch");
    source = source
        .reveal_session(f, RESUMED_SESSION, at + Duration::seconds(2))
        .expect("reveal");
    source = source
        .mark_ambiguous(f, AMBIGUITY_RESTART, at + Duration::seconds(3))
        .expect("ambiguous");
    source = source
        .resolve(
            f,
            Resolution {
                kind: ResolutionKind::Resume,
                decided_by: DECIDED_BY_OPERATOR_RESUME.to_string(),
            },
            at + Duration::seconds(4),
        )
        .expect("resolve");
    w.st.store_attempt(source.clone());
    w.life.set_generation(1); // the claim takes generation 2
    let from = resume_from(
        source.clone(),
        RESUME_PROMPT,
        Budget {
            cost_micro_usd: RESUME_COST_LIMIT,
            wall_clock: Duration::minutes(30),
            cost_defaulted: false,
            wall_clock_defaulted: false,
        },
    );
    src.set_from(Some(from.clone()));
    ResumeFixture {
        w,
        src,
        run,
        source,
        from,
        id,
    }
}

impl ResumeFixture {
    fn run_once(&self) -> super::ports::HarnessResult {
        block_on(
            self.w
                .orch
                .run_dispatchable(self.run.clone(), "2.1.283", &*self.w.stop),
        )
    }

    /// `stored` — the harness row of the claimed attempt.
    fn stored(&self) -> Attempt {
        self.w.st.stored(self.id).unwrap_or_else(|| {
            unreachable!(
                "no harness row for the claimed attempt: {:?}",
                self.w.tr.all()
            )
        })
    }

    /// `preparedResumeRow` — the resume row an earlier claim (fence 1)
    /// created.
    fn prepared_resume_row(&self) -> Attempt {
        Attempt::prepare_resume(
            &self.source,
            PrepareInput {
                id: self.id,
                workspace_id: self.run.workspace_id,
                run_id: self.run.run_id,
                kind: Kind::new("claude-code"),
                adapter_version: "claudecode/3a".to_string(),
                workspace: self.source.workspace.clone(),
                permission: PermissionPolicy::Deny,
                fence: Fence { generation: 1 },
                at: self.w.clock.now() - Duration::minutes(1),
                budget: self.from.budget,
            },
        )
        .expect("PrepareResume")
    }
}

#[test]
fn orchestrator_resumes_the_source_session_without_provisioning() {
    let f = resume_fixture(default_cfg(), resume_caps(), vec![resumed_script()]);
    let res = f.run_once();
    assert!(
        res.outcome == Outcome::Succeeded && res.err.is_none(),
        "result = {res:?} ({:?})",
        f.w.tr.all()
    );
    assert_eq!(
        f.w.tr.count("provisioner.Provision"),
        0,
        "Provision calls on the resume path"
    );
    let reopens = f.w.prov.reopen_calls();
    assert!(
        reopens.len() == 1
            && reopens[0].want == f.source.workspace
            && reopens[0].run == f.run.run_id
            && reopens[0].ws == f.run.workspace_id,
        "reopens = {reopens:?}, want one of {:?}",
        f.source.workspace
    );
    let calls = f.src.calls();
    assert!(
        calls.len() == 1 && calls[0].step_attempt_id == f.run.step_attempt_id,
        "resume source calls = {calls:?}"
    );
    let a = f.stored();
    assert!(
        a.resume_of == Some(f.source.id)
            && a.resume_session_id == f.source.harness_session_id
            && a.budget == f.from.budget
            && a.workspace == f.source.workspace
            && a.state == State::Succeeded
            && a.harness_session_id == RESUMED_SESSION,
        "resume row = {a:?}"
    );
    let adapter_calls = f.w.ad.calls();
    assert_eq!(adapter_calls.len(), 1, "adapter calls = {adapter_calls:?}");
    let c = &adapter_calls[0];
    assert!(
        c.0 == "Resume" && c.2.harness_session_id == f.source.harness_session_id,
        "adapter call = {} {:?}",
        c.0,
        c.2
    );
    assert!(
        c.1.prompt == f.from.prompt && c.1.prompt != f.w.life.prompt(),
        "the resume was not launched with the continuation prompt"
    );
    assert!(
        c.1.limits.max_cost_micro_usd == RESUME_COST_LIMIT
            && c.1.workspace == f.source.workspace
            && c.1.attempt == f.id
            && c.1.env.sandbox_scope_id == f.id.to_string()
            && c.1.permission == PermissionPolicy::Deny,
        "resume spec = {:?}",
        c.1
    );
    let order = [
        "provisioner.CheckFreeSpace",
        "provisioner.Reopen",
        "store.Create",
        "lifecycle.MarkInvoked",
        "adapter.Resume",
        "lifecycle.CompleteWithReport",
    ];
    let mut last = -1;
    for call in order {
        let i = f.w.tr.index(call);
        assert!(
            i > last,
            "{call} at {i}, not after {last}: {:?}",
            f.w.tr.all()
        );
        last = i;
    }
    assert_eq!(
        f.w.tr.count("adapter.Start"),
        0,
        "a resume started a fresh session"
    );
}

#[test]
fn orchestrator_adopts_a_prepared_resume_row_after_a_restart() {
    let f = resume_fixture(default_cfg(), resume_caps(), vec![resumed_script()]);
    let prior = f.prepared_resume_row();
    f.w.st.store_attempt(prior.clone());
    let res = f.run_once();
    assert!(
        res.outcome == Outcome::Succeeded && res.err.is_none(),
        "result = {res:?} ({:?})",
        f.w.tr.all()
    );
    assert_eq!(
        f.w.tr.count("provisioner.Provision"),
        0,
        "Provision calls while adopting a resume row"
    );
    let a = f.stored();
    assert!(
        a.fence.generation == 2
            && a.prepared_at == prior.prepared_at
            && a.resume_of == Some(f.source.id)
            && a.state == State::Succeeded,
        "adopted row = {} fence {} prepared {} resume of {:?}",
        a.state.as_str(),
        a.fence.generation,
        a.prepared_at,
        a.resume_of
    );
    let order = [
        "provisioner.Reopen",
        "store.Create",
        "store.Save:prepared",
        "lifecycle.MarkInvoked",
        "adapter.Resume",
    ];
    let mut last = -1;
    for call in order {
        let i = f.w.tr.index(call);
        assert!(
            i > last,
            "{call} at {i}, not after {last}: {:?}",
            f.w.tr.all()
        );
        last = i;
    }
    let c = f.w.ad.calls();
    assert!(
        c.len() == 1 && c[0].0 == "Resume" && c[0].2.harness_session_id == RESUMED_SESSION,
        "adapter calls = {c:?}"
    );
}

#[test]
fn orchestrator_refuses_to_adopt_a_row_of_the_other_kind() {
    let f = resume_fixture(default_cfg(), resume_caps(), vec![resumed_script()]);
    let ordinary = Attempt::prepare(PrepareInput {
        id: f.id,
        workspace_id: f.run.workspace_id,
        run_id: f.run.run_id,
        kind: Kind::new("claude-code"),
        adapter_version: "claudecode/3a".to_string(),
        workspace: f.source.workspace.clone(),
        permission: PermissionPolicy::Deny,
        fence: Fence { generation: 1 },
        at: f.w.clock.now() - Duration::minutes(1),
        budget: f.from.budget,
    })
    .expect("prepare");
    f.w.st.store_attempt(ordinary.clone());
    let res = f.run_once();
    assert!(
        res.outcome == Outcome::Abandoned && res.reason == FailureCode::EXECUTION_FAILED,
        "result = {res:?}"
    );
    assert!(
        is_code(res.err.as_ref(), domain::codes::VERSION_CONFLICT),
        "cause = {:?}",
        res.err
    );
    assert!(
        f.w.ad.calls().is_empty()
            && f.w.tr.count("lifecycle.MarkInvoked") == 0
            && f.w.tr.count("provisioner.Provision") == 0,
        "launched or provisioned: {:?}",
        f.w.tr.all()
    );
    let a = f.stored();
    assert!(
        a.state == State::Prepared && a.fence.generation == 1,
        "the ordinary row was changed: {} fence {}",
        a.state.as_str(),
        a.fence.generation
    );
}

#[test]
fn orchestrator_abandons_a_resume_it_cannot_start() {
    struct Case {
        name: &'static str,
        caps: Capabilities,
        setup: Box<dyn Fn(&ResumeFixture)>,
        reason: FailureCode,
    }
    let cases = vec![
        Case {
            name: "clone unavailable",
            caps: resume_caps(),
            setup: Box::new(|f: &ResumeFixture| {
                f.w.prov.set_reopen_err(Some(Failure::unavailable(
                    codes::WORKSPACE_UNAVAILABLE,
                    "the run directory was replaced",
                )));
            }),
            reason: FailureCode::WORKSPACE_UNAVAILABLE,
        },
        Case {
            name: "no usable source",
            caps: resume_caps(),
            setup: Box::new(|f: &ResumeFixture| {
                f.src.set_err(Some(Failure::unavailable(
                    codes::RESUME_UNAVAILABLE,
                    "no usable source",
                )));
            }),
            reason: FailureCode::EXECUTION_FAILED,
        },
        Case {
            name: "chain budget exhausted",
            caps: resume_caps(),
            setup: Box::new(|f: &ResumeFixture| {
                f.src.set_err(Some(Failure::conflict(
                    domain::codes::CHAIN_BUDGET_EXHAUSTED,
                    "9999 micro-USD remaining",
                )));
            }),
            reason: FailureCode::BUDGET_COST,
        },
        Case {
            name: "adapter cannot resume",
            caps: Capabilities {
                native_cost_limit: true,
                ..Capabilities::default()
            },
            setup: Box::new(|_: &ResumeFixture| {}),
            reason: FailureCode::EXECUTION_FAILED,
        },
        Case {
            name: "empty prompt",
            caps: resume_caps(),
            setup: Box::new(|f: &ResumeFixture| {
                let mut from = f.from.clone();
                from.prompt = String::new();
                f.src.set_from(Some(from));
            }),
            reason: FailureCode::EXECUTION_FAILED,
        },
    ];
    for tc in cases {
        let f = resume_fixture(default_cfg(), tc.caps, vec![resumed_script()]);
        (tc.setup)(&f);
        let res = f.run_once();
        assert!(
            res.outcome == Outcome::Abandoned && res.reason == tc.reason,
            "{}: result = {res:?}",
            tc.name
        );
        let (_, settled, abandoned) = f.w.life.snapshot();
        assert!(
            abandoned == vec![tc.reason.clone()] && settled.is_empty(),
            "{}: abandoned={abandoned:?} settled={settled:?}",
            tc.name
        );
        assert_eq!(
            f.w.tr.count("provisioner.Provision"),
            0,
            "{}: Provision calls",
            tc.name
        );
        assert!(
            f.w.ad.calls().is_empty(),
            "{}: adapter calls = {:?}",
            tc.name,
            f.w.ad.calls()
        );
        assert!(
            f.w.tr.count("store.Create") == 0 && f.w.tr.count("lifecycle.MarkInvoked") == 0,
            "{}: a resume that cannot start went on: {:?}",
            tc.name,
            f.w.tr.all()
        );
        let m = f.w.sink.of(MilestoneKind::Terminal);
        assert!(
            m.len() == 1 && m[0].reason == tc.reason.as_str(),
            "{}: terminal milestone = {m:?}",
            tc.name
        );
    }
}

#[test]
fn orchestrator_cancel_before_a_resume_launch_settles_the_cancellation() {
    let mut cfg = default_cfg();
    cfg.heartbeat_interval = Duration::milliseconds(10);
    let f = resume_fixture(cfg, resume_caps(), vec![resumed_script()]);
    let life = f.w.life.clone();
    f.src.set_block(move || {
        life.cancelling.store(true, Ordering::SeqCst);
    });
    // The heartbeat sees the cancel and ends the pre-launch work; the
    // pending resume call is dropped by the work race.
    let res = f.run_once();
    require_cancelled(&f.w, &res);
    for call in [
        "provisioner.Provision",
        "provisioner.Reopen",
        "store.Create",
        "lifecycle.MarkInvoked",
        "adapter.",
    ] {
        assert_eq!(
            f.w.tr.count(call),
            0,
            "{call} after the cancellation: {:?}",
            f.w.tr.all()
        );
    }
    assert!(f.w.ad.calls().is_empty(), "a cancelled resume was launched");
}

#[test]
fn orchestrator_provisions_when_there_is_no_resume_source() {
    // no source
    {
        let f = resume_fixture(
            default_cfg(),
            resume_caps(),
            vec![succeeded_script(Vec::new())],
        );
        f.src.set_from(None);
        let res = f.run_once();
        assert!(
            res.outcome == Outcome::Succeeded && res.err.is_none(),
            "result = {res:?} ({:?})",
            f.w.tr.all()
        );
        assert_eq!(f.w.tr.count("provisioner.Provision"), 1, "Provision calls");
        assert_eq!(
            f.w.prov.reopen_calls().len(),
            0,
            "Reopen calls on the ordinary path"
        );
        let c = f.w.ad.calls();
        assert!(
            c.len() == 1 && c[0].0 == "Start" && c[0].1.prompt == f.w.life.prompt(),
            "adapter calls = {c:?}"
        );
        let a = f.stored();
        assert!(
            a.resume_of.is_none() && a.resume_session_id.is_empty(),
            "ordinary row = {a:?}"
        );
        assert!(
            f.w.tr.index("provisioner.CheckFreeSpace") < f.w.tr.index("provisioner.Provision"),
            "order: {:?}",
            f.w.tr.all()
        );
    }
    // source unavailable
    {
        let f = resume_fixture(
            default_cfg(),
            resume_caps(),
            vec![succeeded_script(Vec::new())],
        );
        f.src.set_err(Some(Failure::unavailable(
            codes::RESUME_UNAVAILABLE,
            "step sequence 2 has no source",
        )));
        let res = f.run_once();
        assert!(
            res.outcome == Outcome::Abandoned
                && res.reason == FailureCode::EXECUTION_FAILED
                && is_code(res.err.as_ref(), codes::RESUME_UNAVAILABLE),
            "result = {res:?}"
        );
        assert_eq!(f.w.tr.count("provisioner.Provision"), 0, "Provision calls");
        assert!(f.w.ad.calls().is_empty(), "launched without a source");
    }
}

#[test]
fn new_orchestrator_requires_a_resume_source() {
    // `OrchestratorConfig::new` fills the `noResume` default; a config
    // whose resume source is absent is unrepresentable in Rust — the
    // field is non-optional. The meaningful half is that the default
    // source answers `None` (the `noResume` port).
    let src = Arc::new(NoResume);
    let res = block_on(super::ports::ResumeSource::resume_from(
        src.as_ref(),
        super::ports::ClaimedRun {
            workspace_id: central_foundation::identity::WorkspaceId::new(),
            task_id: TaskId::new(),
            run_id: central_foundation::identity::RunId::new(),
            step_id: StepId::new(),
            step_attempt_id: StepAttemptId::new(),
            prompt: "p".to_string(),
            permission: PermissionPolicy::Deny,
            budget: Budget::default(),
            lease: crate::port::ExecutionLease {
                generation: 1,
                credential: [7; 32],
            },
        },
    ));
    assert!(matches!(res, Ok(None)), "noResume = {res:?}");
}

// ===========================================================================
// reconciler_test.go — the startup reconciler and the Resolver (harness
// phase 3e/3g/3k): every non-terminal harness row takes the state its
// linked StepAttempt implies, under the recovery authority.
// ===========================================================================

/// `resolvedAs` — the stored row a concurrent writer would leave.
fn resolved_as(a: &Attempt, res: Resolution) -> Attempt {
    let mut next = a
        .resolve(a.fence, res, a.updated_at + Duration::SECOND)
        .expect("resolve");
    next.version = a.version + 1;
    next
}

#[test]
fn reconciler_gives_each_attempt_the_state_its_step_attempt_implies() {
    struct Case {
        name: &'static str,
        state: State,
        step: LinkedStepAttemptState,
        lease_live: bool,
        want: Option<State>,
        reason: &'static str,
    }
    let cases = vec![
        Case {
            name: "launched then restart",
            state: State::Running,
            step: LinkedStepAttemptState::Reconciliation,
            lease_live: false,
            want: Some(State::Ambiguous),
            reason: "",
        },
        Case {
            name: "launching then restart",
            state: State::Launching,
            step: LinkedStepAttemptState::Reconciliation,
            lease_live: false,
            want: Some(State::Ambiguous),
            reason: "",
        },
        Case {
            name: "awaiting permission then restart",
            state: State::AwaitingPermission,
            step: LinkedStepAttemptState::Reconciliation,
            lease_live: false,
            want: Some(State::Ambiguous),
            reason: "",
        },
        Case {
            name: "invoked but never launched",
            state: State::Prepared,
            step: LinkedStepAttemptState::Reconciliation,
            lease_live: false,
            want: Some(State::Ambiguous),
            reason: "",
        },
        Case {
            name: "stop before MarkInvoked",
            state: State::Prepared,
            step: LinkedStepAttemptState::Cancelled,
            lease_live: false,
            want: Some(State::Failed),
            reason: REASON_NOT_LAUNCHED,
        },
        Case {
            name: "cancelled after launch",
            state: State::Running,
            step: LinkedStepAttemptState::Cancelled,
            lease_live: false,
            want: Some(State::Ambiguous),
            reason: "",
        },
        Case {
            name: "settled succeeded from receipt",
            state: State::Running,
            step: LinkedStepAttemptState::Succeeded,
            lease_live: false,
            want: Some(State::Succeeded),
            reason: REASON_RECOVERED_SETTLEMENT,
        },
        Case {
            name: "settled failed from receipt",
            state: State::Running,
            step: LinkedStepAttemptState::Failed,
            lease_live: false,
            want: Some(State::Failed),
            reason: REASON_RECOVERED_SETTLEMENT,
        },
        Case {
            name: "settled failed never launched",
            state: State::Prepared,
            step: LinkedStepAttemptState::Failed,
            lease_live: false,
            want: Some(State::Failed),
            reason: REASON_NOT_LAUNCHED,
        },
        Case {
            name: "settled succeeded but unrepresentable",
            state: State::Launching,
            step: LinkedStepAttemptState::Succeeded,
            lease_live: false,
            want: Some(State::Ambiguous),
            reason: "",
        },
        Case {
            name: "operator resolution lost its harness write",
            state: State::Ambiguous,
            step: LinkedStepAttemptState::Failed,
            lease_live: false,
            want: Some(State::Resolved),
            reason: "",
        },
        Case {
            name: "ambiguous awaiting the operator",
            state: State::Ambiguous,
            step: LinkedStepAttemptState::Reconciliation,
            lease_live: false,
            want: None,
            reason: "",
        },
        Case {
            name: "lease still live",
            state: State::Running,
            step: LinkedStepAttemptState::Invoked,
            lease_live: true,
            want: None,
            reason: "",
        },
        Case {
            name: "invoked, not recovered",
            state: State::Running,
            step: LinkedStepAttemptState::Invoked,
            lease_live: false,
            want: None,
            reason: "",
        },
        Case {
            name: "no linked step attempt",
            state: State::Prepared,
            step: LinkedStepAttemptState::Unset,
            lease_live: false,
            want: None,
            reason: "",
        },
    ];
    for tc in cases {
        let st = FakeStore::new(&Trace::default());
        let a = attempt_in(tc.state);
        st.put(a.clone(), tc.step, tc.lease_live);
        let r = Reconciler::new(st.clone(), Arc::new(RealClock));
        let sum = block_on(r.run()).unwrap_or_else(|e| unreachable!("{}: {e}", tc.name));
        let got = st
            .stored(a.id)
            .unwrap_or_else(|| unreachable!("{}: no stored row", tc.name));
        match tc.want {
            None => {
                assert!(
                    got.version == a.version && st.recovered().is_empty() && sum.skipped == 1,
                    "{}: attempt touched: {} v{}, summary {sum:?}",
                    tc.name,
                    got.state.as_str(),
                    got.version
                );
                continue;
            }
            Some(want) => {
                assert!(
                    got.state == want
                        && got.version == a.version + 1
                        && got.fence == a.fence
                        && got.last_event_seq == a.last_event_seq,
                    "{}: attempt = {} v{} fence {}, want {} v{}",
                    tc.name,
                    got.state.as_str(),
                    got.version,
                    got.fence.generation,
                    want.as_str(),
                    a.version + 1
                );
            }
        }
        if !tc.reason.is_empty() {
            assert_eq!(
                got.terminal.reason, tc.reason,
                "{}: terminal reason",
                tc.name
            );
        }
        if got.state == State::Ambiguous {
            assert_eq!(
                got.ambiguity_reason, AMBIGUITY_RESTART,
                "{}: ambiguity reason",
                tc.name
            );
        }
        if got.state == State::Resolved {
            assert!(
                got.resolution.kind == ResolutionKind::Abandon
                    && got.resolution.decided_by == DECIDED_BY_RECOVERY,
                "{}: resolution = {:?}",
                tc.name,
                got.resolution
            );
        }
        assert!(
            sum.scanned == 1 && sum.skipped == 0,
            "{}: summary = {sum:?}",
            tc.name
        );
    }
}

#[test]
fn reconciler_skips_what_the_recovery_authority_refuses() {
    let st = FakeStore::new(&Trace::default());
    let a = attempt_in(State::Running);
    st.put(a.clone(), LinkedStepAttemptState::Reconciliation, false);
    st.set_refuse(
        a.id,
        Failure::denied(domain::codes::RECOVERY_NOT_AUTHORIZED, "still lease-live"),
    );
    let r = Reconciler::new(st.clone(), Arc::new(RealClock));
    let sum = block_on(r.run()).expect("run");
    assert!(sum.skipped == 1 && sum.ambiguous == 0, "summary = {sum:?}");
    let got = st.stored(a.id).expect("stored");
    assert!(
        got.version == a.version && st.recovered().is_empty(),
        "attempt touched"
    );
}

#[test]
fn reconciler_pages_through_every_candidate() {
    let st = FakeStore::new(&Trace::default());
    let n = crate::port::MAX_RECOVERY_CANDIDATES + 7;
    for i in 0..n {
        let mut a = attempt_in(State::Running);
        a.prepared_at = EPOCH + Duration::milliseconds(i as i64);
        st.put(a, LinkedStepAttemptState::Reconciliation, false);
    }
    let r = Reconciler::new(st.clone(), Arc::new(RealClock));
    let sum = block_on(r.run()).expect("run");
    assert!(sum.scanned == n && sum.ambiguous == n, "summary = {sum:?}");
}

#[test]
fn reconciler_is_idempotent() {
    let st = FakeStore::new(&Trace::default());
    st.put(
        attempt_in(State::Running),
        LinkedStepAttemptState::Reconciliation,
        false,
    );
    st.put(
        attempt_in(State::Prepared),
        LinkedStepAttemptState::Cancelled,
        false,
    );
    let r = Reconciler::new(st.clone(), Arc::new(RealClock));
    block_on(r.run()).expect("first run");
    let writes = st.recovered().len();
    let sum = block_on(r.run()).expect("second run");
    assert!(
        st.recovered().len() == writes
            && sum.ambiguous + sum.unlaunched + sum.settled + sum.resolved == 0,
        "second pass wrote: {sum:?}"
    );
}

#[test]
fn resolver_resolves_the_ambiguous_attempt_as_abandon() {
    let st = FakeStore::new(&Trace::default());
    let a = attempt_in(State::Ambiguous);
    st.put(a.clone(), LinkedStepAttemptState::Failed, false);
    let r = Resolver::new(st.clone(), Arc::new(RealClock));
    block_on(r.resolve_abandon(a.workspace_id, step_of(&a), "operator-session:alice"))
        .expect("resolve");
    let got = st.stored(a.id).expect("stored");
    assert!(
        got.state == State::Resolved
            && got.resolution
                == Resolution {
                    kind: ResolutionKind::Abandon,
                    decided_by: "operator-session:alice".to_string(),
                },
        "attempt = {} {:?}",
        got.state.as_str(),
        got.resolution
    );
    // Idempotent: a second resolve writes nothing.
    let writes = st.recovered().len();
    block_on(r.resolve_abandon(a.workspace_id, step_of(&a), "operator-session:alice"))
        .expect("second");
    assert_eq!(st.recovered().len(), writes, "second call wrote");
}

#[test]
fn resolver_marks_a_live_attempt_ambiguous_first() {
    let st = FakeStore::new(&Trace::default());
    let a = attempt_in(State::Running);
    st.put(a.clone(), LinkedStepAttemptState::Failed, false);
    let r = Resolver::new(st.clone(), Arc::new(RealClock));
    block_on(r.resolve_abandon(a.workspace_id, step_of(&a), "operator-session:alice"))
        .expect("resolve");
    let rec = st.recovered();
    assert!(
        rec.len() == 2
            && rec[0].state == State::Ambiguous
            && rec[1].state == State::Resolved
            && rec[1].resolution.kind == ResolutionKind::Abandon,
        "recovered = {rec:?}"
    );
}

#[test]
fn resolver_without_a_harness_row_is_a_no_op() {
    let st = FakeStore::new(&Trace::default());
    let r = Resolver::new(st.clone(), Arc::new(RealClock));
    block_on(r.resolve_abandon(
        central_foundation::identity::WorkspaceId::new(),
        StepAttemptId::new(),
        "operator-session:alice",
    ))
    .expect("resolve");
    assert!(st.recovered().is_empty());
}

#[test]
fn reconciler_supersedes_the_pending_approval_of_what_it_settles() {
    for step in [
        LinkedStepAttemptState::Reconciliation,
        LinkedStepAttemptState::Failed,
        LinkedStepAttemptState::Cancelled,
    ] {
        let st = FakeStore::new(&Trace::default());
        let a = attempt_in(State::AwaitingPermission);
        st.put(a.clone(), step, false);
        let approval = st.put_approval(&a);
        let r = Reconciler::new(st.clone(), Arc::new(RealClock));
        block_on(r.run()).expect("run");
        let got = &st.approval_list()[0];
        assert!(
            got.id == approval.id
                && got.state == crate::approval::ApprovalState::Superseded
                && got.decided_by == crate::approval::DECIDED_BY_SUPERSEDED,
            "{step:?}: approval = {got:?}"
        );
        let next = st.only();
        assert!(
            next.state == State::Ambiguous || next.state.is_terminal(),
            "{step:?}: attempt = {}",
            next.state.as_str()
        );
    }
}

#[test]
fn resolver_fail_unlaunched_fails_a_prepared_row_once() {
    let st = FakeStore::new(&Trace::default());
    let a = attempt_in(State::Prepared);
    st.put(a.clone(), LinkedStepAttemptState::Cancelled, false);
    let r = Resolver::new(st.clone(), Arc::new(RealClock));
    block_on(r.fail_unlaunched(a.workspace_id, step_of(&a))).expect("fail");
    let got = st.stored(a.id).expect("stored");
    assert!(
        got.state == State::Failed
            && got.terminal.reason == REASON_NOT_LAUNCHED
            && got.fence == a.fence
            && got.version == a.version + 1,
        "attempt = {} {:?} fence {} v{}",
        got.state.as_str(),
        got.terminal.reason,
        got.fence.generation,
        got.version
    );
    // Idempotent.
    let writes = st.recovered().len();
    block_on(r.fail_unlaunched(a.workspace_id, step_of(&a))).expect("second");
    assert_eq!(st.recovered().len(), writes, "second call wrote");
}

#[test]
fn resolver_fail_unlaunched_without_a_row_is_a_no_op() {
    let st = FakeStore::new(&Trace::default());
    let r = Resolver::new(st.clone(), Arc::new(RealClock));
    block_on(r.fail_unlaunched(
        central_foundation::identity::WorkspaceId::new(),
        StepAttemptId::new(),
    ))
    .expect("fail");
    assert!(st.recovered().is_empty());
}

#[test]
fn resolver_fail_unlaunched_leaves_a_launched_row_to_the_reconciler() {
    let st = FakeStore::new(&Trace::default());
    let a = attempt_in(State::Running);
    st.put(a.clone(), LinkedStepAttemptState::Cancelled, false);
    let r = Resolver::new(st.clone(), Arc::new(RealClock));
    block_on(r.fail_unlaunched(a.workspace_id, step_of(&a))).expect("fail");
    let got = st.stored(a.id).expect("stored");
    assert!(
        got.state == State::Running && st.recovered().is_empty(),
        "a launched row was failed: {}",
        got.state.as_str()
    );
}

#[test]
fn resolver_fail_unlaunched_returns_the_recovery_refusal() {
    let st = FakeStore::new(&Trace::default());
    let a = attempt_in(State::Prepared);
    st.put(a.clone(), LinkedStepAttemptState::Cancelled, false);
    st.set_refuse(
        a.id,
        Failure::denied(domain::codes::RECOVERY_NOT_AUTHORIZED, "still lease-live"),
    );
    let r = Resolver::new(st.clone(), Arc::new(RealClock));
    let err = block_on(r.fail_unlaunched(a.workspace_id, step_of(&a)))
        .expect_err("the refusal is returned");
    assert_eq!(err.code(), domain::codes::RECOVERY_NOT_AUTHORIZED);
    let got = st.stored(a.id).expect("stored");
    assert!(got.state == State::Prepared, "attempt touched");
}

// Harness phase 3g decision 6: an operator's resume created the
// successor StepAttempt but its resolved(resume) harness write was
// lost.
#[test]
fn reconciler_heals_a_lost_resume_write() {
    // ambiguous with a successor becomes resolved(resume)
    {
        let st = FakeStore::new(&Trace::default());
        let a = attempt_in(State::Ambiguous);
        st.put(a.clone(), LinkedStepAttemptState::Resumed, false);
        let r = Reconciler::new(st.clone(), Arc::new(RealClock));
        let sum = block_on(r.run()).expect("run");
        assert!(sum.resolved == 1 && sum.skipped == 0, "summary = {sum:?}");
        let got = st.stored(a.id).expect("stored");
        assert!(
            got.state == State::Resolved
                && got.version == a.version + 1
                && got.resolution
                    == Resolution {
                        kind: ResolutionKind::Resume,
                        decided_by: DECIDED_BY_OPERATOR_RESUME.to_string(),
                    },
            "attempt = {} v{} {:?}",
            got.state.as_str(),
            got.version,
            got.resolution
        );
    }
    // no session id falls back to resolved(abandon)
    {
        let st = FakeStore::new(&Trace::default());
        let a = ambiguous_without_session();
        st.put(a.clone(), LinkedStepAttemptState::Resumed, false);
        let r = Reconciler::new(st.clone(), Arc::new(RealClock));
        let sum = block_on(r.run()).expect("run");
        assert!(sum.resolved == 1 && sum.skipped == 0, "summary = {sum:?}");
        let got = st.stored(a.id).expect("stored");
        assert!(
            got.state == State::Resolved
                && got.resolution
                    == Resolution {
                        kind: ResolutionKind::Abandon,
                        decided_by: DECIDED_BY_RECOVERY.to_string(),
                    },
            "attempt = {} {:?}",
            got.state.as_str(),
            got.resolution
        );
    }
    // ambiguous failed without a successor still abandons
    {
        let st = FakeStore::new(&Trace::default());
        let a = attempt_in(State::Ambiguous);
        st.put(a.clone(), LinkedStepAttemptState::Failed, false);
        let r = Reconciler::new(st.clone(), Arc::new(RealClock));
        let sum = block_on(r.run()).expect("run");
        assert_eq!(sum.resolved, 1, "summary = {sum:?}");
        let got = st.stored(a.id).expect("stored");
        assert!(
            got.state == State::Resolved
                && got.resolution
                    == Resolution {
                        kind: ResolutionKind::Abandon,
                        decided_by: DECIDED_BY_RECOVERY.to_string(),
                    },
            "attempt = {} {:?}",
            got.state.as_str(),
            got.resolution
        );
    }
    // a non-ambiguous row with a successor takes the failed path
    {
        let st = FakeStore::new(&Trace::default());
        let a = attempt_in(State::Running);
        st.put(a.clone(), LinkedStepAttemptState::Resumed, false);
        let r = Reconciler::new(st.clone(), Arc::new(RealClock));
        let sum = block_on(r.run()).expect("run");
        assert_eq!(sum.settled, 1, "summary = {sum:?}");
        let got = st.stored(a.id).expect("stored");
        assert!(
            got.state == State::Failed && got.terminal.reason == REASON_RECOVERED_SETTLEMENT,
            "attempt = {} {:?}",
            got.state.as_str(),
            got.terminal.reason
        );
    }
}

#[test]
fn resolver_complete_resume() {
    const DECIDER: &str = "operator-session:alice";
    let resumed = Resolution {
        kind: ResolutionKind::Resume,
        decided_by: DECIDER.to_string(),
    };

    // ambiguous is resolved once as resume by the given decider
    {
        let st = FakeStore::new(&Trace::default());
        let a = attempt_in(State::Ambiguous);
        st.put(a.clone(), LinkedStepAttemptState::Resumed, false);
        let r = Resolver::new(st.clone(), Arc::new(RealClock));
        block_on(r.complete_resume(a.workspace_id, step_of(&a), DECIDER)).expect("complete");
        let rec = st.recovered();
        assert!(
            rec.len() == 1 && rec[0].state == State::Resolved && rec[0].resolution == resumed,
            "recovered = {rec:?}"
        );
        block_on(r.complete_resume(a.workspace_id, step_of(&a), DECIDER)).expect("second");
        assert_eq!(st.recovered().len(), 1, "second call wrote");
    }
    // already resolved(resume) writes nothing
    {
        let st = FakeStore::new(&Trace::default());
        let a = resolved_as(&attempt_in(State::Ambiguous), resumed.clone());
        st.put(a.clone(), LinkedStepAttemptState::Resumed, false);
        let r = Resolver::new(st.clone(), Arc::new(RealClock));
        block_on(r.complete_resume(a.workspace_id, step_of(&a), "another-decider"))
            .expect("complete");
        assert!(st.recovered().is_empty(), "wrote");
    }
    // a version conflict reloads once and accepts resolved(resume)
    {
        let st = FakeStore::new(&Trace::default());
        let a = attempt_in(State::Ambiguous);
        st.put(a.clone(), LinkedStepAttemptState::Resumed, false);
        let won = resolved_as(&a, resumed.clone());
        let st2 = st.clone();
        let cs = Arc::new(ConflictOnce::new(st.clone(), move || {
            st2.store_attempt(won.clone());
        }));
        let r = Resolver::new(cs, Arc::new(RealClock));
        block_on(r.complete_resume(a.workspace_id, step_of(&a), DECIDER)).expect("complete");
        assert!(st.recovered().is_empty(), "wrote over the winner");
    }
    // a version conflict reloads once and writes a row still ambiguous
    {
        let st = FakeStore::new(&Trace::default());
        let a = attempt_in(State::Ambiguous);
        st.put(a.clone(), LinkedStepAttemptState::Resumed, false);
        let st2 = st.clone();
        let cs = Arc::new(ConflictOnce::new(st.clone(), move || {
            let mut bumped = st2.stored(a.id).expect("stored");
            bumped.version += 1;
            st2.store_attempt(bumped);
        }));
        let r = Resolver::new(cs.clone(), Arc::new(RealClock));
        block_on(r.complete_resume(a.workspace_id, step_of(&a), DECIDER)).expect("complete");
        let rec = st.recovered();
        assert!(
            cs.done.load(Ordering::SeqCst)
                && rec.len() == 1
                && rec[0].version == a.version + 2
                && rec[0].resolution == resumed,
            "conflict seen {}, recovered = {rec:?}",
            cs.done.load(Ordering::SeqCst)
        );
    }
    // a version conflict reloads once and refuses resolved(abandon)
    {
        let st = FakeStore::new(&Trace::default());
        let a = attempt_in(State::Ambiguous);
        st.put(a.clone(), LinkedStepAttemptState::Resumed, false);
        let abandoned = resolved_as(
            &a,
            Resolution {
                kind: ResolutionKind::Abandon,
                decided_by: "operator-session:bob".to_string(),
            },
        );
        let st2 = st.clone();
        let cs = Arc::new(ConflictOnce::new(st.clone(), move || {
            st2.store_attempt(abandoned.clone());
        }));
        let r = Resolver::new(cs.clone(), Arc::new(RealClock));
        let err = block_on(r.complete_resume(a.workspace_id, step_of(&a), DECIDER))
            .expect_err("resolved(abandon) refuses");
        assert!(
            err.code() == domain::codes::RESUME_NOT_ALLOWED
                && cs.done.load(Ordering::SeqCst)
                && st.recovered().is_empty(),
            "err {err}, conflict seen {}, writes",
            cs.done.load(Ordering::SeqCst)
        );
    }
    // a persistent version conflict is returned after one reload
    {
        let st = FakeStore::new(&Trace::default());
        let a = attempt_in(State::Ambiguous);
        st.put(a.clone(), LinkedStepAttemptState::Resumed, false);
        st.set_refuse(
            a.id,
            Failure::conflict(domain::codes::VERSION_CONFLICT, "the attempt moved on"),
        );
        let r = Resolver::new(st.clone(), Arc::new(RealClock));
        let err = block_on(r.complete_resume(a.workspace_id, step_of(&a), DECIDER))
            .expect_err("conflict returned");
        assert_eq!(err.code(), domain::codes::VERSION_CONFLICT);
    }
    // resolved(abandon) is not resumable
    {
        let st = FakeStore::new(&Trace::default());
        let a = resolved_as(
            &attempt_in(State::Ambiguous),
            Resolution {
                kind: ResolutionKind::Abandon,
                decided_by: "operator-session:bob".to_string(),
            },
        );
        st.put(a.clone(), LinkedStepAttemptState::Failed, false);
        let r = Resolver::new(st.clone(), Arc::new(RealClock));
        let err = block_on(r.complete_resume(a.workspace_id, step_of(&a), DECIDER))
            .expect_err("not resumable");
        assert!(
            err.code() == domain::codes::RESUME_NOT_ALLOWED && st.recovered().is_empty(),
            "err {err}, writes"
        );
    }
    // a live attempt is not resumable
    {
        let st = FakeStore::new(&Trace::default());
        let a = attempt_in(State::Running);
        st.put(a.clone(), LinkedStepAttemptState::Invoked, false);
        let r = Resolver::new(st.clone(), Arc::new(RealClock));
        let err = block_on(r.complete_resume(a.workspace_id, step_of(&a), DECIDER))
            .expect_err("not resumable");
        assert!(
            err.code() == domain::codes::RESUME_NOT_ALLOWED && st.recovered().is_empty(),
            "err {err}, writes"
        );
    }
    // an ambiguous attempt without a session id is not resumable
    {
        let st = FakeStore::new(&Trace::default());
        let a = ambiguous_without_session();
        st.put(a.clone(), LinkedStepAttemptState::Resumed, false);
        let r = Resolver::new(st.clone(), Arc::new(RealClock));
        let err = block_on(r.complete_resume(a.workspace_id, step_of(&a), DECIDER))
            .expect_err("not resumable");
        assert!(
            err.code() == domain::codes::RESUME_NOT_ALLOWED && st.recovered().is_empty(),
            "err {err}, writes"
        );
    }
    // no row wraps ErrAttemptNotFound
    {
        let st = FakeStore::new(&Trace::default());
        let r = Resolver::new(st.clone(), Arc::new(RealClock));
        let err = block_on(r.complete_resume(
            central_foundation::identity::WorkspaceId::new(),
            StepAttemptId::new(),
            DECIDER,
        ))
        .expect_err("missing row");
        assert_eq!(err.code(), domain::codes::ATTEMPT_NOT_FOUND);
    }
}

// ===========================================================================
// rerun_resolver_test.go — harness phase 3k decision 4 (acceptance 1):
// ResolveRerun has ResolveAbandon's shape with the kind rerun.
// ===========================================================================

#[test]
fn resolver_resolve_rerun() {
    const DECIDER: &str = "operator-session:alice";

    // ambiguous: resolved(rerun), once
    {
        let st = FakeStore::new(&Trace::default());
        let a = attempt_in(State::Ambiguous);
        st.put(a.clone(), LinkedStepAttemptState::Failed, false);
        let r = Resolver::new(st.clone(), Arc::new(RealClock));
        block_on(r.resolve_rerun(a.workspace_id, step_of(&a), DECIDER)).expect("rerun");
        let got = st.stored(a.id).expect("stored");
        assert!(
            got.state == State::Resolved
                && got.resolution
                    == Resolution {
                        kind: ResolutionKind::Rerun,
                        decided_by: DECIDER.to_string(),
                    }
                && got.fence == a.fence
                && got.version == a.version + 1,
            "attempt = {} {:?} fence {} v{}",
            got.state.as_str(),
            got.resolution,
            got.fence.generation,
            got.version
        );
        let writes = st.recovered().len();
        block_on(r.resolve_rerun(a.workspace_id, step_of(&a), DECIDER)).expect("second");
        assert_eq!(st.recovered().len(), writes, "second call wrote");
    }
    // a live row is marked ambiguous first
    {
        let st = FakeStore::new(&Trace::default());
        let a = attempt_in(State::Running);
        st.put(a.clone(), LinkedStepAttemptState::Failed, false);
        let r = Resolver::new(st.clone(), Arc::new(RealClock));
        block_on(r.resolve_rerun(a.workspace_id, step_of(&a), DECIDER)).expect("rerun");
        let rec = st.recovered();
        assert!(
            rec.len() == 2
                && rec[0].state == State::Ambiguous
                && rec[1].state == State::Resolved
                && rec[1].resolution.kind == ResolutionKind::Rerun,
            "recovered = {rec:?}"
        );
    }
    // already resolved(abandon) is left alone
    {
        let st = FakeStore::new(&Trace::default());
        let a = resolved_as(
            &attempt_in(State::Ambiguous),
            Resolution {
                kind: ResolutionKind::Abandon,
                decided_by: DECIDED_BY_RECOVERY.to_string(),
            },
        );
        st.put(a.clone(), LinkedStepAttemptState::Failed, false);
        let r = Resolver::new(st.clone(), Arc::new(RealClock));
        block_on(r.resolve_rerun(a.workspace_id, step_of(&a), DECIDER)).expect("rerun");
        assert!(st.recovered().is_empty(), "a resolved row was touched");
    }
    // no row is a no-op
    {
        let st = FakeStore::new(&Trace::default());
        let r = Resolver::new(st.clone(), Arc::new(RealClock));
        block_on(r.resolve_rerun(
            central_foundation::identity::WorkspaceId::new(),
            StepAttemptId::new(),
            DECIDER,
        ))
        .expect("rerun");
        assert!(st.recovered().is_empty());
    }
    // the recovery authority's refusal is returned
    {
        let st = FakeStore::new(&Trace::default());
        let a = attempt_in(State::Ambiguous);
        st.put(a.clone(), LinkedStepAttemptState::Failed, false);
        st.set_refuse(
            a.id,
            Failure::denied(domain::codes::RECOVERY_NOT_AUTHORIZED, "retry pending"),
        );
        let r = Resolver::new(st.clone(), Arc::new(RealClock));
        let err = block_on(r.resolve_rerun(a.workspace_id, step_of(&a), DECIDER))
            .expect_err("refusal returned");
        assert_eq!(err.code(), domain::codes::RECOVERY_NOT_AUTHORIZED);
    }
}

// ===========================================================================
// dispatcher_test.go — the bounded fan-out driver (harness phase 3h):
// probe before claim, paused states, bounded concurrency, the startup
// sweep, cooldowns, lost/settle-failed holds, bounded shutdown.
// ===========================================================================

/// `lastIndex` — the last trace position of `call`, or -1.
fn last_index(calls: &[String], call: &str) -> i64 {
    calls
        .iter()
        .rposition(|c| c == call)
        .map(|i| i as i64)
        .unwrap_or(-1)
}

/// `dispatcherConfig{}` — the world default the port of
/// `newDispatchWorld` applies.
fn dispatch_cfg() -> DispatcherConfig {
    DispatcherConfig {
        concurrency: 1,
        launch_env: test_env(),
        poll_interval: Duration::milliseconds(5),
        pause_retry: Duration::milliseconds(30),
        shutdown_budget: Duration::ZERO,
        probe_budget: Duration::ZERO,
        not_startable_cooldown: Duration::ZERO,
        max_not_startable_cooldown: Duration::ZERO,
    }
}

fn probe_ok() -> port::ProbeResult {
    port::ProbeResult {
        harness_version: "2.1.283".to_string(),
        authenticated: true,
        detail: String::new(),
    }
}

#[test]
fn dispatcher_probes_before_claiming_and_pauses_when_not_logged_in() {
    let tr = Trace::default();
    let run = queued_run();
    let life = Arc::new(Lifecycle::new(&tr, vec![run.clone()]));
    let w = new_dispatch_world(None, life, dispatch_cfg());
    w.ad.set_probe(port::ProbeResult {
        harness_version: "2.1.283".to_string(),
        authenticated: false,
        detail: String::new(),
    });
    w.start();
    wait_for("a not-logged-in pause", || {
        let s = w.disp.status();
        s.state == DispatcherState::Paused && s.pause == PauseReason::NotLoggedIn
    });
    std::thread::sleep(std::time::Duration::from_millis(80)); // several re-probes
    assert_eq!(
        w.tr.count("lifecycle.Start"),
        0,
        "claimed while not logged in"
    );
    let paused = w.sink.of(MilestoneKind::DispatchPaused);
    assert!(
        paused.len() == 1
            && paused[0].task_id == run.task_id
            && paused[0].reason == PauseReason::NotLoggedIn.as_str(),
        "paused milestones = {paused:?}"
    );
    w.ad.set_probe(probe_ok());
    wait_for("the claim after login", || {
        w.tr.count("lifecycle.Start") == 1
    });
    assert_eq!(
        w.disp.status().state,
        DispatcherState::Running,
        "status = {:?}",
        w.disp.status()
    );
    let calls = w.tr.all();
    let last = last_index(&calls, "adapter.Probe");
    assert!(
        !(last > w.tr.index("lifecycle.Start") || last < 0),
        "no probe before the claim: {calls:?}"
    );
    let resumed = w.sink.of(MilestoneKind::DispatchResumed);
    assert!(
        resumed.len() == 1 && resumed[0].task_id == run.task_id,
        "resumed milestones = {resumed:?}"
    );
    w.stop_wait().expect("stop");
    assert_eq!(
        w.disp.status().state,
        DispatcherState::Stopped,
        "status after stop = {:?}",
        w.disp.status()
    );
}

#[test]
fn dispatcher_pauses_while_the_launcher_is_unreachable() {
    let tr = Trace::default();
    let life = Arc::new(Lifecycle::new(&tr, vec![queued_run()]));
    let w = new_dispatch_world(None, life, dispatch_cfg());
    w.ad.set_probe_err(Some(Failure::internal(
        "probe",
        "dial unix: connection refused",
    )));
    w.start();
    wait_for("a launcher-unreachable pause", || {
        let s = w.disp.status();
        s.paused() && s.pause == PauseReason::LauncherUnreachable
    });
    assert_eq!(
        w.tr.count("lifecycle.Start"),
        0,
        "claimed with the launcher unreachable"
    );
    w.ad.set_probe_err(None);
    wait_for("the claim after the launcher returned", || {
        w.tr.count("lifecycle.Start") == 1
    });
}

#[test]
fn dispatcher_pauses_on_low_disk_without_probing() {
    let tr = Trace::default();
    let life = Arc::new(Lifecycle::new(&tr, vec![queued_run()]));
    let w = new_dispatch_world(None, life, dispatch_cfg());
    w.prov.set_space_err(Some(Failure::unavailable(
        codes::LOW_DISK,
        "free space below the minimum",
    )));
    w.start();
    wait_for("a low-disk pause", || {
        let s = w.disp.status();
        s.paused() && s.pause == PauseReason::LowDisk
    });
    std::thread::sleep(std::time::Duration::from_millis(60));
    assert!(
        w.tr.count("adapter.Probe") == 0 && w.tr.count("lifecycle.Start") == 0,
        "probed or claimed on low disk: {:?}",
        w.tr.all()
    );
    w.prov.set_space_err(None);
    wait_for("the claim after space was freed", || {
        w.tr.count("lifecycle.Start") == 1
    });
}

#[test]
fn dispatcher_idles_without_probing_when_nothing_is_dispatchable() {
    let tr = Trace::default();
    let life = Arc::new(Lifecycle::new(&tr, vec![]));
    let w = new_dispatch_world(None, life, dispatch_cfg());
    w.start();
    wait_for("running", || {
        w.disp.status().state == DispatcherState::Running
    });
    std::thread::sleep(std::time::Duration::from_millis(40));
    // One startup probe, then none while the queue is empty.
    assert_eq!(
        w.tr.count("adapter.Probe"),
        1,
        "probes, want only the startup probe"
    );
}

// §7 acceptance: serve starting with the launcher stopped is ready with
// the dispatcher paused, and resumes once the probe succeeds.
#[test]
fn dispatcher_starts_paused_when_the_harness_is_unavailable() {
    struct Case {
        name: &'static str,
        down: Box<dyn Fn(&DispatchWorld)>,
        up: Box<dyn Fn(&DispatchWorld)>,
        reason: PauseReason,
    }
    let cases = vec![
        Case {
            name: "launcher down",
            down: Box::new(|w: &DispatchWorld| {
                w.ad.set_probe_err(Some(Failure::internal(
                    "probe",
                    "dial unix: connection refused",
                )));
            }),
            up: Box::new(|w: &DispatchWorld| w.ad.set_probe_err(None)),
            reason: PauseReason::LauncherUnreachable,
        },
        Case {
            name: "not logged in",
            down: Box::new(|w: &DispatchWorld| {
                w.ad.set_probe(port::ProbeResult {
                    harness_version: "2.1.283".to_string(),
                    authenticated: false,
                    detail: String::new(),
                });
            }),
            up: Box::new(|w: &DispatchWorld| w.ad.set_probe(probe_ok())),
            reason: PauseReason::NotLoggedIn,
        },
    ];
    for tc in cases {
        let tr = Trace::default();
        let life = Arc::new(Lifecycle::new(&tr, vec![]));
        let mut cfg = dispatch_cfg();
        cfg.pause_retry = Duration::milliseconds(20);
        let w = new_dispatch_world(None, life, cfg);
        (tc.down)(&w);
        w.start();
        wait_for("a paused start", || {
            let s = w.disp.status();
            s.paused() && s.pause == tc.reason
        });
        assert!(
            w.tr.index("adapter.Probe") >= 0,
            "{}: paused without a probe: {:?}",
            tc.name,
            w.tr.all()
        );
        wait_for("a re-probe while paused", || {
            w.tr.count("adapter.Probe") >= 3
        });
        assert_eq!(
            w.disp.status().state,
            DispatcherState::Paused,
            "{}: status = {:?}",
            tc.name,
            w.disp.status()
        );
        (tc.up)(&w);
        wait_for("running after the probe succeeded", || {
            w.disp.status().state == DispatcherState::Running
        });
        let probes = w.tr.count("adapter.Probe");
        std::thread::sleep(std::time::Duration::from_millis(60)); // three pause retries
        assert_eq!(
            w.tr.count("adapter.Probe"),
            probes,
            "{}: probed an empty queue after resuming",
            tc.name
        );
        assert!(
            w.sink.of(MilestoneKind::DispatchPaused).is_empty(),
            "{}: paused milestone with no waiting task",
            tc.name
        );
        w.stop_wait().expect("stop");
    }
}

#[test]
fn dispatcher_runs_at_most_concurrency_attempts() {
    let tr = Trace::default();
    let runs: Vec<DispatchableRun> = (0..5).map(|_| queued_run()).collect();
    let life = Arc::new(Lifecycle::new(&tr, runs));
    let release = Arc::new(ManualCancel::default());
    let mut runner = ScriptedRunner::new(life.clone());
    runner.release = Some(release.clone());
    runner.result = HarnessResult::bare(Outcome::Succeeded, None);
    let runner = Arc::new(runner);
    let mut cfg = dispatch_cfg();
    cfg.concurrency = 2;
    let w = new_dispatch_world(Some(runner.clone()), life, cfg);
    w.start();
    wait_for("two attempts", || runner.active.load(Ordering::SeqCst) == 2);
    std::thread::sleep(std::time::Duration::from_millis(40));
    assert!(
        runner.calls.load(Ordering::SeqCst) == 2 && w.disp.status().active == 2,
        "calls={} active={}",
        runner.calls.load(Ordering::SeqCst),
        w.disp.status().active
    );
    release.cancel();
    wait_for("every run", || {
        runner.calls.load(Ordering::SeqCst) == 5 && runner.active.load(Ordering::SeqCst) == 0
    });
    assert_eq!(runner.max_active.load(Ordering::SeqCst), 2, "max active");
}

#[test]
fn new_dispatcher_rejects_concurrency_outside_one_to_four() {
    let tr = Trace::default();
    let life = Arc::new(Lifecycle::new(&tr, vec![]));
    for c in [0usize, 5] {
        let mut cfg = dispatch_cfg();
        cfg.concurrency = c;
        let res = super::dispatcher::Dispatcher::new(super::dispatcher::DispatcherDeps {
            lifecycle: life.clone(),
            runner: starting_runner(life.clone()),
            adapter: Arc::new(FakeAdapter::new(
                &tr,
                "claude-code",
                Capabilities::default(),
                vec![],
            )),
            launcher: Arc::new(FakeLauncher::new()),
            recovery: FakeStore::new(&tr),
            workspaces: Arc::new(Provisioner::new(&tr, Arc::new(super::ports::RealTicker))),
            events: Arc::new(Sink::new(&tr, false)),
            clock: Arc::new(RealClock),
            ticker: Arc::new(super::ports::RealTicker),
            logger: Arc::new(RecordingLog::default()),
            cfg,
        });
        assert!(res.is_err(), "concurrency {c} accepted");
    }
}

#[test]
fn dispatcher_sweeps_ambiguous_scopes_on_first_start() {
    let tr = Trace::default();
    let life = Arc::new(Lifecycle::new(&tr, vec![]));
    let w = new_dispatch_world(None, life, dispatch_cfg());
    let alive = attempt_in(State::Ambiguous);
    let dead = attempt_in(State::Ambiguous);
    let running = attempt_in(State::Running);
    w.st.put(alive.clone(), LinkedStepAttemptState::Reconciliation, false);
    w.st.put(dead.clone(), LinkedStepAttemptState::Reconciliation, false);
    w.st.put(running.clone(), LinkedStepAttemptState::Invoked, true);
    w.launcher.set_alive(&alive.sandbox_scope_id, true);
    w.launcher.set_alive(&running.sandbox_scope_id, true);
    w.launcher
        .fail_alive(Some(Failure::internal("alive", "launcher unreachable")));
    w.start();
    wait_for("a launcher-unreachable pause", || {
        let s = w.disp.status();
        s.paused() && s.pause == PauseReason::LauncherUnreachable
    });
    assert!(
        w.launcher.kills().is_empty(),
        "killed without asking the launcher"
    );
    w.launcher.fail_alive(None);
    wait_for("running after the sweep", || {
        w.disp.status().state == DispatcherState::Running
    });
    let kills = w.launcher.kills();
    assert!(
        kills.len() == 1 && kills[0] == alive.sandbox_scope_id,
        "kills = {kills:?}, want only {}",
        alive.sandbox_scope_id
    );
}

#[test]
fn dispatcher_never_redispatches_a_lost_run() {
    let tr = Trace::default();
    let run = queued_run();
    let life = Arc::new(Lifecycle::new(&tr, vec![run.clone()]));
    life.set_relist_all(true); // relistingLifecycle
    let mut runner = ScriptedRunner::new(life.clone());
    runner.result = HarnessResult {
        outcome: Outcome::Lost,
        reason: FailureCode::LEASE_LOST,
        low_disk: false,
        settle_failed: false,
        err: Some(Failure::conflict(codes::LEASE_LOST, "the lease was lost")),
    };
    let runner = Arc::new(runner);
    let w = new_dispatch_world(Some(runner.clone()), life, dispatch_cfg());
    w.start();
    wait_for("the lost run to be recorded", || {
        w.disp.status().lost.len() == 1
    });
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert_eq!(
        runner.calls.load(Ordering::SeqCst),
        1,
        "lost run dispatched more than once"
    );
    let lost = w.disp.status().lost;
    assert_eq!(lost[0], run.run_id, "lost = {lost:?}");
}

#[test]
fn dispatcher_shutdown_closes_lifelines_within_the_budget() {
    let w = new_world(
        default_cfg(),
        Capabilities::default(),
        vec![blocking_script(), blocking_script()],
    );
    w.life.push_run(queued_run());
    let runner: Arc<dyn super::dispatcher::AttemptRunner> = Arc::new(
        Orchestrator::new(super::orchestrator::OrchestratorDeps {
            lifecycle: w.life.clone(),
            attempts: w.st.clone(),
            adapter: w.ad.clone(),
            workspaces: w.prov.clone(),
            capture: w.cap.clone(),
            artifacts: w.arts.clone(),
            clock: w.clock.clone(),
            ticker: w.ticker.clone(),
            cfg: {
                let mut c = default_cfg();
                c.adapter_version = "claudecode/3a".to_string();
                c.launch_env = test_env();
                c.events = Some(w.sink.clone());
                c
            },
        })
        .expect("NewOrchestrator"),
    );
    let mut cfg = dispatch_cfg();
    cfg.concurrency = 2;
    cfg.shutdown_budget = Duration::SECOND;
    let d = super::dispatcher::Dispatcher::new(super::dispatcher::DispatcherDeps {
        lifecycle: w.life.clone(),
        runner,
        adapter: w.ad.clone(),
        launcher: Arc::new(FakeLauncher::new()),
        recovery: w.st.clone(),
        workspaces: w.prov.clone(),
        events: w.sink.clone(),
        clock: w.clock.clone(),
        ticker: w.ticker.clone(),
        logger: Arc::new(RecordingLog::default()),
        cfg,
    })
    .expect("NewDispatcher");
    let d = Arc::new(d);
    let stop: Arc<dyn super::ports::CancelSignal> = w.stop.clone();
    let d2 = d.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(block_on(d2.run(stop)));
    });
    wait_for("two waiting sessions", || {
        w.tr.count("store.AppendEvent:permission_requested") == 2
    });
    let started = std::time::Instant::now();
    w.stop.cancel();
    rx.recv_timeout(std::time::Duration::from_secs(10))
        .expect("Run did not return")
        .expect("Run");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(1),
        "shutdown took {:?}",
        started.elapsed()
    );
    for i in 0..2 {
        let (_, kills) =
            w.ad.session_counts(i)
                .unwrap_or_else(|| unreachable!("session {i}"));
        assert_eq!(kills, 1, "session {i} lifeline not closed");
    }
    assert_eq!(w.tr.count("lifecycle.Settle"), 0, "settled during shutdown");
    assert_eq!(
        d.status().state,
        DispatcherState::Stopped,
        "status = {:?}",
        d.status()
    );
}

#[test]
fn dispatcher_shutdown_reports_an_attempt_that_outlives_the_budget() {
    let tr = Trace::default();
    let life = Arc::new(Lifecycle::new(&tr, vec![queued_run()]));
    let release = Arc::new(ManualCancel::default());
    let mut runner = ScriptedRunner::new(life.clone());
    runner.release = Some(release.clone());
    runner.ignore_stop = true;
    let runner = Arc::new(runner);
    let mut cfg = dispatch_cfg();
    cfg.shutdown_budget = Duration::milliseconds(30);
    let w = new_dispatch_world(Some(runner.clone()), life, cfg);
    w.start();
    wait_for("the attempt", || runner.active.load(Ordering::SeqCst) == 1);
    assert!(
        w.stop_wait().is_err(),
        "shutdown past the budget reported no error"
    );
    release.cancel();
}

#[test]
fn dispatcher_pauses_on_low_disk_reported_by_an_attempt() {
    let tr = Trace::default();
    let life = Arc::new(Lifecycle::new(&tr, vec![queued_run()]));
    let mut runner = ScriptedRunner::new(life.clone());
    runner.result = HarnessResult {
        outcome: Outcome::Abandoned,
        reason: FailureCode::WORKSPACE_UNAVAILABLE,
        low_disk: true,
        settle_failed: false,
        err: None,
    };
    let runner = Arc::new(runner);
    let mut cfg = dispatch_cfg();
    cfg.pause_retry = Duration::HOUR;
    let w = new_dispatch_world(Some(runner), life, cfg);
    w.start();
    wait_for("a low-disk pause", || {
        let s = w.disp.status();
        s.paused() && s.pause == PauseReason::LowDisk
    });
}

// Review T-I2: the oldest Run is listed but refused at start. It must
// not block the Run after it, and the dispatcher must not re-probe
// for it round after round.
#[test]
fn dispatcher_cools_down_a_run_it_cannot_start() {
    let tr = Trace::default();
    let next = queued_run();
    let life = Arc::new(Lifecycle::new(&tr, vec![next]));
    let refused = queued_run();
    life.set_refused(Some(refused));
    let mut cfg = dispatch_cfg();
    cfg.not_startable_cooldown = Duration::HOUR;
    let w = new_dispatch_world(Some(starting_runner(life.clone())), life.clone(), cfg);
    w.start();
    wait_for("the run behind the refused one", || {
        w.tr.count("lifecycle.Start") == 2
    });
    std::thread::sleep(std::time::Duration::from_millis(100)); // twenty poll intervals
    assert_eq!(
        life.refuse_attempts.load(Ordering::SeqCst),
        1,
        "refused run started more than once (cool-down)"
    );
    // The startup probe, then one per claim round.
    assert!(
        w.tr.count("adapter.Probe") <= 3,
        "probed {} times for one refused and one started run",
        w.tr.count("adapter.Probe")
    );
    assert_eq!(
        w.disp.status().state,
        DispatcherState::Running,
        "status = {:?}",
        w.disp.status()
    );
}

#[test]
fn dispatcher_retries_a_refused_run_after_its_cooldown() {
    let tr = Trace::default();
    let life = Arc::new(Lifecycle::new(&tr, vec![]));
    life.set_refused(Some(queued_run()));
    let mut cfg = dispatch_cfg();
    cfg.not_startable_cooldown = Duration::milliseconds(20);
    cfg.max_not_startable_cooldown = Duration::milliseconds(40);
    let w = new_dispatch_world(Some(starting_runner(life.clone())), life.clone(), cfg);
    w.start();
    wait_for("a retry after the cool-down", || {
        life.refuse_attempts.load(Ordering::SeqCst) >= 3
    });
    let started = std::time::Instant::now();
    let before = life.refuse_attempts.load(Ordering::SeqCst);
    std::thread::sleep(std::time::Duration::from_millis(100));
    // At most one retry per capped back-off (40 ms), plus one in
    // flight.
    let n = life.refuse_attempts.load(Ordering::SeqCst) - before;
    let budget = (started.elapsed().as_millis() / 40) as i64 + 1;
    assert!(
        n <= budget,
        "{n} retries in {:?}: the back-off is not applied",
        started.elapsed()
    );
}

#[test]
fn dispatcher_sweep_bounds_a_hanging_launcher() {
    let tr = Trace::default();
    let life = Arc::new(Lifecycle::new(&tr, vec![]));
    let mut cfg = dispatch_cfg();
    cfg.pause_retry = Duration::milliseconds(20);
    cfg.probe_budget = Duration::milliseconds(20);
    let w = new_dispatch_world(None, life, cfg);
    let survivor = attempt_in(State::Ambiguous);
    w.st.put(
        survivor.clone(),
        LinkedStepAttemptState::Reconciliation,
        false,
    );
    w.launcher.set_alive(&survivor.sandbox_scope_id, true);
    w.launcher.hang.store(true, Ordering::SeqCst);
    w.start();
    wait_for("a launcher-unreachable pause", || {
        let s = w.disp.status();
        s.paused() && s.pause == PauseReason::LauncherUnreachable
    });
    wait_for("a second bounded sweep", || {
        w.launcher.alive_calls.load(Ordering::SeqCst) >= 2
    });
    w.launcher.hang.store(false, Ordering::SeqCst);
    wait_for("running after the sweep", || {
        w.disp.status().state == DispatcherState::Running
    });
    let kills = w.launcher.kills();
    assert!(
        kills.len() == 1 && kills[0] == survivor.sandbox_scope_id,
        "kills = {kills:?}"
    );
}

#[test]
fn dispatcher_surfaces_a_failed_settlement_and_never_redispatches_it() {
    let tr = Trace::default();
    let run = queued_run();
    let life = Arc::new(Lifecycle::new(&tr, vec![run.clone()]));
    life.set_relist_all(true); // relistingLifecycle
    let mut runner = ScriptedRunner::new(life.clone());
    runner.result = HarnessResult {
        outcome: Outcome::Failed,
        reason: FailureCode::BUDGET_COST,
        low_disk: false,
        settle_failed: true,
        err: Some(Failure::internal(
            "settle",
            "settle refused: IMMUTABLE_ATTEMPT",
        )),
    };
    let runner = Arc::new(runner);
    let w = new_dispatch_world(Some(runner.clone()), life, dispatch_cfg());
    w.start();
    wait_for("the settle-failed run to be recorded", || {
        w.disp.status().settle_failed.len() == 1
    });
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert_eq!(
        runner.calls.load(Ordering::SeqCst),
        1,
        "settle-failed run dispatched more than once"
    );
    let s = w.disp.status();
    assert!(
        s.settle_failed[0] == run.run_id && s.lost.is_empty() && s.needs_restart(),
        "status = {s:?}"
    );
    let out = w.log.all();
    assert!(
        out.contains("level=WARN")
            && out.contains("settlement not written")
            && out.contains("IMMUTABLE_ATTEMPT")
            && out.contains(&run.run_id.to_string())
            && out.contains("outcome=failed"),
        "log = {out}"
    );
}

#[test]
fn dispatcher_logs_the_error_of_any_outcome() {
    let tr = Trace::default();
    let run = queued_run();
    let life = Arc::new(Lifecycle::new(&tr, vec![run.clone()]));
    let mut runner = ScriptedRunner::new(life.clone());
    runner.result = HarnessResult {
        outcome: Outcome::Abandoned,
        reason: FailureCode::WORKSPACE_UNAVAILABLE,
        low_disk: false,
        settle_failed: false,
        err: Some(Failure::internal("resume", "source missing")),
    };
    let runner = Arc::new(runner);
    let w = new_dispatch_world(Some(runner.clone()), life, dispatch_cfg());
    w.start();
    wait_for("the run", || runner.calls.load(Ordering::SeqCst) == 1);
    wait_for("the warning", || {
        let out = w.log.all();
        out.contains("level=WARN")
            && out.contains("source missing")
            && out.contains("outcome=abandoned")
            && out.contains(&run.run_id.to_string())
    });
    assert!(
        !w.disp.status().needs_restart(),
        "status = {:?}",
        w.disp.status()
    );
}

// The lost set keeps at most 256 Runs, evicting the oldest.
#[test]
fn dispatcher_bounds_the_lost_set() {
    const RUNS: usize = 300;
    let tr = Trace::default();
    let all: Vec<DispatchableRun> = (0..RUNS).map(|_| queued_run()).collect();
    let life = Arc::new(Lifecycle::new(&tr, all));
    life.set_relist_all(true); // relistingLifecycle
    let mut runner = ScriptedRunner::new(life.clone());
    runner.result = HarnessResult {
        outcome: Outcome::Lost,
        reason: FailureCode::LEASE_LOST,
        low_disk: false,
        settle_failed: false,
        err: Some(Failure::conflict(codes::LEASE_LOST, "the lease was lost")),
    };
    let runner = Arc::new(runner);
    let mut cfg = dispatch_cfg();
    cfg.concurrency = super::dispatcher::MAX_CONCURRENCY;
    cfg.poll_interval = Duration::milliseconds(1);
    let w = new_dispatch_world(Some(runner.clone()), life, cfg);
    w.start();
    wait_for("every run to be lost once", || {
        assert!(
            w.disp.status().lost.len() <= 256,
            "lost set holds {} runs",
            w.disp.status().lost.len()
        );
        runner.calls.load(Ordering::SeqCst) >= RUNS as i64
    });
    assert_eq!(w.disp.status().lost.len(), 256, "lost set holds, want 256");
}

// Review minor 1: a start whose commit outcome is unknown may have
// left the Task running with nobody driving it. It is held lost, so
// NeedsRestart and the banner show it, and it is never re-dispatched.
#[test]
fn dispatcher_holds_a_start_with_an_unknown_outcome_as_lost() {
    let tr = Trace::default();
    let run = queued_run();
    let life = Arc::new(Lifecycle::new(&tr, vec![run.clone()]));
    life.set_relist_all(true); // relistingLifecycle
    life.set_start_err(Some(Failure::internal(
        codes::START_OUTCOME_UNKNOWN,
        "connection reset at commit",
    )));
    let w = new_dispatch_world(None, life.clone(), dispatch_cfg());
    let runner: Arc<dyn super::dispatcher::AttemptRunner> = Arc::new(
        Orchestrator::new(super::orchestrator::OrchestratorDeps {
            lifecycle: life.clone(),
            attempts: w.st.clone(),
            adapter: w.ad.clone(),
            workspaces: w.prov.clone(),
            capture: w.cap.clone(),
            artifacts: w.arts.clone(),
            clock: w.clock.clone(),
            ticker: w.ticker.clone(),
            cfg: {
                let mut c = default_cfg();
                c.adapter_version = "v".to_string();
                c.launch_env = test_env();
                c.events = Some(w.sink.clone());
                c
            },
        })
        .expect("NewOrchestrator"),
    );
    let d = super::dispatcher::Dispatcher::new(super::dispatcher::DispatcherDeps {
        lifecycle: life.clone(),
        runner,
        adapter: w.ad.clone(),
        launcher: w.launcher.clone(),
        recovery: w.st.clone(),
        workspaces: w.prov.clone(),
        events: w.sink.clone(),
        clock: w.clock.clone(),
        ticker: w.ticker.clone(),
        logger: w.log.clone(),
        cfg: dispatch_cfg(),
    })
    .expect("NewDispatcher");
    let d = Arc::new(d);
    let stop: Arc<dyn super::ports::CancelSignal> = w.stop.clone();
    let d2 = d.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(block_on(d2.run(stop)));
    });
    wait_for("the unknown start to be held lost", || {
        d.status().lost.len() == 1
    });
    std::thread::sleep(std::time::Duration::from_millis(50));
    let s = d.status();
    assert!(
        s.lost[0] == run.run_id && s.needs_restart(),
        "status = {s:?}"
    );
    assert_eq!(
        w.tr.count("lifecycle.Start"),
        1,
        "started more than once (never re-dispatched)"
    );
    assert_eq!(
        w.tr.count("provisioner.Provision") + w.tr.count("store.Create"),
        0,
        "worked on an unknown start: {:?}",
        w.tr.all()
    );
    w.stop.cancel();
    let _ = rx.recv_timeout(std::time::Duration::from_secs(10));
}
