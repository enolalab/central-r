//! The consumer-side ports of the harness control plane — the port of
//! `internal/harness/app/ports.go`. [`Orchestrator`](super::Orchestrator)
//! depends only on these traits plus the capability-owned
//! [`crate::port`] traits; `central-kernel` implements them over the
//! execution, task and artifact services (R3 task 13). All are
//! dyn-compatible via [`PortFuture`].
//!
//! Go `ctx` cancellation is modelled by the orchestrator's
//! [`CancelSignal`]/standing-arm select: a future dropped while racing is
//! the Go call returning `ctx.Err()`. Method arguments that upstream
//! passes by value (`run`, `d`) are owned here too, so the returned
//! future borrows only `&'a self`.

use std::collections::BTreeMap;
use std::fmt;

use central_foundation::failure::Failure;
use central_foundation::identity::{
    HarnessAttemptId, RunId, StepAttemptId, StepId, TaskId, WorkspaceId,
};
use time::{Duration, OffsetDateTime};

use crate::attempt::Attempt;
use crate::budget::Budget;
use crate::domain::{PermissionPolicy, Workspace, vocab};
use crate::port::{ExecutionLease, PortFuture};

/// `app.FailureCode` — a bounded Task/Run failure reason. The codes this
/// package produces are the consts on [`FailureCode`]; adapter
/// `Terminal.reason` values pass through unchanged, so the code wraps
/// `Cow<'static, str>` — never harness free text or prompt content.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FailureCode(std::borrow::Cow<'static, str>);

impl FailureCode {
    pub const EXECUTION_FAILED: Self = Self::new_const("execution_failed");
    pub const WORKSPACE_UNAVAILABLE: Self = Self::new_const("workspace_unavailable");
    pub const LAUNCH_FAILED: Self = Self::new_const("harness_launch_failed");
    pub const ABORTED: Self = Self::new_const("harness_aborted");
    pub const BUDGET: Self = Self::new_const("harness_budget");
    pub const MAX_TURNS: Self = Self::new_const("harness_max_turns");
    pub const PROTOCOL_ERROR: Self = Self::new_const("harness_protocol_error");
    pub const EXITED_WITHOUT_RESULT: Self = Self::new_const("harness_exited_without_result");
    pub const LEASE_LOST: Self = Self::new_const("harness_lease_lost");
    /// Harness phase 3b artifact-capture codes (3b decision 8).
    pub const ARTIFACT_CAPTURE_FAILED: Self = Self::new_const("artifact_capture_failed");
    pub const ARTIFACT_REJECTED: Self = Self::new_const("artifact_rejected");
    pub const ARTIFACT_TOO_LARGE: Self = Self::new_const("artifact_too_large");
    pub const ARTIFACT_QUOTA_EXCEEDED: Self = Self::new_const("artifact_quota_exceeded");
    pub const HARNESS_REPORT_MISSING: Self = Self::new_const("harness_report_missing");
    /// A bridged permission request could not be carried to or from the
    /// operator (harness phase 3c decision 10); the attempt fails closed.
    pub const PERMISSION_BRIDGE_UNAVAILABLE: Self =
        Self::new_const("permission_bridge_unavailable");
    /// Harness phase 3d budget codes (3d decision 7): the reason names
    /// the bound that stopped the Run.
    pub const BUDGET_COST: Self = Self::new_const("budget_cost");
    pub const BUDGET_WALL_CLOCK: Self = Self::new_const("budget_wall_clock");
    /// Central stopped the attempt at the serve-wide token ceiling
    /// (harness phase 3l decision 5).
    pub const BUDGET_TOKENS: Self = Self::new_const("budget_tokens");

    const fn new_const(s: &'static str) -> Self {
        Self(std::borrow::Cow::Borrowed(s))
    }

    /// A code carried through from an adapter reason.
    pub fn new(s: impl Into<String>) -> Self {
        Self(std::borrow::Cow::Owned(s.into()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Display for FailureCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<&'static str> for FailureCode {
    fn from(s: &'static str) -> Self {
        Self::new_const(s)
    }
}

impl From<String> for FailureCode {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

/// Stable machine codes standing in for the upstream `app.Err*`
/// sentinels — the `errors.Is` surface callers match on.
pub mod codes {
    /// `app.ErrLeaseLost` — the Run's execution lease is gone or fenced
    /// out; close the lifeline and stop writing (decision 10).
    pub const LEASE_LOST: &str = "harness_app_lease_lost";
    /// `app.ErrNotStartable` — a dispatchable Run could not be started;
    /// nothing was written.
    pub const NOT_STARTABLE: &str = "harness_app_not_startable";
    /// `app.ErrStartOutcomeUnknown` — the claim may have committed.
    pub const START_OUTCOME_UNKNOWN: &str = "harness_app_start_outcome_unknown";
    /// `app.ErrWorkspaceUnavailable` — the workspace could not be
    /// provisioned (missing/empty source, clone or ACL failure).
    pub const WORKSPACE_UNAVAILABLE: &str = "harness_app_workspace_unavailable";
    /// `app.ErrLowDisk` — free space below the configured minimum.
    pub const LOW_DISK: &str = "harness_app_low_disk";
    /// `app.ErrCancelRequested` — the Run's Task is cancelling; the call
    /// wrote nothing.
    pub const CANCEL_REQUESTED: &str = "harness_app_cancel_requested";
    /// `app.ErrCaptureFailed` — a git or I/O error, a sealing failure or
    /// the capture deadline.
    pub const CAPTURE_FAILED: &str = "harness_app_capture_failed";
    /// `app.ErrCaptureTooLarge` — a captured body exceeded its cap.
    pub const CAPTURE_TOO_LARGE: &str = "harness_app_capture_too_large";
    /// `app.ErrResumeUnavailable` — a resume has no usable source.
    pub const RESUME_UNAVAILABLE: &str = "harness_app_resume_unavailable";
    /// `errCaptureNotAttempted` — the launcher did not confirm the
    /// scope's exit; capture never ran (decision 8).
    pub const CAPTURE_NOT_ATTEMPTED: &str = "harness_app_capture_not_attempted";
    /// `errBridgeUnavailable` — the permission bridge failed; the
    /// attempt fails closed (decision 10).
    pub const BRIDGE_UNAVAILABLE: &str = "harness_app_bridge_unavailable";
    /// `errEventWriteBudget` — an event write kept failing for the whole
    /// event-write budget.
    pub const EVENT_WRITE_BUDGET: &str = "harness_app_event_write_budget";
    /// Internal: the attempt context ended (lease lost or serve stop),
    /// standing in for `ctx.Err()` of a dropped in-flight call.
    pub const ATTEMPT_ENDED: &str = "harness_app_attempt_ended";
}

vocab! {
    /// How one orchestration ended — upstream `app.Outcome`.
    Outcome {
        /// `not_started` — `RunLifecycle::start` claimed nothing.
        NotStarted => "not_started",
        /// `succeeded`.
        Succeeded => "succeeded",
        /// `failed`.
        Failed => "failed",
        /// `abandoned` — a pre-launch failure ended the Run through
        /// `abandon_prepared`.
        Abandoned => "abandoned",
        /// `lost` — the lease was lost, a write was fenced out, or the
        /// claim returned an invalid lease (decision 10).
        Lost => "lost",
        /// `stopped` — serve stopped; the lifeline was closed (decision 13).
        Stopped => "stopped",
        /// `cancelled` — the Task was asked to cancel (review T-I1).
        Cancelled => "cancelled",
        /// `reconciliation` — an Artifact outcome was ambiguous; the
        /// attempt went to B08 reconciliation (3b decision 8).
        Reconciliation => "reconciliation",
    }
}

vocab! {
    /// Why a Run is dispatchable — upstream `app.DispatchCase`.
    DispatchCase {
        /// `queued` — started with `RunLifecycle::start`'s fused claim.
        Queued => "queued",
        /// `prepared_successor` — a running Task whose current
        /// StepAttempt is a B08 prepared successor with no live lease.
        PreparedSuccessor => "prepared_successor",
    }
}

vocab! {
    /// The required role of one harness Artifact — upstream
    /// `app.ArtifactRole` (harness phase 3b decision 1).
    ArtifactRole {
        /// `harness.report` — the attempt's final assistant message.
        Report => "harness.report",
        /// `harness.patch` — the unified diff of the final clone.
        Patch => "harness.patch",
        /// `harness.commits` — before/after HEAD and the harness's commits.
        Commits => "harness.commits",
    }
}

vocab! {
    /// How one Artifact materialization ended — upstream
    /// `app.ArtifactOutcomeKind`.
    ArtifactOutcomeKind {
        /// `ready` — durably ready (for the report: Task and Run done).
        Ready => "ready",
        /// `retryable` — certainly not ready; the Run fails with `reason`.
        Retryable => "retryable",
        /// `terminal` — certainly not ready; the Run fails with `reason`.
        Terminal => "terminal",
        /// `reconciliation` — the finalize commit's outcome is unknown.
        Reconciliation => "reconciliation",
    }
}

vocab! {
    /// A harness milestone kind projected into the task event log —
    /// upstream `app.MilestoneKind` (decision 16).
    MilestoneKind {
        /// `harness.attempt_launched`.
        AttemptLaunched => "harness.attempt_launched",
        /// `harness.session_started`.
        SessionStarted => "harness.session_started",
        /// `harness.permission_denied`.
        PermissionDenied => "harness.permission_denied",
        /// `harness.retry`.
        Retry => "harness.retry",
        /// `harness.terminal`.
        Terminal => "harness.terminal",
        /// `harness.dispatch_paused`.
        DispatchPaused => "harness.dispatch_paused",
        /// `harness.dispatch_resumed`.
        DispatchResumed => "harness.dispatch_resumed",
        /// `harness.settle_failed` — replaces the terminal milestone
        /// when the settlement write could not be made.
        SettleFailed => "harness.settle_failed",
        /// `harness.artifacts_captured` — the Run's Artifacts are ready.
        ArtifactsCaptured => "harness.artifacts_captured",
        /// `harness.artifacts_partial` — a failed Run's capture or
        /// artifact store did not complete (decision 10).
        ArtifactsPartial => "harness.artifacts_partial",
        /// `harness.permission_requested` — a bridged request's
        /// approval was opened (3c decision 14); reason = tool name.
        PermissionRequested => "harness.permission_requested",
        /// `harness.permission_allowed` — a bridged request answered
        /// allow; reason = who answered.
        PermissionAllowed => "harness.permission_allowed",
    }
}

/// `app.MilestoneKinds` — every kind in declaration order.
#[must_use]
pub fn milestone_kinds() -> &'static [MilestoneKind] {
    MilestoneKind::ALL
}

/// `app.MilestoneReasonCancelled`/`MilestoneReasonReconciliation` — the
/// terminal-milestone reasons of a cancelled and a reconciled attempt.
pub const MILESTONE_REASON_CANCELLED: &str = "cancelled";
/// `app.MilestoneReasonReconciliation`.
pub const MILESTONE_REASON_RECONCILIATION: &str = "reconciliation";

/// One Run the dispatcher may start — upstream `app.DispatchableRun`.
/// `step_id`/`step_attempt_id` name the prepared successor for
/// [`DispatchCase::PreparedSuccessor`] and are nil for
/// [`DispatchCase::Queued`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchableRun {
    /// The dispatch case.
    pub case: DispatchCase,
    /// The owning workspace.
    pub workspace_id: WorkspaceId,
    /// The owning task.
    pub task_id: TaskId,
    /// The run to start.
    pub run_id: RunId,
    /// The prepared successor's step, if any.
    pub step_id: StepId,
    /// The prepared successor's step attempt, if any.
    pub step_attempt_id: StepAttemptId,
}

/// A Run whose execution lease this process holds — upstream
/// `app.ClaimedRun`. `prompt` is sensitive and never printed.
/// `permission` unset means [`PermissionPolicy::Deny`].
#[derive(Clone)]
pub struct ClaimedRun {
    /// The owning workspace.
    pub workspace_id: WorkspaceId,
    /// The owning task.
    pub task_id: TaskId,
    /// The run.
    pub run_id: RunId,
    /// The prepared StepAttempt's step.
    pub step_id: StepId,
    /// The prepared StepAttempt the harness attempt links to.
    pub step_attempt_id: StepAttemptId,
    /// The Task's instruction — sensitive, never printed.
    pub prompt: String,
    /// The Task's permission policy.
    pub permission: PermissionPolicy,
    /// The Run's effective budget resolved at claim; zero bounds take
    /// the orchestrator's defaults flagged as defaulted.
    pub budget: Budget,
    /// The held execution lease — the bearer is never printed.
    pub lease: ExecutionLease,
}

impl fmt::Display for ClaimedRun {
    /// Upstream `String`/`GoString`: never the prompt or the bearer.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "app.ClaimedRun{{Run:{} Attempt:{} Permission:{} Budget:{}microUSD/{}s Lease:{} Prompt:<redacted {} bytes>}}",
            self.run_id,
            self.step_attempt_id,
            self.permission,
            self.budget.cost_micro_usd,
            self.budget.wall_clock.whole_seconds(),
            self.lease,
            self.prompt.len()
        )
    }
}

impl fmt::Debug for ClaimedRun {
    /// `Debug`/`{:#?}` share `Display`'s redaction — the prompt is
    /// never printed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// The final outcome of a launched attempt — upstream `app.Settlement`.
/// `reason` is empty on success.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Settlement {
    /// Whether the attempt succeeded.
    pub succeeded: bool,
    /// The bounded failure reason.
    pub reason: FailureCode,
}

/// The bounded result of one Artifact materialization — upstream
/// `app.ArtifactOutcome`. `reason` is a retryable/terminal code.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ArtifactOutcome {
    /// The outcome kind.
    pub kind: ArtifactOutcomeKind,
    /// The bounded reason of a retryable/terminal outcome.
    pub reason: FailureCode,
}

/// One Run's captured work — upstream `app.Capture`: runtime-owned temp
/// paths (this package never opens files) and the after HEAD.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Capture {
    /// The patch body path.
    pub patch: String,
    /// The commits body path.
    pub commits: String,
    /// The after HEAD ("" when unavailable).
    pub after_head: String,
}

/// How a claimed attempt continues an earlier harness session — upstream
/// `app.ResumeFrom` (harness phase 3g).
#[derive(Clone)]
pub struct ResumeFrom {
    /// `resolved(resume)` — its `harness_session_id` and `workspace` are
    /// resumed.
    pub source: Attempt,
    /// The chain budget: root budget minus recorded chain cost.
    pub budget: Budget,
    /// The fixed continuation text — never Task or request input;
    /// never printed.
    pub prompt: String,
}

impl fmt::Debug for ResumeFrom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResumeFrom")
            .field("source", &self.source)
            .field("budget", &self.budget)
            .field(
                "prompt",
                &format_args!("<redacted {} bytes>", self.prompt.len()),
            )
            .finish()
    }
}

/// One bounded task event — upstream `app.Milestone`. `status`/`reason`
/// are fixed codes, never free text. `key` is unique per occurrence.
#[derive(Debug, Clone, PartialEq)]
pub struct Milestone {
    /// The idempotency key.
    pub key: String,
    /// The milestone kind.
    pub kind: MilestoneKind,
    /// The owning workspace.
    pub workspace_id: WorkspaceId,
    /// The owning task.
    pub task_id: TaskId,
    /// The owning run.
    pub run_id: RunId,
    /// The step attempt (nil for dispatcher milestones on a queued Task).
    pub step_attempt_id: StepAttemptId,
    /// A fixed status code (a terminal status, a pause state).
    pub status: String,
    /// A fixed reason code (a [`FailureCode`]), never free text.
    pub reason: String,
    /// When it happened — always a [`Clock`] timestamp.
    pub at: OffsetDateTime,
}

/// The report's size limit (decision 14): the Artifact class's default.
pub const MAX_REPORT_BYTES: usize = 1 << 20;

/// `app.DecidedByPolicyDeny` — the `decided_by` of the orchestrator's
/// automatic deny answer under the Deny policy.
pub const DECIDED_BY_POLICY_DENY: &str = "policy:deny";

/// The execution and task side of one harness attempt — upstream
/// `app.RunLifecycle`. The composition root implements it over the
/// execution application service. Lease-bound methods return
/// [`codes::LEASE_LOST`]; the write methods return
/// [`codes::CANCEL_REQUESTED`] (and write nothing) when the Task is
/// cancelling: only `settle_cancellation` may end such a Run.
pub trait RunLifecycle: Send + Sync + 'static {
    /// Upstream `ListDispatchable`: up to `limit` dispatchable Runs,
    /// oldest Task first.
    fn list_dispatchable<'a>(
        &'a self,
        limit: usize,
    ) -> PortFuture<'a, Result<Vec<DispatchableRun>, Failure>>;

    /// Upstream `Start`: claims `run` — [`codes::NOT_STARTABLE`] means
    /// nothing was claimed; [`codes::START_OUTCOME_UNKNOWN`] that the
    /// claim may have committed.
    fn start<'a>(&'a self, run: DispatchableRun) -> PortFuture<'a, Result<ClaimedRun, Failure>>;

    /// Upstream `Heartbeat`: extends the lease and reports whether the
    /// Task is cancelling.
    fn heartbeat<'a>(&'a self, run: ClaimedRun) -> PortFuture<'a, Result<bool, Failure>>;

    /// Upstream `MarkInvoked`: records that the harness is about to be
    /// launched; must precede [`crate::port::Adapter::start`].
    fn mark_invoked<'a>(&'a self, run: ClaimedRun) -> PortFuture<'a, Result<(), Failure>>;

    /// Upstream `AbandonPrepared`: fails a never-invoked attempt's Task
    /// and Run with `reason` and releases the lease.
    fn abandon_prepared<'a>(
        &'a self,
        run: ClaimedRun,
        reason: FailureCode,
    ) -> PortFuture<'a, Result<(), Failure>>;

    /// Upstream `RecordCompletion`: the execution completion receipt.
    fn record_completion<'a>(
        &'a self,
        run: ClaimedRun,
        outcome: Settlement,
    ) -> PortFuture<'a, Result<(), Failure>>;

    /// Upstream `Settle`: settles the invoked attempt and ends the Run
    /// and Task.
    fn settle<'a>(
        &'a self,
        run: ClaimedRun,
        outcome: Settlement,
    ) -> PortFuture<'a, Result<(), Failure>>;

    /// Upstream `SettleCancellation`: ends a cancelling Task and its
    /// Run cancelled and releases the lease.
    fn settle_cancellation<'a>(&'a self, run: ClaimedRun) -> PortFuture<'a, Result<(), Failure>>;

    /// Upstream `CompleteWithReport` — the only way a harness Run
    /// succeeds (3b decisions 2 and 8): materializes `report` as the
    /// Run's `harness.report` Artifact with the success settlement
    /// committed atomically. [`ArtifactOutcomeKind::Ready`] means the
    /// Task and Run are completed. Never retried in-process.
    fn complete_with_report<'a>(
        &'a self,
        run: ClaimedRun,
        report: Vec<u8>,
    ) -> PortFuture<'a, Result<ArtifactOutcome, Failure>>;

    /// Upstream `Reconcile`: moves the invoked attempt into B08
    /// reconciliation and releases the lease.
    fn reconcile<'a>(&'a self, run: ClaimedRun) -> PortFuture<'a, Result<(), Failure>>;
}

/// Stores the supporting Artifacts of a harness Run — upstream
/// `app.ArtifactSink` (decision 11). `body` is the runtime-owned temp
/// path [`crate::app::ports::WorkspaceCapture::capture`] wrote to;
/// never retried in-process. An error means the outcome is
/// unclassified.
pub trait ArtifactSink: Send + Sync + 'static {
    /// Upstream `Store`.
    fn store<'a>(
        &'a self,
        run: ClaimedRun,
        role: ArtifactRole,
        body: String,
    ) -> PortFuture<'a, Result<ArtifactOutcome, Failure>>;
}

/// Captures a Run's clone once no harness process of the attempt is
/// left — upstream `app.WorkspaceCapture` (decisions 4–6).
pub trait WorkspaceCapture: Send + Sync + 'static {
    /// Upstream `Capture`: seals the Run, then writes the patch and
    /// commits bodies without running harness-controlled config.
    fn capture<'a>(
        &'a self,
        ws: WorkspaceId,
        workspace: Workspace,
        run: RunId,
    ) -> PortFuture<'a, Result<Capture, Failure>>;

    /// Upstream `Release`: removes the Run's capture files; idempotent.
    fn release<'a>(&'a self, run: RunId) -> PortFuture<'a, Result<(), Failure>>;
}

/// Creates the per-Run clone — upstream `app.WorkspaceProvisioner`
/// (decisions 5, 6, 14).
pub trait WorkspaceProvisioner: Send + Sync + 'static {
    /// Upstream `CheckFreeSpace`: [`codes::LOW_DISK`] when free space at
    /// the data root is below the configured minimum.
    fn check_free_space<'a>(&'a self) -> PortFuture<'a, Result<(), Failure>>;

    /// Upstream `Provision`: clones the workspace's source for `run`;
    /// failures wrap [`codes::WORKSPACE_UNAVAILABLE`].
    fn provision<'a>(
        &'a self,
        ws: WorkspaceId,
        run: RunId,
    ) -> PortFuture<'a, Result<Workspace, Failure>>;

    /// Upstream `Reopen`: checks that `run`'s existing clone is still
    /// usable at `want`, for a resumed attempt that must not
    /// `provision`.
    fn reopen<'a>(
        &'a self,
        ws: WorkspaceId,
        run: RunId,
        want: Workspace,
    ) -> PortFuture<'a, Result<(), Failure>>;
}

/// Whether a claimed attempt continues an earlier session — upstream
/// `app.ResumeSource` (3g decision 5). Keyed on the claimed
/// StepAttempt, never the Run's latest harness row. `Ok(None)` starts a
/// fresh session. [`crate::domain::codes::CHAIN_BUDGET_EXHAUSTED`]
/// abandons the Run `budget_cost`; any other error
/// `execution_failed`.
pub trait ResumeSource: Send + Sync + 'static {
    /// Upstream `ResumeFrom`.
    fn resume_from<'a>(
        &'a self,
        run: ClaimedRun,
    ) -> PortFuture<'a, Result<Option<ResumeFrom>, Failure>>;
}

/// Appends milestones to the task event log — upstream
/// `app.TaskEventSink`. Appends are best-effort: a failure is logged
/// and never fails the attempt.
pub trait TaskEventSink: Send + Sync + 'static {
    /// Upstream `Record`.
    fn record<'a>(&'a self, m: Milestone) -> PortFuture<'a, Result<(), Failure>>;
}

/// The store surface the operator resolve action needs — upstream
/// `app.ResolveStore`.
pub trait ResolveStore: Send + Sync + 'static {
    /// Upstream `Load`.
    fn load<'a>(
        &'a self,
        ws: WorkspaceId,
        id: HarnessAttemptId,
    ) -> PortFuture<'a, Result<Attempt, Failure>>;

    /// Upstream `RecoverAttempt`: writes the resolution under the
    /// recovery authority.
    fn recover_attempt<'a>(
        &'a self,
        expected: &'a Attempt,
        next: &'a Attempt,
    ) -> PortFuture<'a, Result<Attempt, Failure>>;
}

/// Supplies timestamps for attempt writes and milestones — upstream
/// `app.Clock`.
pub trait Clock: Send + Sync + 'static {
    /// Upstream `Now`.
    fn now(&self) -> OffsetDateTime;
}

/// A one-shot timer — the Rust form of the upstream's
/// `time.NewTimer`/`time.NewTicker` uses. `after(d)` resolves once,
/// `d` later, in wall-clock terms. Re-armed per use; a dropped future
/// is the stopped timer.
pub trait Ticker: Send + Sync + 'static {
    /// Resolves once `d` has elapsed.
    fn after<'a>(&'a self, d: Duration) -> PortFuture<'a, ()>;
}

/// The serve-stop (and lease-loss) wake-up — the Rust form of the
/// upstream's `ctx.Done()`. `cancelled()` resolves when the stop is
/// requested; a future that is dropped is the cancelled Go call.
pub trait CancelSignal: Send + Sync + 'static {
    /// Resolves when the stop is requested.
    fn cancelled(&self) -> PortFuture<'_, ()>;

    /// Whether the stop was already requested — upstream `ctx.Err() != nil`.
    fn is_cancelled(&self) -> bool;
}

/// A [`CancelSignal`] that is never cancelled — `context.Background()`.
#[derive(Debug, Default)]
pub struct NeverCancelled;

impl CancelSignal for NeverCancelled {
    fn cancelled(&self) -> PortFuture<'_, ()> {
        Box::pin(std::future::pending())
    }

    fn is_cancelled(&self) -> bool {
        false
    }
}

/// A real-clock [`Ticker`] for tests and the kernel's std executor
/// (sleeps on a thread; the delay survives in wall-clock terms).
#[derive(Debug, Default)]
pub struct RealTicker;

/// One `after` timer's shared state: the sleeping thread marks `done`
/// and wakes the registered waker.
#[derive(Debug, Default)]
struct TimerState {
    done: std::sync::atomic::AtomicBool,
    waker: std::sync::Mutex<Option<std::task::Waker>>,
}

impl Ticker for RealTicker {
    fn after<'a>(&'a self, d: Duration) -> PortFuture<'a, ()> {
        let millis = d.whole_milliseconds().max(0) as u64;
        let state = std::sync::Arc::new(TimerState::default());
        let state2 = std::sync::Arc::clone(&state);
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(millis));
            state2.done.store(true, std::sync::atomic::Ordering::SeqCst);
            if let Ok(mut g) = state2.waker.lock()
                && let Some(w) = g.take()
            {
                w.wake();
            }
        });
        Box::pin(async move {
            std::future::poll_fn(move |cx| {
                if state.done.load(std::sync::atomic::Ordering::SeqCst) {
                    return std::task::Poll::Ready(());
                }
                if let Ok(mut g) = state.waker.lock() {
                    *g = Some(cx.waker().clone());
                }
                std::task::Poll::Pending
            })
            .await
        })
    }
}

/// `app.Result` — reports one orchestration.
#[derive(Debug)]
pub struct HarnessResult {
    /// How the orchestration ended.
    pub outcome: Outcome,
    /// The bounded failure code of a failed/abandoned Run.
    pub reason: FailureCode,
    /// Free space was below the minimum at provisioning time.
    pub low_disk: bool,
    /// The Run's settlement failed permanently or after retries: the
    /// outcome is the intended one, `err` the write's error; the Task
    /// stays running until the next start reconciles it.
    pub settle_failed: bool,
    /// The diagnostic error (never printed into other errors).
    pub err: Option<Failure>,
}

impl HarnessResult {
    /// Shorthand for a result carrying only `err`.
    pub fn bare(outcome: Outcome, err: Option<Failure>) -> Self {
        Self {
            outcome,
            reason: FailureCode::default(),
            low_disk: false,
            settle_failed: false,
            err,
        }
    }
}

/// A [`LaunchEnv`](crate::port::LaunchEnv) built from a plain map —
/// upstream's `cfg.LaunchEnv map[string]string`.
pub fn launch_env(
    vars: BTreeMap<String, String>,
    sandbox_scope_id: String,
) -> crate::port::LaunchEnv {
    crate::port::LaunchEnv {
        vars,
        sandbox_scope_id,
    }
}
