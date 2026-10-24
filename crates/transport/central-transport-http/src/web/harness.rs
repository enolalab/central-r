//! The OPTIONAL harness operator surface (upstream `harness.go`). A
//! missing `HarnessOperator` renders no banner and no resolve form, and
//! the resolve/resume/permission routes answer 404.

use std::fmt;

use central_foundation::failure::Failure;
use central_foundation::identity::{HarnessPermissionApprovalId, RunId, TaskId, WorkspaceId};
use central_task::domain::{TaskStatus, WaitingReason};
use time::OffsetDateTime;

use crate::ports::BoxFuture;

// ---------------------------------------------------------------------------
// DTOs (upstream web.Harness* types — defined in the transport layer
// exactly like upstream's web package)
// ---------------------------------------------------------------------------

/// `HarnessBanner` — what every `/app` page shows about harness
/// execution: the paused dispatcher's (or restart-needed) notice, and
/// the Workspace's pending permission requests.
#[derive(Debug, Clone, Default)]
pub struct HarnessBanner {
    /// The notice text, or `""`.
    pub notice: String,
    /// Pending permission request count.
    pub pending_permissions: i32,
    /// The Task of the oldest pending request.
    pub oldest_permission_task_id: Option<TaskId>,
}

/// `HarnessPermissionPanel` — a harness Run's pending permission
/// request. `input` and `resources` come from serve memory only;
/// `allowable` is whether this process holds them — the only case an
/// Allow is offered.
#[derive(Clone)]
pub struct HarnessPermissionPanel {
    /// The approval id the decision form posts back.
    pub approval_id: HarnessPermissionApprovalId,
    /// The requesting tool's name.
    pub tool_name: String,
    /// The requesting tool call's id.
    pub tool_call_id: String,
    /// The resources the tool wants.
    pub resources: Vec<String>,
    /// The tool input the operator must see before deciding.
    pub input: Vec<u8>,
    /// The bridged input's byte size.
    pub input_size: i64,
    /// The hex MAC the decision form posts back.
    pub input_mac: String,
    /// When the request was raised.
    pub requested_at: OffsetDateTime,
    /// When it expires.
    pub expires_at: OffsetDateTime,
    /// Whether this process can deliver an answer.
    pub allowable: bool,
}

impl fmt::Debug for HarnessPermissionPanel {
    /// Never prints the input or the resources: both come from the
    /// harness and may hold a secret.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HarnessPermissionPanel")
            .field("approval_id", &self.approval_id)
            .field("tool_name", &self.tool_name)
            .field(
                "input",
                &format_args!("<redacted {} bytes>", self.input.len()),
            )
            .field(
                "resources",
                &format_args!("<redacted {}>", self.resources.len()),
            )
            .field("allowable", &self.allowable)
            .finish()
    }
}

/// `HarnessPermissionRecord` — one row of a Run's permission history.
#[derive(Debug, Clone)]
pub struct HarnessPermissionRecord {
    /// The tool name.
    pub tool_name: String,
    /// The recorded outcome.
    pub outcome: String,
    /// Who decided.
    pub decided_by: String,
    /// When the request was raised.
    pub requested_at: OffsetDateTime,
    /// When it was decided (epoch = undecided).
    pub decided_at: OffsetDateTime,
}

/// `HarnessPermissionDecision` — the operator's answer to one pending
/// request. `principal` is the validated session's principal, never a
/// form field.
#[derive(Debug, Clone)]
pub struct HarnessPermissionDecision {
    /// The workspace scope.
    pub workspace_id: WorkspaceId,
    /// The task owning the run.
    pub task_id: TaskId,
    /// The approval being answered.
    pub approval_id: HarnessPermissionApprovalId,
    /// The posted hex MAC.
    pub input_mac: String,
    /// Allow (`true`) or deny (`false`).
    pub allow: bool,
    /// The validated session principal.
    pub principal: String,
}

/// `HarnessResolveRequest` — the authenticated operator session's facts.
/// `expected_run_version` is the Run's version from the same aggregate
/// load this request's `run_id` came from.
#[derive(Debug, Clone)]
pub struct HarnessResolveRequest {
    /// The workspace scope.
    pub workspace_id: WorkspaceId,
    /// The task.
    pub task_id: TaskId,
    /// Its current run.
    pub run_id: RunId,
    /// The run version the page loaded.
    pub expected_run_version: i64,
    /// The validated session principal.
    pub principal: String,
}

/// `HarnessRetryState` — a Task's recorded harness cost against the
/// Task cost cap; a zero `cap_micro_usd` gates nothing.
#[derive(Debug, Clone, Default)]
pub struct HarnessRetryState {
    /// Recorded cost of every Run of the task.
    pub used_micro_usd: i64,
    /// The serve-wide cap.
    pub cap_micro_usd: i64,
    /// Whether less than US$0.01 remains.
    pub blocked: bool,
}

/// `HarnessBudgetDefaults` — serve's default Run budget bounds, the
/// submit form's placeholders.
#[derive(Debug, Clone, Default)]
pub struct HarnessBudgetDefaults {
    /// The default cost bound.
    pub cost_micro_usd: i64,
    /// The default wall clock.
    pub wall_clock: std::time::Duration,
}

/// `HarnessRunBudget` — what task detail shows of a harness Run's
/// budget and scope-normalized reported usage.
#[derive(Debug, Clone, Default)]
pub struct HarnessRunBudget {
    /// The recorded cost limit.
    pub cost_micro_usd: i64,
    /// The recorded wall-clock bound, in seconds.
    pub wall_clock_seconds: i64,
    /// Whether the cost was inherited from the serve default.
    pub cost_defaulted: bool,
    /// Whether the wall clock was inherited.
    pub wall_clock_defaulted: bool,
    /// Whether the harness reported usage.
    pub usage_reported: bool,
    /// Billed input tokens.
    pub tokens_in: i64,
    /// Billed output tokens.
    pub tokens_out: i64,
    /// Cache reads.
    pub cache_read: i64,
    /// Cache writes.
    pub cache_write: i64,
    /// The reported cost.
    pub cost_used_micro_usd: i64,
    /// Whether the cost is the harness's estimate.
    pub estimated: bool,
    /// Whether the attempt succeeded (marks a success over its limit).
    pub succeeded: bool,
    /// The number of the Run's harness attempts the usage sums.
    pub attempts: i32,
    /// Whether the cost and cache counters are real (not a live `0`).
    pub cost_reported: bool,
    /// Whether the latest attempt ended.
    pub ended: bool,
}

/// `HarnessResumeBlock` — the one obstacle that keeps Resume
/// unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HarnessResumeBlock {
    /// The attempt ceiling.
    AttemptLimit,
    /// The budget.
    BudgetUsedUp,
    /// The eligibility floor (`CENTRAL_HARNESS_ELIGIBLE_AFTER`).
    NotEligible,
    /// No obstacle named (the zero value).
    #[default]
    None,
}

/// `HarnessResumeState` — eligible, or the one obstacle.
#[derive(Debug, Clone, Default)]
pub struct HarnessResumeState {
    /// Whether Resume is offered.
    pub eligible: bool,
    /// The obstacle when not eligible.
    pub blocked: HarnessResumeBlock,
}

// ---------------------------------------------------------------------------
// Error sentinels — upstream `ErrHarness*`; carried inside `Failure`
// via their stable codes so the handler's matching stays typed.
// ---------------------------------------------------------------------------

/// `ErrHarnessNotResolvable` — the Task no longer waits on the operator.
pub const ERR_HARNESS_NOT_RESOLVABLE: &str = "HARNESS_NOT_RESOLVABLE";
/// `ErrHarnessStarting` — a live lease holds the attempt (retryable).
pub const ERR_HARNESS_STARTING: &str = "HARNESS_STARTING";
/// `ErrHarnessPermissionNotPending` — the decision no longer applies.
pub const ERR_HARNESS_PERMISSION_NOT_PENDING: &str = "HARNESS_PERMISSION_NOT_PENDING";

/// Whether `f` carries the harness sentinel `code`.
#[must_use]
pub fn failure_is(f: &Failure, code: &str) -> bool {
    f.code() == code
}

// ---------------------------------------------------------------------------
// The operator surface port (upstream `web.HarnessOperator`)
// ---------------------------------------------------------------------------

/// `HarnessOperator` — the OPTIONAL operator surface of harness
/// execution. Implementations live outside the transport crate; the
/// web state holds `Option<Arc<dyn HarnessOperator>>`. Boxed futures
/// keep the trait dyn-compatible like every other `/app` port.
pub trait HarnessOperator: Send + Sync + 'static {
    /// `Banner` — the notice plus pending-permission facts every `/app`
    /// page of `workspace_id` shows.
    fn banner(&self, workspace_id: WorkspaceId) -> BoxFuture<'_, HarnessBanner>;
    /// `Resolvable` — whether the run's harness attempt waits on the
    /// operator.
    fn resolvable(
        &self,
        workspace_id: WorkspaceId,
        task_id: TaskId,
        run_id: RunId,
    ) -> BoxFuture<'_, Result<bool, Failure>>;
    /// `ResolveFailed` — "Mark failed (operator resolved)".
    fn resolve_failed(&self, req: HarnessResolveRequest) -> BoxFuture<'_, Result<(), Failure>>;
    /// `ResolveCancelled` — "Mark cancelled (operator resolved)".
    fn resolve_cancelled(&self, req: HarnessResolveRequest) -> BoxFuture<'_, Result<(), Failure>>;
    /// `PreparedSettleable` — whether "Finish cancelling" applies to a
    /// never-invoked harness attempt.
    fn prepared_settleable(
        &self,
        workspace_id: WorkspaceId,
        task_id: TaskId,
        run_id: RunId,
    ) -> BoxFuture<'_, Result<bool, Failure>>;
    /// `SettlePrepared` — "Finish cancelling" on such a run.
    fn settle_prepared(&self, req: HarnessResolveRequest) -> BoxFuture<'_, Result<(), Failure>>;
    /// `ResumeState` — the page predicate of Resume (UX gating only).
    fn resume_state(
        &self,
        workspace_id: WorkspaceId,
        task_id: TaskId,
        run_id: RunId,
    ) -> BoxFuture<'_, Result<HarnessResumeState, Failure>>;
    /// `Resume` — "Resume" on an ambiguous attempt.
    fn resume(&self, req: HarnessResolveRequest) -> BoxFuture<'_, Result<(), Failure>>;
    /// `RerunOffered` — the page predicate of "Mark failed and rerun".
    fn rerun_offered(
        &self,
        workspace_id: WorkspaceId,
        task_id: TaskId,
        run_id: RunId,
    ) -> BoxFuture<'_, Result<bool, Failure>>;
    /// `ResolveRerun` — "Mark failed and rerun (operator resolved)".
    fn resolve_rerun(&self, req: HarnessResolveRequest) -> BoxFuture<'_, Result<(), Failure>>;
    /// `PermissionPanel` — the pending permission request of the run.
    fn permission_panel(
        &self,
        workspace_id: WorkspaceId,
        task_id: TaskId,
        run_id: RunId,
    ) -> BoxFuture<'_, Result<Option<HarnessPermissionPanel>, Failure>>;
    /// `PermissionHistory` — the run's requests, newest first, ≤20.
    fn permission_history(
        &self,
        workspace_id: WorkspaceId,
        run_id: RunId,
    ) -> BoxFuture<'_, Result<Vec<HarnessPermissionRecord>, Failure>>;
    /// `DecidePermission` — answers one pending request.
    fn decide_permission(
        &self,
        req: HarnessPermissionDecision,
    ) -> BoxFuture<'_, Result<(), Failure>>;
    /// `RetryState` — the Retry gate of the Task cost cap.
    fn retry_state(
        &self,
        workspace_id: WorkspaceId,
        task_id: TaskId,
    ) -> BoxFuture<'_, Result<HarnessRetryState, Failure>>;
    /// `RunBudget` — the budget a harness Run ran under, or `None`.
    fn run_budget(
        &self,
        workspace_id: WorkspaceId,
        run_id: RunId,
    ) -> BoxFuture<'_, Result<Option<HarnessRunBudget>, Failure>>;
    /// `PermissionPoliciesEnabled` — whether a Task may be submitted
    /// with a policy other than deny.
    fn permission_policies_enabled(&self) -> bool;
    /// `HarnessBackend` — the configured backend id; always set.
    fn harness_backend(&self) -> &'static str;
    /// `BudgetDefaults` — serve's default Run budget bounds.
    fn budget_defaults(&self) -> HarnessBudgetDefaults;
}

// ---------------------------------------------------------------------------
// Views (upstream harnessBannerView / harnessResolveView)
// ---------------------------------------------------------------------------

/// `harnessBannerView` — the banner every `/app` page renders.
#[derive(Debug, Clone, Default)]
pub struct HarnessBannerView {
    /// The paused dispatcher's (or restart-needed) notice.
    pub notice: String,
    /// The pending permission count shown.
    pub pending_permissions: i32,
    /// The oldest pending request's Task id.
    pub task_id: String,
}

impl HarnessBannerView {
    /// `newHarnessBannerView` — counts only render with a task to link.
    #[must_use]
    pub fn new(b: HarnessBanner) -> Self {
        let mut v = Self {
            notice: b.notice,
            ..Self::default()
        };
        if b.pending_permissions > 0
            && let Some(id) = b.oldest_permission_task_id
            && !id.is_nil()
        {
            v.pending_permissions = b.pending_permissions;
            v.task_id = id.to_string();
        }
        v
    }
}

/// `harnessResolveView` — what the detail page's resolve panel offers,
/// derived from the durable Task status alone before the attempt is
/// checked.
#[derive(Debug, Clone, Default)]
pub struct HarnessResolveView {
    /// Offer "Mark failed (operator resolved)".
    pub mark_failed: bool,
    /// Offer "Mark cancelled (operator resolved)".
    pub mark_cancelled: bool,
    /// Whether the settling copy renders.
    pub settling: bool,
    /// Offer Resume.
    pub resume: bool,
    /// The one reason Resume is unavailable.
    pub resume_unavailable: &'static str,
    /// Offer "Mark failed and rerun (operator resolved)".
    pub rerun: bool,
}

impl HarnessResolveView {
    /// `Offered` — whether the panel renders.
    #[must_use]
    pub const fn offered(&self) -> bool {
        self.mark_failed || self.mark_cancelled
    }
}

/// `resolveActions` — what `status` offers before the attempt is
/// checked: a cancelling Task only "Mark cancelled"; a Task waiting on
/// reconciliation both buttons.
#[must_use]
pub fn resolve_actions(status: TaskStatus, reason: Option<WaitingReason>) -> HarnessResolveView {
    if status == TaskStatus::Cancelling {
        return HarnessResolveView {
            mark_cancelled: true,
            settling: true,
            ..HarnessResolveView::default()
        };
    }
    if status == TaskStatus::Waiting && reason == Some(WaitingReason::Reconciliation) {
        return HarnessResolveView {
            mark_failed: true,
            mark_cancelled: true,
            ..HarnessResolveView::default()
        };
    }
    HarnessResolveView::default()
}

/// `resumeUnavailableText` — a Resume obstacle to its page text; an
/// unknown block shows nothing.
#[must_use]
pub fn resume_unavailable_text(block: HarnessResumeBlock) -> &'static str {
    match block {
        HarnessResumeBlock::AttemptLimit => "Resume is unavailable: attempt limit reached",
        HarnessResumeBlock::BudgetUsedUp => "Resume is unavailable: budget used up",
        HarnessResumeBlock::NotEligible => {
            "Resume is unavailable: this Task was created before harness execution was enabled"
        }
        HarnessResumeBlock::None => "",
    }
}

/// `harnessStartingMsg` — the retryable 409 of "Finish cancelling"
/// while a live lease holds the never-invoked attempt.
pub const HARNESS_STARTING_MSG: &str = "The harness is still starting. Try again in a moment.";
