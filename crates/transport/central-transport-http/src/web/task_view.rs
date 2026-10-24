//! Task view models — the pure projections upstream `task_view.go`
//! computes for the `tasks_list` and `tasks_detail` templates. Every label
//! and eligibility flag is derived from the real domain status, never from
//! a coarser display label.

use central_execution::domain::AttemptState;
use central_task::domain::{PermissionPolicy, RunStatus, TaskStatus};
use central_task::query::{ArtifactRef, RunSummary};

use super::activity_view::ActivityRow;
use super::budget_view::RunBudgetView;
use super::format_timestamp;
use super::harness::HarnessBannerView;
use super::harness::HarnessResolveView;
use super::permission_view::{PermissionHistoryRow, PermissionPanelView};

/// `taskStatusLabel` — the seven B11 view labels; an unrecognised status
/// fails closed to a visible, non-actionable `Unsuccessful`, never a
/// silent blank.
#[must_use]
pub fn task_status_label(status: TaskStatus) -> &'static str {
    match status {
        TaskStatus::Queued => "Queued",
        TaskStatus::Running => "Running",
        TaskStatus::Waiting => "Waiting",
        TaskStatus::Cancelling => "Settling",
        TaskStatus::Failed | TaskStatus::Cancelled => "Unsuccessful",
        TaskStatus::Completed => "Completed",
        _ => "Unsuccessful",
    }
}

/// `taskCancelEligible` — mirrors `request_cancellation`'s own status
/// switch exactly (queued/running/waiting), so the rendered form's
/// visibility can never drift from what the domain accepts.
#[must_use]
pub fn task_cancel_eligible(status: TaskStatus) -> bool {
    matches!(
        status,
        TaskStatus::Queued | TaskStatus::Running | TaskStatus::Waiting
    )
}

/// `taskRetryEligible` — failed only; `TaskStatus::Cancelled` shares the
/// `Unsuccessful` label but must never show Retry (rerun is its route).
#[must_use]
pub fn task_retry_eligible(status: TaskStatus) -> bool {
    status == TaskStatus::Failed
}

/// `taskRerunEligible` — cancelled only; same deliberate label
/// independence as [`task_retry_eligible`].
#[must_use]
pub fn task_rerun_eligible(status: TaskStatus) -> bool {
    status == TaskStatus::Cancelled
}

/// `initialPollIntervalMS` — the starting poll interval for the rendered
/// label: in-flight labels poll fast; backoff lives client-side in
/// `tasks_poll.js`.
#[must_use]
pub fn initial_poll_interval_ms(label: &str) -> &'static str {
    match label {
        "Running" | "Settling" => "2000",
        _ => "10000",
    }
}

/// `runStatusLabel` — the run-level vocabulary verbatim (a task's single
/// `Unsuccessful` hides whether the attempt failed or was cancelled).
/// An unrecognised status never renders blank.
#[must_use]
pub fn run_status_label(status: RunStatus) -> String {
    match status {
        RunStatus::Queued => "Queued".to_string(),
        RunStatus::Running => "Running".to_string(),
        RunStatus::Waiting => "Waiting".to_string(),
        RunStatus::Cancelling => "Cancelling".to_string(),
        RunStatus::Succeeded => "Succeeded".to_string(),
        RunStatus::Failed => "Failed".to_string(),
        RunStatus::Cancelled => "Cancelled".to_string(),
        other => format!("Unknown ({})", other.as_str()),
    }
}

/// One attempt in the task-detail run timeline.
#[derive(Debug, Clone)]
pub struct RunHistoryRow {
    /// The run's index within the task.
    pub index: i64,
    /// Human status label.
    pub status: String,
    /// The most specific reason available (failure, else wait phrase).
    pub reason: String,
    /// When the attempt started.
    pub started: String,
}

/// `buildRunHistory` — display rows for the detail timeline, preserving
/// store order. A failure reason outranks the waiting phrase; an empty
/// input yields no section.
#[must_use]
pub fn build_run_history(runs: &[RunSummary]) -> Vec<RunHistoryRow> {
    runs.iter()
        .map(|run| RunHistoryRow {
            index: run.index,
            status: run_status_label(run.status),
            reason: if run.failure_reason.is_empty() {
                run.waiting_reason.as_ref().map_or_else(String::new, |r| {
                    super::overview_view::waiting_reason_phrase(Some(*r))
                })
            } else {
                run.failure_reason.clone()
            },
            started: format_timestamp(run.created_at),
        })
        .collect()
}

/// One provider turn rendered on the detail page — the Rust projection
/// carries step attempts rather than upstream's `RunTurnActivity` turn
/// rows, so the attempt's state and timestamps are the displayed facts.
#[derive(Debug, Clone)]
pub struct TurnActivityRow {
    /// 1-based sequence in the page.
    pub index: usize,
    /// Human state label.
    pub state: String,
    /// When the attempt started.
    pub started: String,
    /// When the attempt last reported (terminal/ambiguous only).
    pub responded: String,
}

/// `runTurnStateLabel` — a visible, non-blank label for a step-attempt
/// state (upstream's provider-turn label mapped onto the Rust
/// projection's `AttemptState` vocabulary).
#[must_use]
pub fn turn_state_label(state: AttemptState) -> &'static str {
    match state {
        AttemptState::AttemptPrepared => "Preparing",
        AttemptState::AttemptInvoked => "Calling provider",
        AttemptState::AttemptSettling => "Running tools",
        AttemptState::AttemptReconciliation => "Reconciling",
        AttemptState::AttemptSucceeded => "Succeeded",
        AttemptState::AttemptFailed => "Failed",
        AttemptState::AttemptCancelled => "Cancelled",
    }
}

/// `buildTurnActivity` — oldest-first display rows from the bounded turn
/// page. `responded` mirrors upstream's `RespondedAt`: the Rust
/// projection's closest durable fact is `updated_at`, shown once the
/// attempt has moved past its invoke window.
#[must_use]
pub fn build_turn_activity(
    projection: &central_execution::query::RunTurnActivityResult,
) -> Vec<TurnActivityRow> {
    projection
        .activities
        .iter()
        .enumerate()
        .map(|(i, t)| TurnActivityRow {
            index: i + 1,
            state: turn_state_label(t.attempt.state).to_string(),
            started: format_timestamp(t.attempt.created_at),
            responded: match t.attempt.state {
                AttemptState::AttemptPrepared | AttemptState::AttemptInvoked => String::new(),
                _ => format_timestamp(t.attempt.updated_at),
            },
        })
        .collect()
}

/// One ready Artifact row of the detail page: a fixed label for the
/// role (never the stored role text), verified size, and the id the
/// preview/download links carry.
#[derive(Debug, Clone)]
pub struct TaskArtifactRow {
    /// The artifact id (opaque UUID text).
    pub id: String,
    /// The fixed role label.
    pub label: &'static str,
    /// Human size.
    pub size: String,
}

/// `artifactRoleLabel` — the fixed label of an Artifact role.
#[must_use]
pub fn artifact_role_label(role: &str) -> &'static str {
    match role {
        "harness.report" => "Report",
        "harness.patch" => "Patch",
        "harness.commits" => "Commits",
        _ => "Artifact",
    }
}

/// `formatArtifactSize` — B, KiB, or MiB.
#[must_use]
pub fn format_artifact_size(n: i64) -> String {
    if n < 1 << 10 {
        format!("{n} B")
    } else if n < 1 << 20 {
        format!("{:.1} KiB", n as f64 / 1024.0)
    } else {
        format!("{:.1} MiB", n as f64 / 1_048_576.0)
    }
}

/// `buildArtifactRows` — nil-id refs are skipped defensively.
#[must_use]
pub fn build_artifact_rows(refs: &[ArtifactRef]) -> Vec<TaskArtifactRow> {
    refs.iter()
        .filter(|r| !r.id.is_nil())
        .map(|r| TaskArtifactRow {
            id: r.id.to_string(),
            label: artifact_role_label(&r.role),
            size: format_artifact_size(r.verified_size),
        })
        .collect()
}

// Harness phase 3e decision 13: the notices of an operator action that
// lost to a concurrent transition — a fixed code in the query, never text.
/// The detail page's notice query parameter.
pub const ACTION_NOTICE_QUERY: &str = "notice";
/// Cancel lost the dispatcher claim race.
pub const ACTION_NOTICE_CANCEL_LOST_CLAIM: &str = "cancel_started";
/// The task was already cancelled.
pub const ACTION_NOTICE_ALREADY_CANCELLED: &str = "already_cancelled";

/// "The Task started. Press Cancel again."
pub const CANCEL_LOST_CLAIM_MSG: &str = "The Task started. Press Cancel again.";
/// "Already cancelled."
pub const ALREADY_CANCELLED_MSG: &str = "Already cancelled.";

/// `actionNoticeText` — a notice code to its text; unknown shows nothing.
#[must_use]
pub fn action_notice_text(code: &str) -> &'static str {
    match code {
        ACTION_NOTICE_CANCEL_LOST_CLAIM => CANCEL_LOST_CLAIM_MSG,
        ACTION_NOTICE_ALREADY_CANCELLED => ALREADY_CANCELLED_MSG,
        _ => "",
    }
}

/// `permissionPolicyLabel` — the detail page's name for a Task policy.
#[must_use]
pub fn permission_policy_label(policy: PermissionPolicy) -> &'static str {
    match policy {
        PermissionPolicy::Bridge => "Bridge: the operator answers each tool permission request",
        PermissionPolicy::AutoAllow => "Auto-allow",
        _ => "Deny: every tool permission request is denied",
    }
}

// ---------------------------------------------------------------------------
// Task list view model + template
// ---------------------------------------------------------------------------

/// One rendered row in the task list.
#[derive(Debug, Clone)]
pub struct TaskRow {
    /// The task id (opaque UUID text).
    pub id: String,
    /// The task title.
    pub title: String,
    /// The seven-label status.
    pub label: &'static str,
}

/// The `tasks_list` view model.
#[derive(askama::Template)]
#[template(path = "tasks_list.html")]
pub struct TaskListTemplate {
    /// One sentinel "Empty" row plus task rows.
    pub rows: Vec<TaskRow>,
    /// Whether the projection held no tasks.
    pub empty: bool,
    /// The session CSRF cookie value for the submit form.
    pub csrf_field: String,
    /// The operator-configured workspace-root allowlist.
    pub allowed_roots: Vec<String>,
    /// Fresh single-use idempotency token, minted per render — never the
    /// session CSRF value (it is stable across the session).
    pub idempotency_key: String,
    /// Whether the permission-policy select renders (harness enabled and
    /// the backend is not deny-only).
    pub policy_select: bool,
    /// The user-settings note under the select.
    pub user_settings_note: &'static str,
    /// The auto-allow acknowledgement text.
    pub auto_allow_warning: &'static str,
    /// The deny-only backend note replacing the select.
    pub deny_only_note: &'static str,
    /// Whether the optional budget fields render.
    pub budget_fields: bool,
    /// Serve's default cost limit as the field placeholder (USD units).
    pub cost_placeholder: String,
    /// Serve's default wall clock as the field placeholder (minutes).
    pub wall_clock_placeholder: String,
    /// The backend's cost-reporting note.
    pub subscription_note: &'static str,
    /// Whether the cost field is disabled (a backend that reports no cost).
    pub cost_disabled: bool,
    /// The harness dispatcher/permission banner.
    pub banner: HarnessBannerView,
}

impl TaskListTemplate {
    pub(crate) fn render(&self) -> String {
        <Self as askama::Template>::render(self)
            .unwrap_or_else(|_| crate::rendering::render_error_page("Tasks", "Unavailable"))
    }
}

// ---------------------------------------------------------------------------
// Task detail view model + template
// ---------------------------------------------------------------------------

/// The `tasks_detail` view model — every flag precomputed from the real
/// domain status and the durable gates (restart barrier, retry cap).
#[derive(askama::Template)]
#[template(path = "tasks_detail.html")]
pub struct TaskDetailTemplate {
    /// The task id.
    pub id: String,
    /// The task title.
    pub title: String,
    /// The seven-label status.
    pub label: &'static str,
    /// Rerun lineage.
    pub has_parent: bool,
    /// The parent (cancelled source) task id.
    pub parent_task_id: String,
    /// Restart barrier: the current run is quarantined.
    pub restart_barrier: bool,
    /// The barrier's machine reason (`RECOVERY_*`).
    pub barrier_reason: String,
    /// Human phrase for the block — only while actually Waiting.
    pub waiting_reason: String,
    /// The session CSRF value for the mutation forms.
    pub csrf_field: String,
    /// Fresh single-use idempotency token per render.
    pub idempotency_key: String,
    /// Status eligibility AND no restart barrier.
    pub cancellable: bool,
    /// Failed AND no barrier AND cost cap not exhausted.
    pub retryable: bool,
    /// Cancelled AND no barrier.
    pub rerunnable: bool,
    /// Whether the report links render (durably ready artifact only).
    pub has_artifact: bool,
    /// The required-report artifact id.
    pub artifact_id: String,
    /// Every ready artifact of the current run.
    pub artifacts: Vec<TaskArtifactRow>,
    /// Starting poll interval for `tasks_poll.js`.
    pub poll_interval_ms: &'static str,
    /// The task's optimistic-concurrency version the poll compares.
    pub projection_revision: i64,
    /// The highest workspace event sequence the poll compares.
    pub event_revision: i64,
    /// The task's failure reason — only while `Unsuccessful`.
    pub failure_reason: String,
    /// Which budget bound stopped a failed run, in words.
    pub budget_reason: String,
    /// The per-attempt timeline.
    pub runs: Vec<RunHistoryRow>,
    /// Persisted terminal failures so far.
    pub retry_count: i64,
    /// Absolute RFC3339 UTC timestamps.
    pub created_at: String,
    /// Absolute RFC3339 UTC timestamps.
    pub updated_at: String,
    /// The task's requested instruction (display-only parse).
    pub instruction: String,
    /// The task's selected repository root.
    pub workspace_root: String,
    /// Per-task bounded activity rows.
    pub activity: Vec<ActivityRow>,
    /// The current run's provider-turn timeline.
    pub turn_activity: Vec<TurnActivityRow>,
    /// The harness dispatcher/permission banner.
    pub banner: HarnessBannerView,
    /// The Task's permission policy label.
    pub permission_policy: &'static str,
    /// The auto-allow warning for an auto-allow Task.
    pub auto_allow_warning: &'static str,
    /// The current run's pending permission request panel.
    pub permission_panel: Option<PermissionPanelView>,
    /// The run's permission history, newest first.
    pub permission_history: Vec<PermissionHistoryRow>,
    /// "This request is no longer pending." after a stale decision.
    pub permission_notice: &'static str,
    /// The notice of an action that lost to a concurrent transition.
    pub action_notice: &'static str,
    /// "Finish cancelling" for a cancelling task whose run never claimed
    /// (or whose prepared harness attempt was never invoked).
    pub finish_cancelling: bool,
    /// Whether the prepared-attempt copy renders.
    pub finish_cancelling_prepared: bool,
    /// Whether the resolve panel renders at all.
    pub harness_resolvable: bool,
    /// Which resolve buttons the panel offers.
    pub harness_resolve: HarnessResolveView,
    /// The current harness run's recorded limits and reported usage.
    pub budget: Option<RunBudgetView>,
    /// The task's recorded harness cost against the cost cap.
    pub task_cost: String,
    /// Why Retry is unavailable (cost cap), or `""`.
    pub retry_unavailable: &'static str,
}

impl TaskDetailTemplate {
    pub(crate) fn render(&self) -> String {
        <Self as askama::Template>::render(self)
            .unwrap_or_else(|_| crate::rendering::render_error_page("Task detail", "Unavailable"))
    }
}
