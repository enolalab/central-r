//! Overview view model — the "is the instance healthy, and what needs
//! me?" landing projection (`overview_view.go`). Pure: no I/O, no clock.

use std::collections::BTreeMap;

use central_task::domain::{TaskStatus, WaitingReason};
use central_task::query::TaskListProjection;

use crate::health::{ProbeSnapshot, ProbeState};

use super::harness::HarnessBannerView;
use super::task_view::{task_rerun_eligible, task_retry_eligible, task_status_label};

/// The fixed presentation order for the per-status counts — the six
/// live labels; `Empty` is the whole-instance case, not a status.
const OVERVIEW_LABEL_ORDER: [&str; 6] = [
    "Queued",
    "Running",
    "Waiting",
    "Settling",
    "Unsuccessful",
    "Completed",
];

/// One status bucket: a canonical label plus its count within the
/// bounded projection.
#[derive(Debug, Clone)]
pub struct OverviewStatusCount {
    /// The label.
    pub label: &'static str,
    /// How many tasks carry it in the counted page.
    pub count: usize,
}

/// One task the operator can act on right now from the web console.
/// Destructive recovery is deliberately never an attention action — that
/// path requires physical-console consent (web-ui-feature-spec invariant 2).
#[derive(Debug, Clone)]
pub struct OverviewAttentionRow {
    /// The task id (detail-link target).
    pub id: String,
    /// The task title.
    pub title: String,
    /// The status label.
    pub label: &'static str,
    /// The available next step, in a short phrase.
    pub action: String,
}

/// `healthStateLabel` — a stable human label for a readiness state; an
/// unexpected state never renders blank.
#[must_use]
pub fn health_state_label(state: ProbeState) -> &'static str {
    match state {
        ProbeState::Ready => "Ready",
        ProbeState::Starting => "Starting",
        ProbeState::NotReady => "Not ready",
        ProbeState::ShuttingDown => "Shutting down",
        ProbeState::Failed => "Failed",
    }
}

/// `waitingReasonPhrase` — a Task's [`WaitingReason`] as a human phrase.
/// `None` (defensive) and an unrecognised reason both yield a visible,
/// non-blank phrase rather than hiding the block.
#[must_use]
pub fn waiting_reason_phrase(reason: Option<WaitingReason>) -> String {
    match reason {
        None => "Waiting — reason unavailable".to_string(),
        Some(WaitingReason::Approval) => "Awaiting your approval".to_string(),
        Some(WaitingReason::ExternalInput) => "Awaiting external input".to_string(),
        Some(WaitingReason::RetryDelay) => "Waiting for a retry delay".to_string(),
        Some(WaitingReason::Dependency) => "Blocked on a dependency".to_string(),
        Some(WaitingReason::Reconciliation) => "Awaiting reconciliation".to_string(),
        Some(other) => format!("Waiting ({})", other.as_str()),
    }
}

/// `operatorActionableWaiting` — only approval and external input need a
/// human; retry-delay, dependency, and reconciliation blocks are resumed
/// by the execution engine itself. An unexplained block is actionable so
/// it is never silently hidden.
#[must_use]
pub fn operator_actionable_waiting(reason: Option<WaitingReason>) -> bool {
    !matches!(
        reason,
        Some(WaitingReason::RetryDelay)
            | Some(WaitingReason::Dependency)
            | Some(WaitingReason::Reconciliation)
    )
}

/// `attentionAction` — the operator-actionable next step for a task:
/// an actionable Waiting (phrase of the reason), a Failed (Retry), or a
/// Cancelled (Rerun). The cost-cap check lives on the detail page only.
#[must_use]
pub fn attention_action(status: TaskStatus, reason: Option<WaitingReason>) -> Option<String> {
    if status == TaskStatus::Waiting {
        if !operator_actionable_waiting(reason) {
            return None;
        }
        return Some(waiting_reason_phrase(reason));
    }
    if task_retry_eligible(status) {
        return Some("Retry available".to_string());
    }
    if task_rerun_eligible(status) {
        return Some("Rerun available".to_string());
    }
    None
}

/// `summarizeOverview` — counts and the attention list from one bounded
/// task projection. Counts emit in the fixed order with an explicit zero
/// for every live label; attention preserves projection order.
#[must_use]
pub fn summarize_overview(
    health: &ProbeSnapshot,
    projection: &TaskListProjection,
) -> OverviewTemplate {
    let mut by_label: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut attention = Vec::new();
    for t in &projection.tasks {
        *by_label.entry(task_status_label(t.status)).or_insert(0) += 1;
        if let Some(action) = attention_action(t.status, t.waiting_reason) {
            attention.push(OverviewAttentionRow {
                id: t.task_id.to_string(),
                title: t.title.clone(),
                label: task_status_label(t.status),
                action,
            });
        }
    }
    let healthy = health.state == ProbeState::Ready;
    OverviewTemplate {
        state_label: health_state_label(health.state),
        healthy,
        reason: if healthy {
            String::new()
        } else {
            health.reason.clone()
        },
        remediation: if healthy {
            String::new()
        } else {
            health.remediation.clone()
        },
        total: projection.tasks.len(),
        no_tasks: projection.tasks.is_empty(),
        truncated: projection.next_cursor.is_some(),
        counts: OVERVIEW_LABEL_ORDER
            .iter()
            .map(|label| OverviewStatusCount {
                label,
                count: by_label.get(label).copied().unwrap_or(0),
            })
            .collect(),
        attention,
        banner: HarnessBannerView::default(),
    }
}

/// The `overview` view model.
#[derive(askama::Template)]
#[template(path = "overview.html")]
pub struct OverviewTemplate {
    /// The readiness state as a human label.
    pub state_label: &'static str,
    /// Whether the instance is fully ready.
    pub healthy: bool,
    /// Bounded diagnostic text when not ready.
    pub reason: String,
    /// Bounded remediation copy when not ready.
    pub remediation: String,
    /// Counted tasks in the bounded page.
    pub total: usize,
    /// Whether the instance has no tasks at all.
    pub no_tasks: bool,
    /// Whether the counts are a lower bound (a further page exists).
    pub truncated: bool,
    /// Per-status counts in the fixed order.
    pub counts: Vec<OverviewStatusCount>,
    /// Operator-actionable tasks, projection order.
    pub attention: Vec<OverviewAttentionRow>,
    /// The harness dispatcher/permission banner.
    pub banner: HarnessBannerView,
}

impl OverviewTemplate {
    pub(crate) fn render(&self) -> String {
        <Self as askama::Template>::render(self)
            .unwrap_or_else(|_| crate::rendering::render_error_page("Overview", "Unavailable"))
    }
}
