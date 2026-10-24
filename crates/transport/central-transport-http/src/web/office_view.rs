//! Office view model — the canvas visualization of the live task
//! projection (`office_view.go`). The client-side renderer
//! (`/assets/office.js`) reads the per-task `data-*` attributes the
//! template emits — no executable data island, so the strict
//! `script-src 'self'` CSP holds.

use central_task::query::{TaskEventLogProjection, TaskListProjection};

use crate::health::{ProbeSnapshot, ProbeState};

use super::harness::HarnessBannerView;
use super::overview_view::{health_state_label, waiting_reason_phrase};
use super::task_view::task_status_label;

/// One task rendered as a worker in the office.
#[derive(Debug, Clone)]
pub struct OfficeAgent {
    /// The task id.
    pub id: String,
    /// The task title.
    pub title: String,
    /// The canonical status label (which room it stands in).
    pub label: &'static str,
    /// Waiting phrase while Waiting, failure reason while Unsuccessful.
    pub reason: String,
}

/// A recent lifecycle event for the activity ticker — only the task id
/// and the monotonic sequence (the client flashes any task with a newer
/// sequence than it has seen).
#[derive(Debug, Clone)]
pub struct OfficeEvent {
    /// The task the event concerns.
    pub task_id: String,
    /// The workspace event sequence.
    pub seq: i64,
}

/// `buildOffice` — pure projection: health + bounded tasks + bounded
/// events into the office model. `reason` reuses the exact waiting
/// phrase the overview and detail pages use.
#[must_use]
pub fn build_office(
    health: &ProbeSnapshot,
    projection: &TaskListProjection,
    events: &TaskEventLogProjection,
) -> OfficeTemplate {
    OfficeTemplate {
        state_label: health_state_label(health.state),
        healthy: health.state == ProbeState::Ready,
        no_tasks: projection.tasks.is_empty(),
        truncated: projection.next_cursor.is_some(),
        agents: projection
            .tasks
            .iter()
            .map(|t| {
                let label = task_status_label(t.status);
                OfficeAgent {
                    id: t.task_id.to_string(),
                    title: t.title.clone(),
                    label,
                    reason: match label {
                        "Waiting" => waiting_reason_phrase(t.waiting_reason),
                        "Unsuccessful" => t.failure_reason.clone(),
                        _ => String::new(),
                    },
                }
            })
            .collect(),
        events: events
            .events
            .iter()
            .map(|e| OfficeEvent {
                task_id: e.task_id.to_string(),
                seq: e.sequence,
            })
            .collect(),
        banner: HarnessBannerView::default(),
    }
}

/// The `office` view model.
#[derive(askama::Template)]
#[template(path = "office.html")]
pub struct OfficeTemplate {
    /// Readiness state as a human label.
    pub state_label: &'static str,
    /// Whether the instance is fully ready.
    pub healthy: bool,
    /// Whether the instance has no tasks.
    pub no_tasks: bool,
    /// Whether the page is a lower bound.
    pub truncated: bool,
    /// Per-task canvas data.
    pub agents: Vec<OfficeAgent>,
    /// Recent events for the ticker.
    pub events: Vec<OfficeEvent>,
    /// The harness dispatcher/permission banner.
    pub banner: HarnessBannerView,
}

impl OfficeTemplate {
    pub(crate) fn render(&self) -> String {
        <Self as askama::Template>::render(self)
            .unwrap_or_else(|_| crate::rendering::render_error_page("Office", "Unavailable"))
    }
}
