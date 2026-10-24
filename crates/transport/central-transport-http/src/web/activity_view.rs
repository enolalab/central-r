//! Activity view model — the bounded, newest-first lifecycle feed
//! (`activity_view.go`).

use central_task::query::TaskEventLogProjection;

use super::format_timestamp;
use super::harness::HarnessBannerView;
use super::task_view::task_status_label;

/// One rendered line in the activity feed.
#[derive(Debug, Clone)]
pub struct ActivityRow {
    /// The task the event concerns (detail-link target).
    pub task_id: String,
    /// Human phrase for the event kind.
    pub kind: String,
    /// The resulting task-state label (empty when the event carried none).
    pub state: String,
    /// When the event occurred.
    pub at: String,
}

/// `humanizeEventKind` — `task.cancel_requested` → `cancel requested`;
/// an unrecognised shape renders as-is rather than blanked.
#[must_use]
pub fn humanize_event_kind(kind: &str) -> String {
    let stripped = kind.strip_prefix("task.").unwrap_or(kind);
    let s = stripped.replace('_', " ");
    if s.is_empty() { kind.to_string() } else { s }
}

/// `buildActivity` — pure projection to the view model. The state label
/// is set only when the event carried one; an empty state renders no
/// label rather than fail-closing to `Unsuccessful`.
#[must_use]
pub fn build_activity(projection: &TaskEventLogProjection) -> ActivityTemplate {
    ActivityTemplate {
        rows: projection
            .events
            .iter()
            .map(|e| ActivityRow {
                task_id: e.task_id.to_string(),
                kind: humanize_event_kind(&e.kind),
                state: e
                    .state
                    .map_or_else(String::new, |s| task_status_label(s).to_string()),
                at: format_timestamp(e.at),
            })
            .collect(),
        empty: projection.events.is_empty(),
        truncated: projection.next_cursor.is_some(),
        banner: HarnessBannerView::default(),
    }
}

/// The `activity` view model.
#[derive(askama::Template)]
#[template(path = "activity.html")]
pub struct ActivityTemplate {
    /// Newest-first display rows.
    pub rows: Vec<ActivityRow>,
    /// Whether the page held no events.
    pub empty: bool,
    /// Whether a further (older) page exists.
    pub truncated: bool,
    /// The harness dispatcher/permission banner.
    pub banner: HarnessBannerView,
}

impl ActivityTemplate {
    pub(crate) fn render(&self) -> String {
        <Self as askama::Template>::render(self)
            .unwrap_or_else(|_| crate::rendering::render_error_page("Activity", "Unavailable"))
    }
}
