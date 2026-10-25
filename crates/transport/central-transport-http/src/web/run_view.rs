//! Run view handlers (issue #96, slice 2E): `GET /app/runs` census,
//! `GET /app/runs/detail` DAG + journal fold-check + residue banners,
//! `GET /app/runs/node` attempt history + node timeline. All read-only:
//! every hard projection failure is a bare 503, a nil reader the same —
//! never a partial page, never a panic.

use std::collections::BTreeMap;
use std::sync::Arc;

use askama::Template;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::Response;
use central_eventjournal::domain::RunEvent;
use central_eventjournal::fold::{compare_fold, fold};
use central_foundation::identity::{RunId, WorkflowNodeId};
use central_runview::domain::{AttemptRow, GraphNode, LeaseRow, RunGraph, RunSummary};
use central_runview::query::{
    RUN_DETAIL_EVENT_LIMIT, RUN_LIST_PAGE_SIZE, RUN_NODE_STATE_ORDER, decode_run_cursor,
    encode_run_cursor, known_run_node_state, run_view_status_label,
};
use central_scheduler::domain as scheduler;

use super::handler::{harness_banner, query_value};
use super::{
    WebState, active_session, format_timestamp, html_response, render_bootstrap, render_not_found,
};
use crate::error;
use crate::ports::RunsReader;

/// `nodeBadgeToken` — the node's badge text: the v33 state verbatim, or
/// the composite `not_before-deferred` when a ready node still carries
/// a `not_before` mark (the view layer has no clock, so the timestamp
/// itself is rendered rather than judged past/future).
fn node_badge_token(node: &GraphNode) -> String {
    if node.status == "ready" && node.not_before.is_some() {
        return "not_before-deferred".to_string();
    }
    node.status.clone()
}

/// `nodeBadgeClass` — the rendered badge token's stylesheet suffix.
/// Unknown tokens fall to `other` — the text still renders, only the
/// accent is generic.
pub(crate) fn node_badge_class(token: &str) -> &str {
    match token {
        "declared"
        | "ready"
        | "not_before-deferred"
        | "dispatched"
        | "running"
        | "succeeded"
        | "failed_terminal"
        | "attempt_ambiguous"
        | "cancelled" => token,
        _ => "other",
    }
}

/// One state badge in a run's node census.
pub(crate) struct RunCountChip {
    pub state: String,
    pub count: i64,
}

/// `runStateCounts` — renders a run's `{state: count}` map as chips in
/// the canonical v33 vocabulary order; states absent from the map
/// render a 0 only when the run has other counts (a zero-node run
/// renders nothing). States outside the fixed vocabulary still render —
/// appended after the canonical ones rather than hidden.
fn run_state_counts(counts: &BTreeMap<String, i64>) -> Vec<RunCountChip> {
    if counts.is_empty() {
        return Vec::new();
    }
    let mut chips: Vec<RunCountChip> = Vec::with_capacity(counts.len());
    for state in RUN_NODE_STATE_ORDER {
        if let Some(&n) = counts.get(state)
            && n > 0
        {
            chips.push(RunCountChip {
                state: state.to_string(),
                count: n,
            });
        }
    }
    for (state, &n) in counts {
        if n <= 0 || known_run_node_state(state) {
            continue;
        }
        chips.push(RunCountChip {
            state: state.clone(),
            count: n,
        });
    }
    chips
}

/// `formatTimePtr` — a nullable timestamp, `""` when absent.
fn format_time_ptr(t: Option<time::OffsetDateTime>) -> String {
    t.map_or_else(String::new, format_timestamp)
}

// ---------------------------------------------------------------------------
// Run list — `GET /app/runs` (the census rows; the submit section's
// template fields are owned by run_submit.rs's template struct).
// ---------------------------------------------------------------------------

/// One run of the workspace run list. Runs with zero workflow nodes (a
/// Phase-1 harness-only run) render like the others — the list is the
/// complete workspace census by design.
pub(crate) struct RunListRow {
    pub id: String,
    pub task_id: String,
    pub index: i64,
    /// The raw `runs.status` token.
    pub status: String,
    pub label: String,
    pub run_key: String,
    pub counts: Vec<RunCountChip>,
    pub created: String,
    pub started: String,
    pub ended: String,
}

/// `buildRunList` — projects one `list_runs` page into display rows.
fn build_run_list(runs: &[RunSummary]) -> Vec<RunListRow> {
    runs.iter()
        .map(|run| RunListRow {
            id: run.id.to_string(),
            task_id: run.task_id.to_string(),
            index: run.index,
            status: run.status.clone(),
            label: run_view_status_label(&run.status).to_string(),
            run_key: run.run_key.clone().unwrap_or_default(),
            counts: run_state_counts(&run.node_counts),
            created: format_timestamp(run.created_at),
            started: format_time_ptr(run.started_at),
            ended: format_time_ptr(run.ended_at),
        })
        .collect()
}

/// `ServeRunList`'s census half — invoked by `run_submit::serve_run_list`
/// once session + reader stand, so the submit form and the census share
/// the one handler (the same single `GET /app/runs` upstream serves).
/// Returns the rows plus the opaque next-page cursor minted from the
/// LAST RENDERED row (never the lookahead row).
pub(crate) async fn run_list_page(
    reader: &Arc<dyn RunsReader>,
    workspace_id: central_foundation::identity::WorkspaceId,
    after: Option<central_runview::domain::RunCursor>,
) -> Result<(Vec<RunListRow>, String), ()> {
    let mut runs = reader
        .list_runs(workspace_id, after, RUN_LIST_PAGE_SIZE + 1)
        .await
        .map_err(|_| ())?;
    let mut next_cursor = String::new();
    if runs.len() as i64 > RUN_LIST_PAGE_SIZE {
        runs.truncate(RUN_LIST_PAGE_SIZE as usize);
        if let Some(last) = runs.last() {
            next_cursor = encode_run_cursor(&central_runview::domain::RunCursor {
                created_at: last.created_at,
                id: last.id,
            });
        }
    }
    Ok((build_run_list(&runs), next_cursor))
}

/// `decodeRunCursor` for the `?cursor=` query param — a malformed token
/// is the same generic 404 as a malformed id.
pub(crate) fn decode_cursor_param(
    query: Option<&str>,
) -> Result<Option<central_runview::domain::RunCursor>, ()> {
    let raw = query.and_then(|q| query_value(q, "cursor"));
    decode_run_cursor(raw).map_err(|_| ())
}

// ---------------------------------------------------------------------------
// Run detail — view models + pure builders
// ---------------------------------------------------------------------------

/// One anomaly line (a fold finding or a `compare_fold` divergence):
/// the SCREAMING_CASE reason, the detail, and the seq that surfaced it.
struct RunFindingView {
    reason: String,
    detail: String,
    seq: i64,
}

/// One incoming dependency edge of a DAG node: the prerequisite key
/// plus its v33 kind badge. Artifact edges name the artifact id as
/// text — the preview link is deliberately not offered here because
/// the edge does not prove the artifact is ready; the lineage page
/// owns artifact links with their lifecycle resolution.
pub(crate) struct DagEdgeView {
    pub from_key: String,
    pub kind: String,
    pub artifact_id: String,
}

/// One DAG node with its badge, its "waits on" edge badges, and its
/// rendered children (nested by `parent_node_id`). The template
/// renders it recursively.
pub(crate) struct DagNodeView {
    pub id: String,
    pub key: String,
    pub badge: String,
    pub badge_class: String,
    pub reason: String,
    /// "n / max", or "n" when max is 0.
    pub attempts: String,
    /// Rendered only for the deferred badge.
    pub not_before: String,
    pub waits_on: Vec<DagEdgeView>,
    pub children: Vec<DagNodeView>,
}

/// `buildRunDAG` — nests the flat, `(depth, created_at, node_key)`-
/// ordered node list into a renderable tree keyed on `parent_key`. A
/// node whose declared parent is absent from the projection attaches
/// to the roots — a node is displaced, never hidden.
fn build_run_dag(graph: &RunGraph) -> Vec<DagNodeView> {
    let key_to_node: BTreeMap<&str, &GraphNode> =
        graph.nodes.iter().map(|n| (n.key.as_str(), n)).collect();
    let mut incoming: BTreeMap<&str, Vec<DagEdgeView>> = BTreeMap::new();
    for edge in &graph.edges {
        incoming
            .entry(edge.to_key.as_str())
            .or_default()
            .push(DagEdgeView {
                from_key: edge.from_key.clone(),
                kind: edge.kind.clone(),
                artifact_id: edge.artifact_id.map_or_else(String::new, |a| a.to_string()),
            });
    }

    let mut views: BTreeMap<String, DagNodeView> = BTreeMap::new();
    let mut order: Vec<String> = Vec::new(); // first-seen key order
    for node in &graph.nodes {
        let badge = node_badge_token(node);
        let view = DagNodeView {
            id: node.id.to_string(),
            key: node.key.clone(),
            badge_class: node_badge_class(&badge).to_string(),
            badge,
            reason: node.reason.clone(),
            attempts: if node.max_attempts > 0 {
                format!("{} / {}", node.attempt_count, node.max_attempts)
            } else {
                format!("{}", node.attempt_count)
            },
            not_before: format_time_ptr(node.not_before),
            waits_on: incoming.remove(node.key.as_str()).unwrap_or_default(),
            children: Vec::new(),
        };
        views.insert(node.key.clone(), view);
        order.push(node.key.clone());
    }

    let mut roots: Vec<DagNodeView> = Vec::new();
    // Parent attachment needs mutable access to both child and parent —
    // take views out, link, and push roots.
    let mut children_of: BTreeMap<String, Vec<DagNodeView>> = BTreeMap::new();
    for key in &order {
        let node = key_to_node[key.as_str()];
        // Every `order` key was inserted above — `remove` cannot miss.
        let Some(view) = views.remove(key) else {
            continue;
        };
        if let Some(parent_key) = &node.parent_key
            && parent_key != &node.key
            && key_to_node.contains_key(parent_key.as_str())
        {
            children_of
                .entry(parent_key.clone())
                .or_default()
                .push(view);
            continue;
        }
        roots.push(view);
    }
    // Attach children depth-first: parents precede children in `order`,
    // so one pass over a queue nests the whole tree.
    fn attach(node: &mut DagNodeView, children_of: &mut BTreeMap<String, Vec<DagNodeView>>) {
        if let Some(mut children) = children_of.remove(&node.key) {
            for child in &mut children {
                attach(child, children_of);
            }
            node.children = children;
        }
    }
    for root in &mut roots {
        attach(root, &mut children_of);
    }
    roots
}

/// Minimal HTML escaping for the Rust-side DAG renderer — every dynamic
/// value (`esc`d) plus the closed-vocabulary badges; the template marks
/// the assembled markup `|safe`, so correctness lives entirely here.
fn esc(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for ch in v.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

/// `{{template "run_dag_node" .}}` — renders the nested `<ul>` the
/// `dag_node` template fragment produced upstream. Askama templates do
/// not recurse, so the nesting is rendered here with the identical
/// markup; every interpolated value is `esc`d exactly as the template
/// engine would have.
fn render_dag_node(node: &DagNodeView, out: &mut String) {
    out.push_str("<li><a href=\"/app/runs/node?id=");
    out.push_str(&esc(&node.id));
    out.push_str("\"><code>");
    out.push_str(&esc(&node.key));
    out.push_str("</code></a> <span class=\"badge badge-");
    out.push_str(&esc(&node.badge_class));
    out.push_str("\">");
    out.push_str(&esc(&node.badge));
    out.push_str("</span>");
    if !node.not_before.is_empty() {
        out.push_str(" <span class=\"hint\">not before ");
        out.push_str(&esc(&node.not_before));
        out.push_str("</span>");
    }
    out.push_str(" <span class=\"hint\">attempts ");
    out.push_str(&esc(&node.attempts));
    out.push_str("</span>");
    if !node.reason.is_empty() {
        out.push_str("<br><span>");
        out.push_str(&esc(&node.reason));
        out.push_str("</span>");
    }
    if !node.waits_on.is_empty() {
        out.push_str("<ul class=\"edge-badges\">");
        for edge in &node.waits_on {
            out.push_str("<li>waits on <code>");
            out.push_str(&esc(&edge.from_key));
            out.push_str("</code> <span class=\"badge badge-edge-");
            out.push_str(&esc(&edge.kind));
            out.push_str("\">");
            out.push_str(&esc(&edge.kind));
            out.push_str("</span>");
            if !edge.artifact_id.is_empty() {
                out.push_str(" <code>");
                out.push_str(&esc(&edge.artifact_id));
                out.push_str("</code>");
            }
            out.push_str("</li>");
        }
        out.push_str("</ul>");
    }
    if !node.children.is_empty() {
        out.push_str("<ul>");
        for child in &node.children {
            render_dag_node(child, out);
        }
        out.push_str("</ul>");
    }
    out.push_str("</li>");
}

/// Renders the whole root list (upstream `{{range .DAG}}` over the
/// fragment).
fn render_dag_html(roots: &[DagNodeView]) -> String {
    let mut out = String::new();
    for node in roots {
        render_dag_node(node, &mut out);
    }
    out
}

/// One journaled event of the timeline. `detail` carries a small
/// kind-aware extraction (`child_spec_rejected`'s offending keys) —
/// payloads are never rendered raw.
pub(crate) struct RunEventRow {
    pub seq: i64,
    pub kind: String,
    /// Resolved node key, `""` for run-scope events.
    pub node_key: String,
    /// `/app/runs/node?id=...` target id text when `node_id` present.
    pub node_link: String,
    pub actor: String,
    pub reason: String,
    pub detail: String,
    pub at: String,
}

/// `runEventDetail` — extracts the one kind-versioned payload member
/// the run timeline surfaces: `child_spec_rejected`'s `offending_keys`,
/// the keys the scheduler refused verbatim. Every other payload renders
/// nothing — the journal payloads are evidence, not display text.
fn run_event_detail(ev: &RunEvent) -> String {
    if ev.kind != "child_spec_rejected" || ev.payload.is_null() {
        return String::new();
    }
    let payload = &ev.payload;
    let keys: Vec<&str> = payload
        .get("offending_keys")
        .and_then(|k| k.as_array())
        .map(|arr| arr.iter().filter_map(|k| k.as_str()).collect())
        .unwrap_or_default();
    if keys.is_empty() {
        return String::new();
    }
    format!("offending keys: {}", keys.join(", "))
}

/// `buildRunEvents` — projects the journal into timeline rows,
/// resolving node ids to keys through the graph. The rendered page
/// caps at `RUN_DETAIL_EVENT_LIMIT` rows; the fold uses the full slice.
fn build_run_events(
    events: &[RunEvent],
    graph: &RunGraph,
    limit: usize,
) -> (Vec<RunEventRow>, usize, bool) {
    let node_keys: BTreeMap<WorkflowNodeId, &str> =
        graph.nodes.iter().map(|n| (n.id, n.key.as_str())).collect();
    let total = events.len();
    let truncated = total > limit;
    let rows = events
        .iter()
        .take(limit)
        .map(|ev| {
            let (node_key, node_link) = ev.node_id.map_or_else(
                || (String::new(), String::new()),
                |id| {
                    (
                        node_keys
                            .get(&id)
                            .map_or_else(|| id.to_string(), |k| (*k).to_string()),
                        id.to_string(),
                    )
                },
            );
            RunEventRow {
                seq: ev.seq,
                kind: ev.kind.clone(),
                node_key,
                node_link,
                actor: ev.actor.clone(),
                reason: ev.reason_code.clone().unwrap_or_default(),
                detail: run_event_detail(ev),
                at: format_timestamp(ev.recorded_at),
            }
        })
        .collect();
    (rows, total, truncated)
}

/// `buildNodeEvents` — filters the run journal to the node's own
/// timeline: events whose envelope `node_id` is this node.
fn build_node_events(events: &[RunEvent], node_id: WorkflowNodeId) -> Vec<RunEventRow> {
    events
        .iter()
        .filter(|ev| ev.node_id == Some(node_id))
        .map(|ev| RunEventRow {
            seq: ev.seq,
            kind: ev.kind.clone(),
            node_key: String::new(),
            node_link: String::new(),
            actor: ev.actor.clone(),
            reason: ev.reason_code.clone().unwrap_or_default(),
            detail: run_event_detail(ev),
            at: format_timestamp(ev.recorded_at),
        })
        .collect()
}

/// One `attempt_ambiguous` node named by the reconciliation banner.
struct ParkedNodeView {
    id: String,
    key: String,
    reason: String,
}

/// One live lease of the run whose heartbeat age crosses the
/// scheduler's suspect/lost ladder.
struct LeaseWarningView {
    node_key: String,
    node_id: String,
    /// "suspect" or "lost" — the ladder's verdict.
    state: String,
    missed_beats: i64,
    age_seconds: i64,
    worker_id: String,
}

/// `RenderRunDetail` view model.
struct RunDetailViewModel {
    run_id: String,
    task_id: String,
    index: i64,
    status: String,
    label: String,
    run_key: String,
    counts: Vec<RunCountChip>,
    created: String,
    updated: String,
    started: String,
    ended: String,
    deadline: String,

    divergence: Vec<RunFindingView>,
    journal_findings: Vec<RunFindingView>,
    parked: Vec<ParkedNodeView>,
    lease_warnings: Vec<LeaseWarningView>,

    dag: Vec<DagNodeView>,
    /// The nested `<ul>` HTML the `dag` tree renders to — Askama cannot
    /// recurse templates, so the recursion lives here; every dynamic
    /// value passes through [`esc`].
    dag_html: String,
    dag_empty: bool,

    events: Vec<RunEventRow>,
    events_total: usize,
    events_truncated: bool,
}

/// `buildRunDetail` — assembles the run detail view model: header, the
/// divergence + residue banners, the nested DAG and the capped
/// timeline. `leases` is the caller's workspace-wide live-lease read;
/// this pure function filters it to the run.
fn build_run_detail(
    summary: &RunSummary,
    graph: &RunGraph,
    events: &[RunEvent],
    current: &BTreeMap<String, String>,
    leases: &[LeaseRow],
) -> RunDetailViewModel {
    let mut vm = RunDetailViewModel {
        run_id: summary.id.to_string(),
        task_id: summary.task_id.to_string(),
        index: summary.index,
        status: summary.status.clone(),
        label: run_view_status_label(&summary.status).to_string(),
        run_key: summary.run_key.clone().unwrap_or_default(),
        counts: run_state_counts(&summary.node_counts),
        created: format_timestamp(summary.created_at),
        updated: format_timestamp(summary.updated_at),
        started: format_time_ptr(summary.started_at),
        ended: format_time_ptr(summary.ended_at),
        deadline: format_time_ptr(summary.deadline),
        divergence: Vec::new(),
        journal_findings: Vec::new(),
        parked: Vec::new(),
        lease_warnings: Vec::new(),
        dag: Vec::new(),
        dag_html: String::new(),
        dag_empty: graph.nodes.is_empty(),
        events: Vec::new(),
        events_total: 0,
        events_truncated: false,
    };

    // Divergence: fold the journal, compare against materialized
    // state. Both anomaly sets render verbatim — the page names the
    // evidence, it does not arbitrate it.
    let folded = fold(events);
    for f in compare_fold(current, &folded) {
        vm.divergence.push(RunFindingView {
            reason: f.reason_code.as_str().to_string(),
            detail: f.detail,
            seq: f.seq,
        });
    }
    for f in &folded.findings {
        vm.journal_findings.push(RunFindingView {
            reason: f.reason_code.as_str().to_string(),
            detail: f.detail.clone(),
            seq: f.seq,
        });
    }

    // Residue banners: parked ambiguous nodes (awaiting operator
    // decision) and live leases whose heartbeat age crosses the
    // scheduler's suspect/lost ladder.
    let node_by_id: BTreeMap<WorkflowNodeId, &GraphNode> =
        graph.nodes.iter().map(|n| (n.id, n)).collect();
    for node in &graph.nodes {
        if node.status == "attempt_ambiguous" {
            vm.parked.push(ParkedNodeView {
                id: node.id.to_string(),
                key: node.key.clone(),
                reason: node.reason.clone(),
            });
        }
    }
    for lease in leases {
        if lease.run_id != summary.id {
            continue;
        }
        let missed =
            (lease.heartbeat_age_seconds / scheduler::HEARTBEAT_INTERVAL_SEC).max(0) as u32;
        let state = scheduler::ladder(missed);
        if state == scheduler::WorkerState::Active {
            continue;
        }
        let key = if lease.node_key.is_empty() {
            node_by_id
                .get(&lease.node_id)
                .map_or_else(String::new, |n| n.key.clone())
        } else {
            lease.node_key.clone()
        };
        vm.lease_warnings.push(LeaseWarningView {
            node_key: key,
            node_id: lease.node_id.to_string(),
            state: state.as_str().to_string(),
            missed_beats: i64::from(missed),
            age_seconds: lease.heartbeat_age_seconds,
            worker_id: lease.worker_id.to_string(),
        });
    }

    vm.dag = build_run_dag(graph);
    vm.dag_html = render_dag_html(&vm.dag);
    let (events, total, truncated) = build_run_events(events, graph, RUN_DETAIL_EVENT_LIMIT);
    vm.events = events;
    vm.events_total = total;
    vm.events_truncated = truncated;
    vm
}

/// One scalar member of the spec's `"versions"` object.
pub(crate) struct SpecExtraView {
    pub key: String,
    pub value: String,
}

/// One session attempt of the node detail page. Version fields render
/// "not recorded" verbatim when the projection carried `None` — the
/// degraded honest answer the `Versions` projection documents.
pub(crate) struct AttemptViewRow {
    pub seq: i32,
    pub state: String,
    pub reason: String,
    pub worker: String,
    pub claimed: String,
    pub started: String,
    pub ended: String,
    pub adapter: String,
    pub harness: String,
    pub spec_extras: Vec<SpecExtraView>,
    /// The artifact id rendered only ever as a preview link.
    pub prompt_ref: String,
}

/// `versionOrUnrecorded` — a version `Option` as its value or the
/// explicit "not recorded" answer.
fn version_or_unrecorded(v: &Option<String>) -> String {
    match v {
        Some(s) if !s.is_empty() => s.clone(),
        _ => "not recorded".to_string(),
    }
}

/// `buildAttemptRows` — projects the attempt ledger into display rows
/// (spec extras sorted by key; `BTreeMap` iteration is already sorted).
fn build_attempt_rows(attempts: &[AttemptRow]) -> Vec<AttemptViewRow> {
    attempts
        .iter()
        .map(|attempt| AttemptViewRow {
            seq: attempt.seq,
            state: attempt.state.clone(),
            reason: attempt.reason_code.clone().unwrap_or_default(),
            worker: attempt
                .worker_id
                .map_or_else(String::new, |w| w.to_string()),
            claimed: format_timestamp(attempt.claimed_at),
            started: format_time_ptr(attempt.started_at),
            ended: format_time_ptr(attempt.ended_at),
            adapter: version_or_unrecorded(&attempt.versions.adapter_version),
            harness: version_or_unrecorded(&attempt.versions.harness_version),
            spec_extras: attempt
                .versions
                .spec_extras
                .iter()
                .map(|(key, value)| SpecExtraView {
                    key: key.clone(),
                    value: value.clone(),
                })
                .collect(),
            prompt_ref: attempt
                .versions
                .prompt_ref_artifact_id
                .map_or_else(String::new, |a| a.to_string()),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `ServeRunDetail` — `GET /app/runs/detail?run=<id>`: the run's DAG,
/// event timeline and residue banners. `run_for_id` is the
/// existence/scope check in one read — malformed, absent and
/// cross-workspace ids are the same generic 404. Graph, journal and
/// materialized state are all hard reads; a projection failure is a
/// bare 503.
pub(crate) async fn serve_run_detail(state: Arc<WebState>, req: Request) -> Response {
    let Some(sess) = active_session(&state, req.headers()).await else {
        return render_bootstrap(&req, StatusCode::OK, "");
    };
    let Some(reader) = state.runs.clone() else {
        return error::reject(StatusCode::SERVICE_UNAVAILABLE, "");
    };
    let query = req.uri().query().map(str::to_string);
    let Some(run_id) = query
        .as_deref()
        .and_then(|q| query_value(q, "run"))
        .and_then(|v| RunId::parse(v).ok())
    else {
        return render_not_found();
    };
    let workspace_id = sess.workspace_id;
    let summary = match reader.run_for_id(workspace_id, run_id).await {
        Ok(s) => s,
        Err(f) if f.kind() == central_foundation::failure::FailureKind::NotFound => {
            return render_not_found();
        }
        Err(_) => return error::reject(StatusCode::SERVICE_UNAVAILABLE, ""),
    };
    let Ok(graph) = reader.graph_for_run(run_id).await else {
        return error::reject(StatusCode::SERVICE_UNAVAILABLE, "");
    };
    let Ok(events) = reader.events_for_run(run_id).await else {
        return error::reject(StatusCode::SERVICE_UNAVAILABLE, "");
    };
    let Ok(current) = reader.nodes_current(run_id).await else {
        return error::reject(StatusCode::SERVICE_UNAVAILABLE, "");
    };
    let Ok(leases) = reader.live_leases(workspace_id).await else {
        return error::reject(StatusCode::SERVICE_UNAVAILABLE, "");
    };
    let banner = harness_banner(&state, workspace_id).await;
    html_response(
        StatusCode::OK,
        &RunDetailTemplate {
            vm: build_run_detail(&summary, &graph, &events, &current, &leases),
            banner,
        }
        .render(),
    )
}

/// `ServeNodeDetail` — `GET /app/runs/node?id=<node-id>`: the node's
/// attempt history (with the degraded honest `Versions` record) and
/// its journaled timeline. `node_for_id` is the existence/scope check
/// in one read.
pub(crate) async fn serve_node_detail(state: Arc<WebState>, req: Request) -> Response {
    let Some(sess) = active_session(&state, req.headers()).await else {
        return render_bootstrap(&req, StatusCode::OK, "");
    };
    let Some(reader) = state.runs.clone() else {
        return error::reject(StatusCode::SERVICE_UNAVAILABLE, "");
    };
    let query = req.uri().query().map(str::to_string);
    let Some(node_id) = query
        .as_deref()
        .and_then(|q| query_value(q, "id"))
        .and_then(|v| WorkflowNodeId::parse(v).ok())
    else {
        return render_not_found();
    };
    let workspace_id = sess.workspace_id;
    let node = match reader.node_for_id(workspace_id, node_id).await {
        Ok(n) => n,
        Err(f) if f.kind() == central_foundation::failure::FailureKind::NotFound => {
            return render_not_found();
        }
        Err(_) => return error::reject(StatusCode::SERVICE_UNAVAILABLE, ""),
    };
    let Ok(attempts) = reader.attempts_for_node(node_id).await else {
        return error::reject(StatusCode::SERVICE_UNAVAILABLE, "");
    };
    let Ok(events) = reader.events_for_run(node.run_id).await else {
        return error::reject(StatusCode::SERVICE_UNAVAILABLE, "");
    };
    let banner = harness_banner(&state, workspace_id).await;
    let badge = node_badge_token(&node);
    html_response(
        StatusCode::OK,
        &RunNodeTemplate {
            node_id: node.id.to_string(),
            run_id: node.run_id.to_string(),
            key: node.key.clone(),
            status: node.status.clone(),
            badge_class: node_badge_class(&badge).to_string(),
            badge,
            reason: node.reason.clone(),
            attempts: if node.max_attempts > 0 {
                format!("{} / {}", node.attempt_count, node.max_attempts)
            } else {
                format!("{}", node.attempt_count)
            },
            not_before: format_time_ptr(node.not_before),
            parent_key: node.parent_key.clone().unwrap_or_default(),
            created: format_timestamp(node.created_at),
            attempt_rows: build_attempt_rows(&attempts),
            events: build_node_events(&events, node_id),
            banner,
        }
        .render(),
    )
}

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

/// `runDetailViewModel` + banner — the run detail page.
#[derive(Template)]
#[template(path = "runs/detail.html")]
struct RunDetailTemplate {
    vm: RunDetailViewModel,
    banner: super::harness::HarnessBannerView,
}

impl RunDetailTemplate {
    fn render(&self) -> String {
        <Self as askama::Template>::render(self)
            .unwrap_or_else(|_| crate::rendering::render_error_page("Run detail", "Unavailable"))
    }
}

/// `runNodeViewModel` + banner — the node detail page.
#[derive(Template)]
#[template(path = "runs/node.html")]
struct RunNodeTemplate {
    node_id: String,
    run_id: String,
    key: String,
    status: String,
    badge: String,
    badge_class: String,
    reason: String,
    attempts: String,
    not_before: String,
    parent_key: String,
    created: String,
    attempt_rows: Vec<AttemptViewRow>,
    events: Vec<RunEventRow>,
    banner: super::harness::HarnessBannerView,
}

impl RunNodeTemplate {
    fn render(&self) -> String {
        <Self as askama::Template>::render(self)
            .unwrap_or_else(|_| crate::rendering::render_error_page("Node detail", "Unavailable"))
    }
}
