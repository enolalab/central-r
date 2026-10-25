//! Run operator controls (issue #96, slice 2E, packet P2E04): the
//! server-rendered control page and the state-changing POST routes over
//! the Phase-2 orchestration stores — run/node cancel, the parked-node
//! operator decision, checkpoint resume, and checkpoint write/pin/gc.
//!
//! Every POST replicates the task-submit security prelude verbatim:
//! POST-only (the route table), a non-empty Origin, exactly one
//! well-formed `csrf` form field, and the genuinely CSRF-enforcing
//! `active_session_with_csrf`. Dedup honesty: the controls carry NO
//! web-layer idempotency key — each store owns its own convergence. A
//! refused or deduped call renders its journaled reason code inline —
//! never silently. Verdicts render at 200: the POST was processed
//! honestly, refusals carry the reason rather than a bare status.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use askama::Template;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use central_checkpoint::domain::{GcClass, ResumeCheckpoint};
use central_foundation::failure::Failure as DomainFailure;
use central_foundation::identity::{ResumeCheckpointId, RunId, WorkflowNodeId, WorkspaceId};
use central_runview::domain::{GraphNode, RunGraph};
use central_runview::query::run_view_status_label;
use central_workflow::domain::NodeStatus;
use central_workflow::readiness::ambiguous_decision_known;
use sha2::{Digest, Sha256};

use super::handler::{active_session_with_csrf, harness_banner, query_value};
use super::run_view::node_badge_class;
use super::{
    WebState, active_session, form_value, format_timestamp, html_response, parse_body_form,
    render_bootstrap, render_not_found, session_csrf_value,
};
use crate::b64;
use crate::error;

/// `actorRunControl` — the journal actor every operator control lands
/// under, matching the CLI's operator actor.
const ACTOR_RUN_CONTROL: &str = "operator";

/// `nodeBadgeToken` — shared with the run view (the controls page
/// renders the same badge vocabulary).
fn badge_token(node: &GraphNode) -> String {
    if node.status == "ready" && node.not_before.is_some() {
        return "not_before-deferred".to_string();
    }
    node.status.clone()
}

// ---------------------------------------------------------------------------
// Shared prelude — the task-submit security sequence, verbatim
// ---------------------------------------------------------------------------

/// `renderRunControlFailure` — the run-control mirror of
/// `renderTaskActionFailure`: a generic, fail-closed text outcome that
/// never discloses a domain reason or run/node existence before the
/// scope check has passed.
fn render_run_control_failure(status: StatusCode) -> Response {
    (
        status,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; charset=utf-8",
        )],
        "RUN_CONTROL_FAILED\n",
    )
        .into_response()
}

/// `runControlPrelude` — the CSRF/session/form prelude every
/// run-control POST shares: Origin must be present, the body parses
/// inside the body cap, exactly one `csrf` field decodes, and
/// `activeSessionWithCSRF` enforces the session-bound CSRF hash.
/// Returns the parsed form and the session workspace on success.
async fn run_control_prelude(
    state: &Arc<WebState>,
    req: &mut Request,
) -> Result<(WorkspaceId, HashMap<String, Vec<String>>), Box<Response>> {
    if req
        .headers()
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .is_none_or(|v| v.is_empty())
    {
        return Err(Box::new(render_run_control_failure(StatusCode::FORBIDDEN)));
    }
    let form = parse_body_form(req)
        .await
        .map_err(|_| Box::new(render_run_control_failure(StatusCode::FORBIDDEN)))?;
    let csrf_fields = form.get("csrf").map_or(0, Vec::len);
    if csrf_fields != 1 {
        return Err(Box::new(render_run_control_failure(StatusCode::FORBIDDEN)));
    }
    let Some(csrf_value) = form
        .get("csrf")
        .and_then(|v| v.first())
        .and_then(|v| b64::decode(v))
    else {
        return Err(Box::new(render_run_control_failure(StatusCode::FORBIDDEN)));
    };
    let Some(sess) = active_session_with_csrf(state, req.headers(), csrf_value).await else {
        return Err(Box::new(render_run_control_failure(StatusCode::FORBIDDEN)));
    };
    Ok((sess.workspace_id, form))
}

/// `scopeRunForControl` — resolves the posted run id inside the
/// caller's session workspace. Malformed, absent and cross-workspace
/// ids are the same generic 404; a projection failure is a bare 503;
/// an unwired Runs port is the same 503. The probe is `run_scope` —
/// the single-column `workspace_id` read — not the full `run_for_id`
/// projection.
async fn scope_run_for_control(
    state: &Arc<WebState>,
    workspace_id: WorkspaceId,
    run_id_text: &str,
) -> Result<RunId, Box<Response>> {
    let Ok(run_id) = RunId::parse(run_id_text) else {
        return Err(Box::new(render_not_found()));
    };
    let Some(reader) = state.runs.clone() else {
        return Err(Box::new(error::reject(StatusCode::SERVICE_UNAVAILABLE, "")));
    };
    match reader.run_scope(run_id).await {
        Ok(Some(scope)) if scope == workspace_id => Ok(run_id),
        Ok(_) => Err(Box::new(render_not_found())),
        Err(_) => Err(Box::new(error::reject(StatusCode::SERVICE_UNAVAILABLE, ""))),
    }
}

/// `scopeNodeForControl` — resolves the posted node id inside the
/// session workspace AND proves it belongs to `run_id` — a node id of
/// another run is the same generic 404 as an absent one, so a
/// decide/cancel form can never act on a node the operator did not
/// name.
async fn scope_node_for_control(
    state: &Arc<WebState>,
    workspace_id: WorkspaceId,
    run_id: RunId,
    node_id_text: &str,
) -> Result<GraphNode, Box<Response>> {
    let Ok(node_id) = WorkflowNodeId::parse(node_id_text) else {
        return Err(Box::new(render_not_found()));
    };
    let Some(reader) = state.runs.clone() else {
        return Err(Box::new(error::reject(StatusCode::SERVICE_UNAVAILABLE, "")));
    };
    let node = match reader.node_for_id(workspace_id, node_id).await {
        Ok(n) => n,
        Err(f) if f.kind() == central_foundation::failure::FailureKind::NotFound => {
            return Err(Box::new(render_not_found()));
        }
        Err(_) => return Err(Box::new(error::reject(StatusCode::SERVICE_UNAVAILABLE, ""))),
    };
    if node.run_id != run_id {
        return Err(Box::new(render_not_found()));
    }
    Ok(node)
}

// ---------------------------------------------------------------------------
// Reason extraction — spec vocabularies render inline, verbatim
// ---------------------------------------------------------------------------

/// `workflowReasonCode` / `checkpointReasonCode` — the domain failure's
/// stable machine code (`Failure::code`) is the closed spec vocabulary
/// the refusal renders verbatim; it never carries node keys or
/// workspace detail.
fn reason_code(f: &DomainFailure) -> String {
    f.code().to_string()
}

/// `runDecisionFingerprint` — the spec-5 replay-compare value a decide
/// POST commits: SHA-256 over the compact canonical JSON object
/// `{"decision","node_id","run_id"}` — byte-for-byte the fingerprint
/// the CLI's `central node decide` computes, so a decision issued from
/// either surface dedupes on the same `attempt_decisions` row.
fn run_decision_fingerprint(run_id: RunId, node_id: WorkflowNodeId, decision: &str) -> [u8; 32] {
    let payload = format!(
        "{{\"decision\":{},\"node_id\":\"{}\",\"run_id\":\"{}\"}}",
        serde_json::to_string(decision).unwrap_or_else(|_| "\"\"".to_string()),
        node_id,
        run_id
    );
    Sha256::digest(payload.as_bytes()).into()
}

// ---------------------------------------------------------------------------
// View models
// ---------------------------------------------------------------------------

/// One rendered verdict line of a control result: the subject (node
/// key, checkpoint id, "run"), the outcome word, and the journaled
/// reason code when the store refused.
struct ControlOutcomeRow {
    subject: String,
    verdict: String,
    reason: String,
    detail: String,
}

/// The `run_control_result` view model: the action taken, per-subject
/// verdict rows, and — for checkpoint create — the fresh resume token.
struct RunControlResultModel {
    run_id: String,
    action: String,
    rows: Vec<ControlOutcomeRow>,
    token: String,
    checkpoint_id: String,
    collected: Option<i64>,
    ok: bool,
}

/// One node's row of the controls page: identity, status badge, and
/// which forms its state admits.
struct RunControlNodeRow {
    id: String,
    key: String,
    badge: String,
    badge_class: String,
    reason: String,
    /// Renders the cancel form on every non-terminal node — the store
    /// itself denies terminal roots, so the form is honest about which
    /// nodes accept it. Ambiguous nodes are also cancellable
    /// (`cancel_node` parks an ambiguous root's untouched state and
    /// cascades past it).
    cancellable: bool,
    /// Renders the two decide forms; the decision is one row ever,
    /// replay-deduped by the store.
    ambiguous: bool,
}

/// One listed checkpoint with its retention class and the pin/unpin
/// form the class implies.
struct RunControlCheckpointRow {
    id: String,
    seq: i64,
    gc_class: String,
    /// Anchor node key, falling back to the node id.
    anchor: String,
    created: String,
    expires: String,
    pinnable: bool,
    pinned: bool,
}

/// The `run_controls` view model.
struct RunControlsModel {
    run_id: String,
    status: String,
    label: String,
    run_key: String,
    csrf_field: String,

    nodes: Vec<RunControlNodeRow>,
    nodes_empty: bool,

    checkpoints: Vec<RunControlCheckpointRow>,

    /// Per-port availability flags: an unwired port's forms are absent
    /// and the notice names the missing control — disabled silently is
    /// never honest.
    can_cancel: bool,
    can_decide: bool,
    can_checkpoint: bool,
    can_resume: bool,
    any_control: bool,
}

/// `renderRunControlResult` — the outcome page of a control POST with
/// the mandatory harness banner. Verdicts render at 200.
async fn render_run_control_result(
    state: &Arc<WebState>,
    workspace_id: WorkspaceId,
    vm: RunControlResultModel,
) -> Response {
    let banner = harness_banner(state, workspace_id).await;
    html_response(
        StatusCode::OK,
        &RunControlResultTemplate { vm, banner }.render(),
    )
}

// ---------------------------------------------------------------------------
// GET /app/runs/controls — the control surface
// ---------------------------------------------------------------------------

/// `ServeRunControls` — `GET /app/runs/controls?run=<id>`: the
/// run-scoped operator-control page. A read GET on the read-route
/// precedent (unauthenticated → bootstrap shell, absent or
/// cross-workspace run → generic 404); the POST forms it carries are
/// the actual control surface and each enforces its own CSRF/session
/// prelude.
pub(crate) async fn serve_run_controls(state: Arc<WebState>, req: Request) -> Response {
    let Some(sess) = active_session(&state, req.headers()).await else {
        return render_bootstrap(&req, StatusCode::OK, "");
    };
    let Some(reader) = state.runs.clone() else {
        return error::reject(StatusCode::SERVICE_UNAVAILABLE, "");
    };
    let workspace_id = sess.workspace_id;
    let query = req.uri().query().map(str::to_string);
    let Some(run_id) = query
        .as_deref()
        .and_then(|q| query_value(q, "run"))
        .and_then(|v| RunId::parse(&v).ok())
    else {
        return render_not_found();
    };
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

    let mut vm = RunControlsModel {
        run_id: run_id.to_string(),
        status: summary.status.clone(),
        label: run_view_status_label(&summary.status).to_string(),
        run_key: summary.run_key.clone().unwrap_or_default(),
        csrf_field: session_csrf_value(&req),
        nodes: Vec::new(),
        nodes_empty: false,
        checkpoints: Vec::new(),
        can_cancel: state.controls.canceller.is_some(),
        can_decide: state.controls.resolver.is_some(),
        can_checkpoint: state.controls.checkpoints.is_some(),
        can_resume: state.controls.resumer.is_some(),
        any_control: false,
    };
    vm.any_control = vm.can_cancel || vm.can_decide || vm.can_checkpoint || vm.can_resume;

    let node_keys: BTreeMap<WorkflowNodeId, &str> =
        graph.nodes.iter().map(|n| (n.id, n.key.as_str())).collect();
    for node in &graph.nodes {
        let status = NodeStatus::parse(&node.status);
        let badge = badge_token(node);
        vm.nodes.push(RunControlNodeRow {
            id: node.id.to_string(),
            key: node.key.clone(),
            badge_class: node_badge_class(&badge).to_string(),
            badge,
            reason: node.reason.clone(),
            cancellable: vm.can_cancel && !status.is_some_and(|s| s.is_terminal()),
            ambiguous: vm.can_decide && status == Some(NodeStatus::AttemptAmbiguous),
        });
    }
    vm.nodes_empty = vm.nodes.is_empty();

    if let Some(checkpoints) = state.controls.checkpoints.clone() {
        let Ok(list) = checkpoints.list_checkpoints(run_id).await else {
            return error::reject(StatusCode::SERVICE_UNAVAILABLE, "");
        };
        for c in list {
            let anchor = node_keys
                .get(&c.node_id)
                .filter(|k| !k.is_empty())
                .map_or_else(|| c.node_id.to_string(), |k| (*k).to_string());
            let pinned = c.gc_class == GcClass::Pinned;
            vm.checkpoints.push(RunControlCheckpointRow {
                id: c.id.to_string(),
                seq: c.checkpoint_seq,
                gc_class: c.gc_class.as_str().to_string(),
                anchor,
                created: format_timestamp(c.created_at),
                expires: c.expires_at.map_or_else(String::new, format_timestamp),
                pinnable: !pinned,
                pinned,
            });
        }
    }
    let banner = harness_banner(&state, workspace_id).await;
    html_response(StatusCode::OK, &RunControlsTemplate { vm, banner }.render())
}

// ---------------------------------------------------------------------------
// POST /app/runs/controls/cancel-run — cancel every root of a run
// ---------------------------------------------------------------------------

/// `cancelAffectedRows` — re-reads the run's materialized graph once
/// and labels every affected node by the state it actually holds now:
/// cancelled, parked in `attempt_ambiguous` awaiting an operator
/// decision, or still live with a journaled `cancel_requested`. The
/// post-commit read is what makes the report honest rather than a
/// re-statement of the plan.
async fn cancel_affected_rows(
    state: &Arc<WebState>,
    run_id: RunId,
    affected: &[WorkflowNodeId],
) -> Vec<ControlOutcomeRow> {
    if affected.is_empty() {
        return Vec::new();
    }
    let mut states: BTreeMap<WorkflowNodeId, String> = BTreeMap::new();
    let mut keys: BTreeMap<WorkflowNodeId, String> = BTreeMap::new();
    if let Some(reader) = state.runs.clone()
        && let Ok(graph) = reader.graph_for_run(run_id).await
    {
        for node in &graph.nodes {
            states.insert(node.id, node.status.clone());
            keys.insert(node.id, node.key.clone());
        }
    }
    let mut rows = Vec::with_capacity(affected.len());
    for id in affected {
        let subject = keys
            .get(id)
            .filter(|k| !k.is_empty())
            .map_or_else(|| id.to_string(), Clone::clone);
        let mut row = ControlOutcomeRow {
            subject,
            verdict: String::new(),
            reason: String::new(),
            detail: String::new(),
        };
        match states.get(id).map_or("", String::as_str) {
            "cancelled" => row.verdict = "cancelled".to_string(),
            "attempt_ambiguous" => {
                row.verdict = "parked".to_string();
                row.detail = "attempt_ambiguous -- requires an operator decision".to_string();
            }
            "" => {
                row.verdict = "affected".to_string();
                row.detail = "post-commit state could not be re-read".to_string();
            }
            other => {
                row.verdict = "cancel requested".to_string();
                row.detail = format!("live node -- state {other}, cancel_requested journaled");
            }
        }
        rows.push(row);
    }
    rows
}

/// `ServeRunCancel` — cancels a whole run: the roots are the nodes that
/// never appear as a dependent, and `cancel_node` is applied to each
/// root. Per-root verdicts aggregate — a terminal root's DENIAL and a
/// cascade's ambiguous blocks render their reason/state inline, and
/// the post-commit state of every affected node is re-read.
pub(crate) async fn serve_control_cancel_run(state: Arc<WebState>, mut req: Request) -> Response {
    let (workspace_id, form) = match run_control_prelude(&state, &mut req).await {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let run_id =
        match scope_run_for_control(&state, workspace_id, form_value(&form, "run_id")).await {
            Ok(id) => id,
            Err(resp) => return *resp,
        };
    let Some(canceller) = state.controls.canceller.clone() else {
        return error::reject(StatusCode::SERVICE_UNAVAILABLE, "");
    };
    let Some(reader) = state.runs.clone() else {
        return error::reject(StatusCode::SERVICE_UNAVAILABLE, "");
    };
    let Ok(graph) = reader.graph_for_run(run_id).await else {
        return error::reject(StatusCode::SERVICE_UNAVAILABLE, "");
    };

    // Roots = nodes with no incoming dependency edge of any kind.
    let dependents: std::collections::BTreeSet<&str> =
        graph.edges.iter().map(|e| e.to_key.as_str()).collect();
    let roots: Vec<&GraphNode> = graph
        .nodes
        .iter()
        .filter(|n| !dependents.contains(n.key.as_str()))
        .collect();

    let mut vm = RunControlResultModel {
        run_id: run_id.to_string(),
        action: "Cancel run".to_string(),
        rows: Vec::new(),
        token: String::new(),
        checkpoint_id: String::new(),
        collected: None,
        ok: false,
    };
    if roots.is_empty() {
        vm.rows.push(ControlOutcomeRow {
            subject: "run".to_string(),
            verdict: "no-op".to_string(),
            reason: String::new(),
            detail: "the run has no root nodes -- nothing to cancel".to_string(),
        });
        return render_run_control_result(&state, workspace_id, vm).await;
    }
    let mut affected: Vec<WorkflowNodeId> = Vec::new();
    for root in &roots {
        match canceller.cancel_node(root.id, ACTOR_RUN_CONTROL).await {
            Err(f) => vm.rows.push(ControlOutcomeRow {
                subject: root.key.clone(),
                verdict: "refused".to_string(),
                reason: reason_code(&f),
                detail: String::new(),
            }),
            Ok(ids) => {
                vm.rows.push(ControlOutcomeRow {
                    subject: root.key.clone(),
                    verdict: "cascade committed".to_string(),
                    reason: String::new(),
                    detail: format!("{} node(s) affected", ids.len()),
                });
                affected.extend(ids);
            }
        }
    }
    vm.rows
        .extend(cancel_affected_rows(&state, run_id, &affected).await);
    render_run_control_result(&state, workspace_id, vm).await
}

/// `ServeRunNodeCancel` — applies `cancel_node` to one node of a run
/// (the same cascade semantics as run cancel, scoped to the node's
/// subtree).
pub(crate) async fn serve_control_cancel_node(state: Arc<WebState>, mut req: Request) -> Response {
    let (workspace_id, form) = match run_control_prelude(&state, &mut req).await {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let run_id =
        match scope_run_for_control(&state, workspace_id, form_value(&form, "run_id")).await {
            Ok(id) => id,
            Err(resp) => return *resp,
        };
    let node =
        match scope_node_for_control(&state, workspace_id, run_id, form_value(&form, "node_id"))
            .await
        {
            Ok(n) => n,
            Err(resp) => return *resp,
        };
    let Some(canceller) = state.controls.canceller.clone() else {
        return error::reject(StatusCode::SERVICE_UNAVAILABLE, "");
    };
    let mut vm = RunControlResultModel {
        run_id: run_id.to_string(),
        action: "Cancel node".to_string(),
        rows: Vec::new(),
        token: String::new(),
        checkpoint_id: String::new(),
        collected: None,
        ok: false,
    };
    match canceller.cancel_node(node.id, ACTOR_RUN_CONTROL).await {
        Err(f) => vm.rows.push(ControlOutcomeRow {
            subject: node.key.clone(),
            verdict: "refused".to_string(),
            reason: reason_code(&f),
            detail: String::new(),
        }),
        Ok(affected) => {
            vm.ok = true;
            vm.rows.push(ControlOutcomeRow {
                subject: node.key.clone(),
                verdict: "cascade committed".to_string(),
                reason: String::new(),
                detail: format!("{} node(s) affected", affected.len()),
            });
            vm.rows
                .extend(cancel_affected_rows(&state, run_id, &affected).await);
        }
    }
    render_run_control_result(&state, workspace_id, vm).await
}

// ---------------------------------------------------------------------------
// POST /app/runs/controls/decide — the operator decision
// ---------------------------------------------------------------------------

/// `ServeRunNodeDecide` — records the operator's one-row-ever
/// `attempt_decision` on an `attempt_ambiguous` node. The decision
/// vocabulary is exactly spec-1's resume|rerun pair — anything else is
/// a grammar refusal before the store is touched — and the fingerprint
/// is byte-identical to the CLI's.
pub(crate) async fn serve_control_decide(state: Arc<WebState>, mut req: Request) -> Response {
    let (workspace_id, form) = match run_control_prelude(&state, &mut req).await {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let decision = form_value(&form, "decision").to_string();
    if !ambiguous_decision_known(&decision) {
        return render_run_control_failure(StatusCode::BAD_REQUEST);
    }
    let run_id =
        match scope_run_for_control(&state, workspace_id, form_value(&form, "run_id")).await {
            Ok(id) => id,
            Err(resp) => return *resp,
        };
    let node =
        match scope_node_for_control(&state, workspace_id, run_id, form_value(&form, "node_id"))
            .await
        {
            Ok(n) => n,
            Err(resp) => return *resp,
        };
    let Some(resolver) = state.controls.resolver.clone() else {
        return error::reject(StatusCode::SERVICE_UNAVAILABLE, "");
    };
    let fingerprint = run_decision_fingerprint(run_id, node.id, &decision);
    let mut vm = RunControlResultModel {
        run_id: run_id.to_string(),
        action: "Node decision".to_string(),
        rows: Vec::new(),
        token: String::new(),
        checkpoint_id: String::new(),
        collected: None,
        ok: false,
    };
    match resolver
        .resolve_ambiguous(node.id, &decision, fingerprint, ACTOR_RUN_CONTROL)
        .await
    {
        Err(f) => vm.rows.push(ControlOutcomeRow {
            subject: node.key.clone(),
            verdict: "refused".to_string(),
            reason: reason_code(&f),
            detail: String::new(),
        }),
        Ok(()) => {
            vm.ok = true;
            vm.rows.push(ControlOutcomeRow {
                subject: node.key.clone(),
                verdict: "decision recorded".to_string(),
                reason: String::new(),
                detail: format!(
                    "decision={decision} -- replays dedupe on the recorded attempt_decisions row"
                ),
            });
        }
    }
    render_run_control_result(&state, workspace_id, vm).await
}

// ---------------------------------------------------------------------------
// POST /app/runs/controls/resume — resume a subtree from a token
// ---------------------------------------------------------------------------

/// `ServeRunResume` — runs the spec-D3 preflight then the D4 subtree
/// resume for the posted token. The resolved record's workspace must
/// equal the session workspace before any mutation is attempted — a
/// foreign token's checkpoint is the same generic 404 as an absent
/// run.
pub(crate) async fn serve_control_resume(state: Arc<WebState>, mut req: Request) -> Response {
    let (workspace_id, form) = match run_control_prelude(&state, &mut req).await {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let token = form_value(&form, "token").to_string();
    if token.is_empty() {
        return render_run_control_failure(StatusCode::BAD_REQUEST);
    }
    let Some(resumer) = state.controls.resumer.clone() else {
        return error::reject(StatusCode::SERVICE_UNAVAILABLE, "");
    };
    let record: ResumeCheckpoint = match resumer.resume_preflight(&token).await {
        Err(f) => {
            let vm = RunControlResultModel {
                run_id: form_value(&form, "run_id").to_string(),
                action: "Resume from checkpoint".to_string(),
                rows: vec![ControlOutcomeRow {
                    subject: "checkpoint".to_string(),
                    verdict: "refused".to_string(),
                    reason: reason_code(&f),
                    detail: String::new(),
                }],
                token: String::new(),
                checkpoint_id: String::new(),
                collected: None,
                ok: false,
            };
            return render_run_control_result(&state, workspace_id, vm).await;
        }
        Ok(r) => r,
    };
    if record.workspace_id != workspace_id {
        return render_not_found();
    }
    let mut vm = RunControlResultModel {
        run_id: record.run_id.to_string(),
        action: "Resume from checkpoint".to_string(),
        rows: Vec::new(),
        token: String::new(),
        checkpoint_id: record.id.to_string(),
        collected: None,
        ok: false,
    };
    match resumer.resume_subtree(&token, ACTOR_RUN_CONTROL).await {
        Err(f) => vm.rows.push(ControlOutcomeRow {
            subject: "run".to_string(),
            verdict: "refused".to_string(),
            reason: reason_code(&f),
            detail: String::new(),
        }),
        Ok(()) => {
            vm.ok = true;
            vm.rows.push(ControlOutcomeRow {
                subject: "run".to_string(),
                verdict: "resumed".to_string(),
                reason: String::new(),
                detail: format!("subtree rebuilt from checkpoint {}", record.id),
            });
        }
    }
    render_run_control_result(&state, workspace_id, vm).await
}

// ---------------------------------------------------------------------------
// POST /app/runs/controls/checkpoint-write
// ---------------------------------------------------------------------------

/// `ServeRunCheckpointCreate` — writes one durable checkpoint anchored
/// at the named node of the run. `seq` is the caller-supplied
/// `(attempt_id, checkpoint_seq)` idempotency coordinate and is
/// required >= 1; the store dedupes on it — a retry at the same seq
/// replays the recorded row and a differing payload refuses
/// `DUPLICATE_IDEMPOTENCY_KEY`, rendered inline.
pub(crate) async fn serve_control_checkpoint_write(
    state: Arc<WebState>,
    mut req: Request,
) -> Response {
    let (workspace_id, form) = match run_control_prelude(&state, &mut req).await {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let Ok(seq) = form_value(&form, "seq").parse::<i64>() else {
        return render_run_control_failure(StatusCode::BAD_REQUEST);
    };
    if seq < 1 {
        return render_run_control_failure(StatusCode::BAD_REQUEST);
    }
    let gc_class = match form_value(&form, "gc_class") {
        "" => GcClass::Supersedeable,
        raw => match GcClass::parse(raw) {
            Ok(c) => c,
            Err(_) => return render_run_control_failure(StatusCode::BAD_REQUEST),
        },
    };
    let run_id =
        match scope_run_for_control(&state, workspace_id, form_value(&form, "run_id")).await {
            Ok(id) => id,
            Err(resp) => return *resp,
        };
    let node =
        match scope_node_for_control(&state, workspace_id, run_id, form_value(&form, "node_id"))
            .await
        {
            Ok(n) => n,
            Err(resp) => return *resp,
        };
    let Some(checkpoints) = state.controls.checkpoints.clone() else {
        return error::reject(StatusCode::SERVICE_UNAVAILABLE, "");
    };
    let mut vm = RunControlResultModel {
        run_id: run_id.to_string(),
        action: "Write checkpoint".to_string(),
        rows: Vec::new(),
        token: String::new(),
        checkpoint_id: String::new(),
        collected: None,
        ok: false,
    };
    match checkpoints
        .write_checkpoint(run_id, node.id, ACTOR_RUN_CONTROL, gc_class, seq)
        .await
    {
        Err(f) => vm.rows.push(ControlOutcomeRow {
            subject: node.key.clone(),
            verdict: "refused".to_string(),
            reason: reason_code(&f),
            detail: String::new(),
        }),
        Ok(record) => {
            vm.ok = true;
            vm.checkpoint_id = record.id.to_string();
            vm.token = record.encode_token();
            vm.rows.push(ControlOutcomeRow {
                subject: node.key.clone(),
                verdict: "written".to_string(),
                reason: String::new(),
                detail: format!(
                    "seq={} class={} watermark={}",
                    record.checkpoint_seq,
                    record.gc_class.as_str(),
                    record.event_watermark
                ),
            });
        }
    }
    render_run_control_result(&state, workspace_id, vm).await
}

// ---------------------------------------------------------------------------
// POST /app/runs/controls/checkpoint-pin + -unpin — retention classes
// ---------------------------------------------------------------------------

/// `serveRunCheckpointClass` — sets a checkpoint's retention class.
/// Pin → `pinned`; unpin → `supersedeable` (the least-retentive class —
/// an unpinned checkpoint must never become uncollectable by accident).
/// Both are state-convergent writes: the checkpoint id is scope-checked
/// through its own record's workspace before the class change is
/// attempted.
async fn serve_checkpoint_class(
    state: Arc<WebState>,
    mut req: Request,
    class: GcClass,
    action: &str,
    verdict: &str,
) -> Response {
    let (workspace_id, form) = match run_control_prelude(&state, &mut req).await {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let Ok(checkpoint_id) = ResumeCheckpointId::parse(form_value(&form, "checkpoint_id")) else {
        return render_not_found();
    };
    let Some(checkpoints) = state.controls.checkpoints.clone() else {
        return error::reject(StatusCode::SERVICE_UNAVAILABLE, "");
    };
    let record = match checkpoints.load_checkpoint(checkpoint_id).await {
        // `CHECKPOINT_NOT_FOUND` and any other spec-3 refusal answer the
        // same generic 404 as an absent run — existence is never
        // disclosed across workspaces. Infrastructure failures (the
        // store-error kinds) alone answer the bare 503.
        Err(f)
            if !matches!(
                f.kind(),
                central_foundation::failure::FailureKind::Internal
                    | central_foundation::failure::FailureKind::Unavailable
            ) =>
        {
            return render_not_found();
        }
        Err(_) => return error::reject(StatusCode::SERVICE_UNAVAILABLE, ""),
        Ok(r) => r,
    };
    if record.workspace_id != workspace_id {
        return render_not_found();
    }
    let mut vm = RunControlResultModel {
        run_id: record.run_id.to_string(),
        action: action.to_string(),
        rows: Vec::new(),
        token: String::new(),
        checkpoint_id: checkpoint_id.to_string(),
        collected: None,
        ok: false,
    };
    match checkpoints.update_gc_class(checkpoint_id, class).await {
        Err(f) => vm.rows.push(ControlOutcomeRow {
            subject: checkpoint_id.to_string(),
            verdict: "refused".to_string(),
            reason: reason_code(&f),
            detail: String::new(),
        }),
        Ok(()) => {
            vm.ok = true;
            vm.rows.push(ControlOutcomeRow {
                subject: checkpoint_id.to_string(),
                verdict: verdict.to_string(),
                reason: String::new(),
                detail: format!("gc_class={}", class.as_str()),
            });
        }
    }
    render_run_control_result(&state, workspace_id, vm).await
}

/// `ServeRunCheckpointPin` — sets a checkpoint's retention class to
/// `pinned`.
pub(crate) async fn serve_control_checkpoint_pin(state: Arc<WebState>, req: Request) -> Response {
    serve_checkpoint_class(state, req, GcClass::Pinned, "Pin checkpoint", "pinned").await
}

/// `ServeRunCheckpointUnpin` — returns a checkpoint to the
/// `supersedeable` retention class.
pub(crate) async fn serve_control_checkpoint_unpin(state: Arc<WebState>, req: Request) -> Response {
    serve_checkpoint_class(
        state,
        req,
        GcClass::Supersedeable,
        "Unpin checkpoint",
        "unpinned",
    )
    .await
}

// ---------------------------------------------------------------------------
// POST /app/runs/controls/checkpoint-gc — one manual collect pass
// ---------------------------------------------------------------------------

/// `ServeRunCheckpointGC` — runs one checkpoint GC pass, the same
/// `Collect` selection the janitor runs on schedule. The collected
/// count always renders; a partial pass additionally renders
/// `CHECKPOINT_GC_PARTIAL` since at least one anchor's pass failed.
pub(crate) async fn serve_control_checkpoint_gc(
    state: Arc<WebState>,
    mut req: Request,
) -> Response {
    let (workspace_id, form) = match run_control_prelude(&state, &mut req).await {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let Some(checkpoints) = state.controls.checkpoints.clone() else {
        return error::reject(StatusCode::SERVICE_UNAVAILABLE, "");
    };
    let outcome = checkpoints.collect(time::OffsetDateTime::now_utc()).await;
    let mut vm = RunControlResultModel {
        run_id: form_value(&form, "run_id").to_string(),
        action: "Checkpoint GC".to_string(),
        rows: Vec::new(),
        token: String::new(),
        checkpoint_id: String::new(),
        collected: None,
        ok: false,
    };
    match outcome {
        Ok(outcome) => {
            vm.collected = Some(outcome.collected as i64);
            if outcome.has_failures() {
                vm.rows.push(ControlOutcomeRow {
                    subject: "gc pass".to_string(),
                    verdict: "partial".to_string(),
                    reason: "CHECKPOINT_GC_PARTIAL".to_string(),
                    detail: format!(
                        "collected {} row(s) before the pass failed",
                        outcome.collected
                    ),
                });
            } else {
                vm.ok = true;
                vm.rows.push(ControlOutcomeRow {
                    subject: "gc pass".to_string(),
                    verdict: "collected".to_string(),
                    reason: String::new(),
                    detail: format!("{} checkpoint row(s) deleted", outcome.collected),
                });
            }
        }
        Err(_) => {
            vm.collected = Some(0);
            vm.rows.push(ControlOutcomeRow {
                subject: "gc pass".to_string(),
                verdict: "partial".to_string(),
                reason: "CHECKPOINT_GC_PARTIAL".to_string(),
                detail: "collected 0 row(s) before the pass failed".to_string(),
            });
        }
    }
    render_run_control_result(&state, workspace_id, vm).await
}

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

/// `runControlsModel` + banner — the control surface.
#[derive(Template)]
#[template(path = "runs/controls.html")]
struct RunControlsTemplate {
    vm: RunControlsModel,
    banner: super::harness::HarnessBannerView,
}

impl RunControlsTemplate {
    fn render(&self) -> String {
        <Self as askama::Template>::render(self)
            .unwrap_or_else(|_| crate::rendering::render_error_page("Run controls", "Unavailable"))
    }
}

/// `runControlResultModel` + banner — the control outcome page.
#[derive(Template)]
#[template(path = "runs/control_result.html")]
struct RunControlResultTemplate {
    vm: RunControlResultModel,
    banner: super::harness::HarnessBannerView,
}

impl RunControlResultTemplate {
    fn render(&self) -> String {
        <Self as askama::Template>::render(self).unwrap_or_else(|_| {
            crate::rendering::render_error_page("Run control result", "Unavailable")
        })
    }
}

/// Keep `RunGraph` referenced for the doc-commented scope helpers.
#[allow(dead_code)]
fn _graph_marker(_: &RunGraph) {}
