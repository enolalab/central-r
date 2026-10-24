//! The `/app` handlers — the Task 12 port of upstream `handler.go` and
//! the handler half of `harness.go`. Middleware has already enforced
//! method, Origin, session and session-CSRF per the route policy; the
//! handlers re-assert the origin field, consume the extension seams, and
//! add the load-and-gate preludes upstream keeps handler-side.

use std::collections::BTreeSet;
use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;
use central_artifact::app::{DeliverArtifactOutcome, DeliverReadyArtifactRequest};
use central_execution::domain::TrustedScope;
use central_foundation::identity::{ArtifactId, TaskId};
use central_session::domain::Session;
use central_task::app::CommandMeta;
use central_task::domain::{
    CancelUnclaimedTaskRequest, MutationInput, PermissionPolicy, RequestCancellationRequest,
    RerunCancelledTaskRequest, SubmitTaskRequest, TaskStatus,
};
use central_task::port::LoadedAggregate;
use central_task::query::{
    MAX_TASK_LIST_PAGE_SIZE, TaskDetailRequest, TaskEventLogRequest, TaskListRequest,
};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;

use super::activity_view::build_activity;
use super::budget_view;
use super::harness::{
    self, ERR_HARNESS_NOT_RESOLVABLE, ERR_HARNESS_PERMISSION_NOT_PENDING, ERR_HARNESS_STARTING,
    HarnessPermissionDecision, HarnessResolveRequest,
};
use super::office_view::build_office;
use super::overview_view::{summarize_overview, waiting_reason_phrase};
use super::permission_form;
use super::permission_view::{
    self, PERMISSION_NOT_PENDING_MSG, PERMISSION_STALE_QUERY, PERMISSION_STALE_VALUE,
};
use super::repository_analysis;
use super::task_view::action_notice_text;
use super::task_view::{
    self, ACTION_NOTICE_ALREADY_CANCELLED, ACTION_NOTICE_CANCEL_LOST_CLAIM, ACTION_NOTICE_QUERY,
};
use super::{
    WebState, active_session, authenticated, clear_session_cookies, duplicate_cookie_name,
    form_value, html_response, issue_fresh_preauth, parse_body_form, redirect_303,
    render_bootstrap, render_harness_starting, render_not_found, session_csrf_value,
    task_action_failure,
};
use crate::assets;
use crate::b64;
use crate::error;
use crate::health::ProbeState;

/// `artifactPreviewMaxBytes` — how much of a ready Artifact's raw body
/// the preview route reads. HTML escaping expands bytes ~5× in the
/// worst case; 128 KiB stays far under the page's buffered cap.
const ARTIFACT_PREVIEW_MAX_BYTES: usize = 128 * 1024;

/// The upstream fixed `Content-Disposition` of the download route.
const DOWNLOAD_DISPOSITION: &str = "attachment; filename=\"report.md\"";

// ---------------------------------------------------------------------------
// Root, bootstrap, logout
// ---------------------------------------------------------------------------

/// `ServeRoot` — the signed-in ready shell for an active session, the
/// bootstrap shell otherwise.
pub(crate) async fn serve_root(state: Arc<WebState>, req: Request) -> Response {
    if state.readiness.health().state == ProbeState::Ready
        && active_session(&state, req.headers()).await.is_some()
    {
        return html_response(
            StatusCode::OK,
            &super::ReadyTemplate {
                csrf_field: session_csrf_value(&req),
            }
            .render(),
        );
    }
    render_bootstrap(&req, StatusCode::OK, "")
}

/// `ServeBootstrap` — the labelled bootstrap form (the middleware minted
/// the pre-auth CSRF cookie on this safe route).
pub(crate) async fn serve_bootstrap(state: Arc<WebState>, req: Request) -> Response {
    let _ = state;
    render_bootstrap(&req, StatusCode::OK, "")
}

/// `ServeLogout` — revokes the session server-side, clears both session
/// cookies, mints a fresh pre-auth CSRF for immediate re-bootstrap, and
/// renders the recovery shell. Failure shapes never disclose whether the
/// session was valid.
pub(crate) async fn serve_logout(state: Arc<WebState>, req: Request) -> Response {
    // Defense-in-depth Origin re-assertion — the admission/origin
    // middleware is the primary gate; this keeps the handler safe when
    // mounted behind a thinner chain.
    if req.headers().get(header::ORIGIN).is_none() {
        return logout_failure(&state, StatusCode::FORBIDDEN, LOGOUT_UNCONFIRMED);
    }
    if duplicate_cookie_name(&req, crate::cookies::SESSION_COOKIE)
        || duplicate_cookie_name(&req, crate::cookies::SESSION_CSRF_COOKIE)
    {
        return logout_failure(&state, StatusCode::FORBIDDEN, LOGOUT_UNCONFIRMED);
    }
    let mut req = req;
    let form = match parse_body_form(&mut req).await {
        Ok(f) if f.get("csrf").map_or(0, Vec::len) == 1 => f,
        _ => return logout_failure(&state, StatusCode::FORBIDDEN, LOGOUT_UNCONFIRMED),
    };
    let csrf_value = match b64::decode(form_value(&form, "csrf")) {
        Some(v) => v,
        None => return logout_failure(&state, StatusCode::FORBIDDEN, LOGOUT_UNCONFIRMED),
    };
    // The submitted csrf must be the session CSRF cookie itself (the
    // double-submit comparison upstream performs with
    // `subtle.ConstantTimeCompare` on the raw cookie text).
    let cookie = crate::cookies::cookie_values(req.headers(), crate::cookies::SESSION_CSRF_COOKIE);
    let presented = form_value(&form, "csrf").as_bytes();
    if cookie.len() != 1 || !crate::cookies::ct_eq(cookie[0].as_bytes(), presented) {
        return logout_failure(&state, StatusCode::FORBIDDEN, LOGOUT_UNCONFIRMED);
    }
    let sess = match active_session_with_csrf(&state, req.headers(), csrf_value).await {
        Some(s) => s,
        None => return logout_failure(&state, StatusCode::FORBIDDEN, LOGOUT_UNCONFIRMED),
    };
    if state.sessions.logout(sess.id).await.is_err() {
        return logout_failure(&state, StatusCode::SERVICE_UNAVAILABLE, LOGOUT_RETRY);
    }
    let mut headers = axum::http::HeaderMap::new();
    clear_session_cookies(&mut headers);
    let mut resp = match issue_fresh_preauth(&state, &mut headers) {
        Some(fresh) => html_response(
            StatusCode::OK,
            &super::RecoveryTemplate {
                csrf_field: fresh,
                error: String::new(),
            }
            .render(),
        ),
        None => html_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &super::RecoveryTemplate {
                csrf_field: String::new(),
                error: "Logout completed, but a fresh bootstrap challenge could not be issued. Reload and retry."
                    .to_string(),
            }
            .render(),
        ),
    };
    resp.headers_mut().extend(headers);
    resp
}

/// `activeSessionWithCSRF` — the genuinely CSRF-enforcing session
/// validation for the raw-body mutation/logout preludes.
async fn active_session_with_csrf(
    state: &WebState,
    headers: &axum::http::HeaderMap,
    csrf: [u8; 32],
) -> Option<Session> {
    let token = super::presented_session_token(headers)?;
    let session = state
        .sessions
        .validate(central_session::domain::ValidationRequest {
            token_hash: Sha256::digest(token).into(),
            presented_csrf_hash: Some(Sha256::digest(csrf).into()),
            epoch: (state.epoch_source)(),
        })
        .await
        .ok()?;
    (session.state == central_session::domain::SessionState::Active).then_some(session)
}

/// `renderLogoutFailure` — the fail-closed recovery shell: session
/// cookies cleared, a fresh pre-auth CSRF issued when possible.
fn logout_failure(state: &WebState, status: StatusCode, message: &str) -> Response {
    let mut headers = axum::http::HeaderMap::new();
    clear_session_cookies(&mut headers);
    let mut resp = match issue_fresh_preauth(state, &mut headers) {
        Some(fresh) => html_response(
            status,
            &super::RecoveryTemplate {
                csrf_field: fresh,
                error: message.to_string(),
            }
            .render(),
        ),
        None => html_response(
            status,
            &super::RecoveryTemplate {
                csrf_field: String::new(),
                error: format!("{message} Reload the page before trying recovery."),
            }
            .render(),
        ),
    };
    resp.headers_mut().extend(headers);
    resp
}

const LOGOUT_UNCONFIRMED: &str =
    "Logout could not be confirmed. Request a fresh recovery form and try again.";
const LOGOUT_RETRY: &str = "Logout could not be confirmed. Your previous session may still be active; sign in again only after retrying logout.";

/// `ServeAsset` — the embedded `/assets/{name}` allowlist.
pub(crate) async fn serve_asset(req: Request) -> Response {
    let name = req
        .uri()
        .path()
        .strip_prefix("/assets/")
        .unwrap_or_default();
    assets::response(name).unwrap_or_else(|| crate::error::not_found(req.uri().path()))
}

// ---------------------------------------------------------------------------
// Overview / activity / office / task list
// ---------------------------------------------------------------------------

/// `ServeOverview` — the authenticated operator landing view.
pub(crate) async fn serve_overview(state: Arc<WebState>, req: Request) -> Response {
    let Some(sess) = active_session(&state, req.headers()).await else {
        return render_bootstrap(&req, StatusCode::OK, "");
    };
    let workspace_id = sess.workspace_id;
    let projection = match state
        .tasks
        .list_tasks(TaskListRequest {
            workspace_id,
            cursor: None,
            page_size: MAX_TASK_LIST_PAGE_SIZE,
        })
        .await
    {
        Ok(p) => p,
        Err(_) => return error::reject(StatusCode::SERVICE_UNAVAILABLE, ""),
    };
    let mut vm = summarize_overview(&state.readiness.health(), &projection);
    vm.banner = harness_banner(&state, workspace_id).await;
    html_response(StatusCode::OK, &vm.render())
}

/// `ServeOffice` — the canvas visualisation of the live task projection.
pub(crate) async fn serve_office(state: Arc<WebState>, req: Request) -> Response {
    let Some(sess) = active_session(&state, req.headers()).await else {
        return render_bootstrap(&req, StatusCode::OK, "");
    };
    let workspace_id = sess.workspace_id;
    let projection = match state
        .tasks
        .list_tasks(TaskListRequest {
            workspace_id,
            cursor: None,
            page_size: MAX_TASK_LIST_PAGE_SIZE,
        })
        .await
    {
        Ok(p) => p,
        Err(_) => return error::reject(StatusCode::SERVICE_UNAVAILABLE, ""),
    };
    // Best-effort ticker events — a failed read yields an empty feed,
    // never a failed page.
    let events = state
        .tasks
        .list_task_events(TaskEventLogRequest {
            workspace_id,
            task_id: None,
            cursor: None,
            page_size: 30,
        })
        .await
        .unwrap_or_else(|_| central_task::query::TaskEventLogProjection {
            events: Vec::new(),
            next_cursor: None,
        });
    let mut vm = build_office(&state.readiness.health(), &projection, &events);
    vm.banner = harness_banner(&state, workspace_id).await;
    html_response(StatusCode::OK, &vm.render())
}

/// `ServeActivity` — the bounded newest-first lifecycle event feed.
pub(crate) async fn serve_activity(state: Arc<WebState>, req: Request) -> Response {
    let Some(sess) = active_session(&state, req.headers()).await else {
        return render_bootstrap(&req, StatusCode::OK, "");
    };
    let workspace_id = sess.workspace_id;
    let projection = match state
        .tasks
        .list_task_events(TaskEventLogRequest {
            workspace_id,
            task_id: None,
            cursor: None,
            page_size: central_task::query::DEFAULT_TASK_EVENT_LOG_PAGE_SIZE,
        })
        .await
    {
        Ok(p) => p,
        Err(_) => return error::reject(StatusCode::SERVICE_UNAVAILABLE, ""),
    };
    let mut vm = build_activity(&projection);
    vm.banner = harness_banner(&state, workspace_id).await;
    html_response(StatusCode::OK, &vm.render())
}

/// `ServeTaskList` — the bounded task list plus the submit form.
pub(crate) async fn serve_task_list(state: Arc<WebState>, req: Request) -> Response {
    let Some(sess) = active_session(&state, req.headers()).await else {
        return render_bootstrap(&req, StatusCode::OK, "");
    };
    let workspace_id = sess.workspace_id;
    let projection = match state
        .tasks
        .list_tasks(TaskListRequest {
            workspace_id,
            cursor: None,
            page_size: 0,
        })
        .await
    {
        Ok(p) => p,
        Err(_) => return error::reject(StatusCode::SERVICE_UNAVAILABLE, ""),
    };
    let policies_enabled = permission_policies_enabled(&state);
    let deny_only = harness_backend_is_deny_only(&state);
    let mut vm = task_view::TaskListTemplate {
        rows: Vec::new(),
        empty: projection.tasks.is_empty(),
        csrf_field: session_csrf_value(&req),
        allowed_roots: state.allowed_roots.clone(),
        idempotency_key: crate::cookies::mint_idempotency_key(),
        policy_select: policies_enabled && !deny_only,
        user_settings_note: "",
        auto_allow_warning: "",
        deny_only_note: "",
        budget_fields: false,
        cost_placeholder: String::new(),
        wall_clock_placeholder: String::new(),
        subscription_note: "",
        cost_disabled: false,
        banner: harness_banner(&state, workspace_id).await,
    };
    if vm.policy_select {
        vm.user_settings_note = permission_view::USER_SETTINGS_NOTE;
        vm.auto_allow_warning = permission_view::AUTO_ALLOW_WARNING;
    }
    if policies_enabled && deny_only {
        vm.deny_only_note = if harness_backend_is(&state, "codex") {
            permission_view::CODEX_DENY_ONLY_NOTE
        } else if harness_backend_is(&state, "antigravity") {
            permission_view::ANTIGRAVITY_DENY_ONLY_NOTE
        } else {
            permission_view::OPENCODE_DENY_ONLY_NOTE
        };
    }
    if budget_fields_enabled(&state)
        && let Some(h) = &state.harness
    {
        let defaults = h.budget_defaults();
        vm.subscription_note = budget_view::BUDGET_SUBSCRIPTION_NOTE;
        if harness_backend_is(&state, "codex") {
            vm.subscription_note = budget_view::CODEX_COST_NOTE;
            vm.cost_disabled = true;
        } else if harness_backend_is(&state, "antigravity") {
            vm.subscription_note = budget_view::ANTIGRAVITY_COST_NOTE;
            vm.cost_disabled = true;
        } else if harness_backend_is(&state, "opencode") {
            vm.subscription_note = budget_view::OPENCODE_COST_NOTE;
        }
        vm.budget_fields = true;
        vm.cost_placeholder = budget_view::cost_placeholder(defaults.cost_micro_usd);
        vm.wall_clock_placeholder = budget_view::wall_clock_placeholder(defaults.wall_clock);
    }
    if vm.empty {
        vm.rows.push(task_view::TaskRow {
            id: String::new(),
            title: String::new(),
            label: "Empty",
        });
    }
    for t in &projection.tasks {
        vm.rows.push(task_view::TaskRow {
            id: t.task_id.to_string(),
            title: t.title.clone(),
            label: task_view::task_status_label(t.status),
        });
    }
    html_response(StatusCode::OK, &vm.render())
}

// ---------------------------------------------------------------------------
// Task detail
// ---------------------------------------------------------------------------

/// `ServeTaskDetail` — `GET /app/tasks/detail?id=<task-id>`. A missing,
/// malformed, absent, or cross-workspace task renders the generic 404 —
/// existence is never disclosed.
pub(crate) async fn serve_task_detail(state: Arc<WebState>, req: Request) -> Response {
    let Some(sess) = active_session(&state, req.headers()).await else {
        return render_bootstrap(&req, StatusCode::OK, "");
    };
    let workspace_id = sess.workspace_id;
    let query = req.uri().query().unwrap_or_default();
    let task_id = match query_value(query, "id").and_then(|v| TaskId::parse(v).ok()) {
        Some(id) => id,
        None => return render_not_found(),
    };
    let projection = match state
        .tasks
        .task_detail(TaskDetailRequest {
            workspace_id,
            task_id,
            run_cursor: None,
            run_page_size: 0,
        })
        .await
    {
        Ok(p) => p,
        Err(f) if f.kind() == central_foundation::failure::FailureKind::NotFound => {
            return render_not_found();
        }
        Err(_) => return error::reject(StatusCode::SERVICE_UNAVAILABLE, ""),
    };
    let label = task_view::task_status_label(projection.task.status);
    // The restart barrier is resolved BEFORE the eligibility flags so
    // the rendered controls never claim an action would work that the
    // server-side mutation prelude refuses. UX consistency only — the
    // real boundary is `load_aggregate_for_mutation`'s claimability
    // check on every mutation POST.
    // Deliberate divergence from upstream: `recovery_claimability`
    // runs directly on the current run here rather than through
    // upstream's decorated first-page detail read. That is MORE
    // faithful to the §2.2 decorated projection (every page of the
    // detail view is barrier-checked, not just page one), and the
    // enforcement path is identical — the mutation prelude re-checks
    // the same gate regardless of what this page rendered.
    let (restart_barrier, barrier_reason) = match projection.task.current_run_id {
        Some(run_id) => match claimability(&state, workspace_id, task_id, run_id).await {
            Ok(c) if !c.claimable => (true, c.reason.clone()),
            _ => (false, String::new()),
        },
        None => (false, String::new()),
    };
    let mut vm = task_view::TaskDetailTemplate {
        id: projection.task.task_id.to_string(),
        title: projection.task.title.clone(),
        label,
        has_parent: projection.task.parent_task_id.is_some(),
        parent_task_id: projection
            .task
            .parent_task_id
            .map_or_else(String::new, |p| p.to_string()),
        restart_barrier,
        barrier_reason,
        waiting_reason: String::new(),
        csrf_field: session_csrf_value(&req),
        idempotency_key: crate::cookies::mint_idempotency_key(),
        cancellable: task_view::task_cancel_eligible(projection.task.status) && !restart_barrier,
        retryable: task_view::task_retry_eligible(projection.task.status) && !restart_barrier,
        rerunnable: task_view::task_rerun_eligible(projection.task.status) && !restart_barrier,
        has_artifact: projection.task.required_artifact_id.is_some(),
        artifact_id: projection
            .task
            .required_artifact_id
            .map_or_else(String::new, |a| a.to_string()),
        artifacts: task_view::build_artifact_rows(&projection.task.artifacts),
        poll_interval_ms: task_view::initial_poll_interval_ms(label),
        projection_revision: projection.task.projection_revision,
        event_revision: projection.task.event_revision,
        failure_reason: String::new(),
        budget_reason: String::new(),
        runs: task_view::build_run_history(&projection.runs),
        retry_count: projection.task.retry_count,
        created_at: super::format_timestamp(projection.task.created_at),
        updated_at: super::format_timestamp(projection.task.updated_at),
        instruction: String::new(),
        workspace_root: String::new(),
        activity: Vec::new(),
        turn_activity: Vec::new(),
        banner: harness_banner(&state, workspace_id).await,
        permission_policy: "",
        auto_allow_warning: "",
        permission_panel: None,
        permission_history: Vec::new(),
        permission_notice: "",
        action_notice: action_notice_text(query_value(query, ACTION_NOTICE_QUERY).unwrap_or("")),
        finish_cancelling: false,
        finish_cancelling_prepared: false,
        harness_resolvable: false,
        harness_resolve: harness::HarnessResolveView::default(),
        budget: None,
        task_cost: String::new(),
        retry_unavailable: "",
    };
    // The resolve panel is UX gating only; the POST re-checks durable
    // facts. On a Task waiting on an ambiguous attempt it replaces
    // Cancel: "Mark cancelled" is the cancel there.
    if !restart_barrier {
        vm.harness_resolve = harness_resolve(
            &state,
            workspace_id,
            task_id,
            projection.task.current_run_id,
            projection.task.status,
            projection.task.waiting_reason,
        )
        .await;
    }
    vm.harness_resolvable = vm.harness_resolve.offered();
    if vm.harness_resolve.mark_failed {
        vm.cancellable = false;
    }
    if projection.task.status == TaskStatus::Waiting {
        vm.waiting_reason = waiting_reason_phrase(projection.task.waiting_reason);
    }
    if label == "Unsuccessful" {
        vm.failure_reason = projection.task.failure_reason.clone();
        vm.budget_reason =
            budget_view::budget_reason_text(&projection.task.failure_reason).to_string();
    }
    // Display-only parse of the stored input — the same canonical
    // parser and allowlist the submit route validates against; a parse
    // failure simply omits the section.
    if let Ok(parsed) = repository_analysis::parse_repository_analysis_input(
        projection.task.input.as_bytes(),
        &state.allowed_roots,
    ) {
        vm.instruction = parsed.instruction;
        vm.workspace_root = parsed.workspace_root_id;
    }
    if permission_policies_enabled(&state)
        || projection.task.permission_policy != PermissionPolicy::Deny
    {
        vm.permission_policy =
            task_view::permission_policy_label(projection.task.permission_policy);
    }
    if projection.task.permission_policy == PermissionPolicy::AutoAllow {
        vm.auto_allow_warning = permission_view::AUTO_ALLOW_WARNING;
    }
    if query_value(query, PERMISSION_STALE_QUERY) == Some(PERMISSION_STALE_VALUE) {
        vm.permission_notice = PERMISSION_NOT_PENDING_MSG;
    }
    // "Finish cancelling" for a cancelling Task whose current Run was
    // never claimed, or whose prepared harness attempt was never
    // invoked (phase 3f decisions 8 and 10) — UX gating only.
    if projection.task.status == TaskStatus::Cancelling && !restart_barrier {
        match state.tasks.load_aggregate(workspace_id, task_id).await {
            Ok(loaded) if loaded.aggregate.unclaimed() => vm.finish_cancelling = true,
            _ => {
                if let (Some(h), Some(run_id)) = (&state.harness, projection.task.current_run_id)
                    && let Ok(true) = h.prepared_settleable(workspace_id, task_id, run_id).await
                {
                    vm.finish_cancelling = true;
                    vm.finish_cancelling_prepared = true;
                }
            }
        }
    }
    if let (Some(h), Some(run_id)) = (&state.harness, projection.task.current_run_id) {
        if let Ok(panel) = h.permission_panel(workspace_id, task_id, run_id).await {
            vm.permission_panel =
                permission_view::build_permission_panel(panel.as_ref(), OffsetDateTime::now_utc());
        }
        if let Ok(history) = h.permission_history(workspace_id, run_id).await {
            vm.permission_history = permission_view::build_permission_history(&history);
        }
        if let Ok(b) = h.run_budget(workspace_id, run_id).await {
            vm.budget = budget_view::build_run_budget(b.as_ref());
        }
    }
    // The Task's recorded cost against the cap, and Retry only while at
    // least US$0.01 remains — UX gating only; `ServeTaskRetry` asks
    // again. A failed read hides the button and says nothing.
    if let Some(h) = &state.harness {
        match h.retry_state(workspace_id, task_id).await {
            Err(_) => vm.retryable = false,
            Ok(st) if st.cap_micro_usd > 0 => {
                vm.task_cost = budget_view::task_cost_line(&st);
                if st.blocked && vm.retryable {
                    vm.retryable = false;
                    vm.retry_unavailable = budget_view::RETRY_UNAVAILABLE_COST_CAP;
                }
            }
            _ => {}
        }
    }
    // Best-effort per-task activity — a failed read omits the section.
    if let Ok(ev) = state
        .tasks
        .list_task_events(TaskEventLogRequest {
            workspace_id,
            task_id: Some(task_id),
            cursor: None,
            page_size: 20,
        })
        .await
    {
        vm.activity = build_activity(&ev).rows;
    }
    // Best-effort per-run attempt timeline (ADR 0021 analogue).
    if let (Some(read), Some(run_id)) = (&state.turn_activity, projection.task.current_run_id)
        && let Ok(turns) = read
            .read(central_execution::query::RunTurnActivityRequest {
                scope: TrustedScope {
                    principal_id: sess.principal_identity.clone(),
                    workspace_id,
                    capabilities: BTreeSet::new(),
                },
                workspace_id,
                task_id,
                run_id,
                cursor: String::new(),
                page_size: central_execution::query::DEFAULT_TURN_ACTIVITY_PAGE_SIZE,
            })
            .await
    {
        vm.turn_activity = task_view::build_turn_activity(&turns);
    }
    html_response(StatusCode::OK, &vm.render())
}

/// `harnessResolve` — the detail page's resolve panel: what the Task's
/// status offers, when its harness attempt waits on the operator.
async fn harness_resolve(
    state: &WebState,
    workspace_id: central_foundation::identity::WorkspaceId,
    task_id: TaskId,
    run_id: Option<central_foundation::identity::RunId>,
    status: TaskStatus,
    reason: Option<central_task::domain::WaitingReason>,
) -> harness::HarnessResolveView {
    let mut view = harness::resolve_actions(status, reason);
    let (Some(h), Some(run_id)) = (&state.harness, run_id) else {
        return harness::HarnessResolveView::default();
    };
    if !view.offered() {
        return harness::HarnessResolveView::default();
    }
    match h.resolvable(workspace_id, task_id, run_id).await {
        Ok(true) => {}
        _ => return harness::HarnessResolveView::default(),
    }
    // Resume is offered on a Task waiting on reconciliation only; an
    // error hides the button.
    if view.mark_failed {
        if let Ok(st) = h.resume_state(workspace_id, task_id, run_id).await {
            view.resume = st.eligible;
            if !st.eligible {
                view.resume_unavailable = harness::resume_unavailable_text(st.blocked);
            }
        }
        if let Ok(offered) = h.rerun_offered(workspace_id, task_id, run_id).await {
            view.rerun = offered;
        }
    }
    view
}

/// `harnessBanner` — the banner every `/app` page renders; absent
/// operator surface means no banner.
async fn harness_banner(
    state: &WebState,
    workspace_id: central_foundation::identity::WorkspaceId,
) -> harness::HarnessBannerView {
    match &state.harness {
        Some(h) => harness::HarnessBannerView::new(h.banner(workspace_id).await),
        None => harness::HarnessBannerView::default(),
    }
}

/// `permissionPoliciesEnabled` — the submit form's policy select gate.
fn permission_policies_enabled(state: &WebState) -> bool {
    state
        .harness
        .as_ref()
        .is_some_and(|h| h.permission_policies_enabled())
}

/// `budgetFieldsEnabled` — the submit form's budget fields gate
/// (identical to the policy select's, upstream).
fn budget_fields_enabled(state: &WebState) -> bool {
    permission_policies_enabled(state)
}

/// `harnessBackendIs` — whether the configured backend is `backend`.
fn harness_backend_is(state: &WebState, backend: &str) -> bool {
    state
        .harness
        .as_ref()
        .is_some_and(|h| h.harness_backend() == backend)
}

/// `harnessBackendIsDenyOnly` — opencode, codex, or antigravity.
fn harness_backend_is_deny_only(state: &WebState) -> bool {
    harness_backend_is(state, "opencode")
        || harness_backend_is(state, "codex")
        || harness_backend_is(state, "antigravity")
}

/// `RecoveryClaimability` prelude — the durable restart-barrier gate.
/// Any error fails closed (`Ok(claimable: false)` equivalent).
async fn claimability(
    state: &WebState,
    workspace_id: central_foundation::identity::WorkspaceId,
    task_id: TaskId,
    run_id: central_foundation::identity::RunId,
) -> Result<central_execution::domain::Claimability, ()> {
    state
        .claimability
        .recovery_claimability(
            TrustedScope {
                principal_id: String::new(),
                workspace_id,
                capabilities: BTreeSet::new(),
            },
            task_id,
            run_id,
        )
        .await
        .map_err(|_| ())
}

/// One `key=value` query parameter (the detail/artifact routes use
/// query-parameter addressing, matching upstream).
fn query_value<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=')
            && k == key
        {
            return Some(v);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Artifact preview / download
// ---------------------------------------------------------------------------

/// `resolveArtifactDelivery` — the shared session/id/delivery prelude.
/// `Err` (a hard failure, including a genuinely absent artifact) and
/// `Denied` (a known-but-denied artifact) map to the exact same generic
/// 404 — never a reason, never a different status.
async fn resolve_artifact_delivery(
    state: &WebState,
    headers: &axum::http::HeaderMap,
    query: &str,
    issued_csrf: &str,
) -> Result<(Box<dyn central_artifact::port::ByteStream>, String, i64), Box<Response>> {
    let Some(sess) = active_session(state, headers).await else {
        return Err(Box::new(super::render_bootstrap_issued(
            issued_csrf,
            StatusCode::OK,
            "",
        )));
    };
    let workspace_id = sess.workspace_id;
    let artifact_id = match query_value(query, "id").and_then(|v| ArtifactId::parse(v).ok()) {
        Some(id) => id,
        None => return Err(Box::new(render_not_found())),
    };
    let outcome = state
        .artifacts
        .deliver_ready_artifact(DeliverReadyArtifactRequest {
            workspace_id,
            artifact_id,
            requesting_session_workspace_id: workspace_id,
        })
        .await;
    match outcome {
        Ok(DeliverArtifactOutcome::Allowed { body, artifact, .. }) => Ok((
            body,
            artifact.artifact_id.to_string(),
            artifact.limits.max_bytes,
        )),
        // `Denied` and every error collapse to the same 404 — see the
        // upstream `resolveArtifactDelivery` contract.
        _ => Err(Box::new(render_not_found())),
    }
}

/// `ServeArtifactPreview` — the bounded, escaped `<pre>` preview.
pub(crate) async fn serve_artifact_preview(state: Arc<WebState>, req: Request) -> Response {
    let (mut body, artifact_id, _max) = match resolve_artifact_delivery(
        &state,
        req.headers(),
        req.uri().query().unwrap_or_default(),
        &super::issued_csrf_value(&req),
    )
    .await
    {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let mut raw: Vec<u8> = Vec::new();
    let mut truncated = false;
    let mut buf = [0u8; 16 * 1024];
    loop {
        match body.read_chunk(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                if raw.len() > ARTIFACT_PREVIEW_MAX_BYTES {
                    raw.truncate(ARTIFACT_PREVIEW_MAX_BYTES);
                    truncated = true;
                    break;
                }
            }
            Err(_) => {
                let _ = body.close().await;
                return error::reject(StatusCode::SERVICE_UNAVAILABLE, "");
            }
        }
    }
    let _ = body.close().await;
    html_response(
        StatusCode::OK,
        &super::ArtifactPreviewTemplate {
            artifact_id,
            content: String::from_utf8_lossy(&raw).into_owned(),
            truncated,
        }
        .render(),
    )
}

/// `ServeArtifactDownload` — the ready body streamed as an attachment,
/// bounded at the artifact's own `limits.max_bytes + 1`.
pub(crate) async fn serve_artifact_download(state: Arc<WebState>, req: Request) -> Response {
    let (mut body, _id, max_bytes) = match resolve_artifact_delivery(
        &state,
        req.headers(),
        req.uri().query().unwrap_or_default(),
        &super::issued_csrf_value(&req),
    )
    .await
    {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    // `io.CopyN(limits.MaxBytes+1)` — the buffered layer bounds the
    // total anyway (the route's response cap), so a fixed chunk loop
    // with the artifact's own bound mirrors upstream's contract.
    let mut raw: Vec<u8> = Vec::new();
    let limit = max_bytes.max(0) as usize + 1;
    let mut buf = [0u8; 64 * 1024];
    loop {
        if raw.len() >= limit {
            break;
        }
        let want = (limit - raw.len()).min(buf.len());
        match body.read_chunk(&mut buf[..want]).await {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&buf[..n]),
            Err(_) => {
                let _ = body.close().await;
                return error::reject(StatusCode::SERVICE_UNAVAILABLE, "");
            }
        }
    }
    let _ = body.close().await;
    let mut resp = Response::new(Body::from(raw));
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/markdown; charset=utf-8"),
    );
    resp.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static(DOWNLOAD_DISPOSITION),
    );
    resp
}

// ---------------------------------------------------------------------------
// Mutations — submit / cancel / retry / rerun
// ---------------------------------------------------------------------------

/// `ServeTaskSubmit` — validates `workspace_root_id` against the
/// configured allowlist via the canonical input parser, applies the
/// policy and budget gates, then submits. The idempotency key is the
/// dedicated per-render form field — never the session CSRF value
/// (a stable session value would alias unrelated submissions as
/// replays).
pub(crate) async fn serve_task_submit(state: Arc<WebState>, req: Request) -> Response {
    if req.headers().get(header::ORIGIN).is_none() {
        return task_action_failure(StatusCode::FORBIDDEN);
    }
    let (sess, form) = match authenticated(&req) {
        Some(v) => v,
        None => {
            // The session middleware normally rejects before here; fall
            // back to the handler-side CSRF/session prelude so the
            // contract holds behind a thinner chain.
            return submit_fallback(state, req).await;
        }
    };
    submit_with(state, &sess, &form).await
}

/// The handler-side prelude for a submit reached without the session
/// middleware's stashes (parseBodyForm → decode → validate-with-CSRF).
async fn submit_fallback(state: Arc<WebState>, req: Request) -> Response {
    let mut req = req;
    let form = match parse_body_form(&mut req).await {
        Ok(f) if f.get("csrf").map_or(0, Vec::len) == 1 => f,
        _ => return task_action_failure(StatusCode::FORBIDDEN),
    };
    let Some(csrf) = b64::decode(form_value(&form, "csrf")) else {
        return task_action_failure(StatusCode::FORBIDDEN);
    };
    let Some(sess) = active_session_with_csrf(&state, req.headers(), csrf).await else {
        return task_action_failure(StatusCode::FORBIDDEN);
    };
    submit_with(state, &sess, &form).await
}

async fn submit_with(
    state: Arc<WebState>,
    sess: &Session,
    form: &HashMap<String, Vec<String>>,
) -> Response {
    let workspace_id = sess.workspace_id;
    // `raw` is the exact repository_analysis/v1 JSON validated here and
    // persisted verbatim as the Task's Input.
    let raw = repository_analysis::repository_analysis_json(
        form_value(form, "instruction"),
        form_value(form, "workspace_root_id"),
    );
    if repository_analysis::parse_repository_analysis_input(&raw, &state.allowed_roots).is_err() {
        return task_action_failure(StatusCode::BAD_REQUEST);
    }
    // The policy gates: no choice is deny; anything else needs harness
    // execution enabled, never a deny-only backend, and auto_allow its
    // acknowledgement.
    let policy =
        match permission_form::parse_permission_policy(form_value(form, "permission_policy")) {
            Some(p) => p,
            None => return task_action_failure(StatusCode::BAD_REQUEST),
        };
    if form.get("permission_policy").map_or(0, Vec::len) > 1
        || (policy != PermissionPolicy::Deny && !permission_policies_enabled(&state))
        || (policy != PermissionPolicy::Deny && harness_backend_is_deny_only(&state))
        || (policy == PermissionPolicy::AutoAllow
            && (form.get("auto_allow_ack").map_or(0, Vec::len) != 1
                || form_value(form, "auto_allow_ack") != "1"))
    {
        return task_action_failure(StatusCode::BAD_REQUEST);
    }
    let Some((budget, present)) = budget_view::parse_budget_form(form) else {
        return task_action_failure(StatusCode::BAD_REQUEST);
    };
    if (present && !budget_fields_enabled(&state))
        || (budget.cost_micro_usd > 0
            && (harness_backend_is(&state, "codex") || harness_backend_is(&state, "antigravity")))
    {
        return task_action_failure(StatusCode::BAD_REQUEST);
    }
    let result = state
        .tasks
        .submit_task(
            SubmitTaskRequest {
                workspace_id,
                title: form_value(form, "title").to_string(),
                input: String::from_utf8_lossy(&raw).into_owned(),
                permission_policy: Some(policy),
                budget,
                run_key: None,
                now: OffsetDateTime::now_utc(),
            },
            CommandMeta {
                // Upstream passes `formValue(...)` verbatim (`""` when
                // absent); the commit path treats `""` exactly like
                // `None` (`commit_task_change_set` gates the receipt on
                // `!k.is_empty()`, mirroring upstream's `!= ""`), so
                // mapping `""` to `None` is byte-exact-equivalent.
                idempotency_key: Some(form_value(form, "idempotency_key").to_string())
                    .filter(|k| !k.is_empty()),
                ..CommandMeta::default()
            },
        )
        .await;
    match result {
        Ok(r) => redirect_303(&format!("/app/tasks/detail?id={}", r.task.id)),
        Err(_) => task_action_failure(StatusCode::SERVICE_UNAVAILABLE),
    }
}

/// `loadAggregateForMutation` — the shared session/aggregate-load
/// prelude for every mutation route. A missing/malformed `task_id` or a
/// cross-workspace/absent task renders the generic 404; the restart
/// barrier fails closed as a generic 409. Returns the session (the
/// harness routes bind its principal), workspace, loaded aggregate,
/// and parsed form.
struct MutationPrelude {
    session: Session,
    loaded: LoadedAggregate,
    form: HashMap<String, Vec<String>>,
}

async fn load_aggregate_for_mutation(
    state: &WebState,
    session: Session,
    form: HashMap<String, Vec<String>>,
) -> Result<MutationPrelude, Box<Response>> {
    let workspace_id = session.workspace_id;
    let task_id = match TaskId::parse(form_value(&form, "task_id")) {
        Ok(id) => id,
        Err(_) => return Err(Box::new(render_not_found())),
    };
    let loaded = match state.tasks.load_aggregate(workspace_id, task_id).await {
        Ok(l) => l,
        Err(f) if f.kind() == central_foundation::failure::FailureKind::NotFound => {
            return Err(Box::new(render_not_found()));
        }
        Err(_) => {
            return Err(Box::new(task_action_failure(
                StatusCode::SERVICE_UNAVAILABLE,
            )));
        }
    };
    if let Some(run) = &loaded.aggregate.current_run {
        // Fail closed and never disclose the specific barrier reason.
        match claimability(state, workspace_id, loaded.aggregate.task.id, run.id).await {
            Ok(c) if c.claimable => {}
            _ => return Err(Box::new(task_action_failure(StatusCode::CONFLICT))),
        }
    }
    Ok(MutationPrelude {
        session,
        loaded,
        form,
    })
}

/// `mutationExpectedRunVersion` — the `RunVersion` a caller echoes back
/// as `MutationInput::expected_run_version` (`None` when the aggregate
/// has no current run).
fn mutation_expected_run_version(loaded: &LoadedAggregate) -> i64 {
    if loaded.aggregate.current_run.is_none() {
        return 0;
    }
    loaded.run_version.unwrap_or(0)
}

fn mutation_input(loaded: &LoadedAggregate) -> MutationInput {
    MutationInput {
        aggregate: loaded.aggregate.clone(),
        expected_task_version: loaded.task_version,
        expected_run_version: mutation_expected_run_version(loaded),
        now: OffsetDateTime::now_utc(),
    }
}

fn detail_location(task_id: TaskId) -> String {
    format!("/app/tasks/detail?id={task_id}")
}

fn meta_for(form: &HashMap<String, Vec<String>>) -> CommandMeta {
    CommandMeta {
        // `""` → `None` is equivalent to upstream's verbatim `""`: the
        // receipt dedup guards on a non-empty key either way (see the
        // submit site's comment).
        idempotency_key: Some(form_value(form, "idempotency_key").to_string())
            .filter(|k| !k.is_empty()),
        ..CommandMeta::default()
    }
}

/// `ServeTaskCancel` — the handler chooses which domain function to
/// ask; eligibility is re-checked by the task domain itself:
/// - a never-claimed Task goes through `cancel_unclaimed_task`;
/// - a cancelling Task with a claimed Run goes through
///   `HarnessOperator::settle_prepared` (never-invoked attempt);
/// - everything else goes through `request_cancellation`.
///
/// A cancel that loses the dispatcher's claim race returns with "The
/// Task started. Press Cancel again."; a cancelled task returns with
/// "Already cancelled."; any other refusal is a generic 409.
pub(crate) async fn serve_task_cancel(state: Arc<WebState>, req: Request) -> Response {
    if req.headers().get(header::ORIGIN).is_none() {
        return task_action_failure(StatusCode::FORBIDDEN);
    }
    let Some((session, form)) = authenticated(&req) else {
        return task_action_failure(StatusCode::FORBIDDEN);
    };
    let pre = match load_aggregate_for_mutation(&state, session, form).await {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    let input = mutation_input(&pre.loaded);
    let meta = meta_for(&pre.form);
    let mut detail = detail_location(pre.loaded.aggregate.task.id);
    let err = if pre.loaded.aggregate.unclaimed() {
        state
            .tasks
            .cancel_unclaimed_task(CancelUnclaimedTaskRequest { input }, meta)
            .await
            .err()
    } else if state.harness.is_some()
        && pre.loaded.aggregate.task.status == TaskStatus::Cancelling
        && pre.loaded.aggregate.current_run.is_some()
    {
        return finish_prepared_cancel(&state, &pre, &detail).await;
    } else {
        state
            .tasks
            .request_cancellation(RequestCancellationRequest { input }, meta)
            .await
            .err()
    };
    if err.is_some() {
        match cancel_refusal_notice(&state, &pre).await {
            Some(notice) => {
                detail.push_str(&format!("&{ACTION_NOTICE_QUERY}={notice}"));
            }
            None => return task_action_failure(StatusCode::CONFLICT),
        }
    }
    redirect_303(&detail)
}

/// `finishPreparedCancel` — "Finish cancelling" on a cancelling Task
/// whose harness attempt was never invoked. A live lease is the
/// retryable 409; a task cancelled by the re-read is "Already
/// cancelled."; anything else the generic 409.
async fn finish_prepared_cancel(state: &WebState, pre: &MutationPrelude, detail: &str) -> Response {
    let t = &pre.loaded.aggregate.task;
    let Some(run) = &pre.loaded.aggregate.current_run else {
        return task_action_failure(StatusCode::CONFLICT);
    };
    let req_out = HarnessResolveRequest {
        workspace_id: pre.session.workspace_id,
        task_id: t.id,
        run_id: run.id,
        expected_run_version: mutation_expected_run_version(&pre.loaded),
        principal: pre.session.principal_identity.clone(),
    };
    let Some(h) = &state.harness else {
        return task_action_failure(StatusCode::CONFLICT);
    };
    match h.settle_prepared(req_out).await {
        Ok(()) => redirect_303(detail),
        Err(f) if harness::failure_is(&f, ERR_HARNESS_STARTING) => render_harness_starting(),
        Err(f) if harness::failure_is(&f, ERR_HARNESS_NOT_RESOLVABLE) => {
            match state.tasks.load_aggregate(t.workspace_id, t.id).await {
                Ok(now) if now.aggregate.task.status == TaskStatus::Cancelled => redirect_303(
                    &format!("{detail}&{ACTION_NOTICE_QUERY}={ACTION_NOTICE_ALREADY_CANCELLED}"),
                ),
                _ => task_action_failure(StatusCode::CONFLICT),
            }
        }
        Err(_) => task_action_failure(StatusCode::CONFLICT),
    }
}

/// `cancelRefusalNotice` — explains a refused cancel from durable
/// state: cancelled already is "Already cancelled."; a never-claimed
/// Task whose Run was claimed meanwhile lost the race.
async fn cancel_refusal_notice(state: &WebState, pre: &MutationPrelude) -> Option<&'static str> {
    let t = &pre.loaded.aggregate.task;
    if t.status == TaskStatus::Cancelled {
        return Some(ACTION_NOTICE_ALREADY_CANCELLED);
    }
    if !pre.loaded.aggregate.unclaimed() {
        return None;
    }
    let now = state
        .tasks
        .load_aggregate(t.workspace_id, t.id)
        .await
        .ok()?;
    if now.aggregate.task.status == TaskStatus::Cancelled {
        return Some(ACTION_NOTICE_ALREADY_CANCELLED);
    }
    // `actionNoticeCancelLostClaim` — upstream's exact five-conjunct
    // predicate (`handler.go` `cancelRefusalNotice`): the loaded Task
    // was Queued, the re-read Task is not terminal, the re-read has a
    // current Run, it is the SAME Run this request loaded, and that
    // Run is now claimed. Any other re-read state is the generic 409.
    if t.status == TaskStatus::Queued
        && !now.aggregate.task.is_terminal()
        && let (Some(now_run), Some(loaded_run)) = (
            now.aggregate.current_run.as_ref(),
            pre.loaded.aggregate.current_run.as_ref(),
        )
        && now_run.id == loaded_run.id
        && !now_run.ownership_token.is_empty()
    {
        return Some(ACTION_NOTICE_CANCEL_LOST_CLAIM);
    }
    None
}

/// `ServeTaskRetry` — failed → queued with a fresh run. The Task cost
/// cap asks `RetryState` first (a Blocked retry is refused before the
/// task service sees it).
pub(crate) async fn serve_task_retry(state: Arc<WebState>, req: Request) -> Response {
    if req.headers().get(header::ORIGIN).is_none() {
        return task_action_failure(StatusCode::FORBIDDEN);
    }
    let Some((session, form)) = authenticated(&req) else {
        return task_action_failure(StatusCode::FORBIDDEN);
    };
    let pre = match load_aggregate_for_mutation(&state, session, form).await {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    // The cost-cap check runs only for a retry-eligible Task
    // (`taskRetryEligible` = Failed only — `handler.go:1226`); a
    // non-Failed Task skips `retry_state` entirely so its failure can
    // never mask the domain's own 409. A failed read is upstream's
    // 500, never the retryable 503.
    if let Some(h) = &state.harness
        && task_view::task_retry_eligible(pre.loaded.aggregate.task.status)
    {
        match h
            .retry_state(pre.session.workspace_id, pre.loaded.aggregate.task.id)
            .await
        {
            Ok(st) if st.blocked => return task_action_failure(StatusCode::CONFLICT),
            Ok(_) => {}
            Err(_) => return task_action_failure(StatusCode::INTERNAL_SERVER_ERROR),
        }
    }
    match state
        .tasks
        .retry_failed_task(
            central_task::domain::RetryFailedTaskRequest {
                input: mutation_input(&pre.loaded),
            },
            meta_for(&pre.form),
        )
        .await
    {
        Ok(_) => redirect_303(&detail_location(pre.loaded.aggregate.task.id)),
        Err(_) => task_action_failure(StatusCode::CONFLICT),
    }
}

/// `ServeTaskRerun` — cancelled → a brand-new Task with lineage; the
/// redirect targets the NEW task's detail page.
pub(crate) async fn serve_task_rerun(state: Arc<WebState>, req: Request) -> Response {
    if req.headers().get(header::ORIGIN).is_none() {
        return task_action_failure(StatusCode::FORBIDDEN);
    }
    let Some((session, form)) = authenticated(&req) else {
        return task_action_failure(StatusCode::FORBIDDEN);
    };
    let pre = match load_aggregate_for_mutation(&state, session, form).await {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    match state
        .tasks
        .rerun_cancelled_task(
            RerunCancelledTaskRequest {
                source: pre.loaded.aggregate.clone(),
                expected_task_version: pre.loaded.task_version,
                now: OffsetDateTime::now_utc(),
            },
            meta_for(&pre.form),
        )
        .await
    {
        Ok(r) => redirect_303(&detail_location(r.task.id)),
        Err(_) => task_action_failure(StatusCode::CONFLICT),
    }
}

// ---------------------------------------------------------------------------
// Harness operator actions — resolve / resume / permission
// ---------------------------------------------------------------------------

/// `ServeTaskHarnessResolve` — "Mark failed", "Mark cancelled", and
/// "Mark failed and rerun" (operator resolved). The disposition follows
/// the durable Task Status, never WaitingReason; every operator error is
/// a plain 409.
pub(crate) async fn serve_harness_resolve(state: Arc<WebState>, req: Request) -> Response {
    if state.harness.is_none() {
        return render_not_found();
    }
    if req.headers().get(header::ORIGIN).is_none() {
        return task_action_failure(StatusCode::FORBIDDEN);
    }
    let Some((session, form)) = authenticated(&req) else {
        return task_action_failure(StatusCode::FORBIDDEN);
    };
    let pre = match load_aggregate_for_mutation(&state, session, form).await {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    let action = match permission_form::parse_resolve_action(&pre.form) {
        Ok(a) => a,
        Err(_) => return task_action_failure(StatusCode::BAD_REQUEST),
    };
    let t = pre.loaded.aggregate.task.clone();
    let detail = detail_location(t.id);
    // "Mark cancelled" on an already-cancelled Task returns with the
    // notice; fail/rerun are a plain 409.
    if t.status == TaskStatus::Cancelled
        && action != Some(permission_form::RESOLVE_ACTION_FAIL)
        && action != Some(permission_form::RESOLVE_ACTION_RERUN)
    {
        return redirect_303(&format!(
            "{detail}&{ACTION_NOTICE_QUERY}={ACTION_NOTICE_ALREADY_CANCELLED}"
        ));
    }
    let offered = harness::resolve_actions(t.status, t.waiting_reason);
    let mut mark_cancelled = false;
    let mut rerun = false;
    match action {
        _ if !offered.offered() || pre.loaded.aggregate.current_run.is_none() => {
            return task_action_failure(StatusCode::CONFLICT);
        }
        Some(permission_form::RESOLVE_ACTION_CANCEL) => {
            if !offered.mark_cancelled {
                return task_action_failure(StatusCode::CONFLICT);
            }
            mark_cancelled = true;
        }
        Some(permission_form::RESOLVE_ACTION_FAIL) => {
            if !offered.mark_failed {
                return task_action_failure(StatusCode::CONFLICT);
            }
        }
        Some(permission_form::RESOLVE_ACTION_RERUN) => {
            if !offered.mark_failed {
                return task_action_failure(StatusCode::CONFLICT);
            }
            rerun = true;
        }
        Some(_) => return task_action_failure(StatusCode::BAD_REQUEST),
        // No action: the one button the status always offers.
        None => mark_cancelled = !offered.mark_failed,
    }
    let Some(run) = &pre.loaded.aggregate.current_run else {
        return task_action_failure(StatusCode::CONFLICT);
    };
    let run_id = run.id;
    let Some(h) = &state.harness else {
        return render_not_found();
    };
    match h.resolvable(pre.session.workspace_id, t.id, run_id).await {
        Ok(true) => {}
        _ => return task_action_failure(StatusCode::CONFLICT),
    }
    let req_out = HarnessResolveRequest {
        workspace_id: pre.session.workspace_id,
        task_id: t.id,
        run_id,
        expected_run_version: mutation_expected_run_version(&pre.loaded),
        principal: pre.session.principal_identity.clone(),
    };
    let err = if mark_cancelled {
        h.resolve_cancelled(req_out).await
    } else if rerun {
        h.resolve_rerun(req_out).await
    } else {
        h.resolve_failed(req_out).await
    };
    if let Err(f) = err {
        if mark_cancelled
            && harness::failure_is(&f, ERR_HARNESS_NOT_RESOLVABLE)
            && let Ok(now) = state.tasks.load_aggregate(t.workspace_id, t.id).await
            && now.aggregate.task.status == TaskStatus::Cancelled
        {
            return redirect_303(&format!(
                "{detail}&{ACTION_NOTICE_QUERY}={ACTION_NOTICE_ALREADY_CANCELLED}"
            ));
        }
        return task_action_failure(StatusCode::CONFLICT);
    }
    redirect_303(&detail)
}

/// `ServeTaskHarnessResume` — "Resume" on an ambiguous attempt. Only a
/// Task waiting on reconciliation with a current Run is resumable; a
/// live lease is the retryable 409, a refusal the plain 409, any other
/// error 500.
pub(crate) async fn serve_harness_resume(state: Arc<WebState>, req: Request) -> Response {
    if state.harness.is_none() {
        return render_not_found();
    }
    if req.headers().get(header::ORIGIN).is_none() {
        return task_action_failure(StatusCode::FORBIDDEN);
    }
    let Some((session, form)) = authenticated(&req) else {
        return task_action_failure(StatusCode::FORBIDDEN);
    };
    let pre = match load_aggregate_for_mutation(&state, session, form).await {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    let t = &pre.loaded.aggregate.task;
    if t.status != TaskStatus::Waiting
        || t.waiting_reason != Some(central_task::domain::WaitingReason::Reconciliation)
        || pre.loaded.aggregate.current_run.is_none()
    {
        return task_action_failure(StatusCode::CONFLICT);
    }
    let Some(run) = &pre.loaded.aggregate.current_run else {
        return task_action_failure(StatusCode::CONFLICT);
    };
    let run_id = run.id;
    let Some(h) = &state.harness else {
        return render_not_found();
    };
    match h
        .resume(HarnessResolveRequest {
            workspace_id: pre.session.workspace_id,
            task_id: t.id,
            run_id,
            expected_run_version: mutation_expected_run_version(&pre.loaded),
            principal: pre.session.principal_identity.clone(),
        })
        .await
    {
        Ok(()) => redirect_303(&detail_location(t.id)),
        Err(f) if harness::failure_is(&f, ERR_HARNESS_STARTING) => render_harness_starting(),
        Err(f) if harness::failure_is(&f, ERR_HARNESS_NOT_RESOLVABLE) => {
            task_action_failure(StatusCode::CONFLICT)
        }
        Err(_) => task_action_failure(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// `ServeTaskHarnessPermission` — the operator's Allow or Deny of a
/// pending harness permission request. The decider is the validated
/// session's principal, never a form field. A decision that no longer
/// applies returns to detail with "This request is no longer pending.".
pub(crate) async fn serve_harness_permission(state: Arc<WebState>, req: Request) -> Response {
    if state.harness.is_none() {
        return render_not_found();
    }
    if req.headers().get(header::ORIGIN).is_none() {
        return task_action_failure(StatusCode::FORBIDDEN);
    }
    let Some((session, form)) = authenticated(&req) else {
        return task_action_failure(StatusCode::FORBIDDEN);
    };
    let pre = match load_aggregate_for_mutation(&state, session, form).await {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    let decision = match permission_form::parse_permission_decision(&pre.form) {
        Some(d) => d,
        None => return task_action_failure(StatusCode::BAD_REQUEST),
    };
    let t = &pre.loaded.aggregate.task;
    let mut detail = detail_location(t.id);
    let Some(h) = &state.harness else {
        return render_not_found();
    };
    match h
        .decide_permission(HarnessPermissionDecision {
            workspace_id: pre.session.workspace_id,
            task_id: t.id,
            approval_id: decision.approval_id,
            input_mac: decision.input_mac,
            allow: decision.allow,
            principal: pre.session.principal_identity.clone(),
        })
        .await
    {
        Ok(()) => {}
        Err(f) if harness::failure_is(&f, ERR_HARNESS_PERMISSION_NOT_PENDING) => {
            detail.push_str(&format!(
                "&{PERMISSION_STALE_QUERY}={PERMISSION_STALE_VALUE}"
            ));
        }
        Err(_) => return task_action_failure(StatusCode::SERVICE_UNAVAILABLE),
    }
    redirect_303(&detail)
}
