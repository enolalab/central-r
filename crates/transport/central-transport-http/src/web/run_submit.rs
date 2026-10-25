//! Run submission (issue #122): `POST /app/runs/submit` creates one
//! leader + N flat workers through the shared runsubmit service, and
//! `GET /app/runs` carries the submission form above the list.
//!
//! The POST replicates the run-control security prelude verbatim
//! (POST-only, non-empty Origin, exactly one well-formed `csrf` form
//! field, the genuinely CSRF-enforcing `activeSessionWithCSRF`) and the
//! task-submit response precedent: success redirects (303) to the fresh
//! run's detail page; every failure is the generic `RUN_CONTROL_FAILED`
//! body, never the domain reason. Dedup honesty follows the controls:
//! no web-layer idempotency of its own beyond passing the form's fresh
//! `idempotency_key` through as the task-scope receipt key —
//! convergence lives in the service (`run_key` replay) and the stores
//! (native dedup).
//!
//! The list half of `GET /app/runs` (the workspace run census over the
//! `RunsReader` projections) is Task 11's surface; this page renders
//! the submit section plus a placeholder until the run views land.

use std::collections::HashMap;
use std::sync::Arc;

use askama::Template;
use axum::extract::Request;
use axum::http::{StatusCode, header};
use axum::response::Response;
use central_foundation::identity::CommandId;
use central_runsubmit::domain::SubmitRequest;
use central_session::domain::Session;

use super::handler::active_session_with_csrf;
use super::{
    WebState, active_session, authenticated, form_value, parse_body_form, redirect_303,
    render_bootstrap, session_csrf_value,
};
use crate::b64;
use crate::error;
use crate::ports;

/// `renderRunControlFailure` — a generic, fail-closed text outcome
/// that never discloses a domain reason or run/node existence before
/// the scope check has passed (`RUN_CONTROL_FAILED`, run-control
/// family precedent).
fn run_control_failure(status: StatusCode) -> Response {
    error::reject(status, "RUN_CONTROL_FAILED")
}

/// `ServeRunList` — `GET /app/runs`: the workspace's complete run
/// census, newest first, keyset-paginated by the opaque `?cursor`
/// token, above the optional submission form. Phase-1 runs with zero
/// workflow nodes render in the same list. The cursor is the previous
/// page's last `(created_at, id)` pair; a malformed token is the same
/// generic 404 as a malformed id (a silently-reset first page would
/// present stale data under a page-N URL). Nil-tolerant like
/// `run_lineage`: an unwired runs port answers the same bare 503 as a
/// read failure rather than serving a partial page.
pub(crate) async fn serve_run_list(state: Arc<WebState>, req: Request) -> Response {
    let Some(sess) = active_session(&state, req.headers()).await else {
        return render_bootstrap(&req, StatusCode::OK, "");
    };
    let Some(reader) = state.runs.clone() else {
        return error::reject(StatusCode::SERVICE_UNAVAILABLE, "");
    };
    let cursor = match super::run_view::decode_cursor_param(req.uri().query()) {
        Ok(c) => c,
        Err(()) => return super::render_not_found(),
    };
    let (rows, next_cursor) =
        match super::run_view::run_list_page(&reader, sess.workspace_id, cursor).await {
            Ok(v) => v,
            Err(()) => return error::reject(StatusCode::SERVICE_UNAVAILABLE, ""),
        };
    let banner = super::handler::harness_banner(&state, sess.workspace_id).await;
    let can_submit = state.run_submitter.is_some();
    let csrf_field = session_csrf_value(&req);
    // `mintIdempotencyKey` — a fresh per-render receipt key, like the
    // task submit form; the session CSRF value is never reused for it.
    let idempotency_key = if can_submit {
        CommandId::new().to_string()
    } else {
        String::new()
    };
    super::html_response(
        StatusCode::OK,
        &RunsListTemplate {
            can_submit,
            csrf_field,
            idempotency_key,
            empty: rows.is_empty(),
            rows,
            next_cursor,
            banner,
        }
        .render(),
    )
}

/// `ServeRunSubmit` — `POST /app/runs/submit`: one Phase-2 run (leader +
/// flat workers) in the session workspace. An unwired submitter answers
/// the same bare 503 as an unwired read port, before any prelude — the
/// upstream check order.
pub(crate) async fn serve_run_submit(state: Arc<WebState>, req: Request) -> Response {
    let Some(submitter) = state.run_submitter.clone() else {
        return error::reject(StatusCode::SERVICE_UNAVAILABLE, "");
    };
    if req.headers().get(header::ORIGIN).is_none() {
        return run_control_failure(StatusCode::FORBIDDEN);
    }
    let (sess, form) = match authenticated(&req) {
        Some(v) => v,
        // The session middleware normally rejects before here; fall
        // back to the handler-side CSRF/session prelude so the
        // contract holds behind a thinner chain.
        None => return submit_fallback(&submitter, state, req).await,
    };
    submit_with(&submitter, &sess, &form).await
}

/// The handler-side prelude for a submit reached without the session
/// middleware's stashes (parseBodyForm → decode → validate-with-CSRF).
async fn submit_fallback(
    submitter: &Arc<dyn ports::RunSubmitter>,
    state: Arc<WebState>,
    req: Request,
) -> Response {
    let mut req = req;
    let form = match parse_body_form(&mut req).await {
        Ok(f) if f.get("csrf").map_or(0, Vec::len) == 1 => f,
        _ => return run_control_failure(StatusCode::FORBIDDEN),
    };
    let Some(csrf) = b64::decode(form_value(&form, "csrf")) else {
        return run_control_failure(StatusCode::FORBIDDEN);
    };
    let Some(sess) = active_session_with_csrf(&state, req.headers(), csrf).await else {
        return run_control_failure(StatusCode::FORBIDDEN);
    };
    submit_with(submitter, &sess, &form).await
}

/// The submit once session + form stand: worker-count parse, the
/// shared saga, then the PRG. The session's workspace is the
/// authoritative scope — the form never carries one.
async fn submit_with(
    submitter: &Arc<dyn ports::RunSubmitter>,
    sess: &Session,
    form: &HashMap<String, Vec<String>>,
) -> Response {
    let Ok(workers) = form_value(form, "workers").parse::<i64>() else {
        return run_control_failure(StatusCode::BAD_REQUEST);
    };
    let res = submitter
        .submit(SubmitRequest {
            workspace_id: sess.workspace_id,
            title: form_value(form, "title").to_string(),
            workers,
            run_key: Some(form_value(form, "run_key").to_string()).filter(|k| !k.is_empty()),
            idempotency_key: Some(form_value(form, "idempotency_key").to_string())
                .filter(|k| !k.is_empty()),
        })
        .await;
    match res {
        Ok(res) => redirect_303(&format!("/app/runs/detail?run={}", res.run_id)),
        // The request-shape marker is the only refusal class a
        // well-formed form can still hit (title/workers/run_key
        // bounds); everything else is a service failure.
        Err(f) if f.code() == central_runsubmit::domain::codes::REQUEST_VALIDATION => {
            run_control_failure(StatusCode::BAD_REQUEST)
        }
        Err(_) => run_control_failure(StatusCode::SERVICE_UNAVAILABLE),
    }
}

/// `runListViewModel` — the runs page: the workspace census rows plus
/// the optional submit section. `can_submit` mirrors upstream's
/// `Submitter != nil`.
#[derive(Template)]
#[template(path = "runs_list.html")]
struct RunsListTemplate {
    /// `CanSubmit` — renders the run-submission form; false when the
    /// submit port is unwired, in which case `csrf_field`/
    /// `idempotency_key` stay inert.
    can_submit: bool,
    /// The session CSRF value for the hidden `csrf` field.
    csrf_field: String,
    /// The fresh per-render receipt key for `idempotency_key`.
    idempotency_key: String,
    /// The census rows (upstream `Rows`).
    rows: Vec<super::run_view::RunListRow>,
    /// `Empty` — no runs in the workspace census.
    empty: bool,
    /// `NextCursor` — the opaque next-page token, "" when this is the
    /// last page.
    next_cursor: String,
    /// The mandatory harness banner.
    banner: super::harness::HarnessBannerView,
}

impl RunsListTemplate {
    fn render(&self) -> String {
        <Self as askama::Template>::render(self)
            .unwrap_or_else(|_| crate::rendering::render_error_page("Runs", "Unavailable"))
    }
}
