//! `/api/v1/...` JSON controllers — the Task 12 port of upstream's API
//! surface. In scope: the bootstrap exchange. JSON responses use the
//! canonical error envelope; the only JSON the exchange emits is a
//! throttled retry, everything else is the HTML bootstrap shell or the
//! `303` success redirect (upstream's precedent — the exchange is a
//! browser form POST, not a fetch).

pub mod session;

use std::sync::Arc;

use axum::extract::Request;
use axum::http::Method;
use axum::routing::post;

use crate::policy::{self, RouteClass, RoutePolicy, RouteSpec};
use crate::router::RoutedSpec;
use crate::web::WebState;

/// Registers the in-scope API routes. The exchange reuses [`WebState`]
/// — it is the same composition the web handlers hold.
#[must_use]
pub fn routes(state: &Arc<WebState>) -> Vec<RoutedSpec> {
    vec![RoutedSpec {
        spec: RouteSpec {
            method: Method::POST,
            path: "/api/v1/session/bootstrap",
            policy: RoutePolicy {
                class: RouteClass::Api,
                response_cap: policy::API_RESPONSE_CAP,
                body_limit: policy::DEFAULT_BOOTSTRAP_BODY_LIMIT,
                origin_required: true,
                state_changing: true,
                csrf_required: true,
                session_csrf_required: false,
                issue_pre_auth_csrf: false,
                session_required: false,
                restart_barrier: false,
            },
        },
        handler: post({
            let st = Arc::clone(state);
            move |req: Request| session::serve_exchange(Arc::clone(&st), req)
        }),
    }]
}
