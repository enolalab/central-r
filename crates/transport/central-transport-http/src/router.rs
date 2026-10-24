//! Router — the §4.1/§4.2 configured `axum::Router`.
//!
//! [`build_app_router`] wires the canonical layer stack, outermost to
//! innermost (§4.2):
//!
//! 1. [`recover`] — panic → fixed `500` + §4.4 profile.
//! 2. [`metadata`] — strip inbound correlation/forwarding headers,
//!    mint a server-side request id.
//! 3. [`security_headers`] — the exact §4.4 profile on every response.
//! 4. [`access`] — sanitized access observation.
//! 5. [`admission`] + [`origin`] — loopback peer, exact Host, route
//!    allowlist (`404`/`405`), header bounds, duplicate-cookie guard,
//!    active/waiter semaphore, route deadline, exact Origin.
//! 6. Body bounds — `RequestBodyLimitLayer` per route at the policy's
//!    `body_limit` (§4.6 ≤ 2 MiB).
//! 7. Dispatch — the axum `Router` with explicit `MethodRouter` gating.
//! 8. [`session_auth`] + [`preauth`] — session authentication and
//!    header/form/pre-auth CSRF, consulted via the stashed policy.
//! 9. Handlers — supplied by the caller per [`RoutedSpec`]
//!    (Task 12 owns the real handlers).
//!
//! [`build_ops_router`] builds the dedicated loopback operations
//! listener (`/health/live`, `/health/ready`, `/metrics`) on the same
//! outer guards minus session/CSRF (upstream's operations listener).

use std::sync::Arc;

use axum::Router;
use axum::extract::Request;
use axum::http::Uri;
use axum::middleware::from_fn_with_state;
use axum::response::Response;
use axum::routing::{MethodRouter, get};
use central_foundation::failure::{Failure, FailureKind};
use central_session::domain::SecurityEpoch;
use tower::ServiceBuilder;
use tower_http::limit::RequestBodyLimitLayer;

use crate::error;
use crate::health;
use crate::metrics::{self, HttpMetrics, SharedRegistry};
use crate::middleware::access::{self, AccessObserver, TracingAccessObserver};
use crate::middleware::admission::{self, Admission, AdmissionConfig};
use crate::middleware::buffer::{self, BufferedState};
use crate::middleware::origin::{self, OriginConfig};
use crate::middleware::preauth::{self, PreAuthCsrfState};
use crate::middleware::session_auth::{self, SessionAuthState};
use crate::middleware::{metadata, recover, security_headers};
use crate::policy::{self, RouteSpec};
use crate::ports::{DeliveryPrecommit, PreAuthCsrf, SessionValidator};

/// One application route: the admission/policy spec plus the handler
/// that serves it. The same spec drives both the policy table and the
/// axum registration, so the two cannot diverge.
pub struct RoutedSpec {
    /// Method, path template, and per-route policy.
    pub spec: RouteSpec,
    /// The exact-method `MethodRouter` for this spec (Task 12 handlers).
    pub handler: MethodRouter,
}

/// The application-listener collaborator set. In production `P`, `V`,
/// and `D` are the same `central_session::app::Service` — the narrow
/// ports keep the transport generic (kernel wires Task 13, tests use
/// fakes).
#[derive(Clone)]
pub struct TransportConfig<P, V, D>
where
    P: PreAuthCsrf,
    V: SessionValidator,
    D: DeliveryPrecommit,
{
    /// Admission limits/host/metrics; `expected_host` must be set.
    pub admission: AdmissionConfig,
    /// The exact `Origin` value mutations must present
    /// (e.g. `https://127.0.0.1:8080`).
    pub expected_origin: String,
    /// Pre-auth CSRF service seam.
    pub preauth: Arc<P>,
    /// Session validation seam.
    pub sessions: Arc<V>,
    /// Buffered precommit seam.
    pub delivery: Arc<D>,
    /// Workspace security epoch asserted on every session validation
    /// (upstream `Config.EpochSource`).
    pub epoch_source: Arc<dyn Fn() -> SecurityEpoch + Send + Sync>,
    /// Access observer; `None` installs the `tracing` default.
    pub observer: Option<Arc<dyn AccessObserver>>,
}

/// Builds the fully layered application `Router`. Every spec in
/// `routes` registers both an admission-policy entry and an axum route;
/// requests that match neither produce the §4.1.1 fixed `404`/`405`.
///
/// # Errors
/// `Failure` on malformed route templates, duplicate `(method, path)`
/// pairs, §4.6 hard-cap violations in the admission config, or a
/// missing `admission.expected_host` — the application listener must
/// always bind an exact Host (upstream's `r.Host != ExpectedHost`
/// compare rejects everything when unset, so `None` would silently
/// admit any Host).
pub fn build_app_router<P, V, D>(
    routes: Vec<RoutedSpec>,
    cfg: TransportConfig<P, V, D>,
) -> Result<Router, Failure>
where
    P: PreAuthCsrf,
    V: SessionValidator,
    D: DeliveryPrecommit,
{
    if cfg.admission.expected_host.is_none() {
        return Err(Failure::new(
            FailureKind::Invalid,
            "transport_admission",
            "application listener requires admission.expected_host".to_string(),
        ));
    }
    let specs: Vec<RouteSpec> = routes.iter().map(|r| r.spec.clone()).collect();
    let admission = Admission::new(cfg.admission, &specs)?;

    let mut router = Router::new();
    for r in routes {
        let limit = r.spec.policy.effective_body_limit();
        router = router.route(
            r.spec.path,
            r.handler.layer(RequestBodyLimitLayer::new(limit)),
        );
    }
    let adm_for_fallback = admission.clone();
    router = router
        .fallback(fallback_404)
        .method_not_allowed_fallback(axum::routing::any(move |req: Request| {
            let adm = adm_for_fallback.clone();
            async move {
                let allow = adm.allow_for(req.uri().path()).unwrap_or_default();
                error::method_not_allowed(req.uri().path(), &allow)
            }
        }));

    let observer: Arc<dyn AccessObserver> = cfg
        .observer
        .unwrap_or_else(|| Arc::new(TracingAccessObserver));
    let stack = ServiceBuilder::new()
        .layer(recover::layer())
        .layer(axum::middleware::from_fn(metadata::layer))
        .layer(axum::middleware::from_fn(security_headers::layer))
        .layer(from_fn_with_state(observer, access::layer))
        .layer(from_fn_with_state(admission, admission::layer))
        .layer(from_fn_with_state(
            OriginConfig::new(&cfg.expected_origin),
            origin::layer,
        ))
        .layer(from_fn_with_state(
            SessionAuthState {
                service: cfg.sessions,
                epoch_source: cfg.epoch_source,
            },
            session_auth::layer,
        ))
        .layer(from_fn_with_state(
            PreAuthCsrfState {
                service: cfg.preauth,
            },
            preauth::layer,
        ))
        .layer(from_fn_with_state(
            BufferedState {
                service: cfg.delivery,
            },
            buffer::layer,
        ));
    Ok(router.layer(stack))
}

/// The fixed `404` fallback — content-type by path family (§4.1.1).
async fn fallback_404(uri: Uri) -> Response {
    error::not_found(uri.path())
}

/// The operations listener (`/health/live`, `/health/ready`,
/// `/metrics`) — loopback policy only: no session, no Origin, no CSRF.
/// `expected_host` is `None` (upstream re-asserts loopback only; the
/// listener binds `127.0.0.1`) — the only legitimate `None`; the
/// application listener must set it (see [`build_app_router`]).
///
/// # Errors
/// `Failure` on §4.6 hard-cap violations — a failed [`Admission`]
/// build must never silently serve health/metrics unguarded.
pub fn build_ops_router(
    probe: Arc<dyn health::ReadinessProbe>,
    registry: SharedRegistry,
    metrics_hooks: Option<HttpMetrics>,
) -> Result<Router, Failure> {
    let health_routes = Router::new()
        .route("/health/live", get(health::live))
        .route("/health/ready", get(health::ready))
        .with_state(probe);
    let metrics_routes = Router::new()
        .route("/metrics", get(metrics::metrics))
        .with_state(registry);
    let specs = [
        policy::RouteSpec {
            method: axum::http::Method::GET,
            path: "/health/live",
            policy: policy::RoutePolicy::safe_get(policy::RouteClass::Health),
        },
        policy::RouteSpec {
            method: axum::http::Method::GET,
            path: "/health/ready",
            policy: policy::RoutePolicy::safe_get(policy::RouteClass::Health),
        },
        policy::RouteSpec {
            method: axum::http::Method::GET,
            path: "/metrics",
            policy: policy::RoutePolicy::safe_get(policy::RouteClass::Metrics),
        },
    ];
    let admission = Admission::new(
        AdmissionConfig {
            expected_host: None,
            metrics: metrics_hooks,
            ..AdmissionConfig::default()
        },
        &specs,
    )?;
    let router = health_routes.merge(metrics_routes).fallback(fallback_404);
    let stack = ServiceBuilder::new()
        .layer(recover::layer())
        .layer(axum::middleware::from_fn(metadata::layer))
        .layer(axum::middleware::from_fn(security_headers::layer))
        .layer(from_fn_with_state(
            Arc::new(TracingAccessObserver) as Arc<dyn AccessObserver>,
            access::layer,
        ))
        .layer(from_fn_with_state(admission, admission::layer));
    Ok(router.layer(stack))
}
