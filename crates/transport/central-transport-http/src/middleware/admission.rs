//! Admission — port of upstream `middleware/admission.go`.
//!
//! One layer enforcing, in upstream order:
//!
//! 1. Loopback peer (`ConnectInfo` — axum's `RemoteAddr` carrier; the
//!    kernel supplies it via `into_make_service_with_connect_info`).
//! 2. Exact raw `Host` — verbatim compare, no normalization.
//! 3. `OPTIONS` → `403 CORS_DISABLED` (CORS is structurally disabled).
//! 4. Route allowlist — unknown paths `404` (existence not leaked);
//!    known path + unlisted method `405` + `Allow` (§4.1.1, which
//!    diverges from upstream's blanket `404` by contract).
//! 5. Per-header 4 KiB and total-wire 32 KiB caps → `431`; duplicate
//!    cookie names → `400`.
//! 6. Route-policy stash (`MatchedRoute` extension) for the inner
//!    Origin/CSRF/session/buffered layers.
//! 7. Active/waiter semaphore — upstream's slot channel +
//!    waiter-budget acquire: at most `active_limit` in flight, at most
//!    `waiter_limit` queued, a waiter rejected after `wait_timeout`
//!    → `503 ADMISSION_FULL`. Acquired BEFORE any body read or
//!    PostgreSQL touch (§4.6).
//! 8. Per-route deadline — `route_deadline` wraps the inner call; on
//!    expiry the fixed `408` outcome (upstream's `ctx.Done()` +
//!    handler-written 408 collapses to the same wire status).

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::extract::{ConnectInfo, Request};
use axum::http::{Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use central_foundation::failure::{Failure, FailureKind};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::error;
use crate::metrics::HttpMetrics;
use crate::policy::{
    self, DEFAULT_ACTIVE_LIMIT, DEFAULT_MAX_HEADER_BYTES, DEFAULT_ROUTE_DEADLINE,
    DEFAULT_WAIT_TIMEOUT, DEFAULT_WAITER_LIMIT, MAX_ACTIVE_LIMIT, MAX_PER_HEADER_BYTES,
    MAX_WAIT_TIMEOUT, MAX_WAITER_LIMIT, MatchedRoute, RouteMatch, RouteTable,
};

/// The admission-layer configuration. `expected_host`/`expected_origin`
/// must always be set explicitly on the application listener — a zero
/// value would silently admit any Host/Origin. `expected_host: None`
/// skips the Host check; the only legitimate `None` is the loopback
/// operations listener (health + metrics) built by
/// [`crate::router::build_ops_router`]. [`crate::router::build_app_router`]
/// rejects a `None` at startup — fail closed, not per-request.
#[derive(Debug, Clone)]
pub struct AdmissionConfig {
    /// Exact raw `Host` value the application listener binds
    /// (e.g. `127.0.0.1:8080`); `None` disables the check (ops listener
    /// only — the app router refuses to build without one).
    pub expected_host: Option<String>,
    /// Caps on concurrently admitted in-flight requests. `0` → default.
    pub active_limit: usize,
    /// Cap on requests waiting for an active slot. `0` → default.
    pub waiter_limit: usize,
    /// Max time a waiter may queue before `503`. `0` → default.
    pub wait_timeout: Duration,
    /// Per-route budget from admission through response. `0` → default.
    pub route_deadline: Duration,
    /// Total-header wire budget. `0` → default.
    pub max_header_bytes: usize,
    /// Per-header budget. `0` → default.
    pub max_per_header_bytes: usize,
    /// Optional transport metrics hooks.
    pub metrics: Option<HttpMetrics>,
}

impl Default for AdmissionConfig {
    /// The §4.6 installed profile: 32 active / 64 waiters / 5 s wait /
    /// 15 s route deadline / 32 KiB total-header / 4 KiB per-header.
    /// `expected_host` starts `None` — the application listener must
    /// set it explicitly (a zero value would silently admit any Host).
    fn default() -> Self {
        Self {
            expected_host: None,
            active_limit: DEFAULT_ACTIVE_LIMIT,
            waiter_limit: DEFAULT_WAITER_LIMIT,
            wait_timeout: DEFAULT_WAIT_TIMEOUT,
            route_deadline: DEFAULT_ROUTE_DEADLINE,
            max_header_bytes: DEFAULT_MAX_HEADER_BYTES,
            max_per_header_bytes: MAX_PER_HEADER_BYTES,
            metrics: None,
        }
    }
}

/// Shared admission state — one per listener.
#[derive(Debug)]
pub struct Admission {
    cfg: AdmissionConfig,
    table: RouteTable,
    slots: Arc<Semaphore>,
    waiters: AtomicUsize,
}

impl Admission {
    /// Builds the layer state. `<= 0` limits take the upstream defaults;
    /// any value above its §4.6 hard cap is a build-time error
    /// ("exceeding a hard cap fails startup").
    pub fn new(cfg: AdmissionConfig, specs: &[policy::RouteSpec]) -> Result<Arc<Self>, Failure> {
        let cfg = cfg.normalized()?;
        let table = RouteTable::build(specs)?;
        Ok(Arc::new(Self {
            slots: Arc::new(Semaphore::new(cfg.active_limit)),
            cfg,
            table,
            waiters: AtomicUsize::new(0),
        }))
    }
}

impl AdmissionConfig {
    /// Applies defaults and validates against §4.6 hard caps.
    pub fn normalized(mut self) -> Result<Self, Failure> {
        if self.active_limit == 0 {
            self.active_limit = DEFAULT_ACTIVE_LIMIT;
        }
        if self.waiter_limit == 0 {
            self.waiter_limit = DEFAULT_WAITER_LIMIT;
        }
        if self.wait_timeout.is_zero() {
            self.wait_timeout = DEFAULT_WAIT_TIMEOUT;
        }
        if self.route_deadline.is_zero() {
            self.route_deadline = DEFAULT_ROUTE_DEADLINE;
        }
        if self.max_header_bytes == 0 {
            self.max_header_bytes = DEFAULT_MAX_HEADER_BYTES;
        }
        if self.max_per_header_bytes == 0 {
            self.max_per_header_bytes = MAX_PER_HEADER_BYTES;
        }
        let over = |what: &'static str, got: u64, cap: u64| {
            Err(Failure::new(
                FailureKind::Invalid,
                "transport_admission",
                format!("{what} {got} exceeds §4.6 hard cap {cap}"),
            ))
        };
        if self.active_limit > MAX_ACTIVE_LIMIT {
            return over(
                "active_limit",
                self.active_limit as u64,
                MAX_ACTIVE_LIMIT as u64,
            );
        }
        if self.waiter_limit > MAX_WAITER_LIMIT {
            return over(
                "waiter_limit",
                self.waiter_limit as u64,
                MAX_WAITER_LIMIT as u64,
            );
        }
        if self.wait_timeout > MAX_WAIT_TIMEOUT {
            return over(
                "wait_timeout",
                self.wait_timeout.as_secs(),
                MAX_WAIT_TIMEOUT.as_secs(),
            );
        }
        if self.max_header_bytes > policy::MAX_HEADER_BYTES {
            return over(
                "max_header_bytes",
                self.max_header_bytes as u64,
                policy::MAX_HEADER_BYTES as u64,
            );
        }
        if self.max_per_header_bytes > MAX_PER_HEADER_BYTES {
            return over(
                "max_per_header_bytes",
                self.max_per_header_bytes as u64,
                MAX_PER_HEADER_BYTES as u64,
            );
        }
        // §4.6 cross-field: active × 2 MiB must not exceed the 64 MiB
        // aggregate buffered-response cap.
        if (self.active_limit as u64) * (policy::MAX_RESPONSE_BUFFER as u64)
            > policy::MAX_AGGREGATE_BUFFER
        {
            return over(
                "active_limit*max_response_buffer",
                (self.active_limit as u64) * (policy::MAX_RESPONSE_BUFFER as u64),
                policy::MAX_AGGREGATE_BUFFER,
            );
        }
        Ok(self)
    }
}

/// The axum `from_fn_with_state` entry point.
pub async fn layer(
    axum::extract::State(adm): axum::extract::State<Arc<Admission>>,
    req: Request,
    next: Next,
) -> Response {
    adm.serve(req, next).await
}

struct WaiterGuard<'a> {
    waiters: &'a AtomicUsize,
}

impl Drop for WaiterGuard<'_> {
    fn drop(&mut self) {
        self.waiters.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Pairs a gauge `.inc()` with the matching `.dec()` on drop — a panic,
/// early return, or dropped future cannot drift the gauge.
struct GaugeGuard {
    gauge: prometheus_client::metrics::gauge::Gauge<i64>,
}

impl GaugeGuard {
    fn inc_tracked(gauge: &prometheus_client::metrics::gauge::Gauge<i64>) -> Self {
        gauge.inc();
        Self {
            gauge: gauge.clone(),
        }
    }
}

impl Drop for GaugeGuard {
    fn drop(&mut self) {
        self.gauge.dec();
    }
}

impl Admission {
    async fn serve(&self, mut req: Request, next: Next) -> Response {
        // 1. Loopback peer.
        let loopback = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .is_some_and(|ConnectInfo(peer)| peer.ip().is_loopback());
        if !loopback {
            return self.reject(StatusCode::FORBIDDEN, "PEER_NOT_LOOPBACK");
        }
        // 2. Exact raw Host. No normalization: a wrong port, extra
        // trailing dot, or alternate casing is rejected.
        if let Some(expected) = &self.cfg.expected_host
            && request_host(&req) != expected.as_str()
        {
            return self.reject(StatusCode::FORBIDDEN, "HOST_MISMATCH");
        }
        // 3. CORS is disabled: a preflight must never reach a handler.
        if req.method() == Method::OPTIONS {
            return self.reject(StatusCode::FORBIDDEN, "CORS_DISABLED");
        }
        // 4. Route allowlist.
        let path = req.uri().path().to_string();
        let (policy, template) = match self.table.match_route(req.method(), &path) {
            RouteMatch::Matched { policy, template } => (policy, template),
            RouteMatch::MethodNotAllowed => {
                let allow = self.table.allow_for(&path).unwrap_or_default();
                return error::method_not_allowed(&path, &allow);
            }
            RouteMatch::NotFound => return error::not_found(&path),
        };
        // 5. Header bounds. Per-header 4 KiB, total wire 32 KiB,
        // duplicate cookie names.
        for (name, value) in req.headers() {
            if name.as_str().len() + 2 + value.len() + 2 > self.cfg.max_per_header_bytes {
                return self.reject(
                    StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                    "HEADER_TOO_LARGE",
                );
            }
        }
        if wire_header_bytes(&req) > self.cfg.max_header_bytes {
            return self.reject(
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                "HEADERS_TOO_LARGE",
            );
        }
        if crate::cookies::has_duplicate_cookie_names(req.headers()) {
            return self.reject(StatusCode::BAD_REQUEST, "DUPLICATE_COOKIE");
        }
        // 6. Stash route policy for the inner Origin/CSRF/session/
        // buffered layers, and the matched template for the access
        // observer's sanitized path label.
        req.extensions_mut().insert(MatchedRoute {
            policy,
            path_template: template,
        });
        // 7. Active/waiter admission — acquired before any body read or
        // PostgreSQL touch (§4.6).
        let Some(permit) = self.acquire().await else {
            return self.reject(StatusCode::SERVICE_UNAVAILABLE, "ADMISSION_FULL");
        };
        let _permit = permit;
        let _active = self
            .cfg
            .metrics
            .as_ref()
            .map(|m| GaugeGuard::inc_tracked(&m.active_requests));
        // 8. Per-route deadline.
        let ran = tokio::time::timeout(self.cfg.route_deadline, next.run(req)).await;
        match ran {
            Ok(mut resp) => {
                // Propagate the matched template to the response so the
                // outer access observer can label the outcome with the
                // sanitized template (never the raw path).
                resp.extensions_mut().insert(MatchedRoute {
                    policy,
                    path_template: template,
                });
                resp
            }
            Err(_) => self.reject(StatusCode::REQUEST_TIMEOUT, "ROUTE_DEADLINE"),
        }
    }

    /// `acquire` — upstream's slot-channel + waiter-budget acquire:
    /// an immediate active slot wins; otherwise the request registers
    /// as a waiter (bounded by `waiter_limit`) and waits up to
    /// `wait_timeout`. The waiter registration rolls back on timeout,
    /// cancel, or permit acquisition.
    async fn acquire(&self) -> Option<OwnedSemaphorePermit> {
        if let Ok(p) = self.slots.clone().try_acquire_owned() {
            return Some(p);
        }
        if self.waiters.fetch_add(1, Ordering::SeqCst) >= self.cfg.waiter_limit {
            self.waiters.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        let _waiting = self
            .cfg
            .metrics
            .as_ref()
            .map(|m| GaugeGuard::inc_tracked(&m.waiting_requests));
        let _guard = WaiterGuard {
            waiters: &self.waiters,
        };
        let got =
            tokio::time::timeout(self.cfg.wait_timeout, self.slots.clone().acquire_owned()).await;
        match got {
            Ok(Ok(p)) => Some(p),
            _ => None,
        }
    }

    /// The `Allow` header value for a path — used by the
    /// `method_not_allowed` fallback (§4.1.1).
    #[must_use]
    pub fn allow_for(&self, path: &str) -> Option<String> {
        self.table.allow_for(path)
    }

    fn reject(&self, status: StatusCode, reason: &'static str) -> Response {
        if let Some(m) = &self.cfg.metrics {
            m.admission_rejected(reason);
        }
        error::reject(status, reason)
    }
}

/// `r.Host` — the exact raw Host value: the `Host` header when present
/// (HTTP/1.1), else the URI authority (HTTP/2 `:authority` is mapped
/// there by hyper). Anything else yields `""`, which fails the exact
/// compare — fail closed.
#[must_use]
pub fn request_host(req: &Request) -> &str {
    if let Some(v) = req.headers().get(header::HOST) {
        if let Ok(s) = v.to_str() {
            return s;
        }
        return "";
    }
    req.uri().authority().map(|a| a.as_str()).unwrap_or("")
}

/// `WireHeaderBytes` — the exact HTTP/1.1 request-line + header framing
/// accounted for by the admission budget, including Host and the
/// terminal CRLF. `GET /p?q HTTP/1.1\r\n` + `Host: h\r\n` +
/// `Name: v\r\n`×N + `\r\n`. Host is written once explicitly (upstream
/// hoists it out of `r.Header`); the `host` entry in `req.headers()`
/// is skipped so it is never double-counted.
#[must_use]
pub fn wire_header_bytes(req: &Request) -> usize {
    let target = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let mut total = req.method().as_str().len() + 1 + target.len() + " HTTP/1.1\r\n".len();
    total += "Host: ".len() + request_host(req).len() + 2;
    for (name, value) in req.headers() {
        if *name == header::HOST {
            continue;
        }
        total += name.as_str().len() + 2 + value.len() + 2;
    }
    total + 2
}
