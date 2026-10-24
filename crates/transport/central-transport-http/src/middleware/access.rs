//! Access observation — §4.2 layer 4: "safe access observation using
//! sanitized facts only".
//!
//! For every response the layer emits one [`AccessRecord`] containing
//! only sanitized facts: the method, the matched route *template* (or
//! the fixed `unmatched` sentinel — never the raw request path, which
//! could carry tokens/ids), the response status, and the elapsed
//! duration. No headers, bodies, cookies, query strings, peer detail
//! beyond loopback-ness, or failure text is ever recorded.
//!
//! The default observer forwards to `tracing` at `INFO` for 2xx/3xx
//! and `WARN` otherwise; domain code stays free of logging per §7.

use std::sync::Arc;
use std::time::Instant;

use axum::extract::Request;
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::Response;

use crate::policy::MatchedRoute;

/// The sanitized path label for requests admission rejected before
/// matching (404/405 fallouts) — §4.1.1's fixed sentinel.
pub const UNMATCHED: &str = "unmatched";

/// One sanitized access record.
#[derive(Debug, Clone)]
pub struct AccessRecord {
    /// The request method (uppercase, from the HTTP grammar).
    pub method: Method,
    /// The matched route template (e.g. `/app/tasks/{task_id}`) or
    /// `unmatched` — never the raw request path.
    pub route: &'static str,
    /// The final response status.
    pub status: StatusCode,
    /// Wall time from layer entry to response completion.
    pub elapsed: std::time::Duration,
}

/// The observer port — the kernel may swap in its own recorder; the
/// default is the `tracing` emitter below.
pub trait AccessObserver: Send + Sync + 'static {
    /// Called exactly once per response with sanitized facts only.
    fn observe(&self, record: &AccessRecord);
}

/// `TracingAccessObserver` — the default observer: emits one `tracing`
/// event per response carrying only the sanitized fields.
#[derive(Debug, Default, Clone, Copy)]
pub struct TracingAccessObserver;

impl AccessObserver for TracingAccessObserver {
    fn observe(&self, record: &AccessRecord) {
        if record.status.is_server_error() || record.status == StatusCode::TOO_MANY_REQUESTS {
            tracing::warn!(
                method = %record.method,
                route = record.route,
                status = record.status.as_u16(),
                elapsed_ms = record.elapsed.as_millis() as u64,
                "http request"
            );
        } else {
            tracing::info!(
                method = %record.method,
                route = record.route,
                status = record.status.as_u16(),
                elapsed_ms = record.elapsed.as_millis() as u64,
                "http request"
            );
        }
    }
}

/// The middleware entry point (`from_fn_with_state`).
pub async fn layer(
    axum::extract::State(observer): axum::extract::State<Arc<dyn AccessObserver>>,
    req: Request,
    next: Next,
) -> Response {
    let method = req.method().clone();
    let started = Instant::now();
    let resp = next.run(req).await;
    let route = resp
        .extensions()
        .get::<MatchedRoute>()
        .map_or(UNMATCHED, |m| m.path_template);
    observer.observe(&AccessRecord {
        method,
        route,
        status: resp.status(),
        elapsed: started.elapsed(),
    });
    resp
}
