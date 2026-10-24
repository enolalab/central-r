//! Metrics — the loopback scrape endpoint plus the transport's own
//! metric handles.
//!
//! The kernel owns the `prometheus_client::registry::Registry` (Task
//! 13 composition); the transport registers its counters/gauges into
//! it at build time and serves `/metrics` by encoding the registry.
//! The endpoint lives on the dedicated operations listener — the
//! admission layer runs there too (`expected_host: None`), so the
//! loopback-only guard applies to scrapes exactly like the health
//! endpoints.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;

/// The transport's metric handles — registered into a kernel-owned
/// registry at build time. Cloneable; the admission layer holds a copy.
#[derive(Debug, Clone)]
pub struct HttpMetrics {
    /// Currently admitted in-flight requests.
    pub active_requests: Gauge<i64>,
    /// Requests queued waiting for an admission slot.
    pub waiting_requests: Gauge<i64>,
    /// Admission rejections by reason token.
    pub admission_rejections: Family<Vec<(String, String)>, Counter>,
}

impl HttpMetrics {
    /// Registers the transport metrics into `registry`. Idempotent
    /// naming per `prometheus-client` convention.
    #[must_use]
    pub fn register(registry: &mut Registry) -> Self {
        let active = Gauge::<i64>::default();
        let waiting = Gauge::<i64>::default();
        let rejections = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "central_http_active_requests",
            "Currently admitted in-flight requests",
            active.clone(),
        );
        registry.register(
            "central_http_waiting_requests",
            "Requests queued for an admission slot",
            waiting.clone(),
        );
        registry.register(
            "central_http_admission_rejections",
            "Admission rejections by reason token",
            rejections.clone(),
        );
        Self {
            active_requests: active,
            waiting_requests: waiting,
            admission_rejections: rejections,
        }
    }

    /// Records one admission rejection under its stable reason token.
    pub fn admission_rejected(&self, reason: &'static str) {
        self.admission_rejections
            .get_or_create(&vec![("reason".to_string(), reason.to_string())])
            .inc();
    }
}

/// `GET /metrics` — encodes the kernel-owned registry in the
/// Prometheus text format. `503` never happens for encode errors
/// (encoding into a `String` is infallible in practice; an error still
/// maps to the safe empty-body `500`).
pub async fn metrics(
    State(registry): State<Arc<prometheus_client::registry::Registry>>,
) -> Response {
    let mut body = String::new();
    match encode(&mut body, registry.as_ref()) {
        Ok(()) => (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                "application/openmetrics-text; version=1.0.0; charset=utf-8",
            )],
            body,
        )
            .into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// The registry type re-export so callers need no direct
/// `prometheus-client` import.
pub type SharedRegistry = Arc<Registry>;
