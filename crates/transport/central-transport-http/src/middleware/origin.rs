//! Origin — port of upstream `middleware/origin.go`.
//!
//! Exact-Origin discipline applied to every admitted request, on every
//! route and method:
//!
//! - More than one `Origin` header → `400 DUPLICATE_ORIGIN`.
//! - One `Origin` whose value is empty or literally `null`
//!   (case-insensitive) → `403 NULL_ORIGIN`.
//! - One `Origin` that does not equal the expected value verbatim →
//!   `403 ORIGIN_MISMATCH`. No normalization — scheme, host, port, and
//!   path-free shape must match exactly.
//! - No `Origin` at all → rejected with `403 ORIGIN_REQUIRED` only when
//!   the matched route policy sets `origin_required` (state-changing
//!   routes); safe routes may legitimately carry none.
//!
//! CORS is structurally disabled: no `Access-Control-*` header is ever
//! emitted, and the admission layer rejects `OPTIONS` preflights before
//! this layer runs.

use std::sync::Arc;

use axum::extract::Request;
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;

use crate::error;
use crate::policy::MatchedRoute;

/// The expected exact origin string — `scheme://host[:port]` built by
/// the kernel from the listener address and TLS mode (upstream's
/// `serveExpectedOrigin`, e.g. `https://127.0.0.1:8080`). Panics are
/// avoided by construction: [`OriginConfig::new`] rejects an empty
/// value exactly like upstream's `panic("Origin called with empty
/// expected value")` at composition time.
#[derive(Debug, Clone)]
pub struct OriginConfig {
    expected: Arc<str>,
}

impl OriginConfig {
    /// Builds the config; an empty expected value is a composition bug
    /// and fails immediately (upstream panics).
    #[must_use]
    pub fn new(expected: &str) -> Self {
        assert!(
            !expected.is_empty(),
            "middleware: Origin called with empty expected value"
        );
        Self {
            expected: Arc::from(expected),
        }
    }
}

/// Layer 5 (second half) of the §4.2 canonical order — runs directly
/// inside the admission layer's inner neighbor, mirroring upstream's
/// `Admission → Origin → PreAuthCSRF → Buffered` chain.
pub async fn layer(
    axum::extract::State(cfg): axum::extract::State<OriginConfig>,
    req: Request,
    next: Next,
) -> Response {
    let mut values = req.headers().get_all(header::ORIGIN).iter();
    if let Some(first) = values.next() {
        if values.next().is_some() {
            return error::reject(StatusCode::BAD_REQUEST, "DUPLICATE_ORIGIN");
        }
        let raw = first.to_str().unwrap_or("");
        if raw.is_empty() || raw.eq_ignore_ascii_case("null") {
            return error::reject(StatusCode::FORBIDDEN, "NULL_ORIGIN");
        }
        if raw != cfg.expected.as_ref() {
            return error::reject(StatusCode::FORBIDDEN, "ORIGIN_MISMATCH");
        }
    } else {
        let required = req
            .extensions()
            .get::<MatchedRoute>()
            .is_some_and(|m| m.policy.origin_required);
        if required {
            return error::reject(StatusCode::FORBIDDEN, "ORIGIN_REQUIRED");
        }
    }
    next.run(req).await
}
