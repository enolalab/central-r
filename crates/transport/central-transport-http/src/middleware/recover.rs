//! Panic recovery — §4.2 layer 1 ("safe panic recovery (with private
//! final-outcome recorder)").
//!
//! `tower_http::catch_panic::CatchPanicLayer` with a fixed panic
//! outcome: [`crate::error::recovered_internal`], a `500` carrying the
//! canonical `INTERNAL` envelope and the full §4.4 profile (applied
//! inside the handler because this layer is outermost — its output
//! never re-enters the security-headers layer). The panic payload is
//! recorded only in the private outcome recorder (`tracing`), never in
//! the response.

use axum::response::Response;
use tower_http::catch_panic::CatchPanicLayer;

/// The layer value, built once at composition.
#[must_use]
pub fn layer()
-> CatchPanicLayer<impl tower_http::catch_panic::ResponseForPanic<ResponseBody = axum::body::Body>>
{
    CatchPanicLayer::custom(|err: Box<dyn std::any::Any + Send>| -> Response {
        // Private final-outcome recorder: the panic reaches logs, never
        // the wire.
        let msg = err
            .downcast_ref::<&str>()
            .map(|s| (*s).to_string())
            .or_else(|| err.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "unknown panic".to_string());
        tracing::error!(panic = %msg, "http handler panic recovered");
        crate::error::recovered_internal()
    })
}
