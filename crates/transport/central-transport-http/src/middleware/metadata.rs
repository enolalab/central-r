//! Request metadata — §4.2 layer 2: request/correlation identity
//! validation-or-replacement plus metadata bounds.
//!
//! Every inbound `X-Request-Id`/`X-Correlation-Id`/`X-Forwarded-*`
//! value is untrusted: this layer strips inbound correlation headers
//! and installs a freshly minted UUIDv7 `RequestId` extension so the
//! access observer and any inner log context share one safe,
//! server-generated identity. No inbound header value can propagate
//! into logs or responses (§4.2: "strict request/correlation identity
//! validation or replacement" — replacement is the strict choice).

use axum::extract::Request;
use axum::http::header::HeaderName;
use axum::middleware::Next;
use axum::response::Response;

/// Inbound correlation/forwarding headers stripped at the boundary.
/// The list is exact: `X-Forwarded-*` is enumerated rather than
/// prefix-matched so an unrelated `X-Forwarded-Looking` header is not
/// silently eaten.
const STRIPPED: &[&str] = &[
    "x-request-id",
    "x-correlation-id",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
    "forwarded",
];

/// The server-generated request identity (UUIDv7 — time-ordered,
/// never derived from request content).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestId(pub uuid::Uuid);

impl RequestId {
    /// The canonical hyphenated form, safe for logs and `X-Request-Id`.
    #[must_use]
    pub fn as_string(&self) -> String {
        self.0.to_string()
    }
}

/// The middleware entry point (`from_fn`).
pub async fn layer(mut req: Request, next: Next) -> Response {
    for name in STRIPPED {
        req.headers_mut().remove(HeaderName::from_static(name));
    }
    req.extensions_mut().insert(RequestId(uuid::Uuid::now_v7()));
    next.run(req).await
}
