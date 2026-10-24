//! §4.4 response-security profile — the exact header set applied to
//! every response the transport produces (uniform: `/app` HTML, `/api`
//! JSON, assets, health, metrics, fixed outcomes).
//!
//! `Referrer-Policy` is `same-origin`, not `no-referrer` — the SB-G4
//! note carried in §4.4: `no-referrer` makes browsers send a literal
//! `Origin: null` on same-origin non-GET/HEAD native `<form>` POST
//! navigations, which the Origin layer then rejects with `403
//! NULL_ORIGIN`, breaking every JS-free form post. Under this CSP
//! (`*-src` all `'self'`/`'none'`) `same-origin` can never leak a
//! cross-origin `Referer`.

use axum::extract::Request;
use axum::http::{HeaderMap, HeaderValue, header};
use axum::middleware::Next;
use axum::response::Response;

/// `MandatoryContentSecurityPolicy` — the strict baseline CSP applied
/// to every HTML outcome, verbatim from §4.4. `default-src 'none'`
/// blocks all loading; `frame-ancestors 'none'` blocks all framing
/// (stronger than `X-Frame-Options`); `form-action 'self'` allows only
/// same-origin form submission; every fetch directive is `'self'` so
/// only embedded same-origin assets can load — no inline script or
/// style is ever permitted.
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; img-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'";

/// `MandatoryCacheControl` — `no-store`, verbatim from §4.4. A cached
/// bootstrap, ready shell, or API outcome is never replayed.
pub const CACHE_CONTROL: &str = "no-store";

/// `ApplySecurityHeaders` — sets the mandatory §4.4 header set on a
/// response header map. Idempotent; overwrites handler values so the
/// profile can never be weakened by an inner layer.
pub fn apply_security_headers(headers: &mut HeaderMap) {
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(CACHE_CONTROL),
    );
}

/// Layer 3 of the §4.2 canonical order — applies the exact
/// response-security profile to every response, including fixed
/// outcomes produced by inner guards (admission/origin/CSRF rejections,
/// buffered failures, fallbacks). The panic-recovery outcome is the
/// only response produced outside this layer and applies the profile
/// itself.
pub async fn layer(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    apply_security_headers(resp.headers_mut());
    resp
}
