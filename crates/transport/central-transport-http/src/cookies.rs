//! Cookie names, raw `Cookie` header parsing, and `Set-Cookie` builders.
//! Port of upstream `middleware/session.go` and `web/handler.go` cookie
//! handling.
//!
//! Cookie and header names are fixed at compile time. An operator cannot
//! relax them. All credential-bearing cookies are `HttpOnly` (except the
//! session CSRF cookie, which the embedded same-origin form code must
//! read into the hidden form field) and `SameSite=Strict` with `Path=/`.
//! `Secure` is emitted unconditionally: the contract binds these cookies
//! to HTTPS in production, and on the plaintext loopback dev listener the
//! flag is inert.

use axum::http::HeaderMap;
use axum::http::header::COOKIE;

/// `SessionCookieName` — the opaque session identifier minted at
/// activation. HttpOnly and SameSite=Strict.
pub const SESSION_COOKIE: &str = "central_session";

/// `SessionCSRFCookieName` — the session-bound CSRF value. NOT HttpOnly:
/// the embedded same-origin bootstrap helper reads it into the hidden
/// `csrf` form field (upstream `setSessionCookies` keeps this cookie
/// script-readable; the value is double-submit material, not a bearer
/// credential).
pub const SESSION_CSRF_COOKIE: &str = "central_session_csrf";

/// `PreAuthCSRFCookieName` — the cookie carrying the pre-auth CSRF value
/// issued on the bootstrap page. HttpOnly and SameSite=Strict.
pub const PREAUTH_CSRF_COOKIE: &str = "central_preauth_csrf";

/// `PreAuthCSRFHeaderName` — the double-submit header carrying the same
/// pre-auth CSRF value, set by the browser via fetch/XHR on the
/// bootstrap exchange.
pub const PREAUTH_CSRF_HEADER: &str = "x-central-preauth-csrf";

/// `SessionCSRFHeaderName` — the header carrying the session-bound CSRF
/// value on JSON command routes (`X-CSRF-Token` per docs/api/v1.md).
pub const SESSION_CSRF_HEADER: &str = "x-csrf-token";

/// `SessionCSRFFormField` — the hidden form field carrying the
/// session-bound CSRF value on `/app/...` HTML mutations.
pub const SESSION_CSRF_FORM_FIELD: &str = "csrf";

/// Iterate every `name=value` pair across all `Cookie` request headers.
/// The stdlib-style `Request::cookies` helpers deduplicate silently; we
/// walk the raw headers so duplicates stay observable (upstream
/// `splitCookiePairs`).
pub fn cookie_pairs(headers: &HeaderMap) -> impl Iterator<Item = (String, String)> + '_ {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|raw| {
            raw.split(';').map(|pair| {
                let pair = pair.trim();
                match pair.split_once('=') {
                    Some((name, value)) => (name.trim().to_string(), value.trim().to_string()),
                    None => (pair.to_string(), String::new()),
                }
            })
        })
}

/// `pickCSRFCookie` — the first matching cookie value, mirroring
/// upstream `r.Cookie(name)` (first match wins, order preserved).
#[must_use]
pub fn pick_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    cookie_pairs(headers).find_map(|(n, v)| (n == name).then_some(v))
}

/// Every value presented under `name` across the raw `Cookie`
/// header(s), in order. Duplicates stay observable — callers decide
/// whether zero, one, or many values are admissible.
#[must_use]
pub fn cookie_values(headers: &HeaderMap, name: &str) -> Vec<String> {
    cookie_pairs(headers)
        .filter_map(|(n, v)| (n == name).then_some(v))
        .collect()
}

/// `hasDuplicateCookieNames` — whether ANY cookie name appears twice
/// across the raw Cookie header(s). Used by admission as the generic
/// duplicate-cookie guard (400 DUPLICATE_COOKIE).
#[must_use]
pub fn has_duplicate_cookie_names(headers: &HeaderMap) -> bool {
    let mut seen = std::collections::HashSet::new();
    for (name, _) in cookie_pairs(headers) {
        if name.is_empty() {
            continue;
        }
        if !seen.insert(name) {
            return true;
        }
    }
    false
}

/// `hasDuplicateCookieValue` — whether the named cookie appears more
/// than once, regardless of value (a replay signal). Used by the
/// pre-auth CSRF layer as defense in depth (403 CSRF_DUPLICATE).
#[must_use]
pub fn has_duplicate_cookie_name(headers: &HeaderMap, name: &str) -> bool {
    let prefix = format!("{name}=");
    let mut seen = 0usize;
    for raw in headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
    {
        for part in raw.split(';') {
            if part.trim().starts_with(&prefix) {
                seen += 1;
            }
        }
    }
    seen > 1
}

/// Builds a `Set-Cookie` value. The attributes mirror upstream
/// `http.SetCookie` output for the session/pre-auth cookies exactly.
#[must_use]
fn set_cookie(name: &str, value: &str, http_only: bool) -> String {
    let mut s = format!("{name}={value}; Path=/; Secure; SameSite=Strict");
    if http_only {
        s.push_str("; HttpOnly");
    }
    s
}

/// `issueFreshPreAuthCSRF` cookie — HttpOnly pre-auth CSRF cookie.
#[must_use]
pub fn preauth_csrf_set_cookie(value_b64: &str) -> String {
    set_cookie(PREAUTH_CSRF_COOKIE, value_b64, true)
}

/// `setSessionCookies` — the activation pair: the session token is
/// HttpOnly; the session CSRF cookie stays script-readable so the
/// same-origin form code can copy it into the hidden `csrf` field.
#[must_use]
pub fn session_set_cookies(token_b64: &str, csrf_b64: &str) -> [String; 2] {
    [
        set_cookie(SESSION_COOKIE, token_b64, true),
        set_cookie(SESSION_CSRF_COOKIE, csrf_b64, false),
    ]
}

/// `clearSessionCookies` — expires every session-scoped cookie so the
/// browser discards revoked credentials.
#[must_use]
pub fn clear_session_cookies() -> [String; 2] {
    const EXPIRED: &str = "; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Secure; HttpOnly; SameSite=Strict";
    [
        format!("{SESSION_COOKIE}={EXPIRED}"),
        format!("{SESSION_CSRF_COOKIE}={EXPIRED}"),
    ]
}

/// `mintSessionValues` — fresh opaque session token + session-bound
/// CSRF plaintext (request-scoped; hashed before crossing the session
/// boundary). `rand::random` is infallible where upstream's
/// `crypto/rand.Read` was not.
#[must_use]
pub fn mint_session_values() -> ([u8; 32], [u8; 32]) {
    (rand::random(), rand::random())
}

/// `mintIdempotencyKey` — a fresh single-use idempotency token for a
/// mutation form render (upstream B11b `mintIdempotencyKey`).
#[must_use]
pub fn mint_idempotency_key() -> String {
    crate::b64::encode(&rand::random())
}

/// `ct_eq` — constant-time equality over equal-length byte slices (the
/// transport's own copy; `central_session::contract::ct_eq` is
/// crate-private). Every call site compares same-format tokens, so the
/// length check is public.
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
