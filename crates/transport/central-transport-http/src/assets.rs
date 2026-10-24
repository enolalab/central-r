//! Embedded asset registry — the Rust port of upstream
//! `assets/embed.go` (`//go:embed static/*`).
//!
//! Every byte the transport serves under `/assets/...` is compiled into
//! the binary. There is no filesystem fallback and no dynamic content:
//! a name outside the fixed allowlist resolves to `None`, which the
//! route renders as the fixed `404` outcome — identical to any other
//! unmatched path, so asset existence is never enumerable.

use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};

/// One embedded asset: bytes plus its fixed `Content-Type`.
pub struct Asset {
    /// The compiled-in bytes.
    pub bytes: &'static [u8],
    /// The exact `Content-Type` the route emits.
    pub content_type: &'static str,
}

const CENTRAL_CSS: &[u8] = include_bytes!("../assets/central.css");
const BOOTSTRAP_JS: &[u8] = include_bytes!("../assets/bootstrap.js");
const TASKS_POLL_JS: &[u8] = include_bytes!("../assets/tasks_poll.js");
const OFFICE_JS: &[u8] = include_bytes!("../assets/office.js");

/// The embedded allowlist — upstream `assets.Static` reduced to its
/// four shipped files. Path segments are never interpreted: the map
/// key is the whole `{name}` segment.
#[must_use]
pub fn get(name: &str) -> Option<Asset> {
    let (bytes, content_type) = match name {
        "central.css" => (CENTRAL_CSS, "text/css; charset=utf-8"),
        "bootstrap.js" => (BOOTSTRAP_JS, "text/javascript; charset=utf-8"),
        "tasks_poll.js" => (TASKS_POLL_JS, "text/javascript; charset=utf-8"),
        "office.js" => (OFFICE_JS, "text/javascript; charset=utf-8"),
        _ => return None,
    };
    Some(Asset {
        bytes,
        content_type,
    })
}

/// Whether `name` is a well-formed single-segment asset name
/// (defense in depth behind the route template's single-segment
/// match — `/assets/../x` can never reach this registry anyway).
#[must_use]
pub fn well_formed_name(name: &str) -> bool {
    !name.is_empty()
        && !name.contains('/')
        && !name.contains('\\')
        && name != "."
        && name != ".."
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// The route handler body for `/assets/{name}`: fixed content type,
/// fixed bytes. `None` maps to the shared `404` outcome (the caller
/// uses [`crate::error::not_found`]).
#[must_use]
pub fn response(name: &str) -> Option<Response> {
    if !well_formed_name(name) {
        return None;
    }
    let asset = get(name)?;
    let mut resp = asset.bytes.into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(asset.content_type),
    );
    Some(resp)
}
