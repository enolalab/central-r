//! `central-transport-http` — the HTTP transport boundary.
//!
//! This crate is the sole `axum`/`tower`/`askama` consumer in the
//! workspace (§2). It ports the upstream `gintransport` HTTP contract:
//!
//! - [`middleware::admission`] — loopback peer, exact Host, route
//!   allowlist, header bounds, duplicate-cookie guard, the
//!   active/waiter semaphore (32 in flight / 64 queued / 5 s), and the
//!   per-route deadline. Admission is acquired before any body read or
//!   PostgreSQL touch (§4.6).
//! - [`middleware::origin`] — exact-Origin enforcement; CORS is
//!   structurally disabled.
//! - [`middleware::preauth`] — the pre-auth double-submit CSRF pair
//!   (`central_preauth_csrf` cookie ↔ `X-Central-Preauth-CSRF` header).
//! - [`middleware::session_auth`] — `central_session` validation via
//!   `central_session::app::Service` plus the session-CSRF
//!   double-submit (`X-CSRF-Token` header or `csrf` form field ↔
//!   `central_session_csrf` cookie).
//! - [`middleware::buffer`] — per-route bounded response buffering and
//!   the `delivery_pending → active` precommit seam.
//! - [`middleware::security_headers`] — the exact §4.4 profile on every
//!   response; [`middleware::recover`], [`middleware::metadata`],
//!   [`middleware::access`] complete the §4.2 order.
//! - [`health`] — `/health/live` + profile-aware `/health/ready`;
//!   [`metrics`] — the loopback `/metrics` listener surface.
//! - [`rendering`] + [`assets`] — Askama templates and the embedded
//!   static allowlist (no filesystem fallback).
//! - [`router`] — the §4.1 configured router: explicit `MethodRouter`
//!   gating, fixed `404`/`405` outcomes, no trailing-slash redirects,
//!   no CORS.
//!
//! Handlers for `/app/...` and `/api/v1/...` are Task 12; kernel
//! composition (concrete session service, TLS, listeners) is Task 13.
//! The transport stays generic over the session service through the
//! narrow [`ports`] traits.

pub mod api;
pub mod assets;
pub mod b64;
pub mod cookies;
pub mod error;
pub mod health;
pub mod metrics;
pub mod middleware;
pub mod policy;
pub mod ports;
pub mod rendering;
pub mod router;
/// B06: TLS 1.3-only termination for the application listener
/// (`TlsListener` over the bound loopback `TcpListener`).
pub mod tls;
pub mod web;

/// Constant-time string equality (`crypto/subtle.ConstantTimeCompare`
/// on UTF-8 bytes — the length check exits early exactly like
/// upstream's).
#[must_use]
pub fn ct_eq_str(a: &str, b: &str) -> bool {
    cookies::ct_eq(a.as_bytes(), b.as_bytes())
}
