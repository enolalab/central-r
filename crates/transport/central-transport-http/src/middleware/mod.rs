//! The §4.2 canonical layer stack, one module per layer.
//!
//! Order (outermost → innermost), wired by [`crate::router`]:
//!
//! 1. [`recover`] — panic → fixed `500` + §4.4 profile.
//! 2. [`metadata`] — strip inbound correlation headers, mint request id.
//! 3. [`security_headers`] — the exact §4.4 profile on every response.
//! 4. [`access`] — sanitized access observation.
//! 5. [`admission`] + [`origin`] — loopback peer, exact Host, route
//!    allowlist, header bounds, semaphore/waiter admission, route
//!    deadline, exact Origin.
//! 6. [`session_auth`] + [`preauth`] — session authentication and
//!    CSRF validation per the stashed route policy.
//! 7. [`buffer`] (innermost transport layer) — bounded response
//!    buffering and the delivery precommit.

pub mod access;
pub mod admission;
pub mod buffer;
pub mod metadata;
pub mod origin;
pub mod preauth;
pub mod recover;
pub mod security_headers;
pub mod session_auth;
