//! `central-session` — the B06 session capability: bootstrap exchange
//! two-phase protocol, session lifecycle, cookie/CSRF result bindings,
//! and crash-cutpoint reconciliation. Port of upstream
//! `internal/session`.
//!
//! Four-layer structure (rust-application-boundaries.md §2):
//!
//! - [`domain`] — the `pending_bootstrap -> delivery_pending -> active
//!   -> revoked` lifecycle state machine, the hash-only `Session`
//!   entity, and every request/result type crossing the ports.
//! - [`contract`] — the opaque `BootstrapVerifier`, `CandidateBinding`,
//!   `RequestIdentity`, `PreAuthCSRF`, and the typed `Failure` contract
//!   whose `Display`/`Debug` never carry plaintext or digest material.
//! - [`port`] — `SessionStore` (durable session persistence) and
//!   `ProtectedBootstrap` (D1: the broker-facing candidate activation
//!   port; R3 ships the dev-gated `central-adapter-linux` file-backed
//!   implementation, the protected broker lands in R5).
//! - [`query`] — the read projections driving the `/app/bootstrap`
//!   server-rendered page.
//! - [`app`] — the `Service` orchestrating pre-auth CSRF, exchange,
//!   delivery, precommit activation, validation, logout, and
//!   reconciliation.
//!
//! Plaintext bootstrap tokens, session tokens, and CSRF values are
//! transport-scoped only; every type crossing a port boundary carries
//! opaque identifiers and SHA-256 hashes. Throttle, expiry, and
//! first-use fences are all decided on PostgreSQL `clock_timestamp()`.

#![forbid(unsafe_code)]

pub mod app;
pub mod contract;
pub mod domain;
pub mod port;
pub mod query;
