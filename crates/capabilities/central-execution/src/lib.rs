//! `central-execution` — execution commands (claim, cancel, resume,
//! harness-run, recovery epochs, retry, outbox); owns the
//! claimability-decoration query contract (cyclic-edge inversion,
//! rust-application-boundaries.md §2.2).
//!
//! Stub crate: the `domain.rs` / `port.rs` / `query.rs` / `app.rs`
//! four-layer structure lands in this capability's R-slice.
