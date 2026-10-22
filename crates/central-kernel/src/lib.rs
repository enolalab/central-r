//! `central-kernel` — the single composition root (manual constructor
//! injection), supervised-component lifecycle, and graceful shutdown.
//! It is the only crate that may import both inward capability contracts
//! and concrete adapters (rust-application-boundaries.md §3.3).
//!
//! Stub crate: lifecycle supervision lands in this kernel's R-slice.
