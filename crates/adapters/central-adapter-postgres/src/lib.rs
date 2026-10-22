//! `central-adapter-postgres` — `sqlx` implementations of capability
//! `port.rs`/`query.rs` traits and the native `central.schema_migrations`
//! ledger runner. Sole consumer of `sqlx` (canonical declaration per
//! rust-engineering-workflow.md §3.4; `migrate` feature prohibited).
//!
//! Stub crate: implementations land in this adapter's R-slice
//! (rust-application-boundaries.md §2.4).
