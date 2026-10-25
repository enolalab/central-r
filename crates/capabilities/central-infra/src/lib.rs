//! `central-infra` — local init, prepare, compose lifecycle, doctor,
//! maintenance, advisory; infrastructure authority mediated through the
//! root-owned helper protocol (ADR 0009/0011 topology).
//!
//! `config` is the strict `central.config/v1` loader, validator, and
//! authenticated-view verifier ported from upstream
//! `internal/config`. The remaining `domain.rs` / `port.rs` /
//! `query.rs` / `app.rs` four-layer structure lands in this
//! capability's R-slice (rust-application-boundaries.md §2).

pub mod config;
