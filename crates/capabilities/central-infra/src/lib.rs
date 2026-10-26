//! `central-infra` — local init, prepare, compose lifecycle, doctor,
//! maintenance, advisory; infrastructure authority mediated through the
//! root-owned helper protocol (ADR 0009/0011 topology).
//!
//! `config` is the strict `central.config/v1` loader, validator, and
//! authenticated-view verifier ported from upstream
//! `internal/config`. `authority` is the A03 host-authority domain —
//! the durable `InstanceBinding`, the locked no-login identities, the
//! helper-verb matrix, and the broker/helper protocol vocabulary
//! ported from upstream `internal/authority` (kept here rather than
//! in `central-authorization` per rust-application-boundaries.md §2:
//! host infrastructure authority is this capability's, not the
//! Workspace-scoped authorization domain's). `domain` holds the B03
//! lifecycle state machine, the B04/B05/B10 secret-bootstrap domain,
//! the byte-exact MinIO policy contracts, and the B02 dependency
//! vocabulary the ports carry. `port` declares the async boundary
//! traits the privileged adapters implement. `app` is the thin
//! orchestration layer; `query` is a documented stub until the B01–B03
//! read-side projections land.

pub mod advisory;
pub mod app;
pub mod authority;
pub mod config;
pub mod domain;
pub mod port;
pub mod query;
