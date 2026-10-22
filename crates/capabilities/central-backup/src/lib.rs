//! `central-backup` — backup/restore manifests, verified restore
//! tickets, chunked inventory, quarantine; exclusive advisory-lock scope
//! and consistent-point snapshots.
//!
//! Layer structure (rust-application-boundaries.md §2):
//!
//! - [`domain`] — the backup/migration lifecycle vocabulary
//!   (`internal/backup/migration.go`): target/session bindings,
//!   broker proofs, the canonical lock order, baseline manifest.
//! - [`port`] — the migration-domain contracts
//!   (`internal/backup/port/migration_port.go`): the broker proof
//!   service, runner request/result types, and inspector facts.
//!
//! `query` / `app` land in this capability's later R-slices.

pub mod domain;
pub mod port;
