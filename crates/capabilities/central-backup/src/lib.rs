//! `central-backup` — backup/restore manifests, verified restore
//! tickets, chunked inventory, quarantine; exclusive advisory-lock scope
//! and consistent-point snapshots.
//!
//! Layer structure (rust-application-boundaries.md §2):
//!
//! - [`domain`] — the backup/migration lifecycle vocabulary
//!   (`internal/backup/migration.go`): target/session bindings,
//!   broker proofs, the canonical lock order, baseline manifest,
//!   provisioning phases, and the external record state machine.
//! - [`backup`] — the C01/C02 backup operation, capacity admission,
//!   ready-artifact inventory chunks, and the seal-root manifest
//!   (`internal/backup/recovery.go`, `inventory.go`,
//!   `repository_seal.go`).
//! - [`recovery`] — the C03–C05 restore operation, ticket/reset
//!   evidence, admission profile, closed refusal vocabulary, and the
//!   quarantine finding vocabulary.
//! - [`repository`] — the repository binding, sealed-backup manifest,
//!   seal companion, and publication receipt
//!   (`internal/backup/repository_metadata.go`, `repository_seal.go`).
//! - [`port`] — the capability-owned contracts
//!   (`internal/backup/port/migration_port.go`,
//!   `internal/backup/port/recovery_port.go`): migration proofs,
//!   protected backup/restore journals, atomic admission snapshots,
//!   target exclusions, the destructive engine, and the broker-only
//!   ticket/authority boundaries.
//! - [`app`] — the coordinators
//!   (`internal/backup/app/{migration_coordinator,backup_coordinator,
//!   restore_coordinator,restore_verifier,authority_reset}.go`).
//! - [`query`] — read-side projections.

pub mod app;
pub mod backup;
pub mod domain;
pub mod port;
pub mod query;
pub mod recovery;
pub mod repository;
mod wire;
