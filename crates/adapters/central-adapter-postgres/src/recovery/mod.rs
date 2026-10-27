//! `internal/adapter/postgres/backup` — the recovery-side PostgreSQL
//! surface: the b25–b29 durable evidence stores.
//!
//! - [`store::RecoveryAuditStore`] — `recovery_audit.go`: the C04
//!   projection (`recovery_operations`), quarantine findings
//!   (`recovery_quarantines`), C05 database authority reset
//!   (`recovery_bootstrap_registrations`), and the aggregate authority
//!   reset receipt (`recovery_authority_reset_receipts`). Bound to one
//!   dedicated `central_migration` connection, exactly like upstream.
//! - [`restored_inventory::RestoredInventoryVerifier`] —
//!   `restored_inventory.go`: merge-compares the sealed inventory with
//!   restored metadata, then rereads every expected body.
//! - [`import_verify::ImportTargetInspector`] — `import_verify.go`:
//!   post-restore ready-artifact listing and dump-TOC shape verification.
//! - [`prune_log::PruneLogStore`] — the b29 crash-resume journal
//!   (`destructive.PruneJournal`).

mod import_verify;
mod prune_log;
mod restored_inventory;
mod store;

pub use import_verify::{ImportReadyArtifact, ImportTableRef, ImportTargetInspector};
pub use prune_log::{PruneBatch, PruneCandidate, PruneJournal, PruneLogStore, PruneRowState};
pub use restored_inventory::RestoredInventoryVerifier;
pub use store::RecoveryAuditStore;
