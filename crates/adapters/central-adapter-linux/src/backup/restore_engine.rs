//! `restore_engine.go` — the composed production restore engine.
//!
//! Joins the independent C04/C05 capabilities — target excluder, pinned
//! `pg_restore` runner, PostgreSQL audit projection, restored-inventory
//! verifier, and the authority resetter — behind the single
//! [`RestoreEngine`] port. It contains no fallback and accepts no
//! caller-selected paths; phase transitions stay with the domain
//! coordinator.

#![forbid(unsafe_code)]

use central_backup::port::{RestoreEngine, RestoreTargetExcluder, RestoreTargetExclusion};
use central_backup::recovery::operation::{AuthorityResetReceipt, RestoreOperation};
use central_backup::recovery::quarantine::QuarantineFinding;
use central_foundation::failure::Failure;

use super::pg_restore::PgRestore;

/// `RestoreDatabaseRunner` — the narrow process boundary implemented by
/// the pinned `pg_restore` adapter. Deliberately exposes no program,
/// target, credential, or repository selector.
pub trait RestoreDatabaseRunner: Send + Sync {
    /// `Restore`.
    fn restore_database(&self, operation: &RestoreOperation) -> Result<(), Failure>;
}

impl RestoreDatabaseRunner for PgRestore {
    fn restore_database(&self, operation: &RestoreOperation) -> Result<(), Failure> {
        PgRestore::restore_database(self, operation)
    }
}

/// `RestoreInventoryVerifier` — compares the exact sealed inventory
/// with the recovered PostgreSQL metadata and object bodies. Findings
/// are locator-free domain evidence; persistence stays with the audit
/// store.
pub trait RestoreInventoryVerifier: Send + Sync {
    /// `VerifyInventory`.
    fn verify_inventory(
        &self,
        operation: &RestoreOperation,
    ) -> Result<Vec<QuarantineFinding>, Failure>;
}

/// `RestoreAuditProjection` — the PostgreSQL projection boundary. The
/// protected broker journal remains authoritative for the restore
/// phase.
pub trait RestoreAuditProjection: Send + Sync {
    /// `ProjectRestoreOperation`.
    fn project_restore_operation(&self, operation: &RestoreOperation) -> Result<(), Failure>;
    /// `RecordQuarantineFindings`.
    fn record_quarantine_findings(
        &self,
        operation: &RestoreOperation,
        findings: &[QuarantineFinding],
    ) -> Result<u64, Failure>;
    /// `UnresolvedQuarantineCount`.
    fn unresolved_quarantine_count(&self, operation: &RestoreOperation) -> Result<u64, Failure>;
}

/// `RestoreAuthorityResetter` — owns the four-step C05 reset
/// composition and returns only the aggregate receipt accepted by the
/// restore coordinator.
pub trait RestoreAuthorityResetter: Send + Sync {
    /// `ResetAuthority`.
    fn reset_authority(
        &self,
        operation: &RestoreOperation,
    ) -> Result<AuthorityResetReceipt, Failure>;
}

/// `ComposedRestoreEngine` — the production adapter that joins
/// independent C04/C05 capabilities without moving phase transitions
/// out of the domain coordinator.
pub struct ComposedRestoreEngine {
    excluder: Box<dyn RestoreTargetExcluder>,
    database: Box<dyn RestoreDatabaseRunner>,
    audit: Box<dyn RestoreAuditProjection>,
    inventory: Box<dyn RestoreInventoryVerifier>,
    resetter: Box<dyn RestoreAuthorityResetter>,
}

impl ComposedRestoreEngine {
    /// `NewComposedRestoreEngine` — every component is required; a nil
    /// composition is never a working engine.
    pub fn new(
        excluder: Box<dyn RestoreTargetExcluder>,
        database: Box<dyn RestoreDatabaseRunner>,
        audit: Box<dyn RestoreAuditProjection>,
        inventory: Box<dyn RestoreInventoryVerifier>,
        resetter: Box<dyn RestoreAuthorityResetter>,
    ) -> Result<Self, Failure> {
        Ok(Self {
            excluder,
            database,
            audit,
            inventory,
            resetter,
        })
    }
}

impl RestoreEngine for ComposedRestoreEngine {
    fn acquire_restore_target_exclusion(
        &self,
        operation: &RestoreOperation,
    ) -> Result<Box<dyn RestoreTargetExclusion>, Failure> {
        self.excluder.acquire_restore_target_exclusion(operation)
    }

    fn restore_database(&self, operation: &RestoreOperation) -> Result<(), Failure> {
        self.database.restore_database(operation)
    }

    fn project_restore_operation(&self, operation: &RestoreOperation) -> Result<(), Failure> {
        self.audit.project_restore_operation(operation)
    }

    fn verify_inventory(
        &self,
        operation: &RestoreOperation,
    ) -> Result<Vec<QuarantineFinding>, Failure> {
        self.inventory.verify_inventory(operation)
    }

    fn record_quarantine_findings(
        &self,
        operation: &RestoreOperation,
        findings: &[QuarantineFinding],
    ) -> Result<u64, Failure> {
        self.audit.record_quarantine_findings(operation, findings)
    }

    fn unresolved_quarantine_count(&self, operation: &RestoreOperation) -> Result<u64, Failure> {
        self.audit.unresolved_quarantine_count(operation)
    }

    fn reset_authority(
        &self,
        operation: &RestoreOperation,
    ) -> Result<AuthorityResetReceipt, Failure> {
        self.resetter.reset_authority(operation)
    }
}
