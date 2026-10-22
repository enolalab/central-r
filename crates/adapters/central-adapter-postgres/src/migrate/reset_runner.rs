//! `ResetRunner` — the version-zero-only reset (`reset_runner.go`).
//!
//! `delete_schema` takes the canonical locks on the same session, rechecks
//! that the observed records are exactly clean `v0` (upstream
//! `deleteSchemaVersionZeroOnly`), consumes the reset-confirmation proof,
//! then drops the schemas and roles verbatim and verifies the stock target
//! afterward.

use sqlx::PgConnection;

use super::baseline::BaselineInstaller;
use super::runner::{acquire_migration_locks, release_migration_locks, session_binding};
use super::verify_shape::{read_migration_records, schema_exists};
use super::{
    BrokerProofService, ResetConfirmation, ResetRequest, Result, TargetIdentity,
    VersionZeroEligibility,
};
use central_foundation::failure::Failure;

fn invalid(code: &'static str, msg: impl Into<String>) -> Failure {
    Failure::invalid(code, msg.into())
}
fn conflict(code: &'static str, msg: impl Into<String>) -> Failure {
    Failure::conflict(code, msg.into())
}

/// Reset driver bound to one non-rebinding `central_migration` session.
pub struct ResetRunner<'a> {
    conn: &'a mut PgConnection,
    proof_service: Option<std::sync::Arc<dyn super::DynProofService>>,
}

impl<'a> ResetRunner<'a> {
    /// `NewResetRunner`.
    pub fn new<P>(conn: &'a mut PgConnection, proof_service: Option<std::sync::Arc<P>>) -> Self
    where
        P: BrokerProofService + Send + Sync + 'static,
    {
        Self {
            conn,
            proof_service: proof_service.map(|p| p as std::sync::Arc<dyn super::DynProofService>),
        }
    }

    /// `DeleteSchema` — the locked, version-zero-only reset.
    ///
    /// # Errors
    /// Lock/eligibility/proof/drop/verify failures; partial drops are
    /// surfaced as internal repair-required failures.
    pub async fn delete_schema(&mut self, req: &ResetRequest) -> Result<()> {
        let target = &req.target;
        acquire_migration_locks(self.conn)
            .await
            .map_err(|err| wrap("reset: acquire locks", err))?;
        let binding = session_binding(self.conn)
            .await
            .map_err(|err| wrap("reset: session binding", err))?;

        let installer = BaselineInstaller::new();
        let installed = schema_exists(self.conn)
            .await
            .map_err(|err| wrap("reset: check installed", err))?;
        if installed {
            // Owned target — recheck eligibility, then consume the proof.
            let records = read_migration_records(self.conn)
                .await
                .map_err(|err| wrap("reset: version-zero recheck", err))?;
            self.delete_version_zero_only(&records, target)?;
            self.reset_confirmation_proof(binding.clone(), target, &req.confirmation)
                .await?;
        } else if installer.verify_stock_target(self.conn).await.is_err() {
            // Not stock and not installed — there is nothing reset may
            // legitimately drop.
            return Err(conflict(
                "reset_schema_missing",
                "reset: central schema is missing",
            ));
        }
        // Fresh/stock targets converge idempotently with no proof (fresh
        // reset requests carry no schema ownership).
        self.apply_schema_drop().await?;
        installer
            .verify_stock_target(self.conn)
            .await
            .map_err(|err| wrap("reset: verify stock target", err))
    }

    /// `deleteSchemaVersionZeroOnly` — refuse anything except the clean
    /// bare-`v0` chain.
    fn delete_version_zero_only(
        &self,
        records: &[super::verify_shape::MigrationRecord],
        target: &TargetIdentity,
    ) -> Result<()> {
        if records.len() == 1
            && records[0].version == 0
            && records[0].checksum == "baseline-zero"
            && !records[0].dirty
        {
            let _ = target;
            return Ok(());
        }
        if records.iter().any(|r| r.dirty) {
            return Err(invalid(
                "reset_requires_clean_version_zero",
                "reset: version-zero-only reset requires a clean version-zero migration chain",
            ));
        }
        Err(invalid(
            "reset_requires_version_zero_only",
            "reset: version-zero-only reset requires schema ownership records",
        ))
    }

    /// `resetConfirmationProof` — the reset confirmation must carry a
    /// complete session binding, and the broker consumes it once against
    /// the target.
    async fn reset_confirmation_proof(
        &self,
        binding: super::SessionBinding,
        target: &TargetIdentity,
        confirmation: &ResetConfirmation,
    ) -> Result<()> {
        // The mutation must run under a complete binding captured on the
        // locked session; the broker verifies the confirmation's own
        // binding fields on consumption.
        if !binding.is_complete() {
            return Err(invalid(
                "reset_session_binding_incomplete",
                "reset: complete session binding required before reset",
            ));
        }
        let Some(proof_service) = &self.proof_service else {
            return Err(invalid(
                "reset_proof_service_required",
                "reset: broker proof service required",
            ));
        };
        proof_service
            .consume_verified_reset_confirmation(target, confirmation.clone())
            .await
            .map_err(|err| wrap("reset: consume reset confirmation", err))
    }

    /// `applySchemaDrop` — drop the central schema and the three roles.
    async fn apply_schema_drop(&mut self) -> Result<()> {
        let statements = [
            "DROP SCHEMA IF EXISTS central CASCADE",
            "DROP SCHEMA IF EXISTS central_internal CASCADE",
            "DROP SCHEMA IF EXISTS central_audit CASCADE",
            "DROP SCHEMA IF EXISTS central_migrate CASCADE",
            "DROP SCHEMA IF EXISTS central_runtime CASCADE",
            "DROP SCHEMA IF EXISTS central_event CASCADE",
            "DROP SCHEMA IF EXISTS central_public CASCADE",
            "DROP ROLE IF EXISTS central_runtime",
            "DROP ROLE IF EXISTS central_outbox",
            "DROP ROLE IF EXISTS central_migration",
        ];
        let mut partial = false;
        for statement in statements {
            if let Err(err) = sqlx::query(statement).execute(&mut *self.conn).await {
                let classified = crate::error::classify_sqlx(&err);
                if classified.kind() == central_foundation::failure::FailureKind::Internal {
                    partial = true;
                }
                return Err(if partial {
                    Failure::internal(
                        "reset_partial_drop",
                        format!("reset: {statement}: partial reset requires operator repair"),
                    )
                } else {
                    wrap("reset: drop schema", classified)
                });
            }
        }
        let _ = release_migration_locks(&mut *self.conn).await;
        Ok(())
    }

    /// `VersionZeroEligibility` — facts for the reset gate.
    ///
    /// # Errors
    /// Inspection queries fail.
    pub async fn version_zero_eligibility(&mut self) -> Result<VersionZeroEligibility> {
        if !schema_exists(self.conn).await? {
            return Ok(VersionZeroEligibility {
                installed: false,
                has_schema_ownership: false,
                clean_version_zero_only: false,
            });
        }
        let records = read_migration_records(self.conn).await?;
        let clean = records.len() == 1
            && records[0].version == 0
            && records[0].checksum == "baseline-zero"
            && !records[0].dirty;
        Ok(VersionZeroEligibility {
            installed: true,
            has_schema_ownership: true,
            clean_version_zero_only: clean,
        })
    }
}

fn wrap(context: &'static str, err: Failure) -> Failure {
    Failure::new(
        err.kind(),
        err.code(),
        format!("{context}: {}", err.message()),
    )
}
