//! `Runner` — the single-session two-phase migration driver (`runner.go`).
//!
//! `prepare_up` takes the canonical advisory locks (in order), captures the
//! [`SessionBinding`] (backend PID + postmaster start + boot identity), and
//! verifies the stock target. `commit_up` re-binds on the *same* session,
//! consumes the broker's `VerifiedEmptyTarget` proof, then installs and
//! verifies the baseline shape. `resume` admits either an already-installed
//! target (repair through `install`) or a fresh install leg under a new
//! binding + proof.

use sqlx::{PgConnection, Row};

use super::baseline::BaselineInstaller;
use super::verify_shape::schema_exists;
use super::{
    BrokerProofService, CANONICAL_LOCK_ORDER, CommitUpRequest, ExternalRecordState,
    PrepareUpRequest, PrepareUpResult, ProvisioningPhase, ResetConfirmation, Result, ResumeRequest,
    ResumeResult, SessionBinding, TargetIdentity, UpRequest, UpResult, VerifiedEmptyTarget,
};
use crate::error::SqlxContext;
use central_foundation::failure::{Failure, FailureKind};

fn invalid(code: &'static str, msg: impl Into<String>) -> Failure {
    Failure::invalid(code, msg.into())
}

/// Acquire the canonical advisory locks in order on `conn`.
/// Session-level locks persist until released or the session ends.
pub(crate) async fn acquire_migration_locks(conn: &mut PgConnection) -> Result<()> {
    for (acquired, lock_name) in CANONICAL_LOCK_ORDER.into_iter().enumerate() {
        let result = sqlx::query("SELECT pg_advisory_lock(hashtext($1))")
            .bind(lock_name)
            .execute(&mut *conn)
            .await;
        if let Err(err) = result {
            for prior in CANONICAL_LOCK_ORDER[..acquired].iter().rev() {
                let _ = sqlx::query("SELECT pg_advisory_unlock(hashtext($1))")
                    .bind(prior)
                    .execute(&mut *conn)
                    .await;
            }
            return Err(crate::error::classify_sqlx(&err));
        }
    }
    Ok(())
}

/// Release the canonical advisory locks in reverse order.
pub(crate) async fn release_migration_locks(conn: &mut PgConnection) -> Result<()> {
    let mut failures = Vec::new();
    for lock_name in CANONICAL_LOCK_ORDER.iter().rev() {
        match sqlx::query("SELECT pg_advisory_unlock(hashtext($1))")
            .bind(lock_name)
            .fetch_one(&mut *conn)
            .await
        {
            Ok(row) if row.get::<bool, _>(0) => {}
            Ok(_) | Err(_) => failures.push(*lock_name),
        }
    }
    if !failures.is_empty() {
        return Err(invalid(
            "migration_lock_release",
            format!(
                "b08 migration: release advisory locks: {}",
                failures.join(",")
            ),
        ));
    }
    Ok(())
}

/// `runner.go: sessionBinding` — backend PID, postmaster start, and the
/// boot identity (cluster name, else `postmaster:<start>`).
pub(crate) async fn session_binding(conn: &mut PgConnection) -> Result<SessionBinding> {
    let pid: i32 = sqlx::query("SELECT pg_backend_pid()")
        .fetch_one(&mut *conn)
        .await
        .ctx("runner: get backend pid")
        .map(|row| row.get::<i32, _>(0))?;
    let backend_start: String = sqlx::query("SELECT pg_postmaster_start_time()::text")
        .fetch_one(&mut *conn)
        .await
        .ctx("runner: get backend start")
        .map(|row| row.get::<String, _>(0))?;
    let mut boot_id: String = sqlx::query(
        "SELECT COALESCE((SELECT setting FROM pg_catalog.pg_settings \
         WHERE name = 'cluster_name'), '') AS boot_id",
    )
    .fetch_one(&mut *conn)
    .await
    .ctx("runner: get boot id")
    .map(|row| row.get::<String, _>(0))?;
    if boot_id.is_empty() {
        boot_id = format!("postmaster:{backend_start}");
    }
    Ok(SessionBinding {
        backend_pid: pid,
        backend_start,
        boot_id,
        lock_identities: CANONICAL_LOCK_ORDER
            .iter()
            .map(|s| (*s).to_owned())
            .collect(),
    })
}

/// The two-phase migration runner bound to one non-rebinding session.
pub struct Runner<'a> {
    conn: &'a mut PgConnection,
    proof_service: Option<std::sync::Arc<dyn super::DynProofService>>,
}

impl<'a> Runner<'a> {
    /// `NewRunner` — the connection must be the same non-rebinding
    /// `central_migration` session that will hold the advisory locks.
    pub fn new<P>(conn: &'a mut PgConnection, proof_service: Option<std::sync::Arc<P>>) -> Self
    where
        P: BrokerProofService + Send + Sync + 'static,
    {
        Self {
            conn,
            proof_service: proof_service.map(|p| p as std::sync::Arc<dyn super::DynProofService>),
        }
    }

    /// `NewRunner` over the already-erased proof seam — the kernel's
    /// `MigrationSession` shares one `Arc<dyn DynProofService>` across
    /// the per-call runner constructions (upstream composes the same
    /// proof service into every runner leg).
    #[must_use]
    pub fn new_dyn(
        conn: &'a mut PgConnection,
        proof_service: Option<std::sync::Arc<dyn super::DynProofService>>,
    ) -> Self {
        Self {
            conn,
            proof_service,
        }
    }

    /// `Up` — prepare then commit.
    ///
    /// # Errors
    /// See [`Runner::prepare_up`] and [`Runner::commit_up`].
    pub async fn up(&mut self, req: &UpRequest) -> Result<UpResult> {
        let prepare = self
            .prepare_up(&PrepareUpRequest {
                operation_id: req.operation_id,
                target: req.target.clone(),
            })
            .await?;
        self.commit_up(&CommitUpRequest {
            operation_id: req.operation_id,
            target: req.target.clone(),
            session_binding: prepare.session_binding,
            proof: req.proof.clone(),
        })
        .await
    }

    /// `PrepareUp` — acquire the canonical locks, capture the session
    /// binding, verify the stock target.
    ///
    /// # Errors
    /// Lock acquisition, binding capture, or stock-target checks fail.
    pub async fn prepare_up(&mut self, req: &PrepareUpRequest) -> Result<PrepareUpResult> {
        acquire_migration_locks(self.conn)
            .await
            .map_err(|err| wrap("runner prepare: acquire locks", err))?;
        let binding = session_binding(self.conn)
            .await
            .map_err(|err| wrap("runner prepare: session binding", err))?;
        BaselineInstaller::new()
            .verify_stock_target(self.conn)
            .await
            .map_err(|err| wrap("runner prepare: verify stock target", err))?;
        Ok(PrepareUpResult {
            operation_id: req.operation_id,
            session_binding: binding,
        })
    }

    /// `CommitUp` — same-session binding check, proof binding + consumption,
    /// install, verify shape.
    ///
    /// # Errors
    /// Binding/proof mismatches, broker consumption failure, install or
    /// shape failures.
    pub async fn commit_up(&mut self, req: &CommitUpRequest) -> Result<UpResult> {
        let installer = BaselineInstaller::new();
        let current = session_binding(self.conn)
            .await
            .map_err(|err| wrap("runner commit: session binding", err))?;
        if !req.session_binding.is_complete() || current != req.session_binding {
            return Err(invalid(
                "runner_session_binding_mismatch",
                "runner commit: complete session binding mismatch",
            ));
        }
        if req.proof.operation_id != req.operation_id
            || req.proof.session_binding != req.session_binding
        {
            return Err(invalid(
                "runner_proof_unbound",
                "runner commit: proof is not bound to the mutation request",
            ));
        }
        let Some(proof_service) = &self.proof_service else {
            return Err(invalid(
                "runner_proof_service_required",
                "runner commit: broker proof service is required",
            ));
        };
        proof_service
            .consume_verified_empty_target(&req.target, req.proof.clone())
            .await
            .map_err(|err| wrap("runner commit: consume verified proof", err))?;
        installer
            .install(self.conn)
            .await
            .map_err(|err| wrap("runner commit: install baseline", err))?;
        installer
            .verify_shape(self.conn)
            .await
            .map_err(|err| wrap("runner commit: verify shape", err))?;
        Ok(UpResult {
            operation_id: req.operation_id,
            record_state: ExternalRecordState::Ready,
            session_binding: req.session_binding.clone(),
        })
    }

    /// `Resume` — either the repair leg (target already installed →
    /// `install` converges it) or the fresh-install leg (stock target →
    /// binding + proof → install).
    ///
    /// # Errors
    /// Instance/OID mismatches, missing proof on the fresh leg, or
    /// install/shape failures.
    pub async fn resume(&mut self, req: &ResumeRequest) -> Result<ResumeResult> {
        let installer = BaselineInstaller::new();
        acquire_migration_locks(self.conn)
            .await
            .map_err(|err| wrap("runner resume: acquire locks", err))?;
        let current = session_binding(self.conn)
            .await
            .map_err(|err| wrap("runner resume: session binding", err))?;
        if !current.same_instance(&req.expected_session_binding) {
            return Err(Failure::new(
                FailureKind::Conflict,
                "session_binding_mismatch",
                "the PostgreSQL instance has changed since the operation started; \
                 reset and re-provision",
            ));
        }
        let current_oid: String =
            sqlx::query("SELECT oid::text FROM pg_database WHERE datname = current_database()")
                .fetch_one(&mut *self.conn)
                .await
                .ctx("runner resume: get database OID")
                .map(|row| row.get::<String, _>(0))?;
        if current_oid != req.target.database_oid {
            return Err(Failure::new(
                FailureKind::Conflict,
                "target_database_oid_mismatch",
                "the database OID has changed; reset and re-provision",
            ));
        }
        let already_installed = schema_exists(self.conn)
            .await
            .map_err(|err| wrap("runner resume: check installed", err))?;
        if already_installed {
            installer
                .install(self.conn)
                .await
                .map_err(|err| wrap("runner resume: repair existing baseline", err))?;
            return Ok(ResumeResult {
                operation_id: req.operation_id,
                record_state: ExternalRecordState::Ready,
                final_phase: ProvisioningPhase::CandidateActive,
            });
        }
        installer
            .verify_stock_target(self.conn)
            .await
            .map_err(|err| wrap("runner resume: verify stock target", err))?;
        if !req.session_binding.is_complete() || current != req.session_binding {
            return Err(invalid(
                "runner_session_binding_mismatch",
                "runner resume: complete fresh session binding required before baseline install",
            ));
        }
        if req.proof.operation_id != req.operation_id
            || req.proof.session_binding != req.session_binding
        {
            return Err(invalid(
                "runner_proof_unbound",
                "runner resume: fresh broker proof required before baseline install",
            ));
        }
        let Some(proof_service) = &self.proof_service else {
            return Err(invalid(
                "runner_proof_service_required",
                "runner resume: fresh broker proof required before baseline install",
            ));
        };
        proof_service
            .consume_verified_empty_target(&req.target, req.proof.clone())
            .await
            .map_err(|err| wrap("runner resume: consume verified proof", err))?;
        installer
            .install(self.conn)
            .await
            .map_err(|err| wrap("runner resume: install baseline", err))?;
        installer
            .verify_shape(self.conn)
            .await
            .map_err(|err| wrap("runner resume: verify shape", err))?;
        Ok(ResumeResult {
            operation_id: req.operation_id,
            record_state: ExternalRecordState::Ready,
            final_phase: ProvisioningPhase::CandidateActive,
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

// `runner.go` line 244 — the stock-target rejection upstream exposes as a
// sentinel; the structured failure carries it.
/// Sentinel-style check for the `ErrSchemaExists` condition: true when the
/// failure is the stock-target rejection.
#[must_use]
pub fn is_schema_exists_failure(err: &Failure) -> bool {
    err.code() == "baseline_schema_exists"
}

// Keep the proof/confirmation types referenced by this module's public API
// linked for rustdoc.
#[allow(dead_code)]
type _DocLinks = (
    VerifiedEmptyTarget,
    ResetConfirmation,
    TargetIdentity,
    ProvisioningPhase,
);
