//! `recovery_audit.go` — [`RecoveryAuditStore`] mirrors the broker-owned
//! restore journal into the b25–b27 PostgreSQL audit relations. It is
//! deliberately bound to one dedicated `central_migration` connection:
//! callers retain the C04 target exclusion on that same session while
//! every projection is written.

use central_backup::backup::capacity::SUPPORTED_RECOVERY_RECORD_COUNT;
use central_backup::port::{PostgresAuthorityReset, RestoreQuarantineStore};
use central_backup::recovery::operation::{
    AuthorityResetReceipt, RecoveryBootstrapActivation, RecoveryBootstrapDraft,
    RecoveryBootstrapRegistration, RestoreCheckpoint, RestoreOperation, RestorePhase,
    new_authority_reset_receipt,
};
use central_backup::recovery::quarantine::QuarantineFinding;
use central_foundation::failure::{Failure, FailureKind};
use sqlx::{Connection as _, PgConnection, Postgres, Transaction};
use uuid::Uuid;

use crate::backup::{decode_sha256, hex_encode, is_zero_time, rfc3339_nano, truncate_micros};
use crate::error::SqlxContext as _;
use crate::migrate::SENTINEL_WORKSPACE_ID;
use crate::store_support::{BlockingConn, PG_DATA_CORRUPT};

fn audit_invalid(message: &'static str) -> Failure {
    Failure::invalid("recovery_audit", message)
}

fn audit_conflict(message: &'static str) -> Failure {
    Failure::new(FailureKind::Conflict, "recovery_audit_conflict", message)
}

fn corrupt(message: &'static str) -> Failure {
    Failure::internal(PG_DATA_CORRUPT, message)
}

/// `RecoveryAuditStore` — see module docs. Implements
/// [`RestoreQuarantineStore`] and [`PostgresAuthorityReset`]; the
/// `project_restore_operation` inherent method is the audit-projection
/// half the composed `RestoreEngine` delegates to.
pub struct RecoveryAuditStore {
    conn: BlockingConn,
}

impl RecoveryAuditStore {
    /// `NewRecoveryAuditStore` — refuses to build without a connection
    /// (the dedicated `central_migration` session is the caller's).
    ///
    /// # Errors
    /// `pg_adapter_error` when the bridge runtime cannot be built.
    pub fn new(conn: PgConnection) -> Result<Self, Failure> {
        Ok(Self {
            conn: BlockingConn::new(conn)?,
        })
    }

    /// `ProjectRestoreOperation` is idempotent for an exact protected
    /// revision. It rejects binding changes, skipped revisions,
    /// same-revision state changes and all backward writes except the
    /// one safe ambiguity: PostgreSQL may already contain the projected
    /// `ready` successor when the final broker CAS was lost.
    ///
    /// # Errors
    /// `invalid` for a malformed operation; `conflict` for a projection
    /// that is ahead, rebound, or transitioned illegally; classified
    /// SQLSTATE failures otherwise.
    pub fn project_restore_operation(&self, operation: &RestoreOperation) -> Result<(), Failure> {
        if operation.validate().is_err()
            || operation.last_checkpoint == RestoreCheckpoint::TicketConsumed
        {
            return Err(audit_invalid("recovery audit projection is invalid"));
        }
        let target_fingerprint = decode_sha256(&operation.target_fingerprint)
            .map_err(|_| audit_invalid("recovery audit target fingerprint is invalid"))?;
        let manifest_digest = decode_sha256(&operation.manifest_digest)
            .map_err(|_| audit_invalid("recovery audit manifest digest is invalid"))?;
        let receipt_hash = if operation.authority_reset_receipt_hash.is_empty() {
            None
        } else {
            Some(
                decode_sha256(&operation.authority_reset_receipt_hash)
                    .map_err(|_| audit_invalid("recovery audit authority receipt is invalid"))?,
            )
        };
        let operation = operation.clone();
        self.conn.run(|conn| {
            Box::pin(async move {
                let mut tx = conn.begin().await.ctx("recovery audit begin")?;
                let incoming = ProjectedRestoreRow::from_operation(
                    &operation,
                    target_fingerprint.to_vec(),
                    manifest_digest.to_vec(),
                    receipt_hash.map(|h| h.to_vec()),
                )?;
                let found =
                    read_projected_restore_for_update(&mut tx, operation.operation_id).await?;
                match found {
                    None => {
                        insert_projected_restore(&mut tx, operation.operation_id, &incoming)
                            .await?;
                    }
                    Some(existing) => {
                        if !existing.same_binding(&incoming) {
                            return Err(audit_conflict(
                                "recovery audit immutable binding mismatch",
                            ));
                        }
                        let mut write = true;
                        if existing.revision > incoming.revision {
                            // The one safe ambiguity: a committed `ready`
                            // successor one revision ahead with identical
                            // epochs and receipt replays cleanly — and is
                            // NEVER rolled backward by the predecessor's
                            // write.
                            if existing.revision != incoming.revision + 1
                                || existing.phase != RestorePhase::Ready
                                || existing.checkpoint != RestoreCheckpoint::AuthorityReset
                                || incoming.phase != RestorePhase::Verifying
                                || incoming.checkpoint != RestoreCheckpoint::AuthorityReset
                                || existing.security_epoch != incoming.security_epoch
                                || existing.authority_receipt_hash
                                    != incoming.authority_receipt_hash
                            {
                                return Err(audit_conflict(
                                    "recovery audit projection is ahead of protected authority",
                                ));
                            }
                            write = false;
                        } else if existing.revision == incoming.revision {
                            if !existing.same_state(&incoming) {
                                return Err(audit_conflict(
                                    "recovery audit same-revision state mismatch",
                                ));
                            }
                        } else if incoming.revision != existing.revision + 1
                            || !existing.valid_transition(&incoming)
                        {
                            return Err(audit_conflict(
                                "recovery audit revision transition is invalid",
                            ));
                        }
                        // Upstream updates unconditionally after the
                        // checks on the normal found paths: an exact
                        // same-revision replay still executes the CAS
                        // write (it rewrites identical values); only the
                        // ahead-of-authority arm above commits without one.
                        if write {
                            update_projected_restore(
                                &mut tx,
                                operation.operation_id,
                                existing.revision,
                                &incoming,
                            )
                            .await?;
                        }
                    }
                }
                tx.commit().await.ctx("recovery audit commit")
            })
        })
    }

    /// `RecordQuarantineFindings` inserts locator-free inventory
    /// mismatches in a stable Artifact order. During quarantine the
    /// supplied findings are the complete result of a fresh inventory
    /// pass: an open prior finding is resolved only when absent from
    /// that pass, proving the normal Artifact re-ingest or
    /// delete-finalization effect rather than accepting a direct
    /// flag-clear call. Re-entry never rewrites the original finding or
    /// reopens a resolved row.
    fn record_quarantine_findings_inner(
        &self,
        operation: &RestoreOperation,
        findings: &[QuarantineFinding],
    ) -> Result<u64, Failure> {
        if operation.validate().is_err()
            || !operation.admits_inventory_verification()
            || findings.len() as u64 > SUPPORTED_RECOVERY_RECORD_COUNT
        {
            return Err(audit_invalid("recovery quarantine projection is invalid"));
        }
        let mut ordered = findings.to_vec();
        ordered.sort_by_key(|f| f.artifact_id);
        for (index, finding) in ordered.iter().enumerate() {
            if finding.validate_for(operation).is_err()
                || (index > 0 && ordered[index - 1].artifact_id == finding.artifact_id)
            {
                return Err(audit_invalid("recovery quarantine finding is invalid"));
            }
        }
        let target_fingerprint = decode_sha256(&operation.target_fingerprint)
            .map_err(|_| audit_invalid("recovery quarantine target fingerprint is invalid"))?;
        let manifest_digest = decode_sha256(&operation.manifest_digest)
            .map_err(|_| audit_invalid("recovery quarantine manifest digest is invalid"))?;
        let operation = operation.clone();
        self.conn.run(|conn| {
            Box::pin(async move {
                let mut tx = conn.begin().await.ctx("recovery quarantine begin")?;
                let projected =
                    read_projected_restore_for_update(&mut tx, operation.operation_id).await?;
                let Some(projected) = projected else {
                    return Err(audit_conflict(
                        "recovery quarantine lacks exact database-replaced projection",
                    ));
                };
                if !projected.matches_operation(
                    &operation,
                    &target_fingerprint,
                    &manifest_digest,
                )? || projected.phase != operation.phase
                    || projected.checkpoint != operation.last_checkpoint
                {
                    return Err(audit_conflict(
                        "recovery quarantine lacks exact database-replaced projection",
                    ));
                }
                for finding in &ordered {
                    sqlx::query!(
                        "INSERT INTO central.recovery_quarantines (
                            quarantine_id, operation_id, artifact_id, reason, observation_source,
                            expected_checksum, observed_checksum, expected_size, observed_size,
                            state, resolution, created_at, resolved_at
                        ) VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7, $8, $9,
                            'open', NULL, $10, NULL)
                        ON CONFLICT (operation_id, artifact_id) DO NOTHING",
                        finding.quarantine_id,
                        finding.operation_id,
                        finding.artifact_id,
                        finding.reason.as_str(),
                        finding.observation_source.as_str(),
                        finding.expected_checksum.map(|c| c.to_vec()),
                        finding.observed_checksum.map(|c| c.to_vec()),
                        finding.expected_size,
                        finding.observed_size,
                        truncate_micros(finding.created_at),
                    )
                    .execute(&mut *tx)
                    .await
                    .ctx("recovery quarantine insert finding")?;
                    verify_stored_quarantine(&mut tx, finding).await?;
                }
                if operation.phase == RestorePhase::Quarantined {
                    let current: Vec<uuid::Uuid> = ordered.iter().map(|f| f.artifact_id).collect();
                    sqlx::query!(
                        "UPDATE central.recovery_quarantines SET
                            state='resolved',
                            resolution=CASE WHEN reason='unexpected_artifact'
                                THEN 'delete_finalized' ELSE 'reingested' END,
                            resolved_at=GREATEST(clock_timestamp(), created_at)
                        WHERE operation_id=$1::uuid AND state='open'
                          AND NOT (artifact_id = ANY($2::uuid[]))",
                        operation.operation_id,
                        &current,
                    )
                    .execute(&mut *tx)
                    .await
                    .ctx("recovery quarantine reconcile inventory")?;
                }
                let unresolved = sqlx::query_scalar!(
                    "SELECT count(*)::bigint AS \"count!\" FROM central.recovery_quarantines
                        WHERE operation_id=$1::uuid AND state='open'",
                    operation.operation_id,
                )
                .fetch_one(&mut *tx)
                .await
                .ctx("recovery quarantine count")?;
                if unresolved < 0 {
                    return Err(corrupt("recovery quarantine count is invalid"));
                }
                tx.commit().await.ctx("recovery quarantine commit")?;
                u64::try_from(unresolved).map_err(|_| corrupt("recovery quarantine count"))
            })
        })
    }

    /// `UnresolvedQuarantineCount` — exact `quarantined`/
    /// `inventory_verified` projection required.
    fn unresolved_quarantine_count_inner(
        &self,
        operation: &RestoreOperation,
    ) -> Result<u64, Failure> {
        if operation.validate().is_err()
            || operation.phase != RestorePhase::Quarantined
            || operation.last_checkpoint != RestoreCheckpoint::InventoryVerified
        {
            return Err(audit_invalid(
                "recovery quarantine count request is invalid",
            ));
        }
        let target_fingerprint = decode_sha256(&operation.target_fingerprint)
            .map_err(|_| audit_invalid("recovery quarantine target fingerprint is invalid"))?;
        let manifest_digest = decode_sha256(&operation.manifest_digest)
            .map_err(|_| audit_invalid("recovery quarantine manifest digest is invalid"))?;
        let operation = operation.clone();
        self.conn.run(|conn| {
            Box::pin(async move {
                let mut tx = conn.begin().await.ctx("recovery quarantine count begin")?;
                let projected =
                    read_projected_restore_for_update(&mut tx, operation.operation_id).await?;
                let Some(projected) = projected else {
                    return Err(audit_conflict(
                        "recovery quarantine count lacks exact protected projection",
                    ));
                };
                if !projected.matches_operation(
                    &operation,
                    &target_fingerprint,
                    &manifest_digest,
                )? || projected.phase != operation.phase
                    || projected.checkpoint != operation.last_checkpoint
                {
                    return Err(audit_conflict(
                        "recovery quarantine count lacks exact protected projection",
                    ));
                }
                let unresolved = sqlx::query_scalar!(
                    "SELECT count(*)::bigint AS \"count!\" FROM central.recovery_quarantines
                        WHERE operation_id=$1::uuid AND state='open'",
                    operation.operation_id,
                )
                .fetch_one(&mut *tx)
                .await
                .ctx("recovery quarantine count")?;
                if unresolved < 0 {
                    return Err(corrupt("recovery quarantine count is invalid"));
                }
                tx.commit().await.ctx("recovery quarantine commit")?;
                u64::try_from(unresolved).map_err(|_| corrupt("recovery quarantine count"))
            })
        })
    }

    /// `ResetDatabaseAuthority` executes C05's in-database portion
    /// atomically. The restored values are deliberately not trusted as
    /// predecessors: the protected operation supplies the monotonic
    /// target epochs that replace them.
    fn reset_database_authority_inner(
        &self,
        operation: &RestoreOperation,
        draft: &RecoveryBootstrapDraft,
    ) -> Result<RecoveryBootstrapRegistration, Failure> {
        if operation.validate().is_err()
            || operation.phase != RestorePhase::Verifying
            || operation.last_checkpoint != RestoreCheckpoint::InventoryVerified
            || operation.security_epoch == u64::MAX
            || operation.security_epoch > i64::MAX as u64 - 1
            || operation.restore_epoch > i64::MAX as u64
            || draft.validate_for(operation).is_err()
        {
            return Err(audit_invalid(
                "recovery database authority reset is invalid",
            ));
        }
        let broker_hash = decode_sha256(&draft.broker_receipt_hash)
            .map_err(|_| audit_invalid("recovery broker receipt hash is invalid"))?;
        let target_fingerprint = decode_sha256(&operation.target_fingerprint)
            .map_err(|_| audit_invalid("recovery audit target fingerprint is invalid"))?;
        let manifest_digest = decode_sha256(&operation.manifest_digest)
            .map_err(|_| audit_invalid("recovery audit manifest digest is invalid"))?;
        let operation = operation.clone();
        let draft = draft.clone();
        self.conn.run(|conn| {
            Box::pin(async move {
                let mut tx = conn
                    .begin()
                    .await
                    .ctx("recovery database authority reset begin")?;
                let projected =
                    read_projected_restore_for_update(&mut tx, operation.operation_id).await?;
                let Some(projected) = projected else {
                    return Err(audit_conflict(
                        "recovery database authority reset lacks exact inventory projection",
                    ));
                };
                if !projected.matches_operation(
                    &operation,
                    &target_fingerprint,
                    &manifest_digest,
                )? || projected.phase != RestorePhase::Verifying
                    || projected.checkpoint != RestoreCheckpoint::InventoryVerified
                {
                    return Err(audit_conflict(
                        "recovery database authority reset lacks exact inventory projection",
                    ));
                }
                if let Some(registration) =
                    read_recovery_bootstrap_registration(&mut tx, &operation, &draft).await?
                {
                    tx.commit()
                        .await
                        .ctx("recovery database authority reset commit")?;
                    return Ok(registration);
                }

                // Lock every target epoch row before changing any
                // restored authority — deterministic lock order.
                let marker_count = sqlx::query_scalar!(
                    "SELECT count(*)::bigint AS \"count!\" FROM (
                        SELECT id FROM central.epoch_markers ORDER BY id FOR UPDATE
                    ) AS markers"
                )
                .fetch_one(&mut *tx)
                .await
                .ctx("recovery database authority reset lock markers")?;
                let workspace_count = sqlx::query_scalar!(
                    "SELECT count(*)::bigint AS \"count!\" FROM (
                        SELECT id FROM central.workspaces ORDER BY id FOR UPDATE
                    ) AS ws"
                )
                .fetch_one(&mut *tx)
                .await
                .ctx("recovery database authority reset lock workspaces")?;
                if marker_count == 0 || workspace_count == 0 {
                    return Err(audit_conflict(
                        "recovery database authority reset target census is empty",
                    ));
                }
                let sentinel = Uuid::parse_str(SENTINEL_WORKSPACE_ID)
                    .map_err(|_| corrupt("the sentinel workspace id is invalid"))?;
                let generations = sqlx::query_scalar!(
                    "SELECT generation AS \"generation!\" FROM central.bootstrap_generations
                        WHERE workspace_id=$1::uuid ORDER BY generation FOR UPDATE",
                    sentinel,
                )
                .fetch_all(&mut *tx)
                .await
                .ctx("recovery database authority reset lock bootstrap generations")?;
                let mut maximum_generation: i64 = -1;
                for generation in generations {
                    if generation < 0 {
                        return Err(corrupt(
                            "recovery database authority reset bootstrap generation is invalid",
                        ));
                    }
                    maximum_generation = generation;
                }
                if maximum_generation < 0 || maximum_generation == i64::MAX {
                    return Err(audit_conflict(
                        "recovery database authority reset cannot allocate bootstrap generation",
                    ));
                }
                let next_generation = maximum_generation + 1;

                let completed_at = sqlx::query_scalar!("SELECT clock_timestamp() AS \"now!\"")
                    .fetch_one(&mut *tx)
                    .await
                    .ctx("recovery database authority reset clock")?;
                let completed_at = truncate_micros(completed_at);

                let restore_epoch = i64::try_from(operation.restore_epoch).map_err(|_| {
                    audit_invalid("recovery audit counter exceeds PostgreSQL range")
                })?;
                let new_security_epoch =
                    i64::try_from(operation.security_epoch + 1).map_err(|_| {
                        audit_invalid("recovery audit counter exceeds PostgreSQL range")
                    })?;

                sqlx::query!(
                    "UPDATE central.epoch_markers
                        SET restore_epoch=$1, security_epoch=$2, updated_at=$3",
                    restore_epoch,
                    new_security_epoch,
                    completed_at,
                )
                .execute(&mut *tx)
                .await
                .ctx("recovery database authority reset epoch markers")?;
                sqlx::query!(
                    "UPDATE central.workspaces
                        SET restore_epoch=$1, security_epoch=$2, updated_at=$3",
                    restore_epoch,
                    new_security_epoch,
                    completed_at,
                )
                .execute(&mut *tx)
                .await
                .ctx("recovery database authority reset workspaces")?;
                sqlx::query!(
                    "UPDATE central.sessions
                        SET lifecycle_state='revoked',
                            revoked_at=COALESCE(revoked_at,$1),
                            delivery_outcome='revoked'
                        WHERE lifecycle_state IN ('pending_bootstrap','delivery_pending','active')",
                    completed_at,
                )
                .execute(&mut *tx)
                .await
                .ctx("recovery database authority reset sessions")?;
                sqlx::query!(
                    "UPDATE central.bootstrap_generations
                        SET state='consumed',
                            consumed_at=COALESCE(consumed_at,$1),
                            presentation_deadline=NULL
                        WHERE state='active'",
                    completed_at,
                )
                .execute(&mut *tx)
                .await
                .ctx("recovery database authority reset bootstrap generations")?;
                sqlx::query!(
                    "UPDATE central.execution_ownership
                        SET lease_expiry=CASE WHEN lease_expiry IS NULL THEN NULL
                                ELSE $1::timestamptz END,
                            lease_expires_at=$1::timestamptz,
                            heartbeat_at=$1::timestamptz,
                            fencing_generation=fencing_generation+1,
                            updated_at=$1::timestamptz",
                    completed_at,
                )
                .execute(&mut *tx)
                .await
                .ctx("recovery database authority reset execution ownership")?;
                sqlx::query!(
                    "UPDATE central.outbox
                        SET lease_expiry=CASE WHEN lease_expiry IS NULL THEN NULL
                                ELSE $1::timestamptz END,
                            claim_expires_at=$1::timestamptz,
                            updated_at=$1::timestamptz
                        WHERE delivery_state='claimed'",
                    completed_at,
                )
                .execute(&mut *tx)
                .await
                .ctx("recovery database authority reset outbox claims")?;
                sqlx::query!(
                    "UPDATE central.outbox_workspace_work
                        SET claim_expires_at=$1, version=version+1
                        WHERE claim_expires_at IS NOT NULL",
                    completed_at,
                )
                .execute(&mut *tx)
                .await
                .ctx("recovery database authority reset workspace outbox claims")?;
                sqlx::query!(
                    "UPDATE central.recovery_coordinators
                        SET state='expired',
                            lease_expires_at=$1,
                            fencing_generation=fencing_generation+1,
                            version=version+1,
                            updated_at=$1
                        WHERE state='claimed'",
                    completed_at,
                )
                .execute(&mut *tx)
                .await
                .ctx("recovery database authority reset recovery coordinators")?;
                sqlx::query!(
                    "UPDATE central.recovery_epoch_workspaces
                        SET claim_expires_at=$1, updated_at=$1
                        WHERE delivery_state='claimed'",
                    completed_at,
                )
                .execute(&mut *tx)
                .await
                .ctx("recovery database authority reset recovery workspace claims")?;
                sqlx::query!(
                    "UPDATE central.artifact_reconciliation_claims
                        SET lease_expires_at=$1, updated_at=$1
                        WHERE lease_expires_at>$1",
                    completed_at,
                )
                .execute(&mut *tx)
                .await
                .ctx("recovery database authority reset artifact reconciliation claims")?;
                sqlx::query!(
                    "UPDATE central.approvals
                        SET state='suspended',
                            suspend_reason='restore_review_required',
                            updated_at=$1
                        WHERE state='active'",
                    completed_at,
                )
                .execute(&mut *tx)
                .await
                .ctx("recovery database authority reset approvals")?;
                sqlx::query!(
                    "UPDATE central.provider_bindings
                        SET revoked_at=COALESCE(revoked_at,$1)
                        WHERE revoked_at IS NULL",
                    completed_at,
                )
                .execute(&mut *tx)
                .await
                .ctx("recovery database authority reset provider bindings")?;
                sqlx::query!(
                    "UPDATE central.b09_authorization_decisions
                        SET revoked_at=COALESCE(revoked_at,$1)
                        WHERE revoked_at IS NULL",
                    completed_at,
                )
                .execute(&mut *tx)
                .await
                .ctx("recovery database authority reset provider decisions")?;
                sqlx::query!(
                    "UPDATE central.provider_fence_consumptions
                        SET delivery_state='reconciliation',
                            handoff_failure_code='restore_authority_reset'
                        WHERE delivery_state='delivery_pending'"
                )
                .execute(&mut *tx)
                .await
                .ctx("recovery database authority reset provider handoffs")?;

                let payload = serde_json::to_vec(&DatabaseReceiptPayload {
                    operation_id: operation.operation_id.to_string(),
                    draft_id: draft.draft_id.to_string(),
                    candidate_id: draft.candidate_id.to_string(),
                    generation: next_generation,
                    previous_restore_epoch: operation.restore_epoch - 1,
                    new_restore_epoch: operation.restore_epoch,
                    previous_security_epoch: operation.security_epoch,
                    new_security_epoch: operation.security_epoch + 1,
                    broker_receipt_hash: &draft.broker_receipt_hash,
                    registered_at: rfc3339_nano(completed_at),
                    components: DATABASE_RESET_COMPONENTS,
                })
                .map_err(|_| {
                    audit_invalid("recovery database authority reset receipt encoding failed")
                })?;
                let database_receipt = sha2::Sha256::digest(&payload);
                let registration = RecoveryBootstrapRegistration {
                    operation_id: operation.operation_id,
                    draft_id: draft.draft_id,
                    candidate_id: draft.candidate_id,
                    generation: u64::try_from(next_generation)
                        .map_err(|_| corrupt("recovery bootstrap generation underflow"))?,
                    verifier_hash: draft.verifier_hash,
                    candidate_digest: draft.candidate_digest,
                    broker_receipt_hash: draft.broker_receipt_hash.clone(),
                    database_receipt_hash: format!("sha256:{}", hex_encode(&database_receipt)),
                    registered_at: completed_at,
                };
                if registration.validate_for(&operation, &draft).is_err() {
                    return Err(audit_invalid(
                        "recovery database authority reset produced invalid bootstrap registration",
                    ));
                }
                sqlx::query!(
                    "INSERT INTO central.bootstrap_generations
                        (id,workspace_id,generation,verifier_hash,state,principal_identity,
                         candidate_id,candidate_digest,registered_generation,created_at)
                        VALUES ($1::uuid,$2::uuid,$3,$4,'active','recovery-bootstrap',
                            $5::uuid,$6,$3,$7)",
                    draft.draft_id,
                    sentinel,
                    next_generation,
                    &draft.verifier_hash[..],
                    draft.candidate_id,
                    &draft.candidate_digest[..],
                    completed_at,
                )
                .execute(&mut *tx)
                .await
                .ctx("recovery database authority reset insert fresh bootstrap")?;
                sqlx::query!(
                    "INSERT INTO central.recovery_bootstrap_registrations
                        (operation_id,draft_id,candidate_id,generation,verifier_hash,
                         candidate_digest,broker_receipt_hash,database_receipt_hash,registered_at)
                        VALUES ($1::uuid,$2::uuid,$3::uuid,$4,$5,$6,$7,$8,$9)",
                    operation.operation_id,
                    draft.draft_id,
                    draft.candidate_id,
                    next_generation,
                    &draft.verifier_hash[..],
                    &draft.candidate_digest[..],
                    &broker_hash[..],
                    &database_receipt[..],
                    completed_at,
                )
                .execute(&mut *tx)
                .await
                .ctx("recovery database authority reset persist bootstrap registration")?;
                tx.commit()
                    .await
                    .ctx("recovery database authority reset commit")?;
                Ok(registration)
            })
        })
    }

    /// `FinalizeDatabaseAuthorityReset` appends the aggregate receipt
    /// only after the protected broker has activated the exact
    /// generation registered by the reset transaction. A crash before
    /// this point leaves the external state verifying.
    fn finalize_database_authority_reset_inner(
        &self,
        operation: &RestoreOperation,
        registration: &RecoveryBootstrapRegistration,
        activation: &RecoveryBootstrapActivation,
    ) -> Result<AuthorityResetReceipt, Failure> {
        if operation.validate().is_err()
            || activation.validate_for(operation, registration).is_err()
        {
            return Err(audit_invalid(
                "recovery authority reset finalization is invalid",
            ));
        }
        let target_fingerprint = decode_sha256(&operation.target_fingerprint)
            .map_err(|_| audit_invalid("recovery audit target fingerprint is invalid"))?;
        let manifest_digest = decode_sha256(&operation.manifest_digest)
            .map_err(|_| audit_invalid("recovery audit manifest digest is invalid"))?;
        let broker_hash = decode_sha256(&registration.broker_receipt_hash)
            .map_err(|_| audit_invalid("recovery broker receipt hash is invalid"))?;
        let operation = operation.clone();
        let registration = registration.clone();
        let activation = activation.clone();
        self.conn.run(|conn| {
            Box::pin(async move {
                let mut tx = conn
                    .begin()
                    .await
                    .ctx("recovery authority reset finalization begin")?;
                let projected =
                    read_projected_restore_for_update(&mut tx, operation.operation_id).await?;
                let Some(projected) = projected else {
                    return Err(audit_conflict(
                        "recovery authority reset finalization lacks exact inventory projection",
                    ));
                };
                if !projected.matches_operation(
                    &operation,
                    &target_fingerprint,
                    &manifest_digest,
                )? || projected.phase != RestorePhase::Verifying
                    || projected.checkpoint != RestoreCheckpoint::InventoryVerified
                {
                    return Err(audit_conflict(
                        "recovery authority reset finalization lacks exact inventory projection",
                    ));
                }
                let draft = RecoveryBootstrapDraft {
                    operation_id: registration.operation_id,
                    draft_id: registration.draft_id,
                    candidate_id: registration.candidate_id,
                    verifier_hash: registration.verifier_hash,
                    candidate_digest: registration.candidate_digest,
                    broker_receipt_hash: registration.broker_receipt_hash.clone(),
                    created_at: operation.updated_at,
                };
                let stored_registration =
                    read_recovery_bootstrap_registration(&mut tx, &operation, &draft).await?;
                if stored_registration.as_ref() != Some(&registration) {
                    return Err(audit_conflict(
                        "recovery authority reset finalization registration mismatch",
                    ));
                }
                // The completion instant is decided exactly once, by the
                // call that actually inserts the receipt, and is never
                // recomputed afterwards: it is the eleventh component of
                // the hashed payload below, so a fresh clock read on a
                // replay would move both `completed_at` and
                // `aggregate_receipt_hash` and make the found-branch's
                // equality unsatisfiable forever. Lock acquisition order
                // stays projection → registration → receipt.
                let existing =
                    read_authority_reset_receipt(&mut tx, operation.operation_id).await?;
                let completed_at = match existing.as_ref() {
                    Some(existing) => existing.completed_at,
                    None => truncate_micros(
                        sqlx::query_scalar!(
                            "SELECT GREATEST(clock_timestamp(), $1::timestamptz) AS \"now!\"",
                            activation.activated_at,
                        )
                        .fetch_one(&mut *tx)
                        .await
                        .ctx("recovery authority reset finalization clock")?,
                    ),
                };
                let receipt = new_authority_reset_receipt(
                    &operation,
                    &registration,
                    &activation,
                    completed_at,
                )
                .map_err(|_| {
                    audit_invalid("recovery authority reset finalization produced invalid evidence")
                })?;
                if let Some(mut existing) = existing {
                    // The receipts table persists seven of eleven fields;
                    // the cross-boundary fields replay from the verified
                    // registration/activation before the equality check.
                    existing.database_receipt_hash = registration.database_receipt_hash.clone();
                    existing.bootstrap_candidate_id = registration.candidate_id;
                    existing.bootstrap_generation = registration.generation;
                    existing.bootstrap_activation_receipt_hash =
                        activation.activation_receipt_hash.clone();
                    if existing != receipt {
                        return Err(audit_conflict(
                            "recovery authority reset finalization replay mismatch",
                        ));
                    }
                    tx.commit()
                        .await
                        .ctx("recovery authority reset finalization commit")?;
                    return Ok(existing);
                }
                insert_authority_reset_receipt(&mut tx, &receipt, &broker_hash).await?;
                tx.commit()
                    .await
                    .ctx("recovery authority reset finalization commit")?;
                Ok(receipt)
            })
        })
    }
}

impl RestoreQuarantineStore for RecoveryAuditStore {
    fn record_quarantine_findings(
        &self,
        operation: &RestoreOperation,
        findings: &[QuarantineFinding],
    ) -> Result<u64, Failure> {
        self.record_quarantine_findings_inner(operation, findings)
    }

    fn unresolved_quarantine_count(&self, operation: &RestoreOperation) -> Result<u64, Failure> {
        self.unresolved_quarantine_count_inner(operation)
    }
}

impl PostgresAuthorityReset for RecoveryAuditStore {
    fn reset_database_authority(
        &self,
        operation: &RestoreOperation,
        draft: &RecoveryBootstrapDraft,
    ) -> Result<RecoveryBootstrapRegistration, Failure> {
        self.reset_database_authority_inner(operation, draft)
    }

    fn finalize_database_authority_reset(
        &self,
        operation: &RestoreOperation,
        registration: &RecoveryBootstrapRegistration,
        activation: &RecoveryBootstrapActivation,
    ) -> Result<AuthorityResetReceipt, Failure> {
        self.finalize_database_authority_reset_inner(operation, registration, activation)
    }
}

// ---------------------------------------------------------------------------
// `DatabaseReceiptPayload` — the 12-field canonical payload the reset
// transaction hashes into `database_receipt_hash` (upstream's anonymous
// struct; JSON field order is part of the hashed wire shape).
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
struct DatabaseReceiptPayload<'a> {
    operation_id: String,
    draft_id: String,
    candidate_id: String,
    generation: i64,
    previous_restore_epoch: u64,
    new_restore_epoch: u64,
    previous_security_epoch: u64,
    new_security_epoch: u64,
    broker_receipt_hash: &'a str,
    registered_at: String,
    components: [&'a str; 16],
}

/// `components` — the exact upstream list, in order.
const DATABASE_RESET_COMPONENTS: [&str; 16] = [
    "epoch_markers",
    "workspaces",
    "sessions",
    "bootstrap_generations",
    "execution_ownership",
    "outbox",
    "outbox_workspace_work",
    "recovery_coordinators",
    "recovery_epoch_workspaces",
    "artifact_reconciliation_claims",
    "approvals",
    "provider_bindings",
    "provider_authorizations",
    "provider_fence_consumptions",
    "broker_tls",
    "fresh_bootstrap_registration",
];

// ---------------------------------------------------------------------------
// `projectedRestoreRow` — one `recovery_operations` projection.
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct ProjectedRestoreRow {
    backup_id: uuid::Uuid,
    target_fingerprint: Vec<u8>,
    manifest_digest: Vec<u8>,
    restore_epoch: i64,
    security_epoch: i64,
    revision: i64,
    phase: RestorePhase,
    checkpoint: RestoreCheckpoint,
    authority_receipt_hash: Option<Vec<u8>>,
    started_at: time::OffsetDateTime,
    updated_at: time::OffsetDateTime,
    ready_at: Option<time::OffsetDateTime>,
}

impl ProjectedRestoreRow {
    fn from_operation(
        operation: &RestoreOperation,
        target_fingerprint: Vec<u8>,
        manifest_digest: Vec<u8>,
        receipt_hash: Option<Vec<u8>>,
    ) -> Result<Self, Failure> {
        Ok(Self {
            backup_id: operation.backup_id,
            target_fingerprint,
            manifest_digest,
            restore_epoch: i64::try_from(operation.restore_epoch)
                .map_err(|_| audit_invalid("recovery audit counter exceeds PostgreSQL range"))?,
            security_epoch: i64::try_from(operation.security_epoch)
                .map_err(|_| audit_invalid("recovery audit counter exceeds PostgreSQL range"))?,
            revision: i64::try_from(operation.revision)
                .map_err(|_| audit_invalid("recovery audit counter exceeds PostgreSQL range"))?,
            phase: operation.phase,
            checkpoint: operation.last_checkpoint,
            authority_receipt_hash: receipt_hash,
            started_at: truncate_micros(operation.started_at),
            updated_at: truncate_micros(operation.updated_at),
            ready_at: (!is_zero_time(operation.ready_at))
                .then(|| truncate_micros(operation.ready_at)),
        })
    }

    /// `projectedRowMatchesOperation` — the exact projection equality the
    /// quarantine/reset/finalize paths require (binding + epochs +
    /// revision + microsecond timestamps).
    fn matches_operation(
        &self,
        operation: &RestoreOperation,
        target_fingerprint: &[u8; 32],
        manifest_digest: &[u8; 32],
    ) -> Result<bool, Failure> {
        if operation.restore_epoch > i64::MAX as u64
            || operation.security_epoch > i64::MAX as u64
            || operation.revision > i64::MAX as u64
        {
            return Ok(false);
        }
        Ok(self.backup_id == operation.backup_id
            && self.target_fingerprint == target_fingerprint
            && self.manifest_digest == manifest_digest
            && self.restore_epoch == operation.restore_epoch as i64
            && self.security_epoch == operation.security_epoch as i64
            && self.revision == operation.revision as i64
            && self.started_at == truncate_micros(operation.started_at)
            && self.updated_at == truncate_micros(operation.updated_at))
    }

    /// `sameProjectionBinding` — the immutable identity fields.
    fn same_binding(&self, other: &Self) -> bool {
        self.backup_id == other.backup_id
            && self.target_fingerprint == other.target_fingerprint
            && self.manifest_digest == other.manifest_digest
            && self.restore_epoch == other.restore_epoch
            && self.started_at == other.started_at
    }

    /// `sameProjectionState` — the mutable projection fields, with the
    /// `ready` phase's `ready_at == updated_at` monotonic rule.
    fn same_state(&self, other: &Self) -> bool {
        if self.phase != other.phase
            || self.checkpoint != other.checkpoint
            || self.security_epoch != other.security_epoch
            || self.authority_receipt_hash != other.authority_receipt_hash
            || self.ready_at.is_some() != other.ready_at.is_some()
        {
            return false;
        }
        if self.phase == RestorePhase::Ready {
            return other.updated_at >= self.updated_at && other.ready_at == Some(other.updated_at);
        }
        self.updated_at == other.updated_at && self.ready_at.is_none()
    }

    /// `projectedRowIsResumable` — mirrors
    /// `RestoreOperation::is_resumable` (phase-only, like the domain).
    fn is_resumable(&self) -> bool {
        matches!(
            self.phase,
            RestorePhase::Applying | RestorePhase::Verifying | RestorePhase::Quarantined
        )
    }

    /// `validProjectedTransition` — the closed transition table, with
    /// the abandonment arm (the complement of resumability: only the
    /// phase changes, exactly like
    /// `RestoreOperation::validate_transition_to`'s abandon arm).
    fn valid_transition(&self, next: &Self) -> bool {
        if self.restore_epoch != next.restore_epoch {
            return false;
        }
        if self.is_resumable()
            && next.phase == RestorePhase::Abandoned
            && next.checkpoint == self.checkpoint
            && next.security_epoch == self.security_epoch
            && self.authority_receipt_hash == next.authority_receipt_hash
        {
            return true;
        }
        match (self.phase, self.checkpoint) {
            (RestorePhase::Applying, RestoreCheckpoint::DatabaseReplaced) => {
                next.phase == RestorePhase::Verifying
                    && next.checkpoint == RestoreCheckpoint::DatabaseReplaced
                    && next.security_epoch == self.security_epoch
            }
            (RestorePhase::Verifying, RestoreCheckpoint::DatabaseReplaced) => {
                next.phase == RestorePhase::Verifying
                    && next.checkpoint == RestoreCheckpoint::InventoryVerified
                    && next.security_epoch == self.security_epoch
            }
            (RestorePhase::Verifying, RestoreCheckpoint::InventoryVerified) => {
                (next.phase == RestorePhase::Quarantined
                    && next.checkpoint == RestoreCheckpoint::InventoryVerified
                    && next.security_epoch == self.security_epoch)
                    || (self.security_epoch < i64::MAX
                        && next.phase == RestorePhase::Verifying
                        && next.checkpoint == RestoreCheckpoint::AuthorityReset
                        && next.security_epoch == self.security_epoch + 1)
            }
            (RestorePhase::Quarantined, RestoreCheckpoint::InventoryVerified) => {
                next.phase == RestorePhase::Verifying
                    && next.checkpoint == RestoreCheckpoint::InventoryVerified
                    && next.security_epoch == self.security_epoch
            }
            (RestorePhase::Verifying, RestoreCheckpoint::AuthorityReset) => {
                next.phase == RestorePhase::Ready
                    && next.checkpoint == RestoreCheckpoint::AuthorityReset
                    && next.security_epoch == self.security_epoch
            }
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Projection I/O
// ---------------------------------------------------------------------------

struct RawProjectedRow {
    backup_id: uuid::Uuid,
    target_fingerprint: Vec<u8>,
    manifest_digest: Vec<u8>,
    restore_epoch: i64,
    security_epoch: i64,
    revision: i64,
    phase: String,
    last_checkpoint: String,
    authority_reset_receipt_hash: Option<Vec<u8>>,
    started_at: time::OffsetDateTime,
    updated_at: time::OffsetDateTime,
    ready_at: Option<time::OffsetDateTime>,
}

fn parse_phase(value: &str) -> Result<RestorePhase, Failure> {
    match value {
        "applying" => Ok(RestorePhase::Applying),
        "verifying" => Ok(RestorePhase::Verifying),
        "quarantined" => Ok(RestorePhase::Quarantined),
        "ready" => Ok(RestorePhase::Ready),
        "abandoned" => Ok(RestorePhase::Abandoned),
        _ => Err(corrupt("a stored recovery operation phase is unknown")),
    }
}

fn parse_checkpoint(value: &str) -> Result<RestoreCheckpoint, Failure> {
    match value {
        "ticket_consumed" => Ok(RestoreCheckpoint::TicketConsumed),
        "database_replaced" => Ok(RestoreCheckpoint::DatabaseReplaced),
        "inventory_verified" => Ok(RestoreCheckpoint::InventoryVerified),
        "authority_reset" => Ok(RestoreCheckpoint::AuthorityReset),
        _ => Err(corrupt("a stored recovery operation checkpoint is unknown")),
    }
}

impl TryFrom<RawProjectedRow> for ProjectedRestoreRow {
    type Error = Failure;

    fn try_from(row: RawProjectedRow) -> Result<Self, Self::Error> {
        Ok(Self {
            backup_id: row.backup_id,
            target_fingerprint: row.target_fingerprint,
            manifest_digest: row.manifest_digest,
            restore_epoch: row.restore_epoch,
            security_epoch: row.security_epoch,
            revision: row.revision,
            phase: parse_phase(&row.phase)?,
            checkpoint: parse_checkpoint(&row.last_checkpoint)?,
            authority_receipt_hash: row.authority_reset_receipt_hash,
            started_at: truncate_micros(row.started_at),
            updated_at: truncate_micros(row.updated_at),
            ready_at: row.ready_at.map(truncate_micros),
        })
    }
}

async fn read_projected_restore_for_update(
    tx: &mut Transaction<'_, Postgres>,
    operation_id: Uuid,
) -> Result<Option<ProjectedRestoreRow>, Failure> {
    let row = sqlx::query_as!(
        RawProjectedRow,
        "SELECT backup_id, target_fingerprint, manifest_digest,
            restore_epoch, security_epoch, revision, phase, last_checkpoint,
            authority_reset_receipt_hash, started_at, updated_at, ready_at
        FROM central.recovery_operations WHERE operation_id = $1::uuid FOR UPDATE",
        operation_id,
    )
    .fetch_optional(&mut **tx)
    .await
    .ctx("recovery audit read projection")?;
    row.map(ProjectedRestoreRow::try_from).transpose()
}

async fn insert_projected_restore(
    tx: &mut Transaction<'_, Postgres>,
    operation_id: Uuid,
    row: &ProjectedRestoreRow,
) -> Result<(), Failure> {
    sqlx::query!(
        "INSERT INTO central.recovery_operations (
            operation_id, backup_id, target_fingerprint, manifest_digest,
            restore_epoch, security_epoch, revision, phase, last_checkpoint,
            authority_reset_receipt_hash, started_at, updated_at, ready_at
        ) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
        operation_id,
        row.backup_id,
        row.target_fingerprint,
        row.manifest_digest,
        row.restore_epoch,
        row.security_epoch,
        row.revision,
        row.phase.as_str(),
        row.checkpoint.as_str(),
        row.authority_receipt_hash,
        row.started_at,
        row.updated_at,
        row.ready_at,
    )
    .execute(&mut **tx)
    .await
    .ctx("recovery audit insert projection")?;
    Ok(())
}

async fn update_projected_restore(
    tx: &mut Transaction<'_, Postgres>,
    operation_id: Uuid,
    expected_revision: i64,
    row: &ProjectedRestoreRow,
) -> Result<(), Failure> {
    let tag = sqlx::query!(
        "UPDATE central.recovery_operations SET
            revision = $3, phase = $4, last_checkpoint = $5, security_epoch = $6,
            authority_reset_receipt_hash = $7, updated_at = $8, ready_at = $9
        WHERE operation_id = $1::uuid AND revision = $2",
        operation_id,
        expected_revision,
        row.revision,
        row.phase.as_str(),
        row.checkpoint.as_str(),
        row.security_epoch,
        row.authority_receipt_hash,
        row.updated_at,
        row.ready_at,
    )
    .execute(&mut **tx)
    .await
    .ctx("recovery audit update projection")?;
    if tag.rows_affected() != 1 {
        return Err(audit_conflict(
            "recovery audit projection changed concurrently",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// `recovery_bootstrap_registrations` / `recovery_authority_reset_receipts`
// ---------------------------------------------------------------------------

async fn read_recovery_bootstrap_registration(
    tx: &mut Transaction<'_, Postgres>,
    operation: &RestoreOperation,
    draft: &RecoveryBootstrapDraft,
) -> Result<Option<RecoveryBootstrapRegistration>, Failure> {
    struct RawRegistration {
        draft_id: uuid::Uuid,
        candidate_id: uuid::Uuid,
        generation: i64,
        verifier_hash: Vec<u8>,
        candidate_digest: Vec<u8>,
        broker_receipt_hash: Vec<u8>,
        database_receipt_hash: Vec<u8>,
        registered_at: time::OffsetDateTime,
    }
    let row = sqlx::query_as!(
        RawRegistration,
        "SELECT draft_id, candidate_id, generation, verifier_hash, candidate_digest,
            broker_receipt_hash, database_receipt_hash, registered_at
        FROM central.recovery_bootstrap_registrations
        WHERE operation_id=$1::uuid FOR UPDATE",
        operation.operation_id,
    )
    .fetch_optional(&mut **tx)
    .await
    .ctx("recovery bootstrap registration read")?;
    let Some(row) = row else {
        return Ok(None);
    };
    let verifier_hash: [u8; 32] = row
        .verifier_hash
        .as_slice()
        .try_into()
        .map_err(|_| corrupt("recovery bootstrap registration is invalid"))?;
    let candidate_digest: [u8; 32] = row
        .candidate_digest
        .as_slice()
        .try_into()
        .map_err(|_| corrupt("recovery bootstrap registration is invalid"))?;
    let broker_hash: [u8; 32] = row
        .broker_receipt_hash
        .as_slice()
        .try_into()
        .map_err(|_| corrupt("recovery bootstrap registration is invalid"))?;
    let database_hash: [u8; 32] = row
        .database_receipt_hash
        .as_slice()
        .try_into()
        .map_err(|_| corrupt("recovery bootstrap registration is invalid"))?;
    if row.draft_id.is_nil() || row.candidate_id.is_nil() || row.generation <= 0 {
        return Err(corrupt("recovery bootstrap registration is invalid"));
    }
    let registration = RecoveryBootstrapRegistration {
        operation_id: operation.operation_id,
        draft_id: row.draft_id,
        candidate_id: row.candidate_id,
        generation: u64::try_from(row.generation)
            .map_err(|_| corrupt("recovery bootstrap registration is invalid"))?,
        verifier_hash,
        candidate_digest,
        broker_receipt_hash: format!("sha256:{}", hex_encode(&broker_hash)),
        database_receipt_hash: format!("sha256:{}", hex_encode(&database_hash)),
        registered_at: truncate_micros(row.registered_at),
    };
    if registration.validate_for(operation, draft).is_err() {
        return Err(audit_conflict(
            "recovery bootstrap registration replay mismatch",
        ));
    }
    Ok(Some(registration))
}

async fn read_authority_reset_receipt(
    tx: &mut Transaction<'_, Postgres>,
    operation_id: Uuid,
) -> Result<Option<AuthorityResetReceipt>, Failure> {
    struct RawReceipt {
        previous_restore_epoch: i64,
        new_restore_epoch: i64,
        previous_security_epoch: i64,
        new_security_epoch: i64,
        broker_receipt_hash: Vec<u8>,
        aggregate_receipt_hash: Vec<u8>,
        completed_at: time::OffsetDateTime,
    }
    let row = sqlx::query_as!(
        RawReceipt,
        "SELECT previous_restore_epoch, new_restore_epoch,
            previous_security_epoch, new_security_epoch, broker_receipt_hash,
            aggregate_receipt_hash, completed_at
        FROM central.recovery_authority_reset_receipts
        WHERE operation_id=$1::uuid FOR UPDATE",
        operation_id,
    )
    .fetch_optional(&mut **tx)
    .await
    .ctx("recovery authority reset read receipt")?;
    let Some(row) = row else {
        return Ok(None);
    };
    let broker_hash: [u8; 32] = row
        .broker_receipt_hash
        .as_slice()
        .try_into()
        .map_err(|_| corrupt("recovery authority reset stored receipt is invalid"))?;
    let aggregate_hash: [u8; 32] = row
        .aggregate_receipt_hash
        .as_slice()
        .try_into()
        .map_err(|_| corrupt("recovery authority reset stored receipt is invalid"))?;
    if row.previous_restore_epoch < 0
        || row.new_restore_epoch < 0
        || row.previous_security_epoch < 0
        || row.new_security_epoch < 0
    {
        return Err(corrupt(
            "recovery authority reset stored receipt is invalid",
        ));
    }
    Ok(Some(AuthorityResetReceipt {
        operation_id,
        previous_restore_epoch: u64::try_from(row.previous_restore_epoch)
            .map_err(|_| corrupt("recovery authority reset stored receipt is invalid"))?,
        new_restore_epoch: u64::try_from(row.new_restore_epoch)
            .map_err(|_| corrupt("recovery authority reset stored receipt is invalid"))?,
        previous_security_epoch: u64::try_from(row.previous_security_epoch)
            .map_err(|_| corrupt("recovery authority reset stored receipt is invalid"))?,
        new_security_epoch: u64::try_from(row.new_security_epoch)
            .map_err(|_| corrupt("recovery authority reset stored receipt is invalid"))?,
        broker_receipt_hash: format!("sha256:{}", hex_encode(&broker_hash)),
        // The cross-boundary fields are not persisted in this table; the
        // caller fills them from the verified registration/activation.
        database_receipt_hash: String::new(),
        bootstrap_candidate_id: Uuid::nil(),
        bootstrap_generation: 0,
        bootstrap_activation_receipt_hash: String::new(),
        aggregate_receipt_hash: format!("sha256:{}", hex_encode(&aggregate_hash)),
        completed_at: truncate_micros(row.completed_at),
    }))
}

async fn insert_authority_reset_receipt(
    tx: &mut Transaction<'_, Postgres>,
    receipt: &AuthorityResetReceipt,
    broker_hash: &[u8; 32],
) -> Result<(), Failure> {
    let aggregate = decode_sha256(&receipt.aggregate_receipt_hash)
        .map_err(|_| audit_invalid("recovery authority reset aggregate hash is invalid"))?;
    let normalized_completed_at = truncate_micros(receipt.completed_at);
    sqlx::query!(
        "INSERT INTO central.recovery_authority_reset_receipts (
            operation_id, previous_restore_epoch, new_restore_epoch,
            previous_security_epoch, new_security_epoch, broker_receipt_hash,
            aggregate_receipt_hash, completed_at
        ) VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (operation_id) DO NOTHING",
        receipt.operation_id,
        i64::try_from(receipt.previous_restore_epoch)
            .map_err(|_| audit_invalid("recovery audit counter exceeds PostgreSQL range"))?,
        i64::try_from(receipt.new_restore_epoch)
            .map_err(|_| audit_invalid("recovery audit counter exceeds PostgreSQL range"))?,
        i64::try_from(receipt.previous_security_epoch)
            .map_err(|_| audit_invalid("recovery audit counter exceeds PostgreSQL range"))?,
        i64::try_from(receipt.new_security_epoch)
            .map_err(|_| audit_invalid("recovery audit counter exceeds PostgreSQL range"))?,
        &broker_hash[..],
        &aggregate[..],
        normalized_completed_at,
    )
    .execute(&mut **tx)
    .await
    .ctx("recovery authority reset insert receipt")?;
    // Re-read inside the transaction — ON CONFLICT DO NOTHING plus a
    // concurrent winner must still satisfy the equality check.
    let Some(mut stored) = read_authority_reset_receipt(tx, receipt.operation_id).await? else {
        return Err(corrupt(
            "recovery authority reset receipt was not persisted",
        ));
    };
    stored.database_receipt_hash = receipt.database_receipt_hash.clone();
    stored.bootstrap_candidate_id = receipt.bootstrap_candidate_id;
    stored.bootstrap_generation = receipt.bootstrap_generation;
    stored.bootstrap_activation_receipt_hash = receipt.bootstrap_activation_receipt_hash.clone();
    let mut normalized = receipt.clone();
    normalized.completed_at = normalized_completed_at;
    if stored != normalized {
        return Err(audit_conflict(
            "recovery authority-reset receipt replay mismatch",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// `recovery_quarantines` verification
// ---------------------------------------------------------------------------

async fn verify_stored_quarantine(
    tx: &mut Transaction<'_, Postgres>,
    finding: &QuarantineFinding,
) -> Result<(), Failure> {
    struct RawStored {
        reason: String,
        expected_checksum: Option<Vec<u8>>,
        observed_checksum: Option<Vec<u8>>,
        expected_size: Option<i64>,
        observed_size: Option<i64>,
        state: String,
    }
    let row = sqlx::query_as!(
        RawStored,
        "SELECT reason, expected_checksum, observed_checksum,
            expected_size, observed_size, state FROM central.recovery_quarantines
        WHERE operation_id=$1::uuid AND artifact_id=$2::uuid FOR UPDATE",
        finding.operation_id,
        finding.artifact_id,
    )
    .fetch_one(&mut **tx)
    .await
    .ctx("recovery quarantine verify finding")?;
    // `observation_source` is deliberately NOT reread: the source/reason
    // relation is a bijection enforced by the database's own
    // `recovery_quarantines_reason_source_check` (migration b28), so a
    // stored row whose source differed would necessarily differ in
    // reason too.
    let reason_matches = row.reason == finding.reason.as_str();
    let checksum_matches =
        |stored: &Option<Vec<u8>>, expected: Option<[u8; 32]>| match (stored, expected) {
            (None, None) => true,
            (Some(stored), Some(expected)) => stored.as_slice() == expected,
            _ => false,
        };
    if !reason_matches
        || row.state != "open"
        || !checksum_matches(&row.expected_checksum, finding.expected_checksum)
        || !checksum_matches(&row.observed_checksum, finding.observed_checksum)
        || row.expected_size != finding.expected_size
        || row.observed_size != finding.observed_size
    {
        return Err(audit_conflict("recovery quarantine replay mismatch"));
    }
    Ok(())
}

// Needed for sha2::Digest::digest — kept at the bottom like upstream's
// helper block.
use sha2::Digest as _;
