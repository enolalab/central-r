//! `internal/backup/recovery.go` — C03/C04: the broker-issued one-use
//! `RestoreTicket`, the `RestoreOperation` state machine persisted in
//! the protected restore journal, the C05 `AuthorityResetReceipt`, and
//! the bootstrap draft/registration/activation evidence chain.

use central_foundation::failure::Failure;
use uuid::Uuid;

use crate::domain::TargetIdentity;
use crate::wire::{
    FIELD_SEPARATOR, hex_encode, hmac_sha256, is_v7, is_zero_time, mac_equal, rfc3339_nano,
    valid_recovery_digest, valid_sha256_fingerprint,
};

use crate::backup::operation::BACKUP_DATABASE_SCHEMA_VERSION;

/// `ServeTargetExclusionLockKey` — held for the full serving lifetime
/// and for every destructive C04 recovery (`"cent"` big-endian).
pub const SERVE_TARGET_EXCLUSION_LOCK_KEY: i64 = 0x63656e74;

fn invalid_restore() -> Failure {
    Failure::invalid("backup_recovery", "invalid recovery restore operation")
}

// ---------------------------------------------------------------------------
// RestoreTicket
// ---------------------------------------------------------------------------

/// `RestoreTicket` — broker-issued, one-use authorization input for
/// C03/C04. Consumption is recorded by the protected operation journal,
/// never the database being restored. `hidden_nonce` is never
/// serialized or displayed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreTicket {
    /// Ticket identity.
    pub ticket_id: Uuid,
    /// Bound operation identity.
    pub operation_id: Uuid,
    /// Bound backup identity.
    pub backup_id: Uuid,
    /// Bound target.
    pub target: TargetIdentity,
    /// `sha256:`-prefixed target fingerprint.
    pub target_fingerprint: String,
    /// `sha256:`-prefixed seal-root manifest digest.
    pub manifest_digest: String,
    /// Security epoch at issue.
    pub security_epoch: u64,
    /// Restore epoch at issue (the operation carries `+ 1`).
    pub restore_epoch: u64,
    /// `sha256:`-prefixed config fingerprint.
    pub config_fingerprint: String,
    /// Payload epoch (v7 UUID).
    pub payload_epoch_id: Uuid,
    /// Fixed [`BACKUP_DATABASE_SCHEMA_VERSION`].
    pub database_schema_version: String,
    /// `sha256:`-prefixed capacity evidence digest.
    pub capacity_evidence_digest: String,
    /// Pinned dump tool version.
    pub tool_version: String,
    /// One-use hidden nonce; never rendered.
    pub hidden_nonce: Vec<u8>,
    /// Issue instant (UTC).
    pub issued_at: time::OffsetDateTime,
    /// Expiry instant (UTC).
    pub expires_at: time::OffsetDateTime,
    /// Lowercase-hex HMAC-SHA-256 over `canonical_payload`.
    pub hmac: String,
}

impl RestoreTicket {
    /// `IsExpiredAt` — deterministic expiry; a malformed ticket is
    /// unusable even when its clock values would otherwise look valid.
    #[must_use]
    pub fn is_expired_at(&self, now: time::OffsetDateTime) -> bool {
        self.ticket_id.is_nil()
            || self.operation_id.is_nil()
            || self.backup_id.is_nil()
            || !self.target.is_valid()
            || self.target_fingerprint.is_empty()
            || self.manifest_digest.is_empty()
            || self.config_fingerprint.is_empty()
            || !is_v7(self.payload_epoch_id)
            || self.database_schema_version != BACKUP_DATABASE_SCHEMA_VERSION
            || !valid_sha256_fingerprint(&self.capacity_evidence_digest)
            || self.tool_version.is_empty()
            || self.hidden_nonce.is_empty()
            || is_zero_time(self.issued_at)
            || is_zero_time(self.expires_at)
            || self.expires_at <= self.issued_at
            || now >= self.expires_at
    }

    /// `CanonicalPayload` — `\n`-separated fields binding every mutable
    /// restore-admission input. The HMAC is excluded by construction;
    /// the nonce is included but never rendered.
    #[must_use]
    pub fn canonical_payload(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for value in [
            self.ticket_id.to_string(),
            self.operation_id.to_string(),
            self.backup_id.to_string(),
            self.target.system_id.clone(),
            self.target.database_oid.clone(),
            self.target.database.clone(),
            self.target.config_hash.clone(),
            self.target.epoch.to_string(),
            self.target_fingerprint.clone(),
            self.manifest_digest.clone(),
            self.security_epoch.to_string(),
            self.restore_epoch.to_string(),
            self.config_fingerprint.clone(),
            self.payload_epoch_id.to_string(),
            self.database_schema_version.clone(),
            self.capacity_evidence_digest.clone(),
            self.tool_version.clone(),
        ] {
            buf.extend_from_slice(value.as_bytes());
            buf.push(FIELD_SEPARATOR);
        }
        buf.extend_from_slice(&self.hidden_nonce);
        buf.push(FIELD_SEPARATOR);
        for value in [rfc3339_nano(self.issued_at), rfc3339_nano(self.expires_at)] {
            buf.extend_from_slice(value.as_bytes());
            buf.push(FIELD_SEPARATOR);
        }
        buf
    }

    /// `VerifyHMAC` — validates the ticket before its protected
    /// one-use consumption.
    #[must_use]
    pub fn verify_hmac(&self, key: &[u8]) -> bool {
        if self.hmac.is_empty() || key.is_empty() {
            return false;
        }
        let expected = hex_encode(&hmac_sha256(key, &self.canonical_payload()));
        mac_equal(self.hmac.as_bytes(), expected.as_bytes())
    }

    /// Mints the hex HMAC field — the broker-side counterpart used by
    /// tests and future broker adapters.
    #[must_use]
    pub fn issue_hmac(&self, key: &[u8]) -> String {
        hex_encode(&hmac_sha256(key, &self.canonical_payload()))
    }
}

// ---------------------------------------------------------------------------
// Short-lived ceremonies
// ---------------------------------------------------------------------------

/// `RestoreApplyAuthorization` — the short-lived, one-use result of
/// the helper-owned fresh PAM and physical-TTY ceremony. Every apply
/// and resume needs a new ceremony bound to the exact ticket and
/// protected operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestoreApplyAuthorization {
    /// Authorization identity.
    pub authorization_id: Uuid,
    /// Bound operation.
    pub operation_id: Uuid,
    /// Bound ticket.
    pub ticket_id: Uuid,
    /// Issue instant.
    pub issued_at: time::OffsetDateTime,
    /// Expiry instant.
    pub expires_at: time::OffsetDateTime,
}

impl RestoreApplyAuthorization {
    /// `ValidAt`.
    #[must_use]
    pub fn valid_at(&self, now: time::OffsetDateTime) -> bool {
        !self.authorization_id.is_nil()
            && !self.operation_id.is_nil()
            && !self.ticket_id.is_nil()
            && !is_zero_time(self.issued_at)
            && !is_zero_time(self.expires_at)
            && self.expires_at > self.issued_at
            && now > self.issued_at
            && now < self.expires_at
    }

    /// `Binds`.
    #[must_use]
    pub fn binds(&self, ticket: &RestoreTicket) -> bool {
        self.operation_id == ticket.operation_id && self.ticket_id == ticket.ticket_id
    }
}

/// `RestoreAbandonAcknowledgement` — the fixed, non-negotiable text a
/// fresh ceremony must attach: exact wording bound like every other
/// closed protocol identity.
pub const RESTORE_ABANDON_ACKNOWLEDGEMENT: &str =
    "central.restore-abandon-acknowledge-data-loss/v1";

/// `RestoreAbandonAuthorization` — short-lived, one-use, operation-
/// bound, carrying the explicit data-loss acknowledgement. Deliberately
/// a distinct type: a routine resume confirmation can never be
/// replayed as consent to give up the target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreAbandonAuthorization {
    /// Authorization identity.
    pub authorization_id: Uuid,
    /// Bound operation.
    pub operation_id: Uuid,
    /// Issue instant.
    pub issued_at: time::OffsetDateTime,
    /// Expiry instant.
    pub expires_at: time::OffsetDateTime,
    /// Must equal [`RESTORE_ABANDON_ACKNOWLEDGEMENT`].
    pub acknowledgement: String,
}

impl RestoreAbandonAuthorization {
    /// `ValidAt`.
    #[must_use]
    pub fn valid_at(&self, now: time::OffsetDateTime) -> bool {
        !self.authorization_id.is_nil()
            && !self.operation_id.is_nil()
            && !is_zero_time(self.issued_at)
            && !is_zero_time(self.expires_at)
            && self.expires_at > self.issued_at
            && now > self.issued_at
            && now < self.expires_at
            && self.acknowledgement == RESTORE_ABANDON_ACKNOWLEDGEMENT
    }
}

// ---------------------------------------------------------------------------
// RestoreOperation
// ---------------------------------------------------------------------------

/// `RestoreCheckpoint` — an externally durable recovery boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreCheckpoint {
    /// `ticket_consumed`.
    TicketConsumed,
    /// `database_replaced`.
    DatabaseReplaced,
    /// `inventory_verified`.
    InventoryVerified,
    /// `authority_reset`.
    AuthorityReset,
}

impl RestoreCheckpoint {
    /// The wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TicketConsumed => "ticket_consumed",
            Self::DatabaseReplaced => "database_replaced",
            Self::InventoryVerified => "inventory_verified",
            Self::AuthorityReset => "authority_reset",
        }
    }

    /// `validRestoreCheckpoint`.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        true
    }
}

/// `RestorePhase` — the operation-local representation of the
/// protected operator-state barrier. No phase permits serving until
/// `Ready`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestorePhase {
    /// `applying`.
    Applying,
    /// `verifying`.
    Verifying,
    /// `quarantined`.
    Quarantined,
    /// `ready`.
    Ready,
    /// `abandoned` — terminal, irreversible; reachable only through
    /// [`RestoreOperation::abandon`] from a resumable phase.
    Abandoned,
}

impl RestorePhase {
    /// The wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applying => "applying",
            Self::Verifying => "verifying",
            Self::Quarantined => "quarantined",
            Self::Ready => "ready",
            Self::Abandoned => "abandoned",
        }
    }
}

/// `AuthorityResetReceipt` — the non-secret aggregate evidence returned
/// by the C05 reset transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityResetReceipt {
    /// Bound operation.
    pub operation_id: Uuid,
    /// `operation.restore_epoch - 1`.
    pub previous_restore_epoch: u64,
    /// `operation.restore_epoch`.
    pub new_restore_epoch: u64,
    /// Security epoch before the reset.
    pub previous_security_epoch: u64,
    /// `previous_security_epoch + 1` exactly.
    pub new_security_epoch: u64,
    /// `sha256:` broker sub-receipt hash.
    pub broker_receipt_hash: String,
    /// `sha256:` database sub-receipt hash.
    pub database_receipt_hash: String,
    /// Bootstrap candidate (opaque).
    pub bootstrap_candidate_id: Uuid,
    /// Fresh bootstrap generation (nonzero).
    pub bootstrap_generation: u64,
    /// `sha256:` bootstrap activation receipt hash.
    pub bootstrap_activation_receipt_hash: String,
    /// `sha256:` aggregate hash binding every reset substep.
    pub aggregate_receipt_hash: String,
    /// Completion instant.
    pub completed_at: time::OffsetDateTime,
}

impl AuthorityResetReceipt {
    /// `ValidateFor`.
    pub fn validate_for(&self, operation: &RestoreOperation) -> Result<(), Failure> {
        let invalid = || {
            Failure::invalid(
                "backup_recovery",
                "invalid recovery authority-reset receipt",
            )
        };
        if operation.validate().is_err()
            || operation.phase != RestorePhase::Verifying
            || operation.last_checkpoint != RestoreCheckpoint::InventoryVerified
            || self.operation_id != operation.operation_id
            || operation.restore_epoch == 0
            || self.previous_restore_epoch != operation.restore_epoch - 1
            || self.new_restore_epoch != operation.restore_epoch
            || self.previous_security_epoch != operation.security_epoch
            || operation.security_epoch == u64::MAX
            || self.new_security_epoch != operation.security_epoch + 1
            || self.broker_receipt_hash.is_empty()
            || self.database_receipt_hash.is_empty()
            || self.bootstrap_candidate_id.is_nil()
            || self.bootstrap_generation == 0
            || self.bootstrap_activation_receipt_hash.is_empty()
            || self.aggregate_receipt_hash.is_empty()
            || is_zero_time(self.completed_at)
            || self.completed_at < operation.updated_at
        {
            return Err(invalid());
        }
        Ok(())
    }
}

/// `RecoveryBootstrapDraft` — broker-created recovery bootstrap
/// evidence. Plaintext remains in protected broker storage; only
/// hashes and opaque IDs cross this boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryBootstrapDraft {
    /// Bound operation.
    pub operation_id: Uuid,
    /// Draft identity.
    pub draft_id: Uuid,
    /// Candidate identity.
    pub candidate_id: Uuid,
    /// Verifier hash.
    pub verifier_hash: [u8; 32],
    /// Candidate digest.
    pub candidate_digest: [u8; 32],
    /// `sha256:` broker receipt hash.
    pub broker_receipt_hash: String,
    /// Creation instant.
    pub created_at: time::OffsetDateTime,
}

impl RecoveryBootstrapDraft {
    /// `ValidateFor`.
    pub fn validate_for(&self, operation: &RestoreOperation) -> Result<(), Failure> {
        if operation.validate().is_err()
            || operation.phase != RestorePhase::Verifying
            || operation.last_checkpoint != RestoreCheckpoint::InventoryVerified
            || self.operation_id != operation.operation_id
            || self.draft_id.is_nil()
            || self.candidate_id.is_nil()
            || self.verifier_hash == [0u8; 32]
            || self.candidate_digest == [0u8; 32]
            || !valid_recovery_digest(&self.broker_receipt_hash)
            || is_zero_time(self.created_at)
            || self.created_at < operation.updated_at
        {
            return Err(Failure::invalid(
                "backup_recovery",
                "invalid recovery bootstrap draft",
            ));
        }
        Ok(())
    }
}

/// `RecoveryBootstrapRegistration` — the exact fresh generation
/// atomically registered by PostgreSQL while all restored authority
/// is invalidated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryBootstrapRegistration {
    /// Bound operation.
    pub operation_id: Uuid,
    /// Bound draft.
    pub draft_id: Uuid,
    /// Bound candidate.
    pub candidate_id: Uuid,
    /// Fresh generation (nonzero).
    pub generation: u64,
    /// Verifier hash (must equal the draft's).
    pub verifier_hash: [u8; 32],
    /// Candidate digest (must equal the draft's).
    pub candidate_digest: [u8; 32],
    /// `sha256:` broker receipt hash (must equal the draft's).
    pub broker_receipt_hash: String,
    /// `sha256:` database receipt hash.
    pub database_receipt_hash: String,
    /// Registration instant.
    pub registered_at: time::OffsetDateTime,
}

impl RecoveryBootstrapRegistration {
    /// `ValidateFor`.
    pub fn validate_for(
        &self,
        operation: &RestoreOperation,
        draft: &RecoveryBootstrapDraft,
    ) -> Result<(), Failure> {
        if draft.validate_for(operation).is_err()
            || self.operation_id != operation.operation_id
            || self.draft_id != draft.draft_id
            || self.candidate_id != draft.candidate_id
            || self.generation == 0
            || self.verifier_hash != draft.verifier_hash
            || self.candidate_digest != draft.candidate_digest
            || self.broker_receipt_hash != draft.broker_receipt_hash
            || !valid_recovery_digest(&self.database_receipt_hash)
            || is_zero_time(self.registered_at)
            || self.registered_at < draft.created_at
        {
            return Err(Failure::invalid(
                "backup_recovery",
                "invalid recovery bootstrap registration",
            ));
        }
        Ok(())
    }
}

/// `RecoveryBootstrapActivation` — proves the broker registered and
/// activated the exact database-issued generation. Creates no session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryBootstrapActivation {
    /// Bound operation.
    pub operation_id: Uuid,
    /// Bound draft.
    pub draft_id: Uuid,
    /// Bound candidate.
    pub candidate_id: Uuid,
    /// Bound generation.
    pub generation: u64,
    /// `sha256:` database receipt hash (must equal the registration's).
    pub database_receipt_hash: String,
    /// `sha256:` activation receipt hash.
    pub activation_receipt_hash: String,
    /// Activation instant.
    pub activated_at: time::OffsetDateTime,
}

impl RecoveryBootstrapActivation {
    /// `ValidateFor`.
    pub fn validate_for(
        &self,
        operation: &RestoreOperation,
        registration: &RecoveryBootstrapRegistration,
    ) -> Result<(), Failure> {
        if operation.validate().is_err()
            || self.operation_id != operation.operation_id
            || self.draft_id != registration.draft_id
            || self.candidate_id != registration.candidate_id
            || self.generation != registration.generation
            || self.database_receipt_hash != registration.database_receipt_hash
            || !valid_recovery_digest(&self.activation_receipt_hash)
            || is_zero_time(self.activated_at)
            || self.activated_at < registration.registered_at
        {
            return Err(Failure::invalid(
                "backup_recovery",
                "invalid recovery bootstrap activation",
            ));
        }
        Ok(())
    }
}

/// `RestoreOperation` — the state persisted in the protected restore
/// journal. PostgreSQL audit projections may mirror it, but cannot be
/// the authority: the database is deliberately replaced during this
/// operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreOperation {
    /// Operation identity.
    pub operation_id: Uuid,
    /// Consumed ticket identity.
    pub ticket_id: Uuid,
    /// Backup identity.
    pub backup_id: Uuid,
    /// Bound target.
    pub target: TargetIdentity,
    /// `sha256:`-prefixed target fingerprint.
    pub target_fingerprint: String,
    /// `sha256:`-prefixed manifest digest.
    pub manifest_digest: String,
    /// Payload epoch (v7 UUID).
    pub payload_epoch_id: Uuid,
    /// Fixed schema version.
    pub database_schema_version: String,
    /// `sha256:`-prefixed capacity evidence digest.
    pub capacity_evidence_digest: String,
    /// Security epoch (advances exactly once at authority reset).
    pub security_epoch: u64,
    /// Restore epoch (`ticket.restore_epoch + 1`).
    pub restore_epoch: u64,
    /// Journal CAS fence.
    pub revision: u64,
    /// Current phase.
    pub phase: RestorePhase,
    /// Last durable checkpoint.
    pub last_checkpoint: RestoreCheckpoint,
    /// Aggregate reset receipt hash (set at `AuthorityReset`).
    pub authority_reset_receipt_hash: String,
    /// Start instant.
    pub started_at: time::OffsetDateTime,
    /// Last update.
    pub updated_at: time::OffsetDateTime,
    /// Ready instant (only when `phase == Ready`).
    pub ready_at: time::OffsetDateTime,
}

/// `NewRestoreOperation` — the atomic protected-journal transaction
/// that consumes a valid ticket and records `applying` before target
/// mutation. HMAC and one-use consumption are verified by the broker
/// before this transition; callers must still provide the unexpired
/// complete ticket.
pub fn new_restore_operation(
    ticket: &RestoreTicket,
    now: time::OffsetDateTime,
) -> Result<RestoreOperation, Failure> {
    if is_zero_time(now)
        || ticket.is_expired_at(now)
        || now < ticket.issued_at
        || ticket.restore_epoch == u64::MAX
    {
        return Err(Failure::invalid(
            "backup_recovery",
            "invalid recovery restore ticket",
        ));
    }
    let now = now.to_offset(time::UtcOffset::UTC);
    Ok(RestoreOperation {
        operation_id: ticket.operation_id,
        ticket_id: ticket.ticket_id,
        backup_id: ticket.backup_id,
        target: ticket.target.clone(),
        target_fingerprint: ticket.target_fingerprint.clone(),
        manifest_digest: ticket.manifest_digest.clone(),
        payload_epoch_id: ticket.payload_epoch_id,
        database_schema_version: ticket.database_schema_version.clone(),
        capacity_evidence_digest: ticket.capacity_evidence_digest.clone(),
        security_epoch: ticket.security_epoch,
        restore_epoch: ticket.restore_epoch + 1,
        revision: 1,
        phase: RestorePhase::Applying,
        last_checkpoint: RestoreCheckpoint::TicketConsumed,
        authority_reset_receipt_hash: String::new(),
        started_at: now,
        updated_at: now,
        ready_at: crate::wire::zero_time(),
    })
}

impl RestoreOperation {
    /// `IsResumable` — the exact protected operation, rather than a
    /// new ticket or process-local reconstruction, may resume.
    #[must_use]
    pub fn is_resumable(&self) -> bool {
        matches!(
            self.phase,
            RestorePhase::Applying | RestorePhase::Verifying | RestorePhase::Quarantined
        )
    }

    /// `IsTerminal` — `Ready` or `Abandoned`; both permanently refuse
    /// resumption.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self.phase, RestorePhase::Ready | RestorePhase::Abandoned)
    }

    /// `ServingAllowed` — deliberately stricter than terminality: a
    /// receipt-bound authority reset is mandatory even after the
    /// database and inventory verify.
    #[must_use]
    pub fn serving_allowed(&self) -> bool {
        self.phase == RestorePhase::Ready
            && self.last_checkpoint == RestoreCheckpoint::AuthorityReset
            && !is_zero_time(self.ready_at)
    }

    /// `AdmitsInventoryVerification` — the single definition every
    /// inventory-verification consumer shares: `verifying` just after
    /// `database_replaced`, or `quarantined` just after a prior
    /// inventory pass finished.
    #[must_use]
    pub fn admits_inventory_verification(&self) -> bool {
        (self.phase == RestorePhase::Verifying
            && self.last_checkpoint == RestoreCheckpoint::DatabaseReplaced)
            || (self.phase == RestorePhase::Quarantined
                && self.last_checkpoint == RestoreCheckpoint::InventoryVerified)
    }

    /// `Validate` — the complete persisted shape the protected journal
    /// accepts.
    pub fn validate(&self) -> Result<(), Failure> {
        if self.operation_id.is_nil()
            || self.ticket_id.is_nil()
            || self.backup_id.is_nil()
            || !self.target.is_valid()
            || self.target_fingerprint.is_empty()
            || self.manifest_digest.is_empty()
            || !is_v7(self.payload_epoch_id)
            || self.database_schema_version != BACKUP_DATABASE_SCHEMA_VERSION
            || !valid_sha256_fingerprint(&self.capacity_evidence_digest)
            || self.restore_epoch == 0
            || self.revision == 0
            || is_zero_time(self.started_at)
            || is_zero_time(self.updated_at)
            || self.updated_at < self.started_at
        {
            return Err(invalid_restore());
        }
        match self.phase {
            RestorePhase::Applying => {
                if !matches!(
                    self.last_checkpoint,
                    RestoreCheckpoint::TicketConsumed | RestoreCheckpoint::DatabaseReplaced
                ) {
                    return Err(invalid_restore());
                }
            }
            RestorePhase::Verifying => {
                if !matches!(
                    self.last_checkpoint,
                    RestoreCheckpoint::DatabaseReplaced
                        | RestoreCheckpoint::InventoryVerified
                        | RestoreCheckpoint::AuthorityReset
                ) {
                    return Err(invalid_restore());
                }
            }
            RestorePhase::Quarantined => {
                if self.last_checkpoint != RestoreCheckpoint::InventoryVerified {
                    return Err(invalid_restore());
                }
            }
            RestorePhase::Ready => {
                if !self.serving_allowed() {
                    return Err(invalid_restore());
                }
            }
            // `abandoned` preserves whichever checkpoint the resumable
            // operation reached; any of the four is legitimate.
            RestorePhase::Abandoned => {}
        }
        if self.last_checkpoint == RestoreCheckpoint::AuthorityReset
            && self.authority_reset_receipt_hash.is_empty()
        {
            return Err(invalid_restore());
        }
        if self.phase != RestorePhase::Ready && !is_zero_time(self.ready_at) {
            return Err(invalid_restore());
        }
        Ok(())
    }

    fn with_updated_at(&self, at: time::OffsetDateTime) -> Result<Self, Failure> {
        if self.validate().is_err() || is_zero_time(at) || at < self.updated_at {
            return Err(invalid_restore());
        }
        let mut next = self.clone();
        next.revision += 1;
        next.updated_at = at.to_offset(time::UtcOffset::UTC);
        Ok(next)
    }

    fn with_checkpoint(
        &self,
        checkpoint: RestoreCheckpoint,
        at: time::OffsetDateTime,
    ) -> Result<Self, Failure> {
        let mut next = self.with_updated_at(at)?;
        next.last_checkpoint = checkpoint;
        Ok(next)
    }

    /// `RecordDatabaseReplaced` — after `pg_restore` succeeds under
    /// the helper barrier.
    pub fn record_database_replaced(&self, at: time::OffsetDateTime) -> Result<Self, Failure> {
        if self.phase != RestorePhase::Applying
            || self.last_checkpoint != RestoreCheckpoint::TicketConsumed
        {
            return Err(Failure::invalid(
                "backup_recovery",
                "invalid recovery database replacement checkpoint",
            ));
        }
        self.with_checkpoint(RestoreCheckpoint::DatabaseReplaced, at)
    }

    /// `BeginVerification` — a crash before this transition remains
    /// `applying` and resumable.
    pub fn begin_verification(&self, at: time::OffsetDateTime) -> Result<Self, Failure> {
        if self.phase != RestorePhase::Applying
            || self.last_checkpoint != RestoreCheckpoint::DatabaseReplaced
        {
            return Err(Failure::invalid(
                "backup_recovery",
                "invalid recovery verification transition",
            ));
        }
        let mut next = self.with_updated_at(at)?;
        next.phase = RestorePhase::Verifying;
        Ok(next)
    }

    /// `RecordInventoryVerified` — must happen before either
    /// quarantine or authority reset.
    pub fn record_inventory_verified(&self, at: time::OffsetDateTime) -> Result<Self, Failure> {
        if self.phase != RestorePhase::Verifying
            || self.last_checkpoint != RestoreCheckpoint::DatabaseReplaced
        {
            return Err(Failure::invalid(
                "backup_recovery",
                "invalid recovery inventory checkpoint",
            ));
        }
        self.with_checkpoint(RestoreCheckpoint::InventoryVerified, at)
    }

    /// `EnterQuarantine` — resolution is a normal artifact lifecycle
    /// action, never a flag clear on this operation.
    pub fn enter_quarantine(&self, at: time::OffsetDateTime) -> Result<Self, Failure> {
        if self.phase != RestorePhase::Verifying
            || self.last_checkpoint != RestoreCheckpoint::InventoryVerified
        {
            return Err(Failure::invalid(
                "backup_recovery",
                "invalid recovery quarantine transition",
            ));
        }
        let mut next = self.with_updated_at(at)?;
        next.phase = RestorePhase::Quarantined;
        Ok(next)
    }

    /// `ResumeVerification` — only an external journal count of zero
    /// unresolved findings releases the barrier. A nonzero count keeps
    /// the target blocked and makes no change.
    pub fn resume_verification(
        &self,
        unresolved_quarantines: u64,
        at: time::OffsetDateTime,
    ) -> Result<Self, Failure> {
        if self.phase != RestorePhase::Quarantined
            || self.last_checkpoint != RestoreCheckpoint::InventoryVerified
            || unresolved_quarantines != 0
        {
            return Err(Failure::invalid(
                "backup_recovery",
                "recovery quarantine remains unresolved",
            ));
        }
        let mut next = self.with_updated_at(at)?;
        next.phase = RestorePhase::Verifying;
        Ok(next)
    }

    /// `RecordAuthorityReset` — the only precursor to `Ready`; installs
    /// the receipt's exact next security epoch.
    pub fn record_authority_reset(&self, receipt: &AuthorityResetReceipt) -> Result<Self, Failure> {
        if receipt.validate_for(self).is_err() {
            return Err(Failure::invalid(
                "backup_recovery",
                "invalid recovery authority-reset checkpoint",
            ));
        }
        let mut next =
            self.with_checkpoint(RestoreCheckpoint::AuthorityReset, receipt.completed_at)?;
        next.security_epoch = receipt.new_security_epoch;
        next.authority_reset_receipt_hash = receipt.aggregate_receipt_hash.clone();
        Ok(next)
    }

    /// `MarkReady` — there is intentionally no force-ready or shortcut
    /// transition.
    pub fn mark_ready(&self, at: time::OffsetDateTime) -> Result<Self, Failure> {
        if self.phase != RestorePhase::Verifying
            || self.last_checkpoint != RestoreCheckpoint::AuthorityReset
            || self.authority_reset_receipt_hash.is_empty()
        {
            return Err(Failure::invalid(
                "backup_recovery",
                "invalid recovery ready transition",
            ));
        }
        let mut next = self.with_updated_at(at)?;
        next.phase = RestorePhase::Ready;
        next.ready_at = at.to_offset(time::UtcOffset::UTC);
        Ok(next)
    }

    /// `Abandon` — the terminal, irreversible outcome ADR 0016
    /// authorizes: a fresh, unexpired, operation-bound authorization
    /// carrying the explicit data-loss acknowledgement, from any
    /// resumable phase.
    pub fn abandon(
        &self,
        authorization: &RestoreAbandonAuthorization,
        at: time::OffsetDateTime,
    ) -> Result<Self, Failure> {
        if !self.is_resumable() {
            return Err(Failure::invalid(
                "backup_recovery",
                "invalid recovery abandonment transition",
            ));
        }
        if authorization.operation_id != self.operation_id || !authorization.valid_at(at) {
            return Err(Failure::invalid(
                "backup_recovery",
                "recovery abandonment requires a fresh operation-bound ceremony",
            ));
        }
        let mut next = self.with_updated_at(at)?;
        next.phase = RestorePhase::Abandoned;
        Ok(next)
    }

    /// `ValidateTransitionTo` — rejects a syntactically valid record
    /// not produced by a closed transition method. Journal adapters
    /// call it before every CAS so caller-supplied state cannot skip
    /// checkpoints or manufacture a security-epoch advance.
    pub fn validate_transition_to(&self, next: &RestoreOperation) -> Result<(), Failure> {
        let invalid = || Failure::invalid("backup_recovery", "invalid recovery restore transition");
        if self.validate().is_err()
            || next.validate().is_err()
            || next.revision != self.revision + 1
            || next.operation_id != self.operation_id
            || next.ticket_id != self.ticket_id
            || next.backup_id != self.backup_id
            || next.target != self.target
            || next.target_fingerprint != self.target_fingerprint
            || next.manifest_digest != self.manifest_digest
            || next.payload_epoch_id != self.payload_epoch_id
            || next.database_schema_version != self.database_schema_version
            || next.capacity_evidence_digest != self.capacity_evidence_digest
            || next.restore_epoch != self.restore_epoch
            || next.started_at != self.started_at
            || next.updated_at < self.updated_at
        {
            return Err(invalid());
        }
        let security_unchanged = next.security_epoch == self.security_epoch;
        let receipt_unchanged =
            next.authority_reset_receipt_hash == self.authority_reset_receipt_hash;
        let ready_unchanged = next.ready_at == self.ready_at;

        // Abandonment: the complement of `is_resumable`, from every
        // resumable phase; the checkpoint never changes.
        if self.is_resumable()
            && next.phase == RestorePhase::Abandoned
            && next.last_checkpoint == self.last_checkpoint
            && security_unchanged
            && receipt_unchanged
            && ready_unchanged
        {
            return Ok(());
        }

        let allowed = match (self.phase, self.last_checkpoint) {
            (RestorePhase::Applying, RestoreCheckpoint::TicketConsumed) => {
                next.phase == RestorePhase::Applying
                    && next.last_checkpoint == RestoreCheckpoint::DatabaseReplaced
                    && security_unchanged
                    && receipt_unchanged
                    && ready_unchanged
            }
            (RestorePhase::Applying, RestoreCheckpoint::DatabaseReplaced) => {
                next.phase == RestorePhase::Verifying
                    && next.last_checkpoint == RestoreCheckpoint::DatabaseReplaced
                    && security_unchanged
                    && receipt_unchanged
                    && ready_unchanged
            }
            (RestorePhase::Verifying, RestoreCheckpoint::DatabaseReplaced) => {
                next.phase == RestorePhase::Verifying
                    && next.last_checkpoint == RestoreCheckpoint::InventoryVerified
                    && security_unchanged
                    && receipt_unchanged
                    && ready_unchanged
            }
            (RestorePhase::Verifying, RestoreCheckpoint::InventoryVerified) => {
                (next.phase == RestorePhase::Quarantined
                    && next.last_checkpoint == RestoreCheckpoint::InventoryVerified
                    && security_unchanged
                    && receipt_unchanged
                    && ready_unchanged)
                    || (self.security_epoch != u64::MAX
                        && next.phase == RestorePhase::Verifying
                        && next.last_checkpoint == RestoreCheckpoint::AuthorityReset
                        && next.security_epoch == self.security_epoch + 1
                        && !next.authority_reset_receipt_hash.is_empty()
                        && ready_unchanged)
            }
            (RestorePhase::Quarantined, RestoreCheckpoint::InventoryVerified) => {
                next.phase == RestorePhase::Verifying
                    && next.last_checkpoint == RestoreCheckpoint::InventoryVerified
                    && security_unchanged
                    && receipt_unchanged
                    && ready_unchanged
            }
            (RestorePhase::Verifying, RestoreCheckpoint::AuthorityReset) => {
                next.phase == RestorePhase::Ready
                    && next.last_checkpoint == RestoreCheckpoint::AuthorityReset
                    && security_unchanged
                    && receipt_unchanged
                    && next.ready_at == next.updated_at
                    && !is_zero_time(next.ready_at)
            }
            _ => false,
        };
        if allowed { Ok(()) } else { Err(invalid()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn target() -> TargetIdentity {
        TargetIdentity {
            system_id: "sys".into(),
            database_oid: "16384".into(),
            database: "central".into(),
            config_hash: "cfg".into(),
            epoch: 1,
        }
    }

    fn ticket() -> RestoreTicket {
        RestoreTicket {
            ticket_id: Uuid::now_v7(),
            operation_id: Uuid::now_v7(),
            backup_id: Uuid::now_v7(),
            target: target(),
            target_fingerprint: format!("sha256:{}", "a".repeat(64)),
            manifest_digest: format!("sha256:{}", "b".repeat(64)),
            security_epoch: 7,
            restore_epoch: 3,
            config_fingerprint: format!("sha256:{}", "c".repeat(64)),
            payload_epoch_id: Uuid::now_v7(),
            database_schema_version: BACKUP_DATABASE_SCHEMA_VERSION.into(),
            capacity_evidence_digest: format!("sha256:{}", "d".repeat(64)),
            tool_version: "pg_dump-16.14".into(),
            hidden_nonce: b"nonce".to_vec(),
            issued_at: datetime!(2026-03-01 12:00:00 UTC),
            expires_at: datetime!(2026-03-01 13:00:00 UTC),
            hmac: String::new(),
        }
    }

    #[test]
    fn ticket_hmac_binds_every_field() {
        let key = b"broker-key";
        let mut ticket = ticket();
        ticket.hmac = ticket.issue_hmac(key);
        assert!(ticket.verify_hmac(key));
        // Tampered target binding refuses.
        let mut replay = ticket.clone();
        replay.manifest_digest = format!("sha256:{}", "9".repeat(64));
        assert!(!replay.verify_hmac(key));
        // Wrong key refuses; empty HMAC refuses.
        assert!(!ticket.verify_hmac(b"other"));
        let mut bare = ticket.clone();
        bare.hmac.clear();
        assert!(!bare.verify_hmac(key));
        // Expired ticket refuses at is_expired_at.
        assert!(!ticket.is_expired_at(datetime!(2026-03-01 12:30:00 UTC)));
        assert!(ticket.is_expired_at(datetime!(2026-03-01 13:00:00 UTC)));
        // Boundary: issued_at itself is not yet valid for an operation.
        assert!(new_restore_operation(&ticket, ticket.issued_at - time::Duration::SECOND).is_err());
        assert!(new_restore_operation(&ticket, ticket.expires_at).is_err());
    }

    fn receipt_for(op: &RestoreOperation) -> AuthorityResetReceipt {
        AuthorityResetReceipt {
            operation_id: op.operation_id,
            previous_restore_epoch: op.restore_epoch - 1,
            new_restore_epoch: op.restore_epoch,
            previous_security_epoch: op.security_epoch,
            new_security_epoch: op.security_epoch + 1,
            broker_receipt_hash: "sha256:aa".into(),
            database_receipt_hash: "sha256:bb".into(),
            bootstrap_candidate_id: Uuid::now_v7(),
            bootstrap_generation: 1,
            bootstrap_activation_receipt_hash: "sha256:cc".into(),
            aggregate_receipt_hash: "sha256:dd".into(),
            completed_at: op.updated_at,
        }
    }

    #[test]
    fn restore_lifecycle_and_serving_barrier() {
        let now = datetime!(2026-03-01 12:30:00 UTC);
        let operation = new_restore_operation(&ticket(), now).unwrap();
        assert_eq!(operation.phase, RestorePhase::Applying);
        assert_eq!(operation.restore_epoch, 4);
        assert!(operation.is_resumable() && !operation.is_terminal());
        assert!(!operation.serving_allowed());
        assert!(operation.validate().is_ok());

        // No shortcut: verification needs database_replaced first.
        assert!(operation.begin_verification(now).is_err());
        assert!(operation.record_inventory_verified(now).is_err());
        let replaced = operation.record_database_replaced(now).unwrap();
        assert!(!replaced.admits_inventory_verification());
        let verifying = replaced.begin_verification(now).unwrap();
        assert!(verifying.admits_inventory_verification());
        let verified = verifying.record_inventory_verified(now).unwrap();
        // Ready is impossible before the authority reset.
        assert!(verified.mark_ready(now).is_err());
        // A bogus receipt refuses.
        let mut bad = receipt_for(&verified);
        bad.new_security_epoch += 1;
        assert!(verified.record_authority_reset(&bad).is_err());
        let reset = verified
            .record_authority_reset(&receipt_for(&verified))
            .unwrap();
        assert_eq!(reset.security_epoch, 8);
        assert_eq!(reset.authority_reset_receipt_hash, "sha256:dd");
        let ready = reset.mark_ready(now).unwrap();
        assert!(ready.serving_allowed());
        assert!(ready.is_terminal() && !ready.is_resumable());
        // validate_transition_to accepts exactly the produced chain.
        assert!(operation.validate_transition_to(&replaced).is_ok());
        assert!(replaced.validate_transition_to(&verifying).is_ok());
        assert!(verifying.validate_transition_to(&verified).is_ok());
        assert!(verified.validate_transition_to(&reset).is_ok());
        assert!(reset.validate_transition_to(&ready).is_ok());
        // Skipping a checkpoint cannot be forged.
        assert!(verifying.validate_transition_to(&ready).is_err());
        // Quarantine round-trip.
        let quarantined = verified.enter_quarantine(now).unwrap();
        assert!(quarantined.resume_verification(1, now).is_err());
        let resumed = quarantined.resume_verification(0, now).unwrap();
        assert_eq!(resumed.phase, RestorePhase::Verifying);
        // Abandonment needs the exact acknowledgement and binds the op.
        let auth = RestoreAbandonAuthorization {
            authorization_id: Uuid::now_v7(),
            operation_id: quarantined.operation_id,
            issued_at: now - time::Duration::MINUTE,
            expires_at: now + time::Duration::MINUTE,
            acknowledgement: RESTORE_ABANDON_ACKNOWLEDGEMENT.into(),
        };
        let abandoned = quarantined.abandon(&auth, now).unwrap();
        assert!(abandoned.is_terminal() && !abandoned.is_resumable());
        assert!(!abandoned.serving_allowed());
        let mut wrong_op = auth.clone();
        wrong_op.operation_id = Uuid::now_v7();
        assert!(quarantined.abandon(&wrong_op, now).is_err());
        let mut wrong_text = auth.clone();
        wrong_text.acknowledgement = "sure, whatever".into();
        assert!(quarantined.abandon(&wrong_text, now).is_err());
        // Terminal phases refuse abandonment.
        assert!(ready.abandon(&auth, now).is_err());
    }
}
