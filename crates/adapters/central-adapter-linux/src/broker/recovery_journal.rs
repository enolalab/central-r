//! `recovery_journal.rs` — the port of upstream
//! `internal/adapter/authority/broker/recovery_journal.go`: the
//! file-backed protected source of truth for C01/C03/C04/C05.
//!
//! Ticket material, apply/abandon ceremonies, restore and backup
//! operation records, MinIO credential handoffs, backup seals, and the
//! broker half of the authority reset all live below the broker root
//! rather than in the PostgreSQL database being replaced. Record
//! filenames are `sha256` hashes of their identities, so neither a
//! caller-supplied ID nor a target name becomes a filesystem path.
//!
//! Every record type here is a private wire struct: the domain types
//! (`RestoreTicket`, `RestoreOperation`, `BackupOperation`, the seal
//! evidence) deliberately carry no serde derives, so this module owns
//! the PascalCase-on-disk shapes upstream's `json.Marshal` produces,
//! plus the strict `deny_unknown_fields` decode
//! `DisallowUnknownFields` performs. Reads re-validate ownership,
//! mode, regular-file status, link count, and re-run the domain
//! `Validate`/`Verify`/`HMAC` checks on every load — a corrupt,
//! partial, foreign, or ambiguous entry fails closed and is never
//! silently repaired.

use std::io::Read as _;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use central_backup::backup::operation::{
    BackupAcceptedFacts, BackupOperation, BackupPhase, BackupSealProposal,
};
use central_backup::domain::TargetIdentity;
use central_backup::port::RestoreAdmissionFacts;
use central_backup::recovery::operation::{
    RecoveryBootstrapDraft, RestoreAbandonAuthorization, RestoreApplyAuthorization,
    RestoreCheckpoint, RestoreOperation, RestorePhase, RestoreTicket, new_restore_operation,
};
use central_backup::repository::{
    BACKUP_SEAL_HMAC_DOMAIN, BACKUP_SEAL_KEY_VERSION, BackupRepositoryAttestation,
    BackupSealCompanion, BackupTargetLockAttestation,
};
use central_foundation::failure::Failure;
use central_infra::authority::{
    MinioProvisionedDescriptor, RecoveryMinioHandoffReceipt, RecoveryMinioHandoffRequest,
};
use central_infra::domain::{
    MINIO_PROVISIONER_GID, MINIO_PROVISIONER_UID, Purpose, minio_recovery_key_scope,
    minio_recovery_policy_digest,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use zeroize::Zeroize as _;

use super::durable;
use super::protected_file::{Generation, ProtectedFileBackend};
use super::signing::SigningService;
use super::wire;

pub(crate) const RECOVERY_TICKET_DIRECTORY: &str = "restore-tickets";
/// `recoveryTicketLaunchDirectory` — the operation → issuing-launch
/// records the capacity gate and the reserve sweep read.
pub(crate) const RECOVERY_TICKET_LAUNCH_DIRECTORY: &str = "restore-ticket-launches";
pub(crate) const RECOVERY_APPLY_DIRECTORY: &str = "restore-apply-authorizations";
/// `recoveryAbandonDirectory` — ADR 0016 abandonment authorizations,
/// kept apart from the apply authorizations because they are a
/// different authority: an apply authorization names a ticket and
/// permits a destructive run, an abandonment authorization names only
/// an operation and permits giving it up.
pub(crate) const RECOVERY_ABANDON_DIRECTORY: &str = "restore-abandon-authorizations";
pub(crate) const RECOVERY_OPERATION_DIRECTORY: &str = "restore-operations";
pub(crate) const BACKUP_OPERATION_DIRECTORY: &str = "backup-operations";
pub(crate) const RECOVERY_MINIO_RECEIPT_DIR: &str = "recovery-minio-receipts";
pub(crate) const RECOVERY_BROKER_RESET_DIR: &str = "recovery-broker-resets";
pub(crate) const BACKUP_SEAL_DIRECTORY: &str = "backup-seals";

pub(crate) const RESTORE_TICKET_HMAC_DOMAIN: &str = "slice-c-restore-ticket-v1";
pub(crate) const RESTORE_TICKET_LAUNCH_HMAC_DOMAIN: &str = "slice-c-restore-ticket-launch-v1";
/// `RestoreTicketLaunchRecordSchema` — versions the operation →
/// issuing-launch record. It is separate from every other schema
/// constant because it is the one a future build must recognize as
/// unreadable rather than absent: the sweep's retention of a bound set
/// turns on it.
pub(crate) const RESTORE_TICKET_LAUNCH_RECORD_SCHEMA: &str =
    "central.restore-ticket-launch-record/v1";
#[allow(dead_code)] // slice-(b) broker-reset surface
pub(crate) const BROKER_RESET_HMAC_DOMAIN: &str = "slice-c-broker-authority-reset-record-v1";
#[allow(dead_code)] // slice-(b) broker-reset surface
const BROKER_RESET_RECEIPT_HMAC_DOMAIN: &str = "slice-c-broker-authority-reset-v1";
const BACKUP_AUTHORITY_ENVELOPE_HMAC_DOMAIN: &str = "slice-c-backup-authority-envelope-v1";
pub(crate) const RESTORE_TICKET_LIFETIME: Duration = Duration::minutes(15);
pub(crate) const RESTORE_APPLY_LIFETIME: Duration = Duration::minutes(2);
/// `restoreAbandonLifetime` — bounds an abandonment authorization to
/// the same window as an apply one; a separate constant because the
/// two ceremonies are separate authorities.
pub(crate) const RESTORE_ABANDON_LIFETIME: Duration = Duration::minutes(2);

const READ_PRIVATE_JSON_LIMIT: u64 = 256 * 1024;
#[allow(dead_code)] // slice-(b) broker-reset surface
const BOOTSTRAP_VALUE_LIMIT: usize = 4096;
const ARTIFACTS_BUCKET: &str = "central-artifacts-v1";

/// `errRecoveryJournalUnavailable` — the one sentinel every refusal
/// path collapses into; upstream deliberately does not distinguish
/// "absent" from "corrupt" on the guarded paths.
pub(crate) const JOURNAL_UNAVAILABLE_CODE: &str = "broker_recovery_journal_unavailable";

pub(crate) fn unavailable() -> Failure {
    Failure::internal(
        JOURNAL_UNAVAILABLE_CODE,
        "broker: recovery journal unavailable",
    )
}

/// `errRestoreTicketLaunchNotFound` — the operation → issuing-launch
/// record demonstrably does not exist. Distinct from [`unavailable`]
/// because the reserve sweep may treat "not there" as "nothing to
/// protect" and must never treat "there and unreadable" the same way.
pub(crate) const TICKET_LAUNCH_NOT_FOUND_CODE: &str = "broker_restore_ticket_launch_not_found";

fn ticket_launch_not_found() -> Failure {
    Failure::internal(
        TICKET_LAUNCH_NOT_FOUND_CODE,
        "broker: restore ticket launch record not found",
    )
}

// ---------------------------------------------------------------------------
// Domain wire shapes — PascalCase, exactly as Go's `json.Marshal`
// emits for the tag-less domain structs. `deny_unknown_fields` is the
// `DisallowUnknownFields` decode upstream performs.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TargetIdentityWire {
    #[serde(rename = "SystemID")]
    pub system_id: String,
    #[serde(rename = "DatabaseOID")]
    pub database_oid: String,
    #[serde(rename = "Database")]
    pub database: String,
    #[serde(rename = "ConfigHash")]
    pub config_hash: String,
    #[serde(rename = "Epoch")]
    pub epoch: u64,
}

fn target_to_wire(target: &TargetIdentity) -> TargetIdentityWire {
    TargetIdentityWire {
        system_id: target.system_id.clone(),
        database_oid: target.database_oid.clone(),
        database: target.database.clone(),
        config_hash: target.config_hash.clone(),
        epoch: target.epoch,
    }
}

fn target_from_wire(wire: &TargetIdentityWire) -> TargetIdentity {
    TargetIdentity {
        system_id: wire.system_id.clone(),
        database_oid: wire.database_oid.clone(),
        database: wire.database.clone(),
        config_hash: wire.config_hash.clone(),
        epoch: wire.epoch,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RestoreTicketWire {
    #[serde(rename = "TicketID")]
    pub(crate) ticket_id: Uuid,
    #[serde(rename = "OperationID")]
    pub(crate) operation_id: Uuid,
    #[serde(rename = "BackupID")]
    pub(crate) backup_id: Uuid,
    #[serde(rename = "Target")]
    pub(crate) target: TargetIdentityWire,
    #[serde(rename = "TargetFingerprint")]
    pub(crate) target_fingerprint: String,
    #[serde(rename = "ManifestDigest")]
    pub(crate) manifest_digest: String,
    #[serde(rename = "SecurityEpoch")]
    pub(crate) security_epoch: u64,
    #[serde(rename = "RestoreEpoch")]
    pub(crate) restore_epoch: u64,
    #[serde(rename = "ConfigFingerprint")]
    pub(crate) config_fingerprint: String,
    #[serde(rename = "PayloadEpochID")]
    pub(crate) payload_epoch_id: Uuid,
    #[serde(rename = "DatabaseSchemaVersion")]
    pub(crate) database_schema_version: String,
    #[serde(rename = "CapacityEvidenceDigest")]
    pub(crate) capacity_evidence_digest: String,
    #[serde(rename = "ToolVersion")]
    pub(crate) tool_version: String,
    #[serde(rename = "HiddenNonce", with = "wire::b64")]
    pub(crate) hidden_nonce: Vec<u8>,
    #[serde(rename = "IssuedAt", with = "wire::rfc3339")]
    pub(crate) issued_at: OffsetDateTime,
    #[serde(rename = "ExpiresAt", with = "wire::rfc3339")]
    pub(crate) expires_at: OffsetDateTime,
    #[serde(rename = "HMAC")]
    pub(crate) hmac: String,
}

fn ticket_to_wire(ticket: &RestoreTicket) -> RestoreTicketWire {
    RestoreTicketWire {
        ticket_id: ticket.ticket_id,
        operation_id: ticket.operation_id,
        backup_id: ticket.backup_id,
        target: target_to_wire(&ticket.target),
        target_fingerprint: ticket.target_fingerprint.clone(),
        manifest_digest: ticket.manifest_digest.clone(),
        security_epoch: ticket.security_epoch,
        restore_epoch: ticket.restore_epoch,
        config_fingerprint: ticket.config_fingerprint.clone(),
        payload_epoch_id: ticket.payload_epoch_id,
        database_schema_version: ticket.database_schema_version.clone(),
        capacity_evidence_digest: ticket.capacity_evidence_digest.clone(),
        tool_version: ticket.tool_version.clone(),
        hidden_nonce: ticket.hidden_nonce.clone(),
        issued_at: ticket.issued_at,
        expires_at: ticket.expires_at,
        hmac: ticket.hmac.clone(),
    }
}

fn ticket_from_wire(wire: &RestoreTicketWire) -> RestoreTicket {
    RestoreTicket {
        ticket_id: wire.ticket_id,
        operation_id: wire.operation_id,
        backup_id: wire.backup_id,
        target: target_from_wire(&wire.target),
        target_fingerprint: wire.target_fingerprint.clone(),
        manifest_digest: wire.manifest_digest.clone(),
        security_epoch: wire.security_epoch,
        restore_epoch: wire.restore_epoch,
        config_fingerprint: wire.config_fingerprint.clone(),
        payload_epoch_id: wire.payload_epoch_id,
        database_schema_version: wire.database_schema_version.clone(),
        capacity_evidence_digest: wire.capacity_evidence_digest.clone(),
        tool_version: wire.tool_version.clone(),
        hidden_nonce: wire.hidden_nonce.clone(),
        issued_at: wire.issued_at,
        expires_at: wire.expires_at,
        hmac: wire.hmac.clone(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RestoreApplyAuthorizationWire {
    #[serde(rename = "AuthorizationID")]
    authorization_id: Uuid,
    #[serde(rename = "OperationID")]
    operation_id: Uuid,
    #[serde(rename = "TicketID")]
    ticket_id: Uuid,
    #[serde(rename = "IssuedAt", with = "wire::rfc3339")]
    issued_at: OffsetDateTime,
    #[serde(rename = "ExpiresAt", with = "wire::rfc3339")]
    expires_at: OffsetDateTime,
}

pub(crate) fn apply_authorization_to_wire(
    a: &RestoreApplyAuthorization,
) -> RestoreApplyAuthorizationWire {
    RestoreApplyAuthorizationWire {
        authorization_id: a.authorization_id,
        operation_id: a.operation_id,
        ticket_id: a.ticket_id,
        issued_at: a.issued_at,
        expires_at: a.expires_at,
    }
}

pub(crate) fn apply_authorization_from_wire(
    wire: &RestoreApplyAuthorizationWire,
) -> RestoreApplyAuthorization {
    RestoreApplyAuthorization {
        authorization_id: wire.authorization_id,
        operation_id: wire.operation_id,
        ticket_id: wire.ticket_id,
        issued_at: wire.issued_at,
        expires_at: wire.expires_at,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RestoreAbandonAuthorizationWire {
    #[serde(rename = "AuthorizationID")]
    authorization_id: Uuid,
    #[serde(rename = "OperationID")]
    operation_id: Uuid,
    #[serde(rename = "IssuedAt", with = "wire::rfc3339")]
    issued_at: OffsetDateTime,
    #[serde(rename = "ExpiresAt", with = "wire::rfc3339")]
    expires_at: OffsetDateTime,
    #[serde(rename = "Acknowledgement")]
    acknowledgement: String,
}

pub(crate) fn abandon_authorization_to_wire(
    a: &RestoreAbandonAuthorization,
) -> RestoreAbandonAuthorizationWire {
    RestoreAbandonAuthorizationWire {
        authorization_id: a.authorization_id,
        operation_id: a.operation_id,
        issued_at: a.issued_at,
        expires_at: a.expires_at,
        acknowledgement: a.acknowledgement.clone(),
    }
}

pub(crate) fn abandon_authorization_from_wire(
    wire: &RestoreAbandonAuthorizationWire,
) -> RestoreAbandonAuthorization {
    RestoreAbandonAuthorization {
        authorization_id: wire.authorization_id,
        operation_id: wire.operation_id,
        issued_at: wire.issued_at,
        expires_at: wire.expires_at,
        acknowledgement: wire.acknowledgement.clone(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RestoreOperationWire {
    #[serde(rename = "OperationID")]
    operation_id: Uuid,
    #[serde(rename = "TicketID")]
    ticket_id: Uuid,
    #[serde(rename = "BackupID")]
    backup_id: Uuid,
    #[serde(rename = "Target")]
    target: TargetIdentityWire,
    #[serde(rename = "TargetFingerprint")]
    target_fingerprint: String,
    #[serde(rename = "ManifestDigest")]
    manifest_digest: String,
    #[serde(rename = "PayloadEpochID")]
    payload_epoch_id: Uuid,
    #[serde(rename = "DatabaseSchemaVersion")]
    database_schema_version: String,
    #[serde(rename = "CapacityEvidenceDigest")]
    capacity_evidence_digest: String,
    #[serde(rename = "SecurityEpoch")]
    security_epoch: u64,
    #[serde(rename = "RestoreEpoch")]
    restore_epoch: u64,
    #[serde(rename = "Revision")]
    revision: u64,
    #[serde(rename = "Phase")]
    phase: String,
    #[serde(rename = "LastCheckpoint")]
    last_checkpoint: String,
    #[serde(rename = "AuthorityResetReceiptHash")]
    authority_reset_receipt_hash: String,
    #[serde(rename = "StartedAt", with = "wire::rfc3339")]
    started_at: OffsetDateTime,
    #[serde(rename = "UpdatedAt", with = "wire::rfc3339")]
    updated_at: OffsetDateTime,
    #[serde(
        rename = "ReadyAt",
        default = "wire::go_zero_time",
        with = "wire::rfc3339"
    )]
    ready_at: OffsetDateTime,
}

fn restore_phase_from_str(value: &str) -> Option<RestorePhase> {
    Some(match value {
        "applying" => RestorePhase::Applying,
        "verifying" => RestorePhase::Verifying,
        "quarantined" => RestorePhase::Quarantined,
        "ready" => RestorePhase::Ready,
        "abandoned" => RestorePhase::Abandoned,
        _ => return None,
    })
}

fn restore_checkpoint_from_str(value: &str) -> Option<RestoreCheckpoint> {
    Some(match value {
        "ticket_consumed" => RestoreCheckpoint::TicketConsumed,
        "database_replaced" => RestoreCheckpoint::DatabaseReplaced,
        "inventory_verified" => RestoreCheckpoint::InventoryVerified,
        "authority_reset" => RestoreCheckpoint::AuthorityReset,
        _ => return None,
    })
}

fn backup_phase_from_str(value: &str) -> Option<BackupPhase> {
    Some(match value {
        "planned" => BackupPhase::Planned,
        "admitted" => BackupPhase::Admitted,
        "dumping" => BackupPhase::Dumping,
        "inventory" => BackupPhase::Inventory,
        "sealing" => BackupPhase::Sealing,
        "sealed" => BackupPhase::Sealed,
        "failed" => BackupPhase::Failed,
        _ => return None,
    })
}

pub(crate) fn operation_to_wire(operation: &RestoreOperation) -> RestoreOperationWire {
    RestoreOperationWire {
        operation_id: operation.operation_id,
        ticket_id: operation.ticket_id,
        backup_id: operation.backup_id,
        target: target_to_wire(&operation.target),
        target_fingerprint: operation.target_fingerprint.clone(),
        manifest_digest: operation.manifest_digest.clone(),
        payload_epoch_id: operation.payload_epoch_id,
        database_schema_version: operation.database_schema_version.clone(),
        capacity_evidence_digest: operation.capacity_evidence_digest.clone(),
        security_epoch: operation.security_epoch,
        restore_epoch: operation.restore_epoch,
        revision: operation.revision,
        phase: operation.phase.as_str().to_owned(),
        last_checkpoint: operation.last_checkpoint.as_str().to_owned(),
        authority_reset_receipt_hash: operation.authority_reset_receipt_hash.clone(),
        started_at: operation.started_at,
        updated_at: operation.updated_at,
        ready_at: operation.ready_at,
    }
}

pub(crate) fn operation_from_wire(
    wire: &RestoreOperationWire,
) -> Result<RestoreOperation, Failure> {
    let (Some(phase), Some(last_checkpoint)) = (
        restore_phase_from_str(&wire.phase),
        restore_checkpoint_from_str(&wire.last_checkpoint),
    ) else {
        return Err(unavailable());
    };
    Ok(RestoreOperation {
        operation_id: wire.operation_id,
        ticket_id: wire.ticket_id,
        backup_id: wire.backup_id,
        target: target_from_wire(&wire.target),
        target_fingerprint: wire.target_fingerprint.clone(),
        manifest_digest: wire.manifest_digest.clone(),
        payload_epoch_id: wire.payload_epoch_id,
        database_schema_version: wire.database_schema_version.clone(),
        capacity_evidence_digest: wire.capacity_evidence_digest.clone(),
        security_epoch: wire.security_epoch,
        restore_epoch: wire.restore_epoch,
        revision: wire.revision,
        phase,
        last_checkpoint,
        authority_reset_receipt_hash: wire.authority_reset_receipt_hash.clone(),
        started_at: wire.started_at,
        updated_at: wire.updated_at,
        ready_at: wire.ready_at,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackupAcceptedFactsWire {
    #[serde(rename = "DatabaseTime", with = "wire::rfc3339")]
    database_time: OffsetDateTime,
    #[serde(rename = "TargetFingerprint")]
    target_fingerprint: String,
    #[serde(rename = "ConfigFingerprint")]
    config_fingerprint: String,
    /// `PayloadEpochID uuid.UUID \`json:"payload_epoch_id"\`` — the one
    /// tagged field in upstream's otherwise untagged struct.
    #[serde(rename = "payload_epoch_id")]
    payload_epoch_id: Uuid,
    #[serde(rename = "RepositoryBindingID")]
    repository_binding_id: Uuid,
    #[serde(rename = "TargetLockProtocol")]
    target_lock_protocol: String,
    #[serde(rename = "TargetLockProof")]
    target_lock_proof: String,
    #[serde(rename = "InventoryBoundary")]
    inventory_boundary: String,
    #[serde(rename = "DatabaseSchemaVersion")]
    database_schema_version: String,
    #[serde(rename = "ToolVersion")]
    tool_version: String,
    #[serde(rename = "ChecksumManifest")]
    checksum_manifest: String,
    #[serde(rename = "ServiceIdentity")]
    service_identity: String,
}

pub(crate) fn accepted_facts_to_wire(facts: &BackupAcceptedFacts) -> BackupAcceptedFactsWire {
    BackupAcceptedFactsWire {
        database_time: facts.database_time,
        target_fingerprint: facts.target_fingerprint.clone(),
        config_fingerprint: facts.config_fingerprint.clone(),
        payload_epoch_id: facts.payload_epoch_id,
        repository_binding_id: facts.repository_binding_id,
        target_lock_protocol: facts.target_lock_protocol.clone(),
        target_lock_proof: facts.target_lock_proof.clone(),
        inventory_boundary: facts.inventory_boundary.clone(),
        database_schema_version: facts.database_schema_version.clone(),
        tool_version: facts.tool_version.clone(),
        checksum_manifest: facts.checksum_manifest.clone(),
        service_identity: facts.service_identity.clone(),
    }
}

pub(crate) fn accepted_facts_from_wire(wire: &BackupAcceptedFactsWire) -> BackupAcceptedFacts {
    BackupAcceptedFacts {
        database_time: wire.database_time,
        target_fingerprint: wire.target_fingerprint.clone(),
        config_fingerprint: wire.config_fingerprint.clone(),
        payload_epoch_id: wire.payload_epoch_id,
        repository_binding_id: wire.repository_binding_id,
        target_lock_protocol: wire.target_lock_protocol.clone(),
        target_lock_proof: wire.target_lock_proof.clone(),
        inventory_boundary: wire.inventory_boundary.clone(),
        database_schema_version: wire.database_schema_version.clone(),
        tool_version: wire.tool_version.clone(),
        checksum_manifest: wire.checksum_manifest.clone(),
        service_identity: wire.service_identity.clone(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackupOperationWire {
    #[serde(rename = "OperationID")]
    operation_id: Uuid,
    #[serde(rename = "BackupID")]
    backup_id: Uuid,
    #[serde(rename = "Target")]
    target: TargetIdentityWire,
    #[serde(rename = "AcceptedFacts")]
    accepted_facts: BackupAcceptedFactsWire,
    #[serde(rename = "Revision")]
    revision: u64,
    #[serde(rename = "Phase")]
    phase: String,
    #[serde(rename = "FailureReason")]
    failure_reason: String,
    #[serde(rename = "CreatedAt", with = "wire::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(
        rename = "AcceptedAt",
        default = "wire::go_zero_time",
        with = "wire::rfc3339"
    )]
    accepted_at: OffsetDateTime,
    #[serde(rename = "UpdatedAt", with = "wire::rfc3339")]
    updated_at: OffsetDateTime,
}

pub(crate) fn backup_operation_to_wire(operation: &BackupOperation) -> BackupOperationWire {
    BackupOperationWire {
        operation_id: operation.operation_id,
        backup_id: operation.backup_id,
        target: target_to_wire(&operation.target),
        accepted_facts: accepted_facts_to_wire(&operation.accepted_facts),
        revision: operation.revision,
        phase: operation.phase.as_str().to_owned(),
        failure_reason: operation.failure_reason.clone(),
        created_at: operation.created_at,
        accepted_at: operation.accepted_at,
        updated_at: operation.updated_at,
    }
}

pub(crate) fn backup_operation_from_wire(
    wire: &BackupOperationWire,
) -> Result<BackupOperation, Failure> {
    let Some(phase) = backup_phase_from_str(&wire.phase) else {
        return Err(unavailable());
    };
    Ok(BackupOperation {
        operation_id: wire.operation_id,
        backup_id: wire.backup_id,
        target: target_from_wire(&wire.target),
        accepted_facts: accepted_facts_from_wire(&wire.accepted_facts),
        revision: wire.revision,
        phase,
        failure_reason: wire.failure_reason.clone(),
        created_at: wire.created_at,
        accepted_at: wire.accepted_at,
        updated_at: wire.updated_at,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackupSealProposalWire {
    #[serde(rename = "OperationID")]
    operation_id: Uuid,
    #[serde(rename = "BackupID")]
    backup_id: Uuid,
    #[serde(rename = "Target")]
    target: TargetIdentityWire,
    #[serde(rename = "AcceptedAt", with = "wire::rfc3339")]
    accepted_at: OffsetDateTime,
    #[serde(rename = "RepositoryBindingID")]
    repository_binding_id: Uuid,
    #[serde(rename = "TargetFingerprint")]
    target_fingerprint: String,
    #[serde(rename = "ConfigFingerprint")]
    config_fingerprint: String,
    /// `json:"payload_epoch_id"` — upstream's lone tag on
    /// `BackupSealProposal` (all other fields marshal PascalCase).
    #[serde(rename = "payload_epoch_id")]
    payload_epoch_id: Uuid,
    /// `RootManifestJSON []byte` — Go's `[]byte` base64 string.
    #[serde(rename = "RootManifestJSON", with = "wire::b64")]
    root_manifest_json: Vec<u8>,
    /// `[sha256.Size]byte` — Go marshals a fixed array as a JSON
    /// number array, not base64.
    #[serde(rename = "ManifestDigest", with = "wire::digest32")]
    manifest_digest: [u8; 32],
    #[serde(rename = "FileTreeDigest", with = "wire::digest32")]
    file_tree_digest: [u8; 32],
    #[serde(rename = "ProposedAt", with = "wire::rfc3339")]
    proposed_at: OffsetDateTime,
}

fn digest32(value: &[u8]) -> Result<[u8; 32], Failure> {
    <[u8; 32]>::try_from(value).map_err(|_| unavailable())
}

pub(crate) fn seal_proposal_to_wire(proposal: &BackupSealProposal) -> BackupSealProposalWire {
    BackupSealProposalWire {
        operation_id: proposal.operation_id,
        backup_id: proposal.backup_id,
        target: target_to_wire(&proposal.target),
        accepted_at: proposal.accepted_at,
        repository_binding_id: proposal.repository_binding_id,
        target_fingerprint: proposal.target_fingerprint.clone(),
        config_fingerprint: proposal.config_fingerprint.clone(),
        payload_epoch_id: proposal.payload_epoch_id,
        root_manifest_json: proposal.root_manifest_json.clone(),
        manifest_digest: proposal.manifest_digest,
        file_tree_digest: proposal.file_tree_digest,
        proposed_at: proposal.proposed_at,
    }
}

pub(crate) fn seal_proposal_from_wire(
    wire: &BackupSealProposalWire,
) -> Result<BackupSealProposal, Failure> {
    Ok(BackupSealProposal {
        operation_id: wire.operation_id,
        backup_id: wire.backup_id,
        target: target_from_wire(&wire.target),
        accepted_at: wire.accepted_at,
        repository_binding_id: wire.repository_binding_id,
        target_fingerprint: wire.target_fingerprint.clone(),
        config_fingerprint: wire.config_fingerprint.clone(),
        payload_epoch_id: wire.payload_epoch_id,
        root_manifest_json: wire.root_manifest_json.clone(),
        manifest_digest: wire.manifest_digest,
        file_tree_digest: wire.file_tree_digest,
        proposed_at: wire.proposed_at,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackupSealCompanionWire {
    #[serde(rename = "AuthorityEnvelopeID")]
    authority_envelope_id: String,
    #[serde(rename = "BackupID")]
    backup_id: Uuid,
    #[serde(rename = "OperationID")]
    operation_id: Uuid,
    #[serde(rename = "RepositoryBindingID")]
    repository_binding_id: Uuid,
    #[serde(rename = "TargetFingerprint")]
    target_fingerprint: String,
    #[serde(rename = "ConfigFingerprint")]
    config_fingerprint: String,
    #[serde(rename = "PayloadEpochID")]
    payload_epoch_id: Uuid,
    /// `[sha256.Size]byte` — JSON number array, not base64.
    #[serde(rename = "RootManifestDigest", with = "wire::digest32")]
    root_manifest_digest: [u8; 32],
    #[serde(rename = "FileTreeDigest", with = "wire::digest32")]
    file_tree_digest: [u8; 32],
    #[serde(rename = "SealedAt", with = "wire::rfc3339")]
    sealed_at: OffsetDateTime,
    #[serde(rename = "HMAC")]
    hmac: String,
    #[serde(rename = "Digest", with = "wire::digest32")]
    digest: [u8; 32],
}

pub(crate) fn seal_companion_to_wire(companion: &BackupSealCompanion) -> BackupSealCompanionWire {
    BackupSealCompanionWire {
        authority_envelope_id: companion.authority_envelope_id.clone(),
        backup_id: companion.backup_id,
        operation_id: companion.operation_id,
        repository_binding_id: companion.repository_binding_id,
        target_fingerprint: companion.target_fingerprint.clone(),
        config_fingerprint: companion.config_fingerprint.clone(),
        payload_epoch_id: companion.payload_epoch_id,
        root_manifest_digest: companion.root_manifest_digest,
        file_tree_digest: companion.file_tree_digest,
        sealed_at: companion.sealed_at,
        hmac: companion.hmac.clone(),
        digest: companion.digest,
    }
}

pub(crate) fn seal_companion_from_wire(
    wire: &BackupSealCompanionWire,
) -> Result<BackupSealCompanion, Failure> {
    Ok(BackupSealCompanion {
        authority_envelope_id: wire.authority_envelope_id.clone(),
        backup_id: wire.backup_id,
        operation_id: wire.operation_id,
        repository_binding_id: wire.repository_binding_id,
        target_fingerprint: wire.target_fingerprint.clone(),
        config_fingerprint: wire.config_fingerprint.clone(),
        payload_epoch_id: wire.payload_epoch_id,
        root_manifest_digest: wire.root_manifest_digest,
        file_tree_digest: wire.file_tree_digest,
        sealed_at: wire.sealed_at,
        hmac: wire.hmac.clone(),
        digest: wire.digest,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackupRepositoryAttestationJournalWire {
    #[serde(rename = "LaunchEvidenceID")]
    launch_evidence_id: Uuid,
    #[serde(rename = "OperationID")]
    operation_id: Uuid,
    #[serde(rename = "BackupID")]
    backup_id: Uuid,
    #[serde(rename = "RepositoryBindingID")]
    repository_binding_id: Uuid,
    /// `[sha256.Size]byte` — JSON number arrays, not base64.
    #[serde(rename = "RootManifestDigest", with = "wire::digest32")]
    root_manifest_digest: [u8; 32],
    #[serde(rename = "SealCompanionDigest", with = "wire::digest32")]
    seal_companion_digest: [u8; 32],
    #[serde(rename = "FileTreeDigest", with = "wire::digest32")]
    file_tree_digest: [u8; 32],
    #[serde(rename = "RepositoryManifestDigest", with = "wire::digest32")]
    repository_manifest_digest: [u8; 32],
    #[serde(rename = "RepositoryRevision")]
    repository_revision: u64,
    #[serde(rename = "AttestedAt", with = "wire::rfc3339")]
    attested_at: OffsetDateTime,
    #[serde(rename = "ImmutableDigest", with = "wire::digest32")]
    immutable_digest: [u8; 32],
}

impl Default for BackupRepositoryAttestationJournalWire {
    fn default() -> Self {
        Self {
            launch_evidence_id: Uuid::nil(),
            operation_id: Uuid::nil(),
            backup_id: Uuid::nil(),
            repository_binding_id: Uuid::nil(),
            root_manifest_digest: [0u8; 32],
            seal_companion_digest: [0u8; 32],
            file_tree_digest: [0u8; 32],
            repository_manifest_digest: [0u8; 32],
            repository_revision: 0,
            attested_at: wire::go_zero_time(),
            immutable_digest: [0u8; 32],
        }
    }
}

pub(crate) fn attestation_to_wire(
    attestation: &Option<BackupRepositoryAttestation>,
) -> BackupRepositoryAttestationJournalWire {
    match attestation {
        Some(a) => BackupRepositoryAttestationJournalWire {
            launch_evidence_id: a.launch_evidence_id,
            operation_id: a.operation_id,
            backup_id: a.backup_id,
            repository_binding_id: a.repository_binding_id,
            root_manifest_digest: a.root_manifest_digest,
            seal_companion_digest: a.seal_companion_digest,
            file_tree_digest: a.file_tree_digest,
            repository_manifest_digest: a.repository_manifest_digest,
            repository_revision: a.repository_revision,
            attested_at: a.attested_at,
            immutable_digest: a.immutable_digest,
        },
        None => BackupRepositoryAttestationJournalWire::default(),
    }
}

pub(crate) fn attestation_from_wire(
    wire: &BackupRepositoryAttestationJournalWire,
) -> Result<Option<BackupRepositoryAttestation>, Failure> {
    if wire.launch_evidence_id.is_nil()
        && wire.operation_id.is_nil()
        && wire.backup_id.is_nil()
        && wire.repository_binding_id.is_nil()
        && wire.root_manifest_digest == [0u8; 32]
        && wire.seal_companion_digest == [0u8; 32]
        && wire.file_tree_digest == [0u8; 32]
        && wire.repository_manifest_digest == [0u8; 32]
        && wire.repository_revision == 0
        && wire::is_go_zero_time(wire.attested_at)
        && wire.immutable_digest == [0u8; 32]
    {
        return Ok(None);
    }
    Ok(Some(BackupRepositoryAttestation {
        launch_evidence_id: wire.launch_evidence_id,
        operation_id: wire.operation_id,
        backup_id: wire.backup_id,
        repository_binding_id: wire.repository_binding_id,
        root_manifest_digest: wire.root_manifest_digest,
        seal_companion_digest: wire.seal_companion_digest,
        file_tree_digest: wire.file_tree_digest,
        repository_manifest_digest: wire.repository_manifest_digest,
        repository_revision: wire.repository_revision,
        attested_at: wire.attested_at,
        immutable_digest: wire.immutable_digest,
    }))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackupTargetLockJournalWire {
    #[serde(rename = "SupervisorLaunchID")]
    supervisor_launch_id: Uuid,
    #[serde(rename = "LaunchEvidenceID")]
    launch_evidence_id: Uuid,
    #[serde(rename = "OperationID")]
    operation_id: Uuid,
    #[serde(rename = "BackupID")]
    backup_id: Uuid,
    /// `TargetLockProof string` — upstream carries the proof as a
    /// string here; only `ImmutableDigest` is a `[32]byte` array.
    #[serde(rename = "TargetLockProof")]
    target_lock_proof: String,
    #[serde(rename = "AssertedAt", with = "wire::rfc3339")]
    asserted_at: OffsetDateTime,
    #[serde(rename = "ImmutableDigest", with = "wire::digest32")]
    immutable_digest: [u8; 32],
}

impl Default for BackupTargetLockJournalWire {
    fn default() -> Self {
        Self {
            supervisor_launch_id: Uuid::nil(),
            launch_evidence_id: Uuid::nil(),
            operation_id: Uuid::nil(),
            backup_id: Uuid::nil(),
            target_lock_proof: String::new(),
            asserted_at: wire::go_zero_time(),
            immutable_digest: [0u8; 32],
        }
    }
}

pub(crate) fn target_lock_to_wire(
    attestation: &Option<BackupTargetLockAttestation>,
) -> BackupTargetLockJournalWire {
    match attestation {
        Some(a) => BackupTargetLockJournalWire {
            supervisor_launch_id: a.supervisor_launch_id,
            launch_evidence_id: a.launch_evidence_id,
            operation_id: a.operation_id,
            backup_id: a.backup_id,
            target_lock_proof: a.target_lock_proof.clone(),
            asserted_at: a.asserted_at,
            immutable_digest: a.immutable_digest,
        },
        None => BackupTargetLockJournalWire::default(),
    }
}

pub(crate) fn target_lock_from_wire(
    wire: &BackupTargetLockJournalWire,
) -> Result<Option<BackupTargetLockAttestation>, Failure> {
    if wire.supervisor_launch_id.is_nil()
        && wire.launch_evidence_id.is_nil()
        && wire.operation_id.is_nil()
        && wire.backup_id.is_nil()
        && wire.target_lock_proof.is_empty()
        && wire::is_go_zero_time(wire.asserted_at)
        && wire.immutable_digest == [0u8; 32]
    {
        return Ok(None);
    }
    Ok(Some(BackupTargetLockAttestation {
        supervisor_launch_id: wire.supervisor_launch_id,
        launch_evidence_id: wire.launch_evidence_id,
        operation_id: wire.operation_id,
        backup_id: wire.backup_id,
        target_lock_proof: wire.target_lock_proof.clone(),
        asserted_at: wire.asserted_at,
        immutable_digest: wire.immutable_digest,
    }))
}

// ---------------------------------------------------------------------------
// Journal record shapes — the snake_case record envelopes upstream
// defines beside the domain payloads.
// ---------------------------------------------------------------------------

/// `restoreTicketRecord` — ticket plus consumption state and the
/// issuing launch it was minted under.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RestoreTicketRecordWire {
    pub(crate) ticket: RestoreTicketWire,
    pub(crate) state: String,
    // Go's `,omitempty` on a `uuid.UUID` (a `[16]byte`) never omits —
    // the nil UUID serializes, so this field is always present.
    #[serde(default)]
    pub(crate) launch_evidence_id: Uuid,
    #[serde(with = "wire::rfc3339")]
    pub(crate) issued_at: OffsetDateTime,
}

/// `restoreTicketLaunchRecord` — the operation-keyed carry of the
/// issuing launch. Create-only and never rewritten: Issue mints both
/// ids, so a collision is a broken store rather than a retry, and
/// Begin re-reads it to refuse a ticket whose carry disagrees.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RestoreTicketLaunchRecordWire {
    pub(crate) schema_version: String,
    pub(crate) operation_id: Uuid,
    pub(crate) ticket_id: Uuid,
    #[serde(default)]
    pub(crate) launch_evidence_id: Uuid,
    #[serde(with = "wire::rfc3339")]
    pub(crate) issued_at: OffsetDateTime,
    #[serde(with = "wire::rfc3339")]
    pub(crate) expires_at: OffsetDateTime,
    pub(crate) hmac: String,
}

impl RestoreTicketLaunchRecordWire {
    fn valid(&self) -> bool {
        self.schema_version == RESTORE_TICKET_LAUNCH_RECORD_SCHEMA
            && !self.operation_id.is_nil()
            && self.operation_id.get_version_num() == 7
            && !self.ticket_id.is_nil()
            && self.ticket_id.get_version_num() == 7
            && !wire::is_go_zero_time(self.issued_at)
            && !wire::is_go_zero_time(self.expires_at)
            && self.expires_at > self.issued_at
    }
}

fn ticket_launch_payload(record: &RestoreTicketLaunchRecordWire) -> Result<Vec<u8>, Failure> {
    if !record.valid() {
        return Err(unavailable());
    }
    let mut unsigned = record.clone();
    unsigned.hmac = String::new();
    serde_json::to_vec(&unsigned).map_err(|_| unavailable())
}

/// `restoreApplyRecord` — the protected proof that the helper
/// completed a fresh PAM plus physical-console ceremony for one exact
/// ticket. Never carries a credential or target locator.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreApplyRecordWire {
    authorization: RestoreApplyAuthorizationWire,
    state: String,
    peer_uid: u32,
    peer_pid: i32,
}

/// `restoreAbandonRecord` — the protected proof of the abandonment
/// ceremony for one exact protected operation; names no ticket.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreAbandonRecordWire {
    authorization: RestoreAbandonAuthorizationWire,
    state: String,
    peer_uid: u32,
    peer_pid: i32,
}

/// `recoveryMinioReceiptRecord`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryMinioReceiptRecordWire {
    receipt: RecoveryMinioHandoffReceipt,
    state: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    generation_id: String,
}

/// `recoveryMinioOperationBinding` — the credential-free index from
/// one recovery operation and purpose to its opaque provision receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryMinioOperationBindingWire {
    operation_id: String,
    purpose: String,
    receipt_id: String,
}

/// `backupSealRecord` — domain-side shape. `attestation`/`target_lock`
/// `None` ⇔ the Go zero struct (`committed`); `completed_at` `None` ⇔
/// Go's zero `time.Time`.
#[derive(Debug, Clone)]
pub(crate) struct BackupSealRecord {
    pub(crate) proposal: BackupSealProposal,
    companion: BackupSealCompanion,
    state: String,
    attestation: Option<BackupRepositoryAttestation>,
    target_lock: Option<BackupTargetLockAttestation>,
    completed_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupSealRecordWire {
    proposal: BackupSealProposalWire,
    companion: BackupSealCompanionWire,
    state: String,
    // Go's `,omitempty`-less struct fields always serialize — a
    // committed seal carries the zero attestation shape on disk.
    attestation: BackupRepositoryAttestationJournalWire,
    target_lock_attestation: BackupTargetLockJournalWire,
    #[serde(with = "wire::rfc3339")]
    completed_at: OffsetDateTime,
}

fn seal_record_to_wire(record: &BackupSealRecord) -> Result<BackupSealRecordWire, Failure> {
    Ok(BackupSealRecordWire {
        proposal: seal_proposal_to_wire(&record.proposal),
        companion: seal_companion_to_wire(&record.companion),
        state: record.state.clone(),
        attestation: attestation_to_wire(&record.attestation),
        target_lock_attestation: target_lock_to_wire(&record.target_lock),
        completed_at: record.completed_at.unwrap_or_else(wire::go_zero_time),
    })
}

fn seal_record_from_wire(wire: &BackupSealRecordWire) -> Result<BackupSealRecord, Failure> {
    Ok(BackupSealRecord {
        proposal: seal_proposal_from_wire(&wire.proposal)?,
        companion: seal_companion_from_wire(&wire.companion)?,
        state: wire.state.clone(),
        attestation: attestation_from_wire(&wire.attestation)?,
        target_lock: target_lock_from_wire(&wire.target_lock_attestation)?,
        completed_at: if wire::is_go_zero_time(wire.completed_at) {
            None
        } else {
            Some(wire.completed_at)
        },
    })
}

/// `recoveryBootstrapActivationRecord`.
#[allow(dead_code)] // slice-(b) broker-reset surface
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryBootstrapActivationRecord {
    pub generation: u64,
    pub database_receipt_hash: String,
    pub activation_receipt_hash: String,
    #[serde(with = "wire::rfc3339")]
    pub activated_at: OffsetDateTime,
    #[serde(default = "wire::go_zero_time", with = "wire::rfc3339")]
    pub presented_at: OffsetDateTime,
}

/// `recoveryBrokerResetRecord` — the protected commit point for the
/// broker half of C05. Only opaque identities and fingerprints;
/// private TLS keys and bootstrap material stay in their own stores.
#[allow(dead_code)] // slice-(b) broker-reset surface
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryBrokerResetRecord {
    pub operation_id: Uuid,
    pub ticket_id: Uuid,
    pub backup_id: Uuid,
    pub target_fingerprint: String,
    pub manifest_digest: String,
    pub restore_epoch: u64,
    pub security_epoch: u64,
    pub prepared_revision: u64,
    #[serde(with = "wire::rfc3339")]
    pub prepared_updated_at: OffsetDateTime,
    pub ca_fingerprint: String,
    pub leaf_fingerprint: String,
    pub draft_id: Uuid,
    pub candidate_id: Uuid,
    pub verifier_hash: String,
    pub candidate_digest: String,
    pub protected_generation_id: Uuid,
    pub receipt_hash: String,
    #[serde(with = "wire::rfc3339")]
    pub committed_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation: Option<RecoveryBootstrapActivationRecord>,
    #[serde(default = "wire::go_zero_time", with = "wire::rfc3339")]
    pub draft_released_at: OffsetDateTime,
    pub hmac: String,
}

impl RecoveryBrokerResetRecord {
    /// `record.draft()` — decode the base64url-raw hashes back into the
    /// domain draft the service layer returns.
    #[allow(dead_code)]
    pub(crate) fn draft(&self) -> Result<RecoveryBootstrapDraft, Failure> {
        let verifier = decode_recovery_hash(&self.verifier_hash)?;
        let digest = decode_recovery_hash(&self.candidate_digest)?;
        Ok(RecoveryBootstrapDraft {
            operation_id: self.operation_id,
            draft_id: self.draft_id,
            candidate_id: self.candidate_id,
            verifier_hash: verifier,
            candidate_digest: digest,
            broker_receipt_hash: self.receipt_hash.clone(),
            created_at: self.committed_at,
        })
    }
}

/// `decodeRecoveryHash` — base64-RawStd 32-byte nonzero hash.
pub(crate) fn decode_recovery_hash(value: &str) -> Result<[u8; 32], Failure> {
    let decoded = wire::b64_raw_decode(value).ok_or_else(unavailable)?;
    let out = digest32(&decoded)?;
    if out == [0u8; 32] {
        return Err(unavailable());
    }
    Ok(out)
}

/// `brokerResetRecordPayload` — the canonical HMAC input: the record
/// with its own HMAC field cleared.
#[allow(dead_code)]
fn broker_reset_record_payload(record: &RecoveryBrokerResetRecord) -> Result<Vec<u8>, Failure> {
    let mut unsigned = record.clone();
    unsigned.hmac = String::new();
    serde_json::to_vec(&unsigned).map_err(|_| unavailable())
}

/// `sameBrokerResetOperation` — authenticates a live caller-supplied
/// operation against the record's prepared revision and updated_at.
#[allow(dead_code)]
fn same_broker_reset_operation(
    record: &RecoveryBrokerResetRecord,
    operation: &RestoreOperation,
) -> bool {
    let mut security_matches = record.security_epoch == operation.security_epoch;
    let mut revision_matches = record.prepared_revision == operation.revision
        && record.prepared_updated_at == operation.updated_at;
    if operation.last_checkpoint == RestoreCheckpoint::AuthorityReset
        && record.security_epoch != u64::MAX
    {
        security_matches = operation.security_epoch == record.security_epoch + 1;
        revision_matches = (operation.phase == RestorePhase::Verifying
            && operation.revision == record.prepared_revision + 1)
            || (operation.phase == RestorePhase::Ready
                && operation.revision == record.prepared_revision + 2);
    }
    record.operation_id == operation.operation_id
        && record.ticket_id == operation.ticket_id
        && record.backup_id == operation.backup_id
        && record.target_fingerprint == operation.target_fingerprint
        && record.manifest_digest == operation.manifest_digest
        && record.restore_epoch == operation.restore_epoch
        && security_matches
        && revision_matches
}

/// `readPrivateJSON` — lstat + private-file validation + bounded
/// strict decode (`DisallowUnknownFields`, one JSON value, then EOF).
pub(crate) fn read_private_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, Failure> {
    let meta = durable::lstat(path).map_err(|_| unavailable())?;
    durable::validate_private_file(&meta, "recovery journal record").map_err(|_| unavailable())?;
    let file = durable::open_read(path).map_err(|_| unavailable())?;
    let mut limited = file.take(READ_PRIVATE_JSON_LIMIT + 1);
    let mut buf = Vec::new();
    limited.read_to_end(&mut buf).map_err(|_| unavailable())?;
    if buf.len() as u64 > READ_PRIVATE_JSON_LIMIT {
        return Err(unavailable());
    }
    let mut de = serde_json::Deserializer::from_slice(&buf);
    let value = T::deserialize(&mut de).map_err(|_| unavailable())?;
    // `decoder.Decode(&extra) == io.EOF` upstream: only whitespace may
    // follow the single value.
    de.end().map_err(|_| unavailable())?;
    Ok(value)
}

/// `generationKey` — `sha256` hex of the caller-facing identity so a
/// caller-supplied string can never steer the path this store writes.
pub(crate) fn generation_key(identity: &str) -> String {
    wire::sha256_hex(identity.as_bytes())
}

/// `validRecoveryOperationLockName` — `<64 lowercase hex>.json.lock`.
fn valid_recovery_operation_lock_name(name: &str) -> bool {
    const SUFFIX: &str = ".json.lock";
    let Some(stem) = name.strip_suffix(SUFFIX) else {
        return false;
    };
    stem.len() == 64
        && stem
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_recovery_minio_purpose(purpose: Purpose) -> bool {
    matches!(
        purpose,
        Purpose::MinioBackup | Purpose::MinioRestore | Purpose::MinioImport
    )
}

fn valid_recovery_facts(facts: &RestoreAdmissionFacts) -> bool {
    facts.target.is_valid()
        && !facts.target_fingerprint.is_empty()
        && !facts.config_fingerprint.is_empty()
        && !facts.payload_epoch_id.is_nil()
        && facts.payload_epoch_id.get_version_num() == 7
        && facts.database_schema_version
            == central_backup::backup::operation::BACKUP_DATABASE_SCHEMA_VERSION
        && wire::valid_prefixed_sha256(&facts.capacity_evidence_digest)
        && facts.tool_version == "pg_restore-16.14"
}

fn valid_recovery_minio_request(request: &RecoveryMinioHandoffRequest) -> bool {
    if request.operation_id.is_empty()
        || request.instance_id.is_empty()
        || request.bucket != ARTIFACTS_BUCKET
        || request.fence_token == 0
        || wire::is_go_zero_time(request.expires_at)
        || OffsetDateTime::now_utc() >= request.expires_at
    {
        return false;
    }
    let Ok(purpose) = request.purpose.parse::<Purpose>() else {
        return false;
    };
    let Ok(scope) = minio_recovery_key_scope(purpose) else {
        return false;
    };
    if request.key_prefix != scope {
        return false;
    }
    let Ok(digest) = minio_recovery_policy_digest(purpose, &request.bucket) else {
        return false;
    };
    request.policy_digest == digest
}

fn valid_recovery_minio_descriptor(
    descriptor: &MinioProvisionedDescriptor,
    now: OffsetDateTime,
) -> bool {
    if descriptor.service != "minio-provision"
        || descriptor.target != "sealed_memfd"
        || descriptor.uid != MINIO_PROVISIONER_UID
        || descriptor.gid != MINIO_PROVISIONER_GID
        || descriptor.receipt_id.is_empty()
        || descriptor.operation_id.is_empty()
        || descriptor.instance_id.is_empty()
        || descriptor.bucket != ARTIFACTS_BUCKET
        || descriptor.fence_token == 0
        || wire::is_go_zero_time(descriptor.expires_at)
        || now >= descriptor.expires_at
    {
        return false;
    }
    let Ok(purpose) = descriptor.purpose.parse::<Purpose>() else {
        return false;
    };
    let Ok(scope) = minio_recovery_key_scope(purpose) else {
        return false;
    };
    if descriptor.key_prefix != scope {
        return false;
    }
    let Ok(digest) = minio_recovery_policy_digest(purpose, &descriptor.bucket) else {
        return false;
    };
    descriptor.policy_digest == digest
}

fn same_recovery_minio_binding(
    receipt: &RecoveryMinioHandoffReceipt,
    descriptor: &MinioProvisionedDescriptor,
) -> bool {
    receipt.receipt_id == descriptor.receipt_id
        && receipt.operation_id == descriptor.operation_id
        && receipt.instance_id == descriptor.instance_id
        && receipt.purpose == descriptor.purpose
        && receipt.bucket == descriptor.bucket
        && receipt.key_prefix == descriptor.key_prefix
        && receipt.policy_digest == descriptor.policy_digest
        && receipt.fence_token == descriptor.fence_token
        && receipt.expires_at == descriptor.expires_at
}

fn same_recovery_minio_request(
    request: &RecoveryMinioHandoffRequest,
    receipt: &RecoveryMinioHandoffReceipt,
) -> bool {
    request.operation_id == receipt.operation_id
        && request.instance_id == receipt.instance_id
        && request.purpose == receipt.purpose
        && request.bucket == receipt.bucket
        && request.key_prefix == receipt.key_prefix
        && request.policy_digest == receipt.policy_digest
        && request.fence_token == receipt.fence_token
        && request.expires_at.to_offset(time::UtcOffset::UTC) == receipt.expires_at
}

fn same_ticket(left: &RestoreTicket, right: &RestoreTicket) -> bool {
    left.ticket_id == right.ticket_id
        && left.operation_id == right.operation_id
        && left.backup_id == right.backup_id
        && left.target == right.target
        && left.target_fingerprint == right.target_fingerprint
        && left.manifest_digest == right.manifest_digest
        && left.security_epoch == right.security_epoch
        && left.restore_epoch == right.restore_epoch
        && left.config_fingerprint == right.config_fingerprint
        && left.payload_epoch_id == right.payload_epoch_id
        && left.database_schema_version == right.database_schema_version
        && left.capacity_evidence_digest == right.capacity_evidence_digest
        && left.tool_version == right.tool_version
        && left.issued_at == right.issued_at
        && left.expires_at == right.expires_at
        && wire::hmac_equal(&left.hidden_nonce, &right.hidden_nonce)
        && wire::hmac_equal(left.hmac.as_bytes(), right.hmac.as_bytes())
}

fn same_backup_seal_operation(operation: &BackupOperation, proposal: &BackupSealProposal) -> bool {
    operation.operation_id == proposal.operation_id
        && operation.backup_id == proposal.backup_id
        && operation.target == proposal.target
        && operation.accepted_at == proposal.accepted_at
        && operation.accepted_facts.repository_binding_id == proposal.repository_binding_id
        && operation.accepted_facts.target_fingerprint == proposal.target_fingerprint
        && operation.accepted_facts.config_fingerprint == proposal.config_fingerprint
        && operation.accepted_facts.payload_epoch_id == proposal.payload_epoch_id
}

fn same_backup_seal_proposal(left: &BackupSealProposal, right: &BackupSealProposal) -> bool {
    left.operation_id == right.operation_id
        && left.backup_id == right.backup_id
        && left.target == right.target
        && left.accepted_at == right.accepted_at
        && left.repository_binding_id == right.repository_binding_id
        && left.target_fingerprint == right.target_fingerprint
        && left.config_fingerprint == right.config_fingerprint
        && left.payload_epoch_id == right.payload_epoch_id
        && left.root_manifest_json == right.root_manifest_json
        && left.manifest_digest == right.manifest_digest
        && left.file_tree_digest == right.file_tree_digest
        && left.proposed_at == right.proposed_at
}

// ---------------------------------------------------------------------------
// RecoveryJournalStore — `recoveryJournalStore`.
// ---------------------------------------------------------------------------

/// The protected source of truth for C03/C04 (and the C01/C05 broker
/// state this file also owns). Every mutating path serializes through
/// per-record `.lock` files acquired with blocking exclusive `flock`.
pub struct RecoveryJournalStore {
    tickets: PathBuf,
    /// `ticketLaunches` — the operation → issuing-launch index.
    ticket_launches: PathBuf,
    apply: PathBuf,
    abandons: PathBuf,
    operations: PathBuf,
    backups: PathBuf,
    handoffs: PathBuf,
    #[allow(dead_code)] // read only by the slice-(b) broker-reset path
    resets: PathBuf,
    seals: PathBuf,
    signing: Arc<SigningService>,
    backend: ProtectedFileBackend,
}

impl RecoveryJournalStore {
    /// `newRecoveryJournalStore` — create and validate every private
    /// record root.
    pub fn new(
        root: &Path,
        signing: Arc<SigningService>,
        backend: ProtectedFileBackend,
    ) -> Result<Self, Failure> {
        let tickets = root.join(RECOVERY_TICKET_DIRECTORY);
        let ticket_launches = root.join(RECOVERY_TICKET_LAUNCH_DIRECTORY);
        let apply = root.join(RECOVERY_APPLY_DIRECTORY);
        let abandons = root.join(RECOVERY_ABANDON_DIRECTORY);
        let operations = root.join(RECOVERY_OPERATION_DIRECTORY);
        let backups = root.join(BACKUP_OPERATION_DIRECTORY);
        let handoffs = root.join(RECOVERY_MINIO_RECEIPT_DIR);
        let resets = root.join(RECOVERY_BROKER_RESET_DIR);
        let seals = root.join(BACKUP_SEAL_DIRECTORY);
        for (path, name) in [
            (&tickets, "recovery ticket root"),
            (&ticket_launches, "recovery ticket launch root"),
            (&apply, "recovery apply authorization root"),
            (&abandons, "recovery abandon authorization root"),
            (&operations, "recovery operation root"),
            (&backups, "recovery backup operation root"),
            (&handoffs, "recovery MinIO receipt root"),
            (&resets, "recovery broker reset root"),
            (&seals, "backup seal root"),
        ] {
            durable::mkdir_p(path, durable::PRIVATE_DIRECTORY_MODE).map_err(|e| {
                Failure::internal(
                    JOURNAL_UNAVAILABLE_CODE,
                    format!("broker: create {name}: {e}"),
                )
            })?;
            durable::validate_private_directory(path, name)?;
        }
        Ok(Self {
            tickets,
            ticket_launches,
            apply,
            abandons,
            operations,
            backups,
            handoffs,
            resets,
            seals,
            signing,
            backend,
        })
    }

    // -- paths ---------------------------------------------------------------

    fn ticket_path(&self, ticket_id: Uuid) -> PathBuf {
        self.tickets
            .join(format!("{}.json", generation_key(&ticket_id.to_string())))
    }

    fn ticket_launch_path(&self, operation_id: Uuid) -> PathBuf {
        self.ticket_launches.join(format!(
            "{}.json",
            generation_key(&operation_id.to_string())
        ))
    }

    fn apply_path(&self, authorization_id: Uuid) -> PathBuf {
        self.apply.join(format!(
            "{}.json",
            generation_key(&authorization_id.to_string())
        ))
    }

    fn abandon_path(&self, authorization_id: Uuid) -> PathBuf {
        self.abandons.join(format!(
            "{}.json",
            generation_key(&authorization_id.to_string())
        ))
    }

    pub(crate) fn operation_path(&self, operation_id: Uuid) -> PathBuf {
        self.operations.join(format!(
            "{}.json",
            generation_key(&operation_id.to_string())
        ))
    }

    pub(crate) fn restore_barrier_lock_path(&self) -> PathBuf {
        self.operations.join(".barrier")
    }

    fn backup_path(&self, operation_id: Uuid) -> PathBuf {
        self.backups.join(format!(
            "{}.json",
            generation_key(&operation_id.to_string())
        ))
    }

    fn handoff_path(&self, receipt_id: &str) -> PathBuf {
        self.handoffs
            .join(format!("{}.json", generation_key(receipt_id)))
    }

    fn handoff_operation_path(&self, operation_id: &str, purpose: &str) -> PathBuf {
        self.handoffs.join(format!(
            "{}.json",
            generation_key(&format!("operation\x00{operation_id}\x00{purpose}"))
        ))
    }

    fn seal_path(&self, backup_id: Uuid) -> PathBuf {
        self.seals
            .join(format!("{}.json", generation_key(&backup_id.to_string())))
    }

    #[allow(dead_code)] // slice-(b)/(c) authority surface
    pub(crate) fn broker_reset_path(&self, operation_id: Uuid) -> PathBuf {
        self.resets.join(format!(
            "{}.json",
            generation_key(&operation_id.to_string())
        ))
    }

    /// `s.openLock(recordPath)` — `<record>.lock`, blocking exclusive
    /// `flock` on a private `0600` file.
    pub(crate) fn open_lock(&self, record_path: &Path) -> Result<OwnedFd, Failure> {
        let lock_path = {
            let mut os = record_path.as_os_str().to_os_string();
            os.push(".lock");
            PathBuf::from(os)
        };
        durable::open_lock(&lock_path).map_err(|_| unavailable())
    }

    /// `s.writeExclusiveJSON` — create-only `O_EXCL` publication.
    pub(crate) fn write_exclusive_json<T: Serialize>(
        &self,
        path: &Path,
        value: &T,
    ) -> Result<(), Failure> {
        durable::write_exclusive_json(path, value).map_err(|_| unavailable())
    }

    /// `s.replaceJSON` — fsync'd temp + atomic rename + dir sync.
    pub(crate) fn replace_json<T: Serialize>(&self, path: &Path, value: &T) -> Result<(), Failure> {
        durable::replace_json(path, value).map_err(|_| unavailable())
    }

    // -- broker reset record --------------------------------------------------

    /// `newBrokerResetRecord` — the broker half of the C05 commit,
    /// built only for a `verifying`/`inventory_verified` operation.
    #[allow(clippy::too_many_arguments)]
    #[allow(dead_code)] // slice-(b)/(c) authority surface
    pub(crate) fn new_broker_reset_record(
        &self,
        operation: &RestoreOperation,
        ca_fingerprint: &str,
        leaf_fingerprint: &str,
        draft_id: Uuid,
        candidate_id: Uuid,
        protected_generation_id: Uuid,
        verifier_hash: [u8; 32],
        candidate_digest: [u8; 32],
        committed_at: OffsetDateTime,
    ) -> Result<RecoveryBrokerResetRecord, Failure> {
        if operation.validate().is_err()
            || operation.phase != RestorePhase::Verifying
            || operation.last_checkpoint != RestoreCheckpoint::InventoryVerified
            || !wire::valid_sha256_hex(ca_fingerprint)
            || !wire::valid_sha256_hex(leaf_fingerprint)
            || draft_id.is_nil()
            || candidate_id.is_nil()
            || protected_generation_id.is_nil()
            || verifier_hash == [0u8; 32]
            || candidate_digest == [0u8; 32]
            || wire::is_go_zero_time(committed_at)
            || committed_at < operation.updated_at
        {
            return Err(unavailable());
        }
        let mut record = RecoveryBrokerResetRecord {
            operation_id: operation.operation_id,
            ticket_id: operation.ticket_id,
            backup_id: operation.backup_id,
            target_fingerprint: operation.target_fingerprint.clone(),
            manifest_digest: operation.manifest_digest.clone(),
            restore_epoch: operation.restore_epoch,
            security_epoch: operation.security_epoch,
            prepared_revision: operation.revision,
            prepared_updated_at: operation.updated_at,
            ca_fingerprint: ca_fingerprint.to_owned(),
            leaf_fingerprint: leaf_fingerprint.to_owned(),
            committed_at: committed_at.to_offset(time::UtcOffset::UTC),
            draft_id,
            candidate_id,
            protected_generation_id,
            verifier_hash: wire::b64_raw_encode(&verifier_hash),
            candidate_digest: wire::b64_raw_encode(&candidate_digest),
            receipt_hash: String::new(),
            activation: None,
            draft_released_at: wire::go_zero_time(),
            hmac: String::new(),
        };
        #[derive(Serialize)]
        struct ReceiptPayload<'a> {
            operation_id: Uuid,
            target_fingerprint: &'a str,
            manifest_digest: &'a str,
            restore_epoch: u64,
            security_epoch: u64,
            ca_fingerprint: &'a str,
            leaf_fingerprint: &'a str,
            draft_id: Uuid,
            candidate_id: Uuid,
            verifier_hash: &'a str,
            candidate_digest: &'a str,
        }
        let receipt_payload = serde_json::to_vec(&ReceiptPayload {
            operation_id: record.operation_id,
            target_fingerprint: &record.target_fingerprint,
            manifest_digest: &record.manifest_digest,
            restore_epoch: record.restore_epoch,
            security_epoch: record.security_epoch,
            ca_fingerprint: &record.ca_fingerprint,
            leaf_fingerprint: &record.leaf_fingerprint,
            draft_id: record.draft_id,
            candidate_id: record.candidate_id,
            verifier_hash: &record.verifier_hash,
            candidate_digest: &record.candidate_digest,
        })
        .map_err(|_| unavailable())?;
        record.receipt_hash = format!(
            "sha256:{}",
            self.signing
                .fingerprint(BROKER_RESET_RECEIPT_HMAC_DOMAIN, &receipt_payload)
        );
        self.sign_broker_reset_record(&mut record)?;
        Ok(record)
    }

    /// `signBrokerResetRecord` — HMAC over the canonical payload.
    #[allow(dead_code)] // slice-(b)/(c) authority surface
    pub(crate) fn sign_broker_reset_record(
        &self,
        record: &mut RecoveryBrokerResetRecord,
    ) -> Result<(), Failure> {
        let canonical = broker_reset_record_payload(record)?;
        record.hmac = self
            .signing
            .fingerprint(BROKER_RESET_HMAC_DOMAIN, &canonical);
        Ok(())
    }

    /// `readBrokerReset` — `(record, found)`; the record must match
    /// the live operation and verify under its own HMAC.
    #[allow(dead_code)] // slice-(b)/(c) authority surface
    pub(crate) fn read_broker_reset(
        &self,
        operation: &RestoreOperation,
    ) -> Result<(RecoveryBrokerResetRecord, bool), Failure> {
        if operation.validate().is_err()
            || durable::validate_private_directory(&self.resets, "recovery broker reset root")
                .is_err()
        {
            return Err(unavailable());
        }
        let path = self.broker_reset_path(operation.operation_id);
        match durable::lstat(&path) {
            Err(e) if e == rustix::io::Errno::NOENT => return Ok((empty_reset_record(), false)),
            Err(_) => return Err(unavailable()),
            Ok(_) => {}
        }
        let record: RecoveryBrokerResetRecord = read_private_json(&path)?;
        if !same_broker_reset_operation(&record, operation)
            || !wire::valid_sha256_hex(&record.ca_fingerprint)
            || !wire::valid_sha256_hex(&record.leaf_fingerprint)
            || record.draft_id.is_nil()
            || record.candidate_id.is_nil()
            || record.protected_generation_id.is_nil()
            || record.prepared_revision == 0
            || wire::is_go_zero_time(record.prepared_updated_at)
            || !wire::valid_prefixed_sha256(&record.receipt_hash)
            || wire::is_go_zero_time(record.committed_at)
            || record.committed_at < record.prepared_updated_at
            || record.hmac.is_empty()
        {
            return Err(unavailable());
        }
        record.draft()?;
        if let Some(activation) = &record.activation
            && (activation.generation == 0
                || !wire::valid_prefixed_sha256(&activation.database_receipt_hash)
                || !wire::valid_prefixed_sha256(&activation.activation_receipt_hash)
                || wire::is_go_zero_time(activation.activated_at)
                || activation.activated_at < record.committed_at
                || (!wire::is_go_zero_time(activation.presented_at)
                    && activation.presented_at < activation.activated_at))
        {
            return Err(unavailable());
        }
        // DraftReleasedAt and Activation are mutually exclusive markers
        // for the same protected generation.
        if !wire::is_go_zero_time(record.draft_released_at)
            && (record.activation.is_some() || record.draft_released_at < record.committed_at)
        {
            return Err(unavailable());
        }
        let canonical = broker_reset_record_payload(&record)?;
        let expected = self
            .signing
            .fingerprint(BROKER_RESET_HMAC_DOMAIN, &canonical);
        if !wire::hmac_equal(record.hmac.as_bytes(), expected.as_bytes()) {
            return Err(unavailable());
        }
        Ok((record, true))
    }

    /// `takeActivatedRecoveryBootstrap` — returns one fresh token only
    /// after the exact restore is durably `Ready`. The protected
    /// generation is marked presented and deleted before plaintext
    /// leaves the broker, so restart cannot replay it.
    #[allow(dead_code)] // slice-(b)/(c) authority surface
    pub(crate) fn take_activated_recovery_bootstrap(&self) -> Result<Vec<u8>, Failure> {
        let barrier_lock = self.open_lock(&self.restore_barrier_lock_path())?;
        let result = (|| -> Result<Vec<u8>, Failure> {
            let entries = durable::read_dir(&self.operations).map_err(|_| unavailable())?;
            let mut latest: Option<RestoreOperation> = None;
            for entry in &entries {
                let Some(name) = entry.name.to_str() else {
                    continue;
                };
                if entry.file_type.is_dir() || !name.ends_with(".json") {
                    continue;
                }
                let operation_wire: RestoreOperationWire =
                    read_private_json(&self.operations.join(name))?;
                let operation = operation_from_wire(&operation_wire)?;
                if operation.validate().is_err() {
                    return Err(unavailable());
                }
                // An abandoned record is terminal-but-skippable here:
                // it never served and never will, so it must not count
                // against every other, otherwise-Ready record. Before
                // skipping, release whatever bootstrap generation its
                // own C05 handshake created.
                if operation.phase == RestorePhase::Abandoned {
                    self.release_abandoned_recovery_bootstrap(&operation)?;
                    continue;
                }
                if !operation.serving_allowed() {
                    return Err(unavailable());
                }
                match &latest {
                    None => latest = Some(operation),
                    Some(current) if operation.restore_epoch > current.restore_epoch => {
                        latest = Some(operation);
                    }
                    Some(current) if operation.restore_epoch == current.restore_epoch => {
                        return Err(unavailable());
                    }
                    Some(_) => {}
                }
            }
            let Some(latest) = latest else {
                return Err(unavailable());
            };
            let lock = self.open_lock(&self.broker_reset_path(latest.operation_id))?;
            let outcome = (|| -> Result<Vec<u8>, Failure> {
                let (mut record, found) = self.read_broker_reset(&latest)?;
                let activation_presented = record
                    .activation
                    .as_ref()
                    .is_some_and(|a| !wire::is_go_zero_time(a.presented_at));
                if !found || record.activation.is_none() || activation_presented {
                    return Err(unavailable());
                }
                let generation = self
                    .backend
                    .get_by_id(record.protected_generation_id)
                    .map_err(|_| unavailable())?;
                let mut value = self.backend.read(&generation).map_err(|_| unavailable())?;
                if value.is_empty() || value.len() > BOOTSTRAP_VALUE_LIMIT {
                    value.zeroize();
                    return Err(unavailable());
                }
                if let Some(activation) = record.activation.as_mut() {
                    activation.presented_at = OffsetDateTime::now_utc();
                }
                if self.sign_broker_reset_record(&mut record).is_err()
                    || self
                        .replace_json(&self.broker_reset_path(latest.operation_id), &record)
                        .is_err()
                {
                    value.zeroize();
                    return Err(unavailable());
                }
                if self.backend.delete(record.protected_generation_id).is_err() {
                    value.zeroize();
                    return Err(unavailable());
                }
                Ok(value)
            })();
            durable::unlock_and_close(lock);
            outcome
        })();
        durable::unlock_and_close(barrier_lock);
        result
    }

    /// `releaseAbandonedRecoveryBootstrap` — releases the protected
    /// generation an abandoned operation's own C05 broker reset record
    /// is holding, in whichever of the two states abandonment landed
    /// on: post-activation (present-and-delete via `PresentedAt`) or
    /// pre-activation (delete-only via `DraftReleasedAt`). Reads the
    /// exact record for this operation's content-addressed path and
    /// verifies it under its own HMAC; the generation is deleted
    /// without ever being read.
    #[allow(dead_code)] // slice-(b)/(c) authority surface
    fn release_abandoned_recovery_bootstrap(
        &self,
        operation: &RestoreOperation,
    ) -> Result<(), Failure> {
        if operation.phase != RestorePhase::Abandoned {
            return Err(unavailable());
        }
        let path = self.broker_reset_path(operation.operation_id);
        let lock = self.open_lock(&path)?;
        let result = (|| -> Result<(), Failure> {
            match durable::lstat(&path) {
                Err(e) if e == rustix::io::Errno::NOENT => return Ok(()),
                Err(_) => return Err(unavailable()),
                Ok(_) => {}
            }
            let mut record: RecoveryBrokerResetRecord = read_private_json(&path)?;
            if record.operation_id != operation.operation_id
                || record.protected_generation_id.is_nil()
            {
                return Err(unavailable());
            }
            let canonical = broker_reset_record_payload(&record)?;
            let expected = self
                .signing
                .fingerprint(BROKER_RESET_HMAC_DOMAIN, &canonical);
            if !wire::hmac_equal(record.hmac.as_bytes(), expected.as_bytes()) {
                return Err(unavailable());
            }
            match record.activation.as_mut() {
                None => {
                    if !wire::is_go_zero_time(record.draft_released_at) {
                        return Ok(());
                    }
                    self.backend
                        .delete(record.protected_generation_id)
                        .map_err(|_| unavailable())?;
                    record.draft_released_at = OffsetDateTime::now_utc();
                    self.sign_broker_reset_record(&mut record)?;
                    self.replace_json(&path, &record)
                }
                Some(activation) => {
                    if !wire::is_go_zero_time(activation.presented_at) {
                        return Ok(());
                    }
                    self.backend
                        .delete(record.protected_generation_id)
                        .map_err(|_| unavailable())?;
                    activation.presented_at = OffsetDateTime::now_utc();
                    self.sign_broker_reset_record(&mut record)?;
                    self.replace_json(&path, &record)
                }
            }
        })();
        durable::unlock_and_close(lock);
        result
    }

    // -- backup operations ----------------------------------------------------

    /// `CreateBackup` — records the complete planned operation before
    /// the first accepted state can be advanced.
    pub fn create_backup(&self, operation: &BackupOperation) -> Result<(), Failure> {
        if operation.validate().is_err()
            || operation.phase != BackupPhase::Planned
            || !wire::is_go_zero_time(operation.accepted_at)
        {
            return Err(unavailable());
        }
        self.write_exclusive_json(
            &self.backup_path(operation.operation_id),
            &backup_operation_to_wire(operation),
        )
    }

    /// `readBackup` — strict decode + domain validation.
    fn read_backup(&self, operation_id: Uuid) -> Result<BackupOperation, Failure> {
        let wire_record: BackupOperationWire = read_private_json(&self.backup_path(operation_id))?;
        let operation = backup_operation_from_wire(&wire_record)?;
        if operation.operation_id != operation_id || operation.validate().is_err() {
            return Err(unavailable());
        }
        Ok(operation)
    }

    /// `ReadBackup` — status/reconciliation-only.
    pub fn read_backup_operation(&self, operation_id: Uuid) -> Result<BackupOperation, Failure> {
        if operation_id.is_nil() {
            return Err(unavailable());
        }
        self.read_backup(operation_id)
    }

    /// `CompareAndSwapBackup` — accepts only the immediate domain
    /// transition and the next monotonic revision, both checked under
    /// the operation lock.
    pub fn compare_and_swap_backup(
        &self,
        expected: &BackupOperation,
        next: &BackupOperation,
    ) -> Result<(), Failure> {
        if expected.validate().is_err()
            || next.validate().is_err()
            || expected.operation_id != next.operation_id
            || expected.backup_id != next.backup_id
            || expected.revision == 0
            || next.revision != expected.revision + 1
        {
            return Err(unavailable());
        }
        if next.phase == BackupPhase::Sealed {
            return Err(unavailable());
        }
        let computed = if next.phase == BackupPhase::Admitted {
            expected.accept(next.accepted_facts.clone())
        } else if next.phase == BackupPhase::Failed {
            expected.fail(&next.failure_reason, next.updated_at)
        } else {
            expected.advance(next.phase, next.updated_at)
        };
        let Ok(computed) = computed else {
            return Err(unavailable());
        };
        if computed != *next {
            return Err(unavailable());
        }
        let lock = self.open_lock(&self.backup_path(expected.operation_id))?;
        let result = (|| -> Result<(), Failure> {
            let current = self.read_backup(expected.operation_id)?;
            if current != *expected {
                return Err(unavailable());
            }
            self.replace_json(
                &self.backup_path(expected.operation_id),
                &backup_operation_to_wire(next),
            )?;
            if next.phase == BackupPhase::Failed {
                // SC-DEF-69: best-effort fast-path release, now that
                // this backup is durably Failed and can never need its
                // MinIO backup credential again.
                let _ = self
                    .release_minio_handoff_generation(expected.operation_id, Purpose::MinioBackup);
            }
            Ok(())
        })();
        durable::unlock_and_close(lock);
        result
    }

    // -- restore ticket issue -------------------------------------------------

    /// `Issue` — mints one restore ticket, its operation id, and the
    /// operation → issuing-launch record that binds both to the launch
    /// that was live when this call was made.
    ///
    /// `launch_evidence_id` is that launch, supplied by the caller:
    /// the journal store owns no launch record. `Uuid::nil()` is
    /// admitted — see `restoreTicketRecord.LaunchEvidenceID`.
    pub fn issue(
        &self,
        backup_id: Uuid,
        manifest_digest: &str,
        facts: &RestoreAdmissionFacts,
        launch_evidence_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<RestoreTicket, Failure> {
        if backup_id.is_nil()
            || !valid_recovery_facts(facts)
            || wire::is_go_zero_time(now)
            || manifest_digest.is_empty()
        {
            return Err(unavailable());
        }
        let ticket_id = Uuid::now_v7();
        let operation_id = Uuid::now_v7();
        let mut nonce = [0u8; 32];
        rustix::rand::getrandom(&mut nonce, rustix::rand::GetRandomFlags::empty())
            .map_err(|_| unavailable())?;
        let mut ticket = RestoreTicket {
            ticket_id,
            operation_id,
            backup_id,
            target: facts.target.clone(),
            target_fingerprint: facts.target_fingerprint.clone(),
            manifest_digest: manifest_digest.to_owned(),
            security_epoch: facts.security_epoch,
            restore_epoch: facts.restore_epoch,
            config_fingerprint: facts.config_fingerprint.clone(),
            payload_epoch_id: facts.payload_epoch_id,
            database_schema_version: facts.database_schema_version.clone(),
            capacity_evidence_digest: facts.capacity_evidence_digest.clone(),
            tool_version: facts.tool_version.clone(),
            hidden_nonce: nonce.to_vec(),
            issued_at: now.to_offset(time::UtcOffset::UTC),
            expires_at: now.to_offset(time::UtcOffset::UTC) + RESTORE_TICKET_LIFETIME,
            hmac: String::new(),
        };
        ticket.hmac = self
            .signing
            .fingerprint(RESTORE_TICKET_HMAC_DOMAIN, &ticket.canonical_payload());
        if ticket.is_expired_at(now) {
            return Err(unavailable());
        }
        let record = RestoreTicketRecordWire {
            ticket: ticket_to_wire(&ticket),
            state: "issued".to_owned(),
            launch_evidence_id,
            issued_at: now.to_offset(time::UtcOffset::UTC),
        };
        self.write_exclusive_json(&self.ticket_path(ticket.ticket_id), &record)?;
        // The operation-keyed carry is written after the ticket, never
        // before: a carry naming a ticket that does not exist would
        // let Begin's cross-check pass against nothing, while the
        // reverse — a ticket with no carry — is a ticket that can
        // never spend a reserve, which is the closed-fail direction.
        self.write_ticket_launch(&ticket, launch_evidence_id)?;
        Ok(ticket)
    }

    fn write_ticket_launch(
        &self,
        ticket: &RestoreTicket,
        launch_evidence_id: Uuid,
    ) -> Result<(), Failure> {
        let mut record = RestoreTicketLaunchRecordWire {
            schema_version: RESTORE_TICKET_LAUNCH_RECORD_SCHEMA.to_owned(),
            operation_id: ticket.operation_id,
            ticket_id: ticket.ticket_id,
            launch_evidence_id,
            issued_at: ticket.issued_at.to_offset(time::UtcOffset::UTC),
            expires_at: ticket.expires_at.to_offset(time::UtcOffset::UTC),
            hmac: String::new(),
        };
        let payload = ticket_launch_payload(&record)?;
        record.hmac = self
            .signing
            .fingerprint(RESTORE_TICKET_LAUNCH_HMAC_DOMAIN, &payload);
        // O_EXCL, never replace. Both ids were freshly minted, so a
        // collision is a broken store; and no later event legitimately
        // changes which launch issued a ticket.
        self.write_exclusive_json(&self.ticket_launch_path(ticket.operation_id), &record)
    }

    /// `readTicketLaunch` — tells "does not exist" apart from "exists
    /// and could not be authenticated".
    pub(crate) fn read_ticket_launch(
        &self,
        operation_id: Uuid,
    ) -> Result<RestoreTicketLaunchRecordWire, Failure> {
        if operation_id.is_nil() {
            return Err(unavailable());
        }
        let path = self.ticket_launch_path(operation_id);
        match durable::lstat(&path) {
            Err(e) if e == rustix::io::Errno::NOENT => return Err(ticket_launch_not_found()),
            Err(_) => return Err(unavailable()),
            Ok(_) => {}
        }
        let record: RestoreTicketLaunchRecordWire = read_private_json(&path)?;
        if record.operation_id != operation_id || !record.valid() {
            return Err(unavailable());
        }
        let payload = ticket_launch_payload(&record)?;
        let expected = self
            .signing
            .fingerprint(RESTORE_TICKET_LAUNCH_HMAC_DOMAIN, &payload);
        if !wire::hmac_equal(record.hmac.as_bytes(), expected.as_bytes()) {
            return Err(unavailable());
        }
        Ok(record)
    }

    // -- MinIO recovery handoffs ------------------------------------------------

    /// `IssueMinioHandoff` — records the exact recovery credential
    /// scope that an external minio-provision invocation may deliver.
    /// The opaque receipt ID is the only value crossing to that
    /// provisioner; a descriptor is accepted later only if it echoes
    /// every persisted field exactly.
    pub fn issue_minio_handoff(
        &self,
        request: &RecoveryMinioHandoffRequest,
    ) -> Result<RecoveryMinioHandoffReceipt, Failure> {
        if !valid_recovery_minio_request(request) {
            return Err(unavailable());
        }
        let Ok(purpose) = request.purpose.parse::<Purpose>() else {
            return Err(unavailable());
        };
        let policy_digest =
            minio_recovery_policy_digest(purpose, &request.bucket).map_err(|_| unavailable())?;
        // SC-DEF-69: reconcile before this call's own index lock is
        // acquired. Its own failure is deliberately ignored —
        // reconciliation is unrelated cleanup of other operations'
        // generations.
        self.reconcile_minio_handoff_generations(OffsetDateTime::now_utc());
        let index_path = self.handoff_operation_path(&request.operation_id, &request.purpose);
        let index_lock = self.open_lock(&index_path)?;
        let outcome = (|| -> Result<RecoveryMinioHandoffReceipt, Failure> {
            if durable::lstat(&index_path).is_ok() {
                let binding =
                    self.read_minio_operation_binding(&request.operation_id, &request.purpose)?;
                let record = self.read_minio_receipt(&binding.receipt_id)?;
                if record.state == "binding"
                    || !same_recovery_minio_request(request, &record.receipt)
                {
                    return Err(unavailable());
                }
                let mut receipt = record.receipt.clone();
                receipt.bound = record.state == "bound";
                return Ok(receipt);
            }
            let receipt = RecoveryMinioHandoffReceipt {
                receipt_id: Uuid::now_v7().to_string(),
                operation_id: request.operation_id.clone(),
                instance_id: request.instance_id.clone(),
                purpose: request.purpose.clone(),
                bucket: request.bucket.clone(),
                key_prefix: request.key_prefix.clone(),
                policy_digest,
                expires_at: request.expires_at.to_offset(time::UtcOffset::UTC),
                fence_token: request.fence_token,
                bound: false,
            };
            self.write_exclusive_json(
                &self.handoff_path(&receipt.receipt_id),
                &RecoveryMinioReceiptRecordWire {
                    receipt: receipt.clone(),
                    state: "issued".to_owned(),
                    generation_id: String::new(),
                },
            )?;
            let index = RecoveryMinioOperationBindingWire {
                operation_id: receipt.operation_id.clone(),
                purpose: receipt.purpose.clone(),
                receipt_id: receipt.receipt_id.clone(),
            };
            if self.write_exclusive_json(&index_path, &index).is_err() {
                // The orphan receipt is deliberately unusable:
                // BindMinioHandoff checks this exact index before
                // consuming it.
                return Err(unavailable());
            }
            Ok(receipt)
        })();
        durable::unlock_and_close(index_lock);
        outcome
    }

    /// `BindMinioHandoff` — consumes a receipt before persisting the
    /// sealed recovery credential in the broker-owned protected store.
    /// A crash in the binding state remains unavailable and
    /// non-replayable.
    pub fn bind_minio_handoff(
        &self,
        descriptor: &MinioProvisionedDescriptor,
        value: &[u8],
        now: OffsetDateTime,
    ) -> Result<(), Failure> {
        if value.is_empty() || !valid_recovery_minio_descriptor(descriptor, now) {
            return Err(unavailable());
        }
        let lock = self.open_lock(&self.handoff_path(&descriptor.receipt_id))?;
        let result = (|| -> Result<(), Failure> {
            let mut record = self.read_minio_receipt(&descriptor.receipt_id)?;
            let index =
                self.read_minio_operation_binding(&descriptor.operation_id, &descriptor.purpose)?;
            if index.receipt_id != descriptor.receipt_id
                || record.state != "issued"
                || !same_recovery_minio_binding(&record.receipt, descriptor)
            {
                return Err(unavailable());
            }
            // Persist the no-replay decision before touching protected
            // credential storage. A crash here is deliberately
            // fail-closed.
            record.state = "binding".to_owned();
            self.replace_json(&self.handoff_path(&descriptor.receipt_id), &record)?;
            let generation = self
                .backend
                .create(&descriptor.purpose, value)
                .map_err(|_| unavailable())?;
            record.state = "bound".to_owned();
            record.generation_id = generation.generation_id.to_string();
            if self
                .replace_json(&self.handoff_path(&descriptor.receipt_id), &record)
                .is_err()
            {
                // The credential is durably stored but its binding
                // outcome is unknown; keep the receipt in binding and
                // deny retry.
                return Err(unavailable());
            }
            Ok(())
        })();
        durable::unlock_and_close(lock);
        result
    }

    /// `ResolveBoundMinioHandoff` — the exact protected generation and
    /// fixed scope selected by broker-owned operation state. Neither
    /// receipt nor generation identity is accepted from the worker.
    pub fn resolve_bound_minio_handoff(
        &self,
        operation_id: Uuid,
        purpose: Purpose,
    ) -> Result<(Generation, RecoveryMinioHandoffReceipt), Failure> {
        if operation_id.is_nil() || !valid_recovery_minio_purpose(purpose) {
            return Err(unavailable());
        }
        let index =
            self.read_minio_operation_binding(&operation_id.to_string(), purpose.as_str())?;
        let record = self.read_minio_receipt(&index.receipt_id)?;
        if record.state != "bound"
            || record.receipt.operation_id != operation_id.to_string()
            || record.receipt.purpose != purpose.as_str()
        {
            return Err(unavailable());
        }
        let Ok(generation_id) = Uuid::parse_str(&record.generation_id) else {
            return Err(unavailable());
        };
        if generation_id.is_nil() {
            return Err(unavailable());
        }
        let generation = self
            .backend
            .get_by_id(generation_id)
            .map_err(|_| unavailable())?;
        if generation.purpose != purpose.as_str() {
            return Err(unavailable());
        }
        Ok((generation, record.receipt))
    }

    /// `readMinioReceipt` — strict decode plus the liveness predicate;
    /// an expired receipt refuses to return at all.
    fn read_minio_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<RecoveryMinioReceiptRecordWire, Failure> {
        let record: RecoveryMinioReceiptRecordWire =
            read_private_json(&self.handoff_path(receipt_id))?;
        let request = RecoveryMinioHandoffRequest {
            operation_id: record.receipt.operation_id.clone(),
            instance_id: record.receipt.instance_id.clone(),
            purpose: record.receipt.purpose.clone(),
            bucket: record.receipt.bucket.clone(),
            key_prefix: record.receipt.key_prefix.clone(),
            policy_digest: record.receipt.policy_digest.clone(),
            expires_at: record.receipt.expires_at,
            fence_token: record.receipt.fence_token,
        };
        if record.receipt.receipt_id != receipt_id
            || !matches!(record.state.as_str(), "issued" | "binding" | "bound")
            || !valid_recovery_minio_request(&request)
        {
            return Err(unavailable());
        }
        Ok(record)
    }

    /// `readMinioOperationBinding`.
    fn read_minio_operation_binding(
        &self,
        operation_id: &str,
        purpose: &str,
    ) -> Result<RecoveryMinioOperationBindingWire, Failure> {
        if operation_id.is_empty() {
            return Err(unavailable());
        }
        let Ok(parsed) = purpose.parse::<Purpose>() else {
            return Err(unavailable());
        };
        if !valid_recovery_minio_purpose(parsed) {
            return Err(unavailable());
        }
        let binding: RecoveryMinioOperationBindingWire =
            read_private_json(&self.handoff_operation_path(operation_id, purpose))?;
        if binding.operation_id != operation_id
            || binding.purpose != purpose
            || binding.receipt_id.is_empty()
        {
            return Err(unavailable());
        }
        Ok(binding)
    }

    /// `readMinioReceiptRecordForRelease` — reads a receipt record
    /// exactly as persisted, without the `validRecoveryMinioRequest`
    /// liveness check; release must be able to read a receipt
    /// specifically because it has expired.
    fn read_minio_receipt_record_for_release(
        &self,
        receipt_id: &str,
    ) -> Result<RecoveryMinioReceiptRecordWire, Failure> {
        let record: RecoveryMinioReceiptRecordWire =
            read_private_json(&self.handoff_path(receipt_id))?;
        if record.receipt.receipt_id != receipt_id {
            return Err(unavailable());
        }
        Ok(record)
    }

    /// `releaseMinioHandoffGeneration` — deletes the broker-owned
    /// protected-storage copy of a bound MinIO credential once it can
    /// never legitimately be resolved again (SC-DEF-69). Never
    /// mutates the receipt record itself; deliberately best-effort —
    /// it only runs after the primary outcome it cleans up after is
    /// durable.
    pub(crate) fn release_minio_handoff_generation(
        &self,
        operation_id: Uuid,
        purpose: Purpose,
    ) -> Result<(), Failure> {
        if operation_id.is_nil() || !valid_recovery_minio_purpose(purpose) {
            return Ok(());
        }
        let index_path = self.handoff_operation_path(&operation_id.to_string(), purpose.as_str());
        match durable::lstat(&index_path) {
            Err(e) if e == rustix::io::Errno::NOENT => return Ok(()),
            Err(e) => return Err(Failure::internal(JOURNAL_UNAVAILABLE_CODE, format!("{e}"))),
            Ok(_) => {}
        }
        let index_lock = self.open_lock(&index_path)?;
        let outcome = (|| -> Result<(), Failure> {
            let index =
                self.read_minio_operation_binding(&operation_id.to_string(), purpose.as_str())?;
            let receipt_lock = self.open_lock(&self.handoff_path(&index.receipt_id))?;
            let result = (|| -> Result<(), Failure> {
                let record = match self.read_minio_receipt_record_for_release(&index.receipt_id) {
                    Ok(record) => record,
                    Err(e) if e.code() == JOURNAL_UNAVAILABLE_CODE => return Ok(()),
                    Err(e) => return Err(e),
                };
                if record.state != "bound" || record.generation_id.is_empty() {
                    return Ok(());
                }
                let Ok(generation_id) = Uuid::parse_str(&record.generation_id) else {
                    return Ok(());
                };
                // `cleanupProtectedGeneration` — upstream detaches the
                // delete from the caller's cancel context; the Rust
                // backend is synchronous and owns no context at all.
                self.backend
                    .delete(generation_id)
                    .map_err(|e| Failure::internal(JOURNAL_UNAVAILABLE_CODE, e.message()))
            })();
            durable::unlock_and_close(receipt_lock);
            result
        })();
        durable::unlock_and_close(index_lock);
        outcome
    }

    /// `minioHandoffOwnerIsTerminal` — whether the restore or backup
    /// operation has reached a phase from which it can never again
    /// need its bound MinIO credential.
    fn minio_handoff_owner_is_terminal(&self, operation_id: Uuid, purpose: Purpose) -> bool {
        if purpose == Purpose::MinioRestore {
            return self
                .read_operation(operation_id)
                .is_ok_and(|operation| operation.is_terminal());
        }
        if purpose == Purpose::MinioImport {
            // Import has no journal operation record — the bound
            // receipt is the only broker-side import state.
            return false;
        }
        self.read_backup(operation_id)
            .is_ok_and(|operation| operation.phase.is_terminal())
    }

    /// `reconcileMinioHandoffGenerations` — releases every bound
    /// handoff generation whose credential can never legitimately be
    /// resolved again: an expired receipt, or a terminal owning
    /// operation. Best-effort throughout: an unreadable entry is
    /// skipped, and one entry's failure never stops the scan.
    fn reconcile_minio_handoff_generations(&self, now: OffsetDateTime) {
        let Ok(entries) = durable::read_dir(&self.handoffs) else {
            return;
        };
        for entry in &entries {
            let Some(name) = entry.name.to_str() else {
                continue;
            };
            if entry.file_type.is_dir() || !name.ends_with(".json") {
                continue;
            }
            let Ok(record) =
                read_private_json::<RecoveryMinioReceiptRecordWire>(&self.handoffs.join(name))
            else {
                continue;
            };
            if record.receipt.receipt_id.is_empty()
                || record.state != "bound"
                || record.generation_id.is_empty()
            {
                continue;
            }
            let Ok(purpose) = record.receipt.purpose.parse::<Purpose>() else {
                continue;
            };
            if !valid_recovery_minio_purpose(purpose) {
                continue;
            }
            let Ok(operation_id) = Uuid::parse_str(&record.receipt.operation_id) else {
                continue;
            };
            let expired = now >= record.receipt.expires_at;
            if !expired && !self.minio_handoff_owner_is_terminal(operation_id, purpose) {
                continue;
            }
            let _ = self.release_minio_handoff_generation(operation_id, purpose);
        }
    }

    // -- restore apply/abandon authorization issue ----------------------------

    /// `IssueRestoreApplyAuthorization` — records a fresh helper
    /// ceremony after it has verified the kernel-derived peer.
    pub fn issue_restore_apply_authorization(
        &self,
        ticket: &RestoreTicket,
        peer_uid: u32,
        peer_pid: i32,
        now: OffsetDateTime,
    ) -> Result<RestoreApplyAuthorization, Failure> {
        if peer_pid <= 0
            || wire::is_go_zero_time(now)
            || ticket.ticket_id.is_nil()
            || ticket.operation_id.is_nil()
        {
            return Err(unavailable());
        }
        let lock = self.open_lock(&self.ticket_path(ticket.ticket_id))?;
        let outcome = (|| -> Result<RestoreApplyAuthorization, Failure> {
            let record = self.read_ticket(ticket.ticket_id)?;
            if record.1 != "issued"
                || !same_ticket(&record.0, ticket)
                || !self.valid_ticket(ticket, now)
            {
                return Err(unavailable());
            }
            self.issue_restore_apply_authorization_locked(ticket, peer_uid, peer_pid, now)
        })();
        durable::unlock_and_close(lock);
        outcome
    }

    /// `IssueRestoreApplyAuthorizationForOperation` — resolves the
    /// single still-issued ticket bound to an operation ID and
    /// authorizes exactly that ticket. Ambiguity is not tolerated.
    pub fn issue_restore_apply_authorization_for_operation(
        &self,
        operation_id: Uuid,
        peer_uid: u32,
        peer_pid: i32,
        now: OffsetDateTime,
    ) -> Result<RestoreApplyAuthorization, Failure> {
        if operation_id.is_nil() || peer_pid <= 0 || wire::is_go_zero_time(now) {
            return Err(unavailable());
        }
        let ticket_id = self.resolve_issued_ticket_for_operation(operation_id, now)?;
        let lock = self.open_lock(&self.ticket_path(ticket_id))?;
        let outcome = (|| -> Result<RestoreApplyAuthorization, Failure> {
            // Re-read under the lock: the unlocked resolution above
            // only nominates a candidate.
            let record = self.read_ticket(ticket_id)?;
            if record.1 != "issued"
                || record.0.operation_id != operation_id
                || !self.valid_ticket(&record.0, now)
            {
                return Err(unavailable());
            }
            self.issue_restore_apply_authorization_locked(&record.0, peer_uid, peer_pid, now)
        })();
        durable::unlock_and_close(lock);
        outcome
    }

    /// `issuedTicketOperationIDs` — the operation ID of every
    /// currently valid, unconsumed ticket (SC-DEF-59). A nomination
    /// only: every reported field is re-validated under lock by the
    /// call that later acts on it.
    #[allow(dead_code)] // slice-(b)/(c) authority surface
    pub(crate) fn issued_ticket_operation_ids(
        &self,
        now: OffsetDateTime,
    ) -> Result<Vec<Uuid>, Failure> {
        durable::validate_private_directory(&self.tickets, "recovery ticket root")
            .map_err(|_| unavailable())?;
        let entries = durable::read_dir(&self.tickets).map_err(|_| unavailable())?;
        let mut ids = Vec::new();
        for entry in &entries {
            let Some(name) = entry.name.to_str() else {
                return Err(unavailable());
            };
            let path = self.tickets.join(name);
            if valid_recovery_operation_lock_name(name) {
                let meta = durable::lstat(&path).map_err(|_| unavailable())?;
                durable::validate_private_file(&meta, "recovery ticket lock")
                    .map_err(|_| unavailable())?;
                continue;
            }
            if entry.file_type.is_dir() || !name.ends_with(".json") {
                return Err(unavailable());
            }
            let record: RestoreTicketRecordWire = read_private_json(&path)?;
            if record.ticket.ticket_id.is_nil()
                || name
                    != format!(
                        "{}.json",
                        generation_key(&record.ticket.ticket_id.to_string())
                    )
            {
                return Err(unavailable());
            }
            if record.state != "issued"
                || !self.valid_ticket(&ticket_from_wire(&record.ticket), now)
            {
                continue;
            }
            ids.push(record.ticket.operation_id);
        }
        Ok(ids)
    }

    /// `hasIssuedRestoreApplyAuthorizationForOperation` — whether a
    /// still-valid restore-apply authorization is issued for
    /// `operation_id`, without requiring the operation to exist yet.
    #[allow(dead_code)] // slice-(b)/(c) authority surface
    pub(crate) fn has_issued_restore_apply_authorization_for_operation(
        &self,
        operation_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<bool, Failure> {
        durable::validate_private_directory(&self.apply, "recovery apply authorization root")
            .map_err(|_| unavailable())?;
        let entries = durable::read_dir(&self.apply).map_err(|_| unavailable())?;
        for entry in &entries {
            let Some(name) = entry.name.to_str() else {
                return Err(unavailable());
            };
            let path = self.apply.join(name);
            if valid_recovery_operation_lock_name(name) {
                let meta = durable::lstat(&path).map_err(|_| unavailable())?;
                durable::validate_private_file(&meta, "recovery apply authorization lock")
                    .map_err(|_| unavailable())?;
                continue;
            }
            if entry.file_type.is_dir() || !name.ends_with(".json") {
                return Err(unavailable());
            }
            let record: RestoreApplyRecordWire = read_private_json(&path)?;
            if record.authorization.authorization_id.is_nil()
                || name
                    != format!(
                        "{}.json",
                        generation_key(&record.authorization.authorization_id.to_string())
                    )
            {
                return Err(unavailable());
            }
            let authorization = apply_authorization_from_wire(&record.authorization);
            if record.state == "issued"
                && authorization.operation_id == operation_id
                && authorization.valid_at(now)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// `resolveIssuedTicketForOperation` — scans protected ticket
    /// state for the exact unexpired issued ticket of one operation.
    fn resolve_issued_ticket_for_operation(
        &self,
        operation_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<Uuid, Failure> {
        durable::validate_private_directory(&self.tickets, "recovery ticket root")
            .map_err(|_| unavailable())?;
        let entries = durable::read_dir(&self.tickets).map_err(|_| unavailable())?;
        let mut resolved = Uuid::nil();
        for entry in &entries {
            let Some(name) = entry.name.to_str() else {
                return Err(unavailable());
            };
            let path = self.tickets.join(name);
            if valid_recovery_operation_lock_name(name) {
                let meta = durable::lstat(&path).map_err(|_| unavailable())?;
                durable::validate_private_file(&meta, "recovery ticket lock")
                    .map_err(|_| unavailable())?;
                continue;
            }
            if entry.file_type.is_dir() || !name.ends_with(".json") {
                return Err(unavailable());
            }
            let record: RestoreTicketRecordWire = read_private_json(&path)?;
            if record.ticket.ticket_id.is_nil()
                || name
                    != format!(
                        "{}.json",
                        generation_key(&record.ticket.ticket_id.to_string())
                    )
            {
                return Err(unavailable());
            }
            let ticket = ticket_from_wire(&record.ticket);
            if record.state != "issued"
                || ticket.operation_id != operation_id
                || !self.valid_ticket(&ticket, now)
            {
                continue;
            }
            if !resolved.is_nil() {
                return Err(unavailable());
            }
            resolved = ticket.ticket_id;
        }
        if resolved.is_nil() {
            return Err(unavailable());
        }
        Ok(resolved)
    }

    /// `issueRestoreApplyAuthorizationLocked` — mints the record under
    /// a ticket lock the caller already holds.
    fn issue_restore_apply_authorization_locked(
        &self,
        ticket: &RestoreTicket,
        peer_uid: u32,
        peer_pid: i32,
        now: OffsetDateTime,
    ) -> Result<RestoreApplyAuthorization, Failure> {
        if peer_pid <= 0
            || wire::is_go_zero_time(now)
            || ticket.ticket_id.is_nil()
            || ticket.operation_id.is_nil()
            || !self.valid_ticket(ticket, now)
        {
            return Err(unavailable());
        }
        let authorization = RestoreApplyAuthorization {
            authorization_id: Uuid::now_v7(),
            operation_id: ticket.operation_id,
            ticket_id: ticket.ticket_id,
            issued_at: now.to_offset(time::UtcOffset::UTC),
            expires_at: now.to_offset(time::UtcOffset::UTC) + RESTORE_APPLY_LIFETIME,
        };
        if !authorization.valid_at(now + Duration::NANOSECOND) {
            return Err(unavailable());
        }
        self.write_exclusive_json(
            &self.apply_path(authorization.authorization_id),
            &RestoreApplyRecordWire {
                authorization: apply_authorization_to_wire(&authorization),
                state: "issued".to_owned(),
                peer_uid,
                peer_pid,
            },
        )?;
        Ok(authorization)
    }

    /// `IssueRestoreResumeAuthorizationForOperation` — a new one-use
    /// authorization for an already-started protected restore. The
    /// original ticket must be consumed and the operation must still
    /// be non-ready.
    pub fn issue_restore_resume_authorization_for_operation(
        &self,
        operation_id: Uuid,
        peer_uid: u32,
        peer_pid: i32,
        now: OffsetDateTime,
    ) -> Result<RestoreApplyAuthorization, Failure> {
        if operation_id.is_nil() || peer_pid <= 0 || wire::is_go_zero_time(now) {
            return Err(unavailable());
        }
        let lock = self.open_lock(&self.operation_path(operation_id))?;
        let outcome = (|| -> Result<RestoreApplyAuthorization, Failure> {
            let operation = self.read_operation(operation_id)?;
            if !operation.is_resumable() {
                return Err(unavailable());
            }
            let (ticket, state) = self.read_ticket(operation.ticket_id)?;
            if state != "consumed"
                || ticket.operation_id != operation_id
                || ticket.backup_id != operation.backup_id
                || ticket.target != operation.target
            {
                return Err(unavailable());
            }
            let authorization = RestoreApplyAuthorization {
                authorization_id: Uuid::now_v7(),
                operation_id,
                ticket_id: operation.ticket_id,
                issued_at: now.to_offset(time::UtcOffset::UTC),
                expires_at: now.to_offset(time::UtcOffset::UTC) + RESTORE_APPLY_LIFETIME,
            };
            if !authorization.valid_at(now + Duration::NANOSECOND) {
                return Err(unavailable());
            }
            self.write_exclusive_json(
                &self.apply_path(authorization.authorization_id),
                &RestoreApplyRecordWire {
                    authorization: apply_authorization_to_wire(&authorization),
                    state: "issued".to_owned(),
                    peer_uid,
                    peer_pid,
                },
            )?;
            Ok(authorization)
        })();
        durable::unlock_and_close(lock);
        outcome
    }

    /// `IssueRestoreAbandonAuthorization` — records the fresh
    /// helper-owned abandonment ceremony for one exact protected
    /// operation. Anchored only on the operation still being
    /// resumable; the acknowledgement is attached by the issuer,
    /// never accepted from a caller.
    pub fn issue_restore_abandon_authorization(
        &self,
        operation_id: Uuid,
        peer_uid: u32,
        peer_pid: i32,
        now: OffsetDateTime,
    ) -> Result<RestoreAbandonAuthorization, Failure> {
        if operation_id.is_nil() || peer_pid <= 0 || wire::is_go_zero_time(now) {
            return Err(unavailable());
        }
        let lock = self.open_lock(&self.operation_path(operation_id))?;
        let outcome = (|| -> Result<RestoreAbandonAuthorization, Failure> {
            let operation = self.read_operation(operation_id)?;
            if !operation.is_resumable() {
                return Err(unavailable());
            }
            let authorization = RestoreAbandonAuthorization {
                authorization_id: Uuid::now_v7(),
                operation_id,
                issued_at: now.to_offset(time::UtcOffset::UTC),
                expires_at: now.to_offset(time::UtcOffset::UTC) + RESTORE_ABANDON_LIFETIME,
                acknowledgement:
                    central_backup::recovery::operation::RESTORE_ABANDON_ACKNOWLEDGEMENT.to_owned(),
            };
            if !authorization.valid_at(now + Duration::NANOSECOND) {
                return Err(unavailable());
            }
            self.write_exclusive_json(
                &self.abandon_path(authorization.authorization_id),
                &RestoreAbandonRecordWire {
                    authorization: abandon_authorization_to_wire(&authorization),
                    state: "issued".to_owned(),
                    peer_uid,
                    peer_pid,
                },
            )?;
            Ok(authorization)
        })();
        durable::unlock_and_close(lock);
        outcome
    }

    // -- restore begin/resume/abandon/read/CAS --------------------------------

    /// `Begin` — atomically claims a protected issued ticket plus the
    /// fresh helper authorization and persists `applying` before any
    /// restore engine receives control.
    pub fn begin(
        &self,
        ticket: &RestoreTicket,
        authorization: &RestoreApplyAuthorization,
        now: OffsetDateTime,
    ) -> Result<RestoreOperation, Failure> {
        if wire::is_go_zero_time(now)
            || ticket.ticket_id.is_nil()
            || ticket.operation_id.is_nil()
            || !authorization.valid_at(now)
            || !authorization.binds(ticket)
        {
            return Err(unavailable());
        }
        let barrier_lock = self.open_lock(&self.restore_barrier_lock_path())?;
        let outcome = (|| -> Result<RestoreOperation, Failure> {
            let (_, active) = self.inspect_restore_barrier_locked()?;
            if active {
                return Err(unavailable());
            }
            let ticket_lock = self.open_lock(&self.ticket_path(ticket.ticket_id))?;
            let inner = (|| -> Result<RestoreOperation, Failure> {
                let authorization_lock =
                    self.open_lock(&self.apply_path(authorization.authorization_id))?;
                let result = (|| -> Result<RestoreOperation, Failure> {
                    let (stored_ticket, state) = self.read_ticket(ticket.ticket_id)?;
                    if state != "issued"
                        || !same_ticket(&stored_ticket, ticket)
                        || !self.valid_ticket(ticket, now)
                    {
                        return Err(unavailable());
                    }
                    let ticket_record: RestoreTicketRecordWire =
                        read_private_json(&self.ticket_path(ticket.ticket_id))?;
                    // The issuing-launch carry, re-checked at the one
                    // point the destructive path is entered.
                    let carry = self.read_ticket_launch(ticket.operation_id)?;
                    if carry.ticket_id != ticket.ticket_id
                        || carry.launch_evidence_id != ticket_record.launch_evidence_id
                    {
                        return Err(unavailable());
                    }
                    let mut authorization_record: RestoreApplyRecordWire =
                        read_private_json(&self.apply_path(authorization.authorization_id))?;
                    if authorization_record.state != "issued"
                        || apply_authorization_from_wire(&authorization_record.authorization)
                            != *authorization
                        || !authorization.valid_at(now)
                    {
                        return Err(unavailable());
                    }
                    // Persist the no-replay decision before replacement
                    // begins. An interrupted binding cannot be retried
                    // with the same confirmation, but a new fresh
                    // ceremony may be issued while the ticket remains
                    // unconsumed.
                    authorization_record.state = "consuming".to_owned();
                    self.replace_json(
                        &self.apply_path(authorization.authorization_id),
                        &authorization_record,
                    )?;
                    let operation =
                        new_restore_operation(ticket, now).map_err(|_| unavailable())?;
                    self.write_exclusive_json(
                        &self.operation_path(operation.operation_id),
                        &operation_to_wire(&operation),
                    )
                    .map_err(|_| {
                        // Existing operation means an earlier process
                        // durably consumed the exact ticket.
                        unavailable()
                    })?;
                    let mut consumed = ticket_record;
                    consumed.state = "consumed".to_owned();
                    self.replace_json(&self.ticket_path(ticket.ticket_id), &consumed)?;
                    authorization_record.state = "consumed".to_owned();
                    self.replace_json(
                        &self.apply_path(authorization.authorization_id),
                        &authorization_record,
                    )?;
                    Ok(operation)
                })();
                durable::unlock_and_close(authorization_lock);
                result
            })();
            durable::unlock_and_close(ticket_lock);
            inner
        })();
        durable::unlock_and_close(barrier_lock);
        outcome
    }

    /// `Resume` — atomically consumes a fresh helper authorization and
    /// returns the exact resumable protected operation.
    pub fn resume(
        &self,
        operation_id: Uuid,
        authorization: &RestoreApplyAuthorization,
        now: OffsetDateTime,
    ) -> Result<RestoreOperation, Failure> {
        if operation_id.is_nil()
            || wire::is_go_zero_time(now)
            || !authorization.valid_at(now)
            || authorization.operation_id != operation_id
        {
            return Err(unavailable());
        }
        let operation_lock = self.open_lock(&self.operation_path(operation_id))?;
        let outcome = (|| -> Result<RestoreOperation, Failure> {
            let authorization_lock =
                self.open_lock(&self.apply_path(authorization.authorization_id))?;
            let result = (|| -> Result<RestoreOperation, Failure> {
                let operation = self.read_operation(operation_id)?;
                if !operation.is_resumable() || authorization.ticket_id != operation.ticket_id {
                    return Err(unavailable());
                }
                let mut record: RestoreApplyRecordWire =
                    read_private_json(&self.apply_path(authorization.authorization_id))?;
                if record.state != "issued"
                    || apply_authorization_from_wire(&record.authorization) != *authorization
                {
                    return Err(unavailable());
                }
                record.state = "consuming".to_owned();
                self.replace_json(&self.apply_path(authorization.authorization_id), &record)?;
                record.state = "consumed".to_owned();
                self.replace_json(&self.apply_path(authorization.authorization_id), &record)?;
                Ok(operation)
            })();
            durable::unlock_and_close(authorization_lock);
            result
        })();
        durable::unlock_and_close(operation_lock);
        outcome
    }

    /// `Abandon` — consumes one fresh abandonment authorization and
    /// publishes ADR 0016's terminal outcome for exactly its
    /// operation. The transition is the domain's, computed under the
    /// same locks that serialize every other phase change, and
    /// re-checked through `ValidateTransitionTo`.
    pub fn abandon(
        &self,
        operation_id: Uuid,
        authorization: &RestoreAbandonAuthorization,
        now: OffsetDateTime,
    ) -> Result<RestoreOperation, Failure> {
        if operation_id.is_nil()
            || wire::is_go_zero_time(now)
            || authorization.operation_id != operation_id
            || !authorization.valid_at(now)
        {
            return Err(unavailable());
        }
        let barrier_lock = self.open_lock(&self.restore_barrier_lock_path())?;
        let outcome = (|| -> Result<RestoreOperation, Failure> {
            let operation_lock = self.open_lock(&self.operation_path(operation_id))?;
            let inner = (|| -> Result<RestoreOperation, Failure> {
                let authorization_lock =
                    self.open_lock(&self.abandon_path(authorization.authorization_id))?;
                let result = (|| -> Result<RestoreOperation, Failure> {
                    let operation = self.read_operation(operation_id)?;
                    if !operation.is_resumable() {
                        return Err(unavailable());
                    }
                    let mut record: RestoreAbandonRecordWire =
                        read_private_json(&self.abandon_path(authorization.authorization_id))?;
                    if record.state != "issued"
                        || abandon_authorization_from_wire(&record.authorization) != *authorization
                    {
                        return Err(unavailable());
                    }
                    let abandoned = operation
                        .abandon(authorization, now)
                        .map_err(|_| unavailable())?;
                    if operation.validate_transition_to(&abandoned).is_err() {
                        return Err(unavailable());
                    }
                    // Persist the no-replay decision before the
                    // outcome, exactly as Begin does.
                    record.state = "consuming".to_owned();
                    self.replace_json(&self.abandon_path(authorization.authorization_id), &record)?;
                    self.replace_json(
                        &self.operation_path(operation_id),
                        &operation_to_wire(&abandoned),
                    )?;
                    record.state = "consumed".to_owned();
                    self.replace_json(&self.abandon_path(authorization.authorization_id), &record)?;
                    // SC-DEF-69: best-effort fast-path release of this
                    // operation's MinIO restore credential, now that
                    // it is durably Abandoned.
                    let _ =
                        self.release_minio_handoff_generation(operation_id, Purpose::MinioRestore);
                    Ok(abandoned)
                })();
                durable::unlock_and_close(authorization_lock);
                result
            })();
            durable::unlock_and_close(operation_lock);
            inner
        })();
        durable::unlock_and_close(barrier_lock);
        outcome
    }

    /// `Read` — the durable record; absent is an error.
    pub fn read(&self, operation_id: Uuid) -> Result<RestoreOperation, Failure> {
        if operation_id.is_nil() {
            return Err(unavailable());
        }
        self.read_operation(operation_id)
    }

    /// `readOperation` — strict decode + operation-id match + domain
    /// validation.
    fn read_operation(&self, operation_id: Uuid) -> Result<RestoreOperation, Failure> {
        let wire_record: RestoreOperationWire =
            read_private_json(&self.operation_path(operation_id))?;
        let operation = operation_from_wire(&wire_record)?;
        if operation.operation_id != operation_id || operation.validate().is_err() {
            return Err(unavailable());
        }
        Ok(operation)
    }

    /// `restoreOperationPresent` — whether a protected restore
    /// operation record exists on disk at all; presence only, reads
    /// no content.
    #[allow(dead_code)] // slice-(b)/(c) authority surface
    pub(crate) fn restore_operation_present(&self, operation_id: Uuid) -> bool {
        if operation_id.is_nil() {
            return false;
        }
        durable::lstat(&self.operation_path(operation_id)).is_ok()
    }

    /// `InspectRestoreBarrier` — the single non-ready restore
    /// operation. Any unexpected directory entry, invalid record, or
    /// second active operation is ambiguous and therefore denies
    /// serving.
    pub fn inspect_restore_barrier(&self) -> Result<(RestoreOperation, bool), Failure> {
        let lock = self.open_lock(&self.restore_barrier_lock_path())?;
        let outcome = self.inspect_restore_barrier_locked();
        durable::unlock_and_close(lock);
        outcome
    }

    fn inspect_restore_barrier_locked(&self) -> Result<(RestoreOperation, bool), Failure> {
        durable::validate_private_directory(&self.operations, "recovery operation root")
            .map_err(|_| unavailable())?;
        let entries = durable::read_dir(&self.operations).map_err(|_| unavailable())?;
        let barrier_lock_name = format!(
            "{}.lock",
            self.restore_barrier_lock_path()
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(".barrier")
        );
        let mut active: Option<RestoreOperation> = None;
        for entry in &entries {
            let Some(name) = entry.name.to_str() else {
                return Err(unavailable());
            };
            let path = self.operations.join(name);
            if name == barrier_lock_name || valid_recovery_operation_lock_name(name) {
                let meta = durable::lstat(&path).map_err(|_| unavailable())?;
                durable::validate_private_file(&meta, "recovery operation lock")
                    .map_err(|_| unavailable())?;
                continue;
            }
            if entry.file_type.is_dir() || !name.ends_with(".json") {
                return Err(unavailable());
            }
            let wire_record: RestoreOperationWire = read_private_json(&path)?;
            let operation = operation_from_wire(&wire_record)?;
            if operation.validate().is_err()
                || name
                    != format!(
                        "{}.json",
                        generation_key(&operation.operation_id.to_string())
                    )
            {
                return Err(unavailable());
            }
            // Ready and Abandoned both stop occupying the barrier.
            if operation.is_terminal() {
                continue;
            }
            if active.is_some() {
                return Err(unavailable());
            }
            active = Some(operation);
        }
        Ok((
            active.clone().unwrap_or_else(empty_operation),
            active.is_some(),
        ))
    }

    /// `CompareAndSwap` — requires exact current equality and runs
    /// `validate_transition_to` under the barrier + operation locks.
    pub fn compare_and_swap(
        &self,
        expected: &RestoreOperation,
        next: &RestoreOperation,
    ) -> Result<(), Failure> {
        if expected.validate_transition_to(next).is_err() {
            return Err(unavailable());
        }
        let barrier_lock = self.open_lock(&self.restore_barrier_lock_path())?;
        let outcome = (|| -> Result<(), Failure> {
            let lock = self.open_lock(&self.operation_path(expected.operation_id))?;
            let result = (|| -> Result<(), Failure> {
                let current = self.read_operation(expected.operation_id)?;
                if current != *expected {
                    return Err(unavailable());
                }
                self.replace_json(
                    &self.operation_path(expected.operation_id),
                    &operation_to_wire(next),
                )?;
                if next.is_terminal() && !expected.is_terminal() {
                    // SC-DEF-69: best-effort fast-path release.
                    let _ = self.release_minio_handoff_generation(
                        expected.operation_id,
                        Purpose::MinioRestore,
                    );
                }
                Ok(())
            })();
            durable::unlock_and_close(lock);
            result
        })();
        durable::unlock_and_close(barrier_lock);
        outcome
    }

    /// `validTicket` — expiry plus the broker-key HMAC over the
    /// canonical payload.
    fn valid_ticket(&self, ticket: &RestoreTicket, now: OffsetDateTime) -> bool {
        if ticket.is_expired_at(now) {
            return false;
        }
        let expected = self
            .signing
            .fingerprint(RESTORE_TICKET_HMAC_DOMAIN, &ticket.canonical_payload());
        wire::hmac_equal(ticket.hmac.as_bytes(), expected.as_bytes())
    }

    /// `readTicket` — `(ticket, state)`.
    fn read_ticket(&self, ticket_id: Uuid) -> Result<(RestoreTicket, String), Failure> {
        let record: RestoreTicketRecordWire = read_private_json(&self.ticket_path(ticket_id))?;
        if record.ticket.ticket_id != ticket_id
            || !matches!(record.state.as_str(), "issued" | "consumed")
        {
            return Err(unavailable());
        }
        Ok((ticket_from_wire(&record.ticket), record.state))
    }

    /// `readTicketRecord` — the whole record (launch carry check).
    #[allow(dead_code)] // slice-(b)/(c) authority surface
    pub(crate) fn read_ticket_record(
        &self,
        ticket_id: Uuid,
    ) -> Result<RestoreTicketRecordWire, Failure> {
        let record: RestoreTicketRecordWire = read_private_json(&self.ticket_path(ticket_id))?;
        if record.ticket.ticket_id != ticket_id
            || !matches!(record.state.as_str(), "issued" | "consumed")
        {
            return Err(unavailable());
        }
        Ok(record)
    }

    // -- backup seals ---------------------------------------------------------

    /// `newBackupSealRecord` — mints the companion under the broker
    /// signing key for a valid proposal.
    fn new_backup_seal_record(
        &self,
        proposal: &BackupSealProposal,
        at: OffsetDateTime,
    ) -> Result<BackupSealRecord, Failure> {
        if wire::is_go_zero_time(at) || at < proposal.accepted_at || at < proposal.proposed_at {
            return Err(unavailable());
        }
        let mut companion = BackupSealCompanion {
            authority_envelope_id: format!(
                "sha256:{}",
                self.signing.fingerprint(
                    BACKUP_AUTHORITY_ENVELOPE_HMAC_DOMAIN,
                    BACKUP_SEAL_KEY_VERSION.as_bytes(),
                )
            ),
            backup_id: proposal.backup_id,
            operation_id: proposal.operation_id,
            repository_binding_id: proposal.repository_binding_id,
            target_fingerprint: proposal.target_fingerprint.clone(),
            config_fingerprint: proposal.config_fingerprint.clone(),
            payload_epoch_id: proposal.payload_epoch_id,
            root_manifest_digest: proposal.manifest_digest,
            file_tree_digest: proposal.file_tree_digest,
            sealed_at: at.to_offset(time::UtcOffset::UTC),
            hmac: String::new(),
            digest: [0u8; 32],
        };
        let payload = companion.hmac_payload().map_err(|_| unavailable())?;
        companion.hmac = self.signing.fingerprint(BACKUP_SEAL_HMAC_DOMAIN, &payload);
        let canonical = companion.canonical_json().map_err(|_| unavailable())?;
        companion.digest = Sha256::digest(&canonical).into();
        companion.verify().map_err(|_| unavailable())?;
        Ok(BackupSealRecord {
            proposal: proposal.clone(),
            companion,
            state: "committed".to_owned(),
            attestation: None,
            target_lock: None,
            completed_at: None,
        })
    }

    /// `readBackupSeal` — strict decode plus the broker-HMAC
    /// re-derivation: the stored companion must equal what this key
    /// would mint for the stored proposal.
    pub(crate) fn read_backup_seal(&self, backup_id: Uuid) -> Result<BackupSealRecord, Failure> {
        let wire_record: BackupSealRecordWire = read_private_json(&self.seal_path(backup_id))?;
        let record = seal_record_from_wire(&wire_record)?;
        if record.proposal.backup_id != backup_id
            || record.proposal.validate().is_err()
            || record.companion.verify().is_err()
            || !matches!(record.state.as_str(), "committed" | "completed")
        {
            return Err(unavailable());
        }
        let expected = self.new_backup_seal_record(&record.proposal, record.companion.sealed_at)?;
        if record.companion.authority_envelope_id != expected.companion.authority_envelope_id
            || !wire::hmac_equal(
                record.companion.hmac.as_bytes(),
                expected.companion.hmac.as_bytes(),
            )
            || record.companion.digest != expected.companion.digest
        {
            return Err(unavailable());
        }
        if record.state == "committed" {
            if record.attestation.is_some()
                || record.target_lock.is_some()
                || record.completed_at.is_some()
            {
                return Err(unavailable());
            }
        } else {
            let (Some(attestation), Some(target_lock), Some(completed_at)) = (
                record.attestation.as_ref(),
                record.target_lock.as_ref(),
                record.completed_at,
            ) else {
                return Err(unavailable());
            };
            if !attestation.binds(&record.companion)
                || target_lock.verify().is_err()
                || target_lock.operation_id != record.proposal.operation_id
                || target_lock.backup_id != record.proposal.backup_id
                || target_lock.target_lock_proof.is_empty()
                || completed_at < attestation.attested_at
                || completed_at < target_lock.asserted_at
            {
                return Err(unavailable());
            }
        }
        Ok(record)
    }

    /// `SealBackup` — the broker-owned final commit for an immutable
    /// recovery manifest. Repeating the exact proposal is idempotent;
    /// changing any bound field for an already sealed backup is
    /// denied rather than replacing history.
    pub fn seal_backup(
        &self,
        proposal: &BackupSealProposal,
    ) -> Result<BackupSealCompanion, Failure> {
        if proposal.validate().is_err() {
            return Err(unavailable());
        }
        let operation = self.read_backup(proposal.operation_id)?;
        if !same_backup_seal_operation(&operation, proposal)
            || !matches!(operation.phase, BackupPhase::Sealing | BackupPhase::Sealed)
        {
            return Err(unavailable());
        }
        if operation.phase == BackupPhase::Sealed {
            let existing = self.read_backup_seal(proposal.backup_id)?;
            if !same_backup_seal_proposal(&existing.proposal, proposal) {
                return Err(unavailable());
            }
            return Ok(existing.companion);
        }
        let record = self.new_backup_seal_record(proposal, OffsetDateTime::now_utc())?;
        let path = self.seal_path(proposal.backup_id);
        if self
            .write_exclusive_json(&path, &seal_record_to_wire(&record)?)
            .is_ok()
        {
            return Ok(record.companion);
        }
        // The create-only conflict may be a retry after an ambiguous
        // response — successful only when the already durable record
        // is byte-for-byte the same logical seal and still verifies.
        let existing = self.read_backup_seal(proposal.backup_id)?;
        if !same_backup_seal_proposal(&existing.proposal, proposal) {
            return Err(unavailable());
        }
        Ok(existing.companion)
    }

    /// `CompleteAttestedBackupSeal` — the only transition to the
    /// terminal sealed phase. The root helper supplies evidence it
    /// independently recomputed after reaping the worker tree.
    pub fn complete_attested_backup_seal(
        &self,
        operation_id: Uuid,
        launch_evidence_id: Uuid,
        attestation: &BackupRepositoryAttestation,
        target_lock: &BackupTargetLockAttestation,
    ) -> Result<BackupOperation, Failure> {
        if operation_id.is_nil()
            || launch_evidence_id.is_nil()
            || attestation.verify().is_err()
            || target_lock.verify().is_err()
            || attestation.operation_id != operation_id
            || attestation.launch_evidence_id != launch_evidence_id
            || target_lock.operation_id != operation_id
            || target_lock.launch_evidence_id != launch_evidence_id
            || target_lock.backup_id != attestation.backup_id
        {
            return Err(unavailable());
        }
        let operation_lock = self.open_lock(&self.backup_path(operation_id))?;
        let outcome = (|| -> Result<BackupOperation, Failure> {
            let expected = self.read_backup(operation_id)?;
            if !matches!(expected.phase, BackupPhase::Sealing | BackupPhase::Sealed)
                || expected.backup_id != attestation.backup_id
                || expected.accepted_facts.repository_binding_id
                    != attestation.repository_binding_id
                || expected.accepted_facts.target_lock_proof != target_lock.target_lock_proof
            {
                return Err(unavailable());
            }
            let seal_lock = self.open_lock(&self.seal_path(expected.backup_id))?;
            let result = (|| -> Result<BackupOperation, Failure> {
                let mut record = self.read_backup_seal(expected.backup_id)?;
                if !same_backup_seal_operation(&expected, &record.proposal)
                    || !attestation.binds(&record.companion)
                    || !matches!(record.state.as_str(), "committed" | "completed")
                {
                    return Err(unavailable());
                }
                let mut current = self.read_backup(expected.operation_id)?;
                if record.state == "completed" {
                    if record.attestation.as_ref() != Some(attestation)
                        || record.target_lock.as_ref() != Some(target_lock)
                        || record.completed_at != Some(current.updated_at)
                        || current.phase != BackupPhase::Sealed
                        || !same_backup_seal_operation(&current, &record.proposal)
                    {
                        return Err(unavailable());
                    }
                    return Ok(current);
                }
                if current.phase == BackupPhase::Sealing {
                    let now = OffsetDateTime::now_utc();
                    if now < current.updated_at {
                        return Err(unavailable());
                    }
                    current = current
                        .advance(BackupPhase::Sealed, now)
                        .map_err(|_| unavailable())?;
                    self.replace_json(
                        &self.backup_path(operation_id),
                        &backup_operation_to_wire(&current),
                    )?;
                } else if current.phase != BackupPhase::Sealed
                    || !same_backup_seal_operation(&current, &record.proposal)
                {
                    return Err(unavailable());
                }
                record.state = "completed".to_owned();
                record.attestation = Some(attestation.clone());
                record.target_lock = Some(target_lock.clone());
                record.completed_at = Some(current.updated_at.to_offset(time::UtcOffset::UTC));
                self.replace_json(
                    &self.seal_path(attestation.backup_id),
                    &seal_record_to_wire(&record)?,
                )?;
                // SC-DEF-69: best-effort fast-path release, now that
                // this backup is durably Sealed.
                let _ = self.release_minio_handoff_generation(operation_id, Purpose::MinioBackup);
                Ok(current)
            })();
            durable::unlock_and_close(seal_lock);
            result
        })();
        durable::unlock_and_close(operation_lock);
        outcome
    }

    /// `VerifyBackupSeal` — proves the immutable repository digest is
    /// backed by the broker's final seal. Mandatory before C03 can
    /// issue a restore ticket.
    pub fn verify_backup_seal(
        &self,
        backup_id: Uuid,
        manifest_digest: [u8; 32],
        seal_companion_digest: [u8; 32],
        file_tree_digest: [u8; 32],
        repository_manifest_digest: [u8; 32],
        repository_revision: u64,
    ) -> Result<(), Failure> {
        if backup_id.is_nil()
            || manifest_digest == [0u8; 32]
            || seal_companion_digest == [0u8; 32]
            || file_tree_digest == [0u8; 32]
            || repository_manifest_digest == [0u8; 32]
            || repository_revision == 0
        {
            return Err(unavailable());
        }
        let record = self.read_backup_seal(backup_id)?;
        if record.state != "completed"
            || record.proposal.manifest_digest != manifest_digest
            || record.proposal.file_tree_digest != file_tree_digest
            || record.companion.digest != seal_companion_digest
            || record.companion.root_manifest_digest != manifest_digest
            || record.companion.file_tree_digest != file_tree_digest
        {
            return Err(unavailable());
        }
        let Some(attestation) = record.attestation.as_ref() else {
            return Err(unavailable());
        };
        let publication = attestation.publication().map_err(|_| unavailable())?;
        if publication.repository_manifest_digest != repository_manifest_digest
            || publication.repository_revision != repository_revision
            || publication.root_manifest_digest != manifest_digest
            || publication.seal_companion_digest != seal_companion_digest
            || publication.file_tree_digest != file_tree_digest
        {
            return Err(unavailable());
        }
        let operation = self.read_backup(record.proposal.operation_id)?;
        if operation.phase != BackupPhase::Sealed
            || !same_backup_seal_operation(&operation, &record.proposal)
        {
            return Err(unavailable());
        }
        Ok(())
    }
}

fn empty_operation() -> RestoreOperation {
    RestoreOperation {
        operation_id: Uuid::nil(),
        ticket_id: Uuid::nil(),
        backup_id: Uuid::nil(),
        target: TargetIdentity::default(),
        target_fingerprint: String::new(),
        manifest_digest: String::new(),
        payload_epoch_id: Uuid::nil(),
        database_schema_version: String::new(),
        capacity_evidence_digest: String::new(),
        security_epoch: 0,
        restore_epoch: 0,
        revision: 0,
        phase: RestorePhase::Applying,
        last_checkpoint: RestoreCheckpoint::TicketConsumed,
        authority_reset_receipt_hash: String::new(),
        started_at: wire::go_zero_time(),
        updated_at: wire::go_zero_time(),
        ready_at: wire::go_zero_time(),
    }
}

#[allow(dead_code)]
fn empty_reset_record() -> RecoveryBrokerResetRecord {
    RecoveryBrokerResetRecord {
        operation_id: Uuid::nil(),
        ticket_id: Uuid::nil(),
        backup_id: Uuid::nil(),
        target_fingerprint: String::new(),
        manifest_digest: String::new(),
        restore_epoch: 0,
        security_epoch: 0,
        prepared_revision: 0,
        prepared_updated_at: wire::go_zero_time(),
        ca_fingerprint: String::new(),
        leaf_fingerprint: String::new(),
        draft_id: Uuid::nil(),
        candidate_id: Uuid::nil(),
        verifier_hash: String::new(),
        candidate_digest: String::new(),
        protected_generation_id: Uuid::nil(),
        receipt_hash: String::new(),
        committed_at: wire::go_zero_time(),
        activation: None,
        draft_released_at: wire::go_zero_time(),
        hmac: String::new(),
    }
}

// ---------------------------------------------------------------------------
// central-backup port trait impls — the journal is the production
// store behind the recovery/backup journal, sealer, verifier, and
// barrier-inspector ports.
// ---------------------------------------------------------------------------

impl central_backup::port::RestoreJournalStore for RecoveryJournalStore {
    fn begin_restore(
        &self,
        ticket: &RestoreTicket,
        authorization: &RestoreApplyAuthorization,
        at: OffsetDateTime,
    ) -> Result<RestoreOperation, Failure> {
        self.begin(ticket, authorization, at)
    }

    fn resume_restore(
        &self,
        operation_id: Uuid,
        authorization: &RestoreApplyAuthorization,
        at: OffsetDateTime,
    ) -> Result<RestoreOperation, Failure> {
        self.resume(operation_id, authorization, at)
    }

    fn abandon_restore(
        &self,
        operation_id: Uuid,
        authorization: &RestoreAbandonAuthorization,
        at: OffsetDateTime,
    ) -> Result<RestoreOperation, Failure> {
        self.abandon(operation_id, authorization, at)
    }

    fn read_restore(&self, operation_id: Uuid) -> Result<RestoreOperation, Failure> {
        self.read(operation_id)
    }

    fn compare_and_swap_restore(
        &self,
        expected: &RestoreOperation,
        next: &RestoreOperation,
    ) -> Result<(), Failure> {
        self.compare_and_swap(expected, next)
    }
}

impl central_backup::port::RestoreBarrierInspector for RecoveryJournalStore {
    fn inspect_restore_barrier(&self) -> Result<(RestoreOperation, bool), Failure> {
        self.inspect_restore_barrier()
    }
}

impl central_backup::port::BackupJournalStore for RecoveryJournalStore {
    fn create_backup(&self, operation: &BackupOperation) -> Result<(), Failure> {
        self.create_backup(operation)
    }

    fn read_backup(&self, operation_id: Uuid) -> Result<BackupOperation, Failure> {
        self.read_backup(operation_id)
    }

    fn compare_and_swap_backup(
        &self,
        expected: &BackupOperation,
        next: &BackupOperation,
    ) -> Result<(), Failure> {
        self.compare_and_swap_backup(expected, next)
    }
}

impl central_backup::port::BackupSealer for RecoveryJournalStore {
    fn seal_backup(&self, proposal: &BackupSealProposal) -> Result<BackupSealCompanion, Failure> {
        self.seal_backup(proposal)
    }
}

impl central_backup::port::BackupSealVerifier for RecoveryJournalStore {
    fn verify_backup_seal(
        &self,
        backup_id: Uuid,
        manifest_digest: [u8; 32],
        seal_companion_digest: [u8; 32],
        file_tree_digest: [u8; 32],
        repository_manifest_digest: [u8; 32],
        repository_revision: u64,
    ) -> Result<(), Failure> {
        self.verify_backup_seal(
            backup_id,
            manifest_digest,
            seal_companion_digest,
            file_tree_digest,
            repository_manifest_digest,
            repository_revision,
        )
    }
}

// ---------------------------------------------------------------------------
// Focused tests — the Rust port of the salient
// `recovery_journal_test.go` cases: restart persistence, replay
// rejection, CAS validation, barrier blocking + abandonment,
// fail-closed corruption handling, MinIO handoff scope/binding,
// and the seal + broker-reset paths.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::protected_file::ProtectedFileBackend;
    use crate::broker::testutil::TempDir;
    use central_backup::backup::operation::{
        BackupAcceptedFacts, BackupPhase, BackupSealProposal, new_backup_accepted_facts,
        new_backup_operation,
    };
    use central_backup::recovery::operation::{
        RecoveryBootstrapActivation, RecoveryBootstrapRegistration, RestorePhase,
        new_authority_reset_receipt,
    };
    use central_backup::repository::{
        BackupSealPublication, new_backup_repository_attestation,
        new_backup_target_lock_attestation,
    };
    use std::sync::Arc;

    fn now() -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
    const FP: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const FP2: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    const FP3: &str = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
    const CAP: &str = "sha256:4444444444444444444444444444444444444444444444444444444444444444";

    fn store(dir: &TempDir) -> (Arc<RecoveryJournalStore>, ProtectedFileBackend) {
        let backend = ProtectedFileBackend::new(dir.join("protected"));
        let journal =
            RecoveryJournalStore::new(dir, Arc::new(SigningService::new()), backend.clone())
                .unwrap();
        (Arc::new(journal), backend)
    }

    fn target() -> TargetIdentity {
        TargetIdentity {
            system_id: "sys-1".to_owned(),
            database_oid: "16400".to_owned(),
            database: "central".to_owned(),
            config_hash: FP.to_owned(),
            epoch: 7,
        }
    }

    fn facts() -> RestoreAdmissionFacts {
        RestoreAdmissionFacts {
            target: target(),
            target_fingerprint: FP.to_owned(),
            security_epoch: 3,
            restore_epoch: 7,
            config_fingerprint: FP2.to_owned(),
            payload_epoch_id: Uuid::now_v7(),
            database_schema_version:
                central_backup::backup::operation::BACKUP_DATABASE_SCHEMA_VERSION.to_owned(),
            capacity_evidence_digest: CAP.to_owned(),
            tool_version: "pg_restore-16.14".to_owned(),
        }
    }

    fn issue_ticket(journal: &RecoveryJournalStore) -> RestoreTicket {
        journal
            .issue(
                Uuid::now_v7(),
                "manifest-digest",
                &facts(),
                Uuid::nil(),
                now(),
            )
            .unwrap()
    }

    fn begin_restore(journal: &RecoveryJournalStore) -> (RestoreTicket, RestoreOperation) {
        let ticket = issue_ticket(journal);
        let authorization = journal
            .issue_restore_apply_authorization(&ticket, 0, 4242, now())
            .unwrap();
        let operation = journal
            .begin(&ticket, &authorization, now() + Duration::seconds(1))
            .unwrap();
        (ticket, operation)
    }

    fn sha(tag: u8) -> [u8; 32] {
        [tag; 32]
    }

    // -- ticket + begin lifecycle -------------------------------------------

    #[test]
    fn issue_persists_ticket_and_carry_across_reopen() {
        let dir = TempDir::new("recover-persist");
        let (journal, _backend) = store(&dir);
        let launch_id = Uuid::now_v7();
        let ticket = journal
            .issue(
                Uuid::now_v7(),
                "manifest-digest",
                &facts(),
                launch_id,
                now(),
            )
            .unwrap();
        assert!(!ticket.hidden_nonce.is_empty());
        assert!(ticket.expires_at > ticket.issued_at);

        let carry = journal.read_ticket_launch(ticket.operation_id).unwrap();
        assert_eq!(carry.ticket_id, ticket.ticket_id);
        assert_eq!(carry.launch_evidence_id, launch_id);
        assert!(!carry.hmac.is_empty());
        assert_eq!(carry.expires_at, ticket.expires_at);
    }

    #[test]
    fn same_signing_key_reopen_validates() {
        let dir = TempDir::new("recover-reopen");
        let signing = Arc::new(SigningService::new());
        let backend = ProtectedFileBackend::new(dir.join("protected"));
        let journal = RecoveryJournalStore::new(&dir, signing.clone(), backend.clone()).unwrap();
        let ticket = issue_ticket(&journal);
        let journal2 = RecoveryJournalStore::new(&dir, signing, backend).unwrap();
        let carry = journal2.read_ticket_launch(ticket.operation_id).unwrap();
        assert_eq!(carry.ticket_id, ticket.ticket_id);
        let (stored, state) = journal2.read_ticket(ticket.ticket_id).unwrap();
        assert_eq!(state, "issued");
        assert!(same_ticket(&stored, &ticket));
    }

    #[test]
    fn begin_consumes_ticket_and_authorization_rejects_replay() {
        let dir = TempDir::new("recover-begin");
        let (journal, _b) = store(&dir);
        let (ticket, operation) = begin_restore(&journal);
        assert_eq!(operation.phase, RestorePhase::Applying);
        assert_eq!(operation.operation_id, ticket.operation_id);

        // Ticket consumed: a second Begin on the same ticket fails.
        let authorization = journal
            .issue_restore_apply_authorization(&ticket, 0, 4243, now())
            .unwrap_err();
        assert_eq!(authorization.code(), JOURNAL_UNAVAILABLE_CODE);

        // A fabricated authorization naming the consumed ticket cannot
        // drive a second Begin either.
        let forged = RestoreApplyAuthorization {
            authorization_id: Uuid::now_v7(),
            operation_id: ticket.operation_id,
            ticket_id: ticket.ticket_id,
            issued_at: now(),
            expires_at: now() + RESTORE_APPLY_LIFETIME,
        };
        assert!(
            journal
                .begin(&ticket, &forged, now() + Duration::seconds(1))
                .is_err()
        );
    }

    #[test]
    fn barrier_blocks_second_active_restore() {
        let dir = TempDir::new("recover-barrier");
        let (journal, _b) = store(&dir);
        let (_t1, _op1) = begin_restore(&journal);
        let (operation, active) = journal.inspect_restore_barrier().unwrap();
        assert!(active);
        assert_eq!(operation.phase, RestorePhase::Applying);

        // A second Begin is refused while the first is non-terminal.
        let ticket2 = issue_ticket(&journal);
        let auth2 = journal
            .issue_restore_apply_authorization(&ticket2, 0, 5555, now())
            .unwrap();
        assert!(
            journal
                .begin(&ticket2, &auth2, now() + Duration::seconds(1))
                .is_err()
        );
    }

    #[test]
    fn resume_consumes_fresh_authorization_once() {
        let dir = TempDir::new("recover-resume");
        let (journal, _b) = store(&dir);
        let (_ticket, operation) = begin_restore(&journal);
        let auth = journal
            .issue_restore_resume_authorization_for_operation(
                operation.operation_id,
                0,
                4242,
                now(),
            )
            .unwrap();
        let resumed = journal
            .resume(operation.operation_id, &auth, now() + Duration::seconds(1))
            .unwrap();
        assert_eq!(resumed.operation_id, operation.operation_id);
        // One-use: replay is refused.
        assert!(
            journal
                .resume(operation.operation_id, &auth, now() + Duration::seconds(1))
                .is_err()
        );
    }

    #[test]
    fn abandon_terminates_and_clears_barrier() {
        let dir = TempDir::new("recover-abandon");
        let (journal, _b) = store(&dir);
        let (_ticket, operation) = begin_restore(&journal);
        let auth = journal
            .issue_restore_abandon_authorization(operation.operation_id, 0, 4242, now())
            .unwrap();
        let abandoned = journal
            .abandon(operation.operation_id, &auth, now() + Duration::seconds(1))
            .unwrap();
        assert_eq!(abandoned.phase, RestorePhase::Abandoned);
        assert!(abandoned.is_terminal());
        // Replay is refused.
        assert!(
            journal
                .abandon(operation.operation_id, &auth, now() + Duration::seconds(1))
                .is_err()
        );
        let (_op, active) = journal.inspect_restore_barrier().unwrap();
        assert!(!active);
        // Abandoned operations are not resumable.
        assert!(
            journal
                .issue_restore_resume_authorization_for_operation(
                    operation.operation_id,
                    0,
                    4242,
                    now()
                )
                .is_err()
        );
    }

    #[test]
    fn cas_requires_exact_expected_and_closed_transition() {
        let dir = TempDir::new("recover-cas");
        let (journal, _b) = store(&dir);
        let (_ticket, operation) = begin_restore(&journal);

        // Closed transition: applying -> applying/database_replaced.
        let next = operation
            .record_database_replaced(now() + Duration::seconds(2))
            .unwrap();
        journal.compare_and_swap(&operation, &next).unwrap();

        // Stale expected is refused.
        let later = next
            .begin_verification(now() + Duration::seconds(3))
            .unwrap();
        assert!(journal.compare_and_swap(&operation, &later).is_err());
        journal.compare_and_swap(&next, &later).unwrap();

        // Skipping checkpoints is refused by validate_transition_to.
        let mut forged = later.clone();
        forged.phase = RestorePhase::Ready;
        assert!(journal.compare_and_swap(&later, &forged).is_err());
    }

    #[test]
    fn corrupt_and_foreign_records_fail_closed() {
        let dir = TempDir::new("recover-corrupt");
        let (journal, _b) = store(&dir);
        let ticket = issue_ticket(&journal);
        let path = journal.ticket_path(ticket.ticket_id);

        // Truncated JSON → unavailable, never repaired.
        std::fs::write(&path, br#"{"ticket":{"TicketID":""#).unwrap();
        assert!(journal.read_ticket(ticket.ticket_id).is_err());
        assert!(
            journal
                .issue_restore_apply_authorization(&ticket, 0, 4242, now())
                .is_err()
        );

        // Unknown field → strict-decode refusal.
        std::fs::write(&path, br#"{"ticket":{},"state":"issued","launch_evidence_id":"00000000-0000-0000-0000-000000000000","issued_at":"2026-01-01T00:00:00Z","unexpected":1}"#).unwrap();
        assert!(journal.read_ticket(ticket.ticket_id).is_err());

        // World-readable record → private-file validation refusal.
        let ticket2 = issue_ticket(&journal);
        let path2 = journal.ticket_path(ticket2.ticket_id);
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path2, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(journal.read_ticket(ticket2.ticket_id).is_err());
    }

    #[test]
    fn ticket_hmac_identity_substitution_fails() {
        let dir = TempDir::new("recover-tamper");
        let (journal, _b) = store(&dir);
        let ticket = issue_ticket(&journal);
        // A caller-forged ticket with a swapped backup_id but the
        // original HMAC cannot pass valid_ticket inside Begin.
        let mut forged = ticket.clone();
        forged.backup_id = Uuid::now_v7();
        let auth = RestoreApplyAuthorization {
            authorization_id: Uuid::now_v7(),
            operation_id: ticket.operation_id,
            ticket_id: ticket.ticket_id,
            issued_at: now(),
            expires_at: now() + RESTORE_APPLY_LIFETIME,
        };
        // Write a syntactically valid issued authorization for it…
        assert!(
            journal
                .begin(&forged, &auth, now() + Duration::seconds(1))
                .is_err()
        );
    }

    // -- MinIO handoff ---------------------------------------------------------

    fn minio_request(op: Uuid, purpose: &str) -> RecoveryMinioHandoffRequest {
        let p: Purpose = purpose.parse().unwrap();
        RecoveryMinioHandoffRequest {
            operation_id: op.to_string(),
            instance_id: "central-minio".to_owned(),
            purpose: purpose.to_owned(),
            bucket: "central-artifacts-v1".to_owned(),
            key_prefix: minio_recovery_key_scope(p).unwrap().to_owned(),
            policy_digest: minio_recovery_policy_digest(p, "central-artifacts-v1").unwrap(),
            expires_at: now() + Duration::minutes(10),
            fence_token: 9,
        }
    }

    #[test]
    fn minio_handoff_binds_scope_and_releases_generation() {
        let dir = TempDir::new("recover-minio");
        let (journal, backend) = store(&dir);
        let op = Uuid::now_v7();
        let request = minio_request(op, "minio_restore_v1");
        let receipt = journal.issue_minio_handoff(&request).unwrap();
        assert!(!receipt.bound);
        assert_eq!(receipt.fence_token, 9);

        // Idempotent re-issue returns the same receipt.
        let again = journal.issue_minio_handoff(&request).unwrap();
        assert_eq!(again.receipt_id, receipt.receipt_id);

        let descriptor = MinioProvisionedDescriptor {
            service: "minio-provision".to_owned(),
            target: "sealed_memfd".to_owned(),
            uid: MINIO_PROVISIONER_UID,
            gid: MINIO_PROVISIONER_GID,
            bucket: receipt.bucket.clone(),
            key_prefix: receipt.key_prefix.clone(),
            policy_digest: receipt.policy_digest.clone(),
            purpose: receipt.purpose.clone(),
            operation_id: receipt.operation_id.clone(),
            instance_id: receipt.instance_id.clone(),
            receipt_id: receipt.receipt_id.clone(),
            expires_at: receipt.expires_at,
            fence_token: receipt.fence_token,
        };
        // A descriptor that echoes a different scope is refused.
        let mut wrong = descriptor.clone();
        wrong.key_prefix = "other".to_owned();
        assert!(
            journal
                .bind_minio_handoff(&wrong, b"secret", now())
                .is_err()
        );

        journal
            .bind_minio_handoff(&descriptor, b"minio-credential", now())
            .unwrap();
        // Binding is one-use.
        assert!(
            journal
                .bind_minio_handoff(&descriptor, b"minio-credential", now())
                .is_err()
        );

        let (generation, bound) = journal
            .resolve_bound_minio_handoff(op, Purpose::MinioRestore)
            .unwrap();
        // `record.Receipt` returns verbatim — `bound` is the stored
        // flag, never flipped at bind (upstream identical).
        assert_eq!(bound.receipt_id, receipt.receipt_id);
        assert_eq!(bound.operation_id, op.to_string());
        assert_eq!(backend.read(&generation).unwrap(), b"minio-credential");

        journal
            .release_minio_handoff_generation(op, Purpose::MinioRestore)
            .unwrap();
        assert!(
            journal
                .resolve_bound_minio_handoff(op, Purpose::MinioRestore)
                .is_err()
                || backend.read(&generation).is_err()
        );
    }

    #[test]
    fn minio_request_out_of_scope_is_refused() {
        let dir = TempDir::new("recover-minio-scope");
        let (journal, _b) = store(&dir);
        let mut request = minio_request(Uuid::now_v7(), "minio_restore_v1");
        request.key_prefix = "not-the-scope".to_owned();
        assert!(journal.issue_minio_handoff(&request).is_err());
        let mut expired = minio_request(Uuid::now_v7(), "minio_restore_v1");
        expired.expires_at = now() - Duration::seconds(1);
        assert!(journal.issue_minio_handoff(&expired).is_err());
    }

    // -- backup operations + seals ----------------------------------------------

    fn backup_facts(binding_id: Uuid, proof: &str) -> BackupAcceptedFacts {
        new_backup_accepted_facts(
            // `database_time` becomes `accepted_at`; the journal
            // refuses a seal whose acceptance lies in the future.
            now(),
            FP,
            FP2,
            Uuid::now_v7(),
            binding_id,
            proof,
        )
        .unwrap()
    }

    fn drive_to_sealing(
        journal: &RecoveryJournalStore,
        proof: &str,
    ) -> (BackupOperation, BackupOperation) {
        let binding_id = Uuid::now_v7();
        let operation =
            new_backup_operation(Uuid::now_v7(), Uuid::now_v7(), target(), now()).unwrap();
        journal.create_backup(&operation).unwrap();
        let admitted = operation.accept(backup_facts(binding_id, proof)).unwrap();
        journal
            .compare_and_swap_backup(&operation, &admitted)
            .unwrap();
        // Real clock timestamps: the seal-completion path refuses a
        // `updated_at` that lies in the future.
        let dumping = admitted.advance(BackupPhase::Dumping, now()).unwrap();
        journal
            .compare_and_swap_backup(&admitted, &dumping)
            .unwrap();
        let inventory = dumping.advance(BackupPhase::Inventory, now()).unwrap();
        journal
            .compare_and_swap_backup(&dumping, &inventory)
            .unwrap();
        let sealing = inventory.advance(BackupPhase::Sealing, now()).unwrap();
        journal
            .compare_and_swap_backup(&inventory, &sealing)
            .unwrap();
        (operation, sealing)
    }

    fn seal_proposal_for(operation: &BackupOperation) -> BackupSealProposal {
        use central_backup::backup::inventory::{InventoryEntry, new_inventory_chunk};
        use central_backup::backup::manifest::new_seal_root_manifest;
        use central_backup::backup::operation::DumpEvidence;
        let manifest = new_seal_root_manifest(
            operation,
            DumpEvidence {
                size: 4096,
                digest: [7u8; 32],
            },
            &[new_inventory_chunk(
                0,
                vec![InventoryEntry {
                    artifact_id: Uuid::from_bytes([1u8; 16]),
                    checksum: [2u8; 32],
                    size: 100,
                }],
            )
            .unwrap()],
        )
        .unwrap();
        let manifest_json = manifest.canonical_json().unwrap();
        BackupSealProposal {
            operation_id: operation.operation_id,
            backup_id: operation.backup_id,
            target: operation.target.clone(),
            accepted_at: operation.accepted_at,
            repository_binding_id: operation.accepted_facts.repository_binding_id,
            target_fingerprint: operation.accepted_facts.target_fingerprint.clone(),
            config_fingerprint: operation.accepted_facts.config_fingerprint.clone(),
            payload_epoch_id: operation.accepted_facts.payload_epoch_id,
            manifest_digest: Sha256::digest(&manifest_json).into(),
            root_manifest_json: manifest_json,
            file_tree_digest: sha(0xbb),
            // `proposed_at >= accepted_at` and `newBackupSealRecord`
            // refuses a future timestamp — pin to `accepted_at`.
            proposed_at: operation.accepted_at,
        }
    }

    #[test]
    fn backup_seal_commits_and_attested_completion_verifies() {
        let dir = TempDir::new("recover-seal");
        let (journal, _b) = store(&dir);
        let proof = [0xabu8; 32];
        let proof_str = format!("sha256:{}", wire::hex_encode(&proof));
        let (_planned, sealing) = drive_to_sealing(&journal, &proof_str);
        let proposal = seal_proposal_for(&sealing);

        let companion = journal.seal_backup(&proposal).unwrap();
        // Idempotent replay of the identical proposal.
        let again = journal.seal_backup(&proposal).unwrap();
        assert_eq!(again.digest, companion.digest);
        // A different proposal for the same backup is refused.
        let mut other = proposal.clone();
        other.manifest_digest = sha(0xcc);
        assert!(journal.seal_backup(&other).is_err());

        // Attested completion binds launch + attestation + target lock.
        let launch_evidence_id = Uuid::now_v7();
        let publication = BackupSealPublication {
            operation_id: sealing.operation_id,
            backup_id: sealing.backup_id,
            repository_binding_id: sealing.accepted_facts.repository_binding_id,
            root_manifest_digest: proposal.manifest_digest,
            seal_companion_digest: companion.digest,
            file_tree_digest: proposal.file_tree_digest,
            repository_manifest_digest: sha(0xdd),
            repository_revision: 3,
        };
        let attestation =
            new_backup_repository_attestation(launch_evidence_id, &publication, now()).unwrap();
        let supervisor_launch_id = Uuid::now_v7();
        let target_lock = new_backup_target_lock_attestation(
            supervisor_launch_id,
            launch_evidence_id,
            sealing.operation_id,
            sealing.backup_id,
            proof,
            now(),
        )
        .unwrap();

        // Wrong launch evidence is refused.
        let sealed = journal.complete_attested_backup_seal(
            sealing.operation_id,
            Uuid::now_v7(),
            &attestation,
            &target_lock,
        );
        assert!(sealed.is_err());

        let sealed = journal
            .complete_attested_backup_seal(
                sealing.operation_id,
                launch_evidence_id,
                &attestation,
                &target_lock,
            )
            .unwrap();
        assert_eq!(sealed.phase, BackupPhase::Sealed);
        // Replay of the same completion is idempotent.
        let sealed2 = journal
            .complete_attested_backup_seal(
                sealing.operation_id,
                launch_evidence_id,
                &attestation,
                &target_lock,
            )
            .unwrap();
        assert_eq!(sealed2, sealed);

        journal
            .verify_backup_seal(
                sealing.backup_id,
                proposal.manifest_digest,
                companion.digest,
                proposal.file_tree_digest,
                sha(0xdd),
                3,
            )
            .unwrap();
        // Wrong repository revision fails closed.
        assert!(
            journal
                .verify_backup_seal(
                    sealing.backup_id,
                    proposal.manifest_digest,
                    companion.digest,
                    proposal.file_tree_digest,
                    sha(0xdd),
                    4,
                )
                .is_err()
        );
    }

    // -- broker reset / bootstrap take -------------------------------------------

    #[test]
    fn take_bootstrap_presents_plaintext_once() {
        let dir = TempDir::new("recover-bootstrap");
        let (journal, backend) = store(&dir);
        let (_ticket, operation) = begin_restore(&journal);
        let op2 = operation
            .record_database_replaced(now() + Duration::seconds(2))
            .unwrap();
        journal.compare_and_swap(&operation, &op2).unwrap();
        let op3 = op2
            .begin_verification(now() + Duration::seconds(3))
            .unwrap();
        journal.compare_and_swap(&op2, &op3).unwrap();
        let op4 = op3
            .record_inventory_verified(now() + Duration::seconds(4))
            .unwrap();
        journal.compare_and_swap(&op3, &op4).unwrap();

        // Broker reset record prepared at verifying/inventory_verified.
        let generation = backend
            .create("recovery-bootstrap", b"bootstrap-token")
            .unwrap();
        let mut record = journal
            .new_broker_reset_record(
                &op4,
                &"a".repeat(64),
                &"b".repeat(64),
                Uuid::now_v7(),
                Uuid::now_v7(),
                generation.generation_id,
                sha(0x11),
                sha(0x22),
                now() + Duration::seconds(4),
            )
            .unwrap();

        // Registration + activation record chain to reach Ready.
        let registration = RecoveryBootstrapRegistration {
            operation_id: op4.operation_id,
            draft_id: record.draft_id,
            candidate_id: record.candidate_id,
            generation: 1,
            verifier_hash: sha(0x11),
            candidate_digest: sha(0x22),
            broker_receipt_hash: record.receipt_hash.clone(),
            database_receipt_hash: FP3.to_owned(),
            registered_at: now() + Duration::seconds(5),
        };
        let activation = RecoveryBootstrapActivation {
            operation_id: op4.operation_id,
            draft_id: record.draft_id,
            candidate_id: record.candidate_id,
            generation: 1,
            database_receipt_hash: FP3.to_owned(),
            activation_receipt_hash: FP.to_owned(),
            activated_at: now() + Duration::seconds(5),
        };
        let receipt = new_authority_reset_receipt(
            &op4,
            &registration,
            &activation,
            now() + Duration::seconds(6),
        )
        .unwrap();
        let op5 = op4.record_authority_reset(&receipt).unwrap();
        journal.compare_and_swap(&op4, &op5).unwrap();
        let op6 = op5.mark_ready(now() + Duration::seconds(7)).unwrap();
        journal.compare_and_swap(&op5, &op6).unwrap();

        record.activation = Some(RecoveryBootstrapActivationRecord {
            generation: 1,
            database_receipt_hash: FP3.to_owned(),
            activation_receipt_hash: FP.to_owned(),
            activated_at: now() + Duration::seconds(5),
            presented_at: wire::go_zero_time(),
        });
        journal.sign_broker_reset_record(&mut record).unwrap();
        journal
            .replace_json(&journal.broker_reset_path(op4.operation_id), &record)
            .unwrap();

        let value = journal.take_activated_recovery_bootstrap().unwrap();
        assert_eq!(value, b"bootstrap-token");
        // Presented-once: a second take is refused, and the protected
        // generation is gone.
        assert!(journal.take_activated_recovery_bootstrap().is_err());
        assert!(backend.read(&generation).is_err());
    }

    #[test]
    fn abandoned_operation_releases_its_bootstrap_generation() {
        let dir = TempDir::new("recover-abandon-release");
        let (journal, backend) = store(&dir);
        let (_ticket, operation) = begin_restore(&journal);
        let op2 = operation
            .record_database_replaced(now() + Duration::seconds(2))
            .unwrap();
        journal.compare_and_swap(&operation, &op2).unwrap();
        let op3 = op2
            .begin_verification(now() + Duration::seconds(3))
            .unwrap();
        journal.compare_and_swap(&op2, &op3).unwrap();
        let op4 = op3
            .record_inventory_verified(now() + Duration::seconds(4))
            .unwrap();
        journal.compare_and_swap(&op3, &op4).unwrap();

        let generation = backend
            .create("recovery-bootstrap", b"draft-token")
            .unwrap();
        let record = journal
            .new_broker_reset_record(
                &op4,
                &"a".repeat(64),
                &"b".repeat(64),
                Uuid::now_v7(),
                Uuid::now_v7(),
                generation.generation_id,
                sha(0x11),
                sha(0x22),
                now() + Duration::seconds(4),
            )
            .unwrap();
        journal
            .replace_json(&journal.broker_reset_path(op4.operation_id), &record)
            .unwrap();

        // Abandon the operation; the next take-scan releases the
        // draft generation without ever reading it.
        let auth = journal
            .issue_restore_abandon_authorization(op4.operation_id, 0, 4242, now())
            .unwrap();
        let abandoned = journal
            .abandon(op4.operation_id, &auth, now() + Duration::seconds(4))
            .unwrap();
        assert!(abandoned.is_terminal());

        // No Ready operation exists, so take fails — but the sweep has
        // already released the abandoned sibling's generation.
        assert!(journal.take_activated_recovery_bootstrap().is_err());
        assert!(backend.read(&generation).is_err());
    }
}

#[cfg(test)]
mod debug_tests {
    use super::*;
    use crate::broker::protected_file::ProtectedFileBackend;
    use crate::broker::testutil::TempDir;
    use central_backup::domain::TargetIdentity;
    use central_backup::port::RestoreAdmissionFacts;
    use std::sync::Arc;
    use uuid::Uuid;

    fn now() -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
    const FP: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    fn debug_issue_apply_steps() {
        let dir = TempDir::new("dbg");
        let signing = Arc::new(SigningService::new());
        let backend = ProtectedFileBackend::new(dir.join("protected"));
        let journal = RecoveryJournalStore::new(&dir, signing, backend).unwrap();
        let facts = RestoreAdmissionFacts {
            target: TargetIdentity {
                system_id: "sys-1".into(),
                database_oid: "16400".into(),
                database: "central".into(),
                config_hash: FP.into(),
                epoch: 7,
            },
            target_fingerprint: FP.into(),
            security_epoch: 3,
            restore_epoch: 7,
            config_fingerprint: FP.into(),
            payload_epoch_id: Uuid::now_v7(),
            database_schema_version: "central.schema-manifest/v1".into(),
            capacity_evidence_digest: FP.into(),
            tool_version: "pg_restore-16.14".into(),
        };
        let ticket = journal
            .issue(Uuid::now_v7(), "m", &facts, Uuid::nil(), now())
            .unwrap();
        eprintln!("issue ok");
        let lock = journal.open_lock(&journal.ticket_path(ticket.ticket_id));
        eprintln!("lock: {:?}", lock.is_ok());
        if let Ok(fd) = lock {
            durable::unlock_and_close(fd);
        }
        let (stored, state) = journal.read_ticket(ticket.ticket_id).unwrap();
        eprintln!("read_ticket ok state={state}");
        eprintln!("same_ticket={}", same_ticket(&stored, &ticket));
        eprintln!("valid_ticket={}", journal.valid_ticket(&ticket, now()));
        let res = journal.issue_restore_apply_authorization(&ticket, 0, 4242, now());
        eprintln!("issue_apply: {:?}", res.is_ok());
        let auth = res.unwrap();
        eprintln!("binds={}", auth.binds(&ticket));
        // begin() internals, step by step:
        eprintln!(
            "barrier lock: {:?}",
            journal
                .open_lock(&journal.restore_barrier_lock_path())
                .is_ok()
        );
        let bl = journal
            .open_lock(&journal.restore_barrier_lock_path())
            .unwrap();
        eprintln!(
            "inspect: {:?}",
            journal.inspect_restore_barrier_locked().map(|(_, a)| a)
        );
        let tl = journal.open_lock(&journal.ticket_path(ticket.ticket_id));
        eprintln!("ticket lock: {:?}", tl.is_ok());
        let al = journal.open_lock(&journal.apply_path(auth.authorization_id));
        eprintln!("apply lock: {:?}", al.is_ok());
        eprintln!(
            "carry: {:?}",
            journal
                .read_ticket_launch(ticket.operation_id)
                .map(|c| (c.ticket_id, c.launch_evidence_id))
        );
        let rec: Result<RestoreApplyRecordWire, _> =
            read_private_json(&journal.apply_path(auth.authorization_id));
        eprintln!("apply rec: {:?}", rec.map(|r| r.state));
        eprintln!(
            "new op: {:?}",
            new_restore_operation(&ticket, now()).map(|o| o.revision)
        );
        eprintln!("auth valid_at now(): {}", auth.valid_at(now()));
        {
            let mut ar: RestoreApplyRecordWire =
                read_private_json(&journal.apply_path(auth.authorization_id)).unwrap();
            eprintln!(
                "auth eq: {}",
                apply_authorization_from_wire(&ar.authorization) == auth
            );
            ar.state = "consuming".into();
            eprintln!(
                "replace consuming: {:?}",
                journal.replace_json(&journal.apply_path(auth.authorization_id), &ar)
            );
            ar.state = "issued".into();
            eprintln!(
                "restore issued: {:?}",
                journal.replace_json(&journal.apply_path(auth.authorization_id), &ar)
            );
        }
        {
            let op = new_restore_operation(&ticket, now()).unwrap();
            eprintln!(
                "write op: {:?}",
                journal.write_exclusive_json(
                    &journal.operation_path(op.operation_id),
                    &operation_to_wire(&op)
                )
            );
            std::fs::remove_file(journal.operation_path(op.operation_id)).unwrap();
        }
        if let Ok(fd) = al {
            durable::unlock_and_close(fd);
        }
        if let Ok(fd) = tl {
            durable::unlock_and_close(fd);
        }
        durable::unlock_and_close(bl);
        let out = journal.begin(&ticket, &auth, now());
        eprintln!("begin: {:?}", out.map(|o| o.revision));
    }
}
