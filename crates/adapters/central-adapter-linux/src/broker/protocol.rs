//! The broker wire protocol — the port of upstream `server.go`'s
//! frame markers, strict request decoder, framed transport readers,
//! peer predicates, and denial encoders.
//!
//! Layout on the connection: the first byte selects the transport.
//! A *marker* byte (`0xB1`, `0xB2`, `0xB4`, `0xB5`, `0xC1`..`0xC5`)
//! introduces a length-prefixed or descriptor-carried frame; every
//! other first byte begins an ordinary newline-terminated JSON
//! `BrokerRequest` line (the byte is itself part of the line — the
//! scanner is a `MultiReader` of the marker byte plus the stream).
//!
//! Framed reads are `u32` big-endian length + payload: valid sizes are
//! `1..=64 KiB`; the length is refused, never clamped. The JSON request
//! decoder is strict: object-shaped, no duplicate fields, no unknown
//! fields, no trailing data — Go's `decodeBrokerRequest` verbatim,
//! including the `null`/`{}` payload distinction `BrokerRequest` keeps.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use central_foundation::failure::Failure;
use central_infra::authority::{
    BrokerOutcome, BrokerRequest, BrokerResponse, MinioProvisionedDescriptor,
};

use crate::sys::peercred::PeerCred;

// ---------------------------------------------------------------------------
// Frame markers and sizes (server.go)
// ---------------------------------------------------------------------------

/// `b04FrameMarker` — B04 `materialize_minio_root` framed transport.
pub const B04_FRAME_MARKER: u8 = 0xb4;
/// `b05MigrationFrameMarker` — B05 `materialize_postgres_migration`.
pub const B05_MIGRATION_FRAME_MARKER: u8 = 0xb5;
/// `b10MinioRuntimeFrameMarker` — B10 outbound `minio_runtime_v1`
/// delivery to the runtime or the provisioner (ADR 0013 widened).
pub const B10_MINIO_RUNTIME_FRAME_MARKER: u8 = 0xb1;
/// `b10ProvisionedFrameMarker` — B10 inbound sealed-memfd descriptor
/// transport from `minio-provision`.
pub const B10_PROVISIONED_FRAME_MARKER: u8 = 0xb2;
/// `backupWorkerCredentialFrameMarker` — R6 backup worker credential.
pub const BACKUP_WORKER_CREDENTIAL_FRAME_MARKER: u8 = 0xc1;
/// `restoreMigrationCredentialFrameMarker` — R6 restore credential.
pub const RESTORE_MIGRATION_CREDENTIAL_FRAME_MARKER: u8 = 0xc2;
/// `restoreCapacityReserveFrameMarker` — R6 capacity reserve.
pub const RESTORE_CAPACITY_RESERVE_FRAME_MARKER: u8 = 0xc3;
/// `restoreCapacityReceiptFrameMarker` — R6 capacity receipt.
pub const RESTORE_CAPACITY_RECEIPT_FRAME_MARKER: u8 = 0xc4;
/// `restoreCapacityReserveInspectionFrameMarker` — R6 inspection.
pub const RESTORE_CAPACITY_RESERVE_INSPECTION_FRAME_MARKER: u8 = 0xc5;

/// The B04/B05/B10 `size > 64*1024` refusal bound.
pub const MAX_FRAME_SIZE: u32 = 64 * 1024;
/// `maxB10ProvisionedFrameSize` — the single-`recvmsg` buffer for the
/// provisioned descriptor frame; SCM_RIGHTS rides with the bytes read
/// in that call, so the buffer must hold the whole message up front.
pub const MAX_B10_PROVISIONED_FRAME_SIZE: usize = 64 * 1024;
/// The ordinary-request scanner bound (`bufio.Scanner` 65536).
pub const MAX_REQUEST_LINE: usize = 64 * 1024;

/// `brokerConnectionDeadline` — one second for the initial framed
/// exchange and every pre-authentication denial.
pub const BROKER_CONNECTION_DEADLINE_MS: u64 = 1000;

/// `SO_PEERCRED`-attested identities (upstream `authority` /
/// `secretbootstrap` constants).
pub const CENTRAL_RUNTIME_UID: u32 = 501;
/// Runtime GID — `authority.CentralRuntimeGID`.
pub const CENTRAL_RUNTIME_GID: u32 = 501;
/// `secretbootstrap.MinioProvisionerUID`.
pub const MINIO_PROVISIONER_UID: u32 = 1000;
/// `secretbootstrap.MinioProvisionerGID`.
pub const MINIO_PROVISIONER_GID: u32 = 1000;
/// `authority.CentralMigrateUID`.
pub const CENTRAL_MIGRATE_UID: u32 = 986;
/// `authority.CentralMigrateGID`.
pub const CENTRAL_MIGRATE_GID: u32 = 986;

// ---------------------------------------------------------------------------
// Purpose vocabulary
// ---------------------------------------------------------------------------

// Task-6 purposes: migration proof + provisioning RPCs, lifecycle.
pub const MIGRATION_ISSUE_EMPTY_PROOF_RPC: &str = "migration_issue_empty_proof";
pub const MIGRATION_VERIFY_EMPTY_PROOF_RPC: &str = "migration_verify_empty_proof";
pub const MIGRATION_CONSUME_EMPTY_PROOF_RPC: &str = "migration_consume_empty_proof";
pub const MIGRATION_ISSUE_RESET_RPC: &str = "migration_issue_reset_confirmation";
pub const MIGRATION_VERIFY_RESET_RPC: &str = "migration_verify_reset_confirmation";
pub const MIGRATION_CONSUME_RESET_RPC: &str = "migration_consume_reset_confirmation";
pub const MIGRATION_READ_RECORD_RPC: &str = "migration_read_provisioning_record";
pub const MIGRATION_CREATE_RECORD_RPC: &str = "migration_create_provisioning_record";
pub const MIGRATION_REPLACE_RECORD_RPC: &str = "migration_replace_provisioning_record";
pub const MIGRATION_REPORT_OUTCOME_RPC: &str = "migration_report_launch_outcome";
pub const MIGRATION_READ_OUTCOME_RPC: &str = "migration_read_launch_outcome";
pub const MIGRATION_RECORD_ABSENT_CODE: &str = "PROVISIONING_RECORD_ABSENT";
pub const ISSUE_MIGRATION_LAUNCH_RPC: &str = "issue_migration_launch";
pub const AUTHORIZE_LIFECYCLE_RPC: &str = "authorize_lifecycle";
pub const CONSUME_LIFECYCLE_RPC: &str = "consume_lifecycle";
pub const VERIFY_LIFECYCLE_LOCK_OWNER_RPC: &str = "verify_lifecycle_lock_owner";
pub const HMAC_FINGERPRINT_RPC: &str = "hmac_fingerprint";
pub const PRESENT_BOOTSTRAP_RPC: &str = "present_bootstrap";
pub const REGISTER_BOOTSTRAP_CANDIDATE_RPC: &str = "register_bootstrap_candidate";
pub const ACTIVATE_BOOTSTRAP_CANDIDATE_RPC: &str = "activate_bootstrap_candidate";
pub const MATERIALIZE_DEPENDENCY_HANDOFF_RPC: &str = "materialize_dependency_handoff";
pub const CREATE_PROTECTED_GENERATION_RPC: &str = "create_protected_generation";
pub const SIGN_LEAF_RPC: &str = "sign_leaf";
pub const MATERIALIZE_MINIO_ROOT_RPC: &str = "materialize_minio_root";
pub const MATERIALIZE_POSTGRES_MIGRATION_RPC: &str = "materialize_postgres_migration";
pub const MATERIALIZE_MINIO_RUNTIME_RPC: &str = "materialize_minio_runtime";
pub const ADOPT_B03_MINIO_BOOTSTRAP_RPC: &str = "adopt_b03_minio_bootstrap";
pub const ISSUE_B04_LIFECYCLE_PROOF_RPC: &str = "issue_b04_lifecycle_proof";

// R6 surface — registered so they deny with the slice's exact closed
// outcome, never "unknown purpose".
pub const BACKUP_ISSUE_LAUNCH_RPC: &str = "backup_issue_launch";
pub const BACKUP_ISSUE_MINIO_RPC: &str = "backup_issue_minio_handoff";
pub const BACKUP_SEAL_RPC: &str = "backup_seal_for_launch";
pub const BACKUP_MARK_REAPED_RPC: &str = "backup_mark_launch_reaped";
pub const BACKUP_COMPLETE_RPC: &str = "backup_complete_attested_seal";
pub const BACKUP_VERIFY_SEAL_RPC: &str = "backup_verify_seal";
pub const BACKUP_READ_STATUS_RPC: &str = "backup_read_status";
pub const BACKUP_WORKER_CONTEXT_RPC: &str = "backup_worker_context";
pub const BACKUP_WORKER_EPOCH_RPC: &str = "backup_worker_active_payload_epoch";
pub const BACKUP_WORKER_THROUGHPUT_RPC: &str = "backup_worker_read_throughput";
pub const BACKUP_WORKER_CREATE_RPC: &str = "backup_worker_create_operation";
pub const BACKUP_WORKER_READ_RPC: &str = "backup_worker_read_operation";
pub const BACKUP_WORKER_CAS_RPC: &str = "backup_worker_cas_operation";
pub const BACKUP_THROUGHPUT_ISSUE_LAUNCH_RPC: &str = "backup_throughput_issue_launch";
pub const BACKUP_THROUGHPUT_READ_LAUNCH_RPC: &str = "backup_throughput_read_launch";
pub const BACKUP_THROUGHPUT_FIXTURE_LOADED_RPC: &str = "backup_throughput_fixture_loaded";
pub const BACKUP_THROUGHPUT_WORKER_CONTEXT_RPC: &str = "backup_throughput_worker_context";
pub const BACKUP_THROUGHPUT_WORKER_TARGET_RPC: &str = "backup_throughput_worker_target_locked";
pub const BACKUP_THROUGHPUT_WORKER_STAGE_RPC: &str = "backup_throughput_worker_stage";
pub const BACKUP_THROUGHPUT_ACCEPT_RPC: &str = "backup_throughput_accept";
pub const BACKUP_THROUGHPUT_CURRENT_RPC: &str = "backup_throughput_current_attempt";
pub const BACKUP_THROUGHPUT_COMPLETE_PENDING_RPC: &str = "backup_throughput_complete_pending";
pub const BACKUP_THROUGHPUT_ACTIVATE_RPC: &str = "backup_throughput_activate";
pub const BACKUP_THROUGHPUT_FAILED_RPC: &str = "backup_throughput_failed";
pub const BACKUP_THROUGHPUT_CLEANUP_REQUIRED_RPC: &str = "backup_throughput_cleanup_required";
pub const BACKUP_THROUGHPUT_CLEANUP_RESOLVED_RPC: &str = "backup_throughput_cleanup_resolved";
pub const BACKUP_ENSURE_PAYLOAD_EPOCH_RPC: &str = "backup_ensure_payload_epoch";
pub const RESTORE_ISSUE_LAUNCH_RPC: &str = "restore_issue_launch";
pub const RESTORE_APPLY_AUTHORIZATION_RPC: &str = "issue_restore_apply_authorization";
pub const RESTORE_RESUME_AUTHORIZATION_RPC: &str = "issue_restore_resume_authorization";
pub const RESTORE_ABANDON_AUTHORIZATION_RPC: &str = "issue_restore_abandon_authorization";
pub const RESTORE_ABANDON_RPC: &str = "abandon_restore";
pub const RESTORE_BARRIER_INSPECT_RPC: &str = "inspect_restore_barrier";
pub const RESTORE_TICKET_BARRIER_INSPECT_RPC: &str = "inspect_restore_ticket_barrier";
pub const RESTORE_BROKER_AUTHORITY_PREPARE_RPC: &str = "prepare_recovery_broker_authority";
pub const RESTORE_BOOTSTRAP_ACTIVATE_RPC: &str = "activate_recovery_bootstrap";
pub const POSTGRES_SERVICE_ROLE_BIND_RPC: &str = "bind_postgres_service_role";
pub const ADVISORY_EVALUATION_JOURNAL_RPC: &str = "append_advisory_evaluation";

/// The slice's closed-denial convention for every R6 operation the R5
/// broker registers but does not implement (plan §"Scope split").
pub const UNSUPPORTED_IN_THIS_SLICE: &str = "unsupported in this slice";

/// `isMigrationAuthorityPurpose` — the migration peer's own purposes.
#[must_use]
pub fn is_migration_authority_purpose(purpose: &str) -> bool {
    matches!(
        purpose,
        MIGRATION_ISSUE_EMPTY_PROOF_RPC
            | MIGRATION_VERIFY_EMPTY_PROOF_RPC
            | MIGRATION_CONSUME_EMPTY_PROOF_RPC
            | MIGRATION_ISSUE_RESET_RPC
            | MIGRATION_VERIFY_RESET_RPC
            | MIGRATION_CONSUME_RESET_RPC
            | MIGRATION_READ_RECORD_RPC
            | MIGRATION_CREATE_RECORD_RPC
            | MIGRATION_REPLACE_RECORD_RPC
            | MIGRATION_REPORT_OUTCOME_RPC
            | RESTORE_BROKER_AUTHORITY_PREPARE_RPC
            | RESTORE_BOOTSTRAP_ACTIVATE_RPC
    )
}

/// `isRecoveryAuthorityPurpose` — recovery mutations the migration
/// peer alone may even reach Dispatch with.
#[must_use]
pub fn is_recovery_authority_purpose(purpose: &str) -> bool {
    matches!(
        purpose,
        RESTORE_BROKER_AUTHORITY_PREPARE_RPC | RESTORE_BOOTSTRAP_ACTIVATE_RPC
    )
}

/// `isBootstrapAuthorityPurpose` — bootstrap-session purposes a
/// migration peer is never allowed to invoke.
#[must_use]
pub fn is_bootstrap_authority_purpose(purpose: &str) -> bool {
    matches!(
        purpose,
        REGISTER_BOOTSTRAP_CANDIDATE_RPC | ACTIVATE_BOOTSTRAP_CANDIDATE_RPC | PRESENT_BOOTSTRAP_RPC
    )
}

/// `isBackupWorkerAuthorityPurpose` — backup worker purposes bound to
/// the worker launch store's runtime identity.
#[must_use]
pub fn is_backup_worker_authority_purpose(purpose: &str) -> bool {
    matches!(
        purpose,
        BACKUP_SEAL_RPC
            | BACKUP_WORKER_CONTEXT_RPC
            | BACKUP_WORKER_CREATE_RPC
            | BACKUP_WORKER_EPOCH_RPC
            | BACKUP_WORKER_THROUGHPUT_RPC
            | BACKUP_WORKER_READ_RPC
            | BACKUP_WORKER_CAS_RPC
            | BACKUP_THROUGHPUT_WORKER_CONTEXT_RPC
            | BACKUP_THROUGHPUT_WORKER_TARGET_RPC
            | BACKUP_THROUGHPUT_WORKER_STAGE_RPC
    )
}

/// `isBackupHelperAuthorityPurpose` — root-helper backup purposes.
#[must_use]
pub fn is_backup_helper_authority_purpose(purpose: &str) -> bool {
    matches!(
        purpose,
        BACKUP_ISSUE_LAUNCH_RPC
            | BACKUP_THROUGHPUT_ISSUE_LAUNCH_RPC
            | BACKUP_THROUGHPUT_READ_LAUNCH_RPC
            | BACKUP_THROUGHPUT_FIXTURE_LOADED_RPC
            | BACKUP_ISSUE_MINIO_RPC
            | BACKUP_MARK_REAPED_RPC
            | BACKUP_COMPLETE_RPC
            | BACKUP_VERIFY_SEAL_RPC
            | BACKUP_READ_STATUS_RPC
            | BACKUP_THROUGHPUT_CURRENT_RPC
            | BACKUP_THROUGHPUT_ACCEPT_RPC
            | BACKUP_THROUGHPUT_COMPLETE_PENDING_RPC
            | BACKUP_THROUGHPUT_ACTIVATE_RPC
            | BACKUP_THROUGHPUT_FAILED_RPC
            | BACKUP_THROUGHPUT_CLEANUP_REQUIRED_RPC
            | BACKUP_THROUGHPUT_CLEANUP_RESOLVED_RPC
            | BACKUP_ENSURE_PAYLOAD_EPOCH_RPC
    )
}

/// `isRestoreHelperAuthorityPurpose` — root-helper restore purposes.
#[must_use]
pub fn is_restore_helper_authority_purpose(purpose: &str) -> bool {
    purpose == RESTORE_ISSUE_LAUNCH_RPC
}

/// `isPostgresServiceRoleAuthorityPurpose`.
#[must_use]
pub fn is_postgres_service_role_authority_purpose(purpose: &str) -> bool {
    purpose == POSTGRES_SERVICE_ROLE_BIND_RPC
}

/// `isAdvisoryEvaluationAuthorityPurpose`.
#[must_use]
pub fn is_advisory_evaluation_authority_purpose(purpose: &str) -> bool {
    purpose == ADVISORY_EVALUATION_JOURNAL_RPC
}

/// Upstream RPCs this slice registers but deliberately does not port —
/// used by [`super::server`]'s dispatch so such a name returns
/// [`UNSUPPORTED_IN_THIS_SLICE`] rather than `"unknown purpose"`.
/// Connection-only purposes with real `HandleConn` handlers (the
/// backup/throughput/payload-epoch worker and helper sets,
/// `restore_issue_launch`) are NOT here — upstream's `Dispatch`
/// `default` answers `"unknown purpose"` for them, and the match arm
/// owns every live dispatch.
#[must_use]
pub fn is_r6_purpose(purpose: &str) -> bool {
    // `append_advisory_evaluation` is live now: `HandleConn` serves it
    // behind the root-backup-helper peer gate, and upstream's
    // `Dispatch` answers `"unknown purpose"` for it like every other
    // connection-only purpose — so it no longer belongs to the closed
    // R6 set.
    is_postgres_service_role_authority_purpose(purpose)
}

// ---------------------------------------------------------------------------
// Peer predicates (kernel-attested SO_PEERCRED)
// ---------------------------------------------------------------------------

/// `isRuntimeOrRootPeer` — uid 0 or the runtime uid.
#[must_use]
pub fn is_runtime_or_root_peer(runtime_uid: u32, peer: &PeerCred) -> bool {
    peer.uid.as_raw() == 0 || peer.uid.as_raw() == runtime_uid
}

/// `isMinioRuntimeOutboundPeer` — frame `0xB1` admits the provisioner
/// identity `(1000:1000)` or the runtime uid (ADR 0013); not root.
#[must_use]
pub fn is_minio_runtime_outbound_peer(runtime_uid: u32, peer: &PeerCred) -> bool {
    (peer.uid.as_raw() == MINIO_PROVISIONER_UID && peer.gid.as_raw() == MINIO_PROVISIONER_GID)
        || peer.uid.as_raw() == runtime_uid
}

/// `isCentralMigratePeer` — `986:986` exactly.
#[must_use]
pub fn is_central_migrate_peer(peer: &PeerCred) -> bool {
    peer.uid.as_raw() == CENTRAL_MIGRATE_UID && peer.gid.as_raw() == CENTRAL_MIGRATE_GID
}

/// `isMinioProvisionerPeer` — the inbound `0xB2` gate: provisioner
/// `1000:1000` only, checked before any descriptor is received.
#[must_use]
pub fn is_minio_provisioner_peer(peer: &PeerCred) -> bool {
    peer.uid.as_raw() == MINIO_PROVISIONER_UID && peer.gid.as_raw() == MINIO_PROVISIONER_GID
}

/// `isRootBackupHelperPeer` — uid 0, gid 0, a live pid.
#[must_use]
pub fn is_root_backup_helper_peer(peer: &PeerCred) -> bool {
    peer.uid.as_raw() == 0 && peer.gid.as_raw() == 0 && peer.pid.as_raw_pid() > 0
}

// ---------------------------------------------------------------------------
// Frame codec
// ---------------------------------------------------------------------------

fn invalid(msg: impl Into<String>) -> Failure {
    Failure::invalid("broker_protocol", msg.into())
}

/// `binary.Read(BigEndian, size)` + `io.ReadFull` — the length-prefixed
/// frame read shared by the B04/B05/B10 request transports. `size`
/// must be `1..=64 KiB`; refused, never truncated.
///
/// # Errors
/// `broker_protocol` on read failure or an out-of-range size.
pub fn read_framed_payload(r: &mut impl Read, name: &str) -> Result<Vec<u8>, Failure> {
    let mut size_buf = [0u8; 4];
    r.read_exact(&mut size_buf).map_err(|e| {
        Failure::internal("broker_protocol", format!("broker: read frame size: {e}"))
    })?;
    let size = u32::from_be_bytes(size_buf);
    if size == 0 || size > MAX_FRAME_SIZE {
        return Err(invalid(format!("invalid {name} frame size {size}")));
    }
    let mut payload = vec![0u8; size as usize];
    r.read_exact(&mut payload)
        .map_err(|e| Failure::internal("broker_protocol", format!("broker: read frame: {e}")))?;
    Ok(payload)
}

/// `readB04RequestFrame`/`readB05RequestFrame`/`readB10RequestFrame`:
/// a length-prefixed strict-decoded `BrokerRequest` whose `purpose`
/// must equal `expected`.
///
/// # Errors
/// `broker_protocol` on any framing, decode, or purpose mismatch.
pub fn read_request_frame(
    r: &mut impl Read,
    name: &str,
    expected_purpose: &str,
) -> Result<BrokerRequest, Failure> {
    let payload = read_framed_payload(r, name)?;
    let req = decode_broker_request(&payload)?;
    if req.purpose != expected_purpose {
        return Err(invalid(format!(
            "unexpected framed {name} purpose {:?}",
            req.purpose
        )));
    }
    Ok(req)
}

/// `backupWorkerCredentialFrameSize` — marker + kind + two UUIDs.
pub const BACKUP_WORKER_CREDENTIAL_FRAME_SIZE: usize = 1 + 1 + 16 + 16;

/// `backupWorkerPostgresCredential` — the 0xc1 credential kinds.
pub const BACKUP_WORKER_POSTGRES_CREDENTIAL: u8 = 1;
/// `backupWorkerMinioCredential`.
pub const BACKUP_WORKER_MINIO_CREDENTIAL: u8 = 2;
/// `backupThroughputPostgresTargetCredential`.
pub const BACKUP_THROUGHPUT_POSTGRES_TARGET_CREDENTIAL: u8 = 3;
/// `backupThroughputPostgresProbeCredential`.
pub const BACKUP_THROUGHPUT_POSTGRES_PROBE_CREDENTIAL: u8 = 4;
/// `backupThroughputMinioCredential`.
pub const BACKUP_THROUGHPUT_MINIO_CREDENTIAL: u8 = 5;

/// `validBackupWorkerCredentialKind` — the closed `1..=5` kind set.
#[must_use]
pub fn valid_backup_worker_credential_kind(kind: u8) -> bool {
    kind == BACKUP_WORKER_POSTGRES_CREDENTIAL
        || kind == BACKUP_WORKER_MINIO_CREDENTIAL
        || kind == BACKUP_THROUGHPUT_POSTGRES_TARGET_CREDENTIAL
        || kind == BACKUP_THROUGHPUT_POSTGRES_PROBE_CREDENTIAL
        || kind == BACKUP_THROUGHPUT_MINIO_CREDENTIAL
}

/// `backupWorkerCredentialRequest` — the parsed 0xc1 frame body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackupWorkerCredentialRequest {
    /// The credential `kind` byte (`1..=5`).
    pub kind: u8,
    /// The worker launch evidence this credential rides on.
    pub launch_evidence_id: uuid::Uuid,
    /// The operation the denial echoes.
    pub operation_id: uuid::Uuid,
}

/// `readBackupWorkerCredentialRequest` — the fixed 33-byte body after
/// the `0xc1` marker: `kind` byte, `launch_evidence_id`, then
/// `operation_id`. Upstream reads it before the worker peer check so
/// the denial can echo the operation id; nil UUIDs and an unknown kind
/// are invalid.
///
/// # Errors
/// `broker_protocol` on a short read or an invalid request.
pub fn read_backup_worker_credential_request(
    r: &mut impl Read,
) -> Result<BackupWorkerCredentialRequest, Failure> {
    let mut payload = [0u8; BACKUP_WORKER_CREDENTIAL_FRAME_SIZE - 1];
    r.read_exact(&mut payload).map_err(|e| {
        Failure::internal(
            "broker_protocol",
            format!("broker: read backup credential frame: {e}"),
        )
    })?;
    let kind = payload[0];
    let mut launch_bytes = [0u8; 16];
    launch_bytes.copy_from_slice(&payload[1..17]);
    let launch_evidence_id = uuid::Uuid::from_bytes(launch_bytes);
    let mut operation_bytes = [0u8; 16];
    operation_bytes.copy_from_slice(&payload[17..33]);
    let operation_id = uuid::Uuid::from_bytes(operation_bytes);
    if launch_evidence_id.is_nil()
        || operation_id.is_nil()
        || !valid_backup_worker_credential_kind(kind)
    {
        return Err(invalid("broker: invalid backup credential request"));
    }
    Ok(BackupWorkerCredentialRequest {
        kind,
        launch_evidence_id,
        operation_id,
    })
}

/// `restoreMigrationCredentialFrameSize` — marker + kind + one UUID.
pub const RESTORE_MIGRATION_CREDENTIAL_FRAME_SIZE: usize = 1 + 1 + 16;

/// `restoreMigrationCredential` — the destructive `pg_restore`
/// migration credential (kind 1).
pub const RESTORE_MIGRATION_CREDENTIAL: u8 = 1;
/// `restoreRuntimeCredential` — kind 2; the only kind a nil operation
/// may request.
pub const RESTORE_RUNTIME_CREDENTIAL: u8 = 2;
/// `restoreMinioCredential` — kind 3.
pub const RESTORE_MINIO_CREDENTIAL: u8 = 3;
/// `restoreAuditMigrationCredential` — kind 4 (SC-DEF-62/63).
pub const RESTORE_AUDIT_MIGRATION_CREDENTIAL: u8 = 4;
/// `restoreMinioImportCredential` — kind 5 (ADR 0034).
pub const RESTORE_MINIO_IMPORT_CREDENTIAL: u8 = 5;
/// `restoreImportMigrationCredential` — kind 6 (ADR 0034).
pub const RESTORE_IMPORT_MIGRATION_CREDENTIAL: u8 = 6;

/// `validRestoreCredentialKind` — the closed `1..=6` kind set.
#[must_use]
pub fn valid_restore_credential_kind(kind: u8) -> bool {
    kind == RESTORE_MIGRATION_CREDENTIAL
        || kind == RESTORE_RUNTIME_CREDENTIAL
        || kind == RESTORE_MINIO_CREDENTIAL
        || kind == RESTORE_AUDIT_MIGRATION_CREDENTIAL
        || kind == RESTORE_MINIO_IMPORT_CREDENTIAL
        || kind == RESTORE_IMPORT_MIGRATION_CREDENTIAL
}

/// `restoreCredentialRequest` — the parsed 0xc2 frame body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestoreCredentialRequest {
    /// The credential `kind` byte (`1..=6`).
    pub kind: u8,
    /// The operation this credential serves; nil only for the runtime
    /// credential during verification, which runs before any
    /// operation exists.
    pub operation_id: uuid::Uuid,
}

/// `readRestoreCredentialRequest` — the fixed 17-byte body after the
/// `0xc2` marker: `kind` byte, then `operation_id`. The frame carries
/// no purpose, locator, role, path, or descriptor selector: which
/// credential is released is fixed by executable policy, never by
/// anything the caller writes. A non-nil operation must be UUIDv7;
/// only the runtime credential may be requested without an operation.
///
/// # Errors
/// `broker_protocol` on a short read or an invalid request.
pub fn read_restore_credential_request(
    r: &mut impl Read,
) -> Result<RestoreCredentialRequest, Failure> {
    let mut payload = [0u8; RESTORE_MIGRATION_CREDENTIAL_FRAME_SIZE - 1];
    r.read_exact(&mut payload).map_err(|e| {
        Failure::internal(
            "broker_protocol",
            format!("broker: read restore credential frame: {e}"),
        )
    })?;
    let kind = payload[0];
    let mut operation_bytes = [0u8; 16];
    operation_bytes.copy_from_slice(&payload[1..17]);
    let operation_id = uuid::Uuid::from_bytes(operation_bytes);
    if !valid_restore_credential_kind(kind)
        || (!operation_id.is_nil() && operation_id.get_version_num() != 7)
        || (operation_id.is_nil() && kind != RESTORE_RUNTIME_CREDENTIAL)
    {
        return Err(invalid("broker: invalid restore credential request"));
    }
    Ok(RestoreCredentialRequest { kind, operation_id })
}

/// `decodeB10ProvisionedDescriptor` — `size == len(data)-4` (exactly,
/// never a prefix), then the JSON `MinioProvisionedDescriptor`.
///
/// # Errors
/// `broker_protocol` on a short frame, a length mismatch, or a decode
/// failure.
pub fn decode_b10_provisioned_descriptor(
    data: &[u8],
) -> Result<MinioProvisionedDescriptor, Failure> {
    if data.len() < 4 {
        return Err(invalid("broker: provisioned frame too short"));
    }
    let size = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if size == 0 || size as usize != data.len() - 4 {
        return Err(invalid(format!(
            "broker: invalid provisioned frame size {size}"
        )));
    }
    serde_json::from_slice::<MinioProvisionedDescriptor>(&data[4..])
        .map_err(|e| invalid(format!("broker: decode provisioned descriptor: {e}")))
}

/// `decodeBrokerRequest` — the strict request decoder: must be a JSON
/// object; field names must be drawn from `operation_id`, `purpose`,
/// `session_token`, `payload`; duplicates refuse; trailing data
/// refuses. Decoded through a `MapAccess` visitor so every constraint
/// the Go token loop enforces is structural, not post-hoc.
///
/// # Errors
/// `broker_protocol` on any violation, mirroring upstream's message
/// text (`request must be a JSON object`, `duplicate request field`,
/// `unknown request field`, `trailing request data`).
pub fn decode_broker_request(data: &[u8]) -> Result<BrokerRequest, Failure> {
    // Custom Visitor: object-only, closed field set, no duplicates.
    struct RequestVisitor;
    struct Fields {
        operation_id: Option<String>,
        purpose: Option<String>,
        session_token: Option<String>,
        /// Outer `Option` — the key's presence (duplicate detection
        /// needs it); inner — `None` for an explicit `null`.
        payload: Option<Option<BTreeMap<String, Box<serde_json::value::RawValue>>>>,
    }
    impl<'de> serde::de::Visitor<'de> for RequestVisitor {
        type Value = Fields;
        fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("a broker request object")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> Result<Self::Value, A::Error> {
            let mut fields = Fields {
                operation_id: None,
                purpose: None,
                session_token: None,
                payload: None,
            };
            while let Some(key) = map.next_key::<String>()? {
                match key.as_str() {
                    "operation_id" => {
                        if fields.operation_id.is_some() {
                            return Err(serde::de::Error::custom(
                                "broker: duplicate request field \"operation_id\"",
                            ));
                        }
                        fields.operation_id = Some(map.next_value()?);
                    }
                    "purpose" => {
                        if fields.purpose.is_some() {
                            return Err(serde::de::Error::custom(
                                "broker: duplicate request field \"purpose\"",
                            ));
                        }
                        fields.purpose = Some(map.next_value()?);
                    }
                    "session_token" => {
                        if fields.session_token.is_some() {
                            return Err(serde::de::Error::custom(
                                "broker: duplicate request field \"session_token\"",
                            ));
                        }
                        fields.session_token = Some(map.next_value()?);
                    }
                    "payload" => {
                        if fields.payload.is_some() {
                            return Err(serde::de::Error::custom(
                                "broker: duplicate request field \"payload\"",
                            ));
                        }
                        fields.payload = Some(map.next_value()?);
                    }
                    other => {
                        return Err(serde::de::Error::custom(format!(
                            "broker: unknown request field {other:?}"
                        )));
                    }
                }
            }
            Ok(fields)
        }
    }
    let mut de = serde_json::Deserializer::from_slice(data);
    use serde::Deserializer as _;
    let fields = de
        .deserialize_map(RequestVisitor)
        .map_err(|e| invalid(format!("broker: invalid request: {e}")))?;
    de.end()
        .map_err(|e| invalid(format!("broker: trailing request data: {e}")))?;

    // `payload`: Go's `map[string]json.RawMessage` — `null` and absent
    // both mean nil; an object means a map (possibly empty). Any other
    // JSON shape fails Go's unmarshal, so `next_value` refused it above.
    let payload = match fields.payload {
        None | Some(None) => None,
        Some(Some(map)) => Some(map),
    };
    Ok(BrokerRequest {
        operation_id: fields.operation_id.unwrap_or_default(),
        purpose: fields.purpose.unwrap_or_default(),
        session_token: fields.session_token.unwrap_or_default(),
        payload,
    })
}

// ---------------------------------------------------------------------------
// Response encoders
// ---------------------------------------------------------------------------

/// `json.Marshal(resp) + '\n'` — every broker response is one
/// newline-terminated JSON line.
///
/// # Errors
/// `broker_protocol` on marshal/write failure.
pub fn write_response(w: &mut impl Write, resp: &BrokerResponse) -> Result<(), Failure> {
    let mut payload = serde_json::to_vec(resp)
        .map_err(|e| Failure::internal("broker_protocol", format!("marshal response: {e}")))?;
    payload.push(b'\n');
    w.write_all(&payload)
        .map_err(|e| Failure::internal("broker_protocol", format!("write response: {e}")))
}

/// `writeDeny` — `outcome: "denied"` with `evidence.message`.
/// `Evidence.OperationID` stays `""`, exactly as every upstream
/// denial helper leaves it.
pub fn write_deny(w: &mut impl Write, op_id: &str, msg: &str) {
    let resp = BrokerResponse {
        operation_id: op_id.to_owned(),
        outcome: BrokerOutcome::Denied,
        result: None,
        evidence: central_infra::authority::BrokerEvidence {
            operation_id: String::new(),
            code: String::new(),
            message: msg.to_owned(),
        },
    };
    let _ = write_response(w, &resp);
}

/// `writeDeny` carrying `evidence.code` — `migrationRPCDeniedWithCode`.
pub fn write_deny_with_code(w: &mut impl Write, op_id: &str, code: &str, msg: &str) {
    let resp = BrokerResponse {
        operation_id: op_id.to_owned(),
        outcome: BrokerOutcome::Denied,
        result: None,
        evidence: central_infra::authority::BrokerEvidence {
            operation_id: String::new(),
            code: code.to_owned(),
            message: msg.to_owned(),
        },
    };
    let _ = write_response(w, &resp);
}

/// `writeAccept` — bare `outcome: "success"`.
pub fn write_accept(w: &mut impl Write, op_id: &str) {
    let resp = BrokerResponse {
        operation_id: op_id.to_owned(),
        outcome: BrokerOutcome::Success,
        result: None,
        evidence: Default::default(),
    };
    let _ = write_response(w, &resp);
}

/// `sendB04Descriptor` — `WriteMsgUnix([0x01], UnixRights(fd))`.
///
/// # Errors
/// `sys_scm_rights_*` on the send failure.
pub fn send_descriptor<Fd: AsFd>(conn: Fd, fd: BorrowedFd<'_>) -> Result<(), Failure> {
    crate::sys::scm_rights::send(conn, &[crate::sys::scm_rights::TRANSPORT_MARKER], &[fd])?;
    Ok(())
}

/// Receive the B04/B05 destination descriptor — `ReceiveDescriptor`'s
/// `0x01` marker + single-SCM_RIGHTS + descriptor-shape gate.
///
/// # Errors
/// `sys_scm_rights_denied`/`sys_memfd_denied` on any wrong shape.
pub fn receive_descriptor<Fd: AsFd>(conn: Fd) -> Result<OwnedFd, Failure> {
    let fd = crate::sys::scm_rights::recv_marker_descriptor(conn)?;
    crate::sys::memfd::validate_destination(&fd, rustix::process::Uid::ROOT)?;
    Ok(fd)
}

// ---------------------------------------------------------------------------
// Tests — upstream `server.go` frame/decoder coverage, ported.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn cred(uid: u32, gid: u32) -> PeerCred {
        PeerCred {
            pid: rustix::process::Pid::from_raw(4242).unwrap(),
            uid: rustix::process::Uid::from_raw(uid),
            gid: rustix::process::Gid::from_raw(gid),
        }
    }

    // -- strict request decoder ----------------------------------------

    #[test]
    fn decode_golden_request() {
        // The canonical wire shape every helper and client emits.
        let req = decode_broker_request(
            br#"{"operation_id":"op-1","purpose":"hmac_fingerprint","session_token":"t","payload":{"request":{"x":1}}}"#,
        )
        .unwrap();
        assert_eq!(req.operation_id, "op-1");
        assert_eq!(req.purpose, "hmac_fingerprint");
        assert_eq!(req.session_token, "t");
        // RawValue passthrough — the captured bytes are the verbatim
        // wire text, whitespace and key order included.
        assert_eq!(req.payload.unwrap()["request"].get(), r#"{"x":1}"#);
    }

    #[test]
    fn decode_rejects_non_object() {
        for bad in [b"[]".as_slice(), b"42", b"\"x\"", b"true", b"null"] {
            assert!(decode_broker_request(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn decode_rejects_duplicate_fields() {
        assert!(
            decode_broker_request(br#"{"operation_id":"a","operation_id":"b","purpose":"p"}"#)
                .is_err()
        );
        assert!(decode_broker_request(br#"{"purpose":"a","purpose":"b"}"#).is_err());
        assert!(decode_broker_request(br#"{"payload":{},"payload":{}}"#).is_err());
    }

    #[test]
    fn decode_rejects_unknown_fields() {
        assert!(decode_broker_request(br#"{"operation_id":"a","purpose":"p","bogus":1}"#).is_err());
    }

    #[test]
    fn decode_rejects_trailing_data() {
        assert!(decode_broker_request(br#"{"purpose":"p"} {"x":1}"#).is_err());
        assert!(decode_broker_request(br#"{"purpose":"p"}garbage"#).is_err());
    }

    #[test]
    fn decode_preserves_null_vs_empty_payload() {
        // `null` and absent both mean nil; `{}` is a non-nil empty map.
        let absent = decode_broker_request(br#"{"purpose":"p"}"#).unwrap();
        let null = decode_broker_request(br#"{"purpose":"p","payload":null}"#).unwrap();
        let empty = decode_broker_request(br#"{"purpose":"p","payload":{}}"#).unwrap();
        assert!(absent.payload.is_none());
        assert!(null.payload.is_none());
        assert!(empty.payload.is_some_and(|m| m.is_empty()));
    }

    #[test]
    fn decode_rejects_non_object_payload() {
        for bad in [
            br#"{"purpose":"p","payload":[]}"#.as_slice(),
            br#"{"purpose":"p","payload":"x"}"#,
            br#"{"purpose":"p","payload":7}"#,
        ] {
            assert!(decode_broker_request(bad).is_err(), "accepted {bad:?}");
        }
    }

    // -- framed codec ----------------------------------------------------

    #[test]
    fn framed_payload_golden() {
        // u32be length + payload, the B04/B05/B10 request framing.
        let mut wire = Vec::new();
        wire.extend_from_slice(&4u32.to_be_bytes());
        wire.extend_from_slice(b"pong");
        let mut cur = Cursor::new(wire);
        assert_eq!(read_framed_payload(&mut cur, "b04").unwrap(), b"pong");
    }

    #[test]
    fn framed_payload_rejects_bad_sizes() {
        // 0 and >64 KiB are refused, never clamped.
        let mut zero = Cursor::new(0u32.to_be_bytes().to_vec());
        assert!(read_framed_payload(&mut zero, "b04").is_err());
        let mut big = Cursor::new((MAX_FRAME_SIZE + 1).to_be_bytes().to_vec());
        assert!(read_framed_payload(&mut big, "b04").is_err());
        // Declared length larger than the bytes present.
        let mut short = Cursor::new({
            let mut v = 8u32.to_be_bytes().to_vec();
            v.extend_from_slice(b"ab");
            v
        });
        assert!(read_framed_payload(&mut short, "b04").is_err());
    }

    #[test]
    fn request_frame_enforces_purpose() {
        let request = br#"{"operation_id":"op-9","purpose":"materialize_minio_root","payload":{"request":{}}}"#;
        let mut wire = Vec::new();
        wire.extend_from_slice(&(request.len() as u32).to_be_bytes());
        wire.extend_from_slice(request);
        let mut cur = Cursor::new(wire.clone());
        let req = read_request_frame(&mut cur, "b04", MATERIALIZE_MINIO_ROOT_RPC).unwrap();
        assert_eq!(req.operation_id, "op-9");
        // A mismatched purpose on the same bytes fails closed.
        let mut cur = Cursor::new(wire);
        assert!(read_request_frame(&mut cur, "b05", MATERIALIZE_POSTGRES_MIGRATION_RPC).is_err());
    }

    #[test]
    fn provisioned_descriptor_requires_exact_size() {
        let payload = serde_json::to_vec(&serde_json::json!({
            "service": "minio-provision", "target": "sealed_memfd", "uid": 501, "gid": 501,
            "bucket": "central", "key_prefix": "inst/", "purpose": "minio_runtime_v1",
            "operation_id": "op", "instance_id": "inst", "receipt_id": "r",
            "expires_at": "2030-01-01T00:00:00Z", "fence_token": 1
        }))
        .unwrap();
        let mut wire = (payload.len() as u32).to_be_bytes().to_vec();
        wire.extend_from_slice(&payload);
        // Exact length parses; a trailing byte or size mismatch refuses.
        decode_b10_provisioned_descriptor(&wire).unwrap();
        let mut longer = wire.clone();
        longer.push(0);
        assert!(decode_b10_provisioned_descriptor(&longer).is_err());
        assert!(decode_b10_provisioned_descriptor(&wire[..3]).is_err());
    }

    // -- response encoders -------------------------------------------------

    #[test]
    fn response_is_newline_terminated_json() {
        let mut buf = Vec::new();
        write_deny(&mut buf, "op-1", "authority denied");
        assert!(buf.ends_with(b"\n"));
        let resp: BrokerResponse = serde_json::from_slice(&buf[..buf.len() - 1]).unwrap();
        assert_eq!(resp.outcome, BrokerOutcome::Denied);
        assert_eq!(resp.operation_id, "op-1");
        assert_eq!(resp.evidence.message, "authority denied");
        let mut buf = Vec::new();
        write_deny_with_code(&mut buf, "op-2", "PROVISIONING_RECORD_ABSENT", "absent");
        let resp: BrokerResponse = serde_json::from_slice(&buf[..buf.len() - 1]).unwrap();
        assert_eq!(resp.evidence.code, "PROVISIONING_RECORD_ABSENT");
        let mut buf = Vec::new();
        write_accept(&mut buf, "op-3");
        let resp: BrokerResponse = serde_json::from_slice(&buf[..buf.len() - 1]).unwrap();
        assert_eq!(resp.outcome, BrokerOutcome::Success);
    }

    // -- peer predicates -------------------------------------------------

    #[test]
    fn b1_peer_matrix_admits_only_runtime_and_provisioner() {
        // ADR 0013: frame `0xB1` admits the provisioner identity
        // (1000:1000) OR the runtime uid — never root, never anyone else.
        let runtime = CENTRAL_RUNTIME_UID;
        assert!(is_minio_runtime_outbound_peer(runtime, &cred(1000, 1000)));
        assert!(is_minio_runtime_outbound_peer(runtime, &cred(runtime, 42)));
        // Not root, not the runtime gid alone, not provisioner uid alone,
        // not an arbitrary identity.
        for (u, g) in [(0, 0), (runtime - 1, runtime), (1000, 999), (4242, 4242)] {
            assert!(
                !is_minio_runtime_outbound_peer(runtime, &cred(u, g)),
                "admitted {u}:{g}"
            );
        }
    }

    #[test]
    fn peer_predicates_match_upstream_tables() {
        assert!(is_runtime_or_root_peer(501, &cred(0, 7)));
        assert!(is_runtime_or_root_peer(501, &cred(501, 7)));
        assert!(!is_runtime_or_root_peer(501, &cred(502, 0)));
        assert!(is_central_migrate_peer(&cred(986, 986)));
        assert!(!is_central_migrate_peer(&cred(986, 0)));
        assert!(is_minio_provisioner_peer(&cred(1000, 1000)));
        assert!(!is_minio_provisioner_peer(&cred(1000, 0)));
        assert!(is_root_backup_helper_peer(&cred(0, 0)));
        assert!(!is_root_backup_helper_peer(&cred(0, 1)));
    }

    // -- closed purpose tables --------------------------------------------

    #[test]
    fn every_r6_purpose_is_registered() {
        // Only upstream RPCs this slice deliberately does not port stay
        // in the closed table — everything else is either a live
        // `Dispatch` arm or a connection-only purpose upstream's
        // `default` answers `"unknown purpose"` for.
        assert!(is_r6_purpose("bind_postgres_service_role"));
        // `append_advisory_evaluation` is live — `HandleConn` serves it
        // behind the root-backup-helper peer gate, and `Dispatch`'s
        // `default` answers `"unknown purpose"`, like every other
        // connection-only purpose.
        assert!(!is_r6_purpose("append_advisory_evaluation"));
        for handled in [
            // Live RPCs and the purposes with a real Dispatch arm are
            // never R6-classified — the arm owns them.
            MIGRATION_ISSUE_EMPTY_PROOF_RPC,
            MIGRATION_READ_RECORD_RPC,
            AUTHORIZE_LIFECYCLE_RPC,
            HMAC_FINGERPRINT_RPC,
            SIGN_LEAF_RPC,
            PRESENT_BOOTSTRAP_RPC,
            REGISTER_BOOTSTRAP_CANDIDATE_RPC,
            ACTIVATE_BOOTSTRAP_CANDIDATE_RPC,
            // The live recovery arms.
            RESTORE_APPLY_AUTHORIZATION_RPC,
            RESTORE_RESUME_AUTHORIZATION_RPC,
            RESTORE_ABANDON_AUTHORIZATION_RPC,
            RESTORE_ABANDON_RPC,
            RESTORE_BARRIER_INSPECT_RPC,
            RESTORE_TICKET_BARRIER_INSPECT_RPC,
            RESTORE_BROKER_AUTHORITY_PREPARE_RPC,
            RESTORE_BOOTSTRAP_ACTIVATE_RPC,
            // Connection-only purposes — real `HandleConn` handlers,
            // upstream `"unknown purpose"` through `Dispatch`.
            "backup_issue_launch",
            "backup_issue_minio_handoff",
            "backup_seal_for_launch",
            "backup_mark_launch_reaped",
            "backup_complete_attested_seal",
            "backup_verify_seal",
            "backup_read_status",
            "backup_worker_context",
            "backup_worker_active_payload_epoch",
            "backup_worker_read_throughput",
            "backup_worker_create_operation",
            "backup_worker_read_operation",
            "backup_worker_cas_operation",
            "backup_throughput_issue_launch",
            "backup_throughput_read_launch",
            "backup_throughput_fixture_loaded",
            "backup_throughput_worker_context",
            "backup_throughput_worker_target_locked",
            "backup_throughput_worker_stage",
            "backup_throughput_accept",
            "backup_throughput_current_attempt",
            "backup_throughput_complete_pending",
            "backup_throughput_activate",
            "backup_throughput_failed",
            "backup_throughput_cleanup_required",
            "backup_throughput_cleanup_resolved",
            "backup_ensure_payload_epoch",
            "restore_issue_launch",
            "migration_report_launch_outcome",
            // Other live/registered arms.
            "migration_read_launch_outcome",
            "issue_migration_launch",
            "adopt_b03_minio_bootstrap",
            "issue_b04_lifecycle_proof",
            "materialize_postgres_migration",
            "materialize_minio_root",
            "materialize_minio_runtime",
            "create_protected_generation",
            "materialize_dependency_handoff",
        ] {
            assert!(
                !is_r6_purpose(handled),
                "handled purpose {handled} misclassified"
            );
        }
        assert!(!is_r6_purpose("genuinely_unknown"));
    }
}
