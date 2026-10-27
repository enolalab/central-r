//! Recovery authority RPC dispatch — `recovery_authority_rpc.go`'s
//! broker-side handlers plus the `restore_issue_launch` helper arm
//! from `restore_launch.go`, and the C05 lifecycle methods from
//! `service.go` (`PrepareRecoveryBrokerAuthority`,
//! `ActivateRecoveryBootstrap`, `ResetBootstrapAuthority`) those
//! handlers call.
//!
//! Unlike the backup surface, recovery request decode is upstream's
//! plain `json.Unmarshal` — tolerant of absent and unknown fields —
//! so every request wire here is `#[serde(default)]` throughout and
//! carries no `deny_unknown_fields`. Denials are upstream's
//! `recoveryAuthorizationDenied`: `Evidence.Message` only, never a
//! code — and several rungs deliberately answer with `OperationID`
//! `"unknown"` rather than echoing the request's ID.
//!
//! Payload shapes are byte-exact:
//! - the three authorization issues and `abandon_restore` require a
//!   payload map containing a `request` key (absent payload ⇒ deny as
//!   `"unknown"`);
//! - both barrier inspections require `len(payload) == 0`;
//! - `prepare_recovery_broker_authority` /
//!   `activate_recovery_bootstrap` require `len(payload) == 2`
//!   (`"request"` plus the client's `"launch_evidence_id"` echo).
//!
//! Wire notes: `recoveryBootstrapDraftWire`/`…RegistrationWire`/
//! `…ActivationWire` carry `verifier_hash`/`candidate_digest` as
//! base64-RawStd strings — upstream hashes them into strings, they are
//! not `[32]byte` arrays on this wire.

use central_backup::recovery::operation::{
    RecoveryBootstrapActivation, RecoveryBootstrapDraft, RecoveryBootstrapRegistration,
    RestoreAbandonAuthorization, RestoreApplyAuthorization, RestoreCheckpoint, RestoreOperation,
    RestorePhase,
};
use central_foundation::failure::Failure;
use central_infra::authority::{BrokerRequest, BrokerResponse};
use central_session::contract::CandidateBinding;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use super::lifecycle_client::LifecycleClient;
use super::protocol::{
    RESTORE_ABANDON_AUTHORIZATION_RPC, RESTORE_ABANDON_RPC, RESTORE_APPLY_AUTHORIZATION_RPC,
    RESTORE_BOOTSTRAP_ACTIVATE_RPC, RESTORE_BROKER_AUTHORITY_PREPARE_RPC,
    RESTORE_RESUME_AUTHORIZATION_RPC,
};
use super::recovery_journal::{
    self, RecoveryBrokerResetRecord, RestoreAbandonAuthorizationWire,
    RestoreApplyAuthorizationWire, RestoreOperationWire, abandon_authorization_from_wire,
    abandon_authorization_to_wire, apply_authorization_from_wire, apply_authorization_to_wire,
    operation_from_wire, operation_to_wire,
};
use super::restore_launch::RestoreLaunchEvidence;
use super::server::Service;
use super::wire;
use crate::sys::peercred::PeerCred;

/// `recoveryBootstrapPurpose` — the protected-generation purpose the
/// recovery bootstrap token lives under.
const RECOVERY_BOOTSTRAP_PURPOSE: &str = "central-recovery-bootstrap-v1";

/// `recoveryAuthorizationDenied` — recovery denials are message-only:
/// `Evidence.Code` stays empty and several rungs answer `"unknown"`
/// rather than the request's operation ID.
fn recovery_denied(operation_id: &str, message: &str) -> BrokerResponse {
    BrokerResponse {
        operation_id: operation_id.into(),
        outcome: central_infra::authority::BrokerOutcome::Denied,
        result: None,
        evidence: central_infra::authority::BrokerEvidence {
            operation_id: String::new(),
            code: String::new(),
            message: message.into(),
        },
    }
}

/// `json.Marshal(result)` embedded verbatim — the recovery surface
/// never degrades a marshal failure to an error outcome; it denies
/// with the handler's own encode message (each caller chooses its
/// message), so this only runs for values that always marshal.
fn recovery_success<T: Serialize>(
    operation_id: &str,
    result: &T,
    encode_message: &str,
) -> BrokerResponse {
    let Ok(serialized) = serde_json::to_string(result) else {
        return recovery_denied(operation_id, encode_message);
    };
    let escaped = wire::go_json_escape(&serialized);
    match serde_json::value::RawValue::from_string(escaped) {
        Ok(raw) => BrokerResponse {
            operation_id: operation_id.into(),
            outcome: central_infra::authority::BrokerOutcome::Success,
            result: Some(raw),
            evidence: central_infra::authority::BrokerEvidence {
                operation_id: String::new(),
                code: String::new(),
                message: String::new(),
            },
        },
        Err(_) => recovery_denied(operation_id, encode_message),
    }
}

/// The payload map's `"request"` member as raw JSON — upstream's
/// `req.Payload["request"]` lookup (absent vs. present-but-malformed
/// are distinct rungs).
fn request_raw(req: &BrokerRequest) -> Option<&serde_json::value::RawValue> {
    req.payload.as_ref()?.get("request").map(Box::as_ref)
}

// ---------------------------------------------------------------------------
// Request wire shapes — tolerant `json.Unmarshal` mirrors (every field
// `#[serde(default)]`, no unknown-field rejection): Go's zero values
// for absent members.
// ---------------------------------------------------------------------------

/// `restoreApplyAuthorizationRequest` / `restoreResumeAuthorizationRequest`
/// / `restoreAbandonAuthorizationRequest` — identical shapes.
#[derive(Debug, Deserialize)]
struct PeerAuthorizationRequest {
    #[serde(default)]
    peer_uid: u32,
    #[serde(default)]
    peer_pid: i32,
    #[serde(default = "wire::go_zero_time", with = "wire::rfc3339")]
    issued_at: OffsetDateTime,
}

/// `backup.RestoreAbandonAuthorization` as a *request* member — Go's
/// untagged domain struct marshals PascalCase and `json.Unmarshal`
/// ignores unknown fields.
#[derive(Debug, Deserialize)]
struct RestoreAbandonAuthorizationRequestWire {
    #[serde(rename = "AuthorizationID", default)]
    authorization_id: Uuid,
    #[serde(rename = "OperationID", default)]
    operation_id: Uuid,
    #[serde(
        rename = "IssuedAt",
        default = "wire::go_zero_time",
        with = "wire::rfc3339"
    )]
    issued_at: OffsetDateTime,
    #[serde(
        rename = "ExpiresAt",
        default = "wire::go_zero_time",
        with = "wire::rfc3339"
    )]
    expires_at: OffsetDateTime,
    #[serde(rename = "Acknowledgement", default)]
    acknowledgement: String,
}

impl Default for RestoreAbandonAuthorizationRequestWire {
    fn default() -> Self {
        Self {
            authorization_id: Uuid::nil(),
            operation_id: Uuid::nil(),
            issued_at: wire::go_zero_time(),
            expires_at: wire::go_zero_time(),
            acknowledgement: String::new(),
        }
    }
}

/// `restoreAbandonRequest`.
#[derive(Debug, Deserialize)]
struct RestoreAbandonRequest {
    #[serde(default)]
    authorization: RestoreAbandonAuthorizationRequestWire,
    #[serde(default = "wire::go_zero_time", with = "wire::rfc3339")]
    at: OffsetDateTime,
}

/// `backup.TargetIdentity` — the request-side mirror used inside the
/// operation decode (PascalCase, tolerant).
#[derive(Debug, Default, Deserialize)]
struct TargetIdentityRequestWire {
    #[serde(rename = "SystemID", default)]
    system_id: String,
    #[serde(rename = "DatabaseOID", default)]
    database_oid: String,
    #[serde(rename = "Database", default)]
    database: String,
    #[serde(rename = "ConfigHash", default)]
    config_hash: String,
    #[serde(rename = "Epoch", default)]
    epoch: u64,
}

/// `backup.RestoreOperation` as a *request* member — PascalCase,
/// tolerant; `Phase`/`LastCheckpoint` decode through the same
/// string vocabulary the journal wire uses.
#[derive(Debug, Deserialize)]
struct RestoreOperationRequestWire {
    #[serde(rename = "OperationID", default)]
    operation_id: Uuid,
    #[serde(rename = "TicketID", default)]
    ticket_id: Uuid,
    #[serde(rename = "BackupID", default)]
    backup_id: Uuid,
    #[serde(rename = "Target", default)]
    target: TargetIdentityRequestWire,
    #[serde(rename = "TargetFingerprint", default)]
    target_fingerprint: String,
    #[serde(rename = "ManifestDigest", default)]
    manifest_digest: String,
    #[serde(rename = "PayloadEpochID", default)]
    payload_epoch_id: Uuid,
    #[serde(rename = "DatabaseSchemaVersion", default)]
    database_schema_version: String,
    #[serde(rename = "CapacityEvidenceDigest", default)]
    capacity_evidence_digest: String,
    #[serde(rename = "SecurityEpoch", default)]
    security_epoch: u64,
    #[serde(rename = "RestoreEpoch", default)]
    restore_epoch: u64,
    #[serde(rename = "Revision", default)]
    revision: u64,
    #[serde(rename = "Phase", default)]
    phase: String,
    #[serde(rename = "LastCheckpoint", default)]
    last_checkpoint: String,
    #[serde(rename = "AuthorityResetReceiptHash", default)]
    authority_reset_receipt_hash: String,
    #[serde(
        rename = "StartedAt",
        default = "wire::go_zero_time",
        with = "wire::rfc3339"
    )]
    started_at: OffsetDateTime,
    #[serde(
        rename = "UpdatedAt",
        default = "wire::go_zero_time",
        with = "wire::rfc3339"
    )]
    updated_at: OffsetDateTime,
    #[serde(
        rename = "ReadyAt",
        default = "wire::go_zero_time",
        with = "wire::rfc3339"
    )]
    ready_at: OffsetDateTime,
}

impl Default for RestoreOperationRequestWire {
    fn default() -> Self {
        Self {
            operation_id: Uuid::nil(),
            ticket_id: Uuid::nil(),
            backup_id: Uuid::nil(),
            target: TargetIdentityRequestWire::default(),
            target_fingerprint: String::new(),
            manifest_digest: String::new(),
            payload_epoch_id: Uuid::nil(),
            database_schema_version: String::new(),
            capacity_evidence_digest: String::new(),
            security_epoch: 0,
            restore_epoch: 0,
            revision: 0,
            phase: String::new(),
            last_checkpoint: String::new(),
            authority_reset_receipt_hash: String::new(),
            started_at: wire::go_zero_time(),
            updated_at: wire::go_zero_time(),
            ready_at: wire::go_zero_time(),
        }
    }
}

/// `recoveryBootstrapRegistrationWire` (request side — the wire type
/// upstream shares between request and client-side result decode).
#[derive(Debug, Deserialize)]
struct RecoveryBootstrapRegistrationWire {
    #[serde(default)]
    operation_id: Uuid,
    #[serde(default)]
    draft_id: Uuid,
    #[serde(default)]
    candidate_id: Uuid,
    #[serde(default)]
    generation: u64,
    #[serde(default)]
    verifier_hash: String,
    #[serde(default)]
    candidate_digest: String,
    #[serde(default)]
    broker_receipt_hash: String,
    #[serde(default)]
    database_receipt_hash: String,
    #[serde(default = "wire::go_zero_time", with = "wire::rfc3339")]
    registered_at: OffsetDateTime,
}

/// `recoveryAuthorityRequest`.
#[derive(Debug, Deserialize)]
struct RecoveryAuthorityRequest {
    #[serde(default)]
    operation: RestoreOperationRequestWire,
    #[serde(default)]
    registration: Option<RecoveryBootstrapRegistrationWire>,
}

/// `restoreLaunchIssueRequest`.
#[derive(Debug, Deserialize)]
struct RestoreLaunchIssueRequest {
    #[serde(default)]
    pid: i32,
    #[serde(default)]
    process_start: String,
    #[serde(default)]
    executable: String,
    #[serde(default)]
    mode: String,
    #[serde(default = "wire::go_zero_time", with = "wire::rfc3339")]
    expires_at: OffsetDateTime,
}

// ---------------------------------------------------------------------------
// Result wire shapes — `draftToWire`/`activationToWire`, the barrier
// result structs, and `RestoreOperation`/`authorization` domain
// marshals.
// ---------------------------------------------------------------------------

/// `recoveryBootstrapDraftWire` — `verifier_hash`/`candidate_digest`
/// are base64-RawStd strings, exactly as `draftToWire` builds them.
#[derive(Serialize)]
struct RecoveryBootstrapDraftWire {
    operation_id: Uuid,
    draft_id: Uuid,
    candidate_id: Uuid,
    verifier_hash: String,
    candidate_digest: String,
    broker_receipt_hash: String,
    #[serde(with = "wire::rfc3339")]
    created_at: OffsetDateTime,
}

fn draft_to_wire(draft: &RecoveryBootstrapDraft) -> RecoveryBootstrapDraftWire {
    RecoveryBootstrapDraftWire {
        operation_id: draft.operation_id,
        draft_id: draft.draft_id,
        candidate_id: draft.candidate_id,
        verifier_hash: wire::b64_raw_encode(&draft.verifier_hash),
        candidate_digest: wire::b64_raw_encode(&draft.candidate_digest),
        broker_receipt_hash: draft.broker_receipt_hash.clone(),
        created_at: draft.created_at,
    }
}

/// `registrationFromWire` — the two base64-RawStd hash fields must
/// decode to nonzero 32-byte values.
fn registration_from_wire(
    w: &RecoveryBootstrapRegistrationWire,
) -> Result<RecoveryBootstrapRegistration, Failure> {
    let verifier = recovery_journal::decode_recovery_hash(&w.verifier_hash)
        .map_err(|_| Failure::invalid("broker", "invalid recovery verifier hash"))?;
    let digest = recovery_journal::decode_recovery_hash(&w.candidate_digest)
        .map_err(|_| Failure::invalid("broker", "invalid recovery candidate digest"))?;
    Ok(RecoveryBootstrapRegistration {
        operation_id: w.operation_id,
        draft_id: w.draft_id,
        candidate_id: w.candidate_id,
        generation: w.generation,
        verifier_hash: verifier,
        candidate_digest: digest,
        broker_receipt_hash: w.broker_receipt_hash.clone(),
        database_receipt_hash: w.database_receipt_hash.clone(),
        registered_at: w.registered_at,
    })
}

/// `recoveryBootstrapActivationWire`.
#[derive(Serialize)]
struct RecoveryBootstrapActivationWire {
    operation_id: Uuid,
    draft_id: Uuid,
    candidate_id: Uuid,
    generation: u64,
    database_receipt_hash: String,
    activation_receipt_hash: String,
    #[serde(with = "wire::rfc3339")]
    activated_at: OffsetDateTime,
}

fn activation_to_wire(activation: &RecoveryBootstrapActivation) -> RecoveryBootstrapActivationWire {
    RecoveryBootstrapActivationWire {
        operation_id: activation.operation_id,
        draft_id: activation.draft_id,
        candidate_id: activation.candidate_id,
        generation: activation.generation,
        database_receipt_hash: activation.database_receipt_hash.clone(),
        activation_receipt_hash: activation.activation_receipt_hash.clone(),
        activated_at: activation.activated_at,
    }
}

/// `restoreBarrierResult` — `Operation` is `,omitempty` upstream but
/// Go never elides a non-pointer struct member, so it always serializes.
#[derive(Serialize)]
struct RestoreBarrierResultWire {
    active: bool,
    operation: super::recovery_journal::RestoreOperationWire,
}

/// `restoreTicketBarrierResult` — a nil Go slice marshals `null`,
/// never `[]`; `None` here carries that distinction.
#[derive(Serialize)]
struct RestoreTicketBarrierResultWire {
    operation_ids: Option<Vec<Uuid>>,
}

/// The restore-issue denial — `RESTORE_LAUNCH_DENIED: <message>` in
/// `Message` only.
fn restore_launch_denied(operation_id: &str, message: &str) -> BrokerResponse {
    recovery_denied(operation_id, &format!("RESTORE_LAUNCH_DENIED: {message}"))
}

impl Service {
    /// `dispatchRestoreApplyAuthorization` —
    /// `issue_restore_apply_authorization`.
    pub(crate) fn dispatch_restore_apply_authorization(
        &self,
        req: &BrokerRequest,
    ) -> BrokerResponse {
        if self.recovery_journal.is_none() || req.payload.is_none() {
            return recovery_denied("unknown", "recovery journal unavailable");
        }
        let Some(raw) = request_raw(req) else {
            return recovery_denied(
                &req.operation_id,
                "restore apply authorization request missing",
            );
        };
        let Ok(request) = serde_json::from_str::<PeerAuthorizationRequest>(raw.get()) else {
            return recovery_denied(
                &req.operation_id,
                "invalid restore apply authorization request",
            );
        };
        if request.peer_pid <= 0 || wire::is_go_zero_time(request.issued_at) {
            return recovery_denied(
                &req.operation_id,
                "invalid restore apply authorization request",
            );
        }
        let Ok(operation_id) = Uuid::parse_str(&req.operation_id) else {
            return recovery_denied(&req.operation_id, "invalid restore operation binding");
        };
        if operation_id.is_nil() {
            return recovery_denied(&req.operation_id, "invalid restore operation binding");
        }
        let Some(journal) = &self.recovery_journal else {
            return recovery_denied("unknown", "recovery journal unavailable");
        };
        let Ok(authorization) = journal.issue_restore_apply_authorization_for_operation(
            operation_id,
            request.peer_uid,
            request.peer_pid,
            request.issued_at.to_offset(time::UtcOffset::UTC),
        ) else {
            return recovery_denied(&req.operation_id, "restore apply authorization denied");
        };
        recovery_success(
            &req.operation_id,
            &apply_authorization_to_wire(&authorization),
            "encode restore apply authorization",
        )
    }

    /// `dispatchRestoreResumeAuthorization` —
    /// `issue_restore_resume_authorization`.
    pub(crate) fn dispatch_restore_resume_authorization(
        &self,
        req: &BrokerRequest,
    ) -> BrokerResponse {
        if self.recovery_journal.is_none() || req.payload.is_none() {
            return recovery_denied("unknown", "recovery journal unavailable");
        }
        let Some(raw) = request_raw(req) else {
            return recovery_denied(
                &req.operation_id,
                "restore resume authorization request missing",
            );
        };
        let Ok(request) = serde_json::from_str::<PeerAuthorizationRequest>(raw.get()) else {
            return recovery_denied(
                &req.operation_id,
                "invalid restore resume authorization request",
            );
        };
        if request.peer_pid <= 0 || wire::is_go_zero_time(request.issued_at) {
            return recovery_denied(
                &req.operation_id,
                "invalid restore resume authorization request",
            );
        }
        let Ok(operation_id) = Uuid::parse_str(&req.operation_id) else {
            return recovery_denied(&req.operation_id, "invalid restore operation binding");
        };
        if operation_id.is_nil() {
            return recovery_denied(&req.operation_id, "invalid restore operation binding");
        }
        let Some(journal) = &self.recovery_journal else {
            return recovery_denied("unknown", "recovery journal unavailable");
        };
        let Ok(authorization) = journal.issue_restore_resume_authorization_for_operation(
            operation_id,
            request.peer_uid,
            request.peer_pid,
            request.issued_at.to_offset(time::UtcOffset::UTC),
        ) else {
            return recovery_denied(&req.operation_id, "restore resume authorization denied");
        };
        recovery_success(
            &req.operation_id,
            &apply_authorization_to_wire(&authorization),
            "encode restore resume authorization",
        )
    }

    /// `dispatchRestoreAbandonAuthorization` —
    /// `issue_restore_abandon_authorization`.
    pub(crate) fn dispatch_restore_abandon_authorization(
        &self,
        req: &BrokerRequest,
    ) -> BrokerResponse {
        if self.recovery_journal.is_none() || req.payload.is_none() {
            return recovery_denied("unknown", "recovery journal unavailable");
        }
        let Some(raw) = request_raw(req) else {
            return recovery_denied(
                &req.operation_id,
                "restore abandon authorization request missing",
            );
        };
        let Ok(request) = serde_json::from_str::<PeerAuthorizationRequest>(raw.get()) else {
            return recovery_denied(
                &req.operation_id,
                "invalid restore abandon authorization request",
            );
        };
        if request.peer_pid <= 0 || wire::is_go_zero_time(request.issued_at) {
            return recovery_denied(
                &req.operation_id,
                "invalid restore abandon authorization request",
            );
        }
        let Ok(operation_id) = Uuid::parse_str(&req.operation_id) else {
            return recovery_denied(&req.operation_id, "invalid restore operation binding");
        };
        if operation_id.is_nil() {
            return recovery_denied(&req.operation_id, "invalid restore operation binding");
        }
        let Some(journal) = &self.recovery_journal else {
            return recovery_denied("unknown", "recovery journal unavailable");
        };
        let Ok(authorization) = journal.issue_restore_abandon_authorization(
            operation_id,
            request.peer_uid,
            request.peer_pid,
            request.issued_at.to_offset(time::UtcOffset::UTC),
        ) else {
            return recovery_denied(&req.operation_id, "restore abandon authorization denied");
        };
        recovery_success(
            &req.operation_id,
            &abandon_authorization_to_wire(&authorization),
            "encode restore abandon authorization",
        )
    }

    /// `dispatchRestoreAbandon` — `abandon_restore`.
    pub(crate) fn dispatch_restore_abandon(&self, req: &BrokerRequest) -> BrokerResponse {
        if self.recovery_journal.is_none() || req.payload.is_none() {
            return recovery_denied("unknown", "recovery journal unavailable");
        }
        let Some(raw) = request_raw(req) else {
            return recovery_denied(&req.operation_id, "restore abandon request missing");
        };
        let Ok(request) = serde_json::from_str::<RestoreAbandonRequest>(raw.get()) else {
            return recovery_denied(&req.operation_id, "invalid restore abandon request");
        };
        if wire::is_go_zero_time(request.at) {
            return recovery_denied(&req.operation_id, "invalid restore abandon request");
        }
        let Ok(operation_id) = Uuid::parse_str(&req.operation_id) else {
            return recovery_denied(&req.operation_id, "invalid restore operation binding");
        };
        if operation_id.is_nil() {
            return recovery_denied(&req.operation_id, "invalid restore operation binding");
        }
        let authorization = RestoreAbandonAuthorization {
            authorization_id: request.authorization.authorization_id,
            operation_id: request.authorization.operation_id,
            issued_at: request.authorization.issued_at,
            expires_at: request.authorization.expires_at,
            acknowledgement: request.authorization.acknowledgement,
        };
        let Some(journal) = &self.recovery_journal else {
            return recovery_denied("unknown", "recovery journal unavailable");
        };
        let Ok(operation) = journal.abandon(
            operation_id,
            &authorization,
            request.at.to_offset(time::UtcOffset::UTC),
        ) else {
            return recovery_denied(&req.operation_id, "restore abandon denied");
        };
        recovery_success(
            &req.operation_id,
            &operation_to_wire(&operation),
            "encode restore abandon outcome",
        )
    }

    /// `dispatchRestoreBarrierInspect` — `inspect_restore_barrier`.
    /// Payload must be exactly empty; the zero-operation marshals
    /// PascalCase inside `{"active":…,"operation":…}`.
    pub(crate) fn dispatch_restore_barrier_inspect(&self, req: &BrokerRequest) -> BrokerResponse {
        // Upstream requires `Payload` non-nil AND empty — a nil payload
        // is denied, `Some(empty)` is the only live shape.
        let payload_ok = matches!(&req.payload, Some(p) if p.is_empty());
        if self.recovery_journal.is_none() || !payload_ok {
            return recovery_denied("unknown", "restore barrier inspection denied");
        }
        if Uuid::parse_str(&req.operation_id).is_err() {
            return recovery_denied(
                &req.operation_id,
                "invalid restore barrier inspection binding",
            );
        }
        let Some(journal) = &self.recovery_journal else {
            return recovery_denied("unknown", "restore barrier inspection denied");
        };
        let Ok((operation, active)) = journal.inspect_restore_barrier() else {
            return recovery_denied(&req.operation_id, "restore barrier unavailable");
        };
        recovery_success(
            &req.operation_id,
            &RestoreBarrierResultWire {
                active,
                operation: operation_to_wire(&operation),
            },
            "encode restore barrier result",
        )
    }

    /// `dispatchRestoreTicketBarrierInspect` —
    /// `inspect_restore_ticket_barrier`.
    pub(crate) fn dispatch_restore_ticket_barrier_inspect(
        &self,
        req: &BrokerRequest,
    ) -> BrokerResponse {
        let payload_ok = matches!(&req.payload, Some(p) if p.is_empty());
        if self.recovery_journal.is_none() || !payload_ok {
            return recovery_denied("unknown", "restore ticket barrier inspection denied");
        }
        if Uuid::parse_str(&req.operation_id).is_err() {
            return recovery_denied(
                &req.operation_id,
                "invalid restore ticket barrier inspection binding",
            );
        }
        let Some(journal) = &self.recovery_journal else {
            return recovery_denied("unknown", "restore ticket barrier inspection denied");
        };
        let Ok(ids) = journal.issued_ticket_operation_ids(OffsetDateTime::now_utc()) else {
            return recovery_denied(&req.operation_id, "restore ticket barrier unavailable");
        };
        // A nil Go slice marshals `null` — an empty-but-live answer is
        // indistinguishable from a nil one at the source, so `None` iff
        // the list is empty.
        recovery_success(
            &req.operation_id,
            &RestoreTicketBarrierResultWire {
                operation_ids: if ids.is_empty() { None } else { Some(ids) },
            },
            "encode restore ticket barrier result",
        )
    }

    /// `dispatchRecoveryBrokerAuthorityReset` — the shared handler for
    /// `prepare_recovery_broker_authority` and
    /// `activate_recovery_bootstrap`.
    pub(crate) fn dispatch_recovery_broker_authority_reset(
        &self,
        req: &BrokerRequest,
    ) -> BrokerResponse {
        let payload_len = req.payload.as_ref().map_or(0, |p| p.len());
        if self.recovery_journal.is_none() || payload_len != 2 {
            return recovery_denied("unknown", "recovery broker authority reset denied");
        }
        let Ok(operation_id) = Uuid::parse_str(&req.operation_id) else {
            return recovery_denied(&req.operation_id, "invalid recovery broker reset request");
        };
        let Some(raw) = request_raw(req) else {
            return recovery_denied(&req.operation_id, "recovery broker reset operation missing");
        };
        let Ok(request) = serde_json::from_str::<RecoveryAuthorityRequest>(raw.get()) else {
            return recovery_denied(&req.operation_id, "invalid recovery broker reset operation");
        };
        if request.operation.operation_id != operation_id {
            return recovery_denied(&req.operation_id, "invalid recovery broker reset operation");
        }
        let operation = request_operation(&request.operation);
        match req.purpose.as_str() {
            RESTORE_BROKER_AUTHORITY_PREPARE_RPC => {
                if request.registration.is_some() {
                    return recovery_denied(&req.operation_id, "unexpected recovery registration");
                }
                let Ok(draft) = self.prepare_recovery_broker_authority(&operation) else {
                    return recovery_denied(
                        &req.operation_id,
                        "recovery broker authority reset denied",
                    );
                };
                recovery_success(
                    &req.operation_id,
                    &draft_to_wire(&draft),
                    "encode recovery broker draft",
                )
            }
            RESTORE_BOOTSTRAP_ACTIVATE_RPC => {
                let Some(registration_wire) = &request.registration else {
                    return recovery_denied(&req.operation_id, "recovery registration missing");
                };
                let Ok(registration) = registration_from_wire(registration_wire) else {
                    return recovery_denied(&req.operation_id, "invalid recovery registration");
                };
                let Ok(activation) = self.activate_recovery_bootstrap(&operation, &registration)
                else {
                    return recovery_denied(
                        &req.operation_id,
                        "recovery bootstrap activation denied",
                    );
                };
                recovery_success(
                    &req.operation_id,
                    &activation_to_wire(&activation),
                    "encode recovery bootstrap activation",
                )
            }
            _ => recovery_denied(&req.operation_id, "unknown recovery authority request"),
        }
    }

    /// `dispatchRestoreIssueLaunch` — `restore_issue_launch`. The
    /// helper's own SO_PEERCRED PID pins the engine child's parent —
    /// never a value from the request body.
    pub(crate) fn dispatch_restore_issue_launch(
        &self,
        req: &BrokerRequest,
        peer: &PeerCred,
    ) -> BrokerResponse {
        let Some(launches) = &self.restore_launches else {
            return restore_launch_denied(&req.operation_id, "unavailable");
        };
        let Some(raw) = request_raw(req) else {
            return restore_launch_denied(&req.operation_id, "missing request");
        };
        let Ok(issue) = serde_json::from_str::<RestoreLaunchIssueRequest>(raw.get()) else {
            return restore_launch_denied(&req.operation_id, "invalid request");
        };
        // `RESTORE_LAUNCH_DENIED: <err>` — the store's own message.
        if let Err(e) = launches.issue(
            &RestoreLaunchEvidence {
                pid: issue.pid,
                process_start: issue.process_start,
                executable: issue.executable,
                mode: issue.mode,
                expires_at: issue.expires_at,
            },
            peer.pid.as_raw_pid(),
        ) {
            return restore_launch_denied(&req.operation_id, e.message());
        }
        // `{"outcome":"success"}` with no `result` — upstream returns a
        // success response with `Result` unset.
        BrokerResponse {
            operation_id: req.operation_id.clone(),
            outcome: central_infra::authority::BrokerOutcome::Success,
            result: None,
            evidence: central_infra::authority::BrokerEvidence {
                operation_id: String::new(),
                code: String::new(),
                message: String::new(),
            },
        }
    }

    // -- C05 lifecycle (service.go) ----------------------------------------

    /// `ResetBootstrapAuthority` — clears the persistent bootstrap
    /// session, scrubs any staged plaintext, and deletes every
    /// recovery-bootstrap generation (a presented-but-never-consumed
    /// token or a crash-time orphan alike).
    pub(crate) fn reset_bootstrap_authority(&self) -> Result<(), Failure> {
        let Some(session) = &self.bootstrap_session else {
            return Err(unavailable());
        };
        session.reset()?;
        {
            let mut guard = self.bootstrap_mu.lock().unwrap_or_else(|e| e.into_inner());
            guard.bootstrap_value.fill(0);
            guard.bootstrap_value.clear();
        }
        let generations = self
            .backend
            .enumerate(RECOVERY_BOOTSTRAP_PURPOSE)
            .map_err(|_| unavailable())?;
        for generation in &generations {
            self.backend
                .delete(generation.generation_id)
                .map_err(|_| unavailable())?;
        }
        Ok(())
    }

    /// `PrepareRecoveryBrokerAuthority` — resets restored broker
    /// authority, rekeys TLS, and creates one protected fresh bootstrap
    /// draft. Plaintext is written only to the protected backend and
    /// never returned across the application port.
    pub(crate) fn prepare_recovery_broker_authority(
        &self,
        operation: &RestoreOperation,
    ) -> Result<RecoveryBootstrapDraft, Failure> {
        let (Some(tls), Some(journal)) = (&self.tls, &self.recovery_journal) else {
            return Err(unavailable());
        };
        if operation.validate().is_err()
            || operation.phase != RestorePhase::Verifying
            || operation.last_checkpoint != RestoreCheckpoint::InventoryVerified
        {
            return Err(unavailable());
        }
        let current = journal
            .read(operation.operation_id)
            .map_err(|_| unavailable())?;
        if current != *operation {
            return Err(unavailable());
        }
        let lock = journal.open_lock(&journal.broker_reset_path(operation.operation_id))?;
        let outcome = (|| -> Result<RecoveryBootstrapDraft, Failure> {
            let (existing, found) = journal.read_broker_reset(operation)?;
            if found {
                return existing.draft();
            }
            self.reset_bootstrap_authority()?;
            tls.rekey().map_err(|e| {
                Failure::internal(
                    "broker",
                    format!("broker recovery TLS rekey: {}", e.message()),
                )
            })?;
            let ca = tls.ca_fingerprint()?;
            let leaf = tls.leaf_fingerprint()?;
            let mut plaintext_seed = Zeroizing::new([0u8; 32]);
            rustix::rand::getrandom(
                &mut plaintext_seed[..],
                rustix::rand::GetRandomFlags::empty(),
            )
            .map_err(|_| unavailable())?;
            let mut plaintext =
                Zeroizing::new(wire::b64_raw_url_encode(&plaintext_seed[..]).into_bytes());
            let verifier_hash: [u8; 32] = {
                use sha2::Digest as _;
                sha2::Sha256::digest(&plaintext[..]).into()
            };
            let mut candidate_digest = [0u8; 32];
            if rustix::rand::getrandom(&mut candidate_digest, rustix::rand::GetRandomFlags::empty())
                .is_err()
            {
                return Err(unavailable());
            }
            let draft_id = Uuid::now_v7();
            let candidate_id = Uuid::now_v7();
            let protected = self
                .backend
                .create(RECOVERY_BOOTSTRAP_PURPOSE, &plaintext[..])
                .map_err(|_| unavailable())?;
            plaintext.zeroize();
            let record = match journal.new_broker_reset_record(
                operation,
                &ca,
                &leaf,
                draft_id,
                candidate_id,
                protected.generation_id,
                verifier_hash,
                candidate_digest,
                OffsetDateTime::now_utc(),
            ) {
                Ok(record) => record,
                Err(e) => {
                    let _ = self.backend.delete(protected.generation_id);
                    return Err(e);
                }
            };
            let path = journal.broker_reset_path(operation.operation_id);
            if journal.write_exclusive_json(&path, &record).is_err() {
                // Resolve a possible publish-response ambiguity by
                // accepting only the exact authenticated record for
                // this immutable operation.
                let (existing, found) = journal
                    .read_broker_reset(operation)
                    .map_err(|_| unavailable())?;
                if !found || existing != record {
                    let _ = self.backend.delete(protected.generation_id);
                    return Err(unavailable());
                }
            }
            record.draft()
        })();
        super::durable::unlock_and_close(lock);
        outcome
    }

    /// `ActivateRecoveryBootstrap` — registers and activates only the
    /// exact fresh generation committed by PostgreSQL. Exact replay is
    /// idempotent across a broker restart; any changed generation or
    /// receipt is denied.
    pub(crate) fn activate_recovery_bootstrap(
        &self,
        operation: &RestoreOperation,
        registration: &RecoveryBootstrapRegistration,
    ) -> Result<RecoveryBootstrapActivation, Failure> {
        let (Some(session), Some(journal)) = (&self.bootstrap_session, &self.recovery_journal)
        else {
            return Err(unavailable());
        };
        if operation.validate().is_err() {
            return Err(unavailable());
        }
        let lock = journal.open_lock(&journal.broker_reset_path(operation.operation_id))?;
        let outcome = (|| -> Result<RecoveryBootstrapActivation, Failure> {
            let (mut record, found) = journal.read_broker_reset(operation)?;
            if !found {
                return Err(unavailable());
            }
            let draft = record.draft()?;
            if registration.validate_for(operation, &draft).is_err() {
                return Err(unavailable());
            }
            if let Some(activation) = &record.activation {
                let activation = broker_activation_from_record(&record, activation);
                if activation.validate_for(operation, registration).is_err() {
                    return Err(unavailable());
                }
                return Ok(activation);
            }
            let binding = CandidateBinding {
                candidate_id: registration.candidate_id.to_string(),
                generation: registration.generation,
                digest: Zeroizing::new(registration.candidate_digest),
            };
            if !session.activated(&binding) {
                session.register(&binding)?;
                session.activate(&binding)?;
            }
            let mut activated_at = OffsetDateTime::now_utc();
            if activated_at < registration.registered_at {
                activated_at = registration.registered_at;
            }
            #[derive(Serialize)]
            struct ActivationPayload {
                operation_id: Uuid,
                draft_id: Uuid,
                candidate_id: Uuid,
                generation: u64,
                database_receipt_hash: String,
            }
            let payload = serde_json::to_vec(&ActivationPayload {
                operation_id: operation.operation_id,
                draft_id: registration.draft_id,
                candidate_id: registration.candidate_id,
                generation: registration.generation,
                database_receipt_hash: registration.database_receipt_hash.clone(),
            })
            .map_err(|_| unavailable())?;
            record.activation = Some(recovery_journal::RecoveryBootstrapActivationRecord {
                generation: registration.generation,
                database_receipt_hash: registration.database_receipt_hash.clone(),
                activation_receipt_hash: format!(
                    "sha256:{}",
                    self.signing
                        .fingerprint("slice-c-recovery-bootstrap-activation-v1", &payload)
                ),
                activated_at,
                presented_at: wire::go_zero_time(),
            });
            if journal.sign_broker_reset_record(&mut record).is_err()
                || journal
                    .replace_json(&journal.broker_reset_path(operation.operation_id), &record)
                    .is_err()
            {
                return Err(unavailable());
            }
            let activation = broker_activation_from_record(
                &record,
                record
                    .activation
                    .as_ref()
                    .unwrap_or_else(|| unreachable!("set above")),
            );
            Ok(activation)
        })();
        super::durable::unlock_and_close(lock);
        outcome
    }
}

/// `brokerActivationFromRecord` — the activation the journal record
/// carries, re-bound to the registration the caller presented.
fn broker_activation_from_record(
    record: &RecoveryBrokerResetRecord,
    activation: &recovery_journal::RecoveryBootstrapActivationRecord,
) -> RecoveryBootstrapActivation {
    RecoveryBootstrapActivation {
        operation_id: record.operation_id,
        draft_id: record.draft_id,
        candidate_id: record.candidate_id,
        generation: activation.generation,
        database_receipt_hash: activation.database_receipt_hash.clone(),
        activation_receipt_hash: activation.activation_receipt_hash.clone(),
        activated_at: activation.activated_at,
    }
}

/// The request-side `backup.RestoreOperation` decode — a
/// `RestoreOperation` built from the tolerant wire. Upstream passes
/// the decoded struct straight through; `Validate()` rungs in the
/// called methods reject malformed values exactly as upstream's.
fn request_operation(w: &RestoreOperationRequestWire) -> RestoreOperation {
    use central_backup::domain::TargetIdentity;
    RestoreOperation {
        operation_id: w.operation_id,
        ticket_id: w.ticket_id,
        backup_id: w.backup_id,
        target: TargetIdentity {
            system_id: w.target.system_id.clone(),
            database_oid: w.target.database_oid.clone(),
            database: w.target.database.clone(),
            config_hash: w.target.config_hash.clone(),
            epoch: w.target.epoch,
        },
        target_fingerprint: w.target_fingerprint.clone(),
        manifest_digest: w.manifest_digest.clone(),
        payload_epoch_id: w.payload_epoch_id,
        database_schema_version: w.database_schema_version.clone(),
        capacity_evidence_digest: w.capacity_evidence_digest.clone(),
        security_epoch: w.security_epoch,
        restore_epoch: w.restore_epoch,
        revision: w.revision,
        phase: restore_phase(&w.phase),
        last_checkpoint: restore_checkpoint(&w.last_checkpoint),
        authority_reset_receipt_hash: w.authority_reset_receipt_hash.clone(),
        started_at: w.started_at,
        updated_at: w.updated_at,
        ready_at: w.ready_at,
    }
}

/// `json.Unmarshal` into a Go `RestorePhase` decodes the string
/// through its `UnmarshalJSON` — an unknown value is a decode error
/// upstream. The operation validate() calls downstream reject nil
/// phases identically, so map unknown values to the same "invalid"
/// terminal the operation's own validation produces (a phase value
/// that `validate()` refuses).
fn restore_phase(value: &str) -> RestorePhase {
    match value {
        "applying" => RestorePhase::Applying,
        "verifying" => RestorePhase::Verifying,
        "quarantined" => RestorePhase::Quarantined,
        "ready" => RestorePhase::Ready,
        "abandoned" => RestorePhase::Abandoned,
        // Unknown/absent — Go's custom unmarshal keeps the zero value
        // ("") which `operation.Validate()` then rejects; map it onto a
        // phase `validate()` also refuses (Applying is not valid for a
        // zero operation but IS a real variant — the zero-string maps
        // there are equivalent for the deny paths, since both
        // `PrepareRecoveryBrokerAuthority` requires Verifying and
        // `ActivateRecoveryBootstrap` requires operation.Validate()).
        _ => RestorePhase::Applying,
    }
}

fn restore_checkpoint(value: &str) -> RestoreCheckpoint {
    match value {
        "ticket_consumed" => RestoreCheckpoint::TicketConsumed,
        "database_replaced" => RestoreCheckpoint::DatabaseReplaced,
        "inventory_verified" => RestoreCheckpoint::InventoryVerified,
        "authority_reset" => RestoreCheckpoint::AuthorityReset,
        _ => RestoreCheckpoint::TicketConsumed,
    }
}

fn unavailable() -> Failure {
    Failure::internal("broker", "broker: authority store unavailable")
}

// ---------------------------------------------------------------------------
// Client half — `recovery_authority_rpc.go`'s
// `RestoreApplyAuthorizationIssuer` and `RestoreAbandonClient`. Each is
// deliberately not a general recovery client: the issuer can only ask
// the broker to issue a fresh one-use authorization; the abandon
// client runs the issuance half and then spends exactly what it was
// given on one terminal transition. Every call wraps the
// `{peer_uid, peer_pid, issued_at}` payload in the standard
// `{"request": ...}` envelope through `call_with_operation_id`, so
// the broker records carry the protected operation identity.
// ---------------------------------------------------------------------------

/// `{peer_uid, peer_pid, issued_at}` — the client-side mirror of
/// `restoreApplyAuthorizationRequest`/`restoreResumeAuthorizationRequest`/
/// `restoreAbandonAuthorizationRequest` (identical shapes).
#[derive(Serialize)]
struct PeerAuthorizationRequestWire {
    peer_uid: u32,
    peer_pid: i32,
    #[serde(with = "wire::rfc3339")]
    issued_at: OffsetDateTime,
}

fn recovery_client_unavailable(what: &str) -> Failure {
    Failure::internal(
        "broker_recovery_client",
        format!("broker {what}: unavailable"),
    )
}

fn recovery_client_denied(what: &str) -> Failure {
    Failure::denied("broker_recovery_client", format!("broker {what}: denied"))
}

/// `RestoreApplyAuthorizationIssuer` — asks the broker to issue a
/// fresh one-use apply/resume authorization bound to the protected
/// ticket record; the helper never learns the ticket HMAC.
/// `dead_code`: the apply/resume handlers this feeds stay
/// unconfigured until the restore engine launcher lands (upstream
/// composes them `WithEngine` only — the authorization must never
/// reach the operator); the type is the R6T7 wire seam that
/// composition then wires.
#[allow(dead_code)]
pub struct RestoreApplyAuthorizationIssuer {
    client: LifecycleClient,
}

#[allow(dead_code)]
impl RestoreApplyAuthorizationIssuer {
    /// `NewRestoreApplyAuthorizationIssuer`.
    pub fn new(socket_path: std::path::PathBuf) -> Result<Self, Failure> {
        if socket_path.as_os_str().is_empty() {
            return Err(recovery_client_unavailable("restore apply authorization"));
        }
        Ok(Self {
            client: LifecycleClient::new(socket_path),
        })
    }
}

impl crate::helper::restore::RestoreApplyAuthorizationIssuer for RestoreApplyAuthorizationIssuer {
    /// `IssueRestoreApplyAuthorizationForOperation`. The one-
    /// nanosecond nudge mirrors upstream exactly: the honest broker
    /// echoes the transmitted `issued_at` back as the authorization's
    /// `IssuedAt`, and `valid_at` requires `now` strictly after it —
    /// validating at the exact issuing instant could never succeed.
    fn issue_restore_apply_authorization(
        &self,
        _deadline: Instant,
        operation_id: Uuid,
        peer_uid: u32,
        peer_pid: i32,
        issued_at: OffsetDateTime,
    ) -> Result<RestoreApplyAuthorization, Failure> {
        if operation_id.is_nil() || peer_pid <= 0 || issued_at == OffsetDateTime::UNIX_EPOCH {
            return Err(recovery_client_unavailable("restore apply authorization"));
        }
        let wire: RestoreApplyAuthorizationWire = self
            .client
            .call_with_operation_id(
                &operation_id.to_string(),
                RESTORE_APPLY_AUTHORIZATION_RPC,
                &PeerAuthorizationRequestWire {
                    peer_uid,
                    peer_pid,
                    issued_at,
                },
            )
            .map_err(|_| recovery_client_denied("restore apply authorization"))?;
        let authorization = apply_authorization_from_wire(&wire);
        if authorization.operation_id != operation_id
            || authorization.ticket_id.is_nil()
            || !authorization.valid_at(issued_at + time::Duration::NANOSECOND)
        {
            return Err(recovery_client_denied("restore apply authorization"));
        }
        Ok(authorization)
    }

    /// `IssueRestoreResumeAuthorizationForOperation` — identical
    /// shape, resume RPC; the same echoed-`IssuedAt` epsilon applies.
    fn issue_restore_resume_authorization(
        &self,
        _deadline: Instant,
        operation_id: Uuid,
        peer_uid: u32,
        peer_pid: i32,
        issued_at: OffsetDateTime,
    ) -> Result<RestoreApplyAuthorization, Failure> {
        if operation_id.is_nil() || peer_pid <= 0 || issued_at == OffsetDateTime::UNIX_EPOCH {
            return Err(recovery_client_unavailable("restore resume authorization"));
        }
        let wire: RestoreApplyAuthorizationWire = self
            .client
            .call_with_operation_id(
                &operation_id.to_string(),
                RESTORE_RESUME_AUTHORIZATION_RPC,
                &PeerAuthorizationRequestWire {
                    peer_uid,
                    peer_pid,
                    issued_at,
                },
            )
            .map_err(|_| recovery_client_denied("restore resume authorization"))?;
        let authorization = apply_authorization_from_wire(&wire);
        if authorization.operation_id != operation_id
            || authorization.ticket_id.is_nil()
            || !authorization.valid_at(issued_at + time::Duration::NANOSECOND)
        {
            return Err(recovery_client_denied("restore resume authorization"));
        }
        Ok(authorization)
    }
}

/// `RestoreAbandonClient` — the helper's narrow ADR 0016 view: it can
/// ask the broker to run the issuance half and then consume what it
/// was given; it cannot read, begin, or resume anything.
pub struct RestoreAbandonClient {
    client: LifecycleClient,
}

impl RestoreAbandonClient {
    /// `NewRestoreAbandonClient`.
    pub fn new(socket_path: std::path::PathBuf) -> Result<Self, Failure> {
        if socket_path.as_os_str().is_empty() {
            return Err(recovery_client_unavailable("restore abandon"));
        }
        Ok(Self {
            client: LifecycleClient::new(socket_path),
        })
    }
}

impl crate::helper::restore::RestoreAbandonAuthority for RestoreAbandonClient {
    /// `IssueRestoreAbandonAuthorizationForOperation`. The
    /// acknowledgement check and the one-nanosecond `IssuedAt` epsilon
    /// both mirror upstream verbatim.
    fn issue_restore_abandon_authorization(
        &self,
        _deadline: Instant,
        operation_id: Uuid,
        peer_uid: u32,
        peer_pid: i32,
        issued_at: OffsetDateTime,
    ) -> Result<RestoreAbandonAuthorization, Failure> {
        if operation_id.is_nil() || peer_pid <= 0 || issued_at == OffsetDateTime::UNIX_EPOCH {
            return Err(recovery_client_unavailable("restore abandon authorization"));
        }
        let wire: RestoreAbandonAuthorizationWire = self
            .client
            .call_with_operation_id(
                &operation_id.to_string(),
                RESTORE_ABANDON_AUTHORIZATION_RPC,
                &PeerAuthorizationRequestWire {
                    peer_uid,
                    peer_pid,
                    issued_at,
                },
            )
            .map_err(|_| recovery_client_denied("restore abandon authorization"))?;
        let authorization = abandon_authorization_from_wire(&wire);
        if authorization.operation_id != operation_id
            || authorization.acknowledgement
                != central_backup::recovery::operation::RESTORE_ABANDON_ACKNOWLEDGEMENT
            || !authorization.valid_at(issued_at + time::Duration::NANOSECOND)
        {
            return Err(recovery_client_denied("restore abandon authorization"));
        }
        Ok(authorization)
    }

    /// `AbandonRestore` — consumes the issued authorization on exactly
    /// one terminal transition; the result must be `abandoned` and
    /// valid, or the outcome is invalid at the boundary.
    fn abandon_restore(
        &self,
        _deadline: Instant,
        operation_id: Uuid,
        authorization: &RestoreAbandonAuthorization,
        at: OffsetDateTime,
    ) -> Result<RestoreOperation, Failure> {
        if operation_id.is_nil()
            || at == OffsetDateTime::UNIX_EPOCH
            || authorization.operation_id != operation_id
            || !authorization.valid_at(at)
        {
            return Err(recovery_client_unavailable("restore abandon"));
        }
        /// `restoreAbandonRequest` — `{authorization, at}`.
        #[derive(Serialize)]
        struct AbandonRequestWire {
            authorization: RestoreAbandonAuthorizationWire,
            #[serde(with = "wire::rfc3339")]
            at: OffsetDateTime,
        }
        let wire: RestoreOperationWire = self
            .client
            .call_with_operation_id(
                &operation_id.to_string(),
                RESTORE_ABANDON_RPC,
                &AbandonRequestWire {
                    authorization: abandon_authorization_to_wire(authorization),
                    at,
                },
            )
            .map_err(|_| recovery_client_denied("restore abandon"))?;
        let operation =
            operation_from_wire(&wire).map_err(|_| recovery_client_denied("restore abandon"))?;
        if operation.operation_id != operation_id
            || operation.validate().is_err()
            || operation.phase != RestorePhase::Abandoned
        {
            return Err(recovery_client_denied("restore abandon"));
        }
        Ok(operation)
    }
}
