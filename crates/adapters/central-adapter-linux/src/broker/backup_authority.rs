//! Backup authority RPC dispatch — `backup_authority_rpc.go`,
//! `backup_throughput_launch_rpc.go`, `backup_throughput_rpc.go`, and
//! `backup_payload_epoch_rpc.go` ported with upstream's peer routing
//! preserved.
//!
//! Two caller classes reach these handlers from `server.rs`'s
//! `dispatch_json`:
//!
//! - **Root helpers** (`isRootBackupHelperPeer`): launch issuance,
//!   MinIO handoff, reap/complete/verify/status, throughput launch and
//!   journal authority, payload-epoch genesis.
//! - **Backup workers** (exact runtime uid/gid from the launch store,
//!   then per-handler `ValidateWorker`/`ValidateWorkerOperation`
//!   process-identity checks): seal, worker context, payload-epoch
//!   read, throughput read, journal create/read/CAS, throughput
//!   worker context/target-lock/stage.
//!
//! Every denial is upstream's `backupRPCDenied` — `Code` and `Message`
//! both carry the denial code and the evidence `operation_id` is left
//! empty, exactly as upstream's helper constructs it.
//!
//! Wire notes: request decode goes through
//! [`decode_exact_broker_payload`], the upstream
//! `decodeExactBrokerPayload` — exactly one `request` key,
//! `DisallowUnknownFields`, then a canonical `json.Marshal` of the
//! decoded value must byte-equal the raw bytes. Result marshal mirrors
//! `backupRPCSuccess`: `json.Marshal(result)` — typed structs in Go
//! declaration order, `time.Time` as RFC3339Nano, `time.Duration` as
//! integer nanoseconds, `[32]byte` as number arrays, `[]byte` as
//! standard base64, and Go's HTML escaping applied via
//! [`wire::go_json_escape`].

use central_backup::backup::operation::{BackupOperation, BackupPhase};
use central_backup::repository::{BackupRepositoryAttestation, BackupTargetLockAttestation};
use central_foundation::failure::Failure;
use central_infra::authority::{BrokerRequest, BrokerResponse, RecoveryMinioHandoffRequest};
use central_infra::domain::Purpose;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use time::OffsetDateTime;
use uuid::Uuid;

use super::backup_launch::{BackupLaunchEvidence, binding_from_wire};
use super::backup_throughput_launch::{
    BackupThroughputFixtureLoadAttestation, BackupThroughputTargetLockAttestation,
};
use super::protocol::*;
use super::recovery_journal::{
    BackupAcceptedFactsWire, BackupOperationWire, BackupRepositoryAttestationJournalWire,
    BackupSealProposalWire, BackupTargetLockJournalWire, accepted_facts_from_wire,
    attestation_from_wire, backup_operation_from_wire, backup_operation_to_wire,
    seal_companion_to_wire, seal_proposal_from_wire, target_lock_from_wire,
};
use super::server::{Service, backup_denied, success};
use super::throughput_journal::{
    ThroughputCleanupCounts, ThroughputEvidenceWire, evidence_from_wire, evidence_to_wire,
    new_throughput_cleanup_attestation, new_throughput_cleanup_resolution,
};
use super::wire;
use crate::sys::peercred::PeerCred;

/// `decodeExactBrokerPayload` — the request decodes only when the
/// payload is exactly `{"request": <canonical>}`: strict unknown-field
/// rejection, no trailing JSON value, and a canonical re-marshal of
/// the decoded value byte-equal to the raw bytes. The canonical form
/// is Go's `json.Marshal` — declaration-order fields plus HTML
/// escaping.
fn decode_exact_broker_payload<T>(req: &BrokerRequest) -> Option<T>
where
    T: serde::de::DeserializeOwned + Serialize,
{
    let payload = req.payload.as_ref()?;
    if payload.len() != 1 {
        return None;
    }
    let raw = payload.get("request")?;
    let decoded: T = serde_json::from_str(raw.get()).ok()?;
    let canonical = serde_json::to_string(&decoded).ok()?;
    let canonical = wire::go_json_escape(&canonical);
    (canonical.as_bytes() == raw.get().as_bytes()).then_some(decoded)
}

/// `backupRPCSuccess` — `json.Marshal(result)` embedded verbatim;
/// a marshal failure degrades to `BACKUP_AUTHORITY_ERROR`, exactly
/// as upstream.
fn backup_success<T: Serialize>(operation_id: &str, result: &T) -> BrokerResponse {
    let Ok(serialized) = serde_json::to_string(result) else {
        return backup_denied(operation_id, "BACKUP_AUTHORITY_ERROR");
    };
    let escaped = wire::go_json_escape(&serialized);
    match serde_json::value::RawValue::from_string(escaped) {
        Ok(raw) => success(operation_id, raw),
        Err(_) => backup_denied(operation_id, "BACKUP_AUTHORITY_ERROR"),
    }
}

// ---------------------------------------------------------------------------
// Request wire shapes — snake_case request structs (upstream tags) and
// PascalCase domain values. All are `deny_unknown_fields`, matching
// `DisallowUnknownFields`; `[32]byte` fields decode through
// `wire::digest32` (Go's zero-pad/truncate array semantics — the
// canonical compare then refuses anything that was not already the
// exact marshal).
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackupWorkerIdentityRPCRequest {
    pub(crate) launch_evidence_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackupWorkerOperationRPCRequest {
    pub(crate) launch_evidence_id: Uuid,
    pub(crate) operation: BackupOperationWire,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackupWorkerThroughputRPCRequest {
    pub(crate) launch_evidence_id: Uuid,
    pub(crate) operation: BackupOperationWire,
    pub(crate) accepted_facts: BackupAcceptedFactsWire,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackupWorkerCASRPCRequest {
    pub(crate) launch_evidence_id: Uuid,
    pub(crate) expected: BackupOperationWire,
    pub(crate) next: BackupOperationWire,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackupSealRPCRequest {
    pub(crate) launch_evidence_id: Uuid,
    pub(crate) proposal: BackupSealProposalWire,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupReapedRPCRequest {
    operation_id: Uuid,
    launch_evidence_id: Uuid,
    #[serde(with = "wire::digest32")]
    target_lock_proof: [u8; 32],
    #[serde(with = "wire::rfc3339")]
    reaped_at: OffsetDateTime,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupCompleteRPCRequest {
    operation_id: Uuid,
    launch_evidence_id: Uuid,
    attestation: BackupRepositoryAttestationJournalWire,
    target_lock_attestation: BackupTargetLockJournalWire,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupVerifySealRPCRequest {
    backup_id: Uuid,
    #[serde(with = "wire::digest32")]
    manifest_digest_sha256: [u8; 32],
    #[serde(with = "wire::digest32")]
    seal_companion_digest_sha256: [u8; 32],
    #[serde(with = "wire::digest32")]
    file_tree_digest_sha256: [u8; 32],
    #[serde(with = "wire::digest32")]
    repository_manifest_digest_sha256: [u8; 32],
    repository_revision: u64,
}

/// `helper.BackupLaunchEvidence` — the root helper's worker launch
/// claim. `repository_binding` marshals PascalCase inside.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupLaunchEvidenceWire {
    supervisor_launch_id: Uuid,
    pid: i32,
    process_start: String,
    executable: String,
    mode: String,
    operation_id: String,
    repository_binding: super::backup_launch::RepositoryBindingJournalWire,
    #[serde(with = "wire::rfc3339")]
    expires_at: OffsetDateTime,
}

/// `authority.RecoveryMinioHandoffRequest` — Go carries NO json tags
/// here: the request marshals PascalCase (unlike the receipt).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryMinioHandoffRequestWire {
    #[serde(rename = "OperationID")]
    operation_id: String,
    #[serde(rename = "InstanceID")]
    instance_id: String,
    #[serde(rename = "Purpose")]
    purpose: String,
    #[serde(rename = "Bucket")]
    bucket: String,
    #[serde(rename = "KeyPrefix")]
    key_prefix: String,
    #[serde(rename = "PolicyDigest")]
    policy_digest: String,
    #[serde(rename = "ExpiresAt", with = "wire::rfc3339")]
    expires_at: OffsetDateTime,
    #[serde(rename = "FenceToken")]
    fence_token: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackupThroughputWorkerIdentityRequest {
    pub(crate) launch_evidence_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackupThroughputWorkerStageRequest {
    pub(crate) launch_evidence_id: Uuid,
    pub(crate) evidence: ThroughputEvidenceWire,
    #[serde(with = "wire::rfc3339")]
    pub(crate) staged_at: OffsetDateTime,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupThroughputFixtureLoadedRequest {
    launch_evidence_id: Uuid,
    attestation: BackupThroughputFixtureLoadAttestation,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackupThroughputWorkerTargetRequest {
    pub(crate) launch_evidence_id: Uuid,
    pub(crate) attestation: BackupThroughputTargetLockAttestation,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupThroughputAcceptRequest {
    #[serde(with = "wire::rfc3339")]
    accepted_at: OffsetDateTime,
    #[serde(with = "wire::rfc3339")]
    deadline: OffsetDateTime,
}

/// `backupThroughputCompleteRequest` — `time.Duration` fields are
/// integer nanoseconds on the wire.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupThroughputCompleteRequest {
    launch_evidence_id: Uuid,
    #[serde(with = "wire::digest32")]
    retained_target_lock_proof_sha256: [u8; 32],
    worker_tree_reaped: bool,
    counts: ThroughputCleanupCounts,
    #[serde(
        serialize_with = "ser_duration_ns",
        deserialize_with = "de_duration_ns"
    )]
    parent_elapsed: time::Duration,
    #[serde(with = "wire::rfc3339")]
    attested_at: OffsetDateTime,
}

fn ser_duration_ns<S: serde::Serializer>(d: &time::Duration, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_i64(d.whole_nanoseconds() as i64)
}

fn de_duration_ns<'de, D: serde::Deserializer<'de>>(d: D) -> Result<time::Duration, D::Error> {
    let ns = i64::deserialize(d)?;
    Ok(time::Duration::nanoseconds(ns))
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupThroughputTerminalRequest {
    #[serde(with = "wire::rfc3339")]
    at: OffsetDateTime,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupThroughputCleanupResolutionRequest {
    counts: ThroughputCleanupCounts,
    #[serde(with = "wire::rfc3339")]
    at: OffsetDateTime,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupThroughputActivateRequest {
    #[serde(with = "wire::rfc3339")]
    activated_at: OffsetDateTime,
}

/// `struct{}` — `backup_read_status`/`backup_throughput_current_attempt`/
/// `backup_ensure_payload_epoch` carry an empty object.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyRequest {}

// ---------------------------------------------------------------------------
// Result wire shapes — upstream's literal `struct{...}` results and
// the named result types, all in Go declaration order.
// ---------------------------------------------------------------------------

fn is_false(v: &bool) -> bool {
    !*v
}

#[derive(Serialize, Deserialize)]
pub(crate) struct BackupLaunchAuthorityWire {
    pub(crate) launch_evidence_id: Uuid,
    pub(crate) operation_id: Uuid,
    pub(crate) backup_id: Uuid,
}

#[derive(Serialize, Deserialize)]
struct BackupStatusResultWire {
    operation_id: String,
    backup_id: String,
    phase: String,
    reason: String,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct PayloadEpochResult {
    pub(crate) payload_epoch_id: Uuid,
}

/// `BackupThroughputAttemptStatus` — the root reconciliation view.
/// `,omitempty` never fires on `uuid.UUID`/`time.Time`/`[32]byte`
/// (fixed-size composite types are never "empty" to Go), so those
/// fields always serialize; only the string fields and the
/// `cleanup_attested` bool honor omitempty.
#[derive(Serialize)]
struct BackupThroughputAttemptStatusWire {
    found: bool,
    operation_id: Uuid,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    phase: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    selector_phase: String,
    #[serde(with = "wire::rfc3339")]
    accepted_at: OffsetDateTime,
    #[serde(with = "wire::rfc3339")]
    deadline: OffsetDateTime,
    #[serde(with = "wire::rfc3339")]
    activated_at: OffsetDateTime,
    #[serde(with = "wire::rfc3339")]
    cleanup_resolved_at: OffsetDateTime,
    #[serde(with = "wire::rfc3339")]
    expires_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "is_false")]
    cleanup_attested: bool,
    supervisor_launch_id: Uuid,
    launch_evidence_id: Uuid,
    repository_binding_id: Uuid,
    target_lock_proof_sha256: [u8; 32],
    #[serde(default, skip_serializing_if = "String::is_empty")]
    minio_seed_binding: String,
}

impl Default for BackupThroughputAttemptStatusWire {
    fn default() -> Self {
        let zero = wire::go_zero_time();
        Self {
            found: false,
            operation_id: Uuid::nil(),
            phase: String::new(),
            selector_phase: String::new(),
            accepted_at: zero,
            deadline: zero,
            activated_at: zero,
            cleanup_resolved_at: zero,
            expires_at: zero,
            cleanup_attested: false,
            supervisor_launch_id: Uuid::nil(),
            launch_evidence_id: Uuid::nil(),
            repository_binding_id: Uuid::nil(),
            target_lock_proof_sha256: [0u8; 32],
            minio_seed_binding: String::new(),
        }
    }
}

/// `backupStatusReason` — the operator-facing reason vocabulary.
fn backup_status_reason(operation: &BackupOperation) -> &'static str {
    match operation.phase {
        BackupPhase::Sealed => "BACKUP_SEALED",
        BackupPhase::Failed => "",
        BackupPhase::Planned
        | BackupPhase::Admitted
        | BackupPhase::Dumping
        | BackupPhase::Inventory
        | BackupPhase::Sealing => "BACKUP_IN_PROGRESS",
    }
}

impl Service {
    // -- root-helper backup arms (HandleConn's isRootBackupHelperPeer gate) --

    /// `dispatchBackupLaunchIssue` — `backup_issue_launch`.
    pub(crate) fn dispatch_backup_launch_issue(&self, req: &BrokerRequest) -> BrokerResponse {
        const CODE: &str = "BACKUP_LAUNCH_DENIED";
        let Some(evidence) = decode_exact_broker_payload::<BackupLaunchEvidenceWire>(req) else {
            return backup_denied(&req.operation_id, CODE);
        };
        if evidence.operation_id != req.operation_id {
            return backup_denied(&req.operation_id, CODE);
        }
        let Ok(repository_binding) = binding_from_wire(&evidence.repository_binding) else {
            return backup_denied(&req.operation_id, CODE);
        };
        let Some(launches) = &self.backup_launches else {
            return backup_denied(&req.operation_id, CODE);
        };
        match launches.issue(&BackupLaunchEvidence {
            supervisor_launch_id: evidence.supervisor_launch_id,
            pid: evidence.pid,
            process_start: evidence.process_start,
            executable: evidence.executable,
            mode: evidence.mode,
            operation_id: evidence.operation_id,
            repository_binding,
            expires_at: evidence.expires_at,
        }) {
            Err(_) => backup_denied(&req.operation_id, CODE),
            Ok(issued) => backup_success(
                &req.operation_id,
                &BackupLaunchAuthorityWire {
                    launch_evidence_id: issued.launch_evidence_id,
                    operation_id: issued.operation_id,
                    backup_id: issued.backup_id,
                },
            ),
        }
    }

    /// `dispatchBackupMinioIssue` — `backup_issue_minio_handoff`.
    pub(crate) fn dispatch_backup_minio_issue(&self, req: &BrokerRequest) -> BrokerResponse {
        const CODE: &str = "BACKUP_MINIO_HANDOFF_DENIED";
        let Some(request) = decode_exact_broker_payload::<RecoveryMinioHandoffRequestWire>(req)
        else {
            return backup_denied(&req.operation_id, CODE);
        };
        if request.operation_id != req.operation_id {
            return backup_denied(&req.operation_id, CODE);
        }
        let Some(journal) = &self.recovery_journal else {
            return backup_denied(&req.operation_id, CODE);
        };
        match journal.issue_minio_handoff(&RecoveryMinioHandoffRequest {
            operation_id: request.operation_id,
            instance_id: request.instance_id,
            purpose: request.purpose,
            bucket: request.bucket,
            key_prefix: request.key_prefix,
            policy_digest: request.policy_digest,
            expires_at: request.expires_at,
            fence_token: request.fence_token,
        }) {
            Err(_) => backup_denied(&req.operation_id, CODE),
            Ok(receipt) => backup_success(&req.operation_id, &receipt),
        }
    }

    /// `dispatchBackupMarkReaped` — `backup_mark_launch_reaped`.
    pub(crate) fn dispatch_backup_mark_reaped(&self, req: &BrokerRequest) -> BrokerResponse {
        const CODE: &str = "BACKUP_REAP_EVIDENCE_DENIED";
        let Some(request) = decode_exact_broker_payload::<BackupReapedRPCRequest>(req) else {
            return backup_denied(&req.operation_id, CODE);
        };
        if request.operation_id.to_string() != req.operation_id
            || request.launch_evidence_id.is_nil()
            || request.target_lock_proof == [0u8; 32]
            || wire::is_go_zero_time(request.reaped_at)
        {
            return backup_denied(&req.operation_id, CODE);
        }
        let Some(launches) = &self.backup_launches else {
            return backup_denied(&req.operation_id, CODE);
        };
        match launches.mark_reaped(
            request.launch_evidence_id,
            request.operation_id,
            request.target_lock_proof,
            request.reaped_at,
        ) {
            Err(_) => backup_denied(&req.operation_id, CODE),
            Ok(()) => backup_success(&req.operation_id, &serde_json::json!({"reaped": true})),
        }
    }

    /// `dispatchBackupComplete` — `backup_complete_attested_seal`.
    pub(crate) fn dispatch_backup_complete(&self, req: &BrokerRequest) -> BrokerResponse {
        const CODE: &str = "BACKUP_ATTESTATION_DENIED";
        let Some(request) = decode_exact_broker_payload::<BackupCompleteRPCRequest>(req) else {
            return backup_denied(&req.operation_id, CODE);
        };
        let (Ok(attestation), Ok(target_lock)) = (
            attestation_from_wire(&request.attestation),
            target_lock_from_wire(&request.target_lock_attestation),
        ) else {
            return backup_denied(&req.operation_id, CODE);
        };
        let (Some(attestation), Some(target_lock)) = (attestation, target_lock) else {
            return backup_denied(&req.operation_id, CODE);
        };
        if request.operation_id.to_string() != req.operation_id
            || request.launch_evidence_id.is_nil()
            || attestation.operation_id != request.operation_id
            || attestation.launch_evidence_id != request.launch_evidence_id
            || target_lock.operation_id != request.operation_id
            || target_lock.launch_evidence_id != request.launch_evidence_id
        {
            return backup_denied(&req.operation_id, CODE);
        }
        match self.complete_attested_backup_seal(
            request.operation_id,
            request.launch_evidence_id,
            &attestation,
            &target_lock,
        ) {
            Err(_) => backup_denied(&req.operation_id, CODE),
            Ok(operation) => {
                backup_success(&req.operation_id, &backup_operation_to_wire(&operation))
            }
        }
    }

    /// `dispatchBackupVerifySeal` — `backup_verify_seal`.
    pub(crate) fn dispatch_backup_verify_seal(&self, req: &BrokerRequest) -> BrokerResponse {
        const CODE: &str = "BACKUP_VERIFY_DENIED";
        let Some(request) = decode_exact_broker_payload::<BackupVerifySealRPCRequest>(req) else {
            return backup_denied(&req.operation_id, CODE);
        };
        let Some(journal) = &self.recovery_journal else {
            return backup_denied(&req.operation_id, CODE);
        };
        if request.backup_id.to_string() != req.operation_id
            || journal
                .verify_backup_seal(
                    request.backup_id,
                    request.manifest_digest_sha256,
                    request.seal_companion_digest_sha256,
                    request.file_tree_digest_sha256,
                    request.repository_manifest_digest_sha256,
                    request.repository_revision,
                )
                .is_err()
        {
            return backup_denied(&req.operation_id, CODE);
        }
        backup_success(&req.operation_id, &serde_json::json!({"verified": true}))
    }

    /// `dispatchBackupReadStatus` — `backup_read_status`.
    pub(crate) fn dispatch_backup_read_status(&self, req: &BrokerRequest) -> BrokerResponse {
        const CODE: &str = "BACKUP_STATUS_DENIED";
        let operation_id = Uuid::parse_str(&req.operation_id).unwrap_or_default();
        if decode_exact_broker_payload::<EmptyRequest>(req).is_none()
            || operation_id.is_nil()
            || operation_id.get_version_num() != 7
        {
            return backup_denied(&req.operation_id, CODE);
        }
        let Some(journal) = &self.recovery_journal else {
            return backup_denied(&req.operation_id, CODE);
        };
        let Ok(operation) = journal.read_backup_operation(operation_id) else {
            return backup_denied(&req.operation_id, CODE);
        };
        if operation.operation_id != operation_id || operation.backup_id.is_nil() {
            return backup_denied(&req.operation_id, CODE);
        }
        let reason = match operation.phase {
            BackupPhase::Failed => operation.failure_reason.clone(),
            _ => backup_status_reason(&operation).to_owned(),
        };
        if reason.is_empty() {
            return backup_denied(&req.operation_id, CODE);
        }
        backup_success(
            &req.operation_id,
            &BackupStatusResultWire {
                operation_id: operation.operation_id.to_string(),
                backup_id: operation.backup_id.to_string(),
                phase: operation.phase.as_str().to_owned(),
                reason,
            },
        )
    }

    // -- backup worker arms (HandleConn's runtime uid/gid gate + peer) --

    /// `dispatchBackupSeal` — `backup_seal_for_launch`.
    pub(crate) fn dispatch_backup_seal(
        &self,
        req: &BrokerRequest,
        peer: &PeerCred,
    ) -> BrokerResponse {
        const CODE: &str = "BACKUP_SEAL_DENIED";
        let Some(request) = decode_exact_broker_payload::<BackupSealRPCRequest>(req) else {
            return backup_denied(&req.operation_id, CODE);
        };
        let Ok(proposal) = seal_proposal_from_wire(&request.proposal) else {
            return backup_denied(&req.operation_id, CODE);
        };
        if proposal.operation_id.to_string() != req.operation_id
            || request.launch_evidence_id.is_nil()
        {
            return backup_denied(&req.operation_id, CODE);
        }
        let Some(journal) = &self.recovery_journal else {
            return backup_denied(&req.operation_id, CODE);
        };
        let Some(launches) = &self.backup_launches else {
            return backup_denied(&req.operation_id, CODE);
        };
        // `sealBackupForLaunch` — the worker-facing commit boundary:
        // the helper-issued process evidence validates before the
        // protected journal issues a companion.
        if launches
            .validate_worker(request.launch_evidence_id, proposal.operation_id, peer)
            .is_err()
        {
            return backup_denied(&req.operation_id, CODE);
        }
        match journal.seal_backup(&proposal) {
            Err(_) => backup_denied(&req.operation_id, CODE),
            Ok(companion) => backup_success(&req.operation_id, &seal_companion_to_wire(&companion)),
        }
    }

    /// `dispatchBackupWorkerContext` — `backup_worker_context`.
    pub(crate) fn dispatch_backup_worker_context(
        &self,
        req: &BrokerRequest,
        peer: &PeerCred,
    ) -> BrokerResponse {
        const CODE: &str = "BACKUP_WORKER_AUTHORITY_DENIED";
        let Some(request) = decode_exact_broker_payload::<BackupWorkerIdentityRPCRequest>(req)
        else {
            return backup_denied(&req.operation_id, CODE);
        };
        if request.launch_evidence_id.is_nil() {
            return backup_denied(&req.operation_id, CODE);
        }
        let Some(launches) = &self.backup_launches else {
            return backup_denied(&req.operation_id, CODE);
        };
        match launches.worker_authority(request.launch_evidence_id, peer) {
            Err(_) => backup_denied(&req.operation_id, CODE),
            Ok(authority) if authority.operation_id.to_string() != req.operation_id => {
                backup_denied(&req.operation_id, CODE)
            }
            Ok(authority) => backup_success(
                &req.operation_id,
                &BackupLaunchAuthorityWire {
                    launch_evidence_id: authority.launch_evidence_id,
                    operation_id: authority.operation_id,
                    backup_id: authority.backup_id,
                },
            ),
        }
    }

    /// `dispatchBackupWorkerPayloadEpoch` —
    /// `backup_worker_active_payload_epoch`.
    pub(crate) fn dispatch_backup_worker_payload_epoch(
        &self,
        req: &BrokerRequest,
        peer: &PeerCred,
    ) -> BrokerResponse {
        const CODE: &str = "BACKUP_WORKER_PAYLOAD_EPOCH_DENIED";
        let Ok(operation_id) = Uuid::parse_str(&req.operation_id) else {
            return backup_denied(&req.operation_id, CODE);
        };
        let Some(request) = decode_exact_broker_payload::<BackupWorkerIdentityRPCRequest>(req)
        else {
            return backup_denied(&req.operation_id, CODE);
        };
        let (Some(launches), Some(epochs)) = (&self.backup_launches, &self.payload_epochs) else {
            return backup_denied(&req.operation_id, CODE);
        };
        if launches
            .validate_worker(request.launch_evidence_id, operation_id, peer)
            .is_err()
        {
            return backup_denied(&req.operation_id, CODE);
        }
        match epochs.read_active() {
            Ok(payload_epoch_id)
                if !payload_epoch_id.is_nil() && payload_epoch_id.get_version_num() == 7 =>
            {
                backup_success(&req.operation_id, &PayloadEpochResult { payload_epoch_id })
            }
            _ => backup_denied(&req.operation_id, CODE),
        }
    }

    /// `dispatchBackupWorkerThroughput` —
    /// `backup_worker_read_throughput`.
    pub(crate) fn dispatch_backup_worker_throughput(
        &self,
        req: &BrokerRequest,
        peer: &PeerCred,
    ) -> BrokerResponse {
        const CODE: &str = "BACKUP_WORKER_THROUGHPUT_DENIED";
        let Ok(operation_id) = Uuid::parse_str(&req.operation_id) else {
            return backup_denied(&req.operation_id, CODE);
        };
        let Some(request) = decode_exact_broker_payload::<BackupWorkerThroughputRPCRequest>(req)
        else {
            return backup_denied(&req.operation_id, CODE);
        };
        let Ok(operation) = backup_operation_from_wire(&request.operation) else {
            return backup_denied(&req.operation_id, CODE);
        };
        let facts = accepted_facts_from_wire(&request.accepted_facts);
        let (Some(launches), Some(journal), Some(epochs), Some(throughput)) = (
            &self.backup_launches,
            &self.recovery_journal,
            &self.payload_epochs,
            &self.throughput,
        ) else {
            return backup_denied(&req.operation_id, CODE);
        };
        if operation.operation_id != operation_id
            || operation.phase != BackupPhase::Planned
            || facts.validate().is_err()
            || launches
                .validate_worker(request.launch_evidence_id, operation_id, peer)
                .is_err()
        {
            return backup_denied(&req.operation_id, CODE);
        }
        let Ok(record) = launches.read(request.launch_evidence_id) else {
            return backup_denied(&req.operation_id, CODE);
        };
        if record.repository_binding.binding_id != facts.repository_binding_id {
            return backup_denied(&req.operation_id, CODE);
        }
        let Ok(payload_epoch_id) = epochs.read_active() else {
            return backup_denied(&req.operation_id, CODE);
        };
        if payload_epoch_id != facts.payload_epoch_id {
            return backup_denied(&req.operation_id, CODE);
        }
        let Ok((_generation, minio_receipt)) =
            journal.resolve_bound_minio_handoff(operation_id, Purpose::MinioBackup)
        else {
            return backup_denied(&req.operation_id, CODE);
        };
        let Ok(evidence) = throughput.read_active(OffsetDateTime::now_utc()) else {
            return backup_denied(&req.operation_id, CODE);
        };
        let binding = evidence.binding();
        if binding.payload_epoch_id != payload_epoch_id
            || binding.repository_binding_id != record.repository_binding.binding_id
            || binding.target_fingerprint != facts.target_fingerprint
            || binding.config_digest != facts.config_fingerprint
            || binding.pg_dump_tool_version != "16.14"
            || binding.minio_backup_policy_digest != minio_receipt.policy_digest
        {
            return backup_denied(&req.operation_id, CODE);
        }
        backup_success(&req.operation_id, &evidence_to_wire(&evidence))
    }

    /// `dispatchBackupWorkerCreate` — `backup_worker_create_operation`.
    pub(crate) fn dispatch_backup_worker_create(
        &self,
        req: &BrokerRequest,
        peer: &PeerCred,
    ) -> BrokerResponse {
        const CODE: &str = "BACKUP_WORKER_JOURNAL_DENIED";
        let Some(request) = decode_exact_broker_payload::<BackupWorkerOperationRPCRequest>(req)
        else {
            return backup_denied(&req.operation_id, CODE);
        };
        let Ok(operation) = backup_operation_from_wire(&request.operation) else {
            return backup_denied(&req.operation_id, CODE);
        };
        let (Some(launches), Some(journal)) = (&self.backup_launches, &self.recovery_journal)
        else {
            return backup_denied(&req.operation_id, CODE);
        };
        if operation.operation_id.to_string() != req.operation_id
            || operation.phase != BackupPhase::Planned
            || launches
                .validate_worker_operation(request.launch_evidence_id, &operation, peer)
                .is_err()
            || journal.create_backup(&operation).is_err()
        {
            return backup_denied(&req.operation_id, CODE);
        }
        backup_success(&req.operation_id, &serde_json::json!({"created": true}))
    }

    /// `dispatchBackupWorkerRead` — `backup_worker_read_operation`.
    pub(crate) fn dispatch_backup_worker_read(
        &self,
        req: &BrokerRequest,
        peer: &PeerCred,
    ) -> BrokerResponse {
        const CODE: &str = "BACKUP_WORKER_JOURNAL_DENIED";
        let Ok(operation_id) = Uuid::parse_str(&req.operation_id) else {
            return backup_denied(&req.operation_id, CODE);
        };
        let Some(request) = decode_exact_broker_payload::<BackupWorkerIdentityRPCRequest>(req)
        else {
            return backup_denied(&req.operation_id, CODE);
        };
        let (Some(launches), Some(journal)) = (&self.backup_launches, &self.recovery_journal)
        else {
            return backup_denied(&req.operation_id, CODE);
        };
        if launches
            .validate_worker(request.launch_evidence_id, operation_id, peer)
            .is_err()
        {
            return backup_denied(&req.operation_id, CODE);
        }
        let Ok(operation) = journal.read_backup_operation(operation_id) else {
            return backup_denied(&req.operation_id, CODE);
        };
        if launches
            .validate_worker_operation(request.launch_evidence_id, &operation, peer)
            .is_err()
        {
            return backup_denied(&req.operation_id, CODE);
        }
        backup_success(&req.operation_id, &backup_operation_to_wire(&operation))
    }

    /// `dispatchBackupWorkerCAS` — `backup_worker_cas_operation`.
    pub(crate) fn dispatch_backup_worker_cas(
        &self,
        req: &BrokerRequest,
        peer: &PeerCred,
    ) -> BrokerResponse {
        const CODE: &str = "BACKUP_WORKER_JOURNAL_DENIED";
        let Some(request) = decode_exact_broker_payload::<BackupWorkerCASRPCRequest>(req) else {
            return backup_denied(&req.operation_id, CODE);
        };
        let (Ok(expected), Ok(next)) = (
            backup_operation_from_wire(&request.expected),
            backup_operation_from_wire(&request.next),
        ) else {
            return backup_denied(&req.operation_id, CODE);
        };
        let (Some(launches), Some(journal)) = (&self.backup_launches, &self.recovery_journal)
        else {
            return backup_denied(&req.operation_id, CODE);
        };
        if expected.operation_id.to_string() != req.operation_id
            || next.operation_id.to_string() != req.operation_id
            || launches
                .validate_worker_operation(request.launch_evidence_id, &expected, peer)
                .is_err()
            || launches
                .validate_worker_operation(request.launch_evidence_id, &next, peer)
                .is_err()
            || journal.compare_and_swap_backup(&expected, &next).is_err()
        {
            return backup_denied(&req.operation_id, CODE);
        }
        backup_success(&req.operation_id, &serde_json::json!({"updated": true}))
    }

    // -- throughput launch arms (root helper + worker) --

    /// `dispatchBackupThroughputLaunchIssue` —
    /// `backup_throughput_issue_launch`.
    pub(crate) fn dispatch_backup_throughput_launch_issue(
        &self,
        req: &BrokerRequest,
    ) -> BrokerResponse {
        const CODE: &str = "BACKUP_THROUGHPUT_LAUNCH_DENIED";
        let Ok(operation_id) = Uuid::parse_str(&req.operation_id) else {
            return backup_denied(&req.operation_id, CODE);
        };
        let Some(evidence) = decode_exact_broker_payload::<
            super::backup_throughput_launch::BackupThroughputLaunchEvidence,
        >(req) else {
            return backup_denied(&req.operation_id, CODE);
        };
        if operation_id.is_nil() || evidence.operation_id != operation_id {
            return backup_denied(&req.operation_id, CODE);
        }
        let Some(launches) = &self.throughput_launches else {
            return backup_denied(&req.operation_id, CODE);
        };
        match launches.issue(&evidence) {
            Err(_) => backup_denied(&req.operation_id, CODE),
            Ok(authority) => backup_success(&req.operation_id, &authority),
        }
    }

    /// `dispatchBackupThroughputLaunchRead` —
    /// `backup_throughput_read_launch`.
    pub(crate) fn dispatch_backup_throughput_launch_read(
        &self,
        req: &BrokerRequest,
    ) -> BrokerResponse {
        const CODE: &str = "BACKUP_THROUGHPUT_LAUNCH_READ_DENIED";
        let Ok(operation_id) = Uuid::parse_str(&req.operation_id) else {
            return backup_denied(&req.operation_id, CODE);
        };
        let Some(request) =
            decode_exact_broker_payload::<BackupThroughputWorkerIdentityRequest>(req)
        else {
            return backup_denied(&req.operation_id, CODE);
        };
        if operation_id.is_nil() {
            return backup_denied(&req.operation_id, CODE);
        }
        let Some(launches) = &self.throughput_launches else {
            return backup_denied(&req.operation_id, CODE);
        };
        match launches.read_state(operation_id, request.launch_evidence_id) {
            Err(_) => backup_denied(&req.operation_id, CODE),
            Ok(status) => backup_success(&req.operation_id, &status),
        }
    }

    /// `dispatchBackupThroughputFixtureLoaded` —
    /// `backup_throughput_fixture_loaded`.
    pub(crate) fn dispatch_backup_throughput_fixture_loaded(
        &self,
        req: &BrokerRequest,
    ) -> BrokerResponse {
        const CODE: &str = "BACKUP_THROUGHPUT_FIXTURE_DENIED";
        let Ok(operation_id) = Uuid::parse_str(&req.operation_id) else {
            return backup_denied(&req.operation_id, CODE);
        };
        let Some(request) =
            decode_exact_broker_payload::<BackupThroughputFixtureLoadedRequest>(req)
        else {
            return backup_denied(&req.operation_id, CODE);
        };
        if operation_id.is_nil() {
            return backup_denied(&req.operation_id, CODE);
        }
        let Some(launches) = &self.throughput_launches else {
            return backup_denied(&req.operation_id, CODE);
        };
        match launches.mark_fixture_loaded(
            operation_id,
            request.launch_evidence_id,
            &request.attestation,
        ) {
            Err(_) => backup_denied(&req.operation_id, CODE),
            Ok(()) => backup_success(&req.operation_id, &serde_json::json!({"loaded": true})),
        }
    }

    /// `dispatchBackupThroughputWorkerContext` —
    /// `backup_throughput_worker_context`.
    pub(crate) fn dispatch_backup_throughput_worker_context(
        &self,
        req: &BrokerRequest,
        peer: &PeerCred,
    ) -> BrokerResponse {
        const CODE: &str = "BACKUP_THROUGHPUT_WORKER_DENIED";
        let Ok(operation_id) = Uuid::parse_str(&req.operation_id) else {
            return backup_denied(&req.operation_id, CODE);
        };
        let Some(request) =
            decode_exact_broker_payload::<BackupThroughputWorkerIdentityRequest>(req)
        else {
            return backup_denied(&req.operation_id, CODE);
        };
        if operation_id.is_nil() {
            return backup_denied(&req.operation_id, CODE);
        }
        let Some(launches) = &self.throughput_launches else {
            return backup_denied(&req.operation_id, CODE);
        };
        match launches.worker_context(request.launch_evidence_id, operation_id, peer) {
            Err(_) => backup_denied(&req.operation_id, CODE),
            Ok(context) => backup_success(&req.operation_id, &context),
        }
    }

    /// `dispatchBackupThroughputWorkerTargetLocked` —
    /// `backup_throughput_worker_target_locked`.
    pub(crate) fn dispatch_backup_throughput_worker_target_locked(
        &self,
        req: &BrokerRequest,
        peer: &PeerCred,
    ) -> BrokerResponse {
        const CODE: &str = "BACKUP_THROUGHPUT_TARGET_LOCK_DENIED";
        let Ok(operation_id) = Uuid::parse_str(&req.operation_id) else {
            return backup_denied(&req.operation_id, CODE);
        };
        let Some(request) = decode_exact_broker_payload::<BackupThroughputWorkerTargetRequest>(req)
        else {
            return backup_denied(&req.operation_id, CODE);
        };
        if operation_id.is_nil() {
            return backup_denied(&req.operation_id, CODE);
        }
        let Some(launches) = &self.throughput_launches else {
            return backup_denied(&req.operation_id, CODE);
        };
        match launches.mark_target_locked(
            request.launch_evidence_id,
            operation_id,
            peer,
            &request.attestation,
        ) {
            Err(_) => backup_denied(&req.operation_id, CODE),
            Ok(()) => backup_success(&req.operation_id, &serde_json::json!({"locked": true})),
        }
    }

    /// `dispatchBackupThroughputWorkerStage` —
    /// `backup_throughput_worker_stage`.
    pub(crate) fn dispatch_backup_throughput_worker_stage(
        &self,
        req: &BrokerRequest,
        peer: &PeerCred,
    ) -> BrokerResponse {
        const CODE: &str = "BACKUP_THROUGHPUT_WORKER_STAGE_DENIED";
        let Ok(operation_id) = Uuid::parse_str(&req.operation_id) else {
            return backup_denied(&req.operation_id, CODE);
        };
        let Some(request) = decode_exact_broker_payload::<BackupThroughputWorkerStageRequest>(req)
        else {
            return backup_denied(&req.operation_id, CODE);
        };
        let evidence = evidence_from_wire(&request.evidence);
        if operation_id.is_nil() || evidence.probe_operation_id != operation_id {
            return backup_denied(&req.operation_id, CODE);
        }
        let (Some(launches), Some(_)) = (&self.throughput_launches, &self.throughput) else {
            return backup_denied(&req.operation_id, CODE);
        };
        match launches.stage_measurement(
            request.launch_evidence_id,
            operation_id,
            peer,
            &evidence,
            request.staged_at,
        ) {
            Err(_) => backup_denied(&req.operation_id, CODE),
            Ok(()) => backup_success(&req.operation_id, &serde_json::json!({"staged": true})),
        }
    }

    // -- throughput journal authority (root helper) --

    /// `dispatchBackupThroughputAuthority` — the seven journal
    /// purposes share one upstream switch.
    pub(crate) fn dispatch_backup_throughput_authority(
        &self,
        req: &BrokerRequest,
    ) -> BrokerResponse {
        const CODE: &str = "BACKUP_THROUGHPUT_AUTHORITY_DENIED";
        let Ok(operation_id) = Uuid::parse_str(&req.operation_id) else {
            return backup_denied(&req.operation_id, CODE);
        };
        let Some(throughput) = &self.throughput else {
            return backup_denied(&req.operation_id, CODE);
        };
        if operation_id.is_nil() || operation_id.get_version_num() != 7 {
            return backup_denied(&req.operation_id, CODE);
        }
        match req.purpose.as_str() {
            BACKUP_THROUGHPUT_CURRENT_RPC => {
                let Some(launches) = &self.throughput_launches else {
                    return backup_denied(&req.operation_id, CODE);
                };
                if decode_exact_broker_payload::<EmptyRequest>(req).is_none() {
                    return backup_denied(&req.operation_id, CODE);
                }
                let Ok((record, found)) = throughput.current_attempt() else {
                    return backup_denied(&req.operation_id, CODE);
                };
                if !found {
                    return backup_success(
                        &req.operation_id,
                        &BackupThroughputAttemptStatusWire {
                            found: false,
                            ..Default::default()
                        },
                    );
                }
                let mut status = BackupThroughputAttemptStatusWire {
                    found: true,
                    operation_id: record.operation_id,
                    phase: record.phase.clone(),
                    selector_phase: record.selector_phase.clone(),
                    accepted_at: record.accepted_at,
                    deadline: record.deadline,
                    activated_at: record.activated_at,
                    cleanup_attested: record.cleanup.is_some(),
                    ..Default::default()
                };
                if let Some(evidence) = &record.evidence {
                    status.expires_at = evidence.expires_at;
                }
                if let Some(resolution) = &record.resolution {
                    status.cleanup_resolved_at = resolution.resolved_at;
                }
                match launches.root_state(record.operation_id) {
                    Ok(launch) => {
                        status.supervisor_launch_id = launch.supervisor_launch_id;
                        status.launch_evidence_id = launch.launch_evidence_id;
                        status.target_lock_proof_sha256 = launch.target_lock_proof_sha256;
                        status.minio_seed_binding = launch.minio_seed_binding;
                        status.repository_binding_id = launch.repository_binding_id;
                    }
                    Err(_)
                        if record.phase.as_str() != "accepted"
                            && record.phase.as_str() != "failed"
                            && !(record.phase.as_str() == "cleanup_required"
                                && record.evidence.is_none()) =>
                    {
                        return backup_denied(&req.operation_id, CODE);
                    }
                    Err(_) => {}
                }
                backup_success(&req.operation_id, &status)
            }
            BACKUP_THROUGHPUT_ACCEPT_RPC => {
                let Some(request) =
                    decode_exact_broker_payload::<BackupThroughputAcceptRequest>(req)
                else {
                    return backup_denied(&req.operation_id, CODE);
                };
                match throughput.accept(operation_id, request.accepted_at, request.deadline) {
                    Err(_) => backup_denied(&req.operation_id, CODE),
                    Ok(()) => {
                        backup_success(&req.operation_id, &serde_json::json!({"accepted": true}))
                    }
                }
            }
            BACKUP_THROUGHPUT_COMPLETE_PENDING_RPC => {
                let Some(request) =
                    decode_exact_broker_payload::<BackupThroughputCompleteRequest>(req)
                else {
                    return backup_denied(&req.operation_id, CODE);
                };
                let Some(launches) = &self.throughput_launches else {
                    return backup_denied(&req.operation_id, CODE);
                };
                if request.launch_evidence_id.is_nil()
                    || request.retained_target_lock_proof_sha256 == [0u8; 32]
                {
                    return backup_denied(&req.operation_id, CODE);
                }
                let Ok(status) = launches.read_state(operation_id, request.launch_evidence_id)
                else {
                    return backup_denied(&req.operation_id, CODE);
                };
                if status.phase != "measurement_staged"
                    || status.target_lock_proof_sha256 != request.retained_target_lock_proof_sha256
                {
                    return backup_denied(&req.operation_id, CODE);
                }
                let Ok(attestation) = new_throughput_cleanup_attestation(
                    operation_id,
                    request.attested_at,
                    request.parent_elapsed,
                    request.worker_tree_reaped,
                    request.counts,
                ) else {
                    return backup_denied(&req.operation_id, CODE);
                };
                match throughput.complete_pending_cleanup_attested(
                    operation_id,
                    attestation,
                    request.attested_at,
                ) {
                    Err(_) => backup_denied(&req.operation_id, CODE),
                    Ok(()) => {
                        backup_success(&req.operation_id, &serde_json::json!({"pending": true}))
                    }
                }
            }
            BACKUP_THROUGHPUT_ACTIVATE_RPC => {
                let Some(request) =
                    decode_exact_broker_payload::<BackupThroughputActivateRequest>(req)
                else {
                    return backup_denied(&req.operation_id, CODE);
                };
                if wire::is_go_zero_time(request.activated_at) {
                    return backup_denied(&req.operation_id, CODE);
                }
                match throughput.activate_completion(operation_id, request.activated_at) {
                    Err(_) => backup_denied(&req.operation_id, CODE),
                    Ok(evidence) => backup_success(&req.operation_id, &evidence_to_wire(&evidence)),
                }
            }
            BACKUP_THROUGHPUT_FAILED_RPC | BACKUP_THROUGHPUT_CLEANUP_RESOLVED_RPC => {
                let Some(request) =
                    decode_exact_broker_payload::<BackupThroughputCleanupResolutionRequest>(req)
                else {
                    return backup_denied(&req.operation_id, CODE);
                };
                if wire::is_go_zero_time(request.at) {
                    return backup_denied(&req.operation_id, CODE);
                }
                let Ok(resolution) =
                    new_throughput_cleanup_resolution(operation_id, request.counts, request.at)
                else {
                    return backup_denied(&req.operation_id, CODE);
                };
                let result = if req.purpose == BACKUP_THROUGHPUT_FAILED_RPC {
                    throughput.mark_failed_cleanup_attested(operation_id, resolution)
                } else {
                    throughput.resolve_cleanup_required(operation_id, resolution)
                };
                match result {
                    Err(_) => backup_denied(&req.operation_id, CODE),
                    Ok(()) => {
                        backup_success(&req.operation_id, &serde_json::json!({"terminal": true}))
                    }
                }
            }
            BACKUP_THROUGHPUT_CLEANUP_REQUIRED_RPC => {
                let Some(request) =
                    decode_exact_broker_payload::<BackupThroughputTerminalRequest>(req)
                else {
                    return backup_denied(&req.operation_id, CODE);
                };
                if wire::is_go_zero_time(request.at) {
                    return backup_denied(&req.operation_id, CODE);
                }
                match throughput.mark_cleanup_required(operation_id, request.at) {
                    Err(_) => backup_denied(&req.operation_id, CODE),
                    Ok(()) => {
                        backup_success(&req.operation_id, &serde_json::json!({"terminal": true}))
                    }
                }
            }
            _ => backup_denied(&req.operation_id, CODE),
        }
    }

    /// `dispatchBackupEnsurePayloadEpoch` — `backup_ensure_payload_epoch`.
    pub(crate) fn dispatch_backup_ensure_payload_epoch(
        &self,
        req: &BrokerRequest,
    ) -> BrokerResponse {
        const CODE: &str = "BACKUP_PAYLOAD_EPOCH_DENIED";
        let Ok(operation_id) = Uuid::parse_str(&req.operation_id) else {
            return backup_denied(&req.operation_id, CODE);
        };
        let Some(epochs) = &self.payload_epochs else {
            return backup_denied(&req.operation_id, CODE);
        };
        if operation_id.is_nil()
            || operation_id.get_version_num() != 7
            || decode_exact_broker_payload::<EmptyRequest>(req).is_none()
        {
            return backup_denied(&req.operation_id, CODE);
        }
        let mut epoch_id = epochs.read_active();
        if epoch_id.is_err() {
            epoch_id = epochs.create_and_activate(operation_id, Uuid::nil());
            if epoch_id.is_err() {
                // A racing authenticated helper may have won genesis;
                // reading the now-complete chain is safe.
                epoch_id = epochs.read_active();
            }
        }
        match epoch_id {
            Ok(epoch_id) if !epoch_id.is_nil() && epoch_id.get_version_num() == 7 => {
                backup_success(
                    &req.operation_id,
                    &PayloadEpochResult {
                        payload_epoch_id: epoch_id,
                    },
                )
            }
            _ => backup_denied(&req.operation_id, CODE),
        }
    }

    /// `CompleteAttestedBackupSeal` — `RequireReaped` gates the
    /// journal completion; `MarkCompleted` pins the attested digests
    /// onto the launch record after.
    fn complete_attested_backup_seal(
        &self,
        operation_id: Uuid,
        launch_evidence_id: Uuid,
        attestation: &BackupRepositoryAttestation,
        target_lock: &BackupTargetLockAttestation,
    ) -> Result<BackupOperation, Failure> {
        let (Some(journal), Some(launches)) = (&self.recovery_journal, &self.backup_launches)
        else {
            return Err(unavailable());
        };
        launches.require_reaped(
            launch_evidence_id,
            operation_id,
            attestation,
            target_lock,
            OffsetDateTime::now_utc(),
        )?;
        let operation = journal.complete_attested_backup_seal(
            operation_id,
            launch_evidence_id,
            attestation,
            target_lock,
        )?;
        launches.mark_completed(launch_evidence_id, operation_id, attestation, target_lock)?;
        Ok(operation)
    }
}

fn unavailable() -> Failure {
    Failure::internal("broker", "broker: authority store unavailable")
}

// ---------------------------------------------------------------------------
// Client half — `backup_authority_rpc.go`'s `BackupLaunchIssuer`,
// `BackupOperatorAuthorityClient`, `BackupMinioHandoffIssuer`, and
// `BackupAttestationClient`. Each wraps [`LifecycleClient`] exactly as
// upstream wraps `*LifecycleClient`, and every RPC goes through
// `call_with_operation_id` on the protected socket. Denials are
// locator-free: the broker's own diagnostic text never crosses into a
// caller-visible error.
// ---------------------------------------------------------------------------

use super::lifecycle_client::LifecycleClient;

fn client_unavailable(what: &str) -> Failure {
    Failure::internal(
        "broker_backup_client",
        format!("broker {what}: unavailable"),
    )
}

fn client_denied(what: &str) -> Failure {
    Failure::denied("broker_backup_client", format!("broker {what}: denied"))
}

/// `BackupLaunchIssuer` — submits helper-observed launch evidence;
/// the broker mints the opaque identity.
pub struct BackupLaunchIssuer {
    client: LifecycleClient,
}

impl BackupLaunchIssuer {
    /// `NewBackupLaunchEvidenceIssuer`.
    pub fn new(socket_path: std::path::PathBuf) -> Self {
        Self {
            client: LifecycleClient::new(socket_path),
        }
    }
}

impl crate::helper::backup::BackupLaunchEvidenceIssuer for BackupLaunchIssuer {
    fn issue_backup_launch(
        &self,
        _deadline: Instant,
        evidence: &crate::broker::backup_launch::BackupLaunchEvidence,
    ) -> Result<crate::broker::backup_launch::BackupLaunchAuthority, Failure> {
        if evidence.operation_id.is_empty() {
            return Err(client_unavailable("backup launch"));
        }
        let payload = BackupLaunchEvidenceWire {
            supervisor_launch_id: evidence.supervisor_launch_id,
            pid: evidence.pid,
            process_start: evidence.process_start.clone(),
            executable: evidence.executable.clone(),
            mode: evidence.mode.clone(),
            operation_id: evidence.operation_id.clone(),
            repository_binding: super::backup_launch::binding_to_wire(&evidence.repository_binding),
            expires_at: evidence.expires_at,
        };
        let result: BackupLaunchAuthorityWire = self
            .client
            .call_with_operation_id(&evidence.operation_id, BACKUP_ISSUE_LAUNCH_RPC, &payload)
            .map_err(|_| client_denied("backup launch"))?;
        if result.launch_evidence_id.is_nil()
            || result.operation_id.to_string() != evidence.operation_id
            || result.backup_id.is_nil()
        {
            return Err(client_denied("backup launch"));
        }
        Ok(crate::broker::backup_launch::BackupLaunchAuthority {
            launch_evidence_id: result.launch_evidence_id,
            operation_id: result.operation_id,
            backup_id: result.backup_id,
        })
    }
}

/// `BackupOperatorAuthorityClient` — the root-helper-only read client
/// for physical verification and protected operation status.
pub struct BackupOperatorAuthorityClient {
    client: LifecycleClient,
}

impl BackupOperatorAuthorityClient {
    /// `NewBackupOperatorAuthorityClient`.
    pub fn new(socket_path: std::path::PathBuf) -> Self {
        Self {
            client: LifecycleClient::new(socket_path),
        }
    }
}

impl crate::helper::backup::BackupReadAuthority for BackupOperatorAuthorityClient {
    #[allow(clippy::too_many_arguments)] // mirrors the trait signature
    fn verify_backup_seal(
        &self,
        _deadline: Instant,
        backup_id: Uuid,
        manifest_digest: [u8; 32],
        seal_companion_digest: [u8; 32],
        file_tree_digest: [u8; 32],
        repository_manifest_digest: [u8; 32],
        repository_revision: u64,
    ) -> Result<(), Failure> {
        if backup_id.is_nil() || backup_id.get_version_num() != 7 || repository_revision == 0 {
            return Err(client_unavailable("backup verify"));
        }
        #[derive(Deserialize)]
        struct VerifiedResult {
            #[serde(default)]
            verified: bool,
        }
        let result: VerifiedResult = self
            .client
            .call_with_operation_id(
                &backup_id.to_string(),
                BACKUP_VERIFY_SEAL_RPC,
                &BackupVerifySealRPCRequest {
                    backup_id,
                    manifest_digest_sha256: manifest_digest,
                    seal_companion_digest_sha256: seal_companion_digest,
                    file_tree_digest_sha256: file_tree_digest,
                    repository_manifest_digest_sha256: repository_manifest_digest,
                    repository_revision,
                },
            )
            .map_err(|_| client_denied("backup verify"))?;
        if !result.verified {
            return Err(client_denied("backup verify"));
        }
        Ok(())
    }

    fn read_backup_status(
        &self,
        _deadline: Instant,
        operation_id: Uuid,
    ) -> Result<crate::helper::backup::BackupStatusResult, Failure> {
        if operation_id.is_nil() || operation_id.get_version_num() != 7 {
            return Err(client_unavailable("backup status"));
        }
        let result: BackupStatusResultWire = self
            .client
            .call_with_operation_id(
                &operation_id.to_string(),
                BACKUP_READ_STATUS_RPC,
                &EmptyRequest {},
            )
            .map_err(|_| client_denied("backup status"))?;
        if result.operation_id != operation_id.to_string()
            || result.backup_id.is_empty()
            || result.phase.is_empty()
            || result.reason.is_empty()
        {
            return Err(client_denied("backup status"));
        }
        Ok(crate::helper::backup::BackupStatusResult {
            operation_id: result.operation_id,
            backup_id: result.backup_id,
            phase: result.phase,
            reason: result.reason,
        })
    }
}

/// `BackupMinioHandoffIssuer` — admitted only from the root-helper
/// arm. Returns the credential-free, one-use provisioner receipt.
/// `dead_code`: the MinIO credential preparer that consumes this
/// client is the later production composition (same capacity-role
/// machinery chain as the restore engine launcher); the type is the
/// R6T7 wire seam, installed here so that composition only wires it.
#[allow(dead_code)]
pub struct BackupMinioHandoffIssuer {
    client: LifecycleClient,
}

#[allow(dead_code)]
impl BackupMinioHandoffIssuer {
    /// `NewBackupMinioHandoffIssuer`.
    pub fn new(socket_path: std::path::PathBuf) -> Self {
        Self {
            client: LifecycleClient::new(socket_path),
        }
    }

    /// `IssueRecoveryMinioHandoff`.
    pub fn issue_recovery_minio_handoff(
        &self,
        request: &RecoveryMinioHandoffRequest,
    ) -> Result<central_infra::authority::RecoveryMinioHandoffReceipt, Failure> {
        let Ok(operation_id) = Uuid::parse_str(&request.operation_id) else {
            return Err(client_unavailable("backup minio handoff"));
        };
        if operation_id.is_nil() {
            return Err(client_unavailable("backup minio handoff"));
        }
        let result: central_infra::authority::RecoveryMinioHandoffReceipt = self
            .client
            .call_with_operation_id(
                &request.operation_id,
                BACKUP_ISSUE_MINIO_RPC,
                &RecoveryMinioHandoffRequestWire {
                    operation_id: request.operation_id.clone(),
                    instance_id: request.instance_id.clone(),
                    purpose: request.purpose.clone(),
                    bucket: request.bucket.clone(),
                    key_prefix: request.key_prefix.clone(),
                    policy_digest: request.policy_digest.clone(),
                    expires_at: request.expires_at,
                    fence_token: request.fence_token,
                },
            )
            .map_err(|_| client_denied("backup minio handoff"))?;
        if result.operation_id != request.operation_id
            || result.receipt_id.is_empty()
            || result.policy_digest.is_empty()
        {
            return Err(client_denied("backup minio handoff"));
        }
        Ok(result)
    }
}

/// `BackupAttestationClient` — the helper-facing post-reap authority:
/// reap evidence, then the terminal attested-seal transition.
pub struct BackupAttestationClient {
    client: LifecycleClient,
}

impl BackupAttestationClient {
    /// `NewBackupAttestationClient`.
    pub fn new(socket_path: std::path::PathBuf) -> Self {
        Self {
            client: LifecycleClient::new(socket_path),
        }
    }
}

impl crate::helper::backup::BackupLaunchReaper for BackupAttestationClient {
    fn mark_backup_launch_reaped(
        &self,
        _deadline: Instant,
        operation_id: Uuid,
        launch_evidence_id: Uuid,
        target_lock_proof: [u8; 32],
        reaped_at: OffsetDateTime,
    ) -> Result<(), Failure> {
        if operation_id.is_nil()
            || launch_evidence_id.is_nil()
            || target_lock_proof == [0u8; 32]
            || wire::is_go_zero_time(reaped_at)
        {
            return Err(client_unavailable("backup reaping"));
        }
        #[derive(Deserialize)]
        struct ReapedResult {
            #[serde(default)]
            reaped: bool,
        }
        let result: ReapedResult = self
            .client
            .call_with_operation_id(
                &operation_id.to_string(),
                BACKUP_MARK_REAPED_RPC,
                &BackupReapedRPCRequest {
                    operation_id,
                    launch_evidence_id,
                    target_lock_proof,
                    reaped_at,
                },
            )
            .map_err(|_| client_denied("backup reaping"))?;
        if !result.reaped {
            return Err(client_denied("backup reaping"));
        }
        Ok(())
    }
}

impl crate::helper::backup::BackupSealAttestationCompleter for BackupAttestationClient {
    fn complete_attested_backup_seal(
        &self,
        _deadline: Instant,
        operation_id: Uuid,
        launch_evidence_id: Uuid,
        attestation: &BackupRepositoryAttestation,
        target_lock: &BackupTargetLockAttestation,
    ) -> Result<BackupOperation, Failure> {
        if operation_id.is_nil()
            || launch_evidence_id.is_nil()
            || attestation.verify().is_err()
            || target_lock.verify().is_err()
        {
            return Err(client_unavailable("backup attestation"));
        }
        let wire: BackupOperationWire = self
            .client
            .call_with_operation_id(
                &operation_id.to_string(),
                BACKUP_COMPLETE_RPC,
                &BackupCompleteRPCRequest {
                    operation_id,
                    launch_evidence_id,
                    attestation: super::recovery_journal::attestation_to_wire(&Some(
                        attestation.clone(),
                    )),
                    target_lock_attestation: super::recovery_journal::target_lock_to_wire(&Some(
                        target_lock.clone(),
                    )),
                },
            )
            .map_err(|_| client_denied("backup attestation"))?;
        let operation =
            backup_operation_from_wire(&wire).map_err(|_| client_denied("backup attestation"))?;
        if operation.validate().is_err() {
            return Err(client_denied("backup attestation"));
        }
        Ok(operation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn req_with_request(raw_json: &str) -> BrokerRequest {
        BrokerRequest {
            operation_id: Uuid::now_v7().to_string(),
            purpose: "backup_worker_context".into(),
            session_token: String::new(),
            payload: Some(BTreeMap::from([(
                "request".to_owned(),
                serde_json::value::RawValue::from_string(raw_json.to_owned()).unwrap(),
            )])),
        }
    }

    #[test]
    fn exact_decode_accepts_only_canonical_bytes() {
        let id = Uuid::now_v7();
        // The canonical marshal — byte-equal to Go's `json.Marshal`.
        let canonical = format!(r#"{{"launch_evidence_id":"{id}"}}"#);
        let decoded = decode_exact_broker_payload::<BackupWorkerIdentityRPCRequest>(
            &req_with_request(&canonical),
        );
        assert_eq!(decoded.unwrap().launch_evidence_id, id);
        // Insignificant whitespace makes the bytes non-canonical —
        // upstream's `bytes.Equal(canonical, raw)` refuses.
        assert!(
            decode_exact_broker_payload::<BackupWorkerIdentityRPCRequest>(&req_with_request(
                &format!(r#"{{ "launch_evidence_id": "{id}" }}"#)
            ),)
            .is_none()
        );
        // A re-ordered second field cannot match declaration order.
        assert!(
            decode_exact_broker_payload::<BackupWorkerOperationRPCRequest>(&req_with_request(
                &format!(r#"{{"operation":{{}},"launch_evidence_id":"{id}"}}"#)
            ),)
            .is_none()
        );
    }

    #[test]
    fn exact_decode_refuses_payload_shape_deviations() {
        let id = Uuid::now_v7();
        let mut req = req_with_request(&format!(r#"{{"launch_evidence_id":"{id}"}}"#));
        // A second payload key refuses — upstream requires
        // `len(req.Payload) == 1`.
        req.payload.as_mut().unwrap().insert(
            "extra".to_owned(),
            serde_json::from_str::<Box<serde_json::value::RawValue>>("1").unwrap(),
        );
        assert!(decode_exact_broker_payload::<BackupWorkerIdentityRPCRequest>(&req).is_none());
        // Payload must be present at all.
        let mut req = req_with_request(&format!(r#"{{"launch_evidence_id":"{id}"}}"#));
        req.payload = None;
        assert!(decode_exact_broker_payload::<BackupWorkerIdentityRPCRequest>(&req).is_none());
        // `DisallowUnknownFields` — an extra member refuses.
        assert!(
            decode_exact_broker_payload::<BackupWorkerIdentityRPCRequest>(&req_with_request(
                &format!(r#"{{"launch_evidence_id":"{id}","bogus":1}}"#)
            ),)
            .is_none()
        );
        // A trailing second value cannot survive inside the decoded
        // `RawValue` payload — `serde_json` refuses it while decoding
        // `BrokerRequest` itself, the same guarantee upstream's
        // `io.EOF` check gives on `RawMessage` bytes.
        let wire = format!(
            r#"{{"operation_id":"op","purpose":"p","session_token":"","payload":{{"request":{{"launch_evidence_id":"{id}"}} trailing}}}}"#
        );
        assert!(serde_json::from_str::<BrokerRequest>(&wire).is_err());
        // A base64 digest cannot decode into a `[32]byte` field —
        // Go refuses a string for an array type.
        assert!(
            decode_exact_broker_payload::<BackupVerifySealRPCRequest>(
                &req_with_request(&format!(
                    r#"{{"backup_id":"{id}","manifest_digest_sha256":"aGVsbG8=","seal_companion_digest_sha256":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"file_tree_digest_sha256":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"repository_manifest_digest_sha256":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"repository_revision":0}}"#
                )),
            )
            .is_none()
        );
    }

    #[test]
    fn backup_denied_carries_code_in_both_evidence_fields() {
        // `backupRPCDenied` — `Code` and `Message` are the same string,
        // `Evidence.OperationID` empty.
        let resp = backup_denied("op-1", "BACKUP_SEAL_DENIED");
        assert_eq!(
            resp.outcome,
            central_infra::authority::BrokerOutcome::Denied
        );
        assert_eq!(resp.operation_id, "op-1");
        assert_eq!(resp.evidence.code, "BACKUP_SEAL_DENIED");
        assert_eq!(resp.evidence.message, "BACKUP_SEAL_DENIED");
        assert!(resp.evidence.operation_id.is_empty());
        assert!(resp.result.is_none());
    }
}
