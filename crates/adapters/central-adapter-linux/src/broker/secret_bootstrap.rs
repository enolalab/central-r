//! `SecretBootstrap` — the port of upstream `secret_bootstrap.go`: the
//! B04 secret bootstrap protocol's durable authority registry.
//!
//! Layout under the private broker root (upstream-identical):
//!
//! ```text
//! <root>/leases/<binding_id>.json          durable lease per binding
//! <root>/leases/<binding_id>.revoked       revocation tombstone
//! <root>/bindings/<binding_id>/metadata.json   binding → generation map
//! <root>/bindings/<binding_id>/receipts/<receipt_id>.json
//! <root>/bindings/<binding_id>/operations/<operation_id>.json
//! <root>/proofs/<proof_id>.json            lifecycle proofs
//! <root>/evidence/<generation_id>.json     B03 source evidence
//! ```
//!
//! Custody invariants (unchanged from upstream):
//!
//! - `validate_materialize_request` never reads plaintext; plaintext is
//!   resolved by `resolve_credential` strictly *after* the destination
//!   descriptor has been received and validated (descriptor-first).
//! - Receipts are one-use; a consumed receipt denies replays durably
//!   across restarts.
//! - Every mutation is persisted (temp file + rename) before the
//!   in-memory map updates are treated as committed upstream do.
//! - Receipt and operation records persist with upstream's untagged
//!   (PascalCase) JSON field names; leases and proofs with upstream's
//!   snake_case tags. UUIDs tolerate any RFC 4122 version on load —
//!   upstream `uuid.FromString` accepts v4 callers' IDs.
//! - No secret value, receipt HMAC input, or binding metadata is ever
//!   placed on a wire response; errors carry the stable upstream codes
//!   (`B04_HANDOFF_DENIED`, `RECEIPT_CONSUMED`, `FENCING_CONFLICT`, …).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use central_foundation::failure::Failure;
use central_foundation::identity::{
    DurableLeaseId, HandoffReceiptId, LifecycleProofId, OperationId, ProtectedGenerationId,
    SecretBindingId,
};
use central_infra::domain::{
    AdoptRequest, BootstrapOutcome, DurableLease, HandoffOperation, HandoffOperationState,
    HandoffReceipt, HandoffReceiptState, HandoffRequest, LifecycleProof, MAX_SECRET_BYTES, Purpose,
    SecretBinding, codes,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use super::durable::{self, PRIVATE_DIRECTORY_MODE, ensure_private_root, sync_dir};
use super::journal::Journal;
use super::protected_file::ProtectedFileBackend;
use super::signing::SigningService;
use super::wire;

const RECEIPT_TTL: time::Duration = time::Duration::minutes(5);
const PROOF_TTL: time::Duration = time::Duration::minutes(5);

fn internal(msg: impl Into<String>) -> Failure {
    Failure::internal("broker_bootstrap", msg)
}

/// `fmt.Errorf("%s: …", ReasonB04HandoffDenied, …)` — the denial code
/// is `B04_HANDOFF_DENIED`; the message keeps upstream's prefix shape.
fn denied_prefixed(msg: impl Into<String>) -> Failure {
    Failure::denied(codes::B04_HANDOFF_DENIED, msg)
}

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

// ---------------------------------------------------------------------------
// Wire records — upstream's exact JSON field names
// ---------------------------------------------------------------------------

/// `DurableLease` — upstream snake_case tags. `holder_op_id` marshals
/// the nil UUID when unset; the tolerant UUID parse is load-side only.
#[derive(Serialize, Deserialize)]
struct LeaseRecord {
    lease_id: String,
    binding_id: String,
    holder_op_id: String,
    #[serde(with = "wire::rfc3339")]
    expires_at: OffsetDateTime,
    fencing_token: u64,
    #[serde(with = "wire::rfc3339")]
    created_at: OffsetDateTime,
}

/// `HandoffReceipt` — upstream fields carry NO json tags: Go marshals
/// PascalCase names (`"ReceiptID"`, `"PeerUID"`, …).
#[derive(Serialize, Deserialize)]
struct ReceiptRecord {
    #[serde(rename = "ReceiptID")]
    receipt_id: String,
    #[serde(rename = "OperationID")]
    operation_id: String,
    #[serde(rename = "BindingID")]
    binding_id: String,
    #[serde(rename = "Purpose")]
    purpose: String,
    #[serde(rename = "Service")]
    service: String,
    #[serde(rename = "Target")]
    target: String,
    #[serde(rename = "UID")]
    uid: u32,
    #[serde(rename = "GID")]
    gid: u32,
    #[serde(rename = "PeerUID")]
    peer_uid: u32,
    #[serde(rename = "PeerPID")]
    peer_pid: i32,
    #[serde(rename = "HMAC")]
    hmac: String,
    #[serde(rename = "State")]
    state: String,
    #[serde(rename = "FencingToken")]
    fencing_token: u64,
    #[serde(rename = "ExpiresAt", with = "wire::rfc3339")]
    expires_at: OffsetDateTime,
    #[serde(rename = "IssuedAt", with = "wire::rfc3339")]
    issued_at: OffsetDateTime,
}

/// `HandoffOperation` — PascalCase, same as the receipt.
#[derive(Serialize, Deserialize)]
struct OperationRecord {
    #[serde(rename = "OperationID")]
    operation_id: String,
    #[serde(rename = "ReceiptID")]
    receipt_id: String,
    #[serde(rename = "BindingID")]
    binding_id: String,
    #[serde(rename = "Purpose")]
    purpose: String,
    #[serde(rename = "State")]
    state: String,
    #[serde(rename = "FencingToken")]
    fencing_token: u64,
    #[serde(rename = "CreatedAt", with = "wire::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(rename = "UpdatedAt", with = "wire::rfc3339")]
    updated_at: OffsetDateTime,
    #[serde(rename = "HMAC")]
    hmac: String,
    #[serde(rename = "ResolvedAction")]
    resolved_action: String,
}

/// `b03SourceEvidence` — upstream snake_case tags.
#[derive(Serialize, Deserialize, Default)]
struct B03SourceEvidence {
    legacy_binding_id: String,
    generation_token: String,
    keyed_fingerprint: String,
    provisioning_receipt_id: String,
    lifecycle_operation_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    mount_release_proof: String,
}

/// `bindings/<id>/metadata.json` — upstream `map[string]string`.
type BindingMetadata = std::collections::BTreeMap<String, String>;

// ---------------------------------------------------------------------------
// Record <-> domain conversions (loose UUID parse, trusted-boundary IDs)
// ---------------------------------------------------------------------------

/// `uuid.FromString` — accept any RFC 4122 UUID (callers mint v4 or v7).
fn loose_uuid(text: &str) -> Result<Uuid, Failure> {
    Uuid::parse_str(text)
        .map_err(|e| internal(format!("broker: invalid persisted uuid {text:?}: {e}")))
}

fn lease_record(l: &DurableLease) -> LeaseRecord {
    LeaseRecord {
        lease_id: l.lease_id.to_string(),
        binding_id: l.binding_id.to_string(),
        holder_op_id: l.holder_op_id.to_string(),
        expires_at: l.expires_at,
        fencing_token: l.fencing_token,
        created_at: l.created_at,
    }
}

fn lease_domain(r: &LeaseRecord) -> Result<DurableLease, Failure> {
    Ok(DurableLease {
        lease_id: DurableLeaseId::from_trusted_db_bytes(*loose_uuid(&r.lease_id)?.as_bytes()),
        binding_id: SecretBindingId::from_trusted_db_bytes(*loose_uuid(&r.binding_id)?.as_bytes()),
        holder_op_id: OperationId::from_trusted_db_bytes(*loose_uuid(&r.holder_op_id)?.as_bytes()),
        expires_at: r.expires_at,
        fencing_token: r.fencing_token,
        created_at: r.created_at,
    })
}

fn receipt_record(r: &HandoffReceipt) -> ReceiptRecord {
    ReceiptRecord {
        receipt_id: r.receipt_id.to_string(),
        operation_id: r.operation_id.to_string(),
        binding_id: r.binding_id.to_string(),
        purpose: r.purpose.as_str().to_owned(),
        service: r.service.clone(),
        target: r.target.clone(),
        uid: r.uid,
        gid: r.gid,
        peer_uid: r.peer_uid,
        peer_pid: r.peer_pid,
        hmac: r.hmac.clone(),
        state: r.state.as_str().to_owned(),
        fencing_token: r.fencing_token,
        expires_at: r.expires_at,
        issued_at: r.issued_at,
    }
}

fn receipt_state(s: &str) -> Option<HandoffReceiptState> {
    match s {
        "issued" => Some(HandoffReceiptState::Issued),
        "reserved" => Some(HandoffReceiptState::Reserved),
        "acknowledged" => Some(HandoffReceiptState::Acknowledged),
        "invalidated" => Some(HandoffReceiptState::Invalidated),
        _ => None,
    }
}

fn receipt_domain(r: &ReceiptRecord) -> Result<HandoffReceipt, Failure> {
    let purpose: Purpose = r
        .purpose
        .parse()
        .map_err(|_| internal(format!("broker: invalid persisted purpose {:?}", r.purpose)))?;
    Ok(HandoffReceipt {
        receipt_id: HandoffReceiptId::from_trusted_db_bytes(*loose_uuid(&r.receipt_id)?.as_bytes()),
        operation_id: OperationId::from_trusted_db_bytes(*loose_uuid(&r.operation_id)?.as_bytes()),
        binding_id: SecretBindingId::from_trusted_db_bytes(*loose_uuid(&r.binding_id)?.as_bytes()),
        purpose,
        service: r.service.clone(),
        target: r.target.clone(),
        uid: r.uid,
        gid: r.gid,
        peer_uid: r.peer_uid,
        peer_pid: r.peer_pid,
        hmac: r.hmac.clone(),
        state: receipt_state(&r.state)
            .ok_or_else(|| internal(format!("broker: invalid receipt state {:?}", r.state)))?,
        fencing_token: r.fencing_token,
        expires_at: r.expires_at,
        issued_at: r.issued_at,
    })
}

fn operation_record(o: &HandoffOperation) -> OperationRecord {
    OperationRecord {
        operation_id: o.operation_id.to_string(),
        receipt_id: o.receipt_id.to_string(),
        binding_id: o.binding_id.to_string(),
        purpose: o.purpose.as_str().to_owned(),
        state: o.state.as_str().to_owned(),
        fencing_token: o.fencing_token,
        created_at: o.created_at,
        updated_at: o.updated_at,
        hmac: o.hmac.clone(),
        resolved_action: o.resolved_action.clone(),
    }
}

fn operation_state(s: &str) -> Option<HandoffOperationState> {
    match s {
        "issued" => Some(HandoffOperationState::Issued),
        "reserved" => Some(HandoffOperationState::Reserved),
        "write_started" => Some(HandoffOperationState::WriteStarted),
        "broker_closed" => Some(HandoffOperationState::BrokerClosed),
        "helper_acknowledged" => Some(HandoffOperationState::HelperAcknowledged),
        "acknowledged" => Some(HandoffOperationState::Acknowledged),
        "reconciliation_required" => Some(HandoffOperationState::ReconciliationRequired),
        "invalidated" => Some(HandoffOperationState::Invalidated),
        "failed" => Some(HandoffOperationState::Failed),
        _ => None,
    }
}

fn operation_domain(r: &OperationRecord) -> Result<HandoffOperation, Failure> {
    let purpose: Purpose = r
        .purpose
        .parse()
        .map_err(|_| internal(format!("broker: invalid persisted purpose {:?}", r.purpose)))?;
    Ok(HandoffOperation {
        operation_id: OperationId::from_trusted_db_bytes(*loose_uuid(&r.operation_id)?.as_bytes()),
        receipt_id: HandoffReceiptId::from_trusted_db_bytes(*loose_uuid(&r.receipt_id)?.as_bytes()),
        binding_id: SecretBindingId::from_trusted_db_bytes(*loose_uuid(&r.binding_id)?.as_bytes()),
        purpose,
        state: operation_state(&r.state)
            .ok_or_else(|| internal(format!("broker: invalid operation state {:?}", r.state)))?,
        fencing_token: r.fencing_token,
        created_at: r.created_at,
        updated_at: r.updated_at,
        hmac: r.hmac.clone(),
        resolved_action: r.resolved_action.clone(),
    })
}

/// `omitempty` predicate for the `&'a str` token fields below —
/// upstream emits these keys only when non-empty; the absence is part
/// of the canonical proof form the HMAC is computed over.
fn str_ref_is_empty(s: &&str) -> bool {
    s.is_empty()
}

/// The proof record on disk uses the domain type's own serde (upstream
/// tags match); only the newtype-strict UUID parse differs — proofs
/// persisted by this broker always carry UUIDv7 IDs, matching
/// upstream's `uuid.Must(uuid.NewV7())` minting.
fn proof_to_json(proof: &LifecycleProof) -> Result<Vec<u8>, Failure> {
    // Marshal through a tolerant record so callers' operation IDs of any
    // UUID version serialize without tripping the v7-strict newtype.
    #[derive(Serialize)]
    struct ProofRecord<'a> {
        proof_id: String,
        instance_id: &'a str,
        operation_id: String,
        lock_id: &'a str,
        stopped_proof: bool,
        mount_release_proof: bool,
        bootstrap_fingerprint: &'a str,
        provisioning_receipt: &'a str,
        fencing_token: u64,
        #[serde(skip_serializing_if = "str_ref_is_empty")]
        stopped_proof_token: &'a str,
        #[serde(skip_serializing_if = "str_ref_is_empty")]
        mount_release_token: &'a str,
        #[serde(skip_serializing_if = "str_ref_is_empty")]
        binding_evidence_token: &'a str,
        #[serde(with = "wire::rfc3339")]
        issued_at: OffsetDateTime,
        #[serde(with = "wire::rfc3339")]
        expires_at: OffsetDateTime,
        hmac: &'a str,
    }
    let r = ProofRecord {
        proof_id: proof.proof_id.to_string(),
        instance_id: &proof.instance_id,
        operation_id: proof.operation_id.to_string(),
        lock_id: &proof.lock_id,
        stopped_proof: proof.stopped_proof,
        mount_release_proof: proof.mount_release_proof,
        bootstrap_fingerprint: &proof.bootstrap_fingerprint,
        provisioning_receipt: &proof.provisioning_receipt,
        fencing_token: proof.fencing_token,
        stopped_proof_token: &proof.stopped_proof_token,
        mount_release_token: &proof.mount_release_token,
        binding_evidence_token: &proof.binding_evidence_token,
        issued_at: proof.issued_at,
        expires_at: proof.expires_at,
        hmac: &proof.hmac,
    };
    serde_json::to_vec(&r).map_err(|e| internal(format!("broker: marshal proof: {e}")))
}

#[derive(Deserialize)]
struct ProofRecordLoad {
    proof_id: String,
    instance_id: String,
    operation_id: String,
    #[serde(default)]
    lock_id: String,
    #[serde(default)]
    stopped_proof: bool,
    #[serde(default)]
    mount_release_proof: bool,
    #[serde(default)]
    bootstrap_fingerprint: String,
    #[serde(default)]
    provisioning_receipt: String,
    #[serde(default)]
    fencing_token: u64,
    #[serde(default)]
    stopped_proof_token: String,
    #[serde(default)]
    mount_release_token: String,
    #[serde(default)]
    binding_evidence_token: String,
    #[serde(default = "wire::go_zero_time", with = "wire::rfc3339")]
    issued_at: OffsetDateTime,
    #[serde(default = "wire::go_zero_time", with = "wire::rfc3339")]
    expires_at: OffsetDateTime,
    #[serde(default)]
    hmac: String,
}

fn proof_domain(r: &ProofRecordLoad) -> Result<LifecycleProof, Failure> {
    Ok(LifecycleProof {
        proof_id: LifecycleProofId::from_trusted_db_bytes(*loose_uuid(&r.proof_id)?.as_bytes()),
        instance_id: r.instance_id.clone(),
        operation_id: OperationId::from_trusted_db_bytes(*loose_uuid(&r.operation_id)?.as_bytes()),
        lock_id: r.lock_id.clone(),
        stopped_proof: r.stopped_proof,
        mount_release_proof: r.mount_release_proof,
        bootstrap_fingerprint: r.bootstrap_fingerprint.clone(),
        provisioning_receipt: r.provisioning_receipt.clone(),
        fencing_token: r.fencing_token,
        stopped_proof_token: r.stopped_proof_token.clone(),
        mount_release_token: r.mount_release_token.clone(),
        binding_evidence_token: r.binding_evidence_token.clone(),
        issued_at: r.issued_at,
        expires_at: r.expires_at,
        hmac: r.hmac.clone(),
    })
}

// ---------------------------------------------------------------------------
// SecretBootstrap
// ---------------------------------------------------------------------------

#[derive(Default)]
struct BootstrapState {
    /// `leases[binding_id]`
    leases: HashMap<SecretBindingId, DurableLease>,
    /// `receipts[receipt_id]`
    receipts: HashMap<HandoffReceiptId, HandoffReceipt>,
    /// `operations[operation_id]`
    operations: HashMap<OperationId, HandoffOperation>,
    /// `proofs[proof_id]`
    proofs: HashMap<LifecycleProofId, LifecycleProof>,
}

/// `SecretBootstrap` — durable B04 leases, receipts, operations, and
/// lifecycle proofs. See the module doc for the on-disk layout and the
/// descriptor-first custody invariant.
pub struct SecretBootstrap {
    root_path: PathBuf,
    backend: ProtectedFileBackend,
    /// Held for parity with upstream's composition and for the R6
    /// recovery slice's `bindRecoveryMinioHandoff` use.
    #[allow(dead_code)]
    journal: Arc<Journal>,
    signing: Arc<SigningService>,
    state: Mutex<BootstrapState>,
}

impl SecretBootstrap {
    /// `NewSecretBootstrap` — recover any persisted state, then serve.
    pub fn new(
        root_path: PathBuf,
        backend: ProtectedFileBackend,
        journal: Arc<Journal>,
        signing: Arc<SigningService>,
    ) -> Result<Self, Failure> {
        ensure_private_root(&root_path)?;
        let sb = Self {
            root_path,
            backend,
            journal,
            signing,
            state: Mutex::new(BootstrapState::default()),
        };
        sb.recover_state()?;
        Ok(sb)
    }

    fn binding_dir(&self, binding_id: &SecretBindingId) -> PathBuf {
        self.root_path.join("bindings").join(binding_id.to_string())
    }

    fn lease_dir(&self) -> PathBuf {
        self.root_path.join("leases")
    }

    fn lock(&self) -> Result<MutexGuard<'_, BootstrapState>, Failure> {
        self.state
            .lock()
            .map_err(|_| internal("broker: secret bootstrap lock poisoned"))
    }

    /// `recoverState` — reload leases (skipping tombstoned revocations),
    /// receipts, operations, and proofs. Unparseable records are
    /// skipped, exactly as upstream's `continue` on unmarshal errors —
    /// but only the record's own file is skipped.
    fn recover_state(&self) -> Result<(), Failure> {
        let mut guard = self.lock()?;

        let leases_dir = self.lease_dir();
        if let Ok(entries) = durable::read_dir(&leases_dir) {
            for e in entries {
                let Some(name) = e.name.to_str() else {
                    continue;
                };
                if !name.ends_with(".json") {
                    continue;
                }
                // Skip recovery when a revocation tombstone exists.
                let tombstone = format!("{}.revoked", name.trim_end_matches(".json"));
                if durable::exists(&leases_dir.join(&tombstone)) {
                    continue;
                }
                let Ok(data) = durable::read_file(&leases_dir.join(&e.name)) else {
                    continue;
                };
                let Ok(record) = serde_json::from_slice::<LeaseRecord>(&data) else {
                    continue;
                };
                let Ok(lease) = lease_domain(&record) else {
                    continue;
                };
                if lease.binding_id.is_nil() {
                    continue;
                }
                guard.leases.insert(lease.binding_id, lease);
            }
        }

        let bindings_dir = self.root_path.join("bindings");
        if let Ok(entries) = durable::read_dir(&bindings_dir) {
            for be in entries {
                if !be.file_type.is_dir() {
                    continue;
                }
                let Some(name) = be.name.to_str().map(str::to_owned) else {
                    continue;
                };
                if Uuid::parse_str(&name).is_err() {
                    continue;
                }
                let receipts_dir = bindings_dir.join(&be.name).join("receipts");
                if let Ok(receipt_entries) = durable::read_dir(&receipts_dir) {
                    for re in receipt_entries {
                        if !re.file_type.is_file() {
                            continue;
                        }
                        let Ok(data) = durable::read_file(&receipts_dir.join(&re.name)) else {
                            continue;
                        };
                        let Ok(record) = serde_json::from_slice::<ReceiptRecord>(&data) else {
                            continue;
                        };
                        let Ok(receipt) = receipt_domain(&record) else {
                            continue;
                        };
                        if receipt.receipt_id.is_nil() {
                            continue;
                        }
                        guard.receipts.insert(receipt.receipt_id, receipt);
                    }
                }
                let ops_dir = bindings_dir.join(&be.name).join("operations");
                if let Ok(op_entries) = durable::read_dir(&ops_dir) {
                    for oe in op_entries {
                        if !oe.file_type.is_file() {
                            continue;
                        }
                        let Ok(data) = durable::read_file(&ops_dir.join(&oe.name)) else {
                            continue;
                        };
                        let Ok(record) = serde_json::from_slice::<OperationRecord>(&data) else {
                            continue;
                        };
                        let Ok(op) = operation_domain(&record) else {
                            continue;
                        };
                        if op.operation_id.is_nil() {
                            continue;
                        }
                        guard.operations.insert(op.operation_id, op);
                    }
                }
            }
        }

        let proofs_dir = self.root_path.join("proofs");
        if let Ok(entries) = durable::read_dir(&proofs_dir) {
            for e in entries {
                let Some(name) = e.name.to_str() else {
                    continue;
                };
                if !name.ends_with(".json") {
                    continue;
                }
                let Ok(data) = durable::read_file(&proofs_dir.join(&e.name)) else {
                    continue;
                };
                let Ok(record) = serde_json::from_slice::<ProofRecordLoad>(&data) else {
                    continue;
                };
                let Ok(proof) = proof_domain(&record) else {
                    continue;
                };
                if proof.proof_id.is_nil() {
                    continue;
                }
                guard.proofs.insert(proof.proof_id, proof);
            }
        }
        Ok(())
    }

    /// `ActiveBindingForPurpose` — the single live protected binding
    /// and its lease for a purpose. The migration operator never
    /// supplies these values itself.
    pub fn active_binding_for_purpose(
        &self,
        purpose: Purpose,
    ) -> Result<(SecretBinding, DurableLease), Failure> {
        let guard = self.lock()?;
        let bindings_dir = self.root_path.join("bindings");
        let entries = durable::read_dir(&bindings_dir)
            .map_err(|e| internal(format!("read protected bindings: {e}")))?;
        let mut binding: Option<SecretBinding> = None;
        for entry in entries {
            if !entry.file_type.is_dir() {
                continue;
            }
            let Some(name) = entry.name.to_str().map(str::to_owned) else {
                continue;
            };
            let Ok(id) = Uuid::parse_str(&name) else {
                continue;
            };
            let binding_id = SecretBindingId::from_trusted_db_bytes(*id.as_bytes());
            let Ok(meta) = self.read_binding_metadata(&binding_id) else {
                continue;
            };
            if meta.get("purpose").map(String::as_str) != Some(purpose.as_str()) {
                continue;
            }
            let Some(lease) = guard.leases.get(&binding_id) else {
                continue;
            };
            if lease.fencing_token == 0 {
                continue;
            }
            if binding.is_some() {
                return Err(internal("multiple active protected bindings for purpose"));
            }
            let Ok(gen_id) = meta
                .get("generation_id")
                .ok_or_else(|| internal("binding metadata missing generation_id"))
                .and_then(|s| loose_uuid(s))
            else {
                continue;
            };
            binding = Some(SecretBinding {
                purpose,
                instance_id: meta.get("instance_id").cloned().unwrap_or_default(),
                generation_id: ProtectedGenerationId::from_trusted_db_bytes(*gen_id.as_bytes()),
                workspace_id: String::new(),
                secret_ref: String::new(),
                binding_id,
            });
        }
        let binding = binding.ok_or_else(|| internal("no active protected binding for purpose"))?;
        let lease = guard
            .leases
            .get(&binding.binding_id)
            .cloned()
            .ok_or_else(|| internal("no active protected binding for purpose"))?;
        Ok((binding, lease))
    }

    /// `findExistingBinding` — the adopted-binding lookup used by
    /// `adopt_b03`'s idempotent return.
    fn find_existing_binding(&self, gen_id: Uuid, instance_id: &str) -> Option<SecretBinding> {
        let bindings_dir = self.root_path.join("bindings");
        let entries = durable::read_dir(&bindings_dir).ok()?;
        for e in entries {
            if !e.file_type.is_dir() {
                continue;
            }
            let Some(name) = e.name.to_str().map(str::to_owned) else {
                continue;
            };
            let Ok(binding_uuid) = Uuid::parse_str(&name) else {
                continue;
            };
            let binding_id = SecretBindingId::from_trusted_db_bytes(*binding_uuid.as_bytes());
            let Ok(meta) = self.read_binding_metadata(&binding_id) else {
                continue;
            };
            if meta.get("generation_id").map(String::as_str) == Some(gen_id.to_string().as_str())
                && meta.get("instance_id").map(String::as_str) == Some(instance_id)
                && meta.get("purpose").map(String::as_str) == Some(Purpose::MinioRoot.as_str())
            {
                return Some(SecretBinding {
                    purpose: Purpose::MinioRoot,
                    instance_id: instance_id.to_owned(),
                    generation_id: ProtectedGenerationId::from_trusted_db_bytes(*gen_id.as_bytes()),
                    workspace_id: String::new(),
                    secret_ref: String::new(),
                    binding_id,
                });
            }
        }
        None
    }

    fn read_binding_metadata(
        &self,
        binding_id: &SecretBindingId,
    ) -> Result<BindingMetadata, Failure> {
        let data = durable::read_file(&self.binding_dir(binding_id).join("metadata.json"))
            .map_err(|e| internal(format!("broker: read binding metadata: {e}")))?;
        serde_json::from_slice(&data)
            .map_err(|e| internal(format!("broker: decode binding metadata: {e}")))
    }

    /// `IssueLifecycleProof` — mint (or return idempotently) the durable
    /// broker proof for B03 lifecycle evidence. The HMAC covers the
    /// canonical JSON of the proof *with its `hmac` field cleared*.
    ///
    /// Returns `(proof, created)`.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_lifecycle_proof(
        &self,
        instance_id: &str,
        operation_id: OperationId,
        lock_id: &str,
        bootstrap_fingerprint: &str,
        provisioning_receipt: &str,
        fencing_token: u64,
        stopped_proof_token: &str,
        mount_release_token: &str,
        binding_evidence_token: &str,
    ) -> Result<(LifecycleProof, bool), Failure> {
        let mut guard = self.lock()?;
        for existing in guard.proofs.values() {
            if existing.operation_id == operation_id
                && existing.instance_id == instance_id
                && existing.lock_id == lock_id
            {
                return Ok((existing.clone(), false));
            }
        }
        let issued_at = now();
        let mut proof = LifecycleProof {
            proof_id: LifecycleProofId::new(),
            instance_id: instance_id.to_owned(),
            operation_id,
            lock_id: lock_id.to_owned(),
            stopped_proof: !stopped_proof_token.is_empty(),
            mount_release_proof: !mount_release_token.is_empty(),
            bootstrap_fingerprint: bootstrap_fingerprint.to_owned(),
            provisioning_receipt: provisioning_receipt.to_owned(),
            fencing_token,
            stopped_proof_token: stopped_proof_token.to_owned(),
            mount_release_token: mount_release_token.to_owned(),
            binding_evidence_token: binding_evidence_token.to_owned(),
            issued_at,
            expires_at: issued_at + PROOF_TTL,
            hmac: String::new(),
        };
        // Sign canonical form without HMAC.
        let canonical = proof_to_json(&proof)?;
        proof.hmac = self.signing.fingerprint("b04-proof", &canonical);
        guard.proofs.insert(proof.proof_id, proof.clone());
        if let Err(e) = self.persist_proof(&proof) {
            guard.proofs.remove(&proof.proof_id);
            return Err(e);
        }
        Ok((proof, true))
    }

    /// `AdoptB03` — migrate a legacy B03 protected generation (or mint
    /// the first-boot generation when none exists — SC-DEF-14) into a
    /// durable B04 binding with a lease carrying the caller's fencing
    /// token.
    pub fn adopt_b03(
        &self,
        req: &AdoptRequest,
    ) -> Result<(SecretBinding, BootstrapOutcome), Failure> {
        req.validate()?;
        if req.purpose != Purpose::MinioRoot || !req.purpose.materializable() {
            return Err(Failure::denied(
                codes::NOT_MATERIALIZABLE,
                "secretbootstrap: purpose is declaration-only",
            ));
        }

        let mut guard = self.lock()?;
        let bootstrap_purpose = format!("bootstrap.minio-root-password.{}", req.instance_id);
        let existing = self.backend.enumerate(&bootstrap_purpose).map_err(|e| {
            Failure::denied(
                codes::B04_CUTOVER_REPAIR_REQUIRED,
                format!("B04_CUTOVER_REPAIR_REQUIRED: enumerate: {}", e.message()),
            )
        })?;
        if existing.len() > 1 {
            return Err(Failure::denied(
                codes::B04_PROTECTED_STATE_REPAIR_REQUIRED,
                "B04_PROTECTED_STATE_REPAIR_REQUIRED: multiple bootstrap generations",
            ));
        }
        let legacy_gen = if existing.is_empty() {
            // SC-DEF-14: mint the generation there is nothing to cut
            // over from — a genuine first boot has no legacy secret.
            self.backend
                .create(&bootstrap_purpose, Uuid::new_v4().to_string().as_bytes())
                .map_err(|e| internal(format!("minting first-boot generation: {}", e.message())))?
        } else {
            existing[0].clone()
        };

        if let Some(existing_binding) =
            self.find_existing_binding(legacy_gen.generation_id, &req.instance_id)
        {
            // SC-DEF-18: refresh the adopted lease's fencing token so a
            // later `up` attempt's fresh token can still materialize.
            if let Some(lease) = guard.leases.get_mut(&existing_binding.binding_id)
                && lease.fencing_token != req.fencing_token
            {
                lease.fencing_token = req.fencing_token;
                self.persist_lease(lease).map_err(|e| {
                    Failure::denied(
                        codes::B04_HANDOFF_DENIED,
                        format!("updating lease fencing token: {}", e.message()),
                    )
                })?;
            }
            return Ok((existing_binding, BootstrapOutcome::AlreadyAdopted));
        }

        let evidence = self.load_b03_source_evidence(legacy_gen.generation_id);
        if !evidence.legacy_binding_id.is_empty() {
            if evidence.generation_token != legacy_gen.generation_id.to_string()
                || evidence.keyed_fingerprint
                    != self.compute_b03_fingerprint(
                        &req.instance_id,
                        &bootstrap_purpose,
                        legacy_gen.generation_id,
                    )
            {
                return Err(Failure::denied(
                    codes::B04_CUTOVER_REPAIR_REQUIRED,
                    codes::B04_CUTOVER_REPAIR_REQUIRED,
                ));
            }
            let binding_id = SecretBindingId::new();
            let lease = DurableLease {
                lease_id: DurableLeaseId::new(),
                binding_id,
                holder_op_id: OperationId::from_trusted_db_bytes(*Uuid::nil().as_bytes()),
                expires_at: wire::GO_ZERO_TIME,
                fencing_token: req.fencing_token,
                created_at: now(),
            };
            guard.leases.insert(binding_id, lease.clone());
            if let Err(e) = self.persist_lease(&lease) {
                guard.leases.remove(&binding_id);
                return Err(e);
            }
            return Ok((
                SecretBinding {
                    purpose: Purpose::MinioRoot,
                    instance_id: req.instance_id.clone(),
                    generation_id: ProtectedGenerationId::from_trusted_db_bytes(
                        *legacy_gen.generation_id.as_bytes(),
                    ),
                    workspace_id: String::new(),
                    secret_ref: String::new(),
                    binding_id,
                },
                BootstrapOutcome::AlreadyAdopted,
            ));
        }

        let new_evidence = B03SourceEvidence {
            legacy_binding_id: bootstrap_purpose.clone(),
            generation_token: legacy_gen.generation_id.to_string(),
            keyed_fingerprint: self.compute_b03_fingerprint(
                &req.instance_id,
                &bootstrap_purpose,
                legacy_gen.generation_id,
            ),
            provisioning_receipt_id: req.operation_id.to_string(),
            lifecycle_operation_id: req.operation_id.to_string(),
            mount_release_proof: String::new(),
        };
        self.persist_b03_source_evidence(legacy_gen.generation_id, &new_evidence)
            .map_err(|e| denied_prefixed(format!("persist b03 evidence: {}", e.message())))?;

        let binding_id = SecretBindingId::new();
        let binding_dir = self.binding_dir(&binding_id);
        durable::mkdir_p(&binding_dir, PRIVATE_DIRECTORY_MODE)
            .map_err(|e| internal(format!("broker: create binding dir: {e}")))?;

        let mut meta = BindingMetadata::new();
        meta.insert("purpose".to_owned(), Purpose::MinioRoot.as_str().to_owned());
        meta.insert("instance_id".to_owned(), req.instance_id.clone());
        meta.insert(
            "generation_id".to_owned(),
            legacy_gen.generation_id.to_string(),
        );
        self.write_binding_metadata(&binding_id, &meta)?;

        let lease = DurableLease {
            lease_id: DurableLeaseId::new(),
            binding_id,
            holder_op_id: OperationId::from_trusted_db_bytes(*Uuid::nil().as_bytes()),
            expires_at: wire::GO_ZERO_TIME,
            fencing_token: req.fencing_token,
            created_at: now(),
        };
        guard.leases.insert(binding_id, lease.clone());
        if let Err(e) = self.persist_lease(&lease) {
            guard.leases.remove(&binding_id);
            return Err(e);
        }
        Ok((
            SecretBinding {
                purpose: Purpose::MinioRoot,
                instance_id: req.instance_id.clone(),
                generation_id: ProtectedGenerationId::from_trusted_db_bytes(
                    *legacy_gen.generation_id.as_bytes(),
                ),
                workspace_id: String::new(),
                secret_ref: String::new(),
                binding_id,
            },
            BootstrapOutcome::Adopted,
        ))
    }

    /// `computeB03Fingerprint` — `HMAC-SHA256("b03-evidence",
    /// instance:purpose:gen)`; a *fixed* key by upstream design (the
    /// fingerprint binds the record, it is not a secret).
    fn compute_b03_fingerprint(&self, instance_id: &str, purpose: &str, gen_id: Uuid) -> String {
        use hmac::Mac as _;
        let mut mac = <hmac::Hmac<sha2::Sha256> as hmac::KeyInit>::new_from_slice(b"b03-evidence")
            .unwrap_or_else(|_| unreachable!("HMAC-SHA-256 accepts any key length"));
        mac.update(format!("{instance_id}:{purpose}:{gen_id}").as_bytes());
        wire::hex_encode(&mac.finalize().into_bytes())
    }

    fn load_b03_source_evidence(&self, gen_id: Uuid) -> B03SourceEvidence {
        let path = self
            .root_path
            .join("evidence")
            .join(format!("{gen_id}.json"));
        let Ok(data) = durable::read_file(&path) else {
            return B03SourceEvidence::default();
        };
        serde_json::from_slice(&data).unwrap_or_default()
    }

    fn persist_b03_source_evidence(
        &self,
        gen_id: Uuid,
        evidence: &B03SourceEvidence,
    ) -> Result<(), Failure> {
        let dir = self.root_path.join("evidence");
        durable::mkdir_p(&dir, PRIVATE_DIRECTORY_MODE)
            .map_err(|e| internal(format!("broker: evidence dir: {e}")))?;
        let data = serde_json::to_vec(evidence)
            .map_err(|e| internal(format!("broker: marshal evidence: {e}")))?;
        let path = dir.join(format!("{gen_id}.json"));
        write_private(&path, &data, PRIVATE_READ_ONLY_MODE)
    }

    fn write_binding_metadata(
        &self,
        binding_id: &SecretBindingId,
        meta: &BindingMetadata,
    ) -> Result<(), Failure> {
        let data = serde_json::to_vec(meta)
            .map_err(|e| internal(format!("broker: marshal binding metadata: {e}")))?;
        write_private(
            &self.binding_dir(binding_id).join("metadata.json"),
            &data,
            PRIVATE_READ_ONLY_MODE,
        )
    }

    /// `ValidateMaterializeRequest` — validate the handoff against the
    /// durable lease and receipts WITHOUT reading the secret value.
    /// Returns `(receipt, operation)`: `operation` is `Some` for a fresh
    /// operation and for a resume of an existing non-terminal one
    /// (upstream's `nil` op return is instead the persisted op itself,
    /// so a resumed handoff can drive its remaining transitions without
    /// dereferencing absent state).
    pub fn validate_materialize_request(
        &self,
        req: &HandoffRequest,
    ) -> Result<(HandoffReceipt, Option<HandoffOperation>), Failure> {
        req.validate()
            .map_err(|e| denied_prefixed(format!("B04_HANDOFF_DENIED: {}", e.message())))?;
        if !req.purpose.materializable() {
            return Err(denied_prefixed(
                "B04_HANDOFF_DENIED: purpose not materializable",
            ));
        }

        let mut guard = self.lock()?;
        let lease = guard
            .leases
            .get(&req.binding_id)
            .ok_or_else(|| denied_prefixed("B04_HANDOFF_DENIED: no active lease"))?;
        if req.fencing_token != lease.fencing_token {
            return Err(Failure::denied(
                codes::FENCING_CONFLICT,
                "B04_HANDOFF_DENIED: secretbootstrap: fencing token conflict",
            ));
        }

        if let Some(existing) = guard.receipts.get(&req.receipt_id) {
            match existing.state {
                HandoffReceiptState::Acknowledged => {
                    return Err(Failure::denied(
                        codes::RECEIPT_CONSUMED,
                        "secretbootstrap: receipt already consumed",
                    ));
                }
                HandoffReceiptState::Invalidated => {
                    return Err(denied_prefixed("B04_HANDOFF_DENIED: receipt invalidated"));
                }
                _ => return Ok((existing.clone(), None)),
            }
        }

        let expected_hmac = self.compute_receipt_hmac(req);
        if !wire::hmac_equal(req.receipt_hmac.as_bytes(), expected_hmac.as_bytes()) {
            return Err(denied_prefixed("B04_HANDOFF_DENIED: hmac mismatch"));
        }

        let meta = self.read_binding_metadata(&req.binding_id).map_err(|e| {
            denied_prefixed(format!("B04_HANDOFF_DENIED: {}", binding_meta_msg(&e)))
        })?;
        let gen_id = meta
            .get("generation_id")
            .ok_or_else(|| denied_prefixed("B04_HANDOFF_DENIED: invalid generation id"))
            .and_then(|s| {
                Uuid::parse_str(s)
                    .map_err(|_| denied_prefixed("B04_HANDOFF_DENIED: invalid generation id"))
            })?;
        self.backend
            .get_by_id(gen_id)
            .map_err(|_| denied_prefixed("B04_HANDOFF_DENIED: generation not found"))?;

        // Repeated call for an existing operation: return the operation's
        // own state for resume — never mint a second receipt.
        if let Some(existing_op) = guard.operations.get(&req.operation_id) {
            if existing_op.state.is_terminal() {
                if existing_op.state == HandoffOperationState::Acknowledged {
                    return Err(Failure::denied(
                        codes::RECEIPT_CONSUMED,
                        "secretbootstrap: receipt already consumed",
                    ));
                }
                return Err(denied_prefixed(format!(
                    "B04_HANDOFF_DENIED: operation {} is terminal ({})",
                    req.operation_id,
                    existing_op.state.as_str()
                )));
            }
            // Non-terminal: resume. Return the existing operation's
            // receipt even when the caller supplies a fresh receipt ID.
            if let Some(r) = guard.receipts.get(&existing_op.receipt_id) {
                return Ok((r.clone(), Some(existing_op.clone())));
            }
        }

        let issued_at = now();
        let op = HandoffOperation {
            operation_id: req.operation_id,
            receipt_id: req.receipt_id,
            binding_id: req.binding_id,
            purpose: req.purpose,
            state: HandoffOperationState::Issued,
            fencing_token: req.fencing_token,
            created_at: issued_at,
            updated_at: issued_at,
            hmac: String::new(),
            resolved_action: String::new(),
        };
        guard.operations.insert(req.operation_id, op.clone());
        if let Err(e) = self.persist_operation(&op) {
            guard.operations.remove(&req.operation_id);
            return Err(e);
        }

        let receipt = HandoffReceipt {
            receipt_id: req.receipt_id,
            operation_id: req.operation_id,
            binding_id: req.binding_id,
            purpose: req.purpose,
            service: req.service.clone(),
            target: req.target.clone(),
            uid: req.uid,
            gid: req.gid,
            peer_uid: req.peer_uid,
            peer_pid: req.peer_pid,
            hmac: req.receipt_hmac.clone(),
            state: HandoffReceiptState::Issued,
            fencing_token: req.fencing_token,
            expires_at: issued_at + RECEIPT_TTL,
            issued_at,
        };
        guard.receipts.insert(req.receipt_id, receipt.clone());
        if let Err(e) = self.persist_receipt(&req.binding_id, &receipt) {
            guard.receipts.remove(&req.receipt_id);
            return Err(e);
        }
        Ok((receipt, Some(op)))
    }

    /// `ResolveCredential` — read the bound generation's plaintext from
    /// the protected backend. MUST only be called after the descriptor
    /// has been received and validated via SCM_RIGHTS.
    pub fn resolve_credential(&self, receipt: &HandoffReceipt) -> Result<Vec<u8>, Failure> {
        let _guard = self.lock()?;
        let meta = self
            .read_binding_metadata(&receipt.binding_id)
            .map_err(|e| {
                denied_prefixed(format!("B04_HANDOFF_DENIED: {}", binding_meta_msg(&e)))
            })?;
        let gen_id = meta
            .get("generation_id")
            .ok_or_else(|| denied_prefixed("B04_HANDOFF_DENIED: invalid generation id"))
            .and_then(|s| {
                Uuid::parse_str(s)
                    .map_err(|_| denied_prefixed("B04_HANDOFF_DENIED: invalid generation id"))
            })?;
        let generation = self
            .backend
            .get_by_id(gen_id)
            .map_err(|_| denied_prefixed("B04_HANDOFF_DENIED: generation not found"))?;
        let value = self.backend.read(&generation)?;
        if value.len() > MAX_SECRET_BYTES {
            return Err(denied_prefixed(format!(
                "B04_HANDOFF_DENIED: secret exceeds {MAX_SECRET_BYTES} byte limit"
            )));
        }
        Ok(value)
    }

    /// `MaterializeDependency` — the JSON convenience path: validate
    /// then resolve in one call. The descriptor transport calls
    /// `validate_materialize_request` + `resolve_credential` separately
    /// and never reaches plaintext through here.
    pub fn materialize_dependency(
        &self,
        req: &HandoffRequest,
    ) -> Result<(HandoffReceipt, Vec<u8>), Failure> {
        let (receipt, _op) = self.validate_materialize_request(req)?;
        let value = self.resolve_credential(&receipt)?;
        Ok((receipt, value))
    }

    /// `ComputeReceiptHMAC` — the `b04-materialize` fingerprint over the
    /// colon-joined request payload.
    pub fn compute_receipt_hmac(&self, req: &HandoffRequest) -> String {
        let payload = format!(
            "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
            req.binding_id,
            req.operation_id,
            req.receipt_id,
            req.purpose.as_str(),
            req.peer_uid,
            req.peer_pid,
            req.service,
            req.target,
            req.uid,
            req.gid
        );
        self.signing
            .fingerprint("b04-materialize", payload.as_bytes())
    }

    /// `computeOperationHMAC` — `b04-operation` over the canonical op
    /// payload (operation, receipt, binding, purpose, state, fence,
    /// created-at-nanos).
    fn compute_operation_hmac(&self, op: &HandoffOperation) -> String {
        let payload = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            op.operation_id,
            op.receipt_id,
            op.binding_id,
            op.purpose.as_str(),
            op.state.as_str(),
            op.fencing_token,
            op.created_at.unix_timestamp_nanos()
        );
        self.signing
            .fingerprint("b04-operation", payload.as_bytes())
    }

    /// `StartReserved` — `issued → reserved`.
    pub fn start_reserved(&self, operation_id: OperationId) -> Result<(), Failure> {
        self.transition_operation(operation_id, HandoffOperationState::Reserved)
    }

    /// `StartWrite` — `reserved → write_started`.
    pub fn start_write(&self, operation_id: OperationId) -> Result<(), Failure> {
        self.transition_operation(operation_id, HandoffOperationState::WriteStarted)
    }

    /// `CompleteBrokerWrite` — `write_started → broker_closed` after the
    /// broker has written and closed the descriptor.
    pub fn complete_broker_write(&self, operation_id: OperationId) -> Result<(), Failure> {
        self.transition_operation(operation_id, HandoffOperationState::BrokerClosed)
    }

    /// `ConfirmHelperAcknowledged` — `broker_closed →
    /// helper_acknowledged` after the helper's `0x03` confirmation.
    pub fn confirm_helper_acknowledged(&self, operation_id: OperationId) -> Result<(), Failure> {
        self.transition_operation(operation_id, HandoffOperationState::HelperAcknowledged)
    }

    /// `AcknowledgeMaterialization` — `helper_acknowledged →
    /// acknowledged`, and the receipt is durably marked acknowledged so
    /// replays refuse across restarts.
    pub fn acknowledge_materialization(&self, operation_id: OperationId) -> Result<(), Failure> {
        let mut guard = self.lock()?;
        let op = guard
            .operations
            .get_mut(&operation_id)
            .ok_or_else(|| internal(format!("operation {operation_id} not found")))?;
        if !op.state.can_transition(HandoffOperationState::Acknowledged) {
            return Err(invalid_transition(
                op.state,
                HandoffOperationState::Acknowledged,
            ));
        }
        op.state = HandoffOperationState::Acknowledged;
        op.updated_at = now();
        op.hmac = self.compute_operation_hmac(op);
        self.persist_operation(op)?;
        let receipt_id = op.receipt_id;
        let binding_id = op.binding_id;
        if let Some(r) = guard.receipts.get_mut(&receipt_id)
            && r.state != HandoffReceiptState::Acknowledged
        {
            r.state = HandoffReceiptState::Acknowledged;
            let receipt = r.clone();
            self.persist_receipt(&binding_id, &receipt)?;
        }
        Ok(())
    }

    fn transition_operation(
        &self,
        operation_id: OperationId,
        to: HandoffOperationState,
    ) -> Result<(), Failure> {
        let mut guard = self.lock()?;
        let op = guard
            .operations
            .get_mut(&operation_id)
            .ok_or_else(|| internal(format!("operation {operation_id} not found")))?;
        if !op.state.can_transition(to) {
            return Err(invalid_transition(op.state, to));
        }
        op.state = to;
        op.updated_at = now();
        op.hmac = self.compute_operation_hmac(op);
        self.persist_operation(op)
    }

    /// `PrepareSystemGeneration` — mint a fresh protected generation for
    /// a materializable purpose and bind it with a lease.
    pub fn prepare_system_generation(
        &self,
        purpose: Purpose,
        instance_id: &str,
    ) -> Result<SecretBinding, Failure> {
        if !purpose.materializable() {
            return Err(Failure::denied(
                codes::NOT_MATERIALIZABLE,
                "secretbootstrap: purpose is declaration-only",
            ));
        }
        if instance_id.is_empty() {
            return Err(Failure::invalid(
                codes::BOOTSTRAP_INVALID,
                "secretbootstrap: instance id required",
            ));
        }
        let mut guard = self.lock()?;
        let bootstrap_purpose = format!("bootstrap.{}.{instance_id}", purpose.as_str());
        let generation = self
            .backend
            .create(&bootstrap_purpose, Uuid::new_v4().to_string().as_bytes())?;

        let binding_id = SecretBindingId::new();
        let binding_dir = self.binding_dir(&binding_id);
        durable::mkdir_p(&binding_dir, PRIVATE_DIRECTORY_MODE)
            .map_err(|e| internal(format!("broker: create binding dir: {e}")))?;

        let mut meta = BindingMetadata::new();
        meta.insert("purpose".to_owned(), purpose.as_str().to_owned());
        meta.insert("instance_id".to_owned(), instance_id.to_owned());
        meta.insert(
            "generation_id".to_owned(),
            generation.generation_id.to_string(),
        );
        self.write_binding_metadata(&binding_id, &meta)?;

        let lease = DurableLease {
            lease_id: DurableLeaseId::new(),
            binding_id,
            holder_op_id: OperationId::from_trusted_db_bytes(*Uuid::nil().as_bytes()),
            expires_at: wire::GO_ZERO_TIME,
            fencing_token: 1,
            created_at: now(),
        };
        guard.leases.insert(binding_id, lease.clone());
        if let Err(e) = self.persist_lease(&lease) {
            guard.leases.remove(&binding_id);
            return Err(e);
        }
        Ok(SecretBinding {
            purpose,
            instance_id: instance_id.to_owned(),
            generation_id: ProtectedGenerationId::from_trusted_db_bytes(
                *generation.generation_id.as_bytes(),
            ),
            workspace_id: String::new(),
            secret_ref: String::new(),
            binding_id,
        })
    }

    /// `BindMaterializedSecret` — install a caller-supplied value as the
    /// new active protected generation for a materializable purpose and
    /// bind it with a TTL'd lease (ADR 0019 §4 rotate-then-sync). Any
    /// prior active binding for the same purpose+instance is revoked
    /// first — a rotation is a replacement.
    pub fn bind_materialized_secret(
        &self,
        purpose: Purpose,
        instance_id: &str,
        value: &[u8],
        ttl: time::Duration,
    ) -> Result<SecretBindingId, Failure> {
        if !purpose.materializable() {
            return Err(Failure::denied(
                codes::NOT_MATERIALIZABLE,
                "secretbootstrap: purpose is declaration-only",
            ));
        }
        if instance_id.is_empty() || value.is_empty() || ttl <= time::Duration::ZERO {
            return Err(Failure::invalid(
                codes::BOOTSTRAP_INVALID,
                "secretbootstrap: invalid materialized secret binding",
            ));
        }
        let mut guard = self.lock()?;
        let bindings_dir = self.root_path.join("bindings");
        if let Ok(entries) = durable::read_dir(&bindings_dir) {
            for entry in entries {
                if !entry.file_type.is_dir() {
                    continue;
                }
                let Some(name) = entry.name.to_str().map(str::to_owned) else {
                    continue;
                };
                let Ok(id) = Uuid::parse_str(&name) else {
                    continue;
                };
                let binding_id = SecretBindingId::from_trusted_db_bytes(*id.as_bytes());
                let Ok(meta) = self.read_binding_metadata(&binding_id) else {
                    continue;
                };
                if meta.get("purpose").map(String::as_str) != Some(purpose.as_str())
                    || meta.get("instance_id").map(String::as_str) != Some(instance_id)
                {
                    continue;
                }
                let Some(lease) = guard.leases.get(&binding_id) else {
                    continue;
                };
                if lease.fencing_token == 0 {
                    continue;
                }
                self.revoke_binding_locked(&mut guard, binding_id)
                    .map_err(|e| {
                        internal(format!(
                            "bind materialized secret: revoke prior binding: {}",
                            e.message()
                        ))
                    })?;
            }
        }

        let generation = self
            .backend
            .create(purpose.as_str(), value)
            .map_err(|e| internal(format!("bind materialized secret: {}", e.message())))?;

        let binding_id = SecretBindingId::new();
        let binding_dir = self.binding_dir(&binding_id);
        let cleanup = |this: &Self| {
            let _ = this.backend.delete(generation.generation_id);
        };
        if let Err(e) = durable::mkdir_p(&binding_dir, PRIVATE_DIRECTORY_MODE) {
            cleanup(self);
            return Err(internal(format!("bind materialized secret: {e}")));
        }
        let mut meta = BindingMetadata::new();
        meta.insert("purpose".to_owned(), purpose.as_str().to_owned());
        meta.insert("instance_id".to_owned(), instance_id.to_owned());
        meta.insert(
            "generation_id".to_owned(),
            generation.generation_id.to_string(),
        );
        self.write_binding_metadata(&binding_id, &meta)
            .map_err(|e| {
                cleanup(self);
                internal(format!("bind materialized secret: {}", e.message()))
            })?;

        let now_ = now();
        let lease = DurableLease {
            lease_id: DurableLeaseId::new(),
            binding_id,
            holder_op_id: OperationId::from_trusted_db_bytes(*Uuid::nil().as_bytes()),
            expires_at: now_ + ttl,
            fencing_token: 1,
            created_at: now_,
        };
        guard.leases.insert(binding_id, lease.clone());
        if let Err(e) = self.persist_lease(&lease) {
            guard.leases.remove(&binding_id);
            return Err(internal(format!(
                "bind materialized secret: {}",
                e.message()
            )));
        }
        Ok(binding_id)
    }

    /// `RevokeBinding` — invalidate unconsumed receipts, transitionable
    /// operations, write the durable tombstone, then remove the lease.
    pub fn revoke_binding(&self, binding_id: SecretBindingId) -> Result<BootstrapOutcome, Failure> {
        let mut guard = self.lock()?;
        self.revoke_binding_locked(&mut guard, binding_id)
    }

    fn revoke_binding_locked(
        &self,
        guard: &mut BootstrapState,
        binding_id: SecretBindingId,
    ) -> Result<BootstrapOutcome, Failure> {
        let mut first_err: Option<Failure> = None;
        let mut join = |e: Failure| {
            if first_err.is_none() {
                first_err = Some(e);
            }
        };

        let affected: Vec<HandoffReceiptId> = guard
            .receipts
            .iter()
            .filter(|(_, r)| {
                r.binding_id == binding_id && r.state != HandoffReceiptState::Acknowledged
            })
            .map(|(id, _)| *id)
            .collect();
        for id in affected {
            if let Some(r) = guard.receipts.get_mut(&id) {
                r.state = HandoffReceiptState::Invalidated;
                let receipt = r.clone();
                if let Err(e) = self.persist_receipt(&binding_id, &receipt) {
                    join(e);
                }
            }
        }
        let affected_ops: Vec<OperationId> = guard
            .operations
            .iter()
            .filter(|(_, o)| o.binding_id == binding_id && o.state.is_transitionable())
            .map(|(id, _)| *id)
            .collect();
        for id in affected_ops {
            if let Some(op) = guard.operations.get_mut(&id) {
                op.state = HandoffOperationState::Invalidated;
                op.updated_at = now();
                op.hmac = self.compute_operation_hmac(op);
                let op = op.clone();
                if let Err(e) = self.persist_operation(&op) {
                    join(e);
                }
            }
        }

        // Tombstone + dir-sync BEFORE the lease file is removed: a crash
        // between the two leaves the tombstone intact and keeps the
        // revoked lease unrecoverable.
        let lease_dir = self.lease_dir();
        durable::mkdir_p(&lease_dir, PRIVATE_DIRECTORY_MODE)
            .map_err(|e| internal(format!("broker: lease dir: {e}")))?;
        // Upstream writes the tombstone with `time.RFC3339` — whole
        // seconds, no fractional field.
        let tombstone = format!(
            "{{\"revoked_at\":\"{}\"}}",
            wire::format_rfc3339_seconds(now())
        );
        if let Err(e) = write_private(
            &lease_dir.join(format!("{binding_id}.revoked")),
            tombstone.as_bytes(),
            PRIVATE_READ_ONLY_MODE,
        ) {
            join(e);
        }
        if let Err(e) = sync_dir(&lease_dir) {
            join(e);
        }
        guard.leases.remove(&binding_id);
        if let Err(e) = durable::remove_file(&lease_dir.join(format!("{binding_id}.json")))
            && e != rustix::io::Errno::NOENT
        {
            join(internal(format!("broker: remove lease: {e}")));
        }

        match first_err {
            Some(e) => Err(e),
            None => Ok(BootstrapOutcome::Revoked),
        }
    }

    /// `DeleteBinding` — fencing-token-checked removal of the binding,
    /// its lease, receipts, operations, and the binding directory.
    pub fn delete_binding(
        &self,
        binding_id: SecretBindingId,
        fencing_token: u64,
    ) -> Result<BootstrapOutcome, Failure> {
        let mut guard = self.lock()?;
        if let Some(lease) = guard.leases.get(&binding_id)
            && lease.fencing_token != fencing_token
        {
            return Err(Failure::denied(
                codes::FENCING_CONFLICT,
                "secretbootstrap: fencing token conflict",
            ));
        }
        guard.leases.remove(&binding_id);
        let _ = durable::remove_file(&self.lease_dir().join(format!("{binding_id}.json")));
        let receipt_ids: Vec<HandoffReceiptId> = guard
            .receipts
            .iter()
            .filter(|(_, r)| r.binding_id == binding_id)
            .map(|(id, _)| *id)
            .collect();
        for id in receipt_ids {
            guard.receipts.remove(&id);
        }
        let op_ids: Vec<OperationId> = guard
            .operations
            .iter()
            .filter(|(_, o)| o.binding_id == binding_id)
            .map(|(id, _)| *id)
            .collect();
        for id in op_ids {
            guard.operations.remove(&id);
        }
        let binding_dir = self.binding_dir(&binding_id);
        if let Err(e) = durable::remove_all(&binding_dir)
            && e != rustix::io::Errno::NOENT
        {
            return Err(internal(format!("broker: remove binding dir: {e}")));
        }
        Ok(BootstrapOutcome::Deleted)
    }

    /// `VerifyLifecycleProof` — the caller-supplied adoption evidence
    /// must match a broker-issued, unexpired, unexpired-at-call proof
    /// whose stored HMAC verifies over the canonical record.
    pub fn verify_lifecycle_proof(
        &self,
        instance_id: &str,
        fencing_token: u64,
        stopped_proof_token: &str,
        mount_release_token: &str,
        binding_evidence_token: &str,
        expires_at: OffsetDateTime,
    ) -> Result<LifecycleProof, Failure> {
        let guard = self.lock()?;
        if now() > expires_at {
            return Err(denied_prefixed(
                "B04_HANDOFF_DENIED: lifecycle proof expired",
            ));
        }
        for proof in guard.proofs.values() {
            if proof.instance_id != instance_id {
                continue;
            }
            // Verify canonical HMAC — recompute with `hmac` cleared.
            let saved_hmac = proof.hmac.clone();
            let mut canonical_proof = proof.clone();
            canonical_proof.hmac = String::new();
            let Ok(canonical) = proof_to_json(&canonical_proof) else {
                continue;
            };
            let expected = self.signing.fingerprint("b04-proof", &canonical);
            if !wire::hmac_equal(saved_hmac.as_bytes(), expected.as_bytes()) {
                continue;
            }
            if proof.expires_at < now() {
                continue;
            }
            if proof.fencing_token != fencing_token
                || proof.stopped_proof_token != stopped_proof_token
                || proof.mount_release_token != mount_release_token
                || proof.binding_evidence_token != binding_evidence_token
            {
                continue;
            }
            return Ok(proof.clone());
        }
        Err(denied_prefixed(format!(
            "B04_HANDOFF_DENIED: no valid lifecycle proof for instance {instance_id}"
        )))
    }

    // ------------------------------------------------------------------
    // Persistence helpers — `.tmp` + rename, private modes, dir sync
    // ------------------------------------------------------------------

    fn persist_lease(&self, lease: &DurableLease) -> Result<(), Failure> {
        let dir = self.lease_dir();
        durable::mkdir_p(&dir, PRIVATE_DIRECTORY_MODE)
            .map_err(|e| internal(format!("broker: lease dir: {e}")))?;
        let data = serde_json::to_vec(&lease_record(lease))
            .map_err(|e| internal(format!("broker: marshal lease: {e}")))?;
        let path = dir.join(format!("{}.json", lease.binding_id));
        atomic_write_private(&path, &data)?;
        sync_dir(&dir)
    }

    fn persist_receipt(
        &self,
        binding_id: &SecretBindingId,
        receipt: &HandoffReceipt,
    ) -> Result<(), Failure> {
        let dir = self.binding_dir(binding_id).join("receipts");
        durable::mkdir_p(&dir, PRIVATE_DIRECTORY_MODE)
            .map_err(|e| internal(format!("broker: receipts dir: {e}")))?;
        let data = serde_json::to_vec(&receipt_record(receipt))
            .map_err(|e| internal(format!("broker: marshal receipt: {e}")))?;
        let path = dir.join(format!("{}.json", receipt.receipt_id));
        atomic_write_private(&path, &data)
    }

    fn persist_operation(&self, op: &HandoffOperation) -> Result<(), Failure> {
        let dir = self.binding_dir(&op.binding_id).join("operations");
        durable::mkdir_p(&dir, PRIVATE_DIRECTORY_MODE)
            .map_err(|e| internal(format!("broker: operations dir: {e}")))?;
        let data = serde_json::to_vec(&operation_record(op))
            .map_err(|e| internal(format!("broker: marshal operation: {e}")))?;
        let path = dir.join(format!("{}.json", op.operation_id));
        atomic_write_private(&path, &data)
    }

    fn persist_proof(&self, proof: &LifecycleProof) -> Result<(), Failure> {
        let dir = self.root_path.join("proofs");
        durable::mkdir_p(&dir, PRIVATE_DIRECTORY_MODE)
            .map_err(|e| internal(format!("broker: proofs dir: {e}")))?;
        let data = proof_to_json(proof)?;
        let path = dir.join(format!("{}.json", proof.proof_id));
        atomic_write_private(&path, &data)?;
        sync_dir(&dir)
    }
}

/// Upstream writes binding metadata and evidence at `0400` (read-only
/// even to the owner); receipts/operations/leases at `0400` via the
/// tmp+rename helpers too.
const PRIVATE_READ_ONLY_MODE: u32 = 0o400;

fn invalid_transition(from: HandoffOperationState, to: HandoffOperationState) -> Failure {
    internal(format!(
        "invalid transition {} -> {}",
        from.as_str(),
        to.as_str()
    ))
}

/// Map a metadata read failure to upstream's denial messages: missing
/// file → "binding not found", undecodable → "invalid binding metadata".
fn binding_meta_msg(e: &Failure) -> &'static str {
    if e.message().contains("read binding metadata") {
        "binding not found"
    } else {
        "invalid binding metadata"
    }
}

/// `os.WriteFile` at a private mode — plain write (upstream's own
/// pattern for `metadata.json`/`evidence/*.json` and the tombstone).
fn write_private(path: &Path, data: &[u8], mode: u32) -> Result<(), Failure> {
    use std::io::Write as _;
    let mut file = durable::open_write(path, mode)
        .map_err(|e| internal(format!("broker: write {}: {e}", path.display())))?;
    file.write_all(data)
        .and_then(|()| file.sync_all())
        .map_err(|e| internal(format!("broker: write {}: {e}", path.display())))?;
    // Enforce the mode even when the file pre-existed (O_CREATE keeps
    // the old mode otherwise). `fchmod` on the open fd is on the
    // allow-list; path-based `fchmodat` is not (ADR 0044).
    rustix::fs::fchmod(&file, rustix::fs::Mode::from_raw_mode(mode))
        .map_err(|e| internal(format!("broker: secure {}: {e}", path.display())))?;
    Ok(())
}

/// Upstream's `path + ".tmp"` → `os.Rename` sequence for receipts,
/// operations, leases, and proofs — a private-mode tmp write followed
/// by atomic rename and tmp cleanup on failure.
fn atomic_write_private(path: &Path, data: &[u8]) -> Result<(), Failure> {
    let tmp = {
        let mut p = path.as_os_str().to_owned();
        p.push(".tmp");
        PathBuf::from(p)
    };
    let result = write_private(&tmp, data, PRIVATE_READ_ONLY_MODE).and_then(|()| {
        durable::rename_replace(&tmp, path).map_err(|e| {
            internal(format!(
                "broker: publish {}: {}",
                path.display(),
                e.message()
            ))
        })
    });
    if result.is_err() {
        let _ = durable::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::journal::Journal;
    use crate::broker::testutil::TempDir;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    fn fixture() -> (TempDir, SecretBootstrap) {
        let dir = TempDir::new("sb");
        let root = dir.to_path_buf();
        let backend = ProtectedFileBackend::new(root.join("protected"));
        let signing = std::sync::Arc::new(SigningService::new_persistent(&root).unwrap());
        let journal =
            std::sync::Arc::new(Journal::new(root.join("journal"), signing.clone(), None));
        let sb = SecretBootstrap::new(root.clone(), backend, journal, signing).unwrap();
        (dir, sb)
    }

    fn handoff_req(
        sb: &SecretBootstrap,
        binding_id: SecretBindingId,
        fencing_token: u64,
        peer_pid: i32,
    ) -> HandoffRequest {
        let mut req = HandoffRequest {
            binding_id,
            peer_uid: 0,
            peer_pid,
            operation_id: OperationId::new(),
            receipt_id: HandoffReceiptId::new(),
            receipt_hmac: String::new(),
            fencing_token,
            purpose: Purpose::MinioRoot,
            service: "minio".to_owned(),
            target: "/run/secrets/minio-root-password".to_owned(),
            uid: 1000,
            gid: 1000,
        };
        req.receipt_hmac = sb.compute_receipt_hmac(&req);
        req
    }

    #[test]
    fn adopt_first_boot_mints_generation_and_binding() {
        let (_dir, sb) = fixture();
        let req = AdoptRequest {
            instance_id: "inst-1".to_owned(),
            purpose: Purpose::MinioRoot,
            legacy_generation_id: None,
            operation_id: OperationId::new(),
            fencing_token: 7,
        };
        let (binding, outcome) = sb.adopt_b03(&req).unwrap();
        assert_eq!(outcome, BootstrapOutcome::Adopted);
        assert_eq!(binding.purpose, Purpose::MinioRoot);
        // Repeat adoption is idempotent and refreshes the fence (SC-DEF-18).
        let mut req2 = req.clone();
        req2.operation_id = OperationId::new();
        req2.fencing_token = 9;
        let (binding2, outcome2) = sb.adopt_b03(&req2).unwrap();
        assert_eq!(outcome2, BootstrapOutcome::AlreadyAdopted);
        assert_eq!(binding.binding_id, binding2.binding_id);
    }

    #[test]
    fn adopt_lease_uses_caller_fencing_token() {
        let (_dir, sb) = fixture();
        let req = AdoptRequest {
            instance_id: "inst-2".to_owned(),
            purpose: Purpose::MinioRoot,
            legacy_generation_id: None,
            operation_id: OperationId::new(),
            fencing_token: 42,
        };
        let (binding, _) = sb.adopt_b03(&req).unwrap();
        // Materialize with the wrong fence refuses.
        let req_bad = handoff_req(&sb, binding.binding_id, 1, 1234);
        assert!(sb.validate_materialize_request(&req_bad).is_err());
        // Correct fence validates and persists operation+receipt.
        let req_ok = handoff_req(&sb, binding.binding_id, 42, 1234);
        let (receipt, op) = sb.validate_materialize_request(&req_ok).unwrap();
        assert_eq!(receipt.state, HandoffReceiptState::Issued);
        let op = op.unwrap();
        assert_eq!(op.state, HandoffOperationState::Issued);
    }

    #[test]
    fn materialize_rejects_replayed_and_expired() {
        let (_dir, sb) = fixture();
        let req = AdoptRequest {
            instance_id: "inst-3".to_owned(),
            purpose: Purpose::MinioRoot,
            legacy_generation_id: None,
            operation_id: OperationId::new(),
            fencing_token: 5,
        };
        let (binding, _) = sb.adopt_b03(&req).unwrap();
        let req_ok = handoff_req(&sb, binding.binding_id, 5, 77);
        let (_, op) = sb.validate_materialize_request(&req_ok).unwrap();
        let op = op.unwrap();
        // Walk the state machine to acknowledged.
        sb.start_reserved(op.operation_id).unwrap();
        sb.start_write(op.operation_id).unwrap();
        sb.complete_broker_write(op.operation_id).unwrap();
        sb.confirm_helper_acknowledged(op.operation_id).unwrap();
        sb.acknowledge_materialization(op.operation_id).unwrap();
        // Replay of the same receipt now denies as consumed.
        let replay = handoff_req(&sb, binding.binding_id, 5, 77);
        let mut replayed = replay;
        replayed.receipt_id = req_ok.receipt_id;
        replayed.operation_id = req_ok.operation_id;
        replayed.receipt_hmac = sb.compute_receipt_hmac(&replayed);
        let err = sb.validate_materialize_request(&replayed).unwrap_err();
        assert_eq!(err.code(), codes::RECEIPT_CONSUMED);
    }

    #[test]
    fn lifecycle_proof_issue_verify_and_reuse() {
        let (_dir, sb) = fixture();
        let op_id = OperationId::new();
        let (proof, created) = sb
            .issue_lifecycle_proof(
                "inst-4", op_id, "lock-1", "fp", "receipt", 9, "stopped", "mount", "bind",
            )
            .unwrap();
        assert!(created);
        // Same (operation, instance, lock) returns the existing proof.
        let (again, created2) = sb
            .issue_lifecycle_proof(
                "inst-4", op_id, "lock-1", "fp", "receipt", 9, "stopped", "mount", "bind",
            )
            .unwrap();
        assert!(!created2);
        assert_eq!(again.proof_id, proof.proof_id);
        // Verify accepts exact evidence within expiry.
        sb.verify_lifecycle_proof(
            "inst-4",
            9,
            "stopped",
            "mount",
            "bind",
            now() + time::Duration::minutes(1),
        )
        .unwrap();
        // Wrong token refuses.
        assert!(
            sb.verify_lifecycle_proof(
                "inst-4",
                9,
                "WRONG",
                "mount",
                "bind",
                now() + time::Duration::minutes(1),
            )
            .is_err()
        );
        // Caller's evidence-expiry already past refuses outright.
        assert!(
            sb.verify_lifecycle_proof(
                "inst-4",
                9,
                "stopped",
                "mount",
                "bind",
                now() - time::Duration::seconds(1),
            )
            .is_err()
        );
    }

    #[test]
    fn restart_recovers_leases_receipts_and_proofs() {
        let dir = TempDir::new("sb-restart");
        let root = dir.to_path_buf();
        let (binding_id, receipt_id, proof_id);
        {
            let backend = ProtectedFileBackend::new(root.join("protected"));
            let signing = std::sync::Arc::new(SigningService::new_persistent(&root).unwrap());
            let journal =
                std::sync::Arc::new(Journal::new(root.join("journal"), signing.clone(), None));
            let sb = SecretBootstrap::new(root.clone(), backend, journal, signing).unwrap();
            let req = AdoptRequest {
                instance_id: "inst-5".to_owned(),
                purpose: Purpose::MinioRoot,
                legacy_generation_id: None,
                operation_id: OperationId::new(),
                fencing_token: 3,
            };
            let (binding, _) = sb.adopt_b03(&req).unwrap();
            binding_id = binding.binding_id;
            let hreq = handoff_req(&sb, binding_id, 3, 99);
            let (receipt, _) = sb.validate_materialize_request(&hreq).unwrap();
            receipt_id = receipt.receipt_id;
            let (proof, _) = sb
                .issue_lifecycle_proof(
                    "inst-5",
                    OperationId::new(),
                    "lock",
                    "",
                    "",
                    3,
                    "s",
                    "m",
                    "b",
                )
                .unwrap();
            proof_id = proof.proof_id;
        }
        let backend = ProtectedFileBackend::new(root.join("protected"));
        let signing = std::sync::Arc::new(SigningService::new_persistent(&root).unwrap());
        let journal =
            std::sync::Arc::new(Journal::new(root.join("journal"), signing.clone(), None));
        let sb2 = SecretBootstrap::new(root.clone(), backend, journal, signing).unwrap();
        let (binding, lease) = sb2.active_binding_for_purpose(Purpose::MinioRoot).unwrap();
        assert_eq!(binding.binding_id, binding_id);
        assert_eq!(lease.fencing_token, 3);
        // Recovered receipt is recognized — replayable HMAC path works.
        let mut hreq2 = handoff_req(&sb2, binding_id, 3, 99);
        hreq2.receipt_id = receipt_id;
        let (receipt2, _) = sb2.validate_materialize_request(&hreq2).unwrap();
        assert_eq!(receipt2.receipt_id, receipt_id);
        // Proof recovered and verifies.
        sb2.verify_lifecycle_proof(
            "inst-5",
            3,
            "s",
            "m",
            "b",
            now() + time::Duration::minutes(1),
        )
        .unwrap();
        assert_eq!(proof_id.to_string().len(), 36);
    }

    #[test]
    fn revoke_invalidates_unconsumed_receipts() {
        let (_dir, sb) = fixture();
        let req = AdoptRequest {
            instance_id: "inst-6".to_owned(),
            purpose: Purpose::MinioRoot,
            legacy_generation_id: None,
            operation_id: OperationId::new(),
            fencing_token: 11,
        };
        let (binding, _) = sb.adopt_b03(&req).unwrap();
        let hreq = handoff_req(&sb, binding.binding_id, 11, 55);
        sb.validate_materialize_request(&hreq).unwrap();
        assert_eq!(
            sb.revoke_binding(binding.binding_id).unwrap(),
            BootstrapOutcome::Revoked
        );
        // Materialization after revoke: no active lease.
        let hreq2 = handoff_req(&sb, binding.binding_id, 11, 55);
        assert!(sb.validate_materialize_request(&hreq2).is_err());
        // Tombstone survives restart: the lease stays revoked.
        let dir_root = sb.root_path.clone();
        let backend = ProtectedFileBackend::new(dir_root.join("protected"));
        let signing = std::sync::Arc::new(SigningService::new_persistent(&dir_root).unwrap());
        let journal = std::sync::Arc::new(Journal::new(
            dir_root.join("journal"),
            signing.clone(),
            None,
        ));
        let sb2 = SecretBootstrap::new(dir_root, backend, journal, signing).unwrap();
        assert!(sb2.active_binding_for_purpose(Purpose::MinioRoot).is_err());
    }

    #[test]
    fn delete_binding_requires_fencing_match() {
        let (_dir, sb) = fixture();
        let req = AdoptRequest {
            instance_id: "inst-7".to_owned(),
            purpose: Purpose::MinioRoot,
            legacy_generation_id: None,
            operation_id: OperationId::new(),
            fencing_token: 21,
        };
        let (binding, _) = sb.adopt_b03(&req).unwrap();
        let err = sb.delete_binding(binding.binding_id, 22).unwrap_err();
        assert_eq!(err.code(), codes::FENCING_CONFLICT);
        assert_eq!(
            sb.delete_binding(binding.binding_id, 21).unwrap(),
            BootstrapOutcome::Deleted
        );
    }

    #[test]
    fn bind_materialized_secret_rotates_prior_binding() {
        let (_dir, sb) = fixture();
        let first = sb
            .bind_materialized_secret(
                Purpose::PostgresRuntime,
                "inst-8",
                b"pgpass-v1\n",
                time::Duration::hours(1),
            )
            .unwrap();
        let second = sb
            .bind_materialized_secret(
                Purpose::PostgresRuntime,
                "inst-8",
                b"pgpass-v2\n",
                time::Duration::hours(1),
            )
            .unwrap();
        assert_ne!(first, second);
        // Exactly one active binding survives.
        let (binding, lease) = sb
            .active_binding_for_purpose(Purpose::PostgresRuntime)
            .unwrap();
        assert_eq!(binding.binding_id, second);
        assert!(lease.expires_at > now());
        // Non-materializable purpose refuses.
        assert!(
            sb.bind_materialized_secret(
                Purpose::MinioBackup,
                "inst-8",
                b"x",
                time::Duration::hours(1),
            )
            .is_err()
        );
    }

    #[test]
    fn persisted_records_use_upstream_field_names() {
        let (_dir, sb) = fixture();
        let req = AdoptRequest {
            instance_id: "inst-9".to_owned(),
            purpose: Purpose::MinioRoot,
            legacy_generation_id: None,
            operation_id: OperationId::new(),
            fencing_token: 4,
        };
        let (binding, _) = sb.adopt_b03(&req).unwrap();
        let hreq = handoff_req(&sb, binding.binding_id, 4, 12);
        sb.validate_materialize_request(&hreq).unwrap();
        // Receipt record: PascalCase.
        let receipt_path = sb
            .binding_dir(&binding.binding_id)
            .join("receipts")
            .join(format!("{}.json", hreq.receipt_id));
        let text = fs::read_to_string(&receipt_path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert!(v.get("ReceiptID").is_some());
        assert!(v.get("PeerUID").is_some());
        assert!(v.get("receipt_id").is_none());
        assert_eq!(
            fs::metadata(&receipt_path).unwrap().permissions().mode() & 0o777,
            0o400
        );
        // Lease record: snake_case.
        let lease_path = sb.lease_dir().join(format!("{}.json", binding.binding_id));
        let lv: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&lease_path).unwrap()).unwrap();
        assert!(lv.get("binding_id").is_some());
        assert!(lv.get("holder_op_id").is_some());
    }
}
