//! `proof_service.go` — the broker's HMAC-signed one-use proof service:
//! `verified-empty-target-v1` proofs (60 s lifetime) and
//! `reset-confirmation-v1` confirmations (5 minutes), with durable
//! tombstones so a consumed proof stays consumed across a restart.
//!
//! Canonical payloads are upstream `CanonicalPayload()` verbatim — raw
//! field bytes joined by `\n`, HMAC-SHA-256 keyed by the persistent
//! broker fingerprint key under the domain separator. Consumption is a
//! tombstone, not a deletion: the in-memory map is written first, the
//! durable `migration-proof-state.json` + the journal's
//! `migration-proof-consumed` record must commit, and a durable
//! failure rolls the in-memory tombstone back — upstream's exact
//! ordering.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use central_backup::domain::{
    ResetConfirmation, SessionBinding, TargetIdentity, VerifiedEmptyTarget,
};
use central_backup::port::{IssueEmptyTargetProofRequest, IssueResetConfirmationRequest};
use central_foundation::failure::Failure;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use super::durable::{PRIVATE_FILE_MODE, sync_dir};
use super::journal::Journal;
use super::provisioning::{SessionBindingWire, TargetIdentityWire, target_fingerprint};
use super::signing::SigningService;
use super::wire::{b64, format_rfc3339_nano, hmac_equal, is_go_zero_time, rfc3339};

fn denied(msg: impl Into<String>) -> Failure {
    Failure::denied("broker_proof", msg.into())
}
fn internal(msg: impl Into<String>) -> Failure {
    Failure::internal("broker_proof", msg.into())
}

const PROOF_DOMAIN: &str = "verified-empty-target-v1";
const RESET_DOMAIN: &str = "reset-confirmation-v1";
/// `proofLifetime` — 60 s.
pub const PROOF_LIFETIME_SECS: i64 = 60;
/// `resetLifetime` — five minutes.
pub const RESET_LIFETIME_SECS: i64 = 5 * 60;

// ---------------------------------------------------------------------------
// Canonical payloads + wire shapes (internal/backup/migration.go)
// ---------------------------------------------------------------------------

/// `backup.VerifiedEmptyTarget.CanonicalPayload()` — the fields the
/// proof HMAC binds, `\n`-separated, RFC 3339Nano timestamps.
#[must_use]
pub fn verified_empty_target_canonical_payload(p: &VerifiedEmptyTarget) -> Vec<u8> {
    let b = &p.session_binding;
    let lock = |i: usize| b.lock_identities.get(i).map_or("", String::as_str);
    let mut buf = Vec::new();
    let mut field = |bytes: &[u8]| {
        if !buf.is_empty() {
            buf.push(b'\n');
        }
        buf.extend_from_slice(bytes);
    };
    field(p.operation_id.to_string().as_bytes());
    field(p.empty_fingerprint.as_bytes());
    field(p.baseline_digest.as_bytes());
    field(b.backend_pid.to_string().as_bytes());
    field(b.backend_start.as_bytes());
    field(b.boot_id.as_bytes());
    field(lock(0).as_bytes());
    field(lock(1).as_bytes());
    field(lock(2).as_bytes());
    field(format_rfc3339_nano(p.issued_at).as_bytes());
    field(format_rfc3339_nano(p.expires_at).as_bytes());
    buf
}

/// `backup.ResetConfirmation.CanonicalPayload()`.
#[must_use]
pub fn reset_confirmation_canonical_payload(c: &ResetConfirmation) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut field = |bytes: &[u8]| {
        if !buf.is_empty() {
            buf.push(b'\n');
        }
        buf.extend_from_slice(bytes);
    };
    field(c.operation_id.to_string().as_bytes());
    field(c.target_fingerprint.as_bytes());
    field(&c.nonce);
    field(format_rfc3339_nano(c.expires_at).as_bytes());
    buf
}

/// `VerifiedEmptyTarget.IsExpired` — a zero or past expiry is expired.
#[must_use]
pub fn proof_expired(expires_at: OffsetDateTime) -> bool {
    is_go_zero_time(expires_at) || OffsetDateTime::now_utc() > expires_at
}

/// Wire form of `backup.VerifiedEmptyTarget` (PascalCase, `nonce`→none).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerifiedEmptyTargetWire {
    /// `OperationID`.
    #[serde(rename = "OperationID")]
    pub operation_id: Uuid,
    /// `SessionBinding`.
    #[serde(rename = "SessionBinding")]
    pub session_binding: SessionBindingWire,
    /// `EmptyFingerprint`.
    #[serde(rename = "EmptyFingerprint")]
    pub empty_fingerprint: String,
    /// `BaselineDigest`.
    #[serde(rename = "BaselineDigest")]
    pub baseline_digest: String,
    /// `IssuedAt`.
    #[serde(rename = "IssuedAt", with = "rfc3339")]
    pub issued_at: OffsetDateTime,
    /// `ExpiresAt`.
    #[serde(rename = "ExpiresAt", with = "rfc3339")]
    pub expires_at: OffsetDateTime,
    /// `HMAC`.
    #[serde(rename = "HMAC")]
    pub hmac: String,
}

impl From<&VerifiedEmptyTarget> for VerifiedEmptyTargetWire {
    fn from(p: &VerifiedEmptyTarget) -> Self {
        Self {
            operation_id: p.operation_id,
            session_binding: SessionBindingWire::from(&p.session_binding),
            empty_fingerprint: p.empty_fingerprint.clone(),
            baseline_digest: p.baseline_digest.clone(),
            issued_at: p.issued_at,
            expires_at: p.expires_at,
            hmac: p.hmac.clone(),
        }
    }
}

impl From<&VerifiedEmptyTargetWire> for VerifiedEmptyTarget {
    fn from(p: &VerifiedEmptyTargetWire) -> Self {
        Self {
            operation_id: p.operation_id,
            session_binding: SessionBinding::from(&p.session_binding),
            empty_fingerprint: p.empty_fingerprint.clone(),
            baseline_digest: p.baseline_digest.clone(),
            issued_at: p.issued_at,
            expires_at: p.expires_at,
            hmac: p.hmac.clone(),
        }
    }
}

/// Wire form of `backup.ResetConfirmation` (PascalCase; `Nonce` is a
/// Go `[]byte` → standard base64).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResetConfirmationWire {
    /// `OperationID`.
    #[serde(rename = "OperationID")]
    pub operation_id: Uuid,
    /// `TargetFingerprint`.
    #[serde(rename = "TargetFingerprint")]
    pub target_fingerprint: String,
    /// `Nonce` — Go `[]byte` encodes as standard base64, `null` as nil.
    #[serde(rename = "Nonce", with = "b64")]
    pub nonce: Vec<u8>,
    /// `ExpiresAt`.
    #[serde(rename = "ExpiresAt", with = "rfc3339")]
    pub expires_at: OffsetDateTime,
    /// `HMAC`.
    #[serde(rename = "HMAC")]
    pub hmac: String,
}

impl From<&ResetConfirmation> for ResetConfirmationWire {
    fn from(c: &ResetConfirmation) -> Self {
        Self {
            operation_id: c.operation_id,
            target_fingerprint: c.target_fingerprint.clone(),
            nonce: c.nonce.clone(),
            expires_at: c.expires_at,
            hmac: c.hmac.clone(),
        }
    }
}

impl From<&ResetConfirmationWire> for ResetConfirmation {
    fn from(c: &ResetConfirmationWire) -> Self {
        Self {
            operation_id: c.operation_id,
            target_fingerprint: c.target_fingerprint.clone(),
            nonce: c.nonce.clone(),
            expires_at: c.expires_at,
            hmac: c.hmac.clone(),
        }
    }
}

/// `port.IssueEmptyTargetProofRequest` wire form (PascalCase).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IssueEmptyTargetProofRequestWire {
    /// `OperationID`.
    #[serde(rename = "OperationID")]
    pub operation_id: Uuid,
    /// `Target`.
    #[serde(rename = "Target")]
    pub target: TargetIdentityWire,
    /// `SessionBinding`.
    #[serde(rename = "SessionBinding")]
    pub session_binding: SessionBindingWire,
    /// `BaselineDigest`.
    #[serde(rename = "BaselineDigest")]
    pub baseline_digest: String,
}

/// `port.IssueResetConfirmationRequest` wire form (PascalCase).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IssueResetConfirmationRequestWire {
    /// `OperationID`.
    #[serde(rename = "OperationID")]
    pub operation_id: Uuid,
    /// `TargetFingerprint`.
    #[serde(rename = "TargetFingerprint")]
    pub target_fingerprint: String,
}

// ---------------------------------------------------------------------------
// ProofService
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Serialize, Deserialize)]
struct ProofState {
    #[serde(default)]
    consumed: BTreeMap<String, OffsetDateTime>,
    #[serde(default)]
    reset_used: BTreeMap<String, OffsetDateTime>,
}

/// `ProofService` — HMAC issuance/verification plus the durable
/// tombstone pair. `state_path`/`journal` are `None` for the
/// [`new_proof_service`] in-memory construction upstream keeps for
/// tests.
pub struct ProofService {
    signing: SigningService,
    inner: Mutex<ProofState>,
    state_path: Option<PathBuf>,
    journal: Option<std::sync::Arc<Journal>>,
}

/// `NewProofService` — memory-only tombstones (upstream's test seam).
#[must_use]
pub fn new_proof_service(signing: SigningService) -> ProofService {
    ProofService {
        signing,
        inner: Mutex::new(ProofState::default()),
        state_path: None,
        journal: None,
    }
}

/// `newPersistentProofService` — restore tombstones from protected
/// broker state; the persistent HMAC key keeps proofs verifiable across
/// a restart while consumed proofs stay refused.
///
/// # Errors
/// `broker_proof` on load/decode failure; absent state file is empty.
pub fn new_persistent_proof_service(
    root_path: &std::path::Path,
    signing: SigningService,
    journal: Option<std::sync::Arc<Journal>>,
) -> Result<ProofService, Failure> {
    let state_path = root_path.join("migration-proof-state.json");
    let mut state = ProofState::default();
    match fs::read(&state_path) {
        Ok(data) => {
            #[derive(Deserialize)]
            struct Stored {
                #[serde(default, with = "super::wire::rfc3339_map")]
                consumed: BTreeMap<String, OffsetDateTime>,
                #[serde(default, rename = "reset_used", with = "super::wire::rfc3339_map")]
                reset_used: BTreeMap<String, OffsetDateTime>,
            }
            let stored: Stored = serde_json::from_slice(&data)
                .map_err(|e| internal(format!("decode migration proof state: {e}")))?;
            state.consumed = stored.consumed;
            state.reset_used = stored.reset_used;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(internal(format!("load migration proof state: {e}"))),
    }
    Ok(ProofService {
        signing,
        inner: Mutex::new(state),
        state_path: Some(state_path),
        journal,
    })
}

fn empty_fingerprint(t: &TargetIdentity) -> String {
    format!(
        "{}:{}:{}:{}:{}",
        t.system_id, t.database_oid, t.database, t.config_hash, t.epoch
    )
}

impl ProofService {
    fn lock(&self) -> Result<MutexGuard<'_, ProofState>, Failure> {
        self.inner
            .lock()
            .map_err(|_| internal("proof state lock poisoned"))
    }

    /// `persistLocked` — journal `migration-proof-consumed`, then
    /// `migration-proof-state.json` via tmp+fsync+rename, then dir
    /// sync. Called with the tombstone map already mutated; failure
    /// rolls the in-memory entry back at the call site.
    fn persist_locked(
        &self,
        state: &ProofState,
        operation: &str,
        kind: &str,
    ) -> Result<(), Failure> {
        let Some(state_path) = &self.state_path else {
            return Ok(());
        };
        if let Some(journal) = &self.journal {
            let payload = serde_json::to_vec(&serde_json::json!({
                "operation_id": operation,
                "kind": kind,
            }))
            .map_err(|e| internal(format!("marshal proof journal payload: {e}")))?;
            // `json.RawMessage` passthrough — hash and persist the same
            // bytes that were marshaled, never a `Value` re-encoding.
            let raw_payload: Box<serde_json::value::RawValue> = serde_json::from_slice(&payload)
                .map_err(|e| internal(format!("marshal proof journal payload: {e}")))?;
            let mut record = central_infra::authority::AuthorityTransitionPayload {
                schema_version: "central.authority-transition/v1".into(),
                stream_id: String::new(),
                sequence_num: 0,
                phase: String::new(),
                operation: "migration-proof-consumed".into(),
                instance_id: String::new(),
                binding_id: String::new(),
                launch_id: String::new(),
                nonce: String::new(),
                payload: Some(raw_payload),
                payload_digest: String::new(),
                payload_bytes: 0,
                prior_digest: String::new(),
                broker_key_ver: String::new(),
                hmac: String::new(),
                signature: String::new(),
                signed_at: String::new(),
            };
            journal
                .append_committed(&format!("migration-proof-{operation}"), &mut record)
                .map_err(|e| internal(format!("journal proof consumption: {}", e.message())))?;
        }
        #[derive(Serialize)]
        struct Stored {
            #[serde(with = "super::wire::rfc3339_map")]
            consumed: BTreeMap<String, OffsetDateTime>,
            #[serde(with = "super::wire::rfc3339_map")]
            reset_used: BTreeMap<String, OffsetDateTime>,
        }
        let data = serde_json::to_vec(&Stored {
            consumed: state.consumed.clone(),
            reset_used: state.reset_used.clone(),
        })
        .map_err(|e| internal(format!("marshal proof state: {e}")))?;
        let tmp = state_path.with_extension("json.tmp");
        {
            use std::io::Write as _;
            use std::os::unix::fs::OpenOptionsExt as _;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(PRIVATE_FILE_MODE)
                .custom_flags(libc::O_CLOEXEC)
                .open(&tmp)
                .map_err(|e| internal(format!("write proof state tmp: {e}")))?;
            file.write_all(&data)
                .and_then(|()| file.sync_all())
                .map_err(|e| {
                    let _ = fs::remove_file(&tmp);
                    internal(format!("sync proof state tmp: {e}"))
                })?;
        }
        fs::rename(&tmp, state_path).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            internal(format!("rename proof state: {e}"))
        })?;
        sync_dir(
            state_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new(".")),
        )
    }

    /// `IssueEmptyTargetProof` — bind operation, target fingerprint,
    /// session binding, and baseline digest under one HMAC; the proof
    /// expires [`PROOF_LIFETIME_SECS`] after issuance.
    ///
    /// # Errors
    /// `broker_proof` — none currently; the signature never fails. Kept
    /// as `Result` for port parity.
    pub fn issue_empty_target_proof(
        &self,
        req: &IssueEmptyTargetProofRequest,
    ) -> Result<VerifiedEmptyTarget, Failure> {
        let now = OffsetDateTime::now_utc();
        let mut proof = VerifiedEmptyTarget {
            operation_id: req.operation_id,
            session_binding: req.session_binding.clone(),
            empty_fingerprint: empty_fingerprint(&req.target),
            baseline_digest: req.baseline_digest.clone(),
            issued_at: now,
            expires_at: now + time::Duration::seconds(PROOF_LIFETIME_SECS),
            hmac: String::new(),
        };
        proof.hmac = self.signing.fingerprint(
            PROOF_DOMAIN,
            &verified_empty_target_canonical_payload(&proof),
        );
        Ok(proof)
    }

    /// `VerifyEmptyTarget` — not expired, not tombstoned, fingerprint
    /// matches the presented target, HMAC valid.
    ///
    /// # Errors
    /// `broker_proof` denied on every verification failure.
    pub fn verify_empty_target(
        &self,
        target: &TargetIdentity,
        proof: &VerifiedEmptyTarget,
    ) -> Result<(), Failure> {
        if proof_expired(proof.expires_at) {
            return Err(denied(format!(
                "proof expired (issued {}, expires {})",
                format_rfc3339_nano(proof.issued_at),
                format_rfc3339_nano(proof.expires_at)
            )));
        }
        {
            let state = self.lock()?;
            if state.consumed.contains_key(&proof.operation_id.to_string()) {
                return Err(denied(format!(
                    "proof already consumed for operation {}",
                    proof.operation_id
                )));
            }
        }
        let expected_fingerprint = empty_fingerprint(target);
        if proof.empty_fingerprint != expected_fingerprint {
            return Err(denied(format!(
                "proof fingerprint mismatch: expected {expected_fingerprint}, got {}",
                proof.empty_fingerprint
            )));
        }
        let expected = self.signing.fingerprint(
            PROOF_DOMAIN,
            &verified_empty_target_canonical_payload(proof),
        );
        if !hmac_equal(proof.hmac.as_bytes(), expected.as_bytes()) {
            return Err(denied(format!(
                "proof HMAC verification failed for operation {}",
                proof.operation_id
            )));
        }
        Ok(())
    }

    /// `ConsumeEmptyProof` — tombstone the operation id (no target
    /// check).
    ///
    /// # Errors
    /// `broker_proof` — expired, replayed, bad HMAC, or a durable
    /// persistence failure (which rolls the tombstone back).
    pub fn consume_empty_proof(&self, proof: &VerifiedEmptyTarget) -> Result<(), Failure> {
        let mut state = self.lock()?;
        let op_id = proof.operation_id.to_string();
        if proof_expired(proof.expires_at) {
            return Err(denied("proof expired"));
        }
        if state.consumed.contains_key(&op_id) {
            return Err(denied(format!(
                "proof already consumed for operation {op_id}"
            )));
        }
        let expected = self.signing.fingerprint(
            PROOF_DOMAIN,
            &verified_empty_target_canonical_payload(proof),
        );
        if !hmac_equal(proof.hmac.as_bytes(), expected.as_bytes()) {
            return Err(denied(format!(
                "proof HMAC verification failed for operation {op_id}"
            )));
        }
        state
            .consumed
            .insert(op_id.clone(), OffsetDateTime::now_utc());
        if let Err(e) = self.persist_locked(&state, &op_id, "empty_target") {
            state.consumed.remove(&op_id);
            return Err(e);
        }
        Ok(())
    }

    /// `ConsumeVerifiedEmptyTarget` — validate against the presented
    /// target, then tombstone atomically.
    ///
    /// # Errors
    /// `broker_proof` — expired, replayed, fingerprint/HMAC mismatch,
    /// or persistence failure (rolled back).
    pub fn consume_verified_empty_target(
        &self,
        target: &TargetIdentity,
        proof: &VerifiedEmptyTarget,
    ) -> Result<(), Failure> {
        let mut state = self.lock()?;
        if proof_expired(proof.expires_at) {
            return Err(denied("proof expired"));
        }
        if state.consumed.contains_key(&proof.operation_id.to_string()) {
            return Err(denied(format!(
                "proof already consumed for operation {}",
                proof.operation_id
            )));
        }
        if proof.empty_fingerprint != empty_fingerprint(target) {
            return Err(denied("proof fingerprint mismatch"));
        }
        let expected = self.signing.fingerprint(
            PROOF_DOMAIN,
            &verified_empty_target_canonical_payload(proof),
        );
        if !hmac_equal(proof.hmac.as_bytes(), expected.as_bytes()) {
            return Err(denied(format!(
                "proof HMAC verification failed for operation {}",
                proof.operation_id
            )));
        }
        let op_id = proof.operation_id.to_string();
        state
            .consumed
            .insert(op_id.clone(), OffsetDateTime::now_utc());
        if let Err(e) = self.persist_locked(&state, &op_id, "empty_target") {
            state.consumed.remove(&op_id);
            return Err(e);
        }
        Ok(())
    }

    /// `IssueResetConfirmation` — random 32-byte nonce,
    /// [`RESET_LIFETIME_SECS`] expiry, HMAC bound.
    ///
    /// # Errors
    /// `broker_proof` on entropy failure.
    pub fn issue_reset_confirmation(
        &self,
        req: &IssueResetConfirmationRequest,
    ) -> Result<ResetConfirmation, Failure> {
        let mut nonce = vec![0u8; 32];
        let mut filled = 0usize;
        while filled < nonce.len() {
            filled += rustix::rand::getrandom(
                &mut nonce[filled..],
                rustix::rand::GetRandomFlags::empty(),
            )
            .map_err(|e| internal(format!("issue reset confirmation: nonce: {e}")))?;
        }
        let now = OffsetDateTime::now_utc();
        let mut confirmation = ResetConfirmation {
            operation_id: req.operation_id,
            target_fingerprint: req.target_fingerprint.clone(),
            nonce,
            expires_at: now + time::Duration::seconds(RESET_LIFETIME_SECS),
            hmac: String::new(),
        };
        confirmation.hmac = self.signing.fingerprint(
            RESET_DOMAIN,
            &reset_confirmation_canonical_payload(&confirmation),
        );
        Ok(confirmation)
    }

    /// `VerifyResetConfirmation` — not expired, not used, HMAC valid.
    ///
    /// # Errors
    /// `broker_proof` denied on every verification failure.
    pub fn verify_reset_confirmation(
        &self,
        confirmation: &ResetConfirmation,
    ) -> Result<(), Failure> {
        if proof_expired(confirmation.expires_at) {
            return Err(denied(format!(
                "reset confirmation expired (expires {})",
                format_rfc3339_nano(confirmation.expires_at)
            )));
        }
        {
            let state = self.lock()?;
            if state
                .reset_used
                .contains_key(&confirmation.operation_id.to_string())
            {
                return Err(denied(format!(
                    "reset confirmation already consumed for operation {}",
                    confirmation.operation_id
                )));
            }
        }
        let expected = self.signing.fingerprint(
            RESET_DOMAIN,
            &reset_confirmation_canonical_payload(confirmation),
        );
        if !hmac_equal(confirmation.hmac.as_bytes(), expected.as_bytes()) {
            return Err(denied(format!(
                "reset confirmation HMAC verification failed for operation {}",
                confirmation.operation_id
            )));
        }
        Ok(())
    }

    /// `ConsumeResetConfirmation` — tombstone the confirmation.
    ///
    /// # Errors
    /// `broker_proof` — expired, replayed, bad HMAC, or persistence
    /// failure (rolled back).
    pub fn consume_reset_confirmation(
        &self,
        confirmation: &ResetConfirmation,
    ) -> Result<(), Failure> {
        let mut state = self.lock()?;
        let op_id = confirmation.operation_id.to_string();
        if proof_expired(confirmation.expires_at) {
            return Err(denied("reset confirmation expired"));
        }
        if state.reset_used.contains_key(&op_id) {
            return Err(denied(format!(
                "reset confirmation already consumed for operation {op_id}"
            )));
        }
        let expected = self.signing.fingerprint(
            RESET_DOMAIN,
            &reset_confirmation_canonical_payload(confirmation),
        );
        if !hmac_equal(confirmation.hmac.as_bytes(), expected.as_bytes()) {
            return Err(denied(format!(
                "reset confirmation HMAC verification failed for operation {op_id}"
            )));
        }
        state
            .reset_used
            .insert(op_id.clone(), OffsetDateTime::now_utc());
        if let Err(e) = self.persist_locked(&state, &op_id, "reset_confirmation") {
            state.reset_used.remove(&op_id);
            return Err(e);
        }
        Ok(())
    }

    /// `ConsumeVerifiedResetConfirmation` — target-bound consumption.
    ///
    /// # Errors
    /// `broker_proof` — expired, replayed, target/HMAC mismatch, or
    /// persistence failure (rolled back).
    pub fn consume_verified_reset_confirmation(
        &self,
        target: &TargetIdentity,
        confirmation: &ResetConfirmation,
    ) -> Result<(), Failure> {
        let mut state = self.lock()?;
        if proof_expired(confirmation.expires_at) {
            return Err(denied("reset confirmation expired"));
        }
        if state
            .reset_used
            .contains_key(&confirmation.operation_id.to_string())
        {
            return Err(denied(format!(
                "reset confirmation already consumed for operation {}",
                confirmation.operation_id
            )));
        }
        if confirmation.target_fingerprint != target_fingerprint(target) {
            return Err(denied("reset confirmation target mismatch"));
        }
        let expected = self.signing.fingerprint(
            RESET_DOMAIN,
            &reset_confirmation_canonical_payload(confirmation),
        );
        if !hmac_equal(confirmation.hmac.as_bytes(), expected.as_bytes()) {
            return Err(denied(format!(
                "reset confirmation HMAC verification failed for operation {}",
                confirmation.operation_id
            )));
        }
        let op_id = confirmation.operation_id.to_string();
        state
            .reset_used
            .insert(op_id.clone(), OffsetDateTime::now_utc());
        if let Err(e) = self.persist_locked(&state, &op_id, "reset_confirmation") {
            state.reset_used.remove(&op_id);
            return Err(e);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests — upstream `proof_service.go` lifecycle coverage, ported.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::testutil::TempDir;
    use std::sync::Arc;

    fn target() -> TargetIdentity {
        TargetIdentity {
            system_id: "sys-1".into(),
            database_oid: "16384".into(),
            database: "central".into(),
            config_hash: "cfg".into(),
            epoch: 1,
        }
    }

    fn binding() -> SessionBinding {
        SessionBinding {
            backend_pid: 4242,
            backend_start: "2026-01-01 00:00:00".into(),
            boot_id: "boot".into(),
            lock_identities: vec!["a".into(), "b".into(), "c".into()],
        }
    }

    fn issue_req(op: Uuid) -> IssueEmptyTargetProofRequest {
        IssueEmptyTargetProofRequest {
            operation_id: op,
            target: target(),
            session_binding: binding(),
            baseline_digest: "sha256:base".into(),
        }
    }

    #[test]
    fn empty_proof_issue_verify_consume() {
        let svc = new_proof_service(SigningService::new());
        let proof = svc
            .issue_empty_target_proof(&issue_req(Uuid::now_v7()))
            .unwrap();
        assert!(!proof.hmac.is_empty());
        svc.verify_empty_target(&target(), &proof).unwrap();
        svc.consume_verified_empty_target(&target(), &proof)
            .unwrap();
        // Tombstoned: both verify and consume deny on replay.
        assert!(svc.verify_empty_target(&target(), &proof).is_err());
        assert!(svc.consume_empty_proof(&proof).is_err());
    }

    #[test]
    fn proof_rejects_tampered_hmac_and_fingerprint_mismatch() {
        let svc = new_proof_service(SigningService::new());
        let proof = svc
            .issue_empty_target_proof(&issue_req(Uuid::now_v7()))
            .unwrap();
        let mut bad = proof.clone();
        bad.baseline_digest = "forged".into();
        assert!(svc.verify_empty_target(&target(), &bad).is_err());
        let mut other = target();
        other.database = "elsewhere".into();
        assert!(svc.verify_empty_target(&other, &proof).is_err());
    }

    #[test]
    fn expired_proof_denies() {
        let svc = new_proof_service(SigningService::new());
        let mut proof = svc
            .issue_empty_target_proof(&issue_req(Uuid::now_v7()))
            .unwrap();
        proof.expires_at = OffsetDateTime::now_utc() - time::Duration::seconds(1);
        // Re-sign so the only failure is expiry.
        proof.hmac = svc.signing.fingerprint(
            PROOF_DOMAIN,
            &verified_empty_target_canonical_payload(&proof),
        );
        assert!(svc.verify_empty_target(&target(), &proof).is_err());
        assert!(svc.consume_empty_proof(&proof).is_err());
    }

    #[test]
    fn consumed_tombstone_survives_restart() {
        let dir = TempDir::new("proof");
        let op = Uuid::now_v7();
        {
            let svc = new_persistent_proof_service(&dir, SigningService::new(), None).unwrap();
            let proof = svc.issue_empty_target_proof(&issue_req(op)).unwrap();
            svc.consume_empty_proof(&proof).unwrap();
        }
        // A reopened store refuses the consumed operation even though
        // the persistent HMAC key still verifies the proof itself.
        let svc = new_persistent_proof_service(&dir, SigningService::new(), None).unwrap();
        let proof = svc.issue_empty_target_proof(&issue_req(op)).unwrap();
        assert!(svc.verify_empty_target(&target(), &proof).is_err());
    }

    #[test]
    fn reset_confirmation_issue_verify_consume() {
        let svc = new_proof_service(SigningService::new());
        let op = Uuid::now_v7();
        let confirmation = svc
            .issue_reset_confirmation(&IssueResetConfirmationRequest {
                operation_id: op,
                target_fingerprint: target_fingerprint(&target()),
            })
            .unwrap();
        assert!(!confirmation.hmac.is_empty());
        assert_eq!(confirmation.nonce.len(), 32);
        svc.verify_reset_confirmation(&confirmation).unwrap();
        svc.consume_verified_reset_confirmation(&target(), &confirmation)
            .unwrap();
        assert!(svc.verify_reset_confirmation(&confirmation).is_err());
        // A reset nonce binds the target fingerprint — another target
        // denies even while the confirmation is fresh.
        let c2 = svc
            .issue_reset_confirmation(&IssueResetConfirmationRequest {
                operation_id: Uuid::now_v7(),
                target_fingerprint: target_fingerprint(&target()),
            })
            .unwrap();
        let mut other = target();
        other.database = "other".into();
        assert!(
            svc.consume_verified_reset_confirmation(&other, &c2)
                .is_err()
        );
    }

    #[test]
    fn journal_backed_consume_records_transition() {
        let dir = TempDir::new("proof");
        let journal = Arc::new(Journal::new(
            dir.to_path_buf(),
            Arc::new(SigningService::new()),
            None,
        ));
        let svc = new_persistent_proof_service(&dir, SigningService::new(), Some(journal)).unwrap();
        let proof = svc
            .issue_empty_target_proof(&issue_req(Uuid::now_v7()))
            .unwrap();
        svc.consume_empty_proof(&proof).unwrap();
        // The durable tombstone committed through the journal stream.
        let stream = format!("migration-proof-{}", proof.operation_id);
        assert!(dir.join("authority-records").join(stream).exists());
    }
}
