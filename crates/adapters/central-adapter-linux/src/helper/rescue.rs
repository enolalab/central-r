//! `rescue.go` — D06: the deny-safe escape path. No-op when the
//! installed advisory is already current, refusal when denial is not
//! hard-expired, and the ceremony/cleanup/evaluate/exit sequence
//! otherwise. The installed advisory's verdict is a branch, never a
//! gate: rescue is the escape from denial, so gating it on a Current
//! result would deadlock the very instance it exists to save.

use super::audit::{DenySafeState, RescueAttempt, is_deny_safe_active, load_deny_safe};
use super::grant::CeremonyScope;
use super::protocol::*;
use super::{PeerIdentity, verb};
use central_foundation::failure::Failure;
use central_infra::advisory::{self, Code, Outcome, State};
use serde::{Deserialize, Serialize};
use std::time::Instant;

/// `rescuePAMConfirmer` — the D06 ceremony. Rescue re-arms a denied
/// instance, so it carries a full destructive-adjacent ceremony with
/// its own phrase even though it destroys no data. `None` on the
/// handler refuses — upstream's failed type assertion.
pub trait RescuePamConfirmer: Send + Sync {
    fn confirm_security_rescue(
        &self,
        peer: PeerIdentity,
        deadline: Option<Instant>,
        scope: &CeremonyScope,
        operation_id: &str,
    ) -> Result<String, Failure>;
    fn verify_and_consume(&self, token: &str) -> bool;
}

/// `rescueAdvisoryEvaluator` — reports the INSTALLED advisory's state.
pub trait RescueAdvisoryEvaluator: Send + Sync {
    fn evaluate(&self) -> Result<Outcome, Failure>;
}

/// `rescueCandidateEvaluator` — runs B01 over operator-carried
/// candidate bytes without recording or advancing anything.
pub trait RescueCandidateEvaluator: Send + Sync {
    fn evaluate_candidate(&self, candidate: &[u8]) -> Result<Outcome, Failure>;
}

/// `rescueCleanup` — stops services, terminates sandboxes, and drains
/// connections without destroying state. Must be idempotent: a crash
/// between cleanup steps re-runs the whole cleanup on the next
/// attempt.
pub trait RescueCleanup: Send + Sync {
    fn cleanup(&self) -> Result<(), Failure>;
}

/// `RescueRequest` — the operator-carried candidate advisory bytes.
pub struct RescueRequest {
    pub operation_id: String,
    pub candidate: Vec<u8>,
}

/// `RescueResult` — the bounded rescue outcome: identities and state
/// only.
#[derive(Debug, Clone, Default, Serialize)]
pub struct RescueResult {
    pub operation_id: String,
    pub exited: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub already_current: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub resumed_after_crash: bool,
    pub attempts: i64,
    pub completed_at: String,
}

/// `decodeRescueCandidate` — unwraps the base64 candidate and enforces
/// the size bound before any evaluation touches it.
fn decode_rescue_candidate(encoded: &str) -> Result<Vec<u8>, String> {
    let raw = crate::broker::wire::b64_decode(encoded)
        .ok_or_else(|| "helper: invalid rescue candidate".to_owned())?;
    if raw.is_empty() || raw.len() > advisory::MAX_CANDIDATE_ADVISORY_BYTES {
        return Err("helper: rescue candidate size is out of bounds".to_owned());
    }
    Ok(raw)
}

/// `ParseRescueRequest` — rejects unknown fields and bounds the
/// candidate; raw bytes cannot ride the request envelope so the
/// candidate arrives base64 inside the JSON payload.
pub fn parse_rescue_request(req: &Request) -> Result<RescueRequest, String> {
    if req.operation_id.is_empty() {
        return Err("helper: missing rescue operation".to_owned());
    }
    let trimmed = {
        let p = req.payload_bytes();
        let s = p
            .iter()
            .position(|c| !c.is_ascii_whitespace())
            .unwrap_or(p.len());
        let e = p
            .iter()
            .rposition(|c| !c.is_ascii_whitespace())
            .map_or(s, |i| i + 1);
        &p[s..e.max(s)]
    };
    if trimmed.is_empty() {
        return Err("helper: rescue requires a candidate payload".to_owned());
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Payload {
        candidate_base64: String,
    }
    let payload: Payload =
        strict_decode(trimmed).map_err(|e| format!("helper: invalid rescue payload: {e}"))?;
    if payload.candidate_base64.is_empty() {
        return Err("helper: rescue requires a candidate".to_owned());
    }
    Ok(RescueRequest {
        operation_id: req.operation_id.clone(),
        candidate: decode_rescue_candidate(&payload.candidate_base64)?,
    })
}

/// `RescueRoots` pins the deny-safe state hierarchy.
#[derive(Debug, Clone)]
pub struct RescueRoots {
    pub deny_safe_dir: String,
    /// `DenySafeUID`/`DenySafeGID` own the state record (root in
    /// production).
    pub deny_safe_uid: u32,
    pub deny_safe_gid: u32,
}

/// `RescueHandlerImpl` performs D06.
pub struct RescueHandlerImpl {
    pub pam: Option<Box<dyn RescuePamConfirmer>>,
    pub installed: Option<Box<dyn RescueAdvisoryEvaluator>>,
    pub candidate: Option<Box<dyn RescueCandidateEvaluator>>,
    pub cleanup: Option<Box<dyn RescueCleanup>>,
    pub store: Option<crate::infra::advisory_fetch::FileDenySafeStore>,
    pub scope: CeremonyScope,
    pub roots: RescueRoots,
}

/// The transport seam.
pub trait RescueHandler: Send + Sync {
    fn rescue(&self, peer: PeerIdentity, deadline: Instant, request: RescueRequest) -> Response;
}

fn rescue_response(operation_id: &str, outcome: &str, code: i64, reason: &str) -> Response {
    Response::new(operation_id, outcome, code, reason)
}

fn now_rfc3339() -> String {
    super::audit::format_rfc3339nano(time::OffsetDateTime::now_utc())
}

/// `NewRescueAttempt` — mints one attempt record for a candidate
/// evaluation. The digest binds the record to the carried file; the
/// bytes themselves are never stored.
fn new_rescue_attempt(candidate_sha256: &str, outcome: &Outcome) -> Result<RescueAttempt, Failure> {
    Ok(RescueAttempt {
        attempt_id: uuid::Uuid::now_v7().to_string(),
        at: now_rfc3339(),
        candidate_digest_sha256: candidate_sha256.to_owned(),
        result: outcome.state.as_str().to_owned(),
        code: outcome.code.as_str().to_owned(),
    })
}

impl RescueHandler for RescueHandlerImpl {
    /// `Rescue` — upstream ordering verbatim: request and seams, then
    /// the installed verdict branches (current-and-calm no-op,
    /// non-expired refusal, full sequence otherwise).
    fn rescue(&self, peer: PeerIdentity, deadline: Instant, request: RescueRequest) -> Response {
        let op = request.operation_id.as_str();
        let valid_id = uuid::Uuid::parse_str(op).is_ok()
            && uuid::Uuid::parse_str(op)
                .map(|u| u != uuid::Uuid::nil())
                .unwrap_or(false);
        if !valid_id
            || !peer.available()
            || self.pam.is_none()
            || self.installed.is_none()
            || self.candidate.is_none()
            || self.cleanup.is_none()
            || self.store.is_none()
            || self.scope.instance_id.is_empty()
            || self.scope.target_id.is_empty()
            || self.roots.deny_safe_dir.is_empty()
        {
            return rescue_response(op, "denied", 7, advisory::REASON_RESCUE_CEREMONY_REQUIRED);
        }
        if request.candidate.is_empty() {
            return rescue_response(op, "denied", 2, advisory::REASON_RESCUE_INVALID_REQUEST);
        }
        let Some(installed_eval) = &self.installed else {
            return rescue_response(op, "denied", 7, advisory::REASON_RESCUE_UNAVAILABLE);
        };
        let installed = match installed_eval.evaluate() {
            Ok(o) => o,
            Err(_) => {
                return rescue_response(op, "denied", 7, advisory::REASON_RESCUE_UNAVAILABLE);
            }
        };
        let active = is_deny_safe_active(&self.roots.deny_safe_dir);
        if installed.state == State::Current && !active {
            return Response::new(op, "success", 0, "ok").with_result(&RescueResult {
                operation_id: op.to_owned(),
                already_current: true,
                completed_at: now_rfc3339(),
                ..RescueResult::default()
            });
        }
        if installed.state != State::Current && installed.state != State::HardExpired && !active {
            // Denied, stale, or unevaluable without deny-safe active:
            // rescue is the hard-expired escape, not the remedy for
            // these.
            return rescue_response(op, "denied", 7, advisory::REASON_RESCUE_NOT_APPLICABLE);
        }
        self.rescue_from_deny_safe(peer, deadline, request, active)
    }
}

impl RescueHandlerImpl {
    /// `rescueFromDenySafe` — enter (keeping the original entry on
    /// re-entry), ceremony, idempotent cleanup, candidate evaluation,
    /// and — only on a Current candidate — exit.
    fn rescue_from_deny_safe(
        &self,
        peer: PeerIdentity,
        deadline: Instant,
        request: RescueRequest,
        was_active: bool,
    ) -> Response {
        let op = request.operation_id.as_str();
        let mut trigger = Code::HardExpired.as_str().to_owned();
        if was_active && let Ok((state, true)) = load_deny_safe(&self.roots.deny_safe_dir) {
            trigger = state.trigger_code;
        }
        let Some(store) = &self.store else {
            return rescue_response(op, "denied", 7, advisory::REASON_RESCUE_UNAVAILABLE);
        };
        let state = match store.enter_deny_safe(&trigger, time::OffsetDateTime::now_utc()) {
            Ok(s) => s,
            Err(_) => {
                return rescue_response(op, "denied", 7, advisory::REASON_RESCUE_UNAVAILABLE);
            }
        };
        let resumed = was_active && !state.cleanup_done;
        let Some(pam) = &self.pam else {
            return rescue_response(op, "denied", 7, advisory::REASON_RESCUE_CEREMONY_REQUIRED);
        };
        let confirmation = pam
            .confirm_security_rescue(peer, Some(deadline), &self.scope, &request.operation_id)
            .ok()
            .filter(|token| pam.verify_and_consume(token));
        if confirmation.is_none() {
            return rescue_response(op, "denied", 7, advisory::REASON_RESCUE_AUTHORITY_DENIED);
        }
        if !state.cleanup_done {
            let Some(cleanup) = &self.cleanup else {
                return rescue_response(op, "denied", 7, advisory::REASON_RESCUE_CLEANUP_FAILED);
            };
            if cleanup.cleanup().is_err() || store.mark_deny_safe_cleanup_done().is_err() {
                return rescue_response(op, "denied", 7, advisory::REASON_RESCUE_CLEANUP_FAILED);
            }
        }
        let Some(candidate_eval) = &self.candidate else {
            return rescue_response(op, "denied", 7, advisory::REASON_RESCUE_UNAVAILABLE);
        };
        let mut candidate = request.candidate;
        let result = candidate_eval.evaluate_candidate(&candidate);
        let digest = advisory::digest_candidate(&candidate);
        advisory::discard_candidate(&mut candidate);
        let result = match result {
            Ok(r) => r,
            Err(_) => {
                return rescue_response(op, "denied", 7, advisory::REASON_RESCUE_UNAVAILABLE);
            }
        };
        let attempt = match new_rescue_attempt(&digest, &result) {
            Ok(a) => a,
            Err(_) => {
                return rescue_response(op, "denied", 7, advisory::REASON_RESCUE_UNAVAILABLE);
            }
        };
        // Recording failure refuses rather than exiting on an
        // unrecorded evaluation.
        if store.record_deny_safe_attempt(&attempt).is_err() {
            return rescue_response(op, "denied", 7, advisory::REASON_RESCUE_UNAVAILABLE);
        }
        if result.state != State::Current {
            if result.code == Code::Invalid || result.code == Code::SignatureInvalid {
                return rescue_response(op, "denied", 7, advisory::REASON_RESCUE_ADVISORY_INVALID);
            }
            return rescue_response(op, "denied", 7, advisory::REASON_RESCUE_STAYS_DENIED);
        }
        if store
            .exit_deny_safe(time::OffsetDateTime::now_utc())
            .is_err()
        {
            return rescue_response(op, "denied", 7, advisory::REASON_RESCUE_UNAVAILABLE);
        }
        let (completed, _, completed_ok) = match load_deny_safe(&self.roots.deny_safe_dir) {
            Ok((s, f)) => (s, f, true),
            Err(_) => (DenySafeState::default(), false, false),
        };
        if !completed_ok {
            return rescue_response(op, "denied", 7, advisory::REASON_RESCUE_UNAVAILABLE);
        }
        Response::new(op, "success", 0, "ok").with_result(&RescueResult {
            operation_id: op.to_owned(),
            exited: true,
            resumed_after_crash: resumed,
            attempts: completed.rescue_attempts.len() as i64,
            completed_at: now_rfc3339(),
            ..RescueResult::default()
        })
    }
}

// ---------------------------------------------------------------------------
// RescueClient — client_linux.go's linuxRescueClient.
// ---------------------------------------------------------------------------

/// `RescueClientResult` mirrors the helper's `RescueResult` across the
/// socket.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RescueClientResult {
    pub operation_id: String,
    #[serde(default)]
    pub exited: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub already_current: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub resumed_after_crash: bool,
    pub attempts: i64,
    pub completed_at: String,
}

/// `RescueWireReason*` — the closed refusal vocabulary the client
/// retains.
pub const RESCUE_WIRE_REASON_ADVISORY_INVALID: &str = "RESCUE_ADVISORY_INVALID";
pub const RESCUE_WIRE_REASON_STAYS_DENIED: &str = "RESCUE_STAYS_DENIED";
pub const RESCUE_WIRE_REASON_NOT_APPLICABLE: &str = "RESCUE_NOT_APPLICABLE";
pub const RESCUE_WIRE_REASON_CLEANUP_FAILED: &str = "RESCUE_CLEANUP_FAILED";
pub const RESCUE_WIRE_REASON_CEREMONY_REQUIRED: &str = "RESCUE_CEREMONY_REQUIRED";
pub const RESCUE_WIRE_REASON_AUTHORITY_DENIED: &str = "AUTHORITY_DENIED";

/// `RescueClientError` exposes only the stable exit class plus a
/// whitelisted reason token.
#[derive(Debug)]
pub struct RescueClientError {
    exit_code: i64,
    reason: String,
}

impl RescueClientError {
    pub fn exit_code(&self) -> i64 {
        self.exit_code
    }
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl std::fmt::Display for RescueClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "helper: rescue failed")
    }
}
impl std::error::Error for RescueClientError {}

fn retained_rescue_reason(reason: &str) -> String {
    match reason {
        advisory::REASON_DENY_SAFE_ACTIVE
        | RESCUE_WIRE_REASON_ADVISORY_INVALID
        | RESCUE_WIRE_REASON_STAYS_DENIED
        | RESCUE_WIRE_REASON_NOT_APPLICABLE
        | RESCUE_WIRE_REASON_CLEANUP_FAILED
        | RESCUE_WIRE_REASON_CEREMONY_REQUIRED
        | RESCUE_WIRE_REASON_AUTHORITY_DENIED => reason.to_owned(),
        _ => String::new(),
    }
}

fn new_rescue_client_error(exit_code: i64, reason: &str) -> RescueClientError {
    let exit_code = if !(2..=7).contains(&exit_code) {
        6
    } else {
        exit_code
    };
    RescueClientError {
        exit_code,
        reason: retained_rescue_reason(reason),
    }
}

/// `decodeExactRescueResult` — strict decode plus canonical
/// re-encode equality.
fn decode_exact_rescue_result(payload: &[u8]) -> Result<RescueClientResult, String> {
    if payload.is_empty() {
        return Err("helper: rescue result is invalid".to_owned());
    }
    let result: RescueClientResult = strict_decode(payload)?;
    let canonical = serde_json::to_vec(&result)
        .map_err(|_| "helper: rescue result is not canonical".to_owned())?;
    if canonical != payload {
        return Err("helper: rescue result is not canonical".to_owned());
    }
    Ok(result)
}

/// `RescueClient` — `linuxRescueClient`: dials the security-rescue
/// verb.
pub struct RescueClient {
    socket_path: String,
}

impl RescueClient {
    pub fn new(socket_path: impl Into<String>) -> Self {
        RescueClient {
            socket_path: socket_path.into(),
        }
    }

    /// `Rescue` — sends `candidate_base64` and validates the bounded
    /// result: operation id echoes and a complete timestamp.
    ///
    /// # Errors
    /// [`RescueClientError`] — transport failures fold to exit 3, a
    /// non-canonical or mismatched result to exit 6, and helper denials
    /// carry the envelope code plus the whitelisted reason.
    pub fn rescue(
        &self,
        operation_id: &str,
        candidate: &[u8],
    ) -> Result<RescueClientResult, RescueClientError> {
        if self.socket_path.is_empty() || operation_id.is_empty() || candidate.is_empty() {
            return Err(new_rescue_client_error(3, ""));
        }
        let mut conn = super::browser::dial_unix_bounded(
            std::path::Path::new(&self.socket_path),
            super::client::DIAL_TIMEOUT,
        )
        .map_err(|_| new_rescue_client_error(3, ""))?;
        let _ = conn.set_read_timeout(Some(
            super::client::DIAL_TIMEOUT + super::server::RESCUE_BUDGET,
        ));
        let _ = conn.set_write_timeout(Some(super::client::DIAL_TIMEOUT));
        let payload = serde_json::json!({
            "candidate_base64": crate::broker::wire::b64_encode(candidate),
        });
        let msg = Request {
            operation_id: operation_id.to_owned(),
            verb: verb::SECURITY_RESCUE.to_owned(),
            payload: serde_json::value::RawValue::from_string(payload.to_string()).ok(),
        };
        write_request(&mut conn, &msg).map_err(|_| new_rescue_client_error(3, ""))?;
        let response = read_response(&mut conn).map_err(|_| new_rescue_client_error(3, ""))?;
        if response.outcome != "success" || response.exit_code != 0 {
            return Err(new_rescue_client_error(
                response.exit_code,
                &response.reason,
            ));
        }
        let raw = response
            .result
            .as_ref()
            .map_or(&b""[..], |r| r.get().as_bytes());
        let result = decode_exact_rescue_result(raw).map_err(|_| new_rescue_client_error(6, ""))?;
        if result.operation_id != operation_id
            || result.completed_at.is_empty()
            || result.attempts < 0
        {
            return Err(new_rescue_client_error(
                response.exit_code,
                &response.reason,
            ));
        }
        Ok(result)
    }
}
