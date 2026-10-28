//! `security_update.go` — B01's write path: an operator-supplied,
//! already-signed advisory envelope, confirmed at the operator's
//! console, then installed as this instance's new active advisory
//! generation. The handler performs no signature verification of the
//! envelope itself: `install` only validates shape, because verifying
//! the signature is the read side's job — duplicating that check here
//! would be a second place the two could disagree about whether a
//! bundle is trusted.

use super::protocol::*;
use super::{PeerIdentity, verb};
use serde::{Deserialize, Serialize};
use std::time::Instant;

/// `SECURITY_UPDATE_*` — the closed refusal vocabulary.
pub const REASON_SECURITY_UPDATE_UNAVAILABLE: &str = "SECURITY_UPDATE_UNAVAILABLE";
pub const REASON_INVALID_SECURITY_UPDATE_REQUEST: &str = "INVALID_SECURITY_UPDATE_REQUEST";
pub const REASON_SECURITY_UPDATE_AUTHORIZATION_REQUIRED: &str =
    "SECURITY_UPDATE_AUTHORIZATION_REQUIRED";
pub const REASON_SECURITY_UPDATE_INSTALL_FAILED: &str = "SECURITY_UPDATE_INSTALL_FAILED";
pub const REASON_AUTHORITY_DENIED: &str = "AUTHORITY_DENIED";

/// `securityUpdatePAMConfirmer` — the generic lifecycle confirmation
/// (`h.pam.Confirm(ctx, operationID)` upstream), an optional seam: a
/// confirmer that cannot run the ceremony refuses rather than falling
/// back to an unbound token.
pub trait SecurityUpdatePamConfirmer: Send + Sync {
    fn confirm(
        &self,
        peer: PeerIdentity,
        deadline: Option<Instant>,
        operation_id: &str,
    ) -> Result<String, central_foundation::failure::Failure>;
    fn verify_and_consume(&self, token: &str) -> bool;
}

/// `SecurityUpdateInstaller` — the narrow write-side capability of
/// `advisory.InstallActiveBundle`: install envelope bytes as the new
/// active advisory generation beneath `root_path`, bound to
/// `binding_id`, and report the generation id that now selects it.
pub type SecurityUpdateInstaller =
    dyn Fn(&str, &str, &[u8]) -> Result<String, central_foundation::failure::Failure> + Send + Sync;

/// `SecurityUpdateRequest` — the typed payload. `envelope` carries the
/// exact signed envelope bytes the operator named on the command line,
/// unmodified by this layer.
pub struct SecurityUpdateRequest {
    pub operation_id: String,
    pub envelope: Vec<u8>,
}

/// `SecurityUpdateResult` — the safe operator projection of an
/// install: which generation is now active.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SecurityUpdateResult {
    pub operation_id: String,
    pub generation_id: String,
}

/// `ParseSecurityUpdateRequest` — unknown fields are rejected, and an
/// empty or missing envelope is refused here rather than left for the
/// installer to discover.
pub fn parse_security_update_request(req: &Request) -> Result<SecurityUpdateRequest, String> {
    if req.operation_id.is_empty() {
        return Err("helper: missing security update request".to_owned());
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
        return Err("helper: missing security update request".to_owned());
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Payload {
        envelope: Box<serde_json::value::RawValue>,
    }
    let payload: Payload = strict_decode(trimmed)
        .map_err(|e| format!("helper: invalid security update request: {e}"))?;
    let envelope = payload.envelope.get().trim();
    if envelope.is_empty() {
        return Err("helper: invalid security update request".to_owned());
    }
    Ok(SecurityUpdateRequest {
        operation_id: req.operation_id.clone(),
        envelope: envelope.as_bytes().to_vec(),
    })
}

/// `SecurityUpdateHandler` — `SecurityUpdateHandler` upstream.
/// `root_path` and `binding_id` are fixed instance identity the helper
/// resolves itself — never accepted from the operator request.
pub struct SecurityUpdateHandler {
    pub pam: Option<Box<dyn SecurityUpdatePamConfirmer>>,
    pub install: Option<Box<SecurityUpdateInstaller>>,
    pub root_path: String,
    pub binding_id: String,
}

fn security_update_response(
    operation_id: &str,
    outcome: &str,
    code: i64,
    reason: &str,
) -> Response {
    Response::new(operation_id, outcome, code, reason)
}

impl SecurityUpdateHandler {
    /// `InstallSecurityUpdate` — upstream ordering verbatim: request,
    /// seams, ceremony, install, bounded result.
    pub fn install_security_update(
        &self,
        peer: PeerIdentity,
        deadline: Instant,
        request: SecurityUpdateRequest,
    ) -> Response {
        let op = request.operation_id.as_str();
        if !peer.available() || request.envelope.is_empty() {
            return security_update_response(
                op,
                "denied",
                2,
                REASON_INVALID_SECURITY_UPDATE_REQUEST,
            );
        }
        let (Some(pam), Some(install)) = (&self.pam, &self.install) else {
            return security_update_response(
                op,
                "denied",
                7,
                REASON_SECURITY_UPDATE_AUTHORIZATION_REQUIRED,
            );
        };
        if self.root_path.is_empty() || self.binding_id.is_empty() {
            return security_update_response(
                op,
                "denied",
                7,
                REASON_SECURITY_UPDATE_AUTHORIZATION_REQUIRED,
            );
        }
        let mut envelope = request.envelope;
        let confirmation = pam
            .confirm(peer, Some(deadline), &request.operation_id)
            .ok()
            .filter(|token| pam.verify_and_consume(token));
        if confirmation.is_none() {
            envelope.fill(0);
            return security_update_response(op, "denied", 7, REASON_AUTHORITY_DENIED);
        }
        let generation = install(&self.root_path, &self.binding_id, &envelope);
        envelope.fill(0);
        let Ok(generation_id) = generation else {
            return security_update_response(op, "error", 6, REASON_SECURITY_UPDATE_INSTALL_FAILED);
        };
        if generation_id.is_empty() {
            return security_update_response(op, "error", 6, REASON_SECURITY_UPDATE_INSTALL_FAILED);
        }
        security_update_response(op, "success", 0, "").with_result(&SecurityUpdateResult {
            operation_id: op.to_owned(),
            generation_id,
        })
    }
}

// ---------------------------------------------------------------------------
// SecurityUpdateClient — client_linux.go's linuxSecurityUpdateClient.
// ---------------------------------------------------------------------------

/// `SecurityUpdateClientResult` mirrors the helper's
/// `SecurityUpdateResult` across the socket.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityUpdateClientResult {
    pub operation_id: String,
    pub generation_id: String,
}

/// `SecurityUpdateClientError` exposes only the stable exit class
/// plus a whitelisted reason token.
#[derive(Debug)]
pub struct SecurityUpdateClientError {
    exit_code: i64,
    reason: String,
}

impl SecurityUpdateClientError {
    pub fn exit_code(&self) -> i64 {
        self.exit_code
    }
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl std::fmt::Display for SecurityUpdateClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "helper: security update failed")
    }
}
impl std::error::Error for SecurityUpdateClientError {}

fn retained_security_update_reason(reason: &str) -> String {
    match reason {
        central_infra::advisory::REASON_DENY_SAFE_ACTIVE
        | REASON_SECURITY_UPDATE_AUTHORIZATION_REQUIRED
        | REASON_AUTHORITY_DENIED => reason.to_owned(),
        _ => String::new(),
    }
}

fn new_security_update_client_error(exit_code: i64, reason: &str) -> SecurityUpdateClientError {
    let exit_code = if !(2..=7).contains(&exit_code) {
        6
    } else {
        exit_code
    };
    SecurityUpdateClientError {
        exit_code,
        reason: retained_security_update_reason(reason),
    }
}

/// `decodeExactSecurityUpdateResult` — strict decode plus canonical
/// re-encode equality.
fn decode_exact_security_update_result(
    payload: &[u8],
) -> Result<SecurityUpdateClientResult, String> {
    if payload.is_empty() {
        return Err("helper: security update result is invalid".to_owned());
    }
    let result: SecurityUpdateClientResult = strict_decode(payload)?;
    let canonical = serde_json::to_vec(&result)
        .map_err(|_| "helper: security update result is not canonical".to_owned())?;
    if canonical != payload {
        return Err("helper: security update result is not canonical".to_owned());
    }
    Ok(result)
}

/// `SecurityUpdateClient` — `linuxSecurityUpdateClient`: dials the
/// security-update verb.
pub struct SecurityUpdateClient {
    socket_path: String,
}

impl SecurityUpdateClient {
    pub fn new(socket_path: impl Into<String>) -> Self {
        SecurityUpdateClient {
            socket_path: socket_path.into(),
        }
    }

    /// `InstallSecurityUpdate` — sends the exact envelope bytes and
    /// validates the bounded result: operation id echoes and a
    /// non-empty generation id.
    ///
    /// # Errors
    /// [`SecurityUpdateClientError`] — transport failures fold to
    /// exit 3, a non-canonical or mismatched result to exit 6, and
    /// helper denials carry the envelope code plus the whitelisted
    /// reason.
    pub fn install_security_update(
        &self,
        operation_id: &str,
        envelope: &[u8],
    ) -> Result<SecurityUpdateClientResult, SecurityUpdateClientError> {
        if self.socket_path.is_empty() || operation_id.is_empty() || envelope.is_empty() {
            return Err(new_security_update_client_error(3, ""));
        }
        let envelope_json = String::from_utf8(envelope.to_vec())
            .map_err(|_| new_security_update_client_error(2, ""))?;
        let payload = format!("{{\"envelope\":{envelope_json}}}");
        let mut conn = super::browser::dial_unix_bounded(
            std::path::Path::new(&self.socket_path),
            super::client::DIAL_TIMEOUT,
        )
        .map_err(|_| new_security_update_client_error(3, ""))?;
        let _ = conn.set_read_timeout(Some(
            super::client::DIAL_TIMEOUT + super::server::SECURITY_UPDATE_BUDGET,
        ));
        let _ = conn.set_write_timeout(Some(super::client::DIAL_TIMEOUT));
        let msg = Request {
            operation_id: operation_id.to_owned(),
            verb: verb::SECURITY_UPDATE.to_owned(),
            payload: serde_json::value::RawValue::from_string(payload).ok(),
        };
        write_request(&mut conn, &msg).map_err(|_| new_security_update_client_error(3, ""))?;
        let response =
            read_response(&mut conn).map_err(|_| new_security_update_client_error(3, ""))?;
        if response.outcome != "success" || response.exit_code != 0 {
            return Err(new_security_update_client_error(
                response.exit_code,
                &response.reason,
            ));
        }
        let raw = response
            .result
            .as_ref()
            .map_or(&b""[..], |r| r.get().as_bytes());
        let result = decode_exact_security_update_result(raw)
            .map_err(|_| new_security_update_client_error(6, ""))?;
        if result.operation_id != operation_id || result.generation_id.is_empty() {
            return Err(new_security_update_client_error(
                response.exit_code,
                &response.reason,
            ));
        }
        Ok(result)
    }
}
