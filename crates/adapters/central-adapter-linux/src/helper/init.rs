//! `init.go` + `init_client_linux.go` — the init verb's wire shape, the
//! genesis server's handler seam, and the operator-side init client.
//! The genesis core itself (layout, lock, genesis record) is T13's;
//! this module is its transport and client contract.

use super::PeerIdentity;
use super::protocol::*;
use central_foundation::failure::Failure;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

// The complete init wire-reason vocabulary (init.go's const block).
pub const INIT_REASON_ALREADY_INITIALIZED: &str = "ALREADY_INITIALIZED";
pub const INIT_REASON_HELPER_UNAVAILABLE: &str = "HELPER_UNAVAILABLE";
pub const INIT_REASON_INSTANCE_BROKEN: &str = "INSTANCE_BROKEN";
pub const INIT_REASON_CAPACITY: &str = "CAPACITY_INSUFFICIENT";
pub const INIT_REASON_LOCK_TIMEOUT: &str = "LOCK_TIMEOUT";
pub const INIT_REASON_AUTHORITY_DENIED: &str = "AUTHORITY_DENIED";
pub const INIT_REASON_MUTATION_FAILED: &str = "MUTATION_FAILED";
pub const INIT_REASON_INVALID_REQUEST: &str = "INVALID_INIT_REQUEST";
pub const INIT_REASON_UNCONFIRMED: &str = "INIT_UNCONFIRMED";
pub const INIT_REASON_CONFIRMATION_MISMATCH: &str = "CONFIRMATION_MISMATCH";

/// `InitRequest` — carries nothing but the enclosing operation id.
pub struct InitRequest {
    pub operation_id: String,
}

/// `ParseInitRequest` — empty or `{}` only; a smuggled field fails the
/// request rather than being ignored.
pub fn parse_init_request(req: &Request) -> Result<InitRequest, String> {
    if req.operation_id.is_empty() {
        return Err("helper: missing init operation".to_owned());
    }
    payload_is_empty_object(req.payload_bytes())
        .map_err(|e| format!("helper: invalid init payload: {e}"))?;
    Ok(InitRequest {
        operation_id: req.operation_id.clone(),
    })
}

/// `InitResult` — the three contract IDs, in marshal order so the
/// client's canonical round-trip check stays exact.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitResult {
    pub instance_id: String,
    pub config_binding_id: String,
    pub init_operation_id: String,
}

/// `NewInitResponse` — success, plus ALREADY_INITIALIZED when nothing
/// was created.
pub fn new_init_response(operation_id: &str, result: &InitResult, already: bool) -> Response {
    match serde_json::to_string(result) {
        Ok(raw) => Response {
            operation_id: operation_id.to_owned(),
            outcome: "success".to_owned(),
            exit_code: 0,
            reason: if already {
                INIT_REASON_ALREADY_INITIALIZED.to_owned()
            } else {
                String::new()
            },
            result: serde_json::value::RawValue::from_string(raw).ok(),
        },
        Err(_) => new_init_denial(operation_id, 6, INIT_REASON_MUTATION_FAILED),
    }
}

/// `NewInitDenial` — an exit class and a fixed reason token, never text.
pub fn new_init_denial(operation_id: &str, exit_code: i64, reason: &str) -> Response {
    Response::denied(operation_id, exit_code, reason)
}

/// `InitHandler` — the seam the genesis core and the present-instance
/// answer both implement. `deadline` is the verb's transport bound.
pub trait InitHandler: Send + Sync {
    fn init(&self, peer: PeerIdentity, deadline: Instant, request: InitRequest) -> Response;
}

/// `InitConfirmer` — the init ceremony (fresh PAM + `CONFIRM <code>
/// init`) and the one-use token it mints.
pub trait InitConfirmer: Send + Sync {
    fn confirm_init(
        &self,
        peer: PeerIdentity,
        deadline: Option<Instant>,
        operation_id: &str,
    ) -> Result<String, Failure>;
    fn verify_and_consume(&self, token: &str) -> bool;
}

/// `InitConsole` — init's operator lines travel only on the trusted
/// TTY plane.
pub trait InitConsole: Send + Sync {
    fn write_init_line(&self, peer: PeerIdentity, line: &[u8]) -> Result<(), Failure>;
}

/// `PhysicalConsole` — the production InitConsole, the same physical
/// console the init ceremony validated.
pub struct PhysicalInitConsole;

impl InitConsole for PhysicalInitConsole {
    fn write_init_line(&self, peer: PeerIdentity, line: &[u8]) -> Result<(), Failure> {
        crate::sys::tty::write_init_line(
            rustix::process::Pid::from_raw(peer.pid).ok_or_else(|| {
                Failure::denied(
                    "sys_tty_console_unfit",
                    "tty_ceremony: Unix peer is unavailable",
                )
            })?,
            line,
        )
    }
}

/// `genesisModeDenial` — every non-init verb's answer before genesis.
pub fn genesis_mode_denial(req: &Request) -> Response {
    new_init_denial(&req.operation_id, 3, INIT_REASON_HELPER_UNAVAILABLE)
}

/// `ConfirmInitCeremony` — the ceremony under its own two-minute share,
/// leaving the machine share on `deadline` for the genesis that follows.
pub fn confirm_init_ceremony(
    confirmer: &dyn InitConfirmer,
    peer: PeerIdentity,
    verb_deadline: Instant,
    operation_id: &str,
) -> Result<String, Failure> {
    let ceremony_share = verb_deadline.min(Instant::now() + super::server::CEREMONY_BUDGET);
    confirmer.confirm_init(peer, Some(ceremony_share), operation_id)
}

// ---------------------------------------------------------------------------
// Init client (`init_client_linux.go`)
// ---------------------------------------------------------------------------

/// `InitClientResult`.
#[derive(Debug, Clone, Default)]
pub struct InitClientResult {
    pub instance_id: String,
    pub config_binding_id: String,
    pub init_operation_id: String,
    pub already_initialized: bool,
}

/// `InitClientError` — the stable exit class plus a whitelisted reason.
#[derive(Debug, Clone)]
pub struct InitClientError {
    pub exit_code: i64,
    pub reason: String,
    pub no_answer: bool,
    pub untrusted: bool,
}

impl InitClientError {
    fn new(exit_code: i64, reason: &str) -> Self {
        let exit_code = if !(2..=7).contains(&exit_code) {
            6
        } else {
            exit_code
        };
        InitClientError {
            exit_code,
            reason: retained_init_reason(reason),
            no_answer: false,
            untrusted: false,
        }
    }
}

/// `retainedInitReason` — the whitelist minus ALREADY_INITIALIZED (which
/// is a success annotation, not a failure reason).
fn retained_init_reason(reason: &str) -> String {
    match reason {
        INIT_REASON_HELPER_UNAVAILABLE
        | INIT_REASON_INSTANCE_BROKEN
        | INIT_REASON_CAPACITY
        | INIT_REASON_LOCK_TIMEOUT
        | INIT_REASON_AUTHORITY_DENIED
        | INIT_REASON_MUTATION_FAILED
        | INIT_REASON_INVALID_REQUEST
        | INIT_REASON_UNCONFIRMED
        | INIT_REASON_CONFIRMATION_MISMATCH => reason.to_owned(),
        _ => String::new(),
    }
}

/// `linuxInitClient` — dial, one init request, strict result checks.
pub struct InitClient {
    socket_path: String,
}

impl InitClient {
    pub fn new(socket_path: impl Into<String>) -> Self {
        InitClient {
            socket_path: socket_path.into(),
        }
    }

    /// `Init` — the whole exchange, bounded by the init transport
    /// budget; a helper that closes unanswered is HELPER_UNAVAILABLE
    /// with `no_answer` set.
    pub fn init(&self, operation_id: &str) -> Result<InitClientResult, InitClientError> {
        if self.socket_path.is_empty() || operation_id.is_empty() {
            return Err(InitClientError::new(3, INIT_REASON_HELPER_UNAVAILABLE));
        }
        let unanswered = |no_answer: bool| {
            let mut e = InitClientError::new(3, INIT_REASON_HELPER_UNAVAILABLE);
            e.no_answer = no_answer;
            e
        };
        // Upstream `net.Dialer{Timeout: 5 * time.Second}` — bounded
        // connect rather than a blocking `UnixStream::connect` that
        // can hold the operator path open on a wedged accept queue.
        let mut conn = match super::browser::dial_unix_bounded(
            std::path::Path::new(&self.socket_path),
            Duration::from_secs(5),
        ) {
            Ok(c) => c,
            Err(_) => return Err(unanswered(false)),
        };
        let _ = conn.set_read_timeout(Some(
            super::server::INIT_BUDGET + super::server::CONN_WRITE_GRACE * 2,
        ));
        let _ = conn.set_write_timeout(Some(super::server::INIT_BUDGET));
        let request = Request {
            operation_id: operation_id.to_owned(),
            verb: super::verb::INIT.to_owned(),
            payload: None,
        };
        if write_request(&mut conn, &request).is_err() {
            return Err(unanswered(true));
        }
        let response = match read_response(&mut conn) {
            Ok(r) => r,
            Err(_) => return Err(unanswered(true)),
        };
        if response.outcome != "success" || response.exit_code != 0 {
            return Err(InitClientError::new(response.exit_code, &response.reason));
        }
        let untrusted = || {
            let mut e = InitClientError::new(6, "");
            e.untrusted = true;
            e
        };
        if response.operation_id != operation_id
            || (!response.reason.is_empty() && response.reason != INIT_REASON_ALREADY_INITIALIZED)
        {
            return Err(untrusted());
        }
        let payload = response
            .result
            .as_deref()
            .map_or(&b""[..], |r| r.get().as_bytes());
        let result = decode_exact_init_result(payload).map_err(|_| untrusted())?;
        Ok(InitClientResult {
            instance_id: result.instance_id,
            config_binding_id: result.config_binding_id,
            init_operation_id: result.init_operation_id,
            already_initialized: response.reason == INIT_REASON_ALREADY_INITIALIZED,
        })
    }
}

/// `decodeExactInitResult` — strict shape, canonical bytes, UUIDv7 ids.
pub fn decode_exact_init_result(payload: &[u8]) -> Result<InitResult, String> {
    if payload.is_empty() {
        return Err("helper: init result is missing".to_owned());
    }
    let result: InitResult =
        strict_decode(payload).map_err(|_| "helper: init result is invalid".to_owned())?;
    let canonical =
        serde_json::to_vec(&result).map_err(|_| "helper: init result is invalid".to_owned())?;
    if canonical != payload {
        return Err("helper: init result is not canonical".to_owned());
    }
    for id in [
        &result.instance_id,
        &result.config_binding_id,
        &result.init_operation_id,
    ] {
        match uuid::Uuid::parse_str(id) {
            Ok(parsed) if parsed.get_version() == Some(uuid::Version::SortRand) => {
                if parsed.to_string() != *id {
                    return Err("helper: init result carries an id that is not a UUIDv7".to_owned());
                }
            }
            _ => return Err("helper: init result carries an id that is not a UUIDv7".to_owned()),
        }
    }
    Ok(result)
}
