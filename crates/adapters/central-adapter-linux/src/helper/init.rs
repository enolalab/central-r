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
// The genesis handlers (`local_init_helper_linux.go`)
// ---------------------------------------------------------------------------

use crate::genesis::{
    GENESIS_CEREMONY_GRANT, GENESIS_CEREMONY_PHYSICAL_TTY, GenesisEnv, GenesisError,
    GenesisFailure, GenesisRecord, GenesisRoots, GenesisState,
};
use std::sync::Arc;

/// `initResultFrom` — the record's three contract IDs.
fn init_result_from(record: &GenesisRecord) -> InitResult {
    InitResult {
        instance_id: record.instance_id.clone(),
        config_binding_id: record.config_binding_id.clone(),
        init_operation_id: record.init_operation_id.clone(),
    }
}

/// `genesisInitStoreDir` — the pre-instance grant store under the
/// protected root (`/var/lib/central-protected/v1/genesis`).
pub fn genesis_init_store_dir(roots: &GenesisRoots) -> String {
    format!("{}/genesis", roots.protected_root)
}

/// `InitAuthorization` — what authorized one genesis: the ceremony
/// the install records, and the consumed grant's nonce (empty for
/// `physical_tty`).
pub struct InitAuthorization {
    pub mode: String,
    pub grant_nonce: String,
}

/// `genesisInitHandler` — runs genesis for the admitted operator:
/// pre-check, capacity, the init ceremony (or a consumed init
/// grant), then the genesis core under its lock.
pub struct GenesisInitHandler {
    pub env: GenesisEnv,
    pub confirmer: Box<dyn InitConfirmer>,
    /// `console` shows a line at the physical console where the
    /// operator confirmed — the only place the config path and the
    /// cleanup paths are shown.
    pub console: Box<dyn InitConsole>,
    /// The genesis grant store directory. Empty means no store is
    /// configured: every request takes the ceremony path.
    pub grants: String,
    /// Reports the running boot, for grant consumption; `None` is
    /// [`super::read_boot_id`].
    pub boot_id: Option<Arc<dyn Fn() -> Result<String, Failure> + Send + Sync>>,
}

impl GenesisInitHandler {
    /// `newGenesisHelperServer`'s handler half — the production env,
    /// the physical console, and the genesis grant store.
    pub fn production(confirmer: Box<dyn InitConfirmer>) -> Self {
        GenesisInitHandler {
            env: GenesisEnv::production(),
            confirmer,
            console: Box::new(PhysicalInitConsole),
            grants: genesis_init_store_dir(&GenesisRoots::production()),
            boot_id: None,
        }
    }

    fn boot_id(&self) -> Arc<dyn Fn() -> Result<String, Failure> + Send + Sync> {
        self.boot_id
            .clone()
            .unwrap_or_else(|| Arc::new(super::read_boot_id))
    }

    /// `tryGrant` — one grant authorization. `Ok(None)` when no
    /// grant authorizes this request (no store configured, no peer
    /// identity to record, absent store, unreadable boot id, or no
    /// usable grant), so the caller falls back to the ceremony;
    /// `Err(denial)` when the store exists but cannot be opened —
    /// falling back would hide a tampered store.
    fn try_grant(
        &self,
        operation_id: &str,
        peer: PeerIdentity,
    ) -> Result<Option<InitAuthorization>, Response> {
        if self.grants.is_empty() || !peer.available() {
            return Ok(None);
        }
        // The absent-store fallback distinguishes a store that was
        // never issued from a store that cannot be opened —
        // `ScopedDir` folds every open error into `internal`, so the
        // not-exists check is a pre-open stat, exactly as upstream's
        // `errors.Is(err, fs.ErrNotExist)` reads the open's errno.
        if let Err(e) = std::fs::metadata(&self.grants)
            && e.kind() == std::io::ErrorKind::NotFound
        {
            return Ok(None);
        }
        let store = match super::grant::GrantStore::open(
            &self.grants,
            self.env.owners.root_uid,
            self.env.owners.root_gid,
        ) {
            Ok(store) => store,
            Err(e) => {
                eprintln!(
                    "helper: init: genesis grant store {} cannot be opened: {}",
                    self.grants,
                    e.message()
                );
                return Err(new_init_denial(
                    operation_id,
                    3,
                    INIT_REASON_HELPER_UNAVAILABLE,
                ));
            }
        };
        let boot = match (self.boot_id())() {
            Ok(boot) => boot,
            Err(e) => {
                eprintln!(
                    "helper: init: boot id unavailable, skipping grant attempt: {}",
                    e.message()
                );
                return Ok(None);
            }
        };
        match store.consume(
            &super::grant::GrantScope {
                kind: super::grant::GrantKind::Init,
                ..Default::default()
            },
            &boot,
            peer.uid,
            peer.pid,
        ) {
            Ok(grant) => Ok(Some(InitAuthorization {
                mode: GENESIS_CEREMONY_GRANT.to_owned(),
                grant_nonce: grant.nonce,
            })),
            Err(_) => Ok(None),
        }
    }

    /// `tell` — one line at the operator's console. Best effort: the
    /// operator gets the machine result only when the console cannot
    /// be opened, and the journal says a line could not be shown —
    /// never what it said.
    fn tell(&self, mode: &str, line: &str, peer: PeerIdentity) {
        if mode == GENESIS_CEREMONY_GRANT {
            return;
        }
        if let Err(e) = self.console.write_init_line(peer, line.as_bytes()) {
            eprintln!(
                "helper: init: a line for the operator could not be shown at the console: {}",
                e.message()
            );
        }
    }

    /// `failure` — maps a genesis error to its exit class and wire
    /// reason. After the accepted point it names, at the operator's
    /// console only, the paths to remove — or that nothing of an
    /// instance was written. The journal line carries the error,
    /// never the cleanup list.
    fn failure(
        &self,
        operation_id: &str,
        err: &GenesisError,
        mode: &str,
        peer: PeerIdentity,
    ) -> Response {
        eprintln!("helper: init: {err}");
        match err.failure {
            GenesisFailure::Capacity => {
                self.tell(
                    mode,
                    &format!(
                        "Central local init needs 40 GiB free on the filesystem of {}; nothing was written.\n",
                        self.env.roots.state_root
                    ),
                    peer,
                );
                new_init_denial(operation_id, 4, INIT_REASON_CAPACITY)
            }
            GenesisFailure::LockTimeout => {
                new_init_denial(operation_id, 4, INIT_REASON_LOCK_TIMEOUT)
            }
            GenesisFailure::Unavailable => {
                new_init_denial(operation_id, 3, INIT_REASON_HELPER_UNAVAILABLE)
            }
            GenesisFailure::Broken => new_init_denial(operation_id, 3, INIT_REASON_INSTANCE_BROKEN),
            GenesisFailure::Unconfirmed => {
                // The config was committed; only its durability, or
                // the host's verification afterwards, is unknown.
                // Nothing is to be removed, so no cleanup path is
                // named.
                self.tell(
                    mode,
                    "Central local init wrote the instance but could not confirm it; the instance may exist. Remove nothing: run central local status, or run central local init again.\n",
                    peer,
                );
                new_init_denial(operation_id, 6, INIT_REASON_UNCONFIRMED)
            }
            GenesisFailure::Mutation => {
                if err.cleanup.is_empty() {
                    self.tell(
                        mode,
                        "Central local init failed before it wrote any instance; nothing is to be removed. Run central local init again.\n",
                        peer,
                    );
                } else {
                    self.tell(
                        mode,
                        &format!(
                            "Central local init failed after it started writing. Remove these paths as root, then run central local init again: {}\n",
                            err.cleanup
                                .iter()
                                .map(|p| p.display().to_string())
                                .collect::<Vec<_>>()
                                .join(" ")
                        ),
                        peer,
                    );
                }
                new_init_denial(operation_id, 6, INIT_REASON_MUTATION_FAILED)
            }
        }
    }

    fn create(
        &self,
        deadline: Instant,
        operation_id: &str,
        ceremony: &str,
        grant_nonce: &str,
        peer: PeerIdentity,
    ) -> Response {
        match self.env.create(deadline, ceremony, grant_nonce) {
            Err(err) => self.failure(operation_id, &err, ceremony, peer),
            Ok(outcome) => {
                if outcome.created {
                    let config_path = self
                        .env
                        .roots
                        .instances_root()
                        .join(&outcome.record.instance_id)
                        .join("config.json");
                    self.tell(
                        ceremony,
                        &format!(
                            "Central instance {} is initialized. Its configuration is {}\n",
                            outcome.record.instance_id,
                            config_path.display()
                        ),
                        peer,
                    );
                }
                new_init_response(
                    operation_id,
                    &init_result_from(&outcome.record),
                    !outcome.created,
                )
            }
        }
    }
}

impl InitHandler for GenesisInitHandler {
    fn init(&self, peer: PeerIdentity, deadline: Instant, request: InitRequest) -> Response {
        let (state, record, err) = self.env.state();
        match state {
            GenesisState::Present => {
                let Some(record) = record else {
                    return new_init_denial(&request.operation_id, 3, INIT_REASON_INSTANCE_BROKEN);
                };
                return new_init_response(&request.operation_id, &init_result_from(&record), true);
            }
            GenesisState::Absent => {}
            GenesisState::Broken => {
                eprintln!(
                    "helper: init refused, the host is not absent: {}",
                    err.unwrap_or_else(|| "the host is broken".to_owned())
                );
                return new_init_denial(&request.operation_id, 3, INIT_REASON_INSTANCE_BROKEN);
            }
        }
        if let Err(err) = self.env.check_capacity() {
            return self.failure(
                &request.operation_id,
                &err,
                GENESIS_CEREMONY_PHYSICAL_TTY,
                peer,
            );
        }
        match self.try_grant(&request.operation_id, peer) {
            Err(denial) => return denial,
            Ok(Some(auth)) => {
                return self.create(
                    deadline,
                    &request.operation_id,
                    &auth.mode,
                    &auth.grant_nonce,
                    peer,
                );
            }
            Ok(None) => {}
        }
        // No grant: B1's ceremony, exactly as before. The ceremony
        // runs under its own two-minute share, so the rest of the
        // deadline still covers the genesis lock wait and the
        // install after it.
        match confirm_init_ceremony(
            self.confirmer.as_ref(),
            peer,
            deadline,
            &request.operation_id,
        ) {
            Err(err) => {
                eprintln!("helper: init: the init ceremony refused: {}", err.message());
                // `ErrInitConfirmationMismatch` — the phrase was
                // mistyped twice; every other refusal is authority
                // denied.
                if err.code() == "sys_tty_init_mismatch" {
                    return new_init_denial(
                        &request.operation_id,
                        7,
                        INIT_REASON_CONFIRMATION_MISMATCH,
                    );
                }
                new_init_denial(&request.operation_id, 7, INIT_REASON_AUTHORITY_DENIED)
            }
            Ok(token) => {
                if !self.confirmer.verify_and_consume(&token) {
                    eprintln!("helper: init: the init ceremony's token did not verify");
                    return new_init_denial(&request.operation_id, 7, INIT_REASON_AUTHORITY_DENIED);
                }
                self.create(
                    deadline,
                    &request.operation_id,
                    GENESIS_CEREMONY_PHYSICAL_TTY,
                    "",
                    peer,
                )
            }
        }
    }
}

/// `presentInitHandler` — init on a helper serving an instance: the
/// existing instance's IDs, with no ceremony and no mutation.
pub struct PresentInitHandler {
    pub env: GenesisEnv,
}

impl PresentInitHandler {
    /// `newPresentInitHandler`.
    pub fn production() -> Self {
        PresentInitHandler {
            env: GenesisEnv::production(),
        }
    }
}

impl InitHandler for PresentInitHandler {
    fn init(&self, _peer: PeerIdentity, _deadline: Instant, request: InitRequest) -> Response {
        let (state, record, err) = self.env.state();
        if state == GenesisState::Present {
            let Some(record) = record else {
                return new_init_denial(&request.operation_id, 3, INIT_REASON_INSTANCE_BROKEN);
            };
            return new_init_response(&request.operation_id, &init_result_from(&record), true);
        }
        eprintln!(
            "helper: init: the instance state is {}: {}",
            state.as_str(),
            err.unwrap_or_else(|| "no state error".to_owned())
        );
        new_init_denial(&request.operation_id, 3, INIT_REASON_INSTANCE_BROKEN)
    }
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

// ---------------------------------------------------------------------------
// Tests — the T13 handler matrix: present/broken pre-check, capacity,
// the ceremony's two refusals and the token check, the grant path, and
// the already-initialized re-run's stable result code.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genesis::{self, GENESIS_CEREMONY_PHYSICAL_TTY};
    use std::os::unix::fs::DirBuilderExt as _;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "central-init-handler-{}-{tag}-{}",
            std::process::id(),
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir_all(&dir).expect("scratch root");
        dir
    }

    fn euid() -> u32 {
        rustix::process::getuid().as_raw()
    }

    fn egid() -> u32 {
        rustix::process::getgid().as_raw()
    }

    /// `GenesisEnv::test` over `base/state/v1` + `base/protected/v1`,
    /// the scratch shape upstream's handler tests run genesis on.
    fn test_env(base: &Path) -> GenesisEnv {
        GenesisEnv::test(
            &base.join("state/v1"),
            &base.join("protected/v1"),
            euid(),
            egid(),
        )
    }

    /// A stub `InitConfirmer`: `confirm` answers (or refuses) once
    /// per call; `verify_and_consume` returns `verify` for the minted
    /// token only. The counters prove the ceremony ran — or, on the
    /// grant path, never ran.
    struct StubConfirmer {
        confirm: Mutex<Result<String, Failure>>,
        verify: bool,
        confirm_calls: AtomicUsize,
        verify_calls: AtomicUsize,
    }

    impl InitConfirmer for StubConfirmer {
        fn confirm_init(
            &self,
            _peer: PeerIdentity,
            _deadline: Option<Instant>,
            _operation_id: &str,
        ) -> Result<String, Failure> {
            self.confirm_calls.fetch_add(1, Ordering::SeqCst);
            self.confirm
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .map(|t| t.clone())
                .map_err(|e| Failure::new(e.kind(), e.code(), e.message().to_owned()))
        }
        fn verify_and_consume(&self, token: &str) -> bool {
            self.verify_calls.fetch_add(1, Ordering::SeqCst);
            self.verify
                && self
                    .confirm
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .as_ref()
                    .map(|minted| minted.as_str() == token)
                    .unwrap_or(false)
        }
    }

    /// A stub `InitConsole` collecting the operator lines.
    struct StubConsole {
        lines: Mutex<Vec<String>>,
    }

    impl InitConsole for StubConsole {
        fn write_init_line(&self, _peer: PeerIdentity, line: &[u8]) -> Result<(), Failure> {
            self.lines
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(String::from_utf8_lossy(line).into_owned());
            Ok(())
        }
    }

    fn handler(
        env: GenesisEnv,
        confirm: Result<String, Failure>,
        verify: bool,
    ) -> (GenesisInitHandler, Arc<StubConfirmer>, Arc<StubConsole>) {
        let confirmer = Arc::new(StubConfirmer {
            confirm: Mutex::new(confirm),
            verify,
            confirm_calls: AtomicUsize::new(0),
            verify_calls: AtomicUsize::new(0),
        });
        let console = Arc::new(StubConsole {
            lines: Mutex::new(Vec::new()),
        });
        let handler = GenesisInitHandler {
            env,
            confirmer: Box::new(ArcConfirmer(confirmer.clone())),
            console: Box::new(ArcConsole(console.clone())),
            grants: String::new(),
            boot_id: None,
        };
        (handler, confirmer, console)
    }

    /// Box-sized adapters so the stubs can be shared for the call
    /// counters.
    struct ArcConfirmer(Arc<StubConfirmer>);
    impl InitConfirmer for ArcConfirmer {
        fn confirm_init(
            &self,
            peer: PeerIdentity,
            deadline: Option<Instant>,
            operation_id: &str,
        ) -> Result<String, Failure> {
            self.0.confirm_init(peer, deadline, operation_id)
        }
        fn verify_and_consume(&self, token: &str) -> bool {
            self.0.verify_and_consume(token)
        }
    }
    struct ArcConsole(Arc<StubConsole>);
    impl InitConsole for ArcConsole {
        fn write_init_line(&self, peer: PeerIdentity, line: &[u8]) -> Result<(), Failure> {
            self.0.write_init_line(peer, line)
        }
    }

    fn peer() -> PeerIdentity {
        PeerIdentity {
            uid: euid(),
            gid: egid(),
            pid: 4242,
        }
    }

    fn req() -> InitRequest {
        InitRequest {
            operation_id: uuid::Uuid::now_v7().to_string(),
        }
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    /// `GenesisServer`'s init on a present host: the durable record's
    /// three ids under `ALREADY_INITIALIZED`, no ceremony, no
    /// mutation — the re-run's stable result code.
    #[test]
    fn init_on_present_is_already_initialized_with_the_same_ids() {
        let base = scratch("present");
        let env = test_env(&base);
        // First genesis, straight through the env (as a confirmed
        // ceremony would).
        let outcome = env
            .create(deadline(), GENESIS_CEREMONY_PHYSICAL_TTY, "")
            .expect("first genesis");
        let (handler, confirmer, _console) = handler(env, Ok("tok".to_owned()), true);
        let response = handler.init(peer(), deadline(), req());
        assert_eq!(response.outcome, "success");
        assert_eq!(response.exit_code, 0);
        assert_eq!(response.reason, INIT_REASON_ALREADY_INITIALIZED);
        let result = decode_exact_init_result(
            response
                .result
                .as_deref()
                .map_or(&b""[..], |r| r.get().as_bytes()),
        )
        .expect("init result decodes");
        assert_eq!(result.instance_id, outcome.record.instance_id);
        assert_eq!(result.config_binding_id, outcome.record.config_binding_id);
        assert_eq!(result.init_operation_id, outcome.record.init_operation_id);
        // The present answer never runs the ceremony.
        assert_eq!(confirmer.confirm_calls.load(Ordering::SeqCst), 0);
        assert_eq!(confirmer.verify_calls.load(Ordering::SeqCst), 0);
    }

    /// The full bare-init flow: absent → ceremony → install → success
    /// with the contract's three ids, then a second `init` answers
    /// `ALREADY_INITIALIZED` at exit 0 with the same ids and no second
    /// ceremony.
    #[test]
    fn absent_runs_ceremony_then_installs_rerun_is_already() {
        let base = scratch("ceremony");
        let env = test_env(&base);
        let (handler, confirmer, console) = handler(env, Ok("tok".to_owned()), true);
        let response = handler.init(peer(), deadline(), req());
        assert_eq!(response.outcome, "success");
        assert_eq!(response.exit_code, 0);
        assert_eq!(response.reason, "");
        let first = decode_exact_init_result(
            response
                .result
                .as_deref()
                .map_or(&b""[..], |r| r.get().as_bytes()),
        )
        .expect("init result decodes");
        assert_eq!(confirmer.confirm_calls.load(Ordering::SeqCst), 1);
        assert_eq!(confirmer.verify_calls.load(Ordering::SeqCst), 1);
        // The operator's console heard the instance id and config path.
        let shown = console.lines.lock().unwrap_or_else(|e| e.into_inner());
        assert!(shown.iter().any(|l| l.contains(&first.instance_id)));
        // The genesis record carries physical_tty.
        let record = genesis::read_genesis_record(
            &handler.env.roots.instances_root().join(&first.instance_id),
            euid(),
            egid(),
        )
        .expect("genesis record reads");
        assert_eq!(record.ceremony, GENESIS_CEREMONY_PHYSICAL_TTY);
        drop(shown);
        // The re-run.
        let response = handler.init(peer(), deadline(), req());
        assert_eq!(response.outcome, "success");
        assert_eq!(response.exit_code, 0);
        assert_eq!(response.reason, INIT_REASON_ALREADY_INITIALIZED);
        let second = decode_exact_init_result(
            response
                .result
                .as_deref()
                .map_or(&b""[..], |r| r.get().as_bytes()),
        )
        .expect("init result decodes");
        assert_eq!(second.instance_id, first.instance_id);
        assert_eq!(second.config_binding_id, first.config_binding_id);
        assert_eq!(second.init_operation_id, first.init_operation_id);
        assert_eq!(confirmer.confirm_calls.load(Ordering::SeqCst), 1);
    }

    /// The ceremony's two refusals and the token check all map to
    /// exit 7: mismatch to `CONFIRMATION_MISMATCH`, anything else to
    /// `AUTHORITY_DENIED`, and a minted token the confirmer cannot
    /// verify back to `AUTHORITY_DENIED`.
    #[test]
    fn ceremony_refusals_map_to_exit_seven() {
        for (confirm, verify, reason) in [
            (
                Err(Failure::denied(
                    "sys_tty_init_mismatch",
                    "tty_ceremony: the typed init phrase did not match",
                )),
                false,
                INIT_REASON_CONFIRMATION_MISMATCH,
            ),
            (
                Err(Failure::denied(
                    "sys_tty_console_unfit",
                    "tty_ceremony: no physical console",
                )),
                false,
                INIT_REASON_AUTHORITY_DENIED,
            ),
            (Ok("tok".to_owned()), false, INIT_REASON_AUTHORITY_DENIED),
        ] {
            let base = scratch(match reason {
                INIT_REASON_CONFIRMATION_MISMATCH => "mismatch",
                _ => "denied",
            });
            let env = test_env(&base);
            let (handler, _confirmer, _console) = handler(env, confirm, verify);
            let response = handler.init(peer(), deadline(), req());
            assert_eq!(response.outcome, "denied");
            assert_eq!(response.exit_code, 7, "{reason}");
            assert_eq!(response.reason, reason);
        }
    }

    /// A broken host is `INSTANCE_BROKEN` exit 3 before capacity,
    /// grants, or the ceremony.
    #[test]
    fn broken_host_is_instance_broken() {
        let base = scratch("broken");
        let env = test_env(&base);
        // Protected instance without a state peer — upstream's named
        // broken branch.
        let planted = env
            .roots
            .protected_instances_root()
            .join("00000000-0000-7000-8000-000000000000");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&planted)
            .unwrap();
        let (handler, confirmer, _console) = handler(env, Ok("tok".to_owned()), true);
        let response = handler.init(peer(), deadline(), req());
        assert_eq!(response.outcome, "denied");
        assert_eq!(response.exit_code, 3);
        assert_eq!(response.reason, INIT_REASON_INSTANCE_BROKEN);
        assert_eq!(confirmer.confirm_calls.load(Ordering::SeqCst), 0);
    }

    /// The capacity refusal is `CAPACITY_INSUFFICIENT` exit 4 and the
    /// ceremony never runs.
    #[test]
    fn capacity_refusal_is_exit_four() {
        let base = scratch("capacity");
        let mut env = test_env(&base);
        env.free_bytes = Arc::new(|_| Ok(0));
        let (handler, confirmer, console) = handler(env, Ok("tok".to_owned()), true);
        let response = handler.init(peer(), deadline(), req());
        assert_eq!(response.outcome, "denied");
        assert_eq!(response.exit_code, 4);
        assert_eq!(response.reason, INIT_REASON_CAPACITY);
        assert_eq!(confirmer.confirm_calls.load(Ordering::SeqCst), 0);
        // The operator was told on the console (physical_tty mode).
        let shown = console.lines.lock().unwrap_or_else(|e| e.into_inner());
        assert!(shown.iter().any(|l| l.contains("40 GiB")));
    }

    /// The grant path: a usable init grant in the genesis store
    /// authorizes the install with no ceremony, the record carries
    /// `grant` plus the consumed nonce, and the instance is born in
    /// grant mode (ceremony-mode file + grant store dir).
    #[test]
    fn init_grant_consumes_installs_grant_mode() {
        let base = scratch("grant");
        let env = test_env(&base);
        let grants_dir = genesis_init_store_dir(&env.roots);
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&grants_dir)
            .unwrap();
        let store = crate::helper::grant::GrantStore::open(&grants_dir, euid(), egid())
            .expect("genesis grant store opens");
        store
            .issue_init("boot-test", "test-release", Duration::from_secs(300), false)
            .expect("init grant issues");
        drop(store);
        let (mut handler, confirmer, console) = handler(env, Ok("tok".to_owned()), true);
        handler.grants = grants_dir;
        handler.boot_id = Some(Arc::new(|| Ok("boot-test".to_owned())));
        let response = handler.init(peer(), deadline(), req());
        assert_eq!(response.outcome, "success");
        assert_eq!(response.exit_code, 0);
        assert_eq!(response.reason, "");
        // No ceremony ran.
        assert_eq!(confirmer.confirm_calls.load(Ordering::SeqCst), 0);
        // Grant mode tells the operator nothing.
        assert!(
            console
                .lines
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty()
        );
        let result = decode_exact_init_result(
            response
                .result
                .as_deref()
                .map_or(&b""[..], |r| r.get().as_bytes()),
        )
        .expect("init result decodes");
        let state_root = handler.env.roots.instances_root().join(&result.instance_id);
        let record =
            genesis::read_genesis_record(&state_root, euid(), egid()).expect("record reads");
        assert_eq!(record.ceremony, genesis::GENESIS_CEREMONY_GRANT);
        assert!(!record.grant_nonce.is_empty());
        // Born in grant mode: the ceremony-mode file and the grant
        // store directory exist under the instance root.
        assert!(state_root.join("grants").is_dir());
        assert!(
            state_root
                .read_dir()
                .unwrap()
                .filter_map(|e| e.ok())
                .any(|e| e.file_name().to_string_lossy().starts_with("ceremony-mode"))
        );
    }

    /// The grant store that exists but cannot be opened is denied
    /// `HELPER_UNAVAILABLE` — the fallback is never used to hide a
    /// tampered store. (A mode-0755 dir fails the store's own
    /// 0700 owner check.)
    #[test]
    fn unopenable_grant_store_is_denied_not_fallen_back() {
        let base = scratch("badstore");
        let env = test_env(&base);
        let grants_dir = genesis_init_store_dir(&env.roots);
        // The protected chain at the exact 0700 shape so the host
        // classifies absent, then the store dir itself at 0755 —
        // present but unopenable.
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&grants_dir)
            .unwrap();
        std::fs::set_permissions(
            &grants_dir,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .unwrap();
        let (mut handler, confirmer, _console) = handler(env, Ok("tok".to_owned()), true);
        handler.grants = grants_dir;
        handler.boot_id = Some(Arc::new(|| Ok("boot-test".to_owned())));
        let response = handler.init(peer(), deadline(), req());
        assert_eq!(response.outcome, "denied");
        assert_eq!(response.exit_code, 3);
        assert_eq!(response.reason, INIT_REASON_HELPER_UNAVAILABLE);
        assert_eq!(confirmer.confirm_calls.load(Ordering::SeqCst), 0);
    }

    /// `presentInitHandler` — the instance-branch init: present
    /// answers ALREADY_INITIALIZED, absent answers INSTANCE_BROKEN.
    #[test]
    fn present_handler_answers_record_or_broken() {
        let base = scratch("present-handler");
        let env = test_env(&base);
        // Absent: the instance branch refuses as broken.
        let handler = PresentInitHandler { env: env.clone() };
        let response = handler.init(peer(), deadline(), req());
        assert_eq!(response.outcome, "denied");
        assert_eq!(response.exit_code, 3);
        assert_eq!(response.reason, INIT_REASON_INSTANCE_BROKEN);
        // Present: the durable ids, no ceremony.
        let outcome = env
            .create(deadline(), GENESIS_CEREMONY_PHYSICAL_TTY, "")
            .expect("first genesis");
        let response = handler.init(peer(), deadline(), req());
        assert_eq!(response.outcome, "success");
        assert_eq!(response.exit_code, 0);
        assert_eq!(response.reason, INIT_REASON_ALREADY_INITIALIZED);
        let result = decode_exact_init_result(
            response
                .result
                .as_deref()
                .map_or(&b""[..], |r| r.get().as_bytes()),
        )
        .expect("init result decodes");
        assert_eq!(result.instance_id, outcome.record.instance_id);
    }

    /// `parseInitRequest` — the empty-payload-only grammar.
    #[test]
    fn parse_init_request_is_empty_payload_only() {
        let request = |payload: Option<serde_json::Value>| Request {
            operation_id: "op-1".to_owned(),
            verb: crate::helper::verb::INIT.to_owned(),
            payload: payload.and_then(|v| serde_json::value::to_raw_value(&v).ok()),
        };
        assert!(parse_init_request(&request(None)).is_ok());
        assert!(parse_init_request(&request(Some(serde_json::json!({})))).is_ok());
        assert!(parse_init_request(&request(Some(serde_json::json!({"x": 1})))).is_err());
        let mut missing = request(None);
        missing.operation_id = String::new();
        assert!(parse_init_request(&missing).is_err());
    }

    /// `decodeExactInitResult` — canonical bytes and UUIDv7 ids, or
    /// refusal.
    #[test]
    fn init_result_gate_is_canonical_and_uuidv7() {
        let result = InitResult {
            instance_id: uuid::Uuid::now_v7().to_string(),
            config_binding_id: uuid::Uuid::now_v7().to_string(),
            init_operation_id: uuid::Uuid::now_v7().to_string(),
        };
        let canonical = serde_json::to_vec(&result).unwrap();
        let decoded = decode_exact_init_result(&canonical).unwrap();
        assert_eq!(decoded.instance_id, result.instance_id);
        assert_eq!(decoded.config_binding_id, result.config_binding_id);
        assert_eq!(decoded.init_operation_id, result.init_operation_id);
        assert!(decode_exact_init_result(b"").is_err());
        // Trailing data.
        let mut trailing = canonical.clone();
        trailing.extend_from_slice(b" {}");
        assert!(decode_exact_init_result(&trailing).is_err());
        // Reordered fields are not canonical bytes.
        let reordered = br#"{"config_binding_id":"00000000-0000-7000-8000-000000000000","instance_id":"00000000-0000-7000-8000-000000000000","init_operation_id":"00000000-0000-7000-8000-000000000000"}"#;
        assert!(decode_exact_init_result(reordered).is_err());
        // A non-v7 id refuses.
        let bad = InitResult {
            instance_id: "not-a-uuid".to_owned(),
            ..result.clone()
        };
        assert!(decode_exact_init_result(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
}
