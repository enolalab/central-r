//! `client_linux.go` + `socket_path.go` — the operator-side clients
//! that dial the helper's Unix socket. The R5 slice carries the
//! lifecycle and prepare clients plus the raw write/read helpers every
//! other client (init.rs already carries `InitClient`) is built on;
//! `helperB06Client` (`cmd/central/main.go`) — the B06 browser-open /
//! bootstrap-show operator client — lands with its verbs. The
//! remaining R6 clients — wipe, backup, restore, export/import,
//! delete, prune, state-audit, rescue, maintenance, security-update —
//! are deferred with their verbs: a client for a verb the matrix
//! answers `UNSUPPORTED_IN_THIS_SLICE` would only add untested surface.

use super::protocol::*;
use super::server::SocketPolicy;
use serde_json::value::RawValue;
use std::time::Duration;

/// `ProductionSocketPath` — where
/// `packaging/systemd/central-helper.socket` listens. Its directory is
/// 0711; the socket itself is 0660 root:<operator primary group>,
/// which `SocketPolicy::validate` enforces at startup.
pub const PRODUCTION_SOCKET_PATH: &str = "/run/central-operator/helper.sock";

pub(crate) const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

/// `LifecycleResult` — the typed result the lifecycle client returns.
#[derive(Debug, Clone, Default)]
pub struct LifecycleResult {
    pub operation_id: String,
    pub phase: String,
    pub state: String,
    pub reason_code: String,
    pub receipt_id: String,
}

/// `LifecycleClient` — `linuxLifecycleClient`: up/down/status against
/// the helper socket.
pub struct LifecycleClient {
    socket_path: String,
}

impl LifecycleClient {
    /// `NewLifecycleClient`.
    pub fn new(socket_path: impl Into<String>) -> Self {
        LifecycleClient {
            socket_path: socket_path.into(),
        }
    }

    /// `lifecycleOp` — upstream returns `(LifecycleResult, error)`: a
    /// denied envelope still carries whatever result details the helper
    /// sent, so the CLI's outcome mapping sees both halves. The `Some`
    /// string is the transport/denial error; `None` means the helper
    /// reported a successful operation.
    fn lifecycle_op(
        &self,
        verb: &str,
        req: &LifecycleRequest,
    ) -> (LifecycleResult, Option<String>) {
        let transport = |result: LifecycleResult, message: String| (result, Some(message));
        // Upstream `net.Dialer{Timeout: 5 * time.Second}` — the same
        // bounded connect the browser boundary uses, with the helper
        // client's own five-second dial budget.
        let mut conn = match super::browser::dial_unix_bounded(
            std::path::Path::new(&self.socket_path),
            DIAL_TIMEOUT,
        ) {
            Ok(conn) => conn,
            Err(e) => {
                return transport(LifecycleResult::default(), format!("helper: dial: {e}"));
            }
        };
        let _ = conn.set_read_timeout(Some(
            DIAL_TIMEOUT + super::server::helper_verb_deadline(verb),
        ));
        let _ = conn.set_write_timeout(Some(DIAL_TIMEOUT));
        let payload = match serde_json::to_vec(req) {
            Ok(payload) => payload,
            Err(e) => {
                return transport(
                    LifecycleResult::default(),
                    format!("helper: marshal lifecycle request: {e}"),
                );
            }
        };
        let msg = Request {
            operation_id: format!("client-lifecycle-{}", now_nanos()),
            verb: verb.to_owned(),
            payload: serde_json::value::RawValue::from_string(
                String::from_utf8(payload).unwrap_or_default(),
            )
            .ok(),
        };
        if let Err(e) = write_request(&mut conn, &msg) {
            return transport(
                LifecycleResult::default(),
                format!("helper: write request: {e}"),
            );
        }
        let resp = match read_response(&mut conn) {
            Ok(resp) => resp,
            Err(e) => {
                return transport(
                    LifecycleResult::default(),
                    format!("helper: read response: {e}"),
                );
            }
        };
        let mut details = LifecycleResultDetails::default();
        if let Some(raw) = &resp.result {
            match serde_json::from_str(raw.get()) {
                Ok(parsed) => details = parsed,
                Err(e) => {
                    return transport(
                        LifecycleResult::default(),
                        format!("helper: parse result: {e}"),
                    );
                }
            }
        }
        let mut result = LifecycleResult {
            operation_id: details.operation_id,
            phase: details.phase,
            state: details.state,
            reason_code: details.reason_code,
            receipt_id: details.receipt_id,
        };
        if resp.outcome != "success" {
            if result.reason_code.is_empty() {
                // A denial before the service ran — a failed ceremony,
                // a refused authorization — carries its code on the
                // envelope alone.
                result.reason_code = resp.reason.clone();
            }
            return transport(
                result,
                format!(
                    "helper: lifecycle {verb} denied: {} (reason: {})",
                    resp.outcome, resp.reason
                ),
            );
        }
        (result, None)
    }

    pub fn up(&self, req: &LifecycleRequest) -> (LifecycleResult, Option<String>) {
        self.lifecycle_op(super::verb::UP, req)
    }

    pub fn down(&self, req: &LifecycleRequest) -> (LifecycleResult, Option<String>) {
        self.lifecycle_op(super::verb::DOWN, req)
    }

    pub fn status(&self, req: &LifecycleRequest) -> (LifecycleResult, Option<String>) {
        self.lifecycle_op(super::verb::STATUS, req)
    }
}

/// `PrepareResult` — the operator's summary; the client carries the
/// helper's safe projection through unchanged rather than re-deriving
/// a next action from a phase string.
#[derive(Debug, Clone, Default)]
pub struct PrepareResult {
    pub state: String,
    pub code: String,
    pub operation_id: String,
    pub receipt_id: String,
    pub remediation: String,
    pub phase: String,
    pub selector: String,
    pub resume_required: bool,
    pub reused: i64,
    pub acquired: i64,
    pub advisory_id: String,
    pub safe_next_action: String,
    pub operation_elapsed_ms: i64,
    pub stage_timings: Vec<StageTiming>,
    pub resource_counters: Option<ResourceCounters>,
}

/// `prepareResultFrom` — both of `Prepare`'s return paths use it, so
/// a denied result carries the same summary a successful one does.
fn prepare_result_from(details: PrepareResultDetails) -> PrepareResult {
    PrepareResult {
        state: details.authority_state,
        code: details.reason_code,
        operation_id: details.operation_id,
        remediation: details.remediation,
        receipt_id: details.receipt_id,
        phase: details.phase,
        selector: details.selector,
        resume_required: details.resume_required,
        reused: details.reused,
        acquired: details.acquired,
        advisory_id: details.advisory_id,
        safe_next_action: details.safe_next_action,
        operation_elapsed_ms: details.operation_elapsed_ms,
        stage_timings: details.stage_timings,
        resource_counters: details.resource_counters,
    }
}

/// `Client` — `linuxClient`: the prepare verb's operator client.
pub struct PrepareClient {
    socket_path: String,
}

impl PrepareClient {
    /// `NewClient`.
    pub fn new(socket_path: impl Into<String>) -> Self {
        PrepareClient {
            socket_path: socket_path.into(),
        }
    }

    /// `Prepare` — dial, one prepare request, the wire projection
    /// back. Upstream returns `(result, error)`: a denial still
    /// carries whatever safe projection the helper sent, so the
    /// caller's outcome mapping sees both halves. The string is the
    /// transport/denial error; `None` means the helper reported a
    /// successful operation.
    pub fn prepare(&self, req: &PrepareRequest) -> (PrepareResult, Option<String>) {
        let mut conn = match super::browser::dial_unix_bounded(
            std::path::Path::new(&self.socket_path),
            DIAL_TIMEOUT,
        ) {
            Ok(conn) => conn,
            Err(e) => {
                return (PrepareResult::default(), Some(format!("helper: dial: {e}")));
            }
        };
        let _ = conn.set_read_timeout(Some(super::server::PREPARE_BUDGET));
        let _ = conn.set_write_timeout(Some(DIAL_TIMEOUT));
        let transport = |result: PrepareResult, message: String| (result, Some(message));
        let payload = match serde_json::to_vec(req) {
            Ok(payload) => payload,
            Err(e) => {
                return transport(
                    PrepareResult::default(),
                    format!("helper: marshal prepare request: {e}"),
                );
            }
        };
        let msg = Request {
            operation_id: format!("client-prepare-{}", now_nanos()),
            verb: super::verb::PREPARE.to_owned(),
            payload: serde_json::value::RawValue::from_string(
                String::from_utf8(payload).unwrap_or_default(),
            )
            .ok(),
        };
        if let Err(e) = write_request(&mut conn, &msg) {
            return transport(
                PrepareResult::default(),
                format!("helper: write request: {e}"),
            );
        }
        let resp = match read_response(&mut conn) {
            Ok(resp) => resp,
            Err(e) => {
                return transport(
                    PrepareResult::default(),
                    format!("helper: read response: {e}"),
                );
            }
        };
        let mut details = PrepareResultDetails::default();
        if let Some(raw) = &resp.result {
            match serde_json::from_str(raw.get()) {
                Ok(parsed) => details = parsed,
                Err(e) => {
                    return transport(
                        PrepareResult::default(),
                        format!("helper: parse result: {e}"),
                    );
                }
            }
        }
        if resp.outcome != "success" {
            let mut result = prepare_result_from(details);
            if result.code.is_empty() {
                // A denial's code lives on the envelope when no result
                // details came back — which is most of them.
                result.code = resp.reason.clone();
            }
            return transport(
                result,
                format!(
                    "helper: prepare denied: {} (reason: {})",
                    resp.outcome, resp.reason
                ),
            );
        }
        (prepare_result_from(details), None)
    }
}

/// `B06Error` — the two upstream `helperB06Client.call` error values,
/// kept as classes because that is all the dispatch reads: every
/// pre-response failure is `errors.New("helper unavailable")`; a
/// refused, non-zero, or unreadable answer is
/// `errors.New("authority denied")`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum B06Error {
    /// "helper unavailable" — socket-policy, dial, or write failure.
    Unavailable,
    /// "authority denied" — `ReadResponse` failed or the envelope is
    /// not a zero-exit `success`.
    Denied,
}

/// `helperB06Client` — the B06 operator client: the resolved socket
/// path plus the `SocketPolicy` that proves the socket the call dials
/// is the systemd-created one, not a replacement.
pub struct B06Client {
    socket_path: String,
    policy: SocketPolicy,
}

impl B06Client {
    /// The explicit composition — upstream's
    /// `helper.SocketPolicy{Path: socket, OwnerUID: 0, GroupGID: gid,
    /// Mode: 0660}` literal.
    pub fn new(socket_path: impl Into<String>, operator_gid: u32) -> Self {
        let socket_path = socket_path.into();
        B06Client {
            policy: SocketPolicy {
                path: socket_path.clone(),
                owner_uid: 0,
                group_gid: operator_gid,
                mode: 0o660,
            },
            socket_path,
        }
    }

    /// `newHelperB06Client` — `CENTRAL_HELPER_SOCKET` or the
    /// production socket for both `socket` and `policy.Path`;
    /// `CENTRAL_OPERATOR_GID` (`ParseUint(_, 10, 32)`, nonzero only)
    /// with the `os.Getgid()` fallback for the operator group.
    pub fn from_env(env: &dyn Fn(&str) -> Option<String>) -> Self {
        let gid = env("CENTRAL_OPERATOR_GID")
            .and_then(|v| super::daemon::parse_u32_strict(&v))
            .filter(|v| *v != 0)
            .unwrap_or_else(|| rustix::process::getegid().as_raw());
        Self::new(super::daemon::helper_socket_path(env), gid)
    }

    /// `Open` — `call(ctx, HelperBrowserOpen, nil)`: the nil payload
    /// becomes the literal `{}` on the wire.
    pub fn open(&self) -> Result<(), B06Error> {
        self.call(super::verb::BROWSER_OPEN, None)
    }

    /// `Show` — `call(ctx, HelperBootstrapShow,
    /// BootstrapShowRequest{})`: the empty request struct marshals to
    /// `{}` upstream, the same bytes `open` sends.
    pub fn show(&self) -> Result<(), B06Error> {
        let payload = serde_json::to_string(&BootstrapShowRequest::default())
            .ok()
            .and_then(|s| RawValue::from_string(s).ok());
        self.call(super::verb::BOOTSTRAP_SHOW, payload)
    }

    /// `call` — validate the socket policy (upstream's `policy.Path
    /// != ""` gate), dial with the five-second `net.Dialer` budget,
    /// write the one request line, read the one response line. Every
    /// failure before the response is "helper unavailable"; an
    /// unreadable response or a non-success envelope is "authority
    /// denied". Upstream sets no I/O deadline on this client — the
    /// helper answers or the connection breaks.
    fn call(&self, verb: &str, payload: Option<Box<RawValue>>) -> Result<(), B06Error> {
        if !self.policy.path.is_empty() && self.policy.validate().is_err() {
            return Err(B06Error::Unavailable);
        }
        let payload = payload.or_else(|| RawValue::from_string("{}".to_owned()).ok());
        let mut conn = super::browser::dial_unix_bounded(
            std::path::Path::new(&self.socket_path),
            DIAL_TIMEOUT,
        )
        .map_err(|_| B06Error::Unavailable)?;
        let msg = Request {
            operation_id: format!("central-b06-{}", now_nanos()),
            verb: verb.to_owned(),
            payload,
        };
        write_request(&mut conn, &msg).map_err(|_| B06Error::Unavailable)?;
        let resp = read_response(&mut conn).map_err(|_| B06Error::Denied)?;
        if resp.exit_code != 0 || resp.outcome != "success" {
            return Err(B06Error::Denied);
        }
        Ok(())
    }
}

/// `time.Now().UnixNano()` for the client-minted operation ids.
fn now_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The lifecycle client round-trips the helper's own wire shapes:
    /// a closed-matrix server answers `status` with the deferred
    /// service-unavailable response, and the client folds the envelope
    /// reason into `reason_code`.
    #[test]
    fn lifecycle_client_folds_envelope_reason() {
        let dir = std::env::temp_dir().join(format!("helper-client-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("h.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let server_thread = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let req = read_request(&mut conn).unwrap();
            assert_eq!(req.verb, super::super::verb::STATUS);
            write_response(
                &mut conn,
                &Response::deferred(&req.operation_id, "LIFECYCLE_SERVICE_UNAVAILABLE"),
            )
            .unwrap();
        });
        let client = LifecycleClient::new(path.to_string_lossy());
        let (result, err) = client.status(&LifecycleRequest::default());
        let err = err.expect("a deferred envelope is a denial");
        assert!(err.contains("LIFECYCLE_SERVICE_UNAVAILABLE"), "{err}");
        // The denied result still carries the envelope-folded code.
        assert_eq!(result.reason_code, "LIFECYCLE_SERVICE_UNAVAILABLE");
        server_thread.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Upstream's `(LifecycleResult, error)` contract: a denied
    /// envelope that carries result details returns BOTH halves — the
    /// operation/phase fields survive for the CLI's `omitempty`
    /// projection, and the details' own reason code wins over the
    /// envelope's.
    #[test]
    fn lifecycle_client_keeps_result_details_on_denied_response() {
        let dir = std::env::temp_dir().join(format!("helper-client-deny-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("h.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let server_thread = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let req = read_request(&mut conn).unwrap();
            assert_eq!(req.verb, super::super::verb::UP);
            let details = LifecycleResultDetails {
                operation_id: "life-op-9".to_owned(),
                phase: "failed".to_owned(),
                reason_code: "AUTHORITY_DENIED".to_owned(),
                receipt_id: "receipt-9".to_owned(),
                ..LifecycleResultDetails::default()
            };
            write_response(
                &mut conn,
                &Response::denied(&req.operation_id, 6, "AUTHORITY_DENIED").with_result(&details),
            )
            .unwrap();
        });
        let client = LifecycleClient::new(path.to_string_lossy());
        let (result, err) = client.up(&LifecycleRequest::default());
        let err = err.expect("a denied envelope is an error");
        assert!(err.contains("denied"), "{err}");
        assert_eq!(result.operation_id, "life-op-9");
        assert_eq!(result.phase, "failed");
        assert_eq!(result.receipt_id, "receipt-9");
        assert_eq!(result.reason_code, "AUTHORITY_DENIED");
        server_thread.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A helper-less host is the zero-result + dial-error pair the
    /// CLI maps to `LIFECYCLE_EXECUTION_FAILED`/`START_CENTRAL_HELPER`.
    #[test]
    fn lifecycle_client_dial_failure_returns_default_result_and_error() {
        let client = LifecycleClient::new(format!(
            "/nonexistent-central-helper-{}.sock",
            std::process::id()
        ));
        for op in ["up", "down", "status"] {
            let (result, err) = match op {
                "up" => client.up(&LifecycleRequest::default()),
                "down" => client.down(&LifecycleRequest::default()),
                _ => client.status(&LifecycleRequest::default()),
            };
            let err = err.expect("a missing socket is an error");
            assert!(err.starts_with("helper: dial:"), "{op}: {err}");
            assert!(result.operation_id.is_empty(), "{op}");
            assert!(result.reason_code.is_empty(), "{op}");
        }
    }

    // -- `helperB06Client` ---------------------------------------------------

    /// One-accept unix-socket server: reads the request, answers with
    /// `answer`, and returns the request it read so the test can assert
    /// the wire shape after the client call. The returned `PathBuf` is
    /// the socket's parent dir for cleanup.
    fn b06_socket_server(
        name: &str,
        answer: impl FnOnce(&Request) -> Response + Send + 'static,
    ) -> (std::path::PathBuf, std::thread::JoinHandle<Request>) {
        let dir =
            std::env::temp_dir().join(format!("b06-client-test-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("h.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let handle = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let req = read_request(&mut conn).unwrap();
            write_response(&mut conn, &answer(&req)).unwrap();
            req
        });
        (dir, handle)
    }

    /// Upstream's `helperB06Client{socket: socket}` test composition:
    /// an empty `policy.Path` skips `Validate` — exactly the gate
    /// `call` applies — so the client reaches the dial on a socket a
    /// test can own.
    fn b06_test_client(socket_path: String) -> B06Client {
        B06Client {
            socket_path,
            policy: SocketPolicy {
                path: String::new(),
                owner_uid: 0,
                group_gid: 0,
                mode: 0o660,
            },
        }
    }

    /// `Open` sends `browser-open` with a `central-b06-<nanos>`
    /// operation id and the literal `{}` payload; a zero-exit
    /// `success` envelope is `Ok(())`.
    #[test]
    fn b06_client_open_roundtrips_success() {
        let (dir, server) = b06_socket_server("open", |req| {
            assert_eq!(req.verb, super::super::verb::BROWSER_OPEN);
            assert!(
                req.operation_id.starts_with("central-b06-"),
                "{}",
                req.operation_id
            );
            assert_eq!(req.payload_bytes(), b"{}");
            Response::new(&req.operation_id, "success", 0, "")
        });
        let client = b06_test_client(dir.join("h.sock").to_string_lossy().into_owned());
        client.open().unwrap();
        server.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `Show` sends `bootstrap-show`; the marshaled empty request
    /// lands as the same `{}` payload `open` sends.
    #[test]
    fn b06_client_show_roundtrips_success() {
        let (dir, server) = b06_socket_server("show", |req| {
            assert_eq!(req.verb, super::super::verb::BOOTSTRAP_SHOW);
            assert_eq!(req.payload_bytes(), b"{}");
            Response::new(&req.operation_id, "success", 0, "")
        });
        let client = b06_test_client(dir.join("h.sock").to_string_lossy().into_owned());
        client.show().unwrap();
        server.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Upstream's `err != nil || ExitCode != 0 || Outcome !=
    /// "success"` rule: each leg alone produces the denied class —
    /// a denial, a zero-exit non-success outcome, and a success-named
    /// non-zero exit.
    #[test]
    fn b06_client_non_success_envelopes_are_denied() {
        for (name, outcome, exit_code, reason) in [
            ("denied", "denied", 7, "AUTHORITY_DENIED"),
            ("deferred", "deferred", 0, "UNSUPPORTED_IN_THIS_SLICE"),
            ("nonzero", "success", 1, ""),
        ] {
            let (dir, server) = b06_socket_server(name, move |req| {
                Response::new(&req.operation_id, outcome, exit_code, reason)
            });
            let client = b06_test_client(dir.join("h.sock").to_string_lossy().into_owned());
            assert_eq!(client.open(), Err(B06Error::Denied), "case {name}");
            server.join().unwrap();
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// An unreadable answer — the peer writes garbage, not a
    /// response line — is `ReadResponse`'s error branch: denied.
    #[test]
    fn b06_client_unreadable_response_is_denied() {
        let dir = std::env::temp_dir().join(format!("b06-client-garbage-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("h.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let _req = read_request(&mut conn).unwrap();
            use std::io::Write;
            conn.write_all(b"not-a-response\n").unwrap();
        });
        let client = b06_test_client(path.to_string_lossy().into_owned());
        assert_eq!(client.open(), Err(B06Error::Denied));
        server.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A dial to a path nothing listens on is the unavailable class —
    /// and so is a policy that cannot validate, which never reaches
    /// the dial at all.
    #[test]
    fn b06_client_dial_and_policy_failures_are_unavailable() {
        let missing = b06_test_client(format!(
            "/nonexistent-central-b06-{}.sock",
            std::process::id()
        ));
        assert_eq!(missing.open(), Err(B06Error::Unavailable));

        // A socket that exists but does not match the production
        // policy (wrong owner/mode) fails `Validate` before the dial —
        // a listener is bound so a dial would succeed, proving the
        // policy gate did the refusing.
        let dir = std::env::temp_dir().join(format!("b06-client-policy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("h.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let client = B06Client::new(path.to_string_lossy(), 0);
        assert_eq!(client.open(), Err(B06Error::Unavailable));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A policy satisfied by the socket on disk — real uid/gid from
    /// `lstat`, mode 0660 — passes `Validate` and reaches the helper.
    #[test]
    fn b06_client_validated_policy_reaches_the_helper() {
        let (dir, server) = b06_socket_server("policy", |req| {
            Response::new(&req.operation_id, "success", 0, "")
        });
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let path = dir.join("h.sock");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();
        let meta = std::fs::symlink_metadata(&path).unwrap();
        let client = B06Client {
            socket_path: path.to_string_lossy().into_owned(),
            policy: SocketPolicy {
                path: path.to_string_lossy().into_owned(),
                owner_uid: meta.uid(),
                group_gid: meta.gid(),
                mode: 0o660,
            },
        };
        client.open().unwrap();
        server.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
