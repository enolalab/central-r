//! `client_linux.go` + `socket_path.go` — the operator-side clients
//! that dial the helper's Unix socket. The R5 slice carries the
//! lifecycle and prepare clients plus the raw write/read helpers every
//! other client (init.rs already carries `InitClient`) is built on.
//! The R6 clients — wipe, backup, restore, export/import, delete,
//! prune, state-audit, rescue, maintenance, security-update — are
//! deferred with their verbs: a client for a verb the matrix answers
//! `UNSUPPORTED_IN_THIS_SLICE` would only add untested surface.

use super::protocol::*;
use std::time::Duration;

/// `ProductionSocketPath` — where
/// `packaging/systemd/central-helper.socket` listens. Its directory is
/// 0711; the socket itself is 0660 root:<operator primary group>,
/// which `SocketPolicy::validate` enforces at startup.
pub const PRODUCTION_SOCKET_PATH: &str = "/run/central-operator/helper.sock";

const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

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
}
