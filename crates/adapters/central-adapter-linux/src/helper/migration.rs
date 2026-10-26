//! `migrate-launch` / `migrate-read-outcome` helper client — the
//! socket half of upstream `cmd/central/migration_client.go`.
//!
//! `central migrate *` never receives a migration credential and never
//! opens PostgreSQL: every verb delegates to the PAM-gated helper's
//! `migrate-launch`, then polls `migrate-read-outcome` until the
//! broker's durable [`MigrationLaunchOutcome`] goes terminal (the
//! operator's own CLI cannot dial the broker's peer gate, so the root
//! helper forwards the read). A launch acceptance or a reaped child
//! is never success evidence; only the durable terminal outcome is.
//!
//! Until Task 2's `central-migration-launcherd` exists the helper has
//! no `migrate-launch` handler and this client fails closed with
//! `MIGRATION_HELPER_UNAVAILABLE` / `MIGRATION_LAUNCH_DENIED` — never
//! a silent in-process fallback.

use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use super::browser::dial_unix_bounded;
use super::protocol::{Request, Response, read_response, write_request};
use super::{server, verb};

const DIAL_TIMEOUT: Duration = Duration::from_secs(5);
/// Upstream `waitForMigrationOutcome`'s poll cadence.
const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// `helper.MigrationLaunchRequest` — the closed, credential-free
/// launch request; `operation_id` is bound by the enclosing helper
/// request (upstream `json:"-"`), never by arbitrary CLI flags.
#[derive(Debug, Clone, Serialize)]
pub struct MigrationLaunchRequest {
    /// The closed command (`up|resume|status|verify|reset`).
    pub command: String,
    /// Reserved args — always empty upstream.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
}

/// `helper.MigrationOutcomeReadRequest` — the one capability the
/// operator's polling loop has: the launch evidence ID its own
/// successful launch returned.
#[derive(Debug, Clone, Serialize)]
pub struct MigrationOutcomeReadRequest {
    /// The broker-issued launch evidence identity.
    pub launch_evidence_id: String,
}

/// `authority.B05MigrationLaunchResult` — the opaque broker-issued
/// evidence for the subsequent materialization; never signing
/// material or a credential path.
#[derive(Debug, Clone, Deserialize)]
pub struct MigrationLaunchResult {
    /// The operation the launch is bound to.
    pub operation_id: String,
    /// The launch evidence identity.
    pub launch_evidence_id: String,
}

/// `broker.MigrationLaunchOutcome` — broker-owned durable execution
/// evidence. A missing terminal state is intentionally ambiguous:
/// recovery must reconcile it rather than infer success from child
/// reaping or a lost client connection.
#[derive(Debug, Clone, Deserialize)]
pub struct MigrationLaunchOutcome {
    /// Launch evidence identity.
    pub launch_evidence_id: String,
    /// Operation identity.
    pub operation_id: String,
    /// `issued|started|succeeded|failed|ambiguous`.
    pub state: String,
    /// Failure reason, when present.
    #[serde(default)]
    pub reason: String,
    /// Operator-safe next action.
    #[serde(default)]
    pub safe_next_action: String,
    /// The dedicated operator's typed result — required for
    /// status/verify consumers.
    pub operator_result: Option<central_backup::app::MigrationOperatorResult>,
    /// Last broker update (RFC 3339; opaque here).
    #[serde(default)]
    pub updated_at: String,
}

impl MigrationLaunchOutcome {
    /// `outcome.Terminal()` — succeeded, failed, or ambiguous.
    #[must_use]
    pub fn terminal(&self) -> bool {
        matches!(self.state.as_str(), "succeeded" | "failed" | "ambiguous")
    }
}

/// `command.MigrationError` — the classified launch error: an exit
/// code, a machine reason, and the operator-safe next action. The
/// `central` CLI maps it verbatim into the result envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationClientError {
    /// Upstream `ExitCode`.
    pub exit_code: u8,
    /// Upstream `Reason`.
    pub reason: String,
    /// Upstream `SafeNextAction`.
    pub safe_next_action: String,
}

impl std::fmt::Display for MigrationClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for MigrationClientError {}

fn migration_error(exit_code: u8, reason: &str, safe_next_action: &str) -> MigrationClientError {
    MigrationClientError {
        exit_code,
        reason: reason.to_owned(),
        safe_next_action: safe_next_action.to_owned(),
    }
}

/// `migrationClientStub` — upstream's production client (the name is
/// historical; it IS the real client): `migrate-launch` over the
/// helper socket plus the `migrate-read-outcome` poll. Synchronous,
/// like upstream's blocking dial + 25 ms poll, with the helper's own
/// per-verb read budgets (`migrate-launch` 30 s, outcome 10 s).
pub struct MigrationClient {
    socket_path: String,
    /// Outcome-poll budget. Upstream polls on `context.Background()`
    /// (unbounded — the broker's own reconcile settles the row); tests
    /// pass a short bound through [`Self::with_poll_deadline`].
    poll_deadline: Option<Duration>,
}

impl MigrationClient {
    /// `NewMigrationClient` over the helper socket path.
    #[must_use]
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
            poll_deadline: None,
        }
    }

    /// Test seam — bound the outcome poll like upstream's `ctx`.
    #[must_use]
    pub fn with_poll_deadline(mut self, deadline: Duration) -> Self {
        self.poll_deadline = Some(deadline);
        self
    }

    /// One bounded helper round trip. The stage distinguishes the
    /// dial arm from the write/read arms — upstream maps them to
    /// different `SafeNextAction` hints on the launch path.
    fn call(
        &self,
        verb_name: &str,
        operation_id: &str,
        payload: &impl Serialize,
    ) -> Result<Response, CallError> {
        let mut conn: UnixStream = dial_unix_bounded(Path::new(&self.socket_path), DIAL_TIMEOUT)
            .map_err(|e| CallError {
                stage: CallStage::Dial,
                message: format!("dial helper {}: {e}", self.socket_path),
            })?;
        let read_budget = DIAL_TIMEOUT + server::helper_verb_deadline(verb_name);
        let _ = conn.set_read_timeout(Some(read_budget));
        let _ = conn.set_write_timeout(Some(DIAL_TIMEOUT));
        let payload: Option<Box<RawValue>> = serde_json::to_string(payload)
            .ok()
            .and_then(|raw| RawValue::from_string(raw).ok());
        let request = Request {
            operation_id: operation_id.to_owned(),
            verb: verb_name.to_owned(),
            payload,
        };
        write_request(&mut conn, &request).map_err(|e| CallError {
            stage: CallStage::Io,
            message: format!("write {verb_name}: {e}"),
        })?;
        read_response(&mut conn).map_err(|e| CallError {
            stage: CallStage::Io,
            message: format!("read {verb_name}: {e}"),
        })
    }

    /// `launch` — delegate one verb to the helper, then wait for the
    /// durable terminal outcome.
    ///
    /// # Errors
    /// Invalid operation ID (2), helper unavailable (3), launch
    /// denied (the helper's own exit class), outcome unavailable (3),
    /// a pending outcome past the poll bound (3), or a non-succeeded
    /// terminal state (6).
    pub fn launch(
        &self,
        command: &str,
        operation_id: &str,
    ) -> Result<MigrationLaunchOutcome, MigrationClientError> {
        if uuid::Uuid::parse_str(operation_id).is_err() {
            return Err(migration_error(
                2,
                "INVALID_OPERATION_FLAG",
                "PROVIDE_A_VALID_OPERATION_ID",
            ));
        }
        let response = self
            .call(
                verb::MIGRATE_LAUNCH,
                operation_id,
                &MigrationLaunchRequest {
                    command: command.to_owned(),
                    args: Vec::new(),
                },
            )
            .map_err(|e| {
                // Upstream: dial failure hints at the helper itself;
                // a broken write/read hints at retrying once repaired.
                let next = match e.stage {
                    CallStage::Dial => "START_OR_REPAIR_THE_CENTRAL_HELPER",
                    CallStage::Io => "RETRY_AFTER_REPAIRING_THE_CENTRAL_HELPER",
                };
                migration_error(3, "MIGRATION_HELPER_UNAVAILABLE", next)
            })?;
        if response.outcome != "success" || response.exit_code != 0 {
            // Upstream propagates the helper's raw exit int; codes
            // outside the closed {0,3,5,6,7} set fall back to the
            // operator-failure class rather than clamping into a
            // false success.
            return Err(migration_error(
                u8::try_from(response.exit_code).unwrap_or(6),
                "MIGRATION_LAUNCH_DENIED",
                "REAUTHENTICATE_AND_RUN_CENTRAL_MIGRATE_AGAIN",
            ));
        }
        let launch: MigrationLaunchResult = response
            .result
            .as_deref()
            .and_then(|raw| serde_json::from_str(raw.get()).ok())
            .ok_or_else(|| {
                migration_error(
                    3,
                    "MIGRATION_LAUNCH_OUTCOME_UNAVAILABLE",
                    "RETRY_OR_RUN_CENTRAL_MIGRATE_STATUS",
                )
            })?;
        if launch.operation_id != operation_id || launch.launch_evidence_id.is_empty() {
            return Err(migration_error(
                3,
                "MIGRATION_LAUNCH_OUTCOME_UNAVAILABLE",
                "RETRY_OR_RUN_CENTRAL_MIGRATE_STATUS",
            ));
        }
        self.wait_for_outcome(operation_id, &launch.launch_evidence_id)
    }

    /// `readMigrationOutcomeViaHelper` — one `migrate-read-outcome`
    /// request. Dial/denial/decode failures are plain strings — the
    /// poll treats them as transient exactly like upstream's
    /// `fmt.Errorf` arms. A not-yet-consumed evidence ID reads the
    /// same way (the operator has not reached the broker), which is
    /// why the poll retries rather than failing on the first unlucky
    /// read.
    ///
    /// # Errors
    /// Dial, write, read, denial, or decode failures.
    pub fn read_outcome(
        &self,
        operation_id: &str,
        evidence_id: &str,
    ) -> Result<MigrationLaunchOutcome, String> {
        let response = self
            .call(
                verb::MIGRATE_READ_OUTCOME,
                operation_id,
                &MigrationOutcomeReadRequest {
                    launch_evidence_id: evidence_id.to_owned(),
                },
            )
            .map_err(|e| e.message)?;
        // Upstream folds an empty `result` into the same "denied" arm
        // as a failure outcome — an empty payload is never evidence.
        if response.outcome != "success" || response.exit_code != 0 || response.result.is_none() {
            return Err(format!(
                "migration outcome: helper denied: {}",
                response.reason
            ));
        }
        let raw = response.result.as_deref().map_or("", |r| r.get());
        serde_json::from_str(raw).map_err(|e| format!("migration outcome: decode: {e}"))
    }

    /// `waitForMigrationOutcome` — poll the durable outcome until it
    /// goes terminal; only the terminal row is evidence.
    fn wait_for_outcome(
        &self,
        operation_id: &str,
        evidence_id: &str,
    ) -> Result<MigrationLaunchOutcome, MigrationClientError> {
        let deadline = self.poll_deadline.map(|d| Instant::now() + d);
        loop {
            match self.read_outcome(operation_id, evidence_id) {
                Ok(outcome) => {
                    if outcome.terminal() {
                        if outcome.state == "succeeded" {
                            return Ok(outcome);
                        }
                        // Upstream builds the reason verbatim —
                        // `"MIGRATION_OPERATOR_" + string(state)` —
                        // keeping the lowercase state suffix.
                        return Err(migration_error(
                            6,
                            &format!("MIGRATION_OPERATOR_{}", outcome.state),
                            &outcome.safe_next_action,
                        ));
                    }
                    // Non-terminal durable outcome — upstream's
                    // `ctx.Done()` arm maps a bounded poll to
                    // OUTCOME_PENDING.
                    if deadline.is_some_and(|d| Instant::now() >= d) {
                        return Err(migration_error(
                            3,
                            "MIGRATION_OUTCOME_PENDING",
                            "RUN_CENTRAL_MIGRATE_STATUS_TO_RECONCILE",
                        ));
                    }
                }
                Err(_) => {
                    // Transient (operator has not reached the broker
                    // yet); a bounded poll gives up with
                    // LAUNCH_OUTCOME_UNAVAILABLE like upstream's
                    // cancelled context arm.
                    if deadline.is_some_and(|d| Instant::now() >= d) {
                        return Err(migration_error(
                            3,
                            "MIGRATION_LAUNCH_OUTCOME_UNAVAILABLE",
                            "RETRY_OR_RUN_CENTRAL_MIGRATE_STATUS",
                        ));
                    }
                }
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }
}

/// Which half of the helper round trip failed — upstream uses it to
/// pick the `SafeNextAction` hint on the launch path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallStage {
    /// `net.Dial` arm → `START_OR_REPAIR_THE_CENTRAL_HELPER`.
    Dial,
    /// `conn.Write`/`Decode` arms → `RETRY_AFTER_REPAIRING_THE_CENTRAL_HELPER`.
    Io,
}

/// A helper round-trip failure tagged with its stage.
#[derive(Debug)]
struct CallError {
    stage: CallStage,
    message: String,
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;

    use super::*;

    fn op_id() -> String {
        uuid::Uuid::now_v7().to_string()
    }

    /// Serve `script` request/response pairs on a private socket; each
    /// accepted connection reads one request line and answers the next
    /// scripted response (or closes on `None`).
    fn serve(script: Vec<Option<Response>>) -> (String, std::thread::JoinHandle<()>) {
        let dir = std::env::temp_dir().join(format!("mig-cli-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("helper.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let handle = std::thread::spawn(move || {
            for scripted in script {
                let Ok((conn, _)) = listener.accept() else {
                    return;
                };
                let Some(resp) = scripted else { return };
                let mut reader = BufReader::new(conn.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() {
                    return;
                }
                let mut conn = conn;
                let mut body = serde_json::to_string(&resp).unwrap();
                body.push('\n');
                if conn.write_all(body.as_bytes()).is_err() {
                    return;
                }
            }
        });
        (path.to_string_lossy().into_owned(), handle)
    }

    fn ok_response(operation_id: &str, result: serde_json::Value) -> Response {
        Response {
            operation_id: operation_id.to_owned(),
            outcome: "success".to_owned(),
            exit_code: 0,
            reason: String::new(),
            result: RawValue::from_string(result.to_string()).ok(),
        }
    }

    #[test]
    fn unavailable_socket_maps_to_helper_unavailable() {
        let client = MigrationClient::new("/nonexistent/helper.sock");
        let err = client.launch("status", &op_id()).unwrap_err();
        assert_eq!(err.exit_code, 3);
        assert_eq!(err.reason, "MIGRATION_HELPER_UNAVAILABLE");
        assert_eq!(err.safe_next_action, "START_OR_REPAIR_THE_CENTRAL_HELPER");
    }

    #[test]
    fn invalid_operation_id_is_class_two() {
        let client = MigrationClient::new("/nonexistent/helper.sock");
        let err = client.launch("up", "not-a-uuid").unwrap_err();
        assert_eq!(err.exit_code, 2);
        assert_eq!(err.reason, "INVALID_OPERATION_FLAG");
    }

    #[test]
    fn launch_denial_propagates_helper_exit_class() {
        let op = op_id();
        let (path, _server) = serve(vec![Some(Response {
            operation_id: op.clone(),
            outcome: "failure".to_owned(),
            exit_code: 7,
            reason: "PAM_DENIED".to_owned(),
            result: None,
        })]);
        let client = MigrationClient::new(&path);
        let err = client.launch("up", &op).unwrap_err();
        assert_eq!(err.exit_code, 7);
        assert_eq!(err.reason, "MIGRATION_LAUNCH_DENIED");
        assert_eq!(
            err.safe_next_action,
            "REAUTHENTICATE_AND_RUN_CENTRAL_MIGRATE_AGAIN"
        );
    }

    #[test]
    fn succeeded_outcome_returns_terminal_result() {
        let op = op_id();
        let evidence = uuid::Uuid::now_v7().to_string();
        let outcome = serde_json::json!({
            "launch_evidence_id": evidence,
            "operation_id": op,
            "state": "succeeded",
            "safe_next_action": "",
            "operator_result": null,
            "updated_at": "2026-10-23T00:00:00Z"
        });
        let launch = serde_json::json!({
            "operation_id": op,
            "launch_evidence_id": evidence,
        });
        let (path, _server) = serve(vec![
            Some(ok_response(&op, launch)),
            Some(ok_response(&op, outcome)),
        ]);
        let client = MigrationClient::new(&path).with_poll_deadline(Duration::from_secs(5));
        let out = client.launch("status", &op).unwrap();
        assert_eq!(out.state, "succeeded");
        assert_eq!(out.operation_id, op);
    }

    #[test]
    fn pending_then_failed_outcome_is_terminal_six() {
        let op = op_id();
        let evidence = uuid::Uuid::now_v7().to_string();
        let launch = serde_json::json!({
            "operation_id": op,
            "launch_evidence_id": evidence,
        });
        let pending = serde_json::json!({
            "launch_evidence_id": evidence,
            "operation_id": op,
            "state": "started",
            "operator_result": null
        });
        let failed = serde_json::json!({
            "launch_evidence_id": evidence,
            "operation_id": op,
            "state": "failed",
            "reason": "OPERATOR_CRASHED",
            "safe_next_action": "RUN_CENTRAL_MIGRATE_STATUS",
            "operator_result": null
        });
        let (path, _server) = serve(vec![
            Some(ok_response(&op, launch)),
            Some(ok_response(&op, pending)),
            Some(ok_response(&op, failed)),
        ]);
        let client = MigrationClient::new(&path).with_poll_deadline(Duration::from_secs(5));
        let err = client.launch("up", &op).unwrap_err();
        assert_eq!(err.exit_code, 6);
        // Upstream builds the reason verbatim — lowercase state suffix.
        assert_eq!(err.reason, "MIGRATION_OPERATOR_failed");
        assert_eq!(err.safe_next_action, "RUN_CENTRAL_MIGRATE_STATUS");
    }

    #[test]
    fn poll_deadline_expiry_is_outcome_pending() {
        let op = op_id();
        // Launch accepted; every outcome poll answers a non-terminal
        // `started` row, so a bounded poll must surface
        // MIGRATION_OUTCOME_PENDING rather than hang.
        let dir = std::env::temp_dir().join(format!("mig-cli-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("helper.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let launch = ok_response(
            &op,
            serde_json::json!({
                "operation_id": op,
                "launch_evidence_id": uuid::Uuid::now_v7().to_string(),
            }),
        );
        let pending = ok_response(
            &op,
            serde_json::json!({
                "launch_evidence_id": uuid::Uuid::now_v7().to_string(),
                "operation_id": op,
                "state": "started",
                "operator_result": null,
            }),
        );
        std::thread::spawn(move || {
            let mut first = true;
            while let Ok((conn, _)) = listener.accept() {
                let mut reader = BufReader::new(conn.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() {
                    return;
                }
                let response = if first { &launch } else { &pending };
                first = false;
                let mut conn = conn;
                let mut body = serde_json::to_string(response).unwrap();
                body.push('\n');
                let _ = conn.write_all(body.as_bytes());
            }
        });
        let client = MigrationClient::new(path.to_string_lossy().into_owned())
            .with_poll_deadline(Duration::from_millis(120));
        let err = client.launch("status", &op).unwrap_err();
        assert_eq!(err.exit_code, 3);
        assert_eq!(err.reason, "MIGRATION_OUTCOME_PENDING");
        assert_eq!(
            err.safe_next_action,
            "RUN_CENTRAL_MIGRATE_STATUS_TO_RECONCILE"
        );
    }

    #[test]
    fn silent_outcome_socket_maps_to_outcome_unavailable() {
        let op = op_id();
        // Launch accepted; outcome polls hit connections that close
        // unanswered (transient reads — the operator has not reached
        // the broker), so a bounded poll surfaces
        // MIGRATION_LAUNCH_OUTCOME_UNAVAILABLE — upstream's cancelled
        // context arm.
        let dir = std::env::temp_dir().join(format!("mig-cli-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("helper.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let launch = ok_response(
            &op,
            serde_json::json!({
                "operation_id": op,
                "launch_evidence_id": uuid::Uuid::now_v7().to_string(),
            }),
        );
        std::thread::spawn(move || {
            let mut first = true;
            while let Ok((conn, _)) = listener.accept() {
                let mut reader = BufReader::new(conn.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() {
                    return;
                }
                if first {
                    first = false;
                    let mut conn = conn;
                    let mut body = serde_json::to_string(&launch).unwrap();
                    body.push('\n');
                    let _ = conn.write_all(body.as_bytes());
                }
                // later connections: drop — EOF on the client's read.
            }
        });
        let client = MigrationClient::new(path.to_string_lossy().into_owned())
            .with_poll_deadline(Duration::from_millis(120));
        let err = client.launch("status", &op).unwrap_err();
        assert_eq!(err.exit_code, 3);
        assert_eq!(err.reason, "MIGRATION_LAUNCH_OUTCOME_UNAVAILABLE");
    }

    #[test]
    fn outcome_wire_roundtrip() {
        let op = op_id();
        let raw = serde_json::json!({
            "launch_evidence_id": uuid::Uuid::now_v7().to_string(),
            "operation_id": op,
            "state": "ambiguous",
            "reason": "OPERATOR_UNREACHABLE",
            "safe_next_action": "RUN_CENTRAL_MIGRATE_STATUS",
            "operator_result": null,
            "updated_at": "2026-10-23T00:00:00Z"
        });
        let outcome: MigrationLaunchOutcome = serde_json::from_value(raw).unwrap();
        assert!(outcome.terminal());
        assert_eq!(outcome.reason, "OPERATOR_UNREACHABLE");
        assert!(outcome.operator_result.is_none());
    }
}
