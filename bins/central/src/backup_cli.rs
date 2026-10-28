//! `central backup create|verify|status` — upstream
//! `internal/command/backup.go`'s `runBackup*` handlers over
//! `cmd/central/backup_client.go`/`backup_read_client.go`'s
//! helper-delegating clients.
//!
//! The operator CLI never carries a repository descriptor, a
//! credential, or PostgreSQL access: `create` is one `backup-create`
//! helper request, `verify`/`status` are the locator-free
//! `backup-verify`/`backup-status` reads. Every details field rides
//! upstream's `omitempty` rule; the only always-present number is
//! `elapsed_ms`.

use std::io::Write;
use std::time::Instant;

use central_adapter_linux::helper::backup::{
    BACKUP_CREATE_WIRE_REASON_AUTHORIZATION_REQUIRED, BACKUP_CREATE_WIRE_REASON_WORKER_FAILED,
    BackupCreateClient, BackupCreateClientError, BackupCreateResult, BackupOperatorClient,
};
use central_adapter_linux::helper::client::PRODUCTION_SOCKET_PATH;
use central_foundation::failure::ExitClass;
use central_foundation::local_result::LocalResult;
use serde::Serialize;
use uuid::Uuid;

/// `command.BackupCreateDetails` — `elapsed_ms` is the only field
/// that is never omitted.
#[derive(Debug, Default, Serialize)]
struct BackupCreateDetails {
    #[serde(skip_serializing_if = "String::is_empty")]
    operation_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    backup_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    phase: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    safe_next_action: String,
    elapsed_ms: u64,
}

/// `command.BackupReadDetails` — verify/status share it.
#[derive(Debug, Default, Serialize)]
struct BackupReadDetails {
    #[serde(skip_serializing_if = "String::is_empty")]
    operation_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    backup_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    phase: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    status_reason: String,
    #[serde(skip_serializing_if = "is_false")]
    verified: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    safe_next_action: String,
    elapsed_ms: u64,
}

fn is_false(v: &bool) -> bool {
    !*v
}

/// `helperSocketPath` — same rule `migrate_cli`/`local_cli` use:
/// `CENTRAL_HELPER_SOCKET` when non-empty, else production.
pub(crate) fn helper_socket_path() -> String {
    #[cfg(test)]
    if let Some(path) = TEST_SOCKET_OVERRIDE.lock().unwrap().clone() {
        return path;
    }
    std::env::var("CENTRAL_HELPER_SOCKET")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| PRODUCTION_SOCKET_PATH.to_owned())
}

/// The census test's socket pin — `Some(path)` wins over both the
/// env override and the production default.
#[cfg(test)]
pub(crate) static TEST_SOCKET_OVERRIDE: std::sync::Mutex<Option<String>> =
    std::sync::Mutex::new(None);

/// One global pin means one stub at a time: every test that writes
/// [`TEST_SOCKET_OVERRIDE`] holds this for its whole pin→call span.
#[cfg(test)]
pub(crate) static TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// `Dispatch`'s backup arm — the three landed verbs plus the deferred
/// envelope for the maintenance verbs T9b owns.
pub(crate) fn backup(
    command_id: &str,
    tokens: &[String],
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> u8 {
    let started = Instant::now();
    let result = match command_id {
        "backup.create" => handle_create(command_id, tokens, started),
        "backup.verify" => handle_verify(command_id, tokens, started),
        "backup.status" => handle_status(command_id, tokens, started),
        // `runBackupDelete`/`runBackupPrune` — the D04 verbs; prune's
        // `apply` entry is shadowed by the shared `(backup, prune)`
        // registry key upstream-fashion, so the sub-action resolves
        // inside the handler.
        // `runBackupExport`/`runBackupImport` — the D02/D03 portable
        // verbs live beside the other destructive flows.
        "backup.export" => {
            return crate::destructive_cli::backup_export(command_id, tokens, stdout, stderr);
        }
        "backup.import" => {
            return crate::destructive_cli::backup_import(command_id, tokens, stdout, stderr);
        }
        "backup.delete" => {
            return crate::destructive_cli::backup_delete(command_id, tokens, stdout, stderr);
        }
        "backup.prune.plan" => {
            return crate::destructive_cli::backup_prune(command_id, tokens, stdout, stderr);
        }
        _ => LocalResult::unsupported(command_id),
    };
    emit(result, stdout, stderr)
}

/// `cli.WriteResult` — one envelope line, exit 6 when it cannot be
/// written.
fn emit(result: LocalResult, stdout: &mut impl Write, stderr: &mut impl Write) -> u8 {
    match result.write_json_line(stdout) {
        Ok(()) => result.exit_code,
        Err(err) => {
            let _ = writeln!(stderr, "central: could not write result envelope");
            let _ = err;
            ExitClass::Terminal.code()
        }
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis() as u64
}

fn create_details(details: BackupCreateDetails) -> Option<serde_json::Value> {
    serde_json::to_value(details).ok()
}

fn read_details(details: BackupReadDetails) -> Option<serde_json::Value> {
    serde_json::to_value(details).ok()
}

fn create_envelope(
    command_id: &str,
    exit: ExitClass,
    reason: &str,
    details: BackupCreateDetails,
) -> LocalResult {
    LocalResult::now(
        command_id,
        exit,
        Some(reason.to_owned()),
        create_details(details),
    )
}

fn read_envelope(
    command_id: &str,
    exit: ExitClass,
    reason: &str,
    details: BackupReadDetails,
) -> LocalResult {
    LocalResult::now(
        command_id,
        exit,
        Some(reason.to_owned()),
        read_details(details),
    )
}

/// `validUUIDv7` — parse + non-nil + v7 + canonical string, the one
/// check every positional backup identifier passes.
fn valid_uuid_v7(value: &str) -> bool {
    match Uuid::parse_str(value) {
        Ok(id) => !id.is_nil() && id.get_version_num() == 7 && id.to_string() == value,
        Err(_) => false,
    }
}

/// `NewBackupCreateError` — the closed (exit, reason, safe_next)
/// table; a pair outside it folds to the terminal failure.
fn create_error_result(exit_code: u8, reason: &str) -> (ExitClass, &'static str, &'static str) {
    match (exit_code, reason) {
        (3, "BACKUP_CREATE_DEPENDENCY_UNAVAILABLE") => (
            ExitClass::Unavailable,
            "BACKUP_CREATE_DEPENDENCY_UNAVAILABLE",
            "START_OR_REPAIR_CENTRAL_HELPER",
        ),
        (4, "BACKUP_CREATE_LOCK_TIMEOUT") => (
            ExitClass::Timeout,
            "BACKUP_CREATE_LOCK_TIMEOUT",
            "RETRY_BACKUP_CREATE",
        ),
        (6, "BACKUP_WORKER_FAILED") => (
            ExitClass::Terminal,
            "BACKUP_WORKER_FAILED",
            "CHECK_BACKUP_STATUS",
        ),
        (7, "BACKUP_CREATE_AUTHORITY_DENIED") => (
            ExitClass::Denied,
            "BACKUP_CREATE_AUTHORITY_DENIED",
            "REAUTHENTICATE_AND_RETRY",
        ),
        (7, "BACKUP_CREATE_AUTHORIZATION_REQUIRED") => (
            ExitClass::Denied,
            "BACKUP_CREATE_AUTHORIZATION_REQUIRED",
            "CONTACT_OPERATIONS",
        ),
        _ => (
            ExitClass::Terminal,
            "BACKUP_CREATE_FAILED",
            "CHECK_BACKUP_STATUS",
        ),
    }
}

/// `mapHelperBackupCreateError` — the adapter's closed (exit, reason)
/// triple, before `NewBackupCreateError` folds it.
fn map_create_error(err: &BackupCreateClientError) -> (u8, String) {
    let code = err.exit_code();
    let code_u8 = u8::try_from(code).unwrap_or(6);
    match code {
        3 | 5 => (3, "BACKUP_CREATE_DEPENDENCY_UNAVAILABLE".to_owned()),
        4 => (4, "BACKUP_CREATE_LOCK_TIMEOUT".to_owned()),
        7 => {
            if err.reason() == "DENY_SAFE_ACTIVE" {
                // `NewBackupCreateError(7, "DENY_SAFE_ACTIVE")` has no
                // matching case upstream — it folds to the generic
                // terminal failure below.
                return create_error_fold(7, "DENY_SAFE_ACTIVE");
            }
            if err.reason() == BACKUP_CREATE_WIRE_REASON_AUTHORIZATION_REQUIRED {
                return (
                    7,
                    BACKUP_CREATE_WIRE_REASON_AUTHORIZATION_REQUIRED.to_owned(),
                );
            }
            (7, "BACKUP_CREATE_AUTHORITY_DENIED".to_owned())
        }
        _ => {
            if code == 6 && err.reason() == BACKUP_CREATE_WIRE_REASON_WORKER_FAILED {
                return (6, BACKUP_CREATE_WIRE_REASON_WORKER_FAILED.to_owned());
            }
            (code_u8, "BACKUP_CREATE_FAILED".to_owned())
        }
    }
}

/// The `NewBackupCreateError` fold: the (exit, reason) pair runs
/// through the closed table; an unknown pair is the terminal failure.
fn create_error_fold(exit_code: u8, reason: &str) -> (u8, String) {
    let (_, r, _) = create_error_result(exit_code, reason);
    (exit_code_for_reason(r), r.to_owned())
}

fn exit_code_for_reason(reason: &str) -> u8 {
    match reason {
        "BACKUP_CREATE_DEPENDENCY_UNAVAILABLE" => 3,
        "BACKUP_CREATE_LOCK_TIMEOUT" => 4,
        "BACKUP_CREATE_AUTHORITY_DENIED" | "BACKUP_CREATE_AUTHORIZATION_REQUIRED" => 7,
        _ => 6,
    }
}

/// `runBackupCreate` — closed grammar (no positional arguments), a
/// command-owned v7 operation ID, one helper call, the sealed-result
/// recheck.
fn handle_create(command_id: &str, tokens: &[String], started: Instant) -> LocalResult {
    if !tokens.is_empty() {
        return create_envelope(
            command_id,
            ExitClass::Usage,
            "INVALID_BACKUP_CREATE_GRAMMAR",
            BackupCreateDetails {
                safe_next_action: "RUN_CENTRAL_BACKUP_CREATE_WITHOUT_ARGUMENTS".to_owned(),
                elapsed_ms: elapsed_ms(started),
                ..BackupCreateDetails::default()
            },
        );
    }
    let operation_id = Uuid::now_v7().to_string();
    let client = BackupCreateClient::new(helper_socket_path());
    match client.create_backup(&operation_id) {
        Err(err) => {
            let (wire_exit, wire_reason) = map_create_error(&err);
            let (exit, reason, next) = create_error_result(wire_exit, &wire_reason);
            create_envelope(
                command_id,
                exit,
                reason,
                BackupCreateDetails {
                    operation_id,
                    safe_next_action: next.to_owned(),
                    elapsed_ms: elapsed_ms(started),
                    ..BackupCreateDetails::default()
                },
            )
        }
        Ok(result) => {
            if !valid_backup_create_result(&operation_id, &result) {
                return create_envelope(
                    command_id,
                    ExitClass::Terminal,
                    "BACKUP_CREATE_RESULT_INVALID",
                    BackupCreateDetails {
                        operation_id,
                        safe_next_action: "CHECK_BACKUP_STATUS".to_owned(),
                        elapsed_ms: elapsed_ms(started),
                        ..BackupCreateDetails::default()
                    },
                );
            }
            create_envelope(
                command_id,
                ExitClass::Success,
                "ok",
                BackupCreateDetails {
                    operation_id: result.operation_id,
                    backup_id: result.backup_id,
                    phase: result.phase,
                    safe_next_action: "BACKUP_READY".to_owned(),
                    elapsed_ms: elapsed_ms(started),
                },
            )
        }
    }
}

/// `validBackupCreateResult` — both UUIDs parse non-nil, the
/// operation echoes, the phase is sealed.
fn valid_backup_create_result(operation_id: &str, result: &BackupCreateResult) -> bool {
    let operation_ok = Uuid::parse_str(&result.operation_id)
        .map(|id| !id.is_nil())
        .unwrap_or(false);
    let backup_ok = Uuid::parse_str(&result.backup_id)
        .map(|id| !id.is_nil())
        .unwrap_or(false);
    operation_ok && backup_ok && result.operation_id == operation_id && result.phase == "sealed"
}

/// `NewBackupOperatorError` — the verify/status closed table.
fn operator_error_result(exit_code: u8, verify: bool) -> (ExitClass, &'static str) {
    match (exit_code, verify) {
        (3, true) | (5, true) => (
            ExitClass::Unavailable,
            "BACKUP_VERIFY_DEPENDENCY_UNAVAILABLE",
        ),
        (7, true) => (ExitClass::Denied, "BACKUP_VERIFY_AUTHORITY_DENIED"),
        (_, true) => (ExitClass::Terminal, "BACKUP_VERIFY_FAILED"),
        (3, false) | (5, false) => (
            ExitClass::Unavailable,
            "BACKUP_STATUS_DEPENDENCY_UNAVAILABLE",
        ),
        (7, false) => (ExitClass::Denied, "BACKUP_STATUS_AUTHORITY_DENIED"),
        (_, false) => (ExitClass::Terminal, "BACKUP_STATUS_FAILED"),
    }
}

/// `runBackupVerify` — `central backup verify <backup-uuid-v7>`;
/// the helper's sealed attestation rechecked at the boundary.
fn handle_verify(command_id: &str, tokens: &[String], started: Instant) -> LocalResult {
    let [backup_id] = tokens else {
        return verify_grammar_envelope(command_id, started);
    };
    if !valid_uuid_v7(backup_id) {
        return verify_grammar_envelope(command_id, started);
    }
    let client = BackupOperatorClient::new(helper_socket_path());
    match client.verify_backup(backup_id) {
        Err(err) => {
            let (exit, reason) =
                operator_error_result(u8::try_from(err.exit_code()).unwrap_or(6), true);
            read_envelope(
                command_id,
                exit,
                reason,
                BackupReadDetails {
                    backup_id: backup_id.clone(),
                    safe_next_action: "CHECK_BACKUP_STATUS".to_owned(),
                    elapsed_ms: elapsed_ms(started),
                    ..BackupReadDetails::default()
                },
            )
        }
        Ok(result) => {
            if !valid_uuid_v7(&result.operation_id)
                || result.backup_id != *backup_id
                || result.phase != "sealed"
                || !result.verified
            {
                return read_envelope(
                    command_id,
                    ExitClass::Terminal,
                    "BACKUP_VERIFY_RESULT_INVALID",
                    BackupReadDetails {
                        backup_id: backup_id.clone(),
                        safe_next_action: "CHECK_BACKUP_STATUS".to_owned(),
                        elapsed_ms: elapsed_ms(started),
                        ..BackupReadDetails::default()
                    },
                );
            }
            read_envelope(
                command_id,
                ExitClass::Success,
                "ok",
                BackupReadDetails {
                    operation_id: result.operation_id,
                    backup_id: result.backup_id,
                    phase: result.phase,
                    verified: true,
                    safe_next_action: "BACKUP_VERIFIED".to_owned(),
                    elapsed_ms: elapsed_ms(started),
                    ..BackupReadDetails::default()
                },
            )
        }
    }
}

fn verify_grammar_envelope(command_id: &str, started: Instant) -> LocalResult {
    read_envelope(
        command_id,
        ExitClass::Usage,
        "INVALID_BACKUP_VERIFY_GRAMMAR",
        BackupReadDetails {
            safe_next_action: "RUN_CENTRAL_BACKUP_VERIFY_WITH_BACKUP_UUID".to_owned(),
            elapsed_ms: elapsed_ms(started),
            ..BackupReadDetails::default()
        },
    )
}

/// `runBackupStatus` — `central backup status <operation-uuid-v7>`;
/// the phase→reason projection rechecked exactly.
fn handle_status(command_id: &str, tokens: &[String], started: Instant) -> LocalResult {
    let [operation_id] = tokens else {
        return status_grammar_envelope(command_id, started);
    };
    if !valid_uuid_v7(operation_id) {
        return status_grammar_envelope(command_id, started);
    }
    let client = BackupOperatorClient::new(helper_socket_path());
    match client.read_backup_status(operation_id) {
        Err(err) => {
            let (exit, reason) =
                operator_error_result(u8::try_from(err.exit_code()).unwrap_or(6), false);
            read_envelope(
                command_id,
                exit,
                reason,
                BackupReadDetails {
                    operation_id: operation_id.clone(),
                    safe_next_action: "RETRY_BACKUP_STATUS".to_owned(),
                    elapsed_ms: elapsed_ms(started),
                    ..BackupReadDetails::default()
                },
            )
        }
        Ok(result) => {
            if !valid_backup_status_result(operation_id, &result.phase, &result.reason)
                || result.operation_id != *operation_id
                || !valid_uuid_v7(&result.backup_id)
            {
                return read_envelope(
                    command_id,
                    ExitClass::Terminal,
                    "BACKUP_STATUS_RESULT_INVALID",
                    BackupReadDetails {
                        operation_id: operation_id.clone(),
                        safe_next_action: "RETRY_BACKUP_STATUS".to_owned(),
                        elapsed_ms: elapsed_ms(started),
                        ..BackupReadDetails::default()
                    },
                );
            }
            read_envelope(
                command_id,
                ExitClass::Success,
                "ok",
                BackupReadDetails {
                    operation_id: result.operation_id,
                    backup_id: result.backup_id,
                    status_reason: result.reason,
                    safe_next_action: backup_status_next_action(&result.phase).to_owned(),
                    phase: result.phase,
                    elapsed_ms: elapsed_ms(started),
                    ..BackupReadDetails::default()
                },
            )
        }
    }
}

fn status_grammar_envelope(command_id: &str, started: Instant) -> LocalResult {
    read_envelope(
        command_id,
        ExitClass::Usage,
        "INVALID_BACKUP_STATUS_GRAMMAR",
        BackupReadDetails {
            safe_next_action: "RUN_CENTRAL_BACKUP_STATUS_WITH_OPERATION_UUID".to_owned(),
            elapsed_ms: elapsed_ms(started),
            ..BackupReadDetails::default()
        },
    )
}

/// `validBackupStatusResult`'s phase→reason half.
fn valid_backup_status_result(_operation_id: &str, phase: &str, reason: &str) -> bool {
    match phase {
        "sealed" => reason == "BACKUP_SEALED",
        "failed" => reason == "BACKUP_FAILED",
        "planned" | "admitted" | "dumping" | "inventory" | "sealing" => {
            reason == "BACKUP_IN_PROGRESS"
        }
        _ => false,
    }
}

/// `backupStatusNextAction`.
fn backup_status_next_action(phase: &str) -> &'static str {
    match phase {
        "sealed" => "BACKUP_READY",
        "failed" => "CREATE_NEW_BACKUP",
        _ => "CHECK_BACKUP_STATUS",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_v7_gate_is_exact() {
        let id = Uuid::now_v7();
        assert!(valid_uuid_v7(&id.to_string()));
        assert!(!valid_uuid_v7(&Uuid::nil().to_string()));
        assert!(!valid_uuid_v7(&id.to_string().to_uppercase()));
        assert!(!valid_uuid_v7("not-a-uuid"));
        assert!(!valid_uuid_v7(&id.simple().to_string()));
    }

    #[test]
    fn create_error_table_is_closed() {
        assert_eq!(
            create_error_result(3, "BACKUP_CREATE_DEPENDENCY_UNAVAILABLE"),
            (
                ExitClass::Unavailable,
                "BACKUP_CREATE_DEPENDENCY_UNAVAILABLE",
                "START_OR_REPAIR_CENTRAL_HELPER"
            )
        );
        assert_eq!(
            create_error_result(4, "BACKUP_CREATE_LOCK_TIMEOUT"),
            (
                ExitClass::Timeout,
                "BACKUP_CREATE_LOCK_TIMEOUT",
                "RETRY_BACKUP_CREATE"
            )
        );
        assert_eq!(
            create_error_result(6, "BACKUP_WORKER_FAILED"),
            (
                ExitClass::Terminal,
                "BACKUP_WORKER_FAILED",
                "CHECK_BACKUP_STATUS"
            )
        );
        assert_eq!(
            create_error_result(7, "BACKUP_CREATE_AUTHORITY_DENIED"),
            (
                ExitClass::Denied,
                "BACKUP_CREATE_AUTHORITY_DENIED",
                "REAUTHENTICATE_AND_RETRY"
            )
        );
        assert_eq!(
            create_error_result(7, "BACKUP_CREATE_AUTHORIZATION_REQUIRED"),
            (
                ExitClass::Denied,
                "BACKUP_CREATE_AUTHORIZATION_REQUIRED",
                "CONTACT_OPERATIONS"
            )
        );
        // Unknown pairs fold to the terminal failure — including the
        // upstream `DENY_SAFE_ACTIVE` path.
        assert_eq!(
            create_error_result(7, "DENY_SAFE_ACTIVE"),
            (
                ExitClass::Terminal,
                "BACKUP_CREATE_FAILED",
                "CHECK_BACKUP_STATUS"
            )
        );
    }

    #[test]
    fn operator_error_table_is_closed() {
        assert_eq!(
            operator_error_result(3, true),
            (
                ExitClass::Unavailable,
                "BACKUP_VERIFY_DEPENDENCY_UNAVAILABLE"
            )
        );
        assert_eq!(
            operator_error_result(5, true),
            (
                ExitClass::Unavailable,
                "BACKUP_VERIFY_DEPENDENCY_UNAVAILABLE"
            )
        );
        assert_eq!(
            operator_error_result(7, true),
            (ExitClass::Denied, "BACKUP_VERIFY_AUTHORITY_DENIED")
        );
        assert_eq!(
            operator_error_result(6, true),
            (ExitClass::Terminal, "BACKUP_VERIFY_FAILED")
        );
        assert_eq!(
            operator_error_result(3, false),
            (
                ExitClass::Unavailable,
                "BACKUP_STATUS_DEPENDENCY_UNAVAILABLE"
            )
        );
        assert_eq!(
            operator_error_result(7, false),
            (ExitClass::Denied, "BACKUP_STATUS_AUTHORITY_DENIED")
        );
        assert_eq!(
            operator_error_result(2, false),
            (ExitClass::Terminal, "BACKUP_STATUS_FAILED")
        );
    }

    #[test]
    fn status_projection_and_next_action() {
        for (phase, reason) in [
            ("sealed", "BACKUP_SEALED"),
            ("failed", "BACKUP_FAILED"),
            ("planned", "BACKUP_IN_PROGRESS"),
            ("sealing", "BACKUP_IN_PROGRESS"),
        ] {
            assert!(valid_backup_status_result("op", phase, reason), "{phase}");
        }
        assert!(!valid_backup_status_result("op", "sealed", "BACKUP_FAILED"));
        assert!(!valid_backup_status_result(
            "op",
            "weird",
            "BACKUP_IN_PROGRESS"
        ));
        assert_eq!(backup_status_next_action("sealed"), "BACKUP_READY");
        assert_eq!(backup_status_next_action("failed"), "CREATE_NEW_BACKUP");
        assert_eq!(backup_status_next_action("dumping"), "CHECK_BACKUP_STATUS");
    }

    #[test]
    fn details_omit_empty_fields_like_upstream() {
        let details = serde_json::to_value(BackupCreateDetails {
            safe_next_action: "BACKUP_READY".to_owned(),
            elapsed_ms: 3,
            ..BackupCreateDetails::default()
        })
        .unwrap();
        assert_eq!(details["safe_next_action"], "BACKUP_READY");
        assert_eq!(details["elapsed_ms"], 3);
        for absent in ["operation_id", "backup_id", "phase"] {
            assert!(details.get(absent).is_none(), "{absent} must be omitted");
        }
        let read = serde_json::to_value(BackupReadDetails {
            verified: true,
            elapsed_ms: 1,
            ..BackupReadDetails::default()
        })
        .unwrap();
        assert_eq!(read["verified"], true);
        assert!(read.get("status_reason").is_none());
    }

    // -------------------------------------------------------------------
    // In-process helper stub — the real Unix transport and wire bytes,
    // no supervisor, so the CLI surface is exercised end to end here.
    // -------------------------------------------------------------------

    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixListener;

    /// A one-shot helper: binds a unix socket, answers each accepted
    /// connection with `respond(request_line)`, and stops when the
    /// listener's own end is dropped. Returns the socket path.
    struct StubHelper {
        _dir: String,
        path: String,
    }

    fn stub_helper(
        respond: impl Fn(&serde_json::Value) -> central_adapter_linux::helper::Response + Send + 'static,
    ) -> StubHelper {
        let dir = std::env::temp_dir().join(format!("cb-cli-stub-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("helper.sock").to_string_lossy().into_owned();
        let listener = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            while let Ok((mut conn, _)) = listener.accept() {
                let mut line = String::new();
                if BufReader::new(&mut conn).read_line(&mut line).is_err() {
                    return;
                }
                let req: serde_json::Value =
                    serde_json::from_str(&line).unwrap_or(serde_json::Value::Null);
                let response = respond(&req);
                let _ =
                    central_adapter_linux::helper::protocol::write_response(&mut conn, &response);
            }
        });
        StubHelper {
            _dir: dir.to_string_lossy().into_owned(),
            path,
        }
    }

    fn pin_socket(path: &str) {
        *TEST_SOCKET_OVERRIDE.lock().unwrap() = Some(path.to_owned());
    }

    fn run_backup(command_id: &str, tokens: &[&str]) -> (u8, serde_json::Value) {
        let toks: Vec<String> = tokens.iter().map(|s| (*s).to_owned()).collect();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = backup(command_id, &toks, &mut stdout, &mut stderr);
        (
            code,
            serde_json::from_slice::<serde_json::Value>(&stdout).unwrap_or(serde_json::Value::Null),
        )
    }

    /// C01 through the operator surface: `backup-create` answered
    /// `sealed` yields the exact success envelope — operation echoed,
    /// backup id, phase, `BACKUP_READY`.
    #[test]
    fn create_over_a_real_socket_reports_sealed() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let operation = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let seen = operation.clone();
        let stub = stub_helper(move |req| {
            *seen.lock().unwrap() = req["operation_id"].as_str().unwrap_or("").to_owned();
            central_adapter_linux::helper::Response::new(
                req["operation_id"].as_str().unwrap_or(""),
                "success",
                0,
                "",
            )
            .with_result(&BackupCreateResult {
                operation_id: req["operation_id"].as_str().unwrap_or("").to_owned(),
                backup_id: uuid::Uuid::now_v7().to_string(),
                phase: "sealed".to_owned(),
            })
        });
        pin_socket(&stub.path);
        let (code, env) = run_backup("backup.create", &[]);
        assert_eq!(code, 0, "{env}");
        assert_eq!(env["reason"], "ok");
        assert_eq!(
            env["details"]["operation_id"],
            serde_json::Value::from(operation.lock().unwrap().as_str())
        );
        assert!(valid_uuid_v7(env["details"]["backup_id"].as_str().unwrap()));
        assert_eq!(env["details"]["phase"], "sealed");
        assert_eq!(env["details"]["safe_next_action"], "BACKUP_READY");
        assert!(env["details"]["elapsed_ms"].is_number());
    }

    /// A denied `backup-create` rides its exit class and the
    /// whitelisted reason token — never helper diagnostic text.
    #[test]
    fn create_denied_maps_exit_and_reason() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let stub = stub_helper(|req| {
            central_adapter_linux::helper::Response::new(
                req["operation_id"].as_str().unwrap_or(""),
                "denied",
                7,
                "AUTHORITY_DENIED",
            )
        });
        pin_socket(&stub.path);
        let (code, env) = run_backup("backup.create", &[]);
        assert_eq!(code, 7);
        assert_eq!(env["reason"], "BACKUP_CREATE_AUTHORITY_DENIED");
        assert_eq!(
            env["details"]["safe_next_action"],
            "REAUTHENTICATE_AND_RETRY"
        );
    }

    /// C03 through the operator surface: `backup-verify` of a sealed
    /// record and `backup-status` of the operation — exact wire
    /// binding (the payload's `backup_id` must equal the envelope op).
    #[test]
    fn verify_and_status_over_a_real_socket() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let backup_id = uuid::Uuid::now_v7().to_string();
        let operation_id = uuid::Uuid::now_v7().to_string();
        let bid = backup_id.clone();
        let oid = operation_id.clone();
        let stub = stub_helper(move |req| {
            let verb = req["verb"].as_str().unwrap_or("");
            let op = req["operation_id"].as_str().unwrap_or("");
            match verb {
                "backup-verify" => {
                    central_adapter_linux::helper::Response::new(op, "success", 0, "").with_result(
                        &central_adapter_linux::helper::backup::BackupVerifyResult {
                            operation_id: oid.clone(),
                            backup_id: op.to_owned(),
                            phase: "sealed".to_owned(),
                            verified: true,
                        },
                    )
                }
                "backup-status" => {
                    central_adapter_linux::helper::Response::new(op, "success", 0, "").with_result(
                        &central_adapter_linux::helper::backup::BackupStatusResult {
                            operation_id: op.to_owned(),
                            backup_id: bid.clone(),
                            phase: "sealed".to_owned(),
                            reason: "BACKUP_SEALED".to_owned(),
                        },
                    )
                }
                _ => central_adapter_linux::helper::Response::new(op, "error", 6, ""),
            }
        });
        pin_socket(&stub.path);
        let (code, env) = run_backup("backup.verify", &[&backup_id]);
        assert_eq!(code, 0, "{env}");
        assert_eq!(env["details"]["verified"], true);
        assert_eq!(env["details"]["backup_id"], backup_id.as_str());
        assert_eq!(env["details"]["safe_next_action"], "BACKUP_VERIFIED");
        let (code, env) = run_backup("backup.status", &[&operation_id]);
        assert_eq!(code, 0, "{env}");
        assert_eq!(env["details"]["phase"], "sealed");
        assert_eq!(env["details"]["status_reason"], "BACKUP_SEALED");
        assert_eq!(env["details"]["safe_next_action"], "BACKUP_READY");
    }

    /// A non-verified verify result is refused inside the adapter's
    /// own recheck (exit 6), which the command maps to the generic
    /// `BACKUP_VERIFY_FAILED` — never `BACKUP_VERIFY_RESULT_INVALID`.
    #[test]
    fn verify_rejects_a_non_sealed_projection() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let backup_id = uuid::Uuid::now_v7().to_string();
        let stub = stub_helper(|req| {
            central_adapter_linux::helper::Response::new(
                req["operation_id"].as_str().unwrap_or(""),
                "success",
                0,
                "",
            )
            .with_result(&central_adapter_linux::helper::backup::BackupVerifyResult {
                operation_id: uuid::Uuid::now_v7().to_string(),
                backup_id: req["operation_id"].as_str().unwrap_or("").to_owned(),
                phase: "sealed".to_owned(),
                verified: false,
            })
        });
        pin_socket(&stub.path);
        let (code, env) = run_backup("backup.verify", &[&backup_id]);
        // The adapter refuses a non-verified projection at its own
        // recheck (exit 6), which the command maps to the generic
        // verify failure — the terminal fold is the honest answer.
        assert_eq!(code, 6);
        assert_eq!(env["reason"], "BACKUP_VERIFY_FAILED");
    }
}
