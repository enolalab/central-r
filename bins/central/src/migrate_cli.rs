//! `central migrate up|resume|status|verify|reset` — upstream
//! `internal/command/migrate.go`'s `runMigrate` over
//! `cmd/central/migration_client.go`'s helper-delegating client.
//!
//! The serving CLI never receives a migration credential and never
//! opens PostgreSQL: every verb is a `migrate-launch` helper request
//! plus a `migrate-read-outcome` poll until the broker's durable
//! outcome goes terminal. A launch acceptance is never success
//! evidence. Until Task 2's `central-migration-launcherd` exists the
//! helper refuses `migrate-launch` and every verb fails closed —
//! there is no in-process fallback.

use std::io::Write;
use std::time::Instant;

use central_adapter_linux::helper::client::PRODUCTION_SOCKET_PATH;
use central_adapter_linux::helper::migration::{
    MigrationClient, MigrationClientError, MigrationLaunchOutcome,
};
use central_foundation::failure::ExitClass;
use central_foundation::local_result::LocalResult;
use serde::Serialize;

/// `command.MigrationDetails` — the `details` payload; every field
/// rides upstream's `omitempty` rule, never serialized as `null`.
#[derive(Debug, Default, Serialize)]
struct MigrationDetails {
    #[serde(skip_serializing_if = "String::is_empty")]
    operation_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    state: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    phase: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    safe_next_action: String,
    #[serde(skip_serializing_if = "is_false")]
    ready: bool,
    #[serde(skip_serializing_if = "is_false")]
    matches: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    drifts: Vec<String>,
    #[serde(skip_serializing_if = "is_false")]
    initialized: bool,
    #[serde(skip_serializing_if = "is_zero")]
    elapsed_ms: u64,
}

fn is_false(v: &bool) -> bool {
    !*v
}
fn is_zero(v: &u64) -> bool {
    *v == 0
}

/// `helperSocketPath` — `CENTRAL_HELPER_SOCKET` when non-empty, else
/// the production helper socket (same rule `local_cli` uses).
fn helper_socket_path() -> String {
    // Test seam — mutating process env is `unsafe` (Rust 2024) and
    // races parallel tests, so in-crate tests pin the socket here.
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

/// `runMigrate` — the dispatch arm for every `migrate-*` command id.
pub(crate) fn migrate(
    command_id: &str,
    tokens: &[String],
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> u8 {
    let started = Instant::now();
    let client = MigrationClient::new(helper_socket_path());
    let result = match command_id {
        "migrate-up" => handle_up(&client, command_id, started),
        "migrate-resume" => handle_resume(&client, command_id, tokens, started),
        "migrate-status" => handle_status(&client, command_id, started),
        "migrate-verify" => handle_verify(&client, command_id, started),
        "migrate-reset" => handle_reset(&client, command_id, tokens, started),
        _ => LocalResult::now(
            command_id,
            ExitClass::Incompatible,
            Some("UNKNOWN_MIGRATE_COMMAND".to_owned()),
            details_json(MigrationDetails {
                safe_next_action: "CHECK_COMMAND_GRAMMAR".to_owned(),
                elapsed_ms: elapsed_ms(started),
                ..MigrationDetails::default()
            }),
        ),
    };
    emit(result, stdout, stderr)
}

/// `cli.WriteResult` — one envelope line, exit 6 when it cannot be
/// written (upstream's "a command ending without a result" rule).
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

fn details_json(details: MigrationDetails) -> Option<serde_json::Value> {
    serde_json::to_value(details).ok()
}

/// `extractMigrationError` — the `MigrationError` triple verbatim.
fn failure_envelope(command_id: &str, err: &MigrationClientError, started: Instant) -> LocalResult {
    LocalResult::now(
        command_id,
        exit_class(err.exit_code),
        Some(err.reason.clone()),
        details_json(MigrationDetails {
            safe_next_action: err.safe_next_action.clone(),
            elapsed_ms: elapsed_ms(started),
            ..MigrationDetails::default()
        }),
    )
}

/// `mapSafeNextActionToExitCode` — the status readiness map.
fn map_safe_next_action(code: &str) -> u8 {
    match code {
        "READY" => ExitClass::Success.code(),
        "PROVISION_REQUIRED" => ExitClass::Denied.code(),
        "RESUME_REQUIRED" => ExitClass::Terminal.code(),
        // `REPAIR_REQUIRED` and every unknown row collapse onto
        // upstream's `ExitUnsupported` arm.
        _ => ExitClass::Incompatible.code(),
    }
}

/// Arbitrary upstream exit integer → the closed `ExitClass` enum;
/// unknown values fail closed at `Terminal` (6).
fn exit_class(code: u8) -> ExitClass {
    match code {
        0 => ExitClass::Success,
        2 => ExitClass::Usage,
        3 => ExitClass::Unavailable,
        4 => ExitClass::Timeout,
        5 => ExitClass::Incompatible,
        7 => ExitClass::Denied,
        _ => ExitClass::Terminal,
    }
}

/// `migrationResultFromOutcome` — the up/resume projection: the
/// operator result wins when present; a bare `succeeded` reads as
/// `completed` / `migrate status`.
fn migration_result_from_outcome(
    outcome: &MigrationLaunchOutcome,
) -> (String, String, String, String) {
    let mut state = outcome.state.clone();
    let mut phase = String::new();
    let mut safe_next = outcome.safe_next_action.clone();
    if let Some(op) = &outcome.operator_result {
        state = op.state.clone();
        phase = op.phase.clone();
        safe_next = op.safe_next_action.clone();
    } else if outcome.state == "succeeded" {
        state = "completed".to_owned();
        safe_next = "migrate status".to_owned();
    }
    (outcome.operation_id.clone(), state, phase, safe_next)
}

fn handle_up(client: &MigrationClient, command_id: &str, started: Instant) -> LocalResult {
    let operation_id = uuid::Uuid::now_v7().to_string();
    match client.launch("up", &operation_id) {
        Err(err) => failure_envelope(command_id, &err, started),
        Ok(outcome) => {
            let (op, state, phase, safe_next) = migration_result_from_outcome(&outcome);
            LocalResult::now(
                command_id,
                ExitClass::Success,
                Some("ok".to_owned()),
                details_json(MigrationDetails {
                    operation_id: op,
                    state,
                    phase,
                    safe_next_action: safe_next,
                    elapsed_ms: elapsed_ms(started),
                    ..MigrationDetails::default()
                }),
            )
        }
    }
}

/// `parseOperationFlag` — scan for `--operation=`; a duplicate or an
/// empty value is a parse error, absence is not.
fn parse_operation_flag(tokens: &[String]) -> Result<String, ()> {
    let mut operation_id = String::new();
    for token in tokens {
        if let Some(value) = token.strip_prefix("--operation=") {
            if !operation_id.is_empty() || value.is_empty() {
                return Err(());
            }
            operation_id = value.to_owned();
        }
    }
    Ok(operation_id)
}

/// `parseConfirmationFlag` — first `--confirm=` wins; absence or an
/// empty value both read as `""` upstream.
fn parse_confirmation_flag(tokens: &[String]) -> String {
    tokens
        .iter()
        .find_map(|t| t.strip_prefix("--confirm=").map(str::to_owned))
        .unwrap_or_default()
}

fn flag_error_envelope(
    command_id: &str,
    reason: &str,
    safe_next: &str,
    started: Instant,
) -> LocalResult {
    LocalResult::now(
        command_id,
        ExitClass::Usage,
        Some(reason.to_owned()),
        details_json(MigrationDetails {
            safe_next_action: safe_next.to_owned(),
            elapsed_ms: elapsed_ms(started),
            ..MigrationDetails::default()
        }),
    )
}

fn handle_resume(
    client: &MigrationClient,
    command_id: &str,
    tokens: &[String],
    started: Instant,
) -> LocalResult {
    let operation_id = match parse_operation_flag(tokens) {
        Err(()) => {
            return flag_error_envelope(
                command_id,
                "INVALID_OPERATION_FLAG",
                "CHECK_OPERATION_ID_FORMAT",
                started,
            );
        }
        Ok(id) if id.is_empty() => {
            return flag_error_envelope(
                command_id,
                "MISSING_OPERATION_FLAG",
                "PROVIDE_OPERATION_ID",
                started,
            );
        }
        Ok(id) => id,
    };
    match client.launch("resume", &operation_id) {
        Err(err) => failure_envelope(command_id, &err, started),
        Ok(outcome) => {
            let (op, state, phase, safe_next) = migration_result_from_outcome(&outcome);
            LocalResult::now(
                command_id,
                ExitClass::Success,
                Some("ok".to_owned()),
                details_json(MigrationDetails {
                    operation_id: op,
                    state,
                    phase,
                    safe_next_action: safe_next,
                    elapsed_ms: elapsed_ms(started),
                    ..MigrationDetails::default()
                }),
            )
        }
    }
}

fn handle_status(client: &MigrationClient, command_id: &str, started: Instant) -> LocalResult {
    let operation_id = uuid::Uuid::now_v7().to_string();
    let outcome = match client.launch("status", &operation_id) {
        Err(err) => return failure_envelope(command_id, &err, started),
        Ok(outcome) => outcome,
    };
    // A terminal outcome is not the operator result — status consumes
    // the typed row and rejects a command-mismatched one.
    let Some(op) = outcome.operator_result else {
        return failure_envelope(
            command_id,
            &MigrationClientError {
                exit_code: 3,
                reason: "MIGRATION_OPERATOR_RESULT_UNAVAILABLE".to_owned(),
                safe_next_action: "RUN_CENTRAL_MIGRATE_STATUS_TO_RECONCILE".to_owned(),
            },
            started,
        );
    };
    if op.command != "status" {
        return failure_envelope(
            command_id,
            &MigrationClientError {
                exit_code: 3,
                reason: "MIGRATION_OPERATOR_RESULT_UNAVAILABLE".to_owned(),
                safe_next_action: "RUN_CENTRAL_MIGRATE_STATUS_TO_RECONCILE".to_owned(),
            },
            started,
        );
    }
    let exit = if op.ready {
        ExitClass::Success
    } else {
        exit_class(map_safe_next_action(&op.safe_next_action))
    };
    LocalResult::now(
        command_id,
        exit,
        Some(op.safe_next_action.clone()),
        details_json(MigrationDetails {
            safe_next_action: op.safe_next_action,
            ready: op.ready,
            initialized: op.initialized,
            elapsed_ms: elapsed_ms(started),
            ..MigrationDetails::default()
        }),
    )
}

fn handle_verify(client: &MigrationClient, command_id: &str, started: Instant) -> LocalResult {
    let operation_id = uuid::Uuid::now_v7().to_string();
    let outcome = match client.launch("verify", &operation_id) {
        Err(err) => return failure_envelope(command_id, &err, started),
        Ok(outcome) => outcome,
    };
    let Some(op) = outcome.operator_result.filter(|r| r.command == "verify") else {
        return failure_envelope(
            command_id,
            &MigrationClientError {
                exit_code: 3,
                reason: "MIGRATION_OPERATOR_RESULT_UNAVAILABLE".to_owned(),
                safe_next_action: "RUN_CENTRAL_MIGRATE_VERIFY_TO_RECONCILE".to_owned(),
            },
            started,
        );
    };
    let exit = if op.matches {
        ExitClass::Success
    } else {
        ExitClass::Incompatible
    };
    LocalResult::now(
        command_id,
        exit,
        Some("ok".to_owned()),
        details_json(MigrationDetails {
            matches: op.matches,
            drifts: op.drifts,
            safe_next_action: "READY".to_owned(),
            elapsed_ms: elapsed_ms(started),
            ..MigrationDetails::default()
        }),
    )
}

fn handle_reset(
    client: &MigrationClient,
    command_id: &str,
    tokens: &[String],
    started: Instant,
) -> LocalResult {
    let operation_id = match parse_operation_flag(tokens) {
        Err(()) => {
            return flag_error_envelope(
                command_id,
                "INVALID_OPERATION_FLAG",
                "CHECK_OPERATION_ID_FORMAT",
                started,
            );
        }
        Ok(id) if id.is_empty() => {
            return flag_error_envelope(
                command_id,
                "MISSING_OPERATION_FLAG",
                "PROVIDE_OPERATION_ID",
                started,
            );
        }
        Ok(id) => id,
    };
    // Upstream parses the token here but the helper-delegated stub
    // drops it — only the in-process adapter decoded it, and this
    // process never carries the migration credential.
    let _confirmation_token = parse_confirmation_flag(tokens);
    match client.launch("reset", &operation_id) {
        Err(err) => failure_envelope(command_id, &err, started),
        Ok(_outcome) => LocalResult::now(
            command_id,
            ExitClass::Success,
            Some("ok".to_owned()),
            details_json(MigrationDetails {
                operation_id,
                safe_next_action: "READY".to_owned(),
                elapsed_ms: elapsed_ms(started),
                ..MigrationDetails::default()
            }),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn parse_operation_flag_accepts_one_value() {
        assert_eq!(
            parse_operation_flag(&tokens(&["--operation=abc"])).unwrap(),
            "abc"
        );
        assert_eq!(parse_operation_flag(&tokens(&[])).unwrap(), "");
        assert!(parse_operation_flag(&tokens(&["--operation="])).is_err());
        assert!(parse_operation_flag(&tokens(&["--operation=a", "--operation=b"])).is_err());
    }

    #[test]
    fn parse_confirmation_flag_first_wins() {
        assert_eq!(
            parse_confirmation_flag(&tokens(&["--confirm=tok", "--confirm=other"])),
            "tok"
        );
        assert_eq!(parse_confirmation_flag(&tokens(&[])), "");
    }

    #[test]
    fn safe_next_action_maps_to_upstream_exit_codes() {
        assert_eq!(map_safe_next_action("READY"), 0);
        assert_eq!(map_safe_next_action("PROVISION_REQUIRED"), 7);
        assert_eq!(map_safe_next_action("RESUME_REQUIRED"), 6);
        assert_eq!(map_safe_next_action("REPAIR_REQUIRED"), 5);
        assert_eq!(map_safe_next_action("ANYTHING_ELSE"), 5);
    }

    #[test]
    fn migration_result_projection_matches_upstream() {
        // Outcomes arrive over the wire — decode them like the helper
        // response does rather than constructing the adapter type.
        let bare: MigrationLaunchOutcome = serde_json::from_value(serde_json::json!({
            "launch_evidence_id": "e",
            "operation_id": "op",
            "state": "succeeded",
            "operator_result": null
        }))
        .unwrap();
        let (op, state, phase, next) = migration_result_from_outcome(&bare);
        assert_eq!(
            (op.as_str(), state.as_str(), phase.as_str(), next.as_str()),
            ("op", "completed", "", "migrate status")
        );

        let typed: MigrationLaunchOutcome = serde_json::from_value(serde_json::json!({
            "launch_evidence_id": "e",
            "operation_id": "op",
            "state": "succeeded",
            "operator_result": {
                "command": "up",
                "state": "ready",
                "phase": "baseline_installed",
                "safe_next_action": "READY"
            }
        }))
        .unwrap();
        let (_, state, phase, next) = migration_result_from_outcome(&typed);
        assert_eq!(
            (state.as_str(), phase.as_str(), next.as_str()),
            ("ready", "baseline_installed", "READY")
        );
    }

    #[test]
    fn details_omits_empty_fields_like_upstream() {
        let details = serde_json::to_value(MigrationDetails {
            safe_next_action: "READY".to_owned(),
            elapsed_ms: 12,
            ..MigrationDetails::default()
        })
        .unwrap();
        assert_eq!(details["safe_next_action"], "READY");
        assert_eq!(details["elapsed_ms"], 12);
        for absent in [
            "operation_id",
            "state",
            "phase",
            "ready",
            "matches",
            "drifts",
            "initialized",
        ] {
            assert!(details.get(absent).is_none(), "{absent} must be omitted");
        }
    }
}
