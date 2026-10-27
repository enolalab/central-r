//! `central restore verify|apply|resume|abandon` — upstream
//! `internal/command/restore.go`'s `runRestore*` handlers over
//! `cmd/central/restore_operator_client.go`'s helper-delegating
//! client.
//!
//! The operator CLI never carries a ticket, authorization, target,
//! path, or credential: each verb is one helper request over the
//! socket, and which backup is verified or which operation is
//! applied, resumed, or abandoned is resolved on the privileged
//! side. Every details field rides upstream's `omitempty` rule; the
//! only always-present number is `elapsed_ms`.

use std::io::Write;
use std::time::Instant;

use central_adapter_linux::helper::client::PRODUCTION_SOCKET_PATH;
use central_adapter_linux::helper::restore::{
    RestoreOperationResult, RestoreOperatorClient, RestoreOperatorClientError,
};
use central_foundation::failure::ExitClass;
use central_foundation::local_result::LocalResult;
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

// The closed operator reason vocabulary — `internal/command/restore.go`'s
// constants, kept verb-prefixed so verify and apply cannot drift into one
// vocabulary.
const RESTORE_VERIFY_REASON_DEPENDENCY_UNAVAILABLE: &str = "RESTORE_VERIFY_DEPENDENCY_UNAVAILABLE";
const RESTORE_VERIFY_REASON_FAILED: &str = "RESTORE_VERIFY_FAILED";
const RESTORE_VERIFY_REASON_AUTHORITY_DENIED: &str = "RESTORE_VERIFY_AUTHORITY_DENIED";
const RESTORE_APPLY_REASON_DEPENDENCY_UNAVAILABLE: &str = "RESTORE_APPLY_DEPENDENCY_UNAVAILABLE";
const RESTORE_APPLY_REASON_FAILED: &str = "RESTORE_APPLY_FAILED";
const RESTORE_APPLY_REASON_AUTHORITY_DENIED: &str = "RESTORE_APPLY_AUTHORITY_DENIED";
const RESTORE_APPLY_REASON_LOCK_TIMEOUT: &str = "RESTORE_APPLY_LOCK_TIMEOUT";
const RESTORE_RESUME_REASON_DEPENDENCY_UNAVAILABLE: &str = "RESTORE_RESUME_DEPENDENCY_UNAVAILABLE";
const RESTORE_RESUME_REASON_FAILED: &str = "RESTORE_RESUME_FAILED";
const RESTORE_RESUME_REASON_AUTHORITY_DENIED: &str = "RESTORE_RESUME_AUTHORITY_DENIED";
const RESTORE_RESUME_REASON_LOCK_TIMEOUT: &str = "RESTORE_RESUME_LOCK_TIMEOUT";

// Abandonment has no lock-timeout reason: it acquires no target
// exclusion, because it touches neither PostgreSQL nor the repository.
const RESTORE_ABANDON_REASON_DEPENDENCY_UNAVAILABLE: &str =
    "RESTORE_ABANDON_DEPENDENCY_UNAVAILABLE";
const RESTORE_ABANDON_REASON_FAILED: &str = "RESTORE_ABANDON_FAILED";
const RESTORE_ABANDON_REASON_AUTHORITY_DENIED: &str = "RESTORE_ABANDON_AUTHORITY_DENIED";

// The two resolver refusals. Apply, resume, and abandonment all resolve
// the single live protected operation themselves — the operator names
// nothing — so these are the two ways that resolution can decline.
const RESTORE_REASON_NO_LIVE_OPERATION: &str = "RESTORE_NO_LIVE_OPERATION";
const RESTORE_REASON_LIVE_OPERATION_AMBIGUOUS: &str = "RESTORE_LIVE_OPERATION_AMBIGUOUS";

// Verify's own pair. `restore verify` resolves the single admissible
// sealed backup itself, so it declines the same two ways.
const RESTORE_VERIFY_REASON_NO_CANDIDATE: &str = "RESTORE_NO_ADMISSIBLE_BACKUP";
const RESTORE_VERIFY_REASON_CANDIDATE_AMBIGUOUS: &str = "RESTORE_BACKUP_CANDIDATE_AMBIGUOUS";

const RESTORE_VERIFY_REASON_STATE_INVALID: &str = "RESTORE_VERIFY_STATE_INVALID";
const RESTORE_VERIFY_REASON_MEDIA_INVALID: &str = "RESTORE_VERIFY_MEDIA_INVALID";
const RESTORE_VERIFY_REASON_CAPACITY_INSUFFICIENT: &str = "RESTORE_VERIFY_CAPACITY_INSUFFICIENT";
const RESTORE_VERIFY_REASON_ENGINE_UNAVAILABLE: &str = "RESTORE_VERIFY_ENGINE_UNAVAILABLE";
const RESTORE_VERIFY_REASON_TARGET_ADMISSION_STALE: &str = "RESTORE_VERIFY_TARGET_ADMISSION_STALE";

/// `DenySafeActiveWireReason` — the one gate reason every helper wire
/// client admits through to the operator unchanged.
const DENY_SAFE_ACTIVE_WIRE_REASON: &str = "DENY_SAFE_ACTIVE";

/// `command.RestoreVerifyDetails` — the only restore-verify payload
/// emitted to stdout.
#[derive(Debug, Default, Serialize)]
struct RestoreVerifyDetails {
    #[serde(skip_serializing_if = "String::is_empty")]
    ticket_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    backup_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    expires_at: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    safe_next_action: String,
    elapsed_ms: u64,
}

/// `command.RestoreOperationDetails` — the shared apply/resume/abandon
/// payload. `unresolved_quarantines` is `omitempty`: the helper's
/// receipt carries no quarantine census, and inventing one would let
/// the operator's result assert a state this process never observed.
#[derive(Debug, Default, Serialize)]
struct RestoreOperationDetails {
    #[serde(skip_serializing_if = "String::is_empty")]
    operation_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    phase: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    checkpoint: String,
    #[serde(skip_serializing_if = "is_zero")]
    unresolved_quarantines: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    safe_next_action: String,
    elapsed_ms: u64,
}

fn is_zero(v: &u64) -> bool {
    *v == 0
}

/// `helperSocketPath` — same rule `backup_cli`/`migrate_cli` use:
/// `CENTRAL_HELPER_SOCKET` when non-empty, else production.
fn helper_socket_path() -> String {
    #[cfg(test)]
    if let Some(path) = crate::backup_cli::TEST_SOCKET_OVERRIDE
        .lock()
        .unwrap()
        .clone()
    {
        return path;
    }
    std::env::var("CENTRAL_HELPER_SOCKET")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| PRODUCTION_SOCKET_PATH.to_owned())
}

/// `Dispatch`'s restore arm — the four C03–C05 verbs.
pub(crate) fn restore(
    command_id: &str,
    tokens: &[String],
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> u8 {
    let started = Instant::now();
    let result = match command_id {
        "restore.verify" => handle_verify(command_id, tokens, started),
        "restore.apply" => handle_apply(command_id, tokens, started),
        "restore.resume" => handle_resume(command_id, tokens, started),
        "restore.abandon" => handle_abandon(command_id, tokens, started),
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

fn verify_details(details: RestoreVerifyDetails) -> Option<serde_json::Value> {
    serde_json::to_value(details).ok()
}

fn operation_details(details: RestoreOperationDetails) -> Option<serde_json::Value> {
    serde_json::to_value(details).ok()
}

fn verify_envelope(
    command_id: &str,
    exit: ExitClass,
    reason: &str,
    details: RestoreVerifyDetails,
) -> LocalResult {
    LocalResult::now(
        command_id,
        exit,
        Some(reason.to_owned()),
        verify_details(details),
    )
}

fn operation_envelope(
    command_id: &str,
    exit: ExitClass,
    reason: &str,
    details: RestoreOperationDetails,
) -> LocalResult {
    LocalResult::now(
        command_id,
        exit,
        Some(reason.to_owned()),
        operation_details(details),
    )
}

// ---------------------------------------------------------------------------
// `command.RestoreError` — the closed (exit, reason) table.
// ---------------------------------------------------------------------------

/// `command.RestoreError` — the closed, safe failure the mapping
/// produces. Callers cannot supply output text.
struct RestoreError {
    exit: ExitClass,
    reason: &'static str,
}

/// `NewRestoreError` accepts only known exit/reason pairs and
/// otherwise reduces the failure to a terminal one, so an adapter
/// cannot widen the closed set. `exit` is the [`ExitClass`] the pair
/// must match exactly.
fn new_restore_error(exit: ExitClass, reason: &'static str) -> RestoreError {
    if valid_restore_failure(exit, reason) {
        RestoreError { exit, reason }
    } else {
        RestoreError {
            exit: ExitClass::Terminal,
            reason: RESTORE_APPLY_REASON_FAILED,
        }
    }
}

/// `validRestoreFailure` — the whole (exit, reason) matrix upstream
/// enumerates: dependency-unavailable at 3, lock-timeout at 4,
/// authority-denied at 7, and every terminal reason at 6.
fn valid_restore_failure(exit: ExitClass, reason: &str) -> bool {
    match reason {
        RESTORE_VERIFY_REASON_DEPENDENCY_UNAVAILABLE
        | RESTORE_APPLY_REASON_DEPENDENCY_UNAVAILABLE
        | RESTORE_RESUME_REASON_DEPENDENCY_UNAVAILABLE
        | RESTORE_ABANDON_REASON_DEPENDENCY_UNAVAILABLE
        | RESTORE_VERIFY_REASON_ENGINE_UNAVAILABLE => exit == ExitClass::Unavailable,
        RESTORE_VERIFY_REASON_AUTHORITY_DENIED
        | RESTORE_APPLY_REASON_AUTHORITY_DENIED
        | RESTORE_RESUME_REASON_AUTHORITY_DENIED
        | RESTORE_ABANDON_REASON_AUTHORITY_DENIED
        | DENY_SAFE_ACTIVE_WIRE_REASON => exit == ExitClass::Denied,
        RESTORE_APPLY_REASON_LOCK_TIMEOUT | RESTORE_RESUME_REASON_LOCK_TIMEOUT => {
            exit == ExitClass::Timeout
        }
        RESTORE_VERIFY_REASON_FAILED
        | RESTORE_APPLY_REASON_FAILED
        | RESTORE_RESUME_REASON_FAILED
        | RESTORE_ABANDON_REASON_FAILED
        | RESTORE_VERIFY_REASON_STATE_INVALID
        | RESTORE_VERIFY_REASON_MEDIA_INVALID
        | RESTORE_VERIFY_REASON_CAPACITY_INSUFFICIENT
        | RESTORE_VERIFY_REASON_TARGET_ADMISSION_STALE
        | RESTORE_REASON_NO_LIVE_OPERATION
        | RESTORE_REASON_LIVE_OPERATION_AMBIGUOUS
        | RESTORE_VERIFY_REASON_NO_CANDIDATE
        | RESTORE_VERIFY_REASON_CANDIDATE_AMBIGUOUS => exit == ExitClass::Terminal,
        _ => false,
    }
}

/// `NewRestoreVerifyRefusalError` maps the restore engine's sanitized,
/// locator-free refusal cause onto the closed set of verify-specific
/// operator reasons this module accepts.
fn new_restore_verify_refusal_error(cause: &str) -> RestoreError {
    match cause {
        "RESTORE_STATE_INVALID" => {
            new_restore_error(ExitClass::Terminal, RESTORE_VERIFY_REASON_STATE_INVALID)
        }
        "RESTORE_MEDIA_INVALID" => {
            new_restore_error(ExitClass::Terminal, RESTORE_VERIFY_REASON_MEDIA_INVALID)
        }
        "RESTORE_CAPACITY_INSUFFICIENT" => new_restore_error(
            ExitClass::Terminal,
            RESTORE_VERIFY_REASON_CAPACITY_INSUFFICIENT,
        ),
        "RESTORE_TARGET_ADMISSION_STALE" => new_restore_error(
            ExitClass::Terminal,
            RESTORE_VERIFY_REASON_TARGET_ADMISSION_STALE,
        ),
        "RESTORE_ENGINE_UNAVAILABLE" => new_restore_error(
            ExitClass::Unavailable,
            RESTORE_VERIFY_REASON_ENGINE_UNAVAILABLE,
        ),
        _ => new_restore_error(ExitClass::Terminal, RESTORE_VERIFY_REASON_FAILED),
    }
}

// ---------------------------------------------------------------------------
// `helperRestoreOperatorClient` — the wire-client failure mapping.
// ---------------------------------------------------------------------------

/// `mapHelperRestoreVerifyError` is separate from
/// [`map_helper_restore_error`] because verify has its own refusal
/// vocabulary in both directions: the engine's four sanitized causes,
/// which [`new_restore_verify_refusal_error`] already maps, and the
/// candidate resolver's two.
fn map_helper_restore_verify_error(failure: &RestoreOperatorClientError) -> RestoreError {
    match failure.reason() {
        DENY_SAFE_ACTIVE_WIRE_REASON => {
            return new_restore_error(ExitClass::Denied, DENY_SAFE_ACTIVE_WIRE_REASON);
        }
        "RESTORE_NO_ADMISSIBLE_BACKUP" => {
            return new_restore_error(ExitClass::Terminal, RESTORE_VERIFY_REASON_NO_CANDIDATE);
        }
        "RESTORE_BACKUP_CANDIDATE_AMBIGUOUS" => {
            return new_restore_error(
                ExitClass::Terminal,
                RESTORE_VERIFY_REASON_CANDIDATE_AMBIGUOUS,
            );
        }
        _ => {}
    }
    // The engine's own typed causes reach the operator through the
    // mapping `internal/command` already owns, so the four
    // verify-specific reasons stay mutually distinguishable at the
    // terminal.
    if !failure.engine_refusal().is_empty() {
        return new_restore_verify_refusal_error(failure.engine_refusal());
    }
    match failure.exit_code() {
        3 | 5 => new_restore_error(
            ExitClass::Unavailable,
            RESTORE_VERIFY_REASON_DEPENDENCY_UNAVAILABLE,
        ),
        7 => new_restore_error(ExitClass::Denied, RESTORE_VERIFY_REASON_AUTHORITY_DENIED),
        _ => new_restore_error(ExitClass::Terminal, RESTORE_VERIFY_REASON_FAILED),
    }
}

/// `mapHelperRestoreError` takes the four per-verb reasons as
/// arguments so apply, resume, and abandonment share one mapping
/// without sharing one vocabulary. `lock` empty is abandonment's own
/// spelling of "no lock-timeout reason exists for this verb".
fn map_helper_restore_error(
    failure: &RestoreOperatorClientError,
    dependency: &'static str,
    lock: &'static str,
    denied: &'static str,
    failed: &'static str,
) -> RestoreError {
    // A resolver refusal is checked before the exit class, because it
    // is the more specific fact: the exit class only says "terminal".
    match failure.reason() {
        DENY_SAFE_ACTIVE_WIRE_REASON => {
            return new_restore_error(ExitClass::Denied, DENY_SAFE_ACTIVE_WIRE_REASON);
        }
        "RESTORE_NO_LIVE_OPERATION" => {
            return new_restore_error(ExitClass::Terminal, RESTORE_REASON_NO_LIVE_OPERATION);
        }
        "RESTORE_LIVE_OPERATION_AMBIGUOUS" => {
            return new_restore_error(ExitClass::Terminal, RESTORE_REASON_LIVE_OPERATION_AMBIGUOUS);
        }
        _ => {}
    }
    match failure.exit_code() {
        3 | 5 => new_restore_error(ExitClass::Unavailable, dependency),
        4 => {
            if lock.is_empty() {
                new_restore_error(ExitClass::Terminal, failed)
            } else {
                new_restore_error(ExitClass::Timeout, lock)
            }
        }
        7 => new_restore_error(ExitClass::Denied, denied),
        _ => new_restore_error(ExitClass::Terminal, failed),
    }
}

// ---------------------------------------------------------------------------
// `runRestore*` handlers.
// ---------------------------------------------------------------------------

/// `runRestoreVerify` — closed grammar (no positional arguments), one
/// helper call, the result recheck.
fn handle_verify(command_id: &str, tokens: &[String], started: Instant) -> LocalResult {
    if !tokens.is_empty() {
        return verify_envelope(
            command_id,
            ExitClass::Usage,
            "INVALID_RESTORE_VERIFY_GRAMMAR",
            RestoreVerifyDetails {
                safe_next_action: "RUN_CENTRAL_RESTORE_VERIFY_WITHOUT_ARGUMENTS".to_owned(),
                elapsed_ms: elapsed_ms(started),
                ..RestoreVerifyDetails::default()
            },
        );
    }
    let client = RestoreOperatorClient::new(helper_socket_path());
    match client.verify_restore(None) {
        Err(failure) => {
            let mapped = map_helper_restore_verify_error(&failure);
            verify_envelope(
                command_id,
                mapped.exit,
                mapped.reason,
                RestoreVerifyDetails {
                    safe_next_action: "CHECK_RECOVERY_MEDIA_AND_RETRY_VERIFY".to_owned(),
                    elapsed_ms: elapsed_ms(started),
                    ..RestoreVerifyDetails::default()
                },
            )
        }
        Ok(result) => {
            let Ok(expires_at) = OffsetDateTime::parse(&result.expires_at, &Rfc3339) else {
                return verify_envelope(
                    command_id,
                    ExitClass::Terminal,
                    "RESTORE_VERIFY_RESULT_INVALID",
                    RestoreVerifyDetails {
                        safe_next_action: "CHECK_RECOVERY_MEDIA_AND_RETRY_VERIFY".to_owned(),
                        elapsed_ms: elapsed_ms(started),
                        ..RestoreVerifyDetails::default()
                    },
                );
            };
            if !valid_restore_verify_result(&result.ticket_id, &result.backup_id, expires_at) {
                return verify_envelope(
                    command_id,
                    ExitClass::Terminal,
                    "RESTORE_VERIFY_RESULT_INVALID",
                    RestoreVerifyDetails {
                        safe_next_action: "CHECK_RECOVERY_MEDIA_AND_RETRY_VERIFY".to_owned(),
                        elapsed_ms: elapsed_ms(started),
                        ..RestoreVerifyDetails::default()
                    },
                );
            }
            verify_envelope(
                command_id,
                ExitClass::Success,
                "ok",
                RestoreVerifyDetails {
                    ticket_id: result.ticket_id,
                    backup_id: result.backup_id,
                    expires_at: expires_at
                        .format(&Rfc3339)
                        .unwrap_or_else(|_| result.expires_at.clone()),
                    safe_next_action: "RUN_CENTRAL_RESTORE_APPLY_BEFORE_TICKET_EXPIRY".to_owned(),
                    elapsed_ms: elapsed_ms(started),
                },
            )
        }
    }
}

fn handle_apply(command_id: &str, tokens: &[String], started: Instant) -> LocalResult {
    if !tokens.is_empty() {
        return operation_envelope(
            command_id,
            ExitClass::Usage,
            "INVALID_RESTORE_APPLY_GRAMMAR",
            RestoreOperationDetails {
                safe_next_action: "RUN_CENTRAL_RESTORE_APPLY_WITHOUT_ARGUMENTS".to_owned(),
                elapsed_ms: elapsed_ms(started),
                ..RestoreOperationDetails::default()
            },
        );
    }
    let client = RestoreOperatorClient::new(helper_socket_path());
    match client.apply_restore(None) {
        Err(failure) => {
            let mapped = map_helper_restore_error(
                &failure,
                RESTORE_APPLY_REASON_DEPENDENCY_UNAVAILABLE,
                RESTORE_APPLY_REASON_LOCK_TIMEOUT,
                RESTORE_APPLY_REASON_AUTHORITY_DENIED,
                RESTORE_APPLY_REASON_FAILED,
            );
            write_restore_operation_result(
                command_id,
                started,
                None,
                Some(mapped),
                RESTORE_APPLY_REASON_FAILED,
                "RESTORE_APPLY_RESULT_INVALID",
            )
        }
        Ok(result) => write_restore_operation_result(
            command_id,
            started,
            Some(&result),
            None,
            RESTORE_APPLY_REASON_FAILED,
            "RESTORE_APPLY_RESULT_INVALID",
        ),
    }
}

fn handle_resume(command_id: &str, tokens: &[String], started: Instant) -> LocalResult {
    if !tokens.is_empty() {
        return operation_envelope(
            command_id,
            ExitClass::Usage,
            "INVALID_RESTORE_RESUME_GRAMMAR",
            RestoreOperationDetails {
                safe_next_action: "RUN_CENTRAL_RESTORE_RESUME_WITHOUT_ARGUMENTS".to_owned(),
                elapsed_ms: elapsed_ms(started),
                ..RestoreOperationDetails::default()
            },
        );
    }
    let client = RestoreOperatorClient::new(helper_socket_path());
    match client.resume_restore(None) {
        Err(failure) => {
            let mapped = map_helper_restore_error(
                &failure,
                RESTORE_RESUME_REASON_DEPENDENCY_UNAVAILABLE,
                RESTORE_RESUME_REASON_LOCK_TIMEOUT,
                RESTORE_RESUME_REASON_AUTHORITY_DENIED,
                RESTORE_RESUME_REASON_FAILED,
            );
            write_restore_operation_result(
                command_id,
                started,
                None,
                Some(mapped),
                RESTORE_RESUME_REASON_FAILED,
                "RESTORE_RESUME_RESULT_INVALID",
            )
        }
        Ok(result) => write_restore_operation_result(
            command_id,
            started,
            Some(&result),
            None,
            RESTORE_RESUME_REASON_FAILED,
            "RESTORE_RESUME_RESULT_INVALID",
        ),
    }
}

/// `runRestoreAbandon` reports ADR 0016's terminal outcome. It does
/// not share [`write_restore_operation_result`] with apply and
/// resume, because those two treat every phase but ready as a
/// failure and abandonment's only success is "abandoned".
fn handle_abandon(command_id: &str, tokens: &[String], started: Instant) -> LocalResult {
    if !tokens.is_empty() {
        return operation_envelope(
            command_id,
            ExitClass::Usage,
            "INVALID_RESTORE_ABANDON_GRAMMAR",
            RestoreOperationDetails {
                safe_next_action: "RUN_CENTRAL_RESTORE_ABANDON_WITHOUT_ARGUMENTS".to_owned(),
                elapsed_ms: elapsed_ms(started),
                ..RestoreOperationDetails::default()
            },
        );
    }
    let client = RestoreOperatorClient::new(helper_socket_path());
    match client.abandon_restore(None) {
        Err(failure) => {
            let mapped = map_helper_restore_error(
                &failure,
                RESTORE_ABANDON_REASON_DEPENDENCY_UNAVAILABLE,
                // Abandonment acquires no target exclusion, so it has
                // no lock-timeout reason. The empty lock argument
                // says exactly that: a lock exit class from the
                // helper collapses to the generic terminal failure.
                "",
                RESTORE_ABANDON_REASON_AUTHORITY_DENIED,
                RESTORE_ABANDON_REASON_FAILED,
            );
            operation_envelope(
                command_id,
                mapped.exit,
                mapped.reason,
                RestoreOperationDetails {
                    safe_next_action: "INSPECT_PROTECTED_RECOVERY_STATUS".to_owned(),
                    elapsed_ms: elapsed_ms(started),
                    ..RestoreOperationDetails::default()
                },
            )
        }
        Ok(result) => {
            if !valid_restore_abandon_result(&result) {
                return operation_envelope(
                    command_id,
                    ExitClass::Terminal,
                    "RESTORE_ABANDON_RESULT_INVALID",
                    RestoreOperationDetails {
                        safe_next_action: "INSPECT_PROTECTED_RECOVERY_STATUS".to_owned(),
                        elapsed_ms: elapsed_ms(started),
                        ..RestoreOperationDetails::default()
                    },
                );
            }
            operation_envelope(
                command_id,
                ExitClass::Success,
                "ok",
                RestoreOperationDetails {
                    operation_id: result.operation_id,
                    phase: result.phase,
                    checkpoint: result.checkpoint,
                    safe_next_action: "RESTORE_ABANDONED_START_A_NEW_RESTORE_VERIFY".to_owned(),
                    elapsed_ms: elapsed_ms(started),
                    ..RestoreOperationDetails::default()
                },
            )
        }
    }
}

/// `writeRestoreOperationResult` is shared so apply and resume
/// cannot drift in how a non-ready or quarantined operation is
/// reported to the operator. `operation` is `None` when the call
/// itself failed — the helper's partial record is never trusted onto
/// the wire.
fn write_restore_operation_result(
    command_id: &str,
    started: Instant,
    result: Option<&RestoreOperationResult>,
    failure: Option<RestoreError>,
    fallback: &'static str,
    invalid_reason: &'static str,
) -> LocalResult {
    if let Some(mapped) = failure {
        return operation_envelope(
            command_id,
            mapped.exit,
            mapped.reason,
            RestoreOperationDetails {
                operation_id: result
                    .map(|r| safe_restore_operation_id(&r.operation_id))
                    .unwrap_or_default(),
                safe_next_action: "RUN_CENTRAL_RESTORE_RESUME".to_owned(),
                elapsed_ms: elapsed_ms(started),
                ..RestoreOperationDetails::default()
            },
        );
    }
    let Some(result) = result else {
        return operation_envelope(
            command_id,
            ExitClass::Terminal,
            fallback,
            RestoreOperationDetails {
                safe_next_action: "RUN_CENTRAL_RESTORE_RESUME".to_owned(),
                elapsed_ms: elapsed_ms(started),
                ..RestoreOperationDetails::default()
            },
        );
    };
    if !valid_restore_operation_result(result) {
        return operation_envelope(
            command_id,
            ExitClass::Terminal,
            invalid_reason,
            RestoreOperationDetails {
                safe_next_action: "RUN_CENTRAL_RESTORE_RESUME".to_owned(),
                elapsed_ms: elapsed_ms(started),
                ..RestoreOperationDetails::default()
            },
        );
    }
    let (exit, reason) = if result.phase == "ready" {
        (ExitClass::Success, "ok")
    } else {
        // A non-ready outcome is not a success: serving stays blocked
        // until the operator resolves quarantine or resumes, so the
        // exit code must not tell an automation that recovery
        // finished.
        (ExitClass::Terminal, fallback)
    };
    operation_envelope(
        command_id,
        exit,
        reason,
        RestoreOperationDetails {
            operation_id: result.operation_id.clone(),
            phase: result.phase.clone(),
            checkpoint: result.checkpoint.clone(),
            safe_next_action: restore_next_action(&result.phase).to_owned(),
            elapsed_ms: elapsed_ms(started),
            ..RestoreOperationDetails::default()
        },
    )
}

/// `safeRestoreOperationID` — the operation identity is reported on a
/// failure only when it is itself well-formed.
fn safe_restore_operation_id(operation_id: &str) -> String {
    if valid_uuid_v7(operation_id) {
        operation_id.to_owned()
    } else {
        String::new()
    }
}

/// `validUUIDv7` — parse + non-nil + v7 + canonical string.
fn valid_uuid_v7(value: &str) -> bool {
    match Uuid::parse_str(value) {
        Ok(id) => !id.is_nil() && id.get_version_num() == 7 && id.to_string() == value,
        Err(_) => false,
    }
}

/// `validRestoreVerifyResult` — both identities well-formed and the
/// ticket still inside its validity window.
fn valid_restore_verify_result(
    ticket_id: &str,
    backup_id: &str,
    expires_at: OffsetDateTime,
) -> bool {
    valid_uuid_v7(ticket_id) && valid_uuid_v7(backup_id) && expires_at > OffsetDateTime::now_utc()
}

/// `validRestoreOperationResult` — the closed phase set apply and
/// resume may report: `ready` carries no unresolved quarantine by
/// construction; the in-flight phases are all reportable.
fn valid_restore_operation_result(result: &RestoreOperationResult) -> bool {
    if !valid_uuid_v7(&result.operation_id) || result.checkpoint.is_empty() {
        return false;
    }
    matches!(
        result.phase.as_str(),
        "ready" | "applying" | "verifying" | "quarantined" | "resetting"
    )
}

/// `validRestoreAbandonResult` is deliberately separate from
/// [`valid_restore_operation_result`]: "abandoned" is not admitted
/// into that closed phase set, so an apply or resume that answered
/// "abandoned" stays invalid there.
fn valid_restore_abandon_result(result: &RestoreOperationResult) -> bool {
    valid_uuid_v7(&result.operation_id)
        && !result.checkpoint.is_empty()
        && result.phase == "abandoned"
}

/// `restoreNextAction` — the phase-driven next step.
fn restore_next_action(phase: &str) -> &'static str {
    match phase {
        "ready" => "RESTORE_COMPLETE_START_CENTRAL",
        "quarantined" => "RESOLVE_QUARANTINED_ARTIFACTS_THEN_RESUME",
        _ => "RUN_CENTRAL_RESTORE_RESUME",
    }
}
