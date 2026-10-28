//! `central local audit` / `central local security *` — the D05/D06
//! operator surface. Ports upstream `internal/command/audit.go`,
//! `security_update.go`, and `security_rescue.go` end to end: the
//! grammar, the closed error mapping, the safe stdout projection
//! (counts and identities, never paths or candidate bytes), and the
//! working-directory evidence artifacts.
//!
//! Dispatch note: every `local security *` form resolves to the
//! `local.security-update` registry id — upstream `Resolve`'s
//! first-match collapse — so [`local_security`] routes the sub-action
//! on `tokens[0]` exactly like `runLocalSecurity` reads `args[3]`.

use std::io::Write;
use std::time::Instant;

use central_adapter_linux::helper::audit::{
    AuditClient, AuditClientError, AuditClientResult, REASON_AUDIT_CEREMONY_REQUIRED,
    REASON_AUDIT_DENIED_SIGNED, REASON_AUDIT_REPAIR_FAILED, REASON_AUDIT_REPAIR_REFUSED,
    REASON_DENY_SAFE_ACTIVE,
};
use central_adapter_linux::helper::rescue::{
    RESCUE_WIRE_REASON_ADVISORY_INVALID, RESCUE_WIRE_REASON_AUTHORITY_DENIED,
    RESCUE_WIRE_REASON_CEREMONY_REQUIRED, RESCUE_WIRE_REASON_CLEANUP_FAILED,
    RESCUE_WIRE_REASON_NOT_APPLICABLE, RESCUE_WIRE_REASON_STAYS_DENIED, RescueClient,
    RescueClientError,
};
use central_adapter_linux::helper::security_update::{
    REASON_SECURITY_UPDATE_AUTHORIZATION_REQUIRED, SecurityUpdateClient, SecurityUpdateClientError,
};
use central_foundation::failure::ExitClass;
use central_foundation::local_result::LocalResult;
use serde::Serialize;
use uuid::Uuid;

/// `StateAuditEvidenceFileName` — the D05 evidence artifact, written
/// to the working directory on success.
const STATE_AUDIT_EVIDENCE_FILE_NAME: &str = "slice-d-state-audit.json";
/// `RescueEvidenceFileName` — the D06 evidence artifact.
const RESCUE_EVIDENCE_FILE_NAME: &str = "slice-d-rescue.json";

fn emit(result: LocalResult, stdout: &mut impl Write, stderr: &mut impl Write) -> u8 {
    match result.write_json_line(stdout) {
        Ok(()) => result.exit_code,
        Err(_) => {
            let _ = writeln!(stderr, "central: could not write result envelope");
            ExitClass::Terminal.code()
        }
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis() as u64
}

/// `cli.WriteResult` — upstream's `reason,omitempty` drops the empty
/// string, so `""` maps to `None` here.
fn envelope<T: Serialize>(
    command_id: &str,
    class: ExitClass,
    reason: &str,
    details: &T,
) -> LocalResult {
    LocalResult::now(
        command_id,
        class,
        (!reason.is_empty()).then(|| reason.to_owned()),
        serde_json::to_value(details).ok(),
    )
}

/// Maps a wire exit code (2..=7, already clamped by the client error
/// constructors) onto an [`ExitClass`]; anything outside the CLI
/// exit classes collapses to terminal.
fn exit_class_of(wire: i64) -> ExitClass {
    match wire {
        2 => ExitClass::Usage,
        3 => ExitClass::Unavailable,
        4 => ExitClass::Timeout,
        5 => ExitClass::Incompatible,
        7 => ExitClass::Denied,
        _ => ExitClass::Terminal,
    }
}

/// `os.WriteFile(name, marshalIndent(evidence)+"\n", 0o644)` — same
/// plain write the wipe/export evidence helpers use.
fn write_evidence<T: Serialize>(name: &str, evidence: &T) -> Result<(), ()> {
    let mut body = serde_json::to_vec_pretty(evidence).map_err(|_| ())?;
    body.push(b'\n');
    std::fs::write(name, body).map_err(|_| ())
}

/// Same socket rule `local_cli`/`migrate_cli` use:
/// `CENTRAL_HELPER_SOCKET` when non-empty, else the production path.
fn helper_socket() -> String {
    use central_adapter_linux::helper::client::PRODUCTION_SOCKET_PATH;
    std::env::var("CENTRAL_HELPER_SOCKET")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| PRODUCTION_SOCKET_PATH.to_owned())
}

// -- `central local audit [--repair]` -------------------------------------

/// `command.AuditDetails` — counts and verdicts only; the tampered
/// paths stay inside the evidence artifact.
#[derive(Debug, Default, Serialize)]
struct AuditDetails {
    #[serde(skip_serializing_if = "String::is_empty")]
    operation_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    report_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    manifest_id: String,
    manifest_valid: bool,
    #[serde(skip_serializing_if = "is_zero_i64")]
    checked: i64,
    #[serde(skip_serializing_if = "is_zero_i64")]
    tamper_count: i64,
    #[serde(skip_serializing_if = "is_zero_i64")]
    unreadable_count: i64,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    late: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    baseline_created: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    repaired: bool,
    safe_next_action: String,
    elapsed_ms: u64,
}

fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}

/// `audit.AuditEvidence` — the report verdict and lists; nothing
/// else (no signature: the signed report lives helper-side).
#[derive(Debug, Default, Serialize)]
struct AuditEvidence {
    operation_id: String,
    report_id: String,
    manifest_id: String,
    manifest_valid: bool,
    checked: i64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tampered: Vec<central_adapter_linux::helper::audit::TamperedFile>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    unreadable: Vec<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    late: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    baseline_created: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    repaired: bool,
    completed_at: String,
}

/// `parseAuditArgs` — `central local audit [--repair]`; duplicate or
/// unknown flags refuse (there is deliberately no `--force`).
fn parse_audit_args(tokens: &[String]) -> Result<bool, ()> {
    let mut repair = false;
    for arg in tokens {
        match arg.as_str() {
            "--repair" if !repair => repair = true,
            _ => return Err(()),
        }
    }
    Ok(repair)
}

/// `mapHelperAuditError` + `auditErrorResult` — the closed reason →
/// (exit class, reason, safe next action) table. An empty reason is
/// the transport/decode failure: upstream falls through `default`,
/// keeping the wire exit class under `AUDIT_FAILED`.
fn audit_error_result(err: &AuditClientError) -> (ExitClass, &'static str, &'static str) {
    let class = exit_class_of(err.exit_code());
    match err.reason() {
        REASON_DENY_SAFE_ACTIVE => (
            class,
            REASON_DENY_SAFE_ACTIVE,
            "RUN_CENTRAL_LOCAL_SECURITY_RESCUE",
        ),
        REASON_AUDIT_REPAIR_REFUSED => (
            class,
            REASON_AUDIT_REPAIR_REFUSED,
            "WIPE_AND_RESEED_INSTEAD",
        ),
        REASON_AUDIT_REPAIR_FAILED => (class, REASON_AUDIT_REPAIR_FAILED, "INSPECT_AUDIT_STATE"),
        REASON_AUDIT_DENIED_SIGNED => {
            (class, REASON_AUDIT_DENIED_SIGNED, "RESOLVE_ADVISORY_DENIAL")
        }
        REASON_AUDIT_CEREMONY_REQUIRED => (
            class,
            REASON_AUDIT_CEREMONY_REQUIRED,
            "COMPLETE_REPAIR_CEREMONY",
        ),
        "AUTHORITY_DENIED" => (class, "AUTHORITY_DENIED", "COMPLETE_REPAIR_CEREMONY"),
        _ => (class, "AUDIT_FAILED", "INSPECT_AUDIT_STATE"),
    }
}

/// `runLocalAudit` — grammar, helper audit, evidence artifact, and
/// the bounded stdout projection.
pub(crate) fn local_audit(
    command_id: &str,
    tokens: &[String],
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> u8 {
    let started = Instant::now();
    let repair = match parse_audit_args(tokens) {
        Ok(repair) => repair,
        Err(()) => {
            return emit(
                envelope(
                    command_id,
                    ExitClass::Usage,
                    "INVALID_AUDIT_GRAMMAR",
                    &AuditDetails {
                        safe_next_action: "RUN_CENTRAL_LOCAL_AUDIT".to_owned(),
                        elapsed_ms: elapsed_ms(started),
                        ..AuditDetails::default()
                    },
                ),
                stdout,
                stderr,
            );
        }
    };
    let operation_id = Uuid::now_v7().to_string();
    let socket = helper_socket();
    let result = match AuditClient::new(socket).audit(&operation_id, repair, false, "") {
        Ok(result) => result,
        Err(err) => {
            let (class, reason, next) = audit_error_result(&err);
            return emit(
                envelope(
                    command_id,
                    class,
                    reason,
                    &AuditDetails {
                        operation_id,
                        safe_next_action: next.to_owned(),
                        elapsed_ms: elapsed_ms(started),
                        ..AuditDetails::default()
                    },
                ),
                stdout,
                stderr,
            );
        }
    };
    if !valid_audit_result(&operation_id, &result) {
        return emit(
            envelope(
                command_id,
                ExitClass::Terminal,
                "AUDIT_RESULT_INVALID",
                &AuditDetails {
                    operation_id,
                    safe_next_action: "INSPECT_AUDIT_STATE".to_owned(),
                    elapsed_ms: elapsed_ms(started),
                    ..AuditDetails::default()
                },
            ),
            stdout,
            stderr,
        );
    }
    let evidence = AuditEvidence {
        operation_id: result.operation_id.clone(),
        report_id: result.report_id.clone(),
        manifest_id: result.manifest_id.clone(),
        manifest_valid: result.manifest_valid,
        checked: result.checked,
        tampered: result.tampered.clone(),
        unreadable: result.unreadable.clone(),
        late: result.late,
        baseline_created: result.baseline_created,
        repaired: result.repaired,
        completed_at: result.completed_at.clone(),
    };
    if write_evidence(STATE_AUDIT_EVIDENCE_FILE_NAME, &evidence).is_err() {
        return emit(
            envelope(
                command_id,
                ExitClass::Terminal,
                "AUDIT_EVIDENCE_FAILED",
                &AuditDetails {
                    operation_id,
                    safe_next_action: "INSPECT_AUDIT_STATE".to_owned(),
                    elapsed_ms: elapsed_ms(started),
                    ..AuditDetails::default()
                },
            ),
            stdout,
            stderr,
        );
    }
    emit(
        envelope(
            command_id,
            ExitClass::Success,
            "ok",
            &AuditDetails {
                operation_id: result.operation_id,
                report_id: result.report_id,
                manifest_id: result.manifest_id,
                manifest_valid: result.manifest_valid,
                checked: result.checked,
                tamper_count: result.tampered.len() as i64,
                unreadable_count: result.unreadable.len() as i64,
                late: result.late,
                baseline_created: result.baseline_created,
                repaired: result.repaired,
                safe_next_action: "AUDIT_COMPLETE".to_owned(),
                elapsed_ms: elapsed_ms(started),
            },
        ),
        stdout,
        stderr,
    )
}

/// `validAuditResult` — op echo, complete identities, non-negative
/// count, and every finding carries path plus reason.
fn valid_audit_result(operation_id: &str, result: &AuditClientResult) -> bool {
    if result.operation_id != operation_id
        || result.report_id.is_empty()
        || result.manifest_id.is_empty()
        || result.completed_at.is_empty()
        || result.checked < 0
    {
        return false;
    }
    result
        .tampered
        .iter()
        .all(|f| !f.path.is_empty() && !f.reason.is_empty())
}

// -- `central local security update|rescue` --------------------------------

/// `command.SecurityUpdateDetails` — the safe locator-free outcome:
/// which advisory generation is now active.
#[derive(Debug, Default, Serialize)]
struct SecurityUpdateDetails {
    #[serde(skip_serializing_if = "String::is_empty")]
    operation_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    generation_id: String,
    safe_next_action: String,
    elapsed_ms: u64,
}

/// `command.RescueDetails` — verdicts and counts, never advisory
/// bytes or paths.
#[derive(Debug, Default, Serialize)]
struct RescueDetails {
    #[serde(skip_serializing_if = "String::is_empty")]
    operation_id: String,
    exited: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    already_current: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    resumed_after_crash: bool,
    #[serde(skip_serializing_if = "is_zero_i64")]
    attempts: i64,
    safe_next_action: String,
    elapsed_ms: u64,
}

/// `runLocalSecurity` — the `("local","security")` dispatch key:
/// update, rescue, and the Slice E rescue cleanup. The sub-action is
/// decided from `tokens[0]` — upstream `args[3]`.
pub(crate) fn local_security(
    command_id: &str,
    tokens: &[String],
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> u8 {
    match tokens.first().map(String::as_str) {
        Some("update") => run_security_update(command_id, tokens, stdout, stderr),
        Some("rescue") => {
            if tokens.get(1).map(String::as_str) == Some("cleanup") {
                // Slice E owns rescue cleanup; it stays deferred here.
                return emit(
                    envelope(
                        command_id,
                        ExitClass::Incompatible,
                        "UNSUPPORTED_IN_THIS_SLICE",
                        &RescueDetails {
                            safe_next_action: "WAIT_FOR_SLICE_E".to_owned(),
                            ..RescueDetails::default()
                        },
                    ),
                    stdout,
                    stderr,
                );
            }
            run_security_rescue(command_id, tokens, stdout, stderr)
        }
        _ => emit(
            envelope(
                command_id,
                ExitClass::Usage,
                "INVALID_SECURITY_GRAMMAR",
                &RescueDetails {
                    safe_next_action: "RUN_CENTRAL_LOCAL_SECURITY_UPDATE_OR_RESCUE".to_owned(),
                    ..RescueDetails::default()
                },
            ),
            stdout,
            stderr,
        ),
    }
}

/// `runSecurityUpdate` — `central local security update
/// <envelope-path>`: the file's bytes cross, never its path.
fn run_security_update(
    command_id: &str,
    tokens: &[String],
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> u8 {
    let started = Instant::now();
    if tokens.len() != 2 || tokens[1].is_empty() {
        return emit(
            envelope(
                command_id,
                ExitClass::Usage,
                "INVALID_SECURITY_UPDATE_GRAMMAR",
                &SecurityUpdateDetails {
                    safe_next_action: "RUN_CENTRAL_LOCAL_SECURITY_UPDATE_WITH_ENVELOPE_PATH"
                        .to_owned(),
                    elapsed_ms: elapsed_ms(started),
                    ..SecurityUpdateDetails::default()
                },
            ),
            stdout,
            stderr,
        );
    }
    let envelope_bytes = match std::fs::read(&tokens[1]) {
        Ok(bytes) => bytes,
        Err(_) => {
            return emit(
                envelope(
                    command_id,
                    ExitClass::Usage,
                    "SECURITY_UPDATE_ENVELOPE_UNREADABLE",
                    &SecurityUpdateDetails {
                        safe_next_action: "CHECK_ENVELOPE_FILE".to_owned(),
                        elapsed_ms: elapsed_ms(started),
                        ..SecurityUpdateDetails::default()
                    },
                ),
                stdout,
                stderr,
            );
        }
    };
    let operation_id = Uuid::now_v7().to_string();
    let socket = helper_socket();
    let result = match SecurityUpdateClient::new(socket)
        .install_security_update(&operation_id, &envelope_bytes)
    {
        Ok(result) => result,
        Err(err) => {
            let (class, reason, next) = security_update_error_result(&err);
            return emit(
                envelope(
                    command_id,
                    class,
                    reason,
                    &SecurityUpdateDetails {
                        operation_id,
                        safe_next_action: next.to_owned(),
                        elapsed_ms: elapsed_ms(started),
                        ..SecurityUpdateDetails::default()
                    },
                ),
                stdout,
                stderr,
            );
        }
    };
    if result.operation_id != operation_id || result.generation_id.is_empty() {
        return emit(
            envelope(
                command_id,
                ExitClass::Terminal,
                "SECURITY_UPDATE_RESULT_INVALID",
                &SecurityUpdateDetails {
                    operation_id,
                    safe_next_action: "CHECK_ENVELOPE_FILE".to_owned(),
                    elapsed_ms: elapsed_ms(started),
                    ..SecurityUpdateDetails::default()
                },
            ),
            stdout,
            stderr,
        );
    }
    emit(
        envelope(
            command_id,
            ExitClass::Success,
            "ok",
            &SecurityUpdateDetails {
                operation_id: result.operation_id,
                generation_id: result.generation_id,
                safe_next_action: "SECURITY_UPDATE_INSTALLED".to_owned(),
                elapsed_ms: elapsed_ms(started),
            },
        ),
        stdout,
        stderr,
    )
}

/// `mapHelperSecurityUpdateError` + `securityUpdateErrorResult` —
/// the exit-class switch upstream uses: transport and unsupported
/// fold to dependency-unavailable; authority-denied splits on the
/// whitelisted reason; everything else is the terminal failure.
fn security_update_error_result(
    err: &SecurityUpdateClientError,
) -> (ExitClass, &'static str, &'static str) {
    match err.exit_code() {
        3 | 5 => (
            ExitClass::Unavailable,
            "SECURITY_UPDATE_DEPENDENCY_UNAVAILABLE",
            "START_OR_REPAIR_CENTRAL_HELPER",
        ),
        7 => {
            // A mis-composed handler and a refused authentication share
            // the exit class; only the whitelisted reason separates
            // them. Anything else folds to the generic denial —
            // including `DENY_SAFE_ACTIVE`, which is not in
            // `NewSecurityUpdateError`'s whitelist and collapses to the
            // terminal failure there.
            if err.reason() == REASON_SECURITY_UPDATE_AUTHORIZATION_REQUIRED {
                (
                    ExitClass::Denied,
                    "SECURITY_UPDATE_AUTHORIZATION_REQUIRED",
                    "CONTACT_OPERATIONS",
                )
            } else if err.reason() == "DENY_SAFE_ACTIVE" {
                (
                    ExitClass::Terminal,
                    "SECURITY_UPDATE_FAILED",
                    "CHECK_ENVELOPE_FILE",
                )
            } else {
                (
                    ExitClass::Denied,
                    "SECURITY_UPDATE_AUTHORITY_DENIED",
                    "REAUTHENTICATE_AND_RETRY",
                )
            }
        }
        _ => (
            ExitClass::Terminal,
            "SECURITY_UPDATE_FAILED",
            "CHECK_ENVELOPE_FILE",
        ),
    }
}

/// `runSecurityRescue` — `central local security rescue
/// --advisory=<path>`: the D06 hard-expired rescue. The candidate is
/// zeroized after the helper call, exactly as upstream's `for i :=
/// range candidate { candidate[i] = 0 }`.
fn run_security_rescue(
    command_id: &str,
    tokens: &[String],
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> u8 {
    let started = Instant::now();
    let advisory_path = match parse_rescue_args(tokens) {
        Ok(path) => path,
        Err(()) => {
            return emit(
                envelope(
                    command_id,
                    ExitClass::Usage,
                    "INVALID_RESCUE_GRAMMAR",
                    &RescueDetails {
                        safe_next_action: "RUN_CENTRAL_LOCAL_SECURITY_RESCUE_WITH_ADVISORY"
                            .to_owned(),
                        elapsed_ms: elapsed_ms(started),
                        ..RescueDetails::default()
                    },
                ),
                stdout,
                stderr,
            );
        }
    };
    let mut candidate = match std::fs::read(&advisory_path) {
        Ok(bytes)
            if !bytes.is_empty()
                && bytes.len() <= central_infra::advisory::MAX_CANDIDATE_ADVISORY_BYTES =>
        {
            bytes
        }
        _ => {
            return emit(
                envelope(
                    command_id,
                    ExitClass::Usage,
                    "RESCUE_ADVISORY_UNREADABLE",
                    &RescueDetails {
                        safe_next_action: "CHECK_ADVISORY_FILE".to_owned(),
                        elapsed_ms: elapsed_ms(started),
                        ..RescueDetails::default()
                    },
                ),
                stdout,
                stderr,
            );
        }
    };
    let operation_id = Uuid::now_v7().to_string();
    let socket = helper_socket();
    let result = RescueClient::new(socket).rescue(&operation_id, &candidate);
    candidate.fill(0);
    let result = match result {
        Ok(result) => result,
        Err(err) => {
            let (class, reason, next) = rescue_error_result(&err);
            return emit(
                envelope(
                    command_id,
                    class,
                    reason,
                    &RescueDetails {
                        operation_id,
                        safe_next_action: next.to_owned(),
                        elapsed_ms: elapsed_ms(started),
                        ..RescueDetails::default()
                    },
                ),
                stdout,
                stderr,
            );
        }
    };
    if !valid_rescue_result(&operation_id, &result) {
        return emit(
            envelope(
                command_id,
                ExitClass::Terminal,
                "RESCUE_RESULT_INVALID",
                &RescueDetails {
                    operation_id,
                    safe_next_action: "INSPECT_RESCUE_STATE".to_owned(),
                    elapsed_ms: elapsed_ms(started),
                    ..RescueDetails::default()
                },
            ),
            stdout,
            stderr,
        );
    }
    let evidence = central_infra::advisory::RescueEvidence {
        operation_id: result.operation_id.clone(),
        exited: result.exited,
        already_current: result.already_current,
        resumed_after_crash: result.resumed_after_crash,
        attempts: result.attempts,
        completed_at: result.completed_at.clone(),
    };
    if write_evidence(RESCUE_EVIDENCE_FILE_NAME, &evidence).is_err() {
        return emit(
            envelope(
                command_id,
                ExitClass::Terminal,
                "RESCUE_EVIDENCE_FAILED",
                &RescueDetails {
                    operation_id,
                    safe_next_action: "INSPECT_RESCUE_STATE".to_owned(),
                    elapsed_ms: elapsed_ms(started),
                    ..RescueDetails::default()
                },
            ),
            stdout,
            stderr,
        );
    }
    emit(
        envelope(
            command_id,
            ExitClass::Success,
            "ok",
            &RescueDetails {
                operation_id: result.operation_id,
                exited: result.exited,
                already_current: result.already_current,
                resumed_after_crash: result.resumed_after_crash,
                attempts: result.attempts,
                safe_next_action: "RESCUE_COMPLETE".to_owned(),
                elapsed_ms: elapsed_ms(started),
            },
        ),
        stdout,
        stderr,
    )
}

/// `parseRescueArgs` — `rescue --advisory=<path>`: exactly one
/// non-empty `--advisory=` flag and nothing else. `tokens` here is
/// `["rescue", rest…]` — upstream `args[3:]`.
fn parse_rescue_args(tokens: &[String]) -> Result<String, ()> {
    if tokens.first().map(String::as_str) != Some("rescue") {
        return Err(());
    }
    let mut advisory_path: Option<String> = None;
    for arg in &tokens[1..] {
        let Some(value) = arg.strip_prefix("--advisory=") else {
            return Err(());
        };
        if advisory_path.is_some() || value.is_empty() {
            return Err(());
        }
        advisory_path = Some(value.to_owned());
    }
    advisory_path.ok_or(())
}

/// `validRescueResult` — op echo, complete timestamp, non-negative
/// attempts, and exactly one of exited / already-current.
fn valid_rescue_result(
    operation_id: &str,
    result: &central_adapter_linux::helper::rescue::RescueClientResult,
) -> bool {
    if result.operation_id != operation_id || result.completed_at.is_empty() || result.attempts < 0
    {
        return false;
    }
    result.exited != result.already_current
}

/// `mapHelperRescueError` + `rescueErrorResult` — the closed reason
/// → (exit class, reason, safe next action) table.
fn rescue_error_result(err: &RescueClientError) -> (ExitClass, &'static str, &'static str) {
    let class = exit_class_of(err.exit_code());
    match err.reason() {
        REASON_DENY_SAFE_ACTIVE => (
            class,
            REASON_DENY_SAFE_ACTIVE,
            "RUN_CENTRAL_LOCAL_SECURITY_RESCUE",
        ),
        RESCUE_WIRE_REASON_ADVISORY_INVALID => (
            class,
            RESCUE_WIRE_REASON_ADVISORY_INVALID,
            "CARRY_A_SIGNED_ADVISORY",
        ),
        RESCUE_WIRE_REASON_STAYS_DENIED => (
            class,
            RESCUE_WIRE_REASON_STAYS_DENIED,
            "RETRY_WITH_CURRENT_ADVISORY",
        ),
        RESCUE_WIRE_REASON_NOT_APPLICABLE => (
            class,
            RESCUE_WIRE_REASON_NOT_APPLICABLE,
            "USE_THE_MATCHING_REMEDY",
        ),
        RESCUE_WIRE_REASON_CLEANUP_FAILED => (
            class,
            RESCUE_WIRE_REASON_CLEANUP_FAILED,
            "INSPECT_SERVICE_STATE",
        ),
        RESCUE_WIRE_REASON_CEREMONY_REQUIRED => (
            class,
            RESCUE_WIRE_REASON_CEREMONY_REQUIRED,
            "COMPLETE_RESCUE_CEREMONY",
        ),
        RESCUE_WIRE_REASON_AUTHORITY_DENIED => (
            class,
            RESCUE_WIRE_REASON_AUTHORITY_DENIED,
            "COMPLETE_RESCUE_CEREMONY",
        ),
        _ => (class, "RESCUE_FAILED", "INSPECT_RESCUE_STATE"),
    }
}
