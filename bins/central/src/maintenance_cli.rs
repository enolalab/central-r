//! `central maintenance plan` / `central maintenance apply` — the
//! Slice E operator surface. Ports upstream
//! `internal/command/maintenance.go` end to end: the `--check` /
//! `--set`|`--resume`|`--rollback`|`--abandon` grammar, the closed
//! error mapping (including the denied plan's violation echo and the
//! refused apply's partial result), the safe stdout projection, and
//! the `slice-e-*.json` evidence artifacts.

use std::io::Write;
use std::time::Instant;

use central_adapter_linux::helper::maintenance::{
    MaintenanceApplyClient, MaintenanceApplyRequest, MaintenanceApplyResult, MaintenanceClient,
    MaintenanceClientError, MaintenanceResult, REASON_INVALID_MAINTENANCE_REQUEST,
    REASON_MAINTENANCE_MATRIX_TAMPERED, REASON_MAINTENANCE_UNAVAILABLE,
};
use central_foundation::failure::ExitClass;
use central_foundation::local_result::LocalResult;
use central_infra::maintenance as m;
use serde::Serialize;
use uuid::Uuid;

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
/// string (the plan/apply success rows carry `""`), so `""` maps to
/// `None` here.
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

fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}

fn is_zero_u64(v: &u64) -> bool {
    *v == 0
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

/// `maintenance` — the `maintenance.*` dispatch arm.
pub(crate) fn maintenance(
    command_id: &str,
    tokens: &[String],
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> u8 {
    match command_id {
        "maintenance.plan" => run_maintenance_plan(command_id, tokens, stdout, stderr),
        "maintenance.apply" => run_maintenance_apply(command_id, tokens, stdout, stderr),
        _ => emit(LocalResult::unsupported(command_id), stdout, stderr),
    }
}

// -- `central maintenance plan [--check name=target]` ----------------------

/// `command.MaintenancePlanDetails` — counts, digests, and verdicts;
/// never file contents.
#[derive(Debug, Default, Serialize)]
struct MaintenancePlanDetails {
    #[serde(skip_serializing_if = "String::is_empty")]
    operation_id: String,
    initialized: bool,
    #[serde(skip_serializing_if = "is_zero_i64")]
    entries: i64,
    allowed: i64,
    forbidden: i64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    violations: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    matrix_digest: String,
    #[serde(skip_serializing_if = "is_zero_u64")]
    sequence_num: u64,
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    observed: std::collections::BTreeMap<String, String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    evidence_file: String,
    safe_next_action: String,
    elapsed_ms: u64,
}

/// `runMaintenancePlan` — grammar, helper plan, `slice-e-compatibility-matrix.json`
/// evidence, and the bounded projection.
fn run_maintenance_plan(
    command_id: &str,
    tokens: &[String],
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> u8 {
    let started = Instant::now();
    let checks = match parse_maintenance_args(tokens) {
        Ok(checks) => checks,
        Err(()) => {
            return emit(
                envelope(
                    command_id,
                    ExitClass::Usage,
                    "INVALID_MAINTENANCE_GRAMMAR",
                    &MaintenancePlanDetails {
                        safe_next_action: "RUN_CENTRAL_MAINTENANCE_PLAN".to_owned(),
                        elapsed_ms: elapsed_ms(started),
                        ..MaintenancePlanDetails::default()
                    },
                ),
                stdout,
                stderr,
            );
        }
    };
    let operation_id = Uuid::now_v7().to_string();
    let socket = helper_socket();
    let result = match MaintenanceClient::new(socket).plan(&operation_id, &checks) {
        Ok(result) => result,
        Err(err) => {
            let (class, reason, next, violations) = maintenance_error_result(&operation_id, &err);
            return emit(
                envelope(
                    command_id,
                    class,
                    reason,
                    &MaintenancePlanDetails {
                        operation_id,
                        violations,
                        safe_next_action: next.to_owned(),
                        elapsed_ms: elapsed_ms(started),
                        ..MaintenancePlanDetails::default()
                    },
                ),
                stdout,
                stderr,
            );
        }
    };
    if !valid_maintenance_result(&operation_id, &result) {
        return emit(
            envelope(
                command_id,
                ExitClass::Terminal,
                "MAINTENANCE_RESULT_INVALID",
                &MaintenancePlanDetails {
                    operation_id,
                    safe_next_action: "INSPECT_MATRIX_STATE".to_owned(),
                    elapsed_ms: elapsed_ms(started),
                    ..MaintenancePlanDetails::default()
                },
            ),
            stdout,
            stderr,
        );
    }
    let cwd = match std::env::current_dir() {
        Ok(cwd) => cwd,
        Err(_) => {
            return emit(
                envelope(
                    command_id,
                    ExitClass::Terminal,
                    "MAINTENANCE_EVIDENCE_UNAVAILABLE",
                    &MaintenancePlanDetails {
                        operation_id,
                        safe_next_action: "RETRY_MAINTENANCE_PLAN".to_owned(),
                        elapsed_ms: elapsed_ms(started),
                        ..MaintenancePlanDetails::default()
                    },
                ),
                stdout,
                stderr,
            );
        }
    };
    let evidence = m::new_evidence(
        &result.matrix_digest,
        result.sequence_num,
        result.dependencies.clone(),
        result.initialized,
    );
    if m::write_evidence_file(&cwd, &evidence).is_err() {
        return emit(
            envelope(
                command_id,
                ExitClass::Terminal,
                "MAINTENANCE_EVIDENCE_WRITE_FAILED",
                &MaintenancePlanDetails {
                    operation_id,
                    safe_next_action: "RETRY_MAINTENANCE_PLAN".to_owned(),
                    elapsed_ms: elapsed_ms(started),
                    ..MaintenancePlanDetails::default()
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
            "",
            &MaintenancePlanDetails {
                operation_id,
                initialized: result.initialized,
                entries: result.entries,
                allowed: result.allowed,
                forbidden: result.forbidden,
                matrix_digest: result.matrix_digest,
                sequence_num: result.sequence_num,
                observed: result.observed,
                evidence_file: m::EVIDENCE_FILE_NAME.to_owned(),
                safe_next_action: "REVIEW_MATRIX".to_owned(),
                elapsed_ms: elapsed_ms(started),
                ..MaintenancePlanDetails::default()
            },
        ),
        stdout,
        stderr,
    )
}

/// `parseMaintenanceArgs` — `central maintenance plan [--check
/// name=target]…`: repeated `--check=` flags, nothing else.
fn parse_maintenance_args(tokens: &[String]) -> Result<Vec<String>, ()> {
    let mut checks = Vec::new();
    for arg in tokens {
        let Some(spec) = arg.strip_prefix("--check=") else {
            return Err(());
        };
        let Some((name, target)) = spec.split_once('=') else {
            return Err(());
        };
        if name.is_empty() || target.is_empty() {
            return Err(());
        }
        checks.push(spec.to_owned());
    }
    Ok(checks)
}

/// `validMaintenanceResult` — op echo, complete matrix identity, and
/// a positive sequence.
fn valid_maintenance_result(operation_id: &str, result: &MaintenanceResult) -> bool {
    result.operation_id == operation_id
        && !result.matrix_digest.is_empty()
        && !result.completed_at.is_empty()
        && result.sequence_num > 0
}

/// `helperMaintenanceClient.MaintenancePlan`'s denial handling plus
/// `mapHelperMaintenanceError`: a denied plan that carries its own
/// violations echoes them as `dependency (REASON)` strings under
/// `RESOLVE_MATRIX_TRANSITION`; every other failure maps through the
/// closed reason table.
fn maintenance_error_result(
    operation_id: &str,
    err: &MaintenanceClientError,
) -> (ExitClass, &'static str, &'static str, Vec<String>) {
    if let Some(denied) = err.plan_result()
        && denied.operation_id == operation_id
        && !denied.violations.is_empty()
    {
        let violations = denied
            .violations
            .iter()
            .map(|v| format!("{} ({})", v.dependency, v.reason))
            .collect();
        return (
            exit_class_of(err.exit_code()),
            retained_reason(err.reason()),
            "RESOLVE_MATRIX_TRANSITION",
            violations,
        );
    }
    let class = exit_class_of(err.exit_code());
    match err.reason() {
        "DENY_SAFE_ACTIVE" => (
            class,
            "DENY_SAFE_ACTIVE",
            "RUN_CENTRAL_LOCAL_SECURITY_RESCUE",
            vec![],
        ),
        m::REASON_UNLISTED => (
            class,
            m::REASON_UNLISTED,
            "RESOLVE_MATRIX_TRANSITION",
            vec![],
        ),
        REASON_MAINTENANCE_MATRIX_TAMPERED => (
            class,
            REASON_MAINTENANCE_MATRIX_TAMPERED,
            "INSPECT_MATRIX_STATE",
            vec![],
        ),
        _ => (
            class,
            "MAINTENANCE_PLAN_FAILED",
            "RETRY_MAINTENANCE_PLAN",
            vec![],
        ),
    }
}

/// Echoes the wire reason the client retained — upstream's
/// `failure.Reason()` verbatim — over the same closed set the client
/// retains; anything else collapses to the generic plan failure.
fn retained_reason(wire: &str) -> &'static str {
    match wire {
        "DENY_SAFE_ACTIVE" => "DENY_SAFE_ACTIVE",
        "AUTHORITY_DENIED" => "AUTHORITY_DENIED",
        REASON_MAINTENANCE_UNAVAILABLE => REASON_MAINTENANCE_UNAVAILABLE,
        REASON_MAINTENANCE_MATRIX_TAMPERED => REASON_MAINTENANCE_MATRIX_TAMPERED,
        REASON_INVALID_MAINTENANCE_REQUEST => REASON_INVALID_MAINTENANCE_REQUEST,
        m::REASON_UNLISTED => m::REASON_UNLISTED,
        m::REASON_PATCH_PENDING => m::REASON_PATCH_PENDING,
        m::REASON_PATCH_UNKNOWN => m::REASON_PATCH_UNKNOWN,
        m::REASON_PATCH_CLOSED => m::REASON_PATCH_CLOSED,
        m::REASON_ROLLBACK_STALE => m::REASON_ROLLBACK_STALE,
        m::REASON_GATE_UNKNOWN => m::REASON_GATE_UNKNOWN,
        m::REASON_GATE_FAILED => m::REASON_GATE_FAILED,
        _ => "MAINTENANCE_PLAN_FAILED",
    }
}

// -- `central maintenance apply` --------------------------------------------

/// `command.MaintenanceApplyDetails` — the only apply payload emitted
/// to stdout.
#[derive(Debug, Default, Serialize)]
struct MaintenanceApplyDetails {
    #[serde(skip_serializing_if = "String::is_empty")]
    operation_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    mode: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    attempt_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    dependency: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    from: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    to: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    gate: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    gate_detail: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    matrix_digest: String,
    #[serde(skip_serializing_if = "is_zero_u64")]
    sequence_num: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    evidence_file: String,
    safe_next_action: String,
    elapsed_ms: u64,
}

/// `runMaintenanceApply` — the emit closure writes the evidence
/// artifact best-effort once the command carries an operation
/// identity; a grammar refusal before the operation exists writes
/// nothing.
fn run_maintenance_apply(
    command_id: &str,
    tokens: &[String],
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> u8 {
    let started = Instant::now();
    let emit_apply =
        |code: ExitClass, reason: &str, action: &str, ev: &m::ApplyEvidence| -> LocalResult {
            let mut evidence_file = String::new();
            if !ev.operation_id.is_empty()
                && let Ok(cwd) = std::env::current_dir()
                && m::write_apply_evidence_file(&cwd, ev).is_ok()
            {
                evidence_file = m::APPLY_EVIDENCE_FILE_NAME.to_owned();
            }
            envelope(
                command_id,
                code,
                reason,
                &MaintenanceApplyDetails {
                    operation_id: ev.operation_id.clone(),
                    attempt_id: ev.attempt_id.clone(),
                    dependency: ev.dependency.clone(),
                    from: ev.from.clone(),
                    to: ev.to.clone(),
                    gate: ev.gate.clone(),
                    gate_detail: ev.gate_detail.clone(),
                    matrix_digest: ev.matrix_digest.clone(),
                    sequence_num: ev.sequence_num,
                    evidence_file,
                    safe_next_action: action.to_owned(),
                    elapsed_ms: elapsed_ms(started),
                    ..MaintenanceApplyDetails::default()
                },
            )
        };
    let parsed = match parse_maintenance_apply_args(tokens) {
        Ok(parsed) => parsed,
        Err(()) => {
            return emit(
                emit_apply(
                    ExitClass::Usage,
                    "INVALID_MAINTENANCE_GRAMMAR",
                    "RUN_CENTRAL_MAINTENANCE_PLAN",
                    &m::ApplyEvidence {
                        verdict: "refused".to_owned(),
                        reason: "INVALID_MAINTENANCE_GRAMMAR".to_owned(),
                        ..m::ApplyEvidence::default()
                    },
                ),
                stdout,
                stderr,
            );
        }
    };
    let operation_id = Uuid::now_v7().to_string();
    let request = MaintenanceApplyRequest {
        operation_id: operation_id.clone(),
        set: parsed.set,
        resume: parsed.resume,
        rollback: parsed.rollback,
        abandon: parsed.abandon,
    };
    let socket = helper_socket();
    let result = match MaintenanceApplyClient::new(socket).apply(&operation_id, &request) {
        Ok(result) => result,
        Err(err) => {
            let (class, reason, next, partial) = maintenance_apply_error_result(&err);
            return emit(
                emit_apply(
                    class,
                    reason,
                    next,
                    &m::ApplyEvidence {
                        operation_id: operation_id.clone(),
                        mode: partial.mode.clone(),
                        attempt_id: partial.attempt_id.clone(),
                        dependency: partial.dependency.clone(),
                        from: partial.from.clone(),
                        to: partial.to.clone(),
                        gate: partial.gate.clone(),
                        gate_detail: partial.gate_detail.clone(),
                        verdict: apply_verdict_for_reason(reason).to_owned(),
                        reason: reason.to_owned(),
                        matrix_digest: partial.matrix_digest.clone(),
                        sequence_num: partial.sequence_num,
                        ..m::ApplyEvidence::default()
                    },
                ),
                stdout,
                stderr,
            );
        }
    };
    if result.operation_id != operation_id
        || result.attempt_id.is_empty()
        || result.completed_at.is_empty()
        || result.matrix_digest.is_empty()
    {
        return emit(
            emit_apply(
                ExitClass::Terminal,
                "MAINTENANCE_RESULT_INVALID",
                "INSPECT_MATRIX_STATE",
                &m::ApplyEvidence {
                    operation_id: operation_id.clone(),
                    verdict: "refused".to_owned(),
                    reason: "MAINTENANCE_RESULT_INVALID".to_owned(),
                    ..m::ApplyEvidence::default()
                },
            ),
            stdout,
            stderr,
        );
    }
    let verdict = if result.mode == "abandon" {
        "abandoned"
    } else {
        "applied"
    };
    emit(
        emit_apply(
            ExitClass::Success,
            "",
            "REVIEW_MATRIX",
            &m::ApplyEvidence {
                operation_id: result.operation_id,
                mode: result.mode,
                attempt_id: result.attempt_id,
                dependency: result.dependency,
                from: result.from,
                to: result.to,
                gate: result.gate,
                verdict: verdict.to_owned(),
                matrix_digest: result.matrix_digest,
                sequence_num: result.sequence_num,
                ..m::ApplyEvidence::default()
            },
        ),
        stdout,
        stderr,
    )
}

/// `maintenanceApplyArgs` — exactly one of set/resume/rollback/abandon.
#[derive(Debug, Default)]
struct MaintenanceApplyArgs {
    set: String,
    resume: String,
    rollback: String,
    abandon: String,
}

impl MaintenanceApplyArgs {
    fn filled(&self) -> usize {
        [&self.set, &self.resume, &self.rollback, &self.abandon]
            .iter()
            .filter(|v| !v.is_empty())
            .count()
    }
}

/// `parseMaintenanceApplyArgs` — `central maintenance apply` with
/// exactly one of `--set name=target`, `--resume id`, `--rollback id`,
/// or `--abandon id` — nothing else. The id flags require a UUID like
/// upstream's `uuid.FromString`.
fn parse_maintenance_apply_args(tokens: &[String]) -> Result<MaintenanceApplyArgs, ()> {
    fn id_flag(arg: &str, prefix: &str, filled: usize) -> Result<String, ()> {
        if filled != 0 {
            return Err(());
        }
        let Some(id) = arg.strip_prefix(prefix) else {
            return Err(());
        };
        if Uuid::parse_str(id).is_err() {
            return Err(());
        }
        Ok(id.to_owned())
    }
    let mut out = MaintenanceApplyArgs::default();
    for arg in tokens {
        if let Some(spec) = arg.strip_prefix("--set=") {
            if out.filled() != 0 {
                return Err(());
            }
            let Some((name, target)) = spec.split_once('=') else {
                return Err(());
            };
            if name.is_empty() || target.is_empty() {
                return Err(());
            }
            out.set = spec.to_owned();
        } else if arg.starts_with("--resume=") {
            out.resume = id_flag(arg, "--resume=", out.filled())?;
        } else if arg.starts_with("--rollback=") {
            out.rollback = id_flag(arg, "--rollback=", out.filled())?;
        } else if arg.starts_with("--abandon=") {
            out.abandon = id_flag(arg, "--abandon=", out.filled())?;
        } else {
            return Err(());
        }
    }
    if out.filled() != 1 {
        return Err(());
    }
    Ok(out)
}

/// `mapHelperMaintenanceApplyError` + `maintenanceApplyErrorResult` —
/// the closed reason → (exit class, reason, safe next action, partial
/// result) table. The helper may attach a bounded partial result to a
/// refusal; it rides along so the evidence still records the attempt.
fn maintenance_apply_error_result(
    err: &MaintenanceClientError,
) -> (
    ExitClass,
    &'static str,
    &'static str,
    MaintenanceApplyResult,
) {
    let partial = err.apply_result().cloned().unwrap_or_default();
    let class = exit_class_of(err.exit_code());
    let (reason, next) = match err.reason() {
        "DENY_SAFE_ACTIVE" => ("DENY_SAFE_ACTIVE", "RUN_CENTRAL_LOCAL_SECURITY_RESCUE"),
        m::REASON_UNLISTED => (m::REASON_UNLISTED, "RESOLVE_MATRIX_TRANSITION"),
        REASON_MAINTENANCE_MATRIX_TAMPERED => {
            (REASON_MAINTENANCE_MATRIX_TAMPERED, "INSPECT_MATRIX_STATE")
        }
        m::REASON_PATCH_PENDING => (m::REASON_PATCH_PENDING, "RESUME_OR_ABANDON_PENDING_PATCH"),
        m::REASON_PATCH_UNKNOWN => (m::REASON_PATCH_UNKNOWN, "RESOLVE_MATRIX_TRANSITION"),
        m::REASON_PATCH_CLOSED => (m::REASON_PATCH_CLOSED, "RESOLVE_MATRIX_TRANSITION"),
        m::REASON_GATE_FAILED => (m::REASON_GATE_FAILED, "OBSERVE_TARGET_THEN_RETRY"),
        m::REASON_GATE_UNKNOWN => (m::REASON_GATE_UNKNOWN, "RESOLVE_MATRIX_TRANSITION"),
        m::REASON_ROLLBACK_STALE => (m::REASON_ROLLBACK_STALE, "INSPECT_MATRIX_STATE"),
        _ => ("MAINTENANCE_APPLY_FAILED", "RETRY_MAINTENANCE_APPLY"),
    };
    (class, reason, next, partial)
}

/// `applyVerdictForReason` — a gate failure records `failed`; every
/// other refusal records `refused`.
fn apply_verdict_for_reason(reason: &str) -> &'static str {
    if reason == m::REASON_GATE_FAILED {
        "failed"
    } else {
        "refused"
    }
}
