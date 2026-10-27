//! `runLocalWipe`/`runBackupDelete`/`runBackupPrune` — the D01/D04 CLI
//! entry points. Each parses its own grammar, mints a ceremony-bound
//! operation id, delegates the destructive verb to the authority
//! helper over the production socket, validates the bounded result,
//! and writes the D-slice evidence artifact to the working directory.
//! No result is trusted: every field the envelope prints is proven
//! against what the CLI sent.

use std::io::Write;
use std::time::Instant;

use central_adapter_linux::helper::audit::REASON_DENY_SAFE_ACTIVE;
use central_adapter_linux::helper::backup::BackupCreateClient;
use central_adapter_linux::helper::delete::{DeleteClient, DeleteClientError};
use central_adapter_linux::helper::prune::{PruneBody, PruneClient, PruneClientError};
use central_adapter_linux::helper::wipe::{WipeClient, WipeClientError};
use central_foundation::failure::ExitClass;
use central_foundation::local_result::LocalResult;
use central_infra::destructive::{self as domain, AppArmorState, DeleteEvidence, WipeEvidence};
use serde::Serialize;
use uuid::Uuid;

/// `WipeEvidenceFileName` — the D01 evidence artifact.
const WIPE_EVIDENCE_FILE_NAME: &str = "slice-d-wipe-reseed.json";
/// `DeletePruneEvidenceFileName` — the D04 evidence artifact delete
/// and prune-apply both write.
const DELETE_PRUNE_EVIDENCE_FILE_NAME: &str = "slice-d-delete-prune.json";
/// `PrunePlanFilePrefix` — `slice-d-prune-plan-<plan-id>.json`.
const PRUNE_PLAN_FILE_PREFIX: &str = "slice-d-prune-plan-";

/// `WipeDetails` — the only wipe payload emitted to stdout:
/// identities and state, never a path or credential.
#[derive(Debug, Default, Serialize)]
struct WipeDetails {
    #[serde(skip_serializing_if = "String::is_empty")]
    operation_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    wiped_instance_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    new_instance_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    checkpoint_backup_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    apparmor: String,
    safe_next_action: String,
    elapsed_ms: u64,
}

/// `DeleteDetails` — the only delete payload emitted to stdout.
#[derive(Debug, Default, Serialize)]
struct DeleteDetails {
    #[serde(skip_serializing_if = "String::is_empty")]
    operation_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    backup_id: String,
    #[serde(skip_serializing_if = "is_zero_i32")]
    retention_age_days: i32,
    #[serde(skip_serializing_if = "is_zero_i32")]
    reference_count: i32,
    safe_next_action: String,
    elapsed_ms: u64,
}

/// `PruneDetails` — the only prune payload emitted to stdout.
#[derive(Debug, Default, Serialize)]
struct PruneDetails {
    #[serde(skip_serializing_if = "String::is_empty")]
    operation_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    plan_id: String,
    #[serde(skip_serializing_if = "is_zero_i64")]
    body_count: i64,
    #[serde(skip_serializing_if = "is_zero_i64")]
    bodies_deleted: i64,
    #[serde(skip_serializing_if = "is_zero_i64")]
    batches_done: i64,
    #[serde(skip_serializing_if = "is_false")]
    resumed_after_crash: bool,
    safe_next_action: String,
    elapsed_ms: u64,
}

/// `PrunePlanFile` — the intermediate plan file `prune plan` writes
/// and `prune apply` reads back. The helper re-proves every body
/// before deleting, so a hand-edited plan cannot smuggle a young or
/// referenced body past the checks.
#[derive(Debug, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PrunePlanFile {
    plan_id: String,
    retention_days: i32,
    bodies: Vec<PruneBody>,
    created_at: String,
}

fn is_zero_i32(v: &i32) -> bool {
    *v == 0
}

fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}

fn is_false(v: &bool) -> bool {
    !*v
}

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

fn envelope<T: Serialize>(
    command_id: &str,
    class: ExitClass,
    reason: &str,
    details: &T,
) -> LocalResult {
    LocalResult::now(
        command_id,
        class,
        Some(reason.to_owned()),
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

// -- `central local wipe --target <path>` ---------------------------------

/// `runLocalWipe` — `local wipe --target <path>`: seal a C01
/// checkpoint backup (its own ceremony), wipe with the checkpoint
/// bound, write `slice-d-wipe-reseed.json`.
pub(crate) fn local_wipe(
    command_id: &str,
    tokens: &[String],
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> u8 {
    let started = Instant::now();
    if tokens.len() != 2 || tokens[0] != "--target" || tokens[1].is_empty() {
        return emit(
            envelope(
                command_id,
                ExitClass::Usage,
                "INVALID_WIPE_GRAMMAR",
                &WipeDetails {
                    safe_next_action: "RUN_CENTRAL_LOCAL_WIPE_WITH_TARGET_PATH".to_owned(),
                    elapsed_ms: elapsed_ms(started),
                    ..WipeDetails::default()
                },
            ),
            stdout,
            stderr,
        );
    }
    emit(
        execute_wipe(command_id, &tokens[1], started),
        stdout,
        stderr,
    )
}

/// `executeWipe` — the D01 operator flow with the production helper
/// clients and the working directory as evidence root.
fn execute_wipe(command_id: &str, target_path: &str, started: Instant) -> LocalResult {
    let socket = crate::backup_cli::helper_socket_path();
    let checkpoint_op = Uuid::now_v7().to_string();
    let checkpoint = match BackupCreateClient::new(&socket).create_backup(&checkpoint_op) {
        Ok(result)
            if result.operation_id == checkpoint_op
                && !result.backup_id.is_empty()
                && result.phase == "sealed" =>
        {
            result
        }
        _ => {
            return envelope(
                command_id,
                ExitClass::Terminal,
                domain::REASON_WIPE_CHECKPOINT_FAILED,
                &WipeDetails {
                    operation_id: checkpoint_op,
                    safe_next_action: "CREATE_CHECKPOINT_BACKUP_FIRST".to_owned(),
                    elapsed_ms: elapsed_ms(started),
                    ..WipeDetails::default()
                },
            );
        }
    };
    let wipe_op = Uuid::now_v7().to_string();
    let result = match WipeClient::new(&socket).wipe(&wipe_op, target_path, &checkpoint.backup_id) {
        Ok(result) => result,
        Err(err) => {
            let (class, reason, next) = wipe_error_result(&err);
            return envelope(
                command_id,
                class,
                reason,
                &WipeDetails {
                    operation_id: wipe_op,
                    safe_next_action: next.to_owned(),
                    elapsed_ms: elapsed_ms(started),
                    ..WipeDetails::default()
                },
            );
        }
    };
    if result.operation_id != wipe_op
        || result.wiped_instance_id.is_empty()
        || result.new_instance_id.is_empty()
        || result.checkpoint_backup_id != checkpoint.backup_id
    {
        return envelope(
            command_id,
            ExitClass::Terminal,
            "WIPE_RESULT_INVALID",
            &WipeDetails {
                operation_id: wipe_op,
                safe_next_action: "INSPECT_WIPE_STATE".to_owned(),
                elapsed_ms: elapsed_ms(started),
                ..WipeDetails::default()
            },
        );
    }
    let apparmor = match result.apparmor.as_str() {
        "not_confined" => AppArmorState::NotConfined,
        "profile_removed" => AppArmorState::ProfileRemoved,
        _ => {
            return envelope(
                command_id,
                ExitClass::Terminal,
                "WIPE_RESULT_INVALID",
                &WipeDetails {
                    operation_id: wipe_op,
                    safe_next_action: "INSPECT_WIPE_STATE".to_owned(),
                    elapsed_ms: elapsed_ms(started),
                    ..WipeDetails::default()
                },
            );
        }
    };
    let evidence = WipeEvidence {
        operation_id: result.operation_id.clone(),
        wiped_instance_id: result.wiped_instance_id.clone(),
        new_instance_id: result.new_instance_id.clone(),
        checkpoint_backup_id: result.checkpoint_backup_id.clone(),
        apparmor,
        resumed_after_crash: result.resumed_after_crash,
        completed_at: result.completed_at.clone(),
    };
    if write_evidence(WIPE_EVIDENCE_FILE_NAME, &evidence).is_err() {
        return envelope(
            command_id,
            ExitClass::Terminal,
            "WIPE_EVIDENCE_FAILED",
            &WipeDetails {
                operation_id: wipe_op,
                safe_next_action: "INSPECT_WIPE_STATE".to_owned(),
                elapsed_ms: elapsed_ms(started),
                ..WipeDetails::default()
            },
        );
    }
    envelope(
        command_id,
        ExitClass::Success,
        "ok",
        &WipeDetails {
            operation_id: result.operation_id,
            wiped_instance_id: result.wiped_instance_id,
            new_instance_id: result.new_instance_id,
            checkpoint_backup_id: result.checkpoint_backup_id,
            apparmor: result.apparmor,
            safe_next_action: "WIPE_COMPLETE".to_owned(),
            elapsed_ms: elapsed_ms(started),
        },
    )
}

/// `mapHelperWipeError` + `wipeErrorResult` — the closed reason→
/// (exit class, reason, safe next action) table.
fn wipe_error_result(err: &WipeClientError) -> (ExitClass, &'static str, &'static str) {
    // Upstream's `mapHelperWipeError`: an empty reason is the
    // transport/decode failure — `!errors.As` — which collapses to
    // terminal `WIPE_FAILED` rather than inheriting a wire class.
    if err.reason().is_empty() {
        return (ExitClass::Terminal, "WIPE_FAILED", "INSPECT_WIPE_STATE");
    }
    let class = exit_class_of(err.exit_code());
    match err.reason() {
        r if r == REASON_DENY_SAFE_ACTIVE => (
            class,
            REASON_DENY_SAFE_ACTIVE,
            "RUN_CENTRAL_LOCAL_SECURITY_RESCUE",
        ),
        r if r == domain::REASON_WIPE_DENIED_SIGNED => (
            class,
            domain::REASON_WIPE_DENIED_SIGNED,
            "RESOLVE_ADVISORY_DENIAL",
        ),
        r if r == domain::REASON_WIPE_CHECKPOINT_FAILED => (
            class,
            domain::REASON_WIPE_CHECKPOINT_FAILED,
            "CREATE_CHECKPOINT_BACKUP_FIRST",
        ),
        r if r == domain::REASON_WIPE_APPARMOR_REFUSED => (
            class,
            domain::REASON_WIPE_APPARMOR_REFUSED,
            "CLEAR_APPARMOR_CONFINEMENT",
        ),
        r if r == domain::REASON_WIPE_TARGET_INVALID => (
            class,
            domain::REASON_WIPE_TARGET_INVALID,
            "NAME_INSTALLED_STATE_ROOT",
        ),
        r if r == domain::REASON_WIPE_TARGET_LIVE => (
            class,
            domain::REASON_WIPE_TARGET_LIVE,
            "RUN_CENTRAL_LOCAL_DOWN_FIRST",
        ),
        r if r == domain::REASON_WIPE_RESEED_FAILED => (
            class,
            domain::REASON_WIPE_RESEED_FAILED,
            "INSPECT_WIPE_STATE",
        ),
        r if r == domain::REASON_WIPE_CEREMONY_REQUIRED => (
            class,
            domain::REASON_WIPE_CEREMONY_REQUIRED,
            "COMPLETE_WIPE_CEREMONY",
        ),
        r if r == domain::REASON_WIPE_AUTHORITY_DENIED => (
            class,
            domain::REASON_WIPE_AUTHORITY_DENIED,
            "COMPLETE_WIPE_CEREMONY",
        ),
        _ => (class, "WIPE_FAILED", "INSPECT_WIPE_STATE"),
    }
}

// -- `central backup delete` ----------------------------------------------

/// `runBackupDelete` — `backup delete [--backup=<uuid>]
/// [--retention-days=<n>]`; empty `--backup` resolves the single
/// sealed candidate helper-side.
pub(crate) fn backup_delete(
    command_id: &str,
    tokens: &[String],
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> u8 {
    let started = Instant::now();
    let (backup_id, retention_days) = match parse_delete_args(tokens) {
        Ok(parsed) => parsed,
        Err(()) => {
            return emit(
                envelope(
                    command_id,
                    ExitClass::Usage,
                    "INVALID_DELETE_GRAMMAR",
                    &DeleteDetails {
                        safe_next_action: "RUN_CENTRAL_BACKUP_DELETE_WITH_FLAGS".to_owned(),
                        elapsed_ms: elapsed_ms(started),
                        ..DeleteDetails::default()
                    },
                ),
                stdout,
                stderr,
            );
        }
    };
    let operation_id = Uuid::now_v7().to_string();
    let result = match DeleteClient::new(crate::backup_cli::helper_socket_path()).delete(
        &operation_id,
        &backup_id,
        retention_days,
    ) {
        Ok(result) => result,
        Err(err) => {
            let (class, reason, next) = delete_error_result(&err);
            return emit(
                envelope(
                    command_id,
                    class,
                    reason,
                    &DeleteDetails {
                        operation_id,
                        safe_next_action: next.to_owned(),
                        elapsed_ms: elapsed_ms(started),
                        ..DeleteDetails::default()
                    },
                ),
                stdout,
                stderr,
            );
        }
    };
    // `validDeleteResult` — the helper's echo is proven, not trusted.
    if result.operation_id != operation_id
        || result.backup_id.is_empty()
        || result.completed_at.is_empty()
        || (!backup_id.is_empty() && result.backup_id != backup_id)
        || result.retention_age_days < 0
        || result.reference_count < 0
    {
        return emit(
            envelope(
                command_id,
                ExitClass::Terminal,
                "DELETE_RESULT_INVALID",
                &DeleteDetails {
                    operation_id,
                    safe_next_action: "INSPECT_DELETE_STATE".to_owned(),
                    elapsed_ms: elapsed_ms(started),
                    ..DeleteDetails::default()
                },
            ),
            stdout,
            stderr,
        );
    }
    let evidence = DeleteEvidence {
        operation_id: result.operation_id.clone(),
        verb: "delete".to_owned(),
        plan_id: String::new(),
        backup_id: result.backup_id.clone(),
        bodies_deleted: 1,
        batches_done: 0,
        resumed_after_crash: false,
        completed_at: result.completed_at.clone(),
    };
    if write_evidence(DELETE_PRUNE_EVIDENCE_FILE_NAME, &evidence).is_err() {
        return emit(
            envelope(
                command_id,
                ExitClass::Terminal,
                "DELETE_EVIDENCE_FAILED",
                &DeleteDetails {
                    operation_id,
                    safe_next_action: "INSPECT_DELETE_STATE".to_owned(),
                    elapsed_ms: elapsed_ms(started),
                    ..DeleteDetails::default()
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
            &DeleteDetails {
                operation_id: result.operation_id,
                backup_id: result.backup_id,
                retention_age_days: result.retention_age_days,
                reference_count: result.reference_count,
                safe_next_action: "DELETE_COMPLETE".to_owned(),
                elapsed_ms: elapsed_ms(started),
            },
        ),
        stdout,
        stderr,
    )
}

/// `parseDeleteArgs` — `--backup=<uuid>` and `--retention-days=<n>`,
/// each at most once; below-floor retention is refused.
fn parse_delete_args(tokens: &[String]) -> Result<(String, i32), ()> {
    let mut backup_id = String::new();
    let mut retention_days = 0i32;
    let mut seen_backup = false;
    let mut seen_retention = false;
    for token in tokens {
        if let Some(value) = token.strip_prefix("--backup=") {
            if seen_backup {
                return Err(());
            }
            seen_backup = true;
            match Uuid::parse_str(value) {
                Ok(id) if !id.is_nil() => backup_id = value.to_owned(),
                _ => return Err(()),
            }
        } else if let Some(value) = token.strip_prefix("--retention-days=") {
            if seen_retention {
                return Err(());
            }
            seen_retention = true;
            match value.parse::<i32>() {
                Ok(days) if days >= domain::DEFAULT_RETENTION_DAYS => retention_days = days,
                _ => return Err(()),
            }
        } else {
            return Err(());
        }
    }
    Ok((backup_id, retention_days))
}

/// `mapHelperDeleteError` + `deleteErrorResult`.
fn delete_error_result(err: &DeleteClientError) -> (ExitClass, &'static str, &'static str) {
    if err.reason().is_empty() {
        return (ExitClass::Terminal, "DELETE_FAILED", "INSPECT_DELETE_STATE");
    }
    let class = exit_class_of(err.exit_code());
    match err.reason() {
        r if r == REASON_DENY_SAFE_ACTIVE => (
            class,
            REASON_DENY_SAFE_ACTIVE,
            "RUN_CENTRAL_LOCAL_SECURITY_RESCUE",
        ),
        r if r == domain::REASON_DELETE_UNAVAILABLE => (
            class,
            domain::REASON_DELETE_UNAVAILABLE,
            "INSTALL_DELETE_SERVICE",
        ),
        r if r == domain::REASON_DELETE_NO_BACKUP => (
            class,
            domain::REASON_DELETE_NO_BACKUP,
            "CREATE_BACKUP_FIRST",
        ),
        r if r == domain::REASON_DELETE_BACKUP_AMBIGUOUS => (
            class,
            domain::REASON_DELETE_BACKUP_AMBIGUOUS,
            "NAME_BACKUP_EXPLICITLY",
        ),
        r if r == domain::REASON_DELETE_RETENTION_TOO_YOUNG => (
            class,
            domain::REASON_DELETE_RETENTION_TOO_YOUNG,
            "WAIT_FOR_RETENTION",
        ),
        r if r == domain::REASON_DELETE_REFERENCED => (
            class,
            domain::REASON_DELETE_REFERENCED,
            "RESOLVE_BACKUP_REFERENCES",
        ),
        r if r == domain::REASON_DELETE_DENIED_SIGNED => (
            class,
            domain::REASON_DELETE_DENIED_SIGNED,
            "RESOLVE_ADVISORY_DENIAL",
        ),
        r if r == domain::REASON_DELETE_CEREMONY_REQUIRED => (
            class,
            domain::REASON_DELETE_CEREMONY_REQUIRED,
            "COMPLETE_DELETE_CEREMONY",
        ),
        r if r == domain::REASON_DELETE_AUTHORITY_DENIED => (
            class,
            domain::REASON_DELETE_AUTHORITY_DENIED,
            "COMPLETE_DELETE_CEREMONY",
        ),
        _ => (class, "DELETE_FAILED", "INSPECT_DELETE_STATE"),
    }
}

// -- `central backup prune plan|apply` ------------------------------------

/// `runBackupPrune` — routes the sub-action on the first token, the
/// `local.init.*` precedent: both registry entries share the
/// `(backup, prune)` dispatch key.
pub(crate) fn backup_prune(
    command_id: &str,
    tokens: &[String],
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> u8 {
    let started = Instant::now();
    match tokens.first().map(String::as_str) {
        Some("plan") => run_prune_plan(command_id, &tokens[1..], started, stdout, stderr),
        Some("apply") => run_prune_apply(command_id, &tokens[1..], started, stdout, stderr),
        _ => emit(
            envelope(
                command_id,
                ExitClass::Usage,
                "INVALID_PRUNE_GRAMMAR",
                &PruneDetails {
                    safe_next_action: "RUN_CENTRAL_BACKUP_PRUNE_PLAN_OR_APPLY".to_owned(),
                    elapsed_ms: elapsed_ms(started),
                    ..PruneDetails::default()
                },
            ),
            stdout,
            stderr,
        ),
    }
}

fn run_prune_plan(
    command_id: &str,
    tokens: &[String],
    started: Instant,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> u8 {
    let retention_days = match parse_prune_retention_flag(tokens) {
        Ok(days) => days,
        Err(()) => {
            return emit(
                envelope(
                    command_id,
                    ExitClass::Usage,
                    "INVALID_PRUNE_GRAMMAR",
                    &PruneDetails {
                        safe_next_action: "RUN_CENTRAL_BACKUP_PRUNE_PLAN".to_owned(),
                        elapsed_ms: elapsed_ms(started),
                        ..PruneDetails::default()
                    },
                ),
                stdout,
                stderr,
            );
        }
    };
    let operation_id = Uuid::now_v7().to_string();
    let result = match PruneClient::new(crate::backup_cli::helper_socket_path())
        .plan(&operation_id, retention_days)
    {
        Ok(result) => result,
        Err(err) => {
            let (class, reason, next) = prune_error_result(&err);
            return emit(
                envelope(
                    command_id,
                    class,
                    reason,
                    &PruneDetails {
                        operation_id,
                        safe_next_action: next.to_owned(),
                        elapsed_ms: elapsed_ms(started),
                        ..PruneDetails::default()
                    },
                ),
                stdout,
                stderr,
            );
        }
    };
    // `validPrunePlanResult`.
    if result.operation_id != operation_id
        || result.completed_at.is_empty()
        || Uuid::parse_str(&result.plan_id)
            .map(|id| id.is_nil())
            .unwrap_or(true)
    {
        return emit(
            envelope(
                command_id,
                ExitClass::Terminal,
                "PRUNE_RESULT_INVALID",
                &PruneDetails {
                    operation_id,
                    safe_next_action: "INSPECT_PRUNE_STATE".to_owned(),
                    elapsed_ms: elapsed_ms(started),
                    ..PruneDetails::default()
                },
            ),
            stdout,
            stderr,
        );
    }
    let bodies = result.bodies.clone().unwrap_or_default();
    let plan_file = PrunePlanFile {
        plan_id: result.plan_id.clone(),
        retention_days,
        bodies: bodies.clone(),
        created_at: result.completed_at.clone(),
    };
    if write_evidence(
        &format!("{PRUNE_PLAN_FILE_PREFIX}{}.json", result.plan_id),
        &plan_file,
    )
    .is_err()
    {
        return emit(
            envelope(
                command_id,
                ExitClass::Terminal,
                "PRUNE_EVIDENCE_FAILED",
                &PruneDetails {
                    operation_id,
                    plan_id: result.plan_id,
                    safe_next_action: "INSPECT_PRUNE_STATE".to_owned(),
                    elapsed_ms: elapsed_ms(started),
                    ..PruneDetails::default()
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
            &PruneDetails {
                operation_id: result.operation_id,
                plan_id: result.plan_id,
                body_count: bodies.len() as i64,
                safe_next_action: "PRUNE_PLAN_COMPLETE".to_owned(),
                elapsed_ms: elapsed_ms(started),
                ..PruneDetails::default()
            },
        ),
        stdout,
        stderr,
    )
}

fn run_prune_apply(
    command_id: &str,
    tokens: &[String],
    started: Instant,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> u8 {
    let (plan_id, mut retention_days) = match parse_prune_apply_args(tokens) {
        Ok(parsed) => parsed,
        Err(()) => {
            return emit(
                envelope(
                    command_id,
                    ExitClass::Usage,
                    "INVALID_PRUNE_GRAMMAR",
                    &PruneDetails {
                        safe_next_action: "RUN_CENTRAL_BACKUP_PRUNE_APPLY_WITH_PLAN".to_owned(),
                        elapsed_ms: elapsed_ms(started),
                        ..PruneDetails::default()
                    },
                ),
                stdout,
                stderr,
            );
        }
    };
    let plan = match read_prune_plan_file(&plan_id) {
        Ok(plan) => plan,
        Err(()) => {
            return emit(
                envelope(
                    command_id,
                    ExitClass::Terminal,
                    "PRUNE_PLAN_UNKNOWN",
                    &PruneDetails {
                        plan_id,
                        safe_next_action: "RUN_CENTRAL_BACKUP_PRUNE_PLAN_FIRST".to_owned(),
                        elapsed_ms: elapsed_ms(started),
                        ..PruneDetails::default()
                    },
                ),
                stdout,
                stderr,
            );
        }
    };
    if retention_days == 0 {
        retention_days = plan.retention_days;
    }
    let operation_id = Uuid::now_v7().to_string();
    let result = match PruneClient::new(crate::backup_cli::helper_socket_path()).apply(
        &operation_id,
        &plan_id,
        &plan.bodies,
        retention_days,
    ) {
        Ok(result) => result,
        Err(err) => {
            let (class, reason, next) = prune_error_result(&err);
            return emit(
                envelope(
                    command_id,
                    class,
                    reason,
                    &PruneDetails {
                        operation_id,
                        plan_id,
                        safe_next_action: next.to_owned(),
                        elapsed_ms: elapsed_ms(started),
                        ..PruneDetails::default()
                    },
                ),
                stdout,
                stderr,
            );
        }
    };
    // `validPruneApplyResult`.
    if result.operation_id != operation_id
        || result.plan_id != plan_id
        || result.completed_at.is_empty()
        || result.bodies_deleted < 0
        || result.batches_done < 0
    {
        return emit(
            envelope(
                command_id,
                ExitClass::Terminal,
                "PRUNE_RESULT_INVALID",
                &PruneDetails {
                    operation_id,
                    plan_id,
                    safe_next_action: "INSPECT_PRUNE_STATE".to_owned(),
                    elapsed_ms: elapsed_ms(started),
                    ..PruneDetails::default()
                },
            ),
            stdout,
            stderr,
        );
    }
    let evidence = DeleteEvidence {
        operation_id: result.operation_id.clone(),
        verb: "prune-apply".to_owned(),
        plan_id: result.plan_id.clone(),
        backup_id: String::new(),
        bodies_deleted: result.bodies_deleted,
        batches_done: result.batches_done,
        resumed_after_crash: result.resumed_after_crash,
        completed_at: result.completed_at.clone(),
    };
    if write_evidence(DELETE_PRUNE_EVIDENCE_FILE_NAME, &evidence).is_err() {
        return emit(
            envelope(
                command_id,
                ExitClass::Terminal,
                "PRUNE_EVIDENCE_FAILED",
                &PruneDetails {
                    operation_id,
                    plan_id,
                    safe_next_action: "INSPECT_PRUNE_STATE".to_owned(),
                    elapsed_ms: elapsed_ms(started),
                    ..PruneDetails::default()
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
            &PruneDetails {
                operation_id: result.operation_id,
                plan_id: result.plan_id,
                bodies_deleted: result.bodies_deleted,
                batches_done: result.batches_done,
                resumed_after_crash: result.resumed_after_crash,
                safe_next_action: "PRUNE_APPLY_COMPLETE".to_owned(),
                elapsed_ms: elapsed_ms(started),
                ..PruneDetails::default()
            },
        ),
        stdout,
        stderr,
    )
}

/// `parsePruneRetentionFlag` — the one optional flag; below the
/// dossier floor is refused, absence selects the helper default.
fn parse_prune_retention_flag(tokens: &[String]) -> Result<i32, ()> {
    let mut retention_days = 0i32;
    let mut seen = false;
    for token in tokens {
        let Some(value) = token.strip_prefix("--retention-days=") else {
            return Err(());
        };
        if seen {
            return Err(());
        }
        seen = true;
        match value.parse::<i32>() {
            Ok(days) if days >= domain::DEFAULT_RETENTION_DAYS => retention_days = days,
            _ => return Err(()),
        }
    }
    Ok(retention_days)
}

/// `parsePruneApplyArgs` — `--plan=<uuid>` required once plus the
/// optional retention flag.
fn parse_prune_apply_args(tokens: &[String]) -> Result<(String, i32), ()> {
    let mut plan_id = String::new();
    let mut seen_plan = false;
    let mut rest = Vec::new();
    for token in tokens {
        if let Some(value) = token.strip_prefix("--plan=") {
            if seen_plan {
                return Err(());
            }
            seen_plan = true;
            match Uuid::parse_str(value) {
                Ok(id) if !id.is_nil() => plan_id = value.to_owned(),
                _ => return Err(()),
            }
        } else {
            rest.push(token.clone());
        }
    }
    if !seen_plan {
        return Err(());
    }
    let retention_days = parse_prune_retention_flag(&rest)?;
    Ok((plan_id, retention_days))
}

/// `readPrunePlanFile` — the file name derives from the validated
/// plan UUID alone; no operator path is accepted, so no traversal is
/// possible. Unknown fields and a plan-id mismatch are refused.
fn read_prune_plan_file(plan_id: &str) -> Result<PrunePlanFile, ()> {
    match Uuid::parse_str(plan_id) {
        Ok(id) if !id.is_nil() && id.to_string() == plan_id => {}
        _ => return Err(()),
    }
    let raw = std::fs::read(format!("{PRUNE_PLAN_FILE_PREFIX}{plan_id}.json")).map_err(|_| ())?;
    let plan: PrunePlanFile = serde_json::from_slice(&raw).map_err(|_| ())?;
    if plan.plan_id != plan_id || plan.bodies.is_empty() {
        return Err(());
    }
    for body in &plan.bodies {
        if body.artifact_id.is_empty()
            || body.workspace_id.is_empty()
            || body.object_key.is_empty()
            || body.staging_generation.is_empty()
        {
            return Err(());
        }
    }
    Ok(plan)
}

/// `mapHelperPruneError` + `pruneErrorResult`.
fn prune_error_result(err: &PruneClientError) -> (ExitClass, &'static str, &'static str) {
    if err.reason().is_empty() {
        return (ExitClass::Terminal, "PRUNE_FAILED", "INSPECT_PRUNE_STATE");
    }
    let class = exit_class_of(err.exit_code());
    match err.reason() {
        r if r == REASON_DENY_SAFE_ACTIVE => (
            class,
            REASON_DENY_SAFE_ACTIVE,
            "RUN_CENTRAL_LOCAL_SECURITY_RESCUE",
        ),
        r if r == domain::REASON_PRUNE_UNAVAILABLE => (
            class,
            domain::REASON_PRUNE_UNAVAILABLE,
            "INSTALL_PRUNE_SERVICE",
        ),
        r if r == domain::REASON_PRUNE_PLAN_STALE => {
            (class, domain::REASON_PRUNE_PLAN_STALE, "REPLAN_PRUNE")
        }
        r if r == domain::REASON_PRUNE_DENIED_SIGNED => (
            class,
            domain::REASON_PRUNE_DENIED_SIGNED,
            "RESOLVE_ADVISORY_DENIAL",
        ),
        r if r == domain::REASON_PRUNE_CEREMONY_REQUIRED => (
            class,
            domain::REASON_PRUNE_CEREMONY_REQUIRED,
            "COMPLETE_PRUNE_CEREMONY",
        ),
        r if r == domain::REASON_PRUNE_AUTHORITY_DENIED => (
            class,
            domain::REASON_PRUNE_AUTHORITY_DENIED,
            "COMPLETE_PRUNE_CEREMONY",
        ),
        _ => (class, "PRUNE_FAILED", "INSPECT_PRUNE_STATE"),
    }
}

/// `os.WriteFile(name, marshalIndent(evidence)+"\n", 0o644)` — the
/// evidence artifact lands atomically enough for a CLI (create +
/// write + sync would be stronger; upstream writes plainly, and the
/// file carries identities only).
fn write_evidence<T: Serialize>(name: &str, evidence: &T) -> Result<(), ()> {
    let mut body = serde_json::to_vec_pretty(evidence).map_err(|_| ())?;
    body.push(b'\n');
    std::fs::write(name, body).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(argv: &[&str]) -> Vec<String> {
        argv.iter().map(|s| (*s).to_string()).collect()
    }

    // -- grammar -----------------------------------------------------------

    #[test]
    fn delete_args_accept_explicit_backup_and_retention() {
        let id = Uuid::now_v7().to_string();
        let (backup, days) =
            parse_delete_args(&args(&[&format!("--backup={id}"), "--retention-days=45"])).unwrap();
        assert_eq!(backup, id);
        assert_eq!(days, 45);
    }

    #[test]
    fn delete_args_reject_bad_flags_and_below_floor_retention() {
        for tokens in [
            args(&["--retention-days=29"]),
            args(&["--retention-days=abc"]),
            args(&["--backup=not-a-uuid"]),
            args(&["--unknown=1"]),
            args(&["--retention-days=30", "--retention-days=31"]),
        ] {
            assert!(parse_delete_args(&tokens).is_err(), "{tokens:?}");
        }
        // No flags at all resolves the single sealed candidate.
        let (backup, days) = parse_delete_args(&args(&[])).unwrap();
        assert!(backup.is_empty() && days == 0);
    }

    #[test]
    fn prune_plan_args_accept_only_retention_flag() {
        assert_eq!(parse_prune_retention_flag(&args(&[])).unwrap(), 0);
        assert_eq!(
            parse_prune_retention_flag(&args(&["--retention-days=30"])).unwrap(),
            30
        );
        for tokens in [
            args(&["--retention-days=29"]),
            args(&["--plan=x"]),
            args(&["--retention-days=30", "--retention-days=31"]),
        ] {
            assert!(parse_prune_retention_flag(&tokens).is_err(), "{tokens:?}");
        }
    }

    #[test]
    fn prune_apply_args_require_one_plan_uuid() {
        let id = Uuid::now_v7().to_string();
        let (plan, days) =
            parse_prune_apply_args(&args(&[&format!("--plan={id}"), "--retention-days=45"]))
                .unwrap();
        assert_eq!(plan, id);
        assert_eq!(days, 45);
        for tokens in [
            args(&[]),
            args(&["--plan=not-a-uuid"]),
            args(&[&format!("--plan={id}"), &format!("--plan={id}")]),
        ] {
            assert!(parse_prune_apply_args(&tokens).is_err(), "{tokens:?}");
        }
    }

    #[test]
    fn wipe_grammar_requires_exactly_target_flag() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = local_wipe("local.wipe", &args(&["--target"]), &mut out, &mut err);
        assert_eq!(code, 2);
        let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(parsed["reason"], "INVALID_WIPE_GRAMMAR");
        assert_eq!(
            parsed["details"]["safe_next_action"],
            "RUN_CENTRAL_LOCAL_WIPE_WITH_TARGET_PATH"
        );
    }

    #[test]
    fn prune_routes_plan_apply_and_refuses_unknown() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = backup_prune("backup.prune.plan", &args(&["bogus"]), &mut out, &mut err);
        assert_eq!(code, 2);
        let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(parsed["reason"], "INVALID_PRUNE_GRAMMAR");
    }

    // -- error tables ------------------------------------------------------

    #[test]
    fn wipe_error_table_maps_every_stable_reason() {
        let cases: &[(i64, &str, ExitClass, &str, &str)] = &[
            (
                7,
                REASON_DENY_SAFE_ACTIVE,
                ExitClass::Denied,
                REASON_DENY_SAFE_ACTIVE,
                "RUN_CENTRAL_LOCAL_SECURITY_RESCUE",
            ),
            (
                7,
                domain::REASON_WIPE_DENIED_SIGNED,
                ExitClass::Denied,
                domain::REASON_WIPE_DENIED_SIGNED,
                "RESOLVE_ADVISORY_DENIAL",
            ),
            (
                6,
                domain::REASON_WIPE_CHECKPOINT_FAILED,
                ExitClass::Terminal,
                domain::REASON_WIPE_CHECKPOINT_FAILED,
                "CREATE_CHECKPOINT_BACKUP_FIRST",
            ),
            (
                6,
                domain::REASON_WIPE_APPARMOR_REFUSED,
                ExitClass::Terminal,
                domain::REASON_WIPE_APPARMOR_REFUSED,
                "CLEAR_APPARMOR_CONFINEMENT",
            ),
            (
                2,
                domain::REASON_WIPE_TARGET_INVALID,
                ExitClass::Usage,
                domain::REASON_WIPE_TARGET_INVALID,
                "NAME_INSTALLED_STATE_ROOT",
            ),
            (
                5,
                domain::REASON_WIPE_TARGET_LIVE,
                ExitClass::Incompatible,
                domain::REASON_WIPE_TARGET_LIVE,
                "RUN_CENTRAL_LOCAL_DOWN_FIRST",
            ),
            (
                6,
                domain::REASON_WIPE_RESEED_FAILED,
                ExitClass::Terminal,
                domain::REASON_WIPE_RESEED_FAILED,
                "INSPECT_WIPE_STATE",
            ),
            (
                7,
                domain::REASON_WIPE_CEREMONY_REQUIRED,
                ExitClass::Denied,
                domain::REASON_WIPE_CEREMONY_REQUIRED,
                "COMPLETE_WIPE_CEREMONY",
            ),
            (
                7,
                domain::REASON_WIPE_AUTHORITY_DENIED,
                ExitClass::Denied,
                domain::REASON_WIPE_AUTHORITY_DENIED,
                "COMPLETE_WIPE_CEREMONY",
            ),
            (
                6,
                "ANYTHING_ELSE",
                ExitClass::Terminal,
                "WIPE_FAILED",
                "INSPECT_WIPE_STATE",
            ),
        ];
        for (wire, reason, class, mapped_reason, next) in cases {
            let err = WipeClientError::new_for_test(*wire, reason);
            let (c, r, n) = wipe_error_result(&err);
            assert_eq!((c, r, n), (*class, *mapped_reason, *next), "{reason}");
        }
    }

    #[test]
    fn delete_error_table_maps_every_stable_reason() {
        let cases: &[(i64, &str, &str)] = &[
            (
                3,
                domain::REASON_DELETE_UNAVAILABLE,
                "INSTALL_DELETE_SERVICE",
            ),
            (5, domain::REASON_DELETE_NO_BACKUP, "CREATE_BACKUP_FIRST"),
            (
                2,
                domain::REASON_DELETE_BACKUP_AMBIGUOUS,
                "NAME_BACKUP_EXPLICITLY",
            ),
            (
                7,
                domain::REASON_DELETE_RETENTION_TOO_YOUNG,
                "WAIT_FOR_RETENTION",
            ),
            (
                7,
                domain::REASON_DELETE_REFERENCED,
                "RESOLVE_BACKUP_REFERENCES",
            ),
            (
                7,
                domain::REASON_DELETE_DENIED_SIGNED,
                "RESOLVE_ADVISORY_DENIAL",
            ),
            (
                7,
                domain::REASON_DELETE_CEREMONY_REQUIRED,
                "COMPLETE_DELETE_CEREMONY",
            ),
            (
                7,
                domain::REASON_DELETE_AUTHORITY_DENIED,
                "COMPLETE_DELETE_CEREMONY",
            ),
        ];
        for (wire, reason, next) in cases {
            let err = DeleteClientError::new_for_test(*wire, reason);
            let (_, r, n) = delete_error_result(&err);
            assert_eq!((r, n), (*reason, *next), "{reason}");
        }
        let err = DeleteClientError::new_for_test(6, "UNEXPECTED");
        let (_, r, n) = delete_error_result(&err);
        assert_eq!((r, n), ("DELETE_FAILED", "INSPECT_DELETE_STATE"));
    }

    #[test]
    fn prune_error_table_maps_every_stable_reason() {
        let cases: &[(i64, &str, &str)] = &[
            (3, domain::REASON_PRUNE_UNAVAILABLE, "INSTALL_PRUNE_SERVICE"),
            (5, domain::REASON_PRUNE_PLAN_STALE, "REPLAN_PRUNE"),
            (
                7,
                domain::REASON_PRUNE_DENIED_SIGNED,
                "RESOLVE_ADVISORY_DENIAL",
            ),
            (
                7,
                domain::REASON_PRUNE_CEREMONY_REQUIRED,
                "COMPLETE_PRUNE_CEREMONY",
            ),
            (
                7,
                domain::REASON_PRUNE_AUTHORITY_DENIED,
                "COMPLETE_PRUNE_CEREMONY",
            ),
        ];
        for (wire, reason, next) in cases {
            let err = PruneClientError::new_for_test(*wire, reason);
            let (_, r, n) = prune_error_result(&err);
            assert_eq!((r, n), (*reason, *next), "{reason}");
        }
        let err = PruneClientError::new_for_test(6, "UNEXPECTED");
        let (_, r, n) = prune_error_result(&err);
        assert_eq!((r, n), ("PRUNE_FAILED", "INSPECT_PRUNE_STATE"));
    }

    // -- plan file ----------------------------------------------------------

    #[test]
    fn plan_file_round_trips_and_rejects_tampering() {
        let plan_id = Uuid::now_v7().to_string();
        let file = PrunePlanFile {
            plan_id: plan_id.clone(),
            retention_days: 30,
            bodies: vec![PruneBody {
                artifact_id: Uuid::now_v7().to_string(),
                workspace_id: Uuid::now_v7().to_string(),
                object_key: "k".to_owned(),
                staging_generation: "g".to_owned(),
                size: 4,
                retention_age_days: 40,
                reference_count: 0,
            }],
            created_at: "2026-10-23T00:00:00Z".to_owned(),
        };
        let dir = std::env::temp_dir().join(format!("central-prune-test-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let name = format!("{PRUNE_PLAN_FILE_PREFIX}{plan_id}.json");
        write_evidence(&name, &file).unwrap();
        let loaded = read_prune_plan_file(&plan_id).unwrap();
        assert_eq!(loaded.plan_id, plan_id);
        assert_eq!(loaded.bodies.len(), 1);
        // Unknown field rejection — a plan the CLI did not write.
        std::fs::write(
            &name,
            br#"{"plan_id":"x","retention_days":30,"bodies":[],"created_at":"t","extra":1}"#,
        )
        .unwrap();
        assert!(read_prune_plan_file(&plan_id).is_err());
        std::env::set_current_dir(cwd).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
