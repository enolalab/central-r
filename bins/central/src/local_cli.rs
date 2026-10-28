//! `central local *` — the R5 operator surface. Ports the upstream
//! `internal/command` handlers for the verbs registered this slice:
//! `doctor` (the host-prerequisite check runs for real — it owns no
//! backend), `init` (grammar only; the helper side is T6), `prepare`
//! (the real helper call runs — a helper-less host is upstream's
//! `helper: dial:` transport-failure branch), and the
//! `up`/`down`/`status` lifecycle trio — the real binary always
//! installs a lifecycle client, so a helper-less host is upstream's
//! `helper: dial:` failure branch.
//!
//! `local.wipe` is the D01 verb (destructive_cli), `local.security-*`
//! the D06 update/rescue pair and `local.audit` the D05 protected-state
//! audit (security_cli). `local.browser.open` is the B06 verb — the
//! real `helperB06Client` call runs, so a helper-less host is the
//! client's "helper unavailable" class on upstream's
//! `DEPENDENCY_UNAVAILABLE` envelope.
//!
//! Every other registered `local` id — `local.trust.install`,
//! `local.dependency-upgrade-plan` — stays deferred to its owning
//! slice through the exact `UNSUPPORTED_IN_THIS_SLICE` envelope.

use std::io::Write;
use std::time::Instant;

use central_foundation::failure::ExitClass;
use central_foundation::local_result::LocalResult;

use crate::modes;

/// Upstream `InitHintStartHelper` (internal/command/init.go).
const INIT_HINT_START_HELPER: &str = "central local init: the helper is not reachable; start it with: sudo systemctl start central-helper.socket";
/// Upstream `InitHintBrokenHost`.
const INIT_HINT_BROKEN_HOST: &str = "central local init: this host holds partial Central state under /var/lib/central-state/v1/instances or /var/lib/central-protected/v1/instances; journalctl -u central-helper names it";
/// Upstream `InitHintCapacity`.
const INIT_HINT_CAPACITY: &str = "central local init: the filesystem of /var/lib/central-state needs 40 GiB free; nothing was written";
/// Upstream `InitHintConsole`.
const INIT_HINT_CONSOLE: &str = "central local init: run it as the operator at this machine's physical console (a VT or serial console, not SSH) and answer the PAM and CONFIRM prompts there; on a host with no console, root can authorize one run over SSH first: sudo central grant issue --kind init --ttl 10m";
/// Upstream `InitHintConfirmationMismatch`.
const INIT_HINT_CONFIRMATION_MISMATCH: &str = "central local init: the typed phrase did not match the one shown, twice; nothing was created. At the physical console, turn off any input method (plain keyboard layout), run central local init again and type the phrase exactly as shown";
/// Upstream `InitHintInspect`.
const INIT_HINT_INSPECT: &str = "central local init: initialization failed; the console where you confirmed shows either the paths to remove as root or that nothing is to be removed (then run central local init again); if it showed neither, check ls /var/lib/central-state/v1/instances /var/lib/central-protected/v1/instances as root before retrying";
/// Upstream `InitHintNoAnswer`.
const INIT_HINT_NO_ANSWER: &str = "central local init: the helper closed the connection without answering; check journalctl -u central-helper, and start it with: sudo systemctl start central-helper.socket";
/// Upstream `InitHintUnconfirmed`.
const INIT_HINT_UNCONFIRMED: &str = "central local init: the instance may have been created but could not be confirmed; remove nothing, and run central local status or central local init again";
/// Upstream `InitHintUntrusted`.
const INIT_HINT_UNTRUSTED: &str = "central local init: the helper's answer could not be trusted; run central local init again to learn whether the instance exists, and check journalctl -u central-helper";

/// The null UUID upstream refuses for `--resume` (prepare.go).
const NULL_UUID: &str = "00000000-0000-0000-0000-000000000000";

/// Dispatches one resolved `local.*` command id. `tokens` are the
/// argv elements after the `<verb> <sub>` pair (upstream `args[3:]`).
pub(crate) fn local(
    command_id: &str,
    tokens: &[String],
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> u8 {
    match command_id {
        "local.doctor.prerequisites" => run_doctor(stdout, stderr),
        "local.init" => run_init(tokens, stdout, stderr),
        "local.up" | "local.down" | "local.status" => run_lifecycle(command_id, stdout, stderr),
        "local.prepare" => run_prepare(command_id, tokens, stdout, stderr),
        // `runBrowserOpen` — the B06 verb; upstream ignores its args.
        "local.browser.open" => run_browser_open(stdout, stderr),
        // `runLocalWipe` — the D01 verb: checkpoint, wipe, evidence.
        "local.wipe" => crate::destructive_cli::local_wipe(command_id, tokens, stdout, stderr),
        // `runLocalSecurity` — the shared `("local","security")` key
        // routes update/rescue on tokens[0]; `rescue cleanup` stays
        // deferred to Slice E inside the handler.
        "local.security-update" => {
            crate::security_cli::local_security(command_id, tokens, stdout, stderr)
        }
        // `runLocalAudit` — the D05 protected-state audit.
        "local.audit" => crate::security_cli::local_audit(command_id, tokens, stdout, stderr),
        _ => emit(
            command_id,
            stdout,
            stderr,
            ExitClass::Incompatible,
            Some("UNSUPPORTED_IN_THIS_SLICE"),
            None,
        ),
    }
}

/// Emits the single `central.local-result/v1` envelope; a write
/// failure collapses to exit `6` (upstream `cli.ResultExitCode`) —
/// the same shape `serve` and `run_cli` use.
fn emit(
    command_id: &str,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
    class: ExitClass,
    reason: Option<&str>,
    details: Option<serde_json::Value>,
) -> u8 {
    let result = LocalResult::now(command_id, class, reason.map(str::to_string), details);
    match result.write_json_line(stdout) {
        Ok(()) => result.exit_code,
        Err(_) => {
            let _ = writeln!(stderr, "central: could not write result envelope");
            ExitClass::Terminal.code()
        }
    }
}

/// Ports `cli.WriteError`: the envelope on stdout (no details) plus a
/// `REASON: message` line on stderr.
fn emit_error(
    command_id: &str,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
    class: ExitClass,
    reason: &str,
    message: &str,
) -> u8 {
    let code = emit(command_id, stdout, stderr, class, Some(reason), None);
    if code == class.code() {
        let _ = writeln!(stderr, "{reason}: {message}");
    }
    code
}

// -- `local doctor` -----------------------------------------------------

/// Ports `runDoctor` verbatim: OS and architecture checks against the
/// reference host, `/etc/os-release` carried through into the details,
/// `HOST_PREREQUISITE_MISMATCH` at exit 5 on failure. On linux/amd64
/// this is a real exit-0 check.
fn run_doctor(stdout: &mut impl Write, stderr: &mut impl Write) -> u8 {
    let mut failures: Vec<String> = Vec::new();
    if !cfg!(target_os = "linux") {
        failures.push(format!("unsupported OS: {}", host_goos()));
    }
    if modes::host_goarch() != "amd64" {
        failures.push(format!(
            "unsupported architecture: {}",
            modes::host_goarch()
        ));
    }
    let release = modes::os_release().unwrap_or_else(|| "unknown".to_string());
    if failures.is_empty() {
        emit(
            "local.doctor.prerequisites",
            stdout,
            stderr,
            ExitClass::Success,
            Some("ok"),
            Some(serde_json::json!({
                "os_release": release,
                "architecture": modes::host_goarch(),
            })),
        )
    } else {
        // Go `%v` of []string renders space-separated inside brackets.
        emit_error(
            "local.doctor.prerequisites",
            stdout,
            stderr,
            ExitClass::Incompatible,
            "HOST_PREREQUISITE_MISMATCH",
            &format!("[{}]", failures.join(" ")),
        )
    }
}

/// `runtime.GOOS` for the odd non-linux build (dead on the linux
/// reference host — the `cfg!` guard never reaches it there).
fn host_goos() -> &'static str {
    std::env::consts::OS
}

// -- `local init` -------------------------------------------------------

/// Ports `parseInitArgs` (`internal/command/init.go`): exactly four
/// grammar forms. `tokens` is `args[3:]` upstream — everything after
/// `local init`.
fn parse_init_args(tokens: &[String]) -> Result<&'static str, String> {
    if tokens.is_empty() {
        return Ok("local.init");
    }
    if tokens.len() > 1 {
        return Err("takes at most one of --status, --resume=<id>, --abandon=<id>".to_string());
    }
    let arg = tokens[0].as_str();
    match arg {
        "--status" => Ok("local.init.status"),
        _ if arg.starts_with("--resume=") && arg.len() > "--resume=".len() => {
            Ok("local.init.resume")
        }
        _ if arg.starts_with("--abandon=") && arg.len() > "--abandon=".len() => {
            Ok("local.init.abandon")
        }
        "--config" => Err("is configless and takes no --config".to_string()),
        _ if arg.starts_with("--config=") => Err("is configless and takes no --config".to_string()),
        _ => Err(format!("unknown argument {arg:?}")),
    }
}

/// `mapHelperInitError` — the helper's exit class and whitelisted
/// reason mapped to the contract's `(exit class, reason, hint)`
/// (§7.4). A broken host is `HELPER_UNAVAILABLE` exit 3, as an
/// unreachable helper is, with a hint that names the instance roots.
fn map_helper_init_error(
    err: &central_adapter_linux::helper::init::InitClientError,
) -> (ExitClass, &'static str, &'static str) {
    use central_adapter_linux::helper::init::*;
    if err.no_answer {
        return (
            ExitClass::Unavailable,
            "HELPER_UNAVAILABLE",
            INIT_HINT_NO_ANSWER,
        );
    }
    if err.untrusted {
        return (ExitClass::Terminal, "MUTATION_FAILED", INIT_HINT_UNTRUSTED);
    }
    match err.reason.as_str() {
        INIT_REASON_HELPER_UNAVAILABLE => (
            ExitClass::Unavailable,
            "HELPER_UNAVAILABLE",
            INIT_HINT_START_HELPER,
        ),
        INIT_REASON_INSTANCE_BROKEN => (
            ExitClass::Unavailable,
            "HELPER_UNAVAILABLE",
            INIT_HINT_BROKEN_HOST,
        ),
        INIT_REASON_CAPACITY => (
            ExitClass::Timeout,
            "CAPACITY_INSUFFICIENT",
            INIT_HINT_CAPACITY,
        ),
        INIT_REASON_LOCK_TIMEOUT => (ExitClass::Timeout, "LOCK_TIMEOUT", ""),
        INIT_REASON_AUTHORITY_DENIED => (ExitClass::Denied, "AUTHORITY_DENIED", INIT_HINT_CONSOLE),
        INIT_REASON_CONFIRMATION_MISMATCH => {
            // The contract's reason stays AUTHORITY_DENIED; the hint
            // differs, because the operator was at the console and
            // mistyped (install D1 decision 2).
            (
                ExitClass::Denied,
                "AUTHORITY_DENIED",
                INIT_HINT_CONFIRMATION_MISMATCH,
            )
        }
        INIT_REASON_MUTATION_FAILED => (ExitClass::Terminal, "MUTATION_FAILED", INIT_HINT_INSPECT),
        INIT_REASON_INVALID_REQUEST => (ExitClass::Usage, "INVALID_INVOCATION", ""),
        INIT_REASON_UNCONFIRMED => {
            // The contract's reason stays MUTATION_FAILED; the hint
            // differs, because there is nothing to remove.
            (
                ExitClass::Terminal,
                "MUTATION_FAILED",
                INIT_HINT_UNCONFIRMED,
            )
        }
        _ => match err.exit_code {
            // An unknown reason keeps its exit class.
            2 => (ExitClass::Usage, "INVALID_INVOCATION", ""),
            3 => (
                ExitClass::Unavailable,
                "HELPER_UNAVAILABLE",
                INIT_HINT_START_HELPER,
            ),
            4 => (ExitClass::Timeout, "LOCK_TIMEOUT", ""),
            5 => (ExitClass::Incompatible, "UNSUPPORTED_IN_THIS_SLICE", ""),
            7 => (ExitClass::Denied, "AUTHORITY_DENIED", INIT_HINT_CONSOLE),
            _ => (ExitClass::Terminal, "MUTATION_FAILED", INIT_HINT_INSPECT),
        },
    }
}

/// Ports `runInit` + `runBareInit`: grammar errors are
/// `INVALID_INVOCATION` at exit 2 under the `local.init` command id;
/// the flag forms keep their own ids in the deferred envelope; the
/// bare form dials the helper through the real [`InitClient`]
/// (`installInitClient`'s composition — `CENTRAL_HELPER_SOCKET` or
/// the production socket) and maps the answer through
/// [`map_helper_init_error`].
fn run_init(tokens: &[String], stdout: &mut impl Write, stderr: &mut impl Write) -> u8 {
    let form = match parse_init_args(tokens) {
        Ok(form) => form,
        Err(err) => {
            let code = emit(
                "local.init",
                stdout,
                stderr,
                ExitClass::Usage,
                Some("INVALID_INVOCATION"),
                None,
            );
            if code == ExitClass::Usage.code() {
                let _ = writeln!(stderr, "central local init: {err}");
            }
            return code;
        }
    };
    if form != "local.init" {
        return emit(
            form,
            stdout,
            stderr,
            ExitClass::Incompatible,
            Some("UNSUPPORTED_IN_THIS_SLICE"),
            None,
        );
    }
    // `helperSocketPath` — the override only counts when non-empty,
    // exactly like upstream's `os.Getenv` + `socket != ""` check.
    let socket_path = std::env::var("CENTRAL_HELPER_SOCKET")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| {
            central_adapter_linux::helper::client::PRODUCTION_SOCKET_PATH.to_owned()
        });
    let client = central_adapter_linux::helper::init::InitClient::new(socket_path);
    run_bare_init(&client, stdout, stderr)
}

/// `runBareInit` — one minted operation id, one `Init` call, then
/// either the three-ID success detail or the mapped failure.
fn run_bare_init(
    client: &central_adapter_linux::helper::init::InitClient,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> u8 {
    let operation_id = central_foundation::identity::OperationId::new().to_string();
    match client.init(&operation_id) {
        Ok(result) => {
            let reason = if result.already_initialized {
                "ALREADY_INITIALIZED"
            } else {
                "ok"
            };
            emit(
                "local.init",
                stdout,
                stderr,
                ExitClass::Success,
                Some(reason),
                Some(serde_json::json!({
                    "instance_id": result.instance_id,
                    "config_binding_id": result.config_binding_id,
                    "init_operation_id": result.init_operation_id,
                })),
            )
        }
        Err(err) => {
            let (class, reason, hint) = map_helper_init_error(&err);
            if !hint.is_empty() {
                let _ = writeln!(stderr, "{hint}");
            }
            emit("local.init", stdout, stderr, class, Some(reason), None)
        }
    }
}

// -- `local up|down|status` ----------------------------------------------

/// Ports `runLifecycle` (`internal/command/lifecycle.go`): the real
/// binary installs a lifecycle client unconditionally, so the
/// nil-client `LIFECYCLE_SERVICE_UNAVAILABLE` branch is unreachable —
/// the helper dial is always attempted first (`CENTRAL_HELPER_SOCKET`
/// override, then the production socket), and a helper-less host is
/// the `helper: dial: …` transport-failure branch
/// `lifecycleSafeNextAction` maps to `START_CENTRAL_HELPER` under
/// `LIFECYCLE_EXECUTION_FAILED` at exit 5.
fn run_lifecycle(command_id: &str, stdout: &mut impl Write, stderr: &mut impl Write) -> u8 {
    use central_adapter_linux::helper::client::{
        LifecycleClient, LifecycleResult, PRODUCTION_SOCKET_PATH,
    };
    use central_adapter_linux::helper::protocol::LifecycleRequest;

    let socket_path = std::env::var("CENTRAL_HELPER_SOCKET")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| PRODUCTION_SOCKET_PATH.to_owned());
    let client = LifecycleClient::new(socket_path);
    let req = LifecycleRequest::default();
    let (result, err): (LifecycleResult, Option<String>) = match command_id {
        "local.up" => client.up(&req),
        "local.down" => client.down(&req),
        _ => client.status(&req),
    };
    match err {
        None => emit(
            command_id,
            stdout,
            stderr,
            ExitClass::Success,
            Some(&result.state),
            Some(lifecycle_details(&result, "", "")),
        ),
        Some(err) => emit(
            command_id,
            stdout,
            stderr,
            ExitClass::Incompatible,
            Some("LIFECYCLE_EXECUTION_FAILED"),
            Some(lifecycle_details(
                &result,
                &lifecycle_failure_code(&result.reason_code),
                &lifecycle_safe_next_action(&result, &err),
            )),
        ),
    }
}

/// `lifecycleFailureCode` — reduces a lifecycle failure's reason to
/// the closed-vocabulary code it starts with; a reason that is not a
/// code names no code.
fn lifecycle_failure_code(reason: &str) -> String {
    let code = reason.split(':').next().unwrap_or_default().trim();
    if code
        .chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    {
        code.to_owned()
    } else {
        String::new()
    }
}

/// `lifecycleSafeNextAction` — the codes with a known remedy map to
/// the one safe thing an operator can do next; everything else keeps
/// the status check.
fn lifecycle_safe_next_action(
    result: &central_adapter_linux::helper::client::LifecycleResult,
    err: &str,
) -> String {
    match lifecycle_failure_code(&result.reason_code).as_str() {
        "AUTHORITY_DENIED"
        | "LIFECYCLE_AUTHORIZATION_REQUIRED"
        | "LIFECYCLE_AUTHORIZATION_DENIED"
        | "LIFECYCLE_AUTHORIZATION_REJECTED" => "RUN_CENTRAL_GRANT_ISSUE".to_owned(),
        "ADMISSION_FAILED" | "ADMISSION_REINSPECTION_FAILED" => {
            "RUN_CENTRAL_LOCAL_PREPARE".to_owned()
        }
        _ => {
            if err.starts_with("helper: dial:") {
                "START_CENTRAL_HELPER".to_owned()
            } else {
                "CHECK_LIFECYCLE_STATUS".to_owned()
            }
        }
    }
}

/// `cli.LifecycleDetails`'s `omitempty` set for the lifecycle verbs —
/// the zero-valued fields upstream's failed call leaves out.
fn lifecycle_details(
    result: &central_adapter_linux::helper::client::LifecycleResult,
    reason_code: &str,
    safe_next_action: &str,
) -> serde_json::Value {
    let mut details = serde_json::json!({});
    if !result.operation_id.is_empty() {
        details["operation_id"] = serde_json::json!(result.operation_id);
    }
    if !result.receipt_id.is_empty() {
        details["receipt_id"] = serde_json::json!(result.receipt_id);
    }
    if !result.phase.is_empty() {
        details["phase"] = serde_json::json!(result.phase);
    }
    if !result.state.is_empty() {
        details["state"] = serde_json::json!(result.state);
    }
    if !reason_code.is_empty() {
        details["reason_code"] = serde_json::json!(reason_code);
    }
    if !safe_next_action.is_empty() {
        details["safe_next_action"] = serde_json::json!(safe_next_action);
    }
    details
}

// -- B06: `local browser open` ---------------------------------------------

/// `pendingB06Details` — the one detail shape the B06 verbs ever
/// write: a safe next action and nothing else.
fn b06_details(safe_next_action: &str) -> serde_json::Value {
    serde_json::json!({ "safe_next_action": safe_next_action })
}

/// The shared B06 outcome table — upstream's `runBrowserOpen` /
/// `runBootstrapShow` keep the same three envelopes. The client's
/// "helper unavailable" class takes the `DEPENDENCY_UNAVAILABLE` exit
/// 3 envelope upstream's nil-client branch writes (the real binary
/// always installs the client, so the client's own unavailable class
/// is that envelope's reachable cause); the "authority denied" class
/// and success map verbatim.
fn run_b06(
    outcome: Result<(), central_adapter_linux::helper::client::B06Error>,
    command_id: &str,
    success_reason: &str,
    success_action: &str,
    denied_action: &str,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> u8 {
    use central_adapter_linux::helper::client::B06Error;
    match outcome {
        Ok(()) => emit(
            command_id,
            stdout,
            stderr,
            ExitClass::Success,
            Some(success_reason),
            Some(b06_details(success_action)),
        ),
        Err(B06Error::Unavailable) => emit(
            command_id,
            stdout,
            stderr,
            ExitClass::Unavailable,
            Some("DEPENDENCY_UNAVAILABLE"),
            Some(b06_details("START_CENTRAL_HELPER")),
        ),
        Err(B06Error::Denied) => emit(
            command_id,
            stdout,
            stderr,
            ExitClass::Denied,
            Some("AUTHORITY_DENIED"),
            Some(b06_details(denied_action)),
        ),
    }
}

/// Ports `runBrowserOpen` (`internal/command/b06_serve.go`) on the
/// real `helperB06Client` composition — `newHelperB06Client` resolves
/// `CENTRAL_HELPER_SOCKET`/`CENTRAL_OPERATOR_GID` inside the client.
/// Upstream takes args and ignores them.
fn run_browser_open(stdout: &mut impl Write, stderr: &mut impl Write) -> u8 {
    let client =
        central_adapter_linux::helper::client::B06Client::from_env(&|key| std::env::var(key).ok());
    run_browser_open_with(&client, stdout, stderr)
}

/// The `runBrowserOpen` mapping over an injected client — the same
/// seam upstream's `browserOpenClient` package var provides.
fn run_browser_open_with(
    client: &central_adapter_linux::helper::client::B06Client,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> u8 {
    run_b06(
        client.open(),
        "local.browser.open",
        "BROWSER_OPENED",
        "CENTRAL_BOOTSTRAP_SHOW",
        "CHECK_READY_PROOF",
        stdout,
        stderr,
    )
}

// -- `local prepare` ------------------------------------------------------

/// Ports `parseResumeFlag`: scans for `--resume=` prefixed tokens;
/// the space-separated form is not a flag upstream and falls through.
fn parse_resume_flag(tokens: &[String]) -> Result<String, String> {
    let mut resume = String::new();
    for arg in tokens {
        if let Some(value) = arg.strip_prefix("--resume=") {
            if !resume.is_empty() {
                return Err("multiple --resume flags are not allowed".to_string());
            }
            if value.is_empty() {
                return Err("--resume flag requires a UUIDv7 value".to_string());
            }
            resume = value.to_string();
        }
    }
    Ok(resume)
}

/// Ports `parseReleaseFlags`: `--from-release=`/`--export-release=`
/// prefixed tokens only.
fn parse_release_flags(tokens: &[String]) -> Result<(String, String), String> {
    let mut from = String::new();
    let mut export = String::new();
    for arg in tokens {
        if let Some(value) = arg.strip_prefix("--from-release=") {
            if !from.is_empty() {
                return Err("multiple --from-release flags are not allowed".to_string());
            }
            if value.is_empty() {
                return Err("--from-release flag requires a directory value".to_string());
            }
            from = value.to_string();
        } else if let Some(value) = arg.strip_prefix("--export-release=") {
            if !export.is_empty() {
                return Err("multiple --export-release flags are not allowed".to_string());
            }
            if value.is_empty() {
                return Err("--export-release flag requires a directory value".to_string());
            }
            export = value.to_string();
        }
    }
    Ok((from, export))
}

/// The `cli.PrepareDetails` failure shape upstream writes for the
/// flag-grammar refusals and the transport failure: the always-present
/// fields plus `remediation`/`safe_next_action` when set.
fn prepare_details(
    reason_code: &str,
    remediation: Option<&str>,
    safe_next_action: Option<&str>,
    elapsed_ms: i64,
) -> serde_json::Value {
    let mut details = serde_json::json!({
        "authority_state": "error",
        "reason_code": reason_code,
        "phase": "",
        "resume_required": false,
        "reused": 0,
        "acquired": 0,
        "elapsed_ms": elapsed_ms,
    });
    if let Some(text) = remediation {
        details["remediation"] = serde_json::json!(text);
    }
    if let Some(action) = safe_next_action {
        details["safe_next_action"] = serde_json::json!(action);
    }
    details
}

/// `prepareSummary` — carries the helper's measurements onto the CLI
/// result. The timings and counters are the helper's, not re-derived
/// here: the CLI never saw the phases and cannot honestly time them.
/// Field presence matches `cli.PrepareDetails`'s `omitempty` set.
fn prepare_summary(
    result: &central_adapter_linux::helper::client::PrepareResult,
    elapsed_ms: i64,
) -> serde_json::Value {
    let mut details = serde_json::json!({
        "phase": result.phase,
        "resume_required": result.resume_required,
        "reused": result.reused,
        "acquired": result.acquired,
        "elapsed_ms": elapsed_ms,
    });
    if !result.operation_id.is_empty() {
        details["operation_id"] = serde_json::json!(result.operation_id);
    }
    if !result.advisory_id.is_empty() {
        details["advisory_id"] = serde_json::json!(result.advisory_id);
    }
    if !result.safe_next_action.is_empty() {
        details["safe_next_action"] = serde_json::json!(result.safe_next_action);
    }
    if result.operation_elapsed_ms != 0 {
        details["operation_elapsed_ms"] = serde_json::json!(result.operation_elapsed_ms);
    }
    if !result.stage_timings.is_empty() {
        details["stage_timings"] =
            serde_json::to_value(&result.stage_timings).unwrap_or(serde_json::Value::Null);
    }
    if let Some(counters) = &result.resource_counters {
        details["resource_counters"] =
            serde_json::to_value(counters).unwrap_or(serde_json::Value::Null);
    }
    details
}

/// The closed `SafeNextAction` wire set: a value outside it is
/// unspellable and reads as no action at all, which `runPrepare`
/// upgrades to `TERMINAL_FAILURE` on the error path.
fn valid_safe_next_action(value: &str) -> bool {
    matches!(
        value,
        "" | "RESUME_REQUIRED" | "PREPARATION_REQUIRED" | "TERMINAL_FAILURE"
    )
}

/// Ports `runPrepare` (`internal/command/prepare.go`): the flag
/// grammar runs verbatim, then the real helper prepare call —
/// `CENTRAL_HELPER_SOCKET` or the production socket, the helper's own
/// transport budget inside the client — and the four upstream outcome
/// branches: transport/denial `PREPARE_FAILED` exit 7 (or
/// `RESUME_REQUIRED` exit 6 when the denial still names an unsettled
/// operation), `RESUME_REQUIRED` exit 6, `PREPARATION_REQUIRED`
/// exit 6, and the `ok` exit 0 completion.
fn run_prepare(
    command_id: &str,
    tokens: &[String],
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> u8 {
    use central_adapter_linux::helper::client::{
        PRODUCTION_SOCKET_PATH, PrepareClient, PrepareResult,
    };
    use central_adapter_linux::helper::protocol::PrepareRequest;

    let start = Instant::now();
    let elapsed_ms = || i64::try_from(start.elapsed().as_millis()).unwrap_or(i64::MAX);

    let resume = match parse_resume_flag(tokens) {
        Ok(resume) => resume,
        Err(err) => {
            return emit(
                command_id,
                stdout,
                stderr,
                ExitClass::Incompatible,
                Some("INVALID_RESUME_FLAG"),
                Some(prepare_details(
                    "INVALID_RESUME_FLAG",
                    Some(&err),
                    Some("TERMINAL_FAILURE"),
                    elapsed_ms(),
                )),
            );
        }
    };
    if resume == NULL_UUID {
        return emit(
            command_id,
            stdout,
            stderr,
            ExitClass::Incompatible,
            Some("INVALID_RESUME_FLAG"),
            Some(prepare_details(
                "INVALID_RESUME_FLAG",
                Some("resume operation ID must not be the null UUID"),
                Some("TERMINAL_FAILURE"),
                elapsed_ms(),
            )),
        );
    }
    let (from, export) = match parse_release_flags(tokens) {
        Ok(pair) => pair,
        Err(err) => {
            return emit(
                command_id,
                stdout,
                stderr,
                ExitClass::Incompatible,
                Some("INVALID_RELEASE_FLAGS"),
                Some(prepare_details(
                    "INVALID_RELEASE_FLAGS",
                    Some(&err),
                    Some("TERMINAL_FAILURE"),
                    elapsed_ms(),
                )),
            );
        }
    };
    if !from.is_empty() && !export.is_empty() {
        return emit(
            command_id,
            stdout,
            stderr,
            ExitClass::Incompatible,
            Some("INVALID_RELEASE_FLAGS"),
            Some(prepare_details(
                "INVALID_RELEASE_FLAGS",
                Some("--from-release and --export-release are mutually exclusive"),
                Some("TERMINAL_FAILURE"),
                elapsed_ms(),
            )),
        );
    }
    if !resume.is_empty() && (!from.is_empty() || !export.is_empty()) {
        return emit(
            command_id,
            stdout,
            stderr,
            ExitClass::Incompatible,
            Some("INVALID_RELEASE_FLAGS"),
            Some(prepare_details(
                "INVALID_RELEASE_FLAGS",
                Some("--resume cannot be combined with --from-release or --export-release"),
                Some("TERMINAL_FAILURE"),
                elapsed_ms(),
            )),
        );
    }
    // `defaultPrepareSocket` — the operator-overridable socket, then
    // the production helper socket; an empty override is no override.
    let socket_path = std::env::var("CENTRAL_HELPER_SOCKET")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| PRODUCTION_SOCKET_PATH.to_owned());
    let client = PrepareClient::new(socket_path);
    let request = PrepareRequest {
        resume_operation_id: resume,
        from_release_dir: from,
        export_release_dir: export,
        confirmation_claim: None,
    };
    let (result, err): (PrepareResult, Option<String>) = client.prepare(&request);

    if let Some(err) = err {
        let mut details = prepare_summary(&result, elapsed_ms());
        details["authority_state"] = serde_json::json!("error");
        details["reason_code"] = serde_json::json!(if result.code.is_empty() {
            // The helper's reason code is the verdict; PREPARE_FAILED
            // is the fallback for a denial that carried none.
            "PREPARE_FAILED".to_owned()
        } else {
            result.code.clone()
        });
        // A remedy the helper sent says what to do next; the
        // transport's "denied (reason: X)" line is the fallback, not
        // the message.
        details["remediation"] = serde_json::json!(if result.remediation.is_empty() {
            err
        } else {
            result.remediation.clone()
        });
        if result.resume_required {
            details["receipt_id"] = serde_json::json!(result.receipt_id);
            details["resume_required"] = serde_json::json!(true);
            details["safe_next_action"] = serde_json::json!("RESUME_REQUIRED");
            return emit(
                command_id,
                stdout,
                stderr,
                ExitClass::Terminal,
                Some("RESUME_REQUIRED"),
                Some(details),
            );
        }
        // A transport failure is not a verdict on the operation, so
        // the helper's own safe next action is preferred when it sent
        // one; only a request that never produced a result is
        // terminal by default.
        if !valid_safe_next_action(&result.safe_next_action) || result.safe_next_action.is_empty() {
            details["safe_next_action"] = serde_json::json!("TERMINAL_FAILURE");
        }
        return emit(
            command_id,
            stdout,
            stderr,
            ExitClass::Denied,
            Some("PREPARE_FAILED"),
            Some(details),
        );
    }

    if result.resume_required {
        let mut details = prepare_summary(&result, elapsed_ms());
        details["authority_state"] = serde_json::json!("unsettled");
        details["reason_code"] = serde_json::json!("RESUME_REQUIRED");
        details["receipt_id"] = serde_json::json!(result.receipt_id);
        details["remediation"] = serde_json::json!(
            "An unsettled prepare operation exists. Run `central prepare --resume` to continue."
        );
        details["resume_required"] = serde_json::json!(true);
        details["safe_next_action"] = serde_json::json!("RESUME_REQUIRED");
        return emit(
            command_id,
            stdout,
            stderr,
            ExitClass::Terminal,
            Some("RESUME_REQUIRED"),
            Some(details),
        );
    }

    // A prepare that reports anything other than a prepared
    // dependency set has not prepared one, whatever the transport
    // said. The helper names the next action; the CLI does not
    // second-guess it, and it does not invent one.
    if result.safe_next_action == "PREPARATION_REQUIRED" {
        let mut details = prepare_summary(&result, elapsed_ms());
        details["authority_state"] = serde_json::json!("unprepared");
        details["reason_code"] = serde_json::json!("PREPARATION_REQUIRED");
        details["receipt_id"] = serde_json::json!(result.receipt_id);
        details["remediation"] = serde_json::json!(
            "Dependencies are not prepared. Run `central local prepare` once the reported condition is resolved."
        );
        return emit(
            command_id,
            stdout,
            stderr,
            ExitClass::Terminal,
            Some("PREPARATION_REQUIRED"),
            Some(details),
        );
    }

    let mut details = prepare_summary(&result, elapsed_ms());
    details["authority_state"] = serde_json::json!("current");
    details["reason_code"] = serde_json::json!("OK");
    details["evidence_id"] = serde_json::json!(result.receipt_id);
    details["receipt_id"] = serde_json::json!(result.receipt_id);
    // A completed preparation names no next action — upstream
    // assigns `SafeNextNone`, which `omitempty` drops from the
    // envelope entirely.
    if let Some(map) = details.as_object_mut() {
        map.remove("safe_next_action");
    }
    emit(
        command_id,
        stdout,
        stderr,
        ExitClass::Success,
        Some("ok"),
        Some(details),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    fn invoke(id: &str, tokens: &[&str]) -> (u8, String, String) {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = local(id, &argv(tokens), &mut out, &mut err);
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    // -- init grammar (upstream parseInitArgs table) --------------------

    #[test]
    fn init_grammar_forms() {
        for (tokens, want) in [
            (vec![], Ok("local.init")),
            (vec!["--status"], Ok("local.init.status")),
            (vec!["--resume=abc"], Ok("local.init.resume")),
            (vec!["--abandon=abc"], Ok("local.init.abandon")),
            (
                vec!["--abandon", "abc"],
                Err("takes at most one of --status, --resume=<id>, --abandon=<id>".to_string()),
            ),
            (
                vec!["--resume"],
                Err("unknown argument \"--resume\"".to_string()),
            ),
            (
                vec!["--resume="],
                Err("unknown argument \"--resume=\"".to_string()),
            ),
            (
                vec!["--config"],
                Err("is configless and takes no --config".to_string()),
            ),
            (
                vec!["--config=/x"],
                Err("is configless and takes no --config".to_string()),
            ),
            (vec!["foo"], Err("unknown argument \"foo\"".to_string())),
        ] {
            assert_eq!(parse_init_args(&argv(&tokens)), want, "tokens {tokens:?}");
        }
    }

    #[test]
    fn init_bare_is_helper_unavailable_exit_3() {
        // A socket nothing listens on — the production shape an
        // absent host takes without systemd, deterministic on any
        // machine.
        let client =
            central_adapter_linux::helper::init::InitClient::new("/nonexistent-central-init.sock");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_bare_init(&client, &mut out, &mut err);
        let (stdout, stderr) = (
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        );
        assert_eq!(code, 3);
        assert_eq!(stderr, format!("{INIT_HINT_START_HELPER}\n"));
        let parsed: serde_json::Value = serde_json::from_str(stdout.trim_end()).unwrap();
        assert_eq!(parsed["schema_version"], "central.local-result/v1");
        assert_eq!(parsed["command_id"], "local.init");
        assert_eq!(parsed["exit_code"], 3);
        assert_eq!(parsed["reason"], "HELPER_UNAVAILABLE");
        assert!(parsed.get("details").is_none());
    }

    /// `mapHelperInitError` — the whole upstream reason→contract
    /// table: helper-class reasons keep their exit class, the two
    /// re-reasoned cases (`CONFIRMATION_MISMATCH`,
    /// `INIT_UNCONFIRMED`) carry their distinct hints, and the
    /// unknown-reason fallback keeps the exit class.
    #[test]
    fn map_helper_init_error_table() {
        use central_adapter_linux::helper::init::*;
        let err = |exit_code: i64, reason: &str| InitClientError {
            exit_code,
            reason: reason.to_owned(),
            no_answer: false,
            untrusted: false,
        };
        for (given, want) in [
            (
                err(3, INIT_REASON_HELPER_UNAVAILABLE),
                (
                    ExitClass::Unavailable,
                    "HELPER_UNAVAILABLE",
                    INIT_HINT_START_HELPER,
                ),
            ),
            (
                err(3, INIT_REASON_INSTANCE_BROKEN),
                (
                    ExitClass::Unavailable,
                    "HELPER_UNAVAILABLE",
                    INIT_HINT_BROKEN_HOST,
                ),
            ),
            (
                err(4, INIT_REASON_CAPACITY),
                (
                    ExitClass::Timeout,
                    "CAPACITY_INSUFFICIENT",
                    INIT_HINT_CAPACITY,
                ),
            ),
            (
                err(4, INIT_REASON_LOCK_TIMEOUT),
                (ExitClass::Timeout, "LOCK_TIMEOUT", ""),
            ),
            (
                err(7, INIT_REASON_AUTHORITY_DENIED),
                (ExitClass::Denied, "AUTHORITY_DENIED", INIT_HINT_CONSOLE),
            ),
            (
                err(7, INIT_REASON_CONFIRMATION_MISMATCH),
                (
                    ExitClass::Denied,
                    "AUTHORITY_DENIED",
                    INIT_HINT_CONFIRMATION_MISMATCH,
                ),
            ),
            (
                err(6, INIT_REASON_MUTATION_FAILED),
                (ExitClass::Terminal, "MUTATION_FAILED", INIT_HINT_INSPECT),
            ),
            (
                err(2, INIT_REASON_INVALID_REQUEST),
                (ExitClass::Usage, "INVALID_INVOCATION", ""),
            ),
            (
                err(6, INIT_REASON_UNCONFIRMED),
                (
                    ExitClass::Terminal,
                    "MUTATION_FAILED",
                    INIT_HINT_UNCONFIRMED,
                ),
            ),
            // Unknown reason → the exit class fallback table.
            (
                err(2, "BOGUS"),
                (ExitClass::Usage, "INVALID_INVOCATION", ""),
            ),
            (
                err(3, "BOGUS"),
                (
                    ExitClass::Unavailable,
                    "HELPER_UNAVAILABLE",
                    INIT_HINT_START_HELPER,
                ),
            ),
            (err(4, "BOGUS"), (ExitClass::Timeout, "LOCK_TIMEOUT", "")),
            (
                err(5, "BOGUS"),
                (ExitClass::Incompatible, "UNSUPPORTED_IN_THIS_SLICE", ""),
            ),
            (
                err(7, "BOGUS"),
                (ExitClass::Denied, "AUTHORITY_DENIED", INIT_HINT_CONSOLE),
            ),
            (
                err(9, "BOGUS"),
                (ExitClass::Terminal, "MUTATION_FAILED", INIT_HINT_INSPECT),
            ),
        ] {
            assert_eq!(map_helper_init_error(&given), want, "{:?}", given.reason);
        }
        let mut no_answer = err(6, "");
        no_answer.no_answer = true;
        assert_eq!(
            map_helper_init_error(&no_answer),
            (
                ExitClass::Unavailable,
                "HELPER_UNAVAILABLE",
                INIT_HINT_NO_ANSWER
            )
        );
        let mut untrusted = err(0, "");
        untrusted.untrusted = true;
        assert_eq!(
            map_helper_init_error(&untrusted),
            (ExitClass::Terminal, "MUTATION_FAILED", INIT_HINT_UNTRUSTED)
        );
    }

    #[test]
    fn init_flag_forms_keep_their_own_ids_unsupported() {
        for (tokens, want_id) in [
            (vec!["--status"], "local.init.status"),
            (vec!["--resume=abc"], "local.init.resume"),
            (vec!["--abandon=abc"], "local.init.abandon"),
        ] {
            let (code, stdout, _) = invoke("local.init", &tokens);
            assert_eq!(code, 5, "tokens {tokens:?}");
            let parsed: serde_json::Value = serde_json::from_str(stdout.trim_end()).unwrap();
            assert_eq!(parsed["command_id"], want_id, "tokens {tokens:?}");
            assert_eq!(parsed["reason"], "UNSUPPORTED_IN_THIS_SLICE");
        }
    }

    #[test]
    fn init_grammar_errors_are_invalid_invocation_exit_2() {
        let (code, stdout, stderr) = invoke("local.init", &["--abandon", "abc"]);
        assert_eq!(code, 2);
        let parsed: serde_json::Value = serde_json::from_str(stdout.trim_end()).unwrap();
        assert_eq!(parsed["command_id"], "local.init");
        assert_eq!(parsed["exit_code"], 2);
        assert_eq!(parsed["reason"], "INVALID_INVOCATION");
        assert_eq!(
            stderr,
            "central local init: takes at most one of --status, --resume=<id>, --abandon=<id>\n"
        );
    }

    // -- lifecycle --------------------------------------------------------

    #[test]
    fn lifecycle_verbs_report_the_helper_dial_failure_exit_5() {
        // The pair the real binary emits on a helper-less host:
        // LIFECYCLE_EXECUTION_FAILED + START_CENTRAL_HELPER (upstream
        // cli_exit_status_test.go, "local status without a helper").
        for id in ["local.up", "local.down", "local.status"] {
            let (code, stdout, _) = invoke(id, &[]);
            assert_eq!(code, 5, "id {id}");
            let parsed: serde_json::Value = serde_json::from_str(stdout.trim_end()).unwrap();
            assert_eq!(parsed["command_id"], id);
            assert_eq!(parsed["reason"], "LIFECYCLE_EXECUTION_FAILED");
            assert_eq!(
                parsed["details"]["safe_next_action"],
                "START_CENTRAL_HELPER"
            );
            // Zero-valued result fields stay omitted (upstream's
            // LifecycleDetails are all omitempty).
            for field in [
                "operation_id",
                "receipt_id",
                "phase",
                "state",
                "reason_code",
            ] {
                assert!(
                    parsed["details"].get(field).is_none(),
                    "id {id} leaks {field}"
                );
            }
        }
    }

    /// `lifecycleFailureCode` reduces a reason to its leading
    /// closed-vocabulary code; prose names no code.
    #[test]
    fn lifecycle_failure_code_extracts_leading_code() {
        for (reason, code) in [
            (
                "ADMISSION_FAILED: receipt binding mismatch",
                "ADMISSION_FAILED",
            ),
            ("AUTHORITY_DENIED", "AUTHORITY_DENIED"),
            ("DOWN_SETTLE_FAILED: journal write", "DOWN_SETTLE_FAILED"),
            ("not a code", ""),
            ("", ""),
        ] {
            assert_eq!(lifecycle_failure_code(reason), code, "reason {reason:?}");
        }
    }

    /// `lifecycleSafeNextAction` — the closed remedy mapping: denied
    /// authority → grant-issue, admission → local prepare, a dial
    /// transport failure → start the helper, everything else → status.
    #[test]
    fn lifecycle_safe_next_action_closed_mapping() {
        use central_adapter_linux::helper::client::LifecycleResult;
        let result_with = |code: &str| LifecycleResult {
            reason_code: code.to_owned(),
            ..LifecycleResult::default()
        };
        for code in [
            "AUTHORITY_DENIED",
            "LIFECYCLE_AUTHORIZATION_REQUIRED",
            "LIFECYCLE_AUTHORIZATION_DENIED",
            "LIFECYCLE_AUTHORIZATION_REJECTED",
        ] {
            assert_eq!(
                lifecycle_safe_next_action(&result_with(code), "helper: some err"),
                "RUN_CENTRAL_GRANT_ISSUE",
                "code {code}"
            );
        }
        for code in ["ADMISSION_FAILED", "ADMISSION_REINSPECTION_FAILED"] {
            assert_eq!(
                lifecycle_safe_next_action(&result_with(code), "helper: some err"),
                "RUN_CENTRAL_LOCAL_PREPARE",
                "code {code}"
            );
        }
        // A dial failure wins over an empty reason code.
        assert_eq!(
            lifecycle_safe_next_action(&result_with(""), "helper: dial: refused"),
            "START_CENTRAL_HELPER"
        );
        // Any other helper-side failure keeps the status check.
        assert_eq!(
            lifecycle_safe_next_action(
                &result_with("DOWN_SETTLE_FAILED"),
                "helper: lifecycle down denied: denied"
            ),
            "CHECK_LIFECYCLE_STATUS"
        );
    }

    // -- prepare -----------------------------------------------------------

    #[test]
    fn prepare_flag_grammar_refusals() {
        // Bad --resume family → INVALID_RESUME_FLAG exit 5.
        for tokens in [vec!["--resume=a", "--resume=b"], vec!["--resume="]] {
            let (code, stdout, _) = invoke("local.prepare", &tokens);
            assert_eq!(code, 5, "tokens {tokens:?}");
            let parsed: serde_json::Value = serde_json::from_str(stdout.trim_end()).unwrap();
            assert_eq!(parsed["reason"], "INVALID_RESUME_FLAG", "tokens {tokens:?}");
            assert_eq!(parsed["details"]["authority_state"], "error");
            assert_eq!(parsed["details"]["safe_next_action"], "TERMINAL_FAILURE");
        }
        let (code, stdout, _) = invoke(
            "local.prepare",
            &["--resume=00000000-0000-0000-0000-000000000000"],
        );
        assert_eq!(code, 5);
        let parsed: serde_json::Value = serde_json::from_str(stdout.trim_end()).unwrap();
        assert_eq!(parsed["reason"], "INVALID_RESUME_FLAG");
        assert_eq!(
            parsed["details"]["remediation"],
            "resume operation ID must not be the null UUID"
        );

        // Release-flag family → INVALID_RELEASE_FLAGS exit 5.
        for tokens in [
            vec!["--from-release="],
            vec!["--from-release=/a", "--export-release=/b"],
            vec!["--resume=a", "--from-release=/a"],
        ] {
            let (code, stdout, _) = invoke("local.prepare", &tokens);
            assert_eq!(code, 5, "tokens {tokens:?}");
            let parsed: serde_json::Value = serde_json::from_str(stdout.trim_end()).unwrap();
            assert_eq!(
                parsed["reason"], "INVALID_RELEASE_FLAGS",
                "tokens {tokens:?}"
            );
        }
    }

    #[test]
    fn prepare_without_helper_is_prepare_failed_exit_7() {
        // A helper-less host is upstream's transport failure: the dial
        // error is the remediation, no helper verdict arrived, and the
        // unspellable/absent next action upgrades to TERMINAL_FAILURE.
        let (code, stdout, _) = invoke("local.prepare", &[]);
        assert_eq!(code, 7);
        let parsed: serde_json::Value = serde_json::from_str(stdout.trim_end()).unwrap();
        assert_eq!(parsed["command_id"], "local.prepare");
        assert_eq!(parsed["exit_code"], 7);
        assert_eq!(parsed["reason"], "PREPARE_FAILED");
        let details = &parsed["details"];
        assert_eq!(details["authority_state"], "error");
        assert_eq!(details["reason_code"], "PREPARE_FAILED");
        assert!(
            details["remediation"]
                .as_str()
                .unwrap()
                .starts_with("helper: dial:"),
            "remediation carries the dial error: {}",
            details["remediation"]
        );
        assert_eq!(details["phase"], "");
        assert_eq!(details["resume_required"], false);
        assert_eq!(details["reused"], 0);
        assert_eq!(details["acquired"], 0);
        assert_eq!(details["safe_next_action"], "TERMINAL_FAILURE");
        assert!(details["elapsed_ms"].is_number());
    }

    #[test]
    fn prepare_resume_flag_is_prefix_only() {
        // The space-separated `--resume <id>` form is ignored upstream
        // (parseResumeFlag matches the `--resume=` prefix only) — it
        // falls through to the transport failure, not a usage error.
        let (code, _, _) = invoke("local.prepare", &["--resume", "x"]);
        assert_eq!(code, 7);
    }

    // -- `local browser open` (B06) -----------------------------------------

    /// A helper-less host is `helperB06Client.call`'s "helper
    /// unavailable" class — `DEPENDENCY_UNAVAILABLE` exit 3 with
    /// `START_CENTRAL_HELPER`. The injected client is upstream's
    /// `browserOpenClient` package-var seam; a socket path nothing
    /// answers fails `SocketPolicy::validate` before any dial.
    #[test]
    fn browser_open_without_helper_is_dependency_unavailable_exit_3() {
        let client = central_adapter_linux::helper::client::B06Client::new(
            format!("/nonexistent-central-b06-{}.sock", std::process::id()),
            1000,
        );
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_browser_open_with(&client, &mut out, &mut err);
        assert_eq!(code, 3);
        let parsed: serde_json::Value =
            serde_json::from_str(String::from_utf8(out).unwrap().trim_end()).unwrap();
        assert_eq!(parsed["command_id"], "local.browser.open");
        assert_eq!(parsed["exit_code"], 3);
        assert_eq!(parsed["reason"], "DEPENDENCY_UNAVAILABLE");
        assert_eq!(
            parsed["details"]["safe_next_action"],
            "START_CENTRAL_HELPER"
        );
    }

    /// The env-composed path lands on the same envelope — this test
    /// makes the same no-live-helper assumption the lifecycle
    /// helper-less test does.
    #[test]
    fn browser_open_composed_client_is_unavailable_without_a_socket() {
        let (code, stdout, _) = invoke("local.browser.open", &["open"]);
        assert_eq!(code, 3);
        let parsed: serde_json::Value = serde_json::from_str(stdout.trim_end()).unwrap();
        assert_eq!(parsed["command_id"], "local.browser.open");
        assert_eq!(parsed["reason"], "DEPENDENCY_UNAVAILABLE");
        assert_eq!(
            parsed["details"]["safe_next_action"],
            "START_CENTRAL_HELPER"
        );
    }

    /// The other two arms of the shared `run_b06` table: the denied
    /// class is `AUTHORITY_DENIED` exit 7 with `CHECK_READY_PROOF`;
    /// success is `BROWSER_OPENED` exit 0 with `CENTRAL_BOOTSTRAP_SHOW`.
    #[test]
    fn browser_open_outcome_table_denied_and_success() {
        use central_adapter_linux::helper::client::B06Error;
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_b06(
            Err(B06Error::Denied),
            "local.browser.open",
            "BROWSER_OPENED",
            "CENTRAL_BOOTSTRAP_SHOW",
            "CHECK_READY_PROOF",
            &mut out,
            &mut err,
        );
        assert_eq!(code, 7);
        let parsed: serde_json::Value =
            serde_json::from_str(String::from_utf8(out).unwrap().trim_end()).unwrap();
        assert_eq!(parsed["command_id"], "local.browser.open");
        assert_eq!(parsed["reason"], "AUTHORITY_DENIED");
        assert_eq!(parsed["details"]["safe_next_action"], "CHECK_READY_PROOF");

        let mut out = Vec::new();
        let code = run_b06(
            Ok(()),
            "local.browser.open",
            "BROWSER_OPENED",
            "CENTRAL_BOOTSTRAP_SHOW",
            "CHECK_READY_PROOF",
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0);
        let parsed: serde_json::Value =
            serde_json::from_str(String::from_utf8(out).unwrap().trim_end()).unwrap();
        assert_eq!(parsed["command_id"], "local.browser.open");
        assert_eq!(parsed["reason"], "BROWSER_OPENED");
        assert_eq!(
            parsed["details"]["safe_next_action"],
            "CENTRAL_BOOTSTRAP_SHOW"
        );
    }

    // -- doctor -----------------------------------------------------------

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn doctor_on_reference_shape_reports_ok() {
        let (code, stdout, _) = invoke("local.doctor.prerequisites", &[]);
        assert_eq!(code, 0);
        let parsed: serde_json::Value = serde_json::from_str(stdout.trim_end()).unwrap();
        assert_eq!(parsed["command_id"], "local.doctor.prerequisites");
        assert_eq!(parsed["reason"], "ok");
        assert_eq!(parsed["details"]["architecture"], "amd64");
        assert!(parsed["details"]["os_release"].is_string());
        assert!(parsed["details"].get("failures").is_none());
    }

    // -- deferred local ids -------------------------------------------------

    #[test]
    fn other_registered_local_ids_stay_unsupported() {
        for id in ["local.trust.install", "local.dependency-upgrade-plan"] {
            let (code, stdout, _) = invoke(id, &["x"]);
            assert_eq!(code, 5, "id {id}");
            let parsed: serde_json::Value = serde_json::from_str(stdout.trim_end()).unwrap();
            assert_eq!(parsed["command_id"], id);
            assert_eq!(parsed["reason"], "UNSUPPORTED_IN_THIS_SLICE");
            assert!(parsed.get("details").is_none());
        }
    }
}
