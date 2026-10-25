//! `central` — the main CLI and serving binary (rust-application-
//! boundaries.md §2.1/§3.2).
//!
//! Mode resolution ports `cmd/central/modes.go`: the daemon flags
//! (`--helper`, `--broker`, `--sandbox-launcher`, `--archguard`,
//! `--slice-a-verify`) win anywhere in argv, then the `verb`/`sub`
//! grammar selects Doctor/Init/Migrate/Serve/Bootstrap/BrokerServe/
//! Grant/Attest/Version, and everything else is a registry dispatch.
//! Privilege and `LISTEN_FDS` gates run before any handler.
//!
//! `central artifact read` (Phase R4 task 7), `central checkpoint *`
//! (Phase R4 task 8), `central node decide` (Phase R4 task 9),
//! `central run submit` (task 10), `central serve` and `harness
//! resume|rerun|cancel` (R3 task 13) are the landed verbs. R5 owns
//! the `local` census: `doctor` runs the real host check, `init`
//! parses the four grammar forms, `prepare` parses its flag grammar,
//! and `up`/`down`/`status` report upstream's helper-dial failure —
//! while `grant`, `attest`, `broker serve`,
//! and the three protected modes reach argv-exact skeletons that fail
//! closed at upstream's not-ready exits until T6/T8/T9/T13 land.
//! Every remaining registered command emits the schema-valid
//! `UNSUPPORTED_IN_THIS_SLICE` envelope at exit `5` with no mutation;
//! anything outside the closed grammar is `unknown`. A command that
//! ends without a written result fails closed at exit `6`, matching
//! upstream `cli.ResultExitCode`.

use std::io::Write;
use std::process::ExitCode;

use central_foundation::failure::{ExitClass, Failure};
use central_foundation::local_result::LocalResult;
use central_kernel::lifecycle;

mod artifact_cli;
mod checkpoint_cli;
mod grant_cli;
mod harness_cli;
mod local_cli;
mod modes;
mod node_cli;
mod run_cli;
mod serve;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut stdout = std::io::stdout().lock();
    let mut stderr = std::io::stderr().lock();
    ExitCode::from(run(&args, &mut stdout, &mut stderr))
}

/// Dispatches one operator invocation and returns the process exit
/// status. Mode gates run first — upstream `main()` checks privilege
/// then socket activation before any handler runs — and mode-owned
/// surfaces (`--helper`, `grant`, `broker serve`, …) bypass the
/// command registry entirely. Everything else resolves through the
/// closed command table; unregistered grammar is the `unknown`
/// envelope.
fn run(args: &[String], stdout: &mut impl Write, stderr: &mut impl Write) -> u8 {
    let mode = modes::resolve_mode(args);
    if let Err(msg) = modes::check_privilege_for_uid(mode, modes::current_uid()) {
        let _ = writeln!(stderr, "authority denied: {msg}");
        return ExitClass::Denied.code();
    }
    let listen_fds = std::env::var("LISTEN_FDS").ok().filter(|v| !v.is_empty());
    if let Err(msg) = modes::check_socket_activation(mode, listen_fds.as_deref()) {
        let _ = writeln!(stderr, "dependency unavailable: {msg}");
        return ExitClass::Unavailable.code();
    }
    match mode {
        modes::Mode::Version => {
            match writeln!(stdout, "{{\"version\":{:?}}}", env!("CARGO_PKG_VERSION")) {
                Ok(()) => ExitClass::Success.code(),
                Err(err) => write_io_failure(stderr, &err),
            }
        }
        modes::Mode::Helper => modes::run_helper_daemon(stderr),
        modes::Mode::Broker => modes::run_broker_daemon(stderr),
        modes::Mode::BrokerServe => modes::run_broker_serve(&args[2..], stderr),
        modes::Mode::SandboxLauncher => modes::run_sandbox_daemon(stderr),
        modes::Mode::ArchGuard => modes::run_archguard(stdout, stderr),
        modes::Mode::Verify => modes::run_slice_a_verify(stderr),
        modes::Mode::Grant => grant_cli::grant(&args[1..], stdout, stderr),
        modes::Mode::Attest => modes::run_attest(&args[1..], stdout, stderr),
        // Upstream `runCentralServe` bypasses Dispatch — `central
        // serve <anything>` runs the server entry point.
        modes::Mode::Serve => serve::serve(&args[1..], stdout, stderr),
        modes::Mode::Doctor
        | modes::Mode::Init
        | modes::Mode::Migrate
        | modes::Mode::Bootstrap
        | modes::Mode::Deferred
        | modes::Mode::Unknown => dispatch(args, stdout, stderr),
    }
}

/// The closed command grammar — the `(verb, subcommand)` pairs of
/// upstream `internal/command/registry.go` resolved by
/// `internal/command/dispatch.go`'s first-match `resolve` (entries
/// sharing a pair collapse onto the first registry id, e.g.
/// `local security rescue cleanup` → `local.security-update` and
/// `local init --status` → `local.init`, whose flag form is then
/// re-derived inside `runInit`). `checkpoint show` and the `harness`
/// verbs are the Rust side's deliberate additions — they landed in
/// earlier slices and stay registered so the census covers them.
/// Anything outside the table resolves `unknown`, upstream's
/// Dispatch fallback.
const COMMAND_REGISTRY: &[(&str, &str, &str)] = &[
    ("local", "doctor", "local.doctor.prerequisites"),
    ("local", "init", "local.init"),
    ("local", "security", "local.security-update"),
    ("local", "prepare", "local.prepare"),
    ("local", "up", "local.up"),
    ("local", "down", "local.down"),
    ("local", "status", "local.status"),
    ("local", "browser", "local.browser.open"),
    ("local", "trust", "local.trust.install"),
    ("migrate", "up", "migrate-up"),
    ("migrate", "verify", "migrate-verify"),
    ("migrate", "status", "migrate-status"),
    ("migrate", "resume", "migrate-resume"),
    ("migrate", "reset", "migrate-reset"),
    ("serve", "", "serve"),
    ("bootstrap", "show", "bootstrap.show"),
    ("backup", "create", "backup.create"),
    ("backup", "verify", "backup.verify"),
    ("backup", "status", "backup.status"),
    ("restore", "verify", "restore.verify"),
    ("restore", "apply", "restore.apply"),
    ("restore", "resume", "restore.resume"),
    ("restore", "abandon", "restore.abandon"),
    ("local", "wipe", "local.wipe"),
    ("backup", "export", "backup.export"),
    ("backup", "import", "backup.import"),
    ("backup", "delete", "backup.delete"),
    ("backup", "prune", "backup.prune.plan"),
    ("local", "audit", "local.audit"),
    ("local", "dependency", "local.dependency-upgrade-plan"),
    ("maintenance", "plan", "maintenance.plan"),
    ("maintenance", "apply", "maintenance.apply"),
    ("artifact", "read", "artifact.read"),
    ("checkpoint", "create", "checkpoint.create"),
    ("checkpoint", "resume", "checkpoint.resume"),
    ("checkpoint", "gc", "checkpoint.gc"),
    ("checkpoint", "pin", "checkpoint.pin"),
    ("checkpoint", "unpin", "checkpoint.unpin"),
    ("checkpoint", "list", "checkpoint.list"),
    ("node", "decide", "node.decide"),
    ("run", "submit", "run.submit"),
    ("checkpoint", "show", "checkpoint.show"),
    ("harness", "resume", "harness.resume"),
    ("harness", "rerun", "harness.rerun"),
    ("harness", "cancel", "harness.cancel"),
];

/// First-match `(verb, subcommand)` resolution — upstream
/// `resolve(verb, subcmd)` over the registry table. `sub` is exactly
/// the one token after the verb (`args[2]` upstream).
fn resolve_command_id(args: &[String]) -> &'static str {
    let verb = args.first().map(String::as_str).unwrap_or("");
    let sub = args.get(1).map(String::as_str).unwrap_or("");
    COMMAND_REGISTRY
        .iter()
        .find(|(v, s, _)| *v == verb && *s == sub)
        .map(|(_, _, id)| *id)
        .unwrap_or("unknown")
}

/// Registry dispatch — upstream `Dispatch`: the landed slices own
/// their envelopes end to end; every other registered command id
/// emits the deferred envelope.
fn dispatch(args: &[String], stdout: &mut impl Write, stderr: &mut impl Write) -> u8 {
    let command_id = resolve_command_id(args);
    // Tokens after the `<verb> <sub>` pair — upstream `args[3:]`.
    let tokens = if args.len() > 2 { &args[2..] } else { &[][..] };
    // `serve` resolves Mode::Serve before dispatch runs, so its
    // registry row is upstream-census documentation only — there is
    // no dispatch arm for it.
    if command_id.starts_with("harness.") {
        return harness_cli::harness(command_id, tokens, stdout, stderr);
    }
    if command_id == "artifact.read" {
        return artifact_cli::artifact_read(tokens, stdout, stderr);
    }
    if command_id.starts_with("checkpoint.") {
        return checkpoint_cli::checkpoint(command_id, tokens, stdout, stderr);
    }
    if command_id.starts_with("node.") {
        return node_cli::node(command_id, tokens, stdout, stderr);
    }
    if command_id.starts_with("run.") {
        return run_cli::run(command_id, tokens, stdout, stderr);
    }
    if command_id.starts_with("local.") {
        return local_cli::local(command_id, tokens, stdout, stderr);
    }
    let result = LocalResult::unsupported(command_id);
    match result.write_json_line(stdout) {
        Ok(()) => result.exit_code,
        Err(err) => write_io_failure(stderr, &err),
    }
}

/// Fails closed on a result that could not be written: upstream's rule
/// is that a command ending without a result is exit 6.
fn write_io_failure(stderr: &mut impl Write, err: &std::io::Error) -> u8 {
    let _ = writeln!(stderr, "central: could not write result envelope");
    lifecycle::exit_code(Some(&Failure::internal(
        "central_result_write_failed",
        err.to_string(),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(argv: &[&str]) -> Vec<String> {
        argv.iter().map(|s| (*s).to_string()).collect()
    }

    /// Runs `run` capturing both planes, returning
    /// `(exit_code, stdout, stderr)`.
    fn invoke(argv: &[&str]) -> (u8, String, String) {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run(&args(argv), &mut stdout, &mut stderr);
        (
            code,
            String::from_utf8(stdout).unwrap(),
            String::from_utf8(stderr).unwrap(),
        )
    }

    /// Non-root assumption for the operator-mode assertions — the
    /// privilege gate is exercised directly through
    /// `modes::check_privilege_for_uid`; a root test run sees the
    /// denied branch instead and these cases skip like upstream's
    /// `os.Getuid() == 0` skips.
    fn non_root() -> bool {
        modes::current_uid() != 0
    }

    fn parse_envelope(stdout: &str) -> serde_json::Value {
        serde_json::from_str(stdout.trim_end()).unwrap()
    }

    #[test]
    fn version_prints_one_json_line_and_exits_0() {
        // Upstream has only the `version` verb — `--version`/`-V` were
        // never registered and resolve `unknown` like any other flag.
        let (code, stdout, _) = invoke(&["version"]);
        assert_eq!(code, 0);
        assert_eq!(
            stdout,
            format!("{{\"version\":\"{}\"}}\n", env!("CARGO_PKG_VERSION"))
        );
        for argv in [
            &["--version"][..],
            &["-V"][..],
            &["--version", "serve"][..],
            &["--config", "/abs/central.json", "version"][..],
        ] {
            let (code, stdout, _) = invoke(argv);
            assert_eq!(code, 5, "argv {argv:?}");
            assert_eq!(
                parse_envelope(&stdout)["command_id"],
                "unknown",
                "argv {argv:?}"
            );
        }
    }

    #[test]
    fn serve_mode_owns_any_argv_after_the_verb() {
        // `central serve --version`/`central serve extra` reach the
        // server composition (upstream `runCentralServe` ignores
        // trailing args) — never a version print, never `unknown`.
        if !non_root() {
            return;
        }
        for argv in [
            &["serve", "--version"][..],
            &["serve", "-V"][..],
            &["serve", "extra"][..],
        ] {
            let (code, stdout, _) = invoke(argv);
            let parsed = parse_envelope(&stdout);
            assert_eq!(parsed["command_id"], "serve", "argv {argv:?}");
            assert_eq!(parsed["reason"], "DEPENDENCY_UNAVAILABLE", "argv {argv:?}");
            assert_eq!(code, 3, "argv {argv:?}");
        }
    }

    /// The complete registered census: every `(verb, sub)` pair in
    /// COMMAND_REGISTRY must route — landed verbs to their modules,
    /// the R5 `local` skeletons to their not-ready outcomes, and the
    /// still-deferred commands to the exact exit-5 envelope.
    #[test]
    fn every_registered_verb_is_reachable() {
        if !non_root() {
            return;
        }
        // Deferred commands: exact upstream envelope, no details.
        let deferred: &[(&[&str], &str)] = &[
            (&["local", "init", "--status"], "local.init.status"),
            (&["local", "init", "--resume=abc"], "local.init.resume"),
            (&["local", "init", "--abandon=abc"], "local.init.abandon"),
            (&["local", "wipe", "--target", "/x"], "local.wipe"),
            (&["local", "audit"], "local.audit"),
            (&["local", "browser", "open"], "local.browser.open"),
            (&["local", "trust", "install"], "local.trust.install"),
            (&["local", "security", "update"], "local.security-update"),
            // First-match collapse: every `local security *` form
            // resolves to the first `local security` registry id.
            (&["local", "security", "rescue"], "local.security-update"),
            (
                &["local", "security", "rescue", "cleanup"],
                "local.security-update",
            ),
            (
                &["local", "dependency", "upgrade", "plan"],
                "local.dependency-upgrade-plan",
            ),
            (
                &["local", "dependency", "upgrade", "apply"],
                "local.dependency-upgrade-plan",
            ),
            (&["migrate", "up"], "migrate-up"),
            (&["migrate", "verify"], "migrate-verify"),
            (&["migrate", "status"], "migrate-status"),
            (&["migrate", "resume", "--operation=x"], "migrate-resume"),
            (&["migrate", "reset"], "migrate-reset"),
            (&["backup", "create"], "backup.create"),
            (&["backup", "verify", "id"], "backup.verify"),
            (&["backup", "status"], "backup.status"),
            (&["backup", "export"], "backup.export"),
            (&["backup", "import"], "backup.import"),
            (&["backup", "delete"], "backup.delete"),
            (&["backup", "prune", "plan"], "backup.prune.plan"),
            // First-match: `backup.prune.apply` is the shadowed entry.
            (&["backup", "prune", "apply"], "backup.prune.plan"),
            (&["restore", "verify"], "restore.verify"),
            (&["restore", "apply"], "restore.apply"),
            (&["restore", "resume"], "restore.resume"),
            (&["restore", "abandon"], "restore.abandon"),
            (&["maintenance", "plan"], "maintenance.plan"),
            (&["maintenance", "apply"], "maintenance.apply"),
            (&["bootstrap", "show"], "bootstrap.show"),
        ];
        for (argv, want_id) in deferred {
            let (code, stdout, _) = invoke(argv);
            assert_eq!(code, 5, "argv {argv:?} must exit 5");
            let parsed = parse_envelope(&stdout);
            assert_eq!(parsed["schema_version"], "central.local-result/v1");
            assert_eq!(parsed["command_id"], *want_id, "argv {argv:?}");
            assert_eq!(parsed["exit_code"], 5);
            assert_eq!(parsed["reason"], "UNSUPPORTED_IN_THIS_SLICE");
            assert!(parsed["timestamp"].is_string());
            assert!(parsed.get("details").is_none());
        }

        // R5 local skeletons.
        let (code, stdout, _) = invoke(&["local", "doctor"]);
        assert_eq!(code, 0);
        assert_eq!(
            parse_envelope(&stdout)["command_id"],
            "local.doctor.prerequisites"
        );

        let (code, stdout, stderr) = invoke(&["local", "init"]);
        assert_eq!(code, 3);
        assert_eq!(parse_envelope(&stdout)["reason"], "HELPER_UNAVAILABLE");
        assert!(stderr.contains("systemctl start central-helper.socket"));

        for argv in [
            &["local", "up"][..],
            &["local", "down"][..],
            &["local", "status"][..],
        ] {
            let (code, stdout, _) = invoke(argv);
            assert_eq!(code, 5, "argv {argv:?}");
            let parsed = parse_envelope(&stdout);
            assert_eq!(parsed["reason"], "LIFECYCLE_EXECUTION_FAILED");
            assert_eq!(
                parsed["details"]["safe_next_action"],
                "START_CENTRAL_HELPER"
            );
        }

        let (code, stdout, _) = invoke(&["local", "prepare"]);
        assert_eq!(code, 7);
        assert_eq!(parse_envelope(&stdout)["reason"], "PREPARE_FAILED");

        // Landed commands route to their own modules (covered in
        // detail by the dedicated tests below).
        let (code, stdout, _) = invoke(&["serve"]);
        assert_eq!(code, 3);
        assert_eq!(parse_envelope(&stdout)["reason"], "DEPENDENCY_UNAVAILABLE");
        let (code, stdout, _) = invoke(&["artifact", "read", "id"]);
        assert_eq!(code, 5);
        assert_eq!(
            parse_envelope(&stdout)["reason"],
            "ARTIFACT_READ_UNAVAILABLE"
        );
        let (code, stdout, _) = invoke(&["checkpoint", "list", "--run", "r"]);
        assert_eq!(code, 5);
        assert_eq!(parse_envelope(&stdout)["reason"], "CHECKPOINT_UNAVAILABLE");
        let (code, stdout, _) = invoke(&["run", "submit"]);
        assert_eq!(code, 5);
        assert_eq!(parse_envelope(&stdout)["reason"], "RUN_UNAVAILABLE");
        let (code, _, _) = invoke(&["harness", "resume"]);
        assert_eq!(code, 2);
    }

    /// Grammar closure: anything the registry does not contain is the
    /// `unknown` envelope at exit 5 — including bare nouns, unknown
    /// subverbs under known nouns, and leading global flags upstream
    /// never had (`--config`, `--version`).
    #[test]
    fn unregistered_grammar_is_unknown_at_exit_5() {
        if !non_root() {
            return;
        }
        for argv in [
            &[][..],
            &["frobnicate"][..],
            &["local"][..],
            &["local", "bogus"][..],
            &["local", "tls", "inspect"][..],
            &["migrate"][..],
            &["migrate", "bogus"][..],
            &["backup"][..],
            &["backup", "bogus"][..],
            &["restore"][..],
            &["node"][..],
            &["node", "bogus"][..],
            &["run"][..],
            &["run", "list"][..],
            &["artifact"][..],
            &["artifact", "bogus"][..],
            &["checkpoint"][..],
            &["checkpoint", "bogus"][..],
            &["harness"][..],
            &["harness", "status"][..],
            &["maintenance"][..],
            &["bootstrap"][..],
            &["bootstrap", "bogus"][..],
            &["broker"][..],
            &["broker", "bogus"][..],
            &["helper"][..],
            &["central-protected-broker"][..],
            &["central-sandbox-launcher"][..],
            &["--config", "/abs/central.json", "local", "up"][..],
            &["--bogus-flag"][..],
        ] {
            let (code, stdout, _) = invoke(argv);
            assert_eq!(code, 5, "argv {argv:?}");
            let parsed = parse_envelope(&stdout);
            assert_eq!(parsed["schema_version"], "central.local-result/v1");
            assert_eq!(parsed["command_id"], "unknown", "argv {argv:?}");
            assert_eq!(parsed["exit_code"], 5);
            assert_eq!(parsed["reason"], "UNSUPPORTED_IN_THIS_SLICE");
            assert!(parsed["timestamp"].is_string());
            assert!(parsed.get("details").is_none());
        }
    }

    /// The protected modes are reachable only through their exact
    /// flag argv; as a non-root operator they deny at exit 7 before
    /// any body runs, matching upstream `checkPrivilege`.
    #[test]
    fn protected_modes_require_exact_flag_and_root() {
        if !non_root() {
            return;
        }
        for (argv, uid_msg) in [
            (&["--helper"][..], "--helper"),
            (&["--broker"][..], "--broker"),
            (&["--sandbox-launcher"][..], "--sandbox-launcher"),
            (&["--slice-a-verify"][..], "--slice-a-verify"),
            (&["grant", "issue", "--kind", "init"][..], "grant"),
            (
                &["broker", "serve", "--state-root", "/x", "--socket", "/y"][..],
                "broker serve",
            ),
            // Flag precedence: the daemon flag anywhere selects the mode.
            (&["local", "up", "--helper"][..], "--helper precedence"),
        ] {
            let (code, stdout, stderr) = invoke(argv);
            assert_eq!(code, 7, "argv {argv:?} ({uid_msg})");
            assert_eq!(stdout, "", "argv {argv:?} writes no envelope");
            assert!(
                stderr.contains("authority denied: mode requires root (UID 0)"),
                "argv {argv:?} stderr {stderr:?}"
            );
        }
        // Positional lookalikes never reach the modes.
        for argv in [
            &["helper"][..],
            &["central-protected-broker"][..],
            &["central-sandbox-launcher"][..],
            &["broker", "bogus"][..],
        ] {
            let (code, stdout, _) = invoke(argv);
            assert_eq!(code, 5, "argv {argv:?}");
            assert_eq!(parse_envelope(&stdout)["command_id"], "unknown");
        }
    }

    /// `attest` carries no privilege gate upstream — a non-root
    /// invocation reaches the dispatch skeleton (usage at exit 2),
    /// while `grant`/`broker serve` deny first.
    #[test]
    fn attest_reaches_dispatch_without_root() {
        if !non_root() {
            return;
        }
        let (code, stdout, stderr) = invoke(&["attest"]);
        assert_eq!(code, 2);
        assert_eq!(stdout, "");
        assert_eq!(stderr, "usage: central attest keygen ...\n");
        let (code, _, stderr) = invoke(&["attest", "bogus"]);
        assert_eq!(code, 2);
        assert_eq!(stderr, "attest: unknown subcommand \"bogus\"\n");
    }

    /// `--archguard` is a non-root mode: it passes the gate and fails
    /// closed through the deferred envelope (the Go-source guard has
    /// no Rust counterpart).
    #[test]
    fn archguard_mode_is_closed_unsupported() {
        if !non_root() {
            return;
        }
        let (code, stdout, _) = invoke(&["--archguard"]);
        assert_eq!(code, 5);
        let parsed = parse_envelope(&stdout);
        assert_eq!(parsed["command_id"], "archguard");
        assert_eq!(parsed["reason"], "UNSUPPORTED_IN_THIS_SLICE");
    }

    #[test]
    fn local_init_grammar_is_closed() {
        if !non_root() {
            return;
        }
        // Usage errors are exit 2 under the `local.init` id.
        for argv in [
            &["local", "init", "--abandon", "abc"][..],
            &["local", "init", "--resume", "abc"][..],
            &["local", "init", "--config", "/x"][..],
            &["local", "init", "extra"][..],
        ] {
            let (code, stdout, stderr) = invoke(argv);
            assert_eq!(code, 2, "argv {argv:?}");
            let parsed = parse_envelope(&stdout);
            assert_eq!(parsed["command_id"], "local.init", "argv {argv:?}");
            assert_eq!(parsed["reason"], "INVALID_INVOCATION");
            assert!(stderr.starts_with("central local init: "), "argv {argv:?}");
        }
    }

    #[test]
    fn artifact_read_without_env_config_is_unavailable_at_exit_5() {
        // `artifact.read` is landed: without the composition env it
        // reports ARTIFACT_READ_UNAVAILABLE (still exit 5), never the
        // deferred-verb placeholder.
        if !non_root() {
            return;
        }
        let (code, stdout, _) = invoke(&["artifact", "read", "id"]);
        assert_eq!(code, 5);
        let parsed = parse_envelope(&stdout);
        assert_eq!(parsed["schema_version"], "central.local-result/v1");
        assert_eq!(parsed["command_id"], "artifact.read");
        assert_eq!(parsed["exit_code"], 5);
        assert_eq!(parsed["reason"], "ARTIFACT_READ_UNAVAILABLE");
    }

    #[test]
    fn serve_without_env_is_unavailable_at_exit_3() {
        // `serve` is landed (task 13): without the runtime credential
        // env it reports DEPENDENCY_UNAVAILABLE at exit 3, never the
        // deferred-verb placeholder.
        if !non_root() {
            return;
        }
        let (code, stdout, _) = invoke(&["serve"]);
        assert_eq!(code, 3);
        let parsed = parse_envelope(&stdout);
        assert_eq!(parsed["schema_version"], "central.local-result/v1");
        assert_eq!(parsed["command_id"], "serve");
        assert_eq!(parsed["exit_code"], 3);
        assert_eq!(parsed["reason"], "DEPENDENCY_UNAVAILABLE");
    }

    #[test]
    fn harness_verbs_without_env_are_unavailable() {
        // `harness resume|rerun|cancel` are landed (task 13): a
        // missing flag is a usage refusal at exit 2; fully flagged
        // but without a DSN they report HARNESS_UNAVAILABLE at exit 3.
        if !non_root() {
            return;
        }
        let (code, stdout, _) = invoke(&["harness", "resume"]);
        assert_eq!(code, 2);
        let parsed = parse_envelope(&stdout);
        assert_eq!(parsed["command_id"], "harness.resume");
        assert_eq!(parsed["reason"], "HARNESS_USAGE");

        let (code, stdout, _) = invoke(&[
            "harness",
            "cancel",
            "--workspace",
            "00000000-0000-7000-8000-000000000001",
            "--task",
            "00000000-0000-7000-8000-000000000002",
            "--run",
            "00000000-0000-7000-8000-000000000003",
        ]);
        assert_eq!(code, 3);
        let parsed = parse_envelope(&stdout);
        assert_eq!(parsed["command_id"], "harness.cancel");
        assert_eq!(parsed["reason"], "HARNESS_UNAVAILABLE");

        // Every other harness verb is outside the closed grammar and
        // resolves `unknown` (upstream has no harness registry).
        for argv in [
            &["harness", "status"][..],
            &["harness", "launch", "--x"][..],
            &["harness"][..],
        ] {
            let (code, stdout, _) = invoke(argv);
            assert_eq!(code, 5, "argv {argv:?}");
            let parsed = parse_envelope(&stdout);
            assert_eq!(parsed["command_id"], "unknown");
            assert_eq!(parsed["reason"], "UNSUPPORTED_IN_THIS_SLICE");
        }
    }

    #[test]
    fn tokens_after_the_verb_pair_reach_the_landed_module() {
        // upstream `args[3:]`: everything after `<verb> <sub>`.
        let argv = args(&["artifact", "read", "id", "--stdout"]);
        assert_eq!(&argv[2..], &["id", "--stdout"]);
        let argv = args(&["checkpoint", "list", "--run", "r"]);
        assert_eq!(&argv[2..], &["--run", "r"]);
        let argv = args(&["local", "init", "--status"]);
        assert_eq!(&argv[2..], &["--status"]);
    }

    #[test]
    fn checkpoint_verbs_without_env_are_unavailable_at_exit_5() {
        // `checkpoint *` is landed: without CENTRAL_CHECKPOINT_DSN the
        // verbs report CHECKPOINT_UNAVAILABLE (still exit 5), never
        // the deferred-verb placeholder.
        if !non_root() {
            return;
        }
        for argv in [
            &["checkpoint", "create"][..],
            &["checkpoint", "resume", "--token", "t"][..],
            &["checkpoint", "list", "--run", "r"][..],
            &["checkpoint", "show", "id"][..],
            &["checkpoint", "gc"][..],
            &["checkpoint", "pin", "id"][..],
            &["checkpoint", "unpin", "id"][..],
        ] {
            let (code, stdout, _) = invoke(argv);
            assert_eq!(code, 5, "argv {argv:?}");
            let parsed = parse_envelope(&stdout);
            assert_eq!(parsed["schema_version"], "central.local-result/v1");
            assert_eq!(parsed["reason"], "CHECKPOINT_UNAVAILABLE", "argv {argv:?}");
            assert_eq!(parsed["exit_code"], 5);
        }
    }

    #[test]
    fn node_decide_without_env_is_unavailable_at_exit_5() {
        // `node decide` is landed: without CENTRAL_NODE_DSN it
        // reports NODE_UNAVAILABLE (still exit 5), never the
        // deferred-verb placeholder.
        if !non_root() {
            return;
        }
        let (code, stdout, _) = invoke(&[
            "node",
            "decide",
            "--run",
            "r",
            "--node",
            "n",
            "--decision",
            "rerun",
        ]);
        assert_eq!(code, 5);
        let parsed = parse_envelope(&stdout);
        assert_eq!(parsed["schema_version"], "central.local-result/v1");
        assert_eq!(parsed["command_id"], "node.decide");
        assert_eq!(parsed["exit_code"], 5);
        assert_eq!(parsed["reason"], "NODE_UNAVAILABLE");
    }

    #[test]
    fn run_submit_without_env_is_unavailable_at_exit_5() {
        // `run submit` is landed: without CENTRAL_NODE_DSN it
        // reports RUN_UNAVAILABLE (still exit 5), never the
        // deferred-verb placeholder.
        if !non_root() {
            return;
        }
        let (code, stdout, _) = invoke(&[
            "run",
            "submit",
            "--workspace",
            "00000000-0000-7000-8000-000000000001",
            "--title",
            "t",
            "--workers",
            "2",
        ]);
        assert_eq!(code, 5);
        let parsed = parse_envelope(&stdout);
        assert_eq!(parsed["schema_version"], "central.local-result/v1");
        assert_eq!(parsed["command_id"], "run.submit");
        assert_eq!(parsed["exit_code"], 5);
        assert_eq!(parsed["reason"], "RUN_UNAVAILABLE");
    }

    #[test]
    fn envelope_exit_code_equals_process_status() {
        // The §7.2 contract: exit_code must equal the process exit
        // status — `run` returns exactly the emitted code.
        if !non_root() {
            return;
        }
        let (code, stdout, _) = invoke(&["local", "up"]);
        let parsed = parse_envelope(&stdout);
        assert_eq!(parsed["exit_code"].as_u64().unwrap(), u64::from(code));
    }
}
