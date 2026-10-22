//! `central` — the main CLI and serving binary (rust-application-
//! boundaries.md §2.1/§3.2).
//!
//! R1 ships the closed fail-closed skeleton only: `--version`/`version`
//! and the `central.local-result/v1` envelope. Every command owned by a
//! not-yet-landed R-slice — `serve`, `local *`, `migrate *`, `backup *`,
//! `restore *`, `run *`, `node *`, `checkpoint *`, `artifact *`,
//! `maintenance *`, `bootstrap *`, `grant`, `attest`, `broker *`, and the
//! protected execution modes — resolves to a schema-valid
//! `UNSUPPORTED_IN_THIS_SLICE` result at exit `5` with no mutation
//! (local-development-environment.md §11). A command that ends without a
//! written result fails closed at exit `6`, matching upstream
//! `cli.ResultExitCode`.

use std::io::Write;
use std::process::ExitCode;

use central_foundation::failure::{ExitClass, Failure};
use central_foundation::local_result::LocalResult;
use central_kernel::lifecycle;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut stdout = std::io::stdout().lock();
    let mut stderr = std::io::stderr().lock();
    ExitCode::from(run(&args, &mut stdout, &mut stderr))
}

/// Dispatches one operator invocation and returns the process exit
/// status. Every result path writes exactly one envelope; a write
/// failure collapses to [`ExitClass::Terminal`] so the exit status never
/// looks like a success the envelope did not record.
fn run(args: &[String], stdout: &mut impl Write, stderr: &mut impl Write) -> u8 {
    match resolve(args) {
        Resolution::Version => {
            match writeln!(stdout, "{{\"version\":{:?}}}", env!("CARGO_PKG_VERSION")) {
                Ok(()) => ExitClass::Success.code(),
                Err(err) => write_io_failure(stderr, &err),
            }
        }
        Resolution::Command(command_id) => {
            let result = LocalResult::unsupported(command_id);
            match result.write_json_line(stdout) {
                Ok(()) => result.exit_code,
                Err(err) => write_io_failure(stderr, &err),
            }
        }
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

enum Resolution {
    Version,
    Command(String),
}

/// Resolves argv (minus argv[0]) to a version print or the canonical
/// `command_id` for the deferred envelope.
fn resolve(args: &[String]) -> Resolution {
    // `--version`/`-V` wins only as the sole argument or while it still
    // precedes the first positional verb — `central serve --version`
    // must reach the deferred `serve` command, not print the version.
    // `--config` consumes its value before the scan continues.
    let mut skip_value = false;
    for arg in args {
        if skip_value {
            skip_value = false;
            continue;
        }
        match arg.as_str() {
            "--config" => skip_value = true,
            "--version" | "-V" => return Resolution::Version,
            _ if !arg.starts_with('-') => break,
            _ => {}
        }
    }

    // Global flags are consumed without affecting command identity; the
    // daemon-mode flags resolve to fixed mode command ids.
    let mut positional: Vec<&str> = Vec::new();
    let mut flags: Vec<&str> = Vec::new();
    let mut skip_value = false;
    for arg in args {
        if skip_value {
            skip_value = false;
            continue;
        }
        match arg.as_str() {
            "--config" => skip_value = true,
            "--helper" => return Resolution::Command("helper".to_string()),
            "--broker" => return Resolution::Command("broker".to_string()),
            "--sandbox-launcher" => {
                return Resolution::Command("sandbox-launcher".to_string());
            }
            "--archguard" => return Resolution::Command("archguard".to_string()),
            "--slice-a-verify" => return Resolution::Command("slice-a-verify".to_string()),
            _ => {
                if let Some(flag) = arg.strip_prefix("--") {
                    flags.push(flag);
                } else {
                    positional.push(arg.as_str());
                }
            }
        }
    }

    let Some(&verb) = positional.first() else {
        return Resolution::Command("unknown".to_string());
    };
    if verb == "version" {
        return Resolution::Version;
    }
    Resolution::Command(command_id(verb, &positional[1..], &flags))
}

/// True when `flag` was passed either bare (`--status`) or with a value
/// (`--resume=<id>`), mirroring the upstream flag-sensitive command ids.
fn has_flag(flags: &[&str], flag: &str) -> bool {
    flags
        .iter()
        .any(|f| *f == flag || f.starts_with(&format!("{flag}=")))
}

/// The canonical `command_id` for a deferred command, matching the
/// upstream command registry ids where they exist (`internal/command/
/// registry.go`) and a deterministic `<verb>[.<sub>]` derivation
/// otherwise.
fn command_id(verb: &str, rest: &[&str], flags: &[&str]) -> String {
    let sub = rest.first().copied();
    match (verb, sub) {
        ("serve", _) => "serve".to_string(),
        ("local", Some("init")) => {
            if has_flag(flags, "status") {
                "local.init.status".to_string()
            } else if has_flag(flags, "resume") {
                "local.init.resume".to_string()
            } else if has_flag(flags, "abandon") {
                "local.init.abandon".to_string()
            } else {
                "local.init".to_string()
            }
        }
        ("local", Some("doctor")) => {
            if has_flag(flags, "host-prerequisites") {
                "local.doctor.prerequisites".to_string()
            } else {
                "local.doctor".to_string()
            }
        }
        ("local", Some("security")) => match rest.get(1).copied() {
            Some("update") => "local.security-update".to_string(),
            Some("rescue") => {
                if rest.get(2).copied() == Some("cleanup") {
                    "local.security-rescue-cleanup".to_string()
                } else {
                    "local.security-rescue".to_string()
                }
            }
            other => format!("local.security.{}", other.unwrap_or("status")),
        },
        ("local", Some("dependency")) => match (rest.get(1).copied(), rest.get(2).copied()) {
            (Some("upgrade"), Some("plan")) => "local.dependency-upgrade-plan".to_string(),
            (Some("upgrade"), Some("apply")) => "local.dependency-upgrade-apply".to_string(),
            _ => "local.dependency".to_string(),
        },
        ("local", Some("browser")) => match rest.get(1).copied() {
            Some(action) => format!("local.browser.{action}"),
            None => "local.browser".to_string(),
        },
        ("local", Some("trust")) => match rest.get(1).copied() {
            Some(action) => format!("local.trust.{action}"),
            None => "local.trust".to_string(),
        },
        ("local", Some("tls")) => match rest.get(1).copied() {
            Some(action) => format!("local.tls.{action}"),
            None => "local.tls".to_string(),
        },
        ("local", Some(sub)) => format!("local.{sub}"),
        ("local", None) => "local".to_string(),
        ("migrate", Some(sub)) => format!("migrate-{sub}"),
        ("migrate", None) => "migrate".to_string(),
        ("backup", Some("prune")) => match rest.get(1).copied() {
            Some("plan") => "backup.prune.plan".to_string(),
            Some("apply") => "backup.prune.apply".to_string(),
            _ => "backup.prune".to_string(),
        },
        ("backup", Some(sub)) => format!("backup.{sub}"),
        ("backup", None) => "backup".to_string(),
        ("restore", Some(sub)) => format!("restore.{sub}"),
        ("restore", None) => "restore".to_string(),
        ("run", Some(sub)) => format!("run.{sub}"),
        ("run", None) => "run".to_string(),
        ("node", Some(sub)) => format!("node.{sub}"),
        ("node", None) => "node".to_string(),
        ("checkpoint", Some(sub)) => format!("checkpoint.{sub}"),
        ("checkpoint", None) => "checkpoint".to_string(),
        ("artifact", Some(sub)) => format!("artifact.{sub}"),
        ("artifact", None) => "artifact".to_string(),
        ("maintenance", Some(sub)) => format!("maintenance.{sub}"),
        ("maintenance", None) => "maintenance".to_string(),
        ("bootstrap", Some(sub)) => format!("bootstrap.{sub}"),
        ("bootstrap", None) => "bootstrap".to_string(),
        ("grant", _) => "grant".to_string(),
        ("attest", _) => "attest".to_string(),
        ("broker", Some(sub)) => format!("broker.{sub}"),
        ("broker", None) => "broker".to_string(),
        ("helper", _) => "helper".to_string(),
        ("central-protected-broker", _) => "central-protected-broker".to_string(),
        ("central-sandbox-launcher", _) => "central-sandbox-launcher".to_string(),
        _ => "unknown".to_string(),
    }
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

    #[test]
    fn version_prints_one_json_line_and_exits_0() {
        for argv in [
            &["--version"][..],
            &["-V"][..],
            &["version"][..],
            &["--config", "/abs/central.json", "--version"][..],
        ] {
            let (code, stdout, _) = invoke(argv);
            assert_eq!(code, 0, "argv {argv:?}");
            assert_eq!(
                stdout,
                format!("{{\"version\":\"{}\"}}\n", env!("CARGO_PKG_VERSION"))
            );
        }
    }

    #[test]
    fn version_flag_after_a_positional_verb_reaches_the_deferred_path() {
        // `central serve --version` is a deferred `serve` invocation,
        // not a version print — the flag belongs to the command.
        for argv in [
            &["serve", "--version"][..],
            &["serve", "-V"][..],
            &["local", "up", "--version"][..],
        ] {
            let (code, stdout, _) = invoke(argv);
            assert_eq!(code, 5, "argv {argv:?}");
            let parsed: serde_json::Value = serde_json::from_str(stdout.trim_end()).unwrap();
            assert_eq!(parsed["reason"], "UNSUPPORTED_IN_THIS_SLICE");
        }
        let (_, stdout, _) = invoke(&["serve", "--version"]);
        let parsed: serde_json::Value = serde_json::from_str(stdout.trim_end()).unwrap();
        assert_eq!(parsed["command_id"], "serve");
    }

    #[test]
    fn version_flag_before_any_positional_verb_still_prints() {
        for argv in [
            &["--version", "serve"][..],
            &["-V", "serve"][..],
            &["--config", "/abs/central.json", "--version", "serve"][..],
        ] {
            let (code, stdout, _) = invoke(argv);
            assert_eq!(code, 0, "argv {argv:?}");
            assert_eq!(
                stdout,
                format!("{{\"version\":\"{}\"}}\n", env!("CARGO_PKG_VERSION"))
            );
        }
    }

    #[test]
    fn every_deferred_verb_fails_closed_at_exit_5() {
        // The R2–R6-owned command surface plus representative flag-
        // sensitive ids — all UNSUPPORTED_IN_THIS_SLICE until the owning
        // slice lands (local-development-environment.md §11).
        let cases: &[(&[&str], &str)] = &[
            (&["serve"], "serve"),
            (&["local", "init"], "local.init"),
            (&["local", "init", "--status"], "local.init.status"),
            (&["local", "init", "--resume=abc"], "local.init.resume"),
            (&["local", "init", "--abandon", "abc"], "local.init.abandon"),
            (&["local", "doctor"], "local.doctor"),
            (
                &["local", "doctor", "--host-prerequisites"],
                "local.doctor.prerequisites",
            ),
            (&["local", "prepare"], "local.prepare"),
            (&["local", "up"], "local.up"),
            (&["local", "down"], "local.down"),
            (&["local", "status"], "local.status"),
            (&["local", "wipe", "--target", "/x"], "local.wipe"),
            (&["local", "audit"], "local.audit"),
            (&["local", "browser", "open"], "local.browser.open"),
            (&["local", "trust", "install"], "local.trust.install"),
            (&["local", "security", "update"], "local.security-update"),
            (&["local", "security", "rescue"], "local.security-rescue"),
            (
                &["local", "security", "rescue", "cleanup"],
                "local.security-rescue-cleanup",
            ),
            (
                &["local", "dependency", "upgrade", "plan"],
                "local.dependency-upgrade-plan",
            ),
            (
                &["local", "dependency", "upgrade", "apply"],
                "local.dependency-upgrade-apply",
            ),
            (&["migrate", "up"], "migrate-up"),
            (&["migrate", "verify"], "migrate-verify"),
            (&["migrate", "status"], "migrate-status"),
            (&["migrate", "resume", "--operation=x"], "migrate-resume"),
            (&["backup", "create"], "backup.create"),
            (&["backup", "verify", "id"], "backup.verify"),
            (&["backup", "export"], "backup.export"),
            (&["backup", "import"], "backup.import"),
            (&["backup", "delete"], "backup.delete"),
            (&["backup", "prune", "plan"], "backup.prune.plan"),
            (&["backup", "prune", "apply"], "backup.prune.apply"),
            (&["restore", "verify"], "restore.verify"),
            (&["restore", "apply"], "restore.apply"),
            (&["restore", "resume"], "restore.resume"),
            (&["restore", "abandon"], "restore.abandon"),
            (&["run", "submit"], "run.submit"),
            (&["node", "decide"], "node.decide"),
            (&["checkpoint", "create"], "checkpoint.create"),
            (&["checkpoint", "resume"], "checkpoint.resume"),
            (&["checkpoint", "list"], "checkpoint.list"),
            (&["artifact", "read", "id"], "artifact.read"),
            (&["maintenance", "plan"], "maintenance.plan"),
            (&["maintenance", "apply"], "maintenance.apply"),
            (&["bootstrap", "show"], "bootstrap.show"),
            (&["grant", "admin"], "grant"),
            (&["attest"], "attest"),
            (&["broker", "serve"], "broker.serve"),
            (&["helper"], "helper"),
            (&["central-protected-broker"], "central-protected-broker"),
            (&["central-sandbox-launcher"], "central-sandbox-launcher"),
            (&["--helper"], "helper"),
            (&["--broker"], "broker"),
            (&["--sandbox-launcher"], "sandbox-launcher"),
            (&["--archguard"], "archguard"),
            (&["--slice-a-verify"], "slice-a-verify"),
            (&[], "unknown"),
            (&["frobnicate"], "unknown"),
            (
                &["--config", "/abs/central.json", "local", "up"],
                "local.up",
            ),
            (&["--config=/abs/central.json", "serve"], "serve"),
        ];
        for (argv, want_id) in cases {
            let (code, stdout, _) = invoke(argv);
            assert_eq!(code, 5, "argv {argv:?} must exit 5");
            let parsed: serde_json::Value = serde_json::from_str(stdout.trim_end()).unwrap();
            assert_eq!(parsed["schema_version"], "central.local-result/v1");
            assert_eq!(parsed["command_id"], *want_id, "argv {argv:?}");
            assert_eq!(parsed["exit_code"], 5);
            assert_eq!(parsed["reason"], "UNSUPPORTED_IN_THIS_SLICE");
            assert!(parsed["timestamp"].is_string());
            assert!(parsed.get("details").is_none());
        }
    }

    #[test]
    fn no_args_emits_unknown_envelope_at_exit_5() {
        let (code, stdout, _) = invoke(&[]);
        assert_eq!(code, 5);
        let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(parsed["command_id"], "unknown");
        assert_eq!(parsed["reason"], "UNSUPPORTED_IN_THIS_SLICE");
    }

    #[test]
    fn envelope_exit_code_equals_process_status() {
        // The §7.2 contract: exit_code must equal the process exit
        // status — `run` returns exactly the emitted code.
        let (code, stdout, _) = invoke(&["local", "up"]);
        let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(parsed["exit_code"].as_u64().unwrap(), u64::from(code));
    }
}
