//! Protected-execution mode resolution and gates — ports
//! `cmd/central/modes.go` and the skeletons of the mode entry points
//! (`runHelperDaemon`, `runBrokerDaemon`, `runSandboxDaemon`,
//! `runBrokerServe`, `runSliceAVerify`, `runAttest`) whose real bodies
//! land in later R5 tasks (helper protocol, protected broker, sandbox
//! launcher).
//!
//! Mode selection is argv-driven exactly like upstream `resolveMode`:
//! the explicit daemon flags `--helper`, `--broker`,
//! `--sandbox-launcher`, `--archguard`, and `--slice-a-verify` win over
//! positional grammar anywhere in argv, then `verb`/`subcommand`
//! dispatch applies. Systemd activates the daemons through the flag
//! forms with `LISTEN_FDS`; a mode reached any other way fails closed
//! at the privilege and socket-activation gates before touching its
//! body.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use central_foundation::failure::ExitClass;
use central_foundation::local_result::LocalResult;

/// The upstream mode set (`cmd/central/modes.go`), one variant per
/// distinguishable invocation class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// Bare `central` with no arguments — upstream's `ModeUnknown`
    /// falls through both gates to the `unknown` envelope.
    Unknown,
    /// `central local doctor` (any `--host-prerequisites` flag).
    Doctor,
    /// `central local init` (every grammar form).
    Init,
    /// `central --helper` — the genesis/instance helper daemon.
    Helper,
    /// `central --broker` — the protected broker daemon.
    Broker,
    /// `central --sandbox-launcher` — the sandbox launcher daemon.
    SandboxLauncher,
    /// `central --archguard` — the workspace architecture guard.
    ArchGuard,
    /// `central --slice-a-verify` — the reference-host verification run.
    Verify,
    /// `central migrate *` — the migrate mode installs its client then
    /// dispatches.
    Migrate,
    /// `central serve` — routes straight to `serve`, ignoring extras.
    Serve,
    /// `central bootstrap show`.
    Bootstrap,
    /// Every other operator invocation — resolved through the command
    /// registry.
    Deferred,
    /// `central grant *` — root-only grant surface.
    Grant,
    /// `central attest *` — no privilege gate upstream.
    Attest,
    /// `central version`.
    Version,
    /// `central broker serve` — root-only non-systemd broker.
    BrokerServe,
}

/// Ports `resolveMode`: daemon flags first (upstream scans all of
/// `os.Args`; here argv[0] is already stripped — it is never a daemon
/// flag in any real invocation), then the exact-verb grammar.
pub(crate) fn resolve_mode(args: &[String]) -> Mode {
    if args.is_empty() {
        return Mode::Unknown;
    }
    for arg in args {
        match arg.as_str() {
            "--helper" => return Mode::Helper,
            "--broker" => return Mode::Broker,
            "--sandbox-launcher" => return Mode::SandboxLauncher,
            "--archguard" => return Mode::ArchGuard,
            "--slice-a-verify" => return Mode::Verify,
            _ => {}
        }
    }
    let verb = args[0].as_str();
    let subcmd = args.get(1).map(String::as_str).unwrap_or("");
    match (verb, subcmd) {
        ("migrate", _) => Mode::Migrate,
        ("serve", _) => Mode::Serve,
        ("broker", "serve") => Mode::BrokerServe,
        ("bootstrap", "show") => Mode::Bootstrap,
        ("local", "doctor") => Mode::Doctor,
        ("local", "init") => Mode::Init,
        ("grant", _) => Mode::Grant,
        ("attest", _) => Mode::Attest,
        ("version", _) => Mode::Version,
        _ => Mode::Deferred,
    }
}

/// Ports `checkPrivilege` against an explicit uid so tests cover both
/// branches without root (the upstream `ForUID` seam shape).
///
/// Root-required modes: helper, broker, sandbox launcher, verify,
/// grant, broker serve. Operator modes reject root: doctor, init,
/// archguard, migrate, serve, bootstrap, deferred. Unknown, attest,
/// and version carry no gate.
pub(crate) fn check_privilege_for_uid(mode: Mode, uid: u32) -> Result<(), String> {
    match mode {
        Mode::Helper
        | Mode::Broker
        | Mode::SandboxLauncher
        | Mode::Verify
        | Mode::Grant
        | Mode::BrokerServe => {
            if uid != 0 {
                Err(format!("mode requires root (UID 0), got UID {uid}"))
            } else {
                Ok(())
            }
        }
        Mode::Doctor
        | Mode::Init
        | Mode::ArchGuard
        | Mode::Migrate
        | Mode::Serve
        | Mode::Bootstrap
        | Mode::Deferred => {
            if uid == 0 {
                Err("mode must not run as root (UID 0)".to_string())
            } else {
                Ok(())
            }
        }
        Mode::Unknown | Mode::Attest | Mode::Version => Ok(()),
    }
}

/// Ports `checkSocketActivation` against an explicit `LISTEN_FDS`
/// value (`None` = unset or empty, matching upstream's `os.Getenv`).
/// Socket-activated modes require it; every other mode only validates
/// the value's form when present.
pub(crate) fn check_socket_activation(mode: Mode, listen_fds: Option<&str>) -> Result<(), String> {
    match listen_fds {
        None => match mode {
            Mode::Helper | Mode::Broker | Mode::SandboxLauncher => {
                Err("socket-activated mode requires LISTEN_FDS from systemd".to_string())
            }
            _ => Ok(()),
        },
        Some(fds) => match fds.parse::<i64>() {
            Ok(n) if n >= 1 => Ok(()),
            _ => Err(format!("invalid LISTEN_FDS: {fds:?}")),
        },
    }
}

/// The process real uid — upstream `os.Getuid` parity.
pub(crate) fn current_uid() -> u32 {
    rustix::process::getuid().as_raw()
}

/// Reads `/etc/os-release` like upstream; `None` when unreadable.
pub(crate) fn os_release() -> Option<String> {
    std::fs::read_to_string("/etc/os-release").ok()
}

/// The upstream `runtime.GOARCH`-style architecture token.
pub(crate) fn host_goarch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

/// Ports `isReferenceHost`: Ubuntu >= 24.04 per `/etc/os-release` on
/// x86_64 hardware.
fn is_reference_host() -> bool {
    let Some(release) = os_release() else {
        return false;
    };
    if !release.contains("Ubuntu") {
        return false;
    }
    for line in release.lines() {
        if let Some(raw) = line.strip_prefix("VERSION_ID=") {
            let ver = raw.trim_matches('"');
            if let Some(major) = ver.split('.').next()
                && major.parse::<u32>().unwrap_or(0) < 24
            {
                return false;
            }
            break;
        }
    }
    std::env::consts::ARCH == "x86_64"
}

// -- mode entry points (skeletons until their R5 tasks land) -----------

/// `central --helper` after the gates — upstream `runHelperDaemon`.
/// The genesis branch composes from `CENTRAL_OPERATOR_UID`/`GID`
/// alone; the instance branch needs the production instance. Either
/// way the real server lands in T6, so composition failures report
/// upstream's `helper: [genesis] composition:` class at exit 6.
pub(crate) fn run_helper_daemon(stderr: &mut impl Write) -> u8 {
    helper_daemon(genesis_roots_absent(), helper_policy_from_env(), stderr)
}

fn helper_daemon(genesis_absent: bool, policy: Result<(), String>, stderr: &mut impl Write) -> u8 {
    let which = if genesis_absent {
        "genesis composition"
    } else {
        "composition"
    };
    let msg = match policy {
        Err(err) => err,
        Ok(()) => "helper server is not implemented in this slice".to_string(),
    };
    let _ = writeln!(stderr, "helper: {which}: {msg}");
    ExitClass::Terminal.code()
}

/// The two instance roots genesis distinguishes: state and protected
/// (`genesisRoots.instancesRoot()`/`protectedInstancesRoot()`).
const GENESIS_STATE_INSTANCES: &str = "/var/lib/central-state/v1/instances";
const GENESIS_PROTECTED_INSTANCES: &str = "/var/lib/central-protected/v1/instances";

/// Minimal stand-in for genesis `state()`: absent means both instance
/// roots are missing or empty. An unreadable root counts as present —
/// the helper then follows the instance composition branch, which
/// still fails closed this slice.
fn genesis_roots_absent() -> bool {
    for root in [GENESIS_STATE_INSTANCES, GENESIS_PROTECTED_INSTANCES] {
        match std::fs::read_dir(root) {
            Ok(mut entries) => {
                if entries.next().is_some() {
                    return false;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return false,
        }
    }
    true
}

/// Ports `helperPeerPolicyFromEnvironment`: both operator ids must be
/// set, numeric, and nonzero.
fn helper_peer_policy(uid: Option<String>, gid: Option<String>) -> Result<(), String> {
    for (name, value) in [("CENTRAL_OPERATOR_UID", uid), ("CENTRAL_OPERATOR_GID", gid)] {
        let raw = value
            .filter(|v| !v.is_empty())
            .ok_or_else(|| format!("{name} is not set"))?;
        let parsed: u32 = raw
            .trim()
            .parse()
            .map_err(|_| format!("{name} is not a number: {raw:?}"))?;
        if parsed == 0 {
            return Err(format!("{name} must be a valid nonzero uid/gid: {raw:?}"));
        }
    }
    Ok(())
}

fn helper_policy_from_env() -> Result<(), String> {
    helper_peer_policy(
        std::env::var("CENTRAL_OPERATOR_UID").ok(),
        std::env::var("CENTRAL_OPERATOR_GID").ok(),
    )
}

/// `central --broker` after the gates — upstream `runBrokerDaemon`.
/// Production-instance resolution is `central-infra` work (T9), so
/// the skeleton reports upstream's resolution failure verbatim.
pub(crate) fn run_broker_daemon(stderr: &mut impl Write) -> u8 {
    let _ = writeln!(
        stderr,
        "broker: production instance: production instance authority unavailable"
    );
    ExitClass::Terminal.code()
}

/// `central --sandbox-launcher` after the gates — upstream
/// `runSandboxDaemon`. The launcher itself is T9 work; the portable
/// failure keeps upstream's `sandbox: <serve-error>` exit-3 shape.
pub(crate) fn run_sandbox_daemon(stderr: &mut impl Write) -> u8 {
    let _ = writeln!(
        stderr,
        "sandbox: sandbox-daemon: not implemented in this slice"
    );
    ExitClass::Unavailable.code()
}

/// `central --slice-a-verify` after the gates — upstream
/// `runSliceAVerify`. The verification suite is not ported; the
/// off-reference-host refusal is the reachable not-ready branch.
pub(crate) fn run_slice_a_verify(stderr: &mut impl Write) -> u8 {
    if !is_reference_host() {
        let _ = writeln!(
            stderr,
            "slice-a verification unavailable: not running on reference host (Ubuntu 24.04 LTS amd64 required)"
        );
    } else {
        let _ = writeln!(
            stderr,
            "slice-a verification unavailable: verification suite is not implemented in this slice"
        );
    }
    ExitClass::Usage.code()
}

/// `central --archguard` — upstream's guard is a Go-source lint that
/// does not exist for the Rust workspace (clippy/workspace lints own
/// that job). Stays fail-closed through the deferred envelope.
pub(crate) fn run_archguard(stdout: &mut impl Write, stderr: &mut impl Write) -> u8 {
    let result = LocalResult::unsupported("archguard");
    match result.write_json_line(stdout) {
        Ok(()) => result.exit_code,
        Err(_) => {
            let _ = writeln!(stderr, "central: could not write result envelope");
            ExitClass::Terminal.code()
        }
    }
}

// -- `central broker serve` -------------------------------------------

/// The validated `central broker serve` invocation — upstream
/// `brokerServeConfig`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct BrokerServeConfig {
    pub state_root: String,
    pub socket_path: String,
}

const BROKER_SERVE_USAGE: &str =
    "usage: central broker serve --state-root <abs-dir> --socket <abs-path>";

/// Ports `parseBrokerServeArgs`: `--state-root <abs> --socket <abs>`,
/// both `--flag value` and `--flag=value`; both paths must be absolute
/// and clean.
pub(crate) fn parse_broker_serve_args(args: &[String]) -> Result<BrokerServeConfig, String> {
    let mut cfg = BrokerServeConfig {
        state_root: String::new(),
        socket_path: String::new(),
    };
    let mut index = 0usize;
    while index < args.len() {
        let raw = &args[index];
        let (name, mut value, has_value) = match raw.split_once('=') {
            Some((n, v)) => (n, v.to_string(), true),
            None => (raw.as_str(), String::new(), false),
        };
        match name {
            "--state-root" | "--socket" => {
                if !has_value {
                    index += 1;
                    if index >= args.len() {
                        return Err(BROKER_SERVE_USAGE.to_string());
                    }
                    value = args[index].clone();
                }
                if value.is_empty() || !value.starts_with('/') || go_clean(&value) != value {
                    return Err(BROKER_SERVE_USAGE.to_string());
                }
                if name == "--state-root" {
                    cfg.state_root = value;
                } else {
                    cfg.socket_path = value;
                }
            }
            _ => return Err(BROKER_SERVE_USAGE.to_string()),
        }
        index += 1;
    }
    if cfg.state_root.is_empty() || cfg.socket_path.is_empty() {
        return Err(BROKER_SERVE_USAGE.to_string());
    }
    Ok(cfg)
}

/// Ports `checkBrokerServeStateRootForUID`: an existing uid-owned 0700
/// directory, inspected via lstat (symlinks refuse like upstream).
pub(crate) fn check_broker_serve_state_root_for_uid(path: &str, uid: u32) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() && meta.mode() & 0o777 == 0o700 => {
            if meta.uid() == uid {
                Ok(())
            } else {
                Err(format!(
                    "broker serve: state root must be owned by uid {uid}"
                ))
            }
        }
        _ => Err("broker serve: state root must be an existing 0700 directory".to_string()),
    }
}

/// Ports `checkBrokerServeSocketForUID`: the socket path must not
/// exist yet and its parent must be an existing uid-owned directory
/// that is not world-writable.
pub(crate) fn check_broker_serve_socket_for_uid(path: &str, uid: u32) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    match std::fs::symlink_metadata(path) {
        Ok(_) => {
            return Err(
                "broker serve: socket path already exists (remove the stale socket first)"
                    .to_string(),
            );
        }
        Err(err) if err.kind() != std::io::ErrorKind::NotFound => {
            return Err("broker serve: socket path is not usable".to_string());
        }
        Err(_) => {}
    }
    let parent = Path::new(path).parent().unwrap_or_else(|| Path::new("/"));
    match std::fs::symlink_metadata(parent) {
        Ok(meta) if meta.is_dir() && meta.mode() & 0o002 == 0 => {
            if meta.uid() == uid {
                Ok(())
            } else {
                Err(format!(
                    "broker serve: socket parent must be owned by uid {uid}"
                ))
            }
        }
        _ => Err(
            "broker serve: socket parent must be an existing directory that is not world-writable"
                .to_string(),
        ),
    }
}

/// `central broker serve` — the composition-root entry point,
/// upstream `runBrokerServe`. Arg/path checks run verbatim; the real
/// `broker.NewService` is T9 work and fails closed in its slot.
pub(crate) fn run_broker_serve(args: &[String], stderr: &mut impl Write) -> u8 {
    let cfg = match parse_broker_serve_args(args) {
        Ok(cfg) => cfg,
        Err(err) => {
            let _ = writeln!(stderr, "broker serve: {err}");
            return ExitClass::Terminal.code();
        }
    };
    if let Err(err) = check_broker_serve_state_root_for_uid(&cfg.state_root, 0) {
        let _ = writeln!(stderr, "broker serve: {err}");
        return ExitClass::Terminal.code();
    }
    if let Err(err) = check_broker_serve_socket_for_uid(&cfg.socket_path, 0) {
        let _ = writeln!(stderr, "broker serve: {err}");
        return ExitClass::Terminal.code();
    }
    let _ = writeln!(
        stderr,
        "broker serve: new service: broker service is not implemented in this slice"
    );
    ExitClass::Terminal.code()
}

// -- `central attest` ---------------------------------------------------

/// Attest failure classes — upstream `errAttestUsage` wraps vs a
/// generic failure (`attestDispatch` exits 2 vs 7).
enum AttestError {
    Usage(String),
    Failed(String),
}

/// `central attest` — ports `attestDispatch`. No privilege gate
/// upstream; `keygen` writes only the one file `--out` names. The key
/// generation itself is deferred so the skeleton fails closed.
pub(crate) fn run_attest(args: &[String], stdout: &mut impl Write, stderr: &mut impl Write) -> u8 {
    if args.is_empty() {
        let _ = writeln!(stderr, "usage: central attest keygen ...");
        return ExitClass::Usage.code();
    }
    let result = match args[0].as_str() {
        "keygen" => attest_keygen(&args[1..], stdout, stderr),
        other => {
            let _ = writeln!(stderr, "attest: unknown subcommand {other:?}");
            return ExitClass::Usage.code();
        }
    };
    match result {
        Ok(()) => ExitClass::Success.code(),
        Err(AttestError::Usage(msg)) => {
            let _ = writeln!(stderr, "attest: usage: {msg}");
            ExitClass::Usage.code()
        }
        Err(AttestError::Failed(msg)) => {
            let _ = writeln!(stderr, "attest: {msg}");
            ExitClass::Denied.code()
        }
    }
}

fn attest_keygen(
    args: &[String],
    _stdout: &mut impl Write,
    _stderr: &mut impl Write,
) -> Result<(), AttestError> {
    let (flags, _positionals) = parse_go_flags(
        args,
        &[
            ("key-id", GoFlag::Value),
            ("out", GoFlag::Value),
            ("label", GoFlag::Value),
        ],
    )
    .map_err(AttestError::Usage)?;
    if flags.get("key-id").is_none_or(String::is_empty)
        || flags.get("out").is_none_or(String::is_empty)
    {
        return Err(AttestError::Usage(
            "--key-id and --out are required".to_string(),
        ));
    }
    Err(AttestError::Failed(
        "attestation key generation is not implemented in this slice".to_string(),
    ))
}

// -- Go `flag`-package scan ---------------------------------------------

/// One Go `flag` spec: a string flag consumes the next token or an
/// `=value`, a bool takes only `=value`, and `Duration` parses like
/// `time.ParseDuration` (the shape `fs.Func` gives upstream's
/// `--ttl`).
#[derive(Clone, Copy)]
pub(crate) enum GoFlag {
    Value,
    Bool,
    Duration,
}

/// Minimal Go `flag.Parse` port used by `grant`/`attest` grammar:
/// scanning stops at the first non-flag token or `--`; `-` alone is a
/// positional; at most two leading dashes; bool flags accept only
/// `=v`. Error strings mirror Go's messages.
pub(crate) fn parse_go_flags(
    tokens: &[String],
    specs: &[(&str, GoFlag)],
) -> Result<(BTreeMap<String, String>, Vec<String>), String> {
    let mut values = BTreeMap::new();
    let mut positionals = Vec::new();
    let mut index = 0usize;
    while index < tokens.len() {
        let token = &tokens[index];
        if token == "--" {
            positionals.extend_from_slice(&tokens[index + 1..]);
            return Ok((values, positionals));
        }
        if !token.starts_with('-') || token == "-" {
            positionals.extend_from_slice(&tokens[index..]);
            return Ok((values, positionals));
        }
        let name_and_value = token.trim_start_matches('-').to_string();
        if token.len() - name_and_value.len() > 2 {
            return Err(format!("bad flag syntax: {token}"));
        }
        if name_and_value.is_empty()
            || name_and_value.starts_with('-')
            || name_and_value.starts_with('=')
        {
            return Err(format!("bad flag syntax: {token}"));
        }
        let (name, inline_value) = match name_and_value.split_once('=') {
            Some((n, v)) => (n.to_string(), Some(v.to_string())),
            None => (name_and_value, None),
        };
        let Some((_, spec)) = specs.iter().find(|(n, _)| *n == name) else {
            return Err(format!("flag provided but not defined: -{name}"));
        };
        match spec {
            GoFlag::Bool => {
                let value = match inline_value {
                    None => "true".to_string(),
                    Some(v) => match v.as_str() {
                        "1" | "t" | "T" | "TRUE" | "true" | "True" => "true".to_string(),
                        "0" | "f" | "F" | "FALSE" | "false" | "False" => "false".to_string(),
                        _ => {
                            return Err(format!(
                                "invalid boolean value {v:?} for -{name}: parse error"
                            ));
                        }
                    },
                };
                values.insert(name, value);
            }
            GoFlag::Value | GoFlag::Duration => {
                let value = match inline_value {
                    Some(v) => v,
                    None => {
                        index += 1;
                        if index >= tokens.len() {
                            return Err(format!("flag needs an argument: -{name}"));
                        }
                        tokens[index].clone()
                    }
                };
                if matches!(spec, GoFlag::Duration) && parse_go_duration(&value).is_none() {
                    return Err(format!(
                        "invalid value {value:?} for flag -{name}: time: invalid duration {value:?}"
                    ));
                }
                values.insert(name, value);
            }
        }
        index += 1;
    }
    Ok((values, positionals))
}

/// Go `time.ParseDuration` validity port: `[+-]` then one or more
/// `number+unit` runs (`ns|us|µs|μs|ms|s|m|h`); bare `0` is valid.
/// Returns nanoseconds so callers can compare ranges.
pub(crate) fn parse_go_duration(raw: &str) -> Option<i64> {
    let mut rest = raw;
    let neg = rest.starts_with('-');
    if neg || rest.starts_with('+') {
        rest = &rest[1..];
    }
    if rest == "0" {
        return Some(0);
    }
    if rest.is_empty() {
        return None;
    }
    let mut total: i64 = 0;
    while !rest.is_empty() {
        let digits_end = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(rest.len());
        if digits_end == 0 || rest[..digits_end].matches('.').count() > 1 {
            return None;
        }
        let magnitude: f64 = rest[..digits_end].parse().ok()?;
        rest = &rest[digits_end..];
        // Multi-byte units first (µs/μs are 3-byte sequences); "ms"
        // must win over 'm'/'s' single-letter matches.
        let (unit_len, nanos) = if rest.starts_with("ns") {
            (2, 1i64)
        } else if rest.starts_with("µs") || rest.starts_with("μs") {
            (3, 1_000i64)
        } else if rest.starts_with("us") {
            (2, 1_000i64)
        } else if rest.starts_with("ms") {
            (2, 1_000_000i64)
        } else if rest.starts_with('s') {
            (1, 1_000_000_000i64)
        } else if rest.starts_with('m') {
            (1, 60_000_000_000i64)
        } else if rest.starts_with('h') {
            (1, 3_600_000_000_000i64)
        } else {
            return None;
        };
        rest = &rest[unit_len..];
        let scaled = magnitude * nanos as f64;
        if !scaled.is_finite() || scaled > i64::MAX as f64 {
            return None;
        }
        total = total.checked_add(scaled as i64)?;
    }
    Some(if neg { -total } else { total })
}

/// Go `filepath.Clean` port (lexical): collapses `/` runs, drops `.`,
/// resolves `..` (clamped at root for absolute paths), and never keeps
/// a trailing slash.
pub(crate) fn go_clean(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let rooted = path.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for elem in path.split('/') {
        match elem {
            "" | "." => {}
            ".." => match out.last() {
                Some(&"..") => out.push(".."),
                Some(_) => {
                    out.pop();
                }
                None if !rooted => out.push(".."),
                None => {}
            },
            e => out.push(e),
        }
    }
    let joined = out.join("/");
    let result = if rooted { format!("/{joined}") } else { joined };
    if result.is_empty() {
        if rooted {
            "/".to_string()
        } else {
            ".".to_string()
        }
    } else {
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    // -- resolveMode ports (upstream modes_test.go tables) -----------

    #[test]
    fn daemon_flags_win_over_positional_grammar() {
        for (args, want) in [
            (vec!["--helper"], Mode::Helper),
            (vec!["local", "up", "--helper"], Mode::Helper),
            (vec!["--broker"], Mode::Broker),
            (vec!["local", "up", "--broker"], Mode::Broker),
            (vec!["--sandbox-launcher"], Mode::SandboxLauncher),
            (vec!["x", "--sandbox-launcher"], Mode::SandboxLauncher),
            (vec!["--archguard"], Mode::ArchGuard),
            (vec!["serve", "--archguard"], Mode::ArchGuard),
            (vec!["--slice-a-verify"], Mode::Verify),
            (vec!["local", "init", "--slice-a-verify"], Mode::Verify),
        ] {
            assert_eq!(resolve_mode(&argv(&args)), want, "args {args:?}");
        }
    }

    #[test]
    fn verb_grammar_resolves_exactly() {
        for (args, want) in [
            (vec!["local", "doctor"], Mode::Doctor),
            (
                vec!["local", "doctor", "--host-prerequisites"],
                Mode::Doctor,
            ),
            (vec!["local", "init"], Mode::Init),
            (vec!["local", "init", "--status"], Mode::Init),
            (vec!["migrate"], Mode::Migrate),
            (vec!["migrate", "up"], Mode::Migrate),
            (vec!["migrate", "bogus"], Mode::Migrate),
            (vec!["serve"], Mode::Serve),
            (vec!["serve", "anything"], Mode::Serve),
            (vec!["broker", "serve"], Mode::BrokerServe),
            (vec!["broker"], Mode::Deferred),
            (vec!["broker", "bogus"], Mode::Deferred),
            (vec!["bootstrap", "show"], Mode::Bootstrap),
            (vec!["bootstrap"], Mode::Deferred),
            (vec!["grant"], Mode::Grant),
            (vec!["grant", "issue", "--kind", "init"], Mode::Grant),
            (vec!["attest"], Mode::Attest),
            (vec!["version"], Mode::Version),
            (vec!["local", "up"], Mode::Deferred),
            (vec!["local", "prepare"], Mode::Deferred),
            (vec!["frobnicate"], Mode::Deferred),
            (vec!["helper"], Mode::Deferred),
        ] {
            assert_eq!(resolve_mode(&argv(&args)), want, "args {args:?}");
        }
        assert_eq!(resolve_mode(&argv(&[])), Mode::Unknown);
    }

    // -- checkPrivilege ports -----------------------------------------

    #[test]
    fn verify_and_grant_modes_require_root() {
        for mode in [
            Mode::Helper,
            Mode::Broker,
            Mode::SandboxLauncher,
            Mode::Verify,
            Mode::Grant,
            Mode::BrokerServe,
        ] {
            let err = check_privilege_for_uid(mode, 1000).unwrap_err();
            assert_eq!(err, "mode requires root (UID 0), got UID 1000", "{mode:?}");
            assert!(check_privilege_for_uid(mode, 0).is_ok(), "{mode:?}");
        }
    }

    #[test]
    fn operator_modes_reject_root() {
        for mode in [
            Mode::Doctor,
            Mode::Init,
            Mode::ArchGuard,
            Mode::Migrate,
            Mode::Serve,
            Mode::Bootstrap,
            Mode::Deferred,
        ] {
            let err = check_privilege_for_uid(mode, 0).unwrap_err();
            assert_eq!(err, "mode must not run as root (UID 0)", "{mode:?}");
            assert!(check_privilege_for_uid(mode, 1000).is_ok(), "{mode:?}");
        }
    }

    #[test]
    fn unknown_attest_version_carry_no_gate() {
        for mode in [Mode::Unknown, Mode::Attest, Mode::Version] {
            assert!(check_privilege_for_uid(mode, 0).is_ok(), "{mode:?}");
            assert!(check_privilege_for_uid(mode, 1000).is_ok(), "{mode:?}");
        }
    }

    // -- checkSocketActivation ports ----------------------------------

    #[test]
    fn socket_activated_modes_require_listen_fds() {
        for mode in [Mode::Helper, Mode::Broker, Mode::SandboxLauncher] {
            let err = check_socket_activation(mode, None).unwrap_err();
            assert_eq!(
                err, "socket-activated mode requires LISTEN_FDS from systemd",
                "{mode:?}"
            );
            assert!(check_socket_activation(mode, Some("1")).is_ok(), "{mode:?}");
        }
    }

    #[test]
    fn listen_fds_must_parse_positive_when_present() {
        for mode in [Mode::Doctor, Mode::Deferred, Mode::Attest] {
            assert!(check_socket_activation(mode, None).is_ok(), "{mode:?}");
            assert!(check_socket_activation(mode, Some("3")).is_ok(), "{mode:?}");
            let err = check_socket_activation(mode, Some("abc")).unwrap_err();
            assert_eq!(err, "invalid LISTEN_FDS: \"abc\"", "{mode:?}");
            let err = check_socket_activation(mode, Some("0")).unwrap_err();
            assert_eq!(err, "invalid LISTEN_FDS: \"0\"", "{mode:?}");
        }
    }

    // -- helper daemon skeleton ---------------------------------------

    #[test]
    fn helper_genesis_needs_operator_ids_then_fails_closed() {
        let mut stderr = Vec::new();
        let code = helper_daemon(
            true,
            Err("CENTRAL_OPERATOR_UID is not set".into()),
            &mut stderr,
        );
        assert_eq!(code, 6);
        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            "helper: genesis composition: CENTRAL_OPERATOR_UID is not set\n"
        );

        let mut stderr = Vec::new();
        let code = helper_daemon(
            false,
            Err("CENTRAL_OPERATOR_UID is not set".into()),
            &mut stderr,
        );
        assert_eq!(code, 6);
        assert!(
            String::from_utf8(stderr)
                .unwrap()
                .starts_with("helper: composition: CENTRAL_OPERATOR_UID is not set")
        );

        // Composed policy still cannot serve this slice.
        let mut stderr = Vec::new();
        let code = helper_daemon(true, Ok(()), &mut stderr);
        assert_eq!(code, 6);
        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            "helper: genesis composition: helper server is not implemented in this slice\n"
        );
    }

    #[test]
    fn peer_policy_ported_messages() {
        assert_eq!(
            helper_peer_policy(None, Some("1".into())).unwrap_err(),
            "CENTRAL_OPERATOR_UID is not set"
        );
        assert_eq!(
            helper_peer_policy(Some("".into()), Some("1".into())).unwrap_err(),
            "CENTRAL_OPERATOR_UID is not set"
        );
        assert_eq!(
            helper_peer_policy(Some("abc".into()), Some("1".into())).unwrap_err(),
            "CENTRAL_OPERATOR_UID is not a number: \"abc\""
        );
        assert_eq!(
            helper_peer_policy(Some("0".into()), Some("1".into())).unwrap_err(),
            "CENTRAL_OPERATOR_UID must be a valid nonzero uid/gid: \"0\""
        );
        assert!(helper_peer_policy(Some("1".into()), Some("2".into())).is_ok());
    }

    // -- broker / sandbox skeletons ------------------------------------

    #[test]
    fn broker_daemon_fails_closed_at_resolution() {
        let mut stderr = Vec::new();
        let code = run_broker_daemon(&mut stderr);
        assert_eq!(code, 6);
        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            "broker: production instance: production instance authority unavailable\n"
        );
    }

    #[test]
    fn sandbox_daemon_fails_closed_exit_3() {
        let mut stderr = Vec::new();
        let code = run_sandbox_daemon(&mut stderr);
        assert_eq!(code, 3);
        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            "sandbox: sandbox-daemon: not implemented in this slice\n"
        );
    }

    // -- broker serve grammar/checks -----------------------------------

    #[test]
    fn broker_serve_args_port() {
        let cfg =
            parse_broker_serve_args(&argv(&["--state-root", "/a/b", "--socket", "/x/y.sock"]))
                .unwrap();
        assert_eq!(cfg.state_root, "/a/b");
        assert_eq!(cfg.socket_path, "/x/y.sock");

        let cfg =
            parse_broker_serve_args(&argv(&["--state-root=/a/b", "--socket=/x/y.sock"])).unwrap();
        assert_eq!(cfg.state_root, "/a/b");

        for bad in [
            vec![],
            vec!["--state-root", "/a"],
            vec!["--socket", "/a/s"],
            vec!["--state-root"],
            vec!["--state-root", "rel/dir", "--socket", "/x"],
            vec!["--state-root", "/a/", "--socket", "/x"],
            vec!["--state-root", "/a/../b", "--socket", "/x"],
            vec!["--state-root", "", "--socket", "/x"],
            vec!["positional"],
            vec!["--state-root=/a", "--bogus"],
        ] {
            assert_eq!(
                parse_broker_serve_args(&argv(&bad)).unwrap_err(),
                BROKER_SERVE_USAGE,
                "args {bad:?}"
            );
        }
    }

    #[test]
    fn broker_serve_state_root_checks() {
        let dir = std::env::temp_dir().join(format!("central-bsroot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .unwrap();
        let uid = current_uid();
        assert!(check_broker_serve_state_root_for_uid(dir.to_str().unwrap(), uid).is_ok());
        assert_eq!(
            check_broker_serve_state_root_for_uid(dir.to_str().unwrap(), uid + 1).unwrap_err(),
            format!("broker serve: state root must be owned by uid {}", uid + 1)
        );
        assert_eq!(
            check_broker_serve_state_root_for_uid("/nonexistent/central", uid).unwrap_err(),
            "broker serve: state root must be an existing 0700 directory"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn broker_serve_socket_checks() {
        let dir = std::env::temp_dir().join(format!("central-bssock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let uid = current_uid();
        let sock = dir.join("b.sock");
        assert!(check_broker_serve_socket_for_uid(sock.to_str().unwrap(), uid).is_ok());
        std::fs::write(&sock, b"x").unwrap();
        assert_eq!(
            check_broker_serve_socket_for_uid(sock.to_str().unwrap(), uid).unwrap_err(),
            "broker serve: socket path already exists (remove the stale socket first)"
        );
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            check_broker_serve_socket_for_uid("/nonexistent-dir/x.sock", uid).unwrap_err(),
            "broker serve: socket parent must be an existing directory that is not world-writable"
        );
    }

    // -- attest skeleton -----------------------------------------------

    fn attest(args: &[&str]) -> (u8, String, String) {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_attest(&argv(args), &mut out, &mut err);
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    #[test]
    fn attest_usage_and_unknown_subcommand() {
        let (code, _, stderr) = attest(&[]);
        assert_eq!(code, 2);
        assert_eq!(stderr, "usage: central attest keygen ...\n");

        let (code, _, stderr) = attest(&["bogus"]);
        assert_eq!(code, 2);
        assert_eq!(stderr, "attest: unknown subcommand \"bogus\"\n");
    }

    #[test]
    fn attest_keygen_grammar() {
        let (code, _, stderr) = attest(&["keygen"]);
        assert_eq!(code, 2);
        assert_eq!(stderr, "attest: usage: --key-id and --out are required\n");

        let (code, _, stderr) = attest(&["keygen", "--bogus"]);
        assert_eq!(code, 2);
        assert_eq!(
            stderr,
            "attest: usage: flag provided but not defined: -bogus\n"
        );

        // Fully flagged still fails closed — the key generator is not
        // implemented in this slice.
        let (code, stdout, stderr) = attest(&[
            "keygen",
            "--key-id",
            "k1",
            "--out",
            "/tmp/central-attest-test-key",
        ]);
        assert_eq!(code, 7);
        assert_eq!(stdout, "");
        assert_eq!(
            stderr,
            "attest: attestation key generation is not implemented in this slice\n"
        );
    }

    // -- Go flag / duration ports ---------------------------------------

    #[test]
    fn go_flag_scan() {
        let (values, pos) = parse_go_flags(
            &argv(&["--kind", "init", "-replace", "--operation=x", "extra"]),
            &[
                ("kind", GoFlag::Value),
                ("operation", GoFlag::Value),
                ("replace", GoFlag::Bool),
            ],
        )
        .unwrap();
        assert_eq!(values["kind"], "init");
        assert_eq!(values["operation"], "x");
        assert_eq!(values["replace"], "true");
        assert_eq!(pos, vec!["extra"]);

        assert_eq!(
            parse_go_flags(&argv(&["--bogus"]), &[("kind", GoFlag::Value)]).unwrap_err(),
            "flag provided but not defined: -bogus"
        );
        assert_eq!(
            parse_go_flags(&argv(&["--kind"]), &[("kind", GoFlag::Value)]).unwrap_err(),
            "flag needs an argument: -kind"
        );
        // A value flag consumes the next token verbatim — `--operation
        // --kind init` treats `--kind` as the operation value.
        let (values, pos) = parse_go_flags(
            &argv(&["--operation", "--kind", "init"]),
            &[("operation", GoFlag::Value), ("kind", GoFlag::Value)],
        )
        .unwrap();
        assert_eq!(values["operation"], "--kind");
        assert_eq!(pos, vec!["init"]);
        assert_eq!(
            parse_go_flags(&argv(&["---x"]), &[("x", GoFlag::Bool)]).unwrap_err(),
            "bad flag syntax: ---x"
        );
        assert_eq!(
            parse_go_flags(&argv(&["-replace=wat"]), &[("replace", GoFlag::Bool)]).unwrap_err(),
            "invalid boolean value \"wat\" for -replace: parse error"
        );
        // `--` terminates flags.
        let (values, pos) = parse_go_flags(
            &argv(&["--kind", "x", "--", "--bogus"]),
            &[("kind", GoFlag::Value)],
        )
        .unwrap();
        assert_eq!(values["kind"], "x");
        assert_eq!(pos, vec!["--bogus"]);
    }

    #[test]
    fn go_duration_scan() {
        for (raw, want) in [
            ("1h", Some(3_600_000_000_000)),
            ("15m", Some(900_000_000_000)),
            ("1h30m", Some(5_400_000_000_000)),
            ("-5m", Some(-300_000_000_000)),
            ("300ms", Some(300_000_000)),
            ("0", Some(0)),
            ("1.5h", Some(5_400_000_000_000)),
            ("bogus", None),
            ("", None),
            ("5x", None),
            ("1..2h", None),
            ("-0", Some(0)),
        ] {
            assert_eq!(parse_go_duration(raw), want, "raw {raw:?}");
        }
    }

    #[test]
    fn go_clean_port() {
        for (input, want) in [
            ("/a/b", "/a/b"),
            ("/a/b/", "/a/b"),
            ("/a/./b", "/a/b"),
            ("/a/../b", "/b"),
            ("/../b", "/b"),
            ("//a///b//", "/a/b"),
            ("/", "/"),
            ("", "."),
            ("a/../b", "b"),
            ("../b", "../b"),
        ] {
            assert_eq!(go_clean(input), want, "input {input:?}");
        }
    }
}
