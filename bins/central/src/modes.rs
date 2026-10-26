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

use central_foundation::failure::{ExitClass, Failure};
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

/// `central --helper` after the gates — upstream `runHelperDaemon`,
/// now the adapter's real daemon: `LISTEN_FDS` admission, the
/// genesis/instance branch, `helperPeerPolicyFromEnvironment`, and
/// `Serve`/`ServeGenesis` on the activated socket (`fd 3`). The env
/// seam keeps the failure arms testable without systemd.
pub(crate) fn run_helper_daemon(stderr: &mut impl Write) -> u8 {
    // `helperModeFor`: the genesis server only on an absent host —
    // the real classifier the helper will run again inside, not a
    // path shape approximation.
    let (state, _, _) = central_adapter_linux::genesis::GenesisEnv::production().state();
    helper_daemon(
        state == central_adapter_linux::genesis::GenesisState::Absent,
        |key| std::env::var(key).ok(),
        stderr,
    )
}

fn helper_daemon(
    genesis_absent: bool,
    env: impl Fn(&str) -> Option<String>,
    stderr: &mut impl Write,
) -> u8 {
    // `runtimePresentationGuard` — upstream binds the PostgreSQL
    // presentation lease unconditionally; the bin owns the `sqlx`
    // bridge because `central-adapter-linux` deliberately holds none.
    let deps = central_adapter_linux::helper::daemon::HelperRuntimeDeps {
        begin_presentation: Some(Box::new(PgRuntimePresentation)),
        validate_presentation: Some(Box::new(PgRuntimePresentation)),
    };
    central_adapter_linux::helper::daemon::run_helper_daemon(genesis_absent, &env, deps, stderr)
}

/// `runtimePresentationGuard` (upstream `cmd/central/main.go`) — the
/// PostgreSQL presentation lease the helper daemon cannot reach on its
/// own: a dedicated `central_runtime` pool of one per call, exactly
/// like `openDedicatedConn(ctx, connString, "helper_presentation")`.
/// Stateless — the descriptor path resolves per call through the same
/// env the serve composition reads.
struct PgRuntimePresentation;

impl PgRuntimePresentation {
    /// The sync-over-async bridge: a single-use current-thread runtime
    /// opens the one-connection pool and runs the store call —
    /// upstream's dedicated-conn shape kept per call.
    fn with_store<T>(
        f: impl FnOnce(
            central_adapter_postgres::session::PgSessionStore,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<T, Failure>> + Send>,
        >,
    ) -> Result<T, Failure> {
        let dsn = load_runtime_credential_descriptor()?;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| Failure::unavailable("helper_presentation", "tokio runtime"))?;
        rt.block_on(async move {
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(1)
                .min_connections(0)
                .connect(&dsn)
                .await
                .map_err(|_| {
                    Failure::unavailable("helper_presentation", "dedicated runtime conn")
                })?;
            f(central_adapter_postgres::session::PgSessionStore::new(pool)).await
        })
    }
}

/// The kernel's `session_failure` mapping, private here for the same
/// boundary reason: the capability's `Failure` crosses into the
/// helper as a foundation `Failure` (the handler collapses it to
/// `AUTHORITY_DENIED` regardless).
fn session_failure(f: central_session::contract::Failure) -> Failure {
    use central_session::contract::FailureClass;
    let code = f
        .class
        .map(|c| c.as_str())
        .unwrap_or("session_bootstrap_failed");
    match f.class {
        Some(FailureClass::CsrfInvalid | FailureClass::BootstrapInvalid) => {
            Failure::invalid(code, f.reason)
        }
        Some(FailureClass::BootstrapThrottled) => Failure::conflict(code, f.reason),
        Some(FailureClass::SessionInvalidated | FailureClass::AuthorityDenied) => {
            Failure::denied(code, f.reason)
        }
        None => Failure::internal(code, f.reason),
    }
}

impl central_adapter_linux::helper::browser::PresentationLeaseStarterV2 for PgRuntimePresentation {
    /// `BeginPresentation` — the durable lease, converted to the
    /// helper's `PresentationLease` wire shape.
    fn begin_presentation(
        &self,
    ) -> Result<central_adapter_linux::helper::browser::PresentationLease, Failure> {
        use central_session::port::PresentationStore;
        Self::with_store(|store| {
            Box::pin(async move {
                store
                    .begin_presentation()
                    .await
                    .map_err(session_failure)
                    .map(
                        |lease| central_adapter_linux::helper::browser::PresentationLease {
                            generation: lease.generation,
                            // `None` is Go's zero time — the managed
                            // launcher's deadline gate denies epoch-zero.
                            deadline_unix: lease.deadline.map_or(0, |d| d.unix_timestamp()),
                        },
                    )
            })
        })
    }
}

impl central_adapter_linux::helper::browser::PresentationGuard for PgRuntimePresentation {
    /// `ValidatePresentation` — the durable deadline check.
    fn validate_presentation(&self) -> Result<(), Failure> {
        use central_session::port::PresentationStore;
        Self::with_store(|store| {
            Box::pin(async move { store.validate_presentation().await.map_err(session_failure) })
        })
    }
}

/// `loadCredentialDescriptor` — the strict runtime-descriptor read:
/// 0400 regular file owned by the effective uid, one `host:port:db:
/// role:secret` line, fixed `127.0.0.1:55432:central:central_runtime`
/// shape, plaintext-DSN injection refused. The DSN is rebuilt with
/// `url.UserPassword` userinfo escaping, never trusted raw.
fn load_runtime_credential_descriptor() -> Result<String, Failure> {
    fn bad() -> Failure {
        Failure::denied(
            "helper_presentation_credential",
            "invalid runtime credential descriptor",
        )
    }
    let path = std::env::var(central_kernel::serve::ENV_CREDENTIAL_DESCRIPTOR)
        .ok()
        .filter(|v| !v.is_empty())
        .ok_or_else(bad)?;
    let meta = std::fs::symlink_metadata(&path).map_err(|_| bad())?;
    use std::os::unix::fs::MetadataExt;
    if !meta.is_file()
        || meta.mode() & 0o777 != 0o400
        || meta.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(bad());
    }
    let data = std::fs::read(&path).map_err(|_| bad())?;
    if data.is_empty()
        || data.len() > 4096
        || data.iter().filter(|b| **b == b'\n').count() != 1
        || data.contains(&b'\r')
    {
        return Err(bad());
    }
    let line = std::str::from_utf8(&data)
        .map_err(|_| bad())?
        .trim_end_matches('\n');
    if line.contains("://") {
        return Err(Failure::denied(
            "helper_presentation_credential",
            "plaintext runtime DSN is forbidden",
        ));
    }
    let fields: Vec<&str> = line.split(':').collect();
    if fields.len() != 5
        || fields[0] != "127.0.0.1"
        || fields[1] != "55432"
        || fields[2] != "central"
        || fields[3] != "central_runtime"
        || fields[4].is_empty()
    {
        return Err(bad());
    }
    // `url.UserPassword(role, secret)` — Go's userinfo escape set:
    // unreserved + `!$&'()*+,;=` + `:` survive; everything else is
    // %XX (uppercase).
    fn userinfo_escape(s: &str) -> String {
        const ALLOWED: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$&'()*+,;=:";
        let mut out = String::with_capacity(s.len());
        for &b in s.as_bytes() {
            if ALLOWED.contains(&b) {
                out.push(b as char);
            } else {
                out.push_str(&format!("%{b:02X}"));
            }
        }
        out
    }
    Ok(format!(
        "postgres://{}:{}@{}:{}/{}?sslmode=disable",
        userinfo_escape(fields[3]),
        userinfo_escape(fields[4]),
        fields[0],
        fields[1],
        fields[2]
    ))
}

/// `central --broker` after the gates — upstream `runBrokerDaemon`,
/// now the adapter's real composition: `resolveProductionInstance-
/// Composition` → `resolveProductionBrokerRoot` → `NewService` →
/// `LISTEN_FDS` → `Harden` → `Serve` on fd 3. The env seam keeps the
/// `LISTEN_FDS` arm testable without systemd; every earlier arm is
/// the adapter's own fail-closed refusal.
pub(crate) fn run_broker_daemon(stderr: &mut impl Write) -> u8 {
    broker_daemon(|key| std::env::var(key).ok(), stderr)
}

fn broker_daemon(env: impl Fn(&str) -> Option<String>, stderr: &mut impl Write) -> u8 {
    central_adapter_linux::broker::daemon::run_broker_daemon(&env, stderr)
}

/// `central --sandbox-launcher` after the gates — upstream
/// `runSandboxDaemon`: `LISTEN_FDS` admission, then `ServeLauncher`
/// on the activated fd 3. The env seam keeps the admission arm
/// testable without systemd.
pub(crate) fn run_sandbox_daemon(stderr: &mut impl Write) -> u8 {
    sandbox_daemon(|key| std::env::var(key).ok(), stderr)
}

fn sandbox_daemon(env: impl Fn(&str) -> Option<String>, stderr: &mut impl Write) -> u8 {
    central_adapter_linux::sandbox::daemon::run_sandbox_daemon(&env, stderr)
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
/// upstream `runBrokerServe`. Arg/path checks run verbatim, then the
/// adapter composes the identical `Service` the activated daemon
/// uses and serves it on the operator socket until SIGINT/SIGTERM.
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
    central_adapter_linux::broker::daemon::run_broker_serve(
        &cfg.state_root,
        &cfg.socket_path,
        stderr,
    )
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
    stderr: &mut impl Write,
) -> Result<(), AttestError> {
    let (flags, _positionals) = parse_go_flags(
        args,
        "attest keygen",
        &[
            (
                "key-id",
                GoFlag::Value,
                "the lock's attestation_trust key_id this key will be trusted under",
            ),
            (
                "out",
                GoFlag::Value,
                "absolute path to write the key file to",
            ),
            (
                "label",
                GoFlag::Value,
                "a human-readable label carried in the key file, never trusted",
            ),
        ],
        stderr,
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
///
/// Each spec entry is `(name, kind, usage)` — the usage text the
/// FlagSet was declared with upstream. Like `flag.ContinueOnError`,
/// every parse failure is `failf`: the error line followed by the
/// `Usage of <flag_set_name>:` defaults block on `err_out`, with the
/// bare message returned for the caller's `usage:` wrapper. `-h` and
/// `--help` print only the usage block and return Go's `ErrHelp`
/// text, `flag: help requested`.
pub(crate) fn parse_go_flags(
    tokens: &[String],
    flag_set_name: &str,
    specs: &[(&str, GoFlag, &str)],
    err_out: &mut impl Write,
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
            return Err(failf(
                err_out,
                flag_set_name,
                specs,
                format!("bad flag syntax: {token}"),
            ));
        }
        if name_and_value.is_empty()
            || name_and_value.starts_with('-')
            || name_and_value.starts_with('=')
        {
            return Err(failf(
                err_out,
                flag_set_name,
                specs,
                format!("bad flag syntax: {token}"),
            ));
        }
        let (name, inline_value) = match name_and_value.split_once('=') {
            Some((n, v)) => (n.to_string(), Some(v.to_string())),
            None => (name_and_value, None),
        };
        let Some((_, spec, _)) = specs.iter().find(|(n, _, _)| *n == name) else {
            // Go's special case: an undefined -h/--help prints the
            // usage block (no error line) and returns ErrHelp.
            if name == "help" || name == "h" {
                write_go_flag_usage(err_out, flag_set_name, specs);
                return Err("flag: help requested".to_string());
            }
            return Err(failf(
                err_out,
                flag_set_name,
                specs,
                format!("flag provided but not defined: -{name}"),
            ));
        };
        match spec {
            GoFlag::Bool => {
                let value = match inline_value {
                    None => "true".to_string(),
                    Some(v) => match v.as_str() {
                        "1" | "t" | "T" | "TRUE" | "true" | "True" => "true".to_string(),
                        "0" | "f" | "F" | "FALSE" | "false" | "False" => "false".to_string(),
                        _ => {
                            return Err(failf(
                                err_out,
                                flag_set_name,
                                specs,
                                format!("invalid boolean value {v:?} for -{name}: parse error"),
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
                            return Err(failf(
                                err_out,
                                flag_set_name,
                                specs,
                                format!("flag needs an argument: -{name}"),
                            ));
                        }
                        tokens[index].clone()
                    }
                };
                if matches!(spec, GoFlag::Duration) && parse_go_duration(&value).is_none() {
                    return Err(failf(
                        err_out,
                        flag_set_name,
                        specs,
                        format!(
                            "invalid value {value:?} for flag -{name}: time: invalid duration {value:?}"
                        ),
                    ));
                }
                values.insert(name, value);
            }
        }
        index += 1;
    }
    Ok((values, positionals))
}

/// Go `failf`: the error line then `f.usage()` on the FlagSet output;
/// the message returns so the caller can wrap it (`%w: %v`).
fn failf(
    err_out: &mut impl Write,
    flag_set_name: &str,
    specs: &[(&str, GoFlag, &str)],
    msg: String,
) -> String {
    let _ = writeln!(err_out, "{msg}");
    write_go_flag_usage(err_out, flag_set_name, specs);
    msg
}

/// Go `defaultUsage` + `PrintDefaults`: `Usage of <name>:` then one
/// entry per flag, sorted by name — `  -name <type>` and the usage
/// text on a `    \t`-indented continuation (a single-line `\t` only
/// fits a one-letter flag). `fs.String` prints `string`, `fs.Bool`
/// prints no type name, and `fs.Func` prints `value` — which is what
/// upstream's `--ttl` is. No spec in this port has a non-zero
/// default, so the ` (default …)` suffix never renders.
fn write_go_flag_usage(out: &mut impl Write, flag_set_name: &str, specs: &[(&str, GoFlag, &str)]) {
    let _ = writeln!(out, "Usage of {flag_set_name}:");
    let mut sorted: Vec<&(&str, GoFlag, &str)> = specs.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    for (name, kind, usage) in sorted {
        let type_name = match kind {
            GoFlag::Bool => "",
            GoFlag::Value => "string",
            GoFlag::Duration => "value",
        };
        let mut line = format!("  -{name}");
        if !type_name.is_empty() {
            line.push(' ');
            line.push_str(type_name);
        }
        if line.len() <= 4 {
            line.push('\t');
        } else {
            line.push_str("\n    \t");
        }
        line.push_str(&usage.replace('\n', "\n    \t"));
        let _ = writeln!(out, "{line}");
    }
}

/// Go `time.ParseDuration` validity port: `[+-]` then one or more
/// `number+unit` runs (`ns|us|µs|μs|ms|s|m|h`); bare `0` is valid.
/// Returns nanoseconds so callers can compare ranges.
///
/// A `.` immediately after digits with an empty fraction is legal in
/// Go (`"1.h"` → 1h, verified against go1.26 — the fraction may be
/// empty when the integer part is nonempty), and the f64 scan here
/// accepts it identically.
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

    // -- helper daemon -------------------------------------------------

    /// `runHelperDaemon` at the bin seam: the env closure feeds the
    /// adapter daemon, which owns upstream's `LISTEN_FDS` gate
    /// (exit 3) and the `[genesis] composition:` failures (exit 6).
    #[test]
    fn helper_daemon_env_seam() {
        use std::collections::HashMap;
        let env = |pairs: &[(&str, &str)]| {
            let map: HashMap<String, String> = pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            move |k: &str| map.get(k).cloned()
        };

        // No LISTEN_FDS: exit 3 with upstream's `no socket fd` line.
        let mut stderr = Vec::new();
        assert_eq!(helper_daemon(true, env(&[]), &mut stderr), 3);
        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            "helper: no socket fd (LISTEN_FDS=\"\")\n"
        );

        // Activated but unprovisioned: exit 6 on each branch name.
        let mut stderr = Vec::new();
        assert_eq!(
            helper_daemon(true, env(&[("LISTEN_FDS", "1")]), &mut stderr),
            6
        );
        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            "helper: genesis composition: operator UID policy is not provisioned\n"
        );
        let mut stderr = Vec::new();
        assert_eq!(
            helper_daemon(false, env(&[("LISTEN_FDS", "1")]), &mut stderr),
            6
        );
        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            "helper: composition: operator UID policy is not provisioned\n"
        );
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

    /// `runSandboxDaemon` at the bin seam: the env closure feeds the
    /// adapter daemon, which owns upstream's `LISTEN_FDS` gate —
    /// `strconv.Atoi` failing (absent or malformed) prints `no socket
    /// fd`, exit 3; a present-but-unclaimed fd 3 fails the same way.
    #[test]
    fn sandbox_daemon_env_seam() {
        use std::collections::HashMap;
        let env = |pairs: &[(&str, &str)]| {
            let map: HashMap<String, String> = pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            move |k: &str| map.get(k).cloned()
        };

        // Absent: upstream's `Atoi` failure arm, verbatim line.
        let mut stderr = Vec::new();
        assert_eq!(sandbox_daemon(env(&[]), &mut stderr), 3);
        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            "sandbox: no socket fd (LISTEN_FDS=\"\")\n"
        );

        // Malformed: same arm with the raw value echoed.
        let mut stderr = Vec::new();
        assert_eq!(sandbox_daemon(env(&[("LISTEN_FDS", "x")]), &mut stderr), 3);
        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            "sandbox: no socket fd (LISTEN_FDS=\"x\")\n"
        );

        // Present LISTEN_FDS reaches `socket_activation_fd(0)`, which
        // CLAIMS fd 3 as an `OwnedFd` and closes it on the way out —
        // in a shared test process that steals whatever fd 3 a
        // parallel test happens to hold. The arm only runs when fd 3
        // can be made a socket this test owns: `into_raw_fd` hands the
        // daemon a legitimate claim, `serve_launcher` fails accept on
        // a connected (non-listening) socket, and the only descriptor
        // destroyed is the sacrificial one. When another thread holds
        // fd 3 the arm is skipped — there is no safe way to take it.
        use std::os::fd::{AsRawFd as _, IntoRawFd as _};
        use std::os::unix::net::UnixStream;
        let mut held = Vec::new();
        let mut sacrificial = None;
        while sacrificial.is_none() && held.len() < 64 {
            let (a, b) = UnixStream::pair().unwrap();
            held.push(b);
            if a.as_raw_fd() == 3 {
                sacrificial = Some(a);
            } else {
                held.push(a);
            }
        }
        if let Some(fd3) = sacrificial {
            let raw = fd3.into_raw_fd();
            debug_assert_eq!(raw, 3, "the loop watched it land on fd 3");
            let mut stderr = Vec::new();
            assert_eq!(sandbox_daemon(env(&[("LISTEN_FDS", "1")]), &mut stderr), 3);
            assert!(
                String::from_utf8(stderr).unwrap().starts_with("sandbox: "),
                "a failure line, never silence"
            );
        }
        drop(held);
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

        // Go `flag.ContinueOnError` writes the failf line plus the
        // `Usage of attest keygen:` defaults block before the
        // dispatcher's `attest: usage:` line.
        let (code, _, stderr) = attest(&["keygen", "--bogus"]);
        assert_eq!(code, 2);
        assert_eq!(
            stderr,
            concat!(
                "flag provided but not defined: -bogus\n",
                "Usage of attest keygen:\n",
                "  -key-id string\n",
                "    \tthe lock's attestation_trust key_id this key will be trusted under\n",
                "  -label string\n",
                "    \ta human-readable label carried in the key file, never trusted\n",
                "  -out string\n",
                "    \tabsolute path to write the key file to\n",
                "attest: usage: flag provided but not defined: -bogus\n",
            )
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

    const SCAN_SPECS: &[(&str, GoFlag, &str)] = &[
        ("kind", GoFlag::Value, "ceremony kind: lifecycle, prepare"),
        ("operation", GoFlag::Value, "exact operation id"),
        (
            "ttl",
            GoFlag::Duration,
            "how long the grant stays spendable",
        ),
        ("replace", GoFlag::Bool, "revoke the pending init grant"),
    ];

    const SCAN_USAGE: &str = concat!(
        "Usage of grant issue:\n",
        "  -kind string\n",
        "    \tceremony kind: lifecycle, prepare\n",
        "  -operation string\n",
        "    \texact operation id\n",
        "  -replace\n",
        "    \trevoke the pending init grant\n",
        "  -ttl value\n",
        "    \thow long the grant stays spendable\n",
    );

    type ScanResult = Result<(BTreeMap<String, String>, Vec<String>), String>;

    fn scan(tokens: &[&str]) -> (ScanResult, String) {
        let mut errbuf = Vec::new();
        let result = parse_go_flags(&argv(tokens), "grant issue", SCAN_SPECS, &mut errbuf);
        (result, String::from_utf8(errbuf).unwrap())
    }

    #[test]
    fn go_flag_scan() {
        let (result, errout) = scan(&["--kind", "init", "-replace", "--operation=x", "extra"]);
        let (values, pos) = result.unwrap();
        assert_eq!(errout, "");
        assert_eq!(values["kind"], "init");
        assert_eq!(values["operation"], "x");
        assert_eq!(values["replace"], "true");
        assert_eq!(pos, vec!["extra"]);

        // A value flag consumes the next token verbatim — `--operation
        // --kind init` treats `--kind` as the operation value.
        let (result, _) = scan(&["--operation", "--kind", "init"]);
        let (values, pos) = result.unwrap();
        assert_eq!(values["operation"], "--kind");
        assert_eq!(pos, vec!["init"]);

        // `--` terminates flags.
        let (result, _) = scan(&["--kind", "x", "--", "--bogus"]);
        let (values, pos) = result.unwrap();
        assert_eq!(values["kind"], "x");
        assert_eq!(pos, vec!["--bogus"]);
    }

    #[test]
    fn go_flag_failf_writes_error_then_usage_block() {
        // failf prints the error line, then `Usage of <ctx>:` plus
        // the sorted PrintDefaults entries, and returns the bare
        // message for the caller's `usage:` wrapper.
        let (result, errout) = scan(&["--bogus"]);
        assert_eq!(result.unwrap_err(), "flag provided but not defined: -bogus");
        assert_eq!(
            errout,
            format!("flag provided but not defined: -bogus\n{SCAN_USAGE}")
        );

        let (result, errout) = scan(&["--kind"]);
        assert_eq!(result.unwrap_err(), "flag needs an argument: -kind");
        assert_eq!(
            errout,
            format!("flag needs an argument: -kind\n{SCAN_USAGE}")
        );

        let (result, errout) = scan(&["---x"]);
        assert_eq!(result.unwrap_err(), "bad flag syntax: ---x");
        assert_eq!(errout, format!("bad flag syntax: ---x\n{SCAN_USAGE}"));

        let (result, errout) = scan(&["-replace=wat"]);
        assert_eq!(
            result.unwrap_err(),
            "invalid boolean value \"wat\" for -replace: parse error"
        );
        assert_eq!(
            errout,
            format!("invalid boolean value \"wat\" for -replace: parse error\n{SCAN_USAGE}")
        );

        let (result, errout) = scan(&["--ttl", "bogus"]);
        assert_eq!(
            result.unwrap_err(),
            "invalid value \"bogus\" for flag -ttl: time: invalid duration \"bogus\""
        );
        assert_eq!(
            errout,
            format!(
                "invalid value \"bogus\" for flag -ttl: time: invalid duration \"bogus\"\n{SCAN_USAGE}"
            )
        );
    }

    #[test]
    fn go_flag_help_prints_usage_only() {
        // `-h`/`--help` when undefined: Go prints the usage block
        // (no error line) and returns ErrHelp's text.
        for flag in ["-h", "--help"] {
            let (result, errout) = scan(&[flag]);
            assert_eq!(result.unwrap_err(), "flag: help requested", "flag {flag}");
            assert_eq!(errout, SCAN_USAGE, "flag {flag}");
        }
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
            // Go accepts a bare `.` after digits (go1.26 verifies
            // `time.ParseDuration("1.h") == 1h`); the f64 scan matches.
            ("1.h", Some(3_600_000_000_000)),
            (".5h", Some(1_800_000_000_000)),
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
