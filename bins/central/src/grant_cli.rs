//! `central grant` — the root-only grant surface skeleton. Ports
//! `cmd/central/grant_cli.go`'s dispatch shape (`runGrant` →
//! `resolveGrantEnvironment` → `grantDispatch`) with closed-failure
//! bodies; the real ceremony/lock/store machinery is R5 task 8.
//!
//! Environment resolution runs before dispatch exactly like upstream:
//! without a resolvable production instance every verb fails at
//! `grant: production instance authority unavailable` (exit 6) —
//! except `grant issue --kind init`, which dispatches on the
//! composition-less pre-instance env and gates on the genesis state
//! itself.

use std::io::Write;

use central_foundation::failure::ExitClass;

use crate::modes;

/// The recognized `--kind` values — upstream `helper.ParseGrantKind`
/// (the flag help omits `maintenance_apply`; the parser accepts it).
const GRANT_KINDS: &[&str] = &[
    "lifecycle",
    "prepare",
    "migration_reset",
    "restore_apply",
    "restore_abandon",
    "wipe",
    "backup_export",
    "backup_import",
    "backup_delete",
    "backup_prune",
    "security_rescue",
    "maintenance_apply",
    "init",
];

/// The recognized `grant mode` values — upstream
/// `helper.ParseCeremonyMode`.
const CEREMONY_MODES: &[&str] = &["physical_tty", "grant"];

/// The resolved env a dispatch acts on — upstream `grantEnvironment`.
/// `Production` carries the installed instance's composition (T8);
/// `PreInstance` is the composition-less fallback only `issue --kind
/// init` may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GrantEnv {
    /// Constructed once `production_grant_environment` can resolve a
    /// real instance (T8); today only the dispatch tests build it.
    #[cfg_attr(not(test), allow(dead_code))]
    Production,
    PreInstance,
}

/// Grant failure classes — upstream `errGrantUsage` (exit 2), the
/// refusal family `errGrantStateRefusal`/`ErrInitGrantPending`/
/// `ErrGrantStoreBusy` (exit 6), and everything else (exit 7).
enum GrantError {
    Usage(String),
    StateRefusal(String),
    Other(String),
}

impl GrantError {
    fn exit_code(&self) -> u8 {
        match self {
            GrantError::Usage(_) => ExitClass::Usage.code(),
            GrantError::StateRefusal(_) => ExitClass::Terminal.code(),
            GrantError::Other(_) => ExitClass::Denied.code(),
        }
    }

    fn message(&self) -> String {
        match self {
            GrantError::Usage(msg) => format!("usage: {msg}"),
            GrantError::StateRefusal(msg) | GrantError::Other(msg) => msg.clone(),
        }
    }
}

/// `central grant ...` — ports `runGrant`. `args` are the tokens after
/// `grant` (upstream `os.Args[2:]`).
pub(crate) fn grant(args: &[String], stdout: &mut impl Write, stderr: &mut impl Write) -> u8 {
    match resolve_grant_environment(args) {
        Ok(env) => grant_dispatch(&env, args, stdout, stderr),
        Err(msg) => {
            let _ = writeln!(stderr, "grant: {msg}");
            ExitClass::Terminal.code()
        }
    }
}

/// Ports `resolveGrantEnvironment`: production composition first; on
/// failure only `issue --kind init` may fall back to the
/// composition-less env (it reads the genesis roots, never the
/// composition). Every other verb keeps the resolution error.
///
/// `production_grant_environment` is the `resolveProductionInstanceComposition`
/// slot — the instance composition loader is `central-infra` work
/// (T13), so it always fails with upstream's no-instance error text.
fn resolve_grant_environment(args: &[String]) -> Result<GrantEnv, String> {
    match production_grant_environment() {
        Ok(env) => Ok(env),
        Err(msg) => {
            if pre_instance_issue_kind(args).as_deref() == Some("init") {
                Ok(GrantEnv::PreInstance)
            } else {
                Err(msg)
            }
        }
    }
}

fn production_grant_environment() -> Result<GrantEnv, String> {
    Err("production instance authority unavailable".to_string())
}

/// Ports `preInstanceIssueKind`: parses `issue`'s flags with the same
/// grammar `grantIssue` uses so a `--kind`-looking flag *value* can
/// never misroute (`--operation --kind init` parses `--kind` as the
/// operation value). Any parse failure is "not an init issuance".
fn pre_instance_issue_kind(args: &[String]) -> Option<String> {
    if args.first().map(String::as_str) != Some("issue") {
        return None;
    }
    parse_grant_issue_flags(&args[1..]).ok().map(|f| f.kind)
}

/// Ports `grantDispatch`: usage/unknown-subcommand at exit 2, the
/// refusal family at exit 6, everything else at exit 7 — all plain
/// stderr text, never an envelope.
fn grant_dispatch(
    env: &GrantEnv,
    args: &[String],
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> u8 {
    if args.is_empty() {
        let _ = writeln!(stderr, "usage: central grant issue|mode|list ...");
        return ExitClass::Usage.code();
    }
    let result = match args[0].as_str() {
        "issue" => grant_issue(env, &args[1..], stdout),
        "mode" => grant_mode(env, &args[1..]),
        "list" => grant_list(env, stdout),
        other => {
            let _ = writeln!(stderr, "grant: unknown subcommand {other:?}");
            return ExitClass::Usage.code();
        }
    };
    match result {
        Ok(()) => ExitClass::Success.code(),
        Err(err) => {
            let _ = writeln!(stderr, "grant: {}", err.message());
            err.exit_code()
        }
    }
}

/// `grant issue` flags — upstream `grantIssueFlags`: `--kind`,
/// `--operation`, `--ttl` (Go duration), `--replace` (bool).
struct GrantIssueFlags {
    kind: String,
    operation: String,
    ttl_ns: Option<i64>,
    replace: bool,
}

fn parse_grant_issue_flags(args: &[String]) -> Result<GrantIssueFlags, String> {
    // Upstream ignores leftover positionals — `fs.Parse` leaves them
    // in `fs.Args()` and `grantIssue` never inspects it.
    let (values, _positionals) = modes::parse_go_flags(
        args,
        &[
            ("kind", modes::GoFlag::Value),
            ("operation", modes::GoFlag::Value),
            ("ttl", modes::GoFlag::Duration),
            ("replace", modes::GoFlag::Bool),
        ],
    )?;
    Ok(GrantIssueFlags {
        kind: values.get("kind").cloned().unwrap_or_default(),
        operation: values.get("operation").cloned().unwrap_or_default(),
        ttl_ns: values
            .get("ttl")
            .and_then(|raw| modes::parse_go_duration(raw)),
        replace: values.get("replace").is_some_and(|v| v == "true"),
    })
}

/// Ports `grantIssue` up to the points that need real machinery.
/// Flag-parse failures are `usage:` (exit 2); a `--kind` the registry
/// does not know is usage too. `init` routes to the genesis-gated
/// issuance; every other kind needs the instance ceremony state and
/// grant store — not implemented until T8, so it fails closed at
/// exit 7 like upstream's generic command errors.
fn grant_issue(
    env: &GrantEnv,
    args: &[String],
    _stdout: &mut impl Write,
) -> Result<(), GrantError> {
    let flags = parse_grant_issue_flags(args).map_err(GrantError::Usage)?;
    // Upstream ParseGrantKind trims before matching and quotes the
    // untrimmed raw value in the error.
    if !GRANT_KINDS.contains(&flags.kind.trim()) {
        return Err(GrantError::Usage(format!(
            "grant: unknown kind {:?}",
            flags.kind
        )));
    }
    if flags.kind.trim() == "init" {
        return grant_issue_init(env, &flags);
    }
    if flags.replace {
        return Err(GrantError::Other(
            "grant: --replace is init-only".to_string(),
        ));
    }
    // Upstream reads the ceremony mode and the grant store from the
    // resolved composition — neither exists until T8.
    Err(GrantError::Other(
        "grant issuance is not implemented in this slice".to_string(),
    ))
}

/// Ports `grantIssueInit`: `--operation` is refused (plain error —
/// exit 7), `--ttl` must sit in `(0, 15m]`, and a non-absent genesis
/// state is the `refused by host state` class (exit 6). Past the
/// gate the genesis grant store is T8 work — the skeleton fails
/// closed rather than minting or mutating anything.
fn grant_issue_init(env: &GrantEnv, flags: &GrantIssueFlags) -> Result<(), GrantError> {
    let _ = env;
    if !flags.operation.is_empty() {
        return Err(GrantError::Other(
            "grant: --operation is refused for --kind init".to_string(),
        ));
    }
    // helper.InitGrantTTL = 15m; unset means the default is used.
    let ttl = flags.ttl_ns.unwrap_or(15 * 60 * 1_000_000_000);
    if ttl <= 0 || ttl > 15 * 60 * 1_000_000_000 {
        return Err(GrantError::Other(format!(
            "grant: init ttl {} is outside (0, 15m]",
            format_go_duration(ttl)
        )));
    }
    match probe_genesis_state() {
        GenesisProbe::Absent => Err(GrantError::Other(
            "init grant issuance is not implemented in this slice".to_string(),
        )),
        state => Err(GrantError::StateRefusal(format!(
            "cannot issue an init grant on a {state} host: refused by host state"
        ))),
    }
}

/// Light stand-in for genesis `state()`: absent when both instance
/// roots are missing or empty; broken when either exists but cannot
/// be read; present otherwise. Full ownership/mode classification is
/// T8's real `genesisEnv.state`.
enum GenesisProbe {
    Absent,
    Present,
    Broken,
}

impl std::fmt::Display for GenesisProbe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GenesisProbe::Absent => f.write_str("absent"),
            GenesisProbe::Present => f.write_str("present"),
            GenesisProbe::Broken => f.write_str("broken"),
        }
    }
}

fn probe_genesis_state() -> GenesisProbe {
    let mut saw_entry = false;
    for root in [
        "/var/lib/central-state/v1/instances",
        "/var/lib/central-protected/v1/instances",
    ] {
        match std::fs::read_dir(root) {
            Ok(mut entries) => {
                if entries.next().is_some() {
                    saw_entry = true;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return GenesisProbe::Broken,
        }
    }
    if saw_entry {
        GenesisProbe::Present
    } else {
        GenesisProbe::Absent
    }
}

/// Ports `grantMode`: exactly one `physical_tty|grant` argument —
/// everything else is usage. The real mode write + store-dir creation
/// is T8; the skeleton fails closed.
fn grant_mode(env: &GrantEnv, args: &[String]) -> Result<(), GrantError> {
    let _ = env;
    if args.len() != 1 {
        return Err(GrantError::Usage(
            "central grant mode <physical_tty|grant>".to_string(),
        ));
    }
    // Upstream ParseCeremonyMode trims before matching.
    if !CEREMONY_MODES.contains(&args[0].trim()) {
        return Err(GrantError::Usage(format!(
            "ceremony: unknown mode {:?}",
            args[0]
        )));
    }
    Err(GrantError::Other(
        "ceremony mode transitions are not implemented in this slice".to_string(),
    ))
}

/// Ports `grantList`'s shape: it needs the grant store — T8.
fn grant_list(env: &GrantEnv, _stdout: &mut impl Write) -> Result<(), GrantError> {
    let _ = env;
    Err(GrantError::Other(
        "grant listing is not implemented in this slice".to_string(),
    ))
}

/// Go `time.Duration.String()` — the `%s` rendering upstream puts in
/// the ttl-range error: `1h30m0s` for whole seconds at scale, a
/// fractional-seconds tail, and the largest even unit below one
/// second.
fn format_go_duration(ns: i64) -> String {
    if ns == 0 {
        return "0s".to_string();
    }
    let mut out = String::from(if ns < 0 { "-" } else { "" });
    let mut n = ns.unsigned_abs();
    let hours = n / 3_600_000_000_000;
    n %= 3_600_000_000_000;
    let minutes = n / 60_000_000_000;
    n %= 60_000_000_000;
    let seconds = n / 1_000_000_000;
    n %= 1_000_000_000;
    // The fractional-seconds tail Go renders as `.ddd` (trailing
    // zeros trimmed).
    let frac = |rest: u64| -> String {
        if rest == 0 {
            return String::new();
        }
        let mut digits = format!("{rest:09}");
        while digits.ends_with('0') {
            digits.pop();
        }
        format!(".{digits}")
    };
    if hours > 0 {
        out += &format!("{hours}h{minutes}m{seconds}{}s", frac(n));
    } else if minutes > 0 {
        out += &format!("{minutes}m{seconds}{}s", frac(n));
    } else if seconds > 0 {
        out += &format!("{seconds}{}s", frac(n));
    } else if n.is_multiple_of(1_000_000) {
        out += &format!("{}ms", n / 1_000_000);
    } else if n.is_multiple_of(1_000) {
        out += &format!("{}µs", n / 1_000);
    } else {
        out += &format!("{n}ns");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    fn run(args: &[&str]) -> (u8, String, String) {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = grant(&argv(args), &mut out, &mut err);
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    /// Drives `grantDispatch` directly with a chosen env (upstream's
    /// `grantDispatch(env, args)` test seam).
    fn dispatch(env: GrantEnv, args: &[&str]) -> (u8, String, String) {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = grant_dispatch(&env, &argv(args), &mut out, &mut err);
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    // -- resolveGrantEnvironment / runGrant -----------------------------

    #[test]
    fn grant_env_resolution_precedes_dispatch() {
        // No instance resolves: every non-init-issue verb fails at env
        // resolution (exit 6, upstream's resolution error text).
        for args in [
            vec![],
            vec!["bogus"],
            vec!["list"],
            vec!["mode", "grant"],
            vec!["issue", "--kind", "lifecycle"],
            vec!["issue", "--kind=bogus"],
            // `--operation --kind init` parses `--kind` as the
            // operation VALUE — not an init issuance.
            vec!["issue", "--operation", "--kind", "init"],
        ] {
            let (code, _, stderr) = run(&args);
            assert_eq!(code, 6, "args {args:?}");
            assert_eq!(
                stderr, "grant: production instance authority unavailable\n",
                "args {args:?}"
            );
        }
    }

    #[test]
    fn issue_init_reaches_dispatch_on_pre_instance_env() {
        // `issue --kind init` is the one env-resolution fallback; past
        // it the genesis state gates the outcome.
        let (code, _, stderr) = run(&["issue", "--kind", "init"]);
        match probe_genesis_state() {
            GenesisProbe::Absent => {
                assert_eq!(code, 7);
                assert_eq!(
                    stderr,
                    "grant: init grant issuance is not implemented in this slice\n"
                );
            }
            state => {
                assert_eq!(code, 6);
                assert_eq!(
                    stderr,
                    format!(
                        "grant: cannot issue an init grant on a {state} host: refused by host state\n"
                    )
                );
            }
        }
    }

    #[test]
    fn issue_init_flag_refusals_are_plain_errors() {
        // `--operation` with --kind init: upstream's exit-7 refusal.
        let (code, _, stderr) = run(&["issue", "--kind", "init", "--operation", "op-1"]);
        assert_eq!(code, 7);
        assert_eq!(
            stderr,
            "grant: grant: --operation is refused for --kind init\n"
        );

        // Out-of-range ttl: exit 7.
        let (code, _, stderr) = run(&["issue", "--kind", "init", "--ttl", "1h"]);
        assert_eq!(code, 7);
        assert_eq!(
            stderr,
            "grant: grant: init ttl 1h0m0s is outside (0, 15m]\n"
        );
        let (code, _, stderr) = run(&["issue", "--kind", "init", "--ttl", "-1m"]);
        assert_eq!(code, 7);
        assert_eq!(stderr, "grant: grant: init ttl -1m0s is outside (0, 15m]\n");
    }

    #[test]
    fn pre_instance_issue_kind_never_misroutes() {
        for (args, want) in [
            (vec!["issue", "--kind", "init"], Some("init")),
            (vec!["issue", "--kind=init"], Some("init")),
            // `--operation` consumes `--kind` as its value — kind is
            // empty, never the positional `init`.
            (vec!["issue", "--operation", "--kind", "init"], Some("")),
            (vec!["issue", "--ttl", "bogus", "--kind", "init"], None),
            (vec!["issue", "--bogus"], None),
            (vec!["issue"], Some("")),
            (vec!["mode", "grant"], None),
            (vec![], None),
        ] {
            assert_eq!(
                pre_instance_issue_kind(&argv(&args)).as_deref(),
                want,
                "args {args:?}"
            );
        }
    }

    // -- grantDispatch --------------------------------------------------

    #[test]
    fn dispatch_usage_and_unknown_subcommand() {
        for env in [GrantEnv::Production, GrantEnv::PreInstance] {
            let (code, _, stderr) = dispatch(env, &[]);
            assert_eq!(code, 2);
            assert_eq!(stderr, "usage: central grant issue|mode|list ...\n");

            let (code, _, stderr) = dispatch(env, &["bogus"]);
            assert_eq!(code, 2);
            assert_eq!(stderr, "grant: unknown subcommand \"bogus\"\n");
        }
    }

    #[test]
    fn issue_flag_parse_errors_are_usage() {
        for (args, want) in [
            (
                vec!["issue", "--bogus"],
                "grant: usage: flag provided but not defined: -bogus\n",
            ),
            (
                vec!["issue", "--ttl", "bogus"],
                "grant: usage: invalid value \"bogus\" for flag -ttl: time: invalid duration \"bogus\"\n",
            ),
            (
                vec!["issue", "--kind"],
                "grant: usage: flag needs an argument: -kind\n",
            ),
            // Positionals are ignored upstream — `issue positional`
            // fails the empty kind check instead.
            (
                vec!["issue", "positional"],
                "grant: usage: grant: unknown kind \"\"\n",
            ),
            (
                vec!["issue", "--kind", "bogus"],
                "grant: usage: grant: unknown kind \"bogus\"\n",
            ),
            // Missing --kind parses fine but fails the kind check.
            (vec!["issue"], "grant: usage: grant: unknown kind \"\"\n"),
        ] {
            let (code, _, stderr) = dispatch(GrantEnv::Production, &args);
            assert_eq!(code, 2, "args {args:?}");
            assert_eq!(stderr, want, "args {args:?}");
        }
    }

    #[test]
    fn non_init_issue_is_closed_failure() {
        let (code, _, stderr) = dispatch(GrantEnv::Production, &["issue", "--kind", "lifecycle"]);
        assert_eq!(code, 7);
        assert_eq!(
            stderr,
            "grant: grant issuance is not implemented in this slice\n"
        );
        let (code, _, stderr) = dispatch(
            GrantEnv::Production,
            &["issue", "--kind", "lifecycle", "--replace"],
        );
        assert_eq!(code, 7);
        assert_eq!(stderr, "grant: grant: --replace is init-only\n");
    }

    #[test]
    fn mode_grammar_is_closed() {
        let (code, _, stderr) = dispatch(GrantEnv::Production, &["mode"]);
        assert_eq!(code, 2);
        assert_eq!(
            stderr,
            "grant: usage: central grant mode <physical_tty|grant>\n"
        );
        let (code, _, stderr) = dispatch(GrantEnv::Production, &["mode", "bogus"]);
        assert_eq!(code, 2);
        assert_eq!(stderr, "grant: usage: ceremony: unknown mode \"bogus\"\n");
        for mode in ["physical_tty", "grant"] {
            let (code, _, stderr) = dispatch(GrantEnv::Production, &["mode", mode]);
            assert_eq!(code, 7, "mode {mode}");
            assert_eq!(
                stderr,
                "grant: ceremony mode transitions are not implemented in this slice\n"
            );
        }
    }

    #[test]
    fn list_is_closed_failure() {
        let (code, _, stderr) = dispatch(GrantEnv::Production, &["list"]);
        assert_eq!(code, 7);
        assert_eq!(
            stderr,
            "grant: grant listing is not implemented in this slice\n"
        );
    }

    #[test]
    fn go_duration_string_shape() {
        assert_eq!(format_go_duration(3_600_000_000_000), "1h0m0s");
        assert_eq!(format_go_duration(900_000_000_000), "15m0s");
        assert_eq!(format_go_duration(-60_000_000_000), "-1m0s");
        assert_eq!(format_go_duration(30_000_000_000), "30s");
        assert_eq!(format_go_duration(500_000_000), "500ms");
        assert_eq!(format_go_duration(0), "0s");
    }
}
