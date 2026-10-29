//! `central grant` — the root-only grant surface. Ports
//! `cmd/central/grant_cli.go`'s dispatch shape (`runGrant` →
//! `resolveGrantEnvironment` → `grantDispatch`). `issue --kind init`
//! is the real pre-instance issuance upstream's headless flow
//! advertises; the instance-scoped kinds keep the closed-failure
//! bodies — their ceremony/lock/store machinery is R5 task 8.
//!
//! Environment resolution runs before dispatch exactly like upstream:
//! without a resolvable production instance every verb fails at
//! `grant: production instance authority unavailable` (exit 6) —
//! except `grant issue --kind init`, which dispatches on the
//! composition-less pre-instance env and gates on the genesis state
//! itself.

use std::io::Write;
use std::path::Path;

use central_adapter_linux::genesis::GenesisState;
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

/// The resolved env a dispatch acts on — upstream `grantEnvironment`.
/// `Production` carries the installed instance's composition plus the
/// ceremony owner (`ceremonyOwner`: the process's euid/egid — root in
/// production, the test process otherwise); `PreInstance` is the
/// composition-less fallback only `issue --kind init` may use.
#[derive(Debug, Clone)]
pub(crate) enum GrantEnv {
    Production {
        composition: Box<central_adapter_linux::broker::daemon::ProductionInstanceComposition>,
        owner_uid: u32,
        owner_gid: u32,
    },
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
    // Upstream `productionGrantEnvironment`:
    // `resolveProductionInstanceComposition` + `ceremonyOwner` (the
    // process's own euid/egid — root in production).
    let composition = Box::new(
        central_adapter_linux::broker::daemon::resolve_production_instance_composition()
            .map_err(str::to_owned)?,
    );
    Ok(GrantEnv::Production {
        composition,
        owner_uid: rustix::process::geteuid().as_raw(),
        owner_gid: rustix::process::getegid().as_raw(),
    })
}

/// Ports `preInstanceIssueKind`: parses `issue`'s flags with the same
/// grammar `grantIssue` uses so a `--kind`-looking flag *value* can
/// never misroute (`--operation --kind init` parses `--kind` as the
/// operation value). Any parse failure is "not an init issuance".
fn pre_instance_issue_kind(args: &[String]) -> Option<String> {
    if args.first().map(String::as_str) != Some("issue") {
        return None;
    }
    // Upstream passes io.Discard here — the probe must not spray flag
    // errors or the usage block at the operator during env resolution.
    parse_grant_issue_flags(&args[1..], &mut std::io::sink())
        .ok()
        .map(|f| f.kind)
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
        "issue" => grant_issue(env, &args[1..], stdout, stderr),
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

fn parse_grant_issue_flags(
    args: &[String],
    err_out: &mut impl Write,
) -> Result<GrantIssueFlags, String> {
    // Upstream ignores leftover positionals — `fs.Parse` leaves them
    // in `fs.Args()` and `grantIssue` never inspects it. `err_out` is
    // the FlagSet output: flag.ContinueOnError writes the failf line
    // plus the `Usage of grant issue:` defaults block there before
    // the caller's `grant: usage:` line.
    let (values, _positionals) = modes::parse_go_flags(
        args,
        "grant issue",
        &[
            (
                "kind",
                modes::GoFlag::Value,
                "ceremony kind: lifecycle, prepare, migration_reset, restore_apply, restore_abandon, wipe, backup_export, backup_import, backup_delete, backup_prune, security_rescue, init",
            ),
            (
                "operation",
                modes::GoFlag::Value,
                "exact operation id the grant is for (required for migration_reset, restore_* and backup_prune)",
            ),
            (
                "ttl",
                modes::GoFlag::Duration,
                "how long the grant stays spendable (default 1h, 15m for init; max 24h)",
            ),
            (
                "replace",
                modes::GoFlag::Bool,
                "revoke the pending init grant and issue a new one (init only)",
            ),
        ],
        err_out,
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
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<(), GrantError> {
    let flags = parse_grant_issue_flags(args, stderr).map_err(GrantError::Usage)?;
    // Upstream ParseGrantKind trims before matching and quotes the
    // untrimmed raw value in the error.
    if !GRANT_KINDS.contains(&flags.kind.trim()) {
        return Err(GrantError::Usage(format!(
            "grant: unknown kind {:?}",
            flags.kind
        )));
    }
    if flags.kind.trim() == "init" {
        return grant_issue_init(env, &flags, stdout);
    }
    if flags.replace {
        return Err(GrantError::Other(
            "grant: --replace is init-only".to_string(),
        ));
    }
    // Upstream `grantIssue`: the composition's ceremony mode must be
    // `grant` (a physical-tty instance takes the console ceremony, not a
    // root-issued grant), then the store issues the scoped grant bound
    // to the running boot.
    let GrantEnv::Production {
        composition,
        owner_uid,
        owner_gid,
    } = env
    else {
        return Err(GrantError::Other(
            "grant issuance needs the installed instance; run central local init first".to_string(),
        ));
    };
    let mode = central_adapter_linux::helper::grant::read_ceremony_mode(
        &composition.authoritative_state_root,
        *owner_uid,
        *owner_gid,
    )
    .map_err(|e| GrantError::Other(e.message().to_owned()))?;
    if mode != central_adapter_linux::helper::grant::CeremonyMode::Grant {
        return Err(GrantError::Other(format!(
            "instance ceremony mode is {}; run `central grant mode grant` first",
            mode.as_str()
        )));
    }
    let ttl_ns = flags.ttl_ns.unwrap_or(60 * 60 * 1_000_000_000);
    let store_dir = format!("{}/grants", composition.authoritative_state_root);
    let store =
        central_adapter_linux::helper::grant::GrantStore::open(&store_dir, *owner_uid, *owner_gid)
            .map_err(|e| GrantError::Other(e.message().to_owned()))?;
    let boot_id = grant_boot_id().map_err(GrantError::Other)?;
    let kind = central_adapter_linux::helper::grant::parse_grant_kind(flags.kind.trim())
        .map_err(|e| GrantError::Usage(e.message().to_owned()))?;
    let scope = central_adapter_linux::helper::grant::GrantScope {
        kind,
        instance_id: "default".to_owned(),
        target_id: "postgres:central".to_owned(),
        operation_id: flags.operation.clone(),
    };
    let grant = store
        .issue(
            &scope,
            &boot_id,
            &central_adapter_linux::helper::prepare::helper_release_identity(""),
            std::time::Duration::from_nanos(ttl_ns as u64),
        )
        .map_err(|e| GrantError::Other(e.message().to_owned()))?;
    print_grant_json(stdout, &grant)
}

/// Ports `grantIssueInit`: `--operation` is refused (plain error —
/// exit 7), `--ttl` must sit in `(0, 15m]`, and a non-absent genesis
/// state is the `refused by host state` class (exit 6). An absent
/// host gets the genesis store ensured at its upstream path, opened
/// under the genesis env's owners, issued by `IssueInit` against the
/// running boot and this process's helper identity, and printed as
/// upstream's grant JSON.
fn grant_issue_init(
    env: &GrantEnv,
    flags: &GrantIssueFlags,
    stdout: &mut impl Write,
) -> Result<(), GrantError> {
    let _ = env;
    // Exit-class rule (upstream's pinned restore_apply test: a
    // semantically refused flag combination is exit 7, not usage).
    // Only flag PARSE failures are usage (exit 2).
    if !flags.operation.is_empty() {
        return Err(GrantError::Other(
            "grant: --operation is refused for --kind init".to_string(),
        ));
    }
    // helper.InitGrantTTL = 15m; unset means the default is used.
    let ttl_ns = flags.ttl_ns.unwrap_or(15 * 60 * 1_000_000_000);
    if ttl_ns <= 0 || ttl_ns > 15 * 60 * 1_000_000_000 {
        return Err(GrantError::Other(format!(
            "grant: init ttl {} is outside (0, 15m]",
            format_go_duration(ttl_ns)
        )));
    }
    // There is no instance yet, so there is no ceremony-mode check:
    // the genesis state itself gates issuance.
    let genv = grant_genesis_env();
    let (state, _, state_err) = genv.state();
    if state_err.is_some() || state != GenesisState::Absent {
        return Err(GrantError::StateRefusal(format!(
            "cannot issue an init grant on a {} host: refused by host state",
            state.as_str()
        )));
    }
    let dir = central_adapter_linux::helper::init::genesis_init_store_dir(&genv.roots);
    central_adapter_linux::genesis::ensure_genesis_init_store(&genv, Path::new(&dir))
        .map_err(GrantError::Other)?;
    let boot_id = grant_boot_id().map_err(GrantError::Other)?;
    // `OpenGrantStore(dir, genv.owners.RootUID, genv.owners.RootGID)`
    // — the genesis env's root identity owns the protected tree and
    // the store it creates; on `sudo central grant issue` that is the
    // invoking operator's effective identity, not a service account.
    let store = central_adapter_linux::helper::grant::GrantStore::open(
        &dir,
        genv.owners.root_uid,
        genv.owners.root_gid,
    )
    .map_err(|e| GrantError::Other(e.message().to_owned()))?;
    let grant = store
        .issue_init(
            &boot_id,
            &central_adapter_linux::helper::prepare::helper_release_identity(""),
            std::time::Duration::from_nanos(ttl_ns as u64),
            flags.replace,
        )
        .map_err(|e| match e.code() {
            // `ErrInitGrantPending`/`ErrGrantStoreBusy` — the exit-6
            // refusal class upstream's dispatch keys on.
            "sys_grant_pending" | "sys_grant_busy" => {
                GrantError::StateRefusal(e.message().to_owned())
            }
            _ => GrantError::Other(e.message().to_owned()),
        })?;
    print_grant_json(stdout, &grant)
}

/// `printGrantJSON` — the MAC stays in the store; what the operator
/// gets is enough to find the grant in the helper log and the
/// `ceremony_records` manifest entry. Go's `json.Encoder` emits one
/// compact object plus a newline in upstream's field order, and
/// `operation_id` is `omitempty` — absent on an init grant.
fn print_grant_json(
    w: &mut impl Write,
    grant: &central_adapter_linux::helper::grant::Grant,
) -> Result<(), GrantError> {
    let esc =
        |s: &str| serde_json::to_string(s).map_err(|e| GrantError::Other(format!("grant: {e}")));
    let mut line = String::from("{\"kind\":");
    line.push_str(&esc(&grant.kind)?);
    if !grant.operation_id.is_empty() {
        line.push_str(",\"operation_id\":");
        line.push_str(&esc(&grant.operation_id)?);
    }
    line.push_str(",\"nonce\":");
    line.push_str(&esc(&grant.nonce)?);
    line.push_str(",\"issued_at\":");
    line.push_str(&esc(&grant.issued_at)?);
    line.push_str(",\"expires_at\":");
    line.push_str(&esc(&grant.expires_at)?);
    line.push_str("}\n");
    w.write_all(line.as_bytes())
        .map_err(|e| GrantError::Other(format!("grant: {e}")))
}

/// Upstream's `env.testGenesis`/`env.bootID` slots — the seams
/// `grantIssueInit` reads the genesis roots, owners, and boot binding
/// through. Production resolves them live; tests install a scratch
/// env and a fixed boot id on the calling thread.
#[cfg(not(test))]
fn grant_genesis_env() -> central_adapter_linux::genesis::GenesisEnv {
    central_adapter_linux::genesis::GenesisEnv::production()
}

/// The test half of `env.testGenesis`: the installed scratch env, or
/// the production env when none is.
#[cfg(test)]
fn grant_genesis_env() -> central_adapter_linux::genesis::GenesisEnv {
    TEST_GENESIS_ENV
        .with(|slot| slot.borrow().clone())
        .unwrap_or_else(central_adapter_linux::genesis::GenesisEnv::production)
}

/// `env.bootID` — `/proc/sys/kernel/random/boot_id`; tests substitute
/// a fixed id or a failure.
#[cfg(not(test))]
fn grant_boot_id() -> Result<String, String> {
    central_adapter_linux::helper::read_boot_id().map_err(|e| e.message().to_owned())
}

#[cfg(test)]
fn grant_boot_id() -> Result<String, String> {
    TEST_BOOT_ID
        .with(|slot| slot.borrow().clone())
        .unwrap_or_else(|| {
            central_adapter_linux::helper::read_boot_id().map_err(|e| e.message().to_owned())
        })
}

// `grantEnvironment.testGenesis`/`bootID` — the test seams
// `grantIssueInit` consults. Thread-local so parallel dispatch tests
// keep their own env; the installer clears both on drop because cargo
// reuses test threads.
#[cfg(test)]
thread_local! {
    static TEST_GENESIS_ENV: std::cell::RefCell<
        Option<central_adapter_linux::genesis::GenesisEnv>,
    > = const { std::cell::RefCell::new(None) };
    static TEST_BOOT_ID: std::cell::RefCell<Option<Result<String, String>>> =
        const { std::cell::RefCell::new(None) };
}

/// Ports `grantMode`: exactly one `physical_tty|grant` argument —
/// everything else is usage. The real mode write + store-dir creation
/// is T8; the skeleton fails closed.
fn grant_mode(env: &GrantEnv, args: &[String]) -> Result<(), GrantError> {
    if args.len() != 1 {
        return Err(GrantError::Usage(
            "central grant mode <physical_tty|grant>".to_string(),
        ));
    }
    let mode = central_adapter_linux::helper::grant::parse_ceremony_mode(&args[0])
        .map_err(|e| GrantError::Usage(e.message().to_owned()))?;
    let GrantEnv::Production {
        composition,
        owner_uid,
        owner_gid,
    } = env
    else {
        return Err(GrantError::Other(
            "ceremony mode needs the installed instance; run central local init first".to_string(),
        ));
    };
    if mode == central_adapter_linux::helper::grant::CeremonyMode::Grant {
        // Upstream `grantMode`: switching to grant mode ensures the
        // store exists first — the mkdir+chmod are idempotent.
        let dir = format!("{}/grants", composition.authoritative_state_root);
        let _ = std::fs::create_dir(&dir);
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        let _store =
            central_adapter_linux::helper::grant::GrantStore::open(&dir, *owner_uid, *owner_gid)
                .map_err(|e| GrantError::Other(e.message().to_owned()))?;
    }
    central_adapter_linux::helper::grant::write_ceremony_mode(
        &composition.authoritative_state_root,
        mode,
    )
    .map_err(|e| GrantError::Other(e.message().to_owned()))?;
    println!("ceremony mode: {}", mode.as_str());
    Ok(())
}

/// Ports `grantList`: open the store and print each consumed record as
/// one JSON line, upstream's `json.Encoder` loop.
fn grant_list(env: &GrantEnv, stdout: &mut impl Write) -> Result<(), GrantError> {
    let GrantEnv::Production {
        composition,
        owner_uid,
        owner_gid,
    } = env
    else {
        return Err(GrantError::Other(
            "grant listing needs the installed instance; run central local init first".to_string(),
        ));
    };
    let store = central_adapter_linux::helper::grant::GrantStore::open(
        &format!("{}/grants", composition.authoritative_state_root),
        *owner_uid,
        *owner_gid,
    )
    .map_err(|e| GrantError::Other(e.message().to_owned()))?;
    for record in store
        .consumed()
        .map_err(|e| GrantError::Other(e.message().to_owned()))?
    {
        let line =
            serde_json::to_string(&record).map_err(|e| GrantError::Other(format!("grant: {e}")))?;
        stdout
            .write_all(format!("{line}\n").as_bytes())
            .map_err(|e| GrantError::Other(format!("grant: {e}")))?;
    }
    Ok(())
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
    use std::path::PathBuf;

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
    fn dispatch(env: &GrantEnv, args: &[&str]) -> (u8, String, String) {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = grant_dispatch(env, &argv(args), &mut out, &mut err);
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    /// A production env rooted at a scratch instance dir: the same
    /// shape the resolver hands production, with a state root that
    /// exists so store/mode paths land somewhere real.
    fn prod_env_at(root: &Path) -> GrantEnv {
        GrantEnv::Production {
            composition: Box::new(
                central_adapter_linux::broker::daemon::ProductionInstanceComposition {
                    instance_id: "00000000-0000-7000-8000-000000000000".to_owned(),
                    config_binding: String::new(),
                    authoritative_state_root: root.to_string_lossy().into_owned(),
                    dependency_root: String::new(),
                    lifecycle_root: String::new(),
                    role_roots: Default::default(),
                    backup_repository_root: String::new(),
                    compose_path: String::new(),
                    object_store_bucket: String::new(),
                    backup_policy_digest: String::new(),
                    restore_policy_digest: String::new(),
                    import_policy_digest: String::new(),
                },
            ),
            owner_uid: rustix::process::geteuid().as_raw(),
            owner_gid: rustix::process::getegid().as_raw(),
        }
    }

    /// A production env on a fresh scratch root (no ceremony-mode
    /// file, no store) — an absent mode file reads `physical_tty`.
    fn prod_env() -> GrantEnv {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = scratch(&format!(
            "prod-{}",
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        prod_env_at(&root)
    }

    /// A private scratch directory per test.
    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "central-grant-cli-test-{}-{tag}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The `genesisTestEnv` shape upstream's grant tests use: the
    /// scratch `state`/`protected` roots with every owner set to the
    /// test's euid — the identity `sudo` would hand a real issuance.
    fn scratch_genesis_env(base: &Path) -> central_adapter_linux::genesis::GenesisEnv {
        let mut env = central_adapter_linux::genesis::GenesisEnv::production();
        env.roots = central_adapter_linux::genesis::GenesisRoots {
            state_root: base.join("state/v1").to_string_lossy().into_owned(),
            protected_root: base.join("protected/v1").to_string_lossy().into_owned(),
        };
        let (uid, gid) = (
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw(),
        );
        env.owners = central_adapter_linux::genesis::GenesisOwners {
            root_uid: uid,
            root_gid: gid,
            runtime_uid: uid,
            runtime_gid: gid,
        };
        env.lock_wait = std::time::Duration::from_secs(2);
        env.free_bytes = std::sync::Arc::new(|_| Ok(u64::MAX));
        env.ensure_identities = std::sync::Arc::new(|| Ok(()));
        env
    }

    /// Installs `env.testGenesis` + `env.bootID` on this thread and
    /// clears both on drop (cargo reuses test threads).
    struct InitSeams;

    impl InitSeams {
        fn install(
            env: central_adapter_linux::genesis::GenesisEnv,
            boot_id: Result<String, String>,
        ) -> Self {
            TEST_GENESIS_ENV.with(|slot| *slot.borrow_mut() = Some(env));
            TEST_BOOT_ID.with(|slot| *slot.borrow_mut() = Some(boot_id));
            InitSeams
        }
    }

    impl Drop for InitSeams {
        fn drop(&mut self) {
            TEST_GENESIS_ENV.with(|slot| *slot.borrow_mut() = None);
            TEST_BOOT_ID.with(|slot| *slot.borrow_mut() = None);
        }
    }

    /// The upstream test's `decode`/`window` pair: stdout must be the
    /// printed grant JSON, and `expires_at - issued_at` the ttl.
    fn decode(stdout: &str) -> serde_json::Value {
        serde_json::from_str(stdout).expect("stdout is not JSON")
    }

    fn grant_window(v: &serde_json::Value) -> time::Duration {
        let parse = |key: &str| {
            time::OffsetDateTime::parse(
                v[key].as_str().expect("timestamp is a string"),
                &time::format_description::well_known::Rfc3339,
            )
            .expect("timestamp is RFC 3339")
        };
        parse("expires_at") - parse("issued_at")
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

    // -- grantIssueInit (upstream TestGrantIssueInit) -------------------

    #[test]
    fn issue_init_mints_and_prints_the_grant_json() {
        let base = scratch("basic");
        let env = scratch_genesis_env(&base);
        let store_dir = central_adapter_linux::helper::init::genesis_init_store_dir(&env.roots);
        // `issue --kind init` is the one env-resolution fallback; the
        // scratch genesis env keeps it off the production roots.
        let _seams = InitSeams::install(env, Ok("boot-test".to_owned()));
        let (code, stdout, stderr) = run(&["issue", "--kind", "init"]);
        assert_eq!(code, 0, "stderr {stderr}");
        let v = decode(&stdout);
        assert_eq!(v["kind"], "init");
        assert!(v["nonce"].as_str().is_some_and(|n| !n.is_empty()));
        // `operation_id` is omitempty — an init grant carries none.
        assert!(v.get("operation_id").is_none(), "{stdout}");
        assert_eq!(v.as_object().unwrap().len(), 4, "{stdout}");
        // The unset --ttl means the default: helper.InitGrantTTL = 15m.
        assert_eq!(grant_window(&v), time::Duration::minutes(15));
        // ensureGenesisInitStore created the store at the upstream
        // path, exactly 0700.
        let mode = std::fs::metadata(&store_dir).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(mode.mode() & 0o777, 0o700);
    }

    #[test]
    fn issue_init_pending_refuses_then_replace_reissues() {
        let base = scratch("replace");
        let env = scratch_genesis_env(&base);
        let store_dir = central_adapter_linux::helper::init::genesis_init_store_dir(&env.roots);
        let _seams = InitSeams::install(env, Ok("boot-test".to_owned()));
        let (code, stdout, _) = run(&["issue", "--kind", "init"]);
        assert_eq!(code, 0);
        let first = decode(&stdout)["nonce"].as_str().unwrap().to_owned();
        // A second usable init grant is ErrInitGrantPending → exit 6,
        // naming GRANT_PENDING and --replace.
        let (code, _, stderr) = run(&["issue", "--kind", "init"]);
        assert_eq!(code, 6);
        assert_eq!(
            stderr,
            "grant: init grant already pending (GRANT_PENDING); use --replace to revoke it and issue a new one\n"
        );
        // --replace revokes the pending grant and mints a distinct one.
        let (code, stdout, stderr) = run(&["issue", "--kind", "init", "--replace"]);
        assert_eq!(code, 0, "stderr {stderr}");
        let second = decode(&stdout)["nonce"].as_str().unwrap().to_owned();
        assert_ne!(first, second);
        let revoked = std::fs::read_dir(&store_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".revoked"))
            .count();
        assert_eq!(revoked, 1);
    }

    #[test]
    fn issue_init_ttl_flag_sizes_the_window() {
        let base = scratch("ttl");
        let env = scratch_genesis_env(&base);
        let _seams = InitSeams::install(env, Ok("boot-test".to_owned()));
        let (code, stdout, stderr) = run(&["issue", "--kind", "init", "--ttl", "10m"]);
        assert_eq!(code, 0, "stderr {stderr}");
        assert_eq!(grant_window(&decode(&stdout)), time::Duration::minutes(10));
    }

    #[test]
    fn issue_init_on_a_present_host_is_refused() {
        let base = scratch("present");
        let env = scratch_genesis_env(&base);
        // mustCreateGenesis — the install makes the host `present`.
        env.create(
            std::time::Instant::now() + std::time::Duration::from_secs(30),
            central_adapter_linux::genesis::GENESIS_CEREMONY_PHYSICAL_TTY,
            "",
        )
        .expect("first genesis");
        let _seams = InitSeams::install(env, Ok("boot-test".to_owned()));
        let (code, _, stderr) = run(&["issue", "--kind", "init"]);
        assert_eq!(code, 6);
        assert_eq!(
            stderr,
            "grant: cannot issue an init grant on a present host: refused by host state\n"
        );
    }

    #[test]
    fn issue_init_with_a_bad_store_mode_refuses() {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
        let base = scratch("badmode");
        let env = scratch_genesis_env(&base);
        let store_dir = central_adapter_linux::helper::init::genesis_init_store_dir(&env.roots);
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&store_dir)
            .unwrap();
        std::fs::set_permissions(&store_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let _seams = InitSeams::install(env, Ok("boot-test".to_owned()));
        // OpenGrantStore refuses the pre-existing 0755 dir — a plain
        // error (exit 7), never a repair.
        let (code, _, stderr) = run(&["issue", "--kind", "init"]);
        assert_eq!(code, 7);
        assert_eq!(
            stderr,
            "grant: grant: store must be a 0700 directory owned by the instance owner\n"
        );
    }

    #[test]
    fn issue_init_boot_id_failure_is_a_plain_error() {
        let base = scratch("bootid");
        let env = scratch_genesis_env(&base);
        let _seams = InitSeams::install(env, Err("helper: read boot id: no such file".to_owned()));
        let (code, _, stderr) = run(&["issue", "--kind", "init"]);
        assert_eq!(code, 7);
        assert_eq!(stderr, "grant: helper: read boot id: no such file\n");
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
        for env in [prod_env(), GrantEnv::PreInstance] {
            let (code, _, stderr) = dispatch(&env, &[]);
            assert_eq!(code, 2);
            assert_eq!(stderr, "usage: central grant issue|mode|list ...\n");

            let (code, _, stderr) = dispatch(&env, &["bogus"]);
            assert_eq!(code, 2);
            assert_eq!(stderr, "grant: unknown subcommand \"bogus\"\n");
        }
    }

    /// The `Usage of grant issue:` block Go's `flag.ContinueOnError`
    /// FlagSet writes (failf + PrintDefaults) before `grantDispatch`'s
    /// `grant: usage:` line — verbatim upstream spec order sorted by
    /// flag name.
    const ISSUE_USAGE: &str = concat!(
        "Usage of grant issue:\n",
        "  -kind string\n",
        "    \tceremony kind: lifecycle, prepare, migration_reset, restore_apply, restore_abandon, wipe, backup_export, backup_import, backup_delete, backup_prune, security_rescue, init\n",
        "  -operation string\n",
        "    \texact operation id the grant is for (required for migration_reset, restore_* and backup_prune)\n",
        "  -replace\n",
        "    \trevoke the pending init grant and issue a new one (init only)\n",
        "  -ttl value\n",
        "    \thow long the grant stays spendable (default 1h, 15m for init; max 24h)\n",
    );

    #[test]
    fn issue_flag_parse_errors_are_usage() {
        // flag_err entries additionally expect the failf line plus the
        // usage block before the dispatcher's `grant: usage:` line.
        for (args, flag_err, tail) in [
            (
                vec!["issue", "--bogus"],
                Some("flag provided but not defined: -bogus"),
                "grant: usage: flag provided but not defined: -bogus\n",
            ),
            (
                vec!["issue", "--ttl", "bogus"],
                Some("invalid value \"bogus\" for flag -ttl: time: invalid duration \"bogus\""),
                "grant: usage: invalid value \"bogus\" for flag -ttl: time: invalid duration \"bogus\"\n",
            ),
            (
                vec!["issue", "--kind"],
                Some("flag needs an argument: -kind"),
                "grant: usage: flag needs an argument: -kind\n",
            ),
            // Positionals are ignored upstream — `issue positional`
            // fails the empty kind check instead.
            (
                vec!["issue", "positional"],
                None,
                "grant: usage: grant: unknown kind \"\"\n",
            ),
            (
                vec!["issue", "--kind", "bogus"],
                None,
                "grant: usage: grant: unknown kind \"bogus\"\n",
            ),
            // Missing --kind parses fine but fails the kind check.
            (
                vec!["issue"],
                None,
                "grant: usage: grant: unknown kind \"\"\n",
            ),
        ] {
            let (code, _, stderr) = dispatch(&prod_env(), &args);
            assert_eq!(code, 2, "args {args:?}");
            let want = match flag_err {
                Some(err) => format!("{err}\n{ISSUE_USAGE}{tail}"),
                None => tail.to_string(),
            };
            assert_eq!(stderr, want, "args {args:?}");
        }
    }

    #[test]
    fn issue_help_prints_usage_and_help_requested() {
        // `-h`/`--help` undefined: Go prints the usage block with no
        // error line, then ErrHelp reaches the `grant: usage:` wrap.
        let (code, _, stderr) = dispatch(&prod_env(), &["issue", "--help"]);
        assert_eq!(code, 2);
        assert_eq!(
            stderr,
            format!("{ISSUE_USAGE}grant: usage: flag: help requested\n")
        );
    }

    #[test]
    fn non_init_issue_is_closed_failure() {
        let (code, _, stderr) = dispatch(&prod_env(), &["issue", "--kind", "lifecycle"]);
        assert_eq!(code, 7);
        assert_eq!(
            stderr,
            "grant: instance ceremony mode is physical_tty; run `central grant mode grant` first\n"
        );
        let (code, _, stderr) =
            dispatch(&prod_env(), &["issue", "--kind", "lifecycle", "--replace"]);
        assert_eq!(code, 7);
        assert_eq!(stderr, "grant: grant: --replace is init-only\n");
    }

    #[test]
    fn mode_grammar_is_closed() {
        let (code, _, stderr) = dispatch(&prod_env(), &["mode"]);
        assert_eq!(code, 2);
        assert_eq!(
            stderr,
            "grant: usage: central grant mode <physical_tty|grant>\n"
        );
        let (code, _, stderr) = dispatch(&prod_env(), &["mode", "bogus"]);
        assert_eq!(code, 2);
        assert_eq!(stderr, "grant: usage: ceremony: unknown mode \"bogus\"\n");
        for mode in ["physical_tty", "grant"] {
            let (code, _, stderr) = dispatch(&prod_env(), &["mode", mode]);
            assert_eq!(code, 0, "mode {mode}: {stderr}");
            assert_eq!(stderr, "");
        }
    }

    #[test]
    fn list_reads_the_consumed_records() {
        let env = prod_env();
        // No store yet: upstream OpenGrantStore fails closed.
        let (code, _, _) = dispatch(&env, &["list"]);
        assert_eq!(code, 7);
        // Switch the instance to grant mode (creates the store), then
        // an empty consumed set lists nothing successfully.
        let (code, _, _) = dispatch(&env, &["mode", "grant"]);
        assert_eq!(code, 0);
        let (code, out, stderr) = dispatch(&env, &["list"]);
        assert_eq!((code, out.as_str(), stderr.as_str()), (0, "", ""));
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
