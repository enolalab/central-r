//! Harness serve composition — the kernel's port of upstream
//! `cmd/central/harness_config.go` plus the launcher/bootstrap
//! selection policy of `harness_backend.go` and
//! `harness_launcher_linux.go` (issue #120, issue #124).
//!
//! What lives here:
//!
//! - [`HarnessConfig`] — the validated `CENTRAL_HARNESS_*`
//!   environment, field-for-field `harnessConfig` upstream
//!   (`loadHarnessConfig`). When `CENTRAL_HARNESS_ENABLED` is unset or
//!   `0` the harness is off and every other variable keeps its
//!   default — nothing else is validated, exactly like upstream's
//!   early return.
//! - [`select_launcher`] — the issue-#120/#124 rule: the real
//!   `central-harness-launcher` daemon client ([`HostLauncher`]) is
//!   the DEFAULT and only production launcher; `localexec` is
//!   reachable only when the explicit `CENTRAL_LOCALEXEC=1` dev gate
//!   is set (and [`LocalExec::new`] itself re-checks the gate
//!   fail-closed).
//! - [`select_bootstrap`] — the file-backed dev bootstrap
//!   ([`DevFileProtectedBootstrap`]) is likewise reachable only under
//!   the dev gate; without it the broker-backed bootstrap is deferred
//!   to R5 and selection fails closed.
//!
//! Upstream `newHarnessHostLauncher` constructs its socket client
//! inside the launcher constructor (`hostlauncher.NewSocket` dials
//! lazily per request). The Rust port keeps the audited
//! `AF_UNIX`/`SOCK_SEQPACKET` + `SCM_RIGHTS` CHL1 transport outside
//! `central-adapter-harness` (rust-application-boundaries.md §2.1);
//! the composition root injects the concrete
//! [`client::LauncherClient`] — see `socket_client` in this module.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use central_adapter_harness::launcher::client::{self, HostLauncher};
use central_adapter_harness::localexec::{self, LocalExec};
use central_adapter_linux::dev_bootstrap::DevFileProtectedBootstrap;
use central_foundation::failure::{Failure, FailureKind};
use central_harness::port::ProcessLauncher;
use time::{Duration, OffsetDateTime};

/// `errHarnessConfig` — every config/selection failure carries this
/// code prefix so `serve` classifies it `CONFIG_INVALID`.
pub const ERR_HARNESS_CONFIG: &str = "harness_config_invalid";

fn config_err(msg: impl Into<String>) -> Failure {
    Failure::invalid(ERR_HARNESS_CONFIG, msg.into())
}

// ---------------------------------------------------------------------------
// Environment names (exact upstream `envHarness*` constants)
// ---------------------------------------------------------------------------

pub const ENV_HARNESS_ENABLED: &str = "CENTRAL_HARNESS_ENABLED";
pub const ENV_HARNESS_ELIGIBLE_AFTER: &str = "CENTRAL_HARNESS_ELIGIBLE_AFTER";
pub const ENV_HARNESS_DATA_ROOT: &str = "CENTRAL_HARNESS_DATA_ROOT";
pub const ENV_HARNESS_PATH: &str = "CENTRAL_HARNESS_PATH";
pub const ENV_HARNESS_WALL_CLOCK: &str = "CENTRAL_HARNESS_WALL_CLOCK";
pub const ENV_HARNESS_CONCURRENCY: &str = "CENTRAL_HARNESS_CONCURRENCY";
pub const ENV_HARNESS_MIN_FREE: &str = "CENTRAL_HARNESS_MIN_FREE";
pub const ENV_HARNESS_CLAUDE_VERSION: &str = "CENTRAL_HARNESS_CLAUDE_VERSION";
pub const ENV_HARNESS_BACKEND: &str = "CENTRAL_HARNESS_BACKEND";
pub const ENV_HARNESS_OPENCODE_VERSION: &str = "CENTRAL_HARNESS_OPENCODE_VERSION";
pub const ENV_HARNESS_CODEX_VERSION: &str = "CENTRAL_HARNESS_CODEX_VERSION";
pub const ENV_HARNESS_ANTIGRAVITY_VERSION: &str = "CENTRAL_HARNESS_ANTIGRAVITY_VERSION";
pub const ENV_HARNESS_OPERATOR_UID: &str = "CENTRAL_HARNESS_OPERATOR_UID";
pub const ENV_HARNESS_APPROVAL_TIMEOUT: &str = "CENTRAL_HARNESS_APPROVAL_TIMEOUT";
pub const ENV_HARNESS_MAX_COST_USD: &str = "CENTRAL_HARNESS_MAX_COST_USD";
/// `envHarnessMaxAttempts` — default 3, valid 1..=10, validated only
/// when enabled.
pub const ENV_HARNESS_MAX_ATTEMPTS: &str = "CENTRAL_HARNESS_MAX_ATTEMPTS";
pub const ENV_HARNESS_TASK_COST_CAP_USD: &str = "CENTRAL_HARNESS_TASK_COST_CAP_USD";
/// `envHarnessMaxTokens` — the serve-wide billed-token ceiling; 0
/// (the default while harness execution is off) is no ceiling.
pub const ENV_HARNESS_MAX_TOKENS: &str = "CENTRAL_HARNESS_MAX_TOKENS";

/// `CENTRAL_LOCALEXEC` — the explicit development gate that permits
/// the `localexec` launcher and the file-backed dev bootstrap
/// (issue #120). Shared constant: both adapter crates define their
/// own copy; the kernel names it once here for the selection policy.
pub const ENV_LOCALEXEC: &str = localexec::DEV_GATE_ENV;

const DEFAULT_HARNESS_MAX_ATTEMPTS: i64 = 3;
const MIN_HARNESS_MAX_ATTEMPTS: i64 = 1;
const MAX_HARNESS_MAX_ATTEMPTS: i64 = 10;

const DEFAULT_HARNESS_DATA_ROOT: &str = "/var/lib/central-harness";
const DEFAULT_HARNESS_PATH: &str = "/usr/local/bin:/usr/bin:/bin";
const DEFAULT_HARNESS_MIN_FREE: u64 = 2 << 30;
const MIN_HARNESS_WALL_CLOCK: Duration = Duration::minutes(1);
const MAX_HARNESS_WALL_CLOCK: Duration = Duration::hours(24);
const MIN_HARNESS_APPROVAL: Duration = Duration::seconds(30);
const MAX_HARNESS_APPROVAL: Duration = Duration::hours(24);

/// `minHarnessMaxCostMicroUSD`/`maxHarnessMaxCostMicroUSD` — the task
/// budget bounds (`task.Min/MaxBudgetCostMicroUSD`).
const MIN_HARNESS_MAX_COST_MICRO_USD: i64 = central_task::domain::MIN_BUDGET_COST_MICRO_USD;
const MAX_HARNESS_MAX_COST_MICRO_USD: i64 = central_task::domain::MAX_BUDGET_COST_MICRO_USD;

const MIN_HARNESS_TASK_COST_CAP_MICRO_USD: i64 = 10_000;
const MAX_HARNESS_TASK_COST_CAP_MICRO_USD: i64 = 100_000_000_000;
const HARNESS_TASK_COST_CAP_DEFAULT_MULTIPLE: i64 = 5;

/// `minHarnessMaxTokens`/`maxHarnessMaxTokens` — the 3l token ceiling
/// bounds; `CENTRAL_HARNESS_MAX_TOKENS` accepts a bare positive whole
/// number in this range.
const MIN_HARNESS_MAX_TOKENS: i64 = 100_000;
const MAX_HARNESS_MAX_TOKENS: i64 = 1_000_000_000;

/// `harness.Kind` — the serve-wide adapter selection. Per-Task mixing
/// is not expressible upstream, so it is not expressible here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Backend {
    /// `claude-code` — the default.
    #[default]
    ClaudeCode,
    /// `opencode` (issue #126).
    Opencode,
    /// `codex` (issue #128) — reports tokens, no cost.
    Codex,
    /// `antigravity` (issue #129) — reports tokens, no cost.
    Antigravity,
}

impl Backend {
    /// Upstream `harness.Kind`'s string form.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::Opencode => "opencode",
            Self::Codex => "codex",
            Self::Antigravity => "antigravity",
        }
    }

    /// A tokens-only backend reports no cost, so an explicit cost
    /// limit would run silently unenforced (upstream's fail-closed
    /// rule for codex/antigravity).
    fn reports_cost(self) -> bool {
        matches!(self, Self::ClaudeCode | Self::Opencode)
    }

    /// `adapterVersion` — the *adapter* identifier a Run records: a
    /// fixed constant per backend (`harnessAdapterVersion`,
    /// `opencodeAdapterVersion`, `codexAdapterVersion`,
    /// `antigravityAdapterVersion` in `harness_backend.go`), never the
    /// pinned tool version. The version is a launch-time pin; the
    /// adapter id names the adapter contract the Run executed under.
    #[must_use]
    pub const fn adapter_version(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claudecode/phase-3a",
            Self::Opencode => "opencode/issue-126",
            Self::Codex => "codex/issue-128",
            Self::Antigravity => "antigravity/issue-129",
        }
    }
}

/// `harnessConfig` — the validated harness environment. Defaults are
/// upstream's; validation happens only while `enabled` (upstream's
/// early return leaves an off harness inert).
#[derive(Debug, Clone)]
pub struct HarnessConfig {
    /// `CENTRAL_HARNESS_ENABLED=1`.
    pub enabled: bool,
    /// `CENTRAL_HARNESS_ELIGIBLE_AFTER` — required, RFC 3339.
    pub eligible_after: OffsetDateTime,
    /// `CENTRAL_HARNESS_DATA_ROOT` — absolute, clean, non-root.
    pub data_root: PathBuf,
    /// `CENTRAL_HARNESS_PATH` — colon-separated absolute dirs only.
    pub path: String,
    /// `CENTRAL_HARNESS_WALL_CLOCK` — 1 minute to 24 hours.
    pub wall_clock: Duration,
    /// `CENTRAL_HARNESS_CONCURRENCY` — 1 to
    /// [`central_harness::app::dispatcher::MAX_CONCURRENCY`].
    pub concurrency: usize,
    /// `CENTRAL_HARNESS_MIN_FREE` — bytes or a KiB/MiB/GiB/TiB count.
    pub min_free: u64,
    /// `CENTRAL_HARNESS_CLAUDE_VERSION` — pinned `x.y.z`.
    pub claude_version: String,
    /// `CENTRAL_HARNESS_BACKEND`.
    pub backend: Backend,
    /// `CENTRAL_HARNESS_OPENCODE_VERSION`.
    pub opencode_version: String,
    /// `CENTRAL_HARNESS_CODEX_VERSION`.
    pub codex_version: String,
    /// `CENTRAL_HARNESS_ANTIGRAVITY_VERSION`.
    pub antigravity_version: String,
    /// `CENTRAL_HARNESS_OPERATOR_UID` — numeric, non-root.
    pub operator_uid: u32,
    /// `CENTRAL_HARNESS_APPROVAL_TIMEOUT` — 30 seconds to 24 hours.
    pub approval_timeout: Duration,
    /// `CENTRAL_HARNESS_MAX_COST_USD` — the per-Run default cost
    /// bound (0.01 to 1000 USD).
    pub max_cost_micro_usd: i64,
    /// `CENTRAL_HARNESS_MAX_ATTEMPTS` — 1..=10; 1 disables Resume.
    pub max_attempts: i64,
    /// `CENTRAL_HARNESS_TASK_COST_CAP_USD` — never below
    /// `max_cost_micro_usd`; default 5× the per-Run default.
    pub task_cost_cap_micro_usd: i64,
    /// `CENTRAL_HARNESS_MAX_TOKENS` — 0 is no ceiling.
    pub max_tokens: i64,
}

impl Default for HarnessConfig {
    /// Upstream `loadHarnessConfig`'s inert defaults — the values an
    /// off harness carries (validated only when enabled).
    fn default() -> Self {
        Self {
            enabled: false,
            eligible_after: OffsetDateTime::UNIX_EPOCH,
            data_root: PathBuf::from(DEFAULT_HARNESS_DATA_ROOT),
            path: DEFAULT_HARNESS_PATH.to_string(),
            wall_clock: Duration::minutes(30),
            concurrency: 1,
            min_free: DEFAULT_HARNESS_MIN_FREE,
            claude_version: central_adapter_harness::claudecode::DEFAULT_PINNED_VERSION.to_string(),
            backend: Backend::default(),
            opencode_version: central_adapter_harness::opencode::DEFAULT_PINNED_VERSION.to_string(),
            codex_version: central_adapter_harness::codex::DEFAULT_PINNED_VERSION.to_string(),
            antigravity_version: central_adapter_harness::antigravity::DEFAULT_PINNED_VERSION
                .to_string(),
            operator_uid: 0,
            approval_timeout: central_harness::app::bridge::DEFAULT_APPROVAL_TIMEOUT,
            max_cost_micro_usd: 5_000_000,
            max_attempts: DEFAULT_HARNESS_MAX_ATTEMPTS,
            task_cost_cap_micro_usd: 0, // filled by load()/default_task_cost_cap
            max_tokens: 0,
        }
    }
}

/// `defaultTaskCostCap` — `min(perRun*5, 100_000_000_000)`.
fn default_task_cost_cap(per_run: i64) -> i64 {
    (per_run.saturating_mul(HARNESS_TASK_COST_CAP_DEFAULT_MULTIPLE))
        .min(MAX_HARNESS_TASK_COST_CAP_MICRO_USD)
}

/// `pinnedVersionShape` — `^[0-9]+\.[0-9]+\.[0-9]+$` without regex.
fn is_pinned_version(v: &str) -> bool {
    let mut parts = v.split('.');
    matches!(
        (parts.next(), parts.next(), parts.next(), parts.next()),
        (Some(a), Some(b), Some(c), None)
            if [a, b, c].iter().all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    )
}

/// `maxTokensShape` — `^[1-9][0-9]*$` without regex.
fn is_positive_whole(v: &str) -> bool {
    !v.is_empty()
        && v.starts_with(|c: char| c.is_ascii_digit() && c != '0')
        && v.bytes().all(|b| b.is_ascii_digit())
}

/// `parseByteSize` — a plain byte count or a KiB/MiB/GiB/TiB count.
fn parse_byte_size(v: &str) -> Result<u64, Failure> {
    for (suffix, shift) in [("TiB", 40u32), ("GiB", 30), ("MiB", 20), ("KiB", 10)] {
        if let Some(num) = v.strip_suffix(suffix) {
            let n: u64 = num.parse().map_err(|_| {
                config_err(format!(
                    "{ENV_HARNESS_MIN_FREE} must be a byte count such as 2147483648 or 2GiB"
                ))
            })?;
            return n
                .checked_shl(shift)
                .ok_or_else(|| config_err(format!("{ENV_HARNESS_MIN_FREE} is out of range")));
        }
    }
    v.parse::<u64>().map_err(|_| {
        config_err(format!(
            "{ENV_HARNESS_MIN_FREE} must be a byte count such as 2147483648 or 2GiB"
        ))
    })
}

/// Upstream's `time.ParseDuration` surface for the bounded harness
/// durations: accepts the Go forms `300ms`, `45s`, `30m`, `24h` (and
/// composites like `1h30m`). Negative values parse but fail the
/// range checks, matching upstream.
fn parse_go_duration(v: &str) -> Result<Duration, Failure> {
    let invalid = || config_err("invalid duration");
    let mut total = Duration::ZERO;
    let mut rest = v.trim();
    if let Some(stripped) = rest.strip_prefix('-') {
        rest = stripped;
        let d = parse_go_duration(rest)?;
        return Ok(-d);
    }
    if rest.is_empty() {
        return Err(invalid());
    }
    while !rest.is_empty() {
        let digits = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(rest.len());
        if digits == 0 {
            return Err(invalid());
        }
        let (num, unit_rest) = rest.split_at(digits);
        let value: f64 = num.parse().map_err(|_| invalid())?;
        let (unit, next) = if let Some(s) = unit_rest.strip_prefix("ms") {
            (1000.0, s)
        } else if let Some(s) = unit_rest.strip_prefix('s') {
            (1_000_000.0, s)
        } else if let Some(s) = unit_rest.strip_prefix('m') {
            (60_000_000.0, s)
        } else if let Some(s) = unit_rest.strip_prefix('h') {
            (3_600_000_000.0, s)
        } else {
            return Err(invalid());
        };
        total += Duration::microseconds((value * unit) as i64);
        rest = next;
    }
    Ok(total)
}

impl HarnessConfig {
    /// `loadHarnessConfig` — reads the process environment.
    ///
    /// # Errors
    /// `harness_config_invalid` ([`FailureKind::Invalid`]) on any
    /// malformed value; `serve` maps it to a `CONFIG_INVALID` exit.
    pub fn from_env() -> Result<Self, Failure> {
        Self::load(|name| std::env::var(name).unwrap_or_default())
    }

    /// `loadHarnessConfig` — the injectable-env form upstream tests
    /// and the kernel's own tests use. `getenv` returns "" for unset.
    ///
    /// # Errors
    /// Same as [`Self::from_env`].
    pub fn load(getenv: impl Fn(&str) -> String) -> Result<Self, Failure> {
        let mut cfg = Self {
            task_cost_cap_micro_usd: default_task_cost_cap(5_000_000),
            ..Self::default()
        };
        match getenv(ENV_HARNESS_ENABLED).as_str() {
            "" | "0" => return Ok(cfg),
            "1" => cfg.enabled = true,
            _ => {
                return Err(config_err(format!("{ENV_HARNESS_ENABLED} must be 1 or 0")));
            }
        }

        let raw = getenv(ENV_HARNESS_ELIGIBLE_AFTER);
        if raw.is_empty() {
            return Err(config_err(format!(
                "{ENV_HARNESS_ELIGIBLE_AFTER} is required when harness execution is enabled"
            )));
        }
        cfg.eligible_after =
            OffsetDateTime::parse(&raw, &time::format_description::well_known::Rfc3339).map_err(
                |_| {
                    config_err(format!(
                        "{ENV_HARNESS_ELIGIBLE_AFTER} must be an RFC 3339 time"
                    ))
                },
            )?;

        let v = getenv(ENV_HARNESS_DATA_ROOT);
        if !v.is_empty() {
            let p = Path::new(&v);
            let clean = p == p.components().collect::<PathBuf>().as_path();
            if !p.is_absolute() || !clean || p == Path::new("/") {
                return Err(config_err(format!(
                    "{ENV_HARNESS_DATA_ROOT} must be an absolute, clean, non-root path"
                )));
            }
            cfg.data_root = PathBuf::from(v);
        }
        let v = getenv(ENV_HARNESS_PATH);
        if !v.is_empty() {
            for dir in v.split(':') {
                let p = Path::new(dir);
                let clean = p == p.components().collect::<PathBuf>().as_path();
                if dir.is_empty() || !p.is_absolute() || !clean {
                    return Err(config_err(format!(
                        "{ENV_HARNESS_PATH} may list only absolute directories"
                    )));
                }
            }
            cfg.path = v;
        }
        let v = getenv(ENV_HARNESS_WALL_CLOCK);
        if !v.is_empty() {
            let d = parse_go_duration(&v).map_err(|_| {
                config_err(format!(
                    "{ENV_HARNESS_WALL_CLOCK} must be a duration from {MIN_HARNESS_WALL_CLOCK} to {MAX_HARNESS_WALL_CLOCK}"
                ))
            })?;
            if d < MIN_HARNESS_WALL_CLOCK || d > MAX_HARNESS_WALL_CLOCK {
                return Err(config_err(format!(
                    "{ENV_HARNESS_WALL_CLOCK} must be a duration from {MIN_HARNESS_WALL_CLOCK} to {MAX_HARNESS_WALL_CLOCK}"
                )));
            }
            cfg.wall_clock = d;
        }
        let v = getenv(ENV_HARNESS_APPROVAL_TIMEOUT);
        if !v.is_empty() {
            let d = parse_go_duration(&v).map_err(|_| {
                config_err(format!(
                    "{ENV_HARNESS_APPROVAL_TIMEOUT} must be a duration from {MIN_HARNESS_APPROVAL} to {MAX_HARNESS_APPROVAL}"
                ))
            })?;
            if d < MIN_HARNESS_APPROVAL || d > MAX_HARNESS_APPROVAL {
                return Err(config_err(format!(
                    "{ENV_HARNESS_APPROVAL_TIMEOUT} must be a duration from {MIN_HARNESS_APPROVAL} to {MAX_HARNESS_APPROVAL}"
                )));
            }
            cfg.approval_timeout = d;
        }
        let v = getenv(ENV_HARNESS_MAX_COST_USD);
        if !v.is_empty() {
            let micro = central_task::domain::parse_budget_cost_usd(&v).filter(|m| {
                *m >= MIN_HARNESS_MAX_COST_MICRO_USD && *m <= MAX_HARNESS_MAX_COST_MICRO_USD
            });
            let Some(micro) = micro else {
                return Err(config_err(format!(
                    "{ENV_HARNESS_MAX_COST_USD} must be a dollar amount from 0.01 to 1000 with at most two decimal places"
                )));
            };
            cfg.max_cost_micro_usd = micro;
        }
        // Read after the per-Run default: the cap's default and its
        // lower bound derive from it (harness phase 3j decision 1).
        cfg.task_cost_cap_micro_usd = default_task_cost_cap(cfg.max_cost_micro_usd);
        let v = getenv(ENV_HARNESS_TASK_COST_CAP_USD);
        if !v.is_empty() {
            let micro = central_task::domain::parse_budget_cost_usd(&v).filter(|m| {
                *m >= MIN_HARNESS_TASK_COST_CAP_MICRO_USD
                    && *m <= MAX_HARNESS_TASK_COST_CAP_MICRO_USD
            });
            let Some(micro) = micro else {
                return Err(config_err(format!(
                    "{ENV_HARNESS_TASK_COST_CAP_USD} must be a dollar amount from 0.01 to 100000 with at most two decimal places"
                )));
            };
            if micro < cfg.max_cost_micro_usd {
                return Err(config_err(format!(
                    "{ENV_HARNESS_TASK_COST_CAP_USD} must be at least the per-Run default {ENV_HARNESS_MAX_COST_USD}"
                )));
            }
            cfg.task_cost_cap_micro_usd = micro;
        }
        let v = getenv(ENV_HARNESS_MAX_ATTEMPTS);
        if !v.is_empty() {
            let n: i64 = v.parse().map_err(|_| {
                config_err(format!(
                    "{ENV_HARNESS_MAX_ATTEMPTS} must be {MIN_HARNESS_MAX_ATTEMPTS} to {MAX_HARNESS_MAX_ATTEMPTS}"
                ))
            })?;
            if !(MIN_HARNESS_MAX_ATTEMPTS..=MAX_HARNESS_MAX_ATTEMPTS).contains(&n) {
                return Err(config_err(format!(
                    "{ENV_HARNESS_MAX_ATTEMPTS} must be {MIN_HARNESS_MAX_ATTEMPTS} to {MAX_HARNESS_MAX_ATTEMPTS}"
                )));
            }
            cfg.max_attempts = n;
        }
        let v = getenv(ENV_HARNESS_MAX_TOKENS);
        if !v.is_empty() {
            let n: i64 = v.parse().unwrap_or(-1);
            if !is_positive_whole(&v)
                || !(MIN_HARNESS_MAX_TOKENS..=MAX_HARNESS_MAX_TOKENS).contains(&n)
            {
                return Err(config_err(format!(
                    "{ENV_HARNESS_MAX_TOKENS} must be a whole number of tokens from {MIN_HARNESS_MAX_TOKENS} to {MAX_HARNESS_MAX_TOKENS}, without separators"
                )));
            }
            cfg.max_tokens = n;
        }
        let v = getenv(ENV_HARNESS_CONCURRENCY);
        if !v.is_empty() {
            let n: usize = v.parse().map_err(|_| {
                config_err(format!(
                    "{ENV_HARNESS_CONCURRENCY} must be 1 to {}",
                    central_harness::app::dispatcher::MAX_CONCURRENCY
                ))
            })?;
            if !(1..=central_harness::app::dispatcher::MAX_CONCURRENCY).contains(&n) {
                return Err(config_err(format!(
                    "{ENV_HARNESS_CONCURRENCY} must be 1 to {}",
                    central_harness::app::dispatcher::MAX_CONCURRENCY
                )));
            }
            cfg.concurrency = n;
        }
        let v = getenv(ENV_HARNESS_MIN_FREE);
        if !v.is_empty() {
            cfg.min_free = parse_byte_size(&v)?;
        }
        let v = getenv(ENV_HARNESS_CLAUDE_VERSION);
        if !v.is_empty() {
            if !is_pinned_version(&v) {
                return Err(config_err(format!(
                    "{ENV_HARNESS_CLAUDE_VERSION} must look like 1.2.3"
                )));
            }
            cfg.claude_version = v;
        }
        let v = getenv(ENV_HARNESS_BACKEND);
        if !v.is_empty() {
            cfg.backend = match v.as_str() {
                "claude-code" => Backend::ClaudeCode,
                "opencode" => Backend::Opencode,
                "codex" => Backend::Codex,
                "antigravity" => Backend::Antigravity,
                _ => {
                    return Err(config_err(format!(
                        "{ENV_HARNESS_BACKEND} must be claude-code, opencode, codex or antigravity"
                    )));
                }
            };
        }
        let v = getenv(ENV_HARNESS_OPENCODE_VERSION);
        if !v.is_empty() {
            if !is_pinned_version(&v) {
                return Err(config_err(format!(
                    "{ENV_HARNESS_OPENCODE_VERSION} must look like 1.2.3"
                )));
            }
            cfg.opencode_version = v;
        }
        let v = getenv(ENV_HARNESS_CODEX_VERSION);
        if !v.is_empty() {
            if !is_pinned_version(&v) {
                return Err(config_err(format!(
                    "{ENV_HARNESS_CODEX_VERSION} must look like 1.2.3"
                )));
            }
            cfg.codex_version = v;
        }
        let v = getenv(ENV_HARNESS_ANTIGRAVITY_VERSION);
        if !v.is_empty() {
            if !is_pinned_version(&v) {
                return Err(config_err(format!(
                    "{ENV_HARNESS_ANTIGRAVITY_VERSION} must look like 1.2.3"
                )));
            }
            cfg.antigravity_version = v;
        }
        if !cfg.backend.reports_cost() {
            // A tokens-only backend reports no cost, so an explicit
            // cost limit would run silently unenforced: refuse it
            // fail-closed. Unset variables keep their inert defaults.
            for cost_var in [ENV_HARNESS_MAX_COST_USD, ENV_HARNESS_TASK_COST_CAP_USD] {
                if !getenv(cost_var).is_empty() {
                    return Err(config_err(format!(
                        "{cost_var} must be unset when {ENV_HARNESS_BACKEND} is {}: the {} backend reports no cost, so a cost limit cannot be enforced",
                        cfg.backend.as_str(),
                        cfg.backend.as_str()
                    )));
                }
            }
        }
        let v = getenv(ENV_HARNESS_OPERATOR_UID);
        let uid: i64 = v.parse().map_err(|_| {
            config_err(format!(
                "{ENV_HARNESS_OPERATOR_UID} must be the operator's numeric, non-root uid"
            ))
        })?;
        if uid <= 0 {
            return Err(config_err(format!(
                "{ENV_HARNESS_OPERATOR_UID} must be the operator's numeric, non-root uid"
            )));
        }
        if uid > i64::from(u32::MAX - 1) {
            return Err(config_err(format!(
                "{ENV_HARNESS_OPERATOR_UID} must be at most {} (the largest non-reserved uid)",
                u32::MAX - 1
            )));
        }
        cfg.operator_uid = uid as u32;
        Ok(cfg)
    }

    /// `WorktreeRoot` — `DataRoot/worktrees` (the host launcher's
    /// worktree root; must match the daemon's configuration).
    #[must_use]
    pub fn worktree_root(&self) -> PathBuf {
        self.data_root.join("worktrees")
    }

    /// `ProbeWorkDir` — `DataRoot/probe` (the launcher's version/auth
    /// probe workdir; must not lie beneath `worktree_root`).
    #[must_use]
    pub fn probe_work_dir(&self) -> PathBuf {
        self.data_root.join("probe")
    }

    /// `LaunchEnv` — the launch environment every attempt gets:
    /// `PATH` exactly as configured (upstream `cfg.LaunchEnv`).
    #[must_use]
    pub fn launch_env(&self) -> BTreeMap<String, String> {
        let mut vars = BTreeMap::new();
        vars.insert("PATH".to_string(), self.path.clone());
        vars
    }
}

// ---------------------------------------------------------------------------
// Launcher selection — issue #120 / issue #124
// ---------------------------------------------------------------------------

/// Which launcher the serve composition builds. The real
/// `central-harness-launcher` daemon client is the DEFAULT and only
/// production launcher; `localexec` exists only behind
/// `CENTRAL_LOCALEXEC=1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LauncherSelection {
    /// `hostlauncher.NewSocket` — the root daemon over its fixed
    /// socket (ADR 0036). The production default.
    Real,
    /// `localexec.New` — development only, and only when
    /// `CENTRAL_LOCALEXEC=1` is set in the environment.
    LocalExec,
}

/// The issue-#120 selection rule, pure and env-testable: `Real`
/// unless `CENTRAL_LOCALEXEC=1` is explicitly set. Every other value
/// (including `0`, `true`, `yes`) keeps the real launcher — upstream
/// tests pin that only the exact `1` admits localexec.
#[must_use]
pub fn select_launcher(getenv: impl Fn(&str) -> LauncherSelectionArgs<'_>) -> LauncherSelection {
    match getenv(ENV_LOCALEXEC) {
        LauncherSelectionArgs("1") => LauncherSelection::LocalExec,
        _ => LauncherSelection::Real,
    }
}

/// New-type so `select_launcher` reads like upstream's `getenv`
/// while staying `Copy` for the test matrix.
#[derive(Debug, Clone, Copy)]
pub struct LauncherSelectionArgs<'a>(pub &'a str);

/// `newHarnessHostLauncher` — builds the production launcher. The
/// injected `client` is the audited CHL1 socket transport
/// (`harnesslauncher.NewClient` upstream); `HostLauncher::new`
/// validates `worktree_root`/`probe_work_dir` exactly like upstream.
///
/// # Errors
/// Propagates [`HostLauncher::new`]'s config refusal.
pub fn build_host_launcher(
    cfg: &HarnessConfig,
    client: Arc<dyn client::LauncherClient>,
) -> Result<Arc<dyn ProcessLauncher>, Failure> {
    let launcher = HostLauncher::new(
        client::Config {
            worktree_root: cfg.worktree_root(),
            probe_work_dir: cfg.probe_work_dir(),
        },
        client,
    )?;
    Ok(Arc::new(launcher))
}

/// `localexec.New` — the dev-gated launcher. `LocalExec::new` itself
/// refuses unless `CENTRAL_LOCALEXEC=1`; the kernel additionally
/// refuses to even reach it unless [`select_launcher`] chose it, so
/// a config path that forgot the check cannot get a localexec.
///
/// # Errors
/// `harness_config_invalid` when the selection is not `LocalExec`;
/// otherwise `LocalExec::new`'s `localexec_dev_gate_required` /
/// `localexec_invalid_config` failures.
pub fn build_localexec_launcher(
    cfg: &HarnessConfig,
    selection: LauncherSelection,
    signals: Arc<dyn localexec::GroupSignals>,
    programs: BTreeMap<String, PathBuf>,
) -> Result<Arc<dyn ProcessLauncher>, Failure> {
    if selection != LauncherSelection::LocalExec {
        return Err(Failure::denied(
            localexec::codes::DEV_GATE_REQUIRED,
            "localexec selected without the CENTRAL_LOCALEXEC=1 dev gate (issue #120)",
        ));
    }
    let launcher = LocalExec::new(
        localexec::Config {
            operator_uid: cfg.operator_uid,
            programs,
            kill_grace: std::time::Duration::ZERO,
        },
        signals,
    )?;
    Ok(Arc::new(launcher))
}

// ---------------------------------------------------------------------------
// Bootstrap selection — the R3 D1/R5 deferral
// ---------------------------------------------------------------------------

/// `bootstrapFile` — the protected bootstrap the session service
/// consumes. In production the broker-backed bootstrap supplies it;
/// under the explicit dev gate the file-backed
/// [`DevFileProtectedBootstrap`] stands in (R3 D1).
#[must_use]
pub enum BootstrapSelection {
    /// `CENTRAL_LOCALEXEC=1` dev path — the file-backed bootstrap.
    Dev(DevFileProtectedBootstrap),
    /// Broker-backed bootstrap — R5, not available in this slice.
    Broker,
}

/// The dev-gated bootstrap rule: `CENTRAL_LOCALEXEC=1` returns the
/// file-backed bootstrap at `root`; anything else fails closed —
/// the broker-backed bootstrap is deferred to R5 and serve must not
/// silently accept a substitute.
///
/// # Errors
/// `harness_config_invalid` ([`FailureKind::Denied`] under the hood
/// for the gate refusal — classified `CONFIG_INVALID` at the serve
/// boundary) when the dev gate is unset; propagates
/// [`DevFileProtectedBootstrap::new`] errors otherwise.
pub fn select_bootstrap(
    getenv: impl Fn(&str) -> Option<std::ffi::OsString>,
    root: &Path,
) -> Result<DevFileProtectedBootstrap, Failure> {
    let gate_open = getenv(ENV_LOCALEXEC).is_some_and(|v| v == "1");
    if !gate_open {
        return Err(Failure::denied(
            ERR_HARNESS_CONFIG,
            "session bootstrap requires the broker-backed protected bootstrap (deferred to R5); set CENTRAL_LOCALEXEC=1 for the file-backed development bootstrap",
        ));
    }
    DevFileProtectedBootstrap::new(root).map_err(session_failure)
}

/// Maps a session-contract failure onto the foundation taxonomy the
/// kernel classifies exits with. The session `reason` is already
/// redacted-safe; the class becomes the foundation kind/code.
pub(crate) fn session_failure(f: central_session::contract::Failure) -> Failure {
    use central_session::contract::FailureClass;
    let (kind, code) = match f.class {
        Some(FailureClass::CsrfInvalid | FailureClass::BootstrapInvalid) => {
            (FailureKind::Invalid, f.class.map(|c| c.as_str()))
        }
        Some(FailureClass::BootstrapThrottled) => {
            (FailureKind::Conflict, f.class.map(|c| c.as_str()))
        }
        Some(FailureClass::SessionInvalidated | FailureClass::AuthorityDenied) => {
            (FailureKind::Denied, f.class.map(|c| c.as_str()))
        }
        None => (FailureKind::Internal, None),
    };
    Failure::new(kind, code.unwrap_or("session_bootstrap_failed"), f.reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> String {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        move |name| map.get(name).cloned().unwrap_or_default()
    }

    fn enabled_env() -> Vec<(&'static str, &'static str)> {
        vec![
            (ENV_HARNESS_ENABLED, "1"),
            (ENV_HARNESS_ELIGIBLE_AFTER, "2026-10-23T00:00:00Z"),
            (ENV_HARNESS_OPERATOR_UID, "1000"),
        ]
    }

    #[test]
    fn disabled_by_default() {
        let cfg = HarnessConfig::load(env_of(&[])).unwrap();
        assert!(!cfg.enabled);
        assert_eq!(cfg.backend, Backend::ClaudeCode);
        assert_eq!(cfg.data_root, PathBuf::from(DEFAULT_HARNESS_DATA_ROOT));
        assert_eq!(cfg.concurrency, 1);
        assert_eq!(cfg.max_attempts, 3);
        assert_eq!(cfg.max_cost_micro_usd, 5_000_000);
        assert_eq!(cfg.task_cost_cap_micro_usd, 25_000_000);
        assert_eq!(cfg.max_tokens, 0);
    }

    #[test]
    fn enabled_requires_eligible_after() {
        let err = HarnessConfig::load(env_of(&[
            (ENV_HARNESS_ENABLED, "1"),
            (ENV_HARNESS_OPERATOR_UID, "1000"),
        ]))
        .unwrap_err();
        assert_eq!(err.code(), ERR_HARNESS_CONFIG);
    }

    #[test]
    fn enabled_validates_operator_uid() {
        for bad in ["0", "-1", "abc", "4294967295"] {
            let mut pairs = enabled_env();
            pairs.push((ENV_HARNESS_OPERATOR_UID, bad));
            let env: Vec<(&str, &str)> = pairs;
            let err = HarnessConfig::load(env_of(&env)).unwrap_err();
            assert_eq!(err.code(), ERR_HARNESS_CONFIG, "uid {bad}");
        }
    }

    #[test]
    fn enabled_accepts_valid_env() {
        let mut pairs = enabled_env();
        pairs.extend([
            (ENV_HARNESS_CONCURRENCY, "4"),
            (ENV_HARNESS_MAX_ATTEMPTS, "10"),
            (ENV_HARNESS_WALL_CLOCK, "1h"),
            (ENV_HARNESS_MIN_FREE, "2GiB"),
            (ENV_HARNESS_BACKEND, "opencode"),
            (ENV_HARNESS_OPENCODE_VERSION, "1.18.32"),
            (ENV_HARNESS_MAX_COST_USD, "10.00"),
        ]);
        let cfg = HarnessConfig::load(env_of(&pairs)).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.concurrency, 4);
        assert_eq!(cfg.max_attempts, 10);
        assert_eq!(cfg.wall_clock, Duration::hours(1));
        assert_eq!(cfg.min_free, 2 << 30);
        assert_eq!(cfg.backend, Backend::Opencode);
        assert_eq!(cfg.max_cost_micro_usd, 10_000_000);
        assert_eq!(cfg.task_cost_cap_micro_usd, 50_000_000);
    }

    #[test]
    fn tokens_only_backend_refuses_cost_vars() {
        for backend in ["codex", "antigravity"] {
            let mut pairs = enabled_env();
            pairs.extend([
                (ENV_HARNESS_BACKEND, backend),
                (ENV_HARNESS_MAX_COST_USD, "10.00"),
            ]);
            let err = HarnessConfig::load(env_of(&pairs)).unwrap_err();
            assert_eq!(err.code(), ERR_HARNESS_CONFIG, "backend {backend}");
        }
        // Without explicit cost vars the tokens-only backend is fine.
        let mut pairs = enabled_env();
        pairs.push((ENV_HARNESS_BACKEND, "codex"));
        assert!(HarnessConfig::load(env_of(&pairs)).is_ok());
    }

    #[test]
    fn task_cap_never_below_per_run() {
        let mut pairs = enabled_env();
        pairs.extend([
            (ENV_HARNESS_MAX_COST_USD, "10.00"),
            (ENV_HARNESS_TASK_COST_CAP_USD, "5.00"),
        ]);
        let err = HarnessConfig::load(env_of(&pairs)).unwrap_err();
        assert_eq!(err.code(), ERR_HARNESS_CONFIG);
    }

    #[test]
    fn real_launcher_is_the_default() {
        // Unset gate, `0`, `true`, `yes` — everything but exact `1`
        // keeps the production host launcher.
        for v in [None, Some("0"), Some("true"), Some("yes"), Some("")] {
            let sel = select_launcher(|_| match v {
                Some(s) => LauncherSelectionArgs(s),
                None => LauncherSelectionArgs(""),
            });
            assert_eq!(sel, LauncherSelection::Real, "gate {v:?}");
        }
        let sel = select_launcher(|_| LauncherSelectionArgs("1"));
        assert_eq!(sel, LauncherSelection::LocalExec);
    }

    #[test]
    fn localexec_build_refused_without_selection() {
        let cfg = HarnessConfig::load(env_of(&enabled_env())).unwrap();
        let signals: Arc<dyn localexec::GroupSignals> = Arc::new(NoSignals);
        let result =
            build_localexec_launcher(&cfg, LauncherSelection::Real, signals, BTreeMap::new());
        let err = result
            .err()
            .expect("localexec without dev gate must be refused");
        assert_eq!(err.code(), localexec::codes::DEV_GATE_REQUIRED);
    }

    #[test]
    fn bootstrap_fail_closed_without_gate() {
        let err = select_bootstrap(|_| None, Path::new("/tmp/x")).unwrap_err();
        assert_eq!(err.code(), ERR_HARNESS_CONFIG);
    }

    struct NoSignals;
    impl localexec::GroupSignals for NoSignals {
        fn group_alive(&self, _pgid: i64) -> bool {
            false
        }
        fn send_signal(&self, _pgid: i64, _sig: localexec::Signal) -> Result<(), Failure> {
            Ok(())
        }
    }
}
