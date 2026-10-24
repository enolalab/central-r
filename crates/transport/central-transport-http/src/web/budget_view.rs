//! Budget parsing and formatting (upstream `budget_view.go`) — harness
//! phase 3d/3j/3l display rules.

use std::collections::HashMap;

use central_task::domain::{
    Budget, MAX_BUDGET_COST_MICRO_USD, MAX_BUDGET_WALL_CLOCK_SECONDS, MIN_BUDGET_COST_MICRO_USD,
    parse_budget_cost_usd,
};

use super::harness::{HarnessRetryState, HarnessRunBudget};

// Operator-facing budget texts (phase 3d decision 9, phase 3l decision 7).
/// The cost-field note for a subscription login.
pub const BUDGET_SUBSCRIPTION_NOTE: &str = "For a subscription login the cost is Claude Code's own estimate, a proxy for quota use, not a charge.";
/// OpenCode's cost note.
pub const OPENCODE_COST_NOTE: &str =
    "OpenCode reports per-step cost in USD computed from token usage; free-tier models report 0.";
/// Codex's cost note (no cost reported, so no cost limit).
pub const CODEX_COST_NOTE: &str =
    "Codex reports token usage but no cost, so a cost limit cannot be enforced on this backend.";
/// Antigravity's cost note.
pub const ANTIGRAVITY_COST_NOTE: &str = "Antigravity reports token usage but no cost, so a cost limit cannot be enforced on this backend.";
/// "The harness stopped at its budget limit".
pub const BUDGET_REASON_HARNESS: &str = "The harness stopped at its budget limit";
/// "Central stopped the Run: the reported cost reached the limit".
pub const BUDGET_REASON_COST: &str = "Central stopped the Run: the reported cost reached the limit";
/// "Central stopped the Run: the wall clock limit was reached".
pub const BUDGET_REASON_WALL_CLOCK: &str =
    "Central stopped the Run: the wall clock limit was reached";
/// "Central stopped the Run: the billed tokens reached the token ceiling".
pub const BUDGET_REASON_TOKENS: &str =
    "Central stopped the Run: the billed tokens reached the token ceiling";
/// Replaces the Retry button of a failed Task whose Runs used the cost
/// cap (phase 3j decision 3).
pub const RETRY_UNAVAILABLE_COST_CAP: &str =
    "Retry is unavailable: this Task has used its cost cap";

/// `budgetReasonText` — the words for a budget failure reason, or `""`.
#[must_use]
pub fn budget_reason_text(reason: &str) -> &'static str {
    match reason {
        "harness_budget" => BUDGET_REASON_HARNESS,
        "budget_cost" => BUDGET_REASON_COST,
        "budget_wall_clock" => BUDGET_REASON_WALL_CLOCK,
        "budget_tokens" => BUDGET_REASON_TOKENS,
        _ => "",
    }
}

/// `parseBudgetForm` — the optional `budget_cost_usd` (dollars, ≤2
/// places) and `budget_wall_clock_minutes` (whole minutes) fields.
/// Returns `(budget, present)`; `None` on a repeated, malformed, or
/// out-of-range value.
#[must_use]
pub fn parse_budget_form(form: &HashMap<String, Vec<String>>) -> Option<(Budget, bool)> {
    for name in ["budget_cost_usd", "budget_wall_clock_minutes"] {
        if form.get(name).map_or(0, Vec::len) > 1 {
            return None;
        }
    }
    let mut budget = Budget::default();
    let mut present = false;
    let cost = super::form_value(form, "budget_cost_usd");
    if !cost.is_empty() {
        present = true;
        let micro = parse_budget_cost_usd(cost)?;
        if !(MIN_BUDGET_COST_MICRO_USD..=MAX_BUDGET_COST_MICRO_USD).contains(&micro) {
            return None;
        }
        budget.cost_micro_usd = micro;
    }
    let minutes_raw = super::form_value(form, "budget_wall_clock_minutes");
    if !minutes_raw.is_empty() {
        present = true;
        // `^[0-9]{1,5}$` — whole minutes only.
        if minutes_raw.len() > 5 || !minutes_raw.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let minutes: i64 = minutes_raw.parse().ok()?;
        if !(1..).contains(&minutes) || minutes * 60 > i64::from(MAX_BUDGET_WALL_CLOCK_SECONDS) {
            return None;
        }
        budget.wall_clock_seconds = (minutes * 60) as i32;
    }
    budget.validate().ok()?;
    Some((budget, present))
}

/// `formatUSD` — two places for whole cents, four otherwise; truncated
/// with integer arithmetic so a cost under a limit never reads as the
/// limit.
#[must_use]
pub fn format_usd(micro: i64) -> String {
    if micro % 10_000 == 0 {
        let cents = micro / 10_000;
        format!("US${}.{:02}", cents / 100, cents % 100)
    } else {
        let units = micro / 100; // ten-thousandths, truncated
        format!("US${}.{:04}", units / 10_000, units % 10_000)
    }
}

/// `formatCostAgainst` — a used cost next to its limit: at or under, it
/// is truncated; over, it is rounded up to the next ten-thousandth so a
/// cost just over US$0.50 reads US$0.5001, not US$0.5000.
#[must_use]
pub fn format_cost_against(used: i64, limit: i64) -> String {
    let used = if used > limit && used % 100 != 0 {
        used + (100 - used % 100)
    } else {
        used
    };
    format_usd(used)
}

/// `formatBudgetDuration` — a wall clock in minutes when whole.
#[must_use]
pub fn format_budget_duration(seconds: i64) -> String {
    if seconds > 0 && seconds % 60 == 0 {
        let m = seconds / 60;
        if m == 1 {
            "1 minute".to_string()
        } else {
            format!("{m} minutes")
        }
    } else {
        go_duration_string(seconds)
    }
}

/// Go `time.Duration.String()` for an integer-second value: the
/// seconds field always renders, the minutes and hours fields join
/// only while nonzero, and hours are the largest unit (Go renders no
/// days). `90` → `"1m30s"`, `3600` → `"1h0m0s"`, `3661` → `"1h1m1s"`,
/// `0` → `"0s"`, `-90` → `"-1m30s"`.
fn go_duration_string(seconds: i64) -> String {
    let mut u = seconds.unsigned_abs();
    let mut out = format!("{}s", u % 60);
    u /= 60;
    if u > 0 {
        out = format!("{}m{out}", u % 60);
        u /= 60;
        if u > 0 {
            out = format!("{u}h{out}");
        }
    }
    if seconds < 0 {
        out.insert(0, '-');
    }
    out
}

/// `costPlaceholder` — serve's default cost bound in the field's own
/// units (bare USD number, no `US$` prefix).
#[must_use]
pub fn cost_placeholder(micro: i64) -> String {
    format_usd(micro).trim_start_matches("US$").to_string()
}

/// `wallClockPlaceholder` — the default's whole-minute floor.
#[must_use]
pub fn wall_clock_placeholder(wall_clock: std::time::Duration) -> String {
    (wall_clock.as_secs() / 60).to_string()
}

/// `taskCostLine` — "Task cost used: US$<used> of US$<cap>" (phase 3j
/// decision 6); the used figure never reads as the cap unless it is.
#[must_use]
pub fn task_cost_line(st: &HarnessRetryState) -> String {
    let used = st.used_micro_usd.min(i64::MAX - 99);
    format!(
        "Task cost used: {} of {}",
        format_cost_against(used, st.cap_micro_usd),
        format_usd(st.cap_micro_usd)
    )
}

/// `runBudgetView` — task detail's budget section for a harness Run.
#[derive(Debug, Clone, Default)]
pub struct RunBudgetView {
    /// The recorded cost limit.
    pub cost_limit: String,
    /// Whether it was inherited from serve's default.
    pub cost_default: bool,
    /// The recorded wall-clock bound.
    pub wall_clock: String,
    /// Whether it was inherited.
    pub wall_clock_default: bool,
    /// Whether the harness reported usage.
    pub usage_reported: bool,
    /// Billed input tokens.
    pub tokens_in: String,
    /// Billed output tokens.
    pub tokens_out: String,
    /// Cache reads (hidden while `!cost_reported`).
    pub cache_read: String,
    /// Cache writes.
    pub cache_write: String,
    /// The reported cost, limit-aware.
    pub cost: String,
    /// Whether the cost is the harness's estimate.
    pub estimated: bool,
    /// A success over its limit.
    pub over_limit: bool,
    /// The number of attempts `cost` sums (named only above one).
    pub attempts: i32,
    /// Whether the cost and cache counters are real (not a live `0`).
    pub cost_reported: bool,
    /// Whether the latest attempt ended (no more reports will arrive).
    pub ended: bool,
}

/// `buildRunBudget` — `None` in, `None` out.
#[must_use]
pub fn build_run_budget(b: Option<&HarnessRunBudget>) -> Option<RunBudgetView> {
    let b = b?;
    Some(RunBudgetView {
        cost_limit: format_usd(b.cost_micro_usd),
        cost_default: b.cost_defaulted,
        wall_clock: format_budget_duration(b.wall_clock_seconds),
        wall_clock_default: b.wall_clock_defaulted,
        usage_reported: b.usage_reported,
        tokens_in: b.tokens_in.to_string(),
        tokens_out: b.tokens_out.to_string(),
        cache_read: b.cache_read.to_string(),
        cache_write: b.cache_write.to_string(),
        cost: format_cost_against(b.cost_used_micro_usd, b.cost_micro_usd),
        estimated: b.estimated,
        over_limit: b.succeeded && b.cost_used_micro_usd > b.cost_micro_usd,
        attempts: b.attempts,
        cost_reported: b.cost_reported,
        ended: b.ended,
    })
}
