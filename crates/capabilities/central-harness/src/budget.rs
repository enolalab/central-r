//! The per-attempt effective budget and the Run's chain cost — the port
//! of `internal/harness/budget.go` (harness phase 3d decisions 2 and 4,
//! phase 3g decision 9).
//!
//! The composition resolves a [`Budget`] at claim, from the Task's
//! requested budget or the serve default, and `Prepare` records it; it
//! never changes afterwards, so a later change to the serve defaults
//! never rewrites what an attempt ran under. [`sum_chain`] folds a Run's
//! recorded usage and [`ChainCost::next`] computes a resumed attempt's
//! budget.

use central_foundation::failure::Failure;
use serde::{Deserialize, Serialize};
use time::Duration;

use crate::attempt::Attempt;
use crate::domain::codes;

/// The effective budget one attempt runs under — upstream `Budget`.
/// `cost_micro_usd` bounds the cost the harness reports, in micro-USD;
/// the harness enforces it natively when its adapter declares
/// `Capabilities::native_cost_limit`, and Central backstops it for
/// adapters that report usage while the session is live. `wall_clock`
/// bounds the attempt's duration; Central's timer enforces it. The
/// `*_defaulted` flags record that the bound was inherited from the
/// serve default rather than asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Budget {
    /// The cost bound in micro-USD.
    pub cost_micro_usd: i64,
    /// The attempt's wall-clock bound.
    pub wall_clock: Duration,
    /// `true` when the cost bound came from the serve default.
    pub cost_defaulted: bool,
    /// `true` when the wall-clock bound came from the serve default.
    pub wall_clock_defaulted: bool,
}

/// `harness.MaxBudgetCostMicroUSD` — US$1,000 in micro-USD, the upper
/// bound of an effective [`Budget`]; migration b32 pins the same bound
/// in the `harness_attempts` CHECKs.
pub const MAX_BUDGET_COST_MICRO_USD: i64 = 1_000_000_000;

/// `harness.MaxBudgetWallClock` — one day.
pub const MAX_BUDGET_WALL_CLOCK: Duration = Duration::hours(24);

/// `harness.MinResumeCostMicroUSD` — the smallest cost budget a resumed
/// attempt may run under: US$0.01, the adapter's native minimum (harness
/// phase 3g decision 9).
pub const MIN_RESUME_COST_MICRO_USD: i64 = 10_000;

impl Budget {
    /// Upstream `Budget.Validate`: both bounds positive and within
    /// range. The lower bound is any positive value, because the serve
    /// configuration owns its own minimums.
    pub fn validate(&self) -> Result<(), Failure> {
        if self.cost_micro_usd <= 0 || self.cost_micro_usd > MAX_BUDGET_COST_MICRO_USD {
            return Err(Failure::invalid(
                codes::INVALID_ATTEMPT,
                format!("budget cost must be from 1 to {MAX_BUDGET_COST_MICRO_USD} micro-USD"),
            ));
        }
        if self.wall_clock <= Duration::ZERO || self.wall_clock > MAX_BUDGET_WALL_CLOCK {
            return Err(Failure::invalid(
                codes::INVALID_ATTEMPT,
                format!("budget wall clock must be positive and at most {MAX_BUDGET_WALL_CLOCK}"),
            ));
        }
        Ok(())
    }
}

/// One Run's budget and recorded cost — upstream `ChainCost` (harness
/// phase 3g decision 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainCost {
    /// The earliest-prepared attempt's recorded budget.
    pub root: Budget,
    /// Σ `usage.cost_micro_usd` over every attempt of the Run,
    /// saturating at `i64::MAX`.
    pub used_cost: i64,
    /// The number of attempts folded.
    pub attempts: usize,
}

impl ChainCost {
    /// Upstream `ChainCost.Remaining`: `root.cost_micro_usd - used_cost`;
    /// it may be ≤ 0.
    #[must_use]
    pub fn remaining(&self) -> i64 {
        self.root.cost_micro_usd - self.used_cost
    }

    /// Upstream `ChainCost.Next`: the next resumed attempt's budget —
    /// `root` with `cost_micro_usd` = [`remaining`](Self::remaining),
    /// keeping the root's wall clock and defaulted flags (the wall clock
    /// is per attempt). Below [`MIN_RESUME_COST_MICRO_USD`] it fails
    /// with `codes::CHAIN_BUDGET_EXHAUSTED`.
    pub fn next(&self) -> Result<Budget, Failure> {
        let remaining = self.remaining();
        if remaining < MIN_RESUME_COST_MICRO_USD {
            return Err(Failure::conflict(
                codes::CHAIN_BUDGET_EXHAUSTED,
                format!(
                    "{remaining} micro-USD remaining, at least {MIN_RESUME_COST_MICRO_USD} required"
                ),
            ));
        }
        let mut next = self.root;
        next.cost_micro_usd = remaining;
        Ok(next)
    }
}

/// Upstream `SumChain`: folds the Run's attempts (any order); `None` for
/// none. The root is the attempt with the earliest `prepared_at` (ties
/// broken by id string, as the store orders them), so a later attempt's
/// budget, prepared under a changed serve default or with the chain's
/// remaining cost, never replaces it.
pub fn sum_chain(attempts: &[Attempt]) -> Option<ChainCost> {
    let root = attempts.first()?;
    let mut root = root;
    let mut used: i64 = 0;
    for a in attempts {
        // Saturate: the adapter clamps a harness-supplied cost to
        // i64::MAX, and a wrapped sum would make `remaining` exceed the
        // root budget.
        used = used.saturating_add(a.usage.cost_micro_usd);
        if a.prepared_at < root.prepared_at
            || (a.prepared_at == root.prepared_at && a.id.to_string() < root.id.to_string())
        {
            root = a;
        }
    }
    Some(ChainCost {
        root: root.budget,
        used_cost: used,
        attempts: attempts.len(),
    })
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::attempt::Attempt;
    use crate::domain::{Fence, Terminal, TerminalStatus, codes};
    use crate::event::{Usage, UsageScope};
    use crate::testkit::{
        FENCE, bare_attempt, is_code, ok, prepare_input, running, t0, test_budget,
    };

    // Ports upstream `TestBudgetValidate`.
    #[test]
    fn budget_validate() {
        for b in [
            Budget {
                cost_micro_usd: 1,
                wall_clock: Duration::NANOSECOND,
                ..Budget::default()
            },
            Budget {
                cost_micro_usd: MAX_BUDGET_COST_MICRO_USD,
                wall_clock: MAX_BUDGET_WALL_CLOCK,
                ..Budget::default()
            },
            Budget {
                cost_micro_usd: 5_000_000,
                wall_clock: Duration::minutes(30),
                cost_defaulted: true,
                wall_clock_defaulted: true,
            },
        ] {
            assert!(b.validate().is_ok(), "{b:?}");
        }
        assert_eq!(MAX_BUDGET_COST_MICRO_USD, 1_000_000_000);
        assert_eq!(MAX_BUDGET_WALL_CLOCK, Duration::hours(24));
        let invalid: [(&str, Budget); 8] = [
            ("zero", Budget::default()),
            (
                "no cost",
                Budget {
                    wall_clock: Duration::minutes(1),
                    ..Budget::default()
                },
            ),
            (
                "negative cost",
                Budget {
                    cost_micro_usd: -1,
                    wall_clock: Duration::minutes(1),
                    ..Budget::default()
                },
            ),
            (
                "cost over the cap",
                Budget {
                    cost_micro_usd: MAX_BUDGET_COST_MICRO_USD + 1,
                    wall_clock: Duration::minutes(1),
                    ..Budget::default()
                },
            ),
            (
                "no wall clock",
                Budget {
                    cost_micro_usd: 1,
                    ..Budget::default()
                },
            ),
            (
                "negative wall",
                Budget {
                    cost_micro_usd: 1,
                    wall_clock: -Duration::SECOND,
                    ..Budget::default()
                },
            ),
            (
                "wall over a day",
                Budget {
                    cost_micro_usd: 1,
                    wall_clock: MAX_BUDGET_WALL_CLOCK + Duration::NANOSECOND,
                    ..Budget::default()
                },
            ),
            (
                "defaulted but zero",
                Budget {
                    cost_defaulted: true,
                    wall_clock_defaulted: true,
                    ..Budget::default()
                },
            ),
        ];
        for (name, b) in invalid {
            let err = b.validate().unwrap_err();
            assert!(is_code(&err, codes::INVALID_ATTEMPT), "{name}: err = {err}");
        }
    }

    // Ports upstream `TestPrepareRecordsAValidBudget`.
    #[test]
    fn prepare_records_a_valid_budget() {
        let mut input = prepare_input();
        input.budget = test_budget();
        let a = ok(Attempt::prepare(input.clone()));
        assert_eq!(a.budget, test_budget());
        input.budget = Budget::default();
        let err = Attempt::prepare(input.clone()).unwrap_err();
        assert!(
            is_code(&err, codes::INVALID_ATTEMPT),
            "prepare without a budget: {err}"
        );
        input.budget = Budget {
            cost_micro_usd: 1,
            wall_clock: Duration::hours(25),
            ..Budget::default()
        };
        let err = Attempt::prepare(input).unwrap_err();
        assert!(
            is_code(&err, codes::INVALID_ATTEMPT),
            "prepare with an out-of-range budget: {err}"
        );
    }

    // Ports upstream `TestEveryMutatorKeepsTheBudget`.
    #[test]
    fn every_mutator_keeps_the_budget() {
        let a = running();
        let want = a.budget;
        let steps = [
            ok(a.record_progress(FENCE, 1, t0())),
            ok(a.apply_usage(
                FENCE,
                Usage {
                    cost_micro_usd: want.cost_micro_usd * 2,
                    scope: UsageScope::SessionCumulative,
                    estimated: true,
                    ..Usage::default()
                },
                t0(),
            )),
            ok(a.await_permission(FENCE, "req-1", t0())),
            ok(a.terminate(
                FENCE,
                Terminal {
                    status: TerminalStatus::Budget,
                    reason: "budget_cost".to_string(),
                    exit_code: None,
                },
                t0(),
            )),
            ok(a.mark_ambiguous(FENCE, "lost", t0())),
            ok(a.refence(FENCE, Fence { generation: 2 }, t0())),
        ];
        for (i, got) in steps.iter().enumerate() {
            assert_eq!(got.budget, want, "step {i} changed the budget");
        }
        let mut tampered = a.clone();
        tampered.budget = Budget::default();
        let err = tampered.validate().unwrap_err();
        assert!(
            is_code(&err, codes::INVALID_ATTEMPT),
            "an attempt without a budget validated: {err}"
        );
    }

    // Ports upstream `TestSumChainPinsTheRootAndSumsRecordedCost`.
    #[test]
    fn sum_chain_pins_the_root_and_sums_recorded_cost() {
        assert_eq!(MIN_RESUME_COST_MICRO_USD, 10_000);
        assert!(sum_chain(&[]).is_none(), "sum_chain of no attempts");
        let root = Attempt {
            prepared_at: t0(),
            budget: Budget {
                cost_micro_usd: 1_000_000,
                wall_clock: Duration::minutes(20),
                cost_defaulted: true,
                wall_clock_defaulted: false,
            },
            usage: Usage {
                cost_micro_usd: 400_000,
                scope: UsageScope::SessionCumulative,
                ..Usage::default()
            },
            ..bare_attempt()
        };
        let second = Attempt {
            prepared_at: t0() + Duration::hours(1),
            // A later attempt's budget (a changed serve default, or the
            // remaining budget it was prepared with) never becomes the
            // root.
            budget: Budget {
                cost_micro_usd: 600_000,
                wall_clock: Duration::minutes(5),
                cost_defaulted: false,
                wall_clock_defaulted: true,
            },
            usage: Usage {
                cost_micro_usd: 250_000,
                scope: UsageScope::SessionCumulative,
                ..Usage::default()
            },
            ..bare_attempt()
        };
        let third = Attempt {
            prepared_at: t0() + Duration::hours(2),
            budget: Budget {
                cost_micro_usd: 350_000,
                wall_clock: Duration::minutes(5),
                ..Budget::default()
            },
            ..bare_attempt()
        };
        // The root is passed last: sum_chain folds in any order.
        let chain = sum_chain(&[third.clone(), second.clone(), root.clone()])
            .expect("sum_chain reported no attempts");
        assert_eq!(chain.root, root.budget);
        assert_eq!(chain.used_cost, 650_000);
        assert_eq!(chain.attempts, 3);
        assert_eq!(chain.remaining(), 350_000);
        let next = chain.next().unwrap();
        let want = Budget {
            cost_micro_usd: 350_000,
            ..root.budget
        };
        assert_eq!(next, want, "next must keep the root's clock and flags");

        for (name, used, want_err) in [
            ("exactly the floor remaining", 1_000_000 - 10_000, false),
            ("one below the floor", 1_000_000 - 9_999, true),
            ("used up", 1_000_000, true),
            ("overspent", 1_200_000, true),
        ] {
            let mut spent = root.clone();
            spent.usage.cost_micro_usd = used;
            let c = sum_chain(&[spent]).expect("sum_chain reported no attempts");
            assert_eq!(c.remaining(), 1_000_000 - used, "{name}");
            if want_err {
                let err = c.next().unwrap_err();
                assert!(
                    is_code(&err, codes::CHAIN_BUDGET_EXHAUSTED),
                    "{name}: Next error = {err}"
                );
            } else {
                let b = c.next().unwrap();
                assert_eq!(b.cost_micro_usd, MIN_RESUME_COST_MICRO_USD, "{name}");
                assert_eq!(b.wall_clock, root.budget.wall_clock, "{name}");
            }
        }

        // The adapter clamps a harness-supplied total_cost_usd to i64::MAX,
        // so the chain sum saturates rather than wrapping negative: a
        // wrapped sum would make Remaining exceed the root and Next grow
        // the budget.
        {
            let mut a = root.clone();
            a.usage.cost_micro_usd = i64::MAX;
            let mut b = second.clone();
            b.usage.cost_micro_usd = i64::MAX;
            let c = sum_chain(&[a, b]).expect("sum_chain reported no attempts");
            assert_eq!(c.used_cost, i64::MAX, "saturating sum");
            assert!(c.remaining() <= 0);
            let err = c.next().unwrap_err();
            assert!(
                is_code(&err, codes::CHAIN_BUDGET_EXHAUSTED),
                "saturated Next error = {err}"
            );
        }
        {
            let mut a = root.clone();
            a.usage.cost_micro_usd = i64::MAX - 5;
            let mut b = second;
            b.usage.cost_micro_usd = 3;
            let c = sum_chain(&[b, a]).expect("sum_chain reported no attempts");
            assert_eq!(c.used_cost, i64::MAX - 2, "near-max sum");
            let err = c.next().unwrap_err();
            assert!(
                is_code(&err, codes::CHAIN_BUDGET_EXHAUSTED),
                "near-max Next error = {err}"
            );
        }
    }
}
