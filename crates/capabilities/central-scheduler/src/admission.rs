//! Admission — the spec-8 concurrency and resource-limit policy
//! (P2B06): the installed cap table ([`ConcurrencyProfile`] — the
//! `RecoveryProfile` analogue, narrowable but never widened past
//! compiled bounds), the pure dispatch-admission check modeled on
//! `backup.CheckBackupAdmission`, and the mid-session ceiling-breach
//! predicate. Pure domain — measured quantities only, never a path,
//! credential, or object key (spec-8 snapshot rule).
//!
//! Port of `central/internal/scheduler/admission.go`.
//!
//! OWNING PACKET: P2B06. SLICE: 2B.

use std::fmt;

use time::Duration;

// ---------------------------------------------------------------------------
// Compiled bounds — spec-8 cap table defaults, never widen
// ---------------------------------------------------------------------------

/// The global host cap on live session attempts (locked default 4;
/// operator instance config may narrow only).
pub const SUPPORTED_MAX_PARALLEL_SESSIONS: i32 = 4;
/// The per-run inflight cap (OQ-3: equal to `max_parallel_sessions` —
/// one run may saturate the host, FIFO serializes).
pub const SUPPORTED_MAX_INFLIGHT_NODES: i32 = SUPPORTED_MAX_PARALLEL_SESSIONS;
/// Bounds a run's graph (locked default 64); enforced at child-spec
/// validation, declared here so the profile carries the full table.
pub const SUPPORTED_MAX_NODES_PER_RUN: i32 = 64;
/// Bounds graph depth (locked default 3); likewise enforced at
/// child-spec validation.
pub const SUPPORTED_MAX_DEPTH: i32 = 3;
/// The `'worktree'` workspace disk budget (OQ-2: 8 GiB). Re-declares
/// the locked value the workspace-provisioning adapter stamps into each
/// workspace's `.central-workspace-budget` marker — a drift assertion
/// keeps them in step from the adapter side (a domain package may not
/// import the adapter).
pub const SUPPORTED_DISK_BUDGET_WORKTREE: u64 = 8 << 30;
/// The `'directory'` workspace disk budget (OQ-2: 4 GiB).
pub const SUPPORTED_DISK_BUDGET_DIRECTORY: u64 = 4 << 30;

/// The installed cap envelope (upstream `ConcurrencyProfile`) —
/// spec-8's `{scope, limit, default, overridable-by}` table flattened
/// to fields. `wall_clock_ceiling` and `cost_ceiling` are the
/// session-level defaults ADR 0035 assigns to the harness-adapter spec
/// (spec-8 OQ-1): zero means unset — no default ceiling is enforced,
/// while a per-attempt declared ceiling still enforces through
/// [`SessionCeilings`]/[`ceiling_breach`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ConcurrencyProfile {
    /// Global: live session attempts, host-wide.
    pub max_parallel_sessions: i32,
    /// Graph: live attempts of one run.
    pub max_inflight_nodes: i32,
    /// Graph: total nodes per run.
    pub max_nodes_per_run: i32,
    /// Graph: deepest node depth.
    pub max_depth: i32,
    /// Session wall-clock ceiling; `ZERO` = unset.
    pub wall_clock_ceiling: Duration,
    /// Harness-reported cost ceiling; `0.0` = unset.
    pub cost_ceiling: f64,
    /// Workspace disk cap for `'worktree'`.
    pub disk_budget_worktree: u64,
    /// Workspace disk cap for `'directory'`.
    pub disk_budget_directory: u64,
}

/// The spec-8 defaults (upstream `DefaultConcurrencyProfile`): 4
/// host-wide parallel sessions, 4 inflight nodes per run (OQ-3), 64
/// nodes per run, depth 3, 8 GiB / 4 GiB workspace disk budgets.
/// Session ceilings stay unset (OQ-1) — per-harness defaults belong to
/// the harness-adapter spec and per-attempt ceilings arrive declared,
/// never invented here.
impl Default for ConcurrencyProfile {
    fn default() -> Self {
        Self {
            max_parallel_sessions: SUPPORTED_MAX_PARALLEL_SESSIONS,
            max_inflight_nodes: SUPPORTED_MAX_INFLIGHT_NODES,
            max_nodes_per_run: SUPPORTED_MAX_NODES_PER_RUN,
            max_depth: SUPPORTED_MAX_DEPTH,
            wall_clock_ceiling: Duration::ZERO,
            cost_ceiling: 0.0,
            disk_budget_worktree: SUPPORTED_DISK_BUDGET_WORKTREE,
            disk_budget_directory: SUPPORTED_DISK_BUDGET_DIRECTORY,
        }
    }
}

/// Which cap field a refused [`ConcurrencyProfile`] violated — the
/// typed form of upstream `Validate`'s `fmt.Errorf` messages (`Display`
/// restates them verbatim).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileViolation {
    /// `max_parallel_sessions` outside `1..=4`.
    MaxParallelSessions,
    /// `max_inflight_nodes` outside `1..=4`.
    MaxInflightNodes,
    /// `max_nodes_per_run` outside `1..=64`.
    MaxNodesPerRun,
    /// `max_depth` outside `1..=3`.
    MaxDepth,
    /// A workspace disk budget of zero or above the compiled bound.
    WorkspaceDiskBudget,
    /// A negative session ceiling.
    SessionCeiling,
}

impl fmt::Display for ProfileViolation {
    /// Upstream `Validate`'s message strings, verbatim.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MaxParallelSessions => "invalid max_parallel_sessions",
            Self::MaxInflightNodes => "invalid max_inflight_nodes",
            Self::MaxNodesPerRun => "invalid max_nodes_per_run",
            Self::MaxDepth => "invalid max_depth",
            Self::WorkspaceDiskBudget => "invalid workspace disk budget",
            Self::SessionCeiling => "invalid session ceiling",
        })
    }
}

impl std::error::Error for ProfileViolation {}

impl ConcurrencyProfile {
    /// Refuses a profile that widens a compiled bound or carries a
    /// nonsensical value (upstream `Validate`) — the same narrow-only
    /// rule `RecoveryProfile.Validate` enforces. Session ceilings may
    /// be zero (unset) but never negative.
    pub fn validate(&self) -> Result<(), ProfileViolation> {
        if self.max_parallel_sessions < 1
            || self.max_parallel_sessions > SUPPORTED_MAX_PARALLEL_SESSIONS
        {
            return Err(ProfileViolation::MaxParallelSessions);
        }
        if self.max_inflight_nodes < 1 || self.max_inflight_nodes > SUPPORTED_MAX_INFLIGHT_NODES {
            return Err(ProfileViolation::MaxInflightNodes);
        }
        if self.max_nodes_per_run < 1 || self.max_nodes_per_run > SUPPORTED_MAX_NODES_PER_RUN {
            return Err(ProfileViolation::MaxNodesPerRun);
        }
        if self.max_depth < 1 || self.max_depth > SUPPORTED_MAX_DEPTH {
            return Err(ProfileViolation::MaxDepth);
        }
        if self.disk_budget_worktree == 0
            || self.disk_budget_worktree > SUPPORTED_DISK_BUDGET_WORKTREE
            || self.disk_budget_directory == 0
            || self.disk_budget_directory > SUPPORTED_DISK_BUDGET_DIRECTORY
        {
            return Err(ProfileViolation::WorkspaceDiskBudget);
        }
        if self.wall_clock_ceiling < Duration::ZERO || self.cost_ceiling < 0.0 {
            return Err(ProfileViolation::SessionCeiling);
        }
        Ok(())
    }

    /// Derives the default ceiling set for one workspace kind from the
    /// profile (upstream `SessionCeilings`): the kind's disk budget
    /// plus the (possibly unset) session defaults. An unknown kind
    /// carries no disk budget.
    #[must_use]
    pub fn session_ceilings(&self, workspace_kind: &str) -> SessionCeilings {
        let mut ceilings = SessionCeilings {
            wall_clock: self.wall_clock_ceiling,
            cost: self.cost_ceiling,
            disk_bytes: 0,
        };
        match workspace_kind {
            // v33 vocabulary; spec-8's 'code'.
            "worktree" => ceilings.disk_bytes = self.disk_budget_worktree,
            // spec-8's 'plain'.
            "directory" => ceilings.disk_bytes = self.disk_budget_directory,
            _ => {}
        }
        ceilings
    }
}

// ---------------------------------------------------------------------------
// Dispatch admission — spec-8 decision 2 + 6
// ---------------------------------------------------------------------------

/// The measured quantities one claim-time admission check consumes
/// (upstream `AdmissionSnapshot`, spec-8's CapacitySnapshot rule):
/// counts and bytes only — never a path, credential, or object key.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct AdmissionSnapshot {
    /// The host-wide count of live session attempts (states
    /// `claimed|provisioning|started`) measured inside the claim
    /// transaction.
    pub inflight_sessions: i32,
    /// The live-attempt count of the candidate's run, measured under
    /// the run-row lock.
    pub run_inflight_nodes: i32,
    /// The run's aggregated budget spent (spec-8 decision 3). `false`
    /// until run-budget accounting lands; a caller holding the
    /// aggregate passes the measured verdict.
    pub run_budget_exhausted: bool,
    /// Whether `free_bytes` is a real reading of the device hosting the
    /// candidate's workspace kind's root. `false` skips the floor check
    /// — the capacity-port wiring (spec-8's reuse of
    /// `port.Capacity.Admit`/`port.CapacityChecker.HasCapacity`)
    /// supplies it.
    pub disk_measured: bool,
    /// The measured free space on that device.
    pub free_bytes: u64,
    /// The reservation the candidate's workspace kind demands —
    /// `session_ceilings(ws_kind).disk_bytes`.
    pub disk_budget_bytes: u64,
}

/// The claim-time verdict (upstream `Admission`). `admit == false`
/// always carries [`REASON_CAPACITY_ADMISSION_DEFERRED`] — the one
/// deferral code spec-8 declares; `detail` names which cap refused for
/// the journaled payload and is diagnostic vocabulary, not a
/// wire-visible reason code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Admission {
    /// Whether the candidate may dispatch now.
    pub admit: bool,
    /// The deferral reason code; `None` when admitted.
    pub reason_code: Option<&'static str>,
    /// Which cap refused (`"invalid_profile"`, `"max_parallel_sessions"`,
    /// `"max_inflight_nodes"`, `"run_budget_exhausted"`, `"disk_budget"`);
    /// `None` when admitted.
    pub detail: Option<&'static str>,
}

/// Evaluates spec-8's admission check for one ready candidate against
/// the measured snapshot (upstream `CheckDispatchAdmission`). Deferral
/// order is fixed: an invalid profile fails closed, then the host cap,
/// then the run inflight cap, then the run budget, then the device
/// floor. A deferred node stays `ready` and keeps its FIFO position —
/// the scheduler journals `admission_deferred` and re-evaluates on
/// capacity-freeing events (spec-8 decision 6); deferral is never an
/// error and never consumes an `attempt_seq`.
#[must_use]
pub fn check_dispatch_admission(
    profile: &ConcurrencyProfile,
    snapshot: &AdmissionSnapshot,
) -> Admission {
    fn deferral(detail: &'static str) -> Admission {
        Admission {
            admit: false,
            reason_code: Some(REASON_CAPACITY_ADMISSION_DEFERRED),
            detail: Some(detail),
        }
    }
    if profile.validate().is_err() {
        return deferral("invalid_profile");
    }
    if snapshot.inflight_sessions >= profile.max_parallel_sessions {
        return deferral("max_parallel_sessions");
    }
    if snapshot.run_inflight_nodes >= profile.max_inflight_nodes {
        return deferral("max_inflight_nodes");
    }
    if snapshot.run_budget_exhausted {
        return deferral("run_budget_exhausted");
    }
    if snapshot.disk_measured
        && snapshot.disk_budget_bytes > 0
        && snapshot.free_bytes <= snapshot.disk_budget_bytes
    {
        return deferral("disk_budget");
    }
    Admission {
        admit: true,
        reason_code: None,
        detail: None,
    }
}

// ---------------------------------------------------------------------------
// Mid-session ceilings — spec-8 decision 7
// ---------------------------------------------------------------------------

/// One attempt's effective ceiling set (upstream `SessionCeilings`):
/// the profile default per axis, or the child-spec-narrowed value when
/// the launch envelope declared one (spec-8 decision 3 — a child may
/// narrow, never widen). A zero field means unset on that axis and
/// admits any usage.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct SessionCeilings {
    /// Wall-clock bound since `started_at`; `ZERO` = unset.
    pub wall_clock: Duration,
    /// Harness-reported cost bound; `0.0` = unset.
    pub cost: f64,
    /// Workspace byte bound; `0` = unset.
    pub disk_bytes: u64,
}

/// The live measured consumption of one attempt (upstream
/// `SessionUsage`) — elapsed wall clock since `started_at`, the
/// harness-reported cumulative cost (ADR 0035: Central never estimates
/// consumption; the figure or nothing), and the measured workspace
/// bytes when a measurement exists.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct SessionUsage {
    /// Wall clock since `started_at`.
    pub elapsed: Duration,
    /// The harness-reported cumulative cost.
    pub reported_cost: f64,
    /// Whether `disk_bytes` is a real measurement.
    pub disk_measured: bool,
    /// The measured workspace bytes.
    pub disk_bytes: u64,
}

/// A crossed ceiling (upstream `Breach`): the `attempt_failed` reason
/// code spec-8 declares for the axis, plus the axis name for
/// diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Breach {
    /// The spec-8 reason code.
    pub reason_code: &'static str,
    /// The breached axis (`"wall_clock"` | `"cost"` | `"disk"`).
    pub axis: &'static str,
}

/// Evaluates spec-8 decision 7 for one attempt (upstream
/// `CeilingBreach`): usage at or past a declared ceiling breaches it.
/// Axes evaluate in fixed order — wall clock, reported cost, workspace
/// disk — so a session crossing two ceilings at once reports the first
/// deterministically. Unset ceilings (0) and unmeasured disk never
/// breach.
#[must_use]
pub fn ceiling_breach(ceilings: &SessionCeilings, usage: &SessionUsage) -> Option<Breach> {
    if ceilings.wall_clock > Duration::ZERO && usage.elapsed >= ceilings.wall_clock {
        return Some(Breach {
            reason_code: REASON_SESSION_WALL_CLOCK_REACHED,
            axis: "wall_clock",
        });
    }
    if ceilings.cost > 0.0 && usage.reported_cost >= ceilings.cost {
        return Some(Breach {
            reason_code: REASON_SESSION_COST_CEILING_REACHED,
            axis: "cost",
        });
    }
    if ceilings.disk_bytes > 0 && usage.disk_measured && usage.disk_bytes >= ceilings.disk_bytes {
        return Some(Breach {
            reason_code: REASON_WORKSPACE_DISK_BUDGET_EXCEEDED,
            axis: "disk",
        });
    }
    None
}

/// Whether `code` is one of spec-8's mid-session breach codes
/// (upstream `CeilingBreachReason`) — the closed set
/// `record_ceiling_breach` accepts onto `attempt_failed`.
#[must_use]
pub fn ceiling_breach_reason(code: &str) -> bool {
    matches!(
        code,
        REASON_SESSION_WALL_CLOCK_REACHED
            | REASON_SESSION_COST_CEILING_REACHED
            | REASON_WORKSPACE_DISK_BUDGET_EXCEEDED
    )
}

// ---------------------------------------------------------------------------
// Reason codes — spec-8 failure semantics
// ---------------------------------------------------------------------------

/// `CAPACITY_ADMISSION_DEFERRED` — a claim-time admission refusal (host
/// or profile cap unavailable), journaled on `admission_deferred` while
/// the node stays `ready`.
pub const REASON_CAPACITY_ADMISSION_DEFERRED: &str = "CAPACITY_ADMISSION_DEFERRED";
/// `SESSION_WALL_CLOCK_REACHED` — an attempt past its wall-clock
/// ceiling; journaled on `attempt_failed`.
pub const REASON_SESSION_WALL_CLOCK_REACHED: &str = "SESSION_WALL_CLOCK_REACHED";
/// `SESSION_COST_CEILING_REACHED` — harness-reported usage crossing the
/// attempt's cost ceiling; journaled on `attempt_failed`.
pub const REASON_SESSION_COST_CEILING_REACHED: &str = "SESSION_COST_CEILING_REACHED";
/// `WORKSPACE_DISK_BUDGET_EXCEEDED` — workspace growth past
/// `disk_budget`; journaled on `attempt_failed`.
pub const REASON_WORKSPACE_DISK_BUDGET_EXCEEDED: &str = "WORKSPACE_DISK_BUDGET_EXCEEDED";
/// `INVALID_BREACH_CODE` — the store's boundary refusal for a
/// `record_ceiling_breach` call carrying a code outside the spec-8 set.
pub const REASON_INVALID_BREACH_CODE: &str = "INVALID_BREACH_CODE";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::REASON_LEASE_FENCE_STALE;

    // -- upstream admission_test.go: TestDefaultConcurrencyProfileIsValidAndSpec8

    /// Pins the spec-8 cap-table defaults and proves the installed
    /// default passes its own narrow-only validation.
    #[test]
    fn default_concurrency_profile_is_valid_and_spec8() {
        let p = ConcurrencyProfile::default();
        assert_eq!(p.max_parallel_sessions, 4);
        // OQ-3: per-run inflight equals the host cap.
        assert_eq!(p.max_inflight_nodes, p.max_parallel_sessions);
        assert_eq!(p.max_nodes_per_run, 64);
        assert_eq!(p.max_depth, 3);
        assert_eq!(p.disk_budget_worktree, 8 << 30);
        assert_eq!(p.disk_budget_directory, 4 << 30);
        // OQ-1: session ceilings stay unset at the profile level;
        // per-harness defaults belong to the harness-adapter spec.
        assert_eq!(p.wall_clock_ceiling, Duration::ZERO);
        assert_eq!(p.cost_ceiling, 0.0);
        assert!(p.validate().is_ok(), "default profile rejected");
    }

    // -- upstream admission_test.go: TestConcurrencyProfileValidateNarrowOnly

    /// Pins the narrow-only rule: every cap accepts a narrowed value
    /// and refuses both a widened one and a nonsensical one.
    /// `(name, mutate, want_err)` — the upstream mutation table.
    type ValidateCase = (&'static str, fn(&mut ConcurrencyProfile), bool);

    #[test]
    fn concurrency_profile_validate_narrow_only() {
        let cases: &[ValidateCase] = &[
            (
                "narrowed parallel sessions",
                |p| p.max_parallel_sessions = 2,
                false,
            ),
            (
                "widened parallel sessions",
                |p| p.max_parallel_sessions = 5,
                true,
            ),
            (
                "zero parallel sessions",
                |p| p.max_parallel_sessions = 0,
                true,
            ),
            ("widened inflight nodes", |p| p.max_inflight_nodes = 5, true),
            ("widened nodes per run", |p| p.max_nodes_per_run = 65, true),
            ("widened depth", |p| p.max_depth = 4, true),
            (
                "widened worktree budget",
                |p| p.disk_budget_worktree = 16 << 30,
                true,
            ),
            (
                "zeroed directory budget",
                |p| p.disk_budget_directory = 0,
                true,
            ),
            (
                "negative wall clock",
                |p| p.wall_clock_ceiling = Duration::seconds(-1),
                true,
            ),
            ("negative cost", |p| p.cost_ceiling = -1.0, true),
            (
                "set ceilings are legal",
                |p| {
                    p.wall_clock_ceiling = Duration::hours(1);
                    p.cost_ceiling = 12.5;
                },
                false,
            ),
        ];
        for (name, mutate, want_err) in cases {
            let mut p = ConcurrencyProfile::default();
            mutate(&mut p);
            assert_eq!(p.validate().is_err(), *want_err, "{name}");
        }
        // The typed violation names the same field upstream's message
        // does.
        let p = ConcurrencyProfile {
            max_depth: 4,
            ..Default::default()
        };
        assert_eq!(
            p.validate(),
            Err(ProfileViolation::MaxDepth),
            "violation must name the field"
        );
        assert_eq!(ProfileViolation::MaxDepth.to_string(), "invalid max_depth");
    }

    // -- upstream admission_test.go: TestCheckDispatchAdmissionMatrix -

    /// Pins the deferral axes and their boundaries: at-cap defers,
    /// below admits, and every refusal carries
    /// `CAPACITY_ADMISSION_DEFERRED`.
    #[test]
    fn check_dispatch_admission_matrix() {
        let p = ConcurrencyProfile::default(); // 4 host / 4 per-run inflight
        let cases: &[(&str, AdmissionSnapshot, bool, Option<&str>)] = &[
            (
                "empty host admits",
                AdmissionSnapshot::default(),
                true,
                None,
            ),
            (
                "host one below cap admits",
                AdmissionSnapshot {
                    inflight_sessions: 3,
                    ..Default::default()
                },
                true,
                None,
            ),
            (
                "host at cap defers",
                AdmissionSnapshot {
                    inflight_sessions: 4,
                    ..Default::default()
                },
                false,
                Some("max_parallel_sessions"),
            ),
            (
                "host over cap defers",
                AdmissionSnapshot {
                    inflight_sessions: 9,
                    ..Default::default()
                },
                false,
                Some("max_parallel_sessions"),
            ),
            (
                "run at inflight cap defers",
                AdmissionSnapshot {
                    run_inflight_nodes: 4,
                    ..Default::default()
                },
                false,
                Some("max_inflight_nodes"),
            ),
            (
                "run cap checked after host cap",
                AdmissionSnapshot {
                    inflight_sessions: 4,
                    run_inflight_nodes: 4,
                    ..Default::default()
                },
                false,
                Some("max_parallel_sessions"),
            ),
            (
                "exhausted run budget defers",
                AdmissionSnapshot {
                    run_budget_exhausted: true,
                    ..Default::default()
                },
                false,
                Some("run_budget_exhausted"),
            ),
            (
                "unmeasured disk never defers",
                AdmissionSnapshot {
                    disk_budget_bytes: 8 << 30,
                    ..Default::default()
                },
                true,
                None,
            ),
            (
                "disk above budget admits",
                AdmissionSnapshot {
                    disk_measured: true,
                    free_bytes: 9 << 30,
                    disk_budget_bytes: 8 << 30,
                    ..Default::default()
                },
                true,
                None,
            ),
            (
                "disk at budget defers",
                AdmissionSnapshot {
                    disk_measured: true,
                    free_bytes: 8 << 30,
                    disk_budget_bytes: 8 << 30,
                    ..Default::default()
                },
                false,
                Some("disk_budget"),
            ),
            (
                "disk below budget defers",
                AdmissionSnapshot {
                    disk_measured: true,
                    free_bytes: 1,
                    disk_budget_bytes: 8 << 30,
                    ..Default::default()
                },
                false,
                Some("disk_budget"),
            ),
        ];
        for (name, snapshot, want_admit, want_detail) in cases {
            let got = check_dispatch_admission(&p, snapshot);
            assert_eq!(got.admit, *want_admit, "{name} (detail {:?})", got.detail);
            if !got.admit {
                assert_eq!(
                    got.reason_code,
                    Some(REASON_CAPACITY_ADMISSION_DEFERRED),
                    "{name}"
                );
            }
            assert_eq!(got.detail, *want_detail, "{name}");
        }
    }

    // -- upstream admission_test.go: TestCheckDispatchAdmissionInvalidProfileFailsClosed

    /// Pins the fail-closed precedent: an installed-but-invalid profile
    /// defers every dispatch rather than admit against unverified
    /// bounds.
    #[test]
    fn check_dispatch_admission_invalid_profile_fails_closed() {
        let empty = ConcurrencyProfile {
            max_parallel_sessions: 0,
            max_inflight_nodes: 0,
            max_nodes_per_run: 0,
            max_depth: 0,
            wall_clock_ceiling: Duration::ZERO,
            cost_ceiling: 0.0,
            disk_budget_worktree: 0,
            disk_budget_directory: 0,
        };
        let got = check_dispatch_admission(&empty, &AdmissionSnapshot::default());
        assert!(!got.admit);
        assert_eq!(got.reason_code, Some(REASON_CAPACITY_ADMISSION_DEFERRED));
        assert_eq!(got.detail, Some("invalid_profile"));
    }

    // -- upstream admission_test.go: TestSessionCeilingsDerivesPerKind

    /// Pins the workspace-kind budget mapping (v33 vocabulary:
    /// `'worktree'`/`'directory'`).
    #[test]
    fn session_ceilings_derives_per_kind() {
        let p = ConcurrencyProfile {
            wall_clock_ceiling: Duration::hours(2),
            cost_ceiling: 5.0,
            ..Default::default()
        };
        let wt = p.session_ceilings("worktree");
        assert_eq!(wt.disk_bytes, 8 << 30);
        assert_eq!(wt.wall_clock, Duration::hours(2));
        assert_eq!(wt.cost, 5.0);
        assert_eq!(p.session_ceilings("directory").disk_bytes, 4 << 30);
        assert_eq!(
            p.session_ceilings("bogus").disk_bytes,
            0,
            "unknown kind carries no disk budget"
        );
    }

    // -- upstream admission_test.go: TestCeilingBreachAxes ------------

    /// Pins each breach axis at its boundary, the deterministic
    /// first-breach order, and the unset/unmeasured no-ops.
    #[test]
    fn ceiling_breach_axes() {
        let ceilings = SessionCeilings {
            wall_clock: Duration::hours(1),
            cost: 10.0,
            disk_bytes: 100,
        };
        let cases: &[(&str, SessionCeilings, SessionUsage, Option<&str>)] = &[
            (
                "below every ceiling",
                ceilings,
                SessionUsage {
                    elapsed: Duration::minutes(59),
                    reported_cost: 9.0,
                    disk_measured: true,
                    disk_bytes: 99,
                },
                None,
            ),
            (
                "wall clock at ceiling breaches",
                ceilings,
                SessionUsage {
                    elapsed: Duration::hours(1),
                    ..Default::default()
                },
                Some(REASON_SESSION_WALL_CLOCK_REACHED),
            ),
            (
                "wall clock past ceiling breaches",
                ceilings,
                SessionUsage {
                    elapsed: Duration::hours(2),
                    ..Default::default()
                },
                Some(REASON_SESSION_WALL_CLOCK_REACHED),
            ),
            (
                "unset wall clock never breaches",
                SessionCeilings {
                    cost: 10.0,
                    ..Default::default()
                },
                SessionUsage {
                    elapsed: Duration::hours(100),
                    ..Default::default()
                },
                None,
            ),
            (
                "cost at ceiling breaches",
                ceilings,
                SessionUsage {
                    reported_cost: 10.0,
                    ..Default::default()
                },
                Some(REASON_SESSION_COST_CEILING_REACHED),
            ),
            (
                "cost past ceiling breaches",
                ceilings,
                SessionUsage {
                    reported_cost: 10.5,
                    ..Default::default()
                },
                Some(REASON_SESSION_COST_CEILING_REACHED),
            ),
            (
                "unset cost never breaches",
                SessionCeilings::default(),
                SessionUsage {
                    reported_cost: 1e12,
                    ..Default::default()
                },
                None,
            ),
            (
                "disk at budget breaches",
                ceilings,
                SessionUsage {
                    disk_measured: true,
                    disk_bytes: 100,
                    ..Default::default()
                },
                Some(REASON_WORKSPACE_DISK_BUDGET_EXCEEDED),
            ),
            (
                "disk unmeasured never breaches",
                ceilings,
                SessionUsage {
                    disk_bytes: 1 << 40,
                    ..Default::default()
                },
                None,
            ),
            (
                "order: wall clock before cost",
                ceilings,
                SessionUsage {
                    elapsed: Duration::hours(1),
                    reported_cost: 10.0,
                    ..Default::default()
                },
                Some(REASON_SESSION_WALL_CLOCK_REACHED),
            ),
            (
                "order: cost before disk",
                ceilings,
                SessionUsage {
                    reported_cost: 10.0,
                    disk_measured: true,
                    disk_bytes: 100,
                    ..Default::default()
                },
                Some(REASON_SESSION_COST_CEILING_REACHED),
            ),
        ];
        for (name, ceilings, usage, want) in cases {
            let got = ceiling_breach(ceilings, usage);
            match want {
                None => assert!(got.is_none(), "{name}: breach = {got:?}"),
                Some(code) => {
                    let breach = got.expect("{name}: want breach");
                    assert_eq!(breach.reason_code, *code, "{name}");
                }
            }
        }
    }

    // -- upstream admission_test.go: TestCeilingBreachReasonSet -------

    /// Pins the closed spec-8 code set `record_ceiling_breach` accepts.
    #[test]
    fn ceiling_breach_reason_set() {
        for code in [
            REASON_SESSION_WALL_CLOCK_REACHED,
            REASON_SESSION_COST_CEILING_REACHED,
            REASON_WORKSPACE_DISK_BUDGET_EXCEEDED,
        ] {
            assert!(
                ceiling_breach_reason(code),
                "{code} should be a breach reason"
            );
        }
        for code in [
            "",
            REASON_CAPACITY_ADMISSION_DEFERRED,
            REASON_LEASE_FENCE_STALE,
            "WORKSPACE_PROVISION_FAILED",
        ] {
            assert!(
                !ceiling_breach_reason(code),
                "{code:?} must not be a breach reason"
            );
        }
    }
}
