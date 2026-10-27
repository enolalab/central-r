//! `internal/recovery/runner.go` — the runner that records what a C06 run
//! actually did, one outcome per catalogue entry, plus the skip census.
//!
//! Rust has neither `t.Run` subtests nor `t.SkipNow`, so the port keeps the
//! upstream invariants through the mechanisms Rust offers:
//!
//! - one `#[test]` fn per scenario calls [`Runner::run`]; the outcome is read
//!   out of `catch_unwind` (a panic is a failure) instead of `testing.T`'s
//!   bookkeeping;
//! - a skip decided before `run` goes through [`Runner::skip`], which records
//!   it in the census; every C06 entry is `required_for_scg3`, so a recorded
//!   skip is then a gate failure — reported by panicking, the libtest `FailNow`
//!   equivalent;
//! - [`Runner::require_armed`] is the one skip that produces no census entry:
//!   an unarmed run reaches no catalogue entry. It writes the notice to the
//!   real stderr (`std::io::stderr`, which libtest's output capture does not
//!   intercept) and returns `false`; the test body returns early.

use std::collections::HashMap;
use std::io::Write as _;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime};

use serde::Serialize;

use crate::catalogue::{self, Entry, Kind, ReasonClass};

/// `ArmEnv` — arms the C06 suite. Unset, the suite was not asked for and runs
/// nothing, records nothing and emits nothing.
pub const ARM_ENV: &str = "CENTRAL_C06_REFERENCE_HOST";

/// `COMPLETENESS_WAIT_ENV` — seconds an armed reconciling test waits for
/// every catalogue entry to record before reconciling whatever arrived.
///
/// Upstream's `TestMain` reconciles after `m.Run()` returns — the wait is
/// structural, not a timeout: every test is finished when it begins. libtest
/// gives this port no such hook and runs tests in parallel, so the `zz_*`
/// tests wait on the runner until each declared entry has an outcome. The
/// bound exists only for runs that cannot complete: a filtered suite
/// (`--skip`), or this interim slice whose Task 10b bodies do not exist yet.
/// Those reconcile to named missing entries, exactly as an upstream
/// `-test.run`-filtered armed run reconciles them. A full reference-host
/// run whose longest scenario approaches `BACKUP_CREATE_BUDGET` raises this
/// in the runbook rather than letting the default bound it.
pub const COMPLETENESS_WAIT_ENV: &str = "CENTRAL_C06_COMPLETENESS_WAIT_SECS";

/// The default bound: `helper::server::CEREMONY_BUDGET`'s 120s scale — long
/// enough for every live test this slice ships, short enough that an armed
/// suite missing bodies fails inside minutes rather than stalling.
pub const COMPLETENESS_WAIT_DEFAULT_SECS: u64 = 120;

/// `completeness_wait` — the bound, env-overridden in whole seconds.
pub fn completeness_wait() -> Duration {
    let seconds = std::env::var(COMPLETENESS_WAIT_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(COMPLETENESS_WAIT_DEFAULT_SECS);
    Duration::from_secs(seconds)
}

/// `armedByValue` — the arming decision itself, separated from the process
/// environment so it can be exercised over every value it must decide.
pub fn armed_by_value(value: Option<&str>) -> bool {
    match value {
        None => false,
        Some(raw) => {
            let trimmed = raw.trim();
            !trimmed.is_empty() && trimmed != "0"
        }
    }
}

/// `ArmedFromEnv` — the sanctioned way to answer "was the suite asked for".
pub fn armed_from_env() -> bool {
    armed_by_value(std::env::var(ARM_ENV).ok().as_deref())
}

/// `Result` — the outcome kind recorded for a catalogue entry. Only pass and
/// fail may reach the emitted evidence; skip reaches the census.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Result {
    Pass,
    Fail,
    Skip,
}

impl Result {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Skip => "skip",
        }
    }
}

/// `Outcome` — the single record a catalogue entry produces in a run.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub id: String,
    pub result: Result,
    /// Set only for a skip, and only from the closed vocabulary.
    pub reason_class: Option<ReasonClass>,
    /// Locator-free explanation of a skip.
    pub detail: String,
    /// The exact divergence from expectation on a failure.
    pub divergence: String,
    /// Digest of this entry's captured log (governance field 10).
    pub log_sha256: String,
    pub started_at: SystemTime,
    pub completed_at: SystemTime,
}

/// `CensusEntry` — one skip, with the reason class it was filed under.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct CensusEntry {
    pub id: String,
    pub reason_class: String,
    pub detail: String,
    pub required_for_sc_g3: bool,
}

/// `Census` — governance field 18's shape, derived from recorded outcomes.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct Census {
    pub count: usize,
    pub entries: Vec<CensusEntry>,
}

struct Inner {
    outcomes: Vec<Outcome>,
    logs: HashMap<String, String>,
    divergences: HashMap<String, String>,
}

/// `Runner` records what a C06 run actually did. It is the only sanctioned
/// way for a C06 scenario to skip: a skip that bypasses the census is a
/// failure rather than a skip.
pub struct Runner {
    catalogue: Vec<Entry>,
    armed: bool,
    inner: Mutex<Inner>,
    /// Signalled by `record` — `await_completeness` sleeps on it, so the
    /// reconcile gate sees the last outcome the moment it lands.
    recorded: Condvar,
}

static RUNNER: std::sync::OnceLock<Runner> = std::sync::OnceLock::new();

/// The process-wide runner over the installed catalogue — the whole of it,
/// always, armed from the process environment. There is deliberately no
/// public constructor taking a catalogue: a reconciliation is only a
/// statement about C06 if the catalogue it reconciles against is C06's.
pub fn runner() -> &'static Runner {
    RUNNER.get_or_init(|| Runner::new(installed(), armed_from_env()))
}

fn installed() -> Vec<Entry> {
    catalogue::installed_catalogue()
}

impl Runner {
    /// `newRunnerFor` — builds a runner over an arbitrary catalogue. Private:
    /// tests exercise reconciliation over a narrowed fixture catalogue, and
    /// nothing outside this module may narrow what reconciliation covers.
    fn new(catalogue: Vec<Entry>, armed: bool) -> Self {
        Self {
            catalogue,
            armed,
            inner: Mutex::new(Inner {
                outcomes: Vec::new(),
                logs: HashMap::new(),
                divergences: HashMap::new(),
            }),
            recorded: Condvar::new(),
        }
    }

    /// `Armed`.
    pub fn armed(&self) -> bool {
        self.armed
    }

    /// `Catalogue` — a copy, so the declaration cannot be edited through the
    /// runner.
    pub fn catalogue(&self) -> Vec<Entry> {
        self.catalogue.clone()
    }

    /// `RequireArmed` — the one skip that produces no census entry. Prints the
    /// unarmed notice to the real stderr and reports `false`; the caller
    /// returns without recording anything.
    pub fn require_armed(&self) -> bool {
        if self.armed {
            return true;
        }
        let _ = std::io::stderr().write_all(
            format!("recovery: {ARM_ENV} is not set; the C06 acceptance suite was not asked for\n")
                .as_bytes(),
        );
        false
    }

    /// `Run` — executes one catalogue scenario and records exactly one
    /// outcome for it. `body` receives a [`Scenario`]; a panic is a failure,
    /// and a body that returns `Err` is a failure carrying its divergence.
    pub fn run(
        &self,
        id: &str,
        body: impl FnOnce(&mut Scenario) -> std::result::Result<(), String>,
    ) {
        self.admit(id);
        let started = SystemTime::now();
        let mut handle = Scenario { id: id.to_owned() };
        let outcome = catch_unwind(AssertUnwindSafe(|| body(&mut handle)));
        let completed = SystemTime::now();
        let mut recorded = Outcome {
            id: id.to_owned(),
            result: Result::Pass,
            reason_class: None,
            detail: String::new(),
            divergence: String::new(),
            log_sha256: String::new(),
            started_at: started,
            completed_at: completed,
        };
        // The outcome is consumed once: a recorded panic re-raises after the
        // record lands, a recorded divergence fails the test body the same
        // way. Both are failures the census sees before the run unwinds.
        let mut raise: Option<Box<dyn std::any::Any + Send>> = None;
        let mut fail: Option<String> = None;
        match outcome {
            Ok(Ok(())) => {}
            Ok(Err(divergence)) => {
                recorded.result = Result::Fail;
                recorded.divergence = divergence.clone();
                fail = Some(divergence);
            }
            Err(payload) => {
                recorded.result = Result::Fail;
                let message = payload
                    .downcast_ref::<&str>()
                    .map(|s| (*s).to_owned())
                    .or_else(|| payload.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "panic".to_owned());
                recorded.divergence = format!("the scenario panicked: {message}");
                raise = Some(payload);
            }
        }
        self.record(recorded);
        if let Some(payload) = raise {
            resume_unwind(payload);
        }
        if let Some(divergence) = fail {
            panic!("{divergence}");
        }
    }

    /// `admit` — refuses an undeclared id or an unarmed run; both are
    /// failures rather than runs.
    fn admit(&self, id: &str) {
        if self.catalogue.iter().all(|e| e.id != id) {
            panic!(
                "recovery: {id:?} is not declared in the C06 catalogue; scenarios are declared data, not discovered functions, so nothing runs that the catalogue does not name"
            );
        }
        if !self.armed {
            panic!(
                "recovery: refusing to run {id:?} because {ARM_ENV} is not set; an unarmed run must record nothing and emit nothing"
            );
        }
    }

    /// `Skip` — records a skip and then refuses to proceed. A skip of an entry
    /// the gate requires fails (governance rule E-1); since every C06 entry is
    /// required, this records the outcome and then panics.
    ///
    /// `from_body` marks a call made from inside `run`'s scenario body — a
    /// skip decides whether the scenario runs at all and belongs before `run`,
    /// so an in-body call is refused rather than allowed to record a second
    /// outcome.
    pub fn skip(&self, id: &str, class: ReasonClass, detail: &str, from_body: bool) -> ! {
        if from_body {
            panic!(
                "recovery: skip({id:?}) was called from inside a scenario body; a skip decides whether a scenario runs at all and belongs before run, which is the only place it can produce one outcome rather than two"
            );
        }
        let entry = self
            .catalogue
            .iter()
            .find(|e| e.id == id)
            .unwrap_or_else(|| {
                panic!("recovery: cannot skip {id:?} because the C06 catalogue does not declare it")
            });
        if !self.armed {
            panic!(
                "recovery: refusing to record a skip for {id:?} because {ARM_ENV} is not set; an unarmed run must record nothing and emit nothing"
            );
        }
        let now = SystemTime::now();
        self.record(Outcome {
            id: entry.id.to_owned(),
            result: Result::Skip,
            reason_class: Some(class),
            detail: detail.to_owned(),
            divergence: String::new(),
            log_sha256: String::new(),
            started_at: now,
            completed_at: now,
        });
        if entry.required_for_scg3 {
            panic!(
                "recovery: {} is required for SC-G3 and was skipped (reason_class={}, detail={detail}); governance rule E-1: a skip recorded where the gate requires a run is a gate failure, not a caveat",
                entry.id,
                class.as_str()
            );
        }
        panic!(
            "recovery: {} skipped (reason_class={}): {detail}",
            entry.id,
            class.as_str()
        );
    }

    /// `record` appends an outcome, filling the log digest and divergence the
    /// scenario attached. A second outcome for the same entry is deliberately
    /// accepted: reconciliation is where that becomes a failure.
    fn record(&self, mut outcome: Outcome) {
        let mut inner = self.inner.lock().expect("runner poisoned");
        if outcome.log_sha256.is_empty()
            && let Some(log) = inner.logs.get(&outcome.id)
        {
            outcome.log_sha256 = log.clone();
        }
        if outcome.result == Result::Fail
            && outcome.divergence.is_empty()
            && let Some(divergence) = inner.divergences.get(&outcome.id)
        {
            outcome.divergence = divergence.clone();
        }
        inner.outcomes.push(outcome);
        drop(inner);
        self.recorded.notify_all();
    }

    /// `await_completeness` — blocks until every catalogue entry carries at
    /// least one outcome (the state upstream's `m.Run()`-then-reconcile
    /// reaches structurally) or `wait` elapses. Returns `true` only in the
    /// complete state; the caller reconciles either way, so a partial run
    /// fails with the same named entries either way.
    pub fn await_completeness(&self, wait: Duration) -> bool {
        let deadline = Instant::now() + wait;
        let mut guard = self.inner.lock().expect("runner poisoned");
        loop {
            let complete = self
                .catalogue
                .iter()
                .all(|e| guard.outcomes.iter().any(|o| o.id == e.id));
            if complete {
                return true;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            let (g, _) = self
                .recorded
                .wait_timeout(guard, left)
                .expect("runner poisoned");
            guard = g;
        }
    }

    /// `AttachDivergence` — records the divergence this entry carries if it
    /// fails. Attach it when the expectation is stated, before the check.
    pub fn attach_divergence(&self, id: &str, divergence: &str) {
        if self.catalogue.iter().all(|e| e.id != id) {
            panic!(
                "recovery: cannot attach a divergence to {id:?} because the C06 catalogue does not declare it; the entry it was meant for would emit a null divergence"
            );
        }
        self.inner
            .lock()
            .expect("runner poisoned")
            .divergences
            .insert(id.to_owned(), divergence.to_owned());
    }

    /// `AttachLog` — records the sha-256 of the log an entry captured.
    pub fn attach_log(&self, id: &str, sha256_hex: &str) {
        if self.catalogue.iter().all(|e| e.id != id) {
            panic!(
                "recovery: cannot attach a log to {id:?} because the C06 catalogue does not declare it; the digest would be attached to nothing"
            );
        }
        self.inner
            .lock()
            .expect("runner poisoned")
            .logs
            .insert(id.to_owned(), sha256_hex.to_owned());
    }

    /// `Outcomes` — a copy of every recorded outcome, in the order recorded.
    pub fn outcomes(&self) -> Vec<Outcome> {
        self.inner.lock().expect("runner poisoned").outcomes.clone()
    }

    /// `Census` — the skip census derived from recorded outcomes, in
    /// catalogue order.
    pub fn census(&self) -> Census {
        let outcomes = self.outcomes();
        let mut entries: Vec<CensusEntry> = outcomes
            .iter()
            .filter(|o| o.result == Result::Skip)
            .map(|o| CensusEntry {
                id: o.id.clone(),
                reason_class: o.reason_class.map(|c| c.as_str()).unwrap_or("").to_owned(),
                detail: o.detail.clone(),
                required_for_sc_g3: self
                    .catalogue
                    .iter()
                    .find(|e| e.id == o.id)
                    .map(|e| e.required_for_scg3)
                    .unwrap_or(false),
            })
            .collect();
        entries.sort_by_key(|e| catalogue::index_of(&e.id));
        Census {
            count: entries.len(),
            entries,
        }
    }

    /// `Reconcile` — the fail-if-unaccounted rule. Reports every problem at
    /// once; an unarmed run that reached reconciliation is itself a failure.
    pub fn reconcile(&self) -> std::result::Result<(), String> {
        let outcomes = self.outcomes();
        if !self.armed {
            if !outcomes.is_empty() {
                return Err(format!(
                    "recovery: the C06 suite was never armed ({ARM_ENV} is not set) yet recorded {} outcome(s); an unarmed run must record nothing and emit nothing",
                    outcomes.len()
                ));
            }
            return Err(format!(
                "recovery: the C06 suite was never armed ({ARM_ENV} is unset, empty or 0), so no catalogue entry ran and nothing was recorded; a run that did not happen is not a run that passed"
            ));
        }
        let mut problems: Vec<String> = Vec::new();
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for outcome in &outcomes {
            *counts.entry(outcome.id.as_str()).or_default() += 1;
            match self.catalogue.iter().find(|e| e.id == outcome.id) {
                None => problems.push(format!(
                    "an outcome was recorded for {:?}, which the C06 catalogue does not declare",
                    outcome.id
                )),
                Some(entry) => {
                    if outcome.result == Result::Skip && entry.required_for_scg3 {
                        problems.push(format!("{} is required for SC-G3 but was skipped (reason_class={}); governance rule E-1: a skip recorded where the gate requires a run is a gate failure", entry.id, outcome.reason_class.map(|c| c.as_str()).unwrap_or("")));
                    }
                }
            }
        }
        for entry in &self.catalogue {
            match counts.get(entry.id).copied().unwrap_or(0) {
                0 => problems.push(format!("{} ({}, {}) has no outcome: it was neither run nor accounted for", entry.id, entry.packet.as_str(), entry.kind.as_str())),
                n if n > 1 => problems.push(format!("{} has {n} outcomes; governance field 10 requires every declared scenario to appear exactly once, with no scenario duplicated", entry.id)),
                _ => {}
            }
        }
        if problems.is_empty() {
            return Ok(());
        }
        problems.sort();
        Err(format!(
            "recovery: C06 reconciliation failed:\n  - {}",
            problems.join("\n  - ")
        ))
    }
}

/// `ScenarioT` — the handle a scenario body is given. It carries the
/// catalogue id so helpers can attach logs/divergences; a `skip` call routed
/// through it is refused by [`Runner::skip`]'s `from_body` flag.
pub struct Scenario {
    /// The catalogue id this body is running as.
    pub id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn two_entry_catalogue() -> Vec<Entry> {
        vec![
            Entry {
                id: "test.one",
                packet: catalogue::Packet::C01,
                attribution: catalogue::AttributionSource::BySubject,
                kind: Kind::Scenario,
                boundary: "",
                preconditions: catalogue::Preconditions::ROOT,
                required_for_scg3: true,
                summary: "first",
            },
            Entry {
                id: "test.two",
                packet: catalogue::Packet::C02,
                attribution: catalogue::AttributionSource::BySubject,
                kind: Kind::Scenario,
                boundary: "",
                preconditions: catalogue::Preconditions::ROOT,
                required_for_scg3: false,
                summary: "second",
            },
        ]
    }

    #[test]
    fn arming_is_read_exactly_once_the_same_way() {
        assert!(!armed_by_value(None));
        assert!(!armed_by_value(Some("")));
        assert!(!armed_by_value(Some("0")));
        assert!(!armed_by_value(Some("  ")));
        assert!(armed_by_value(Some("1")));
        assert!(armed_by_value(Some("anything")));
    }

    #[test]
    fn an_unarmed_run_reconciles_as_a_failure() {
        let runner = Runner::new(two_entry_catalogue(), false);
        let err = runner.reconcile().expect_err("unarmed must fail");
        assert!(err.contains("never armed"), "{err}");
    }

    #[test]
    fn an_armed_run_reconciles_only_with_every_entry_accounted_for() {
        let runner = Runner::new(two_entry_catalogue(), true);
        let err = runner
            .reconcile()
            .expect_err("unaccounted entries must fail");
        assert!(err.contains("test.one"), "{err}");
        assert!(err.contains("test.two"), "{err}");
    }
}
