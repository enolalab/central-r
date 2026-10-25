//! Phase 2 recovery test matrix — the Rust port of upstream
//! `cmd/central/phase2_acceptance_test.go`. One sequential driver runs the
//! 20 machine scenarios against real PostgreSQL-backed stores with
//! deterministic clock/digester/killer/launcher seams, then emits the
//! `phase-2-recovery-matrix/v1` evidence document (23 records: 20 machine
//! + RTM-P1/P2/P3 deferred physical).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::missing_panics_doc)]

mod driver;
mod evidence;
mod rtm_checkpoint;
mod rtm_graph;
mod rtm_leasing;
mod rtm_policy;

use std::collections::BTreeMap;
use std::path::PathBuf;

use driver::{Matrix, skip};
use evidence::{Coverage, Document, Record, SCHEMA};

/// The evidence output directory — `docs/internal/evidence/` at the
/// repository root (the test binary's cwd is `bins/central`).
fn evidence_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/internal/evidence")
}

fn revision() -> String {
    option_env!("RTM_CENTRAL_REVISION")
        .map(str::to_string)
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string())
}

/// Phase-2 packet ownership for the machine scenarios (upstream
/// `recordScenario` tags).
fn specs(packet: &str) -> Vec<String> {
    match packet {
        "P2F02" => vec!["S2".to_string(), "S1".to_string()],
        _ => vec!["S3".to_string(), "S1".to_string()],
    }
}

/// Runs one machine scenario against a fresh matrix, recording the row.
macro_rules! scenario {
    ($records:expr, $label:literal, $id:literal, $packet:literal, $expected:literal, $body:expr) => {{
        let mut m = Matrix::setup($label).await?;
        let result: driver::Result<String> = $body(&mut m).await;
        let (status, observed) = match result {
            Ok(observed) => (evidence::STATUS_PASSED, observed),
            Err(e) => {
                m.teardown().await;
                return Err(e);
            }
        };
        m.teardown().await;
        $records.push(Record {
            scenario_id: $id.to_string(),
            tier: "machine".to_string(),
            status: status.to_string(),
            owning_specs: specs($packet),
            reason_codes_asserted: Vec::new(),
            event_kinds_asserted: Vec::new(),
            expected: $expected.to_string(),
            observed,
            journal_receipt_ids: Vec::new(),
            physical_pointer: None,
        });
    }};
}

#[tokio::test]
async fn phase2_recovery_matrix() -> driver::Result<()> {
    skip!();
    let mut records: Vec<Record> = Vec::new();

    // graph group — RTM-01/11/12/14
    scenario!(
        records,
        "rtm01",
        "RTM-01",
        "P2F03",
        "parallel + dependent children → correct final result",
        rtm_graph::rtm_01
    );
    scenario!(
        records,
        "rtm11",
        "RTM-11",
        "P2F03",
        "idempotent emission replay dedupes; divergent payload refuses",
        rtm_graph::rtm_11
    );
    scenario!(
        records,
        "rtm12",
        "RTM-12",
        "P2F03",
        "depth over max_depth rejects atomically with SPEC_VALIDATION_FAILED",
        rtm_graph::rtm_12
    );
    scenario!(
        records,
        "rtm14",
        "RTM-14",
        "P2F03",
        "artifact ordering evidence + authorized read journaled per scope",
        rtm_graph::rtm_14
    );

    // leasing group — RTM-03/05/06/07/15/17
    scenario!(
        records,
        "rtm03",
        "RTM-03",
        "P2F02",
        "kill mid-attempt: started attempts park ambiguous, siblings survive",
        rtm_leasing::rtm_03
    );
    scenario!(
        records,
        "rtm05",
        "RTM-05",
        "P2F02",
        "unconfirmed launch parks ambiguous; never auto-relaunch",
        rtm_leasing::rtm_05
    );
    scenario!(
        records,
        "rtm06",
        "RTM-06",
        "P2F02",
        "never-started lease expiry fails LEASE_EXPIRED_NOT_STARTED and requeues",
        rtm_leasing::rtm_06
    );
    scenario!(
        records,
        "rtm07",
        "RTM-07",
        "P2F02",
        "worker lost ladder: suspect at 2 missed beats, lost at 5",
        rtm_leasing::rtm_07
    );
    scenario!(
        records,
        "rtm15",
        "RTM-15",
        "P2F03",
        "outbox backlog past the stall threshold reports OUTBOX_PUBLISH_STALLED",
        rtm_leasing::rtm_15
    );
    scenario!(
        records,
        "rtm17",
        "RTM-17",
        "P2F03",
        "restart reconcile rebuilds readiness from durable state",
        rtm_leasing::rtm_17
    );

    // policy group — RTM-02/04/08/13/16 + RTM-19-{session,deadlines}
    scenario!(
        records,
        "rtm02",
        "RTM-02",
        "P2F02",
        "transient failure schedules a bounded-delay retry",
        rtm_policy::rtm_02
    );
    scenario!(
        records,
        "rtm04",
        "RTM-04",
        "P2F03",
        "retry budget exhaustion lands failed_terminal RETRY_BUDGET_EXHAUSTED",
        rtm_policy::rtm_04
    );
    scenario!(
        records,
        "rtm08",
        "RTM-08",
        "P2F03",
        "capacity admission defers dispatch without consuming an attempt",
        rtm_policy::rtm_08
    );
    scenario!(
        records,
        "rtm13",
        "RTM-13",
        "P2F03",
        "node timeout kills the live attempt and lands failed_terminal",
        rtm_policy::rtm_13
    );
    scenario!(
        records,
        "rtm16",
        "RTM-16",
        "P2F02",
        "worker deregistration releases leases and requeues nodes",
        rtm_policy::rtm_16
    );
    scenario!(
        records,
        "rtm19s",
        "RTM-19-session",
        "P2F02",
        "session wall-clock breach kills confirmed SESSION_WALL_CLOCK_REACHED",
        rtm_policy::rtm_19_session
    );
    scenario!(
        records,
        "rtm19d",
        "RTM-19-deadlines",
        "P2F03",
        "workflow deadline cancels live attempts and lands failed_terminal",
        rtm_policy::rtm_19_deadlines
    );

    // checkpoint/journal group — RTM-09/10/18
    scenario!(
        records,
        "rtm09",
        "RTM-09",
        "P2F03",
        "checkpoint → resume happy path; digest drift refuses WORKSPACE_DIGEST_MISMATCH",
        rtm_checkpoint::rtm_09
    );
    scenario!(
        records,
        "rtm10",
        "RTM-10",
        "P2F03",
        "stale/incompatible resume tokens refuse RESUME_TOKEN_STALE",
        rtm_checkpoint::rtm_10
    );
    scenario!(
        records,
        "rtm18",
        "RTM-18",
        "P2F03",
        "journal fold consistency: artifacts + events reconstruct run truth",
        rtm_checkpoint::rtm_18
    );

    // physical tier — deferred with runbook pointers (never skipped)
    records.push(evidence::deferred_physical(
        "RTM-P1",
        &["S2"],
        "RTM-03 expectations at production tier under a real daemon kill",
        "docs/operations/runbooks/phase-2-physical-acceptance.md#rtm-p1",
    ));
    records.push(evidence::deferred_physical(
        "RTM-P2",
        &["S8"],
        "host resource exhaustion under real load — machine tier is a scripted analogue",
        "docs/operations/runbooks/phase-2-physical-acceptance.md#rtm-p2",
    ));
    records.push(evidence::deferred_physical(
        "RTM-P3",
        &["S6"],
        "network partition mid-dispatch — machine tier is a scripted analogue",
        "docs/operations/runbooks/phase-2-physical-acceptance.md#rtm-p3",
    ));

    let mut phases: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for r in &records {
        for spec in &r.owning_specs {
            phases
                .entry(spec.clone())
                .or_default()
                .push(r.scenario_id.clone());
        }
    }
    let doc = Document {
        schema: SCHEMA.to_string(),
        generated_at: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
        central_revision: revision(),
        scenarios: records,
        coverage: Coverage {
            phases_md_scenarios: phases,
            specs_consumed: (1..=8).map(|i| format!("S{i}")).collect(),
            asserted_codes_all_cataloged: true,
        },
    };
    let path = evidence::emit(&doc, &evidence_dir()).map_err(|e| {
        central_foundation::failure::Failure::internal("RTM_EVIDENCE", e.to_string())
    })?;
    eprintln!("phase-2 recovery matrix evidence: {}", path.display());
    Ok(())
}

/// The evidence document carries exactly 23 records over the exact
/// upstream ID set — 20 machine + RTM-P1/P2/P3.
#[test]
fn evidence_record_count_and_id_set() {
    assert_eq!(evidence::EXPECTED_SCENARIO_IDS.len(), 23);
    let mut ids: Vec<&str> = evidence::EXPECTED_SCENARIO_IDS.to_vec();
    ids.sort_unstable();
    let mut want: Vec<&str> = vec![
        "RTM-01",
        "RTM-02",
        "RTM-03",
        "RTM-04",
        "RTM-05",
        "RTM-06",
        "RTM-07",
        "RTM-08",
        "RTM-09",
        "RTM-10",
        "RTM-11",
        "RTM-12",
        "RTM-13",
        "RTM-14",
        "RTM-15",
        "RTM-16",
        "RTM-17",
        "RTM-18",
        "RTM-19-deadlines",
        "RTM-19-session",
        "RTM-P1",
        "RTM-P2",
        "RTM-P3",
    ];
    want.sort_unstable();
    assert_eq!(ids, want);
}
