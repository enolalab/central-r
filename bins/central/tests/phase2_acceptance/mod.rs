//! Phase 2 recovery test matrix — the Rust port of upstream
//! `cmd/central/phase2_acceptance_test.go`. One sequential driver runs the
//! 20 machine scenarios against real PostgreSQL-backed stores with
//! deterministic clock/digester/killer/launcher seams, then emits the
//! `phase-2-recovery-matrix/v1` evidence document (23 records: 20 machine
//! + RTM-P1/P2/P3 deferred physical).
//!
//! Upstream `t.Run` semantics are preserved: a scenario failure never
//! aborts the matrix — every scenario runs, its row records
//! `failed`/`passed` (an `INCONCLUSIVE`-prefixed observed records
//! `failed`), the evidence document emits unconditionally (the
//! `CENTRAL_PHASE2_EVIDENCE_DIR` gate decides the file write), and the
//! test fails only after all scenarios complete if any row failed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

mod driver;
mod evidence;
mod rtm_checkpoint;
mod rtm_graph;
mod rtm_leasing;
mod rtm_policy;

use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};

use driver::Matrix;
use evidence::{Coverage, Document, PrereqRecord, Record, SCHEMA};

/// `CENTRAL_PHASE2_EVIDENCE_DIR` — the upstream emission gate: when set,
/// the document lands at `<dir>/phase-2-recovery-matrix.json`; when
/// unset, the matrix still runs but writes nothing.
const EVIDENCE_ENV: &str = "CENTRAL_PHASE2_EVIDENCE_DIR";

/// The `git rev-parse` fallback order for `central_revision` /
/// `candidate_commit` (upstream reads `GITHUB_SHA` and fails closed when
/// evidence emission is requested without it).
fn revision() -> String {
    for var in ["GITHUB_SHA", "CENTRAL_CANDIDATE_COMMIT"] {
        if let Ok(v) = std::env::var(var)
            && !v.is_empty()
        {
            return v;
        }
    }
    std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unresolved-revision".to_string())
}

/// The rustc version the host profile fingerprints (upstream records
/// `go_version`; the Rust port records its compiler).
fn rustc_version() -> String {
    std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Per-scenario evidence metadata — the upstream `recordScenario` packet
/// + owning-spec pairs (transcribed from the upstream calls; scenario
///   bodies record their asserted codes/kinds live).
struct ScenarioMeta {
    packet: &'static str,
    owning_specs: &'static [&'static str],
    expected: &'static str,
}

const fn meta(
    packet: &'static str,
    owning_specs: &'static [&'static str],
    expected: &'static str,
) -> ScenarioMeta {
    ScenarioMeta {
        packet,
        owning_specs,
        expected,
    }
}

fn scenario_meta(id: &str) -> ScenarioMeta {
    match id {
        "RTM-01" => meta(
            "P2F03",
            &["S1", "S7"],
            "parallel children fan into a gated aggregator; every final artifact is journaled and resolvable",
        ),
        "RTM-02" => meta(
            "P2F02",
            &["S4", "S1"],
            "session crash requeues under backoff",
        ),
        "RTM-03" => meta(
            "P2F02",
            &["S2", "S1"],
            "kill loses no completed outputs; started attempts park ambiguous; reconcile precedes reinvoke",
        ),
        "RTM-04" => meta(
            "P2F03",
            &["S4"],
            "rate-limit hints are honored exactly within the cap and ignored off-class",
        ),
        "RTM-05" => meta(
            "P2F02",
            &["S2"],
            "suspect is observable-only; lost expires every held lease; clean shutdown releases",
        ),
        "RTM-06" => meta(
            "P2F02",
            &["S2", "S1"],
            "never-started expiry requeues under a new lease",
        ),
        "RTM-07" => meta(
            "P2F02",
            &["S2"],
            "mid-flight expiry parks ambiguous without requeue; the stale lease fences writes",
        ),
        "RTM-08" => meta(
            "P2F03",
            &["S5"],
            "exact replays dedupe observably; same-key different-payload replays conflict",
        ),
        "RTM-09" => meta(
            "P2F03",
            &["S3"],
            "legal writes resolve; the four refusals fail safe with codes; live anchors refuse writes",
        ),
        "RTM-10" => meta(
            "P2F03",
            &["S3", "S7"],
            "resume returns unfinished work claimable, parks in-flight ambiguity, and re-exposes reads without restoring payloads",
        ),
        "RTM-11" => meta(
            "P2F03",
            &["S1"],
            "cancel cascades: live nodes signal, ready/declared cancel, ambiguity parks while the cascade flows past",
        ),
        "RTM-12" => meta(
            "P2F03",
            &["S1", "S4"],
            "a cyclic batch rejects atomically naming the cycle; a corrected batch commits",
        ),
        "RTM-13" => meta(
            "P2F03",
            &["S4"],
            "budgets exhaust terminally; terminal classes land at once; managed hooks run once, unmanaged journal only",
        ),
        "RTM-14" => meta(
            "P2F03",
            &["S7", "S5"],
            "reads gate on finalization and scope; declare-or-flag journals undeclared reads",
        ),
        "RTM-15" => meta(
            "P2F03",
            &["S8", "S5"],
            "one slot admits one node and defers the other; the disk floor denies; stalls surface without corrupting transitions",
        ),
        "RTM-16" => meta(
            "P2F02",
            &["S2", "S4", "S5"],
            "timers skip ambiguity; the operator decision is idempotent; the rerun takes a new attempt_seq",
        ),
        "RTM-17" => meta(
            "P2F03",
            &["S8"],
            "saturation never starves: FIFO holds across re-evaluations and freeing dispatches",
        ),
        "RTM-18" => meta(
            "P2F03",
            &["S6"],
            "gaps and undeclared kinds flag; redelivery dedupes; every scenario run journals cataloged kinds",
        ),
        "RTM-19-session" => meta(
            "P2F02",
            &["S2", "S4", "S8"],
            "confirmed session kill requeues retryable; unconfirmed parks ambiguous",
        ),
        "RTM-19-deadlines" => meta(
            "P2F03",
            &["S4", "S2", "S8"],
            "expired node bounds land terminal; expired run bounds cancel and land; ambiguity skips both timers",
        ),
        _ => panic!("no evidence metadata for scenario {id}"),
    }
}

/// `CatchUnwind` — poll-wrapping future catching a panic inside the
/// scenario body (upstream's per-`t.Run` panic isolation: a panicking
/// scenario records failed and the matrix continues). No `futures`
/// dependency — the workspace forbids new deps — the wrapper polls the
/// boxed future under `catch_unwind`.
struct CatchUnwind<F: Future>(Pin<Box<F>>);

impl<F: Future> Future for CatchUnwind<F> {
    type Output = std::result::Result<F::Output, Box<dyn std::any::Any + Send>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match catch_unwind(AssertUnwindSafe(|| self.0.as_mut().poll(cx))) {
            Ok(Poll::Ready(v)) => Poll::Ready(Ok(v)),
            Ok(Poll::Pending) => Poll::Pending,
            Err(payload) => Poll::Ready(Err(payload)),
        }
    }
}

/// The scenario-body function shape — a `&mut Matrix` borrow that
/// returns a boxed future (the `for<'a>` fn pointer escapes the
/// `impl Future` lifetime-capture problem plain generics hit).
type ScenarioBody =
    for<'a> fn(&'a mut Matrix) -> Pin<Box<dyn Future<Output = driver::Result<String>> + 'a>>;

/// One scenario execution: setup → body under panic-catch → teardown →
/// record. Setup failure, body failure, and panic all record `failed`
/// — the matrix never aborts mid-run (upstream `t.Run` parity).
async fn run_scenario(records: &mut Vec<Record>, label: &str, id: &str, body: ScenarioBody) {
    let meta = scenario_meta(id);
    let mut m = match Matrix::setup(label).await {
        Ok(m) => m,
        Err(err) => {
            records.push(Record {
                scenario_id: id.to_string(),
                tier: "machine".to_string(),
                status: evidence::STATUS_FAILED.to_string(),
                packet: Some(meta.packet.to_string()),
                owning_specs: meta.owning_specs.iter().map(ToString::to_string).collect(),
                reason_codes_asserted: Vec::new(),
                event_kinds_asserted: Vec::new(),
                expected: meta.expected.to_string(),
                observed: format!("setup failed: {err}"),
                journal_receipt_ids: Vec::new(),
                physical_pointer: None,
            });
            return;
        }
    };
    let fut = CatchUnwind(Box::pin(body(&mut m)));
    let caught = fut.await;
    let (status, observed) = match caught {
        Ok(Ok(observed)) if observed.starts_with("INCONCLUSIVE") => {
            (evidence::STATUS_FAILED, observed)
        }
        Ok(Ok(observed)) => (evidence::STATUS_PASSED, observed),
        Ok(Err(err)) => (evidence::STATUS_FAILED, format!("failed: {err}")),
        Err(payload) => {
            let msg = payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_string()))
                .unwrap_or_else(|| "non-string panic payload".to_string());
            (evidence::STATUS_FAILED, format!("panicked: {msg}"))
        }
    };
    let (reason_codes, event_kinds) = m.take_assertions();
    m.recorded_runs.push(m.run);
    // Teardown runs under the same panic isolation as the body: a
    // panicking teardown must not abort the matrix (continue-all), and
    // a failed DROP is best-effort — the suite-start `rtm_*` sweep
    // cleans stragglers on the next run.
    let _ = CatchUnwind(Box::pin(m.teardown())).await;
    records.push(Record {
        scenario_id: id.to_string(),
        tier: "machine".to_string(),
        status: status.to_string(),
        packet: Some(meta.packet.to_string()),
        owning_specs: meta.owning_specs.iter().map(ToString::to_string).collect(),
        reason_codes_asserted: reason_codes,
        event_kinds_asserted: event_kinds,
        expected: meta.expected.to_string(),
        observed,
        journal_receipt_ids: Vec::new(),
        physical_pointer: None,
    });
}

macro_rules! scenario {
    ($records:expr, $label:literal, $id:literal, $body:expr) => {
        crate::run_scenario(
            &mut $records,
            $label,
            $id,
            |m: &mut driver::Matrix| -> std::pin::Pin<
                Box<dyn std::future::Future<Output = driver::Result<String>> + '_>,
            > { Box::pin($body(m)) },
        )
        .await;
    };
}

/// `indexPrerequisites` — records each phase-2 slice plan file's path +
/// hex SHA-256 + parse status. The Rust workspace carries no prior
/// acceptance JSONs, so the slice plans are the indexed prerequisite
/// evidence (the divergence is recorded in `divergences`).
fn index_prerequisites(records: &mut Vec<PrereqRecord>) -> driver::Result<()> {
    use sha2::Digest as _;
    let root = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").to_string());
    let root = PathBuf::from(root);
    for rel in evidence::PREREQ_EVIDENCE {
        let path = root.join(rel);
        let raw = std::fs::read(&path).map_err(|e| {
            central_foundation::failure::Failure::internal(
                "RTM_PREREQ",
                format!("prerequisite {rel}: {e}"),
            )
        })?;
        let digest = sha2::Sha256::digest(&raw);
        let sha = digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        records.push(PrereqRecord {
            gate: "phase-2-slice".to_string(),
            path: rel.to_string(),
            sha256: sha,
            parse_status: "ok".to_string(),
            notes: "markdown slice plan; upstream indexes the regenerated JSON \
                    acceptance bundles (see divergences)"
                .to_string(),
        });
    }
    Ok(())
}

#[tokio::test]
async fn phase2_recovery_matrix() -> driver::Result<()> {
    // Upstream `requirePG`: the gate fails closed, never skips.
    let mut admin = driver::admin_conn().await?;
    driver::drop_stale_scenario_dbs(&mut admin).await?;

    let mut records: Vec<Record> = Vec::new();

    // catalog order — P2F02 crash/leasing then P2F03 policy rows
    scenario!(records, "rtm01", "RTM-01", rtm_graph::rtm_01);
    scenario!(records, "rtm02", "RTM-02", rtm_policy::rtm_02);
    scenario!(records, "rtm03", "RTM-03", rtm_leasing::rtm_03);
    scenario!(records, "rtm04", "RTM-04", rtm_policy::rtm_04);
    scenario!(records, "rtm05", "RTM-05", rtm_leasing::rtm_05);
    scenario!(records, "rtm06", "RTM-06", rtm_leasing::rtm_06);
    scenario!(records, "rtm07", "RTM-07", rtm_leasing::rtm_07);
    scenario!(records, "rtm08", "RTM-08", rtm_policy::rtm_08);
    scenario!(records, "rtm09", "RTM-09", rtm_checkpoint::rtm_09);
    scenario!(records, "rtm10", "RTM-10", rtm_checkpoint::rtm_10);
    scenario!(records, "rtm11", "RTM-11", rtm_graph::rtm_11);
    scenario!(records, "rtm12", "RTM-12", rtm_graph::rtm_12);
    scenario!(records, "rtm13", "RTM-13", rtm_policy::rtm_13);
    scenario!(records, "rtm14", "RTM-14", rtm_graph::rtm_14);
    scenario!(records, "rtm15", "RTM-15", rtm_leasing::rtm_15);
    scenario!(records, "rtm16", "RTM-16", rtm_policy::rtm_16);
    scenario!(records, "rtm17", "RTM-17", rtm_leasing::rtm_17);
    scenario!(records, "rtm18", "RTM-18", rtm_checkpoint::rtm_18);
    scenario!(
        records,
        "rtm19s",
        "RTM-19-session",
        rtm_policy::rtm_19_session
    );
    scenario!(
        records,
        "rtm19d",
        "RTM-19-deadlines",
        rtm_policy::rtm_19_deadlines
    );

    // physical tier — deferred with prose acceptance-track pointers
    // (upstream `recordDeferredPhysical`; no runbook file exists).
    records.push(evidence::deferred_physical(
        "RTM-P1",
        &["S2"],
        "operator runbook",
    ));
    records.push(evidence::deferred_physical(
        "RTM-P2",
        &["S4"],
        "maintainer run",
    ));
    records.push(evidence::deferred_physical(
        "RTM-P3",
        &["S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8"],
        "phases.md exit track",
    ));

    // `host_profile` doubles as the PostgreSQL gate (upstream
    // `fillHostProfile`): the version query runs on the admin
    // connection the suite already holds.
    let pg_version: String = sqlx::query_scalar("SHOW server_version")
        .fetch_one(&mut admin)
        .await
        .map_err(|e| central_foundation::failure::Failure::internal("RTM_HOST", e.to_string()))?;
    let mut host_profile = std::collections::BTreeMap::new();
    host_profile.insert("rustc_version".to_string(), rustc_version());
    host_profile.insert("pg_server_version".to_string(), pg_version);
    host_profile.insert("profile".to_string(), "test".to_string());

    let mut prerequisites = Vec::new();
    index_prerequisites(&mut prerequisites)?;

    let revision = revision();
    let doc = Document {
        schema: SCHEMA.to_string(),
        generated_at: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
        central_revision: revision.clone(),
        candidate_commit: revision,
        scenarios: records.clone(),
        coverage: Coverage {
            phases_md_scenarios: evidence::phases_md_scenarios(),
            specs_consumed: evidence::specs_consumed(&records),
            asserted_codes_all_cataloged: evidence::all_codes_cataloged(&records),
        },
        prerequisites,
        host_profile,
        commands: vec![
            "CENTRAL_TEST_DSN=… cargo test -p central --test phase2_acceptance".to_string(),
        ],
        divergences: vec![
            "per-scenario PostgreSQL databases replace the upstream shared \
             connection (stronger isolation; same-DB probe graphs restore the \
             cross-run legs that need them)"
                .to_string(),
            "prerequisites index the phase-2 slice plan markdown (the Rust \
             workspace carries no prior JSON acceptance bundles to re-index)"
                .to_string(),
            "RTM-14's read legs drive the production authorize_read/record_read \
             ports through the matrix read seam (scripted bodies) — the \
             `central artifact read` CLI boundary composes the same ports"
                .to_string(),
        ],
        skip_census: Vec::new(),
    };

    if let Ok(dir) = std::env::var(EVIDENCE_ENV) {
        let path = evidence::emit(&doc, std::path::Path::new(&dir)).map_err(|e| {
            central_foundation::failure::Failure::internal("RTM_EVIDENCE", e.to_string())
        })?;
        eprintln!("phase-2 recovery matrix evidence: {}", path.display());
    }

    // Upstream `t.Run` semantics: every scenario ran; the test fails
    // once, at the end, if any row failed.
    let failed: Vec<&str> = doc
        .scenarios
        .iter()
        .filter(|r| r.status == evidence::STATUS_FAILED)
        .map(|r| r.scenario_id.as_str())
        .collect();
    assert!(
        failed.is_empty(),
        "phase-2 recovery matrix failures: {failed:?}"
    );
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

/// Every asserted-code→spec transcription in `codeToSpec` names a spec
/// inside S2–S8 (S1 owns no codes — upstream parity), and the verbatim
/// phases map covers the upstream scenario set.
#[test]
fn evidence_catalog_coherence() {
    for code in [
        "LEASE_FENCE_STALE",
        "RESUME_TOKEN_STALE",
        "RETRY_BUDGET_EXHAUSTED",
        "DUPLICATE_IDEMPOTENCY_KEY",
        "EVENT_SEQUENCE_GAP",
        "ARTIFACT_SCOPE_DENIED",
        "CAPACITY_ADMISSION_DEFERRED",
    ] {
        assert!(evidence::code_to_spec(code).is_some(), "{code} uncataloged");
    }
    let phases = evidence::phases_md_scenarios();
    assert_eq!(phases.len(), 6);
    assert_eq!(evidence::code_to_spec("MATRIX_DRIVER"), None);
}
