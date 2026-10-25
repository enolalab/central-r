//! `phase-2-recovery-matrix/v1` evidence document — byte-faithful port of
//! the upstream `phase2acceptance` emission (schema, field names, and the
//! machine|physical tier split). Exactly 23 scenario records: the 20
//! machine scenarios plus RTM-P1/P2/P3 carried `deferred-physical` with
//! prose acceptance-track pointers (upstream `recordDeferredPhysical`
//! emits the same prose pointers — no runbook file exists in either
//! tree).
//!
//! Document-level fields mirror upstream's `manifest` struct:
//! `candidate_commit`, `prerequisites` (the phase-2 slice plan files,
//! sha256-indexed — upstream indexes the regenerated slice acceptance
//! JSONs; the Rust workspace carries no prior acceptance JSONs, so the
//! slice plans are the indexed prerequisite evidence — recorded in
//! `divergences`), `host_profile`, `commands`, `divergences`, and
//! `skip_census`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::missing_panics_doc)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Serialize;

/// The emitted schema identifier.
pub const SCHEMA: &str = "phase-2-recovery-matrix/v1";

/// Status the driver records for a machine scenario that ran green.
pub const STATUS_PASSED: &str = "passed";
/// Status for a machine scenario that ran and failed (upstream's
/// `INCONCLUSIVE`-prefixed observed records `failed`).
pub const STATUS_FAILED: &str = "failed";
/// Status for the physical-tier rows the machine driver never runs.
pub const STATUS_DEFERRED: &str = "deferred-physical";

/// One scenario record — upstream's `recordScenario` row. Field order and
/// names match the upstream JSON shape byte-for-byte where testable.
/// `packet` serializes `omitempty` like upstream (`packet,omitempty`).
#[derive(Debug, Clone, Serialize)]
pub struct Record {
    pub scenario_id: String,
    pub tier: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packet: Option<String>,
    pub owning_specs: Vec<String>,
    pub reason_codes_asserted: Vec<String>,
    pub event_kinds_asserted: Vec<String>,
    pub expected: String,
    pub observed: String,
    pub journal_receipt_ids: Vec<String>,
    pub physical_pointer: Option<String>,
}

/// One indexed prerequisite row — upstream `prereqRecord`. `gate` is the
/// document's own gate field when it carries one; `notes` names the
/// attestation shape plus any absent schema/gate keys.
#[derive(Debug, Clone, Serialize)]
pub struct PrereqRecord {
    pub gate: String,
    pub path: String,
    pub sha256: String,
    pub parse_status: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub notes: String,
}

/// The `coverage` block — phase-scenario mapping, consumed specs, and the
/// reason-code catalog verdict.
#[derive(Debug, Clone, Serialize)]
pub struct Coverage {
    pub phases_md_scenarios: BTreeMap<String, Vec<String>>,
    pub specs_consumed: Vec<String>,
    pub asserted_codes_all_cataloged: bool,
}

/// The emitted document — upstream `manifest`'s serialized fields.
#[derive(Debug, Clone, Serialize)]
pub struct Document {
    pub schema: String,
    pub generated_at: String,
    pub central_revision: String,
    pub candidate_commit: String,
    pub scenarios: Vec<Record>,
    pub coverage: Coverage,
    pub prerequisites: Vec<PrereqRecord>,
    pub host_profile: BTreeMap<String, String>,
    pub commands: Vec<String>,
    pub divergences: Vec<String>,
    pub skip_census: Vec<String>,
}

/// `codeToSpec` — every SCREAMING_CASE reason code transcribed from the
/// specs 1-8 failure-semantics sections, mapped to its owning spec
/// (upstream's literal `codeToSpec` map; S1 owns no codes — event-level
/// semantics only). `recordScenario` fails closed on any asserted code
/// absent here, and `asserted_codes_all_cataloged` is COMPUTED from this
/// map, never hardcoded.
pub fn code_to_spec(code: &str) -> Option<&'static str> {
    Some(match code {
        // S2 task-leasing-worker-protocol.
        "WORKER_REGISTRATION_REJECTED" => "S2",
        "LEASE_RENEWAL_STALE" => "S2",
        "LEASE_EXPIRED_NOT_STARTED" => "S2",
        "ATTEMPT_AMBIGUOUS_LEASE_EXPIRED" => "S2",
        "WORKER_LOST_GRACE_EXPIRED" => "S2",
        "ATTEMPT_AMBIGUOUS_WORKER_LOST" => "S2",
        "ATTEMPT_AMBIGUOUS_KILL_UNCONFIRMED" => "S2",
        "ATTEMPT_AMBIGUOUS_LAUNCH_UNKNOWN" => "S2",
        "LEASE_FENCE_STALE" => "S2",
        "WORKER_SHUTDOWN_LEASE_RELEASED" => "S2",
        // S3 checkpoint-resume-format.
        "RESUME_TOKEN_STALE" => "S3",
        "CHECKPOINT_INCOMPATIBLE" => "S3",
        "WORKSPACE_DIGEST_MISMATCH" => "S3",
        "CHECKPOINT_ARTIFACT_MISSING" => "S3",
        "RESUME_REQUIRES_OPERATOR_DECISION" => "S3",
        "CHECKPOINT_BOUNDARY_ILLEGAL" => "S3",
        // S4 retry-timeout-error-taxonomy.
        "RETRY_BUDGET_EXHAUSTED" => "S4",
        "NODE_TIMEOUT" => "S4",
        "WORKFLOW_TIMEOUT" => "S4",
        "PROCESS_EXIT_NONZERO" => "S4",
        "ADAPTER_ERROR" => "S4",
        "RATE_LIMITED" => "S4",
        "WORKSPACE_PROVISION_FAILED" => "S4",
        "LAUNCHER_REFUSED" => "S4",
        "SPEC_VALIDATION_FAILED" => "S4",
        "BUDGET_EXHAUSTED" => "S4",
        "WORKSPACE_UNAVAILABLE" => "S4",
        "CAPABILITY_MISSING" => "S4",
        // S5 idempotency-consistency.
        "DUPLICATE_IDEMPOTENCY_KEY" => "S5",
        "ARTIFACT_ALREADY_FINALIZED" => "S5",
        "ARTIFACT_CHECKSUM_MISMATCH" => "S5",
        "OUTBOX_PUBLISH_STALLED" => "S5",
        // S6 event-schema-reconstruction.
        "EVENT_SEQUENCE_GAP" => "S6",
        "DUPLICATE_EVENT_ID" => "S6",
        "UNKNOWN_EVENT_KIND" => "S6",
        "INVALID_EVENT_PAYLOAD" => "S6",
        "ORPHAN_EVENT" => "S6",
        "RECONSTRUCTION_DIVERGED" => "S6",
        "PREPARE_UNAVAILABLE" => "S6",
        // S7 artifact-lineage.
        "ARTIFACT_NOT_FINALIZED" => "S7",
        "ARTIFACT_SCOPE_DENIED" => "S7",
        "ARTIFACT_READ_UNRESOLVED" => "S7",
        "LINEAGE_READ_UNDECLARED" => "S7",
        "ARTIFACT_BODY_INTEGRITY" => "S7",
        "ARTIFACT_READ_AMBIGUOUS" => "S7",
        // S8 concurrency-resource-limits.
        "BUDGET_EXCEEDS_PARENT" => "S8",
        "MAX_NODES_PER_RUN_REACHED" => "S8",
        "MAX_DEPTH_EXCEEDED" => "S8",
        "CAPACITY_ADMISSION_DEFERRED" => "S8",
        "SESSION_WALL_CLOCK_REACHED" => "S8",
        "SESSION_COST_CEILING_REACHED" => "S8",
        "WORKSPACE_DISK_BUDGET_EXCEEDED" => "S8",
        _ => return None,
    })
}

/// Every asserted reason code must transcribe into `codeToSpec`; the
/// computed coverage flag (upstream's `asserted_codes_all_cataloged`,
/// derived — never hardcoded true).
pub fn all_codes_cataloged(records: &[Record]) -> bool {
    records
        .iter()
        .flat_map(|r| r.reason_codes_asserted.iter())
        .all(|code| code_to_spec(code).is_some())
}

/// The specs owning at least one scenario row — upstream hardcodes
/// `S1..S8` because its per-scenario `owningSpecs` cover all eight; the
/// Rust port computes the same set so a future row cannot inflate the
/// claim.
pub fn specs_consumed(records: &[Record]) -> Vec<String> {
    let mut owned = BTreeSet::new();
    for record in records {
        for spec in &record.owning_specs {
            owned.insert(spec.clone());
        }
    }
    owned.into_iter().collect()
}

/// The RTM D2 `phases.md` mapping — verbatim upstream keys (the scenario
/// strings, not spec ids).
pub fn phases_md_scenarios() -> BTreeMap<String, Vec<String>> {
    let mut map = BTreeMap::new();
    map.insert(
        "parallel + dependent children → correct final result".to_string(),
        vec!["RTM-01".to_string(), "RTM-14".to_string()],
    );
    map.insert(
        "kill application/worker loses no completed child outputs".to_string(),
        vec![
            "RTM-03".to_string(),
            "RTM-05".to_string(),
            "RTM-P1".to_string(),
        ],
    );
    map.insert(
        "expired lease → safe reassignment, no duplicate durable effects".to_string(),
        vec![
            "RTM-06".to_string(),
            "RTM-07".to_string(),
            "RTM-16".to_string(),
        ],
    );
    map.insert(
        "repeated idempotency key → no duplicates".to_string(),
        vec!["RTM-08".to_string()],
    );
    map.insert(
        "incompatible checkpoint fails safe + actionable reason".to_string(),
        vec!["RTM-09".to_string()],
    );
    map.insert(
        "parent cancel propagates per documented policy".to_string(),
        vec!["RTM-11".to_string()],
    );
    map
}

/// The phase-2 slice plan files the Rust workspace indexes as
/// prerequisite evidence (upstream indexes the regenerated slice
/// acceptance JSONs — see `divergences` for the format note). Repo-
/// relative paths.
pub const PREREQ_EVIDENCE: [&str; 5] = [
    "docs/implementation/phase-2-slices/slice-a-workflow-graph-lineage.md",
    "docs/implementation/phase-2-slices/slice-b-scheduler-workers.md",
    "docs/implementation/phase-2-slices/slice-c-checkpoint-resume.md",
    "docs/implementation/phase-2-slices/slice-d-retry-idempotency.md",
    "docs/implementation/phase-2-slices/slice-e-graph-ui.md",
];

/// Records the deferred physical-tier rows the machine suite cannot run
/// (upstream `recordDeferredPhysical`) — each carries its prose
/// acceptance-track pointer.
pub fn deferred_physical(id: &str, specs: &[&str], pointer: &str) -> Record {
    Record {
        scenario_id: id.to_string(),
        tier: "physical".to_string(),
        status: STATUS_DEFERRED.to_string(),
        packet: None,
        owning_specs: specs.iter().map(ToString::to_string).collect(),
        reason_codes_asserted: Vec::new(),
        event_kinds_asserted: Vec::new(),
        expected: "catalog expectations at production tier".to_string(),
        observed: format!("deferred to physical tier: {pointer}"),
        journal_receipt_ids: Vec::new(),
        physical_pointer: Some(pointer.to_string()),
    }
}

/// Serializes the document and writes it under `dir` as
/// `phase-2-recovery-matrix.json`; returns the written path. Callers
/// gate on `CENTRAL_PHASE2_EVIDENCE_DIR` — emission is opt-in, upstream
/// `emitManifest` parity.
pub fn emit(doc: &Document, dir: &Path) -> Result<std::path::PathBuf, std::io::Error> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join("phase-2-recovery-matrix.json");
    let mut body = serde_json::to_string_pretty(doc)?;
    body.push('\n');
    std::fs::write(&path, body)?;
    Ok(path)
}

/// The canonical 23-record scenario ID set — the assertion target of the
/// exact-count/exact-set test.
pub const EXPECTED_SCENARIO_IDS: [&str; 23] = [
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
    "RTM-19-session",
    "RTM-19-deadlines",
    "RTM-P1",
    "RTM-P2",
    "RTM-P3",
];
