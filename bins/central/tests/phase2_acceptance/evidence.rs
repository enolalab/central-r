//! `phase-2-recovery-matrix/v1` evidence document — byte-faithful port of
//! the upstream `phase2acceptance` emission (schema, field names, and the
//! machine|physical tier split). Exactly 23 scenario records: the 20
//! machine scenarios plus RTM-P1/P2/P3 carried `deferred-physical` with
//! runbook pointers.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::missing_panics_doc)]

use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;

/// The emitted schema identifier.
pub const SCHEMA: &str = "phase-2-recovery-matrix/v1";

/// Status the driver records for a machine scenario that ran green.
pub const STATUS_PASSED: &str = "passed";
/// Status for the physical-tier rows the machine driver never runs.
pub const STATUS_DEFERRED: &str = "deferred-physical";

/// One scenario record — upstream's `recordScenario` row. Field order and
/// names match the upstream JSON shape byte-for-byte where testable.
#[derive(Debug, Clone, Serialize)]
pub struct Record {
    pub scenario_id: String,
    pub tier: String,
    pub status: String,
    pub owning_specs: Vec<String>,
    pub reason_codes_asserted: Vec<String>,
    pub event_kinds_asserted: Vec<String>,
    pub expected: String,
    pub observed: String,
    pub journal_receipt_ids: Vec<String>,
    pub physical_pointer: Option<String>,
}

/// The `coverage` block — phase-scenario mapping, consumed specs, and the
/// reason-code catalog verdict.
#[derive(Debug, Clone, Serialize)]
pub struct Coverage {
    pub phases_md_scenarios: BTreeMap<String, Vec<String>>,
    pub specs_consumed: Vec<String>,
    pub asserted_codes_all_cataloged: bool,
}

/// The emitted document.
#[derive(Debug, Clone, Serialize)]
pub struct Document {
    pub schema: String,
    pub generated_at: String,
    pub central_revision: String,
    pub scenarios: Vec<Record>,
    pub coverage: Coverage,
}

/// Records the deferred physical-tier rows the machine suite cannot run
/// (upstream `recordDeferredPhysical`) — each carries its runbook pointer.
pub fn deferred_physical(id: &str, specs: &[&str], expected: &str, pointer: &str) -> Record {
    Record {
        scenario_id: id.to_string(),
        tier: "physical".to_string(),
        status: STATUS_DEFERRED.to_string(),
        owning_specs: specs.iter().map(ToString::to_string).collect(),
        reason_codes_asserted: Vec::new(),
        event_kinds_asserted: Vec::new(),
        expected: expected.to_string(),
        observed: "deferred to the physical-tier acceptance track".to_string(),
        journal_receipt_ids: Vec::new(),
        physical_pointer: Some(pointer.to_string()),
    }
}

/// Serializes the document and writes it under `dir` as
/// `phase-2-recovery-matrix.json`; returns the written path.
pub fn emit(doc: &Document, dir: &Path) -> Result<std::path::PathBuf, std::io::Error> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join("phase-2-recovery-matrix.json");
    let body = serde_json::to_string_pretty(doc)?;
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
