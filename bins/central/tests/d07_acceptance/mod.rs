//! D07 Slice-D acceptance suite — the Rust port of upstream's
//! `cmd/central/d07_harness_test.go` + `d07_scenarios_test.go` (R6 Task
//! 14). The `d07_buildtag_{pam,nopam}` split collapses into Cargo's
//! always-compiled grant-mode confirmer: `PamConfirmer::with_grants`
//! needs no build tag, so the fixture tier exercises the real grant
//! ceremony unconditionally.
//!
//! The suite drives the real operator path —
//! CLI grammar → Unix socket → `helper::Server::handle_conn` →
//! production handlers → evidence artifacts — in two tiers:
//!
//!   - fixture tier (default, non-root, no docker): every root is a
//!     fresh fixture tree owned by the test user. It runs in ordinary
//!     `cargo test`.
//!   - production tier (`CENTRAL_D07_RUN=1` AND euid 0): upstream
//!     currently skips the root install
//!     (`d07InstallProductionInstance`, d07_harness_test.go:444); the
//!     port records the same honest `skip` verdict per scenario rather
//!     than pretending production passed.
//!
//! Layout mirrors upstream's two-file split: `harness` is
//! `d07_harness_test.go` (env, fixture seams, sealed-backup builder,
//! grant helpers, run/read_file, repo admission), `seams` the test
//! doubles, `scenarios` the eight `d07_scenarios_test.go` bodies.

// Test-target relaxation, same as `c06_acceptance`: a refused run IS
// the assertion — panic/unwrap/expect are how a libtest body reports
// FailNow.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc
)]
#![allow(dead_code)]

use std::path::{Path, PathBuf};

mod harness;
mod scenarios;
mod seams;

/// Lowercase hex — the Go `hex.EncodeToString` shape upstream emits
/// for every digest. Local to the suite; the workspace carries no hex
/// crate.
pub(crate) fn hex_lower(bytes: impl AsRef<[u8]>) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let bytes = bytes.as_ref();
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

/// `d07RunEnv` — the explicit production-tier opt-in.
const D07_RUN_ENV: &str = "CENTRAL_D07_RUN";
/// `CENTRAL_D07_EVIDENCE_DIR` — the optional dossier copy target.
const D07_EVIDENCE_ENV: &str = "CENTRAL_D07_EVIDENCE_DIR";

/// `d07Tier` reports which tier the suite runs. Production needs root
/// AND the explicit opt-in: installing under production paths is a
/// destructive-adjacent act no test takes by default.
pub(crate) fn d07_tier() -> &'static str {
    if std::env::var(D07_RUN_ENV).ok().as_deref() == Some("1")
        && rustix::process::geteuid().as_raw() == 0
    {
        "production"
    } else {
        "fixture"
    }
}

/// `d07ScenarioVerdict` — one row of the acceptance bundle.
#[derive(Debug, Default, serde::Serialize)]
pub(crate) struct ScenarioVerdict {
    pub id: String,
    pub name: String,
    pub verdict: String,
    /// Go `Evidence []string` — nil marshals `null`, matching
    /// upstream's undecorated slice.
    pub evidence_files: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub disclosures: Vec<String>,
    /// Go `workDir` — unexported, never serialized.
    #[serde(skip)]
    pub work_dir: Option<PathBuf>,
    /// Keeps the fixture tree alive until the verdict (and the copy
    /// the runner makes from it) is done — upstream's `t.TempDir`
    /// lifetime, which cleans at test end.
    #[serde(skip)]
    pub(crate) _tree: Option<std::sync::Arc<harness::FixtureTree>>,
}

/// `d07AcceptanceBundle` — `slice-d-acceptance.json`: the suite's own
/// verdict over the eight dossier scenarios.
#[derive(Debug, serde::Serialize)]
struct AcceptanceBundle {
    schema_version: &'static str,
    evidence_profile: &'static str,
    tier: &'static str,
    scenarios: Vec<ScenarioVerdict>,
    completed_at: String,
}

/// `skipped` — the verdict a production-tier scenario records while
/// upstream's root install remains unrehearsed.
fn skipped(note: &str) -> ScenarioVerdict {
    ScenarioVerdict {
        verdict: "skip".to_owned(),
        notes: vec![note.to_owned()],
        ..ScenarioVerdict::default()
    }
}

/// One `run(id, name, fn)` call: execute the scenario, normalize the
/// verdict, copy declared evidence, and append the row. A scenario
/// panic fails the suite exactly as upstream's `t.Fatalf` fails the
/// subtest and the parent.
fn run_scenario(
    verdicts: &mut Vec<ScenarioVerdict>,
    id: &str,
    name: &str,
    f: fn() -> ScenarioVerdict,
) {
    let mut verdict = f();
    verdict.id = id.to_owned();
    verdict.name = name.to_owned();
    if verdict.verdict.is_empty() {
        verdict.verdict = "pass".to_owned();
    }
    if let Ok(dir) = std::env::var(D07_EVIDENCE_ENV)
        && !dir.is_empty()
        && let (Some(work), Some(files)) = (&verdict.work_dir, &verdict.evidence_files)
    {
        mkdir_mode(&dir, 0o700).expect("create evidence dir");
        for name in files {
            let raw = std::fs::read(work.join(name)).unwrap_or_else(|e| {
                panic!(
                    "declared evidence {name} unreadable in {}: {e}",
                    work.display()
                )
            });
            write_mode(Path::new(&dir).join(name), &raw, 0o644).expect("write evidence copy");
        }
    }
    verdicts.push(verdict);
}

/// `os.WriteFile(..., mode)` — mode applies at create only, exactly
/// like Go.
pub(crate) fn write_mode(path: impl AsRef<Path>, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)
        .and_then(|mut f| std::io::Write::write_all(&mut f, bytes))
}

/// `mkdirAll(path, 0o700)` — mode applies at create only.
pub(crate) fn mkdir_mode(path: impl AsRef<Path>, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(mode)
        .create(path)
}

/// `TestD07Acceptance` — the eight-scenario acceptance over Slice D.
#[test]
fn d07_acceptance() {
    let tier = d07_tier();
    eprintln!("D07 acceptance tier: {tier} (evidence_profile: docker)");
    let mut verdicts: Vec<ScenarioVerdict> = Vec::new();

    run_scenario(
        &mut verdicts,
        "S1",
        "wipe and reseed with grant ceremony and sealed checkpoint",
        scenarios::wipe_reseed,
    );
    run_scenario(
        &mut verdicts,
        "S2",
        "signed denial blocks wipe without ceremony",
        scenarios::signed_denial,
    );
    run_scenario(
        &mut verdicts,
        "S3",
        "export, independent token verify, fresh-instance import staging",
        scenarios::export_import,
    );
    run_scenario(
        &mut verdicts,
        "S4",
        "delete refuses closed with the engine unplumbed",
        scenarios::delete_fail_closed,
    );
    run_scenario(
        &mut verdicts,
        "S5",
        "prune refuses closed with the engine unplumbed",
        scenarios::prune_fail_closed,
    );
    run_scenario(
        &mut verdicts,
        "S6",
        "audit detects tampering and repairs honestly",
        scenarios::audit_tamper,
    );
    run_scenario(
        &mut verdicts,
        "S7",
        "deny-safe gate and rescue attempt cycle",
        scenarios::rescue_cycle,
    );
    run_scenario(
        &mut verdicts,
        "S8",
        "authority evaluation branches rescue correctly",
        scenarios::rescue_authority,
    );

    for verdict in &verdicts {
        assert!(
            verdict.verdict == "pass" || verdict.verdict == "skip",
            "D07 acceptance failed: {verdict:?}"
        );
    }
    let bundle = AcceptanceBundle {
        schema_version: "slice-d-acceptance/v1",
        evidence_profile: "docker",
        tier,
        scenarios: verdicts,
        completed_at: central_adapter_linux::helper::audit::format_rfc3339nano(
            time::OffsetDateTime::now_utc(),
        ),
    };
    let encoded = serde_json::to_string_pretty(&bundle).expect("encode bundle");
    let ephemeral;
    let dir = match std::env::var(D07_EVIDENCE_ENV) {
        Ok(dir) if !dir.is_empty() => {
            ephemeral = false;
            PathBuf::from(dir)
        }
        _ => {
            ephemeral = true;
            std::env::temp_dir().join(format!(
                "central-d07-bundle-{}-{}",
                std::process::id(),
                uuid::Uuid::now_v7()
            ))
        }
    };
    mkdir_mode(&dir, 0o700).expect("create bundle dir");
    let path = dir.join("slice-d-acceptance.json");
    write_mode(&path, format!("{encoded}\n").as_bytes(), 0o644).expect("write bundle");
    eprintln!("D07 acceptance bundle: {}", path.display());
    if ephemeral {
        // Upstream's `t.TempDir` auto-cleans the no-EVIDENCE_DIR case.
        let _ = std::fs::remove_dir_all(&dir);
    }
}
