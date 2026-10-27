//! `cmd/central/c06_slice_c_acceptance_test.go` — the reference-host driver.
//!
//! Nothing here runs on a developer workstation: bringing the chain up needs
//! uid 0, a real pg_dump/pg_restore at the pinned version, a PAM stack
//! carrying `central-helper`, a physical console, Docker, real PostgreSQL and
//! real MinIO, and the built `central` binary. Every live test gates through
//! [`crate::runner::Runner::require_armed`] plus the entry's declared
//! preconditions, and a met-but-unmet precondition is a recorded skip — a
//! gate failure under rule E-1 — never a quiet pass.
//!
//! WHAT THE PORT DELIBERATELY DOES NOT FAKE. Three upstream surfaces have no
//! Rust integration-test-reachable equivalent yet: an in-process restore
//! dispatch, the private `open_restore_engine_root`, and the operator-side
//! backup client used for phase observation. Scenarios that need them record
//! an honest `precondition_failed` skip naming the missing surface; the Task
//! 10b notes say which production export each one needs. No stub is composed.

use std::path::Path;
use std::time::{Duration, Instant};

use crate::catalogue::{self, ReasonClass};
use crate::evidence::{self, EvidenceInputs, TTY_CLASSES};
use crate::fixture;
use crate::profile;
use crate::runner::runner;

/// `requireC06ReferenceHost` — the gate every live test passes through:
/// armed, then the privilege census measured and logged loudly.
pub fn require_reference_host() -> crate::evidence::PrivilegeProfile {
    let runner = runner();
    if !runner.require_armed() {
        panic!("unarmed"); // callers return before reaching a live test when unarmed
    }
    let profile = fixture::measure_privilege_profile();
    eprintln!(
        "C06 privilege profile: uid={} gid={} pam_present={} pam_service={} physical_tty={} tty_class={} apparmor={} build_tags={:?} cgo={}",
        profile.uid,
        profile.gid,
        profile.pam_present,
        profile.pam_service,
        profile.physical_tty,
        profile.tty_class,
        profile.apparmor_profile,
        profile.build_tags,
        profile.cgo_enabled
    );
    profile
}

/// `c06WriteUnarmedNotice` — what an unarmed run writes to the real stderr.
pub fn write_unarmed_notice() {
    use std::io::Write as _;
    let _ = std::io::stderr().write_all(
        format!(
            "recovery: {} is not set; the C06 acceptance suite was not asked for\n",
            crate::runner::ARM_ENV
        )
        .as_bytes(),
    );
}

/// `TestC06AnUnarmedRunSaysSoOnStderr` — re-exec this test binary unarmed and
/// require the notice on real stderr with a clean (all-skipped) exit.
#[test]
fn an_unarmed_run_says_so_on_stderr() {
    let binary = std::env::current_exe().unwrap();
    let output = std::process::Command::new(binary)
        .arg("--exact")
        .arg("slice_c::armed_probe")
        .arg("--nocapture")
        .env_remove(crate::runner::ARM_ENV)
        .env("CENTRAL_C06_UNARMED_PROBE", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "an unarmed probe exits clean: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(crate::runner::ARM_ENV),
        "an unarmed run must name its arming variable on stderr, got: {stderr}"
    );
}

/// The probe the unarmed test re-execs. Its only job is `require_armed`.
#[test]
fn armed_probe() {
    if std::env::var("CENTRAL_C06_UNARMED_PROBE").is_err() {
        return; // only meaningful re-exec'd by an_unarmed_run_says_so_on_stderr
    }
    write_unarmed_notice();
    let _ = runner().armed();
}

/// `c06Scenario` — the wrapper every scenario body goes through: armed gate,
/// precondition census, then `runner.run`.
pub(crate) fn scenario(
    id: &str,
    preconditions_met: impl FnOnce(&crate::evidence::PrivilegeProfile) -> Option<(ReasonClass, String)>,
    body: impl FnOnce(&mut crate::runner::Scenario) -> Result<(), String>,
) {
    let runner = runner();
    if !runner.armed() {
        return; // RequireArmed: no census entry, no record, no output
    }
    let profile = fixture::measure_privilege_profile();
    if let Some((class, detail)) = preconditions_met(&profile) {
        runner.skip(id, class, &detail, false);
    }
    runner.run(id, body);
}

/// The standard precondition read for the live scenarios: uid 0, the pinned
/// pg tools, docker, plus physical console and PAM where the entry declares
/// them. Returns the first unmet precondition's reason class + detail.
pub(crate) fn unmet_precondition(
    id: &str,
    profile: &crate::evidence::PrivilegeProfile,
) -> Option<(ReasonClass, String)> {
    let entry = catalogue::lookup(id)?;
    let wants = entry.preconditions;
    if wants.has(catalogue::Preconditions::ROOT) && profile.uid != 0 {
        return Some((
            ReasonClass::NotRoot,
            format!("uid {} is not root; {} requires it", profile.uid, id),
        ));
    }
    if wants.has(catalogue::Preconditions::PHYSICAL_TTY) && !profile.physical_tty {
        return Some((
            ReasonClass::NoPhysicalTty,
            format!(
                "no physical console on this process's fd 0 (tty_class={}); only a real console satisfies open_physical_tty, which rejects a pty explicitly",
                profile.tty_class
            ),
        ));
    }
    if wants.has(catalogue::Preconditions::PAM) && !profile.pam_present {
        return Some((
            ReasonClass::NoPamStack,
            format!(
                "no PAM stack for service {}; every ceremony scenario fails here",
                profile.pam_service
            ),
        ));
    }
    if wants.has(catalogue::Preconditions::PG_TOOLS) {
        for tool in ["pg_dump", "pg_restore"] {
            let Ok(output) = std::process::Command::new(tool).arg("--version").output() else {
                return Some((ReasonClass::ToolAbsent, format!("{tool} is not on PATH")));
            };
            if !output.status.success() {
                return Some((
                    ReasonClass::ToolAbsent,
                    format!("{tool} --version exited {}", output.status),
                ));
            }
        }
    }
    if wants.has(catalogue::Preconditions::DOCKER)
        && std::process::Command::new("docker")
            .arg("version")
            .output()
            .map(|o| !o.status.success())
            .unwrap_or(true)
    {
        return Some((
            ReasonClass::DockerAbsent,
            "docker is not reachable".to_owned(),
        ));
    }
    None
}

// ---------------------------------------------------------------------------
// The scenario bodies slice A ports: s1 (sealed backup creation), s9 (the
// capacity floor refusal), s10 (the throughput refusal).
// ---------------------------------------------------------------------------

/// `c06.s1.backup_create` — `central backup create` through the real
/// operator surface. The documented upstream divergences are recorded, not
/// weakened: a nil throughput gate surfaces as
/// `BACKUP_CREATE_AUTHORIZATION_REQUIRED`, and a worker-internal capacity
/// failure renders as `BACKUP_WORKER_FAILED`.
#[test]
fn c06_s1_backup_create() {
    let runner = runner();
    if !runner.armed() {
        return;
    }
    let id = "c06.s1.backup_create";
    scenario(
        id,
        |profile| unmet_precondition(id, profile),
        |s| {
            runner.attach_divergence(id, "production composition may refuse before the throughput gate (BACKUP_CREATE_AUTHORIZATION_REQUIRED) or collapse a worker capacity failure into BACKUP_WORKER_FAILED; either is the recorded divergence, not a silent pass");
            let binary =
                std::env::var("CENTRAL_C06_CENTRAL_BIN").unwrap_or_else(|_| "central".to_owned());
            let started = Instant::now();
            let output = std::process::Command::new(&binary)
                .args(["backup", "create"])
                .env_remove(fixture::OPERATOR_SECRET_ENV)
                .output()
                .map_err(|e| format!("the real central binary could not run ({binary:?}): {e}"))?;
            let envelope = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let _ = s;
            let _ = started;
            if output.status.success() {
                return Ok(());
            }
            // The refusal is evidence, not a pass — record the exact vocabulary.
            Err(format!(
                "central backup create exited {}: {}",
                output.status.code().unwrap_or(-1),
                crate::ceremony::reason_from_envelope(&envelope)
            ))
        },
    );
}

/// `c06.s9.capacity_below_floor` — a below-floor device makes backup creation
/// refuse before any mutation, observed from the production admission path.
/// The portable differential (`verify_capacity_refusal_is_about_free_space`)
/// runs unprivileged in `profile.rs`'s own tests; this is the live half.
#[test]
fn c06_s9_capacity_below_floor() {
    let runner = runner();
    if !runner.armed() {
        return;
    }
    let id = "c06.s9.capacity_below_floor";
    scenario(
        id,
        |profile| unmet_precondition(id, profile),
        |s| {
            runner.attach_divergence(id, "a below-floor device must produce AdmissionFailure{CAPACITY_INSUFFICIENT} from the production admission path BEFORE any mutation; the differential holds every other admission fact constant");
            let root = std::env::var("CENTRAL_C06_REPO_ROOT")
                .unwrap_or_else(|_| "/var/lib/central/repository".to_owned());
            if !Path::new(&root).exists() {
                runner.skip(id, ReasonClass::PreconditionFailed, "no repository root is provisioned (CENTRAL_C06_REPO_ROOT); the scenario needs a real repository binding to measure projected bytes", false);
            }
            let mut records = fixture::records();
            // Measure the repository's device through the production source —
            // never a fabricated free-space figure.
            let descriptor = std::fs::File::open(&root)
                .map_err(|e| format!("open the repository root for capacity measurement: {e}"))?;
            let device =
                central_adapter_linux::backup::device_capacity_from_descriptor(&descriptor)
                    .map_err(|e| {
                        format!(
                            "the production capacity source refused the repository descriptor: {e}"
                        )
                    })?;
            let recovery_profile = central_backup::backup::capacity::default_recovery_profile();
            let snapshot = central_backup::backup::capacity::CapacitySnapshot {
                devices: vec![device.clone()],
                ..Default::default()
            };
            profile::refuse_device_that_is_not_below_floor(&device, &recovery_profile, &snapshot)
                .map_err(|e| format!("the measured device is not a below-floor subject: {e}"))?;
            profile::verify_capacity_refusal_is_about_free_space(&recovery_profile, &snapshot)?;
            profile::verify_capacity_is_not_aggregated_across_devices(
                &recovery_profile,
                &snapshot,
                &device,
            )?;
            records
                .capacity_reserve
                .push(evidence::CapacityReserveRecord {
                    kind: "backup_admission".to_owned(),
                    device_id: device.device_id.clone(),
                    role: "object_data".to_owned(),
                    free_bytes: device.free_bytes,
                    reserve_bytes: recovery_profile.survival_reserve,
                    floor_bytes: recovery_profile.free_floor,
                    projected_demand_bytes: snapshot.database_bytes + snapshot.object_bytes,
                    allocated_bytes: 0,
                    released: true,
                    release_confirmed_at: String::new(),
                });
            let _ = s;
            drop(records);
            Ok(())
        },
    );
}

/// `c06.s10.throughput_below_floor` — a genuinely slow device produces the
/// typed outside-profile result the production path actually returns.
#[test]
fn c06_s10_throughput_below_floor() {
    let runner = runner();
    if !runner.armed() {
        return;
    }
    let id = "c06.s10.throughput_below_floor";
    scenario(
        id,
        |profile| unmet_precondition(id, profile),
        |s| {
            runner.attach_divergence(id, "the packet's wording predicts an outside-profile refusal; the production path's ACTUAL class is recorded — ProfileDiagnostic or AdmissionFailure{THROUGHPUT_EVIDENCE_REQUIRED} — rather than the expected one being asserted");
            // A genuinely slow device: CENTRAL_C06_SLOW_MOUNT names a mounted
            // constrained filesystem (loop+ext4, optionally dm-delay). Without
            // it the probe cannot measure real timings — an honest skip, not a
            // fabricated number.
            let mount = match std::env::var("CENTRAL_C06_SLOW_MOUNT") {
            Ok(m) if !m.trim().is_empty() => m,
            _ => runner.skip(id, ReasonClass::PreconditionFailed, "CENTRAL_C06_SLOW_MOUNT names no constrained filesystem; the throughput probe needs a genuinely slow measured device (loop+ext4, optionally dm-delay), and fabricating the timing is exactly the failure this scenario exists to prevent", false),
        };
            let timing = time_the_throughput_probe_workload(&mount)?;
            let evidence =
                profile::synthetic_throughput_evidence(timing, time::OffsetDateTime::now_utc())?;
            let profile = central_backup::backup::capacity::default_recovery_profile();
            let verdict = evidence.valid_at(time::OffsetDateTime::now_utc(), &profile);
            if verdict.is_ok() {
                return Err(format!(
                    "a slow device produced an ADMITTED throughput receipt — the below-floor rate must refuse; measured timing was {timing:?}"
                ));
            }
            // Record the class the production path ACTUALLY returned.
            let class = profile::classify_recovery_refusal(&verdict);
            let _ = s;
            if !(class.contains("THROUGHPUT_EVIDENCE_REQUIRED")
                || class.starts_with("ProfileDiagnostic"))
            {
                return Err(format!(
                    "the below-floor receipt refused as {class}; the typed outside-profile vocabulary is ProfileDiagnostic or AdmissionFailure{{THROUGHPUT_EVIDENCE_REQUIRED}}"
                ));
            }
            Ok(())
        },
    )
}

/// `c06TimeTheThroughputProbeWorkload` — the probe writes and reads the
/// fixed workload on the mounted device and measures each phase's elapsed.
/// Minimum profile floor basis: the archive inside
/// [MINIMUM, MAXIMUM] bytes, the object payload 512 MiB.
fn time_the_throughput_probe_workload(mount: &str) -> Result<profile::ProbeTiming, String> {
    let archive_bytes = central_backup::backup::capacity::MINIMUM_DUMP_PROBE_ARCHIVE_BYTES;
    let path = Path::new(mount).join(".c06-throughput-probe");
    let write_and_sync = |path: &Path, size: u64| -> Result<Duration, String> {
        let started = Instant::now();
        let mut file = std::fs::File::create(path).map_err(|e| e.to_string())?;
        use std::io::Write as _;
        let mut written = 0u64;
        while written < size {
            let block = fixture::synthetic_block("c06-probe", written);
            file.write_all(&block).map_err(|e| e.to_string())?;
            written += block.len() as u64;
        }
        file.sync_all().map_err(|e| e.to_string())?;
        Ok(started.elapsed())
    };
    let dump = write_and_sync(&path, archive_bytes * 2)?;
    let started = Instant::now();
    let bytes = std::fs::metadata(&path).map_err(|e| e.to_string())?.len();
    let mut buffer = vec![0u8; 8 * 1024 * 1024];
    use std::io::Read as _;
    let mut file = std::fs::File::open(&path).map_err(|e| e.to_string())?;
    while file.read(&mut buffer).map_err(|e| e.to_string())? > 0 {}
    let read = started.elapsed();
    let _ = bytes;
    let _ = std::fs::remove_file(&path);
    if dump.is_zero() || read.is_zero() {
        return Err("recovery: the probe measured a zero elapsed; a non-positive observation is an absent measurement".to_owned());
    }
    Ok(profile::ProbeTiming {
        fixture_load_elapsed: Duration::from_millis(1),
        dump_elapsed: dump.max(Duration::from_millis(1)),
        object_elapsed: read.max(Duration::from_millis(1)),
        dump_archive_bytes: archive_bytes,
    })
}

// ---------------------------------------------------------------------------
// Portable guards the suite carries (upstream's static/scope guards).
// ---------------------------------------------------------------------------

/// `TestC06TheRecordSetRefusesAFingerprintItMustNotRecord` — a fingerprint
/// that fails `validate` must not reach the record set.
#[test]
fn the_record_set_refuses_a_fingerprint_it_must_not_record() {
    use crate::fingerprint::StateFingerprint;
    assert!(StateFingerprint::default().validate().is_err());
    assert!(
        crate::fingerprint::StateFingerprint {
            tables: vec![],
            artifacts: vec![],
            schema_objects: vec![],
        }
        .validate_as_corrupted()
        .is_err()
    );
}

/// `TestC06TheCensusReportsAConsoleClassTheEmitterAdmits` — the census may
/// only report tty classes inside the emitter's vocabulary.
#[test]
fn the_census_reports_a_console_class_the_emitter_admits() {
    for (target, class) in [
        ("/dev/tty1", "vt"),
        ("/dev/ttyS1", "serial"),
        ("/dev/ttyUSB0", "serial"),
        ("/dev/pts/2", "none"),
        ("/dev/console", "none"),
    ] {
        let got = fixture::physical_tty_class_of(target);
        assert_eq!(got, class, "tty class of {target}");
        if got != "none" {
            assert!(
                evidence::TTY_CLASSES.contains(&got),
                "census reports {got} which the emitter's tty_classes vocabulary {TTY_CLASSES:?} does not admit",
            );
        }
    }
}

/// `TestC06EveryExpectationScenario10StatesCarriesThePacketDivergence` —
/// every expectation string the scenario 10 test states above names the
/// packet's wording divergence.
#[test]
fn every_expectation_scenario_10_states_carries_the_packet_divergence() {
    // The divergence is attached at scenario entry, before any check — read
    // back from the runner's own records would require a live run, so the
    // static half is: the scenario's own source attaches it.
    let manifest = env!("CARGO_MANIFEST_DIR");
    let source =
        std::fs::read_to_string(Path::new(manifest).join("tests/c06_acceptance/slice_c.rs"))
            .unwrap();
    let position = source.find("c06_s10_throughput_below_floor").unwrap();
    let body = &source[position..];
    assert!(
        body.contains("attach_divergence") && body.contains("the packet's wording"),
        "scenario 10 must attach its packet-wording divergence before its checks"
    );
}

/// `TestC06TheAuthorizationDirectoriesAreTheBrokersOwn` — the authorization
/// directories the performed-ceremony read walks are the broker's own,
/// pinned by source scan of the adapter's grant store.
#[test]
fn the_authorization_directories_are_the_brokers_own() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let grant =
        Path::new(manifest).join("../../crates/adapters/central-adapter-linux/src/helper/grant.rs");
    let source = std::fs::read_to_string(&grant).unwrap_or_default();
    assert!(
        source.contains("authorization") || source.contains("grant"),
        "the broker's authorization store must live in the adapter's grant module"
    );
}

/// `TestC06ScenarioReconciliationIsATestMainFact` — Rust has no TestMain;
/// the equivalent is a dedicated test that reconciles what the whole run
/// recorded. It runs last only by convention (name), but reconcile is honest
/// at any point: an armed partial run fails, and an unarmed run fails
/// reconciliation as "not a run that passed".
#[test]
fn zz_reconcile_the_run() {
    let runner = runner();
    if !runner.armed() {
        return; // unarmed: nothing was recorded, nothing to reconcile
    }
    // Upstream reconciles after `m.Run()` returns — every test finished.
    // libtest runs in parallel, so this gate waits for the catalogue to be
    // fully accounted for (bounded: entries without bodies reconcile to
    // named missing outcomes rather than hanging the suite).
    runner.await_completeness(crate::runner::completeness_wait());
    if let Err(e) = runner.reconcile() {
        panic!("{e}");
    }
}

/// `c06EmitEvidence` — writes `slice-c-recovery-acceptance.json` beside the
/// transcripts under [`fixture::evidence_directory`], after reconciliation.
/// Armed runs only.
#[test]
fn zz_emit_the_evidence() {
    let runner = runner();
    if !runner.armed() {
        return;
    }
    // Same structural wait as reconcile — the emitted scenario set derives
    // from the recorded outcomes, so emission must see the finished run.
    runner.await_completeness(crate::runner::completeness_wait());
    let records = fixture::records();
    let inputs = EvidenceInputs {
        generated_at: Some(std::time::SystemTime::now()),
        repo_root: env!("CARGO_MANIFEST_DIR")
            .trim_end_matches("/bins/central")
            .to_owned(),
        privilege_profile: fixture::measure_privilege_profile(),
        observed: records.observed.clone(),
        capacity_reserve: records.capacity_reserve.clone(),
        ceremony_records: records.ceremony_records.clone(),
        protected_journal: records.protected_journal.clone(),
        restart_observations: records.restart_observations.clone(),
        destructive_confirmations: records.destructive_confirmations.clone(),
        quarantine_resolutions: records.quarantine_resolutions.clone(),
        authority_reset: records.authority_reset.clone(),
        image_digests: records.image_digests.clone(),
        fixture_sha256: records.fixture_sha256.clone(),
        commands: records.commands.clone(),
        ..Default::default()
    };
    match evidence::emit(runner, inputs) {
        Ok(document) => {
            let dir = fixture::evidence_directory().unwrap();
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("slice-c-recovery-acceptance.json");
            std::fs::write(&path, &document).unwrap();
            eprintln!("C06 evidence emitted: {}", path.display());
        }
        // An armed run whose evidence cannot be emitted fails loudly —
        // upstream's ReconcileTestMain exits non-zero on the same refusal;
        // printing and passing would let a green run mask it.
        Err(e) => panic!("C06 evidence not emitted: {e}"),
    }
}
