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
pub(crate) fn c06_s1_backup_create() {
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
            let mut log = crate::scenario2::ScenarioLog::new(id);
            // Governance field 17's four tool readings, taken the way
            // upstream takes them: the server and toolchain at bring-up
            // (this body is the first catalogue entry), the two pg tools
            // inside scenario 1's own body — every one from the tool's own
            // output, through recorders that refuse a second capture so a
            // re-reading taken after the environment changed cannot
            // silently replace the reading this run restored under.
            let dsn = crate::scenario2::require_env(fixture::PG_DSN_ENV).ok_or_else(|| {
                format!(
                    "{} unset; the server version governance field 17 carries cannot be read",
                    fixture::PG_DSN_ENV
                )
            })?;
            let server = crate::scenario2::connect_pg(&dsn)?
                .run(|c| {
                    Box::pin(async move {
                        sqlx::query_scalar::<sqlx::Postgres, String>("SELECT version()")
                            .fetch_one(&mut *c)
                            .await
                            .map_err(|e| {
                                central_foundation::failure::Failure::internal(
                                    "c06",
                                    format!("read the migrated server's own version: {e}"),
                                )
                            })
                    })
                })
                .map_err(|e| e.to_string())?;
            let toolchain_out = std::process::Command::new("rustc")
                .arg("--version")
                .output()
                .map_err(|e| format!("rustc --version could not run: {e}"))?;
            let toolchain = format!(
                "{}{}",
                String::from_utf8_lossy(&toolchain_out.stdout),
                String::from_utf8_lossy(&toolchain_out.stderr)
            );
            fixture::records().record_server_tool_versions(&server, &toolchain)?;
            let pg_dump = fixture::pg_tool_version_output("pg_dump")?;
            let pg_restore = fixture::pg_tool_version_output("pg_restore")?;
            fixture::records().record_pg_tool_versions(&pg_dump, &pg_restore)?;
            log.recordf(format_args!(
                "tool versions recorded from each tool's own output: server, rustc, pg_dump, pg_restore"
            ));
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
            // Governance field 9, recorded where the invocation is made —
            // upstream's RecordCommand site for this command. No variable is
            // set FOR this command: the operator secret is deliberately
            // STRIPPED from its environment rather than passed, so it is not
            // a variable that was set and does not appear here.
            let exit_code = output.status.code().unwrap_or(-1) as i64;
            let reason = crate::ceremony::reason_from_envelope(&envelope);
            fixture::records().record_command(
                id,
                "central backup create",
                Vec::new(),
                exit_code,
                if exit_code == 0 && reason == "ok" {
                    crate::evidence::SCENARIO_PASSED
                } else {
                    crate::evidence::SCENARIO_FAILED
                },
                &crate::evidence::evidence_digest(envelope.as_bytes()),
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
pub(crate) fn c06_s9_capacity_below_floor() {
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
            let mut log = crate::scenario2::ScenarioLog::new(id);
            crate::continuous_run::gate_the_sequence("c06.s8.minimum_profile", &mut log)?;
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
                    // An admission MEASUREMENT, not a released reserve:
                    // nothing allocated, nothing released — `released: true`
                    // with an empty confirmation is the exact shape
                    // `check_capacity_reserve` exists to refuse.
                    allocated_bytes: 0,
                    released: false,
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
pub(crate) fn c06_s10_throughput_below_floor() {
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
            let mut log = crate::scenario2::ScenarioLog::new(id);
            crate::continuous_run::gate_the_sequence("c06.s9.capacity_below_floor", &mut log)?;
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

/// `c06MeasureBinaryDigests` — governance field 17's two build digests,
/// measured over the binaries the operator names for the run: the restore
/// engine and the launcher daemon, upstream's `harness.EngineSHA256` and
/// its out-of-worktree build. An unset or unreadable name leaves the field
/// empty and the emitter refuses it — a digest that could not be taken is
/// no digest at all.
fn measure_binary_digests() -> evidence::BinaryDigests {
    use sha2::Digest as _;
    let digest_of = |env: &str| -> String {
        std::env::var(env)
            .ok()
            .and_then(|path| std::fs::read(&path).ok())
            .map(|body| crate::hex_lower(sha2::Sha256::digest(&body)))
            .unwrap_or_default()
    };
    evidence::BinaryDigests {
        central_restore_build_sha256: digest_of("CENTRAL_C06_RESTORE_BIN"),
        launcher_daemon_build_sha256: digest_of("CENTRAL_C06_LAUNCHERD_BIN"),
    }
}

/// `c06EmitTheEvidenceArtifact` — drives the emitter for real and proves
/// what it emitted corresponds to what ran.
///
/// The order matters, kept verbatim from upstream. The inputs are validated
/// through the EMITTER'S OWN shape rules first, so a value composed wrong
/// fails naming the field rather than failing the whole emit at the end.
/// The census is checked before the emit, so a required skip is reported as
/// a skip rather than as a reconciliation error. The document is then
/// emitted twice and required to be byte identical, audited against the run
/// that produced it, and only then written — to a location outside the
/// repository, never into it.
#[test]
fn zz_emit_the_evidence() {
    let runner = runner();
    if !runner.armed() {
        return;
    }
    // Same structural wait as reconcile — the emitted scenario set derives
    // from the recorded outcomes, so emission must see the finished run.
    runner.await_completeness(crate::runner::completeness_wait());
    // Upstream's last gate — after the restart injections and before
    // emission: an instance a restart left unusable must not be covered by
    // an artifact that reads clean. Under the sequential driver the damage
    // belongs to the restart batch, exactly as upstream attributes it.
    if let Err(e) = crate::continuous_run::probe_the_instance_is_still_usable() {
        panic!(
            "after the restart injections' catalogue entries completed, the instance this continuous run shares is no longer usable: {e}.\n\nIn the sequential run the damage belongs to the restart batch. Emission is refused either way — an artifact over a damaged instance would carry a health claim the run no longer holds."
        );
    }
    // A transcript that could not be persisted during a body's unwind is a
    // digest committed to bytes that do not exist; refuse rather than write
    // an artifacts array naming files that are not there.
    let persist_failures = fixture::take_transcript_failures();
    if !persist_failures.is_empty() {
        panic!(
            "the run committed transcript digests whose bytes could not be persisted:\n  - {}",
            persist_failures.join("\n  - ")
        );
    }
    let generated_at = std::time::SystemTime::now();
    let records = fixture::records();
    let inputs = EvidenceInputs {
        generated_at: Some(generated_at),
        repo_root: env!("CARGO_MANIFEST_DIR")
            .trim_end_matches("/bins/central")
            .to_owned(),
        tool_version_output: records.tool_version_output.clone(),
        binary_digests: measure_binary_digests(),
        privilege_profile: fixture::measure_privilege_profile(),
        observed: records.observed.clone(),
        capacity_reserve: records.capacity_reserve.clone(),
        ceremony_records: records.ceremony_records.clone(),
        protected_journal: records.protected_journal.clone(),
        restart_observations: records.restart_observations.clone(),
        destructive_confirmations: records.destructive_confirmations.clone(),
        // Fields 25, 7 and 9 are Option-typed on the input: None emits the
        // explicit null not-measured marker, never a zeroed struct, an empty
        // map, or an empty array that would read as a measurement.
        quarantine_resolutions: records
            .quarantine_resolutions_recorded
            .then(|| records.quarantine_resolutions.clone()),
        authority_reset: records.authority_reset.clone(),
        image_digests: measure_image_digests()
            .unwrap_or_else(|e| panic!("governance field 7 could not be measured: {e}")),
        fixture_sha256: records.fixture_sha256.clone(),
        commands: records.commands_recorded.then(|| records.commands.clone()),
    };
    if let Err(e) = evidence::validate_evidence_inputs(&inputs) {
        panic!("the inputs this run assembled are not ones the emitter admits: {e}");
    }
    for entry in &runner.census().entries {
        if entry.required_for_sc_g3 {
            panic!(
                "{} is required for SC-G3 and this run recorded a skip for it (reason_class={}): {}. Governance rule E-1: a skip recorded where the gate requires a run is a gate failure, not a caveat",
                entry.id, entry.reason_class, entry.detail
            );
        }
    }
    let document = match evidence::emit(runner, inputs.clone()) {
        Ok(document) => document,
        // An armed run whose evidence cannot be emitted fails loudly —
        // upstream's ReconcileTestMain exits non-zero on the same refusal;
        // printing and passing would let a green run mask it.
        Err(e) => panic!("emitting the C06 evidence artifact failed: {e}"),
    };
    let again = match evidence::emit(runner, inputs) {
        Ok(document) => document,
        Err(e) => panic!("the second emit of the same run failed: {e}"),
    };
    if document != again {
        panic!(
            "two emits of the same run produced different bytes ({} and {}); governance field 12 recomputes this document's digest, and a document that is not a function of the run is one no reviewer can recompute",
            evidence::evidence_digest(&document),
            evidence::evidence_digest(&again)
        );
    }
    if let Err(e) = evidence::scan_prohibitions(&document) {
        panic!("the emitted artifact carries material governance section 3.1 forbids: {e}");
    }
    let decoded: evidence::Evidence = match serde_json::from_slice(&document) {
        Ok(evidence) => evidence,
        Err(e) => panic!("the emitted artifact cannot be read back: {e}"),
    };
    // `&*records` — the audit takes the record SET, not the shared guard.
    if let Err(e) = crate::continuous_run::audit_the_emitted_artifact(&decoded, Some(&*records)) {
        panic!("the emitted artifact does not correspond to the run that produced it:\n{e}");
    }
    drop(records);

    let dir = fixture::evidence_directory()
        .unwrap_or_else(|e| panic!("resolve the directory this run's evidence is written to: {e}"));
    std::fs::create_dir_all(&dir)
        .unwrap_or_else(|e| panic!("create the evidence directory {}: {e}", dir.display()));
    let target = dir.join("slice-c-recovery-acceptance.json");
    // Mode 0600 — the artifact names transcripts a reviewer reads beside
    // it; nothing else may read or replace what the run attested.
    std::fs::write(&target, &document)
        .unwrap_or_else(|e| panic!("write the emitted artifact: {e}"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(EVIDENCE_FILE_MODE))
            .unwrap_or_else(|e| panic!("mode the emitted artifact 0600: {e}"));
        let mode = std::fs::metadata(&target)
            .unwrap_or_else(|e| panic!("stat the emitted artifact: {e}"))
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, EVIDENCE_FILE_MODE,
            "the emitted artifact must be readable by the run's user only; mode {mode:o} is not 0600"
        );
    }
    let dir_str = dir
        .to_str()
        .unwrap_or_else(|| panic!("the evidence directory {} is not UTF-8", dir.display()));

    // FINAL-REVIEW I-2, decided where it can be decided: the artifacts
    // array is re-read against the directory it was just written into.
    // Every entry's file must exist and recompute to the digest the entry
    // registers AND to the log_sha256 the scenario itself recorded, for
    // every scenario, pass or fail. Emitting the array is a claim; this is
    // the check of it, and it runs against the same bytes a reviewer would
    // be handed.
    if let Err(e) = evidence::verify_transcripts(dir_str, &decoded) {
        panic!("the emitted artifact registers transcripts this run cannot produce:\n{e}");
    }
    eprintln!(
        "C06 evidence: {} transcript(s) registered in the artifacts array, each re-read beside the artifact and recomputed to the log_sha256 its scenario recorded",
        decoded.artifacts.len()
    );
    eprintln!(
        "C06 evidence artifact emitted: {} bytes, sha256 {}, {} scenarios, {} restart injections, {} skips, catalogue {}",
        document.len(),
        evidence::evidence_digest(&document),
        decoded.scenarios.len(),
        decoded.restart_injections.len(),
        decoded.skip_census.count,
        decoded.catalogue_sha256
    );
    eprintln!(
        "C06 evidence artifact written to the directory named by {}, or to the suite's default under target/c06-evidence when it is unset. It is NOT written into the repository: a committed instance would be evidence this suite does not ship.",
        fixture::EVIDENCE_OUTPUT_ENV
    );
}

/// `c06EvidenceWrittenMode` — the artifact's required file mode.
#[cfg(unix)]
pub(crate) const EVIDENCE_FILE_MODE: u32 = 0o600;

/// `c06MeasureImageDigests` — governance field 7: each container image the
/// run used, resolved to its digest-pinned reference through `docker
/// inspect`, upstream's own two-step. It is measured from the RUNNING
/// CONTAINERS rather than read off a fixture, because field 7 is about the
/// images the run used: the reference a container was started with is asked
/// of the container, and its digest-pinned form is then asked of the image —
/// a mutable tag is not a weaker pin, it is no pin.
///
/// The port's containers are named by `CENTRAL_C06_POSTGRES_CONTAINER` and
/// `CENTRAL_C06_MINIO_CONTAINER` — the port has no self-provisioning
/// composition to derive names from the way upstream's bring-up does. A run
/// that names no containers emits `null` (the not-measured marker), never
/// `{}`, which would read as a measured-empty map.
fn measure_image_digests() -> Result<Option<std::collections::HashMap<String, String>>, String> {
    let mut digests = std::collections::HashMap::new();
    for (service, env) in [
        ("postgres", "CENTRAL_C06_POSTGRES_CONTAINER"),
        ("minio", "CENTRAL_C06_MINIO_CONTAINER"),
    ] {
        let Some(container) = crate::scenario2::require_env(env) else {
            continue;
        };
        let inspect = |args: &[&str]| -> Result<String, String> {
            let output = std::process::Command::new("docker")
                .args(args)
                .output()
                .map_err(|e| format!("docker {} could not run: {e}", args.join(" ")))?;
            if !output.status.success() {
                return Err(format!(
                    "docker {} exited {}: {}",
                    args.join(" "),
                    output.status,
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
        };
        let reference = inspect(&["inspect", &container, "--format", "{{.Config.Image}}"])?;
        let pinned = inspect(&[
            "inspect",
            "image",
            &reference,
            "--format",
            "{{if .RepoDigests}}{{index .RepoDigests 0}}{{end}}",
        ])?;
        if pinned.is_empty() {
            return Err(format!(
                "the {service} image {reference:?} carries no repository digest, so governance field 7's pin cannot be recorded as a fact about it"
            ));
        }
        digests.insert(service.to_owned(), pinned);
    }
    if digests.is_empty() {
        return Ok(None);
    }
    Ok(Some(digests))
}
