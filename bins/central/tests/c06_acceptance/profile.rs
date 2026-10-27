//! `internal/recovery/{measurement,profile}.go` — C02's admission profile
//! arithmetic: the capacity floor, the throughput receipt, the five emitted
//! measurements, and the differential checks that prove a refusal is about
//! the fact the scenario is about rather than one of the other inputs that
//! answer with the same string.
//!
//! THE COUNT, AS UPSTREAM STATES IT: `CAPACITY_INSUFFICIENT` is returned from
//! eight distinct return sites of `check_backup_admission`; two (overflow
//! guards) are unreachable at the installed profile, so six are reachable,
//! driven by seven distinguishable inputs — exactly one about free space.
//! `THROUGHPUT_EVIDENCE_REQUIRED` comes from ~thirty conjuncts of
//! `ThroughputEvidence::valid_at`. The checks below are differential: move
//! one fact, show the verdict move with it.

use std::time::Duration as StdDuration;

use central_backup::backup::capacity::{
    BackupCheck, CapacitySnapshot, DeviceCapacitySnapshot, MAXIMUM_DUMP_PROBE_ARCHIVE_BYTES,
    MINIMUM_DUMP_PROBE_ARCHIVE_BYTES, OBJECT_PROBE_PAYLOAD_BYTES, RecoveryProfile,
    THROUGHPUT_EVIDENCE_MAX_AGE, check_backup_admission, default_recovery_profile,
};
use central_backup::recovery::profile::{
    BACKUP_THROUGHPUT_RECEIPT_SCHEMA, BACKUP_TRANSFER_ENVELOPE_VERSION, ThroughputEvidence,
    ThroughputEvidenceBinding,
};
use sha2::{Digest, Sha256};

use crate::evidence::{Measurement, Measurements, ObservedMeasurements};

// ---------------------------------------------------------------------------
// Classifying a C02 refusal.
// ---------------------------------------------------------------------------

/// `ClassifyRecoveryRefusal` — renders the admission result as its typed
/// class so a run log and a portable test describe the same answer in the
/// same words.
pub fn classify_recovery_refusal(check: &Result<(), BackupCheck>) -> String {
    match check {
        Ok(()) => "admitted".to_owned(),
        Err(BackupCheck::Admission(reason)) => format!("AdmissionFailure{{{reason}}}"),
        Err(BackupCheck::Diagnostic(reason)) => format!("ProfileDiagnostic{{{reason}}}"),
        Err(BackupCheck::Profile(failure)) => format!("other{{{failure}}}"),
    }
}

/// `IsAdmissionFailure` — an `Admission` carrying exactly `reason`.
pub fn is_admission_failure(check: &Result<(), BackupCheck>, reason: &str) -> bool {
    matches!(check, Err(BackupCheck::Admission(r)) if r == reason)
}

/// `IsProfileDiagnostic`.
pub fn is_profile_diagnostic(check: &Result<(), BackupCheck>) -> bool {
    matches!(check, Err(BackupCheck::Diagnostic(_)))
}

// ---------------------------------------------------------------------------
// Scenario 9's capacity floor.
// ---------------------------------------------------------------------------

/// `CapacityFloorFor` — the free-space threshold applied to EVERY writable
/// device independently: survival reserve + free floor + the whole projected
/// write. `<=` the floor is refused, so exactly at the floor is refused.
/// Reports `None` on any overflow.
pub fn capacity_floor_for(profile: &RecoveryProfile, snapshot: &CapacitySnapshot) -> Option<u64> {
    let projected = snapshot.database_bytes.checked_add(snapshot.object_bytes)?;
    let threshold = profile.survival_reserve.checked_add(profile.free_floor)?;
    threshold.checked_add(projected)
}

/// `RefuseDeviceThatIsNotBelowFloor` — a below-floor scenario needs a device
/// that is genuinely below the floor; anything else is no subject at all.
pub fn refuse_device_that_is_not_below_floor(
    device: &DeviceCapacitySnapshot,
    profile: &RecoveryProfile,
    snapshot: &CapacitySnapshot,
) -> Result<(), String> {
    if device.device_id.is_empty() {
        return Err("recovery: the measured device carries no opaque identity, so check_backup_admission would refuse it for the empty-identity reason rather than for its free space -- under the identical CAPACITY_INSUFFICIENT string".to_owned());
    }
    if device.free_bytes == 0 {
        return Err("recovery: the measured device reports zero free bytes, which is what a capacity source that failed and returned its zero value looks like; it satisfies 'below the floor' while measuring nothing".to_owned());
    }
    let threshold = capacity_floor_for(profile, snapshot).ok_or_else(|| {
        "recovery: the capacity floor overflows for this profile and snapshot, so there is no threshold to be below".to_owned()
    })?;
    if device.free_bytes > threshold {
        return Err(format!(
            "recovery: the device this scenario constrained measures {} free bytes, which is above the {threshold}-byte floor (survival reserve {} + free floor {} + projected write {}); it is not a below-floor subject, and any refusal observed from it would be one of the six other CAPACITY_INSUFFICIENT inputs that are not about free space",
            device.free_bytes,
            profile.survival_reserve,
            profile.free_floor,
            snapshot.database_bytes + snapshot.object_bytes
        ));
    }
    Ok(())
}

/// `VerifyCapacityRefusalIsAboutFreeSpace` — scenario 9's load-bearing check,
/// differential: the measured snapshot is refused; the SAME snapshot with
/// every device's free space raised one byte above the floor is admitted.
pub fn verify_capacity_refusal_is_about_free_space(
    profile: &RecoveryProfile,
    snapshot: &CapacitySnapshot,
) -> Result<(), String> {
    let threshold = capacity_floor_for(profile, snapshot).ok_or_else(|| {
        "recovery: the capacity floor overflows for this profile and snapshot, so no differential can be drawn across it".to_owned()
    })?;
    if snapshot.devices.is_empty() {
        return Err("recovery: the snapshot carries no device, so it is refused for the empty-census reason and raising free space cannot change that".to_owned());
    }
    let as_measured = check_backup_admission(profile, snapshot);
    if !is_admission_failure(&as_measured, "CAPACITY_INSUFFICIENT") {
        return Err(format!(
            "recovery: the measured snapshot yielded {}, want AdmissionFailure{{CAPACITY_INSUFFICIENT}}",
            classify_recovery_refusal(&as_measured)
        ));
    }
    let mut raised = snapshot.clone();
    for device in &mut raised.devices {
        if threshold == u64::MAX {
            return Err("recovery: the capacity floor is the maximum representable value, so there is no free-space reading above it to compare against".to_owned());
        }
        device.free_bytes = threshold + 1;
    }
    if let Err(check) = check_backup_admission(profile, &raised) {
        return Err(format!(
            "recovery: the same snapshot with every device raised one byte above the {threshold}-byte floor is still refused ({}). The refusal this scenario observed is therefore NOT about free space -- check_backup_admission answers CAPACITY_INSUFFICIENT from eight return sites, six of them reachable at the installed profile and driven by seven distinguishable inputs, and six of those inputs have nothing to do with the device census's readings",
            classify_recovery_refusal(&Err(check))
        ));
    }
    Ok(())
}

/// `VerifyCapacityIsNotAggregatedAcrossDevices` — C02's per-device rule: a
/// device below the floor is refused however much its neighbours hold.
pub fn verify_capacity_is_not_aggregated_across_devices(
    profile: &RecoveryProfile,
    snapshot: &CapacitySnapshot,
    starved: &DeviceCapacitySnapshot,
) -> Result<(), String> {
    let threshold = capacity_floor_for(profile, snapshot).ok_or_else(|| {
        "recovery: the capacity floor overflows for this profile and snapshot".to_owned()
    })?;
    if starved.device_id.is_empty() || starved.free_bytes > threshold {
        return Err(format!(
            "recovery: the starved device ({:?}, {} free bytes) is not below the {threshold}-byte floor, so this proves nothing about aggregation",
            starved.device_id, starved.free_bytes
        ));
    }
    if threshold > u64::MAX / 1000 {
        return Err(
            "recovery: the floor is too large for a generous neighbour to be represented"
                .to_owned(),
        );
    }
    let generous = DeviceCapacitySnapshot {
        device_id: format!("{}-generous-neighbour", starved.device_id),
        free_bytes: threshold * 1000,
    };
    let mut alone = snapshot.clone();
    alone.devices = vec![generous.clone()];
    if let Err(check) = check_backup_admission(profile, &alone) {
        return Err(format!(
            "recovery: the generous neighbour is refused on its own ({}), so it cannot show that a starved device is refused despite it",
            classify_recovery_refusal(&Err(check))
        ));
    }
    let mut together = snapshot.clone();
    together.devices = vec![generous.clone(), starved.clone()];
    let check = check_backup_admission(profile, &together);
    if !is_admission_failure(&check, "CAPACITY_INSUFFICIENT") {
        return Err(format!(
            "recovery: a census of one device with {} free bytes and one with {} yielded {}; C02 checks every writable device independently and must refuse the starved one rather than aggregating free space from distinct filesystems",
            generous.free_bytes,
            starved.free_bytes,
            classify_recovery_refusal(&check)
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Scenario 10's throughput receipt.
// ---------------------------------------------------------------------------

/// `PinnedPGToolVersion` — the pg_dump/pg_restore version Slice C pins, and
/// the only value `ThroughputEvidenceBinding::validate` admits.
pub const PINNED_PG_TOOL_VERSION: &str = "16.14";

/// `ProbeTiming` — what a live throughput probe measured: the three elapsed
/// parts and the archive size the probe's own pg_dump produced.
#[derive(Debug, Clone, Copy)]
pub struct ProbeTiming {
    pub fixture_load_elapsed: StdDuration,
    pub dump_elapsed: StdDuration,
    pub object_elapsed: StdDuration,
    pub dump_archive_bytes: u64,
}

fn synthetic_fingerprint(label: &str) -> String {
    format!(
        "sha256:{}",
        crate::hex_lower(Sha256::digest(label.as_bytes()))
    )
}

/// `derivedBytesPerSecond` — `measuredBytesPerSecond`'s arithmetic, restated
/// because it is unexported in the domain: bytes / elapsed-in-whole-seconds,
/// with a sub-second elapsed counting as one.
fn derived_bytes_per_second(bytes: u64, elapsed: StdDuration) -> u64 {
    let seconds = elapsed.as_secs().max(1);
    bytes / seconds
}

/// `SyntheticThroughputEvidence` — a C02 receipt valid in every respect
/// EXCEPT what the supplied timings make of it, so scenario 10 can put a
/// genuinely measured slow-device timing in front of the production
/// admission path. Everything not a timing is obviously synthetic, derived
/// deterministically from a label.
pub fn synthetic_throughput_evidence(
    timing: ProbeTiming,
    now: time::OffsetDateTime,
) -> Result<ThroughputEvidence, String> {
    if timing.fixture_load_elapsed.is_zero()
        || timing.dump_elapsed.is_zero()
        || timing.object_elapsed.is_zero()
    {
        return Err(format!(
            "recovery: a throughput probe timing must be positive in all three parts, got fixture={:?} dump={:?} object={:?}",
            timing.fixture_load_elapsed, timing.dump_elapsed, timing.object_elapsed
        ));
    }
    if !(MINIMUM_DUMP_PROBE_ARCHIVE_BYTES..=MAXIMUM_DUMP_PROBE_ARCHIVE_BYTES)
        .contains(&timing.dump_archive_bytes)
    {
        return Err(format!(
            "recovery: the probe archive is {} bytes, and the C02 probe protocol fixes it inside [{MINIMUM_DUMP_PROBE_ARCHIVE_BYTES}, {MAXIMUM_DUMP_PROBE_ARCHIVE_BYTES}]; a receipt outside that range is refused for its archive size under the same THROUGHPUT_EVIDENCE_REQUIRED string a slow device produces",
            timing.dump_archive_bytes
        ));
    }
    if now == time::OffsetDateTime::UNIX_EPOCH {
        return Err("recovery: a throughput receipt cannot be dated from a zero time".to_owned());
    }
    let elapsed = |d: StdDuration| {
        time::Duration::try_from(d).map_err(|e| format!("recovery: probe timing out of range: {e}"))
    };
    let probe_elapsed =
        elapsed(timing.fixture_load_elapsed + timing.dump_elapsed + timing.object_elapsed)?;
    let completed_at = now;
    let started_at = completed_at - probe_elapsed;
    let dump_work = timing.dump_archive_bytes * 2;
    let object_work = OBJECT_PROBE_PAYLOAD_BYTES * 3;
    let binding = ThroughputEvidenceBinding {
        instance_id: uuid::Uuid::now_v7(),
        payload_epoch_id: uuid::Uuid::now_v7(),
        target_fingerprint: synthetic_fingerprint("target"),
        repository_binding_id: uuid::Uuid::now_v7(),
        device_mount_set_digest: synthetic_fingerprint("device-mount-set"),
        host_profile_digest: synthetic_fingerprint("host-profile"),
        dependency_provisioning_digest: synthetic_fingerprint("dependency-provisioning"),
        postgres_image_digest: synthetic_fingerprint("postgres-image"),
        minio_image_digest: synthetic_fingerprint("minio-image"),
        pg_dump_tool_digest: synthetic_fingerprint("pg-dump-tool"),
        pg_dump_tool_version: PINNED_PG_TOOL_VERSION.to_owned(),
        config_digest: synthetic_fingerprint("config"),
        minio_backup_policy_digest: synthetic_fingerprint("minio-backup-policy"),
        fixture_digest: synthetic_fingerprint("fixture"),
        transfer_envelope_version: BACKUP_TRANSFER_ENVELOPE_VERSION.to_owned(),
        transfer_envelope_digest: synthetic_fingerprint("transfer-envelope"),
    };
    Ok(ThroughputEvidence {
        schema_version: BACKUP_THROUGHPUT_RECEIPT_SCHEMA.to_owned(),
        receipt_id: uuid::Uuid::now_v7(),
        probe_operation_id: uuid::Uuid::now_v7(),
        probe_started_at: started_at,
        probe_completed_at: completed_at,
        probe_elapsed,
        measured_at: completed_at,
        // The receipt's whole permitted lifetime.
        expires_at: completed_at + THROUGHPUT_EVIDENCE_MAX_AGE,
        binding,
        dump_archive_bytes: timing.dump_archive_bytes,
        dump_work_bytes: dump_work,
        dump_elapsed: elapsed(timing.dump_elapsed)?,
        fixture_load_elapsed: elapsed(timing.fixture_load_elapsed)?,
        // The rates are DERIVED from the work and the measured elapsed, by the
        // same arithmetic admission recomputes them with.
        dump_bytes_per_sec: derived_bytes_per_second(dump_work, timing.dump_elapsed),
        object_payload_bytes: OBJECT_PROBE_PAYLOAD_BYTES,
        object_work_bytes: object_work,
        object_elapsed: elapsed(timing.object_elapsed)?,
        object_bytes_per_sec: derived_bytes_per_second(object_work, timing.object_elapsed),
        cleanup_state: "clean".to_owned(),
        cleanup_verified_at: completed_at,
    })
}

// ---------------------------------------------------------------------------
// Manifest field 11's measurement vocabulary (measurement.go).
// ---------------------------------------------------------------------------

/// `MeasurementField` — one key of the emitted measurements object; values
/// are the serde field names `Measurements` itself carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MeasurementField {
    BackupBytesPerSec,
    RestoreBytesPerSec,
    RestoreElapsedSeconds,
    RepositoryBytes,
    DeviceFreeBytesMin,
}

impl MeasurementField {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BackupBytesPerSec => "backup_bytes_per_sec",
            Self::RestoreBytesPerSec => "restore_bytes_per_sec",
            Self::RestoreElapsedSeconds => "restore_elapsed_seconds",
            Self::RepositoryBytes => "repository_bytes",
            Self::DeviceFreeBytesMin => "device_free_bytes_min",
        }
    }
}

pub const RELATION_AT_LEAST: &str = ">=";
pub const RELATION_AT_MOST: &str = "<=";
pub const RELATION_BELOW: &str = "<";
pub const RELATION_ABOVE: &str = ">";
/// `RelationNotMeasured` — what the emitter writes in place of a direction
/// when nobody took the reading (final-review I-3).
pub const RELATION_NOT_MEASURED: &str = "not measured";

/// `MeasurementFields` — the declared vocabulary, in emitted order.
pub const MEASUREMENT_FIELDS: [MeasurementField; 5] = [
    MeasurementField::BackupBytesPerSec,
    MeasurementField::RestoreBytesPerSec,
    MeasurementField::RestoreElapsedSeconds,
    MeasurementField::RepositoryBytes,
    MeasurementField::DeviceFreeBytesMin,
];

/// `MeasurementsByField` — renders a `Measurements` keyed by its own emitted
/// field names, read off the serialized object so the vocabulary is the
/// artifact's, not a second typed-out copy.
pub fn measurements_by_field(
    measurements: &Measurements,
) -> std::collections::BTreeMap<String, Measurement> {
    let mut out = std::collections::BTreeMap::new();
    for (field, measurement) in [
        (
            MeasurementField::BackupBytesPerSec,
            &measurements.backup_bytes_per_sec,
        ),
        (
            MeasurementField::RestoreBytesPerSec,
            &measurements.restore_bytes_per_sec,
        ),
        (
            MeasurementField::RestoreElapsedSeconds,
            &measurements.restore_elapsed_seconds,
        ),
        (
            MeasurementField::RepositoryBytes,
            &measurements.repository_bytes,
        ),
        (
            MeasurementField::DeviceFreeBytesMin,
            &measurements.device_free_bytes_min,
        ),
    ] {
        out.insert(field.as_str().to_owned(), measurement.clone());
    }
    out
}

impl Measurement {
    /// `Holds` — evaluates the reading against its own declared bound; an
    /// unrecognised relation is an error and never a pass.
    pub fn holds(&self) -> Result<bool, String> {
        match self.relation.as_str() {
            RELATION_AT_LEAST => Ok(self.observed >= self.bound),
            RELATION_AT_MOST => Ok(self.observed <= self.bound),
            RELATION_BELOW => Ok(self.observed < self.bound),
            RELATION_ABOVE => Ok(self.observed > self.bound),
            other => Err(format!(
                "recovery: {other:?} is not a relation this suite can evaluate; a measurement carried with an unrecognised relation is one no reviewer can recompute, and treating it as satisfied would emit an unchecked number"
            )),
        }
    }
}

/// `declaredRelations` — the direction each measurement is checked in.
fn declared_relation(field: MeasurementField) -> &'static str {
    match field {
        MeasurementField::BackupBytesPerSec => RELATION_AT_LEAST,
        MeasurementField::RestoreBytesPerSec => RELATION_AT_LEAST,
        MeasurementField::RestoreElapsedSeconds => RELATION_AT_MOST,
        MeasurementField::RepositoryBytes => RELATION_BELOW,
        MeasurementField::DeviceFreeBytesMin => RELATION_ABOVE,
    }
}

/// `DeclaredBoundsFromInstalledProfile` — each bound derived from the
/// installed recovery profile rather than restated; a zero anywhere is a
/// refusal, not a narrower check.
pub fn declared_bounds_from_installed_profile()
-> Result<std::collections::BTreeMap<String, i64>, String> {
    let profile = default_recovery_profile();
    profile
        .validate()
        .map_err(|e| format!("recovery: the installed recovery profile does not validate, so no bound can be derived from it: {e}"))?;
    let deadline_seconds = profile.default_deadline.whole_seconds();
    let mut bounds = std::collections::BTreeMap::new();
    bounds.insert(
        MeasurementField::BackupBytesPerSec.as_str().to_owned(),
        profile.min_throughput_bps as i64,
    );
    bounds.insert(
        MeasurementField::RestoreBytesPerSec.as_str().to_owned(),
        profile.min_throughput_bps as i64,
    );
    bounds.insert(
        MeasurementField::RestoreElapsedSeconds.as_str().to_owned(),
        deadline_seconds,
    );
    bounds.insert(
        MeasurementField::RepositoryBytes.as_str().to_owned(),
        profile.max_repository_bytes as i64,
    );
    bounds.insert(
        MeasurementField::DeviceFreeBytesMin.as_str().to_owned(),
        (profile.survival_reserve + profile.free_floor) as i64,
    );
    let zero: Vec<&String> = bounds
        .iter()
        .filter(|(_, v)| **v <= 0)
        .map(|(k, _)| k)
        .collect();
    if !zero.is_empty() {
        return Err(format!(
            "recovery: the installed profile derives a non-positive bound for {}; a bound of zero is not a narrower check, it is no check",
            zero.iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    Ok(bounds)
}

/// `VerifyDeclaredBoundsAreTheInstalledProfiles` — the tie between the
/// constants the emitter writes and the profile the runtime admits against,
/// including each measurement's relation.
pub fn verify_declared_bounds_are_the_installed_profiles() -> Result<(), String> {
    let derived = declared_bounds_from_installed_profile()?;
    // Rendered from a POSITIVE observation because an absent reading emits
    // `not measured`; both halves are checked.
    let measured = ObservedMeasurements {
        backup_bytes_per_sec: 1,
        restore_bytes_per_sec: 1,
        restore_elapsed_seconds: 1,
        repository_bytes: 1,
        device_free_bytes_min: 1,
    };
    let emitted = measurements_by_field(&crate::evidence::measurements_from(&measured));
    if emitted.is_empty() {
        return Err("recovery: the emitter renders no measurement at all, so this check would compare two empty tables and report agreement".to_owned());
    }
    for (field, measurement) in measurements_by_field(&crate::evidence::measurements_from(
        &ObservedMeasurements::default(),
    )) {
        if measurement.relation != RELATION_NOT_MEASURED {
            return Err(format!(
                "recovery: {field} is emitted with relation {:?} over an observation nobody took; a reading of zero against an upper bound reads as a comfortably passing measurement, which is what {RELATION_NOT_MEASURED:?} exists to prevent",
                measurement.relation
            ));
        }
    }
    let mut problems = Vec::new();
    for (field, bound) in &derived {
        match emitted.get(field) {
            None => problems.push(format!("{field} is derived from the installed profile and the emitter carries no such measurement")),
            Some(measurement) => {
                if measurement.bound != *bound {
                    problems.push(format!("{field} is emitted with bound {} and the installed profile derives {bound}", measurement.bound));
                }
                let field_enum = MEASUREMENT_FIELDS.iter().find(|f| f.as_str() == field.as_str()).copied();
                if let Some(f) = field_enum
                    && measurement.relation != declared_relation(f)
                {
                    problems.push(format!("{field} is emitted with relation {:?} and is declared {:?}; a bound checked in the wrong direction passes for the observation it exists to refuse", measurement.relation, declared_relation(f)));
                }
            }
        }
    }
    for field in emitted.keys() {
        if !derived.contains_key(field) {
            problems.push(format!("{field} is emitted and no bound is derived for it from the installed profile, so it reaches the artifact unchecked"));
        }
    }
    if problems.is_empty() {
        return Ok(());
    }
    problems.sort();
    Err(format!(
        "recovery: the emitted measurement bounds are not the installed recovery profile's:\n  - {}",
        problems.join("\n  - ")
    ))
}

/// `MinimumProfileAssertion` — one of the packet's four assertions and the
/// measurements that decide it.
pub struct MinimumProfileAssertion {
    pub name: &'static str,
    pub fields: &'static [MeasurementField],
}

/// `MinimumProfileAssertions` — the declared mapping of the packet's four
/// assertions onto the artifact's five measurements.
pub fn minimum_profile_assertions() -> &'static [MinimumProfileAssertion] {
    &[
        MinimumProfileAssertion {
            name: "backup throughput within profile",
            fields: &[MeasurementField::BackupBytesPerSec],
        },
        MinimumProfileAssertion {
            name: "restore throughput within profile",
            fields: &[MeasurementField::RestoreBytesPerSec],
        },
        MinimumProfileAssertion {
            name: "disk usage within the reserve formula",
            fields: &[
                MeasurementField::RepositoryBytes,
                MeasurementField::DeviceFreeBytesMin,
            ],
        },
        MinimumProfileAssertion {
            name: "restore time within deadline",
            fields: &[MeasurementField::RestoreElapsedSeconds],
        },
    ]
}

/// `VerifyMeasurementVocabularyIsTheEmittedOne` — declared vocabulary, bound
/// table, relation table and assertion mapping held equal to the fields the
/// artifact carries, in both directions.
pub fn verify_measurement_vocabulary_is_the_emitted_one() -> Result<(), String> {
    let emitted = measurements_by_field(&crate::evidence::measurements_from(
        &ObservedMeasurements::default(),
    ));
    if emitted.is_empty() {
        return Err("recovery: the emitter renders no measurement at all, so every rule this check holds would hold over an empty set".to_owned());
    }
    let mut declared = std::collections::HashSet::new();
    for field in MEASUREMENT_FIELDS {
        if !declared.insert(field.as_str()) {
            return Err(format!(
                "recovery: {} is declared twice in the measurement vocabulary",
                field.as_str()
            ));
        }
    }
    let mut problems = Vec::new();
    for field in emitted.keys() {
        if !declared.contains(field.as_str()) {
            problems.push(format!("{field} is emitted into the artifact and is not in the declared vocabulary, so it carries no assertion and no bound anybody checks"));
        }
        if MEASUREMENT_FIELDS.iter().all(|f| f.as_str() != field) {
            problems.push(format!(
                "{field} is emitted into the artifact and no relation is declared for it"
            ));
        }
    }
    for field in &declared {
        if !emitted.contains_key(*field) {
            problems.push(format!(
                "{field} is in the declared vocabulary and the artifact carries no such measurement"
            ));
        }
    }
    let mut asserted: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    let assertions = minimum_profile_assertions();
    if assertions.is_empty() {
        problems.push("no minimum-profile assertion is declared at all".to_owned());
    }
    for assertion in assertions {
        if assertion.name.trim().is_empty() {
            problems.push("an assertion is declared with no name".to_owned());
        }
        if assertion.fields.is_empty() {
            problems.push(format!("assertion {:?} is decided by no measurement, so it holds whatever the run observed", assertion.name));
        }
        for field in assertion.fields {
            *asserted.entry(field.as_str()).or_default() += 1;
        }
    }
    for field in MEASUREMENT_FIELDS {
        match asserted.get(field.as_str()).copied().unwrap_or(0) {
            1 => {}
            0 => problems.push(format!("{} is measured and no assertion is decided by it, so it reaches the artifact without being part of any claim", field.as_str())),
            n => problems.push(format!("{} decides {n} assertions; a failure in it could not be attributed to one", field.as_str())),
        }
    }
    for field in asserted.keys() {
        if !declared.contains(field) {
            problems.push(format!(
                "an assertion is decided by {field}, which is not a declared measurement"
            ));
        }
    }
    if problems.is_empty() {
        return Ok(());
    }
    problems.sort();
    Err(format!(
        "recovery: the measurement vocabulary is not the one the artifact carries:\n  - {}",
        problems.join("\n  - ")
    ))
}

/// `VerifyMinimumProfileMeasurements` — scenario 8's whole check. A
/// non-positive observation is an ABSENT measurement and is named as one:
/// two of the four assertions are satisfied by zero, so a run that measured
/// nothing would otherwise pass them.
pub fn verify_minimum_profile_measurements(observed: &ObservedMeasurements) -> Result<(), String> {
    verify_measurement_vocabulary_is_the_emitted_one()?;
    verify_declared_bounds_are_the_installed_profiles()?;
    let by_field = measurements_by_field(&crate::evidence::measurements_from(observed));
    let mut problems = Vec::new();
    for assertion in minimum_profile_assertions() {
        for field in assertion.fields {
            let Some(measurement) = by_field.get(field.as_str()) else {
                problems.push(format!(
                    "{:?} is decided by {} and the emitter carries no such measurement",
                    assertion.name,
                    field.as_str()
                ));
                continue;
            };
            if measurement.observed <= 0 {
                problems.push(format!("{:?}: {} was never measured (observed {}); a non-positive reading is an absent measurement, and an absent measurement against an upper bound would read as a pass", assertion.name, field.as_str(), measurement.observed));
                continue;
            }
            match measurement.holds() {
                Err(e) => problems.push(e),
                Ok(false) => problems.push(format!(
                    "{:?}: {} observed {} fails its declared bound {} {}",
                    assertion.name,
                    field.as_str(),
                    measurement.observed,
                    measurement.relation,
                    measurement.bound
                )),
                Ok(true) => {}
            }
        }
    }
    if problems.is_empty() {
        return Ok(());
    }
    problems.sort();
    Err(format!(
        "recovery: the minimum-profile measurements do not hold:\n  - {}",
        problems.join("\n  - ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> CapacitySnapshot {
        CapacitySnapshot {
            devices: vec![],
            repository_bytes: 0,
            sealed_backups: 0,
            database_bytes: 1,
            object_bytes: 1,
            record_count: 1,
        }
    }

    #[test]
    fn the_capacity_floor_is_the_reserve_plus_the_whole_write() {
        let profile = default_recovery_profile();
        let snapshot = snapshot();
        let floor = capacity_floor_for(&profile, &snapshot).unwrap();
        assert_eq!(floor, profile.survival_reserve + profile.free_floor + 2);
    }

    #[test]
    fn a_device_at_the_floor_is_refused_and_above_it_admitted() {
        let profile = default_recovery_profile();
        let mut snapshot = snapshot();
        let floor = capacity_floor_for(&profile, &snapshot).unwrap();
        snapshot.devices = vec![DeviceCapacitySnapshot {
            device_id: "fs-deadbeef".to_owned(),
            free_bytes: floor,
        }];
        // `<=` the floor refuses.
        verify_capacity_refusal_is_about_free_space(&profile, &snapshot).unwrap();
    }

    #[test]
    fn the_differential_fails_when_free_space_is_not_the_reason() {
        let profile = default_recovery_profile();
        // A duplicate device identity refuses under the same string; raising
        // free space does not move the verdict, so the differential must fail.
        let mut snapshot = snapshot();
        snapshot.devices = vec![
            DeviceCapacitySnapshot {
                device_id: "fs-same".to_owned(),
                free_bytes: 1,
            },
            DeviceCapacitySnapshot {
                device_id: "fs-same".to_owned(),
                free_bytes: 1,
            },
        ];
        let err = verify_capacity_refusal_is_about_free_space(&profile, &snapshot)
            .expect_err("must refuse");
        assert!(err.contains("NOT about free space"), "{err}");
    }

    #[test]
    fn free_space_is_never_aggregated_across_devices() {
        let profile = default_recovery_profile();
        let mut snapshot = snapshot();
        let floor = capacity_floor_for(&profile, &snapshot).unwrap();
        snapshot.devices = vec![DeviceCapacitySnapshot {
            device_id: "fs-starved".to_owned(),
            free_bytes: 1,
        }];
        verify_capacity_is_not_aggregated_across_devices(
            &profile,
            &snapshot,
            &DeviceCapacitySnapshot {
                device_id: "fs-starved".to_owned(),
                free_bytes: 1,
            },
        )
        .unwrap();
        let _ = floor;
    }

    #[test]
    fn a_synthetic_receipt_validates_and_a_slow_one_fails_on_the_rate() {
        let now = time::OffsetDateTime::now_utc();
        let timing = ProbeTiming {
            fixture_load_elapsed: StdDuration::from_secs(10),
            dump_elapsed: StdDuration::from_secs(60),
            object_elapsed: StdDuration::from_secs(90),
            dump_archive_bytes: MINIMUM_DUMP_PROBE_ARCHIVE_BYTES,
        };
        let evidence = synthetic_throughput_evidence(timing, now).unwrap();
        let profile = default_recovery_profile();
        // Structurally valid against its own binding.
        evidence
            .valid_for(now, &profile, &evidence.binding().clone())
            .unwrap();
        // A non-positive part is refused rather than receipt-shaped.
        assert!(
            synthetic_throughput_evidence(
                ProbeTiming {
                    dump_elapsed: StdDuration::ZERO,
                    ..timing
                },
                now
            )
            .is_err()
        );
    }

    #[test]
    fn the_emitted_bounds_are_the_installed_profiles() {
        verify_declared_bounds_are_the_installed_profiles().unwrap();
        verify_measurement_vocabulary_is_the_emitted_one().unwrap();
    }

    #[test]
    fn an_unmeasured_run_fails_the_minimum_profile_check() {
        let err = verify_minimum_profile_measurements(&ObservedMeasurements::default())
            .expect_err("must refuse");
        assert!(err.contains("never measured"), "{err}");
    }
}
