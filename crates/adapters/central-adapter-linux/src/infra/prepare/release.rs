//! Release verification and import — the port of upstream
//! `release_verify_linux.go` and `release_import_linux.go`.
//!
//! A release is a directory an operator hands over: `release.json`, the
//! MinIO image tarball, three attestation envelopes, the recorded
//! comparison, and the infra image tarball. Nothing in it is trusted until
//! it has been staged under root-owned caps (`release_stage`) and verified
//! here in the spec's fixed order: `release.json` lock check, MinIO
//! subject, the three envelopes, comparison drift, infra pin. Only staged
//! copies are read, never the operator's directory.
//!
//! Trust comes from the importer's embedded lock, never from the release's
//! own claims; producer-local materials (builder identities, invocation,
//! operation id) are overlaid from the envelope into the expectation, the
//! trust-relevant ones (lock digest, source archive, commit, bases) are
//! compared against the lock first so a release built under another lock is
//! reported as a lock mismatch rather than an untrusted envelope.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::Path;

use central_foundation::failure::Failure;
use central_infra::domain::{
    ComparisonFact, REQUIRED_ATTESTATION_PREDICATES, ServiceMode, inventory_digest,
    validate_attestation_facts,
};
use central_infra::prepare::{
    AttestationExpectation, AttestationMaterials, Lock, MAX_COMPARISON_BYTES, MAX_ENVELOPE_BYTES,
    MAX_RELEASE_FILE_BYTES, PreparedManifest, RELEASE_INFRA_MODES, ReleaseEvidence, ReleasePaths,
    parse_release_file, prepare_codes, release_trust_materials, subject_from_inventory,
    validate_manifest_source,
};

use super::OpDeadline;
use super::attestation::{AttestationVerifier, parse_unverified_statement};
use super::image_load::{DockerImageLoader, ImageLoader};
use super::release_stage::{
    read_infra_save_config, read_release_minio_inventory, stage_release_dir,
};

fn release_failure(code: &'static str, kind: &str, detail: impl std::fmt::Display) -> Failure {
    Failure::invalid(code, format!("dependencyprepare: release {kind}: {detail}"))
}

fn invalid(detail: impl std::fmt::Display) -> Failure {
    release_failure(prepare_codes::RELEASE_INVALID, "invalid", detail)
}

fn untrusted(detail: impl std::fmt::Display) -> Failure {
    release_failure(prepare_codes::RELEASE_UNTRUSTED, "untrusted", detail)
}

/// `readBounded` — one staged file, refused past `max_bytes`.
fn read_bounded(path: &str, max_bytes: u64) -> Result<Vec<u8>, String> {
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    file.take(max_bytes + 1)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    if raw.len() as u64 > max_bytes {
        return Err(format!("file exceeds {max_bytes} bytes"));
    }
    Ok(raw)
}

/// `trustMaterialsEqual` — whether the envelope's trust-relevant materials
/// match the importer's lock. Producer-local fields are overlaid into the
/// expectation, never compared here.
fn trust_materials_equal(trust: &AttestationMaterials, got: &AttestationMaterials) -> bool {
    trust.base_identities == got.base_identities
        && trust.lock_digest == got.lock_digest
        && trust.source_archive_digest == got.source_archive_digest
        && trust.source_commit == got.source_commit
}

fn overlay_producer_fields(
    trust: &AttestationMaterials,
    statement: &AttestationMaterials,
) -> AttestationMaterials {
    let mut materials = trust.clone();
    materials
        .builder_identity_a
        .clone_from(&statement.builder_identity_a);
    materials
        .builder_identity_b
        .clone_from(&statement.builder_identity_b);
    materials
        .invocation_digest
        .clone_from(&statement.invocation_digest);
    materials.operation_id.clone_from(&statement.operation_id);
    materials
}

/// `readReleaseComparison` — the staged comparison must name the verified
/// inventory: a comparison that drifted from the MinIO tarball is invalid,
/// not merely untrusted.
fn read_release_comparison(
    path: &str,
    inventory: &central_infra::domain::OciInventory,
) -> Result<ComparisonFact, Failure> {
    let raw = read_bounded(path, MAX_COMPARISON_BYTES)
        .map_err(|e| invalid(format!("comparison: {e}")))?;
    let comparison: ComparisonFact =
        serde_json::from_slice(&raw).map_err(|e| invalid(format!("comparison: {e}")))?;
    comparison
        .validate()
        .map_err(|e| invalid(format!("comparison: {}", e.message())))?;
    if comparison.index_digest != inventory.index_digest
        || comparison.inventory_digest != inventory_digest(inventory)
    {
        return Err(invalid(
            "comparison drifts from the verified minio inventory",
        ));
    }
    Ok(comparison)
}

/// `checkInfraPin` — the staged infra tarball's config must equal the pin
/// every `RELEASE_INFRA_MODES` lock mode carries, and the lock must carry
/// the full set: a lock that lost a pin is not checked against the rest.
fn check_infra_pin(tar_path: &Path, lock: &Lock) -> Result<(), Failure> {
    let scratch = tar_path.parent().unwrap_or_else(|| Path::new("."));
    let config = read_infra_save_config(tar_path, scratch)?;
    let mut found = 0;
    for locked in &lock.modes {
        if !RELEASE_INFRA_MODES.contains(&locked.mode) {
            continue;
        }
        found += 1;
        if locked.inventory.config_digest != config {
            return Err(untrusted(format!(
                "infra tarball config {config} != lock pin {} for mode {}",
                locked.inventory.config_digest, locked.mode
            )));
        }
    }
    if found != RELEASE_INFRA_MODES.len() {
        return Err(untrusted(format!(
            "lock carries {found} of {} infra pins",
            RELEASE_INFRA_MODES.len()
        )));
    }
    Ok(())
}

/// `VerifyRelease` — verifies staged paths in the spec's fixed order.
///
/// # Errors
/// `RELEASE_INVALID`, `RELEASE_UNTRUSTED` or `RELEASE_LOCK_MISMATCH`,
/// or a cancellation when the budget elapsed.
pub fn verify_release(
    deadline: OpDeadline,
    paths: &ReleasePaths,
    lock: &Lock,
    verifier: &AttestationVerifier,
) -> Result<ReleaseEvidence, Failure> {
    let trust = release_trust_materials(lock)?;
    let raw = read_bounded(&paths.release_file, MAX_RELEASE_FILE_BYTES)
        .map_err(|e| invalid(format!("release.json: {e}")))?;
    let release = parse_release_file(&raw)?;
    if release.lock_digest != trust.lock_digest {
        return Err(release_failure(
            prepare_codes::RELEASE_LOCK_MISMATCH,
            "lock mismatch",
            format!(
                "release claims {}, embedded lock is {}",
                release.lock_digest, trust.lock_digest
            ),
        ));
    }
    let minio_tar = Path::new(&paths.minio_tar);
    let inventory = read_release_minio_inventory(
        minio_tar,
        minio_tar.parent().unwrap_or_else(|| Path::new(".")),
    )
    .map_err(|e| invalid(format!("minio tarball: {}", e.message())))?;
    let subject = subject_from_inventory("minio", &inventory);
    let mut facts = Vec::new();
    let mut envelopes = BTreeMap::new();
    for predicate in REQUIRED_ATTESTATION_PREDICATES {
        deadline.check()?;
        let path = paths
            .envelopes
            .get(&predicate)
            .ok_or_else(|| invalid(format!("{predicate} envelope: not staged")))?;
        let raw = read_bounded(path, MAX_ENVELOPE_BYTES)
            .map_err(|e| invalid(format!("{predicate} envelope: {e}")))?;
        let statement = parse_unverified_statement(&raw)
            .map_err(|e| untrusted(format!("{predicate} envelope: {}", e.message())))?;
        // The release.json digest check binds the claimed lock, but the
        // canonical hash covers the lock's raw bytes: only this comparison
        // sees the trust fields themselves. An envelope that binds another
        // lock's source or bases is a lock mismatch, not an untrusted
        // envelope.
        if !trust_materials_equal(&trust, &statement.materials) {
            return Err(release_failure(
                prepare_codes::RELEASE_LOCK_MISMATCH,
                "lock mismatch",
                format!("{predicate} envelope binds a different lock"),
            ));
        }
        let fact = verifier
            .verify(
                &raw,
                &AttestationExpectation {
                    predicate,
                    subject: subject.clone(),
                    materials: overlay_producer_fields(&trust, &statement.materials),
                },
            )
            .map_err(|e| untrusted(format!("{predicate} envelope: {}", e.message())))?;
        facts.push(fact);
        envelopes.insert(predicate, raw);
    }
    validate_attestation_facts(&facts, &subject.index_digest)
        .map_err(|e| untrusted(e.message().to_owned()))?;
    let comparison = read_release_comparison(&paths.comparison_file, &inventory)?;
    check_infra_pin(Path::new(&paths.infra_tar), lock)?;
    Ok(ReleaseEvidence {
        facts,
        subject,
        inventory,
        comparison,
        minio_tar: paths.minio_tar.clone(),
        infra_tar: paths.infra_tar.clone(),
        envelopes,
        staged_bytes: paths.staged_bytes,
    })
}

/// `ReverifyManifestEnvelopes` — re-verifies a release manifest's persisted
/// envelopes against the embedded lock: the offline-audit entry point. Trust
/// comes from the lock, never from the manifest's own facts — the recorded
/// facts are the CLAIM under audit, the rebuilt fresh facts the verdict.
/// Build manifests (no envelopes) pass vacuously.
///
/// # Errors
/// `RELEASE_UNTRUSTED` or `RELEASE_INVALID` for any envelope that does not
/// re-verify to exactly its recorded fact.
pub fn reverify_manifest_envelopes(
    deadline: OpDeadline,
    manifest: &PreparedManifest,
    lock: &Lock,
    verifier: &AttestationVerifier,
) -> Result<(), Failure> {
    validate_manifest_source(manifest)?;
    if manifest.effective_source() != central_infra::domain::ManifestSource::Release {
        return Ok(());
    }
    let trust = release_trust_materials(lock)?;
    let inventory = manifest
        .dependency_set
        .modes
        .iter()
        .find(|m| m.mode == ServiceMode::Minio)
        .map(|m| m.inventory.clone())
        .ok_or_else(|| invalid("release manifest names no minio inventory"))?;
    let subject = subject_from_inventory("minio", &inventory);
    validate_attestation_facts(&manifest.attestations, &subject.index_digest)
        .map_err(|e| untrusted(format!("recorded facts: {}", e.message())))?;
    for predicate in REQUIRED_ATTESTATION_PREDICATES {
        deadline.check()?;
        let raw = manifest
            .envelopes
            .iter()
            .find(|e| e.predicate == predicate)
            .map(|e| &e.envelope)
            .ok_or_else(|| {
                untrusted(format!("predicate {predicate:?} has no persisted envelope"))
            })?;
        let want = manifest
            .attestations
            .iter()
            .find(|f| f.predicate == predicate)
            .ok_or_else(|| untrusted(format!("predicate {predicate:?} has no recorded fact")))?;
        let statement = parse_unverified_statement(raw)
            .map_err(|e| untrusted(format!("envelope {predicate:?}: {}", e.message())))?;
        let fresh = verifier
            .verify(
                raw,
                &AttestationExpectation {
                    predicate,
                    subject: subject.clone(),
                    materials: overlay_producer_fields(&trust, &statement.materials),
                },
            )
            .map_err(|e| untrusted(format!("envelope {predicate:?}: {}", e.message())))?;
        if &fresh != want {
            return Err(untrusted(format!(
                "envelope {predicate:?} fact does not match the recorded fact"
            )));
        }
    }
    Ok(())
}

/// `port.ReleaseImporter` — verifies a release directory and loads its
/// images: the import path's single seam. Stage/switch stay in the state
/// machine.
pub trait ReleaseImporter: Send + Sync {
    /// `ImportRelease`.
    ///
    /// # Errors
    /// Any staging, verification or load failure.
    fn import_release(
        &self,
        deadline: OpDeadline,
        dir: &Path,
        workdir: &Path,
    ) -> Result<ReleaseEvidence, Failure>;
}

/// `infraPinManifests` — the infra image's manifest and config digests all
/// four infra modes must pin. Both pins are needed: the tarball's config is
/// compared to the config pin, and the daemon's `{{.Id}}` answer (the
/// manifest on the containerd store) to the manifest pin.
///
/// # Errors
/// `RELEASE_INVALID` when the modes pin different images or the lock names
/// no complete pin.
pub fn infra_pin_manifests(lock: &Lock) -> Result<(String, String), Failure> {
    let mut pin: Option<(String, String)> = None;
    let mut found = 0;
    for locked in &lock.modes {
        if !RELEASE_INFRA_MODES.contains(&locked.mode) {
            continue;
        }
        found += 1;
        let here = (
            locked.inventory.manifest_digest.clone(),
            locked.inventory.config_digest.clone(),
        );
        match &pin {
            None => pin = Some(here),
            Some(first) if *first != here => {
                return Err(invalid("infra modes pin different images"));
            }
            Some(_) => {}
        }
    }
    match pin {
        Some((m, c)) if found == RELEASE_INFRA_MODES.len() && !m.is_empty() && !c.is_empty() => {
            Ok((m, c))
        }
        _ => Err(invalid("lock names no complete infra pin")),
    }
}

/// `ReleaseImportService` — verifies a release directory and loads its
/// images through the same loader the build path uses.
pub struct ReleaseImportService {
    lock: Lock,
    verifier: AttestationVerifier,
    loader: std::sync::Arc<dyn ImageLoader>,
    infra: Option<DockerImageLoader>,
}

impl ReleaseImportService {
    /// `NewReleaseImportService`.
    #[must_use]
    pub fn new(
        lock: Lock,
        verifier: AttestationVerifier,
        loader: std::sync::Arc<dyn ImageLoader>,
        infra: Option<DockerImageLoader>,
    ) -> Self {
        Self {
            lock,
            verifier,
            loader,
            infra,
        }
    }
}

impl ReleaseImporter for ReleaseImportService {
    fn import_release(
        &self,
        deadline: OpDeadline,
        dir: &Path,
        workdir: &Path,
    ) -> Result<ReleaseEvidence, Failure> {
        super::mkdir_all(workdir, 0o700).map_err(|e| {
            release_failure(
                prepare_codes::RELEASE_UNREADABLE,
                "unreadable",
                format!("stage root: {e}"),
            )
        })?;
        let paths = stage_release_dir(deadline, dir, workdir)?;
        let evidence = verify_release(deadline, &paths, &self.lock, &self.verifier)?;
        let load_req = central_infra::prepare::ImageLoadRequest {
            selector: "minio".to_owned(),
            export: evidence.minio_tar.clone(),
            proven: evidence.inventory.clone(),
        };
        load_req.validate().map_err(|e| {
            Failure::internal(
                "IMAGE_LOAD",
                format!("dependencyprepare: load minio: {}", e.message()),
            )
        })?;
        let loaded = self.loader.load(deadline, &load_req).map_err(|e| {
            Failure::internal(
                "IMAGE_LOAD",
                format!("dependencyprepare: load minio: {}", e.message()),
            )
        })?;
        central_infra::prepare::validate_loaded_image(&loaded, &evidence.inventory).map_err(
            |e| {
                Failure::invalid(
                    e.code(),
                    format!("dependencyprepare: minio unresolvable: {}", e.message()),
                )
            },
        )?;
        let (pin_manifest, pin_config) = infra_pin_manifests(&self.lock)?;
        // Fail at use, not at entry: a missing infra loader must not mask the
        // precise staging/verification errors above.
        let infra = self.infra.as_ref().ok_or_else(|| {
            Failure::internal(
                "IMAGE_LOAD",
                "dependencyprepare: load infra: no image loader",
            )
        })?;
        infra
            .load_infra_tarball(
                deadline,
                Path::new(&evidence.infra_tar),
                &pin_manifest,
                &pin_config,
            )
            .map_err(|e| {
                Failure::invalid(
                    e.code(),
                    format!("dependencyprepare: load infra: {}", e.message()),
                )
            })?;
        Ok(evidence)
    }
}

#[cfg(test)]
mod tests {
    use super::super::release_fixture::{release, signer, stage, tmp};
    use super::*;
    use crate::infra::prepare::image_load::DockerExec;
    use central_infra::prepare::{AttestationTrustPolicy, TrustedKey};
    use std::sync::Arc;

    #[test]
    fn a_release_signed_by_a_trusted_key_verifies_to_full_evidence() {
        let r = release("ok");
        let (paths, work) = stage(&r);
        let ev = verify_release(OpDeadline::NONE, &paths, &r.lock, &r.verifier).expect("verify");
        assert_eq!(ev.facts.len(), REQUIRED_ATTESTATION_PREDICATES.len());
        assert_eq!(ev.inventory, r.inventory);
        assert_eq!(ev.envelopes.len(), 3);
        assert_eq!(ev.subject.index_digest, r.inventory.index_digest);
        let _ = std::fs::remove_dir_all(work);
    }

    #[test]
    fn untrusted_keys_foreign_locks_drift_and_infra_pins_are_refused_by_name() {
        let r = release("neg");
        let (paths, work) = stage(&r);

        let stranger = AttestationVerifier::new(AttestationTrustPolicy {
            keys: vec![TrustedKey {
                key_id: "other".to_owned(),
                public_key: signer().public_key_hex(),
                expires_at: None,
                revoked: false,
            }],
        });
        let err =
            verify_release(OpDeadline::NONE, &paths, &r.lock, &stranger).expect_err("untrusted");
        assert_eq!(err.code(), prepare_codes::RELEASE_UNTRUSTED);

        std::fs::write(
            &paths.release_file,
            format!(
                r#"{{"schema_version":"central.release/v1","lock_digest":"sha256:{}"}}"#,
                "0".repeat(64)
            ),
        )
        .expect("rewrite");
        let err = verify_release(OpDeadline::NONE, &paths, &r.lock, &r.verifier).expect_err("lock");
        assert_eq!(err.code(), prepare_codes::RELEASE_LOCK_MISMATCH);

        let r2 = release("neg2");
        let (paths2, work2) = stage(&r2);
        std::fs::write(&paths2.comparison_file, br#"{"comparator":"x","equal":true,"index_digest":"sha256:z","inventory_digest":"sha256:z"}"#).expect("drift");
        let err =
            verify_release(OpDeadline::NONE, &paths2, &r2.lock, &r2.verifier).expect_err("drift");
        assert_eq!(err.code(), prepare_codes::RELEASE_INVALID);

        let r3 = release("neg3");
        let (paths3, work3) = stage(&r3);
        let mut other_pin = r3.lock.clone();
        for locked in &mut other_pin.modes {
            if RELEASE_INFRA_MODES.contains(&locked.mode) {
                locked.inventory.config_digest = format!("sha256:{}", "a".repeat(64));
            }
        }
        let err =
            verify_release(OpDeadline::NONE, &paths3, &other_pin, &r3.verifier).expect_err("pin");
        assert_eq!(err.code(), prepare_codes::RELEASE_UNTRUSTED);
        for w in [work, work2, work3] {
            let _ = std::fs::remove_dir_all(w);
        }
    }

    #[test]
    fn an_envelope_binding_another_lock_is_a_lock_mismatch() {
        let r = release("other-lock");
        let (paths, work) = stage(&r);
        let mut other = r.lock.clone();
        other.fetches.minio.commit = "f".repeat(40);
        let err =
            verify_release(OpDeadline::NONE, &paths, &other, &r.verifier).expect_err("commit");
        assert_eq!(err.code(), prepare_codes::RELEASE_LOCK_MISMATCH);
        let _ = std::fs::remove_dir_all(work);
    }

    #[test]
    fn infra_pins_must_be_one_complete_image() {
        let r = release("pins");
        let (m, c) = infra_pin_manifests(&r.lock).expect("pins");
        assert_eq!(m, r.infra_manifest);
        assert!(c.starts_with("sha256:"));
        let mut split = r.lock.clone();
        let first = split
            .modes
            .iter_mut()
            .find(|l| RELEASE_INFRA_MODES.contains(&l.mode))
            .expect("infra mode");
        first.inventory.manifest_digest = format!("sha256:{}", "c".repeat(64));
        assert_eq!(
            infra_pin_manifests(&split).expect_err("split").code(),
            prepare_codes::RELEASE_INVALID
        );
        let mut missing = r.lock.clone();
        missing
            .modes
            .retain(|l| !RELEASE_INFRA_MODES.contains(&l.mode));
        assert!(infra_pin_manifests(&missing).is_err());
    }

    #[test]
    fn import_loads_minio_then_the_pinned_infra_tarball() {
        let r = release("import");
        let calls: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
        let manifest = r.infra_manifest.clone();
        let minio_manifest = r.inventory.manifest_digest.clone();
        let make = |log: Arc<std::sync::Mutex<Vec<String>>>, answer: String| -> DockerExec {
            Box::new(move |_, args, _, _| {
                log.lock().expect("log").push(args.join(" "));
                match args[0].as_str() {
                    "image" => Ok(format!("{answer}\n").into_bytes()),
                    _ => Ok(Vec::new()),
                }
            })
        };
        let loader = DockerImageLoader::new("/usr/bin/docker")
            .with_exec(make(Arc::clone(&calls), minio_manifest));
        let infra = DockerImageLoader::new("/usr/bin/docker")
            .with_exec(make(Arc::clone(&calls), manifest.clone()));
        let svc = ReleaseImportService::new(
            r.lock.clone(),
            r.verifier.clone(),
            Arc::new(loader),
            Some(infra),
        );
        let work = tmp("import-work");
        let ev = svc
            .import_release(OpDeadline::NONE, &r.dir, &work)
            .expect("import");
        assert_eq!(ev.facts.len(), 3);
        let log = calls.lock().expect("log").clone();
        let minio_at = log
            .iter()
            .position(|c| c.starts_with("load -i") && c.contains("minio"))
            .expect("minio load");
        let infra_at = log
            .iter()
            .position(|c| c.starts_with("load -i") && c.contains("infra"))
            .expect("infra load");
        assert!(minio_at < infra_at, "{log:?}");

        let wrong = DockerImageLoader::new("/usr/bin/docker").with_exec(make(
            Arc::clone(&calls),
            format!("sha256:{}", "d".repeat(64)),
        ));
        let svc = ReleaseImportService::new(
            r.lock.clone(),
            r.verifier.clone(),
            Arc::new(DockerImageLoader::new("/usr/bin/docker").with_exec(make(
                Arc::clone(&calls),
                r.inventory.manifest_digest.clone(),
            ))),
            Some(wrong),
        );
        let err = svc
            .import_release(OpDeadline::NONE, &r.dir, &tmp("import-work2"))
            .expect_err("infra digest drift");
        assert_eq!(err.code(), prepare_codes::RELEASE_UNTRUSTED);

        let no_infra = ReleaseImportService::new(
            r.lock.clone(),
            r.verifier.clone(),
            Arc::new(DockerImageLoader::new("/usr/bin/docker").with_exec(make(
                Arc::clone(&calls),
                r.inventory.manifest_digest.clone(),
            ))),
            None,
        );
        assert!(
            no_infra
                .import_release(OpDeadline::NONE, &r.dir, &tmp("import-work3"))
                .expect_err("no infra loader")
                .message()
                .contains("no image loader")
        );
        let _ = std::fs::remove_dir_all(work);
    }

    #[test]
    fn reverify_audits_release_manifests_and_passes_build_manifests_vacuously() {
        use central_infra::domain::{
            ManifestSource, PreparedDependencySet, PreparedMode, StoredEnvelope,
        };
        let r = release("reverify");
        let (paths, work) = stage(&r);
        let ev = verify_release(OpDeadline::NONE, &paths, &r.lock, &r.verifier).expect("verify");
        let mut manifest = PreparedManifest {
            source: ManifestSource::Release,
            attestations: ev.facts.clone(),
            envelopes: REQUIRED_ATTESTATION_PREDICATES
                .iter()
                .map(|p| StoredEnvelope {
                    predicate: *p,
                    envelope: ev.envelopes[p].clone(),
                })
                .collect(),
            dependency_set: PreparedDependencySet {
                modes: vec![PreparedMode {
                    mode: ServiceMode::Minio,
                    inventory: ev.inventory.clone(),
                }],
            },
            ..PreparedManifest::default()
        };
        reverify_manifest_envelopes(OpDeadline::NONE, &manifest, &r.lock, &r.verifier)
            .expect("audit");
        manifest.attestations[0].envelope_digest = "sha256:forged".to_owned();
        assert_eq!(
            reverify_manifest_envelopes(OpDeadline::NONE, &manifest, &r.lock, &r.verifier)
                .expect_err("forged fact")
                .code(),
            prepare_codes::RELEASE_UNTRUSTED
        );
        let build = PreparedManifest::default();
        reverify_manifest_envelopes(OpDeadline::NONE, &build, &r.lock, &r.verifier)
            .expect("vacuous");
        let _ = std::fs::remove_dir_all(work);
    }
}
