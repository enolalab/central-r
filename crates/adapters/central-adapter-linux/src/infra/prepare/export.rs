//! `ReleaseExportService` — the port of upstream `release_export_linux.go`:
//! assembles a release tree from one completed build operation (the
//! op-artifact bundle plus a `docker save` of the lock-pinned infra image),
//! self-checks it through the import path, and only then copies it out.
//!
//! The export proves its own output imports: it stages the assembled tree
//! under caps and runs the full [`verify_release`]; a failure there is an
//! assembly bug or a mutated op directory, never a releasable tree.
//!
//! The DIR rule — absent, or an empty directory, and nothing else — is
//! enforced before the prepare runs (no twenty-minute build for an unusable
//! DIR) and re-checked at copy-out (TOCTOU). Nothing is ever merged or
//! repaired.

use std::fs;
use std::io::Read as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use central_foundation::failure::Failure;
use central_infra::domain::{
    ComparisonFact, INFRA_IMAGE_REPOSITORY, REQUIRED_ATTESTATION_PREDICATES, valid_operation_id,
};
use central_infra::prepare::{
    COMPARISON_FILE_NAME, INFRA_TAR_NAME, Lock, MAX_COMPARISON_BYTES, MAX_ENVELOPE_BYTES,
    MAX_MINIO_TAR_BYTES, MINIO_TAR_NAME, RELEASE_FILE_NAME, RELEASE_INFRA_MODES,
    RELEASE_SCHEMA_VERSION, ReleaseFile, envelope_file_name, prepare_codes,
    release_trust_materials,
};

use super::OpDeadline;
use super::attestation::AttestationVerifier;
use super::image_load::DockerImageLoader;
use super::release::verify_release;
use super::release_stage::stage_release_dir;

/// `releaseExportTag` — the transient tag the export saves the infra image
/// under. A digest-saved tarball carries no RepoTags, and the import
/// contract requires the tarball to name a tag to resolve — so the export
/// tags by digest reference first, saves by tag, and untags best-effort. The
/// name is namespaced to this operation; a leftover resolves to our own pin.
pub fn release_export_tag() -> String {
    format!("{INFRA_IMAGE_REPOSITORY}:central-release-export")
}

fn export_failed(detail: impl std::fmt::Display) -> Failure {
    Failure::invalid(
        prepare_codes::RELEASE_EXPORT_FAILED,
        format!("dependencyprepare: release export failed: {detail}"),
    )
}

fn dir_unusable(detail: impl std::fmt::Display) -> Failure {
    Failure::invalid(
        prepare_codes::RELEASE_EXPORT_DIR_UNUSABLE,
        format!("dependencyprepare: release export dir unusable: {detail}"),
    )
}

/// `readBounded`.
fn read_bounded(path: &Path, max_bytes: u64) -> std::io::Result<Vec<u8>> {
    let mut raw = Vec::new();
    fs::File::open(path)?
        .take(max_bytes + 1)
        .read_to_end(&mut raw)?;
    if raw.len() as u64 > max_bytes {
        return Err(std::io::Error::other("file exceeds its cap"));
    }
    Ok(raw)
}

/// `ReleaseExportService`.
pub struct ReleaseExportService {
    lock: Lock,
    verifier: AttestationVerifier,
    docker: DockerImageLoader,
    build_dir: PathBuf,
}

impl ReleaseExportService {
    /// `NewReleaseExportService`.
    #[must_use]
    pub fn new(
        lock: Lock,
        verifier: AttestationVerifier,
        docker: DockerImageLoader,
        build_dir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            lock,
            verifier,
            docker,
            build_dir: build_dir.into(),
        }
    }

    /// `CheckExportDir` — the DIR rule.
    ///
    /// # Errors
    /// `RELEASE_EXPORT_DIR_UNUSABLE` for an empty, relative, oversized,
    /// non-directory or non-empty target.
    pub fn check_export_dir(&self, dir: &Path) -> Result<(), Failure> {
        let text = dir.as_os_str();
        if text.is_empty() {
            return Err(dir_unusable("export dir is required"));
        }
        if !dir.is_absolute() {
            return Err(dir_unusable("export dir must be absolute"));
        }
        if text.len() > 4096 {
            return Err(dir_unusable("export dir exceeds 4096 bytes"));
        }
        let meta = match fs::symlink_metadata(dir) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(dir_unusable(format!("stat export dir: {e}"))),
        };
        if !meta.is_dir() {
            return Err(dir_unusable("export dir is not a directory"));
        }
        let mut entries =
            fs::read_dir(dir).map_err(|e| dir_unusable(format!("list export dir: {e}")))?;
        if entries.next().is_some() {
            return Err(dir_unusable("export dir is not empty"));
        }
        Ok(())
    }

    /// `ExportRelease` — assemble, self-check, and publish a release from
    /// one completed build operation.
    ///
    /// # Errors
    /// `RELEASE_EXPORT_FAILED` for any missing, malformed or unverifiable
    /// input or output; `RELEASE_EXPORT_DIR_UNUSABLE` for a bad target.
    #[allow(clippy::too_many_lines)]
    pub fn export_release(
        &self,
        deadline: OpDeadline,
        operation_id: &str,
        dir: &Path,
    ) -> Result<(), Failure> {
        if self.build_dir.as_os_str().is_empty() || !self.docker_is_configured() {
            return Err(export_failed("release exporter is not configured"));
        }
        valid_operation_id(operation_id).map_err(|e| export_failed(e.message()))?;
        self.check_export_dir(dir)?;
        let trust = release_trust_materials(&self.lock).map_err(|e| export_failed(e.message()))?;
        let op_dir = self.build_dir.join(operation_id);

        let mut envelopes = Vec::new();
        for predicate in REQUIRED_ATTESTATION_PREDICATES {
            let raw = read_bounded(
                &op_dir
                    .join("attestations")
                    .join(format!("{predicate}.json")),
                MAX_ENVELOPE_BYTES,
            )
            .map_err(|_| export_failed(format!("operation attestation {predicate} is missing")))?;
            if raw.is_empty() {
                return Err(export_failed(format!(
                    "operation attestation {predicate} is empty"
                )));
            }
            envelopes.push((predicate, raw));
        }
        let comparison_raw = read_bounded(&op_dir.join("comparison.json"), MAX_COMPARISON_BYTES)
            .map_err(|_| export_failed("operation comparison is missing"))?;
        let comparison: ComparisonFact = serde_json::from_slice(&comparison_raw)
            .map_err(|e| export_failed(format!("operation comparison is invalid: {e}")))?;
        comparison.validate().map_err(|e| {
            export_failed(format!("operation comparison is invalid: {}", e.message()))
        })?;
        let export_raw = read_bounded(&op_dir.join("build-one-export.txt"), 4096)
            .map_err(|_| export_failed("operation names no build-one export"))?;
        let export_text = String::from_utf8_lossy(&export_raw).trim().to_owned();
        let export_path = PathBuf::from(&export_text);
        let export_ok = !export_text.is_empty()
            && export_path.is_absolute()
            && fs::metadata(&export_path)
                .is_ok_and(|m| m.is_file() && m.len() > 0 && m.len() <= MAX_MINIO_TAR_BYTES);
        if !export_ok {
            return Err(export_failed("build-one export is missing or over cap"));
        }

        let manifest = self.infra_export_pin()?;
        let reference = format!("{INFRA_IMAGE_REPOSITORY}@{manifest}");
        let tag = release_export_tag();
        let output = self
            .docker
            .run_args(
                deadline,
                &["image", "inspect", "--format", "{{.Id}}", &reference],
            )
            .map_err(|_| export_failed("the lock-pinned infra image is not present locally"))?;
        // {{.Id}} is the MANIFEST digest on the containerd image store this
        // feature requires (the minio loader's validate_loaded_image pins the
        // same rule): comparing it to the config digest fails every live
        // export.
        if String::from_utf8_lossy(&output).trim() != manifest {
            return Err(export_failed(
                "the local infra image is not the lock-pinned one",
            ));
        }
        if let Ok(tag_out) = self
            .docker
            .run_args(deadline, &["image", "inspect", "--format", "{{.Id}}", &tag])
            && String::from_utf8_lossy(&tag_out).trim() != manifest
        {
            return Err(export_failed("the export tag is occupied by another image"));
        }

        let staging =
            self.build_dir
                .join(format!("export-{}-{}", std::process::id(), unique_suffix()));
        mkdir(&staging, 0o700).map_err(|e| export_failed(format!("stage export: {e}")))?;
        let result = (|| {
            mkdir(&staging.join("minio"), 0o700)
                .and_then(|()| mkdir(&staging.join("infra"), 0o700))
                .map_err(|e| export_failed(format!("stage export: {e}")))?;
            let release_file = serde_json::to_vec(&ReleaseFile {
                schema_version: RELEASE_SCHEMA_VERSION.to_owned(),
                lock_digest: trust.lock_digest.clone(),
            })
            .map_err(|e| export_failed(format!("encode release file: {e}")))?;
            write_file(
                &staging.join(RELEASE_FILE_NAME),
                &[release_file.as_slice(), b"\n"].concat(),
                0o600,
            )
            .map_err(|e| export_failed(format!("stage export: {e}")))?;
            copy_file(
                &export_path,
                &staging.join("minio").join(MINIO_TAR_NAME),
                0o600,
            )
            .map_err(|e| export_failed(format!("stage minio tarball: {e}")))?;
            write_file(
                &staging.join("minio").join(COMPARISON_FILE_NAME),
                &comparison_raw,
                0o600,
            )
            .map_err(|e| export_failed(format!("stage export: {e}")))?;
            for (predicate, raw) in &envelopes {
                // NOTE the rename: op artifacts use "<predicate>.json" (the
                // attestor), the release uses "attestation-<predicate>.json"
                // (the layout).
                write_file(
                    &staging.join("minio").join(envelope_file_name(*predicate)),
                    raw,
                    0o600,
                )
                .map_err(|e| export_failed(format!("stage export: {e}")))?;
            }
            self.docker
                .run_args(deadline, &["tag", &reference, &tag])
                .map_err(|_| export_failed("tag the infra image for save"))?;
            let saved = self.docker.run_args(
                deadline,
                &[
                    "save",
                    "-o",
                    &staging.join("infra").join(INFRA_TAR_NAME).to_string_lossy(),
                    &tag,
                ],
            );
            // Best-effort untag: teardown must not mask the save outcome.
            let _ = self.docker.run_args(deadline, &["rmi", &tag]);
            saved.map_err(|_| export_failed("save the infra image"))?;
            // The export proves its own output imports.
            let paths = stage_release_dir(deadline, &staging, &self.build_dir).map_err(|e| {
                export_failed(format!("export self-check staging: {}", e.message()))
            })?;
            let verified = verify_release(deadline, &paths, &self.lock, &self.verifier);
            let _ = fs::remove_dir_all(&paths.root);
            verified.map_err(|e| {
                export_failed(format!("export self-check verification: {}", e.message()))
            })?;
            self.check_export_dir(dir)?;
            copy_release_out(&staging, dir).map_err(export_failed)
        })();
        let _ = fs::remove_dir_all(&staging);
        result
    }

    fn docker_is_configured(&self) -> bool {
        self.docker.is_configured()
    }

    /// `infraExportPin` — the infra image's manifest digest every
    /// `RELEASE_INFRA_MODES` lock mode must pin (same set, same full-set
    /// strictness as the import side).
    fn infra_export_pin(&self) -> Result<String, Failure> {
        let mut pin: Option<(String, String)> = None;
        let mut found = 0;
        for locked in &self.lock.modes {
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
                    return Err(export_failed("infra modes pin different images"));
                }
                Some(_) => {}
            }
        }
        match pin {
            Some((manifest, config))
                if found == RELEASE_INFRA_MODES.len()
                    && !manifest.is_empty()
                    && !config.is_empty() =>
            {
                Ok(manifest)
            }
            _ => Err(export_failed("lock names no complete infra pin")),
        }
    }
}

fn unique_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default()
}

fn mkdir(path: &Path, mode: u32) -> std::io::Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(mode)
        .create(path)
}

fn write_file(path: &Path, data: &[u8], mode: u32) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)?;
    f.write_all(data)
}

/// Streaming copy: the tarball may be up to `MAX_MINIO_TAR_BYTES`.
fn copy_file(src: &Path, dst: &Path, mode: u32) -> std::io::Result<()> {
    let mut input = fs::File::open(src)?;
    let mut out = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(dst)?;
    if let Err(e) = std::io::copy(&mut input, &mut out) {
        let _ = fs::remove_file(dst);
        return Err(e);
    }
    Ok(())
}

/// `copyReleaseOut` — publishes the self-checked staging tree. Dirs land
/// 0755, files `create_new` 0644 (explicit chmods: creation modes are
/// umask-filtered and the release layout pins exact modes). A non-regular
/// staging entry is impossible by construction and refused closed rather
/// than followed.
fn copy_release_out(staging: &Path, dir: &Path) -> Result<(), String> {
    let chmod = |p: &Path, mode: u32| {
        fs::set_permissions(p, fs::Permissions::from_mode(mode))
            .map_err(|e| format!("create export dir: {e}"))
    };
    mkdir(dir, 0o755).map_err(|e| format!("create export dir: {e}"))?;
    chmod(dir, 0o755)?;
    fn walk(
        from: &Path,
        to: &Path,
        chmod: &dyn Fn(&Path, u32) -> Result<(), String>,
    ) -> Result<(), String> {
        let mut entries: Vec<_> = fs::read_dir(from)
            .map_err(|e| format!("list staged export: {e}"))?
            .collect::<Result<_, _>>()
            .map_err(|e| format!("list staged export: {e}"))?;
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            let dst = to.join(entry.file_name());
            let kind = entry
                .file_type()
                .map_err(|e| format!("list staged export: {e}"))?;
            if kind.is_dir() {
                mkdir(&dst, 0o755).map_err(|e| format!("create export dir: {e}"))?;
                chmod(&dst, 0o755)?;
                walk(&entry.path(), &dst, chmod)?;
            } else if kind.is_file() {
                if let Err(e) = copy_file(&entry.path(), &dst, 0o644) {
                    return Err(format!("copy export file: {e}"));
                }
                if let Err(e) = chmod(&dst, 0o644) {
                    let _ = fs::remove_file(&dst);
                    return Err(e);
                }
            } else {
                return Err("staged export holds a non-regular entry".to_owned());
            }
        }
        Ok(())
    }
    walk(staging, dir, &chmod)
}

#[cfg(test)]
mod tests {
    use super::super::image_load::DockerExec;
    use super::super::release_fixture::{Release, release, tmp};
    use super::*;
    use std::sync::{Arc, Mutex};

    struct Env {
        release: Release,
        build: PathBuf,
        out: PathBuf,
        calls: Arc<Mutex<Vec<String>>>,
        svc: ReleaseExportService,
    }

    impl Drop for Env {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.build);
        }
    }

    fn env(tag: &str, local_image: Option<String>) -> Env {
        let release = release(tag);
        let build = tmp("export-build");
        let op = build.join("prepare-1");
        fs::create_dir_all(op.join("attestations")).expect("attestations");
        for p in REQUIRED_ATTESTATION_PREDICATES {
            fs::copy(
                release.dir.join("minio").join(envelope_file_name(p)),
                op.join("attestations").join(format!("{p}.json")),
            )
            .expect("envelope");
        }
        fs::copy(
            release.dir.join("minio").join(COMPARISON_FILE_NAME),
            op.join("comparison.json"),
        )
        .expect("comparison");
        let export = release.dir.join("minio").join(MINIO_TAR_NAME);
        fs::write(
            op.join("build-one-export.txt"),
            format!("{}\n", export.display()),
        )
        .expect("export path");
        let calls: Arc<Mutex<Vec<String>>> = Arc::default();
        let log = Arc::clone(&calls);
        let infra_tar = release.dir.join("infra").join(INFRA_TAR_NAME);
        let answer = local_image.unwrap_or_else(|| release.infra_manifest.clone());
        let exec: DockerExec = Box::new(move |_, args, _, _| {
            log.lock().expect("log").push(args.join(" "));
            match args[0].as_str() {
                "image"
                    if args
                        .last()
                        .is_some_and(|a| a.contains("central-release-export")) =>
                {
                    Err("no such image".to_owned())
                }
                "image" => Ok(format!("{answer}\n").into_bytes()),
                "save" => {
                    fs::copy(&infra_tar, &args[2]).map_err(|e| e.to_string())?;
                    Ok(Vec::new())
                }
                _ => Ok(Vec::new()),
            }
        });
        let out = tmp("export-out").join("release");
        let svc = ReleaseExportService::new(
            release.lock.clone(),
            release.verifier.clone(),
            DockerImageLoader::new("/usr/bin/docker").with_exec(exec),
            &build,
        );
        Env {
            release,
            build,
            out,
            calls,
            svc,
        }
    }

    #[test]
    fn export_assembles_self_checks_and_publishes_a_verifiable_release() {
        let e = env("exp-ok", None);
        e.svc
            .export_release(OpDeadline::NONE, "prepare-1", &e.out)
            .expect("export");
        for name in [
            "release.json",
            "minio/image.tar",
            "minio/comparison.json",
            "infra/image.tar",
        ] {
            let meta = fs::metadata(e.out.join(name)).expect(name);
            assert_eq!(meta.permissions().mode() & 0o777, 0o644, "{name}");
        }
        for p in REQUIRED_ATTESTATION_PREDICATES {
            assert!(e.out.join("minio").join(envelope_file_name(p)).is_file());
        }
        assert_eq!(
            fs::metadata(&e.out).expect("dir").permissions().mode() & 0o777,
            0o755
        );
        // The published tree imports again.
        let work = tmp("export-reimport");
        let paths = stage_release_dir(OpDeadline::NONE, &e.out, &work).expect("stage");
        verify_release(
            OpDeadline::NONE,
            &paths,
            &e.release.lock,
            &e.release.verifier,
        )
        .expect("re-verify");
        let calls = e.calls.lock().expect("calls").join("\n");
        let tag_at = calls.find("tag ").expect("tag");
        let rmi_at = calls.find("rmi ").expect("untag");
        assert!(
            tag_at < calls.find("save ").expect("save") && calls.find("save ").unwrap() < rmi_at
        );
        // No staging directory is left behind.
        assert!(!fs::read_dir(&e.build).expect("build").any(|d| {
            d.expect("entry")
                .file_name()
                .to_string_lossy()
                .starts_with("export-")
        }));
        let _ = fs::remove_dir_all(work);
    }

    #[test]
    fn the_export_dir_rule_is_absent_or_empty_and_nothing_else() {
        let e = env("exp-dir", None);
        let check = |p: &Path| e.svc.check_export_dir(p);
        assert!(check(Path::new("")).is_err());
        assert!(check(Path::new("relative/dir")).is_err());
        assert!(check(Path::new(&format!("/{}", "a".repeat(4100)))).is_err());
        assert!(check(&e.out).is_ok(), "absent passes");
        fs::create_dir_all(&e.out).expect("mkdir");
        assert!(check(&e.out).is_ok(), "empty dir passes");
        fs::write(e.out.join("x"), b"x").expect("write");
        assert_eq!(
            check(&e.out).expect_err("non-empty").code(),
            prepare_codes::RELEASE_EXPORT_DIR_UNUSABLE
        );
        let file = e.out.join("x");
        assert!(check(&file).is_err(), "a file is not a directory");
        let err = e
            .svc
            .export_release(OpDeadline::NONE, "prepare-1", &e.out)
            .expect_err("refused before any docker call");
        assert_eq!(err.code(), prepare_codes::RELEASE_EXPORT_DIR_UNUSABLE);
        assert!(e.calls.lock().expect("calls").is_empty());
    }

    #[test]
    fn missing_or_tampered_operation_inputs_fail_export_by_name() {
        let e = env("exp-bad", None);
        assert!(
            e.svc
                .export_release(OpDeadline::NONE, "../x", &e.out)
                .is_err()
        );
        assert!(
            e.svc
                .export_release(OpDeadline::NONE, "unknown-op", &e.out)
                .is_err()
        );
        let op = e.build.join("prepare-1");
        fs::write(
            op.join("comparison.json"),
            br#"{"comparator":"","equal":false}"#,
        )
        .expect("bad cmp");
        let err = e
            .svc
            .export_release(OpDeadline::NONE, "prepare-1", &e.out)
            .expect_err("invalid comparison");
        assert_eq!(err.code(), prepare_codes::RELEASE_EXPORT_FAILED);
        assert!(!e.out.exists(), "nothing published on failure");
        fs::write(op.join("build-one-export.txt"), b"relative/path\n").expect("bad export");
        assert!(
            e.svc
                .export_release(OpDeadline::NONE, "prepare-1", &e.out)
                .is_err()
        );
    }

    #[test]
    fn a_local_infra_image_that_is_not_the_pinned_one_is_refused() {
        let e = env("exp-pin", Some(format!("sha256:{}", "9".repeat(64))));
        let err = e
            .svc
            .export_release(OpDeadline::NONE, "prepare-1", &e.out)
            .expect_err("wrong local image");
        assert!(
            err.message().contains("not the lock-pinned one"),
            "{}",
            err.message()
        );
        assert!(!e.out.exists());
        assert!(
            !e.calls
                .lock()
                .expect("calls")
                .iter()
                .any(|c| c.starts_with("save "))
        );
    }

    #[test]
    fn a_tampered_attestation_fails_the_self_check_and_publishes_nothing() {
        let e = env("exp-tamper", None);
        let path = e.build.join("prepare-1/attestations/sbom.json");
        let mut raw = fs::read(&path).expect("read");
        raw.truncate(raw.len() - 8);
        fs::write(&path, raw).expect("tamper");
        let err = e
            .svc
            .export_release(OpDeadline::NONE, "prepare-1", &e.out)
            .expect_err("self-check");
        assert!(err.message().contains("self-check"), "{}", err.message());
        assert!(!e.out.exists());
        let _ = e.release.signer.key_id();
    }
}
