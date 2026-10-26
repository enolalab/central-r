//! `release_stage_linux.go` — the release-tree staging path. A release
//! directory is operator-owned input, so it is staged before it is
//! trusted: the fixed tree is enumerated against a closed allowlist,
//! each entry is copied beneath a root-owned staging dir inside its
//! byte cap, and only then do the inventory readers touch the staged
//! copies. The operator's directory is read through a kernel-confined
//! root ([`ReleaseRoot`], `openat2` beneath the dir) so a symlink the
//! operator planted cannot re-point a staged copy somewhere it was
//! never checked.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use central_foundation::failure::Failure;
use central_infra::domain::OciInventory;
use central_infra::prepare::{self, ReleasePaths, envelope_file_name, prepare_codes};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use super::buildkit::inventory_from_oci_layout;
use super::{OpDeadline, ReleaseRoot, hex_lower, lexically_contained, mkdir_all};

/// `ReleasePaths`'s fixed entry set: every entry known, every entry
/// bounded. `want` maps each staged relative name to its cap.
fn release_want() -> BTreeMap<String, u64> {
    let mut want = BTreeMap::from([
        (
            prepare::RELEASE_FILE_NAME.to_owned(),
            prepare::MAX_RELEASE_FILE_BYTES,
        ),
        (
            format!("minio/{}", prepare::MINIO_TAR_NAME),
            prepare::MAX_MINIO_TAR_BYTES,
        ),
        (
            format!("minio/{}", prepare::COMPARISON_FILE_NAME),
            prepare::MAX_COMPARISON_BYTES,
        ),
        (
            format!("infra/{}", prepare::INFRA_TAR_NAME),
            prepare::MAX_INFRA_TAR_BYTES,
        ),
    ]);
    for predicate in central_infra::domain::REQUIRED_ATTESTATION_PREDICATES {
        want.insert(
            format!("minio/{}", envelope_file_name(predicate)),
            prepare::MAX_ENVELOPE_BYTES,
        );
    }
    want
}

/// `StageReleaseDir` — copy the fixed release tree out of the
/// operator-owned `dir` into a fresh staging dir under `workdir`.
/// Every later step reads the staged copies, never the operator DIR.
///
/// # Errors
/// `RELEASE_UNREADABLE` when the dir cannot be opened/staged or a file
/// exceeds its cap; `RELEASE_INVALID` for a non-regular, unknown, or
/// missing entry; `cancelled` when the budget elapsed.
pub fn stage_release_dir(
    deadline: OpDeadline,
    dir: &Path,
    workdir: &Path,
) -> Result<ReleasePaths, Failure> {
    if dir.as_os_str().is_empty() || !dir.is_absolute() {
        return Err(Failure::invalid(
            prepare_codes::RELEASE_UNREADABLE,
            "dependencyprepare: release unreadable: release dir must be absolute",
        ));
    }
    let root = ReleaseRoot::new(dir).map_err(|_| {
        Failure::invalid(
            prepare_codes::RELEASE_UNREADABLE,
            "dependencyprepare: release unreadable: open release dir".to_owned(),
        )
    })?;
    let staged = {
        // `os.MkdirTemp(workdir, "release-")` — a fresh, uniquely named
        // staging dir created mode 0700 atomically; `fs::create_dir`
        // would inherit the umask and a post-create chmod would leave
        // a looser-mode window.
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            let candidate = workdir.join(format!("release-{}-{}", std::process::id(), attempt));
            match fs::DirBuilder::new().mode(0o700).create(&candidate) {
                Ok(()) => break candidate,
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists && attempt < 64 => {
                    continue;
                }
                Err(e) => {
                    return Err(Failure::invalid(
                        prepare_codes::RELEASE_UNREADABLE,
                        format!("dependencyprepare: release unreadable: stage dir: {e}"),
                    ));
                }
            }
        }
    };
    let mut staged_guard = ReleaseStageGuard {
        path: staged.clone(),
        armed: true,
    };
    let want = release_want();
    let result = (|| {
        refuse_unknown_release_entries(&root)?;

        let mut out = ReleasePaths {
            root: staged.display().to_string(),
            envelopes: BTreeMap::new(),
            ..ReleasePaths::default()
        };
        for (name, max) in &want {
            deadline.check()?;
            let n = stage_one_file(&root, name, &staged.join(name), *max)?;
            #[allow(clippy::cast_possible_wrap)]
            {
                out.staged_bytes += n as i64;
            }
        }
        out.release_file = staged
            .join(prepare::RELEASE_FILE_NAME)
            .display()
            .to_string();
        out.minio_tar = staged
            .join("minio")
            .join(prepare::MINIO_TAR_NAME)
            .display()
            .to_string();
        out.comparison_file = staged
            .join("minio")
            .join(prepare::COMPARISON_FILE_NAME)
            .display()
            .to_string();
        out.infra_tar = staged
            .join("infra")
            .join(prepare::INFRA_TAR_NAME)
            .display()
            .to_string();
        for predicate in central_infra::domain::REQUIRED_ATTESTATION_PREDICATES {
            out.envelopes.insert(
                predicate,
                staged
                    .join("minio")
                    .join(envelope_file_name(predicate))
                    .display()
                    .to_string(),
            );
        }
        Ok(out)
    })();
    match result {
        Ok(out) => {
            // Disarm: the staged tree is the answer now.
            staged_guard.armed = false;
            Ok(out)
        }
        Err(e) => Err(e),
    }
}

/// `os.RemoveAll(staged)` on every failure path — the guard drops the
/// half-staged tree unless [`ReleaseStageGuard::armed`] was cleared.
struct ReleaseStageGuard {
    path: PathBuf,
    armed: bool,
}

impl Drop for ReleaseStageGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

/// `refuseUnknownReleaseEntries` — the release tree must contain
/// exactly the known entries: anything unknown, or anything
/// known-but-missing, refuses the whole tree rather than staging a
/// partial or surprising copy.
fn refuse_unknown_release_entries(root: &ReleaseRoot) -> Result<(), Failure> {
    let top: BTreeMap<String, bool> = BTreeMap::from([
        (prepare::RELEASE_FILE_NAME.to_owned(), true),
        ("minio".to_owned(), true),
        ("infra".to_owned(), true),
    ]);
    check_release_dir_entries(root, ".", &top)?;
    let mut minio: BTreeMap<String, bool> = BTreeMap::from([
        (prepare::MINIO_TAR_NAME.to_owned(), true),
        (prepare::COMPARISON_FILE_NAME.to_owned(), true),
    ]);
    for predicate in central_infra::domain::REQUIRED_ATTESTATION_PREDICATES {
        minio.insert(envelope_file_name(predicate), true);
    }
    check_release_dir_entries(root, "minio", &minio)?;
    let infra: BTreeMap<String, bool> =
        BTreeMap::from([(prepare::INFRA_TAR_NAME.to_owned(), true)]);
    check_release_dir_entries(root, "infra", &infra)?;
    Ok(())
}

/// `checkReleaseDirEntries` — `dir` must contain exactly `want`:
/// every entry present must be named by the allowlist and every
/// allowlisted name must be present.
fn check_release_dir_entries(
    root: &ReleaseRoot,
    dir: &str,
    want: &BTreeMap<String, bool>,
) -> Result<(), Failure> {
    let entries = root.read_dir(dir).map_err(|e| {
        Failure::invalid(
            prepare_codes::RELEASE_INVALID,
            format!(
                "dependencyprepare: release invalid: list {dir}: {}",
                e.message()
            ),
        )
    })?;
    let mut seen: BTreeMap<String, bool> = BTreeMap::new();
    for entry in &entries {
        seen.insert(entry.clone(), true);
        if !want.contains_key(entry) {
            let joined = if dir == "." {
                entry.clone()
            } else {
                format!("{dir}/{entry}")
            };
            return Err(Failure::invalid(
                prepare_codes::RELEASE_INVALID,
                format!("dependencyprepare: release invalid: unknown release entry {joined:?}"),
            ));
        }
    }
    for name in want.keys() {
        if !seen.contains_key(name) {
            let joined = if dir == "." {
                name.clone()
            } else {
                format!("{dir}/{name}")
            };
            return Err(Failure::invalid(
                prepare_codes::RELEASE_INVALID,
                format!("dependencyprepare: release invalid: missing release entry {joined:?}"),
            ));
        }
    }
    Ok(())
}

/// `stageOneFile` — copy one operator file to its staged path. The
/// source must be a regular file within its cap; the copy is created
/// `O_EXCL` 0600 and its size re-checked after the copy, so a file
/// that grows mid-copy is refused rather than staged over cap.
/// Returns the staged byte count.
fn stage_one_file(
    root: &ReleaseRoot,
    name: &str,
    dst: &Path,
    max_bytes: u64,
) -> Result<u64, Failure> {
    let info = root.lstat(name).map_err(|_| {
        Failure::invalid(
            prepare_codes::RELEASE_INVALID,
            format!("dependencyprepare: release invalid: lstat {name}"),
        )
    })?;
    // `info.Mode().IsRegular()` — rustix `st_mode` file-type bits.
    if info.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(Failure::invalid(
            prepare_codes::RELEASE_INVALID,
            format!("dependencyprepare: release invalid: {name} is not a regular file"),
        ));
    }
    #[allow(clippy::cast_sign_loss)]
    let size = info.st_size as u64;
    if size > max_bytes {
        return Err(Failure::invalid(
            prepare_codes::RELEASE_UNREADABLE,
            format!("dependencyprepare: release unreadable: {name} exceeds {max_bytes} bytes"),
        ));
    }
    if let Some(parent) = dst.parent() {
        mkdir_all(parent, 0o700).map_err(|e| {
            Failure::invalid(
                prepare_codes::RELEASE_UNREADABLE,
                format!("dependencyprepare: release unreadable: stage {name}: {e}"),
            )
        })?;
    }
    let src = root.open(name).map_err(|_| {
        Failure::invalid(
            prepare_codes::RELEASE_UNREADABLE,
            format!("dependencyprepare: release unreadable: open {name}"),
        )
    })?;
    let mut out = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(dst)
        .map_err(|e| {
            Failure::invalid(
                prepare_codes::RELEASE_UNREADABLE,
                format!("dependencyprepare: release unreadable: create staged {name}: {e}"),
            )
        })?;
    // `io.CopyN(out, src, maxBytes+1)` — the cap plus one byte is what
    // detects mid-copy growth.
    let mut limited = src.take(max_bytes + 1);
    let copied = io::copy(&mut limited, &mut out).map_err(|e| {
        let _ = fs::remove_file(dst);
        Failure::invalid(
            prepare_codes::RELEASE_UNREADABLE,
            format!("dependencyprepare: release unreadable: copy {name}: {e}"),
        )
    })?;
    out.flush().map_err(|e| {
        let _ = fs::remove_file(dst);
        Failure::invalid(
            prepare_codes::RELEASE_UNREADABLE,
            format!("dependencyprepare: release unreadable: write staged {name}: {e}"),
        )
    })?;
    if copied > max_bytes {
        let _ = fs::remove_file(dst);
        return Err(Failure::invalid(
            prepare_codes::RELEASE_UNREADABLE,
            format!("dependencyprepare: release unreadable: {name} exceeds {max_bytes} bytes"),
        ));
    }
    Ok(copied)
}

/// `extractReleaseTar` — extract a plain tarball into `dest_dir`:
/// regular files and directories only (no symlinks, hardlinks, or
/// special members), every member contained under `dest_dir`, at most
/// [`prepare::MAX_RELEASE_TAR_MEMBERS`] members and `max_bytes`
/// cumulative content bytes.
///
/// # Errors
/// `RELEASE_UNREADABLE` for I/O failures; `RELEASE_INVALID` for every
/// member that violates the closed policy.
pub fn extract_release_tar(
    deadline: OpDeadline,
    tar_path: &Path,
    dest_dir: &Path,
    max_bytes: u64,
) -> Result<(), Failure> {
    let file = fs::File::open(tar_path).map_err(|_| {
        Failure::invalid(
            prepare_codes::RELEASE_UNREADABLE,
            format!(
                "dependencyprepare: release unreadable: open {}",
                tar_path.display()
            ),
        )
    })?;
    mkdir_all(dest_dir, 0o700).map_err(|e| {
        Failure::invalid(
            prepare_codes::RELEASE_UNREADABLE,
            format!("dependencyprepare: release unreadable: extract dir: {e}"),
        )
    })?;
    let mut archive = tar::Archive::new(file);
    let mut members: u64 = 0;
    let mut written: u64 = 0;
    let entries = archive.entries().map_err(|_| {
        Failure::invalid(
            prepare_codes::RELEASE_UNREADABLE,
            format!(
                "dependencyprepare: release unreadable: read {}",
                tar_path.display()
            ),
        )
    })?;
    for entry in entries {
        deadline.check()?;
        let mut entry = entry.map_err(|_| {
            Failure::invalid(
                prepare_codes::RELEASE_UNREADABLE,
                format!(
                    "dependencyprepare: release unreadable: read {}",
                    tar_path.display()
                ),
            )
        })?;
        members += 1;
        if members > prepare::MAX_RELEASE_TAR_MEMBERS {
            return Err(Failure::invalid(
                prepare_codes::RELEASE_INVALID,
                format!(
                    "dependencyprepare: release invalid: {} has more than {} members",
                    tar_path.display(),
                    prepare::MAX_RELEASE_TAR_MEMBERS
                ),
            ));
        }
        let raw_name = String::from_utf8_lossy(&entry.path_bytes()).into_owned();
        let name = clean_posix(&raw_name);
        // Any `..` component is refused outright — `path.Clean`
        // collapsing it does not make the archive's traversal claim
        // disappear — alongside the cleaned absolute/empty refusals.
        let traversal = raw_name.split('/').any(|c| c == "..");
        if raw_name.is_empty() || name == "." || Path::new(&raw_name).is_absolute() || traversal {
            return Err(Failure::invalid(
                prepare_codes::RELEASE_INVALID,
                format!(
                    "dependencyprepare: release invalid: {} member {raw_name:?} escapes the extraction dir",
                    tar_path.display()
                ),
            ));
        }
        let target = dest_dir.join(&name);
        if !lexically_contained(dest_dir, &target) {
            return Err(Failure::invalid(
                prepare_codes::RELEASE_INVALID,
                format!(
                    "dependencyprepare: release invalid: {} member {raw_name:?} escapes the extraction dir",
                    tar_path.display()
                ),
            ));
        }
        match entry.header().entry_type() {
            tar::EntryType::Directory => {
                mkdir_all(&target, 0o700).map_err(|e| {
                    Failure::invalid(
                        prepare_codes::RELEASE_UNREADABLE,
                        format!("dependencyprepare: release unreadable: create {name}: {e}"),
                    )
                })?;
            }
            // `tar.TypeReg` ('0') and `tar.TypeRegA` ('\0') — the
            // release tars are produced by the export side on this
            // host, which writes both; upstream accepts both here.
            tar::EntryType::Regular => {
                if let Some(parent) = target.parent() {
                    mkdir_all(parent, 0o700).map_err(|e| {
                        Failure::invalid(
                            prepare_codes::RELEASE_UNREADABLE,
                            format!("dependencyprepare: release unreadable: create {name}: {e}"),
                        )
                    })?;
                }
                let mut out = match fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(0o600)
                    .open(&target)
                {
                    Ok(out) => out,
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                        return Err(Failure::invalid(
                            prepare_codes::RELEASE_INVALID,
                            format!(
                                "dependencyprepare: release invalid: {} member {name:?} appears twice",
                                tar_path.display()
                            ),
                        ));
                    }
                    Err(e) => {
                        return Err(Failure::invalid(
                            prepare_codes::RELEASE_UNREADABLE,
                            format!("dependencyprepare: release unreadable: create {name}: {e}"),
                        ));
                    }
                };
                let mut limited = (&mut entry).take(max_bytes - written + 1);
                let copied = io::copy(&mut limited, &mut out).map_err(|e| {
                    Failure::invalid(
                        prepare_codes::RELEASE_UNREADABLE,
                        format!("dependencyprepare: release unreadable: write {name}: {e}"),
                    )
                })?;
                written += copied;
                if written > max_bytes {
                    return Err(Failure::invalid(
                        prepare_codes::RELEASE_UNREADABLE,
                        format!(
                            "dependencyprepare: release unreadable: {} exceeds {max_bytes} bytes",
                            tar_path.display()
                        ),
                    ));
                }
            }
            other => {
                return Err(Failure::invalid(
                    prepare_codes::RELEASE_INVALID,
                    format!(
                        "dependencyprepare: release invalid: {} member {name:?} has unsupported type {other:?}",
                        tar_path.display()
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// `path.Clean` for a slash-separated member name (duplicate of
/// `fetch`'s private helper — kept local because the two policies
/// differ in what they do with the result).
fn clean_posix(name: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for part in name.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if out.last() == Some(&"..") || out.is_empty() {
                    out.push("..");
                } else {
                    out.pop();
                }
            }
            p => out.push(p),
        }
    }
    let joined = out.join("/");
    if joined.is_empty() {
        ".".to_owned()
    } else {
        joined
    }
}

/// `ReadReleaseMinioInventory` — extract the staged MinIO OCI tarball
/// into a scratch dir and read back its inventory with the same
/// single-manifest rule the build path uses.
///
/// # Errors
/// `RELEASE_UNREADABLE`/`RELEASE_INVALID` on staging or layout
/// failures.
pub fn read_release_minio_inventory(
    tar_path: &Path,
    tmpdir: &Path,
) -> Result<OciInventory, Failure> {
    let dir = scratch_dir(tmpdir, "minio-inv-")?;
    let result = (|| {
        extract_release_tar(
            OpDeadline::NONE,
            tar_path,
            &dir,
            prepare::MAX_MINIO_TAR_BYTES,
        )?;
        inventory_from_oci_layout(&dir).map_err(|e| {
            Failure::invalid(
                prepare_codes::RELEASE_INVALID,
                format!(
                    "dependencyprepare: release invalid: minio image.tar: {}",
                    e.message()
                ),
            )
        })
    })();
    let _ = fs::remove_dir_all(&dir);
    result
}

/// `ReadInfraSaveConfig` — the sha256 digest of the single manifest
/// entry's config blob bytes.
pub fn read_infra_save_config(tar_path: &Path, tmpdir: &Path) -> Result<String, Failure> {
    let (config, _) = read_infra_save_manifest(tar_path, tmpdir)?;
    Ok(config)
}

/// `ReadInfraSaveManifest` — extract the staged infra docker-save
/// tarball, require exactly one manifest entry, and return the sha256
/// digest of that entry's config blob bytes plus the entry's repo
/// tags.
pub fn read_infra_save_manifest(
    tar_path: &Path,
    tmpdir: &Path,
) -> Result<(String, Vec<String>), Failure> {
    let dir = scratch_dir(tmpdir, "infra-save-")?;
    let result = (|| {
        extract_release_tar(
            OpDeadline::NONE,
            tar_path,
            &dir,
            prepare::MAX_INFRA_TAR_BYTES,
        )?;
        let raw = fs::read(dir.join("manifest.json")).map_err(|_| {
            Failure::invalid(
                prepare_codes::RELEASE_INVALID,
                "dependencyprepare: release invalid: infra image.tar manifest.json",
            )
        })?;
        let entries: Vec<InfraSaveEntry> = serde_json::from_slice(&raw).map_err(|_| {
            Failure::invalid(
                prepare_codes::RELEASE_INVALID,
                "dependencyprepare: release invalid: infra image.tar manifest.json",
            )
        })?;
        if entries.len() != 1 || entries[0].config.is_empty() {
            return Err(Failure::invalid(
                prepare_codes::RELEASE_INVALID,
                "dependencyprepare: release invalid: infra image.tar must hold exactly one image",
            ));
        }
        let cfg_name = clean_posix(&entries[0].config);
        if cfg_name == "." || Path::new(&entries[0].config).is_absolute() {
            return Err(Failure::invalid(
                prepare_codes::RELEASE_INVALID,
                format!(
                    "dependencyprepare: release invalid: infra config {:?} escapes",
                    entries[0].config
                ),
            ));
        }
        // `containedPath(dir, cfgName)` — the containment question is
        // asked of the *normalized join*: Go's `filepath.Join` cleans
        // its result so `..` resolves against `dir`, while `Path::join`
        // keeps it verbatim and `starts_with` compares components
        // verbatim — `dir/../x` "starts with" `dir`, which would make
        // this a dead gate (the kernel read would then escape, just
        // reported under the wrong refusal class).
        let cfg_path = dir.join(&cfg_name);
        if !lexically_contained(&dir, &cfg_path) {
            return Err(Failure::invalid(
                prepare_codes::RELEASE_INVALID,
                format!(
                    "dependencyprepare: release invalid: infra config {:?} escapes",
                    entries[0].config
                ),
            ));
        }
        let cfg_bytes = fs::read(&cfg_path).map_err(|_| {
            Failure::invalid(
                prepare_codes::RELEASE_INVALID,
                format!(
                    "dependencyprepare: release invalid: infra config {:?}",
                    entries[0].config
                ),
            )
        })?;
        Ok((
            format!("sha256:{}", hex_lower(&Sha256::digest(&cfg_bytes))),
            entries[0].repo_tags.clone(),
        ))
    })();
    let _ = fs::remove_dir_all(&dir);
    result
}

/// `manifest.json`'s one docker-save entry.
#[derive(Debug, Deserialize)]
struct InfraSaveEntry {
    #[serde(rename = "Config")]
    config: String,
    #[serde(rename = "RepoTags", default)]
    repo_tags: Vec<String>,
    #[serde(rename = "Layers", default)]
    #[allow(dead_code)]
    layers: Vec<String>,
}

/// `os.MkdirTemp(tmpdir, prefix)` — a fresh scratch dir, created mode
/// 0700 atomically (`fs::create_dir` would inherit the umask).
fn scratch_dir(tmpdir: &Path, prefix: &str) -> Result<PathBuf, Failure> {
    for attempt in 0u32..64 {
        let candidate = tmpdir.join(format!("{prefix}{}-{}", std::process::id(), attempt));
        match fs::DirBuilder::new().mode(0o700).create(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(Failure::invalid(
                    prepare_codes::RELEASE_UNREADABLE,
                    format!("dependencyprepare: release unreadable: temp dir: {e}"),
                ));
            }
        }
    }
    Err(Failure::invalid(
        prepare_codes::RELEASE_UNREADABLE,
        "dependencyprepare: release unreadable: temp dir: exhausted",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use central_infra::domain::REQUIRED_ATTESTATION_PREDICATES;
    use std::collections::BTreeMap as Map;

    fn tempdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "central-release-test-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&dir).expect("tempdir");
        dir
    }

    /// `testDigestHex`.
    fn digest_hex(data: &[u8]) -> String {
        hex_lower(&Sha256::digest(data))
    }

    /// `writeTar` — a plain tarball from name → body pairs (sorted for
    /// determinism like upstream's).
    fn write_tar(tar_path: &Path, files: &Map<String, Vec<u8>>) {
        let file = fs::File::create(tar_path).expect("tar");
        let mut builder = tar::Builder::new(file);
        for (name, body) in files {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(body.len() as u64);
            header.set_mode(0o600);
            header.set_cksum();
            builder
                .append_data(&mut header, name, body.as_slice())
                .expect("member");
        }
        builder.finish().expect("finish");
    }

    /// `raw_named_header` — a regular-file header whose member name is
    /// written straight into the header block: the tests deliberately
    /// craft names (`..`, absolute) that `append_data`'s own path
    /// policy would refuse — the point is the *reader's* policy.
    fn raw_named_header(name: &str, size: u64) -> tar::Header {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(size);
        header.set_mode(0o600);
        {
            let gnu = header.as_gnu_mut().expect("gnu header");
            let bytes = name.as_bytes();
            assert!(bytes.len() < gnu.name.len(), "test name too long");
            gnu.name[..bytes.len()].copy_from_slice(bytes);
        }
        header.set_cksum();
        header
    }

    /// `writeMinioTar` — `<dir>/minio/image.tar`: a real minimal OCI
    /// layout tarball whose config blob carries `config_marker`.
    fn write_minio_tar(dir: &Path, config_marker: &str) -> PathBuf {
        let config =
            format!(r#"{{"architecture":"amd64","os":"linux","marker":{config_marker:?}}}"#)
                .into_bytes();
        let config_hex = digest_hex(&config);
        let layer = format!("layer-{config_marker}").into_bytes();
        let layer_hex = digest_hex(&layer);
        let manifest = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:{config_hex}","size":{}}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"sha256:{layer_hex}","size":{}}}]}}"#,
            config.len(),
            layer.len()
        )
        .into_bytes();
        let manifest_hex = digest_hex(&manifest);
        let index = format!(
            r#"{{"schemaVersion":2,"manifests":[{{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:{manifest_hex}","size":{}}}]}}"#,
            manifest.len()
        )
        .into_bytes();
        let tar_path = dir.join("minio").join("image.tar");
        fs::create_dir_all(dir.join("minio")).expect("minio dir");
        write_tar(
            &tar_path,
            &Map::from([
                ("index.json".to_owned(), index),
                (
                    "oci-layout".to_owned(),
                    br#"{"imageLayoutVersion":"1.0.0"}"#.to_vec(),
                ),
                (format!("blobs/sha256/{manifest_hex}"), manifest),
                (format!("blobs/sha256/{config_hex}"), config),
                (format!("blobs/sha256/{layer_hex}"), layer),
            ]),
        );
        tar_path
    }

    /// `writeInfraTar` — `<dir>/infra/image.tar`: a docker-save-shaped
    /// tarball with exactly one manifest entry.
    fn write_infra_tar(dir: &Path, config_marker: &str) -> PathBuf {
        let config =
            format!(r#"{{"architecture":"amd64","os":"linux","marker":{config_marker:?}}}"#)
                .into_bytes();
        let config_name = format!("{}.json", digest_hex(&config));
        let layer_hex = digest_hex(format!("layer-{config_marker}").as_bytes());
        let manifest = format!(
            r#"[{{"Config":{config_name:?},"RepoTags":["test:latest"],"Layers":[{lay:?}]}}]"#,
            lay = format!("{layer_hex}/layer.tar")
        )
        .into_bytes();
        let tar_path = dir.join("infra").join("image.tar");
        fs::create_dir_all(dir.join("infra")).expect("infra dir");
        write_tar(
            &tar_path,
            &Map::from([
                ("manifest.json".to_owned(), manifest),
                (config_name, config),
                (
                    format!("{layer_hex}/layer.tar"),
                    format!("fake-infra-layer-{config_marker}").into_bytes(),
                ),
            ]),
        );
        tar_path
    }

    /// `writeTestRelease` — a VALID release tree under `dir`.
    fn write_test_release(dir: &Path) {
        let digest = format!("sha256:{}", "b".repeat(64));
        let release_json =
            format!(r#"{{"schema_version":"central.release/v1","lock_digest":"{digest}"}}"#) + "\n";
        fs::write(dir.join("release.json"), release_json).expect("release.json");
        write_minio_tar(dir, "minio-config");
        let minio_dir = dir.join("minio");
        for predicate in REQUIRED_ATTESTATION_PREDICATES {
            fs::write(
                minio_dir.join(prepare::envelope_file_name(predicate)),
                b"{}",
            )
            .expect("envelope");
        }
        fs::write(minio_dir.join("comparison.json"), b"{}").expect("comparison");
        write_infra_tar(dir, "infra-config");
    }

    /// `TestStageReleaseDirCopiesUnderCaps` — every known entry lands
    /// under its cap, envelopes populate, and the staged root is not
    /// the operator's dir.
    #[test]
    fn stage_release_dir_copies_under_caps() {
        let src = tempdir("release-src");
        write_test_release(&src);
        let work = tempdir("release-work");
        let paths = stage_release_dir(OpDeadline::NONE, &src, &work).expect("stage");
        assert!(Path::new(&paths.minio_tar).is_file());
        assert_eq!(paths.envelopes.len(), 3);
        assert_ne!(paths.root, src.display().to_string());
        fs::remove_dir_all(&src).ok();
        fs::remove_dir_all(&work).ok();
    }

    /// `TestStageReleaseDirRefusesUnknownEntries` — top-level AND
    /// nested unknowns refuse.
    #[test]
    fn stage_release_dir_refuses_unknown_entries() {
        let src = tempdir("unknown-src");
        write_test_release(&src);
        let work = tempdir("unknown-work");
        fs::write(src.join("evil.sh"), b"x").expect("evil");
        let err = stage_release_dir(OpDeadline::NONE, &src, &work).unwrap_err();
        assert_eq!(err.code(), prepare_codes::RELEASE_INVALID);
        fs::remove_file(src.join("evil.sh")).expect("clean");
        fs::write(src.join("minio").join("extra.json"), b"{}").expect("extra");
        let err = stage_release_dir(OpDeadline::NONE, &src, &work).unwrap_err();
        assert_eq!(err.code(), prepare_codes::RELEASE_INVALID);
        fs::remove_dir_all(&src).ok();
        fs::remove_dir_all(&work).ok();
    }

    /// `TestStageReleaseDirEnforcesCaps` — an over-cap envelope is
    /// refused, not truncated.
    #[test]
    fn stage_release_dir_enforces_caps() {
        let src = tempdir("caps-src");
        write_test_release(&src);
        let work = tempdir("caps-work");
        fs::write(
            src.join("minio").join("attestation-sbom.json"),
            vec![0u8; (2 << 20) as usize],
        )
        .expect("big envelope");
        let err = stage_release_dir(OpDeadline::NONE, &src, &work).unwrap_err();
        assert_eq!(err.code(), prepare_codes::RELEASE_UNREADABLE);
        fs::remove_dir_all(&src).ok();
        fs::remove_dir_all(&work).ok();
    }

    /// `TestStageReleaseDirRefusesMissing` — a missing dir and a
    /// missing member both refuse.
    #[test]
    fn stage_release_dir_refuses_missing() {
        let work = tempdir("missing-work");
        let err = stage_release_dir(
            OpDeadline::NONE,
            &tempdir("missing-src").join("nope"),
            &work,
        )
        .unwrap_err();
        assert_eq!(err.code(), prepare_codes::RELEASE_UNREADABLE);
        let src = tempdir("missing-src2");
        write_test_release(&src);
        fs::remove_file(src.join("infra").join("image.tar")).expect("remove");
        let err = stage_release_dir(OpDeadline::NONE, &src, &work).unwrap_err();
        assert_eq!(err.code(), prepare_codes::RELEASE_INVALID);
        // A relative dir refuses before the open is attempted.
        let err =
            stage_release_dir(OpDeadline::NONE, Path::new("relative/dir"), &work).unwrap_err();
        assert_eq!(err.code(), prepare_codes::RELEASE_UNREADABLE);
        fs::remove_dir_all(&src).ok();
        fs::remove_dir_all(&work).ok();
    }

    /// `TestReadReleaseMinioInventory` — the staged MinIO tarball
    /// reads back a complete inventory.
    #[test]
    fn read_release_minio_inventory_works() {
        let src = tempdir("inv-src");
        write_test_release(&src);
        let tmp = tempdir("inv-tmp");
        let inv = read_release_minio_inventory(&src.join("minio").join("image.tar"), &tmp)
            .expect("inventory");
        assert!(
            !inv.index_digest.is_empty()
                && !inv.manifest_digest.is_empty()
                && !inv.config_digest.is_empty()
        );
        fs::remove_dir_all(&src).ok();
        fs::remove_dir_all(&tmp).ok();
    }

    /// `TestReadInfraSaveConfig` — the config digest is a sha256.
    #[test]
    fn read_infra_save_config_works() {
        let src = tempdir("infra-src");
        write_test_release(&src);
        let tmp = tempdir("infra-tmp");
        let digest = read_infra_save_config(&src.join("infra").join("image.tar"), &tmp)
            .expect("save config");
        assert!(digest.starts_with("sha256:"));
        // The manifest variant also returns tags.
        let (config, tags) =
            read_infra_save_manifest(&src.join("infra").join("image.tar"), &tmp).expect("manifest");
        assert_eq!(config, digest);
        assert_eq!(tags, ["test:latest"]);
        fs::remove_dir_all(&src).ok();
        fs::remove_dir_all(&tmp).ok();
    }

    /// A manifest `Config` of `../escape` is refused by the lexical
    /// containment check itself — the joined path is normalized before
    /// the component-prefix compare, so `scratch/../escape` cannot
    /// pass even when the escape target exists and is readable
    /// (upstream `filepath.Join` cleans; Rust's `Path::join` does
    /// not, which is what made the verbatim `starts_with` a dead
    /// gate).
    #[test]
    fn infra_save_manifest_refuses_traversal_config_lexically() {
        let dir = tempdir("cfgtrav");
        let tmp = tempdir("cfgtrav-tmp");
        // The escape target exists: without the normalized-join check
        // the verbatim prefix compare would pass and this file's
        // bytes would be digested as the config rather than refused.
        fs::write(tmp.join("escape"), b"escaped-bytes").expect("escape file");
        let tar_path = dir.join("infra.tar");
        write_tar(
            &tar_path,
            &Map::from([(
                "manifest.json".to_owned(),
                br#"[{"Config":"../escape","RepoTags":["test:latest"],"Layers":[]}]"#.to_vec(),
            )]),
        );
        let err = read_infra_save_manifest(&tar_path, &tmp).unwrap_err();
        assert_eq!(err.code(), prepare_codes::RELEASE_INVALID);
        fs::remove_dir_all(&dir).ok();
        fs::remove_dir_all(&tmp).ok();
    }

    /// `TestExtractReleaseTarRefusesSymlinks` — a link member is
    /// refused, never silently dropped.
    #[test]
    fn extract_release_tar_refuses_symlinks() {
        let dir = tempdir("evil");
        let tar_path = dir.join("evil.tar");
        {
            let file = fs::File::create(&tar_path).expect("tar");
            let mut builder = tar::Builder::new(file);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_link_name("/etc/passwd").expect("link");
            header.set_cksum();
            builder
                .append_data(&mut header, "x", io::empty())
                .expect("member");
            builder.finish().expect("finish");
        }
        let err = extract_release_tar(OpDeadline::NONE, &tar_path, &dir.join("out"), 1 << 20)
            .unwrap_err();
        assert_eq!(err.code(), prepare_codes::RELEASE_INVALID);
        fs::remove_dir_all(&dir).ok();
    }

    /// `extractReleaseTar` — the traversal/absolute/dup/member-cap
    /// refusals upstream's switch covers.
    #[test]
    fn extract_release_tar_policy() {
        let dir = tempdir("policy");
        // Traversal member.
        let traversal = dir.join("traversal.tar");
        {
            let file = fs::File::create(&traversal).expect("tar");
            let mut builder = tar::Builder::new(file);
            builder
                .append(&raw_named_header("../escaped", 1), b"x".as_slice())
                .expect("member");
            builder.finish().expect("finish");
        }
        let err = extract_release_tar(OpDeadline::NONE, &traversal, &dir.join("out1"), 1 << 20)
            .unwrap_err();
        assert_eq!(err.code(), prepare_codes::RELEASE_INVALID);

        // Absolute member.
        let abs = dir.join("abs.tar");
        {
            let file = fs::File::create(&abs).expect("tar");
            let mut builder = tar::Builder::new(file);
            builder
                .append(&raw_named_header("/etc/abs", 1), b"x".as_slice())
                .expect("member");
            builder.finish().expect("finish");
        }
        let err =
            extract_release_tar(OpDeadline::NONE, &abs, &dir.join("out2"), 1 << 20).unwrap_err();
        assert_eq!(err.code(), prepare_codes::RELEASE_INVALID);

        // Duplicate member.
        let dup = dir.join("dup.tar");
        write_tar(&dup, &Map::from([("same".to_owned(), b"a".to_vec())]));
        // Rebuild with the same name twice.
        {
            let file = fs::File::create(&dup).expect("tar");
            let mut builder = tar::Builder::new(file);
            for _ in 0..2 {
                let mut header = tar::Header::new_gnu();
                header.set_entry_type(tar::EntryType::Regular);
                header.set_size(1);
                header.set_mode(0o600);
                header.set_cksum();
                builder
                    .append_data(&mut header, "same", b"a".as_slice())
                    .expect("member");
            }
            builder.finish().expect("finish");
        }
        let err =
            extract_release_tar(OpDeadline::NONE, &dup, &dir.join("out3"), 1 << 20).unwrap_err();
        assert_eq!(err.code(), prepare_codes::RELEASE_INVALID);

        // Byte cap.
        let big = dir.join("big.tar");
        write_tar(&big, &Map::from([("blob".to_owned(), vec![b'x'; 2048])]));
        let err = extract_release_tar(OpDeadline::NONE, &big, &dir.join("out4"), 1024).unwrap_err();
        assert_eq!(err.code(), prepare_codes::RELEASE_UNREADABLE);

        // Member-count cap.
        let many = dir.join("many.tar");
        {
            let file = fs::File::create(&many).expect("tar");
            let mut builder = tar::Builder::new(file);
            for i in 0..(prepare::MAX_RELEASE_TAR_MEMBERS + 1) {
                let mut header = tar::Header::new_gnu();
                header.set_entry_type(tar::EntryType::Regular);
                header.set_size(0);
                header.set_mode(0o600);
                header.set_cksum();
                builder
                    .append_data(&mut header, format!("f{i}"), io::empty())
                    .expect("member");
            }
            builder.finish().expect("finish");
        }
        let err =
            extract_release_tar(OpDeadline::NONE, &many, &dir.join("out5"), 1 << 40).unwrap_err();
        assert_eq!(err.code(), prepare_codes::RELEASE_INVALID);
        fs::remove_dir_all(&dir).ok();
    }
}
