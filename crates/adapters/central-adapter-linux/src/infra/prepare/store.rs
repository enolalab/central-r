//! `internal/adapter/dependencyprepare/store_linux.go` — the
//! root-owned protected candidate store: `Stage` writes an immutable
//! candidate (manifest + digest + local identities), `SwitchSelector`
//! is the sole prepared-state commit (re-inspection, quarantine on
//! drift, atomic `RENAME_NOREPLACE`-free same-directory rename of the
//! `active` file, settlement record written exactly once), and
//! `Active` resolves the selected receipt B03 consumes. `Recover` is
//! deferred to the prepare pipeline that calls it; genesis needs
//! only the three ported methods.

use std::io::Read as _;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use central_foundation::failure::Failure;
use central_infra::domain::{
    AdmissionBinding, Candidate, DependencyReceipt, codes, selector_token,
};
use central_infra::prepare::{PreparedManifest, PreparedReceiptRecord};
use rustix::fs::{Mode, OFlags};
use sha2::{Digest as _, Sha256};

use super::lock::LockAdapter;
use super::{OpDeadline, hex_lower};

const MANIFEST_FILE: &str = "manifest.json";
const MANIFEST_DIGEST_FILE: &str = "manifest.digest";
const DOCKER_IDENTITY_FILE: &str = "docker-identity";
const RECEIPT_FILE: &str = "receipt.json";
const ACTIVE_FILE: &str = "active";
const CANDIDATES_DIR: &str = "candidates";
const QUARANTINE_DIR: &str = "quarantine";

/// `maxStoreFileBytes`.
const MAX_STORE_FILE_BYTES: u64 = 4 << 20;

fn invalid_candidate(message: impl Into<String>) -> Failure {
    Failure::invalid(codes::CANDIDATE_INVALID, message.into())
}

fn invalid_binding(message: impl Into<String>) -> Failure {
    Failure::invalid(codes::ADMISSION_BINDING_INVALID, message.into())
}

fn manifest_integrity(message: impl Into<String>) -> Failure {
    // `dp.ErrManifestIntegrity` — a distinct kind so `inspectAll`
    // routes it to quarantine without matching on text.
    Failure::invalid("MANIFEST_INTEGRITY", message.into())
}

fn io_failure(step: impl Into<String>, e: impl std::fmt::Display) -> Failure {
    Failure::internal("dependencyprepare_store", format!("{}: {e}", step.into()))
}

/// `os.ErrNotExist` — the one errno callers branch on (`Active`'s
/// missing files, `EnsureVersionZeroReceipt`'s active probe). All
/// other kernel errors stay internal failures.
fn map_io(step: impl Into<String>, e: rustix::io::Errno) -> Failure {
    if e == rustix::io::Errno::NOENT {
        return Failure::not_found("dependencyprepare_store", format!("{}: {e}", step.into()));
    }
    io_failure(step, e)
}

fn valid_path_component(name: &str) -> Result<(), Failure> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\0') {
        return Err(Failure::invalid(
            "dependencyprepare_store",
            format!("{name:?} is not a single safe path component"),
        ));
    }
    Ok(())
}

fn sha256_hex(data: &[u8]) -> String {
    format!("sha256:{}", hex_lower(&Sha256::digest(data)))
}

/// `openStoreDir` — the directory path is trusted configuration;
/// everything opened beneath the descriptor runs the no-follow
/// discipline.
fn open_store_dir(path: &Path) -> Result<OwnedFd, Failure> {
    rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| {
        map_io(
            format!("dependencyprepare: open store dir {}", path.display()),
            e,
        )
    })
}

/// `createOnlyAt` — `O_WRONLY|O_CREAT|O_EXCL` `0600` through
/// `openat2`'s no-symlink resolve, written and synced before close.
fn create_only_at<Fd: AsFd>(dir: Fd, name: &str, data: &[u8]) -> Result<(), Failure> {
    valid_path_component(name)?;
    let fd = rustix::fs::openat2(
        &dir,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
        rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|e| io_failure(format!("dependencyprepare: create-only {name}"), e))?;
    let mut file = std::fs::File::from(fd);
    use std::io::Write as _;
    if let Err(e) = file.write_all(data) {
        let _ = rustix::fs::unlinkat(&dir, name, rustix::fs::AtFlags::empty());
        return Err(io_failure(format!("dependencyprepare: write {name}"), e));
    }
    if let Err(e) = file.sync_all() {
        let _ = rustix::fs::unlinkat(&dir, name, rustix::fs::AtFlags::empty());
        return Err(io_failure(format!("dependencyprepare: sync {name}"), e));
    }
    Ok(())
}

/// `readNoFollowAt` — no-follow open plus the regular-file `fstat`
/// gate, bounded at `maxStoreFileBytes`.
fn read_no_follow_at<Fd: AsFd>(dir: Fd, name: &str) -> Result<Vec<u8>, Failure> {
    valid_path_component(name)?;
    let fd = rustix::fs::openat2(
        &dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
        rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|e| map_io(format!("open {name}"), e))?;
    let stat = rustix::fs::fstat(&fd).map_err(|e| map_io(format!("fstat {name}"), e))?;
    if !rustix::fs::FileType::from_raw_mode(stat.st_mode).is_file() {
        return Err(invalid_candidate(format!(
            "dependencyprepare: {name} is not a regular file"
        )));
    }
    let file = std::fs::File::from(fd);
    let mut data = Vec::new();
    file.take(MAX_STORE_FILE_BYTES + 1)
        .read_to_end(&mut data)
        .map_err(|e| io_failure(format!("read {name}"), e))?;
    if data.len() as u64 > MAX_STORE_FILE_BYTES {
        return Err(invalid_candidate(format!(
            "dependencyprepare: {name} exceeds {MAX_STORE_FILE_BYTES} bytes"
        )));
    }
    Ok(data)
}

/// `publishCreateOnly` — written and synced under a temporary name in
/// `dir_path`, then `RENAME_NOREPLACE`d into `dir`; the directory is
/// synced after the rename.
fn publish_create_only<Fd: AsFd>(
    dir: Fd,
    dir_path: &Path,
    name: &str,
    data: &[u8],
) -> Result<(), Failure> {
    valid_path_component(name)?;
    // `os.CreateTemp(dirPath, "."+name+"-*.tmp")`.
    let mut tmp_path = PathBuf::new();
    let mut tmp_file = None;
    for attempt in 0..16u32 {
        let candidate = dir_path.join(format!(
            ".{name}-{:x}-{}.tmp",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
                + u128::from(attempt)
        ));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&candidate)
        {
            Ok(f) => {
                tmp_path = candidate;
                tmp_file = Some(f);
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(io_failure(
                    format!("dependencyprepare: create {name} temp"),
                    e,
                ));
            }
        }
    }
    let Some(mut tmp) = tmp_file else {
        return Err(io_failure(
            format!("dependencyprepare: create {name} temp"),
            "no free temporary name",
        ));
    };
    let cleanup = |tmp_path: &Path| {
        let _ = std::fs::remove_file(tmp_path);
    };
    use std::io::Write as _;
    if let Err(e) = tmp.write_all(data).and_then(|()| tmp.sync_all()) {
        drop(tmp);
        cleanup(&tmp_path);
        return Err(io_failure(format!("dependencyprepare: write {name}"), e));
    }
    drop(tmp);
    match rustix::fs::renameat_with(
        rustix::fs::CWD,
        &tmp_path,
        &dir,
        name,
        rustix::fs::RenameFlags::NOREPLACE,
    ) {
        Ok(()) => {}
        Err(rustix::io::Errno::EXIST) => {
            cleanup(&tmp_path);
            return Err(Failure::conflict(
                "dependencyprepare_store",
                format!("dependencyprepare: publish {name}: already exists"),
            ));
        }
        Err(e) => {
            cleanup(&tmp_path);
            return Err(io_failure(format!("dependencyprepare: publish {name}"), e));
        }
    }
    rustix::fs::fsync(&dir).map_err(|e| {
        io_failure(
            format!("dependencyprepare: sync directory after publishing {name}"),
            e,
        )
    })
}

/// `generateCandidateID` — `cand-<12 hex>` over selector + timestamp
/// + 16 bytes of CSPRNG nonce.
fn generate_candidate_id(selector: &str) -> Result<String, Failure> {
    let mut nonce = [0u8; 16];
    rustix::rand::getrandom(&mut nonce, rustix::rand::GetRandomFlags::empty())
        .map_err(|e| io_failure("dependencyprepare: candidate ID", e))?;
    let mut hasher = Sha256::new();
    hasher.update(selector.as_bytes());
    hasher.update(format!("{:?}", time::OffsetDateTime::now_utc()).as_bytes());
    hasher.update(nonce);
    let sum = hasher.finalize();
    Ok(format!("cand-{}", &hex_lower(&sum)[..12]))
}

/// `parseActiveSelector` — `id\nselector\ntimestamp?\n`.
fn parse_active_selector(data: &[u8]) -> Result<(String, String, String), Failure> {
    let text = String::from_utf8_lossy(data);
    let lines: Vec<&str> = text.split('\n').filter(|l| !l.is_empty()).collect();
    // Upstream splits on '\n' and keeps trailing-empty handling: the
    // file ends with a newline so a well-formed file is exactly the
    // id and selector lines plus the optional timestamp.
    if lines.len() < 2 {
        return Err(io_failure(
            "dependencyprepare: invalid active selector format",
            "fewer than two lines",
        ));
    }
    Ok((
        lines[0].to_owned(),
        lines[1].to_owned(),
        lines.get(2).map_or_else(String::new, |s| (*s).to_owned()),
    ))
}

/// `CandidateStore` — `locker` is optional: read-only consumers pass
/// `None`; a store that stages passes the lock adapter so the
/// manifest can record the lock digest it was staged under.
pub struct CandidateStore {
    locker: Option<LockAdapter>,
    base_dir: PathBuf,
}

impl CandidateStore {
    /// `NewCandidateStore`.
    pub fn new(locker: Option<LockAdapter>, base_dir: impl Into<PathBuf>) -> Self {
        Self {
            locker,
            base_dir: base_dir.into(),
        }
    }

    /// `Stage` — one immutable candidate: manifest, its digest, the
    /// local identities, all create-only and synced with both
    /// directories before return.
    pub fn stage(&self, deadline: OpDeadline, candidate: &Candidate) -> Result<Candidate, Failure> {
        deadline.check()?;
        if candidate.selector.is_empty() {
            return Err(invalid_candidate(
                "dependencyprepare: invalid candidate: selector must not be empty",
            ));
        }
        let candidates_dir = self.base_dir.join(CANDIDATES_DIR);
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&candidates_dir)
            .map_err(|e| io_failure("dependencyprepare: create candidates dir", e))?;
        let candidates_fd = open_store_dir(&candidates_dir)?;

        let id = generate_candidate_id(&candidate.selector)?;
        rustix::fs::mkdirat(&candidates_fd, id.as_str(), Mode::from_raw_mode(0o700))
            .map_err(|e| io_failure("dependencyprepare: create candidate dir", e))?;
        let candidate_dir = candidates_dir.join(&id);
        let candidate_fd = open_store_dir(&candidate_dir)?;
        let cleanup = |dir: &Path| {
            let _ = std::fs::remove_dir_all(dir);
        };

        let identity = match self.inspect_docker_identity() {
            Ok(i) => i,
            Err(e) => {
                cleanup(&candidate_dir);
                return Err(io_failure("dependencyprepare: inspect docker identity", e));
            }
        };
        let manifest = self.build_manifest(candidate, &id);
        if let Err(e) = central_infra::prepare::validate_manifest_source(&manifest) {
            cleanup(&candidate_dir);
            return Err(e);
        }
        let data = match serde_json::to_vec_pretty(&manifest) {
            Ok(d) => d,
            Err(e) => {
                cleanup(&candidate_dir);
                return Err(io_failure("dependencyprepare: marshal manifest", e));
            }
        };
        for (name, payload) in [
            (MANIFEST_FILE, data.clone()),
            (MANIFEST_DIGEST_FILE, sha256_hex(&data).into_bytes()),
            (DOCKER_IDENTITY_FILE, identity.into_bytes()),
        ] {
            if let Err(e) = create_only_at(&candidate_fd, name, &payload) {
                cleanup(&candidate_dir);
                return Err(e);
            }
        }
        for (fd, tag) in [(&candidate_fd, "candidate"), (&candidates_fd, "candidates")] {
            if let Err(e) = rustix::fs::fsync(fd) {
                cleanup(&candidate_dir);
                return Err(io_failure(format!("dependencyprepare: sync {tag} dir"), e));
            }
        }
        let mut staged = candidate.clone();
        staged.id = id;
        staged.phase = Some(central_infra::domain::PreparePhase::Staging);
        Ok(staged)
    }

    /// `SwitchSelector` — the sole prepared-state commit. A repeat of
    /// the same switch returns the first call's settlement record.
    pub fn switch_selector(
        &self,
        deadline: OpDeadline,
        candidate: &Candidate,
        binding: &AdmissionBinding,
    ) -> Result<DependencyReceipt, Failure> {
        deadline.check()?;
        if candidate.id.is_empty() || candidate.selector.is_empty() {
            return Err(invalid_candidate(
                "dependencyprepare: invalid candidate: candidate must have ID and selector",
            ));
        }
        if binding.admission_receipt_id.is_empty() || binding.selector_token.is_empty() {
            return Err(invalid_binding(
                "dependencyprepare: invalid admission binding: binding must have receipt ID and selector token",
            ));
        }
        valid_path_component(&candidate.id)
            .map_err(|e| invalid_candidate(format!("dependencyprepare: invalid candidate: {e}")))?;
        if binding.selector_token != selector_token(&candidate.selector) {
            return Err(invalid_binding(format!(
                "dependencyprepare: invalid admission binding: selector token does not bind selector {:?}",
                candidate.selector
            )));
        }
        let base_fd = open_store_dir(&self.base_dir)?;
        let candidate_dir = self.base_dir.join(CANDIDATES_DIR).join(&candidate.id);
        let candidate_fd = open_store_dir(&candidate_dir)?;

        // Active-candidate settlement is read-only: the candidate the
        // active file names is prepared state, not a promotable
        // candidate (upstream's SC-DEF comment verbatim in effect).
        let already_active = self
            .active_selector(&base_fd)
            .is_ok_and(|active| active == candidate.id);
        let (manifest, manifest_data) = if already_active {
            self.read_manifest(&candidate_fd)?
        } else {
            self.inspect_all(deadline, &candidate_fd, &candidate.id)?
        };
        if !manifest.selector.is_empty() && manifest.selector != candidate.selector {
            return Err(invalid_candidate(format!(
                "dependencyprepare: invalid candidate: staged candidate {:?} carries selector {:?}, not {:?}",
                candidate.id, manifest.selector, candidate.selector
            )));
        }
        let record = self.settlement_record(
            &candidate_fd,
            candidate,
            binding,
            &sha256_hex(&manifest_data),
        )?;
        if already_active {
            return Ok(receipt_from_record(&record, &manifest));
        }
        deadline.check()?;
        self.commit_selector(&base_fd, candidate)?;
        Ok(receipt_from_record(&record, &manifest))
    }

    /// `Active` — resolves the current selector into the receipt B03
    /// consumes; the manifest verifies against the recorded digest.
    pub fn active(&self, deadline: OpDeadline) -> Result<DependencyReceipt, Failure> {
        deadline.check()?;
        let base_fd = open_store_dir(&self.base_dir).map_err(|e| {
            invalid_candidate(format!(
                "dependencyprepare: invalid candidate: no active selector: {e}"
            ))
        })?;
        let data = read_no_follow_at(&base_fd, ACTIVE_FILE).map_err(|e| {
            invalid_candidate(format!(
                "dependencyprepare: invalid candidate: no active selector: {e}"
            ))
        })?;
        let (id, selector, _timestamp) = parse_active_selector(&data)?;
        valid_path_component(&id).map_err(|e| {
            invalid_candidate(format!(
                "dependencyprepare: invalid candidate: active selector names {e}"
            ))
        })?;
        let candidate_fd =
            open_store_dir(&self.base_dir.join(CANDIDATES_DIR).join(&id)).map_err(|e| {
                io_failure(
                    format!("dependencyprepare: open active candidate {id:?}"),
                    e,
                )
            })?;
        let (manifest, manifest_data) = self.read_manifest(&candidate_fd)?;
        let mut receipt = DependencyReceipt {
            id: id.clone(),
            manifest_digest: sha256_hex(&manifest_data),
            operation_id: manifest.operation_id.clone(),
            selector_generation: selector,
            dependency_set: manifest.dependency_set.clone(),
        };
        match self.read_settlement_record(&candidate_fd) {
            Ok(record) => receipt.operation_id = record.operation_id,
            Err(e) => {
                if !is_not_found(&e) {
                    return Err(e);
                }
            }
        }
        Ok(receipt)
    }

    /// `commitSelector` — `<id>\n<selector>\n<rfc3339>\n` under a temp
    /// name, same-directory rename, parent synced.
    fn commit_selector(&self, base_fd: &OwnedFd, candidate: &Candidate) -> Result<(), Failure> {
        let content = format!(
            "{}\n{}\n{}\n",
            candidate.id,
            candidate.selector,
            time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
        );
        let mut tmp_path = PathBuf::new();
        for attempt in 0..16u32 {
            let candidate_path = self.base_dir.join(format!(
                ".active-{:x}-{}.tmp",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or_default()
                    + u128::from(attempt)
            ));
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&candidate_path)
            {
                Ok(_) => {
                    tmp_path = candidate_path;
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => {
                    return Err(io_failure(
                        "dependencyprepare: create active selector temp",
                        e,
                    ));
                }
            }
        }
        if tmp_path.as_os_str().is_empty() {
            return Err(io_failure(
                "dependencyprepare: create active selector temp",
                "no free temporary name",
            ));
        }
        let committed = (|| -> Result<(), Failure> {
            use std::io::Write as _;
            let mut tmp = std::fs::OpenOptions::new()
                .write(true)
                .open(&tmp_path)
                .map_err(|e| io_failure("dependencyprepare: open active selector temp", e))?;
            tmp.write_all(content.as_bytes())
                .and_then(|()| tmp.sync_all())
                .map_err(|e| io_failure("dependencyprepare: write active selector", e))?;
            drop(tmp);
            rustix::fs::renameat_with(
                rustix::fs::CWD,
                &tmp_path,
                base_fd,
                ACTIVE_FILE,
                rustix::fs::RenameFlags::empty(),
            )
            .map_err(|e| io_failure("dependencyprepare: atomic rename active selector", e))?;
            rustix::fs::fsync(base_fd)
                .map_err(|e| io_failure("dependencyprepare: sync selector directory", e))?;
            Ok(())
        })();
        if committed.is_err() {
            let _ = std::fs::remove_file(&tmp_path);
        }
        committed
    }

    /// `settlementRecord` — written create-only the first time; a
    /// repeated switch reads the original record back.
    fn settlement_record(
        &self,
        candidate_fd: &OwnedFd,
        candidate: &Candidate,
        binding: &AdmissionBinding,
        manifest_digest: &str,
    ) -> Result<PreparedReceiptRecord, Failure> {
        let record = PreparedReceiptRecord {
            schema: central_infra::domain::PREPARED_RECEIPT_SCHEMA.to_owned(),
            receipt_id: candidate.id.clone(),
            manifest_digest: manifest_digest.to_owned(),
            operation_id: candidate.operation_id.clone(),
            selector_generation: candidate.selector.clone(),
            admission_receipt_id: binding.admission_receipt_id.clone(),
            settled_at: time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned()),
        };
        record.validate()?;
        let data = serde_json::to_vec_pretty(&record)
            .map_err(|e| io_failure("dependencyprepare: marshal settlement record", e))?;
        let candidate_dir = self.base_dir.join(CANDIDATES_DIR).join(&candidate.id);
        match publish_create_only(candidate_fd, &candidate_dir, RECEIPT_FILE, &data) {
            Ok(()) => Ok(record),
            Err(e) if e.kind() == central_foundation::failure::FailureKind::Conflict => {
                self.read_settlement_record(candidate_fd)
            }
            Err(e) => Err(e),
        }
    }

    fn read_settlement_record(
        &self,
        candidate_fd: &OwnedFd,
    ) -> Result<PreparedReceiptRecord, Failure> {
        let data = read_no_follow_at(candidate_fd, RECEIPT_FILE)?;
        let record: PreparedReceiptRecord = serde_json::from_slice(&data)
            .map_err(|e| io_failure("dependencyprepare: decode settlement record", e))?;
        record.validate()?;
        Ok(record)
    }

    /// `buildManifest` — the lock-bound store records the dependency
    /// lock's digest; the read-only probe carries none.
    fn build_manifest(&self, candidate: &Candidate, id: &str) -> PreparedManifest {
        let mut manifest = PreparedManifest {
            schema: central_infra::domain::PREPARED_MANIFEST_SCHEMA.to_owned(),
            candidate_id: id.to_owned(),
            operation_id: candidate.operation_id.clone(),
            selector: candidate.selector.clone(),
            phase: central_infra::domain::PreparePhase::Staging,
            created_at: time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned()),
            dependency_set: candidate.dependency_set.clone(),
            comparison: candidate.comparison.clone(),
            attestations: candidate.attestations.clone(),
            source: candidate.source,
            envelopes: candidate.envelopes.clone(),
            ..PreparedManifest::default()
        };
        if let Some(locker) = &self.locker
            && let Ok(digest) = locker.lock().canonical_hash()
        {
            manifest.lock_digest = digest;
        }
        manifest
    }

    /// `readManifest` — the staged manifest plus its exact bytes,
    /// verified against the recorded digest; the legacy
    /// (schema-less) manifest admits a missing digest, any
    /// schema-bearing manifest requires it.
    fn read_manifest(
        &self,
        candidate_fd: &OwnedFd,
    ) -> Result<(PreparedManifest, Vec<u8>), Failure> {
        let data = read_no_follow_at(candidate_fd, MANIFEST_FILE)
            .map_err(|e| io_failure("dependencyprepare: read manifest", e))?;
        let manifest: PreparedManifest = serde_json::from_slice(&data)
            .map_err(|e| io_failure("dependencyprepare: decode manifest", e))?;
        match read_no_follow_at(candidate_fd, MANIFEST_DIGEST_FILE) {
            Ok(expected) => {
                let got = sha256_hex(&data);
                if got != String::from_utf8_lossy(&expected).trim() {
                    return Err(manifest_integrity(format!(
                        "dependencyprepare: manifest digest {got} does not match recorded {}",
                        String::from_utf8_lossy(&expected).trim()
                    )));
                }
            }
            Err(e) if is_not_found(&e) => {
                if !manifest.is_legacy() {
                    return Err(manifest_integrity(format!(
                        "dependencyprepare: manifest carries schema {:?} but no digest is recorded beside it",
                        manifest.schema
                    )));
                }
            }
            Err(e) => {
                return Err(io_failure(
                    "dependencyprepare: read manifest digest",
                    e.message().to_owned(),
                ));
            }
        }
        Ok((manifest, data))
    }

    fn active_selector(&self, base_fd: &OwnedFd) -> Result<String, Failure> {
        let data = read_no_follow_at(base_fd, ACTIVE_FILE)?;
        let (id, _, _) = parse_active_selector(&data)?;
        Ok(id)
    }

    /// `inspectDockerIdentity` — the socket's dev/ino/mode/mtime, or
    /// the stable `no-docker-socket` sentinel on a host without one
    /// (ENOENT, EACCES, ENOTDIR).
    fn inspect_docker_identity(&self) -> Result<String, Failure> {
        const DOCKER_SOCK: &str = "/var/run/docker.sock";
        match std::fs::metadata(DOCKER_SOCK) {
            Ok(meta) => Ok(format!(
                "docker-socket:{}:{}:{}:{}",
                meta.dev(),
                meta.ino(),
                meta.mode(),
                meta.mtime_nsec()
            )),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                ) || e.raw_os_error() == Some(rustix::io::Errno::NOTDIR.raw_os_error()) =>
            {
                Ok("no-docker-socket".to_owned())
            }
            Err(e) => Err(io_failure("stat docker socket", e)),
        }
    }

    /// `inspectAll` — re-inspects every identity the staged candidate
    /// is bound to before promotion; drift quarantines the candidate.
    fn inspect_all(
        &self,
        deadline: OpDeadline,
        candidate_fd: &OwnedFd,
        id: &str,
    ) -> Result<(PreparedManifest, Vec<u8>), Failure> {
        deadline.check()?;
        let (manifest, data) = match self.read_manifest(candidate_fd) {
            Ok(pair) => pair,
            Err(e) if e.code() == "MANIFEST_INTEGRITY" => {
                return Err(self.quarantine(id, "manifest-integrity", &e));
            }
            Err(e) => return Err(e),
        };
        let staged = read_no_follow_at(candidate_fd, DOCKER_IDENTITY_FILE)
            .map_err(|e| io_failure("dependencyprepare: read docker identity", e))?;
        let current = self
            .inspect_docker_identity()
            .map_err(|e| io_failure("dependencyprepare: inspect docker identity", e))?;
        if staged != current.as_bytes() {
            let drift = io_failure(
                "docker identity drifted",
                format!("from {:?} to {current:?}", String::from_utf8_lossy(&staged)),
            );
            return Err(self.quarantine(id, "docker-identity-drift", &drift));
        }
        Ok((manifest, data))
    }

    /// `quarantine` — the candidate is moved out of the promotable
    /// set, kept as audit evidence under `quarantine/<id>-*` with a
    /// create-only `quarantine.json`; destination and candidates
    /// directory sync before the quarantine error returns.
    fn quarantine(&self, id: &str, reason: &str, cause: &Failure) -> Failure {
        let fail = || -> Result<(), Failure> {
            let quarantine_dir = self.base_dir.join(QUARANTINE_DIR);
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&quarantine_dir)
                .map_err(|e| io_failure("dependencyprepare: quarantine", e))?;
            // `os.MkdirTemp(quarantineDir, id+"-")` — a destination
            // that cannot collide with an earlier quarantine.
            let mut dest = PathBuf::new();
            for attempt in 0..16u32 {
                let candidate_dest = quarantine_dir.join(format!(
                    "{id}-{:x}{attempt}",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_nanos())
                        .unwrap_or_default()
                ));
                match std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&candidate_dest)
                {
                    Ok(()) => {
                        dest = candidate_dest;
                        break;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(e) => return Err(io_failure("dependencyprepare: quarantine", e)),
                }
            }
            if dest.as_os_str().is_empty() {
                return Err(io_failure(
                    "dependencyprepare: quarantine",
                    "no free destination",
                ));
            }
            let record = serde_json::json!({
                "schema": "central.quarantined-candidate/v1",
                "candidate_id": id,
                "reason": reason,
                "detail": cause.message(),
                "quarantined_at": time::OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned()),
            });
            let data = serde_json::to_vec_pretty(&record)
                .map_err(|e| io_failure("dependencyprepare: quarantine: marshal record", e))?;
            let dest_fd = open_store_dir(&dest)
                .map_err(|e| io_failure("dependencyprepare: quarantine", e.message().to_owned()))?;
            create_only_at(&dest_fd, "quarantine.json", &data)
                .map_err(|e| io_failure("dependencyprepare: quarantine", e.message().to_owned()))?;
            let candidate_dir = self.base_dir.join(CANDIDATES_DIR).join(id);
            std::fs::rename(&candidate_dir, dest.join("candidate"))
                .map_err(|e| io_failure("dependencyprepare: quarantine: move candidate", e))?;
            rustix::fs::fsync(&dest_fd)
                .map_err(|e| io_failure("dependencyprepare: quarantine: sync", e))?;
            if let Ok(candidates_fd) = open_store_dir(&self.base_dir.join(CANDIDATES_DIR)) {
                rustix::fs::fsync(&candidates_fd).map_err(|e| {
                    io_failure("dependencyprepare: quarantine: sync candidates dir", e)
                })?;
            }
            Ok(())
        };
        if let Err(e) = fail() {
            return e;
        }
        // `dp.ErrCandidateQuarantined`.
        Failure::invalid(
            "CANDIDATE_QUARANTINED",
            format!("candidate quarantined: {reason}: {}", cause.message()),
        )
    }
}

/// `ActiveReceiptReader` — the lifecycle service's B02 selector
/// boundary: `NewCandidateStore(nil, dependencyRoot)` is upstream's
/// read-only receipts seam in `newHelperLifecycleHandler`. The narrowed
/// port carries no request context, so `OpDeadline::NONE` is the
/// always-live `ctx` upstream's one `ctx.Err()` check observes — the
/// store's own filesystem reads are the whole operation.
impl crate::infra::lifecycle::ActiveReceiptReader for CandidateStore {
    fn active(&self) -> Result<DependencyReceipt, Failure> {
        self.active(OpDeadline::NONE)
    }
}

fn receipt_from_record(
    record: &PreparedReceiptRecord,
    manifest: &PreparedManifest,
) -> DependencyReceipt {
    DependencyReceipt {
        id: record.receipt_id.clone(),
        manifest_digest: record.manifest_digest.clone(),
        operation_id: record.operation_id.clone(),
        selector_generation: record.selector_generation.clone(),
        dependency_set: manifest.dependency_set.clone(),
    }
}

/// Whether a Failure carries `os.ErrNotExist` (`map_io` maps
/// `Errno::NOENT` to `FailureKind::NotFound`; `Conflict` marks
/// publish's EEXIST separately).
fn is_not_found(e: &Failure) -> bool {
    e.kind() == central_foundation::failure::FailureKind::NotFound
}

#[cfg(test)]
mod tests {
    use super::*;
    use central_infra::domain::{PreparePhase, PreparedDependencySet, new_candidate};

    fn tempdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "central-t13-store-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn candidate_for(selector: &str) -> Candidate {
        let mut candidate = new_candidate(selector).unwrap();
        candidate.operation_id = "op-1".to_owned();
        candidate
    }

    /// `Stage` writes the three create-only files; `SwitchSelector`
    /// promotes the candidate and `Active` resolves the same receipt;
    /// a repeated switch returns the first settlement record.
    #[test]
    fn stage_switch_active_round_trip() {
        let dir = tempdir("round");
        let store = CandidateStore::new(None, &dir);
        let mut candidate = candidate_for("version-zero");
        candidate.dependency_set = PreparedDependencySet::default();
        let staged = store.stage(OpDeadline::NONE, &candidate).unwrap();
        assert!(staged.id.starts_with("cand-"));
        assert_eq!(staged.phase, Some(PreparePhase::Staging));
        let binding = central_infra::domain::new_admission_binding(
            "version-zero:test",
            &selector_token(&staged.selector),
        )
        .unwrap();
        let receipt = store
            .switch_selector(OpDeadline::NONE, &staged, &binding)
            .unwrap();
        assert_eq!(receipt.selector_generation, "version-zero");
        let active = store.active(OpDeadline::NONE).unwrap();
        assert_eq!(active.id, receipt.id);
        // A repeated switch returns the original settlement record.
        let again = store
            .switch_selector(OpDeadline::NONE, &staged, &binding)
            .unwrap();
        assert_eq!(again.id, receipt.id);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `Active` on an empty store refuses; a dangling active file is
    /// the same refusal class.
    #[test]
    fn active_refuses_without_selector() {
        let dir = tempdir("empty");
        let store = CandidateStore::new(None, &dir);
        assert!(store.active(OpDeadline::NONE).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A schema-bearing manifest whose digest sidecar is missing fails
    /// closed as manifest-integrity (quarantined through
    /// `SwitchSelector`).
    #[test]
    fn missing_digest_quarantines() {
        let dir = tempdir("quar");
        let store = CandidateStore::new(None, &dir);
        let mut candidate = candidate_for("version-zero");
        candidate.dependency_set = PreparedDependencySet::default();
        let staged = store.stage(OpDeadline::NONE, &candidate).unwrap();
        std::fs::remove_file(
            dir.join(CANDIDATES_DIR)
                .join(&staged.id)
                .join(MANIFEST_DIGEST_FILE),
        )
        .unwrap();
        let binding = central_infra::domain::new_admission_binding(
            "version-zero:test",
            &selector_token(&staged.selector),
        )
        .unwrap();
        let err = store
            .switch_selector(OpDeadline::NONE, &staged, &binding)
            .unwrap_err();
        assert_eq!(err.code(), "CANDIDATE_QUARANTINED");
        assert!(
            dir.join(QUARANTINE_DIR)
                .read_dir()
                .unwrap()
                .next()
                .is_some()
        );
        assert!(!dir.join(CANDIDATES_DIR).join(&staged.id).exists());
        std::fs::remove_dir_all(&dir).ok();
    }
}
