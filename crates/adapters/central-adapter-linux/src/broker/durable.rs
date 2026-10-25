//! Durable-file primitives shared by the broker's protected stores —
//! the port of the helpers upstream spreads across `signing.go`,
//! `migration_launch.go`, `recovery_journal.go`, and `journal.go`
//! (`ensurePrivateRoot`, `validateBrokerOwnedRoot`, `validatePrivateDirectory`,
//! `validatePrivateFile`, `validateOwner`, `syncDir`, `syncFile`,
//! `writeExclusiveJSON`, `replaceJSON`, `readPrivateJSON`, `openLock` /
//! `unlockAndClose`).
//!
//! Everything here is the adapter's private durability vocabulary:
//! private modes (`0700`/`0600`), create-exclusive writes, fsync'd
//! temp-file replace, and the `flock` guard the stores use to serialize
//! read-modify-write state transitions.

use std::fs;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use central_foundation::failure::Failure;
use rustix::fs::{CWD, Mode, OFlags, RenameFlags, renameat_with};

/// `privateFileMode` — `0600`: broker-private regular files.
pub(crate) const PRIVATE_FILE_MODE: u32 = 0o600;
/// `privateDirectoryMode` — `0700`: broker-private directories.
pub(crate) const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
/// `fingerprintKeyFilename` — the signing service's persistent key.
pub(crate) const FINGERPRINT_KEY_FILENAME: &str = "hmac-fingerprint.key";

fn internal(code: &'static str, msg: impl Into<String>) -> Failure {
    Failure::internal(code, msg)
}

/// `procSelfFDRootPattern` — exactly `/proc/self/fd/<digits>` (and
/// nothing longer), the kernel-synthesized magic-symlink path
/// `adoptInheritedDirectory` hands the broker as its protected root so a
/// TOCTOU path-based reopen is never needed (SC-DEF-56). Implemented
/// as a plain string check — the upstream regex is
/// `^/proc/self/fd/[0-9]+$`.
pub(crate) fn is_proc_self_fd_root(path: &Path) -> bool {
    path.as_os_str().to_str().is_some_and(|s| {
        s.strip_prefix("/proc/self/fd/")
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
    })
}

/// `validateOwner` — the effective user must own the entry.
pub(crate) fn validate_owner(meta: &fs::Metadata, name: &str) -> Result<(), Failure> {
    if meta.uid() != rustix::process::geteuid().as_raw() {
        return Err(Failure::denied(
            "broker_durable_denied",
            format!("broker: {name} is not owned by the broker user"),
        ));
    }
    Ok(())
}

/// `ensurePrivateRoot` — create-or-adopt the broker state root. The
/// `/proc/self/fd/<N>` carve-out skips `mkdir`/symlink rejection because
/// the kernel resolves it to an already-open, already-validated
/// descriptor; every other shape must be a real directory owned by the
/// effective user.
pub(crate) fn ensure_private_root(root: &Path) -> Result<(), Failure> {
    if is_proc_self_fd_root(root) {
        let meta = fs::metadata(root).map_err(|e| {
            internal(
                "broker_durable_os",
                format!("broker: inspect signing key root: {e}"),
            )
        })?;
        if !meta.is_dir() {
            return Err(internal(
                "broker_durable_invalid",
                "broker: signing key root is not a directory",
            ));
        }
        return validate_owner(&meta, "signing key root");
    }
    fs::create_dir_all(root).map_err(|e| {
        internal(
            "broker_durable_os",
            format!("broker: create signing key root: {e}"),
        )
    })?;
    let meta = fs::symlink_metadata(root).map_err(|e| {
        internal(
            "broker_durable_os",
            format!("broker: inspect signing key root: {e}"),
        )
    })?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(internal(
            "broker_durable_invalid",
            "broker: signing key root is not a directory",
        ));
    }
    validate_owner(&meta, "signing key root")
}

/// `validateBrokerOwnedRoot` — the shared parent must be a real
/// owner-controlled directory and never a symlink; the private modes on
/// the store's own children are enforced by [`validate_private_directory`].
pub(crate) fn validate_broker_owned_root(path: &Path, label: &str) -> Result<(), Failure> {
    if is_proc_self_fd_root(path) {
        let meta = fs::metadata(path)
            .map_err(|e| internal("broker_durable_os", format!("broker: {label}: {e}")))?;
        if !meta.is_dir() {
            return Err(internal(
                "broker_durable_invalid",
                format!("broker: {label} is not a directory"),
            ));
        }
        return validate_owner(&meta, label);
    }
    let meta = fs::symlink_metadata(path)
        .map_err(|e| internal("broker_durable_os", format!("broker: {label}: {e}")))?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(internal(
            "broker_durable_invalid",
            format!("broker: {label} is not a directory"),
        ));
    }
    validate_owner(&meta, label)
}

/// `validatePrivateDirectory` — `lstat`: a real directory with exact
/// `0700` and owner ownership.
pub(crate) fn validate_private_directory(path: &Path, name: &str) -> Result<(), Failure> {
    let meta = fs::symlink_metadata(path).map_err(|e| {
        internal(
            "broker_durable_os",
            format!("migration launch store: inspect {name}: {e}"),
        )
    })?;
    if !meta.is_dir()
        || meta.file_type().is_symlink()
        || meta.permissions().mode() & 0o777 != PRIVATE_DIRECTORY_MODE
    {
        return Err(Failure::denied(
            "broker_durable_denied",
            format!("migration launch store: insecure {name}"),
        ));
    }
    validate_owner(&meta, name)
}

/// `validatePrivateFile` — a regular file with exact `0600`, link count
/// one, owned by the effective user.
pub(crate) fn validate_private_file(meta: &fs::Metadata, name: &str) -> Result<(), Failure> {
    if !meta.file_type().is_file()
        || meta.file_type().is_symlink()
        || meta.permissions().mode() & 0o777 != PRIVATE_FILE_MODE
    {
        return Err(Failure::denied(
            "broker_durable_denied",
            format!("migration launch store: insecure {name}"),
        ));
    }
    validate_owner(meta, name)?;
    if meta.nlink() != 1 {
        return Err(Failure::denied(
            "broker_durable_denied",
            format!("migration launch store: invalid {name} link count"),
        ));
    }
    Ok(())
}

/// `syncDir`/`syncProtectedDirectory` — open the directory and fsync it.
pub(crate) fn sync_dir(dir: &Path) -> Result<(), Failure> {
    let fd = rustix::fs::open(
        dir.as_os_str(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| {
        internal(
            "broker_durable_os",
            format!("sync dir {}: {e}", dir.display()),
        )
    })?;
    rustix::fs::fsync(&fd).map_err(|e| {
        internal(
            "broker_durable_os",
            format!("fsync dir {}: {e}", dir.display()),
        )
    })
}

/// `syncFile` — open the file `O_RDONLY|O_NOFOLLOW` and fsync it.
pub(crate) fn sync_file(path: &Path) -> Result<(), Failure> {
    let fd = rustix::fs::open(
        path.as_os_str(),
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|e| {
        internal(
            "broker_durable_os",
            format!("sync file {}: {e}", path.display()),
        )
    })?;
    rustix::fs::fsync(&fd).map_err(|e| {
        internal(
            "broker_durable_os",
            format!("fsync file {}: {e}", path.display()),
        )
    })
}

/// `writeExclusiveJSON` — `O_WRONLY|O_CREATE|O_EXCL|O_CLOEXEC` at
/// `0600`, write-all, fsync, close, then dir-sync.
pub(crate) fn write_exclusive_json<T: serde::Serialize>(
    path: &Path,
    value: &T,
) -> Result<(), Failure> {
    let payload = serde_json::to_vec(value)
        .map_err(|e| internal("broker_durable_codec", format!("marshal: {e}")))?;
    write_exclusive(path, &payload)
}

/// `O_EXCL` create at `0600` + fsync + dir-sync — the create-only file
/// install upstream's stores use for one-shot records.
pub(crate) fn write_exclusive(path: &Path, payload: &[u8]) -> Result<(), Failure> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .custom_flags(libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| {
            internal(
                "broker_durable_os",
                format!("create exclusive {}: {e}", path.display()),
            )
        })?;
    use std::io::Write as _;
    file.write_all(payload)
        .and_then(|()| file.sync_all())
        .map_err(|e| {
            internal(
                "broker_durable_os",
                format!("write {}: {e}", path.display()),
            )
        })?;
    drop(file);
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    sync_dir(parent)
}

/// `replaceJSON` — a same-directory `.recovery-journal-*` temp file at
/// `0600`, fsync, atomic rename over the target, dir-sync.
pub(crate) fn replace_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), Failure> {
    let payload = serde_json::to_vec(value)
        .map_err(|e| internal("broker_durable_codec", format!("marshal: {e}")))?;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = unique_tmp(dir, ".recovery-journal-")?;
    let result = (|| -> Result<(), Failure> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(PRIVATE_FILE_MODE)
            .custom_flags(libc::O_CLOEXEC)
            .open(&tmp)
            .map_err(|e| internal("broker_durable_os", format!("create tmp: {e}")))?;
        use std::io::Write as _;
        file.write_all(&payload)
            .and_then(|()| file.sync_all())
            .map_err(|e| internal("broker_durable_os", format!("write tmp: {e}")))?;
        drop(file);
        fs::rename(&tmp, path)
            .map_err(|e| internal("broker_durable_os", format!("rename: {e}")))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result?;
    sync_dir(dir)
}

/// Unique temp-path allocation in `dir` with the given prefix — the
/// `os.CreateTemp(dir, ".recovery-journal-")` shape upstream uses. The
/// file is not created here; the caller opens it `O_EXCL`.
fn unique_tmp(dir: &Path, prefix: &str) -> Result<PathBuf, Failure> {
    for _ in 0..64 {
        let mut name = [0u8; 8];
        rustix::rand::getrandom(&mut name, rustix::rand::GetRandomFlags::empty())
            .map_err(|e| internal("broker_durable_os", format!("tmp name entropy: {e}")))?;
        let candidate = dir.join(format!("{}{}", prefix, super::wire::hex_encode(&name)));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(internal(
        "broker_durable_os",
        "tmp name allocation exhausted",
    ))
}

/// `openLock` — `O_CREAT|O_RDWR|O_CLOEXEC|O_NOFOLLOW` `0600`, private
/// shape check, blocking `flock(LOCK_EX)`.
pub(crate) fn open_lock(path: &Path) -> Result<OwnedFd, Failure> {
    let fd = rustix::fs::open(
        path.as_os_str(),
        OFlags::CREATE | OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(PRIVATE_FILE_MODE),
    )
    .map_err(|e| {
        internal(
            "broker_durable_os",
            format!("open lock {}: {e}", path.display()),
        )
    })?;
    let meta = rustix::fs::fstat(&fd)
        .map_err(|e| internal("broker_durable_os", format!("fstat lock: {e}")))?;
    if !rustix::fs::FileType::from_raw_mode(meta.st_mode).is_file() {
        return Err(Failure::denied(
            "broker_durable_denied",
            "lock is not a regular file",
        ));
    }
    if meta.st_mode & 0o777 != PRIVATE_FILE_MODE {
        return Err(Failure::denied(
            "broker_durable_denied",
            "lock has insecure permissions",
        ));
    }
    if meta.st_uid != rustix::process::geteuid().as_raw() {
        return Err(Failure::denied(
            "broker_durable_denied",
            "lock is not owned by the broker user",
        ));
    }
    if meta.st_nlink != 1 {
        return Err(Failure::denied(
            "broker_durable_denied",
            "lock has an invalid link count",
        ));
    }
    rustix::fs::flock(&fd, rustix::fs::FlockOperation::LockExclusive)
        .map_err(|e| internal("broker_durable_os", format!("flock: {e}")))?;
    Ok(fd)
}

/// `unlockAndClose` — `LOCK_UN` then close.
pub(crate) fn unlock_and_close(fd: OwnedFd) {
    let _ = rustix::fs::flock(&fd, rustix::fs::FlockOperation::Unlock);
    drop(fd);
}

/// `renameat2(AT_FDCWD, tmp, AT_FDCWD, target, RENAME_NOREPLACE)` — the
/// journal's atomic commit step: the install succeeds only when no
/// record already occupies the target.
pub(crate) fn rename_noreplace(tmp: &Path, target: &Path) -> Result<(), Failure> {
    renameat_with(
        CWD,
        tmp.as_os_str(),
        CWD,
        target.as_os_str(),
        RenameFlags::NOREPLACE,
    )
    .map_err(|e| {
        internal(
            "broker_durable_os",
            format!("atomic commit {}: {e}", target.display()),
        )
    })
}

/// Plain `renameat2` replacement (no flags) — the active-pointer
/// linearization point upstream installs with `unix.Renameat2(…, 0)`.
pub(crate) fn rename_replace(tmp: &Path, target: &Path) -> Result<(), Failure> {
    renameat_with(
        CWD,
        tmp.as_os_str(),
        CWD,
        target.as_os_str(),
        RenameFlags::empty(),
    )
    .map_err(|e| {
        internal(
            "broker_durable_os",
            format!("atomic replace {}: {e}", target.display()),
        )
    })
}
