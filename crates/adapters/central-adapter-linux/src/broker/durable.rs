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

use std::ffi::OsString;
use std::fs;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStringExt as _;
use std::path::{Component, Path, PathBuf};

use central_foundation::failure::Failure;
use rustix::fs::{
    AtFlags, CWD, FileType, Mode, OFlags, RawDir, RenameFlags, mkdirat, openat, renameat_with,
    statat, unlinkat,
};
use rustix::io::Errno;

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

/// `os.Stat` — `newfstatat(AT_FDCWD, path, 0)`; follows symlinks.
/// `fs::metadata` emits `statx` (332), which the broker seccomp filter
/// does not allow — every post-`harden()` metadata probe goes through
/// this or [`lstat`] (ADR 0044).
pub(crate) fn stat(path: &Path) -> Result<rustix::fs::Stat, Errno> {
    statat(CWD, path.as_os_str(), AtFlags::empty())
}

/// `os.Lstat` — `newfstatat(AT_FDCWD, path, AT_SYMLINK_NOFOLLOW)`; the
/// entry itself is described, not its target (`fs::symlink_metadata`
/// emits `statx`).
pub(crate) fn lstat(path: &Path) -> Result<rustix::fs::Stat, Errno> {
    statat(CWD, path.as_os_str(), AtFlags::SYMLINK_NOFOLLOW)
}

/// `Path::exists` — a stat-follow succeeds.
pub(crate) fn exists(path: &Path) -> bool {
    stat(path).is_ok()
}

fn stat_is_dir(st: &rustix::fs::Stat) -> bool {
    FileType::from_raw_mode(st.st_mode).is_dir()
}

fn stat_is_symlink(st: &rustix::fs::Stat) -> bool {
    FileType::from_raw_mode(st.st_mode).is_symlink()
}

/// `os.MkdirAll` — `mkdirat` each missing component at `mode` (the same
/// mode Go applies to every level it creates); a component that already
/// exists must be a directory after following symlinks, matching
/// `os.Stat`'s terminal check. Callers that used `fs::create_dir_all`
/// plus `fs::set_permissions` relied on `fchmodat` (268), which the
/// filter does not allow — carrying the mode at creation also closes
/// upstream's mkdir→chmod umask race.
pub(crate) fn mkdir_p(path: &Path, mode: u32) -> Result<(), Errno> {
    let mode = Mode::from_raw_mode(mode);
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match component {
            Component::Prefix(_) | Component::RootDir | Component::CurDir => continue,
            Component::ParentDir | Component::Normal(_) => {
                match mkdirat(CWD, current.as_os_str(), mode) {
                    Ok(()) => {}
                    Err(Errno::EXIST) => {
                        let st = stat(&current)?;
                        if !stat_is_dir(&st) {
                            return Err(Errno::NOTDIR);
                        }
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }
    Ok(())
}

/// `os.WriteFile` — `openat(O_WRONLY|O_CREAT|O_TRUNC, mode)`, write-all,
/// close; mode applied at creation (umask-masked, as upstream). The
/// previous `fs::write` + `fs::set_permissions` shape needed `fchmodat`
/// (268), which the filter does not allow.
pub(crate) fn write_file(path: &Path, data: &[u8], mode: u32) -> Result<(), Errno> {
    let fd = rustix::fs::openat(
        CWD,
        path.as_os_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::CLOEXEC,
        Mode::from_raw_mode(mode),
    )?;
    let mut written = 0;
    while written < data.len() {
        match rustix::io::write(&fd, &data[written..]) {
            Ok(0) => return Err(Errno::IO),
            Ok(n) => written += n,
            Err(Errno::INTR) => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// `os.Open` — `openat(O_RDONLY|O_CLOEXEC|O_NOFOLLOW)`, returned as a
/// `File` for `Read`/`read_to_end` callers. `File::open`/`fs::read`
/// emit `open` (2), which the filter does not list — `openat` (257) is
/// the listed primitive (ADR 0044). `NOFOLLOW` keeps the store's
/// leaf-is-never-a-symlink contract at open time.
///
/// # Errors
/// `Errno` of the `openat` failure (`NOENT` for the absent-file
/// sentinel callers check).
pub(crate) fn open_read(path: &Path) -> Result<fs::File, Errno> {
    openat(
        CWD,
        path.as_os_str(),
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map(fs::File::from)
}

/// `os.ReadFile` — [`open_read`] plus read-to-end. The store's records
/// are small bounded JSON; readers that need an explicit cap go
/// through [`crate::broker::protected_file::open_protected_file`]
/// instead.
///
/// # Errors
/// `Errno` of the open/read failure (`NOENT` for absent files).
pub(crate) fn read_file(path: &Path) -> Result<Vec<u8>, Errno> {
    use std::io::Read as _;
    let mut file = open_read(path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)
        .map_err(|e| Errno::from_io_error(&e).unwrap_or(Errno::IO))?;
    Ok(data)
}

/// `os.OpenFile(O_WRONLY|O_CREATE|O_TRUNC|O_CLOEXEC, mode)` — the
/// mode applies at creation (umask-masked, as upstream); a pre-existing
/// file keeps its mode, so callers that must tighten re-check with
/// [`lstat`] or `fchmod` the open fd (`fchmodat` is not listed).
///
/// # Errors
/// `Errno` of the `openat` failure.
pub(crate) fn open_write(path: &Path, mode: u32) -> Result<fs::File, Errno> {
    openat(
        CWD,
        path.as_os_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::CLOEXEC,
        Mode::from_raw_mode(mode),
    )
    .map(fs::File::from)
}

/// `os.OpenFile(O_WRONLY|O_CREATE|O_EXCL|O_CLOEXEC, mode)` — the
/// create-only install upstream's stores use for one-shot records.
///
/// # Errors
/// `Errno` of the `openat` failure (`EXIST` races a prior install).
pub(crate) fn open_exclusive(path: &Path, mode: u32) -> Result<fs::File, Errno> {
    openat(
        CWD,
        path.as_os_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::from_raw_mode(mode),
    )
    .map(fs::File::from)
}

/// One `getdents64` entry: name plus the `d_type` the filesystem
/// reported ([`FileType::UNKNOWN`] when it declined to, matching
/// `fs::DirEntry::file_type`'s cheap path).
pub(crate) struct DirEnt {
    pub name: OsString,
    pub file_type: FileType,
}

/// `os.ReadDir` — `openat(O_DIRECTORY)` + `getdents64` via [`RawDir`]:
/// names and `d_type` only. Unlike `fs::read_dir`, nothing here can
/// emit `statx`/`fstatat` behind the caller's back — entries that need
/// more than `d_type` are [`lstat`]ed by name at the call site (a
/// `newfstatat`, which the filter allows).
pub(crate) fn read_dir(path: &Path) -> Result<Vec<DirEnt>, Errno> {
    let fd = rustix::fs::openat(
        CWD,
        path.as_os_str(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let mut buf = Vec::with_capacity(8192);
    let mut iter = RawDir::new(&fd, buf.spare_capacity_mut());
    let mut out = Vec::new();
    while let Some(entry) = iter.next() {
        let entry = entry?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        out.push(DirEnt {
            name: OsString::from_vec(name.to_vec()),
            file_type: entry.file_type(),
        });
    }
    Ok(out)
}

/// `os.RemoveAll` — `unlinkat` files, depth-first recursion into real
/// directories, `unlinkat(AT_REMOVEDIR)` on the way back up. A symlink
/// is unlinked itself, never descended through. `ENOENT` is success,
/// matching upstream; `fs::remove_dir_all` is avoided because its
/// internal `file_type`/`is_dir` probes can emit `statx`.
pub(crate) fn remove_all(path: &Path) -> Result<(), Errno> {
    match unlinkat(CWD, path.as_os_str(), AtFlags::empty()) {
        Ok(()) | Err(Errno::NOENT) => Ok(()),
        Err(Errno::ISDIR) => {
            for entry in read_dir(path)? {
                remove_all(&path.join(&entry.name))?;
            }
            match unlinkat(CWD, path.as_os_str(), AtFlags::REMOVEDIR) {
                Ok(()) | Err(Errno::NOENT) => Ok(()),
                Err(e) => Err(e),
            }
        }
        Err(e) => Err(e),
    }
}

/// `validateOwner` — the effective user must own the entry.
pub(crate) fn validate_owner(meta: &rustix::fs::Stat, name: &str) -> Result<(), Failure> {
    if meta.st_uid != rustix::process::geteuid().as_raw() {
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
        let meta = stat(root).map_err(|e| {
            internal(
                "broker_durable_os",
                format!("broker: inspect signing key root: {e}"),
            )
        })?;
        if !stat_is_dir(&meta) {
            return Err(internal(
                "broker_durable_invalid",
                "broker: signing key root is not a directory",
            ));
        }
        return validate_owner(&meta, "signing key root");
    }
    mkdir_p(root, PRIVATE_DIRECTORY_MODE).map_err(|e| {
        internal(
            "broker_durable_os",
            format!("broker: create signing key root: {e}"),
        )
    })?;
    let meta = lstat(root).map_err(|e| {
        internal(
            "broker_durable_os",
            format!("broker: inspect signing key root: {e}"),
        )
    })?;
    if !stat_is_dir(&meta) || stat_is_symlink(&meta) {
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
        let meta = stat(path)
            .map_err(|e| internal("broker_durable_os", format!("broker: {label}: {e}")))?;
        if !stat_is_dir(&meta) {
            return Err(internal(
                "broker_durable_invalid",
                format!("broker: {label} is not a directory"),
            ));
        }
        return validate_owner(&meta, label);
    }
    let meta =
        lstat(path).map_err(|e| internal("broker_durable_os", format!("broker: {label}: {e}")))?;
    if !stat_is_dir(&meta) || stat_is_symlink(&meta) {
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
    let meta = lstat(path).map_err(|e| {
        internal(
            "broker_durable_os",
            format!("migration launch store: inspect {name}: {e}"),
        )
    })?;
    if !stat_is_dir(&meta)
        || stat_is_symlink(&meta)
        || meta.st_mode & 0o777 != PRIVATE_DIRECTORY_MODE
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
pub(crate) fn validate_private_file(meta: &rustix::fs::Stat, name: &str) -> Result<(), Failure> {
    if !FileType::from_raw_mode(meta.st_mode).is_file()
        || stat_is_symlink(meta)
        || meta.st_mode & 0o777 != PRIVATE_FILE_MODE
    {
        return Err(Failure::denied(
            "broker_durable_denied",
            format!("migration launch store: insecure {name}"),
        ));
    }
    validate_owner(meta, name)?;
    if meta.st_nlink != 1 {
        return Err(Failure::denied(
            "broker_durable_denied",
            format!("migration launch store: invalid {name} link count"),
        ));
    }
    Ok(())
}

/// `syncDir`/`syncProtectedDirectory` — open the directory and fsync it.
pub(crate) fn sync_dir(dir: &Path) -> Result<(), Failure> {
    let fd = openat(
        CWD,
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
    let fd = openat(
        CWD,
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
    let mut file = open_exclusive(path, PRIVATE_FILE_MODE).map_err(|e| {
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
        let mut file = open_exclusive(&tmp, PRIVATE_FILE_MODE)
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
        if !exists(&candidate) {
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
    let fd = openat(
        CWD,
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
