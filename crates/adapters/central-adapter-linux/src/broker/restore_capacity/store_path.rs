//! `restore_capacity_reserve_store_path_linux.go` — the *one* resolver
//! for the restore-capacity reserve's device-keyed store. Helper
//! creation (`0xc3` confirm), the daemon's admission gate re-open, and
//! the sweep's directory walk must land on byte-identical paths, so
//! every physical reserve object in this package is reached through
//! [`ReserveDeviceStore`]'s held descriptor — never through a path a
//! caller could re-derive.
//!
//! The store is a compile-time-fixed, device-keyed, `root:root 0700`
//! directory *beside* each role root (SC-DEF-70: inside PGDATA it would
//! be an unprivileged-unenumerable descendant that trips fs-init's
//! mount walk), resolved with
//! `openat2(RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH|RESOLVE_NO_XDEV)` from
//! the held descriptor, objects created `O_CREAT|O_EXCL|O_NOFOLLOW`,
//! then fstat-checked for regular-file/`st_dev`/`st_uid==0`/`st_nlink==1`.

use std::fs;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;

use central_foundation::failure::Failure;
use rustix::fs::{FileType, Mode, OFlags, ResolveFlags};
use rustix::io::Errno;
use sha2::{Digest, Sha256};

use crate::broker::durable;
use crate::sys::openat2;

/// `restoreCapacityReserveStoreDirName` — the compile-time-fixed store
/// directory name. No configuration value, environment variable, or
/// argument may name the store.
pub(crate) const STORE_DIR_NAME: &str = ".central-restore-capacity-reserve";

/// `restoreCapacityReserveObjectSuffix` — distinguishes a reserve
/// object from anything else dropped into the store directory.
pub(crate) const OBJECT_SUFFIX: &str = ".reserve";

/// `restoreCapacityReserveFingerprintPrefix`/`...HexLen` — the device
/// fingerprint's shape: `fs-` + 32 lowercase hex (the first 16 digest
/// bytes). A *naming key* only — every identity decision turns on
/// `st_dev`; a fingerprint match is never a substitute for one.
pub(crate) const FINGERPRINT_PREFIX: &str = "fs-";
pub(crate) const FINGERPRINT_HEX_LEN: usize = 32;

/// `restoreCapacityReserveResolveFlags` — the design's `openat2`
/// resolve mask, written once and used by every `openat2` in this
/// module: `RESOLVE_BENEATH` refuses escapes from the held descriptor,
/// `RESOLVE_NO_XDEV` refuses a mount crossing, `RESOLVE_NO_SYMLINKS`
/// refuses any symlink including an intermediate component.
const RESOLVE_FLAGS: ResolveFlags = ResolveFlags::NO_SYMLINKS
    .union(ResolveFlags::BENEATH)
    .union(ResolveFlags::NO_XDEV);

// The store's named refusals — upstream sentinels as `Failure` codes so
// a substitution test (and the sweep) can tell *which* assertion fired.
const FP_INVALID: &str = "broker_restore_reserve_fingerprint_invalid";
const RESOLVE_REFUSED: &str = "broker_restore_reserve_resolve_refused";
const STORE_NOT_DIR: &str = "broker_restore_reserve_store_not_directory";
const STORE_DEVICE: &str = "broker_restore_reserve_store_wrong_device";
const STORE_OWNER: &str = "broker_restore_reserve_store_wrong_owner";
const STORE_MODE: &str = "broker_restore_reserve_store_wrong_mode";
const OBJECT_NOT_REGULAR: &str = "broker_restore_reserve_object_not_regular";
const OBJECT_DEVICE: &str = "broker_restore_reserve_object_wrong_device";
const OBJECT_OWNER: &str = "broker_restore_reserve_object_wrong_owner";
const OBJECT_LINKS: &str = "broker_restore_reserve_object_link_count";
/// `os.ErrExist`/`os.ErrNotExist` carried as codes — upstream returns
/// the bare errno so callers discriminate `errors.Is`; the port's
/// `Failure` carries the same fact as a code instead.
const OBJECT_EXISTS: &str = "broker_restore_reserve_object_exists";
const OBJECT_ABSENT: &str = "broker_restore_reserve_object_absent";

/// `errors.Is(err, os.ErrExist)` — the create path's "already there".
#[allow(dead_code)] // create-path classification for the helper-side allocator
pub(crate) fn is_object_exists(f: &Failure) -> bool {
    f.code() == OBJECT_EXISTS
}

/// `errors.Is(err, os.ErrNotExist)` — the open path's "not there".
#[allow(dead_code)] // open-path classification for the helper-side sweep
pub(crate) fn is_object_absent(f: &Failure) -> bool {
    f.code() == OBJECT_ABSENT
}

fn fingerprint_invalid() -> Failure {
    Failure::invalid(
        FP_INVALID,
        "broker: invalid restore capacity reserve device fingerprint",
    )
}

fn resolve_refused(detail: impl Into<String>) -> Failure {
    Failure::denied(RESOLVE_REFUSED, detail.into())
}

fn assertion(code: &'static str, msg: &str) -> Failure {
    Failure::denied(code, format!("broker: {msg}"))
}

/// `restoreCapacityReserveDeviceFingerprint` — derive the naming key
/// from a filesystem's `f_fsid`, refusing a zero fsid outright (it is
/// not an identity — several filesystems report it). Mirrors
/// `internal/adapter/backup`'s `opaqueFilesystemID` byte-for-byte so the
/// two adapters name the same device the same way. `fsid` packs
/// `val[0]` high, `val[1]` low — [`crate::sys::audited::statfs_fsid`]'s
/// shape.
///
/// # Errors
/// [`FP_INVALID`] when the fsid is zero.
pub(crate) fn device_fingerprint(fsid: u64) -> Result<String, Failure> {
    if fsid == 0 {
        return Err(fingerprint_invalid());
    }
    // Mirrors `opaqueFilesystemID`: little-endian `f_fsid.val[0]` then
    // `val[1]` as u32s, sha256, first 16 bytes hex.
    let mut payload = [0u8; 8];
    payload[..4].copy_from_slice(&((fsid >> 32) as u32).to_le_bytes());
    payload[4..].copy_from_slice(&(fsid as u32).to_le_bytes());
    let digest = Sha256::digest(payload);
    let mut out = String::with_capacity(FINGERPRINT_PREFIX.len() + FINGERPRINT_HEX_LEN);
    out.push_str(FINGERPRINT_PREFIX);
    for b in &digest[..FINGERPRINT_HEX_LEN / 2] {
        out.push_str(&format!("{b:02x}"));
    }
    Ok(out)
}

/// `validRestoreCapacityReserveFingerprint` — pins the exact shape this
/// resolver mints. Applied to every fingerprint that reaches a path
/// component, including ones read back out of protected records.
pub(crate) fn valid_fingerprint(fingerprint: &str) -> bool {
    if fingerprint.len() != FINGERPRINT_PREFIX.len() + FINGERPRINT_HEX_LEN {
        return false;
    }
    let Some(hex_part) = fingerprint.strip_prefix(FINGERPRINT_PREFIX) else {
        return false;
    };
    hex_part
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `RestoreCapacityReserveObjectName` — the single naming function.
/// Returns a *name*, never a path: the containing directory is only
/// ever reachable as a held descriptor.
///
/// # Errors
/// [`FP_INVALID`] when the fingerprint is not this resolver's shape.
pub(crate) fn object_name(fingerprint: &str) -> Result<String, Failure> {
    if !valid_fingerprint(fingerprint) {
        return Err(fingerprint_invalid());
    }
    Ok(format!("{fingerprint}{OBJECT_SUFFIX}"))
}

/// `restoreCapacityReserveIsObjectName` — the inverse: recognizes a
/// name this resolver could have minted, and nothing else.
pub(crate) fn is_object_name(name: &str) -> bool {
    name.strip_suffix(OBJECT_SUFFIX)
        .is_some_and(valid_fingerprint)
}

/// `RestoreCapacityReserveDeviceStore` — a held descriptor on the
/// device-keyed reserve store directory beneath one role root's parent,
/// plus the `st_dev` every object in it must match. Every reserve
/// object is reached through it.
pub(crate) struct ReserveDeviceStore {
    fd: OwnedFd,
    st_dev: u64,
}

/// `OpenRestoreCapacityReserveDeviceStore` — resolve the
/// compile-time-fixed store directory *beside* `role_root`'s data
/// leaf (via the held descriptor's `..`, `RESOLVE_BENEATH`
/// deliberately absent there but `NO_SYMLINKS|NO_XDEV` kept), then
/// validate it. When `create` is set a missing directory is
/// `mkdirat`'d `0700` and re-resolved through the identical
/// `openat2` — a directory this process just created is validated
/// exactly as strictly as one it found.
///
/// # Errors
/// [`RESOLVE_REFUSED`] on any resolution failure; the named
/// store-stat refusals on assertion mismatches.
pub(crate) fn open_device_store<Fd: AsFd>(
    role_root: Fd,
    create: bool,
) -> Result<ReserveDeviceStore, Failure> {
    let root_stat = rustix::fs::fstat(&role_root)
        .map_err(|e| resolve_refused(format!("fstat role root: {e}")))?;
    if !FileType::from_raw_mode(root_stat.st_mode).is_dir() {
        return Err(assertion(
            STORE_NOT_DIR,
            "restore capacity reserve store is not a directory",
        ));
    }
    if root_stat.st_dev == 0 {
        return Err(assertion(
            STORE_DEVICE,
            "restore capacity reserve store is not on its role root's device",
        ));
    }

    // `restoreCapacityReserveOpenRoleParentDir` — `..` anchored to the
    // held descriptor, `NO_SYMLINKS|NO_XDEV` but no `BENEATH`.
    let parent = openat2::resolve_with(
        &role_root,
        Path::new(".."),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        ResolveFlags::NO_SYMLINKS.union(ResolveFlags::NO_XDEV),
    )
    .map_err(|e| resolve_refused(format!("resolve role parent: {e}")))?;

    let fd = match open_store_dir(&parent) {
        Ok(fd) => fd,
        Err(e) if create && e == Errno::NOENT => {
            // `mkdirat(parent, STORE_DIR_NAME, 0700)` then re-resolve
            // through the same `openat2` — never skipped.
            match rustix::fs::mkdirat(
                &parent,
                STORE_DIR_NAME,
                Mode::from_raw_mode(durable::PRIVATE_DIRECTORY_MODE),
            ) {
                Ok(()) | Err(Errno::EXIST) => {}
                Err(_) => {
                    return Err(resolve_refused("mkdir reserve store directory failed"));
                }
            }
            open_store_dir(&parent)
                .map_err(|e| resolve_refused(format!("re-resolve store dir: {e}")))?
        }
        Err(e) => return Err(resolve_refused(format!("resolve store dir: {e}"))),
    };

    let store_stat =
        rustix::fs::fstat(&fd).map_err(|e| resolve_refused(format!("fstat store dir: {e}")))?;
    check_store_stat(&store_stat, root_stat.st_dev)?;
    Ok(ReserveDeviceStore {
        fd,
        st_dev: root_stat.st_dev,
    })
}

impl ReserveDeviceStore {
    /// `StDev` — the device identity every object in this store must
    /// match, read from the held role-root descriptor at open.
    pub(crate) fn st_dev(&self) -> u64 {
        self.st_dev
    }

    /// `DirFD` — the held store-directory descriptor, exposed for the
    /// one operation this resolver cannot express as an object lookup:
    /// the sweep's enumeration.
    pub(crate) fn dir_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// `create` — mint this device's reserve object
    /// `O_CREAT|O_EXCL|O_NOFOLLOW` and run the four fstat assertions.
    /// Deliberately crate-private: nothing outside this package may
    /// mint a reserve object without the allocation path's allowlist,
    /// floor prechecks and host caps.
    pub(crate) fn create(&self, fingerprint: &str) -> Result<fs::File, Failure> {
        self.open_object(
            fingerprint,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW,
        )
    }

    /// `Open` — open an existing reserve object under the identical
    /// four fstat assertions. The admission gate's seam: the daemon
    /// opens the object itself rather than trusting a descriptor
    /// handoff it cannot distinguish from any root-owned file on the
    /// right device.
    pub(crate) fn open(&self, fingerprint: &str) -> Result<fs::File, Failure> {
        self.open_object(fingerprint, OFlags::RDONLY | OFlags::NOFOLLOW)
    }

    /// `Remove` — unlink a reserve object; used by allocation rollback
    /// and the sweep's release.
    pub(crate) fn remove(&self, fingerprint: &str) -> Result<(), Failure> {
        let name = object_name(fingerprint)?;
        match rustix::fs::unlinkat(&self.fd, name.as_str(), rustix::fs::AtFlags::empty()) {
            Ok(()) | Err(Errno::NOENT) => Ok(()),
            Err(e) => Err(Failure::internal(
                "broker_restore_reserve_remove_os",
                format!("broker: remove restore capacity reserve object: {e}"),
            )),
        }
    }

    /// `objectCount` — the census of reserve objects already present in
    /// this store directory, whoever created them; the host caps count
    /// objects with a *different* fingerprint already sitting here
    /// (stale leftovers from a device identity change). Counts by name
    /// only — never opens, mutates or removes.
    pub(crate) fn object_count(&self) -> Result<usize, Failure> {
        // A fresh open of "." rather than a dup: dup shares the file
        // description and its directory offset, so a second census on
        // the same store would report nothing.
        let fd = rustix::fs::openat(
            &self.fd,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| resolve_refused(format!("open store dir for census: {e}")))?;
        let dir = rustix::fs::Dir::read_from(&fd)
            .map_err(|e| resolve_refused(format!("read store dir: {e}")))?;
        let mut count = 0usize;
        for entry in dir {
            let entry = entry.map_err(|e| resolve_refused(format!("read store dir entry: {e}")))?;
            let name = entry.file_name().to_string_lossy();
            if is_object_name(&name) {
                count += 1;
            }
        }
        Ok(count)
    }

    /// `openObject` — resolve `name` under [`RESOLVE_FLAGS`], then the
    /// four fstat assertions. `openat2(2)` refuses a non-zero mode
    /// unless `O_CREAT|O_TMPFILE` is set — the mode goes in only on the
    /// create flags, matching upstream's documented discipline.
    fn open_object(&self, fingerprint: &str, flags: OFlags) -> Result<fs::File, Failure> {
        let name = object_name(fingerprint)?;
        let create = flags.contains(OFlags::CREATE) || flags.contains(OFlags::TMPFILE);
        let fd = if create {
            openat2::resolve_with_mode(
                &self.fd,
                Path::new(&name),
                flags,
                Mode::from_raw_mode(durable::PRIVATE_FILE_MODE),
                RESOLVE_FLAGS,
            )
        } else {
            openat2::resolve_with(&self.fd, Path::new(&name), flags, RESOLVE_FLAGS)
        };
        let fd = match fd {
            Ok(fd) => fd,
            // `EEXIST`/`ENOENT` carry their own codes — the create and
            // open callers discriminate them exactly as upstream
            // discriminates the bare errnos; every other refusal keeps
            // the errno in the message so a substitution test can tell
            // `ELOOP` from `EXDEV`.
            Err(e @ (Errno::EXIST | Errno::NOENT)) => {
                return Err(Failure::denied(
                    if e == Errno::EXIST {
                        OBJECT_EXISTS
                    } else {
                        OBJECT_ABSENT
                    },
                    format!("broker: resolve reserve object: {e}"),
                ));
            }
            Err(e) => {
                return Err(resolve_refused(format!(
                    "broker: restore capacity reserve store could not be resolved from the held descriptor: {e}"
                )));
            }
        };
        // A create that got this far made the object (`O_EXCL`), so an
        // assertion failure must take it back out — a refused create
        // may not orphan bytes the caller was told do not exist. An
        // *open* that fails must never unlink: the file it found is by
        // definition not ours.
        let stat = match rustix::fs::fstat(&fd) {
            Ok(stat) => stat,
            Err(e) => {
                drop(fd);
                if create {
                    let _ =
                        rustix::fs::unlinkat(&self.fd, name.as_str(), rustix::fs::AtFlags::empty());
                }
                return Err(resolve_refused(format!("fstat reserve object: {e}")));
            }
        };
        if let Err(e) = check_object_stat(&stat, self.st_dev) {
            drop(fd);
            if create {
                let _ = rustix::fs::unlinkat(&self.fd, name.as_str(), rustix::fs::AtFlags::empty());
            }
            return Err(e);
        }
        Ok(fs::File::from(fd))
    }
}

/// `restoreCapacityReserveOpenStoreDir` — `openat2` the store directory
/// beneath the held role-parent descriptor.
fn open_store_dir<Fd: AsFd>(parent: Fd) -> Result<OwnedFd, Errno> {
    openat2::resolve_with(
        parent,
        Path::new(STORE_DIR_NAME),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        RESOLVE_FLAGS,
    )
}

/// `checkRestoreCapacityReserveStoreStat` — fixed evaluation order:
/// shape, then device identity, then ownership, then mode.
fn check_store_stat(stat: &rustix::fs::Stat, want_dev: u64) -> Result<(), Failure> {
    if !FileType::from_raw_mode(stat.st_mode).is_dir() {
        return Err(assertion(
            STORE_NOT_DIR,
            "restore capacity reserve store is not a directory",
        ));
    }
    if want_dev == 0 || stat.st_dev != want_dev {
        return Err(assertion(
            STORE_DEVICE,
            "restore capacity reserve store is not on its role root's device",
        ));
    }
    if stat.st_uid != 0 || stat.st_gid != 0 {
        return Err(assertion(
            STORE_OWNER,
            "restore capacity reserve store is not owned by root",
        ));
    }
    if stat.st_mode & 0o777 != durable::PRIVATE_DIRECTORY_MODE {
        return Err(assertion(
            STORE_MODE,
            "restore capacity reserve store is not mode 0700",
        ));
    }
    Ok(())
}

/// `checkRestoreCapacityReserveObjectStat` — the reserve object's four
/// assertions against the *held descriptor*: regular file, `st_dev`,
/// `st_uid`/`st_gid`, `st_nlink` — fixed order so a substitution test
/// can prove which one refused.
fn check_object_stat(stat: &rustix::fs::Stat, want_dev: u64) -> Result<(), Failure> {
    if !FileType::from_raw_mode(stat.st_mode).is_file() {
        return Err(assertion(
            OBJECT_NOT_REGULAR,
            "restore capacity reserve object is not a regular file",
        ));
    }
    if want_dev == 0 || stat.st_dev != want_dev {
        return Err(assertion(
            OBJECT_DEVICE,
            "restore capacity reserve object is not on its role root's device",
        ));
    }
    if stat.st_uid != 0 || stat.st_gid != 0 {
        return Err(assertion(
            OBJECT_OWNER,
            "restore capacity reserve object is not owned by root",
        ));
    }
    if stat.st_nlink != 1 {
        return Err(assertion(
            OBJECT_LINKS,
            "restore capacity reserve object has more than one link",
        ));
    }
    Ok(())
}

/// `fstatfs` availability bytes at the held descriptor — the
/// measurement behind `ObservedFreeBytes` (`f_bavail * f_bsize`).
#[allow(dead_code)] // fstatfs free-bytes reading for the helper-side measurement
pub(crate) fn available_bytes<Fd: AsFd>(fd: Fd) -> Result<u64, Failure> {
    let s = rustix::fs::fstatfs(fd).map_err(|e| {
        Failure::internal(
            "broker_restore_reserve_os",
            format!("broker: fstatfs reserve root: {e}"),
        )
    })?;
    Ok(s.f_bavail
        .saturating_mul(u64::try_from(s.f_bsize).unwrap_or(0)))
}

#[cfg(test)]
mod tests {
    //! `restore_capacity_reserve_store_path_guard_linux_test.go` plus
    //! the resolver's own unit surface: the source-text guard is a
    //! structural property only a file scan can see; the stat
    //! assertions are exercised on crafted `Stat` values (the
    //! behavioural substitutions that need real root-owned trees are
    //! the root-variant suite in `allocation`'s root tests).

    use super::*;

    /// `TestRestoreCapacityReserveStoreDirNameIsReferencedOnlyByItsResolver` —
    /// the compile-time-fixed name may be spelled out by this file
    /// alone; every other file reaches the directory through a
    /// descriptor or through [`ReserveDeviceStore::dir_fd`]. A
    /// behaviour test cannot see a future bypass — a source scan of
    /// the package's own files can.
    #[test]
    fn store_dir_name_is_referenced_only_by_its_resolver() {
        let identifier = "STORE_DIR_NAME";
        let literal = STORE_DIR_NAME;
        let package = concat!(env!("CARGO_MANIFEST_DIR"), "/src/broker");
        let mut files = Vec::new();
        let mut stack = vec![std::path::PathBuf::from(package)];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    files.push(path);
                }
            }
        }
        let mut checked = 0usize;
        for path in &files {
            let text = std::fs::read_to_string(path).unwrap();
            // The tests inside this file name both the identifier and
            // the literal legitimately; a file's *impl* half (before
            // `#[cfg(test)]`) is what the guard judges.
            let implementation = text.split("#[cfg(test)]").next().unwrap();
            if path.file_name().unwrap() == "store_path.rs" {
                assert!(
                    implementation.contains(identifier),
                    "store_path.rs no longer defines {identifier}; the guard is stale",
                );
                continue;
            }
            checked += 1;
            assert!(
                !implementation.contains(identifier),
                "{} names {identifier} — the store directory is the resolver's alone to name; re-deriving it is the duplication this guard exists to prevent",
                path.display(),
            );
            assert!(
                !implementation.contains(literal),
                "{} spells the store directory's literal value ({literal:?}) — equivalent to naming the constant; store_path.rs is the only file allowed to spell it out",
                path.display(),
            );
        }
        assert!(checked > 0, "guard checked no files");
    }

    #[test]
    fn device_fingerprint_shape_and_zero_refusal() {
        // Zero f_fsid is not an identity — several filesystems report
        // it — so it is refused outright.
        let err = device_fingerprint(0).unwrap_err();
        assert_eq!(err.code(), FP_INVALID);

        // A nonzero fsid mints `fs-` + 32 lowercase hex of the first
        // 16 sha256 bytes over val[0] LE || val[1] LE — byte-identical
        // with `opaqueFilesystemID`.
        let fingerprint = device_fingerprint(0x0102_0304_0506_0708u64).unwrap();
        assert!(valid_fingerprint(&fingerprint));
        assert!(fingerprint.starts_with("fs-"));
        assert_eq!(fingerprint.len(), 3 + 32);
        let mut payload = [0u8; 8];
        payload[..4].copy_from_slice(&0x0102_0304u32.to_le_bytes());
        payload[4..].copy_from_slice(&0x0506_0708u32.to_le_bytes());
        let digest = Sha256::digest(payload);
        let mut expected = String::from("fs-");
        for b in &digest[..16] {
            expected.push_str(&format!("{b:02x}"));
        }
        assert_eq!(fingerprint, expected);
    }

    #[test]
    fn fingerprint_shape_gate() {
        for bad in [
            "",
            "fs-",
            "fs-0123",                              // short
            "fs-0123456789abcdef0123456789abcdefZ", // wrong char
            "fs-0123456789ABCDEF0123456789abcdef",  // uppercase
            "xx-0123456789abcdef0123456789abcdef",  // wrong prefix
            "fs-0123456789abcdef0123456789abcdef0", // long
        ] {
            assert!(!valid_fingerprint(bad), "{bad:?} must not validate");
            assert!(object_name(bad).is_err());
        }
        let good = "fs-0123456789abcdef0123456789abcdef";
        assert!(valid_fingerprint(good));
    }

    #[test]
    fn object_name_round_trip() {
        let fingerprint = "fs-0123456789abcdef0123456789abcdef";
        let name = object_name(fingerprint).unwrap();
        assert_eq!(name, format!("{fingerprint}.reserve"));
        assert!(is_object_name(&name));
        // The inverse accepts nothing the resolver could not have minted.
        for bad in [
            "anything.txt",
            "fs-0123456789abcdef0123456789abcdef", // no suffix
            "fs-0123456789abcdef0123456789abcdeg.reserve", // bad char
            "fs-short.reserve",
            ".reserve",
            "fs-0123456789abcdef0123456789abcdef.reserve.extra",
        ] {
            assert!(
                !is_object_name(bad),
                "{bad:?} must not parse as an object name"
            );
        }
    }

    /// A `Stat` carrying exactly the fields the assertions read,
    /// seeded off a real temp file so every field is valid.
    fn stat(mode: u32, dev: u64, uid: u32, gid: u32, nlink: u64) -> rustix::fs::Stat {
        let seed = std::env::temp_dir().join(format!(
            "central-stat-seed-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&seed, b"x").unwrap();
        let mut s = rustix::fs::stat(&seed).unwrap();
        let _ = std::fs::remove_file(&seed);
        s.st_mode = mode;
        s.st_dev = dev;
        s.st_uid = uid;
        s.st_gid = gid;
        s.st_nlink = nlink;
        s
    }

    #[test]
    fn store_stat_assertion_order() {
        // Fixed order — shape, device, owner, mode — so a substitution
        // test can prove *which* assertion fired.
        let good = stat(libc::S_IFDIR | 0o700, 0xBEEF, 0, 0, 1);
        assert!(check_store_stat(&good, 0xBEEF).is_ok());

        let not_dir = stat(libc::S_IFREG | 0o700, 0xBEEF, 0, 0, 1);
        assert_eq!(
            check_store_stat(&not_dir, 0xBEEF).unwrap_err().code(),
            STORE_NOT_DIR
        );
        // Device wins over owner/mode: a wrong-device store refuses as
        // device even with otherwise-perfect metadata.
        let wrong_dev = stat(libc::S_IFDIR | 0o777, 0xDEAD, 99, 99, 2);
        assert_eq!(
            check_store_stat(&wrong_dev, 0xBEEF).unwrap_err().code(),
            STORE_DEVICE
        );
        // wantDev 0 is itself a refusal — never a wildcard match.
        assert_eq!(check_store_stat(&good, 0).unwrap_err().code(), STORE_DEVICE);
        let wrong_owner = stat(libc::S_IFDIR | 0o700, 0xBEEF, 1000, 0, 1);
        assert_eq!(
            check_store_stat(&wrong_owner, 0xBEEF).unwrap_err().code(),
            STORE_OWNER
        );
        let wrong_mode = stat(libc::S_IFDIR | 0o755, 0xBEEF, 0, 0, 1);
        assert_eq!(
            check_store_stat(&wrong_mode, 0xBEEF).unwrap_err().code(),
            STORE_MODE
        );
    }

    #[test]
    fn object_stat_assertion_order() {
        // Fixed order — regular file, st_dev, owner, nlink.
        let good = stat(libc::S_IFREG | 0o600, 0xBEEF, 0, 0, 1);
        assert!(check_object_stat(&good, 0xBEEF).is_ok());

        let dir = stat(libc::S_IFDIR | 0o700, 0xBEEF, 0, 0, 1);
        assert_eq!(
            check_object_stat(&dir, 0xBEEF).unwrap_err().code(),
            OBJECT_NOT_REGULAR
        );
        let wrong_dev = stat(libc::S_IFREG | 0o600, 0xDEAD, 99, 99, 2);
        assert_eq!(
            check_object_stat(&wrong_dev, 0xBEEF).unwrap_err().code(),
            OBJECT_DEVICE
        );
        assert_eq!(
            check_object_stat(&good, 0).unwrap_err().code(),
            OBJECT_DEVICE
        );
        let wrong_owner = stat(libc::S_IFREG | 0o600, 0xBEEF, 1000, 0, 1);
        assert_eq!(
            check_object_stat(&wrong_owner, 0xBEEF).unwrap_err().code(),
            OBJECT_OWNER
        );
        let hardlinked = stat(libc::S_IFREG | 0o600, 0xBEEF, 0, 0, 2);
        assert_eq!(
            check_object_stat(&hardlinked, 0xBEEF).unwrap_err().code(),
            OBJECT_LINKS
        );
    }
}
