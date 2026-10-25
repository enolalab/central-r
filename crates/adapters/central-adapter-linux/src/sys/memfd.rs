//! Sealed-`memfd` handoff descriptors — the port of upstream
//! `internal/adapter/authority/broker/handoff_linux.go`
//! (`HandoffService.Handoff`) and of the two descriptor-shape
//! validations the broker applies to descriptors moved by
//! [`crate::sys::scm_rights`]:
//!
//! - [`validate_sealed`] — `server.go`'s `validateProvisionedDescriptorFD`
//!   (the B10 inbound shape): a sealed, non-empty, peer-owned tmpfs file.
//! - [`validate_destination`] — `secret_bootstrap_transport_linux.go`'s
//!   `ReceiveDescriptor` fstat/fstatfs block (the B04/B05 inbound
//!   shape): a root-owned, empty, `0400`, unlinked tmpfs file the
//!   broker is about to write a secret into.
//!
//! `create_sealed` is `Handoff` verbatim: `memfd_create` with
//! `MFD_CLOEXEC|MFD_ALLOW_SEALING`, `fchmod(0600)` (upstream's
//! comment — a path-reopened consumer, e.g. a `/proc/self/fd/N`
//! passfile, fails its own group/world-readable rejection otherwise),
//! chunked write, `lseek` rewind, then `F_ADD_SEALS` with
//! `SEAL|SHRINK|GROW|WRITE` — the descriptor can be read but never
//! changed again.

use std::os::fd::{AsFd, OwnedFd};

use central_foundation::failure::Failure;
use rustix::fs::{
    MemfdFlags, Mode, SealFlags, SeekFrom, fchmod, fcntl_add_seals, fcntl_get_seals, fstat,
    fstatfs, memfd_create, seek,
};
use rustix::io::{Errno, write};
use rustix::process::Uid;

/// `secretbootstrap.MaxSecretBytes` — the broker's bound on every value
/// a handoff descriptor may carry.
pub const MAX_VALUE_BYTES: u64 = 64 * 1024;

/// The seals `create_sealed` applies — `F_SEAL_SEAL|SHRINK|GROW|WRITE`,
/// upstream's `handoff_linux.go:81`. With `SEAL` present the set can
/// never be widened; `SHRINK`/`GROW`/`WRITE` fix size and content.
pub const SEALED_MEMFD_SEALS: SealFlags = SealFlags::SEAL
    .union(SealFlags::SHRINK)
    .union(SealFlags::GROW)
    .union(SealFlags::WRITE);

/// `TMPFS_MAGIC` (`fstatfs.f_type` for a memfd).
const TMPFS_MAGIC: rustix::fs::FsWord = 0x0102_1994;

fn invalid(msg: impl Into<String>) -> Failure {
    Failure::invalid("sys_memfd_invalid", msg.into())
}

fn os_failure(step: &str, e: Errno) -> Failure {
    Failure::internal("sys_memfd_os", format!("{step}: {e}"))
}

fn denied(msg: impl Into<String>) -> Failure {
    Failure::denied("sys_memfd_denied", msg.into())
}

/// `Handoff` — a sealed memfd carrying `value`, ready for `SCM_RIGHTS`
/// delivery. Empty or oversized values refuse before the descriptor
/// exists (upstream `len(value) == 0 || > MaxSecretBytes`).
///
/// # Errors
/// `sys_memfd_invalid` when `value` is empty or exceeds
/// [`MAX_VALUE_BYTES`]; `sys_memfd_os` on any syscall failure.
pub fn create_sealed(name: &str, value: &[u8]) -> Result<OwnedFd, Failure> {
    if value.is_empty() || value.len() as u64 > MAX_VALUE_BYTES {
        return Err(invalid("handoff value is out of bounds"));
    }
    let fd = memfd_create(name, MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING)
        .map_err(|e| os_failure("memfd_create", e))?;
    let done = (|| -> Result<(), Failure> {
        fchmod(&fd, Mode::from_bits_retain(0o600)).map_err(|e| os_failure("fchmod", e))?;
        let mut offset = 0usize;
        while offset < value.len() {
            let end = (offset + 4096).min(value.len());
            match write(&fd, &value[offset..end]) {
                Err(Errno::INTR) => continue,
                Err(e) => return Err(os_failure("write", e)),
                Ok(0) => return Err(os_failure("write", Errno::IO)),
                Ok(n) => offset += n,
            }
        }
        seek(&fd, SeekFrom::Start(0)).map_err(|e| os_failure("seek", e))?;
        fcntl_add_seals(&fd, SEALED_MEMFD_SEALS).map_err(|e| os_failure("F_ADD_SEALS", e))?;
        Ok(())
    })();
    // `fd` drops (closes) on the error path — upstream's unix.Close.
    done.map(|()| fd)
}

/// `validateProvisionedDescriptorFD` — the sealed, non-empty,
/// peer-owned tmpfs shape: regular file, at most one link (a memfd is
/// unlinked, `nlink == 0`), owned by `expected_uid`, non-empty and
/// within [`MAX_VALUE_BYTES`], on tmpfs, and write-sealed so its
/// content cannot change after this check.
///
/// # Errors
/// `sys_memfd_denied` when the descriptor has the wrong shape;
/// `sys_memfd_os` when `fstat`/`fstatfs`/`F_GET_SEALS` itself fails.
pub fn validate_sealed(fd: impl AsFd, expected_uid: Uid) -> Result<(), Failure> {
    let fd = fd.as_fd();
    let st = fstat(fd).map_err(|e| os_failure("fstat", e))?;
    if !rustix::fs::FileType::from_raw_mode(st.st_mode).is_file() {
        return Err(denied(format!(
            "fd is not a regular file (mode={:o})",
            st.st_mode
        )));
    }
    if st.st_nlink > 1 {
        return Err(denied(format!(
            "invalid link count {}, expected at most 1",
            st.st_nlink
        )));
    }
    if st.st_uid != expected_uid.as_raw() {
        return Err(denied(format!(
            "fd is not owned by the expected peer (uid={})",
            st.st_uid
        )));
    }
    // Upstream rejects only `Size <= 0`; the `MAX_VALUE_BYTES` ceiling
    // is a deliberate strictness addition — a sealed descriptor
    // carrying more than `MaxSecretBytes` can never be a legitimate
    // payload, so refusing it here fail-closes a class of oversized
    // handoffs upstream leaves to the later payload-size check.
    if st.st_size <= 0 || st.st_size as u64 > MAX_VALUE_BYTES {
        return Err(denied("fd size is out of bounds"));
    }
    let fs = fstatfs(fd).map_err(|e| os_failure("fstatfs", e))?;
    if fs.f_type != TMPFS_MAGIC {
        return Err(denied(format!(
            "fd is not on tmpfs (type={:#x})",
            fs.f_type
        )));
    }
    let seals = fcntl_get_seals(fd).map_err(|e| os_failure("F_GET_SEALS", e))?;
    if !seals.contains(SealFlags::WRITE) {
        return Err(denied("fd is not write-sealed"));
    }
    Ok(())
}

/// `ReceiveDescriptor`'s post-recvmsg checks — the empty destination
/// shape a B04/B05 materialize transport sends inbound: regular file,
/// at most one link, owned by `owner` (production passes `Uid::ROOT`),
/// empty, `0400` (writable by owner only — the broker fills it), on
/// tmpfs.
///
/// # Errors
/// `sys_memfd_denied` when the descriptor has the wrong shape;
/// `sys_memfd_os` when `fstat`/`fstatfs` itself fails.
pub fn validate_destination(fd: impl AsFd, owner: Uid) -> Result<(), Failure> {
    let fd = fd.as_fd();
    let st = fstat(fd).map_err(|e| os_failure("fstat", e))?;
    if !rustix::fs::FileType::from_raw_mode(st.st_mode).is_file() {
        return Err(denied(format!(
            "fd is not a regular file (mode={:o})",
            st.st_mode
        )));
    }
    if st.st_nlink > 1 {
        return Err(denied(format!(
            "invalid link count {}, expected at most 1",
            st.st_nlink
        )));
    }
    if st.st_uid != owner.as_raw() {
        return Err(denied(format!("fd is not owner-owned (uid={})", st.st_uid)));
    }
    if st.st_size != 0 {
        return Err(denied(format!("fd is not empty (size={})", st.st_size)));
    }
    if st.st_mode & 0o777 != 0o400 {
        return Err(denied(format!(
            "fd mode {:o} is not restrictive (want 0400)",
            st.st_mode & 0o777
        )));
    }
    let fs = fstatfs(fd).map_err(|e| os_failure("fstatfs", e))?;
    if fs.f_type != TMPFS_MAGIC {
        return Err(denied(format!(
            "fd is not on tmpfs (type={:#x})",
            fs.f_type
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::path::Path;

    /// `Handoff`'s round trip: the descriptor reads back exactly the
    /// value, at offset 0, and `F_GET_SEALS` reports the full set.
    #[test]
    fn sealed_round_trip() {
        let value = b"secret-material";
        let fd = create_sealed("central-test", value).expect("sealed memfd");
        let seals = fcntl_get_seals(&fd).expect("F_GET_SEALS");
        assert_eq!(seals, SEALED_MEMFD_SEALS);
        let mut file = std::fs::File::from(fd);
        let mut got = Vec::new();
        file.read_to_end(&mut got).expect("read back");
        assert_eq!(got, value);
    }

    /// `validate_sealed` accepts the shape `create_sealed` produces
    /// for this process's uid.
    #[test]
    fn validate_sealed_accepts_handoff_shape() {
        let fd = create_sealed("central-test", b"value").expect("sealed memfd");
        validate_sealed(&fd, rustix::process::geteuid()).expect("valid shape");
    }

    /// `F_SEAL_WRITE` makes the content immutable after handoff — a
    /// write to the sealed descriptor is `EPERM`.
    #[test]
    fn sealed_memfd_refuses_write() {
        let fd = create_sealed("central-test", b"value").expect("sealed memfd");
        assert_eq!(write(&fd, b"x").unwrap_err(), Errno::PERM);
        // ftruncate is blocked by F_SEAL_SHRINK/F_SEAL_GROW too.
        assert_eq!(rustix::fs::ftruncate(&fd, 0).unwrap_err(), Errno::PERM);
    }

    /// An unsealed memfd fails the write-seal check — upstream's
    /// `fd is not write-sealed`.
    #[test]
    fn validate_sealed_rejects_unsealed() {
        let fd = memfd_create(
            "central-test",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
        )
        .expect("memfd");
        write(&fd, b"value").expect("write");
        let err = validate_sealed(&fd, rustix::process::geteuid()).unwrap_err();
        assert_eq!(err.code(), "sys_memfd_denied");
        assert!(err.message().contains("write-sealed"));
    }

    /// An empty memfd fails the non-empty check.
    #[test]
    fn validate_sealed_rejects_empty() {
        let fd = memfd_create(
            "central-test",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
        )
        .expect("memfd");
        let err = validate_sealed(&fd, rustix::process::geteuid()).unwrap_err();
        assert_eq!(err.code(), "sys_memfd_denied");
        assert!(err.message().contains("out of bounds"));
    }

    /// A wrong peer uid is a denial — upstream's `fd is not owned by
    /// the expected peer`.
    #[test]
    fn validate_sealed_rejects_wrong_uid() {
        let fd = create_sealed("central-test", b"value").expect("sealed memfd");
        let other = if rustix::process::geteuid().as_raw() == 0 {
            Uid::from_raw(1)
        } else {
            Uid::ROOT
        };
        let err = validate_sealed(&fd, other).unwrap_err();
        assert_eq!(err.code(), "sys_memfd_denied");
        assert!(err.message().contains("expected peer"));
    }

    /// A regular file on a real filesystem fails the tmpfs check —
    /// the descriptor must be a memfd, not something opened off disk.
    /// The file lives under the crate's manifest dir: `/tmp` is tmpfs
    /// on the reference host, which would pass the `f_type` check and
    /// make the test exercise the write-seal branch instead.
    #[test]
    fn validate_sealed_rejects_non_tmpfs() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("central-sys-memfd-nontmpfs-{}", std::process::id()));
        std::fs::write(&path, b"value").expect("seed file");
        let fd = rustix::fs::open(
            path.as_os_str(),
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open file");
        let err = validate_sealed(&fd, rustix::process::geteuid()).unwrap_err();
        let _ = std::fs::remove_file(&path);
        assert_eq!(err.code(), "sys_memfd_denied");
        assert!(
            err.message().contains("tmpfs"),
            "unexpected refusal: {}",
            err.message()
        );
    }

    /// The B04 destination shape: empty, `0400`, owner-matching
    /// memfd — accepted; a seeded (non-empty) one denied.
    #[test]
    fn validate_destination_accepts_empty_0400() {
        let fd = memfd_create(
            "central-test",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
        )
        .expect("memfd");
        fchmod(&fd, Mode::from_bits_retain(0o400)).expect("fchmod");
        validate_destination(&fd, rustix::process::geteuid()).expect("destination shape");

        let seeded = memfd_create(
            "central-test",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
        )
        .expect("memfd");
        fchmod(&seeded, Mode::from_bits_retain(0o400)).expect("fchmod");
        write(&seeded, b"x").expect("write");
        let err = validate_destination(&seeded, rustix::process::geteuid()).unwrap_err();
        assert!(err.message().contains("not empty"));
    }

    /// `0600` instead of `0400` is wider than the transport admits.
    #[test]
    fn validate_destination_rejects_wide_mode() {
        let fd = memfd_create(
            "central-test",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
        )
        .expect("memfd");
        // memfd_create's default mode is 0777&~umask — set the exact
        // transport-wrong mode.
        fchmod(&fd, Mode::from_bits_retain(0o600)).expect("fchmod");
        let err = validate_destination(&fd, rustix::process::geteuid()).unwrap_err();
        assert!(err.message().contains("not restrictive"));
    }

    /// `create_sealed` refuses out-of-bounds values before the
    /// descriptor exists — upstream's `len(value)==0 || >MaxSecretBytes`.
    #[test]
    fn create_sealed_bounds() {
        assert_eq!(
            create_sealed("central-test", b"").unwrap_err().code(),
            "sys_memfd_invalid"
        );
        let big = vec![0u8; (MAX_VALUE_BYTES + 1) as usize];
        assert_eq!(
            create_sealed("central-test", &big).unwrap_err().code(),
            "sys_memfd_invalid"
        );
        // The exact boundary is admitted.
        let edge = vec![7u8; MAX_VALUE_BYTES as usize];
        let fd = create_sealed("central-test", &edge).expect("64KiB boundary");
        let st = fstat(&fd).expect("fstat");
        assert_eq!(st.st_size as u64, MAX_VALUE_BYTES);
    }
}
