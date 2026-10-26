//! `central-migrate` OS boundary — the audited descriptor and identity
//! syscalls the operator needs (upstream `unix.*`/`os.Geteuid` sites in
//! `cmd/central-migrate/main.go`). Launcher-binary carve-out: the
//! `unsafe` blocks below are the audited `BorrowedFd::borrow_raw`/
//! `OwnedFd::from_raw_fd` sites for the fixed launch descriptors, the
//! same audited pattern `central-harness-launcherd/src/sys.rs` uses.

#![allow(unsafe_code)]

use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

use central_foundation::failure::Failure;

/// `launchEvidenceFD` — the native launcher's fixed launch-evidence
/// descriptor.
pub const LAUNCH_EVIDENCE_FD: RawFd = 3;
/// `credentialDescriptorFD` — the fixed credential handoff descriptor.
pub const CREDENTIAL_DESCRIPTOR_FD: RawFd = 4;

/// `authority.CentralMigrateUID`.
pub const CENTRAL_MIGRATE_UID: u32 = 986;
/// `authority.CentralMigrateGID`.
pub const CENTRAL_MIGRATE_GID: u32 = 986;

/// The UID/GID predicate behind the `must run as central-migrate`
/// gate — split out so tests can exercise the identity rule without
/// the process's own credentials.
#[must_use]
pub fn is_central_migrate_identity(uid: u32, gid: u32) -> bool {
    uid == CENTRAL_MIGRATE_UID && gid == CENTRAL_MIGRATE_GID
}

/// `os.Geteuid() == 986 && os.Getegid() == 986`.
#[must_use]
pub fn running_as_central_migrate() -> bool {
    is_central_migrate_identity(
        rustix::process::geteuid().as_raw(),
        rustix::process::getegid().as_raw(),
    )
}

/// `readLaunchEvidenceUUID` consumes the native launcher's fixed FD3
/// protocol: exactly one 16-byte UUID, no trailing byte, non-nil. The
/// parse is pure over the reader so tests drive it through `Cursor`
/// exactly like upstream's table test.
///
/// # Errors
/// Framing or UUID validation fails.
pub fn read_launch_evidence_uuid(mut r: impl Read) -> Result<uuid::Uuid, Failure> {
    let mut wire = [0u8; 16];
    r.read_exact(&mut wire).map_err(|e| {
        Failure::internal(
            "launch_evidence_read",
            format!("central-migrate: read launch evidence: {e}"),
        )
    })?;
    // One extra byte must be EOF — a trailing byte or a read error is
    // invalid framing, exactly as upstream.
    let mut extra = [0u8; 1];
    match r.read(&mut extra) {
        Ok(0) => {}
        _ => {
            return Err(Failure::internal(
                "launch_evidence_framing",
                "central-migrate: invalid launch evidence framing",
            ));
        }
    }
    let id = uuid::Uuid::from_bytes(wire);
    if id.is_nil() {
        return Err(Failure::internal(
            "launch_evidence_uuid",
            "central-migrate: invalid launch evidence UUID",
        ));
    }
    Ok(id)
}

/// Read the FD3 launch evidence. The descriptor is opened through
/// `/proc/self/fd/3` — a fresh handle on the same open file
/// description — so this process takes no ownership of the launcher's
/// descriptor and never touches `unsafe` for the read path.
///
/// # Errors
/// The descriptor is absent/unreadable, or the evidence fails the
/// fixed 16-byte framing.
pub fn read_launch_evidence() -> Result<uuid::Uuid, Failure> {
    let f = File::open(format!("/proc/self/fd/{LAUNCH_EVIDENCE_FD}")).map_err(|e| {
        Failure::internal(
            "launch_evidence_open",
            format!("central-migrate: read launch evidence: {e}"),
        )
    })?;
    read_launch_evidence_uuid(f)
}

/// The owned FD4 guard — reaps the credential descriptor on drop on
/// every path, exactly like upstream's `defer unix.Close(4)` (the
/// success-path consumer closes it itself upstream; the extra close
/// here is the same harmless EBADF).
pub struct CredentialDescriptor {
    fd: OwnedFd,
}

impl CredentialDescriptor {
    /// The descriptor number for the (task-2) materialization seam.
    #[must_use]
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl AsRawFd for CredentialDescriptor {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// `protect credential descriptor` — the launcher clears CLOEXEC on
/// FD4 so the credential memfd crosses exec into this fixed operator;
/// the operator reapplies it only now, after exec and before the
/// descriptor handoff, so no later exec can inherit credentials. Then
/// the descriptor is owned by the returned guard (the `defer close`).
///
/// # Errors
/// The `F_SETFD` fcntl fails or FD4 is absent.
pub fn protect_credential_descriptor() -> Result<CredentialDescriptor, Failure> {
    // SAFETY: FD4 is this process's fixed credential descriptor passed
    // across exec by the launcher; `borrow_raw` creates no ownership
    // and is used solely for the CLOEXEC fcntl — the audited borrow
    // pattern the launcher binaries use.
    let borrowed = unsafe { BorrowedFd::borrow_raw(CREDENTIAL_DESCRIPTOR_FD) };
    rustix::io::fcntl_setfd(borrowed, rustix::io::FdFlags::CLOEXEC).map_err(|e| {
        Failure::internal(
            "credential_descriptor_protect",
            format!("central-migrate: protect credential descriptor: {e}"),
        )
    })?;
    // SAFETY: FD4 is owned solely by this process after the launcher's
    // handoff; taking ownership here makes the guard's Drop the single
    // `defer unix.Close` — no other close touches it.
    let fd = unsafe { OwnedFd::from_raw_fd(CREDENTIAL_DESCRIPTOR_FD) };
    Ok(CredentialDescriptor { fd })
}
