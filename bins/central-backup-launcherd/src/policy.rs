//! Admission policy — upstream `main.c`'s permit custody
//! (`inspect_permit_file`/`initialize_permits`/`acquire_permits`/
//! `close_permits`), the `validate_repository_fd` launch-descriptor
//! shape check, and the `valid_retained_target_socket` gate the
//! monitor applies to the worker's handed-off target lock.
//!
//! The permit gate works in two phases exactly like upstream:
//!
//! - **initialize** at daemon start: each permit path is opened
//!   (`O_RDWR|O_CLOEXEC|O_NOFOLLOW`), shape-checked (regular file,
//!   expected owner, mode exactly `0600` under mask `07777`, single
//!   link), its `(dev, ino)` recorded, and closed again. The two
//!   permits must be distinct inodes. A failed initialize refuses the
//!   daemon's whole start.
//! - **acquire** per launch: both files are re-opened and must still
//!   validate *and* still name the recorded `(dev, ino)` — a permit
//!   swapped out from under the daemon denies the launch. Each open
//!   descriptor is then `flock(LOCK_EX|LOCK_NB)`ed and handed to the
//!   launch record, which holds the locks for the launch's whole
//!   life — committed or not — until the record completes or clears.
//!
//! The monitor child never keeps them: `close_permits_in_child` drops
//! the pair before the fixed-fd shuffles, and a launcher crash closes
//! the parent-held descriptors, which is the revoke.

use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};

use rustix::fs::{FlockOperation, Mode, OFlags, flock};

use crate::sys;

/// A permit's `(dev, ino)` identity captured at initialize.
#[derive(Debug, Clone, Copy)]
struct PermitIdentity {
    dev: u64,
    ino: u64,
}

fn check_shape(st: &rustix::fs::Stat, uid: u32, gid: u32) -> Result<(), String> {
    if st.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err("not a regular file".to_owned());
    }
    if st.st_uid != uid || st.st_gid != gid {
        return Err(format!(
            "owner {}:{} expected {uid}:{gid}",
            st.st_uid, st.st_gid
        ));
    }
    // Upstream masks with 07777 — setuid/setgid/sticky bits refuse too.
    if st.st_mode & 0o7777 != 0o600 {
        return Err(format!("mode {:o} expected 600", st.st_mode & 0o7777));
    }
    if st.st_nlink != 1 {
        return Err(format!("nlink {} expected 1", st.st_nlink));
    }
    Ok(())
}

fn open_permit(path: &str, uid: u32, gid: u32) -> Result<(OwnedFd, PermitIdentity), String> {
    let fd = rustix::fs::open(
        path,
        OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|e| format!("permits: open {path}: {e}"))?;
    let st = rustix::fs::fstat(&fd).map_err(|e| format!("permits: fstat {path}: {e}"))?;
    check_shape(&st, uid, gid).map_err(|why| format!("permits: {path}: {why}"))?;
    Ok((
        fd,
        PermitIdentity {
            dev: st.st_dev,
            ino: st.st_ino,
        },
    ))
}

/// `initialize_permits` + `acquire_permits`'s expected-identity pair.
pub struct PermitGate {
    paths: [String; 2],
    uid: u32,
    gid: u32,
    identity: [PermitIdentity; 2],
}

impl PermitGate {
    /// `initialize_permits` — inspect both files, record their
    /// `(dev, ino)`, require distinctness; failure ends startup.
    pub fn initialize(paths: [String; 2], uid: u32, gid: u32) -> Result<Self, String> {
        let mut identity = [PermitIdentity { dev: 0, ino: 0 }; 2];
        for (i, path) in paths.iter().enumerate() {
            let (fd, id) = open_permit(path, uid, gid)?;
            identity[i] = id;
            drop(fd);
        }
        if identity[0].dev == identity[1].dev && identity[0].ino == identity[1].ino {
            return Err("permits: both paths name the same file".to_owned());
        }
        Ok(Self {
            paths,
            uid,
            gid,
            identity,
        })
    }

    /// `acquire_permits` — re-open both, re-validate shape and the
    /// recorded identity, take the exclusive non-blocking flock on
    /// each. Any failure releases whatever was taken.
    pub fn acquire(&self) -> Result<PermitHold, String> {
        let mut fds: Vec<OwnedFd> = Vec::with_capacity(2);
        for (i, path) in self.paths.iter().enumerate() {
            let (fd, id) = open_permit(path, self.uid, self.gid)?;
            if id.dev != self.identity[i].dev || id.ino != self.identity[i].ino {
                return Err(format!("permits: {path}: identity changed"));
            }
            flock(&fd, FlockOperation::NonBlockingLockExclusive)
                .map_err(|e| format!("permits: lock {path}: {e}"))?;
            fds.push(fd);
        }
        let mut it = fds.into_iter();
        let (Some(a), Some(b)) = (it.next(), it.next()) else {
            return Err("permits: short acquire".to_owned());
        };
        Ok(PermitHold { a, b })
    }
}

/// The pair a launch record holds for the launch's whole life —
/// upstream `release_record_permits` is the `Drop`.
pub struct PermitHold {
    a: OwnedFd,
    b: OwnedFd,
}

impl PermitHold {
    /// The raw descriptors — the forked monitor closes both before the
    /// fixed-fd shuffles (`close_permits_in_child`). Closing the child's
    /// inherited copy does not release the lock: flock state lives on
    /// the open file description the daemon's copies still hold.
    pub fn raw_fds(&self) -> (RawFd, RawFd) {
        (self.a.as_fd().as_raw_fd(), self.b.as_fd().as_raw_fd())
    }
}

impl Drop for PermitHold {
    /// `close_permits` — `flock LOCK_UN` then close (close alone
    /// would release the lock; upstream unlocks explicitly).
    fn drop(&mut self) {
        let _ = flock(&self.a, FlockOperation::Unlock);
        let _ = flock(&self.b, FlockOperation::Unlock);
    }
}

/// `validate_repository_fd` — the single descriptor a launch carries
/// must be a `BACKUP_UID:BACKUP_GID`-owned, not-group/other-writable,
/// `O_RDONLY` (not `O_PATH`) directory.
pub fn validate_repository_fd<Fd: AsFd>(fd: Fd, uid: u32, gid: u32) -> Result<(), String> {
    let st = rustix::fs::fstat(&fd).map_err(|e| format!("repository: fstat: {e}"))?;
    if st.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err("repository: not a directory".to_owned());
    }
    if st.st_uid != uid || st.st_gid != gid {
        return Err(format!(
            "repository: owner {}:{} expected {uid}:{gid}",
            st.st_uid, st.st_gid
        ));
    }
    if st.st_mode & (libc::S_IWGRP | libc::S_IWOTH) != 0 {
        return Err("repository: group/other writable".to_owned());
    }
    let flags =
        sys::getfl(fd.as_fd().as_raw_fd()).map_err(|e| format!("repository: getfl: {e}"))?;
    let oflags = OFlags::from_bits_retain(flags as u32);
    // Upstream: `(flags & O_ACCMODE) != O_RDONLY || (flags & O_PATH)`.
    if oflags.intersection(OFlags::ACCMODE) != OFlags::RDONLY || oflags.contains(OFlags::PATH) {
        return Err("repository: not O_RDONLY / O_PATH".to_owned());
    }
    Ok(())
}

/// `valid_retained_target_socket` — the worker's handed-off target
/// lock must be a `FD_CLOEXEC` `SOCK_STREAM` socket with no pending
/// error, bound on loopback, and connected to `127.0.0.1:55432`.
pub fn valid_retained_target_socket<Fd: AsFd>(fd: Fd, peer_port: u16) -> bool {
    let Ok(flags) = rustix::io::fcntl_getfd(&fd) else {
        return false;
    };
    if !flags.contains(rustix::io::FdFlags::CLOEXEC) {
        return false;
    }
    let Ok(ty) = rustix::net::sockopt::socket_type(&fd) else {
        return false;
    };
    if ty != rustix::net::SocketType::STREAM {
        return false;
    }
    let Ok(soerr) = rustix::net::sockopt::socket_error(&fd) else {
        return false;
    };
    if soerr.is_err() {
        return false;
    }
    let Ok(local) = rustix::net::getsockname(&fd) else {
        return false;
    };
    let Ok(local4) = std::net::SocketAddrV4::try_from(local) else {
        return false;
    };
    if *local4.ip() != std::net::Ipv4Addr::LOCALHOST {
        return false;
    }
    let Ok(Some(peer)) = rustix::net::getpeername(&fd) else {
        return false;
    };
    let Ok(peer4) = std::net::SocketAddrV4::try_from(peer) else {
        return false;
    };
    peer4.port() == peer_port && *peer4.ip() == std::net::Ipv4Addr::LOCALHOST
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn uid() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    fn gid() -> u32 {
        rustix::process::getegid().as_raw()
    }

    fn dir(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "cbl-policy-{}-{}-{name}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn permit(path: &std::path::Path, mode: u32) {
        std::fs::write(path, b"permit\n").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn gate(base: &std::path::Path) -> PermitGate {
        PermitGate::initialize(
            [
                base.join("a.lock").display().to_string(),
                base.join("b.lock").display().to_string(),
            ],
            uid(),
            gid(),
        )
        .unwrap()
    }

    fn two_permits(base: &std::path::Path) {
        permit(&base.join("a.lock"), 0o600);
        permit(&base.join("b.lock"), 0o600);
    }

    #[test]
    fn permits_initialize_and_acquire() {
        let base = dir("permits");
        two_permits(&base);
        let gate = gate(&base);
        // A held pair locks a second acquisition out — the launch
        // serialization upstream's flock pair enforces.
        let hold = gate.acquire().unwrap();
        assert!(gate.acquire().is_err());
        drop(hold);
        assert!(gate.acquire().is_ok());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn permits_reject_bad_shapes() {
        // Missing file.
        let base = dir("missing");
        permit(&base.join("a.lock"), 0o600);
        assert!(
            PermitGate::initialize(
                [
                    base.join("a.lock").display().to_string(),
                    base.join("b.lock").display().to_string(),
                ],
                uid(),
                gid(),
            )
            .is_err()
        );
        // Wrong mode.
        let base = dir("mode");
        permit(&base.join("a.lock"), 0o600);
        permit(&base.join("b.lock"), 0o644);
        assert!(
            PermitGate::initialize(
                [
                    base.join("a.lock").display().to_string(),
                    base.join("b.lock").display().to_string(),
                ],
                uid(),
                gid(),
            )
            .is_err()
        );
        // Wrong owner.
        assert!(
            PermitGate::initialize(
                [
                    base.join("a.lock").display().to_string(),
                    base.join("a.lock").display().to_string(),
                ],
                uid() + 1,
                gid(),
            )
            .is_err()
        );
        // Both paths the same file → not distinct.
        let base = dir("same");
        permit(&base.join("a.lock"), 0o600);
        assert!(
            PermitGate::initialize(
                [
                    base.join("a.lock").display().to_string(),
                    base.join("a.lock").display().to_string(),
                ],
                uid(),
                gid(),
            )
            .is_err()
        );
        // A hardlinked permit fails nlink.
        let base = dir("hardlink");
        two_permits(&base);
        std::fs::hard_link(base.join("a.lock"), base.join("a.extra")).unwrap();
        assert!(
            PermitGate::initialize(
                [
                    base.join("a.lock").display().to_string(),
                    base.join("b.lock").display().to_string(),
                ],
                uid(),
                gid(),
            )
            .is_err()
        );
        // A symlinked permit fails O_NOFOLLOW at open.
        let base = dir("symlink");
        two_permits(&base);
        std::fs::remove_file(base.join("a.lock")).unwrap();
        std::os::unix::fs::symlink(base.join("b.lock"), base.join("a.lock")).unwrap();
        assert!(
            PermitGate::initialize(
                [
                    base.join("a.lock").display().to_string(),
                    base.join("b.lock").display().to_string(),
                ],
                uid(),
                gid(),
            )
            .is_err()
        );
    }

    #[test]
    fn permits_reject_identity_swap() {
        let base = dir("swap");
        two_permits(&base);
        let gate = gate(&base);
        // Replacing a permit file under the same name fails the
        // recorded (dev, ino) identity at acquire.
        std::fs::remove_file(base.join("a.lock")).unwrap();
        permit(&base.join("a.lock"), 0o600);
        assert!(gate.acquire().is_err());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn repository_fd_shape() {
        let base = dir("repo");
        std::fs::create_dir(base.join("good")).unwrap();
        std::fs::set_permissions(base.join("good"), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let good = rustix::fs::open(
            base.join("good"),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        assert!(validate_repository_fd(&good, uid(), gid()).is_ok());
        // A regular file is not a directory.
        std::fs::write(base.join("file"), b"x").unwrap();
        let regular = rustix::fs::open(
            base.join("file"),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        assert!(validate_repository_fd(&regular, uid(), gid()).is_err());
        // Group-writable fails.
        std::fs::create_dir(base.join("groupw")).unwrap();
        std::fs::set_permissions(base.join("groupw"), std::fs::Permissions::from_mode(0o770))
            .unwrap();
        let groupw = rustix::fs::open(
            base.join("groupw"),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        assert!(validate_repository_fd(&groupw, uid(), gid()).is_err());
        // O_PATH fails.
        let opath = rustix::fs::open(
            base.join("good"),
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        assert!(validate_repository_fd(&opath, uid(), gid()).is_err());
        // (O_RDWR on a directory is EISDIR — an `O_ACCMODE != O_RDONLY`
        // descriptor is unconstructable on Linux; the check still
        // stands for upstream parity.)
        // A mismatched expected owner fails.
        assert!(validate_repository_fd(&good, uid() + 1, gid()).is_err());
        let _ = std::fs::remove_dir_all(&base);
    }
}
