//! Offline-mutation permit custody — upstream `main.c`'s
//! `inspect_permit_file`/`initialize_permits`/`acquire_permits`/
//! `close_permits`/`release_record_permits`.
//!
//! The gate works in two phases exactly like upstream:
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
//!   life — committed or not — until the record is killed or reaped.
//!
//! The child never keeps them: `close_permits_in_child` drops the
//! pair before the fixed-fd shuffles, and a launcher crash closes the
//! parent-held descriptors, which is the revoke.

use std::os::fd::{AsFd, AsRawFd, OwnedFd};

use rustix::fs::{FlockOperation, Mode, OFlags, flock};

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
    /// The raw descriptors — the forked child closes both before the
    /// fixed-fd shuffles (`close_permits_in_child`).
    pub fn raw_fds(&self) -> (i32, i32) {
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
