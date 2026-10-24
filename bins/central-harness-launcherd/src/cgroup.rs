//! Scope cgroups (spec decision 12) — upstream `cgroup.c`. The daemon
//! runs in `<own>/supervisor`, and every launch's tree lives in
//! `<own>/scopes/<uuid>`, root-owned so the harness cannot write
//! `cgroup.procs` to leave it. Liveness is `cgroup.events` "populated";
//! the kill is `cgroup.kill`.
//!
//! Test builds take `<own>` from `CHL_TEST_CGROUP_ROOT`. With
//! `CHL_TEST_NO_ISOLATION` that is an ordinary directory: the interface
//! files are plain files the monitor and the test write (the fake
//! cgroup).

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStringExt;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicI32, Ordering};

use central_adapter_harness::launcher::protocol::{Reason, Scope, parse_scope};
use rustix::fs::{
    Access, AtFlags, Dir, FileType, Mode, OFlags, accessat, mkdirat, open, openat, statat, unlinkat,
};
use rustix::io::{Errno, read, write};

use crate::knobs;
use crate::protocol::{log, scope_string};
use crate::sys;

const CGROUP_FS: &str = "/sys/fs/cgroup";

static SCOPES_FD: AtomicI32 = AtomicI32::new(-1);
static SCOPES_PATH: OnceLock<std::path::PathBuf> = OnceLock::new();

fn scopes_fd() -> Option<BorrowedFd<'static>> {
    let fd = SCOPES_FD.load(Ordering::Relaxed);
    (fd >= 0).then(|| sys::borrow(fd))
}

/// `write_at` writes text to dirfd/name. Real cgroup files already
/// exist; the fake cgroup root creates them.
fn write_at(dirfd: impl AsFd, name: &str, text: &[u8]) -> Result<(), Errno> {
    let flags = if knobs::no_isolation() {
        OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::CREATE | OFlags::TRUNC
    } else {
        OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW
    };
    let fd = openat(dirfd, name, flags, Mode::from_bits_retain(0o644))?;
    let mut written = 0usize;
    while written < text.len() {
        match write(&fd, &text[written..]) {
            Err(Errno::INTR) => continue,
            Err(e) => return Err(e),
            Ok(0) => return Err(Errno::IO),
            Ok(n) => written += n,
        }
    }
    Ok(())
}

fn own_cgroup_path() -> Result<std::path::PathBuf, Errno> {
    if let Some(root) = knobs::cgroup_root() {
        let p = std::path::PathBuf::from(root);
        if p.as_os_str().len() < PATH_MAX_LEN {
            return Ok(p);
        }
        return Err(Errno::INVAL);
    }
    let text = std::fs::read("/proc/self/cgroup")
        .map_err(|e| Errno::from_io_error(&e).unwrap_or(Errno::INVAL))?;
    for line in text.split(|b| *b == b'\n') {
        if line.starts_with(b"0::") {
            let mut out = CGROUP_FS.as_bytes().to_vec();
            out.extend_from_slice(&line[3..]);
            if out.len() < PATH_MAX_LEN {
                return Ok(std::path::PathBuf::from(std::ffi::OsString::from_vec(out)));
            }
            return Err(Errno::INVAL);
        }
    }
    Err(Errno::INVAL)
}

const PATH_MAX_LEN: usize = 4096;

/// `chl_cgroup_setup` — fail closed without cgroup v2 `cgroup.kill`;
/// build `supervisor`/`scopes` and arm the subtree controllers.
pub fn setup() -> Result<(), Errno> {
    let own = own_cgroup_path()?;
    let own_fd = open(
        own.as_os_str(),
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    accessat(&own_fd, "cgroup.kill", Access::EXISTS, AtFlags::empty())?;
    for d in ["supervisor", "scopes"] {
        match mkdirat(&own_fd, d, Mode::from_bits_retain(0o755)) {
            Ok(()) | Err(Errno::EXIST) => {}
            Err(e) => return Err(e),
        }
    }
    let procs = format!("{}\n", rustix::process::getpid().as_raw_nonzero());
    write_at(&own_fd, "supervisor/cgroup.procs", procs.as_bytes())?;
    // The limits need the pids and memory controllers in every scope;
    // cpu is needed only when cpu_max is configured, so a missing one
    // fails that launch instead.
    write_at(&own_fd, "cgroup.subtree_control", b"+pids +memory")?;
    let _ = write_at(&own_fd, "cgroup.subtree_control", b"+cpu");
    write_at(&own_fd, "scopes/cgroup.subtree_control", b"+pids +memory")?;
    let _ = write_at(&own_fd, "scopes/cgroup.subtree_control", b"+cpu");
    let scopes_path = own.join("scopes");
    if scopes_path.as_os_str().len() >= PATH_MAX_LEN {
        return Err(Errno::INVAL);
    }
    let scopes = openat(
        &own_fd,
        "scopes",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    SCOPES_PATH.set(scopes_path).ok();
    SCOPES_FD.store(scopes.as_raw_fd(), Ordering::Relaxed);
    std::mem::forget(scopes); // the static owns it from now on
    Ok(())
}

/// `chl_cgroup_reopen` — a monitor that closed every inherited
/// descriptor re-opens the scopes directory by path.
pub fn reopen() -> Result<(), Errno> {
    let path = SCOPES_PATH.get().ok_or(Errno::INVAL)?.clone();
    let fd = open(
        path.as_os_str(),
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    SCOPES_FD.store(fd.as_raw_fd(), Ordering::Relaxed);
    std::mem::forget(fd);
    Ok(())
}

fn scope_name(scope: &Scope) -> String {
    scope_string(scope)
}

/// `chl_scope_open` — an O_RDONLY dirfd of the scope cgroup.
pub fn scope_open(scope: &Scope) -> Result<OwnedFd, Errno> {
    let scopes = scopes_fd().ok_or(Errno::INVAL)?;
    openat(
        scopes,
        scope_name(scope).as_str(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
}

/// `chl_scope_exists`.
pub fn scope_exists(scope: &Scope) -> bool {
    let Some(scopes) = scopes_fd() else {
        return false;
    };
    statat(
        scopes,
        scope_name(scope).as_str(),
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .is_ok()
}

/// `chl_scope_create` — mkdir + limits (+ fake interface files).
pub fn scope_create(scope: &Scope, c: &crate::policy::Config) -> Result<(), Errno> {
    let scopes = scopes_fd().ok_or(Errno::INVAL)?;
    let name = scope_name(scope);
    mkdirat(scopes, name.as_str(), Mode::from_bits_retain(0o755))?;
    let result = (|| -> Result<(), Errno> {
        if knobs::no_isolation() {
            let path = format!("{name}/cgroup.events");
            write_at(scopes, &path, b"populated 0\nfrozen 0\n")?;
            let path = format!("{name}/cgroup.kill");
            write_at(scopes, &path, b"")?;
        }
        let path = format!("{name}/pids.max");
        write_at(scopes, &path, format!("{}\n", c.pids_max).as_bytes())?;
        let path = format!("{name}/memory.max");
        write_at(scopes, &path, format!("{}\n", c.memory_max).as_bytes())?;
        if !c.cpu_max.is_empty() {
            let path = format!("{name}/cpu.max");
            write_at(scopes, &path, &c.cpu_max)?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = scope_remove(scope);
    }
    result
}

/// `chl_scope_mark` — the fake cgroup.events of a no-isolation build.
#[cfg(feature = "test-build")]
pub fn scope_mark(scope: &Scope, populated: bool) {
    if let Some(scopes) = scopes_fd() {
        let path = format!("{}/cgroup.events", scope_name(scope));
        let _ = write_at(
            scopes,
            &path,
            if populated {
                b"populated 1\nfrozen 0\n"
            } else {
                b"populated 0\nfrozen 0\n"
            },
        );
    }
}

/// `chl_scope_populated` — 1 populated, 0 not (or no such scope),
/// Err on unreadable.
pub fn scope_populated(scope: &Scope) -> Result<bool, Errno> {
    let scopes = scopes_fd().ok_or(Errno::INVAL)?;
    let path = format!("{}/cgroup.events", scope_name(scope));
    let fd = match openat(
        scopes,
        path.as_str(),
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    ) {
        Err(Errno::NOENT) => return Ok(false),
        other => other?,
    };
    let mut text = [0u8; 256];
    let n = match read(&fd, &mut text[..255]) {
        Err(Errno::INTR) => read(&fd, &mut text[..255])?,
        other => other?,
    };
    let text = &text[..n];
    let Some(p) = find_subslice(text, b"populated ") else {
        return Err(Errno::IO);
    };
    // C's 256-byte NUL-padded buffer makes the value read infallible; the
    // un-padded slice can end exactly at "populated " — treat a missing
    // value byte as not-populated (same answer C's NUL gives).
    Ok(text.get(p + 10) == Some(&b'1'))
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// `chl_scope_kill` — write "1" to cgroup.kill; ENOENT is success.
pub fn scope_kill(scope: &Scope) -> Result<(), Errno> {
    let scopes = scopes_fd().ok_or(Errno::INVAL)?;
    let path = format!("{}/cgroup.kill", scope_name(scope));
    let fd = match openat(
        scopes,
        path.as_str(),
        OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    ) {
        Err(Errno::NOENT) => return Ok(()),
        other => other?,
    };
    match write(&fd, b"1") {
        Err(Errno::INTR) => match write(&fd, b"1") {
            Ok(1) => Ok(()),
            _ => Err(Errno::IO),
        },
        Ok(1) => Ok(()),
        _ => Err(Errno::IO),
    }
}

/// `chl_scope_wait_empty` — poll the populated flag until `timeout_ms`.
pub fn scope_wait_empty(scope: &Scope, timeout_ms: i32) -> Result<(), Errno> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms as u64);
    loop {
        if let Ok(false) = scope_populated(scope) {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(Errno::TIMEDOUT);
        }
        sys::sleep_ms(10);
    }
}

/// `chl_scope_remove` — rmdir; under the fake cgroup the plain files go
/// first.
pub fn scope_remove(scope: &Scope) -> Result<(), Errno> {
    let scopes = scopes_fd().ok_or(Errno::INVAL)?;
    let name = scope_name(scope);
    if knobs::no_isolation() {
        match openat(
            scopes,
            name.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        ) {
            Err(Errno::NOENT) => return Ok(()),
            Err(e) => return Err(e),
            Ok(dirfd) => {
                if let Ok(dir) = Dir::read_from(&dirfd) {
                    for entry in dir {
                        let Ok(e) = entry else { continue };
                        if e.file_type() == FileType::RegularFile {
                            let _ = unlinkat(&dirfd, e.file_name(), AtFlags::empty());
                        }
                    }
                }
            }
        }
    }
    match unlinkat(scopes, name.as_str(), AtFlags::REMOVEDIR) {
        Err(Errno::NOENT) => Ok(()),
        other => other,
    }
}

/// `chl_cgroup_sweep` — kill and remove every scope a previous instance
/// left.
pub fn sweep() {
    let Some(scopes) = scopes_fd() else { return };
    let Ok(dirfd) = openat(
        scopes,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) else {
        return;
    };
    let Ok(dir) = Dir::read_from(&dirfd) else {
        return;
    };
    for entry in dir {
        let Ok(e) = entry else { continue };
        if e.file_type() != FileType::Directory {
            continue;
        }
        let name = e.file_name().to_str().unwrap_or("");
        let Ok(scope) = parse_scope(name) else {
            continue;
        };
        let _ = scope_kill(&scope);
        if scope_wait_empty(&scope, knobs::sweep_timeout_ms()).is_ok()
            && scope_remove(&scope).is_ok()
        {
            log("scope_swept", Reason::Ok, Some(&scope));
        } else {
            log("scope_sweep_failed", Reason::LaunchFailed, Some(&scope));
        }
    }
}
