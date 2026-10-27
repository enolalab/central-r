//! Containment-safe `openat2` path resolution — the port of upstream
//! `internal/sandbox/path_resolve.go` (`ResolvePath` /
//! `ResolveDirectory` / `ResolveRegularFile`).
//!
//! Every resolution runs under [`RESOLVE_FLAGS`] —
//! `RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|
//! RESOLVE_NO_XDEV` — so the kernel refuses `..` escapes, symlink and
//! magic-link traversal, and cross-mount escapes *before* a descriptor
//! exists. `O_CLOEXEC` is always added.
//!
//! This is the sandbox launcher's resolve set, one flag stricter than
//! [`crate::workspace_seal`]'s `open_beneath` (which deliberately omits
//! `NO_XDEV` because sealed clone trees may legitimately contain
//! mounts). Callers resolving *trusted* runtime trees use this module.

use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;

use central_foundation::failure::Failure;
use rustix::fs::{FileType, Mode, OFlags, ResolveFlags, fstat, openat2};
use rustix::io::Errno;

/// `path_resolve.go`'s `resolveFlags` — the containment every sandbox
/// lookup runs under.
pub const RESOLVE_FLAGS: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS)
    .union(ResolveFlags::NO_XDEV);

fn os_failure(step: &str, rel: &Path, e: Errno) -> Failure {
    Failure::internal("sys_openat2_os", format!("{step} {}: {e}", rel.display()))
}

fn denied(step: &str, rel: &Path) -> Failure {
    Failure::denied("sys_openat2_denied", format!("{step} {}", rel.display()))
}

/// `ResolvePath` — open `rel` beneath the `root` descriptor under the
/// full containment set. The returned descriptor is valid only within
/// `root`'s mount namespace.
///
/// `oflags` are the caller's access flags; `O_CLOEXEC` is always added.
/// `ELOOP` (symlink/magic-link) and `EXDEV` (escape/mount) surface as
/// `sys_openat2_os` — the kernel's refusal is the containment check,
/// not a pre-scan.
///
/// # Errors
/// `sys_openat2_os` on any `openat2` refusal.
pub fn resolve<Fd: AsFd>(root: Fd, rel: &Path, oflags: OFlags) -> Result<OwnedFd, Failure> {
    resolve_with(root, rel, oflags, RESOLVE_FLAGS).map_err(|e| os_failure("openat2", rel, e))
}

/// The flag-parameterized primitive behind [`resolve`] — the single
/// `openat2` call site every confined resolution in the workspace
/// routes through (R5 task 14 / D5 carry-forward). Callers with a
/// different deliberate resolve policy pass their own `resolve` set:
/// [`crate::workspace_seal`]'s `open_beneath` drops `NO_XDEV` because
/// sealed clone trees may legitimately contain mounts, and the harness
/// launcherd resolves work trees under `RESOLVE_BENEATH` alone since
/// in-tree symlinks are legal there.
///
/// The raw `Errno` is returned so the caller keeps its own errno
/// discrimination (`ELOOP`/`EXDEV`/`ENOENT` verdicts) — [`resolve`] is
/// the `Failure`-mapping convenience for the sandbox path's policy.
///
/// # Errors
/// The `openat2` `Errno` unchanged.
pub fn resolve_with<Fd: AsFd>(
    root: Fd,
    rel: &Path,
    oflags: OFlags,
    resolve: ResolveFlags,
) -> Result<OwnedFd, Errno> {
    resolve_with_mode(root, rel, oflags, Mode::empty(), resolve)
}

/// [`resolve_with`] plus a creation `mode`. Upstream documents the
/// `openat2(2)` discipline (restore_capacity_reserve_store_path_linux.go):
/// `build_open_flags()` refuses a non-zero `open_how.mode` with `EINVAL`
/// unless `O_CREAT` or `O_TMPFILE` is present — so callers must pass a
/// mode *only* on create flags, never unconditionally. This split keeps
/// that rule in one audited call site.
///
/// # Errors
/// The `openat2` `Errno` unchanged.
pub fn resolve_with_mode<Fd: AsFd>(
    root: Fd,
    rel: &Path,
    oflags: OFlags,
    mode: Mode,
    resolve: ResolveFlags,
) -> Result<OwnedFd, Errno> {
    openat2(root, rel, oflags | OFlags::CLOEXEC, mode, resolve)
}

/// `ResolveDirectory` — [`resolve`] with `O_DIRECTORY|O_NOFOLLOW`:
/// "is a directory" becomes a kernel precondition instead of a
/// post-hoc check, and `O_NOFOLLOW` restates the symlink refusal on
/// the final component.
///
/// # Errors
/// `sys_openat2_os` when `rel` is not a directory beneath `root` or
/// resolution is refused.
pub fn resolve_directory<Fd: AsFd>(root: Fd, rel: &Path) -> Result<OwnedFd, Failure> {
    resolve(
        root,
        rel,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
    )
}

/// `ResolveRegularFile` — [`resolve`] with `O_NOFOLLOW|O_NONBLOCK`,
/// then the `S_ISREG` post-check. `O_NONBLOCK` removes the FIFO-open
/// stall (a no-op on regular files) so the type check — not a block —
/// refuses device nodes, sockets, and pipes.
///
/// # Errors
/// `sys_openat2_denied` when the resolved entry is not a regular
/// file; `sys_openat2_os` on `openat2`/`fstat` failure.
pub fn resolve_regular_file<Fd: AsFd>(root: Fd, rel: &Path) -> Result<OwnedFd, Failure> {
    let fd = resolve(
        root,
        rel,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK,
    )?;
    let st = fstat(&fd).map_err(|e| os_failure("fstat", rel, e))?;
    if !FileType::from_raw_mode(st.st_mode).is_file() {
        return Err(denied("not a regular file:", rel));
    }
    Ok(fd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    /// A scratch directory tree owned by the test.
    struct Tree(std::path::PathBuf);

    impl Tree {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("central-sys-openat2-{name}-{}", std::process::id()));
            std::fs::remove_dir_all(&dir).ok();
            std::fs::create_dir_all(dir.join("inner")).expect("mkdir inner");
            std::fs::write(dir.join("inner/file.txt"), b"content").expect("seed file");
            std::fs::write(dir.join("top.txt"), b"top").expect("seed top");
            Self(dir)
        }

        fn fd(&self) -> OwnedFd {
            rustix::fs::open(
                &self.0,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .expect("open root")
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    /// `ResolvePath` opens a real file beneath the root and the
    /// content reads back.
    #[test]
    fn resolve_opens_beneath() {
        let tree = Tree::new("beneath");
        let root = tree.fd();
        let fd = resolve(&root, Path::new("inner/file.txt"), OFlags::RDONLY).expect("resolve");
        let mut buf = String::new();
        std::fs::File::from(fd)
            .read_to_string(&mut buf)
            .expect("read");
        assert_eq!(buf, "content");
    }

    /// Every spelling of `..` escape is refused by `RESOLVE_BENEATH`
    /// — the kernel answers `EXDEV` before the descriptor exists.
    #[test]
    fn resolve_denies_dotdot_escape() {
        let tree = Tree::new("dotdot");
        let root = tree.fd();
        let err = resolve(&root, Path::new("../top.txt"), OFlags::RDONLY).unwrap_err();
        assert_eq!(err.code(), "sys_openat2_os");
        let err = resolve(&root, Path::new("inner/../../top.txt"), OFlags::RDONLY).unwrap_err();
        assert_eq!(err.code(), "sys_openat2_os");
        // `..` that stays *within* the root is still resolution — not
        // an escape — and is admitted.
        resolve(&root, Path::new("inner/../top.txt"), OFlags::RDONLY).expect("in-root ..");
    }

    /// `RESOLVE_NO_SYMLINKS` — a symlink *inside* the tree pointing at
    /// a real file is refused with `ELOOP`.
    #[test]
    fn resolve_denies_symlink() {
        let tree = Tree::new("symlink");
        std::os::unix::fs::symlink("file.txt", tree.0.join("inner/link")).expect("symlink");
        let root = tree.fd();
        let err = resolve(&root, Path::new("inner/link"), OFlags::RDONLY).unwrap_err();
        assert_eq!(err.code(), "sys_openat2_os");
    }

    /// A symlink whose target is *outside* the root — the escape the
    /// broker exists to refuse — fails before following anything.
    #[test]
    fn resolve_denies_symlink_escape() {
        let tree = Tree::new("symlink-escape");
        std::os::unix::fs::symlink("/etc/hostname", tree.0.join("escape")).expect("symlink");
        let root = tree.fd();
        let err = resolve(&root, Path::new("escape"), OFlags::RDONLY).unwrap_err();
        assert_eq!(err.code(), "sys_openat2_os");
    }

    /// A magic link — `/proc/self/fd/N` — is refused even when the
    /// descriptor is perfectly legitimate.
    #[test]
    fn resolve_denies_magic_link() {
        let tree = Tree::new("magic");
        // Open a real file; its /proc/self/fd entry is a magic link.
        let probe = rustix::fs::open(
            tree.0.join("inner/file.txt"),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("probe fd");
        std::os::unix::fs::symlink(
            format!("/proc/self/fd/{}", std::os::fd::AsRawFd::as_raw_fd(&probe)),
            tree.0.join("magic"),
        )
        .expect("magic symlink");
        let root = tree.fd();
        let err = resolve(&root, Path::new("magic"), OFlags::RDONLY).unwrap_err();
        assert_eq!(err.code(), "sys_openat2_os");
    }

    /// `ResolveDirectory` — `O_DIRECTORY` makes directory-ness a
    /// kernel precondition; a file refuses as `ENOTDIR`.
    #[test]
    fn resolve_directory_gate() {
        let tree = Tree::new("dir");
        let root = tree.fd();
        resolve_directory(&root, Path::new("inner")).expect("dir resolves");
        let err = resolve_directory(&root, Path::new("top.txt")).unwrap_err();
        assert_eq!(err.code(), "sys_openat2_os");
    }

    /// `ResolveRegularFile` — the post-check refuses a directory; a
    /// FIFO never stalls the open (`O_NONBLOCK`) and refuses on
    /// `S_ISREG`.
    #[test]
    fn resolve_regular_file_gate() {
        let tree = Tree::new("reg");
        let root = tree.fd();
        resolve_regular_file(&root, Path::new("inner/file.txt")).expect("regular file");
        let err = resolve_regular_file(&root, Path::new("inner")).unwrap_err();
        assert_eq!(err.code(), "sys_openat2_denied");

        // A FIFO beneath the root: `O_NONBLOCK` opens it without
        // stalling; the S_ISREG check then refuses.
        rustix::fs::mkfifoat(&root, "pipe", Mode::from_bits_retain(0o600)).expect("mkfifoat");
        let err = resolve_regular_file(&root, Path::new("pipe")).unwrap_err();
        assert_eq!(err.code(), "sys_openat2_denied");
        assert!(err.message().contains("not a regular file"));
    }
}
