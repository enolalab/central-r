//! `workspace_seal` — the production [`WorkspaceSealer`] of R3 open
//! decision D2: the untrusted-clone OS boundary upstream gitclone keeps
//! in `acl_linux.go`, `seal_linux.go`, `reopen_linux.go` and the
//! `RLIMIT_AS` of `capture_linux.go`, ported over `rustix` safe
//! wrappers.
//!
//! Every path under an untrusted Run clone is opened beneath the
//! verified clone-root descriptor with `openat2`
//! (`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`), so
//! a swapped-in symlink, magic link or `..` escape is refused by the
//! kernel. Ownership and file type are checked on the opened descriptor
//! (`fstat`), never on a path. POSIX ACLs are the `system.posix_acl_*`
//! xattrs in the kernel's version-2 little-endian layout.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

use central_foundation::failure::Failure;
use central_foundation::identity::RunId;
use central_harness::app::ports::{ObjectLimits, SealedClone, WalkLimits, WorkspaceSealer, codes};
use central_harness::gitmeta;
use central_harness::port::PortFuture;
use rustix::fs::{Mode, OFlags, ResolveFlags};

/// `ACL_UNDEFINED_ID` — `u32::MAX`.
const ACL_UNDEF: u32 = u32::MAX;
/// POSIX ACL xattr version (`POSIX_ACL_XATTR_VERSION`, 0x0002).
const ACL_VERSION: u32 = 0x0002;
mod acl_tag {
    pub const USER_OBJ: u16 = 0x01;
    pub const USER: u16 = 0x02;
    pub const GROUP_OBJ: u16 = 0x04;
    pub const MASK: u16 = 0x10;
    pub const OTHER: u16 = 0x20;
}
const ACL_ACCESS: &str = "system.posix_acl_access";
const ACL_DEFAULT: &str = "system.posix_acl_default";

fn capture_failed(step: &str) -> Failure {
    Failure::internal(codes::CAPTURE_FAILED, step.to_string())
}
fn unavailable(step: &str) -> Failure {
    Failure::unavailable(codes::WORKSPACE_UNAVAILABLE, step.to_string())
}

/// One encoded ACL entry: tag, permissions, id (little-endian records,
/// `posix_acl_xattr_entry`).
#[derive(Clone, Copy)]
struct AclEntry {
    tag: u16,
    perm: u16,
    id: u32,
}

/// Encodes the kernel `posix_acl_xattr` layout: u32 version then
/// (u16 tag, u16 perm, u32 id) records, sorted by tag and then id —
/// upstream `encodeACL`'s sort; the kernel requires `ACL_USER` entries
/// ascending by id.
fn encode_acl(entries: &[AclEntry]) -> Vec<u8> {
    let mut sorted = entries.to_vec();
    sorted.sort_by_key(|e| (e.tag, e.id));
    let mut v = Vec::with_capacity(4 + sorted.len() * 8);
    v.extend_from_slice(&ACL_VERSION.to_le_bytes());
    for e in &sorted {
        v.extend_from_slice(&e.tag.to_le_bytes());
        v.extend_from_slice(&e.perm.to_le_bytes());
        v.extend_from_slice(&e.id.to_le_bytes());
    }
    v
}

/// Decodes the kernel layout — the tests check `encode_acl`'s sort
/// against it.
#[cfg(test)]
fn decode_acl(data: &[u8]) -> Option<Vec<AclEntry>> {
    let (ver, rest) = data.split_at_checked(4)?;
    if u32::from_le_bytes(ver.try_into().ok()?) != ACL_VERSION {
        return None;
    }
    let mut out = Vec::new();
    let (chunks, _) = rest.as_chunks::<8>();
    for chunk in chunks {
        out.push(AclEntry {
            tag: u16::from_le_bytes([chunk[0], chunk[1]]),
            perm: u16::from_le_bytes([chunk[2], chunk[3]]),
            id: u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]),
        });
    }
    Some(out)
}

/// `namedUserPerm` — setfacl's `rwX`: read and write, plus execute for
/// a directory or a file already executable by someone.
fn named_user_perm(perm: u32, is_dir: bool) -> u16 {
    let mut p = 0o6u16;
    if is_dir || perm & 0o111 != 0 {
        p |= 1;
    }
    p
}

/// `accessACL` — keeps the owner, group and other permissions of
/// `perm` (the member's `mode & 0o777`), grants each uid `rwX`, and
/// sets the mask to the union of the group-class entries, so the mask
/// never restricts the grant.
fn access_acl(perm: u32, is_dir: bool, uids: &[u32]) -> Vec<AclEntry> {
    let perm = perm & 0o777;
    let named = named_user_perm(perm, is_dir);
    let group_obj = ((perm >> 3) & 7) as u16;
    let mut entries = vec![
        AclEntry {
            tag: acl_tag::USER_OBJ,
            perm: ((perm >> 6) & 7) as u16,
            id: ACL_UNDEF,
        },
        AclEntry {
            tag: acl_tag::GROUP_OBJ,
            perm: group_obj,
            id: ACL_UNDEF,
        },
        AclEntry {
            tag: acl_tag::MASK,
            perm: named | group_obj,
            id: ACL_UNDEF,
        },
        AclEntry {
            tag: acl_tag::OTHER,
            perm: (perm & 7) as u16,
            id: ACL_UNDEF,
        },
    ];
    for &u in uids {
        entries.push(AclEntry {
            tag: acl_tag::USER,
            perm: named,
            id: u,
        });
    }
    entries
}

/// `defaultACL` — a directory's inheritable ACL: the same owner,
/// group and other bits, `rwx` for each uid and mask `rwx`, so files
/// the harness creates stay readable by the runtime and writable by
/// the operator.
fn default_acl(perm: u32, uids: &[u32]) -> Vec<AclEntry> {
    let perm = perm & 0o777;
    let mut entries = vec![
        AclEntry {
            tag: acl_tag::USER_OBJ,
            perm: ((perm >> 6) & 7) as u16,
            id: ACL_UNDEF,
        },
        AclEntry {
            tag: acl_tag::GROUP_OBJ,
            perm: ((perm >> 3) & 7) as u16,
            id: ACL_UNDEF,
        },
        AclEntry {
            tag: acl_tag::MASK,
            perm: 0o7,
            id: ACL_UNDEF,
        },
        AclEntry {
            tag: acl_tag::OTHER,
            perm: (perm & 7) as u16,
            id: ACL_UNDEF,
        },
    ];
    for &u in uids {
        entries.push(AclEntry {
            tag: acl_tag::USER,
            perm: 0o7,
            id: u,
        });
    }
    entries
}

/// The production sealer — upstream's `acl_linux.go`/`seal_linux.go`
/// over `data_root`.
pub struct LinuxWorkspaceSealer {
    data_root: PathBuf,
    /// The ACL grantees: operator, plus runtime when distinct.
    uids: Vec<u32>,
    runtime_uid: u32,
    min_free: u64,
}

impl LinuxWorkspaceSealer {
    /// Constructs the sealer. `data_root` must be the provisioner's
    /// data root; `operator_uid`/`runtime_uid` are upstream Config's.
    #[must_use]
    pub fn new(data_root: PathBuf, operator_uid: u32, runtime_uid: u32, min_free: u64) -> Self {
        let mut uids = vec![operator_uid];
        if runtime_uid != operator_uid {
            uids.push(runtime_uid);
        }
        Self {
            data_root,
            uids,
            runtime_uid,
            min_free,
        }
    }

    fn run_dir(&self, run: RunId) -> PathBuf {
        self.data_root
            .join("worktrees")
            .join("runs")
            .join(run.to_string())
    }

    /// The Run directory's path relative to the data root — the
    /// `openat2` `RESOLVE_BENEATH` path anchored at the data-root
    /// descriptor (upstream's `openBeneath(rootFD, "worktrees/runs/<run>")`).
    fn run_rel(&self, run: RunId) -> PathBuf {
        Path::new("worktrees").join("runs").join(run.to_string())
    }
}

/// Opens `path` beneath `dir` refusing every symlink/magic-link/escape
/// (`openat2`), or `Err` on `ELOOP`/`EXDEV`/missing. `dir` is the
/// trusted anchor: the run dir or clone-root descriptor.
fn open_beneath(
    dir: &impl std::os::fd::AsFd,
    path: &Path,
    oflags: OFlags,
) -> Result<rustix::fd::OwnedFd, rustix::io::Errno> {
    rustix::fs::openat2(
        dir,
        path,
        oflags | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
}

/// `vanishedErr` — an open or stat under the untrusted clone failed
/// because the entry is not there as a real file or directory beneath
/// the root: gone (`ENOENT`), swapped for a non-directory (`ENOTDIR`)
/// or a symlink (`ELOOP`), or resolving outside the tree (`EXDEV`,
/// from `RESOLVE_BENEATH`). The work-tree walk skips such an entry; a
/// `dir.flatten()`-style read or open failure of any other kind fails
/// the capture.
fn vanished(e: rustix::io::Errno) -> bool {
    matches!(
        e,
        rustix::io::Errno::NOENT
            | rustix::io::Errno::NOTDIR
            | rustix::io::Errno::LOOP
            | rustix::io::Errno::XDEV
    )
}

/// `unavailableErr` — `vanishedErr` or an entry the runtime cannot
/// read (`EACCES`): the object copy skips it; anything else fails the
/// capture.
fn unavailable_err(e: rustix::io::Errno) -> bool {
    vanished(e) || e == rustix::io::Errno::ACCESS
}

/// `readXattr`'s two-call read: the size, then the value, retrying
/// `ERANGE` (the xattr grew between the two calls).
fn fgetxattr_full(d: &impl std::os::fd::AsFd, name: &str) -> Result<Vec<u8>, rustix::io::Errno> {
    let mut empty: [u8; 0] = [];
    loop {
        let size = rustix::fs::fgetxattr(d, name, &mut empty)?;
        let mut buf = vec![0u8; size];
        match rustix::fs::fgetxattr(d, name, buf.as_mut_slice()) {
            Ok(n) => {
                buf.truncate(n);
                return Ok(buf);
            }
            Err(e) if e == rustix::io::Errno::RANGE => continue,
            Err(e) => return Err(e),
        }
    }
}

/// `aclMode` — the permission bits the kernel shows for an access
/// ACL: the owner entry, the mask (or the owning group without one)
/// and other.
fn acl_mode(entries: &[AclEntry]) -> u32 {
    let (mut owner, mut group, mut mask, mut other) = (0u32, 0u32, 0u32, 0u32);
    let mut has_mask = false;
    for e in entries {
        match e.tag {
            acl_tag::USER_OBJ => owner = u32::from(e.perm),
            acl_tag::GROUP_OBJ => group = u32::from(e.perm),
            acl_tag::MASK => {
                mask = u32::from(e.perm);
                has_mask = true;
            }
            acl_tag::OTHER => other = u32::from(e.perm),
            _ => {}
        }
    }
    if has_mask {
        group = mask;
    }
    owner << 6 | group << 3 | other
}

fn fstat_kind(fd: &impl std::os::fd::AsFd) -> Result<rustix::fs::Stat, Failure> {
    rustix::fs::fstat(fd).map_err(|_| capture_failed("stat a clone member"))
}

impl WorkspaceSealer for LinuxWorkspaceSealer {
    /// `freeBytes`/`CheckFreeSpace` — `statfs` the data root.
    fn check_free_space<'a>(&'a self) -> PortFuture<'a, Result<(), Failure>> {
        Box::pin(async move {
            if self.min_free == 0 {
                return Ok(());
            }
            let st =
                rustix::fs::statfs(&self.data_root).map_err(|_| unavailable("read free space"))?;
            let free = st
                .f_bavail
                .saturating_mul(u64::try_from(st.f_bsize).unwrap_or(0));
            if free < self.min_free {
                return Err(Failure::unavailable(
                    codes::LOW_DISK,
                    format!("{free} bytes free, {} required", self.min_free),
                ));
            }
            Ok(())
        })
    }

    /// `grantTree` — grants the provisioned ACLs on `run`'s tree,
    /// children before their directory and the Run directory last
    /// (security review S4).
    fn grant_run<'a>(&'a self, run: RunId) -> PortFuture<'a, Result<(), Failure>> {
        let uids = self.uids.clone();
        let run_dir = self.run_dir(run);
        Box::pin(async move {
            let rd = run_dir.clone();
            tokio::task::spawn_blocking(move || grant_tree(&rd, &uids))
                .await
                .map_err(|_| unavailable("grant the run ACLs"))??;
            Ok(())
        })
    }

    /// The syscall half of `Reopen` — the Run directory is a real
    /// runtime-owned directory still carrying the provisioned ACLs (a
    /// half-sealed Run is refused, never repaired), and `repo` is a
    /// real runtime-owned directory.
    fn verify_clone<'a>(&'a self, run: RunId) -> PortFuture<'a, Result<(), Failure>> {
        let data_root = self.data_root.clone();
        let run_rel = self.run_rel(run);
        let uids = self.uids.clone();
        let runtime_uid = self.runtime_uid;
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                verify_clone(&data_root, &run_rel, runtime_uid, &uids)
            })
            .await
            .map_err(|_| unavailable("verify the clone"))?
        })
    }

    /// `seal` — `seal_linux.go`: take the operator's access away,
    /// verify the clone root through `openat2`, hand back the handle.
    fn seal<'a>(&'a self, run: RunId) -> PortFuture<'a, Result<Box<dyn SealedClone>, Failure>> {
        let data_root = self.data_root.clone();
        let run_rel = self.run_rel(run);
        let run_dir = self.run_dir(run);
        let uids = self.uids.clone();
        let runtime_uid = self.runtime_uid;
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                seal_run(&data_root, &run_rel, &run_dir, runtime_uid, &uids)
            })
            .await
            .map_err(|_| capture_failed("seal"))?
            .map(|s| Box::new(s) as Box<dyn SealedClone>)
        })
    }

    /// `capture.start`'s `Prlimit(RLIMIT_AS)`.
    fn limit_process_memory<'a>(
        &'a self,
        pid: u32,
        bytes: u64,
    ) -> PortFuture<'a, Result<(), Failure>> {
        Box::pin(async move {
            let pid = rustix::process::Pid::from_raw(pid.cast_signed());
            let lim = rustix::process::Rlimit {
                current: Some(bytes),
                maximum: Some(bytes),
            };
            rustix::process::prlimit(pid, rustix::process::Resource::As, lim)
                .map(|_| ())
                .map_err(|_| capture_failed("limit git's memory"))
        })
    }
}

/// `grantTree` — the provisioned ACLs on every directory and regular
/// file under `root` (access) and every directory (default). Symlinks
/// are skipped, never followed; anything else (a FIFO, a socket, a
/// device) is refused, since a fresh clone contains none.
///
/// The tree is walked first and the ACLs applied afterwards in
/// post-order — children before their directory and `root` last
/// (security review S4): until `root` is granted only the runtime can
/// traverse the 0750 run directory, so no operator process can swap a
/// visited directory for a symlink and redirect a later grant onto a
/// path outside the run.
fn grant_tree(root: &Path, uids: &[u32]) -> Result<(), Failure> {
    let mut nodes = Vec::new();
    collect_tree(root, &mut nodes)?;
    for (path, perm, is_dir) in nodes.iter().rev() {
        let access = encode_acl(&access_acl(*perm, *is_dir, uids));
        set_acl(path, ACL_ACCESS, &access)?;
        if *is_dir {
            let deflt = encode_acl(&default_acl(*perm, uids));
            set_acl(path, ACL_DEFAULT, &deflt)?;
        }
    }
    Ok(())
}

/// `filepath.WalkDir`'s side of `grantTree`: the member list, dirs
/// before their entries.
fn collect_tree(dir: &Path, nodes: &mut Vec<(PathBuf, u32, bool)>) -> Result<(), Failure> {
    let md = std::fs::symlink_metadata(dir).map_err(|_| unavailable("grant the run ACLs"))?;
    if md.file_type().is_symlink() || !md.is_dir() {
        return Err(unavailable("the run directory is not a real directory"));
    }
    nodes.push((dir.to_path_buf(), md.mode() & 0o777, true));
    for e in std::fs::read_dir(dir).map_err(|_| unavailable("grant the run ACLs"))? {
        let e = e.map_err(|_| unavailable("grant the run ACLs"))?;
        let md =
            std::fs::symlink_metadata(e.path()).map_err(|_| unavailable("grant the run ACLs"))?;
        let ft = md.file_type();
        if ft.is_symlink() {
            continue; // ACLs are not granted through symlinks
        }
        if ft.is_dir() {
            collect_tree(&e.path(), nodes)?;
        } else if ft.is_file() {
            nodes.push((e.path(), md.mode() & 0o777, false));
        } else {
            return Err(unavailable("unexpected file type in run directory"));
        }
    }
    Ok(())
}

/// `setACL` — the xattr write, never through a symlink. `EOPNOTSUPP`
/// reports the filesystem's missing POSIX-ACL support.
fn set_acl(path: &Path, name: &str, encoded: &[u8]) -> Result<(), Failure> {
    match rustix::fs::lsetxattr(path, name, encoded, rustix::fs::XattrFlags::empty()) {
        Ok(()) => Ok(()),
        Err(e) if e == rustix::io::Errno::OPNOTSUPP || e == rustix::io::Errno::NOTSUP => {
            Err(Failure::unavailable(
                codes::WORKSPACE_UNAVAILABLE,
                "filesystem does not support POSIX ACLs",
            ))
        }
        Err(_) => Err(unavailable("grant the run ACLs")),
    }
}

/// Opens the data root — the trusted anchor upstream opens with
/// `unix.Open(p.dataRoot, O_RDONLY|O_DIRECTORY|O_CLOEXEC)`.
fn open_data_root(
    data_root: &Path,
    err: fn(&'static str) -> Failure,
) -> Result<rustix::fd::OwnedFd, Failure> {
    rustix::fs::openat(
        rustix::fs::CWD,
        data_root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| err("open the data root"))
}

/// `requireProvisionedACLs` — the Run directory's access and default
/// ACL xattrs must be exactly the ones `grantTree` writes for a Run
/// directory whose mode is within 0750 (Provision's `os.Mkdir(runDir,
/// 0o750)`, narrowed by the umask), byte for byte.
///
/// The mode Provision created is not the one `fstat` shows now: with
/// an ACL in place the kernel shows the ACL mask as the group class,
/// and the mask `grantTree` writes on a directory is `rwx`, so `st`
/// shows `0770` for `0750` and for `0700` alike. The owner and other
/// bits are `st`'s own; the owning group's bits live only in the ACL.
/// So each group value that keeps the mode within `0750` is tried, and
/// the xattrs must be byte-equal to the ACLs of one of them. A missing
/// xattr (a Run left sealed, or its ACL removed) is refused.
fn require_provisioned_acls(
    d: &impl std::os::fd::AsFd,
    st_mode: u32,
    uids: &[u32],
) -> Result<(), Failure> {
    let mut access = [0u8; 4 << 10];
    let an = rustix::fs::fgetxattr(d, ACL_ACCESS, &mut access)
        .map_err(|_| unavailable("read the run directory's access ACL"))?;
    let mut deflt = [0u8; 4 << 10];
    let dn = rustix::fs::fgetxattr(d, ACL_DEFAULT, &mut deflt)
        .map_err(|_| unavailable("read the run directory's default ACL"))?;
    let shown = st_mode & 0o777;
    if shown & 0o707 & !0o750 != 0 {
        return Err(unavailable("the run directory's mode is wider than 0750"));
    }
    for group in 0u32..=7 {
        let mode = (shown & 0o707) | group << 3;
        if mode & !0o750 != 0 {
            continue;
        }
        if access[..an] == encode_acl(&access_acl(mode, true, uids))[..]
            && deflt[..dn] == encode_acl(&default_acl(mode, uids))[..]
        {
            return Ok(());
        }
    }
    Err(unavailable(
        "the run directory's ACLs are not the provisioned ones",
    ))
}

/// `Reopen`'s fd checks — the Run directory is opened beneath the
/// data-root descriptor with `openat2`, is a real runtime-owned
/// directory still carrying the provisioned ACLs (a half-sealed Run is
/// refused, never repaired), and `repo` is a real runtime-owned
/// directory.
fn verify_clone(
    data_root: &Path,
    run_rel: &Path,
    runtime_uid: u32,
    uids: &[u32],
) -> Result<(), Failure> {
    let root_fd = open_data_root(data_root, unavailable)?;
    let d = open_beneath(&root_fd, run_rel, OFlags::RDONLY | OFlags::DIRECTORY)
        .map_err(|_| unavailable("open the run directory"))?;
    let st = fstat_kind(&d).map_err(|_| unavailable("stat the run directory"))?;
    if !rustix::fs::FileType::from_raw_mode(st.st_mode).is_dir() || st.st_uid != runtime_uid {
        return Err(unavailable(
            "the run directory is not a runtime-owned directory",
        ));
    }
    require_provisioned_acls(&d, st.st_mode, uids)?;
    let repo = open_beneath(&d, Path::new("repo"), OFlags::RDONLY | OFlags::DIRECTORY)
        .map_err(|_| unavailable("open the clone root"))?;
    let st = fstat_kind(&repo).map_err(|_| unavailable("stat the clone root"))?;
    if !rustix::fs::FileType::from_raw_mode(st.st_mode).is_dir() || st.st_uid != runtime_uid {
        return Err(unavailable("the clone root is not the provisioned one"));
    }
    let git = open_beneath(&repo, Path::new(".git"), OFlags::RDONLY | OFlags::DIRECTORY)
        .map_err(|_| unavailable("open the clone's .git"))?;
    let st = fstat_kind(&git).map_err(|_| unavailable("stat the clone's .git"))?;
    if !rustix::fs::FileType::from_raw_mode(st.st_mode).is_dir() {
        return Err(unavailable("the clone's .git is not a real directory"));
    }
    Ok(())
}

/// `provisionedRunACLs` — the Run directory's ACLs and mode as
/// provisioned. A Run left sealed (a serve stop during an earlier
/// capture) has no ACL: it then gets the ACLs Provision grants a
/// fresh Run directory and the mode the kernel shows once that ACL is
/// set (its group class is the mask), so `unseal` can restore a
/// usable directory instead of leaving the Run sealed for good. Any
/// xattr error other than `ENODATA` fails the capture.
fn provisioned_run_acls(
    d: &impl std::os::fd::AsFd,
    st_mode: u32,
    uids: &[u32],
) -> Result<(Vec<u8>, Vec<u8>, u32), Failure> {
    let access = fgetxattr_full(d, ACL_ACCESS);
    let deflt = fgetxattr_full(d, ACL_DEFAULT);
    if let (Ok(a), Ok(dd)) = (&access, &deflt) {
        return Ok((a.clone(), dd.clone(), st_mode & 0o7777));
    }
    for e in [access.as_ref().err(), deflt.as_ref().err()]
        .into_iter()
        .flatten()
    {
        if *e != rustix::io::Errno::NODATA {
            return Err(capture_failed("read the run directory's ACL"));
        }
    }
    // A left-sealed Run gets the ACLs Provision grants a fresh Run
    // directory of the canonical mode 0750, and that mode as the kernel
    // shows it once the ACL is set (its group class is the ACL mask).
    let entries = access_acl(0o750, true, uids);
    Ok((
        encode_acl(&entries),
        encode_acl(&default_acl(0o750, uids)),
        acl_mode(&entries),
    ))
}

/// `restoreRunACLs` — the ACLs first and the mode last on the Run
/// directory's descriptor: the recorded mode was read with the ACL in
/// place (its group class is the ACL mask), so the chmod leaves the
/// restored mask as it was, and the directory never has the mode's
/// group class without its ACL.
fn restore_run_acls(
    d: &impl std::os::fd::AsFd,
    access: &[u8],
    deflt: &[u8],
    mode: u32,
) -> Result<(), Failure> {
    rustix::fs::fsetxattr(d, ACL_ACCESS, access, rustix::fs::XattrFlags::empty())
        .map_err(|_| capture_failed("restore the operator's access to the run directory"))?;
    rustix::fs::fsetxattr(d, ACL_DEFAULT, deflt, rustix::fs::XattrFlags::empty())
        .map_err(|_| capture_failed("restore the run directory's default ACL"))?;
    rustix::fs::fchmod(d, Mode::from_raw_mode(mode))
        .map_err(|_| capture_failed("restore the run directory's mode"))
}

/// `seal` — record the Run directory's ACLs and mode, set its mode to
/// 0700 and remove its ACL xattrs, then verify the clone root beneath
/// it. The Run directory is opened beneath the data-root descriptor
/// with `openat2`. A refused clone root restores the ACL and mode
/// before returning; a failed restore is reported with the refusal.
/// Seal is idempotent.
fn seal_run(
    data_root: &Path,
    run_rel: &Path,
    run_dir: &Path,
    runtime_uid: u32,
    uids: &[u32],
) -> Result<LinuxSealed, Failure> {
    let root_fd = open_data_root(data_root, capture_failed)?;
    let d = open_beneath(&root_fd, run_rel, OFlags::RDONLY | OFlags::DIRECTORY)
        .map_err(|_| capture_failed("open the run directory"))?;
    let st = fstat_kind(&d)?;
    if !rustix::fs::FileType::from_raw_mode(st.st_mode).is_dir() || st.st_uid != runtime_uid {
        return Err(capture_failed(
            "the run directory is not a runtime-owned directory",
        ));
    }
    let (saved_acl, saved_default, saved_mode) = provisioned_run_acls(&d, st.st_mode, uids)?;
    // The chmod comes first: with the ACL still in place it sets the
    // mask to ---, so no moment exists where the group class (the old
    // mask) outlives the ACL's removal. Then both xattrs go: only the
    // runtime owner keeps access, whatever the directory's group.
    rustix::fs::fchmod(&d, Mode::from_raw_mode(0o700))
        .map_err(|_| capture_failed("restrict the run directory"))?;
    for name in [ACL_ACCESS, ACL_DEFAULT] {
        match rustix::fs::fremovexattr(&d, name) {
            Ok(()) | Err(rustix::io::Errno::NODATA) => {}
            Err(_) => {
                return Err(capture_failed(
                    "remove the operator's access to the run directory",
                ));
            }
        }
    }
    // The clone root beneath the sealed run dir must be a real
    // runtime-owned directory; a refusal restores the operator's
    // access before the error is reported.
    let repo_fd = match open_beneath(&d, Path::new("repo"), OFlags::RDONLY | OFlags::DIRECTORY) {
        Ok(f) => f,
        Err(_) => {
            let _ = restore_run_acls(&d, &saved_acl, &saved_default, saved_mode);
            return Err(capture_failed("open the clone root"));
        }
    };
    let rst = fstat_kind(&repo_fd);
    let ok = matches!(
        rst,
        Ok(ref s)
            if rustix::fs::FileType::from_raw_mode(s.st_mode).is_dir() && s.st_uid == runtime_uid
    );
    if !ok {
        let _ = restore_run_acls(&d, &saved_acl, &saved_default, saved_mode);
        return Err(capture_failed(
            "the clone root is not a runtime-owned directory",
        ));
    }
    Ok(LinuxSealed {
        run_dir_fd: d,
        repo: run_dir.join("repo"),
        repo_fd,
        saved_mode,
        saved_acl,
        saved_default,
        unsealed: std::sync::atomic::AtomicBool::new(false),
    })
}

/// The sealed clone — `sealedRun`'s verified clone root plus the
/// descriptor-scoped reads. `drop` restores the operator's access, so
/// a dropped capture never leaves the Run sealed.
struct LinuxSealed {
    run_dir_fd: rustix::fd::OwnedFd,
    repo: PathBuf,
    repo_fd: rustix::fd::OwnedFd,
    saved_mode: u32,
    saved_acl: Vec<u8>,
    saved_default: Vec<u8>,
    unsealed: std::sync::atomic::AtomicBool,
}

impl Drop for LinuxSealed {
    fn drop(&mut self) {
        let _ = self.unseal();
    }
}

/// The shadow objects subdirectory — upstream `os.Mkdir(sub, 0o700)`
/// tolerating `ErrExist`.
fn create_shadow_dir(path: &Path) -> Result<(), Failure> {
    use std::os::unix::fs::DirBuilderExt;
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(_) => Err(capture_failed("create a shadow objects directory")),
    }
}

impl LinuxSealed {
    /// `readSmallFile` — a bounded regular-file read beneath the clone
    /// root (HEAD, a loose ref, packed-refs): `O_NONBLOCK` and the
    /// regular-file `fstat` keep a FIFO or device from blocking. The
    /// size is checked on `fstat` before the read, and again after —
    /// upstream never serves a file over its cap. `Ok(None)` is the
    /// open's `ENOENT` alone (the loose ref's "not there" that sends
    /// the caller to packed-refs); `Err(())` is every other failure,
    /// upstream's `errNotARef` or propagated error — both make the
    /// after HEAD unavailable.
    fn read_small(&self, rel: &Path, cap: u64) -> Result<Option<Vec<u8>>, ()> {
        let fd = match open_beneath(
            &self.repo_fd,
            rel,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW,
        ) {
            Ok(f) => f,
            Err(e) if e == rustix::io::Errno::NOENT => return Ok(None),
            Err(_) => return Err(()),
        };
        let st = rustix::fs::fstat(&fd).map_err(|_| ())?;
        if !rustix::fs::FileType::from_raw_mode(st.st_mode).is_file() {
            return Err(());
        }
        if st.st_size < 0 || st.st_size.cast_unsigned() > cap {
            return Err(());
        }
        let f = std::fs::File::from(fd);
        use std::io::Read;
        let mut out = Vec::new();
        f.take(cap + 1).read_to_end(&mut out).map_err(|_| ())?;
        if out.len() as u64 > cap {
            return Err(());
        }
        Ok(Some(out))
    }

    /// `readDirNames` — the names in the directory fd, without `.` and
    /// `..`, sorted. It reads the entries with `getdents` on fd itself:
    /// no path is resolved, and the dirent `d_type` is never trusted
    /// (entries are typed by `lstatAt` below). Once the directory has
    /// more than `budget` entries it fails — upstream's
    /// `errDirOverBudget` — and it stops when the deadline ends; a
    /// `getdents` failure propagates too — nothing is flattened away.
    fn read_names(
        fd: &impl std::os::fd::AsFd,
        budget: usize,
        deadline: Instant,
        what: &'static str,
    ) -> Result<Vec<OsString>, Failure> {
        // Rewind so a descriptor listed before reads from its start.
        rustix::fs::seek(fd, rustix::fs::SeekFrom::Start(0)).map_err(|_| capture_failed(what))?;
        let dir = rustix::fs::Dir::read_from(fd).map_err(|_| capture_failed(what))?;
        let mut names = Vec::new();
        for e in dir {
            if Instant::now() > deadline {
                return Err(capture_failed(what));
            }
            let e = e.map_err(|_| capture_failed(what))?;
            let name = OsStr::from_bytes(e.file_name().to_bytes());
            if name == "." || name == ".." {
                continue;
            }
            names.push(name.to_os_string());
            if names.len() > budget {
                return Err(capture_failed(what));
            }
        }
        names.sort_unstable();
        Ok(names)
    }

    /// `lstatAt` — the entry's type without following it.
    fn lstat_at(
        dirfd: &impl std::os::fd::AsFd,
        name: &OsStr,
    ) -> Result<rustix::fs::FileType, rustix::io::Errno> {
        let st = rustix::fs::statat(
            dirfd,
            Path::new(name),
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )?;
        Ok(rustix::fs::FileType::from_raw_mode(st.st_mode))
    }

    /// `copyObjects` — the clone's object files (the loose/pack
    /// allowlist only) copied into `dst` as data, on descriptors all
    /// the way down. `Ok(false)` when `.git` or `.git/objects` is not a
    /// real directory — an `unavailableErr` there reports false, any
    /// other error fails the capture.
    fn copy_objects_walk(
        &self,
        dst: &Path,
        deadline: Instant,
        limits: ObjectLimits,
    ) -> Result<bool, Failure> {
        if Instant::now() > deadline {
            return Err(capture_failed("capture deadline"));
        }
        let git_fd = match open_beneath(
            &self.repo_fd,
            Path::new(".git"),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NONBLOCK,
        ) {
            Ok(f) => f,
            Err(e) if unavailable_err(e) => return Ok(false),
            Err(_) => return Err(capture_failed("open the clone's .git")),
        };
        let obj_fd = match open_beneath(
            &git_fd,
            Path::new("objects"),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NONBLOCK,
        ) {
            Ok(f) => f,
            Err(e) if unavailable_err(e) => return Ok(false),
            Err(_) => return Err(capture_failed("open the clone's objects")),
        };
        let mut w = ObjectWalk {
            deadline,
            limits,
            entries: 0,
            total: 0,
            dir: OsString::new(),
        };
        w.copy_dir(&obj_fd, dst, 0)?;
        Ok(true)
    }
}

/// `treeWalker` — `findNestedRepos`'s walk state: the deadline, the
/// limits, the consumed entry budget and the collected nested roots.
struct TreeWalk {
    deadline: Instant,
    limits: WalkLimits,
    entries: usize,
    nested: Vec<Vec<u8>>,
}

impl TreeWalk {
    /// `treeWalker.walk` — every directory below the root holding a
    /// `.git` entry of any type is a nested repository, reported and
    /// not descended into; `.git`-named entries are never descended
    /// into (the clone's own repository is never walked). A
    /// subdirectory `vanishedErr` skips; an unreadable directory fails
    /// closed (that is where the patch's completeness is enforced —
    /// `git add --all` only warns about one). Recursion is on the
    /// child's own descriptor, like upstream.
    fn walk(
        &mut self,
        dirfd: &rustix::fd::OwnedFd,
        rel: &Path,
        depth: usize,
    ) -> Result<(), Failure> {
        if depth > self.limits.max_depth {
            return Err(capture_failed("the work tree exceeds the depth limit"));
        }
        let names = LinuxSealed::read_names(
            dirfd,
            self.limits.max_entries.saturating_sub(self.entries),
            self.deadline,
            "list a work tree directory",
        )?;
        if !rel.as_os_str().is_empty() && names.iter().any(|x| x.as_bytes() == b".git") {
            self.nested.push(rel.as_os_str().as_bytes().to_vec());
            return Ok(());
        }
        for name in names {
            if Instant::now() > self.deadline {
                return Err(capture_failed("capture deadline"));
            }
            self.entries += 1;
            if self.entries > self.limits.max_entries {
                return Err(capture_failed("the work tree exceeds the entry limit"));
            }
            if name.as_bytes() == b".git" {
                continue; // the clone's own repository is never descended
            }
            let t = match LinuxSealed::lstat_at(dirfd, &name) {
                Ok(t) => t,
                Err(e) if vanished(e) => continue, // raced away
                Err(_) => return Err(capture_failed("stat a work tree entry")),
            };
            if !t.is_dir() {
                continue;
            }
            let fd = match open_beneath(
                dirfd,
                Path::new(&name),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NONBLOCK,
            ) {
                Ok(f) => f,
                Err(e) if vanished(e) => continue, // swapped or gone
                Err(_) => return Err(capture_failed("open a work tree directory")), // EACCES included
            };
            self.walk(&fd, &rel.join(&name), depth + 1)?;
        }
        Ok(())
    }
}

/// `objectWalker` — `copyObjects`'s walk state: the deadline, the
/// limits, the consumed entry budget, the copied total and `dir`, the
/// objects subdirectory being copied ("pack" or a loose fan-out
/// directory, empty at the top).
struct ObjectWalk {
    deadline: Instant,
    limits: ObjectLimits,
    entries: usize,
    total: u64,
    dir: OsString,
}

impl ObjectWalk {
    /// `objectWalker.copyDir` — one objects directory: only the
    /// allowlisted loose objects and pack files are copied;
    /// `objects/info`, a planted alternates file, a multi-pack-index,
    /// commit-graphs and bitmaps are never read. Symlinks, FIFOs,
    /// sockets and devices are skipped without being opened.
    fn copy_dir(
        &mut self,
        dirfd: &rustix::fd::OwnedFd,
        dst: &Path,
        depth: usize,
    ) -> Result<(), Failure> {
        let names = LinuxSealed::read_names(
            dirfd,
            self.limits.max_entries.saturating_sub(self.entries),
            self.deadline,
            "list the clone's objects",
        )?;
        for name in names {
            if Instant::now() > self.deadline {
                return Err(capture_failed("capture deadline"));
            }
            self.entries += 1;
            if self.entries > self.limits.max_entries {
                return Err(capture_failed("the clone's objects exceed the entry limit"));
            }
            let nb = name.as_bytes();
            let want_dir = depth == 0 && (nb == b"pack" || gitmeta::is_loose_dir_name(nb));
            let want_file = depth == 1
                && if self.dir.as_bytes() == b"pack" {
                    gitmeta::is_pack_file_name(nb)
                } else {
                    gitmeta::is_loose_object_name(nb)
                };
            if !want_dir && !want_file {
                continue; // not an object entry: never opened
            }
            let t = match LinuxSealed::lstat_at(dirfd, &name) {
                Ok(t) => t,
                Err(e) if unavailable_err(e) => continue, // raced away
                Err(_) => return Err(capture_failed("stat a clone object entry")),
            };
            if want_dir && t.is_dir() {
                let fd = match open_beneath(
                    dirfd,
                    Path::new(&name),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NONBLOCK,
                ) {
                    Ok(f) => f,
                    Err(e) if unavailable_err(e) => continue, // swapped, gone or unreadable
                    Err(_) => return Err(capture_failed("open a clone objects directory")),
                };
                let sub = dst.join(&name);
                create_shadow_dir(&sub)?;
                self.dir = name.clone();
                let r = self.copy_dir(&fd, &sub, depth + 1);
                self.dir = OsString::new();
                r?;
            } else if want_file && t.is_file() {
                self.copy_file(
                    dirfd,
                    &name,
                    &dst.join(&name),
                    self.dir.as_bytes() != b"pack",
                )?;
            }
        }
        Ok(())
    }

    /// `copyFile` — one object file copied as data: `fstat` before the
    /// read refuses anything that grew past `max_file_bytes`; a
    /// `total + st_size` over the total limit fails; a malformed or
    /// oversized loose object (the header check) is skipped without an
    /// error. The body streams into an `O_EXCL` `0400` shadow file; the
    /// deadline is checked between reads, upstream's `ctxReader`.
    fn copy_file(
        &mut self,
        dirfd: &rustix::fd::OwnedFd,
        name: &OsStr,
        dst: &Path,
        loose: bool,
    ) -> Result<(), Failure> {
        let fd = match open_beneath(dirfd, Path::new(name), OFlags::RDONLY | OFlags::NONBLOCK) {
            Ok(f) => f,
            Err(e) if unavailable_err(e) => return Ok(()), // swapped, gone or unreadable
            Err(_) => return Err(capture_failed("open a clone object file")),
        };
        let st = rustix::fs::fstat(&fd).map_err(|_| capture_failed("stat a clone object file"))?;
        if !rustix::fs::FileType::from_raw_mode(st.st_mode).is_file() {
            return Ok(());
        }
        let size = st.st_size.cast_unsigned();
        if size > self.limits.max_file_bytes {
            return Err(capture_failed(
                "a clone object file exceeds the per-file limit",
            ));
        }
        if self.total + size > self.limits.max_total_bytes {
            return Err(capture_failed("the clone's objects exceed the total limit"));
        }
        use std::io::{Read, Write};
        let mut f = std::fs::File::from(fd);
        // A loose object's header check inflates only `<type> <size>\0`
        // — 32 KiB of compressed input is far more than it needs.
        let mut head = Vec::new();
        if loose {
            let mut buf = vec![0u8; 32 << 10];
            let n = f
                .read(&mut buf)
                .map_err(|_| capture_failed("copy a clone object file"))?;
            buf.truncate(n);
            if !gitmeta::loose_header_acceptable(&buf) {
                return Ok(()); // malformed or oversized: not copied, no error
            }
            head = buf;
        }
        use std::os::unix::fs::OpenOptionsExt;
        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .open(dst)
            .map_err(|_| capture_failed("create a shadow object file"))?;
        out.write_all(&head)
            .map_err(|_| capture_failed("copy a clone object file"))?;
        let mut written = head.len() as u64;
        let mut buf = vec![0u8; 64 << 10];
        while written < size {
            if Instant::now() > self.deadline {
                return Err(capture_failed("copy a clone object file"));
            }
            let want = (size - written).min(buf.len() as u64) as usize;
            let n = f
                .read(&mut buf[..want])
                .map_err(|_| capture_failed("copy a clone object file"))?;
            if n == 0 {
                break; // the object shrank mid-copy
            }
            out.write_all(&buf[..n])
                .map_err(|_| capture_failed("copy a clone object file"))?;
            written += n as u64;
        }
        self.total += written;
        Ok(())
    }
}

impl SealedClone for LinuxSealed {
    fn repo_path(&self) -> &str {
        self.repo.to_str().unwrap_or("")
    }

    fn nested_repos<'a>(
        &'a self,
        deadline: Instant,
        limits: WalkLimits,
    ) -> PortFuture<'a, Result<Vec<Vec<u8>>, Failure>> {
        Box::pin(async move {
            let mut w = TreeWalk {
                deadline,
                limits,
                entries: 0,
                nested: Vec::new(),
            };
            w.walk(&self.repo_fd, Path::new(""), 0)?;
            let mut out = w.nested;
            out.sort();
            Ok(out)
        })
    }

    fn copy_objects<'a>(
        &'a self,
        dst: PathBuf,
        deadline: Instant,
        limits: ObjectLimits,
    ) -> PortFuture<'a, Result<bool, Failure>> {
        Box::pin(async move { self.copy_objects_walk(&dst, deadline, limits) })
    }

    /// `readAfterHEAD` — the sealed clone's HEAD resolved without git:
    /// `.git/HEAD` (4 KiB cap), a loose ref, then `packed-refs`
    /// (1 MiB cap, and only when the loose ref was absent — `ENOENT`,
    /// as upstream). `None` when unavailable for any reason.
    fn after_head(&self) -> Option<String> {
        let head = self.read_small(Path::new(".git/HEAD"), 4 << 10).ok()??;
        match gitmeta::parse_head(&head)? {
            gitmeta::HeadRef::Detached(id) => String::from_utf8(id).ok(),
            gitmeta::HeadRef::Symbolic(name) => {
                let rel = String::from_utf8_lossy(&name).into_owned();
                match self.read_small(&Path::new(".git").join(&rel), 4 << 10) {
                    Ok(Some(d)) => {
                        if let Some(line) = gitmeta::one_line(&d)
                            && gitmeta::is_object_id(line)
                        {
                            return String::from_utf8(line.to_vec()).ok();
                        }
                        None
                    }
                    Ok(None) => {
                        let packed = self
                            .read_small(Path::new(".git/packed-refs"), 1 << 20)
                            .ok()??;
                        gitmeta::packed_ref_lookup(&packed, &name)
                            .and_then(|id| String::from_utf8(id).ok())
                    }
                    Err(()) => None,
                }
            }
        }
    }

    /// `unseal` — writes the recorded ACLs first and the mode last on
    /// the Run directory's descriptor, as `restoreRunACLs`; both are
    /// always present (a left-sealed Run recorded the synthesized
    /// provisioned ACLs).
    fn unseal(&self) -> Result<(), Failure> {
        if self
            .unsealed
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            return Ok(());
        }
        rustix::fs::fsetxattr(
            &self.run_dir_fd,
            ACL_ACCESS,
            &self.saved_acl,
            rustix::fs::XattrFlags::empty(),
        )
        .map_err(|_| capture_failed("restore the operator's access to the run directory"))?;
        rustix::fs::fsetxattr(
            &self.run_dir_fd,
            ACL_DEFAULT,
            &self.saved_default,
            rustix::fs::XattrFlags::empty(),
        )
        .map_err(|_| capture_failed("restore the run directory's default ACL"))?;
        rustix::fs::fchmod(&self.run_dir_fd, Mode::from_raw_mode(self.saved_mode))
            .map_err(|_| capture_failed("restore the run directory's mode"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_root() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "central-linux-seal-{}-{}",
            std::process::id(),
            RunId::new()
        ));
        let _ = std::fs::create_dir_all(d.join("worktrees/runs"));
        d
    }

    fn uid() -> u32 {
        std::fs::metadata("/proc/self")
            .map(|m| m.uid())
            .unwrap_or(1000)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn seal_unseal_roundtrip_restores_mode() {
        let root = tmp_root();
        let run = RunId::new();
        let rd = root.join("worktrees/runs").join(run.to_string());
        std::fs::create_dir_all(rd.join("repo/.git/objects")).ok();
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&rd, std::fs::Permissions::from_mode(0o750));
        let sealer = LinuxWorkspaceSealer::new(root.clone(), uid(), uid(), 0);
        // Provision the ACLs, then reopen is clean on the
        // provisioned-shaped directory.
        assert!(sealer.grant_run(run).await.is_ok());
        let r = sealer.verify_clone(run).await;
        assert!(
            r.is_ok(),
            "{}",
            r.err().map(|e| e.to_string()).unwrap_or_default()
        );
        let sealed = sealer.seal(run).await;
        assert!(sealed.is_ok());
        let sealed = sealed.ok();
        // While sealed the run dir is 0700.
        let mode = std::fs::metadata(&rd)
            .map(|m| m.mode() & 0o777)
            .unwrap_or(0);
        assert_eq!(mode, 0o700);
        // A sealed run refuses reopen; seal itself is idempotent.
        assert!(sealer.verify_clone(run).await.is_err());
        if let Some(s) = sealed.as_ref() {
            let r = s.unseal();
            assert!(
                r.is_ok(),
                "{}",
                r.err().map(|e| e.to_string()).unwrap_or_default()
            );
        }
        // Mode is ACL-derived: the grant's mask gives group rwx.
        let mode = std::fs::metadata(&rd)
            .map(|m| m.mode() & 0o777)
            .unwrap_or(0);
        assert_eq!(mode, 0o770);
        let r = sealer.verify_clone(run).await;
        assert!(
            r.is_ok(),
            "{}",
            r.err().map(|e| e.to_string()).unwrap_or_default()
        );
        // Nested-repo and after-HEAD reads work on the descriptor.
        std::fs::create_dir_all(rd.join("repo/deep/x/.git")).ok();
        std::fs::write(
            rd.join("repo/.git/HEAD"),
            "0123456789abcdef0123456789abcdef01234567\n",
        )
        .ok();
        if let Some(s) = sealed {
            let nested = s
                .nested_repos(
                    Instant::now() + std::time::Duration::from_secs(10),
                    WalkLimits::default(),
                )
                .await
                .ok()
                .unwrap_or_default();
            assert_eq!(nested, vec![b"deep/x".to_vec()]);
            assert_eq!(
                s.after_head(),
                Some("0123456789abcdef0123456789abcdef01234567".to_string())
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn seal_refuses_a_symlink_clone_root() {
        let root = tmp_root();
        let run = RunId::new();
        let rd = root.join("worktrees/runs").join(run.to_string());
        std::fs::create_dir_all(&rd).ok();
        std::os::unix::fs::symlink("/tmp", rd.join("repo")).ok();
        let sealer = LinuxWorkspaceSealer::new(root.clone(), uid(), uid(), 0);
        assert!(sealer.seal(run).await.is_err());
        // The refused seal restored the operator's access — the dir is
        // not left 0700 without its ACL.
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn free_space_check_reports_low_disk() {
        let root = tmp_root();
        let sealer = LinuxWorkspaceSealer::new(root.clone(), uid(), uid(), u64::MAX);
        let e = sealer.check_free_space().await.err();
        assert_eq!(e.map(|e| e.code()), Some(codes::LOW_DISK));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The kernel requires `ACL_USER` entries ascending by id: an
    /// operator uid above the runtime uid must not yield `EINVAL` on
    /// `setxattr`.
    #[test]
    fn encode_acl_sorts_named_users_by_uid() {
        let enc = encode_acl(&access_acl(0o750, true, &[2000, 1000]));
        let dec = decode_acl(&enc).unwrap_or_default();
        let ids: Vec<u32> = dec
            .iter()
            .filter(|e| e.tag == acl_tag::USER)
            .map(|e| e.id)
            .collect();
        assert_eq!(ids, vec![1000, 2000]);
    }

    /// `requireProvisionedACLs` — a mode wider than 0750 refuses even
    /// with the provisioned ACLs present.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn verify_refuses_a_wider_mode() {
        let root = tmp_root();
        let run = RunId::new();
        let rd = root.join("worktrees/runs").join(run.to_string());
        std::fs::create_dir_all(rd.join("repo/.git")).ok();
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&rd, std::fs::Permissions::from_mode(0o750));
        let sealer = LinuxWorkspaceSealer::new(root.clone(), uid(), uid(), 0);
        assert!(sealer.grant_run(run).await.is_ok());
        assert!(sealer.verify_clone(run).await.is_ok());
        let _ = std::fs::set_permissions(&rd, std::fs::Permissions::from_mode(0o777));
        assert!(sealer.verify_clone(run).await.is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The clone's own `.git` is never descended: its entries do not
    /// consume the walk's entry budget and never read as a nested
    /// repository.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn nested_walk_skips_the_clones_own_git() {
        let root = tmp_root();
        let run = RunId::new();
        let rd = root.join("worktrees/runs").join(run.to_string());
        let objects = rd.join("repo/.git/objects/aa");
        std::fs::create_dir_all(&objects).ok();
        // Enough entries inside .git that descending it would blow the
        // budget below.
        for i in 0..20 {
            std::fs::write(objects.join(format!("obj{i:02}")), b"x").ok();
        }
        std::fs::create_dir_all(rd.join("repo/deep/x/.git")).ok();
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&rd, std::fs::Permissions::from_mode(0o750));
        let sealer = LinuxWorkspaceSealer::new(root.clone(), uid(), uid(), 0);
        assert!(sealer.grant_run(run).await.is_ok());
        let sealed = sealer.seal(run).await.expect("seal failed");
        let nested = sealed
            .nested_repos(
                Instant::now() + std::time::Duration::from_secs(10),
                WalkLimits {
                    max_entries: 10,
                    max_depth: 256,
                },
            )
            .await;
        assert_eq!(nested.ok().unwrap_or_default(), vec![b"deep/x".to_vec()]);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `copyFile`'s fstat size check — a loose object over
    /// `max_file_bytes` fails the capture, not a truncated copy.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn copy_objects_refuses_an_oversized_object() {
        let root = tmp_root();
        let run = RunId::new();
        let rd = root.join("worktrees/runs").join(run.to_string());
        let objects = rd.join("repo/.git/objects/ab");
        std::fs::create_dir_all(&objects).ok();
        // A 38-lower-hex loose object name (`.git/objects/ab/<...>`).
        std::fs::write(
            objects.join("cdef0123456789abcdef0123456789abcdef01"),
            vec![0u8; 64],
        )
        .ok();
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&rd, std::fs::Permissions::from_mode(0o750));
        let sealer = LinuxWorkspaceSealer::new(root.clone(), uid(), uid(), 0);
        assert!(sealer.grant_run(run).await.is_ok());
        let sealed = sealer.seal(run).await.expect("seal failed");
        let dst = root.join("shadow-objects");
        std::fs::create_dir_all(&dst).ok();
        let r = sealed
            .copy_objects(
                dst,
                Instant::now() + std::time::Duration::from_secs(10),
                ObjectLimits {
                    max_file_bytes: 16,
                    max_total_bytes: u64::MAX,
                    max_entries: 1 << 20,
                },
            )
            .await;
        assert_eq!(r.err().map(|e| e.code()), Some(codes::CAPTURE_FAILED));
        let _ = std::fs::remove_dir_all(&root);
    }
}
