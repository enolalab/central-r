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
/// (u16 tag, u16 perm, u32 id) records.
fn encode_acl(entries: &[AclEntry]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + entries.len() * 8);
    v.extend_from_slice(&ACL_VERSION.to_le_bytes());
    for e in entries {
        v.extend_from_slice(&e.tag.to_le_bytes());
        v.extend_from_slice(&e.perm.to_le_bytes());
        v.extend_from_slice(&e.id.to_le_bytes());
    }
    v
}

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

/// The provisioned ACL for one tree member: `u::<grantee>:rwX` per
/// grantee (X = the execute bit directories and executable files get),
/// group and other closed.
fn grant_acl(uids: &[u32], executable: bool) -> Vec<AclEntry> {
    let perm = if executable { 0o7 } else { 0o6 };
    let mut e = vec![AclEntry {
        tag: acl_tag::USER_OBJ,
        perm,
        id: ACL_UNDEF,
    }];
    for &u in uids {
        e.push(AclEntry {
            tag: acl_tag::USER,
            perm,
            id: u,
        });
    }
    e.push(AclEntry {
        tag: acl_tag::GROUP_OBJ,
        perm: 0,
        id: ACL_UNDEF,
    });
    e.push(AclEntry {
        tag: acl_tag::MASK,
        perm,
        id: ACL_UNDEF,
    });
    e.push(AclEntry {
        tag: acl_tag::OTHER,
        perm: 0,
        id: ACL_UNDEF,
    });
    e
}

/// The sealed ACL — the provisioned ACL minus every named user (the
/// operator's access is what seal removes); owner perms stay 0700's.
fn sealed_acl(saved: &[AclEntry]) -> Vec<AclEntry> {
    saved
        .iter()
        .copied()
        .filter(|e| e.tag != acl_tag::USER)
        .collect()
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
        oflags,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
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
    /// runtime-owned directory still carrying the provisioned ACL (a
    /// half-sealed Run is refused, never repaired), and `repo` is a
    /// real runtime-owned directory.
    fn verify_clone<'a>(&'a self, run: RunId) -> PortFuture<'a, Result<(), Failure>> {
        let run_dir = self.run_dir(run);
        let runtime_uid = self.runtime_uid;
        Box::pin(async move {
            let rd = run_dir.clone();
            tokio::task::spawn_blocking(move || verify_clone(&rd, runtime_uid))
                .await
                .map_err(|_| unavailable("verify the clone"))?
        })
    }

    /// `seal` — `seal_linux.go`: take the operator's access away,
    /// verify the clone root through `openat2`, hand back the handle.
    fn seal<'a>(&'a self, run: RunId) -> PortFuture<'a, Result<Box<dyn SealedClone>, Failure>> {
        let run_dir = self.run_dir(run);
        let runtime_uid = self.runtime_uid;
        Box::pin(async move {
            let rd = run_dir.clone();
            tokio::task::spawn_blocking(move || seal_run(&rd, runtime_uid))
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

/// Post-order tree walk applying the grant ACL — children before their
/// directory (S4), the `root` directory last.
fn grant_tree(root: &Path, uids: &[u32]) -> Result<(), Failure> {
    let md = std::fs::symlink_metadata(root).map_err(|_| unavailable("grant the run ACLs"))?;
    if !md.is_dir() || md.file_type().is_symlink() {
        return Err(unavailable("the run directory is not a real directory"));
    }
    grant_dir(root, uids)
}

fn grant_dir(dir: &Path, uids: &[u32]) -> Result<(), Failure> {
    let mut members = Vec::new();
    for e in std::fs::read_dir(dir).map_err(|_| unavailable("grant the run ACLs"))? {
        let e = e.map_err(|_| unavailable("grant the run ACLs"))?;
        members.push(e.path());
    }
    for p in &members {
        let ft = std::fs::symlink_metadata(p)
            .map_err(|_| unavailable("grant the run ACLs"))?
            .file_type();
        if ft.is_symlink() {
            continue; // ACLs are not granted through symlinks
        }
        if ft.is_dir() {
            grant_dir(p, uids)?;
        }
        apply_acl(p, uids, ft.is_dir())?;
    }
    apply_acl(dir, uids, true)
}

fn apply_acl(path: &Path, uids: &[u32], is_dir: bool) -> Result<(), Failure> {
    let md = std::fs::symlink_metadata(path).map_err(|_| unavailable("grant the run ACLs"))?;
    let executable = is_dir || md.mode() & 0o111 != 0;
    let acl = encode_acl(&grant_acl(uids, executable));
    rustix::fs::setxattr(path, ACL_ACCESS, &acl, rustix::fs::XattrFlags::empty())
        .map_err(|_| unavailable("grant the run ACLs"))?;
    if is_dir {
        rustix::fs::setxattr(path, ACL_DEFAULT, &acl, rustix::fs::XattrFlags::empty())
            .map_err(|_| unavailable("grant the run ACLs"))?;
    }
    Ok(())
}

/// `Reopen`'s fd checks — Run dir real dir, runtime-owned, still
/// carrying at least the base access ACL entries; `repo` real dir,
/// runtime-owned.
fn verify_clone(run_dir: &Path, runtime_uid: u32) -> Result<(), Failure> {
    let d = rustix::fs::openat(
        rustix::fs::CWD,
        run_dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| unavailable("open the run directory"))?;
    let st = fstat_kind(&d).map_err(|_| unavailable("stat the run directory"))?;
    if !rustix::fs::FileType::from_raw_mode(st.st_mode).is_dir()
        || st.st_uid != runtime_uid
        || st.st_mode & 0o777 == 0o700
    {
        // A 0700 Run directory is a sealed or half-sealed one — refuse,
        // never repair.
        return Err(unavailable("the run directory is not the provisioned one"));
    }
    let mut acl = vec![0u8; 1 << 12];
    let n = rustix::fs::fgetxattr(&d, ACL_ACCESS, &mut acl)
        .map_err(|_| unavailable("read the run directory ACL"))?;
    acl.truncate(n);
    let entries = decode_acl(&acl).unwrap_or_default();
    if !entries.iter().any(|e| e.tag == acl_tag::USER_OBJ) {
        return Err(unavailable(
            "the run directory ACL is not the provisioned one",
        ));
    }
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

/// `seal` — record the Run directory's ACL and mode, verify the clone
/// root beneath it, then remove the operator's access (0700 + ACL
/// minus named users). A refused seal restores the operator's access.
fn seal_run(run_dir: &Path, runtime_uid: u32) -> Result<LinuxSealed, Failure> {
    let d = rustix::fs::openat(
        rustix::fs::CWD,
        run_dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| capture_failed("open the run directory"))?;
    let st = fstat_kind(&d)?;
    if !rustix::fs::FileType::from_raw_mode(st.st_mode).is_dir() || st.st_uid != runtime_uid {
        return Err(capture_failed("the run directory is not runtime-owned"));
    }
    let saved_mode = st.st_mode & 0o7777;
    let mut saved_acl = vec![0u8; 1 << 16];
    let saved_acl = rustix::fs::fgetxattr(&d, ACL_ACCESS, &mut saved_acl)
        .map(|n| {
            saved_acl.truncate(n);
            saved_acl.clone()
        })
        .unwrap_or_default();
    let mut saved_default = vec![0u8; 1 << 16];
    let saved_default = rustix::fs::fgetxattr(&d, ACL_DEFAULT, &mut saved_default)
        .map(|n| {
            saved_default.truncate(n);
            saved_default.clone()
        })
        .unwrap_or_default();
    // Verify the clone root beneath the run dir before sealing.
    let repo_fd = open_beneath(&d, Path::new("repo"), OFlags::RDONLY | OFlags::DIRECTORY)
        .map_err(|_| capture_failed("open the clone root"))?;
    let rst = fstat_kind(&repo_fd)?;
    if !rustix::fs::FileType::from_raw_mode(rst.st_mode).is_dir() || rst.st_uid != runtime_uid {
        return Err(capture_failed(
            "the clone root is not a runtime-owned directory",
        ));
    }
    // Seal: the run dir goes 0700 and its access ACL loses every named
    // user — the operator's access is gone.
    let sealed = sealed_acl(&decode_acl(&saved_acl).unwrap_or_default());
    let acl_entries = if sealed.is_empty() {
        grant_acl(&[], true)
    } else {
        sealed
    };
    let acl_bytes = encode_acl(&acl_entries);
    if let Err(e) =
        rustix::fs::fsetxattr(&d, ACL_ACCESS, &acl_bytes, rustix::fs::XattrFlags::empty())
            .and_then(|_| rustix::fs::fchmod(&d, Mode::from_raw_mode(0o700)))
    {
        // Restore what we recorded; report the seal refusal after.
        let _ = rustix::fs::fsetxattr(&d, ACL_ACCESS, &saved_acl, rustix::fs::XattrFlags::empty());
        let _ = e;
        return Err(capture_failed("seal the run directory"));
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

impl LinuxSealed {
    /// Reads a bounded regular file beneath the clone root — HEAD,
    /// a loose ref, packed-refs. `cap` is 4 KiB (HEAD/ref) or 1 MiB
    /// (packed-refs). `O_NONBLOCK` + the regular-file `fstat` check keep
    /// a FIFO or device from blocking the read.
    fn read_bounded(&self, rel: &Path, cap: u64) -> Option<Vec<u8>> {
        let fd = open_beneath(
            &self.repo_fd,
            rel,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW,
        )
        .ok()?;
        let st = rustix::fs::fstat(&fd).ok()?;
        if !rustix::fs::FileType::from_raw_mode(st.st_mode).is_file() {
            return None;
        }
        let f = std::fs::File::from(fd);
        use std::io::Read;
        let mut out = Vec::new();
        let _ = f.take(cap).read_to_end(&mut out).ok()?;
        Some(out)
    }

    /// One directory listing beneath the clone root.
    fn list(&self, rel: &Path) -> Option<Vec<(OsString, rustix::fs::FileType)>> {
        let rel = if rel.as_os_str().is_empty() {
            Path::new(".")
        } else {
            rel
        };
        let fd = open_beneath(&self.repo_fd, rel, OFlags::RDONLY | OFlags::DIRECTORY).ok()?;
        let st = rustix::fs::fstat(&fd).ok()?;
        if !rustix::fs::FileType::from_raw_mode(st.st_mode).is_dir() {
            return None;
        }
        let dir = rustix::fs::Dir::read_from(&fd).ok()?;
        let mut out = Vec::new();
        for e in dir.flatten() {
            let name = OsStr::from_bytes(e.file_name().to_bytes());
            if name == "." || name == ".." {
                continue;
            }
            out.push((name.to_os_string(), e.file_type()));
        }
        Some(out)
    }

    /// `findNestedRepos`'s walk and `copyObjects`'s object walk share
    /// this beneath-opened directory recursion on relative paths.
    fn nested_walk(
        &self,
        rel: &Path,
        depth: usize,
        limits: WalkLimits,
        deadline: Instant,
        n: &mut usize,
        out: &mut Vec<Vec<u8>>,
    ) -> Result<(), Failure> {
        if depth > limits.max_depth || Instant::now() > deadline {
            return Err(capture_failed("walk the work tree"));
        }
        let Some(entries) = self.list(rel) else {
            return Ok(()); // not a real directory: skipped, not fatal
        };
        let mut has_git = false;
        for (name, _t) in &entries {
            if name.as_bytes() == b".git" {
                has_git = true;
            }
        }
        if has_git && rel != Path::new("") {
            out.push(rel.as_os_str().as_bytes().to_vec());
            return Ok(());
        }
        for (name, t) in entries {
            *n += 1;
            if *n > limits.max_entries || Instant::now() > deadline {
                return Err(capture_failed("walk the work tree"));
            }
            if t.is_dir() {
                self.nested_walk(&rel.join(&name), depth + 1, limits, deadline, n, out)?;
            }
        }
        Ok(())
    }

    fn copy_objects_walk(
        &self,
        dst: &Path,
        deadline: Instant,
        limits: ObjectLimits,
    ) -> Result<bool, Failure> {
        // .git and .git/objects must be real directories opened beneath
        // the clone root.
        if self.list(Path::new(".git")).is_none() || self.list(Path::new(".git/objects")).is_none()
        {
            return Ok(false);
        }
        let mut entries_n = 0usize;
        let mut total = 0u64;
        let Some(top) = self.list(Path::new(".git/objects")) else {
            return Ok(false);
        };
        for (name, t) in top {
            entries_n += 1;
            if entries_n > limits.max_entries || Instant::now() > deadline {
                return Err(capture_failed("copy the clone objects"));
            }
            if !t.is_dir() {
                continue;
            }
            let nb = name.as_bytes();
            if gitmeta::is_loose_dir_name(nb) {
                let sub = Path::new(".git/objects").join(&name);
                let Some(loose) = self.list(&sub) else {
                    continue;
                };
                for (oname, ot) in loose {
                    entries_n += 1;
                    if entries_n > limits.max_entries {
                        return Err(capture_failed("copy the clone objects"));
                    }
                    if !ot.is_file() || !gitmeta::is_loose_object_name(oname.as_bytes()) {
                        continue;
                    }
                    let rel = sub.join(&oname);
                    let data = match self.read_bounded(&rel, limits.max_file_bytes) {
                        Some(d) => d,
                        None => continue,
                    };
                    if data.len() as u64 > limits.max_file_bytes {
                        return Err(Failure::internal(
                            codes::CAPTURE_TOO_LARGE,
                            "object file over its cap",
                        ));
                    }
                    if !gitmeta::loose_header_acceptable(&data[..data.len().min(32 << 10)]) {
                        continue; // malformed: not copied, no error
                    }
                    total += data.len() as u64;
                    if total > limits.max_total_bytes {
                        return Err(Failure::internal(
                            codes::CAPTURE_TOO_LARGE,
                            "objects over the total cap",
                        ));
                    }
                    let dd = dst.join(&name);
                    std::fs::create_dir_all(&dd)
                        .map_err(|_| capture_failed("write a shadow object"))?;
                    std::fs::write(dd.join(&oname), &data)
                        .map_err(|_| capture_failed("write a shadow object"))?;
                }
            } else if nb == b"pack" {
                let sub = Path::new(".git/objects/pack");
                let Some(packs) = self.list(sub) else {
                    continue;
                };
                for (pname, pt) in packs {
                    entries_n += 1;
                    if entries_n > limits.max_entries {
                        return Err(capture_failed("copy the clone objects"));
                    }
                    if !pt.is_file() || !gitmeta::is_pack_file_name(pname.as_bytes()) {
                        continue;
                    }
                    let data = match self.read_bounded(&sub.join(&pname), limits.max_file_bytes) {
                        Some(d) => d,
                        None => continue,
                    };
                    total += data.len() as u64;
                    if total > limits.max_total_bytes || data.len() as u64 > limits.max_file_bytes {
                        return Err(Failure::internal(
                            codes::CAPTURE_TOO_LARGE,
                            "objects over the cap",
                        ));
                    }
                    let dd = dst.join("pack");
                    std::fs::create_dir_all(&dd)
                        .map_err(|_| capture_failed("write a shadow object"))?;
                    std::fs::write(dd.join(&pname), &data)
                        .map_err(|_| capture_failed("write a shadow object"))?;
                }
            }
        }
        Ok(true)
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
            let mut out = Vec::new();
            let mut n = 0usize;
            self.nested_walk(Path::new(""), 0, limits, deadline, &mut n, &mut out)?;
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
    /// (1 MiB cap). `None` when unavailable for any reason.
    fn after_head(&self) -> Option<String> {
        let head = self.read_bounded(Path::new(".git/HEAD"), 4 << 10)?;
        match gitmeta::parse_head(&head)? {
            gitmeta::HeadRef::Detached(id) => String::from_utf8(id).ok(),
            gitmeta::HeadRef::Symbolic(name) => {
                let rel = String::from_utf8_lossy(&name).into_owned();
                if let Some(d) = self.read_bounded(&Path::new(".git").join(&rel), 4 << 10) {
                    if let Some(line) = gitmeta::one_line(&d)
                        && gitmeta::is_object_id(line)
                    {
                        return String::from_utf8(line.to_vec()).ok();
                    }
                    return None;
                }
                let packed = self.read_bounded(Path::new(".git/packed-refs"), 1 << 20)?;
                gitmeta::packed_ref_lookup(&packed, &name).and_then(|id| String::from_utf8(id).ok())
            }
        }
    }

    /// `unseal` — writes the recorded ACLs and mode back on the Run
    /// directory's descriptor.
    fn unseal(&self) -> Result<(), Failure> {
        if self
            .unsealed
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            return Ok(());
        }
        if !self.saved_acl.is_empty() {
            let _ = rustix::fs::fsetxattr(
                &self.run_dir_fd,
                ACL_ACCESS,
                &self.saved_acl,
                rustix::fs::XattrFlags::empty(),
            );
        }
        if !self.saved_default.is_empty() {
            let _ = rustix::fs::fsetxattr(
                &self.run_dir_fd,
                ACL_DEFAULT,
                &self.saved_default,
                rustix::fs::XattrFlags::empty(),
            );
        }
        rustix::fs::fchmod(&self.run_dir_fd, Mode::from_raw_mode(self.saved_mode))
            .map_err(|_| capture_failed("unseal the run directory"))
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
}
