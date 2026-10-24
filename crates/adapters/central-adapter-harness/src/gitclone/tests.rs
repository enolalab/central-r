//! Ported `gitclone` tests — temp-directory git fixtures for
//! provision, reopen, seal/capture and path-escape rejection, with the
//! filesystem-level in-memory sealer the D2 port substitutes for the
//! Linux ACL implementation.

use super::*;
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use std::sync::Mutex;

use central_foundation::failure::Failure;
use central_foundation::identity::{RunId, WorkspaceId};
use central_harness::app::ports::{ObjectLimits, WalkLimits, codes};
use central_harness::domain::Workspace;
use central_harness::gitmeta;
use central_harness::port::PortFuture;

/// The in-memory sealer of the D2 port's test side: filesystem-level
/// checks only — a real clone root under the Run directory, a seal that
/// flips the Run directory's mode, and plain-path implementations of
/// the walkers the Linux sealer runs on descriptors.
struct TestSealer {
    root: PathBuf,
    sealed: std::sync::Arc<Mutex<Vec<RunId>>>,
    free: u64,
    min_free: u64,
}

impl TestSealer {
    fn run_dir(&self, run: RunId) -> PathBuf {
        self.root
            .join("worktrees")
            .join("runs")
            .join(run.to_string())
    }
}

struct TestSealed {
    run_dir: PathBuf,
    repo: PathBuf,
    sealed: std::sync::Arc<Mutex<Vec<RunId>>>,
    run: RunId,
}

fn walk(
    base: &Path,
    dir: &Path,
    depth: usize,
    out: &mut Vec<Vec<u8>>,
    limits: WalkLimits,
    n: &mut usize,
) {
    if depth > limits.max_depth {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        *n += 1;
        if *n > limits.max_entries {
            return;
        }
        // `.git`-named entries are never descended — the clone's own
        // repository is not a nested one (upstream's name check).
        if e.file_name().as_encoded_bytes() == b".git" {
            continue;
        }
        let p = e.path();
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_dir() && !ft.is_symlink() {
            if p.join(".git").exists() {
                let rel = p.strip_prefix(base).unwrap_or(&p);
                let mut v = rel.as_os_str().as_encoded_bytes().to_vec();
                v.iter_mut().for_each(|b| {
                    if *b == std::path::MAIN_SEPARATOR as u8 {
                        *b = b'/';
                    }
                });
                out.push(v);
            } else {
                walk(base, &p, depth + 1, out, limits, n);
            }
        }
    }
}

impl central_harness::app::ports::SealedClone for TestSealed {
    fn repo_path(&self) -> &str {
        self.repo.to_str().unwrap_or("")
    }
    fn nested_repos<'a>(
        &'a self,
        _d: std::time::Instant,
        limits: WalkLimits,
    ) -> PortFuture<'a, Result<Vec<Vec<u8>>, Failure>> {
        Box::pin(async move {
            let mut out = Vec::new();
            let mut n = 0usize;
            let repo = self.repo.clone();
            tokio::task::spawn_blocking(move || {
                walk(&repo.clone(), &repo, 0, &mut out, limits, &mut n);
                out
            })
            .await
            .map(|mut o| {
                o.sort();
                o
            })
            .map_err(|_| Failure::internal(codes::CAPTURE_FAILED, "walk"))
        })
    }
    fn copy_objects<'a>(
        &'a self,
        dst: PathBuf,
        _d: std::time::Instant,
        limits: ObjectLimits,
    ) -> PortFuture<'a, Result<bool, Failure>> {
        Box::pin(async move {
            let src = self.repo.join(".git").join("objects");
            if !src.is_dir() {
                return Ok(false);
            }
            let mut total = 0u64;
            let mut entries = 0usize;
            for e in std::fs::read_dir(&src)
                .map_err(|_| Failure::internal(codes::CAPTURE_FAILED, "objects"))?
            {
                let e = e.map_err(|_| Failure::internal(codes::CAPTURE_FAILED, "objects"))?;
                entries += 1;
                if entries > limits.max_entries {
                    return Err(Failure::internal(codes::CAPTURE_FAILED, "entry cap"));
                }
                let name = e.file_name();
                let bytes = name.as_encoded_bytes();
                let ft = e
                    .file_type()
                    .map_err(|_| Failure::internal(codes::CAPTURE_FAILED, "objects"))?;
                if !ft.is_dir() || ft.is_symlink() {
                    continue;
                }
                if gitmeta::is_loose_dir_name(bytes) {
                    for obj in std::fs::read_dir(e.path())
                        .map_err(|_| Failure::internal(codes::CAPTURE_FAILED, "objects"))?
                    {
                        let obj =
                            obj.map_err(|_| Failure::internal(codes::CAPTURE_FAILED, "objects"))?;
                        entries += 1;
                        let oname = obj.file_name();
                        if !gitmeta::is_loose_object_name(oname.as_encoded_bytes()) {
                            continue;
                        }
                        let data = std::fs::read(obj.path())
                            .map_err(|_| Failure::internal(codes::CAPTURE_FAILED, "objects"))?;
                        if data.len() as u64 > limits.max_file_bytes {
                            return Err(Failure::internal(codes::CAPTURE_TOO_LARGE, "object"));
                        }
                        if !gitmeta::loose_header_acceptable(&data[..data.len().min(32 << 10)]) {
                            continue; // malformed: not copied, no error
                        }
                        total += data.len() as u64;
                        if total > limits.max_total_bytes {
                            return Err(Failure::internal(codes::CAPTURE_TOO_LARGE, "objects"));
                        }
                        let ddir = dst.join(e.file_name());
                        std::fs::create_dir_all(&ddir)
                            .map_err(|_| Failure::internal(codes::CAPTURE_FAILED, "objects"))?;
                        std::fs::write(ddir.join(&oname), &data)
                            .map_err(|_| Failure::internal(codes::CAPTURE_FAILED, "objects"))?;
                    }
                } else if bytes == b"pack" {
                    for pk in std::fs::read_dir(e.path())
                        .map_err(|_| Failure::internal(codes::CAPTURE_FAILED, "objects"))?
                    {
                        let pk =
                            pk.map_err(|_| Failure::internal(codes::CAPTURE_FAILED, "objects"))?;
                        entries += 1;
                        let pname = pk.file_name();
                        if !gitmeta::is_pack_file_name(pname.as_encoded_bytes()) {
                            continue;
                        }
                        let data = std::fs::read(pk.path())
                            .map_err(|_| Failure::internal(codes::CAPTURE_FAILED, "objects"))?;
                        total += data.len() as u64;
                        if total > limits.max_total_bytes
                            || data.len() as u64 > limits.max_file_bytes
                        {
                            return Err(Failure::internal(codes::CAPTURE_TOO_LARGE, "objects"));
                        }
                        let ddir = dst.join("pack");
                        std::fs::create_dir_all(&ddir)
                            .map_err(|_| Failure::internal(codes::CAPTURE_FAILED, "objects"))?;
                        std::fs::write(ddir.join(&pname), &data)
                            .map_err(|_| Failure::internal(codes::CAPTURE_FAILED, "objects"))?;
                    }
                }
            }
            Ok(true)
        })
    }
    fn after_head(&self) -> Option<String> {
        let head = std::fs::read(self.repo.join(".git").join("HEAD")).ok()?;
        match gitmeta::parse_head(&head)? {
            gitmeta::HeadRef::Detached(id) => String::from_utf8(id).ok(),
            gitmeta::HeadRef::Symbolic(name) => {
                let rel = String::from_utf8_lossy(&name).into_owned();
                let p = self.repo.join(".git").join(&rel);
                if let Ok(d) = std::fs::read(&p) {
                    return gitmeta::one_line(&d)
                        .filter(|l| gitmeta::is_object_id(l))
                        .and_then(|l| String::from_utf8(l.to_vec()).ok());
                }
                let packed = std::fs::read(self.repo.join(".git").join("packed-refs")).ok()?;
                gitmeta::packed_ref_lookup(&packed, &name).and_then(|id| String::from_utf8(id).ok())
            }
        }
    }
    fn unseal(&self) -> Result<(), Failure> {
        // Mode restore stands in for the ACL restore.
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&self.run_dir, std::fs::Permissions::from_mode(0o750));
        self.sealed
            .lock()
            .map(|mut v| v.retain(|r| *r != self.run))
            .ok();
        Ok(())
    }
}

impl central_harness::app::ports::WorkspaceSealer for TestSealer {
    fn check_free_space<'a>(&'a self) -> PortFuture<'a, Result<(), Failure>> {
        Box::pin(async move {
            if self.free < self.min_free {
                return Err(Failure::unavailable(codes::LOW_DISK, "low disk"));
            }
            Ok(())
        })
    }
    fn grant_run<'a>(&'a self, _run: RunId) -> PortFuture<'a, Result<(), Failure>> {
        Box::pin(async { Ok(()) })
    }
    fn verify_clone<'a>(&'a self, run: RunId) -> PortFuture<'a, Result<(), Failure>> {
        let sealed = self
            .sealed
            .lock()
            .map(|v| v.contains(&run))
            .unwrap_or(false);
        let repo = self.run_dir(run).join("repo");
        Box::pin(async move {
            if sealed || !repo.join(".git").is_dir() {
                return Err(Failure::unavailable(
                    codes::WORKSPACE_UNAVAILABLE,
                    "the clone is not the provisioned one",
                ));
            }
            Ok(())
        })
    }
    fn seal<'a>(
        &'a self,
        run: RunId,
    ) -> PortFuture<'a, Result<Box<dyn central_harness::app::ports::SealedClone>, Failure>> {
        let run_dir = self.run_dir(run);
        let repo = run_dir.join("repo");
        let sealed_list = self.sealed.lock().map(|v| v.clone()).unwrap_or_default();
        let already = sealed_list.contains(&run);
        Box::pin(async move {
            if already || !repo.join(".git").is_dir() {
                return Err(Failure::internal(codes::CAPTURE_FAILED, "seal"));
            }
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&run_dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|_| Failure::internal(codes::CAPTURE_FAILED, "seal"))?;
            if let Ok(mut v) = self.sealed.lock() {
                v.push(run);
            }
            Ok(Box::new(TestSealed {
                run_dir,
                repo,
                sealed: std::sync::Arc::clone(&self.sealed),
                run,
            })
                as Box<dyn central_harness::app::ports::SealedClone>)
        })
    }
    fn limit_process_memory<'a>(
        &'a self,
        _pid: u32,
        _bytes: u64,
    ) -> PortFuture<'a, Result<(), Failure>> {
        Box::pin(async { Ok(()) })
    }
}

/// A test harness: data root + initialized bare source with one commit
/// and a file.
struct Fixture {
    root: PathBuf,
    ws: WorkspaceId,
    git: GitClone,
}

fn git(dir: &Path, args: &[&str]) {
    let o = StdCommand::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("HOME", "/nonexistent")
        .output()
        .unwrap();
    assert!(
        o.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
}

fn fixture() -> Option<Fixture> {
    fixture_at(None)
}

/// `fixture` with a custom `git_path` — the provisioner still runs it
/// with its closed environment, so a script can wrap the real binary.
fn fixture_at(git_path: Option<String>) -> Option<Fixture> {
    if StdCommand::new("git").arg("--version").output().is_err() {
        return None; // no git on this host
    }
    let unique = std::env::temp_dir().join(format!(
        "central-gitclone-test-{}-{}",
        std::process::id(),
        RunId::new()
    ));
    let root = unique.join("data");
    let ws = WorkspaceId::new();
    let src_seed = unique.join("seed");
    let src = root.join("sources").join(format!("{ws}.git"));
    std::fs::create_dir_all(&src_seed).ok()?;
    git(&src_seed, &["init", "--quiet"]);
    std::fs::write(src_seed.join("a.txt"), "one\n").ok()?;
    git(&src_seed, &["add", "a.txt"]);
    git(
        &src_seed,
        &[
            "-c",
            "user.email=t@t",
            "-c",
            "user.name=t",
            "commit",
            "--quiet",
            "-m",
            "one",
        ],
    );
    std::fs::create_dir_all(src.parent()?).ok()?;
    git(
        &unique,
        &[
            "clone",
            "--quiet",
            "--bare",
            &src_seed.to_string_lossy(),
            &src.to_string_lossy(),
        ],
    );
    std::fs::create_dir_all(root.join("worktrees/runs")).ok()?;
    std::fs::create_dir_all(root.join("capture/tmp")).ok()?;
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(root.join("capture"), std::fs::Permissions::from_mode(0o700));
    let _ = std::fs::set_permissions(
        root.join("capture/tmp"),
        std::fs::Permissions::from_mode(0o700),
    );
    let uid = libc_uid();
    let cfg = GitCloneConfig {
        data_root: root.clone(),
        git_path: git_path.unwrap_or_default(),
        operator_uid: uid,
        runtime_uid: uid,
        ..GitCloneConfig::default()
    };
    let sealer = std::sync::Arc::new(TestSealer {
        root: root.clone(),
        sealed: std::sync::Arc::new(Mutex::new(Vec::new())),
        free: u64::MAX,
        min_free: 0,
    });
    let git = GitClone::new(cfg, sealer).ok()?;
    Some(Fixture { root, ws, git })
}

fn libc_uid() -> u32 {
    // uid via statfs of / is wrong; ask the OS through /proc/self.
    std::fs::metadata("/proc/self")
        .map(|m| {
            use std::os::unix::fs::MetadataExt;
            m.uid()
        })
        .unwrap_or(1000)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provision_clones_and_records_base() {
    let Some(f) = fixture() else { return };
    let run = RunId::new();
    let ws = central_harness::app::ports::WorkspaceProvisioner::provision(&f.git, f.ws, run)
        .await
        .map_err(|e| e.to_string());
    let ws = ws.ok().unwrap_or_default();
    assert!(!ws.base_sha.is_empty());
    assert!(Path::new(&ws.path).join(".git").is_dir());
    assert!(ws.path.ends_with(&format!("{}/repo", run)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provision_git_runs_past_the_wait_delay() {
    // A provisioning git command is unbounded: a git binary that
    // sleeps past `GIT_WAIT_DELAY` on the clone still provisions —
    // the delay bounds only the post-exit pipe drain.
    let unique = std::env::temp_dir().join(format!(
        "central-gitclone-fakegit-{}-{}",
        std::process::id(),
        RunId::new()
    ));
    std::fs::create_dir_all(&unique).unwrap_or_default();
    let fake = unique.join("fake-git");
    std::fs::write(
        &fake,
        "#!/bin/sh\ncase \" $*\" in\n*\" clone \"*) sleep 6 ;;\nesac\nexec /usr/bin/git \"$@\"\n",
    )
    .unwrap_or_default();
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755));
    let Some(f) = fixture_at(Some(fake.to_string_lossy().into_owned())) else {
        return;
    };
    let run = RunId::new();
    let ws = central_harness::app::ports::WorkspaceProvisioner::provision(&f.git, f.ws, run)
        .await
        .map_err(|e| e.to_string());
    let _ = std::fs::remove_dir_all(&unique);
    let ws = ws.ok().unwrap_or_default();
    assert!(!ws.base_sha.is_empty());
    assert!(Path::new(&ws.path).join(".git").is_dir());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provision_missing_source_refused() {
    let Some(f) = fixture() else { return };
    let run = RunId::new();
    let r = central_harness::app::ports::WorkspaceProvisioner::provision(
        &f.git,
        WorkspaceId::new(),
        run,
    )
    .await;
    assert_eq!(
        r.err().map(|e| e.code()),
        Some(super::codes::SOURCE_MISSING)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reopen_verifies_without_git() {
    let Some(f) = fixture() else { return };
    let run = RunId::new();
    let ws = central_harness::app::ports::WorkspaceProvisioner::provision(&f.git, f.ws, run)
        .await
        .ok()
        .unwrap_or_default();
    let r =
        central_harness::app::ports::WorkspaceProvisioner::reopen(&f.git, f.ws, run, ws.clone())
            .await;
    assert!(r.is_ok());
    // A foreign workspace path is refused.
    let bad = Workspace {
        path: "/tmp/elsewhere".into(),
        base_sha: ws.base_sha,
    };
    assert!(
        central_harness::app::ports::WorkspaceProvisioner::reopen(&f.git, f.ws, run, bad)
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capture_writes_patch_and_commits() {
    let Some(f) = fixture() else { return };
    let run = RunId::new();
    let ws = central_harness::app::ports::WorkspaceProvisioner::provision(&f.git, f.ws, run)
        .await
        .ok()
        .unwrap_or_default();
    let repo = PathBuf::from(&ws.path);
    // A tracked change plus a new commit on the clone's branch.
    std::fs::write(repo.join("a.txt"), "two\n").unwrap_or(());
    std::fs::write(repo.join("new.txt"), "fresh\n").unwrap_or(());
    git(&repo, &["add", "-A"]);
    git(
        &repo,
        &[
            "-c",
            "user.email=t@t",
            "-c",
            "user.name=t",
            "commit",
            "--quiet",
            "-m",
            "two",
        ],
    );
    let cap = central_harness::app::ports::WorkspaceCapture::capture(&f.git, f.ws, ws.clone(), run)
        .await
        .ok()
        .unwrap_or_default();
    assert!(!cap.after_head.is_empty() && cap.after_head != ws.base_sha);
    let patch = std::fs::read_to_string(&cap.patch).unwrap_or_default();
    assert!(patch.contains("a.txt") && patch.contains("+two"));
    let commits = std::fs::read_to_string(&cap.commits).unwrap_or_default();
    assert!(commits.contains(&format!("before HEAD: {}", ws.base_sha)));
    assert!(commits.contains(&format!("after HEAD: {}", cap.after_head)));
    assert!(commits.contains("commits: 1"));
    // Release removes the capture files; it is idempotent.
    let _ = central_harness::app::ports::WorkspaceCapture::release(&f.git, run).await;
    assert!(!Path::new(&cap.patch).exists());
    let _ = central_harness::app::ports::WorkspaceCapture::release(&f.git, run).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capture_without_changes_writes_fixed_lines() {
    let Some(f) = fixture() else { return };
    let run = RunId::new();
    let ws = central_harness::app::ports::WorkspaceProvisioner::provision(&f.git, f.ws, run)
        .await
        .ok()
        .unwrap_or_default();
    let cap =
        central_harness::app::ports::WorkspaceCapture::capture(&f.git, f.ws, ws.clone(), run).await;
    let cap = match cap {
        Ok(c) => c,
        Err(e) => {
            unreachable!("capture failed: {e}");
        }
    };
    let patch = std::fs::read_to_string(&cap.patch).unwrap_or_default();
    assert_eq!(patch, capture::PATCH_NO_CHANGES_LINE);
    // No new commit: after == base (the source holds it).
    assert_eq!(cap.after_head, ws.base_sha);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capture_excludes_nested_repositories() {
    let Some(f) = fixture() else { return };
    let run = RunId::new();
    let ws = central_harness::app::ports::WorkspaceProvisioner::provision(&f.git, f.ws, run)
        .await
        .ok()
        .unwrap_or_default();
    let repo = PathBuf::from(&ws.path);
    let nested = repo.join("deep").join("x");
    std::fs::create_dir_all(&nested).unwrap_or(());
    git(&nested, &["init", "--quiet"]);
    std::fs::write(nested.join("inside.txt"), "hidden\n").unwrap_or(());
    git(&nested, &["add", "inside.txt"]);
    git(
        &nested,
        &[
            "-c",
            "user.email=t@t",
            "-c",
            "user.name=t",
            "commit",
            "--quiet",
            "-m",
            "n",
        ],
    );
    let cap = central_harness::app::ports::WorkspaceCapture::capture(&f.git, f.ws, ws, run)
        .await
        .ok()
        .unwrap_or_default();
    let patch = std::fs::read_to_string(&cap.patch).unwrap_or_default();
    assert!(patch.starts_with(capture::PATCH_EXCLUDED_PREFIX));
    assert!(patch.contains("\"deep/x\""));
    assert!(!patch.contains("inside.txt"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capture_rejects_foreign_workspace() {
    let Some(f) = fixture() else { return };
    let run = RunId::new();
    let _ = central_harness::app::ports::WorkspaceProvisioner::provision(&f.git, f.ws, run).await;
    let bad = Workspace {
        path: "/tmp".into(),
        base_sha: "0123456789abcdef0123456789abcdef01234567".into(),
    };
    let e = central_harness::app::ports::WorkspaceCapture::capture(&f.git, f.ws, bad, run)
        .await
        .err();
    assert_eq!(e.map(|e| e.code()), Some(codes::CAPTURE_FAILED));
    // A malformed base sha is refused too (path escape via `..` would
    // not be an object id; the record match is the guard).
    let bad2 = Workspace {
        path: f
            .root
            .join("worktrees/runs")
            .join(run.to_string())
            .join("repo")
            .to_string_lossy()
            .into_owned(),
        base_sha: "deadbeef".into(),
    };
    assert!(
        central_harness::app::ports::WorkspaceCapture::capture(&f.git, f.ws, bad2, run)
            .await
            .is_err()
    );
}
