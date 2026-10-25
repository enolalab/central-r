//! The Slice-2B dispatch workspace provisioner — the port of upstream
//! `internal/adapter/workspace/provision/provisioner.go`: the
//! [`central_scheduler::port::Provisioner`] implementation that gives
//! every claimed node an isolated workspace under the instance scratch
//! root (spec-2 locked input 3 — isolation is provisioned at dispatch,
//! never by the worker).
//!
//! Layout: `<scratch_root>/workspaces/<run-id>/<node-id>`. `worktree`
//! nodes get a detached git worktree added from the configured source
//! repository at the recorded base ref; `directory` nodes get a private
//! directory. Provisioning is at-least-once and idempotent (spec-5): a
//! re-prepare of the same `(run, node)` dedupes on the path via the
//! `.central-workspace-kind` marker written only after a complete
//! provision, while a partial leftover is pruned and re-created.
//!
//! Each workspace also carries a `.central-workspace-budget` marker
//! recording its disk byte cap — the locked defaults 8 GiB worktree /
//! 4 GiB directory (P2B06). The file documents the bound for the
//! harness and the sweeper; enforcement is the P2B06 sweep's, not this
//! module's.
//!
//! Git is executed only on repositories and worktrees Central owns,
//! with hooks, fsmonitor, prompts and ambient config disabled — the
//! same discipline `central-adapter-harness`'s gitclone runs under.
//!
//! OWNING PACKET: P2B02. SLICE: 2B (issue #93).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use central_foundation::failure::Failure;
use central_foundation::identity::{RunId, SessionAttemptId, WorkflowNodeId};
use central_scheduler::port::Provisioner;

/// `DefaultGitPath` — the git binary provision runs. It is never
/// resolved through `PATH`, matching gitclone's rule.
pub const DEFAULT_GIT_PATH: &str = "/usr/bin/git";

/// The locked spec-8 disk budget recorded in a worktree workspace's
/// `.central-workspace-budget` marker — 8 GiB (upstream
/// `BudgetWorktreeBytes`).
pub const BUDGET_WORKTREE_BYTES: u64 = 8 << 30;

/// The locked spec-8 disk budget recorded in a directory workspace's
/// `.central-workspace-budget` marker — 4 GiB (upstream
/// `BudgetDirectoryBytes`).
pub const BUDGET_DIRECTORY_BYTES: u64 = 4 << 30;

/// The subtree of the scratch root holding every dispatch workspace.
const WORKSPACES_DIR: &str = "workspaces";
/// The in-workspace marker recording which provisioner kind completed
/// the workspace. Its presence marks the provision complete —
/// re-prepare dedupes on it — so it is written last.
const KIND_MARKER: &str = ".central-workspace-kind";
/// The in-workspace marker recording the workspace's disk byte cap.
const BUDGET_MARKER: &str = ".central-workspace-budget";
/// Bounds the `git worktree remove` inside [`Provisioner::free`] and
/// the partial-leftover cleanup, whose port signature carries no
/// cancellation (upstream `freeTimeout`).
const GIT_OP_TIMEOUT: Duration = Duration::from_secs(30);

/// `workflow.WorkspaceKindWorktree`'s wire spelling.
const KIND_WORKTREE: &str = "worktree";
/// `workflow.WorkspaceKindDirectory`'s wire spelling.
const KIND_DIRECTORY: &str = "directory";

const CODE_INVALID_CONFIG: &str = "provision_invalid_config";
const CODE_UNKNOWN_KIND: &str = "provision_unknown_workspace_kind";
const CODE_SOURCE_REPO_REQUIRED: &str = "provision_source_repo_required";
const CODE_PATH_OUTSIDE_ROOT: &str = "provision_path_outside_root";
const CODE_PROVISION_FAILED: &str = "workspace_provision_failed";

fn invalid(message: impl Into<String>) -> Failure {
    Failure::invalid(CODE_INVALID_CONFIG, message)
}

fn provision_failed(message: impl Into<String>) -> Failure {
    Failure::internal(CODE_PROVISION_FAILED, message)
}

/// `provision.Provisioner` — creates and frees per-`(run, node)`
/// dispatch workspaces. Implements [`central_scheduler::port::Provisioner`].
pub struct DispatchProvisioner {
    scratch_root: PathBuf,
    /// The git repository `worktree`-kind workspaces are added from.
    /// Required only when a `worktree` node is provisioned, so a
    /// directory-only instance may leave it unset.
    source_repo: Option<PathBuf>,
    git: PathBuf,
}

impl DispatchProvisioner {
    /// `NewProvisioner` — validates cfg-level inputs. `scratch_root`
    /// must be an absolute, clean, non-root path — workspaces live in
    /// its `workspaces/` subtree; the caller passes the instance
    /// scratch root. `source_repo` is the repository `worktree`-kind
    /// workspaces are added from and may be `None` for a
    /// directory-only deployment.
    ///
    /// # Errors
    /// `provision_invalid_config` when a path fails its shape rule —
    /// the same refusals upstream's constructor makes.
    pub fn new(scratch_root: &str, source_repo: &str) -> Result<Self, Failure> {
        // Upstream `filepath.Clean(p) == p`: the Rust shape is "no
        // CurDir/ParentDir components" on an absolute, non-root path.
        let scratch = Path::new(scratch_root);
        if !scratch.is_absolute()
            || scratch.components().any(|c| {
                matches!(
                    c,
                    std::path::Component::CurDir | std::path::Component::ParentDir
                )
            })
            || scratch == Path::new("/")
        {
            return Err(invalid(format!(
                "scratch root must be an absolute, clean, non-root path: {scratch_root}"
            )));
        }
        let source = if source_repo.is_empty() {
            None
        } else {
            let repo = Path::new(source_repo);
            if !repo.is_absolute()
                || repo.components().any(|c| {
                    matches!(
                        c,
                        std::path::Component::CurDir | std::path::Component::ParentDir
                    )
                })
            {
                return Err(invalid(format!(
                    "source repo must be an absolute, clean path: {source_repo}"
                )));
            }
            Some(repo.to_path_buf())
        };
        Ok(Self {
            scratch_root: scratch.to_path_buf(),
            source_repo: source,
            git: PathBuf::from(DEFAULT_GIT_PATH),
        })
    }

    /// `workspacePath` — maps a `(run, node)` pair to its workspace
    /// directory and asserts the result stays inside
    /// `<scratch_root>/workspaces`. The ids are uuid-typed so `..`
    /// cannot arrive, but the boundary check is kept so the invariant
    /// is enforced here regardless of caller hygiene.
    fn workspace_path(&self, run_id: RunId, node_id: WorkflowNodeId) -> Result<PathBuf, Failure> {
        let root = self.scratch_root.join(WORKSPACES_DIR);
        let dir = root.join(run_id.to_string()).join(node_id.to_string());
        let rel = dir.strip_prefix(&root).map_err(|_| {
            Failure::denied(
                CODE_PATH_OUTSIDE_ROOT,
                "workspace path escapes the scratch root",
            )
        })?;
        if rel.as_os_str().is_empty() {
            return Err(Failure::denied(
                CODE_PATH_OUTSIDE_ROOT,
                "workspace path escapes the scratch root",
            ));
        }
        Ok(dir)
    }

    /// `provisionDirectory` — creates (or reuses) a private directory
    /// workspace. An existing directory without a marker is reused per
    /// the spec's re-prepare rule — except one containing a `.git`
    /// entry, which is a worktree leftover or foreign content a
    /// `directory` node must not silently inherit; that drift is
    /// refused, never cleaned.
    fn provision_directory(&self, dir: &Path) -> Result<String, Failure> {
        match read_marker(dir, KIND_MARKER)?.as_str() {
            KIND_DIRECTORY => return Ok(dir.to_string_lossy().into_owned()),
            KIND_WORKTREE => {
                return Err(provision_failed(
                    "workspace recorded as worktree, requested directory",
                ));
            }
            _ => {}
        }
        if dir.join(".git").symlink_metadata().is_ok() {
            return Err(provision_failed(
                "unmarked workspace contains a .git entry -- refusing to reuse it as a directory",
            ));
        }
        std::fs::create_dir_all(dir)
            .map_err(|e| provision_failed(format!("create workspace directory: {e}")))?;
        set_private(dir)?;
        write_markers(dir, KIND_DIRECTORY, BUDGET_DIRECTORY_BYTES)?;
        Ok(dir.to_string_lossy().into_owned())
    }

    /// `provisionWorktree` — adds a detached worktree of `source_repo`
    /// at `base_ref` (empty → HEAD). `--detach` keeps the checkout at
    /// the recorded base ref without claiming a branch name; Phase 2
    /// never merges the worktree (spec-1 OQ-2), it remains for
    /// operator/leader inspection.
    fn provision_worktree(&self, dir: &Path, base_ref: &str) -> Result<String, Failure> {
        let Some(source_repo) = &self.source_repo else {
            return Err(Failure::invalid(
                CODE_SOURCE_REPO_REQUIRED,
                "worktree workspace_kind requires a source repository",
            ));
        };
        let git_ref = sanitize_ref(base_ref)?;
        match read_marker(dir, KIND_MARKER)?.as_str() {
            KIND_WORKTREE => {
                // Dedupe only a whole worktree: the marker plus the
                // `.git` gitfile. A marker without the gitfile is a
                // torn leftover — fall through and re-provision.
                if dir
                    .join(".git")
                    .symlink_metadata()
                    .is_ok_and(|st| !st.is_dir())
                {
                    return Ok(dir.to_string_lossy().into_owned());
                }
            }
            KIND_DIRECTORY => {
                return Err(provision_failed(
                    "workspace recorded as directory, requested worktree",
                ));
            }
            _ => {}
        }
        // A leftover without a marker is a partial provision: drop any
        // worktree registration it left, then the directory itself.
        if dir.symlink_metadata().is_ok() {
            let _ = self.git_run(
                source_repo,
                GIT_OP_TIMEOUT,
                &["worktree", "remove", "--force", &dir.to_string_lossy()],
            );
            std::fs::remove_dir_all(dir)
                .map_err(|e| provision_failed(format!("clear a partial workspace: {e}")))?;
        }
        // Prune clears administrative entries whose directories vanished
        // out from under git (e.g. a crash between worktree add and
        // marker write followed by manual cleanup).
        self.git_run(source_repo, GIT_OP_TIMEOUT, &["worktree", "prune"])
            .map_err(|e| provision_failed(format!("git worktree prune: {}", e.message())))?;
        let parent = dir.parent().unwrap_or_else(|| Path::new("/"));
        std::fs::create_dir_all(parent)
            .map_err(|e| provision_failed(format!("create run workspace root: {e}")))?;
        set_private(parent)?;
        self.git_run(
            source_repo,
            GIT_OP_TIMEOUT,
            &[
                "worktree",
                "add",
                "--detach",
                &dir.to_string_lossy(),
                &git_ref,
            ],
        )
        .map_err(|e| provision_failed(format!("git worktree add: {}", e.message())))?;
        write_markers(dir, KIND_WORKTREE, BUDGET_WORKTREE_BYTES)?;
        Ok(dir.to_string_lossy().into_owned())
    }

    /// `gitRun` — executes git in `dir` with an environment built from
    /// empty: no system or global config, no hooks, no fsmonitor, no
    /// prompts. git's stderr is not echoed into errors — it may quote
    /// repository content.
    fn git_run(&self, dir: &Path, timeout: Duration, args: &[&str]) -> Result<String, Failure> {
        let mut full: Vec<String> = vec![
            "-c".into(),
            "core.hooksPath=/dev/null".into(),
            "-c".into(),
            "core.fsmonitor=false".into(),
            "-c".into(),
            "protocol.allow=never".into(),
            "-c".into(),
            "protocol.file.allow=always".into(),
        ];
        full.extend(args.iter().map(|a| (*a).to_string()));
        let mut child = Command::new(&self.git)
            .args(&full)
            .current_dir(dir)
            .env_clear()
            .envs([
                ("PATH", "/usr/bin:/bin"),
                ("LANG", "C"),
                ("LC_ALL", "C"),
                ("GIT_CONFIG_NOSYSTEM", "1"),
                ("GIT_CONFIG_GLOBAL", "/dev/null"),
                ("GIT_TERMINAL_PROMPT", "0"),
                ("GIT_ASKPASS", "/bin/false"),
                ("HOME", "/nonexistent"),
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| provision_failed(format!("run git {}: {e}", args[0])))?;
        let deadline = std::time::Instant::now() + timeout;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let mut out = String::new();
                    if let Some(mut stdout) = child.stdout.take() {
                        use std::io::Read;
                        let _ = stdout.read_to_string(&mut out);
                    }
                    if status.success() {
                        return Ok(out);
                    }
                    return Err(provision_failed(format!(
                        "git {} exited with status {}",
                        args[0],
                        status.code().unwrap_or(-1)
                    )));
                }
                Ok(None) => {
                    if std::time::Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(provision_failed(format!(
                            "git {} timed out after {timeout:?}",
                            args[0]
                        )));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => return Err(provision_failed(format!("wait git {}: {e}", args[0]))),
            }
        }
    }
}

/// `0700` — the mode upstream `os.MkdirAll(dir, 0o700)` installs on
/// newly created workspace directories. Best-effort on an existing
/// directory: the marker/`.git` drift checks already gate reuse.
#[cfg(unix)]
fn set_private(dir: &Path) -> Result<(), Failure> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| provision_failed(format!("chmod workspace directory: {e}")))
}

#[cfg(not(unix))]
fn set_private(_dir: &Path) -> Result<(), Failure> {
    Ok(())
}

/// `sanitizeRef` — defaults an empty `base_ref` to `HEAD` and refuses
/// spellings that could smuggle a git option or an unintended revision
/// expression (leading `-`, `..`, whitespace or NUL). Deliberately
/// tighter than `git check-ref-format`: `base_ref` only ever names a
/// commit-ish the run recorded.
fn sanitize_ref(base_ref: &str) -> Result<String, Failure> {
    if base_ref.is_empty() {
        return Ok("HEAD".to_string());
    }
    if base_ref.starts_with('-')
        || base_ref.contains("..")
        || base_ref.chars().any(|c| c.is_whitespace() || c == '\0')
    {
        return Err(invalid(format!("unsafe base ref: {base_ref}")));
    }
    Ok(base_ref.to_string())
}

/// `readMarker` — the trimmed content of `dir`'s marker file, `""` when
/// the marker (or the workspace) does not exist.
fn read_marker(dir: &Path, name: &str) -> Result<String, Failure> {
    match std::fs::read_to_string(dir.join(name)) {
        Ok(content) => Ok(content.trim().to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(provision_failed(format!("read workspace marker: {e}"))),
    }
}

/// `writeMarkers` — records the workspace's budget bound first and its
/// kind marker last — the kind marker's presence is what a re-prepare
/// treats as a complete provision.
fn write_markers(dir: &Path, kind: &str, budget: u64) -> Result<(), Failure> {
    std::fs::write(dir.join(BUDGET_MARKER), format!("{budget}\n"))
        .map_err(|e| provision_failed(format!("write budget marker: {e}")))?;
    std::fs::write(dir.join(KIND_MARKER), format!("{kind}\n"))
        .map_err(|e| provision_failed(format!("write kind marker: {e}")))?;
    Ok(())
}

impl Provisioner for DispatchProvisioner {
    /// `Provision` — prepares the node's workspace and returns its
    /// absolute path. Idempotent: a complete prior provision of the
    /// same kind returns the recorded path without disturbing the
    /// content; a leftover without a marker is removed and
    /// provisioned again. `attempt_id` is part of the port contract
    /// for future per-attempt auditing; the path is deliberately
    /// `(run, node)`-keyed so a retried attempt of the same node
    /// converges on the same workspace.
    async fn provision(
        &self,
        run_id: RunId,
        node_id: WorkflowNodeId,
        attempt_id: SessionAttemptId,
        kind: &str,
        base_ref: &str,
    ) -> Result<String, Failure> {
        // Upstream's `uuid.Nil` guard: nil ids are unreachable through
        // `new`/`parse` but can arrive via `from_trusted_db_bytes`.
        if run_id.is_nil() || node_id.is_nil() || attempt_id.is_nil() {
            return Err(invalid("run, node and attempt ids must be non-nil"));
        }
        // Rust has no `ctx`: a dropped future abandons the work — the
        // port's `Cancelled` arm — so the body runs synchronously like
        // upstream's blocking exec calls did.
        let dir = self.workspace_path(run_id, node_id)?;
        match kind {
            KIND_WORKTREE => self.provision_worktree(&dir, base_ref),
            KIND_DIRECTORY => self.provision_directory(&dir),
            other => Err(Failure::invalid(
                CODE_UNKNOWN_KIND,
                format!("unknown workspace_kind: {other}"),
            )),
        }
    }

    /// `Free` — releases a workspace previously returned by
    /// [`provision`](Self::provision). The kind marker selects the
    /// teardown: a worktree goes through `git worktree remove --force`
    /// against the source repo, a directory is removed directly. A path
    /// whose marker is missing but that still looks like a worktree (a
    /// `.git` gitfile) is treated as a worktree. Free is idempotent and
    /// refuses paths outside `<scratch_root>/workspaces`.
    fn free(&self, path: &str) -> Result<(), Failure> {
        let clean = PathBuf::from(path);
        let root = self.scratch_root.join(WORKSPACES_DIR);
        let rel = clean.strip_prefix(&root).map_err(|_| {
            Failure::denied(
                CODE_PATH_OUTSIDE_ROOT,
                format!("workspace path escapes the scratch root: {path}"),
            )
        })?;
        if rel.as_os_str().is_empty()
            || rel
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(Failure::denied(
                CODE_PATH_OUTSIDE_ROOT,
                format!("workspace path escapes the scratch root: {path}"),
            ));
        }
        let kind = read_marker(&clean, KIND_MARKER)?;
        let mut worktree = kind == KIND_WORKTREE;
        if kind.is_empty() {
            // Unmarked leftover: treat as a worktree only if it carries
            // a gitfile, so `worktree remove` has a chance to
            // unregister it.
            worktree = clean
                .join(".git")
                .symlink_metadata()
                .is_ok_and(|st| !st.is_dir());
        }
        if worktree && let Some(source_repo) = &self.source_repo {
            // A remove failure (unregistered or already gone)
            // falls through to `remove_dir_all` — Free stays
            // idempotent.
            let _ = self.git_run(
                source_repo,
                GIT_OP_TIMEOUT,
                &["worktree", "remove", "--force", &clean.to_string_lossy()],
            );
        }
        match std::fs::remove_dir_all(&clean) {
            Ok(()) => Ok(()),
            // Upstream `os.RemoveAll`: freeing an already-freed
            // workspace succeeds — Free is idempotent.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(provision_failed(format!("free workspace: {e}"))),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests — the port of upstream provisioner_test.go
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// `t.TempDir` — a unique scratch root removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("central-provision-test-{}", RunId::new()));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    impl std::ops::Deref for TempDir {
        type Target = Path;
        fn deref(&self) -> &Path {
            &self.0
        }
    }

    /// `git` — the real git binary with the ambient config pinned off,
    /// like upstream's helper, so the test does not observe the
    /// developer's ~/.gitconfig.
    fn git(dir: &Path, args: &[&str]) -> String {
        let out = Command::new(DEFAULT_GIT_PATH)
            .args(args)
            .current_dir(dir)
            .env_clear()
            .envs([
                ("PATH", "/usr/bin:/bin"),
                ("LANG", "C"),
                ("LC_ALL", "C"),
                ("GIT_CONFIG_NOSYSTEM", "1"),
                ("GIT_CONFIG_GLOBAL", "/dev/null"),
                ("GIT_TERMINAL_PROMPT", "0"),
                ("HOME", "/nonexistent"),
                ("GIT_AUTHOR_NAME", "Test"),
                ("GIT_AUTHOR_EMAIL", "test@example.com"),
                ("GIT_COMMITTER_NAME", "Test"),
                ("GIT_COMMITTER_EMAIL", "test@example.com"),
            ])
            .output()
            .expect("spawn git");
        assert!(
            out.status.success(),
            "git {args:?} in {}: {}",
            dir.display(),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// `initSourceRepo` — a source repository with two commits;
    /// returns its path plus the first commit's sha.
    fn init_source_repo() -> (TempDir, PathBuf, String) {
        let holder = TempDir::new();
        let repo = holder.join("source");
        std::fs::create_dir_all(&repo).unwrap();
        git(&repo, &["init", "-b", "main"]);
        std::fs::write(repo.join("file.txt"), "v1\n").unwrap();
        git(&repo, &["add", "file.txt"]);
        git(&repo, &["commit", "-m", "first"]);
        let first_sha = git(&repo, &["rev-parse", "HEAD"]);
        std::fs::write(repo.join("file.txt"), "v2\n").unwrap();
        git(&repo, &["add", "file.txt"]);
        git(&repo, &["commit", "-m", "second"]);
        (holder, repo, first_sha)
    }

    fn worktree_listed(repo: &Path, path: &str) -> bool {
        git(repo, &["worktree", "list", "--porcelain"])
            .lines()
            .any(|line| line == format!("worktree {path}"))
    }

    fn marker(dir: &Path, name: &str) -> String {
        std::fs::read_to_string(dir.join(name))
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    }

    #[test]
    fn new_provisioner_rejects_bad_roots() {
        for root in ["", "relative/dir", "/", "a/../b"] {
            let err = DispatchProvisioner::new(root, "")
                .err()
                .unwrap_or_else(|| unreachable!("NewProvisioner({root:?}) accepted"));
            assert_eq!(err.code(), CODE_INVALID_CONFIG, "root {root:?}");
        }
        let scratch = TempDir::new();
        let err = DispatchProvisioner::new(&scratch.to_string_lossy(), "relative/repo")
            .err()
            .expect("relative source repo accepted");
        assert_eq!(err.code(), CODE_INVALID_CONFIG);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn provision_directory_creates_and_reuses() {
        let scratch = TempDir::new();
        let p = DispatchProvisioner::new(&scratch.to_string_lossy(), "").unwrap();
        let (run, node, attempt) = (RunId::new(), WorkflowNodeId::new(), SessionAttemptId::new());
        let want = scratch
            .join(WORKSPACES_DIR)
            .join(run.to_string())
            .join(node.to_string());

        let path = p
            .provision(run, node, attempt, "directory", "")
            .await
            .expect("Provision(directory)");
        assert_eq!(path, want.to_string_lossy());
        let meta = std::fs::metadata(&want).expect("workspace dir missing");
        assert!(meta.is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                meta.permissions().mode() & 0o777,
                0o700,
                "workspace dir mode"
            );
        }
        assert_eq!(marker(&want, KIND_MARKER), "directory");
        assert_eq!(marker(&want, BUDGET_MARKER), "4294967296");

        // Re-prepare dedupes on the recorded path: content survives.
        let kept = want.join("kept.txt");
        std::fs::write(&kept, "still here").unwrap();
        let again = p
            .provision(run, node, attempt, "directory", "")
            .await
            .expect("re-Provision(directory)");
        assert_eq!(again, want.to_string_lossy());
        assert!(kept.exists(), "re-prepare dropped workspace content");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn provision_worktree_adds_at_base_ref_and_dedupes() {
        let (_holder, repo, _) = init_source_repo();
        let head_sha = git(&repo, &["rev-parse", "HEAD"]);
        let scratch = TempDir::new();
        let p =
            DispatchProvisioner::new(&scratch.to_string_lossy(), &repo.to_string_lossy()).unwrap();
        let (run, node, attempt) = (RunId::new(), WorkflowNodeId::new(), SessionAttemptId::new());
        let want = scratch
            .join(WORKSPACES_DIR)
            .join(run.to_string())
            .join(node.to_string());

        // Empty baseRef defaults to HEAD.
        let path = p
            .provision(run, node, attempt, "worktree", "")
            .await
            .expect("Provision(worktree)");
        assert_eq!(path, want.to_string_lossy());
        let gitfile = want
            .join(".git")
            .symlink_metadata()
            .expect("worktree gitfile missing");
        assert!(!gitfile.is_dir(), ".git must be the worktree gitfile");
        assert_eq!(git(&want, &["rev-parse", "HEAD"]), head_sha);
        assert!(want.join("file.txt").exists(), "worktree content missing");
        assert_eq!(marker(&want, KIND_MARKER), "worktree");
        assert_eq!(marker(&want, BUDGET_MARKER), "8589934592");
        assert!(worktree_listed(&repo, &path), "worktree not registered");

        // Re-prepare dedupes: same path, still exactly one registration.
        let again = p
            .provision(run, node, attempt, "worktree", "")
            .await
            .expect("re-Provision(worktree)");
        assert_eq!(again, want.to_string_lossy());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn provision_worktree_at_explicit_base_ref() {
        let (_holder, repo, first_sha) = init_source_repo();
        let scratch = TempDir::new();
        let p =
            DispatchProvisioner::new(&scratch.to_string_lossy(), &repo.to_string_lossy()).unwrap();
        let path = p
            .provision(
                RunId::new(),
                WorkflowNodeId::new(),
                SessionAttemptId::new(),
                "worktree",
                &first_sha,
            )
            .await
            .expect("Provision(worktree@first)");
        assert_eq!(git(Path::new(&path), &["rev-parse", "HEAD"]), first_sha);
        assert_eq!(
            std::fs::read_to_string(Path::new(&path).join("file.txt")).unwrap(),
            "v1\n"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn provision_worktree_without_source_repo_fails() {
        let scratch = TempDir::new();
        let p = DispatchProvisioner::new(&scratch.to_string_lossy(), "").unwrap();
        let err = p
            .provision(
                RunId::new(),
                WorkflowNodeId::new(),
                SessionAttemptId::new(),
                "worktree",
                "",
            )
            .await
            .expect_err("worktree without a source repo");
        assert_eq!(err.code(), CODE_SOURCE_REPO_REQUIRED);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn provision_unknown_kind_fails() {
        let scratch = TempDir::new();
        let p = DispatchProvisioner::new(&scratch.to_string_lossy(), "").unwrap();
        let err = p
            .provision(
                RunId::new(),
                WorkflowNodeId::new(),
                SessionAttemptId::new(),
                "volume",
                "",
            )
            .await
            .expect_err("unknown kind");
        assert_eq!(err.code(), CODE_UNKNOWN_KIND);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn provision_rejects_nil_ids() {
        let scratch = TempDir::new();
        let p = DispatchProvisioner::new(&scratch.to_string_lossy(), "").unwrap();
        let nil = [0u8; 16];
        let (run, node, attempt) = (RunId::new(), WorkflowNodeId::new(), SessionAttemptId::new());
        for (r, n, a) in [
            (RunId::from_trusted_db_bytes(nil), node, attempt),
            (run, WorkflowNodeId::from_trusted_db_bytes(nil), attempt),
            (run, node, SessionAttemptId::from_trusted_db_bytes(nil)),
        ] {
            let err = p
                .provision(r, n, a, "directory", "")
                .await
                .expect_err("nil id accepted");
            assert_eq!(err.code(), CODE_INVALID_CONFIG);
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn provision_worktree_recovers_partial_leftover() {
        let (_holder, repo, _) = init_source_repo();
        let scratch = TempDir::new();
        let p =
            DispatchProvisioner::new(&scratch.to_string_lossy(), &repo.to_string_lossy()).unwrap();
        let (run, node, attempt) = (RunId::new(), WorkflowNodeId::new(), SessionAttemptId::new());
        let path = scratch
            .join(WORKSPACES_DIR)
            .join(run.to_string())
            .join(node.to_string());

        // A partial attempt left a plain directory with junk and no
        // marker.
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(path.join("junk.partial"), "x").unwrap();
        let got = p
            .provision(run, node, attempt, "worktree", "")
            .await
            .expect("Provision over partial leftover");
        assert_eq!(got, path.to_string_lossy());
        assert!(
            path.join("junk.partial").symlink_metadata().is_err(),
            "partial leftover content survived worktree provisioning"
        );
        let gitfile = path
            .join(".git")
            .symlink_metadata()
            .expect("worktree gitfile missing");
        assert!(!gitfile.is_dir());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn provision_directory_refuses_worktree_leftover() {
        let (_holder, repo, _) = init_source_repo();
        let scratch = TempDir::new();
        let p =
            DispatchProvisioner::new(&scratch.to_string_lossy(), &repo.to_string_lossy()).unwrap();
        let (run, node, attempt) = (RunId::new(), WorkflowNodeId::new(), SessionAttemptId::new());
        let path = p
            .provision(run, node, attempt, "worktree", "")
            .await
            .unwrap();
        // Simulate a marker-less worktree leftover, then ask for a
        // directory at the same (run, node).
        std::fs::remove_file(Path::new(&path).join(KIND_MARKER)).unwrap();
        let err = p
            .provision(run, node, attempt, "directory", "")
            .await
            .expect_err("kind drift accepted");
        assert_eq!(err.code(), CODE_PROVISION_FAILED);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn free_removes_both_kinds() {
        let (_holder, repo, _) = init_source_repo();
        let scratch = TempDir::new();
        let p =
            DispatchProvisioner::new(&scratch.to_string_lossy(), &repo.to_string_lossy()).unwrap();

        let dir_path = p
            .provision(
                RunId::new(),
                WorkflowNodeId::new(),
                SessionAttemptId::new(),
                "directory",
                "",
            )
            .await
            .unwrap();
        let wt_path = p
            .provision(
                RunId::new(),
                WorkflowNodeId::new(),
                SessionAttemptId::new(),
                "worktree",
                "",
            )
            .await
            .unwrap();
        assert!(
            worktree_listed(&repo, &wt_path),
            "worktree missing before Free"
        );
        p.free(&dir_path).expect("Free(directory)");
        assert!(
            Path::new(&dir_path).symlink_metadata().is_err(),
            "directory survived Free"
        );
        p.free(&wt_path).expect("Free(worktree)");
        assert!(
            Path::new(&wt_path).symlink_metadata().is_err(),
            "worktree survived Free"
        );
        assert!(
            !worktree_listed(&repo, &wt_path),
            "worktree still registered"
        );

        // Free is idempotent: a second pass succeeds.
        p.free(&wt_path).expect("re-Free(worktree)");
        p.free(&dir_path).expect("re-Free(directory)");
    }

    #[test]
    fn free_rejects_outside_root() {
        let scratch = TempDir::new();
        let scratch_str = scratch.to_string_lossy().into_owned();
        let p = DispatchProvisioner::new(&scratch_str, "").unwrap();
        let workspaces = format!("{scratch_str}/{WORKSPACES_DIR}");
        for path in [
            "/etc".to_string(),
            scratch_str.clone(),
            workspaces.clone(),
            format!("{workspaces}/../x"),
        ] {
            let err = p.free(&path).expect_err("outside-root path accepted");
            assert_eq!(err.code(), CODE_PATH_OUTSIDE_ROOT, "Free({path:?})");
        }
    }
}
