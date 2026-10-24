//! Upstream `capture.go` + `capture_linux.go` — the harness phase 3b
//! capture (decisions 4–6, 14): seal the Run, run git only against two
//! shadow repositories, bound both artifact bodies.

use std::ffi::OsString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use central_foundation::failure::Failure;
use central_foundation::identity::{RunId, WorkspaceId};
use central_harness::app::ports::{
    Capture, ObjectLimits, SealedClone, WalkLimits, WorkspaceCapture, codes,
};
use central_harness::domain::Workspace;
use central_harness::gitmeta::is_object_id;
use central_harness::port::PortFuture;
use tokio::fs::File;
use tokio::process::Command;

use super::GitClone;
use crate::process::{async_read, async_write};

// Harness phase 3b capture limits (decisions 4, 6, 14).
/// `CaptureTimeout` bounds one whole capture.
pub const CAPTURE_TIMEOUT: Duration = Duration::from_secs(120);
/// `MaxPatchBytes` — the patch body cap (10 MiB).
pub const MAX_PATCH_BYTES: u64 = 10 << 20;
/// `MaxCommitsBytes` — the commits body cap (1 MiB).
pub const MAX_COMMITS_BYTES: u64 = 1 << 20;
/// `MaxCommits` bounds the commits listed; more are summarized.
pub const MAX_COMMITS: usize = 1000;
/// `captureWaitDelay` — how long a capture git may take to return once
/// the deadline ended it.
const CAPTURE_WAIT_DELAY: Duration = Duration::from_secs(2);
/// `CaptureGitMemoryLimit` — the address-space limit of every capture
/// git child (RLIMIT_AS 4 GiB).
pub const CAPTURE_GIT_MEMORY_LIMIT: u64 = 4 << 30;

/// `PatchExcludedPrefix` opens the header line listing every nested
/// repository the patch excludes.
pub const PATCH_EXCLUDED_PREFIX: &str = "# excluded nested repositories:";
/// `PatchNoChangesLine` — the whole diff of a clone with no change.
pub const PATCH_NO_CHANGES_LINE: &str = "# no changes against the base commit\n";
/// `CommitsUnavailableLine` replaces the count and list when git cannot
/// walk `base..after` (decision 6).
pub const COMMITS_UNAVAILABLE_LINE: &str = "commits: unavailable\n";

/// `shadowAttributes` neutralizes every work-tree attribute that
/// changes conversion or diff output (decision 4).
const SHADOW_ATTRIBUTES: &str =
    "* !diff !text !eol !ident !filter !working-tree-encoding !merge !crlf\n";

/// `commitFormat` — the fixed per-commit record (decision 6): `%an`/`%ae`,
/// never the mailmap-aware `%aN`/`%aE`.
const COMMIT_FORMAT: &str = "format:%ncommit %H%nauthor %an <%ae>%ndate %aI%nsubject %s";

/// `shadowConfig` — the command-line configuration of every capture git
/// command (decision 4).
const SHADOW_CONFIG: &[&str] = &[
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.untrackedCache=false",
    "-c",
    "core.autocrlf=false",
    "-c",
    "core.symlinks=true",
    "-c",
    "core.attributesFile=/dev/null",
    "-c",
    "log.mailmap=false",
    "-c",
    "core.multiPackIndex=false",
    "-c",
    "core.commitGraph=false",
    "-c",
    "pack.useBitmaps=false",
    "-c",
    "core.useReplaceRefs=false",
    "-c",
    "gc.auto=0",
    "-c",
    "core.packedGitLimit=1g",
    "-c",
    "core.packedGitWindowSize=256m",
];

fn failed(step: &str) -> Failure {
    Failure::internal(codes::CAPTURE_FAILED, step.to_string())
}

fn too_large() -> Failure {
    Failure::internal(codes::CAPTURE_TOO_LARGE, "a captured body exceeded its cap")
}

/// `gitExitError` vs every other capture failure — upstream's
/// `errors.As(err, &gitExitError)`: a git that ran and exited
/// non-zero is distinguished from a spawn, deadline, memory-limit or
/// output-write failure because the commits artifact degrades to
/// "unavailable" only on the former.
struct GitAtError {
    failure: Failure,
    /// The git command ran and exited non-zero (upstream
    /// `gitExitError`, including a signal death that is not the
    /// deadline's).
    git_exit: bool,
}

impl GitAtError {
    /// A non-git-exit failure — `git_exit` is false.
    fn plain(failure: Failure) -> Self {
        Self {
            failure,
            git_exit: false,
        }
    }

    /// `out.fail(err)` — the [`Failure`] for a caller that does not
    /// degrade on a git exit.
    fn into_failure(self) -> Failure {
        self.failure
    }
}

/// `cappedFile` — an artifact temp file that refuses to grow past `max`
/// bytes (decision 14): the write that would exceed it fails, which
/// ends the git command producing it, and the capture is too-large.
struct CappedFile {
    f: File,
    n: u64,
    max: u64,
    overflow: bool,
}

impl CappedFile {
    async fn create(path: &Path, max: u64) -> Result<Self, Failure> {
        let f = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .await
            .map_err(|_| failed("create a capture temp file"))?;
        Ok(Self {
            f,
            n: 0,
            max,
            overflow: false,
        })
    }

    async fn write(&mut self, b: &[u8]) -> Result<(), Failure> {
        if self.overflow || self.n + b.len() as u64 > self.max {
            self.overflow = true;
            return Err(too_large());
        }
        let mut rest = b;
        while !rest.is_empty() {
            let n = async_write(&mut self.f, rest)
                .await
                .map_err(|_| failed("write a capture temp file"))?;
            if n == 0 {
                return Err(failed("write a capture temp file"));
            }
            rest = &rest[n..];
        }
        self.n += b.len() as u64;
        Ok(())
    }

    /// `reset` — empties the file so a degraded body can replace a
    /// partial one: truncate, rewind, and clear the overflow flag.
    /// (`io-util` is not enabled, so the `AsyncSeek` core trait's
    /// `start_seek`/`poll_complete` are driven directly.)
    async fn reset(&mut self) -> Result<(), Failure> {
        use tokio::io::AsyncSeek;
        self.f
            .set_len(0)
            .await
            .map_err(|_| failed("reset a capture temp file"))?;
        std::pin::Pin::new(&mut self.f)
            .start_seek(io::SeekFrom::Start(0))
            .map_err(|_| failed("reset a capture temp file"))?;
        std::future::poll_fn(|cx| std::pin::Pin::new(&mut self.f).poll_complete(cx))
            .await
            .map_err(|_| failed("reset a capture temp file"))?;
        self.n = 0;
        self.overflow = false;
        Ok(())
    }

    /// `finish` — sync the artifact body before it is reported, as
    /// upstream `finish`'s `f.Sync()`.
    async fn finish(&mut self) -> Result<u64, Failure> {
        self.f
            .sync_all()
            .await
            .map_err(|_| failed("sync a capture temp file"))?;
        Ok(self.n)
    }
}

/// `capture` — one Run's capture state (upstream `capture`).
struct CaptureCtx {
    repo: String,
    base: String,
    shadow: PathBuf,
    log_shadow: PathBuf,
    tmp: PathBuf,
    index: PathBuf,
}

impl GitClone {
    /// `initShadow` — a bare repository with Central's config, the
    /// source's objects as its only alternate and the attributes
    /// neutralizer. `init` ignores `GIT_INDEX_FILE`; upstream still
    /// names the capture's index for it.
    async fn init_shadow(
        &self,
        deadline: Instant,
        dir: &Path,
        source: &Path,
        index: &Path,
    ) -> Result<(), Failure> {
        self.git_at(
            deadline,
            None,
            None,
            false,
            None,
            index,
            &[
                OsString::from("init"),
                OsString::from("--quiet"),
                OsString::from("--bare"),
                OsString::from("--template="),
                dir.as_os_str().to_os_string(),
            ],
        )
        .await
        .map_err(GitAtError::into_failure)?;
        tokio::fs::set_permissions(dir, {
            use std::os::unix::fs::PermissionsExt;
            std::fs::Permissions::from_mode(0o700)
        })
        .await
        .map_err(|_| failed("restrict the shadow repository"))?;
        let info = dir.join("objects").join("info");
        tokio::fs::create_dir_all(&info)
            .await
            .map_err(|_| failed("create the shadow objects/info"))?;
        tokio::fs::write(
            info.join("alternates"),
            format!("{}\n", source.join("objects").display()),
        )
        .await
        .map_err(|_| failed("write the shadow alternates"))?;
        tokio::fs::create_dir_all(dir.join("info"))
            .await
            .map_err(|_| failed("create the shadow info"))?;
        tokio::fs::write(dir.join("info").join("attributes"), SHADOW_ATTRIBUTES)
            .await
            .map_err(|_| failed("write the shadow attributes"))?;
        Ok(())
    }

    /// Upstream `gitAt` — one capture git command against `git_dir`
    /// (`None` only for init) and the sealed work tree when `worktree`,
    /// with an empty environment apart from decision 4's variables,
    /// Central's command-line config, the capture deadline and a wait
    /// delay. `stdout` receives the output; `None` captures at most
    /// 4 KiB for the caller. Neither argv nor git's output reaches an
    /// error. The whole command — output drain and reap — is bound by
    /// `deadline`, upstream's `exec.CommandContext(c.ctx)`; once it
    /// ends the child is killed and the reap bound by `captureWaitDelay`.
    /// The wide signature mirrors upstream `gitAt`'s parameter list.
    #[allow(clippy::too_many_arguments)]
    async fn git_at(
        &self,
        deadline: Instant,
        git_dir: Option<&Path>,
        mut stdout: Option<&mut CappedFile>,
        worktree: bool,
        repo: Option<&str>,
        index: &Path,
        args: &[OsString],
    ) -> Result<String, GitAtError> {
        let mut cmd = Command::new(&self.git);
        cmd.args(SHADOW_CONFIG.iter().map(|s| OsString::from(*s)));
        if let Some(d) = git_dir {
            cmd.arg(format!("--git-dir={}", d.display()));
        }
        if worktree && let Some(r) = repo {
            cmd.arg(format!("--work-tree={r}"));
        }
        cmd.args(args)
            .current_dir(self.capture_root())
            .env_clear()
            .envs([
                ("GIT_CONFIG_NOSYSTEM", "1"),
                ("GIT_CONFIG_GLOBAL", "/dev/null"),
                ("GIT_TERMINAL_PROMPT", "0"),
                ("GIT_OPTIONAL_LOCKS", "0"),
            ])
            .env("GIT_INDEX_FILE", index)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut child = cmd
            .spawn()
            .map_err(|_| GitAtError::plain(failed("start git")))?;
        // `capture.start` — bound the child's address space so a zlib
        // bomb in a pack cannot make git exhaust host memory; a child
        // whose limit cannot be set is killed and fails the capture.
        if let Some(id) = child.id()
            && let Err(e) = self
                .sealer
                .limit_process_memory(id, CAPTURE_GIT_MEMORY_LIMIT)
                .await
        {
            let _ = child.start_kill();
            let _ = child.wait().await;
            return Err(GitAtError::plain(e));
        }
        let t_deadline = tokio::time::Instant::from_std(deadline);
        let run = async {
            let mut captured = Vec::new();
            let mut write_err = None;
            let mut pipe = child.stdout.take();
            let mut buf = [0u8; 8192];
            if let Some(p) = pipe.as_mut() {
                loop {
                    match async_read(p, &mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if let Some(out) = stdout.as_mut() {
                                if let Err(e) = out.write(&buf[..n]).await {
                                    // The cap overflow or a write
                                    // failure both end the child; the
                                    // error is reported once it is
                                    // reaped (`cappedFile.fail`
                                    // distinguishes the two).
                                    let _ = child.start_kill();
                                    write_err = Some(e);
                                    break;
                                }
                            } else if captured.len() < 4 << 10 {
                                let room = (4 << 10) - captured.len();
                                captured.extend_from_slice(&buf[..n.min(room)]);
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
            let status = child.wait().await.ok();
            (captured, write_err, status)
        };
        let (captured, write_err, status) = match tokio::time::timeout_at(t_deadline, run).await {
            Ok(v) => v,
            Err(_) => {
                let _ = child.start_kill();
                let _ = tokio::time::timeout(CAPTURE_WAIT_DELAY, child.wait()).await;
                return Err(GitAtError::plain(failed("capture deadline")));
            }
        };
        // Overflow and write errors win over the induced-kill status:
        // only the cap maps to `ErrCaptureTooLarge`.
        if let Some(e) = write_err {
            return Err(GitAtError::plain(e));
        }
        let Some(status) = status else {
            return Err(GitAtError::plain(failed("run git")));
        };
        if !status.success() {
            if Instant::now() > deadline {
                return Err(GitAtError::plain(failed("capture deadline")));
            }
            let op = args
                .first()
                .map(|a| a.to_string_lossy().into_owned())
                .unwrap_or_default();
            return Err(GitAtError {
                failure: Failure::internal(
                    codes::CAPTURE_FAILED,
                    format!(
                        "git {op} exited with status {}",
                        status.code().unwrap_or(-1)
                    ),
                ),
                git_exit: true,
            });
        }
        Ok(String::from_utf8_lossy(&captured).into_owned())
    }

    /// `writePatch` — the patch artifact (decision 5): an empty temp
    /// index, `add -A` over the sealed work tree with every nested
    /// repository excluded by a literal pathspec, then `diff --cached`
    /// against the base, all against the patch shadow, which holds no
    /// clone object.
    async fn write_patch(
        &self,
        deadline: Instant,
        c: &CaptureCtx,
        path: &Path,
        nested: &[Vec<u8>],
    ) -> Result<u64, Failure> {
        let mut out = CappedFile::create(path, self.max_patch_bytes).await?;
        if !nested.is_empty() {
            let quoted: Vec<String> = nested.iter().map(|n| go_quote(n)).collect();
            out.write(format!("{} {}\n", PATCH_EXCLUDED_PREFIX, quoted.join(" ")).as_bytes())
                .await?;
        }
        let header = out.n;
        let mut pathspecs: Vec<OsString> = vec![OsString::from(".")];
        for n in nested {
            let mut p = OsString::from(":(exclude,literal)");
            p.push(std::ffi::OsStr::from_bytes(n));
            pathspecs.push(p);
        }
        let mut add_args = vec![
            OsString::from("add"),
            OsString::from("--all"),
            OsString::from("--"),
        ];
        add_args.extend(pathspecs.iter().cloned());
        self.git_at(
            deadline,
            Some(&c.shadow),
            None,
            true,
            Some(&c.repo),
            &c.index,
            &add_args,
        )
        .await
        .map_err(GitAtError::into_failure)?;
        let mut diff_args = [
            "diff",
            "--cached",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            "--no-renames",
        ]
        .iter()
        .map(OsString::from)
        .collect::<Vec<_>>();
        diff_args.push(OsString::from(&c.base));
        diff_args.push(OsString::from("--"));
        diff_args.extend(pathspecs.iter().cloned());
        self.git_at(
            deadline,
            Some(&c.shadow),
            Some(&mut out),
            true,
            Some(&c.repo),
            &c.index,
            &diff_args,
        )
        .await
        .map_err(GitAtError::into_failure)?;
        if out.n == header {
            out.write(PATCH_NO_CHANGES_LINE.as_bytes()).await?;
        }
        out.finish().await
    }

    /// `hasCommit` — whether `id` names a commit in the log shadow.
    /// `cat-file -t` reads only the object's header.
    async fn has_commit(&self, deadline: Instant, c: &CaptureCtx, id: &str) -> bool {
        self.git_at(
            deadline,
            Some(&c.log_shadow),
            None,
            false,
            None,
            &c.index,
            &[
                OsString::from("cat-file"),
                OsString::from("-t"),
                OsString::from(id),
            ],
        )
        .await
        .is_ok_and(|out| out.trim() == "commit")
    }

    /// `writeCommits` — the commits artifact (decision 6): the before
    /// HEAD (the base), the after HEAD or "unavailable", and, when
    /// available, the commits `base..after`, at most `max_commits` with
    /// a truncation note, or [`COMMITS_UNAVAILABLE_LINE`] when git
    /// cannot walk that history. Only a git that ran and exited
    /// non-zero while the deadline holds degrades the artifact —
    /// upstream's `unavailable` (`errors.As(err, &gitExitError)` with
    /// `c.ctx.Err() == nil`); every other failure fails the capture.
    async fn write_commits(
        &self,
        deadline: Instant,
        c: &CaptureCtx,
        path: &Path,
        after: &str,
    ) -> Result<u64, Failure> {
        let mut out = CappedFile::create(path, self.max_commits_bytes).await?;
        if after.is_empty() {
            out.write(format!("before HEAD: {}\nafter HEAD: unavailable\n", c.base).as_bytes())
                .await?;
            return out.finish().await;
        }
        let heads = format!("before HEAD: {}\nafter HEAD: {}\n", c.base, after);
        let count = self
            .git_at(
                deadline,
                Some(&c.log_shadow),
                None,
                false,
                None,
                &c.index,
                &[
                    OsString::from("rev-list"),
                    OsString::from("--count"),
                    OsString::from(format!("{}..{}", c.base, after)),
                    OsString::from("--"),
                ],
            )
            .await;
        let count = match count {
            Ok(c) => c,
            // gitExitError within the deadline → the degraded artifact.
            Err(e) if e.git_exit && Instant::now() <= deadline => {
                out.reset().await?;
                out.write(format!("{heads}{COMMITS_UNAVAILABLE_LINE}").as_bytes())
                    .await?;
                return out.finish().await;
            }
            Err(e) => return Err(e.failure),
        };
        let n: i64 = count
            .trim()
            .parse()
            .map_err(|_| failed("count the commits: git rev-list printed no count"))?;
        if n < 0 {
            return Err(failed("count the commits: git rev-list printed no count"));
        }
        let summary = if n as usize > self.max_commits {
            format!("commits: {n} (first {} listed)\n", self.max_commits)
        } else {
            format!("commits: {n}\n")
        };
        out.write(format!("{heads}{summary}").as_bytes()).await?;
        if n > 0 {
            let args = [
                OsString::from("log"),
                OsString::from("--no-show-signature"),
                OsString::from("--no-decorate"),
                OsString::from("--no-color"),
                OsString::from(format!("--max-count={}", self.max_commits)),
                OsString::from(format!("--format={COMMIT_FORMAT}")),
                OsString::from(format!("{}..{}", c.base, after)),
                OsString::from("--"),
            ];
            match self
                .git_at(
                    deadline,
                    Some(&c.log_shadow),
                    Some(&mut out),
                    false,
                    None,
                    &c.index,
                    &args,
                )
                .await
            {
                Ok(_) => {}
                Err(e) if e.git_exit && Instant::now() <= deadline => {
                    out.reset().await?;
                    out.write(format!("{heads}{COMMITS_UNAVAILABLE_LINE}").as_bytes())
                        .await?;
                    return out.finish().await;
                }
                Err(e) => return Err(e.failure),
            }
            out.write(b"\n").await?;
        }
        out.finish().await
    }

    /// `CheckCaptureDir` — the startup probe half of
    /// `probeHarnessCaptureHost`: `data_root/capture` must exist as a
    /// runtime-owned, non-symlink 0700 directory before serve admits
    /// the harness (upstream's sync check — the async
    /// [`require_runtime_private_dir`] variant stays for the run-time
    /// temp provisioning).
    ///
    /// # Errors
    /// `Failure::invalid`-shaped capture failure when the directory is
    /// missing or not a runtime-owned 0700 directory.
    pub fn check_capture_dir(&self) -> Result<(), Failure> {
        let md = std::fs::symlink_metadata(self.capture_root())
            .map_err(|_| failed("the capture directory is missing (run the harness setup)"))?;
        use std::os::unix::fs::MetadataExt;
        let ok = md.is_dir()
            && !md.file_type().is_symlink()
            && md.uid() == self.runtime_uid
            && md.mode() & 0o777 == 0o700;
        if !ok {
            return Err(failed(
                "the capture directory is not a runtime-owned 0700 directory",
            ));
        }
        Ok(())
    }

    /// `requireRuntimePrivateDir` — the capture directory must be a
    /// runtime-owned 0700 directory, as the installation creates it.
    async fn require_runtime_private_dir(&self, path: &Path) -> Result<(), Failure> {
        let md = tokio::fs::symlink_metadata(path)
            .await
            .map_err(|_| failed("the capture directory is missing (run the harness setup)"))?;
        use std::os::unix::fs::MetadataExt;
        let ok = md.is_dir()
            && !md.file_type().is_symlink()
            && md.uid() == self.runtime_uid
            && md.mode() & 0o777 == 0o700;
        if !ok {
            return Err(failed(
                "the capture directory is not a runtime-owned 0700 directory",
            ));
        }
        Ok(())
    }

    /// `prepareCaptureDirs` — requires `data_root/capture`, creates
    /// `capture/tmp` the same way if needed, removes a leftover
    /// capture, and gives the Run a fresh temp directory.
    async fn prepare_capture_dirs(&self, run: RunId) -> Result<(), Failure> {
        self.require_runtime_private_dir(&self.capture_root())
            .await?;
        let tmp = self.capture_root().join("tmp");
        match tokio::fs::create_dir(&tmp).await {
            Ok(()) => {
                use std::os::unix::fs::PermissionsExt;
                tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o700))
                    .await
                    .map_err(|_| failed("create the capture temp directory"))?;
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(failed("create the capture temp directory")),
        }
        self.require_runtime_private_dir(&tmp).await?;
        self.release_dirs(run).await?;
        let run_tmp = self.capture_tmp_path(run);
        tokio::fs::create_dir(&run_tmp)
            .await
            .map_err(|_| failed("create the run's capture temp directory"))?;
        // Upstream `os.Mkdir(captureTmpPath, 0o700)` — a failed mode
        // fails the capture.
        tokio::fs::set_permissions(&run_tmp, {
            use std::os::unix::fs::PermissionsExt;
            std::fs::Permissions::from_mode(0o700)
        })
        .await
        .map_err(|_| failed("create the run's capture temp directory"))?;
        Ok(())
    }

    async fn release_dirs(&self, run: RunId) -> Result<(), Failure> {
        let mut failed_dir = false;
        for p in [
            self.shadow_path(run),
            self.log_shadow_path(run),
            self.capture_tmp_path(run),
        ] {
            match tokio::fs::remove_dir_all(&p).await {
                Err(e) if e.kind() != io::ErrorKind::NotFound => failed_dir = true,
                _ => {}
            }
        }
        if failed_dir {
            return Err(failed("remove the capture files"));
        }
        Ok(())
    }
}

/// `go_quote` — `strconv.Quote` for a byte string: `"`…`"` with `\xNN`
/// escapes for control and non-ASCII bytes.
fn go_quote(b: &[u8]) -> String {
    let mut s = String::from("\"");
    for &c in b {
        match c {
            b'"' => s.push_str("\\\""),
            b'\\' => s.push_str("\\\\"),
            0x20..=0x7e => s.push(c as char),
            b'\n' => s.push_str("\\n"),
            b'\t' => s.push_str("\\t"),
            _ => s.push_str(&format!("\\x{c:02x}")),
        }
    }
    s.push('"');
    s
}

impl WorkspaceCapture for GitClone {
    /// Upstream `Capture` — seals the Run for the capture's duration
    /// (the operator gets its access back when this returns), then
    /// writes the patch and the commits artifact into
    /// `data_root/capture/tmp/<run-id>/` under their byte caps, all
    /// under one [`CAPTURE_TIMEOUT`] deadline.
    fn capture<'a>(
        &'a self,
        ws: WorkspaceId,
        workspace: Workspace,
        run: RunId,
    ) -> PortFuture<'a, Result<Capture, Failure>> {
        Box::pin(async move {
            if ws.is_nil() || run.is_nil() {
                return Err(failed("workspace and run ids are required"));
            }
            let repo = self.run_dir(run).join("repo");
            if workspace.path != repo.to_string_lossy()
                || !is_object_id(workspace.base_sha.as_bytes())
            {
                return Err(failed("the workspace is not this run's clone"));
            }
            let deadline = Instant::now() + CAPTURE_TIMEOUT;
            let check = |d: Instant| {
                if Instant::now() > d {
                    Err(failed("capture deadline"))
                } else {
                    Ok(())
                }
            };
            let sealed: Box<dyn SealedClone> = match tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                self.sealer.seal(run),
            )
            .await
            {
                Ok(r) => r?,
                Err(_) => return Err(failed("capture deadline")),
            };
            // Unseal once every read of the clone is done, on success
            // and failure alike; `Unseal`'s drop also covers the drop
            // path.
            let result = async {
                self.prepare_capture_dirs(run).await?;
                let source = self.source_path(ws);
                let c = CaptureCtx {
                    repo: sealed.repo_path().to_string(),
                    base: workspace.base_sha.clone(),
                    shadow: self.shadow_path(run),
                    log_shadow: self.log_shadow_path(run),
                    tmp: self.capture_tmp_path(run),
                    index: self.capture_tmp_path(run).join("index"),
                };
                // The patch, written whole with the patch shadow before
                // any clone object is copied anywhere.
                self.init_shadow(deadline, &c.shadow, &source, &c.index)
                    .await?;
                let nested = sealed.nested_repos(deadline, WalkLimits::default()).await?;
                let patch = c.tmp.join("patch");
                self.write_patch(deadline, &c, &patch, &nested).await?;
                // The commits, with the log shadow; the clone's objects
                // are copied as data.
                self.init_shadow(deadline, &c.log_shadow, &source, &c.index)
                    .await?;
                let _ = sealed
                    .copy_objects(
                        c.log_shadow.join("objects"),
                        deadline,
                        ObjectLimits::default(),
                    )
                    .await?;
                check(deadline)?;
                let mut after = sealed.after_head().unwrap_or_default();
                check(deadline)?;
                if !after.is_empty() && !self.has_commit(deadline, &c, &after).await {
                    after = String::new();
                }
                let commits = c.tmp.join("commits");
                self.write_commits(deadline, &c, &commits, &after).await?;
                check(deadline)?;
                Ok(Capture {
                    patch: patch.to_string_lossy().into_owned(),
                    commits: commits.to_string_lossy().into_owned(),
                    after_head: after,
                })
            }
            .await;
            let _ = sealed.unseal();
            if result.is_err() {
                let _ = self.release_dirs(run).await;
            }
            result
        })
    }

    /// Upstream `Release` — removes the Run's two shadow repositories
    /// and capture temp files; idempotent.
    fn release<'a>(&'a self, run: RunId) -> PortFuture<'a, Result<(), Failure>> {
        Box::pin(async move {
            if run.is_nil() {
                return Err(failed("run id is required"));
            }
            self.release_dirs(run).await
        })
    }
}
