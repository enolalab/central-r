//! Upstream `gitclone.go`'s provisioning half: `Provision`,
//! `Reopen`, `CheckFreeSpace` and the hermetic `git` runner.

use std::io;
use std::path::Path;
use std::process::Stdio;

use central_foundation::failure::Failure;
use central_foundation::identity::{RunId, WorkspaceId};
use central_harness::app::ports::{WorkspaceProvisioner, codes};
use central_harness::domain::Workspace;
use central_harness::gitmeta::is_object_id;
use central_harness::port::PortFuture;
use tokio::process::Command;

use super::{GIT_WAIT_DELAY, GitClone};

impl GitClone {
    /// Upstream `run` — one provisioning git command with an
    /// environment built from empty: no system or global config, no
    /// hooks, no fsmonitor, no prompts. Neither argv nor git's output
    /// reaches an error: git's stderr may quote repository content.
    async fn run_git(&self, dir: &Path, args: &[&str]) -> Result<String, Failure> {
        let mut cmd = Command::new(&self.git);
        cmd.args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "protocol.allow=never",
            "-c",
            "protocol.file.allow=always",
        ])
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
            ("GIT_ASKPASS", "/bin/false"),
            ("HOME", "/nonexistent"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
        let child = cmd.spawn().map_err(|_| git_failed(args[0]))?;
        // WaitDelay: give a killed git GIT_WAIT_DELAY to die, then reap
        // regardless of pipe-holding grandchildren.
        let out = match tokio::time::timeout(GIT_WAIT_DELAY, child.wait_with_output()).await {
            Ok(Ok(o)) => o,
            Ok(Err(_)) | Err(_) => return Err(git_failed(args[0])),
        };
        if !out.status.success() {
            return Err(git_failed(args[0]));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

fn git_failed(op: &str) -> Failure {
    Failure::unavailable(codes::WORKSPACE_UNAVAILABLE, format!("git {op} failed"))
}

fn workspace_unavailable(step: &str) -> Failure {
    Failure::unavailable(codes::WORKSPACE_UNAVAILABLE, step.to_string())
}

impl WorkspaceProvisioner for GitClone {
    /// Upstream `CheckFreeSpace` — delegated to the sealer's `freeBytes`.
    fn check_free_space<'a>(&'a self) -> PortFuture<'a, Result<(), Failure>> {
        Box::pin(async move {
            if self.min_free == 0 {
                return Ok(());
            }
            self.sealer.check_free_space().await
        })
    }

    /// Upstream `Provision` — clones the Workspace's source into
    /// `run_dir(run)/repo`, records the checked-out default-branch HEAD
    /// as `base_sha`, and grants the ACLs. It must run only before the
    /// attempt's `MarkInvoked`; under that precondition it is
    /// idempotent — a Run directory left by an earlier never-launched
    /// attempt is removed and provisioned again.
    fn provision<'a>(
        &'a self,
        ws: WorkspaceId,
        run: RunId,
    ) -> PortFuture<'a, Result<Workspace, Failure>> {
        Box::pin(async move {
            if ws.is_nil() || run.is_nil() {
                return Err(Failure::invalid(
                    super::codes::INVALID_CONFIG,
                    "workspace and run ids are required",
                ));
            }
            self.check_free_space().await?;
            let source = self.source_path(ws);
            // Lstat: a source that is a symlink is refused, never
            // followed.
            let is_dir = match tokio::fs::symlink_metadata(&source).await {
                Ok(m) => m.is_dir(),
                Err(_) => false,
            };
            if !is_dir {
                return Err(Failure::unavailable(
                    super::codes::SOURCE_MISSING,
                    "source repository missing (run the harness setup)",
                ));
            }
            let runs = self
                .run_dir(run)
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_default();
            match tokio::fs::metadata(&runs).await {
                Ok(m) if m.is_dir() => {}
                _ => return Err(workspace_unavailable("the runs directory is missing")),
            }
            let run_dir = self.run_dir(run);
            tokio::fs::remove_dir_all(&run_dir)
                .await
                .or_else(|e| {
                    if e.kind() == io::ErrorKind::NotFound {
                        Ok(())
                    } else {
                        Err(e)
                    }
                })
                .map_err(|_| workspace_unavailable("clear a stale run directory"))?;
            tokio::fs::create_dir(&run_dir)
                .await
                .map_err(|_| workspace_unavailable("create run directory"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ =
                    tokio::fs::set_permissions(&run_dir, std::fs::Permissions::from_mode(0o750))
                        .await;
            }
            let repo = run_dir.join("repo");
            let repo_s = repo.to_string_lossy().into_owned();
            // --no-local: the operator's group can write the source, so
            // the clone goes through upload-pack — only valid,
            // checksummed objects — instead of copying object files by
            // path (a path copy races a swapped-in symlink; S2).
            self.run_git(
                &run_dir,
                &[
                    "clone",
                    "--no-local",
                    "--no-hardlinks",
                    "--quiet",
                    "--template=",
                    "--",
                    &source.to_string_lossy(),
                    &repo_s,
                ],
            )
            .await?;
            let out = self
                .run_git(
                    &repo,
                    &["rev-parse", "--verify", "--quiet", "HEAD^{commit}"],
                )
                .await
                .map_err(|_| {
                    Failure::unavailable(
                        super::codes::SOURCE_EMPTY,
                        "source repository has no commit on its default branch",
                    )
                })?;
            let sha = out.trim();
            if !is_object_id(sha.as_bytes()) {
                return Err(workspace_unavailable("git rev-parse returned no commit id"));
            }
            let base_sha = sha.to_string();
            self.sealer.grant_run(run).await?;
            Ok(Workspace {
                path: repo_s,
                base_sha,
            })
        })
    }

    /// Upstream `Reopen` — verifies, without git and without reading
    /// clone content, that `want` names this Run's clone and that the
    /// Run directory and clone root are still the provisioned,
    /// runtime-owned ones. A half-sealed Run is refused, never
    /// repaired; everything after the `want` check is the sealer's.
    fn reopen<'a>(
        &'a self,
        ws: WorkspaceId,
        run: RunId,
        want: Workspace,
    ) -> PortFuture<'a, Result<(), Failure>> {
        Box::pin(async move {
            if ws.is_nil() || run.is_nil() {
                return Err(Failure::invalid(
                    super::codes::INVALID_CONFIG,
                    "workspace and run ids are required",
                ));
            }
            let repo = self.run_dir(run).join("repo");
            if want.path != repo.to_string_lossy() || !is_object_id(want.base_sha.as_bytes()) {
                return Err(workspace_unavailable(
                    "the workspace is not this run's clone",
                ));
            }
            self.sealer.verify_clone(run).await
        })
    }
}
