//! `gitclone` — the Central-owned per-Run workspace of harness phase 3a
//! (decisions 5, 6, 14): a `git clone --no-local --no-hardlinks` of the
//! Workspace's source repository, hooks and fsmonitor disabled, into
//! `<data_root>/worktrees/runs/<run-id>/repo`, the base commit recorded
//! and POSIX ACLs (granted through the [`WorkspaceSealer`]) letting the
//! operator's harness write the clone while the runtime keeps read
//! access.
//!
//! It runs git only on data serve owns. Once a harness has run in a
//! clone, everything under the Run directory is untrusted (3a spec
//! §10): [`GitClone::provision`] never touches a clone again, and
//! [`GitClone::capture`] (harness phase 3b) seals the Run for its
//! duration through the injected [`WorkspaceSealer`], runs git only
//! against its own shadow repositories, reading the clone through
//! no-follow file descriptors and as a work tree only.
//!
//! R3 open decision D2: the OS-boundary half of upstream's Linux-only
//! code is the consumer-side [`WorkspaceSealer`] port in
//! `central_harness::app::ports`; `central-adapter-linux::workspace_seal`
//! implements it over `rustix`. This crate never imports the Linux
//! adapter — the kernel injects the sealer at construction.

mod capture;
mod provision;
#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};

use central_foundation::identity::{RunId, WorkspaceId};

pub use capture::{
    CAPTURE_GIT_MEMORY_LIMIT, CAPTURE_TIMEOUT, MAX_COMMITS, MAX_COMMITS_BYTES, MAX_PATCH_BYTES,
};

/// `DefaultGitPath` — the git binary [`GitClone`] runs when
/// [`GitCloneConfig::git_path`] is empty. Never resolved through `PATH`.
pub const DEFAULT_GIT_PATH: &str = "/usr/bin/git";

/// `gitWaitDelay` — how long a cancelled provisioning git's run may
/// take to return once its deadline killed it (5 s upstream).
pub const GIT_WAIT_DELAY: std::time::Duration = std::time::Duration::from_secs(5);

/// `maxValidUID` — `u32::MAX - 1`; `u32::MAX` is the kernel ACL
/// xattr's `ACL_UNDEFINED_ID`.
pub const MAX_VALID_UID: u32 = u32::MAX - 1;

/// Upstream `Config` — validated by [`GitClone::new`].
#[derive(Debug, Clone)]
pub struct GitCloneConfig {
    /// `DataRoot` — the root-owned harness data root
    /// (`/var/lib/central-harness`). Sources live in
    /// `DataRoot/sources/<workspace-id>.git`, Run clones in
    /// `DataRoot/worktrees/runs/<run-id>/repo`.
    pub data_root: PathBuf,
    /// `GitPath` — the absolute git binary; empty means
    /// [`DEFAULT_GIT_PATH`].
    pub git_path: String,
    /// `OperatorUID` — the user whose harness writes the clone.
    pub operator_uid: u32,
    /// `RuntimeUID` — central-runtime's user; owns every Run
    /// directory and clone root.
    pub runtime_uid: u32,
    /// `MinFree` — the minimum free space at the data root
    /// (`CENTRAL_HARNESS_MIN_FREE`); zero disables the check.
    pub min_free: u64,
    /// `MaxPatchBytes` — the patch body cap (tests shrink it).
    pub max_patch_bytes: u64,
    /// `MaxCommitsBytes` — the commits body cap.
    pub max_commits_bytes: u64,
    /// `MaxCommits` — the listed-commits bound.
    pub max_commits: usize,
}

impl Default for GitCloneConfig {
    fn default() -> Self {
        Self {
            data_root: PathBuf::new(),
            git_path: String::new(),
            operator_uid: 0,
            runtime_uid: 0,
            min_free: 0,
            max_patch_bytes: MAX_PATCH_BYTES,
            max_commits_bytes: MAX_COMMITS_BYTES,
            max_commits: MAX_COMMITS,
        }
    }
}

/// Upstream `Provisioner` — creates per-Run clones and captures their
/// work. The sealer is the D2-injected untrusted-clone OS boundary.
pub struct GitClone {
    root: PathBuf,
    git: String,
    runtime_uid: u32,
    min_free: u64,
    sealer: std::sync::Arc<dyn central_harness::app::ports::WorkspaceSealer>,
    max_patch_bytes: u64,
    max_commits_bytes: u64,
    max_commits: usize,
}

mod codes {
    /// `ErrInvalidConfig` — bad constructor arguments.
    pub const INVALID_CONFIG: &str = "gitclone_invalid_config";
    /// `ErrSourceMissing` — the source repository is absent or not a
    /// real directory.
    pub const SOURCE_MISSING: &str = "gitclone_source_missing";
    /// `ErrSourceEmpty` — the source has no commit on its default
    /// branch.
    pub const SOURCE_EMPTY: &str = "gitclone_source_empty";
}

impl GitClone {
    /// Upstream `New` — validates `cfg` and takes the D2 sealer.
    pub fn new(
        cfg: GitCloneConfig,
        sealer: std::sync::Arc<dyn central_harness::app::ports::WorkspaceSealer>,
    ) -> Result<Self, central_foundation::failure::Failure> {
        use central_foundation::failure::Failure;
        let git = if cfg.git_path.is_empty() {
            DEFAULT_GIT_PATH.to_string()
        } else {
            cfg.git_path.clone()
        };
        for (name, p) in [
            ("data root", cfg.data_root.as_path()),
            ("git path", Path::new(&git)),
        ] {
            let s = p.as_os_str();
            let clean = p == Path::new(&s).components().collect::<PathBuf>();
            if !p.is_absolute() || !clean || p == Path::new("/") {
                return Err(Failure::invalid(
                    codes::INVALID_CONFIG,
                    format!("{name} must be an absolute, clean, non-root path"),
                ));
            }
        }
        if cfg.operator_uid < 1
            || cfg.operator_uid > MAX_VALID_UID
            || cfg.runtime_uid < 1
            || cfg.runtime_uid > MAX_VALID_UID
        {
            return Err(Failure::invalid(
                codes::INVALID_CONFIG,
                format!("operator and runtime uids must be in [1, {MAX_VALID_UID}]"),
            ));
        }
        Ok(Self {
            root: cfg.data_root,
            git,
            runtime_uid: cfg.runtime_uid,
            min_free: cfg.min_free,
            sealer,
            max_patch_bytes: cfg.max_patch_bytes,
            max_commits_bytes: cfg.max_commits_bytes,
            max_commits: cfg.max_commits,
        })
    }

    /// Upstream `SourcePath` — the Workspace's source repository.
    #[must_use]
    pub fn source_path(&self, ws: WorkspaceId) -> PathBuf {
        self.root.join("sources").join(format!("{ws}.git"))
    }

    /// Upstream `RunDir` — the Run's directory; the clone is `repo`.
    #[must_use]
    pub fn run_dir(&self, run: RunId) -> PathBuf {
        self.root
            .join("worktrees")
            .join("runs")
            .join(run.to_string())
    }

    /// `captureRoot` — `data_root/capture`.
    fn capture_root(&self) -> PathBuf {
        self.root.join("capture")
    }

    /// `shadowPath` — the patch shadow; it never holds a clone object.
    fn shadow_path(&self, run: RunId) -> PathBuf {
        self.capture_root().join(format!("{run}.git"))
    }

    /// `logShadowPath` — the log shadow, the only place the clone's
    /// objects are copied to.
    fn log_shadow_path(&self, run: RunId) -> PathBuf {
        self.capture_root().join(format!("{run}-log.git"))
    }

    /// `captureTmpPath` — the Run's capture temp directory.
    fn capture_tmp_path(&self, run: RunId) -> PathBuf {
        self.capture_root().join("tmp").join(run.to_string())
    }
}
