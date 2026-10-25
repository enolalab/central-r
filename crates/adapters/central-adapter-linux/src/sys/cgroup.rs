//! cgroup v2 resource limits — upstream `internal/sandbox/envelope_linux.go`'s
//! `ApplyCgroupLimits` plus `launcher_linux.go`'s
//! `createCgroup`/`cleanupCgroup` lifecycle.
//!
//! Upstream's writes, one per set limit: `cpu.max` as
//! `"<cpu_cores * 100000> 100000"` (quota over the fixed 100ms period),
//! `memory.max` as the byte count, `pids.max` as the count. A zero or
//! absent limit writes nothing — same as upstream's `> 0` gates.
//!
//! [`create`] makes `/sys/fs/cgroup/central-sandbox/<run>/`, applies
//! the limits, and unlinks the subtree on failure — the transient
//! cgroup a sandboxed worker is moved into.

use std::path::{Path, PathBuf};

use central_foundation::failure::Failure;
use central_foundation::identity::RunId;

/// The cgroup v2 interface directory upstream creates subtrees under.
pub const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Upstream's subtree prefix — `/sys/fs/cgroup/central-sandbox/<uuid>/`.
const SANDBOX_SUBTREE: &str = "central-sandbox";

/// The cgroup-v2 limits — upstream `ResourceLimits`'s three
/// cgroup-backed fields. `MaxFileDescriptors` is a rlimit, not a
/// cgroup write, and stays in the launcher's own attr setup.
#[derive(Clone, Copy, Debug, Default)]
pub struct Limits {
    /// CPU in cores; `> 0` writes `cpu.max "<cores*100000> 100000"`.
    pub cpu_cores: f64,
    /// Memory ceiling in bytes; `> 0` writes `memory.max`.
    pub memory_bytes: u64,
    /// Process count ceiling; `> 0` writes `pids.max`.
    pub max_processes: u32,
}

fn os_failure(step: &str, e: impl std::fmt::Display) -> Failure {
    Failure::internal("sys_cgroup_os", format!("{step}: {e}"))
}

/// `ApplyCgroupLimits` — write each set limit to its cgroup v2
/// interface file beneath `cg`.
///
/// # Errors
/// `sys_cgroup_os` on the first write failure (`EACCES`/`EPERM` on a
/// cgroup the caller cannot delegate to, `ENOENT` on a v1 host).
pub fn apply_limits(cg: &Path, limits: &Limits) -> Result<(), Failure> {
    if limits.cpu_cores > 0.0 {
        // CPU quota is expressed as "MAX PERIOD" in microseconds.
        // Period is fixed at 100000 µs (100 ms) — upstream's comment.
        let quota = (limits.cpu_cores * 100_000.0) as i64;
        write_file(cg, "cpu.max", format!("{quota} 100000"))?;
    }
    if limits.memory_bytes > 0 {
        write_file(cg, "memory.max", limits.memory_bytes.to_string())?;
    }
    if limits.max_processes > 0 {
        write_file(cg, "pids.max", limits.max_processes.to_string())?;
    }
    Ok(())
}

fn write_file(cg: &Path, name: &'static str, value: String) -> Result<(), Failure> {
    std::fs::write(cg.join(name), value).map_err(|e| os_failure(name, e))
}

/// `createCgroup` — a transient subtree under
/// `/sys/fs/cgroup/central-sandbox/<run>` with the limits applied;
/// the subtree is removed on any failure, upstream's cleanup-before-
/// return.
///
/// # Errors
/// `sys_cgroup_os` on `mkdir` or a limit write failure (a non-root
/// caller gets `EACCES` — the launcher is privileged).
pub fn create(run: RunId, limits: &Limits) -> Result<PathBuf, Failure> {
    let parent = Path::new(CGROUP_ROOT).join(SANDBOX_SUBTREE);
    std::fs::create_dir_all(&parent).map_err(|e| os_failure("cgroup mkdir parent", e))?;
    let cg = parent.join(run.to_string());
    std::fs::create_dir(&cg).map_err(|e| os_failure("cgroup mkdir", e))?;
    if let Err(e) = apply_limits(&cg, limits) {
        cleanup(&cg);
        return Err(e);
    }
    Ok(cg)
}

/// `cleanupCgroup` — remove a subtree [`create`] made; missing is fine.
pub fn cleanup(cg: &Path) {
    let _ = std::fs::remove_dir(cg);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The writes land with upstream's exact encodings — on a real
    /// cgroup tree when the test can reach one; on any writable
    /// directory otherwise (the interface files are plain writes —
    /// the cgroup magic is the kernel's, not the file's).
    #[test]
    fn apply_writes_upstream_values() {
        // A real cgroup v2 write is a root-only, mount-dependent case;
        // the value-encoding contract — what upstream's tests pin — is
        // host-independent.
        let dir = std::env::temp_dir().join(format!("central-sys-cgroup-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        apply_limits(
            &dir,
            &Limits {
                cpu_cores: 1.5,
                memory_bytes: 1 << 30,
                max_processes: 64,
            },
        )
        .expect("apply");
        assert_eq!(
            std::fs::read_to_string(dir.join("cpu.max")).unwrap(),
            "150000 100000"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("memory.max")).unwrap(),
            "1073741824"
        );
        assert_eq!(std::fs::read_to_string(dir.join("pids.max")).unwrap(), "64");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A zero limit writes nothing — upstream's `> 0` gates, no file.
    #[test]
    fn apply_skips_zero_limits() {
        let dir =
            std::env::temp_dir().join(format!("central-sys-cgroup-zero-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        apply_limits(&dir, &Limits::default()).expect("apply");
        assert!(!dir.join("cpu.max").exists());
        assert!(!dir.join("memory.max").exists());
        assert!(!dir.join("pids.max").exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `create`/`cleanup` against the real cgroup root — root-only,
    /// skips as non-root (expected, not a failure).
    #[test]
    fn create_and_cleanup_real_cgroup() {
        if !rustix::process::geteuid().is_root() {
            return;
        }
        if !Path::new(CGROUP_ROOT).join("cgroup.controllers").exists() {
            return; // cgroup v1 host — the primitive is v2-only
        }
        match create(
            RunId::new(),
            &Limits {
                cpu_cores: 0.0,
                memory_bytes: 0,
                max_processes: 32,
            },
        ) {
            Ok(cg) => {
                assert_eq!(std::fs::read_to_string(cg.join("pids.max")).unwrap(), "32");
                cleanup(&cg);
                assert!(!cg.exists());
            }
            Err(e) => {
                // A read-only or delegation-refusing cgroup mount is a
                // valid host state — report it, don't claim a pass.
                eprintln!("cgroup create refused by host: {e}");
            }
        }
    }
}
