//! Development restore-barrier inspector — the R3 dev-gated stand-in
//! for upstream's broker-mediated `InspectRestoreBarrier`
//! (`internal/adapter/authority/broker/recovery_journal.go`).
//!
//! Upstream the protected broker owns a private file journal of restore
//! operations and serves an authoritative scan under its journal lock.
//! The R3 slice has no broker; under the `CENTRAL_LOCALEXEC=1`
//! development gate this inspector applies the same rules to a
//! development journal directory:
//!
//! - a *missing* directory means no protected restore has ever run —
//!   the barrier is inactive (the dev layout creates the root on first
//!   use, where upstream's broker always provisions its root);
//! - a present directory is validated private (0700) and must contain
//!   only `{operation-id}.json` records and `*.json.lock` lock files;
//!   anything else is ambiguous and therefore denies serving;
//! - a record whose `phase` is not terminal (`ready`/`abandoned`)
//!   occupies the barrier: serve must refuse with
//!   `RESTORE_RESUME_REQUIRED`;
//! - two active records or a malformed one are ambiguous — refuse.
//!
//! The production path keeps upstream's refusal: without the dev gate
//! the composition reports `RESTORE_BARRIER_UNAVAILABLE` — the same
//! fail-closed shape as the dev bootstrap gate.

use std::path::{Path, PathBuf};

use central_foundation::failure::Failure;

fn failed(msg: &'static str) -> Failure {
    Failure::unavailable("restore_barrier", msg)
}

/// One journal record — the minimal projection the barrier decision
/// needs (upstream validates the full record and the file name binds
/// the operation id).
#[derive(serde::Deserialize)]
struct JournalRecord {
    operation_id: String,
    phase: String,
}

/// `journalStore.InspectRestoreBarrier` over a dev journal directory.
pub struct DevRestoreBarrier {
    root: PathBuf,
}

impl DevRestoreBarrier {
    /// Creates (or opens) the private journal root — the dev layout
    /// provisions the directory the way upstream's broker always does
    /// (`os.MkdirAll(path, privateDirectoryMode)` → `0700`), so an
    /// absent root is a first-run rather than a fault. A pre-existing
    /// directory is adopted as-is: [`Self::inspect`] validates its
    /// permissions and refuses a non-`0700` root — the barrier never
    /// chmods what it did not create.
    ///
    /// # Errors
    /// `Failure::unavailable` when the root cannot be provisioned.
    pub fn new(root: PathBuf) -> Result<Self, Failure> {
        if !root.exists() {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&root)
                .map_err(|_| failed("create the restore journal root"))?;
        }
        Ok(Self { root })
    }

    /// `InspectRestoreBarrier` — returns the single non-terminal
    /// restore operation id when the barrier is occupied.
    ///
    /// # Errors
    /// `Failure::unavailable` when the journal cannot be trusted
    /// (permissions, unexpected entries, malformed records, or more
    /// than one active operation).
    pub fn inspect(&self) -> Result<Option<String>, Failure> {
        validate_private_directory(&self.root)?;
        let mut active: Option<String> = None;
        let entries =
            std::fs::read_dir(&self.root).map_err(|_| failed("read the restore journal"))?;
        for entry in entries {
            let entry = entry.map_err(|_| failed("read a restore journal entry"))?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let path = entry.path();
            if name.ends_with(".json.lock") {
                validate_private_file(&path)?;
                continue;
            }
            if entry
                .file_type()
                .map_err(|_| failed("inspect a restore journal entry"))?
                .is_dir()
                || !name.ends_with(".json")
            {
                return Err(failed("unexpected entry in the restore journal"));
            }
            validate_private_file(&path)?;
            let body = std::fs::read(&path).map_err(|_| failed("read a restore journal record"))?;
            let record: JournalRecord = serde_json::from_slice(&body)
                .map_err(|_| failed("restore journal record is malformed"))?;
            let id_ok = !record.operation_id.is_empty()
                && record.operation_id.parse::<uuid_like::Id>().is_ok();
            if !id_ok {
                return Err(failed("restore journal record is malformed"));
            }
            if matches!(record.phase.as_str(), "ready" | "abandoned") {
                continue;
            }
            if active.is_some() {
                return Err(failed("more than one active restore operation"));
            }
            active = Some(record.operation_id);
        }
        Ok(active)
    }
}

mod uuid_like {
    /// A minimal UUID shape check — the journal binds the operation id;
    /// the kernel does not need its value.
    pub struct Id;
    impl std::str::FromStr for Id {
        type Err = ();
        fn from_str(s: &str) -> Result<Self, ()> {
            let hex = s.len() == 36
                && s.chars().enumerate().all(|(i, c)| match i {
                    8 | 13 | 18 | 23 => c == '-',
                    _ => c.is_ascii_hexdigit(),
                });
            if hex { Ok(Id) } else { Err(()) }
        }
    }
}

/// `validatePrivateDirectory` — the journal root must be a
/// runtime-owned 0700 directory (upstream's private-state rule).
fn validate_private_directory(path: &Path) -> Result<(), Failure> {
    let md =
        std::fs::symlink_metadata(path).map_err(|_| failed("inspect the restore journal root"))?;
    use std::os::unix::fs::MetadataExt;
    if !(md.is_dir() && !md.file_type().is_symlink() && md.mode() & 0o777 == 0o700) {
        return Err(failed(
            "the restore journal root is not a private directory",
        ));
    }
    Ok(())
}

/// `validatePrivateFile` — journal records are regular 0600 files.
fn validate_private_file(path: &Path) -> Result<(), Failure> {
    let md =
        std::fs::symlink_metadata(path).map_err(|_| failed("inspect a restore journal entry"))?;
    use std::os::unix::fs::MetadataExt;
    if !(md.file_type().is_file() && md.mode() & 0o777 == 0o600) {
        return Err(failed("a restore journal entry is not a private file"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};

    fn test_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "central-restore-barrier-test-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    /// A first-run root is provisioned private — `0700`, not the umask
    /// default — so `inspect` admits it instead of self-refusing.
    #[test]
    fn fresh_root_is_created_private_and_inactive() {
        let root = test_root("fresh");
        let barrier = DevRestoreBarrier::new(root.clone()).unwrap();
        let md = std::fs::symlink_metadata(&root).unwrap();
        assert_eq!(
            md.mode() & 0o777,
            0o700,
            "the dev journal root must be provisioned private"
        );
        assert_eq!(
            barrier.inspect().unwrap(),
            None,
            "an empty journal is an inactive barrier"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A pre-existing root is adopted as-is: a non-private directory
    /// stays non-private (no chmod) and `inspect` refuses it.
    #[test]
    fn preexisting_non_private_root_still_refuses() {
        let root = test_root("nonprivate");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(&root)
            .unwrap();
        let barrier = DevRestoreBarrier::new(root.clone()).unwrap();
        let md = std::fs::symlink_metadata(&root).unwrap();
        assert_eq!(
            md.mode() & 0o777,
            0o755,
            "the barrier must not chmod a root it did not create"
        );
        let err = barrier.inspect().unwrap_err();
        assert_eq!(err.code(), "restore_barrier");
        let _ = std::fs::remove_dir_all(&root);
    }
}
