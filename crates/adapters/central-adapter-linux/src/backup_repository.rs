//! `internal/adapter/backup/repository.go` — the genesis-needed slice:
//! `repositoryFilesystemIdentity`, `secureOpenAt`, `createOnlyAt`,
//! `fchownAt`, and `InitializeRepositoryBinding`, which writes the
//! fresh `binding.json` + `backup-repository.lock` +
//! `repository-manifest.json` triple bound to the new instance
//! (SC-DEF-31). The repository reader/mutator surface is the R6
//! backup slice's.

use std::os::fd::AsFd;
#[cfg(test)]
use std::os::unix::fs::MetadataExt as _;

use central_backup::repository::{
    RepositoryBinding, new_repository_binding, new_repository_manifest,
};
use central_foundation::failure::Failure;
use rustix::fs::{AtFlags, FileType, Mode, OFlags, StatxFlags, openat2, statx};

use crate::sys::openat2::RESOLVE_FLAGS;

/// Upstream's single refusal — `ErrInvalidRepository`. Every failure
/// inside `initializeRepositoryBinding` collapses onto it, so callers
/// distinguish "invalid repository" from nothing else.
fn invalid(message: impl Into<String>) -> Failure {
    Failure::invalid(
        "sys_backup_repository",
        format!("repository binding: {}", message.into()),
    )
}

fn io_invalid(step: impl std::fmt::Display, e: impl std::fmt::Display) -> Failure {
    Failure::internal(
        "sys_backup_repository",
        format!("repository binding: {step}: {e}"),
    )
}

/// `safePathComponent`.
fn safe_path_component(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains('/') && !name.contains('\0')
}

/// `secureOpenAt` — descriptor-relative `openat2` under the full
/// containment set (`RESOLVE_BENEATH|NO_SYMLINKS|NO_MAGICLINKS|
/// NO_XDEV`, plus `O_NOFOLLOW` on the final component).
fn secure_open_at<Fd: AsFd>(
    parent: Fd,
    name: &str,
    flags: OFlags,
    mode: Mode,
) -> Result<std::os::fd::OwnedFd, Failure> {
    if !safe_path_component(name) {
        return Err(invalid(format!(
            "{name:?} is not a single safe path component"
        )));
    }
    openat2(
        parent,
        name,
        flags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        mode,
        RESOLVE_FLAGS,
    )
    .map_err(|e| io_invalid("openat2", e))
}

/// `createOnlyAt` — `O_WRONLY|O_CREAT|O_EXCL` at mode `0600`, written
/// and synced through the fresh descriptor; the parent directory is
/// synced before returning so a crash cannot lose the entry.
fn create_only_at<Fd: AsFd>(parent: Fd, name: &str, payload: &[u8]) -> Result<(), Failure> {
    let fd = secure_open_at(
        &parent,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|e| {
        // Upstream maps EEXIST to ErrAlreadyExists and everything else
        // to ErrInvalidRepository; genesis needs only the refusal.
        let _ = e;
        invalid(format!("create-only {name}"))
    })?;
    {
        let mut file = std::fs::File::from(fd);
        use std::io::Write as _;
        file.write_all(payload)
            .map_err(|e| io_invalid(format!("write {name}"), e))?;
        file.sync_all()
            .map_err(|e| io_invalid(format!("sync {name}"), e))?;
    }
    rustix::fs::fsync(&parent).map_err(|e| io_invalid("sync repository root", e))
}

/// `fchownAt` — chowns `name`, opened relative to `parent` with
/// `O_NOFOLLOW`, to `uid:gid`. Only ever used on this module's own
/// just-created files (SC-DEF-31).
fn fchown_at<Fd: AsFd>(parent: Fd, name: &str, uid: u32, gid: u32) -> Result<(), Failure> {
    let fd = secure_open_at(parent, name, OFlags::RDONLY, Mode::empty())?;
    rustix::fs::fchown(
        fd,
        Some(rustix::process::Uid::from_raw(uid)),
        Some(rustix::process::Gid::from_raw(gid)),
    )
    .map_err(|e| io_invalid(format!("chown {name}"), e))
}

/// `repositoryFilesystemFacts`.
struct RepositoryFilesystemFacts {
    uid: u32,
    gid: u32,
    device_major: u64,
    device_minor: u64,
    inode: u64,
    mount_id: u64,
}

/// `repositoryFilesystemIdentity` — `statx(dirfd, "",
/// AT_EMPTY_PATH|AT_NO_AUTOMOUNT, BASIC_STATS|MNT_ID)`: the directory
/// must be `S_IFDIR` `0700` with a nonzero inode and mount id.
fn repository_filesystem_identity<Fd: AsFd>(fd: Fd) -> Result<RepositoryFilesystemFacts, Failure> {
    let stat = statx(
        fd,
        "",
        AtFlags::EMPTY_PATH | AtFlags::NO_AUTOMOUNT,
        StatxFlags::BASIC_STATS | StatxFlags::MNT_ID,
    )
    .map_err(|e| io_invalid("filesystem identity: statx", e))?;
    if !FileType::from_raw_mode(u32::from(stat.stx_mode)).is_dir()
        || stat.stx_mode & 0o777 != 0o700
        || stat.stx_ino == 0
        || stat.stx_mnt_id == 0
    {
        return Err(invalid(format!(
            "filesystem identity: root facts mode={:#o} inode={} mount={}",
            stat.stx_mode, stat.stx_ino, stat.stx_mnt_id
        )));
    }
    Ok(RepositoryFilesystemFacts {
        uid: stat.stx_uid,
        gid: stat.stx_gid,
        device_major: u64::from(stat.stx_dev_major),
        device_minor: u64::from(stat.stx_dev_minor),
        inode: stat.stx_ino,
        mount_id: stat.stx_mnt_id,
    })
}

/// `InitializeRepositoryBinding` — fresh `binding.json` bound to
/// `instance_id`, plus the sibling lock and the revision-0 manifest,
/// each chowned to the repository directory's own uid:gid (the
/// runtime owner the directory was handed to — SC-DEF-31). `fd` must
/// already be the validated repository root.
pub fn initialize_repository_binding<Fd: AsFd>(
    fd: Fd,
    instance_id: &str,
) -> Result<RepositoryBinding, Failure> {
    if instance_id.is_empty() {
        return Err(invalid("instance id is required"));
    }
    let identity = repository_filesystem_identity(&fd)?;
    let binding_id = uuid::Uuid::now_v7();
    let mut nonce = [0u8; 32];
    rustix::rand::getrandom(&mut nonce, rustix::rand::GetRandomFlags::empty())
        .map_err(|e| io_invalid("binding nonce", e))?;
    let binding = new_repository_binding(
        binding_id,
        instance_id,
        identity.uid,
        identity.gid,
        identity.device_major,
        identity.device_minor,
        identity.inode,
        identity.mount_id,
        time::OffsetDateTime::now_utc(),
        nonce,
    )
    .map_err(|_| invalid("binding value"))?;
    let payload = binding
        .canonical_json()
        .map_err(|_| invalid("binding encoding"))?;
    create_only_at(&fd, "binding.json", &payload).map_err(|_| invalid("binding publication"))?;
    fchown_at(&fd, "binding.json", identity.uid, identity.gid)
        .map_err(|_| invalid("binding ownership"))?;
    create_only_at(&fd, "backup-repository.lock", &[]).map_err(|_| invalid("lock publication"))?;
    fchown_at(&fd, "backup-repository.lock", identity.uid, identity.gid)
        .map_err(|_| invalid("lock ownership"))?;
    let manifest = new_repository_manifest(binding_id, 0, Vec::new())
        .map_err(|_| invalid("manifest value"))?;
    let manifest_payload = manifest
        .canonical_json()
        .map_err(|_| invalid("manifest encoding"))?;
    create_only_at(&fd, "repository-manifest.json", &manifest_payload)
        .map_err(|_| invalid("manifest publication"))?;
    fchown_at(&fd, "repository-manifest.json", identity.uid, identity.gid)
        .map_err(|_| invalid("manifest ownership"))?;
    Ok(binding)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    fn tempdir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "central-t13-repo-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .unwrap();
        dir
    }

    /// `InitializeRepositoryBinding` — the three files land
    /// create-only, owned by the directory's owner, bound to the
    /// instance; a second call refuses (nothing is create-once
    /// replaced).
    #[test]
    fn binding_init_writes_triple_bound_to_instance() {
        let dir = tempdir("init");
        let fd = rustix::fs::open(
            &dir,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let instance = uuid::Uuid::now_v7().to_string();
        let binding = initialize_repository_binding(&fd, &instance).unwrap();
        assert_eq!(binding.instance_id, instance);
        assert_eq!(binding.owner_uid, std::fs::metadata(&dir).unwrap().uid());
        for name in [
            "binding.json",
            "backup-repository.lock",
            "repository-manifest.json",
        ] {
            let meta = std::fs::metadata(dir.join(name)).unwrap();
            assert_eq!(meta.mode() & 0o777, 0o600, "{name}");
            assert_eq!(meta.nlink(), 1, "{name}");
        }
        let parsed = central_backup::repository::parse_repository_binding(
            &std::fs::read(dir.join("binding.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(parsed, binding);
        // Re-run refuses: create-only never replaces evidence.
        assert!(initialize_repository_binding(&fd, &instance).is_err());
        assert!(fd.as_raw_fd() >= 0);
        std::fs::remove_dir_all(&dir).ok();
    }
}
