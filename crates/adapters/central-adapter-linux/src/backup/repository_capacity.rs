//! `repository_capacity.go` — the descriptor-derived C02 repository
//! observation. `bytes` includes sealed, unsealed, partial, and
//! temporary regular files; `sealed_backups` comes only from the
//! canonical root index.

#![forbid(unsafe_code)]

use std::os::fd::OwnedFd;

use central_backup::backup::capacity::DeviceCapacitySnapshot;
use central_backup::port::BackupRepositoryCensus;
use central_foundation::failure::Failure;
use rustix::fs::{Dir, FileType, Mode, OFlags, fstat};
use uuid::Uuid;

use super::capacity::{capacity_descriptor_unavailable, device_capacity_from_descriptor};
use super::repository::{
    Repository, duplicate_descriptor, repository_census_unavailable, safe_path_component,
    secure_open_at,
};

/// `maximumRepositoryCensusEntries`.
const MAXIMUM_REPOSITORY_CENSUS_ENTRIES: usize = 250_000;
/// `maximumRepositoryCensusDepth`.
const MAXIMUM_REPOSITORY_CENSUS_DEPTH: usize = 16;

impl Repository {
    /// `CapacityCensus` traverses only beneath the already-bound root
    /// descriptor. It neither accepts nor reports a pathname and fails
    /// closed on any unexpected filesystem type, ownership/mode/link
    /// drift, mount crossing, or bound.
    pub fn capacity_census(&self) -> Result<BackupRepositoryCensus, Failure> {
        if self.validate().is_err() {
            return Err(repository_census_unavailable());
        }
        let index = self
            .read_root_manifest()
            .map_err(|_| repository_census_unavailable())?;
        let mut census = CensusWalk {
            uid: self.binding.owner_uid,
            gid: self.binding.owner_gid,
            entries: 0,
            bytes: 0,
        };
        census
            .directory(&self.root_fd, 0)
            .map_err(|_| repository_census_unavailable())?;
        Ok(BackupRepositoryCensus {
            bytes: census.bytes,
            sealed_backups: index.sealed_backups.len() as u64,
        })
    }

    /// `SealedBackupIDs` returns the identity of every sealed backup in
    /// the canonical root index, in the index's own order. It is the
    /// same single source of truth `capacity_census` counts —
    /// `write_seal_companion` appends to that index only after the
    /// immutable per-backup seal has been published, so a backup
    /// appears here exactly when it became restorable — rather than a
    /// second opinion derived from a directory listing, which would
    /// report half-written media as a candidate.
    ///
    /// It reports identities and nothing else: no path, size,
    /// timestamp, or ordering hint that could be used to rank one
    /// candidate above another. That is deliberate. Its only caller is
    /// the verify candidate resolver, whose whole rule is to take the
    /// single candidate and refuse to guess when there is more than
    /// one; handing it a field it could sort by would be handing it a
    /// way to choose.
    pub fn sealed_backup_ids(&self) -> Result<Vec<Uuid>, Failure> {
        if self.validate().is_err() {
            return Err(repository_census_unavailable());
        }
        let index = self
            .read_root_manifest()
            .map_err(|_| repository_census_unavailable())?;
        let mut identities = Vec::with_capacity(index.sealed_backups.len());
        for entry in &index.sealed_backups {
            if entry.backup_id.is_nil() {
                return Err(repository_census_unavailable());
            }
            identities.push(entry.backup_id);
        }
        Ok(identities)
    }

    /// `DeviceCapacity` measures the exact device behind this bound
    /// repository.
    pub fn device_capacity(&self) -> Result<DeviceCapacitySnapshot, Failure> {
        if self.validate().is_err() {
            return Err(capacity_descriptor_unavailable());
        }
        device_capacity_from_descriptor(&self.root_fd)
    }
}

/// `repositoryCensusWalk`.
struct CensusWalk {
    uid: u32,
    gid: u32,
    entries: usize,
    bytes: u64,
}

impl CensusWalk {
    fn directory(&mut self, directory_fd: &OwnedFd, depth: usize) -> Result<(), Failure> {
        if depth > MAXIMUM_REPOSITORY_CENSUS_DEPTH {
            return Err(repository_census_unavailable());
        }
        let duplicate =
            duplicate_descriptor(directory_fd).map_err(|_| repository_census_unavailable())?;
        let mut dir = Dir::read_from(&duplicate).map_err(|_| repository_census_unavailable())?;
        for entry in dir.by_ref() {
            let entry = entry.map_err(|_| repository_census_unavailable())?;
            let name = entry
                .file_name()
                .to_str()
                .map_err(|_| repository_census_unavailable())?;
            if name == "." || name == ".." {
                continue;
            }
            if !safe_path_component(name) || self.entries >= MAXIMUM_REPOSITORY_CENSUS_ENTRIES {
                return Err(repository_census_unavailable());
            }
            self.entries += 1;
            let fd = secure_open_at(directory_fd, name, OFlags::RDONLY, Mode::empty())
                .map_err(|_| repository_census_unavailable())?;
            let stat = fstat(&fd).map_err(|_| repository_census_unavailable())?;
            if stat.st_uid != self.uid || stat.st_gid != self.gid {
                return Err(repository_census_unavailable());
            }
            let file_type = FileType::from_raw_mode(stat.st_mode);
            if file_type.is_dir() {
                if stat.st_mode & 0o777 != 0o700 {
                    return Err(repository_census_unavailable());
                }
                self.directory(&fd, depth + 1)?;
            } else if file_type.is_file() {
                if stat.st_mode & 0o777 != 0o600
                    || stat.st_nlink != 1
                    || stat.st_size < 0
                    || self.bytes.checked_add(stat.st_size as u64).is_none()
                {
                    return Err(repository_census_unavailable());
                }
                self.bytes += stat.st_size as u64;
            } else {
                return Err(repository_census_unavailable());
            }
        }
        Ok(())
    }
}
