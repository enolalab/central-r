//! `capacity_linux.go` — descriptor-relative filesystem capacity
//! measurements for the recovery boundary. It never accepts a
//! pathname, so the runtime cannot select or disclose a device; the
//! returned identifier is a one-way representation of the filesystem
//! identity, suitable only for C02's duplicate-device and continuity
//! checks.

#![forbid(unsafe_code)]

use std::os::fd::AsFd;

use central_backup::backup::capacity::DeviceCapacitySnapshot;
use central_foundation::failure::Failure;
use rustix::fs::{FileType, fstat, fstatfs};
use sha2::{Digest, Sha256};

/// `ErrCapacityDescriptor` — a trusted recovery-root descriptor could
/// not produce a safe device measurement. It deliberately contains no
/// pathname, mount name, or filesystem diagnostic.
pub(crate) fn capacity_descriptor_unavailable() -> Failure {
    Failure::unavailable(
        "backup_capacity_descriptor",
        "recovery capacity descriptor is unavailable",
    )
}

/// `DeviceCapacityFromDescriptor` measures the writable filesystem
/// behind an already-authorized recovery-root directory descriptor.
pub fn device_capacity_from_descriptor<Fd: AsFd>(
    root_fd: Fd,
) -> Result<DeviceCapacitySnapshot, Failure> {
    let stat = fstat(&root_fd).map_err(|_| capacity_descriptor_unavailable())?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir() {
        return Err(capacity_descriptor_unavailable());
    }
    let filesystem = fstatfs(&root_fd).map_err(|_| capacity_descriptor_unavailable())?;
    if filesystem.f_bsize <= 0 {
        return Err(capacity_descriptor_unavailable());
    }
    let free_bytes = filesystem
        .f_bavail
        .checked_mul(
            u64::try_from(filesystem.f_bsize).map_err(|_| capacity_descriptor_unavailable())?,
        )
        .ok_or_else(capacity_descriptor_unavailable)?;
    let fsid = crate::sys::audited::statfs_fsid(&root_fd)
        .map_err(|_| capacity_descriptor_unavailable())?;
    Ok(DeviceCapacitySnapshot {
        device_id: opaque_filesystem_id(fsid),
        free_bytes,
    })
}

/// `opaqueFilesystemID` — `"fs-"` + the first 16 bytes of
/// `SHA-256(val[0] LE ‖ val[1] LE)`. The raw fsid never enters domain
/// evidence. `id` packs `val[0]` high, `val[1]` low
/// ([`crate::sys::audited::statfs_fsid`]).
fn opaque_filesystem_id(id: u64) -> String {
    let mut payload = [0u8; 8];
    payload[..4].copy_from_slice(&(id >> 32).to_le_bytes()[..4]);
    payload[4..].copy_from_slice(&(id as u32).to_le_bytes());
    let digest = Sha256::digest(payload);
    format!(
        "fs-{}",
        crate::backup::repository::hex_encode(&digest[..16])
    )
}
