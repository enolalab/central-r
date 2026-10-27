//! `repository_throughput_linux.go` — the bounded probe streams
//! measured on helper-selected recovery storage. A probe stream is
//! written, synchronized, fully reread, and checksummed beneath the
//! bound root; the temporary is never published and is removed before
//! success is returned.
//!
//! The Rust port has no `context.Context` surface (the domain ports
//! are synchronous); cancellation therefore maps to the caller never
//! handing the probe a stream it must abandon mid-copy — the bounded
//! loop itself cannot stall on a shrinking budget.

#![forbid(unsafe_code)]

use std::io::{Read, Seek, SeekFrom, Write};
use std::time::{Duration, Instant};

use central_backup::backup::capacity::{
    MAXIMUM_DUMP_PROBE_ARCHIVE_BYTES, MINIMUM_DUMP_PROBE_ARCHIVE_BYTES, OBJECT_PROBE_PAYLOAD_BYTES,
};
use central_foundation::failure::Failure;
use rustix::fs::{Mode, OFlags, fsync, unlinkat};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::repository::{Repository, hex_decode, secure_open_at};

/// `throughputProbeBufferBytes`.
const THROUGHPUT_PROBE_BUFFER_BYTES: usize = 256 * 1024;

/// The fixed object-fixture digest `MeasureObjectProbe` verifies
/// before the temporary is removed (`throughputProbeFixtureSHA256`).
const OBJECT_PROBE_FIXTURE_DIGEST_HEX: &str =
    "21134f507d39ce301dca4d0f44ca3d2f56b1b2d2fbca4171ec1751193ca0f276";

/// `ErrThroughputProbeStorage` — closed, locator-free probe-storage
/// refusal.
fn probe_storage_unavailable() -> Failure {
    Failure::unavailable(
        "throughput_probe_storage",
        "recovery throughput probe storage unavailable",
    )
}

impl Repository {
    /// `MeasureDumpProbe` writes the bounded `pg_dump` archive to
    /// recovery storage, synchronizes it, then fully rereads and
    /// checksums it.
    pub fn measure_dump_probe(
        &self,
        operation_id: Uuid,
        source: &mut dyn Read,
    ) -> Result<(u64, Duration), Failure> {
        self.measure_throughput_probe_stream(
            operation_id,
            "dump",
            source,
            MINIMUM_DUMP_PROBE_ARCHIVE_BYTES,
            MAXIMUM_DUMP_PROBE_ARCHIVE_BYTES,
            None,
        )
    }

    /// `MeasureObjectProbe` accounts for all three required
    /// object-path transfers: the fixed S3 GET source, then the
    /// repository write+sync and the full synchronized
    /// reread/checksum. The fixed fixture digest is verified before
    /// the temporary is removed.
    pub fn measure_object_probe(
        &self,
        operation_id: Uuid,
        source: &mut dyn Read,
    ) -> Result<(u64, Duration), Failure> {
        let want =
            hex_decode(OBJECT_PROBE_FIXTURE_DIGEST_HEX).map_err(|_| probe_storage_unavailable())?;
        let digest: [u8; 32] = want
            .as_slice()
            .try_into()
            .map_err(|_| probe_storage_unavailable())?;
        self.measure_throughput_probe_stream(
            operation_id,
            "object",
            source,
            OBJECT_PROBE_PAYLOAD_BYTES,
            OBJECT_PROBE_PAYLOAD_BYTES,
            Some(digest),
        )
    }

    /// `measureThroughputProbeStream`.
    fn measure_throughput_probe_stream(
        &self,
        operation_id: Uuid,
        stage: &str,
        source: &mut dyn Read,
        minimum_bytes: u64,
        maximum_bytes: u64,
        expected_digest: Option<[u8; 32]>,
    ) -> Result<(u64, Duration), Failure> {
        if self.validate_writable().is_err()
            || operation_id.is_nil()
            || operation_id.get_version_num() != 7
            || (stage != "dump" && stage != "object")
            || minimum_bytes == 0
            || maximum_bytes < minimum_bytes
        {
            return Err(probe_storage_unavailable());
        }
        let name = format!(".throughput-probe-{operation_id}-{stage}.tmp");
        let fd = secure_open_at(
            &self.root_fd,
            &name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| probe_storage_unavailable())?;
        let result = (|| {
            let mut file = std::fs::File::from(fd);
            let started = Instant::now();
            let (written, write_digest) =
                copy_bounded_probe_stream(&mut file, source, maximum_bytes)?;
            if written < minimum_bytes || written > maximum_bytes {
                return Err(probe_storage_unavailable());
            }
            file.sync_all().map_err(|_| probe_storage_unavailable())?;
            fsync(&self.root_fd).map_err(|_| probe_storage_unavailable())?;
            file.seek(SeekFrom::Start(0))
                .map_err(|_| probe_storage_unavailable())?;
            let mut sink = std::io::sink();
            let (reread, reread_digest) =
                copy_bounded_probe_stream(&mut sink, &mut file, maximum_bytes)?;
            if reread != written
                || reread_digest != write_digest
                || expected_digest.is_some_and(|want| reread_digest != want)
            {
                return Err(probe_storage_unavailable());
            }
            let elapsed = started.elapsed();
            if elapsed.is_zero() {
                return Err(probe_storage_unavailable());
            }
            file.sync_all().map_err(|_| probe_storage_unavailable())?;
            drop(file);
            Ok((written, elapsed))
        })();
        // Upstream's defer: the temporary is always unlinked and the
        // root fsynced before any result is returned — an interrupted
        // probe leaves no stray bytes behind.
        let unlink_ok = unlinkat(&self.root_fd, &name, rustix::fs::AtFlags::empty()).is_ok();
        let sync_ok = fsync(&self.root_fd).is_ok();
        match (result, unlink_ok && sync_ok) {
            (Ok(measured), true) => Ok(measured),
            (Ok(_), false) => Err(probe_storage_unavailable()),
            (Err(e), _) => Err(e),
        }
    }
}

/// `copyBoundedProbeStream` — one bounded, hashed copy. `Ok(0)` on a
/// `Read` is EOF (Rust's contract for the read side); the guard that
/// upstream reserves for a `0, nil` pair maps onto the
/// `total > maximum` overflow refusal instead.
fn copy_bounded_probe_stream(
    destination: &mut dyn Write,
    source: &mut dyn Read,
    maximum_bytes: u64,
) -> Result<(u64, [u8; 32]), Failure> {
    if maximum_bytes == 0 {
        return Err(probe_storage_unavailable());
    }
    let mut digest = Sha256::new();
    let mut buffer = vec![0u8; THROUGHPUT_PROBE_BUFFER_BYTES];
    let mut total: u64 = 0;
    loop {
        let count = match source.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => count,
            Err(_) => return Err(probe_storage_unavailable()),
        };
        if u64::try_from(count).unwrap_or(u64::MAX) > maximum_bytes - total {
            return Err(probe_storage_unavailable());
        }
        digest.update(&buffer[..count]);
        destination
            .write_all(&buffer[..count])
            .map_err(|_| probe_storage_unavailable())?;
        total += count as u64;
    }
    Ok((total, digest.finalize().into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    fn tempdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "central-r6-probe-{tag}-{}-{}",
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

    fn open_dir(path: &Path) -> std::os::fd::OwnedFd {
        rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap()
    }

    fn fixture(dir: &Path) -> Repository {
        let root = open_dir(dir);
        let binding =
            crate::backup_repository::initialize_repository_binding(&root, "probe-instance")
                .unwrap();
        Repository::from_descriptor(&root, &binding).unwrap()
    }

    #[test]
    fn dump_probe_measures_writes_and_leaves_no_temp() {
        let dir = tempdir("dump");
        let repository = fixture(&dir);
        let payload = vec![0xabu8; (MINIMUM_DUMP_PROBE_ARCHIVE_BYTES + 17) as usize];
        let mut source = std::io::Cursor::new(payload);
        let (bytes, elapsed) = repository
            .measure_dump_probe(Uuid::now_v7(), &mut source)
            .unwrap();
        assert_eq!(bytes, MINIMUM_DUMP_PROBE_ARCHIVE_BYTES + 17);
        assert!(!elapsed.is_zero());
        // No probe temporary survives success.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(".throughput-probe-")
            })
            .collect();
        assert!(leftovers.is_empty());
        repository.close().unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn probe_bounds_and_fixture_digest_are_enforced() {
        let dir = tempdir("bounds");
        let repository = fixture(&dir);
        // Undersized dump probe refuses.
        let mut short = std::io::Cursor::new(vec![0u8; 1024]);
        assert!(
            repository
                .measure_dump_probe(Uuid::now_v7(), &mut short)
                .is_err()
        );
        // The fixed fixture digest refuses arbitrary payloads.
        let mut wrong_object = std::io::Cursor::new(vec![0u8; OBJECT_PROBE_PAYLOAD_BYTES as usize]);
        assert!(
            repository
                .measure_object_probe(Uuid::now_v7(), &mut wrong_object)
                .is_err()
        );
        // A non-v7 or nil operation identity refuses.
        assert!(
            repository
                .measure_dump_probe(Uuid::nil(), &mut short)
                .is_err()
        );
        assert!(
            repository
                .measure_dump_probe(Uuid::new_v4(), &mut short)
                .is_err()
        );
        // A read-only repository cannot probe.
        repository.close().unwrap();
        let binding =
            crate::backup::repository::inspect_repository_descriptor(open_dir(&dir)).unwrap();
        let read_only = Repository::read_only_from_descriptor(open_dir(&dir), &binding).unwrap();
        let mut payload = std::io::Cursor::new(vec![0u8; 1024]);
        assert!(
            read_only
                .measure_dump_probe(Uuid::now_v7(), &mut payload)
                .is_err()
        );
        read_only.close().unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }
}
