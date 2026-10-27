//! `recovery_credential_linux.go` — the fixed local MinIO client built
//! from one broker-delivered `minio_backup_v1` (or `minio_import_v1`)
//! sealed memfd. The credential never becomes an environment variable
//! or a path: it is validated as a sealed, regular, size-bounded
//! descriptor, split `access:secret`, zeroed, and handed straight to
//! [`S3ObjectStore::new`].
//!
//! The resulting store crosses only narrow seams: the
//! [`ThroughputProbeObjectSource`] fixture and the
//! `ReadyArtifactObjectReader`-shaped `read` the kernel adapts for
//! postgres' ready-artifact source. No key, bucket, or endpoint ever
//! leaves through the returned errors.

#![forbid(unsafe_code)]

use std::fs::File;
use std::io::Read;
use std::os::fd::AsFd;
use std::sync::Arc;

use central_adapter_s3::{Config, S3ObjectStore};
use central_artifact::port::{ByteStream, ObjectInfo, ObjectRef, ObjectStore as _};
use central_backup::port::ReadClose;
use central_foundation::failure::Failure;
use rustix::fs::{FileType, SealFlags, fcntl_get_seals, fstat};
use tokio::runtime::Handle;

use super::throughput_probe::ThroughputProbeObjectSource;
use crate::sys::memfd::MAX_VALUE_BYTES;

/// `ErrBackupCredential` — closed, locator-free credential refusal.
fn backup_credential_unavailable() -> Failure {
    Failure::unavailable(
        "backup_objectstore_credential",
        "recovery object-store credential is unavailable",
    )
}

/// The fixed MinIO endpoint/bucket/region upstream pins — the helper
/// alone may reach them, so they are compile-time constants here, not
/// configuration.
const RECOVERY_OBJECT_ENDPOINT: &str = "127.0.0.1:59000";
const RECOVERY_OBJECT_BUCKET: &str = "central-artifacts-v1";
const RECOVERY_OBJECT_REGION: &str = "us-east-1";

/// `validateBackupCredentialDescriptor` — the four-seal set on a
/// regular file of bounded, nonzero size. Unlike the pgpass handoff
/// upstream checks neither uid nor tmpfs here, so neither does this
/// port; every later check still fails closed on `ErrBackupCredential`.
fn validate_backup_credential_descriptor<Fd: AsFd>(fd: Fd) -> Result<(), Failure> {
    let seals = fcntl_get_seals(&fd).map_err(|_| backup_credential_unavailable())?;
    let required = SealFlags::SEAL
        .union(SealFlags::SHRINK)
        .union(SealFlags::GROW)
        .union(SealFlags::WRITE);
    if !seals.contains(required) {
        return Err(backup_credential_unavailable());
    }
    let stat = fstat(&fd).map_err(|_| backup_credential_unavailable())?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_size <= 0
        || stat.st_size as u64 > MAX_VALUE_BYTES
    {
        return Err(backup_credential_unavailable());
    }
    Ok(())
}

/// `zeroBackupCredential` — the credential buffer's only dead state
/// is zeroed bytes. `zeroize` prevents dead-store elimination.
fn zero_backup_credential(value: &mut [u8]) {
    zeroize::Zeroize::zeroize(value);
}

/// The shared `New*FromSealedCredential` body: read the bounded sealed
/// bytes, split `access:secret` on the first `:` with no second one,
/// reject whitespace/NUL, zero the buffer, build the fixed Config.
fn recovery_store_from_sealed_credential(mut credential: File) -> Result<S3ObjectStore, Failure> {
    if validate_backup_credential_descriptor(&credential).is_err() {
        return Err(backup_credential_unavailable());
    }
    let mut value = Vec::new();
    let read = credential
        .by_ref()
        .take(MAX_VALUE_BYTES + 1)
        .read_to_end(&mut value);
    if read.is_err()
        || value.is_empty()
        || value.len() as u64 > MAX_VALUE_BYTES
        || value.contains(&0)
    {
        zero_backup_credential(&mut value);
        return Err(backup_credential_unavailable());
    }
    let Some(separator) = value.iter().position(|b| *b == b':') else {
        zero_backup_credential(&mut value);
        return Err(backup_credential_unavailable());
    };
    let valid = separator > 0
        && separator < value.len() - 1
        && !value[separator + 1..].contains(&b':')
        && !value
            .iter()
            .any(|b| matches!(*b, b'\r' | b'\n' | b'\t' | b' '));
    if !valid {
        zero_backup_credential(&mut value);
        return Err(backup_credential_unavailable());
    }
    // Upstream passes the raw bytes into Go strings verbatim; `String`
    // requires UTF-8, and a malformed secret must refuse rather than
    // become a different secret via lossy conversion.
    let Ok(access_key_id) = std::str::from_utf8(&value[..separator]) else {
        zero_backup_credential(&mut value);
        return Err(backup_credential_unavailable());
    };
    let Ok(secret_access_key) = std::str::from_utf8(&value[separator + 1..]) else {
        zero_backup_credential(&mut value);
        return Err(backup_credential_unavailable());
    };
    let access_key_id = access_key_id.to_owned();
    let secret_access_key = secret_access_key.to_owned();
    zero_backup_credential(&mut value);
    S3ObjectStore::new(Config {
        endpoint: RECOVERY_OBJECT_ENDPOINT.into(),
        access_key_id,
        secret_access_key,
        session_token: String::new(),
        bucket: RECOVERY_OBJECT_BUCKET.into(),
        region: RECOVERY_OBJECT_REGION.into(),
        use_tls: false,
    })
    .map_err(|_| backup_credential_unavailable())
}

/// `NewBackupReaderFromSealedCredential` — the store passed only
/// through `ReadyArtifactSource`'s read-only interface.
pub fn new_backup_reader_from_sealed_credential(
    credential: File,
) -> Result<S3ObjectStore, Failure> {
    recovery_store_from_sealed_credential(credential)
}

/// `NewImportWriterFromSealedCredential` — the store passed only to
/// the import data-plane runner, whose uploads go through
/// `restore_body_create_only`'s ready-only, create-only, exact-size
/// PUT.
pub fn new_import_writer_from_sealed_credential(
    credential: File,
) -> Result<S3ObjectStore, Failure> {
    recovery_store_from_sealed_credential(credential)
}

/// `ByteStreamReadClose` — adapts the capability's async
/// [`ByteStream`] to the sync [`ReadClose`] the probe/restore
/// composition consumes. `Handle::block_on` is used only because the
/// backup worker is a dedicated synchronous process — it must never
/// run on an async worker thread (a runtime-thread `block_on` would
/// panic; upstream's goroutine blocking model has no such footgun).
struct ByteStreamReadClose {
    runtime: Handle,
    stream: Box<dyn ByteStream>,
}

impl Read for ByteStreamReadClose {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.runtime.block_on(self.stream.read_chunk(buf)) {
            Ok(count) => Ok(count),
            Err(_) => Err(std::io::Error::other("object stream read failed")),
        }
    }
}

impl ReadClose for ByteStreamReadClose {
    fn close(mut self: Box<Self>) -> Result<(), Failure> {
        self.runtime.block_on(self.stream.close())
    }
}

/// `S3BackupObjectSource` — the recovery S3 seam behind a runtime
/// handle: fixture reads for the throughput probe and ready-object
/// reads for the postgres `ReadyArtifactObjectReader` bridge the
/// kernel composes.
pub struct S3BackupObjectSource {
    store: Arc<S3ObjectStore>,
    runtime: Handle,
}

impl S3BackupObjectSource {
    /// Requires the already-composed store plus the runtime that owns
    /// its transfers; both are mandatory (upstream's nil checks).
    pub fn new(store: Arc<S3ObjectStore>, runtime: Handle) -> Result<Self, Failure> {
        Ok(Self { store, runtime })
    }

    /// `ReadyArtifactObjectReader::read`'s exact shape — the kernel's
    /// one-line bridge impl delegates here so this seam stays the only
    /// place the sync/async conversion happens.
    pub fn read_ready_object(
        &self,
        reference: &ObjectRef,
    ) -> Result<(Box<dyn ReadClose>, ObjectInfo), Failure> {
        let (stream, info) = self.runtime.block_on(self.store.read(reference.clone()))?;
        Ok((
            Box::new(ByteStreamReadClose {
                runtime: self.runtime.clone(),
                stream,
            }),
            info,
        ))
    }
}

impl ThroughputProbeObjectSource for S3BackupObjectSource {
    /// `OpenBackupThroughputFixture` — the fixed system-object stream;
    /// the caller learns no key, only bytes.
    fn open_backup_throughput_fixture(&self) -> Result<Box<dyn ReadClose>, Failure> {
        let stream = self
            .runtime
            .block_on(self.store.open_backup_throughput_fixture())?;
        Ok(Box::new(ByteStreamReadClose {
            runtime: self.runtime.clone(),
            stream: Box::new(stream),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sealed_credential(value: &[u8]) -> File {
        crate::sys::memfd::create_sealed("minio_backup_v1", value)
            .map(File::from)
            .unwrap()
    }

    #[test]
    fn sealed_credential_builds_the_fixed_store() {
        let store = new_backup_reader_from_sealed_credential(sealed_credential(
            b"backup-reader-key:backup-reader-secret",
        ))
        .unwrap();
        // The store composition succeeded — no endpoint, bucket, or
        // secret detail escapes into the result type by construction.
        drop(store);
        // The import writer path builds identically.
        assert!(
            new_import_writer_from_sealed_credential(sealed_credential(
                b"import-writer-key:import-writer-secret",
            ))
            .is_ok()
        );
    }

    #[test]
    fn malformed_credentials_are_refused_and_zeroed() {
        // No colon separator.
        assert!(new_backup_reader_from_sealed_credential(sealed_credential(b"nocolon")).is_err());
        // Empty access key.
        assert!(new_backup_reader_from_sealed_credential(sealed_credential(b":secret")).is_err());
        // Empty secret.
        assert!(new_backup_reader_from_sealed_credential(sealed_credential(b"access:")).is_err());
        // A second colon inside the secret.
        assert!(new_backup_reader_from_sealed_credential(sealed_credential(b"a:b:c")).is_err());
        // Whitespace anywhere.
        for value in [
            &b"a ccess:secret"[..],
            &b"access:sec ret"[..],
            &b"access:\tsecret"[..],
        ] {
            assert!(new_backup_reader_from_sealed_credential(sealed_credential(value)).is_err());
        }
        // Embedded NUL.
        assert!(
            new_backup_reader_from_sealed_credential(sealed_credential(b"access:sec\0ret"))
                .is_err()
        );
    }

    #[test]
    fn unsealed_or_regular_files_are_refused() {
        // A plain tmpfs file with no seals is not a credential.
        let dir = std::env::temp_dir().join(format!(
            "central-r6-osb-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cred");
        std::fs::write(&path, b"access:secret").unwrap();
        let file = File::open(&path).unwrap();
        assert!(new_backup_reader_from_sealed_credential(file).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}
