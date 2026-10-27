//! `repository.go` — the trusted recovery-repository filesystem
//! adapter. The helper supplies its root descriptor in production;
//! this adapter accepts only a preselected root and never derives a
//! target from command input.
//!
//! `Repository` is a fixed recovery root. It intentionally does not
//! expose an arbitrary-path write method: callers can write only
//! canonical backup IDs and immutable inventory/manifest filenames.
//! Every open is descriptor-relative under the full `openat2`
//! containment set (`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
//! RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV`, plus `O_NOFOLLOW` on the
//! final component) — the same policy [`crate::sys::openat2`] fixes.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::atomic::{AtomicU64, Ordering};

use central_backup::backup::capacity::{
    DeviceCapacitySnapshot, RecoveryProfile, default_recovery_profile,
};
use central_backup::backup::inventory::{
    InventoryChunk, InventoryEntry, MAXIMUM_INVENTORY_CHUNK_ENTRIES, parse_inventory_chunk,
};
use central_backup::backup::manifest::{
    SealRootManifest, parse_seal_root_manifest, parse_seal_root_references,
};
use central_backup::backup::operation::{BackupOperation, DumpEvidence};
use central_backup::port::ERR_BACKUP_ARTIFACT_EVIDENCE_MISMATCH;
use central_backup::repository::{
    self, BackupBinding, BackupFileTreeEvidence, BackupRepositoryAttestation, BackupSealCompanion,
    BackupSealPublication, RepositoryBinding, RepositoryManifest, RepositoryManifestEntry,
    new_backup_binding, new_repository_manifest, parse_backup_binding, parse_backup_seal_companion,
    parse_repository_binding, parse_repository_manifest,
};
use central_foundation::failure::Failure;
use rustix::fs::{
    AtFlags, Dir, FileType, FlockOperation, Mode, OFlags, RenameFlags, StatxFlags, flock, fstat,
    fsync, mkdirat, openat2, renameat, renameat_with, statx, unlinkat,
};
use rustix::io::{Errno, fcntl_dupfd_cloexec};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// `maximumInventoryMetadataBytes`.
pub(crate) const MAXIMUM_INVENTORY_METADATA_BYTES: i64 = 4 * 1024 * 1024;
/// `maximumRepositoryBindingBytes`.
pub(crate) const MAXIMUM_REPOSITORY_BINDING_BYTES: i64 = 16 * 1024;
/// Stream copy quantum (upstream `createOnlyStreamAt`'s 256 KiB
/// buffer).
const STREAM_BUFFER_BYTES: usize = 256 * 1024;

/// `ErrInvalidRepository` — a single refusal shape; the adapter never
/// discloses which invariant failed.
pub(crate) fn invalid_repository() -> Failure {
    Failure::invalid("backup_repository", "invalid recovery repository")
}

/// `ErrAlreadyExists`.
fn already_exists() -> Failure {
    Failure::invalid(
        "backup_repository_entry_exists",
        "recovery repository entry already exists",
    )
}

/// `ErrRepositoryLimit`.
pub(crate) fn repository_limit() -> Failure {
    Failure::invalid(
        "backup_repository_limit",
        "recovery repository entry exceeds its limit",
    )
}

/// `ErrCorruptEvidence`.
pub(crate) fn corrupt_evidence() -> Failure {
    Failure::invalid(
        "backup_repository_corrupt",
        "recovery repository evidence is invalid",
    )
}

/// `ErrEvidenceMismatch` — upstream aliases
/// `port.ErrBackupArtifactEvidenceMismatch`.
pub(crate) fn evidence_mismatch() -> Failure {
    Failure::invalid(
        ERR_BACKUP_ARTIFACT_EVIDENCE_MISMATCH,
        "backup artifact evidence mismatch",
    )
}

/// `ErrRepositoryCensus` (repository_capacity.go).
pub(crate) fn repository_census_unavailable() -> Failure {
    Failure::unavailable(
        "backup_repository_census",
        "recovery repository census is unavailable",
    )
}

fn is_already_exists(e: &Failure) -> bool {
    e.code() == "backup_repository_entry_exists"
}

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

/// `Repository` — see the module header.
pub struct Repository {
    pub(crate) root_fd: OwnedFd,
    lock_fd: OwnedFd,
    pub(crate) binding: RepositoryBinding,
    read_only: bool,
}

/// `NewRepository` — verifies a pre-existing, non-symlink root. It
/// exists for controlled bootstrap and tests; production recovery
/// must use [`Repository::from_descriptor`] so the runtime never
/// chooses a root path.
pub fn new_repository(root: &std::path::Path) -> Result<Repository, Failure> {
    if !root.is_absolute() {
        return Err(invalid_repository());
    }
    let fd = openat2(
        rustix::fs::CWD,
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        crate::sys::openat2::RESOLVE_FLAGS,
    )
    .map_err(|_| invalid_repository())?;
    // This constructor is restricted to controlled bootstrap/tests.
    // The production descriptor constructor never repairs
    // permissions; it rejects drift. Normalize the freshly selected
    // fixture root before binding it.
    rustix::fs::fchmod(&fd, Mode::from_raw_mode(0o700)).map_err(|_| invalid_repository())?;
    let binding_id = Uuid::now_v7();
    let binding = crate::backup_repository::initialize_repository_binding(
        &fd,
        &format!("fixture-{binding_id}"),
    )
    .map_err(|_| invalid_repository())?;
    Repository::from_descriptor(fd, &binding)
}

impl Repository {
    /// `NewRepositoryFromDescriptor` binds a repository to the
    /// already-validated root directory descriptor supplied by the
    /// trusted helper. It duplicates the descriptor so callers may
    /// close their received `SCM_RIGHTS` descriptor as soon as the
    /// authority handoff completes.
    pub fn from_descriptor<Fd: AsFd>(
        root_fd: Fd,
        expected: &RepositoryBinding,
    ) -> Result<Self, Failure> {
        Self::from_descriptor_inner(root_fd.as_fd(), expected, false)
    }

    /// `NewReadOnlyRepositoryFromDescriptor` acquires the shared
    /// verification lock. It can verify and open sealed evidence but
    /// cannot create, replace, or bind any repository entry.
    pub fn read_only_from_descriptor<Fd: AsFd>(
        root_fd: Fd,
        expected: &RepositoryBinding,
    ) -> Result<Self, Failure> {
        Self::from_descriptor_inner(root_fd.as_fd(), expected, true)
    }

    fn from_descriptor_inner(
        root_fd: BorrowedFd<'_>,
        expected: &RepositoryBinding,
        read_only: bool,
    ) -> Result<Self, Failure> {
        if expected.verify().is_err() {
            return Err(invalid_repository());
        }
        let fd = duplicate_descriptor(root_fd)?;
        if validate_repository_root(&fd, expected).is_err() {
            return Err(invalid_repository());
        }
        let payload = read_file_at_owned(
            &fd,
            "binding.json",
            MAXIMUM_REPOSITORY_BINDING_BYTES,
            expected.owner_uid,
            expected.owner_gid,
        )
        .map_err(|_| invalid_repository())?;
        let stored = parse_repository_binding(&payload).map_err(|_| invalid_repository())?;
        if stored != *expected {
            return Err(invalid_repository());
        }
        let lock_fd = secure_open_at(&fd, "backup-repository.lock", OFlags::RDONLY, Mode::empty())
            .map_err(|_| invalid_repository())?;
        let lock_mode = if read_only {
            FlockOperation::NonBlockingLockShared
        } else {
            FlockOperation::NonBlockingLockExclusive
        };
        if validate_repository_file(&lock_fd, expected.owner_uid, expected.owner_gid, 0o600)
            .is_err()
            || flock(&lock_fd, lock_mode).is_err()
        {
            return Err(invalid_repository());
        }
        Ok(Self {
            root_fd: fd,
            lock_fd,
            binding: expected.clone(),
            read_only,
        })
    }

    /// `Close` releases the held lock; the owned descriptors close on
    /// drop. It is called during controlled command shutdown; it never
    /// removes or mutates recovery evidence.
    pub fn close(self) -> Result<(), Failure> {
        if flock(&self.lock_fd, FlockOperation::Unlock).is_err() {
            return Err(invalid_repository());
        }
        Ok(())
    }

    /// `BindingID` — safe composition evidence for constructing
    /// trusted accepted facts. It reveals no path, descriptor number,
    /// mount location, or credential.
    #[must_use]
    pub fn binding_id(&self) -> Uuid {
        self.binding.binding_id
    }

    /// `Binding` — the complete locator-free repository identity for
    /// helper composition and descriptor substitution checks.
    #[must_use]
    pub fn binding(&self) -> RepositoryBinding {
        self.binding.clone()
    }

    /// `BindBackup` creates the immutable per-backup binding before
    /// any dump body or inventory file can be written. An exact repeat
    /// verifies the existing bytes; any substitution fails closed.
    pub fn bind_backup(&self, operation: &BackupOperation) -> Result<(), Failure> {
        self.validate_writable()?;
        let binding = new_backup_binding(operation).map_err(|_| invalid_repository())?;
        if binding.repository_binding_id != self.binding.binding_id {
            return Err(invalid_repository());
        }
        let payload = binding.canonical_json().map_err(|_| invalid_repository())?;
        let directory = self.backup_directory_unchecked(operation.backup_id)?;
        match create_only_at(&directory, "binding.json", &payload) {
            Ok(()) => Ok(()),
            Err(e) if !is_already_exists(&e) => Err(e),
            _ => {
                let existing = read_file_at_owned(
                    &directory,
                    "binding.json",
                    MAXIMUM_REPOSITORY_BINDING_BYTES,
                    self.binding.owner_uid,
                    self.binding.owner_gid,
                )
                .map_err(|_| invalid_repository())?;
                if existing != payload {
                    return Err(invalid_repository());
                }
                Ok(())
            }
        }
    }

    /// `WriteChunk` writes one immutable canonical inventory page. A
    /// pre-existing filename is never overwritten, including after a
    /// crash; callers must verify it or terminate the operation with
    /// preserved evidence.
    pub fn write_chunk(&self, backup_id: Uuid, chunk: &InventoryChunk) -> Result<(), Failure> {
        if backup_id.is_nil() {
            return Err(invalid_repository());
        }
        chunk.verify()?;
        self.validate_writable()?;
        let payload = chunk.canonical_json()?;
        let directory = self.backup_directory(backup_id, &["inventory"])?;
        create_only_at(&directory, &ordinal_file_name(chunk.ordinal), &payload)
    }

    /// `WriteManifest` writes the root manifest only after every
    /// referenced chunk has been verified. Its create-only write is
    /// the final local precondition before a separate broker seal
    /// commit.
    pub fn write_manifest(
        &self,
        manifest: &SealRootManifest,
    ) -> Result<BackupFileTreeEvidence, Failure> {
        self.validate_writable()?;
        manifest.verify()?;
        let payload = manifest.canonical_json()?;
        let directory = self.backup_directory(manifest.backup_id, &[])?;
        let binding =
            read_backup_binding_at(&directory, self.binding.owner_uid, self.binding.owner_gid)
                .map_err(|_| invalid_repository())?;
        if binding.repository_binding_id != manifest.repository_binding_id
            || binding.backup_id != manifest.backup_id
            || binding.operation_id != manifest.operation_id
            || binding.target_fingerprint != manifest.accepted_facts.target_fingerprint
            || binding.config_fingerprint != manifest.accepted_facts.config_fingerprint
            || binding.payload_epoch_id != manifest.accepted_facts.payload_epoch_id
            || binding.accepted_at
                != manifest
                    .accepted_facts
                    .database_time
                    .to_offset(time::UtcOffset::UTC)
        {
            return Err(invalid_repository());
        }
        create_only_at(&directory, "root-manifest.json", &payload)?;
        let verified = verify_unsealed_backup_at(
            &directory,
            manifest.backup_id,
            &default_recovery_profile(),
            self.binding.owner_uid,
            self.binding.owner_gid,
        )
        .map_err(|_| corrupt_evidence())?;
        if verified.manifest.digest != manifest.digest {
            return Err(corrupt_evidence());
        }
        Ok(verified.file_tree)
    }

    /// `WriteDump` streams `pg_dump` output into an immutable
    /// repository entry. The caller supplies the supported-profile
    /// maximum; a too-large or interrupted stream leaves only unsealed
    /// evidence and cannot be referenced by a manifest.
    pub fn write_dump(
        &self,
        backup_id: Uuid,
        source: &mut dyn Read,
        maximum_bytes: i64,
    ) -> Result<DumpEvidence, Failure> {
        if backup_id.is_nil() || maximum_bytes <= 0 {
            return Err(invalid_repository());
        }
        self.validate_writable()?;
        let directory = self.backup_directory(backup_id, &["database"])?;
        let (size, digest) =
            create_only_stream_at(&directory, "central.dump", source, maximum_bytes, -1)?;
        let evidence = DumpEvidence { size, digest };
        evidence.validate()?;
        Ok(evidence)
    }

    /// `WriteArtifactBody` copies one body to its opaque checksum-based
    /// recovery filename. It verifies the stream's exact expected
    /// length and SHA-256 before returning success; object keys and
    /// live storage paths never enter the root.
    pub fn write_artifact_body(
        &self,
        backup_id: Uuid,
        entry: &InventoryEntry,
        source: &mut dyn Read,
    ) -> Result<(), Failure> {
        if backup_id.is_nil() {
            return Err(invalid_repository());
        }
        entry.validate()?;
        self.validate_writable()?;
        let encoded = hex_encode(&entry.checksum);
        let directory = self.backup_directory(backup_id, &["bodies", "sha256", &encoded[..2]])?;
        let (size, digest) = create_verified_body_at(
            &directory,
            &encoded[2..],
            source,
            entry.size,
            entry.checksum,
        )?;
        if size != entry.size || digest != entry.checksum {
            return Err(evidence_mismatch());
        }
        Ok(())
    }

    /// `WriteSealCompanion` publishes the exact broker result and only
    /// then appends the backup to the root sealed-backup index. An
    /// exact retry completes an interrupted publication; no caller can
    /// replace either immutable seal.
    pub fn write_seal_companion(
        &self,
        companion: &BackupSealCompanion,
    ) -> Result<BackupSealPublication, Failure> {
        if companion.verify().is_err() || self.validate_writable().is_err() {
            return Err(invalid_repository());
        }
        let directory = self.open_backup_directory(companion.backup_id)?;
        let verified = verify_unsealed_backup_at(
            &directory,
            companion.backup_id,
            &default_recovery_profile(),
            self.binding.owner_uid,
            self.binding.owner_gid,
        )?;
        if companion.operation_id != verified.manifest.operation_id
            || companion.repository_binding_id != self.binding.binding_id
            || companion.repository_binding_id != verified.manifest.repository_binding_id
            || companion.target_fingerprint != verified.manifest.accepted_facts.target_fingerprint
            || companion.config_fingerprint != verified.manifest.accepted_facts.config_fingerprint
            || companion.payload_epoch_id != verified.manifest.accepted_facts.payload_epoch_id
            || companion.root_manifest_digest != verified.manifest.digest
            || companion.file_tree_digest != verified.file_tree.digest
            || companion.sealed_at < verified.manifest.accepted_facts.database_time
        {
            return Err(evidence_mismatch());
        }
        let payload = companion
            .canonical_json()
            .map_err(|_| invalid_repository())?;
        if let Err(e) = create_only_at(&directory, "root-manifest.auth.json", &payload) {
            if !is_already_exists(&e) {
                return Err(e);
            }
            let existing = read_file_at_owned(
                &directory,
                "root-manifest.auth.json",
                MAXIMUM_REPOSITORY_BINDING_BYTES,
                self.binding.owner_uid,
                self.binding.owner_gid,
            )
            .map_err(|_| evidence_mismatch())?;
            if existing != payload {
                return Err(evidence_mismatch());
            }
        }

        let index = self
            .read_root_manifest()
            .map_err(|_| invalid_repository())?;
        let entry = RepositoryManifestEntry {
            backup_id: companion.backup_id,
            accepted_at: verified.manifest.accepted_facts.database_time,
            root_manifest_digest: verified.manifest.digest,
            seal_companion_digest: companion.digest,
            file_tree_digest: verified.file_tree.digest,
        };
        for existing in &index.sealed_backups {
            if existing.backup_id == companion.backup_id {
                if *existing != entry {
                    return Err(evidence_mismatch());
                }
                return Ok(seal_publication(companion, &index));
            }
        }
        if index.sealed_backups.len() >= repository::MAXIMUM_SEALED_BACKUPS
            || index.revision == u64::MAX
        {
            return Err(repository_limit());
        }
        let mut entries = index.sealed_backups.clone();
        entries.push(entry);
        let next = new_repository_manifest(index.root_binding_id, index.revision + 1, entries)
            .map_err(|_| invalid_repository())?;
        let next_payload = next.canonical_json().map_err(|_| invalid_repository())?;
        write_atomic_replace_at(&self.root_fd, "repository-manifest.json", &next_payload)?;
        let stored = read_file_at_owned(
            &self.root_fd,
            "repository-manifest.json",
            MAXIMUM_INVENTORY_METADATA_BYTES,
            self.binding.owner_uid,
            self.binding.owner_gid,
        )
        .map_err(|_| invalid_repository())?;
        if stored != next_payload {
            return Err(invalid_repository());
        }
        Ok(seal_publication(companion, &next))
    }

    /// `VerifyBackup` walks exactly the files addressed by a canonical
    /// root manifest through descriptor-relative, no-follow reads. It
    /// never lists a caller path or repairs/deletes evidence. Any
    /// mismatch remains a fail-closed C03 result.
    pub fn verify_backup(
        &self,
        backup_id: Uuid,
        profile: &RecoveryProfile,
    ) -> Result<VerificationEvidence, Failure> {
        if backup_id.is_nil() || profile.validate().is_err() {
            return Err(invalid_repository());
        }
        let directory = self.open_backup_directory(backup_id)?;
        let verified = verify_unsealed_backup_at(
            &directory,
            backup_id,
            profile,
            self.binding.owner_uid,
            self.binding.owner_gid,
        )?;
        let companion_payload = read_file_at_owned(
            &directory,
            "root-manifest.auth.json",
            MAXIMUM_REPOSITORY_BINDING_BYTES,
            self.binding.owner_uid,
            self.binding.owner_gid,
        )
        .map_err(|_| corrupt_evidence())?;
        let companion =
            parse_backup_seal_companion(&companion_payload).map_err(|_| corrupt_evidence())?;
        if companion.backup_id != backup_id
            || companion.operation_id != verified.manifest.operation_id
            || companion.repository_binding_id != self.binding.binding_id
            || companion.repository_binding_id != verified.manifest.repository_binding_id
            || companion.target_fingerprint != verified.manifest.accepted_facts.target_fingerprint
            || companion.config_fingerprint != verified.manifest.accepted_facts.config_fingerprint
            || companion.payload_epoch_id != verified.manifest.accepted_facts.payload_epoch_id
            || companion.root_manifest_digest != verified.manifest.digest
            || companion.file_tree_digest != verified.file_tree.digest
            || companion.sealed_at < verified.manifest.accepted_facts.database_time
        {
            return Err(corrupt_evidence());
        }
        let index = self.read_root_manifest().map_err(|_| corrupt_evidence())?;
        let want_entry = RepositoryManifestEntry {
            backup_id,
            accepted_at: verified.manifest.accepted_facts.database_time,
            root_manifest_digest: verified.manifest.digest,
            seal_companion_digest: companion.digest,
            file_tree_digest: verified.file_tree.digest,
        };
        let mut found = false;
        for entry in &index.sealed_backups {
            if entry.backup_id == backup_id {
                if found || *entry != want_entry {
                    return Err(corrupt_evidence());
                }
                found = true;
            }
        }
        if !found {
            return Err(corrupt_evidence());
        }
        Ok(VerificationEvidence {
            operation_id: verified.manifest.operation_id,
            backup_id,
            repository_binding_id: self.binding.binding_id,
            dump: verified.dump,
            manifest_digest: verified.manifest.digest,
            seal_companion_digest: companion.digest,
            file_tree_digest: verified.file_tree.digest,
            repository_manifest_digest: index.digest,
            repository_revision: index.revision,
            artifact_count: verified.artifact_count,
            object_bytes: verified.object_bytes,
            manifest: verified.manifest,
        })
    }

    /// `AttestSealedPublication` is called only by the helper after it
    /// has reaped the backup worker and every descendant. The helper
    /// opens its independently retained descriptor with the exclusive
    /// repository lock, then this method recomputes every referenced
    /// digest and the exact root index. Worker-supplied publication
    /// claims are never accepted at this boundary.
    pub fn attest_sealed_publication(
        &self,
        launch_evidence_id: Uuid,
        operation_id: Uuid,
        backup_id: Uuid,
        profile: &RecoveryProfile,
        attested_at: time::OffsetDateTime,
    ) -> Result<BackupRepositoryAttestation, Failure> {
        if self.read_only
            || launch_evidence_id.is_nil()
            || operation_id.is_nil()
            || backup_id.is_nil()
            || attested_at == time::OffsetDateTime::UNIX_EPOCH
        {
            return Err(invalid_repository());
        }
        let evidence = self.verify_backup(backup_id, profile)?;
        if evidence.operation_id != operation_id
            || evidence.repository_binding_id != self.binding.binding_id
        {
            return Err(corrupt_evidence());
        }
        let publication = BackupSealPublication {
            operation_id: evidence.operation_id,
            backup_id: evidence.backup_id,
            repository_binding_id: evidence.repository_binding_id,
            root_manifest_digest: evidence.manifest_digest,
            seal_companion_digest: evidence.seal_companion_digest,
            file_tree_digest: evidence.file_tree_digest,
            repository_manifest_digest: evidence.repository_manifest_digest,
            repository_revision: evidence.repository_revision,
        };
        repository::new_backup_repository_attestation(launch_evidence_id, &publication, attested_at)
            .map_err(|_| corrupt_evidence())
    }

    /// `OpenVerifiedDump` opens exactly the immutable dump belonging to
    /// `backup_id`. It re-hashes the opened descriptor before returning
    /// it, rather than trusting a path checked earlier by another
    /// restore step. The returned stream is positioned at byte zero
    /// and carries no repository path to its caller.
    pub fn open_verified_dump(
        &self,
        backup_id: Uuid,
        profile: &RecoveryProfile,
    ) -> Result<File, Failure> {
        if backup_id.is_nil() || profile.validate().is_err() {
            return Err(invalid_repository());
        }
        let evidence = self.verify_backup(backup_id, profile)?;
        let directory = self.open_backup_directory(backup_id)?;
        let database_dir = open_existing_directory_at(
            &directory,
            "database",
            self.binding.owner_uid,
            self.binding.owner_gid,
        )?;
        let fd = secure_open_at(&database_dir, "central.dump", OFlags::RDONLY, Mode::empty())
            .map_err(|_| corrupt_evidence())?;
        let mut file = File::from(fd);
        check_verified_dump(&mut file, &self.binding, profile, &evidence)?;
        file.seek(SeekFrom::Start(0))
            .map_err(|_| corrupt_evidence())?;
        Ok(file)
    }

    /// `ReadInventoryChunk` — the `RecoveryRepositoryStore` read-back
    /// leg; backup-scoped like every other access.
    pub fn read_inventory_chunk(
        &self,
        backup_id: Uuid,
        ordinal: u32,
    ) -> Result<InventoryChunk, Failure> {
        let directory = self.open_backup_directory(backup_id)?;
        let inventory_dir = open_existing_directory_at(
            &directory,
            "inventory",
            self.binding.owner_uid,
            self.binding.owner_gid,
        )?;
        let payload = read_file_at_owned(
            &inventory_dir,
            &ordinal_file_name(ordinal),
            MAXIMUM_INVENTORY_METADATA_BYTES,
            self.binding.owner_uid,
            self.binding.owner_gid,
        )?;
        let chunk = parse_inventory_chunk(&payload).map_err(|_| corrupt_evidence())?;
        if chunk.ordinal != ordinal {
            return Err(corrupt_evidence());
        }
        Ok(chunk)
    }

    /// `ReadSealRoot` — the canonical seal-root bytes; backup-scoped.
    pub fn read_seal_root(&self, backup_id: Uuid) -> Result<Vec<u8>, Failure> {
        let directory = self.open_backup_directory(backup_id)?;
        read_file_at_owned(
            &directory,
            "root-manifest.json",
            MAXIMUM_INVENTORY_METADATA_BYTES,
            self.binding.owner_uid,
            self.binding.owner_gid,
        )
    }

    pub(crate) fn read_root_manifest(&self) -> Result<RepositoryManifest, Failure> {
        let payload = read_file_at_owned(
            &self.root_fd,
            "repository-manifest.json",
            MAXIMUM_INVENTORY_METADATA_BYTES,
            self.binding.owner_uid,
            self.binding.owner_gid,
        )?;
        let index = parse_repository_manifest(&payload).map_err(|_| corrupt_evidence())?;
        if index.root_binding_id != self.binding.binding_id {
            return Err(corrupt_evidence());
        }
        Ok(index)
    }

    pub(crate) fn validate(&self) -> Result<(), Failure> {
        if self.binding.verify().is_err()
            || validate_repository_root(&self.root_fd, &self.binding).is_err()
            || validate_repository_file(
                &self.lock_fd,
                self.binding.owner_uid,
                self.binding.owner_gid,
                0o600,
            )
            .is_err()
        {
            return Err(invalid_repository());
        }
        let payload = read_file_at_owned(
            &self.root_fd,
            "binding.json",
            MAXIMUM_REPOSITORY_BINDING_BYTES,
            self.binding.owner_uid,
            self.binding.owner_gid,
        )
        .map_err(|_| invalid_repository())?;
        let binding = parse_repository_binding(&payload).map_err(|_| invalid_repository())?;
        if binding != self.binding {
            return Err(invalid_repository());
        }
        // The held lock must name the same inode
        // `backup-repository.lock` resolves to today.
        let held = fstat(&self.lock_fd).map_err(|_| invalid_repository())?;
        let named_fd = secure_open_at(
            &self.root_fd,
            "backup-repository.lock",
            OFlags::RDONLY,
            Mode::empty(),
        )
        .map_err(|_| invalid_repository())?;
        let named = fstat(&named_fd).map_err(|_| invalid_repository())?;
        if held.st_dev != named.st_dev || held.st_ino != named.st_ino {
            return Err(invalid_repository());
        }
        Ok(())
    }

    pub(crate) fn validate_writable(&self) -> Result<(), Failure> {
        if self.read_only {
            return Err(invalid_repository());
        }
        self.validate()
    }

    fn backup_directory_unchecked(&self, backup_id: Uuid) -> Result<OwnedFd, Failure> {
        if backup_id.is_nil() {
            return Err(invalid_repository());
        }
        let mut fd = duplicate_descriptor(&self.root_fd)?;
        for name in ["backups", &backup_id.to_string()] {
            fd = ensure_directory_at(&fd, name)?;
        }
        Ok(fd)
    }

    fn backup_directory(&self, backup_id: Uuid, parts: &[&str]) -> Result<OwnedFd, Failure> {
        self.validate()?;
        let mut fd = self.backup_directory_unchecked(backup_id)?;
        let binding = read_backup_binding_at(&fd, self.binding.owner_uid, self.binding.owner_gid)
            .map_err(|_| invalid_repository())?;
        if binding.backup_id != backup_id
            || binding.repository_binding_id != self.binding.binding_id
        {
            return Err(invalid_repository());
        }
        for name in parts {
            fd = ensure_directory_at(&fd, name)?;
        }
        Ok(fd)
    }

    pub(crate) fn open_backup_directory(&self, backup_id: Uuid) -> Result<OwnedFd, Failure> {
        if backup_id.is_nil() || self.validate().is_err() {
            return Err(invalid_repository());
        }
        let mut fd = duplicate_descriptor(&self.root_fd)?;
        for name in ["backups", &backup_id.to_string()] {
            fd = open_existing_directory_at(
                &fd,
                name,
                self.binding.owner_uid,
                self.binding.owner_gid,
            )?;
        }
        let binding = read_backup_binding_at(&fd, self.binding.owner_uid, self.binding.owner_gid)?;
        if binding.backup_id != backup_id
            || binding.repository_binding_id != self.binding.binding_id
        {
            return Err(corrupt_evidence());
        }
        Ok(fd)
    }
}

// ---------------------------------------------------------------------------
// InspectRepositoryDescriptor
// ---------------------------------------------------------------------------

/// `InspectRepositoryDescriptor` derives the immutable binding from an
/// already selected helper-owned descriptor. It accepts no pathname
/// and verifies the binding file's owner against both the root inode
/// and its canonical payload before briefly acquiring the shared
/// repository lock.
pub fn inspect_repository_descriptor<Fd: AsFd>(root_fd: Fd) -> Result<RepositoryBinding, Failure> {
    let binding_fd = secure_open_at(&root_fd, "binding.json", OFlags::RDONLY, Mode::empty())
        .map_err(|_| invalid_repository())?;
    let stat = fstat(&binding_fd).map_err(|_| invalid_repository())?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_mode & 0o777 != 0o600
        || stat.st_nlink != 1
        || stat.st_size < 0
        || stat.st_size > MAXIMUM_REPOSITORY_BINDING_BYTES
    {
        return Err(invalid_repository());
    }
    drop(binding_fd);
    let payload = read_file_at_owned(
        &root_fd,
        "binding.json",
        MAXIMUM_REPOSITORY_BINDING_BYTES,
        stat.st_uid,
        stat.st_gid,
    )
    .map_err(|_| invalid_repository())?;
    let binding = parse_repository_binding(&payload).map_err(|_| invalid_repository())?;
    if binding.owner_uid != stat.st_uid
        || binding.owner_gid != stat.st_gid
        || validate_repository_root(&root_fd, &binding).is_err()
    {
        return Err(invalid_repository());
    }
    let repository = Repository::read_only_from_descriptor(&root_fd, &binding)
        .map_err(|_| invalid_repository())?;
    repository.close().map_err(|_| invalid_repository())?;
    Ok(binding)
}

// ---------------------------------------------------------------------------
// Verification evidence and the unsealed walk
// ---------------------------------------------------------------------------

/// `VerificationEvidence` is the safe result of physical repository
/// verification. A broker seal and target/PAM checks remain separate
/// C03 boundaries; this value proves only that immutable local
/// evidence is internally consistent and complete.
pub struct VerificationEvidence {
    /// Bound operation.
    pub operation_id: Uuid,
    /// Bound backup.
    pub backup_id: Uuid,
    /// Repository binding.
    pub repository_binding_id: Uuid,
    /// Dump evidence.
    pub dump: DumpEvidence,
    /// Seal-root manifest digest.
    pub manifest_digest: [u8; 32],
    /// Seal companion digest.
    pub seal_companion_digest: [u8; 32],
    /// Immutable file-tree digest.
    pub file_tree_digest: [u8; 32],
    /// Repository manifest digest.
    pub repository_manifest_digest: [u8; 32],
    /// Repository manifest revision.
    pub repository_revision: u64,
    /// Sealed artifact count.
    pub artifact_count: u64,
    /// Sealed object bytes.
    pub object_bytes: u64,
    /// The exact sealed root this walk revalidated. It is carried so
    /// a consumer can re-derive every field above from broker-sealed
    /// content instead of repeating the walk.
    pub manifest: SealRootManifest,
}

/// `repositoryFileTreeEntryWire`.
#[derive(Serialize)]
struct FileTreeEntryWire {
    logical_reference: String,
    size: i64,
    digest_sha256: String,
}

/// `repositoryFileTreeWire` — `central.backup-file-tree/v1`.
#[derive(Serialize)]
struct FileTreeWire {
    schema_version: &'static str,
    backup_id: String,
    files: Vec<FileTreeEntryWire>,
}

pub(crate) struct UnsealedBackupEvidence {
    pub(crate) manifest: SealRootManifest,
    pub(crate) dump: DumpEvidence,
    pub(crate) file_tree: BackupFileTreeEvidence,
    pub(crate) artifact_count: u64,
    pub(crate) object_bytes: u64,
}

fn seal_publication(
    companion: &BackupSealCompanion,
    manifest: &RepositoryManifest,
) -> BackupSealPublication {
    BackupSealPublication {
        operation_id: companion.operation_id,
        backup_id: companion.backup_id,
        repository_binding_id: companion.repository_binding_id,
        root_manifest_digest: companion.root_manifest_digest,
        seal_companion_digest: companion.digest,
        file_tree_digest: companion.file_tree_digest,
        repository_manifest_digest: manifest.digest,
        repository_revision: manifest.revision,
    }
}

/// `mediaVerificationWalks` — one counter, delta reads only, so a
/// composed path's walk count is observable. Process-wide and
/// monotonic; read deltas, never absolutes.
static MEDIA_VERIFICATION_WALKS: AtomicU64 = AtomicU64::new(0);

/// `MediaVerificationWalks` reports how many full media walks this
/// process has performed. It is a counter, not a capability: it
/// discloses no identity, path, or digest. Exported deliberately with
/// no production caller so admission tests can pin the walk count.
#[must_use]
pub fn media_verification_walks() -> u64 {
    MEDIA_VERIFICATION_WALKS.load(Ordering::Relaxed)
}

pub(crate) fn verify_unsealed_backup_at(
    directory: &OwnedFd,
    backup_id: Uuid,
    profile: &RecoveryProfile,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<UnsealedBackupEvidence, Failure> {
    MEDIA_VERIFICATION_WALKS.fetch_add(1, Ordering::Relaxed);
    let root_payload = read_file_at_owned(
        directory,
        "root-manifest.json",
        MAXIMUM_INVENTORY_METADATA_BYTES,
        owner_uid,
        owner_gid,
    )?;
    let references = parse_seal_root_references(&root_payload).map_err(|_| corrupt_evidence())?;
    if references.backup_id != backup_id {
        return Err(corrupt_evidence());
    }
    let maximum_chunks = profile
        .max_record_count
        .div_ceil(MAXIMUM_INVENTORY_CHUNK_ENTRIES as u64);
    if references.chunks.len() as u64 > maximum_chunks {
        return Err(repository_limit());
    }
    let binding_payload = read_file_at_owned(
        directory,
        "binding.json",
        MAXIMUM_REPOSITORY_BINDING_BYTES,
        owner_uid,
        owner_gid,
    )
    .map_err(|_| corrupt_evidence())?;
    let binding = parse_backup_binding(&binding_payload).map_err(|_| corrupt_evidence())?;
    if binding.backup_id != backup_id
        || binding.operation_id != references.operation_id
        || binding.repository_binding_id != references.repository_binding_id
        || binding.target_fingerprint != references.accepted_facts.target_fingerprint
        || binding.config_fingerprint != references.accepted_facts.config_fingerprint
        || binding.payload_epoch_id != references.accepted_facts.payload_epoch_id
        || binding.accepted_at
            != references
                .accepted_facts
                .database_time
                .to_offset(time::UtcOffset::UTC)
    {
        return Err(corrupt_evidence());
    }
    let mut files = vec![FileTreeEntryWire {
        logical_reference: "binding.json".to_owned(),
        size: binding_payload.len() as i64,
        digest_sha256: hex_encode(&Sha256::digest(&binding_payload)),
    }];
    let mut chunks: Vec<InventoryChunk> = Vec::with_capacity(references.chunks.len());
    let mut artifact_count: u64 = 0;
    let mut object_bytes: u64 = 0;
    let mut body_sizes: BTreeMap<[u8; 32], i64> = BTreeMap::new();
    if !references.chunks.is_empty() {
        let inventory_dir =
            open_existing_directory_at(directory, "inventory", owner_uid, owner_gid)?;
        for reference in &references.chunks {
            let payload = read_file_at_owned(
                &inventory_dir,
                &ordinal_file_name(reference.ordinal),
                MAXIMUM_INVENTORY_METADATA_BYTES,
                owner_uid,
                owner_gid,
            )?;
            let chunk = parse_inventory_chunk(&payload).map_err(|_| corrupt_evidence())?;
            if chunk.ordinal != reference.ordinal
                || chunk.digest != reference.digest
                || chunk.entries.len() != reference.entry_count
            {
                return Err(corrupt_evidence());
            }
            files.push(FileTreeEntryWire {
                logical_reference: format!("inventory/{}", ordinal_file_name(chunk.ordinal)),
                size: payload.len() as i64,
                digest_sha256: hex_encode(&Sha256::digest(&payload)),
            });
            for entry in &chunk.entries {
                if entry.size < 0
                    || entry.size as u64 > profile.max_object_bytes.saturating_sub(object_bytes)
                    || artifact_count >= profile.max_record_count
                {
                    return Err(repository_limit());
                }
                if let Some(previous) = body_sizes.get(&entry.checksum)
                    && *previous != entry.size
                {
                    return Err(corrupt_evidence());
                }
                body_sizes.insert(entry.checksum, entry.size);
                artifact_count += 1;
                object_bytes += entry.size as u64;
            }
            chunks.push(chunk);
        }
        let expected: Vec<String> = references
            .chunks
            .iter()
            .map(|r| ordinal_file_name(r.ordinal))
            .collect();
        require_exact_directory_entries(&inventory_dir, &expected, &BTreeSet::new())
            .map_err(|_| corrupt_evidence())?;
    }
    let manifest =
        parse_seal_root_manifest(&root_payload, &chunks).map_err(|_| corrupt_evidence())?;
    if manifest.backup_id != backup_id {
        return Err(corrupt_evidence());
    }
    let database_dir = open_existing_directory_at(directory, "database", owner_uid, owner_gid)?;
    let (dump_size, dump_digest) = hash_file_at_owned(
        &database_dir,
        "central.dump",
        profile.max_database_bytes as i64,
        owner_uid,
        owner_gid,
    )
    .map_err(|_| corrupt_evidence())?;
    let dump_evidence = DumpEvidence {
        size: dump_size,
        digest: dump_digest,
    };
    if dump_evidence.validate().is_err() || dump_evidence != manifest.dump {
        return Err(corrupt_evidence());
    }
    require_exact_directory_entries(
        &database_dir,
        &["central.dump".to_owned()],
        &BTreeSet::new(),
    )
    .map_err(|_| corrupt_evidence())?;
    files.push(FileTreeEntryWire {
        logical_reference: "database/central.dump".to_owned(),
        size: dump_size,
        digest_sha256: hex_encode(&dump_digest),
    });
    if !body_sizes.is_empty() {
        let bodies_dir = open_existing_directory_at(directory, "bodies", owner_uid, owner_gid)?;
        let sha_dir = open_existing_directory_at(&bodies_dir, "sha256", owner_uid, owner_gid)?;
        let encoded_bodies: Vec<String> =
            body_sizes.keys().map(|digest| hex_encode(digest)).collect();
        let mut expected_fanout_files: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for encoded in &encoded_bodies {
            expected_fanout_files
                .entry(encoded[..2].to_owned())
                .or_default()
                .push(encoded[2..].to_owned());
        }
        for encoded in &encoded_bodies {
            let digest_bytes = hex_decode(encoded).map_err(|_| corrupt_evidence())?;
            let mut expected_digest = [0u8; 32];
            if digest_bytes.len() != 32 {
                return Err(corrupt_evidence());
            }
            expected_digest.copy_from_slice(&digest_bytes);
            let expected_size = *body_sizes
                .get(&expected_digest)
                .ok_or_else(corrupt_evidence)?;
            let fanout_dir =
                open_existing_directory_at(&sha_dir, &encoded[..2], owner_uid, owner_gid)?;
            let (size, digest) = hash_file_at_owned(
                &fanout_dir,
                &encoded[2..],
                expected_size,
                owner_uid,
                owner_gid,
            )
            .map_err(|_| corrupt_evidence())?;
            if size != expected_size || digest != expected_digest {
                return Err(corrupt_evidence());
            }
            let expected_names = expected_fanout_files
                .get(&encoded[..2])
                .ok_or_else(corrupt_evidence)?;
            require_exact_directory_entries(&fanout_dir, expected_names, &BTreeSet::new())
                .map_err(|_| corrupt_evidence())?;
            files.push(FileTreeEntryWire {
                logical_reference: format!("bodies/sha256/{encoded}"),
                size,
                digest_sha256: encoded.clone(),
            });
        }
        let expected_fanouts: Vec<String> = expected_fanout_files.keys().cloned().collect();
        require_exact_directory_entries(&sha_dir, &expected_fanouts, &BTreeSet::new())
            .map_err(|_| corrupt_evidence())?;
        require_exact_directory_entries(&bodies_dir, &["sha256".to_owned()], &BTreeSet::new())
            .map_err(|_| corrupt_evidence())?;
    }
    let mut required_root = vec![
        "binding.json".to_owned(),
        "database".to_owned(),
        "root-manifest.json".to_owned(),
    ];
    if !references.chunks.is_empty() {
        required_root.push("inventory".to_owned());
    }
    if !body_sizes.is_empty() {
        required_root.push("bodies".to_owned());
    }
    let optional: BTreeSet<String> = ["root-manifest.auth.json".to_owned()].into_iter().collect();
    require_exact_directory_entries(directory, &required_root, &optional)
        .map_err(|_| corrupt_evidence())?;
    files.push(FileTreeEntryWire {
        logical_reference: "root-manifest.json".to_owned(),
        size: root_payload.len() as i64,
        digest_sha256: hex_encode(&manifest.digest),
    });
    files.sort_by(|a, b| a.logical_reference.cmp(&b.logical_reference));
    let file_tree_payload = serde_json::to_vec(&FileTreeWire {
        schema_version: "central.backup-file-tree/v1",
        backup_id: backup_id.to_string(),
        files,
    })
    .map_err(|_| invalid_repository())?;
    let file_tree = BackupFileTreeEvidence {
        digest: Sha256::digest(&file_tree_payload).into(),
    };
    file_tree.validate().map_err(|_| corrupt_evidence())?;
    Ok(UnsealedBackupEvidence {
        manifest,
        dump: dump_evidence,
        file_tree,
        artifact_count,
        object_bytes,
    })
}

// ---------------------------------------------------------------------------
// Descriptor primitives
// ---------------------------------------------------------------------------

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[(byte >> 4) as usize]));
        out.push(char::from(DIGITS[(byte & 0x0f) as usize]));
    }
    out
}

pub(crate) fn hex_decode(raw: &str) -> Result<Vec<u8>, Failure> {
    let bytes = raw.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(invalid_repository());
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.as_chunks::<2>().0 {
        let high = hex_value(pair[0]).ok_or_else(invalid_repository)?;
        let low = hex_value(pair[1]).ok_or_else(invalid_repository)?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn safe_path_component(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains('/') && !name.contains('\0')
}

/// `secureOpenAt` — descriptor-relative `openat2` under the full
/// containment set plus `O_NOFOLLOW` on the final component. The raw
/// `Errno` is preserved so create-only paths keep their `EEXIST`
/// discrimination.
fn secure_open_errno<Fd: AsFd>(
    parent: Fd,
    name: &str,
    flags: OFlags,
    mode: Mode,
) -> Result<OwnedFd, Errno> {
    if !safe_path_component(name) {
        return Err(Errno::INVAL);
    }
    openat2(
        parent,
        name,
        flags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        mode,
        crate::sys::openat2::RESOLVE_FLAGS,
    )
}

pub(crate) fn secure_open_at<Fd: AsFd>(
    parent: Fd,
    name: &str,
    flags: OFlags,
    mode: Mode,
) -> Result<OwnedFd, Failure> {
    secure_open_errno(parent, name, flags, mode).map_err(|_| invalid_repository())
}

/// `duplicateDescriptor` preserves the descriptor-selected object
/// while making the duplicate close-on-exec. Recovery repository
/// descriptors must never be inherited by `pg_dump`, object-store
/// clients, or any other child process.
pub(crate) fn duplicate_descriptor<Fd: AsFd>(fd: Fd) -> Result<OwnedFd, Failure> {
    fcntl_dupfd_cloexec(fd, 0).map_err(|_| invalid_repository())
}

/// `repositoryFilesystemFacts`.
struct FilesystemFacts {
    uid: u32,
    gid: u32,
    device_major: u64,
    device_minor: u64,
    inode: u64,
    mount_id: u64,
}

/// `repositoryFilesystemIdentity`.
fn repository_filesystem_identity<Fd: AsFd>(fd: Fd) -> Result<FilesystemFacts, Failure> {
    let stat = statx(
        fd,
        "",
        AtFlags::EMPTY_PATH | AtFlags::NO_AUTOMOUNT,
        StatxFlags::BASIC_STATS | StatxFlags::MNT_ID,
    )
    .map_err(|_| invalid_repository())?;
    if !FileType::from_raw_mode(u32::from(stat.stx_mode)).is_dir()
        || stat.stx_mode & 0o777 != 0o700
        || stat.stx_ino == 0
        || stat.stx_mnt_id == 0
    {
        return Err(invalid_repository());
    }
    Ok(FilesystemFacts {
        uid: stat.stx_uid,
        gid: stat.stx_gid,
        device_major: u64::from(stat.stx_dev_major),
        device_minor: u64::from(stat.stx_dev_minor),
        inode: stat.stx_ino,
        mount_id: stat.stx_mnt_id,
    })
}

fn validate_repository_root<Fd: AsFd>(fd: Fd, expected: &RepositoryBinding) -> Result<(), Failure> {
    let identity = repository_filesystem_identity(fd)?;
    if identity.uid != expected.owner_uid
        || identity.gid != expected.owner_gid
        || identity.device_major != expected.device_major
        || identity.device_minor != expected.device_minor
        || identity.inode != expected.root_inode
        || identity.mount_id != expected.mount_id
    {
        return Err(invalid_repository());
    }
    Ok(())
}

fn validate_repository_file<Fd: AsFd>(
    fd: Fd,
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<(), Failure> {
    let stat = fstat(fd).map_err(|_| invalid_repository())?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_mode & 0o777 != mode
        || stat.st_uid != uid
        || stat.st_gid != gid
        || stat.st_nlink != 1
    {
        return Err(invalid_repository());
    }
    Ok(())
}

pub(crate) fn validate_repository_directory_owned<Fd: AsFd>(
    fd: Fd,
    uid: u32,
    gid: u32,
) -> Result<(), Failure> {
    let stat = fstat(fd).map_err(|_| invalid_repository())?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || stat.st_mode & 0o777 != 0o700
        || stat.st_uid != uid
        || stat.st_gid != gid
    {
        return Err(invalid_repository());
    }
    Ok(())
}

fn ensure_directory_at<Fd: AsFd>(parent: Fd, name: &str) -> Result<OwnedFd, Failure> {
    if !safe_path_component(name) {
        return Err(invalid_repository());
    }
    match mkdirat(&parent, name, Mode::from_raw_mode(0o700)) {
        Ok(()) => fsync(&parent).map_err(|_| invalid_repository())?,
        Err(Errno::EXIST) => {}
        Err(_) => return Err(invalid_repository()),
    }
    let fd = secure_open_at(
        &parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map_err(|_| invalid_repository())?;
    validate_repository_directory_owned(&fd, effective_uid(), effective_gid())
        .map_err(|_| invalid_repository())?;
    Ok(fd)
}

pub(crate) fn open_existing_directory_at<Fd: AsFd>(
    parent: Fd,
    name: &str,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<OwnedFd, Failure> {
    if !safe_path_component(name) {
        return Err(invalid_repository());
    }
    let fd = secure_open_at(
        &parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map_err(|_| corrupt_evidence())?;
    validate_repository_directory_owned(&fd, owner_uid, owner_gid)
        .map_err(|_| corrupt_evidence())?;
    Ok(fd)
}

fn create_only_at<Fd: AsFd>(parent: Fd, name: &str, payload: &[u8]) -> Result<(), Failure> {
    let mut cursor = io::Cursor::new(payload);
    create_only_stream_at(
        parent,
        name,
        &mut cursor,
        payload.len() as i64,
        payload.len() as i64,
    )?;
    Ok(())
}

fn write_atomic_replace_at<Fd: AsFd>(
    parent: Fd,
    name: &str,
    payload: &[u8],
) -> Result<(), Failure> {
    if !safe_path_component(name) || payload.is_empty() {
        return Err(invalid_repository());
    }
    let mut nonce = [0u8; 16];
    rustix::rand::getrandom(&mut nonce, rustix::rand::GetRandomFlags::empty())
        .map_err(|_| invalid_repository())?;
    let temporary_name = format!(".repository-manifest-{}.tmp", hex_encode(&nonce));
    create_only_at(&parent, &temporary_name, payload)?;
    match renameat(&parent, &temporary_name, &parent, name) {
        Ok(()) => fsync(&parent).map_err(|_| invalid_repository()),
        Err(_) => {
            let _ = unlinkat(&parent, &temporary_name, AtFlags::empty());
            let _ = fsync(&parent);
            Err(invalid_repository())
        }
    }
}

/// `createOnlyStreamAt` leaves a partially written entry in place on
/// any source, size, checksum, sync, or close failure. That is
/// deliberate: recovery media is evidence, and create-only naming
/// prevents a retry from pretending an ambiguous write is a fresh
/// valid copy.
fn create_only_stream_at<Fd: AsFd>(
    parent: Fd,
    name: &str,
    source: &mut dyn Read,
    maximum_bytes: i64,
    expected_bytes: i64,
) -> Result<(i64, [u8; 32]), Failure> {
    if !safe_path_component(name) {
        return Err(invalid_repository());
    }
    let fd = match secure_open_errno(
        &parent,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
        Mode::from_raw_mode(0o600),
    ) {
        Ok(fd) => fd,
        Err(Errno::EXIST) => return Err(already_exists()),
        Err(_) => return Err(invalid_repository()),
    };
    let mut file = File::from(fd);
    let result = stream_body(&mut file, source, maximum_bytes, expected_bytes);
    let sync_result = file.sync_all();
    drop(file);
    // Upstream syncs the parent on every exit path so the temporary
    // (or partial) name's durably visible state matches the returned
    // failure.
    let _ = fsync(&parent);
    match (result, sync_result) {
        (Ok((size, digest)), Ok(())) => Ok((size, digest)),
        (Err(e), _) => Err(e),
        (Ok(_), Err(_)) => Err(invalid_repository()),
    }
}

fn stream_body(
    file: &mut File,
    source: &mut dyn Read,
    maximum_bytes: i64,
    expected_bytes: i64,
) -> Result<(i64, [u8; 32]), Failure> {
    let mut digest = Sha256::new();
    let mut bytes_written: i64 = 0;
    let mut buffer = vec![0u8; STREAM_BUFFER_BYTES];
    loop {
        match source.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                if expected_bytes >= 0 && bytes_written > expected_bytes - count as i64 {
                    return Err(evidence_mismatch());
                }
                if bytes_written > maximum_bytes - count as i64 {
                    return Err(repository_limit());
                }
                file.write_all(&buffer[..count])
                    .map_err(|_| invalid_repository())?;
                digest.update(&buffer[..count]);
                bytes_written += count as i64;
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(invalid_repository()),
        }
    }
    if expected_bytes >= 0 && bytes_written != expected_bytes {
        return Err(evidence_mismatch());
    }
    Ok((bytes_written, digest.finalize().into()))
}

pub(crate) fn read_file_at_owned<Fd: AsFd>(
    parent: Fd,
    name: &str,
    maximum_bytes: i64,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<Vec<u8>, Failure> {
    if maximum_bytes < 0 || !safe_path_component(name) {
        return Err(invalid_repository());
    }
    let fd = secure_open_at(&parent, name, OFlags::RDONLY, Mode::empty())
        .map_err(|_| corrupt_evidence())?;
    let stat = fstat(&fd).map_err(|_| corrupt_evidence())?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_mode & 0o777 != 0o600
        || stat.st_uid != owner_uid
        || stat.st_gid != owner_gid
        || stat.st_nlink != 1
        || stat.st_size < 0
        || stat.st_size > maximum_bytes
    {
        return Err(corrupt_evidence());
    }
    let mut file = File::from(fd);
    let mut payload = Vec::new();
    let mut buffer = vec![0u8; STREAM_BUFFER_BYTES.min((maximum_bytes + 1) as usize)];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                payload.extend_from_slice(&buffer[..count]);
                if payload.len() as i64 > maximum_bytes {
                    return Err(corrupt_evidence());
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(corrupt_evidence()),
        }
    }
    Ok(payload)
}

pub(crate) fn hash_file_at<Fd: AsFd>(
    parent: Fd,
    name: &str,
    maximum_bytes: i64,
) -> Result<(i64, [u8; 32]), Failure> {
    hash_file_at_owned(
        parent,
        name,
        maximum_bytes,
        effective_uid(),
        effective_gid(),
    )
}

pub(crate) fn hash_file_at_owned<Fd: AsFd>(
    parent: Fd,
    name: &str,
    maximum_bytes: i64,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<(i64, [u8; 32]), Failure> {
    if maximum_bytes < 0 || !safe_path_component(name) {
        return Err(invalid_repository());
    }
    let fd = secure_open_at(&parent, name, OFlags::RDONLY, Mode::empty())
        .map_err(|_| corrupt_evidence())?;
    let stat = fstat(&fd).map_err(|_| corrupt_evidence())?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_mode & 0o777 != 0o600
        || stat.st_uid != owner_uid
        || stat.st_gid != owner_gid
        || stat.st_nlink != 1
        || stat.st_size < 0
        || stat.st_size > maximum_bytes
    {
        return Err(corrupt_evidence());
    }
    let mut file = File::from(fd);
    let mut digest = Sha256::new();
    let mut buffer = vec![0u8; STREAM_BUFFER_BYTES];
    let mut bytes_read: i64 = 0;
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                bytes_read += count as i64;
                if bytes_read > maximum_bytes {
                    return Err(corrupt_evidence());
                }
                digest.update(&buffer[..count]);
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(corrupt_evidence()),
        }
    }
    if bytes_read != stat.st_size || bytes_read > maximum_bytes {
        return Err(corrupt_evidence());
    }
    Ok((bytes_read, digest.finalize().into()))
}

/// `createVerifiedBodyAt` — temp-name stream + `RENAME_NOREPLACE`
/// publish; an identical existing body verifies, any drift mismatches.
fn create_verified_body_at<Fd: AsFd>(
    directory: Fd,
    name: &str,
    source: &mut dyn Read,
    expected_bytes: i64,
    expected_digest: [u8; 32],
) -> Result<(i64, [u8; 32]), Failure> {
    if !safe_path_component(name) || expected_bytes < 0 || expected_digest == [0u8; 32] {
        return Err(invalid_repository());
    }
    if let Ok((size, digest)) = hash_file_at(&directory, name, expected_bytes)
        && size == expected_bytes
        && digest == expected_digest
    {
        return Ok((size, digest));
    }
    let mut nonce = [0u8; 16];
    rustix::rand::getrandom(&mut nonce, rustix::rand::GetRandomFlags::empty())
        .map_err(|_| invalid_repository())?;
    let temporary_name = format!(".body-attempt-{}", hex_encode(&nonce));
    let stream_result = create_only_stream_at(
        &directory,
        &temporary_name,
        source,
        expected_bytes,
        expected_bytes,
    );
    let (size, digest) = match stream_result {
        Ok((size, digest)) if size == expected_bytes && digest == expected_digest => (size, digest),
        Ok(_) => {
            // A complete write that disagrees on size or digest is an
            // evidence mismatch, not an I/O failure.
            let _ = unlinkat(&directory, &temporary_name, AtFlags::empty());
            let _ = fsync(&directory);
            return Err(evidence_mismatch());
        }
        Err(e) => {
            let _ = unlinkat(&directory, &temporary_name, AtFlags::empty());
            let _ = fsync(&directory);
            if e.code() == repository_limit().code()
                || e.code() == ERR_BACKUP_ARTIFACT_EVIDENCE_MISMATCH
            {
                return Err(evidence_mismatch());
            }
            return Err(e);
        }
    };
    match renameat_with(
        &directory,
        &temporary_name,
        &directory,
        name,
        RenameFlags::NOREPLACE,
    ) {
        Ok(()) => {
            fsync(&directory).map_err(|_| invalid_repository())?;
            Ok((size, digest))
        }
        Err(Errno::EXIST) => {
            let _ = unlinkat(&directory, &temporary_name, AtFlags::empty());
            let _ = fsync(&directory);
            match hash_file_at(&directory, name, expected_bytes) {
                Ok((existing_size, existing_digest))
                    if existing_size == expected_bytes && existing_digest == expected_digest =>
                {
                    Ok((existing_size, existing_digest))
                }
                _ => Err(evidence_mismatch()),
            }
        }
        Err(_) => {
            let _ = unlinkat(&directory, &temporary_name, AtFlags::empty());
            let _ = fsync(&directory);
            Err(invalid_repository())
        }
    }
}

fn check_verified_dump(
    file: &mut File,
    binding: &RepositoryBinding,
    profile: &RecoveryProfile,
    evidence: &VerificationEvidence,
) -> Result<(), Failure> {
    let stat = fstat(&*file).map_err(|_| corrupt_evidence())?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_mode & 0o777 != 0o600
        || stat.st_uid != binding.owner_uid
        || stat.st_gid != binding.owner_gid
        || stat.st_nlink != 1
        || stat.st_size <= 0
        || stat.st_size as u64 > profile.max_database_bytes
    {
        return Err(corrupt_evidence());
    }
    let mut digest = Sha256::new();
    let mut buffer = vec![0u8; STREAM_BUFFER_BYTES];
    let mut bytes_read: i64 = 0;
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                bytes_read += count as i64;
                if bytes_read > profile.max_database_bytes as i64 + 1 {
                    return Err(corrupt_evidence());
                }
                digest.update(&buffer[..count]);
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(corrupt_evidence()),
        }
    }
    let sum: [u8; 32] = digest.finalize().into();
    if bytes_read != stat.st_size
        || bytes_read as u64 > profile.max_database_bytes
        || bytes_read != evidence.dump.size
        || sum != evidence.dump.digest
    {
        return Err(corrupt_evidence());
    }
    Ok(())
}

fn require_exact_directory_entries(
    directory: &OwnedFd,
    required: &[String],
    optional: &BTreeSet<String>,
) -> Result<(), Failure> {
    let mut expected: BTreeSet<String> = BTreeSet::new();
    for name in required {
        if !safe_path_component(name) {
            return Err(corrupt_evidence());
        }
        expected.insert(name.clone());
    }
    for name in optional {
        if !safe_path_component(name) {
            return Err(corrupt_evidence());
        }
        expected.insert(name.clone());
    }
    let mut dir = Dir::read_from(directory).map_err(|_| corrupt_evidence())?;
    let mut names: Vec<String> = Vec::new();
    for entry in dir.by_ref() {
        let entry = entry.map_err(|_| corrupt_evidence())?;
        let name = entry.file_name().to_str().map_err(|_| corrupt_evidence())?;
        if name == "." || name == ".." {
            continue;
        }
        names.push(name.to_owned());
    }
    if names.len() < required.len() || names.len() > expected.len() {
        return Err(corrupt_evidence());
    }
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for name in &names {
        if !expected.contains(name) || !seen.insert(name.clone()) {
            return Err(corrupt_evidence());
        }
    }
    for name in required {
        if !seen.contains(name) {
            return Err(corrupt_evidence());
        }
    }
    Ok(())
}

pub(crate) fn read_backup_binding_at(
    directory: &OwnedFd,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<BackupBinding, Failure> {
    let payload = read_file_at_owned(
        directory,
        "binding.json",
        MAXIMUM_REPOSITORY_BINDING_BYTES,
        owner_uid,
        owner_gid,
    )?;
    parse_backup_binding(&payload).map_err(|_| corrupt_evidence())
}

pub(crate) fn ordinal_file_name(ordinal: u32) -> String {
    format!("chunk-{ordinal:010}.json")
}

pub(crate) fn effective_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

pub(crate) fn effective_gid() -> u32 {
    rustix::process::getegid().as_raw()
}

impl central_backup::port::RecoveryRepositoryStore for Repository {
    fn bind_backup(&self, operation: &BackupOperation) -> Result<(), Failure> {
        Self::bind_backup(self, operation)
    }
    fn write_dump(
        &self,
        backup_id: Uuid,
        source: &mut dyn std::io::Read,
        maximum_bytes: i64,
    ) -> Result<DumpEvidence, Failure> {
        Self::write_dump(self, backup_id, source, maximum_bytes)
    }
    fn write_artifact_body(
        &self,
        backup_id: Uuid,
        entry: &InventoryEntry,
        source: &mut dyn std::io::Read,
    ) -> Result<(), Failure> {
        Self::write_artifact_body(self, backup_id, entry, source)
    }
    fn write_chunk(&self, backup_id: Uuid, chunk: &InventoryChunk) -> Result<(), Failure> {
        Self::write_chunk(self, backup_id, chunk)
    }
    fn write_manifest(
        &self,
        manifest: &SealRootManifest,
    ) -> Result<BackupFileTreeEvidence, Failure> {
        Self::write_manifest(self, manifest)
    }
    fn write_seal_companion(
        &self,
        backup_id: Uuid,
        companion: &BackupSealCompanion,
    ) -> Result<BackupSealPublication, Failure> {
        if companion.backup_id != backup_id {
            return Err(invalid_repository());
        }
        Self::write_seal_companion(self, companion)
    }
    fn read_inventory_chunk(
        &self,
        backup_id: Uuid,
        ordinal: u32,
    ) -> Result<InventoryChunk, Failure> {
        Self::read_inventory_chunk(self, backup_id, ordinal)
    }
    fn read_seal_root(&self, backup_id: Uuid) -> Result<Vec<u8>, Failure> {
        Self::read_seal_root(self, backup_id)
    }
}

impl central_backup::port::BackupRepositoryInspector for Repository {
    fn capacity_census(&self) -> Result<central_backup::port::BackupRepositoryCensus, Failure> {
        Self::capacity_census(self)
    }
    fn device_capacity(&self) -> Result<DeviceCapacitySnapshot, Failure> {
        Self::device_capacity(self)
    }
    fn binding_id(&self) -> Uuid {
        Self::binding_id(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::repository_verifier::RepositoryVerifier;
    use central_backup::backup::manifest::new_seal_root_manifest;
    use central_backup::backup::operation::{
        BackupPhase, new_backup_accepted_facts, new_backup_operation,
    };
    use central_backup::domain::TargetIdentity;
    use central_backup::port::{RecoveryInventorySource, RecoveryRepositoryVerifier};
    use std::os::unix::fs::MetadataExt as _;
    use std::path::{Path, PathBuf};

    fn tempdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "central-r6-repo-{tag}-{}-{}",
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

    fn open_dir(path: &Path) -> OwnedFd {
        rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap()
    }

    /// Initialize a fresh repository root, then open the exclusive
    /// `Repository` over it.
    fn fixture(dir: &Path) -> Repository {
        let root = open_dir(dir);
        let binding =
            crate::backup_repository::initialize_repository_binding(&root, "fixture-instance")
                .expect("initialize_repository_binding");
        let fd = duplicate_descriptor(&root).expect("duplicate");
        validate_repository_root(&fd, &binding).expect("validate_repository_root");
        let payload = read_file_at_owned(
            &fd,
            "binding.json",
            MAXIMUM_REPOSITORY_BINDING_BYTES,
            binding.owner_uid,
            binding.owner_gid,
        )
        .expect("read_file_at_owned");
        let stored = parse_repository_binding(&payload).expect("parse_repository_binding");
        assert_eq!(stored, binding, "binding round-trip drift");
        Repository::from_descriptor(&root, &binding).expect("from_descriptor")
    }

    fn fingerprint(byte: u8) -> String {
        format!("sha256:{}", hex_encode(&[byte; 32]))
    }

    fn target() -> TargetIdentity {
        TargetIdentity {
            system_id: "sys-1".into(),
            database_oid: "16639".into(),
            database: "central".into(),
            config_hash: "hash-1".into(),
            epoch: 7,
        }
    }

    fn admitted_operation(binding_id: Uuid, backup_id: Uuid) -> BackupOperation {
        let created = time::OffsetDateTime::from_unix_timestamp(1_760_000_000).unwrap();
        let accepted = created + time::Duration::seconds(60);
        let operation = new_backup_operation(Uuid::now_v7(), backup_id, target(), created).unwrap();
        let facts = new_backup_accepted_facts(
            accepted,
            &fingerprint(0x11),
            &fingerprint(0x22),
            Uuid::now_v7(),
            binding_id,
            &fingerprint(0x33),
        )
        .unwrap();
        operation.accept(facts).unwrap()
    }

    fn dump_bytes() -> &'static [u8] {
        b"PGDMP\x05\x01central-fixture-dump-bytes"
    }

    fn sha256_of(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    /// The full write→seal path producing a sealed, restorable backup.
    fn sealed_backup(
        repository: &Repository,
        backup_id: Uuid,
        bodies: &[(InventoryEntry, Vec<u8>)],
    ) -> BackupSealCompanion {
        let now = time::OffsetDateTime::now_utc();
        let operation = admitted_operation(repository.binding_id(), backup_id)
            .advance(BackupPhase::Dumping, now)
            .unwrap()
            .advance(BackupPhase::Inventory, now)
            .unwrap();
        repository.bind_backup(&operation).unwrap();
        let mut source = std::io::Cursor::new(dump_bytes());
        let dump = repository
            .write_dump(backup_id, &mut source, 1 << 20)
            .unwrap();
        for (entry, body) in bodies {
            let mut body_source = std::io::Cursor::new(body.clone());
            repository
                .write_artifact_body(backup_id, entry, &mut body_source)
                .unwrap();
        }
        let chunk = central_backup::backup::inventory::new_inventory_chunk(
            0,
            bodies.iter().map(|(e, _)| *e).collect(),
        )
        .unwrap();
        repository.write_chunk(backup_id, &chunk).unwrap();
        let manifest = new_seal_root_manifest(&operation, dump, &[chunk]).unwrap();
        let tree = repository.write_manifest(&manifest).unwrap();
        let mut companion = BackupSealCompanion {
            authority_envelope_id: fingerprint(0x44),
            backup_id,
            operation_id: operation.operation_id,
            repository_binding_id: repository.binding_id(),
            target_fingerprint: operation.accepted_facts.target_fingerprint.clone(),
            config_fingerprint: operation.accepted_facts.config_fingerprint.clone(),
            payload_epoch_id: operation.accepted_facts.payload_epoch_id,
            root_manifest_digest: manifest.digest,
            file_tree_digest: tree.digest,
            sealed_at: operation.accepted_facts.database_time + time::Duration::seconds(5),
            hmac: hex_encode(&[0x77; 32]),
            digest: [0u8; 32],
        };
        companion.digest = Sha256::digest(companion.canonical_json().unwrap()).into();
        let publication = repository.write_seal_companion(&companion).unwrap();
        assert_eq!(publication.seal_companion_digest, companion.digest);
        assert_eq!(publication.repository_revision, 1);
        companion
    }

    #[test]
    fn repository_bind_write_seal_verify_round_trip() {
        let dir = tempdir("seal");
        let repository = fixture(&dir);
        let binding = repository.binding();
        assert!(binding.verify().is_ok());
        assert_eq!(repository.binding_id(), binding.binding_id);

        let backup_id = Uuid::now_v7();
        let body = b"artifact-body-one".to_vec();
        let entry = InventoryEntry {
            artifact_id: Uuid::now_v7(),
            checksum: sha256_of(&body),
            size: body.len() as i64,
        };
        let companion = sealed_backup(&repository, backup_id, &[(entry, body)]);

        let profile = default_recovery_profile();
        let evidence = repository.verify_backup(backup_id, &profile).unwrap();
        assert_eq!(evidence.repository_revision, 1);
        assert_eq!(evidence.artifact_count, 1);
        assert_eq!(evidence.manifest_digest, companion.root_manifest_digest);
        assert_eq!(evidence.seal_companion_digest, companion.digest);
        assert_eq!(evidence.file_tree_digest, companion.file_tree_digest);

        // The sealed dump re-opens byte-identical at position zero.
        let mut dump = repository.open_verified_dump(backup_id, &profile).unwrap();
        let mut bytes = Vec::new();
        dump.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, dump_bytes());

        // Attestation requires the exclusive (non-read-only) lock.
        let attestation = repository
            .attest_sealed_publication(
                Uuid::now_v7(),
                evidence.operation_id,
                backup_id,
                &profile,
                operation_time(),
            )
            .unwrap();
        assert!(attestation.verify().is_ok());
        assert!(attestation.binds(&companion));

        // Census and identity surfaces.
        let census = repository.capacity_census().unwrap();
        assert!(census.bytes > 0);
        assert_eq!(census.sealed_backups, 1);
        assert_eq!(repository.sealed_backup_ids().unwrap(), vec![backup_id]);
        assert!(
            repository
                .device_capacity()
                .unwrap()
                .device_id
                .starts_with("fs-")
        );
        assert_eq!(
            repository
                .read_inventory_chunk(backup_id, 0)
                .unwrap()
                .ordinal,
            0
        );
        assert!(!repository.read_seal_root(backup_id).unwrap().is_empty());
        repository.close().unwrap();

        // The verifier port opens a read-only handle (shared lock after
        // the exclusive lock is released) and walks once for the
        // complete evidence, then re-verifies for inventory.
        let read_only = Repository::read_only_from_descriptor(open_dir(&dir), &binding).unwrap();
        let verifier = RepositoryVerifier::new(read_only);
        let port_evidence =
            RecoveryRepositoryVerifier::verify_backup(&verifier, backup_id, &profile).unwrap();
        assert_eq!(port_evidence.manifest_digest, evidence.manifest_digest);
        let inventory = verifier
            .read_verified_inventory(backup_id, &profile)
            .unwrap();
        assert_eq!(inventory, vec![entry]);
        std::fs::remove_dir_all(&dir).ok();
    }

    fn operation_time() -> time::OffsetDateTime {
        time::OffsetDateTime::now_utc()
    }

    #[test]
    fn repository_create_only_and_tamper_refusals() {
        let dir = tempdir("tamper");
        let repository = fixture(&dir);
        let backup_id = Uuid::now_v7();
        let operation = admitted_operation(repository.binding_id(), backup_id);
        repository.bind_backup(&operation).unwrap();
        // Exact-repeat bind verifies the identical bytes.
        repository.bind_backup(&operation).unwrap();

        let mut source = std::io::Cursor::new(dump_bytes());
        let dump = repository
            .write_dump(backup_id, &mut source, 1 << 20)
            .unwrap();
        // Second dump write refuses create-only.
        let mut again = std::io::Cursor::new(dump_bytes());
        assert!(
            repository
                .write_dump(backup_id, &mut again, 1 << 20)
                .is_err()
        );

        // A tampered body mismatches evidence, not I/O.
        let entry = InventoryEntry {
            artifact_id: Uuid::now_v7(),
            checksum: [0xaa; 32],
            size: 8,
        };
        let mut wrong = std::io::Cursor::new(vec![0u8; 8]);
        let err = repository
            .write_artifact_body(backup_id, &entry, &mut wrong)
            .unwrap_err();
        assert_eq!(err.code(), ERR_BACKUP_ARTIFACT_EVIDENCE_MISMATCH);

        // Writes to a different backup id are refused (no binding).
        let mut src = std::io::Cursor::new(dump_bytes());
        assert!(
            repository
                .write_dump(Uuid::now_v7(), &mut src, 1 << 20)
                .is_err()
        );
        assert!(dump.validate().is_ok());
        repository.close().unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn repository_unsealed_is_not_verifiable() {
        let dir = tempdir("unsealed");
        let repository = fixture(&dir);
        let backup_id = Uuid::now_v7();
        let operation = admitted_operation(repository.binding_id(), backup_id)
            .advance(BackupPhase::Dumping, operation_time())
            .unwrap()
            .advance(BackupPhase::Inventory, operation_time())
            .unwrap();
        repository.bind_backup(&operation).unwrap();
        let mut source = std::io::Cursor::new(dump_bytes());
        let dump = repository
            .write_dump(backup_id, &mut source, 1 << 20)
            .unwrap();
        let manifest = new_seal_root_manifest(&operation, dump, &[]).unwrap();
        repository.write_manifest(&manifest).unwrap();
        // No companion → sealed verification and dump open refuse.
        let profile = default_recovery_profile();
        assert!(repository.verify_backup(backup_id, &profile).is_err());
        assert!(repository.open_verified_dump(backup_id, &profile).is_err());
        repository.close().unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn repository_read_only_lock_blocks_exclusive() {
        let dir = tempdir("locks");
        let repository = fixture(&dir);
        let binding = repository.binding();
        // Exclusive lock held: a second writer must refuse; a read-only
        // handle must also refuse while the exclusive lock is held.
        let root = open_dir(&dir);
        assert!(Repository::from_descriptor(&root, &binding).is_err());
        assert!(Repository::read_only_from_descriptor(&root, &binding).is_err());
        // Read-only open succeeds once the exclusive lock is released.
        repository.close().unwrap();
        let read_only = Repository::read_only_from_descriptor(&root, &binding).unwrap();
        assert_eq!(read_only.binding_id(), binding.binding_id);
        // A read-only repository cannot write.
        let operation = admitted_operation(binding.binding_id, Uuid::now_v7());
        assert!(read_only.bind_backup(&operation).is_err());
        read_only.close().unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn repository_rejects_foreign_root_and_planned_binding() {
        let dir = tempdir("foreign");
        let repository = fixture(&dir);
        let binding = repository.binding();
        // A different binding for the same directory refuses.
        let other_dir = tempdir("other");
        let other = fixture(&other_dir);
        let other_binding_id = other.binding_id();
        assert!(Repository::from_descriptor(open_dir(&dir), &other.binding()).is_err());
        other.close().unwrap();
        // A planned (never-admitted) operation cannot bind.
        let planned =
            new_backup_operation(Uuid::now_v7(), Uuid::now_v7(), target(), operation_time())
                .unwrap();
        assert!(repository.bind_backup(&planned).is_err());
        // A foreign repository binding refuses.
        let foreign = admitted_operation(other_binding_id, Uuid::now_v7());
        assert!(repository.bind_backup(&foreign).is_err());
        repository.close().unwrap();
        assert_eq!(binding.owner_uid, std::fs::metadata(&dir).unwrap().uid());
        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&other_dir).ok();
    }
}
