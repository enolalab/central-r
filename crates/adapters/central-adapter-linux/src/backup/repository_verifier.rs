//! `repository_verifier.go` — adapts the descriptor-bound filesystem
//! repository to the C03 read-only verifier port.

#![forbid(unsafe_code)]

use central_backup::backup::capacity::RecoveryProfile;
use central_backup::backup::inventory::InventoryEntry;
use central_backup::port::{
    RecoveryInventorySource, RecoveryRepositoryVerifier, RecoveryVerificationEvidence,
};
use central_foundation::failure::Failure;
use uuid::Uuid;

use super::repository::{
    Repository, corrupt_evidence, invalid_repository, verify_unsealed_backup_at,
};

/// `RepositoryVerifier` — one full verification walk per call, like
/// upstream.
pub struct RepositoryVerifier {
    repository: Repository,
}

impl RepositoryVerifier {
    /// `NewRepositoryVerifier`.
    #[must_use]
    pub fn new(repository: Repository) -> Self {
        Self { repository }
    }
}

impl RecoveryRepositoryVerifier for RepositoryVerifier {
    /// `VerifyBackup` — every field of the physical evidence crosses
    /// the port, including the sealed root manifest. Dropping
    /// `operation_id`, `repository_binding_id`, `dump`,
    /// `artifact_count`, `object_bytes` and the manifest is what
    /// forced the admission inspector to walk the media a second and
    /// third time for facts this walk had already established.
    fn verify_backup(
        &self,
        backup_id: Uuid,
        profile: &RecoveryProfile,
    ) -> Result<RecoveryVerificationEvidence, Failure> {
        if backup_id.is_nil() {
            return Err(invalid_repository());
        }
        let evidence = self.repository.verify_backup(backup_id, profile)?;
        Ok(RecoveryVerificationEvidence {
            operation_id: evidence.operation_id,
            backup_id: evidence.backup_id,
            repository_binding_id: evidence.repository_binding_id,
            manifest_digest: evidence.manifest_digest,
            seal_companion_digest: evidence.seal_companion_digest,
            file_tree_digest: evidence.file_tree_digest,
            repository_manifest_digest: evidence.repository_manifest_digest,
            repository_revision: evidence.repository_revision,
            dump: evidence.dump,
            artifact_count: evidence.artifact_count,
            object_bytes: evidence.object_bytes,
            manifest: evidence.manifest,
        })
    }
}

impl RecoveryInventorySource for RepositoryVerifier {
    /// `ReadVerifiedInventory` — `verify_backup` first closes
    /// authenticity over the root index and broker companion. The
    /// second descriptor-relative walk below returns entries only
    /// from the same fully revalidated immutable chunks. This
    /// deliberately favors a complete fresh read over trusting a
    /// prior in-memory projection.
    fn read_verified_inventory(
        &self,
        backup_id: Uuid,
        profile: &RecoveryProfile,
    ) -> Result<Vec<InventoryEntry>, Failure> {
        if backup_id.is_nil() || profile.validate().is_err() {
            return Err(invalid_repository());
        }
        let evidence = self.repository.verify_backup(backup_id, profile)?;
        let directory = self.repository.open_backup_directory(backup_id)?;
        let verified = verify_unsealed_backup_at(
            &directory,
            backup_id,
            profile,
            self.repository.binding.owner_uid,
            self.repository.binding.owner_gid,
        )?;
        if verified.manifest.operation_id != evidence.operation_id
            || verified.manifest.digest != evidence.manifest_digest
            || verified.file_tree.digest != evidence.file_tree_digest
            || verified.artifact_count != evidence.artifact_count
            || verified.object_bytes != evidence.object_bytes
        {
            return Err(corrupt_evidence());
        }
        let mut entries = Vec::with_capacity(verified.artifact_count as usize);
        for chunk in &verified.manifest.chunks {
            entries.extend(chunk.entries.iter().cloned());
        }
        if entries.len() as u64 != evidence.artifact_count {
            return Err(corrupt_evidence());
        }
        Ok(entries)
    }
}
