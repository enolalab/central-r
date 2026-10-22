//! Native PostgreSQL migration engine — port of
//! `internal/adapter/postgres/migrate/`.
//!
//! The module replays the compile-time-embedded, trusted static SQL corpus
//! ([`manifest::MIGRATIONS`]) verbatim through `sqlx::raw_sql`, preserving
//! every file's own `begin`/`commit`/`SET LOCAL` transaction boundaries and
//! its durable dirty-intent → DDL → clean-marker ledger protocol. There is
//! no `sqlx::migrate!` and no `_sqlx_migrations` table.
//!
//! The migration-domain types are owned by the `central-backup`
//! capability crate — `domain.rs` mirrors `internal/backup/migration.go`
//! and `port.rs` mirrors `internal/backup/port/migration_port.go`
//! field-for-field — and are re-exported here so this adapter's public
//! `migrate::*` surface is unchanged.

pub mod baseline;
pub mod grants;
pub mod inspector;
pub mod manifest;
pub mod reset_runner;
pub mod runner;
mod shape_spec;
pub mod verify_shape;

pub use baseline::BaselineInstaller;
pub use grants::reapply_runtime_grants;
pub use inspector::Inspector;
pub use manifest::{
    B10_FORWARD_CORRECTION_CHECKSUM, B10_FORWARD_CORRECTION_VERSION, LATEST_VERSION, MIGRATIONS,
    MigrationEntry, REAPPLY_RUNTIME_GRANTS_SQL, WITH_V15_CHAIN, WITHOUT_V15_CHAIN,
};
pub use reset_runner::ResetRunner;
pub use runner::Runner;

pub use central_backup::domain::{
    BaselineManifest, CANONICAL_LOCK_ORDER, ExternalRecordState, ProvisioningPhase,
    ResetConfirmation, SessionBinding, TargetIdentity, VerifiedEmptyTarget,
};
pub use central_backup::port::{
    BrokerProofService, CommitUpRequest, DirtyEvidence, EpochMarker, EpochMarkers,
    IssueEmptyTargetProofRequest, IssueResetConfirmationRequest, PostgresMigrationFacts,
    PrepareUpRequest, PrepareUpResult, ResetRequest, ResumeRequest, ResumeResult, UpRequest,
    UpResult, VersionChecksum, VersionZeroEligibility,
};

use central_foundation::failure::Failure;

/// Result alias for all adapter entry points: a sanitized
/// [`central_foundation::failure::Failure`], never a raw `sqlx` error.
pub type Result<T> = core::result::Result<T, Failure>;

/// The sole B05 workspace used by the local bootstrap and the session
/// capability (upstream `migrate.SentinelWorkspaceID`). Fixed UUIDv7 —
/// never the nil UUID — so `WorkspaceID::is_zero`'s "never set" invariant
/// cannot alias the one real workspace.
pub const SENTINEL_WORKSPACE_ID: &str = "019fdc8d-e33a-76ed-9ef0-a0d9fe92e54a";

pub(crate) type BoxFuture<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Object-safe erase of [`BrokerProofService`] for the runners' stored
/// `Arc<dyn …>` — `#[trait_variant::make(Send)]` keeps async methods as
/// return-position `impl Future`, which cannot build a vtable. Runners
/// only consume proofs, so the erased surface is exactly the two
/// consume-verified calls.
pub(crate) trait DynProofService: Send + Sync {
    /// Verify + consume `proof` once against `target`.
    fn consume_verified_empty_target<'a>(
        &'a self,
        target: &'a TargetIdentity,
        proof: VerifiedEmptyTarget,
    ) -> BoxFuture<'a, Result<()>>;
    /// Verify + consume `confirmation` once against `target`.
    fn consume_verified_reset_confirmation<'a>(
        &'a self,
        target: &'a TargetIdentity,
        confirmation: ResetConfirmation,
    ) -> BoxFuture<'a, Result<()>>;
}

impl<T: BrokerProofService + Send + Sync> DynProofService for T {
    fn consume_verified_empty_target<'a>(
        &'a self,
        target: &'a TargetIdentity,
        proof: VerifiedEmptyTarget,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(BrokerProofService::consume_verified_empty_target(
            self, target, proof,
        ))
    }
    fn consume_verified_reset_confirmation<'a>(
        &'a self,
        target: &'a TargetIdentity,
        confirmation: ResetConfirmation,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(BrokerProofService::consume_verified_reset_confirmation(
            self,
            target,
            confirmation,
        ))
    }
}
