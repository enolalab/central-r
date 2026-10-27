//! Linux backup/recovery execution adapters (R6 task 5).
//!
//! Ports of `internal/adapter/backup/` from upstream Go: the pinned
//! `pg_dump`/`pg_restore` process boundary, the descriptor-bound recovery
//! repository, the S3-backed artifact source, environment/admission
//! evidence, and the composed restore engine. Every adapter in this
//! module is fixed-configuration: a caller can never select a binary,
//! argument, target, environment value, credential path, repository
//! path, or object key.
//!
//! Credential material never becomes a string inside this module. The
//! broker hands a sealed memfd to a provider trait; the adapter
//! validates seals, moves it to child fd 3 via
//! [`crate::sys::audited::pg_tool_command`], and closes the parent copy
//! the instant `spawn` returns.

pub(crate) mod capacity;
mod environment;
mod objectstore_backup;
mod operator_state;
mod pg_dump;
mod pg_restore;
mod pgdump_throughput;
mod pgtool;
pub(crate) mod repository;
mod repository_capacity;
mod repository_throughput;
mod repository_verifier;
mod restore_engine;
mod throughput_probe;

pub use capacity::device_capacity_from_descriptor;
pub use environment::{BackupEnvironment, new_backup_environment};
pub use objectstore_backup::{
    S3BackupObjectSource, new_backup_reader_from_sealed_credential,
    new_import_writer_from_sealed_credential,
};
pub use operator_state::{
    ProtectedInspector, ProvisioningRecord, ProvisioningRecordReader, new_protected_inspector,
};
pub use pg_dump::{PgDump, PgDumpConfig, PgDumpStream, SealedPassfileProvider};
pub use pg_restore::{
    PgRestore, PgRestoreConfig, RestoreDumpSource, SealedRestorePassfileProvider,
};
pub use pgdump_throughput::{PgDumpThroughputProbe, ThroughputProbePassfileProvider};
pub use repository::{
    Repository, VerificationEvidence, inspect_repository_descriptor, media_verification_walks,
    new_repository,
};
pub use repository_verifier::RepositoryVerifier;
pub use restore_engine::{
    ComposedRestoreEngine, RestoreAuditProjection, RestoreAuthorityResetter, RestoreDatabaseRunner,
    RestoreInventoryVerifier,
};
pub use throughput_probe::{
    ThroughputProbeDumpSource, ThroughputProbeObjectSource, ThroughputProbeRepository,
    ThroughputProbeRunner, new_throughput_probe_runner,
};
