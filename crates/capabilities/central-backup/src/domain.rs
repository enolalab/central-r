//! Backup/migration lifecycle domain types (ports
//! `internal/backup/migration.go`; rust-application-boundaries.md §2).
//!
//! These are the value types the migration runner, reset runner, and
//! broker proof flow share — the adapter implements the operations, the
//! domain owns the vocabulary.

use central_foundation::failure::Failure;

/// Result alias for the backup capability's port surface: a sanitized
/// [`Failure`], never a raw adapter error.
pub type Result<T> = core::result::Result<T, Failure>;

/// Canonical advisory-lock acquisition order (upstream
/// `backup.CanonicalLockOrder`). Sessions take `pg_advisory_lock` in this
/// order and release in reverse.
pub const CANONICAL_LOCK_ORDER: [&str; 3] = ["lock-common", "lock-opstate", "lock-migration"];

/// A one-PostgreSQL-session binding: backend PID, postmaster start time,
/// and a boot identity (cluster name, or the postmaster start as the local
/// boot identity on stock clusters). Ports `backup.SessionBinding`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionBinding {
    /// `pg_backend_pid()` — differs across reconnects; excluded from
    /// [`SessionBinding::same_instance`].
    pub backend_pid: i32,
    /// `pg_postmaster_start_time()` text — the instance start identity.
    pub backend_start: String,
    /// `cluster_name` setting, or `"postmaster:<start>"` when unset.
    pub boot_id: String,
    /// The three canonical lock identities, in [`CANONICAL_LOCK_ORDER`].
    pub lock_identities: Vec<String>,
}

impl SessionBinding {
    /// Ports `backup.SameInstance`: same postmaster start and same boot ID;
    /// `BackendPID` is intentionally excluded. A zero `expected` value skips
    /// the check (returns `true`).
    #[must_use]
    pub fn same_instance(&self, expected: &Self) -> bool {
        if expected.backend_start.is_empty() && expected.boot_id.is_empty() {
            return true;
        }
        self.backend_start == expected.backend_start && self.boot_id == expected.boot_id
    }

    /// Ports `completeSessionBinding`: nonzero PID, populated start/boot,
    /// and the canonical lock identity set.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.backend_pid > 0
            && !self.backend_start.is_empty()
            && !self.boot_id.is_empty()
            && self.lock_identities
                == CANONICAL_LOCK_ORDER
                    .iter()
                    .map(|s| (*s).to_owned())
                    .collect::<Vec<_>>()
    }
}

/// Stable PostgreSQL target identity bound at every authorization fence.
/// Ports `backup.TargetIdentity`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TargetIdentity {
    /// PostgreSQL system identifier.
    pub system_id: String,
    /// `pg_database.oid` for `current_database()`.
    pub database_oid: String,
    /// Database name.
    pub database: String,
    /// Content-addressed config binding.
    pub config_hash: String,
    /// Target epoch.
    pub epoch: u64,
}

impl TargetIdentity {
    /// The complete stable binding required at a mutation fence.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.system_id.is_empty()
            && !self.database_oid.is_empty()
            && !self.database.is_empty()
            && !self.config_hash.is_empty()
    }
}

/// One-use broker-signed proof that a target is empty (expires 60 s after
/// issuance upstream). Ports `backup.VerifiedEmptyTarget`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEmptyTarget {
    /// Operation the proof binds to.
    pub operation_id: uuid::Uuid,
    /// Session binding the proof was issued under.
    pub session_binding: SessionBinding,
    /// SHA-256 of target identity + empty state.
    pub empty_fingerprint: String,
    /// Baseline digest the proof binds.
    pub baseline_digest: String,
    /// Issuance time.
    pub issued_at: time::OffsetDateTime,
    /// Expiry time.
    pub expires_at: time::OffsetDateTime,
    /// Broker signature (one use).
    pub hmac: String,
}

/// Broker reset confirmation for the destructive version-zero reset.
/// Ports `backup.ResetConfirmation`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResetConfirmation {
    /// Operation the confirmation binds to.
    pub operation_id: uuid::Uuid,
    /// Target fingerprint binding.
    pub target_fingerprint: String,
    /// Broker nonce.
    pub nonce: Vec<u8>,
    /// Expiry time.
    pub expires_at: time::OffsetDateTime,
    /// Broker signature.
    pub hmac: String,
}

/// `backup.ExternalRecordState` — only the ready state the migration
/// runner produces is modeled here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalRecordState {
    /// `backup.ExternalRecordReady`.
    Ready,
}

/// `backup.ProvisioningPhase` — the terminal phase reported by `resume`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisioningPhase {
    /// `backup.ProvisioningCandidateActive`.
    CandidateActive,
}

/// `backup.BaselineManifest` — the installer asserts the latest applied
/// version and every known checksum so checksum drift reads as repair
/// required. `checksums` maps each ledger checksum to itself, as upstream.
#[derive(Debug, Clone)]
pub struct BaselineManifest {
    /// Latest applied migration version (37).
    pub version: i32,
    /// `checksum → checksum` for all known ledger checksums.
    pub checksums: std::collections::BTreeMap<String, String>,
}

impl BaselineManifest {
    /// Content digest of the manifest (upstream `BaselineManifest.Digest`):
    /// sha256 over `version:N` + sorted `file:sha` pairs.
    #[must_use]
    pub fn digest(&self) -> String {
        use core::fmt::Write as _;
        use sha2::Digest as _;
        let mut h = sha2::Sha256::new();
        h.update(format!("version:{}", self.version));
        for (file, sha) in &self.checksums {
            h.update(format!("|{file}:{sha}"));
        }
        let mut out = String::with_capacity(64);
        for b in h.finalize() {
            let _ = write!(out, "{b:02x}");
        }
        out
    }
}
