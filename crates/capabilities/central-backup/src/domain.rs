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

    /// `broker.TargetFingerprint` — the stable SHA-256 fingerprint of a
    /// target identity (`system_id:database_oid:database:config_hash:epoch`
    /// fed to the digest verbatim). The reset-confirmation binding and
    /// every provisioning journal intent key on it.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        use core::fmt::Write as _;
        use sha2::Digest as _;
        let mut h = sha2::Sha256::new();
        h.update(self.system_id.as_bytes());
        h.update(b":");
        h.update(self.database_oid.as_bytes());
        h.update(b":");
        h.update(self.database.as_bytes());
        h.update(b":");
        h.update(self.config_hash.as_bytes());
        h.update(b":");
        h.update(self.epoch.to_string().as_bytes());
        let mut out = String::with_capacity(64);
        for b in h.finalize() {
            let _ = write!(out, "{b:02x}");
        }
        out
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

/// `backup.ExternalRecordState` — the string states the broker's
/// protected provisioning record can hold, including the restore
/// phases the recovery audit projection uses (`applying`,
/// `verifying`, `quarantined`). `Absent` is the honest answer for a
/// target with no record at all (upstream's
/// `MigrationOperatorInspector` returns `ExternalRecordAbsent`, never
/// an error, for a missing record).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExternalRecordState {
    /// `backup.ExternalRecordAbsent` — `"absent"`.
    #[default]
    Absent,
    /// `backup.ExternalRecordInitializing` — `"initializing"`.
    Initializing,
    /// `backup.ExternalRecordReady` — `"ready"`.
    Ready,
    /// `backup.ExternalRecordApplying` — `"applying"` (restore).
    Applying,
    /// `backup.ExternalRecordVerifying` — `"verifying"` (restore).
    Verifying,
    /// `backup.ExternalRecordQuarantined` — `"quarantined"`.
    Quarantined,
}

impl ExternalRecordState {
    /// The wire state string (`backup.ExternalRecordState` values).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Initializing => "initializing",
            Self::Ready => "ready",
            Self::Applying => "applying",
            Self::Verifying => "verifying",
            Self::Quarantined => "quarantined",
        }
    }

    /// The `ExternalRecordReady` predicate (upstream `IsReady`).
    #[must_use]
    pub const fn is_ready(self) -> bool {
        matches!(self, Self::Ready)
    }

    /// `backup.ExternalRecordState.ValidTransitions` — the closed set
    /// of legal next states: `absent → initializing → ready|absent`;
    /// `ready → applying|quarantined`; `applying → verifying`;
    /// `verifying → ready|quarantined`; `quarantined → verifying`.
    #[must_use]
    pub const fn valid_transitions(self) -> &'static [Self] {
        match self {
            Self::Absent => &[Self::Initializing],
            Self::Initializing => &[Self::Ready, Self::Absent],
            Self::Ready => &[Self::Applying, Self::Quarantined],
            Self::Applying => &[Self::Verifying],
            Self::Verifying => &[Self::Ready, Self::Quarantined],
            Self::Quarantined => &[Self::Verifying],
        }
    }

    /// `backup.ExternalRecordState.CanTransition`.
    #[must_use]
    pub fn can_transition(self, next: Self) -> bool {
        self.valid_transitions().contains(&next)
    }

    /// `backup.ExternalRecordState.IsTerminal` — `ready` is the only
    /// terminal external state.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Ready)
    }

    /// Parse one wire state string; empty/unknown input is `Absent`,
    /// never a manufactured `Ready`.
    #[must_use]
    pub fn parse(state: &str) -> Self {
        match state {
            "initializing" => Self::Initializing,
            "ready" => Self::Ready,
            "applying" => Self::Applying,
            "verifying" => Self::Verifying,
            "quarantined" => Self::Quarantined,
            _ => Self::Absent,
        }
    }
}

/// `backup.ProvisioningPhase` — the journal phases an operation's
/// record passes through (`recorded → candidate_staged →
/// baseline_installed → candidate_active`); `reset` journals
/// `reset_started`/`database_removed`/`reset_complete` as free-form
/// phases the enum does not close over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProvisioningPhase {
    /// `backup.ProvisioningRecorded` — `"recorded"`.
    Recorded,
    /// `backup.ProvisioningCandidateStaged` — `"candidate_staged"`.
    CandidateStaged,
    /// `backup.ProvisioningBaselineInstalled` — `"baseline_installed"`.
    BaselineInstalled,
    /// `backup.ProvisioningCandidateActive` — `"candidate_active"`.
    CandidateActive,
    /// The empty phase — a settled (`ready`/`absent`) record carries
    /// no in-flight phase (upstream `""`).
    #[default]
    None,
}

impl ProvisioningPhase {
    /// The wire phase string (`backup.ProvisioningPhase` values).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::CandidateStaged => "candidate_staged",
            Self::BaselineInstalled => "baseline_installed",
            Self::CandidateActive => "candidate_active",
            Self::None => "",
        }
    }

    /// Parse one wire phase string; unknown values are `None`.
    #[must_use]
    pub fn parse(phase: &str) -> Self {
        match phase {
            "recorded" => Self::Recorded,
            "candidate_staged" => Self::CandidateStaged,
            "baseline_installed" => Self::BaselineInstalled,
            "candidate_active" => Self::CandidateActive,
            _ => Self::None,
        }
    }

    /// `isPreBaseline` — `recorded`/`candidate_staged` phases precede
    /// the baseline install leg of `resume`.
    #[must_use]
    pub const fn is_pre_baseline(self) -> bool {
        matches!(self, Self::Recorded | Self::CandidateStaged)
    }

    /// `backup.ProvisioningPhase.ValidTransitions` — the linear
    /// `recorded → candidate_staged → baseline_installed →
    /// candidate_active` chain; `candidate_active` (and `None`) have
    /// no legal successors.
    #[must_use]
    pub const fn valid_transitions(self) -> &'static [Self] {
        match self {
            Self::Recorded => &[Self::CandidateStaged],
            Self::CandidateStaged => &[Self::BaselineInstalled],
            Self::BaselineInstalled => &[Self::CandidateActive],
            Self::CandidateActive | Self::None => &[],
        }
    }

    /// `backup.ProvisioningPhase.CanTransition`.
    #[must_use]
    pub fn can_transition(self, next: Self) -> bool {
        self.valid_transitions().contains(&next)
    }

    /// `backup.ProvisioningPhase.IsTerminal` — `candidate_active` is
    /// the terminal provisioning phase.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::CandidateActive)
    }
}

/// `backup.Operation` — one migration operation's durable projection:
/// the coordinator's `up`/`resume` verbs return it and
/// `executeMigrationCommand` projects `{record_state, phase}` into the
/// operator result. `hidden_nonce` is broker-generated and never
/// serialized upstream; the Rust port does not model it at all.
#[derive(Debug, Clone, Default)]
pub struct Operation {
    /// Operation identity.
    pub operation_id: uuid::Uuid,
    /// Target the operation ran against.
    pub target: TargetIdentity,
    /// SHA-256 of the checksum manifest the baseline install bound.
    pub embedded_baseline_digest: String,
    /// External record state after the verb.
    pub record_state: ExternalRecordState,
    /// Terminal provisioning phase reported by the verb.
    pub provisioning_phase: ProvisioningPhase,
    /// Operation start (UTC).
    pub started_at: Option<time::OffsetDateTime>,
    /// Operation finalize (UTC); absent while in flight.
    pub finalized_at: Option<time::OffsetDateTime>,
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
