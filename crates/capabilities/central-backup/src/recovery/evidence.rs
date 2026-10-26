//! `internal/recovery/evidence.go` — the C06 evidence document's
//! record shapes and the validation rules that keep it safe: ticket
//! accounting consistency, no unresolved quarantine at ready, exactly
//! incremented epochs, present bootstrap generation, `sha256:` digest
//! shapes, and prohibition scanning so no locator or credential
//! material reaches the artifact.

use central_foundation::failure::Failure;
use serde::{Deserialize, Serialize};

use crate::wire::{sha256_hex, valid_recovery_digest, wire_failure};

fn evidence_failure(message: &'static str) -> Failure {
    wire_failure("backup_recovery_evidence", message)
}

/// `EvidenceDigest` — SHA-256 over the emitted document bytes.
#[must_use]
pub fn evidence_digest(document: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(document))
}

/// `ScenarioResult` — `pass`/`fail` only; a skipped or unknown value
/// is a parse error upstream and unrepresentable here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScenarioResult {
    /// `pass`.
    Pass,
    /// `fail`.
    Fail,
}

/// `Measurements`/`Measurement` — one observation carried with the
/// bound it is checked against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Measurement {
    /// Observed value.
    pub observed: i64,
    /// Checked bound.
    pub bound: i64,
    /// Relation token (`<=`, `>=`, `=`).
    pub relation: String,
}

/// `Measurements` — manifest field 11.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Measurements {
    /// Backup bytes/second.
    pub backup_bytes_per_sec: Measurement,
    /// Restore bytes/second.
    pub restore_bytes_per_sec: Measurement,
    /// Restore elapsed seconds.
    pub restore_elapsed_seconds: Measurement,
    /// Repository bytes.
    pub repository_bytes: Measurement,
    /// Minimum device free bytes.
    pub device_free_bytes_min: Measurement,
}

/// `CapacityReserveRecord` — manifest field 20. `device_id` is the
/// opaque helper-derived identity, never a path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityReserveRecord {
    /// Closed reserve kind.
    pub kind: String,
    /// Opaque device identity.
    pub device_id: String,
    /// Capacity role.
    pub role: String,
    /// Free bytes observed.
    pub free_bytes: u64,
    /// Reserved bytes.
    pub reserve_bytes: u64,
    /// Floor bytes.
    pub floor_bytes: u64,
    /// Projected demand bytes.
    pub projected_demand_bytes: u64,
    /// Allocated bytes.
    pub allocated_bytes: u64,
    /// Reserve released.
    pub released: bool,
    /// Release-confirmation instant (RFC 3339).
    pub release_confirmed_at: String,
}

/// `CeremonyRecord` — manifest field 21. Identities are opaque UUIDs;
/// no token and no nonce appears.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CeremonyRecord {
    /// Closed ceremony kind.
    pub kind: String,
    /// Authorization identity.
    pub authorization_id: String,
    /// Operation identity.
    pub operation_id: String,
    /// Issue instant (RFC 3339).
    pub issued_at: String,
    /// Expiry instant (RFC 3339).
    pub expires_at: String,
    /// The authorization was consumed exactly once.
    pub consumed_exactly_once: bool,
}

/// `ProtectedJournal` — manifest field 22: the operation IDs, phase
/// and checkpoint sequences, ticket issued/consumed counts, and
/// observed post-restart state.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedJournal {
    /// Operation identities (one per recorded operation).
    pub operation_ids: Vec<String>,
    /// `operation_id` → ordered phase names.
    pub phase_sequences: std::collections::BTreeMap<String, Vec<String>>,
    /// `operation_id` → ordered checkpoint names.
    pub checkpoint_sequences: std::collections::BTreeMap<String, Vec<String>>,
    /// Tickets issued.
    pub ticket_issued: i64,
    /// Tickets consumed.
    pub ticket_consumed: i64,
    /// `operation_id` → observed state after restart.
    pub state_after_restart: std::collections::BTreeMap<String, String>,
}

/// `RestartInjectionRecord` — manifest field 23; carries its own
/// outcome so a recorded failure can never read as clean.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestartInjectionRecord {
    /// Catalogue identity.
    pub id: String,
    /// Restart boundary (catalogue vocabulary).
    pub boundary: String,
    /// Restarted process (closed vocabulary).
    pub process: String,
    /// Observed state after restart.
    pub observed_after_restart: String,
    /// Outcome.
    pub result: ScenarioResult,
    /// `sha256:` transcript digest.
    pub log_sha256: String,
    /// Divergence text; `None` on pass.
    pub divergence: Option<String>,
}

/// Confirmation modes for [`DestructiveConfirmation::confirmation_mode`].
pub mod confirmation_mode {
    /// `typed_phrase`.
    pub const TYPED_PHRASE: &str = "typed_phrase";
    /// `grant` (ADR 0031 Docker profile — no phrase; the consumed
    /// grant nonce's digest takes `phrase_sha256`'s place).
    pub const GRANT: &str = "grant";
}

/// `DestructiveConfirmation` — manifest field 24. The phrase appears
/// only as a digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestructiveConfirmation {
    /// Destructive operation kind.
    pub operation_kind: String,
    /// `sha256:` phrase (or grant-nonce) digest.
    pub phrase_sha256: String,
    /// Admitted peer UID.
    pub admitted_peer_uid: i64,
    /// Redirected input was rejected.
    pub rejected_redirected_input: bool,
    /// Flag substitution was rejected.
    pub rejected_flag_substitution: bool,
    /// A phrase from another ceremony was rejected.
    pub rejected_cross_ceremony_phrase: bool,
    /// `typed_phrase` or `grant`.
    pub confirmation_mode: String,
    /// Missing grant rejected (grant mode).
    pub rejected_missing_grant: bool,
    /// Expired grant rejected (grant mode).
    pub rejected_expired_grant: bool,
    /// Spent grant rejected (grant mode).
    pub rejected_spent_grant: bool,
    /// Wrong-operation grant rejected (grant mode).
    pub rejected_wrong_operation_grant: bool,
}

/// `QuarantineByReason` — the typed breakdown of field 25.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuarantineByReason {
    /// `missing_body` count.
    pub missing_body: i64,
    /// `checksum_mismatch` count.
    pub checksum_mismatch: i64,
    /// `size_mismatch` count.
    pub size_mismatch: i64,
    /// `unexpected_artifact` count.
    pub unexpected_artifact: i64,
    /// `metadata_mismatch` count.
    pub metadata_mismatch: i64,
}

/// `QuarantineResolutions` — manifest field 25.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuarantineResolutions {
    /// Findings resolved by artifact re-ingest.
    pub reingested: i64,
    /// Findings resolved by delete finalization.
    pub delete_finalized: i64,
    /// Findings still unresolved.
    pub unresolved: i64,
    /// Findings still open at the ready boundary — must be zero.
    pub open_findings_at_ready: i64,
    /// Per-reason census.
    pub by_reason: QuarantineByReason,
}

/// `InvalidatedCounts` — field 26's invalidation census.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvalidatedCounts {
    /// Sessions.
    pub sessions: i64,
    /// Grants.
    pub grants: i64,
    /// Claims.
    pub claims: i64,
    /// Leases.
    pub leases: i64,
    /// Fences.
    pub fences: i64,
    /// Provider bindings.
    pub provider_bindings: i64,
    /// Secret references.
    pub secret_references: i64,
}

/// `AuthorityReset` — manifest field 26.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityResetEvidence {
    /// Restore epoch before.
    pub restore_epoch_before: i64,
    /// Restore epoch after (`before + 1`).
    pub restore_epoch_after: i64,
    /// Security epoch before.
    pub security_epoch_before: i64,
    /// Security epoch after (`before + 1`).
    pub security_epoch_after: i64,
    /// Invalidation census.
    pub invalidated: InvalidatedCounts,
    /// Broker TLS was re-keyed.
    pub broker_tls_rekeyed: bool,
    /// Bootstrap generations allocated (≥ 1).
    pub bootstrap_generations_allocated: i64,
    /// `sha256:` aggregate receipt digest.
    pub aggregate_receipt_sha256: String,
}

/// `CommandRecord` — manifest field 9: the literal command line, the
/// *names* of the environment variables set, exit code, result, log
/// digest. A name carrying its value is refused at emit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandRecord {
    /// Record identity.
    pub id: String,
    /// Literal command line.
    pub command_line: String,
    /// Environment variable names only.
    pub env_names: Vec<String>,
    /// Exit code.
    pub exit_code: i32,
    /// Outcome.
    pub result: ScenarioResult,
    /// `sha256:` transcript digest.
    pub log_sha256: String,
}

/// `ArtifactRecord` — governance field 12: names one scenario's
/// persisted transcript so its `log_sha256` is dereferenceable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRecord {
    /// `<scenario-id>.transcript.txt`.
    pub id: String,
    /// `sha256:` digest — must equal the scenario's `log_sha256`.
    pub checksum_sha256: String,
}

/// `validateAuthorityReset` — the field-26 consistency rules.
pub fn validate_authority_reset_evidence(reset: &AuthorityResetEvidence) -> Result<(), Failure> {
    if reset.restore_epoch_before < 0
        || reset.restore_epoch_after != reset.restore_epoch_before + 1
        || reset.security_epoch_before < 0
        || reset.security_epoch_after != reset.security_epoch_before + 1
        || !reset.broker_tls_rekeyed
        || reset.bootstrap_generations_allocated < 1
        || !valid_recovery_digest(&reset.aggregate_receipt_sha256)
    {
        return Err(evidence_failure(
            "invalid recovery evidence authority reset",
        ));
    }
    Ok(())
}

/// `validateProtectedJournal` — the field-22 accounting rules:
/// issued == consumed, every named sequence binds a declared
/// operation, counts are non-negative.
pub fn validate_protected_journal(journal: &ProtectedJournal) -> Result<(), Failure> {
    if journal.ticket_issued < 0
        || journal.ticket_consumed < 0
        || journal.ticket_issued != journal.ticket_consumed
        || journal.ticket_issued != journal.operation_ids.len() as i64
    {
        return Err(evidence_failure(
            "inconsistent recovery evidence ticket accounting",
        ));
    }
    for id in journal
        .phase_sequences
        .keys()
        .chain(journal.checkpoint_sequences.keys())
        .chain(journal.state_after_restart.keys())
    {
        if !journal.operation_ids.iter().any(|known| known == id) {
            return Err(evidence_failure(
                "recovery evidence journal names an undeclared operation",
            ));
        }
    }
    Ok(())
}

/// `validateQuarantineResolutions` — a `ready` boundary cannot be
/// claimed with open findings.
pub fn validate_quarantine_resolutions(resolutions: &QuarantineResolutions) -> Result<(), Failure> {
    let total = resolutions.by_reason.missing_body
        + resolutions.by_reason.checksum_mismatch
        + resolutions.by_reason.size_mismatch
        + resolutions.by_reason.unexpected_artifact
        + resolutions.by_reason.metadata_mismatch;
    if resolutions.reingested < 0
        || resolutions.delete_finalized < 0
        || resolutions.unresolved < 0
        || resolutions.open_findings_at_ready != 0
        || resolutions.reingested + resolutions.delete_finalized + resolutions.unresolved != total
    {
        return Err(evidence_failure(
            "invalid recovery evidence quarantine resolutions",
        ));
    }
    Ok(())
}

/// `ScanProhibitions` (bounded domain half) — a document must not
/// carry DSN-shaped text, an absolute path, or the typed
/// confirmation phrase. The full byte-shape walk lives upstream; the
/// domain reproduces its three load-bearing refusals.
pub fn scan_prohibitions(document: &str) -> Result<(), Failure> {
    let lowered = document.to_ascii_lowercase();
    if lowered.contains("postgres://")
        || lowered.contains("postgresql://")
        || lowered.contains("password=")
        || lowered.contains("central.restore-confirm")
    {
        return Err(evidence_failure(
            "recovery evidence carries prohibited locator or credential material",
        ));
    }
    for line in document.lines() {
        for token in line.split(|c: char| c.is_whitespace() || "\"'=:(,[<;>&".contains(c)) {
            if token.len() > 1 && token.starts_with('/') && token[1..].contains('/') {
                return Err(evidence_failure(
                    "recovery evidence carries prohibited locator or credential material",
                ));
            }
        }
    }
    Ok(())
}

/// Transcript artifact rule: `<scenario-id>.transcript.txt` whose
/// `checksum_sha256` equals the scenario's `log_sha256`.
pub fn validate_transcript_artifact(
    record: &ArtifactRecord,
    scenario_id: &str,
    log_sha256: &str,
) -> Result<(), Failure> {
    if record.id != format!("{scenario_id}.transcript.txt")
        || record.checksum_sha256 != log_sha256
        || !valid_recovery_digest(log_sha256)
    {
        return Err(evidence_failure(
            "invalid recovery evidence transcript artifact",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_ticket_accounting_must_balance() {
        let mut journal = ProtectedJournal {
            operation_ids: vec!["op1".into()],
            ticket_issued: 1,
            ticket_consumed: 1,
            ..Default::default()
        };
        assert!(validate_protected_journal(&journal).is_ok());
        journal.ticket_consumed = 2;
        assert!(validate_protected_journal(&journal).is_err());
        journal.ticket_consumed = 1;
        journal
            .phase_sequences
            .insert("ghost".into(), vec!["applying".into()]);
        assert!(validate_protected_journal(&journal).is_err());
    }

    #[test]
    fn quarantine_ready_requires_zero_open() {
        let mut resolutions = QuarantineResolutions {
            reingested: 1,
            unresolved: 0,
            by_reason: QuarantineByReason {
                missing_body: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(validate_quarantine_resolutions(&resolutions).is_ok());
        resolutions.open_findings_at_ready = 1;
        assert!(validate_quarantine_resolutions(&resolutions).is_err());
        resolutions.open_findings_at_ready = 0;
        resolutions.unresolved = 5; // breaks the census identity
        assert!(validate_quarantine_resolutions(&resolutions).is_err());
    }

    #[test]
    fn authority_reset_epochs_increment_exactly_once() {
        let mut reset = AuthorityResetEvidence {
            restore_epoch_before: 3,
            restore_epoch_after: 4,
            security_epoch_before: 7,
            security_epoch_after: 8,
            invalidated: InvalidatedCounts {
                sessions: 2,
                ..Default::default()
            },
            broker_tls_rekeyed: true,
            bootstrap_generations_allocated: 1,
            aggregate_receipt_sha256: format!("sha256:{}", "a".repeat(64)),
        };
        assert!(validate_authority_reset_evidence(&reset).is_ok());
        reset.security_epoch_after = 9;
        assert!(validate_authority_reset_evidence(&reset).is_err());
        reset.security_epoch_after = 8;
        reset.bootstrap_generations_allocated = 0;
        assert!(validate_authority_reset_evidence(&reset).is_err());
        reset.bootstrap_generations_allocated = 1;
        reset.broker_tls_rekeyed = false;
        assert!(validate_authority_reset_evidence(&reset).is_err());
    }

    #[test]
    fn prohibition_scan_refuses_locators_and_credentials() {
        assert!(scan_prohibitions("{\"note\":\"clean\"}").is_ok());
        assert!(scan_prohibitions("postgres://u:p@h/db").is_err());
        assert!(scan_prohibitions("password=hunter2").is_err());
        assert!(scan_prohibitions("wrote /var/lib/central/dump.pg").is_err());
        let digest = format!("sha256:{}", "a".repeat(64));
        assert!(scan_prohibitions(&format!("digest={digest}")).is_ok());
    }

    #[test]
    fn transcript_artifact_binds_log_digest() {
        let record = ArtifactRecord {
            id: "c06.s3.transcript.txt".into(),
            checksum_sha256: format!("sha256:{}", "f".repeat(64)),
        };
        assert!(validate_transcript_artifact(&record, "c06.s3", &record.checksum_sha256).is_ok());
        assert!(validate_transcript_artifact(&record, "c06.s4", &record.checksum_sha256).is_err());
        assert!(validate_transcript_artifact(&record, "c06.s3", "sha256:dead").is_err());
    }
}
