//! `internal/recovery/evidence.go` — the C06 evidence document's
//! record shapes and the validation rules that keep it safe: ticket
//! accounting consistency, no unresolved quarantine at ready, exactly
//! incremented epochs, present bootstrap generation, `sha256:` digest
//! shapes, and prohibition scanning so no locator or credential
//! material reaches the artifact.

use central_foundation::failure::Failure;
use serde::{Deserialize, Serialize};

use crate::wire::{sha256_hex, valid_recovery_digest, wire_failure};

fn evidence_failure(message: impl Into<String>) -> Failure {
    wire_failure("backup_recovery_evidence", message)
}

/// `EvidenceDigest` — lowercase-hex SHA-256 over the emitted document
/// bytes, terminating newline included. Callers add the `sha256:`
/// prefix at the manifest field that carries it.
#[must_use]
pub fn evidence_digest(document: &[u8]) -> String {
    sha256_hex(document)
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

// ---------------------------------------------------------------------------
// the prohibition scan (governance section 3.1)
// ---------------------------------------------------------------------------

/// `confirmationPhrasePrefixes` — the destructive-ceremony phrase
/// prefixes declared at
/// `internal/adapter/authority/helper/confirmation_phrase.go`. They
/// are unexported there and cannot be imported, so they are restated
/// here exactly as upstream restates them: a phrase the helper reads
/// and this scanner does not know is a phrase that can reach the
/// artifact.
const CONFIRMATION_PHRASE_PREFIXES: [&str; 10] = [
    "RESET VERSION-ZERO",
    "RESTORE CENTRAL",
    "ABANDON RESTORE",
    "WIPE CENTRAL",
    "EXPORT CENTRAL",
    "IMPORT CENTRAL",
    "DELETE BACKUP",
    "PRUNE ARTIFACTS",
    "RESCUE CENTRAL",
    "PATCH CENTRAL",
];

/// `base64BlobThreshold` — the length at which an unbroken run of
/// base64 alphabet is treated as an encoded blob rather than an
/// identifier. Digests are exempted explicitly by [`is_hex_digest`]:
/// a sha-256 hex string is a declared, checked field and is also a
/// subset of the base64 alphabet.
const BASE64_BLOB_THRESHOLD: usize = 48;

/// `pathBoundary` — the characters after which a `'/'` begins a path
/// rather than continuing one, so `"/etc/x"` and `"--dir=/etc/x"` are
/// hits while `"docker.io/library/postgres"` and
/// `"./internal/recovery/..."` are not.
///
/// The set covers every separator a captured diagnostic can put in
/// front of a path — including the line terminators, because a
/// failing scenario's stderr arrives newline-separated. The residual
/// limit upstream accepts, unchanged: a path with no boundary byte
/// before it at all (embedded mid-token) evades this.
const PATH_BOUNDARY: &str = " \t\n\r\u{b}\u{c}\"'=:(,[<;>&";

/// `weakPathBoundary` — boundaries ordinary prose produces as often
/// as a shell does. After a weak boundary a `'/'` has to begin more
/// than one path segment before it counts; every value the widened
/// set was added to catch still catches, because a leaked filesystem
/// path has segments to spare. The residual upstream accepts: a
/// single-segment path (`"/etc"`) appearing only immediately after
/// `')'` or `'|'` is not detected.
const WEAK_PATH_BOUNDARY: &str = ")|";

/// `prohibitedClass` — the class name governance reports, or `None`.
fn prohibited_class(value: &str) -> Option<&'static str> {
    if contains_private_key(value) {
        Some("private key material")
    } else if contains_dsn(value) {
        Some("a DSN")
    } else if contains_confirmation_phrase(value) {
        Some("a confirmation phrase prefix")
    } else if contains_absolute_path(value) {
        Some("an absolute path")
    } else if is_base64_shaped_blob(value) {
        Some("a base64-shaped blob")
    } else {
        None
    }
}

/// `privateKeyPattern` — `BEGIN[ A-Z0-9]*PRIVATE KEY`: `BEGIN`,
/// a run of uppercase/digit/space characters, then `PRIVATE KEY`.
fn contains_private_key(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut from = 0;
    while let Some(offset) = find_subslice(&bytes[from..], b"BEGIN") {
        let begin = from + offset;
        let mut at = begin + 5;
        loop {
            if bytes[at..].starts_with(b"PRIVATE KEY") {
                return true;
            }
            if at >= bytes.len() || !matches!(bytes[at], b' ' | b'A'..=b'Z' | b'0'..=b'9') {
                break;
            }
            at += 1;
        }
        from = begin + 1;
    }
    false
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// `containsDSN` — `"://"` anywhere, or a credential keyword followed
/// by optional whitespace and `'='` (upstream's case-insensitive
/// `(password|passfile|sslkey|sslcert|sslpassword)\s*=`).
fn contains_dsn(value: &str) -> bool {
    if value.contains("://") {
        return true;
    }
    let lowered = value.to_ascii_lowercase();
    let bytes = lowered.as_bytes();
    for keyword in ["password", "passfile", "sslkey", "sslcert", "sslpassword"] {
        let needle = keyword.as_bytes();
        let mut from = 0;
        while let Some(offset) = find_subslice(&bytes[from..], needle) {
            let mut at = from + offset + needle.len();
            // regexp `\s` = [\t\n\f\r ].
            while at < bytes.len() && matches!(bytes[at], b'\t' | b'\n' | 0x0b | b'\r' | b' ') {
                at += 1;
            }
            if at < bytes.len() && bytes[at] == b'=' {
                return true;
            }
            from += offset + 1;
        }
    }
    false
}

/// `containsConfirmationPhrase`.
fn contains_confirmation_phrase(value: &str) -> bool {
    CONFIRMATION_PHRASE_PREFIXES
        .iter()
        .any(|prefix| value.contains(prefix))
}

/// `containsAbsolutePath`.
fn contains_absolute_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    for position in 0..bytes.len() {
        if bytes[position] != b'/' {
            continue;
        }
        if position + 1 >= bytes.len() || !is_path_byte(bytes[position + 1]) {
            continue;
        }
        if position == 0 {
            return true;
        }
        let previous = bytes[position - 1];
        if PATH_BOUNDARY.as_bytes().contains(&previous) {
            return true;
        }
        if WEAK_PATH_BOUNDARY.as_bytes().contains(&previous)
            && has_second_segment(&bytes[position + 1..])
        {
            return true;
        }
    }
    false
}

/// `hasSecondSegment` — whether the token beginning at `rest` (the
/// bytes after a leading `'/'`) carries a second `'/'`-separated
/// segment. It is how a weak boundary is told from a strong one.
fn has_second_segment(rest: &[u8]) -> bool {
    for position in 0..rest.len() {
        if rest[position] == b'/' {
            return position + 1 < rest.len() && is_path_byte(rest[position + 1]);
        }
        if !is_path_byte(rest[position]) {
            return false;
        }
    }
    false
}

/// `isPathByte` — `[A-Za-z0-9._-]`.
fn is_path_byte(candidate: u8) -> bool {
    candidate.is_ascii_alphanumeric() || matches!(candidate, b'.' | b'_' | b'-')
}

/// `isBase64ShapedBlob` — whether the value CONTAINS an encoded blob,
/// not whether it IS one. The unit judged is a maximal run of base64
/// alphabet: anything outside it — a space, a quote, a hyphen, an
/// underscore, a full stop — ends the run, so ordinary prose and
/// every UUID break into pieces far below the threshold.
fn is_base64_shaped_blob(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut start = 0;
    while start < bytes.len() {
        if !is_base64_byte(bytes[start]) {
            start += 1;
            continue;
        }
        let mut end = start;
        while end < bytes.len() && is_base64_byte(bytes[end]) {
            end += 1;
        }
        if run_is_blob_shaped(&bytes[start..end]) {
            return true;
        }
        start = end;
    }
    false
}

/// `runIsBlobShaped` — decides one maximal run of base64 alphabet.
/// The run is split on `'='` before the length test: a genuine base64
/// encoding carries `'='` only as trailing padding, so splitting
/// never breaks a real blob, but it stops a label welded to a digest
/// (`"sha256=<64 hex>"`) from reading as a blob.
fn run_is_blob_shaped(run: &[u8]) -> bool {
    if run.len() < BASE64_BLOB_THRESHOLD {
        return false;
    }
    run.split(|b| *b == b'=')
        .any(|piece| piece.len() >= BASE64_BLOB_THRESHOLD && !is_hex_digest(piece))
}

/// `isHexDigest` — exactly 40 or 64 lowercase hex chars.
fn is_hex_digest(value: &[u8]) -> bool {
    if value.len() != 40 && value.len() != 64 {
        return false;
    }
    value
        .iter()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}

/// `isBase64Byte` — `[A-Za-z0-9+/=]`.
fn is_base64_byte(candidate: u8) -> bool {
    candidate.is_ascii_alphanumeric() || matches!(candidate, b'+' | b'/' | b'=')
}

/// `walkJSONStrings` — visits every string in the decoded artifact:
/// object keys (at `path.key (key)`) and string values alike. Keys
/// are visited in sorted order (`serde_json`'s object is a
/// `BTreeMap`; upstream sorts the map keys itself).
fn walk_json_strings(node: &serde_json::Value, path: &str, visit: &mut dyn FnMut(&str, &str)) {
    match node {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                visit(&format!("{path}.{key} (key)"), key);
                walk_json_strings(value, &format!("{path}.{key}"), visit);
            }
        }
        serde_json::Value::Array(elements) => {
            for (index, element) in elements.iter().enumerate() {
                walk_json_strings(element, &format!("{path}[{index}]"), visit);
            }
        }
        serde_json::Value::String(text) => visit(path, text),
        _ => {}
    }
}

/// `ScanProhibitions` — reads every string in an emitted artifact,
/// values and object keys alike, and reports the classes governance
/// section 3.1 forbids. A hit fails the emit.
///
/// The report names the JSON path and the class and never the
/// offending value: an error that quoted what it found would copy
/// the prohibited material into a run report, which is where it
/// would then be read from.
pub fn scan_prohibitions(document: &[u8]) -> Result<(), Failure> {
    let decoded: serde_json::Value = serde_json::from_slice(document).map_err(|e| {
        evidence_failure(format!(
            "recovery: the emitted artifact could not be re-read for the prohibition scan: {e}"
        ))
    })?;
    let mut problems = Vec::new();
    walk_json_strings(&decoded, "$", &mut |path, value| {
        if let Some(class) = prohibited_class(value) {
            problems.push(format!("{path} carries {class}"));
        }
    });
    if problems.is_empty() {
        return Ok(());
    }
    problems.sort();
    Err(evidence_failure(format!(
        "recovery: the emitted artifact carries material governance section 3.1 forbids:\n  - {}",
        problems.join("\n  - ")
    )))
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
        // Clean document, and a declared digest field exempted from
        // the base64-blob class.
        let digest = format!("sha256:{}", "a".repeat(64));
        assert!(scan_prohibitions(
            format!(r#"{{"note":"clean","digest":"{digest}","uuid":"a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"}}"#)
                .as_bytes()
        )
        .is_ok());
        // Each upstream class.
        assert!(scan_prohibitions(br#"{"d":"postgres://u:p@h/db"}"#.as_slice()).is_err());
        assert!(scan_prohibitions(br#"{"d":"password=hunter2"}"#.as_slice()).is_err());
        assert!(scan_prohibitions(br#"{"d":"sslcert = x"}"#.as_slice()).is_err());
        assert!(
            scan_prohibitions(br#"{"d":"-----BEGIN RSA PRIVATE KEY-----"}"#.as_slice()).is_err()
        );
        assert!(
            scan_prohibitions(br#"{"d":"typed RESTORE CENTRAL before apply"}"#.as_slice()).is_err()
        );
        assert!(
            scan_prohibitions(br#"{"d":"wrote /var/lib/central/dump.pg"}"#.as_slice()).is_err()
        );
        assert!(
            scan_prohibitions(
                br#"{"d":"stderr:\n/var/lib/postgresql/17/main/base/16384 could not be opened"}"#
                    .as_slice()
            )
            .is_err()
        );
        // Weak boundary: two segments needed after ')' or '|'.
        assert!(scan_prohibitions(br#"{"d":"rows(before)/rows(after)"}"#.as_slice()).is_ok());
        assert!(scan_prohibitions(br#"{"d":"expected (5)/got 3"}"#.as_slice()).is_ok());
        assert!(scan_prohibitions(br#"{"d":"(cd /srv/data)"}"#.as_slice()).is_err());
        assert!(scan_prohibitions(br#"{"d":"single /etc only"}"#.as_slice()).is_err());
        assert!(scan_prohibitions(br#"{"d":"see )/etc for detail"}"#.as_slice()).is_ok());
        // Base64 blob vs labelled digest vs plain UUID.
        let blob = "QUJD".repeat(13); // 52 chars, no hex shape
        assert!(
            scan_prohibitions(format!(r#"{{"d":"helper replied {blob}"}}"#).as_bytes()).is_err()
        );
        let labelled = format!("sha256={}", "a".repeat(64));
        assert!(scan_prohibitions(format!(r#"{{"d":"{labelled}"}}"#).as_bytes()).is_ok());
        // Object keys are scanned too.
        assert!(scan_prohibitions(br#"{"/var/lib/x":1}"#.as_slice()).is_err());
        // Not JSON at all refuses to re-read.
        assert!(scan_prohibitions(b"not json").is_err());
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
