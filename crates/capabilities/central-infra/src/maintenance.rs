//! `internal/maintenance` — the Slice E directional compatibility
//! matrix (E01), the validation gates (E02), and the protected-root
//! store: the matrix file plus its append-only signed transition
//! journal. Upstream keeps the file work inside the domain package;
//! the port does the same.
//!
//! Every matrix update is journaled as a `central.authority-transition/
//! v1` record, hash-chained (`prior_digest` carries the previous row's
//! HMAC) and HMAC-signed with the instance-local root-only key. A
//! rewritten line or a matrix that no longer matches the latest
//! journaled transition fails closed.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

use central_foundation::failure::Failure;

/// `MatrixSchemaVersion` — the only accepted matrix document schema.
pub const MATRIX_SCHEMA_VERSION: &str = "central.compatibility-matrix/v1";

/// `ErrMatrixTampered`'s failure code — the on-disk matrix does not
/// match the latest journaled transition. Handlers map it to the
/// `MAINTENANCE_MATRIX_TAMPERED` wire reason.
pub const MATRIX_TAMPERED_CODE: &str = "maintenance.matrix_tampered";

/// Entry kinds.
pub const KIND_HOST_TOOL: &str = "host-tool";
pub const KIND_IMAGE_DIGEST: &str = "image-digest";
pub const KIND_GO_MODULES: &str = "go-modules";

/// Upgrade paths.
pub const PATH_DIRECT: &str = "direct";
pub const PATH_OUT_OF_PLACE: &str = "out-of-place";
pub const PATH_UNSUPPORTED: &str = "unsupported";

/// `ReasonUnlisted` — the typed refusal for a transition the matrix
/// does not list.
pub const REASON_UNLISTED: &str = "MAINTENANCE_TRANSITION_UNLISTED";
/// Typed refusal reasons the command layer maps to stable exit
/// classes (`patch.go`).
pub const REASON_PATCH_PENDING: &str = "MAINTENANCE_PATCH_PENDING";
pub const REASON_PATCH_UNKNOWN: &str = "MAINTENANCE_PATCH_UNKNOWN";
pub const REASON_PATCH_CLOSED: &str = "MAINTENANCE_PATCH_CLOSED";
pub const REASON_ROLLBACK_STALE: &str = "MAINTENANCE_ROLLBACK_STALE";
pub const REASON_GATE_UNKNOWN: &str = "MAINTENANCE_GATE_UNKNOWN";
pub const REASON_GATE_FAILED: &str = "MAINTENANCE_GATE_FAILED";

/// Gate verbs E02 implements (`patch.go`). Baseline gate strings map
/// onto these; anything unmapped refuses rather than weakening to a
/// no-op.
pub const GATE_VERSION_PRESENT: &str = "version-present";
pub const GATE_DIGEST_PRESENT: &str = "digest-present";
pub const GATE_MODULES_VERIF: &str = "modules-verified";

/// File names inside the instance's protected state directory
/// (`store.go`).
pub const MATRIX_FILE_NAME: &str = "compatibility-matrix.json";
pub const JOURNAL_FILE_NAME: &str = "maintenance-transitions.jsonl";
pub const KEY_FILE_NAME: &str = "maintenance.key";
/// `EvidenceFileName` — the `maintenance plan` artifact.
pub const EVIDENCE_FILE_NAME: &str = "slice-e-compatibility-matrix.json";
/// `ApplyEvidenceFileName` — the `maintenance apply` artifact.
pub const APPLY_EVIDENCE_FILE_NAME: &str = "slice-e-patch-apply.json";
/// `EvidenceSchema`.
pub const EVIDENCE_SCHEMA: &str = "slice-e-compatibility-matrix/v1";
/// `ApplyEvidenceSchema`.
pub const APPLY_EVIDENCE_SCHEMA: &str = "slice-e-patch-apply/v1";

const TRANSITION_SCHEMA: &str = "central.authority-transition/v1";
const OP_MATRIX_INIT: &str = "matrix_initialized";
const OP_MATRIX_UPDATE: &str = "maintenance_matrix";
/// Patch operations (E02) and rollback/abandon operations (E03).
/// Pending/failed/abandoned rows echo the unchanged matrix digest and
/// sequence — they journal authority over an attempt, not a matrix
/// change — so the tamper check stays unchanged.
pub const OP_PATCH_PENDING: &str = "patch_pending";
pub const OP_PATCH_APPLIED: &str = "patch_applied";
pub const OP_PATCH_FAILED: &str = "patch_failed";
pub const OP_PATCH_ABANDONED: &str = "patch_abandoned";
pub const OP_ROLLBACK_PENDING: &str = "rollback_pending";
pub const OP_ROLLBACK_APPLIED: &str = "rollback_applied";
pub const OP_ROLLBACK_FAILED: &str = "rollback_failed";
pub const OP_ROLLBACK_ABANDONED: &str = "rollback_abandoned";

fn internal(msg: impl Into<String>) -> Failure {
    Failure::internal("maintenance_store", msg.into())
}

// ---------------------------------------------------------------------------
// Matrix document (matrix.go)
// ---------------------------------------------------------------------------

/// `Entry` — one directional compatibility row. Field order is the
/// upstream struct's: canonical encoding and the wire decode depend on
/// it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub name: String,
    pub kind: String,
    pub current: String,
    pub min: String,
    pub max: String,
    pub path: String,
    pub gate: String,
}

/// `Matrix` — the directional transition matrix. `sequence_num`
/// increments on every recorded update; bootstrap writes sequence 1.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Matrix {
    pub schema_version: String,
    pub sequence_num: u64,
    pub entries: Vec<Entry>,
}

/// `ParseMatrix` — strict decode; unknown fields cannot silently
/// become authority.
pub fn parse_matrix(raw: &[u8]) -> Result<Matrix, Failure> {
    let m: Matrix = serde_json::from_slice(raw)
        .map_err(|e| internal(format!("maintenance: parse matrix: {e}")))?;
    validate_matrix(&m)?;
    Ok(m)
}

/// `ValidateMatrix` — the closed contract.
pub fn validate_matrix(m: &Matrix) -> Result<(), Failure> {
    if m.schema_version != MATRIX_SCHEMA_VERSION {
        return Err(internal(format!(
            "maintenance: matrix schema {:?} unsupported",
            m.schema_version
        )));
    }
    if m.sequence_num == 0 {
        return Err(internal("maintenance: matrix sequence_num must be >= 1"));
    }
    if m.entries.is_empty() {
        return Err(internal("maintenance: matrix has no entries"));
    }
    let mut seen = std::collections::BTreeSet::new();
    for (i, e) in m.entries.iter().enumerate() {
        if e.name.is_empty() {
            return Err(internal(format!("maintenance: entry {i} has no name")));
        }
        if !seen.insert(&e.name) {
            return Err(internal(format!(
                "maintenance: duplicate entry {:?}",
                e.name
            )));
        }
        match e.kind.as_str() {
            KIND_HOST_TOOL | KIND_IMAGE_DIGEST | KIND_GO_MODULES => {}
            _ => {
                return Err(internal(format!(
                    "maintenance: entry {:?} kind {:?} unknown",
                    e.name, e.kind
                )));
            }
        }
        if e.current.is_empty() {
            return Err(internal(format!(
                "maintenance: entry {:?} has no current pin",
                e.name
            )));
        }
        match e.path.as_str() {
            PATH_DIRECT | PATH_OUT_OF_PLACE | PATH_UNSUPPORTED => {}
            _ => {
                return Err(internal(format!(
                    "maintenance: entry {:?} path {:?} unknown",
                    e.name, e.path
                )));
            }
        }
        if e.gate.is_empty() {
            return Err(internal(format!(
                "maintenance: entry {:?} has no validation gate",
                e.name
            )));
        }
    }
    Ok(())
}

impl Matrix {
    /// `Canonical` — deterministic encoding: the digest A05
    /// transitions carry must not depend on entry ordering. Go's
    /// `json.Marshal` emits struct fields in declaration order and
    /// serde's derive does the same, so the sorted-entry struct
    /// re-encodes byte-identically.
    pub fn canonical(&self) -> Result<Vec<u8>, Failure> {
        #[derive(Serialize)]
        struct Canonical<'a> {
            schema_version: &'a str,
            sequence_num: u64,
            entries: &'a [Entry],
        }
        let mut ordered = self.entries.clone();
        ordered.sort_by(|a, b| a.name.cmp(&b.name));
        serde_json::to_vec(&Canonical {
            schema_version: &self.schema_version,
            sequence_num: self.sequence_num,
            entries: &ordered,
        })
        .map_err(|e| internal(format!("maintenance: canonical matrix: {e}")))
    }

    /// `Digest` — the canonical sha256 identity transitions carry and
    /// refusals echo.
    pub fn digest(&self) -> Result<String, Failure> {
        canonical_digest(self)
    }

    /// `EntryByName`.
    pub fn entry_by_name(&self, name: &str) -> Option<Entry> {
        self.entries.iter().find(|e| e.name == name).cloned()
    }
}

/// `canonicalDigest`.
fn canonical_digest(m: &Matrix) -> Result<String, Failure> {
    let canonical = m.canonical()?;
    Ok(format!(
        "sha256:{}",
        crate::authority::wire::hex_encode(&Sha256::digest(&canonical))
    ))
}

/// `allowedDigests` — the digest allowlist inside a digest-kind
/// `max` (`digest:<sha256>,<sha256>…`).
pub fn allowed_digests(entry: &Entry) -> Vec<String> {
    let Some(rest) = entry.max.strip_prefix("digest:") else {
        return Vec::new();
    };
    rest.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_owned)
        .collect()
}

/// `BaselineMatrix` — the embedded matrix bootstrap writes on first
/// use (sequence 1).
pub fn baseline_matrix() -> Matrix {
    Matrix {
        schema_version: MATRIX_SCHEMA_VERSION.to_owned(),
        sequence_num: 1,
        entries: vec![
            Entry {
                name: "go-toolchain".to_owned(),
                kind: KIND_HOST_TOOL.to_owned(),
                current: "go1.26.6".to_owned(),
                min: "1.26.6".to_owned(),
                max: "1.26.x".to_owned(),
                path: PATH_DIRECT.to_owned(),
                gate: "full-test-suite+govulncheck".to_owned(),
            },
            Entry {
                name: "postgresql".to_owned(),
                kind: KIND_HOST_TOOL.to_owned(),
                current: "16.14".to_owned(),
                min: "16.14".to_owned(),
                max: "16.x".to_owned(),
                path: PATH_DIRECT.to_owned(),
                gate: "migration-replay+pg-dump-restore".to_owned(),
            },
            Entry {
                name: "minio-image".to_owned(),
                kind: KIND_IMAGE_DIGEST.to_owned(),
                current: "sha256:5e4a6ac5f4fdb500e5aa9b4317e5ec4b7cfa21cd8d3ac74e931b2b3e7a2ef2c1"
                    .to_owned(),
                min: "sha256:5e4a6ac5f4fdb500e5aa9b4317e5ec4b7cfa21cd8d3ac74e931b2b3e7a2ef2c1"
                    .to_owned(),
                max:
                    "digest:sha256:5e4a6ac5f4fdb500e5aa9b4317e5ec4b7cfa21cd8d3ac74e931b2b3e7a2ef2c1"
                        .to_owned(),
                path: PATH_DIRECT.to_owned(),
                gate: "artifact-upload-verify-roundtrip".to_owned(),
            },
            Entry {
                name: "docker-engine".to_owned(),
                kind: KIND_HOST_TOOL.to_owned(),
                current: "probed".to_owned(),
                min: "25.0".to_owned(),
                max: "29.x".to_owned(),
                path: PATH_DIRECT.to_owned(),
                gate: "compose-up-down-cycle".to_owned(),
            },
            Entry {
                name: "docker-compose".to_owned(),
                kind: KIND_HOST_TOOL.to_owned(),
                current: "probed".to_owned(),
                min: "2.0".to_owned(),
                max: "5.x".to_owned(),
                path: PATH_DIRECT.to_owned(),
                gate: "compose-up-down-cycle".to_owned(),
            },
            Entry {
                name: "infra-image".to_owned(),
                kind: KIND_IMAGE_DIGEST.to_owned(),
                current: "sha256:3930ac40a034eff98b844a500e61c5c4924cb44bdeb45b2efedc18f048c0063b"
                    .to_owned(),
                min: "sha256:3930ac40a034eff98b844a500e61c5c4924cb44bdeb45b2efedc18f048c0063b"
                    .to_owned(),
                max:
                    "digest:sha256:3930ac40a034eff98b844a500e61c5c4924cb44bdeb45b2efedc18f048c0063b"
                        .to_owned(),
                path: PATH_DIRECT.to_owned(),
                gate: "provision-roundtrip".to_owned(),
            },
            Entry {
                name: "go-modules".to_owned(),
                kind: KIND_GO_MODULES.to_owned(),
                current: "vendored".to_owned(),
                min: String::new(),
                max: String::new(),
                path: PATH_DIRECT.to_owned(),
                gate: "vendored-tree-verified".to_owned(),
            },
        ],
    }
}

// ---------------------------------------------------------------------------
// Transition evaluation (plan.go)
// ---------------------------------------------------------------------------

/// `Transition` — a requested dependency change: move `name` to `to`.
pub struct Transition<'a> {
    pub name: &'a str,
    pub to: &'a str,
}

/// `Verdict` — the matrix's answer for one dependency: whether the
/// requested transition is listed, plus the entry it was judged
/// against so a refusal can echo the governing row verbatim.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Verdict {
    pub dependency: String,
    pub allowed: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<Entry>,
}

/// `Evaluate` — one requested transition against the matrix. An
/// unknown dependency is unlisted — the matrix enumerates the closed
/// pin set.
pub fn evaluate(m: &Matrix, t: &Transition) -> Verdict {
    let Some(entry) = m.entry_by_name(t.name) else {
        return Verdict {
            dependency: t.name.to_owned(),
            reason: REASON_UNLISTED.to_owned(),
            ..Verdict::default()
        };
    };
    let mut v = Verdict {
        dependency: t.name.to_owned(),
        entry: Some(entry.clone()),
        ..Verdict::default()
    };
    if t.to.is_empty() || !entry_admits(&entry, t.to) {
        v.reason = REASON_UNLISTED.to_owned();
        return v;
    }
    v.allowed = true;
    v
}

/// `entryAdmits` — whether `to` is a permitted target under the entry.
fn entry_admits(e: &Entry, to: &str) -> bool {
    match e.kind.as_str() {
        KIND_IMAGE_DIGEST => allowed_digests(e).iter().any(|d| d == to),
        KIND_GO_MODULES => {
            // The cohort rule: any recorded module-set change is
            // admissible only as a matrix update — never silently.
            !to.is_empty() && to != e.current
        }
        _ => version_in_range(to, &e.min, &e.max),
    }
}

/// `versionInRange` — the X / X.Y / X.Y.Z / trailing-x range
/// notation. `16.x` means any 16.Y; absent components in min/max open
/// the bound.
fn version_in_range(v: &str, min: &str, max: &str) -> bool {
    let v = normalize_version(v);
    if v.is_empty() {
        return false;
    }
    if !min.is_empty() && compare_version(v, min.trim_start_matches('v')) < 0 {
        return false;
    }
    if !max.is_empty() && compare_version(v, max.trim_start_matches('v')) > 0 {
        return false;
    }
    true
}

/// `compareVersion` — two dotted numeric versions that may end in a
/// trailing `x` wildcard component. The wildcard makes the bound
/// inclusive of everything under it: `16.x` ≥ `16.anything`.
fn compare_version(a: &str, b: &str) -> i32 {
    let a_parts: Vec<&str> = a.split('.').collect();
    let b_parts: Vec<&str> = b.split('.').collect();
    let len = a_parts.len().max(b_parts.len());
    for i in 0..len {
        let ac = a_parts.get(i).copied().unwrap_or("0");
        let bc = b_parts.get(i).copied().unwrap_or("0");
        if bc == "x" {
            return 0;
        }
        let an = ac.parse::<i64>();
        let bn = bc.parse::<i64>();
        match (an, bn) {
            (Ok(an), Ok(bn)) => {
                if an != bn {
                    return if an < bn { -1 } else { 1 };
                }
            }
            // Non-numeric component — compare literally, exactly as
            // upstream's Atoi-error arm does.
            _ => {
                if ac != bc {
                    return if ac < bc { -1 } else { 1 };
                }
            }
        }
    }
    0
}

/// `normalizeVersion` — strips the prefixes host probes report
/// ("go1.26.6", "v16.14") so comparisons target the bare dotted
/// version.
fn normalize_version(v: &str) -> &str {
    let v = v.trim();
    let v = v.strip_prefix("go").unwrap_or(v);
    v.strip_prefix('v').unwrap_or(v)
}

/// `Plan` — the full picture `central maintenance plan` reports.
pub struct Plan {
    pub dependencies: Vec<Observed>,
}

/// `Observed` — a matrix entry paired with the version actually on
/// the host.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observed {
    pub entry: Entry,
    pub observed: String,
    #[serde(rename = "match")]
    pub matches: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

/// `EvaluateCurrent` — observed versions against the matrix's
/// `current` pins: the plan verb's core answer ("does this host still
/// run what the matrix pinned?").
pub fn evaluate_current(m: &Matrix, observed: &BTreeMap<String, String>) -> Plan {
    let mut p = Plan {
        dependencies: Vec::with_capacity(m.entries.len()),
    };
    for e in &m.entries {
        let mut o = Observed {
            entry: e.clone(),
            ..Observed::default()
        };
        let Some(got) = observed.get(&e.name) else {
            o.detail = "unprobed".to_owned();
            p.dependencies.push(o);
            continue;
        };
        o.observed = got.clone();
        o.matches = match e.kind.as_str() {
            KIND_HOST_TOOL => version_in_range(got, &e.min, &e.max),
            _ => *got == e.current,
        };
        if !o.matches {
            o.detail = format!("observed {:?} outside matrix [{}..{}]", got, e.min, e.max);
        }
        p.dependencies.push(o);
    }
    p
}

// ---------------------------------------------------------------------------
// Gates (patch.go)
// ---------------------------------------------------------------------------

/// `gateVerb` — maps a matrix entry's declared gate string to its
/// verb.
fn gate_verb(e: &Entry) -> &'static str {
    match e.gate.as_str() {
        "full-test-suite+govulncheck"
        | "migration-replay+pg-dump-restore"
        | "compose-up-down-cycle" => GATE_VERSION_PRESENT,
        "artifact-upload-verify-roundtrip" | "provision-roundtrip" => GATE_DIGEST_PRESENT,
        "vendored-tree-verified" => GATE_MODULES_VERIF,
        _ => GATE_UNKNOWN_SENTINEL,
    }
}

/// The unknown-gate marker — `gateVerb` returns the entry's own gate
/// string upstream, but the handler's `gateVerbFor` only needs the
/// implemented set; an out-of-vocabulary string is preserved verbatim
/// so `run_gate` can name it unimplemented.
const GATE_UNKNOWN_SENTINEL: &str = "";

fn gate_verb_owned(e: &Entry) -> String {
    let mapped = gate_verb(e);
    if mapped.is_empty() {
        e.gate.clone()
    } else {
        mapped.to_owned()
    }
}

/// `GateResult` — the outcome of running an entry's validation gate.
#[derive(Debug, Clone, Default)]
pub struct GateResult {
    pub verb: String,
    pub pass: bool,
    pub detail: String,
}

/// `GateProbe` — the named host-probe seam `run_gate` consults for
/// `version-present` entries: observes installed host-tool versions
/// by entry name.
pub type GateProbe<'a> = Option<&'a dyn Fn(&str) -> Result<String, Failure>>;
/// `ImageExistsProbe` — the seam `digest-present` entries consult:
/// answers whether an image digest is resolvable on this host.
/// Both seams are adapter-provided; a `None` seam refuses loudly
/// rather than weakening to a no-op.
pub type ImageExistsProbe<'a> = Option<&'a dyn Fn(&str) -> Result<bool, Failure>>;

/// `RunGate` — evaluates the matrix-declared gate for an attempt.
/// Gates never guess: a missing probe or an unrecognized verb fails
/// loudly rather than weakening to a no-op.
pub fn run_gate(
    e: &Entry,
    a: &Attempt,
    probe: GateProbe<'_>,
    image_exists: ImageExistsProbe<'_>,
) -> GateResult {
    let verb = gate_verb_owned(e);
    match verb.as_str() {
        GATE_VERSION_PRESENT => {
            let Some(probe) = probe else {
                return GateResult {
                    verb,
                    detail: "no probe installed".to_owned(),
                    ..GateResult::default()
                };
            };
            let got = match probe(&e.name) {
                Ok(v) if !v.is_empty() => v,
                _ => {
                    return GateResult {
                        verb,
                        detail: format!("probe {:?} unavailable", e.name),
                        ..GateResult::default()
                    };
                }
            };
            let got = got.trim();
            if normalize_version(got) != normalize_version(&a.to) {
                return GateResult {
                    verb,
                    detail: format!("observed {:?}, want {:?}", got, a.to),
                    ..GateResult::default()
                };
            }
            GateResult {
                verb,
                pass: true,
                ..GateResult::default()
            }
        }
        GATE_DIGEST_PRESENT => {
            if !allowed_digests(e).contains(&a.to) {
                return GateResult {
                    verb,
                    detail: "digest outside the allowlist".to_owned(),
                    ..GateResult::default()
                };
            }
            let Some(image_exists) = image_exists else {
                return GateResult {
                    verb,
                    detail: "no image probe installed".to_owned(),
                    ..GateResult::default()
                };
            };
            match image_exists(&a.to) {
                Err(_) => GateResult {
                    verb,
                    detail: "image probe unavailable".to_owned(),
                    ..GateResult::default()
                },
                Ok(false) => GateResult {
                    verb,
                    detail: format!("digest {} not resolvable on this host", a.to),
                    ..GateResult::default()
                },
                Ok(true) => GateResult {
                    verb,
                    pass: true,
                    ..GateResult::default()
                },
            }
        }
        GATE_MODULES_VERIF => {
            // The vendored cohort cannot be re-pinned at runtime —
            // module-set transitions ride repo releases, so the gate
            // refuses loudly.
            GateResult {
                verb,
                detail: "module cohort transitions ride repo releases".to_owned(),
                ..GateResult::default()
            }
        }
        _ => GateResult {
            verb,
            detail: "gate verb not implemented".to_owned(),
            ..GateResult::default()
        },
    }
}

// ---------------------------------------------------------------------------
// Store (store.go) — the protected-root matrix file plus the signed
// append-only transition journal.
// ---------------------------------------------------------------------------

/// `transition` — the append-only journal record: the A05 payload
/// shape, hash-chained and HMAC-signed with the instance-local
/// root-only key. Field order is upstream's for the row encoding.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct TransitionRow {
    schema_version: String,
    operation: String,
    sequence_num: u64,
    matrix_digest: String,
    prior_digest: String,
    hmac: String,
    signed_at: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    attempt_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    dependency: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    from: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    to: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    gate: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    gate_result: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    failure_reason: String,
}

/// `Attempt` — one patch try: the dependency, the from→to transition,
/// and the validation gate the matrix row names.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attempt {
    pub attempt_id: String,
    pub dependency: String,
    pub from: String,
    pub to: String,
    pub gate: String,
    pub started_at: String,
}

/// `Store` — the protected-root maintenance store.
pub struct Store {
    dir: PathBuf,
}

/// `NewStore` — binds the store to an instance protected root.
pub fn new_store(dir: impl Into<PathBuf>) -> Store {
    Store { dir: dir.into() }
}

impl Store {
    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// `LoadOrBootstrap` — the current matrix, initialized to the
    /// baseline (and minting the journal key) on first use. The
    /// second return is true when this call performed the
    /// initialization.
    pub fn load_or_bootstrap(&self) -> Result<(Matrix, bool), Failure> {
        let path = self.path(MATRIX_FILE_NAME);
        let raw = match std::fs::read(&path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return self.bootstrap();
            }
            Err(e) => {
                return Err(internal(format!("maintenance: read matrix: {e}")));
            }
        };
        let m = parse_matrix(&raw)?;
        let last = self.last_transition()?;
        let digest = canonical_digest(&m)?;
        match last {
            Some(last) if last.matrix_digest == digest => Ok((m, false)),
            _ => Err(Failure::internal(
                MATRIX_TAMPERED_CODE,
                "maintenance: matrix digest does not match the latest journaled transition",
            )),
        }
    }

    /// `bootstrap` — writes the baseline matrix, mints the HMAC key,
    /// and journals `matrix_initialized` as sequence 1.
    fn bootstrap(&self) -> Result<(Matrix, bool), Failure> {
        let m = baseline_matrix();
        self.key()?;
        self.commit(&m, OP_MATRIX_INIT)?;
        Ok((m, true))
    }

    /// `CommitUpdate` — writes a new matrix revision and journals it.
    /// Sequence must be prior+1.
    pub fn commit_update(&self, m: &Matrix) -> Result<(), Failure> {
        let last = self.last_transition()?;
        let Some(last) = last else {
            return Err(internal("maintenance: no initialized matrix to update"));
        };
        if m.sequence_num != last.sequence_num + 1 {
            return Err(internal(format!(
                "maintenance: update sequence {}, expected {}",
                m.sequence_num,
                last.sequence_num + 1
            )));
        }
        self.commit(m, OP_MATRIX_UPDATE)
    }

    /// `commit` — writes the matrix file and appends the signed
    /// transition.
    fn commit(&self, m: &Matrix, op: &str) -> Result<(), Failure> {
        let canonical = m.canonical()?;
        let tmp = self.path(&format!("{MATRIX_FILE_NAME}.tmp"));
        write_file_mode(&tmp, &canonical, 0o600)
            .map_err(|e| internal(format!("maintenance: write matrix: {e}")))?;
        std::fs::rename(&tmp, self.path(MATRIX_FILE_NAME))
            .map_err(|e| internal(format!("maintenance: rename matrix: {e}")))?;
        let key = self.key()?;
        let last = self.last_transition()?;
        let prior = last.as_ref().map(|l| l.hmac.clone()).unwrap_or_default();
        let digest = format!(
            "sha256:{}",
            crate::authority::wire::hex_encode(&Sha256::digest(&canonical))
        );
        let mut tr = TransitionRow {
            schema_version: TRANSITION_SCHEMA.to_owned(),
            operation: op.to_owned(),
            sequence_num: m.sequence_num,
            matrix_digest: digest,
            prior_digest: prior,
            signed_at: crate::authority::wire::format_rfc3339_nano(OffsetDateTime::now_utc()),
            ..TransitionRow::default()
        };
        tr.hmac = sign_transition(&key, &tr);
        self.append_row(&tr)
    }

    /// `appendRow` — one signed transition row to the journal.
    fn append_row(&self, tr: &TransitionRow) -> Result<(), Failure> {
        let mut line = serde_json::to_vec(tr).map_err(|e| internal(e.to_string()))?;
        line.push(b'\n');
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(self.path(JOURNAL_FILE_NAME))
            .map_err(|e| internal(format!("maintenance: open journal: {e}")))?;
        use std::io::Write;
        f.write_all(&line)
            .map_err(|e| internal(format!("maintenance: append journal: {e}")))
    }

    /// `AppendAttempt` — journals a patch/rollback attempt row.
    /// Attempt rows echo the current matrix digest and sequence — they
    /// record authority over an attempt, not a matrix change.
    pub fn append_attempt(
        &self,
        op: &str,
        a: &Attempt,
        gate_result: &str,
        failure_reason: &str,
    ) -> Result<(), Failure> {
        match op {
            OP_PATCH_PENDING
            | OP_PATCH_APPLIED
            | OP_PATCH_FAILED
            | OP_PATCH_ABANDONED
            | OP_ROLLBACK_PENDING
            | OP_ROLLBACK_APPLIED
            | OP_ROLLBACK_FAILED
            | OP_ROLLBACK_ABANDONED => {}
            _ => {
                return Err(internal(format!(
                    "maintenance: attempt operation {op:?} unknown"
                )));
            }
        }
        if a.attempt_id.is_empty() || a.dependency.is_empty() || a.to.is_empty() {
            return Err(internal("maintenance: attempt is incomplete"));
        }
        let key = self.key()?;
        let Some(last) = self.last_transition()? else {
            return Err(internal(
                "maintenance: no initialized matrix to journal against",
            ));
        };
        let mut tr = TransitionRow {
            schema_version: TRANSITION_SCHEMA.to_owned(),
            operation: op.to_owned(),
            sequence_num: last.sequence_num,
            matrix_digest: last.matrix_digest.clone(),
            prior_digest: last.hmac.clone(),
            signed_at: crate::authority::wire::format_rfc3339_nano(OffsetDateTime::now_utc()),
            attempt_id: a.attempt_id.clone(),
            dependency: a.dependency.clone(),
            from: a.from.clone(),
            to: a.to.clone(),
            gate: a.gate.clone(),
            gate_result: gate_result.to_owned(),
            failure_reason: failure_reason.to_owned(),
            ..TransitionRow::default()
        };
        tr.hmac = sign_transition(&key, &tr);
        self.append_row(&tr)
    }

    /// `PendingAttempt` — the latest pending row (patch or rollback)
    /// with no direction-matched closing row for the same attempt id.
    pub fn pending_attempt(&self) -> Result<Option<(Attempt, String)>, Failure> {
        let rows = self.transitions()?;
        let mut closed: std::collections::BTreeSet<(String, String)> =
            std::collections::BTreeSet::new();
        let mut pending: BTreeMap<(String, String), Attempt> = BTreeMap::new();
        let mut order: Vec<(String, String)> = Vec::new();
        for r in &rows {
            let dir = attempt_direction(&r.operation).to_owned();
            if attempt_is_pending(&r.operation) {
                let k = (r.attempt_id.clone(), dir);
                pending.insert(
                    k.clone(),
                    Attempt {
                        attempt_id: r.attempt_id.clone(),
                        dependency: r.dependency.clone(),
                        from: r.from.clone(),
                        to: r.to.clone(),
                        gate: r.gate.clone(),
                        started_at: r.signed_at.clone(),
                    },
                );
                order.push(k);
            } else if attempt_closes(&r.operation) {
                closed.insert((r.attempt_id.clone(), dir));
            }
        }
        for k in order.iter().rev() {
            if !closed.contains(k) {
                return Ok(pending.get(k).cloned().map(|a| (a, k.1.clone())));
            }
        }
        Ok(None)
    }

    /// `FindAttempt` — the journaled attempt by id: the identity check
    /// resume/rollback/abandon perform. The status is the latest
    /// operation recorded for that id; the `Attempt` carries the
    /// latest pending row's fields (or the original patch row's when
    /// nothing pending remains).
    pub fn find_attempt(&self, id: &str) -> Result<(Option<Attempt>, String), Failure> {
        let rows = self.transitions()?;
        let mut found: Option<Attempt> = None;
        let mut status = String::new();
        for r in &rows {
            if r.attempt_id != id {
                continue;
            }
            if attempt_is_pending(&r.operation) {
                found = Some(Attempt {
                    attempt_id: r.attempt_id.clone(),
                    dependency: r.dependency.clone(),
                    from: r.from.clone(),
                    to: r.to.clone(),
                    gate: r.gate.clone(),
                    started_at: r.signed_at.clone(),
                });
            }
            status = r.operation.clone();
        }
        if status.is_empty() {
            return Ok((None, String::new()));
        }
        if found.is_none() {
            // No pending row — reconstruct the identity from the last
            // row so callers can still name the dependency/target.
            for r in rows.iter().rev() {
                if r.attempt_id == id {
                    found = Some(Attempt {
                        attempt_id: r.attempt_id.clone(),
                        dependency: r.dependency.clone(),
                        from: r.from.clone(),
                        to: r.to.clone(),
                        gate: r.gate.clone(),
                        started_at: r.signed_at.clone(),
                    });
                    break;
                }
            }
        }
        Ok((found, status))
    }

    /// `key` — loads or mints the root-only journal HMAC key.
    fn key(&self) -> Result<[u8; 32], Failure> {
        let path = self.path(KEY_FILE_NAME);
        match std::fs::read(&path) {
            Ok(raw) if raw.len() == 32 => {
                let mut key = [0u8; 32];
                key.copy_from_slice(&raw);
                Ok(key)
            }
            Ok(raw) => Err(internal(format!(
                "maintenance: journal key corrupt ({} bytes)",
                raw.len()
            ))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // `crypto/rand.Read` — two v4 UUIDs carry the same OS
                // CSPRNG source.
                let mut key = [0u8; 32];
                key[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
                key[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
                write_file_mode(&path, &key, 0o600)
                    .map_err(|e| internal(format!("maintenance: write journal key: {e}")))?;
                Ok(key)
            }
            Err(e) => Err(internal(format!("maintenance: read journal key: {e}"))),
        }
    }

    /// `transitions` — every journal row, each HMAC verified: a forged
    /// or rewritten line fails closed.
    fn transitions(&self) -> Result<Vec<TransitionRow>, Failure> {
        let raw = match std::fs::read(self.path(JOURNAL_FILE_NAME)) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(internal(format!("maintenance: read journal: {e}"))),
        };
        let key = self.key()?;
        let mut out = Vec::new();
        // Only `\n`-terminated records are consumed — a crash-torn
        // trailing append is ignored upstream-fashion; the latest
        // complete row wins.
        for line in raw.split_inclusive(|b| *b == b'\n') {
            let Some(line) = line.strip_suffix(b"\n") else {
                continue;
            };
            if line.is_empty() {
                continue;
            }
            // Go's `json.Unmarshal` tolerates unknown fields — serde's
            // default (no deny_unknown_fields) matches.
            let tr: TransitionRow = serde_json::from_slice(line)
                .map_err(|e| internal(format!("maintenance: corrupt journal line: {e}")))?;
            if tr.schema_version != TRANSITION_SCHEMA {
                return Err(internal(format!(
                    "maintenance: journal schema {:?} unsupported",
                    tr.schema_version
                )));
            }
            if tr.hmac != sign_transition(&key, &tr) {
                return Err(internal(
                    "maintenance: journal transition fails HMAC (tampered)",
                ));
            }
            out.push(tr);
        }
        Ok(out)
    }

    /// `lastTransition` — the journal tail; a line rewritten without
    /// the key is refused by `transitions` before this returns.
    fn last_transition(&self) -> Result<Option<TransitionRow>, Failure> {
        Ok(self.transitions()?.into_iter().last())
    }
}

/// `signTransition` — the pipe-joined fields HMAC-SHA256, exactly
/// upstream's `fmt.Fprintf` sequence: attempt fields join only when
/// `attempt_id` is set.
fn sign_transition(key: &[u8; 32], tr: &TransitionRow) -> String {
    let mut msg = format!(
        "{}|{}|{}|{}|{}|{}",
        tr.schema_version,
        tr.operation,
        tr.sequence_num,
        tr.matrix_digest,
        tr.prior_digest,
        tr.signed_at
    );
    if !tr.attempt_id.is_empty() {
        msg.push_str(&format!(
            "|{}|{}|{}|{}|{}|{}|{}",
            tr.attempt_id,
            tr.dependency,
            tr.from,
            tr.to,
            tr.gate,
            tr.gate_result,
            tr.failure_reason
        ));
    }
    format!(
        "hmac-sha256:{}",
        crate::authority::wire::hex_encode(&crate::authority::wire::hmac_sha256(
            key,
            msg.as_bytes()
        ))
    )
}

/// `attemptDirection` — the eight attempt operations classified into
/// patch and rollback flows. Closing is direction-scoped: a patch
/// terminal row never closes a rollback pending row and vice versa.
fn attempt_direction(op: &str) -> &str {
    if op.starts_with("rollback") {
        "rollback"
    } else if op.starts_with("patch") {
        "patch"
    } else {
        ""
    }
}

fn attempt_is_pending(op: &str) -> bool {
    op == OP_PATCH_PENDING || op == OP_ROLLBACK_PENDING
}

fn attempt_closes(op: &str) -> bool {
    matches!(
        op,
        OP_PATCH_APPLIED
            | OP_PATCH_FAILED
            | OP_PATCH_ABANDONED
            | OP_ROLLBACK_APPLIED
            | OP_ROLLBACK_FAILED
            | OP_ROLLBACK_ABANDONED
    )
}

/// `os.WriteFile(path, body, mode)` — mode applies at creation, the
/// upstream semantics.
fn write_file_mode(path: &Path, body: &[u8], mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)?;
    use std::io::Write;
    f.write_all(body)
}

// ---------------------------------------------------------------------------
// Evidence (evidence.go)
// ---------------------------------------------------------------------------

/// `Evidence` — the `slice-e-compatibility-matrix.json` artifact body:
/// verdicts and identities only, never secrets or file contents.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Evidence {
    pub schema_version: String,
    pub matrix_digest: String,
    pub sequence_num: u64,
    pub initialized: bool,
    pub dependencies: Vec<Observed>,
    pub verdict: String,
    pub completed_at: String,
}

/// `NewEvidence` — builds the evidence body from a digest, sequence,
/// and plan. The CLI composes this from the helper's wire result — it
/// never touches the protected store.
pub fn new_evidence(
    digest: &str,
    sequence_num: u64,
    dependencies: Vec<Observed>,
    initialized: bool,
) -> Evidence {
    let mut verdict = "pass".to_owned();
    for d in &dependencies {
        if !d.observed.is_empty() && !d.matches {
            verdict = "diverged".to_owned();
        }
    }
    Evidence {
        schema_version: EVIDENCE_SCHEMA.to_owned(),
        matrix_digest: digest.to_owned(),
        sequence_num,
        initialized,
        dependencies,
        verdict,
        completed_at: crate::authority::wire::format_rfc3339_nano(OffsetDateTime::now_utc()),
    }
}

/// `WriteEvidenceFile` — an already-built `Evidence` into `dir`.
pub fn write_evidence_file(dir: &Path, ev: &Evidence) -> Result<(), Failure> {
    let mut raw = serde_json::to_vec_pretty(ev).map_err(|e| internal(e.to_string()))?;
    raw.push(b'\n');
    write_file_mode(&dir.join(EVIDENCE_FILE_NAME), &raw, 0o644)
        .map_err(|e| internal(format!("maintenance: write evidence: {e}")))
}

/// `ApplyEvidence` — the `slice-e-patch-apply.json` body: the attempt
/// identity, transition, gate verdict, and resulting matrix identity.
/// Refusals carry `reason` instead of a matrix mutation.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ApplyEvidence {
    pub schema_version: String,
    pub operation_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub mode: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub attempt_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub dependency: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub from: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub to: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub gate: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub gate_detail: String,
    pub verdict: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub reason: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub matrix_digest: String,
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub sequence_num: u64,
    pub completed_at: String,
}

fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

/// `WriteApplyEvidenceFile` — the apply evidence artifact into `dir`.
/// `schema_version`/`completed_at` fill in when absent, exactly as
/// upstream's writer does.
pub fn write_apply_evidence_file(dir: &Path, ev: &ApplyEvidence) -> Result<(), Failure> {
    let mut ev = ev.clone();
    if ev.schema_version.is_empty() {
        ev.schema_version = APPLY_EVIDENCE_SCHEMA.to_owned();
    }
    if ev.completed_at.is_empty() {
        ev.completed_at = crate::authority::wire::format_rfc3339_nano(OffsetDateTime::now_utc());
    }
    let mut raw = serde_json::to_vec_pretty(&ev).map_err(|e| internal(e.to_string()))?;
    raw.push(b'\n');
    write_file_mode(&dir.join(APPLY_EVIDENCE_FILE_NAME), &raw, 0o644)
        .map_err(|e| internal(format!("maintenance: write apply evidence: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("central-maint-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn baseline_validates_and_digests() {
        let m = baseline_matrix();
        validate_matrix(&m).unwrap();
        let d = m.digest().unwrap();
        assert!(d.starts_with("sha256:"), "{d}");
        assert_eq!(d.len(), "sha256:".len() + 64);
    }

    #[test]
    fn parse_matrix_rejects_unknown_fields_and_bad_rows() {
        let canonical = baseline_matrix().canonical().unwrap();
        parse_matrix(&canonical).unwrap();
        let mut bad: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
        bad["extra"] = serde_json::json!(1);
        assert!(parse_matrix(bad.to_string().as_bytes()).is_err());
        for (schema, seq, name, kind, current, path, gate) in [
            ("bogus", 1u64, "a", KIND_HOST_TOOL, "1", PATH_DIRECT, "g"),
            (
                MATRIX_SCHEMA_VERSION,
                0,
                "a",
                KIND_HOST_TOOL,
                "1",
                PATH_DIRECT,
                "g",
            ),
            (
                MATRIX_SCHEMA_VERSION,
                1,
                "",
                KIND_HOST_TOOL,
                "1",
                PATH_DIRECT,
                "g",
            ),
            (
                MATRIX_SCHEMA_VERSION,
                1,
                "a",
                "bogus-kind",
                "1",
                PATH_DIRECT,
                "g",
            ),
            (
                MATRIX_SCHEMA_VERSION,
                1,
                "a",
                KIND_HOST_TOOL,
                "",
                PATH_DIRECT,
                "g",
            ),
            (
                MATRIX_SCHEMA_VERSION,
                1,
                "a",
                KIND_HOST_TOOL,
                "1",
                "bogus-path",
                "g",
            ),
            (
                MATRIX_SCHEMA_VERSION,
                1,
                "a",
                KIND_HOST_TOOL,
                "1",
                PATH_DIRECT,
                "",
            ),
        ] {
            let m = Matrix {
                schema_version: schema.to_owned(),
                sequence_num: seq,
                entries: vec![Entry {
                    name: name.to_owned(),
                    kind: kind.to_owned(),
                    current: current.to_owned(),
                    min: String::new(),
                    max: String::new(),
                    path: path.to_owned(),
                    gate: gate.to_owned(),
                }],
            };
            assert!(validate_matrix(&m).is_err(), "{schema} {seq} {name} {kind}");
        }
    }

    /// `compareVersion` — the upstream notation table: numeric
    /// components, trailing `x` wildcard bound, literal fallback.
    #[test]
    fn compare_version_table() {
        for (a, b, want) in [
            ("16.14", "16.x", 0),
            ("16.0", "16.x", 0),
            ("16.14", "16.14", 0),
            ("16.14", "16.15", -1),
            ("16.15", "16.14", 1),
            ("16.14", "17.x", -1),
            ("29.3", "29.x", 0),
            ("30.0", "29.x", 1),
            ("1.26.6", "1.26.x", 0),
            ("1.27.0", "1.26.x", 1),
            ("16", "16.0.0", 0),
            ("16.0.1", "16.0", 1),
        ] {
            assert_eq!(compare_version(a, b), want, "{a} vs {b}");
        }
    }

    /// `versionInRange` — upstream's range table: min floors named
    /// components, `x` opens the bound, normalization strips go/v.
    #[test]
    fn version_in_range_table() {
        for (v, min, max, want) in [
            ("16.14", "16.14", "16.x", true),
            ("go1.26.6", "1.26.6", "1.26.x", true),
            ("1.26.5", "1.26.6", "1.26.x", false),
            ("1.27.0", "1.26.6", "1.26.x", false),
            ("v16.14", "16.14", "16.x", true),
            ("25.0", "25.0", "29.x", true),
            ("24.9", "25.0", "29.x", false),
            ("30.0", "25.0", "29.x", false),
            ("2.0", "2.0", "5.x", true),
            ("", "1", "2", false),
            ("1.26.6", "", "", true),
        ] {
            assert_eq!(version_in_range(v, min, max), want, "{v} in [{min}..{max}]");
        }
    }

    #[test]
    fn evaluate_lists_and_refuses() {
        let m = baseline_matrix();
        // Unknown dependency → unlisted with no entry.
        let v = evaluate(
            &m,
            &Transition {
                name: "bogus",
                to: "1",
            },
        );
        assert!(!v.allowed && v.reason == REASON_UNLISTED && v.entry.is_none());
        // Out-of-range version → unlisted with the governing entry.
        let v = evaluate(
            &m,
            &Transition {
                name: "postgresql",
                to: "17.0",
            },
        );
        assert!(!v.allowed && v.reason == REASON_UNLISTED && v.entry.is_some());
        // In-range host tool → allowed.
        let v = evaluate(
            &m,
            &Transition {
                name: "postgresql",
                to: "16.15",
            },
        );
        assert!(v.allowed && v.reason.is_empty());
        // Empty target → unlisted.
        let v = evaluate(
            &m,
            &Transition {
                name: "postgresql",
                to: "",
            },
        );
        assert!(!v.allowed);
        // Allowlisted image digest → allowed; unlisted digest → refused.
        let e = m.entry_by_name("minio-image").unwrap();
        let digest = allowed_digests(&e).pop().unwrap();
        let v = evaluate(
            &m,
            &Transition {
                name: "minio-image",
                to: &digest,
            },
        );
        assert!(v.allowed);
        let v = evaluate(
            &m,
            &Transition {
                name: "minio-image",
                to: "sha256:0f",
            },
        );
        assert!(!v.allowed);
        // Modules cohort: a changed target admits, the current refuses.
        let v = evaluate(
            &m,
            &Transition {
                name: "go-modules",
                to: "sha256:new",
            },
        );
        assert!(v.allowed);
        let v = evaluate(
            &m,
            &Transition {
                name: "go-modules",
                to: "vendored",
            },
        );
        assert!(!v.allowed);
    }

    #[test]
    fn evaluate_current_reports_unprobed_and_divergence() {
        let m = baseline_matrix();
        let mut observed = BTreeMap::new();
        observed.insert("postgresql".to_owned(), "16.14".to_owned());
        observed.insert("docker-engine".to_owned(), "31.0".to_owned());
        let plan = evaluate_current(&m, &observed);
        assert_eq!(plan.dependencies.len(), m.entries.len());
        let by = |n: &str| {
            plan.dependencies
                .iter()
                .find(|o| o.entry.name == n)
                .unwrap()
        };
        assert!(by("postgresql").matches && by("postgresql").detail.is_empty());
        assert!(
            !by("docker-engine").matches && by("docker-engine").detail.contains("outside matrix")
        );
        assert_eq!(by("go-toolchain").detail, "unprobed");
        // Image pins compare Current exactly.
        assert_eq!(by("minio-image").detail, "unprobed");
    }

    #[test]
    fn run_gate_verbs() {
        let m = baseline_matrix();
        let entry = |n: &str| m.entry_by_name(n).unwrap();
        let attempt = |to: &str| Attempt {
            attempt_id: "a1".to_owned(),
            dependency: "postgresql".to_owned(),
            to: to.to_owned(),
            ..Attempt::default()
        };
        // version-present: probe must observe the target.
        let probe = |name: &str| -> Result<String, Failure> {
            if name == "postgresql" {
                Ok("16.15".to_owned())
            } else {
                Err(internal("no probe"))
            }
        };
        let g = run_gate(&entry("postgresql"), &attempt("16.15"), Some(&probe), None);
        assert!(g.pass && g.verb == GATE_VERSION_PRESENT);
        let g = run_gate(&entry("postgresql"), &attempt("16.99"), Some(&probe), None);
        assert!(!g.pass && g.detail.contains("observed"));
        let g = run_gate(&entry("postgresql"), &attempt("16.15"), None, None);
        assert!(!g.pass && g.detail == "no probe installed");
        // digest-present: allowlist + resolvable.
        let img = |_: &str| -> Result<bool, Failure> { Ok(true) };
        let digest = allowed_digests(&entry("minio-image")).pop().unwrap();
        let a = Attempt {
            attempt_id: "a1".to_owned(),
            dependency: "minio-image".to_owned(),
            to: digest.clone(),
            ..Attempt::default()
        };
        let g = run_gate(&entry("minio-image"), &a, None, Some(&img));
        assert!(g.pass && g.verb == GATE_DIGEST_PRESENT);
        let g = run_gate(&entry("minio-image"), &a, None, None);
        assert!(!g.pass && g.detail == "no image probe installed");
        let a2 = Attempt {
            to: "sha256:0f".to_owned(),
            ..a.clone()
        };
        let g = run_gate(&entry("minio-image"), &a2, None, Some(&img));
        assert!(!g.pass && g.detail == "digest outside the allowlist");
        // modules cohort refuses loudly; unknown gate names itself.
        let g = run_gate(&entry("go-modules"), &a, None, None);
        assert!(!g.pass && g.detail.contains("repo releases"));
        let e = Entry {
            gate: "bogus-gate".to_owned(),
            ..entry("postgresql")
        };
        let g = run_gate(&e, &a, None, None);
        assert!(!g.pass && g.verb == "bogus-gate" && g.detail == "gate verb not implemented");
    }

    /// `Store` — bootstrap, tamper detection, attempt lifecycle, and
    /// the HMAC chain's closed failure on a rewritten row.
    #[test]
    fn store_bootstrap_tamper_and_attempts() {
        let dir = temp_dir("store");
        let store = new_store(dir.clone());
        let (m, initialized) = store.load_or_bootstrap().unwrap();
        assert!(initialized && m.sequence_num == 1);
        // Second load is not an initialization.
        let (m2, init2) = store.load_or_bootstrap().unwrap();
        assert!(!init2 && m2.sequence_num == 1);
        // Tampered matrix digest fails closed.
        let mut bad = m.clone();
        bad.entries[0].current = "tampered".to_owned();
        write_file_mode(
            &dir.join(MATRIX_FILE_NAME),
            &bad.canonical().unwrap(),
            0o600,
        )
        .unwrap();
        let err = store.load_or_bootstrap().unwrap_err();
        assert_eq!(err.code(), MATRIX_TAMPERED_CODE);
        // Restore by recommitting the real matrix's bytes.
        write_file_mode(&dir.join(MATRIX_FILE_NAME), &m.canonical().unwrap(), 0o600).unwrap();
        store.load_or_bootstrap().unwrap();
        // Rewritten journal HMAC fails closed.
        let journal = dir.join(JOURNAL_FILE_NAME);
        let raw = std::fs::read(&journal).unwrap();
        let mut rows: Vec<serde_json::Value> = raw
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_slice(l).unwrap())
            .collect();
        rows[0]["signed_at"] = serde_json::json!("2020-01-01T00:00:00Z");
        let forged: String = rows
            .iter()
            .map(|r| serde_json::to_string(r).unwrap() + "\n")
            .collect();
        std::fs::write(&journal, forged).unwrap();
        assert!(store.load_or_bootstrap().is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// `Store` attempt rows: pending detection is direction-scoped,
    /// `find_attempt` reconstructs identity from closed rows, and a
    /// sequence-skipping commit refuses.
    #[test]
    fn store_attempt_lifecycle() {
        let dir = temp_dir("attempts");
        let store = new_store(dir.clone());
        let (mut m, _) = store.load_or_bootstrap().unwrap();
        let attempt = Attempt {
            attempt_id: "att-1".to_owned(),
            dependency: "postgresql".to_owned(),
            from: "16.14".to_owned(),
            to: "16.15".to_owned(),
            gate: "migration-replay+pg-dump-restore".to_owned(),
            started_at: String::new(),
        };
        assert!(store.pending_attempt().unwrap().is_none());
        store
            .append_attempt(OP_PATCH_PENDING, &attempt, "", "")
            .unwrap();
        let (pending, dir_name) = store.pending_attempt().unwrap().unwrap();
        assert!(pending.attempt_id == "att-1" && dir_name == "patch");
        let (found, status) = store.find_attempt("att-1").unwrap();
        assert_eq!(found.unwrap().to, "16.15");
        assert_eq!(status, OP_PATCH_PENDING);
        // Committing the matrix and closing the attempt leaves none
        // pending.
        for e in &mut m.entries {
            if e.name == "postgresql" {
                e.current = "16.15".to_owned();
            }
        }
        m.sequence_num += 1;
        store.commit_update(&m).unwrap();
        store
            .append_attempt(OP_PATCH_APPLIED, &attempt, GATE_VERSION_PRESENT, "")
            .unwrap();
        assert!(store.pending_attempt().unwrap().is_none());
        let (found, status) = store.find_attempt("att-1").unwrap();
        assert_eq!(status, OP_PATCH_APPLIED);
        assert_eq!(found.unwrap().attempt_id, "att-1");
        // An unknown id reports nothing.
        let (found, status) = store.find_attempt("nope").unwrap();
        assert!(found.is_none() && status.is_empty());
        // A sequence-skipping commit refuses.
        let mut skip = m.clone();
        skip.sequence_num = 99;
        assert!(store.commit_update(&skip).is_err());
        // Incomplete attempts and unknown ops refuse.
        assert!(
            store
                .append_attempt(OP_PATCH_PENDING, &Attempt::default(), "", "")
                .is_err()
        );
        assert!(store.append_attempt("bogus_op", &attempt, "", "").is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// `pending_attempt` — a rollback terminal row never closes a
    /// patch pending row for the same id (direction-scoped closing).
    #[test]
    fn pending_attempt_direction_scope() {
        let dir = temp_dir("dirs");
        let store = new_store(dir.clone());
        store.load_or_bootstrap().unwrap();
        let a = Attempt {
            attempt_id: "att-9".to_owned(),
            dependency: "postgresql".to_owned(),
            from: "16.14".to_owned(),
            to: "16.15".to_owned(),
            gate: "g".to_owned(),
            started_at: String::new(),
        };
        store.append_attempt(OP_PATCH_PENDING, &a, "", "").unwrap();
        // A rollback close of the same id leaves the patch pending.
        store
            .append_attempt(OP_ROLLBACK_ABANDONED, &a, "", "")
            .unwrap();
        let (pending, dir_name) = store.pending_attempt().unwrap().unwrap();
        assert!(pending.attempt_id == "att-9" && dir_name == "patch");
        store
            .append_attempt(OP_PATCH_ABANDONED, &a, "", "")
            .unwrap();
        assert!(store.pending_attempt().unwrap().is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// `NewEvidence` — the verdict diverges only on a probed mismatch.
    #[test]
    fn evidence_verdict_rule() {
        let ev = new_evidence("sha256:d", 2, Vec::new(), true);
        assert!(ev.verdict == "pass" && ev.initialized);
        let diverged = Observed {
            observed: "9".to_owned(),
            matches: false,
            ..Observed::default()
        };
        let ev = new_evidence("sha256:d", 2, vec![diverged], false);
        assert_eq!(ev.verdict, "diverged");
        // Unprobed (empty observed) mismatches never diverge.
        let unprobed = Observed::default();
        let ev = new_evidence("sha256:d", 2, vec![unprobed], false);
        assert_eq!(ev.verdict, "pass");
    }
}
