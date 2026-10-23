//! Reconstruction fold and divergence detection — pure port of
//! `central/internal/eventjournal/fold.go` (spec-6 decision 4, dossier
//! P2A05). [`fold`] replays a run's journaled events in `(run_id, seq)`
//! order and derives node state, attempt history, graph shape, and
//! artifact references. The output is a read-only projection: where it
//! disagrees with materialized `workflow_nodes` rows, [`compare_fold`]
//! reports `RECONSTRUCTION_DIVERGED` and nothing is silently rewritten
//! — folded evidence never steers a live harness loop (ADR 0035).
//!
//! OWNING PACKET: P2A05. SLICE: 2A.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde::{Deserialize, Deserializer, Serialize};

use central_foundation::identity::{ArtifactId, RunId, SessionAttemptId, WorkflowNodeId};

use crate::domain::{EventKind, ReasonCode, RunEvent, known};

// ---------------------------------------------------------------------------
// Payload contracts the fold consumes
// ---------------------------------------------------------------------------

/// The highest `payload_version` the fold knows for
/// [`EventKind::NodeDeclared`] (spec-6 OQ-5). Absent (`0`) or equal
/// folds; anything higher is undeclared and fails as
/// `INVALID_EVENT_PAYLOAD`.
const NODE_DECLARED_PAYLOAD_VERSION: i64 = 1;

/// The `(artifact_id, checksum)` pair every payload uses to reference
/// an artifact — the same wire shape `central-workflow`'s
/// `ArtifactRef` marshals to and the shape the workflow emitter writes
/// into `input_artifact_refs` and `versions.prompt_ref` (the
/// restatement precedent — this crate's DAG cannot import
/// `central-workflow`). Bodies stay in object storage; payloads carry
/// pairs only. The fold also tolerates `id` in place of `artifact_id`
/// when scanning payloads generically, because the versioning record
/// (spec-6 decision 5) names `prompt_ref` an `(id, checksum)` pair.
///
/// `artifact_id` deserializes through the gofrs `uuid.FromString`
/// grammar upstream uses — any UUID version, case, `urn:uuid:` prefix,
/// or braces — because the payload field is foreign-authored text, not
/// a Central-minted identity (strict v7 parsing would diverge from
/// upstream's tolerance into `INVALID_EVENT_PAYLOAD`). Serialization is
/// the canonical lowercase text both sides emit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRef {
    /// The artifact identity; lenient-parsed on decode (see the
    /// type-level note), canonical on encode.
    #[serde(default = "nil_artifact_id", deserialize_with = "lenient_or_nil_uuid")]
    pub artifact_id: ArtifactId,
    /// The checksum the declared read binds.
    #[serde(default, deserialize_with = "null_default")]
    pub checksum: String,
}

/// The payload schema [`EventKind::NodeDeclared`] carries (upstream
/// `NodeDeclaredPayload`). The fold derives node identity (`node_key`),
/// ordering edges (`depends_on`), and declared input refs
/// (`input_artifact_refs`) from it — the contract the workflow-graph
/// emitter writes. The fold validates what it consumes — `node_key` is
/// required, the remaining fields decode leniently and stay journaled
/// verbatim either way.
///
/// Every field accepts `null` on decode, matching Go's
/// `encoding/json` semantics (`null` into a non-pointer field is a
/// no-op leaving the zero value) — upstream never fails a
/// `node_declared` decode over a `null` member.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NodeDeclaredPayload {
    /// The payload schema version (spec-6 OQ-5); `0` = absent.
    #[serde(
        default,
        skip_serializing_if = "is_zero_version",
        deserialize_with = "null_default"
    )]
    pub payload_version: i64,
    /// The node's run-unique key — required by the fold.
    #[serde(default, deserialize_with = "null_default")]
    pub node_key: String,
    /// The `node_key`s this node waits on (`ordering` edges).
    #[serde(default, deserialize_with = "null_default")]
    pub depends_on: Vec<String>,
    /// The launchable harness name.
    #[serde(default, deserialize_with = "null_default")]
    pub harness: String,
    /// The node's workspace kind.
    #[serde(default, deserialize_with = "null_default")]
    pub workspace_kind: String,
    /// The node's absolute graph depth.
    #[serde(default, deserialize_with = "null_default")]
    pub depth: i64,
    /// Declared `(artifact_id, checksum)` input refs (the RTM-14
    /// declared-read edge set).
    #[serde(default, deserialize_with = "null_default")]
    pub input_artifact_refs: Vec<ArtifactRef>,
}

const fn is_zero_version(version: &i64) -> bool {
    *version == 0
}

/// Go `null`-tolerant decode: an absent or explicit-`null` member
/// yields the Rust default, matching `encoding/json`'s null-no-op
/// semantics for non-pointer targets.
fn null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Option::<T>::deserialize(deserializer).map(Option::unwrap_or_default)
}

const fn nil_artifact_id() -> ArtifactId {
    ArtifactId::from_trusted_db_bytes([0; 16])
}

/// `artifact_id` decode: an explicit `null` yields the nil id (gofrs
/// `UnmarshalJSON` leaves `uuid.Nil` on `null`); any other value must
/// parse under the gofrs `uuid.FromString` grammar.
fn lenient_or_nil_uuid<'de, D>(deserializer: D) -> Result<ArtifactId, D::Error>
where
    D: Deserializer<'de>,
{
    let text = Option::<String>::deserialize(deserializer)?;
    let Some(text) = text else {
        return Ok(nil_artifact_id());
    };
    lenient_uuid_bytes(&text)
        .map(ArtifactId::from_trusted_db_bytes)
        .ok_or_else(|| serde::de::Error::custom("invalid UUID in artifact_id"))
}

/// The gofrs `uuid.FromString` grammar upstream scans artifact refs
/// with: an optional case-insensitive `urn:uuid:` prefix, optional
/// `{...}` braces, then either 36-char hyphenated or 32-char
/// unhyphenated hex, case-insensitive. Returns the raw 16 bytes — no
/// version or variant gating (upstream accepts every version).
fn lenient_uuid_bytes(text: &str) -> Option<[u8; 16]> {
    let mut s = text;
    if s.len() >= 9 && s[..9].eq_ignore_ascii_case("urn:uuid:") {
        s = &s[9..];
    }
    if s.len() >= 2 && s.starts_with('{') && s.ends_with('}') {
        s = &s[1..s.len() - 1];
    }
    let compact;
    if s.len() == 36 {
        let hyphen_ok = [8usize, 13, 18, 23]
            .iter()
            .all(|&i| s.as_bytes()[i] == b'-');
        if !hyphen_ok {
            return None;
        }
        compact = s.replace('-', "");
        s = &compact;
    }
    if s.len() != 32 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (i, chunk) in s.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        bytes[i] = ((hi << 4) | lo) as u8;
    }
    Some(bytes)
}

// ---------------------------------------------------------------------------
// Fold output
// ---------------------------------------------------------------------------

/// One node's folded state (upstream `NodeFold`). `state` carries the
/// `workflow_nodes.state` / migration-v33 CHECK vocabulary (`declared`,
/// `ready`, `dispatched`, `running`, `succeeded`, `failed_terminal`,
/// `attempt_ambiguous`, `cancelled`) as plain text so the journal
/// stays independent of `central-workflow` (the DAG forbids the edge).
/// `last_seq` is the seq of the event that set the current state — the
/// evidence pointer a reconciliation reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeFold {
    /// The node's identity — `None` when the `node_declared` that
    /// established the key carried no `node_id` (upstream's zero-UUID
    /// `NodeID`, honestly encoded).
    pub node_id: Option<WorkflowNodeId>,
    /// The folded node state (the `workflow_nodes.state` vocabulary as
    /// text).
    pub state: String,
    /// The seq of the event that set `state`.
    pub last_seq: i64,
}

/// One fold-time anomaly (upstream `Finding`): a spec-6
/// [`ReasonCode`], a human-readable detail, and the seq whose
/// processing surfaced it. Every anomaly is a finding — the fold never
/// silently corrects or interpolates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The spec-6 reason code.
    pub reason_code: ReasonCode,
    /// Human-readable detail — free text, never a wire contract.
    pub detail: String,
    /// The seq whose processing surfaced the finding (`0` when no
    /// event seq applies — e.g. a materialized-only divergence).
    pub seq: i64,
}

/// The reconstructed projection of one run's journal (upstream
/// `FoldedRun`).
///
/// - `nodes` maps `node_key` to the node's folded state.
/// - `attempts` groups every attempt-carrying event by `attempt_id`,
///   each attempt ordered by seq.
/// - `graph` maps `node_key` to the prerequisite `node_key`s its
///   `node_declared` payload named; expansion batches only ever
///   append.
/// - `artifact_refs` maps `node_key` to the union of
///   `(artifact_id, checksum)` pairs that node's events carried.
/// - `findings` lists every anomaly in the order the fold surfaced it.
///
/// `BTreeMap`s give the deterministic iteration upstream's
/// `map[string]` cannot — the only ordering that matters upstream
/// (attempt history per id) is preserved exactly.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FoldedRun {
    /// `node_key` → folded node state.
    pub nodes: BTreeMap<String, NodeFold>,
    /// `attempt_id` → that attempt's events in seq order.
    pub attempts: BTreeMap<SessionAttemptId, Vec<RunEvent>>,
    /// `node_key` → prerequisite `node_key`s.
    pub graph: BTreeMap<String, Vec<String>>,
    /// `node_key` → the union of artifact refs its events carried.
    pub artifact_refs: BTreeMap<String, Vec<ArtifactRef>>,
    /// Every anomaly in surface order.
    pub findings: Vec<Finding>,
}

// ---------------------------------------------------------------------------
// Kind classification
// ---------------------------------------------------------------------------

/// Maps the state-applicable kinds to the node state they fold to —
/// spec-6 decision 4's reconstruction table (upstream
/// `nodeStateForKind`). Attempt-scope kinds not listed here
/// (`attempt_succeeded`, `attempt_failed`, `attempt_retry_scheduled`)
/// never move the node: a failed attempt returns the node to `ready`
/// only through the retry-path `node_ready` the spec table names, and
/// a succeeded attempt leaves the node running until `node_succeeded`
/// commits. `compensation_requested` annotates a terminal node; it
/// moves nothing either. Kinds absent from this table fold to no node
/// state.
fn node_state_for_kind(kind: &str) -> Option<&'static str> {
    let state = match EventKind::parse(kind)? {
        EventKind::NodeDeclared => "declared",
        EventKind::NodeReady => "ready",
        EventKind::NodeDispatched => "dispatched",
        EventKind::AttemptStarted => "running",
        EventKind::AttemptAmbiguous => "attempt_ambiguous",
        EventKind::NodeSucceeded => "succeeded",
        EventKind::NodeFailedTerminal => "failed_terminal",
        EventKind::NodeCancelled => "cancelled",
        _ => return None,
    };
    Some(state)
}

/// Whether the kind is node-scoped by spec-6's envelope ("`node_id`
/// absent only on run-scope kinds") — upstream `requiresNodeID`.
/// `child_spec_rejected` is the declared run-scope kind; the spec
/// 5/7/8 placeholders (`command_deduped`, `artifact_finalized`,
/// `admission_deferred`) are tolerated without node context because
/// their owning specs may scope them to a run.
fn requires_node_id(kind: &str) -> bool {
    matches!(
        EventKind::parse(kind),
        Some(
            EventKind::NodeDeclared
                | EventKind::NodeReady
                | EventKind::NodeDispatched
                | EventKind::AttemptStarted
                | EventKind::AttemptSucceeded
                | EventKind::AttemptFailed
                | EventKind::AttemptAmbiguous
                | EventKind::AttemptRetryScheduled
                | EventKind::NodeSucceeded
                | EventKind::NodeFailedTerminal
                | EventKind::NodeCancelled
                | EventKind::CompensationRequested
        )
    )
}

/// Whether the kind is attempt-scoped: the envelope carries
/// `attempt_id` only on these (upstream `requiresAttemptID`).
/// `attempt_retry_scheduled` is attempt-scoped on the OLD attempt —
/// the one whose retry it schedules — so it belongs here.
fn requires_attempt_id(kind: &str) -> bool {
    matches!(
        EventKind::parse(kind),
        Some(
            EventKind::AttemptStarted
                | EventKind::AttemptSucceeded
                | EventKind::AttemptFailed
                | EventKind::AttemptAmbiguous
                | EventKind::AttemptRetryScheduled
        )
    )
}

/// Whether the kind opens an attempt's context (upstream
/// `establishesAttempt`): the atomic claim allocates the attempt row
/// it journals on `node_dispatched`, and `attempt_started` marks the
/// attempt live. Any other kind arriving for an `attempt_id` the fold
/// has never seen is an orphan.
fn establishes_attempt(kind: &str) -> bool {
    matches!(
        EventKind::parse(kind),
        Some(EventKind::AttemptStarted | EventKind::NodeDispatched)
    )
}

// ---------------------------------------------------------------------------
// Fold
// ---------------------------------------------------------------------------

/// Reconstructs a run's projection from its journaled events (upstream
/// `Fold`). Input may be unordered and may span runs; events are sorted
/// by `(run_id, seq)` and seq-gap detection is per run. Anomalies are
/// [`Finding`]s, never silent corrections: unknown kinds and
/// undecodable payloads are excluded from the fold (stored raw
/// upstream), seq gaps are flagged and the fold continues, and
/// dangling `node_id`/`attempt_id` references are retained and flagged
/// `ORPHAN_EVENT`.
///
/// Upstream `Fold` returns `FoldedRun`, never an error — every
/// integrity failure mode is a finding by design (spec-6: the fold is
/// a projection, not a gate), so there is no `Result` here.
#[must_use]
pub fn fold(events: &[RunEvent]) -> FoldedRun {
    let mut out = FoldedRun::default();

    let mut ordered: Vec<RunEvent> = events.to_vec();
    // `sort_by` is the stable sort — upstream `sort.SliceStable` on
    // (run_id bytes, seq). `RunId`'s `Ord` is the same lexicographic
    // byte order `bytes.Compare` applies.
    ordered.sort_by(|a, b| a.run_id.cmp(&b.run_id).then(a.seq.cmp(&b.seq)));

    let mut node_key_by_id: HashMap<WorkflowNodeId, String> = HashMap::new();
    let mut seen_attempts: HashSet<SessionAttemptId> = HashSet::new();

    let mut gap_run: Option<RunId> = None;
    let mut prev_seq: i64 = 0;
    let mut have_prev = false;

    for ev in &ordered {
        // Per-run seq contiguity. A gap means a journaled write lost
        // its commit or an ingest failed; flag the missing range and
        // fold on (spec-6 EVENT_SEQUENCE_GAP). A leading window —
        // input beginning above seq 1 — is not a gap: the caller may
        // pass a watermark suffix.
        if gap_run != Some(ev.run_id) {
            gap_run = Some(ev.run_id);
            have_prev = false;
        }
        if have_prev && ev.seq > prev_seq.saturating_add(1) {
            let lo = prev_seq.saturating_add(1);
            let hi = ev.seq.saturating_sub(1);
            let detail = if hi > lo {
                format!("run {}: seqs {}..{} absent", ev.run_id, lo, hi)
            } else {
                format!("run {}: seq {} absent", ev.run_id, lo)
            };
            out.findings.push(Finding {
                reason_code: ReasonCode::EventSequenceGap,
                detail,
                seq: ev.seq,
            });
        }
        prev_seq = ev.seq;
        have_prev = true;

        if !known(&ev.kind) {
            out.findings.push(Finding {
                reason_code: ReasonCode::UnknownEventKind,
                detail: format!("kind {:?} is not in the catalog", ev.kind),
                seq: ev.seq,
            });
            continue;
        }

        // The envelope contract: payload is a kind-versioned JSON
        // object. A non-object payload is excluded from the fold
        // entirely and flagged INVALID_EVENT_PAYLOAD. `Null` is the
        // upstream `len(payload) == 0` / `null` case — no refs to
        // collect, nothing to decode.
        let obj: Option<&serde_json::Map<String, serde_json::Value>> = match &ev.payload {
            serde_json::Value::Object(map) => Some(map),
            serde_json::Value::Null => None,
            _ => {
                out.findings.push(Finding {
                    reason_code: ReasonCode::InvalidEventPayload,
                    detail: format!("kind {:?} payload is not a JSON object", ev.kind),
                    seq: ev.seq,
                });
                continue;
            }
        };

        // Resolve node context established by earlier node_declared
        // events. A node_id nothing has declared is an orphan
        // reference.
        let node_key: Option<&String> = ev.node_id.and_then(|id| node_key_by_id.get(&id));

        // Attempt history: every attempt-carrying event groups under
        // its attempt_id in seq order. A non-establishing kind
        // referencing an attempt the fold has never seen is
        // ORPHAN_EVENT — retained in the history and flagged.
        if let Some(aid) = ev.attempt_id {
            if seen_attempts.insert(aid) && !establishes_attempt(&ev.kind) {
                out.findings.push(Finding {
                    reason_code: ReasonCode::OrphanEvent,
                    detail: format!(
                        "kind {:?} references attempt_id {} with no open context",
                        ev.kind, aid
                    ),
                    seq: ev.seq,
                });
            }
            out.attempts.entry(aid).or_default().push(ev.clone());
        } else if requires_attempt_id(&ev.kind) {
            out.findings.push(Finding {
                reason_code: ReasonCode::OrphanEvent,
                detail: format!("attempt-scope kind {:?} carries no attempt_id", ev.kind),
                seq: ev.seq,
            });
        }

        if ev.kind == EventKind::NodeDeclared.as_str() {
            let p: NodeDeclaredPayload =
                match serde_json::from_value::<NodeDeclaredPayload>(ev.payload.clone()) {
                    Ok(p) => p,
                    Err(err) => {
                        out.findings.push(Finding {
                            reason_code: ReasonCode::InvalidEventPayload,
                            detail: format!("node_declared payload failed to decode: {err}"),
                            seq: ev.seq,
                        });
                        continue;
                    }
                };
            if p.payload_version != 0 && p.payload_version != NODE_DECLARED_PAYLOAD_VERSION {
                out.findings.push(Finding {
                    reason_code: ReasonCode::InvalidEventPayload,
                    detail: format!(
                        "node_declared payload_version {} is undeclared",
                        p.payload_version
                    ),
                    seq: ev.seq,
                });
                continue;
            }
            if p.node_key.is_empty() {
                out.findings.push(Finding {
                    reason_code: ReasonCode::InvalidEventPayload,
                    detail: "node_declared payload carries no node_key".to_string(),
                    seq: ev.seq,
                });
                continue;
            }
            let id = match ev.node_id {
                None => {
                    out.findings.push(Finding {
                        reason_code: ReasonCode::OrphanEvent,
                        detail: "node_declared carries no node_id".to_string(),
                        seq: ev.seq,
                    });
                    None
                }
                Some(id) => {
                    node_key_by_id.insert(id, p.node_key.clone());
                    Some(id)
                }
            };
            // Last applicable kind wins: a re-declared node folds to
            // declared even if a later-seen state preceded this event.
            out.nodes.insert(
                p.node_key.clone(),
                NodeFold {
                    node_id: id,
                    state: "declared".to_string(),
                    last_seq: ev.seq,
                },
            );
            let edges = out.graph.entry(p.node_key.clone()).or_default();
            merge_strings(edges, &p.depends_on);
            let mut refs = p.input_artifact_refs.clone();
            if let Some(map) = obj {
                refs.extend(collect_refs(map));
            }
            let held = out.artifact_refs.entry(p.node_key.clone()).or_default();
            merge_refs(held, &refs);
            continue;
        }

        // Orphan node references: retained (state still applies only
        // when a node_key resolves — without node_declared there is no
        // key to fold under, so the finding is what retains the
        // evidence).
        if ev.node_id.is_none() {
            if requires_node_id(&ev.kind) {
                out.findings.push(Finding {
                    reason_code: ReasonCode::OrphanEvent,
                    detail: format!("node-scope kind {:?} carries no node_id", ev.kind),
                    seq: ev.seq,
                });
            }
        } else if node_key.is_none() {
            out.findings.push(Finding {
                reason_code: ReasonCode::OrphanEvent,
                detail: format!(
                    "kind {:?} references node_id {} with no node_declared",
                    ev.kind,
                    ev.node_id.map(|id| id.to_string()).unwrap_or_default()
                ),
                seq: ev.seq,
            });
        }

        let Some(node_key) = node_key else {
            continue;
        };
        if let Some(state) = node_state_for_kind(&ev.kind) {
            let nf = out
                .nodes
                .entry(node_key.clone())
                .or_insert_with(|| NodeFold {
                    node_id: None,
                    state: String::new(),
                    last_seq: 0,
                });
            nf.state = state.to_string();
            nf.last_seq = ev.seq;
            if let Some(id) = ev.node_id {
                nf.node_id = Some(id);
            }
        }
        // Upstream assigns `ArtifactRefs[nodeKey]` unconditionally once
        // the key resolves — the entry exists even when the event
        // carried no decodable payload (empty union, not absent).
        let held = out.artifact_refs.entry(node_key.clone()).or_default();
        if let Some(map) = obj {
            merge_refs(held, &collect_refs(map));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Divergence detection
// ---------------------------------------------------------------------------

/// Compares the folded projection against materialized node state
/// (`node_key` → current `workflow_nodes.state`) — upstream
/// `CompareFold`. Any disagreement — a materialized node the journal
/// cannot explain, a folded node the table lacks, or differing states —
/// is a `RECONSTRUCTION_DIVERGED` finding that blocks trusting the
/// projection until reconciled; the fold is never rewritten to match.
/// Findings are emitted in `node_key` order so the result is
/// deterministic.
#[must_use]
pub fn compare_fold(current: &BTreeMap<String, String>, folded: &FoldedRun) -> Vec<Finding> {
    let keys: BTreeSet<&String> = current.keys().chain(folded.nodes.keys()).collect();

    let mut findings = Vec::new();
    for key in keys {
        let materialized = current.get(key);
        let folded_node = folded.nodes.get(key);
        match (materialized, folded_node) {
            (Some(materialized), None) => findings.push(Finding {
                reason_code: ReasonCode::ReconstructionDiverged,
                detail: format!(
                    "node {key:?}: materialized state {materialized:?} has no folded evidence"
                ),
                seq: 0,
            }),
            (None, Some(folded_node)) => findings.push(Finding {
                reason_code: ReasonCode::ReconstructionDiverged,
                detail: format!(
                    "node {key:?}: folded state {:?} has no materialized node",
                    folded_node.state
                ),
                seq: folded_node.last_seq,
            }),
            (Some(materialized), Some(folded_node)) if materialized != &folded_node.state => {
                findings.push(Finding {
                    reason_code: ReasonCode::ReconstructionDiverged,
                    detail: format!(
                        "node {key:?}: materialized {materialized:?} diverges from folded {:?}",
                        folded_node.state
                    ),
                    seq: folded_node.last_seq,
                });
            }
            _ => {}
        }
    }
    findings
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// Appends `src` to `dst` preserving first-seen order, deduped — the
/// append-only union expansion batches rely on (upstream
/// `mergeStrings`).
fn merge_strings(dst: &mut Vec<String>, src: &[String]) {
    for s in src {
        if !dst.contains(s) {
            dst.push(s.clone());
        }
    }
}

/// Unions artifact refs by `(artifact_id, checksum)` preserving
/// first-seen order (upstream `mergeRefs`).
fn merge_refs(dst: &mut Vec<ArtifactRef>, src: &[ArtifactRef]) {
    for r in src {
        if !dst.contains(r) {
            dst.push(r.clone());
        }
    }
}

/// Walks a decoded payload object and gathers every object shaped like
/// an artifact reference: a string `artifact_id` (or `id`) that parses
/// as a uuid alongside a string `checksum` (upstream `collectRefs`).
/// Malformed pairs are skipped — generic payloads carry shapes this
/// module does not own; only the `node_declared` schema is strictly
/// validated.
fn collect_refs(obj: &serde_json::Map<String, serde_json::Value>) -> Vec<ArtifactRef> {
    fn walk(value: &serde_json::Value, refs: &mut Vec<ArtifactRef>) {
        match value {
            serde_json::Value::Object(map) => {
                collect_object(map, refs);
            }
            serde_json::Value::Array(items) => {
                for val in items {
                    walk(val, refs);
                }
            }
            _ => {}
        }
    }
    fn collect_object(
        map: &serde_json::Map<String, serde_json::Value>,
        refs: &mut Vec<ArtifactRef>,
    ) {
        let raw_id = map
            .get("artifact_id")
            .and_then(serde_json::Value::as_str)
            .filter(|s| !s.is_empty())
            .or_else(|| {
                map.get("id")
                    .and_then(serde_json::Value::as_str)
                    .filter(|s| !s.is_empty())
            });
        let checksum = map
            .get("checksum")
            .and_then(serde_json::Value::as_str)
            .filter(|s| !s.is_empty());
        if let (Some(raw_id), Some(checksum)) = (raw_id, checksum)
            && let Some(bytes) = lenient_uuid_bytes(raw_id)
        {
            refs.push(ArtifactRef {
                artifact_id: ArtifactId::from_trusted_db_bytes(bytes),
                checksum: checksum.to_string(),
            });
        }
        for val in map.values() {
            walk(val, refs);
        }
    }
    let mut refs = Vec::new();
    collect_object(obj, &mut refs);
    refs
}

#[cfg(test)]
mod tests {
    use super::*;
    use central_foundation::identity::{RunEventId, WorkspaceId};
    use serde_json::json;
    use time::OffsetDateTime;

    // -----------------------------------------------------------------
    // helpers (upstream fold_test.go)
    // -----------------------------------------------------------------

    fn uid(suffix: &str) -> [u8; 16] {
        lenient_uuid_bytes(&format!("00000000-0000-7000-8000-{suffix:0>12}")).expect("test uuid")
    }

    fn run_id_1() -> RunId {
        RunId::parse("00000000-0000-7000-8000-0000000000a1").unwrap()
    }

    fn run_id_2() -> RunId {
        RunId::parse("00000000-0000-7000-8000-0000000000a2").unwrap()
    }

    fn node1() -> WorkflowNodeId {
        WorkflowNodeId::parse("00000000-0000-7000-8000-0000000000b1").unwrap()
    }

    fn node2() -> WorkflowNodeId {
        WorkflowNodeId::parse("00000000-0000-7000-8000-0000000000b2").unwrap()
    }

    fn node3() -> WorkflowNodeId {
        WorkflowNodeId::parse("00000000-0000-7000-8000-0000000000b3").unwrap()
    }

    fn node_x() -> WorkflowNodeId {
        WorkflowNodeId::parse("00000000-0000-7000-8000-0000000000b9").unwrap()
    }

    fn att1() -> SessionAttemptId {
        SessionAttemptId::parse("00000000-0000-7000-8000-0000000000c1").unwrap()
    }

    fn att2() -> SessionAttemptId {
        SessionAttemptId::parse("00000000-0000-7000-8000-0000000000c2").unwrap()
    }

    fn att3() -> SessionAttemptId {
        SessionAttemptId::parse("00000000-0000-7000-8000-0000000000c3").unwrap()
    }

    fn att_x() -> SessionAttemptId {
        SessionAttemptId::parse("00000000-0000-7000-8000-0000000000c9").unwrap()
    }

    fn art1() -> ArtifactId {
        ArtifactId::from_trusted_db_bytes(uid("0000000000d1"))
    }

    fn art2() -> ArtifactId {
        ArtifactId::from_trusted_db_bytes(uid("0000000000d2"))
    }

    fn ws_id() -> WorkspaceId {
        WorkspaceId::parse("00000000-0000-7000-8000-0000000000e1").unwrap()
    }

    fn stray_node_id() -> WorkflowNodeId {
        WorkflowNodeId::parse("00000000-0000-7000-8000-0000000000f1").unwrap()
    }

    #[derive(Default)]
    struct EvOpt {
        node_id: Option<WorkflowNodeId>,
        attempt_id: Option<SessionAttemptId>,
        payload: Option<serde_json::Value>,
    }

    impl EvOpt {
        fn on_node(id: WorkflowNodeId) -> Self {
            Self {
                node_id: Some(id),
                ..Self::default()
            }
        }

        fn on_attempt(id: SessionAttemptId) -> Self {
            Self {
                attempt_id: Some(id),
                ..Self::default()
            }
        }

        fn payload(value: serde_json::Value) -> Self {
            Self {
                payload: Some(value),
                ..Self::default()
            }
        }

        fn and(mut self, other: Self) -> Self {
            if other.node_id.is_some() {
                self.node_id = other.node_id;
            }
            if other.attempt_id.is_some() {
                self.attempt_id = other.attempt_id;
            }
            if other.payload.is_some() {
                self.payload = other.payload;
            }
            self
        }
    }

    fn ev(seq: i64, kind: &str, opts: EvOpt) -> RunEvent {
        RunEvent {
            id: RunEventId::parse(&format!("00000000-0000-7000-8000-{seq:012}")).unwrap(),
            workspace_id: ws_id(),
            run_id: run_id_1(),
            seq,
            node_id: opts.node_id,
            attempt_id: opts.attempt_id,
            kind: kind.to_string(),
            actor: "scheduler".to_string(),
            reason_code: None,
            payload: opts.payload.unwrap_or(serde_json::Value::Null),
            recorded_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn declared(key: &str, deps: &[&str], refs: Vec<ArtifactRef>) -> EvOpt {
        EvOpt::payload(
            serde_json::to_value(NodeDeclaredPayload {
                payload_version: 1,
                node_key: key.to_string(),
                depends_on: deps.iter().map(|d| (*d).to_string()).collect(),
                harness: "claude-code".to_string(),
                workspace_kind: "worktree".to_string(),
                depth: 1,
                input_artifact_refs: refs,
            })
            .unwrap(),
        )
    }

    fn findings_for(f: &FoldedRun, code: ReasonCode) -> Vec<&Finding> {
        f.findings
            .iter()
            .filter(|x| x.reason_code == code)
            .collect()
    }

    // -----------------------------------------------------------------
    // multi-node run: happy path, retry return, ambiguous, artifact refs
    // -----------------------------------------------------------------

    /// The journal of a three-node run (upstream `multiNodeEvents`):
    ///
    /// - `root`: declared → ready → dispatched → started → succeeded →
    ///   node_succeeded
    /// - `worker-a`: declared → ready → dispatched → started → FAILED →
    ///   ready (retry path) → dispatched → started → succeeded →
    ///   node_succeeded
    /// - `worker-b`: declared → ready → dispatched → started →
    ///   attempt_ambiguous (parked)
    ///
    /// `worker-a` declares an ordering edge on `root` plus one input
    /// artifact ref; `worker-b`'s `attempt_started` carries a
    /// `versions.prompt_ref`.
    fn multi_node_events() -> Vec<RunEvent> {
        vec![
            // root lifecycle
            ev(1, "node_declared", EvOpt::on_node(node1()).and(declared("root", &[], vec![]))),
            ev(2, "node_ready", EvOpt::on_node(node1())),
            ev(3, "node_dispatched", EvOpt::on_node(node1()).and(EvOpt::on_attempt(att1()))),
            ev(4, "attempt_started", EvOpt::on_node(node1()).and(EvOpt::on_attempt(att1()))),
            ev(5, "attempt_succeeded", EvOpt::on_node(node1()).and(EvOpt::on_attempt(att1()))),
            ev(6, "node_succeeded", EvOpt::on_node(node1())),
            // expansion batch: worker-a and worker-b
            ev(
                7,
                "node_declared",
                EvOpt::on_node(node2()).and(declared(
                    "worker-a",
                    &["root"],
                    vec![ArtifactRef {
                        artifact_id: art1(),
                        checksum: "sha256:a".to_string(),
                    }],
                )),
            ),
            ev(
                8,
                "node_declared",
                EvOpt::on_node(node3()).and(declared("worker-b", &["root", "worker-a"], vec![])),
            ),
            ev(9, "node_ready", EvOpt::on_node(node2())),
            ev(10, "node_dispatched", EvOpt::on_node(node2()).and(EvOpt::on_attempt(att2()))),
            ev(11, "attempt_started", EvOpt::on_node(node2()).and(EvOpt::on_attempt(att2()))),
            ev(12, "attempt_failed", EvOpt::on_node(node2()).and(EvOpt::on_attempt(att2()))),
            // retry-path return to ready, second attempt
            ev(13, "node_ready", EvOpt::on_node(node2())),
            ev(14, "node_dispatched", EvOpt::on_node(node2()).and(EvOpt::on_attempt(att3()))),
            ev(15, "attempt_started", EvOpt::on_node(node2()).and(EvOpt::on_attempt(att3()))),
            ev(16, "attempt_succeeded", EvOpt::on_node(node2()).and(EvOpt::on_attempt(att3()))),
            ev(17, "node_succeeded", EvOpt::on_node(node2())),
            // ambiguous branch
            ev(18, "node_ready", EvOpt::on_node(node3())),
            ev(19, "node_dispatched", EvOpt::on_node(node3()).and(EvOpt::on_attempt(att_x()))),
            ev(
                20,
                "attempt_started",
                EvOpt::on_node(node3())
                    .and(EvOpt::on_attempt(att_x()))
                    .and(EvOpt::payload(json!({
                        "versions": {
                            "prompt_ref": {"artifact_id": art2().to_string(), "checksum": "sha256:p"}
                        }
                    }))),
            ),
            ev(21, "attempt_ambiguous", EvOpt::on_node(node3()).and(EvOpt::on_attempt(att_x()))),
            // a run-scope rejection folds to nothing
            ev(
                22,
                "child_spec_rejected",
                EvOpt::payload(json!({"offending_keys": ["bad-child"]})),
            ),
        ]
    }

    #[test]
    fn fold_multi_node_run() {
        let events = multi_node_events();
        // Feed the fold an unordered copy; (run_id, seq) order is
        // derived.
        let shuffled: Vec<RunEvent> = [
            12usize, 0, 20, 7, 3, 17, 9, 1, 15, 5, 11, 19, 2, 8, 14, 21, 4, 10, 6, 13, 18, 16,
        ]
        .iter()
        .map(|i| events[*i].clone())
        .collect();
        let f = fold(&shuffled);

        assert!(
            f.findings.is_empty(),
            "unexpected findings: {:?}",
            f.findings
        );

        for (key, want) in [
            ("root", "succeeded"),
            ("worker-a", "succeeded"),
            ("worker-b", "attempt_ambiguous"),
        ] {
            let nf = f.nodes.get(key).expect("node missing from fold");
            assert_eq!(nf.state, want, "node {key:?}");
        }
        assert_eq!(f.nodes["root"].node_id, Some(node1()));
        assert_eq!(f.nodes["root"].last_seq, 6);
        assert_eq!(f.nodes["worker-b"].last_seq, 21);

        // Attempt history groups by attempt_id, seq-ordered.
        let att2 = &f.attempts[&att2()];
        assert_eq!(att2.len(), 3);
        assert_eq!(att2[0].kind, "node_dispatched");
        assert_eq!(att2[1].kind, "attempt_started");
        assert_eq!(att2[2].kind, "attempt_failed");
        let att_x_events = &f.attempts[&att_x()];
        assert_eq!(att_x_events.len(), 3);
        assert_eq!(att_x_events[2].kind, "attempt_ambiguous");
        assert!(f.attempts.contains_key(&att3()));

        // Graph edges fold from node_declared payloads across batches.
        assert_eq!(f.graph["worker-a"], &["root"]);
        assert_eq!(f.graph["worker-b"], &["root", "worker-a"]);
        assert!(f.graph["root"].is_empty());

        // Artifact refs union per node: declared input refs +
        // versions.prompt_ref.
        let wa = &f.artifact_refs["worker-a"];
        assert_eq!(wa.len(), 1);
        assert_eq!(wa[0].artifact_id, art1());
        let wb = &f.artifact_refs["worker-b"];
        assert_eq!(wb.len(), 1);
        assert_eq!(wb[0].artifact_id, art2());
    }

    // The spec-6 fold table row "attempt_failed then retry-path
    // node_ready -> ready": attempt_failed alone never moves the node —
    // it stays running until the node-level node_ready journals the
    // retry return.
    #[test]
    fn fold_attempt_failed_holds_state() {
        let events = multi_node_events();
        // ends at seq 12 attempt_failed; seq 13 node_ready excluded
        let failed_only = fold(&events[..12]);
        assert_eq!(failed_only.nodes["worker-a"].state, "running");
        let full = fold(&events);
        assert_eq!(full.nodes["worker-a"].state, "succeeded");
    }

    // A second emission batch declares new nodes depending on earlier
    // ones; edges and nodes only ever append.
    #[test]
    fn fold_expansion_batch_appends_edges() {
        let f = fold(&[
            ev(
                1,
                "node_declared",
                EvOpt::on_node(node1()).and(declared("root", &[], vec![])),
            ),
            ev(
                2,
                "node_declared",
                EvOpt::on_node(node2()).and(declared("a", &["root"], vec![])),
            ),
            // later expansion batch
            ev(
                3,
                "node_declared",
                EvOpt::on_node(node3()).and(declared("b", &["a", "root"], vec![])),
            ),
            ev(
                4,
                "node_declared",
                EvOpt::on_node(node_x()).and(declared("c", &["b"], vec![])),
            ),
        ]);
        assert!(
            f.findings.is_empty(),
            "unexpected findings: {:?}",
            f.findings
        );
        assert_eq!(f.nodes.len(), 4);
        assert_eq!(f.graph["c"], &["b"]);
        assert_eq!(f.graph["b"], &["a", "root"]);
        for key in ["root", "a", "b", "c"] {
            assert_eq!(f.nodes[key].state, "declared", "node {key}");
        }
    }

    // -----------------------------------------------------------------
    // findings
    // -----------------------------------------------------------------

    #[test]
    fn fold_sequence_gap() {
        let f = fold(&[
            ev(
                1,
                "node_declared",
                EvOpt::on_node(node1()).and(declared("root", &[], vec![])),
            ),
            ev(2, "node_ready", EvOpt::on_node(node1())),
            ev(5, "node_dispatched", EvOpt::on_node(node1())), // gap: seqs 3..4
            ev(7, "node_cancelled", EvOpt::on_node(node1())),  // gap: seq 6
        ]);
        let gaps = findings_for(&f, ReasonCode::EventSequenceGap);
        assert_eq!(gaps.len(), 2, "findings: {:?}", f.findings);
        assert!(
            gaps[0].detail.contains("3..4"),
            "gap detail: {}",
            gaps[0].detail
        );
        assert_eq!(gaps[0].seq, 5);
        assert!(
            gaps[1].detail.contains("seq 6"),
            "gap detail: {}",
            gaps[1].detail
        );
        // The fold still applied every available event.
        assert_eq!(f.nodes["root"].state, "cancelled");
    }

    // Gap detection is scoped per run; two runs interleaved in input
    // each get their own contiguity check, and a leading window (first
    // event above seq 1) is not a gap.
    #[test]
    fn fold_sequence_gap_per_run() {
        let mut e2 = ev(
            3,
            "node_declared",
            EvOpt::on_node(node2()).and(declared("r2", &[], vec![])),
        );
        e2.run_id = run_id_2();
        let mut e4 = ev(5, "node_ready", EvOpt::on_node(node2())); // gap 4 in run2
        e4.run_id = run_id_2();
        let f = fold(&[
            e2,
            // leading window: no gap
            ev(
                10,
                "node_declared",
                EvOpt::on_node(node1()).and(declared("r1", &[], vec![])),
            ),
            e4,
        ]);
        let gaps = findings_for(&f, ReasonCode::EventSequenceGap);
        assert_eq!(gaps.len(), 1, "findings: {:?}", f.findings);
        assert!(
            gaps[0].detail.contains("seq 4"),
            "gap detail: {}",
            gaps[0].detail
        );
        assert!(
            gaps[0].detail.contains(&run_id_2().to_string()),
            "gap detail: {}",
            gaps[0].detail
        );
    }

    #[test]
    fn fold_invalid_payload_excluded_and_flagged() {
        let f = fold(&[
            // payload fails the node_declared schema: node_key must be a
            // string.
            ev(
                1,
                "node_declared",
                EvOpt::on_node(node1()).and(EvOpt::payload(json!({"node_key": 42}))),
            ),
            // upstream's `[]byte("not-json")` case: a JSON document that
            // is not an object — `serde_json::Value` cannot carry
            // invalid JSON bytes, so a bare string stands in for the
            // same "not a JSON object" branch.
            ev(
                2,
                "node_ready",
                EvOpt::on_node(node2()).and(EvOpt::payload(json!("not-json"))),
            ),
            // a non-object JSON payload.
            ev(
                3,
                "node_ready",
                EvOpt::on_node(node3()).and(EvOpt::payload(json!(["a"]))),
            ),
        ]);
        let bad = findings_for(&f, ReasonCode::InvalidEventPayload);
        assert_eq!(bad.len(), 3, "findings: {:?}", f.findings);
        // Excluded from fold: seq 1 never declared the node, so nothing
        // exists.
        assert!(f.nodes.is_empty());
        assert!(!f.graph.contains_key("root"));
    }

    // When node_declared is excluded, later events referencing its
    // node_id have no context — ORPHAN_EVENT.
    #[test]
    fn fold_invalid_declared_chains_orphans() {
        let f = fold(&[
            ev(
                1,
                "node_declared",
                EvOpt::on_node(node1()).and(EvOpt::payload(json!({"node_key": 42}))),
            ),
            ev(2, "node_ready", EvOpt::on_node(node1())),
            ev(3, "node_succeeded", EvOpt::on_node(node1())),
        ]);
        assert!(
            f.findings
                .iter()
                .any(|x| x.reason_code == ReasonCode::InvalidEventPayload
                    && x.detail.contains("node_declared")),
            "findings: {:?}",
            f.findings
        );
        let orphans = findings_for(&f, ReasonCode::OrphanEvent);
        assert_eq!(orphans.len(), 2, "findings: {:?}", f.findings);
        assert!(f.nodes.is_empty());
    }

    #[test]
    fn fold_undeclared_payload_version() {
        let p = NodeDeclaredPayload {
            payload_version: 2,
            node_key: "root".to_string(),
            ..NodeDeclaredPayload::default()
        };
        let f = fold(&[ev(
            1,
            "node_declared",
            EvOpt::on_node(node1()).and(EvOpt::payload(serde_json::to_value(p).unwrap())),
        )]);
        assert!(
            f.findings
                .iter()
                .any(|x| x.reason_code == ReasonCode::InvalidEventPayload
                    && x.detail.contains("payload_version")),
            "findings: {:?}",
            f.findings
        );
        assert!(f.nodes.is_empty());
    }

    #[test]
    fn fold_unknown_kind_excluded_and_flagged() {
        let f = fold(&[
            ev(
                1,
                "node_declared",
                EvOpt::on_node(node1()).and(declared("root", &[], vec![])),
            ),
            ev(
                2,
                "node_teleported",
                EvOpt::on_node(node1()).and(EvOpt::payload(json!({"x": 1}))),
            ),
            ev(
                3,
                "harness.telemetry",
                EvOpt::on_node(node1()).and(EvOpt::on_attempt(att1())),
            ),
        ]);
        let unk = findings_for(&f, ReasonCode::UnknownEventKind);
        assert_eq!(unk.len(), 2, "findings: {:?}", f.findings);
        // Unknown kinds are excluded: no state change, no attempt
        // history.
        assert_eq!(f.nodes["root"].state, "declared");
        assert!(f.attempts.is_empty());
    }

    #[test]
    fn fold_orphan_event() {
        let f = fold(&[
            // attempt-scope event for an attempt never established on a
            // node never declared: two orphan references.
            ev(
                1,
                "attempt_succeeded",
                EvOpt::on_node(node1()).and(EvOpt::on_attempt(att_x())),
            ),
            // node-scope event for a node never declared.
            ev(2, "node_ready", EvOpt::on_node(stray_node_id())),
            // attempt-scope kind missing attempt_id, on a node never
            // declared.
            ev(3, "attempt_failed", EvOpt::on_node(node1())),
        ]);
        let orphans = findings_for(&f, ReasonCode::OrphanEvent);
        assert_eq!(orphans.len(), 5, "findings: {:?}", f.findings);
        // Orphans are retained: the attempt history still groups the
        // event.
        let grouped = &f.attempts[&att_x()];
        assert_eq!(grouped.len(), 1);
        assert_eq!(grouped[0].kind, "attempt_succeeded");
        assert!(f.nodes.is_empty());
    }

    // The attempt reference dangles but the node context is real — the
    // event still applies to node state.
    #[test]
    fn fold_orphan_attempt_on_declared_node() {
        let f = fold(&[
            ev(
                1,
                "node_declared",
                EvOpt::on_node(node1()).and(declared("root", &[], vec![])),
            ),
            ev(
                2,
                "attempt_ambiguous",
                EvOpt::on_node(node1()).and(EvOpt::on_attempt(att_x())),
            ),
        ]);
        assert!(
            f.findings.iter().any(
                |x| x.reason_code == ReasonCode::OrphanEvent && x.detail.contains("attempt_id")
            ),
            "findings: {:?}",
            f.findings
        );
        assert_eq!(f.nodes["root"].state, "attempt_ambiguous");
        assert_eq!(f.attempts[&att_x()].len(), 1);
    }

    // The two Slice-2D kinds' envelopes: attempt_retry_scheduled
    // carries the OLD attempt's id on its node and never moves the node
    // (the retry-path node_ready does that later);
    // compensation_requested is node-scoped with no attempt and also
    // moves nothing. Neither is orphaned when its context exists.
    #[test]
    fn fold_retry_and_compensation_scoping() {
        let f = fold(&[
            ev(
                1,
                "node_declared",
                EvOpt::on_node(node1()).and(declared("root", &[], vec![])),
            ),
            ev(
                2,
                "node_dispatched",
                EvOpt::on_node(node1()).and(EvOpt::on_attempt(att1())),
            ),
            ev(
                3,
                "attempt_started",
                EvOpt::on_node(node1()).and(EvOpt::on_attempt(att1())),
            ),
            ev(
                4,
                "attempt_failed",
                EvOpt::on_node(node1()).and(EvOpt::on_attempt(att1())),
            ),
            ev(
                5,
                "attempt_retry_scheduled",
                EvOpt::on_node(node1()).and(EvOpt::on_attempt(att1())),
            ),
            ev(6, "node_failed_terminal", EvOpt::on_node(node1())),
            ev(7, "compensation_requested", EvOpt::on_node(node1())),
        ]);
        assert!(
            f.findings.is_empty(),
            "unexpected findings: {:?}",
            f.findings
        );
        // The retry schedule event groups under the old attempt's
        // history.
        let history = &f.attempts[&att1()];
        assert_eq!(history.len(), 4);
        assert_eq!(history[3].kind, "attempt_retry_scheduled");
        // compensation_requested annotates but does not move the
        // terminal node.
        assert_eq!(f.nodes["root"].state, "failed_terminal");
    }

    // The same two kinds flagged when their envelope contract is
    // broken — attempt_retry_scheduled with no attempt_id is an orphan
    // even on a declared node; compensation_requested with no node_id
    // is an orphan too.
    #[test]
    fn fold_retry_kind_requires_attempt_and_node() {
        let f = fold(&[
            ev(
                1,
                "node_declared",
                EvOpt::on_node(node1()).and(declared("root", &[], vec![])),
            ),
            ev(2, "attempt_retry_scheduled", EvOpt::on_node(node1())),
            ev(3, "compensation_requested", EvOpt::default()),
        ]);
        let orphans = findings_for(&f, ReasonCode::OrphanEvent);
        assert_eq!(orphans.len(), 2, "findings: {:?}", f.findings);
        assert!(f.attempts.is_empty());
    }

    #[test]
    fn fold_node_scoped_kind_missing_node_id() {
        let f = fold(&[ev(1, "node_ready", EvOpt::default())]);
        assert!(
            f.findings.iter().any(
                |x| x.reason_code == ReasonCode::OrphanEvent && x.detail.contains("no node_id")
            ),
            "findings: {:?}",
            f.findings
        );
        assert!(f.nodes.is_empty());
    }

    #[test]
    fn fold_empty() {
        let f = fold(&[]);
        assert!(f.findings.is_empty());
        assert!(f.nodes.is_empty() && f.attempts.is_empty());
        assert!(f.graph.is_empty() && f.artifact_refs.is_empty());
    }

    // -----------------------------------------------------------------
    // divergence
    // -----------------------------------------------------------------

    /// `(name, materialized rows, expected divergence count)`.
    type CompareCase<'a> = (&'a str, &'a [(&'a str, &'a str)], usize);

    #[test]
    fn compare_fold_cases() {
        let f = fold(&multi_node_events());
        let cases: &[CompareCase] = &[
            (
                "no divergence when materialized matches",
                &[
                    ("root", "succeeded"),
                    ("worker-a", "succeeded"),
                    ("worker-b", "attempt_ambiguous"),
                ],
                0,
            ),
            (
                "state mismatch diverges",
                &[
                    ("root", "succeeded"),
                    ("worker-a", "running"), // materialized disagrees
                    ("worker-b", "attempt_ambiguous"),
                ],
                1,
            ),
            (
                "materialized node missing from fold diverges",
                &[
                    ("root", "succeeded"),
                    ("worker-a", "succeeded"),
                    ("worker-b", "attempt_ambiguous"),
                    ("ghost", "ready"),
                ],
                1,
            ),
            (
                "folded node missing from materialized diverges",
                &[("root", "succeeded")],
                2,
            ),
        ];
        for (name, entries, want) in cases {
            let current: BTreeMap<String, String> = entries
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect();
            let findings = compare_fold(&current, &f);
            assert_eq!(findings.len(), *want, "{name}: {findings:?}");
            for x in &findings {
                assert_eq!(x.reason_code, ReasonCode::ReconstructionDiverged, "{name}");
            }
        }
    }

    #[test]
    fn compare_fold_divergence_detail() {
        let f = fold(&multi_node_events());
        let current: BTreeMap<String, String> = [("worker-b".to_string(), "running".to_string())]
            .into_iter()
            .collect();
        // worker-b mismatches; root and worker-a are absent from
        // materialized.
        let findings = compare_fold(&current, &f);
        assert_eq!(findings.len(), 3, "findings: {findings:?}");
        let mut detail = String::new();
        for x in &findings {
            if x.detail.contains("\"worker-b\"") {
                detail = x.detail.clone();
                assert_eq!(x.seq, 21, "divergence seq wants folded LastSeq 21");
            }
        }
        assert!(detail.contains("running"), "detail: {detail}");
        assert!(detail.contains("attempt_ambiguous"), "detail: {detail}");
    }

    // -----------------------------------------------------------------
    // artifact-ref scanning tolerance (upstream collectRefs grammar)
    // -----------------------------------------------------------------

    // `id` fallback, urn/brace/uppercase leniency, and malformed pairs
    // skipped — the gofrs `uuid.FromString` tolerance the payload
    // scanner owns.
    #[test]
    fn collect_refs_leniency() {
        let refs = collect_refs(
            json!({
                "a": {"id": art1().to_string(), "checksum": "sha256:a"},
                "b": {"artifact_id": "urn:uuid:00000000-0000-4000-8000-0000000000D2", "checksum": "sha256:b"},
                "c": {"artifact_id": "{00000000-0000-4000-8000-0000000000d3}", "checksum": "sha256:c"},
                "missing_checksum": {"artifact_id": art1().to_string()},
                "bad_uuid": {"artifact_id": "not-a-uuid", "checksum": "sha256:x"},
                "nested": [{"artifact_id": "000000000000400080000000000000d4", "checksum": "sha256:d"}],
            })
            .as_object()
            .unwrap(),
        );
        assert_eq!(refs.len(), 4, "refs: {refs:?}");
        assert!(refs.iter().any(|r| r.artifact_id == art1()));
        assert!(refs.iter().all(|r| !r.artifact_id.is_nil()));
        let checksums: BTreeSet<&str> = refs.iter().map(|r| r.checksum.as_str()).collect();
        assert_eq!(
            checksums,
            ["sha256:a", "sha256:b", "sha256:c", "sha256:d"]
                .into_iter()
                .collect()
        );
    }

    // The lenient uuid grammar the payload scanner shares with
    // ArtifactRef decode.
    #[test]
    fn lenient_uuid_grammar() {
        // Canonical, unhyphenated, braces, urn — every version and
        // case upstream accepts.
        for text in [
            "00000000-0000-4000-8000-0000000000D2",
            "000000000000400080000000000000d2",
            "{00000000-0000-4000-8000-0000000000d2}",
            "urn:uuid:00000000-0000-4000-8000-0000000000d2",
            "URN:UUID:00000000-0000-4000-8000-0000000000D2",
        ] {
            assert!(lenient_uuid_bytes(text).is_some(), "rejected: {text}");
        }
        for text in [
            "",
            "not-a-uuid",
            "00000000-0000-4000-8000-0000000000d",
            "{00000000-0000-4000-8000-0000000000d2",
            "urn:uuid:00000000-0000-4000-8000-0000000000d",
            "gggggggg-0000-4000-8000-0000000000d2",
        ] {
            assert!(lenient_uuid_bytes(text).is_none(), "accepted: {text}");
        }
    }
}
