//! The canonical per-run orchestration journal envelope (spec-6
//! decision 1) — pure port of `central/internal/eventjournal/domain.go`.
//!
//! One append-only `central.run_events` row carries the run it belongs
//! to, its per-run monotonic `seq`, its optional node/attempt subjects,
//! the cataloged kind, the emitter actor, an optional SCREAMING_CASE
//! reason code, and the kind-versioned payload. Pure domain — no
//! persistence, no adapter types.
//!
//! OWNING PACKET: P2A04. SLICE: 2A.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use central_foundation::identity::{
    RunEventId, RunId, SessionAttemptId, WorkflowNodeId, WorkspaceId,
};

// ---------------------------------------------------------------------------
// Event kinds — the spec-6 catalog
// ---------------------------------------------------------------------------

/// The cataloged `run_events.kind` vocabulary — the closed 30-kind index
/// of spec-6 decision 6 (upstream's `Kind*` constants + `Catalog`). The
/// first eleven are spec-1's declared set plus `cancel_requested` (its
/// cancel-propagation intent record, consumed by Slice 2B's dispatch);
/// `artifact_finalized` comes from spec-7, `admission_deferred` from
/// spec-8, `command_deduped`/`attempt_decision` from spec-5, the six
/// `worker_*`/`lease_*` kinds from spec-2, the six
/// `checkpoint_*`/`resume_*` kinds from spec-3, and
/// `attempt_retry_scheduled`/`compensation_requested` from spec-4.
///
/// Kinds are added only by their owning spec; the writer stores every
/// kind verbatim (it never gates on the catalog) — [`EventKind::parse`]
/// detects undeclared kinds as spec drift (`UNKNOWN_EVENT_KIND`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EventKind {
    /// `node_declared` — a child-spec node committed.
    NodeDeclared,
    /// `node_ready` — a node entered `ready`.
    NodeReady,
    /// `node_dispatched` — a node entered `dispatched`.
    NodeDispatched,
    /// `attempt_started` — an attempt went live.
    AttemptStarted,
    /// `attempt_succeeded` — an attempt finished cleanly.
    AttemptSucceeded,
    /// `attempt_failed` — an attempt reported a definite failure.
    AttemptFailed,
    /// `attempt_ambiguous` — an attempt's outcome is unknowable; the
    /// node parks for an operator decision.
    AttemptAmbiguous,
    /// `node_succeeded` — a node reached terminal success.
    NodeSucceeded,
    /// `node_failed_terminal` — a node reached terminal failure.
    NodeFailedTerminal,
    /// `node_cancelled` — a node reached terminal cancel.
    NodeCancelled,
    /// `child_spec_rejected` — an atomic batch refusal (run-scope).
    ChildSpecRejected,
    /// `cancel_requested` — cancel intent for a live node.
    CancelRequested,
    /// `artifact_finalized` — spec-7's declared row: an attempt's
    /// artifact committed.
    ArtifactFinalized,
    /// `admission_deferred` — spec-8's declared row: pre-attempt
    /// capacity deferral.
    AdmissionDeferred,
    /// `command_deduped` — spec-5's declared row: an idempotent replay
    /// of a recorded command.
    CommandDeduped,
    /// `attempt_decision` — spec-5's declared row: the operator's
    /// resume/rerun decision on a parked ambiguous attempt.
    AttemptDecision,
    /// `worker_registered` — spec-2: a scheduler worker registered.
    WorkerRegistered,
    /// `worker_deregistered` — spec-2: a worker deregistered.
    WorkerDeregistered,
    /// `worker_suspect` — spec-2: a worker's missed-beat ladder mark.
    WorkerSuspect,
    /// `worker_lost` — spec-2: a worker past its missed-beat grace.
    WorkerLost,
    /// `lease_expired` — spec-2: a node lease lapsed.
    LeaseExpired,
    /// `lease_renewal_rejected` — spec-2: a fenced lease renewal was
    /// refused.
    LeaseRenewalRejected,
    /// `checkpoint_written` — spec-3: a quiescent-boundary checkpoint
    /// committed.
    CheckpointWritten,
    /// `checkpoint_refused` — spec-3: a checkpoint write was refused.
    CheckpointRefused,
    /// `resume_started` — spec-3: a resume attempt began.
    ResumeStarted,
    /// `resume_completed` — spec-3: a resume reached quiescence.
    ResumeCompleted,
    /// `resume_failed` — spec-3: a resume could not continue.
    ResumeFailed,
    /// `checkpoint_gc_collected` — spec-3: the retention-class GC
    /// record.
    CheckpointGcCollected,
    /// `attempt_retry_scheduled` — spec-4: a retryable attempt outcome's
    /// scheduled next attempt; carries the OLD attempt's id (the one
    /// that just failed), the new `not_before`, and the class/reason
    /// that scheduled it.
    AttemptRetryScheduled,
    /// `compensation_requested` — spec-4: a terminal node's
    /// compensation request — node-scoped, no attempt.
    CompensationRequested,
}

impl EventKind {
    /// Every declared kind in declaration order — the closed catalog
    /// ingest and the fold cross-check against.
    pub const ALL: [Self; 30] = [
        Self::NodeDeclared,
        Self::NodeReady,
        Self::NodeDispatched,
        Self::AttemptStarted,
        Self::AttemptSucceeded,
        Self::AttemptFailed,
        Self::AttemptAmbiguous,
        Self::NodeSucceeded,
        Self::NodeFailedTerminal,
        Self::NodeCancelled,
        Self::ChildSpecRejected,
        Self::CancelRequested,
        Self::ArtifactFinalized,
        Self::AdmissionDeferred,
        Self::CommandDeduped,
        Self::AttemptDecision,
        Self::WorkerRegistered,
        Self::WorkerDeregistered,
        Self::WorkerSuspect,
        Self::WorkerLost,
        Self::LeaseExpired,
        Self::LeaseRenewalRejected,
        Self::CheckpointWritten,
        Self::CheckpointRefused,
        Self::ResumeStarted,
        Self::ResumeCompleted,
        Self::ResumeFailed,
        Self::CheckpointGcCollected,
        Self::AttemptRetryScheduled,
        Self::CompensationRequested,
    ];

    /// The journaled text form — byte-identical to upstream's `Kind*`
    /// constants.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NodeDeclared => "node_declared",
            Self::NodeReady => "node_ready",
            Self::NodeDispatched => "node_dispatched",
            Self::AttemptStarted => "attempt_started",
            Self::AttemptSucceeded => "attempt_succeeded",
            Self::AttemptFailed => "attempt_failed",
            Self::AttemptAmbiguous => "attempt_ambiguous",
            Self::NodeSucceeded => "node_succeeded",
            Self::NodeFailedTerminal => "node_failed_terminal",
            Self::NodeCancelled => "node_cancelled",
            Self::ChildSpecRejected => "child_spec_rejected",
            Self::CancelRequested => "cancel_requested",
            Self::ArtifactFinalized => "artifact_finalized",
            Self::AdmissionDeferred => "admission_deferred",
            Self::CommandDeduped => "command_deduped",
            Self::AttemptDecision => "attempt_decision",
            Self::WorkerRegistered => "worker_registered",
            Self::WorkerDeregistered => "worker_deregistered",
            Self::WorkerSuspect => "worker_suspect",
            Self::WorkerLost => "worker_lost",
            Self::LeaseExpired => "lease_expired",
            Self::LeaseRenewalRejected => "lease_renewal_rejected",
            Self::CheckpointWritten => "checkpoint_written",
            Self::CheckpointRefused => "checkpoint_refused",
            Self::ResumeStarted => "resume_started",
            Self::ResumeCompleted => "resume_completed",
            Self::ResumeFailed => "resume_failed",
            Self::CheckpointGcCollected => "checkpoint_gc_collected",
            Self::AttemptRetryScheduled => "attempt_retry_scheduled",
            Self::CompensationRequested => "compensation_requested",
        }
    }

    /// Parses the journaled text form; `None` on anything outside the
    /// catalog — the `UNKNOWN_EVENT_KIND` detector.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|kind| kind.as_str() == s)
    }
}

impl core::fmt::Display for EventKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Reports whether `kind` is cataloged (upstream `eventjournal.Known`).
/// The writer stores every kind verbatim; callers and the fold use this
/// to detect undeclared kinds as spec drift.
#[must_use]
pub fn known(kind: &str) -> bool {
    EventKind::parse(kind).is_some()
}

// ---------------------------------------------------------------------------
// Reason codes — spec-6 failure semantics
// ---------------------------------------------------------------------------

/// The SCREAMING_CASE reason codes spec-6 declares for the ingest and
/// fold paths (upstream's `Reason*` constants). Ingest/fold failures
/// are reason codes, never events (OQ-4), so these travel on the events
/// they annotate or in fold [`crate::fold::Finding`]s.
///
/// `DUPLICATE_EVENT_ID` is the ingest-side re-delivery verdict the
/// [`crate::port::Writer`] dedupe reports by returning the existing
/// row's `seq` — idempotent, not an error; nothing emits it as a
/// finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ReasonCode {
    /// `EVENT_SEQUENCE_GAP` — a `seq` gap detected at fold/audit.
    EventSequenceGap,
    /// `DUPLICATE_EVENT_ID` — an ingest re-delivery deduped by
    /// `event_id`; idempotent, not an error.
    DuplicateEventId,
    /// `UNKNOWN_EVENT_KIND` — a kind absent from the [`EventKind`]
    /// catalog; the event is stored raw and excluded from fold.
    UnknownEventKind,
    /// `INVALID_EVENT_PAYLOAD` — a payload failing its kind's schema;
    /// stored raw, excluded from fold.
    InvalidEventPayload,
    /// `ORPHAN_EVENT` — a `node_id`/`attempt_id` referencing nothing
    /// the fold has seen; retained and flagged.
    OrphanEvent,
    /// `RECONSTRUCTION_DIVERGED` — fold output disagreeing with
    /// materialized node/run state.
    ReconstructionDiverged,
}

impl ReasonCode {
    /// Every fold/ingest reason code in declaration order.
    pub const ALL: [Self; 6] = [
        Self::EventSequenceGap,
        Self::DuplicateEventId,
        Self::UnknownEventKind,
        Self::InvalidEventPayload,
        Self::OrphanEvent,
        Self::ReconstructionDiverged,
    ];

    /// The journaled SCREAMING_CASE text form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EventSequenceGap => "EVENT_SEQUENCE_GAP",
            Self::DuplicateEventId => "DUPLICATE_EVENT_ID",
            Self::UnknownEventKind => "UNKNOWN_EVENT_KIND",
            Self::InvalidEventPayload => "INVALID_EVENT_PAYLOAD",
            Self::OrphanEvent => "ORPHAN_EVENT",
            Self::ReconstructionDiverged => "RECONSTRUCTION_DIVERGED",
        }
    }

    /// Parses the journaled text form; `None` on anything else.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|code| code.as_str() == s)
    }
}

impl core::fmt::Display for ReasonCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Canonical envelope
// ---------------------------------------------------------------------------

/// One journaled `central.run_events` row — the canonical envelope of
/// spec-6 decision 1 (upstream `eventjournal.Event`). `id` is the
/// ingest idempotency key; `seq` is the per-run monotonic sequence
/// allocated inside the transition transaction; `node_id` is absent
/// only on run-scope kinds; `attempt_id` is present only on
/// attempt-scope kinds; `recorded_at` is a diagnostic writer timestamp
/// that is never ordering evidence.
///
/// `kind` and `actor` are verbatim text, exactly like upstream's
/// `string` fields: undeclared kinds must round-trip through the
/// envelope so the fold can flag them `UNKNOWN_EVENT_KIND` — the
/// closed catalog check is [`EventKind::parse`]/[`known`], never the
/// field's type.
///
/// `payload` is the kind-versioned JSON document; [`serde_json::Value`]
/// mirrors upstream `json.RawMessage` for every producer-written
/// payload (Go's `json.Marshal` emits object keys sorted, which is
/// exactly `serde_json`'s canonical order) — `Value::Null` carries the
/// upstream `len(payload) == 0` / `null` "no payload" case.
///
/// The serde shape is byte-identical to upstream
/// `json.Marshal(eventjournal.Event)`: Go's untagged-struct field names
/// (`ID`, `WorkspaceID`, `RunID`, `Seq`, `NodeID`, `AttemptID`,
/// `Kind`, `Actor`, `ReasonCode`, `Payload`, `RecordedAt`), `null` for
/// absent optionals, the payload inlined verbatim, and `recorded_at`
/// in RFC 3339 (`time.Time`'s wire form — the same convention
/// `central-task`'s `Budget` uses for untagged upstream structs).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunEvent {
    /// The ingest idempotency key (`run_events.id`).
    #[serde(rename = "ID")]
    pub id: RunEventId,
    /// The owning workspace.
    #[serde(rename = "WorkspaceID")]
    pub workspace_id: WorkspaceId,
    /// The owning run — every event belongs to exactly one.
    #[serde(rename = "RunID")]
    pub run_id: RunId,
    /// The per-run monotonic sequence (`seq >= 1` by schema CHECK;
    /// allocation is the writer's inside the run-row-locked
    /// transaction).
    #[serde(rename = "Seq", default)]
    pub seq: i64,
    /// The node subject; `None` only on run-scope kinds.
    #[serde(rename = "NodeID", default)]
    pub node_id: Option<WorkflowNodeId>,
    /// The attempt subject; `Some` only on attempt-scope kinds.
    #[serde(rename = "AttemptID", default)]
    pub attempt_id: Option<SessionAttemptId>,
    /// The cataloged kind verbatim — see the type-level note on why
    /// this stays `String` (upstream `Kind string`).
    #[serde(rename = "Kind", default)]
    pub kind: String,
    /// The emitter identity verbatim (`scheduler`, `leader`,
    /// `worker:<id>`, `operator:<id>`, `reconciler`, `ingest`).
    #[serde(rename = "Actor", default)]
    pub actor: String,
    /// The optional SCREAMING_CASE reason code on failure/rejection
    /// kinds — free text; the reason-code vocabulary is owned per
    /// emitting spec, not by this envelope.
    #[serde(rename = "ReasonCode", default)]
    pub reason_code: Option<String>,
    /// The kind-versioned JSON payload; `Value::Null` is the "no
    /// payload" case. See the type-level note on `Value` vs upstream
    /// `json.RawMessage`.
    #[serde(rename = "Payload", default)]
    pub payload: serde_json::Value,
    /// The diagnostic writer timestamp — never ordering evidence.
    /// Serialized exactly as Go's `time.Time` JSON: RFC 3339 with a
    /// variable-width fractional second (trailing zeros trimmed, the
    /// dot omitted when zero).
    #[serde(
        rename = "RecordedAt",
        default = "recorded_at_epoch",
        with = "go_rfc3339_nano"
    )]
    pub recorded_at: OffsetDateTime,
}

/// The deserialize-side "no timestamp" fallback — upstream
/// `json.Unmarshal` leaves `time.Time` zero-valued on an absent key;
/// the Unix epoch is the closest representable sentinel.
const fn recorded_at_epoch() -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH
}

/// Serde adapter reproducing Go `time.Time.MarshalJSON` byte-for-byte
/// (`RFC3339Nano`: `[seconds]` always, fractional digits only as
/// needed, `Z` for UTC, `±hh:mm` otherwise) — the workspace `time`
/// dep ships no `serde-well-known` feature, and the stock `Rfc3339`
/// formatter quantizes subsecond digits to {1,2,3,6,9} rather than
/// Go's trailing-zero trim.
mod go_rfc3339_nano {
    use serde::{Deserialize, Deserializer, Serializer};
    use time::OffsetDateTime;
    use time::format_description::FormatItem;
    use time::format_description::well_known::Rfc3339;
    use time::macros::format_description;

    const SECONDS: &[FormatItem<'_>] =
        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]");

    pub fn serialize<S: Serializer>(dt: &OffsetDateTime, ser: S) -> Result<S::Ok, S::Error> {
        let mut text = dt.format(&SECONDS).map_err(serde::ser::Error::custom)?;
        let mut nanos = dt.nanosecond();
        if nanos != 0 {
            let mut frac = [b'0'; 9];
            for digit in frac.iter_mut().rev() {
                *digit = b'0' + (nanos % 10) as u8;
                nanos /= 10;
            }
            let mut end = 9;
            while end > 0 && frac[end - 1] == b'0' {
                end -= 1;
            }
            text.push('.');
            text.push_str(core::str::from_utf8(&frac[..end]).unwrap_or(""));
        }
        let offset = dt.offset();
        if offset.is_utc() {
            text.push('Z');
        } else {
            let sign = if offset.is_negative() { '-' } else { '+' };
            let hours = offset.whole_hours().unsigned_abs();
            let minutes = offset.minutes_past_hour().unsigned_abs();
            text.push_str(&format!("{sign}{hours:02}:{minutes:02}"));
        }
        ser.serialize_str(&text)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<OffsetDateTime, D::Error> {
        let s = <&str>::deserialize(de)?;
        OffsetDateTime::parse(s, &Rfc3339).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A valid canonical UUIDv7 carrying the same numeric suffix the
    /// upstream fixture uses (upstream's gofrs `uuid.Must` accepts
    /// version-0 test ids; the foundation newtypes enforce v7, so the
    /// port re-mints them with the version nibble set — identities only
    /// need distinctness).
    fn id(suffix: &str) -> RunEventId {
        RunEventId::parse(&format!("00000000-0000-7000-8000-{suffix:0>12}")).unwrap()
    }

    fn ws(suffix: &str) -> WorkspaceId {
        WorkspaceId::parse(&format!("00000000-0000-7000-8000-{suffix:0>12}")).unwrap()
    }

    fn run(suffix: &str) -> RunId {
        RunId::parse(&format!("00000000-0000-7000-8000-{suffix:0>12}")).unwrap()
    }

    // TestCatalogCoversSpecSet pins the catalog against the spec-6 index
    // rows the slice emits and consumes. A drift between this list and
    // the catalog is exactly the kind the catalog exists to detect.
    #[test]
    fn catalog_covers_spec_set() {
        let want: &[&str] = &[
            // spec-1 workflow graph + scheduling declared set
            "node_declared",
            "node_ready",
            "node_dispatched",
            "attempt_started",
            "attempt_succeeded",
            "attempt_failed",
            "attempt_ambiguous",
            "node_succeeded",
            "node_failed_terminal",
            "node_cancelled",
            "child_spec_rejected",
            // spec-1 cancel propagation intent (Slice 2B consumes)
            "cancel_requested",
            // spec-7 artifact lineage
            "artifact_finalized",
            // spec-8 concurrency + limits
            "admission_deferred",
            // spec-5 idempotency + consistency
            "command_deduped",
            "attempt_decision",
            // spec-2 worker protocol + leasing
            "worker_registered",
            "worker_deregistered",
            "worker_suspect",
            "worker_lost",
            "lease_expired",
            "lease_renewal_rejected",
            // spec-3 checkpoint + resume (Slice 2C)
            "checkpoint_written",
            "checkpoint_refused",
            "resume_started",
            "resume_completed",
            "resume_failed",
            "checkpoint_gc_collected",
            // spec-4 retry + timeout taxonomy (Slice 2D)
            "attempt_retry_scheduled",
            "compensation_requested",
        ];
        assert_eq!(EventKind::ALL.len(), want.len());
        for kind in want {
            assert!(known(kind), "catalog missing declared kind {kind:?}");
            assert_eq!(EventKind::parse(kind).map(EventKind::as_str), Some(*kind));
        }
    }

    // TestKnownDetectsUndeclaredKinds proves ingest's drift check: a
    // kind absent from the catalog does not parse — the
    // UNKNOWN_EVENT_KIND signal.
    #[test]
    fn known_detects_undeclared_kinds() {
        for alien in [
            "",
            "NODE_DECLARED",
            "node_declared ",
            "worker_registered ",
            "run_started",
            "bogus",
        ] {
            assert!(
                !known(alien),
                "undeclared kind {alien:?} reported as cataloged"
            );
        }
    }

    // TestReasonCodesPinned keeps the spec-6 failure-semantics
    // vocabulary stable; each code travels on the events it annotates
    // or in fold findings, never as a new event kind.
    #[test]
    fn reason_codes_pinned() {
        let want: &[(ReasonCode, &str)] = &[
            (ReasonCode::EventSequenceGap, "EVENT_SEQUENCE_GAP"),
            (ReasonCode::DuplicateEventId, "DUPLICATE_EVENT_ID"),
            (ReasonCode::UnknownEventKind, "UNKNOWN_EVENT_KIND"),
            (ReasonCode::InvalidEventPayload, "INVALID_EVENT_PAYLOAD"),
            (ReasonCode::OrphanEvent, "ORPHAN_EVENT"),
            (
                ReasonCode::ReconstructionDiverged,
                "RECONSTRUCTION_DIVERGED",
            ),
        ];
        for (code, text) in want {
            assert_eq!(code.as_str(), *text);
            assert_eq!(ReasonCode::parse(text), Some(*code));
        }
    }

    // Golden envelope: `serde_json::to_string(&RunEvent)` is
    // byte-identical to upstream `json.Marshal(eventjournal.Event)` —
    // Go's untagged-struct field names in declaration order, `null`
    // for absent optionals, the payload inlined verbatim (object keys
    // sorted — the same order Go's `json.Marshal(map[string]any)`
    // emits), and RFC 3339 for the timestamp.
    #[test]
    fn envelope_serializes_identically_to_upstream() {
        let ev = RunEvent {
            id: id("0000000000e1"),
            workspace_id: ws("0000000000e2"),
            run_id: run("0000000000e3"),
            seq: 7,
            node_id: Some(WorkflowNodeId::parse("00000000-0000-7000-8000-0000000000e4").unwrap()),
            attempt_id: Some(
                SessionAttemptId::parse("00000000-0000-7000-8000-0000000000e5").unwrap(),
            ),
            kind: EventKind::NodeReady.as_str().to_string(),
            actor: "scheduler".to_string(),
            reason_code: Some("NODE_TIMEOUT".to_string()),
            payload: serde_json::json!({"node_key": "root", "depends_on": []}),
            recorded_at: time::Date::from_calendar_date(2026, time::Month::October, 7)
                .unwrap()
                .with_hms_nano(12, 34, 56, 789_012_345)
                .unwrap()
                .assume_utc(),
        };
        let got = serde_json::to_string(&ev).unwrap();
        let want = concat!(
            r#"{"ID":"00000000-0000-7000-8000-0000000000e1","#,
            r#""WorkspaceID":"00000000-0000-7000-8000-0000000000e2","#,
            r#""RunID":"00000000-0000-7000-8000-0000000000e3","#,
            r#""Seq":7,"#,
            r#""NodeID":"00000000-0000-7000-8000-0000000000e4","#,
            r#""AttemptID":"00000000-0000-7000-8000-0000000000e5","#,
            r#""Kind":"node_ready","Actor":"scheduler","#,
            r#""ReasonCode":"NODE_TIMEOUT","#,
            r#""Payload":{"depends_on":[],"node_key":"root"},"#,
            r#""RecordedAt":"2026-10-07T12:34:56.789012345Z"}"#
        );
        assert_eq!(got, want);

        // Deserialize round-trip: the upstream byte shape is accepted
        // verbatim and round-trips losslessly.
        let decoded: RunEvent = serde_json::from_str(&got).unwrap();
        assert_eq!(decoded, ev);
    }

    // Golden envelope — absent optionals serialize as explicit `null`
    // exactly like Go's `*uuid.UUID`/`*string` nil fields; a whole-second
    // timestamp emits no fractional part (Go RFC3339Nano parity).
    #[test]
    fn envelope_serializes_null_optionals_like_upstream() {
        let ev = RunEvent {
            id: id("0000000000e1"),
            workspace_id: ws("0000000000e2"),
            run_id: run("0000000000e3"),
            seq: 1,
            node_id: None,
            attempt_id: None,
            kind: EventKind::ChildSpecRejected.as_str().to_string(),
            actor: "leader".to_string(),
            reason_code: None,
            payload: serde_json::Value::Null,
            recorded_at: OffsetDateTime::UNIX_EPOCH,
        };
        let got = serde_json::to_string(&ev).unwrap();
        let want = concat!(
            r#"{"ID":"00000000-0000-7000-8000-0000000000e1","#,
            r#""WorkspaceID":"00000000-0000-7000-8000-0000000000e2","#,
            r#""RunID":"00000000-0000-7000-8000-0000000000e3","#,
            r#""Seq":1,"NodeID":null,"AttemptID":null,"#,
            r#""Kind":"child_spec_rejected","Actor":"leader","#,
            r#""ReasonCode":null,"Payload":null,"#,
            r#""RecordedAt":"1970-01-01T00:00:00Z"}"#
        );
        assert_eq!(got, want);
    }
}
