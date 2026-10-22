//! The Phase-1 immutable Event envelope (`docs/events/v1.md`) and its
//! producer-side validation.
//!
//! Pure synchronous Rust (rust-application-boundaries.md §2.3/§7.1): no
//! `async fn`, no I/O.
//!
//! Canonical contract, restated:
//!
//! - An Event is immutable audit-and-recovery evidence appended in the
//!   same transaction as the current-state update it proves. No actor
//!   may mutate a committed Event (§1).
//! - Every v1 Event serializes as the §2 envelope: `event_id`,
//!   `event_sequence`, `schema_version = "v1"`, `type`, `occurred_at`,
//!   `workspace_id`, `aggregate_type`, `aggregate_id`,
//!   `aggregate_version`, `correlation_id`, `causation_id`, `actor`,
//!   `payload`, plus contextual `task_id`/`run_id`/`step_id`/
//!   `attempt_id`/`prior_state`/`next_state`/`reason` when applicable.
//! - `event_sequence` is unique and strictly increasing within one
//!   Workspace, allocated atomically with the append from
//!   `workspace_event_counters` — the domain never assigns it (§7).
//! - Serialization limits (§5): total serialized Event ≤ 32 KiB,
//!   JSON nesting depth ≤ 8 from the root, payload-internal depth ≤ 3.
//!   A producer that cannot stay inside the bound fails the transition;
//!   it never truncates or silently drops fields.
//! - §6 exclusion: no token, credential, SecretReference value, raw
//!   Artifact body, raw filename, object-store key, connection string,
//!   provider credential, or unbounded untrusted text ever enters the
//!   payload — enforced by the sensitive-key denylist and leaf bounds.

use central_foundation::failure::Failure;
use central_foundation::identity::{
    AggregateId, CausationId, CommandId, CorrelationId, EventId, RunId, StepAttemptId, StepId,
    TaskId, WorkspaceId,
};
use time::OffsetDateTime;

/// Stable machine codes emitted by this domain.
pub mod codes {
    pub const EVENT_INVALID: &str = "event_invalid";
    pub const PAYLOAD_INVALID: &str = "event_payload_invalid";
    pub const PAYLOAD_TOO_LARGE: &str = "event_payload_too_large";
    pub const UNSANITIZED_PAYLOAD: &str = "event_unsanitized_payload";
    pub const SEQUENCE_UNASSIGNED: &str = "event_sequence_unassigned";
    pub const CURSOR_INVALID: &str = "event_cursor_invalid";
    pub const CURSOR_WORKSPACE_MISMATCH: &str = "event_cursor_workspace_mismatch";
}

/// The only schema version this contract defines (§2).
pub const SCHEMA_VERSION_V1: &str = "v1";

/// Total serialized Event ceiling — 32 KiB (§5, adapter-mapping §3.11
/// `payload` bound). The producer rejects before commit; an Event that
/// cannot fit must never be appended.
pub const MAX_EVENT_SERIALIZED_BYTES: usize = 32 * 1024;

/// JSON nesting depth ceiling measured from the root object (§5).
pub const MAX_ENVELOPE_DEPTH: usize = 8;

/// Maximum object-nesting depth *inside* `payload` itself (§4/§5).
pub const MAX_PAYLOAD_DEPTH: usize = 3;

/// Leaf-string bound inside the payload. Opaque ids (~36 B), state
/// names, reason codes, timestamps, and `sha256:` fingerprints (~71 B)
/// all fit; §6's "unbounded labels or untrusted user-provided text"
/// cannot. 256 B leaves headroom for bounded fingerprints.
pub const MAX_PAYLOAD_LEAF_BYTES: usize = 256;

/// Bound for `event_type`/`aggregate_type`/`actor_id`/state/reason
/// envelope text.
pub const MAX_ENVELOPE_FIELD_BYTES: usize = 256;

/// Keys that must never appear in any Event payload — the upstream
/// `sensitivePayloadKeys` denylist (internal/execution/domain.go),
/// matched case-insensitively at every nesting level.
const SENSITIVE_PAYLOAD_KEYS: [&str; 10] = [
    "access_token",
    "api_key",
    "api_token",
    "authorization",
    "credential",
    "password",
    "private_key",
    "secret",
    "secret_key",
    "token",
];

/// The allowlisted actor kinds of §3 — the only `actor.actor_kind`
/// values permitted. Display names, addresses, real identities, and
/// tokens are never actors.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActorKind {
    /// An authenticated local session.
    Session,
    /// A Central system component.
    System,
    /// The local executor.
    Executor,
}

impl ActorKind {
    /// Canonical wire text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::System => "system",
            Self::Executor => "executor",
        }
    }

    /// Parses the canonical text; everything else is rejected.
    pub fn parse(text: &str) -> Result<Self, Failure> {
        match text {
            "session" => Ok(Self::Session),
            "system" => Ok(Self::System),
            "executor" => Ok(Self::Executor),
            _ => Err(Failure::invalid(codes::EVENT_INVALID, "unknown actor kind")),
        }
    }
}

/// The §3 `actor` object — `actor_id` + `actor_kind` and nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventActor {
    /// Actor identity (bounded opaque text: a session or system
    /// identity, never a credential).
    pub actor_id: String,
    /// Actor kind.
    pub kind: ActorKind,
}

impl EventActor {
    /// Builds a validated actor.
    pub fn new(actor_id: impl Into<String>, kind: ActorKind) -> Result<Self, Failure> {
        let actor = Self {
            actor_id: actor_id.into(),
            kind,
        };
        if actor.actor_id.is_empty() || actor.actor_id.len() > MAX_ENVELOPE_FIELD_BYTES {
            return Err(Failure::invalid(
                codes::EVENT_INVALID,
                "actor_id must be 1..=256 bytes",
            ));
        }
        Ok(actor)
    }
}

/// The state-transition metadata of §2: what the aggregate moved from
/// and to, plus the safe reason code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateTransition {
    /// Aggregate state before the transition — `None` for creation
    /// (the envelope omits `prior_state`, never emits `null`
    /// gratuitously; a stored `None` serializes absent).
    pub prior_state: Option<String>,
    /// Aggregate state after the transition — required.
    pub next_state: String,
    /// Safe reason code (`approval`, `retry_delay`, `reconciliation`,
    /// …) — `None` when inapplicable.
    pub reason: Option<String>,
}

impl StateTransition {
    /// Builds a validated transition.
    pub fn new(
        prior_state: Option<String>,
        next_state: impl Into<String>,
        reason: Option<String>,
    ) -> Result<Self, Failure> {
        let transition = Self {
            prior_state,
            next_state: next_state.into(),
            reason,
        };
        for text in [
            transition.next_state.as_str(),
            transition.prior_state.as_deref().unwrap_or("x"),
            transition.reason.as_deref().unwrap_or("x"),
        ] {
            if text.is_empty() || text.len() > MAX_ENVELOPE_FIELD_BYTES {
                return Err(Failure::invalid(
                    codes::EVENT_INVALID,
                    "a state/reason field must be 1..=256 bytes",
                ));
            }
        }
        Ok(transition)
    }
}

/// Contextual aggregate lineage of §2 (all optional).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EventContext {
    /// Parent Task.
    pub task_id: Option<TaskId>,
    /// Parent Step.
    pub step_id: Option<StepId>,
    /// Parent StepAttempt or ToolCallAttempt.
    pub attempt_id: Option<StepAttemptId>,
}

/// A validated, bounded, sanitized Event payload (§4/§5/§6) — the
/// canonical JSON object bytes stored in `events.payload` together
/// with the envelope projection the adapter indexes.
///
/// Invariants enforced at construction:
///
/// - the bytes are one complete JSON object (no trailing content);
/// - a `type` discriminator string names the per-type schema (§4);
/// - no key at any depth is a denied sensitive key (§6);
/// - object nesting inside the payload is ≤ [`MAX_PAYLOAD_DEPTH`];
/// - leaf strings are ≤ [`MAX_PAYLOAD_LEAF_BYTES`];
/// - re-encoded canonical bytes ≤ [`MAX_EVENT_SERIALIZED_BYTES`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventPayload {
    bytes: Vec<u8>,
    payload_type: String,
}

impl EventPayload {
    /// Sanitizes raw producer bytes into a storable payload. Rejection
    /// is total — the upstream `sanitizePayload` contract: never
    /// truncate, never silently drop fields.
    pub fn sanitize(raw: &[u8]) -> Result<Self, Failure> {
        if raw.is_empty() || raw.len() > MAX_EVENT_SERIALIZED_BYTES {
            return Err(Failure::invalid(
                codes::PAYLOAD_TOO_LARGE,
                "the payload exceeds the serialized bound",
            ));
        }
        let value: serde_json::Value = serde_json::from_slice(raw).map_err(|_| {
            Failure::invalid(
                codes::PAYLOAD_INVALID,
                "the payload is not a complete JSON document",
            )
        })?;
        let object = value.as_object().ok_or_else(|| {
            Failure::invalid(codes::PAYLOAD_INVALID, "the payload is not a JSON object")
        })?;
        let payload_type = object
            .get("type")
            .and_then(|t| t.as_str())
            .filter(|s| !s.is_empty() && s.len() <= MAX_PAYLOAD_LEAF_BYTES)
            .ok_or_else(|| {
                Failure::invalid(
                    codes::PAYLOAD_INVALID,
                    "the payload lacks its type discriminator",
                )
            })?
            .to_owned();
        sanitize_object(object, 1)?;
        let encoded = serde_json::to_vec(object).map_err(|_| {
            Failure::invalid(codes::PAYLOAD_INVALID, "the payload cannot be re-encoded")
        })?;
        if encoded.len() > MAX_EVENT_SERIALIZED_BYTES {
            return Err(Failure::invalid(
                codes::PAYLOAD_TOO_LARGE,
                "the canonical payload exceeds the serialized bound",
            ));
        }
        Ok(Self {
            bytes: encoded,
            payload_type,
        })
    }

    /// Rehydrates a payload from canonical bytes previously written by
    /// a validated writer (the persistence boundary). The bytes are
    /// re-checked — a corrupted row cannot smuggle an unsanitized
    /// payload through (the upstream `NewEventPayload` + bytes-equal
    /// read rule).
    pub fn from_canonical(raw: &[u8]) -> Result<Self, Failure> {
        Self::sanitize(raw)
    }

    /// The canonical JSON object bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The payload `type` discriminator (e.g. `task.created.v1`).
    #[must_use]
    pub fn payload_type(&self) -> &str {
        &self.payload_type
    }
}

/// Recursive object validation: denylisted keys rejected
/// case-insensitively at every level; object depth bounded; leaf
/// strings bounded; arrays may contain only objects (mirroring the
/// upstream `sanitizeObject` shape rule).
fn sanitize_object(
    object: &serde_json::Map<String, serde_json::Value>,
    depth: usize,
) -> Result<(), Failure> {
    if depth > MAX_PAYLOAD_DEPTH {
        return Err(Failure::invalid(
            codes::PAYLOAD_INVALID,
            "payload nesting exceeds the depth bound",
        ));
    }
    for (key, value) in object {
        let normalized = key.to_lowercase();
        if SENSITIVE_PAYLOAD_KEYS.contains(&normalized.as_str()) {
            return Err(Failure::invalid(
                codes::UNSANITIZED_PAYLOAD,
                "the payload carries a denied sensitive key",
            ));
        }
        match value {
            serde_json::Value::Object(child) => sanitize_object(child, depth + 1)?,
            serde_json::Value::Array(items) => {
                if items.len() > 64 {
                    return Err(Failure::invalid(
                        codes::PAYLOAD_INVALID,
                        "payload arrays are bounded to 64 members",
                    ));
                }
                for item in items {
                    let child = item.as_object().ok_or_else(|| {
                        Failure::invalid(
                            codes::PAYLOAD_INVALID,
                            "payload arrays carry objects only",
                        )
                    })?;
                    sanitize_object(child, depth + 1)?;
                }
            }
            serde_json::Value::String(text) => {
                if text.len() > MAX_PAYLOAD_LEAF_BYTES {
                    return Err(Failure::invalid(
                        codes::PAYLOAD_TOO_LARGE,
                        "a payload leaf string exceeds its bound",
                    ));
                }
            }
            serde_json::Value::Number(_) | serde_json::Value::Bool(_) => {}
            serde_json::Value::Null => {}
        }
    }
    Ok(())
}

/// The immutable Phase-1 Event — one `central.events` row and its §2
/// wire envelope.
///
/// `sequence` is `None` until the persistence boundary allocates it
/// from `workspace_event_counters` inside the append transaction; an
/// Event intent is validated before sequence assignment and sealed
/// afterwards. A validated intent's serialized envelope is already
/// bounded — sequence assignment can never grow it past the limit
/// (the sequence occupies a fixed field and `u64::MAX` adds ≤ 20
/// bytes of headroom the validation accounts for).
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    /// Immutable Event identity.
    pub id: EventId,
    /// Owning Workspace — the only scope an Event is observable in.
    pub workspace_id: WorkspaceId,
    /// Durable Workspace-local sequence — `None` on an uncommitted
    /// intent, `Some` once allocated.
    pub sequence: Option<u64>,
    /// Discriminated Event type (`task.created`, `run.started`, …).
    pub event_type: String,
    /// Domain aggregate kind (`task`, `run`, `step`, …).
    pub aggregate_type: String,
    /// Aggregate identity within the Workspace.
    pub aggregate_id: AggregateId,
    /// Aggregate version after this transition.
    pub aggregate_version: u64,
    /// When the transition was accepted.
    pub occurred_at: OffsetDateTime,
    /// Scope-wide correlation identifier.
    pub correlation_id: Option<CorrelationId>,
    /// Immediate cause Event or command identity.
    pub causation_id: Option<CausationId>,
    /// The command receipt this transition answers, when command-driven.
    pub command_id: Option<CommandId>,
    /// Parent Run, when the Event belongs to one.
    pub run_id: Option<RunId>,
    /// Contextual lineage.
    pub context: EventContext,
    /// The §3 actor object.
    pub actor: EventActor,
    /// State-transition metadata.
    pub transition: StateTransition,
    /// The validated payload object.
    pub payload: EventPayload,
}

/// The uncommitted producer intent — everything [`Event`] carries
/// except the id and sequence the append path assigns.
#[derive(Debug, Clone, PartialEq)]
pub struct EventIntent {
    /// Owning Workspace.
    pub workspace_id: WorkspaceId,
    /// Discriminated Event type.
    pub event_type: String,
    /// Domain aggregate kind.
    pub aggregate_type: String,
    /// Aggregate identity.
    pub aggregate_id: AggregateId,
    /// Aggregate version after the transition.
    pub aggregate_version: u64,
    /// Acceptance time.
    pub occurred_at: OffsetDateTime,
    /// Scope-wide correlation identifier.
    pub correlation_id: Option<CorrelationId>,
    /// Immediate cause identity.
    pub causation_id: Option<CausationId>,
    /// The command receipt, when command-driven.
    pub command_id: Option<CommandId>,
    /// Parent Run.
    pub run_id: Option<RunId>,
    /// Contextual lineage.
    pub context: EventContext,
    /// Actor.
    pub actor: EventActor,
    /// Transition metadata.
    pub transition: StateTransition,
    /// Validated payload.
    pub payload: EventPayload,
}

impl EventIntent {
    /// Seals the intent into an immutable Event at the allocated
    /// Workspace-local sequence. The envelope is re-validated against
    /// the serialized bound before sealing — an intent that passed
    /// `validate` alone could still overflow once the fixed fields are
    /// written, and an oversized Event must never be appended (§5).
    pub fn seal(self, sequence: u64) -> Result<Event, Failure> {
        let event = Event {
            id: EventId::new(),
            workspace_id: self.workspace_id,
            sequence: Some(sequence),
            event_type: self.event_type,
            aggregate_type: self.aggregate_type,
            aggregate_id: self.aggregate_id,
            aggregate_version: self.aggregate_version,
            occurred_at: self.occurred_at,
            correlation_id: self.correlation_id,
            causation_id: self.causation_id,
            command_id: self.command_id,
            run_id: self.run_id,
            context: self.context,
            actor: self.actor,
            transition: self.transition,
            payload: self.payload,
        };
        event.validate()?;
        Ok(event)
    }
}

impl Event {
    /// Envelope validation: bounded fields plus the §5 serialized
    /// ceiling on the full envelope. Safe to call on committed Events
    /// (sequence present) and on intents about to be sealed
    /// (`seal` calls it with the sequence set).
    pub fn validate(&self) -> Result<(), Failure> {
        for (name, text) in [
            ("event_type", &self.event_type),
            ("aggregate_type", &self.aggregate_type),
        ] {
            if text.is_empty() || text.len() > MAX_ENVELOPE_FIELD_BYTES {
                return Err(Failure::invalid(
                    codes::EVENT_INVALID,
                    "an envelope text field must be 1..=256 bytes",
                ));
            }
            let _ = name;
        }
        let serialized = self.envelope_json()?;
        if serialized.len() > MAX_EVENT_SERIALIZED_BYTES {
            return Err(Failure::invalid(
                codes::PAYLOAD_TOO_LARGE,
                "the serialized envelope exceeds 32 KiB",
            ));
        }
        Ok(())
    }

    /// Serializes the §2 v1 envelope as canonical JSON bytes — the
    /// value stored in `events.payload` (a schema-versioned immutable
    /// envelope; the indexed columns are projections of it).
    pub fn envelope_json(&self) -> Result<Vec<u8>, Failure> {
        let mut envelope = serde_json::Map::new();
        envelope.insert(
            "event_id".into(),
            serde_json::Value::String(self.id.to_string()),
        );
        envelope.insert(
            "event_sequence".into(),
            match self.sequence {
                Some(sequence) => serde_json::Value::from(sequence),
                None => serde_json::Value::Null,
            },
        );
        envelope.insert(
            "schema_version".into(),
            serde_json::Value::String(SCHEMA_VERSION_V1.into()),
        );
        envelope.insert(
            "type".into(),
            serde_json::Value::String(self.event_type.clone()),
        );
        envelope.insert(
            "occurred_at".into(),
            serde_json::Value::String(
                self.occurred_at
                    .format(&time::format_description::well_known::Rfc3339)
                    .map_err(|_| {
                        Failure::internal(codes::EVENT_INVALID, "occurred_at is not representable")
                    })?,
            ),
        );
        envelope.insert(
            "workspace_id".into(),
            serde_json::Value::String(self.workspace_id.to_string()),
        );
        envelope.insert(
            "aggregate_type".into(),
            serde_json::Value::String(self.aggregate_type.clone()),
        );
        envelope.insert(
            "aggregate_id".into(),
            serde_json::Value::String(self.aggregate_id.to_string()),
        );
        envelope.insert(
            "aggregate_version".into(),
            serde_json::Value::from(self.aggregate_version),
        );
        if let Some(id) = self.correlation_id {
            envelope.insert(
                "correlation_id".into(),
                serde_json::Value::String(id.to_string()),
            );
        }
        if let Some(id) = self.causation_id {
            envelope.insert(
                "causation_id".into(),
                serde_json::Value::String(id.to_string()),
            );
        }
        if let Some(id) = self.command_id {
            envelope.insert(
                "command_id".into(),
                serde_json::Value::String(id.to_string()),
            );
        }
        if let Some(id) = self.run_id {
            envelope.insert("run_id".into(), serde_json::Value::String(id.to_string()));
        }
        if let Some(id) = self.context.task_id {
            envelope.insert("task_id".into(), serde_json::Value::String(id.to_string()));
        }
        if let Some(id) = self.context.step_id {
            envelope.insert("step_id".into(), serde_json::Value::String(id.to_string()));
        }
        if let Some(id) = self.context.attempt_id {
            envelope.insert(
                "attempt_id".into(),
                serde_json::Value::String(id.to_string()),
            );
        }
        if let Some(prior) = &self.transition.prior_state {
            envelope.insert(
                "prior_state".into(),
                serde_json::Value::String(prior.clone()),
            );
        }
        envelope.insert(
            "next_state".into(),
            serde_json::Value::String(self.transition.next_state.clone()),
        );
        if let Some(reason) = &self.transition.reason {
            envelope.insert("reason".into(), serde_json::Value::String(reason.clone()));
        }
        let mut actor = serde_json::Map::new();
        actor.insert(
            "actor_id".into(),
            serde_json::Value::String(self.actor.actor_id.clone()),
        );
        actor.insert(
            "actor_kind".into(),
            serde_json::Value::String(self.actor.kind.as_str().into()),
        );
        envelope.insert("actor".into(), serde_json::Value::Object(actor));
        let payload: serde_json::Value = serde_json::from_slice(self.payload.as_bytes())
            .map_err(|_| Failure::internal(codes::EVENT_INVALID, "stored payload is corrupt"))?;
        envelope.insert("payload".into(), payload);
        serde_json::to_vec(&serde_json::Value::Object(envelope)).map_err(|_| {
            Failure::internal(codes::EVENT_INVALID, "the envelope cannot be serialized")
        })
    }

    /// The durable `(workspace_id, event_sequence)` ordering key —
    /// `None` while uncommitted.
    #[must_use]
    pub fn sequence(&self) -> Option<u64> {
        self.sequence
    }

    /// Requires the committed sequence.
    pub fn committed_sequence(&self) -> Result<u64, Failure> {
        self.sequence.ok_or_else(|| {
            Failure::invalid(
                codes::SEQUENCE_UNASSIGNED,
                "the event has no allocated sequence",
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use central_foundation::failure::FailureKind;

    const T0: OffsetDateTime = OffsetDateTime::UNIX_EPOCH;

    fn intent() -> EventIntent {
        EventIntent {
            workspace_id: WorkspaceId::new(),
            event_type: "task.created".into(),
            aggregate_type: "task".into(),
            aggregate_id: AggregateId::new(),
            aggregate_version: 1,
            occurred_at: T0,
            correlation_id: Some(CorrelationId::new()),
            causation_id: Some(CausationId::new()),
            command_id: Some(CommandId::new()),
            run_id: Some(RunId::new()),
            context: EventContext {
                task_id: Some(TaskId::new()),
                step_id: None,
                attempt_id: None,
            },
            actor: EventActor::new("session:local", ActorKind::Session).unwrap(),
            transition: StateTransition::new(None, "created", None).unwrap(),
            payload: EventPayload::sanitize(
                br#"{"type":"task.created.v1","task_kind":"agent.run","task_count":1}"#,
            )
            .unwrap(),
        }
    }

    // -- payload ---------------------------------------------------------------

    #[test]
    fn payload_accepts_bounded_objects_and_canonicalizes() {
        let p = EventPayload::sanitize(
            br#"{"type":"task.created.v1","nested":{"a":{"leaf":"ok"}},"ids":["x","y"]}"#,
        )
        .unwrap_err();
        // arrays carry objects only — a string array is rejected
        assert_eq!(p.code(), codes::PAYLOAD_INVALID);

        let p =
            EventPayload::sanitize(br#"{"type":"task.created.v1","nested":{"a":{"leaf":"ok"}}}"#)
                .unwrap();
        assert_eq!(p.payload_type(), "task.created.v1");
        // canonical encoding: sorted keys, no whitespace
        let text = String::from_utf8(p.as_bytes().to_vec()).unwrap();
        assert_eq!(
            text,
            r#"{"nested":{"a":{"leaf":"ok"}},"type":"task.created.v1"}"#
        );
    }

    #[test]
    fn payload_rejects_malformed_trailing_nonobject_and_missing_type() {
        for raw in [
            &b"not json"[..],
            br#"{"type":"x"} trailing"#,
            br#"[{"type":"x"}]"#,
            br#"{"not_type":1}"#,
            br#"{"type":""}"#,
            br#"{"type":7}"#,
            &b""[..],
        ] {
            let err = EventPayload::sanitize(raw).unwrap_err();
            assert_eq!(err.kind(), FailureKind::Invalid, "{raw:?}");
        }
    }

    #[test]
    fn payload_denies_sensitive_keys_at_any_depth() {
        for key in ["token", "Secret", "API_KEY", "private_key", "Authorization"] {
            let raw = format!(r#"{{"type":"x","nested":{{"{key}":"hunter2"}}}}"#);
            let err = EventPayload::sanitize(raw.as_bytes()).unwrap_err();
            assert_eq!(err.code(), codes::UNSANITIZED_PAYLOAD, "{key}");
        }
    }

    #[test]
    fn payload_enforces_depth_and_leaf_bounds() {
        let too_deep = br#"{"type":"x","a":{"b":{"c":{"d":1}}}}"#;
        assert_eq!(
            EventPayload::sanitize(too_deep).unwrap_err().code(),
            codes::PAYLOAD_INVALID
        );
        let ok_depth = br#"{"type":"x","a":{"b":{"c":1}}}"#;
        EventPayload::sanitize(ok_depth).unwrap();

        let big_leaf = format!(r#"{{"type":"x","v":"{}"}}"#, "y".repeat(300));
        assert_eq!(
            EventPayload::sanitize(big_leaf.as_bytes())
                .unwrap_err()
                .code(),
            codes::PAYLOAD_TOO_LARGE
        );
    }

    // -- envelope ---------------------------------------------------------------

    #[test]
    fn sealed_event_serializes_the_v1_envelope() {
        let event = intent().seal(42).unwrap();
        let json: serde_json::Value =
            serde_json::from_slice(&event.envelope_json().unwrap()).unwrap();
        assert_eq!(json["schema_version"], "v1");
        assert_eq!(json["type"], "task.created");
        assert_eq!(json["event_sequence"], 42);
        assert_eq!(json["aggregate_type"], "task");
        assert_eq!(json["aggregate_version"], 1);
        assert_eq!(json["next_state"], "created");
        assert_eq!(json["actor"]["actor_kind"], "session");
        assert_eq!(json["payload"]["type"], "task.created.v1");
        // absent prior_state is omitted, never null (§2)
        assert!(json.get("prior_state").is_none());
        assert_eq!(event.committed_sequence().unwrap(), 42);
    }

    #[test]
    fn envelope_enforces_the_32kib_serialized_ceiling() {
        // A payload that fits its own 32 KiB bound can still overflow
        // once the fixed envelope fields are written — the producer
        // must reject at seal, never append a degraded Event (§5).
        let mut intent = intent();
        let mut members = String::from(r#""type":"x""#);
        for i in 0..125 {
            members.push_str(&format!(r#","k{i:03}":"{}""#, "z".repeat(250)));
        }
        let big = format!("{{{members}}}");
        assert!(big.len() < MAX_EVENT_SERIALIZED_BYTES);
        assert!(big.len() > MAX_EVENT_SERIALIZED_BYTES - 1024);
        intent.payload = EventPayload::sanitize(big.as_bytes()).unwrap();
        let event = intent.seal(1).unwrap_err();
        assert_eq!(event.code(), codes::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn actor_and_transition_are_bounded() {
        assert!(EventActor::new("", ActorKind::System).is_err());
        assert!(EventActor::new("x".repeat(300), ActorKind::System).is_err());
        assert_eq!(
            EventActor::new("a", ActorKind::Session)
                .unwrap()
                .kind
                .as_str(),
            "session"
        );
        assert!(StateTransition::new(None, "", None).is_err());
        assert!(StateTransition::new(Some("x".repeat(300)), "y", None).is_err());
    }

    #[test]
    fn sequence_is_unassigned_until_sealed() {
        let event = Event {
            id: EventId::new(),
            workspace_id: WorkspaceId::new(),
            sequence: None,
            event_type: "run.started".into(),
            aggregate_type: "run".into(),
            aggregate_id: AggregateId::new(),
            aggregate_version: 1,
            occurred_at: T0,
            correlation_id: None,
            causation_id: None,
            command_id: None,
            run_id: None,
            context: EventContext::default(),
            actor: EventActor::new("system", ActorKind::System).unwrap(),
            transition: StateTransition::new(None, "started", None).unwrap(),
            payload: EventPayload::sanitize(br#"{"type":"run.started.v1"}"#).unwrap(),
        };
        assert_eq!(
            event.committed_sequence().unwrap_err().code(),
            codes::SEQUENCE_UNASSIGNED
        );
    }
}
