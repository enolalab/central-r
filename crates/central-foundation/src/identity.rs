//! Opaque RFC 9562 UUIDv7 identity newtypes.
//!
//! Ports `central/internal/identity/identity.go`. `uuid::Uuid` stays
//! private to this module (rust-application-boundaries.md §1): every
//! capability sees only the newtypes below. Text form is always the
//! canonical lowercase 8-4-4-4-12 hyphenated representation; parsing is
//! strict — uppercase hex, braces, `urn:` prefixes, compact unhyphenated
//! text, nil UUIDs, non-v7 versions, and non-RFC 9562 variants are all
//! rejected.

use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use uuid::{Uuid, Variant};

/// Why an identity string was rejected by the strict parser.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdParseErrorKind {
    /// Not canonical lowercase hyphenated 8-4-4-4-12 UUID text
    /// (includes uppercase hex, braces, `urn:` prefixes, unhyphenated
    /// text, and malformed input).
    Malformed,
    /// Well-formed UUID text whose version is not 7.
    WrongVersion,
    /// Well-formed UUID text whose variant is not RFC 9562.
    WrongVariant,
    /// The nil (all-zero) UUID, which is never a valid identity.
    Nil,
}

impl fmt::Display for IdParseErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "not canonical lowercase RFC 9562 UUID text",
            Self::WrongVersion => "must be UUIDv7",
            Self::WrongVariant => "must be RFC 9562 variant",
            Self::Nil => "must be non-zero",
        })
    }
}

/// Error returned when an ID string fails strict UUIDv7 validation.
///
/// The raw input is never echoed into the error: untrusted text must not
/// reach logs or responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IdParseError {
    id_type: &'static str,
    kind: IdParseErrorKind,
}

impl IdParseError {
    const fn new(id_type: &'static str, kind: IdParseErrorKind) -> Self {
        Self { id_type, kind }
    }

    /// Name of the ID type that rejected the input.
    #[must_use]
    pub const fn id_type(&self) -> &'static str {
        self.id_type
    }

    /// Why the input was rejected.
    #[must_use]
    pub const fn kind(&self) -> IdParseErrorKind {
        self.kind
    }
}

impl fmt::Display for IdParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "identity: invalid {}: {}", self.id_type, self.kind)
    }
}

impl std::error::Error for IdParseError {}

/// True iff `text` is exactly the canonical lowercase hyphenated
/// 8-4-4-4-12 form — the only accepted on-wire representation.
fn is_canonical_uuid_text(text: &str) -> bool {
    const HYPHEN_POSITIONS: [usize; 4] = [8, 13, 18, 23];
    let bytes = text.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| {
            if HYPHEN_POSITIONS.contains(&index) {
                *byte == b'-'
            } else {
                matches!(byte, b'0'..=b'9' | b'a'..=b'f')
            }
        })
}

/// Shared strict validator for every ID newtype: canonical syntax, then
/// non-nil, then version 7, then RFC 9562 variant.
fn parse_uuid_v7(id_type: &'static str, text: &str) -> Result<Uuid, IdParseError> {
    if !is_canonical_uuid_text(text) {
        return Err(IdParseError::new(id_type, IdParseErrorKind::Malformed));
    }
    let uuid = Uuid::parse_str(text)
        .map_err(|_| IdParseError::new(id_type, IdParseErrorKind::Malformed))?;
    // Nil before version: the all-zero UUID would otherwise report the
    // less precise "must be UUIDv7" (upstream intent is "must be non-zero").
    if uuid.is_nil() {
        return Err(IdParseError::new(id_type, IdParseErrorKind::Nil));
    }
    if uuid.get_version_num() != 7 {
        return Err(IdParseError::new(id_type, IdParseErrorKind::WrongVersion));
    }
    if uuid.get_variant() != Variant::RFC4122 {
        return Err(IdParseError::new(id_type, IdParseErrorKind::WrongVariant));
    }
    Ok(uuid)
}

/// Generates one opaque UUIDv7 identity newtype.
///
/// The wrapped `uuid::Uuid` field is private — it cannot escape this
/// module. Byte-level access for the PostgreSQL adapter boundary is
/// through `as_bytes` / `from_trusted_db_bytes` only.
macro_rules! define_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        ///
        /// Opaque RFC 9562 UUIDv7 newtype; see
        /// `central_foundation::identity`.
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(Uuid);

        impl $name {
            /// Generates a fresh UUIDv7 identity.
            ///
            /// `Default` is deliberately absent: there is no zero
            /// identity — nil UUIDs are rejected at every boundary, so a
            /// default-constructed ID would be invalid by construction.
            #[allow(clippy::new_without_default)]
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            /// Strict RFC 9562 UUIDv7 parse: canonical lowercase
            /// 8-4-4-4-12 text, version 7, RFC 9562 variant, non-nil.
            pub fn parse(text: &str) -> Result<Self, IdParseError> {
                Ok(Self(parse_uuid_v7(stringify!($name), text)?))
            }

            /// The 16 raw bytes, for crossing the persistence adapter
            /// boundary.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 16] {
                self.0.as_bytes()
            }

            /// Reconstructs an ID from raw bytes loaded through the
            /// persistence adapter boundary.
            ///
            /// Trusted boundary: the value was durably stored by a
            /// validated writer, so no re-validation is performed. Never
            /// call this on untrusted input — use `parse` instead.
            #[must_use]
            pub const fn from_trusted_db_bytes(bytes: [u8; 16]) -> Self {
                Self(Uuid::from_bytes(bytes))
            }

            /// Whether the underlying value is the nil (all-zero) UUID.
            /// Unreachable through `new`/`parse`; only a corrupted
            /// `from_trusted_db_bytes` row can produce it.
            #[must_use]
            pub fn is_nil(&self) -> bool {
                self.0.is_nil()
            }
        }

        impl FromStr for $name {
            type Err = IdParseError;

            /// Same strict rules as `parse`.
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::parse(s)
            }
        }

        impl fmt::Display for $name {
            /// Canonical lowercase hyphenated text — the inverse of
            /// `parse`.
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.0)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.0.to_string())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = String::deserialize(deserializer)?;
                Self::parse(&text).map_err(de::Error::custom)
            }
        }
    };
}

define_id! {
    /// Identifies the Central instance.
    InstanceId
}

define_id! {
    /// Identifies one Workspace.
    WorkspaceId
}

define_id! {
    /// Identifies one Task.
    TaskId
}

define_id! {
    /// Identifies one Run.
    RunId
}

define_id! {
    /// Identifies one logical execution step.
    StepId
}

define_id! {
    /// Identifies one physical attempt of a logical step.
    StepAttemptId
}

define_id! {
    /// Identifies one logical tool call.
    ToolCallId
}

define_id! {
    /// Identifies one physical tool call attempt.
    ToolCallAttemptId
}

define_id! {
    /// Identifies immutable approval evidence.
    ApprovalId
}

define_id! {
    /// Identifies immutable checkpoint evidence.
    CheckpointId
}

define_id! {
    /// Identifies one Artifact.
    ArtifactId
}

define_id! {
    /// Identifies immutable Event evidence.
    EventId
}

define_id! {
    /// Identifies immutable execution-event evidence.
    ExecutionEventId
}

define_id! {
    /// Identifies one session.
    SessionId
}

define_id! {
    /// Identifies one bootstrap generation row.
    BootstrapGenerationId
}

define_id! {
    /// Identifies one operator operation.
    OperationId
}

define_id! {
    /// Identifies one backup.
    BackupId
}

define_id! {
    /// Identifies one verified restore ticket.
    RestoreTicketId
}

define_id! {
    /// Identifies one harness session attempt (ADR 0035): one launch or
    /// resume of an external harness process tree for one Run.
    HarnessAttemptId
}

define_id! {
    /// Identifies one captured harness event.
    HarnessEventId
}

define_id! {
    /// Identifies one harness permission approval.
    HarnessPermissionApprovalId
}

define_id! {
    /// Identifies one workflow graph node (b33).
    WorkflowNodeId
}

define_id! {
    /// Identifies one workflow graph edge (b33).
    WorkflowEdgeId
}

define_id! {
    /// Identifies one canonical `run_events` journal entry (b33).
    RunEventId
}

define_id! {
    /// Identifies one session attempt.
    SessionAttemptId
}

define_id! {
    /// Identifies one registered scheduler worker (b35).
    WorkerId
}

define_id! {
    /// Identifies one scheduler node lease (b35).
    NodeLeaseId
}

define_id! {
    /// Identifies one resume checkpoint (b36).
    ResumeCheckpointId
}

define_id! {
    /// Identifies one `event_outbox` record (b37).
    OutboxEventId
}

define_id! {
    /// Identifies one `outbox_workspace_work` intent row — the execution
    /// outbox (upstream `OutboxID`, `OutboxIntent.ID`).
    OutboxId
}

define_id! {
    /// Identifies the domain aggregate an Event concerns. Events store the
    /// bare aggregate identity; the aggregate *kind* travels separately as
    /// `aggregate_type` (docs/events/v1.md §2).
    AggregateId
}

define_id! {
    /// Identifies one `command_receipts` row — the durable idempotency
    /// receipt of an accepted command (`events.command_id` references it).
    CommandId
}

define_id! {
    /// Identifies one generated `central.config/v1` configuration binding,
    /// recorded on the genesis `InstanceBinding`.
    ConfigBindingId
}

define_id! {
    /// Identifies one `central.secret_use` audit-evidence row — the
    /// durable record that a SecretReference was used under an
    /// authorization decision (adapter-mapping §3.19). The row's `id`
    /// column is a plain `uuid` in the baseline schema.
    SecretUseEvidenceId
}

define_id! {
    /// The scope-wide correlation identifier carried by an Event
    /// (`events.correlation_id`, `command_receipts.correlation_id`) —
    /// an opaque UUID relating causally-linked commands and Events.
    CorrelationId
}

define_id! {
    /// The immediate-cause identifier carried by an Event
    /// (`events.causation_id`): the Event or command identity that
    /// directly caused this transition.
    CausationId
}

/// The b20 sentinel workspace row's fixed identity:
/// `019fdc8d-e33a-76ed-9ef0-a0d9fe92e54a`.
///
/// The single admitted non-generated workspace identity, matching the
/// upstream `SentinelWorkspaceID` constant consumed by
/// `b20_sentinel_workspace_id.go` (the plan text had drifted to a
/// different value). It is itself a valid UUIDv7, so the strict parser
/// admits it with no special-casing.
pub const SENTINEL_WORKSPACE_ID: WorkspaceId = WorkspaceId::from_trusted_db_bytes([
    0x01, 0x9f, 0xdc, 0x8d, 0xe3, 0x3a, 0x76, 0xed, 0x9e, 0xf0, 0xa0, 0xd9, 0xfe, 0x92, 0xe5, 0x4a,
]);

impl WorkspaceId {
    /// The b20 sentinel workspace ID — see [`SENTINEL_WORKSPACE_ID`].
    #[must_use]
    pub const fn sentinel() -> Self {
        SENTINEL_WORKSPACE_ID
    }

    /// Whether this is the b20 sentinel workspace ID.
    #[must_use]
    pub fn is_sentinel(&self) -> bool {
        *self == SENTINEL_WORKSPACE_ID
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A valid lowercase RFC 9562 UUIDv7 in canonical text form.
    const VALID_V7: &str = "018f3b2a-1c4d-7e9f-8a1b-2c3d4e5f6a7b";
    /// The upstream b20 sentinel value (valid v7, RFC 9562 variant).
    const SENTINEL_TEXT: &str = "019fdc8d-e33a-76ed-9ef0-a0d9fe92e54a";

    /// Runs the shared identity contract against one concrete newtype:
    /// strict parse, lowercase-only canonical form, Display/FromStr
    /// round-trip, JSON round-trip, and byte-boundary round-trip.
    fn assert_id_contract<T>()
    where
        T: FromStr<Err = IdParseError>
            + fmt::Display
            + fmt::Debug
            + Copy
            + PartialEq
            + Ord
            + Serialize
            + for<'de> Deserialize<'de>,
    {
        let parsed = VALID_V7.parse::<T>().unwrap();

        // Display renders the canonical lowercase text exactly.
        assert_eq!(parsed.to_string(), VALID_V7);

        // FromStr/Display round-trip.
        let round_tripped: T = parsed.to_string().parse().unwrap();
        assert_eq!(round_tripped, parsed);

        // JSON round-trip — serialized form is the quoted lowercase text.
        let json = serde_json::to_string(&parsed).unwrap();
        assert_eq!(json, format!("\"{VALID_V7}\""));
        let de: T = serde_json::from_str(&json).unwrap();
        assert_eq!(de, parsed);

        // Rejections.
        assert!(VALID_V7.to_uppercase().parse::<T>().is_err());
        assert!("00000000-0000-0000-0000-000000000000".parse::<T>().is_err());
        assert!("550e8400-e29b-41d4-a716-446655440000".parse::<T>().is_err()); // v4
        assert!("018f0000-0000-7000-c000-000000000001".parse::<T>().is_err()); // MS variant
        assert!("018f3b2a1c4d7e9f8a1b2c3d4e5f6a7b".parse::<T>().is_err()); // unhyphenated
        assert!(format!("{{{VALID_V7}}}").parse::<T>().is_err()); // braces
        assert!(format!("urn:uuid:{VALID_V7}").parse::<T>().is_err()); // urn
        assert!("not-a-uuid".parse::<T>().is_err());
    }

    /// Runs the byte-boundary contract for one concrete newtype.
    fn assert_byte_boundary<T>(ctor: fn([u8; 16]) -> T)
    where
        T: Copy + PartialEq + Ord + fmt::Display + fmt::Debug,
    {
        let bytes: [u8; 16] = [
            0x01, 0x8f, 0x3b, 0x2a, 0x1c, 0x4d, 0x7e, 0x9f, 0x8a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f,
            0x6a, 0x7b,
        ];
        let id = ctor(bytes);
        assert_eq!(id.to_string(), VALID_V7);
    }

    #[test]
    fn every_id_type_satisfies_the_strict_contract() {
        assert_id_contract::<InstanceId>();
        assert_id_contract::<WorkspaceId>();
        assert_id_contract::<TaskId>();
        assert_id_contract::<RunId>();
        assert_id_contract::<StepId>();
        assert_id_contract::<StepAttemptId>();
        assert_id_contract::<ToolCallId>();
        assert_id_contract::<ToolCallAttemptId>();
        assert_id_contract::<ApprovalId>();
        assert_id_contract::<CheckpointId>();
        assert_id_contract::<ArtifactId>();
        assert_id_contract::<EventId>();
        assert_id_contract::<ExecutionEventId>();
        assert_id_contract::<SessionId>();
        assert_id_contract::<BootstrapGenerationId>();
        assert_id_contract::<OperationId>();
        assert_id_contract::<BackupId>();
        assert_id_contract::<RestoreTicketId>();
        assert_id_contract::<HarnessAttemptId>();
        assert_id_contract::<HarnessEventId>();
        assert_id_contract::<HarnessPermissionApprovalId>();
        assert_id_contract::<WorkflowNodeId>();
        assert_id_contract::<WorkflowEdgeId>();
        assert_id_contract::<RunEventId>();
        assert_id_contract::<SessionAttemptId>();
        assert_id_contract::<WorkerId>();
        assert_id_contract::<NodeLeaseId>();
        assert_id_contract::<ResumeCheckpointId>();
        assert_id_contract::<OutboxEventId>();
        assert_id_contract::<OutboxId>();
        assert_id_contract::<AggregateId>();
        assert_id_contract::<CommandId>();
        assert_id_contract::<ConfigBindingId>();
        assert_id_contract::<SecretUseEvidenceId>();
        assert_id_contract::<CorrelationId>();
        assert_id_contract::<CausationId>();
    }

    #[test]
    fn trusted_db_bytes_round_trip_and_ordering() {
        assert_byte_boundary::<WorkspaceId>(WorkspaceId::from_trusted_db_bytes);
        let low = TaskId::from_trusted_db_bytes([0x00; 16]);
        let high = TaskId::from_trusted_db_bytes([0xff; 16]);
        assert!(low < high);
        assert_eq!(TaskId::from_trusted_db_bytes(*low.as_bytes()), low);
    }

    #[test]
    fn new_generates_uuidv7_canonical_text() {
        let id = TaskId::new();
        let text = id.to_string();
        // Generated IDs parse back through the strict validator — proof
        // they are canonical lowercase v7 / RFC 9562 / non-nil.
        assert_eq!(TaskId::parse(&text).unwrap(), id);
        assert_eq!(text.len(), 36);
        assert_ne!(TaskId::new(), TaskId::new());
    }

    #[test]
    fn parse_error_kinds_are_precise() {
        let nil = "00000000-0000-0000-0000-000000000000"
            .parse::<TaskId>()
            .unwrap_err();
        assert_eq!(nil.kind(), IdParseErrorKind::Nil);
        assert_eq!(nil.id_type(), "TaskId");

        let v4 = "550e8400-e29b-41d4-a716-446655440000"
            .parse::<TaskId>()
            .unwrap_err();
        assert_eq!(v4.kind(), IdParseErrorKind::WrongVersion);

        let variant = "018f0000-0000-7000-c000-000000000001"
            .parse::<TaskId>()
            .unwrap_err();
        assert_eq!(variant.kind(), IdParseErrorKind::WrongVariant);

        let upper = "018F0000-0000-7000-8000-000000000001"
            .parse::<TaskId>()
            .unwrap_err();
        assert_eq!(upper.kind(), IdParseErrorKind::Malformed);
    }

    #[test]
    fn parse_error_never_echoes_untrusted_input() {
        let sensitive = "deadbeef-dead-beef-dead-beefdeadbeef";
        let err = sensitive.parse::<SessionId>().unwrap_err();
        assert!(!err.to_string().contains(sensitive));
    }

    #[test]
    fn sentinel_workspace_id_is_valid_v7_and_admitted() {
        assert_eq!(SENTINEL_WORKSPACE_ID.to_string(), SENTINEL_TEXT);
        assert_eq!(WorkspaceId::sentinel(), SENTINEL_WORKSPACE_ID);
        assert!(SENTINEL_WORKSPACE_ID.is_sentinel());
        assert!(!WorkspaceId::new().is_sentinel());
        assert_eq!(
            WorkspaceId::parse(SENTINEL_TEXT).unwrap(),
            SENTINEL_WORKSPACE_ID
        );
        assert_eq!(
            SENTINEL_WORKSPACE_ID.as_bytes(),
            &[
                0x01, 0x9f, 0xdc, 0x8d, 0xe3, 0x3a, 0x76, 0xed, 0x9e, 0xf0, 0xa0, 0xd9, 0xfe, 0x92,
                0xe5, 0x4a
            ]
        );
    }
}
