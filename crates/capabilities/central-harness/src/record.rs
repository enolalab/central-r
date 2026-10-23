//! The bounded per-event record — the port of
//! `internal/harness/record.go`. [`EventRecord`] is the metadata
//! persisted for one normalized event (governing spec §6: no payloads in
//! the database): ids, statuses, the raw frame's size and keyed digest,
//! and nothing else — no message, reasoning, tool input or output,
//! permission resources, plan, warning, retry or terminal reason
//! content.

use std::fmt;

use central_foundation::failure::Failure;
use central_foundation::identity::HarnessAttemptId;
use time::OffsetDateTime;

use crate::approval::compute_input_mac;
use crate::domain::{Terminal, TerminalStatus, codes, is_zero_time};
use crate::event::{Event, EventKind, EventPayload, PermissionOutcome, ToolStatus};

/// The bounded metadata persisted for one normalized event — upstream
/// `EventRecord`. No serde: it is persisted as bounded metadata columns
/// upstream, and a derived JSON encoding (`raw_sha256` as a number
/// array) would contradict the digest's hex `Display` convention.
#[derive(Clone, PartialEq)]
pub struct EventRecord {
    /// The attempt the event belongs to.
    pub attempt: HarnessAttemptId,
    /// The per-attempt sequence number.
    pub seq: u64,
    /// The payload kind.
    pub kind: EventKind,
    /// When the adapter observed the event.
    pub at: OffsetDateTime,
    /// The harness session id — never printed (see `Display`).
    pub harness_session_id: String,
    /// The raw frame's size in bytes.
    pub raw_size: i64,
    /// HMAC-SHA256 of the raw frame under the serve process's
    /// per-process input-MAC key (harness phase 3c), not its plain
    /// SHA-256: a frame can carry a tool input, a tool result or a
    /// message with a secret, and a plain hash would let anyone who
    /// reads the database confirm a guessed low-entropy one. The key is
    /// never stored, so the digest identifies a frame only within the
    /// process that recorded it (the append replay check); the column
    /// keeps its name.
    pub raw_sha256: [u8; 32],
    /// The tool call id, when the payload carries one.
    pub tool_call_id: String,
    /// The tool name, when the payload carries one.
    pub tool_name: String,
    /// The tool outcome, when the payload carries one.
    pub tool_status: ToolStatus,
    /// The permission request id, when the payload carries one.
    pub permission_request_id: String,
    /// The permission outcome, when the payload carries one.
    pub permission_outcome: PermissionOutcome,
    /// The terminal status, when the payload carries one.
    pub terminal_status: TerminalStatus,
}

impl Default for EventRecord {
    /// The Go zero value `EventRecord{}` — nil attempt, unset statuses.
    fn default() -> Self {
        Self {
            attempt: HarnessAttemptId::from_trusted_db_bytes([0; 16]),
            seq: 0,
            kind: EventKind::Unset,
            at: crate::domain::ZERO_TIME,
            harness_session_id: String::new(),
            raw_size: 0,
            raw_sha256: [0; 32],
            tool_call_id: String::new(),
            tool_name: String::new(),
            tool_status: ToolStatus::Unset,
            permission_request_id: String::new(),
            permission_outcome: PermissionOutcome::Unset,
            terminal_status: TerminalStatus::Unset,
        }
    }
}

/// Upstream `RecordOf`: validates `e` and derives its record, keying the
/// raw frame's digest with `digest_key` (at least
/// [`crate::approval::MIN_INPUT_MAC_KEY_BYTES`]; see
/// [`EventRecord::raw_sha256`]). Pure.
pub fn record_of(e: &Event, digest_key: &[u8]) -> Result<EventRecord, Failure> {
    e.validate()?;
    let digest = compute_input_mac(digest_key, &e.raw)
        .map_err(|err| Failure::invalid(codes::INVALID_EVENT, err.message()))?;
    let payload = e
        .payload
        .as_ref()
        // `validate` above guarantees a payload is present.
        .ok_or_else(|| Failure::invalid(codes::INVALID_EVENT, "missing payload"))?;
    let mut r = EventRecord {
        attempt: e.attempt,
        seq: e.seq,
        kind: payload.event_kind(),
        at: e.at,
        harness_session_id: e.harness_session_id.clone(),
        raw_size: e.raw.len() as i64,
        raw_sha256: digest.0,
        ..EventRecord::default()
    };
    match payload {
        EventPayload::ToolCall(p) => {
            r.tool_call_id = p.id.clone();
            r.tool_name = p.name.clone();
        }
        EventPayload::ToolResult(p) => {
            r.tool_call_id = p.id.clone();
            r.tool_status = p.status;
        }
        EventPayload::PermissionRequested(p) => {
            // The tool call id is metadata; the tool input never is
            // (harness phase 3c decision 5).
            r.permission_request_id = p.request_id.clone();
            r.tool_call_id = p.tool_call_id.clone();
            r.tool_name = p.tool.clone();
        }
        EventPayload::PermissionResolved(p) => {
            r.permission_request_id = p.request_id.clone();
            r.permission_outcome = p.decision;
        }
        EventPayload::TerminalReported(p) => {
            r.terminal_status = p.terminal.status;
        }
        _ => {}
    }
    Ok(r)
}

impl EventRecord {
    /// Upstream `EventRecord.Validate`: the record's envelope and its
    /// optional statuses. A store runs it before every write, because a
    /// record need not come from [`record_of`].
    pub fn validate(&self) -> Result<(), Failure> {
        if self.attempt.is_nil() {
            return Err(Failure::invalid(
                codes::INVALID_EVENT,
                "record has a zero attempt",
            ));
        }
        if self.seq < 1 {
            return Err(Failure::invalid(
                codes::INVALID_EVENT,
                "record seq must be >= 1",
            ));
        }
        if !self.kind.known() {
            return Err(Failure::invalid(
                codes::INVALID_EVENT,
                format!("unknown event kind {}", self.kind.as_str()),
            ));
        }
        if is_zero_time(self.at) {
            return Err(Failure::invalid(
                codes::INVALID_EVENT,
                "record has a zero timestamp",
            ));
        }
        if self.raw_size < 1 || self.raw_sha256 == [0; 32] {
            return Err(Failure::invalid(
                codes::INVALID_EVENT,
                "record requires a raw size and digest",
            ));
        }
        if !matches!(
            self.tool_status,
            ToolStatus::Unset
                | ToolStatus::Ok
                | ToolStatus::Error
                | ToolStatus::Denied
                | ToolStatus::CutOff
        ) {
            return Err(Failure::invalid(
                codes::INVALID_EVENT,
                format!("unknown tool status {}", self.tool_status.as_str()),
            ));
        }
        if !matches!(
            self.permission_outcome,
            PermissionOutcome::Unset
                | PermissionOutcome::Allowed
                | PermissionOutcome::Denied
                | PermissionOutcome::Timeout
        ) {
            return Err(Failure::invalid(
                codes::INVALID_EVENT,
                format!(
                    "unknown permission outcome {}",
                    self.permission_outcome.as_str()
                ),
            ));
        }
        if self.terminal_status != TerminalStatus::Unset {
            let terminal = Terminal {
                status: self.terminal_status,
                ..Terminal::default()
            };
            if terminal.state().is_err() {
                return Err(Failure::invalid(
                    codes::INVALID_EVENT,
                    format!("unknown terminal status {}", self.terminal_status.as_str()),
                ));
            }
        }
        Ok(())
    }
}

impl fmt::Display for EventRecord {
    /// Prints the envelope and only an 8-hex-digit digest prefix; it
    /// never prints the harness session id — upstream `String`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut prefix = String::with_capacity(8);
        for b in &self.raw_sha256[..4] {
            prefix.push_str(&format!("{b:02x}"));
        }
        write!(
            f,
            "harness.EventRecord{{Attempt:{} Seq:{} Kind:{} RawSize:{} RawSHA256:{}…}}",
            self.attempt, self.seq, self.kind, self.raw_size, prefix
        )
    }
}

impl fmt::Debug for EventRecord {
    /// Matches `Display` so `{:?}` never prints more either — upstream
    /// `GoString`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use central_foundation::identity::HarnessAttemptId;
    use sha2::{Digest, Sha256};
    use time::macros::datetime;

    use super::*;
    use crate::domain::{Terminal, TerminalStatus, codes};
    use crate::event::*;
    use crate::testkit::{Mutation, TEST_DIGEST_KEY, is_code, nil_attempt_id};

    // Ports upstream `validEvent` (shared by record tests).
    fn valid_event(payload: EventPayload) -> Event {
        Event {
            attempt: HarnessAttemptId::new(),
            seq: 1,
            at: datetime!(2026-09-27 00:00:00 UTC),
            harness_session_id: String::new(),
            raw: br#"{"frame":1}"#.to_vec(),
            payload: Some(payload),
        }
    }

    const SECRET: &str = "sk-ant-echoed-credential";

    // Ports upstream `TestRecordOfDerivesBoundedMetadataOnly`.
    #[test]
    fn record_of_derives_bounded_metadata_only() {
        let cases: [(EventPayload, EventRecord); 12] = [
            (
                EventPayload::SessionStarted(SessionStarted {
                    harness_session_id: "s1".to_string(),
                    harness_version: "2.1.0".to_string(),
                    model: SECRET.to_string(),
                    tools: vec![SECRET.to_string()],
                    reported_capabilities: Vec::new(),
                }),
                EventRecord {
                    kind: EventKind::SessionStarted,
                    ..EventRecord::default()
                },
            ),
            (
                EventPayload::Message(Message {
                    role: MessageRole::Assistant,
                    text: SECRET.to_string(),
                    partial: false,
                }),
                EventRecord {
                    kind: EventKind::Message,
                    ..EventRecord::default()
                },
            ),
            (
                EventPayload::Reasoning(Reasoning {
                    text: SECRET.to_string(),
                }),
                EventRecord {
                    kind: EventKind::Reasoning,
                    ..EventRecord::default()
                },
            ),
            (
                EventPayload::ToolCall(ToolCall {
                    id: "t1".to_string(),
                    name: "Bash".to_string(),
                    input: SECRET.as_bytes().to_vec(),
                    ..ToolCall::default()
                }),
                EventRecord {
                    kind: EventKind::ToolCall,
                    tool_call_id: "t1".to_string(),
                    tool_name: "Bash".to_string(),
                    ..EventRecord::default()
                },
            ),
            (
                EventPayload::ToolResult(ToolResult {
                    id: "t1".to_string(),
                    status: ToolStatus::Denied,
                    output: SECRET.as_bytes().to_vec(),
                }),
                EventRecord {
                    kind: EventKind::ToolResult,
                    tool_call_id: "t1".to_string(),
                    tool_status: ToolStatus::Denied,
                    ..EventRecord::default()
                },
            ),
            (
                EventPayload::PermissionRequested(PermissionRequested {
                    request_id: "p1".to_string(),
                    tool: "Bash".to_string(),
                    resources: vec![SECRET.to_string()],
                    options: vec![SECRET.to_string()],
                    ..PermissionRequested::default()
                }),
                EventRecord {
                    kind: EventKind::PermissionRequested,
                    permission_request_id: "p1".to_string(),
                    tool_name: "Bash".to_string(),
                    ..EventRecord::default()
                },
            ),
            (
                EventPayload::PermissionResolved(PermissionResolved {
                    request_id: "p1".to_string(),
                    decision: PermissionOutcome::Timeout,
                    decided_by: "op".to_string(),
                }),
                EventRecord {
                    kind: EventKind::PermissionResolved,
                    permission_request_id: "p1".to_string(),
                    permission_outcome: PermissionOutcome::Timeout,
                    ..EventRecord::default()
                },
            ),
            (
                EventPayload::Plan(Plan {
                    entries: vec![SECRET.to_string()],
                }),
                EventRecord {
                    kind: EventKind::Plan,
                    ..EventRecord::default()
                },
            ),
            (
                EventPayload::UsageReport(UsageReport {
                    usage: Usage {
                        tokens_in: 5,
                        scope: UsageScope::Step,
                        ..Usage::default()
                    },
                }),
                EventRecord {
                    kind: EventKind::UsageReport,
                    ..EventRecord::default()
                },
            ),
            (
                EventPayload::Retry(Retry {
                    reason: SECRET.to_string(),
                }),
                EventRecord {
                    kind: EventKind::Retry,
                    ..EventRecord::default()
                },
            ),
            (
                EventPayload::Warning(Warning {
                    message: SECRET.to_string(),
                }),
                EventRecord {
                    kind: EventKind::Warning,
                    ..EventRecord::default()
                },
            ),
            (
                EventPayload::TerminalReported(TerminalReported {
                    terminal: Terminal {
                        status: TerminalStatus::MaxTurns,
                        reason: SECRET.to_string(),
                        exit_code: Some(2),
                    },
                }),
                EventRecord {
                    kind: EventKind::TerminalReported,
                    terminal_status: TerminalStatus::MaxTurns,
                    ..EventRecord::default()
                },
            ),
        ];
        for (payload, mut want) in cases {
            let mut e = valid_event(payload.clone());
            e.seq = 7;
            e.harness_session_id = "s1".to_string();
            e.raw = format!(r#"{{"frame":"{SECRET}"}}"#).into_bytes();
            let got = record_of(&e, TEST_DIGEST_KEY).unwrap();
            want.attempt = e.attempt;
            want.seq = 7;
            want.at = e.at;
            want.harness_session_id = "s1".to_string();
            want.raw_size = e.raw.len() as i64;
            want.raw_sha256 = crate::approval::compute_input_mac(TEST_DIGEST_KEY, &e.raw)
                .unwrap()
                .0;
            assert_ne!(
                want.raw_sha256,
                <[u8; 32]>::from(Sha256::digest(&e.raw)),
                "{}: the frame digest is its plain SHA-256",
                payload.event_kind()
            );
            assert_eq!(got, want, "{}: record differs", payload.event_kind());
            assert!(
                got.validate().is_ok(),
                "{}: derived record invalid",
                payload.event_kind()
            );
            // No field of the record may carry payload or frame content.
            for field in [
                got.tool_call_id.as_str(),
                got.tool_name.as_str(),
                got.permission_request_id.as_str(),
            ] {
                assert!(
                    !field.contains(SECRET),
                    "{}: record copied sensitive content",
                    payload.event_kind()
                );
            }
        }
        let err = record_of(
            &valid_event(EventPayload::ToolCall(ToolCall {
                id: "t1".to_string(),
                ..ToolCall::default()
            })),
            TEST_DIGEST_KEY,
        )
        .unwrap_err();
        assert!(is_code(&err, codes::INVALID_EVENT), "invalid event: {err}");
    }

    // Ports upstream `TestEventRecordValidate`.
    #[test]
    fn event_record_validate() {
        let e = valid_event(EventPayload::ToolResult(ToolResult {
            id: "t1".to_string(),
            status: ToolStatus::Ok,
            ..ToolResult::default()
        }));
        let base = record_of(&e, TEST_DIGEST_KEY).unwrap();
        let mutations: [Mutation<EventRecord>; 9] = [
            ("zero attempt", |r| r.attempt = nil_attempt_id()),
            ("zero seq", |r| r.seq = 0),
            ("unknown kind", |r| r.kind = EventKind::parse("chatter")),
            ("zero time", |r| r.at = crate::domain::ZERO_TIME),
            ("empty raw", |r| r.raw_size = 0),
            ("zero digest", |r| r.raw_sha256 = [0; 32]),
            ("bad tool status", |r| {
                r.tool_status = ToolStatus::parse("maybe")
            }),
            ("bad outcome", |r| {
                r.permission_outcome = PermissionOutcome::parse("perhaps")
            }),
            ("bad terminal", |r| {
                r.terminal_status = TerminalStatus::parse("boom")
            }),
        ];
        for (name, mutate) in mutations {
            let mut r = base.clone();
            mutate(&mut r);
            let err = r.validate().unwrap_err();
            assert!(is_code(&err, codes::INVALID_EVENT), "{name}: {err}");
        }
    }

    // Ports upstream `TestEventRecordPrintsOnlyADigestPrefix`.
    #[test]
    fn event_record_prints_only_a_digest_prefix() {
        let mut e = valid_event(EventPayload::Message(Message {
            role: MessageRole::Assistant,
            text: "hi".to_string(),
            partial: false,
        }));
        e.harness_session_id = "sess-secret-id".to_string();
        let r = record_of(&e, TEST_DIGEST_KEY).unwrap();
        let full = hex_lower(&r.raw_sha256);
        for out in [format!("{r}"), format!("{r:?}"), format!("{r:#?}")] {
            assert!(
                !out.contains(&full) && !out.contains(&full[8..40]),
                "full digest printed: {out}"
            );
            assert!(out.contains(&full[..8]), "digest prefix missing: {out}");
            assert!(
                !out.contains("sess-secret-id"),
                "harness session id printed: {out}"
            );
        }
    }

    // Ports upstream `TestRecordOfRefusesAShortDigestKey`.
    #[test]
    fn record_of_refuses_a_short_digest_key() {
        let e = valid_event(EventPayload::Message(Message {
            role: MessageRole::Assistant,
            text: "hi".to_string(),
            partial: false,
        }));
        for key in [&b""[..], &b"short"[..]] {
            let err = record_of(&e, key).unwrap_err();
            assert!(
                is_code(&err, codes::INVALID_EVENT),
                "key of {} bytes: {err}",
                key.len()
            );
        }
    }

    // Ports upstream `TestRecordOfCopiesTheToolCallIDAndNeverTheInput`.
    #[test]
    fn record_of_copies_the_tool_call_id_and_never_the_input() {
        let secret = "sk-ant-in-a-bash-command";
        let mut e = valid_event(EventPayload::PermissionRequested(PermissionRequested {
            request_id: "p1".to_string(),
            tool_call_id: "toolu_1".to_string(),
            tool: "Bash".to_string(),
            input: secret.as_bytes().to_vec(),
            ..PermissionRequested::default()
        }));
        e.raw = br#"{"frame":1}"#.to_vec();
        let rec = record_of(&e, TEST_DIGEST_KEY).unwrap();
        assert_eq!(rec.tool_call_id, "toolu_1");
        assert_eq!(rec.permission_request_id, "p1");
        assert_eq!(rec.tool_name, "Bash");
        let printed = format!("{rec} {rec:?}");
        assert!(
            !printed.contains(secret),
            "the record carries the tool input"
        );
    }

    fn hex_lower(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
