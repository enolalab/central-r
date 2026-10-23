//! The normalized event surface — the port of `internal/harness/event.go`:
//! [`Usage`] scope-normalized folding, the sealed [`EventPayload`]
//! vocabulary (exactly the 12 declared payload kinds — a closed enum, so
//! the upstream seal and its type-switch can never be bypassed), and the
//! [`Event`] envelope with its validation and redacted `Display`.
//!
//! `Message`/`Reasoning`/`ToolCall`/`ToolResult`/`PermissionRequested`/
//! `Plan`/`Retry`/`Warning` all carry harness-controlled content; every
//! `Display`/`Debug` implementation prints structure and byte counts only.

use std::fmt;

use central_foundation::failure::Failure;
use central_foundation::identity::HarnessAttemptId;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::approval::{
    MAX_BRIDGED_INPUT_BYTES, MAX_PERMISSION_REQUEST_ID_BYTES, MAX_PERMISSION_RESOURCE_BYTES,
    MAX_PERMISSION_RESOURCES, MAX_TOOL_CALL_ID_BYTES, MAX_TOOL_NAME_BYTES, printable_ascii,
};
use crate::domain::{Terminal, codes, is_zero_time, vocab};

vocab! {
    /// What a harness's usage numbers cover — upstream `UsageScope`.
    /// Budget arithmetic must normalize by scope: Claude Code reports
    /// session-cumulative estimates, OpenCode reports per step.
    UsageScope {
        /// `step`.
        Step => "step",
        /// `run`.
        Run => "run",
        /// `session_cumulative`.
        SessionCumulative => "session_cumulative",
    }
}

vocab! {
    /// Names a normalized event payload type — upstream `EventKind`.
    EventKind {
        /// `session_started`.
        SessionStarted => "session_started",
        /// `message`.
        Message => "message",
        /// `reasoning`.
        Reasoning => "reasoning",
        /// `tool_call`.
        ToolCall => "tool_call",
        /// `tool_result`.
        ToolResult => "tool_result",
        /// `permission_requested`.
        PermissionRequested => "permission_requested",
        /// `permission_resolved`.
        PermissionResolved => "permission_resolved",
        /// `plan`.
        Plan => "plan",
        /// `usage_report`.
        UsageReport => "usage_report",
        /// `retry`.
        Retry => "retry",
        /// `warning`.
        Warning => "warning",
        /// `terminal_reported`.
        TerminalReported => "terminal_reported",
    }
}

vocab! {
    /// The outcome of a tool call — upstream `ToolStatus`.
    ToolStatus {
        /// `ok`.
        Ok => "ok",
        /// `error`.
        Error => "error",
        /// `denied`.
        Denied => "denied",
        /// `cut_off`.
        CutOff => "cut_off",
    }
}

vocab! {
    /// The author of a [`Message`] — upstream `MessageRole`.
    MessageRole {
        /// `assistant`.
        Assistant => "assistant",
        /// `user`.
        User => "user",
        /// `system`.
        System => "system",
    }
}

vocab! {
    /// How a permission request ended — upstream `PermissionOutcome`.
    PermissionOutcome {
        /// `allow`.
        Allowed => "allow",
        /// `deny`.
        Denied => "deny",
        /// `timeout`.
        Timeout => "timeout",
    }
}

/// A harness-reported usage snapshot — upstream `Usage`. Cost is in
/// micro-USD so budget arithmetic never rounds. The default value (no
/// scope, all zero) means "nothing reported yet". On an
/// [`crate::attempt::Attempt`] it is the scope-normalized cumulative
/// total maintained by `Attempt::apply_usage`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Usage {
    /// Input tokens.
    pub tokens_in: i64,
    /// Output tokens.
    pub tokens_out: i64,
    /// Cache-read tokens.
    pub cache_read: i64,
    /// Cache-write tokens.
    pub cache_write: i64,
    /// Cost in micro-USD.
    pub cost_micro_usd: i64,
    /// What the numbers cover.
    pub scope: UsageScope,
    /// `true` when the figures are estimates.
    pub estimated: bool,
}

impl Usage {
    /// Upstream `Usage.Validate`: rejects negative counters and requires
    /// a known scope whenever any counter is reported.
    pub fn validate(&self) -> Result<(), Failure> {
        if self.tokens_in < 0
            || self.tokens_out < 0
            || self.cache_read < 0
            || self.cache_write < 0
            || self.cost_micro_usd < 0
        {
            return Err(Failure::invalid(
                codes::INVALID_EVENT,
                "negative usage counter",
            ));
        }
        let reported = self.tokens_in != 0
            || self.tokens_out != 0
            || self.cache_read != 0
            || self.cache_write != 0
            || self.cost_micro_usd != 0;
        if self.scope == UsageScope::Unset {
            if reported || self.estimated {
                return Err(Failure::invalid(
                    codes::INVALID_EVENT,
                    "usage reported without a scope",
                ));
            }
            return Ok(());
        }
        if !self.scope.known() {
            return Err(Failure::invalid(
                codes::INVALID_EVENT,
                format!("unknown usage scope {}", self.scope.as_str()),
            ));
        }
        Ok(())
    }

    /// Upstream `Usage.fold`: combines the stored cumulative usage `self`
    /// with a validated, non-empty report in the same scope (`self` may
    /// still be the zero value). Unexported upstream; the sole caller is
    /// `crate::attempt::Attempt::apply_usage`.
    pub(crate) fn fold(&self, report: &Usage) -> Result<Usage, Failure> {
        let pairs = [
            (self.tokens_in, report.tokens_in),
            (self.tokens_out, report.tokens_out),
            (self.cache_read, report.cache_read),
            (self.cache_write, report.cache_write),
            (self.cost_micro_usd, report.cost_micro_usd),
        ];
        let mut out = [0i64; 5];
        for (i, (cur, rep)) in pairs.iter().enumerate() {
            match report.scope {
                UsageScope::Step => {
                    out[i] = cur.checked_add(*rep).ok_or_else(|| {
                        Failure::invalid(codes::INVALID_EVENT, "usage counter overflow")
                    })?;
                }
                _ => {
                    if rep < cur {
                        return Err(Failure::invalid(
                            codes::INVALID_EVENT,
                            format!("{} usage counter decreased", report.scope.as_str()),
                        ));
                    }
                    out[i] = *rep;
                }
            }
        }
        Ok(Usage {
            tokens_in: out[0],
            tokens_out: out[1],
            cache_read: out[2],
            cache_write: out[3],
            cost_micro_usd: out[4],
            scope: report.scope,
            estimated: self.estimated || report.estimated,
        })
    }
}

/// `SessionStarted` reports the harness-owned session identifier and
/// metadata — upstream `SessionStarted`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SessionStarted {
    /// The harness-owned session id.
    pub harness_session_id: String,
    /// The harness binary's version.
    pub harness_version: String,
    /// The model in use.
    pub model: String,
    /// Tool names the session declared.
    pub tools: Vec<String>,
    /// Capability names the adapter reported.
    pub reported_capabilities: Vec<String>,
}

/// Conversational text — upstream `Message`. `partial` marks a streaming
/// delta. `text` is sensitive and never printed.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Message {
    /// Who authored the text.
    pub role: MessageRole,
    /// The text — sensitive, redacted from `Display`/`Debug`.
    pub text: String,
    /// A streaming delta when `true`.
    pub partial: bool,
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "harness.Message{{Role:{} Partial:{} Text:<redacted {} bytes>}}",
            self.role,
            self.partial,
            self.text.len()
        )
    }
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Harness-reported thinking text — upstream `Reasoning`. `text` is
/// sensitive.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Reasoning {
    /// The thinking text — sensitive, redacted.
    pub text: String,
}

impl fmt::Display for Reasoning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "harness.Reasoning{{Text:<redacted {} bytes>}}",
            self.text.len()
        )
    }
}

impl fmt::Debug for Reasoning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// A harness tool invocation — upstream `ToolCall`. `input` is sensitive.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ToolCall {
    /// The harness's tool-call id.
    pub id: String,
    /// The parent tool-call id, when nested.
    pub parent_id: String,
    /// The tool name.
    pub name: String,
    /// The raw tool input — sensitive, redacted.
    pub input: Vec<u8>,
}

impl fmt::Display for ToolCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "harness.ToolCall{{ID:{} ParentID:{} Name:{} Input:<redacted {} bytes>}}",
            self.id,
            self.parent_id,
            self.name,
            self.input.len()
        )
    }
}

impl fmt::Debug for ToolCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// The outcome of a [`ToolCall`] — upstream `ToolResult`. `output` is
/// sensitive.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ToolResult {
    /// The tool-call id this answers.
    pub id: String,
    /// How the call ended.
    pub status: ToolStatus,
    /// The raw tool output — sensitive, redacted.
    pub output: Vec<u8>,
}

impl fmt::Display for ToolResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "harness.ToolResult{{ID:{} Status:{} Output:<redacted {} bytes>}}",
            self.id,
            self.status,
            self.output.len()
        )
    }
}

impl fmt::Debug for ToolResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// A harness asking the operator for permission — upstream
/// `PermissionRequested`. `input` is the raw bytes of the tool input,
/// exactly as the adapter echoes them back on an allow (harness phase 3c
/// decision 5); it is sensitive: never printed, logged or persisted — the
/// database keeps only its MAC and size.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PermissionRequested {
    /// The harness's request id.
    pub request_id: String,
    /// The tool call the request is about.
    pub tool_call_id: String,
    /// The tool name.
    pub tool: String,
    /// Resource spellings the request names.
    pub resources: Vec<String>,
    /// The options the harness offered.
    pub options: Vec<String>,
    /// The raw tool input — sensitive, redacted.
    pub input: Vec<u8>,
}

impl fmt::Display for PermissionRequested {
    /// Never includes `resources`, `options` or `input` content: a
    /// harness may pass raw tool input (e.g. a command containing a
    /// token) through them.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "harness.PermissionRequested{{RequestID:{} ToolCallID:{} Tool:{} Resources:<{} items> Options:<{} items> Input:<redacted {} bytes>}}",
            self.request_id,
            self.tool_call_id,
            self.tool,
            self.resources.len(),
            self.options.len(),
            self.input.len()
        )
    }
}

impl fmt::Debug for PermissionRequested {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// The answer to a [`PermissionRequested`] — upstream
/// `PermissionResolved`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PermissionResolved {
    /// The request answered.
    pub request_id: String,
    /// The answer.
    pub decision: PermissionOutcome,
    /// Who answered — the decider vocabulary lives in
    /// [`crate::approval`].
    pub decided_by: String,
}

/// A harness-reported plan — upstream `Plan`; it is persisted, never
/// dropped.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Plan {
    /// The plan entries.
    pub entries: Vec<String>,
}

impl fmt::Display for Plan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "harness.Plan{{Entries:<{} entries>}}",
            self.entries.len()
        )
    }
}

impl fmt::Debug for Plan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// A usage snapshot event — upstream `UsageReport`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct UsageReport {
    /// The snapshot.
    pub usage: Usage,
}

/// An informational harness retry notice — upstream `Retry`.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Retry {
    /// Why the harness retried — redacted (may quote a provider
    /// response).
    pub reason: String,
}

impl fmt::Display for Retry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "harness.Retry{{Reason:<redacted {} bytes>}}",
            self.reason.len()
        )
    }
}

impl fmt::Debug for Retry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// An informational notice, including unexpected harness behavior —
/// upstream `Warning`.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Warning {
    /// The notice — redacted.
    pub message: String,
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "harness.Warning{{Message:<redacted {} bytes>}}",
            self.message.len()
        )
    }
}

impl fmt::Debug for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// The end of the harness session — upstream `TerminalReported`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TerminalReported {
    /// How the session ended.
    pub terminal: Terminal,
}

/// The sealed payload vocabulary — upstream's `EventPayload` interface
/// closed by an enum, so exactly the 12 declared payload kinds exist and
/// the upstream pointer/embedding bypass is unexpressible.
///
/// Serialized with `kind`/`payload` adjacent tags: the `kind` strings are
/// the upstream `EventKind` spellings and each `payload` keeps the
/// payload's own snake_case field names. Upstream Go never emits
/// `EventPayload` JSON to any durable or wire surface —
/// `central.harness_events` stores bounded metadata columns only — so
/// this encoding is an internal Rust-only contract, pinned byte-for-byte
/// by `tests::event_payload_json_golden`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
pub enum EventPayload {
    /// `session_started`.
    SessionStarted(SessionStarted),
    /// `message`.
    Message(Message),
    /// `reasoning`.
    Reasoning(Reasoning),
    /// `tool_call`.
    ToolCall(ToolCall),
    /// `tool_result`.
    ToolResult(ToolResult),
    /// `permission_requested`.
    PermissionRequested(PermissionRequested),
    /// `permission_resolved`.
    PermissionResolved(PermissionResolved),
    /// `plan`.
    Plan(Plan),
    /// `usage_report`.
    UsageReport(UsageReport),
    /// `retry`.
    Retry(Retry),
    /// `warning`.
    Warning(Warning),
    /// `terminal_reported`.
    TerminalReported(TerminalReported),
}

impl EventPayload {
    /// Upstream `EventPayload.EventKind`.
    #[must_use]
    pub const fn event_kind(&self) -> EventKind {
        match self {
            Self::SessionStarted(_) => EventKind::SessionStarted,
            Self::Message(_) => EventKind::Message,
            Self::Reasoning(_) => EventKind::Reasoning,
            Self::ToolCall(_) => EventKind::ToolCall,
            Self::ToolResult(_) => EventKind::ToolResult,
            Self::PermissionRequested(_) => EventKind::PermissionRequested,
            Self::PermissionResolved(_) => EventKind::PermissionResolved,
            Self::Plan(_) => EventKind::Plan,
            Self::UsageReport(_) => EventKind::UsageReport,
            Self::Retry(_) => EventKind::Retry,
            Self::Warning(_) => EventKind::Warning,
            Self::TerminalReported(_) => EventKind::TerminalReported,
        }
    }

    /// The upstream unexported `validate()` each payload type carries.
    pub(crate) fn validate(&self) -> Result<(), Failure> {
        match self {
            Self::SessionStarted(p) => {
                if p.harness_session_id.is_empty() {
                    return Err(Failure::invalid(
                        codes::INVALID_EVENT,
                        "session_started requires a harness session id",
                    ));
                }
            }
            Self::Message(p) => {
                if !matches!(
                    p.role,
                    MessageRole::Assistant | MessageRole::User | MessageRole::System
                ) {
                    return Err(Failure::invalid(
                        codes::INVALID_EVENT,
                        format!("unknown message role {}", p.role.as_str()),
                    ));
                }
            }
            Self::Reasoning(_) => {}
            Self::ToolCall(p) => {
                if p.id.is_empty() || p.name.is_empty() {
                    return Err(Failure::invalid(
                        codes::INVALID_EVENT,
                        "tool_call requires id and name",
                    ));
                }
            }
            Self::ToolResult(p) => {
                if p.id.is_empty() {
                    return Err(Failure::invalid(
                        codes::INVALID_EVENT,
                        "tool_result requires id",
                    ));
                }
                if !matches!(
                    p.status,
                    ToolStatus::Ok | ToolStatus::Error | ToolStatus::Denied | ToolStatus::CutOff
                ) {
                    return Err(Failure::invalid(
                        codes::INVALID_EVENT,
                        format!("unknown tool status {}", p.status.as_str()),
                    ));
                }
            }
            Self::PermissionRequested(p) => {
                // The bounds on harness-controlled fields (decision 5)
                // and the bridged-input limit (decision 13).
                if p.request_id.is_empty() {
                    return Err(Failure::invalid(
                        codes::INVALID_EVENT,
                        "permission_requested requires a request id",
                    ));
                }
                if p.request_id.len() > MAX_PERMISSION_REQUEST_ID_BYTES
                    || p.tool_call_id.len() > MAX_TOOL_CALL_ID_BYTES
                {
                    return Err(Failure::invalid(
                        codes::INVALID_EVENT,
                        format!(
                            "permission_requested ids exceed {MAX_PERMISSION_REQUEST_ID_BYTES} bytes"
                        ),
                    ));
                }
                if p.tool.len() > MAX_TOOL_NAME_BYTES || !printable_ascii(&p.tool) {
                    return Err(Failure::invalid(
                        codes::INVALID_EVENT,
                        format!(
                            "permission_requested tool name must be at most {MAX_TOOL_NAME_BYTES} printable ASCII bytes"
                        ),
                    ));
                }
                if p.resources.len() > MAX_PERMISSION_RESOURCES {
                    return Err(Failure::invalid(
                        codes::INVALID_EVENT,
                        format!(
                            "permission_requested has more than {MAX_PERMISSION_RESOURCES} resources"
                        ),
                    ));
                }
                for r in &p.resources {
                    if r.len() > MAX_PERMISSION_RESOURCE_BYTES {
                        return Err(Failure::invalid(
                            codes::INVALID_EVENT,
                            format!(
                                "permission_requested resource exceeds {MAX_PERMISSION_RESOURCE_BYTES} bytes"
                            ),
                        ));
                    }
                }
                if p.input.len() > MAX_BRIDGED_INPUT_BYTES {
                    return Err(Failure::invalid(
                        codes::INVALID_EVENT,
                        format!(
                            "permission_requested input exceeds {MAX_BRIDGED_INPUT_BYTES} bytes"
                        ),
                    ));
                }
            }
            Self::PermissionResolved(p) => {
                if p.request_id.is_empty() {
                    return Err(Failure::invalid(
                        codes::INVALID_EVENT,
                        "permission_resolved requires a request id",
                    ));
                }
                if !matches!(
                    p.decision,
                    PermissionOutcome::Allowed
                        | PermissionOutcome::Denied
                        | PermissionOutcome::Timeout
                ) {
                    return Err(Failure::invalid(
                        codes::INVALID_EVENT,
                        format!("unknown permission decision {}", p.decision.as_str()),
                    ));
                }
            }
            Self::Plan(_) => {}
            Self::UsageReport(p) => p.usage.validate()?,
            Self::Retry(_) => {}
            Self::Warning(_) => {}
            Self::TerminalReported(p) => {
                if let Err(err) = p.terminal.state() {
                    return Err(Failure::invalid(codes::INVALID_EVENT, err.message()));
                }
            }
        }
        Ok(())
    }
}

impl fmt::Display for EventPayload {
    /// Prints only the kind tag — payload content is sensitive.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "harness.EventPayload{{{}}}", self.event_kind())
    }
}

impl fmt::Debug for EventPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// One normalized harness event — upstream `Event`. `raw` is the
/// untouched source frame and is sensitive: it is never printed.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// The attempt this event belongs to.
    pub attempt: HarnessAttemptId,
    /// The per-attempt sequence number; starts at 1.
    pub seq: u64,
    /// When the adapter observed the event.
    pub at: OffsetDateTime,
    /// The harness session the adapter reports.
    pub harness_session_id: String,
    /// The untouched source frame — sensitive, redacted.
    pub raw: Vec<u8>,
    /// The payload; `None` is the Go `nil`.
    pub payload: Option<EventPayload>,
}

impl Event {
    /// Upstream `Event.Validate`: checks the envelope and the payload.
    /// The payload's concrete-type check is the enum itself — a value
    /// outside the 12 declared kinds cannot be constructed, so the
    /// upstream seal-bypass arm has no Rust counterpart.
    pub fn validate(&self) -> Result<(), Failure> {
        if self.attempt.is_nil() {
            return Err(Failure::invalid(codes::INVALID_EVENT, "zero attempt"));
        }
        if self.seq < 1 {
            return Err(Failure::invalid(codes::INVALID_EVENT, "seq must be >= 1"));
        }
        if is_zero_time(self.at) {
            return Err(Failure::invalid(codes::INVALID_EVENT, "zero timestamp"));
        }
        if self.raw.is_empty() {
            return Err(Failure::invalid(codes::INVALID_EVENT, "empty raw frame"));
        }
        let payload = self
            .payload
            .as_ref()
            .ok_or_else(|| Failure::invalid(codes::INVALID_EVENT, "missing payload"))?;
        payload.validate()?;
        if let EventPayload::SessionStarted(started) = payload
            && started.harness_session_id != self.harness_session_id
        {
            return Err(Failure::invalid(
                codes::INVALID_EVENT,
                "envelope and session_started harness session ids differ",
            ));
        }
        Ok(())
    }
}

impl fmt::Display for Event {
    /// Never includes `raw` or payload content.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = self
            .payload
            .as_ref()
            .map_or(EventKind::Unset, EventPayload::event_kind);
        write!(
            f,
            "harness.Event{{Attempt:{} Seq:{} Kind:{} Raw:<redacted {} bytes>}}",
            self.attempt,
            self.seq,
            kind,
            self.raw.len()
        )
    }
}

impl fmt::Debug for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use central_foundation::identity::HarnessAttemptId;
    use time::macros::datetime;

    use super::*;
    use crate::approval::{
        MAX_BRIDGED_INPUT_BYTES, MAX_PERMISSION_REQUEST_ID_BYTES, MAX_PERMISSION_RESOURCE_BYTES,
        MAX_PERMISSION_RESOURCES, MAX_TOOL_CALL_ID_BYTES, MAX_TOOL_NAME_BYTES,
    };
    use crate::domain::{Terminal, TerminalStatus, codes};
    use crate::testkit::{Mutation, is_code, nil_attempt_id};

    // Ports upstream `validEvent`.
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

    // Ports upstream `TestEventValidateEnvelope`.
    #[test]
    fn event_validate_envelope() {
        let ok_event = valid_event(EventPayload::Message(Message {
            role: MessageRole::Assistant,
            text: "hi".to_string(),
            partial: false,
        }));
        assert!(ok_event.validate().is_ok(), "valid event");
        let mutations: [Mutation<Event>; 5] = [
            ("zero attempt", |e| e.attempt = nil_attempt_id()),
            ("zero seq", |e| e.seq = 0),
            ("zero time", |e| e.at = crate::domain::ZERO_TIME),
            ("empty raw", |e| e.raw = Vec::new()),
            ("nil payload", |e| e.payload = None),
        ];
        for (name, mutate) in mutations {
            let mut e = ok_event.clone();
            mutate(&mut e);
            let err = e.validate().unwrap_err();
            assert!(is_code(&err, codes::INVALID_EVENT), "{name}: {err}");
        }
    }

    // Ports upstream `TestEventPayloadRequiredFields`.
    #[test]
    fn event_payload_required_fields() {
        let invalid: [(&str, EventPayload); 10] = [
            (
                "session without id",
                EventPayload::SessionStarted(SessionStarted::default()),
            ),
            (
                "message bad role",
                EventPayload::Message(Message {
                    role: MessageRole::parse("robot"),
                    ..Message::default()
                }),
            ),
            (
                "tool call without name",
                EventPayload::ToolCall(ToolCall {
                    id: "t1".to_string(),
                    ..ToolCall::default()
                }),
            ),
            (
                "tool result bad status",
                EventPayload::ToolResult(ToolResult {
                    id: "t1".to_string(),
                    status: ToolStatus::parse("maybe"),
                    ..ToolResult::default()
                }),
            ),
            (
                "permission request no id",
                EventPayload::PermissionRequested(PermissionRequested::default()),
            ),
            (
                "permission resolved bad",
                EventPayload::PermissionResolved(PermissionResolved {
                    request_id: "p1".to_string(),
                    decision: PermissionOutcome::parse("perhaps"),
                    ..PermissionResolved::default()
                }),
            ),
            (
                "tool call without id",
                EventPayload::ToolCall(ToolCall {
                    name: "Bash".to_string(),
                    ..ToolCall::default()
                }),
            ),
            (
                "usage without scope",
                EventPayload::UsageReport(UsageReport {
                    usage: Usage {
                        tokens_in: 5,
                        ..Usage::default()
                    },
                }),
            ),
            (
                "usage negative",
                EventPayload::UsageReport(UsageReport {
                    usage: Usage {
                        tokens_in: -1,
                        scope: UsageScope::Step,
                        ..Usage::default()
                    },
                }),
            ),
            (
                "terminal unknown",
                EventPayload::TerminalReported(TerminalReported {
                    terminal: Terminal {
                        status: TerminalStatus::parse("boom"),
                        ..Terminal::default()
                    },
                }),
            ),
        ];
        for (name, payload) in invalid {
            let err = valid_event(payload).validate().unwrap_err();
            assert!(is_code(&err, codes::INVALID_EVENT), "{name}: {err}");
        }
        let valid: [EventPayload; 9] = [
            EventPayload::Reasoning(Reasoning {
                text: "x".to_string(),
            }),
            EventPayload::Plan(Plan {
                entries: vec!["a".to_string()],
            }),
            EventPayload::Retry(Retry {
                reason: "rate".to_string(),
            }),
            EventPayload::Warning(Warning {
                message: "w".to_string(),
            }),
            EventPayload::ToolCall(ToolCall {
                id: "t1".to_string(),
                name: "Bash".to_string(),
                ..ToolCall::default()
            }),
            EventPayload::ToolResult(ToolResult {
                id: "t1".to_string(),
                status: ToolStatus::CutOff,
                ..ToolResult::default()
            }),
            EventPayload::PermissionResolved(PermissionResolved {
                request_id: "p1".to_string(),
                decision: PermissionOutcome::Timeout,
                ..PermissionResolved::default()
            }),
            EventPayload::UsageReport(UsageReport {
                usage: Usage {
                    tokens_in: 5,
                    scope: UsageScope::Step,
                    ..Usage::default()
                },
            }),
            EventPayload::TerminalReported(TerminalReported {
                terminal: Terminal {
                    status: TerminalStatus::MaxTurns,
                    ..Terminal::default()
                },
            }),
        ];
        for payload in valid {
            valid_event(payload).validate().unwrap();
        }
    }

    // Ports upstream `TestSessionStartedMustMatchEnvelope`.
    #[test]
    fn session_started_must_match_envelope() {
        let mut e = valid_event(EventPayload::SessionStarted(SessionStarted {
            harness_session_id: "s1".to_string(),
            ..SessionStarted::default()
        }));
        let err = e.validate().unwrap_err();
        assert!(is_code(&err, codes::INVALID_EVENT), "mismatch: {err}");
        e.harness_session_id = "s1".to_string();
        assert!(e.validate().is_ok(), "matching ids rejected");
    }

    // Ports upstream
    // `TestEventValidateRejectsPointerAndForeignPayloads`. Rust's closed
    // `EventPayload` enum is sealed by construction — the upstream
    // method-promotion bypass cannot be expressed; a structurally
    // well-formed but semantically foreign payload still fails the
    // SessionStarted agreement check.
    #[test]
    fn event_validate_rejects_pointer_and_foreign_payloads() {
        let mut e = valid_event(EventPayload::SessionStarted(SessionStarted {
            harness_session_id: "s1".to_string(),
            ..SessionStarted::default()
        }));
        e.harness_session_id = "other".to_string();
        let err = e.validate().unwrap_err();
        assert!(is_code(&err, codes::INVALID_EVENT), "{err}");
    }

    // Ports upstream `TestSensitiveContentNeverPrinted`.
    #[test]
    fn sensitive_content_never_printed() {
        let mut e = valid_event(EventPayload::ToolResult(ToolResult {
            id: "t1".to_string(),
            status: ToolStatus::Ok,
            output: SECRET.as_bytes().to_vec(),
        }));
        e.raw = SECRET.as_bytes().to_vec();
        let printed = [
            format!("{e}"),
            format!("{e:?}"),
            format!(
                "{}",
                Message {
                    role: MessageRole::Assistant,
                    text: SECRET.to_string(),
                    partial: false,
                }
            ),
            format!(
                "{:?}",
                Reasoning {
                    text: SECRET.to_string()
                }
            ),
            format!(
                "{}",
                ToolCall {
                    id: "t".to_string(),
                    parent_id: String::new(),
                    name: "n".to_string(),
                    input: SECRET.as_bytes().to_vec(),
                }
            ),
            format!(
                "{}",
                ToolResult {
                    id: "t".to_string(),
                    status: ToolStatus::Ok,
                    output: SECRET.as_bytes().to_vec(),
                }
            ),
            format!(
                "{}",
                PermissionRequested {
                    request_id: "p1".to_string(),
                    tool: "Bash".to_string(),
                    resources: vec![SECRET.to_string()],
                    options: vec![SECRET.to_string()],
                    ..PermissionRequested::default()
                }
            ),
            format!(
                "{:?}",
                Warning {
                    message: SECRET.to_string()
                }
            ),
            format!(
                "{}",
                Retry {
                    reason: SECRET.to_string()
                }
            ),
            format!(
                "{:?}",
                Plan {
                    entries: vec![SECRET.to_string()]
                }
            ),
        ];
        for s in printed {
            assert!(!s.contains(SECRET), "sensitive content printed: {s}");
        }
    }

    // Ports upstream `TestToolStatusesEnumerator`.
    #[test]
    fn tool_statuses_enumerator() {
        let mut seen = std::collections::BTreeSet::new();
        for status in ToolStatus::all() {
            let e = valid_event(EventPayload::ToolResult(ToolResult {
                id: "call-1".to_string(),
                status: *status,
                ..ToolResult::default()
            }));
            assert!(e.validate().is_ok(), "{status}: event refused");
            assert!(seen.insert(*status), "{status}: duplicate");
        }
    }

    // Ports upstream `TestPermissionOutcomesEnumerator`.
    #[test]
    fn permission_outcomes_enumerator() {
        let mut seen = std::collections::BTreeSet::new();
        for outcome in PermissionOutcome::all() {
            let e = valid_event(EventPayload::PermissionResolved(PermissionResolved {
                request_id: "req-1".to_string(),
                decision: *outcome,
                decided_by: "op".to_string(),
            }));
            assert!(e.validate().is_ok(), "{outcome}: event refused");
            assert!(seen.insert(*outcome), "{outcome}: duplicate");
        }
    }

    // Ports upstream `TestPermissionRequestedRedactsItsInput`.
    #[test]
    fn permission_requested_redacts_its_input() {
        let secret = "sk-ant-in-a-bash-command";
        let p = PermissionRequested {
            request_id: "p1".to_string(),
            tool_call_id: "toolu_1".to_string(),
            tool: "Bash".to_string(),
            input: format!(r#"{{"command":"curl -H {secret}"}}"#).into_bytes(),
            ..PermissionRequested::default()
        };
        for printed in [
            format!("{p}"),
            format!("{p:?}"),
            format!(
                "{}",
                valid_event(EventPayload::PermissionRequested(p.clone()))
            ),
        ] {
            assert!(
                !printed.contains(secret) && !printed.contains("curl"),
                "tool input printed: {printed}"
            );
        }
        let s = p.to_string();
        assert!(s.contains("ToolCallID:toolu_1"), "String() = {s}");
        assert!(
            s.contains(&format!("Input:<redacted {} bytes>", p.input.len())),
            "String() = {s}"
        );
    }

    // Ports upstream `TestPermissionRequestedBoundsHarnessControlledFields`.
    #[test]
    fn permission_requested_bounds_harness_controlled_fields() {
        let ok_request = PermissionRequested {
            request_id: "r".repeat(MAX_PERMISSION_REQUEST_ID_BYTES),
            tool_call_id: "t".repeat(MAX_TOOL_CALL_ID_BYTES),
            tool: "n".repeat(MAX_TOOL_NAME_BYTES),
            resources: {
                let mut v = vec![String::new(); MAX_PERMISSION_RESOURCES];
                v[0] = "x".repeat(MAX_PERMISSION_RESOURCE_BYTES);
                v
            },
            options: Vec::new(),
            input: vec![0; MAX_BRIDGED_INPUT_BYTES],
        };
        assert!(
            valid_event(EventPayload::PermissionRequested(ok_request.clone()))
                .validate()
                .is_ok(),
            "a request at every bound was refused"
        );
        let mutations: [Mutation<PermissionRequested>; 7] = [
            ("request id", |p| p.request_id.push('r')),
            ("tool call id", |p| p.tool_call_id.push('t')),
            ("tool name", |p| p.tool.push('n')),
            ("tool name ctrl", |p| p.tool = "Ba\x07sh".to_string()),
            ("tool name utf8", |p| p.tool = "Bäsh".to_string()),
            ("resource count", |p| p.resources.push(String::new())),
            ("resource size", |p| p.resources[0].push('x')),
        ];
        for (name, mutate) in mutations {
            let mut p = ok_request.clone();
            mutate(&mut p);
            let err = valid_event(EventPayload::PermissionRequested(p))
                .validate()
                .unwrap_err();
            assert!(is_code(&err, codes::INVALID_EVENT), "{name}: {err}");
        }
        let mut p = ok_request.clone();
        p.input.push(b'0');
        let err = valid_event(EventPayload::PermissionRequested(p))
            .validate()
            .unwrap_err();
        assert!(is_code(&err, codes::INVALID_EVENT), "input size: {err}");
    }

    // Ports upstream `TestUsageScopesEnumerator` (capability_test.go;
    // UsageScope lives here with Usage).
    #[test]
    fn usage_scopes_enumerator() {
        let mut seen = std::collections::BTreeSet::new();
        for scope in UsageScope::all() {
            assert!(scope.known(), "{scope}: not known");
            assert!(seen.insert(*scope), "{scope}: duplicate");
        }
    }

    // Pins the `Event`/`EventPayload` serde_json contract byte-for-byte.
    // Upstream Go emits no payload JSON — `central.harness_events` stores
    // bounded metadata columns only — so this shape is an internal
    // Rust-only contract with no cross-implementation spelling to match.
    // The test locks the `{"kind","payload"}` envelope, the upstream
    // `EventKind` spellings, snake_case field names, `Vec<u8>` as a JSON
    // number array, and vocab enums as their declared strings; any
    // serde-attribute or field drift fails here loudly.
    #[test]
    fn event_payload_json_golden() {
        let cases: [(EventPayload, &str); 4] = [
            (
                EventPayload::SessionStarted(SessionStarted {
                    harness_session_id: "sess-1".to_string(),
                    harness_version: "2.1.0".to_string(),
                    model: "claude".to_string(),
                    tools: vec!["Bash".to_string()],
                    reported_capabilities: vec!["usage_report".to_string()],
                }),
                r#"{"kind":"session_started","payload":{"harness_session_id":"sess-1","harness_version":"2.1.0","model":"claude","tools":["Bash"],"reported_capabilities":["usage_report"]}}"#,
            ),
            (
                EventPayload::ToolCall(ToolCall {
                    id: "toolu_1".to_string(),
                    parent_id: "toolu_0".to_string(),
                    name: "Bash".to_string(),
                    input: vec![123, 34, 99],
                }),
                r#"{"kind":"tool_call","payload":{"id":"toolu_1","parent_id":"toolu_0","name":"Bash","input":[123,34,99]}}"#,
            ),
            (
                EventPayload::UsageReport(UsageReport {
                    usage: Usage {
                        tokens_in: 5,
                        tokens_out: 7,
                        cost_micro_usd: 100,
                        scope: UsageScope::Step,
                        estimated: true,
                        ..Usage::default()
                    },
                }),
                r#"{"kind":"usage_report","payload":{"usage":{"tokens_in":5,"tokens_out":7,"cache_read":0,"cache_write":0,"cost_micro_usd":100,"scope":"step","estimated":true}}}"#,
            ),
            (
                EventPayload::TerminalReported(TerminalReported {
                    terminal: Terminal {
                        status: TerminalStatus::MaxTurns,
                        reason: "turn cap".to_string(),
                        exit_code: Some(2),
                    },
                }),
                r#"{"kind":"terminal_reported","payload":{"terminal":{"status":"max_turns","reason":"turn cap","exit_code":2}}}"#,
            ),
        ];
        for (payload, want) in &cases {
            assert_eq!(serde_json::to_string(payload).unwrap(), *want);
            let back: EventPayload = serde_json::from_str(want).unwrap();
            assert_eq!(&back, payload);
        }

        // The envelope: the attempt id as a UUID string, `at` in the
        // `time` crate's `(year, ordinal, h, m, s, ns, offset h/m/s)`
        // array form, `raw` as a number array, `Some(payload)` inlined
        // and `None` as `null`.
        let event = Event {
            attempt: HarnessAttemptId::from_trusted_db_bytes([
                0x01, 0x9a, 0x3c, 0x5e, 0x9b, 0x0e, 0x7f, 0x3a, 0x9b, 0x0e, 0x9b, 0x0e, 0x9b, 0x0e,
                0x9b, 0x0e,
            ]),
            seq: 1,
            at: datetime!(2026-09-27 10:00:00 UTC),
            harness_session_id: "sess-1".to_string(),
            raw: br#"{"frame":1}"#.to_vec(),
            payload: Some(EventPayload::Warning(Warning {
                message: "w".to_string(),
            })),
        };
        let want = r#"{"attempt":"019a3c5e-9b0e-7f3a-9b0e-9b0e9b0e9b0e","seq":1,"at":[2026,270,10,0,0,0,0,0,0],"harness_session_id":"sess-1","raw":[123,34,102,114,97,109,101,34,58,49,125],"payload":{"kind":"warning","payload":{"message":"w"}}}"#;
        assert_eq!(serde_json::to_string(&event).unwrap(), want);
        assert_eq!(serde_json::from_str::<Event>(want).unwrap(), event);

        let mut no_payload = event.clone();
        no_payload.payload = None;
        assert!(
            serde_json::to_string(&no_payload)
                .unwrap()
                .ends_with(r#""payload":null}"#)
        );
    }
}
