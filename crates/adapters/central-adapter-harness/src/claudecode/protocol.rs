//! `protocol.go` — stream-JSON frame types, normalization helpers the
//! reader task uses, and the outgoing line encoders the writer queues.
//!
//! Frames decode through the crate's byte-level scanner
//! ([`crate::claudecode::json`]): member extraction keeps raw value
//! spans so `input`/`content`/`message` are never re-encoded, and typed
//! member decodes use `Option<…>` targets so JSON `null` is the no-op it
//! is for a Go zero field. The whole-frame grammar is upstream's
//! `frame` struct — an error decoding any member (wrong type, bad
//! syntax) is `warnMalformedInput`, exactly as a `json.Unmarshal` type
//! or syntax error is.

use central_harness::domain::{Terminal, TerminalStatus};
use central_harness::event::{Usage, UsageScope};

use super::json::{self, JsonError, Span};

/// One decoded `control_request.request` object (`protocol.go`'s
/// `controlRequest`).
#[derive(Debug, Default)]
pub(crate) struct ControlRequest {
    pub subtype: String,
    pub tool_name: String,
    /// Raw member bytes — never re-encoded.
    pub input: Vec<u8>,
    pub blocked_path: String,
    pub tool_use_id: String,
}

/// One decoded element of `message.content` (`contentBlock`).
#[derive(Debug, Default)]
pub(crate) struct ContentBlock {
    pub typ: String,
    pub text: String,
    pub thinking: String,
    pub id: String,
    pub name: String,
    /// Raw member bytes for `tool_use.input`.
    pub input: Vec<u8>,
    /// Raw member bytes for `tool_result.content`.
    pub content: Vec<u8>,
    pub tool_use_id: String,
    pub is_error: bool,
}

/// `resultUsage` — every counter is `Option` so `null` is `0` and a
/// wrong type is a decode error, matching Go's `int64` members under
/// `json.Unmarshal`.
#[derive(Debug, Default, Clone, Copy, serde::Deserialize)]
pub(crate) struct ResultUsage {
    input_tokens: Option<i64>,
    output_tokens: Option<i64>,
    cache_read_input_tokens: Option<i64>,
    cache_creation_input_tokens: Option<i64>,
}

impl ResultUsage {
    fn input(&self) -> i64 {
        self.input_tokens.unwrap_or(0)
    }
    fn output(&self) -> i64 {
        self.output_tokens.unwrap_or(0)
    }
    fn cache_read(&self) -> i64 {
        self.cache_read_input_tokens.unwrap_or(0)
    }
    fn cache_creation(&self) -> i64 {
        self.cache_creation_input_tokens.unwrap_or(0)
    }
}

/// `frame` — the discriminated union the reader decodes per line.
/// Fields Go decodes as `json.RawMessage` keep raw spans of the source
/// line (`message`/`request`/`response`); scalars decode through
/// `Option<…>` for Go's null-tolerance.
#[derive(Debug, Default)]
pub(crate) struct Frame {
    pub typ: String,
    pub subtype: String,
    pub session_id: String,
    pub model: String,
    pub tools: Vec<String>,
    pub permission_mode: String,
    pub claude_code_version: String,
    pub capabilities: Vec<String>,
    /// Raw `message` member (assistant/user envelopes).
    pub message: Option<Vec<u8>>,
    pub parent_tool_use_id: Option<String>,
    pub error: String,
    pub tool_use_id: String,
    pub request_id: String,
    /// Raw `request` member (control_request envelope).
    pub request: Option<Vec<u8>>,
    /// Raw `response` member (control_response envelope).
    pub response: Option<Vec<u8>>,
    pub is_error: bool,
    pub result: String,
    pub terminal_reason: String,
    pub total_cost_usd: f64,
    pub usage: Option<ResultUsage>,
    pub queued_turn_count: Option<i64>,
}

/// `json.Unmarshal(line, &frame)` — the whole line must be one object;
/// every recognized member decodes to its Go field type. Repeated
/// members follow unmarshal's last-wins rule.
pub(crate) fn decode_frame(line: &[u8]) -> Result<Frame, JsonError> {
    let members = json::object_members(line)?;
    let mut f = Frame::default();
    for (name, span) in &members {
        match name.as_str() {
            "type" => f.typ = string_field(line, span)?,
            "subtype" => f.subtype = string_field(line, span)?,
            "session_id" => f.session_id = string_field(line, span)?,
            "model" => f.model = string_field(line, span)?,
            "tools" => {
                f.tools = json::field::<Option<Vec<String>>>(line, span)?.unwrap_or_default()
            }
            "permissionMode" => f.permission_mode = string_field(line, span)?,
            "claude_code_version" => f.claude_code_version = string_field(line, span)?,
            "capabilities" => {
                f.capabilities =
                    json::field::<Option<Vec<String>>>(line, span)?.unwrap_or_default();
            }
            "message" => f.message = Some(line[span.clone()].to_vec()),
            "parent_tool_use_id" => {
                f.parent_tool_use_id = json::field::<Option<String>>(line, span)?;
            }
            "error" => f.error = string_field(line, span)?,
            "tool_use_id" => f.tool_use_id = string_field(line, span)?,
            "request_id" => f.request_id = string_field(line, span)?,
            "request" => f.request = Some(line[span.clone()].to_vec()),
            "response" => f.response = Some(line[span.clone()].to_vec()),
            "is_error" => f.is_error = json::field::<Option<bool>>(line, span)?.unwrap_or(false),
            "result" => f.result = string_field(line, span)?,
            "terminal_reason" => f.terminal_reason = string_field(line, span)?,
            "total_cost_usd" => {
                f.total_cost_usd = json::field::<Option<f64>>(line, span)?.unwrap_or(0.0);
            }
            "usage" => f.usage = json::field::<Option<ResultUsage>>(line, span)?,
            "queued_turn_count" => {
                f.queued_turn_count = json::field::<Option<i64>>(line, span)?;
            }
            _ => {}
        }
    }
    Ok(f)
}

fn string_field(b: &[u8], span: &Span) -> Result<String, JsonError> {
    Ok(json::field::<Option<String>>(b, span)?.unwrap_or_default())
}

/// `liveTokens` — the running per-message deltas `countLive` tracks.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LiveTokens {
    pub tokens_in: i64,
    pub tokens_out: i64,
    pub cache_write: i64,
}

impl Frame {
    /// `lastResult` — a result with no `queued_turn_count`, or a
    /// non-positive one, ends the process's work.
    pub(crate) fn last_result(&self) -> bool {
        self.queued_turn_count.is_none_or(|q| q <= 0)
    }

    /// `f.blocks` — `message` member absent or not starting with `{` is
    /// no content; `content` absent or not starting with `[` is no
    /// blocks; anything else must decode fully.
    pub(crate) fn blocks(&self) -> Result<Vec<ContentBlock>, JsonError> {
        let msg = self.message.as_deref().unwrap_or(&[]);
        if msg.first() != Some(&b'{') {
            return Ok(Vec::new());
        }
        let members = json::object_members(msg)?;
        // `role` decodes for the parity reason: a wrong-typed role is a
        // whole-message unmarshal error upstream.
        if let Some(span) = json::member(&members, "role") {
            let _: Option<String> = json::field(msg, span)?;
        }
        let Some(cspan) = json::member(&members, "content") else {
            return Ok(Vec::new());
        };
        let content = &msg[cspan.clone()];
        if content.first() != Some(&b'[') {
            return Ok(Vec::new());
        }
        let spans = json::array_spans(content)?;
        let mut out = Vec::with_capacity(spans.len());
        for es in spans {
            let elem = &content[es.clone()];
            let em = json::object_members(elem)?;
            let mut b = ContentBlock::default();
            for (n, s) in &em {
                match n.as_str() {
                    "type" => b.typ = string_field(elem, s)?,
                    "text" => b.text = string_field(elem, s)?,
                    "thinking" => b.thinking = string_field(elem, s)?,
                    "id" => b.id = string_field(elem, s)?,
                    "name" => b.name = string_field(elem, s)?,
                    "input" => b.input = elem[s.clone()].to_vec(),
                    "content" => b.content = elem[s.clone()].to_vec(),
                    "tool_use_id" => b.tool_use_id = string_field(elem, s)?,
                    "is_error" => {
                        b.is_error = json::field::<Option<bool>>(elem, s)?.unwrap_or(false);
                    }
                    _ => {}
                }
            }
            out.push(b);
        }
        Ok(out)
    }

    /// `f.canUseTool` — `request` must be present and decode as an
    /// object; a `null` request is the decode-free empty struct
    /// `json.Unmarshal("null", &req)` produces upstream.
    pub(crate) fn can_use_tool(&self) -> Result<ControlRequest, JsonError> {
        let Some(raw) = self.request.as_deref() else {
            return Err(JsonError::Malformed);
        };
        if raw == b"null" {
            return Ok(ControlRequest::default());
        }
        let members = json::object_members(raw)?;
        let mut r = ControlRequest::default();
        for (n, s) in &members {
            match n.as_str() {
                "subtype" => r.subtype = string_field(raw, s)?,
                "tool_name" => r.tool_name = string_field(raw, s)?,
                "input" => r.input = raw[s.clone()].to_vec(),
                "blocked_path" => r.blocked_path = string_field(raw, s)?,
                "tool_use_id" => r.tool_use_id = string_field(raw, s)?,
                _ => {}
            }
        }
        Ok(r)
    }

    /// `f.responseRequestID` — response raw absent/not `{`/unmarshable
    /// or `request_id` wrong-typed is the empty string.
    pub(crate) fn response_request_id(&self) -> String {
        let Some(raw) = self.response.as_deref() else {
            return String::new();
        };
        if raw.first() != Some(&b'{') {
            return String::new();
        }
        let Ok(members) = json::object_members(raw) else {
            return String::new();
        };
        let Some(span) = json::member(&members, "request_id") else {
            return String::new();
        };
        json::field::<Option<String>>(raw, span)
            .ok()
            .flatten()
            .unwrap_or_default()
    }

    /// `f.usage` — the session-cumulative report one result frame
    /// contributes; absent `usage` keeps the cost-only record.
    pub(crate) fn usage(&self) -> Usage {
        let u = self.usage.unwrap_or_default();
        Usage {
            tokens_in: u.input(),
            tokens_out: u.output(),
            cache_read: u.cache_read(),
            cache_write: u.cache_creation(),
            cost_micro_usd: cost_micro_usd(self.total_cost_usd),
            scope: UsageScope::SessionCumulative,
            estimated: true,
        }
    }

    /// `f.mainThreadUsage` — `None` for subagent messages, non-object
    /// messages, missing/empty/`null`/`0`-shaped ids, absent or `null`
    /// usage, any member's wrong type, or any negative counter. Note
    /// `cache_read_input_tokens` contributes no stream signal upstream
    /// and is not sign-checked there.
    pub(crate) fn main_thread_usage(&self) -> Option<(String, LiveTokens)> {
        if self.parent_tool_use_id.is_some() {
            return None;
        }
        let msg = self.message.as_deref()?;
        if msg.first() != Some(&b'{') {
            return None;
        }
        let members = json::object_members(msg).ok()?;
        let id = match json::member(&members, "id") {
            Some(span) => json::field::<Option<String>>(msg, span)
                .ok()?
                .unwrap_or_default(),
            None => String::new(),
        };
        if id.is_empty() {
            return None;
        }
        let span = json::member(&members, "usage")?;
        let u = json::field::<Option<ResultUsage>>(msg, span).ok()??;
        if u.input() < 0 || u.output() < 0 || u.cache_creation() < 0 {
            return None;
        }
        Some((
            id,
            LiveTokens {
                tokens_in: u.input(),
                tokens_out: u.output(),
                cache_write: u.cache_creation(),
            },
        ))
    }
}

/// `costMicroUSD` — USD to micro-USD with half-away-from-zero rounding;
/// non-finite or non-positive inputs clamp to zero, overflow to the
/// micro ceiling.
pub(crate) fn cost_micro_usd(usd: f64) -> i64 {
    if !usd.is_finite() || usd <= 0.0 {
        return 0;
    }
    let micros = (usd * 1_000_000.0).round();
    if micros >= i64::MAX as f64 {
        return i64::MAX;
    }
    micros as i64
}

/// `addCounter` — a non-positive delta is ignored (never subtracted);
/// a positive one saturates at `i64::MAX` rather than wrapping.
pub(crate) fn add_counter(total: i64, turn: i64) -> i64 {
    if turn <= 0 {
        return total;
    }
    if turn > i64::MAX - total {
        return i64::MAX;
    }
    total + turn
}

/// `addTurn` — cost = max(total, turn) keeps the later (authoritative)
/// figure; never reports a decrease if a process reuses a session and
/// restarts counters.
pub(crate) fn add_turn(total: Usage, turn: Usage) -> Usage {
    Usage {
        tokens_in: add_counter(total.tokens_in, turn.tokens_in),
        tokens_out: add_counter(total.tokens_out, turn.tokens_out),
        cache_read: add_counter(total.cache_read, turn.cache_read),
        cache_write: add_counter(total.cache_write, turn.cache_write),
        cost_micro_usd: total.cost_micro_usd.max(turn.cost_micro_usd),
        scope: UsageScope::SessionCumulative,
        estimated: true,
    }
}

/// `json.Marshal(s)` via Go's `appendString` with EscapeHTML off — the
/// mode `encodeLine` sets: `"` `\` shorthand escapes, `\n`/`\r`/`\t`,
/// other controls as `\u00xx`, U+2028/U+2029 escaped, everything else
/// raw UTF-8 (`<`/`>`/`&` unescaped).
pub(crate) fn push_json_string(out: &mut Vec<u8>, s: &str) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\u{2028}' => out.extend_from_slice(b"\\u2028"),
            '\u{2029}' => out.extend_from_slice(b"\\u2029"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

/// `control_request` line without the newline —
/// `{"type":"control_request","request_id":"…","request":{"subtype":"…"}}`.
fn control_request_frame(request_id: &str, subtype: &str) -> Vec<u8> {
    let mut b = Vec::with_capacity(96);
    b.extend_from_slice(b"{\"type\":\"control_request\",\"request_id\":");
    push_json_string(&mut b, request_id);
    b.extend_from_slice(b",\"request\":{\"subtype\":");
    push_json_string(&mut b, subtype);
    b.extend_from_slice(b"}}");
    b
}

/// `control_response` lines. Allow echoes `input` — already compacted
/// upstream bytes — as `updatedInput`; deny carries `message` and the
/// fixed `interrupt:false`.
pub(crate) fn permission_response_frame(
    request_id: &str,
    allow: bool,
    input: &[u8],
    deny_message: &str,
) -> Vec<u8> {
    let mut b = Vec::with_capacity(128 + input.len());
    b.extend_from_slice(
        b"{\"type\":\"control_response\",\"response\":{\"subtype\":\"success\",\"request_id\":",
    );
    push_json_string(&mut b, request_id);
    b.extend_from_slice(b",\"response\":");
    if allow {
        b.extend_from_slice(b"{\"behavior\":\"allow\",\"updatedInput\":");
        if input.is_empty() {
            b.extend_from_slice(b"{}");
        } else {
            b.extend_from_slice(input);
        }
        b.push(b'}');
    } else {
        b.extend_from_slice(b"{\"behavior\":\"deny\",\"message\":");
        push_json_string(&mut b, deny_message);
        b.extend_from_slice(b",\"interrupt\":false}");
    }
    b.extend_from_slice(b"}}");
    b
}

/// `unsupportedResponse` — the fixed error response for control
/// requests the adapter does not serve, so the harness never hangs.
pub(crate) fn unsupported_response_frame(request_id: &str) -> Vec<u8> {
    let mut b = Vec::with_capacity(160);
    b.extend_from_slice(
        b"{\"type\":\"control_response\",\"response\":{\"subtype\":\"error\",\"request_id\":",
    );
    push_json_string(&mut b, request_id);
    b.extend_from_slice(b",\"error\":\"unsupported control request\"}}");
    b
}

/// `userMessage` frame (no newline).
pub(crate) fn user_message_frame(text: &str) -> Vec<u8> {
    let mut b = Vec::with_capacity(text.len() + 64);
    b.extend_from_slice(b"{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":");
    push_json_string(&mut b, text);
    b.extend_from_slice(b"}}");
    b
}

/// The frame the adapter writes — a newline-terminated line.
pub(crate) fn encode_line(mut frame: Vec<u8>) -> Vec<u8> {
    frame.push(b'\n');
    frame
}

pub(crate) fn initialize_line(request_id: &str) -> Vec<u8> {
    encode_line(control_request_frame(request_id, "initialize"))
}

pub(crate) fn interrupt_line(request_id: &str) -> Vec<u8> {
    encode_line(control_request_frame(request_id, "interrupt"))
}

pub(crate) fn user_message_line(text: &str) -> Vec<u8> {
    encode_line(user_message_frame(text))
}

/// `mapResult` — pure terminal-status mapping for a result frame.
pub(crate) fn map_result(f: &Frame, auth_failed: bool, interrupt_requested: bool) -> Terminal {
    use super::reasons;
    if !f.is_error {
        return Terminal {
            status: TerminalStatus::Succeeded,
            ..Terminal::default()
        };
    }
    let (status, reason) = if f.terminal_reason == "api_error" && auth_failed {
        (TerminalStatus::Failed, reasons::HARNESS_NOT_AUTHENTICATED)
    } else if f.terminal_reason == "api_error" {
        (TerminalStatus::Failed, reasons::HARNESS_API_ERROR)
    } else if f.terminal_reason == "aborted_tools"
        || (f.subtype == "error_during_execution" && interrupt_requested)
    {
        (TerminalStatus::Interrupted, reasons::HARNESS_ABORTED)
    } else if f.subtype == "error_max_turns" {
        (TerminalStatus::MaxTurns, reasons::HARNESS_MAX_TURNS)
    } else if f.subtype == "error_max_budget_usd" {
        (TerminalStatus::Budget, reasons::HARNESS_BUDGET)
    } else {
        (TerminalStatus::Failed, reasons::HARNESS_API_ERROR)
    };
    Terminal {
        status,
        reason: reason.to_string(),
        ..Terminal::default()
    }
}

/// `boundedRequest` — fail-closed bounds for a `can_use_tool` request;
/// false routes to the bridge-unavailable terminal rather than an
/// answer.
pub(crate) fn bounded_request(
    request_id: &str,
    req: &ControlRequest,
    resources: &[String],
) -> bool {
    request_id.len() <= 512
        && req.tool_use_id.len() <= 512
        && req.tool_name.len() <= 256
        && req.tool_name.bytes().all(|b| (0x20..=0x7e).contains(&b))
        && resources.len() <= 16
        && resources.iter().all(|r| r.len() <= 1024)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `TestCostMicroUSD`.
    #[test]
    fn cost_micro_usd_table() {
        let cases: &[(f64, i64)] = &[
            (0.0, 0),
            (-1.0, 0),
            (0.0714359, 71436),
            (1e300, i64::MAX),
            (f64::NAN, 0),
            (f64::INFINITY, 0),
            (f64::NEG_INFINITY, 0),
        ];
        for (usd, want) in cases {
            assert_eq!(cost_micro_usd(*usd), *want, "usd={usd}");
        }
    }

    /// `TestAddCounter` / `TestAddTurn` — overflow, mixed-sign, and
    /// cost-max behavior.
    #[test]
    fn add_counter_and_turn() {
        assert_eq!(add_counter(i64::MAX, 1), i64::MAX);
        assert_eq!(add_counter(i64::MIN, -1), i64::MIN, "negatives ignored");
        assert_eq!(add_counter(5, 3), 8);
        assert_eq!(
            add_counter(5, -3),
            5,
            "a negative delta is ignored, not subtracted"
        );
        assert_eq!(add_counter(i64::MAX - 4, 4), i64::MAX);
        assert_eq!(add_counter(i64::MAX - 4, 5), i64::MAX);
        let a = Usage {
            cost_micro_usd: 7,
            ..Usage::default()
        };
        let b = Usage {
            cost_micro_usd: 3,
            tokens_in: 10,
            ..Usage::default()
        };
        let s = add_turn(a, b);
        assert_eq!(s.cost_micro_usd, 7, "cost never decreases");
        assert_eq!(s.tokens_in, 10);
        assert!(s.estimated);
        assert_eq!(s.scope, UsageScope::SessionCumulative);
    }

    /// `mapResult`'s vocabulary (session_internal_test's table).
    #[test]
    fn map_result_table() {
        let f = |subtype: &str, reason: &str, is_error: bool, result: &str| {
            let mut fr = Frame {
                subtype: subtype.to_string(),
                ..Frame::default()
            };
            fr.terminal_reason = reason.to_string();
            fr.is_error = is_error;
            fr.result = result.to_string();
            fr
        };
        // Success.
        assert_eq!(
            map_result(&f("success", "", false, "done"), false, false).status,
            TerminalStatus::Succeeded
        );
        // api_error + auth_failed → not_authenticated.
        let t = map_result(
            &f("error_during_execution", "api_error", true, ""),
            true,
            false,
        );
        assert_eq!(t.status, TerminalStatus::Failed);
        assert_eq!(t.reason, super::super::reasons::HARNESS_NOT_AUTHENTICATED);
        // api_error alone → api_error.
        let t = map_result(
            &f("error_during_execution", "api_error", true, ""),
            false,
            false,
        );
        assert_eq!(t.reason, super::super::reasons::HARNESS_API_ERROR);
        // aborted_tools → interrupted regardless of interrupt request.
        let t = map_result(
            &f("error_during_execution", "aborted_tools", true, ""),
            false,
            false,
        );
        assert_eq!(t.status, TerminalStatus::Interrupted);
        assert_eq!(t.reason, super::super::reasons::HARNESS_ABORTED);
        // error_during_execution + interrupt requested → interrupted.
        let t = map_result(&f("error_during_execution", "", true, ""), false, true);
        assert_eq!(t.status, TerminalStatus::Interrupted);
        // error_during_execution without interrupt → api_error.
        let t = map_result(&f("error_during_execution", "", true, ""), false, false);
        assert_eq!(t.reason, super::super::reasons::HARNESS_API_ERROR);
        // max turns / max budget.
        let t = map_result(&f("error_max_turns", "", true, ""), false, false);
        assert_eq!(t.status, TerminalStatus::MaxTurns);
        let t = map_result(&f("error_max_budget_usd", "", true, ""), false, false);
        assert_eq!(t.status, TerminalStatus::Budget);
    }

    /// Duplicate member names on the same object — last wins upstream.
    #[test]
    fn frame_member_last_wins() {
        let f = decode_frame(br#"{"type":"a","type":"b"}"#).unwrap();
        assert_eq!(f.typ, "b");
    }

    /// `mainThreadUsage` parity cases from `TestAPIErrorAfterAuthStall*`:
    /// null usage and bad scalar types are simply not counted.
    #[test]
    fn main_thread_usage_edges() {
        let f = decode_frame(
            br#"{"type":"assistant","message":{"id":"m1","usage":{"input_tokens":null,"output_tokens":2}}}"#,
        )
        .unwrap();
        let (id, lt) = f.main_thread_usage().unwrap();
        assert_eq!(id, "m1");
        assert_eq!(lt.tokens_in, 0);
        assert_eq!(lt.tokens_out, 2);

        let f = decode_frame(
            br#"{"type":"assistant","message":{"id":"m1","usage":{"input_tokens":-1,"output_tokens":0}}}"#,
        )
        .unwrap();
        assert!(f.main_thread_usage().is_none());

        let f = decode_frame(
            br#"{"type":"assistant","parent_tool_use_id":"t1","message":{"id":"m1","usage":{"input_tokens":1}}}"#,
        )
        .unwrap();
        assert!(
            f.main_thread_usage().is_none(),
            "subagent messages are not counted"
        );

        let f =
            decode_frame(br#"{"type":"assistant","message":{"id":7,"usage":{"input_tokens":1}}}"#)
                .unwrap();
        assert!(
            f.main_thread_usage().is_none(),
            "wrong-typed id is a decode error upstream"
        );
    }

    /// `queued_turn_count` — `lastResult` semantics.
    #[test]
    fn last_result_semantics() {
        let mut f = Frame::default();
        assert!(f.last_result());
        f.queued_turn_count = Some(0);
        assert!(f.last_result());
        f.queued_turn_count = Some(-2);
        assert!(f.last_result());
        f.queued_turn_count = Some(3);
        assert!(!f.last_result());
        // null decodes to absent.
        let f = decode_frame(br#"{"type":"result","queued_turn_count":null}"#).unwrap();
        assert!(f.last_result());
    }

    /// `f.usage` — absent usage keeps the cost record; null is the same.
    #[test]
    fn frame_usage_from_result() {
        let f = decode_frame(
            br#"{"type":"result","total_cost_usd":0.0714359,"usage":{"input_tokens":10,"output_tokens":31,"cache_read_input_tokens":13689,"cache_creation_input_tokens":34951}}"#,
        )
        .unwrap();
        let u = f.usage();
        assert_eq!(u.tokens_in, 10);
        assert_eq!(u.tokens_out, 31);
        assert_eq!(u.cache_read, 13689);
        assert_eq!(u.cache_write, 34951);
        assert_eq!(u.cost_micro_usd, 71436);
        assert!(u.estimated);

        let f = decode_frame(br#"{"type":"result","total_cost_usd":0.5,"usage":null}"#).unwrap();
        let u = f.usage();
        assert_eq!(u.tokens_in, 0);
        assert_eq!(u.cost_micro_usd, 500_000);
    }
}
