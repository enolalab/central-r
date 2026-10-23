//! `protocol.go` — the `agy` stream-json envelope grammar and the
//! step/result decoders.
//!
//! Frames decode through the crate's byte-level scanner
//! ([`crate::json`]): the whole line must be one JSON object (Go
//! `json.Unmarshal`'s top-level rule) and `step_update`/`result` keep
//! raw spans so tool parameters are never re-encoded. Unknown fields
//! are ignored; `init`/`cwd`/`model`/`permission_mode`/`tools` are
//! never read (recorded in `raw` only) and the result error body is
//! never decoded (its presence is the signal).

use central_harness::event::{ToolStatus, Usage, UsageScope};

use crate::json::{self, JsonError, push_json_string_html};

/// `warnDenied` — the fixed-literal Warning of a turn whose result
/// carries a non-empty `denied_actions` array: headless mode
/// auto-denied at least one tool action (spec E4). The entries are
/// never decoded; presence is the signal.
pub(crate) const WARN_DENIED: &str = "harness auto-denied tool actions";

/// `frame` — one envelope: `{"event", …}` with one of the
/// `init`/`step_update`/`result` members.
#[derive(Debug, Default)]
pub(crate) struct Frame {
    pub event: String,
    pub conversation_id: String,
    pub step_update: Option<Vec<u8>>,
    pub result: Option<Vec<u8>>,
}

/// `frameKind` — the envelope classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FrameKind {
    Unknown,
    Init,
    Step,
    Result,
}

impl Frame {
    /// `kind` — maps the envelope event; anything else (including "")
    /// is unknown.
    pub(crate) fn kind(&self) -> FrameKind {
        match self.event.as_str() {
            "init" => FrameKind::Init,
            "step_update" => FrameKind::Step,
            "result" => FrameKind::Result,
            _ => FrameKind::Unknown,
        }
    }

    /// `id` — resolves the frame's conversation id: top-level for
    /// init, nested for step_update and result (agy nests it inside
    /// the member). An undecodable member yields `""`, which the
    /// caller treats as missing.
    pub(crate) fn id(&self) -> String {
        match self.kind() {
            FrameKind::Init => self.conversation_id.clone(),
            FrameKind::Step => self
                .step_update
                .as_deref()
                .map(nested_id)
                .unwrap_or_default(),
            FrameKind::Result => self.result.as_deref().map(nested_id).unwrap_or_default(),
            _ => String::new(),
        }
    }
}

/// `nestedID` — the `conversation_id` member of a step_update or
/// result body; `""` when undecodable.
fn nested_id(raw: &[u8]) -> String {
    let Ok(members) = json::object_members(raw) else {
        return String::new();
    };
    for (name, span) in &members {
        if name == "conversation_id" {
            return json::field::<Option<String>>(raw, span)
                .ok()
                .flatten()
                .unwrap_or_default();
        }
    }
    String::new()
}

/// `decodeFrame` — one stdout line. Unknown fields are ignored; a
/// wrongly-typed known member fails the line (Go's unmarshal error).
pub(crate) fn decode_frame(line: &[u8]) -> Result<Frame, JsonError> {
    let members = json::object_members(line)?;
    let mut f = Frame::default();
    for (name, span) in &members {
        match name.as_str() {
            "event" => f.event = json::field::<Option<String>>(line, span)?.unwrap_or_default(),
            "conversation_id" => {
                f.conversation_id = json::field::<Option<String>>(line, span)?.unwrap_or_default();
            }
            "step_update" => f.step_update = Some(line[span.clone()].to_vec()),
            "result" => f.result = Some(line[span.clone()].to_vec()),
            _ => {}
        }
    }
    Ok(f)
}

/// `stepState` — a step_update state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StepState {
    Unknown,
    Active,
    Done,
    Error,
}

/// `stepType` — a step_update body type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StepType {
    Unknown,
    UserInput,
    AgentResponse,
    Tool,
}

/// `toolErrorData` — the decoded `tool_info.error` member.
#[derive(Debug)]
pub(crate) struct ToolErrorData {
    pub message: Option<String>,
    /// The whitespace-compacted raw error object.
    pub raw: Vec<u8>,
}

/// `toolInfoData` — the decoded `tool_info` member. `parameters` is
/// the whitespace-compacted raw parameters, preserving the harness
/// spelling. `output` is the DONE output (`None` when absent).
/// `error` is the ERROR detail.
#[derive(Debug)]
pub(crate) struct ToolInfoData {
    pub parameters: Vec<u8>,
    pub output: Option<String>,
    pub error: Option<ToolErrorData>,
}

/// `stepData` — a decoded step_update body. `usage` is `Some` only
/// when the step carries a usable usage object; `usage_unusable`
/// reports a present-but-bad usage object (the text still stands:
/// usage is auxiliary evidence, warned and skipped on its own).
#[derive(Debug)]
pub(crate) struct StepData {
    pub index: i64,
    pub state: StepState,
    pub typ: StepType,
    /// The agent_response delta (`None` when absent).
    pub text_delta: Option<String>,
    /// The agent_response usage report (`None` when absent).
    pub usage: Option<Usage>,
    /// A present-but-bad usage object.
    pub usage_unusable: bool,
    /// The tool step halves.
    pub tool_name: String,
    pub tool_info: Option<ToolInfoData>,
}

impl Default for StepData {
    fn default() -> Self {
        Self {
            index: 0,
            state: StepState::Unknown,
            typ: StepType::Unknown,
            text_delta: None,
            usage: None,
            usage_unusable: false,
            tool_name: String::new(),
            tool_info: None,
        }
    }
}

/// Whether a raw member is absent or the literal `null` (upstream's
/// `len == 0 || TrimSpace == "null"`).
fn absent_or_null(raw: Option<&Vec<u8>>) -> bool {
    match raw {
        None => true,
        Some(b) => trim_eq(b, b"null"),
    }
}

fn trim_eq(b: &[u8], lit: &[u8]) -> bool {
    let start = b
        .iter()
        .position(|c| !c.is_ascii_whitespace())
        .unwrap_or(b.len());
    let end = b
        .iter()
        .rposition(|c| !c.is_ascii_whitespace())
        .map(|i| i + 1)
        .unwrap_or(start);
    &b[start..end] == lit
}

/// `decodeStep` — a step_update body. A `system_message` step, an
/// unknown `step_type` or state, a body that is not a JSON object, or
/// a missing/negative `step_index` is unusable with a zero header
/// (the session warns and skips it, never stops). A body failure past
/// a good header (non-string text_delta, bad tool name/shape) is
/// unusable with the header set, so the caller can still route on it
/// (a malformed terminal tool frame drops its pending call). A
/// present-but-bad usage object is not a body failure:
/// `usage_unusable` is set and the text stands.
pub(crate) fn decode_step(raw: &[u8]) -> (StepData, bool) {
    let Ok(members) = json::object_members(raw) else {
        return (StepData::default(), false);
    };
    let mut index: Option<i64> = None;
    let mut state = String::new();
    let mut typ = String::new();
    let mut text_delta: Option<Vec<u8>> = None;
    let mut usage_raw: Option<Vec<u8>> = None;
    let mut tool_name_raw: Option<Vec<u8>> = None;
    let mut tool_info_raw: Option<Vec<u8>> = None;
    for (name, span) in &members {
        match name.as_str() {
            "step_index" => match json::field::<Option<i64>>(raw, span) {
                Ok(v) => index = v,
                Err(_) => return (StepData::default(), false),
            },
            "state" => {
                state = match json::field::<Option<String>>(raw, span) {
                    Ok(v) => v.unwrap_or_default(),
                    Err(_) => return (StepData::default(), false),
                };
            }
            "step_type" => {
                typ = match json::field::<Option<String>>(raw, span) {
                    Ok(v) => v.unwrap_or_default(),
                    Err(_) => return (StepData::default(), false),
                };
            }
            "text_delta" => text_delta = Some(raw[span.clone()].to_vec()),
            "usage" => usage_raw = Some(raw[span.clone()].to_vec()),
            "tool_name" => tool_name_raw = Some(raw[span.clone()].to_vec()),
            "tool_info" => tool_info_raw = Some(raw[span.clone()].to_vec()),
            _ => {}
        }
    }
    let Some(index) = index else {
        return (StepData::default(), false);
    };
    if index < 0 {
        return (StepData::default(), false);
    }
    let st = match state.as_str() {
        "ACTIVE" => StepState::Active,
        "DONE" => StepState::Done,
        "ERROR" => StepState::Error,
        _ => return (StepData::default(), false),
    };
    let ty = match typ.as_str() {
        "user_input" => StepType::UserInput,
        "agent_response" => StepType::AgentResponse,
        "tool" => StepType::Tool,
        // system_message and any future step type: forward tolerance,
        // warned and skipped by the caller.
        _ => return (StepData::default(), false),
    };
    let mut out = StepData {
        index,
        state: st,
        typ: ty,
        ..StepData::default()
    };
    match ty {
        StepType::AgentResponse => {
            if !absent_or_null(text_delta.as_ref()) {
                let raw = text_delta.as_deref().unwrap_or(&[]);
                match json::field::<String>(raw, &(0..raw.len())) {
                    Ok(delta) => out.text_delta = Some(delta),
                    Err(_) => return (out, false),
                }
            }
            if !absent_or_null(usage_raw.as_ref()) {
                let raw = usage_raw.as_deref().unwrap_or(&[]);
                match decode_usage(raw) {
                    Some(u) => out.usage = Some(u),
                    None => out.usage_unusable = true,
                }
            }
        }
        StepType::Tool => {
            let name = match tool_name_raw.as_deref() {
                Some(raw) => match json::field::<String>(raw, &(0..raw.len())) {
                    Ok(n) => n,
                    Err(_) => return (out, false),
                },
                None => return (out, false),
            };
            if name.is_empty() || tool_info_raw.is_none() {
                return (out, false);
            }
            out.tool_name = name;
            match decode_tool_info(tool_info_raw.as_deref().unwrap_or(&[])) {
                Some(ti) => out.tool_info = Some(ti),
                None => return (out, false),
            }
        }
        _ => {}
    }
    (out, true)
}

/// `decodeToolInfo` — a `tool_info` member. `parameters` must be
/// present (any JSON value; compacted verbatim). `output` must be a
/// string when present. `error` must be an object when present.
fn decode_tool_info(raw: &[u8]) -> Option<ToolInfoData> {
    let members = json::object_members(raw).ok()?;
    let mut parameters: Option<Vec<u8>> = None;
    let mut output: Option<String> = None;
    let mut error_raw: Option<Vec<u8>> = None;
    for (name, span) in &members {
        match name.as_str() {
            "parameters" => parameters = Some(raw[span.clone()].to_vec()),
            "output" => output = json::field::<Option<String>>(raw, span).ok()?,
            "error" => error_raw = Some(raw[span.clone()].to_vec()),
            _ => {}
        }
    }
    let parameters = parameters?;
    let compacted = json::compact(&parameters).ok()?;
    let mut out = ToolInfoData {
        parameters: compacted,
        output,
        error: None,
    };
    if absent_or_null(error_raw.as_ref()) {
        return Some(out);
    }
    let eraw = error_raw.as_deref().unwrap_or(&[]);
    let em = json::object_members(eraw).ok()?;
    let mut message: Option<String> = None;
    for (name, span) in &em {
        if name == "message" {
            message = json::field::<Option<String>>(eraw, span).ok()?;
        }
    }
    out.error = Some(ToolErrorData {
        message,
        raw: json::compact(eraw).ok()?,
    });
    Some(out)
}

/// `decodeUsage` — an agent_response usage object into a step-scope
/// report. Counters must be present integral int64 JSON numbers;
/// fractional, out-of-range or missing fields make the report
/// unusable. Negative counters become 0 within an emitted report,
/// mirroring `addCounter`. `thinking` folds into output; `total_tokens`
/// is ignored. `cost_micro_usd` is always 0: agy reports no cost.
pub(crate) fn decode_usage(raw: &[u8]) -> Option<Usage> {
    let members = json::object_members(raw).ok()?;
    let mut input: Option<i64> = None;
    let mut output: Option<i64> = None;
    let mut thinking: Option<i64> = None;
    let mut cache: Option<i64> = None;
    for (name, span) in &members {
        match name.as_str() {
            "input_tokens" => input = Some(token_int64(raw, span)?),
            "output_tokens" => output = Some(token_int64(raw, span)?),
            "thinking_tokens" => thinking = Some(token_int64(raw, span)?),
            "cache_read_tokens" => cache = Some(token_int64(raw, span)?),
            _ => {}
        }
    }
    let input = input?;
    let output = output?;
    let thinking = thinking?;
    let cache = cache?;
    // `output >= 0` gates the subtraction: Go's `math.MaxInt64-out`
    // wraps negative for a negative out, making the `thinking <= …`
    // check false so the sum saturates — the gate reproduces the
    // wraparound outcome without overflowing.
    let tokens_out = if thinking > 0 && output >= 0 && thinking <= i64::MAX - output {
        output + thinking
    } else if thinking > 0 {
        i64::MAX
    } else {
        output
    };
    Some(Usage {
        tokens_in: input.max(0),
        tokens_out: tokens_out.max(0),
        cache_read: cache.max(0),
        cache_write: 0,
        cost_micro_usd: 0,
        scope: UsageScope::Step,
        estimated: false,
    })
}

/// `tokenInt64` — one token counter strictly: only a present integral
/// int64 JSON number is usable (a missing or null field decodes as
/// `""` upstream). The member decodes as Go's `json.Number`, so a
/// string member is accepted when its content is a valid JSON number
/// (`"5"` is 5). `json.Number.Int64` rejects fractions and
/// out-of-range values alike.
fn token_int64(raw: &[u8], span: &json::Span) -> Option<i64> {
    json::number_int64(&raw[span.clone()])
}

/// `addCounter` — folds one step counter into a running total: values
/// at or below zero are ignored, and the sum saturates. Mirrors
/// opencode; retained for upstream parity.
#[allow(dead_code)]
fn add_counter(total: i64, step: i64) -> i64 {
    // `total >= 0` gates the subtraction: Go's `math.MaxInt64-total`
    // wraps negative for a negative total, so `step > …` is true and
    // the sum saturates — the gate reproduces that without wrapping.
    if step > 0 && total >= 0 && step <= i64::MAX - total {
        total + step
    } else if step > 0 {
        i64::MAX
    } else {
        total
    }
}

/// `resultData` — a decoded result body. `ok` is true for SUCCESS.
/// `response` is the final text. `denied` is true when
/// `denied_actions` is present and non-empty; the entries are never
/// decoded. The error body is never decoded (its presence is the
/// signal, recorded by the caller from `ok` alone).
#[derive(Debug)]
pub(crate) struct ResultData {
    pub ok: bool,
    pub response: String,
    pub denied: bool,
}

/// `decodeResult` — a result body. A missing or unknown status, or a
/// body that is not a JSON object, is unusable.
pub(crate) fn decode_result(raw: &[u8]) -> Option<ResultData> {
    let members = json::object_members(raw).ok()?;
    let mut status = String::new();
    let mut response: Option<String> = None;
    let mut denied_raw: Option<Vec<u8>> = None;
    for (name, span) in &members {
        match name.as_str() {
            "status" => {
                status = json::field::<Option<String>>(raw, span)
                    .ok()?
                    .unwrap_or_default();
            }
            "response" => response = json::field::<Option<String>>(raw, span).ok()?,
            "denied_actions" => denied_raw = Some(raw[span.clone()].to_vec()),
            _ => {}
        }
    }
    let ok = match status.as_str() {
        "SUCCESS" => true,
        "ERROR" => false,
        _ => return None,
    };
    let mut denied = false;
    if !absent_or_null(denied_raw.as_ref()) {
        let raw = denied_raw.as_deref().unwrap_or(&[]);
        // Must decode as an array upstream (a non-array fails the
        // whole result); count its elements.
        let spans = json::array_spans(raw).ok()?;
        denied = !spans.is_empty();
    }
    Some(ResultData {
        ok,
        response: response.unwrap_or_default(),
        denied,
    })
}

/// `encodeUserEvent` — operator text as one NDJSON stdin line:
/// `{"event":"user","message":{"role":"user","content":text}}`.
/// Upstream encodes with plain `json.Marshal`, so the content escapes
/// as `encoding/json`'s default: `<`, `>` and `&` also become
/// `\u003c`, `\u003e`, `\u0026`. The line ends with exactly one `"\n"`.
pub(crate) fn encode_user_event(text: &str) -> Vec<u8> {
    let mut b = Vec::with_capacity(text.len() + 64);
    b.extend_from_slice(b"{\"event\":\"user\",\"message\":{\"role\":\"user\",\"content\":");
    push_json_string_html(&mut b, text);
    b.extend_from_slice(b"}}\n");
    b
}

/// The tool status a terminal tool frame reports — kept here so the
/// session's mapping stays one line.
pub(crate) fn tool_status(state: StepState) -> ToolStatus {
    match state {
        StepState::Error => ToolStatus::Error,
        _ => ToolStatus::Ok,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `TestDecodeFrameKinds` / `TestFrameIDNesting` /
    /// `TestDecodeFrameMalformed`.
    #[test]
    fn decode_frame_kinds() {
        let cases = [
            (
                r#"{"event":"init","conversation_id":"c1"}"#,
                FrameKind::Init,
            ),
            (
                r#"{"event":"step_update","step_update":{}}"#,
                FrameKind::Step,
            ),
            (r#"{"event":"result","result":{}}"#, FrameKind::Result),
            (r#"{"event":"future_x"}"#, FrameKind::Unknown),
            (r#"{"event":""}"#, FrameKind::Unknown),
        ];
        for (line, want) in cases {
            let f = decode_frame(line.as_bytes()).unwrap();
            assert_eq!(f.kind(), want, "{line}");
        }
        let f = decode_frame(br#"{"event":"init","conversation_id":"c1"}"#).unwrap();
        assert_eq!(f.id(), "c1");
        let f = decode_frame(
            br#"{"event":"step_update","step_update":{"conversation_id":"c2","step_index":0}}"#,
        )
        .unwrap();
        assert_eq!(f.id(), "c2");
        let f = decode_frame(
            br#"{"event":"result","result":{"conversation_id":"c3","status":"SUCCESS"}}"#,
        )
        .unwrap();
        assert_eq!(f.id(), "c3");
        // idless result, malformed nested member.
        let f = decode_frame(br#"{"event":"result","result":{"status":"ERROR"}}"#).unwrap();
        assert_eq!(f.id(), "");
        let f = decode_frame(br#"{"event":"result","result":123}"#).unwrap();
        assert_eq!(f.id(), "");
        for bad in [
            b"".as_slice(),
            b"not json",
            b"{",
            b"[1]",
            br#"{"event":123}"#,
        ] {
            assert!(decode_frame(bad).is_err(), "{bad:?}");
        }
    }

    /// `TestDecodeStepAgentResponse` / `TestDecodeStepUsageProblems`.
    #[test]
    fn decode_step_agent_response() {
        let (d, ok) = decode_step(
            br#"{"step_index":1,"state":"DONE","step_type":"agent_response","text_delta":"hi","usage":{"input_tokens":10,"output_tokens":2,"thinking_tokens":1,"cache_read_tokens":3}}"#,
        );
        assert!(ok);
        assert_eq!(d.index, 1);
        assert_eq!(d.state, StepState::Done);
        assert_eq!(d.typ, StepType::AgentResponse);
        assert_eq!(d.text_delta.as_deref(), Some("hi"));
        let u = d.usage.unwrap();
        assert_eq!(u.tokens_in, 10);
        assert_eq!(u.tokens_out, 3, "thinking folds into output");
        assert_eq!(u.cache_read, 3);
        assert_eq!(u.scope, UsageScope::Step);
        assert_eq!(u.cost_micro_usd, 0);
        // Quoted counters: `json.Number` accepts a string holding a
        // valid JSON number.
        let (d, ok) = decode_step(
            br#"{"step_index":1,"state":"DONE","step_type":"agent_response","usage":{"input_tokens":"5","output_tokens":"3","thinking_tokens":"2","cache_read_tokens":"1"}}"#,
        );
        assert!(ok);
        let u = d.usage.unwrap();
        assert_eq!(u.tokens_in, 5);
        assert_eq!(u.tokens_out, 5);
        assert_eq!(u.cache_read, 1);
        // output<0 ∧ thinking>0: upstream's `math.MaxInt64-out` wraps
        // negative, so the fold saturates to MaxInt64 rather than
        // producing -2.
        let (d, ok) = decode_step(
            br#"{"step_index":1,"state":"DONE","step_type":"agent_response","usage":{"input_tokens":0,"output_tokens":-5,"thinking_tokens":3,"cache_read_tokens":0}}"#,
        );
        assert!(ok);
        assert_eq!(d.usage.unwrap().tokens_out, i64::MAX);
        // Present-but-bad usage keeps the text.
        let (d, ok) = decode_step(
            br#"{"step_index":1,"state":"DONE","step_type":"agent_response","text_delta":"hi","usage":{"input_tokens":"x"}}"#,
        );
        assert!(ok);
        assert!(d.usage_unusable && d.usage.is_none());
        assert_eq!(d.text_delta.as_deref(), Some("hi"));
        // Non-string text_delta → body failure with the header set.
        let (d, ok) = decode_step(
            br#"{"step_index":1,"state":"DONE","step_type":"agent_response","text_delta":5}"#,
        );
        assert!(!ok);
        assert_eq!(d.typ, StepType::AgentResponse);
        // Null text_delta is absent.
        let (d, ok) = decode_step(
            br#"{"step_index":1,"state":"ACTIVE","step_type":"agent_response","text_delta":null}"#,
        );
        assert!(ok);
        assert!(d.text_delta.is_none());
        // Header failures: missing/negative index, unknown state/type,
        // system_message, non-object body.
        for bad in [
            br#"{"state":"DONE","step_type":"agent_response"}"#.as_slice(),
            br#"{"step_index":-1,"state":"DONE","step_type":"agent_response"}"#.as_slice(),
            br#"{"step_index":0,"state":"BOGUS","step_type":"agent_response"}"#.as_slice(),
            br#"{"step_index":0,"state":"DONE","step_type":"system_message"}"#.as_slice(),
            br#"{"step_index":0,"state":"DONE","step_type":"mystery"}"#.as_slice(),
            b"[1]".as_slice(),
            b"not json".as_slice(),
        ] {
            let (d, ok) = decode_step(bad);
            assert!(!ok, "{bad:?}");
            assert_eq!(d.typ, StepType::Unknown, "{bad:?}");
        }
    }

    /// `TestDecodeStepTool` / `TestDecodeStepToolUnusable`.
    #[test]
    fn decode_step_tool() {
        let (d, ok) = decode_step(
            br#"{"step_index":2,"state":"ACTIVE","step_type":"tool","tool_name":"run_command","tool_info":{"name":"run_command","parameters":{"CommandLine":"ls"}}}"#,
        );
        assert!(ok);
        assert_eq!(d.tool_name, "run_command");
        let ti = d.tool_info.unwrap();
        assert_eq!(ti.parameters, br#"{"CommandLine":"ls"}"#.to_vec());
        // DONE with output.
        let (d, ok) = decode_step(
            br#"{"step_index":2,"state":"DONE","step_type":"tool","tool_name":"run_command","tool_info":{"parameters":{},"output":"OUT"}}"#,
        );
        assert!(ok);
        assert_eq!(d.tool_info.unwrap().output.as_deref(), Some("OUT"));
        // ERROR with message.
        let (d, ok) = decode_step(
            br#"{"step_index":2,"state":"ERROR","step_type":"tool","tool_name":"x","tool_info":{"parameters":{},"error":{"type":"TOOL_ERROR","message":"boom"}}}"#,
        );
        assert!(ok);
        let e = d.tool_info.unwrap().error.unwrap();
        assert_eq!(e.message.as_deref(), Some("boom"));
        assert_eq!(e.raw, br#"{"type":"TOOL_ERROR","message":"boom"}"#.to_vec());
        // Unusable: missing name, empty name, missing parameters,
        // bad tool_info.
        for bad in [
            br#"{"step_index":1,"state":"ACTIVE","step_type":"tool"}"#.as_slice(),
            br#"{"step_index":1,"state":"ACTIVE","step_type":"tool","tool_name":""}"#.as_slice(),
            br#"{"step_index":1,"state":"ACTIVE","step_type":"tool","tool_name":"x"}"#.as_slice(),
            br#"{"step_index":1,"state":"ACTIVE","step_type":"tool","tool_name":"x","tool_info":{}}"#.as_slice(),
            br#"{"step_index":1,"state":"ACTIVE","step_type":"tool","tool_name":5,"tool_info":{"parameters":{}}}"#.as_slice(),
        ] {
            let (d, ok) = decode_step(bad);
            assert!(!ok, "{bad:?}");
            assert_eq!(d.typ, StepType::Tool, "{bad:?}");
        }
    }

    /// `TestDecodeResult`.
    #[test]
    fn decode_result_table() {
        let r =
            decode_result(br#"{"status":"SUCCESS","response":"done","denied_actions":[{"a":1}]}"#)
                .unwrap();
        assert!(r.ok && r.denied && r.response == "done");
        let r = decode_result(br#"{"status":"ERROR"}"#).unwrap();
        assert!(!r.ok && !r.denied);
        let r = decode_result(br#"{"status":"SUCCESS","denied_actions":null}"#).unwrap();
        assert!(!r.denied);
        let r = decode_result(br#"{"status":"SUCCESS","denied_actions":[]}"#).unwrap();
        assert!(!r.denied);
        for bad in [
            br#"{"status":"BOGUS"}"#.as_slice(),
            br#"{"response":"x"}"#.as_slice(),
            br#"{"status":"SUCCESS","denied_actions":5}"#.as_slice(),
            b"not json".as_slice(),
        ] {
            assert!(decode_result(bad).is_none(), "{bad:?}");
        }
    }

    /// `TestEncodeUserEventRoundTrip`.
    #[test]
    fn encode_user_event_round_trip() {
        let line = encode_user_event("hello \"world\"\nnext");
        let text = String::from_utf8(line.clone()).unwrap();
        assert!(text.ends_with("}}\n"));
        let v: serde_json::Value = serde_json::from_str(text.trim_end()).unwrap();
        assert_eq!(v["event"], "user");
        assert_eq!(v["message"]["role"], "user");
        assert_eq!(v["message"]["content"], "hello \"world\"\nnext");
        // Plain `json.Marshal` HTML-escapes <, >, & — byte-exact.
        let line = encode_user_event("a<b>&c");
        assert_eq!(
            line,
            b"{\"event\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"a\\u003cb\\u003e\\u0026c\"}}\n"
                .as_slice()
        );
    }
}
