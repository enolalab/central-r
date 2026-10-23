//! `protocol.go` — the `opencode run --format json` NDJSON envelope
//! grammar and the part decoders.
//!
//! Frames decode through the crate's byte-level scanner
//! ([`crate::json`]): the whole line must be one JSON object (Go
//! `json.Unmarshal`'s top-level rule), the `part`/`error` members keep
//! raw spans so tool inputs are never re-encoded, and member decodes
//! use `Option<…>` targets so JSON `null` is the no-op it is for a Go
//! zero field. Unknown members are ignored; the harness `timestamp` is
//! never read (the adapter stamps events itself) and the error body is
//! never decoded (its presence is the signal).

use central_harness::event::{ToolStatus, Usage, UsageScope};

use crate::json::{self, JsonError};

/// `rejectedPermissionText` — the tool-state error of an auto-rejected
/// permission ask (verified live against 1.18.32, spec E4). A tool
/// error equal to it maps to `ToolDenied`; any other error maps to
/// `ToolError`.
const REJECTED_PERMISSION_TEXT: &str =
    "The user rejected permission to use this specific tool call.";

/// `frame` — one envelope: `{"type","timestamp","sessionID",…}`.
/// `part`/`error` keep the raw member bytes (Go `json.RawMessage`);
/// absent members are `None`, a JSON `null` member is `Some("null")`
/// exactly as a Go `RawMessage` holds the literal.
#[derive(Debug, Default)]
pub(crate) struct Frame {
    pub typ: String,
    pub session_id: String,
    pub part: Option<Vec<u8>>,
    pub error: Option<Vec<u8>>,
}

/// `decodeFrame` — one stdout line. Unknown fields are ignored; a
/// wrongly-typed known member fails the line (Go's unmarshal error).
pub(crate) fn decode_frame(line: &[u8]) -> Result<Frame, JsonError> {
    let members = json::object_members(line)?;
    let mut f = Frame::default();
    for (name, span) in &members {
        match name.as_str() {
            "type" => f.typ = json::field::<Option<String>>(line, span)?.unwrap_or_default(),
            "sessionID" => {
                f.session_id = json::field::<Option<String>>(line, span)?.unwrap_or_default();
            }
            "part" => f.part = Some(line[span.clone()].to_vec()),
            "error" => f.error = Some(line[span.clone()].to_vec()),
            _ => {}
        }
    }
    Ok(f)
}

/// `frameKind` — the envelope classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FrameKind {
    Unknown,
    StepStart,
    Text,
    Tool,
    StepFinish,
    Reasoning,
    Error,
}

impl Frame {
    /// `kind` — anything outside the six known types (including "")
    /// is unknown.
    pub(crate) fn kind(&self) -> FrameKind {
        match self.typ.as_str() {
            "step_start" => FrameKind::StepStart,
            "text" => FrameKind::Text,
            "tool_use" => FrameKind::Tool,
            "step_finish" => FrameKind::StepFinish,
            "reasoning" => FrameKind::Reasoning,
            "error" => FrameKind::Error,
            _ => FrameKind::Unknown,
        }
    }

    /// `hasErrorBody` — an error envelope must carry an `error` member
    /// that is not JSON `null`. A bodyless error line is not from the
    /// harness's own emit path, so the session warns on it instead of
    /// recording a failure.
    pub(crate) fn has_error_body(&self) -> bool {
        match &self.error {
            Some(raw) => trim_space(raw) != b"null",
            None => false,
        }
    }
}

/// `bytes.TrimSpace` on the small ASCII set Go uses.
fn trim_space(b: &[u8]) -> &[u8] {
    let ws = |c: &u8| matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c);
    let start = b.iter().position(|c| !ws(c)).unwrap_or(b.len());
    let end = b.iter().rposition(|c| !ws(c)).map_or(start, |i| i + 1);
    &b[start..end]
}

/// `decodeText` — the text of a text part. Empty text is usable:
/// empty parts are structural separators the session skips silently.
/// A missing `part` (`None`) fails exactly as `json.Unmarshal(nil,…)`
/// does upstream.
pub(crate) fn decode_text(part: Option<&[u8]>) -> Option<String> {
    let raw = part?;
    let members = json::object_members(raw).ok()?;
    let span = json::member(&members, "text")?;
    json::field::<Option<String>>(raw, span).ok()?
}

/// `toolCallData` — the decoded `ToolCall` half of a tool part;
/// `input` is the whitespace-compacted raw input, preserving the
/// harness spelling.
#[derive(Debug)]
pub(crate) struct ToolCallData {
    pub id: String,
    pub name: String,
    pub input: Vec<u8>,
}

/// `toolResultData` — the decoded `ToolResult` half.
#[derive(Debug)]
pub(crate) struct ToolResultData {
    pub id: String,
    pub status: ToolStatus,
    pub output: Vec<u8>,
}

/// `decodeTool` — a tool part into its call and result halves. The
/// envelope type decides the shape; `part.type` is not cross-checked.
/// A missing output or error member yields empty output bytes; a
/// status outside completed/error, or a missing id or tool name, is
/// unusable.
pub(crate) fn decode_tool(part: Option<&[u8]>) -> Option<(ToolCallData, ToolResultData)> {
    let raw = part?;
    let members = json::object_members(raw).ok()?;
    let tool = match json::member(&members, "tool") {
        Some(s) => json::field::<Option<String>>(raw, s).ok()?,
        None => None,
    }
    .unwrap_or_default();
    let call_id = match json::member(&members, "callID") {
        Some(s) => json::field::<Option<String>>(raw, s).ok()?,
        None => None,
    }
    .unwrap_or_default();
    let state_span = json::member(&members, "state")?;
    // `p.State *struct` — a JSON `null` is a nil pointer and a
    // non-object value is a whole-unmarshal error; both unusable.
    let state = json::object_members(&raw[state_span.clone()]).ok()?;
    if tool.is_empty() || call_id.is_empty() {
        return None;
    }
    let state_raw = &raw[state_span.clone()];
    let status = match json::member(&state, "status") {
        Some(s) => json::field::<Option<String>>(state_raw, s).ok()?,
        None => None,
    }
    .unwrap_or_default();
    let input = match json::member(&state, "input") {
        Some(s) => json::compact(&state_raw[s.clone()]).ok()?,
        None => Vec::new(),
    };
    let output = match json::member(&state, "output") {
        Some(s) => json::field::<Option<String>>(state_raw, s).ok()?,
        None => None,
    }
    .unwrap_or_default();
    let error = match json::member(&state, "error") {
        Some(s) => json::field::<Option<String>>(state_raw, s).ok()?,
        None => None,
    }
    .unwrap_or_default();
    let call = ToolCallData {
        id: call_id.clone(),
        name: tool,
        input,
    };
    match status.as_str() {
        "completed" => Some((
            call,
            ToolResultData {
                id: call_id,
                status: ToolStatus::Ok,
                output: output.into_bytes(),
            },
        )),
        "error" => {
            let status = if error == REJECTED_PERMISSION_TEXT {
                ToolStatus::Denied
            } else {
                ToolStatus::Error
            };
            Some((
                call,
                ToolResultData {
                    id: call_id,
                    status,
                    output: error.into_bytes(),
                },
            ))
        }
        _ => None,
    }
}

/// `tokenInt64` — one token counter strictly: only an integral int64
/// JSON number is usable. The raw literal text is parsed like
/// `json.Number.Int64()` (Go `ParseInt`), so fractions, exponents and
/// out-of-range values are all unusable.
fn token_int64(raw: &[u8]) -> Option<i64> {
    let s = std::str::from_utf8(raw).ok()?;
    s.parse::<i64>().ok()
}

fn non_negative(v: i64) -> i64 {
    if v < 0 { 0 } else { v }
}

/// `addCounter` — folds one step counter into a running total: values
/// at or below zero are ignored, and the sum saturates. Mirrors
/// claudecode. Upstream keeps the helper in this file for symmetry
/// though the session applies its rule inline.
#[allow(dead_code)]
pub(crate) fn add_counter(total: i64, step: i64) -> i64 {
    if step <= 0 {
        return total;
    }
    if step > i64::MAX - total {
        return i64::MAX;
    }
    total + step
}

/// `costMicroUSD` — USD to micro-USD, rounding half away from zero.
/// Negative or non-finite costs map to 0. Mirrors claudecode.
pub(crate) fn cost_micro_usd(usd: f64) -> i64 {
    if usd <= 0.0 || usd.is_nan() || usd.is_infinite() {
        return 0;
    }
    let micros = (usd * 1e6).round();
    if micros >= i64::MAX as f64 {
        return i64::MAX;
    }
    micros as i64
}

/// `decodeStep` — a step-finish part into a per-step usage report.
/// Tokens must be present integral int64 JSON numbers; fractional,
/// out-of-range or missing fields make the report unusable (the
/// session warns and skips it, never stops). Negative counters become
/// 0 within an emitted report, mirroring `addCounter`. Cost converts
/// by `costMicroUSD`; a missing cost is 0. `total` and `reason` are
/// ignored: the components are disjoint (spec E2) and the reason is a
/// provider-native string recorded in Raw only.
pub(crate) fn decode_step(part: Option<&[u8]>) -> Option<Usage> {
    let raw = part?;
    let members = json::object_members(raw).ok()?;
    let tokens_span = json::member(&members, "tokens")?;
    let tokens = json::object_members(&raw[tokens_span.clone()]).ok()?;
    let tokens_raw = &raw[tokens_span.clone()];
    let num = |name: &str| -> Option<i64> {
        let s = json::member(&tokens, name)?;
        token_int64(&tokens_raw[s.clone()])
    };
    let inp = num("input")?;
    let out = num("output")?;
    let reasoning = num("reasoning")?;
    let cache_span = json::member(&tokens, "cache")?;
    let cache_raw = &tokens_raw[cache_span.clone()];
    let cache = json::object_members(cache_raw).ok()?;
    let cnum = |name: &str| -> Option<i64> {
        let s = json::member(&cache, name)?;
        token_int64(&cache_raw[s.clone()])
    };
    let cache_read = cnum("read")?;
    let cache_write = cnum("write")?;
    // `Cost float64` — a missing or null member is 0; a wrongly-typed
    // or overflowing one is a whole-unmarshal error upstream.
    let cost = match json::member(&members, "cost") {
        Some(s) => {
            let c = json::field::<Option<f64>>(raw, s).ok()?;
            match c {
                Some(c) if c.is_finite() => c,
                Some(_) => return None,
                None => 0.0,
            }
        }
        None => 0.0,
    };
    let tokens_out = if reasoning > 0 && reasoning <= i64::MAX - out {
        out + reasoning
    } else if reasoning > 0 {
        i64::MAX
    } else {
        out
    };
    Some(Usage {
        tokens_in: non_negative(inp),
        tokens_out: non_negative(tokens_out),
        cache_read: non_negative(cache_read),
        cache_write: non_negative(cache_write),
        cost_micro_usd: cost_micro_usd(cost),
        scope: UsageScope::Step,
        estimated: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `TestDecodeFrame` / `TestFrameKind` — protocol_internal_test.go.
    #[test]
    fn decode_frame_and_kind() {
        let line = br#"{"type":"text","timestamp":1791640875576,"sessionID":"ses_abc","part":{"type":"text","text":"ok"}}"#;
        let f = decode_frame(line).unwrap();
        assert_eq!(f.typ, "text");
        assert_eq!(f.session_id, "ses_abc");
        assert!(f.part.is_some());
        assert!(decode_frame(br#"{"type":"#).is_err());
        assert!(decode_frame(b"not json").is_err());
        for (typ, want) in [
            ("step_start", FrameKind::StepStart),
            ("text", FrameKind::Text),
            ("tool_use", FrameKind::Tool),
            ("step_finish", FrameKind::StepFinish),
            ("reasoning", FrameKind::Reasoning),
            ("error", FrameKind::Error),
            ("future_x", FrameKind::Unknown),
            ("", FrameKind::Unknown),
            ("TEXT", FrameKind::Unknown),
        ] {
            let f = Frame {
                typ: typ.to_string(),
                ..Frame::default()
            };
            assert_eq!(f.kind(), want, "{typ}");
        }
    }

    /// `TestDecodeText`.
    #[test]
    fn decode_text_table() {
        assert_eq!(
            decode_text(Some(br#"{"type":"text","text":"ok"}"#)),
            Some("ok".to_string())
        );
        // Empty text is usable (the session skips it silently).
        assert_eq!(
            decode_text(Some(br#"{"type":"text","text":""}"#)),
            Some(String::new())
        );
        for bad in [
            r#"{"type":"text"}"#,
            r#"{"type":"text","text":42}"#,
            r#"{"type":"text","text":null}"#,
            "42",
            "[1]",
        ] {
            assert_eq!(decode_text(Some(bad.as_bytes())), None, "{bad}");
        }
        assert_eq!(decode_text(None), None);
    }

    /// `TestDecodeToolCompleted`.
    #[test]
    fn decode_tool_completed() {
        let part = br#"{"type":"tool","tool":"write","callID":"call_1","state":{"status":"completed","input":{"filePath": "/work/hello.txt", "content": "x"},"output":"Wrote file successfully.","title":"t","time":{"start":1,"end":2}}}"#;
        let (call, result) = decode_tool(Some(part)).expect("tool part rejected");
        assert_eq!(call.id, "call_1");
        assert_eq!(call.name, "write");
        // Input keeps the harness spelling, whitespace-compacted only.
        assert_eq!(
            call.input,
            br#"{"filePath":"/work/hello.txt","content":"x"}"#
        );
        assert_eq!(result.id, "call_1");
        assert_eq!(result.status, ToolStatus::Ok);
        assert_eq!(result.output, b"Wrote file successfully.");
    }

    /// `TestDecodeToolDenied`.
    #[test]
    fn decode_tool_denied() {
        let part = br#"{"type":"tool","tool":"read","callID":"call_2","state":{"status":"error","input":{"filePath":"/work/probe.env"},"error":"The user rejected permission to use this specific tool call.","time":{"start":1,"end":2}}}"#;
        let (_, result) = decode_tool(Some(part)).expect("denied tool part rejected");
        assert_eq!(result.status, ToolStatus::Denied);
    }

    /// `TestDecodeToolError`.
    #[test]
    fn decode_tool_error() {
        let near_miss = REJECTED_PERMISSION_TEXT.replacen("call.", "call..", 1);
        let part = format!(
            r#"{{"type":"tool","tool":"read","callID":"call_3","state":{{"status":"error","input":{{}},"error":{near_miss:?}}}}}"#
        );
        let (_, result) = decode_tool(Some(part.as_bytes())).expect("error tool part rejected");
        assert_eq!(result.status, ToolStatus::Error);
        let part2 = br#"{"type":"tool","tool":"read","callID":"call_4","state":{"status":"error","input":{},"error":"File not found: /work/x"}}"#;
        let (_, result2) = decode_tool(Some(part2)).expect("rejected");
        assert_eq!(result2.status, ToolStatus::Error);
        assert_eq!(result2.output, b"File not found: /work/x");
    }

    /// `TestDecodeToolRefuses`.
    #[test]
    fn decode_tool_refuses() {
        let cases = [
            (
                "missing tool",
                r#"{"type":"tool","callID":"call_1","state":{"status":"completed","input":{}}}"#,
            ),
            (
                "empty tool",
                r#"{"type":"tool","tool":"","callID":"call_1","state":{"status":"completed","input":{}}}"#,
            ),
            (
                "missing callID",
                r#"{"type":"tool","tool":"read","state":{"status":"completed","input":{}}}"#,
            ),
            (
                "empty callID",
                r#"{"type":"tool","tool":"read","callID":"","state":{"status":"completed","input":{}}}"#,
            ),
            (
                "missing state",
                r#"{"type":"tool","tool":"read","callID":"call_1"}"#,
            ),
            (
                "unknown status",
                r#"{"type":"tool","tool":"read","callID":"call_1","state":{"status":"running","input":{}}}"#,
            ),
            ("not an object", "42"),
        ];
        for (name, part) in cases {
            assert!(
                decode_tool(Some(part.as_bytes())).is_none(),
                "{name} accepted"
            );
        }
    }

    /// `TestDecodeStep` / `TestDecodeStepEdges`.
    #[test]
    fn decode_step_table() {
        let part = br#"{"type":"step-finish","reason":"stop","tokens":{"total":100,"input":80,"output":10,"reasoning":5,"cache":{"read":4,"write":1}},"cost":0.0025}"#;
        let u = decode_step(Some(part)).expect("step part rejected");
        let want = Usage {
            tokens_in: 80,
            tokens_out: 15,
            cache_read: 4,
            cache_write: 1,
            cost_micro_usd: 2500,
            scope: UsageScope::Step,
            estimated: false,
        };
        assert_eq!(u, want);
        // Negative counters become 0 within an emitted report.
        let u = decode_step(Some(
            br#"{"type":"step-finish","tokens":{"input":-5,"output":3,"reasoning":0,"cache":{"read":0,"write":0}},"cost":0}"#,
        ))
        .expect("negative-counter step rejected");
        assert_eq!(u.tokens_in, 0);
        assert_eq!(u.tokens_out, 3);
        // Missing cost is 0.
        let u = decode_step(Some(
            br#"{"type":"step-finish","tokens":{"input":1,"output":1,"reasoning":0,"cache":{"read":0,"write":0}}}"#,
        ))
        .expect("missing cost rejected");
        assert_eq!(u.cost_micro_usd, 0);
        for (name, part) in [
            (
                "fractional input",
                r#"{"type":"step-finish","tokens":{"input":3.5,"output":1,"reasoning":0,"cache":{"read":0,"write":0}},"cost":0}"#,
            ),
            (
                "huge output",
                r#"{"type":"step-finish","tokens":{"input":1,"output":9223372036854775808,"reasoning":0,"cache":{"read":0,"write":0}},"cost":0}"#,
            ),
            ("missing tokens", r#"{"type":"step-finish","cost":0}"#),
            (
                "missing cache",
                r#"{"type":"step-finish","tokens":{"input":1,"output":1,"reasoning":0},"cost":0}"#,
            ),
            (
                "string cost",
                r#"{"type":"step-finish","tokens":{"input":1,"output":1,"reasoning":0,"cache":{"read":0,"write":0}},"cost":"0"}"#,
            ),
            ("not an object", "42"),
        ] {
            assert!(
                decode_step(Some(part.as_bytes())).is_none(),
                "{name} accepted"
            );
        }
    }

    /// `TestCostMicroUSD`.
    #[test]
    fn cost_micro_usd_table() {
        for (usd, want) in [
            (0.0, 0),
            (-1.0, 0),
            (f64::NAN, 0),
            (f64::INFINITY, 0),
            (f64::NEG_INFINITY, 0),
            (0.0000004, 0),
            (0.000001, 1),
            (0.0025, 2500),
            (1.23456789, 1234568),
            (1000.0, 1_000_000_000),
            (1e20, i64::MAX),
        ] {
            assert_eq!(cost_micro_usd(usd), want, "costMicroUSD({usd})");
        }
    }

    /// `TestAddCounter`.
    #[test]
    fn add_counter_table() {
        assert_eq!(add_counter(10, 5), 15);
        assert_eq!(add_counter(10, 0), 10);
        assert_eq!(add_counter(10, -5), 10);
        assert_eq!(add_counter(i64::MAX, 1), i64::MAX);
        assert_eq!(add_counter(i64::MAX - 1, 1), i64::MAX);
    }
}
