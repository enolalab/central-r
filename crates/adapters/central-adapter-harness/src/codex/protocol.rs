//! `protocol.go` — the `codex exec --json` envelope grammar and the
//! item decoders.
//!
//! Frames decode through the crate's byte-level scanner
//! ([`crate::json`]): the whole line must be one JSON object (Go
//! `json.Unmarshal`'s top-level rule), `usage`/`item`/`error` keep raw
//! spans so tool inputs are never re-encoded, and member decodes use
//! `Option<…>` targets so JSON `null` is the no-op it is for a Go zero
//! field. Unknown fields are ignored; error bodies are never decoded
//! (their presence is the signal).

use central_harness::event::{ToolStatus, Usage, UsageScope};

use crate::json::{self, JsonError};

/// `frame` — one envelope: `{"type", …}` plus, by type, `thread_id`,
/// `usage`, `item` or `error` members. The last three keep the raw
/// member bytes (Go `json.RawMessage`); absent members are `None`, a
/// JSON `null` member is `Some("null")` exactly as a Go `RawMessage`
/// holds the literal.
#[derive(Debug, Default)]
pub(crate) struct Frame {
    pub typ: String,
    pub thread_id: String,
    pub usage: Option<Vec<u8>>,
    pub item: Option<Vec<u8>>,
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
            "thread_id" => {
                f.thread_id = json::field::<Option<String>>(line, span)?.unwrap_or_default();
            }
            "usage" => f.usage = Some(line[span.clone()].to_vec()),
            "item" => f.item = Some(line[span.clone()].to_vec()),
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
    ThreadStarted,
    TurnStarted,
    TurnCompleted,
    TurnFailed,
    ItemStarted,
    ItemUpdated,
    ItemCompleted,
    TopError,
}

impl Frame {
    /// `kind` — maps the envelope type; anything else (including "")
    /// is unknown.
    pub(crate) fn kind(&self) -> FrameKind {
        match self.typ.as_str() {
            "thread.started" => FrameKind::ThreadStarted,
            "turn.started" => FrameKind::TurnStarted,
            "turn.completed" => FrameKind::TurnCompleted,
            "turn.failed" => FrameKind::TurnFailed,
            "item.started" => FrameKind::ItemStarted,
            "item.updated" => FrameKind::ItemUpdated,
            "item.completed" => FrameKind::ItemCompleted,
            "error" => FrameKind::TopError,
            _ => FrameKind::Unknown,
        }
    }
}

/// `decodeText` — the text of an `agent_message` item. Empty text is
/// unusable: the session skips it (spec D3 emits nothing for it).
pub(crate) fn decode_text(item: &[u8]) -> Option<String> {
    let members = json::object_members(item).ok()?;
    let mut typ = String::new();
    let mut text: Option<String> = None;
    for (name, span) in &members {
        match name.as_str() {
            "type" => {
                typ = json::field::<Option<String>>(item, span)
                    .ok()?
                    .unwrap_or_default()
            }
            "text" => text = json::field::<Option<String>>(item, span).ok()?,
            _ => {}
        }
    }
    match text {
        Some(t) if typ == "agent_message" && !t.is_empty() => Some(t),
        _ => None,
    }
}

/// `toolCallData` — the decoded ToolCall half of a tool item; `input`
/// is the discriminating field (a decoded string, or
/// whitespace-compacted raw JSON preserving the harness spelling),
/// `None` when absent.
#[derive(Debug)]
pub(crate) struct ToolCallData {
    pub id: String,
    pub name: String,
    /// Absent input is the empty bytes of a Go nil `[]byte`.
    pub input: Vec<u8>,
}

/// `toolResultData` — the decoded ToolResult half of a tool item.
#[derive(Debug)]
pub(crate) struct ToolResultData {
    pub id: String,
    pub status: ToolStatus,
    /// Absent output is the empty bytes of a Go nil `[]byte`.
    pub output: Vec<u8>,
}

/// `toolItem` — the shared envelope of every tool item: id plus a
/// flattened type-specific payload.
struct ToolHead {
    id: String,
    typ: String,
}

/// `decodeToolHead` — the id and type of a tool item; both must be
/// present and non-empty.
fn decode_tool_head(item: &[u8]) -> Option<ToolHead> {
    let members = json::object_members(item).ok()?;
    let mut head = ToolHead {
        id: String::new(),
        typ: String::new(),
    };
    for (name, span) in &members {
        match name.as_str() {
            "id" => {
                head.id = json::field::<Option<String>>(item, span)
                    .ok()?
                    .unwrap_or_default()
            }
            "type" => {
                head.typ = json::field::<Option<String>>(item, span)
                    .ok()?
                    .unwrap_or_default();
            }
            _ => {}
        }
    }
    if head.id.is_empty() || head.typ.is_empty() {
        return None;
    }
    Some(head)
}

/// `isToolType` — whether an item type maps to ToolCall/ToolResult
/// (spec D3). Anything else (agent_message, reasoning, todo_list,
/// error) is handled by its own row, and an unknown type warns.
fn is_tool_type(t: &str) -> bool {
    matches!(
        t,
        "command_execution" | "file_change" | "mcp_tool_call" | "web_search" | "collab_tool_call"
    )
}

/// `compact` — the whitespace-compacted raw bytes, or `None` when the
/// member is absent. Present-but-invalid JSON is unusable.
fn compact_raw(raw: Option<&Vec<u8>>) -> Option<Option<Vec<u8>>> {
    match raw {
        None => Some(None),
        Some(b) => json::compact(b).ok().map(Some),
    }
}

/// `decodeToolStart` — the ToolCall half of a started tool item. The
/// name is the item type verbatim.
pub(crate) fn decode_tool_start(item: &[u8]) -> Option<ToolCallData> {
    let head = decode_tool_head(item)?;
    if !is_tool_type(&head.typ) {
        return None;
    }
    let input = tool_input(&head, item)?;
    Some(ToolCallData {
        id: head.id,
        name: head.typ,
        input,
    })
}

/// `decodeToolCompleted` — a completed tool item's call and result
/// halves, so a completed-only item (file_change normally arrives
/// without a start) still yields the pair. Returns
/// `(call, result, terminal)`; `terminal=false` is `in_progress`
/// (the caller's warning — spec D3: it decodes here as an error
/// result and the session warns on it).
pub(crate) fn decode_tool_completed(item: &[u8]) -> Option<(ToolCallData, ToolResultData, bool)> {
    let head = decode_tool_head(item)?;
    if !is_tool_type(&head.typ) {
        return None;
    }
    let input = tool_input(&head, item)?;
    let (output, status, terminal) = tool_output(&head, item)?;
    let call = ToolCallData {
        id: head.id.clone(),
        name: head.typ,
        input,
    };
    let status = if terminal { status } else { ToolStatus::Error };
    Some((
        call,
        ToolResultData {
            id: head.id,
            status,
            output,
        },
        terminal,
    ))
}

/// `toolInput` — the discriminating field of a tool item (spec D3,
/// plan Task 2): decoded strings as bytes, structured fields
/// compacted, absent as empty (Go's nil `[]byte`). `None` means
/// unusable.
fn tool_input(head: &ToolHead, item: &[u8]) -> Option<Vec<u8>> {
    let members = json::object_members(item).ok()?;
    let mut command: Option<String> = None;
    let mut changes: Option<Vec<u8>> = None;
    let mut arguments: Option<Vec<u8>> = None;
    let mut query: Option<String> = None;
    let mut prompt: Option<String> = None;
    for (name, span) in &members {
        match name.as_str() {
            "command" => command = json::field::<Option<String>>(item, span).ok()?,
            "changes" => changes = Some(item[span.clone()].to_vec()),
            "arguments" => arguments = Some(item[span.clone()].to_vec()),
            "query" => query = json::field::<Option<String>>(item, span).ok()?,
            "prompt" => prompt = json::field::<Option<String>>(item, span).ok()?,
            _ => {}
        }
    }
    match head.typ.as_str() {
        "command_execution" => command.map(|c| c.into_bytes()),
        "file_change" => compact_raw(changes.as_ref()).map(|o| o.unwrap_or_default()),
        "mcp_tool_call" => compact_raw(arguments.as_ref()).map(|o| o.unwrap_or_default()),
        "web_search" => query.map(|q| q.into_bytes()),
        "collab_tool_call" => Some(prompt.map(|p| p.into_bytes()).unwrap_or_default()),
        _ => None,
    }
}

/// `toolOutput` — the result field and status of a completed tool
/// item. Returns `terminal=false` for `in_progress` (the session
/// warns and the error status applies); any other unknown status, or
/// a missing status (outside web_search), is unusable.
fn tool_output(head: &ToolHead, item: &[u8]) -> Option<(Vec<u8>, ToolStatus, bool)> {
    let members = json::object_members(item).ok()?;
    let mut status: Option<String> = None;
    let mut aggregated: Option<String> = None;
    let mut result: Option<Vec<u8>> = None;
    let mut error: Option<Vec<u8>> = None;
    let mut results: Option<Vec<u8>> = None;
    let mut agents_states: Option<Vec<u8>> = None;
    for (name, span) in &members {
        match name.as_str() {
            "status" => status = json::field::<Option<String>>(item, span).ok()?,
            "aggregated_output" => {
                aggregated = json::field::<Option<String>>(item, span).ok()?;
            }
            "result" => result = Some(item[span.clone()].to_vec()),
            "error" => error = Some(item[span.clone()].to_vec()),
            "results" => results = Some(item[span.clone()].to_vec()),
            "agents_states" => agents_states = Some(item[span.clone()].to_vec()),
            _ => {}
        }
    }
    let Some(status) = status else {
        // WebSearchItem carries no status in the schema: the
        // item.completed event itself is the completion signal.
        if head.typ != "web_search" {
            return None;
        }
        let out = compact_raw(results.as_ref())?.unwrap_or_default();
        return Some((out, ToolStatus::Ok, true));
    };
    let raw_status = status;
    let (status, terminal) = match raw_status.as_str() {
        "completed" => (ToolStatus::Ok, true),
        "failed" => (ToolStatus::Error, true),
        "declined" => (ToolStatus::Denied, true),
        "in_progress" => (ToolStatus::Error, false),
        _ => return None,
    };
    let out = match head.typ.as_str() {
        "command_execution" => match aggregated {
            Some(s) if !s.is_empty() => s.into_bytes(),
            _ => Vec::new(),
        },
        // Upstream emits the raw status string verbatim
        // (`[]byte(*p.Status)`).
        "file_change" => raw_status.into_bytes(),
        "mcp_tool_call" => {
            if result.is_some() {
                compact_raw(result.as_ref())?.unwrap_or_default()
            } else if error.is_some() {
                compact_raw(error.as_ref())?.unwrap_or_default()
            } else {
                Vec::new()
            }
        }
        "web_search" => compact_raw(results.as_ref())?.unwrap_or_default(),
        "collab_tool_call" => compact_raw(agents_states.as_ref())?.unwrap_or_default(),
        _ => return None,
    };
    Some((out, status, terminal))
}

/// `inProgressCompleted` — whether a completed tool item carries the
/// non-terminal `in_progress` status (spec D3 warns on it).
pub(crate) fn in_progress_completed(item: &[u8]) -> bool {
    let Ok(members) = json::object_members(item) else {
        return false;
    };
    for (name, span) in &members {
        if name == "status" {
            if let Ok(Some(s)) = json::field::<Option<String>>(item, span) {
                return s == "in_progress";
            }
            return false;
        }
    }
    false
}

/// `itemSkip` — a completed item the tool and text decoders refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ItemSkip {
    Unknown,
    /// `itemSilent` — reasoning, todo_list, and an agent_message
    /// whose text is empty or missing (spec D3 emits nothing for
    /// that row).
    Silent,
    /// `itemErrorNoted` — warns and skips: error items are non-fatal
    /// by construction (spec S2).
    ErrorNoted,
}

/// `skippableItem` — classifies a completed item the tool and text
/// decoders refused.
pub(crate) fn skippable_item(item: &[u8]) -> ItemSkip {
    let Ok(members) = json::object_members(item) else {
        return ItemSkip::Unknown;
    };
    let mut typ: Option<String> = None;
    let mut text: Option<String> = None;
    for (name, span) in &members {
        match name.as_str() {
            "type" => {
                typ = match json::field::<Option<String>>(item, span) {
                    Ok(t) => t,
                    Err(_) => return ItemSkip::Unknown,
                };
            }
            "text" => {
                text = match json::field::<Option<String>>(item, span) {
                    Ok(t) => t,
                    Err(_) => return ItemSkip::Unknown,
                };
            }
            _ => {}
        }
    }
    let Some(typ) = typ else {
        return ItemSkip::Unknown;
    };
    match typ.as_str() {
        "reasoning" | "todo_list" => ItemSkip::Silent,
        "error" => ItemSkip::ErrorNoted,
        "agent_message" => match text {
            None => ItemSkip::Silent,
            Some(t) if t.is_empty() => ItemSkip::Silent,
            _ => ItemSkip::Unknown,
        },
        _ => ItemSkip::Unknown,
    }
}

/// `decodeUsage` — a turn-completed usage member into a
/// session-cumulative report (spec D3). The four required counters
/// must be integral non-negative int64 JSON numbers; fractional,
/// negative, out-of-range or missing fields make the whole report
/// unusable (the session warns and skips it, never stops).
/// `cache_write_input_tokens` is optional (absent means 0, its serde
/// default); `total_tokens` is ignored. Reasoning folds into output
/// (both billed as output), saturating.
pub(crate) fn decode_usage(raw: &[u8]) -> Option<Usage> {
    let members = json::object_members(raw).ok()?;
    let mut input: Option<i64> = None;
    let mut cached: Option<i64> = None;
    let mut cache_write: Option<i64> = None;
    let mut output: Option<i64> = None;
    let mut reasoning: Option<i64> = None;
    for (name, span) in &members {
        match name.as_str() {
            "input_tokens" => input = Some(token_int64(raw, span)?),
            "cached_input_tokens" => cached = Some(token_int64(raw, span)?),
            "cache_write_input_tokens" => {
                // Optional: absent means 0; null is unusable (Go's
                // *json.Number nil-check passes null as present? —
                // upstream decodes `"cache_write_input_tokens":null`
                // to nil pointer → 0).
                match json::field::<serde_json::Value>(raw, span) {
                    Ok(serde_json::Value::Null) => cache_write = Some(0),
                    _ => cache_write = Some(token_int64(raw, span)?),
                }
            }
            "output_tokens" => output = Some(token_int64(raw, span)?),
            "reasoning_output_tokens" => reasoning = Some(token_int64(raw, span)?),
            _ => {}
        }
    }
    let input = input?;
    let cached = cached?;
    let output = output?;
    let reasoning = reasoning?;
    if input < 0 || cached < 0 || output < 0 || reasoning < 0 {
        return None;
    }
    let cache_write = cache_write.unwrap_or(0);
    if cache_write < 0 {
        return None;
    }
    Some(Usage {
        tokens_in: input,
        tokens_out: add_counter(output, reasoning),
        cache_read: cached,
        cache_write,
        cost_micro_usd: 0,
        scope: UsageScope::SessionCumulative,
        estimated: false,
    })
}

/// `tokenInt64` — one token counter strictly: only an integral int64
/// JSON number is usable. `json.Number.Int64` rejects fractions,
/// exponents and out-of-range values alike; a missing member decodes
/// as `""` and is rejected too.
fn token_int64(raw: &[u8], span: &json::Span) -> Option<i64> {
    // Go's json.Number accepts only the bare JSON number token; a
    // string or other type fails the whole decode upstream (the field
    // is json.Number, not *). Number.Int64 then rejects fractions and
    // exponents.
    let n = json::field::<serde_json::Number>(raw, span).ok()?;
    n.as_i64()
}

/// `addCounter` — folds one counter into a running total: values at
/// or below zero are ignored, and the sum saturates.
#[allow(dead_code)]
fn add_counter(total: i64, step: i64) -> i64 {
    if step <= 0 {
        return total;
    }
    total.saturating_add(step)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `TestDecodeFrameKinds`.
    #[test]
    fn decode_frame_kinds() {
        let cases = [
            (
                r#"{"type":"thread.started","thread_id":"x"}"#,
                FrameKind::ThreadStarted,
            ),
            (r#"{"type":"turn.started"}"#, FrameKind::TurnStarted),
            (
                r#"{"type":"turn.completed","usage":{}}"#,
                FrameKind::TurnCompleted,
            ),
            (
                r#"{"type":"turn.failed","error":{"message":"x"}}"#,
                FrameKind::TurnFailed,
            ),
            (
                r#"{"type":"item.started","item":{}}"#,
                FrameKind::ItemStarted,
            ),
            (
                r#"{"type":"item.updated","item":{}}"#,
                FrameKind::ItemUpdated,
            ),
            (
                r#"{"type":"item.completed","item":{}}"#,
                FrameKind::ItemCompleted,
            ),
            (r#"{"type":"error","message":"x"}"#, FrameKind::TopError),
            (r#"{"type":"something.else"}"#, FrameKind::Unknown),
            (r#"{"type":""}"#, FrameKind::Unknown),
            (r#"{"nope":1}"#, FrameKind::Unknown),
        ];
        for (line, want) in cases {
            let f = decode_frame(line.as_bytes()).unwrap();
            assert_eq!(f.kind(), want, "{line}");
        }
        let f = decode_frame(
            br#"{"type":"thread.started","thread_id":"t1","usage":{"input_tokens":1},"item":{"id":"i"},"error":{"m":"e"}}"#,
        )
        .unwrap();
        assert_eq!(f.thread_id, "t1");
        assert_eq!(f.usage.unwrap(), br#"{"input_tokens":1}"#);
        assert_eq!(f.item.unwrap(), br#"{"id":"i"}"#);
        assert_eq!(f.error.unwrap(), br#"{"m":"e"}"#);
    }

    /// `TestDecodeFrameMalformed`.
    #[test]
    fn decode_frame_malformed() {
        for bad in [
            b"".as_slice(),
            b"not json",
            b"{",
            b"[1,2]",
            br#"{"type":123}"#,
            br#"{"thread_id":{"x":1}}"#,
            br#"{"type":null}"#.as_slice(),
        ] {
            // `null` type decodes fine to "" in Go — so it must parse;
            // the session checks typ.is_empty separately.
            if bad == br#"{"type":null}"#.as_slice() {
                let f = decode_frame(bad).unwrap();
                assert!(f.typ.is_empty());
                continue;
            }
            assert!(decode_frame(bad).is_err(), "{bad:?}");
        }
    }

    /// `TestDecodeText`.
    #[test]
    fn decode_text_table() {
        let ok = r#"{"id":"i1","type":"agent_message","text":"hi"}"#;
        assert_eq!(decode_text(ok.as_bytes()).as_deref(), Some("hi"));
        for bad in [
            r#"{"id":"i1","type":"command_execution","text":"hi"}"#,
            r#"{"id":"i1","type":"agent_message","text":""}"#,
            r#"{"id":"i1","type":"agent_message"}"#,
            r#"{"id":"i1","type":"agent_message","text":null}"#,
            r#"{"type":"agent_message","text":5}"#,
            "not json",
        ] {
            let b: &[u8] = bad.as_ref();
            assert!(decode_text(b).is_none(), "{b:?}");
        }
    }

    /// `TestDecodeToolStart` / `TestDecodeToolCompleted` /
    /// `TestMCPNullArguments`.
    #[test]
    fn decode_tool_start_table() {
        let started = r#"{"id":"item_0","type":"command_execution","command":"cat hello.txt","status":"in_progress"}"#;
        let c = decode_tool_start(started.as_bytes()).unwrap();
        assert_eq!(c.id, "item_0");
        assert_eq!(c.name, "command_execution");
        assert_eq!(c.input, b"cat hello.txt".to_vec());
        // mcp with null arguments → compact of "null" is "null".
        let mcp = r#"{"id":"m","type":"mcp_tool_call","arguments":null}"#;
        let c = decode_tool_start(mcp.as_bytes()).unwrap();
        assert_eq!(c.input, b"null".to_vec());
        // collab without prompt → absent input.
        let col = r#"{"id":"c","type":"collab_tool_call"}"#;
        let c = decode_tool_start(col.as_bytes()).unwrap();
        assert!(c.input.is_empty());
        // non-tool type → None; missing id → None; missing required input → None.
        assert!(decode_tool_start(br#"{"id":"x","type":"agent_message","text":"t"}"#).is_none());
        assert!(decode_tool_start(br#"{"type":"command_execution","command":"x"}"#).is_none());
        assert!(decode_tool_start(br#"{"id":"x","type":"command_execution"}"#).is_none());
        assert!(decode_tool_start(br#"{"id":"x","type":"web_search"}"#).is_none());
        assert!(decode_tool_start(br#"{"id":"x","type":"unknown"}"#).is_none());
    }

    /// `TestDecodeToolCompleted` — status and per-type output.
    #[test]
    fn decode_tool_completed_table() {
        // command completed with output.
        let (c, r, term) = decode_tool_completed(
            br#"{"id":"a","type":"command_execution","command":"ls","aggregated_output":"OUT","status":"completed"}"#,
        )
        .unwrap();
        assert_eq!((r.status, term), (ToolStatus::Ok, true));
        assert_eq!(r.output, b"OUT".to_vec());
        assert_eq!(c.input, b"ls".to_vec());
        // empty aggregated_output → no output.
        let (_, r, _) = decode_tool_completed(
            br#"{"id":"a","type":"command_execution","command":"ls","aggregated_output":"","status":"completed"}"#,
        )
        .unwrap();
        assert!(r.output.is_empty());
        // failed / declined.
        let (_, r, _) = decode_tool_completed(
            br#"{"id":"a","type":"command_execution","command":"ls","aggregated_output":"E","status":"failed"}"#,
        )
        .unwrap();
        assert_eq!(r.status, ToolStatus::Error);
        let (_, r, _) = decode_tool_completed(
            br#"{"id":"a","type":"command_execution","command":"ls","status":"declined"}"#,
        )
        .unwrap();
        assert_eq!(r.status, ToolStatus::Denied);
        // in_progress → error status, terminal=false.
        let (_, r, term) = decode_tool_completed(
            br#"{"id":"a","type":"command_execution","command":"ls","status":"in_progress"}"#,
        )
        .unwrap();
        assert_eq!((r.status, term), (ToolStatus::Error, false));
        // unknown status → unusable.
        assert!(
            decode_tool_completed(
                br#"{"id":"a","type":"command_execution","command":"ls","status":"weird"}"#
            )
            .is_none()
        );
        // file_change output is the status verbatim.
        let (_, r, _) = decode_tool_completed(
            br#"{"id":"f","type":"file_change","changes":[{"path":"/p","kind":"add"}],"status":"completed"}"#,
        )
        .unwrap();
        assert_eq!(r.output, b"completed".to_vec());
        // mcp result then error precedence.
        let (_, r, _) = decode_tool_completed(
            br#"{"id":"m","type":"mcp_tool_call","arguments":{"q":"x"},"result":{"a":1},"status":"completed"}"#,
        )
        .unwrap();
        assert_eq!(r.output, br#"{"a":1}"#.to_vec());
        let (_, r, _) = decode_tool_completed(
            br#"{"id":"m","type":"mcp_tool_call","error":{"e":2},"status":"failed"}"#,
        )
        .unwrap();
        assert_eq!(r.output, br#"{"e":2}"#.to_vec());
        // web_search: no status → OK with results.
        let (_, r, _) = decode_tool_completed(
            br#"{"id":"w","type":"web_search","query":"q","results":[{"url":"u"}]}"#,
        )
        .unwrap();
        assert_eq!(r.status, ToolStatus::Ok);
        assert_eq!(r.output, br#"[{"url":"u"}]"#.to_vec());
        // collab → agents_states.
        let (_, r, _) = decode_tool_completed(
            br#"{"id":"c","type":"collab_tool_call","agents_states":{"x":{"status":"completed"}},"status":"completed"}"#,
        )
        .unwrap();
        assert_eq!(r.output, br#"{"x":{"status":"completed"}}"#.to_vec());
    }

    /// `TestDecodeUsage` / `TestTokenInt64` / `TestUsageReasoningSaturates`.
    #[test]
    fn decode_usage_table() {
        let u = decode_usage(
            br#"{"input_tokens":200,"cached_input_tokens":60,"cache_write_input_tokens":8,"output_tokens":50,"reasoning_output_tokens":12,"total_tokens":330}"#,
        )
        .unwrap();
        assert_eq!(u.tokens_in, 200);
        assert_eq!(u.tokens_out, 62, "reasoning folds into output");
        assert_eq!(u.cache_read, 60);
        assert_eq!(u.cache_write, 8);
        assert_eq!(u.cost_micro_usd, 0);
        assert_eq!(u.scope, UsageScope::SessionCumulative);
        // cache_write absent → 0.
        let u = decode_usage(
            br#"{"input_tokens":1,"cached_input_tokens":2,"output_tokens":3,"reasoning_output_tokens":4}"#,
        )
        .unwrap();
        assert_eq!(u.cache_write, 0);
        // saturation.
        let u = decode_usage(
            br#"{"input_tokens":0,"cached_input_tokens":0,"output_tokens":9223372036854775807,"reasoning_output_tokens":1}"#,
        )
        .unwrap();
        assert_eq!(u.tokens_out, i64::MAX);
        // unusable cases.
        for bad in [
            br#"{"input_tokens":1.5,"cached_input_tokens":0,"output_tokens":0,"reasoning_output_tokens":0}"#.as_slice(),
            br#"{"input_tokens":-1,"cached_input_tokens":0,"output_tokens":0,"reasoning_output_tokens":0}"#.as_slice(),
            br#"{"cached_input_tokens":0,"output_tokens":0,"reasoning_output_tokens":0}"#.as_slice(),
            br#"{"input_tokens":1e3,"cached_input_tokens":0,"output_tokens":0,"reasoning_output_tokens":0}"#.as_slice(),
            br#"{"input_tokens":"5","cached_input_tokens":0,"output_tokens":0,"reasoning_output_tokens":0}"#.as_slice(),
            br#"{"input_tokens":0,"cached_input_tokens":0,"output_tokens":0,"reasoning_output_tokens":0,"cache_write_input_tokens":-1}"#.as_slice(),
            b"not json".as_slice(),
        ] {
            assert!(decode_usage(bad).is_none(), "{bad:?}");
        }
        assert_eq!(add_counter(10, 0), 10);
        assert_eq!(add_counter(10, -3), 10);
        assert_eq!(add_counter(i64::MAX - 1, 5), i64::MAX);
        assert_eq!(add_counter(5, 5), 10);
    }

    /// `skippableItem` + `inProgressCompleted`.
    #[test]
    fn skip_classification() {
        assert_eq!(
            skippable_item(br#"{"id":"r","type":"reasoning"}"#),
            ItemSkip::Silent
        );
        assert_eq!(
            skippable_item(br#"{"id":"t","type":"todo_list"}"#),
            ItemSkip::Silent
        );
        assert_eq!(
            skippable_item(br#"{"id":"e","type":"error","message":"m"}"#),
            ItemSkip::ErrorNoted
        );
        assert_eq!(
            skippable_item(br#"{"id":"a","type":"agent_message","text":""}"#),
            ItemSkip::Silent
        );
        assert_eq!(
            skippable_item(br#"{"id":"a","type":"agent_message"}"#),
            ItemSkip::Silent
        );
        assert_eq!(
            skippable_item(br#"{"id":"a","type":"agent_message","text":"x"}"#),
            ItemSkip::Unknown
        );
        assert_eq!(
            skippable_item(br#"{"id":"u","type":"weird"}"#),
            ItemSkip::Unknown
        );
        assert_eq!(skippable_item(b"not json"), ItemSkip::Unknown);
        assert!(in_progress_completed(
            br#"{"id":"a","type":"command_execution","status":"in_progress"}"#
        ));
        assert!(!in_progress_completed(
            br#"{"id":"a","type":"command_execution","status":"completed"}"#
        ));
        assert!(!in_progress_completed(
            br#"{"id":"a","type":"command_execution"}"#
        ));
    }
}
