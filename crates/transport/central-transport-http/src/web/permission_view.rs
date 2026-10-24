//! Harness permission views (upstream `permission_view.go`) — display-only
//! projections of a Run's pending permission request and history. The
//! decision route re-checks every fact from durable state; everything here
//! is rendered through the visible-transformation pipeline so the operator
//! can allow only what they actually saw.

use std::collections::HashSet;
use std::fmt::Write as _;

use time::OffsetDateTime;

use super::format_timestamp;
use super::harness::{HarnessPermissionPanel, HarnessPermissionRecord};

// Fixed operator-facing texts (decisions 4, 12 and 17).
/// The auto-allow acknowledgement/warning text.
pub const AUTO_ALLOW_WARNING: &str = "Auto-allow: the harness runs every tool without asking, and can change your own Claude Code settings.";
/// The note under the policy select.
pub const USER_SETTINGS_NOTE: &str = "Your own ~/.claude permission rules and hooks also apply.";
/// OpenCode's deny-only note.
pub const OPENCODE_DENY_ONLY_NOTE: &str = "The OpenCode backend runs deny-only: permission asks are auto-rejected. See the harness runbook.";
/// Codex's deny-only note.
pub const CODEX_DENY_ONLY_NOTE: &str =
    "The Codex backend runs deny-only: permission asks are auto-rejected. See the harness runbook.";
/// Antigravity's deny-only note.
pub const ANTIGRAVITY_DENY_ONLY_NOTE: &str = "The Antigravity backend runs deny-only: permission asks are auto-denied. See the harness runbook.";
/// The stale-decision page notice.
pub const PERMISSION_NOT_PENDING_MSG: &str = "This request is no longer pending.";
/// The non-allowable panel copy.
pub const AWAITING_RECONCILIATION: &str = "Waiting for restart reconciliation, or the run is stopping: this request cannot be answered from here.";
/// The deny-only notice for a repeated member name.
pub const DUPLICATE_KEYS_NOTICE: &str = "This input repeats a field name, so what the tool would run is ambiguous. It can only be denied.";
/// The deny-only notice for malformed input.
pub const MALFORMED_INPUT_NOTICE: &str = "This input is not one well-formed JSON value (it has trailing data, say), so what the tool would run is ambiguous. It is shown as received and can only be denied.";
/// The detail page's query flag after a decision that no longer applied.
pub const PERMISSION_STALE_QUERY: &str = "permission";
/// Its value.
pub const PERMISSION_STALE_VALUE: &str = "stale";

/// One top-level member of a tool input object: the key as its JSON
/// string literal, a string value decoded, any other value as compact
/// JSON — all already made visible.
#[derive(Debug, Clone)]
pub struct PermissionInputField {
    /// The visible key literal (`"command"`).
    pub key: String,
    /// The visible value.
    pub value: String,
    /// Lines in the shown value (before markers).
    pub lines: usize,
    /// Bytes in the shown value (before markers).
    pub bytes: usize,
}

/// The pending request panel (decision 13).
#[derive(Debug, Clone, Default)]
pub struct PermissionPanelView {
    /// The approval id the decision form posts back.
    pub approval_id: String,
    /// The tool name, made visible.
    pub tool_name: String,
    /// The tool call id, made visible.
    pub tool_call_id: String,
    /// The resources, each made visible.
    pub resources: Vec<String>,
    /// Human input size.
    pub input_size: String,
    /// Object inputs, member by member in their own order.
    pub fields: Vec<PermissionInputField>,
    /// Any other input, made visible.
    pub raw: String,
    /// Lines in the raw input.
    pub raw_lines: usize,
    /// Bytes in the raw input.
    pub raw_bytes: usize,
    /// The hex MAC the decision form posts back.
    pub input_mac: String,
    /// When the request expires.
    pub expires_at: String,
    /// Time until expiry, rounded to the second.
    pub time_left: String,
    /// Whether Allow is offered (this process holds the request).
    pub allowable: bool,
    /// The non-allowable explanation.
    pub waiting: &'static str,
    /// Whether the input is ambiguous (deny-only).
    pub ambiguous: bool,
    /// The ambiguity notice.
    pub ambiguous_notice: &'static str,
}

/// One row of a Run's permission history.
#[derive(Debug, Clone)]
pub struct PermissionHistoryRow {
    /// The tool name, made visible.
    pub tool_name: String,
    /// The recorded outcome.
    pub outcome: String,
    /// Who decided, made visible.
    pub decided_by: String,
    /// When (decision time, else request time).
    pub at: String,
}

/// `buildPermissionPanel` — `None` input yields `None`; a non-allowable
/// request renders the waiting copy with no buttons.
#[must_use]
pub fn build_permission_panel(
    p: Option<&HarnessPermissionPanel>,
    now: OffsetDateTime,
) -> Option<PermissionPanelView> {
    let p = p?;
    let mut v = PermissionPanelView {
        approval_id: p.approval_id.to_string(),
        tool_name: visible_text(&p.tool_name),
        tool_call_id: visible_text(&p.tool_call_id),
        resources: p.resources.iter().map(|r| visible_text(r)).collect(),
        input_size: format!("{} bytes", p.input_size),
        input_mac: p.input_mac.clone(),
        expires_at: format_timestamp(p.expires_at),
        time_left: time_left(p.expires_at, now),
        allowable: p.allowable,
        ..PermissionPanelView::default()
    };
    if !p.allowable {
        v.waiting = AWAITING_RECONCILIATION;
        return Some(v);
    }
    let (fields, raw, notice) = render_permission_input(&p.input);
    if !fields.is_empty() {
        v.fields = fields;
    } else {
        let raw_str = if raw.is_empty() {
            String::from_utf8_lossy(&p.input).into_owned()
        } else {
            raw
        };
        v.raw_lines = line_count(&raw_str);
        v.raw_bytes = raw_str.len();
        v.raw = visible_text(&raw_str);
    }
    if !notice.is_empty() {
        v.ambiguous = true;
        v.ambiguous_notice = notice;
    }
    Some(v)
}

/// The number of lines `s` shows: 0 for `""`, else newlines + 1.
#[must_use]
pub fn line_count(s: &str) -> usize {
    if s.is_empty() {
        0
    } else {
        s.matches('\n').count() + 1
    }
}

/// `buildPermissionHistory` — decision time when present, else request
/// time; newest-first order preserved.
#[must_use]
pub fn build_permission_history(records: &[HarnessPermissionRecord]) -> Vec<PermissionHistoryRow> {
    records
        .iter()
        .map(|r| PermissionHistoryRow {
            tool_name: visible_text(&r.tool_name),
            outcome: r.outcome.clone(),
            decided_by: visible_text(&r.decided_by),
            at: format_timestamp(if r.decided_at == OffsetDateTime::UNIX_EPOCH {
                r.requested_at
            } else {
                r.decided_at
            }),
        })
        .collect()
}

/// `timeLeft` — the time until expiry, rounded to the second; an expired
/// request shows `expired`.
#[must_use]
pub fn time_left(expires: OffsetDateTime, now: OffsetDateTime) -> String {
    let d = expires - now;
    let secs = d.whole_seconds();
    if secs <= 0 {
        return "expired".to_string();
    }
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    if h > 0 {
        format!("{h}h{m}m{s}s")
    } else if m > 0 {
        format!("{m}m{s}s")
    } else {
        format!("{s}s")
    }
}

/// `renderPermissionInput` — object inputs render member by member;
/// anything else renders as raw text. A non-empty `notice` makes the
/// page deny-only: trailing/malformed input, or a repeated top-level
/// member name.
#[must_use]
pub fn render_permission_input(input: &[u8]) -> (Vec<PermissionInputField>, String, &'static str) {
    // Upstream `json.Valid`: the input must be exactly one well-formed
    // JSON value (no trailing data) before any member walk happens.
    if serde_json::from_slice::<serde::de::IgnoredAny>(input).is_err() {
        return (
            Vec::new(),
            String::from_utf8_lossy(input).into_owned(),
            MALFORMED_INPUT_NOTICE,
        );
    }
    match object_fields(input) {
        Err(ObjectErr::NotAnObject) => {
            (Vec::new(), String::from_utf8_lossy(input).into_owned(), "")
        }
        Err(_) => (
            Vec::new(),
            String::from_utf8_lossy(input).into_owned(),
            MALFORMED_INPUT_NOTICE,
        ),
        Ok((fields, false)) => (fields, String::new(), DUPLICATE_KEYS_NOTICE),
        Ok((fields, true)) => (fields, String::new(), ""),
    }
}

/// `objectFields`' answer kinds.
#[derive(Debug, PartialEq)]
enum ObjectErr {
    /// The input does not open with `{`.
    NotAnObject,
    /// An object-shaped input that is not one well-formed object.
    Malformed,
}

fn object_fields(input: &[u8]) -> Result<(Vec<PermissionInputField>, bool), ObjectErr> {
    let mut p = skip_ws(input, 0);
    if input.get(p) != Some(&b'{') {
        return Err(ObjectErr::NotAnObject);
    }
    p += 1;
    let mut fields = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut unique = true;
    loop {
        p = skip_ws(input, p);
        match input.get(p) {
            Some(b'}') => {
                p += 1;
                break;
            }
            Some(b'"') => {}
            _ => return Err(ObjectErr::Malformed),
        }
        let key_start = p;
        p = skip_string(input, p).ok_or(ObjectErr::Malformed)?;
        let key_literal = &input[key_start..p];
        let key: String = serde_json::from_slice(key_literal).map_err(|_| ObjectErr::Malformed)?;
        let (shown_key, _) = visible_json_string(key_literal).map_err(|_| ObjectErr::Malformed)?;
        if !seen.insert(key) {
            unique = false;
        }
        p = skip_ws(input, p);
        if input.get(p) != Some(&b':') {
            return Err(ObjectErr::Malformed);
        }
        p = skip_ws(input, p + 1);
        let vstart = p;
        p = skip_value(input, p).ok_or(ObjectErr::Malformed)?;
        let raw = &input[vstart..p];
        let (shown, value) = if raw.first() == Some(&b'"') {
            visible_json_string(raw).map_err(|_| ObjectErr::Malformed)?
        } else {
            let compact = compact_json(raw);
            (visible_text(&compact), compact)
        };
        fields.push(PermissionInputField {
            key: quote_shown_key(&shown_key),
            value: shown,
            lines: line_count(&value),
            bytes: value.len(),
        });
        p = skip_ws(input, p);
        match input.get(p) {
            Some(b',') => p += 1,
            Some(b'}') => {
                p += 1;
                break;
            }
            _ => return Err(ObjectErr::Malformed),
        }
    }
    if skip_ws(input, p) != input.len() {
        // Trailing data after the object — shown raw, deny only.
        return Err(ObjectErr::Malformed);
    }
    Ok((fields, unique))
}

fn skip_ws(b: &[u8], mut p: usize) -> usize {
    while matches!(b.get(p), Some(b' ' | b'\t' | b'\r' | b'\n')) {
        p += 1;
    }
    p
}

/// Scans a JSON string literal starting at `b[p] == '"'`, returning the
/// offset just past the closing quote. Handles `\` escapes.
fn skip_string(b: &[u8], mut p: usize) -> Option<usize> {
    debug_assert_eq!(b.get(p), Some(&b'"'));
    p += 1;
    while p < b.len() {
        match b[p] {
            b'\\' => p += 2,
            b'"' => return Some(p + 1),
            _ => p += 1,
        }
    }
    None
}

/// Scans a JSON value starting at `p`, returning the offset just past
/// it. Structural only — validity was already established by the
/// whole-input `IgnoredAny` pass.
fn skip_value(b: &[u8], p: usize) -> Option<usize> {
    match *b.get(p)? {
        b'"' => skip_string(b, p),
        b'{' | b'[' => {
            let open = b[p];
            let close = if open == b'{' { b'}' } else { b']' };
            let mut depth = 0usize;
            let mut i = p;
            while i < b.len() {
                match b[i] {
                    x if x == open => depth += 1,
                    x if x == close => {
                        depth -= 1;
                        if depth == 0 {
                            return Some(i + 1);
                        }
                    }
                    b'"' => {
                        i = skip_string(b, i)? - 1;
                    }
                    _ => {}
                }
                i += 1;
            }
            None
        }
        _ => {
            // Number or literal: ends at a structural byte or whitespace.
            let mut i = p;
            while i < b.len() && !matches!(b[i], b',' | b'}' | b']' | b' ' | b'\t' | b'\r' | b'\n')
            {
                i += 1;
            }
            (i > p).then_some(i)
        }
    }
}

/// `json.Compact` — whitespace removed outside string literals, byte
/// content preserved exactly (serde reserialization would normalize
/// number literals where Go's `Compact` preserves them).
fn compact_json(raw: &[u8]) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        match raw[i] {
            b' ' | b'\t' | b'\r' | b'\n' => i += 1,
            b'"' => {
                let end = skip_string(raw, i).unwrap_or(raw.len());
                out.push_str(&String::from_utf8_lossy(&raw[i..end]));
                i = end;
            }
            c => {
                out.push(c as char);
                i += 1;
            }
        }
    }
    out
}

/// `quoteShownKey` — an already-visible key rendered as its JSON string
/// literal so boundary whitespace and newlines read differently.
fn quote_shown_key(shown: &str) -> String {
    let mut out = String::with_capacity(shown.len() + 2);
    out.push('"');
    for c in shown.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// `visibleJSONString` — decodes one JSON string literal the way
/// `json.Unmarshal` does, and returns `(visible, decoded)`: the decoded
/// text with every marker-worthy code point marked, including the two
/// things decoding silently turns into U+FFFD — an invalid UTF-8 byte
/// (`⟦0xFF⟧`) and an unpaired UTF-16 surrogate (`⟦U+D800⟧`).
fn visible_json_string(literal: &[u8]) -> Result<(String, String), ()> {
    let decoded: String = serde_json::from_slice(literal).map_err(|_| ())?;
    if literal.len() < 2 {
        return Err(());
    }
    let s = &literal[1..literal.len() - 1]; // serde checked the syntax
    let mut b = String::new();
    let mut i = 0;
    while i < s.len() {
        if s[i] != b'\\' {
            match decode_rune(&s[i..]) {
                Some((r, size)) => {
                    write_visible_rune(&mut b, r);
                    i += size;
                }
                None => {
                    let _ = write!(b, "\u{27e6}0x{:02X}\u{27e7}", s[i]);
                    i += 1;
                }
            }
            continue;
        }
        if s[i + 1] != b'u' {
            let r = match s[i + 1] {
                b'b' => '\u{8}',
                b'f' => '\u{c}',
                b'n' => '\n',
                b'r' => '\r',
                b't' => '\t',
                c => c as char,
            };
            write_visible_rune(&mut b, r);
            i += 2;
            continue;
        }
        let r = u32::from_str_radix(std::str::from_utf8(&s[i + 2..i + 6]).map_err(|_| ())?, 16)
            .map_err(|_| ())?;
        i += 6;
        if !(0xd800..0xe000).contains(&r) {
            write_visible_rune(&mut b, char::from_u32(r).ok_or(())?);
            continue;
        }
        if r < 0xdc00 && i + 6 <= s.len() && s[i] == b'\\' && s[i + 1] == b'u' {
            let low =
                u32::from_str_radix(std::str::from_utf8(&s[i + 2..i + 6]).map_err(|_| ())?, 16)
                    .map_err(|_| ())?;
            if (0xdc00..=0xdfff).contains(&low) {
                let mut it = char::decode_utf16([r as u16, low as u16]);
                if let Some(Ok(c)) = it.next() {
                    write_visible_rune(&mut b, c);
                    i += 6;
                    continue;
                }
            }
        }
        // Unpaired surrogate — the decoder wrote U+FFFD.
        let _ = write!(b, "\u{27e6}U+{r:04X}\u{27e7}");
    }
    Ok((b, decoded))
}

/// One UTF-8 decode step exactly like Go's `utf8.DecodeRune`: `None`
/// (size 1 upstream) on an invalid leading byte, overlong form,
/// surrogate, or >U+10FFFF — never panics, never skips ahead.
fn decode_rune(bytes: &[u8]) -> Option<(char, usize)> {
    let b0 = *bytes.first()?;
    let len = match b0 {
        0x00..=0x7f => 1,
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => return None,
    };
    if bytes.len() < len {
        return None;
    }
    std::str::from_utf8(&bytes[..len])
        .ok()
        .and_then(|s| s.chars().next())
        .map(|c| (c, len))
}

/// `visibleText` — every code point that does not print or that changes
/// direction is replaced by a visible marker (`⟦U+202E⟧`): C0 controls
/// other than newline/tab, DEL, C1, the line/paragraph separators, every
/// Default_Ignorable code point, and the marker's own opening bracket
/// U+27E6 (review M8-1 — input spelling a marker never passes for one).
/// Invalid UTF-8 becomes `⟦0xFF⟧`.
#[must_use]
pub fn visible_text(s: &str) -> String {
    visible_text_bytes(s.as_bytes())
}

/// The byte-level [`visible_text`] for inputs that may hold invalid
/// UTF-8 (tool inputs are `Vec<u8>`, not `String`).
#[must_use]
pub fn visible_text_bytes(s: &[u8]) -> String {
    let mut b = String::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        match decode_rune(&s[i..]) {
            Some((r, size)) => {
                write_visible_rune(&mut b, r);
                i += size;
            }
            None => {
                let _ = write!(b, "\u{27e6}0x{:02X}\u{27e7}", s[i]);
                i += 1;
            }
        }
    }
    b
}

fn write_visible_rune(b: &mut String, r: char) {
    if hidden_rune(r) {
        let _ = write!(b, "\u{27e6}U+{:04X}\u{27e7}", r as u32);
    } else {
        b.push(r);
    }
}

/// U+27E6 — the marker's opening bracket; itself marked so only this
/// pipeline writes a bare one.
const MARKER_OPEN: char = '\u{27e6}';

fn hidden_rune(r: char) -> bool {
    let c = r as u32;
    match r {
        '\n' | '\t' => false,
        _ if c < 0x20 || c == 0x7f || (0x80..=0x9f).contains(&c) => true,
        _ if c == 0x2028 || c == 0x2029 => true,
        MARKER_OPEN => true,
        _ => default_ignorable(c),
    }
}

/// Unicode's derived Default_Ignorable_Code_Point set (Unicode 15),
/// identical to upstream's pinned ranges.
const DEFAULT_IGNORABLE_RANGES: &[(u32, u32)] = &[
    (0x00ad, 0x00ad),
    (0x034f, 0x034f),
    (0x061c, 0x061c),
    (0x115f, 0x1160),
    (0x17b4, 0x17b5),
    (0x180b, 0x180f),
    (0x200b, 0x200f),
    (0x202a, 0x202e),
    (0x2060, 0x206f),
    (0x3164, 0x3164),
    (0xfe00, 0xfe0f),
    (0xfeff, 0xfeff),
    (0xffa0, 0xffa0),
    (0xfff0, 0xfff8),
    (0x1bca0, 0x1bca3),
    (0x1d173, 0x1d17a),
    (0xe0000, 0xe0fff),
];

fn default_ignorable(c: u32) -> bool {
    DEFAULT_IGNORABLE_RANGES
        .iter()
        .any(|&(lo, hi)| c >= lo && c <= hi)
}
