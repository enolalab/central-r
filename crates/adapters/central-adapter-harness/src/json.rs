//! The byte-level JSON machinery the session's fail-closed paths need —
//! the parts of upstream `encoding/json` that `serde_json` does not
//! carry:
//!
//! - **raw member spans** — the `json.RawMessage` equivalent: the
//!   harness's tool input is echoed back in the allow answer exactly as
//!   it arrived, and `PermissionRequested.input` carries those same
//!   bytes, so member extraction never re-encodes (a `serde_json::Value`
//!   round-trip would re-sort object keys).
//! - **`compact`** — upstream `json.Compact`: validates, then strips
//!   insignificant whitespace while preserving member order, escape
//!   spellings and number literals byte-for-byte.
//! - **the duplicate-member-name walk** — upstream
//!   `refuseDuplicateKeys`/`walkUniqueKeys` over the decoder's *decoded*
//!   keys, so `"a"` and `"A"` collide.
//!
//! One iterative validator checks the whole input first, exactly as
//! `json.Compact` runs its scanner before the duplicate walk: objects,
//! arrays, string escapes and UTF-8, number grammar and literals; the
//! depth bound is Go's `maxNestingDepth` (10 000). Iteration, not
//! recursion, so a pathological nest can never exhaust the stack —
//! `dec.Token()` upstream is equally non-recursive at the scan layer.
//!
//! Errors are the upstream pair: [`JsonError::Malformed`] is every
//! syntax/encoding violation (`errMalformedInput` and the
//! `json.Unmarshal`/`json.Compact` errors a caller never distinguishes)
//! and [`JsonError::DuplicateKey`] is `errDuplicateInputKey`. Both end a
//! bridged session at the same terminal reason, so the distinction is
//! diagnostics only.

use std::collections::HashSet;
use std::ops::Range;

/// Why a byte slice is not acceptable JSON for the adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JsonError {
    /// Any syntax or encoding violation — `errMalformedInput` and the
    /// `json.Unmarshal`/`json.Compact` errors upstream.
    Malformed,
    /// An object repeats a member name after decoding —
    /// `errDuplicateInputKey` upstream.
    DuplicateKey,
}

/// A member value's raw byte span inside its containing document.
pub(crate) type Span = Range<usize>;

/// `maxNestingDepth` — the Go json scanner's container-depth bound.
const MAX_DEPTH: usize = 10_000;

/// ` `, `\t`, `\n`, `\r` — Go's `isSpace` set.
fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}

fn skip_ws(b: &[u8], mut pos: usize) -> usize {
    while pos < b.len() && is_ws(b[pos]) {
        pos += 1;
    }
    pos
}

/// An open container on the scan stack.
enum Open {
    /// `keys` records decoded member names when the duplicate walk is
    /// on; `None` when it is off.
    Obj {
        keys: Option<HashSet<String>>,
    },
    Arr,
}

/// Where the scanner stands between tokens.
enum Phase {
    /// At a value start — also after `[` or `,` in an array and after
    /// `:` in an object.
    Value,
    /// Just consumed `[` — the first element or `]`.
    ElemOrEnd,
    /// Just consumed `{` — a member key or `}`.
    KeyOrEnd,
    /// After `,` in an object — a member key only.
    Key,
    /// After a member key — `:`.
    Colon,
    /// A value just completed — `,`, the container's `]`/`}`, or done.
    AfterValue,
}

/// Validates one JSON value at `start` and returns the position right
/// after it — the value's raw end, before any following whitespace.
/// With `dup`, every object's decoded member names must be unique at
/// every depth.
pub(crate) fn scan_value(b: &[u8], start: usize, dup: bool) -> Result<usize, JsonError> {
    let mut stack: Vec<Open> = Vec::new();
    let mut pos = skip_ws(b, start);
    let mut phase = Phase::Value;
    loop {
        match phase {
            Phase::Value => {
                pos = skip_ws(b, pos);
                match *b.get(pos).ok_or(JsonError::Malformed)? {
                    b'{' => {
                        if stack.len() >= MAX_DEPTH {
                            return Err(JsonError::Malformed);
                        }
                        stack.push(Open::Obj {
                            keys: dup.then(HashSet::new),
                        });
                        pos += 1;
                        phase = Phase::KeyOrEnd;
                    }
                    b'[' => {
                        if stack.len() >= MAX_DEPTH {
                            return Err(JsonError::Malformed);
                        }
                        stack.push(Open::Arr);
                        pos += 1;
                        phase = Phase::ElemOrEnd;
                    }
                    b'"' => {
                        pos = scan_string(b, pos)?;
                        phase = Phase::AfterValue;
                    }
                    b't' => {
                        pos = scan_literal(b, pos, b"true")?;
                        phase = Phase::AfterValue;
                    }
                    b'f' => {
                        pos = scan_literal(b, pos, b"false")?;
                        phase = Phase::AfterValue;
                    }
                    b'n' => {
                        pos = scan_literal(b, pos, b"null")?;
                        phase = Phase::AfterValue;
                    }
                    b'-' | b'0'..=b'9' => {
                        pos = scan_number(b, pos)?;
                        phase = Phase::AfterValue;
                    }
                    _ => return Err(JsonError::Malformed),
                }
            }
            Phase::ElemOrEnd => {
                pos = skip_ws(b, pos);
                if b.get(pos) == Some(&b']') {
                    pos += 1;
                    stack.pop();
                    phase = Phase::AfterValue;
                } else {
                    phase = Phase::Value;
                }
            }
            Phase::KeyOrEnd | Phase::Key => {
                pos = skip_ws(b, pos);
                match b.get(pos) {
                    Some(b'}') if matches!(phase, Phase::KeyOrEnd) => {
                        pos += 1;
                        stack.pop();
                        phase = Phase::AfterValue;
                    }
                    Some(b'"') => {
                        let end = scan_string(b, pos)?;
                        if let Some(Open::Obj { keys: Some(keys) }) = stack.last_mut() {
                            // Decoded, so `"a"` and `"A"` collide
                            // (`refuseDuplicateKeys` upstream).
                            if !keys.insert(decode_string(&b[pos..end])?) {
                                return Err(JsonError::DuplicateKey);
                            }
                        }
                        pos = end;
                        phase = Phase::Colon;
                    }
                    _ => return Err(JsonError::Malformed),
                }
            }
            Phase::Colon => {
                pos = skip_ws(b, pos);
                if b.get(pos) != Some(&b':') {
                    return Err(JsonError::Malformed);
                }
                pos += 1;
                phase = Phase::Value;
            }
            Phase::AfterValue => {
                // The value's raw end: checked before whitespace so the
                // returned span excludes it.
                let Some(top) = stack.last() else {
                    return Ok(pos);
                };
                pos = skip_ws(b, pos);
                match (top, b.get(pos)) {
                    (Open::Obj { .. }, Some(b',')) => {
                        pos += 1;
                        phase = Phase::Key;
                    }
                    (Open::Obj { .. }, Some(b'}')) => {
                        pos += 1;
                        stack.pop();
                        phase = Phase::AfterValue;
                    }
                    (Open::Arr, Some(b',')) => {
                        pos += 1;
                        phase = Phase::Value;
                    }
                    (Open::Arr, Some(b']')) => {
                        pos += 1;
                        stack.pop();
                        phase = Phase::AfterValue;
                    }
                    _ => return Err(JsonError::Malformed),
                }
            }
        }
    }
}

/// Validates `b` as one JSON value with nothing but whitespace around
/// it — `json.Compact`'s whole-input rule.
pub(crate) fn scan(b: &[u8], dup: bool) -> Result<(), JsonError> {
    let pos = scan_value(b, 0, dup)?;
    if skip_ws(b, pos) != b.len() {
        return Err(JsonError::Malformed);
    }
    Ok(())
}

/// The members of `b` — the whole input must be one object plus
/// whitespace. Member order is preserved (callers take the last of a
/// repeated name, matching `json.Unmarshal`'s last-wins rule); every
/// member value span points at the raw value bytes.
pub(crate) fn object_members(b: &[u8]) -> Result<Vec<(String, Span)>, JsonError> {
    let mut pos = skip_ws(b, 0);
    if b.get(pos) != Some(&b'{') {
        return Err(JsonError::Malformed);
    }
    pos += 1;
    let mut out = Vec::new();
    pos = skip_ws(b, pos);
    if b.get(pos) == Some(&b'}') {
        pos += 1;
        if skip_ws(b, pos) != b.len() {
            return Err(JsonError::Malformed);
        }
        return Ok(out);
    }
    loop {
        pos = skip_ws(b, pos);
        if b.get(pos) != Some(&b'"') {
            return Err(JsonError::Malformed);
        }
        let kend = scan_string(b, pos)?;
        let key = decode_string(&b[pos..kend])?;
        pos = skip_ws(b, kend);
        if b.get(pos) != Some(&b':') {
            return Err(JsonError::Malformed);
        }
        pos = skip_ws(b, pos + 1);
        let vend = scan_value(b, pos, false)?;
        out.push((key, pos..vend));
        pos = skip_ws(b, vend);
        match b.get(pos) {
            Some(b',') => {
                pos += 1;
            }
            Some(b'}') => {
                pos += 1;
                break;
            }
            _ => return Err(JsonError::Malformed),
        }
    }
    if skip_ws(b, pos) != b.len() {
        return Err(JsonError::Malformed);
    }
    Ok(out)
}

/// The element spans of `b` — the whole input must be one array plus
/// whitespace; each span covers the raw element bytes.
pub(crate) fn array_spans(b: &[u8]) -> Result<Vec<Span>, JsonError> {
    let mut pos = skip_ws(b, 0);
    if b.get(pos) != Some(&b'[') {
        return Err(JsonError::Malformed);
    }
    pos += 1;
    let mut out = Vec::new();
    pos = skip_ws(b, pos);
    if b.get(pos) == Some(&b']') {
        pos += 1;
        if skip_ws(b, pos) != b.len() {
            return Err(JsonError::Malformed);
        }
        return Ok(out);
    }
    loop {
        let vend = scan_value(b, pos, false)?;
        out.push(pos..vend);
        pos = skip_ws(b, vend);
        match b.get(pos) {
            Some(b',') => {
                pos += 1;
            }
            Some(b']') => {
                pos += 1;
                break;
            }
            _ => return Err(JsonError::Malformed),
        }
    }
    if skip_ws(b, pos) != b.len() {
        return Err(JsonError::Malformed);
    }
    Ok(out)
}

/// The last member named `name` — `json.Unmarshal`'s last-wins rule for
/// repeated keys.
pub(crate) fn member<'a>(members: &'a [(String, Span)], name: &str) -> Option<&'a Span> {
    members
        .iter()
        .rev()
        .find(|(k, _)| k == name)
        .map(|(_, s)| s)
}

/// `json.Unmarshal` of one member value into `T`: callers pass
/// `Option<…>` for `T` so JSON `null` is the no-op it is for a Go zero
/// field, and a wrong type is [`JsonError::Malformed`].
pub(crate) fn field<T: serde::de::DeserializeOwned>(b: &[u8], span: &Span) -> Result<T, JsonError> {
    serde_json::from_slice::<T>(&b[span.clone()]).map_err(|_| JsonError::Malformed)
}

/// `json.Compact` — validates the whole input, then copies every byte
/// outside strings while dropping insignificant whitespace. Inside
/// strings bytes are verbatim, so escape spellings and number literals
/// survive exactly (numbers are never decoded — upstream's
/// `dec.UseNumber` point: `1e999` is valid input, not a float error).
pub(crate) fn compact(b: &[u8]) -> Result<Vec<u8>, JsonError> {
    scan(b, false)?;
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            x if is_ws(x) => i += 1,
            b'"' => {
                let end = scan_string(b, i)?;
                out.extend_from_slice(&b[i..end]);
                i = end;
            }
            x => {
                out.push(x);
                i += 1;
            }
        }
    }
    Ok(out)
}

/// `echoedInput` — the compact tool input an allow echoes as
/// `updatedInput`, or the compact failure when any object repeats a
/// decoded member name at any depth. Validation runs before the
/// duplicate walk reports, as upstream runs `json.Compact` first.
pub(crate) fn echoed_input(raw: &[u8]) -> Result<Vec<u8>, JsonError> {
    if raw.is_empty() {
        return Ok(b"{}".to_vec());
    }
    // One pass does both jobs upstream splits in two; the reported
    // variant may differ (a duplicate key found before later garbage
    // that would have failed `compact` first) but both are the same
    // error to every caller.
    scan(raw, true)?;
    compact(raw)
}

/// Validates one string literal at `pos` (which must be `"`) and
/// returns the position after its closing quote. Escapes, unescaped
/// control bytes and UTF-8 are checked exactly as Go's scanner checks
/// them.
fn scan_string(b: &[u8], start: usize) -> Result<usize, JsonError> {
    let mut i = start + 1;
    loop {
        match *b.get(i).ok_or(JsonError::Malformed)? {
            b'"' => return Ok(i + 1),
            b'\\' => {
                i += 1;
                match *b.get(i).ok_or(JsonError::Malformed)? {
                    b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => i += 1,
                    b'u' => {
                        for h in b.get(i + 1..i + 5).ok_or(JsonError::Malformed)? {
                            if !h.is_ascii_hexdigit() {
                                return Err(JsonError::Malformed);
                            }
                        }
                        i += 5;
                    }
                    _ => return Err(JsonError::Malformed),
                }
            }
            // Go's scanner rejects raw control bytes and invalid UTF-8.
            0x00..=0x1f => return Err(JsonError::Malformed),
            0x20..=0x7f => i += 1,
            _ => {
                let n = utf8_len(b[i]).ok_or(JsonError::Malformed)?;
                if i + n > b.len()
                    || std::str::from_utf8(&b[i..i + n]).is_err()
                    || b[i + 1..i + n].iter().any(|c| c & 0xc0 != 0x80)
                {
                    return Err(JsonError::Malformed);
                }
                i += n;
            }
        }
    }
}

/// The lead byte's sequence length, or `None` for a continuation or
/// `0xf8..=0xff` lead.
fn utf8_len(lead: u8) -> Option<usize> {
    match lead {
        0xc0..=0xdf => Some(2),
        0xe0..=0xef => Some(3),
        0xf0..=0xf7 => Some(4),
        _ => None,
    }
}

/// `true`, `false` or `null` at `pos`.
fn scan_literal(b: &[u8], pos: usize, lit: &[u8]) -> Result<usize, JsonError> {
    if b.get(pos..pos + lit.len()) == Some(lit) {
        Ok(pos + lit.len())
    } else {
        Err(JsonError::Malformed)
    }
}

/// The JSON number grammar at `pos` — `-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?`.
fn scan_number(b: &[u8], start: usize) -> Result<usize, JsonError> {
    let mut i = start;
    if b.get(i) == Some(&b'-') {
        i += 1;
    }
    match b.get(i) {
        Some(b'0') => i += 1,
        Some(b'1'..=b'9') => {
            i += 1;
            while b.get(i).is_some_and(u8::is_ascii_digit) {
                i += 1;
            }
        }
        _ => return Err(JsonError::Malformed),
    }
    if b.get(i) == Some(&b'.') {
        i += 1;
        if !b.get(i).is_some_and(u8::is_ascii_digit) {
            return Err(JsonError::Malformed);
        }
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
    }
    if matches!(b.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(b.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        if !b.get(i).is_some_and(u8::is_ascii_digit) {
            return Err(JsonError::Malformed);
        }
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
    }
    Ok(i)
}

/// Decodes a string literal (span includes the quotes) the way Go's
/// `unquote` does: `\uXXXX` escapes combine surrogate pairs, and a lone
/// surrogate decodes to U+FFFD rather than failing.
fn decode_string(s: &[u8]) -> Result<String, JsonError> {
    let inner = &s[1..s.len() - 1];
    let mut out = Vec::with_capacity(inner.len());
    let mut i = 0;
    while i < inner.len() {
        if inner[i] != b'\\' {
            // Multibyte UTF-8 passes through raw — `scan_string` already
            // validated it.
            out.push(inner[i]);
            i += 1;
            continue;
        }
        i += 1;
        match *inner.get(i).ok_or(JsonError::Malformed)? {
            b'"' => out.push(b'"'),
            b'\\' => out.push(b'\\'),
            b'/' => out.push(b'/'),
            b'b' => out.push(0x08),
            b'f' => out.push(0x0c),
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b't' => out.push(b'\t'),
            b'u' => {
                let cp = hex4(&inner[i + 1..i + 5]).ok_or(JsonError::Malformed)?;
                i += 4;
                let ch = if (0xd800..0xdc00).contains(&cp) {
                    // A high surrogate pairs only with a following
                    // `\uDC00..\uDFFF`; anything else is U+FFFD, as
                    // upstream's decoder does.
                    match inner.get(i + 1..i + 7) {
                        Some(rest) if rest[0] == b'\\' && rest[1] == b'u' => {
                            let low = hex4(&rest[2..6]).ok_or(JsonError::Malformed)?;
                            if (0xdc00..0xe000).contains(&low) {
                                i += 6;
                                char::from_u32(0x10000 + ((cp - 0xd800) << 10) + (low - 0xdc00))
                                    .unwrap_or(char::REPLACEMENT_CHARACTER)
                            } else {
                                char::REPLACEMENT_CHARACTER
                            }
                        }
                        _ => char::REPLACEMENT_CHARACTER,
                    }
                } else {
                    char::from_u32(cp).unwrap_or(char::REPLACEMENT_CHARACTER)
                };
                let mut buf = [0u8; 4];
                out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
            }
            _ => return Err(JsonError::Malformed),
        }
        i += 1;
    }
    String::from_utf8(out).map_err(|_| JsonError::Malformed)
}

/// Four hex digits as a scalar.
fn hex4(s: &[u8]) -> Option<u32> {
    let mut v = 0u32;
    for &c in s {
        let d = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => return None,
        };
        v = (v << 4) | u32::from(d);
    }
    Some(v)
}

/// `isValidNumber` — the JSON number grammar `encoding/json` applies
/// to a *quoted* `json.Number` value: `-?(0|[1-9][0-9]*)` with
/// optional `\.[0-9]+` fraction and `[eE][+-]?[0-9]+` exponent, the
/// whole string, no whitespace and no `+` sign.
fn is_valid_number(s: &str) -> bool {
    let mut s = s.as_bytes();
    if s.is_empty() {
        return false;
    }
    if s[0] == b'-' {
        s = &s[1..];
        if s.is_empty() {
            return false;
        }
    }
    match s[0] {
        b'0' => s = &s[1..],
        b'1'..=b'9' => {
            s = &s[1..];
            while !s.is_empty() && s[0].is_ascii_digit() {
                s = &s[1..];
            }
        }
        _ => return false,
    }
    if s.len() >= 2 && s[0] == b'.' {
        s = &s[1..];
        while !s.is_empty() && s[0].is_ascii_digit() {
            s = &s[1..];
        }
    }
    if s.len() >= 2 && matches!(s[0], b'e' | b'E') {
        s = &s[1..];
        if matches!(s[0], b'+' | b'-') {
            s = &s[1..];
            if s.is_empty() {
                return false;
            }
        }
        while !s.is_empty() && s[0].is_ascii_digit() {
            s = &s[1..];
        }
    }
    s.is_empty()
}

/// A `json.Number` member as an integral int64 — the full Go rule:
/// a bare number literal keeps its text; a string member is unquoted
/// and its content must satisfy `isValidNumber` (`"5"` is the number
/// 5, while `"+5"`, `"05"` and `" 5"` fail the whole decode
/// upstream). The literal then parses as `strconv.ParseInt`:
/// fractions, exponents and out-of-range values are all unusable.
pub(crate) fn number_int64(raw: &[u8]) -> Option<i64> {
    if raw.first() == Some(&b'"') {
        // `literalStore`: the member is a string — `unquoteBytes`,
        // then `isValidNumber` before the value reaches the Number.
        let s = field::<String>(raw, &(0..raw.len())).ok()?;
        if !is_valid_number(&s) {
            return None;
        }
        return s.parse::<i64>().ok();
    }
    std::str::from_utf8(raw).ok()?.parse::<i64>().ok()
}

/// `json.Marshal(s)` via Go's `appendString` with EscapeHTML off — the
/// mode `encodeLine` sets: `"` `\` shorthand escapes, `\b`/`\f`,
/// `\n`/`\r`/`\t`, other controls as `\u00xx`, U+2028/U+2029 escaped,
/// everything else raw UTF-8 (`<`/`>`/`&` unescaped).
pub(crate) fn push_json_string(out: &mut Vec<u8>, s: &str) {
    push_json_string_mode(out, s, false);
}

/// `json.Marshal(s)` via Go's `appendString` with EscapeHTML on —
/// `encoding/json`'s default, the mode plain `json.Marshal` uses:
/// identical to [`push_json_string`] except `<`, `>` and `&` also
/// encode as `\u003c`, `\u003e`, `\u0026`.
pub(crate) fn push_json_string_html(out: &mut Vec<u8>, s: &str) {
    push_json_string_mode(out, s, true);
}

/// `appendString` — the shared escape walk; `html` selects Go's
/// `htmlSafeSet` over `safeSet`.
fn push_json_string_mode(out: &mut Vec<u8>, s: &str, html: bool) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            '<' | '>' | '&' if html => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
            }
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
