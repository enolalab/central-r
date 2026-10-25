//! Strict JSON gate — port of upstream `internal/config/strictjson.go`.
//!
//! One JSON document is validated byte-for-byte before typed decoding:
//! bounded size/depth/token/string limits, no duplicate object keys
//! (decoded-name equality, so `"a"` and `"\u0061"` collide), decoded
//! strings must be NFC and within the byte cap, numbers must be
//! non-negative strict integers (`0` or `[1-9][0-9]*` — no floats,
//! exponents, or negatives), no `null`, and exactly one top-level value
//! with nothing but JSON whitespace after it.
//!
//! Errors are the stable [`ErrorKind`] categories; the public [`Error`]
//! redacts all document content.

use std::collections::HashSet;

use unicode_normalization::is_nfc;

use super::ErrorKind;

/// Bounds applied to one JSON document before it is decoded into a typed
/// value.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DecodeLimits {
    pub(crate) max_bytes: usize,
    pub(crate) max_depth: usize,
    pub(crate) max_tokens: usize,
    pub(crate) max_string_bytes: usize,
}

pub(crate) const CONFIG_DOCUMENT_LIMITS: DecodeLimits = DecodeLimits {
    max_bytes: 1 << 20,
    max_depth: 64,
    max_tokens: 4096,
    max_string_bytes: 64 << 10,
};

pub(crate) const VIEW_SIGNATURE_LIMITS: DecodeLimits = DecodeLimits {
    max_bytes: 16 << 10,
    max_depth: 64,
    max_tokens: 4096,
    max_string_bytes: 64 << 10,
};

/// Runs the full strict walk. Mirrors upstream `validateStrictJSON`:
/// byte limit, UTF-8 validity, one complete value within token/depth
/// limits, then nothing but whitespace to EOF.
pub(crate) fn validate_strict_json(raw: &[u8], limits: DecodeLimits) -> Result<(), ErrorKind> {
    if raw.len() > limits.max_bytes {
        return Err(ErrorKind::Limit);
    }
    if std::str::from_utf8(raw).is_err() {
        return Err(ErrorKind::InvalidSyntax);
    }
    let mut walker = Walker {
        raw,
        pos: 0,
        limits,
        tokens: 0,
    };
    walker.skip_ws();
    walker.value(0)?;
    walker.skip_ws();
    if walker.pos != raw.len() {
        return Err(ErrorKind::InvalidSyntax);
    }
    Ok(())
}

/// The canonical-form gate: `raw` must already be RFC 8785 canonical —
/// i.e. `jcs::canonicalize(parse(raw))` must be byte-identical.
/// Upstream `canonicalJSON`.
pub(crate) fn canonical_json(raw: &[u8]) -> Result<(), ErrorKind> {
    let value: serde_json::Value =
        serde_json::from_slice(raw).map_err(|_| ErrorKind::InvalidSyntax)?;
    let canonical =
        central_foundation::jcs::canonicalize(&value).map_err(|_| ErrorKind::InvalidSyntax)?;
    if canonical != raw {
        return Err(ErrorKind::Semantic);
    }
    Ok(())
}

struct Walker<'a> {
    raw: &'a [u8],
    pos: usize,
    limits: DecodeLimits,
    tokens: usize,
}

impl Walker<'_> {
    /// Counts one JSON token (delimiter, object key, or scalar value) and
    /// enforces the token ceiling — same accounting as the upstream
    /// `json.Decoder.Token()`-driven walker.
    fn count_token(&mut self) -> Result<(), ErrorKind> {
        self.tokens += 1;
        if self.tokens > self.limits.max_tokens {
            return Err(ErrorKind::Limit);
        }
        Ok(())
    }

    fn skip_ws(&mut self) {
        while let Some(&c) = self.raw.get(self.pos) {
            if !matches!(c, b' ' | b'\n' | b'\r' | b'\t') {
                break;
            }
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.skip_ws_peek()
    }

    fn skip_ws_peek(&self) -> Option<u8> {
        let mut pos = self.pos;
        while let Some(&c) = self.raw.get(pos) {
            if !matches!(c, b' ' | b'\n' | b'\r' | b'\t') {
                break;
            }
            pos += 1;
        }
        self.raw.get(pos).copied()
    }

    /// Parses one complete value at the current position. `depth` is the
    /// number of enclosing arrays/objects already open.
    fn value(&mut self, depth: usize) -> Result<(), ErrorKind> {
        self.skip_ws();
        match self.raw.get(self.pos) {
            Some(b'{') => {
                self.pos += 1;
                self.count_token()?;
                if depth + 1 > self.limits.max_depth {
                    return Err(ErrorKind::Limit);
                }
                self.object(depth + 1)
            }
            Some(b'[') => {
                self.pos += 1;
                self.count_token()?;
                if depth + 1 > self.limits.max_depth {
                    return Err(ErrorKind::Limit);
                }
                self.array(depth + 1)
            }
            Some(b'"') => {
                self.string()?;
                Ok(())
            }
            Some(b't') | Some(b'f') | Some(b'n') => self.literal(),
            Some(b'-') | Some(b'0'..=b'9') => self.number(),
            _ => Err(ErrorKind::InvalidSyntax),
        }
    }

    /// `object` is entered having consumed `{`; it consumes through the
    /// matching `}`.
    fn object(&mut self, depth: usize) -> Result<(), ErrorKind> {
        let mut keys: HashSet<String> = HashSet::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            self.count_token()?;
            return Ok(());
        }
        loop {
            self.skip_ws();
            if self.raw.get(self.pos) != Some(&b'"') {
                return Err(ErrorKind::InvalidSyntax);
            }
            let key = self.string()?;
            if !keys.insert(key) {
                return Err(ErrorKind::DuplicateKey);
            }
            self.skip_ws();
            if self.raw.get(self.pos) != Some(&b':') {
                return Err(ErrorKind::InvalidSyntax);
            }
            self.pos += 1;
            self.value(depth)?;
            self.skip_ws();
            match self.raw.get(self.pos) {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    self.count_token()?;
                    return Ok(());
                }
                _ => return Err(ErrorKind::InvalidSyntax),
            }
        }
    }

    /// `array` is entered having consumed `[`; it consumes through the
    /// matching `]`.
    fn array(&mut self, depth: usize) -> Result<(), ErrorKind> {
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            self.count_token()?;
            return Ok(());
        }
        loop {
            self.value(depth)?;
            self.skip_ws();
            match self.raw.get(self.pos) {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    self.count_token()?;
                    return Ok(());
                }
                _ => return Err(ErrorKind::InvalidSyntax),
            }
        }
    }

    /// Consumes a `true`/`false`/`null` literal token and counts it.
    /// `null` is reported by the caller as [`ErrorKind::Semantic`].
    fn literal(&mut self) -> Result<(), ErrorKind> {
        let start = self.pos;
        while let Some(&c) = self.raw.get(self.pos) {
            if !c.is_ascii_alphabetic() {
                break;
            }
            self.pos += 1;
        }
        let word = &self.raw[start..self.pos];
        match word {
            b"true" | b"false" | b"null" => {
                self.count_token()?;
                // `null` is valid JSON but not a permitted config value.
                if word == b"null" {
                    return Err(ErrorKind::Semantic);
                }
                Ok(())
            }
            _ => Err(ErrorKind::InvalidSyntax),
        }
    }

    /// Consumes a JSON number per the strict grammar, counts it, then
    /// applies the strict-integer gate.
    fn number(&mut self) -> Result<(), ErrorKind> {
        let start = self.pos;
        if self.raw.get(self.pos) == Some(&b'-') {
            self.pos += 1;
        }
        match self.raw.get(self.pos) {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => {
                self.pos += 1;
                while matches!(self.raw.get(self.pos), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err(ErrorKind::InvalidSyntax),
        }
        if self.raw.get(self.pos) == Some(&b'.') {
            self.pos += 1;
            if !matches!(self.raw.get(self.pos), Some(b'0'..=b'9')) {
                return Err(ErrorKind::InvalidSyntax);
            }
            while matches!(self.raw.get(self.pos), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if matches!(self.raw.get(self.pos), Some(b'e') | Some(b'E')) {
            self.pos += 1;
            if matches!(self.raw.get(self.pos), Some(b'+') | Some(b'-')) {
                self.pos += 1;
            }
            if !matches!(self.raw.get(self.pos), Some(b'0'..=b'9')) {
                return Err(ErrorKind::InvalidSyntax);
            }
            while matches!(self.raw.get(self.pos), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        self.count_token()?;
        let token = &self.raw[start..self.pos];
        // Strict-integer gate: `0` or `[1-9][0-9]*` only. A syntactically
        // valid float/exponent/negative is a semantic rejection, same as
        // upstream's `isStrictInteger` check on the decoded token.
        if !is_strict_integer(token) {
            return Err(ErrorKind::Semantic);
        }
        Ok(())
    }

    /// Consumes a `"..."` string, counts it as a token, decodes escapes
    /// exactly like `encoding/json` (lone `\u` surrogates become
    /// U+FFFD), enforces the decoded byte cap and NFC, and returns the
    /// decoded string for object-key deduplication.
    fn string(&mut self) -> Result<String, ErrorKind> {
        debug_assert_eq!(self.raw.get(self.pos), Some(&b'"'));
        self.pos += 1;
        let mut decoded = String::new();
        loop {
            let Some(&c) = self.raw.get(self.pos) else {
                return Err(ErrorKind::InvalidSyntax);
            };
            self.pos += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let Some(&esc) = self.raw.get(self.pos) else {
                        return Err(ErrorKind::InvalidSyntax);
                    };
                    self.pos += 1;
                    match esc {
                        b'"' => decoded.push('"'),
                        b'\\' => decoded.push('\\'),
                        b'/' => decoded.push('/'),
                        b'b' => decoded.push('\u{8}'),
                        b'f' => decoded.push('\u{c}'),
                        b'n' => decoded.push('\n'),
                        b'r' => decoded.push('\r'),
                        b't' => decoded.push('\t'),
                        b'u' => {
                            let first = self.u_escape()?;
                            if (0xD800..0xDC00).contains(&first) {
                                // High surrogate: Go requires an immediate
                                // `\uXXXX` continuation and substitutes
                                // U+FFFD when it is not a low surrogate.
                                if self.raw.get(self.pos) == Some(&b'\\')
                                    && self.raw.get(self.pos + 1) == Some(&b'u')
                                {
                                    self.pos += 2;
                                    let second = self.u_escape()?;
                                    if (0xDC00..0xE000).contains(&second) {
                                        let code = 0x10000
                                            + (((first - 0xD800) as u32) << 10)
                                            + ((second - 0xDC00) as u32);
                                        decoded.push(char::from_u32(code).unwrap_or('\u{FFFD}'));
                                    } else {
                                        decoded.push('\u{FFFD}');
                                        decoded.push(
                                            char::from_u32(second as u32).unwrap_or('\u{FFFD}'),
                                        );
                                    }
                                } else {
                                    decoded.push('\u{FFFD}');
                                }
                            } else if (0xDC00..0xE000).contains(&first) {
                                decoded.push('\u{FFFD}');
                            } else {
                                decoded.push(char::from_u32(first as u32).unwrap_or('\u{FFFD}'));
                            }
                        }
                        _ => return Err(ErrorKind::InvalidSyntax),
                    }
                }
                0x00..=0x1f => return Err(ErrorKind::InvalidSyntax),
                // `raw` was UTF-8-validated up front; multibyte sequences
                // pass through verbatim — matching Go's decoder, which
                // copies valid UTF-8 bytes into the decoded string.
                c => {
                    let start = self.pos - 1;
                    let tail = utf8_char_width(c);
                    decoded.push_str(
                        std::str::from_utf8(&self.raw[start..start + tail])
                            .map_err(|_| ErrorKind::InvalidSyntax)?,
                    );
                    self.pos = start + tail;
                }
            }
        }
        self.count_token()?;
        if decoded.len() > self.limits.max_string_bytes {
            return Err(ErrorKind::Limit);
        }
        if !is_nfc(&decoded) {
            return Err(ErrorKind::Semantic);
        }
        Ok(decoded)
    }

    /// Reads exactly four hex digits after a `\u`.
    fn u_escape(&mut self) -> Result<u16, ErrorKind> {
        let end = self.pos + 4;
        if end > self.raw.len() {
            return Err(ErrorKind::InvalidSyntax);
        }
        let hex = &self.raw[self.pos..end];
        let mut value: u16 = 0;
        for &b in hex {
            let digit = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => return Err(ErrorKind::InvalidSyntax),
            };
            value = (value << 4) | digit as u16;
        }
        self.pos = end;
        Ok(value)
    }
}

/// Byte length of the UTF-8 sequence starting at `first`.
fn utf8_char_width(first: u8) -> usize {
    match first {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    }
}

/// Upstream `isStrictInteger`: only `0` or `[1-9][0-9]*` survive.
fn is_strict_integer(token: &[u8]) -> bool {
    if token == b"0" {
        return true;
    }
    match token.first() {
        Some(b'1'..=b'9') => token[1..].iter().all(|b| b.is_ascii_digit()),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    //! Port of upstream `strictjson_test.go` plus the error-redaction
    //! coverage that file carries.

    use super::*;

    fn quoted_string(length: usize) -> Vec<u8> {
        let mut raw = Vec::with_capacity(length + 2);
        raw.push(b'"');
        raw.extend(std::iter::repeat_n(b'a', length));
        raw.push(b'"');
        raw
    }

    fn nested_arrays(depth: usize) -> Vec<u8> {
        let mut raw = Vec::with_capacity(depth * 2 + 1);
        raw.extend(std::iter::repeat_n(b'[', depth));
        raw.push(b'0');
        raw.extend(std::iter::repeat_n(b']', depth));
        raw
    }

    fn array_of_zeros(values: usize) -> Vec<u8> {
        let mut raw = Vec::with_capacity(values * 2 + 2);
        raw.push(b'[');
        for i in 0..values {
            if i > 0 {
                raw.push(b',');
            }
            raw.push(b'0');
        }
        raw.push(b']');
        raw
    }

    fn padded_scalar(length: usize) -> Vec<u8> {
        let mut raw = vec![b' '; length];
        raw[0] = b'0';
        raw
    }

    #[test]
    fn accepts_nested_object_and_array() {
        let raw = br#"{"outer":{"values":[1,{"name":"ok"},true],"empty":[]}}"#;
        assert_eq!(
            validate_strict_json(raw, CONFIG_DOCUMENT_LIMITS),
            Ok(()),
            "validate_strict_json rejected a nested object and array"
        );
    }

    #[test]
    fn rejects_nested_duplicate_key() {
        let err = validate_strict_json(
            br#"{"outer":{"name":"a","name":"b"}}"#,
            CONFIG_DOCUMENT_LIMITS,
        );
        assert_eq!(err, Err(ErrorKind::DuplicateKey));
    }

    #[test]
    fn rejects_non_nfc_decoded_string_value() {
        let err = validate_strict_json(br#"{"value":"e\u0301"}"#, CONFIG_DOCUMENT_LIMITS);
        assert_eq!(err, Err(ErrorKind::Semantic));
    }

    #[test]
    fn rejects_table_driven_bad_inputs() {
        let cases: &[(&str, &[u8], ErrorKind)] = &[
            (
                "trailing value",
                br#"{"a":1}{"b":2}"#,
                ErrorKind::InvalidSyntax,
            ),
            (
                "duplicate root key",
                br#"{"name":"a","name":"b"}"#,
                ErrorKind::DuplicateKey,
            ),
            ("null", br#"{"value":null}"#, ErrorKind::Semantic),
            ("float", br#"{"value":1.5}"#, ErrorKind::Semantic),
            ("exponent", br#"{"value":1e3}"#, ErrorKind::Semantic),
            ("negative", br#"{"value":-1}"#, ErrorKind::Semantic),
            ("leading zero", br#"{"value":01}"#, ErrorKind::InvalidSyntax),
            ("non NFC key", br#"{"e\u0301":1}"#, ErrorKind::Semantic),
            (
                "duplicate escaped key",
                br#"{"a":1,"\u0061":2}"#,
                ErrorKind::DuplicateKey,
            ),
        ];
        for (name, raw, want) in cases {
            assert_eq!(
                validate_strict_json(raw, CONFIG_DOCUMENT_LIMITS),
                Err(*want),
                "{name}"
            );
        }
        let err = validate_strict_json(
            &[b'{', b'"', b'x', b'"', b':', b'"', 0xff, b'"', b'}'],
            CONFIG_DOCUMENT_LIMITS,
        );
        assert_eq!(err, Err(ErrorKind::InvalidSyntax), "invalid utf8");
    }

    #[test]
    fn exact_boundary_limits() {
        struct Case {
            name: &'static str,
            raw: Vec<u8>,
            limit: DecodeLimits,
            want: Result<(), ErrorKind>,
        }
        let cases = vec![
            Case {
                name: "config bytes max",
                raw: padded_scalar(CONFIG_DOCUMENT_LIMITS.max_bytes),
                limit: CONFIG_DOCUMENT_LIMITS,
                want: Ok(()),
            },
            Case {
                name: "config bytes max plus one",
                raw: padded_scalar(CONFIG_DOCUMENT_LIMITS.max_bytes + 1),
                limit: CONFIG_DOCUMENT_LIMITS,
                want: Err(ErrorKind::Limit),
            },
            Case {
                name: "view bytes max",
                raw: padded_scalar(VIEW_SIGNATURE_LIMITS.max_bytes),
                limit: VIEW_SIGNATURE_LIMITS,
                want: Ok(()),
            },
            Case {
                name: "view bytes max plus one",
                raw: padded_scalar(VIEW_SIGNATURE_LIMITS.max_bytes + 1),
                limit: VIEW_SIGNATURE_LIMITS,
                want: Err(ErrorKind::Limit),
            },
            Case {
                name: "string max",
                raw: quoted_string(CONFIG_DOCUMENT_LIMITS.max_string_bytes),
                limit: CONFIG_DOCUMENT_LIMITS,
                want: Ok(()),
            },
            Case {
                name: "string max plus one",
                raw: quoted_string(CONFIG_DOCUMENT_LIMITS.max_string_bytes + 1),
                limit: CONFIG_DOCUMENT_LIMITS,
                want: Err(ErrorKind::Limit),
            },
            Case {
                name: "depth max",
                raw: nested_arrays(CONFIG_DOCUMENT_LIMITS.max_depth),
                limit: CONFIG_DOCUMENT_LIMITS,
                want: Ok(()),
            },
            Case {
                name: "depth max plus one",
                raw: nested_arrays(CONFIG_DOCUMENT_LIMITS.max_depth + 1),
                limit: CONFIG_DOCUMENT_LIMITS,
                want: Err(ErrorKind::Limit),
            },
            Case {
                name: "tokens max",
                raw: array_of_zeros(CONFIG_DOCUMENT_LIMITS.max_tokens - 2),
                limit: CONFIG_DOCUMENT_LIMITS,
                want: Ok(()),
            },
            Case {
                name: "tokens max plus one",
                raw: array_of_zeros(CONFIG_DOCUMENT_LIMITS.max_tokens - 1),
                limit: CONFIG_DOCUMENT_LIMITS,
                want: Err(ErrorKind::Limit),
            },
        ];
        for case in cases {
            assert_eq!(
                validate_strict_json(&case.raw, case.limit),
                case.want,
                "{}",
                case.name
            );
        }
    }
}
