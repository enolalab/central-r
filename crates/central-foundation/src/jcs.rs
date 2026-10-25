//! RFC 8785 JSON Canonicalization Scheme (JCS).
//!
//! Hand-written canonicalizer over `serde_json::Value` (Phase R5 decision
//! D6 — no new crate). It reproduces the upstream Go behavior of
//! `github.com/gowebpki/jcs` byte for byte:
//!
//! - object members are emitted sorted by the UTF-16 code units of their
//!   names (NOT by Rust `str`/`String` ordering, which follows UTF-8
//!   bytes — the orders differ across the BMP boundary);
//! - numbers are serialized with the ECMAScript `Number::toString`
//!   algorithm (`1e21` and above use exponent form, `-0` collapses to
//!   `0`, subnormals like `5e-324` are supported);
//! - strings use minimal escaping: only `"`, `\`, and control
//!   characters below U+0020 are escaped, via the short escapes
//!   `\b \f \n \r \t` where they exist and `\u00xx` (lowercase hex)
//!   otherwise; every other character is emitted as raw UTF-8;
//! - non-finite numbers are rejected.
//!
//! `serde_json` parses every JSON number into `i64`/`u64`/`f64`; converting
//! through `f64` here matches upstream, where `encoding/json` decodes all
//! numbers as `float64` before the JCS pass.

use core::fmt;

/// Why a [`serde_json::Value`] could not be canonicalized.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JcsError {
    /// JSON has no NaN or Infinity; the value is outside the JSON domain.
    NonFiniteNumber,
}

impl fmt::Display for JcsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonFiniteNumber => f.write_str("jcs: non-finite number"),
        }
    }
}

impl std::error::Error for JcsError {}

/// Returns the canonical RFC 8785 UTF-8 encoding of `value`.
///
/// # Errors
///
/// [`JcsError::NonFiniteNumber`] if any number in the tree is NaN or
/// infinite. Such values cannot arise from JSON text parsed through
/// `serde_json`, but can arrive through values assembled programmatically.
pub fn canonicalize(value: &serde_json::Value) -> Result<Vec<u8>, JcsError> {
    let mut out = Vec::new();
    write_value(value, &mut out)?;
    Ok(out)
}

/// Serializes one IEEE-754 double exactly as ECMAScript
/// `Number.prototype.toString` does — the RFC 8785 §3.2.2.3 number rule,
/// matching upstream `gowebpki/jcs`'s `NumberToJSON`.
///
/// # Errors
///
/// [`JcsError::NonFiniteNumber`] for NaN or infinities.
pub fn number_to_json(ieee_f64: f64) -> Result<String, JcsError> {
    if !ieee_f64.is_finite() {
        return Err(JcsError::NonFiniteNumber);
    }
    // ES6 eliminates "-0"; `==` covers both signs of zero.
    if ieee_f64 == 0.0 {
        return Ok("0".to_owned());
    }
    let (sign, magnitude) = if ieee_f64 < 0.0 {
        ("-", -ieee_f64)
    } else {
        ("", ieee_f64)
    };
    // ES6 uses fixed notation inside [1e-6, 1e21), exponent notation
    // outside it — the same branch `gowebpki/jcs` takes when selecting
    // Go's 'f'/'e' formats with precision -1 (shortest round-trip digits,
    // which is what Rust's `Display`/`LowerExp` also produce).
    if (1e-6..1e21).contains(&magnitude) {
        // `Display` emits the shortest round-trip decimal in positional
        // notation — identical digits to Go's `FormatFloat(f, 'f', -1, 64)`.
        return Ok(format!("{sign}{magnitude}"));
    }
    // `LowerExp` emits `d[.ddd]e[-]exp` with shortest round-trip mantissa
    // digits and a bare/prefixed-minus exponent; ECMAScript wants an
    // explicit '+' on non-negative exponents.
    let expanded = format!("{magnitude:e}");
    let Some(e_pos) = expanded.find('e') else {
        // `LowerExp` for finite f64 always contains 'e'; unreachable.
        return Err(JcsError::NonFiniteNumber);
    };
    let (mantissa, exponent) = expanded.split_at(e_pos);
    let exponent_digits = &exponent[1..];
    let exponent_sign = if exponent_digits.starts_with('-') {
        ""
    } else {
        "+"
    };
    Ok(format!("{sign}{mantissa}e{exponent_sign}{exponent_digits}"))
}

fn write_value(value: &serde_json::Value, out: &mut Vec<u8>) -> Result<(), JcsError> {
    match value {
        serde_json::Value::Null => out.extend_from_slice(b"null"),
        serde_json::Value::Bool(flag) => {
            out.extend_from_slice(if *flag { b"true" } else { b"false" });
        }
        serde_json::Value::Number(number) => {
            // All JSON numbers serialize through the f64/ECMAScript rule:
            // upstream decodes to float64 too, so i64/u64 rounding here is
            // identical to upstream's `strconv.ParseFloat` on the literal.
            out.extend_from_slice(number_to_json(number.as_f64().unwrap_or(f64::NAN))?.as_bytes());
        }
        serde_json::Value::String(text) => decorate_string(text, out),
        serde_json::Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_value(item, out)?;
            }
            out.push(b']');
        }
        serde_json::Value::Object(members) => {
            let mut sorted: Vec<(&String, &serde_json::Value)> = members.iter().collect();
            // RFC 8785 sorts member names by UTF-16 code units, not by
            // UTF-8 bytes: they disagree across the BMP boundary (e.g.
            // U+FFFF sorts after U+10000 in UTF-16 but before it in UTF-8).
            sorted.sort_by(|left, right| utf16_code_units(left.0).cmp(utf16_code_units(right.0)));
            out.push(b'{');
            for (index, (name, item)) in sorted.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                decorate_string(name, out);
                out.push(b':');
                write_value(item, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

/// Compares two strings by their UTF-16 code-unit sequences.
fn utf16_code_units(text: &str) -> impl Iterator<Item = u16> + '_ {
    text.encode_utf16()
}

/// Emits `text` as a JSON string with RFC 8785 minimal escaping.
///
/// Bytes below 0x20 become `\b \f \n \r \t` where a short escape exists
/// and `\u00xx` (lowercase hex) otherwise; `"` and `\` are escaped;
/// everything else — including DEL and all multi-byte UTF-8 — is copied
/// raw. Iterating bytes is correct: UTF-8 continuation bytes are >= 0x80
/// so they can never collide with the ASCII break characters.
fn decorate_string(text: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for byte in text.as_bytes() {
        match *byte {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x09 => out.extend_from_slice(b"\\t"),
            0x0a => out.extend_from_slice(b"\\n"),
            0x0c => out.extend_from_slice(b"\\f"),
            0x0d => out.extend_from_slice(b"\\r"),
            c if c < 0x20 => {
                out.extend_from_slice(b"\\u00");
                out.push(hex_lower(c >> 4));
                out.push(hex_lower(c & 0x0f));
            }
            c => out.push(c),
        }
    }
    out.push(b'"');
}

fn hex_lower(nibble: u8) -> u8 {
    match nibble {
        0..=9 => b'0' + nibble,
        _ => b'a' + (nibble - 10),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical(input: &str) -> String {
        let value: serde_json::Value = serde_json::from_str(input).unwrap();
        String::from_utf8(canonicalize(&value).unwrap()).unwrap()
    }

    /// RFC 8785 Appendix A — object member sorting ("" < "\n" < " " < "#"
    /// < "$" < "1" < "10" < "A" < "AA" < "a" < "f" < "€"), and `56.0`
    /// collapsing to `56`.
    #[test]
    fn rfc_appendix_sorting_example() {
        assert_eq!(
            canonical(
                r##"{"1":"","f":{"f":"hi","F":"5"},"\n":56.0,"":null,"10":{}," ":7,"#":{},"€":"Euro","$":{},"A":{},"a":{},"AA":{}}"##
            ),
            r##"{"":null,"\n":56," ":7,"#":{},"$":{},"1":"","10":{},"A":{},"AA":{},"a":{},"f":{"F":"5","f":"hi"},"€":"Euro"}"##
        );
    }

    /// RFC 8785 Appendix A — numbers and surrogate-pair unescape.
    #[test]
    fn rfc_appendix_numbers_and_string_example() {
        assert_eq!(
            canonical(r#"{"peaches":1e30,"plums":"\uD834\uDD1E","applet":"yes"}"#),
            r#"{"applet":"yes","peaches":1e+30,"plums":"𝄞"}"#
        );
        // Every escape class: short escapes, \u00xx, surrogate pair,
        // non-ASCII passthrough — captured from upstream `jcs.Transform`.
        assert_eq!(
            canonical(r#"{"s":"\b\f\n\r\t\"\\\u0000\u001f\u000f"}"#),
            r#"{"s":"\b\f\n\r\t\"\\\u0000\u001f\u000f"}"#
        );
        assert_eq!(canonical(r#"{"s":"\u007f"}"#), "{\"s\":\"\u{7f}\"}");
        assert_eq!(canonical(r#"{"s":"\u00e9"}"#), r#"{"s":"é"}"#);
        assert_eq!(canonical(r#"{"s":"\/"}"#), r#"{"s":"/"}"#);
        // Same RFC compound example; the first number uses the
        // parser-agreeing spelling `333333333.3333333` (the RFC's literal
        // `333333333.33333329` is a `serde_json` 1-ulp parse divergence —
        // see `serde_json_parse_divergence`). Array order is preserved
        // by JCS; only object members are reordered.
        assert_eq!(
            canonical(
                r#"{"numbers":[333333333.3333333,1E30,4.5,0.002,1E-27],"string":"\u20ac$\u000F\na'B\u0001\"\\","literals":[null,true,false]}"#
            ),
            r#"{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\na'B\u0001\"\\"}"#
        );
    }

    /// Member names sort by UTF-16 code units, not UTF-8 bytes: U+FFFF
    /// (EF BF BF) precedes U+10000 (F0 90 80 80) byte-wise, but its
    /// UTF-16 code unit 0xFFFF sorts after U+10000's lead surrogate
    /// 0xD800. Upstream `jcs.Transform` output captured for this input.
    #[test]
    fn keys_sort_by_utf16_code_units() {
        assert_eq!(
            canonical(r#"{"￿":1,"𐀀":2,"z":3,"a":4}"#),
            r#"{"a":4,"z":3,"𐀀":2,"￿":1}"#
        );
    }

    /// ECMAScript number serialization — every expectation below is the
    /// byte-exact output of upstream `gowebpki/jcs`'s `NumberToJSON` for
    /// the same input literal.
    ///
    /// Inputs go through `str::parse::<f64>` (correctly rounded, same
    /// result as Go's `strconv.ParseFloat`) to isolate the formatter —
    /// `serde_json::from_str` can hold a 1-ulp-different f64 on
    /// pathological literals (see `serde_json_parse_divergence`).
    #[test]
    fn ecmascript_number_serialization() {
        let cases: &[(&str, &str)] = &[
            ("1e21", "1e+21"),
            ("-1e21", "-1e+21"),
            ("-0", "0"),
            ("0", "0"),
            ("5e-324", "5e-324"),
            ("4.9e-324", "5e-324"),
            ("2.5e-324", "5e-324"),
            ("-5e-324", "-5e-324"),
            ("1e-6", "0.000001"),
            ("1e-7", "1e-7"),
            ("-1e-6", "-0.000001"),
            ("-1e-7", "-1e-7"),
            ("1e-5", "0.00001"),
            ("1.5e-6", "0.0000015"),
            ("22e-7", "0.0000022"),
            ("9e-7", "9e-7"),
            ("999999999999999900000", "999999999999999900000"),
            ("999999999999999999999", "1e+21"),
            ("99999999999999999999", "100000000000000000000"),
            ("123456789012345678901", "123456789012345680000"),
            ("9007199254740991", "9007199254740991"),
            ("-9007199254740991", "-9007199254740991"),
            ("36028797018963968", "36028797018963970"),
            ("1e15", "1000000000000000"),
            ("1e20", "100000000000000000000"),
            ("1e308", "1e+308"),
            ("1.7976931348623157e308", "1.7976931348623157e+308"),
            ("2.2250738585072014e-308", "2.2250738585072014e-308"),
            ("-3.14159e-10", "-3.14159e-10"),
            ("1.23e45", "1.23e+45"),
            ("5e22", "5e+22"),
            ("0.1", "0.1"),
            ("0.30000000000000004", "0.30000000000000004"),
            ("3.0", "3"),
            ("1.0", "1"),
            ("-42", "-42"),
            ("100", "100"),
            ("333333333.33333329", "333333333.3333333"),
            ("0.002", "0.002"),
            ("1e-27", "1e-27"),
            ("4.5", "4.5"),
        ];
        for (input, want) in cases {
            let f: f64 = input.parse().unwrap();
            assert_eq!(number_to_json(f).unwrap(), *want, "input {input}");
        }
    }

    /// `serde_json::Value` trees carrying u64/i64/f64 numbers all pass
    /// through the same f64 rule — matching upstream where `UseNumber`
    /// literals become float64 before canonicalization.
    #[test]
    fn integer_kinds_route_through_f64() {
        let value: serde_json::Value = serde_json::from_str("[9007199254740991,-42,3.5]").unwrap();
        assert_eq!(
            String::from_utf8(canonicalize(&value).unwrap()).unwrap(),
            "[9007199254740991,-42,3.5]"
        );
    }

    /// `serde_json`'s stock float parser is not correctly rounded on
    /// every literal (the `float_roundtrip` feature is off workspace-wide
    /// by dependency policy): a pathological literal can land on a
    /// 1-ulp-different f64 than Go's `strconv.ParseFloat` produced for
    /// upstream fixtures. `canonicalize` still emits the correct JCS for
    /// the f64 the `Value` actually holds — this test pins that contract
    /// rather than the unreachable upstream bytes. Config documents are
    /// unaffected: they admit strict integers <= 2^53 only, which every
    /// parser represents exactly.
    #[test]
    fn serde_json_parse_divergence() {
        for input in ["333333333.33333329", "999999999999999900000"] {
            let value: serde_json::Value = serde_json::from_str(input).unwrap();
            let held = value.as_f64().unwrap();
            // Formatting the held f64 must equal canonicalizing the Value.
            let via_value = String::from_utf8(canonicalize(&value).unwrap()).unwrap();
            assert_eq!(via_value, number_to_json(held).unwrap(), "input {input}");
        }
    }

    #[test]
    fn non_finite_numbers_are_rejected() {
        for f in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert_eq!(number_to_json(f), Err(JcsError::NonFiniteNumber));
        }
    }

    /// Structural nesting, empty containers, and top-level scalars —
    /// byte-exact upstream outputs.
    #[test]
    fn structures_and_scalars() {
        assert_eq!(
            canonical(r#"[{"b":2,"a":1},[3,{"y":1,"x":2}],"tail"]"#),
            r#"[{"a":1,"b":2},[3,{"x":2,"y":1}],"tail"]"#
        );
        assert_eq!(canonical("{}"), "{}");
        assert_eq!(canonical("[]"), "[]");
        assert_eq!(canonical("\"top\""), "\"top\"");
        assert_eq!(canonical("123"), "123");
        assert_eq!(canonical("true"), "true");
        assert_eq!(canonical(r#"{"a":[{},[]]}"#), r#"{"a":[{},[]]}"#);
        assert_eq!(canonical(r#"{"k":{}}"#), r#"{"k":{}}"#);
        assert_eq!(
            canonical(r#"{"s":"héllo wörld"}"#),
            r#"{"s":"héllo wörld"}"#
        );
    }

    /// Byte-equality with the upstream signed-view fixture literals:
    /// `internal/config/view_test.go`'s canonical unsigned and signed
    /// envelopes must come out identical when round-tripped through
    /// `serde_json::Value` + `canonicalize`.
    #[test]
    fn upstream_view_envelope_fixtures_are_byte_identical() {
        const UNSIGNED: &str = r#"{"authoritative_config_digest":"04f1267e277e02b4c348197e980ce26c95da475ac3dc3a17cea94a975d4ce607","config_binding_id":"019b0000-0000-7000-8000-000000000101","instance_id":"019b0000-0000-7000-8000-000000000001","schema_version":"central.view-signature/v1","signed_at":"2026-08-01T12:34:56.123456Z","signing_key_id":"central.view-signing/v1:21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9","view_generation":7}"#;
        const ENVELOPE: &str = r#"{"authoritative_config_digest":"04f1267e277e02b4c348197e980ce26c95da475ac3dc3a17cea94a975d4ce607","config_binding_id":"019b0000-0000-7000-8000-000000000101","instance_id":"019b0000-0000-7000-8000-000000000001","schema_version":"central.view-signature/v1","signature":"kD5W1HpX8O0oeYIF9y4yTvncYc3X++/duN5EqyWHRs5P1EQL90iymmOgtStMyHjsmXTAJJDEBJzWznH+beAHDA","signed_at":"2026-08-01T12:34:56.123456Z","signing_key_id":"central.view-signing/v1:21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9","view_generation":7}"#;
        assert_eq!(canonical(UNSIGNED), UNSIGNED);
        assert_eq!(canonical(ENVELOPE), ENVELOPE);
    }

    /// Byte-equality with the upstream `internal/config/testdata/
    /// complete-config.json` fixture — already JCS-canonical, so a
    /// round-trip must reproduce it verbatim.
    #[test]
    fn upstream_complete_config_fixture_is_byte_identical() {
        let raw = include_bytes!("testdata/complete-config.json");
        let text = core::str::from_utf8(raw).unwrap();
        assert_eq!(canonical(text), text);
    }
}
