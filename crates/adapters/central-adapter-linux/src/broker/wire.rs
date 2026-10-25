//! Wire-codec primitives for the broker's upstream-compatible records.
//!
//! Mirrors the private `wire` module of `central-infra::authority` —
//! kept adapter-local because upstream's broker owns its own record
//! encodings (`protected_file_linux.go`, `payload_epoch_store_linux.go`,
//! `proof_service.go`, `journal.go`), not the domain crate. Serde
//! adapters are `pub(crate)` so a `#[serde(with = ...)]` call site can
//! name them.

use hmac::Mac;
use serde::{Deserialize, Deserializer, Serializer};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use time::macros::datetime;

/// Go's `time.Time{}` zero value — January 1, year 1, 00:00:00 UTC —
/// which upstream `IsZero` checks. `OffsetDateTime` has no zero value,
/// so the ported checks compare against this instant.
pub(crate) const GO_ZERO_TIME: OffsetDateTime = datetime!(1-01-01 0:00:00 UTC);

/// `t.IsZero()` upstream — true only for the exact zero instant.
pub(crate) fn is_go_zero_time(t: OffsetDateTime) -> bool {
    t == GO_ZERO_TIME
}

/// `#[serde(default)]` for `time.Time` fields: Go's `json.Unmarshal`
/// leaves an absent timestamp at the zero value rather than failing
/// the decode.
pub(crate) fn go_zero_time() -> OffsetDateTime {
    GO_ZERO_TIME
}

/// Go `time.RFC3339Nano` formatting: `hh:mm:ss` plus a fractional second
/// field that appears only when the nanosecond part is non-zero, then
/// with trailing zeros trimmed (`.999999999` semantics) — never a fixed
/// nine digits. `Z` for UTC, `±hh:mm` otherwise.
pub(crate) fn format_rfc3339_nano(t: OffsetDateTime) -> String {
    let mut out = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    );
    let nanos = t.nanosecond();
    if nanos != 0 {
        let frac = format!("{nanos:09}");
        out.push('.');
        out.push_str(frac.trim_end_matches('0'));
    }
    let offset = t.offset();
    if offset.is_utc() {
        out.push('Z');
    } else {
        let sign = if offset.is_negative() { '-' } else { '+' };
        out.push_str(&format!(
            "{sign}{:02}:{:02}",
            offset.whole_hours().abs(),
            offset.whole_minutes().abs() % 60
        ));
    }
    out
}

/// Serde adapter for `time.Time` fields tagged `json:"x"`: serializes
/// the RFC 3339 / RFC 3339Nano text Go emits, parses what Go's
/// `time.Time.UnmarshalJSON` accepts.
pub(crate) mod rfc3339 {
    use super::*;

    pub(crate) fn serialize<S: Serializer>(t: &OffsetDateTime, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format_rfc3339_nano(*t))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<OffsetDateTime, D::Error> {
        let text = String::deserialize(d)?;
        OffsetDateTime::parse(&text, &Rfc3339).map_err(serde::de::Error::custom)
    }
}

/// Serde adapter for `*time.Time` fields — `null` or absent ⇔ `None`,
/// an RFC 3339 string ⇔ `Some`.
pub(crate) mod rfc3339_opt {
    use super::*;

    pub(crate) fn serialize<S: Serializer>(
        t: &Option<OffsetDateTime>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match t {
            Some(t) => s.serialize_str(&format_rfc3339_nano(*t)),
            None => s.serialize_none(),
        }
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<OffsetDateTime>, D::Error> {
        let text = Option::<String>::deserialize(d)?;
        match text {
            None => Ok(None),
            Some(t) => OffsetDateTime::parse(&t, &Rfc3339)
                .map(Some)
                .map_err(serde::de::Error::custom),
        }
    }
}

/// Serde adapter for `map[string]time.Time` fields (the proof-state
/// tombstone maps): `{"key":"<rfc3339>"}`.
pub(crate) mod rfc3339_map {
    use std::collections::BTreeMap;

    use serde::Serialize;

    use super::*;

    pub(crate) fn serialize<S: Serializer>(
        map: &BTreeMap<String, OffsetDateTime>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let rendered: BTreeMap<&str, String> = map
            .iter()
            .map(|(k, v)| (k.as_str(), format_rfc3339_nano(*v)))
            .collect();
        rendered.serialize(s)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<BTreeMap<String, OffsetDateTime>, D::Error> {
        let raw = BTreeMap::<String, String>::deserialize(d)?;
        let mut out = BTreeMap::new();
        for (k, v) in raw {
            let parsed = OffsetDateTime::parse(&v, &Rfc3339).map_err(serde::de::Error::custom)?;
            out.insert(k, parsed);
        }
        Ok(out)
    }
}

/// Standard padded Base64 (Go `encoding/base64.StdEncoding`) — the JSON
/// encoding Go applies to `[]byte` fields.
const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub(crate) fn b64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        out.push(B64_ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(B64_ALPHABET[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(B64_ALPHABET[(n >> 6) as usize & 63] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64_ALPHABET[n as usize & 63] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// `base64.RawStdEncoding` — no padding (the bootstrap presentation
/// value's wire form, consumed by the Task-7 custody path).
#[allow(dead_code)]
pub(crate) fn b64_raw_encode(bytes: &[u8]) -> String {
    b64_encode(bytes).trim_end_matches('=').to_owned()
}

/// Strict `StdEncoding` decode: rejects non-alphabet bytes, bad length,
/// padding outside the final quad, and content after padding — matching
/// Go `StdEncoding.DecodeString` refusal shape.
pub(crate) fn b64_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.is_empty() {
        return Some(Vec::new());
    }
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let quads = bytes.len() / 4;
    let mut out = Vec::with_capacity(quads * 3);
    for (i, quad) in bytes.chunks(4).enumerate() {
        let last = i == quads - 1;
        let mut vals = [0u8; 4];
        let mut pad = 0usize;
        for (j, &c) in quad.iter().enumerate() {
            match c {
                b'=' => {
                    if !last || j < 2 {
                        return None;
                    }
                    pad += 1;
                }
                _ if pad > 0 => return None,
                b'A'..=b'Z' => vals[j] = c - b'A',
                b'a'..=b'z' => vals[j] = c - b'a' + 26,
                b'0'..=b'9' => vals[j] = c - b'0' + 52,
                b'+' => vals[j] = 62,
                b'/' => vals[j] = 63,
                _ => return None,
            }
        }
        let n = (u32::from(vals[0]) << 18)
            | (u32::from(vals[1]) << 12)
            | (u32::from(vals[2]) << 6)
            | u32::from(vals[3]);
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Some(out)
}

/// Serde adapter for `[]byte` fields — Go's `[]byte` ⇔ standard
/// base64 string (with `null` accepted as empty, the read-side half of
/// Go's `nil`⇔empty equivalence).
pub(crate) mod b64 {
    use super::*;

    pub(crate) fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&b64_encode(v))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = Option::<String>::deserialize(d)?;
        match text {
            None => Ok(Vec::new()),
            Some(t) => b64_decode(&t).ok_or_else(|| serde::de::Error::custom("invalid base64")),
        }
    }
}

/// Lowercase hex encode — Go `hex.EncodeToString` /
/// `fmt.Sprintf("%x", …)`.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// `validSHA256Hex` — exactly 64 lowercase hex digits decoding to 32
/// bytes (recovery_journal.go).
pub(crate) fn valid_sha256_hex(value: &str) -> bool {
    if value.len() != 64 || value.to_lowercase() != value {
        return false;
    }
    hex_decode(value).is_some_and(|d| d.len() == 32)
}

/// `validPrefixedSHA256` — `sha256:<64 lowercase hex>`.
pub(crate) fn valid_prefixed_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(valid_sha256_hex)
}

pub(crate) fn hex_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let nib = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        out.push((nib(pair[0])? << 4) | nib(pair[1])?);
    }
    Some(out)
}

/// `fmt.Sprintf("%x", sha256.Sum256(payload))` — lowercase hex of the
/// record digest.
pub(crate) fn sha256_hex(data: &[u8]) -> String {
    hex_encode(&Sha256::digest(data))
}

/// `"sha256:" + hex(sha256(data))` — the prefixed-digest vocabulary
/// payload-epoch active records carry.
pub(crate) fn sha256_prefixed(data: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(data))
}

/// `crypto/hmac.Equal` — constant-time byte-slice comparison.
pub(crate) fn hmac_equal(a: &[u8], b: &[u8]) -> bool {
    // hmac 0.13's `Mac` trait is what exposes `verify_slice`; a plain
    // `a == b` is short-circuiting. Route both through a fixed-length
    // digest compare: hash both, then constant-time compare via the
    // crate's own subtle path.
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// HMAC-SHA-256 keyed fingerprint — `hmac.New(sha256.New, key)` over
/// `domain|data`, lowercase hex (upstream `SigningService.HMACFingerprint`).
pub(crate) fn hmac_fingerprint(key: &[u8], domain: &str, data: &[u8]) -> String {
    let mut mac = <hmac::Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC-SHA-256 accepts any key length"));
    mac.update(domain.as_bytes());
    mac.update(b"|");
    mac.update(data);
    hex_encode(&mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_nano_trims_fraction() {
        let t = datetime!(2024-06-01 12:00:00.500000000 UTC);
        assert_eq!(format_rfc3339_nano(t), "2024-06-01T12:00:00.5Z");
        let t2 = datetime!(2024-06-01 12:00:00 UTC);
        assert_eq!(format_rfc3339_nano(t2), "2024-06-01T12:00:00Z");
    }

    #[test]
    fn b64_round_trip() {
        assert_eq!(b64_encode(b"hello"), "aGVsbG8=");
        assert_eq!(b64_decode("aGVsbG8="), Some(b"hello".to_vec()));
        assert_eq!(b64_decode("aGVsbG8"), None);
        assert_eq!(b64_raw_encode(b"hello"), "aGVsbG8");
    }

    #[test]
    fn hmac_fingerprint_matches_rfc_vector() {
        // HMAC-SHA-256("key", "domain|data") — the upstream wire form.
        let fp = hmac_fingerprint(b"key", "domain", b"data");
        assert_eq!(
            fp,
            "9d11179f8cbc72bd60234b8315464ad276582b2edae5139770a4decf5425e803"
        );
    }
}
