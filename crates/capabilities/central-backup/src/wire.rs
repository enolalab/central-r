//! Internal wire helpers shared by the backup/recovery canonical
//! documents (`internal/backup/{migration,inventory,repository_seal,
//! repository_attestation,target_lock_attestation}.go`):
//!
//! - `decode_canonical` — upstream `decodeCanonicalJSON`: strict field
//!   set (`serde(deny_unknown_fields)` ≙ `Decoder.DisallowUnknownFields`)
//!   plus a single-value check (`de.end()` ≙ the second `Decode` that
//!   must see `io.EOF`).
//! - `rfc3339_nano`/`parse_rfc3339` — Go `time.RFC3339Nano`: nanos are
//!   emitted only when nonzero, trailing zeros trimmed. serde's
//!   well-known Rfc3339 never emits a fraction, so an exact
//!   reproduction needs this hand-rolled form.
//! - `hmac_sha256` — `crypto/hmac` over SHA-256 (RFC 2104), implemented
//!   over `sha2` so this crate needs no new dependency.

use central_foundation::failure::Failure;
use serde::de::Deserialize;
use sha2::{Digest as _, Sha256};

/// `fieldSeparator` (`migration.go`) — the canonical ticket/proof
/// payload's field terminator.
pub(crate) const FIELD_SEPARATOR: u8 = b'\n';

/// `errors.New`-class refusal inside this capability's wire layer.
pub(crate) fn wire_failure(context: &'static str, message: impl Into<String>) -> Failure {
    Failure::invalid(context, message.into())
}

/// `hex.EncodeToString`.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// `sha256.Sum256` rendered lowercase-hex.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex_encode(Sha256::digest(bytes).as_slice())
}

/// `parseSHA256` — exactly 64 lowercase hex chars; re-encoding must
/// reproduce the input byte-for-byte (rejects uppercase/mixed).
pub(crate) fn parse_sha256(encoded: &str) -> Result<[u8; 32], Failure> {
    let raw = encoded.as_bytes();
    let nibble = |b: u8| -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        }
    };
    if raw.len() != 64 {
        return Err(wire_failure(
            "backup_recovery",
            "invalid recovery SHA-256 encoding",
        ));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let (Some(hi), Some(lo)) = (nibble(raw[i * 2]), nibble(raw[i * 2 + 1])) else {
            return Err(wire_failure(
                "backup_recovery",
                "invalid recovery SHA-256 encoding",
            ));
        };
        out[i] = (hi << 4) | lo;
    }
    if hex_encode(&out) != encoded {
        return Err(wire_failure(
            "backup_recovery",
            "invalid recovery SHA-256 encoding",
        ));
    }
    Ok(out)
}

/// `validSHA256Fingerprint` — `"sha256:"` + 64 lowercase hex whose
/// re-encoding round-trips.
pub(crate) fn valid_sha256_fingerprint(value: &str) -> bool {
    let Some(hex_part) = value.strip_prefix("sha256:") else {
        return false;
    };
    parse_sha256(hex_part).is_ok()
}

/// `validRecoveryDigest` — same shape, without the re-encode check.
pub(crate) fn valid_recovery_digest(value: &str) -> bool {
    let Some(hex_part) = value.strip_prefix("sha256:") else {
        return false;
    };
    let raw = hex_part.as_bytes();
    raw.len() == 64 && raw.iter().all(|b| b.is_ascii_hexdigit())
}

/// `decodeCanonicalJSON` — strict single-value decode.
pub(crate) fn decode_canonical<'a, T: Deserialize<'a>>(payload: &'a [u8]) -> Result<T, Failure> {
    let mut de = serde_json::Deserializer::from_slice(payload);
    let value = Deserialize::deserialize(&mut de)
        .map_err(|e| wire_failure("backup_canonical_json", e.to_string()))?;
    de.end()
        .map_err(|_| wire_failure("backup_canonical_json", "trailing data after JSON value"))?;
    Ok(value)
}

/// `time.Time.Format(time.RFC3339Nano)` — base seconds always, then a
/// `.` + nanosecond group only when nanos are nonzero, trailing zeros
/// trimmed (`…05Z`, `…05.1Z`, `…05.123456789Z`).
pub(crate) fn rfc3339_nano(t: time::OffsetDateTime) -> String {
    let t = t.to_offset(time::UtcOffset::UTC);
    let base = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        t.year(),
        t.month() as u8,
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    );
    let nanos = t.nanosecond();
    if nanos == 0 {
        return format!("{base}Z");
    }
    let mut frac = format!("{nanos:09}");
    while frac.ends_with('0') {
        frac.pop();
    }
    format!("{base}.{frac}Z")
}

/// `time.Parse(time.RFC3339Nano, …)` + the `Location() == time.UTC`
/// requirement the seal-root parse asserts.
pub(crate) fn parse_rfc3339_utc(raw: &str) -> Result<time::OffsetDateTime, Failure> {
    let parsed = time::OffsetDateTime::parse(raw, &time::format_description::well_known::Rfc3339)
        .map_err(|_| wire_failure("backup_canonical_json", "invalid RFC 3339 instant"))?;
    if parsed.offset() != time::UtcOffset::UTC {
        return Err(wire_failure(
            "backup_canonical_json",
            "non-UTC RFC 3339 instant",
        ));
    }
    Ok(parsed)
}

/// `time.Time.IsZero`.
pub(crate) fn is_zero_time(t: time::OffsetDateTime) -> bool {
    t == time::OffsetDateTime::UNIX_EPOCH
        .replace_year(1)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
        || (t.year() == 1
            && t.month() == time::Month::January
            && t.day() == 1
            && t.hour() == 0
            && t.minute() == 0
            && t.second() == 0
            && t.nanosecond() == 0)
}

/// `hmac.New(sha256.New, key)` — RFC 2104 HMAC-SHA-256.
pub(crate) fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut key_block = [0u8; BLOCK];
    if key.len() > BLOCK {
        let hashed = Sha256::digest(key);
        key_block[..32].copy_from_slice(&hashed);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0u8; BLOCK];
    let mut opad = [0u8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5c;
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    outer.finalize().into()
}

/// `hmac.Equal` — constant-time byte equality.
pub(crate) fn mac_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// `uuid.Nil`/`Version() != uuid.V7` (gofrs) → uuid v7 check.
pub(crate) fn is_v7(id: uuid::Uuid) -> bool {
    !id.is_nil() && id.get_version_num() == 7
}

/// The Go zero `time.Time` (year 1, UTC) — `replace_year(1)` on the
/// epoch never fails, so this `expect` is the single fallible point.
pub(crate) fn zero_time() -> time::OffsetDateTime {
    time::OffsetDateTime::UNIX_EPOCH
        .replace_year(1)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
}
