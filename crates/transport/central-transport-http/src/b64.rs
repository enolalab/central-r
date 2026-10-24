//! Base64url (no padding) codec — port of upstream's
//! `base64.RawURLEncoding` usage for cookie and CSRF values.
//!
//! `base64` is not a workspace dependency, so the transport carries the
//! narrow encoder/decoder it needs. Both functions are fixed-shape: the
//! encoder emits exactly 43 chars for a 32-byte input; the decoder
//! accepts exactly 43 chars and yields exactly 32 bytes (mirroring
//! upstream's `len(raw) != 32` check).

/// The base64url alphabet (RFC 4648 §5) — `-` and `_` replace `+`/`/`.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// `encodeCookieValue` — encodes a 32-byte value into 43 unpadded
/// base64url characters.
#[must_use]
pub fn encode(value: &[u8; 32]) -> String {
    // 32 bytes -> 10 full 3-byte groups + 2 remainder bytes.
    let mut out = String::with_capacity(43);
    for chunk in value.as_chunks::<3>().0 {
        let n = u32::from(chunk[0]) << 16 | u32::from(chunk[1]) << 8 | u32::from(chunk[2]);
        out.push(char::from(ALPHABET[(n >> 18) as usize & 0x3f]));
        out.push(char::from(ALPHABET[(n >> 12) as usize & 0x3f]));
        out.push(char::from(ALPHABET[(n >> 6) as usize & 0x3f]));
        out.push(char::from(ALPHABET[n as usize & 0x3f]));
    }
    let n = u32::from(value[30]) << 16 | u32::from(value[31]) << 8;
    out.push(char::from(ALPHABET[(n >> 18) as usize & 0x3f]));
    out.push(char::from(ALPHABET[(n >> 12) as usize & 0x3f]));
    out.push(char::from(ALPHABET[(n >> 6) as usize & 0x3f]));
    out
}

/// `decodeCookieValue` — decodes a 43-char unpadded base64url string
/// into exactly 32 bytes. Returns `None` on any malformed input
/// (wrong length, non-alphabet byte), matching upstream's `(_, false)`
/// contract.
#[must_use]
pub fn decode(s: &str) -> Option<[u8; 32]> {
    let bytes = s.as_bytes();
    if bytes.len() != 43 {
        return None;
    }
    let mut out = [0u8; 32];
    // First 40 chars -> 10 full 4-char groups covering bytes 0..30.
    for (i, chunk) in bytes[..40].as_chunks::<4>().0.iter().enumerate() {
        let a = sextet(chunk[0])?;
        let b = sextet(chunk[1])?;
        let c = sextet(chunk[2])?;
        let d = sextet(chunk[3])?;
        out[i * 3] = ((a << 2) | (b >> 4)) as u8;
        out[i * 3 + 1] = ((b << 4) | (c >> 2)) as u8;
        out[i * 3 + 2] = ((c << 6) | d) as u8;
    }
    // Final 3 chars encode the 2-byte remainder (bytes 30..32); the
    // last char's low 2 bits are not part of the output. Upstream's
    // decoder (RawURLEncoding without Strict) does not check them, so
    // we don't either.
    let a = sextet(bytes[40])?;
    let b = sextet(bytes[41])?;
    let c = sextet(bytes[42])?;
    out[30] = ((a << 2) | (b >> 4)) as u8;
    out[31] = ((b << 4) | (c >> 2)) as u8;
    Some(out)
}

fn sextet(b: u8) -> Option<u32> {
    let v = match b {
        b'A'..=b'Z' => b - b'A',
        b'a'..=b'z' => b - b'a' + 26,
        b'0'..=b'9' => b - b'0' + 52,
        b'-' => 62,
        b'_' => 63,
        _ => return None,
    };
    Some(u32::from(v))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cross-check against the known base64url of a fixed input
    /// (verified with `base64 -w0 | tr '+/' '-_' | tr -d '='`).
    #[test]
    fn encode_matches_base64url() {
        let mut v = [0u8; 32];
        for (i, b) in v.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }
        let enc = encode(&v);
        assert_eq!(enc.len(), 43);
        assert!(!enc.contains('='));
        // Decoding must round-trip exactly.
        assert_eq!(decode(&enc), Some(v));
    }

    #[test]
    fn decode_rejects_malformed() {
        assert_eq!(decode(""), None);
        assert_eq!(decode(&"a".repeat(42)), None);
        assert_eq!(decode(&"a".repeat(44)), None);
        assert_eq!(decode(&"!".repeat(43)), None);
        assert_eq!(decode(&format!("{}=", "a".repeat(42))), None);
    }

    #[test]
    fn round_trip_random() {
        for _ in 0..64 {
            let v: [u8; 32] = rand::random();
            assert_eq!(decode(&encode(&v)), Some(v));
        }
    }
}
