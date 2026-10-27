//! `internal/adapter/postgres/backup` — the backup-side PostgreSQL
//! surface: the C01 accepted-facts/census/ready-artifact reads, the C03
//! restore-target admission read, and the sealed-passfile runtime
//! connections.
//!
//! Every type binds one **dedicated** `PgConnection` through
//! [`crate::store_support::BlockingConn`]: upstream holds a single
//! `*pgx.Conn` per reader/worker because the C04 target exclusion lives
//! on the same session. The `central-backup` port traits are synchronous
//! by design — `BlockingConn` owns the async bridge on a private runtime.
//!
//! Boundary rule (upstream): no SQL text, DSN, credential, object key,
//! or table name ever crosses these modules' errors — only the stable
//! `recovery_*`/`backup_*` failure codes.

mod accepted_facts;
mod census;
mod restore_admission;
mod runtime_connection;
mod store;
mod target_exclusion;

pub use accepted_facts::{
    AcceptedFactsReader, TrustedPayloadEpochSource, backup_target_fingerprint,
};
pub use census::{BackupDatabaseCensus, CapacityCensusReader};
pub use restore_admission::{RestoreTargetAdmission, RestoreTargetAdmissionReader};
pub use runtime_connection::{
    open_runtime_connection, open_throughput_target_connection, throughput_target_application_name,
};
pub(crate) use store::RawReadyRow;
pub use store::{ReadyArtifactObjectReader, ReadyArtifactRecord, ReadyArtifactSource};
pub use target_exclusion::{
    PostgresBackupTargetExcluder, PostgresRestoreTargetExcluder,
    new_postgres_backup_target_excluder, new_postgres_restore_target_excluder,
};

// ---------------------------------------------------------------------------
// Shared boundary helpers (crate-private; the capability `wire` module is
// `pub(crate)` upstream so the same primitives live here verbatim).
// ---------------------------------------------------------------------------

/// `wire.hex_encode` — lowercase hex of `bytes`.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// `wire.is_v7` — non-nil UUID version 7.
pub(crate) fn is_v7(id: uuid::Uuid) -> bool {
    !id.is_nil() && id.get_version_num() == 7
}

/// `wire.zero_time` — the Go zero `time.Time` (year 1, UTC).
pub(crate) fn zero_time() -> time::OffsetDateTime {
    time::OffsetDateTime::UNIX_EPOCH
        .replace_year(1)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
}

/// `wire.is_zero_time`.
pub(crate) fn is_zero_time(t: time::OffsetDateTime) -> bool {
    t == zero_time()
}

/// `decodeSHA256` — a `"sha256:"`-prefixed 64-hex digest → 32 bytes.
pub(crate) fn decode_sha256(value: &str) -> Result<[u8; 32], central_foundation::failure::Failure> {
    let Some(hex_value) = value.strip_prefix("sha256:") else {
        return Err(central_foundation::failure::Failure::invalid(
            "recovery_audit",
            "invalid sha256 digest",
        ));
    };
    if hex_value.len() != 64 {
        return Err(central_foundation::failure::Failure::invalid(
            "recovery_audit",
            "invalid sha256 digest",
        ));
    }
    let mut out = [0u8; 32];
    let bytes = hex_value.as_bytes();
    for index in 0..32 {
        let hi = (bytes[index * 2] as char).to_digit(16);
        let lo = (bytes[index * 2 + 1] as char).to_digit(16);
        match (hi, lo) {
            (Some(hi), Some(lo)) => out[index] = ((hi << 4) | lo) as u8,
            _ => {
                return Err(central_foundation::failure::Failure::invalid(
                    "recovery_audit",
                    "invalid sha256 digest",
                ));
            }
        }
    }
    Ok(out)
}

/// `RFC3339Nano` — the canonical `time.RFC3339Nano` formatting used by
/// the hashed receipt payloads: UTC, no trailing-zero trimming beyond
/// what Go's layout produces (Go prints *all* nanoseconds present).
pub(crate) fn rfc3339_nano(t: time::OffsetDateTime) -> String {
    let utc = t.to_offset(time::UtcOffset::UTC);
    let nanos = utc.nanosecond();
    if nanos == 0 {
        return format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            utc.year(),
            utc.month() as u8,
            utc.day(),
            utc.hour(),
            utc.minute(),
            utc.second()
        );
    }
    // Go's RFC3339Nano trims trailing zeros in the fraction.
    let mut fraction = format!("{nanos:09}");
    while fraction.ends_with('0') {
        fraction.pop();
    }
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{fraction}Z",
        utc.year(),
        utc.month() as u8,
        utc.day(),
        utc.hour(),
        utc.minute(),
        utc.second()
    )
}

/// `t.UTC().Truncate(time.Microsecond)` — PostgreSQL `timestamptz`
/// resolution.
pub(crate) fn truncate_micros(t: time::OffsetDateTime) -> time::OffsetDateTime {
    let utc = t.to_offset(time::UtcOffset::UTC);
    utc - time::Duration::nanoseconds(i64::from(utc.nanosecond() % 1000))
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn sha256_decode_round_trips_and_refuses() {
        let digest = decode_sha256(&format!("sha256:{}", "ab".repeat(32))).unwrap();
        assert_eq!(digest[0], 0xab);
        assert!(decode_sha256("sha256:xyz").is_err());
        assert!(decode_sha256("md5:aaaa").is_err());
        assert!(decode_sha256("sha256:aa").is_err());
    }

    #[test]
    fn rfc3339_nano_matches_go_layout() {
        assert_eq!(
            rfc3339_nano(datetime!(2026-03-01 12:30:00 UTC)),
            "2026-03-01T12:30:00Z"
        );
        assert_eq!(
            rfc3339_nano(datetime!(2026-03-01 12:30:00.123456789 UTC)),
            "2026-03-01T12:30:00.123456789Z"
        );
        assert_eq!(
            rfc3339_nano(datetime!(2026-03-01 12:30:00.123400000 UTC)),
            "2026-03-01T12:30:00.1234Z"
        );
    }

    #[test]
    fn micros_truncation() {
        let t = datetime!(2026-03-01 12:30:00.123456789 UTC);
        assert_eq!(
            truncate_micros(t),
            datetime!(2026-03-01 12:30:00.123456 UTC)
        );
    }
}
