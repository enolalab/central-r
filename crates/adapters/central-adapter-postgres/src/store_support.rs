//! Shared persistence-boundary helpers for the store modules.
//!
//! These functions exist for exactly two jobs: converting identity
//! newtypes to and from `uuid` column values at the trusted adapter
//! boundary, and converting the domain's `u64` counters/epochs to and
//! from PostgreSQL `bigint`. Everything else stays in the leaf modules
//! so each store reads as one table's contract.

use central_foundation::failure::Failure;
use sqlx::{PgPool, Postgres, Transaction};

/// Stable machine code for durable rows that fail domain
/// reconstruction — a stored row that cannot re-validate is corrupt,
/// never a caller error.
pub(crate) const PG_DATA_CORRUPT: &str = "pg_data_corrupt";

/// `u8; 16` identity bytes → `uuid` column value.
pub(crate) fn uuid_of(bytes: &[u8; 16]) -> uuid::Uuid {
    uuid::Uuid::from_bytes(*bytes)
}

/// Optional identity bytes → optional `uuid` column value.
pub(crate) fn opt_uuid_of<T>(id: Option<T>, bytes: impl Fn(&T) -> &[u8; 16]) -> Option<uuid::Uuid> {
    id.map(|i| uuid_of(bytes(&i)))
}

/// Domain `u64` → `bigint` bind. Values above `i64::MAX` cannot be
/// represented — a caller-level `invalid`, since the domain's contract
/// is the `bigint` range.
pub(crate) fn u64_as_i64(value: u64, code: &'static str) -> Result<i64, Failure> {
    i64::try_from(value)
        .map_err(|_| Failure::invalid(code, "the value does not fit the bigint column range"))
}

/// `bigint` column value → domain `u64`. A negative stored value is
/// corrupt durable state — `internal`, not a caller failure.
pub(crate) fn i64_as_u64(value: i64, what: &'static str) -> Result<u64, Failure> {
    u64::try_from(value).map_err(|_| {
        Failure::internal(
            PG_DATA_CORRUPT,
            format!("a stored {what} is outside the u64 range"),
        )
    })
}

/// `usize` limit → `bigint` bind (page sizes are bounded well under
/// `i64::MAX` by the request contracts).
pub(crate) fn usize_as_i64(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Begins a `READ COMMITTED` transaction with the upstream advisory
/// timeouts installed (eventjournal `Append`: `lock_timeout = 2s`,
/// `statement_timeout = 5s`, `idle_in_transaction_session_timeout =
/// 10s`). Every multi-statement commit coordinator in this adapter
/// goes through here so the lock-ordering discipline runs under one
/// bounded lease.
pub(crate) async fn begin_tx(pool: &PgPool) -> Result<Transaction<'static, Postgres>, Failure> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| crate::error::classify_sqlx(&e))?;
    for (name, value) in [
        ("lock_timeout", "2s"),
        ("statement_timeout", "5s"),
        ("idle_in_transaction_session_timeout", "10s"),
    ] {
        // Session/transaction configuration, not an application leaf
        // query — `set_config` cannot be represented through the
        // compile-checked macros (its name is a bound parameter).
        sqlx::query("SELECT set_config($1, $2, true)")
            .bind(name)
            .bind(value)
            .execute(&mut *tx)
            .await
            .map_err(|e| crate::error::classify_sqlx(&e))?;
    }
    Ok(tx)
}
