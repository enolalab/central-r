//! SQLSTATE → [`Failure`] classification.
//!
//! Ports `internal/adapter/postgres/migrate/errors.go` (extended to the
//! integrity/serialization/cancellation codes the task brief requires).
//! Every mapped failure carries a stable machine `code` and a sanitized,
//! operator-safe message: raw query text, credentials, SQLSTATE internals,
//! and database locators are never surfaced.

use central_foundation::failure::{Failure, FailureKind};

/// Stable machine codes emitted by [`classify_sqlx`].
pub mod codes {
    pub const PG_ADAPTER_ERROR: &str = "pg_adapter_error";
    pub const PG_ERROR: &str = "pg_error";
    pub const PG_UNREACHABLE: &str = "pg_unreachable";
    pub const PG_CONNECTION: &str = "pg_connection_error";
    pub const PG_UNIQUE_VIOLATION: &str = "pg_unique_violation";
    pub const PG_FOREIGN_KEY_VIOLATION: &str = "pg_foreign_key_violation";
    pub const PG_CHECK_VIOLATION: &str = "pg_check_violation";
    pub const PG_SERIALIZATION_FAILURE: &str = "pg_serialization_failure";
    pub const PG_DEADLOCK: &str = "pg_deadlock_detected";
    pub const PG_LOCK_NOT_AVAILABLE: &str = "pg_lock_not_available";
    pub const PG_QUERY_CANCELLED: &str = "pg_query_cancelled";
    pub const PG_INSUFFICIENT_PRIVILEGE: &str = "pg_insufficient_privilege";
    pub const PG_DISK_FULL: &str = "pg_disk_full";
    pub const PG_OUT_OF_MEMORY: &str = "pg_out_of_memory";
}

/// Map an `sqlx` error to a sanitized [`Failure`].
///
/// Only the SQLSTATE classifies the failure; the database error text is
/// discarded so messages, bind values, and statement text cannot leak.
#[must_use]
pub fn classify_sqlx(err: &sqlx::Error) -> Failure {
    if let sqlx::Error::Database(db) = err {
        let state = db.code().unwrap_or_default();
        return match state.as_ref() {
            // Class 23 — integrity violations: the target state conflicts.
            "23505" => Failure::new(
                FailureKind::Conflict,
                codes::PG_UNIQUE_VIOLATION,
                "a uniqueness constraint rejected the statement",
            ),
            "23503" => Failure::new(
                FailureKind::Conflict,
                codes::PG_FOREIGN_KEY_VIOLATION,
                "a foreign-key constraint rejected the statement",
            ),
            "23514" => Failure::new(
                FailureKind::Conflict,
                codes::PG_CHECK_VIOLATION,
                "a check constraint rejected the statement",
            ),
            // Class 40 — transaction rollback: retryable, effect indeterminate.
            "40001" => Failure::new(
                FailureKind::Ambiguous,
                codes::PG_SERIALIZATION_FAILURE,
                "serialization failure; retry after backoff",
            ),
            "40P01" => Failure::new(
                FailureKind::Ambiguous,
                codes::PG_DEADLOCK,
                "deadlock detected; retry after backoff",
            ),
            // Lock acquisition refused (`lock_timeout`/`NOWAIT`): retryable.
            "55P03" => Failure::new(
                FailureKind::Ambiguous,
                codes::PG_LOCK_NOT_AVAILABLE,
                "lock not available; retry after backoff",
            ),
            // 57014 — the statement was cancelled.
            "57014" => Failure::new(
                FailureKind::Cancelled,
                codes::PG_QUERY_CANCELLED,
                "the statement was cancelled",
            ),
            // 42501 — role lacks the required privilege.
            "42501" => Failure::new(
                FailureKind::Denied,
                codes::PG_INSUFFICIENT_PRIVILEGE,
                "insufficient privilege for the statement",
            ),
            // Resource exhaustion — dependency unavailable.
            "53100" => Failure::new(
                FailureKind::Unavailable,
                codes::PG_DISK_FULL,
                "disk full; free disk space",
            ),
            "53200" => Failure::new(
                FailureKind::Unavailable,
                codes::PG_OUT_OF_MEMORY,
                "out of memory; reduce memory pressure",
            ),
            // Class 08 — connection failures: postgres unreachable.
            "08001" | "08004" => Failure::new(
                FailureKind::Unavailable,
                codes::PG_UNREACHABLE,
                "postgres unreachable; check postgres health",
            ),
            _ => Failure::new(
                FailureKind::Internal,
                codes::PG_ERROR,
                "postgres rejected the operation; investigate postgres state",
            ),
        };
    }
    match err {
        sqlx::Error::Io(_) | sqlx::Error::Tls(_) => Failure::new(
            FailureKind::Unavailable,
            codes::PG_CONNECTION,
            "postgres transport error; check postgres health",
        ),
        sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed => Failure::new(
            FailureKind::Unavailable,
            codes::PG_CONNECTION,
            "postgres connection pool unavailable; check postgres health",
        ),
        _ => Failure::new(
            FailureKind::Internal,
            codes::PG_ADAPTER_ERROR,
            "postgres adapter error; check postgres health and retry",
        ),
    }
}

/// Wrap a database call, classifying any error.
///
/// `context` is a short static operation label (e.g. `"baseline: check
/// existing schema"`); the returned message is `"{context} failed"` so no
/// internals cross the boundary.
pub(crate) trait SqlxContext<T> {
    /// Classify `self` with a static failure code and context label.
    ///
    /// # Errors
    /// Returns the mapped [`Failure`].
    fn ctx(self, context: &'static str) -> Result<T, Failure>;
}

impl<T> SqlxContext<T> for Result<T, sqlx::Error> {
    fn ctx(self, context: &'static str) -> Result<T, Failure> {
        self.map_err(|err| {
            let failure = classify_sqlx(&err);
            Failure::new(
                failure.kind(),
                failure.code(),
                format!("{context}: {}", failure.message()),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_database_errors_are_sanitized() {
        let io = sqlx::Error::Io(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "x"));
        let failure = classify_sqlx(&io);
        assert_eq!(failure.kind(), FailureKind::Unavailable);
        assert_eq!(failure.code(), codes::PG_CONNECTION);
        assert!(!failure.message().contains("x"));
    }

    #[test]
    fn row_not_found_maps_to_adapter_error() {
        let failure = classify_sqlx(&sqlx::Error::RowNotFound);
        assert_eq!(failure.kind(), FailureKind::Internal);
        assert_eq!(failure.code(), codes::PG_ADAPTER_ERROR);
    }
}
