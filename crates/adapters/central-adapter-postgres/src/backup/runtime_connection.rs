//! `runtime_connection_linux.go` (non-descriptor half) — the sealed
//! passfile connects for the backup worker and the C02 throughput probe.
//!
//! Like `migrate::runtime_connection`, this module never sees the raw
//! descriptor: the memfd seal/shape validation
//! (`validateRuntimePassfileDescriptor` upstream) lives in
//! `central-adapter-linux`; callers hand over only the bounded, NUL-free
//! pgpass bytes and own zeroization after return. No target, role,
//! password, or option is accepted from argv, environment, or config —
//! `connect_role_from_passfile_value` pins `127.0.0.1:55432/central`.

use sqlx::PgConnection;
use uuid::Uuid;

use central_foundation::failure::Failure;

use crate::migrate::runtime_connection::connect_role_from_passfile_value;

/// `ErrBackupRuntimeConnection` — the one typed connection failure; the
/// credential material never reaches an error message.
fn runtime_connection() -> Failure {
    Failure::unavailable(
        "backup_runtime_connection",
        "recovery PostgreSQL runtime connection is unavailable",
    )
}

/// `OpenRuntimeConnectionFromSealedPassfile` — opens the one fixed local
/// `central_runtime` target from a broker-delivered memfd's bounded bytes
/// under the `central-backup-worker` application name.
///
/// # Errors
/// `backup_runtime_connection` on any parse/binding/connect failure.
pub async fn open_runtime_connection(value: &[u8]) -> Result<PgConnection, Failure> {
    if value.is_empty() {
        return Err(runtime_connection());
    }
    connect_role_from_passfile_value(value, "central_runtime", "central-backup-worker").await
}

/// `OpenThroughputTargetConnectionFromSealedPassfile` — the same fixed
/// central target under an operation-bound application name. Cleanup
/// census can therefore prove the probe control session is gone without
/// accepting a caller-selected label, database, role, host, or
/// connection option.
///
/// # Errors
/// `backup_runtime_connection` on a nil/non-v7 `operation_id` or any
/// parse/binding/connect failure.
pub async fn open_throughput_target_connection(
    value: &[u8],
    operation_id: Uuid,
) -> Result<PgConnection, Failure> {
    if !crate::backup::is_v7(operation_id) || value.is_empty() {
        return Err(runtime_connection());
    }
    connect_role_from_passfile_value(
        value,
        "central_runtime",
        &throughput_target_application_name(operation_id),
    )
    .await
}

/// `throughputTargetApplicationName` — the operation-bound probe label.
#[must_use]
pub fn throughput_target_application_name(operation_id: Uuid) -> String {
    format!("central-probe-lock-{operation_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn application_name_binds_the_operation() {
        let id = Uuid::now_v7();
        assert_eq!(
            throughput_target_application_name(id),
            format!("central-probe-lock-{id}")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn invalid_operation_refuses_before_any_io() {
        assert!(
            open_throughput_target_connection(b"x", Uuid::nil())
                .await
                .is_err()
        );
        assert!(
            open_throughput_target_connection(b"x", Uuid::new_v4())
                .await
                .is_err()
        );
        assert!(open_runtime_connection(b"").await.is_err());
        // A malformed passfile refuses without ever dialing out.
        assert!(open_runtime_connection(b"not:a:pgpass:line").await.is_err());
    }
}
