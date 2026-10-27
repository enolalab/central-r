//! `restore_admission.go` — the production read-only PostgreSQL side of
//! C03 admission.
//!
//! [`RestoreTargetAdmissionReader`] derives target identity and requires
//! every database-owned restore/security marker to agree: `MIN`/`MAX`
//! over the `epoch_markers ∪ workspaces` union, never `MAX` alone — a
//! partially reset target must not authorize a ticket against mixed
//! epochs. The payload epoch remains protected-state authority supplied
//! through [`TrustedPayloadEpochSource`]; it is never inferred from
//! PostgreSQL.

use std::sync::Arc;

use central_backup::backup::operation::{
    BACKUP_DATABASE_SCHEMA_VERSION, PINNED_BACKUP_CONFIGURATION,
};
use central_backup::domain::TargetIdentity;
use central_foundation::failure::Failure;
use sqlx::PgConnection;
use uuid::Uuid;

use super::accepted_facts::{TrustedPayloadEpochSource, sha256_fingerprint};
use crate::error::SqlxContext as _;
use crate::store_support::BlockingConn;

/// `ErrRestoreTargetAdmission` is safe to return across the restore
/// verifier boundary. PostgreSQL errors, DSNs, and protected
/// payload-epoch details are deliberately collapsed into this value.
fn restore_target_admission_unavailable() -> Failure {
    Failure::unavailable(
        "restore_target_admission",
        "restore target admission is unavailable",
    )
}

/// `RestoreTargetAdmission` — `backupadapter.RestoreTargetAdmission`:
/// the database-derived half of C03 admission. The composition's
/// `RestoreAdmissionInspector` combines it with sealed manifest evidence
/// and a fresh capacity observation; this reader returns only what
/// PostgreSQL itself can prove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreTargetAdmission {
    /// Server-derived target identity.
    pub target: TargetIdentity,
    /// `sha256:`-prefixed derived target fingerprint.
    pub target_fingerprint: String,
    /// The coherent security epoch (MIN == MAX enforced).
    pub security_epoch: u64,
    /// The coherent restore epoch (MIN == MAX enforced).
    pub restore_epoch: u64,
    /// `sha256:`-prefixed pinned-config fingerprint.
    pub config_fingerprint: String,
    /// Protected payload epoch (v7).
    pub payload_epoch_id: Uuid,
    /// Fixed [`BACKUP_DATABASE_SCHEMA_VERSION`].
    pub database_schema_version: String,
    /// Pinned restore tool version.
    pub restore_tool_version: String,
}

/// `RestoreTargetAdmissionReader` — one dedicated runtime session plus
/// the protected payload-epoch seam.
pub struct RestoreTargetAdmissionReader {
    conn: BlockingConn,
    payload_epochs: Arc<dyn TrustedPayloadEpochSource>,
}

impl RestoreTargetAdmissionReader {
    /// `NewRestoreTargetAdmissionReader`.
    ///
    /// # Errors
    /// `restore_target_admission` when the bridge runtime cannot be built.
    pub fn new(
        conn: PgConnection,
        payload_epochs: Arc<dyn TrustedPayloadEpochSource>,
    ) -> Result<Self, Failure> {
        Ok(Self {
            conn: BlockingConn::new(conn)?,
            payload_epochs,
        })
    }

    /// `OpenRuntimeConnectionFromSealedPassfile` composition shape: the
    /// caller only has a connect future, and a `PgConnection` must be
    /// made on the same runtime that will drive it
    /// ([`BlockingConn::new_connecting`]'s reactor-binding rule).
    ///
    /// # Errors
    /// `restore_target_admission` when the bridge runtime cannot be
    /// built; whatever `connect` returns otherwise.
    pub fn new_connecting<F, Fut>(
        connect: F,
        payload_epochs: Arc<dyn TrustedPayloadEpochSource>,
    ) -> Result<Self, Failure>
    where
        F: FnOnce() -> Fut,
        Fut: core::future::Future<Output = Result<PgConnection, Failure>>,
    {
        Ok(Self {
            conn: BlockingConn::new_connecting(connect)?,
            payload_epochs,
        })
    }

    /// `ReadRestoreTargetAdmission` — the `restoreTargetAdmissionSQL`
    /// probe plus upstream shape checks: nonblank system id/OID,
    /// `central` database, nonempty marker set, nonnegative and
    /// *coherent* restore/security epochs (MIN == MAX).
    ///
    /// # Errors
    /// `restore_target_admission` on any read or coherence refusal;
    /// `recovery_accepted_facts`-adjacent cancellation propagates as
    /// unavailable too (upstream maps `ctx.Err()` to the same boundary).
    pub fn read_restore_target_admission(
        &self,
        backup_id: Uuid,
    ) -> Result<RestoreTargetAdmission, Failure> {
        if backup_id.is_nil() || !crate::backup::is_v7(backup_id) {
            return Err(restore_target_admission_unavailable());
        }
        let row = self.conn.run(|conn| {
            Box::pin(async move {
                sqlx::query!(
                    "WITH current_epochs AS (
                        SELECT restore_epoch, security_epoch FROM central.epoch_markers
                        UNION ALL
                        SELECT restore_epoch, security_epoch FROM central.workspaces
                    )
                    SELECT
                        (pg_control_system()).system_identifier::text AS \"system_id!\",
                        d.oid::text AS \"database_oid!\",
                        current_database() AS \"database!\",
                        MIN(e.restore_epoch)::bigint AS \"restore_minimum!\",
                        MAX(e.restore_epoch)::bigint AS \"restore_maximum!\",
                        MIN(e.security_epoch)::bigint AS \"security_minimum!\",
                        MAX(e.security_epoch)::bigint AS \"security_maximum!\",
                        COUNT(*)::bigint AS \"marker_count!\"
                    FROM pg_catalog.pg_database AS d
                    CROSS JOIN current_epochs AS e
                    WHERE d.datname = current_database()
                    GROUP BY d.oid"
                )
                .fetch_one(&mut *conn)
                .await
                .ctx("backup: read restore target admission")
            })
        })?;
        if row.system_id.trim().is_empty()
            || row.database_oid.trim().is_empty()
            || row.database != "central"
            || row.marker_count <= 0
            || row.restore_minimum < 0
            || row.restore_minimum != row.restore_maximum
            || row.security_minimum < 0
            || row.security_minimum != row.security_maximum
        {
            return Err(restore_target_admission_unavailable());
        }
        let payload_epoch_id = self
            .payload_epochs
            .active_payload_epoch_id()
            .map_err(|_| restore_target_admission_unavailable())?;
        if payload_epoch_id.is_nil() || !crate::backup::is_v7(payload_epoch_id) {
            return Err(restore_target_admission_unavailable());
        }
        let config_fingerprint = sha256_fingerprint(PINNED_BACKUP_CONFIGURATION.as_bytes());
        let target = TargetIdentity {
            system_id: row.system_id,
            database_oid: row.database_oid,
            database: row.database,
            config_hash: config_fingerprint.clone(),
            epoch: u64::try_from(row.restore_minimum)
                .map_err(|_| restore_target_admission_unavailable())?,
        };
        if !target.is_valid() {
            return Err(restore_target_admission_unavailable());
        }
        let target_fingerprint =
            super::accepted_facts::backup_target_fingerprint(&target, payload_epoch_id)
                .map_err(|_| restore_target_admission_unavailable())?;
        Ok(RestoreTargetAdmission {
            target,
            target_fingerprint,
            security_epoch: u64::try_from(row.security_minimum)
                .map_err(|_| restore_target_admission_unavailable())?,
            restore_epoch: u64::try_from(row.restore_minimum)
                .map_err(|_| restore_target_admission_unavailable())?,
            config_fingerprint,
            payload_epoch_id,
            database_schema_version: BACKUP_DATABASE_SCHEMA_VERSION.into(),
            restore_tool_version: "pg_restore-16.14".into(),
        })
    }
}
