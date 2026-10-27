//! `accepted_facts.go` — the C01 accepted-point reader.
//!
//! [`AcceptedFactsReader`] derives the operation target identity and, under
//! the retained target lock, the exact [`BackupAcceptedFacts`] from one
//! dedicated runtime session. The payload epoch is **never** derived from
//! PostgreSQL: it comes from the trusted protected-state source the caller
//! supplies ([`TrustedPayloadEpochSource`]), exactly like upstream.

use std::sync::Arc;

use central_backup::backup::operation::{
    BackupAcceptedFacts, BackupOperation, BackupPhase, PINNED_BACKUP_CONFIGURATION,
    new_backup_accepted_facts,
};
use central_backup::domain::TargetIdentity;
use central_foundation::failure::Failure;
use sqlx::PgConnection;
use uuid::Uuid;

use crate::error::SqlxContext as _;
use crate::store_support::BlockingConn;

/// `ErrAcceptedBackupFacts` — the locator-free boundary failure. Neither a
/// PostgreSQL error nor a target locator ever crosses it.
pub(crate) fn accepted_facts_unavailable() -> Failure {
    Failure::unavailable(
        "recovery_accepted_facts",
        "recovery accepted-point facts are unavailable",
    )
}

/// The `acceptedBackupTargetSQL` probe (inlined in the `query!` call
/// below) uses only server-derived identity and the durable restore
/// epoch. The pinned local endpoint/role identity is compiled into
/// [`PINNED_BACKUP_CONFIGURATION`]; no caller-controlled DSN, target, or
/// configuration string participates.
///
/// `TrustedPayloadEpochSource` returns the active payload epoch from
/// protected state. PostgreSQL `restore_epoch` is target history and is
/// not payload-epoch authority.
pub trait TrustedPayloadEpochSource: Send + Sync {
    /// `ActivePayloadEpochID` — the protected payload epoch identity.
    ///
    /// # Errors
    /// Implementation-defined; any failure collapses to the caller's
    /// boundary error.
    fn active_payload_epoch_id(&self) -> Result<Uuid, Failure>;
}

/// `AcceptedFactsReader` — one dedicated runtime session plus the
/// protected payload-epoch seam.
pub struct AcceptedFactsReader {
    conn: BlockingConn,
    payload_epochs: Arc<dyn TrustedPayloadEpochSource>,
}

impl AcceptedFactsReader {
    /// `NewAcceptedFactsReader` — refuses a missing epoch source.
    ///
    /// # Errors
    /// `recovery_accepted_facts` when `payload_epochs` is absent or the
    /// bridge runtime cannot be built.
    pub fn new(
        conn: PgConnection,
        payload_epochs: Arc<dyn TrustedPayloadEpochSource>,
    ) -> Result<Self, Failure> {
        Ok(Self {
            conn: BlockingConn::new(conn)?,
            payload_epochs,
        })
    }

    /// `ReadBackupTarget` — the server-derived operation target.
    ///
    /// # Errors
    /// `recovery_accepted_facts` on any read or shape failure.
    pub fn read_backup_target(&self) -> Result<TargetIdentity, Failure> {
        self.read_target()
    }

    /// `BuildBackupAcceptedFacts` — requires the `planned` operation, a
    /// nonzero `database_time`, and a non-nil repository binding, then
    /// re-derives the target and refuses when it drifted from the
    /// operation's binding. The payload epoch is validated v7, both
    /// fingerprints are derived (never accepted), and the closed
    /// [`new_backup_accepted_facts`] constructor applies the pinned
    /// version fields.
    ///
    /// # Errors
    /// `recovery_accepted_facts` on any refusal.
    pub fn build_backup_accepted_facts(
        &self,
        operation: &BackupOperation,
        database_time: time::OffsetDateTime,
        repository_binding_id: Uuid,
        target_lock_proof: &str,
    ) -> Result<BackupAcceptedFacts, Failure> {
        if operation.validate().is_err()
            || operation.phase != BackupPhase::Planned
            || database_time == crate::backup::zero_time()
            || repository_binding_id.is_nil()
        {
            return Err(accepted_facts_unavailable());
        }
        let target = self.read_target()?;
        if target != operation.target {
            return Err(accepted_facts_unavailable());
        }
        let payload_epoch_id = self
            .payload_epochs
            .active_payload_epoch_id()
            .map_err(|_| accepted_facts_unavailable())?;
        if payload_epoch_id.is_nil() || !crate::backup::is_v7(payload_epoch_id) {
            return Err(accepted_facts_unavailable());
        }
        let config_fingerprint = sha256_fingerprint(PINNED_BACKUP_CONFIGURATION.as_bytes());
        let target_fingerprint = backup_target_fingerprint(&target, payload_epoch_id)?;
        new_backup_accepted_facts(
            database_time.to_offset(time::UtcOffset::UTC),
            &target_fingerprint,
            &config_fingerprint,
            payload_epoch_id,
            repository_binding_id,
            target_lock_proof,
        )
        .map_err(|_| accepted_facts_unavailable())
    }

    /// `readTarget` — the single `acceptedBackupTargetSQL` probe plus the
    /// upstream shape checks (nonblank system id/OID, `central` database,
    /// nonnegative epoch, `TargetIdentity::is_valid`).
    fn read_target(&self) -> Result<TargetIdentity, Failure> {
        let row = self.conn.run(|conn| {
            Box::pin(async move {
                sqlx::query!(
                    "SELECT (pg_control_system()).system_identifier::text AS \"system_id!\",
                        d.oid::text AS \"database_oid!\",
                        current_database() AS \"database!\",
                        COALESCE(MAX(m.restore_epoch), 0)::bigint AS \"restore_epoch!\"
                    FROM pg_catalog.pg_database AS d
                    CROSS JOIN central.epoch_markers AS m
                    WHERE d.datname = current_database()
                    GROUP BY d.oid"
                )
                .fetch_one(&mut *conn)
                .await
                .ctx("backup: read accepted target")
            })
        })?;
        if row.system_id.trim().is_empty()
            || row.database_oid.trim().is_empty()
            || row.database != "central"
            || row.restore_epoch < 0
        {
            return Err(accepted_facts_unavailable());
        }
        let config_hash = sha256_fingerprint(PINNED_BACKUP_CONFIGURATION.as_bytes());
        let target = TargetIdentity {
            system_id: row.system_id,
            database_oid: row.database_oid,
            database: row.database,
            config_hash,
            epoch: u64::try_from(row.restore_epoch).map_err(|_| accepted_facts_unavailable())?,
        };
        if !target.is_valid() {
            return Err(accepted_facts_unavailable());
        }
        Ok(target)
    }
}

/// `BackupTargetFingerprint` derives the canonical target identity shared
/// by a normal backup accepted point and the C02 throughput probe. A probe
/// worker must read `TargetIdentity` from its broker-delivered
/// `central_runtime` session; accepting a helper- or caller-supplied
/// fingerprint would allow throughput evidence from a different
/// PostgreSQL target or payload epoch to be reused.
///
/// # Errors
/// `recovery_accepted_facts` when the target is invalid or the payload
/// epoch is nil/non-v7.
pub fn backup_target_fingerprint(
    target: &TargetIdentity,
    payload_epoch_id: Uuid,
) -> Result<String, Failure> {
    if !target.is_valid() || payload_epoch_id.is_nil() || !crate::backup::is_v7(payload_epoch_id) {
        return Err(accepted_facts_unavailable());
    }
    Ok(sha256_fingerprint(
        format!(
            "central.backup-target/v1\u{0}{}\u{0}{}\u{0}{}\u{0}{}\u{0}{}\u{0}{}",
            target.system_id,
            target.database_oid,
            target.database,
            target.config_hash,
            target.epoch,
            payload_epoch_id,
        )
        .as_bytes(),
    ))
}

/// `sha256Fingerprint` — the `"sha256:"`-prefixed hex digest.
pub(crate) fn sha256_fingerprint(payload: &[u8]) -> String {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(payload);
    format!("sha256:{}", crate::backup::hex_encode(&digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> TargetIdentity {
        TargetIdentity {
            system_id: "sys".into(),
            database_oid: "16384".into(),
            database: "central".into(),
            config_hash: sha256_fingerprint(PINNED_BACKUP_CONFIGURATION.as_bytes()),
            epoch: 7,
        }
    }

    #[test]
    fn fingerprint_is_canonical_and_epoch_bound() {
        let epoch = Uuid::now_v7();
        let first = backup_target_fingerprint(&target(), epoch).unwrap();
        assert!(first.starts_with("sha256:"));
        assert_eq!(first.len(), "sha256:".len() + 64);
        // Same inputs → same fingerprint; a different epoch moves it.
        assert_eq!(first, backup_target_fingerprint(&target(), epoch).unwrap());
        let other = backup_target_fingerprint(&target(), Uuid::now_v7()).unwrap();
        assert_ne!(first, other);
        // Nil/non-v7 epochs and invalid targets refuse.
        assert!(backup_target_fingerprint(&target(), Uuid::nil()).is_err());
        let mut bad = target();
        bad.system_id.clear();
        assert!(backup_target_fingerprint(&bad, epoch).is_err());
    }
}
