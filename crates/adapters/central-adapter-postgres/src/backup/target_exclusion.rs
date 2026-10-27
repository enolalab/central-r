//! `postgres_target_exclusion.go` — the session-scoped PostgreSQL
//! advisory-lock fences. Both excluders own one **dedicated**
//! `PgConnection` through [`BlockingConn`]: a pool would let a later
//! query run on another session and silently lose the exclusion. The
//! lock pair is always `SERVE_TARGET_EXCLUSION_LOCK_KEY` plus the
//! SHA-256-derived target key — two recovery attempts for the same
//! database contend on one fence.
//!
//! Known design gap (carried, not weakened):
//! [`central_backup::port::BackupTargetLockRetainer::retain_for_post_reap`]
//! upstream hijacks the pgx connection's raw socket and hands a
//! duplicate to the native monitor over SCM_RIGHTS. `sqlx::PgConnection`
//! exposes no socket descriptor, so the Rust retainer fails closed —
//! the handoff boundary remains for T7/T9 composition work.

use central_backup::backup::operation::BACKUP_TARGET_LOCK_PROTOCOL;
use central_backup::domain::TargetIdentity;
use central_backup::port::{
    BackupTargetExcluder, BackupTargetExclusion, BackupTargetLockRetainer, RestoreTargetExcluder,
    RestoreTargetExclusion,
};
use central_backup::recovery::operation::{RestoreOperation, SERVE_TARGET_EXCLUSION_LOCK_KEY};
use central_foundation::failure::Failure;
use sha2::{Digest as _, Sha256};
use sqlx::PgConnection;
use std::sync::{Arc, Mutex};

use crate::store_support::BlockingConn;

/// `ErrRestoreTargetBusy` — another session owns the target-wide C04
/// fence. Distinct from a restore failure: no target mutation happened
/// and callers may resume the same protected operation after release.
fn restore_target_busy() -> Failure {
    Failure::denied(
        "restore_target_busy",
        "restore target exclusion is already held",
    )
}

/// `ErrBackupTargetBusy` / `ErrBackupTargetExclusion`.
fn backup_target_busy() -> Failure {
    Failure::denied(
        "backup_target_busy",
        "backup target exclusion is already held",
    )
}

fn backup_target_exclusion_unavailable() -> Failure {
    Failure::unavailable(
        "backup_target_exclusion",
        "backup target exclusion is unavailable",
    )
}

fn restore_target_exclusion_unavailable() -> Failure {
    Failure::unavailable(
        "restore_target_exclusion",
        "restore target exclusion is unavailable",
    )
}

/// `restoreTargetLockKey` — deterministic only from the durable target
/// identity; ticket/operation IDs are deliberately excluded so two
/// recovery attempts for the same database contend on one fence.
/// SHA-256 makes accidental cross-target collisions impractical
/// without accepting caller-controlled SQL identifiers.
fn restore_target_lock_key(target: &TargetIdentity) -> i64 {
    let payload = format!(
        "central.restore.target.v1\x00{}\x00{}\x00{}",
        target.system_id, target.database_oid, target.database
    );
    let digest = Sha256::digest(payload.as_bytes());
    i64::from_be_bytes(digest[..8].try_into().unwrap_or([0; 8]))
}

/// The `pg_locks` row proving *this* session still grants the advisory
/// key — `pg_locks` represents an int8 advisory key as the high/low
/// 32-bit OID fields, and the `pid = pg_backend_pid()` clause proves
/// this exact dedicated connection rather than merely observing that
/// another session holds the same key.
async fn advisory_held(
    conn: &mut PgConnection,
    key: i64,
    unavailable: fn() -> Failure,
) -> Result<bool, Failure> {
    let high = (key as u64 >> 32) as u32 as i64;
    let low = key as u64 as u32 as i64;
    sqlx::query_scalar!(
        r#"SELECT EXISTS (
            SELECT 1 FROM pg_catalog.pg_locks
            WHERE locktype = 'advisory' AND pid = pg_backend_pid()
              AND classid = $1::bigint::oid AND objid = $2::bigint::oid
              AND objsubid = 1 AND granted
        ) AS "held!""#,
        high,
        low
    )
    .fetch_one(conn)
    .await
    .map_err(|_| unavailable())
}

async fn advisory_try_lock(
    conn: &mut PgConnection,
    key: i64,
    unavailable: fn() -> Failure,
) -> Result<bool, Failure> {
    sqlx::query_scalar!(r#"SELECT pg_try_advisory_lock($1) AS "held!""#, key)
        .fetch_one(conn)
        .await
        .map_err(|_| unavailable())
}

async fn advisory_unlock(
    conn: &mut PgConnection,
    key: i64,
    unavailable: fn() -> Failure,
) -> Result<bool, Failure> {
    sqlx::query_scalar!(r#"SELECT pg_advisory_unlock($1) AS "released!""#, key)
        .fetch_one(conn)
        .await
        .map_err(|_| unavailable())
}

/// `PostgresRestoreTargetExcluder` — see the module header.
pub struct PostgresRestoreTargetExcluder {
    conn: Arc<BlockingConn>,
}

/// `NewPostgresRestoreTargetExcluder` — binds the dedicated recovery
/// connection. A `None` connection is a composition error, not a
/// target failure.
pub fn new_postgres_restore_target_excluder(
    conn: PgConnection,
) -> Result<PostgresRestoreTargetExcluder, Failure> {
    Ok(PostgresRestoreTargetExcluder {
        conn: Arc::new(BlockingConn::new(conn)?),
    })
}

impl RestoreTargetExcluder for PostgresRestoreTargetExcluder {
    /// `AcquireRestoreTargetExclusion` — `is_resumable`, not a literal
    /// `Applying` comparison: Apply's own prospective operation is
    /// always freshly Applying, but Resume legitimately reacquires
    /// this same exclusion for an operation already at Verifying or
    /// Quarantined — exactly the phases `RestoreCoordinator::resume`
    /// already validated as resumable one line before calling here
    /// (SC-DEF-72).
    fn acquire_restore_target_exclusion(
        &self,
        operation: &RestoreOperation,
    ) -> Result<Box<dyn RestoreTargetExclusion>, Failure> {
        if operation.validate().is_err() || !operation.is_resumable() {
            return Err(restore_target_exclusion_unavailable());
        }
        let keys = [
            SERVE_TARGET_EXCLUSION_LOCK_KEY,
            restore_target_lock_key(&operation.target),
        ];
        let mut acquired = Vec::with_capacity(keys.len());
        for &key in &keys {
            let held = self.conn.run(|c| {
                Box::pin(async move {
                    advisory_try_lock(c, key, restore_target_exclusion_unavailable).await
                })
            })?;
            if !held {
                for &held_key in acquired.iter().rev() {
                    let _ = self.conn.run(|c| {
                        Box::pin(async move {
                            advisory_unlock(c, held_key, restore_target_exclusion_unavailable).await
                        })
                    });
                }
                return Err(restore_target_busy());
            }
            acquired.push(key);
        }
        Ok(Box::new(PostgresRestoreExclusion {
            conn: self.conn.clone(),
            keys: acquired,
            released: Mutex::new(false),
        }))
    }
}

/// `postgresRestoreTargetExclusion`.
struct PostgresRestoreExclusion {
    conn: Arc<BlockingConn>,
    keys: Vec<i64>,
    released: Mutex<bool>,
}

impl RestoreTargetExclusion for PostgresRestoreExclusion {
    /// `AssertHeld` — refuses when the external lease is lost.
    fn assert_held(&self) -> Result<(), Failure> {
        if *self.released.lock().unwrap_or_else(|p| p.into_inner()) {
            return Err(restore_target_exclusion_unavailable());
        }
        for &key in &self.keys {
            let held = self.conn.run(|c| {
                Box::pin(async move {
                    advisory_held(c, key, restore_target_exclusion_unavailable).await
                })
            })?;
            if !held {
                return Err(restore_target_exclusion_unavailable());
            }
        }
        Ok(())
    }

    /// `Release` — the terminal, once-only release.
    fn release(&self) -> Result<(), Failure> {
        let mut released = self.released.lock().unwrap_or_else(|p| p.into_inner());
        if *released {
            return Err(restore_target_exclusion_unavailable());
        }
        for &key in self.keys.iter().rev() {
            let unlocked = self.conn.run(|c| {
                Box::pin(async move {
                    advisory_unlock(c, key, restore_target_exclusion_unavailable).await
                })
            })?;
            if !unlocked {
                return Err(restore_target_exclusion_unavailable());
            }
        }
        *released = true;
        Ok(())
    }
}

/// `PostgresBackupTargetExcluder` — the C01 offline-point lease on one
/// dedicated connection. A pool is intentionally not accepted.
pub struct PostgresBackupTargetExcluder {
    conn: Arc<BlockingConn>,
}

/// `NewPostgresBackupTargetExcluder`.
pub fn new_postgres_backup_target_excluder(
    conn: PgConnection,
) -> Result<PostgresBackupTargetExcluder, Failure> {
    Ok(PostgresBackupTargetExcluder {
        conn: Arc::new(BlockingConn::new(conn)?),
    })
}

impl BackupTargetExcluder for PostgresBackupTargetExcluder {
    /// `AcquireBackupTargetExclusion` — both advisory keys, then the
    /// backend PID, then the accepted-point lock proof binding all of
    /// them to the protocol version.
    fn acquire_backup_target_exclusion(
        &self,
        target: &TargetIdentity,
    ) -> Result<Box<dyn BackupTargetExclusion>, Failure> {
        if !target.is_valid() {
            return Err(backup_target_exclusion_unavailable());
        }
        let keys = [
            SERVE_TARGET_EXCLUSION_LOCK_KEY,
            restore_target_lock_key(target),
        ];
        let mut acquired = Vec::with_capacity(keys.len());
        let release = |conn: &BlockingConn, acquired: &[i64]| {
            for &held_key in acquired.iter().rev() {
                let _ = conn.run(|c| {
                    Box::pin(async move {
                        advisory_unlock(c, held_key, backup_target_exclusion_unavailable).await
                    })
                });
            }
        };
        for &key in &keys {
            let held = self
                .conn
                .run(|c| {
                    Box::pin(async move {
                        advisory_try_lock(c, key, backup_target_exclusion_unavailable).await
                    })
                })
                .map_err(|_| {
                    release(&self.conn, &acquired);
                    backup_target_exclusion_unavailable()
                })?;
            if !held {
                release(&self.conn, &acquired);
                return Err(backup_target_busy());
            }
            acquired.push(key);
        }
        let backend_pid = self
            .conn
            .run(|c| {
                Box::pin(async move {
                    sqlx::query_scalar!(r#"SELECT pg_backend_pid() AS "pid!""#)
                        .fetch_one(c)
                        .await
                        .map_err(|_| backup_target_exclusion_unavailable())
                })
            })
            .map_err(|_| {
                release(&self.conn, &acquired);
                backup_target_exclusion_unavailable()
            })?;
        if backend_pid <= 0 {
            release(&self.conn, &acquired);
            return Err(backup_target_exclusion_unavailable());
        }
        let proof_payload = format!(
            "{}\x00{}\x00{}\x00{}\x00{}\x00{}\x00{}",
            BACKUP_TARGET_LOCK_PROTOCOL,
            target.system_id,
            target.database_oid,
            target.database,
            keys[0],
            keys[1],
            backend_pid
        );
        let digest = Sha256::digest(proof_payload.as_bytes());
        Ok(Box::new(PostgresBackupExclusion {
            conn: self.conn.clone(),
            keys: acquired,
            proof: format!("sha256:{}", super::hex_encode(&digest)),
            state: Mutex::new(ExclusionState::Held),
        }))
    }
}

/// The lease lifecycle: held or released. Upstream also has a
/// `retained` state set inside `RetainForPostReap` once the socket is
/// hijacked; the sqlx retainer can never reach it (see
/// [`BackupTargetLockRetainer::retain_for_post_reap`] below).
#[derive(Clone, Copy, PartialEq, Eq)]
enum ExclusionState {
    Held,
    Released,
}

/// `postgresBackupTargetExclusion`.
struct PostgresBackupExclusion {
    conn: Arc<BlockingConn>,
    keys: Vec<i64>,
    proof: String,
    state: Mutex<ExclusionState>,
}

impl PostgresBackupExclusion {
    fn state(&self) -> ExclusionState {
        *self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn assert_held_locked(&self) -> Result<(), Failure> {
        if self.state() != ExclusionState::Held {
            return Err(backup_target_exclusion_unavailable());
        }
        for &key in &self.keys {
            let held = self.conn.run(|c| {
                Box::pin(
                    async move { advisory_held(c, key, backup_target_exclusion_unavailable).await },
                )
            })?;
            if !held {
                return Err(backup_target_exclusion_unavailable());
            }
        }
        Ok(())
    }
}

impl BackupTargetExclusion for PostgresBackupExclusion {
    /// `AssertHeld` — re-proves the external lease is still owned by
    /// this exact session.
    fn assert_held(&self) -> Result<(), Failure> {
        self.assert_held_locked()
    }

    /// `Release` — ends the lease.
    fn release(&self) -> Result<(), Failure> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if *state != ExclusionState::Held {
            return Err(backup_target_exclusion_unavailable());
        }
        for &key in self.keys.iter().rev() {
            let unlocked = self.conn.run(|c| {
                Box::pin(async move {
                    advisory_unlock(c, key, backup_target_exclusion_unavailable).await
                })
            })?;
            if !unlocked {
                return Err(backup_target_exclusion_unavailable());
            }
        }
        *state = ExclusionState::Released;
        Ok(())
    }

    /// `Proof` — the accepted-point lock proof bound into the
    /// operation's accepted facts.
    fn proof(&self) -> String {
        self.proof.clone()
    }
}

impl BackupTargetLockRetainer for PostgresBackupExclusion {
    /// `RetainForPostReap` — **design gap, carried fail-closed**.
    /// Upstream hijacks the pgx connection's raw TCP socket and hands
    /// a duplicate to the native monitor over SCM_RIGHTS.
    /// `sqlx::PgConnection` exposes no socket descriptor (sqlx owns
    /// the stream end to end), so no honest implementation exists
    /// over this driver — refusing keeps the composition closed
    /// rather than faking a handoff. Tracked under the remaining
    /// T7/T9 composition work.
    fn retain_for_post_reap(
        &self,
        _callback: &mut dyn FnMut(std::os::fd::RawFd, [u8; 32]) -> Result<(), Failure>,
    ) -> Result<(), Failure> {
        Err(backup_target_exclusion_unavailable())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::zero_time;
    use central_backup::backup::operation::BACKUP_DATABASE_SCHEMA_VERSION;
    use central_backup::recovery::operation::{RestoreCheckpoint, RestorePhase};
    use sqlx::Connection as _;
    use uuid::Uuid;

    fn target() -> TargetIdentity {
        TargetIdentity {
            system_id: "system-a".into(),
            database_oid: "42".into(),
            database: "central".into(),
            config_hash: "sha256:config".into(),
            epoch: 1,
        }
    }

    /// A resumable, validated restore operation over `target`.
    fn restore_operation() -> RestoreOperation {
        let now = time::OffsetDateTime::from_unix_timestamp(1_760_000_000).unwrap();
        RestoreOperation {
            operation_id: Uuid::now_v7(),
            ticket_id: Uuid::now_v7(),
            backup_id: Uuid::now_v7(),
            target: target(),
            target_fingerprint: "sha256:".to_owned() + &"ab".repeat(32),
            manifest_digest: "sha256:".to_owned() + &"cd".repeat(32),
            payload_epoch_id: Uuid::now_v7(),
            database_schema_version: BACKUP_DATABASE_SCHEMA_VERSION.into(),
            capacity_evidence_digest: "sha256:".to_owned() + &"ef".repeat(32),
            security_epoch: 2,
            restore_epoch: 1,
            revision: 1,
            phase: RestorePhase::Applying,
            last_checkpoint: RestoreCheckpoint::TicketConsumed,
            authority_reset_receipt_hash: String::new(),
            started_at: now,
            updated_at: now,
            ready_at: zero_time(),
        }
    }

    #[test]
    fn lock_key_stable_per_target_and_separates_targets() {
        let target = target();
        assert_eq!(
            restore_target_lock_key(&target),
            restore_target_lock_key(&target)
        );
        let mut other = target.clone();
        other.database_oid = "43".into();
        assert_ne!(
            restore_target_lock_key(&target),
            restore_target_lock_key(&other)
        );
    }

    /// `CENTRAL_TEST_PG_URL`-gated, exactly like the upstream
    /// integration tests: advisory-lock contention only exists across
    /// real sessions.
    fn test_pg_url() -> Option<String> {
        std::env::var("CENTRAL_TEST_PG_URL")
            .ok()
            .filter(|url| !url.is_empty())
    }

    /// The gated tests share `SERVE_TARGET_EXCLUSION_LOCK_KEY` —
    /// running them in parallel would contended on the same fence.
    static EXCLUSION_GATE: Mutex<()> = Mutex::new(());

    /// A `BlockingConn` whose session was opened on its own reactor —
    /// connecting elsewhere and handing over a `PgConnection` would
    /// leave the socket bound to a dead runtime.
    fn blocking_conn(url: &str) -> BlockingConn {
        let url = url.to_owned();
        BlockingConn::new_connecting(move || {
            let url = url.clone();
            async move {
                PgConnection::connect(&url)
                    .await
                    .map_err(|_| backup_target_exclusion_unavailable())
            }
        })
        .unwrap()
    }

    #[test]
    fn backup_exclusion_excludes_releases_and_retains_fail_closed() {
        let _gate = EXCLUSION_GATE.lock().unwrap();
        let Some(url) = test_pg_url() else {
            eprintln!("CENTRAL_TEST_PG_URL unset; skipping integration test");
            return;
        };
        let owner = PostgresBackupTargetExcluder {
            conn: Arc::new(blocking_conn(&url)),
        };
        let competitor = PostgresBackupTargetExcluder {
            conn: Arc::new(blocking_conn(&url)),
        };
        let target = target();
        let lease = owner.acquire_backup_target_exclusion(&target).unwrap();
        // The proof binds protocol+target+keys+backend PID.
        assert!(lease.proof().starts_with("sha256:"));
        assert_eq!(lease.proof().len(), "sha256:".len() + 64);
        lease.assert_held().unwrap();
        // A competing session contends on the same fence → busy.
        let busy = competitor
            .acquire_backup_target_exclusion(&target)
            .err()
            .unwrap();
        assert_eq!(busy.code(), "backup_target_busy");
        // The post-reap handoff fails closed over sqlx (documented
        // gap) — constructed directly here since the retainer impl
        // lives on the concrete exclusion type.
        let direct = PostgresBackupExclusion {
            conn: Arc::new(blocking_conn(&url)),
            keys: vec![1, 2],
            proof: "sha256:00".into(),
            state: Mutex::new(ExclusionState::Held),
        };
        assert!(
            direct
                .retain_for_post_reap(&mut |_fd, _proof| Ok(()))
                .is_err()
        );
        lease.release().unwrap();
        assert!(lease.assert_held().is_err());
        // The competitor now owns the fence.
        let second = competitor.acquire_backup_target_exclusion(&target).unwrap();
        second.release().unwrap();
    }

    #[test]
    fn restore_exclusion_excludes_and_releases() {
        let _gate = EXCLUSION_GATE.lock().unwrap();
        let Some(url) = test_pg_url() else {
            eprintln!("CENTRAL_TEST_PG_URL unset; skipping integration test");
            return;
        };
        let owner = PostgresRestoreTargetExcluder {
            conn: Arc::new(blocking_conn(&url)),
        };
        let competitor = PostgresRestoreTargetExcluder {
            conn: Arc::new(blocking_conn(&url)),
        };
        let operation = restore_operation();
        let lease = owner.acquire_restore_target_exclusion(&operation).unwrap();
        lease.assert_held().unwrap();
        let busy = competitor
            .acquire_restore_target_exclusion(&operation)
            .err()
            .unwrap();
        assert_eq!(busy.code(), "restore_target_busy");
        lease.release().unwrap();
        assert!(lease.release().is_err());
        let second = competitor
            .acquire_restore_target_exclusion(&operation)
            .unwrap();
        second.release().unwrap();
    }
}
