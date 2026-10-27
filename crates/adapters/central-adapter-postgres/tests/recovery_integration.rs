//! PostgreSQL integration tests for the R6 backup/recovery adapter —
//! the port of upstream `internal/adapter/postgres/backup/`'s
//! database-backed scenarios for the b25–b29 evidence stores
//! (`recovery_operations`, `recovery_quarantines`,
//! `recovery_authority_reset_receipts`,
//! `recovery_bootstrap_registrations`, `prune_log`), plus the
//! `import_verify` and reader smoke checks.
//!
//! Gated on `CENTRAL_TEST_DSN` — a superuser DSN on a scratch cluster
//! whose `central_migration`/`central_runtime` roles exist (passwords
//! `<role>`), the same provisioning contract as
//! `session_store_integration.rs`. Every test provisions its own
//! database owned by `central_migration` and installs the baseline —
//! except the `central`-named-DB reader checks, which follow upstream's
//! shared-schema lifecycle on the fixed `central` database.
//!
//! The stores under test are *synchronous* behind
//! `store_support::BlockingConn`, and `Runtime::block_on` panics inside
//! an ambient runtime — so these are plain `#[test]`s: async
//! provisioning runs on a private runtime, the store calls run on the
//! plain test thread.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::str::FromStr;
use std::sync::Arc;

use central_adapter_postgres::backup::{
    AcceptedFactsReader, CapacityCensusReader, RestoreTargetAdmissionReader,
    TrustedPayloadEpochSource,
};
use central_adapter_postgres::error::classify_sqlx;
use central_adapter_postgres::migrate::{BaselineInstaller, SENTINEL_WORKSPACE_ID};
use central_adapter_postgres::recovery::{
    ImportTableRef, ImportTargetInspector, PruneBatch, PruneCandidate, PruneJournal, PruneLogStore,
    PruneRowState, RecoveryAuditStore,
};
use central_backup::backup::operation::BACKUP_DATABASE_SCHEMA_VERSION;
use central_backup::port::{PostgresAuthorityReset, RestoreQuarantineStore};
use central_backup::recovery::operation::{
    AuthorityResetReceipt, RESTORE_ABANDON_ACKNOWLEDGEMENT, RecoveryBootstrapActivation,
    RecoveryBootstrapDraft, RecoveryBootstrapRegistration, RestoreAbandonAuthorization,
    RestoreOperation, RestorePhase, RestoreTicket, new_restore_operation,
};
use central_backup::recovery::quarantine::{
    QuarantineFinding, QuarantineObservationSource, QuarantineReason, quarantine_source_for,
};
use central_foundation::failure::Failure;
use sha2::{Digest as _, Sha256};
use sqlx::{Connection, PgConnection};
use uuid::Uuid;

type Opts = sqlx::postgres::PgConnectOptions;
type Result<T> = std::result::Result<T, Failure>;

fn admin_opts() -> Option<Opts> {
    let dsn = std::env::var("CENTRAL_TEST_DSN").ok()?;
    Opts::from_str(&dsn).ok()
}

macro_rules! skip {
    () => {
        if admin_opts().is_none() {
            eprintln!("CENTRAL_TEST_DSN unset — skipping PostgreSQL integration test");
            return;
        }
    };
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("test runtime")
}

async fn admin_conn() -> Result<PgConnection> {
    let opts =
        admin_opts().ok_or_else(|| Failure::internal("test_env", "CENTRAL_TEST_DSN unset"))?;
    PgConnection::connect_with(&opts)
        .await
        .map_err(|e| classify_sqlx(&e))
}

async fn migration_conn(db: &str) -> Result<PgConnection> {
    let opts = admin_opts()
        .ok_or_else(|| Failure::internal("test_env", "CENTRAL_TEST_DSN unset"))?
        .database(db)
        .username("central_migration")
        .password("central_migration");
    PgConnection::connect_with(&opts)
        .await
        .map_err(|e| classify_sqlx(&e))
}

async fn runtime_conn(db: &str) -> Result<PgConnection> {
    let opts = admin_opts()
        .ok_or_else(|| Failure::internal("test_env", "CENTRAL_TEST_DSN unset"))?
        .database(db)
        .username("central_runtime")
        .password("central_runtime");
    PgConnection::connect_with(&opts)
        .await
        .map_err(|e| classify_sqlx(&e))
}

/// Provision + baseline + return `(db, central_migration conn)`.
async fn provisioned(label: &str) -> Result<(String, PgConnection)> {
    let mut admin = admin_conn().await?;
    let db = format!("recovery_test_{label}_{}", std::process::id());
    let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS {db} WITH (FORCE)"))
        .execute(&mut admin)
        .await;
    sqlx::query(&format!("CREATE DATABASE {db} OWNER central_migration"))
        .execute(&mut admin)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    let mut mig = migration_conn(&db).await?;
    BaselineInstaller::new()
        .install(&mut mig)
        .await
        .map_err(|e| Failure::internal("test_env", format!("baseline install failed: {e}")))?;
    Ok((db, mig))
}

async fn drop_db(db: &str) {
    if let Ok(mut admin) = admin_conn().await {
        let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS {db} WITH (FORCE)"))
            .execute(&mut admin)
            .await;
    }
}

fn test_sha256(value: &str) -> String {
    format!("sha256:{}", hex(&Sha256::digest(value.as_bytes())))
}

fn sentinel() -> Uuid {
    Uuid::parse_str(SENTINEL_WORKSPACE_ID).expect("sentinel uuid")
}

/// `recoveryAuditOperationWithEpochs` — a fresh `applying`/
/// `ticket_consumed` protected operation with variable epochs.
fn recovery_audit_operation_with_epochs(
    restore_epoch: u64,
    security_epoch: u64,
    seed: &str,
) -> RestoreOperation {
    let now = crate::truncate_test_time(time::OffsetDateTime::now_utc());
    let ticket = RestoreTicket {
        ticket_id: Uuid::now_v7(),
        operation_id: Uuid::now_v7(),
        backup_id: Uuid::now_v7(),
        target: central_backup::domain::TargetIdentity {
            system_id: "system".into(),
            database_oid: "1".into(),
            database: "central".into(),
            config_hash: test_sha256("config"),
            epoch: 7,
        },
        target_fingerprint: test_sha256(&format!("target{seed}")),
        manifest_digest: test_sha256(&format!("manifest{seed}")),
        security_epoch,
        restore_epoch,
        config_fingerprint: test_sha256("configuration"),
        payload_epoch_id: Uuid::now_v7(),
        database_schema_version: BACKUP_DATABASE_SCHEMA_VERSION.into(),
        capacity_evidence_digest: test_sha256("capacity-evidence"),
        tool_version: "pg_restore-16.14".into(),
        hidden_nonce: b"opaque".to_vec(),
        issued_at: now - time::Duration::seconds(1),
        expires_at: now + time::Duration::minutes(1),
        hmac: "broker-owned".into(),
    };
    new_restore_operation(&ticket, now).expect("restore operation fixture")
}

fn truncate_test_time(t: time::OffsetDateTime) -> time::OffsetDateTime {
    let utc = t.to_offset(time::UtcOffset::UTC);
    utc - time::Duration::nanoseconds(i64::from(utc.nanosecond() % 1000))
}

/// `recoveryAuditDraft`.
fn recovery_audit_draft(
    operation: &RestoreOperation,
    receipt_seed: &str,
) -> RecoveryBootstrapDraft {
    RecoveryBootstrapDraft {
        operation_id: operation.operation_id,
        draft_id: Uuid::now_v7(),
        candidate_id: Uuid::now_v7(),
        verifier_hash: Sha256::digest(format!("fresh-verifier-{receipt_seed}").as_bytes()).into(),
        candidate_digest: Sha256::digest(format!("fresh-candidate-{receipt_seed}").as_bytes())
            .into(),
        broker_receipt_hash: test_sha256(receipt_seed),
        created_at: operation.updated_at,
    }
}

/// `recoveryAuditActivation`.
fn recovery_audit_activation(
    registration: &RecoveryBootstrapRegistration,
) -> RecoveryBootstrapActivation {
    RecoveryBootstrapActivation {
        operation_id: registration.operation_id,
        draft_id: registration.draft_id,
        candidate_id: registration.candidate_id,
        generation: registration.generation,
        database_receipt_hash: registration.database_receipt_hash.clone(),
        activation_receipt_hash: test_sha256(&format!("activation-{}", registration.candidate_id)),
        activated_at: registration.registered_at,
    }
}

/// `recoveryAuditProjectInventoryVerified` — drive + project the exact
/// chain to `verifying`/`inventory_verified`.
fn project_inventory_verified(
    store: &RecoveryAuditStore,
    mut operation: RestoreOperation,
) -> RestoreOperation {
    operation.started_at -= time::Duration::seconds(10);
    operation.updated_at -= time::Duration::seconds(10);
    operation = operation
        .record_database_replaced(operation.updated_at + time::Duration::seconds(1))
        .expect("database replaced");
    store
        .project_restore_operation(&operation)
        .expect("project replaced");
    operation = operation
        .begin_verification(operation.updated_at + time::Duration::seconds(1))
        .expect("begin verification");
    store
        .project_restore_operation(&operation)
        .expect("project verifying");
    operation = operation
        .record_inventory_verified(operation.updated_at + time::Duration::seconds(1))
        .expect("inventory verified");
    store
        .project_restore_operation(&operation)
        .expect("project inventory");
    operation
}

/// `recoveryAuditSeedResettableAuthority` — the minimum the reset needs:
/// non-empty marker/workspace censuses + an allocatable sentinel
/// bootstrap generation.
async fn seed_resettable_authority(conn: &mut PgConnection) -> Result<()> {
    let verifier = Sha256::digest(b"seed-verifier").to_vec();
    sqlx::query("UPDATE central.workspaces SET restore_epoch=1, security_epoch=2")
        .execute(&mut *conn)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    sqlx::query("UPDATE central.epoch_markers SET restore_epoch=1, security_epoch=2")
        .execute(&mut *conn)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    sqlx::query(
        "INSERT INTO central.bootstrap_generations
         (id,workspace_id,generation,verifier_hash,state,principal_identity,created_at)
         VALUES ($1::uuid,$2::uuid,1,$3,'active','restored-bootstrap',clock_timestamp())",
    )
    .bind(Uuid::now_v7())
    .bind(sentinel())
    .bind(verifier)
    .execute(&mut *conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// b25–b28: recovery_audit.go parity tests
// ---------------------------------------------------------------------------

#[test]
fn recovery_audit_store_projects_exact_protected_chain() {
    skip!();
    let rt = runtime();
    let (db, mut mig) = rt.block_on(provisioned("chain")).expect("provision");
    let store = RecoveryAuditStore::new(rt.block_on(migration_conn(&db)).expect("migration conn"))
        .expect("audit store");

    let mut operation = recovery_audit_operation_with_epochs(4, 11, "");
    operation.started_at -= time::Duration::seconds(10);
    operation.updated_at -= time::Duration::seconds(10);
    operation = operation
        .record_database_replaced(operation.updated_at + time::Duration::seconds(1))
        .expect("replaced");
    store
        .project_restore_operation(&operation)
        .expect("project replaced");
    store
        .project_restore_operation(&operation)
        .expect("idempotent projection");

    operation = operation
        .begin_verification(operation.updated_at + time::Duration::seconds(1))
        .expect("verify");
    store
        .project_restore_operation(&operation)
        .expect("project verification");

    let expected_checksum: [u8; 32] = Sha256::digest(b"expected-body").into();
    let observed_checksum: [u8; 32] = Sha256::digest(b"observed-body").into();
    let (expected_size, observed_size) = (13i64, 12i64);
    let findings = vec![
        QuarantineFinding {
            quarantine_id: Uuid::now_v7(),
            operation_id: operation.operation_id,
            artifact_id: Uuid::now_v7(),
            reason: QuarantineReason::MissingBody,
            observation_source: QuarantineObservationSource::ObjectPresence,
            expected_checksum: Some(expected_checksum),
            observed_checksum: None,
            expected_size: Some(expected_size),
            observed_size: None,
            created_at: operation.updated_at,
        },
        QuarantineFinding {
            quarantine_id: Uuid::now_v7(),
            operation_id: operation.operation_id,
            artifact_id: Uuid::now_v7(),
            reason: QuarantineReason::ChecksumMismatch,
            observation_source: QuarantineObservationSource::ObjectDigest,
            expected_checksum: Some(expected_checksum),
            observed_checksum: Some(observed_checksum),
            expected_size: None,
            observed_size: None,
            created_at: operation.updated_at,
        },
        QuarantineFinding {
            quarantine_id: Uuid::now_v7(),
            operation_id: operation.operation_id,
            artifact_id: Uuid::now_v7(),
            reason: QuarantineReason::UnexpectedArtifact,
            observation_source: QuarantineObservationSource::RestoredScan,
            expected_checksum: None,
            observed_checksum: Some(observed_checksum),
            expected_size: None,
            observed_size: Some(observed_size),
            created_at: operation.updated_at,
        },
    ];
    assert_eq!(
        store
            .record_quarantine_findings(&operation, &findings)
            .expect("record quarantines"),
        3
    );
    assert_eq!(
        store
            .record_quarantine_findings(&operation, &findings)
            .expect("idempotent quarantines"),
        3
    );
    let mut conflict = findings.clone();
    conflict[0].reason = QuarantineReason::MetadataMismatch;
    conflict[0].observation_source = QuarantineObservationSource::InventoryRow;
    assert!(
        store
            .record_quarantine_findings(&operation, &conflict)
            .is_err(),
        "quarantine store accepted conflicting evidence replay"
    );

    // Every stored row records WHICH comparison observed it.
    for finding in &findings {
        let stored_source: String = rt
            .block_on(async {
                sqlx::query_scalar(
                    "SELECT observation_source FROM central.recovery_quarantines
                     WHERE operation_id=$1 AND artifact_id=$2",
                )
                .bind(operation.operation_id)
                .bind(finding.artifact_id)
                .fetch_one(&mut mig)
                .await
                .map_err(|e| classify_sqlx(&e))
            })
            .expect("read stored observation source");
        let wanted = quarantine_source_for(finding.reason).expect("domain source for reason");
        assert_eq!(
            stored_source,
            wanted.as_str(),
            "the projection stored the wrong observation source"
        );
        assert_eq!(finding.observation_source.as_str(), stored_source);
    }

    operation = operation
        .record_inventory_verified(operation.updated_at + time::Duration::seconds(1))
        .expect("inventory verified");
    store
        .project_restore_operation(&operation)
        .expect("project inventory");
    operation = operation
        .enter_quarantine(operation.updated_at + time::Duration::seconds(1))
        .expect("quarantine");
    store
        .project_restore_operation(&operation)
        .expect("project quarantine");
    assert_eq!(
        store
            .unresolved_quarantine_count(&operation)
            .expect("unresolved"),
        3
    );

    // A complete fresh inventory with no findings resolves the prior
    // open rows via the typed reingest/delete-finalization evidence.
    assert_eq!(
        store
            .record_quarantine_findings(&operation, &[])
            .expect("reconcile"),
        0
    );
    assert_eq!(
        store
            .unresolved_quarantine_count(&operation)
            .expect("resolved count"),
        0
    );
    let (reingested, delete_finalized): (i64, i64) = rt
        .block_on(async {
            sqlx::query_as(
                "SELECT count(*) FILTER (WHERE resolution='reingested'),
                    count(*) FILTER (WHERE resolution='delete_finalized')
                FROM central.recovery_quarantines WHERE operation_id=$1",
            )
            .bind(operation.operation_id)
            .fetch_one(&mut mig)
            .await
            .map_err(|e| classify_sqlx(&e))
        })
        .expect("resolutions");
    assert_eq!((reingested, delete_finalized), (2, 1));

    operation = operation
        .resume_verification(0, operation.updated_at + time::Duration::seconds(2))
        .expect("resume verification");
    store
        .project_restore_operation(&operation)
        .expect("project resumed verification");

    rt.block_on(seed_resettable_authority(&mut mig))
        .expect("seed reset");

    let draft = recovery_audit_draft(&operation, "broker-receipt");
    let registration = store
        .reset_database_authority(&operation, &draft)
        .expect("reset database authority");
    let replay = store
        .reset_database_authority(&operation, &draft)
        .expect("idempotent reset");
    assert_eq!(replay, registration);
    let mut conflicting_draft = draft.clone();
    conflicting_draft.broker_receipt_hash = test_sha256("other-broker-receipt");
    assert!(
        store
            .reset_database_authority(&operation, &conflicting_draft)
            .is_err(),
        "authority reset accepted a conflicting broker receipt replay"
    );

    let activation = recovery_audit_activation(&registration);
    let receipt = store
        .finalize_database_authority_reset(&operation, &registration, &activation)
        .expect("finalize");
    let authority = operation
        .record_authority_reset(&receipt)
        .expect("authority reset");
    store
        .project_restore_operation(&authority)
        .expect("project authority reset");
    let ready = authority
        .mark_ready(authority.updated_at + time::Duration::seconds(1))
        .expect("ready");
    store
        .project_restore_operation(&ready)
        .expect("project ready");

    // A lost final broker CAS leaves PostgreSQL one `ready` revision
    // ahead: re-projecting the exact predecessor replays cleanly.
    store
        .project_restore_operation(&authority)
        .expect("accept final-CAS ambiguity");

    let (revision, phase, checkpoint): (i64, String, String) = rt
        .block_on(async {
            sqlx::query_as(
                "SELECT revision, phase, last_checkpoint FROM central.recovery_operations
                 WHERE operation_id=$1",
            )
            .bind(ready.operation_id)
            .fetch_one(&mut mig)
            .await
            .map_err(|e| classify_sqlx(&e))
        })
        .expect("projected row");
    assert_eq!(revision, ready.revision as i64);
    assert_eq!(phase, "ready");
    assert_eq!(checkpoint, "authority_reset");

    let mut tampered = ready.clone();
    tampered.backup_id = Uuid::now_v7();
    assert!(
        store.project_restore_operation(&tampered).is_err(),
        "recovery audit accepted immutable backup substitution"
    );
    let mut skipped = ready.clone();
    skipped.revision += 2;
    assert!(
        store.project_restore_operation(&skipped).is_err(),
        "recovery audit accepted a skipped revision"
    );

    rt.block_on(drop_db(&db));
}

#[test]
fn recovery_audit_store_projects_abandoned_operation() {
    skip!();
    let rt = runtime();
    let (db, mut mig) = rt.block_on(provisioned("abandon")).expect("provision");
    let store = RecoveryAuditStore::new(rt.block_on(migration_conn(&db)).expect("migration conn"))
        .expect("audit store");

    let mut operation = recovery_audit_operation_with_epochs(4, 11, "");
    operation.started_at -= time::Duration::seconds(10);
    operation.updated_at -= time::Duration::seconds(10);
    operation = operation
        .record_database_replaced(operation.updated_at + time::Duration::seconds(1))
        .expect("replaced");
    store
        .project_restore_operation(&operation)
        .expect("project replaced");

    let authorization = RestoreAbandonAuthorization {
        authorization_id: Uuid::now_v7(),
        operation_id: operation.operation_id,
        issued_at: operation.updated_at + time::Duration::seconds(1),
        expires_at: operation.updated_at + time::Duration::minutes(1),
        acknowledgement: RESTORE_ABANDON_ACKNOWLEDGEMENT.into(),
    };
    let abandoned = operation
        .abandon(
            &authorization,
            operation.updated_at + time::Duration::seconds(2),
        )
        .expect("abandon");
    store
        .project_restore_operation(&abandoned)
        .expect("project abandonment");
    store
        .project_restore_operation(&abandoned)
        .expect("idempotent abandonment projection");

    let (revision, phase, checkpoint, security_epoch): (i64, String, String, i64) = rt
        .block_on(async {
            sqlx::query_as(
                "SELECT revision, phase, last_checkpoint, security_epoch
                 FROM central.recovery_operations WHERE operation_id=$1",
            )
            .bind(abandoned.operation_id)
            .fetch_one(&mut mig)
            .await
            .map_err(|e| classify_sqlx(&e))
        })
        .expect("abandoned row");
    assert_eq!(revision, abandoned.revision as i64);
    assert_eq!(phase, "abandoned");
    assert_eq!(checkpoint, "database_replaced");
    assert_eq!(security_epoch, abandoned.security_epoch as i64);

    // Abandonment is a dead end for this writer.
    let mut resumed = abandoned.clone();
    resumed.revision += 1;
    resumed.phase = RestorePhase::Verifying;
    resumed.updated_at = abandoned.updated_at + time::Duration::seconds(1);
    assert!(
        store.project_restore_operation(&resumed).is_err(),
        "recovery audit accepted a transition out of a projected abandoned row"
    );

    rt.block_on(drop_db(&db));
}

#[test]
fn recovery_audit_store_resets_restored_authority_atomically_and_idempotently() {
    skip!();
    let rt = runtime();
    let (db, mut mig) = rt.block_on(provisioned("reset")).expect("provision");
    let store = RecoveryAuditStore::new(rt.block_on(migration_conn(&db)).expect("migration conn"))
        .expect("audit store");

    let operation =
        project_inventory_verified(&store, recovery_audit_operation_with_epochs(4, 11, ""));

    // Upstream's restored-authority fixtures, verbatim against the Rust
    // schema. This block already carries the reset's minimum (non-empty
    // epoch/workspace censuses + an allocatable sentinel generation), so
    // `seed_resettable_authority` is not called on top of it — its
    // sentinel (workspace,generation=1) row would collide.
    let workspace_id: Uuid = rt
        .block_on(async {
            sqlx::query_scalar("SELECT id FROM central.workspaces ORDER BY id LIMIT 1")
                .fetch_one(&mut mig)
                .await
                .map_err(|e| classify_sqlx(&e))
        })
        .expect("workspace");
    let verifier_hash = Sha256::digest(b"verifier").to_vec();
    let token_hash = Sha256::digest(b"token").to_vec();
    let csrf_hash = Sha256::digest(b"csrf").to_vec();
    let binding_hash = Sha256::digest(b"binding").to_vec();
    let claim_hash = Sha256::digest(b"claim").to_vec();
    let lease_token_hash = Sha256::digest(b"lease").to_vec();
    let recovery_epoch = 7001i64;
    let execution_ownership_id = Uuid::now_v7();
    let task_id = Uuid::now_v7();
    let run_id = Uuid::now_v7();
    let artifact_id = Uuid::now_v7();
    rt.block_on(async {
        sqlx::query("UPDATE central.workspaces SET restore_epoch=1, security_epoch=2")
            .execute(&mut mig)
            .await
            .map_err(|e| classify_sqlx(&e))?;
        sqlx::query("UPDATE central.epoch_markers SET restore_epoch=1, security_epoch=2")
            .execute(&mut mig)
            .await
            .map_err(|e| classify_sqlx(&e))?;
        sqlx::query(
            "INSERT INTO central.bootstrap_generations
             (id,workspace_id,generation,verifier_hash,state,principal_identity,created_at)
             VALUES ($1::uuid,$2::uuid,1,$3,'active','restored-bootstrap',clock_timestamp())",
        )
        .bind(Uuid::now_v7())
        .bind(workspace_id)
        .bind(&verifier_hash)
        .execute(&mut mig)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        sqlx::query(
            "INSERT INTO central.sessions
             (id,workspace_id,token_hash,csrf_hash,principal_identity,lifecycle_state,
              security_epoch,created_at,last_seen_at,idle_expiry,absolute_expiry)
             VALUES ($1::uuid,$2::uuid,$3,$4,'restored-session','active',2,
              clock_timestamp(),clock_timestamp(),
              clock_timestamp()+interval '1 hour',clock_timestamp()+interval '1 day')",
        )
        .bind(Uuid::now_v7())
        .bind(workspace_id)
        .bind(&token_hash)
        .bind(&csrf_hash)
        .execute(&mut mig)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        sqlx::query(
            "INSERT INTO central.approvals
             (id,workspace_id,capability_identity,scope,action,actor_identity,
              authority_identity,reason,state,security_epoch,created_at,updated_at,
              approval_kind,recorded_at)
             VALUES ($1::uuid,$2::uuid,'restored-grant','workspace','grant','restored-actor',
              'restored-authority','restored','active',2,clock_timestamp(),clock_timestamp(),
              'capability',clock_timestamp())",
        )
        .bind(Uuid::now_v7())
        .bind(workspace_id)
        .execute(&mut mig)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        sqlx::query(
            "INSERT INTO central.provider_bindings
             (id,workspace_id,secret_reference,opaque_generation,provider,adapter,model,
              destination,method,path,binding_verifier,created_at)
             VALUES ($1::uuid,$2::uuid,'restored-secret',$3::uuid,'provider','adapter','model',
              'https://provider.invalid','POST','/v1',$4,clock_timestamp())",
        )
        .bind(Uuid::now_v7())
        .bind(workspace_id)
        .bind(Uuid::now_v7())
        .bind(&binding_hash)
        .execute(&mut mig)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        sqlx::query(
            "INSERT INTO central.execution_ownership
             (id,workspace_id,heartbeat_at,lease_token_hash,fencing_generation,
              lease_expires_at,created_at,updated_at)
             VALUES ($1::uuid,$2::uuid,clock_timestamp(),$3,7,
              clock_timestamp()+interval '1 hour',clock_timestamp(),clock_timestamp())",
        )
        .bind(execution_ownership_id)
        .bind(workspace_id)
        .bind(&lease_token_hash)
        .execute(&mut mig)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        sqlx::query(
            "INSERT INTO central.outbox_workspace_work
             (workspace_id,next_visible_at,claim_token_hash,claim_expires_at,version)
             VALUES ($1::uuid,clock_timestamp(),$2,clock_timestamp()+interval '1 hour',7)
             ON CONFLICT (workspace_id) DO UPDATE SET claim_token_hash=EXCLUDED.claim_token_hash,
                claim_expires_at=EXCLUDED.claim_expires_at,version=EXCLUDED.version",
        )
        .bind(workspace_id)
        .bind(&claim_hash)
        .execute(&mut mig)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        sqlx::query(
            "INSERT INTO central.recovery_coordinators
             (recovery_domain,version,instance_id,lease_token_hash,fencing_generation,
              lease_expires_at,state,created_at,updated_at)
             VALUES ('restore-test',7,'restored-coordinator',$1,7,
              clock_timestamp()+interval '1 hour','claimed',clock_timestamp(),clock_timestamp())",
        )
        .bind(&lease_token_hash)
        .execute(&mut mig)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        sqlx::query(
            "INSERT INTO central.recovery_epochs
             (epoch_generation,coordinator_domain,coordinator_fence,state,snapshot_at,
              created_at,updated_at)
             VALUES ($1,'restore-test',7,'open',clock_timestamp(),clock_timestamp(),clock_timestamp())",
        )
        .bind(recovery_epoch)
        .execute(&mut mig)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        sqlx::query(
            "INSERT INTO central.recovery_epoch_workspaces
             (epoch_generation,workspace_id,delivery_state,watermark_created_at,
              watermark_run_id,claim_token_hash,claim_expires_at,created_at,updated_at)
             VALUES ($1,$2::uuid,'claimed',clock_timestamp(),$3::uuid,$4,
              clock_timestamp()+interval '1 hour',clock_timestamp(),clock_timestamp())",
        )
        .bind(recovery_epoch)
        .bind(workspace_id)
        .bind(Uuid::now_v7())
        .bind(&claim_hash)
        .execute(&mut mig)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        sqlx::query(
            "INSERT INTO central.tasks (id,workspace_id,version,status,last_run_index,title,input_spec)
             VALUES ($1::uuid,$2::uuid,1,'running',1,'recovery-claim-fixture','{}'::jsonb)",
        )
        .bind(task_id)
        .bind(workspace_id)
        .execute(&mut mig)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        sqlx::query(
            "INSERT INTO central.runs (id,workspace_id,task_id,version,status,run_index)
             VALUES ($1::uuid,$2::uuid,$3::uuid,1,'running',1)",
        )
        .bind(run_id)
        .bind(workspace_id)
        .bind(task_id)
        .execute(&mut mig)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        sqlx::query(
            "INSERT INTO central.artifacts
             (id,workspace_id,task_id,run_id,version,state,size,staging_generation,
              object_key,sensitivity,disposition,created_at,updated_at)
             VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,1,'reserved',0,$5::uuid,
              'recovery-fixture','restricted','attachment',clock_timestamp(),clock_timestamp())",
        )
        .bind(artifact_id)
        .bind(workspace_id)
        .bind(task_id)
        .bind(run_id)
        .bind(Uuid::now_v7())
        .execute(&mut mig)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        sqlx::query(
            "INSERT INTO central.artifact_reconciliation_claims
             (artifact_id,workspace_id,claim_kind,coordinator_generation,claim_token_hash,
              lease_expires_at,created_at,updated_at)
             VALUES ($1::uuid,$2::uuid,'normal',7,$3,
              clock_timestamp()+interval '1 hour',clock_timestamp(),clock_timestamp())",
        )
        .bind(artifact_id)
        .bind(workspace_id)
        .bind(&claim_hash)
        .execute(&mut mig)
        .await
        .map_err(|e| classify_sqlx(&e))?;
        Ok::<(), Failure>(())
    })
    .expect("seed restored authority");

    let draft = recovery_audit_draft(&operation, "durable-broker-reset");
    let registration = store
        .reset_database_authority(&operation, &draft)
        .expect("reset database authority");
    registration
        .validate_for(&operation, &draft)
        .expect("registration validates");
    assert_eq!(registration.broker_receipt_hash, draft.broker_receipt_hash);
    let replayed = store
        .reset_database_authority(&operation, &draft)
        .expect("idempotent reset");
    assert_eq!(replayed, registration);
    let mut substituted = draft.clone();
    substituted.broker_receipt_hash = test_sha256("substituted-broker-reset");
    assert!(
        store
            .reset_database_authority(&operation, &substituted)
            .is_err(),
        "authority reset accepted a substituted broker receipt"
    );

    let activation = recovery_audit_activation(&registration);
    let receipt = store
        .finalize_database_authority_reset(&operation, &registration, &activation)
        .expect("finalize");
    receipt.validate_for(&operation).expect("receipt validates");

    let (workspace_restore, workspace_security): (i64, i64) = rt
        .block_on(async {
            sqlx::query_as(
                "SELECT restore_epoch,security_epoch FROM central.workspaces WHERE id=$1::uuid",
            )
            .bind(workspace_id)
            .fetch_one(&mut mig)
            .await
            .map_err(|e| classify_sqlx(&e))
        })
        .expect("workspace epochs");
    let (marker_restore, marker_security): (i64, i64) = rt
        .block_on(async {
            sqlx::query_as("SELECT restore_epoch,security_epoch FROM central.epoch_markers ORDER BY id LIMIT 1")
                .fetch_one(&mut mig)
                .await
                .map_err(|e| classify_sqlx(&e))
        })
        .expect("marker epochs");
    let active_sessions: i64 = rt
        .block_on(async {
            sqlx::query_scalar(
                "SELECT count(*) FROM central.sessions
                 WHERE lifecycle_state IN ('pending_bootstrap','delivery_pending','active')",
            )
            .fetch_one(&mut mig)
            .await
            .map_err(|e| classify_sqlx(&e))
        })
        .expect("sessions");
    let active_bootstrap: i64 = rt
        .block_on(async {
            sqlx::query_scalar(
                "SELECT count(*) FROM central.bootstrap_generations WHERE state='active'",
            )
            .fetch_one(&mut mig)
            .await
            .map_err(|e| classify_sqlx(&e))
        })
        .expect("bootstraps");
    let active_approvals: i64 = rt
        .block_on(async {
            sqlx::query_scalar("SELECT count(*) FROM central.approvals WHERE state='active'")
                .fetch_one(&mut mig)
                .await
                .map_err(|e| classify_sqlx(&e))
        })
        .expect("approvals");
    let active_bindings: i64 = rt
        .block_on(async {
            sqlx::query_scalar(
                "SELECT count(*) FROM central.provider_bindings WHERE revoked_at IS NULL",
            )
            .fetch_one(&mut mig)
            .await
            .map_err(|e| classify_sqlx(&e))
        })
        .expect("bindings");
    assert_eq!(workspace_restore, operation.restore_epoch as i64);
    assert_eq!(marker_restore, operation.restore_epoch as i64);
    assert_eq!(workspace_security, operation.security_epoch as i64 + 1);
    assert_eq!(marker_security, operation.security_epoch as i64 + 1);
    assert_eq!(active_sessions, 0);
    assert_eq!(active_bootstrap, 1);
    assert_eq!(active_approvals, 0);
    assert_eq!(active_bindings, 0);

    let (execution_fence, execution_expiry): (i64, time::OffsetDateTime) = rt
        .block_on(async {
            sqlx::query_as(
                "SELECT fencing_generation,lease_expires_at FROM central.execution_ownership
                 WHERE id=$1::uuid",
            )
            .bind(execution_ownership_id)
            .fetch_one(&mut mig)
            .await
            .map_err(|e| classify_sqlx(&e))
        })
        .expect("execution ownership");
    let (coordinator_state, coordinator_fence, coordinator_version, coordinator_expiry): (
        String,
        i64,
        i64,
        time::OffsetDateTime,
    ) = rt
        .block_on(async {
            sqlx::query_as(
                "SELECT state,fencing_generation,version,lease_expires_at
                 FROM central.recovery_coordinators WHERE recovery_domain='restore-test'",
            )
            .fetch_one(&mut mig)
            .await
            .map_err(|e| classify_sqlx(&e))
        })
        .expect("coordinator");
    let workspace_claim_expiry: time::OffsetDateTime = rt
        .block_on(async {
            sqlx::query_scalar(
                "SELECT claim_expires_at FROM central.recovery_epoch_workspaces
                 WHERE epoch_generation=7001",
            )
            .fetch_one(&mut mig)
            .await
            .map_err(|e| classify_sqlx(&e))
        })
        .expect("workspace claim");
    let artifact_claim_expiry: time::OffsetDateTime = rt
        .block_on(async {
            sqlx::query_scalar(
                "SELECT lease_expires_at FROM central.artifact_reconciliation_claims LIMIT 1",
            )
            .fetch_one(&mut mig)
            .await
            .map_err(|e| classify_sqlx(&e))
        })
        .expect("artifact claim");
    let (outbox_claim_expiry, outbox_version): (time::OffsetDateTime, i64) = rt
        .block_on(async {
            sqlx::query_as(
                "SELECT claim_expires_at,version FROM central.outbox_workspace_work
                 WHERE workspace_id=$1::uuid",
            )
            .bind(workspace_id)
            .fetch_one(&mut mig)
            .await
            .map_err(|e| classify_sqlx(&e))
        })
        .expect("outbox work");
    assert_eq!(execution_fence, 8);
    assert_eq!(coordinator_state, "expired");
    assert_eq!(coordinator_fence, 8);
    assert_eq!(coordinator_version, 8);
    assert_eq!(outbox_version, 8);
    assert!(execution_expiry <= receipt.completed_at);
    assert!(coordinator_expiry <= receipt.completed_at);
    assert!(workspace_claim_expiry <= receipt.completed_at);
    assert!(artifact_claim_expiry <= receipt.completed_at);
    assert!(outbox_claim_expiry <= receipt.completed_at);

    rt.block_on(drop_db(&db));
}

#[test]
fn finalize_database_authority_reset_replays_the_stored_receipt() {
    skip!();
    let rt = runtime();
    let (db, mut mig) = rt.block_on(provisioned("replay")).expect("provision");
    let store = RecoveryAuditStore::new(rt.block_on(migration_conn(&db)).expect("migration conn"))
        .expect("audit store");
    rt.block_on(seed_resettable_authority(&mut mig))
        .expect("seed reset");
    let operation =
        project_inventory_verified(&store, recovery_audit_operation_with_epochs(4, 11, ""));

    let draft = recovery_audit_draft(&operation, "replayed-broker-reset");
    let registration = store
        .reset_database_authority(&operation, &draft)
        .expect("reset");
    let activation = recovery_audit_activation(&registration);
    let first: AuthorityResetReceipt = store
        .finalize_database_authority_reset(&operation, &registration, &activation)
        .expect("first finalization");
    first.validate_for(&operation).expect("first validates");

    // Prove the database clock has moved strictly past the stored
    // completion before replaying.
    let mut clock_before_replay = rt
        .block_on(async {
            sqlx::query_scalar::<_, time::OffsetDateTime>("SELECT clock_timestamp()")
                .fetch_one(&mut mig)
                .await
                .map_err(|e| classify_sqlx(&e))
        })
        .expect("clock");
    for _ in 0..100 {
        if clock_before_replay > first.completed_at {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
        clock_before_replay = rt
            .block_on(async {
                sqlx::query_scalar::<_, time::OffsetDateTime>("SELECT clock_timestamp()")
                    .fetch_one(&mut mig)
                    .await
                    .map_err(|e| classify_sqlx(&e))
            })
            .expect("clock");
    }
    assert!(
        clock_before_replay > first.completed_at,
        "database clock never advanced past the stored completion"
    );

    let second = store
        .finalize_database_authority_reset(&operation, &registration, &activation)
        .expect("replayed finalization");
    assert_eq!(second.completed_at, first.completed_at);
    assert_eq!(second.aggregate_receipt_hash, first.aggregate_receipt_hash);
    assert_eq!(second, first);

    // The replay wrote no second row and rewrote nothing.
    let stored: i64 = rt
        .block_on(async {
            sqlx::query_scalar(
                "SELECT count(*) FROM central.recovery_authority_reset_receipts
                 WHERE operation_id=$1::uuid",
            )
            .bind(operation.operation_id)
            .fetch_one(&mut mig)
            .await
            .map_err(|e| classify_sqlx(&e))
        })
        .expect("receipt count");
    let (stored_completion, stored_aggregate): (time::OffsetDateTime, Vec<u8>) = rt
        .block_on(async {
            sqlx::query_as(
                "SELECT completed_at, aggregate_receipt_hash
                 FROM central.recovery_authority_reset_receipts
                 WHERE operation_id=$1::uuid",
            )
            .bind(operation.operation_id)
            .fetch_one(&mut mig)
            .await
            .map_err(|e| classify_sqlx(&e))
        })
        .expect("stored receipt");
    assert_eq!(stored, 1);
    assert_eq!(stored_completion, first.completed_at);
    assert_eq!(
        format!("sha256:{}", hex(&stored_aggregate)),
        first.aggregate_receipt_hash
    );

    // A replay with genuinely different inputs must still be refused.
    let mut substituted_activation = activation.clone();
    substituted_activation.activation_receipt_hash = test_sha256("substituted-activation");
    assert!(
        store
            .finalize_database_authority_reset(&operation, &registration, &substituted_activation)
            .is_err(),
        "finalization accepted a substituted activation receipt on replay"
    );

    rt.block_on(drop_db(&db));
}

#[test]
fn finalize_database_authority_reset_keeps_distinct_operations_distinct() {
    skip!();
    let rt = runtime();
    let (db, mut mig) = rt.block_on(provisioned("distinct")).expect("provision");
    let store = RecoveryAuditStore::new(rt.block_on(migration_conn(&db)).expect("migration conn"))
        .expect("audit store");
    rt.block_on(seed_resettable_authority(&mut mig))
        .expect("seed reset");

    let finalize = |operation: RestoreOperation,
                    seed: &str|
     -> (
        RestoreOperation,
        RecoveryBootstrapRegistration,
        AuthorityResetReceipt,
    ) {
        let operation = project_inventory_verified(&store, operation);
        let draft = recovery_audit_draft(&operation, seed);
        let registration = store
            .reset_database_authority(&operation, &draft)
            .expect("reset");
        let receipt = store
            .finalize_database_authority_reset(
                &operation,
                &registration,
                &recovery_audit_activation(&registration),
            )
            .expect("finalize");
        (operation, registration, receipt)
    };
    let stored_row =
        |operation_id: Uuid, mig: &mut PgConnection| -> (time::OffsetDateTime, String) {
            rt.block_on(async {
                sqlx::query_as::<_, (time::OffsetDateTime, Vec<u8>)>(
                    "SELECT completed_at, aggregate_receipt_hash
                 FROM central.recovery_authority_reset_receipts
                 WHERE operation_id=$1::uuid",
                )
                .bind(operation_id)
                .fetch_one(&mut *mig)
                .await
                .map(|(at, hash)| (at, format!("sha256:{}", hex(&hash))))
                .map_err(|e| classify_sqlx(&e))
            })
            .expect("stored row")
        };

    let (first_operation, first_registration, first_receipt) = finalize(
        recovery_audit_operation_with_epochs(4, 11, "-first"),
        "first-broker-reset",
    );
    let (first_completion, first_aggregate) = stored_row(first_operation.operation_id, &mut mig);
    assert_eq!(first_completion, first_receipt.completed_at);
    assert_eq!(first_aggregate, first_receipt.aggregate_receipt_hash);

    let (second_operation, _second_registration, second_receipt) = finalize(
        recovery_audit_operation_with_epochs(5, 12, "-second"),
        "second-broker-reset",
    );
    assert_ne!(first_operation.operation_id, second_operation.operation_id);
    assert_ne!(
        first_receipt.aggregate_receipt_hash,
        second_receipt.aggregate_receipt_hash
    );
    let (after_completion, after_aggregate) = stored_row(first_operation.operation_id, &mut mig);
    assert_eq!(after_completion, first_completion);
    assert_eq!(after_aggregate, first_aggregate);
    let (second_completion, second_aggregate) = stored_row(second_operation.operation_id, &mut mig);
    assert_eq!(second_completion, second_receipt.completed_at);
    assert_eq!(second_aggregate, second_receipt.aggregate_receipt_hash);

    // Cross-wiring one operation's finalization onto the other's
    // registration must be refused.
    assert!(
        store
            .finalize_database_authority_reset(
                &second_operation,
                &first_registration,
                &recovery_audit_activation(&first_registration),
            )
            .is_err(),
        "finalization accepted another operation's registration"
    );

    let rows: i64 = rt
        .block_on(async {
            sqlx::query_scalar("SELECT count(*) FROM central.recovery_authority_reset_receipts")
                .fetch_one(&mut mig)
                .await
                .map_err(|e| classify_sqlx(&e))
        })
        .expect("row count");
    assert_eq!(rows, 2);

    rt.block_on(drop_db(&db));
}

// ---------------------------------------------------------------------------
// b29: prune_log journal — crash-resume semantics (upstream ships no
// production PruneJournal; these exercise the domain contract directly).
// ---------------------------------------------------------------------------

/// Seed a `ready` artifact + task + run the prune engine may settle.
async fn seed_ready_artifact(
    conn: &mut PgConnection,
    artifact_id: Uuid,
    workspace_id: Uuid,
) -> Result<()> {
    let task_id = Uuid::now_v7();
    let run_id = Uuid::now_v7();
    let generation = Uuid::now_v7();
    let checksum = Sha256::digest(format!("body-{artifact_id}").as_bytes()).to_vec();
    sqlx::query(
        "INSERT INTO central.tasks (id,workspace_id,version,status,last_run_index,title,input_spec)
         VALUES ($1::uuid,$2::uuid,1,'running',1,'prune-fixture','{}'::jsonb)",
    )
    .bind(task_id)
    .bind(workspace_id)
    .execute(&mut *conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    sqlx::query(
        "INSERT INTO central.runs (id,workspace_id,task_id,version,status,run_index)
         VALUES ($1::uuid,$2::uuid,$3::uuid,1,'running',1)",
    )
    .bind(run_id)
    .bind(workspace_id)
    .bind(task_id)
    .execute(&mut *conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    sqlx::query(
        "INSERT INTO central.artifacts
         (id,workspace_id,task_id,run_id,version,state,size,staging_generation,
          object_key,checksum_algorithm,checksum_value,sensitivity,disposition,
          content_generation,ready_key,created_at,updated_at,ready_at)
         VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,1,'ready',64,$5::uuid,
          $6,'sha256',$7,'restricted','attachment',$8::uuid,$9,
          clock_timestamp(),clock_timestamp(),clock_timestamp())",
    )
    .bind(artifact_id)
    .bind(workspace_id)
    .bind(task_id)
    .bind(run_id)
    .bind(generation)
    .bind(format!(
        "v1/ready/{workspace_id}/{artifact_id}/{generation}"
    ))
    .bind(checksum)
    .bind(generation)
    .bind(format!(
        "v1/ready/{workspace_id}/{artifact_id}/{generation}"
    ))
    .execute(&mut *conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    Ok(())
}

#[test]
fn prune_log_journal_crash_resume() {
    skip!();
    let rt = runtime();
    let (db, mut mig) = rt.block_on(provisioned("prune")).expect("provision");
    let store = PruneLogStore::new(rt.block_on(migration_conn(&db)).expect("migration conn"))
        .expect("prune store");

    let workspace_id: Uuid = rt
        .block_on(async {
            sqlx::query_scalar("SELECT id FROM central.workspaces ORDER BY id LIMIT 1")
                .fetch_one(&mut mig)
                .await
                .map_err(|e| classify_sqlx(&e))
        })
        .expect("workspace");
    let artifact_id = Uuid::now_v7();
    rt.block_on(seed_ready_artifact(&mut mig, artifact_id, workspace_id))
        .expect("seed artifact");
    let staging_generation: Uuid = rt
        .block_on(async {
            sqlx::query_scalar("SELECT staging_generation FROM central.artifacts WHERE id=$1::uuid")
                .bind(artifact_id)
                .fetch_one(&mut mig)
                .await
                .map_err(|e| classify_sqlx(&e))
        })
        .expect("staging gen");
    let plan_id = Uuid::now_v7();
    let batch = PruneBatch {
        plan_id,
        batch_seq: 0,
        bodies: vec![PruneCandidate {
            artifact_id,
            workspace_id,
            object_key: format!("v1/ready/{workspace_id}/{artifact_id}/{staging_generation}"),
            staging_generation,
            size: 64,
            retention_age_days: 45,
            reference_count: 0,
        }],
    };

    // Nothing journaled yet.
    assert!(store.batch_states(plan_id).expect("states").is_empty());
    assert!(
        !store
            .has_tombstone(workspace_id, artifact_id)
            .expect("tombstone")
    );

    // Mark applying — idempotent replay must not resurrect later states.
    store.mark_batch_applying(&batch).expect("mark applying");
    store
        .mark_batch_applying(&batch)
        .expect("mark applying replay");
    assert_eq!(
        store.batch_states(plan_id).expect("states").get(&0),
        Some(&PruneRowState::Applying)
    );

    // Crash-resume replay: settle the body, then prove a second call is
    // a no-op (the tombstone is durable).
    let tombstone_id = Uuid::now_v7();
    store
        .record_body_deleted(&batch, &batch.bodies[0], tombstone_id)
        .expect("settle body");
    assert!(
        store
            .has_tombstone(workspace_id, artifact_id)
            .expect("tombstone")
    );
    store
        .record_body_deleted(&batch, &batch.bodies[0], tombstone_id)
        .expect("settle replay");
    let state: String = rt
        .block_on(async {
            sqlx::query_scalar("SELECT state FROM central.artifacts WHERE id=$1::uuid")
                .bind(artifact_id)
                .fetch_one(&mut mig)
                .await
                .map_err(|e| classify_sqlx(&e))
        })
        .expect("artifact state");
    assert_eq!(state, "deleted");
    let deletion_reason: String = rt
        .block_on(async {
            sqlx::query_scalar(
                "SELECT deletion_reason FROM central.artifact_tombstones
                 WHERE workspace_id=$1::uuid AND artifact_id=$2::uuid",
            )
            .bind(workspace_id)
            .bind(artifact_id)
            .fetch_one(&mut mig)
            .await
            .map_err(|e| classify_sqlx(&e))
        })
        .expect("tombstone reason");
    assert_eq!(deletion_reason, "pruned");

    // A replayed mark-applying on the now-settled batch still must not
    // resurrect `done`, and the batch closes.
    store
        .mark_batch_applying(&batch)
        .expect("post-settle applying replay");
    store.mark_batch_done(plan_id, 0).expect("mark done");
    assert_eq!(
        store.batch_states(plan_id).expect("states").get(&0),
        Some(&PruneRowState::Done)
    );
    store.mark_batch_done(plan_id, 0).expect("done replay");
    store
        .mark_batch_applying(&batch)
        .expect("post-done applying replay");
    assert_eq!(
        store.batch_states(plan_id).expect("states").get(&0),
        Some(&PruneRowState::Done),
        "a done batch was resurrected"
    );

    rt.block_on(drop_db(&db));
}

// ---------------------------------------------------------------------------
// import_verify.go — the post-restore shape checks.
// ---------------------------------------------------------------------------

#[test]
fn import_target_inspector_lists_ready_rows_and_verifies_shape() {
    skip!();
    let rt = runtime();
    let (db, mut mig) = rt.block_on(provisioned("import")).expect("provision");
    let inspector =
        ImportTargetInspector::new(rt.block_on(runtime_conn(&db)).expect("runtime conn"))
            .expect("inspector");

    let workspace_id: Uuid = rt
        .block_on(async {
            sqlx::query_scalar("SELECT id FROM central.workspaces ORDER BY id LIMIT 1")
                .fetch_one(&mut mig)
                .await
                .map_err(|e| classify_sqlx(&e))
        })
        .expect("workspace");
    let artifact_id = Uuid::now_v7();
    rt.block_on(seed_ready_artifact(&mut mig, artifact_id, workspace_id))
        .expect("seed artifact");

    let ready = inspector.list_ready_artifacts().expect("list ready");
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].artifact_id, artifact_id);
    assert_eq!(ready[0].size, 64);
    assert!(
        ready[0]
            .ready_key
            .starts_with(&format!("v1/ready/{workspace_id}/{artifact_id}/")),
        "ready key = {}",
        ready[0].ready_key
    );

    // The dump TOC names real tables; a missing one refuses.
    let (checksum, count) = inspector
        .verify_target_shape(&[
            ImportTableRef {
                schema: "central".into(),
                name: "artifacts".into(),
            },
            ImportTableRef {
                schema: "central".into(),
                name: "workspaces".into(),
            },
        ])
        .expect("shape");
    assert_eq!(count, 2);
    assert_eq!(checksum.len(), 64);
    assert!(
        inspector
            .verify_target_shape(&[ImportTableRef {
                schema: "central".into(),
                name: "no_such_table".into(),
            }])
            .is_err(),
        "a missing table passed the shape check"
    );
    // An empty table list is refused, never vacuously accepted.
    assert!(inspector.verify_target_shape(&[]).is_err());
    // A hostile identifier can fail the import, never escape it.
    assert!(
        inspector
            .verify_target_shape(&[ImportTableRef {
                schema: "central".into(),
                name: "artifacts; DROP TABLE central.artifacts; --".into(),
            }])
            .is_err(),
        "a hostile identifier must fail the probe, not escape it"
    );

    rt.block_on(drop_db(&db));
}

// ---------------------------------------------------------------------------
// The `central`-database readers — `current_database()='central'` is a hard
// boundary check, so these follow upstream's shared-schema lifecycle on the
// fixed `central` database rather than a per-test database.
// ---------------------------------------------------------------------------

struct FixturePayloadEpoch(Uuid);

impl TrustedPayloadEpochSource for FixturePayloadEpoch {
    fn active_payload_epoch_id(&self) -> Result<Uuid> {
        Ok(self.0)
    }
}

#[test]
fn readers_bind_the_fixed_central_database() {
    skip!();
    let rt = runtime();
    // Upstream `setupRecoveryAuditDatabase`: drop + reinstall the shared
    // `central` schema inside the fixed `central` database. The
    // migration authority owns the database — the same ownership the
    // provisioner gives every scratch database — otherwise the baseline
    // replay has no privilege to (re)create the schema.
    rt.block_on(async {
        let mut admin = admin_conn().await?;
        sqlx::query("ALTER DATABASE central OWNER TO central_migration")
            .execute(&mut admin)
            .await
            .map_err(|e| classify_sqlx(&e))?;
        Ok::<(), Failure>(())
    })
    .expect("central ownership");
    let mut mig = rt
        .block_on(async {
            let mut conn = migration_conn("central").await?;
            sqlx::query("DROP SCHEMA IF EXISTS central CASCADE")
                .execute(&mut conn)
                .await
                .map_err(|e| classify_sqlx(&e))?;
            BaselineInstaller::new()
                .install(&mut conn)
                .await
                .map_err(|e| Failure::internal("test_env", format!("baseline: {e}")))?;
            Ok::<_, Failure>(conn)
        })
        .expect("central baseline");

    let payload_epoch = Arc::new(FixturePayloadEpoch(Uuid::now_v7()));
    let facts = AcceptedFactsReader::new(
        rt.block_on(runtime_conn("central")).expect("runtime conn"),
        payload_epoch.clone(),
    )
    .expect("facts reader");
    let target = facts.read_backup_target().expect("read target");
    assert_eq!(target.database, "central");
    assert!(!target.system_id.trim().is_empty());
    assert!(target.is_valid());

    let census =
        CapacityCensusReader::new(rt.block_on(runtime_conn("central")).expect("runtime conn"))
            .expect("census reader");
    let snapshot = census.read_backup_capacity().expect("census");
    assert!(snapshot.database_time > time::OffsetDateTime::UNIX_EPOCH);
    assert!(snapshot.database_bytes > 0);

    let admission = RestoreTargetAdmissionReader::new(
        rt.block_on(runtime_conn("central")).expect("runtime conn"),
        payload_epoch,
    )
    .expect("admission reader");
    let evidence = admission
        .read_restore_target_admission(Uuid::now_v7())
        .expect("admission");
    assert_eq!(evidence.target.database, "central");

    // Restore the shared target to an installed, not merely dropped,
    // state — upstream's cleanup contract for sibling packages.
    rt.block_on(async {
        sqlx::query("DROP SCHEMA IF EXISTS central CASCADE")
            .execute(&mut mig)
            .await
            .map_err(|e| classify_sqlx(&e))?;
        BaselineInstaller::new()
            .install(&mut mig)
            .await
            .map_err(|e| Failure::internal("test_env", format!("baseline: {e}")))?;
        Ok::<(), Failure>(())
    })
    .expect("reinstall");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
