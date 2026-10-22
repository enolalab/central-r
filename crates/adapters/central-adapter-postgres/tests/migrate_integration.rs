//! PostgreSQL integration tests for the native migration engine.
//!
//! Gated on `CENTRAL_TEST_DSN` — a superuser DSN on a scratch cluster whose
//! `central_migration`, `central_runtime`, and `central_outbox` roles exist
//! (passwords `<role>`), as provisioned by the local-init SQL:
//!
//! ```sh
//! CENTRAL_TEST_DSN='postgresql://postgres:central@localhost:55432/postgres' \
//!   cargo test -p central-adapter-postgres --test migrate_integration
//! ```
//!
//! Every test provisions its own database owned by `central_migration`, so
//! the suite is parallel-safe and leaves no shared state.

use central_adapter_postgres::error::classify_sqlx;
use central_adapter_postgres::migrate::{
    BaselineInstaller, BrokerProofService, CommitUpRequest, Inspector,
    IssueEmptyTargetProofRequest, IssueResetConfirmationRequest, MIGRATIONS, PrepareUpRequest,
    ResetConfirmation, ResetRequest, ResetRunner, Result, ResumeRequest, Runner, SessionBinding,
    TargetIdentity, VerifiedEmptyTarget, WITHOUT_V15_CHAIN, reapply_runtime_grants,
};
use central_foundation::failure::{Failure, FailureKind};
use sqlx::{Connection, PgConnection, Row};
use std::str::FromStr;
use std::sync::Arc;

type Opts = sqlx::postgres::PgConnectOptions;

fn admin_opts() -> Option<Opts> {
    let dsn = std::env::var("CENTRAL_TEST_DSN").ok()?;
    Opts::from_str(&dsn).ok()
}

macro_rules! skip {
    () => {
        if admin_opts().is_none() {
            eprintln!("CENTRAL_TEST_DSN unset — skipping PostgreSQL integration test");
            return Ok(());
        }
    };
}

fn require_opts() -> Result<Opts> {
    admin_opts().ok_or_else(|| Failure::internal("test_env", "CENTRAL_TEST_DSN unset"))
}

async fn admin_conn() -> Result<PgConnection> {
    PgConnection::connect_with(&require_opts()?)
        .await
        .map_err(|e| classify_sqlx(&e))
}

async fn role_conn(db: &str, role: &str) -> Result<PgConnection> {
    let opts = require_opts()?.database(db).username(role).password(role);
    PgConnection::connect_with(&opts)
        .await
        .map_err(|e| classify_sqlx(&e))
}

async fn provision(admin: &mut PgConnection, label: &str) -> Result<String> {
    let db = format!("migrate_test_{label}_{}", std::process::id());
    let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS {db}"))
        .execute(&mut *admin)
        .await;
    sqlx::query(&format!("CREATE DATABASE {db} OWNER central_migration"))
        .execute(&mut *admin)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    Ok(db)
}

async fn drop_db(admin: &mut PgConnection, db: &str) {
    let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS {db}"))
        .execute(&mut *admin)
        .await;
}

fn sanitize(err: &sqlx::Error) -> Failure {
    classify_sqlx(err)
}

/// Record broker — every consume-verified call is recorded then succeeds
/// (the upstream fake's contract).
#[derive(Debug, Default)]
struct FakeBroker {
    consumed_empty: std::sync::Mutex<Vec<String>>,
    consumed_reset: std::sync::Mutex<Vec<String>>,
}

impl BrokerProofService for FakeBroker {
    async fn issue_empty_target_proof(
        &self,
        _req: IssueEmptyTargetProofRequest,
    ) -> Result<VerifiedEmptyTarget> {
        Err(Failure::internal("fake_not_implemented", "fake broker"))
    }
    async fn verify_empty_target(
        &self,
        _target: &TargetIdentity,
        _proof: &VerifiedEmptyTarget,
    ) -> Result<()> {
        Ok(())
    }
    async fn consume_empty_proof(&self, _proof: VerifiedEmptyTarget) -> Result<()> {
        Ok(())
    }
    async fn consume_verified_empty_target(
        &self,
        target: &TargetIdentity,
        proof: VerifiedEmptyTarget,
    ) -> Result<()> {
        if let Ok(mut guard) = self.consumed_empty.lock() {
            guard.push(format!("{}:{}", target.database, proof.operation_id));
        }
        Ok(())
    }
    async fn issue_reset_confirmation(
        &self,
        _req: IssueResetConfirmationRequest,
    ) -> Result<ResetConfirmation> {
        Err(Failure::internal("fake_not_implemented", "fake broker"))
    }
    async fn verify_reset_confirmation(&self, _confirmation: &ResetConfirmation) -> Result<()> {
        Ok(())
    }
    async fn consume_reset_confirmation(&self, _confirmation: ResetConfirmation) -> Result<()> {
        Ok(())
    }
    async fn consume_verified_reset_confirmation(
        &self,
        target: &TargetIdentity,
        confirmation: ResetConfirmation,
    ) -> Result<()> {
        if let Ok(mut guard) = self.consumed_reset.lock() {
            guard.push(format!("{}:{}", target.database, confirmation.operation_id));
        }
        Ok(())
    }
}

fn target(db: &str) -> TargetIdentity {
    TargetIdentity {
        system_id: "test-system".to_owned(),
        database_oid: String::new(),
        database: db.to_owned(),
        config_hash: "test-config".to_owned(),
        epoch: 0,
    }
}

fn empty_proof(operation_id: uuid::Uuid, binding: SessionBinding) -> VerifiedEmptyTarget {
    VerifiedEmptyTarget {
        operation_id,
        session_binding: binding,
        empty_fingerprint: "fingerprint".to_owned(),
        baseline_digest: "digest".to_owned(),
        issued_at: time::OffsetDateTime::UNIX_EPOCH,
        expires_at: time::OffsetDateTime::UNIX_EPOCH,
        hmac: "hmac".to_owned(),
    }
}

// ---------------------------------------------------------------------------
// Pure-unit coverage required by the brief (no database needed).
// ---------------------------------------------------------------------------

#[test]
fn test_baseline_manifest_targets_latest_applied_migration_through_b37() {
    let manifest = BaselineInstaller::new().baseline_manifest();
    assert_eq!(manifest.version, 37);
    for (_, checksum) in WITHOUT_V15_CHAIN {
        assert_eq!(
            manifest.checksums.get(*checksum).map(String::as_str),
            Some(*checksum)
        );
    }
    assert!(manifest.checksums.len() >= 30);
    assert!(
        manifest
            .checksums
            .contains_key("b10-artifact-lifecycle-forward-correction")
    );
}

#[test]
fn migration_corpus_reaches_v37() {
    assert_eq!(MIGRATIONS.len(), 30);
    assert_eq!(MIGRATIONS.last().map(|m| m.version), Some(37));
}

// ---------------------------------------------------------------------------
// PostgreSQL-backed coverage.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_baseline_install_produces_exact_migration_chain_through_v37()
-> std::result::Result<(), Failure> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = provision(&mut admin, "chain").await?;
    let result = async {
        let mut conn = role_conn(&db, "central_migration").await?;
        BaselineInstaller::new().install(&mut conn).await?;
        let mut inspector = Inspector::for_connection(&mut conn);
        let facts = inspector.inspect().await?;
        assert!(facts.initialized);
        assert!(facts.dirty.is_none());
        let applied: Vec<(i64, &str)> = facts
            .applied_versions
            .iter()
            .map(|v| (i64::from(v.version), v.checksum.as_str()))
            .collect();
        assert_eq!(applied, WITHOUT_V15_CHAIN.to_vec());
        Ok(())
    }
    .await;
    drop_db(&mut admin, &db).await;
    result
}

#[tokio::test]
async fn test_baseline_install_idempotent() -> std::result::Result<(), Failure> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = provision(&mut admin, "idem").await?;
    let result = async {
        let mut conn = role_conn(&db, "central_migration").await?;
        let installer = BaselineInstaller::new();
        installer.install(&mut conn).await?;
        installer.install(&mut conn).await?; // converges cleanly
        installer.verify_shape(&mut conn).await?;
        Ok(())
    }
    .await;
    drop_db(&mut admin, &db).await;
    result
}

#[tokio::test]
async fn test_verify_stock_target_rejects_central() -> std::result::Result<(), Failure> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = provision(&mut admin, "stock").await?;
    let result = async {
        let mut conn = role_conn(&db, "central_migration").await?;
        let installer = BaselineInstaller::new();
        installer.verify_stock_target(&mut conn).await?;
        installer.install(&mut conn).await?;
        let err = installer.verify_stock_target(&mut conn).await;
        assert_eq!(
            err.err().map(|e| e.code().to_owned()),
            Some("baseline_schema_exists".to_owned())
        );
        Ok(())
    }
    .await;
    drop_db(&mut admin, &db).await;
    result
}

#[tokio::test]
async fn test_runner_prepare_commit_up() -> std::result::Result<(), Failure> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = provision(&mut admin, "runner").await?;
    let result = async {
        let mut conn = role_conn(&db, "central_migration").await?;
        let broker = Arc::new(FakeBroker::default());
        let op = uuid::Uuid::now_v7();
        let mut runner = Runner::new(&mut conn, Some(broker.clone()));
        let prepare = runner
            .prepare_up(&PrepareUpRequest {
                operation_id: op,
                target: target(&db),
            })
            .await?;
        assert!(prepare.session_binding.is_complete());
        runner
            .commit_up(&CommitUpRequest {
                operation_id: op,
                target: target(&db),
                session_binding: prepare.session_binding.clone(),
                proof: empty_proof(op, prepare.session_binding.clone()),
            })
            .await?;
        assert_eq!(
            broker.consumed_empty.lock().map(|g| g.len()).unwrap_or(0),
            1
        );
        // Second prepare fails: target is no longer stock.
        let second = runner
            .prepare_up(&PrepareUpRequest {
                operation_id: op,
                target: target(&db),
            })
            .await;
        assert!(second.is_err());
        Ok(())
    }
    .await;
    drop_db(&mut admin, &db).await;
    result
}

#[tokio::test]
async fn test_runner_rejects_proof_binding_mismatch() -> std::result::Result<(), Failure> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = provision(&mut admin, "proof").await?;
    let result = async {
        let mut conn = role_conn(&db, "central_migration").await?;
        let broker = Arc::new(FakeBroker::default());
        let op = uuid::Uuid::now_v7();
        let mut runner = Runner::new(&mut conn, Some(broker));
        let prepare = runner
            .prepare_up(&PrepareUpRequest {
                operation_id: op,
                target: target(&db),
            })
            .await?;
        // Proof bound to a different operation id must be refused before
        // the broker is even consulted.
        let err = runner
            .commit_up(&CommitUpRequest {
                operation_id: op,
                target: target(&db),
                session_binding: prepare.session_binding.clone(),
                proof: empty_proof(uuid::Uuid::now_v7(), prepare.session_binding.clone()),
            })
            .await;
        assert_eq!(
            err.err().map(|e| e.code().to_owned()),
            Some("runner_proof_unbound".to_owned())
        );
        Ok(())
    }
    .await;
    drop_db(&mut admin, &db).await;
    result
}

#[tokio::test]
async fn test_runner_commit_rejects_forged_session_binding() -> std::result::Result<(), Failure> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = provision(&mut admin, "bind").await?;
    let result = async {
        let mut conn = role_conn(&db, "central_migration").await?;
        let broker = Arc::new(FakeBroker::default());
        let op = uuid::Uuid::now_v7();
        let mut runner = Runner::new(&mut conn, Some(broker));
        let prepare = runner
            .prepare_up(&PrepareUpRequest {
                operation_id: op,
                target: target(&db),
            })
            .await?;
        // A forged binding — complete shape, wrong boot identity — must
        // be refused by the same-session fence before the proof service
        // is consulted.
        let mut forged = prepare.session_binding.clone();
        forged.boot_id = "postmaster:1970-01-01 00:00:00+00".to_owned();
        let err = runner
            .commit_up(&CommitUpRequest {
                operation_id: op,
                target: target(&db),
                session_binding: forged.clone(),
                proof: empty_proof(op, forged),
            })
            .await;
        assert_eq!(
            err.err().map(|e| e.code().to_owned()),
            Some("runner_session_binding_mismatch".to_owned())
        );
        Ok(())
    }
    .await;
    drop_db(&mut admin, &db).await;
    result
}

#[tokio::test]
async fn test_runner_resume_rejects_stale_instance_binding() -> std::result::Result<(), Failure> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = provision(&mut admin, "resbind").await?;
    let result = async {
        let mut conn = role_conn(&db, "central_migration").await?;
        BaselineInstaller::new().install(&mut conn).await?;
        // An expected binding captured on a different postmaster
        // generation must be rejected by the instance fence — Conflict,
        // matching upstream's SESSION_BINDING_MISMATCH — before any
        // repair or fresh-install leg runs.
        let stale = SessionBinding {
            backend_pid: 0,
            backend_start: "1970-01-01 00:00:00+00".to_owned(),
            boot_id: "postmaster:1970-01-01 00:00:00+00".to_owned(),
            lock_identities: Vec::new(),
        };
        let op = uuid::Uuid::now_v7();
        let mut runner = Runner::new(&mut conn, None::<Arc<FakeBroker>>);
        let failure = runner
            .resume(&ResumeRequest {
                operation_id: op,
                target: target(&db),
                expected_session_binding: stale,
                session_binding: SessionBinding::default(),
                proof: empty_proof(op, SessionBinding::default()),
            })
            .await
            .expect_err("resume must reject a stale instance binding");
        assert_eq!(failure.code(), "session_binding_mismatch");
        assert_eq!(failure.kind(), FailureKind::Conflict);
        Ok(())
    }
    .await;
    drop_db(&mut admin, &db).await;
    result
}

#[tokio::test]
async fn test_inspector_facts_and_verify_serve_baseline() -> std::result::Result<(), Failure> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = provision(&mut admin, "inspect").await?;
    let result = async {
        let mut mig = role_conn(&db, "central_migration").await?;
        BaselineInstaller::new().install(&mut mig).await?;
        let mut rt = role_conn(&db, "central_runtime").await?;
        Inspector::for_connection(&mut rt)
            .verify_serve_baseline()
            .await?;
        Ok(())
    }
    .await;
    drop_db(&mut admin, &db).await;
    result
}

#[tokio::test]
async fn test_reapply_runtime_grants_restores_revoked_grants() -> std::result::Result<(), Failure> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = provision(&mut admin, "grants").await?;
    let result = async {
        let mut mig = role_conn(&db, "central_migration").await?;
        BaselineInstaller::new().install(&mut mig).await?;
        // Simulate pg_restore --no-owner --no-privileges stripping grants.
        for stmt in [
            "REVOKE SELECT, INSERT, UPDATE, DELETE ON central.event_outbox FROM central_runtime",
            "REVOKE UPDATE ON central.provider_turns FROM central_runtime",
            "REVOKE SELECT ON central.attempt_decisions FROM central_runtime",
        ] {
            if let Err(err) = sqlx::query(stmt).execute(&mut mig).await {
                // provider_turns may not exist under that name on this
                // corpus — tolerate only "undefined table" (42P01);
                // every other error fails.
                let undefined_table = matches!(
                    &err,
                    sqlx::Error::Database(db) if db.code().as_deref() == Some("42P01")
                );
                if stmt.contains("provider_turns") && undefined_table {
                    continue;
                }
                return Err(sanitize(&err));
            }
        }
        reapply_runtime_grants(&mut mig).await?;
        reapply_runtime_grants(&mut mig).await?; // idempotent
        let mut rt = role_conn(&db, "central_runtime").await?;
        Inspector::for_connection(&mut rt)
            .verify_serve_baseline()
            .await?;
        Ok(())
    }
    .await;
    drop_db(&mut admin, &db).await;
    result
}

#[tokio::test]
async fn test_reset_runner_refuses_non_version_zero() -> std::result::Result<(), Failure> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = provision(&mut admin, "reset").await?;
    let result = async {
        let mut mig = role_conn(&db, "central_migration").await?;
        BaselineInstaller::new().install(&mut mig).await?;
        let broker = Arc::new(FakeBroker::default());
        let mut reset = ResetRunner::new(&mut mig, Some(broker));
        let op = uuid::Uuid::now_v7();
        let err = reset
            .delete_schema(&ResetRequest {
                target: target(&db),
                confirmation: ResetConfirmation {
                    operation_id: op,
                    target_fingerprint: "fp".to_owned(),
                    nonce: vec![1, 2, 3],
                    expires_at: time::OffsetDateTime::UNIX_EPOCH,
                    hmac: "h".to_owned(),
                },
            })
            .await;
        assert_eq!(
            err.err().map(|e| e.code().to_owned()),
            Some("reset_requires_version_zero_only".to_owned())
        );
        Ok(())
    }
    .await;
    drop_db(&mut admin, &db).await;
    result
}

#[tokio::test]
async fn test_version_zero_eligibility() -> std::result::Result<(), Failure> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = provision(&mut admin, "elig").await?;
    let result = async {
        let mut mig = role_conn(&db, "central_migration").await?;
        // Version-zero-only install: replay just the baseline file (it
        // carries the schema + ledger rows for v0).
        sqlx::raw_sql(MIGRATIONS[0].sql)
            .execute(&mut mig)
            .await
            .map_err(|e| classify_sqlx(&e))?;
        {
            let broker = Arc::new(FakeBroker::default());
            let mut reset = ResetRunner::new(&mut mig, Some(broker));
            let eligibility = reset.version_zero_eligibility().await?;
            assert!(eligibility.installed);
            assert!(eligibility.clean_version_zero_only);
        }
        BaselineInstaller::new().install(&mut mig).await?;
        {
            let broker = Arc::new(FakeBroker::default());
            let mut reset = ResetRunner::new(&mut mig, Some(broker));
            let eligibility = reset.version_zero_eligibility().await?;
            assert!(eligibility.installed);
            assert!(!eligibility.clean_version_zero_only);
        }
        Ok(())
    }
    .await;
    drop_db(&mut admin, &db).await;
    result
}

#[tokio::test]
async fn test_runner_resume_repairs_installed_target() -> std::result::Result<(), Failure> {
    skip!();
    let mut admin = admin_conn().await?;
    let db = provision(&mut admin, "resume").await?;
    let result = async {
        let mut conn = role_conn(&db, "central_migration").await?;
        BaselineInstaller::new().install(&mut conn).await?;
        let db_oid: String =
            sqlx::query("SELECT oid::text FROM pg_database WHERE datname = current_database()")
                .fetch_one(&mut conn)
                .await
                .map_err(|e| classify_sqlx(&e))?
                .get::<String, _>(0);
        let mut t = target(&db);
        t.database_oid = db_oid;
        let op = uuid::Uuid::now_v7();
        let mut runner = Runner::new(&mut conn, None::<Arc<FakeBroker>>);
        runner
            .resume(&ResumeRequest {
                operation_id: op,
                target: t,
                expected_session_binding: SessionBinding::default(),
                session_binding: SessionBinding::default(),
                proof: empty_proof(op, SessionBinding::default()),
            })
            .await?;
        Ok(())
    }
    .await;
    drop_db(&mut admin, &db).await;
    result
}
