//! PostgreSQL integration tests for `session::PgSessionStore` — the
//! port of upstream `internal/adapter/postgres/session/store_test.go`'s
//! database-backed scenarios.
//!
//! Gated on `CENTRAL_TEST_DSN` — a superuser DSN on a scratch cluster
//! whose `central_migration`, `central_runtime`, and `central_outbox`
//! roles exist (passwords `<role>`), the same provisioning contract as
//! `store_integration.rs`. Every test provisions its own database owned
//! by `central_migration` and installs the baseline through
//! [`BaselineInstaller::install`].
//!
//! Role discipline: `seedGeneration` and `epoch_markers` writes run on
//! the `central_migration` connection (the seed fixture is not part of
//! the serving path; `epoch_markers` UPDATE is withheld from
//! `central_runtime` — SELECT only); every `SessionStore`/
//! `PresentationStore` port operation runs on the `central_runtime`
//! pool — the grants matrix (SELECT/INSERT/UPDATE on
//! `bootstrap_generations` + `sessions`, no DELETE) is proved
//! sufficient by the whole suite passing under it.

use std::str::FromStr;

use central_adapter_postgres::error::classify_sqlx;
use central_adapter_postgres::migrate::BaselineInstaller;
use central_adapter_postgres::session::PgSessionStore;
use central_foundation::failure::Failure;
use central_foundation::identity::WorkspaceId;
use central_session::contract::{
    BOOTSTRAP_VERIFIER_V1, BootstrapVerifier, CandidateBinding, Failure as SessFailure,
    FailureClass, RequestIdentity,
};
use central_session::domain::{
    ActivationRequest, DEFAULT_FIRST_USE_FENCE, DeliveryRequest, ExchangeRequest, MAX_RETRY_AFTER,
    SecurityEpoch, SessionState, ValidationRequest, retry_after_from_failure,
};
use central_session::port::{PresentationStore, SessionStore};
use sha2::{Digest as _, Sha256};
use sqlx::{Connection, PgConnection, PgPool};
use time::Duration;
use zeroize::Zeroizing;

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

async fn role_pool(db: &str, role: &str) -> Result<PgPool> {
    let opts = require_opts()?.database(db).username(role).password(role);
    PgPool::connect_with(opts)
        .await
        .map_err(|e| classify_sqlx(&e))
}

async fn provision(admin: &mut PgConnection, label: &str) -> Result<String> {
    let db = format!("session_test_{label}_{}", std::process::id());
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
    // FORCE severs the still-open `central_runtime` pool connections;
    // PG13+.
    let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS {db} WITH (FORCE)"))
        .execute(&mut *admin)
        .await;
}

/// `testStore` — provision + baseline + a `central_runtime` pool: the
/// database name (for teardown), the store under test, a
/// `central_migration` fixture connection, and the runtime pool.
async fn test_store(
    admin: &mut PgConnection,
    label: &str,
) -> Result<(String, PgSessionStore, PgConnection, PgPool)> {
    let db = provision(admin, label).await?;
    let mut mig = role_conn(&db, "central_migration").await?;
    BaselineInstaller::new().install(&mut mig).await?;
    let pool = role_pool(&db, "central_runtime").await?;
    Ok((db, PgSessionStore::new(pool.clone()), mig, pool))
}

/// `hashByte` — upstream's `sha256.Sum256([]byte{value})` test digest
/// source.
fn hash_byte(value: u8) -> [u8; 32] {
    Sha256::digest([value]).into()
}

fn sentinel_uuid() -> uuid::Uuid {
    uuid::Uuid::from_bytes(*WorkspaceId::sentinel().as_bytes())
}

/// `seedGeneration` — rewrites the baseline's generation-0 row with the
/// test verifier digest and a clean throttle/presentation slate (the
/// upstream fixture UPDATE, verbatim).
async fn seed_generation(conn: &mut PgConnection, digest: [u8; 32]) -> Result<()> {
    sqlx::query(
        r#"UPDATE central.bootstrap_generations
           SET verifier_hash = $1, state = 'active', principal_identity = 'baseline-provisioner',
               candidate_id = NULL, candidate_digest = NULL, registered_generation = NULL,
               throttle_failure_window_start = NULL, throttle_failure_count = 0,
               throttle_next_eligible = NULL, presentation_deadline = NULL, consumed_at = NULL
           WHERE workspace_id = $2 AND generation = 0"#,
    )
    .bind(&digest[..])
    .bind(sentinel_uuid())
    .execute(&mut *conn)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    Ok(())
}

/// `exchangeRequest` — the upstream fixture request.
fn exchange_request(digest: [u8; 32]) -> ExchangeRequest {
    ExchangeRequest {
        workspace_id: None,
        verifier: BootstrapVerifier::new(BOOTSTRAP_VERIFIER_V1, digest),
        identity: RequestIdentity {
            peer_uid: 1000,
            peer_pid: 4242,
            origin: "https://127.0.0.1:8080".to_string(),
        },
        pre_auth_csrf_hash: hash_byte(20),
        epoch: SecurityEpoch(0),
        idle_expiry: Duration::minutes(30),
        absolute_expiry: Duration::hours(12),
        first_use_fence: DEFAULT_FIRST_USE_FENCE,
    }
}

fn assert_class(err: &SessFailure, want: FailureClass) {
    assert_eq!(err.class, Some(want), "error = {err}, want class {want}");
}

/// Test plumbing only — the session `Failure` `Display` is already the
/// redacted upstream shape, so it is safe to lift into the fixture
/// error type.
fn lift(e: SessFailure) -> Failure {
    Failure::internal("session_test", e.to_string())
}

/// `TestDiscoverBootstrapCandidatesReadsDurableDeliveryPendingRows`.
#[tokio::test]
async fn discover_reads_durable_delivery_pending_rows() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let (db, store, mut mig, _pool) = test_store(&mut admin, "discover").await?;

    let digest = hash_byte(11);
    seed_generation(&mut mig, digest).await?;
    let exchange = store
        .exchange(exchange_request(digest))
        .await
        .map_err(lift)?;
    store
        .prepare_delivery(DeliveryRequest {
            session_id: exchange.session.id,
            candidate: exchange.replacement.clone(),
        })
        .await
        .map_err(lift)?;

    let candidates = store.discover_bootstrap_candidates().await.map_err(lift)?;
    assert_eq!(candidates.len(), 1, "candidates = {candidates:?}");
    assert_eq!(
        candidates[0].delivery_id.as_session_id(),
        exchange.session.id
    );
    assert!(candidates[0].activated);
    assert!(!candidates[0].pending_bootstrap);
    assert!(!candidates[0].first_use_overdue);

    drop_db(&mut admin, &db).await;
    Ok(())
}

/// `TestExchangeConcurrentWinnerCreatesOnePendingSession` — two racing
/// exchanges: exactly one creates a `pending_bootstrap` row; the loser
/// gets the indistinguishable invalid outcome.
#[tokio::test]
async fn exchange_concurrent_winner_creates_one_pending_session() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let (db, store, mut mig, pool) = test_store(&mut admin, "concurrent").await?;

    let digest = hash_byte(1);
    seed_generation(&mut mig, digest).await?;

    let store2 = store.clone();
    let req2 = exchange_request(digest);
    let spawned = tokio::spawn(async move { store2.exchange(req2).await });
    let mine = store.exchange(exchange_request(digest)).await;
    let theirs = spawned
        .await
        .map_err(|e| Failure::internal("session_test", format!("join: {e}")))?;

    let (mut pending, mut invalid, mut other_n) = (0usize, 0usize, 0usize);
    for r in [&mine, &theirs] {
        match r {
            Ok(v) if v.session.state == SessionState::PendingBootstrap => pending += 1,
            Err(e) if e.class == Some(FailureClass::BootstrapInvalid) => invalid += 1,
            _ => other_n += 1,
        }
    }
    assert_eq!(
        (pending, invalid, other_n),
        (1, 1, 0),
        "concurrent exchange outcomes: mine={mine:?} theirs={theirs:?}"
    );

    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM central.sessions WHERE lifecycle_state = 'pending_bootstrap'",
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(count, 1, "pending session rows = {count}");

    drop_db(&mut admin, &db).await;
    Ok(())
}

/// `TestExchangeThrottlesAfterFiveInvalidAttempts`.
#[tokio::test]
async fn exchange_throttles_after_five_invalid_attempts() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let (db, store, mut mig, _pool) = test_store(&mut admin, "throttle").await?;

    seed_generation(&mut mig, hash_byte(1)).await?;
    let wrong = hash_byte(2);
    for attempt in 1..=5u8 {
        let err = store.exchange(exchange_request(wrong)).await.unwrap_err();
        if attempt < 5 {
            assert_class(&err, FailureClass::BootstrapInvalid);
        } else {
            assert_class(&err, FailureClass::BootstrapThrottled);
            let retry =
                retry_after_from_failure(&err).expect("throttle failure carries a Retry-After");
            assert!(retry.duration() > Duration::ZERO);
            assert!(retry.duration() <= MAX_RETRY_AFTER);
        }
    }
    let err = store.exchange(exchange_request(wrong)).await.unwrap_err();
    assert_class(&err, FailureClass::BootstrapThrottled);

    drop_db(&mut admin, &db).await;
    Ok(())
}

/// `TestDeliveryRequiresExactCandidateAndActivationCredentials`.
#[tokio::test]
async fn delivery_requires_exact_candidate_and_activation_credentials() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let (db, store, mut mig, _pool) = test_store(&mut admin, "delivery").await?;

    let digest = hash_byte(3);
    seed_generation(&mut mig, digest).await?;
    let exchange = store
        .exchange(exchange_request(digest))
        .await
        .map_err(lift)?;

    let wrong = CandidateBinding {
        candidate_id: exchange.replacement.candidate_id.clone(),
        generation: exchange.replacement.generation,
        digest: Zeroizing::new(hash_byte(99)),
    };
    let err = store
        .prepare_delivery(DeliveryRequest {
            session_id: exchange.session.id,
            candidate: wrong,
        })
        .await
        .unwrap_err();
    assert_class(&err, FailureClass::BootstrapInvalid);

    let delivery = store
        .prepare_delivery(DeliveryRequest {
            session_id: exchange.session.id,
            candidate: exchange.replacement.clone(),
        })
        .await
        .map_err(lift)?;
    assert_eq!(delivery.session.state, SessionState::DeliveryPending);
    assert_eq!(delivery.delivery_id.as_session_id(), exchange.session.id);

    // Zero credential hashes fail closed before any database work.
    let err = store
        .activate_delivery(ActivationRequest {
            delivery_id: delivery.delivery_id,
            token_hash: [0u8; 32],
            csrf_hash: [0u8; 32],
            identity: exchange_request(digest).identity,
            epoch: SecurityEpoch(0),
        })
        .await
        .unwrap_err();
    assert_class(&err, FailureClass::SessionInvalidated);

    let active = store
        .activate_delivery(ActivationRequest {
            delivery_id: delivery.delivery_id,
            token_hash: hash_byte(4),
            csrf_hash: hash_byte(5),
            identity: exchange_request(digest).identity,
            epoch: SecurityEpoch(0),
        })
        .await
        .map_err(lift)?;
    assert_eq!(active.state, SessionState::Active);
    assert_ne!(active.token_hash, [0u8; 32]);
    assert_ne!(active.csrf_hash, [0u8; 32]);
    assert!(active.first_use_deadline.is_some());

    drop_db(&mut admin, &db).await;
    Ok(())
}

/// `TestRevokeTransitionsPendingBootstrapToTerminalState`.
#[tokio::test]
async fn revoke_transitions_pending_bootstrap_to_terminal_state() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let (db, store, mut mig, pool) = test_store(&mut admin, "revoke").await?;

    let digest = hash_byte(10);
    seed_generation(&mut mig, digest).await?;
    let exchange = store
        .exchange(exchange_request(digest))
        .await
        .map_err(lift)?;
    store.revoke(exchange.session.id).await.map_err(lift)?;

    let state: String =
        sqlx::query_scalar("SELECT lifecycle_state FROM central.sessions WHERE id = $1")
            .bind(uuid::Uuid::from_bytes(*exchange.session.id.as_bytes()))
            .fetch_one(&pool)
            .await
            .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(state, SessionState::Revoked.as_str());

    store
        .prepare_delivery(DeliveryRequest {
            session_id: exchange.session.id,
            candidate: exchange.replacement.clone(),
        })
        .await
        .unwrap_err();

    let candidates = store.discover_bootstrap_candidates().await.map_err(lift)?;
    for c in &candidates {
        assert_ne!(c.delivery_id.as_session_id(), exchange.session.id);
    }

    drop_db(&mut admin, &db).await;
    Ok(())
}

/// `TestValidateRecordsFirstUseAndRevokeIsIdempotent`.
#[tokio::test]
async fn validate_records_first_use_and_revoke_is_idempotent() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let (db, store, mut mig, _pool) = test_store(&mut admin, "validate").await?;

    let digest = hash_byte(6);
    seed_generation(&mut mig, digest).await?;
    let exchange = store
        .exchange(exchange_request(digest))
        .await
        .map_err(lift)?;
    let identity = exchange_request(digest).identity;
    let delivery = store
        .prepare_delivery(DeliveryRequest {
            session_id: exchange.session.id,
            candidate: exchange.replacement.clone(),
        })
        .await
        .map_err(lift)?;
    store
        .activate_delivery(ActivationRequest {
            delivery_id: delivery.delivery_id,
            token_hash: hash_byte(7),
            csrf_hash: hash_byte(8),
            identity,
            epoch: SecurityEpoch(0),
        })
        .await
        .map_err(lift)?;

    let validated = store
        .validate(ValidationRequest {
            token_hash: hash_byte(7),
            presented_csrf_hash: Some(hash_byte(8)),
            epoch: SecurityEpoch(0),
        })
        .await
        .map_err(lift)?;
    assert_eq!(validated.state, SessionState::Active);
    assert!(validated.first_used_at.is_some(), "first use not recorded");

    // Wrong session CSRF fails validation.
    let err = store
        .validate(ValidationRequest {
            token_hash: hash_byte(7),
            presented_csrf_hash: Some(hash_byte(9)),
            epoch: SecurityEpoch(0),
        })
        .await
        .unwrap_err();
    assert_class(&err, FailureClass::SessionInvalidated);

    store.revoke(validated.id).await.map_err(lift)?;
    // Second revoke is a no-op, not an error.
    store.revoke(validated.id).await.map_err(lift)?;
    let err = store
        .validate(ValidationRequest {
            token_hash: hash_byte(7),
            presented_csrf_hash: None,
            epoch: SecurityEpoch(0),
        })
        .await
        .unwrap_err();
    assert_class(&err, FailureClass::SessionInvalidated);

    drop_db(&mut admin, &db).await;
    Ok(())
}

/// `TestSessionUsesPersistedNonzeroSecurityEpochAcrossRestartBoundary`.
#[tokio::test]
async fn session_uses_persisted_nonzero_security_epoch_across_restart() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let (db, store, mut mig, _pool) = test_store(&mut admin, "epoch").await?;

    sqlx::query("UPDATE central.epoch_markers SET security_epoch = 7, restore_epoch = 8")
        .execute(&mut mig)
        .await
        .map_err(|e| classify_sqlx(&e))?;

    let digest = hash_byte(12);
    let mut request = exchange_request(digest);
    request.epoch = SecurityEpoch(7);
    seed_generation(&mut mig, digest).await?;
    let exchange = store.exchange(request).await.map_err(lift)?;
    let delivery = store
        .prepare_delivery(DeliveryRequest {
            session_id: exchange.session.id,
            candidate: exchange.replacement.clone(),
        })
        .await
        .map_err(lift)?;
    store
        .activate_delivery(ActivationRequest {
            delivery_id: delivery.delivery_id,
            token_hash: hash_byte(13),
            csrf_hash: hash_byte(14),
            identity: exchange_request(digest).identity,
            epoch: SecurityEpoch(7),
        })
        .await
        .map_err(lift)?;
    store
        .validate(ValidationRequest {
            token_hash: hash_byte(13),
            presented_csrf_hash: None,
            epoch: SecurityEpoch(7),
        })
        .await
        .map_err(lift)?;
    let err = store
        .validate(ValidationRequest {
            token_hash: hash_byte(13),
            presented_csrf_hash: None,
            epoch: SecurityEpoch(0),
        })
        .await
        .unwrap_err();
    assert_class(&err, FailureClass::SessionInvalidated);

    drop_db(&mut admin, &db).await;
    Ok(())
}

/// `TestCurrentGenerationUsesBoundedAuditedIndexPlan` — the
/// `FOR UPDATE … LIMIT 1` current-generation read must use the audited
/// partial index, verbatim from upstream.
#[tokio::test]
async fn current_generation_uses_bounded_audited_index_plan() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let (db, _store, mut mig, pool) = test_store(&mut admin, "plan").await?;

    sqlx::query(
        r#"INSERT INTO central.bootstrap_generations
              (id, workspace_id, generation, verifier_hash, state, principal_identity, created_at)
           SELECT gen_random_uuid(), $1::uuid, generation, decode(repeat('01', 32), 'hex'),
                  CASE WHEN generation > 1000 THEN 'active' ELSE 'consumed' END,
                  'plan-proof', clock_timestamp()
           FROM generate_series(1, 1010) AS generation"#,
    )
    .bind(sentinel_uuid())
    .execute(&mut mig)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    sqlx::query("ANALYZE central.bootstrap_generations")
        .execute(&mut mig)
        .await
        .map_err(|e| classify_sqlx(&e))?;

    let raw_plan: serde_json::Value = sqlx::query_scalar(
        r#"EXPLAIN (FORMAT JSON, COSTS OFF)
           SELECT id, generation, verifier_hash, principal_identity,
                  throttle_failure_window_start, throttle_failure_count,
                  throttle_next_eligible, clock_timestamp()
           FROM central.bootstrap_generations
           WHERE workspace_id = $1::uuid AND state = 'active'
           ORDER BY generation DESC
           LIMIT 1
           FOR UPDATE"#,
    )
    .bind(sentinel_uuid())
    .fetch_one(&pool)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    let text = raw_plan.to_string();
    assert!(
        text.contains("\"Node Type\":\"Limit\""),
        "plan not bounded: {text}"
    );
    assert!(
        text.contains("\"Index Name\":\"bootstrap_generations_active_idx\""),
        "plan does not use audited active index: {text}"
    );

    drop_db(&mut admin, &db).await;
    Ok(())
}

/// The presentation lease round-trip (upstream's
/// `BeginPresentation`/`ValidatePresentation` path): a lease on the
/// active generation is durable and validates against the database
/// clock.
#[tokio::test]
async fn presentation_lease_round_trips_on_database_time() -> Result<()> {
    skip!();
    let mut admin = admin_conn().await?;
    let (db, store, mut mig, _pool) = test_store(&mut admin, "present").await?;

    seed_generation(&mut mig, hash_byte(1)).await?;
    // The fixture clears presentation_deadline — no valid lease yet.
    let err = store.validate_presentation().await.unwrap_err();
    assert_class(&err, FailureClass::BootstrapInvalid);

    let lease = store.begin_presentation().await.map_err(lift)?;
    assert_eq!(lease.generation, 0);
    assert!(lease.deadline.is_some());
    store.validate_presentation().await.map_err(lift)?;

    drop_db(&mut admin, &db).await;
    Ok(())
}
