//! Gated on `CENTRAL_TEST_DSN` — a superuser DSN on a scratch cluster
//! carrying the `central_migration`/`central_runtime` roles, the same
//! contract `central-adapter-postgres`'s integration tests use.
//!
//! The test pins what the unit suite cannot: the composed scheduler
//! capability — worker registration/heartbeat, lease sweeper, claim
//! loop, checkpoint janitor, retry timeout sweeper and outbox
//! publisher — actually starts under the kernel's default settlement
//! profile, the startup reconciler passes against an empty store, and
//! reverse-order settlement deregisters the worker row durably.

use std::str::FromStr;
use std::sync::Arc;

use central_adapter_postgres::checkpoint::Store as PgCheckpointStore;
use central_adapter_postgres::error::classify_sqlx;
use central_adapter_postgres::eventjournal::Store as PgEventJournalStore;
use central_adapter_postgres::migrate::BaselineInstaller;
use central_foundation::failure::Failure;
use central_kernel::BoxFuture;
use central_kernel::lifecycle::{
    BootstrapReconciler, ControlLock, ControlLockLease, PreflightReport, Profile, ProfileConfig,
    ServingPreflight,
};
use central_kernel::readiness::Readiness;
use central_kernel::scheduler_compose::{
    SchedulerCompositionRequest, compose_scheduler, new_scheduler_store,
};
use sqlx::{Connection, PgConnection, PgPool};
use tokio_util::sync::CancellationToken;

type Opts = sqlx::postgres::PgConnectOptions;
type TestResult<T> = std::result::Result<T, Failure>;

fn admin_opts() -> Option<Opts> {
    let dsn = std::env::var("CENTRAL_TEST_DSN").ok()?;
    Opts::from_str(&dsn).ok()
}

fn require_opts() -> TestResult<Opts> {
    admin_opts().ok_or_else(|| Failure::internal("test_env", "CENTRAL_TEST_DSN unset"))
}

async fn admin_conn() -> TestResult<PgConnection> {
    PgConnection::connect_with(&require_opts()?)
        .await
        .map_err(|e| classify_sqlx(&e))
}

async fn role_conn(db: &str, role: &str) -> TestResult<PgConnection> {
    let opts = require_opts()?.database(db).username(role).password(role);
    PgConnection::connect_with(&opts)
        .await
        .map_err(|e| classify_sqlx(&e))
}

async fn role_pool(db: &str, role: &str) -> TestResult<PgPool> {
    let opts = require_opts()?.database(db).username(role).password(role);
    PgPool::connect_with(opts)
        .await
        .map_err(|e| classify_sqlx(&e))
}

async fn provision(admin: &mut PgConnection, label: &str) -> TestResult<String> {
    let db = format!("sched_compose_test_{label}_{}", std::process::id());
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
    let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS {db} WITH (FORCE)"))
        .execute(&mut *admin)
        .await;
}

// -- Minimal profile ports (the kernel's `test_support` stubs are
//    crate-private; integration tests carry their own) --------------

struct GrantingLock;

impl ControlLock for GrantingLock {
    fn acquire(&mut self) -> BoxFuture<'_, Result<Box<dyn ControlLockLease>, Failure>> {
        Box::pin(async { Ok(Box::new(QuietLease) as Box<dyn ControlLockLease>) })
    }
}

struct QuietLease;

impl ControlLockLease for QuietLease {
    fn lost(&self) -> BoxFuture<'static, Failure> {
        Box::pin(std::future::pending())
    }
    fn close(&mut self) -> BoxFuture<'_, std::result::Result<(), Failure>> {
        Box::pin(async { Ok(()) })
    }
}

struct PassingGate;

impl ServingPreflight for PassingGate {
    fn run_for_serve(
        &mut self,
        _runtime: CancellationToken,
        _deadline: tokio::time::Instant,
    ) -> BoxFuture<'_, std::result::Result<PreflightReport, Failure>> {
        Box::pin(async {
            Ok(PreflightReport {
                security_epoch: None,
            })
        })
    }
}

struct NoopBootstrap;

impl BootstrapReconciler for NoopBootstrap {
    fn reconcile_bootstrap(&mut self) -> BoxFuture<'_, std::result::Result<(), Failure>> {
        Box::pin(async { Ok(()) })
    }
}

/// The full Slice-2 stack under `ProfileConfig::default()` — the
/// default settlement profile: the startup reconciler passes, every
/// composed component starts (the worker's durable registration is
/// observable in `central.worker_registrations`), and settlement
/// deregisters the worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scheduler_components_run_under_the_default_settlement_profile() -> TestResult<()> {
    if admin_opts().is_none() {
        eprintln!("CENTRAL_TEST_DSN unset — skipping PostgreSQL integration test");
        return Ok(());
    }
    let mut admin = admin_conn().await?;
    let db = provision(&mut admin, "profile").await?;
    let outcome = run_profile_test(&db).await;
    drop_db(&mut admin, &db).await;
    outcome
}

async fn run_profile_test(db: &str) -> TestResult<()> {
    let mut mig = role_conn(db, "central_migration").await?;
    BaselineInstaller::new().install(&mut mig).await?;
    let pool = role_pool(db, "central_runtime").await?;

    let scratch = std::env::temp_dir().join(format!("sched-compose-{}", std::process::id()));
    let config = central_kernel::scheduler_compose::SchedulerConfig {
        enabled: true,
        scratch_root: scratch.to_string_lossy().into_owned(),
        source_repo: String::new(),
        allow_stub: true, // the launcher seam is the documented stub — no harness here
    };
    let mut capability = compose_scheduler(SchedulerCompositionRequest {
        config,
        store: Some(Arc::new(new_scheduler_store(pool.clone(), None))),
        launcher: None,
        checkpoint_gc: Some(PgCheckpointStore::new(pool.clone())),
        timeout_sweep: Some(new_scheduler_store(pool.clone(), None)),
        outbox_drain: Some(PgEventJournalStore::new(pool.clone())),
        outbox_consumers: None,
    })?;
    let worker_id = capability
        .worker_id()
        .ok_or_else(|| Failure::internal("test", "no composed worker id"))?;

    // Reconcile-before-reinvoke passes against the fresh store.
    capability
        .preflight()
        .ok_or_else(|| Failure::internal("test", "no reconciler preflight"))?
        .run()
        .await?;

    // Register the six components on a default-settlement profile and
    // run it briefly — long enough for the worker to register and one
    // heartbeat + pass to land.
    let mut profile = Profile::new(ProfileConfig::default(), Readiness::new());
    profile.set_control_lock(GrantingLock);
    profile.set_serving_preflight(PassingGate);
    profile.set_bootstrap_reconciler(NoopBootstrap);
    for component in capability.take_components() {
        profile.add_component(component);
    }

    let stop = tokio::time::sleep(std::time::Duration::from_secs(2));
    profile
        .run(stop)
        .await
        .map_err(|e| Failure::internal("test", format!("profile run: {}", e.reason())))?;

    // Settlement deregistered the worker: the durable row is the proof
    // the worker component both started (row exists) and settled
    // (state flipped) under the default profile.
    let state: Option<String> =
        sqlx::query_scalar("SELECT state FROM central.worker_registrations WHERE id = $1")
            .bind(sqlx::types::uuid::Uuid::from_bytes(*worker_id.as_bytes()))
            .fetch_optional(&pool)
            .await
            .map_err(|e| classify_sqlx(&e))?;
    assert_eq!(
        state.as_deref(),
        Some("deregistered"),
        "worker {worker_id} did not settle to deregistered"
    );

    let _ = std::fs::remove_dir_all(&scratch);
    Ok(())
}
