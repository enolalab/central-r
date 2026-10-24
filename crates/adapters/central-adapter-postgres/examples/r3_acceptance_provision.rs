//! `r3-acceptance-provision` — the Phase R3 acceptance runner's database
//! provisioner. Given `CENTRAL_TEST_DSN` (a superuser DSN on a scratch
//! cluster whose `central_migration`/`central_runtime`/`central_outbox`
//! roles exist, same convention as the `migrate_integration` suite) it:
//!
//!   1. drops and recreates `CENTRAL_ACCEPTANCE_DB`
//!      (default `central_r3_acceptance`), owned by `central_migration`;
//!   2. connects as `central_migration` and runs the native
//!      `BaselineInstaller` v0..v37 chain — the only migration executor;
//!   3. prints the derived `central_runtime` DSN on stdout as
//!      `CENTRAL_RUNTIME_DSN=postgresql://central_runtime:central_runtime@<host>:<port>/<db>`
//!      for the acceptance runner to hand to `central serve`.
//!
//! A provision failure exits non-zero; `CENTRAL_ACCEPTANCE_KEEP_DB=1`
//! skips the drop so a second run reuses the database idempotently
//! (the installer is idempotent by contract).

use std::str::FromStr;

use central_adapter_postgres::error::classify_sqlx;
use central_adapter_postgres::migrate::BaselineInstaller;
use sqlx::{Connection, PgConnection};

fn fail(code: &str, msg: &str) -> ! {
    eprintln!("r3-acceptance-provision[{code}]: {msg}");
    std::process::exit(1);
}

#[tokio::main]
async fn main() {
    let dsn = match std::env::var("CENTRAL_TEST_DSN") {
        Ok(d) if !d.trim().is_empty() => d,
        _ => fail("CONFIG_INVALID", "CENTRAL_TEST_DSN is not set"),
    };
    let db = std::env::var("CENTRAL_ACCEPTANCE_DB")
        .ok()
        .filter(|d| !d.trim().is_empty())
        .unwrap_or_else(|| "central_r3_acceptance".to_owned());
    let keep = std::env::var("CENTRAL_ACCEPTANCE_KEEP_DB").as_deref() == Ok("1");

    let opts = match sqlx::postgres::PgConnectOptions::from_str(&dsn) {
        Ok(o) => o,
        Err(e) => fail("CONFIG_INVALID", &format!("CENTRAL_TEST_DSN: {e}")),
    };

    let mut admin = match PgConnection::connect_with(&opts).await {
        Ok(c) => c,
        Err(e) => fail("DEPENDENCY_UNAVAILABLE", classify_sqlx(&e).message()),
    };
    if !keep {
        let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS {db}"))
            .execute(&mut admin)
            .await;
    }
    if let Err(e) = sqlx::query(&format!("CREATE DATABASE {db} OWNER central_migration"))
        .execute(&mut admin)
        .await
    {
        fail(
            "DEPENDENCY_UNAVAILABLE",
            &format!("create {db}: {}", classify_sqlx(&e).message()),
        );
    }

    let mig_opts = opts
        .clone()
        .database(&db)
        .username("central_migration")
        .password("central_migration");
    let mut mig = match PgConnection::connect_with(&mig_opts).await {
        Ok(c) => c,
        Err(e) => fail("DEPENDENCY_UNAVAILABLE", classify_sqlx(&e).message()),
    };
    if let Err(f) = BaselineInstaller::new().install(&mut mig).await {
        fail("MIGRATION_FAILED", f.message());
    }

    let host = mig_opts.get_host();
    let port = mig_opts.get_port();
    println!(
        "CENTRAL_MIGRATION_DSN=postgresql://central_migration:central_migration@{host}:{port}/{db}"
    );
    println!("CENTRAL_RUNTIME_DSN=postgresql://central_runtime:central_runtime@{host}:{port}/{db}");
    println!("CENTRAL_ACCEPTANCE_DB={db}");
}
