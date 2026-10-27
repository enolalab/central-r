//! C01/C03 operator-path e2e — `central backup create|verify|status`
//! against a real installed deployment. Gated on:
//!
//! - `CENTRAL_TEST_DSN`             — scratch-cluster superuser DSN
//! - `CENTRAL_TEST_MINIO_ENDPOINT`  (+ `_ACCESS_KEY`/`_SECRET_KEY`) — object store
//! - `CENTRAL_TEST_HELPER_SOCKET`   — a running `central-helper`
//!   daemon composed with the backup authorities
//!
//! When any gate is unset the test reports itself skipped — it never
//! fabricates a pass. The production C01 path requires pieces T9b
//! must still provide on this host (helper daemon composition with
//! the backup throughput gate wired, the CBL1 launcher socket, a
//! broker serving the `backup_*` verbs, and the PAM ceremony
//! authorities); until those exist no environment can answer
//! `backup-create` with `sealed`, so the honest result here is the
//! documented skip.
//!
//! The wire/grammar halves of both scenarios run unconditionally in
//! `backup_cli`'s unit tests against a real Unix socket.

#![allow(clippy::unwrap_used)]

use std::process::Command;

fn gates() -> Option<String> {
    let helper = std::env::var("CENTRAL_TEST_HELPER_SOCKET")
        .ok()
        .filter(|v| !v.is_empty())?;
    for var in [
        "CENTRAL_TEST_DSN",
        "CENTRAL_TEST_MINIO_ENDPOINT",
        "CENTRAL_TEST_MINIO_ACCESS_KEY",
        "CENTRAL_TEST_MINIO_SECRET_KEY",
    ] {
        std::env::var(var).ok().filter(|v| !v.is_empty())?;
    }
    Some(helper)
}

fn run_central(helper: &str, args: &[&str]) -> (u8, serde_json::Value) {
    let out = Command::new(env!("CARGO_BIN_EXE_central"))
        .args(args)
        .env("CENTRAL_HELPER_SOCKET", helper)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed = serde_json::from_str::<serde_json::Value>(stdout.trim_end())
        .unwrap_or(serde_json::Value::Null);
    (out.status.code().unwrap_or(255) as u8, parsed)
}

/// C01: `backup create` seals a backup; C03: `verify` attests the
/// manifest/ticket/inventory and `status` projects `sealed`.
#[test]
fn c01_create_then_c03_verify_and_status() {
    let Some(helper) = gates() else {
        eprintln!(
            "CENTRAL_TEST_DSN/CENTRAL_TEST_MINIO_*/CENTRAL_TEST_HELPER_SOCKET \
             unset — skipping C01/C03 e2e (T9b must provide the composed \
             helper daemon, launcher socket, broker backup verbs, and PAM \
             ceremony before this path can seal)"
        );
        return;
    };
    // C01 — the sealed create.
    let (code, env) = run_central(&helper, &["backup", "create"]);
    assert_eq!(code, 0, "backup create refused: {env}");
    assert_eq!(env["reason"], "ok");
    let operation_id = env["details"]["operation_id"].as_str().unwrap().to_owned();
    let backup_id = env["details"]["backup_id"].as_str().unwrap().to_owned();
    assert_eq!(env["details"]["phase"], "sealed");

    // C03 — manifest/ticket/inventory verification.
    let (code, env) = run_central(&helper, &["backup", "verify", &backup_id]);
    assert_eq!(code, 0, "backup verify refused: {env}");
    assert_eq!(env["details"]["verified"], true);
    assert_eq!(env["details"]["backup_id"], backup_id.as_str());

    // The operation projection reads sealed through the same path.
    let (code, env) = run_central(&helper, &["backup", "status", &operation_id]);
    assert_eq!(code, 0, "backup status refused: {env}");
    assert_eq!(env["details"]["phase"], "sealed");
    assert_eq!(env["details"]["status_reason"], "BACKUP_SEALED");
}
