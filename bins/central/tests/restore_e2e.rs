//! C03–C05 operator-path e2e — `central restore verify|apply|resume|
//! abandon` against a real installed deployment. Gated on:
//!
//! - `CENTRAL_TEST_DSN`             — scratch-cluster superuser DSN
//! - `CENTRAL_TEST_MINIO_ENDPOINT`  (+ `_ACCESS_KEY`/`_SECRET_KEY`) — object store
//! - `CENTRAL_TEST_HELPER_SOCKET`   — a running `central-helper`
//!   daemon composed with the restore authorities, the PAM/TTY
//!   ceremony, and the root restore-launcher seam
//!
//! When any gate is unset the test reports itself skipped — it never
//! fabricates a pass. The production path requires the full ceremony
//! stack T9b wires (broker ticket issuance, the helper's restore
//! verbs behind physical-TTY confirmation, the launch-gated
//! `central-restore` engine, the C04 capacity reserve and the C05
//! authority reset); until every one of those is answered on the
//! host, the honest result here is the documented skip.
//!
//! The wire/grammar halves — argv contract, receipt shape, refusal
//! classification, substitution rejection, launch-gate grammar — run
//! unconditionally in `central-restore`'s and `central-kernel`'s unit
//! tests, which is where upstream's `main_test.go`/`engine_test.go`
//! semantics live in this port.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

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

/// C03: `restore verify` mints the one-use ticket after sealed-media
/// verification. C04: `apply` consumes it under the capacity reserve
/// and replaces the database. C05: the operation reaches `ready`
/// only after the broker+database authority reset; serving stays
/// blocked in every earlier phase.
///
/// Upstream's scenario suite (`c06_*`) carries the restart/resume,
/// stale-admission, and quarantine batteries; this test asserts the
/// linear path a real deployment can answer end to end.
#[test]
fn c03_verify_then_c04_apply_reaches_ready_or_refuses_cleanly() {
    let Some(helper) = gates() else {
        eprintln!(
            "CENTRAL_TEST_DSN/CENTRAL_TEST_MINIO_*/CENTRAL_TEST_HELPER_SOCKET \
             unset — skipping C03/C04/C05 restore e2e (the composed helper \
             daemon, PAM/TTY ceremony, launch-gated engine, C04 reserve, and \
             C05 reset must all be answered by the host)"
        );
        return;
    };

    // C03 — sealed-media verification mints the one-use ticket.
    let (code, env) = run_central(&helper, &["restore", "verify"]);
    match code {
        0 => {}
        // A composed-but-unprovisioned host answers a refusal, never
        // a silent success: verify's own refusal vocabulary is the
        // only legitimate non-zero here.
        3 => {
            assert_eq!(
                env["reason"], "RESTORE_VERIFY_DEPENDENCY_UNAVAILABLE",
                "unexpected verify refusal: {env}"
            );
            eprintln!("restore verify dependency-unavailable on this host — skipping apply");
            return;
        }
        6 => {
            let reason = env["reason"].as_str().unwrap_or_default();
            assert!(
                matches!(
                    reason,
                    "RESTORE_VERIFY_FAILED"
                        | "RESTORE_VERIFY_STATE_INVALID"
                        | "RESTORE_VERIFY_MEDIA_INVALID"
                        | "RESTORE_VERIFY_CAPACITY_INSUFFICIENT"
                        | "RESTORE_VERIFY_TARGET_ADMISSION_STALE"
                        | "RESTORE_NO_ADMISSIBLE_BACKUP"
                        | "RESTORE_BACKUP_CANDIDATE_AMBIGUOUS"
                ),
                "unclassified verify refusal: {env}"
            );
            eprintln!("restore verify refused with {reason} — skipping apply");
            return;
        }
        7 => {
            assert_eq!(
                env["reason"], "RESTORE_VERIFY_AUTHORITY_DENIED",
                "unexpected verify denial: {env}"
            );
            eprintln!("restore verify authority-denied — skipping apply");
            return;
        }
        _ => panic!("restore verify returned unexpected exit {code}: {env}"),
    }
    assert_eq!(env["reason"], "ok");
    let ticket_id = env["details"]["ticket_id"].as_str().unwrap().to_owned();
    let backup_id = env["details"]["backup_id"].as_str().unwrap().to_owned();
    assert!(!ticket_id.is_empty() && !backup_id.is_empty());
    assert!(!env["details"]["expires_at"].as_str().unwrap().is_empty());
    // The verify details must carry no phase, checkpoint, or secret
    // material — verification never advances an operation.
    for forbidden in ["phase", "checkpoint", "hmac", "nonce"] {
        assert!(
            env["details"].get(forbidden).is_none(),
            "verify details exposed {forbidden}: {env}"
        );
    }

    // C04 — apply consumes the outstanding ticket and runs the
    // destructive path. The only legitimate outcomes are `ready`
    // (the C05 reset completed) or a non-ready phase that still
    // reports a well-formed operation for `restore resume`.
    let (code, env) = run_central(&helper, &["restore", "apply"]);
    match code {
        0 => {
            assert_eq!(env["reason"], "ok");
            assert_eq!(env["details"]["phase"], "ready");
            assert!(!env["details"]["operation_id"].as_str().unwrap().is_empty());
            assert!(!env["details"]["checkpoint"].as_str().unwrap().is_empty());
        }
        6 => {
            let reason = env["reason"].as_str().unwrap_or_default();
            assert!(
                reason.starts_with("RESTORE_APPLY")
                    || matches!(
                        reason,
                        "RESTORE_NO_LIVE_OPERATION" | "RESTORE_LIVE_OPERATION_AMBIGUOUS"
                    ),
                "unclassified apply refusal: {env}"
            );
            // A non-ready terminal outcome still projects a resume-
            // able operation when one exists.
            if reason == "RESTORE_APPLY_FAILED" {
                let phase = env["details"]["phase"].as_str().unwrap_or_default();
                assert!(
                    matches!(
                        phase,
                        "" | "applying" | "verifying" | "quarantined" | "resetting"
                    ),
                    "apply failure reported a phase outside the closed set: {env}"
                );
            }
        }
        3 => assert_eq!(
            env["reason"], "RESTORE_APPLY_DEPENDENCY_UNAVAILABLE",
            "unexpected apply refusal: {env}"
        ),
        4 => assert_eq!(
            env["reason"], "RESTORE_APPLY_LOCK_TIMEOUT",
            "unexpected apply refusal: {env}"
        ),
        7 => {
            let reason = env["reason"].as_str().unwrap_or_default();
            assert!(
                matches!(
                    reason,
                    "RESTORE_APPLY_AUTHORITY_DENIED" | "DENY_SAFE_ACTIVE"
                ),
                "unexpected apply denial: {env}"
            );
        }
        _ => panic!("restore apply returned unexpected exit {code}: {env}"),
    }
}

/// `restore resume`/`abandon` resolve the live protected operation on
/// the privileged side. With no operation in flight the resolver's
/// `RESTORE_NO_LIVE_OPERATION` is the only correct answer; with one,
/// each verb must produce its closed phase vocabulary and nothing
/// else.
#[test]
fn resume_and_abandon_answer_only_the_closed_vocabulary() {
    let Some(helper) = gates() else {
        eprintln!("CENTRAL_TEST_* gates unset — skipping restore resume/abandon e2e");
        return;
    };

    for (verb, prefix) in [("resume", "RESTORE_RESUME"), ("abandon", "RESTORE_ABANDON")] {
        let (code, env) = run_central(&helper, &["restore", verb]);
        match code {
            0 => {
                assert_eq!(env["reason"], "ok");
                let phase = env["details"]["phase"].as_str().unwrap_or_default();
                // Resume's only success is `ready`; abandon's only
                // success is `abandoned` — cross-reporting is the
                // substitution the closed sets exist to stop.
                let want = if verb == "abandon" {
                    "abandoned"
                } else {
                    "ready"
                };
                assert_eq!(phase, want, "{verb} reported {phase}: {env}");
            }
            6 => {
                let reason = env["reason"].as_str().unwrap_or_default();
                assert!(
                    reason.starts_with(prefix)
                        || matches!(
                            reason,
                            "RESTORE_NO_LIVE_OPERATION" | "RESTORE_LIVE_OPERATION_AMBIGUOUS"
                        ),
                    "unclassified {verb} refusal: {env}"
                );
            }
            3 => assert_eq!(
                env["reason"],
                format!("{prefix}_DEPENDENCY_UNAVAILABLE"),
                "unexpected {verb} refusal: {env}"
            ),
            4 => {
                assert!(
                    verb == "resume",
                    "{verb} must never report a lock timeout: {env}"
                );
                assert_eq!(env["reason"], "RESTORE_RESUME_LOCK_TIMEOUT");
            }
            7 => {
                let reason = env["reason"].as_str().unwrap_or_default();
                assert!(
                    reason == format!("{prefix}_AUTHORITY_DENIED") || reason == "DENY_SAFE_ACTIVE",
                    "unexpected {verb} denial: {env}"
                );
            }
            _ => panic!("restore {verb} returned unexpected exit {code}: {env}"),
        }
    }
}
