//! A07 — broker crash mid-transition and journal integrity denials
//! (threat T23, upstream `journal.go` `Recover`/`Exact`/`Unsettled`
//! and `migration.go` proof verification).
//!
//! The authority-transition journal settles torn chains on recovery:
//! an intact `issued.json` commits as-is, a missing issued falls back
//! to `prepared.json`, a *corrupt* issued is skipped — never
//! reinterpreted as prepared — and a present `committed.json` is
//! never overwritten (`RENAME_NOREPLACE`). Prepare records refuse
//! ID-mismatch and corruption; the proof service refuses tampered
//! fingerprints and HMACs in the closed `broker_proof` envelope.

// `allow-*-in-tests` only reaches `#[test]` fns — the fixture helpers
// in this binary unwrap/expect deliberately: an unbuildable fixture
// is the failure.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod a07;

use a07::*;
use central_adapter_linux::broker::journal::Journal;
use central_adapter_linux::broker::proof;
use central_adapter_linux::broker::signing::SigningService;
use central_backup::domain::{SessionBinding, TargetIdentity};
use central_backup::port::IssueEmptyTargetProofRequest;
use central_foundation::failure::FailureKind;
use central_infra::authority::{
    AuthorityTransitionPayload, PrepareOperation, PrepareOperationPhase,
};
use std::path::PathBuf;
use std::sync::Arc;
use time::OffsetDateTime;

fn journal(root: PathBuf) -> Journal {
    Journal::new(root, Arc::new(SigningService::new()), None)
}

fn payload(seq: u64, op: &str) -> AuthorityTransitionPayload {
    AuthorityTransitionPayload {
        schema_version: "central.authority-transition/v1".to_owned(),
        stream_id: "stream-a".to_owned(),
        sequence_num: seq,
        phase: "prepared".to_owned(),
        operation: op.to_owned(),
        instance_id: "i-1".to_owned(),
        binding_id: "b-1".to_owned(),
        launch_id: "l-1".to_owned(),
        nonce: "n-1".to_owned(),
        payload: serde_json::value::RawValue::from_string("{\"k\":1}".to_owned()).ok(),
        payload_digest: String::new(),
        payload_bytes: 0,
        prior_digest: String::new(),
        broker_key_ver: String::new(),
        hmac: String::new(),
        signature: String::new(),
        signed_at: String::new(),
    }
}

fn seq_dir(scratch: &Scratch, stream: &str, seq: u64, op: &str) -> PathBuf {
    scratch.join(&format!("authority-records/{stream}/{seq:020}-{op}"))
}

/// The torn append — `prepared.json` only, no issued — is what a
/// crash between the two phase writes leaves. `recover()` re-issues
/// and commits it; the second `recover()` reports nothing left.
#[test]
fn journal_torn_append_recovers_prepared() {
    let scratch = Scratch::new("journal-torn");
    let j = journal(scratch.path().to_path_buf());
    let dir = seq_dir(&scratch, "stream-a", 7, "up");
    std::fs::create_dir_all(&dir).expect("seq dir");
    std::fs::write(
        dir.join("prepared.json"),
        serde_json::to_vec(&payload(7, "up")).unwrap(),
    )
    .expect("prepared");

    assert_eq!(j.recover().expect("recover"), 1, "one torn chain settled");
    assert!(
        dir.join("committed.json").exists(),
        "recovery commits the torn chain"
    );
    assert!(
        dir.join("issued.json").exists(),
        "recovery re-issues before committing"
    );
    assert_eq!(j.recover().expect("recover again"), 0, "idempotent");
}

/// A crash mid-`issued.json` write leaves garbage bytes: the chain is
/// skipped — a corrupt issued is *never* reinterpreted as a prepared
/// intent and never silently committed.
#[test]
fn journal_corrupt_issued_never_reinterpreted() {
    let scratch = Scratch::new("journal-corrupt-issued");
    let j = journal(scratch.path().to_path_buf());
    let dir = seq_dir(&scratch, "stream-a", 3, "up");
    std::fs::create_dir_all(&dir).expect("seq dir");
    std::fs::write(
        dir.join("prepared.json"),
        serde_json::to_vec(&payload(3, "up")).unwrap(),
    )
    .expect("prepared");
    std::fs::write(dir.join("issued.json"), b"{torn-bytes").expect("issued");

    assert_eq!(j.recover().expect("recover"), 0, "corrupt chain refused");
    assert!(
        !dir.join("committed.json").exists(),
        "a corrupt issued must never produce a committed record"
    );
}

/// A `prepared.json` that cannot be decoded — the crash landed
/// inside the first phase — is skipped the same way.
#[test]
fn journal_corrupt_prepared_skipped() {
    let scratch = Scratch::new("journal-corrupt-prepared");
    let j = journal(scratch.path().to_path_buf());
    let dir = seq_dir(&scratch, "stream-a", 4, "up");
    std::fs::create_dir_all(&dir).expect("seq dir");
    std::fs::write(dir.join("prepared.json"), b"not json at all").expect("prepared");

    assert_eq!(j.recover().expect("recover"), 0);
    assert!(!dir.join("committed.json").exists());
}

/// A settled chain stays settled: `committed.json` exists, so even a
/// corrupt sibling `issued.json` is never re-examined — the committed
/// record is never overwritten.
#[test]
fn journal_committed_record_never_overwritten() {
    let scratch = Scratch::new("journal-committed");
    let j = journal(scratch.path().to_path_buf());
    let dir = seq_dir(&scratch, "stream-a", 5, "up");
    std::fs::create_dir_all(&dir).expect("seq dir");
    std::fs::write(dir.join("committed.json"), b"the settled record").expect("committed");
    std::fs::write(dir.join("issued.json"), b"{torn").expect("issued");

    assert_eq!(j.recover().expect("recover"), 0);
    assert_eq!(
        std::fs::read(dir.join("committed.json")).expect("read"),
        b"the settled record",
        "committed.json is byte-identical after recovery"
    );
}

/// `record_operation`/`unsettled`/`exact` — the prepare-record
/// store's own integrity gates: a corrupt entry is skipped, a
/// terminal phase is settled, a wrong-id lookup refuses.
#[test]
fn journal_prepare_record_gates() {
    let scratch = Scratch::new("journal-prepare");
    let j = journal(scratch.path().to_path_buf());
    let op = PrepareOperation {
        operation_id: "op-1".to_owned(),
        phase: PrepareOperationPhase::Acquiring,
        admission_id: "adm-1".to_owned(),
        selector: "sel-1".to_owned(),
        deadline: OffsetDateTime::now_utc() + time::Duration::minutes(5),
        reason: String::new(),
        reused: 0,
        acquired: 0,
        receipt_id: String::new(),
        created_at: OffsetDateTime::now_utc(),
    };
    j.record_operation(&op).expect("record");
    assert_eq!(
        j.unsettled().map(|o| o.operation_id),
        Some("op-1".to_owned()),
        "a non-terminal record is unsettled"
    );

    // Corrupt entry beside the good one — skipped, never surfaced.
    std::fs::write(scratch.join("prepare-records/corrupt.json"), b"{corrupt")
        .expect("corrupt record");
    assert_eq!(
        j.unsettled().map(|o| o.operation_id),
        Some("op-1".to_owned())
    );

    // `exact` on the wrong id and on the corrupt file both refuse.
    let err = j.exact("op-does-not-exist").unwrap_err();
    assert_eq!(err.code(), "broker_journal");
    let err = j.exact("corrupt").unwrap_err();
    assert_eq!(err.code(), "broker_journal");

    // A record whose stored id differs from its filename is refused —
    // the store never returns a record under a borrowed identity.
    let mut renamed = op.clone();
    renamed.operation_id = "borrowed".to_owned();
    std::fs::write(
        scratch.join("prepare-records/real-name.json"),
        serde_json::to_vec(&renamed).unwrap(),
    )
    .expect("mismatched record");
    let err = j.exact("real-name").unwrap_err();
    assert_eq!(err.code(), "broker_journal");
    assert!(err.message().contains("ID mismatch"), "{}", err.message());
    // The mismatched record is itself non-terminal — remove it so the
    // settled assertion below is about `op-1` alone.
    std::fs::remove_file(scratch.join("prepare-records/real-name.json")).expect("cleanup");

    // Terminal phase settles the operation.
    let mut done = op.clone();
    done.phase = PrepareOperationPhase::Completed;
    j.record_operation(&done).expect("record terminal");
    assert_eq!(
        j.unsettled().map(|o| o.operation_id),
        None,
        "a completed record is settled"
    );
}

// ---------------------------------------------------------------------------
// Proof service — fingerprint and HMAC verification denials
// ---------------------------------------------------------------------------

fn issue_req(op: uuid::Uuid, system_id: &str) -> IssueEmptyTargetProofRequest {
    IssueEmptyTargetProofRequest {
        operation_id: op,
        target: TargetIdentity {
            system_id: system_id.to_owned(),
            database_oid: "16384".to_owned(),
            database: "central".to_owned(),
            config_hash: "cfg".to_owned(),
            epoch: 1,
        },
        session_binding: SessionBinding {
            backend_pid: 42,
            backend_start: "2026-01-01T00:00:00Z".to_owned(),
            boot_id: "boot".to_owned(),
            lock_identities: vec!["lock".to_owned()],
        },
        baseline_digest: "sha256:base".to_owned(),
    }
}

/// A proof minted for one target cannot verify another — the empty
/// fingerprint is bound at issue; a forged HMAC on an intact proof
/// fails verification outright. Both refusals are `broker_proof`
/// denials, never errors.
#[test]
fn proof_target_and_hmac_mismatch_denied() {
    let svc = proof::new_proof_service(SigningService::new());
    let op = uuid::Uuid::new_v4();
    let req = issue_req(op, "sys-A");
    let proof = svc.issue_empty_target_proof(&req).expect("issue");

    // Right target verifies.
    svc.verify_empty_target(&req.target, &proof)
        .expect("verify");

    // Wrong target: fingerprint mismatch.
    let mut other = req.target.clone();
    other.system_id = "sys-B".to_owned();
    let err = svc.verify_empty_target(&other, &proof).unwrap_err();
    assert_denial(
        &err,
        FailureKind::Denied,
        "broker_proof",
        "fingerprint mismatch",
    );

    // Tampered HMAC: flip the stored mac.
    let mut forged = proof.clone();
    forged.hmac = "00".repeat(32);
    let err = svc.verify_empty_target(&req.target, &forged).unwrap_err();
    assert_denial(
        &err,
        FailureKind::Denied,
        "broker_proof",
        "HMAC verification failed",
    );

    // Consumed proofs never verify twice.
    svc.consume_empty_proof(&proof).expect("consume");
    let err = svc.verify_empty_target(&req.target, &proof).unwrap_err();
    assert_denial(
        &err,
        FailureKind::Denied,
        "broker_proof",
        "already consumed",
    );
}

/// The `hmac_fingerprint` RPC is the projection check the B10 client
/// compares against: the same bytes always yield the same
/// fingerprint, and a tampered payload yields a different one — the
/// compare is what refuses substituted state.
#[test]
fn broker_hmac_fingerprint_distinguishes_tampered_payload() {
    let signing = SigningService::new();
    let a = signing.fingerprint("authority-transition", b"payload-bytes");
    let b = signing.fingerprint("authority-transition", b"payload-bytes");
    let c = signing.fingerprint("authority-transition", b"payload-BYTES");
    assert_eq!(a, b, "deterministic");
    assert_ne!(a, c, "a substituted payload never collides");
}
