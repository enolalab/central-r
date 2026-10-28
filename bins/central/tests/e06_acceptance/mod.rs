//! `e06_acceptance_test.go` — E06, Slice E acceptance: the
//! machine-checkable tier of the Phase-1 acceptance suite (spec:
//! `docs/internal/superpowers/specs/2026-10-05-slice-e-e06-acceptance.md`).
//! The E-slice authority cycle runs end to end on real components —
//! `central_infra::maintenance::Store`,
//! `MaintenanceApplyHandlerImpl`, `broker::journal::Journal` — with
//! the confirmer seam stubbed exactly as upstream's handler tests
//! stub it; physical-tier criteria (clean host, real PAM/TTY,
//! restore chain) are recorded `deferred-physical`, upgradeable by
//! maintainer runs. `CENTRAL_E06_EVIDENCE_DIR` emits
//! `slice-e-full-phase1-acceptance.json`.
//!
//! Upstream's file is `//go:build linux`; the port is portable —
//! `unix.Ucred` is `PeerIdentity`, and every component it composes
//! is ordinary Rust.

// Test-target relaxation, same as the other acceptance targets: a
// refused evaluation IS the assertion — unwrap/expect/panic are how
// a libtest body reports FailNow.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use central_adapter_linux::broker::journal::Journal;
use central_adapter_linux::broker::signing::{Ed25519Signer, SigningService};
use central_adapter_linux::helper::PeerIdentity;
use central_adapter_linux::helper::grant::CeremonyScope;
use central_adapter_linux::helper::maintenance::{
    MaintenanceApplyHandler, MaintenanceApplyHandlerImpl, MaintenanceApplyPamConfirmer,
    MaintenanceApplyRequest, MaintenanceApplyResult, MaintenanceProbes,
};
use central_adapter_linux::infra::advisory_fetch::{
    AdvisoryJournalWriter, AdvisoryTransitionRecorder,
};
use central_adapter_linux::infra::lifecycle::block_on;
use central_foundation::failure::Failure;
use central_infra::advisory::{
    CompatibilityMatrix, DenyPolicy, HostFacts, ReleaseTrust, Snapshot, State, TimeWitness,
    Verifier,
};
use central_infra::authority::{AuthorityTransitionPayload, CommittedReceipt};
use central_infra::maintenance as m;
use central_infra::port::TransitionRecorder;
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::macros::datetime;

const E06_EVIDENCE_ENV: &str = "CENTRAL_E06_EVIDENCE_DIR";
const E06_KEY_ID: &str = "central-release-authority/e06-test";

/// `e06Criterion` — one acceptance row; field order and the
/// `detail,omitempty` rule are upstream's.
#[derive(Serialize)]
struct E06Criterion {
    criterion: String,
    tier: String,
    status: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    detail: String,
}

/// `e06StubConfirmer` — upstream's stub returns `"apply-token"` when
/// the scope and operation are populated, `os.ErrInvalid` otherwise;
/// `verify_and_consume` always accepts.
struct E06StubConfirmer;

impl MaintenanceApplyPamConfirmer for E06StubConfirmer {
    fn confirm_maintenance_apply(
        &self,
        _peer: PeerIdentity,
        _deadline: Option<Instant>,
        scope: &CeremonyScope,
        operation_id: &str,
    ) -> Result<String, Failure> {
        if scope.instance_id.is_empty() || scope.target_id.is_empty() || operation_id.is_empty() {
            return Err(Failure::invalid(
                "e06_stub_confirmer",
                "scope or operation identity empty",
            ));
        }
        Ok("apply-token".to_owned())
    }

    fn verify_and_consume(&self, _token: &str) -> bool {
        true
    }
}

/// `e06ApplyReq` — the request shell; the mutator fills exactly one
/// of set/resume/rollback/abandon.
fn e06_apply_req() -> MaintenanceApplyRequest {
    MaintenanceApplyRequest {
        operation_id: uuid::Uuid::now_v7().to_string(),
        ..MaintenanceApplyRequest::default()
    }
}

/// `e06Peer` — upstream `&unix.Ucred{Pid: 77, Uid: 1000, Gid: 1000}`.
fn e06_peer() -> PeerIdentity {
    PeerIdentity {
        uid: 1000,
        gid: 1000,
        pid: 77,
    }
}

/// `e06Result` — the bounded surface a single apply produced.
struct E06Result {
    outcome: String,
    reason: String,
    result: MaintenanceApplyResult,
}

/// `e06Apply` — mutate then apply; decode the bounded result when the
/// response carries one.
fn e06_apply(
    h: &MaintenanceApplyHandlerImpl,
    mutate: impl FnOnce(&mut MaintenanceApplyRequest),
) -> E06Result {
    let mut req = e06_apply_req();
    mutate(&mut req);
    // Upstream's handler takes `context.Context`; the port's deadline
    // is the confirmer's ceremony bound — the stub ignores it.
    let resp = h.maintenance_apply(e06_peer(), Instant::now() + Duration::from_secs(120), req);
    let mut res = MaintenanceApplyResult::default();
    if let Some(raw) = &resp.result {
        res = serde_json::from_str(raw.get()).expect("apply result decode");
    }
    E06Result {
        outcome: resp.outcome,
        reason: resp.reason,
        result: res,
    }
}

/// The in-process `broker.Journal` behind the `AdvisoryJournalWriter`
/// port — upstream `advisory.NewTransitionRecorder(journal)` takes
/// the real journal directly; the RPC client is the production
/// *socket* path this suite deliberately does not need (same seam
/// `e04_advisory` uses).
struct DirectJournalWriter(Journal);

impl AdvisoryJournalWriter for DirectJournalWriter {
    /// `JournalWriter.AppendCommitted` — the writer stamps the record
    /// into the journal's own stream; sequence allocation and all
    /// provenance fields stay journal-owned exactly as over the wire.
    fn append_committed(
        &self,
        stream_id: &str,
        payload: &AuthorityTransitionPayload,
    ) -> Result<CommittedReceipt, Failure> {
        self.0.append_committed(stream_id, &mut payload.clone())
    }
}

/// `t.TempDir` — an owned dir under the system temp root the test
/// removes at end, upstream's auto-clean shape.
fn e06_tempdir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "central-e06-{name}-{}-{}",
        std::process::id(),
        uuid::Uuid::now_v7()
    ));
    mkdir_mode(&dir, 0o700).expect("e06 tempdir");
    dir
}

/// `os.MkdirAll(path, mode)` — mode applies at create only.
fn mkdir_mode(path: impl AsRef<Path>, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(mode)
        .create(path)
}

/// `os.WriteFile(..., mode)` — mode applies at create only.
fn write_mode(path: impl AsRef<Path>, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)
        .and_then(|mut f| std::io::Write::write_all(&mut f, bytes))
}

/// `TestE06Phase1Acceptance` — the authority cycle end to end.
#[test]
fn e06_phase1_acceptance() {
    let dir = e06_tempdir("store");
    // `NewStore` binds a path, not state — the handler and the test's
    // own loads share the same root exactly like upstream's *Store.
    let store = m::new_store(&dir);
    let observed = Arc::new(Mutex::new("16.15".to_owned()));
    let mut probes = MaintenanceProbes::new();
    {
        let observed = Arc::clone(&observed);
        probes.insert(
            "postgresql".to_owned(),
            Box::new(move || Ok(observed.lock().unwrap().clone()))
                as Box<dyn Fn() -> Result<String, Failure> + Send + Sync>,
        );
    }
    let h = MaintenanceApplyHandlerImpl {
        store: Some(m::new_store(&dir)),
        probes,
        images: None,
        pam: Some(Box::new(E06StubConfirmer)),
        scope: CeremonyScope {
            instance_id: "inst".to_owned(),
            target_id: "pg".to_owned(),
        },
    };
    store.load_or_bootstrap().expect("bootstrap");

    let mut criteria: Vec<E06Criterion> = Vec::new();
    macro_rules! pass {
        ($name:expr, $detail:expr) => {
            criteria.push(E06Criterion {
                criterion: $name.to_owned(),
                tier: "machine".to_owned(),
                status: "passed".to_owned(),
                detail: $detail.to_owned(),
            })
        };
    }
    macro_rules! defer_phys {
        ($name:expr, $detail:expr) => {
            criteria.push(E06Criterion {
                criterion: $name.to_owned(),
                tier: "physical".to_owned(),
                status: "deferred-physical".to_owned(),
                detail: $detail.to_owned(),
            })
        };
    }

    // 1. Compatibility matrix enforced: an out-of-range transition
    // refuses.
    let r = e06_apply(&h, |q| q.set = "postgresql=99".to_owned());
    assert_eq!(r.reason, m::REASON_UNLISTED, "unlisted transition");
    pass!(
        "compatibility-matrix-enforced",
        "postgresql=99 refused MAINTENANCE_TRANSITION_UNLISTED"
    );

    // 2. Patch cycle: apply → applied row → matrix commit.
    let r = e06_apply(&h, |q| q.set = "postgresql=16.15".to_owned());
    assert!(
        r.outcome == "success" && !r.result.attempt_id.is_empty(),
        "patch: {:?} {:?}",
        r.outcome,
        r.reason
    );
    let patch_id = r.result.attempt_id.clone();
    let (matrix, _) = store.load_or_bootstrap().expect("load");
    let pg = matrix
        .entry_by_name("postgresql")
        .expect("postgresql entry");
    assert!(
        pg.current == "16.15" && matrix.sequence_num == 2,
        "matrix after patch: {:?} seq={}",
        pg.current,
        matrix.sequence_num
    );
    pass!(
        "patch-apply-committed",
        format!("postgresql 16.14→16.15, seq 2, attempt {patch_id}")
    );

    // 3. Rollback: host observed back on 16.14, matrix restores.
    *observed.lock().unwrap() = "16.14".to_owned();
    let r = e06_apply(&h, |q| q.rollback = patch_id.clone());
    assert!(
        r.outcome == "success" && r.result.mode == "rollback",
        "rollback: {:?} {:?}",
        r.outcome,
        r.reason
    );
    let (matrix, _) = store.load_or_bootstrap().expect("load");
    let pg = matrix
        .entry_by_name("postgresql")
        .expect("postgresql entry");
    assert!(
        pg.current == "16.14" && matrix.sequence_num == 3,
        "matrix after rollback: {:?} seq={}",
        pg.current,
        matrix.sequence_num
    );
    let (_, status) = store.find_attempt(&patch_id).expect("find attempt");
    assert_eq!(status, "rollback_applied", "attempt status");
    pass!(
        "patch-rollback-cycle",
        "rollback restored 16.14 under same attempt id, seq 3"
    );

    // 4. Abandon a pending attempt (journal the crash-window
    // directly).
    let pending = m::Attempt {
        attempt_id: uuid::Uuid::new_v4().to_string(),
        dependency: "postgresql".to_owned(),
        from: "16.14".to_owned(),
        to: "16.15".to_owned(),
        gate: "g".to_owned(),
        ..m::Attempt::default()
    };
    store
        .append_attempt(m::OP_PATCH_PENDING, &pending, "", "")
        .expect("append pending");
    let r = e06_apply(&h, |q| q.abandon = pending.attempt_id.clone());
    assert!(
        r.outcome == "success" && r.result.mode == "abandon",
        "abandon: {:?} {:?}",
        r.outcome,
        r.reason
    );
    pass!(
        "abandon-pending-attempt",
        "pending patch attempt closed patch_abandoned"
    );

    // 5. Advisory lifecycle spot-check: current and hard_expired
    // through the real verifier + journaled recorder.
    let mut seed = [0u8; 32];
    rustix::rand::getrandom(&mut seed, rustix::rand::GetRandomFlags::empty())
        .expect("suite key entropy");
    let suite_key = SigningKey::from_bytes(&seed);
    let verifier = Verifier::for_testing(ReleaseTrust {
        key_id: E06_KEY_ID.to_owned(),
        protocol: "central.security-advisory/v1".to_owned(),
        public_key: suite_key.verifying_key().to_bytes(),
        release_authority_digest: String::new(),
    });
    let now = datetime!(2026-10-05 12:00:00 UTC);
    let journal_dir = e06_tempdir("journal");
    let journal = Journal::new(
        journal_dir.clone(),
        Arc::new(SigningService::new()),
        Some(Arc::new(Ed25519Signer::new().expect("journal signer"))),
    );
    let recorder = AdvisoryTransitionRecorder::new(DirectJournalWriter(journal));
    for (expires, want) in [
        (now + time::Duration::days(30), State::Current),
        (now - time::Duration::days(30), State::HardExpired),
    ] {
        let env = e06_mint_bundle(&suite_key, now - time::Duration::days(40), expires);
        let (bundle, vres) = verifier.verify_snapshot(&Snapshot {
            generation_id: "e06".to_owned(),
            selector_digest: "e06".to_owned(),
            bundle: env.env.clone(),
            signature: env.sig.clone().into_bytes(),
        });
        let result = if vres.state == State::Current {
            verifier.evaluate_verified(
                bundle.as_ref().expect("verified bundle on current"),
                &HostFacts::default(),
                &TimeWitness::default(),
                now,
            )
        } else {
            vres
        };
        assert_eq!(result.state, want, "advisory stage");
        block_on(recorder.record(&result, None, &HostFacts::default()))
            .expect("journal advisory evaluation");
    }
    pass!(
        "advisory-lifecycle-stages",
        "current + hard_expired evaluated and journaled"
    );

    // 6. Acceptance index: the ported gate's archived evidence must
    // exist in-tree. Upstream indexes the SD + SC-G3 verdicts; this
    // repository does not copy upstream gate evidence (it is
    // authoritative in the upstream tree) — the in-tree artifact is
    // the R4 recovery matrix this workspace's own acceptance run
    // committed.
    const PRIOR_EVIDENCE: &[&str] = &["../../docs/internal/evidence/phase-2-recovery-matrix.json"];
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for &ev in PRIOR_EVIDENCE {
        let raw = std::fs::read(manifest.join(ev))
            .unwrap_or_else(|e| panic!("acceptance evidence missing: {ev}: {e}"));
        #[derive(serde::Deserialize)]
        struct Probe {
            #[serde(default)]
            schema_version: String,
            #[serde(default)]
            schema: String,
        }
        // Historical evidence uses "schema" (SC-G*) while newer
        // artifacts use "schema_version" — either marks a parseable
        // manifest.
        let probe: Probe = serde_json::from_slice(&raw)
            .unwrap_or_else(|e| panic!("acceptance evidence {ev} does not parse: {e}"));
        assert!(
            !(probe.schema_version.is_empty() && probe.schema.is_empty()),
            "acceptance evidence {ev} does not parse"
        );
    }
    pass!(
        "prior-acceptance-evidence-indexed",
        "phase-2 recovery matrix evidence present and parsing"
    );

    // Physical-tier criteria — recorded, not run here.
    defer_phys!(
        "end-to-end-clean-host",
        "Slice A→E on fresh host — maintainer reference-host run (slice-c-maintainer-tasks.md)"
    );
    defer_phys!(
        "pam-physical-tty-ceremony",
        "real PAM + physical console — production tier, procedure documented"
    );
    defer_phys!(
        "restore-chain-c01-c06",
        "SC-G3 Accepted (Docker profile); physical run upgrades"
    );
    defer_phys!(
        "destructive-d01-d07-pam",
        "SD Accepted (Docker profile); physical run upgrades"
    );
    defer_phys!(
        "security-sentinel-minimum-profile",
        "A07/B01/B06 sentinel + capacity/throughput bounds — physical acceptance run"
    );

    let evidence_dir = std::env::var(E06_EVIDENCE_ENV).unwrap_or_default();
    if !evidence_dir.is_empty() {
        mkdir_mode(&evidence_dir, 0o755).expect("evidence dir");
        let (matrix, _) = store.load_or_bootstrap().expect("load");
        let digest = matrix.digest().expect("matrix digest");
        #[derive(Serialize)]
        struct Evidence {
            schema_version: &'static str,
            candidate_commit: String,
            criteria: Vec<E06Criterion>,
            matrix_digest: String,
            matrix_sequence: u64,
        }
        let evidence = Evidence {
            schema_version: "slice-e-phase1-acceptance/v1",
            candidate_commit: std::env::var("GITHUB_SHA").unwrap_or_default(),
            criteria,
            matrix_digest: digest,
            matrix_sequence: matrix.sequence_num,
        };
        let raw = serde_json::to_string_pretty(&evidence).expect("evidence marshal");
        write_mode(
            Path::new(&evidence_dir).join("slice-e-full-phase1-acceptance.json"),
            format!("{raw}\n").as_bytes(),
            0o644,
        )
        .expect("evidence write");
    }
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&journal_dir);
}

/// `e06Envelope` — the minted envelope bytes plus the base64
/// signature (upstream returns both; the snapshot consumes the
/// signature text, not the envelope member).
struct E06Envelope {
    env: Vec<u8>,
    sig: String,
}

/// `signedBundle` — the same shape `central-advisory-sign` marshals.
#[derive(Serialize)]
struct SignedBundle {
    schema_version: i64,
    key_id: String,
    issued_at: String,
    expires_at: String,
    compatibility: CompatibilityMatrix,
    emergency_deny: DenyPolicy,
}

/// `e06MintBundle` — canonical JCS bundle → sha256 →
/// `central.security-advisory/v1|bundle|SHA-256:<hex>` message →
/// `ed25519.Sign` → base64 — the identical mint path `e04_advisory`
/// replicates from the sign tool.
fn e06_mint_bundle(
    priv_key: &SigningKey,
    issued: time::OffsetDateTime,
    expires: time::OffsetDateTime,
) -> E06Envelope {
    let bundle = SignedBundle {
        schema_version: 1,
        key_id: E06_KEY_ID.to_owned(),
        issued_at: issued
            .to_offset(time::UtcOffset::UTC)
            .replace_nanosecond(0)
            .expect("issued_at nanos")
            .format(&Rfc3339)
            .expect("issued_at"),
        expires_at: expires
            .to_offset(time::UtcOffset::UTC)
            .replace_nanosecond(0)
            .expect("expires_at nanos")
            .format(&Rfc3339)
            .expect("expires_at"),
        compatibility: CompatibilityMatrix::default(),
        emergency_deny: DenyPolicy::default(),
    };
    let raw = serde_json::to_vec(&bundle).expect("marshal bundle");
    let value: serde_json::Value = serde_json::from_slice(&raw).expect("bundle value");
    let canonical = central_foundation::jcs::canonicalize(&value).expect("canonicalize");
    let sum = Sha256::digest(&canonical);
    let sig = priv_key
        .sign(
            format!(
                "central.security-advisory/v1|bundle|SHA-256:{}",
                hex_encode(&sum)
            )
            .as_bytes(),
        )
        .to_bytes();
    #[derive(Serialize)]
    struct Envelope<'a> {
        bundle: &'a serde_json::value::RawValue,
        signature: String,
    }
    let bundle_raw =
        serde_json::value::RawValue::from_string(String::from_utf8(raw).expect("bundle utf8"))
            .expect("bundle raw");
    let sig_b64 = b64_encode(&sig);
    let env = serde_json::to_vec(&Envelope {
        bundle: &bundle_raw,
        signature: sig_b64.clone(),
    })
    .expect("marshal envelope");
    E06Envelope { env, sig: sig_b64 }
}

// Go `base64.StdEncoding`/`hex.EncodeToString` helpers — private to
// the suite exactly as e04 keeps them (upstream uses the std
// library at both ends; the workspace carries no hex/base64 crate).
fn b64_encode(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk.len();
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let quad = [
            b[0] >> 2,
            ((b[0] & 0x03) << 4) | (b[1] >> 4),
            ((b[1] & 0x0f) << 2) | (b[2] >> 6),
            b[2] & 0x3f,
        ];
        for (i, idx) in quad.iter().enumerate() {
            out.push(if i > n { '=' } else { A[*idx as usize] as char });
        }
    }
    out
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}
