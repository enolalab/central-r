//! A07 — the authority denial ladder (threats T17/T23, upstream
//! `helper_authority_test.go`, `init_test.go`, `init_confirm_portable_test.go`,
//! `delete_test.go`, `grant_flock_unix_test.go`, `denysafe.go`,
//! `infralifecycle` barrier/admission gates, `hardening.go`).
//!
//! Every denial surface the R5 slice exports, asserted with the exact
//! wire tokens: the closed helper matrix (`UNSUPPORTED_IN_THIS_SLICE`
//! exit 5), the deny-safe gate (`DENY_SAFE_ACTIVE` exit 7), the init
//! reason ladder (`INSTANCE_BROKEN`/`AUTHORITY_DENIED`/
//! `CONFIRMATION_MISMATCH`/`ALREADY_INITIALIZED`), grant
//! TTL/one-use/scope rules, the lifecycle barrier veto, capacity and
//! admission denials, and the sandbox envelope's closed refusals.

// `allow-*-in-tests` only reaches `#[test]` fns — the fixture helpers
// in this binary unwrap/expect deliberately: an unbuildable fixture
// is the failure.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod a07;

use a07::*;
use central_adapter_linux::genesis::{GenesisEnv, GenesisOwners, GenesisRoots};
use central_adapter_linux::helper::audit::is_deny_safe_active;
use central_adapter_linux::helper::grant::{self, GrantKind, GrantScope, GrantStore};
use central_adapter_linux::helper::init::{
    self, GenesisInitHandler, InitConfirmer, InitConsole, InitHandler, InitRequest,
};
use central_adapter_linux::helper::protocol::{PrepareRequest, Request};
use central_adapter_linux::helper::{self, PeerIdentity, PeerPolicy, Server, verb};
use central_adapter_linux::infra::lifecycle::{
    self, ActiveReceiptReader, AdvisoryEvaluator, FileBarrier, FilesystemCapacity,
    ReceiptAdmission, ReceiptInspector,
};
use central_adapter_linux::sandbox::envelope;
use central_foundation::failure::{Failure, FailureKind};
use central_infra::advisory;
use central_infra::authority::{PrepareOperation, PrepareOperationPhase};
use central_infra::domain::{
    B03_REQUIRED_SERVICE_MODES, DependencyReceipt, LifecycleBinding, OciInventory,
    PreparedDependencySet, PreparedMode,
};
use central_infra::port::{
    AdmissionRequest, LifecycleAdmission, LifecycleBarrier, LifecycleCapacity,
};
use serde_json::value::RawValue;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// An operator-admitting `Server` — the test peer is the exact
/// configured operator pair.
fn operator_server() -> Server {
    let mut server = Server::new();
    server.peer_policy = Some(PeerPolicy {
        daemon_uid: euid() + 1,
        operator_uid: euid(),
        operator_gid: egid(),
    });
    server
}

/// A daemon-admitting `Server` — the daemon arm takes our uid only.
fn daemon_server() -> Server {
    let mut server = Server::new();
    server.peer_policy = Some(PeerPolicy {
        daemon_uid: euid(),
        operator_uid: euid() + 1,
        operator_gid: egid(),
    });
    server
}

fn req(op: &str, v: &str) -> Request {
    Request {
        operation_id: op.to_owned(),
        verb: v.to_owned(),
        payload: None,
    }
}

fn req_payload(op: &str, v: &str, payload: &str) -> Request {
    Request {
        operation_id: op.to_owned(),
        verb: v.to_owned(),
        payload: RawValue::from_string(payload.to_owned()).ok(),
    }
}

// ---------------------------------------------------------------------------
// The closed matrix — every unsupported verb answers exit 5
// ---------------------------------------------------------------------------

/// An unregistered verb is denied (not deferred) with the exact
/// `UNSUPPORTED_IN_THIS_SLICE` reason at exit 5 — the closed matrix
/// is the whole protocol surface. The verb lands on the daemon arm
/// (`PeerArm::for_verb` defaults), so an operator peer is closed
/// unanswered before the matrix is even consulted.
#[test]
fn helper_matrix_denies_unregistered_verbs_exact() {
    for v in ["no-such-verb", "made-up-operation"] {
        let mut line = serde_json::to_vec(&req("op-u", v)).expect("marshal");
        line.push(b'\n');
        assert_eq!(
            helper_exchange(&operator_server(), &line),
            None,
            "an unregistered verb under an operator peer closes unanswered"
        );
    }
    let server = daemon_server();
    for v in ["no-such-verb", "made-up-operation"] {
        let resp = helper_request(&server, &req("op-u", v));
        assert_eq!(resp.operation_id, "op-u");
        assert_eq!(resp.outcome, "denied", "verb {v}");
        assert_eq!(resp.exit_code, 5, "verb {v}");
        assert_eq!(resp.reason, "UNSUPPORTED_IN_THIS_SLICE", "verb {v}");
    }
}

/// Every registered-but-unimplemented verb on the operator arm defers
/// with the same reason. The maintenance verbs Task 7 ported
/// (`backup-create` … `restore-abandon`), Task 11's destructive set
/// (`wipe`, `backup-delete`, `backup-prune`), Task 12's
/// export/import pair, and the Task-13 set (`security-update`,
/// `state-audit`, `security-rescue`, `maintenance-plan`,
/// `maintenance-apply`) are implemented now — they answer with their
/// own refusal codes and are asserted elsewhere.
#[test]
fn helper_matrix_defers_unimplemented_operator_verbs_exact() {
    let server = operator_server();
    // `prepare` is conditionally implemented through `Server::prepare`
    // upstream, so its matrix row stays closed; `trust-install` is the
    // one plain unimplemented verb left on this arm.
    for v in [verb::PREPARE, verb::TRUST_INSTALL] {
        let resp = helper_request(&server, &req("op-d", v));
        assert_eq!(resp.outcome, "deferred", "verb {v}");
        assert_eq!(resp.exit_code, 5, "verb {v}");
        assert_eq!(resp.reason, "UNSUPPORTED_IN_THIS_SLICE", "verb {v}");
    }
}

/// The eight daemon-arm verbs — every verb the arm table does not
/// name lands on `PeerArm::Daemon`: an operator peer is closed
/// unanswered (see `a07_peers`); under the daemon identity the same
/// verbs get the matrix's deferred `UNSUPPORTED_IN_THIS_SLICE`.
#[test]
fn helper_matrix_defers_unimplemented_daemon_verbs_exact() {
    let server = daemon_server();
    for v in [
        verb::DOCTOR,
        verb::SECURITY_RESCUE_CLEANUP,
        verb::RUNTIME_STAGE,
        verb::RUNTIME_START,
        verb::RUNTIME_STOP,
        verb::INIT_STATUS,
        verb::INIT_RESUME,
        verb::INIT_ABANDON,
    ] {
        let resp = helper_request(&server, &req("op-dm", v));
        assert_eq!(resp.outcome, "deferred", "verb {v}");
        assert_eq!(resp.exit_code, 5, "verb {v}");
        assert_eq!(resp.reason, "UNSUPPORTED_IN_THIS_SLICE", "verb {v}");
    }

    // The same verbs under the operator policy are closed unanswered —
    // the daemon arm never admits an operator identity.
    let mut line = serde_json::to_vec(&req("op-dmx", verb::DOCTOR)).expect("marshal");
    line.push(b'\n');
    assert_eq!(
        helper_exchange(&operator_server(), &line),
        None,
        "a daemon verb under an operator peer closes unanswered"
    );
}

/// The implemented-but-unwired arms answer upstream's own deferred
/// and denied shapes: lifecycle's service-unavailable deferral, the
/// init deferral, and the collapsed `AUTHORITY_DENIED` the browser
/// and bootstrap-show paths produce.
#[test]
fn helper_dispatch_implemented_but_handlerless_verbs() {
    let server = operator_server();
    // No lifecycle handler: the R5 implemented-but-unwired arm
    // answers `LIFECYCLE_SERVICE_UNAVAILABLE`, upstream's deferred
    // reason.
    for v in [verb::UP, verb::DOWN, verb::STATUS] {
        let resp = helper_request(&server, &req("op-l", v));
        assert_eq!(resp.outcome, "deferred", "verb {v}");
        assert_eq!(resp.exit_code, 5);
        assert_eq!(resp.reason, "LIFECYCLE_SERVICE_UNAVAILABLE", "verb {v}");
    }
    // `init` with no init handler defers UNSUPPORTED.
    let resp = helper_request(&server, &req("op-i", verb::INIT));
    assert_eq!(resp.outcome, "deferred");
    assert_eq!(resp.reason, "UNSUPPORTED_IN_THIS_SLICE");
    // `browser-open`/`bootstrap-show` without handlers deny
    // AUTHORITY_DENIED — the collapsed authority refusal, never a
    // handler panic.
    for v in [verb::BROWSER_OPEN, verb::BOOTSTRAP_SHOW] {
        let resp = helper_request(&server, &req("op-b", v));
        assert_eq!(resp.outcome, "denied", "verb {v}");
        assert_eq!(resp.exit_code, 7);
        assert_eq!(resp.reason, "AUTHORITY_DENIED", "verb {v}");
    }
    // The R6 task-2 verbs are implemented arms: with no handler
    // injected each defers with its own upstream reason — never the
    // closed-slice `UNSUPPORTED_IN_THIS_SLICE`. The Slice D and
    // Task-13 verbs defer the same way (`s.Wipe == nil`,
    // `s.Audit == nil`, `s.Rescue == nil`, `s.Maintenance* == nil`,
    // `s.SecurityUpdate == nil`).
    for (v, reason) in [
        (verb::MIGRATE_LAUNCH, "MIGRATION_LAUNCH_UNAVAILABLE"),
        (verb::MIGRATE_READ_OUTCOME, "MIGRATION_OUTCOME_UNAVAILABLE"),
        (verb::WIPE, "WIPE_UNAVAILABLE"),
        (verb::BACKUP_EXPORT, "EXPORT_UNAVAILABLE"),
        (verb::BACKUP_IMPORT, "IMPORT_UNAVAILABLE"),
        (verb::BACKUP_DELETE, "DELETE_UNAVAILABLE"),
        (verb::BACKUP_PRUNE, "PRUNE_UNAVAILABLE"),
        (verb::SECURITY_UPDATE, "SECURITY_UPDATE_UNAVAILABLE"),
        (verb::STATE_AUDIT, "AUDIT_UNAVAILABLE"),
        (verb::SECURITY_RESCUE, "RESCUE_UNAVAILABLE"),
        (verb::MAINTENANCE_PLAN, "MAINTENANCE_UNAVAILABLE"),
        (verb::MAINTENANCE_APPLY, "MAINTENANCE_UNAVAILABLE"),
    ] {
        let resp = helper_request(&server, &req("op-m", v));
        assert_eq!(resp.outcome, "deferred", "verb {v}");
        assert_eq!(resp.exit_code, 5, "verb {v}");
        assert_eq!(resp.reason, reason, "verb {v}");
    }
}

/// A malformed lifecycle payload refuses `INVALID_LIFECYCLE_REQUEST`
/// before any handler is consulted. (Unknown fields are upstream's
/// one tolerated quirk on this parser, so the smuggle uses a wrong
/// value type.)
#[test]
fn helper_lifecycle_invalid_request_denied() {
    let server = operator_server();
    let resp = helper_request(
        &server,
        &Request {
            operation_id: "op-bad".to_owned(),
            verb: verb::UP.to_owned(),
            payload: RawValue::from_string("{\"config_binding\":123}".to_owned()).ok(),
        },
    );
    assert_eq!(resp.outcome, "denied");
    assert_eq!(resp.exit_code, 7);
    assert_eq!(resp.reason, "INVALID_LIFECYCLE_REQUEST");
}

/// A malformed prepare payload refuses `INVALID_PREPARE_REQUEST`
/// when the prepare arm is installed — the parse runs before the
/// handler, upstream's order.
#[test]
fn helper_prepare_invalid_request_denied() {
    struct NullPrepare;
    impl helper::server::PrepareHandler for NullPrepare {
        fn prepare(
            &self,
            _peer: PeerIdentity,
            _deadline: Instant,
            _req: &Request,
            _pr: PrepareRequest,
        ) -> helper::Response {
            helper::Response::deferred("x", "unreachable")
        }
    }
    let mut server = operator_server();
    server.prepare = Some(Box::new(NullPrepare));
    let resp = helper_request(
        &server,
        &Request {
            operation_id: "op-p".to_owned(),
            verb: verb::PREPARE.to_owned(),
            payload: RawValue::from_string("{\"bogus\":1}".to_owned()).ok(),
        },
    );
    assert_eq!(resp.outcome, "denied");
    assert_eq!(resp.exit_code, 7);
    assert_eq!(resp.reason, "INVALID_PREPARE_REQUEST");
}

// ---------------------------------------------------------------------------
// The deny-safe gate — fail-closed mutating verbs, read-only allowed
// ---------------------------------------------------------------------------

/// An active deny-safe record denies mutating verbs
/// (`DENY_SAFE_ACTIVE`, exit 7) while the read-only allowlist still
/// reaches its handlers — upstream `denySafeAdmitsHelper`.
#[test]
fn deny_safe_gate_denies_mutating_and_admits_readonly() {
    let scratch = Scratch::new("deny-safe");
    scratch.file(
        "deny-safe.json",
        br#"{"active":true,"entered_at":"2026-01-01T00:00:00Z","trigger_code":"T"}"#,
        0o600,
    );
    let mut server = operator_server();
    server.deny_safe_dir = Some(scratch.path().to_string_lossy().into_owned());

    // `up` is mutating → denied at the gate.
    let resp = helper_request(&server, &req("op-safe", verb::UP));
    assert_eq!(resp.outcome, "denied");
    assert_eq!(resp.exit_code, 7);
    assert_eq!(resp.reason, "DENY_SAFE_ACTIVE");

    // `status` is allowlisted → passes the gate, reaches the
    // (absent) handler's own answer.
    let resp = helper_request(&server, &req("op-safe", verb::STATUS));
    assert_eq!(resp.outcome, "deferred");
    assert_eq!(resp.reason, "LIFECYCLE_SERVICE_UNAVAILABLE");

    // The rest of upstream's `denySafeAdmitsHelper` table: rescue and
    // maintenance-plan admit unconditionally; audit admits unless it
    // asks for a repair — and an unparseable audit payload still
    // passes the gate because dispatch denies it more precisely.
    for (req, reason) in [
        (
            req("op-safe", verb::SECURITY_RESCUE),
            advisory::REASON_RESCUE_UNAVAILABLE,
        ),
        (
            req("op-safe", verb::MAINTENANCE_PLAN),
            "MAINTENANCE_UNAVAILABLE",
        ),
        (
            req_payload("op-safe", verb::STATE_AUDIT, "{}"),
            "AUDIT_UNAVAILABLE",
        ),
        (
            req_payload("op-safe", verb::STATE_AUDIT, "{\"repair\":false}"),
            "AUDIT_UNAVAILABLE",
        ),
        (
            // Valid wire JSON that `parse_audit_request` cannot
            // decode — upstream's `{oops` case, expressed on the wire.
            req_payload("op-safe", verb::STATE_AUDIT, "\"x\""),
            "AUDIT_UNAVAILABLE",
        ),
    ] {
        let resp = helper_request(&server, &req);
        assert_eq!(resp.outcome, "deferred", "verb {}", req.verb);
        assert_eq!(resp.reason, reason, "verb {}", req.verb);
    }

    // `doctor` sits on the daemon arm, so it needs a daemon-admitting
    // server to reach the gate at all — admitted, it lands on the
    // matrix's own answer, not DENY_SAFE_ACTIVE.
    let mut daemon = daemon_server();
    daemon.deny_safe_dir = Some(scratch.path().to_string_lossy().into_owned());
    let resp = helper_request(&daemon, &req("op-safe", verb::DOCTOR));
    assert_ne!(resp.reason, "DENY_SAFE_ACTIVE", "doctor must pass the gate");
    assert_eq!(resp.reason, "UNSUPPORTED_IN_THIS_SLICE");

    // The deny side: every mutating verb — including the Task-13
    // security-update/maintenance-apply pair and a repair audit —
    // collapses to DENY_SAFE_ACTIVE before reaching a handler.
    for req in [
        req("op-safe", verb::DOWN),
        req("op-safe", verb::WIPE),
        req("op-safe", verb::BACKUP_EXPORT),
        req("op-safe", verb::BACKUP_DELETE),
        req("op-safe", verb::BACKUP_PRUNE),
        req("op-safe", verb::SECURITY_UPDATE),
        req("op-safe", verb::MAINTENANCE_APPLY),
        req_payload("op-safe", verb::STATE_AUDIT, "{\"repair\":true}"),
    ] {
        let resp = helper_request(&server, &req);
        assert_eq!(resp.outcome, "denied", "verb {}", req.verb);
        assert_eq!(resp.exit_code, 7, "verb {}", req.verb);
        assert_eq!(resp.reason, "DENY_SAFE_ACTIVE", "verb {}", req.verb);
    }

    // `is_deny_safe_active` itself: absent → inactive; active →
    // active; corrupt → ACTIVE (the gate fails closed — a lock that
    // cannot be read does not open).
    let empty = Scratch::new("deny-safe-empty");
    assert!(!is_deny_safe_active(empty.path().to_str().unwrap()));
    assert!(is_deny_safe_active(scratch.path().to_str().unwrap()));
    scratch.file("deny-safe.json", b"{corrupt", 0o600);
    assert!(
        is_deny_safe_active(scratch.path().to_str().unwrap()),
        "a corrupt state file must fail closed"
    );
}

// ---------------------------------------------------------------------------
// The init ladder — genesis denials with their exit classes
// ---------------------------------------------------------------------------

struct DenyingConfirmer(Failure);
impl InitConfirmer for DenyingConfirmer {
    fn confirm_init(
        &self,
        _peer: PeerIdentity,
        _deadline: Option<Instant>,
        _operation_id: &str,
    ) -> Result<String, Failure> {
        Err(Failure::denied(self.0.code(), self.0.message().to_owned()))
    }
    fn verify_and_consume(&self, _token: &str) -> bool {
        false
    }
}
struct NullConsole;
impl InitConsole for NullConsole {
    fn write_init_line(&self, _peer: PeerIdentity, _line: &[u8]) -> Result<(), Failure> {
        Ok(())
    }
}

fn genesis_handler(scratch: &Scratch, confirmer: Box<dyn InitConfirmer>) -> GenesisInitHandler {
    GenesisInitHandler {
        env: GenesisEnv {
            roots: GenesisRoots {
                state_root: scratch.join("state/v1").to_string_lossy().into_owned(),
                protected_root: scratch.join("protected/v1").to_string_lossy().into_owned(),
            },
            owners: GenesisOwners {
                root_uid: euid(),
                root_gid: egid(),
                runtime_uid: euid(),
                runtime_gid: egid(),
            },
            lock_wait: Duration::from_secs(2),
            ensure_identities: Arc::new(|| Ok(())),
            free_bytes: Arc::new(|_| Ok(u64::MAX)),
            ..GenesisEnv::production()
        },
        confirmer,
        console: Box::new(NullConsole),
        grants: String::new(),
        boot_id: None,
    }
}

fn init_peer() -> PeerIdentity {
    PeerIdentity {
        uid: euid(),
        gid: egid(),
        pid: self_pid(),
    }
}

/// The absent host's ceremony refusal maps to `AUTHORITY_DENIED`
/// exit 7 — a mistyped phrase maps to `CONFIRMATION_MISMATCH`;
/// upstream's two exact branches.
#[test]
fn genesis_init_ceremony_denials_map_to_exact_reasons() {
    let scratch = Scratch::new("init-ladder");
    let deadline = Instant::now() + Duration::from_secs(5);

    let handler = genesis_handler(
        &scratch,
        Box::new(DenyingConfirmer(Failure::denied(
            "sys_tty_ceremony",
            "refused",
        ))),
    );
    let resp = handler.init(
        init_peer(),
        deadline,
        InitRequest {
            operation_id: "op-init".to_owned(),
        },
    );
    assert_eq!(resp.outcome, "denied");
    assert_eq!(resp.exit_code, 7);
    assert_eq!(resp.reason, "AUTHORITY_DENIED");

    let handler = genesis_handler(
        &scratch,
        Box::new(DenyingConfirmer(Failure::denied(
            "sys_tty_init_mismatch",
            "mismatch",
        ))),
    );
    let resp = handler.init(
        init_peer(),
        deadline,
        InitRequest {
            operation_id: "op-init".to_owned(),
        },
    );
    assert_eq!(resp.outcome, "denied");
    assert_eq!(resp.exit_code, 7);
    assert_eq!(resp.reason, "CONFIRMATION_MISMATCH");
}

/// A broken host refuses init before any ceremony:
/// `INSTANCE_BROKEN`, exit 3 — and the failure path names it.
#[test]
fn genesis_init_broken_host_denied() {
    let scratch = Scratch::new("init-broken");
    // Protected instance without a state peer — the broken shape.
    scratch.dir("protected", 0o700);
    scratch.dir("protected/v1", 0o700);
    scratch.dir("protected/v1/instances", 0o700);
    scratch.dir("protected/v1/instances/inst-1", 0o700);
    let handler = genesis_handler(
        &scratch,
        Box::new(DenyingConfirmer(Failure::denied("x", "never reached"))),
    );
    let resp = handler.init(
        init_peer(),
        Instant::now() + Duration::from_secs(5),
        InitRequest {
            operation_id: "op-init".to_owned(),
        },
    );
    assert_eq!(resp.outcome, "denied");
    assert_eq!(resp.exit_code, 3);
    assert_eq!(resp.reason, "INSTANCE_BROKEN");
}

/// `new_init_response(already=true)` is the present-host answer:
/// `success`, exit 0, reason `ALREADY_INITIALIZED`, the three
/// contract IDs in marshal order.
#[test]
fn init_present_host_answers_already_initialized() {
    let result = init::InitResult {
        instance_id: "i-1".to_owned(),
        config_binding_id: "c-1".to_owned(),
        init_operation_id: "o-1".to_owned(),
    };
    let resp = init::new_init_response("op", &result, true);
    assert_eq!(resp.outcome, "success");
    assert_eq!(resp.exit_code, 0);
    assert_eq!(resp.reason, "ALREADY_INITIALIZED");
    let result: serde_json::Value =
        serde_json::from_str(resp.result.as_ref().unwrap().get()).unwrap();
    assert_eq!(result["instance_id"], "i-1");
    assert_eq!(result["config_binding_id"], "c-1");
    assert_eq!(result["init_operation_id"], "o-1");
}

/// `genesis_mode_denial` — every non-init verb's answer before
/// genesis: `HELPER_UNAVAILABLE`, exit 3.
#[test]
fn genesis_mode_denial_is_helper_unavailable() {
    let resp = init::genesis_mode_denial(&req("op", "status"));
    assert_eq!(resp.outcome, "denied");
    assert_eq!(resp.exit_code, 3);
    assert_eq!(resp.reason, "HELPER_UNAVAILABLE");
}

/// `parse_init_request` — a smuggled payload field fails the request
/// rather than being ignored.
#[test]
fn init_request_smuggled_field_refused() {
    let err = init::parse_init_request(&Request {
        operation_id: "op".to_owned(),
        verb: verb::INIT.to_owned(),
        payload: RawValue::from_string("{\"surprise\":true}".to_owned()).ok(),
    })
    .err()
    .expect("a smuggled field must fail the init request");
    assert!(err.contains("invalid init payload"), "{err}");
}

// ---------------------------------------------------------------------------
// Grants — the consent store's TTL/one-use/scope/MAC denials
// ---------------------------------------------------------------------------

fn open_store(scratch: &Scratch) -> GrantStore {
    let dir = scratch.dir("store", 0o700);
    GrantStore::open(dir.to_str().unwrap(), euid(), egid()).expect("store")
}

fn lifecycle_scope(op: &str) -> GrantScope {
    GrantScope {
        kind: GrantKind::Lifecycle,
        instance_id: "i-1".to_owned(),
        target_id: "t-1".to_owned(),
        operation_id: op.to_owned(),
    }
}

/// `Issue` rejects the init kind (it goes through `IssueInit`) and an
/// unknown kind string — the closed `sys_grant_issue`/`sys_grant_kind`
/// invalids.
#[test]
fn grant_issue_validation_denials() {
    let scratch = Scratch::new("grant-issue");
    let store = open_store(&scratch);
    let err = store
        .issue(
            &GrantScope {
                kind: GrantKind::Init,
                ..GrantScope::default()
            },
            "boot-1",
            "rel-1",
            Duration::from_secs(60),
        )
        .unwrap_err();
    assert_eq!(err.code(), "sys_grant_issue");
    assert!(err.message().contains("IssueInit"), "{}", err.message());

    let err = grant::parse_grant_kind("nonsense").unwrap_err();
    assert_eq!(err.code(), "sys_grant_kind");
}

/// One-use consumption: the grant verifies exactly once; a second
/// consume — and a consume under a different scope or a different
/// boot — are all `sys_grant_none`, upstream's `ErrNoGrant`.
#[test]
fn grant_one_use_and_scope_denials() {
    let scratch = Scratch::new("grant-consume");
    let store = open_store(&scratch);
    let scope = lifecycle_scope("op-1");
    store
        .issue(&scope, "boot-1", "rel-1", Duration::from_secs(3600))
        .expect("issue");

    // Wrong boot: no valid grant.
    let err = store
        .consume(&scope, "boot-2", euid(), self_pid())
        .unwrap_err();
    assert_denial(
        &err,
        FailureKind::Denied,
        "sys_grant_none",
        "no valid grant",
    );

    // Wrong kind: no valid grant.
    let mut other = lifecycle_scope("op-1");
    other.kind = GrantKind::Prepare;
    let err = store
        .consume(&other, "boot-1", euid(), self_pid())
        .unwrap_err();
    assert_denial(&err, FailureKind::Denied, "sys_grant_none", "");

    // The real consume works exactly once.
    store
        .consume(&scope, "boot-1", euid(), self_pid())
        .expect("consume");
    let err = store
        .consume(&scope, "boot-1", euid(), self_pid())
        .unwrap_err();
    assert_denial(
        &err,
        FailureKind::Denied,
        "sys_grant_none",
        "no valid grant",
    );
}

/// Expiry: a grant past its TTL is no valid grant — consumed or not,
/// the store reports `ErrNoGrant`, never an expired consent.
#[test]
fn grant_expiry_denied() {
    let scratch = Scratch::new("grant-expire");
    let store = open_store(&scratch);
    let scope = lifecycle_scope("op-1");
    // The clock is the store's own wall clock: a 1ms TTL lapses
    // before the consume.
    store
        .issue(&scope, "boot-1", "rel-1", Duration::from_millis(1))
        .expect("issue");
    std::thread::sleep(Duration::from_millis(10));
    let err = store
        .consume(&scope, "boot-1", euid(), self_pid())
        .unwrap_err();
    assert_denial(
        &err,
        FailureKind::Denied,
        "sys_grant_none",
        "no valid grant",
    );
}

/// A forged grant file — valid name, wrong MAC — is skipped by
/// `parse_verified`'s constant-time check: the store reports
/// `ErrNoGrant`, never a hit.
#[test]
fn grant_forged_mac_is_no_grant() {
    let scratch = Scratch::new("grant-forge");
    let store = open_store(&scratch);
    let scope = lifecycle_scope("op-1");
    let g = store
        .issue(&scope, "boot-1", "rel-1", Duration::from_secs(3600))
        .expect("issue");
    // Forge: rewrite the same filename with a flipped MAC — the name
    // still matches the scope scan; the verify fails.
    let dir = scratch.join("store");
    let name = format!("{}-{}.grant", g.kind, g.nonce);
    let raw = std::fs::read(dir.join(&name)).expect("grant file");
    let mut forged: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    forged["mac"] = serde_json::Value::from("00".repeat(32));
    std::fs::write(dir.join(&name), serde_json::to_vec(&forged).unwrap()).expect("forge");
    let err = store
        .consume(&scope, "boot-1", euid(), self_pid())
        .unwrap_err();
    assert_denial(
        &err,
        FailureKind::Denied,
        "sys_grant_none",
        "no valid grant",
    );
}

/// `IssueInit`: at most one usable init grant — the second issue is
/// `sys_grant_pending` (GRANT_PENDING), and the grant consumes once.
#[test]
fn init_grant_pending_and_consumed_once() {
    let scratch = Scratch::new("grant-init");
    let store = open_store(&scratch);
    store
        .issue_init("boot-1", "rel-1", Duration::from_secs(60), false)
        .expect("issue init");
    let err = store
        .issue_init("boot-1", "rel-1", Duration::from_secs(60), false)
        .unwrap_err();
    assert_eq!(err.code(), "sys_grant_pending");
    assert_eq!(err.kind(), FailureKind::Conflict);

    // Consume it once under the init scope.
    let scope = GrantScope {
        kind: GrantKind::Init,
        ..GrantScope::default()
    };
    store
        .consume(&scope, "boot-1", euid(), self_pid())
        .expect("consume init");
    let err = store
        .consume(&scope, "boot-1", euid(), self_pid())
        .unwrap_err();
    assert_denial(&err, FailureKind::Denied, "sys_grant_none", "");
}

// ---------------------------------------------------------------------------
// Lifecycle — barrier veto, capacity, admission, unsettled journal
// ---------------------------------------------------------------------------

fn binding() -> LifecycleBinding {
    LifecycleBinding {
        instance_id: "i-1".to_owned(),
        config_binding: "cb-1".to_owned(),
        admission_id: "a-1".to_owned(),
        receipt_id: "r-1".to_owned(),
        model_digest: "m".to_owned(),
        payload_epoch: "e-1".to_owned(),
        bootstrap_fingerprints: vec![],
        b04: Default::default(),
    }
}

/// A `PreparedDependencySet` that passes `validate_b03` — one
/// complete OCI identity per required mode, so the capacity gate
/// reaches its own statfs check rather than the set's refusal.
fn valid_prepared_set() -> PreparedDependencySet {
    PreparedDependencySet {
        modes: B03_REQUIRED_SERVICE_MODES
            .iter()
            .map(|&mode| PreparedMode {
                mode,
                inventory: OciInventory {
                    index_digest: "sha256:index".to_owned(),
                    manifest_digest: "sha256:manifest".to_owned(),
                    config_digest: "sha256:config".to_owned(),
                    layers: vec![],
                },
            })
            .collect(),
    }
}

/// A durable barrier veto: `validate_writable_start` reads the
/// recorded reason back verbatim inside `BARRIER_CONFLICT` — the
/// written bytes are the denial's content, so a veto can never be
/// created silently (empty reason refused as `Invalid`).
#[test]
fn lifecycle_barrier_veto_denied_with_reason() {
    let scratch = Scratch::new("barrier");
    let barrier = FileBarrier::new(scratch.path().to_path_buf());
    barrier
        .block(&binding(), "restore in progress")
        .expect("block");
    let err = lifecycle::block_on(barrier.validate_writable_start(&binding())).unwrap_err();
    assert_denial(
        &err,
        FailureKind::Denied,
        "BARRIER_CONFLICT",
        "restore in progress",
    );

    let err = barrier.block(&binding(), "").unwrap_err();
    assert_eq!(err.code(), "BARRIER");
    assert_eq!(err.kind(), FailureKind::Invalid);
}

/// A binding with missing fields is `Invalid` — the admission and
/// capacity gates validate the binding before any filesystem work.
#[test]
fn lifecycle_binding_incomplete_denied() {
    let mut b = binding();
    b.instance_id = String::new();
    let err = b.validate().unwrap_err();
    assert_eq!(err.code(), "LIFECYCLE_INVALID");
    assert_eq!(err.kind(), FailureKind::Invalid);
    assert!(err.message().contains("instance id"));
}

/// `FilesystemCapacity` refuses when available < required — the
/// denied `CAPACITY_DENIED` with both numbers in the message.
#[test]
fn lifecycle_capacity_denied() {
    let scratch = Scratch::new("capacity");
    let cap = FilesystemCapacity::new(scratch.path().to_path_buf(), i64::MAX);
    let set = valid_prepared_set();
    let err = lifecycle::block_on(cap.admit(&binding(), &set)).unwrap_err();
    assert_eq!(err.code(), "CAPACITY_DENIED");
    assert_eq!(err.kind(), FailureKind::Denied);
    assert!(err.message().contains("required"), "{}", err.message());
}

/// `ReceiptAdmission`: a stale B01 outcome or an incomplete binding
/// is the `ADMISSION` refusal — denied or invalid, never a silent
/// admission.
#[test]
fn lifecycle_admission_denials() {
    struct EvalStale;
    impl AdvisoryEvaluator for EvalStale {
        fn evaluate(&self) -> Result<(advisory::Outcome, advisory::Admission), Failure> {
            Ok((
                advisory::Outcome {
                    state: advisory::State::Stale,
                    code: advisory::Code::Expired,
                    check: String::new(),
                    remediation: String::new(),
                },
                advisory::Admission::default(),
            ))
        }
    }
    struct NoReceipt;
    impl ActiveReceiptReader for NoReceipt {
        fn active(&self) -> Result<DependencyReceipt, Failure> {
            Ok(DependencyReceipt::default())
        }
    }
    struct OkInspect;
    impl ReceiptInspector for OkInspect {
        fn inspect_set(&self, _set: &PreparedDependencySet) -> Result<(), Failure> {
            Ok(())
        }
    }
    let admission = ReceiptAdmission::new(
        Arc::new(EvalStale),
        Arc::new(NoReceipt),
        Arc::new(OkInspect),
    );
    let request = AdmissionRequest {
        instance_id: "i-1".to_owned(),
        config_binding: "cb-1".to_owned(),
        receipt_id: "r-1".to_owned(),
        model_digest: "m".to_owned(),
        payload_epoch: "e-1".to_owned(),
    };
    let err = lifecycle::block_on(admission.verify(request)).unwrap_err();
    assert_denial(&err, FailureKind::Denied, "ADMISSION", "not current");

    // An incomplete binding is refused before the evaluator runs.
    let err = lifecycle::block_on(admission.verify(AdmissionRequest::default())).unwrap_err();
    assert_eq!(err.code(), "ADMISSION");
    assert_eq!(err.kind(), FailureKind::Invalid);
}

/// The same-UID reachability check upstream's production layout
/// answers with the directory mode: authoritative state lives below
/// root-owned `0700`/`0600` parents — here, the grant store itself
/// refuses a store the operator uid could traverse (mode ≠ 0700).
/// The wire-level equivalent ran in `a07_peers`: a same-UID
/// wrong-GID peer is closed unanswered.
#[test]
fn authoritative_state_below_strict_parents_only() {
    let scratch = Scratch::new("strict-parents");
    // A 0755 store dir — group/other-readable — is refused open.
    let loose = scratch.dir("loose-store", 0o755);
    let err = GrantStore::open(loose.to_str().unwrap(), euid(), egid())
        .err()
        .expect("a group-readable store must refuse");
    assert_denial(&err, FailureKind::Denied, "sys_grant_store", "0700");
}

// ---------------------------------------------------------------------------
// The sandbox envelope — ambient-authority routes stay closed
// ---------------------------------------------------------------------------

/// `ValidateLimits`/`ValidateBinary`/`effective_deadline` — the
/// sandbox contract's closed `sandbox_denied` for every over-cap or
/// out-of-set request; the envelope at its own `HARD_LIMITS` admits.
#[test]
fn sandbox_envelope_denials() {
    use envelope::HARD_LIMITS;

    envelope::validate_limits(&HARD_LIMITS).expect("limits at the cap admit");

    let mut limits = HARD_LIMITS;
    limits.cpu += 1.0;
    let err = envelope::validate_limits(&limits).unwrap_err();
    assert_denial(&err, FailureKind::Denied, "sandbox_denied", "CPU");

    limits = HARD_LIMITS;
    limits.memory_bytes += 1;
    let err = envelope::validate_limits(&limits).unwrap_err();
    assert_denial(&err, FailureKind::Denied, "sandbox_denied", "memory");

    limits = HARD_LIMITS;
    limits.max_processes += 1;
    let err = envelope::validate_limits(&limits).unwrap_err();
    assert_denial(&err, FailureKind::Denied, "sandbox_denied", "max_processes");

    limits = HARD_LIMITS;
    limits.max_file_descriptors += 1;
    let err = envelope::validate_limits(&limits).unwrap_err();
    assert_denial(
        &err,
        FailureKind::Denied,
        "sandbox_denied",
        "max_file_descriptors",
    );

    for bad in ["/etc/passwd", "sh", "central-agent --evil"] {
        let err = envelope::validate_binary(bad).unwrap_err();
        assert_denial(
            &err,
            FailureKind::Denied,
            "sandbox_denied",
            "unknown executable class",
        );
    }
    envelope::validate_binary("central-agent").expect("the closed set admits");

    let err = envelope::effective_deadline(Duration::from_secs(601)).unwrap_err();
    assert_denial(&err, FailureKind::Denied, "sandbox_denied", "hard cap");
    envelope::effective_deadline(Duration::from_secs(600)).expect("the cap admits");
}

/// The helper's collapsed authority refusal: every ceremony/authority
/// failure that must not leak detail lands in the same
/// `helper_authority_denied` envelope.
#[test]
fn helper_collapsed_authority_denial() {
    let err = helper::err_denied();
    assert_eq!(err.code(), "helper_authority_denied");
    assert_eq!(err.kind(), FailureKind::Denied);
    assert_eq!(err.message(), "authority denied");
}

/// `SocketPolicy::validate` — a socket that isn't a socket, or whose
/// mode/owner drifted, is refused before the first accept.
#[test]
fn helper_socket_policy_denials() {
    let scratch = Scratch::new("sock-policy");
    let policy = helper::SocketPolicy {
        path: scratch.join("sock").to_string_lossy().into_owned(),
        owner_uid: euid(),
        group_gid: egid(),
        mode: 0o660,
    };
    // Missing socket.
    let err = policy.validate().unwrap_err();
    assert!(err.contains("not a protected Unix socket"), "{err}");

    // A regular file in place of the socket.
    scratch.file("sock", b"x", 0o660);
    let err = policy.validate().unwrap_err();
    assert!(err.contains("not a protected Unix socket"), "{err}");

    // A real socket with the wrong mode.
    let listener = std::os::unix::net::UnixListener::bind(scratch.join("sock2")).expect("bind");
    std::fs::set_permissions(
        scratch.join("sock2"),
        std::os::unix::fs::PermissionsExt::from_mode(0o777),
    )
    .expect("chmod");
    let policy = helper::SocketPolicy {
        path: scratch.join("sock2").to_string_lossy().into_owned(),
        owner_uid: euid(),
        group_gid: egid(),
        mode: 0o660,
    };
    let err = policy.validate().unwrap_err();
    assert!(err.contains("ownership or permissions"), "{err}");
    drop(listener);
}

/// A prepare operation journal entry whose phase is terminal is
/// settled; the `Exact`/`Unsettled` pair upstream's prepare lifecycle
/// consults.
#[test]
fn helper_prepare_operation_terminal_phase_is_settled() {
    let op = PrepareOperation {
        operation_id: "op-1".to_owned(),
        phase: PrepareOperationPhase::Completed,
        admission_id: "adm-1".to_owned(),
        selector: "sel-1".to_owned(),
        deadline: time::OffsetDateTime::now_utc() + time::Duration::minutes(5),
        reason: String::new(),
        reused: 0,
        acquired: 0,
        receipt_id: String::new(),
        created_at: time::OffsetDateTime::now_utc(),
    };
    assert!(op.phase.is_terminal());
    let mut op2 = op.clone();
    op2.phase = PrepareOperationPhase::Acquiring;
    assert!(!op2.phase.is_terminal());
}
