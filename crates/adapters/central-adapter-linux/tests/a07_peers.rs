//! A07 — same-UID / peer-gate denials (threat T17, upstream
//! `prepare_peer_context_linux_test.go`, `helper_authority_test.go`,
//! `server.go` peer predicates).
//!
//! Every admission decision the helper and broker make over
//! `SO_PEERCRED`: the pure arm matrix, the wire-level
//! closed-unanswered refusal an unadmitted peer gets, the
//! kernel-attested `peercred` mismatch denials, and the broker's
//! framed-transport peer gates (`0xB1`/`0xB2`/`0xB4`/`0xB5`) plus the
//! `0xc1`–`0xc5` closed denials.

// `allow-*-in-tests` only reaches `#[test]` fns — the fixture helpers
// in this binary unwrap/expect deliberately: an unbuildable fixture
// is the failure.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod a07;

use a07::*;
use central_adapter_linux::broker::protocol;
use central_adapter_linux::helper::protocol::Request;
use central_adapter_linux::helper::server::PeerArm;
use central_adapter_linux::helper::{PeerPolicy, Server};
use central_adapter_linux::sys::peercred;
use central_foundation::failure::FailureKind;

// ---------------------------------------------------------------------------
// The arm matrix — pure checks upstream `Allows` pins
// ---------------------------------------------------------------------------

/// `PeerPolicy::allows`: the operator arm needs the exact configured
/// (uid, gid) pair AND refuses the daemon's own uid; the daemon arm
/// needs exactly `daemon_uid`. `pid <= 0` never admits.
#[test]
fn peer_policy_arm_matrix_denies_every_mismatch() {
    let uid = euid();
    let gid = egid();
    let policy = PeerPolicy {
        daemon_uid: uid + 1,
        operator_uid: uid,
        operator_gid: gid,
    };
    assert!(policy.allows(PeerArm::Operator, uid, gid, self_pid()));
    // Same UID, wrong GID — the same-UID attacker's exact shape.
    assert!(!policy.allows(PeerArm::Operator, uid, gid + 1, self_pid()));
    // Right (uid, gid) but dead pid.
    assert!(!policy.allows(PeerArm::Operator, uid, gid, 0));
    assert!(!policy.allows(PeerArm::Operator, uid, gid, -1));
    // The daemon's own identity can never run operator verbs — a
    // same-UID process is not an operator.
    let self_policy = PeerPolicy {
        daemon_uid: uid,
        operator_uid: uid,
        operator_gid: gid,
    };
    assert!(!self_policy.allows(PeerArm::Operator, uid, gid, self_pid()));
    assert!(self_policy.allows(PeerArm::Daemon, uid, gid, self_pid()));
    assert!(!self_policy.allows(PeerArm::Daemon, uid + 1, gid, self_pid()));
}

/// A same-UID, wrong-GID peer on the operator arm is closed
/// unanswered — the admitted-only contract upstream
/// `admitHelperConn` pins (no response crosses an unadmitted peer).
#[test]
fn helper_conn_same_uid_wrong_gid_closed_unanswered() {
    let mut server = Server::new();
    server.peer_policy = Some(PeerPolicy {
        daemon_uid: euid() + 1,
        operator_uid: euid(),
        operator_gid: egid() + 1, // our gid never matches
    });
    let mut line = serde_json::to_vec(&Request {
        operation_id: "op-peer-1".to_owned(),
        verb: "status".to_owned(),
        payload: None,
    })
    .expect("marshal");
    line.push(b'\n');
    assert_eq!(
        helper_exchange(&server, &line),
        None,
        "an unadmitted peer must be closed unanswered"
    );
}

/// The same-UID peer on the *daemon* arm: operator-only verbs
/// (`status`) refuse because the arm binds operator identity, while
/// the daemon arm's verbs would need `daemon_uid`.
#[test]
fn helper_conn_daemon_arm_refuses_operator_only_peer() {
    let mut server = Server::new();
    server.peer_policy = Some(PeerPolicy {
        daemon_uid: euid() + 1, // we are not the daemon
        operator_uid: euid(),
        operator_gid: egid(),
    });
    // `wipe` is registered-but-unimplemented on the operator arm:
    // admitted, then deferred — proving the arm gate ran first.
    let resp = helper_request(
        &server,
        &Request {
            operation_id: "op-peer-2".to_owned(),
            verb: "wipe".to_owned(),
            payload: None,
        },
    );
    assert_eq!(resp.outcome, "deferred");
    assert_eq!(resp.exit_code, 5);
    assert_eq!(resp.reason, "UNSUPPORTED_IN_THIS_SLICE");

    // A verb outside the matrix lands on the daemon arm: our peer is
    // not `daemon_uid`, so the connection is closed unanswered.
    let mut line = serde_json::to_vec(&Request {
        operation_id: "op-peer-3".to_owned(),
        verb: "no-such-verb".to_owned(),
        payload: None,
    })
    .expect("marshal");
    line.push(b'\n');
    assert_eq!(helper_exchange(&server, &line), None);
}

/// The daemon's own uid on the operator arm is refused unanswered —
/// the `uid != daemon_uid` clause upstream keeps so a same-UID
/// daemon process cannot mint operator authority.
#[test]
fn helper_conn_operator_verb_refuses_daemon_identity() {
    let mut server = Server::new();
    server.peer_policy = Some(PeerPolicy {
        daemon_uid: euid(), // we ARE the daemon identity
        operator_uid: euid(),
        operator_gid: egid(),
    });
    let mut line = serde_json::to_vec(&Request {
        operation_id: "op-peer-4".to_owned(),
        verb: "status".to_owned(),
        payload: None,
    })
    .expect("marshal");
    line.push(b'\n');
    assert_eq!(helper_exchange(&server, &line), None);
}

/// An unreadable request gets upstream's one fixed denial —
/// `denied "unknown" 7 "invalid request"` — then the connection
/// closes. No peer data, no reason leak.
#[test]
fn helper_conn_malformed_request_closed_denial() {
    let server = Server::new();
    let raw = helper_exchange(&server, b"{not json\n").expect("malformed request answered");
    let resp: central_adapter_linux::helper::Response =
        serde_json::from_slice(raw.trim_ascii_end()).expect("valid denial");
    assert_eq!(resp.operation_id, "unknown");
    assert_eq!(resp.outcome, "denied");
    assert_eq!(resp.exit_code, 7);
    assert_eq!(resp.reason, "invalid request");
}

// ---------------------------------------------------------------------------
// Kernel-attested SO_PEERCRED denials
// ---------------------------------------------------------------------------

/// `verify_peer` / `PeerCred::verify_uid` on a real socket pair: the
/// kernel's credential triple is what is compared — a claimed uid is
/// never consulted. The denial is the exact `sys_peercred_denied`
/// with upstream's message shape.
#[test]
fn peercred_uid_mismatch_denied_exact() {
    let (a, _b) = std::os::unix::net::UnixStream::pair().expect("socketpair");
    let err = peercred::verify_peer(&a, rustix::process::Uid::from_raw(euid() + 1)).unwrap_err();
    assert_denial(
        &err,
        FailureKind::Denied,
        "sys_peercred_denied",
        "peer credential uid",
    );
    assert!(err.message().contains("mismatch"), "{}", err.message());

    let cred = peercred::peercred(&a).expect("peercred");
    assert_eq!(cred.uid.as_raw(), euid());
    assert_eq!(cred.gid.as_raw(), egid());
    let err = cred
        .verify_pid(rustix::process::Pid::from_raw(self_pid() + 1).unwrap())
        .unwrap_err();
    assert_denial(
        &err,
        FailureKind::Denied,
        "sys_peercred_denied",
        "peer credential pid",
    );
}

// ---------------------------------------------------------------------------
// Broker peer gates — framed transports and the JSON ladder
// ---------------------------------------------------------------------------

/// `is_*_peer` — the broker's closed peer predicates over fabricated
/// triples (the wire-level tests below exercise the real creds).
#[test]
fn broker_peer_predicates_deny_every_non_conforming_identity() {
    let runtime = protocol::CENTRAL_RUNTIME_UID;
    // B04: root or the runtime uid only.
    assert!(protocol::is_runtime_or_root_peer(runtime, &peer(0, 999, 5)));
    assert!(protocol::is_runtime_or_root_peer(
        runtime,
        &peer(runtime, 999, 5)
    ));
    assert!(!protocol::is_runtime_or_root_peer(
        runtime,
        &peer(runtime + 1, 0, 5)
    ));
    // 0xB1 MinIO outbound: provisioner (1000:1000) or runtime uid,
    // never root.
    assert!(protocol::is_minio_runtime_outbound_peer(
        runtime,
        &peer(1000, 1000, 5)
    ));
    assert!(protocol::is_minio_runtime_outbound_peer(
        runtime,
        &peer(runtime, 0, 5)
    ));
    assert!(!protocol::is_minio_runtime_outbound_peer(
        runtime,
        &peer(0, 0, 5)
    ));
    assert!(!protocol::is_minio_runtime_outbound_peer(
        runtime,
        &peer(1000, 1001, 5)
    ));
    // B05: exactly 986:986.
    assert!(protocol::is_central_migrate_peer(&peer(986, 986, 5)));
    assert!(!protocol::is_central_migrate_peer(&peer(986, 0, 5)));
    assert!(!protocol::is_central_migrate_peer(&peer(0, 986, 5)));
    // 0xB2 provisioned inbound: exactly 1000:1000.
    assert!(protocol::is_minio_provisioner_peer(&peer(1000, 1000, 5)));
    assert!(!protocol::is_minio_provisioner_peer(&peer(0, 0, 5)));
    assert!(!protocol::is_minio_provisioner_peer(&peer(1000, 0, 5)));
    // Root backup helper: uid 0, gid 0, live pid. `PeerCred.pid` is a
    // `Pid` (non-zero by construction — the kernel never reports 0).
    assert!(protocol::is_root_backup_helper_peer(&peer(0, 0, 5)));
    assert!(!protocol::is_root_backup_helper_peer(&peer(0, 1, 5)));
    assert!(!protocol::is_root_backup_helper_peer(&peer(1, 0, 5)));
}

/// The B04 `0xb4` peer gate: a well-formed framed request from a peer
/// that is neither root nor the runtime uid is denied with the exact
/// `authority denied` evidence — echoing the frame's operation id —
/// before the descriptor transport is even read.
#[test]
fn broker_b04_frame_wrong_peer_denied_exact() {
    let scratch = Scratch::new("broker-b04");
    // runtime_uid is nobody-else: as a non-root test process our peer
    // is neither root nor the runtime identity.
    let svc = broker_service(&scratch, euid() + 1);
    if euid() == 0 {
        eprintln!("SKIP [a07] b04 wrong-peer gate: running as root is always admitted");
        return;
    }
    let req = serde_json::json!({
        "operation_id": "op-b04-1",
        "purpose": protocol::MATERIALIZE_MINIO_ROOT_RPC,
        "payload": {},
    });
    let payload = serde_json::to_vec(&req).unwrap();
    let mut frame = vec![protocol::B04_FRAME_MARKER];
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    let resp = broker_exchange(&svc, &frame).expect("denial written");
    assert_eq!(resp["operation_id"], "op-b04-1");
    assert_eq!(resp["outcome"], "denied");
    assert_eq!(resp["evidence"]["message"], "authority denied");
}

/// The 0xB1 MinIO-runtime gate: the provisioner pair `(1000:1000)`
/// and the runtime uid are attested peers — their well-formed frame
/// is read, then the closed runtime-binding gate denies
/// `B10_MINIO_RUNTIME_DENIED: protected runtime binding unavailable`.
/// Any other peer — root included — is `authority denied`. Which arm
/// this process drives depends on its own uid (the provisioner uid is
/// the common developer identity), so both verdicts are pinned and
/// the gate table is asserted directly.
#[test]
fn broker_b10_runtime_frame_denied_exact() {
    let scratch = Scratch::new("broker-b1");
    let runtime_uid = euid() + 1;
    let svc = broker_service(&scratch, runtime_uid);
    let req = serde_json::json!({
        "operation_id": "op-b1-1",
        "purpose": protocol::MATERIALIZE_MINIO_RUNTIME_RPC,
        "payload": {},
    });
    let payload = serde_json::to_vec(&req).unwrap();
    let mut frame = vec![protocol::B10_MINIO_RUNTIME_FRAME_MARKER];
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    let resp = broker_exchange(&svc, &frame).expect("denial written");
    assert_eq!(resp["operation_id"], "op-b1-1");
    assert_eq!(resp["outcome"], "denied");
    let admitted = (euid() == protocol::MINIO_PROVISIONER_UID
        && egid() == protocol::MINIO_PROVISIONER_GID)
        || euid() == runtime_uid;
    assert_eq!(
        resp["evidence"]["message"],
        if admitted {
            "B10_MINIO_RUNTIME_DENIED: protected runtime binding unavailable"
        } else {
            "authority denied"
        }
    );

    // The gate table itself — provisioner pair or the runtime uid;
    // unlike B04, root is NOT an attested peer here.
    assert!(!protocol::is_minio_runtime_outbound_peer(
        runtime_uid,
        &peer(0, 0, 1)
    ));
    assert!(!protocol::is_minio_runtime_outbound_peer(
        runtime_uid,
        &peer(999, 999, 1)
    ));
    assert!(protocol::is_minio_runtime_outbound_peer(
        runtime_uid,
        &peer(1000, 1000, 1)
    ));
    assert!(protocol::is_minio_runtime_outbound_peer(
        runtime_uid,
        &peer(runtime_uid, 7, 1)
    ));
}

/// The 0xB2 provisioned-descriptor gate denies *before* receiving the
/// descriptor — an unauthorized peer must not make the broker
/// allocate an fd or parse a payload. As the provisioner identity the
/// frame gate runs instead: a shapeless write is `invalid
/// provisioned frame`, and a well-formed frame carrying a sealed
/// memfd reaches the closed inbound store's
/// `B10_PROVISION_DENIED: unsupported in this slice`.
#[test]
fn broker_b10_provisioned_frame_denied_exact() {
    let scratch = Scratch::new("broker-b2");
    let svc = broker_service(&scratch, euid() + 1);
    let provisioner =
        euid() == protocol::MINIO_PROVISIONER_UID && egid() == protocol::MINIO_PROVISIONER_GID;

    let resp =
        broker_exchange(&svc, &[protocol::B10_PROVISIONED_FRAME_MARKER]).expect("denial written");
    assert_eq!(resp["operation_id"], "unknown");
    assert_eq!(resp["outcome"], "denied");
    assert_eq!(
        resp["evidence"]["message"],
        if provisioner {
            "invalid provisioned frame"
        } else {
            "authority denied"
        }
    );

    // The provisioner gate table — `1000:1000` only.
    assert!(protocol::is_minio_provisioner_peer(&peer(1000, 1000, 1)));
    assert!(!protocol::is_minio_provisioner_peer(&peer(1000, 999, 1)));
    assert!(!protocol::is_minio_provisioner_peer(&peer(0, 0, 1)));

    if !provisioner {
        eprintln!(
            "SKIP [a07] b2 provisioned-frame leg: not the provisioner uid, wire leg covered by the peer-denial arm"
        );
        return;
    }

    // The admitted leg: a well-formed frame — `u32` length + the
    // MinioProvisionedDescriptor JSON — with the sealed credential
    // memfd attached in the same message.
    use central_adapter_linux::sys::memfd;
    use rustix::cmsg_space;
    use rustix::fd::AsFd;
    use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
    use std::io::{BufRead, BufReader, IoSlice, Write};
    use std::mem::MaybeUninit;

    let descriptor = serde_json::json!({
        "service": "minio-provision",
        "target": "sealed_memfd",
        "uid": 502,
        "gid": 502,
        "bucket": "central-scope",
        "key_prefix": "inst/run/",
        "purpose": "minio_runtime_v1",
        "operation_id": "op-b2-1",
        "instance_id": "inst-1",
        "receipt_id": "rcpt-1",
        "expires_at": "2027-01-01T00:00:00Z",
        "fence_token": 1,
    });
    let payload = serde_json::to_vec(&descriptor).unwrap();
    let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&payload);
    let mem = memfd::create_sealed("a07-b2", b"credential-bytes").expect("sealed memfd");

    let (mut client, srv) = std::os::unix::net::UnixStream::pair().expect("socketpair");
    client
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .expect("timeout");
    let resp = std::thread::scope(|s| {
        s.spawn(|| {
            let _ = central_adapter_linux::broker::server::handle_conn(srv, &svc);
        });
        client
            .write_all(&[protocol::B10_PROVISIONED_FRAME_MARKER])
            .expect("marker");
        let mut space = [MaybeUninit::<u8>::uninit(); cmsg_space!(ScmRights(1))];
        let mut buf = SendAncillaryBuffer::new(&mut space);
        let rights = [mem.as_fd()];
        assert!(buf.push(SendAncillaryMessage::ScmRights(&rights)));
        rustix::net::sendmsg(
            &client,
            &[IoSlice::new(&frame)],
            &mut buf,
            SendFlags::empty(),
        )
        .expect("sendmsg");
        client.shutdown(std::net::Shutdown::Write).ok();
        let mut line = Vec::new();
        BufReader::new(&client)
            .read_until(b'\n', &mut line)
            .expect("read response");
        serde_json::from_slice::<serde_json::Value>(line.trim_ascii_end())
            .expect("valid broker response")
    });
    assert_eq!(resp["operation_id"], "op-b2-1");
    assert_eq!(resp["outcome"], "denied");
    assert_eq!(
        resp["evidence"]["message"],
        format!(
            "B10_PROVISION_DENIED: {}",
            protocol::UNSUPPORTED_IN_THIS_SLICE
        )
    );
}

/// The `0xc1` backup-worker credential transport is closed for this
/// slice but still answers a well-formed frame with the denial that
/// echoes the operation id — upstream's order (parse, then deny).
#[test]
fn broker_backup_credential_frame_denied_echoes_operation() {
    let scratch = Scratch::new("broker-c1");
    let svc = broker_service(&scratch, euid() + 1);
    let op = uuid::Uuid::new_v4();
    let launch = uuid::Uuid::new_v4();
    let mut frame = vec![protocol::BACKUP_WORKER_CREDENTIAL_FRAME_MARKER];
    frame.push(protocol::BACKUP_WORKER_POSTGRES_CREDENTIAL);
    frame.extend_from_slice(launch.as_bytes());
    frame.extend_from_slice(op.as_bytes());
    let resp = broker_exchange(&svc, &frame).expect("denial written");
    assert_eq!(resp["operation_id"], op.to_string());
    assert_eq!(resp["outcome"], "denied");
    assert_eq!(
        resp["evidence"]["message"],
        "BACKUP_WORKER_CREDENTIAL_DENIED"
    );

    // A malformed 0xc1 (unknown kind byte) denies as `"unknown"` —
    // never echoing attacker-controlled identity.
    let mut bad = vec![protocol::BACKUP_WORKER_CREDENTIAL_FRAME_MARKER, 0xee];
    bad.extend_from_slice(launch.as_bytes());
    bad.extend_from_slice(op.as_bytes());
    let resp = broker_exchange(&svc, &bad).expect("denial written");
    assert_eq!(resp["operation_id"], "unknown");
    assert_eq!(
        resp["evidence"]["message"],
        "BACKUP_WORKER_CREDENTIAL_DENIED"
    );
}

/// The 0xc2 restore-migration credential frame keeps its own peer
/// denial; the 0xc3/0xc4/0xc5 reserve/receipt/inspection transports
/// are live since Task 8 and answer with their own refusal
/// vocabularies — `*_PEER_DENIED` for an unauthorized peer,
/// `*_FRAME_INVALID` for a peer that passed and a body that did not.
#[test]
fn broker_restore_framed_transports_live_vocabularies() {
    let scratch = Scratch::new("broker-c2");
    let svc = broker_service(&scratch, euid() + 1);
    let resp = broker_exchange(&svc, &[protocol::RESTORE_MIGRATION_CREDENTIAL_FRAME_MARKER])
        .expect("denial written");
    assert_eq!(resp["operation_id"], "unknown");
    assert_eq!(resp["outcome"], "denied");
    assert_eq!(resp["evidence"]["message"], "RESTORE_CREDENTIAL_DENIED");

    // 0xc3/0xc4/0xc5 are live transports since Task 8: they answer
    // with their own refusal vocabularies, never the closed-matrix
    // `UNSUPPORTED_IN_THIS_SLICE`. Each arm's peer gate runs before
    // the request decode. For 0xc3/0xc4 that gate is the
    // launch-record predicate — a peer without a recorded launch
    // (root or not) is PEER_DENIED and never reaches decode. For
    // 0xc5 the gate admits root outright, so a root peer's bare
    // marker reaches decode and fails FRAME_INVALID.
    let root = euid() == 0;
    for (marker, reason) in [
        (
            protocol::RESTORE_CAPACITY_RESERVE_FRAME_MARKER,
            "RESTORE_RESERVE_PEER_DENIED",
        ),
        (
            protocol::RESTORE_CAPACITY_RECEIPT_FRAME_MARKER,
            "RESTORE_RECEIPT_PEER_DENIED",
        ),
        (
            protocol::RESTORE_CAPACITY_RESERVE_INSPECTION_FRAME_MARKER,
            if root {
                "RESTORE_INSPECTION_FRAME_INVALID"
            } else {
                "RESTORE_INSPECTION_PEER_DENIED"
            },
        ),
    ] {
        let resp = broker_exchange(&svc, &[marker]).expect("denial written");
        assert_eq!(resp["outcome"], "denied", "marker {marker:#04x}");
        assert_eq!(resp["evidence"]["message"], reason, "marker {marker:#04x}");
    }
}

/// The JSON-line transport's generic peer gate: a peer that is
/// neither root nor the runtime uid is denied `authority denied`
/// before dispatch — whatever purpose it claimed.
#[test]
fn broker_json_transport_wrong_peer_denied() {
    let scratch = Scratch::new("broker-json-peer");
    let svc = broker_service(&scratch, euid() + 1);
    if euid() == 0 {
        eprintln!("SKIP [a07] json wrong-peer gate: running as root is always admitted");
        return;
    }
    let resp = broker_exchange(
        &svc,
        b"{\"operation_id\":\"op-jp-1\",\"purpose\":\"hmac_fingerprint\",\"payload\":{}}\n",
    )
    .expect("denial written");
    assert_eq!(resp["operation_id"], "op-jp-1");
    assert_eq!(resp["outcome"], "denied");
    assert_eq!(resp["evidence"]["message"], "authority denied");
}

/// `dispatch` reaches the purpose ladder only after admission: an
/// admitted peer (the runtime uid) gets the purpose-level denials —
/// `"unknown purpose"` for unregistered names and the closed
/// `BROKER_AUTHORITY_DENIED: UNSUPPORTED_IN_THIS_SLICE` for the R6
/// surface — never `authority denied`.
#[test]
fn broker_dispatch_denies_unknown_and_r6_purposes_exact() {
    let scratch = Scratch::new("broker-dispatch");
    let svc = broker_service(&scratch, euid());
    let resp = svc.dispatch(&broker_request("op-d-1", "no_such_purpose"));
    assert_eq!(
        resp.outcome,
        central_infra::authority::BrokerOutcome::Denied
    );
    assert_eq!(resp.evidence.message, "unknown purpose");

    // R6 surface: a registered-but-closed purpose name — only the
    // Postgres service-role and advisory-evaluation RPCs remain
    // closed in this slice; the backup/recovery surface is live.
    let resp = svc.dispatch(&broker_request(
        "op-d-2",
        protocol::POSTGRES_SERVICE_ROLE_BIND_RPC,
    ));
    assert_eq!(
        resp.outcome,
        central_infra::authority::BrokerOutcome::Denied
    );
    assert_eq!(
        resp.evidence.message,
        format!(
            "BROKER_AUTHORITY_DENIED: {}",
            protocol::UNSUPPORTED_IN_THIS_SLICE
        )
    );

    // Connection-only purposes `HandleConn` serves (peer-gated backup
    // helper and restore-launch RPCs) are not registered in upstream's
    // `Dispatch` switch either — the generic path answers upstream's
    // `default`, `"unknown purpose"`.
    let resp = svc.dispatch(&broker_request("op-d-3", protocol::BACKUP_ISSUE_MINIO_RPC));
    assert_eq!(
        resp.outcome,
        central_infra::authority::BrokerOutcome::Denied
    );
    assert_eq!(resp.evidence.message, "unknown purpose");

    // Descriptor-only transports refuse the JSON path with their
    // pinned messages.
    for (purpose, msg) in [
        (
            protocol::MATERIALIZE_MINIO_ROOT_RPC,
            "B04_HANDOFF_DENIED: descriptor-only transport required",
        ),
        (
            protocol::MATERIALIZE_MINIO_RUNTIME_RPC,
            "B10_MINIO_RUNTIME_DENIED: descriptor-only transport required",
        ),
        (
            protocol::MATERIALIZE_DEPENDENCY_HANDOFF_RPC,
            "B04_HANDOFF_DENIED: legacy pathname handoff is disabled",
        ),
        (
            protocol::CREATE_PROTECTED_GENERATION_RPC,
            "B04_HANDOFF_DENIED: create_protected_generation is permanently denied",
        ),
    ] {
        let resp = svc.dispatch(&broker_request("op-d-x", purpose));
        assert_eq!(
            resp.evidence.message, msg,
            "purpose {purpose} must keep its pinned denial"
        );
    }
}
