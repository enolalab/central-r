//! Shared test scaffolding — in-memory fakes for the transport's
//! narrow service seams and request builders that install the
//! `ConnectInfo` extension the admission layer requires.

#![allow(dead_code)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::Request;
use central_foundation::identity::{SessionId, WorkspaceId};
use central_session::contract::{Failure, FailureClass, PreAuthCSRF, RequestIdentity};
use central_session::domain::{ActivationRequest, Session, SessionState, ValidationRequest};
use central_transport_http::ports::{DeliveryPrecommit, PreAuthCsrf, SessionValidator};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;

/// The test service implementing all three transport seams on one
/// fake — mirrors production where `Service<S, B>` satisfies all of
/// them.
pub struct FakeSessions {
    /// token_hash → Session rows.
    pub sessions: Mutex<HashMap<[u8; 32], Session>>,
    /// activate_delivery calls, in order.
    pub activations: Mutex<Vec<ActivationRequest>>,
    /// revoke calls, in order.
    pub revocations: Mutex<Vec<SessionId>>,
    /// When true, `activate_delivery` fails (authority/store error).
    pub activate_fails: std::sync::atomic::AtomicBool,
    /// Count of `issue_pre_auth_csrf` calls.
    pub issued: AtomicUsize,
}

impl FakeSessions {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            activations: Mutex::new(Vec::new()),
            revocations: Mutex::new(Vec::new()),
            activate_fails: std::sync::atomic::AtomicBool::new(false),
            issued: AtomicUsize::new(0),
        }
    }

    /// Registers an Active session keyed by `token_hash` so `validate`
    /// succeeds for the matching `central_session` cookie value.
    pub fn insert_active(&self, token_value: [u8; 32]) -> Session {
        let now = OffsetDateTime::now_utc();
        let session = Session {
            id: SessionId::new(),
            workspace_id: WorkspaceId::sentinel(),
            state: SessionState::Active,
            principal_identity: "test".to_string(),
            security_epoch: central_session::domain::SecurityEpoch(0),
            token_hash: Sha256::digest(token_value).into(),
            csrf_hash: [7u8; 32],
            idle_expiry: now + time::Duration::minutes(30),
            absolute_expiry: now + time::Duration::hours(12),
            first_use_deadline: None,
            first_used_at: Some(now),
            created_at: now,
            last_seen_at: now,
            revoked_at: None,
        };
        self.sessions
            .lock()
            .unwrap()
            .insert(session.token_hash, session.clone());
        session
    }
}

impl Default for FakeSessions {
    fn default() -> Self {
        Self::new()
    }
}

impl PreAuthCsrf for FakeSessions {
    fn issue_pre_auth_csrf(&self) -> PreAuthCSRF {
        self.issued.fetch_add(1, Ordering::SeqCst);
        let value: [u8; 32] = rand::random();
        let hash: [u8; 32] = Sha256::digest(value).into();
        PreAuthCSRF::new(value, hash)
    }

    fn validate_pre_auth_csrf(&self, p: &PreAuthCSRF) -> Result<(), Failure> {
        // Mirror `Service::validate_pre_auth_csrf`: reject the zero
        // pair and a value/hash mismatch.
        if p.is_zero() {
            return Err(Failure::new(FailureClass::CsrfInvalid, "zero", ""));
        }
        let got: [u8; 32] = Sha256::digest(p.value()).into();
        if got != p.hash() {
            return Err(Failure::new(FailureClass::CsrfInvalid, "mismatch", ""));
        }
        Ok(())
    }
}

impl SessionValidator for FakeSessions {
    async fn validate(&self, req: ValidationRequest) -> Result<Session, Failure> {
        self.sessions
            .lock()
            .unwrap()
            .get(&req.token_hash)
            .cloned()
            .ok_or_else(|| Failure::new(FailureClass::SessionInvalidated, "not found", ""))
    }
}

impl DeliveryPrecommit for FakeSessions {
    async fn activate_delivery(&self, req: ActivationRequest) -> Result<Session, Failure> {
        self.activations.lock().unwrap().push(req.clone());
        if self.activate_fails.load(Ordering::SeqCst) {
            return Err(Failure::new(FailureClass::AuthorityDenied, "denied", ""));
        }
        let now = OffsetDateTime::now_utc();
        Ok(Session {
            id: req.delivery_id.as_session_id(),
            workspace_id: WorkspaceId::sentinel(),
            state: SessionState::Active,
            principal_identity: "test".to_string(),
            security_epoch: req.epoch,
            token_hash: req.token_hash,
            csrf_hash: req.csrf_hash,
            idle_expiry: now + time::Duration::minutes(30),
            absolute_expiry: now + time::Duration::hours(12),
            first_use_deadline: None,
            first_used_at: None,
            created_at: now,
            last_seen_at: now,
            revoked_at: None,
        })
    }

    async fn revoke(&self, id: SessionId) -> Result<(), Failure> {
        self.revocations.lock().unwrap().push(id);
        Ok(())
    }
}

/// The `ConnectInfo<SocketAddr>` loopback extension admission requires.
pub fn loopback_req(builder: axum::http::request::Builder) -> Request<Body> {
    let mut req = builder.body(Body::empty()).unwrap();
    req.extensions_mut().insert(ConnectInfo(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        49_001,
    )));
    req
}

/// Same, carrying a body.
pub fn loopback_req_body(
    builder: axum::http::request::Builder,
    body: impl Into<Body>,
) -> Request<Body> {
    let mut req = loopback_req(builder);
    *req.body_mut() = body.into();
    req
}

/// A request carrying a synthetic non-loopback peer.
pub fn remote_req(builder: axum::http::request::Builder) -> Request<Body> {
    let mut req = builder.body(Body::empty()).unwrap();
    req.extensions_mut().insert(ConnectInfo(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
        49_001,
    )));
    req
}

pub const HOST: &str = "127.0.0.1:8080";
pub const ORIGIN: &str = "https://127.0.0.1:8080";

/// The expected-host request builder: `GET path` with exact Host.
pub fn get(path: &str) -> axum::http::request::Builder {
    Request::builder()
        .method("GET")
        .uri(path)
        .header("host", HOST)
}

/// `POST path` with exact Host and the expected Origin.
pub fn post_origin(path: &str) -> axum::http::request::Builder {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("host", HOST)
        .header("origin", ORIGIN)
}

/// `RequestIdentity` for precommit arms.
pub fn test_identity() -> RequestIdentity {
    RequestIdentity {
        peer_uid: 1000,
        peer_pid: 42,
        origin: ORIGIN.to_string(),
    }
}

/// A body of exactly `n` bytes.
pub fn body_bytes(n: usize) -> Vec<u8> {
    vec![b'x'; n]
}

/// Waits up to `dur` for `f` to become true.
pub async fn wait_for(dur: Duration, mut f: impl FnMut() -> bool) -> bool {
    let deadline = std::time::Instant::now() + dur;
    while std::time::Instant::now() < deadline {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    false
}
