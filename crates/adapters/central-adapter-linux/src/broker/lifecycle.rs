//! `lifecycle.go` + `lifecycle_nonce.go` — one-use bound lifecycle
//! authorizations, the durable nonce tombstone store, the dependency
//! bootstrap cache, and the dead-owner proof.
//!
//! `lifecycleNonceStore.consume` is the O_EXCL marker file: competing
//! consumers can never both create the marker, and a directory fsync
//! makes the successful decision durable before Docker authority is
//! released. The authorization HMAC binds `instance|operation|
//! request_digest|peer_uid|peer_pid|nonce|expires_at_unixnano` — every
//! claim that controls scope or lifetime.

use std::fs;
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;

use central_foundation::failure::Failure;
use central_infra::authority::{
    LifecycleAuthorization, LifecycleAuthorizationRequest, ProtectedGeneration,
};
use central_infra::domain::{LifecycleOperation, LifecyclePhase};
use central_infra::port::DeadOwnerProof;
use sha2::Digest as _;
use time::OffsetDateTime;
use uuid::Uuid;

use super::durable::{PRIVATE_DIRECTORY_MODE, PRIVATE_FILE_MODE, sync_dir};
use super::server::Service;
use super::wire::format_rfc3339_nano;
use super::wire::hex_encode;

fn denied(msg: impl Into<String>) -> Failure {
    Failure::denied("broker_lifecycle", msg.into())
}
fn internal(msg: impl Into<String>) -> Failure {
    Failure::internal("broker_lifecycle", msg.into())
}

/// `ErrAuthorizationReplay` — the nonce marker already exists.
pub const ERR_AUTHORIZATION_REPLAY: &str = "authorization replay detected";

/// The upstream 30-second authorization lifetime.
pub const LIFECYCLE_AUTHORIZATION_SECS: i64 = 30;

/// `lifecycleNonceStore` — `<root>/lifecycle-nonces/<sha256(nonce)>`.
pub struct LifecycleNonceStore {
    root: PathBuf,
}

impl LifecycleNonceStore {
    /// `newLifecycleNonceStore` — creates `<root>/lifecycle-nonces`
    /// `0700`.
    ///
    /// # Errors
    /// `broker_lifecycle` when the root cannot be created.
    pub fn new(root: &std::path::Path) -> Result<Self, Failure> {
        let root = root.join("lifecycle-nonces");
        fs::create_dir_all(&root)
            .map_err(|e| internal(format!("lifecycle nonce store: create root: {e}")))?;
        fs::set_permissions(&root, fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE))
            .map_err(|e| internal(format!("lifecycle nonce store: create root: {e}")))?;
        Ok(Self { root })
    }

    /// `consume` — `O_WRONLY|O_CREATE|O_EXCL` marker at `0600` carrying
    /// the expiry as RFC 3339Nano; `EEXIST` is
    /// [`ERR_AUTHORIZATION_REPLAY`], write/sync failures roll the marker
    /// back, and the containing directory is fsynced before success.
    ///
    /// # Errors
    /// `broker_lifecycle` denied on replay/empty nonce; `internal` on
    /// filesystem failure.
    pub fn consume(&self, nonce: &str, expires_at: OffsetDateTime) -> Result<(), Failure> {
        if nonce.is_empty() {
            return Err(denied("lifecycle nonce store: empty nonce"));
        }
        let sum = sha2::Sha256::digest(nonce.as_bytes());
        let path = self.root.join(hex_encode(&sum));
        let mut file = match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(PRIVATE_FILE_MODE)
            .custom_flags(libc::O_CLOEXEC)
            .open(&path)
        {
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(denied(ERR_AUTHORIZATION_REPLAY));
            }
            Err(e) => {
                return Err(internal(format!(
                    "lifecycle nonce store: reserve nonce: {e}"
                )));
            }
            Ok(f) => f,
        };
        use std::io::Write as _;
        let write_result = file
            .write_all(format!("{}\n", format_rfc3339_nano(expires_at)).as_bytes())
            .and_then(|()| file.sync_all());
        drop(file);
        if let Err(e) = write_result {
            let _ = fs::remove_file(&path);
            return Err(internal(format!(
                "lifecycle nonce store: write marker: {e}"
            )));
        }
        sync_dir(&self.root)
            .map_err(|e| internal(format!("lifecycle nonce store: sync root: {}", e.message())))
    }
}

impl Service {
    /// `AuthorizeLifecycle` — the legacy unbound seam; retained for
    /// trusted in-process callers exactly as upstream (`RequestDigest:
    /// "legacy"`, `PeerPID: 1`).
    ///
    /// # Errors
    /// `broker_lifecycle` on an incomplete binding.
    pub fn authorize_lifecycle(
        &self,
        instance_id: &str,
        operation: &str,
    ) -> Result<LifecycleAuthorization, Failure> {
        self.authorize_bound_lifecycle(&LifecycleAuthorizationRequest {
            instance_id: instance_id.into(),
            operation: operation.into(),
            request_digest: "legacy".into(),
            peer_uid: 0,
            peer_pid: 1,
        })
    }

    /// `AuthorizeBoundLifecycle` — nonce + fingerprint + 30 s expiry.
    ///
    /// # Errors
    /// `broker_lifecycle` denied when any bound field is missing.
    pub fn authorize_bound_lifecycle(
        &self,
        request: &LifecycleAuthorizationRequest,
    ) -> Result<LifecycleAuthorization, Failure> {
        if request.instance_id.is_empty()
            || request.operation.is_empty()
            || request.request_digest.is_empty()
            || request.peer_pid <= 0
        {
            return Err(denied("lifecycle authorization has incomplete binding"));
        }
        let nonce = Uuid::new_v4().to_string();
        let expires_at =
            OffsetDateTime::now_utc() + time::Duration::seconds(LIFECYCLE_AUTHORIZATION_SECS);
        let fp = self.lifecycle_authorization_fingerprint(request, &nonce, expires_at);
        Ok(LifecycleAuthorization {
            nonce,
            instance_id: request.instance_id.clone(),
            operation: request.operation.clone(),
            request_digest: request.request_digest.clone(),
            peer_uid: request.peer_uid,
            peer_pid: request.peer_pid,
            caller_fingerprint: fp,
            expires_at,
        })
    }

    /// `ConsumeLifecycleAuthorization` — consumes a token checking only
    /// the claims embedded in it.
    ///
    /// # Errors
    /// `broker_lifecycle` on expiry, missing fields, fingerprint
    /// mismatch, or [`ERR_AUTHORIZATION_REPLAY`].
    pub fn consume_lifecycle_authorization(
        &self,
        claim: &LifecycleAuthorization,
    ) -> Result<(), Failure> {
        self.consume_lifecycle_authorization_impl(
            claim,
            &LifecycleAuthorizationRequest {
                instance_id: claim.instance_id.clone(),
                operation: claim.operation.clone(),
                request_digest: claim.request_digest.clone(),
                peer_uid: claim.peer_uid,
                peer_pid: claim.peer_pid,
            },
            false,
        )
    }

    /// `ConsumeBoundLifecycleAuthorization` — every bound request
    /// attribute must match the live helper request.
    ///
    /// # Errors
    /// As [`Self::consume_lifecycle_authorization`], plus a binding
    /// mismatch denial.
    pub fn consume_bound_lifecycle_authorization(
        &self,
        claim: &LifecycleAuthorization,
        request: &LifecycleAuthorizationRequest,
    ) -> Result<(), Failure> {
        self.consume_lifecycle_authorization_impl(claim, request, true)
    }

    fn consume_lifecycle_authorization_impl(
        &self,
        claim: &LifecycleAuthorization,
        request: &LifecycleAuthorizationRequest,
        require_binding: bool,
    ) -> Result<(), Failure> {
        if OffsetDateTime::now_utc() > claim.expires_at {
            return Err(denied("lifecycle authorization expired"));
        }
        if claim.nonce.is_empty()
            || claim.instance_id.is_empty()
            || claim.operation.is_empty()
            || super::wire::is_go_zero_time(claim.expires_at)
        {
            return Err(denied("lifecycle authorization has missing claim fields"));
        }
        if require_binding
            && (request.instance_id.is_empty()
                || request.operation.is_empty()
                || request.request_digest.is_empty()
                || request.peer_pid <= 0
                || claim.instance_id != request.instance_id
                || claim.operation != request.operation
                || claim.request_digest != request.request_digest
                || claim.peer_uid != request.peer_uid
                || claim.peer_pid != request.peer_pid)
        {
            return Err(denied("lifecycle authorization binding mismatch"));
        }
        let claim_request = LifecycleAuthorizationRequest {
            instance_id: claim.instance_id.clone(),
            operation: claim.operation.clone(),
            request_digest: claim.request_digest.clone(),
            peer_uid: claim.peer_uid,
            peer_pid: claim.peer_pid,
        };
        let expected_fp = self.lifecycle_authorization_fingerprint(
            &claim_request,
            &claim.nonce,
            claim.expires_at,
        );
        if !super::wire::hmac_equal(expected_fp.as_bytes(), claim.caller_fingerprint.as_bytes()) {
            return Err(denied("lifecycle authorization fingerprint mismatch"));
        }
        let Some(nonces) = &self.nonces else {
            return Err(internal(
                "lifecycle authorization nonce store is unavailable",
            ));
        };
        nonces.consume(&claim.nonce, claim.expires_at)
    }

    /// `lifecycleAuthorizationFingerprint` — HMAC over
    /// `instance|operation|request_digest|peer_uid|peer_pid|nonce|
    /// expires_at_unixnano` under `lifecycle-auth`.
    fn lifecycle_authorization_fingerprint(
        &self,
        request: &LifecycleAuthorizationRequest,
        nonce: &str,
        expires_at: OffsetDateTime,
    ) -> String {
        self.signing.fingerprint(
            "lifecycle-auth",
            format!(
                "{}|{}|{}|{}|{}|{}|{}",
                request.instance_id,
                request.operation,
                request.request_digest,
                request.peer_uid,
                request.peer_pid,
                nonce,
                expires_at.unix_timestamp_nanos()
            )
            .as_bytes(),
        )
    }

    /// `EnsureDependencyBootstrap` — one durable generation per
    /// `bootstrap.<purpose>.<instance>` claim pair; a cached or
    /// already-durable generation is returned rather than rotated.
    ///
    /// # Errors
    /// `broker_lifecycle`/`broker_protected_file` on missing claims,
    /// enumerate/create failure, or multiple durable generations.
    pub fn ensure_dependency_bootstrap(
        &self,
        instance_id: &str,
        purpose: &str,
    ) -> Result<ProtectedGeneration, Failure> {
        if instance_id.is_empty() || purpose.is_empty() {
            return Err(denied("bootstrap instance and purpose are required"));
        }
        let bootstrap_purpose = format!("bootstrap.{purpose}.{instance_id}");
        let mut bootstraps = self.bootstrap_lock()?;
        if let Some(generation) = bootstraps.bootstraps.get(&bootstrap_purpose) {
            return Ok(generation.clone());
        }
        let generations = match self.backend.enumerate(&bootstrap_purpose) {
            Ok(g) => g,
            Err(e) if e.kind() == central_foundation::failure::FailureKind::NotFound => Vec::new(),
            Err(e) => return Err(e),
        };
        if generations.len() == 1 {
            let generation = generations
                .into_iter()
                .next()
                .unwrap_or_else(|| unreachable!());
            let domain = super::protected_file::to_domain(&generation);
            bootstraps
                .bootstraps
                .insert(bootstrap_purpose, domain.clone());
            return Ok(domain);
        }
        if !generations.is_empty() {
            return Err(internal("bootstrap has multiple durable generations"));
        }
        let bootstrap_key = Uuid::new_v4().to_string();
        let generation = self
            .backend
            .create(&bootstrap_purpose, bootstrap_key.as_bytes())?;
        let domain = super::protected_file::to_domain(&generation);
        bootstraps
            .bootstraps
            .insert(bootstrap_purpose, domain.clone());
        Ok(domain)
    }

    /// `AppendLifecycle` — a journaled lifecycle phase transition.
    ///
    /// # Errors
    /// `broker_journal` on the journal failure.
    pub fn append_lifecycle(
        &self,
        op: &LifecycleOperation,
        phase: LifecyclePhase,
    ) -> Result<(), Failure> {
        let Some(journal) = &self.journal else {
            return Err(internal("journal unavailable"));
        };
        journal.append_lifecycle(op, phase)
    }

    /// `VerifyDeadOwner` — `kill(pid, 0)`: `ESRCH` is the dead proof,
    /// success/`EPERM` is alive, anything else is an error. Expiry is
    /// only the trigger; this syscall is the evidence.
    ///
    /// # Errors
    /// `broker_lifecycle` on an invalid owner or a `kill` error other
    /// than `ESRCH`.
    pub fn verify_dead_owner(
        &self,
        lock_id: &str,
        owner_pid: i32,
    ) -> Result<DeadOwnerProof, Failure> {
        if lock_id.is_empty() || owner_pid <= 0 {
            return Err(denied("invalid lifecycle lock owner"));
        }
        let pid = rustix::process::Pid::from_raw(owner_pid)
            .ok_or_else(|| denied("invalid lifecycle lock owner"))?;
        match rustix::process::test_kill_process(pid) {
            Ok(()) | Err(rustix::io::Errno::PERM) => Ok(DeadOwnerProof {
                lock_id: lock_id.into(),
                owner_pid,
                dead: false,
                verified_at: OffsetDateTime::now_utc(),
            }),
            Err(rustix::io::Errno::SRCH) => Ok(DeadOwnerProof {
                lock_id: lock_id.into(),
                owner_pid,
                dead: true,
                verified_at: OffsetDateTime::now_utc(),
            }),
            Err(e) => Err(internal(format!("verify lifecycle lock owner: {e}"))),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests — upstream `lifecycle_test.go` / `lifecycle_nonce.go` coverage.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::testutil::{TempDir, service};

    fn request() -> LifecycleAuthorizationRequest {
        LifecycleAuthorizationRequest {
            instance_id: "inst".into(),
            operation: "up".into(),
            request_digest: "digest".into(),
            peer_uid: 1000,
            peer_pid: 4242,
        }
    }

    #[test]
    fn nonce_marker_is_one_use() {
        let dir = TempDir::new("lifecycle-nonce");
        let store = LifecycleNonceStore::new(&dir).unwrap();
        let expiry = OffsetDateTime::now_utc() + time::Duration::seconds(30);
        store.consume("nonce-1", expiry).unwrap();
        // O_EXCL — the replay is the upstream sentinel denial.
        let err = store.consume("nonce-1", expiry).unwrap_err();
        assert_eq!(err.kind(), central_foundation::failure::FailureKind::Denied);
        assert!(err.message().contains(ERR_AUTHORIZATION_REPLAY));
        store.consume("nonce-2", expiry).unwrap();
        assert!(store.consume("", expiry).is_err());
    }

    #[test]
    fn authorize_then_consume_round_trip() {
        let dir = TempDir::new("lifecycle");
        let svc = service(&dir);
        let claim = svc.authorize_bound_lifecycle(&request()).unwrap();
        assert!(!claim.nonce.is_empty());
        assert!(!claim.caller_fingerprint.is_empty());
        svc.consume_bound_lifecycle_authorization(&claim, &request())
            .unwrap();
        // The nonce marker is durable: a second consume denies replay.
        let err = svc
            .consume_bound_lifecycle_authorization(&claim, &request())
            .unwrap_err();
        assert!(err.message().contains(ERR_AUTHORIZATION_REPLAY));
    }

    #[test]
    fn bound_consume_rejects_binding_mismatch() {
        let dir = TempDir::new("lifecycle");
        let svc = service(&dir);
        let claim = svc.authorize_bound_lifecycle(&request()).unwrap();
        let mut wrong = request();
        wrong.peer_pid = 9999;
        assert_eq!(
            svc.consume_bound_lifecycle_authorization(&claim, &wrong)
                .unwrap_err()
                .kind(),
            central_foundation::failure::FailureKind::Denied
        );
        // A forged fingerprint denies before the nonce is even checked:
        // the claim is still consumable afterwards.
        let mut forged = claim.clone();
        forged.caller_fingerprint = "0".repeat(64);
        assert!(
            svc.consume_bound_lifecycle_authorization(&forged, &request())
                .is_err()
        );
        svc.consume_bound_lifecycle_authorization(&claim, &request())
            .unwrap();
    }

    #[test]
    fn dead_owner_proof_uses_kill_zero() {
        let dir = TempDir::new("lifecycle");
        let svc = service(&dir);
        // This process is alive — the proof says not dead.
        let alive = svc
            .verify_dead_owner("lock-1", std::process::id() as i32)
            .unwrap();
        assert!(!alive.dead);
        // An implausibly large unused pid is dead (ESRCH).
        let dead = svc.verify_dead_owner("lock-1", 4_000_000).unwrap();
        assert!(dead.dead);
        // Invalid input refuses.
        assert!(svc.verify_dead_owner("", 1).is_err());
        assert!(svc.verify_dead_owner("lock", 0).is_err());
    }

    #[test]
    fn dependency_bootstrap_is_single_generation() {
        let dir = TempDir::new("lifecycle");
        let svc = service(&dir);
        let a = svc.ensure_dependency_bootstrap("inst", "minio").unwrap();
        let b = svc.ensure_dependency_bootstrap("inst", "minio").unwrap();
        assert_eq!(a.generation_id, b.generation_id);
        let other = svc.ensure_dependency_bootstrap("inst", "postgres").unwrap();
        assert_ne!(a.generation_id, other.generation_id);
        assert!(svc.ensure_dependency_bootstrap("", "minio").is_err());
    }
}
