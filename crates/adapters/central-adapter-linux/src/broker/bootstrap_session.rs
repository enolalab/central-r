//! `bootstrap_session.go` — the broker-owned one-use bootstrap
//! candidate registry plus the runtime-side presenter/activator
//! clients.
//!
//! Custody invariants (unchanged from upstream):
//!
//! - The broker stores only the opaque `CandidateBinding`
//!   (`candidate_id`, `generation`, `digest`); a bootstrap *verifier*
//!   is never accepted, stored, or persisted anywhere.
//! - `present_bootstrap` (server.rs) returns the staged value once, in
//!   memory, over the protected socket — never to a file, URL, event,
//!   or log — and zeroes the staged copy on read.
//! - The persisted registry at `<root>/bootstrap-candidate-state.json`
//!   records `{candidate_id, generation, digest, activated}`; the
//!   digest travels as raw standard base64. The file is `0600`, written
//!   tmp+fsync+rename with a directory fsync.
//! - `Reset` persists the zero record before returning: a broker
//!   restart cannot resurrect a pre-recovery candidate.
//! - Registration is generation-fenced: a newer generation replaces an
//!   already-consumed registration; same-generation replacement is
//!   denied to prevent candidate rollback.

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use central_foundation::failure::Failure;
use central_infra::authority::{BrokerOutcome, BrokerRequest, BrokerResponse};
use central_session::contract::CandidateBinding;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::durable::{PRIVATE_FILE_MODE, ensure_private_root};
use super::protocol;
use super::wire;

fn denied(msg: impl Into<String>) -> Failure {
    Failure::denied("broker_bootstrap_session", msg)
}

fn internal(msg: impl Into<String>) -> Failure {
    Failure::internal("broker_bootstrap_session", msg)
}

/// Upstream's `syncFile` — fsync the just-written tmp file before the
/// rename publishes it.
fn sync_file(path: &std::path::Path) -> Result<(), Failure> {
    fs::File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(|e| internal(format!("broker: fsync {}: {e}", path.display())))
}

// ---------------------------------------------------------------------------
// Persisted state — upstream's `bootstrap-candidate-state.json`
// ---------------------------------------------------------------------------

/// The on-disk record. `candidate_id`/`generation`/`digest` are
/// omitted when the registry is empty — upstream's `omitempty` — while
/// `activated` is always emitted.
#[derive(Serialize)]
struct StateRecord<'a> {
    #[serde(skip_serializing_if = "str_is_empty")]
    candidate_id: &'a str,
    #[serde(skip_serializing_if = "zero_is_zero")]
    generation: u64,
    #[serde(skip_serializing_if = "str_is_empty")]
    digest: &'a str,
    activated: bool,
}

fn str_is_empty(s: &&str) -> bool {
    s.is_empty()
}

fn zero_is_zero(v: &u64) -> bool {
    *v == 0
}

/// The decode half: defaults keep a missing field a zero value, exactly
/// like Go's untagged-tagged unmarshal into a value struct.
#[derive(Deserialize)]
struct StateRecordLoad {
    #[serde(default)]
    candidate_id: String,
    #[serde(default)]
    generation: u64,
    #[serde(default)]
    digest: String,
    #[serde(default)]
    activated: bool,
}

#[derive(Default)]
struct SessionState {
    registered: Option<CandidateBinding>,
    activated: bool,
}

/// `BootstrapSession` — the broker-owned one-use candidate registry.
/// It stores only the opaque candidate binding; a bootstrap verifier
/// is never accepted.
pub struct BootstrapSession {
    state: Mutex<SessionState>,
    /// `None` ⇒ the ephemeral `NewBootstrapSession` — `persist` is a
    /// no-op and nothing survives the process.
    state_path: Option<PathBuf>,
}

impl BootstrapSession {
    /// `NewBootstrapSession` — the in-memory registry (tests and the
    /// restore-engine's in-process composition).
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(SessionState::default()),
            state_path: None,
        }
    }

    /// `newPersistentBootstrapSession` — load
    /// `<root>/bootstrap-candidate-state.json` if present. A missing
    /// file is an empty registry; an undecodable or invalid record is
    /// refused, never repaired silently.
    pub fn new_persistent(root_path: &std::path::Path) -> Result<Self, Failure> {
        ensure_private_root(root_path)?;
        let session = Self {
            state: Mutex::new(SessionState::default()),
            state_path: Some(root_path.join("bootstrap-candidate-state.json")),
        };
        let Some(path) = &session.state_path else {
            return Ok(session);
        };
        let data = match fs::read(path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(session),
            Err(_) => return Err(internal("broker: load bootstrap candidate state")),
        };
        let record: StateRecordLoad = serde_json::from_slice(&data)
            .map_err(|_| internal("broker: decode bootstrap candidate state"))?;
        if record.candidate_id.is_empty()
            && record.generation == 0
            && record.digest.is_empty()
            && !record.activated
        {
            return Ok(session);
        }
        let digest = wire::b64_raw_decode(&record.digest)
            .filter(|d| d.len() == 32)
            .ok_or_else(|| internal("broker: invalid bootstrap candidate state"))?;
        let mut digest_arr = [0u8; 32];
        digest_arr.copy_from_slice(&digest);
        let binding = CandidateBinding {
            candidate_id: record.candidate_id,
            generation: record.generation,
            digest: Zeroizing::new(digest_arr),
        };
        if !binding.is_valid() {
            return Err(internal("broker: invalid bootstrap candidate state"));
        }
        let mut guard = session.lock()?;
        guard.registered = Some(binding);
        guard.activated = record.activated;
        drop(guard);
        Ok(session)
    }

    fn lock(&self) -> Result<MutexGuard<'_, SessionState>, Failure> {
        self.state
            .lock()
            .map_err(|_| internal("broker: bootstrap session lock poisoned"))
    }

    /// `Register` — record the exact candidate the broker may activate.
    /// A newer generation replaces an already-consumed registration;
    /// same-generation replacement is denied (candidate-rollback
    /// prevention). Re-registering the identical un-activated binding
    /// is idempotent.
    pub fn register(&self, binding: &CandidateBinding) -> Result<(), Failure> {
        if !binding.is_valid() {
            return Err(denied("broker: invalid candidate binding"));
        }
        let mut guard = self.lock()?;
        if let Some(existing) = &guard.registered {
            if existing.equal(binding) && !guard.activated {
                return Ok(());
            }
            if binding.generation <= existing.generation {
                return Err(denied("broker: candidate generation not newer"));
            }
        }
        let previous = guard.registered.clone();
        let previous_activated = guard.activated;
        guard.registered = Some(binding.clone());
        guard.activated = false;
        if let Err(e) = self.persist(&guard) {
            guard.registered = previous;
            guard.activated = previous_activated;
            return Err(e);
        }
        Ok(())
    }

    /// `Activate` — consume the exact currently registered candidate.
    /// The comparison includes candidate id, generation, and digest
    /// (constant-time); it is never a verifier comparison.
    pub fn activate(&self, binding: &CandidateBinding) -> Result<(), Failure> {
        if !binding.is_valid() {
            return Err(denied("broker: invalid candidate binding"));
        }
        let mut guard = self.lock()?;
        match &guard.registered {
            Some(existing) if !guard.activated && existing.equal(binding) => {}
            _ => {
                return Err(denied("broker: candidate mismatch"));
            }
        }
        guard.activated = true;
        if let Err(e) = self.persist(&guard) {
            guard.activated = false;
            return Err(e);
        }
        Ok(())
    }

    /// `Reset` — invalidate the durable candidate registry after a
    /// destructive recovery. No replacement candidate is installed:
    /// successful recovery must complete a new normal bootstrap
    /// exchange. The zero record is persisted before returning.
    pub fn reset(&self) -> Result<(), Failure> {
        let mut guard = self.lock()?;
        let previous = guard.registered.clone();
        let previous_activated = guard.activated;
        guard.registered = None;
        guard.activated = false;
        if let Err(e) = self.persist(&guard) {
            guard.registered = previous;
            guard.activated = previous_activated;
            return Err(e);
        }
        Ok(())
    }

    /// `Activated` — crash reconciliation: whether the exact registered
    /// candidate has been activated. Never exposes the digest.
    pub fn activated(&self, binding: &CandidateBinding) -> bool {
        match self.lock() {
            Ok(guard) => {
                guard.activated && guard.registered.as_ref().is_some_and(|r| r.equal(binding))
            }
            Err(_) => false,
        }
    }

    /// `persistLocked` — tmp `0600` write, fsync, rename, dir fsync.
    /// No-op for the ephemeral session.
    fn persist(&self, guard: &SessionState) -> Result<(), Failure> {
        let Some(path) = &self.state_path else {
            return Ok(());
        };
        let (candidate_id, generation, digest) = match &guard.registered {
            Some(b) => (
                b.candidate_id.clone(),
                b.generation,
                wire::b64_raw_encode(&b.digest[..]),
            ),
            None => (String::new(), 0, String::new()),
        };
        let record = StateRecord {
            candidate_id: &candidate_id,
            generation,
            digest: &digest,
            activated: guard.activated,
        };
        let data = serde_json::to_vec(&record)
            .map_err(|e| internal(format!("broker: marshal bootstrap candidate state: {e}")))?;
        let tmp = {
            let mut p = path.as_os_str().to_owned();
            p.push(".tmp");
            PathBuf::from(p)
        };
        let write_result = (|| -> Result<(), Failure> {
            use std::io::Write as _;
            use std::os::unix::fs::OpenOptionsExt as _;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(PRIVATE_FILE_MODE)
                .custom_flags(libc::O_CLOEXEC)
                .open(&tmp)
                .map_err(|e| internal(format!("broker: write {}: {e}", tmp.display())))?;
            file.write_all(&data)
                .map_err(|e| internal(format!("broker: write {}: {e}", tmp.display())))?;
            fs::set_permissions(&tmp, fs::Permissions::from_mode(PRIVATE_FILE_MODE))
                .map_err(|e| internal(format!("broker: secure {}: {e}", tmp.display())))?;
            sync_file(&tmp)?;
            fs::rename(&tmp, path)
                .map_err(|e| internal(format!("broker: publish {}: {e}", path.display())))?;
            let dir = path
                .parent()
                .ok_or_else(|| internal("broker: state path has no parent"))?;
            super::durable::sync_dir(dir)
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        write_result
    }
}

impl Default for BootstrapSession {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Wire decode — `decodeCandidateBinding` (closed typed decoding)
// ---------------------------------------------------------------------------

/// `candidateBindingWire` — `{"candidate_id","generation","digest"}`.
/// `deny_unknown_fields` reproduces upstream's `DisallowUnknownFields`;
/// serde rejects trailing tokens on its own.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateBindingWire {
    #[serde(default)]
    candidate_id: String,
    #[serde(default)]
    generation: u64,
    #[serde(default)]
    digest: String,
}

/// `decodeCandidateBinding` — exactly one payload key, `"binding"`,
/// closed-decoded; the digest must be raw-standard-base64 32 bytes and
/// the binding valid. Returns `denied` on any deviation.
pub(crate) fn decode_candidate_binding(
    payload: Option<&BTreeMap<String, Box<serde_json::value::RawValue>>>,
) -> Result<CandidateBinding, Failure> {
    let Some(payload) = payload else {
        return Err(denied("broker: candidate binding payload required"));
    };
    if payload.len() != 1 {
        return Err(denied(
            "broker: candidate binding payload must be exactly one key",
        ));
    }
    let Some(raw) = payload.get("binding") else {
        return Err(denied("broker: missing binding field"));
    };
    let wire_binding: CandidateBindingWire =
        serde_json::from_str(raw.get()).map_err(|_| denied("broker: invalid candidate binding"))?;
    let digest = wire::b64_raw_decode(&wire_binding.digest)
        .filter(|d| d.len() == 32)
        .ok_or_else(|| denied("broker: invalid candidate binding"))?;
    let mut digest_arr = [0u8; 32];
    digest_arr.copy_from_slice(&digest);
    let binding = CandidateBinding {
        candidate_id: wire_binding.candidate_id,
        generation: wire_binding.generation,
        digest: Zeroizing::new(digest_arr),
    };
    if !binding.is_valid() {
        return Err(denied("broker: invalid candidate binding"));
    }
    Ok(binding)
}

// ---------------------------------------------------------------------------
// Runtime-side clients — `BootstrapActivator` + `BootstrapPresenter`
// ---------------------------------------------------------------------------

/// `BootstrapActivator` — the runtime-side client for broker candidate
/// activation (`ProtectedBootstrap`). It carries only opaque candidate
/// evidence over the socket; the verifier never crosses.
pub struct BootstrapActivator {
    socket_path: PathBuf,
}

impl BootstrapActivator {
    /// `NewBootstrapActivator` — the socket path is required.
    pub fn new(socket_path: PathBuf) -> Result<Self, Failure> {
        if socket_path.as_os_str().is_empty() {
            return Err(internal("bootstrap activator: socket path is required"));
        }
        Ok(Self { socket_path })
    }

    /// `call` — the shared register/activate exchange: closed-encode
    /// the binding, dial, peer-check, send the request line, require a
    /// success outcome echoed under the same operation id.
    fn call(&self, purpose: &str, binding: &CandidateBinding) -> Result<(), Failure> {
        if !binding.is_valid() {
            return Err(denied("bootstrap activator: invalid candidate binding"));
        }
        let wire_binding = CandidateBindingWire {
            candidate_id: binding.candidate_id.clone(),
            generation: binding.generation,
            digest: wire::b64_raw_encode(&binding.digest[..]),
        };
        let raw = serde_json::to_string(&wire_binding)
            .map_err(|_| denied("bootstrap activator: encode binding"))?;
        let conn = UnixStream::connect(&self.socket_path)
            .map_err(|e| internal(format!("bootstrap activator: dial broker: {e}")))?;
        // Upstream's `b05PeerCredentials` + `peer.Uid != 0 &&
        // peer.Uid != os.Getuid()` gate — the broker must be root or
        // this process's own uid.
        let peer = crate::sys::peercred::peercred(&conn)
            .map_err(|_| denied("bootstrap activator: peer credentials unavailable"))?;
        let self_uid = rustix::process::geteuid().as_raw();
        if peer.uid.as_raw() != 0 && peer.uid.as_raw() != self_uid {
            return Err(denied("bootstrap activator: broker peer not authorized"));
        }
        let op_id = uuid::Uuid::now_v7().to_string();
        let mut payload = BTreeMap::new();
        payload.insert(
            "binding".to_owned(),
            serde_json::value::RawValue::from_string(raw)
                .map_err(|_| denied("bootstrap activator: encode binding"))?,
        );
        let request = BrokerRequest {
            operation_id: op_id.clone(),
            purpose: purpose.to_owned(),
            session_token: String::new(),
            payload: Some(payload),
        };
        let mut line = serde_json::to_vec(&request)
            .map_err(|_| denied("bootstrap activator: encode request"))?;
        line.push(b'\n');
        (&conn)
            .write_all(&line)
            .map_err(|e| internal(format!("bootstrap activator: write broker request: {e}")))?;
        let mut reader = BufReader::new(&conn);
        let mut resp_line = String::new();
        reader
            .read_line(&mut resp_line)
            .map_err(|e| internal(format!("bootstrap activator: read broker response: {e}")))?;
        let response: BrokerResponse = serde_json::from_str(resp_line.trim_end())
            .map_err(|e| internal(format!("bootstrap activator: decode broker response: {e}")))?;
        if response.operation_id != op_id || response.outcome != BrokerOutcome::Success {
            return Err(denied("bootstrap activator: broker denied"));
        }
        Ok(())
    }
}

/// `authority.ErrDenied` at the port boundary — broker internals never
/// cross; the session domain sees the same redacted refusal upstream's
/// plain `ErrDenied` produces.
fn authority_denied() -> central_session::contract::Failure {
    central_session::contract::Failure::new(
        central_session::contract::FailureClass::AuthorityDenied,
        "protected bootstrap authority refused",
        "request a fresh bootstrap token",
    )
}

impl central_session::port::ProtectedBootstrap for BootstrapActivator {
    /// `Register` — install exact candidate evidence for later
    /// activation, separate so activation cannot implicitly trust a
    /// caller-supplied binding.
    async fn register(
        &self,
        binding: CandidateBinding,
    ) -> Result<(), central_session::contract::Failure> {
        self.call(protocol::REGISTER_BOOTSTRAP_CANDIDATE_RPC, &binding)
            .map_err(|_| authority_denied())
    }

    /// `Activate` — confirm activation of the exact registered
    /// candidate binding.
    async fn activate(
        &self,
        binding: CandidateBinding,
    ) -> Result<(), central_session::contract::Failure> {
        self.call(protocol::ACTIVATE_BOOTSTRAP_CANDIDATE_RPC, &binding)
            .map_err(|_| authority_denied())
    }
}

/// `BootstrapPresenter` — requests the one-use staged bootstrap value
/// from the protected broker. The value is returned only to the
/// authenticated helper in memory.
pub struct BootstrapPresenter {
    socket_path: PathBuf,
}

impl BootstrapPresenter {
    /// `NewBootstrapPresenter` — the socket path is required.
    pub fn new(socket_path: PathBuf) -> Result<Self, Failure> {
        if socket_path.as_os_str().is_empty() {
            return Err(internal("bootstrap presenter: socket path is required"));
        }
        Ok(Self { socket_path })
    }

    /// `Produce` — `present_bootstrap` RPC; the returned value is
    /// raw-standard-base64, 1..=4096 bytes decoded.
    pub fn produce(&self) -> Result<Zeroizing<Vec<u8>>, Failure> {
        let conn = UnixStream::connect(&self.socket_path)
            .map_err(|_| denied("bootstrap presenter: dial failed"))?;
        let op_id = uuid::Uuid::now_v7().to_string();
        let request = BrokerRequest {
            operation_id: op_id.clone(),
            purpose: protocol::PRESENT_BOOTSTRAP_RPC.to_owned(),
            session_token: String::new(),
            payload: None,
        };
        let mut line = serde_json::to_vec(&request)
            .map_err(|_| denied("bootstrap presenter: encode request"))?;
        line.push(b'\n');
        (&conn)
            .write_all(&line)
            .map_err(|_| denied("bootstrap presenter: write failed"))?;
        let mut reader = BufReader::new(&conn);
        let mut resp_line = String::new();
        reader
            .read_line(&mut resp_line)
            .map_err(|_| denied("bootstrap presenter: read failed"))?;
        let response: BrokerResponse = serde_json::from_str(resp_line.trim_end())
            .map_err(|_| denied("bootstrap presenter: decode failed"))?;
        if response.operation_id != op_id || response.outcome != BrokerOutcome::Success {
            return Err(denied("bootstrap presenter: broker denied"));
        }
        #[derive(Deserialize)]
        struct PresentResult {
            value: String,
        }
        let result: PresentResult =
            serde_json::from_value(response.result.unwrap_or(serde_json::Value::Null))
                .map_err(|_| denied("bootstrap presenter: invalid result"))?;
        let value = wire::b64_raw_decode(&result.value)
            .filter(|v| !v.is_empty() && v.len() <= 4096)
            .map(Zeroizing::new)
            .ok_or_else(|| denied("bootstrap presenter: invalid value"))?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::testutil::TempDir;

    fn binding(id: &str, generation: u64, seed: u8) -> CandidateBinding {
        CandidateBinding {
            candidate_id: id.to_owned(),
            generation,
            digest: Zeroizing::new([seed; 32]),
        }
    }

    #[test]
    fn register_activate_exact_candidate() {
        let session = BootstrapSession::new();
        let b = binding("cand-1", 1, 0x11);
        session.register(&b).unwrap();
        assert!(!session.activated(&b));
        session.activate(&b).unwrap();
        assert!(session.activated(&b));
        // Activation is one-use.
        assert!(session.activate(&b).is_err());
    }

    #[test]
    fn register_rejects_invalid_and_rollback() {
        let session = BootstrapSession::new();
        // Empty candidate id refuses.
        let mut bad = binding("", 1, 0x22);
        assert!(session.register(&bad).is_err());
        // Zero generation refuses.
        bad = binding("cand", 0, 0x22);
        assert!(session.register(&bad).is_err());
        // Zero digest refuses.
        bad = binding("cand", 1, 0x00);
        assert!(session.register(&bad).is_err());
        // Valid registers; same-generation replacement denies
        // (candidate-rollback prevention).
        let b1 = binding("cand-2", 5, 0x33);
        session.register(&b1).unwrap();
        let same_gen = binding("cand-3", 5, 0x44);
        assert!(session.register(&same_gen).is_err());
        let older_gen = binding("cand-4", 4, 0x55);
        assert!(session.register(&older_gen).is_err());
        // Idempotent re-register of the identical unactivated binding.
        session.register(&b1).unwrap();
        // Newer generation replaces — even once activated.
        session.activate(&b1).unwrap();
        let newer = binding("cand-5", 6, 0x66);
        session.register(&newer).unwrap();
        assert!(!session.activated(&newer));
    }

    #[test]
    fn persistent_session_survives_restart() {
        let dir = TempDir::new("boot-sess");
        let b = binding("cand-p", 3, 0x77);
        {
            let session = BootstrapSession::new_persistent(&dir).unwrap();
            session.register(&b).unwrap();
            session.activate(&b).unwrap();
        }
        let session2 = BootstrapSession::new_persistent(&dir).unwrap();
        assert!(session2.activated(&b));
        // A re-activation attempt against the restarted registry denies.
        assert!(session2.activate(&b).is_err());
        // State file is private.
        let path = dir.join("bootstrap-candidate-state.json");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn reset_persists_zero_record() {
        let dir = TempDir::new("boot-reset");
        let b = binding("cand-r", 2, 0x88);
        {
            let session = BootstrapSession::new_persistent(&dir).unwrap();
            session.register(&b).unwrap();
            session.activate(&b).unwrap();
            session.reset().unwrap();
        }
        let session2 = BootstrapSession::new_persistent(&dir).unwrap();
        assert!(!session2.activated(&b));
        assert!(session2.activate(&b).is_err());
        // The persisted record is the zero state ({"activated":false}).
        let text = fs::read_to_string(dir.join("bootstrap-candidate-state.json")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v.get("activated"), Some(&serde_json::Value::Bool(false)));
        assert!(v.get("candidate_id").is_none());
        assert!(v.get("digest").is_none());
    }

    #[test]
    fn corrupt_state_refuses_restart() {
        let dir = TempDir::new("boot-corrupt");
        let path = dir.join("bootstrap-candidate-state.json");
        // Bad digest length.
        fs::write(
            &path,
            r#"{"candidate_id":"x","generation":1,"digest":"AAAA","activated":false}"#,
        )
        .unwrap();
        assert!(BootstrapSession::new_persistent(&dir).is_err());
        // Invalid JSON.
        fs::write(&path, b"not json").unwrap();
        assert!(BootstrapSession::new_persistent(&dir).is_err());
        // Invalid binding (zero digest array).
        fs::write(
            &path,
            format!(
                "{{\"candidate_id\":\"x\",\"generation\":1,\"digest\":\"{}\",\"activated\":false}}",
                wire::b64_raw_encode(&[0u8; 32])
            ),
        )
        .unwrap();
        assert!(BootstrapSession::new_persistent(&dir).is_err());
        // Empty record decodes as the empty registry.
        fs::write(&path, r#"{"activated":false}"#).unwrap();
        assert!(BootstrapSession::new_persistent(&dir).is_ok());
    }

    #[test]
    fn decode_candidate_binding_is_closed() {
        let b = binding("cand-w", 9, 0xAA);
        let wire_json = serde_json::json!({
            "candidate_id": b.candidate_id,
            "generation": b.generation,
            "digest": wire::b64_raw_encode(&b.digest[..]),
        });
        let mut payload = BTreeMap::new();
        payload.insert(
            "binding".to_owned(),
            serde_json::value::RawValue::from_string(wire_json.to_string()).unwrap(),
        );
        // Exactly one key, correct shape → decoded binding equals.
        let decoded = decode_candidate_binding(Some(&payload)).unwrap();
        assert!(decoded.equal(&b));
        // Missing payload, missing key, extra key, unknown wire field,
        // and padded base64 all deny.
        assert!(decode_candidate_binding(None).is_err());
        let empty = BTreeMap::new();
        assert!(decode_candidate_binding(Some(&empty)).is_err());
        payload.insert(
            "extra".to_owned(),
            serde_json::value::RawValue::from_string("1".to_owned()).unwrap(),
        );
        assert!(decode_candidate_binding(Some(&payload)).is_err());
        payload.remove("extra");
        let unknown_field = serde_json::json!({
            "candidate_id": "x", "generation": 1,
            "digest": wire::b64_raw_encode(&[1u8; 32]), "zzz": 1
        });
        let mut p2 = BTreeMap::new();
        p2.insert(
            "binding".to_owned(),
            serde_json::value::RawValue::from_string(unknown_field.to_string()).unwrap(),
        );
        assert!(decode_candidate_binding(Some(&p2)).is_err());
        // Padded base64 digest refuses (raw std encoding only).
        let padded = serde_json::json!({
            "candidate_id": "x", "generation": 1,
            "digest": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        });
        let mut p3 = BTreeMap::new();
        p3.insert(
            "binding".to_owned(),
            serde_json::value::RawValue::from_string(padded.to_string()).unwrap(),
        );
        assert!(decode_candidate_binding(Some(&p3)).is_err());
    }

    #[test]
    fn activator_and_presenter_require_socket_path() {
        assert!(BootstrapActivator::new(PathBuf::new()).is_err());
        assert!(BootstrapPresenter::new(PathBuf::new()).is_err());
    }
}
