//! `dev_bootstrap` — the R3 open-decision-D1 development implementation
//! of `central_session::port::ProtectedBootstrap`: the broker-owned
//! one-use candidate registry, ported from upstream
//! `internal/adapter/authority/broker/bootstrap_session.go`'s
//! `BootstrapSession` with its `statePath` durability.
//!
//! **It is for development and tests only.** The real bootstrap token
//! authority is the R5 protected broker; this file-backed registry
//! exists so the R3 session slice can run the two-phase exchange
//! end-to-end without the broker. Construction therefore fails closed
//! unless the explicit dev gate [`DEV_GATE_ENV`]`=1` is set — the same
//! gate `central-adapter-harness::localexec` uses for its dev-only
//! launcher (the issue-120 dev-gate contract, applied per D1).
//!
//! Semantics (upstream `Register`/`Activate`/`Reset`/`Activated`):
//!
//! - `register` installs the exact candidate evidence the broker may
//!   later activate. A newer generation replaces an already-consumed
//!   registration; same-generation replacement is denied to prevent
//!   candidate rollback. Re-registering the identical un-activated
//!   binding is idempotent.
//! - `activate` consumes the exact currently registered candidate —
//!   candidate id, generation, AND digest must match; it is never a
//!   verifier comparison. It is single-use: a second activation is
//!   denied.
//! - Every mutation persists atomically (write `.tmp` at mode `0600`,
//!   fsync, rename, fsync the directory) and rolls the in-memory state
//!   back when persistence fails.
//! - `activated` reports whether the exact registered candidate was
//!   activated — the crash-reconciliation read; it never exposes the
//!   digest.
//!
//! Every refusal collapses to the typed
//! `FailureClass::AuthorityDenied` + `Sentinel::AuthorityDenied`
//! failure — upstream's `authority.ErrDenied` — so a malformed request,
//! a stale registration, and a persistence failure are
//! indistinguishable and never carry the binding's digest, the file
//! path, or the underlying I/O error text.
//!
//! Upstream divergence notes:
//!
//! - The persisted JSON keeps upstream's field names
//!   (`candidate_id`/`generation`/`digest`/`activated`) but encodes the
//!   digest as hex rather than `base64.RawStdEncoding` — `base64` is
//!   not a workspace dependency and this file is written and read only
//!   by this module (the R5 broker owns its own state file).
//! - Upstream's context cancellation is absent (the Rust port trait
//!   carries no `ctx`); `syncFile`/`syncDir` are `File::sync_all` calls.

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use central_session::contract::{CandidateBinding, Failure, FailureClass, Sentinel};
use central_session::port::ProtectedBootstrap;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// `DEV_GATE_ENV` — the explicit dev gate. Construction of
/// [`DevFileProtectedBootstrap`] refuses unless this environment
/// variable is exactly `1`. It is deliberately the same variable
/// `central-adapter-harness::localexec::DEV_GATE_ENV` uses (R3 D1:
/// "a file-backed dev implementation behind the same dev gate as
/// `localexec`"); the crate defines its own constant because adapters
/// must not import other adapters.
pub const DEV_GATE_ENV: &str = "CENTRAL_LOCALEXEC";

/// The upstream state-file name within the configured root
/// (`filepath.Join(rootPath, "bootstrap-candidate-state.json")`).
const STATE_FILE_NAME: &str = "bootstrap-candidate-state.json";

/// The durable state — mirrors upstream's anonymous JSON struct. The
/// digest is hex text (see module divergence note); `candidate_id`,
/// `generation`, and `digest` are absent (upstream `omitempty`) when no
/// registration exists.
#[derive(Serialize, Deserialize)]
struct StateFile {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    candidate_id: String,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    generation: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    digest: String,
    activated: bool,
}

const fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

fn hex_encode(input: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(input.len() * 2);
    for &b in input {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Strict hex decode of exactly 32 bytes (`Err` on any other length or
/// non-hex character — the malformed-state path upstream collapses to
/// "invalid bootstrap candidate state").
fn hex_decode_32(text: &str) -> Result<[u8; 32], ()> {
    let b = text.as_bytes();
    if b.len() != 64 {
        return Err(());
    }
    let nibble = |c: u8| -> Result<u8, ()> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            _ => Err(()),
        }
    };
    let mut out = [0u8; 32];
    for (i, pair) in b.as_chunks::<2>().0.iter().enumerate() {
        out[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(out)
}

/// The single in-memory state — the upstream `BootstrapSession`
/// fields under one mutex. `registered: None` is upstream's `set ==
/// false`.
#[derive(Debug)]
struct Inner {
    path: PathBuf,
    registered: Option<CandidateBinding>,
    activated: bool,
}

/// `DevFileProtectedBootstrap` — the dev-gated, file-backed
/// `ProtectedBootstrap`. A `Mutex` serializes register/activate just
/// like upstream's `sync.Mutex`; the guard is never held across an
/// await point (the methods are synchronous file I/O inside async
/// signatures, exactly as upstream's methods are synchronous under
/// `ctx`).
#[derive(Debug)]
pub struct DevFileProtectedBootstrap {
    inner: Mutex<Inner>,
}

impl DevFileProtectedBootstrap {
    /// `New` — fails closed unless [`DEV_GATE_ENV`]`=1` is set, then
    /// loads the persisted registry from `root` (absent file means an
    /// empty registry; malformed content is a safe denial).
    pub fn new(root: &Path) -> Result<Self, Failure> {
        let open = std::env::var_os(DEV_GATE_ENV).is_some_and(|v| v == "1");
        Self::new_checked(root, open)
    }

    /// `new_checked` — the single place gate and state loading live;
    /// tests drive both verdicts without mutating the process
    /// environment (the `localexec::new_checked` seam pattern).
    pub(crate) fn new_checked(root: &Path, gate_open: bool) -> Result<Self, Failure> {
        if !gate_open {
            return Err(denied());
        }
        let path = root.join(STATE_FILE_NAME);
        let mut inner = Inner {
            path,
            registered: None,
            activated: false,
        };
        load(&mut inner)?;
        Ok(Self {
            inner: Mutex::new(inner),
        })
    }

    /// `Activated` — reports whether the exact registered candidate has
    /// been activated. It is intended for crash reconciliation and
    /// never exposes the candidate digest.
    pub fn activated(&self, binding: &CandidateBinding) -> bool {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.activated && inner.registered.as_ref().is_some_and(|r| r.equal(binding))
    }

    /// `Reset` — invalidates the durable candidate registry after a
    /// destructive recovery. It does not install a replacement
    /// candidate: successful recovery must complete a new normal
    /// bootstrap exchange. The zero record is persisted before this
    /// method returns, so a restart cannot resurrect a pre-restore
    /// candidate.
    pub fn reset(&self) -> Result<(), Failure> {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let previous = inner.registered.take();
        let previous_activated = inner.activated;
        inner.activated = false;
        if persist(&inner).is_err() {
            inner.registered = previous;
            inner.activated = previous_activated;
            return Err(denied());
        }
        Ok(())
    }
}

impl ProtectedBootstrap for DevFileProtectedBootstrap {
    /// `Register` — records the exact candidate the broker may
    /// activate. A newer generation replaces an already-consumed
    /// registration; same-generation replacement is denied to prevent
    /// candidate rollback.
    async fn register(&self, binding: CandidateBinding) -> Result<(), Failure> {
        if !binding.is_valid() {
            return Err(denied());
        }
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(registered) = &inner.registered {
            if registered.equal(&binding) && !inner.activated {
                return Ok(());
            }
            if binding.generation <= registered.generation {
                return Err(denied());
            }
        }
        let previous = inner.registered.replace(binding);
        let previous_activated = inner.activated;
        inner.activated = false;
        if persist(&inner).is_err() {
            inner.registered = previous;
            inner.activated = previous_activated;
            return Err(denied());
        }
        Ok(())
    }

    /// `Activate` — consumes the exact currently registered candidate.
    /// The comparison includes candidate ID, generation, and digest,
    /// and is never a verifier comparison.
    async fn activate(&self, binding: CandidateBinding) -> Result<(), Failure> {
        if !binding.is_valid() {
            return Err(denied());
        }
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if inner.activated || !inner.registered.as_ref().is_some_and(|r| r.equal(&binding)) {
            return Err(denied());
        }
        inner.activated = true;
        if persist(&inner).is_err() {
            inner.activated = false;
            return Err(denied());
        }
        Ok(())
    }
}

/// `load` — upstream `newPersistentBootstrapSession`'s read path: a
/// missing file is an empty registry, malformed or implausible content
/// is a denial (never a formatted I/O or decode error).
fn load(inner: &mut Inner) -> Result<(), Failure> {
    let mut data = Vec::new();
    match File::open(&inner.path).and_then(|mut f| f.read_to_end(&mut data)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(denied()),
        Ok(_) => {}
    }
    let state: StateFile = serde_json::from_slice(&data).map_err(|_| denied())?;
    if state.candidate_id.is_empty() && state.generation == 0 && state.digest.is_empty() {
        // The all-empty record is a persisted Reset — still an empty
        // registry regardless of the `activated` bit (upstream clears
        // it through the same zero record).
        return Ok(());
    }
    let digest = hex_decode_32(&state.digest).map_err(|_| denied())?;
    let binding = CandidateBinding {
        candidate_id: state.candidate_id,
        generation: state.generation,
        digest: Zeroizing::new(digest),
    };
    if !binding.is_valid() {
        return Err(denied());
    }
    inner.registered = Some(binding);
    inner.activated = state.activated;
    Ok(())
}

/// `persistLocked` — the upstream atomic write: `0600` temp file,
/// fsync, rename over the state path, fsync the containing directory.
/// Failure leaves the old state file intact.
fn persist(inner: &Inner) -> Result<(), ()> {
    let state = match &inner.registered {
        Some(b) => StateFile {
            candidate_id: b.candidate_id.clone(),
            generation: b.generation,
            digest: hex_encode(&b.digest[..]),
            activated: inner.activated,
        },
        None => StateFile {
            candidate_id: String::new(),
            generation: 0,
            digest: String::new(),
            activated: false,
        },
    };
    let data = serde_json::to_vec(&state).map_err(|_| ())?;
    let tmp = tmp_path(&inner.path);
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|_| ())?;
        let written = f
            .write_all(&data)
            .and_then(|()| f.sync_all())
            .map_err(|_| ());
        drop(f);
        written?;
    }
    std::fs::rename(&tmp, &inner.path).map_err(|_| ())?;
    let dir = inner
        .path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    File::open(dir).and_then(|d| d.sync_all()).map_err(|_| ())?;
    Ok(())
}

fn tmp_path(state: &Path) -> PathBuf {
    let mut name = state.as_os_str().to_os_string();
    name.push(".tmp");
    PathBuf::from(name)
}

/// `authority.ErrDenied` — every refusal collapses to the typed
/// authority-denied `Failure`; no operation name, path, I/O error,
/// or digest reaches the text.
fn denied() -> Failure {
    Failure::new(
        FailureClass::AuthorityDenied,
        "protected bootstrap authority refused",
        "request a fresh bootstrap token",
    )
    .with_cause(Sentinel::AuthorityDenied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    /// Runs an immediately-ready future to completion (the registry
    /// never yields) — the workspace's unsafe-free `block_on` pattern.
    fn block_on<F: core::future::Future>(fut: F) -> F::Output {
        let mut context = core::task::Context::from_waker(core::task::Waker::noop());
        let mut fut = std::pin::pin!(fut);
        loop {
            match fut.as_mut().poll(&mut context) {
                core::task::Poll::Ready(output) => return output,
                core::task::Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    fn temp_root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "central-dev-bootstrap-{}-{}",
            std::process::id(),
            tag
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn binding(candidate_id: &str, generation: u64, seed: u8) -> CandidateBinding {
        CandidateBinding {
            candidate_id: candidate_id.to_string(),
            generation,
            digest: Zeroizing::new([seed; 32]),
        }
    }

    /// `New` refuses to construct without the dev gate — the negative
    /// construction test D1 requires.
    #[test]
    fn new_refuses_without_dev_gate() {
        let dir = temp_root("gate");
        let err = DevFileProtectedBootstrap::new_checked(&dir, false).unwrap_err();
        assert_eq!(err.class, Some(FailureClass::AuthorityDenied));
        assert!(err.is_sentinel(Sentinel::AuthorityDenied));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Register → activate → deny replay, across a state reload.
    #[test]
    fn register_then_activate_persists_and_denies_replay() {
        let dir = temp_root("happy");
        let b = binding("cand-1", 3, 0x11);
        {
            let reg = DevFileProtectedBootstrap::new_checked(&dir, true).unwrap();
            block_on(reg.register(b.clone())).unwrap();
            block_on(reg.activate(b.clone())).unwrap();
            assert!(reg.activated(&b));
        }
        // Reload from disk: the activated marker survives.
        let reg = DevFileProtectedBootstrap::new_checked(&dir, true).unwrap();
        assert!(reg.activated(&b));
        // Second activation is single-use denied.
        let err = block_on(reg.activate(b.clone())).unwrap_err();
        assert_eq!(err.class, Some(FailureClass::AuthorityDenied));
        // A non-matching digest is denied too.
        let other = binding("cand-1", 3, 0x22);
        block_on(reg.activate(other)).unwrap_err();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Register semantics: identical un-activated re-register is
    /// idempotent; same-generation replacement is denied; a newer
    /// generation replaces.
    #[test]
    fn register_semantics_match_upstream() {
        let dir = temp_root("register");
        let reg = DevFileProtectedBootstrap::new_checked(&dir, true).unwrap();
        let gen3 = binding("cand-3", 3, 0x33);
        block_on(reg.register(gen3.clone())).unwrap();
        // Idempotent re-register of the same binding.
        block_on(reg.register(gen3.clone())).unwrap();
        // Same-generation replacement is denied (rollback).
        block_on(reg.register(binding("cand-4", 3, 0x44))).unwrap_err();
        // Older generation is denied.
        block_on(reg.register(binding("cand-5", 2, 0x55))).unwrap_err();
        // Newer generation replaces.
        let gen4 = binding("cand-6", 4, 0x66);
        block_on(reg.register(gen4.clone())).unwrap();
        block_on(reg.activate(gen4.clone())).unwrap();
        // After activation a newer generation may replace.
        let gen5 = binding("cand-7", 5, 0x77);
        block_on(reg.register(gen5.clone())).unwrap();
        block_on(reg.activate(gen5)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Malformed durable state is a denial, never a formatted decode or
    /// I/O error — and contains no secret material.
    #[test]
    fn malformed_state_is_denied_without_leak() {
        for (tag, body) in [
            ("notjson", b"not json".as_slice()),
            ("shortdigest", br#"{"candidate_id":"c","generation":1,"digest":"zz","activated":false}"#.as_slice()),
            ("zerodigest", br#"{"candidate_id":"c","generation":1,"digest":"0000000000000000000000000000000000000000000000000000000000000000","activated":false}"#.as_slice()),
        ] {
            let dir = temp_root(&format!("bad-{tag}"));
            std::fs::write(dir.join(STATE_FILE_NAME), body).unwrap();
            let err = DevFileProtectedBootstrap::new_checked(&dir, true).unwrap_err();
            assert_eq!(err.class, Some(FailureClass::AuthorityDenied));
            let text = err.to_string();
            assert!(!text.contains("candidate_id"));
            assert!(!text.contains("digest"));
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// A persisted `Reset` (`{"activated":false}`) loads as an empty
    /// registry; `reset()` persists the zero record before returning.
    #[test]
    fn reset_persists_zero_record() {
        let dir = temp_root("reset");
        let b = binding("cand-9", 9, 0x99);
        let reg = DevFileProtectedBootstrap::new_checked(&dir, true).unwrap();
        block_on(reg.register(b.clone())).unwrap();
        block_on(reg.activate(b.clone())).unwrap();
        reg.reset().unwrap();
        assert!(!reg.activated(&b));
        // Re-registration after reset is allowed (empty registry).
        let fresh = binding("cand-10", 10, 0xaa);
        block_on(reg.register(fresh.clone())).unwrap();
        // And the zero record survives a reload boundary.
        let reg2 = DevFileProtectedBootstrap::new_checked(&dir, true).unwrap();
        assert!(!reg2.activated(&fresh));
        block_on(reg2.activate(fresh)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `is_valid` gates every port entry: empty id, zero generation, or
    /// zero digest are denied without touching the file.
    #[test]
    fn invalid_bindings_are_denied() {
        let dir = temp_root("invalid");
        let reg = DevFileProtectedBootstrap::new_checked(&dir, true).unwrap();
        for b in [
            binding("", 1, 0x01),
            binding("c", 0, 0x01),
            CandidateBinding {
                candidate_id: "c".to_string(),
                generation: 1,
                digest: Zeroizing::new([0u8; 32]),
            },
        ] {
            block_on(reg.register(b.clone())).unwrap_err();
            block_on(reg.activate(b)).unwrap_err();
        }
        assert!(!dir.join(STATE_FILE_NAME).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The state file is written `0600` — the upstream permission.
    #[test]
    fn state_file_is_owner_only() {
        let dir = temp_root("mode");
        let reg = DevFileProtectedBootstrap::new_checked(&dir, true).unwrap();
        block_on(reg.register(binding("c", 1, 0x01))).unwrap();
        let mode = std::fs::metadata(dir.join(STATE_FILE_NAME))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
