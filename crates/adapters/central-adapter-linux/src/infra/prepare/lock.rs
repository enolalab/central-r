//! `lock.go` — the trivial port surface: hands the loaded, verified
//! dependency lock to whatever stage asks for it. Loading happens once
//! at construction — the same bytes every later stage verifies again
//! before it trusts them.

use central_foundation::failure::Failure;
use central_infra::prepare::{self, Lock};

/// `LockAdapter` — upstream's `port.Locker` implementation.
#[derive(Debug, Clone)]
pub struct LockAdapter {
    lock: Lock,
}

impl LockAdapter {
    /// `NewLockAdapter` — loads the embedded lock and verifies every
    /// identity it ships (upstream `LoadLock`, which runs the full
    /// verification suite at parse).
    ///
    /// # Errors
    /// Any lock verification failure — schema, digest, identities,
    /// capability shapes — refuses construction rather than handing a
    /// questionable lock to a later stage.
    pub fn new() -> Result<Self, Failure> {
        Ok(Self {
            lock: prepare::load_lock()?,
        })
    }

    /// `NewLockAdapterWithLock` — a pre-verified lock, for tests and
    /// for callers that already loaded it.
    #[must_use]
    pub fn with_lock(lock: Lock) -> Self {
        Self { lock }
    }

    /// `Lock` — the verified dependency lock.
    #[must_use]
    pub fn lock(&self) -> &Lock {
        &self.lock
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `TestLockAdapterLoadsEmbeddedLock` — the embedded assets parse
    /// and verify at adapter construction.
    #[test]
    fn lock_adapter_loads_embedded_lock() {
        let adapter = LockAdapter::new().expect("NewLockAdapter");
        assert!(adapter.lock().fetch_capability.contains_key("minio"));
    }

    /// `TestLockAdapterWithInjectedLock` — a caller-supplied lock is
    /// returned verbatim.
    #[test]
    fn lock_adapter_with_injected_lock() {
        let lock = prepare::load_lock().expect("load lock");
        let adapter = LockAdapter::with_lock(lock.clone());
        assert_eq!(adapter.lock().schema, lock.schema);
    }
}
