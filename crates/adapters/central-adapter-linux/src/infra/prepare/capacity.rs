//! `capacity_linux.go` — the free-space gate. One `statfs` on the
//! state root's filesystem answers whether the selector's acquisition
//! may start; the reserve is a fixed floor a prepare may not spend.

use std::path::PathBuf;

use central_foundation::failure::Failure;
use central_infra::domain::codes;

use super::OpDeadline;

/// `reservedCapacityBytes` — the floor left free after any prepare:
/// 2 GiB. An acquisition whose host cannot promise that refuses before
/// it begins.
pub const RESERVED_CAPACITY_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// `allowedSelectors` — the closed selector set a capacity check may
/// be asked about.
const ALLOWED_SELECTORS: [&str; 2] = ["postgresql", "minio"];

/// `CapacityChecker` — upstream `port.CapacityChecker`.
#[derive(Debug, Clone)]
pub struct CapacityChecker {
    base_path: PathBuf,
}

impl CapacityChecker {
    /// `NewCapacityChecker` — `basePath` is the state root whose
    /// filesystem's free space is measured.
    #[must_use]
    pub fn new(base_path: impl Into<PathBuf>) -> Self {
        Self {
            base_path: base_path.into(),
        }
    }

    /// `HasCapacity` — refuses an unknown or empty selector, honors
    /// cancellation, then compares the filesystem's
    /// non-root-available bytes against the reserve.
    ///
    /// # Errors
    /// `CANDIDATE_INVALID` for an unlisted selector, `cancelled` once
    /// the operation deadline has passed, `internal` when `statfs`
    /// itself fails.
    pub fn has_capacity(&self, deadline: OpDeadline, selector: &str) -> Result<bool, Failure> {
        if selector.is_empty() || !ALLOWED_SELECTORS.contains(&selector) {
            return Err(Failure::invalid(
                codes::CANDIDATE_INVALID,
                format!("dependencyprepare: unknown selector {selector:?}"),
            ));
        }
        deadline.check()?;

        let stat = rustix::fs::statfs(&self.base_path).map_err(|e| {
            Failure::internal(
                "CAPACITY_STATFS",
                format!(
                    "dependencyprepare: statfs {}: {e}",
                    self.base_path.display()
                ),
            )
        })?;
        // `f_bavail` is the count an unprivileged caller may actually
        // consume — upstream reads `Bavail`, not `Bfree`.
        #[allow(clippy::cast_sign_loss)]
        let available = stat.f_bavail as u64 * stat.f_bsize as u64;
        Ok(available >= RESERVED_CAPACITY_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// `TestCapacityCheckerHasCapacityForKnownSelector` — the host's
    /// own tempdir reports a real answer for a locked selector.
    #[test]
    fn has_capacity_for_known_selector() {
        let checker = CapacityChecker::new(std::env::temp_dir());
        let answer = checker
            .has_capacity(OpDeadline::NONE, "minio")
            .expect("statfs on tempdir");
        // The test host may or may not carry 2 GiB free; the contract
        // is that the call answered rather than that it answered true.
        let _ = answer;
    }

    /// `TestCapacityCheckerRejectsEmptySelector` and
    /// `TestCapacityCheckerRejectsUnknownSelector`.
    #[test]
    fn rejects_unknown_selectors() {
        let checker = CapacityChecker::new(std::env::temp_dir());
        for selector in ["", "redis", "bogus"] {
            assert_eq!(
                checker
                    .has_capacity(OpDeadline::NONE, selector)
                    .unwrap_err()
                    .code(),
                codes::CANDIDATE_INVALID
            );
        }
    }

    /// `TestCapacityCheckerRejectsNonExistentPath` — a statfs that
    /// fails is a hard error, not a false.
    #[test]
    fn rejects_nonexistent_path() {
        let checker = CapacityChecker::new("/nonexistent/central-test-path");
        assert!(checker.has_capacity(OpDeadline::NONE, "minio").is_err());
    }

    /// `TestCapacityCheckerRespectsContextCancellation` — an elapsed
    /// budget refuses before statfs is consulted.
    #[test]
    fn respects_cancellation() {
        let checker = CapacityChecker::new(std::env::temp_dir());
        let elapsed = OpDeadline(Some(std::time::Instant::now() - Duration::from_secs(1)));
        let err = checker.has_capacity(elapsed, "minio").unwrap_err();
        assert_eq!(
            err.kind(),
            central_foundation::failure::FailureKind::Cancelled
        );
    }
}
