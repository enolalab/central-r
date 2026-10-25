//! `settle.go` — the settlement outcome vocabulary and the SIGTERM →
//! 10 s grace → SIGKILL constant the launcher's deadline arm runs.
//!
//! The settle *loop* lives in `launcher.rs` beside the `waitpid`/`pidfd`
//! handles it needs; what upstream's portable `Settle` stub returned
//! (the outcome shape and the grace constant) is what this file pins.

use std::time::Duration;

/// `DefaultGracePeriod` — how long the launcher waits after SIGTERM
/// before escalating to SIGKILL: upstream's `10 * time.Second`.
pub const DEFAULT_GRACE_PERIOD: Duration = Duration::from_secs(10);

/// `SettleOutcome` — the final state of a sandboxed process after the
/// settlement protocol completes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettleOutcome {
    /// The exit code the process settled with (0 when the class is not
    /// a normal exit and no code was reported — upstream's `int`).
    pub exit_code: i32,
    /// `normal` | `error` | `deadline`.
    pub exit_class: String,
    /// `clean` | `unclean`.
    pub cleanup_result: String,
}

impl SettleOutcome {
    /// `IsClean` — exited normally *and* all resources reclaimed.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.cleanup_result == "clean" && self.exit_class == "normal"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `IsClean` needs both halves — a normal exit over a failed
    /// cleanup is not clean, and neither is a clean teardown of a
    /// failed run.
    #[test]
    fn is_clean_requires_normal_exit_and_clean_cleanup() {
        let clean = SettleOutcome {
            exit_code: 0,
            exit_class: "normal".to_owned(),
            cleanup_result: "clean".to_owned(),
        };
        assert!(clean.is_clean());
        for (class, cleanup) in [
            ("error", "clean"),
            ("deadline", "clean"),
            ("normal", "unclean"),
            ("error", "unclean"),
        ] {
            let outcome = SettleOutcome {
                exit_code: 0,
                exit_class: class.to_owned(),
                cleanup_result: cleanup.to_owned(),
            };
            assert!(!outcome.is_clean(), "{class}/{cleanup}");
        }
    }

    /// The grace constant is upstream's 10 seconds.
    #[test]
    fn grace_period_is_ten_seconds() {
        assert_eq!(DEFAULT_GRACE_PERIOD, Duration::from_secs(10));
    }
}
