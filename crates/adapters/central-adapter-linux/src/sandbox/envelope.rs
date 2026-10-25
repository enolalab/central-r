//! `envelope.go` — the closed resource envelopes and executable-class
//! vocabulary, plus the `LaunchService`'s deadline cap from
//! `internal/sandbox/app/launch_service.go`.
//!
//! Upstream's `ValidateLimits`/`ValidateBinary` messages are carried
//! verbatim (the wire's `reason` field is the only text a caller ever
//! sees); the failure kind is `denied` — an envelope refusal is an
//! authority refusal in this codebase's taxonomy (upstream returns
//! bare `error`s, which all land on the same `{"outcome":"error"}`
//! response).

use std::time::Duration;

use central_foundation::failure::Failure;

use super::domain::ResourceLimits;

/// `DefaultLimits` — the envelope a caller that names no limits gets:
/// half a core, 256 MiB, 32 processes, 64 descriptors.
pub const DEFAULT_LIMITS: ResourceLimits = ResourceLimits {
    cpu: 0.5,
    memory_bytes: 256 * 1024 * 1024,
    max_processes: 32,
    max_file_descriptors: 64,
};

/// `HardLimits` — the ceiling `ValidateLimits` rejects requests
/// above: 1 core, 512 MiB, 32 processes, 64 descriptors.
pub const HARD_LIMITS: ResourceLimits = ResourceLimits {
    cpu: 1.0,
    memory_bytes: 512 * 1024 * 1024,
    max_processes: 32,
    max_file_descriptors: 64,
};

/// The `central-agent` identity — upstream `launcher_linux.go`'s
/// `agentUID`/`agentGID` (502/502), "the locked numeric identities
/// allocated during genesis"; the reference host may override them at
/// genesis, which is why they live on the service config, not only
/// here.
pub const AGENT_UID: u32 = 502;
/// The `central-agent` group.
pub const AGENT_GID: u32 = 502;

/// `allowedBinaries` — the closed set of executable classes the
/// launcher admits. Values are symbolic names the launcher resolves;
/// a request may never name a filesystem path.
pub const ALLOWED_BINARIES: &[&str] = &["central-agent"];

/// The `LaunchService` deadline ceiling — upstream
/// `app/launch_service.go`'s `600*time.Second` hard cap.
pub const DEADLINE_HARD_CAP: Duration = Duration::from_secs(600);

/// The deadline a request with `deadline_ms == 0` gets — the
/// production socket units' operational assumption; upstream applies
/// the raw zero duration, which would settle every launch instantly,
/// so the port pins the same 300 s the broker's idle timeout uses
/// (documented divergence).
pub const DEADLINE_DEFAULT: Duration = Duration::from_secs(300);

fn denied(msg: impl Into<String>) -> Failure {
    Failure::denied("sandbox_denied", msg.into())
}

/// `ValidateLimits` — every field of `req` must be at or under the
/// matching `HardLimits` cap, upstream's checks and messages.
///
/// # Errors
/// `sandbox_denied` naming the first field over its cap.
pub fn validate_limits(req: &ResourceLimits) -> Result<(), Failure> {
    if req.cpu > HARD_LIMITS.cpu {
        return Err(denied(format!(
            "sandbox: CPU {:.1} exceeds hard cap {:.1}",
            req.cpu, HARD_LIMITS.cpu
        )));
    }
    if req.memory_bytes > HARD_LIMITS.memory_bytes {
        return Err(denied(format!(
            "sandbox: memory {} exceeds hard cap {}",
            req.memory_bytes, HARD_LIMITS.memory_bytes
        )));
    }
    if req.max_processes > HARD_LIMITS.max_processes {
        return Err(denied(format!(
            "sandbox: max_processes {} exceeds hard cap {}",
            req.max_processes, HARD_LIMITS.max_processes
        )));
    }
    if req.max_file_descriptors > HARD_LIMITS.max_file_descriptors {
        return Err(denied(format!(
            "sandbox: max_file_descriptors {} exceeds hard cap {}",
            req.max_file_descriptors, HARD_LIMITS.max_file_descriptors
        )));
    }
    Ok(())
}

/// `ValidateBinary` — `name` must be one of [`ALLOWED_BINARIES`]. An
/// absolute path is refused here before it could ever reach the
/// filesystem: `/etc/passwd` is not an executable *class*.
///
/// # Errors
/// `sandbox_denied` with upstream's `unknown executable class`.
pub fn validate_binary(name: &str) -> Result<(), Failure> {
    if !ALLOWED_BINARIES.contains(&name) {
        return Err(denied(format!(
            "sandbox: unknown executable class: {name:?}"
        )));
    }
    Ok(())
}

/// The `LaunchService` deadline gate — `req > 600s` refuses; `0`
/// resolves to [`DEADLINE_DEFAULT`]. Returns the effective deadline.
///
/// # Errors
/// `sandbox_denied` when the requested deadline exceeds the cap.
pub fn effective_deadline(deadline: Duration) -> Result<Duration, Failure> {
    if deadline > DEADLINE_HARD_CAP {
        return Err(denied(format!(
            "sandbox: deadline {} exceeds hard cap 600s",
            go_duration(deadline)
        )));
    }
    if deadline.is_zero() {
        return Ok(DEADLINE_DEFAULT);
    }
    Ok(deadline)
}

/// Go's `Duration.String()` for the denial message — `10m0.000000001s`
/// shapes. Only the h/m/s and fractional-second forms a duration this
/// size can take are rendered.
fn go_duration(d: Duration) -> String {
    let nanos = d.as_nanos() as u64;
    if nanos == 0 {
        return "0s".to_owned();
    }
    let secs = nanos / 1_000_000_000;
    let frac = nanos % 1_000_000_000;
    let hours = secs / 3600;
    let mins = (secs % 3600) / 60;
    let s = secs % 60;
    let mut out = String::new();
    if hours > 0 {
        out.push_str(&format!("{hours}h"));
    }
    if hours > 0 || mins > 0 {
        out.push_str(&format!("{mins}m"));
    }
    out.push_str(&format!("{s}"));
    if frac > 0 {
        let mut frac_str = format!("{frac:09}");
        while frac_str.ends_with('0') {
            frac_str.pop();
        }
        out.push_str(&format!(".{frac_str}"));
    }
    out.push('s');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The envelope constants pin upstream's exact numbers.
    #[test]
    fn envelopes_match_upstream() {
        assert_eq!(DEFAULT_LIMITS.cpu, 0.5);
        assert_eq!(DEFAULT_LIMITS.memory_bytes, 256 << 20);
        assert_eq!(DEFAULT_LIMITS.max_processes, 32);
        assert_eq!(DEFAULT_LIMITS.max_file_descriptors, 64);
        assert_eq!(HARD_LIMITS.cpu, 1.0);
        assert_eq!(HARD_LIMITS.memory_bytes, 512 << 20);
        assert_eq!(HARD_LIMITS.max_processes, 32);
        assert_eq!(HARD_LIMITS.max_file_descriptors, 64);
        assert_eq!(AGENT_UID, 502);
        assert_eq!(AGENT_GID, 502);
    }

    /// `ValidateLimits`'s denial matrix — each field above its cap is
    /// a refused request with upstream's message.
    #[test]
    fn limits_over_cap_are_denied() {
        let cases: [(ResourceLimits, &str); 4] = [
            (
                ResourceLimits {
                    cpu: 2.0,
                    ..ResourceLimits::default()
                },
                "sandbox: CPU 2.0 exceeds hard cap 1.0",
            ),
            (
                ResourceLimits {
                    memory_bytes: 1 << 30,
                    ..ResourceLimits::default()
                },
                "sandbox: memory 1073741824 exceeds hard cap 536870912",
            ),
            (
                ResourceLimits {
                    max_processes: 128,
                    ..ResourceLimits::default()
                },
                "sandbox: max_processes 128 exceeds hard cap 32",
            ),
            (
                ResourceLimits {
                    max_file_descriptors: 256,
                    ..ResourceLimits::default()
                },
                "sandbox: max_file_descriptors 256 exceeds hard cap 64",
            ),
        ];
        for (limits, want) in cases {
            let err = validate_limits(&limits).unwrap_err();
            assert_eq!(err.code(), "sandbox_denied");
            assert_eq!(err.message(), want);
        }
        // At the cap and defaults both pass.
        validate_limits(&HARD_LIMITS).expect("hard cap");
        validate_limits(&DEFAULT_LIMITS).expect("defaults");
        validate_limits(&ResourceLimits::default()).expect("zeros");
    }

    /// `ValidateBinary` — the closed class admits `central-agent` and
    /// refuses every other spelling, including absolute paths: a path
    /// is not an executable *class*.
    #[test]
    fn binary_class_is_closed() {
        validate_binary("central-agent").expect("allowed class");
        for bad in ["/etc/passwd", "/bin/sh", "agent", "central-agent\x00", ""] {
            let err = validate_binary(bad).unwrap_err();
            assert_eq!(err.code(), "sandbox_denied");
            assert_eq!(
                err.message(),
                format!("sandbox: unknown executable class: {bad:?}")
            );
        }
    }

    /// The app-service deadline cap: above 600 s refuses with the
    /// Go-duration message; zero maps to the default; cap is admitted.
    #[test]
    fn deadline_cap() {
        let over = DEADLINE_HARD_CAP + Duration::from_nanos(1);
        let err = effective_deadline(over).unwrap_err();
        assert_eq!(err.code(), "sandbox_denied");
        assert_eq!(
            err.message(),
            "sandbox: deadline 10m0.000000001s exceeds hard cap 600s"
        );
        assert_eq!(
            effective_deadline(Duration::ZERO).expect("zero"),
            DEADLINE_DEFAULT
        );
        assert_eq!(
            effective_deadline(DEADLINE_HARD_CAP).expect("cap"),
            DEADLINE_HARD_CAP
        );
    }
}
