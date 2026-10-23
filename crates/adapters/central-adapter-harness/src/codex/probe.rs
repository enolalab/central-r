//! `probe.go` — the version and login probes. `Probe` runs
//! `codex --version` plus `codex login status` through the launcher in
//! the probe workdir and reports the install state. It is the
//! dispatcher's info source (spec D5): `authenticated` comes from the
//! login-status exit code alone, and the probe never gates on version
//! — `Start` refuses the mismatch per attempt instead.

use std::sync::Arc;

use central_foundation::failure::Failure;
use central_harness::env::validate_launch_env;
use central_harness::port::{ExitStatus, LaunchEnv, ProbeResult, Process, ProcessSpec};

use crate::process::{PROBE_OUTPUT_CAP, Stream, drain_discard, read_capped};

use super::{Codex, codes, program_name, reasons, require_path};

/// `versionPin` — `^([0-9]+\.[0-9]+\.[0-9]+)$` as a scan.
/// `versionShape` checks a pinned-version string.
pub(crate) fn version_shape(v: &str) -> bool {
    let mut it = v.split('.');
    let three = it
        .by_ref()
        .take(3)
        .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    three && it.next().is_none() && v.matches('.').count() == 2
}

/// `versionOutput` — `^codex-cli ([0-9]+\.[0-9]+\.[0-9]+)\n?$`:
/// the strict parse of one probe's stdout into the bare version.
fn parse_version_output(out: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(out).ok()?;
    let rest = s.strip_prefix("codex-cli ")?;
    let v = rest.strip_suffix('\n').unwrap_or(rest);
    if !version_shape(v) {
        return None;
    }
    Some(v.to_string())
}

impl Codex {
    /// `Probe`.
    pub(crate) async fn probe_inner(&self, env: &LaunchEnv) -> Result<ProbeResult, Failure> {
        validate_launch_env(&env.vars, &[])?;
        require_path(env)?;
        if env.sandbox_scope_id.is_empty() {
            return Err(Failure::invalid(
                codes::INVALID_LAUNCH,
                "codex: probe requires a sandbox scope id",
            ));
        }
        let version = self.version(env).await?;
        let authenticated = self.login_status(env).await?;
        Ok(ProbeResult {
            harness_version: version.clone(),
            authenticated,
            detail: self.probe_detail(&version),
        })
    }

    /// `probeDetail` — fixed text plus the parsed version: never
    /// harness output.
    fn probe_detail(&self, version: &str) -> String {
        let detail = format!(
            "codex login status decides Authenticated; per-model auth failures surface as {}",
            reasons::HARNESS_API_ERROR
        );
        if version != self.pinned {
            let verdict = if self.allow_unpinned {
                "allowed by AllowUnpinned"
            } else {
                "Start refuses"
            };
            return format!(
                "{detail} (version {version} differs from pinned {} ({verdict}))",
                self.pinned
            );
        }
        detail
    }

    /// `version` — runs `codex --version` in the probe workdir and
    /// returns the bare version. Every failure mode refuses without
    /// running anything else: a version the adapter cannot parse is
    /// not one it may launch.
    pub(crate) async fn version(&self, env: &LaunchEnv) -> Result<String, Failure> {
        let (out, status) = self.run_probe(env, &["--version"]).await?;
        if status.code != 0 || status.signaled {
            return Err(Failure::invalid(
                codes::UNEXPECTED_PROBE_OUTPUT,
                format!("codex: --version exited {}", status.code),
            ));
        }
        parse_version_output(&out).ok_or_else(|| {
            Failure::invalid(
                codes::UNEXPECTED_PROBE_OUTPUT,
                "codex: --version output did not match",
            )
        })
    }

    /// `loginStatus` — runs `codex login status` in the probe workdir
    /// and reports whether the operator is logged in from the exit
    /// code alone: 0 means logged in, anything else means not (or an
    /// error). Its output is drained and discarded, never parsed,
    /// logged or recorded: the API-key form prints a masked key
    /// (spec S9).
    async fn login_status(&self, env: &LaunchEnv) -> Result<bool, Failure> {
        let (_, status) = self.run_probe(env, &["login", "status"]).await?;
        Ok(status.code == 0 && !status.signaled)
    }

    /// `runProbe` — one probe command returning its bounded stdout
    /// plus the exit status; stderr is drained and discarded. Nothing
    /// it returns may reach an error: callers map every failure to a
    /// fixed text.
    async fn run_probe(
        &self,
        env: &LaunchEnv,
        args: &[&str],
    ) -> Result<(Vec<u8>, ExitStatus), Failure> {
        let proc_box = self
            .launcher
            .launch(ProcessSpec {
                program: program_name().to_string(),
                args: args.iter().map(|s| (*s).to_string()).collect(),
                env: env.vars.clone(),
                work_dir: self.probe_work_dir.clone(),
                scope_id: env.sandbox_scope_id.clone(),
                env_extras: Vec::new(),
            })
            .await
            .map_err(|e| {
                Failure::new(e.kind(), e.code(), format!("codex: probe: {}", e.message()))
            })?;
        let proc: Arc<dyn Process> = Arc::from(proc_box);
        let p2 = proc.clone();
        let stderr_done = tokio::spawn(async move {
            let _ = drain_discard(&*p2, Stream::Stderr).await;
        });
        let read = read_capped(&*proc, PROBE_OUTPUT_CAP).await;
        let (out, read_err) = match read {
            Ok(out) => (out, None),
            Err(e) => (Vec::new(), Some(e)),
        };
        let status = match proc.wait().await {
            Ok(s) => s,
            Err(e) => {
                let _ = proc.kill().await;
                let _ = proc.wait().await;
                let _ = stderr_done.await;
                return Err(Failure::new(
                    e.kind(),
                    e.code(),
                    format!("codex: probe: {}", e.message()),
                ));
            }
        };
        let _ = stderr_done.await;
        if let Some(e) = read_err {
            return Err(Failure::new(
                e.kind(),
                codes::UNEXPECTED_PROBE_OUTPUT,
                "codex: probe: reading probe output",
            ));
        }
        if out.len() > PROBE_OUTPUT_CAP {
            return Err(Failure::invalid(
                codes::UNEXPECTED_PROBE_OUTPUT,
                "codex: probe output too long",
            ));
        }
        Ok((out, status))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `versionOutput` / `versionPin` shapes (probe_test.go refuses).
    #[test]
    fn version_parse() {
        assert_eq!(
            parse_version_output(b"codex-cli 0.162.1\n").as_deref(),
            Some("0.162.1")
        );
        assert_eq!(
            parse_version_output(b"codex-cli 0.162.1").as_deref(),
            Some("0.162.1")
        );
        for bad in [
            b"codex-cli 0.162\n".as_slice(),
            b"codex-cli 0.162.1 (codex)\n".as_slice(),
            b"0.162.1\n".as_slice(),
            b"codex-cli 0.162.1\nextra".as_slice(),
            b"codex 0.162.1\n".as_slice(),
            b"garbage".as_slice(),
            b"".as_slice(),
        ] {
            assert!(parse_version_output(bad).is_none(), "{bad:?}");
        }
        assert!(version_shape("0.162.1"));
        assert!(version_shape("9.9.9"));
        for bad in ["", "0.162", "0.162.1\n", "v0.162.1", "0.162.1.4", "a.b.c"] {
            assert!(!version_shape(bad), "{bad}");
        }
    }
}
