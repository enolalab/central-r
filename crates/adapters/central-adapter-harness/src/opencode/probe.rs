//! `probe.go` — the version probe. `Probe` runs `opencode --version`
//! through the launcher, spending no tokens. OpenCode has no single
//! login state — free models answer with no credentials at all and
//! every auth failure surfaces per model as a run error — so there is
//! no auth probe: `authenticated` is always true and `detail` says so.
//! Harness output is never copied into the result, errors or logs: the
//! version is parsed strictly.

use std::sync::Arc;

use central_foundation::failure::Failure;
use central_harness::env::validate_launch_env;
use central_harness::port::{LaunchEnv, ProbeResult, Process, ProcessSpec};

use crate::process::{PROBE_OUTPUT_CAP, Stream, drain_discard, read_capped};

use super::{OpenCode, codes, program_name, require_path};

/// `versionOutput` — `^([0-9]+\.[0-9]+\.[0-9]+)\n?$` as a byte scan.
/// `versionShape` checks a pinned-version string; `parse` returns the
/// captured digits.
pub(crate) fn version_shape(v: &str) -> bool {
    let v = v.strip_suffix('\n').unwrap_or(v);
    let mut it = v.split('.');
    let three = it
        .by_ref()
        .take(3)
        .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    three && it.next().is_none() && v.matches('.').count() == 2
}

/// `versionOutput.FindSubmatch(out)[1]` — the strict parse of one
/// probe's stdout into the version string; `None` when the output is
/// not exactly `N.N.N` plus an optional trailing newline.
fn parse_version_output(out: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(out).ok()?;
    if !version_shape(s) {
        return None;
    }
    Some(s.strip_suffix('\n').unwrap_or(s).to_string())
}

impl OpenCode {
    /// `Probe`.
    pub(crate) async fn probe_inner(&self, env: &LaunchEnv) -> Result<ProbeResult, Failure> {
        validate_launch_env(&env.vars, &[])?;
        require_path(env)?;
        if env.sandbox_scope_id.is_empty() {
            return Err(Failure::invalid(
                codes::INVALID_LAUNCH,
                "opencode: probe requires a sandbox scope id",
            ));
        }
        let version = self.version(env).await?;
        let mut detail =
            "opencode has no single login; per-model auth failures surface as harness_api_error"
                .to_string();
        if version != self.pinned {
            let verdict = if self.allow_unpinned {
                "allowed by AllowUnpinned"
            } else {
                "Start refuses"
            };
            detail.push_str(&format!(
                "; version {version} differs from pinned {} ({verdict})",
                self.pinned
            ));
        }
        Ok(ProbeResult {
            harness_version: version,
            authenticated: true,
            detail,
        })
    }

    /// `version` — runs `opencode --version` and parses it strictly.
    pub(crate) async fn version(&self, env: &LaunchEnv) -> Result<String, Failure> {
        let (out, status) = self.run_probe(env, &["--version"]).await?;
        if status.code != 0 || status.signaled {
            return Err(Failure::invalid(
                codes::UNEXPECTED_PROBE_OUTPUT,
                format!("opencode: version probe exited with code {}", status.code),
            ));
        }
        parse_version_output(&out).ok_or_else(|| {
            Failure::invalid(
                codes::UNEXPECTED_PROBE_OUTPUT,
                "opencode: version output does not match the expected form",
            )
        })
    }

    /// `runProbe` — one short opencode command in the probe workdir
    /// under the env's scope, returning at most `PROBE_OUTPUT_CAP`
    /// bytes of stdout. Stderr is drained and discarded.
    async fn run_probe(
        &self,
        env: &LaunchEnv,
        args: &[&str],
    ) -> Result<(Vec<u8>, central_harness::port::ExitStatus), Failure> {
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
                Failure::new(
                    e.kind(),
                    e.code(),
                    format!("opencode: probe launch: {}", e.message()),
                )
            })?;
        let proc: Arc<dyn Process> = Arc::from(proc_box);
        let _ = proc.close_stdin().await;
        let p2 = proc.clone();
        let stderr_done = tokio::spawn(async move {
            let _ = drain_discard(&*p2, Stream::Stderr).await;
        });
        let read = read_capped(&*proc, PROBE_OUTPUT_CAP).await;
        let (out, read_err) = match read {
            Ok(out) => (out, None),
            Err(e) => (Vec::new(), Some(e)),
        };
        if out.len() > PROBE_OUTPUT_CAP {
            // A probe never prints this much; stop it rather than read on.
            let _ = proc.kill().await;
        }
        let _ = stderr_done.await;
        let status = match proc.wait().await {
            Ok(s) => s,
            Err(e) => {
                let _ = proc.kill().await;
                return Err(Failure::new(
                    e.kind(),
                    e.code(),
                    format!("opencode: probe wait: {}", e.message()),
                ));
            }
        };
        if let Some(e) = read_err {
            return Err(Failure::new(
                e.kind(),
                codes::UNEXPECTED_PROBE_OUTPUT,
                "opencode: probe output could not be read",
            ));
        }
        if out.len() > PROBE_OUTPUT_CAP {
            return Err(Failure::invalid(
                codes::UNEXPECTED_PROBE_OUTPUT,
                format!("opencode: probe output exceeds {PROBE_OUTPUT_CAP} bytes"),
            ));
        }
        Ok((out, status))
    }
}
