//! `probe.go` — `claude --version` and `claude auth status` through the
//! launcher, spending no tokens. Harness output is never copied into
//! the result, errors or logs: the version is parsed strictly and the
//! auth status is reduced to a boolean and an enum — account
//! identifiers (email, organization, ids) are never read, and stderr is
//! drained and discarded.

use std::sync::Arc;

use central_foundation::failure::Failure;
use central_harness::env::validate_launch_env;
use central_harness::port::{ExitStatus, LaunchEnv, ProbeResult, ProcessSpec};

use crate::process::{PROBE_OUTPUT_CAP, Stream, drain_discard};

use super::{ClaudeCode, codes, program_name};

/// `versionOutput` — `^([0-9]+\.[0-9]+\.[0-9]+) \(Claude Code\)\n?$`.
/// Returns the captured version.
pub(crate) fn parse_version_output(out: &[u8]) -> Option<String> {
    // A non-UTF-8 byte can never sit inside the pattern's alphabet, so a
    // UTF-8 refusal is the regex's no-match.
    let s = std::str::from_utf8(out).ok()?;
    let s = s.strip_suffix('\n').unwrap_or(s);
    let version = s.strip_suffix(" (Claude Code)")?;
    if version_shape(version) {
        Some(version.to_string())
    } else {
        None
    }
}

/// `versionShape` — `versionOutput.MatchString(v + " (Claude Code)")`:
/// three non-empty dot-separated digit runs.
pub(crate) fn version_shape(v: &str) -> bool {
    let parts: Vec<&str> = v.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// `authStatus` — the only two fields ever decoded from `claude auth
/// status`; the decoded method names are a closed enum, the raw string
/// is never copied.
#[derive(Debug, Default)]
struct AuthStatus {
    /// `None` when `loggedIn` is absent or `null` — the `*bool` nil.
    logged_in: Option<bool>,
    auth_method: Option<String>,
}

impl AuthStatus {
    /// `method` — `"claude.ai"`, `"none"` (also absent/empty), or
    /// `"other"`; never the raw value.
    fn method(&self) -> &'static str {
        match self.auth_method.as_deref() {
            Some("claude.ai") => "claude.ai",
            None | Some("") | Some("none") => "none",
            _ => "other",
        }
    }
}

/// `json.Unmarshal(bytes.TrimSpace(out), &authStatus)` — the whole
/// trimmed output must be one object; `loggedIn` wrong-typed or absent
/// is an error upstream (`status.LoggedIn == nil`), and a wrong-typed
/// `authMethod` fails the whole unmarshal.
fn parse_auth_status(out: &[u8]) -> Result<AuthStatus, ()> {
    // `bytes.TrimSpace` — ASCII whitespace covers the fixture surface.
    let ws = |b: u8| matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c);
    let start = out.iter().position(|b| !ws(*b)).unwrap_or(out.len());
    let end = out.iter().rposition(|b| !ws(*b)).map_or(start, |i| i + 1);
    let trimmed = &out[start..end];
    let members = crate::json::object_members(trimmed).map_err(|_| ())?;
    let mut status = AuthStatus::default();
    for (name, span) in &members {
        match name.as_str() {
            "loggedIn" => {
                status.logged_in =
                    crate::json::field::<Option<bool>>(trimmed, span).map_err(|_| ())?;
            }
            "authMethod" => {
                status.auth_method =
                    crate::json::field::<Option<String>>(trimmed, span).map_err(|_| ())?;
            }
            _ => {}
        }
    }
    if status.logged_in.is_none() {
        return Err(());
    }
    Ok(status)
}

impl ClaudeCode {
    /// `Probe`.
    pub(crate) async fn probe_inner(&self, env: &LaunchEnv) -> Result<ProbeResult, Failure> {
        validate_launch_env(&env.vars, &[])?;
        require_path(env)?;
        if env.sandbox_scope_id.is_empty() {
            return Err(Failure::invalid(
                codes::INVALID_LAUNCH,
                "claudecode: probe requires a sandbox scope id",
            ));
        }
        let version = self.version(env).await?;
        let (out, _status) = self.run_probe(env, &["auth", "status"]).await?;
        let status = parse_auth_status(&out).map_err(|_| {
            Failure::invalid(
                codes::UNEXPECTED_PROBE_OUTPUT,
                "claudecode: auth status is not the expected JSON",
            )
        })?;
        let mut details = vec![format!("auth method: {}", status.method())];
        if status.logged_in != Some(true) {
            details.push("not logged in".to_string());
        }
        if version != self.pinned {
            let verdict = if self.allow_unpinned {
                "allowed by AllowUnpinned"
            } else {
                "Start refuses"
            };
            details.push(format!(
                "version {} differs from pinned {} ({verdict})",
                version, self.pinned
            ));
        }
        Ok(ProbeResult {
            harness_version: version,
            authenticated: status.logged_in == Some(true),
            detail: details.join("; "),
        })
    }

    /// `version` — runs `claude --version` and parses it strictly.
    pub(crate) async fn version(&self, env: &LaunchEnv) -> Result<String, Failure> {
        let (out, status) = self.run_probe(env, &["--version"]).await?;
        if status.code != 0 || status.signaled {
            return Err(Failure::invalid(
                codes::UNEXPECTED_PROBE_OUTPUT,
                format!("claudecode: version probe exited with code {}", status.code),
            ));
        }
        parse_version_output(&out).ok_or_else(|| {
            Failure::invalid(
                codes::UNEXPECTED_PROBE_OUTPUT,
                "claudecode: version output does not match the expected form",
            )
        })
    }

    /// `runProbe` — launches one short `claude` command in the probe
    /// workdir under the env's scope and returns at most
    /// `PROBE_OUTPUT_CAP` bytes of stdout. Stderr is drained and
    /// discarded; an over-cap probe is killed (a probe never prints
    /// this much) after its remaining output is drained.
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
                Failure::new(
                    e.kind(),
                    e.code(),
                    format!("claudecode: probe launch: {}", e.message()),
                )
            })?;
        let proc: Arc<dyn central_harness::port::Process> = Arc::from(proc_box);
        let _ = proc.close_stdin().await;
        let p2 = proc.clone();
        let stderr_done = tokio::spawn(async move {
            let _ = drain_discard(&*p2, Stream::Stderr).await;
        });
        let mut out: Vec<u8> = Vec::new();
        let mut buf = [0u8; 8192];
        let mut read_err: Option<Failure> = None;
        loop {
            match proc.read_stdout(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let room = PROBE_OUTPUT_CAP + 1 - out.len().min(PROBE_OUTPUT_CAP + 1);
                    out.extend_from_slice(&buf[..n.min(room)]);
                    if out.len() > PROBE_OUTPUT_CAP {
                        // A probe never prints this much; stop it rather
                        // than read on.
                        let _ = proc.kill().await;
                        let _ = drain_discard(&*proc, Stream::Stdout).await;
                        break;
                    }
                }
                Err(e) => {
                    read_err = Some(e);
                    let _ = drain_discard(&*proc, Stream::Stdout).await;
                    break;
                }
            }
        }
        let _ = stderr_done.await;
        let status = match proc.wait().await {
            Ok(s) => s,
            Err(e) => {
                let _ = proc.kill().await;
                return Err(Failure::new(
                    e.kind(),
                    e.code(),
                    format!("claudecode: probe wait: {}", e.message()),
                ));
            }
        };
        if let Some(e) = read_err {
            return Err(Failure::new(
                e.kind(),
                codes::UNEXPECTED_PROBE_OUTPUT,
                "claudecode: probe output could not be read",
            ));
        }
        if out.len() > PROBE_OUTPUT_CAP {
            return Err(Failure::invalid(
                codes::UNEXPECTED_PROBE_OUTPUT,
                format!(
                    "claudecode: probe output exceeds {} bytes",
                    PROBE_OUTPUT_CAP
                ),
            ));
        }
        Ok((out, status))
    }
}

/// `requirePath` — a PATH whose every entry is an absolute directory.
/// An empty entry (a leading, trailing or doubled `:`) or a relative
/// one would resolve commands against the untrusted worktree, the
/// harness's working directory. The value is never echoed.
pub(crate) fn require_path(env: &LaunchEnv) -> Result<(), Failure> {
    let path = env.vars.get("PATH").cloned().unwrap_or_default();
    if path.is_empty() {
        return Err(Failure::invalid(
            codes::PATH_REQUIRED,
            "claudecode: PATH is required in the launch env and may list only absolute directories",
        ));
    }
    for dir in path.split(':') {
        if !std::path::Path::new(dir).is_absolute() {
            return Err(Failure::invalid(
                codes::PATH_REQUIRED,
                "claudecode: PATH is required in the launch env and may list only absolute directories: an entry is empty or relative",
            ));
        }
    }
    Ok(())
}
