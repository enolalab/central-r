//! `argv.go` — the closed `codex` argv (spec D2). Fresh is
//! `exec --json -s workspace-write [--model M] -`, resume is
//! `exec resume --json -c <literal> [--model M] <uuid> -`. There are
//! no message positionals and no other flags: no `--last` (it follows
//! the operator-global last session, not Central's recorded id), no
//! `-C`/`--cd` (the worktree comes from the launcher's WorkDir), no
//! `--add-dir`/`--worktree`/`--profile`/`--oss` (widening or foreign
//! state), no `--skip-git-repo-check`/`--ephemeral` (fail-closed
//! checks and the rollout resume needs), no `--approve-for-me` or
//! `--dangerously-bypass-*` (Deny by construction). The launcher
//! daemon mirrors this grammar.

use central_foundation::failure::Failure;

use super::codes;

/// `sandboxConfigLiteral` — the only `-c` value the resume argv
/// carries (spec D2): resume has no `-s` flag and the server applies
/// the current config's sandbox as an override, so without this
/// literal a resumed thread would silently downgrade to read-only
/// (spec S5/S6). The launcher daemon matches it exactly.
const SANDBOX_CONFIG_LITERAL: &str = "sandbox_mode=\"workspace-write\"";

/// `launchArgs` — the only inputs to the codex argv (spec D2).
/// `resume_id` is set for a resumed session and empty for a fresh
/// one; the harness always assigns the id. The prompt is never an
/// input: it goes over stdin addressed by the "-" sentinel.
pub(crate) struct LaunchArgs<'a> {
    pub resume_id: &'a str,
    pub model: &'a str,
}

/// `buildArgs` — the closed argv. `INVALID_LAUNCH` marks every refusal.
pub(crate) fn build_args(input: &LaunchArgs<'_>) -> Result<Vec<String>, Failure> {
    if !input.model.is_empty() && !safe_model(input.model) {
        return Err(Failure::invalid(
            codes::INVALID_LAUNCH,
            "codex: model name is not a plain identifier",
        ));
    }
    let mut args: Vec<String> = if input.resume_id.is_empty() {
        vec![
            "exec".to_string(),
            "--json".to_string(),
            "-s".to_string(),
            "workspace-write".to_string(),
        ]
    } else {
        if !valid_session_id(input.resume_id) {
            return Err(Failure::invalid(
                codes::INVALID_LAUNCH,
                "codex: resume id is not a harness session id",
            ));
        }
        vec![
            "exec".to_string(),
            "resume".to_string(),
            "--json".to_string(),
            "-c".to_string(),
            SANDBOX_CONFIG_LITERAL.to_string(),
        ]
    };
    if !input.model.is_empty() {
        args.push("--model".to_string());
        args.push(input.model.to_string());
    }
    if !input.resume_id.is_empty() {
        args.push(input.resume_id.to_string());
    }
    args.push("-".to_string());
    Ok(args)
}

/// `safeModel` — model ids passed verbatim, refusing anything that
/// could be read as an option. Mirrors the siblings' rule and the
/// daemon's `valid_model`; codex validates the model server-side and
/// an unknown model fails the turn.
fn safe_model(m: &str) -> bool {
    if m.is_empty() || m.len() > 128 || m.starts_with('-') {
        return false;
    }
    m.chars().all(|c| {
        c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | ':' | '/' | '[' | ']' | '@')
    })
}

/// `validSessionID` — the thread ids `exec` reports: strict UUID
/// shape (spec S7 renders hyphenated lowercase), 8-4-4-4-12 lowercase
/// hex. Mirrors the daemon's `valid_uuid`.
pub(crate) fn valid_session_id(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    for (i, c) in b.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if *c != b'-' {
                    return false;
                }
            }
            _ => {
                if !c.is_ascii_hexdigit() || c.is_ascii_uppercase() {
                    return false;
                }
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `TestBuildArgsFresh` / `TestBuildArgsMatrix` /
    /// `TestSandboxConfigLiteral` — argv_internal_test.go.
    #[test]
    fn build_args_matrix() {
        let args = build_args(&LaunchArgs {
            resume_id: "",
            model: "",
        })
        .unwrap();
        assert_eq!(args, ["exec", "--json", "-s", "workspace-write", "-"]);
        // The sandbox literal is the daemon-matched string.
        assert_eq!(SANDBOX_CONFIG_LITERAL, "sandbox_mode=\"workspace-write\"");
        let cases = [
            (
                "fresh with model",
                LaunchArgs {
                    resume_id: "",
                    model: "gpt-5.3-codex",
                },
                vec![
                    "exec",
                    "--json",
                    "-s",
                    "workspace-write",
                    "--model",
                    "gpt-5.3-codex",
                    "-",
                ],
            ),
            (
                "resume",
                LaunchArgs {
                    resume_id: "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb",
                    model: "",
                },
                vec![
                    "exec",
                    "resume",
                    "--json",
                    "-c",
                    "sandbox_mode=\"workspace-write\"",
                    "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb",
                    "-",
                ],
            ),
            (
                "resume with model",
                LaunchArgs {
                    resume_id: "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb",
                    model: "a/b",
                },
                vec![
                    "exec",
                    "resume",
                    "--json",
                    "-c",
                    "sandbox_mode=\"workspace-write\"",
                    "--model",
                    "a/b",
                    "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb",
                    "-",
                ],
            ),
        ];
        for (name, input, want) in cases {
            let args = build_args(&input).unwrap();
            assert_eq!(args, want, "{name}");
        }
    }

    /// `TestBuildArgsRefuses`.
    #[test]
    fn build_args_refuses() {
        let long_model = "a".repeat(129);
        let cases: Vec<(&str, LaunchArgs)> = vec![
            (
                "model starting with dash",
                LaunchArgs {
                    resume_id: "",
                    model: "-m",
                },
            ),
            (
                "model with space",
                LaunchArgs {
                    resume_id: "",
                    model: "a b",
                },
            ),
            (
                "model with semicolon",
                LaunchArgs {
                    resume_id: "",
                    model: "a;b",
                },
            ),
            (
                "overlong model",
                LaunchArgs {
                    resume_id: "",
                    model: &long_model,
                },
            ),
            (
                "session not uuid",
                LaunchArgs {
                    resume_id: "abc123",
                    model: "",
                },
            ),
            (
                "session uppercase",
                LaunchArgs {
                    resume_id: "BBBBBBBB-BBBB-4BBB-BBBB-BBBBBBBBBBBB",
                    model: "",
                },
            ),
            (
                "session short",
                LaunchArgs {
                    resume_id: "bbbbbbbb-bbbb-4bbb-bbbb",
                    model: "",
                },
            ),
        ];
        for (name, input) in cases {
            let err = build_args(&input).unwrap_err();
            assert_eq!(err.code(), codes::INVALID_LAUNCH, "{name}");
        }
    }

    /// `TestSafeModel`.
    #[test]
    fn safe_model_table() {
        for ok in ["m", "gpt-5.3-codex", "a:b_c.d/e[f]g@h"] {
            assert!(safe_model(ok), "{ok}");
        }
        assert!(safe_model(&"a".repeat(128)));
        for bad in [
            "", "-m", "a b", "a;b", "a'b", "a\"b", "a`b", "a$b", "a*b", "a?b", "a\\b",
        ] {
            assert!(!safe_model(bad), "{bad}");
        }
    }

    /// `TestValidSessionID`.
    #[test]
    fn valid_session_id_table() {
        assert!(valid_session_id("bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb"));
        assert!(valid_session_id("00000000-0000-4000-8000-000000000000"));
        for bad in [
            "",
            "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbb",
            "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbba",
            "BBBBBBBB-BBBB-4BBB-BBBB-BBBBBBBBBBBB",
            "bbbbbbbb_bbbb-4bbb-bbbb-bbbbbbbbbbbb",
            "abc",
            "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbg",
        ] {
            assert!(!valid_session_id(bad), "{bad}");
        }
    }
}
