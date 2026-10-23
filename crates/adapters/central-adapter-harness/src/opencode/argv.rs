//! `argv.go` — the closed `opencode` argv (spec D2). `run --format
//! json` with an optional `--model` and, for resumes, `--session`.
//! There are no message positionals and no other flags: no `--continue`
//! (it follows the operator-global last session), no `--auto` or
//! permission flags (Deny by construction), no
//! `--agent`/`--command`/`--attach`/`--dir`/`--port`/`--file`/`--share`/
//! `--thinking`/`--variant`. The launcher daemon mirrors this grammar.

use central_foundation::failure::Failure;

use super::codes;

/// `launchArgs` — the only inputs to the opencode argv (spec D2).
/// `resume_id` is set for a resumed session and empty for a fresh one;
/// the harness always assigns the id. The prompt is never an input: it
/// goes over stdin.
pub(crate) struct LaunchArgs<'a> {
    pub resume_id: &'a str,
    pub model: &'a str,
}

/// `buildArgs` — the closed argv. `INVALID_LAUNCH` marks every refusal.
pub(crate) fn build_args(input: &LaunchArgs<'_>) -> Result<Vec<String>, Failure> {
    let mut args = vec![
        "run".to_string(),
        "--format".to_string(),
        "json".to_string(),
    ];
    if !input.model.is_empty() {
        if !safe_model(input.model) {
            return Err(Failure::invalid(
                codes::INVALID_LAUNCH,
                "opencode: model name is not a plain identifier",
            ));
        }
        args.push("--model".to_string());
        args.push(input.model.to_string());
    }
    if !input.resume_id.is_empty() {
        if !valid_session_id(input.resume_id) {
            return Err(Failure::invalid(
                codes::INVALID_LAUNCH,
                "opencode: resume id is not a harness session id",
            ));
        }
        args.push("--session".to_string());
        args.push(input.resume_id.to_string());
    }
    Ok(args)
}

/// `safeModel` — model ids such as "opencode/mimo-v2.6-flash-free" or
/// "nvidia/meta/llama-3.2-1b-instruct", passed verbatim, refusing
/// anything that could be read as an option. Mirrors claudecode's rule
/// and the daemon's `valid_model`.
fn safe_model(m: &str) -> bool {
    if m.is_empty() || m.len() > 128 || m.starts_with('-') {
        return false;
    }
    m.chars().all(|c| {
        c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | ':' | '/' | '[' | ']' | '@')
    })
}

/// `validSessionID` — the harness session ids `run` reports: `ses_`
/// plus 1 to 64 ASCII letters and digits (observed ids are `ses_` + 22
/// alnum). Mirrors the daemon's `valid_ses_id`.
pub(crate) fn valid_session_id(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("ses_") else {
        return false;
    };
    if s.len() < 5 || s.len() > 68 {
        return false;
    }
    !rest.is_empty() && rest.chars().all(|c| c.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `TestBuildArgsFresh` / `TestBuildArgsMatrix` —
    /// `argv_internal_test.go`.
    #[test]
    fn build_args_matrix() {
        let args = build_args(&LaunchArgs {
            resume_id: "",
            model: "",
        })
        .unwrap();
        assert_eq!(args, ["run", "--format", "json"]);
        let cases = [
            (
                "fresh with model",
                LaunchArgs {
                    resume_id: "",
                    model: "opencode/mimo-v2.6-flash-free",
                },
                vec![
                    "run",
                    "--format",
                    "json",
                    "--model",
                    "opencode/mimo-v2.6-flash-free",
                ],
            ),
            (
                "model with provider path",
                LaunchArgs {
                    resume_id: "",
                    model: "nvidia/meta/llama-3.2-1b-instruct",
                },
                vec![
                    "run",
                    "--format",
                    "json",
                    "--model",
                    "nvidia/meta/llama-3.2-1b-instruct",
                ],
            ),
            (
                "resume",
                LaunchArgs {
                    resume_id: "ses_ed9de340effe7fBtzPkP81yXKj",
                    model: "",
                },
                vec![
                    "run",
                    "--format",
                    "json",
                    "--session",
                    "ses_ed9de340effe7fBtzPkP81yXKj",
                ],
            ),
            (
                "resume with model",
                LaunchArgs {
                    resume_id: "ses_abc123",
                    model: "a/b",
                },
                vec![
                    "run",
                    "--format",
                    "json",
                    "--model",
                    "a/b",
                    "--session",
                    "ses_abc123",
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
        let long_id = format!("ses_{}", "a".repeat(65));
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
                "model with quote",
                LaunchArgs {
                    resume_id: "",
                    model: "a'b",
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
                "empty session prefix",
                LaunchArgs {
                    resume_id: "ed9de340effe7fBtzPkP81yXKj",
                    model: "",
                },
            ),
            (
                "session without prefix",
                LaunchArgs {
                    resume_id: "abc123",
                    model: "",
                },
            ),
            (
                "session with dash",
                LaunchArgs {
                    resume_id: "ses_abc-123",
                    model: "",
                },
            ),
            (
                "session with space",
                LaunchArgs {
                    resume_id: "ses_abc 123",
                    model: "",
                },
            ),
            (
                "overlong session",
                LaunchArgs {
                    resume_id: &long_id,
                    model: "",
                },
            ),
            (
                "session bare prefix",
                LaunchArgs {
                    resume_id: "ses_",
                    model: "",
                },
            ),
            (
                "empty model with resume",
                LaunchArgs {
                    resume_id: "ses_abc123",
                    model: "-x",
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
        for ok in ["m", "opencode/mimo-v2.6-flash-free", "a:b_c.d/e[f]g@h"] {
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
        for ok in ["ses_a", "ses_ed9de340effe7fBtzPkP81yXKj"] {
            assert!(valid_session_id(ok), "{ok}");
        }
        assert!(valid_session_id(&format!("ses_{}", "Z".repeat(64))));
        for bad in ["", "ses_", "ses", "abc", "ses_a-b", "ses_a b"] {
            assert!(!valid_session_id(bad), "{bad}");
        }
        assert!(!valid_session_id(&format!("ses_{}", "a".repeat(65))));
    }
}
