//! `argv.go` — the closed `agy` argv (spec D2):
//! `--input-format stream-json --output-format stream-json
//! --disable-slash-commands` with an optional `--model` and, for
//! resumes, `--conversation`. There are no message positionals and no
//! other flags: no `-p`/`--print`/`--prompt` (the prompt would travel
//! as argv), no `--continue` (it follows the operator-global last
//! conversation), no `--dangerously-skip-permissions` (Deny by
//! construction), no `--sandbox`/`--mode`/`--agent`/`--effort`/
//! `--project`/`--add-dir`/`--print-timeout`/`--remote-control`.
//! The launcher daemon mirrors this grammar.

use central_foundation::failure::Failure;

use super::codes;

/// `launchArgs` — the only inputs to the agy argv (spec D2).
/// `resume_id` is set for a resumed session and empty for a fresh
/// one; the harness always assigns the id. The prompt is never an
/// input: it goes over stdin as the first NDJSON user event.
pub(crate) struct LaunchArgs<'a> {
    pub resume_id: &'a str,
    pub model: &'a str,
}

/// `buildArgs` — the closed argv. `INVALID_LAUNCH` marks every refusal.
pub(crate) fn build_args(input: &LaunchArgs<'_>) -> Result<Vec<String>, Failure> {
    let mut args: Vec<String> = [
        "--input-format",
        "stream-json",
        "--output-format",
        "stream-json",
        "--disable-slash-commands",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    if !input.model.is_empty() {
        if !safe_model(input.model) {
            return Err(Failure::invalid(
                codes::INVALID_LAUNCH,
                "antigravity: model name is not a plain identifier",
            ));
        }
        args.push("--model".to_string());
        args.push(input.model.to_string());
    }
    if !input.resume_id.is_empty() {
        if !valid_session_id(input.resume_id) {
            return Err(Failure::invalid(
                codes::INVALID_LAUNCH,
                "antigravity: resume id is not a harness session id",
            ));
        }
        args.push("--conversation".to_string());
        args.push(input.resume_id.to_string());
    }
    Ok(args)
}

/// `safeModel` — model ids such as `gemini-3.8-flash-low`, passed
/// verbatim, refusing anything that could be read as an option. It
/// mirrors claudecode's rule and the daemon's `valid_model`.
fn safe_model(m: &str) -> bool {
    if m.is_empty() || m.len() > 128 || m.starts_with('-') {
        return false;
    }
    m.chars().all(|c| {
        c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | ':' | '/' | '[' | ']' | '@')
    })
}

/// `validSessionID` — the harness conversation ids agy reports:
/// strict lowercase UUIDs, 8-4-4-4-12 hex with hyphens at positions
/// 8, 13, 18 and 23. Mirrors the daemon's `canonical_uuid`.
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

    /// `TestBuildArgsAccept`.
    #[test]
    fn build_args_accept() {
        let base = [
            "--input-format",
            "stream-json",
            "--output-format",
            "stream-json",
            "--disable-slash-commands",
        ];
        let a = build_args(&LaunchArgs {
            resume_id: "",
            model: "",
        })
        .unwrap();
        assert_eq!(a, base.to_vec());
        let a = build_args(&LaunchArgs {
            resume_id: "",
            model: "gemini-3.8-flash-low",
        })
        .unwrap();
        assert_eq!(a[base.len()..], ["--model", "gemini-3.8-flash-low"]);
        let a = build_args(&LaunchArgs {
            resume_id: "66666666-6666-4666-8666-666666666666",
            model: "m",
        })
        .unwrap();
        assert_eq!(
            a[base.len()..],
            [
                "--model",
                "m",
                "--conversation",
                "66666666-6666-4666-8666-666666666666"
            ]
        );
    }

    /// `TestBuildArgsRefuse`.
    #[test]
    fn build_args_refuse() {
        for (name, input) in [
            (
                "dash model",
                LaunchArgs {
                    resume_id: "",
                    model: "-m",
                },
            ),
            (
                "space model",
                LaunchArgs {
                    resume_id: "",
                    model: "a b",
                },
            ),
            (
                "short resume",
                LaunchArgs {
                    resume_id: "abc",
                    model: "",
                },
            ),
            (
                "upper resume",
                LaunchArgs {
                    resume_id: "66666666-6666-4666-8666-66666666666A",
                    model: "",
                },
            ),
        ] {
            let err = build_args(&input).unwrap_err();
            assert_eq!(err.code(), codes::INVALID_LAUNCH, "{name}");
        }
    }

    /// `TestSafeModelBoundaries` / `TestValidSessionIDBoundaries`.
    #[test]
    fn boundaries() {
        assert!(safe_model("gemini-3.8-flash-low"));
        assert!(safe_model(&"a".repeat(128)));
        assert!(!safe_model(&"a".repeat(129)));
        assert!(!safe_model(""));
        assert!(!safe_model("-x"));
        assert!(valid_session_id("11111111-1111-4111-8111-111111111111"));
        assert!(!valid_session_id("11111111-1111-4111-8111-11111111111"));
        assert!(!valid_session_id("11111111_1111-4111-8111-111111111111"));
        assert!(!valid_session_id("11111111-1111-4111-8111-11111111111g"));
    }
}
