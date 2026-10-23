//! `argv.go` — the closed `claude` argv of spec decision 8 plus the
//! native cost limit of harness phase 3d decision 5.
//!
//! [`build_args`] is the only constructor of launch arguments: session
//! and resume ids must be canonical lower-case UUIDs, a model must be a
//! plain identifier that cannot read as an option, and the cost limit is
//! a number the builder formats itself — so no value can smuggle an
//! undeclared flag past the launcher. The prompt is never an input here;
//! it goes over stdin.

use central_foundation::failure::Failure;
use central_harness::domain::PermissionPolicy;

use super::codes;

/// `launchArgs` — exactly one of `session_id` (a fresh, preassigned
/// session) and `resume_id` is set.
pub(crate) struct LaunchArgs<'a> {
    pub policy: PermissionPolicy,
    pub session_id: &'a str,
    pub resume_id: &'a str,
    pub model: &'a str,
    /// The native cost limit; zero passes no limit.
    pub max_cost_micro_usd: i64,
}

/// The native cost range the argv accepts: one cent to US$1,000 — the
/// range a Task's budget and the serve default share.
pub(crate) const MIN_NATIVE_COST_MICRO_USD: i64 = 10_000;
pub(crate) const MAX_NATIVE_COST_MICRO_USD: i64 = 1_000_000_000;

/// `formatCostUSD` — micro-USD as the plain two-place decimal
/// `--max-budget-usd` accepts, rounded DOWN to the cent so the enforced
/// limit never exceeds the recorded one: 2,509,999 micro-USD is "2.50".
pub(crate) fn format_cost_usd(micro_usd: i64) -> String {
    let cents = micro_usd / 10_000;
    format!("{}.{:02}", cents / 100, cents % 100)
}

/// `expectedModes` — the `system/init.permissionMode` each policy must
/// report (verified live against 2.1.283): bridge requests "manual" on
/// argv but init reports it as "default".
pub(crate) fn expected_permission_mode(p: PermissionPolicy) -> &'static str {
    match p {
        PermissionPolicy::Deny => "dontAsk",
        PermissionPolicy::Bridge => "default",
        PermissionPolicy::AutoAllow => "bypassPermissions",
        // `spec.validate` refuses an unset/unknown policy first.
        _ => "",
    }
}

/// `policyFlags` — an explicit `--permission-mode` per policy so no
/// settings file can choose the mode; bridge adds the hidden but
/// required `--permission-prompt-tool stdio`.
fn policy_flags(p: PermissionPolicy) -> Option<&'static [&'static str]> {
    Some(match p {
        PermissionPolicy::Deny => &[
            "--permission-mode",
            "dontAsk",
            "--permission-prompts",
            "none",
        ],
        PermissionPolicy::Bridge => &[
            "--permission-mode",
            "manual",
            "--permission-prompts",
            "host",
            "--permission-prompt-tool",
            "stdio",
        ],
        PermissionPolicy::AutoAllow => &["--permission-mode", "bypassPermissions"],
        // `spec.validate` refuses an unset/unknown policy first; a
        // direct caller still fails closed.
        _ => return None,
    })
}

/// `buildArgs` — the closed argv. Policy order matches upstream:
/// base flags, the session/resume selector, policy flags, model, cost.
pub(crate) fn build_args(args: &LaunchArgs<'_>) -> Result<Vec<String>, Failure> {
    let Some(flags) = policy_flags(args.policy) else {
        return Err(Failure::invalid(
            codes::INVALID_LAUNCH,
            "claudecode: unknown permission policy",
        ));
    };
    let mut out: Vec<String> = [
        "-p",
        "--verbose",
        "--output-format",
        "stream-json",
        "--input-format",
        "stream-json",
        "--setting-sources",
        "user",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    if !args.session_id.is_empty() && !args.resume_id.is_empty() {
        return Err(Failure::invalid(
            codes::INVALID_LAUNCH,
            "claudecode: both a new and a resumed session id",
        ));
    }
    if !args.session_id.is_empty() {
        if !canonical_uuid(args.session_id) {
            return Err(Failure::invalid(
                codes::INVALID_LAUNCH,
                "claudecode: session id is not a canonical UUID",
            ));
        }
        out.push("--session-id".to_string());
        out.push(args.session_id.to_string());
    } else if !args.resume_id.is_empty() {
        if !canonical_uuid(args.resume_id) {
            return Err(Failure::invalid(
                codes::INVALID_LAUNCH,
                "claudecode: resume id is not a canonical UUID",
            ));
        }
        out.push("--resume".to_string());
        out.push(args.resume_id.to_string());
    } else {
        return Err(Failure::invalid(
            codes::INVALID_LAUNCH,
            "claudecode: a session id or resume id is required",
        ));
    }
    out.extend(flags.iter().map(|s| (*s).to_string()));
    if !args.model.is_empty() {
        if !safe_model(args.model) {
            return Err(Failure::invalid(
                codes::INVALID_LAUNCH,
                "claudecode: model name is not a plain identifier",
            ));
        }
        out.push("--model".to_string());
        out.push(args.model.to_string());
    }
    match args.max_cost_micro_usd {
        0 => {}
        c if !(MIN_NATIVE_COST_MICRO_USD..=MAX_NATIVE_COST_MICRO_USD).contains(&c) => {
            return Err(Failure::invalid(
                codes::INVALID_LAUNCH,
                "claudecode: cost limit must be from US$0.01 to US$1000",
            ));
        }
        c => {
            out.push("--max-budget-usd".to_string());
            out.push(format_cost_usd(c));
        }
    }
    Ok(out)
}

/// `canonicalUUID` — only the lower-case 8-4-4-4-12 hex form.
pub(crate) fn canonical_uuid(s: &str) -> bool {
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
                if !(c.is_ascii_digit() || (b'a'..=b'f').contains(c)) {
                    return false;
                }
            }
        }
    }
    true
}

/// `safeModel` — model aliases and ids such as "haiku",
/// "claude-sonnet-4-5-20250929" or "opus[1m]" pass verbatim; anything
/// that could be read as an option is refused.
pub(crate) fn safe_model(m: &str) -> bool {
    if m.is_empty() || m.len() > 128 || m.as_bytes()[0] == b'-' {
        return false;
    }
    m.bytes().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(c, b'-' | b'.' | b'_' | b':' | b'/' | b'[' | b']' | b'@')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_args<'a>(policy: PermissionPolicy) -> LaunchArgs<'a> {
        LaunchArgs {
            policy,
            session_id: "0192f000-0000-7000-8000-000000000001",
            resume_id: "",
            model: "",
            max_cost_micro_usd: 0,
        }
    }

    /// `TestBuildArgsDeny` — exact closed argv.
    #[test]
    fn build_args_deny() {
        let argv = build_args(&base_args(PermissionPolicy::Deny)).unwrap();
        assert_eq!(
            argv,
            vec![
                "-p",
                "--verbose",
                "--output-format",
                "stream-json",
                "--input-format",
                "stream-json",
                "--setting-sources",
                "user",
                "--session-id",
                "0192f000-0000-7000-8000-000000000001",
                "--permission-mode",
                "dontAsk",
                "--permission-prompts",
                "none",
            ]
        );
    }

    /// `TestBuildArgsBridge` — hidden stdio prompt-tool flag.
    #[test]
    fn build_args_bridge() {
        let argv = build_args(&base_args(PermissionPolicy::Bridge)).unwrap();
        assert!(argv.ends_with(&[
            "--permission-mode".to_string(),
            "manual".to_string(),
            "--permission-prompts".to_string(),
            "host".to_string(),
            "--permission-prompt-tool".to_string(),
            "stdio".to_string(),
        ]));
    }

    /// `TestBuildArgsAutoAllow`.
    #[test]
    fn build_args_auto_allow() {
        let argv = build_args(&base_args(PermissionPolicy::AutoAllow)).unwrap();
        assert!(argv.ends_with(&[
            "--permission-mode".to_string(),
            "bypassPermissions".to_string()
        ]));
    }

    /// Resume selector, mutual exclusion, canonical-id enforcement.
    #[test]
    fn session_selectors() {
        let mut a = base_args(PermissionPolicy::Deny);
        a.session_id = "";
        a.resume_id = "0192f000-0000-7000-8000-0000000000aa";
        let argv = build_args(&a).unwrap();
        assert!(argv.contains(&"--resume".to_string()));
        assert!(!argv.contains(&"--session-id".to_string()));

        let mut a = base_args(PermissionPolicy::Deny);
        a.resume_id = "0192f000-0000-7000-8000-0000000000aa";
        let err = build_args(&a).unwrap_err();
        assert_eq!(err.code(), codes::INVALID_LAUNCH);

        // Upper-case and non-UUID ids are refused.
        let mut a = base_args(PermissionPolicy::Deny);
        a.session_id = "0192F000-0000-7000-8000-000000000001";
        assert!(build_args(&a).is_err());
        let mut a = base_args(PermissionPolicy::Deny);
        a.session_id = "not-a-uuid";
        assert!(build_args(&a).is_err());
        // Neither selector.
        let mut a = base_args(PermissionPolicy::Deny);
        a.session_id = "";
        assert!(build_args(&a).is_err());
    }

    /// Model and cost-limit validation plus `formatCostUSD` rounding.
    #[test]
    fn model_and_cost() {
        let mut a = base_args(PermissionPolicy::Deny);
        a.model = "claude-sonnet-4-5-20250929";
        let argv = build_args(&a).unwrap();
        assert!(argv.ends_with(&[
            "--model".to_string(),
            "claude-sonnet-4-5-20250929".to_string()
        ]));

        let mut a = base_args(PermissionPolicy::Deny);
        a.model = "--dangerous";
        assert!(build_args(&a).is_err());
        let mut a = base_args(PermissionPolicy::Deny);
        a.model = "model name with spaces";
        assert!(build_args(&a).is_err());

        assert_eq!(format_cost_usd(2_509_999), "2.50");
        assert_eq!(format_cost_usd(10_000), "0.01");
        assert_eq!(format_cost_usd(1_000_000_000), "1000.00");

        let mut a = base_args(PermissionPolicy::Deny);
        a.max_cost_micro_usd = 9_999;
        assert!(build_args(&a).is_err());
        let mut a = base_args(PermissionPolicy::Deny);
        a.max_cost_micro_usd = 1_000_000_001;
        assert!(build_args(&a).is_err());
        let mut a = base_args(PermissionPolicy::Deny);
        a.max_cost_micro_usd = 2_509_999;
        let argv = build_args(&a).unwrap();
        assert!(argv.ends_with(&["--max-budget-usd".to_string(), "2.50".to_string()]));
    }

    /// `canonicalUUID`/`safeModel`/`expectedPermissionMode` units.
    #[test]
    fn validators() {
        assert!(canonical_uuid("0192f000-0000-7000-8000-000000000001"));
        assert!(!canonical_uuid("0192f000-0000-7000-8000-0000000000010"));
        assert!(!canonical_uuid("0192f000000070008000000000000001"));
        assert!(!canonical_uuid(""));
        assert!(safe_model("haiku"));
        assert!(safe_model("opus[1m]"));
        assert!(safe_model("vendor/model@latest"));
        assert!(!safe_model("-x"));
        assert!(!safe_model(&"a".repeat(129)));
        assert_eq!(
            expected_permission_mode(PermissionPolicy::Bridge),
            "default"
        );
        assert_eq!(expected_permission_mode(PermissionPolicy::Deny), "dontAsk");
        assert_eq!(
            expected_permission_mode(PermissionPolicy::AutoAllow),
            "bypassPermissions"
        );
    }
}
