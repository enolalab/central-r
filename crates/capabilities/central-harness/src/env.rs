//! The launch-environment filter — the port of
//! `internal/harness/env.go`. [`validate_launch_env`] enforces ADR
//! 0035's rule that Central never injects, relocates or redirects
//! harness credentials: a variable is accepted only if its name is in
//! the base allowlist (or has the `LC_` prefix) or in `extras`, and it
//! matches no denylist rule. The allowlist is case-sensitive; the
//! denylist is matched case-insensitively.

use std::collections::{BTreeMap, BTreeSet};

use central_foundation::failure::Failure;

use crate::domain::codes;

/// The non-secret launch environment every adapter may pass — upstream
/// `baseAllowedEnv`. `HOME` and `XDG_*` are deliberately absent: the
/// launcher derives them from the operator's passwd entry so the harness
/// always sees the operator's own login. `CENTRAL_ATTEMPT_SCOPE` is the
/// Phase-2 attempt-scope carrier (`<run_id>:<node_id>:<attempt_id>`),
/// injected by the Slice-2B dispatcher for `central artifact read` — ids
/// only, non-secret.
pub(crate) const BASE_ALLOWED_ENV: &[&str] = &[
    "PATH",
    "LANG",
    "LANGUAGE",
    "TERM",
    "COLORTERM",
    "NO_COLOR",
    "TZ",
    "TMPDIR",
    "USER",
    "LOGNAME",
    "SHELL",
    "CENTRAL_ATTEMPT_SCOPE",
];

/// The additional allowed name prefix — upstream `allowedEnvPrefix`.
pub(crate) const ALLOWED_ENV_PREFIX: &str = "LC_";

// The denylist below is matched against the upper-cased name, so every
// entry is upper case and a lower-case spelling (github_token,
// https_proxy) is denied too. The allowlist above stays case-sensitive.

/// Blocks config relocation, redirection and interception — upstream
/// `deniedEnvExact`.
pub(crate) const DENIED_ENV_EXACT: &[&str] = &[
    "HOME",
    "CLAUDE_CONFIG_DIR",
    "OPENCODE_CONFIG_DIR",
    "OPENCODE_CONFIG",
    "OPENCODE_CONFIG_CONTENT",
    "OPENCODE_DB",
    "CODEX_HOME",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "GOOGLE_APPLICATION_CREDENTIALS",
];

/// Upstream `deniedEnvPrefixes`; the `LD_`/`DYLD_` entries block
/// dynamic-loader injection (glibc and macOS dyld).
pub(crate) const DENIED_ENV_PREFIXES: &[&str] = &[
    "XDG_",
    "NODE_",
    "ANTHROPIC_",
    "CLAUDE_CODE_",
    "OPENAI_",
    "OPENCODE_",
    "AWS_",
    "GOOGLE_",
    "GEMINI_",
    "META_",
    "AZURE_",
    "LD_",
    "DYLD_",
];

/// Upstream `deniedEnvSuffixes`; `_PROXY` covers every proxy variable
/// (`FTP_PROXY`, `SOCKS_PROXY`, ...), not only the exact HTTP ones.
pub(crate) const DENIED_ENV_SUFFIXES: &[&str] = &[
    "_TOKEN",
    "_API_KEY",
    "_KEY",
    "_SECRET",
    "_SECRET_ACCESS_KEY",
    "_ACCESS_KEY_ID",
    "_PASSWORD",
    "_CREDENTIALS",
    "_BASE_URL",
    "_CUSTOM_HEADERS",
    "_PROXY",
];

/// Upstream `envNameValid`: a portable shell name
/// `[A-Za-z_][A-Za-z0-9_]*`. A name containing `=` could otherwise
/// smuggle an assignment such as `HOME=/x`.
fn env_name_valid(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        None => return false,
        Some(c) if !(c == '_' || c.is_ascii_alphabetic()) => return false,
        _ => {}
    }
    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

/// Upstream `envNameDenied`: the denylist, matched case-insensitively.
fn env_name_denied(name: &str) -> bool {
    let name = name.to_uppercase();
    DENIED_ENV_EXACT.contains(&name.as_str())
        || DENIED_ENV_PREFIXES.iter().any(|p| name.starts_with(p))
        || DENIED_ENV_SUFFIXES.iter().any(|s| name.ends_with(s))
}

/// Upstream `ValidateLaunchEnv`. Extras are validated against the
/// denylist too. Names that are not valid shell names are rejected and
/// counted, never printed, because such a name may embed a value. The
/// error lists offending valid names only, sorted, and never includes
/// values.
pub fn validate_launch_env(
    vars: &BTreeMap<String, String>,
    extras: &[&str],
) -> Result<(), Failure> {
    let mut offending: BTreeSet<&str> = BTreeSet::new();
    let mut invalid = 0usize;
    let mut allowed_extra: BTreeSet<&str> = BTreeSet::new();
    for name in extras {
        if !env_name_valid(name) {
            invalid += 1;
        } else if env_name_denied(name) {
            offending.insert(name);
        } else {
            allowed_extra.insert(name);
        }
    }
    for name in vars.keys() {
        if !env_name_valid(name) {
            invalid += 1;
            continue;
        }
        let allowed = BASE_ALLOWED_ENV.contains(&name.as_str())
            || name.starts_with(ALLOWED_ENV_PREFIX)
            || allowed_extra.contains(name.as_str());
        if !allowed || env_name_denied(name) {
            offending.insert(name.as_str());
        }
    }
    if offending.is_empty() && invalid == 0 {
        return Ok(());
    }
    let mut parts: Vec<String> = offending.iter().map(|n| format!("{n:?}")).collect();
    parts.sort();
    if invalid > 0 {
        parts.push(format!("{invalid} invalid variable name(s)"));
    }
    Err(Failure::denied(
        codes::FORBIDDEN_LAUNCH_ENV,
        parts.join(", "),
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde::Deserialize;

    use super::*;
    use crate::domain::codes;
    use crate::testkit::is_code;

    fn vars<const N: usize>(names: [&str; N]) -> BTreeMap<String, String> {
        names
            .iter()
            .map(|n| (n.to_string(), "x".to_string()))
            .collect()
    }

    fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    // Ports upstream `TestValidateLaunchEnvAcceptsAttemptScope`.
    #[test]
    fn validate_launch_env_accepts_attempt_scope() {
        let scope_env = env(&[(
            "CENTRAL_ATTEMPT_SCOPE",
            "0193c5c5-9b0e-7f3a-9b0e-9b0e9b0e9b0e:0193c5c5-9b0e-7f3a-9b0e-9b0e9b0e9b0e:0193c5c5-9b0e-7f3a-9b0e-9b0e9b0e9b0e",
        )]);
        assert!(validate_launch_env(&scope_env, &[]).is_ok());
        let err = validate_launch_env(&vars(["CENTRAL_FOO_TOKEN"]), &[]).unwrap_err();
        assert!(
            is_code(&err, codes::FORBIDDEN_LAUNCH_ENV),
            "secret-suffixed name: {err}"
        );
    }

    // Ports upstream `TestValidateLaunchEnvAcceptsBaseAllowlist`.
    #[test]
    fn validate_launch_env_accepts_base_allowlist() {
        let vars = env(&[
            ("PATH", "/usr/bin"),
            ("LANG", "C.UTF-8"),
            ("LANGUAGE", "en"),
            ("TERM", "xterm"),
            ("COLORTERM", "truecolor"),
            ("NO_COLOR", "1"),
            ("TZ", "UTC"),
            ("TMPDIR", "/tmp"),
            ("USER", "op"),
            ("LOGNAME", "op"),
            ("SHELL", "/bin/sh"),
            ("LC_ALL", "C.UTF-8"),
        ]);
        assert!(
            validate_launch_env(&vars, &[]).is_ok(),
            "base allowlist rejected"
        );
        assert!(
            validate_launch_env(&BTreeMap::new(), &[]).is_ok(),
            "empty env rejected"
        );
    }

    // Ports upstream `TestValidateLaunchEnvRejectsUnknownUnlessDeclared`.
    #[test]
    fn validate_launch_env_rejects_unknown_unless_declared() {
        let vars = env(&[("EDITOR", "vi")]);
        let err = validate_launch_env(&vars, &[]).unwrap_err();
        assert!(is_code(&err, codes::FORBIDDEN_LAUNCH_ENV), "{err}");
        assert!(
            validate_launch_env(&vars, &["EDITOR"]).is_ok(),
            "declared extra rejected"
        );
    }

    // Ports upstream `TestValidateLaunchEnvRejectsDeniedExtras`.
    #[test]
    fn validate_launch_env_rejects_denied_extras() {
        let err = validate_launch_env(&BTreeMap::new(), &["ANTHROPIC_API_KEY", ""]).unwrap_err();
        assert!(is_code(&err, codes::FORBIDDEN_LAUNCH_ENV), "{err}");
        assert!(
            err.message().contains("\"ANTHROPIC_API_KEY\""),
            "error does not name the extra: {err}"
        );
    }

    // Ports upstream `TestValidateLaunchEnvRejectsEveryDenyCategory`.
    #[test]
    fn validate_launch_env_rejects_every_deny_category() {
        for name in [
            "HOME",
            "CLAUDE_CONFIG_DIR",
            "OPENCODE_DB",
            "OPENCODE_CONFIG_CONTENT",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "ANTHROPIC_BASE_URL",
            "ANTHROPIC_CUSTOM_HEADERS",
            "OPENAI_BASE_URL",
            "https_proxy",
            "HTTPS_PROXY",
            "NO_PROXY",
            "SSL_CERT_FILE",
            "NODE_OPTIONS",
            "NODE_EXTRA_CA_CERTS",
            "AWS_SESSION_TOKEN",
            "AWS_PROFILE",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "CLAUDE_CODE_OAUTH_TOKEN",
            "CLAUDE_CODE_USE_BEDROCK",
            "META_API_KEY",
            "GEMINI_API_KEY",
            "GITHUB_TOKEN",
            "DB_PASSWORD",
            "MINIO_SECRET",
            "SOME_API_KEY",
            "LC_TOKEN",
        ] {
            // Declaring the name as an extra must not rescue it.
            let err = validate_launch_env(&vars([name]), &[name]).unwrap_err();
            assert!(
                is_code(&err, codes::FORBIDDEN_LAUNCH_ENV),
                "{name}: err = {err}"
            );
        }
    }

    // Ports upstream
    // `TestValidateLaunchEnvRejectsEachDenyRuleInIsolation`.
    #[test]
    fn validate_launch_env_rejects_each_deny_rule_in_isolation() {
        // Each name matches its rule and, where possible, no other, so
        // removing any single rule from env.rs makes this test fail.
        for name in [
            // exact
            "HOME",
            "CLAUDE_CONFIG_DIR",
            "OPENCODE_CONFIG_DIR",
            "OPENCODE_CONFIG",
            "OPENCODE_CONFIG_CONTENT",
            "OPENCODE_DB",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "no_proxy",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
            "REQUESTS_CA_BUNDLE",
            "CURL_CA_BUNDLE",
            "GOOGLE_APPLICATION_CREDENTIALS",
            // prefixes
            "XDG_X",
            "NODE_X",
            "ANTHROPIC_X",
            "CLAUDE_CODE_X",
            "OPENAI_X",
            "OPENCODE_X",
            "AWS_X",
            "GOOGLE_X",
            "GEMINI_X",
            "META_X",
            "AZURE_X",
            "LD_X",
            "DYLD_X",
            // suffixes
            "FOO_TOKEN",
            "FOO_API_KEY",
            "FOO_KEY",
            "FOO_SECRET",
            "FOO_SECRET_ACCESS_KEY",
            "FOO_ACCESS_KEY_ID",
            "FOO_PASSWORD",
            "FOO_CREDENTIALS",
            "FOO_BASE_URL",
            "FOO_CUSTOM_HEADERS",
            "FOO_PROXY",
        ] {
            let err = validate_launch_env(&vars([name]), &[name]).unwrap_err();
            assert!(
                is_code(&err, codes::FORBIDDEN_LAUNCH_ENV),
                "{name}: err = {err}"
            );
        }
    }

    // Ports upstream
    // `TestValidateLaunchEnvRejectsInvalidNamesWithoutPrintingThem`.
    #[test]
    fn validate_launch_env_rejects_invalid_names_without_printing_them() {
        let cases: [(BTreeMap<String, String>, Vec<&str>); 5] = [
            (env(&[("HOME=/secret-home", "")]), vec![]),
            (BTreeMap::new(), vec!["HOME=/secret-home"]),
            (vars(["1PATH"]), vec![]),
            (vars(["PATH "]), vec![]),
            (BTreeMap::new(), vec![""]),
        ];
        for (vars, extras) in cases {
            let err = validate_launch_env(&vars, &extras).unwrap_err();
            assert!(
                is_code(&err, codes::FORBIDDEN_LAUNCH_ENV),
                "{vars:?}/{extras:?}: err = {err}"
            );
            assert!(
                !err.message().contains("secret-home"),
                "invalid name printed: {err}"
            );
        }
    }

    // Ports upstream `TestValidateLaunchEnvErrorNamesSortedAndHidesValues`.
    #[test]
    fn validate_launch_env_error_names_sorted_and_hides_values() {
        let secret = "sk-ant-super-secret-value";
        let vars = env(&[
            ("ZETA_TOKEN", secret),
            ("HOME", secret),
            ("AWS_REGION", secret),
        ]);
        let err = validate_launch_env(&vars, &[]).unwrap_err();
        assert!(is_code(&err, codes::FORBIDDEN_LAUNCH_ENV), "{err}");
        let msg = err.message();
        assert!(!msg.contains(secret), "error leaked a value: {msg}");
        let a = msg.find("\"AWS_REGION\"");
        let h = msg.find("\"HOME\"");
        let z = msg.find("\"ZETA_TOKEN\"");
        assert!(
            matches!((a, h, z), (Some(a), Some(h), Some(z)) if a < h && h < z),
            "names not all present in sorted order: {msg}"
        );
    }

    // Ports upstream `TestValidateLaunchEnvHardening` — phase 2a spec
    // decision 10: loader injection, every proxy name, and denylist
    // matching regardless of case.
    #[test]
    fn validate_launch_env_hardening() {
        for name in [
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "LD_AUDIT",
            "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH",
            "ftp_proxy",
            "FTP_PROXY",
            "SOCKS_PROXY",
            "socks5_proxy",
            "Http_Proxy",
            "github_token",
            "Github_Token",
            "anthropic_api_key",
            "claude_config_dir",
            "home",
            "xdg_config_home",
            "ld_preload",
            "node_options",
            "aws_region",
            "my_secret",
        ] {
            // Declaring the name as an extra must not rescue it.
            let err = validate_launch_env(&vars([name]), &[name]).unwrap_err();
            assert!(
                is_code(&err, codes::FORBIDDEN_LAUNCH_ENV),
                "{name}: err = {err}"
            );
            let err = validate_launch_env(&BTreeMap::new(), &[name]).unwrap_err();
            assert!(
                is_code(&err, codes::FORBIDDEN_LAUNCH_ENV),
                "{name} as extra only: err = {err}"
            );
        }
    }

    // Ports upstream `TestValidateLaunchEnvAllowlistStaysCaseSensitive`.
    #[test]
    fn validate_launch_env_allowlist_stays_case_sensitive() {
        for name in ["path", "Path", "lang", "lc_all"] {
            let err = validate_launch_env(&vars([name]), &[]).unwrap_err();
            assert!(
                is_code(&err, codes::FORBIDDEN_LAUNCH_ENV),
                "{name}: err = {err}"
            );
        }
        let vars = env(&[("PATH", "/usr/bin"), ("LC_ALL", "C")]);
        assert!(
            validate_launch_env(&vars, &[]).is_ok(),
            "exact allowlist names rejected"
        );
    }

    // Ports upstream `TestLaunchEnvRuleSetsMatchSpec` (internal test —
    // pins every allowlist and denylist entry to phase 1a spec §6 as
    // hardened by phase 2a decision 10).
    #[test]
    fn launch_env_rule_sets_match_spec() {
        fn sorted(mut v: Vec<&'static str>) -> Vec<&'static str> {
            v.sort_unstable();
            v
        }
        let want_base = sorted(vec![
            "PATH",
            "LANG",
            "LANGUAGE",
            "TERM",
            "COLORTERM",
            "NO_COLOR",
            "TZ",
            "TMPDIR",
            "USER",
            "LOGNAME",
            "SHELL",
            "CENTRAL_ATTEMPT_SCOPE",
        ]);
        assert_eq!(sorted(BASE_ALLOWED_ENV.to_vec()), want_base);
        assert_eq!(ALLOWED_ENV_PREFIX, "LC_");
        for rule in DENIED_ENV_EXACT
            .iter()
            .chain(DENIED_ENV_PREFIXES)
            .chain(DENIED_ENV_SUFFIXES)
        {
            assert_eq!(
                *rule,
                rule.to_uppercase(),
                "denylist rule {rule:?} is not upper case and could never match"
            );
        }
        let want_exact = sorted(vec![
            "HOME",
            "CLAUDE_CONFIG_DIR",
            "OPENCODE_CONFIG_DIR",
            "OPENCODE_CONFIG",
            "OPENCODE_CONFIG_CONTENT",
            "OPENCODE_DB",
            "CODEX_HOME",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
            "REQUESTS_CA_BUNDLE",
            "CURL_CA_BUNDLE",
            "GOOGLE_APPLICATION_CREDENTIALS",
        ]);
        assert_eq!(sorted(DENIED_ENV_EXACT.to_vec()), want_exact);
        let want_prefixes = sorted(vec![
            "XDG_",
            "NODE_",
            "ANTHROPIC_",
            "CLAUDE_CODE_",
            "OPENAI_",
            "OPENCODE_",
            "AWS_",
            "GOOGLE_",
            "GEMINI_",
            "META_",
            "AZURE_",
            "LD_",
            "DYLD_",
        ]);
        assert_eq!(sorted(DENIED_ENV_PREFIXES.to_vec()), want_prefixes);
        let want_suffixes = sorted(vec![
            "_TOKEN",
            "_API_KEY",
            "_KEY",
            "_SECRET",
            "_SECRET_ACCESS_KEY",
            "_ACCESS_KEY_ID",
            "_PASSWORD",
            "_CREDENTIALS",
            "_BASE_URL",
            "_CUSTOM_HEADERS",
            "_PROXY",
        ]);
        assert_eq!(sorted(DENIED_ENV_SUFFIXES.to_vec()), want_suffixes);
    }

    // ------------------------------------------------------------------
    // Shared vectors — ports upstream `env_vectors_internal_test.go`.
    // ------------------------------------------------------------------

    #[derive(Deserialize)]
    struct EnvVector {
        id: String,
        env: BTreeMap<String, String>,
        accept: bool,
        wire: Option<bool>,
    }

    fn load_env_vectors() -> Vec<EnvVector> {
        #[derive(Deserialize)]
        struct File {
            vectors: Vec<EnvVector>,
        }
        let file: File =
            serde_json::from_str(include_str!("../testdata/launch-env-vectors.json")).unwrap();
        assert!(!file.vectors.is_empty(), "no vectors");
        let mut seen = std::collections::BTreeSet::new();
        for v in &file.vectors {
            assert!(
                !v.id.is_empty() && seen.insert(v.id.clone()),
                "vector id {:?} is empty or repeated",
                v.id
            );
        }
        file.vectors
    }

    // Ports upstream `TestValidateLaunchEnvMatchesSharedVectors`.
    #[test]
    fn validate_launch_env_matches_shared_vectors() {
        for v in load_env_vectors() {
            match validate_launch_env(&v.env, &[]) {
                Err(err) => {
                    assert!(!v.accept, "{}: refused: {err}", v.id);
                    assert!(
                        is_code(&err, codes::FORBIDDEN_LAUNCH_ENV),
                        "{}: err = {err}",
                        v.id
                    );
                }
                Ok(()) => assert!(v.accept, "{}: accepted", v.id),
            }
        }
    }

    // Ports upstream `TestSharedEnvVectorsCoverEveryRule`.
    #[test]
    fn shared_env_vectors_cover_every_rule() {
        let vectors = load_env_vectors();
        let mut accepted = std::collections::BTreeSet::new();
        let mut refused_singles: Vec<String> = Vec::new();
        for v in &vectors {
            if v.wire == Some(false) {
                for name in v.env.keys() {
                    assert!(
                        name.contains('=') || name.contains('\0'),
                        "{}: wire false but name {name:?} is representable on the wire",
                        v.id
                    );
                }
            }
            if v.accept {
                accepted.extend(v.env.keys().cloned());
            } else if v.env.len() == 1 {
                refused_singles.extend(v.env.keys().map(|n| n.to_uppercase()));
            }
        }
        for name in BASE_ALLOWED_ENV {
            assert!(
                accepted.contains(*name),
                "no accepted vector carries allowlisted {name}"
            );
        }
        let hit = |match_fn: &dyn Fn(&str) -> bool| refused_singles.iter().any(|n| match_fn(n));
        for name in DENIED_ENV_EXACT {
            assert!(
                hit(&|n| n == *name),
                "no refused vector names denied {name}"
            );
        }
        for prefix in DENIED_ENV_PREFIXES {
            assert!(
                hit(&|n| n.starts_with(prefix)),
                "no refused vector uses denied prefix {prefix}"
            );
        }
        for suffix in DENIED_ENV_SUFFIXES {
            // Under the LC_ prefix the allowlist admits the name, so only
            // the suffix rule can refuse it.
            assert!(
                hit(&|n| n.starts_with(ALLOWED_ENV_PREFIX) && n.ends_with(suffix)),
                "no refused LC_ vector uses denied suffix {suffix}"
            );
        }
    }
}
