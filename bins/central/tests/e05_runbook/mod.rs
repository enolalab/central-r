//! `e05_runbook_test.go` — E05 verification: every `central
//! maintenance ...` command documented in the runbook must parse
//! through the real grammar, and every refusal reason token it
//! documents must exist in the Rust sources. A runbook that drifts
//! from the implementation fails here, not at an operator's
//! terminal. `CENTRAL_E05_EVIDENCE_DIR` emits
//! `slice-e-runbooks-verification.json`.
//!
//! Upstream drives `command.Dispatch(args)` in-process with the
//! composition-root clients left nil — grammar parses, then the
//! fail-closed `MAINTENANCE_SERVICE_UNAVAILABLE` arm answers. The
//! Rust binary owns no nil-client seam: the operator path is the
//! compiled binary itself, so this suite spawns
//! `env!("CARGO_BIN_EXE_central")` with the runbook argv and a
//! guaranteed-absent `CENTRAL_HELPER_SOCKET` — the deterministic
//! dial failure is the same "parses, then refuses before any
//! mutation" shape the nil client produced upstream. The privilege
//! gate upstream runs in `main()` — outside `Dispatch` and outside
//! the verified surface — refuses root on the Deferred mode this
//! resolves to, so a root run can produce no envelope at all and
//! the suite skips exactly as `main.rs`'s own dispatch tests do.

// Test-target relaxation, same as the other acceptance targets:
// unwrap/expect/panic are how a libtest body reports FailNow.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// `e05Runbook` — the same manifest-relative path upstream indexes
/// (`cmd/central/../../docs/...` ≡ `bins/central/../../docs/...`); it
/// is also the evidence's `runbook` field verbatim.
const E05_RUNBOOK: &str = "../../docs/operations/maintenance-runbook.md";
const E05_EVIDENCE_ENV: &str = "CENTRAL_E05_EVIDENCE_DIR";

/// The `<attempt-id>` substitution — upstream drops a parseable UUID
/// in for the operator-supplied placeholder so the grammar sees the
/// real shape.
const E05_ATTEMPT_ID: &str = "018f4f3a-9b9c-7def-8123-456789abcdef";

/// `e05Commands` — fenced-code-block lines starting `central `, with
/// the attempt-id placeholder replaced.
fn e05_commands(manifest: &Path) -> Vec<String> {
    let raw = std::fs::read_to_string(manifest.join(E05_RUNBOOK)).expect("runbook unreadable");
    let mut commands = Vec::new();
    let mut in_block = false;
    for line in raw.split('\n') {
        if line.starts_with("```") {
            in_block = !in_block;
            continue;
        }
        if !in_block {
            continue;
        }
        let line = line.trim();
        if !line.starts_with("central ") {
            continue;
        }
        commands.push(line.replace("<attempt-id>", E05_ATTEMPT_ID));
    }
    assert!(
        !commands.is_empty(),
        "runbook documents no central commands"
    );
    commands
}

/// `e05ReasonToken` — the upstream regex
/// `\b(MAINTENANCE_[A-Z_]+|INVALID_MAINTENANCE_GRAMMAR|AUTHORITY_DENIED|DENY_SAFE_ACTIVE)\b`
/// expressed without a regex dependency: split on Go's non-word
/// bytes (word = `[0-9A-Za-z_]`), then keep whole words that are
/// all-uppercase `MAINTENANCE_*` or one of the three literals. Word
/// splitting is what the `\b` anchors amount to — a token embedded
/// in a longer word matches neither there nor here.
fn e05_reason_tokens(text: &str) -> std::collections::BTreeSet<String> {
    fn is_word(c: char) -> bool {
        c.is_ascii_alphanumeric() || c == '_'
    }
    let mut tokens = std::collections::BTreeSet::new();
    let mut word = String::new();
    for c in text.chars().chain(std::iter::once(' ')) {
        if is_word(c) {
            word.push(c);
            continue;
        }
        let w = std::mem::take(&mut word);
        if w.is_empty() {
            continue;
        }
        if matches!(
            w.as_str(),
            "INVALID_MAINTENANCE_GRAMMAR" | "AUTHORITY_DENIED" | "DENY_SAFE_ACTIVE"
        ) || (w.len() > "MAINTENANCE_".len()
            && w.starts_with("MAINTENANCE_")
            && w.chars().all(|c| c.is_ascii_uppercase() || c == '_'))
        {
            tokens.insert(w);
        }
    }
    tokens
}

/// `os.MkdirAll(path, mode)` — mode applies at create only, exactly
/// like Go (`d07_acceptance`'s helper, local to this target).
fn mkdir_mode(path: impl AsRef<Path>, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(mode)
        .create(path)
}

/// `os.WriteFile(..., mode)` — mode applies at create only.
fn write_mode(path: impl AsRef<Path>, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)
        .and_then(|mut f| std::io::Write::write_all(&mut f, bytes))
}

fn walk_rs(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_rs(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// `TestE05RunbookCommandsParse` — every documented command through
/// the real grammar; a runbook drift fails the run, not the operator.
#[test]
fn e05_runbook_commands_parse() {
    // Upstream's `command.Dispatch` carries no privilege gate — it
    // lives in `main()`. The subprocess path reaches the grammar
    // through `run()`'s gate, which refuses root on Deferred mode
    // with no envelope at all, so root runs cannot exercise the
    // equivalent surface and skip (the `non_root` precedent in
    // `main.rs`'s dispatch tests).
    if rustix::process::getuid().as_raw() == 0 {
        eprintln!(
            "e05: skipping as root — upstream exercises `command.Dispatch` \
             in-process, which never ran `main()`'s privilege gate; the \
             spawned binary refuses root on this mode before the grammar"
        );
        return;
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let commands = e05_commands(&manifest);
    // `t.Chdir(t.TempDir())` — a refused apply still writes its
    // `slice-e-patch-apply.json` into the working directory; keep it
    // out of the repo and clean it at test end.
    let cwd = std::env::temp_dir().join(format!(
        "central-e05-cwd-{}-{}",
        std::process::id(),
        uuid::Uuid::now_v7()
    ));
    mkdir_mode(&cwd, 0o700).expect("e05 cwd");
    let mut results = Vec::new();
    for cmd in &commands {
        // `strings.Fields` — the runbook's leading `central` token is
        // argv0; the spawned binary receives the same token slice
        // upstream's `Dispatch(args)` indexed from args[1].
        let args: Vec<&str> = cmd.split_whitespace().collect();
        let out = Command::new(env!("CARGO_BIN_EXE_central"))
            .args(&args[1..])
            .current_dir(&cwd)
            // The hermetic absent-helper seam — upstream's nil
            // client arm answered deterministically; the always-
            // constructed Rust client needs a socket that never
            // answers to keep the refusal deterministic.
            .env(
                "CENTRAL_HELPER_SOCKET",
                "/nonexistent/central-e05/helper.sock",
            )
            // A systemd-activated test shell must not leak the
            // socket-activation gate into operator dispatch.
            .env_remove("LISTEN_FDS")
            .output()
            .expect("spawn central");
        let stdout = String::from_utf8_lossy(&out.stdout);
        #[derive(serde::Deserialize)]
        struct Envelope {
            #[serde(default)]
            reason: String,
            #[serde(default)]
            exit_code: i64,
        }
        let envelope: Envelope = serde_json::from_str(stdout.trim_end())
            .unwrap_or_else(|e| panic!("{cmd:?}: output does not decode: {e}"));
        assert_ne!(
            envelope.reason, "INVALID_MAINTENANCE_GRAMMAR",
            "{cmd:?}: runbook command fails the real grammar"
        );
        // Go `map[string]any` marshals keys sorted — serde_json's Map
        // is a BTreeMap, same order: command, exit_code, parses,
        // reason.
        results.push(serde_json::json!({
            "command": cmd,
            "exit_code": envelope.exit_code,
            "parses": true,
            "reason": envelope.reason,
        }));
    }
    e05_write_evidence(&results);
    let _ = std::fs::remove_dir_all(&cwd);
}

/// `TestE05RunbookReasonTokensExist` — every refusal token the
/// runbook documents exists as a quoted literal in the Rust sources
/// under `crates/` + `bins/` (upstream scans the matching Go roots:
/// the maintenance domain, the command package, the helper adapter,
/// and the cli writer).
#[test]
fn e05_runbook_reason_tokens_exist() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let raw = std::fs::read_to_string(manifest.join(E05_RUNBOOK)).expect("runbook unreadable");
    let tokens = e05_reason_tokens(&raw);
    let mut sources = Vec::new();
    let mut files = Vec::new();
    for root in [manifest.join("../../crates"), manifest.join("../../bins")] {
        walk_rs(&root, &mut files);
    }
    for path in files {
        if let Ok(bytes) = std::fs::read(&path) {
            sources.extend_from_slice(&bytes);
        }
    }
    let haystack = String::from_utf8_lossy(&sources);
    for tok in &tokens {
        assert!(
            haystack.contains(&format!("\"{tok}\"")),
            "runbook documents reason token {tok:?} absent from source"
        );
    }
}

/// `e05WriteEvidence` — `slice-e-runbooks-verification.json` under
/// `CENTRAL_E05_EVIDENCE_DIR`; unset emits nothing, exactly as
/// upstream.
fn e05_write_evidence(results: &[serde_json::Value]) {
    let dir = std::env::var(E05_EVIDENCE_ENV).unwrap_or_default();
    if dir.is_empty() {
        return;
    }
    let dir = PathBuf::from(dir);
    mkdir_mode(&dir, 0o755).expect("evidence dir");
    // Go marshals the anonymous struct in declaration order —
    // schema_version, runbook, commands — so a typed struct, not a
    // `json!` map (which sorts keys), keeps the field order exact.
    #[derive(serde::Serialize)]
    struct Evidence<'a> {
        schema_version: &'static str,
        runbook: &'static str,
        commands: &'a [serde_json::Value],
    }
    let raw = serde_json::to_string_pretty(&Evidence {
        schema_version: "slice-e-runbooks-verification/v1",
        runbook: E05_RUNBOOK,
        commands: results,
    })
    .expect("evidence marshal");
    write_mode(
        dir.join("slice-e-runbooks-verification.json"),
        format!("{raw}\n").as_bytes(),
        0o644,
    )
    .expect("evidence write");
}
