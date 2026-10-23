//! `central checkpoint *` — the operator checkpoint verbs, ported from
//! `internal/command/checkpoint.go` plus the deferred-mode composition
//! of `cmd/central/checkpoint_composition.go` and the workspace
//! digester of `internal/adapter/workspace/digest/digest.go`.
//!
//!   - `create --run <id> --seq <n> [--node <key>]
//!     [--class supersedeable|run_terminal|pinned]` anchors at the
//!     named node, or at the run's unique depth-0 root when `--node` is
//!     absent; zero or several roots refuses
//!     `CHECKPOINT_ANCHOR_AMBIGUOUS` and asks for `--node`. `--seq` is
//!     the caller-supplied `(attempt_id, checkpoint_seq)` idempotency
//!     coordinate: retrying create with the same `--seq` replays the
//!     recorded checkpoint, a different payload at the same `--seq`
//!     refuses `DUPLICATE_IDEMPOTENCY_KEY`.
//!   - `resume --token <tok>` runs the all-or-nothing preflight +
//!     subtree rebuild; every spec violation exits with its named
//!     reason code.
//!   - `gc` runs one manual `Collect` pass — the same selection the
//!     janitor runs on schedule.
//!   - `pin <id>` sets `gc_class=pinned`; `unpin <id>` returns the row
//!     to `supersedeable` (the least-retentive class — an unpinned
//!     checkpoint must never become uncollectable by accident).
//!   - `list --run <id>` emits the run's checkpoint rows newest-first.
//!   - `show <id>` emits the same row projection plus the re-encoded
//!     resume token — the requested read-one verb upstream does not
//!     need (its `list` covers the surface); the token is the only
//!     piece of a row an operator cannot derive by hand.
//!
//! Every verb writes the standard JSON result envelope to stdout.
//! Grammar and input errors exit 2 with `CHECKPOINT_USAGE`; an INVALID
//! domain verdict exits 2 and a DENIED verdict exits 6 with the spec-3
//! reason code verbatim (`checkpointExit`); adapter-level errors exit
//! 6 as `CHECKPOINT_FAILED`. A GC pass that collected some anchors and
//! failed others reports `CHECKPOINT_GC_PARTIAL` with the collected
//! count — partial passes are harmless and the next janitor tick
//! retries.
//!
//! Composition (upstream `newCheckpointBackendFromEnv`): when the
//! environment carries `CENTRAL_CHECKPOINT_DSN` the command composes
//! the real PostgreSQL checkpoint store plus the filesystem workspace
//! digester; without it dispatch fails closed as
//! `CHECKPOINT_UNAVAILABLE` — never a checkpoint write or resume
//! against a store that is not there.

use std::env;
use std::io::Write;
use std::sync::Arc;
use std::time::Instant;

use central_adapter_postgres::checkpoint::Store as CheckpointStore;
use central_checkpoint::domain::{GcClass, ResumeCheckpoint};
use central_checkpoint::port::{Digester, ResumeStore};
use central_foundation::failure::{ExitClass, Failure, FailureKind};
use central_foundation::identity::{ResumeCheckpointId, RunId};
use central_foundation::local_result::LocalResult;
use sqlx::postgres::PgPoolOptions;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// `envCheckpointDSN` — the deferred-mode DSN for the checkpoint store.
/// An operator or a serve-side launcher supplies it; the binary never
/// reads a credential file for it.
const ENV_CHECKPOINT_DSN: &str = "CENTRAL_CHECKPOINT_DSN";

// The command-level reason tokens that are not spec-3 codes: grammar
// errors, the missing-backend refusal, and the partial-GC report.
// Domain verdicts travel on their Failure's own reason code.
const REASON_USAGE: &str = "CHECKPOINT_USAGE";
const REASON_UNAVAILABLE: &str = "CHECKPOINT_UNAVAILABLE";
const REASON_GC_PARTIAL: &str = "CHECKPOINT_GC_PARTIAL";
const REASON_FAILED: &str = "CHECKPOINT_FAILED";

/// `cli.Exit*` mapped onto `ExitClass`'s codes.
const EXIT_OK: ExitClass = ExitClass::Success;
/// `cli.ExitConfigInvalidCode` — invalid invocation / INVALID verdict.
const EXIT_CONFIG_INVALID: ExitClass = ExitClass::Usage;
/// `cli.ExitUnsupported` — the backend is not composable.
const EXIT_UNSUPPORTED: ExitClass = ExitClass::Incompatible;
/// `cli.ExitTerminal` — a terminal failure or DENIED verdict.
const EXIT_TERMINAL: ExitClass = ExitClass::Terminal;

/// `checkpointExit` — maps an error to the verb's exit code + reason:
/// a domain verdict keeps its own reason code, INVALID exits 2 and
/// DENIED exits 6; adapter-level (`pg_*`) failures — the Rust shape of
/// upstream's plain `fmt.Errorf` — report `CHECKPOINT_FAILED`.
fn checkpoint_exit_reason(failure: &Failure) -> (ExitClass, String) {
    if failure.code().starts_with("pg_") {
        return (EXIT_TERMINAL, REASON_FAILED.to_owned());
    }
    match failure.kind() {
        FailureKind::Invalid => (EXIT_CONFIG_INVALID, failure.code().to_owned()),
        _ => (EXIT_TERMINAL, failure.code().to_owned()),
    }
}

/// Operator-supplied ids: canonical lowercase hyphenated 36-char
/// text, version-agnostic, non-nil — deliberately narrower than
/// upstream `uuid.FromString` (which also admits dashless, braced,
/// and urn: forms); canonical is the only realistic operator input.
/// `from_trusted_db_bytes` is safe here because every rule beyond
/// version (canonical form, non-nil) is checked first.
fn parse_uuid_operand(text: &str) -> Option<[u8; 16]> {
    const HYPHENS: [usize; 4] = [8, 13, 18, 23];
    let bytes = text.as_bytes();
    if bytes.len() != 36 {
        return None;
    }
    let mut raw = [0u8; 16];
    let mut index = 0usize;
    let mut nibble = 0usize;
    for (position, byte) in bytes.iter().enumerate() {
        if HYPHENS.contains(&position) {
            if *byte != b'-' {
                return None;
            }
            continue;
        }
        let value = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return None,
        };
        if nibble.is_multiple_of(2) {
            raw[index] = value << 4;
        } else {
            raw[index] |= value;
            index += 1;
        }
        nibble += 1;
    }
    if index != 16 || raw == [0u8; 16] {
        return None;
    }
    Some(raw)
}

/// `parseCheckpointArgs` — walks the post-verb tokens into a flag map
/// and the positional list. `allowed` is the verb's flag vocabulary;
/// every flag takes a value (`--flag v` or `--flag=v`); unknown flags
/// and missing values are grammar errors.
fn parse_checkpoint_args(
    tokens: &[String],
    allowed: &[&str],
) -> Result<(std::collections::HashMap<String, String>, Vec<String>), ()> {
    let mut flags = std::collections::HashMap::new();
    let mut positional: Vec<String> = Vec::new();
    let mut index = 0usize;
    while index < tokens.len() {
        let token = &tokens[index];
        let Some(name_eq) = token.strip_prefix("--") else {
            positional.push(token.clone());
            index += 1;
            continue;
        };
        let (name, value) = match name_eq.split_once('=') {
            Some((name, value)) => (name.to_owned(), value.to_owned()),
            None => {
                if index + 1 >= tokens.len() || tokens[index + 1].starts_with("--") {
                    return Err(());
                }
                index += 1;
                (name_eq.to_owned(), tokens[index].clone())
            }
        };
        if !allowed.contains(&name.as_str()) {
            return Err(());
        }
        flags.insert(name, value);
        index += 1;
    }
    Ok((flags, positional))
}

/// One `checkpoint list`/`show` row in the result details (upstream
/// `CheckpointRow` — timestamps at `time.RFC3339` precision).
fn checkpoint_row(checkpoint: &ResumeCheckpoint) -> serde_json::Value {
    let format_ts = |ts: OffsetDateTime| ts.format(&Rfc3339).unwrap_or_default();
    let mut row = serde_json::json!({
        "checkpoint_id": checkpoint.id.to_string(),
        "node_id": checkpoint.node_id.to_string(),
        "gc_class": checkpoint.gc_class.as_str(),
        "event_watermark": checkpoint.event_watermark,
        "created_at": format_ts(checkpoint.created_at),
    });
    if let Some(expires) = checkpoint.expires_at {
        row["expires_at"] = format_ts(expires).into();
    }
    row
}

/// `CheckpointDetails` — the result envelope's `details` payload:
/// field optionality mirrors the upstream struct (`elapsed_ms` always,
/// everything else `omitempty`).
fn emit(
    mut stdout: &mut dyn Write,
    start: &Instant,
    command_id: &str,
    code: ExitClass,
    reason: &str,
    mut details: serde_json::Value,
) -> u8 {
    if let Some(map) = details.as_object_mut() {
        map.insert(
            "elapsed_ms".to_owned(),
            serde_json::Value::from(start.elapsed().as_millis() as i64),
        );
    } else {
        details = serde_json::json!({
            "elapsed_ms": start.elapsed().as_millis() as i64,
        });
    }
    let result = LocalResult::now(command_id, code, Some(reason.to_owned()), Some(details));
    match result.write_json_line(&mut stdout) {
        Ok(()) => result.exit_code,
        // A command ending without a written result fails closed at 6.
        Err(_) => EXIT_TERMINAL.code(),
    }
}

fn fail(
    stdout: &mut dyn Write,
    start: &Instant,
    command_id: &str,
    code: ExitClass,
    reason: &str,
) -> u8 {
    emit(
        stdout,
        start,
        command_id,
        code,
        reason,
        serde_json::json!({"reason": reason}),
    )
}

fn fail_err(stdout: &mut dyn Write, start: &Instant, command_id: &str, failure: &Failure) -> u8 {
    let (code, reason) = checkpoint_exit_reason(failure);
    fail(stdout, start, command_id, code, &reason)
}

/// `runCheckpoint`'s verb dispatch — generic over the backend seam so
/// the tests drive every verb against a fake; production passes the
/// env-composed PostgreSQL store.
async fn run_verb<B: ResumeStore>(
    backend: &B,
    command_id: &str,
    tokens: &[String],
    mut stdout: &mut dyn Write,
    start: &Instant,
) -> u8 {
    match command_id {
        "checkpoint.create" => {
            let Ok((flags, positional)) =
                parse_checkpoint_args(tokens, &["run", "node", "class", "seq"])
            else {
                return fail(stdout, start, command_id, EXIT_CONFIG_INVALID, REASON_USAGE);
            };
            if !positional.is_empty()
                || flags.get("run").is_none_or(String::is_empty)
                || flags.get("seq").is_none_or(String::is_empty)
            {
                return fail(stdout, start, command_id, EXIT_CONFIG_INVALID, REASON_USAGE);
            }
            // Presence of `run`/`seq` is pre-checked above; `.get` keeps
            // the impossible miss a usage failure, never a panic.
            let Some(run_raw) = flags.get("run").and_then(|text| parse_uuid_operand(text)) else {
                return fail(stdout, start, command_id, EXIT_CONFIG_INVALID, REASON_USAGE);
            };
            let run_id = RunId::from_trusted_db_bytes(run_raw);
            let Some(seq_text) = flags.get("seq") else {
                return fail(stdout, start, command_id, EXIT_CONFIG_INVALID, REASON_USAGE);
            };
            let Ok(checkpoint_seq) = seq_text.parse::<i64>() else {
                return fail(stdout, start, command_id, EXIT_CONFIG_INVALID, REASON_USAGE);
            };
            if checkpoint_seq < 1 {
                return fail(stdout, start, command_id, EXIT_CONFIG_INVALID, REASON_USAGE);
            }
            let class = match flags.get("class") {
                None => GcClass::Supersedeable,
                Some(text) => match GcClass::parse(text) {
                    Ok(class) => class,
                    Err(_) => {
                        return fail(stdout, start, command_id, EXIT_CONFIG_INVALID, REASON_USAGE);
                    }
                },
            };
            let node_key = flags.get("node").cloned().unwrap_or_default();
            let node_id = match backend.anchor_for(run_id, &node_key).await {
                Ok(node_id) => node_id,
                Err(failure) => return fail_err(stdout, start, command_id, &failure),
            };
            match backend
                .write_checkpoint(run_id, node_id, "", class, checkpoint_seq)
                .await
            {
                Ok(record) => emit(
                    stdout,
                    start,
                    command_id,
                    EXIT_OK,
                    "ok",
                    serde_json::json!({
                        "checkpoint_id": record.id.to_string(),
                        "token": record.encode_token(),
                        "run_id": record.run_id.to_string(),
                        "node_id": record.node_id.to_string(),
                        "gc_class": record.gc_class.as_str(),
                        "event_watermark": record.event_watermark,
                    }),
                ),
                Err(failure) => fail_err(stdout, start, command_id, &failure),
            }
        }

        "checkpoint.resume" => {
            let Ok((flags, positional)) = parse_checkpoint_args(tokens, &["token"]) else {
                return fail(stdout, start, command_id, EXIT_CONFIG_INVALID, REASON_USAGE);
            };
            if !positional.is_empty() || flags.get("token").is_none_or(String::is_empty) {
                return fail(stdout, start, command_id, EXIT_CONFIG_INVALID, REASON_USAGE);
            }
            let Some(token) = flags.get("token") else {
                return fail(stdout, start, command_id, EXIT_CONFIG_INVALID, REASON_USAGE);
            };
            match backend.resume_subtree(token, "").await {
                Ok(()) => emit(
                    stdout,
                    start,
                    command_id,
                    EXIT_OK,
                    "ok",
                    serde_json::json!({}),
                ),
                Err(failure) => fail_err(stdout, start, command_id, &failure),
            }
        }

        "checkpoint.gc" => {
            let Ok((_, positional)) = parse_checkpoint_args(tokens, &[]) else {
                return fail(stdout, start, command_id, EXIT_CONFIG_INVALID, REASON_USAGE);
            };
            if !positional.is_empty() {
                return fail(stdout, start, command_id, EXIT_CONFIG_INVALID, REASON_USAGE);
            }
            match backend.collect(OffsetDateTime::now_utc()).await {
                Ok(outcome) if outcome.has_failures() => {
                    // A partial pass still reports what it deleted;
                    // the verdict is terminal because at least one
                    // anchor failed.
                    emit(
                        stdout,
                        start,
                        command_id,
                        EXIT_TERMINAL,
                        REASON_GC_PARTIAL,
                        serde_json::json!({
                            "collected": outcome.collected,
                            "reason": REASON_GC_PARTIAL,
                        }),
                    )
                }
                Ok(outcome) => emit(
                    stdout,
                    start,
                    command_id,
                    EXIT_OK,
                    "ok",
                    serde_json::json!({"collected": outcome.collected}),
                ),
                Err(failure) => fail_err(stdout, start, command_id, &failure),
            }
        }

        "checkpoint.pin" | "checkpoint.unpin" => {
            let Ok((_, positional)) = parse_checkpoint_args(tokens, &[]) else {
                return fail(stdout, start, command_id, EXIT_CONFIG_INVALID, REASON_USAGE);
            };
            if positional.len() != 1 {
                return fail(stdout, start, command_id, EXIT_CONFIG_INVALID, REASON_USAGE);
            }
            let Some(raw) = parse_uuid_operand(&positional[0]) else {
                return fail(stdout, start, command_id, EXIT_CONFIG_INVALID, REASON_USAGE);
            };
            let id = ResumeCheckpointId::from_trusted_db_bytes(raw);
            let class = if command_id == "checkpoint.pin" {
                GcClass::Pinned
            } else {
                GcClass::Supersedeable
            };
            match backend.update_gc_class(id, class).await {
                Ok(()) => emit(
                    stdout,
                    start,
                    command_id,
                    EXIT_OK,
                    "ok",
                    serde_json::json!({
                        "checkpoint_id": id.to_string(),
                        "gc_class": class.as_str(),
                    }),
                ),
                Err(failure) => fail_err(stdout, start, command_id, &failure),
            }
        }

        "checkpoint.list" => {
            let Ok((flags, positional)) = parse_checkpoint_args(tokens, &["run"]) else {
                return fail(stdout, start, command_id, EXIT_CONFIG_INVALID, REASON_USAGE);
            };
            if !positional.is_empty() || flags.get("run").is_none_or(String::is_empty) {
                return fail(stdout, start, command_id, EXIT_CONFIG_INVALID, REASON_USAGE);
            }
            let Some(run_raw) = flags.get("run").and_then(|text| parse_uuid_operand(text)) else {
                return fail(stdout, start, command_id, EXIT_CONFIG_INVALID, REASON_USAGE);
            };
            let run_id = RunId::from_trusted_db_bytes(run_raw);
            match backend.list_checkpoints(run_id).await {
                Ok(rows) => emit(
                    stdout,
                    start,
                    command_id,
                    EXIT_OK,
                    "ok",
                    serde_json::json!({
                        "run_id": run_id.to_string(),
                        "checkpoints": rows.iter().map(checkpoint_row).collect::<Vec<_>>(),
                    }),
                ),
                Err(failure) => fail_err(stdout, start, command_id, &failure),
            }
        }

        // `show` is the requested read-one verb upstream does not
        // carry: the same row projection as `list`, plus the
        // re-encoded resume token — the one field of a checkpoint an
        // operator cannot derive by hand. A missing id is the same
        // INVALID `CHECKPOINT_NOT_FOUND` `pin` reports.
        "checkpoint.show" => {
            let Ok((_, positional)) = parse_checkpoint_args(tokens, &[]) else {
                return fail(stdout, start, command_id, EXIT_CONFIG_INVALID, REASON_USAGE);
            };
            if positional.len() != 1 {
                return fail(stdout, start, command_id, EXIT_CONFIG_INVALID, REASON_USAGE);
            }
            let Some(raw) = parse_uuid_operand(&positional[0]) else {
                return fail(stdout, start, command_id, EXIT_CONFIG_INVALID, REASON_USAGE);
            };
            let id = ResumeCheckpointId::from_trusted_db_bytes(raw);
            match backend.load_resume_checkpoint_by_id(id).await {
                Ok(record) => {
                    let mut details = checkpoint_row(&record);
                    if let Some(map) = details.as_object_mut() {
                        map.insert("token".to_owned(), record.encode_token().into());
                        map.insert("run_id".to_owned(), record.run_id.to_string().into());
                    }
                    emit(stdout, start, command_id, EXIT_OK, "ok", details)
                }
                Err(failure) => fail_err(stdout, start, command_id, &failure),
            }
        }

        _ => {
            // A checkpoint.* id this module does not own stays
            // deferred — dispatch to the standard placeholder, never
            // silently succeed.
            let result = LocalResult::unsupported(command_id);
            match result.write_json_line(&mut stdout) {
                Ok(()) => result.exit_code,
                Err(_) => EXIT_TERMINAL.code(),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// FsDigester — the port of internal/adapter/workspace/digest
// ---------------------------------------------------------------------------

/// The git binary worktree digests run — an absolute path never
/// resolved via PATH so a hostile PATH cannot shadow it (upstream
/// `DefaultGitPath`; same convention as workspace/gitclone).
const DEFAULT_GIT_PATH: &str = "/usr/bin/git";

/// The `.central-workspace-*` marker prefix the provisioner and
/// scheduler stamp into workspaces (`.central-workspace-kind`,
/// `.central-workspace-budget`): platform metadata, not workspace
/// content, excluded from both digest schemes at any depth.
const MARKER_PREFIX: &str = ".central-workspace-";

/// The production [`Digester`]: walks the filesystem for
/// `directory`/`plain` workspaces and runs a hardened git for
/// `worktree`/`code` — the Rust shape of upstream `digest.Digester`
/// the composition injects.
struct FsDigester;

impl Digester for FsDigester {
    fn digest<'a>(
        &'a self,
        path: &'a str,
        kind: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, Failure>> + Send + 'a>>
    {
        Box::pin(async move {
            match kind {
                "directory" | "plain" => digest_directory(path),
                "worktree" | "code" => digest_worktree(path),
                _ => Err(Failure::invalid(
                    "checkpoint_store_error",
                    format!("digest: unknown workspace kind {kind:?}"),
                )),
            }
        })
    }
}

/// Lowercase-hex encodes digest bytes — `hex.EncodeToString` for the
/// `sha256:` digest text (the checkpoint domain's `hex_lower`
/// convention, kept local so the binary carries no hex dependency).
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Walks `root` and hashes a sorted manifest — upstream
/// `digestDirectory`. Every entry contributes one line; the manifest
/// bytes are the digest pre-image:
///
///   regular file: `relpath \t size \t sha256:<content-hex> \t mode:<octal>`
///   directory:    `relpath \t - \t - \t mode:<octal>`
///   symlink:      `relpath \t symlink \t <literal target>`
///   other:        `relpath \t special:<type> \t - \t mode:<octal>`
///
/// The root itself contributes no line, so the digest does not depend
/// on the workspace directory's own name. Symlinks are recorded but
/// never followed (A06 path hygiene).
fn digest_directory(root: &str) -> Result<String, Failure> {
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::os::unix::fs::FileTypeExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};

    let fail = |detail: String| Failure::unavailable("checkpoint_store_error", detail);
    let metadata = fs::symlink_metadata(root)
        .map_err(|err| fail(format!("digest: stat workspace path: {err}")))?;
    if !metadata.is_dir() {
        return Err(Failure::invalid(
            "checkpoint_store_error",
            format!("digest: workspace path {root:?} is not a directory"),
        ));
    }

    fn walk(dir: &Path, root: &Path, manifest: &mut Vec<String>) -> Result<(), std::io::Error> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            let name = entry.file_name();
            if name.to_string_lossy().starts_with(MARKER_PREFIX) {
                // .central-workspace-* markers are platform metadata —
                // never digest them, and never descend into a
                // marker-named directory.
                continue;
            }
            if file_type.is_symlink() {
                let target = fs::read_link(&path)?;
                let rel = rel_path(root, &path);
                manifest.push(format!("{rel}\tsymlink\t{}", target.display()));
                continue;
            }
            if file_type.is_dir() {
                let mode = entry.metadata()?.mode() & 0o7777;
                let rel = rel_path(root, &path);
                manifest.push(format!("{rel}\t-\t-\tmode:{mode:04o}"));
                walk(&path, root, manifest)?;
                continue;
            }
            if file_type.is_file() {
                let meta = entry.metadata()?;
                let sum = hash_file(&path)?;
                let rel = rel_path(root, &path);
                manifest.push(format!(
                    "{rel}\t{}\tsha256:{sum}\tmode:{:04o}",
                    meta.size(),
                    meta.mode() & 0o7777,
                ));
                continue;
            }
            // fifo/socket/device: record type and mode, never open
            // (opening a fifo would block). Type letters mirror Go's
            // FileMode.String for the type bits.
            let kind = if file_type.is_fifo() {
                'p'
            } else if file_type.is_socket() {
                'S'
            } else if file_type.is_char_device() {
                'c'
            } else if file_type.is_block_device() {
                'D'
            } else {
                '?'
            };
            let mode = entry.metadata()?.mode() & 0o7777;
            let rel = rel_path(root, &path);
            manifest.push(format!("{rel}\tspecial:{kind}\t-\tmode:{mode:04o}"));
        }
        Ok(())
    }

    fn rel_path(root: &Path, path: &Path) -> String {
        path.strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/")
    }

    fn hash_file(path: &PathBuf) -> Result<String, std::io::Error> {
        use std::io::Read;
        let mut file = fs::File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            let read = file.read(&mut buf)?;
            if read == 0 {
                break;
            }
            hasher.update(&buf[..read]);
        }
        Ok(hex_lower(&hasher.finalize()))
    }

    let mut manifest = Vec::new();
    walk(Path::new(root), Path::new(root), &mut manifest)
        .map_err(|err| fail(format!("digest: walk {root:?}: {err}")))?;
    manifest.sort();
    let mut hasher = Sha256::new();
    for line in &manifest {
        hasher.update(line.as_bytes());
        hasher.update(b"\n");
    }
    Ok(format!("sha256:{}", hex_lower(&hasher.finalize())))
}

/// Whether any path segment carries the `.central-workspace-` marker
/// prefix — the directory scheme's skip-at-any-level rule applied to
/// porcelain paths (upstream `isMarkerPath`).
fn is_marker_path(path: &str) -> bool {
    path.split('/')
        .any(|segment| segment.starts_with(MARKER_PREFIX))
}

/// Runs `git` against `dir` with an environment built from empty — no
/// system or global config, no hooks, no fsmonitor, no prompts — the
/// same hardening upstream `gitRun` applies: a hostile `.git/config`
/// must not reach this process. Git's stderr is never returned in
/// errors: it may quote repository content.
fn git_run(dir: &str, args: &[&str]) -> Result<String, Failure> {
    let output = std::process::Command::new(DEFAULT_GIT_PATH)
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "protocol.allow=never",
            "-c",
            "protocol.file.allow=always",
            "-C",
            dir,
        ])
        .args(args)
        .env_clear()
        .envs([
            ("PATH", "/usr/bin:/bin"),
            ("LANG", "C"),
            ("LC_ALL", "C"),
            ("GIT_CONFIG_NOSYSTEM", "1"),
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
            ("GIT_TERMINAL_PROMPT", "0"),
            ("GIT_ASKPASS", "/bin/false"),
            ("HOME", "/nonexistent"),
        ])
        .output()
        .map_err(|err| {
            Failure::unavailable(
                "checkpoint_store_error",
                format!("digest: run git {}: {err}", args[0]),
            )
        })?;
    if !output.status.success() {
        return Err(Failure::unavailable(
            "checkpoint_store_error",
            format!(
                "digest: git {} exited with status {}",
                args[0],
                output.status.code().unwrap_or(-1)
            ),
        ));
    }
    String::from_utf8(output.stdout).map_err(|_| {
        Failure::unavailable("checkpoint_store_error", "digest: git output is not UTF-8")
    })
}

/// Hashes git HEAD plus the sorted, marker-filtered porcelain status
/// of the worktree at `path` (upstream `digestWorktree`):
///
///   `HEAD=<full-sha>\n`
///   `<porcelain line>\n`   (each retained status line)
///
/// `rev-parse HEAD` pins committed content; porcelain captures dirty,
/// staged, and untracked state, so any mutation short of a rewritten
/// index changes the digest. A path that is not a git worktree fails
/// `rev-parse`.
fn digest_worktree(path: &str) -> Result<String, Failure> {
    use sha2::{Digest, Sha256};

    let head = git_run(path, &["rev-parse", "HEAD"])?;
    let status = git_run(path, &["status", "--porcelain=v1", "--untracked-files=all"])?;

    let mut lines: Vec<String> = Vec::new();
    for line in status.split('\n') {
        if line.len() < 4 {
            continue; // blank or malformed short line
        }
        // Porcelain v1 is "XY <path>"; for renames the path field is
        // "old -> new" — the live path is the right-hand side.
        let mut p = &line[3..];
        if let Some(rename) = p.find(" -> ") {
            p = &p[rename + 4..];
        }
        if is_marker_path(p) {
            continue;
        }
        lines.push(line.to_owned());
    }
    lines.sort();

    let mut hasher = Sha256::new();
    hasher.update(format!("HEAD={}\n", head.trim()).as_bytes());
    for line in &lines {
        hasher.update(line.as_bytes());
        hasher.update(b"\n");
    }
    Ok(format!("sha256:{}", hex_lower(&hasher.finalize())))
}

// ---------------------------------------------------------------------------
// Composition + entry point
// ---------------------------------------------------------------------------

/// `newCheckpointBackendFromEnv` — composes the real backend when the
/// environment carries the DSN, else `None` (a failed connect resolves
/// to the same `None`: the command reports unavailable instead of
/// acting on a half-configured store).
async fn compose_backend() -> Option<CheckpointStore> {
    let dsn = env::var(ENV_CHECKPOINT_DSN).ok()?;
    if dsn.is_empty() {
        return None;
    }
    let pool = PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(&dsn)
        .await
        .ok()?;
    Some(CheckpointStore::with_digester(pool, Arc::new(FsDigester)))
}

/// `runCheckpoint` — composes the backend (nil reports unavailable
/// before the grammar is even parsed — upstream's check order) and
/// dispatches the verb on a one-shot current-thread runtime.
pub(crate) fn checkpoint(
    command_id: &str,
    tokens: &[String],
    stdout: &mut dyn Write,
    _stderr: &mut dyn Write,
) -> u8 {
    let start = Instant::now();
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return fail(stdout, &start, command_id, EXIT_TERMINAL, REASON_FAILED);
    };
    let Some(backend) = runtime.block_on(compose_backend()) else {
        return fail(
            stdout,
            &start,
            command_id,
            EXIT_UNSUPPORTED,
            REASON_UNAVAILABLE,
        );
    };
    runtime.block_on(run_verb(&backend, command_id, tokens, stdout, &start))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use central_checkpoint::domain::{GRAPH_SCHEMA_VERSION, RESUME_FORMAT_VERSION, codes};
    use central_checkpoint::port::{CollectOutcome, CollectStore};
    use central_foundation::identity::{ArtifactId, SessionAttemptId, WorkflowNodeId, WorkspaceId};

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(f)
    }

    fn strings(tokens: &[&str]) -> Vec<String> {
        tokens.iter().map(|t| (*t).to_owned()).collect()
    }

    fn invoke<B: ResumeStore>(
        backend: &B,
        command_id: &str,
        tokens: &[&str],
    ) -> (u8, serde_json::Value) {
        let mut stdout = Vec::new();
        let start = Instant::now();
        let code = block_on(run_verb(
            backend,
            command_id,
            &strings(tokens),
            &mut stdout,
            &start,
        ));
        let parsed = serde_json::from_slice(&stdout).unwrap();
        (code, parsed)
    }

    fn resume_checkpoint() -> ResumeCheckpoint {
        ResumeCheckpoint {
            id: ResumeCheckpointId::new(),
            workspace_id: WorkspaceId::new(),
            run_id: RunId::new(),
            node_id: WorkflowNodeId::new(),
            attempt_id: SessionAttemptId::new(),
            checkpoint_seq: 1,
            format_version: RESUME_FORMAT_VERSION.to_owned(),
            graph_schema_version: GRAPH_SCHEMA_VERSION.to_owned(),
            event_watermark: 7,
            harness_session_id: None,
            workspace_digest: None,
            workspace_path: None,
            completed_nodes: vec!["root".to_owned()],
            finalized_artifacts: vec![ArtifactId::new()],
            in_flight_nodes: Vec::new(),
            gc_class: GcClass::Supersedeable,
            created_at: OffsetDateTime::now_utc(),
            expires_at: None,
            content_digest: String::new(),
        }
    }

    /// One recorded `write_checkpoint` call: run, anchor, actor,
    /// class, seq.
    type WriteCall = (RunId, WorkflowNodeId, String, GcClass, i64);

    /// The port of upstream `fakeBackend`: scripts each seam's result
    /// and records the call arguments.
    #[derive(Default)]
    struct FakeBackend {
        anchor_result: Mutex<Option<Result<WorkflowNodeId, Failure>>>,
        anchor_calls: Mutex<Vec<(RunId, String)>>,
        write_result: Mutex<Option<Result<ResumeCheckpoint, Failure>>>,
        write_calls: Mutex<Vec<WriteCall>>,
        resume_result: Mutex<Option<Result<(), Failure>>>,
        resume_calls: Mutex<Vec<String>>,
        collect_result: Mutex<Option<Result<CollectOutcome, Failure>>>,
        gc_class_calls: Mutex<Vec<(ResumeCheckpointId, GcClass)>>,
        list_result: Mutex<Vec<ResumeCheckpoint>>,
        load_result: Mutex<Option<Result<ResumeCheckpoint, Failure>>>,
    }

    impl CollectStore for FakeBackend {
        async fn collect(&self, _now: OffsetDateTime) -> Result<CollectOutcome, Failure> {
            self.collect_result
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Ok(CollectOutcome::default()))
        }
    }

    impl ResumeStore for FakeBackend {
        async fn anchor_for(
            &self,
            run_id: RunId,
            node_key: &str,
        ) -> Result<WorkflowNodeId, Failure> {
            self.anchor_calls
                .lock()
                .unwrap()
                .push((run_id, node_key.to_owned()));
            self.anchor_result
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Ok(WorkflowNodeId::new()))
        }

        async fn write_checkpoint(
            &self,
            run_id: RunId,
            node_id: WorkflowNodeId,
            actor: &str,
            gc_class: GcClass,
            checkpoint_seq: i64,
        ) -> Result<ResumeCheckpoint, Failure> {
            self.write_calls.lock().unwrap().push((
                run_id,
                node_id,
                actor.to_owned(),
                gc_class,
                checkpoint_seq,
            ));
            self.write_result
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Ok(resume_checkpoint()))
        }

        async fn resolve_token(&self, _token: &str) -> Result<ResumeCheckpoint, Failure> {
            Ok(resume_checkpoint())
        }

        async fn resume_preflight(&self, _token: &str) -> Result<ResumeCheckpoint, Failure> {
            Ok(resume_checkpoint())
        }

        async fn resume_subtree(&self, token: &str, _actor: &str) -> Result<(), Failure> {
            self.resume_calls.lock().unwrap().push(token.to_owned());
            self.resume_result.lock().unwrap().take().unwrap_or(Ok(()))
        }

        async fn update_gc_class(
            &self,
            checkpoint_id: ResumeCheckpointId,
            class: GcClass,
        ) -> Result<(), Failure> {
            self.gc_class_calls
                .lock()
                .unwrap()
                .push((checkpoint_id, class));
            Ok(())
        }

        async fn list_by_anchor(
            &self,
            _run_id: RunId,
            _node_id: WorkflowNodeId,
        ) -> Result<Vec<ResumeCheckpoint>, Failure> {
            Ok(self.list_result.lock().unwrap().clone())
        }

        async fn list_checkpoints(&self, _run_id: RunId) -> Result<Vec<ResumeCheckpoint>, Failure> {
            Ok(self.list_result.lock().unwrap().clone())
        }

        async fn load_resume_checkpoint_by_id(
            &self,
            _checkpoint_id: ResumeCheckpointId,
        ) -> Result<ResumeCheckpoint, Failure> {
            self.load_result
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Ok(resume_checkpoint()))
        }
    }

    // -- upstream checkpoint_test.go: TestCheckpointCreateGrammarErrors -----

    #[test]
    fn create_grammar_errors() {
        let backend = FakeBackend::default();
        let run = RunId::new().to_string();
        for tokens in [
            vec![],
            vec!["--run", &run],                               // missing --seq
            vec!["--seq", "1"],                                // missing --run
            vec!["--run", "bogus", "--seq", "1"],              // bad run id
            vec!["--run", &run, "--seq", "0"],                 // seq must be >= 1
            vec!["--run", &run, "--seq", "abc"],               // seq not a number
            vec!["--run", &run, "--seq", "1", "extra"],        // stray positional
            vec!["--run", &run, "--seq", "1", "--bogus", "x"], // unknown flag
            vec!["--run", &run, "--seq", "1", "--class", "bogus"], // bad class
        ] {
            let (code, parsed) = invoke(&backend, "checkpoint.create", &tokens);
            assert_eq!(code, 2, "tokens {tokens:?}");
            assert_eq!(parsed["reason"], "CHECKPOINT_USAGE");
        }
        assert!(backend.write_calls.lock().unwrap().is_empty());
    }

    // -- upstream checkpoint_test.go: TestCheckpointCreateDefaultAnchor -----

    #[test]
    fn create_defaults_to_root_anchor() {
        let backend = FakeBackend::default();
        let run = RunId::new();
        let (code, parsed) = invoke(
            &backend,
            "checkpoint.create",
            &["--run", &run.to_string(), "--seq", "3"],
        );
        assert_eq!(code, 0, "{parsed}");
        assert_eq!(parsed["reason"], "ok");
        assert!(
            parsed["details"]["token"]
                .as_str()
                .unwrap()
                .starts_with("ckpt.")
        );
        let calls = backend.anchor_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], (run, String::new()));
        let writes = backend.write_calls.lock().unwrap();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].3, GcClass::Supersedeable);
        assert_eq!(writes[0].4, 3);
    }

    // -- upstream checkpoint_test.go: TestCheckpointCreateExplicitNodeAndClass --

    #[test]
    fn create_explicit_node_and_class() {
        let backend = FakeBackend::default();
        let run = RunId::new();
        let (code, _) = invoke(
            &backend,
            "checkpoint.create",
            &[
                "--run",
                &run.to_string(),
                "--seq",
                "5",
                "--node",
                "worker",
                "--class",
                "run_terminal",
            ],
        );
        assert_eq!(code, 0);
        let calls = backend.anchor_calls.lock().unwrap();
        assert_eq!(calls[0].1, "worker");
        let writes = backend.write_calls.lock().unwrap();
        assert_eq!(writes[0].3, GcClass::RunTerminal);
        assert_eq!(writes[0].4, 5);
    }

    // -- upstream checkpoint_test.go: TestCheckpointCreateAmbiguousRootAsksForNode --

    #[test]
    fn create_ambiguous_root_asks_for_node() {
        let backend = FakeBackend::default();
        *backend.anchor_result.lock().unwrap() = Some(Err(Failure::invalid(
            "CHECKPOINT_ANCHOR_AMBIGUOUS",
            "the run has 2 depth-0 roots; pass --node",
        )));
        let (code, parsed) = invoke(
            &backend,
            "checkpoint.create",
            &["--run", &RunId::new().to_string(), "--seq", "1"],
        );
        // INVALID verdict → exit 2 with the verdict's own code.
        assert_eq!(code, 2);
        assert_eq!(parsed["reason"], "CHECKPOINT_ANCHOR_AMBIGUOUS");
        assert!(backend.write_calls.lock().unwrap().is_empty());
    }

    // -- upstream checkpoint_test.go: TestCheckpointCreateBoundaryIllegalIsTerminal --

    #[test]
    fn create_boundary_illegal_is_terminal() {
        let backend = FakeBackend::default();
        *backend.write_result.lock().unwrap() = Some(Err(Failure::denied(
            codes::BOUNDARY_ILLEGAL,
            "anchor attempt is in its claim-to-outcome window",
        )));
        let (code, parsed) = invoke(
            &backend,
            "checkpoint.create",
            &["--run", &RunId::new().to_string(), "--seq", "1"],
        );
        // DENIED verdict → exit 6 with the spec code verbatim.
        assert_eq!(code, 6);
        assert_eq!(parsed["reason"], "CHECKPOINT_BOUNDARY_ILLEGAL");
    }

    // -- upstream checkpoint_test.go: TestCheckpointResumePassesToken/MissingToken --

    #[test]
    fn resume_passes_token() {
        let backend = FakeBackend::default();
        let (code, _) = invoke(&backend, "checkpoint.resume", &["--token", "ckpt.abc.def"]);
        assert_eq!(code, 0);
        assert_eq!(backend.resume_calls.lock().unwrap()[0], "ckpt.abc.def");
    }

    #[test]
    fn resume_missing_token_is_usage() {
        let backend = FakeBackend::default();
        let (code, parsed) = invoke(&backend, "checkpoint.resume", &[]);
        assert_eq!(code, 2);
        assert_eq!(parsed["reason"], "CHECKPOINT_USAGE");
        assert!(backend.resume_calls.lock().unwrap().is_empty());
    }

    // -- upstream checkpoint_test.go: TestCheckpointResumeStaleTokenIsTerminal --

    #[test]
    fn resume_stale_token_is_terminal() {
        let backend = FakeBackend::default();
        *backend.resume_result.lock().unwrap() = Some(Err(Failure::denied(
            codes::RESUME_TOKEN_STALE,
            "no live checkpoint exists for the token id",
        )));
        let (code, parsed) = invoke(&backend, "checkpoint.resume", &["--token", "ckpt.abc.def"]);
        assert_eq!(code, 6);
        assert_eq!(parsed["reason"], "RESUME_TOKEN_STALE");
    }

    // -- upstream checkpoint_test.go: TestCheckpointGCReportsCollected/Partial --

    #[test]
    fn gc_reports_collected() {
        let backend = FakeBackend::default();
        *backend.collect_result.lock().unwrap() = Some(Ok(CollectOutcome {
            collected: 4,
            failures: Vec::new(),
        }));
        let (code, parsed) = invoke(&backend, "checkpoint.gc", &[]);
        assert_eq!(code, 0);
        assert_eq!(parsed["details"]["collected"], 4);
    }

    #[test]
    fn gc_partial_failure_reports_count() {
        let backend = FakeBackend::default();
        *backend.collect_result.lock().unwrap() = Some(Ok(CollectOutcome {
            collected: 2,
            failures: vec![Failure::unavailable("checkpoint_store_error", "boom")],
        }));
        let (code, parsed) = invoke(&backend, "checkpoint.gc", &[]);
        assert_eq!(code, 6);
        assert_eq!(parsed["reason"], "CHECKPOINT_GC_PARTIAL");
        assert_eq!(parsed["details"]["collected"], 2);
    }

    #[test]
    fn gc_rejects_args() {
        let backend = FakeBackend::default();
        let (code, parsed) = invoke(&backend, "checkpoint.gc", &["extra"]);
        assert_eq!(code, 2);
        assert_eq!(parsed["reason"], "CHECKPOINT_USAGE");
    }

    // -- upstream checkpoint_test.go: TestCheckpointPinAndUnpin ----------------

    #[test]
    fn pin_and_unpin_flip_gc_class() {
        let backend = FakeBackend::default();
        let id = ResumeCheckpointId::new().to_string();
        let (code, _) = invoke(&backend, "checkpoint.pin", &[&id]);
        assert_eq!(code, 0);
        let (code, _) = invoke(&backend, "checkpoint.unpin", &[&id]);
        assert_eq!(code, 0);
        let calls = backend.gc_class_calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].1, GcClass::Pinned);
        assert_eq!(calls[1].1, GcClass::Supersedeable);
    }

    #[test]
    fn pin_grammar_errors() {
        let backend = FakeBackend::default();
        for tokens in [
            vec![],
            vec!["not-a-uuid"],
            vec!["--run", "x"],
            vec![&ResumeCheckpointId::new().to_string(), "extra"],
        ] {
            let (code, parsed) = invoke(&backend, "checkpoint.pin", &tokens);
            assert_eq!(code, 2, "tokens {tokens:?}");
            assert_eq!(parsed["reason"], "CHECKPOINT_USAGE");
        }
    }

    // -- upstream checkpoint_test.go: TestCheckpointPinMissingRowIsConfigInvalid --

    #[test]
    fn checkpoint_exit_maps_invalid_to_usage() {
        let failure = Failure::invalid("CHECKPOINT_NOT_FOUND", "no checkpoint");
        assert_eq!(
            checkpoint_exit_reason(&failure),
            (EXIT_CONFIG_INVALID, "CHECKPOINT_NOT_FOUND".to_owned())
        );
        let failure = Failure::denied(codes::BOUNDARY_ILLEGAL, "live anchor");
        assert_eq!(
            checkpoint_exit_reason(&failure),
            (EXIT_TERMINAL, codes::BOUNDARY_ILLEGAL.to_owned())
        );
        // Adapter-level pg_* codes are the infrastructure arm →
        // CHECKPOINT_FAILED, never a leaked sqlx code.
        let failure = Failure::unavailable("pg_unreachable", "connect failed");
        assert_eq!(
            checkpoint_exit_reason(&failure),
            (EXIT_TERMINAL, REASON_FAILED.to_owned())
        );
    }

    // -- upstream checkpoint_test.go: TestCheckpointListRendersRows ----------

    #[test]
    fn list_renders_rows_newest_first() {
        let backend = FakeBackend::default();
        let mut row = resume_checkpoint();
        row.gc_class = GcClass::RunTerminal;
        let checkpoint_id = row.id.to_string();
        *backend.list_result.lock().unwrap() = vec![row];
        let run = RunId::new();
        let (code, parsed) = invoke(&backend, "checkpoint.list", &["--run", &run.to_string()]);
        assert_eq!(code, 0, "{parsed}");
        let rows = parsed["details"]["checkpoints"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["checkpoint_id"], checkpoint_id);
        assert_eq!(rows[0]["gc_class"], "run_terminal");
        assert_eq!(rows[0]["event_watermark"], 7);
    }

    #[test]
    fn list_grammar_errors() {
        let backend = FakeBackend::default();
        for tokens in [
            vec![],
            vec!["--run", "bogus"],
            vec!["--run", &RunId::new().to_string(), "extra"],
        ] {
            let (code, parsed) = invoke(&backend, "checkpoint.list", &tokens);
            assert_eq!(code, 2, "tokens {tokens:?}");
            assert_eq!(parsed["reason"], "CHECKPOINT_USAGE");
        }
    }

    // -- checkpoint show (the requested verb upstream lacks) --------------------

    #[test]
    fn show_renders_row_plus_token() {
        let backend = FakeBackend::default();
        let id = ResumeCheckpointId::new().to_string();
        let (code, parsed) = invoke(&backend, "checkpoint.show", &[&id]);
        assert_eq!(code, 0, "{parsed}");
        assert!(
            parsed["details"]["token"]
                .as_str()
                .unwrap()
                .starts_with("ckpt.")
        );
        assert!(parsed["details"]["checkpoint_id"].is_string());
        assert!(parsed["details"]["run_id"].is_string());
    }

    #[test]
    fn show_missing_row_is_usage() {
        let backend = FakeBackend::default();
        *backend.load_result.lock().unwrap() = Some(Err(Failure::invalid(
            "CHECKPOINT_NOT_FOUND",
            "no checkpoint exists for the given id",
        )));
        let (code, parsed) = invoke(
            &backend,
            "checkpoint.show",
            &[&ResumeCheckpointId::new().to_string()],
        );
        assert_eq!(code, 2);
        assert_eq!(parsed["reason"], "CHECKPOINT_NOT_FOUND");
    }

    #[test]
    fn show_grammar_errors() {
        let backend = FakeBackend::default();
        for tokens in [
            vec![],
            vec!["not-a-uuid"],
            vec![&ResumeCheckpointId::new().to_string(), "extra"],
        ] {
            let (code, parsed) = invoke(&backend, "checkpoint.show", &tokens);
            assert_eq!(code, 2, "tokens {tokens:?}");
            assert_eq!(parsed["reason"], "CHECKPOINT_USAGE");
        }
    }

    // -- FsDigester: directory scheme determinism + marker exclusion ----------

    #[test]
    fn digest_directory_is_deterministic_and_marker_exempt() {
        let dir = std::env::temp_dir().join(format!(
            "central-digest-test-{}-{}",
            std::process::id(),
            RunId::new()
        ));
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("a.txt"), b"hello").unwrap();
        std::fs::write(dir.join("sub/b.txt"), b"world").unwrap();
        std::fs::write(dir.join(".central-workspace-kind"), b"directory").unwrap();

        let first = digest_directory(dir.to_str().unwrap()).unwrap();
        let second = digest_directory(dir.to_str().unwrap()).unwrap();
        assert_eq!(first, second);
        assert!(first.starts_with("sha256:"));

        // A content mutation changes the digest.
        std::fs::write(dir.join("a.txt"), b"hello!").unwrap();
        let third = digest_directory(dir.to_str().unwrap()).unwrap();
        assert_ne!(first, third);

        // The marker file itself never digests — writing another
        // marker leaves the digest unchanged.
        std::fs::write(dir.join(".central-workspace-budget"), b"8GiB").unwrap();
        let fourth = digest_directory(dir.to_str().unwrap()).unwrap();
        assert_eq!(third, fourth);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn digester_rejects_unknown_kind() {
        let digester = FsDigester;
        let err = block_on(digester.digest("/tmp", "bogus")).unwrap_err();
        assert_eq!(err.code(), "checkpoint_store_error");
    }

    #[test]
    fn digest_rejects_non_directory_path() {
        let err = digest_directory("/definitely/not/a/dir").unwrap_err();
        assert_eq!(err.code(), "checkpoint_store_error");
    }

    // -- parseCheckpointArgs (upstream's flag walk) ---------------------------

    #[test]
    fn checkpoint_arg_parser_accepts_both_flag_forms() {
        let (flags, positional) =
            parse_checkpoint_args(&strings(&["--run", "r", "--seq=1", "pos"]), &["run", "seq"])
                .unwrap();
        assert_eq!(flags["run"], "r");
        assert_eq!(flags["seq"], "1");
        assert_eq!(positional, vec!["pos".to_owned()]);
        // Missing value / unknown flag are grammar errors.
        assert!(parse_checkpoint_args(&strings(&["--run"]), &["run"]).is_err());
        assert!(parse_checkpoint_args(&strings(&["--bogus", "x"]), &["run"]).is_err());
    }
}
