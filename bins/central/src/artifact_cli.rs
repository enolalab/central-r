//! `central artifact read` — the sibling data-flow verb, ported from
//! `internal/command/artifact_read.go` plus the deferred-mode
//! composition of `cmd/central/artifact_read_composition.go`.
//!
//! It resolves an artifact by id or by `--from <producer_node_key>
//! --name <name>` inside the scope's run, checks the read against the
//! attempt's authorized scope — the node's `artifact` in-edges unioned
//! with its spec's `input_artifact_refs` — verifies the delivered body
//! against the finalized SHA-256, releases bytes to `--out` or
//! `--stdout`, and journals the read edge with its declared|undeclared
//! classification and the checksum it bound to.
//!
//! Scope arrives via `CENTRAL_ATTEMPT_SCOPE=<run_id>:<node_id>:<attempt_id>`;
//! absent, the read runs as the synthetic operator reader (spec OQ-5)
//! and is journaled undeclared.
//!
//! Refusals are the closed lineage reason codes; the command never
//! hands over unverified bytes:
//!
//! - `ARTIFACT_READ_UNRESOLVED` — the selector resolves to zero or many
//!   artifacts (or malformed grammar).
//! - `ARTIFACT_NOT_FINALIZED` — the artifact has not reached `ready`.
//! - `ARTIFACT_SCOPE_DENIED` — a read outside the attempt's authorized
//!   set.
//! - `ARTIFACT_BODY_INTEGRITY` — the delivered bytes fail SHA-256
//!   verification.
//! - `ARTIFACT_READ_AMBIGUOUS` — the outcome is unknown mid-stream or
//!   after release.
//! - `LINEAGE_READ_UNDECLARED` — notice on stderr for an
//!   undeclared-but-authorized read.
//!
//! Composition (upstream `newArtifactReadBackendFromEnv`): when the
//! environment carries both `CENTRAL_ARTIFACT_READ_DSN` and a complete
//! `CENTRAL_ARTIFACT_OBJECT_*` config the command composes the real
//! PostgreSQL lineage store plus the object store; any missing or
//! failing piece fails closed as `ARTIFACT_READ_UNAVAILABLE` — never a
//! wider authorization than the configured store can back.

use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use central_adapter_postgres::artifact::Store as LineageStore;
use central_adapter_s3::{Config as ObjectConfig, S3ObjectStore};
use central_artifact::app::{authorize_read, record_read};
use central_artifact::lineage::{ReadRequest, ReadScope, ReadSelector, parse_attempt_scope};
use central_artifact::port::{ObjectRef, ObjectStore, ReadEdgeStore, ReadStore};
use central_foundation::failure::ExitClass;
use central_foundation::identity::ArtifactId;
use central_foundation::local_result::LocalResult;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use time::OffsetDateTime;

/// The command grammar identifier the envelope reports.
const COMMAND_ID: &str = "artifact.read";

/// `envArtifactReadDSN` — the deferred-mode DSN for the lineage store.
const ENV_ARTIFACT_READ_DSN: &str = "CENTRAL_ARTIFACT_READ_DSN";
/// `envArtifactObject*` — the object-store composition inputs.
const ENV_OBJECT_ENDPOINT: &str = "CENTRAL_ARTIFACT_OBJECT_ENDPOINT";
const ENV_OBJECT_BUCKET: &str = "CENTRAL_ARTIFACT_OBJECT_BUCKET";
const ENV_OBJECT_ACCESS: &str = "CENTRAL_ARTIFACT_OBJECT_ACCESS_KEY";
const ENV_OBJECT_SECRET: &str = "CENTRAL_ARTIFACT_OBJECT_SECRET_KEY";
const ENV_OBJECT_REGION: &str = "CENTRAL_ARTIFACT_OBJECT_REGION";
const ENV_OBJECT_TLS: &str = "CENTRAL_ARTIFACT_OBJECT_USE_TLS";
/// `attemptScopeEnv` — the dispatcher-injected attempt credential.
const ENV_ATTEMPT_SCOPE: &str = "CENTRAL_ATTEMPT_SCOPE";

// The closed reason vocabulary (upstream `internal/artifact`'s lineage
// reasons plus this command's own codes). The capability constants
// name the same strings; these locals keep the binary's emit path
// self-describing at each call site.
const REASON_READ_UNAVAILABLE: &str = "ARTIFACT_READ_UNAVAILABLE";
const REASON_READ_UNRESOLVED: &str = "ARTIFACT_READ_UNRESOLVED";
const REASON_SCOPE_DENIED: &str = "ARTIFACT_SCOPE_DENIED";
const REASON_NOT_FINALIZED: &str = "ARTIFACT_NOT_FINALIZED";
const REASON_BODY_INTEGRITY: &str = "ARTIFACT_BODY_INTEGRITY";
const REASON_READ_AMBIGUOUS: &str = "ARTIFACT_READ_AMBIGUOUS";
const REASON_READ_FAILED: &str = "ARTIFACT_READ_FAILED";
const REASON_OUTPUT_FAILED: &str = "ARTIFACT_READ_OUTPUT_FAILED";
const REASON_READ_UNDECLARED: &str = "LINEAGE_READ_UNDECLARED";

/// `cli.Exit*` mapped onto `ExitClass`'s codes.
const EXIT_OK: ExitClass = ExitClass::Success;
/// `cli.ExitConfigInvalidCode` — invalid invocation.
const EXIT_CONFIG_INVALID: ExitClass = ExitClass::Usage;
/// `cli.ExitUnsupported` — the backend is not composable.
const EXIT_UNSUPPORTED: ExitClass = ExitClass::Incompatible;
/// `cli.ExitTerminal` — a terminal failure or unknown outcome.
const EXIT_TERMINAL: ExitClass = ExitClass::Terminal;
/// `cli.ExitAuthorityDenied` — the scope refused the read.
const EXIT_AUTHORITY_DENIED: ExitClass = ExitClass::Denied;

/// `artifactReadArgs` — the tokens after `central artifact read`.
/// Selector: exactly one positional artifact id, or `--from <key>
/// --name <name>` together. Output: `--out <path>` or `--stdout`;
/// neither defaults to a workspace-local file named after the artifact
/// (the spec's materialize-to-path mode).
#[derive(Debug, Default, PartialEq)]
struct ArtifactReadArgs {
    /// The positional artifact id selector.
    artifact_id: Option<ArtifactId>,
    /// `--from <producer_node_key>` — half of the produced selector.
    from_node_key: String,
    /// `--name <name>` — the required-role half of the produced
    /// selector.
    name: String,
    /// `--out <path>` — the materialize destination.
    out: String,
    /// `--stdout` — the raw-bytes-to-stdout mode.
    stdout: bool,
}

/// `uuid.FromString` parity for the selector: canonical lowercase
/// hyphenated text, version-agnostic, non-nil — the lineage model
/// deliberately carries v4 identities (the seeded artifacts, the
/// journaled edge ids), so the strict v7 [`ArtifactId::parse`] cannot
/// serve this boundary. `from_trusted_db_bytes` is safe here because
/// every parse rule the newtype enforces beyond version (canonical
/// form, non-nil) is checked by this function first.
fn parse_artifact_selector(text: &str) -> Option<ArtifactId> {
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
    if index != 16 {
        return None;
    }
    let id = ArtifactId::from_trusted_db_bytes(raw);
    if id.is_nil() {
        return None;
    }
    Some(id)
}

/// `filepath.Base` — the trailing path element after any trailing
/// separators (the `--name` role's basename for the default `--out`).
fn base_name(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    match trimmed.rsplit('/').next() {
        Some(name) if !name.is_empty() => name,
        _ => "/",
    }
}

/// `defaultArtifactReadOut` — the materialize-to-path default: the
/// workspace-local file named for the artifact (the `--name` role when
/// the selector carries one, else the artifact id).
fn default_out(parsed: &ArtifactReadArgs) -> String {
    if !parsed.name.is_empty() {
        return base_name(&parsed.name).to_owned();
    }
    if let Some(id) = parsed.artifact_id {
        return id.to_string();
    }
    "artifact".to_owned()
}

/// `parseArtifactReadArgs` — a byte-faithful port of the upstream
/// grammar walk: `--flag=value` and `--flag value` forms, unknown
/// flags refused, mutual exclusions checked, the output default
/// derived last.
fn parse_artifact_read_args(tokens: &[String]) -> Result<ArtifactReadArgs, ()> {
    let mut parsed = ArtifactReadArgs::default();
    let mut positional: Vec<&str> = Vec::new();
    let mut index = 0usize;
    while index < tokens.len() {
        let token = &tokens[index];
        // `value` — the `=` payload or the following non-flag token.
        macro_rules! value {
            () => {{
                if let Some(eq) = token.find('=') {
                    Some(token[eq + 1..].to_owned())
                } else if index + 1 < tokens.len() && !tokens[index + 1].starts_with("--") {
                    index += 1;
                    Some(tokens[index].clone())
                } else {
                    None
                }
            }};
        }
        if token == "--stdout" {
            parsed.stdout = true;
        } else if let Some(v) = token.strip_prefix("--from=") {
            parsed.from_node_key = v.to_owned();
        } else if token == "--from" {
            let Some(v) = value!() else {
                return Err(());
            };
            parsed.from_node_key = v;
        } else if let Some(v) = token.strip_prefix("--name=") {
            parsed.name = v.to_owned();
        } else if token == "--name" {
            let Some(v) = value!() else {
                return Err(());
            };
            parsed.name = v;
        } else if let Some(v) = token.strip_prefix("--out=") {
            parsed.out = v.to_owned();
        } else if token == "--out" {
            let Some(v) = value!() else {
                return Err(());
            };
            parsed.out = v;
        } else if token.starts_with("--") {
            return Err(());
        } else {
            positional.push(token.as_str());
        }
        index += 1;
    }

    match positional.len() {
        1 => {
            let Some(id) = parse_artifact_selector(positional[0]) else {
                return Err(());
            };
            parsed.artifact_id = Some(id);
        }
        n if n > 1 => return Err(()),
        _ => {}
    }
    if parsed.artifact_id.is_some() && (!parsed.from_node_key.is_empty() || !parsed.name.is_empty())
    {
        return Err(());
    }
    if parsed.from_node_key.is_empty() != parsed.name.is_empty() {
        return Err(());
    }
    if parsed.artifact_id.is_none() && parsed.from_node_key.is_empty() {
        return Err(());
    }
    if !parsed.out.is_empty() && parsed.stdout {
        return Err(());
    }
    if !parsed.stdout && parsed.out.is_empty() {
        parsed.out = default_out(&parsed);
    }
    Ok(parsed)
}

/// `ArtifactReadDetails` — the result envelope's `details` payload.
/// Field optionality mirrors the upstream struct: `declared` and
/// `elapsed_ms` are always present (a journaled undeclared read must
/// report `declared: false`, never omit the flag); every other field
/// is `omitempty` — present only when meaningful.
fn details_json(
    artifact_id: &str,
    run_id: &str,
    declared: bool,
    checksum: &str,
    path: &str,
    stdout: bool,
    reason: &str,
) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    if !artifact_id.is_empty() {
        map.insert("artifact_id".to_owned(), artifact_id.into());
    }
    if !run_id.is_empty() {
        map.insert("run_id".to_owned(), run_id.into());
    }
    map.insert("declared".to_owned(), declared.into());
    if !checksum.is_empty() {
        map.insert("checksum".to_owned(), checksum.into());
    }
    if !path.is_empty() {
        map.insert("path".to_owned(), path.into());
    }
    if stdout {
        map.insert("stdout".to_owned(), true.into());
    }
    if !reason.is_empty() {
        map.insert("reason".to_owned(), reason.into());
    }
    serde_json::Value::Object(map)
}

/// The `fail` helper's details: only `reason` (plus `declared: false`
/// and `elapsed_ms`, which every envelope carries).
fn fail_details(reason: &str) -> serde_json::Value {
    details_json("", "", false, "", "", false, reason)
}

/// `emit` — stamps `elapsed_ms`, wraps `details` in the
/// `central.local-result/v1` envelope, and writes it to the envelope
/// plane (stdout, or stderr when `--stdout` owns stdout for the
/// verified payload). The returned code is the process exit status.
fn emit(
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    stdout_mode: bool,
    start: &Instant,
    code: ExitClass,
    reason: &str,
    mut details: serde_json::Value,
) -> u8 {
    if let Some(map) = details.as_object_mut() {
        map.insert(
            "elapsed_ms".to_owned(),
            serde_json::Value::from(start.elapsed().as_millis() as i64),
        );
    }
    let result = LocalResult::now(COMMAND_ID, code, Some(reason.to_owned()), Some(details));
    let mut envelope: &mut dyn Write = if stdout_mode { stderr } else { stdout };
    match result.write_json_line(&mut envelope) {
        Ok(()) => result.exit_code,
        // A command ending without a written result fails closed at 6.
        Err(_) => EXIT_TERMINAL.code(),
    }
}

fn emit_fail(
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    stdout_mode: bool,
    start: &Instant,
    code: ExitClass,
    reason: &str,
) -> u8 {
    emit(
        stdout,
        stderr,
        stdout_mode,
        start,
        code,
        reason,
        fail_details(reason),
    )
}

/// `spoolVerifiedBody`'s private temp target — one collision-proof name
/// inside `dir`, opened `0600` like `os.CreateTemp`'s private mode.
static SPOOL_COUNTER: AtomicU64 = AtomicU64::new(0);

fn spool_path(dir: &Path) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let counter = SPOOL_COUNTER.fetch_add(1, Ordering::Relaxed);
    dir.join(format!(
        ".central-artifact-read-{}-{nanos}-{counter}",
        process::id()
    ))
}

/// Opens the private spool file (`0600`, create-new), retrying a
/// handful of times on the astronomically unlikely name collision —
/// the same contract `os.CreateTemp` holds.
fn open_spool(dir: &Path) -> std::io::Result<(PathBuf, File)> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    for _ in 0..8 {
        let path = spool_path(dir);
        match options.open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "spool name exhausted",
    ))
}

/// `spoolVerifiedBody` — copies the body stream into a private temp
/// file inside `dir`, hashing as it goes. `verified` reports the
/// SHA-256 equality of the streamed bytes with `expected`; the caller
/// deletes the file unconditionally. Bytes reach the caller's
/// destination only after the whole body verifies, so a corrupt or
/// truncated object can never land at `--out` or on stdout half-read.
async fn spool_verified_body(
    dir: &Path,
    body: &mut dyn central_artifact::port::ByteStream,
    expected: &[u8; 32],
) -> std::io::Result<(PathBuf, bool)> {
    let (path, mut file) = open_spool(dir)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let copy_result = async {
        loop {
            let read = body
                .read_chunk(&mut buf)
                .await
                .map_err(|_| std::io::Error::other("body read failed"))?;
            if read == 0 {
                return Ok(());
            }
            file.write_all(&buf[..read])?;
            hasher.update(&buf[..read]);
        }
    }
    .await;
    if let Err(err) = copy_result {
        let _ = fs::remove_file(&path);
        return Err(err);
    }
    // Upstream checks `tmp.Close()`'s error; the Rust close is a silent
    // drop, so an explicit sync is the equivalent delayed-write barrier.
    if let Err(err) = file.sync_all() {
        let _ = fs::remove_file(&path);
        return Err(err);
    }
    drop(file);
    let digest: [u8; 32] = hasher.finalize().into();
    Ok((path, digest == *expected))
}

/// `copyFileTo` — the `--stdout` release of already-verified bytes.
fn copy_file_to(path: &Path, writer: &mut dyn Write) -> std::io::Result<()> {
    let mut file = File::open(path)?;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            return Ok(());
        }
        writer.write_all(&buf[..read])?;
    }
}

/// `hex.DecodeString` for the 64-character lowercase checksum the
/// journal binds to — `ARTIFACT_BODY_INTEGRITY` on anything else.
fn decode_checksum(hex_text: &str) -> Option<[u8; 32]> {
    let bytes = hex_text.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, &[hi, lo]) in bytes.as_chunks::<2>().0.iter().enumerate() {
        out[index] = (hex_value(hi)? << 4) | hex_value(lo)?;
    }
    Some(out)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// The upstream `fail` switch for an `authorize_read` refusal: the
/// closed lineage codes map onto their exit classes, and any
/// unclassified failure is `ARTIFACT_READ_FAILED` — never a wider
/// authorization than the verdict can name.
fn emit_authorize_failure(
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    stdout_mode: bool,
    start: &Instant,
    code: &str,
) -> u8 {
    match code {
        REASON_SCOPE_DENIED | REASON_READ_UNRESOLVED => emit_fail(
            stdout,
            stderr,
            stdout_mode,
            start,
            EXIT_AUTHORITY_DENIED,
            code,
        ),
        REASON_NOT_FINALIZED | REASON_READ_AMBIGUOUS | REASON_BODY_INTEGRITY => {
            emit_fail(stdout, stderr, stdout_mode, start, EXIT_TERMINAL, code)
        }
        // A closed artifact-domain reason the switch does not name —
        // upstream's `default` arm (`ExitConfigInvalidCode`).
        _ if code.starts_with("ARTIFACT_")
            || code.starts_with("LINEAGE_")
            || code.starts_with("INVALID_") =>
        {
            emit_fail(
                stdout,
                stderr,
                stdout_mode,
                start,
                EXIT_CONFIG_INVALID,
                code,
            )
        }
        // Upstream `case ""` — the untyped-failure arm.
        _ => emit_fail(
            stdout,
            stderr,
            stdout_mode,
            start,
            EXIT_TERMINAL,
            REASON_READ_FAILED,
        ),
    }
}

/// `runArtifactRead`'s async half — authorization, the spool-verify,
/// release, and the journaled read edge. Generic over the lineage
/// store and object store so the unit tests drive the whole flow
/// against fakes; production passes the env-composed adapters.
async fn run_read<S, O>(
    store: &S,
    objects: &O,
    parsed: &ArtifactReadArgs,
    scope: ReadScope,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    start: &Instant,
) -> u8
where
    S: ReadStore + ReadEdgeStore,
    O: ObjectStore,
{
    let selector = match parsed.artifact_id {
        Some(id) => ReadSelector::ByArtifactId(id),
        None => ReadSelector::ByProduced {
            from_node_key: parsed.from_node_key.clone(),
            name: parsed.name.clone(),
        },
    };
    let auth = match authorize_read(Some(store), ReadRequest { scope, selector }).await {
        Ok(auth) => auth,
        Err(err) => {
            return emit_authorize_failure(stdout, stderr, parsed.stdout, start, err.code());
        }
    };

    if auth.artifact.ready_key.is_empty() || auth.artifact.checksum.is_empty() {
        // A ready artifact without a bound body or checksum cannot be
        // verified; refusing is the integrity-safe reading.
        return emit_fail(
            stdout,
            stderr,
            parsed.stdout,
            start,
            EXIT_TERMINAL,
            REASON_BODY_INTEGRITY,
        );
    }
    let Some(expected) = decode_checksum(&auth.artifact.checksum) else {
        return emit_fail(
            stdout,
            stderr,
            parsed.stdout,
            start,
            EXIT_TERMINAL,
            REASON_BODY_INTEGRITY,
        );
    };

    // Preflight the destination before the body fetch: a `--out` read
    // must be able to create its target file, or the command refuses
    // before ever touching the object store.
    if !parsed.stdout {
        let dir = out_dir(&parsed.out);
        match open_spool(&dir) {
            Ok((probe_path, probe)) => {
                drop(probe);
                let _ = fs::remove_file(probe_path);
            }
            Err(_) => {
                return emit_fail(
                    stdout,
                    stderr,
                    parsed.stdout,
                    start,
                    EXIT_TERMINAL,
                    REASON_OUTPUT_FAILED,
                );
            }
        }
    }

    let (mut body, _info) = match objects
        .read(ObjectRef {
            key: auth.artifact.ready_key.clone(),
        })
        .await
    {
        Ok(read) => read,
        // Metadata says ready but the body cannot be produced: the
        // same integrity refusal as a checksum mismatch — nothing is
        // released.
        Err(_) => {
            return emit_fail(
                stdout,
                stderr,
                parsed.stdout,
                start,
                EXIT_TERMINAL,
                REASON_BODY_INTEGRITY,
            );
        }
    };

    // The `--out` spool lives in the destination directory so the
    // release rename is same-filesystem atomic — a default-temp spool
    // would fail cross-device (tmpfs /tmp to the workspace filesystem).
    let spool_dir = if parsed.stdout {
        env::temp_dir()
    } else {
        out_dir(&parsed.out)
    };
    let (spool, verified) = match spool_verified_body(&spool_dir, &mut *body, &expected).await {
        Ok(result) => result,
        // A mid-stream failure leaves the delivered outcome unknown;
        // the journaled dedupe is what lets a retry resolve it cleanly.
        Err(_) => {
            return emit_fail(
                stdout,
                stderr,
                parsed.stdout,
                start,
                EXIT_TERMINAL,
                REASON_READ_AMBIGUOUS,
            );
        }
    };
    let _ = body.close().await;
    if !verified {
        let _ = fs::remove_file(&spool);
        return emit_fail(
            stdout,
            stderr,
            parsed.stdout,
            start,
            EXIT_TERMINAL,
            REASON_BODY_INTEGRITY,
        );
    }

    // Release verified bytes.
    let mut delivered_path = String::new();
    if parsed.stdout {
        if copy_file_to(&spool, &mut *stdout).is_err() {
            let _ = fs::remove_file(&spool);
            return emit_fail(
                stdout,
                stderr,
                parsed.stdout,
                start,
                EXIT_TERMINAL,
                REASON_READ_AMBIGUOUS,
            );
        }
        let _ = fs::remove_file(&spool);
    } else {
        if fs::rename(&spool, &parsed.out).is_err() {
            let _ = fs::remove_file(&spool);
            return emit_fail(
                stdout,
                stderr,
                parsed.stdout,
                start,
                EXIT_TERMINAL,
                REASON_OUTPUT_FAILED,
            );
        }
        delivered_path = parsed.out.clone();
    }

    // The read released bytes; journal the edge. A journal failure
    // after release is the ambiguous outcome — the attempt-scoped
    // dedupe is what makes the retry resolve rather than double-count.
    let edge = auth.edge(OffsetDateTime::now_utc());
    let edge = match record_read(Some(store), edge).await {
        Ok(edge) => edge,
        Err(_) => {
            return emit(
                stdout,
                stderr,
                parsed.stdout,
                start,
                EXIT_TERMINAL,
                REASON_READ_AMBIGUOUS,
                details_json(
                    &auth.artifact.id.to_string(),
                    &auth.artifact.run_id.to_string(),
                    false,
                    "",
                    &delivered_path,
                    parsed.stdout,
                    REASON_READ_AMBIGUOUS,
                ),
            );
        }
    };

    let mut reason = String::new();
    if !edge.declared && !matches!(scope, ReadScope::Operator) {
        // Declare-or-flag: authorized but outside the declared set —
        // journaled declared=false and flagged to the operator, never
        // silent.
        let _ = writeln!(
            stderr,
            "{REASON_READ_UNDECLARED}: read of artifact {} outside the node's declared artifact in-edges",
            auth.artifact.id
        );
        reason = REASON_READ_UNDECLARED.to_owned();
    }
    emit(
        stdout,
        stderr,
        parsed.stdout,
        start,
        EXIT_OK,
        "ok",
        details_json(
            &auth.artifact.id.to_string(),
            &edge.run_id.to_string(),
            edge.declared,
            &edge.checksum,
            &delivered_path,
            parsed.stdout,
            &reason,
        ),
    )
}

/// `filepath.Dir` — the directory the `--out` file lives in (empty is
/// the current directory, like `filepath.Dir("name") == "."`).
fn out_dir(path: &str) -> PathBuf {
    match Path::new(path).parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// The env-carried composition inputs (upstream
/// `artifactObjectStoreConfig` + the DSN) — `None` on any incomplete
/// piece, so the caller reports unavailable rather than authorizing
/// half of a read.
fn env_config() -> Option<(String, ObjectConfig)> {
    let dsn = env::var(ENV_ARTIFACT_READ_DSN).ok()?;
    let mut region = env::var(ENV_OBJECT_REGION).unwrap_or_default();
    if region.is_empty() {
        // Upstream defaults an unset region to us-east-1 (MinIO's
        // conventional answer) rather than treating it as unconfigured.
        region = "us-east-1".to_owned();
    }
    let config = ObjectConfig {
        endpoint: env::var(ENV_OBJECT_ENDPOINT).unwrap_or_default(),
        bucket: env::var(ENV_OBJECT_BUCKET).unwrap_or_default(),
        access_key_id: env::var(ENV_OBJECT_ACCESS).unwrap_or_default(),
        secret_access_key: env::var(ENV_OBJECT_SECRET).unwrap_or_default(),
        session_token: String::new(),
        region,
        use_tls: matches!(env::var(ENV_OBJECT_TLS).as_deref(), Ok("true") | Ok("1")),
    };
    if dsn.is_empty()
        || config.endpoint.is_empty()
        || config.bucket.is_empty()
        || config.access_key_id.is_empty()
        || config.secret_access_key.is_empty()
    {
        return None;
    }
    Some((dsn, config))
}

/// `newArtifactReadBackendFromEnv` — composes the real backend when
/// the environment carries the complete configuration, else `None`
/// (every partial config, failed connect, or store-construction
/// failure resolves to the same `ARTIFACT_READ_UNAVAILABLE`).
async fn compose_backend() -> Option<(LineageStore, S3ObjectStore)> {
    let (dsn, config) = env_config()?;
    let pool = PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(&dsn)
        .await
        .ok()?;
    let objects = S3ObjectStore::new(config).ok()?;
    Some((LineageStore::new(pool), objects))
}

/// `runArtifactRead` — resolves tokens, composes the backend, and runs
/// the read on a one-shot current-thread runtime. The envelope rides
/// stdout for every mode except `--stdout`, where the verified payload
/// owns it and the envelope moves to stderr — decided before parsing
/// so refusals keep the same byte-clean contract the success path
/// does.
pub(crate) fn artifact_read(
    tokens: &[String],
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let start = Instant::now();
    // `--stdout` reserves the stdout plane for verified payload bytes;
    // the envelope rides stderr — decided before parsing so refusals
    // keep the same byte-clean contract the success path does.
    let stdout_mode = tokens.iter().any(|token| token == "--stdout");

    // Composition first — a nil backend reports unavailable before the
    // grammar is even parsed (upstream's check order).
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return emit_fail(
            stdout,
            stderr,
            stdout_mode,
            &start,
            EXIT_TERMINAL,
            REASON_READ_FAILED,
        );
    };
    let Some((store, objects)) = runtime.block_on(compose_backend()) else {
        return emit_fail(
            stdout,
            stderr,
            stdout_mode,
            &start,
            EXIT_UNSUPPORTED,
            REASON_READ_UNAVAILABLE,
        );
    };

    let parsed = match parse_artifact_read_args(tokens) {
        Ok(parsed) => parsed,
        Err(()) => {
            return emit_fail(
                stdout,
                stderr,
                stdout_mode,
                &start,
                EXIT_CONFIG_INVALID,
                REASON_READ_UNRESOLVED,
            );
        }
    };
    let scope = match parse_attempt_scope(&env::var(ENV_ATTEMPT_SCOPE).unwrap_or_default()) {
        Ok(scope) => scope,
        // A malformed attempt credential fails closed: the safe reading
        // of an unparseable scope is denial, never a wider
        // authorization.
        Err(_) => {
            return emit_fail(
                stdout,
                stderr,
                stdout_mode,
                &start,
                EXIT_AUTHORITY_DENIED,
                REASON_SCOPE_DENIED,
            );
        }
    };

    runtime.block_on(run_read(
        &store, &objects, &parsed, scope, stdout, stderr, &start,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use central_artifact::domain::State;
    use central_artifact::lineage::{LineageArtifact, ReadEdge};
    use central_artifact::port::{
        ByteStream, ByteStreamFuture, ObjectInfo, UploadRequest, UploadResult,
    };
    use central_foundation::failure::Failure;
    use central_foundation::identity::{RunId, SessionAttemptId, WorkflowNodeId, WorkspaceId};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    /// An in-memory lineage store + read journal for the CLI tests.
    #[derive(Clone, Default)]
    struct FakeStore {
        artifacts: Arc<Mutex<HashMap<ArtifactId, LineageArtifact>>>,
        produced: Arc<Mutex<Vec<LineageArtifact>>>,
        declared: Arc<Mutex<Vec<ArtifactId>>>,
        in_run: Arc<Mutex<Vec<ArtifactId>>>,
        edges: Arc<Mutex<Vec<ReadEdge>>>,
        edge_err: Arc<Mutex<Option<Failure>>>,
    }

    impl ReadStore for FakeStore {
        async fn find_artifact(
            &self,
            artifact_id: ArtifactId,
        ) -> Result<Option<LineageArtifact>, Failure> {
            Ok(self
                .artifacts
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&artifact_id)
                .cloned())
        }
        async fn resolve_produced(
            &self,
            _run_id: Option<RunId>,
            node_key: &str,
            name: &str,
        ) -> Result<Vec<LineageArtifact>, Failure> {
            let _ = (node_key, name);
            Ok(self
                .produced
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone())
        }
        async fn declared_scope(
            &self,
            _node_id: WorkflowNodeId,
        ) -> Result<Vec<ArtifactId>, Failure> {
            Ok(self
                .declared
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone())
        }
        async fn run_produced_artifacts(&self, _run_id: RunId) -> Result<Vec<ArtifactId>, Failure> {
            Ok(self
                .in_run
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone())
        }
    }

    impl ReadEdgeStore for FakeStore {
        async fn insert_read_edge(&self, edge: ReadEdge) -> Result<ReadEdge, Failure> {
            if let Some(failure) = self
                .edge_err
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
            {
                return Err(failure);
            }
            self.edges
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(edge.clone());
            Ok(edge)
        }
    }

    struct VecStream {
        inner: std::io::Cursor<Vec<u8>>,
    }
    impl ByteStream for VecStream {
        fn read_chunk<'a>(
            &'a mut self,
            buf: &'a mut [u8],
        ) -> ByteStreamFuture<'a, Result<usize, Failure>> {
            Box::pin(async move {
                self.inner
                    .read(buf)
                    .map_err(|_| Failure::internal("fake_read", "read failed"))
            })
        }
        fn close<'a>(&'a mut self) -> ByteStreamFuture<'a, Result<(), Failure>> {
            Box::pin(async move { Ok(()) })
        }
    }

    /// An in-memory object store; only `read` is used by the CLI.
    #[derive(Clone, Default)]
    struct FakeObjects {
        bodies: Arc<Mutex<HashMap<String, Vec<u8>>>>,
        read_err: Arc<Mutex<bool>>,
    }
    impl ObjectStore for FakeObjects {
        async fn upload(&self, _request: UploadRequest) -> Result<UploadResult, Failure> {
            Err(Failure::internal("fake_unimplemented", "upload"))
        }
        async fn read(
            &self,
            reference: ObjectRef,
        ) -> Result<(Box<dyn ByteStream>, ObjectInfo), Failure> {
            if *self.read_err.lock().unwrap_or_else(|e| e.into_inner()) {
                return Err(Failure::internal("fake_read", "object read failed"));
            }
            let body = self
                .bodies
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&reference.key)
                .cloned()
                .ok_or_else(|| Failure::internal("fake_missing", "no such object"))?;
            Ok((
                Box::new(VecStream {
                    inner: std::io::Cursor::new(body.clone()),
                }),
                ObjectInfo {
                    size: body.len() as i64,
                    etag: String::new(),
                    version: String::new(),
                },
            ))
        }
        async fn promote_create_only(
            &self,
            _source: ObjectRef,
            _destination: ObjectRef,
        ) -> Result<ObjectInfo, Failure> {
            Err(Failure::internal("fake_unimplemented", "promote"))
        }
        async fn remove_staging(&self, _reference: ObjectRef) -> Result<(), Failure> {
            Err(Failure::internal("fake_unimplemented", "remove_staging"))
        }
        async fn remove_ready_for_delete(&self, _reference: ObjectRef) -> Result<(), Failure> {
            Err(Failure::internal("fake_unimplemented", "remove_ready"))
        }
    }

    fn tokens(argv: &[&str]) -> Vec<String> {
        argv.iter().map(|s| (*s).to_owned()).collect()
    }

    fn sha256_hex(body: &[u8]) -> String {
        Sha256::digest(body)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn ready_artifact(body: &[u8]) -> LineageArtifact {
        LineageArtifact {
            id: ArtifactId::new(),
            workspace_id: WorkspaceId::new(),
            run_id: RunId::new(),
            state: State::Ready,
            ready_key: "v1/ready/test".to_owned(),
            checksum: sha256_hex(body),
        }
    }

    #[test]
    fn parse_requires_a_selector() {
        assert!(parse_artifact_read_args(&tokens(&[])).is_err());
        assert!(parse_artifact_read_args(&tokens(&["--stdout"])).is_err());
    }

    #[test]
    fn parse_artifact_id_selector_and_default_out() {
        let id = ArtifactId::new().to_string();
        let parsed = parse_artifact_read_args(&tokens(&[id.as_str()])).unwrap();
        assert_eq!(
            parsed.artifact_id.map(|id| id.to_string()),
            Some(id.clone())
        );
        assert_eq!(parsed.out, id);
        assert!(!parsed.stdout);
    }

    #[test]
    fn parse_from_name_selector() {
        let parsed = parse_artifact_read_args(&tokens(&[
            "--from", "planner", "--name", "plan.md", "--stdout",
        ]))
        .unwrap();
        assert_eq!(parsed.from_node_key, "planner");
        assert_eq!(parsed.name, "plan.md");
        assert!(parsed.stdout);
    }

    #[test]
    fn parse_rejects_mutually_exclusive_selectors() {
        let id = ArtifactId::new().to_string();
        assert!(
            parse_artifact_read_args(&tokens(&[id.as_str(), "--from", "n", "--name", "x"]))
                .is_err()
        );
        assert!(parse_artifact_read_args(&tokens(&["--from", "n"])).is_err());
        assert!(parse_artifact_read_args(&tokens(&["--name", "x"])).is_err());
    }

    #[test]
    fn parse_rejects_unknown_flag_and_extra_positionals() {
        let id = ArtifactId::new().to_string();
        assert!(parse_artifact_read_args(&tokens(&[id.as_str(), "--bogus"])).is_err());
        assert!(
            parse_artifact_read_args(&tokens(&[
                id.as_str(),
                ArtifactId::new().to_string().as_str()
            ]))
            .is_err()
        );
        assert!(parse_artifact_read_args(&tokens(&["--stdout", "--out", "/tmp/x"])).is_err());
    }

    #[test]
    fn selector_accepts_version_agnostic_ids() {
        // A UUIDv4-shaped selector resolves — upstream `uuid.FromString`
        // is version-agnostic and the lineage model carries v4 ids.
        let v4 = "2d4f6a8b-1c3e-4a5b-8c7d-9e0f1a2b3c4d";
        assert!(parse_artifact_selector(v4).is_some());
        assert!(parse_artifact_selector("not-a-uuid").is_none());
        assert!(parse_artifact_selector("00000000-0000-0000-0000-000000000000").is_none());
        assert!(
            ArtifactId::parse(v4).is_err(),
            "the strict parser rejects v4"
        );
    }

    #[test]
    fn default_out_uses_name_basename() {
        let mut parsed = ArtifactReadArgs {
            name: "reports/plan.md".to_owned(),
            ..ArtifactReadArgs::default()
        };
        parsed.out = default_out(&parsed);
        assert_eq!(parsed.out, "plan.md");
    }

    /// Drives `run_read` with fakes, capturing stdout and stderr. With
    /// `--stdout` the stdout plane carries payload bytes and the
    /// envelope rides stderr (as the flag line can); otherwise the
    /// envelope is stdout.
    struct Capture {
        code: u8,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    }
    fn invoke_read<O: ObjectStore>(
        store: &FakeStore,
        objects: &O,
        parsed: &ArtifactReadArgs,
        scope: ReadScope,
    ) -> Capture {
        let start = Instant::now();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(run_read(
                store,
                objects,
                parsed,
                scope,
                &mut stdout,
                &mut stderr,
                &start,
            ));
        Capture {
            code,
            stdout,
            stderr,
        }
    }

    /// Finds the `central.local-result/v1` JSON line on either plane.
    fn envelope_json(capture: &Capture) -> serde_json::Value {
        for line in String::from_utf8_lossy(&capture.stdout)
            .lines()
            .chain(String::from_utf8_lossy(&capture.stderr).lines())
        {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(line)
                && value["schema_version"] == "central.local-result/v1"
            {
                return value;
            }
        }
        serde_json::Value::Null
    }

    #[test]
    fn read_to_stdout_streams_verified_bytes_and_journals_edge() {
        let body = b"# report\nall good\n".to_vec();
        let artifact = ready_artifact(&body);
        let store = FakeStore::default();
        store
            .artifacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(artifact.id, artifact.clone());
        let objects = FakeObjects::default();
        objects
            .bodies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert("v1/ready/test".to_owned(), body.clone());

        let parsed = ArtifactReadArgs {
            artifact_id: Some(artifact.id),
            stdout: true,
            ..ArtifactReadArgs::default()
        };
        let capture = invoke_read(&store, &objects, &parsed, ReadScope::Operator);
        assert_eq!(
            capture.code,
            0,
            "stderr: {}",
            String::from_utf8_lossy(&capture.stderr)
        );
        assert_eq!(capture.stdout, body);
        let envelope: serde_json::Value = envelope_json(&capture);
        assert_eq!(envelope["schema_version"], "central.local-result/v1");
        assert_eq!(envelope["command_id"], "artifact.read");
        assert_eq!(envelope["exit_code"], 0);
        assert_eq!(envelope["details"]["stdout"], true);
        assert_eq!(envelope["details"]["declared"], false);
        assert_eq!(envelope["details"]["checksum"], artifact.checksum);
        assert_eq!(envelope["details"]["artifact_id"], artifact.id.to_string());
        assert!(envelope["details"]["elapsed_ms"].is_number());
        // The operator read journals an undeclared edge under the
        // artifact's own run with the NULL reader pair.
        let edges = store.edges.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].artifact_id, artifact.id);
        assert_eq!(edges[0].reader_node_id, None);
        assert!(!edges[0].declared);
        // The operator path prints no undeclared flag line (upstream:
        // `!edge.Declared && !scope.Operator` — an operator has no
        // declared set to violate). stderr carries only the envelope.
        assert!(!String::from_utf8_lossy(&capture.stderr).contains("LINEAGE_READ_UNDECLARED"));
    }

    #[test]
    fn attempt_scope_undeclared_read_flags_and_journals() {
        let body = b"body".to_vec();
        let artifact = ready_artifact(&body);
        let store = FakeStore::default();
        store
            .artifacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(artifact.id, artifact.clone());
        // Attempt scope: the artifact is in-run (authorized) but NOT in
        // the declared set → journaled undeclared + flag line.
        store
            .in_run
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(artifact.id);
        let objects = FakeObjects::default();
        objects
            .bodies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert("v1/ready/test".to_owned(), body.clone());
        let scope = ReadScope::Attempt {
            run_id: artifact.run_id,
            node_id: WorkflowNodeId::new(),
            attempt_id: SessionAttemptId::new(),
        };

        let parsed = ArtifactReadArgs {
            artifact_id: Some(artifact.id),
            stdout: true,
            ..ArtifactReadArgs::default()
        };
        let capture = invoke_read(&store, &objects, &parsed, scope);
        assert_eq!(capture.code, 0);
        assert_eq!(capture.stdout, body);
        let flag = String::from_utf8_lossy(&capture.stderr);
        assert!(flag.contains("LINEAGE_READ_UNDECLARED"), "stderr: {flag}");
        let envelope: serde_json::Value = envelope_json(&capture);
        assert_eq!(envelope["details"]["reason"], "LINEAGE_READ_UNDECLARED");
        assert_eq!(envelope["details"]["declared"], false);
        let edges = store.edges.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(edges.len(), 1);
        assert!(!edges[0].declared);
    }

    #[test]
    fn not_finalized_refuses_at_exit_6() {
        let mut artifact = ready_artifact(b"body");
        artifact.state = State::Verifying;
        let store = FakeStore::default();
        store
            .artifacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(artifact.id, artifact.clone());
        let parsed = ArtifactReadArgs {
            artifact_id: Some(artifact.id),
            stdout: true,
            ..ArtifactReadArgs::default()
        };
        let capture = invoke_read(
            &store,
            &FakeObjects::default(),
            &parsed,
            ReadScope::Operator,
        );
        assert_eq!(capture.code, 6);
        assert!(
            capture.stdout.is_empty(),
            "unverified bytes must never land"
        );
        let envelope: serde_json::Value = envelope_json(&capture);
        assert_eq!(envelope["details"]["reason"], "ARTIFACT_NOT_FINALIZED");
    }

    #[test]
    fn corrupt_body_refuses_and_journals_nothing() {
        let artifact = ready_artifact(b"real body");
        let store = FakeStore::default();
        store
            .artifacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(artifact.id, artifact.clone());
        let objects = FakeObjects::default();
        objects
            .bodies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert("v1/ready/test".to_owned(), b"tampered".to_vec());
        let parsed = ArtifactReadArgs {
            artifact_id: Some(artifact.id),
            stdout: true,
            ..ArtifactReadArgs::default()
        };
        let capture = invoke_read(&store, &objects, &parsed, ReadScope::Operator);
        assert_eq!(capture.code, 6);
        assert!(capture.stdout.is_empty());
        let envelope: serde_json::Value = envelope_json(&capture);
        assert_eq!(envelope["details"]["reason"], "ARTIFACT_BODY_INTEGRITY");
        assert!(
            store
                .edges
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty()
        );
    }

    #[test]
    fn scope_denied_at_exit_7() {
        let artifact = ready_artifact(b"body");
        let store = FakeStore::default();
        store
            .artifacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(artifact.id, artifact.clone());
        // Attempt scope with EMPTY declared + in-run sets → denied.
        let scope = ReadScope::Attempt {
            run_id: RunId::new(),
            node_id: WorkflowNodeId::new(),
            attempt_id: SessionAttemptId::new(),
        };
        let parsed = ArtifactReadArgs {
            artifact_id: Some(artifact.id),
            stdout: true,
            ..ArtifactReadArgs::default()
        };
        let capture = invoke_read(&store, &FakeObjects::default(), &parsed, scope);
        assert_eq!(capture.code, 7);
        let envelope: serde_json::Value = envelope_json(&capture);
        assert_eq!(envelope["details"]["reason"], "ARTIFACT_SCOPE_DENIED");
    }

    #[test]
    fn journal_failure_after_release_is_ambiguous() {
        let body = b"body".to_vec();
        let artifact = ready_artifact(&body);
        let store = FakeStore::default();
        store
            .artifacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(artifact.id, artifact.clone());
        *store.edge_err.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(Failure::internal("fake_journal", "journal failed"));
        let objects = FakeObjects::default();
        objects
            .bodies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert("v1/ready/test".to_owned(), body.clone());
        let parsed = ArtifactReadArgs {
            artifact_id: Some(artifact.id),
            stdout: true,
            ..ArtifactReadArgs::default()
        };
        let capture = invoke_read(&store, &objects, &parsed, ReadScope::Operator);
        assert_eq!(capture.code, 6);
        // The bytes DID release before the journal failure — the
        // ambiguous outcome reports the delivered path, not a refusal.
        assert_eq!(capture.stdout, body);
        let envelope: serde_json::Value = envelope_json(&capture);
        assert_eq!(envelope["details"]["reason"], "ARTIFACT_READ_AMBIGUOUS");
        assert_eq!(envelope["details"]["artifact_id"], artifact.id.to_string());
    }

    /// A private scratch directory per test (the spool must share the
    /// destination filesystem for the release rename to be atomic).
    fn scratch_dir(tag: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!(
            "central-artifact-read-test-{}-{tag}",
            process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn read_to_out_renames_verified_spool_and_reports_path() {
        let body = b"materialized artifact body\n".to_vec();
        let artifact = ready_artifact(&body);
        let store = FakeStore::default();
        store
            .artifacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(artifact.id, artifact.clone());
        let objects = FakeObjects::default();
        objects
            .bodies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert("v1/ready/test".to_owned(), body.clone());
        let dir = scratch_dir("out");
        let out = dir.join("report.md");
        let parsed = ArtifactReadArgs {
            artifact_id: Some(artifact.id),
            out: out.to_string_lossy().into_owned(),
            ..ArtifactReadArgs::default()
        };

        let capture = invoke_read(&store, &objects, &parsed, ReadScope::Operator);
        assert_eq!(
            capture.code,
            0,
            "stderr: {}",
            String::from_utf8_lossy(&capture.stderr)
        );
        // The release is a rename, not a stream: stdout stays byte-clean
        // for the envelope only.
        assert_eq!(fs::read(&out).unwrap(), body);
        let envelope = envelope_json(&capture);
        assert_eq!(envelope["exit_code"], 0);
        assert_eq!(
            envelope["details"]["path"],
            out.to_string_lossy().into_owned()
        );
        assert!(envelope["details"].get("stdout").is_none());
        assert_eq!(envelope["details"]["checksum"], artifact.checksum);
        // No leftover spool siblings in the destination directory.
        let leftovers = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".central-artifact-read-")
            })
            .count();
        assert_eq!(leftovers, 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn body_open_failure_is_integrity_refusal() {
        // Metadata says ready but the object store cannot produce the
        // body — upstream reads this as the same refusal as a checksum
        // mismatch, before any spool exists.
        let artifact = ready_artifact(b"body");
        let store = FakeStore::default();
        store
            .artifacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(artifact.id, artifact.clone());
        let objects = FakeObjects::default();
        *objects.read_err.lock().unwrap_or_else(|e| e.into_inner()) = true;
        let parsed = ArtifactReadArgs {
            artifact_id: Some(artifact.id),
            stdout: true,
            ..ArtifactReadArgs::default()
        };
        let capture = invoke_read(&store, &objects, &parsed, ReadScope::Operator);
        assert_eq!(capture.code, 6);
        assert!(capture.stdout.is_empty());
        let envelope = envelope_json(&capture);
        assert_eq!(envelope["details"]["reason"], "ARTIFACT_BODY_INTEGRITY");
        assert!(
            store
                .edges
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty()
        );
    }

    /// A stream that yields one chunk then fails mid-body.
    struct FailingStream {
        first: Vec<u8>,
        served: bool,
    }
    impl ByteStream for FailingStream {
        fn read_chunk<'a>(
            &'a mut self,
            buf: &'a mut [u8],
        ) -> ByteStreamFuture<'a, Result<usize, Failure>> {
            Box::pin(async move {
                if self.served {
                    return Err(Failure::internal("fake_midstream", "stream truncated"));
                }
                self.served = true;
                let n = self.first.len().min(buf.len());
                buf[..n].copy_from_slice(&self.first[..n]);
                Ok(n)
            })
        }
        fn close<'a>(&'a mut self) -> ByteStreamFuture<'a, Result<(), Failure>> {
            Box::pin(async move { Ok(()) })
        }
    }

    /// A store whose `read` succeeds but whose stream dies mid-body.
    #[derive(Clone, Default)]
    struct TruncatedObjects;
    impl ObjectStore for TruncatedObjects {
        async fn upload(&self, _request: UploadRequest) -> Result<UploadResult, Failure> {
            Err(Failure::internal("fake_unimplemented", "upload"))
        }
        async fn read(
            &self,
            _reference: ObjectRef,
        ) -> Result<(Box<dyn ByteStream>, ObjectInfo), Failure> {
            Ok((
                Box::new(FailingStream {
                    first: b"partial".to_vec(),
                    served: false,
                }),
                ObjectInfo {
                    size: 7,
                    etag: String::new(),
                    version: String::new(),
                },
            ))
        }
        async fn promote_create_only(
            &self,
            _source: ObjectRef,
            _destination: ObjectRef,
        ) -> Result<ObjectInfo, Failure> {
            Err(Failure::internal("fake_unimplemented", "promote"))
        }
        async fn remove_staging(&self, _reference: ObjectRef) -> Result<(), Failure> {
            Err(Failure::internal("fake_unimplemented", "remove_staging"))
        }
        async fn remove_ready_for_delete(&self, _reference: ObjectRef) -> Result<(), Failure> {
            Err(Failure::internal("fake_unimplemented", "remove_ready"))
        }
    }

    #[test]
    fn mid_stream_failure_is_ambiguous_and_releases_nothing() {
        let artifact = ready_artifact(b"full body contents");
        let store = FakeStore::default();
        store
            .artifacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(artifact.id, artifact.clone());

        let parsed = ArtifactReadArgs {
            artifact_id: Some(artifact.id),
            stdout: true,
            ..ArtifactReadArgs::default()
        };
        let capture = invoke_read(&store, &TruncatedObjects, &parsed, ReadScope::Operator);
        assert_eq!(capture.code, 6);
        // The delivered outcome is unknown — but the unverified prefix
        // must never reach stdout.
        assert!(capture.stdout.is_empty());
        let envelope = envelope_json(&capture);
        assert_eq!(envelope["details"]["reason"], "ARTIFACT_READ_AMBIGUOUS");
        assert!(
            store
                .edges
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty()
        );
    }

    #[test]
    fn out_preflight_failure_refuses_before_body_fetch() {
        let artifact = ready_artifact(b"body");
        let store = FakeStore::default();
        store
            .artifacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(artifact.id, artifact.clone());
        let objects = FakeObjects::default();
        let parsed = ArtifactReadArgs {
            artifact_id: Some(artifact.id),
            out: "/nonexistent-dir-9f3a/report.md".to_owned(),
            ..ArtifactReadArgs::default()
        };
        let capture = invoke_read(&store, &objects, &parsed, ReadScope::Operator);
        assert_eq!(capture.code, 6);
        let envelope = envelope_json(&capture);
        assert_eq!(envelope["details"]["reason"], "ARTIFACT_READ_OUTPUT_FAILED");
        assert!(
            store
                .edges
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty()
        );
    }

    #[test]
    fn produced_selector_resolves_through_the_store() {
        let body = b"plan contents".to_vec();
        let artifact = ready_artifact(&body);
        let store = FakeStore::default();
        store
            .produced
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(artifact.clone());
        store
            .artifacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(artifact.id, artifact.clone());
        let objects = FakeObjects::default();
        objects
            .bodies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert("v1/ready/test".to_owned(), body.clone());
        let parsed = ArtifactReadArgs {
            from_node_key: "planner".to_owned(),
            name: "plan.md".to_owned(),
            stdout: true,
            ..ArtifactReadArgs::default()
        };
        let capture = invoke_read(&store, &objects, &parsed, ReadScope::Operator);
        assert_eq!(capture.code, 0);
        assert_eq!(capture.stdout, body);
        let envelope = envelope_json(&capture);
        assert_eq!(envelope["details"]["artifact_id"], artifact.id.to_string());
    }
}
