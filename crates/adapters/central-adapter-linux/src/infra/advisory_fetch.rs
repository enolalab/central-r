//! `advisory_fetch` — the B01 advisory consumer's Linux boundary
//! (upstream `internal/adapter/advisory/{source,active_bundle_linux,
//! host_facts,host_facts_errors,time_witness_linux,install,
//! transition_recorder}.go` plus the `broker` package's
//! `advisory_evaluation_client.go`).
//!
//! Every read runs the same hardened-open discipline upstream's
//! `openat2FS` applies: a trusted parent chain (root-owned, not
//! group/world-writable), `RESOLVE_BENEATH|NO_SYMLINKS|NO_MAGICLINKS`,
//! a regular file owned by root with mode `0400` or `0600`, and an
//! open-reopen `st_dev`/`st_ino` check so a swapped path can never
//! satisfy the digest gate with different bytes. Writes are
//! tmp-file-then-`link`/`rename` with `fsync` before and after, the
//! same atomicity shape `devbootstrap` established.
//!
//! No `unsafe` anywhere in this module — `rustix` safe wrappers only,
//! per the crate's two-audited-sites rule (rust-engineering-workflow
//! §5.2).

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use central_foundation::failure::Failure;
use central_infra::advisory::{
    self, HostFacts, Outcome, Receipt, Snapshot, State, TimeWitness, VerifiedBundle,
};
use central_infra::authority::{
    AdvisoryAdmissionEvidence, AdvisoryHostFacts, AuthorityTransitionPayload, CommittedReceipt,
};
use central_infra::port;
use rustix::fs::{Gid, Mode, OFlags, ResolveFlags, Uid};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;

fn internal(code: &'static str, msg: impl Into<String>) -> Failure {
    Failure::internal(code, msg.into())
}

fn denied(code: &'static str, msg: impl Into<String>) -> Failure {
    Failure::denied(code, msg.into())
}

/// The one source-load failure code upstream wraps around every
/// hardened-read refusal (`advisory.ErrSourceUnavailable`): the
/// evaluation service maps any `load_active` error to
/// `Denied`/`ADVISORY_SOURCE_UNAVAILABLE`, so the detail lives in the
/// message, not the code.
const SRC: &str = advisory::ERR_SOURCE_UNAVAILABLE;

fn source_unavailable(msg: impl Into<String>) -> Failure {
    internal(SRC, format!("active bundle: {}", msg.into()))
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

// ---------------------------------------------------------------------------
// bundleFS seam — source.go's `bundleFS` / active_bundle_linux.go's
// `openat2FS`
// ---------------------------------------------------------------------------

/// `bundleFS` — the file-open seam `LoadActive` reads through. The
/// production implementation is [`Openat2Fs`]; tests inject a plain
/// tempdir FS (upstream `fixtureFS`) so the hardened-open contract is
/// exercised without requiring root ownership.
pub trait BundleFs: Send + Sync {
    /// `fs.Open(name)` — `name` is a `/`-separated path relative to the
    /// store root.
    fn open(&self, name: &str) -> Result<File, Failure>;
}

/// `openat2FS` — the production store filesystem: `openat2`-confined
/// opens beneath a root descriptor, trusted-parent-chain and
/// root-owned/strict-mode assertions exactly as upstream's
/// `active_bundle_linux.go`.
pub struct Openat2Fs {
    root_fd: OwnedFd,
    root_path: PathBuf,
}

/// Upstream's `OpenHow.Resolve` set — deliberately *without*
/// `RESOLVE_NO_XDEV` (the sandbox launcher's set adds that flag; the
/// state root may legitimately span mounts).
const ADVISORY_RESOLVE: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);

impl Openat2Fs {
    /// `newOpenat2FS` — `O_RDONLY|O_DIRECTORY|O_CLOEXEC` on the root.
    ///
    /// # Errors
    /// `internal` when the root cannot be opened as a directory.
    pub fn new(root_path: impl AsRef<Path>) -> Result<Self, Failure> {
        let root_path = root_path.as_ref().to_path_buf();
        let root_fd = rustix::fs::open(
            &root_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| {
            internal(
                "advisory_open_root",
                format!("advisory adapter: open root: {e}"),
            )
        })?;
        Ok(Self { root_fd, root_path })
    }

    /// `verifyTrustedParentChain` — every directory component above the
    /// final path element must be root-owned and free of group/world
    /// write bits.
    fn verify_trusted_parent_chain(&self, rel_path: &str) -> Result<(), Failure> {
        let parts: Vec<&str> = rel_path.split('/').filter(|p| !p.is_empty()).collect();
        for i in 0..parts.len().saturating_sub(1) {
            let dir = self.root_path.join(parts[..=i].iter().collect::<PathBuf>());
            let stat = rustix::fs::stat(&dir).map_err(|e| {
                internal(
                    "advisory_stat_parent",
                    format!("advisory adapter: stat {}: {e}", dir.display()),
                )
            })?;
            if stat.st_uid != 0 {
                return Err(denied(
                    "advisory_parent_owner",
                    format!("advisory adapter: {} not owned by root", dir.display()),
                ));
            }
            if stat.st_mode & 0o022 != 0 {
                return Err(denied(
                    "advisory_parent_mode",
                    format!(
                        "advisory adapter: {} has group/world write bits: {:o}",
                        dir.display(),
                        stat.st_mode & 0o777
                    ),
                ));
            }
        }
        Ok(())
    }
}

impl BundleFs for Openat2Fs {
    /// `openat2FS.Open` — containment resolve, then `fstat`:
    /// root-owned, permission bits exactly `0400` or `0600`.
    fn open(&self, name: &str) -> Result<File, Failure> {
        self.verify_trusted_parent_chain(name)?;
        let fd = rustix::fs::openat2(
            &self.root_fd,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
            ADVISORY_RESOLVE,
        )
        .map_err(|e| {
            internal(
                "advisory_open",
                format!("advisory adapter: open {name}: {e}"),
            )
        })?;
        let stat = rustix::fs::fstat(&fd).map_err(|e| {
            internal(
                "advisory_fstat",
                format!("advisory adapter: fstat {name}: {e}"),
            )
        })?;
        if stat.st_uid != 0 {
            return Err(denied(
                "advisory_file_owner",
                format!("advisory adapter: {name} not owned by root"),
            ));
        }
        let perm = stat.st_mode & 0o777;
        if perm != 0o400 && perm != 0o600 {
            return Err(denied(
                "advisory_file_mode",
                format!("advisory adapter: {name} has insecure file mode {perm:o}"),
            ));
        }
        Ok(File::from(fd))
    }
}

/// `os.SameFile` — dev+inode equality.
fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino()
}

/// `readAndVerifyFile` — hardened open, regular-file check, bounded
/// read, reopen + same-inode proof against a mid-read swap.
fn read_and_verify_file<F: BundleFs>(
    fs: &F,
    name: &str,
    max_size: u64,
) -> Result<Vec<u8>, Failure> {
    let f = fs
        .open(name)
        .map_err(|e| source_unavailable(format!("{e}")))?;
    let fi1 = f
        .metadata()
        .map_err(|e| source_unavailable(format!("{e}")))?;
    if !fi1.is_file() {
        return Err(source_unavailable(format!("{name} is not a regular file")));
    }
    let mut data = Vec::new();
    f.take(max_size)
        .read_to_end(&mut data)
        .map_err(|e| source_unavailable(format!("{e}")))?;
    let f2 = fs
        .open(name)
        .map_err(|e| source_unavailable(format!("{e}")))?;
    let fi2 = f2
        .metadata()
        .map_err(|e| source_unavailable(format!("{e}")))?;
    if !same_file(&fi1, &fi2) {
        return Err(source_unavailable(format!("{name} changed while read")));
    }
    Ok(data)
}

// ---------------------------------------------------------------------------
// ActiveBundleSource — source.go
// ---------------------------------------------------------------------------

const MAX_SELECTOR_SIZE: u64 = 64 * 1024;
const MAX_ENVELOPE_SIZE: u64 = 1 << 20;
const ACTIVE_JSON: &str = "advisories/active.json";

/// `activeSelector` — `advisories/active.json`'s shape.
#[derive(Debug, serde::Deserialize)]
struct ActiveSelector {
    schema_version: String,
    purpose: String,
    binding_id: String,
    generation_id: String,
    generation_sha256: String,
}

/// `selectorEnvelope` — the `{bundle, signature}` outer layer.
#[derive(Debug, serde::Deserialize)]
struct SelectorEnvelope {
    bundle: serde_json::Value,
    signature: String,
}

/// `ActiveBundleSource` — loads the installed snapshot from the
/// production state root through [`Openat2Fs`].
pub struct ActiveBundleSource<F: BundleFs = Openat2Fs> {
    fs: F,
    binding_id: String,
}

impl ActiveBundleSource<Openat2Fs> {
    /// `NewActiveBundleSource`.
    ///
    /// # Errors
    /// `internal` when the state root cannot be opened.
    pub fn new(
        root_path: impl AsRef<Path>,
        binding_id: impl Into<String>,
    ) -> Result<Self, Failure> {
        Ok(Self {
            fs: Openat2Fs::new(root_path)?,
            binding_id: binding_id.into(),
        })
    }
}

impl<F: BundleFs + 'static> port::ActiveBundleSource for ActiveBundleSource<F> {
    async fn load_active(&self) -> Result<Snapshot, Failure> {
        load_active_snapshot(&self.fs, &self.binding_id)
    }
}

/// `loadActiveSnapshot`.
fn load_active_snapshot<F: BundleFs>(fs: &F, binding_id: &str) -> Result<Snapshot, Failure> {
    let selector_raw = read_and_verify_file(fs, ACTIVE_JSON, MAX_SELECTOR_SIZE)?;
    let sel: ActiveSelector =
        serde_json::from_slice(&selector_raw).map_err(|e| source_unavailable(format!("{e}")))?;
    validate_selector(&sel, binding_id)?;

    let env_path = format!("advisories/generations/{}/envelope.json", sel.generation_id);
    let env_raw = read_and_verify_file(fs, &env_path, MAX_ENVELOPE_SIZE + 1)?;
    if env_raw.len() as u64 > MAX_ENVELOPE_SIZE {
        return Err(source_unavailable("envelope exceeds size limit"));
    }

    let digest = hex_lower(&Sha256::digest(&env_raw));
    if digest != sel.generation_sha256 {
        return Err(source_unavailable("generation digest mismatch"));
    }
    advisory::strict_decode(&env_raw)
        .map_err(|e| source_unavailable(format!("strict decode: {e:?}")))?;

    let env: SelectorEnvelope =
        serde_json::from_slice(&env_raw).map_err(|e| source_unavailable(format!("{e}")))?;
    if env.signature.is_empty() {
        return Err(source_unavailable("missing signature"));
    }
    if env.bundle.is_null() {
        return Err(source_unavailable("missing bundle"));
    }

    // `Bundle` carries the *whole* envelope bytes — the domain's
    // `verify_snapshot` unwraps its own `{bundle, signature}` layer
    // (upstream source.go's documented round-trip contract).
    Ok(Snapshot {
        generation_id: sel.generation_id,
        selector_digest: digest,
        bundle: env_raw,
        signature: env.signature.into_bytes(),
    })
}

/// `validateSelector`.
fn validate_selector(sel: &ActiveSelector, binding_id: &str) -> Result<(), Failure> {
    if sel.schema_version != "central.advisory-selector/v1" {
        return Err(source_unavailable("selector schema mismatch"));
    }
    if sel.purpose != "release_security_advisory" {
        return Err(source_unavailable("selector purpose mismatch"));
    }
    if sel.binding_id != binding_id {
        return Err(source_unavailable("selector binding mismatch"));
    }
    if sel.generation_id.is_empty() {
        return Err(source_unavailable("selector generation missing"));
    }
    if sel.generation_sha256.is_empty() {
        return Err(source_unavailable("selector digest missing"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// HostFactsCollector — host_facts.go / host_facts_errors.go
// ---------------------------------------------------------------------------

const HOST_FACTS_COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
const HOST_FACTS_MAX_OUTPUT: usize = 16 * 1024;

/// `host_facts_errors.go` — the classified fact-collection failures.
/// Individual facts are best-effort: every one of these produces an
/// empty field, never a `Collect` failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactError {
    /// `ErrFactAbsent` — the command/file does not exist (and the
    /// deadline-exceeded case upstream folds into `ErrFactAbsent`).
    Absent,
    /// `ErrFactInaccessible` — no permission to execute/read.
    Inaccessible,
    /// `ErrFactMalformed` — output malformed or unexpected.
    Malformed,
    /// `ErrFactAmbiguous` — ambiguous output.
    Ambiguous,
    /// `ErrFactOverLimit` — output exceeded the 16 KiB bound.
    OverLimit,
}

impl FactError {
    /// The message fragment upstream's `runCommand`/`readFile`
    /// surface; kept for diagnostics only — collection itself never
    /// fails on any of these.
    #[cfg(test)]
    fn describe(self) -> &'static str {
        match self {
            Self::Absent => "command/file absent",
            Self::Inaccessible => "no permission to execute/read",
            Self::Malformed => "output malformed or unexpected",
            Self::Ambiguous => "ambiguous output",
            Self::OverLimit => "output exceeds 16 KiB limit",
        }
    }
}

/// `commandRunner` — the exec seam.
pub trait AdvisoryCommandRunner: Send + Sync {
    /// `Run` — execute `name args...` with an empty environment,
    /// bounded combined stdout+stderr, killed once `deadline` passes.
    /// `deadline` is the single budget `Collect` shares across every
    /// command (upstream's one `context.WithTimeout` per `Collect`):
    /// each call gets what remains, never a fresh timeout.
    fn run(&self, deadline: Instant, name: &str, args: &[&str]) -> Result<Vec<u8>, FactError>;
}

/// `realCommandRunner` — `exec.CommandContext` equivalent: empty env,
/// both streams merged into one bounded buffer, killed at the
/// deadline (upstream `context.WithTimeout` semantics).
pub struct RealCommandRunner;

impl RealCommandRunner {
    /// Constructs the production runner.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for RealCommandRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl AdvisoryCommandRunner for RealCommandRunner {
    fn run(&self, deadline: Instant, name: &str, args: &[&str]) -> Result<Vec<u8>, FactError> {
        let mut child = Command::new(name)
            .args(args)
            .env_clear()
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => FactError::Absent,
                std::io::ErrorKind::PermissionDenied => FactError::Inaccessible,
                _ => FactError::Malformed,
            })?;

        // Drain both pipes concurrently like Go's exec does, into one
        // combined bounded buffer; overflow discards but keeps
        // draining so the child can never stall on a full pipe.
        let total = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        let streams: Vec<Box<dyn Read + Send>> = [
            child
                .stdout
                .take()
                .map(|s| Box::new(s) as Box<dyn Read + Send>),
            child
                .stderr
                .take()
                .map(|s| Box::new(s) as Box<dyn Read + Send>),
        ]
        .into_iter()
        .flatten()
        .collect();
        for stream in streams {
            let total = Arc::clone(&total);
            handles.push(thread::spawn(move || {
                let mut kept = Vec::new();
                let mut chunk = [0u8; 4096];
                let mut reader = stream;
                loop {
                    match reader.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let used = total.fetch_add(n, Ordering::SeqCst);
                            if used < HOST_FACTS_MAX_OUTPUT {
                                let room = HOST_FACTS_MAX_OUTPUT - used;
                                kept.extend_from_slice(&chunk[..n.min(room)]);
                            }
                        }
                    }
                }
                kept
            }));
        }

        let outcome = loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    if status.success() {
                        break Ok(());
                    }
                    // Non-zero exit: not exec/permission/deadline
                    // upstream — a raw error the caller maps to an
                    // empty fact.
                    break Err(FactError::Malformed);
                }
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        break Err(FactError::Absent);
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break Err(FactError::Malformed),
            }
        };

        let mut combined = Vec::new();
        let mut overflow = false;
        for h in handles {
            let kept = h.join().unwrap_or_default();
            if combined.len() + kept.len() > HOST_FACTS_MAX_OUTPUT {
                overflow = true;
            }
            combined.extend_from_slice(&kept);
        }
        if total.load(Ordering::SeqCst) > HOST_FACTS_MAX_OUTPUT {
            overflow = true;
        }
        if overflow {
            return Err(FactError::OverLimit);
        }
        outcome.map(|()| combined)
    }
}

/// `HostFactsCollector` — the `/etc/os-release` + `/proc` + tool
/// version collector. File paths are struct fields so tests can read
/// fixtures instead of the production host's files (upstream reads the
/// host's real files unconditionally).
pub struct HostFactsCollector<R: AdvisoryCommandRunner = RealCommandRunner> {
    runner: R,
    os_release_path: PathBuf,
    kernel_release_path: PathBuf,
}

impl HostFactsCollector<RealCommandRunner> {
    /// `NewHostFactsCollector`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            runner: RealCommandRunner::new(),
            os_release_path: PathBuf::from("/etc/os-release"),
            kernel_release_path: PathBuf::from("/proc/sys/kernel/osrelease"),
        }
    }
}

impl Default for HostFactsCollector<RealCommandRunner> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: AdvisoryCommandRunner> HostFactsCollector<R> {
    fn read_fact_file(&self, path: &Path) -> Result<String, FactError> {
        fs::read_to_string(path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => FactError::Absent,
            std::io::ErrorKind::PermissionDenied => FactError::Inaccessible,
            _ => FactError::Malformed,
        })
    }

    fn run_command(
        &self,
        deadline: Instant,
        name: &str,
        args: &[&str],
    ) -> Result<String, FactError> {
        self.runner
            .run(deadline, name, args)
            .map(|out| String::from_utf8_lossy(&out).trim().to_owned())
    }

    fn collect_facts(&self) -> HostFacts {
        // `ctx, cancel := context.WithTimeout(ctx, 5s)` upstream: ONE
        // deadline for the whole collection — the file reads are not
        // ctx-bound but do consume wall-clock budget, and each command
        // runs under what remains rather than a fresh 5 s.
        let deadline = Instant::now() + HOST_FACTS_COMMAND_TIMEOUT;
        let mut facts = HostFacts::default();
        if let Ok(content) = self.read_fact_file(&self.os_release_path)
            && let Ok(ver) = parse_os_release(&content)
        {
            facts.os_release = normalize_version(&ver, "os-release");
        }
        if let Ok(content) = self.read_fact_file(&self.kernel_release_path) {
            facts.kernel = normalize_version(&content, "kernel");
        }
        if let Ok(ver) = self.run_command(
            deadline,
            "/usr/bin/docker",
            &["version", "--format", "{{.Client.Version}}"],
        ) && !ver.is_empty()
        {
            facts.docker = normalize_version(&ver, "docker");
        }
        if let Ok(ver) = self.run_command(
            deadline,
            "/usr/bin/docker",
            &["compose", "version", "--short"],
        ) && !ver.is_empty()
        {
            facts.compose = normalize_version(&ver, "compose");
        }
        if let Ok(ver) = self.run_command(deadline, "/usr/bin/psql", &["--version"])
            && !ver.is_empty()
        {
            facts.psql = normalize_version(&ver, "psql");
        }
        facts
    }
}

impl<R: AdvisoryCommandRunner + 'static> port::HostFactsCollector for HostFactsCollector<R> {
    /// `Collect` — upstream never fails collection: every per-fact
    /// error maps to an empty field.
    async fn collect(&self) -> Result<HostFacts, Failure> {
        Ok(self.collect_facts())
    }
}

/// `parseOSRelease` — first `VERSION_ID=` line, quote-trimmed.
fn parse_os_release(content: &str) -> Result<String, FactError> {
    for line in content.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("VERSION_ID=") {
            return Ok(v.trim_matches('"').to_owned());
        }
    }
    Err(FactError::Malformed)
}

/// `normalizeVersion` — trim, first line only, tool-specific prefixes.
fn normalize_version(raw: &str, tool: &str) -> String {
    let mut raw = raw.trim();
    if let Some(idx) = raw.find('\n') {
        raw = &raw[..idx];
    }
    let raw = match tool {
        "docker" => raw.strip_prefix("Docker version ").unwrap_or(raw),
        "compose" => {
            let r = raw.strip_prefix("Docker Compose version ").unwrap_or(raw);
            r.strip_prefix('v').unwrap_or(r)
        }
        "psql" => raw.strip_prefix("psql (PostgreSQL) ").unwrap_or(raw),
        _ => raw,
    };
    raw.trim().to_owned()
}

// ---------------------------------------------------------------------------
// TimeWitnessStore — time_witness_linux.go
// ---------------------------------------------------------------------------

const TIME_WITNESS_SCHEMA: &str = "central.advisory-time-witness/v1";
const TIME_WITNESS_REL_PATH: &str = "advisories/time-witness.json";
const TIME_WITNESS_FILE_NAME: &str = "time-witness.json";
const MAX_TIME_WITNESS_FILE_SIZE: u64 = 4 * 1024;

/// `timeWitnessFile` — the persisted witness record.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct TimeWitnessFile {
    schema_version: String,
    last_accepted_at: String,
    last_issued_at: String,
}

/// `TimeWitnessStore` — the root-owned witness file beside
/// `advisories/`, with the same hardened-open discipline as the active
/// bundle.
pub struct TimeWitnessStore<F: BundleFs = Openat2Fs> {
    fs: F,
    root_path: PathBuf,
    uid: u32,
    gid: u32,
}

impl TimeWitnessStore<Openat2Fs> {
    /// `NewTimeWitnessStore` — production: root-owned writes (`0:0`).
    ///
    /// # Errors
    /// `internal` when the state root cannot be opened.
    pub fn new(root_path: impl AsRef<Path>) -> Result<Self, Failure> {
        let root_path = root_path.as_ref().to_path_buf();
        Ok(Self {
            fs: Openat2Fs::new(&root_path)?,
            root_path,
            uid: 0,
            gid: 0,
        })
    }
}

impl<F: BundleFs> TimeWitnessStore<F> {
    /// The test seam: an injected FS plus the caller's own uid/gid for
    /// the atomic-write ownership step (non-root test runs use the
    /// effective ids, which `chown` accepts as a same-owner no-op).
    #[cfg(test)]
    pub(crate) fn with_fs(fs: F, root_path: impl AsRef<Path>, uid: u32, gid: u32) -> Self {
        Self {
            fs,
            root_path: root_path.as_ref().to_path_buf(),
            uid,
            gid,
        }
    }

    /// `Load` — absence reports [`advisory::WITNESS_NOT_FOUND_CODE`]
    /// (`NotFound` kind): a never-written witness is a legitimate zero
    /// witness, checked *before* the hardened open so "absent" and
    /// "present but untrusted" can never collapse into one outcome.
    fn load_witness(&self) -> Result<TimeWitness, Failure> {
        let full_path = self.root_path.join(TIME_WITNESS_REL_PATH);
        match fs::symlink_metadata(&full_path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Failure::not_found(
                    advisory::WITNESS_NOT_FOUND_CODE,
                    "advisory adapter: time witness not found",
                ));
            }
            Err(e) => {
                return Err(internal(
                    "advisory_witness_stat",
                    format!("advisory adapter: stat time witness: {e}"),
                ));
            }
            Ok(_) => {}
        }
        let data =
            read_and_verify_file(&self.fs, TIME_WITNESS_REL_PATH, MAX_TIME_WITNESS_FILE_SIZE)
                .map_err(|e| {
                    internal(
                        "advisory_witness_read",
                        format!("advisory adapter: read time witness: {e}"),
                    )
                })?;
        parse_time_witness_file(&data)
    }

    /// `Advance` — durably replace the witness; refuses a zero
    /// `last_accepted_at` like upstream.
    fn advance_witness(&self, witness: &TimeWitness) -> Result<(), Failure> {
        if witness.last_accepted_at.is_none() {
            return Err(internal(
                "advisory_witness_zero",
                "advisory adapter: refusing to advance to a zero time witness",
            ));
        }
        // `t.UTC().Format(time.RFC3339Nano)` — `time`'s own Rfc3339
        // format on a UTC instant already emits the Go shape (fraction
        // only when nonzero, Z suffix); audit.rs's wrapper must not be
        // reused here because it appends the fraction a second time.
        let file = TimeWitnessFile {
            schema_version: TIME_WITNESS_SCHEMA.to_owned(),
            last_accepted_at: witness
                .last_accepted_at
                .map(|t| {
                    t.to_offset(time::UtcOffset::UTC)
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_default()
                })
                .unwrap_or_default(),
            last_issued_at: witness
                .last_issued_at
                .map(|t| {
                    t.to_offset(time::UtcOffset::UTC)
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_default()
                })
                .unwrap_or_default(),
        };
        let data = serde_json::to_vec(&file).map_err(|e| {
            internal(
                "advisory_witness_marshal",
                format!("advisory adapter: marshal time witness: {e}"),
            )
        })?;
        let advisories_dir = self.root_path.join("advisories");
        ensure_owned_dir(&advisories_dir, self.uid, self.gid)?;
        replace_owned(
            &advisories_dir,
            TIME_WITNESS_FILE_NAME,
            &data,
            self.uid,
            self.gid,
        )
        .map_err(|e| {
            internal(
                "advisory_witness_write",
                format!("advisory adapter: write time witness: {e}"),
            )
        })
    }
}

impl<F: BundleFs + 'static> port::TimeWitnessStore for TimeWitnessStore<F> {
    async fn load(&self) -> Result<TimeWitness, Failure> {
        self.load_witness()
    }
    async fn advance(&self, witness: &TimeWitness) -> Result<(), Failure> {
        self.advance_witness(witness)
    }
}

/// The `json.Unmarshal` + schema + timestamp-parse half of `Load`,
/// separated so the fail-closed parse is testable without the FS.
fn parse_time_witness_file(data: &[u8]) -> Result<TimeWitness, Failure> {
    let file: TimeWitnessFile = serde_json::from_slice(data).map_err(|_| {
        internal(
            "advisory_witness_invalid",
            "advisory adapter: invalid time witness",
        )
    })?;
    if file.schema_version != TIME_WITNESS_SCHEMA {
        return Err(internal(
            "advisory_witness_invalid",
            "advisory adapter: invalid time witness",
        ));
    }
    let parse = |s: &str, field: &str| -> Result<OffsetDateTime, Failure> {
        OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).map_err(|e| {
            internal(
                "advisory_witness_parse",
                format!("advisory adapter: parse time witness {field}: {e}"),
            )
        })
    };
    Ok(TimeWitness {
        last_accepted_at: Some(parse(&file.last_accepted_at, "last_accepted_at")?),
        last_issued_at: Some(parse(&file.last_issued_at, "last_issued_at")?),
    })
}

// ---------------------------------------------------------------------------
// install.go — atomic write helpers + InstallActiveBundle
// ---------------------------------------------------------------------------

/// `ensureRootOwnedDir` (parametrized over uid/gid so the witness
/// store's test seam can run non-root): create `dir` `0700` if absent,
/// then *assert* the shape — never a symlink, always chmod `0700`,
/// always chowned to the configured owner.
fn ensure_owned_dir(dir: &Path, uid: u32, gid: u32) -> Result<(), Failure> {
    match fs::create_dir(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => {
            return Err(internal(
                "advisory_mkdir",
                format!("create directory {}: {e}", dir.display()),
            ));
        }
    }
    let info = fs::symlink_metadata(dir).map_err(|e| {
        internal(
            "advisory_stat_dir",
            format!("stat directory {}: {e}", dir.display()),
        )
    })?;
    if info.file_type().is_symlink() || !info.is_dir() {
        return Err(denied(
            "advisory_dir_shape",
            format!("{} is not a plain directory", dir.display()),
        ));
    }
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|e| {
        internal(
            "advisory_chmod_dir",
            format!("secure directory {}: {e}", dir.display()),
        )
    })?;
    rustix::fs::chown(dir, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid))).map_err(|e| {
        internal(
            "advisory_chown_dir",
            format!("own directory {}: {e}", dir.display()),
        )
    })
}

/// `writeSyncClose` — write, fsync, close; first error wins.
fn write_sync_close(f: &mut File, data: &[u8]) -> Result<(), Failure> {
    f.write_all(data)
        .and_then(|()| f.sync_all())
        .map_err(|e| internal("advisory_write", format!("write file: {e}")))
}

fn unique_tmp_path(dir: &Path, name: &str) -> Result<PathBuf, Failure> {
    let mut suffix = [0u8; 16];
    rustix::rand::getrandom(&mut suffix, rustix::rand::GetRandomFlags::empty()).map_err(|e| {
        internal(
            "advisory_tmpname",
            format!("advisory install: temp suffix: {e}"),
        )
    })?;
    Ok(dir.join(format!(".{name}.{}.tmp", hex_lower(&suffix))))
}

/// `syncDir` — fsync the directory so the rename/link is durable.
fn sync_dir(path: &Path) -> Result<(), Failure> {
    File::open(path)
        .and_then(|d| d.sync_all())
        .map_err(|e| internal("advisory_sync_dir", format!("sync directory: {e}")))
}

/// `createOnlyRootOwned` — temp + fsync + chown, then `link` (not
/// `rename`): `EEXIST` fails closed on a race rather than overwriting a
/// generation another install already completed.
fn create_only_owned(
    dir: &Path,
    name: &str,
    data: &[u8],
    uid: u32,
    gid: u32,
) -> Result<(), Failure> {
    let temp_path = unique_tmp_path(dir, name)?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp_path)
        .map_err(|e| internal("advisory_tmp", format!("create temporary file: {e}")))?;
    if let Err(e) = write_sync_close(&mut f, data) {
        drop(f);
        let _ = fs::remove_file(&temp_path);
        return Err(e);
    }
    drop(f);
    if let Err(e) = rustix::fs::chown(
        &temp_path,
        Some(Uid::from_raw(uid)),
        Some(Gid::from_raw(gid)),
    ) {
        let _ = fs::remove_file(&temp_path);
        return Err(internal(
            "advisory_chown",
            format!("own temporary file: {e}"),
        ));
    }
    let final_path = dir.join(name);
    if let Err(e) = fs::hard_link(&temp_path, &final_path) {
        let _ = fs::remove_file(&temp_path);
        return Err(internal("advisory_link", format!("install file: {e}")));
    }
    fs::remove_file(&temp_path)
        .map_err(|e| internal("advisory_unlink", format!("remove temporary file: {e}")))?;
    sync_dir(dir)
}

/// `replaceRootOwned` — temp + fsync + chown + `rename`: the pointer
/// this call is explicitly meant to repoint.
fn replace_owned(dir: &Path, name: &str, data: &[u8], uid: u32, gid: u32) -> Result<(), Failure> {
    let temp_path = unique_tmp_path(dir, name)?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp_path)
        .map_err(|e| internal("advisory_tmp", format!("create temporary file: {e}")))?;
    if let Err(e) = write_sync_close(&mut f, data) {
        drop(f);
        let _ = fs::remove_file(&temp_path);
        return Err(e);
    }
    drop(f);
    if let Err(e) = rustix::fs::chown(
        &temp_path,
        Some(Uid::from_raw(uid)),
        Some(Gid::from_raw(gid)),
    ) {
        let _ = fs::remove_file(&temp_path);
        return Err(internal(
            "advisory_chown",
            format!("own temporary file: {e}"),
        ));
    }
    let final_path = dir.join(name);
    if let Err(e) = fs::rename(&temp_path, &final_path) {
        let _ = fs::remove_file(&temp_path);
        return Err(internal("advisory_rename", format!("install file: {e}")));
    }
    sync_dir(dir)
}

/// `advisory_install_invalid` — `ErrInvalidEnvelope`'s code.
pub const ERR_INVALID_ENVELOPE: &str = "advisory.install_invalid_envelope";

fn invalid_envelope(msg: impl Into<String>) -> Failure {
    internal(
        ERR_INVALID_ENVELOPE,
        format!("advisory install: {}", msg.into()),
    )
}

/// `randomGenerationID` — 16 random bytes, lowercase hex.
fn random_generation_id() -> Result<String, Failure> {
    let mut b = [0u8; 16];
    rustix::rand::getrandom(&mut b, rustix::rand::GetRandomFlags::empty()).map_err(|e| {
        internal(
            "advisory_genid",
            format!("advisory install: generation id: {e}"),
        )
    })?;
    Ok(hex_lower(&b))
}

/// `InstallActiveBundle` — atomically install `envelope` beneath
/// `root_path` (`advisories/generations/<id>/envelope.json` via
/// link-once, then repoint `advisories/active.json` via rename). The
/// bytes must already be a strict, well-formed `{bundle, signature}`
/// envelope exactly as `central-advisory-sign` produced them; nothing
/// is signed or reshaped here.
///
/// Requires the privilege to create root:root files — in production it
/// runs inside the root helper process.
///
/// # Errors
/// [`ERR_INVALID_ENVELOPE`] for empty/oversized/non-strict/malformed
/// input; `internal` on any filesystem failure.
pub fn install_active_bundle(
    root_path: impl AsRef<Path>,
    binding_id: &str,
    envelope: &[u8],
) -> Result<String, Failure> {
    let root_path = root_path.as_ref();
    if root_path.as_os_str().is_empty() || binding_id.is_empty() {
        return Err(invalid_envelope("rootPath and bindingID are required"));
    }
    if envelope.is_empty() || envelope.len() as u64 > MAX_ENVELOPE_SIZE {
        return Err(invalid_envelope("invalid envelope"));
    }
    advisory::strict_decode(envelope)
        .map_err(|e| invalid_envelope(format!("invalid envelope: {e:?}")))?;
    let env: SelectorEnvelope = serde_json::from_slice(envelope)
        .map_err(|e| invalid_envelope(format!("invalid envelope: {e}")))?;
    if env.signature.is_empty() || env.bundle.is_null() {
        return Err(invalid_envelope(
            "invalid envelope: missing bundle or signature",
        ));
    }

    let gen_id = random_generation_id()?;
    let advisories_dir = root_path.join("advisories");
    let generations_dir = advisories_dir.join("generations");
    let gen_dir = generations_dir.join(&gen_id);
    for dir in [&advisories_dir, &generations_dir, &gen_dir] {
        ensure_owned_dir(dir, 0, 0)
            .map_err(|e| internal("advisory_install_dir", format!("advisory install: {e}")))?;
    }
    create_only_owned(&gen_dir, "envelope.json", envelope, 0, 0).map_err(|e| {
        internal(
            "advisory_install_write",
            format!("advisory install: write envelope: {e}"),
        )
    })?;

    let sel = serde_json::json!({
        "schema_version": "central.advisory-selector/v1",
        "purpose": "release_security_advisory",
        "binding_id": binding_id,
        "generation_id": gen_id,
        "generation_sha256": hex_lower(&Sha256::digest(envelope)),
    });
    let sel_bytes = serde_json::to_vec(&sel).map_err(|e| {
        internal(
            "advisory_install_sel",
            format!("advisory install: marshal selector: {e}"),
        )
    })?;
    replace_owned(&advisories_dir, "active.json", &sel_bytes, 0, 0).map_err(|e| {
        internal(
            "advisory_install_sel_write",
            format!("advisory install: write active selector: {e}"),
        )
    })?;
    Ok(gen_id)
}

// ---------------------------------------------------------------------------
// TransitionRecorder + broker journal client — transition_recorder.go
// + advisory_evaluation_client.go
// ---------------------------------------------------------------------------

/// `maxEvidenceBytes` — the helper-side bound; the broker enforces its
/// own independent 16 KiB limit.
const MAX_EVIDENCE_BYTES: usize = 16 * 1024;

/// The fixed journal stream the broker appends advisory evidence to.
const ADVISORY_EVALUATION_STREAM: &str = "advisory-evaluation";
/// `advisoryEvaluationJournalRPC` — `append_advisory_evaluation`.
const ADVISORY_EVALUATION_RPC: &str = "append_advisory_evaluation";
/// `policy_version` upstream stamps on every evaluation record.
const ADVISORY_POLICY_VERSION: &str = "central.security-advisory/v1";

/// `JournalWriter` — the durable-append seam the recorder commits
/// through. Implementations receive the fully assembled
/// [`AuthorityTransitionPayload`]; only `payload` (the opaque evidence
/// bytes) is authoritative on the wire — sequence, HMAC, digests and
/// signatures are broker-owned provenance a caller must never supply.
pub trait AdvisoryJournalWriter: Send + Sync {
    /// `AppendCommitted`.
    ///
    /// # Errors
    /// `internal`/`denied` on any broker refusal or transport failure.
    fn append_committed(
        &self,
        stream_id: &str,
        payload: &AuthorityTransitionPayload,
    ) -> Result<CommittedReceipt, Failure>;
}

/// `TransitionRecorder` — builds the bounded `AdvisoryAdmissionEvidence`
/// record and commits it through the journal writer. Evidence never
/// carries raw bundle bytes, raw signatures, or paths.
pub struct AdvisoryTransitionRecorder<W: AdvisoryJournalWriter> {
    journal: W,
}

impl<W: AdvisoryJournalWriter> AdvisoryTransitionRecorder<W> {
    /// `NewTransitionRecorder`.
    pub fn new(journal: W) -> Self {
        Self { journal }
    }
}

impl<W: AdvisoryJournalWriter> AdvisoryTransitionRecorder<W> {
    /// The synchronous body of `Record` — the port is async only
    /// because the boundary seam is; the commit itself is a blocking
    /// call here as upstream's `JournalWriter.AppendCommitted` is.
    fn record_sync(
        &self,
        outcome: &Outcome,
        bundle: Option<&VerifiedBundle>,
        facts: &HostFacts,
    ) -> Result<Receipt, Failure> {
        let evidence = AdvisoryAdmissionEvidence {
            generation_id: bundle
                .map(|b| b.snapshot.generation_id.clone())
                .unwrap_or_default(),
            selector_digest: bundle
                .map(|b| b.snapshot.selector_digest.clone())
                .unwrap_or_default(),
            canonical_bundle_digest: bundle.map(|b| b.digest.clone()).unwrap_or_default(),
            key_id: bundle.map(|b| b.key_id.clone()).unwrap_or_default(),
            state: outcome.state.as_str().to_owned(),
            code: outcome.code.as_str().to_owned(),
            check: outcome.check.clone(),
            // Upstream stamps `time.Now()` (local offset). The evidence
            // bytes cross the broker append RPC as an opaque
            // `json.RawMessage` — decoded for shape only, never
            // compared byte-wise — so the Z-vs-offset rendering cannot
            // change any verdict; UTC is kept deliberately.
            evaluation_time: OffsetDateTime::now_utc(),
            policy_version: ADVISORY_POLICY_VERSION.to_owned(),
            time_witness_state: if outcome.state == State::Current {
                "advanced".to_owned()
            } else {
                String::new()
            },
            host_facts: if *facts == HostFacts::default() {
                None
            } else {
                Some(AdvisoryHostFacts {
                    os_release: facts.os_release.clone(),
                    kernel: facts.kernel.clone(),
                    docker: facts.docker.clone(),
                    compose: facts.compose.clone(),
                    psql: facts.psql.clone(),
                })
            },
        };
        let data = serde_json::to_vec(&evidence).map_err(|e| {
            internal(
                "advisory_record_marshal",
                format!("transition recorder: marshal: {e}"),
            )
        })?;
        if data.len() > MAX_EVIDENCE_BYTES {
            return Err(internal(
                "advisory_record_size",
                format!(
                    "transition recorder: evidence {} bytes exceeds {} byte limit",
                    data.len(),
                    MAX_EVIDENCE_BYTES
                ),
            ));
        }
        let raw = serde_json::value::RawValue::from_string(
            String::from_utf8(data)
                .map_err(|e| internal("advisory_record_utf8", format!("{e}")))?,
        )
        .map_err(|e| internal("advisory_record_raw", format!("{e}")))?;
        let payload = AuthorityTransitionPayload {
            schema_version: "central.authority-transition/v1".to_owned(),
            stream_id: String::new(),
            sequence_num: 0,
            phase: String::new(),
            operation: "advisory_evaluation".to_owned(),
            instance_id: String::new(),
            binding_id: String::new(),
            launch_id: String::new(),
            nonce: String::new(),
            payload: Some(raw),
            payload_digest: String::new(),
            payload_bytes: 0,
            prior_digest: String::new(),
            broker_key_ver: String::new(),
            hmac: String::new(),
            signature: String::new(),
            signed_at: String::new(),
        };
        let receipt = self
            .journal
            .append_committed(ADVISORY_EVALUATION_STREAM, &payload)
            .map_err(|e| {
                internal(
                    "advisory_record_commit",
                    format!("transition recorder: {e}"),
                )
            })?;
        Ok(Receipt {
            id: receipt.id,
            sequence: receipt.sequence,
        })
    }
}

impl<W: AdvisoryJournalWriter + 'static> port::TransitionRecorder
    for AdvisoryTransitionRecorder<W>
{
    /// `Record` — returns the journaled receipt only after commit.
    async fn record(
        &self,
        outcome: &Outcome,
        bundle: Option<&VerifiedBundle>,
        facts: &HostFacts,
    ) -> Result<Receipt, Failure> {
        self.record_sync(outcome, bundle, facts)
    }
}

/// `advisoryEvaluationAppendRequest` — `{"evidence": <raw json>}`.
#[derive(serde::Serialize)]
struct AdvisoryEvaluationAppendRequest<'a> {
    evidence: &'a serde_json::value::RawValue,
}

/// `advisoryEvaluationAppendResult`.
#[derive(serde::Deserialize)]
struct AdvisoryEvaluationAppendResult {
    receipt_id: String,
    receipt_sequence: u64,
}

/// `AdvisoryEvaluationJournalClient` — the
/// `append_advisory_evaluation` RPC over the protected socket. Only
/// `payload.payload` crosses the wire; every provenance field is
/// broker-owned (see upstream's comment on `AppendCommitted`).
pub struct AdvisoryEvaluationJournalClient {
    client: crate::broker::lifecycle_client::LifecycleClient,
}

impl AdvisoryEvaluationJournalClient {
    /// `NewAdvisoryEvaluationJournalClient`.
    #[must_use]
    pub fn new(socket_path: PathBuf) -> Self {
        Self {
            client: crate::broker::lifecycle_client::LifecycleClient::new(socket_path),
        }
    }
}

impl AdvisoryJournalWriter for AdvisoryEvaluationJournalClient {
    /// `AppendCommitted` — `stream_id` is ignored exactly as upstream:
    /// the broker always appends to its own fixed stream for this RPC.
    fn append_committed(
        &self,
        _stream_id: &str,
        payload: &AuthorityTransitionPayload,
    ) -> Result<CommittedReceipt, Failure> {
        let evidence = payload.payload.as_deref().ok_or_else(|| {
            internal(
                "advisory_eval_unavailable",
                "broker advisory evaluation: unavailable",
            )
        })?;
        // Upstream refuses an absent field (which decodes as the
        // 4-byte literal `null`), whitespace, and over-limit evidence
        // before the broker ever sees it.
        let trimmed = evidence.get().trim();
        if trimmed.is_empty() || trimmed == "null" {
            return Err(internal(
                "advisory_eval_unavailable",
                "broker advisory evaluation: unavailable",
            ));
        }
        let req = AdvisoryEvaluationAppendRequest { evidence };
        let result: AdvisoryEvaluationAppendResult = self
            .client
            .call(ADVISORY_EVALUATION_RPC, &req)
            .map_err(|e| {
                internal(
                    "advisory_eval_rpc",
                    format!("broker advisory evaluation: {e}"),
                )
            })?;
        if result.receipt_id.is_empty() {
            return Err(denied(
                "advisory_eval_denied",
                "broker advisory evaluation: denied",
            ));
        }
        Ok(CommittedReceipt {
            id: result.receipt_id,
            sequence: result.receipt_sequence,
        })
    }
}

// ---------------------------------------------------------------------------
// DenySafeStore — denysafe.go's `EnterDenySafe`/`storeDenySafe` as a
// `port::DenySafeStore` impl. The read side (`load_deny_safe`,
// `is_deny_safe_active`, `DenySafeState`) already lives in
// `helper::audit`; this module owns the write.
// ---------------------------------------------------------------------------

/// `FileDenySafeStore` — the file-backed `port::DenySafeStore`:
/// `deny-safe.json` beneath an absolute directory, written
/// tmp-then-rename with `0700`/`0600` discipline.
pub struct FileDenySafeStore {
    dir: PathBuf,
    uid: u32,
    gid: u32,
}

impl FileDenySafeStore {
    /// Constructs the store. `uid`/`gid` are the file owner — `0:0` in
    /// production (root helper), the effective ids in tests (chown to
    /// self is a permitted no-op for the file owner).
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>, uid: u32, gid: u32) -> Self {
        Self {
            dir: dir.into(),
            uid,
            gid,
        }
    }

    /// `storeDenySafe` — `MarshalIndent`-equivalent JSON + '\n',
    /// temp-file-then-rename with the configured owner.
    fn store(&self, state: &crate::helper::audit::DenySafeState) -> Result<(), Failure> {
        if self.dir.as_os_str().is_empty() || !self.dir.is_absolute() {
            return Err(internal(
                "advisory_denysafe_dir",
                "advisory: deny-safe dir must be absolute",
            ));
        }
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.dir)
            .map_err(|e| internal("advisory_denysafe_mkdir", format!("{e}")))?;
        let encoded = serde_json::to_string_pretty(state)
            .map_err(|e| internal("advisory_denysafe_marshal", format!("{e}")))?;
        let tmp = unique_tmp_path(&self.dir, "deny-safe")?;
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| internal("advisory_denysafe_tmp", format!("{e}")))?;
        if let Err(e) = write_sync_close(&mut f, format!("{encoded}\n").as_bytes()) {
            drop(f);
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
        drop(f);
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
            .map_err(|e| internal("advisory_denysafe_chmod", format!("{e}")))?;
        rustix::fs::chown(
            &tmp,
            Some(Uid::from_raw(self.uid)),
            Some(Gid::from_raw(self.gid)),
        )
        .map_err(|e| {
            let _ = fs::remove_file(&tmp);
            internal("advisory_denysafe_chown", format!("{e}"))
        })?;
        fs::rename(&tmp, self.dir.join("deny-safe.json"))
            .map_err(|e| internal("advisory_denysafe_rename", format!("{e}")))
    }
}

impl FileDenySafeStore {
    /// The synchronous body of `EnterDenySafe`.
    fn enter_sync(&self, trigger_code: &str, now: OffsetDateTime) -> Result<(), Failure> {
        if trigger_code.is_empty() {
            return Err(internal(
                "advisory_denysafe_trigger",
                "advisory: deny-safe trigger is empty",
            ));
        }
        let (state, found) = crate::helper::audit::load_deny_safe(
            self.dir
                .to_str()
                .ok_or_else(|| internal("advisory_denysafe_dir", "deny-safe dir not UTF-8"))?,
        )?;
        if found && state.active && state.exited_at.is_empty() {
            return Ok(());
        }
        // `time.Format(RFC3339Nano)` — see `advance_witness` for why
        // audit.rs's wrapper is not reused.
        let entered = crate::helper::audit::DenySafeState {
            active: true,
            entered_at: now
                .to_offset(time::UtcOffset::UTC)
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            trigger_code: trigger_code.to_owned(),
            rescue_attempts: if found {
                state.rescue_attempts
            } else {
                Vec::new()
            },
            ..crate::helper::audit::DenySafeState::default()
        };
        self.store(&entered)
    }
}

impl port::DenySafeStore for FileDenySafeStore {
    /// `EnterDenySafe` — an already-active record is returned
    /// untouched: entry keeps the original `entered_at` and trigger so
    /// a second hard-expired observation cannot rewrite the history of
    /// the first. Attempts from an earlier completed episode carry
    /// over.
    async fn enter(&self, trigger_code: &str, now: OffsetDateTime) -> Result<(), Failure> {
        self.enter_sync(trigger_code, now)
    }
}

// ---------------------------------------------------------------------------
// Tests — mirrors upstream active_bundle_test.go, host_facts_test.go,
// time_witness_root_linux_test.go, install_root_linux_test.go, and
// transition_recorder_test.go.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// `t.TempDir` — a unique scratch root removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let mut s = [0u8; 8];
            rustix::rand::getrandom(&mut s, rustix::rand::GetRandomFlags::empty())
                .expect("getrandom");
            let dir = std::env::temp_dir().join(format!(
                "advisory-fetch-test-{}-{}",
                std::process::id(),
                hex_lower(&s)
            ));
            fs::create_dir_all(&dir).expect("tempdir");
            Self(dir)
        }

        fn join(&self, rel: &str) -> PathBuf {
            self.0.join(rel)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    impl std::ops::Deref for TempDir {
        type Target = Path;
        fn deref(&self) -> &Path {
            &self.0
        }
    }

    impl AsRef<Path> for TempDir {
        fn as_ref(&self) -> &Path {
            &self.0
        }
    }

    /// Upstream `fixtureFS` — a plain tempdir FS: containment-cleaned
    /// joins, symlinks refused, no ownership assertions.
    struct FixtureFs {
        base: PathBuf,
    }

    impl FixtureFs {
        fn new(base: &Path) -> Self {
            Self {
                base: base.to_path_buf(),
            }
        }
    }

    impl BundleFs for FixtureFs {
        fn open(&self, name: &str) -> Result<File, Failure> {
            let clean = Path::new("/").join(name);
            let clean = clean.strip_prefix("/").unwrap_or_else(|_| Path::new(name));
            let target = self.base.join(clean);
            let abs_target = target.canonicalize().unwrap_or_else(|_| target.clone());
            let abs_base = self
                .base
                .canonicalize()
                .unwrap_or_else(|_| self.base.clone());
            if !abs_target.starts_with(&abs_base) && abs_target != abs_base {
                return Err(denied("fixture_escape", "outside base"));
            }
            let meta = fs::symlink_metadata(&target)
                .map_err(|e| internal("fixture_stat", format!("{e}")))?;
            if meta.file_type().is_symlink() {
                return Err(denied("fixture_symlink", "symlink refused"));
            }
            File::open(&target).map_err(|e| internal("fixture_open", format!("{e}")))
        }
    }

    /// Upstream `replaceOnOpenFS` — swaps `replace_path`'s content at
    /// the second `open` so the same-inode check observes the swap.
    struct ReplaceOnOpenFs {
        base: PathBuf,
        replace_path: String,
        replace_content: Vec<u8>,
        opened: Mutex<bool>,
    }

    impl BundleFs for ReplaceOnOpenFs {
        fn open(&self, name: &str) -> Result<File, Failure> {
            let target = self
                .base
                .join(Path::new("/").join(name).strip_prefix("/").unwrap());
            {
                let mut opened = self.opened.lock().unwrap();
                if !*opened {
                    *opened = true;
                } else {
                    // Upstream replaces `replace_path`'s content on the
                    // second open regardless of which name is being
                    // opened — the reopen then sees different bytes.
                    let swap = self.base.join(
                        Path::new("/")
                            .join(&self.replace_path)
                            .strip_prefix("/")
                            .unwrap(),
                    );
                    fs::write(&swap, &self.replace_content)
                        .map_err(|e| internal("replace_write", format!("{e}")))?;
                }
            }
            File::open(&target).map_err(|e| internal("replace_open", format!("{e}")))
        }
    }

    fn write_file(dir: &Path, rel: &str, data: &[u8]) {
        let p = dir.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, data).unwrap();
    }

    fn envelope_json(bundle: serde_json::Value, signature: &str) -> Vec<u8> {
        serde_json::json!({"bundle": bundle, "signature": signature})
            .to_string()
            .into_bytes()
    }

    fn selector_json(gen_id: &str, digest: &str, binding: &str) -> Vec<u8> {
        serde_json::json!({
            "schema_version": "central.advisory-selector/v1",
            "purpose": "release_security_advisory",
            "binding_id": binding,
            "generation_id": gen_id,
            "generation_sha256": digest,
        })
        .to_string()
        .into_bytes()
    }

    /// Plants `advisories/active.json` + the generation envelope and
    /// returns (gen_id, envelope bytes).
    fn plant_store(dir: &Path, binding: &str) -> (String, Vec<u8>) {
        let env = envelope_json(
            serde_json::json!({"schema_version": 1, "key_id": "k"}),
            "c2ln",
        );
        let digest = hex_lower(&Sha256::digest(&env));
        let gen_id = "gen-1".to_owned();
        write_file(
            dir,
            &format!("advisories/generations/{gen_id}/envelope.json"),
            &env,
        );
        write_file(
            dir,
            "advisories/active.json",
            &selector_json(&gen_id, &digest, binding),
        );
        (gen_id, env)
    }

    // --- loadActiveSnapshot (source.go) ------------------------------

    #[test]
    fn load_active_round_trips_installed_shape() {
        let dir = TempDir::new();
        let (gen_id, env) = plant_store(&dir, "binding-1");
        let fs = FixtureFs::new(&dir);
        let snap = load_active_snapshot(&fs, "binding-1").expect("load");
        assert_eq!(snap.generation_id, gen_id);
        assert_eq!(snap.bundle, env);
        assert_eq!(
            snap.selector_digest,
            hex_lower(&Sha256::digest(&snap.bundle))
        );
        assert_eq!(snap.signature, b"c2ln");
    }

    #[test]
    fn load_active_missing_selector_is_unavailable() {
        let dir = TempDir::new();
        let fs = FixtureFs::new(&dir);
        assert!(load_active_snapshot(&fs, "b").is_err());
    }

    #[test]
    fn load_active_selector_field_table() {
        for (field, value) in [
            ("schema_version", "wrong"),
            ("purpose", "wrong"),
            ("binding_id", "other"),
            ("generation_id", ""),
            ("generation_sha256", ""),
        ] {
            let dir = TempDir::new();
            let (gen_id, _) = plant_store(&dir, "binding-1");
            let env_bytes =
                fs::read(dir.join(&format!("advisories/generations/{gen_id}/envelope.json")))
                    .unwrap();
            let digest = hex_lower(&Sha256::digest(&env_bytes));
            let mut sel: serde_json::Value =
                serde_json::from_slice(&selector_json(&gen_id, &digest, "binding-1")).unwrap();
            sel[field] = serde_json::json!(value);
            write_file(&dir, "advisories/active.json", sel.to_string().as_bytes());
            let fs = FixtureFs::new(&dir);
            assert!(
                load_active_snapshot(&fs, "binding-1").is_err(),
                "field {field}={value:?} must refuse"
            );
        }
    }

    #[test]
    fn load_active_digest_mismatch_is_unavailable() {
        let dir = TempDir::new();
        plant_store(&dir, "binding-1");
        write_file(
            &dir,
            "advisories/active.json",
            &selector_json("gen-1", &"0".repeat(64), "binding-1"),
        );
        let fs = FixtureFs::new(&dir);
        assert!(load_active_snapshot(&fs, "binding-1").is_err());
    }

    #[test]
    fn load_active_strict_decode_failure_is_unavailable() {
        let dir = TempDir::new();
        // Strict-invalid (duplicate key) but parseable digest.
        let env = br#"{"bundle":{"a":1,"a":2},"signature":"c2ln"}"#.to_vec();
        let digest = hex_lower(&Sha256::digest(&env));
        write_file(&dir, "advisories/generations/gen-2/envelope.json", &env);
        write_file(
            &dir,
            "advisories/active.json",
            &selector_json("gen-2", &digest, "b"),
        );
        let fs = FixtureFs::new(&dir);
        assert!(load_active_snapshot(&fs, "b").is_err());
    }

    #[test]
    fn load_active_envelope_over_limit_is_unavailable() {
        let dir = TempDir::new();
        let mut env = envelope_json(serde_json::json!({"pad": "x".repeat(700_000)}), "s");
        env.extend_from_slice(&vec![b' '; 400_000]);
        assert!(env.len() as u64 > MAX_ENVELOPE_SIZE);
        let digest = hex_lower(&Sha256::digest(&env));
        write_file(&dir, "advisories/generations/big/envelope.json", &env);
        write_file(
            &dir,
            "advisories/active.json",
            &selector_json("big", &digest, "b"),
        );
        let fs = FixtureFs::new(&dir);
        assert!(load_active_snapshot(&fs, "b").is_err());
    }

    #[test]
    fn load_active_missing_signature_or_bundle_is_unavailable() {
        for env in [
            serde_json::json!({"bundle": {"a": 1}}),
            serde_json::json!({"bundle": {"a": 1}, "signature": ""}),
            serde_json::json!({"signature": "c2ln"}),
        ] {
            let dir = TempDir::new();
            let env_bytes = env.to_string().into_bytes();
            let digest = hex_lower(&Sha256::digest(&env_bytes));
            write_file(&dir, "advisories/generations/g/envelope.json", &env_bytes);
            write_file(
                &dir,
                "advisories/active.json",
                &selector_json("g", &digest, "b"),
            );
            let fs = FixtureFs::new(&dir);
            assert!(load_active_snapshot(&fs, "b").is_err(), "{env}");
        }
    }

    #[test]
    fn load_active_reopen_swap_is_unavailable() {
        // `replaceOnOpenFS`: the second `open` (the same-inode proof)
        // returns different bytes — the read must refuse.
        let dir = TempDir::new();
        let (gen_id, env) = plant_store(&dir, "b");
        let fs = ReplaceOnOpenFs {
            base: dir.to_path_buf(),
            replace_path: format!("advisories/generations/{gen_id}/envelope.json"),
            replace_content: envelope_json(serde_json::json!({"x": 1}), "swapped"),
            opened: Mutex::new(false),
        };
        let _ = env;
        assert!(load_active_snapshot(&fs, "b").is_err());
    }

    // --- Openat2Fs (active_bundle_linux.go) ---------------------------

    #[test]
    fn openat2_fs_refuses_escape_and_symlink() {
        // Containment checks run before the ownership gate, so these
        // hold as a non-root user too.
        let dir = TempDir::new();
        let fs = Openat2Fs::new(&dir).expect("open root");
        assert!(fs.open("../outside").is_err(), ".. escape must refuse");
        write_file(&dir, "advisories/real.json", b"{}");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(
                dir.join("advisories/real.json"),
                dir.join("advisories/link.json"),
            )
            .unwrap();
            assert!(
                fs.open("advisories/link.json").is_err(),
                "symlink must refuse"
            );
        }
    }

    #[test]
    fn openat2_fs_refuses_non_root_owned_file() {
        if rustix::process::geteuid().is_root() {
            eprintln!("SKIP: non-root-ownership refusal is vacuous under euid 0");
            return;
        }
        let dir = TempDir::new();
        write_file(&dir, "advisories/witness.json", b"{}");
        fs::set_permissions(
            dir.join("advisories/witness.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let fs = Openat2Fs::new(&dir).expect("open root");
        // File is owned by the test user (uid != 0): the hardened open
        // must refuse even though the mode is acceptable — the parent
        // chain check fires first (the dirs are test-user-owned too).
        let err = fs.open("advisories/witness.json").expect_err("must refuse");
        let dbg = format!("{err:?}");
        assert!(
            dbg.contains("advisory_parent_owner") || dbg.contains("advisory_file_owner"),
            "{dbg}"
        );
    }

    /// Root-required: `Openat2Fs.Open` asserts root:root ownership and
    /// `0400`/`0600`, which a non-root user cannot produce. Mirrors
    /// upstream's `requireInstallRoot` convention — the skip names
    /// exactly what did not run.
    #[test]
    fn openat2_fs_accepts_root_owned_0600() {
        if !rustix::process::geteuid().is_root() {
            eprintln!(
                "SKIPPED (needs root, euid={}): Openat2Fs.Open asserts root:root ownership",
                rustix::process::geteuid().as_raw()
            );
            return;
        }
        let dir = TempDir::new();
        let sub = dir.join("advisories");
        fs::create_dir_all(&sub).unwrap();
        let file = sub.join("witness.json");
        fs::write(&file, b"{}").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let fs = Openat2Fs::new(&dir).expect("open root");
        fs.open("advisories/witness.json")
            .expect("root-owned 0600 opens");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            fs.open("advisories/witness.json").is_err(),
            "0644 must refuse"
        );
    }

    // --- HostFactsCollector (host_facts.go) ---------------------------

    struct FakeRunner {
        outputs: HashMap<String, Vec<u8>>,
        errs: HashMap<String, FactError>,
        deadlines: Mutex<Vec<Instant>>,
    }

    impl FakeRunner {
        fn key(name: &str, args: &[&str]) -> String {
            format!("{name}|{}", args.join("|"))
        }
    }

    impl AdvisoryCommandRunner for FakeRunner {
        fn run(&self, deadline: Instant, name: &str, args: &[&str]) -> Result<Vec<u8>, FactError> {
            self.deadlines.lock().unwrap().push(deadline);
            let k = Self::key(name, args);
            if let Some(e) = self.errs.get(&k) {
                return Err(*e);
            }
            Ok(self.outputs.get(&k).cloned().unwrap_or_default())
        }
    }

    fn collector_with(runner: FakeRunner, dir: &Path) -> HostFactsCollector<FakeRunner> {
        HostFactsCollector {
            runner,
            os_release_path: dir.join("os-release"),
            kernel_release_path: dir.join("osrelease"),
        }
    }

    #[test]
    fn host_facts_collect_table() {
        let dir = TempDir::new();
        write_file(
            &dir,
            "os-release",
            b"NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\n",
        );
        write_file(&dir, "osrelease", b"6.8.0-31-generic\n");
        let mut outputs = HashMap::new();
        outputs.insert(
            FakeRunner::key(
                "/usr/bin/docker",
                &["version", "--format", "{{.Client.Version}}"],
            ),
            b"24.0.7\n".to_vec(),
        );
        outputs.insert(
            FakeRunner::key("/usr/bin/docker", &["compose", "version", "--short"]),
            b"2.23.3\n".to_vec(),
        );
        outputs.insert(
            FakeRunner::key("/usr/bin/psql", &["--version"]),
            b"psql (PostgreSQL) 16.1\n".to_vec(),
        );
        let runner = FakeRunner {
            outputs,
            errs: HashMap::new(),
            deadlines: Mutex::new(Vec::new()),
        };
        let c = collector_with(runner, &dir);
        let facts = c.collect_facts();
        assert_eq!(facts.os_release, "24.04");
        assert_eq!(facts.kernel, "6.8.0-31-generic");
        assert_eq!(facts.docker, "24.0.7");
        assert_eq!(facts.compose, "2.23.3");
        assert_eq!(facts.psql, "16.1");
        // Upstream's one `context.WithTimeout` per `Collect`: every
        // command ran under the SAME deadline instant, not a fresh 5 s.
        let deadlines = c.runner.deadlines.lock().unwrap();
        assert_eq!(deadlines.len(), 3);
        assert!(deadlines.iter().all(|d| *d == deadlines[0]));
    }

    #[test]
    fn host_facts_missing_tools_leave_fields_empty() {
        let dir = TempDir::new();
        write_file(&dir, "os-release", b"VERSION_ID=\"22.04\"\n");
        write_file(&dir, "osrelease", b"6.5.0\n");
        let mut errs = HashMap::new();
        errs.insert(
            FakeRunner::key(
                "/usr/bin/docker",
                &["version", "--format", "{{.Client.Version}}"],
            ),
            FactError::Absent,
        );
        errs.insert(
            FakeRunner::key("/usr/bin/docker", &["compose", "version", "--short"]),
            FactError::Absent,
        );
        errs.insert(
            FakeRunner::key("/usr/bin/psql", &["--version"]),
            FactError::Inaccessible,
        );
        let c = collector_with(
            FakeRunner {
                outputs: HashMap::new(),
                errs,
                deadlines: Mutex::new(Vec::new()),
            },
            &dir,
        );
        let facts = c.collect_facts();
        assert_eq!(facts.os_release, "22.04");
        assert_eq!(facts.kernel, "6.5.0");
        assert_eq!(facts.docker, "");
        assert_eq!(facts.compose, "");
        assert_eq!(facts.psql, "");
    }

    #[test]
    fn parse_os_release_variants() {
        assert_eq!(
            parse_os_release("NAME=\"x\"\nVERSION_ID=\"24.04\"\n").unwrap(),
            "24.04"
        );
        assert_eq!(parse_os_release("VERSION_ID=24.04").unwrap(), "24.04");
        assert_eq!(parse_os_release("NAME=\"x\""), Err(FactError::Malformed));
    }

    #[test]
    fn normalize_version_table() {
        for (raw, tool, want) in [
            ("Docker version 24.0.7", "docker", "24.0.7"),
            ("24.0.7", "docker", "24.0.7"),
            ("Docker Compose version v2.23.3", "compose", "2.23.3"),
            ("v2.23.3", "compose", "2.23.3"),
            ("2.23.3\n", "compose", "2.23.3"),
            ("psql (PostgreSQL) 16.1", "psql", "16.1"),
            ("16.1", "psql", "16.1"),
            ("6.8.0-31-generic\nextra", "kernel", "6.8.0-31-generic"),
        ] {
            assert_eq!(normalize_version(raw, tool), want, "{raw}/{tool}");
        }
    }

    #[test]
    fn real_runner_live_commands() {
        let r = RealCommandRunner::new();
        let generous = || Instant::now() + Duration::from_secs(30);
        let out = r.run(generous(), "/bin/echo", &["hello"]).expect("echo");
        assert_eq!(out, b"hello\n");
        // Absent binary → Absent.
        assert_eq!(
            r.run(generous(), "/nonexistent/central-test-binary", &[]),
            Err(FactError::Absent)
        );
        // >16 KiB combined output → OverLimit.
        assert_eq!(
            r.run(generous(), "/usr/bin/head", &["-c", "20000", "/dev/zero"]),
            Err(FactError::OverLimit)
        );
        // Non-zero exit is a raw error (→ empty fact upstream).
        assert!(r.run(generous(), "/bin/false", &[]).is_err());
        // Deadline → Absent (upstream folds deadline into absent); a
        // short budget keeps the test fast, an already-expired one
        // refuses the same way upstream's done-context does.
        let start = Instant::now();
        assert_eq!(
            r.run(start + Duration::from_millis(200), "/bin/sleep", &["30"]),
            Err(FactError::Absent)
        );
        assert!(start.elapsed() < Duration::from_secs(5));
        assert_eq!(
            r.run(Instant::now(), "/bin/sleep", &["30"]),
            Err(FactError::Absent)
        );
        for (e, want) in [
            (FactError::Absent, "command/file absent"),
            (FactError::Inaccessible, "no permission to execute/read"),
            (FactError::Malformed, "output malformed or unexpected"),
            (FactError::Ambiguous, "ambiguous output"),
            (FactError::OverLimit, "output exceeds 16 KiB limit"),
        ] {
            assert_eq!(e.describe(), want);
        }
    }

    // --- TimeWitnessStore (time_witness_linux.go) ---------------------

    fn witness_store(dir: &Path) -> TimeWitnessStore<FixtureFs> {
        TimeWitnessStore::with_fs(
            FixtureFs::new(dir),
            dir,
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw(),
        )
    }

    fn sample_witness() -> TimeWitness {
        let t = OffsetDateTime::parse(
            "2025-01-15T10:30:00.123456789Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        TimeWitness {
            last_accepted_at: Some(t),
            last_issued_at: Some(t),
        }
    }

    #[test]
    fn witness_load_absent_is_witness_not_found() {
        let dir = TempDir::new();
        let store = witness_store(&dir);
        let err = store.load_witness().expect_err("absent must error");
        assert_eq!(err.code(), advisory::WITNESS_NOT_FOUND_CODE);
    }

    #[test]
    fn witness_load_corrupt_is_denial_not_not_found() {
        let dir = TempDir::new();
        write_file(&dir, TIME_WITNESS_REL_PATH, b"not json");
        let store = witness_store(&dir);
        let err = store.load_witness().expect_err("corrupt must error");
        assert_ne!(err.code(), advisory::WITNESS_NOT_FOUND_CODE);
    }

    #[test]
    fn witness_advance_round_trip_and_schema() {
        let dir = TempDir::new();
        let store = witness_store(&dir);
        store.advance_witness(&sample_witness()).expect("advance");
        let w = store.load_witness().expect("reload");
        assert_eq!(w, sample_witness());
        // On-disk shape matches upstream's timeWitnessFile.
        let raw: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.join(TIME_WITNESS_REL_PATH)).unwrap()).unwrap();
        assert_eq!(raw["schema_version"], TIME_WITNESS_SCHEMA);
        assert_eq!(raw["last_accepted_at"], "2025-01-15T10:30:00.123456789Z");
        assert_eq!(raw["last_issued_at"], "2025-01-15T10:30:00.123456789Z");
    }

    #[test]
    fn witness_advance_zero_is_refused() {
        let dir = TempDir::new();
        let store = witness_store(&dir);
        assert!(store.advance_witness(&TimeWitness::default()).is_err());
        // And the refusal wrote nothing.
        assert!(!dir.join(TIME_WITNESS_REL_PATH).exists());
    }

    #[test]
    fn parse_time_witness_file_table() {
        let good = serde_json::json!({
            "schema_version": TIME_WITNESS_SCHEMA,
            "last_accepted_at": "2025-01-15T10:30:00Z",
            "last_issued_at": "2025-01-15T10:30:00Z",
        });
        assert!(parse_time_witness_file(good.to_string().as_bytes()).is_ok());
        for bad in [
            serde_json::json!({"schema_version": "other"}),
            serde_json::json!({
                "schema_version": TIME_WITNESS_SCHEMA,
                "last_accepted_at": "not-a-time",
                "last_issued_at": "2025-01-15T10:30:00Z",
            }),
            serde_json::json!({
                "schema_version": TIME_WITNESS_SCHEMA,
                "last_accepted_at": "2025-01-15T10:30:00Z",
                "last_issued_at": "nope",
            }),
        ] {
            assert!(
                parse_time_witness_file(bad.to_string().as_bytes()).is_err(),
                "{bad}"
            );
        }
    }

    // --- InstallActiveBundle (install.go) -----------------------------

    fn valid_envelope() -> Vec<u8> {
        envelope_json(
            serde_json::json!({"schema_version": 1, "key_id": "k"}),
            "c2ln",
        )
    }

    #[test]
    fn install_refuses_invalid_envelope_before_any_write() {
        for env in [
            Vec::new(),
            b"not json".to_vec(),
            br#"{"bundle":{"a":1,"a":2},"signature":"s"}"#.to_vec(),
            serde_json::json!({"bundle": {"a": 1}})
                .to_string()
                .into_bytes(),
        ] {
            let dir = TempDir::new();
            assert!(install_active_bundle(&dir, "b", &env).is_err(), "{env:?}");
            assert!(
                !dir.join("advisories").exists(),
                "invalid envelope must not create the store"
            );
        }
        // Binding is required.
        let dir = TempDir::new();
        assert!(install_active_bundle(&dir, "", &valid_envelope()).is_err());
        assert!(!dir.join("advisories").exists());
    }

    /// Root-required: install asserts root:root on every file/dir it
    /// creates, the invariant the openat2 reader refuses to trust
    /// otherwise — upstream `requireInstallRoot` convention.
    #[test]
    fn install_round_trip_root_required() {
        if !rustix::process::geteuid().is_root() {
            eprintln!(
                "SKIPPED (needs root, euid={}): InstallActiveBundle asserts root:root ownership",
                rustix::process::geteuid().as_raw()
            );
            return;
        }
        let dir = TempDir::new();
        let env = valid_envelope();
        let gen_id = install_active_bundle(&dir, "binding-1", &env).expect("install");
        // Files on disk: generation envelope + repointed selector.
        let on_disk = fs::read(dir.join(&format!("advisories/generations/{gen_id}/envelope.json")))
            .expect("envelope file");
        assert_eq!(on_disk, env);
        // Second install of the same bytes creates a *new* generation
        // (create-only link semantics) — never silently rewrites.
        let gen_id2 = install_active_bundle(&dir, "binding-1", &env).expect("install 2");
        assert_ne!(gen_id, gen_id2);
        // The hardened reader accepts what install produced.
        let src = ActiveBundleSource::new(&dir, "binding-1").expect("source");
        let snap = load_active_snapshot(&src.fs, "binding-1").expect("load");
        assert_eq!(snap.generation_id, gen_id2);
        assert_eq!(snap.bundle, env);
        assert_eq!(snap.signature, b"c2ln");
    }

    #[test]
    fn install_non_root_cannot_chown_and_fails_closed() {
        if rustix::process::geteuid().is_root() {
            eprintln!("SKIP: the fail-closed assertion is vacuous under euid 0");
            return;
        }
        let dir = TempDir::new();
        // ensure_owned_dir chowns to 0:0 — a non-root user cannot, so
        // install must error rather than leave a half-installed tree.
        assert!(install_active_bundle(&dir, "b", &valid_envelope()).is_err());
    }

    // --- TransitionRecorder (transition_recorder.go) ------------------

    struct FakeJournal {
        result: Result<CommittedReceipt, Failure>,
        captured: Mutex<Vec<(String, AuthorityTransitionPayload)>>,
    }

    impl AdvisoryJournalWriter for FakeJournal {
        fn append_committed(
            &self,
            stream_id: &str,
            payload: &AuthorityTransitionPayload,
        ) -> Result<CommittedReceipt, Failure> {
            self.captured
                .lock()
                .unwrap()
                .push((stream_id.to_owned(), payload.clone()));
            match &self.result {
                Ok(r) => Ok(r.clone()),
                Err(e) => Err(Failure::internal(e.code(), e.to_string())),
            }
        }
    }

    fn test_outcome(state: State, code: advisory::Code, check: &str) -> Outcome {
        Outcome {
            state,
            code,
            check: check.to_owned(),
            remediation: String::new(),
        }
    }

    #[test]
    fn recorder_returns_receipt_only_after_commit() {
        let journal = FakeJournal {
            result: Ok(CommittedReceipt {
                id: "rec-test-0001".into(),
                sequence: 42,
            }),
            captured: Mutex::new(Vec::new()),
        };
        let recorder = AdvisoryTransitionRecorder::new(journal);
        let receipt = recorder
            .record_sync(
                &test_outcome(State::Current, advisory::Code::Invalid, "all_checks_passed"),
                None,
                &HostFacts::default(),
            )
            .expect("record");
        assert_eq!(receipt.id, "rec-test-0001");
        assert_eq!(receipt.sequence, 42);

        let captured = recorder.journal.captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        let (stream, payload) = &captured[0];
        assert_eq!(stream, "advisory-evaluation");
        assert_eq!(payload.schema_version, "central.authority-transition/v1");
        assert_eq!(payload.operation, "advisory_evaluation");
        // Only `payload` is caller-supplied; provenance fields are
        // broker-owned and stay empty.
        assert!(payload.hmac.is_empty() && payload.signature.is_empty());
        let evidence: AdvisoryAdmissionEvidence =
            serde_json::from_str(payload.payload.as_ref().unwrap().get()).unwrap();
        assert_eq!(evidence.state, "current");
        assert_eq!(evidence.check, "all_checks_passed");
        assert_eq!(evidence.policy_version, "central.security-advisory/v1");
        assert_eq!(evidence.time_witness_state, "advanced");
        assert!(evidence.host_facts.is_none());
    }

    #[test]
    fn recorder_evidence_carries_bundle_and_facts_allowlist() {
        let journal = FakeJournal {
            result: Ok(CommittedReceipt {
                id: "r".into(),
                sequence: 1,
            }),
            captured: Mutex::new(Vec::new()),
        };
        let recorder = AdvisoryTransitionRecorder::new(journal);
        let bundle = VerifiedBundle {
            snapshot: Snapshot {
                generation_id: "gen-7".into(),
                selector_digest: "seldigest".into(),
                bundle: b"raw bundle bytes never persisted".to_vec(),
                signature: b"raw signature never persisted".to_vec(),
            },
            canonical: b"canonical".to_vec(),
            digest: "candigest".into(),
            key_id: "key/v1".into(),
            issued_at: OffsetDateTime::UNIX_EPOCH,
            expires_at: OffsetDateTime::UNIX_EPOCH,
            compatibility: advisory::CompatibilityMatrix::default(),
            emergency_deny: advisory::DenyPolicy::default(),
        };
        let facts = HostFacts {
            os_release: "24.04".into(),
            kernel: "6.8".into(),
            ..HostFacts::default()
        };
        recorder
            .record_sync(
                &test_outcome(State::Stale, advisory::Code::HostMismatch, "kernel"),
                Some(&bundle),
                &facts,
            )
            .expect("record");
        let captured = recorder.journal.captured.lock().unwrap();
        let raw = captured[0].1.payload.as_ref().unwrap().get();
        let evidence: AdvisoryAdmissionEvidence = serde_json::from_str(raw).unwrap();
        assert_eq!(evidence.generation_id, "gen-7");
        assert_eq!(evidence.selector_digest, "seldigest");
        assert_eq!(evidence.canonical_bundle_digest, "candigest");
        assert_eq!(evidence.key_id, "key/v1");
        assert_eq!(evidence.state, "stale");
        // Never "advanced" for a non-current outcome.
        assert_eq!(evidence.time_witness_state, "");
        let hf = evidence.host_facts.expect("facts");
        assert_eq!(hf.os_release, "24.04");
        assert_eq!(hf.kernel, "6.8");
        // Raw bundle bytes and signature never appear in the payload.
        assert!(!raw.contains("raw bundle bytes"));
        assert!(!raw.contains("raw signature"));
    }

    #[test]
    fn recorder_journal_error_propagates() {
        let journal = FakeJournal {
            result: Err(internal("journal_down", "journal unavailable")),
            captured: Mutex::new(Vec::new()),
        };
        let recorder = AdvisoryTransitionRecorder::new(journal);
        assert!(
            recorder
                .record_sync(
                    &test_outcome(State::Denied, advisory::Code::EmergencyDeny, ""),
                    None,
                    &HostFacts::default(),
                )
                .is_err()
        );
    }

    #[test]
    fn recorder_evidence_over_limit_refuses_before_commit() {
        let journal = FakeJournal {
            result: Ok(CommittedReceipt {
                id: "r".into(),
                sequence: 1,
            }),
            captured: Mutex::new(Vec::new()),
        };
        let recorder = AdvisoryTransitionRecorder::new(journal);
        let outcome = test_outcome(
            State::Stale,
            advisory::Code::HostMismatch,
            &"x".repeat(MAX_EVIDENCE_BYTES),
        );
        assert!(
            recorder
                .record_sync(&outcome, None, &HostFacts::default())
                .is_err()
        );
        // Nothing reached the journal.
        assert!(recorder.journal.captured.lock().unwrap().is_empty());
    }

    #[test]
    fn journal_client_wire_shape_and_fail_closed() {
        // No server on the path: the RPC must fail closed.
        let dir = TempDir::new();
        let client = AdvisoryEvaluationJournalClient::new(dir.join("missing.sock"));
        let raw = serde_json::value::RawValue::from_string("{}".to_owned()).unwrap();
        let payload = AuthorityTransitionPayload {
            schema_version: "central.authority-transition/v1".into(),
            stream_id: String::new(),
            sequence_num: 0,
            phase: String::new(),
            operation: "advisory_evaluation".into(),
            instance_id: String::new(),
            binding_id: String::new(),
            launch_id: String::new(),
            nonce: String::new(),
            payload: Some(raw),
            payload_digest: String::new(),
            payload_bytes: 0,
            prior_digest: String::new(),
            broker_key_ver: String::new(),
            hmac: String::new(),
            signature: String::new(),
            signed_at: String::new(),
        };
        assert!(
            client
                .append_committed("advisory-evaluation", &payload)
                .is_err()
        );
        // Empty payload is refused before any transport use.
        let mut empty = AuthorityTransitionPayload {
            schema_version: String::new(),
            stream_id: String::new(),
            sequence_num: 0,
            phase: String::new(),
            operation: String::new(),
            instance_id: String::new(),
            binding_id: String::new(),
            launch_id: String::new(),
            nonce: String::new(),
            payload: None,
            payload_digest: String::new(),
            payload_bytes: 0,
            prior_digest: String::new(),
            broker_key_ver: String::new(),
            hmac: String::new(),
            signature: String::new(),
            signed_at: String::new(),
        };
        assert!(client.append_committed("s", &empty).is_err());
        // An absent-field "null" literal is refused exactly like
        // upstream's `bytes.Equal(trimmed, []byte("null"))` check.
        let null_payload = serde_json::value::RawValue::from_string("null".to_owned()).unwrap();
        empty.payload = Some(null_payload);
        assert!(client.append_committed("s", &empty).is_err());
        // The request serializes evidence as embedded JSON, not a string.
        let evidence = serde_json::value::RawValue::from_string(
            r#"{"state":"current","code":"X"}"#.to_owned(),
        )
        .unwrap();
        let wire = serde_json::to_string(&AdvisoryEvaluationAppendRequest {
            evidence: &evidence,
        })
        .unwrap();
        let _ = evidence;
        assert_eq!(wire, r#"{"evidence":{"state":"current","code":"X"}}"#);
    }

    // --- FileDenySafeStore (denysafe.go's EnterDenySafe/storeDenySafe) -

    fn deny_store(dir: &Path) -> FileDenySafeStore {
        FileDenySafeStore::new(
            dir,
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw(),
        )
    }

    #[test]
    fn deny_safe_enter_writes_active_record() {
        let dir = TempDir::new();
        let store = deny_store(&dir.join("state"));
        let now = OffsetDateTime::parse(
            "2025-06-01T00:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        store
            .enter_sync("ADVISORY_HARD_EXPIRED", now)
            .expect("enter");
        let (state, found) =
            crate::helper::audit::load_deny_safe(dir.join("state").to_str().unwrap())
                .expect("load");
        assert!(found);
        assert!(state.active);
        assert_eq!(state.trigger_code, "ADVISORY_HARD_EXPIRED");
        assert_eq!(state.entered_at, "2025-06-01T00:00:00Z");
        assert!(crate::helper::audit::is_deny_safe_active(
            dir.join("state").to_str().unwrap()
        ));
    }

    #[test]
    fn deny_safe_reentry_keeps_original_entry() {
        let dir = TempDir::new();
        let store = deny_store(&dir.join("state"));
        let t1 = OffsetDateTime::parse(
            "2025-06-01T00:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        let t2 = OffsetDateTime::parse(
            "2025-06-02T00:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        store.enter_sync("CODE_A", t1).expect("first");
        store.enter_sync("CODE_B", t2).expect("second");
        let (state, _) = crate::helper::audit::load_deny_safe(dir.join("state").to_str().unwrap())
            .expect("load");
        assert_eq!(state.trigger_code, "CODE_A");
        assert_eq!(state.entered_at, "2025-06-01T00:00:00Z");
    }

    #[test]
    fn deny_safe_rejects_empty_trigger_and_relative_dir() {
        let dir = TempDir::new();
        let store = deny_store(&dir.join("state"));
        let now = OffsetDateTime::UNIX_EPOCH;
        assert!(store.enter_sync("", now).is_err());
        let rel = FileDenySafeStore::new(PathBuf::from("relative/dir"), 0, 0);
        assert!(rel.enter_sync("X", now).is_err());
    }
}
