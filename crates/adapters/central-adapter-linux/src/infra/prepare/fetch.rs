//! `fetch_linux.go` — the lock-capability-gated acquisition. The
//! fetcher derives the one endpoint a selector may be fetched from out
//! of the dependency lock, walks exactly the locked redirect chain,
//! enforces the header/cookie/credential/address policy at the request
//! boundary, streams the body through SHA-256 while it downloads, and
//! stages the verified archive into a build context only after the
//! stored bytes hash back to the lock's pin.
//!
//! The transport is a seam (`FetchTransport`): the root-side helper
//! supplies the concrete implementation — no proxy, no cookie jar, no
//! client certificate, no compression, TLS policy and dial-time
//! address policy applied per the capability — while every *policy
//! decision* about what may be fetched lives here, testable without a
//! socket.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use central_foundation::failure::Failure;
use central_infra::domain::{AcquisitionKind, Candidate, PreparePhase, acquisition_kind_for};
use central_infra::prepare::{FetchCapability, Lock, TlsFetchMode};
use flate2::read::GzDecoder;
use sha2::{Digest as _, Sha256};

use super::module_cache::{self, ModuleAcquirer};
use super::{OpDeadline, hex_lower, prepare_fetch_codes as fc};

/// `allowlistedHeaders` — the only request headers that may reach the
/// wire. An `Authorization` header is the shape a `.netrc`- or
/// keychain-derived credential takes, and it is not on this list.
pub const ALLOWLISTED_HEADERS: [&str; 3] = ["Accept", "Accept-Encoding", "User-Agent"];

/// The request headers that always carry a credential, refused before
/// the allowlist is even consulted.
const CREDENTIAL_HEADERS: [&str; 2] = ["Authorization", "Proxy-Authorization"];

/// `artifactInfo` — the archive a selector is fetched as: its pinned
/// digest and its stored name. Only MinIO has one; PostgreSQL is
/// admitted as a published OCI identity chain, not downloaded.
#[derive(Debug, Clone)]
pub struct ArtifactInfo {
    /// The lock's `archive_sha256` pin.
    pub expected_digest: String,
    /// The name the artifact is stored under `base_dir`.
    pub store_name: String,
}

/// `lockArtifact` — only `"minio"` maps to a fetchable artifact.
#[must_use]
pub fn lock_artifact(lock: &Lock, selector: &str) -> Option<ArtifactInfo> {
    match selector {
        "minio" => Some(ArtifactInfo {
            expected_digest: lock.fetches.minio.archive_sha256.clone(),
            store_name: "minio.tar.gz".to_owned(),
        }),
        _ => None,
    }
}

/// `FetchRequest` — one GET the transport performs. The transport
/// must honor `timeout` (the capability's remaining budget), apply
/// the capability's `address_policy` at dial time (upstream
/// `dialCheckedAddress`: resolve, check every answer, connect to an
/// allowed address — never resolve twice), apply `tls_policy`, send
/// exactly `headers`, follow no redirects, and accept no cookies.
#[derive(Debug, Clone)]
pub struct FetchRequest {
    /// The endpoint, derived from the lock.
    pub url: String,
    /// The exact request headers (allowlist-verified by the caller).
    pub headers: BTreeMap<String, String>,
    /// The capability's TLS mode.
    pub tls_policy: TlsFetchMode,
    /// The capability's address policy string.
    pub address_policy: String,
    /// Per-call budget — the smaller of the capability deadline's
    /// remainder and the operation budget's remainder.
    pub timeout: Option<Duration>,
}

/// `FetchResponse` — the raw response the transport returns. Redirects
/// are *not* followed by the transport; the fetcher walks the locked
/// chain itself so every hop is checked against the lock.
pub struct FetchResponse {
    /// The HTTP status code.
    pub status: u16,
    /// Response headers (name → value), for `Location` and
    /// `Set-Cookie` inspection.
    pub headers: Vec<(String, String)>,
    /// The body stream — read at most `max_bytes + 1` bytes.
    pub body: Box<dyn Read + Send>,
}

/// `TransportFailure` — a transport-level failure that carries no
/// policy verdict: DNS, connect, TLS, read. `timed_out` feeds
/// [`is_transient_fetch_error`]'s `netErr.Timeout()` arm.
#[derive(Debug)]
pub struct TransportFailure {
    /// `net.Error.Timeout()`.
    pub timed_out: bool,
    /// The boundary's own description (never shown to the operator;
    /// results stay redacted).
    pub detail: String,
}

impl std::fmt::Display for TransportFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.detail)
    }
}

/// `FetchTransport` — the network seam. Production binds a
/// helper-side implementation; tests bind a canned one. Contract:
/// perform exactly one GET per call, follow no redirects, consult no
/// ambient configuration (no proxy, no jar, no client certificate,
/// no transparent compression), and enforce the request's
/// `address_policy`/`tls_policy`/`timeout`.
pub trait FetchTransport: Send + Sync {
    /// One unredirected GET.
    ///
    /// # Errors
    /// [`TransportFailure`] for any transport-level failure.
    fn get(&self, req: &FetchRequest) -> Result<FetchResponse, TransportFailure>;
}

/// `FetchError` — the typed failure `attempt` returns so
/// [`is_transient_fetch_error`] can classify it the way upstream's
/// `errors.Is`/`errors.As` chain does. Terminal policy refusals carry
/// a `Failure` with a stable code; a refused status carries the code
/// so 429/5xx can be told apart; transport failures carry the timeout
/// flag.
#[derive(Debug)]
pub enum FetchError {
    /// A terminal refusal — policy, identity, or boundary — carrying
    /// its stable code.
    Terminal(Failure),
    /// `fetchStatusError` — the endpoint answered `>= 300`.
    Status(u16),
    /// `net.Error` — a transport-level failure; retryable only when
    /// it was a timeout.
    Transport(TransportFailure),
}

impl FetchError {
    /// The terminal-side `Failure` a fetch surfaces. Statuses and
    /// transport failures fold into stable codes.
    fn into_failure(self) -> Failure {
        match self {
            Self::Terminal(f) => f,
            Self::Status(status) => Failure::invalid(
                fc::FETCH_POLICY,
                format!(
                    "dependencyprepare: fetch policy violation: server returned status {status}"
                ),
            ),
            Self::Transport(t) => Failure::unavailable(
                fc::FETCH_TRANSPORT,
                format!("dependencyprepare: fetch: {}", t.detail),
            ),
        }
    }
}

/// `isTransientFetchError` — what a retry may be spent on. A digest
/// mismatch, a size overrun, a redirect off the locked chain, a
/// disallowed address, a credential, a cookie, a client cert, or a
/// non-allowlisted header are all statements about the request or the
/// content and are terminal. 429 and 5xx are the only statuses worth
/// another attempt; a transport failure retries only on timeout.
#[must_use]
pub fn is_transient_fetch_error(err: &FetchError) -> bool {
    const TERMINAL_CODES: [&str; 8] = [
        fc::FETCH_DIGEST,
        fc::FETCH_SIZE_EXCEEDED,
        fc::FETCH_REDIRECT,
        fc::FETCH_ADDRESS,
        fc::FETCH_COOKIE,
        fc::FETCH_CREDENTIAL,
        fc::FETCH_CLIENT_CERT,
        fc::FETCH_NON_ALLOWLIST_HEADER,
    ];
    match err {
        FetchError::Terminal(f) => !TERMINAL_CODES.contains(&f.code()),
        FetchError::Status(status) => *status == 429 || *status >= 500,
        FetchError::Transport(t) => t.timed_out,
    }
}

/// `http.Client` stand-in bound to one capability: the transport. The
/// capability itself is passed to `attempt` explicitly — its fields
/// are per-request policy, not per-client state.
struct BoundClient<'a> {
    transport: &'a dyn FetchTransport,
}

/// `Fetcher` — upstream's `port.Fetcher`.
pub struct Fetcher {
    locker: Lock,
    base_dir: PathBuf,
    proxy_enabled: bool,
    headers: BTreeMap<String, String>,
    /// `modules` — the network half of Go module acquisition. `None`
    /// means the docker-backed production implementation; only a test
    /// sets it.
    modules: Option<Box<dyn ModuleAcquirer>>,
    /// `clientCerts` — the only way a client certificate can reach
    /// this fetcher, and it exists so the refusal is testable.
    client_certs_present: bool,
    /// `transport` — the GET seam. `None` means the production
    /// helper-side transport, which the daemon wires at handler
    /// construction.
    transport: Option<Box<dyn FetchTransport>>,
}

impl Fetcher {
    /// `NewFetcher` — `locker` is the already-verified lock (cloned at
    /// construction like upstream's `port.Locker` returning a value).
    #[must_use]
    pub fn new(lock: &Lock, base_dir: impl Into<PathBuf>) -> Self {
        Self {
            locker: lock.clone(),
            base_dir: base_dir.into(),
            proxy_enabled: false,
            headers: BTreeMap::new(),
            modules: None,
            client_certs_present: false,
            transport: None,
        }
    }

    /// `setHeader` — a request header the fetch sends. The allowlist
    /// check in `attempt` is what makes this safe to expose.
    pub fn set_header(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.headers.insert(key.into(), value.into());
    }

    /// `WithTransport` — binds the GET seam. Production passes the
    /// helper-side transport; tests pass a canned one.
    #[must_use]
    pub fn with_transport(mut self, transport: Box<dyn FetchTransport>) -> Self {
        self.transport = Some(transport);
        self
    }

    /// `WithModuleAcquirer` — binds the module-acquisition seam
    /// (`f.modules` in upstream, test-only).
    #[must_use]
    pub fn with_module_acquirer(mut self, acquirer: Box<dyn ModuleAcquirer>) -> Self {
        self.modules = Some(acquirer);
        self
    }

    /// `withProxy`/`clientCerts` — test-only policy-violation inputs.
    #[must_use]
    pub fn with_proxy_enabled(mut self, enabled: bool) -> Self {
        self.proxy_enabled = enabled;
        self
    }

    /// Marks a client certificate as present so the refusal is
    /// testable; production never sets it.
    #[must_use]
    pub fn with_client_cert_present(mut self, present: bool) -> Self {
        self.client_certs_present = present;
        self
    }

    /// `Fetch` — acquire `selector`'s locked artifact: derive the
    /// endpoint from the lock, bind the capability-shaped client,
    /// retry transient failures inside the locked policy, and leave
    /// the verified archive in `base_dir`.
    ///
    /// # Errors
    /// `FETCH_POLICY`/`UNKNOWN_SELECTOR`-family codes for anything the
    /// lock does not permit; `FETCH_DIGEST`, `FETCH_SIZE_EXCEEDED`,
    /// `FETCH_REDIRECT`, `FETCH_ADDRESS`, `FETCH_COOKIE`,
    /// `FETCH_CREDENTIAL`, `FETCH_CLIENT_CERT`,
    /// `FETCH_NON_ALLOWLIST_HEADER` for terminal boundary refusals.
    pub fn fetch(&self, deadline: OpDeadline, selector: &str) -> Result<Candidate, Failure> {
        let lock = &self.locker;

        let kind = acquisition_kind_for(selector).map_err(|_| {
            Failure::invalid(
                fc::FETCH_POLICY,
                format!("dependencyprepare: unknown selector {selector:?}"),
            )
        })?;
        if kind != AcquisitionKind::Built {
            return Err(Failure::invalid(
                fc::FETCH_POLICY,
                format!(
                    "dependencyprepare: fetch policy violation: {selector:?} is admitted as a published image and has no archive to fetch"
                ),
            ));
        }

        let Some(art) = lock_artifact(lock, selector) else {
            return Err(Failure::invalid(
                fc::FETCH_POLICY,
                format!("dependencyprepare: unknown selector {selector:?}"),
            ));
        };

        let capability = lock.fetch_capability_for(selector).map_err(|e| {
            Failure::invalid(
                fc::FETCH_POLICY,
                format!("dependencyprepare: fetch policy violation: {}", e.message()),
            )
        })?;
        let url = fetch_url(lock, &capability, selector)?;

        if self.proxy_enabled {
            return Err(Failure::invalid(
                fc::FETCH_POLICY,
                "dependencyprepare: fetch policy violation: proxy is not allowed",
            ));
        }

        let client = self.client_for(&capability)?;

        let retry = &lock.retry;
        retry.validate().map_err(|e| {
            Failure::invalid(
                fc::FETCH_POLICY,
                format!("dependencyprepare: fetch policy violation: {}", e.message()),
            )
        })?;

        let mut last_err: Option<FetchError> = None;
        for attempt in 1..=retry.max_attempts {
            deadline.check()?;
            let wait = retry.backoff(attempt);
            if !wait.is_zero() {
                std::thread::sleep(wait);
            }
            match self.attempt(deadline, &client, &url, &capability, &art) {
                Ok(written) => {
                    return Ok(Candidate {
                        selector: selector.to_owned(),
                        phase: Some(PreparePhase::Acquiring),
                        source_bytes: written,
                        ..Candidate::default()
                    });
                }
                Err(err) => {
                    let transient = is_transient_fetch_error(&err);
                    // Only a transient condition is retried. An
                    // identity or policy failure is a fact about the
                    // inputs, and repeating the request cannot change
                    // it.
                    if !transient {
                        return Err(err.into_failure());
                    }
                    last_err = Some(err);
                }
            }
        }
        let last = last_err.map(FetchError::into_failure).unwrap_or_else(|| {
            Failure::internal(fc::FETCH_POLICY, "dependencyprepare: fetch failed")
        });
        Err(Failure::unavailable(
            fc::FETCH_TRANSPORT,
            format!(
                "dependencyprepare: fetch {selector} exhausted {} attempts: {}",
                retry.max_attempts,
                last.message()
            ),
        ))
    }

    /// `attempt` — one request chain and, when it succeeds, the stored
    /// verified archive. Returns the bytes read.
    fn attempt(
        &self,
        deadline: OpDeadline,
        client: &BoundClient<'_>,
        url: &str,
        capability: &FetchCapability,
        art: &ArtifactInfo,
    ) -> Result<i64, FetchError> {
        let mut current = url.to_owned();
        // `CheckRedirect` in upstream is invoked by the client per 3xx;
        // here the fetcher walks the same locked chain itself.
        let mut hops_followed = 0usize;
        let response = loop {
            deadline.check().map_err(FetchError::Terminal)?;
            let mut headers = BTreeMap::new();
            for (k, v) in &self.headers {
                headers.insert(k.clone(), v.clone());
            }
            // The allowlist is what stops a credential reaching the
            // wire.
            for key in headers.keys() {
                if CREDENTIAL_HEADERS.contains(&key.as_str()) {
                    return Err(FetchError::Terminal(Failure::invalid(
                        fc::FETCH_CREDENTIAL,
                        format!(
                            "dependencyprepare: fetch credentials not allowed: header {key:?} would carry a credential"
                        ),
                    )));
                }
                if !ALLOWLISTED_HEADERS.contains(&key.as_str()) {
                    return Err(FetchError::Terminal(Failure::invalid(
                        fc::FETCH_NON_ALLOWLIST_HEADER,
                        format!(
                            "dependencyprepare: fetch header not in allowlist: header {key:?} is not allowlisted"
                        ),
                    )));
                }
            }
            if headers.keys().any(|k| k == "Cookie") {
                return Err(FetchError::Terminal(Failure::invalid(
                    fc::FETCH_COOKIE,
                    "dependencyprepare: fetch cookies not allowed: cookie present",
                )));
            }

            let req = FetchRequest {
                url: current.clone(),
                headers,
                tls_policy: capability.tls_policy,
                address_policy: capability.address_policy.clone(),
                timeout: deadline.remaining().map(|r| r.min(capability.deadline())),
            };
            let resp = client.transport.get(&req).map_err(FetchError::Transport)?;

            // A server that tries to set a cookie is not the endpoint
            // the lock describes.
            if resp
                .headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
            {
                return Err(FetchError::Terminal(Failure::invalid(
                    fc::FETCH_COOKIE,
                    "dependencyprepare: fetch cookies not allowed: server attempted to set a cookie",
                )));
            }

            if (300..400).contains(&resp.status) {
                // `CheckRedirect(req, via)` — admit the hop only when
                // the locked chain names it exactly.
                let location = resp
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("location"))
                    .map(|(_, v)| v.clone());
                let Some(location) = location else {
                    return Err(FetchError::Status(resp.status));
                };
                let next = resolve_url(&current, &location).map_err(|e| {
                    FetchError::Terminal(Failure::invalid(
                        fc::FETCH_REDIRECT,
                        format!("dependencyprepare: fetch redirect is not the locked chain: {e}"),
                    ))
                })?;
                check_redirect_hop(capability, &next, hops_followed)
                    .map_err(FetchError::Terminal)?;
                hops_followed += 1;
                current = next;
                continue;
            }
            if resp.status >= 300 {
                return Err(FetchError::Status(resp.status));
            }
            break resp;
        };

        #[allow(clippy::cast_sign_loss)]
        let mut limited = response.body.take(capability.max_bytes as u64 + 1);
        let tmp_path = {
            let mut p = self.base_dir.clone();
            let tag = hex_lower(&Sha256::digest(format!("{:p}", self).as_bytes()));
            p.push(format!(
                ".dependencyprepare-fetch-{}-{}",
                std::process::id(),
                &tag[..16]
            ));
            p
        };
        let cleanup = scopeguard(&tmp_path);
        let mut tmp_file = File::create(&tmp_path).map_err(|e| {
            FetchError::Terminal(Failure::internal(
                fc::FETCH_TRANSPORT,
                format!("dependencyprepare: create temp file: {e}"),
            ))
        })?;
        let mut hasher = Sha256::new();
        let written =
            io::copy(&mut limited, &mut tee(&mut tmp_file, &mut hasher)).map_err(|e| {
                FetchError::Terminal(Failure::internal(
                    fc::FETCH_TRANSPORT,
                    format!("dependencyprepare: download: {e}"),
                ))
            })?;
        tmp_file.flush().map_err(|e| {
            FetchError::Terminal(Failure::internal(
                fc::FETCH_TRANSPORT,
                format!("dependencyprepare: close temp file: {e}"),
            ))
        })?;
        #[allow(clippy::cast_possible_wrap)]
        let written_i64 = written as i64;
        #[allow(clippy::cast_sign_loss)]
        if written > capability.max_bytes as u64 {
            return Err(FetchError::Terminal(Failure::invalid(
                fc::FETCH_SIZE_EXCEEDED,
                format!(
                    "dependencyprepare: fetch size exceeded: {written} bytes exceeds limit of {}",
                    capability.max_bytes
                ),
            )));
        }

        let actual_digest = format!("sha256:{}", hex_lower(&hasher.finalize()));
        if actual_digest != art.expected_digest {
            return Err(FetchError::Terminal(Failure::invalid(
                fc::FETCH_DIGEST,
                format!(
                    "dependencyprepare: fetch digest mismatch: expected {}, got {actual_digest}",
                    art.expected_digest
                ),
            )));
        }

        fs::rename(&tmp_path, self.base_dir.join(&art.store_name)).map_err(|e| {
            FetchError::Terminal(Failure::internal(
                fc::FETCH_TRANSPORT,
                format!("dependencyprepare: store artifact: {e}"),
            ))
        })?;
        cleanup.keep();
        Ok(written_i64)
    }

    /// `clientFor` — the refusal half of building the one client shape
    /// the capability permits. The transport itself is seam-bound; the
    /// checks that make its shape lawful — no client certificate, a
    /// known TLS policy — run here, before any request is made.
    fn client_for<'a>(
        &'a self,
        capability: &'a FetchCapability,
    ) -> Result<BoundClient<'a>, Failure> {
        if self.client_certs_present {
            return Err(Failure::invalid(
                fc::FETCH_CLIENT_CERT,
                "dependencyprepare: fetch client certificate not allowed: client certificate present",
            ));
        }
        match capability.tls_policy {
            TlsFetchMode::SystemRoots => {}
            TlsFetchMode::InsecureTestOnly => {
                // Reachable only from a lock a test constructed; the
                // shipped lock is refused at load time if it ever
                // carries this value.
            }
        }
        let Some(transport) = self.transport.as_deref() else {
            return Err(Failure::unavailable(
                fc::FETCH_TRANSPORT,
                "dependencyprepare: no fetch transport is bound",
            ));
        };
        Ok(BoundClient { transport })
    }

    /// `StageSource` — unpack the verified archive for `selector`
    /// into `dest_dir`, the build's context directory.
    ///
    /// Ordering: the stored archive's digest is re-verified *before*
    /// `dest_dir` is touched — staging is what puts bytes in front of
    /// a builder, so it is where the lock's pin has to hold, and a
    /// drifted archive must leave a prior context byte-identical
    /// rather than half-cleared.
    ///
    /// # Errors
    /// `FETCH_POLICY`/`FETCH_DIGEST`/`FETCH_SIZE_EXCEEDED` family
    /// codes; `internal` for filesystem failures.
    pub fn stage_source(
        &self,
        deadline: OpDeadline,
        selector: &str,
        dest_dir: &Path,
    ) -> Result<(), Failure> {
        if dest_dir.as_os_str().is_empty() {
            return Err(Failure::invalid(
                fc::FETCH_POLICY,
                "dependencyprepare: fetch policy violation: staging needs a destination",
            ));
        }
        let kind = acquisition_kind_for(selector)?;
        if kind != AcquisitionKind::Built {
            return Err(Failure::invalid(
                fc::FETCH_POLICY,
                format!(
                    "dependencyprepare: fetch policy violation: {selector:?} is a published image and has no source to stage"
                ),
            ));
        }
        let lock = &self.locker;
        let Some(art) = lock_artifact(lock, selector) else {
            return Err(Failure::invalid(
                fc::FETCH_POLICY,
                format!("dependencyprepare: unknown selector {selector:?}"),
            ));
        };

        let archive_path = self.base_dir.join(&art.store_name);
        verify_stored_digest(&archive_path, &art.expected_digest)?;

        // `os.RemoveAll(destDir)` — a missing context is not an error.
        match fs::remove_dir_all(dest_dir) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(Failure::internal(
                    "FETCH_STAGE",
                    format!("dependencyprepare: clear build context: {e}"),
                ));
            }
        }
        fs::create_dir_all(dest_dir).map_err(|e| {
            Failure::internal(
                "FETCH_STAGE",
                format!("dependencyprepare: create build context: {e}"),
            )
        })?;
        let capability = lock.fetch_capability_for(selector).map_err(|e| {
            Failure::invalid(
                fc::FETCH_POLICY,
                format!("dependencyprepare: fetch policy violation: {}", e.message()),
            )
        })?;
        #[allow(clippy::cast_sign_loss)]
        extract_archive(
            deadline,
            &archive_path,
            dest_dir,
            capability.max_bytes as u64,
        )?;

        // A Go build cannot resolve its module graph inside a
        // --network=none step, so the modules are acquired here — the
        // phase that already has network and already runs under a
        // lock-declared capability. ADR 0027 / SC-DEF-09.
        let recipe = module_cache::go_build_recipe_for(lock, selector)?;
        let Some(recipe) = recipe else {
            return Ok(());
        };
        self.stage_module_cache(deadline, selector, dest_dir, &recipe.build.go_version)
    }

    /// `stageModuleCache` — see [`super::module_cache`].
    pub(crate) fn stage_module_cache(
        &self,
        deadline: OpDeadline,
        selector: &str,
        dest_dir: &Path,
        go_version: &str,
    ) -> Result<(), Failure> {
        module_cache::stage_module_cache(
            deadline,
            &self.locker,
            &self.base_dir,
            self.modules.as_deref(),
            selector,
            dest_dir,
            go_version,
        )
    }
}

/// A `TeeReader` — writes every byte that passes through into the
/// hasher, so the digest is verified over exactly the bytes stored.
fn tee<'a>(file: &'a mut File, hasher: &'a mut Sha256) -> Tee<'a> {
    Tee { file, hasher }
}

struct Tee<'a> {
    file: &'a mut File,
    hasher: &'a mut Sha256,
}

/// `HashSink` — a `Write` endpoint that feeds every byte into the
/// hasher, for the store-verify pass (`io.Copy(hasher, file)`).
struct HashSink<'a>(&'a mut Sha256);

impl Write for HashSink<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Write for Tee<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.file.write(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

/// Best-effort `defer os.Remove(tmpPath)`: the guard removes the file
/// on drop unless [`ScopeGuard::keep`] was called after the rename.
fn scopeguard(path: &Path) -> ScopeGuard {
    ScopeGuard {
        path: path.to_path_buf(),
        keep: false,
    }
}

struct ScopeGuard {
    path: PathBuf,
    keep: bool,
}

impl ScopeGuard {
    fn keep(mut self) {
        self.keep = true;
    }
}

impl Drop for ScopeGuard {
    fn drop(&mut self) {
        if !self.keep {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// `fetchURL` — the one endpoint a selector may be fetched from,
/// derived out of the dependency lock's fetch capability and the
/// lock's own pinned commit. Tag-based pulls are out of scope: the
/// tag is not another name for the pinned commit — the two archives
/// differ — so the endpoint is the capability's host and path prefix
/// plus `fetches.minio.commit`.
///
/// # Errors
/// `FETCH_POLICY` when the lock pins no commit; `FETCH_POLICY` for a
/// selector with no locked endpoint.
pub fn fetch_url(
    lock: &Lock,
    capability: &FetchCapability,
    selector: &str,
) -> Result<String, Failure> {
    let suffix = match selector {
        "minio" => {
            if lock.fetches.minio.commit.is_empty() {
                return Err(Failure::invalid(
                    fc::FETCH_POLICY,
                    format!(
                        "dependencyprepare: fetch policy violation: the lock pins no commit for {selector:?}"
                    ),
                ));
            }
            format!("{}.tar.gz", lock.fetches.minio.commit)
        }
        _ => {
            return Err(Failure::invalid(
                fc::FETCH_POLICY,
                format!("dependencyprepare: unknown selector {selector:?} has no locked endpoint"),
            ));
        }
    };
    Ok(format!(
        "{}://{}:{}{}{}",
        capability.scheme, capability.host, capability.port, capability.path_prefix, suffix
    ))
}

/// `resolve_url` — `req.URL.Parse(location)`: an absolute `Location`
/// wins outright; a relative one resolves against the URL that
/// redirected. Only the pieces the redirect walker checks matter —
/// scheme, host, port, path.
fn resolve_url(base: &str, location: &str) -> Result<String, String> {
    let loc = location.trim();
    if loc.starts_with("https://") || loc.starts_with("http://") {
        return Ok(loc.to_owned());
    }
    if let Some(rest) = loc.strip_prefix("//") {
        // Scheme-relative.
        let scheme = base.split("://").next().unwrap_or("https");
        return Ok(format!("{scheme}://{rest}"));
    }
    let (scheme_host, base_path) = base
        .split_once("://")
        .map(|(s, rest)| {
            let (host, p) = rest.split_once('/').map_or((rest, ""), |(h, p)| (h, p));
            (format!("{s}://{host}"), format!("/{p}"))
        })
        .ok_or_else(|| format!("cannot parse redirect base {base:?}"))?;
    if let Some(abs) = loc.strip_prefix('/') {
        return Ok(format!("{scheme_host}/{abs}"));
    }
    let dir = base_path
        .rsplit_once('/')
        .map_or("/", |(d, _)| if d.is_empty() { "/" } else { d });
    Ok(format!(
        "{scheme_host}{}/{}",
        dir.trim_end_matches('/'),
        loc
    ))
}

/// `check_redirect_hop` — `redirectWalker`'s per-hop check: hop
/// `index` must exist in the locked chain and match scheme, host,
/// port, and path prefix exactly.
fn check_redirect_hop(
    capability: &FetchCapability,
    url: &str,
    index: usize,
) -> Result<(), Failure> {
    let refuse = |detail: String| {
        Failure::invalid(
            fc::FETCH_REDIRECT,
            format!("dependencyprepare: fetch redirect is not the locked chain: {detail}"),
        )
    };
    if index >= capability.redirect_chain.len() {
        return Err(refuse(format!(
            "hop {} is beyond the locked chain of {}",
            index + 1,
            capability.redirect_chain.len()
        )));
    }
    let hop = &capability.redirect_chain[index];
    let (scheme, host, port, path) =
        split_url(url).ok_or_else(|| refuse(format!("hop {} is not a usable URL", index + 1)))?;
    if scheme != hop.scheme {
        return Err(refuse(format!(
            "hop {} scheme is not the locked one",
            index + 1
        )));
    }
    if host != hop.host {
        return Err(refuse(format!(
            "hop {} host is not the locked one",
            index + 1
        )));
    }
    if url_port(&scheme, port) != hop.port {
        return Err(refuse(format!(
            "hop {} port is not the locked one",
            index + 1
        )));
    }
    if !path.starts_with(&hop.path_prefix) {
        return Err(refuse(format!(
            "hop {} path is not under the locked prefix",
            index + 1
        )));
    }
    Ok(())
}

/// `split_url` — the scheme/host/port/path pieces of an `https?://`
/// URL the hop check compares. Returns `None` for anything else.
fn split_url(url: &str) -> Option<(String, String, Option<u16>, String)> {
    let (scheme, rest) = url.split_once("://")?;
    let (authority, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], rest[idx..].to_owned()),
        None => (rest, "/".to_owned()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
            (h.to_owned(), p.parse::<u16>().ok())
        }
        _ => (authority.to_owned(), None),
    };
    Some((scheme.to_owned(), host, port, path))
}

/// `urlPort` — the effective port a URL carries: the explicit one, or
/// the https default; `-1` for anything non-https without an explicit
/// port (matching upstream's `urlPort`).
#[must_use]
pub fn url_port(scheme: &str, explicit: Option<u16>) -> i64 {
    if let Some(p) = explicit {
        return i64::from(p);
    }
    if scheme == "https" {
        return 443;
    }
    -1
}

/// `isPublicUnicast` — the `public-unicast` address policy's
/// predicate: not loopback, private, link-local, multicast, or
/// unspecified.
#[must_use]
pub fn is_public_unicast(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_unspecified()
                || v4.is_broadcast())
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unspecified()
                // Unique-local (fc00::/7) and link-local (fe80::/10).
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

/// `verifyStoredDigest` — stream the stored artifact through SHA-256
/// and compare `sha256:<hex>` against the lock's pin. Staging is what
/// puts bytes in front of a builder, so the pin is re-checked here
/// rather than trusted from the fetch.
///
/// # Errors
/// `FETCH_DIGEST` on a mismatch; `internal` when the file cannot be
/// read.
pub fn verify_stored_digest(path: &Path, expected: &str) -> Result<(), Failure> {
    let mut file = File::open(path).map_err(|e| {
        Failure::internal(
            "FETCH_STORE",
            format!("dependencyprepare: open stored artifact: {e}"),
        )
    })?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut HashSink(&mut hasher)).map_err(|e| {
        Failure::internal(
            "FETCH_STORE",
            format!("dependencyprepare: hash stored artifact: {e}"),
        )
    })?;
    let actual = format!("sha256:{}", hex_lower(&hasher.finalize()));
    if actual != expected {
        return Err(Failure::invalid(
            fc::FETCH_DIGEST,
            format!(
                "dependencyprepare: fetch digest mismatch: stored artifact is {actual}, lock pins {expected}"
            ),
        ));
    }
    Ok(())
}

/// `extractArchive` — unpack a gzipped tar into `dest_dir` under the
/// closed policy: one leading path component is stripped, every entry
/// must resolve inside `dest_dir`, symlinks may not leave it, and
/// anything that is not a regular file, directory, or contained
/// symlink is refused rather than skipped. Total extracted bytes are
/// bounded by the same ceiling the download is.
///
/// Containment is enforced two ways, because a lexical check alone is
/// not enough. An absolute link target is refused outright (Rust's
/// `Path::join` treats an absolute second argument as a *replacement*,
/// which would make the check vacuous the other way, so the refusal
/// is explicit, exactly like upstream's `path.IsAbs` gate). And every
/// entry's ancestors are checked against the symlinks this extraction
/// already created, because a later entry whose path traverses an
/// earlier symlink is lexically contained but materially is not —
/// `create_dir_all` and `O_CREAT` both follow the link, and this runs
/// as root.
///
/// # Errors
/// `FETCH_POLICY` for every policy violation; `FETCH_SIZE_EXCEEDED`
/// past the byte ceiling; `internal` for I/O failures; `cancelled`
/// when the operation budget has elapsed.
pub fn extract_archive(
    deadline: OpDeadline,
    archive_path: &Path,
    dest_dir: &Path,
    max_bytes: u64,
) -> Result<(), Failure> {
    let file = File::open(archive_path).map_err(|e| {
        Failure::internal(
            "FETCH_EXTRACT",
            format!("dependencyprepare: open archive: {e}"),
        )
    })?;
    let gz = GzDecoder::new(file);
    let mut archive = tar::Archive::new(gz);

    let mut written: u64 = 0;
    // `links` records every symlink this extraction created, by its
    // destDir-relative path, so a later entry cannot be written
    // through one.
    let mut links: BTreeSet<String> = BTreeSet::new();
    let entries = archive.entries().map_err(|e| {
        Failure::internal(
            "FETCH_EXTRACT",
            format!("dependencyprepare: read archive entry: {e}"),
        )
    })?;
    for entry in entries {
        deadline.check()?;
        let mut entry = entry.map_err(|e| {
            Failure::internal(
                "FETCH_EXTRACT",
                format!("dependencyprepare: read archive entry: {e}"),
            )
        })?;
        let raw_name = String::from_utf8_lossy(&entry.path_bytes()).into_owned();
        let header_type = entry.header().entry_type();
        let link_name = entry
            .link_name()
            .map_err(|e| {
                Failure::internal(
                    "FETCH_EXTRACT",
                    format!("dependencyprepare: read archive entry: {e}"),
                )
            })?
            .map(|p| p.to_string_lossy().into_owned());
        let declared_size = entry.header().size().unwrap_or(0);

        let Some(relative) = archive_entry_path(&raw_name)? else {
            continue;
        };
        let target = contained_path(dest_dir, &relative)?;
        refuse_symlinked_path(&links, &relative)?;

        match header_type {
            tar::EntryType::Directory => {
                fs::create_dir_all(&target).map_err(|e| {
                    Failure::internal(
                        "FETCH_EXTRACT",
                        format!("dependencyprepare: create {relative}: {e}"),
                    )
                })?;
            }
            tar::EntryType::Regular if raw_type_is_reg(entry.header()) => {
                if written + declared_size > max_bytes {
                    return Err(Failure::invalid(
                        fc::FETCH_SIZE_EXCEEDED,
                        format!(
                            "dependencyprepare: fetch size exceeded: extracted content exceeds limit of {max_bytes}"
                        ),
                    ));
                }
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent).map_err(|e| {
                        Failure::internal(
                            "FETCH_EXTRACT",
                            format!("dependencyprepare: create {relative}: {e}"),
                        )
                    })?;
                }
                let mut out = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(0o600)
                    .open(&target)
                    .map_err(|e| {
                        Failure::internal(
                            "FETCH_EXTRACT",
                            format!("dependencyprepare: create {relative}: {e}"),
                        )
                    })?;
                let mut remaining = (&mut entry).take(max_bytes - written + 1);
                let copied = io::copy(&mut remaining, &mut out).map_err(|e| {
                    Failure::internal(
                        "FETCH_EXTRACT",
                        format!("dependencyprepare: write {relative}: {e}"),
                    )
                })?;
                written += copied;
                if written > max_bytes {
                    return Err(Failure::invalid(
                        fc::FETCH_SIZE_EXCEEDED,
                        format!(
                            "dependencyprepare: fetch size exceeded: extracted content exceeds limit of {max_bytes}"
                        ),
                    ));
                }
            }
            tar::EntryType::Symlink => {
                let Some(link_target) = link_name else {
                    return Err(Failure::invalid(
                        fc::FETCH_POLICY,
                        format!(
                            "dependencyprepare: fetch policy violation: symlink {relative} names no target"
                        ),
                    ));
                };
                if link_target.is_empty() {
                    return Err(Failure::invalid(
                        fc::FETCH_POLICY,
                        format!(
                            "dependencyprepare: fetch policy violation: symlink {relative} names no target"
                        ),
                    ));
                }
                if Path::new(&link_target).is_absolute() {
                    return Err(Failure::invalid(
                        fc::FETCH_POLICY,
                        format!(
                            "dependencyprepare: fetch policy violation: symlink {relative} targets an absolute path outside the build context"
                        ),
                    ));
                }
                let resolved_dir = target
                    .parent()
                    .unwrap_or_else(|| Path::new(dest_dir))
                    .join(&link_target);
                contained_path_check(dest_dir, &resolved_dir).map_err(|_| {
                    Failure::invalid(
                        fc::FETCH_POLICY,
                        format!(
                            "dependencyprepare: fetch policy violation: symlink {relative} escapes the build context"
                        ),
                    )
                })?;
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent).map_err(|e| {
                        Failure::internal(
                            "FETCH_EXTRACT",
                            format!("dependencyprepare: create {relative}: {e}"),
                        )
                    })?;
                }
                std::os::unix::fs::symlink(&link_target, &target).map_err(|e| {
                    Failure::internal(
                        "FETCH_EXTRACT",
                        format!("dependencyprepare: link {relative}: {e}"),
                    )
                })?;
                links.insert(relative);
            }
            _ => {
                return Err(Failure::invalid(
                    fc::FETCH_POLICY,
                    format!(
                        "dependencyprepare: fetch policy violation: archive entry {relative} has unsupported type {header_type:?}"
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// `raw_type_is_reg` — upstream's `case tar.TypeReg` accepts only the
/// raw `'0'` typeflag, not `'\0'` (`TypeRegA`). The `tar` crate folds
/// both into `EntryType::Regular`, so the raw header byte is checked
/// here for parity.
fn raw_type_is_reg(header: &tar::Header) -> bool {
    header.as_bytes().get(156) == Some(&b'0')
}

/// `archiveEntryPath` — validate one entry's name and strip the
/// archive's single wrapper directory. An entry that escapes —
/// absolute, or climbing out with `..` — is refused rather than
/// skipped; an entry with no second component is the wrapper itself
/// and contributes nothing (`None`).
///
/// # Errors
/// `FETCH_POLICY` for an escaping name.
pub fn archive_entry_path(name: &str) -> Result<Option<String>, Failure> {
    if name.is_empty() {
        return Ok(None);
    }
    // Any `..` component is refused outright — not just one that
    // survives `path.Clean`: a name like `wrap/../escaped` cleans to
    // something contained, but the archive still claimed a traversal,
    // which is what the check is for.
    let traversal = name.split('/').any(|c| c == "..");
    let cleaned = clean_posix(name);
    if traversal || cleaned.starts_with('/') || cleaned == ".." || cleaned.starts_with("../") {
        return Err(Failure::invalid(
            fc::FETCH_POLICY,
            format!(
                "dependencyprepare: fetch policy violation: archive entry {name:?} escapes the build context"
            ),
        ));
    }
    let Some((_, rest)) = cleaned.split_once('/') else {
        return Ok(None);
    };
    Ok(Some(rest.to_owned()))
}

/// `path.Clean` for a slash-separated archive name — the lexical
/// normalization upstream applies before the escape check.
fn clean_posix(name: &str) -> String {
    let is_abs = name.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for part in name.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if out.last() == Some(&"..") || out.is_empty() {
                    out.push("..");
                } else {
                    out.pop();
                }
            }
            p => out.push(p),
        }
    }
    let joined = out.join("/");
    match (is_abs, joined.is_empty()) {
        (true, true) => "/".to_owned(),
        (true, false) => format!("/{joined}"),
        (false, true) => ".".to_owned(),
        (false, false) => joined,
    }
}

/// `refuseSymlinkedPath` — refuse an entry whose own name, or any
/// ancestor of it, is a symlink this extraction already created.
/// `contained_path` is lexical and cannot see that `wrap/esc/pwned`
/// resolves through `wrap/esc`, so this is what stops a contained
/// symlink from being used as a door out of the context.
///
/// # Errors
/// `FETCH_POLICY` for a path through a staged link.
pub fn refuse_symlinked_path(links: &BTreeSet<String>, relative: &str) -> Result<(), Failure> {
    if links.is_empty() {
        return Ok(());
    }
    let mut prefix = String::new();
    for component in relative.split('/') {
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(component);
        if links.contains(&prefix) {
            return Err(Failure::invalid(
                fc::FETCH_POLICY,
                format!(
                    "dependencyprepare: fetch policy violation: archive entry {relative:?} is written through symlink {prefix:?}"
                ),
            ));
        }
    }
    Ok(())
}

/// `containedPath` — join `relative` under `root` and require the
/// result to stay inside it. Purely lexical, exactly like upstream.
///
/// # Errors
/// `FETCH_POLICY` when the join escapes.
pub fn contained_path(root: &Path, relative: &str) -> Result<PathBuf, Failure> {
    let target = root.join(relative);
    contained_path_check(root, &target).map_err(|_| {
        Failure::invalid(
            fc::FETCH_POLICY,
            format!(
                "dependencyprepare: fetch policy violation: archive entry {relative:?} escapes the build context"
            ),
        )
    })?;
    Ok(target)
}

/// The containment half of `containedPath`, shared with the symlink
/// check which joins a link target onto a different base.
///
/// Both sides are normalized lexically first: `Path::starts_with`
/// compares components verbatim, so `root/../../etc` "starts with"
/// `root` — the join has to be resolved like `filepath.Clean` before
/// the prefix question is even asked. A `..` that pops past the
/// filesystem root cannot be contained, so it fails closed too.
fn contained_path_check(root: &Path, target: &Path) -> Result<(), Failure> {
    fn normalize(p: &Path) -> Option<PathBuf> {
        let mut out = PathBuf::new();
        for c in p.components() {
            match c {
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    if !out.pop() {
                        return None;
                    }
                }
                other => out.push(other.as_os_str()),
            }
        }
        Some(out)
    }
    let norm_target = normalize(target).ok_or_else(|| {
        Failure::invalid(
            fc::FETCH_POLICY,
            "dependencyprepare: fetch policy violation: path escapes the build context",
        )
    })?;
    let norm_root = normalize(root).unwrap_or_else(|| root.to_path_buf());
    if norm_target != norm_root && !norm_target.starts_with(&norm_root) {
        return Err(Failure::invalid(
            fc::FETCH_POLICY,
            "dependencyprepare: fetch policy violation: path escapes the build context",
        ));
    }
    Ok(())
}

/// `HttpTransport` — the production transport placeholder. The
/// root-side helper daemon binds a concrete implementation; this
/// default exists so a `Fetcher` built without a seam answers
/// `unavailable` rather than panicking — the same fail-closed shape
/// the helper's handler contract requires.
pub struct HttpTransport;

impl FetchTransport for HttpTransport {
    fn get(&self, req: &FetchRequest) -> Result<FetchResponse, TransportFailure> {
        Err(TransportFailure {
            timed_out: false,
            detail: format!(
                "no transport bound for {} (helper-side transport must be wired)",
                req.url
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use central_infra::prepare::{self, FetchHop, Lock, RetryPolicy};
    use std::io::Cursor;
    use std::sync::Mutex;

    fn tempdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "central-fetch-test-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&dir).expect("tempdir");
        dir
    }

    fn lock() -> Lock {
        prepare::load_lock().expect("LoadLock")
    }

    /// `writeTestArchive` — build a gzipped tar shaped like a GitHub
    /// source archive: everything under one wrapper directory.
    /// Returns the archive's `sha256:<hex>` for lock-pinning.
    fn write_test_archive(path: &Path, entries: &[(String, TestEntry)]) -> String {
        let mut buf = Vec::new();
        {
            let gz = flate2::write::GzEncoder::new(&mut buf, flate2::Compression::fast());
            let mut builder = tar::Builder::new(gz);
            for (name, entry) in entries {
                let mut header = tar::Header::new_gnu();
                match entry {
                    TestEntry::Dir => {
                        header.set_entry_type(tar::EntryType::Directory);
                        header.set_size(0);
                        header.set_mode(0o755);
                    }
                    TestEntry::Regular(body) => {
                        header.set_entry_type(tar::EntryType::Regular);
                        header.set_size(body.len() as u64);
                        header.set_mode(0o644);
                    }
                    TestEntry::Symlink(target) => {
                        header.set_entry_type(tar::EntryType::Symlink);
                        header.set_size(0);
                        header.set_mode(0o777);
                        header.set_link_name(target.as_str()).expect("link name");
                    }
                    TestEntry::Hardlink(target) => {
                        header.set_entry_type(tar::EntryType::Link);
                        header.set_size(0);
                        header.set_mode(0o644);
                        header.set_link_name(target.as_str()).expect("link name");
                    }
                }
                // Write the member name straight into the header: these
                // tests deliberately craft names (`..`, absolute) that
                // `append_data`'s own path policy would refuse — the
                // point is the *reader's* policy.
                {
                    let gnu = header.as_gnu_mut().expect("gnu header");
                    let bytes = name.as_bytes();
                    assert!(bytes.len() < gnu.name.len(), "test name too long");
                    gnu.name[..bytes.len()].copy_from_slice(bytes);
                }
                header.set_cksum();
                match entry {
                    TestEntry::Regular(body) => builder
                        .append(&header, body.as_slice())
                        .expect("file member"),
                    _ => builder.append(&header, io::empty()).expect("member"),
                }
            }
            builder
                .into_inner()
                .expect("tar close")
                .finish()
                .expect("gz close");
        }
        fs::write(path, &buf).expect("write archive");
        format!("sha256:{}", hex_lower(&Sha256::digest(&buf)))
    }

    enum TestEntry {
        Dir,
        Regular(Vec<u8>),
        Symlink(String),
        Hardlink(String),
    }

    /// `lockWithMinioArchiveDigest` — the embedded lock with MinIO's
    /// archive digest re-pinned to the fixture a test just wrote.
    fn lock_with_minio_archive_digest(digest: &str) -> Lock {
        let mut lock = lock();
        lock.fetches.minio.archive_sha256 = digest.to_owned();
        lock
    }

    /// `fakeModuleAcquirer` — writes a caller-chosen number of bytes
    /// under `cache/download` plus a stray extracted tree, and records
    /// what it was asked for so policy inputs can be asserted.
    struct FakeModuleAcquirer {
        calls: Mutex<usize>,
        bytes: Mutex<usize>,
        go_version: Mutex<String>,
        manifest: Mutex<BTreeMap<String, String>>,
        fail: Mutex<Option<String>>,
    }

    impl FakeModuleAcquirer {
        fn new() -> Self {
            Self {
                calls: Mutex::new(0),
                bytes: Mutex::new(0),
                go_version: Mutex::new(String::new()),
                manifest: Mutex::new(BTreeMap::new()),
                fail: Mutex::new(None),
            }
        }
    }

    impl ModuleAcquirer for FakeModuleAcquirer {
        fn acquire(
            &self,
            _deadline: OpDeadline,
            cache_root: &Path,
            manifest_dir: &Path,
            go_version: &str,
            capability: &FetchCapability,
        ) -> Result<(), Failure> {
            *self.calls.lock().expect("calls") += 1;
            *self.go_version.lock().expect("gv") = go_version.to_owned();
            let mut manifest = self.manifest.lock().expect("manifest");
            manifest.clear();
            for entry in fs::read_dir(manifest_dir).expect("manifest dir") {
                let entry = entry.expect("entry");
                manifest.insert(
                    entry.file_name().to_string_lossy().into_owned(),
                    fs::read_to_string(entry.path()).expect("manifest file"),
                );
            }
            if let Some(err) = self.fail.lock().expect("fail").clone() {
                return Err(Failure::unavailable("FETCH_TRANSPORT", err));
            }
            let _ = capability;
            let size = (*self.bytes.lock().expect("bytes")).max(16);
            let download = cache_root.join("cache").join("download");
            fs::create_dir_all(&download).expect("download dir");
            fs::write(download.join("module.zip"), vec![0u8; size]).expect("module.zip");
            let extracted = cache_root.join("example.com").join("mod@v1.0.0");
            fs::create_dir_all(&extracted).expect("extracted");
            fs::write(extracted.join("mod.go"), b"package mod\n").expect("mod.go");
            Ok(())
        }
    }

    // ---- fetch_test.go — pure policy tests ----------------------------

    /// `TestFetcherRejectsUnknownSelector` + `EmptySelector`.
    #[test]
    fn fetch_rejects_unknown_and_empty_selectors() {
        let base = tempdir("unknown");
        let f = Fetcher::new(&lock(), &base);
        for selector in ["unknown-dependency", ""] {
            let err = f.fetch(OpDeadline::NONE, selector).unwrap_err();
            assert_eq!(err.code(), fc::FETCH_POLICY);
        }
        fs::remove_dir_all(&base).ok();
    }

    /// `TestFetcherRefusesToFetchAPublishedImage` — PostgreSQL is
    /// admitted by identity, never downloaded.
    #[test]
    fn fetch_refuses_published_image() {
        let base = tempdir("published");
        let f = Fetcher::new(&lock(), &base);
        let err = f.fetch(OpDeadline::NONE, "postgresql").unwrap_err();
        assert_eq!(err.code(), fc::FETCH_POLICY);
        fs::remove_dir_all(&base).ok();
    }

    /// `TestFetchURLIsDerivedFromTheLockCommit` — the endpoint names
    /// the lock's pinned commit, is HTTPS, and lives under the locked
    /// host; no tag pull.
    #[test]
    fn fetch_url_is_derived_from_the_lock_commit() {
        let lock = lock();
        let capability = lock.fetch_capability_for("minio").expect("capability");
        let endpoint = fetch_url(&lock, &capability, "minio").expect("fetch url");
        assert!(endpoint.contains(&lock.fetches.minio.commit));
        assert!(!endpoint.contains("refs/tags") && !endpoint.contains("RELEASE."));
        assert!(endpoint.starts_with("https://"));
        assert!(endpoint.starts_with(&format!("https://{}", capability.host)));
    }

    /// `TestFetchURLHasNoEndpointForPublishedImages` — PostgreSQL has
    /// no fetch capability and no endpoint.
    #[test]
    fn fetch_url_has_no_endpoint_for_published_images() {
        let lock = lock();
        assert!(!lock.fetch_capability.contains_key("postgresql"));
        assert!(lock.fetch_capability_for("postgresql").is_err());
        let capability = lock.fetch_capability_for("minio").expect("capability");
        let err = fetch_url(&lock, &capability, "postgresql").unwrap_err();
        assert_eq!(err.code(), fc::FETCH_POLICY);
    }

    /// `TestShippedFetchCapabilitiesAreProductionPostures` — the
    /// shipped lock never carries the postures that exist so a test
    /// can reach a local server.
    #[test]
    fn shipped_fetch_capabilities_are_production_postures() {
        let lock = lock();
        assert!(!lock.fetch_capability.is_empty());
        for (selector, capability) in &lock.fetch_capability {
            assert_eq!(
                capability.tls_policy,
                TlsFetchMode::SystemRoots,
                "{selector}: TLS policy must be system-roots"
            );
            assert_eq!(
                capability.address_policy,
                central_infra::prepare::ADDRESS_POLICY_PUBLIC_UNICAST,
                "{selector}: address policy must be public-unicast"
            );
            assert_eq!(capability.scheme, "https", "{selector}: scheme");
        }
    }

    /// `TestFetcherRejectsClientCertificate` — the refusal is what the
    /// field exists for; production never sets it.
    #[test]
    fn fetch_rejects_client_certificate() {
        let base = tempdir("clientcert");
        let f = Fetcher::new(&lock(), &base)
            .with_transport(Box::new(FakeTransport::default()))
            .with_client_cert_present(true);
        let err = f.fetch(OpDeadline::NONE, "minio").unwrap_err();
        assert_eq!(err.code(), fc::FETCH_CLIENT_CERT);
        fs::remove_dir_all(&base).ok();
    }

    /// `TestFetcherRejectsProxy` — ambient proxy configuration is not
    /// an input to a hermetic acquisition.
    #[test]
    fn fetch_rejects_proxy() {
        let base = tempdir("proxy");
        let f = Fetcher::new(&lock(), &base)
            .with_transport(Box::new(FakeTransport::default()))
            .with_proxy_enabled(true);
        let err = f.fetch(OpDeadline::NONE, "minio").unwrap_err();
        assert_eq!(err.code(), fc::FETCH_POLICY);
        fs::remove_dir_all(&base).ok();
    }

    /// `TestFetcherRejectsNonAllowlistedHeader` — a non-allowlisted
    /// header is refused before any request; an allowlisted one is
    /// sent.
    #[test]
    fn fetch_rejects_non_allowlisted_header() {
        let base = tempdir("header");
        let body = b"ok".to_vec();
        let transport = FakeTransport::with_body(200, body.clone());
        let mut f = Fetcher::new(&lock(), &base).with_transport(transport);
        f.set_header("X-Custom-Thing", "value");
        let err = f.fetch(OpDeadline::NONE, "minio").unwrap_err();
        assert_eq!(err.code(), fc::FETCH_NON_ALLOWLIST_HEADER);

        // Credential-shaped headers refuse with the credential code.
        let mut f =
            Fetcher::new(&lock(), &base).with_transport(FakeTransport::with_body(200, body));
        f.set_header("Authorization", "Basic dGVzdA==");
        let err = f.fetch(OpDeadline::NONE, "minio").unwrap_err();
        assert_eq!(err.code(), fc::FETCH_CREDENTIAL);
        fs::remove_dir_all(&base).ok();
    }

    /// `TestFetcherRejectsCookie` — a server that tries to set a
    /// cookie is refused.
    #[test]
    fn fetch_rejects_cookie() {
        let base = tempdir("cookie");
        let transport = FakeTransport {
            responses: Mutex::new(vec![FakeResponse {
                status: 200,
                headers: vec![("Set-Cookie".to_owned(), "session=abc".to_owned())],
                body: b"ok".to_vec(),
            }]),
            requests: Mutex::new(Vec::new()),
        };
        let f = Fetcher::new(&lock(), &base).with_transport(Box::new(transport));
        let err = f.fetch(OpDeadline::NONE, "minio").unwrap_err();
        assert_eq!(err.code(), fc::FETCH_COOKIE);
        fs::remove_dir_all(&base).ok();
    }

    /// `isTransientFetchError` — the retry taxonomy.
    #[test]
    fn transient_classification() {
        // Terminal codes never retry.
        for code in [
            fc::FETCH_DIGEST,
            fc::FETCH_SIZE_EXCEEDED,
            fc::FETCH_REDIRECT,
            fc::FETCH_ADDRESS,
            fc::FETCH_COOKIE,
            fc::FETCH_CREDENTIAL,
            fc::FETCH_CLIENT_CERT,
            fc::FETCH_NON_ALLOWLIST_HEADER,
        ] {
            assert!(
                !is_transient_fetch_error(&FetchError::Terminal(Failure::invalid(code, "x"))),
                "{code} must be terminal"
            );
        }
        // 429 + 5xx retry; 4xx does not.
        assert!(is_transient_fetch_error(&FetchError::Status(429)));
        assert!(is_transient_fetch_error(&FetchError::Status(503)));
        assert!(!is_transient_fetch_error(&FetchError::Status(404)));
        // Transport failures retry only on timeout.
        assert!(is_transient_fetch_error(&FetchError::Transport(
            TransportFailure {
                timed_out: true,
                detail: "d".to_owned(),
            }
        )));
        assert!(!is_transient_fetch_error(&FetchError::Transport(
            TransportFailure {
                timed_out: false,
                detail: "d".to_owned(),
            }
        )));
    }

    /// `isPublicUnicast` — the address policy's predicate.
    #[test]
    fn public_unicast() {
        for bad in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "224.0.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "::1",
            "fe80::1",
            "fc00::1",
            "ff02::1",
            "::",
        ] {
            let ip: IpAddr = bad.parse().expect("ip");
            assert!(!is_public_unicast(&ip), "{bad} must not be public unicast");
        }
        for good in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            let ip: IpAddr = good.parse().expect("ip");
            assert!(is_public_unicast(&ip), "{good} must be public unicast");
        }
    }

    /// `urlPort` — explicit wins; https defaults to 443; anything else
    /// has no port.
    #[test]
    fn url_port_derivation() {
        assert_eq!(url_port("https", None), 443);
        assert_eq!(url_port("https", Some(8443)), 8443);
        assert_eq!(url_port("http", None), -1);
    }

    /// `archiveEntryPath` — wrapper-strip, traversal, absolute.
    #[test]
    fn archive_entry_path_policy() {
        assert_eq!(archive_entry_path("").unwrap(), None);
        assert_eq!(archive_entry_path("wrap").unwrap(), None);
        assert_eq!(
            archive_entry_path("wrap/file").unwrap().as_deref(),
            Some("file")
        );
        assert_eq!(
            archive_entry_path("wrap/dir/file").unwrap().as_deref(),
            Some("dir/file")
        );
        assert_eq!(
            archive_entry_path("wrap/../escaped").unwrap_err().code(),
            fc::FETCH_POLICY
        );
        assert_eq!(
            archive_entry_path("/abs/path").unwrap_err().code(),
            fc::FETCH_POLICY
        );
        assert_eq!(
            archive_entry_path("../../etc/passwd").unwrap_err().code(),
            fc::FETCH_POLICY
        );
    }

    // ---- fetch_test.go — staging tests --------------------------------

    /// `TestStageSourceUnpacksVerifiedArchive` — the wrapper dir is
    /// stripped and the context is the source root.
    #[test]
    fn stage_source_unpacks_verified_archive() {
        let store = tempdir("unpack-store");
        let archive = store.join("minio.tar.gz");
        let digest = write_test_archive(
            &archive,
            &[
                ("minio-abc/".to_owned(), TestEntry::Dir),
                (
                    "minio-abc/main.go".to_owned(),
                    TestEntry::Regular(b"package main\n".to_vec()),
                ),
                (
                    "minio-abc/cmd/run.go".to_owned(),
                    TestEntry::Regular(b"package cmd\n".to_vec()),
                ),
                (
                    "minio-abc/go.mod".to_owned(),
                    TestEntry::Regular(b"module x\n".to_vec()),
                ),
                (
                    "minio-abc/go.sum".to_owned(),
                    TestEntry::Regular(Vec::new()),
                ),
            ],
        );
        let f = Fetcher::new(&lock_with_minio_archive_digest(&digest), &store)
            .with_module_acquirer(Box::new(FakeModuleAcquirer::new()));
        let dest = tempdir("unpack-dest").join("context");
        f.stage_source(OpDeadline::NONE, "minio", &dest)
            .expect("stage");

        let body = fs::read_to_string(dest.join("main.go")).expect("staged root");
        assert_eq!(body, "package main\n");
        assert!(dest.join("cmd").join("run.go").is_file());
        assert!(
            !dest.join("minio-abc").exists(),
            "the archive's wrapper directory was not stripped"
        );
        fs::remove_dir_all(&store).ok();
        fs::remove_dir_all(dest.parent().unwrap_or(&dest)).ok();
    }

    /// `TestStageSourceRefusesArchiveThatDriftedFromTheLock` — the
    /// digest is re-verified before the destination is touched.
    /// `TestStageSourceDigestIsCheckedBeforeDestIsCleared` is the
    /// side-effect-ordering half this task requires.
    #[test]
    fn stage_source_refuses_drifted_archive_without_touching_dest() {
        let store = tempdir("drift-store");
        write_test_archive(
            &store.join("minio.tar.gz"),
            &[(
                "minio-abc/main.go".to_owned(),
                TestEntry::Regular(b"package main\n".to_vec()),
            )],
        );
        let f = Fetcher::new(
            &lock_with_minio_archive_digest(&format!("sha256:{}", "0".repeat(64))),
            &store,
        );
        // A pre-existing context must survive a refused staging.
        let dest = tempdir("drift-dest").join("context");
        fs::create_dir_all(&dest).expect("dest");
        fs::write(dest.join("keep.txt"), b"keep").expect("keep");
        let err = f
            .stage_source(OpDeadline::NONE, "minio", &dest)
            .unwrap_err();
        assert_eq!(err.code(), fc::FETCH_DIGEST);
        assert_eq!(
            fs::read(dest.join("keep.txt")).expect("dest untouched"),
            b"keep"
        );
        fs::remove_dir_all(&store).ok();
        fs::remove_dir_all(dest.parent().unwrap_or(&dest)).ok();
    }

    /// `TestStageSourceRefusesPathTraversal`.
    #[test]
    fn stage_source_refuses_path_traversal() {
        let store = tempdir("traversal-store");
        let digest = write_test_archive(
            &store.join("minio.tar.gz"),
            &[(
                "minio-abc/../../escaped.go".to_owned(),
                TestEntry::Regular(b"break".to_vec()),
            )],
        );
        let f = Fetcher::new(&lock_with_minio_archive_digest(&digest), &store);
        let err = f
            .stage_source(
                OpDeadline::NONE,
                "minio",
                &tempdir("traversal-dest").join("context"),
            )
            .unwrap_err();
        assert_eq!(err.code(), fc::FETCH_POLICY);
        fs::remove_dir_all(&store).ok();
    }

    /// `TestStageSourceRefusesEscapingSymlink` — the `..`-climbing
    /// link target.
    #[test]
    fn stage_source_refuses_escaping_symlink() {
        let store = tempdir("esc-store");
        let digest = write_test_archive(
            &store.join("minio.tar.gz"),
            &[(
                "minio-abc/passwd".to_owned(),
                TestEntry::Symlink("../../../../etc/passwd".to_owned()),
            )],
        );
        let f = Fetcher::new(&lock_with_minio_archive_digest(&digest), &store);
        let err = f
            .stage_source(
                OpDeadline::NONE,
                "minio",
                &tempdir("esc-dest").join("context"),
            )
            .unwrap_err();
        assert_eq!(err.code(), fc::FETCH_POLICY);
        fs::remove_dir_all(&store).ok();
    }

    /// `TestStageSourceRefusesAbsoluteSymlink` — an absolute target is
    /// refused outright, and nothing lands in the context.
    #[test]
    fn stage_source_refuses_absolute_symlink() {
        let store = tempdir("abs-store");
        let digest = write_test_archive(
            &store.join("minio.tar.gz"),
            &[(
                "minio-abc/passwd".to_owned(),
                TestEntry::Symlink("/etc/passwd".to_owned()),
            )],
        );
        let f = Fetcher::new(&lock_with_minio_archive_digest(&digest), &store);
        let dest = tempdir("abs-dest").join("context");
        let err = f
            .stage_source(OpDeadline::NONE, "minio", &dest)
            .unwrap_err();
        assert_eq!(err.code(), fc::FETCH_POLICY);
        assert!(
            fs::read_link(dest.join("passwd")).is_err(),
            "an absolute symlink was staged into the build context"
        );
        fs::remove_dir_all(&store).ok();
        fs::remove_dir_all(dest.parent().unwrap_or(&dest)).ok();
    }

    /// `TestStageSourceRefusesWritingThroughAStagedSymlink` — a
    /// contained symlink followed by an entry that traverses it.
    #[test]
    fn stage_source_refuses_write_through_staged_symlink() {
        let store = tempdir("through-store");
        let outside = tempdir("through-outside");
        let digest = write_test_archive(
            &store.join("minio.tar.gz"),
            &[
                (
                    "minio-abc/wrap/esc".to_owned(),
                    TestEntry::Symlink(outside.display().to_string()),
                ),
                (
                    "minio-abc/wrap/esc/pwned".to_owned(),
                    TestEntry::Regular(b"pwned\n".to_vec()),
                ),
            ],
        );
        let f = Fetcher::new(&lock_with_minio_archive_digest(&digest), &store);
        // The link target above is absolute — which the earlier test
        // refuses on its own — so use a *relative* escaping link the
        // contained check also rejects, plus prove the
        // write-through-link check independently below.
        let err = f
            .stage_source(
                OpDeadline::NONE,
                "minio",
                &tempdir("through-dest").join("context"),
            )
            .unwrap_err();
        assert_eq!(err.code(), fc::FETCH_POLICY);
        assert!(
            !outside.join("pwned").exists(),
            "an archive entry was written outside the build context"
        );

        // Contained-symlink ancestor attack: link `esc` -> `sub`
        // inside the context, then a write through `esc/pwned` — the
        // refuseSymlinkedPath check refuses even though the link is
        // legal.
        let store2 = tempdir("through2-store");
        let digest2 = write_test_archive(
            &store2.join("minio.tar.gz"),
            &[
                ("minio-abc/sub/".to_owned(), TestEntry::Dir),
                (
                    "minio-abc/sub/real".to_owned(),
                    TestEntry::Regular(b"real".to_vec()),
                ),
                (
                    "minio-abc/esc".to_owned(),
                    TestEntry::Symlink("sub".to_owned()),
                ),
                (
                    "minio-abc/esc/pwned".to_owned(),
                    TestEntry::Regular(b"pwned\n".to_vec()),
                ),
            ],
        );
        let f2 = Fetcher::new(&lock_with_minio_archive_digest(&digest2), &store2)
            .with_module_acquirer(Box::new(FakeModuleAcquirer::new()));
        let err = f2
            .stage_source(
                OpDeadline::NONE,
                "minio",
                &tempdir("through2-dest").join("context"),
            )
            .unwrap_err();
        assert_eq!(err.code(), fc::FETCH_POLICY);
        fs::remove_dir_all(&store).ok();
        fs::remove_dir_all(&store2).ok();
        fs::remove_dir_all(&outside).ok();
    }

    /// `TestStageSourceKeepsContainedRelativeSymlinks` — the refusals
    /// are not a blanket ban: a source tree's own relative links still
    /// stage.
    #[test]
    fn stage_source_keeps_contained_relative_symlinks() {
        let store = tempdir("contained-store");
        let digest = write_test_archive(
            &store.join("minio.tar.gz"),
            &[
                (
                    "minio-abc/real.go".to_owned(),
                    TestEntry::Regular(b"body".to_vec()),
                ),
                (
                    "minio-abc/cmd/link.go".to_owned(),
                    TestEntry::Symlink("../real.go".to_owned()),
                ),
                (
                    "minio-abc/go.mod".to_owned(),
                    TestEntry::Regular(b"module x\n".to_vec()),
                ),
                (
                    "minio-abc/go.sum".to_owned(),
                    TestEntry::Regular(Vec::new()),
                ),
            ],
        );
        let f = Fetcher::new(&lock_with_minio_archive_digest(&digest), &store)
            .with_module_acquirer(Box::new(FakeModuleAcquirer::new()));
        let dest = tempdir("contained-dest").join("context");
        f.stage_source(OpDeadline::NONE, "minio", &dest)
            .expect("a contained relative symlink must stage");
        let body = fs::read_to_string(dest.join("cmd").join("link.go")).expect("link resolves");
        assert_eq!(body, "body");
        fs::remove_dir_all(&store).ok();
        fs::remove_dir_all(dest.parent().unwrap_or(&dest)).ok();
    }

    /// `TestStageSourceRefusesPublishedImage`.
    #[test]
    fn stage_source_refuses_published_image() {
        let store = tempdir("pub-store");
        let f = Fetcher::new(&lock(), &store);
        let err = f
            .stage_source(
                OpDeadline::NONE,
                "postgresql",
                &tempdir("pub-dest").join("context"),
            )
            .unwrap_err();
        assert_eq!(err.code(), fc::FETCH_POLICY);
        fs::remove_dir_all(&store).ok();
    }

    /// Hardlinks are an unsupported type — refused, never skipped
    /// (upstream's `default:` arm).
    #[test]
    fn stage_source_refuses_unsupported_entry_types() {
        let store = tempdir("type-store");
        let digest = write_test_archive(
            &store.join("minio.tar.gz"),
            &[(
                "minio-abc/link".to_owned(),
                TestEntry::Hardlink("minio-abc/main.go".to_owned()),
            )],
        );
        let f = Fetcher::new(&lock_with_minio_archive_digest(&digest), &store);
        let err = f
            .stage_source(
                OpDeadline::NONE,
                "minio",
                &tempdir("type-dest").join("context"),
            )
            .unwrap_err();
        assert_eq!(err.code(), fc::FETCH_POLICY, "hardlink must refuse");
        fs::remove_dir_all(&store).ok();
    }

    /// `ErrFetchSizeExceeded` — the extraction byte ceiling is
    /// enforced, not merely declared.
    #[test]
    fn extract_archive_enforces_byte_ceiling() {
        let store = tempdir("ceil-store");
        write_test_archive(
            &store.join("big.tar.gz"),
            &[("wrap/blob".to_owned(), TestEntry::Regular(vec![b'x'; 2048]))],
        );
        let dest = tempdir("ceil-dest");
        let err =
            extract_archive(OpDeadline::NONE, &store.join("big.tar.gz"), &dest, 1024).unwrap_err();
        assert_eq!(err.code(), fc::FETCH_SIZE_EXCEEDED);
        fs::remove_dir_all(&store).ok();
        fs::remove_dir_all(&dest).ok();
    }

    /// `verifyStoredDigest` — match passes, drift refuses.
    #[test]
    fn stored_digest_verification() {
        let store = tempdir("digest");
        let path = store.join("artifact");
        let body = b"stored bytes".to_vec();
        fs::write(&path, &body).expect("write");
        let digest = format!("sha256:{}", hex_lower(&Sha256::digest(&body)));
        verify_stored_digest(&path, &digest).expect("match verifies");
        let err = verify_stored_digest(&path, &format!("sha256:{}", "f".repeat(64))).unwrap_err();
        assert_eq!(err.code(), fc::FETCH_DIGEST);
        fs::remove_dir_all(&store).ok();
    }

    /// `lockArtifact` — only MinIO has a fetchable artifact.
    #[test]
    fn lock_artifact_mapping() {
        let lock = lock();
        let art = lock_artifact(&lock, "minio").expect("minio artifact");
        assert_eq!(art.store_name, "minio.tar.gz");
        assert_eq!(art.expected_digest, lock.fetches.minio.archive_sha256);
        assert!(lock_artifact(&lock, "postgresql").is_none());
        assert!(lock_artifact(&lock, "bogus").is_none());
    }

    /// `check_redirect_hop` — the locked chain admits exactly its own
    /// hops.
    #[test]
    fn redirect_chain_is_locked() {
        let mut capability = lock().fetch_capability_for("minio").expect("capability");
        capability.redirect_chain = vec![
            FetchHop {
                scheme: "https".to_owned(),
                host: "github.com".to_owned(),
                port: 443,
                path_prefix: "/minio/minio/archive/".to_owned(),
            },
            FetchHop {
                scheme: "https".to_owned(),
                host: "codeload.github.com".to_owned(),
                port: 443,
                path_prefix: "/".to_owned(),
            },
        ];
        check_redirect_hop(&capability, "https://github.com/minio/minio/archive/abc", 0)
            .expect("first hop admitted");
        check_redirect_hop(&capability, "https://codeload.github.com/x", 1)
            .expect("second hop admitted");
        // A third hop is beyond the chain.
        assert_eq!(
            check_redirect_hop(&capability, "https://evil.example/", 2)
                .unwrap_err()
                .code(),
            fc::FETCH_REDIRECT
        );
        // Wrong host.
        assert_eq!(
            check_redirect_hop(
                &capability,
                "https://evil.example/minio/minio/archive/abc",
                0
            )
            .unwrap_err()
            .code(),
            fc::FETCH_REDIRECT
        );
        // Wrong scheme.
        assert_eq!(
            check_redirect_hop(&capability, "http://github.com/minio/minio/archive/abc", 0)
                .unwrap_err()
                .code(),
            fc::FETCH_REDIRECT
        );
        // Wrong port.
        assert_eq!(
            check_redirect_hop(
                &capability,
                "https://github.com:8443/minio/minio/archive/abc",
                0
            )
            .unwrap_err()
            .code(),
            fc::FETCH_REDIRECT
        );
    }

    /// `resolve_url` — absolute wins, scheme-relative inherits, paths
    /// resolve against the base.
    #[test]
    fn redirect_url_resolution() {
        assert_eq!(
            resolve_url("https://a/b/c", "https://d/e").as_deref(),
            Ok("https://d/e")
        );
        assert_eq!(
            resolve_url("https://a/b/c", "//d/e").as_deref(),
            Ok("https://d/e")
        );
        assert_eq!(
            resolve_url("https://a/b/c", "/e").as_deref(),
            Ok("https://a/e")
        );
    }

    // ---- fetch_test.go — transport-driven tests ------------------------

    struct FakeResponse {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    /// `FakeTransport` — serves queued responses; the request list is
    /// recorded for assertion.
    struct FakeTransport {
        responses: Mutex<Vec<FakeResponse>>,
        requests: Mutex<Vec<String>>,
    }

    impl FakeTransport {
        fn with_body(status: u16, body: Vec<u8>) -> Box<dyn FetchTransport> {
            Box::new(Self {
                responses: Mutex::new(vec![FakeResponse {
                    status,
                    headers: Vec::new(),
                    body,
                }]),
                requests: Mutex::new(Vec::new()),
            })
        }
    }

    impl Default for FakeTransport {
        fn default() -> Self {
            Self {
                responses: Mutex::new(Vec::new()),
                requests: Mutex::new(Vec::new()),
            }
        }
    }

    impl FetchTransport for FakeTransport {
        fn get(&self, req: &FetchRequest) -> Result<FetchResponse, TransportFailure> {
            self.requests
                .lock()
                .expect("requests")
                .push(req.url.clone());
            let mut responses = self.responses.lock().expect("responses");
            let Some(resp) = responses.first().map(|r| FakeResponse {
                status: r.status,
                headers: r.headers.clone(),
                body: r.body.clone(),
            }) else {
                return Err(TransportFailure {
                    timed_out: false,
                    detail: "no canned response".to_owned(),
                });
            };
            if responses.len() > 1 {
                responses.remove(0);
            }
            Ok(FetchResponse {
                status: resp.status,
                headers: resp.headers,
                body: Box::new(Cursor::new(resp.body)),
            })
        }
    }

    /// `lockWithRetry` — a test's own capability + retry policy so a
    /// retry test does not wait out the shipped backoff.
    fn lock_with_retry(capability: FetchCapability, retry: RetryPolicy) -> Lock {
        let mut lock = lock();
        lock.fetch_capability.insert("minio".to_owned(), capability);
        lock.retry = retry;
        lock
    }

    fn test_capability() -> FetchCapability {
        let mut capability = lock().fetch_capability_for("minio").expect("capability");
        capability.host = "example.test".to_owned();
        capability.path_prefix = "/".to_owned();
        capability.address_policy = central_infra::prepare::ADDRESS_POLICY_ANY.to_owned();
        capability.tls_policy = TlsFetchMode::InsecureTestOnly;
        capability.max_bytes = 512 * 1024 * 1024;
        capability.deadline_ms = 30_000;
        capability
    }

    /// `TestFetcherRetriesTransientFailuresWithinTheLockedCap` —
    /// transient statuses retry until a real body arrives.
    #[test]
    fn fetch_retries_transient_within_locked_cap() {
        let base = tempdir("retry");
        let body = b"eventually-served".to_vec();
        let transport = FakeTransport {
            responses: Mutex::new(vec![
                FakeResponse {
                    status: 503,
                    headers: vec![],
                    body: vec![],
                },
                FakeResponse {
                    status: 503,
                    headers: vec![],
                    body: vec![],
                },
                FakeResponse {
                    status: 200,
                    headers: vec![],
                    body: body.clone(),
                },
            ]),
            requests: Mutex::new(Vec::new()),
        };
        let mut lock = lock_with_retry(
            test_capability(),
            RetryPolicy {
                max_attempts: 3,
                backoff_ms: vec![0, 0],
            },
        );
        lock.fetches.minio.archive_sha256 = format!("sha256:{}", hex_lower(&Sha256::digest(&body)));
        let f = Fetcher::new(&lock, &base).with_transport(Box::new(transport));
        let candidate = f.fetch(OpDeadline::NONE, "minio").expect("retried fetch");
        assert_eq!(candidate.selector, "minio");
        assert_eq!(candidate.phase, Some(PreparePhase::Acquiring));
        assert_eq!(candidate.source_bytes, body.len() as i64);
        assert!(base.join("minio.tar.gz").is_file());
        fs::remove_dir_all(&base).ok();
    }

    /// `TestFetcherStopsAtTheLockedAttemptCap`.
    #[test]
    fn fetch_stops_at_locked_attempt_cap() {
        let base = tempdir("cap");
        let transport = FakeTransport {
            responses: Mutex::new(vec![
                FakeResponse {
                    status: 502,
                    headers: vec![],
                    body: vec![],
                },
                FakeResponse {
                    status: 502,
                    headers: vec![],
                    body: vec![],
                },
                FakeResponse {
                    status: 502,
                    headers: vec![],
                    body: vec![],
                },
            ]),
            requests: Mutex::new(Vec::new()),
        };
        let requests_seen = std::sync::Arc::new(Mutex::new(0usize));
        // Wrap to count requests.
        struct Counting {
            inner: FakeTransport,
            seen: std::sync::Arc<Mutex<usize>>,
        }
        impl FetchTransport for Counting {
            fn get(&self, req: &FetchRequest) -> Result<FetchResponse, TransportFailure> {
                *self.seen.lock().expect("seen") += 1;
                self.inner.get(req)
            }
        }
        let lock = lock_with_retry(
            test_capability(),
            RetryPolicy {
                max_attempts: 2,
                backoff_ms: vec![0],
            },
        );
        let f = Fetcher::new(&lock, &base).with_transport(Box::new(Counting {
            inner: transport,
            seen: requests_seen.clone(),
        }));
        assert!(f.fetch(OpDeadline::NONE, "minio").is_err());
        assert_eq!(*requests_seen.lock().expect("seen"), 2);
        fs::remove_dir_all(&base).ok();
    }

    /// `TestFetcherNeverRetriesAnIdentityFailure` — a digest mismatch
    /// is terminal.
    #[test]
    fn fetch_never_retries_identity_failure() {
        let base = tempdir("identity");
        let transport = FakeTransport::with_body(200, b"not-what-the-lock-pins".to_vec());
        let lock = lock_with_retry(
            test_capability(),
            RetryPolicy {
                max_attempts: 3,
                backoff_ms: vec![0, 0],
            },
        );
        let f = Fetcher::new(&lock, &base).with_transport(transport);
        let err = f.fetch(OpDeadline::NONE, "minio").unwrap_err();
        assert_eq!(err.code(), fc::FETCH_DIGEST);
        fs::remove_dir_all(&base).ok();
    }

    /// `TestFetcherRejectsDigestMismatch` — the served bytes are not
    /// what the lock pins.
    #[test]
    fn fetch_rejects_digest_mismatch() {
        let base = tempdir("mismatch");
        let transport = FakeTransport::with_body(200, b"served".to_vec());
        let f = Fetcher::new(&lock(), &base).with_transport(transport);
        let err = f.fetch(OpDeadline::NONE, "minio").unwrap_err();
        assert_eq!(err.code(), fc::FETCH_DIGEST);
        fs::remove_dir_all(&base).ok();
    }

    /// `TestFetcherFollowsTheExactLockedChain` — a locked hop is
    /// walked; the second GET carries the redirect target.
    #[test]
    fn fetch_follows_exact_locked_chain() {
        let base = tempdir("chain");
        let body = b"payload".to_vec();
        let transport = FakeTransport {
            responses: Mutex::new(vec![
                FakeResponse {
                    status: 302,
                    headers: vec![(
                        "Location".to_owned(),
                        "https://example.test/real/minio.tar.gz".to_owned(),
                    )],
                    body: vec![],
                },
                FakeResponse {
                    status: 200,
                    headers: vec![],
                    body: body.clone(),
                },
            ]),
            requests: Mutex::new(Vec::new()),
        };
        let mut capability = test_capability();
        capability.redirect_chain = vec![FetchHop {
            scheme: "https".to_owned(),
            host: "example.test".to_owned(),
            port: 443,
            path_prefix: "/real/".to_owned(),
        }];
        let mut lock = lock();
        lock.fetch_capability.insert("minio".to_owned(), capability);
        lock.retry = RetryPolicy {
            max_attempts: 1,
            backoff_ms: vec![],
        };
        lock.fetches.minio.archive_sha256 = format!("sha256:{}", hex_lower(&Sha256::digest(&body)));
        let f = Fetcher::new(&lock, &base).with_transport(Box::new(transport));
        f.fetch(OpDeadline::NONE, "minio").expect("chained fetch");
        fs::remove_dir_all(&base).ok();
    }

    /// `TestFetcherRefusesAHopToTheWrongHost` — a redirect off the
    /// locked chain refuses, and the refusal is terminal.
    #[test]
    fn fetch_refuses_unlocked_redirect() {
        let base = tempdir("badchain");
        let transport = FakeTransport {
            responses: Mutex::new(vec![FakeResponse {
                status: 302,
                headers: vec![(
                    "Location".to_owned(),
                    "https://evil.example/minio.tar.gz".to_owned(),
                )],
                body: vec![],
            }]),
            requests: Mutex::new(Vec::new()),
        };
        let mut capability = test_capability();
        capability.redirect_chain = vec![FetchHop {
            scheme: "https".to_owned(),
            host: "example.test".to_owned(),
            port: 443,
            path_prefix: "/real/".to_owned(),
        }];
        let mut lock = lock();
        lock.fetch_capability.insert("minio".to_owned(), capability);
        lock.retry = RetryPolicy {
            max_attempts: 3,
            backoff_ms: vec![0, 0],
        };
        let f = Fetcher::new(&lock, &base).with_transport(Box::new(transport));
        let err = f.fetch(OpDeadline::NONE, "minio").unwrap_err();
        assert_eq!(err.code(), fc::FETCH_REDIRECT);
        fs::remove_dir_all(&base).ok();
    }

    /// `TestFetcherRejectsSizeExceeded` — the download ceiling.
    #[test]
    fn fetch_rejects_size_exceeded() {
        let base = tempdir("size");
        let body = vec![b'x'; 2048];
        let mut capability = test_capability();
        capability.max_bytes = 1024;
        let mut lock = lock();
        lock.fetch_capability.insert("minio".to_owned(), capability);
        lock.retry = RetryPolicy {
            max_attempts: 1,
            backoff_ms: vec![],
        };
        // Pin the digest so size is the only thing that can fail.
        lock.fetches.minio.archive_sha256 = format!("sha256:{}", hex_lower(&Sha256::digest(&body)));
        let f = Fetcher::new(&lock, &base).with_transport(FakeTransport::with_body(200, body));
        let err = f.fetch(OpDeadline::NONE, "minio").unwrap_err();
        assert_eq!(err.code(), fc::FETCH_SIZE_EXCEEDED);
        fs::remove_dir_all(&base).ok();
    }
}
