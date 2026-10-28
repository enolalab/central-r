//! `infra::prepare` — the R5 B02 Linux adapter for dependency
//! preparation (upstream `internal/adapter/dependencyprepare`). This
//! module owns every OS/process/filesystem/transport boundary the
//! prepare pipeline touches: the confined release-tree reader
//! (`openat2`, Go `os.Root` semantics), the lock adapter, the OCI
//! inventory comparator, the statfs capacity check, the verified
//! archive fetch + staging path, the Go module-cache acquirer, the
//! hermetic BuildKit driver, and the release staging/inventory
//! readers. The domain side — the shipped lock, its digests, and all
//! policy decisions — lives in `central_infra::prepare`; nothing here
//! decides what is allowed, only whether the boundary was honored.
//!
//! Ordering invariant (mirrored from upstream): verification always
//! precedes side effects. `StageSource` re-checks the stored archive's
//! digest before the destination directory is cleared; `StageReleaseDir`
//! refuses an unknown or over-cap tree before a single byte is staged;
//! `Build` refuses an unbound or non-isolated request before `docker`
//! is ever consulted.

pub mod attestation;
pub mod buildkit;
pub mod capacity;
pub mod fetch;
pub mod image_load;
pub mod journal;
pub mod lock;
pub mod module_cache;
pub mod oci;
pub mod release;
pub mod release_stage;
pub mod service;
pub mod state_machine;
pub mod store;
pub mod version_zero;

use std::fs::File;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

use central_foundation::failure::Failure;
use rustix::fs::{Mode, OFlags, ResolveFlags};

pub use attestation::{
    ATTESTATION_KEY_ENV, AttestationService, AttestationSigner, AttestationVerifier, Attestor,
    attestation_key_path, load_attestation_signer,
};
pub use buildkit::{
    BUILD_KIT_DAEMON_IMAGE, BuildKit, DETERMINISTIC_SOURCE_DATE_EPOCH, build_recipe_is_go,
    inventory_from_oci_layout, parse_build_recipe,
};
pub use capacity::{CapacityChecker, RESERVED_CAPACITY_BYTES};
pub use fetch::{
    ArtifactInfo, FetchTransport, Fetcher, HttpTransport, TransportFailure, archive_entry_path,
    fetch_url, is_public_unicast, is_transient_fetch_error, lock_artifact, url_port,
    verify_stored_digest,
};
pub use image_load::{
    CONTAINERD_SNAPSHOTTER_DRIVER_TYPE, DockerImageLoader, ImageLoader, UnavailableImageLoader,
    image_loader_for,
};
pub use journal::FileJournal;
pub use lock::LockAdapter;
pub use module_cache::{
    DockerModuleAcquirer, MODULE_CACHE_CAPABILITY_KEY, MODULE_DOWNLOAD_DIR, ModuleAcquirer,
    STAGED_MODULE_CACHE_DIR, module_proxy_url, tree_bytes,
};
pub use oci::{COMPARATOR_VERSION, Comparator, compare_oci};
pub use release::{
    ReleaseImportService, ReleaseImporter, infra_pin_manifests, reverify_manifest_envelopes,
    verify_release,
};
pub use release_stage::{
    read_infra_save_config, read_infra_save_manifest, read_release_minio_inventory,
    stage_release_dir,
};
pub use service::{PrepareService, new_prepare_handler};
pub use store::CandidateStore;
pub use version_zero::{VERSION_ZERO_SELECTOR, ensure_version_zero_receipt};

/// Adapter-side machine codes for the fetch path (upstream
/// `internal/adapter/dependencyprepare`'s `ErrFetch*` sentinels).
/// Domain-owned refusals keep their `central_infra` codes; these name
/// only the boundary conditions the adapter itself detects.
pub mod prepare_fetch_codes {
    /// `ErrFetchPolicy` — a fetch the lock does not permit, or an
    /// archive member the closed extraction policy refuses.
    pub const FETCH_POLICY: &str = "FETCH_POLICY";
    /// `ErrFetchDigest` — bytes arrived that do not hash to the lock's
    /// pin, on the wire or in the stored artifact.
    pub const FETCH_DIGEST: &str = "FETCH_DIGEST";
    /// `ErrFetchSizeExceeded` — the byte ceiling the capability
    /// declares was crossed, downloaded or extracted.
    pub const FETCH_SIZE_EXCEEDED: &str = "FETCH_SIZE_EXCEEDED";
    /// `ErrFetchCookie` — a cookie was attempted in either direction.
    pub const FETCH_COOKIE: &str = "FETCH_COOKIE";
    /// `ErrFetchCredential` — an `Authorization`/`Proxy-Authorization`
    /// header or equivalent credential was about to reach the wire.
    pub const FETCH_CREDENTIAL: &str = "FETCH_CREDENTIAL";
    /// `ErrFetchClientCert` — a client certificate reached the
    /// fetcher. Production never sets one; the check exists so a test
    /// can prove the refusal.
    pub const FETCH_CLIENT_CERT: &str = "FETCH_CLIENT_CERT";
    /// `ErrFetchNonAllowlistHeader` — a request header outside the
    /// `Accept`/`Accept-Encoding`/`User-Agent` set.
    pub const FETCH_NON_ALLOWLIST_HEADER: &str = "FETCH_NON_ALLOWLIST_HEADER";
    /// `ErrFetchRedirect` — a hop the locked redirect chain does not
    /// name.
    pub const FETCH_REDIRECT: &str = "FETCH_REDIRECT";
    /// `ErrFetchAddress` — the dial-time address policy refused the
    /// resolved address.
    pub const FETCH_ADDRESS: &str = "FETCH_ADDRESS";
    /// `ErrFetchTransport` — a transport-level failure that is not one
    /// of the terminal policy refusals above.
    pub const FETCH_TRANSPORT: &str = "FETCH_TRANSPORT";
}

/// `ctx.Err()` — the synchronous stand-in for Go's `context.Context`
/// cancellation. The Go adapter threads a `context.Context` through
/// every boundary function purely for cancellation; the Rust port is
/// synchronous per the domain convention, so the one budget the helper
/// daemon sets on the operation is carried here as an optional
/// deadline and checked at the same points upstream checks
/// `ctx.Err()` (per archive member, per staged file, per retry).
#[derive(Debug, Clone, Copy, Default)]
pub struct OpDeadline(pub Option<Instant>);

impl OpDeadline {
    /// No deadline — tests and pure verification callers.
    pub const NONE: Self = Self(None);

    /// `context.WithTimeout(ctx, budget)` — a deadline `budget` from
    /// now.
    #[must_use]
    pub fn after(budget: std::time::Duration) -> Self {
        Self(Some(Instant::now() + budget))
    }

    /// `ctx.Err()` — refuses once the budget has elapsed.
    ///
    /// # Errors
    /// `cancelled` when the deadline has passed.
    pub fn check(&self) -> Result<(), Failure> {
        if self.0.is_some_and(|deadline| Instant::now() > deadline) {
            return Err(Failure::cancelled(
                "OPERATION_DEADLINE",
                "dependencyprepare: operation deadline exceeded",
            ));
        }
        Ok(())
    }

    /// The time remaining until the deadline, if any — the budget a
    /// single transport call or backoff sleep may consume.
    #[must_use]
    pub fn remaining(&self) -> Option<std::time::Duration> {
        self.0.map(|d| d.saturating_duration_since(Instant::now()))
    }

    /// `context.WithTimeout` nested inside the caller's context — the
    /// earlier of the two deadlines wins, so a capability's own budget
    /// can bound an acquisition without ever outliving the operation
    /// deadline the helper set.
    #[must_use]
    pub fn bounded_by(self, other: Self) -> Self {
        match (self.0, other.0) {
            (Some(a), Some(b)) => Self(Some(a.min(b))),
            (a, b) => Self(a.or(b)),
        }
    }
}

/// `hex.EncodeToString` — lowercase hex, the digest-text half every
/// `sha256:<hex>` comparison is taken over.
pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// `os.OpenRoot` — a directory-scoped filesystem handle. Every lookup
/// is resolved with `openat2(2)` under the `RESOLVE_BENEATH |
/// RESOLVE_NO_MAGICLINKS` envelope, which is Go's
/// `os.Root` semantics: symlinks that resolve inside the root are
/// honored, anything that would resolve outside it — or through a
/// `/proc` magic link — is refused by the kernel rather than by a
/// lexical check this file could get wrong.
pub struct ReleaseRoot {
    root_fd: OwnedFd,
}

/// Go `os.Root` resolution: `RESOLVE_BENEATH` keeps every resolution
/// beneath the root — `..` clamps at the root and absolute symlinks
/// re-root to it — and `RESOLVE_NO_MAGICLINKS` refuses `/proc/self/fd`
/// traversal. (`RESOLVE_IN_ROOT` is *not* added: the kernel rejects
/// `BENEATH|IN_ROOT` as mutually exclusive, and `BENEATH` already
/// carries the re-rooting semantics.) Deliberately without
/// `RESOLVE_NO_SYMLINKS` — `os.Root` resolves in-root symlinks, and
/// the release tree's closed entry set is enforced by the caller's
/// own allowlist, not by banning links the kernel can safely contain.
const RELEASE_RESOLVE: ResolveFlags = ResolveFlags::BENEATH.union(ResolveFlags::NO_MAGICLINKS);

impl ReleaseRoot {
    /// `os.OpenRoot` — `O_RDONLY|O_DIRECTORY|O_CLOEXEC` on the root.
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
            Failure::internal(
                "RELEASE_ROOT_OPEN",
                format!("dependencyprepare: open release root: {e}"),
            )
        })?;
        Ok(Self { root_fd })
    }

    /// `root.Open` — a contained read-only open of `name` beneath the
    /// root.
    ///
    /// # Errors
    /// `internal` when the contained open fails (missing, escaping, or
    /// a non-regular target).
    pub fn open(&self, name: &str) -> Result<File, Failure> {
        let fd = rustix::fs::openat2(
            &self.root_fd,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
            RELEASE_RESOLVE,
        )
        .map_err(|e| {
            Failure::internal(
                "RELEASE_ROOT_OPEN_FILE",
                format!("dependencyprepare: open {name}: {e}"),
            )
        })?;
        Ok(File::from(fd))
    }

    /// `root.Lstat` — metadata for `name` without following its final
    /// component: the parent chain is resolved beneath the root, the
    /// leaf is stated with `SYMLINK_NOFOLLOW`. This is what lets the
    /// release staging refuse a link where it requires a regular file.
    ///
    /// # Errors
    /// `internal` when the parent cannot be resolved or the leaf
    /// cannot be stated.
    pub fn lstat(&self, name: &str) -> Result<rustix::fs::Stat, Failure> {
        let (parent, leaf) = split_parent_leaf(name);
        let parent_fd = rustix::fs::openat2(
            &self.root_fd,
            parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            RELEASE_RESOLVE,
        )
        .map_err(|e| {
            Failure::internal(
                "RELEASE_ROOT_LSTAT_PARENT",
                format!("dependencyprepare: stat {name}: {e}"),
            )
        })?;
        rustix::fs::statat(&parent_fd, leaf, rustix::fs::AtFlags::SYMLINK_NOFOLLOW).map_err(|e| {
            Failure::internal(
                "RELEASE_ROOT_LSTAT",
                format!("dependencyprepare: lstat {name}: {e}"),
            )
        })
    }

    /// `root.Open(dir).ReadDir` — entries of a contained directory,
    /// read through `/proc/self/fd` on the already-contained
    /// descriptor so the listing cannot be re-pointed after the open.
    ///
    /// # Errors
    /// `internal` when the directory cannot be opened or listed.
    pub fn read_dir(&self, name: &str) -> Result<Vec<String>, Failure> {
        // `"."` names the root itself: duplicating the already-contained
        // descriptor is exactly `openat2(root, ".")` without relying on
        // the resolver accepting a bare dot.
        let dir_fd = if name == "." || name.is_empty() {
            self.root_fd.try_clone().map_err(|e| {
                Failure::internal(
                    "RELEASE_ROOT_READ_DIR",
                    format!("dependencyprepare: list {name}: {e}"),
                )
            })?
        } else {
            rustix::fs::openat2(
                &self.root_fd,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                RELEASE_RESOLVE,
            )
            .map_err(|e| {
                Failure::internal(
                    "RELEASE_ROOT_READ_DIR",
                    format!("dependencyprepare: list {name}: {e}"),
                )
            })?
        };
        let proc_path = format!("/proc/self/fd/{}", dir_fd.as_fd().as_raw_fd());
        let mut names = Vec::new();
        let entries = std::fs::read_dir(&proc_path).map_err(|e| {
            Failure::internal(
                "RELEASE_ROOT_READ_DIR",
                format!("dependencyprepare: list {name}: {e}"),
            )
        })?;
        for entry in entries {
            let entry = entry.map_err(|e| {
                Failure::internal(
                    "RELEASE_ROOT_READ_DIR",
                    format!("dependencyprepare: list {name}: {e}"),
                )
            })?;
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
        Ok(names)
    }
}

/// `path.Split`-style decomposition of a slash-separated relative
/// name into its parent and leaf for `statat`. `"minio/image.tar"` →
/// `("minio", "image.tar")`; `"release.json"` → `(".", "release.json")`.
fn split_parent_leaf(name: &str) -> (&str, &str) {
    match name.rfind('/') {
        Some(idx) => {
            let parent = &name[..idx];
            (
                if parent.is_empty() { "." } else { parent },
                &name[idx + 1..],
            )
        }
        None => (".", name),
    }
}

/// `os.MkdirAll(path, mode)` — `fs::create_dir_all` inherits the
/// umask, and upstream pins a mode on every directory it creates.
/// The mode applies to each directory the builder creates; existing
/// ones keep theirs, exactly like `MkdirAll`.
///
/// # Errors
/// `io::Error` from the underlying `mkdir` calls.
pub(crate) fn mkdir_all(path: &Path, mode: u32) -> std::io::Result<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(mode)
        .create(path)
}

/// `filepath.Join` + `strings.HasPrefix(target, root+sep)` — the
/// lexical half of upstream's `containedPath`. Go's `Join` *cleans*
/// its result, so a `..` member resolves against `root` before the
/// prefix question is asked; Rust's `Path::join` keeps `..` verbatim
/// and `Path::starts_with` compares components verbatim, so
/// `root/../../x` "starts with" `root` and a verbatim check is a dead
/// gate. Both sides are normalized lexically here first; a `..` that
/// pops past the filesystem root cannot be contained, so the answer
/// fails closed too.
pub(crate) fn lexically_contained(root: &Path, target: &Path) -> bool {
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
    let Some(norm_target) = normalize(target) else {
        return false;
    };
    let norm_root = normalize(root).unwrap_or_else(|| root.to_path_buf());
    norm_target == norm_root || norm_target.starts_with(&norm_root)
}

/// `tar.TypeReg` — the raw `'0'` typeflag. The `tar` crate folds `'0'`
/// and `TypeRegA` (`'\0'`) into `EntryType::Regular`, and upstream's
/// switches distinguish them (the fetch and OCI-layout extractors
/// accept only `TypeReg`; the release extractor accepts both), so the
/// raw header byte is what the closed policy checks.
pub(crate) fn raw_type_is_reg(header: &tar::Header) -> bool {
    header.as_bytes().get(156) == Some(&b'0')
}

/// `exec.CommandContext` — spawn + poll instead of `.output()`'s
/// uninterruptible wait: when `deadline` lapses the child is killed
/// and reaped and the cancelled failure is returned, so a bounded
/// operation cannot be held open by a child that ignores its budget.
/// The pipes are drained on reader threads so a chatty child cannot
/// block on a full pipe while the loop polls.
///
/// Deliberately not used for best-effort cleanup (upstream's plain
/// `exec.Command` sites, e.g. `remove_isolated_daemon`): teardown must
/// outlive the operation deadline, not die with it.
///
/// # Errors
/// `cancelled` once `deadline` lapses (the child is SIGKILLed and
/// reaped first); `internal` `code` on spawn/wait failures.
pub(crate) fn run_bounded(
    deadline: OpDeadline,
    command: &mut std::process::Command,
    code: &'static str,
    what: &str,
) -> Result<std::process::Output, Failure> {
    fn drain<P: std::io::Read + Send + 'static>(
        pipe: Option<P>,
    ) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut pipe) = pipe {
                let _ = pipe.read_to_end(&mut buf);
            }
            buf
        })
    }
    let mut child = command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| Failure::internal(code, format!("dependencyprepare: {what}: {e}")))?;
    let out_thread = drain(child.stdout.take());
    let err_thread = drain(child.stderr.take());
    const POLL: std::time::Duration = std::time::Duration::from_millis(10);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if let Err(failed) = deadline.check() {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = out_thread.join();
                    let _ = err_thread.join();
                    return Err(failed);
                }
                std::thread::sleep(POLL);
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = out_thread.join();
                let _ = err_thread.join();
                return Err(Failure::internal(
                    code,
                    format!("dependencyprepare: {what}: wait: {e}"),
                ));
            }
        }
    };
    Ok(std::process::Output {
        status,
        stdout: out_thread.join().unwrap_or_default(),
        stderr: err_thread.join().unwrap_or_default(),
    })
}
