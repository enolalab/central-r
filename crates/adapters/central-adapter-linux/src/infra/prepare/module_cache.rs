//! `module_cache_linux.go` — Go module acquisition. A Go build cannot
//! resolve its module graph inside a `--network=none` step, and the
//! pinned source vendors nothing, so the modules are acquired in the
//! fetch phase — the phase that already has network and already runs
//! under a lock-declared capability — then staged inside the build
//! context so the hermetic build sees byte-identical module material.
//!
//! Only `go.mod` and `go.sum` are ever handed to the downloader, never
//! the extracted source tree: `go mod download` needs nothing else to
//! resolve the whole module graph, and copying just those two files
//! means the verified source cannot be mutated by this step at all.

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use central_foundation::failure::Failure;
use central_infra::prepare::{FetchCapability, Lock};

use super::buildkit::{self, BuildRecipe};
use super::{OpDeadline, prepare_fetch_codes as fc};

/// `ModuleCacheCapabilityKey` — the lock's fetch capability for the Go
/// module proxy. It is not a selector: one capability serves every Go
/// build, because the endpoint it admits is the same for all of them.
pub const MODULE_CACHE_CAPABILITY_KEY: &str = "gomodules";

/// `StagedModuleCacheDir` — where the cache lands inside the build
/// context. The generated Dockerfile points `GOMODCACHE` at this path,
/// and it travels into the image through the same COPY as the source,
/// so both builders see byte-identical module material.
pub const STAGED_MODULE_CACHE_DIR: &str = ".central-gomodcache";

/// `moduleCacheReadyMarker` — written only after a download completed
/// and was measured against the capability's ceiling. Its absence
/// means the cache is absent or half-built, and either way must be
/// rebuilt: a partially populated cache would fail the offline build
/// for reasons that look nothing like a truncated download.
const MODULE_CACHE_READY_MARKER: &str = ".central-cache-complete";

/// `moduleDownloadDir` — the part of a Go module cache that holds the
/// downloaded zips. It is the only part staged into the build context:
/// the extracted tree beside it is derivable from these and is four
/// fifths of the bytes.
pub const MODULE_DOWNLOAD_DIR: &str = "cache/download";

/// `moduleAcquirer` — the network step of module acquisition, named so
/// a test can exercise cache staging, the byte ceiling and the
/// completion marker without docker and without a download.
/// Production always uses [`DockerModuleAcquirer`].
pub trait ModuleAcquirer: Send + Sync {
    /// `Acquire` — download the module graph into `cache_root`,
    /// resolving only against `manifest_dir`'s `go.mod`/`go.sum`,
    /// under the pinned `go_version` toolchain and the capability's
    /// proxy allowlist.
    ///
    /// # Errors
    /// Any acquisition failure. An `ErrFetchSizeExceeded`-code
    /// failure is terminal.
    fn acquire(
        &self,
        deadline: OpDeadline,
        cache_root: &Path,
        manifest_dir: &Path,
        go_version: &str,
        capability: &FetchCapability,
    ) -> Result<(), Failure>;
}

/// `stageModuleCache` — populate the per-selector module cache once
/// and link it into the build context.
///
/// Module acquisition belongs to the fetch phase (ADR 0027): it is
/// the phase that already has network, already runs under a
/// lock-declared capability, and already verifies what it retrieves.
/// The build step stays `--network=none`, which is the isolation
/// guarantee the whole arrangement exists to preserve.
///
/// # Errors
/// `FETCH_POLICY` when the lock grants no module capability;
/// `FETCH_SIZE_EXCEEDED` past the ceiling; `internal` for filesystem
/// and acquisition failures.
pub(crate) fn stage_module_cache(
    deadline: OpDeadline,
    lock: &Lock,
    base_dir: &Path,
    modules: Option<&dyn ModuleAcquirer>,
    selector: &str,
    dest_dir: &Path,
    go_version: &str,
) -> Result<(), Failure> {
    let capability = lock
        .fetch_capability_for(MODULE_CACHE_CAPABILITY_KEY)
        .map_err(|e| {
            Failure::invalid(
                fc::FETCH_POLICY,
                format!("dependencyprepare: fetch policy violation: {}", e.message()),
            )
        })?;

    let cache_root = base_dir.join("gomodcache").join(selector);
    populate_module_cache(
        deadline,
        modules,
        base_dir,
        &cache_root,
        dest_dir,
        go_version,
        &capability,
    )?;

    let staged = dest_dir.join(STAGED_MODULE_CACHE_DIR);
    if staged.exists() {
        fs::remove_dir_all(&staged).map_err(|e| {
            Failure::internal(
                "MODULE_STAGE",
                format!("dependencyprepare: clear staged module cache: {e}"),
            )
        })?;
    }
    fs::create_dir_all(&staged).map_err(|e| {
        Failure::internal(
            "MODULE_STAGE",
            format!("dependencyprepare: create staged module cache: {e}"),
        )
    })?;

    // Only the download cache is staged, not the extracted module
    // tree. Go extracts from the zips on demand, so the build has
    // everything it needs, and the build context carries a tenth of
    // the file count — measured on the pinned MinIO source. That
    // matters because BuildKit transfers the whole context once per
    // builder, twice per prepare, inside one pipeline deadline.
    let source = cache_root.join(MODULE_DOWNLOAD_DIR);
    if !source.is_dir() {
        return Err(Failure::internal(
            "MODULE_STAGE",
            "dependencyprepare: module download cache is absent after acquisition",
        ));
    }
    // Hardlinked rather than copied: the cache and the build context
    // live under the same state root, so this costs metadata instead
    // of a second copy, and the linked tree is identical by
    // construction rather than by copy.
    let target = staged.join(MODULE_DOWNLOAD_DIR);
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            Failure::internal(
                "MODULE_STAGE",
                format!("dependencyprepare: create staged download cache: {e}"),
            )
        })?;
    }
    deadline.check()?;
    let output = Command::new("cp")
        .args(["-al"])
        .arg(&source)
        .arg(&target)
        .output()
        .map_err(|e| {
            Failure::internal(
                "MODULE_STAGE",
                format!("dependencyprepare: stage module cache: {e}"),
            )
        })?;
    if !output.status.success() {
        return Err(Failure::internal(
            "MODULE_STAGE",
            format!(
                "dependencyprepare: stage module cache: exit {}: {}",
                output.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ));
    }
    Ok(())
}

/// `populateModuleCache` — download the module graph if the cache is
/// not already complete. A cache that is already marked complete is
/// reused as-is: the module set is pinned by the source's `go.sum`, so
/// a second download could only produce the same bytes.
fn populate_module_cache(
    deadline: OpDeadline,
    modules: Option<&dyn ModuleAcquirer>,
    base_dir: &Path,
    cache_root: &Path,
    source_dir: &Path,
    go_version: &str,
    capability: &FetchCapability,
) -> Result<(), Failure> {
    if cache_root.join(MODULE_CACHE_READY_MARKER).exists() {
        return Ok(());
    }
    if cache_root.exists() {
        fs::remove_dir_all(cache_root).map_err(|e| {
            Failure::internal(
                "MODULE_CACHE",
                format!("dependencyprepare: clear module cache: {e}"),
            )
        })?;
    }
    fs::create_dir_all(cache_root).map_err(|e| {
        Failure::internal(
            "MODULE_CACHE",
            format!("dependencyprepare: create module cache: {e}"),
        )
    })?;

    let manifest_dir = {
        let dir = base_dir.join(format!(
            "gomod-manifest-{}-{}",
            std::process::id(),
            cache_root
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "x".to_owned())
        ));
        if dir.exists() {
            fs::remove_dir_all(&dir).ok();
        }
        fs::create_dir_all(&dir).map_err(|e| {
            Failure::internal(
                "MODULE_CACHE",
                format!("dependencyprepare: module manifest dir: {e}"),
            )
        })?;
        dir
    };
    let manifest_guard = scopeguard(&manifest_dir);
    for name in ["go.mod", "go.sum"] {
        let body = fs::read(source_dir.join(name)).map_err(|e| {
            Failure::internal(
                "MODULE_CACHE",
                format!("dependencyprepare: read {name} from verified source: {e}"),
            )
        })?;
        let mut out = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(manifest_dir.join(name))
            .map_err(|e| {
                Failure::internal(
                    "MODULE_CACHE",
                    format!("dependencyprepare: stage {name}: {e}"),
                )
            })?;
        out.write_all(&body).map_err(|e| {
            Failure::internal(
                "MODULE_CACHE",
                format!("dependencyprepare: stage {name}: {e}"),
            )
        })?;
    }

    let default_acquirer;
    let acquirer: &dyn ModuleAcquirer = match modules {
        Some(m) => m,
        None => {
            default_acquirer = DockerModuleAcquirer;
            &default_acquirer
        }
    };

    deadline.check()?;
    acquirer.acquire(deadline, cache_root, &manifest_dir, go_version, capability)?;
    drop(manifest_guard);

    let size = tree_bytes(cache_root)?;
    if size > capability.max_bytes {
        // Removed rather than kept: a cache over the ceiling must not
        // be reusable by a later run that would skip this check.
        let _ = fs::remove_dir_all(cache_root);
        return Err(Failure::invalid(
            fc::FETCH_SIZE_EXCEEDED,
            format!(
                "dependencyprepare: fetch size exceeded: module cache is {size} bytes, ceiling is {}",
                capability.max_bytes
            ),
        ));
    }

    let marker = cache_root.join(MODULE_CACHE_READY_MARKER);
    fs::write(&marker, b"").map_err(|e| {
        Failure::internal(
            "MODULE_CACHE",
            format!("dependencyprepare: mark module cache complete: {e}"),
        )
    })?;
    Ok(())
}

/// `scopeguard` — `defer os.RemoveAll(manifestDir)`.
fn scopeguard(path: &Path) -> ScopeGuard {
    ScopeGuard {
        path: path.to_path_buf(),
    }
}

struct ScopeGuard {
    path: PathBuf,
}

impl Drop for ScopeGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// `moduleProxyURL` — render the capability as a single GOPROXY
/// endpoint. No `,direct` fallback: with direct, an unresolvable
/// module would send the toolchain to whatever host its path names,
/// and the lock's allowlist would describe nothing.
#[must_use]
pub fn module_proxy_url(capability: &FetchCapability) -> String {
    let host = if capability.port == 443 {
        capability.host.clone()
    } else {
        format!("{}:{}", capability.host, capability.port)
    };
    format!(
        "{}://{}{}",
        capability.scheme,
        host,
        capability.path_prefix.trim_end_matches('/')
    )
}

/// `treeBytes` — total the regular-file bytes under `root`.
///
/// # Errors
/// `internal` when the tree cannot be walked.
pub fn tree_bytes(root: &Path) -> Result<i64, Failure> {
    let mut total: i64 = 0;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = fs::read_dir(&dir).map_err(|e| {
            Failure::internal(
                "MODULE_CACHE",
                format!("dependencyprepare: measure module cache: {e}"),
            )
        })?;
        for entry in entries {
            let entry = entry.map_err(|e| {
                Failure::internal(
                    "MODULE_CACHE",
                    format!("dependencyprepare: measure module cache: {e}"),
                )
            })?;
            // `d.Type()` — the dirent's own type, unfollowed, matching
            // upstream's `d.Type().IsRegular()`.
            let file_type = entry.file_type().map_err(|e| {
                Failure::internal(
                    "MODULE_CACHE",
                    format!("dependencyprepare: measure module cache: {e}"),
                )
            })?;
            if file_type.is_dir() {
                stack.push(entry.path());
            } else if file_type.is_file() {
                let meta = entry.metadata().map_err(|e| {
                    Failure::internal(
                        "MODULE_CACHE",
                        format!("dependencyprepare: measure module cache: {e}"),
                    )
                })?;
                #[allow(clippy::cast_possible_wrap)]
                {
                    total += meta.len() as i64;
                }
            }
        }
    }
    Ok(total)
}

/// `goBuildRecipeFor` — the selector's recipe when that selector is
/// built from Go source. A built selector whose recipe names no Go
/// version is not an error: PostgreSQL's recipe describes an image
/// assembly and has no module graph to acquire. Only a recipe that
/// fails to parse is.
///
/// # Errors
/// Recipe parse failures only.
pub(crate) fn go_build_recipe_for(
    lock: &Lock,
    selector: &str,
) -> Result<Option<BuildRecipe>, Failure> {
    let raw = match selector {
        "minio" => lock.minio_recipe(),
        _ => return Ok(None),
    };
    let recipe = buildkit::parse_build_recipe(raw)?;
    if !buildkit::build_recipe_is_go(&recipe) {
        return Ok(None);
    }
    Ok(Some(recipe))
}

/// `dockerModuleAcquirer` — run `go mod download` in the same pinned
/// toolchain image the build uses, against only `go.mod` and `go.sum`.
pub struct DockerModuleAcquirer;

impl ModuleAcquirer for DockerModuleAcquirer {
    fn acquire(
        &self,
        deadline: OpDeadline,
        cache_root: &Path,
        manifest_dir: &Path,
        go_version: &str,
        capability: &FetchCapability,
    ) -> Result<(), Failure> {
        deadline.check()?;
        if super::buildkit::which("docker").is_none() {
            return Err(Failure::unavailable(
                "MODULE_ACQUIRE",
                "dependencyprepare: docker is required to acquire Go modules: not found in PATH",
            ));
        }
        // GOPROXY is built from the capability and carries no ",direct"
        // fallback. GOSUMDB is off because go.sum is inside an archive
        // the lock already pins by sha256, so every module hash is
        // transitively pinned by the lock already. See ADR 0027.
        let output = Command::new("docker")
            .args([
                "run",
                "--rm",
                "--network",
                "bridge",
                "-v",
                &format!("{}:/gomodcache", cache_root.display()),
                "-v",
                &format!("{}:/src", manifest_dir.display()),
                "-w",
                "/src",
                "-e",
                "GOMODCACHE=/gomodcache",
                "-e",
                &format!("GOPROXY={}", module_proxy_url(capability)),
                "-e",
                "GOSUMDB=off",
                "-e",
                "GOFLAGS=-mod=mod",
                &format!("golang:{go_version}-alpine"),
                "go",
                "mod",
                "download",
            ])
            .output()
            .map_err(|e| {
                Failure::internal(
                    "MODULE_ACQUIRE",
                    format!("dependencyprepare: acquire Go modules: {e}"),
                )
            })?;
        deadline.check()?;
        if !output.status.success() {
            return Err(Failure::internal(
                "MODULE_ACQUIRE",
                format!(
                    "dependencyprepare: acquire Go modules: exit {}: {}",
                    output.status.code().unwrap_or(-1),
                    String::from_utf8_lossy(&output.stdout).trim()
                ),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use central_infra::prepare::{self, Lock, TlsFetchMode};
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    fn tempdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "central-modcache-test-{tag}-{}-{}",
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

    fn shipped_module_capability() -> FetchCapability {
        lock()
            .fetch_capability_for(MODULE_CACHE_CAPABILITY_KEY)
            .expect("the shipped lock must grant a module capability")
    }

    /// `fakeModuleAcquirer` — same shape as upstream's: writes a
    /// caller-chosen number of bytes plus a stray extracted tree.
    struct FakeModuleAcquirer {
        calls: Mutex<usize>,
        bytes: Mutex<usize>,
        go_version: Mutex<String>,
        manifest: Mutex<BTreeMap<String, String>>,
        fail: Mutex<bool>,
    }

    impl FakeModuleAcquirer {
        fn new() -> Self {
            Self {
                calls: Mutex::new(0),
                bytes: Mutex::new(0),
                go_version: Mutex::new(String::new()),
                manifest: Mutex::new(BTreeMap::new()),
                fail: Mutex::new(false),
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
            _capability: &FetchCapability,
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
            if *self.fail.lock().expect("fail") {
                return Err(Failure::unavailable(
                    "MODULE_ACQUIRE",
                    "network died mid-graph",
                ));
            }
            let size = (*self.bytes.lock().expect("bytes")).max(16);
            let download = cache_root.join("cache").join("download");
            fs::create_dir_all(&download).expect("download");
            fs::write(download.join("module.zip"), vec![0u8; size]).expect("zip");
            let extracted = cache_root.join("example.com").join("mod@v1.0.0");
            fs::create_dir_all(&extracted).expect("extracted");
            fs::write(extracted.join("mod.go"), b"package mod\n").expect("mod.go");
            Ok(())
        }
    }

    /// `moduleCacheFixture` — a fetcher-bound lock whose module
    /// capability is the shipped one, a source dir holding only the
    /// manifest files, and the fake acquirer.
    fn module_cache_fixture(
        capability: &FetchCapability,
        tag: &str,
    ) -> (Lock, PathBuf, PathBuf, FakeModuleAcquirer) {
        let mut lock = lock();
        lock.fetch_capability
            .insert(MODULE_CACHE_CAPABILITY_KEY.to_owned(), capability.clone());
        let base = tempdir(&format!("{tag}-base"));
        let source = tempdir(&format!("{tag}-src"));
        for (name, body) in [("go.mod", "module x\n"), ("go.sum", "h1:x\n")] {
            fs::write(source.join(name), body).expect("manifest");
        }
        (lock, base, source, FakeModuleAcquirer::new())
    }

    /// `TestShippedModuleCapabilityAdmitsOneHost` — the ADR authorized
    /// exactly this endpoint.
    #[test]
    fn shipped_module_capability_admits_one_host() {
        let capability = shipped_module_capability();
        assert_eq!(capability.host, "proxy.golang.org");
        assert_eq!(capability.scheme, "https");
        assert_eq!(capability.port, 443);
        assert_eq!(capability.tls_policy, TlsFetchMode::SystemRoots);
        assert_eq!(
            capability.address_policy,
            prepare::ADDRESS_POLICY_PUBLIC_UNICAST
        );
        assert!(capability.max_bytes > 0 && capability.deadline_ms > 0);
    }

    /// `TestModuleProxyURLCarriesNoDirectFallback` — the one that
    /// matters most: a `,direct` fallback would admit whatever host a
    /// module path names.
    #[test]
    fn module_proxy_url_carries_no_direct_fallback() {
        let got = module_proxy_url(&shipped_module_capability());
        assert_eq!(got, "https://proxy.golang.org");
        assert!(!got.contains("direct") && !got.contains(','));
    }

    /// `moduleProxyURL` — non-443 ports are rendered.
    #[test]
    fn module_proxy_url_renders_port() {
        let mut capability = shipped_module_capability();
        capability.port = 8443;
        capability.path_prefix = "/proxy/".to_owned();
        let got = module_proxy_url(&capability);
        assert_eq!(got, "https://proxy.golang.org:8443/proxy");
    }

    /// `TestModuleCacheStagesIntoBuildContext` — the cache has to be
    /// inside the context by the time the offline build starts, and
    /// only the manifest crosses into the downloader.
    #[test]
    fn module_cache_stages_into_build_context() {
        let capability = shipped_module_capability();
        let (lock, base, source, acquirer) = module_cache_fixture(&capability, "stage");
        stage_module_cache(
            OpDeadline::NONE,
            &lock,
            &base,
            Some(&acquirer),
            "minio",
            &source,
            "1.24",
        )
        .expect("stageModuleCache");
        assert!(
            source
                .join(STAGED_MODULE_CACHE_DIR)
                .join("cache")
                .join("download")
                .join("module.zip")
                .is_file(),
            "the cache did not reach the build context"
        );
        assert_eq!(*acquirer.go_version.lock().expect("gv"), "1.24");
        let manifest = acquirer.manifest.lock().expect("manifest");
        assert_eq!(manifest.len(), 2);
        assert_eq!(
            manifest.get("go.mod").map(String::as_str),
            Some("module x\n")
        );
        assert_eq!(manifest.get("go.sum").map(String::as_str), Some("h1:x\n"));
        fs::remove_dir_all(&base).ok();
        fs::remove_dir_all(&source).ok();
    }

    /// `TestModuleCacheIsAcquiredOnce` — the marker guards a
    /// gigabyte-scale second download.
    #[test]
    fn module_cache_is_acquired_once() {
        let capability = shipped_module_capability();
        let (lock, base, source, acquirer) = module_cache_fixture(&capability, "once");
        for _ in 0..3 {
            stage_module_cache(
                OpDeadline::NONE,
                &lock,
                &base,
                Some(&acquirer),
                "minio",
                &source,
                "1.24",
            )
            .expect("stage");
        }
        assert_eq!(*acquirer.calls.lock().expect("calls"), 1);
        fs::remove_dir_all(&base).ok();
        fs::remove_dir_all(&source).ok();
    }

    /// `TestModuleCacheRefusesToExceedTheCeiling` — `max_bytes` is
    /// enforced, and an over-ceiling cache is not left behind for a
    /// later run to reuse past the check.
    #[test]
    fn module_cache_refuses_to_exceed_the_ceiling() {
        let mut capability = shipped_module_capability();
        capability.max_bytes = 64;
        let (lock, base, source, acquirer) = module_cache_fixture(&capability, "ceiling");
        *acquirer.bytes.lock().expect("bytes") = 4096;
        let err = stage_module_cache(
            OpDeadline::NONE,
            &lock,
            &base,
            Some(&acquirer),
            "minio",
            &source,
            "1.24",
        )
        .unwrap_err();
        assert_eq!(err.code(), fc::FETCH_SIZE_EXCEEDED);
        assert!(
            !base.join("gomodcache").join("minio").exists(),
            "an over-ceiling cache was left on disk, so a later run would reuse it and skip the ceiling"
        );
        fs::remove_dir_all(&base).ok();
        fs::remove_dir_all(&source).ok();
    }

    /// `TestModuleCacheIncompleteDownloadIsNotReused` — a failed
    /// acquisition leaves no marker, so the next attempt rebuilds.
    #[test]
    fn module_cache_incomplete_download_is_not_reused() {
        let capability = shipped_module_capability();
        let (lock, base, source, acquirer) = module_cache_fixture(&capability, "partial");
        *acquirer.fail.lock().expect("fail") = true;
        assert!(
            stage_module_cache(
                OpDeadline::NONE,
                &lock,
                &base,
                Some(&acquirer),
                "minio",
                &source,
                "1.24",
            )
            .is_err()
        );
        *acquirer.fail.lock().expect("fail") = false;
        stage_module_cache(
            OpDeadline::NONE,
            &lock,
            &base,
            Some(&acquirer),
            "minio",
            &source,
            "1.24",
        )
        .expect("retry after a failed acquisition");
        assert_eq!(*acquirer.calls.lock().expect("calls"), 2);
        fs::remove_dir_all(&base).ok();
        fs::remove_dir_all(&source).ok();
    }

    /// `TestModuleCacheStagesOnlyTheDownloadCache` — the extracted
    /// tree is derivable from the zips and nine tenths of the file
    /// count; staging it would pay the BuildKit transfer twice for
    /// nothing.
    #[test]
    fn module_cache_stages_only_the_download_cache() {
        let capability = shipped_module_capability();
        let (lock, base, source, _acquirer) = module_cache_fixture(&capability, "downloadonly");
        stage_module_cache(
            OpDeadline::NONE,
            &lock,
            &base,
            Some(&FakeModuleAcquirer::new()),
            "minio",
            &source,
            "1.24",
        )
        .expect("stageModuleCache");
        let staged = source.join(STAGED_MODULE_CACHE_DIR);
        assert!(
            staged
                .join("cache")
                .join("download")
                .join("module.zip")
                .is_file()
        );
        assert!(
            !staged.join("example.com").exists(),
            "the extracted module tree was staged; it is derivable from the zips and doubles the context BuildKit must transfer"
        );
        fs::remove_dir_all(&base).ok();
        fs::remove_dir_all(&source).ok();
    }

    /// `treeBytes` — totals regular files only.
    #[test]
    fn tree_bytes_totals() {
        let dir = tempdir("tree");
        fs::write(dir.join("a"), vec![0u8; 10]).expect("a");
        fs::create_dir_all(dir.join("sub")).expect("sub");
        fs::write(dir.join("sub").join("b"), vec![0u8; 5]).expect("b");
        assert_eq!(tree_bytes(&dir).expect("tree"), 15);
        fs::remove_dir_all(&dir).ok();
    }
}
