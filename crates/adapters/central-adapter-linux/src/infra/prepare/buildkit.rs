//! `buildkit_linux.go` — the hermetic-build driver. One fresh,
//! privileged BuildKit daemon container per `Build` call (its own
//! content store under `root_a`), one `buildctl` invocation whose argv
//! is a pinned, test-readable value, one OCI export whose digests are
//! read back from the layout bytes BuildKit actually produced.
//!
//! Isolation is enforced two ways, both ported verbatim: by refusal —
//! `build` rejects a request that does not carry every isolation flag —
//! and by omission — `hermetic_build_args` never emits `--secret`,
//! `--ssh`, `--allow`, `--import-cache`, or `--export-cache`, so no
//! flag exists that could grant what the flags it does emit withhold.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use central_foundation::failure::Failure;
use central_infra::domain::{BUILT_IMAGE_REPOSITORY, OciInventory, OciLayer, codes};
use central_infra::prepare::{BuildRequest, prepare_codes};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use super::{OpDeadline, hex_lower};

/// `buildKitDaemonImage` — the pinned daemon image hosting each
/// hermetic build. A fresh container is started per `Build` call so no
/// build shares a root, cache, or daemon with any other.
pub const BUILD_KIT_DAEMON_IMAGE: &str = "moby/buildkit:v0.20.2";

/// `deterministicSourceDateEpoch` — the fixed `SOURCE_DATE_EPOCH`
/// every build embeds, so two independent hermetic builds of the same
/// recipe produce byte-identical OCI output.
pub const DETERMINISTIC_SOURCE_DATE_EPOCH: &str = "1700000000";

// Recipe field allowlists (upstream's `regexp` patterns, hand-rolled —
// the crate carries no regex dependency and each set is small enough
// to state as a predicate).
/// `sourceCommitPattern` — `^[0-9a-f]{40}$`.
fn is_source_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
/// `goVersionPattern` — `^[a-zA-Z0-9_.\-]+$`.
fn is_go_version(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}
/// `goTargetPattern` — `^[a-zA-Z0-9_./\-]+$`.
fn is_go_target(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'/' | b'-'))
}
/// `goTagPattern` — `^[a-zA-Z0-9_]+$`.
fn is_go_tag(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}
/// `goLDFlagPattern` — `^[a-zA-Z0-9_=./\-]+$`.
fn is_go_ldflag(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'=' | b'.' | b'/' | b'-'))
}

/// `BuildKit` — upstream `port.Builder`.
#[derive(Debug, Clone, Default)]
pub struct BuildKit {
    /// Scratch space for daemon-side temp files (`workDir`; empty in
    /// the zero-value builder, matching upstream).
    pub work_dir: PathBuf,
}

impl BuildKit {
    /// `NewBuildKit`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `NewBuildKitWithWorkDir`.
    #[must_use]
    pub fn with_work_dir(work_dir: impl Into<PathBuf>) -> Self {
        Self {
            work_dir: work_dir.into(),
        }
    }

    /// `Build` — the refusal envelope runs before any tool path is
    /// consulted: empty or identical roots, `network_after_import`,
    /// any missing isolation flag, an unbound selector or recipe. Only
    /// then does the locked recipe run.
    ///
    /// # Errors
    /// `BUILDER_ISOLATION` for every isolation violation;
    /// `BUILD_REQUEST_INVALID` for an empty selector/recipe;
    /// `internal` for tool and output failures.
    pub fn build(&self, deadline: OpDeadline, req: &BuildRequest) -> Result<OciInventory, Failure> {
        if req.root_a.is_empty() || req.root_b.is_empty() {
            return Err(Failure::invalid(
                prepare_codes::BUILDER_ISOLATION,
                "dependencyprepare: builder root must not be empty",
            ));
        }
        if req.root_a == req.root_b {
            return Err(Failure::invalid(
                prepare_codes::BUILDER_ISOLATION,
                "dependencyprepare: identical RootA and RootB paths are not allowed",
            ));
        }
        if req.network_after_import {
            return Err(Failure::invalid(
                prepare_codes::BUILDER_ISOLATION,
                "dependencyprepare: network after import is not allowed",
            ));
        }
        if !(req.no_default_caches
            && req.no_host_mounts
            && req.no_docker_socket
            && req.no_secrets
            && req.no_ssh
            && req.no_privileged
            && req.no_plugins
            && req.no_external_cache)
        {
            return Err(Failure::invalid(
                prepare_codes::BUILDER_ISOLATION,
                "dependencyprepare: all isolation constraints must be enabled",
            ));
        }
        if req.selector.is_empty() || req.recipe.is_empty() {
            return Err(Failure::invalid(
                codes::BUILD_REQUEST_INVALID,
                "dependencyprepare: invalid build request",
            ));
        }
        self.run_locked_recipe(deadline, req)
    }

    /// `runLockedRecipe` — one real hermetic build and the genuine
    /// [`OciInventory`] of its exported layout.
    fn run_locked_recipe(
        &self,
        deadline: OpDeadline,
        req: &BuildRequest,
    ) -> Result<OciInventory, Failure> {
        let recipe = parse_build_recipe(&req.recipe)?;

        for tool in ["docker", "buildctl"] {
            if which(tool).is_none() {
                return Err(Failure::internal(
                    "BUILD_TOOL_MISSING",
                    format!(
                        "dependencyprepare: {tool} is required to host the isolated BuildKit daemon: not found in PATH"
                    ),
                ));
            }
        }

        fs::create_dir_all(&req.root_a).map_err(|e| {
            Failure::internal(
                "BUILD_ROOT",
                format!("dependencyprepare: create builder root A: {e}"),
            )
        })?;
        fs::create_dir_all(&req.root_b).map_err(|e| {
            Failure::internal(
                "BUILD_ROOT",
                format!("dependencyprepare: create builder root B: {e}"),
            )
        })?;

        let context_dir = req.context_dir();
        let info = fs::metadata(&context_dir).map_err(|e| {
            Failure::internal(
                "BUILD_CONTEXT_MISSING",
                format!("dependencyprepare: build context {} is not staged; the caller must place verified source under <RootB>/context before calling Build: {e}", context_dir.display()),
            )
        })?;
        if !info.is_dir() {
            return Err(Failure::internal(
                "BUILD_CONTEXT_MISSING",
                format!(
                    "dependencyprepare: build context {} is not a directory",
                    context_dir.display()
                ),
            ));
        }
        write_generated_dockerfile(&context_dir)?;

        let daemon_name = format!("central-dp-build-{}", short_root_digest(&req.root_a));
        start_isolated_daemon(deadline, &daemon_name, &req.root_a)?;
        let result = (|| {
            let oci_tar_path = req.export_path();
            run_hermetic_build(deadline, &daemon_name, &context_dir, &oci_tar_path, &recipe)?;
            let layout_dir = Path::new(&req.root_b).join("oci-layout");
            extract_oci_tar(&oci_tar_path, &layout_dir)?;
            inventory_from_oci_layout(&layout_dir)
        })();
        // `defer removeIsolatedDaemon` — teardown runs whether the
        // build above succeeded or not, best-effort like upstream.
        remove_isolated_daemon(&daemon_name, &req.root_a);
        result
    }
}

/// `exec.LookPath` — PATH membership without a shell.
pub(crate) fn which(tool: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(tool);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// `buildRecipe` — the shape shared by the embedded recipe assets.
/// Upstream decodes with `encoding/json` (unknown fields ignored), so
/// this struct does the same rather than `deny_unknown_fields`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct BuildRecipe {
    /// Recipe schema tag.
    #[serde(default)]
    pub schema: String,
    /// The pinned source.
    #[serde(default)]
    pub source: BuildRecipeSource,
    /// The build knobs.
    #[serde(default)]
    pub build: BuildRecipeBuild,
}

/// `buildRecipe.Source`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct BuildRecipeSource {
    /// `repository`.
    #[serde(default)]
    pub repository: String,
    /// `commit` — 40 lowercase hex.
    #[serde(default)]
    pub commit: String,
}

/// `buildRecipe.Build`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct BuildRecipeBuild {
    /// `go_version`.
    #[serde(default)]
    pub go_version: String,
    /// `target`.
    #[serde(default)]
    pub target: String,
    /// `tags`.
    #[serde(default)]
    pub tags: Vec<String>,
    /// `ldflags`.
    #[serde(default)]
    pub ldflags: Vec<String>,
}

/// `parseBuildRecipe` — decode, then enforce the field allowlists that
/// keep recipe values out of shell-interpreted positions. The
/// allowlists mirror upstream's regexes exactly.
///
/// # Errors
/// `internal` on malformed JSON; `invalid` on any field that fails its
/// allowlist or is missing.
pub fn parse_build_recipe(raw: &[u8]) -> Result<BuildRecipe, Failure> {
    let r: BuildRecipe = serde_json::from_slice(raw).map_err(|e| {
        Failure::internal(
            "BUILD_RECIPE_JSON",
            format!("dependencyprepare: recipe is not valid JSON: {e}"),
        )
    })?;
    if r.source.commit.is_empty() {
        return Err(Failure::internal(
            "BUILD_RECIPE_FIELD",
            "dependencyprepare: recipe missing source.commit",
        ));
    }
    if !is_source_commit(&r.source.commit) {
        return Err(Failure::internal(
            "BUILD_RECIPE_FIELD",
            format!(
                "dependencyprepare: recipe source.commit {:?} is not a 40-character lowercase hex commit",
                r.source.commit
            ),
        ));
    }
    if r.build.go_version.is_empty() {
        return Err(Failure::internal(
            "BUILD_RECIPE_FIELD",
            "dependencyprepare: recipe missing build.go_version",
        ));
    }
    if !is_go_version(&r.build.go_version) {
        return Err(Failure::internal(
            "BUILD_RECIPE_FIELD",
            format!(
                "dependencyprepare: recipe build.go_version {:?} is not a safe image tag component",
                r.build.go_version
            ),
        ));
    }
    if r.build.target.is_empty() {
        return Err(Failure::internal(
            "BUILD_RECIPE_FIELD",
            "dependencyprepare: recipe missing build.target",
        ));
    }
    if !is_go_target(&r.build.target) {
        return Err(Failure::internal(
            "BUILD_RECIPE_FIELD",
            format!(
                "dependencyprepare: recipe build.target {:?} is not a safe build-arg value",
                r.build.target
            ),
        ));
    }
    for tag in &r.build.tags {
        if !is_go_tag(tag) {
            return Err(Failure::internal(
                "BUILD_RECIPE_FIELD",
                format!(
                    "dependencyprepare: recipe build.tags entry {tag:?} is not a safe build-arg value"
                ),
            ));
        }
    }
    for flag in &r.build.ldflags {
        if !is_go_ldflag(flag) {
            return Err(Failure::internal(
                "BUILD_RECIPE_FIELD",
                format!(
                    "dependencyprepare: recipe build.ldflags entry {flag:?} is not a safe build-arg value"
                ),
            ));
        }
    }
    Ok(r)
}

/// `goBuildRecipeFor`'s second return — whether this recipe describes
/// a Go build with a module graph to acquire.
#[must_use]
pub fn build_recipe_is_go(recipe: &BuildRecipe) -> bool {
    !recipe.build.go_version.is_empty()
}

/// `writeGeneratedDockerfile` — the one Dockerfile this recipe schema
/// needs: a Go build stage and a scratch final stage, entirely
/// parameterized by `--build-arg`. The recipe fields land only in
/// argv, never in Dockerfile text — and the field allowlists in
/// [`parse_build_recipe`] are what keep the `${VAR}` substitutions the
/// Dockerfile *does* perform safe.
///
/// # Errors
/// `internal` when the file cannot be written.
pub fn write_generated_dockerfile(context_dir: &Path) -> Result<(), Failure> {
    const DOCKERFILE: &str = r#"# syntax=docker/dockerfile:1.10.0
ARG GO_VERSION
FROM golang:${GO_VERSION}-alpine AS build
ARG SOURCE_REPO
ARG SOURCE_COMMIT
ARG GO_TARGET
ARG GO_TAGS
ARG GO_LDFLAGS
WORKDIR /src
COPY . .
RUN --network=none CGO_ENABLED=0 GOFLAGS=-mod=mod GOMODCACHE=/src/.central-gomodcache go build -trimpath -tags "${GO_TAGS}" -ldflags "${GO_LDFLAGS}" -o /out/app ${GO_TARGET}

FROM scratch
COPY --from=build /out/app /app
ARG SOURCE_REPO
ARG SOURCE_COMMIT
LABEL org.opencontainers.image.source=${SOURCE_REPO}
LABEL org.opencontainers.image.revision=${SOURCE_COMMIT}
ENTRYPOINT ["/app"]
"#;
    let path = context_dir.join("Dockerfile");
    fs::write(&path, DOCKERFILE.as_bytes()).map_err(|e| {
        Failure::internal(
            "BUILD_DOCKERFILE",
            format!("dependencyprepare: write generated Dockerfile: {e}"),
        )
    })?;
    Ok(())
}

/// `shortRootDigest` — the deterministic, name-safe token derived
/// from an operation-derived root path, so retries of the same
/// operation address the same daemon container name.
#[must_use]
pub fn short_root_digest(root: &str) -> String {
    hex_lower(&Sha256::digest(root.as_bytes()))[..16].to_owned()
}

/// `startIsolatedDaemon` — remove any stale container under this name,
/// then start the fresh privileged daemon with `data_root` bind-mounted
/// as its `/var/lib/buildkit`.
fn start_isolated_daemon(deadline: OpDeadline, name: &str, data_root: &str) -> Result<(), Failure> {
    deadline.check()?;
    remove_isolated_daemon(name, data_root);
    let output = Command::new("docker")
        .args([
            "run",
            "-d",
            "--name",
            name,
            "--privileged",
            "-v",
            &format!("{data_root}:/var/lib/buildkit"),
            BUILD_KIT_DAEMON_IMAGE,
        ])
        .output()
        .map_err(|e| {
            Failure::internal(
                "BUILD_DAEMON",
                format!("dependencyprepare: start isolated BuildKit daemon: {e}"),
            )
        })?;
    if !output.status.success() {
        return Err(Failure::internal(
            "BUILD_DAEMON",
            format!(
                "dependencyprepare: start isolated BuildKit daemon: exit {}: {}",
                output.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&output.stdout).trim()
            ),
        ));
    }
    Ok(())
}

/// `removeIsolatedDaemon` — best-effort teardown: `docker rm -f` the
/// per-call daemon, then a throwaway `chown -R` container reclaims the
/// root-owned overlayfs content the daemon wrote under `data_root`,
/// so the operation's later `remove_all` can delete its own roots.
/// Failures are swallowed deliberately, matching upstream: this is
/// cleanup of our own scratch state, not something a build's success
/// may depend on.
fn remove_isolated_daemon(name: &str, data_root: &str) {
    let _ = Command::new("docker").args(["rm", "-f", name]).output();
    let uid = rustix::process::getuid();
    let gid = rustix::process::getgid();
    let _ = Command::new("docker")
        .args([
            "run",
            "--rm",
            "-v",
            &format!("{data_root}:/data"),
            "alpine:3.20",
            "chown",
            "-R",
            &format!("{}:{}", uid.as_raw(), gid.as_raw()),
            "/data",
        ])
        .output();
}

/// `exportImageName` — the reference the OCI export is named with:
/// `central-minio:<commit-prefix>`. Derived from the recipe's pinned
/// commit so the same lock produces the same `index.json` on any host
/// at any time — a name derived from the operation ID, the clock, or
/// the host would destroy the two-build reproducibility proof.
#[must_use]
pub fn export_image_name(recipe: &BuildRecipe) -> String {
    format!("{}:{}", BUILT_IMAGE_REPOSITORY, &recipe.source.commit[..12])
}

/// `ociExportOutputArg` — buildctl's `--output` value: the OCI export
/// destination, the deterministic timestamp rewrite, and the name
/// `index.json` records so `docker load` makes the built image
/// resolvable as `central-minio@<manifest digest>`.
#[must_use]
pub fn oci_export_output_arg(oci_tar_path: &str, recipe: &BuildRecipe) -> String {
    format!(
        "type=oci,dest={oci_tar_path},rewrite-timestamp=true,name={}",
        export_image_name(recipe)
    )
}

/// `hermeticBuildArgs` — the complete buildctl argv, a value a test
/// can read rather than a command line assembled at the exec site.
/// Isolation by omission: no `--secret`, `--ssh`, `--allow`, or
/// `--import-cache`/`--export-cache` flag is ever emitted, and the
/// only `--local` mount exposed to the frontend is the staged context
/// directory itself.
#[must_use]
pub fn hermetic_build_args(
    daemon_name: &str,
    context_dir: &Path,
    oci_tar_path: &Path,
    recipe: &BuildRecipe,
) -> Vec<String> {
    let context = context_dir.display().to_string();
    vec![
        "--addr".to_owned(),
        format!("docker-container://{daemon_name}"),
        "--wait".to_owned(),
        "build".to_owned(),
        "--frontend".to_owned(),
        "dockerfile.v0".to_owned(),
        "--local".to_owned(),
        format!("context={context}"),
        "--local".to_owned(),
        format!("dockerfile={context}"),
        "--opt".to_owned(),
        "platform=linux/amd64".to_owned(),
        "--opt".to_owned(),
        format!("build-arg:SOURCE_DATE_EPOCH={DETERMINISTIC_SOURCE_DATE_EPOCH}"),
        "--opt".to_owned(),
        format!("build-arg:GO_VERSION={}", recipe.build.go_version),
        "--opt".to_owned(),
        format!("build-arg:SOURCE_REPO={}", recipe.source.repository),
        "--opt".to_owned(),
        format!("build-arg:SOURCE_COMMIT={}", recipe.source.commit),
        "--opt".to_owned(),
        format!("build-arg:GO_TARGET={}", recipe.build.target),
        "--opt".to_owned(),
        format!("build-arg:GO_TAGS={}", recipe.build.tags.join(",")),
        "--opt".to_owned(),
        format!("build-arg:GO_LDFLAGS={}", recipe.build.ldflags.join(" ")),
        "--no-cache".to_owned(),
        "--output".to_owned(),
        oci_export_output_arg(&oci_tar_path.display().to_string(), recipe),
    ]
}

/// `runHermeticBuild` — drive `buildctl` against the just-started,
/// per-call daemon.
fn run_hermetic_build(
    deadline: OpDeadline,
    daemon_name: &str,
    context_dir: &Path,
    oci_tar_path: &Path,
    recipe: &BuildRecipe,
) -> Result<(), Failure> {
    deadline.check()?;
    let args = hermetic_build_args(daemon_name, context_dir, oci_tar_path, recipe);
    let output = Command::new("buildctl").args(&args).output().map_err(|e| {
        Failure::internal(
            "BUILD_HERMETIC",
            format!("dependencyprepare: hermetic build failed: {e}"),
        )
    })?;
    if !output.status.success() {
        return Err(Failure::internal(
            "BUILD_HERMETIC",
            format!(
                "dependencyprepare: hermetic build failed: exit {}: {}",
                output.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&output.stdout).trim()
            ),
        ));
    }
    Ok(())
}

/// `extractOCITar` — unpack the OCI export into `dest_dir`. Members
/// other than directories and regular files are skipped, matching
/// upstream's `switch` with no default; paths are cleaned beneath
/// `dest_dir` via the `"/"+name` join.
fn extract_oci_tar(tar_path: &Path, dest_dir: &Path) -> Result<(), Failure> {
    fs::create_dir_all(dest_dir).map_err(|e| {
        Failure::internal(
            "BUILD_OCI_TAR",
            format!("dependencyprepare: create OCI layout dir: {e}"),
        )
    })?;
    let file = fs::File::open(tar_path).map_err(|e| {
        Failure::internal(
            "BUILD_OCI_TAR",
            format!("dependencyprepare: open OCI output tar: {e}"),
        )
    })?;
    let mut archive = tar::Archive::new(file);
    let entries = archive.entries().map_err(|e| {
        Failure::internal(
            "BUILD_OCI_TAR",
            format!("dependencyprepare: read OCI output tar: {e}"),
        )
    })?;
    for entry in entries {
        let mut entry = entry.map_err(|e| {
            Failure::internal(
                "BUILD_OCI_TAR",
                format!("dependencyprepare: read OCI output tar: {e}"),
            )
        })?;
        let name = entry
            .path()
            .map_err(|e| {
                Failure::internal(
                    "BUILD_OCI_TAR",
                    format!("dependencyprepare: read OCI output tar: {e}"),
                )
            })?
            .to_string_lossy()
            .into_owned();
        // `filepath.Join(destDir, filepath.Clean("/"+hdr.Name))`:
        // rooting the member before cleaning folds every leading `..`
        // into the layout dir.
        let cleaned = Path::new("/").join(name.as_str());
        let cleaned = cleaned
            .components()
            .filter_map(|c| match c {
                std::path::Component::Normal(p) => Some(p.to_string_lossy().into_owned()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("/");
        let target = dest_dir.join(&cleaned);
        match entry.header().entry_type() {
            tar::EntryType::Directory => {
                fs::create_dir_all(&target).map_err(|e| {
                    Failure::internal(
                        "BUILD_OCI_TAR",
                        format!("dependencyprepare: create {}: {e}", target.display()),
                    )
                })?;
            }
            tar::EntryType::Regular => {
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent).map_err(|e| {
                        Failure::internal(
                            "BUILD_OCI_TAR",
                            format!("dependencyprepare: create {}: {e}", parent.display()),
                        )
                    })?;
                }
                let mut out = fs::File::create(&target).map_err(|e| {
                    Failure::internal(
                        "BUILD_OCI_TAR",
                        format!("dependencyprepare: create {}: {e}", target.display()),
                    )
                })?;
                io::copy(&mut entry, &mut out).map_err(|e| {
                    Failure::internal(
                        "BUILD_OCI_TAR",
                        format!("dependencyprepare: write {}: {e}", target.display()),
                    )
                })?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// `ociIndex` — `index.json`'s manifest list.
#[derive(Debug, Deserialize)]
struct OciIndex {
    manifests: Vec<OciIndexManifest>,
}

#[derive(Debug, Deserialize)]
struct OciIndexManifest {
    digest: String,
}

/// `ociManifest` — the manifest blob's config + layers.
#[derive(Debug, Deserialize)]
struct OciManifest {
    config: OciManifestConfig,
    #[serde(default)]
    layers: Vec<OciManifestLayer>,
}

#[derive(Debug, Deserialize)]
struct OciManifestConfig {
    digest: String,
}

#[derive(Debug, Deserialize)]
struct OciManifestLayer {
    digest: String,
    #[serde(rename = "mediaType")]
    media_type: String,
    size: i64,
    #[serde(default)]
    annotations: BTreeMap<String, String>,
}

/// `inventoryFromOCILayout` — read back the digests BuildKit actually
/// produced: `index_digest` is the raw-byte SHA-256 of `index.json`
/// itself; `manifest_digest` and `config_digest` are the digests the
/// index and manifest already declare.
///
/// # Errors
/// `internal` on unreadable or unparseable layout bytes, on an index
/// that does not hold exactly one manifest, or on an incomplete
/// identity chain.
pub fn inventory_from_oci_layout(layout_dir: &Path) -> Result<OciInventory, Failure> {
    let index_path = layout_dir.join("index.json");
    let index_bytes = fs::read(&index_path).map_err(|e| {
        Failure::internal(
            "BUILD_OCI_LAYOUT",
            format!("dependencyprepare: read index.json: {e}"),
        )
    })?;
    let index_digest = format!("sha256:{}", hex_lower(&Sha256::digest(&index_bytes)));

    let index: OciIndex = serde_json::from_slice(&index_bytes).map_err(|e| {
        Failure::internal(
            "BUILD_OCI_LAYOUT",
            format!("dependencyprepare: parse index.json: {e}"),
        )
    })?;
    if index.manifests.len() != 1 {
        return Err(Failure::internal(
            "BUILD_OCI_LAYOUT",
            format!(
                "dependencyprepare: expected exactly one manifest in index.json, got {}",
                index.manifests.len()
            ),
        ));
    }
    let manifest_digest = index.manifests[0].digest.clone();

    let manifest_bytes = read_blob(layout_dir, &manifest_digest).map_err(|e| {
        Failure::internal(
            "BUILD_OCI_LAYOUT",
            format!("dependencyprepare: read manifest blob: {e}"),
        )
    })?;
    let manifest: OciManifest = serde_json::from_slice(&manifest_bytes).map_err(|e| {
        Failure::internal(
            "BUILD_OCI_LAYOUT",
            format!("dependencyprepare: parse manifest blob: {e}"),
        )
    })?;

    let mut inventory = OciInventory {
        index_digest,
        manifest_digest,
        config_digest: manifest.config.digest,
        layers: Vec::new(),
    };
    for layer in manifest.layers {
        inventory.layers.push(OciLayer {
            digest: layer.digest,
            media_type: layer.media_type,
            size: layer.size,
            annotations: layer.annotations,
        });
    }
    if inventory.index_digest.is_empty()
        || inventory.manifest_digest.is_empty()
        || inventory.config_digest.is_empty()
    {
        return Err(Failure::internal(
            "BUILD_OCI_LAYOUT",
            "dependencyprepare: incomplete OCI inventory read back from build output",
        ));
    }
    Ok(inventory)
}

/// `readBlob` — one content-addressed blob out of the layout.
fn read_blob(layout_dir: &Path, digest: &str) -> Result<Vec<u8>, Failure> {
    let Some((algo, hex_digest)) = digest.split_once(':') else {
        return Err(Failure::internal(
            "BUILD_OCI_LAYOUT",
            format!("dependencyprepare: unsupported digest {digest:?}"),
        ));
    };
    if algo != "sha256" {
        return Err(Failure::internal(
            "BUILD_OCI_LAYOUT",
            format!("dependencyprepare: unsupported digest {digest:?}"),
        ));
    }
    fs::read(layout_dir.join("blobs").join("sha256").join(hex_digest)).map_err(|e| {
        Failure::internal(
            "BUILD_OCI_LAYOUT",
            format!("dependencyprepare: read blob: {e}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use central_infra::prepare::new_build_request;

    fn tempdir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "central-buildkit-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&dir).expect("tempdir");
        dir
    }

    fn isolation_req(root_a: &Path, root_b: &Path) -> BuildRequest {
        new_build_request(
            "minio",
            br#"{"schema":"test"}"#,
            root_a.to_str().unwrap_or_default(),
            root_b.to_str().unwrap_or_default(),
            false,
        )
        .expect("request")
    }

    fn minimal_test_recipe() -> Vec<u8> {
        br#"{"schema":"central.minio-build-recipe/v1","source":{"repository":"https://example.invalid/central-b02-test","commit":"0000000000000000000000000000000000000000"},"build":{"go_version":"1.22","target":".","tags":[],"ldflags":["-s","-w"]}}"#
        .to_vec()
    }

    // ---- buildkit_test.go --------------------------------------------

    /// `TestBuildKitRejectsIdenticalRoots` — two roots must differ; a
    /// build that shares a root shares a content store.
    #[test]
    fn build_rejects_identical_roots() {
        let kit = BuildKit::new();
        let req = new_build_request(
            "minio",
            br#"{"schema":"test"}"#,
            "/same/path",
            "/same/path",
            false,
        )
        .expect("request");
        let err = kit.build(OpDeadline::NONE, &req).unwrap_err();
        assert_eq!(err.code(), prepare_codes::BUILDER_ISOLATION);
    }

    /// `TestBuildKitRejectsNetworkAfterImport`.
    #[test]
    fn build_rejects_network_after_import() {
        let kit = BuildKit::new();
        let mut req = isolation_req(Path::new("/root/a"), Path::new("/root/b"));
        req.network_after_import = true;
        let err = kit.build(OpDeadline::NONE, &req).unwrap_err();
        assert_eq!(err.code(), prepare_codes::BUILDER_ISOLATION);
    }

    /// `TestBuildKitRejectsEmptySelector` / `EmptyRecipe` /
    /// `EmptyRootA` / `EmptyRootB` — every unbound request refuses
    /// before any tool is consulted.
    #[test]
    fn build_rejects_unbound_requests_before_tools() {
        let kit = BuildKit::new();
        // Empty selector.
        let mut req = isolation_req(Path::new("/root/a"), Path::new("/root/b"));
        req.selector.clear();
        assert!(kit.build(OpDeadline::NONE, &req).is_err());
        // Empty recipe.
        let mut req = isolation_req(Path::new("/root/a"), Path::new("/root/b"));
        req.recipe.clear();
        assert!(kit.build(OpDeadline::NONE, &req).is_err());
        // Empty roots: BuildRequest is constructed directly because
        // new_build_request refuses them first — the Build-side refusal
        // is the one under test.
        for (root_a, root_b) in [("", "/root/b"), ("/root/a", "")] {
            let mut req = isolation_req(Path::new("/root/a"), Path::new("/root/b"));
            req.root_a = root_a.to_owned();
            req.root_b = root_b.to_owned();
            let err = kit.build(OpDeadline::NONE, &req).unwrap_err();
            assert_eq!(err.code(), prepare_codes::BUILDER_ISOLATION);
        }
        // A dropped isolation flag refuses identically.
        let mut req = isolation_req(Path::new("/root/a"), Path::new("/root/b"));
        req.no_secrets = false;
        let err = kit.build(OpDeadline::NONE, &req).unwrap_err();
        assert_eq!(err.code(), prepare_codes::BUILDER_ISOLATION);
    }

    /// `TestHermeticBuildArgvIsPinned` — the exact argv, so a flag
    /// cannot be added without this failing; then the omission check
    /// for the flags whose absence IS the isolation guarantee.
    #[test]
    fn hermetic_build_argv_is_pinned() {
        let recipe = parse_build_recipe(&minimal_test_recipe()).expect("recipe");
        let got = hermetic_build_args(
            "central-dp-build-abcdef0123456789",
            Path::new("/roots/b/context"),
            Path::new("/roots/b/oci-output.tar"),
            &recipe,
        );
        let want: Vec<String> = [
            "--addr",
            "docker-container://central-dp-build-abcdef0123456789",
            "--wait",
            "build",
            "--frontend",
            "dockerfile.v0",
            "--local",
            "context=/roots/b/context",
            "--local",
            "dockerfile=/roots/b/context",
            "--opt",
            "platform=linux/amd64",
            "--opt",
            "build-arg:SOURCE_DATE_EPOCH=1700000000",
            "--opt",
            "build-arg:GO_VERSION=1.22",
            "--opt",
            "build-arg:SOURCE_REPO=https://example.invalid/central-b02-test",
            "--opt",
            "build-arg:SOURCE_COMMIT=0000000000000000000000000000000000000000",
            "--opt",
            "build-arg:GO_TARGET=.",
            "--opt",
            "build-arg:GO_TAGS=",
            "--opt",
            "build-arg:GO_LDFLAGS=-s -w",
            "--no-cache",
            "--output",
            "type=oci,dest=/roots/b/oci-output.tar,rewrite-timestamp=true,name=central-minio:000000000000",
        ]
        .iter()
        .map(ToString::to_string)
        .collect();
        assert_eq!(got, want, "the pinned buildctl argv drifted");

        for forbidden in [
            "--secret",
            "--ssh",
            "--allow",
            "--import-cache",
            "--export-cache",
        ] {
            for arg in &got {
                assert!(
                    !arg.starts_with(forbidden),
                    "the hermetic build passed {arg}, which breaks the isolation envelope"
                );
            }
        }
    }

    /// `TestOCIExportIsNamedSoTheBuiltImageCanBeLoaded` — the `name=`
    /// half is what makes `central-minio@<manifest digest>` resolvable
    /// after `docker load`; the pinned embedded recipe keeps it
    /// honest.
    #[test]
    fn oci_export_is_named_for_loading() {
        let lock = central_infra::prepare::load_lock().expect("lock");
        let recipe = parse_build_recipe(lock.minio_recipe()).expect("recipe");
        let got = oci_export_output_arg("/roots/b/oci-output.tar", &recipe);
        assert_eq!(
            got,
            "type=oci,dest=/roots/b/oci-output.tar,rewrite-timestamp=true,name=central-minio:9e49d5e7a648"
        );
        assert!(got.contains(&format!(",name={BUILT_IMAGE_REPOSITORY}:")));
        assert!(got.contains("rewrite-timestamp=true"));
    }

    /// `TestGeneratedDockerfileSetsAnEntrypoint` — SC-DEF-21's
    /// regression: the built image's only executable is `/app`, and a
    /// bare COPY sets no image-level entrypoint.
    #[test]
    fn generated_dockerfile_sets_an_entrypoint() {
        let dir = tempdir();
        write_generated_dockerfile(&dir).expect("write Dockerfile");
        let raw = fs::read_to_string(dir.join("Dockerfile")).expect("read Dockerfile");
        assert!(raw.contains(r#"ENTRYPOINT ["/app"]"#));
        assert!(raw.contains("--network=none"));
        assert!(raw.contains("SOURCE_DATE_EPOCH") || raw.contains("GO_VERSION"));
        fs::remove_dir_all(&dir).ok();
    }

    /// `parseBuildRecipe` — the embedded recipe parses, and each
    /// allowlist refuses what upstream refuses.
    #[test]
    fn recipe_allowlists_hold() {
        let lock = central_infra::prepare::load_lock().expect("lock");
        let recipe = parse_build_recipe(lock.minio_recipe()).expect("minio recipe parses");
        assert_eq!(
            recipe.source.commit,
            "9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a"
        );
        assert_eq!(recipe.build.go_version, "1.24");
        assert_eq!(recipe.build.target, ".");
        assert_eq!(recipe.build.tags, ["kqueue", "netgo"]);
        assert_eq!(recipe.build.ldflags, ["-s", "-w"]);

        // Commit must be 40 lowercase hex.
        let mut bad =
            serde_json::from_slice::<serde_json::Value>(&minimal_test_recipe()).expect("json");
        bad["source"]["commit"] = serde_json::Value::String("UPPER".to_owned() + &"0".repeat(35));
        assert!(parse_build_recipe(bad.to_string().as_bytes()).is_err());
        // Missing go_version.
        let mut bad =
            serde_json::from_slice::<serde_json::Value>(&minimal_test_recipe()).expect("json");
        bad["build"]["go_version"] = serde_json::Value::String(String::new());
        assert!(parse_build_recipe(bad.to_string().as_bytes()).is_err());
        // Shell-breaking target.
        let mut bad =
            serde_json::from_slice::<serde_json::Value>(&minimal_test_recipe()).expect("json");
        bad["build"]["target"] = serde_json::Value::String(".; rm -rf /".to_owned());
        assert!(parse_build_recipe(bad.to_string().as_bytes()).is_err());
        // Tag with whitespace.
        let mut bad =
            serde_json::from_slice::<serde_json::Value>(&minimal_test_recipe()).expect("json");
        bad["build"]["tags"] = serde_json::json!(["net go"]);
        assert!(parse_build_recipe(bad.to_string().as_bytes()).is_err());
        // ldflag with shell metacharacters.
        let mut bad =
            serde_json::from_slice::<serde_json::Value>(&minimal_test_recipe()).expect("json");
        bad["build"]["ldflags"] = serde_json::json!(["-s$(whoami)"]);
        assert!(parse_build_recipe(bad.to_string().as_bytes()).is_err());
    }

    /// `inventoryFromOCILayout` — a synthetic layout reads back its
    /// real digests: `index_digest` is the raw sha256 of index.json.
    #[test]
    fn inventory_reads_back_real_digests() {
        let dir = tempdir();
        let blobs = dir.join("blobs").join("sha256");
        fs::create_dir_all(&blobs).expect("blobs");
        let config = br#"{"architecture":"amd64"}"#.as_slice();
        let config_hex = hex_lower(&Sha256::digest(config));
        let layer = b"layer-bytes".as_slice();
        let layer_hex = hex_lower(&Sha256::digest(layer));
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "config": {
                "digest": format!("sha256:{config_hex}"),
                "size": config.len(),
            },
            "layers": [{
                "mediaType": "application/vnd.oci.image.layer.v1.tar",
                "digest": format!("sha256:{layer_hex}"),
                "size": layer.len(),
            }],
        })
        .to_string();
        let manifest_hex = hex_lower(&Sha256::digest(manifest.as_bytes()));
        fs::write(blobs.join(&config_hex), config).expect("config blob");
        fs::write(blobs.join(&layer_hex), layer).expect("layer blob");
        fs::write(blobs.join(&manifest_hex), &manifest).expect("manifest blob");
        let index = serde_json::json!({
            "schemaVersion": 2,
            "manifests": [{"digest": format!("sha256:{manifest_hex}")}],
        })
        .to_string();
        fs::write(dir.join("index.json"), &index).expect("index");

        let inv = inventory_from_oci_layout(&dir).expect("inventory");
        assert_eq!(
            inv.index_digest,
            format!("sha256:{}", hex_lower(&Sha256::digest(index.as_bytes())))
        );
        assert_eq!(inv.manifest_digest, format!("sha256:{manifest_hex}"));
        assert_eq!(inv.config_digest, format!("sha256:{config_hex}"));
        assert_eq!(inv.layers.len(), 1);
        assert_eq!(inv.layers[0].digest, format!("sha256:{layer_hex}"));

        // A two-manifest index refuses.
        fs::write(
            dir.join("index.json"),
            r#"{"schemaVersion":2,"manifests":[{"digest":"sha256:aaa"},{"digest":"sha256:bbb"}]}"#,
        )
        .expect("index");
        assert!(inventory_from_oci_layout(&dir).is_err());
        fs::remove_dir_all(&dir).ok();
    }

    /// `shortRootDigest` — deterministic, 16 lowercase hex.
    #[test]
    fn short_root_digest_is_stable() {
        let got = short_root_digest("/some/root");
        assert_eq!(got.len(), 16);
        assert!(got.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(got, short_root_digest("/some/root"));
        assert_ne!(got, short_root_digest("/other/root"));
    }

    /// `extractOCITar` — regular files and dirs land; odd members are
    /// skipped like upstream's default-less switch.
    #[test]
    fn extract_oci_tar_writes_members() {
        let dir = tempdir();
        let tar_path = dir.join("out.tar");
        {
            let file = fs::File::create(&tar_path).expect("tar");
            let mut builder = tar::Builder::new(file);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(3);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "index.json", b"abc".as_slice())
                .expect("member");
            builder.finish().expect("finish");
        }
        let out = dir.join("layout");
        extract_oci_tar(&tar_path, &out).expect("extract");
        assert_eq!(fs::read(out.join("index.json")).expect("member"), b"abc");
        fs::remove_dir_all(&dir).ok();
    }

    /// `write_generated_dockerfile` — exact bytes pinned so a recipe
    /// field can never be interpolated into Dockerfile text.
    #[test]
    fn dockerfile_is_byte_exact() {
        let dir = tempdir();
        write_generated_dockerfile(&dir).expect("write");
        let raw = fs::read_to_string(dir.join("Dockerfile")).expect("read");
        assert!(raw.starts_with("# syntax=docker/dockerfile:1.10.0\nARG GO_VERSION"));
        assert!(raw.ends_with("ENTRYPOINT [\"/app\"]\n"));
        // No recipe field is ever interpolated: the only ${...}
        // substitutions are Dockerfile build-args.
        for name in [
            "SOURCE_REPO",
            "SOURCE_COMMIT",
            "GO_TARGET",
            "GO_TAGS",
            "GO_LDFLAGS",
            "GO_VERSION",
        ] {
            assert!(raw.contains(&format!("ARG {name}")), "missing ARG {name}");
        }
        fs::remove_dir_all(&dir).ok();
    }
}
