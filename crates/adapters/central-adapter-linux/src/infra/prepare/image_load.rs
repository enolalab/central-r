//! `DockerImageLoader` — the port of upstream `imageload_linux.go`: the
//! step that makes a proven build resolvable in the host's local image
//! store under the name the promoted receipt will use.
//!
//! It is the only part of prepare that writes outside the operation's own
//! roots, and the narrowest possible use of the Docker socket: import one
//! file, ask the daemon what it now resolves, and pin that content under a
//! name derived from its own manifest digest. `docker load`'s output is
//! deliberately never parsed — on a store that cannot key an image by
//! manifest digest it succeeds and prints "Loaded image" while the digest
//! reference resolves to nothing — so the evidence is the inspection that
//! follows, byte-for-byte what the receipt inspector runs.
//!
//! Errors name the selector and what failed, never the export path, the
//! command line, or the daemon's output: the string reaches an
//! operator-facing reason, and a host path there is a redaction leak.

use std::path::Path;

use central_foundation::failure::Failure;
use central_infra::prepare::{ImageLoadRequest, LoadedImage, prepare_codes};

use super::release_stage::read_infra_save_manifest;
use super::{OpDeadline, run_bounded};

/// `containerdSnapshotterDriverType` — what `docker info` reports for a
/// daemon running the containerd image store, the only store that keys an
/// image record by manifest digest.
pub const CONTAINERD_SNAPSHOTTER_DRIVER_TYPE: &str = "io.containerd.snapshotter.v1";

const DOCKER_DRIVER_STATUS_KEY: &str = "driver-type";
const LOAD_CODE: &str = "IMAGE_LOAD";

/// The subprocess boundary — `(program, args, env, deadline)` → stdout
/// or a redacted failure string. Injectable so argv and the handling of
/// the daemon's answers are testable without a daemon.
pub type DockerExec =
    Box<dyn Fn(&str, &[String], &[String], OpDeadline) -> Result<Vec<u8>, String> + Send + Sync>;

/// `port.ImageLoader`.
pub trait ImageLoader: Send + Sync {
    /// `Supported` — the early probe: can this host's image store resolve
    /// an image by manifest digest at all.
    ///
    /// # Errors
    /// `IMAGE_LOAD` when it cannot, or cannot be inspected.
    fn supported(&self, deadline: OpDeadline) -> Result<(), Failure>;

    /// `Load` — import the proven build's export and report the identity
    /// the host now observes (observed, not assumed: the caller validates
    /// it against the proven identity).
    ///
    /// # Errors
    /// `IMAGE_LOAD_INVALID` for an invalid request; `IMAGE_LOAD` for any
    /// import, inspection or pin failure.
    fn load(&self, deadline: OpDeadline, req: &ImageLoadRequest) -> Result<LoadedImage, Failure>;
}

/// `closedLoaderEnvironment` — the closed environment a docker invocation
/// is given, so nothing from the operator's session leaks into it.
#[must_use]
pub fn closed_loader_environment() -> Vec<String> {
    [
        "PATH=/usr/bin:/bin",
        "HOME=/nonexistent",
        "LANG=C",
        "LC_ALL=C",
    ]
    .map(str::to_owned)
    .to_vec()
}

fn load_failure(message: impl Into<String>) -> Failure {
    Failure::internal(LOAD_CODE, message)
}

fn default_exec() -> DockerExec {
    Box::new(|name, args, env, deadline| {
        let mut cmd = std::process::Command::new(name);
        cmd.args(args)
            .env_clear()
            .envs(env.iter().filter_map(|e| e.split_once('=')));
        let output = run_bounded(deadline, &mut cmd, LOAD_CODE, "docker")
            .map_err(|e| e.message().to_owned())?;
        if output.status.success() {
            Ok(output.stdout)
        } else {
            Err("docker exited unsuccessfully".to_owned())
        }
    })
}

/// `DockerImageLoader`.
pub struct DockerImageLoader {
    docker_path: String,
    exec: DockerExec,
}

impl DockerImageLoader {
    /// `NewDockerImageLoader` — resolves `docker` on `PATH` once, at
    /// composition time, and requires an absolute path: a relative name
    /// would be resolved against whatever `PATH` the process inherited at
    /// call time.
    ///
    /// # Errors
    /// `IMAGE_LOAD` when docker cannot be found.
    pub fn from_path() -> Result<Self, Failure> {
        let path = std::env::var_os("PATH")
            .into_iter()
            .flat_map(|p| std::env::split_paths(&p).collect::<Vec<_>>())
            .map(|d| d.join("docker"))
            .find(|p| p.is_absolute() && p.is_file())
            .ok_or_else(|| {
                load_failure(
                    "dependencyprepare: docker is required to make a built image resolvable",
                )
            })?;
        Ok(Self::new(path.to_string_lossy().into_owned()))
    }

    /// An explicit docker path and the real subprocess boundary.
    #[must_use]
    pub fn new(docker_path: impl Into<String>) -> Self {
        Self {
            docker_path: docker_path.into(),
            exec: default_exec(),
        }
    }

    /// Replace the subprocess boundary (tests).
    #[must_use]
    pub fn with_exec(mut self, exec: DockerExec) -> Self {
        self.exec = exec;
        self
    }

    fn require_path(&self) -> Result<(), Failure> {
        if self.docker_path.starts_with('/') {
            Ok(())
        } else {
            Err(load_failure(
                "dependencyprepare: image loader has no absolute docker path",
            ))
        }
    }

    fn run(&self, deadline: OpDeadline, args: &[&str]) -> Result<Vec<u8>, String> {
        let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
        (self.exec)(
            &self.docker_path,
            &args,
            &closed_loader_environment(),
            deadline,
        )
    }

    /// `LoadInfraTarball` — load a docker-save tarball and prove it is the
    /// pinned infra image: the tarball's config must equal the pinned
    /// config, and the tag it names must inspect to the pinned MANIFEST
    /// digest. Unlike [`ImageLoader::load`] it tags nothing: the
    /// tarball's own digest-stable references are what the receipt
    /// resolves.
    ///
    /// # Errors
    /// `RELEASE_UNTRUSTED` / `RELEASE_INVALID` for a tarball that is not
    /// the pinned image; `IMAGE_LOAD` for import or inspection failures.
    pub fn load_infra_tarball(
        &self,
        deadline: OpDeadline,
        tar_path: &Path,
        pin_manifest_digest: &str,
        pin_config_digest: &str,
    ) -> Result<(), Failure> {
        self.require_path()?;
        let scratch = std::env::temp_dir().join(format!(
            "infra-save-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&scratch)
            .map_err(|e| load_failure(format!("dependencyprepare: infra temp dir: {e}")))?;
        let result = (|| {
            let (config, tags) = read_infra_save_manifest(tar_path, &scratch)?;
            if config != pin_config_digest {
                return Err(Failure::invalid(
                    prepare_codes::RELEASE_UNTRUSTED,
                    format!(
                        "dependencyprepare: release untrusted: infra tarball config {config}, lock pins {pin_config_digest}"
                    ),
                ));
            }
            let Some(tag) = tags.first() else {
                return Err(Failure::invalid(
                    prepare_codes::RELEASE_INVALID,
                    "dependencyprepare: release invalid: infra tarball names no tag to resolve",
                ));
            };
            let tar = tar_path.to_string_lossy();
            self.run(deadline, &["load", "-i", &tar]).map_err(|_| {
                load_failure(
                    "dependencyprepare: importing the infra image into the local image store failed",
                )
            })?;
            let output = self
                .run(deadline, &["image", "inspect", "--format", "{{.Id}}", tag])
                .map_err(|_| {
                    load_failure(format!(
                        "dependencyprepare: the imported infra image is not resolvable as {tag}"
                    ))
                })?;
            let got = String::from_utf8_lossy(&output).trim().to_owned();
            if got != pin_manifest_digest {
                return Err(Failure::invalid(
                    prepare_codes::RELEASE_UNTRUSTED,
                    format!(
                        "dependencyprepare: release untrusted: infra image resolved to {got}, lock pins {pin_manifest_digest}"
                    ),
                ));
            }
            Ok(())
        })();
        let _ = std::fs::remove_dir_all(&scratch);
        result
    }
}

impl ImageLoader for DockerImageLoader {
    fn supported(&self, deadline: OpDeadline) -> Result<(), Failure> {
        self.require_path()?;
        // The daemon's own output is deliberately dropped: it carries host
        // paths and daemon configuration.
        let output = self
            .run(deadline, &["info", "--format", "{{json .DriverStatus}}"])
            .map_err(|_| {
                load_failure("dependencyprepare: docker image store could not be inspected")
            })?;
        let status: Vec<Vec<String>> =
            serde_json::from_str(String::from_utf8_lossy(&output).trim()).map_err(|_| {
                load_failure("dependencyprepare: docker image store type could not be determined")
            })?;
        if status.iter().any(|pair| {
            pair.len() == 2
                && pair[0] == DOCKER_DRIVER_STATUS_KEY
                && pair[1] == CONTAINERD_SNAPSHOTTER_DRIVER_TYPE
        }) {
            return Ok(());
        }
        Err(load_failure(format!(
            "docker's classic graph-driver image store cannot resolve an image by manifest digest; the containerd image store ({CONTAINERD_SNAPSHOTTER_DRIVER_TYPE}) is required"
        )))
    }

    fn load(&self, deadline: OpDeadline, req: &ImageLoadRequest) -> Result<LoadedImage, Failure> {
        self.require_path()?;
        req.validate()?;
        self.run(deadline, &["load", "-i", &req.export]).map_err(|_| {
            load_failure(format!(
                "dependencyprepare: importing the proven build for {:?} into the local image store failed",
                req.selector
            ))
        })?;
        let reference = req.reference();
        let output = self
            .run(
                deadline,
                &["image", "inspect", "--format", "{{.Id}}", &reference],
            )
            .ok()
            .filter(|o| !o.is_empty())
            .ok_or_else(|| {
                load_failure(format!(
                    "dependencyprepare: the imported image for {:?} is not resolvable as {reference}",
                    req.selector
                ))
            })?;
        // Resolvable now is not resolvable later: the exported name is a
        // mutable repository:tag pointer. Pinning under a name derived
        // from the manifest digest makes the receipt durable; repeating it
        // is a no-op onto the same name. Runs after the inspection so a
        // host that cannot key by digest reports that as the reason.
        self.run(deadline, &["tag", &reference, &req.pinned_reference()])
            .map_err(|_| {
                load_failure(format!(
                    "dependencyprepare: pinning the imported image for {:?} under its own manifest digest failed",
                    req.selector
                ))
            })?;
        Ok(LoadedImage {
            reference,
            image_id: String::from_utf8_lossy(&output).trim().to_owned(),
        })
    }
}

/// `unavailableImageLoader` — wired when docker cannot be found, so a host
/// without docker still gets a real loader that fails closed in seconds at
/// the capacity checkpoint, rather than a nil loader the state machine
/// would report as an unconfigured service.
pub struct UnavailableImageLoader {
    reason: Failure,
}

impl UnavailableImageLoader {
    /// Wrap the failure every call will return.
    #[must_use]
    pub fn new(reason: Failure) -> Self {
        Self { reason }
    }
}

impl ImageLoader for UnavailableImageLoader {
    fn supported(&self, _deadline: OpDeadline) -> Result<(), Failure> {
        Err(self.reason.clone())
    }

    fn load(&self, _deadline: OpDeadline, _req: &ImageLoadRequest) -> Result<LoadedImage, Failure> {
        Err(self.reason.clone())
    }
}

/// `imageLoaderFor` — turns the constructor's two-valued answer into the one
/// thing the service may be given: a loader.
#[must_use]
pub fn image_loader_for(loader: Result<DockerImageLoader, Failure>) -> Box<dyn ImageLoader> {
    match loader {
        Ok(l) => Box::new(l),
        Err(reason) => Box::new(UnavailableImageLoader::new(reason)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use central_infra::domain::OciInventory;
    use std::sync::{Arc, Mutex};

    type Calls = Arc<Mutex<Vec<Vec<String>>>>;

    fn recording(answers: Vec<Result<Vec<u8>, String>>) -> (DockerExec, Calls) {
        let calls: Calls = Arc::default();
        let answers = Mutex::new(answers.into_iter());
        let seen = Arc::clone(&calls);
        let exec: DockerExec = Box::new(move |_, args, env, _| {
            assert_eq!(env, closed_loader_environment().as_slice());
            seen.lock().expect("calls").push(args.to_vec());
            answers
                .lock()
                .expect("answers")
                .next()
                .unwrap_or_else(|| Err("unexpected call".to_owned()))
        });
        (exec, calls)
    }

    fn request() -> ImageLoadRequest {
        ImageLoadRequest {
            selector: "minio".to_owned(),
            export: "/work/op/one/a/oci.tar".to_owned(),
            proven: OciInventory {
                index_digest: format!("sha256:{}", "1".repeat(64)),
                manifest_digest: format!("sha256:{}", "2".repeat(64)),
                config_digest: format!("sha256:{}", "3".repeat(64)),
                layers: vec![],
            },
        }
    }

    fn loader(answers: Vec<Result<Vec<u8>, String>>) -> (DockerImageLoader, Calls) {
        let (exec, calls) = recording(answers);
        (
            DockerImageLoader::new("/usr/bin/docker").with_exec(exec),
            calls,
        )
    }

    #[test]
    fn supported_requires_the_containerd_image_store() {
        let ok = br#"[["driver-type","io.containerd.snapshotter.v1"]]"#.to_vec();
        let (l, calls) = loader(vec![Ok(ok)]);
        l.supported(OpDeadline::NONE).expect("supported");
        assert_eq!(
            calls.lock().expect("c")[0],
            ["info", "--format", "{{json .DriverStatus}}"]
        );
        let classic = br#"[["Backing Filesystem","extfs"]]"#.to_vec();
        let (l, _) = loader(vec![Ok(classic)]);
        assert!(
            l.supported(OpDeadline::NONE)
                .expect_err("classic")
                .message()
                .contains("containerd image store")
        );
    }

    #[test]
    fn supported_redacts_daemon_output_on_failure() {
        let (l, _) = loader(vec![Err("secret host path /var/lib/docker".to_owned())]);
        let err = l.supported(OpDeadline::NONE).expect_err("fail");
        assert!(!err.message().contains("/var/lib"));
        let (l, _) = loader(vec![Ok(b"not json".to_vec())]);
        assert!(l.supported(OpDeadline::NONE).is_err());
    }

    #[test]
    fn load_imports_inspects_then_pins_in_that_order() {
        let req = request();
        let id = format!("sha256:{}", "2".repeat(64));
        let (l, calls) = loader(vec![
            Ok(b"Loaded image".to_vec()),
            Ok(format!("{id}\n").into_bytes()),
            Ok(Vec::new()),
        ]);
        let got = l.load(OpDeadline::NONE, &req).expect("load");
        assert_eq!(got.reference, req.reference());
        assert_eq!(got.image_id, id);
        let calls = calls.lock().expect("c");
        assert_eq!(calls[0], ["load", "-i", "/work/op/one/a/oci.tar"]);
        assert_eq!(
            calls[1],
            ["image", "inspect", "--format", "{{.Id}}", &req.reference()]
        );
        assert_eq!(calls[2], ["tag", &req.reference(), &req.pinned_reference()]);
    }

    #[test]
    fn load_failures_never_leak_paths_or_daemon_output() {
        let req = request();
        let (l, _) = loader(vec![Err("open /work/op/one/a/oci.tar: denied".to_owned())]);
        assert!(
            !l.load(OpDeadline::NONE, &req)
                .expect_err("import")
                .message()
                .contains("/work")
        );
        let (l, calls) = loader(vec![Ok(Vec::new()), Ok(Vec::new())]);
        let err = l.load(OpDeadline::NONE, &req).expect_err("unresolvable");
        assert!(err.message().contains("not resolvable"));
        assert_eq!(
            calls.lock().expect("c").len(),
            2,
            "no pin after a failed inspection"
        );
        let (l, _) = loader(vec![
            Ok(Vec::new()),
            Ok(b"id".to_vec()),
            Err("tag boom".to_owned()),
        ]);
        assert!(
            l.load(OpDeadline::NONE, &req)
                .expect_err("pin")
                .message()
                .contains("pinning")
        );
    }

    #[test]
    fn invalid_request_and_relative_docker_path_are_refused_before_any_call() {
        let mut req = request();
        req.export.clear();
        let (l, calls) = loader(vec![]);
        assert!(l.load(OpDeadline::NONE, &req).is_err());
        assert!(calls.lock().expect("c").is_empty());
        let rel = DockerImageLoader::new("docker");
        assert!(rel.supported(OpDeadline::NONE).is_err());
        assert!(rel.load(OpDeadline::NONE, &request()).is_err());
    }

    #[test]
    fn unavailable_loader_fails_closed_on_both_calls() {
        let l = UnavailableImageLoader::new(load_failure("no docker"));
        assert!(l.supported(OpDeadline::NONE).is_err());
        assert!(l.load(OpDeadline::NONE, &request()).is_err());
        assert!(
            image_loader_for(Err(load_failure("x")))
                .supported(OpDeadline::NONE)
                .is_err()
        );
    }
}
