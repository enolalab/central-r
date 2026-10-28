//! `cmd/central/postgres_service_role_compose_runner.go` + the
//! `postgresFirstBootBootstrap` tail of
//! `cmd/central/postgres_superuser_credential.go` +
//! `cmd/central/lifecycle_broker_rendezvous.go` — the composition-root
//! lifecycle decorations (upstream lives in `cmd/central`, this
//! codebase's composition root is the helper daemon).
//!
//! - [`PostgresServiceRoleComposeRunner`] decorates
//!   `ComposeRunner::up` so ADR 0019 §4's rotate-then-sync runs
//!   immediately after `docker compose up` reports the postgres
//!   service healthy.
//! - [`PostgresFirstBootBootstrap`] decorates the broker-backed
//!   lifecycle bootstrap so the postgres daemon's first-boot passfile
//!   is materialized in the same pre-up window that materializes
//!   MinIO's root credential.
//! - [`LifecycleBrokerRendezvous`] supplies the bring-up path the
//!   broker socket entry the rendered minio-provision mount
//!   bind-mounts.
//!
//! LC-T4 wires all three into `helper::daemon`'s lifecycle
//! composition; until then they carry `dead_code` allows on their
//! constructors.

use std::collections::BTreeMap;
use std::sync::Arc;

use central_foundation::failure::Failure;
use central_infra::domain::{B04LifecycleEvidence, LifecycleBinding};
use central_infra::port::{
    B04Bootstrap, BootstrapGeneration, BootstrapHandoff, BootstrapPurpose, LifecycleBootstrap,
    MountProof,
};

use crate::helper::minio_provision::ensure_backup_minio_broker_rendezvous;
use crate::helper::pg_credentials::{
    ProductionPostgresServiceRoleCredentialStore, ProductionPostgresSuperuserCredentialStore,
};
use crate::infra::compose::{
    ComposeError, ComposeRunner, ContainerInspection, RenderedFile, RenderedModel,
};
use crate::infra::lifecycle::{BrokerRendezvous, FileBootstrap};
use crate::infra::prepare::OpDeadline;

/// The shared `errors.New` refusal for a decorator composed without
/// both halves — a composition bug, never a partial drive.
#[allow(dead_code)] // used by the decorators' port impls once wired in LC-T4
fn bootstrap_composition_unavailable() -> Failure {
    Failure::internal(
        "postgres_first_boot",
        "postgres superuser first boot: bootstrap composition unavailable",
    )
}

// ---------------------------------------------------------------------------
// `postgresServiceRoleComposeRunner` — ADR 0019 §4's rotate-then-sync
// in the postgres health window.
// ---------------------------------------------------------------------------

/// `PostgresServiceRoleSync` — the one call the `up` decorator makes
/// on the credential store (upstream's concrete
/// `*productionPostgresServiceRoleCredentialStore` field, narrowed to
/// a port so composition tests record the call without a live
/// server).
#[allow(dead_code)] // consumed by `PostgresServiceRoleComposeRunner`, wired in LC-T4
pub(crate) trait PostgresServiceRoleSync: Send + Sync {
    /// `Sync`.
    fn sync(&self) -> Result<(), Failure>;
}

impl PostgresServiceRoleSync for ProductionPostgresServiceRoleCredentialStore {
    fn sync(&self) -> Result<(), Failure> {
        ProductionPostgresServiceRoleCredentialStore::sync(self)
    }
}

/// `postgresServiceRoleComposeRunner` — decorates a `ComposeRunner`
/// so ADR 0019 §4's rotate-then-sync runs immediately after
/// `docker compose up` reports the postgres service healthy —
/// mirroring how [`PostgresFirstBootBootstrap`] decorates
/// `Bootstrap::materialize` to run the superuser's own first-boot
/// step in the pre-up window. `up`'s `--wait` flag
/// (`CommandComposeRunner::up`) is what makes "the underlying up call
/// returned with no error" mean the healthcheck already passed;
/// running the service roles' rotate-then-sync any earlier would
/// race postgres's own startup.
///
/// Every other `ComposeRunner` method is the embedded, undecorated
/// implementation.
#[allow(dead_code)] // the daemon lifecycle composition wires this in LC-T4
pub(crate) struct PostgresServiceRoleComposeRunner {
    inner: Arc<dyn ComposeRunner>,
    roles: Option<Arc<dyn PostgresServiceRoleSync>>,
}

impl PostgresServiceRoleComposeRunner {
    /// `postgresServiceRoleComposeRunner{ComposeRunner: inner, roles: roles}`
    /// — a `None` roles store is upstream's nil field: `up` still
    /// decorates, the sync step is simply absent.
    #[allow(dead_code)] // the daemon lifecycle composition wires this in LC-T4
    pub(crate) fn new(
        inner: Arc<dyn ComposeRunner>,
        roles: Option<Arc<dyn PostgresServiceRoleSync>>,
    ) -> Self {
        Self { inner, roles }
    }
}

/// `composeServicesInclude` — reports whether `services` names `name`
/// explicitly, or is empty: `up`'s own contract for "every service".
#[allow(dead_code)] // used by `PostgresServiceRoleComposeRunner::up`, wired in LC-T4
fn compose_services_include(services: &[String], name: &str) -> bool {
    services.is_empty() || services.iter().any(|s| s == name)
}

impl ComposeRunner for PostgresServiceRoleComposeRunner {
    fn config(
        &self,
        f: &RenderedFile,
        deadline: OpDeadline,
    ) -> Result<RenderedModel, ComposeError> {
        self.inner.config(f, deadline)
    }

    /// `Up` — delegate first; on success and only when postgres is
    /// among the started services (an empty list is "every service"),
    /// run the service roles' rotate-then-sync. The sync failure
    /// wraps with upstream's exact prefix.
    fn up(
        &self,
        f: &RenderedFile,
        services: &[String],
        deadline: OpDeadline,
    ) -> Result<(), ComposeError> {
        self.inner.up(f, services, deadline)?;
        let Some(roles) = &self.roles else {
            return Ok(());
        };
        if !compose_services_include(services, "postgres") {
            return Ok(());
        }
        roles.sync().map_err(|e| {
            ComposeError::Other(format!("postgres service role rotate-then-sync: {e}"))
        })
    }

    fn run_with_input(
        &self,
        f: &RenderedFile,
        service: &str,
        args: &[String],
        stdin: &[u8],
        deadline: OpDeadline,
    ) -> Result<i32, ComposeError> {
        self.inner.run_with_input(f, service, args, stdin, deadline)
    }

    fn run_with_input_output(
        &self,
        f: &RenderedFile,
        service: &str,
        args: &[String],
        stdin: &[u8],
        deadline: OpDeadline,
    ) -> Result<(Vec<u8>, i32), ComposeError> {
        self.inner
            .run_with_input_output(f, service, args, stdin, deadline)
    }

    fn down(&self, f: &RenderedFile, deadline: OpDeadline) -> Result<(), ComposeError> {
        self.inner.down(f, deadline)
    }

    fn inspect(
        &self,
        container_id: &str,
        deadline: OpDeadline,
    ) -> Result<ContainerInspection, ComposeError> {
        self.inner.inspect(container_id, deadline)
    }

    fn containers(
        &self,
        f: &RenderedFile,
        services: &[String],
        deadline: OpDeadline,
    ) -> Result<BTreeMap<String, ContainerInspection>, ComposeError> {
        self.inner.containers(f, services, deadline)
    }

    fn stopped(
        &self,
        f: &RenderedFile,
        services: &[String],
        deadline: OpDeadline,
    ) -> Result<(), ComposeError> {
        self.inner.stopped(f, services, deadline)
    }
}

// ---------------------------------------------------------------------------
// `postgresFirstBootBootstrap` — the superuser's first-boot passfile
// in the same pre-up window as the B04 MinIO ceremony.
// ---------------------------------------------------------------------------

/// `PostgresSuperuserFirstBoot` — the one call the bootstrap
/// decorator makes on the superuser credential store (upstream's
/// concrete `*productionPostgresSuperuserCredentialStore` field,
/// narrowed to a port so composition tests record the ordering).
#[allow(dead_code)] // consumed by `PostgresFirstBootBootstrap`, wired in LC-T4
pub(crate) trait PostgresSuperuserFirstBoot: Send + Sync {
    /// `EnsureFirstBootMaterialized`.
    fn ensure_first_boot_materialized(&self) -> Result<(), Failure>;
}

impl PostgresSuperuserFirstBoot for ProductionPostgresSuperuserCredentialStore {
    fn ensure_first_boot_materialized(&self) -> Result<(), Failure> {
        ProductionPostgresSuperuserCredentialStore::ensure_first_boot_materialized(self)
    }
}

/// `postgresFirstBootBootstrap` — decorates the broker-backed
/// lifecycle bootstrap so the postgres daemon's first-boot passfile
/// is materialized in the same pre-up window that materializes
/// MinIO's root credential — before any service starts.
/// Materializing postgres first keeps the two independent: a failed
/// B04 MinIO ceremony still leaves the postgres passfile in place.
/// Every other bootstrap method is the embedded broker-backed
/// implementation.
#[allow(dead_code)] // the daemon lifecycle composition wires this in LC-T4
pub(crate) struct PostgresFirstBootBootstrap<B: B04Bootstrap> {
    /// `*infraadapter.FileBootstrap` — `Option` so the decorator can
    /// express upstream's nilable embedded field; the production
    /// composition always installs the broker-backed `FileBootstrap`.
    inner: Option<Arc<FileBootstrap<B>>>,
    /// `superuser` — same nilable-field treatment as `inner`.
    superuser: Option<Arc<dyn PostgresSuperuserFirstBoot>>,
}

impl<B: B04Bootstrap> PostgresFirstBootBootstrap<B> {
    /// `postgresFirstBootBootstrap{FileBootstrap: inner, superuser: superuser}`.
    #[allow(dead_code)] // the daemon lifecycle composition wires this in LC-T4
    pub(crate) fn new(
        inner: Arc<FileBootstrap<B>>,
        superuser: Arc<dyn PostgresSuperuserFirstBoot>,
    ) -> Self {
        Self {
            inner: Some(inner),
            superuser: Some(superuser),
        }
    }

    /// The embedded broker-backed implementation — where upstream's
    /// nil embed would panic, the port refuses with the same
    /// composition-unavailable message `materialize` checks for.
    #[allow(dead_code)] // used by the port impls once wired in LC-T4
    fn delegate(&self) -> Result<&Arc<FileBootstrap<B>>, Failure> {
        self.inner
            .as_ref()
            .ok_or_else(bootstrap_composition_unavailable)
    }
}

impl<B: B04Bootstrap> LifecycleBootstrap for PostgresFirstBootBootstrap<B> {
    async fn ensure(
        &self,
        binding: &LifecycleBinding,
        purpose: BootstrapPurpose,
    ) -> Result<BootstrapGeneration, Failure> {
        self.delegate()?.ensure(binding, purpose).await
    }

    /// `Materialize` — the superuser's first-boot materialization runs
    /// FIRST (postgres before MinIO: a failed B04 ceremony still
    /// leaves the postgres passfile in place), then the embedded
    /// broker-backed materialize runs.
    async fn materialize(&self, handoff: BootstrapHandoff) -> Result<MountProof, Failure> {
        let (Some(inner), Some(superuser)) = (self.inner.as_ref(), self.superuser.as_ref()) else {
            return Err(bootstrap_composition_unavailable());
        };
        superuser.ensure_first_boot_materialized().map_err(|e| {
            // `fmt.Errorf("postgres superuser first boot: %w", err)` —
            // the kind is preserved like `%w` preserves the wrapped
            // error.
            Failure::new(
                e.kind(),
                "postgres_first_boot",
                format!("postgres superuser first boot: {e}"),
            )
        })?;
        inner.materialize(handoff).await
    }

    async fn cleanup(&self, proof: MountProof) -> Result<(), Failure> {
        self.delegate()?.cleanup(proof).await
    }

    async fn record_handoff(
        &self,
        binding: &LifecycleBinding,
        proof: &MountProof,
    ) -> Result<(), Failure> {
        self.delegate()?.record_handoff(binding, proof).await
    }

    async fn cleanup_binding(&self, binding: &LifecycleBinding) -> Result<(), Failure> {
        self.delegate()?.cleanup_binding(binding).await
    }
}

/// The typed B04 authority delegates straight through, matching
/// upstream's embedded `*FileBootstrap` promoting its `B04Bootstrap`
/// methods — and what `ProductionServiceConfig::bootstrap`'s `D`
/// bound requires.
impl<B: B04Bootstrap> B04Bootstrap for PostgresFirstBootBootstrap<B> {
    async fn adopt_b03_minio(&self, evidence: B04LifecycleEvidence) -> Result<(), Failure> {
        self.delegate()?.adopt_b03_minio(evidence).await
    }

    async fn materialize_minio_root(
        &self,
        handoff: BootstrapHandoff,
    ) -> Result<MountProof, Failure> {
        self.delegate()?.materialize_minio_root(handoff).await
    }

    async fn issue_lifecycle_proof(&self, evidence: B04LifecycleEvidence) -> Result<(), Failure> {
        self.delegate()?.issue_lifecycle_proof(evidence).await
    }
}

// ---------------------------------------------------------------------------
// `lifecycleBrokerRendezvous` — the bring-up path's broker socket
// entry.
// ---------------------------------------------------------------------------

/// `lifecycleBrokerRendezvous` — supplies the bring-up path with the
/// same broker socket entry the backup and C02 preparers already
/// create.
///
/// Render mounts `/run/central-infra/<instance>/broker/minio-provision.sock`
/// into the minio-provision container (`addBrokerSocketMount`), but
/// before this type existed the only creator of that entry was
/// `prepareBackupMinioOperation`, which `Topology::provision_minio`
/// never reaches. On the bring-up path the bind source therefore did
/// not exist, Docker created it as an empty directory, and the
/// provisioner's unix dial failed inside the container (upstream's
/// 2026-08-03 SB-G3 acceptance gap).
///
/// It lives in the composition root rather than in the adapter
/// because creating it hardlinks the real root-owned broker socket.
/// [`ensure_backup_minio_broker_rendezvous`] holds the entire trust
/// discipline — the source must be a root-owned socket, every
/// ancestor directory must be root-owned and not group/other
/// writable, an existing entry must itself be a root-owned socket,
/// and a stale entry pointing at a different inode is unlinked
/// rather than trusted — so this delegates to it instead of
/// restating any of it.
#[allow(dead_code)] // the daemon lifecycle composition wires this in LC-T4
pub(crate) struct LifecycleBrokerRendezvous {
    source_socket: String,
}

impl LifecycleBrokerRendezvous {
    /// `newLifecycleBrokerRendezvous`.
    #[allow(dead_code)] // the daemon lifecycle composition wires this in LC-T4
    pub(crate) fn new(source_socket: &str) -> Self {
        Self {
            source_socket: source_socket.to_owned(),
        }
    }
}

impl BrokerRendezvous for LifecycleBrokerRendezvous {
    /// `EnsureMinioProvisionRendezvous` — idempotent:
    /// `ensure_backup_minio_broker_rendezvous` returns early when the
    /// destination already names the same socket inode, so a retried
    /// or resumed operation re-links nothing.
    fn ensure_minio_provision_rendezvous(&self, instance_id: &str) -> Result<(), Failure> {
        ensure_backup_minio_broker_rendezvous(&self.source_socket, instance_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use central_infra::domain::ServiceMode;
    use central_infra::port::HandoffLifetime;

    use crate::infra::lifecycle::{SystemClock, block_on};

    /// A unique scratch directory under `std::env::temp_dir` — the
    /// same convention `helper::pg_credentials`'s tests use.
    fn tempdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("lc-compose-{tag}-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn rendered_file() -> RenderedFile {
        RenderedFile {
            path: "/tmp/lc-compose-test.yaml".to_owned(),
            content: b"services: {}".to_vec(),
        }
    }

    /// A `LifecycleBinding` passing `validate` (`record_handoff`/`ensure`
    /// call it on the delegate).
    fn binding() -> LifecycleBinding {
        LifecycleBinding {
            instance_id: "inst-1".to_owned(),
            config_binding: "cfg-1".to_owned(),
            receipt_id: "receipt-1".to_owned(),
            payload_epoch: "epoch-1".to_owned(),
            ..LifecycleBinding::default()
        }
    }

    /// A `BootstrapHandoff` inside `FileBootstrap::materialize`'s
    /// fixed MinIO destination window.
    fn handoff(instance_id: &str) -> BootstrapHandoff {
        BootstrapHandoff {
            instance_id: instance_id.to_owned(),
            purpose: BootstrapPurpose::FirstSetup,
            service: ServiceMode::Minio,
            target: format!("/run/central-infra/{instance_id}/secrets"),
            uid: 1000,
            gid: 1000,
            lifetime: HandoffLifetime::default(),
            container_id: "ctr-1".to_owned(),
            b04_operation_id: String::new(),
            b04_binding_id: String::new(),
            b04_receipt_id: String::new(),
            b04_fencing_token: 0,
            b04_stopped_topology_proof: String::new(),
            b04_mount_release_proof: String::new(),
            b04_binding_evidence: String::new(),
        }
    }

    // -- PostgresServiceRoleComposeRunner ---------------------------------

    /// Records `up` service lists and replays a scripted failure; the
    /// other methods are the undecorated contract's happy path.
    #[derive(Default)]
    struct FakeRunner {
        ups: Mutex<Vec<Vec<String>>>,
        up_err: Mutex<Option<ComposeError>>,
    }

    impl ComposeRunner for FakeRunner {
        fn config(&self, _f: &RenderedFile, _d: OpDeadline) -> Result<RenderedModel, ComposeError> {
            Ok(RenderedModel::default())
        }
        fn up(
            &self,
            _f: &RenderedFile,
            services: &[String],
            _d: OpDeadline,
        ) -> Result<(), ComposeError> {
            self.ups.lock().unwrap().push(services.to_vec());
            match &*self.up_err.lock().unwrap() {
                Some(e) => Err(e.clone()),
                None => Ok(()),
            }
        }
        fn run_with_input(
            &self,
            _f: &RenderedFile,
            _s: &str,
            _a: &[String],
            _i: &[u8],
            _d: OpDeadline,
        ) -> Result<i32, ComposeError> {
            Ok(0)
        }
        fn run_with_input_output(
            &self,
            _f: &RenderedFile,
            _s: &str,
            _a: &[String],
            _i: &[u8],
            _d: OpDeadline,
        ) -> Result<(Vec<u8>, i32), ComposeError> {
            Ok((Vec::new(), 0))
        }
        fn down(&self, _f: &RenderedFile, _d: OpDeadline) -> Result<(), ComposeError> {
            Ok(())
        }
        fn inspect(&self, _id: &str, _d: OpDeadline) -> Result<ContainerInspection, ComposeError> {
            Ok(ContainerInspection::default())
        }
        fn containers(
            &self,
            _f: &RenderedFile,
            _s: &[String],
            _d: OpDeadline,
        ) -> Result<BTreeMap<String, ContainerInspection>, ComposeError> {
            Ok(BTreeMap::new())
        }
        fn stopped(
            &self,
            _f: &RenderedFile,
            _s: &[String],
            _d: OpDeadline,
        ) -> Result<(), ComposeError> {
            Ok(())
        }
    }

    /// Records `sync` calls and replays a scripted failure.
    #[derive(Default)]
    struct FakeRoles {
        calls: AtomicUsize,
        err: Mutex<Option<Failure>>,
    }

    impl PostgresServiceRoleSync for FakeRoles {
        fn sync(&self) -> Result<(), Failure> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match &*self.err.lock().unwrap() {
                Some(e) => Err(e.clone()),
                None => Ok(()),
            }
        }
    }

    /// `up` runs the rotate-then-sync when postgres is among the
    /// started services — strictly after the healthy `up` returned.
    #[test]
    fn up_runs_sync_when_postgres_in_services() {
        let roles = Arc::new(FakeRoles::default());
        let runner = PostgresServiceRoleComposeRunner::new(
            Arc::new(FakeRunner::default()),
            Some(roles.clone()),
        );
        runner
            .up(
                &rendered_file(),
                &["minio".to_owned(), "postgres".to_owned()],
                OpDeadline::NONE,
            )
            .unwrap();
        assert_eq!(roles.calls.load(Ordering::SeqCst), 1);
    }

    /// An empty service list is `up`'s "every service" — postgres
    /// included — so the sync runs.
    #[test]
    fn up_runs_sync_when_services_empty() {
        let roles = Arc::new(FakeRoles::default());
        let runner = PostgresServiceRoleComposeRunner::new(
            Arc::new(FakeRunner::default()),
            Some(roles.clone()),
        );
        runner.up(&rendered_file(), &[], OpDeadline::NONE).unwrap();
        assert_eq!(roles.calls.load(Ordering::SeqCst), 1);
    }

    /// postgres absent from an explicit list → no sync.
    #[test]
    fn up_skips_sync_when_postgres_absent() {
        let roles = Arc::new(FakeRoles::default());
        let runner = PostgresServiceRoleComposeRunner::new(
            Arc::new(FakeRunner::default()),
            Some(roles.clone()),
        );
        runner
            .up(&rendered_file(), &["minio".to_owned()], OpDeadline::NONE)
            .unwrap();
        assert_eq!(roles.calls.load(Ordering::SeqCst), 0);
    }

    /// A nil roles store is upstream's `r.roles == nil` — `up` still
    /// passes with no sync step.
    #[test]
    fn up_with_nil_roles_store_skips_sync() {
        let runner = PostgresServiceRoleComposeRunner::new(Arc::new(FakeRunner::default()), None);
        runner.up(&rendered_file(), &[], OpDeadline::NONE).unwrap();
    }

    /// The runner's failure propagates verbatim and the sync never
    /// runs — upstream returns the `up` error before the roles check.
    #[test]
    fn up_runner_error_propagates_without_sync() {
        let roles = Arc::new(FakeRoles::default());
        let inner = Arc::new(FakeRunner::default());
        *inner.up_err.lock().unwrap() = Some(ComposeError::Other(
            "compose: up: docker exploded".to_owned(),
        ));
        let runner = PostgresServiceRoleComposeRunner::new(inner, Some(roles.clone()));
        let err = runner
            .up(&rendered_file(), &[], OpDeadline::NONE)
            .unwrap_err();
        assert!(err.to_string().contains("docker exploded"), "{err}");
        assert_eq!(roles.calls.load(Ordering::SeqCst), 0);
    }

    /// The sync failure wraps with upstream's exact
    /// `postgres service role rotate-then-sync: %w` prefix.
    #[test]
    fn up_sync_error_wraps_with_upstream_prefix() {
        let roles = Arc::new(FakeRoles::default());
        *roles.err.lock().unwrap() = Some(Failure::denied("pg_credentials", "broker bind denied"));
        let runner =
            PostgresServiceRoleComposeRunner::new(Arc::new(FakeRunner::default()), Some(roles));
        let err = runner
            .up(&rendered_file(), &["postgres".to_owned()], OpDeadline::NONE)
            .unwrap_err();
        assert!(
            err.to_string()
                .starts_with("postgres service role rotate-then-sync: "),
            "{err}"
        );
        assert!(err.to_string().contains("broker bind denied"), "{err}");
    }

    // -- PostgresFirstBootBootstrap ---------------------------------------

    /// A shared event log so the superuser-before-delegate ordering is
    /// observable across the two fakes.
    type Events = Arc<Mutex<Vec<&'static str>>>;

    /// `fakeB04` — records the typed-authority calls into the shared
    /// event log and returns a scripted mount proof.
    struct FakeB04 {
        events: Events,
        proof: MountProof,
    }

    impl B04Bootstrap for FakeB04 {
        async fn adopt_b03_minio(&self, _e: B04LifecycleEvidence) -> Result<(), Failure> {
            self.events.lock().unwrap().push("b04-adopt");
            Ok(())
        }
        async fn materialize_minio_root(
            &self,
            _h: BootstrapHandoff,
        ) -> Result<MountProof, Failure> {
            self.events.lock().unwrap().push("b04-materialize");
            Ok(self.proof.clone())
        }
        async fn issue_lifecycle_proof(&self, _e: B04LifecycleEvidence) -> Result<(), Failure> {
            self.events.lock().unwrap().push("b04-issue-proof");
            Ok(())
        }
    }

    /// `fakeSuperuser` — records `ensure_first_boot_materialized` and
    /// replays a scripted error.
    struct FakeSuperuser {
        events: Events,
        err: Option<Failure>,
    }

    impl PostgresSuperuserFirstBoot for FakeSuperuser {
        fn ensure_first_boot_materialized(&self) -> Result<(), Failure> {
            self.events.lock().unwrap().push("superuser-ensure");
            match &self.err {
                Some(e) => Err(e.clone()),
                None => Ok(()),
            }
        }
    }

    /// A `FileBootstrap` over the fake B04 rooted at `root`.
    fn file_bootstrap(root: PathBuf, b04: FakeB04) -> Arc<FileBootstrap<FakeB04>> {
        Arc::new(FileBootstrap::new(root, Arc::new(SystemClock), b04))
    }

    /// `materialize` runs the superuser's first-boot step BEFORE the
    /// embedded broker-backed materialize — postgres before MinIO, so
    /// a failed B04 ceremony still leaves the passfile — and the
    /// delegate's proof passes through.
    #[test]
    fn materialize_runs_superuser_first_boot_before_delegate() {
        let events: Events = Arc::new(Mutex::new(Vec::new()));
        let root = tempdir("first-boot-order");
        let mount_path = root.join("mount").join("minio-root-password");
        let inner = file_bootstrap(
            root.join("bootstrap"),
            FakeB04 {
                events: events.clone(),
                proof: MountProof {
                    handoff_digest: "sha256:h".to_owned(),
                    mount_path: mount_path.to_string_lossy().into_owned(),
                    confirmed: true,
                },
            },
        );
        let decorated = PostgresFirstBootBootstrap::new(
            inner,
            Arc::new(FakeSuperuser {
                events: events.clone(),
                err: None,
            }),
        );
        let proof = block_on(decorated.materialize(handoff("inst-1"))).unwrap();
        assert!(proof.confirmed);
        assert_eq!(proof.mount_path, mount_path.to_string_lossy());
        assert_eq!(
            *events.lock().unwrap(),
            vec!["superuser-ensure", "b04-materialize"]
        );
    }

    /// A missing superuser store is upstream's `b.superuser == nil` —
    /// the exact composition-unavailable refusal, and the delegate
    /// never runs.
    #[test]
    fn materialize_refuses_without_superuser_store() {
        let events: Events = Arc::new(Mutex::new(Vec::new()));
        let root = tempdir("first-boot-nil-store");
        let decorated = PostgresFirstBootBootstrap {
            inner: Some(file_bootstrap(
                root.join("bootstrap"),
                FakeB04 {
                    events: events.clone(),
                    proof: MountProof::default(),
                },
            )),
            superuser: None,
        };
        let err = block_on(decorated.materialize(handoff("inst-1"))).unwrap_err();
        assert_eq!(
            err.message(),
            "postgres superuser first boot: bootstrap composition unavailable"
        );
        assert!(events.lock().unwrap().is_empty());
    }

    /// A missing embedded bootstrap is upstream's
    /// `b.FileBootstrap == nil` — the same refusal.
    #[test]
    fn materialize_refuses_without_embedded_bootstrap() {
        let events: Events = Arc::new(Mutex::new(Vec::new()));
        let decorated: PostgresFirstBootBootstrap<FakeB04> = PostgresFirstBootBootstrap {
            inner: None,
            superuser: Some(Arc::new(FakeSuperuser {
                events: events.clone(),
                err: None,
            })),
        };
        let err = block_on(decorated.materialize(handoff("inst-1"))).unwrap_err();
        assert_eq!(
            err.message(),
            "postgres superuser first boot: bootstrap composition unavailable"
        );
        assert!(events.lock().unwrap().is_empty());
    }

    /// The superuser's failure wraps with the upstream
    /// `postgres superuser first boot: %w` prefix and the delegate
    /// never runs — a superuser failure never reaches the B04
    /// ceremony.
    #[test]
    fn materialize_wraps_superuser_error_before_delegate() {
        let events: Events = Arc::new(Mutex::new(Vec::new()));
        let root = tempdir("first-boot-err");
        let decorated = PostgresFirstBootBootstrap::new(
            file_bootstrap(
                root.join("bootstrap"),
                FakeB04 {
                    events: events.clone(),
                    proof: MountProof::default(),
                },
            ),
            Arc::new(FakeSuperuser {
                events: events.clone(),
                err: Some(Failure::denied("pg_credentials", "protected dir refused")),
            }),
        );
        let err = block_on(decorated.materialize(handoff("inst-1"))).unwrap_err();
        assert!(
            err.message().starts_with("postgres superuser first boot: "),
            "{}",
            err.message()
        );
        assert!(
            err.message().contains("protected dir refused"),
            "{}",
            err.message()
        );
        assert_eq!(*events.lock().unwrap(), vec!["superuser-ensure"]);
    }

    /// Every other method is the embedded `FileBootstrap`: `ensure`
    /// writes the durable generation file, `record_handoff`/`cleanup`/
    /// `cleanup_binding` drive the durable handoff record, and the
    /// typed B04 calls record in the shared log.
    #[test]
    fn delegates_all_other_methods_to_file_bootstrap() {
        let events: Events = Arc::new(Mutex::new(Vec::new()));
        let root = tempdir("first-boot-delegate");
        let mount_path = root.join("mount").join("minio-root-password");
        std::fs::create_dir_all(mount_path.parent().unwrap()).unwrap();
        std::fs::write(&mount_path, b"not-a-real-secret").unwrap();
        let decorated = PostgresFirstBootBootstrap::new(
            file_bootstrap(
                root.join("bootstrap"),
                FakeB04 {
                    events: events.clone(),
                    proof: MountProof {
                        handoff_digest: "sha256:h".to_owned(),
                        mount_path: mount_path.to_string_lossy().into_owned(),
                        confirmed: true,
                    },
                },
            ),
            Arc::new(FakeSuperuser {
                events: events.clone(),
                err: None,
            }),
        );
        // `ensure` — the delegate writes the durable generation file.
        let generation =
            block_on(decorated.ensure(&binding(), BootstrapPurpose::FirstSetup)).unwrap();
        assert_eq!(generation.generation, 1);
        assert!(generation.digest.starts_with("sha256:"));
        // `materialize` → superuser first, then the B04 materialize.
        let proof = block_on(decorated.materialize(handoff("inst-1"))).unwrap();
        // `record_handoff` — the durable nonsecret record.
        block_on(decorated.record_handoff(&binding(), &proof)).unwrap();
        // `cleanup` — consumes the proof and removes the mount file.
        block_on(decorated.cleanup(proof.clone())).unwrap();
        assert!(!mount_path.exists());
        // `cleanup_binding` — resumes the recorded cleanup.
        block_on(decorated.cleanup_binding(&binding())).unwrap();
        // The typed B04 authority passes straight through.
        block_on(decorated.issue_lifecycle_proof(B04LifecycleEvidence::default())).unwrap();
        block_on(decorated.adopt_b03_minio(B04LifecycleEvidence::default())).unwrap();
        block_on(decorated.materialize_minio_root(handoff("inst-1"))).unwrap();
        assert_eq!(
            *events.lock().unwrap(),
            vec![
                "superuser-ensure",
                "b04-materialize",
                "b04-issue-proof",
                "b04-adopt",
                "b04-materialize",
            ]
        );
    }

    // -- LifecycleBrokerRendezvous -----------------------------------------

    /// The rendezvous delegates to the shared trust-disciplined
    /// helper: an unparseable instance id fails its first gate, and a
    /// valid id with a missing source socket fails the second — both
    /// prove the call reaches `ensure_backup_minio_broker_rendezvous`
    /// rather than silently succeeding. (The link path itself needs
    /// root-owned fixtures — the daemon composition exercises it.)
    #[test]
    fn rendezvous_delegates_to_the_trust_discipline() {
        let r = LifecycleBrokerRendezvous::new("/nonexistent/broker.sock");
        let err = r
            .ensure_minio_provision_rendezvous("not-an-instance")
            .unwrap_err();
        assert!(
            err.message().contains("invalid broker rendezvous"),
            "{}",
            err.message()
        );
        let err = r
            .ensure_minio_provision_rendezvous(&uuid::Uuid::now_v7().to_string())
            .unwrap_err();
        assert!(
            err.message().contains("untrusted broker socket"),
            "{}",
            err.message()
        );
    }
}
