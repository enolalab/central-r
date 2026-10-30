//! `cmd/central/postgres_superuser_credential.go` +
//! `cmd/central/backup_postgres_admin_credential.go` — ADR 0019's
//! helper-owned superuser credential chain and ADR 0014 §5's
//! single-use postgres-throughput-provision passfile.
//!
//! The `central` PostgreSQL role is the server's initdb superuser;
//! its durable password lives in the root helper's protected instance
//! root — deliberately NOT behind the broker's B04-style handoff
//! ceremony (no privilege boundary to cross: minted by root, stored
//! root-only, consumed by root). Rotate-then-sync (ADR 0019 §4) is
//! the only way any password reaches the live server: record the
//! minted value as candidate, `ALTER ROLE` on the live server,
//! promote candidate to active. Crash recovery probes the server:
//! previous active still authenticating means the rotation never
//! happened (discard candidate); the candidate authenticating means
//! the promote was lost (promote now); neither means fail closed.
//!
//! `write_owned_passfile_atomic`/`validate_root_owned_directory` are
//! the same upstream helpers `backup_minio_composition.go` carries —
//! shared here rather than duplicated so both callers enforce the
//! identical passfile/directory contract.

use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use central_foundation::failure::Failure;

use crate::helper::pg_wire::{
    POSTGRES_DATABASE, POSTGRES_LOOPBACK_HOST_PORT, PostgresServiceRoleSyncer,
    PostgresSuperuserSyncer, valid_postgres_superuser_password,
};
use crate::infra::compose::{POSTGRES_INIT_SCRIPT_SQL, postgres_init_script_host_path};

fn unavailable(msg: &str) -> Failure {
    Failure::denied("pg_credentials", msg.to_owned())
}

/// `postgresSuperuserSecretDirName`/`postgresSuperuserActiveFileName`/
/// `postgresSuperuserCandidateFileName`/`postgresSuperuserPassfileName`.
const POSTGRES_SUPERUSER_SECRET_DIR_NAME: &str = "postgres-server-admin";
const POSTGRES_SUPERUSER_ACTIVE_FILE_NAME: &str = "active";
const POSTGRES_SUPERUSER_CANDIDATE_FILE_NAME: &str = "candidate";
const POSTGRES_SUPERUSER_PASSFILE_NAME: &str = "postgres-superuser-passfile";

/// `postgresDaemonUID`/`postgresDaemonGID` — the compose policy's
/// fixed non-root daemon identity (`user: "999:999"`).
const POSTGRES_DAEMON_UID: u32 = 999;
const POSTGRES_DAEMON_GID: u32 = 999;

/// `postgresAdminPassfileUser`/`postgresAdminPassfileBytes`.
const POSTGRES_ADMIN_PASSFILE_USER: &str = "central";
const POSTGRES_ADMIN_PASSFILE_BYTES: usize = 32;

/// `postgresThroughputProvisionUID`/`GID` — ADR 0014 §5's fixed
/// non-root provisioner identity (`USER 65532:65532`). Deliberately
/// not `CENTRAL_RUNTIME_UID/GID` (501): that identifies Central's own
/// runtime process, not the container this passfile mounts into.
const POSTGRES_THROUGHPUT_PROVISION_UID: u32 = 65532;
const POSTGRES_THROUGHPUT_PROVISION_GID: u32 = 65532;

/// `randomURLSafePassword` — `base64.RawURLEncoding` of 32 random
/// bytes: 43 characters, matching central-local-infra's fixed
/// passfile password length.
pub(crate) fn random_urlsafe_password() -> Result<String, Failure> {
    let mut buf = [0u8; POSTGRES_ADMIN_PASSFILE_BYTES];
    rustix::rand::getrandom(&mut buf, rustix::rand::GetRandomFlags::empty())
        .map_err(|_| unavailable("postgres admin credential: mint password"))?;
    let password = crate::broker::wire::b64_url_raw_encode(&buf);
    if password.len() != 43 {
        return Err(unavailable(
            "postgres admin credential: unexpected password length",
        ));
    }
    Ok(password)
}

/// `validateRootOwnedDirectory` — mode `!022`, uid 0, a real
/// directory (not a symlink upstream refuses to follow).
pub(crate) fn validate_root_owned_directory(path: &str) -> Result<(), Failure> {
    let stat = std::fs::symlink_metadata(path)
        .map_err(|_| unavailable("untrusted broker rendezvous directory"))?;
    if !stat.is_dir() || stat.uid() != 0 || stat.mode() & 0o022 != 0 {
        return Err(unavailable("untrusted broker rendezvous directory"));
    }
    Ok(())
}

/// `os.CreateTemp(dir, prefix)` — a uniquely-named sibling the
/// caller renames into place; `O_NOFOLLOW|O_CLOEXEC` like every
/// other credential write in this daemon. The suffix alphabet is
/// URL-safe (`b64_url_raw_encode`): the standard alphabet's `/`
/// would turn the random suffix into a path separator — Go's
/// `CreateTemp` suffix is alphanumeric, so it can never produce one.
fn tempfile_in(dir: &Path, prefix: &str) -> Result<(std::fs::File, PathBuf), Failure> {
    for _ in 0..16 {
        let mut raw = [0u8; 8];
        rustix::rand::getrandom(&mut raw, rustix::rand::GetRandomFlags::empty())
            .map_err(|_| unavailable("postgres admin credential: write passfile"))?;
        let path = dir.join(format!(
            "{}{}",
            prefix,
            crate::broker::wire::b64_url_raw_encode(&raw)
        ));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
        {
            Ok(file) => return Ok((file, path)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(unavailable("postgres admin credential: write passfile")),
        }
    }
    Err(unavailable("postgres admin credential: write passfile"))
}

/// `writeOwnedPassfileAtomic` — the exact ownership and mode
/// central-local-infra's `readAdminPassfile` requires (mode 0400,
/// regular file), via a temp file in the same directory renamed into
/// place. A failed write removes its temp file.
pub(crate) fn write_owned_passfile_atomic(
    path: &Path,
    content: &[u8],
    uid: u32,
    gid: u32,
) -> Result<(), Failure> {
    let dir = path
        .parent()
        .ok_or_else(|| unavailable("postgres admin credential: write passfile"))?;
    let (mut tmp, tmp_path) = tempfile_in(dir, ".postgres-admin-passfile-")?;
    let result = (|| -> Result<(), Failure> {
        tmp.set_permissions(std::fs::Permissions::from_mode(0o400))
            .map_err(|_| unavailable("postgres admin credential: write passfile"))?;
        rustix::fs::fchown(
            &tmp,
            Some(rustix::process::Uid::from_raw(uid)),
            Some(rustix::process::Gid::from_raw(gid)),
        )
        .map_err(|_| unavailable("postgres admin credential: write passfile"))?;
        tmp.write_all(content)
            .and_then(|()| tmp.sync_all())
            .map_err(|_| unavailable("postgres admin credential: write passfile"))?;
        drop(tmp);
        std::fs::rename(&tmp_path, path)
            .map_err(|_| unavailable("postgres admin credential: write passfile"))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    result
}

/// `syncDirectoryPath` — directory fsync so the rename inside it is
/// durable.
fn sync_directory_path(dir: &Path) -> Result<(), Failure> {
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|_| unavailable("postgres credential: sync directory"))
}

// ---------------------------------------------------------------------------
// `productionPostgresSuperuserCredentialStore` — ADR 0019's
// rotate-then-sync store.
// ---------------------------------------------------------------------------

/// `postgresSuperuserRotator` — what the C02 provisioner composition
/// consumes: one rotate-then-sync cycle returning the now-live
/// password.
pub(crate) trait PostgresSuperuserRotator: Send + Sync {
    /// `RotateForOperation`.
    fn rotate_for_operation(&self) -> Result<String, Failure>;
}

/// `productionPostgresSuperuserCredentialStore`.
pub(crate) struct ProductionPostgresSuperuserCredentialStore {
    protected_dir: PathBuf,
    secrets_dir: PathBuf,
    init_script_path: PathBuf,
    syncer: PostgresSuperuserSyncer,
    passfile_uid: u32,
    passfile_gid: u32,
}

impl ProductionPostgresSuperuserCredentialStore {
    /// `newProductionPostgresSuperuserCredentialStore`.
    pub(crate) fn new_production(
        composition: &crate::broker::daemon::ProductionInstanceComposition,
    ) -> Result<Self, Failure> {
        if composition.instance_id.is_empty() {
            return Err(unavailable(
                "postgres superuser credential composition unavailable",
            ));
        }
        Ok(Self {
            protected_dir: Path::new(crate::broker::daemon::PRODUCTION_PROTECTED_INSTANCES)
                .join(&composition.instance_id)
                .join(POSTGRES_SUPERUSER_SECRET_DIR_NAME),
            secrets_dir: Path::new("/run/central-infra")
                .join(&composition.instance_id)
                .join("secrets"),
            // `infraadapter.PostgresInitScriptHostPath("", instanceID)` —
            // the first-boot role-topology script's bind-mount source.
            init_script_path: PathBuf::from(postgres_init_script_host_path(
                "",
                &composition.instance_id,
            )),
            syncer: PostgresSuperuserSyncer::new(),
            passfile_uid: POSTGRES_DAEMON_UID,
            passfile_gid: POSTGRES_DAEMON_GID,
        })
    }

    /// `EnsureFirstBootMaterialized` — guarantees a durable active
    /// secret exists and the daemon's first-boot passfile is written
    /// from it. It never contacts the server: at first boot the
    /// server does not run yet.
    /// Upstream's call site is `postgresFirstBootBootstrap.
    /// Materialize` inside the helper lifecycle composition — the
    /// `PostgresSuperuserFirstBoot` port impl below is that call.
    pub(crate) fn ensure_first_boot_materialized(&self) -> Result<(), Failure> {
        self.ensure_protected_dir()?;
        let active = match self.read_secret(POSTGRES_SUPERUSER_ACTIVE_FILE_NAME) {
            Ok(active) => active,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                match self.read_secret(POSTGRES_SUPERUSER_CANDIDATE_FILE_NAME) {
                    // Crash between the first mint's candidate write and
                    // promote: no server state exists to disagree with,
                    // so promote it.
                    Ok(candidate) => {
                        self.promote_candidate()?;
                        candidate
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        let minted = random_urlsafe_password()
                            .map_err(|_| unavailable("postgres superuser credential: mint"))?;
                        self.write_secret(POSTGRES_SUPERUSER_CANDIDATE_FILE_NAME, &minted)?;
                        self.promote_candidate()?;
                        minted
                    }
                    Err(_) => {
                        return Err(unavailable("postgres superuser credential: read candidate"));
                    }
                }
            }
            Err(_) => return Err(unavailable("postgres superuser credential: read active")),
        };
        self.write_init_script()?;
        self.write_passfile(&active)
    }

    /// `writeInitScript` — ADR 0019 §3's first-boot role-topology
    /// script at the exact bind-mount source the rendered compose
    /// names. It carries no password material and is rewritten
    /// idempotently.
    fn write_init_script(&self) -> Result<(), Failure> {
        if self.init_script_path.as_os_str().is_empty() {
            return Err(unavailable(
                "postgres superuser credential: init script path unavailable",
            ));
        }
        if let Some(parent) = self.init_script_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|_| unavailable("postgres superuser credential: init script directory"))?;
        }
        std::fs::write(&self.init_script_path, POSTGRES_INIT_SCRIPT_SQL)
            .map_err(|_| unavailable("postgres superuser credential: write init script"))?;
        std::fs::set_permissions(
            &self.init_script_path,
            std::fs::Permissions::from_mode(0o644),
        )
        .map_err(|_| unavailable("postgres superuser credential: write init script"))
    }

    /// `ActivePassword` — the superuser password currently live on
    /// the server; `postgresServiceRoleCredentialStore`'s
    /// rotate-then-sync reuses it as the admin credential for its own
    /// `ALTER ROLE` calls.
    pub(crate) fn active_password(&self) -> Result<String, Failure> {
        self.read_secret(POSTGRES_SUPERUSER_ACTIVE_FILE_NAME)
            .map_err(|_| unavailable("postgres superuser credential store unavailable"))
    }

    fn ensure_protected_dir(&self) -> Result<(), Failure> {
        std::fs::create_dir_all(&self.protected_dir)
            .map_err(|_| unavailable("postgres superuser credential: protected directory"))?;
        std::fs::set_permissions(&self.protected_dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| unavailable("postgres superuser credential: protected directory"))?;
        let stat = std::fs::symlink_metadata(&self.protected_dir)
            .map_err(|_| unavailable("postgres superuser credential: protected directory"))?;
        if !stat.is_dir() || stat.file_type().is_symlink() {
            return Err(unavailable(
                "postgres superuser credential: protected directory is not a directory",
            ));
        }
        Ok(())
    }

    fn secret_path(&self, name: &str) -> PathBuf {
        self.protected_dir.join(name)
    }

    /// `readSecret` — a present-and-valid secret, or `NotFound`.
    fn read_secret(&self, name: &str) -> std::io::Result<String> {
        let value = std::fs::read_to_string(self.secret_path(name))?;
        if !valid_postgres_superuser_password(&value) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "postgres superuser credential: stored secret is malformed",
            ));
        }
        Ok(value)
    }

    /// `writeSecret` — temp file in the protected directory, fsync,
    /// rename, directory fsync.
    fn write_secret(&self, name: &str, value: &str) -> Result<(), Failure> {
        if !valid_postgres_superuser_password(value) {
            return Err(unavailable(
                "postgres superuser credential: refusing to store a malformed secret",
            ));
        }
        let (mut tmp, tmp_path) = tempfile_in(&self.protected_dir, &format!(".{name}-"))?;
        let result = (|| -> Result<(), Failure> {
            tmp.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|_| unavailable("postgres superuser credential: write secret"))?;
            tmp.write_all(value.as_bytes())
                .and_then(|()| tmp.sync_all())
                .map_err(|_| unavailable("postgres superuser credential: write secret"))?;
            drop(tmp);
            std::fs::rename(&tmp_path, self.secret_path(name))
                .map_err(|_| unavailable("postgres superuser credential: write secret"))?;
            sync_directory_path(&self.protected_dir)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp_path);
        }
        result
    }

    fn promote_candidate(&self) -> Result<(), Failure> {
        std::fs::rename(
            self.secret_path(POSTGRES_SUPERUSER_CANDIDATE_FILE_NAME),
            self.secret_path(POSTGRES_SUPERUSER_ACTIVE_FILE_NAME),
        )
        .map_err(|_| unavailable("postgres superuser credential: promote candidate"))?;
        sync_directory_path(&self.protected_dir)
    }

    fn remove_candidate(&self) -> Result<(), Failure> {
        match std::fs::remove_file(self.secret_path(POSTGRES_SUPERUSER_CANDIDATE_FILE_NAME)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(unavailable(
                    "postgres superuser credential: discard candidate",
                ));
            }
        }
        sync_directory_path(&self.protected_dir)
    }

    /// `writePassfile` — the daemon's first-boot passfile: the bare
    /// password plus a trailing newline (the official entrypoint's
    /// `$(< file)` read strips it), mode 0400, owned by the daemon's
    /// fixed non-root identity.
    fn write_passfile(&self, password: &str) -> Result<(), Failure> {
        std::fs::create_dir_all(&self.secrets_dir)
            .map_err(|_| unavailable("postgres superuser credential: secrets directory"))?;
        std::fs::set_permissions(&self.secrets_dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| unavailable("postgres superuser credential: secrets directory"))?;
        let path = self.secrets_dir.join(POSTGRES_SUPERUSER_PASSFILE_NAME);
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(unavailable("postgres superuser credential: write passfile"));
            }
        }
        write_owned_passfile_atomic(
            &path,
            format!("{password}\n").as_bytes(),
            self.passfile_uid,
            self.passfile_gid,
        )
        .map_err(|_| unavailable("postgres superuser credential: write passfile"))
    }
}

impl PostgresSuperuserRotator for ProductionPostgresSuperuserCredentialStore {
    /// `RotateForOperation` — one ADR 0019 §4 rotate-then-sync cycle
    /// for the `central` role; returns the now-live password (ADR
    /// 0014's per-operation container passfile value). The daemon's
    /// first-boot passfile is rewritten too, so the durable store,
    /// the live server, and both passfiles converge.
    fn rotate_for_operation(&self) -> Result<String, Failure> {
        self.ensure_protected_dir()?;
        let mut active = self
            .read_secret(POSTGRES_SUPERUSER_ACTIVE_FILE_NAME)
            .map_err(|_| {
                unavailable(
                    "postgres superuser credential: no active secret; first-boot materialization has not run",
                )
            })?;

        // Crash recovery: resolve a leftover candidate against the
        // live server before minting anything new.
        match self.read_secret(POSTGRES_SUPERUSER_CANDIDATE_FILE_NAME) {
            Ok(candidate) => {
                if self.syncer.verify(&active).is_ok() {
                    // The interrupted rotation never altered the server.
                    self.remove_candidate()?;
                } else if self.syncer.verify(&candidate).is_ok() {
                    // The server was altered but the promote was lost.
                    self.promote_candidate()?;
                    active = candidate;
                } else {
                    return Err(unavailable(
                        "postgres superuser credential: neither active nor candidate authenticates; refusing to guess",
                    ));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(unavailable("postgres superuser credential: read candidate"));
            }
        }

        let minted = random_urlsafe_password()
            .map_err(|_| unavailable("postgres superuser credential: mint"))?;
        self.write_secret(POSTGRES_SUPERUSER_CANDIDATE_FILE_NAME, &minted)?;
        self.syncer
            .alter(&active, &minted)
            .map_err(|_| unavailable("postgres superuser credential: alter live role"))?;
        self.promote_candidate()?;
        self.write_passfile(&minted)?;
        Ok(minted)
    }
}

// ---------------------------------------------------------------------------
// `productionPostgresServiceRoleCredentialStore` — ADR 0019 §4's
// rotate-then-sync cycle for the three service roles
// (`cmd/central/postgres_service_role_credential.go`).
// ---------------------------------------------------------------------------

/// `postgresServiceRole` — one of ADR 0019 §3's three fixed NOLOGIN
/// NOINHERIT service roles and the secretbootstrap purpose its live
/// password is bound under once §4's rotate-then-sync grants it
/// LOGIN.
struct PostgresServiceRole {
    purpose: &'static str,
    role_name: &'static str,
}

/// `postgresServiceRoles` — the closed, ordered set
/// `PostgresInitScriptSQL` creates
/// (`internal/adapter/infralifecycle/compose_linux.go`). Order is
/// deliberate but not load-bearing: `sync` treats each role
/// independently.
const POSTGRES_SERVICE_ROLES: [PostgresServiceRole; 3] = [
    PostgresServiceRole {
        purpose: "postgres_migration_v1",
        role_name: "central_migration",
    },
    PostgresServiceRole {
        purpose: "postgres_runtime_v1",
        role_name: "central_runtime",
    },
    PostgresServiceRole {
        purpose: "postgres_outbox_v1",
        role_name: "central_outbox",
    },
];

/// `postgresServiceRoleSecretDirName`.
const POSTGRES_SERVICE_ROLE_SECRET_DIR_NAME: &str = "postgres-service-roles";

/// `postgresServiceRoleBroker` — the seam `sync` uses to register a
/// rotated password as the new active protected binding —
/// `LifecycleClient` in production (upstream's `brokerClient`).
pub(crate) trait PostgresServiceRoleBroker: Send + Sync {
    /// `BindPostgresServiceRole`.
    fn bind_postgres_service_role(
        &self,
        instance_id: &str,
        purpose: &str,
        value: &[u8],
    ) -> Result<(), Failure>;
}

/// `postgresServiceRoleSyncer` — the live-server seam `sync_one`
/// drives: `verify_as` proves a password currently authenticates the
/// named role; `alter_login` authenticates as `central` and grants
/// the role LOGIN with `new_password`.
pub(crate) trait ServiceRoleSyncer: Send + Sync {
    /// `Verify`.
    fn verify_as(&self, role_name: &str, password: &str) -> Result<(), Failure>;
    /// `AlterLogin`.
    fn alter_login(
        &self,
        auth_password: &str,
        role_name: &str,
        new_password: &str,
    ) -> Result<(), Failure>;
}

impl ServiceRoleSyncer for PostgresServiceRoleSyncer {
    fn verify_as(&self, role_name: &str, password: &str) -> Result<(), Failure> {
        PostgresServiceRoleSyncer::verify_as(self, role_name, password)
    }
    fn alter_login(
        &self,
        auth_password: &str,
        role_name: &str,
        new_password: &str,
    ) -> Result<(), Failure> {
        PostgresServiceRoleSyncer::alter_login(self, auth_password, role_name, new_password)
    }
}

/// `productionPostgresServiceRoleCredentialStore` runs ADR 0019 §4's
/// rotate-then-sync cycle for the three service roles. Unlike the
/// superuser store, it never invents its own admin credential: it
/// authenticates its `ALTER ROLE` calls with whatever password
/// `ProductionPostgresSuperuserCredentialStore` currently has live,
/// since that store is the sole owner of rotating and verifying the
/// `central` role itself.
pub(crate) struct ProductionPostgresServiceRoleCredentialStore {
    instance_id: String,
    protected_dir: PathBuf,
    superuser: Arc<ProductionPostgresSuperuserCredentialStore>,
    broker: Arc<dyn PostgresServiceRoleBroker>,
    syncer: Arc<dyn ServiceRoleSyncer>,
}

impl ProductionPostgresServiceRoleCredentialStore {
    /// `newProductionPostgresServiceRoleCredentialStore`. Upstream's
    /// nil-superuser/nil-broker refusals are the type system's job —
    /// `Arc` parameters cannot be absent.
    pub(crate) fn new_production(
        composition: &crate::broker::daemon::ProductionInstanceComposition,
        superuser: Arc<ProductionPostgresSuperuserCredentialStore>,
        broker: Arc<dyn PostgresServiceRoleBroker>,
    ) -> Result<Self, Failure> {
        if composition.instance_id.is_empty() {
            return Err(unavailable(
                "postgres service role credential composition unavailable",
            ));
        }
        Ok(Self {
            instance_id: composition.instance_id.clone(),
            protected_dir: Path::new(crate::broker::daemon::PRODUCTION_PROTECTED_INSTANCES)
                .join(&composition.instance_id)
                .join(POSTGRES_SERVICE_ROLE_SECRET_DIR_NAME),
            superuser,
            broker,
            syncer: Arc::new(PostgresServiceRoleSyncer::new()),
        })
    }

    /// `Sync` — one rotate-then-sync pass over every service role:
    /// authenticate with the superuser's current live password, grant
    /// LOGIN with a freshly minted one only when the role's
    /// locally-recorded password no longer authenticates (first run,
    /// or drift), then always re-register the (possibly unchanged)
    /// password as the broker's active binding — that call alone
    /// renews the binding's lease, which is what an
    /// otherwise-unchanged password still needs from a
    /// stale-but-still-valid live credential.
    ///
    /// Called from the postgres-provision compose `up` decorator,
    /// strictly after docker compose reports the postgres healthcheck
    /// passing (ADR 0019 §4 must never run against a server that is
    /// not accepting connections yet). Upstream's nil-store/nil-ctx
    /// refusal has no Rust analogue — `&self` cannot be nil and the
    /// port is synchronous.
    pub(crate) fn sync(&self) -> Result<(), Failure> {
        let auth_password = self.superuser.active_password().map_err(|_| {
            unavailable("postgres service role credential: superuser password unavailable")
        })?;
        self.ensure_protected_dir()?;
        // `errors.Join` — `Failure` is flat, so every role's failure
        // is joined into one refusal message, each prefixed with its
        // role name exactly like upstream's `fmt.Errorf("%s: %w")`.
        let mut failures: Vec<String> = Vec::new();
        for role in &POSTGRES_SERVICE_ROLES {
            if let Err(e) = self.sync_one(role, &auth_password) {
                failures.push(format!("{}: {e}", role.role_name));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(unavailable(&failures.join("\n")))
        }
    }

    /// `syncOne` — rotate on first-run or drift (the locally-recorded
    /// password no longer authenticates), then always rebind.
    fn sync_one(&self, role: &PostgresServiceRole, auth_password: &str) -> Result<(), Failure> {
        let recorded = self.read_secret(role.role_name);
        let needs_rotation = match &recorded {
            Err(_) => true,
            Ok(active) => self.syncer.verify_as(role.role_name, active).is_err(),
        };
        let mut active = recorded.unwrap_or_default();
        if needs_rotation {
            let minted = random_urlsafe_password()
                .map_err(|_| unavailable("postgres service role credential: mint"))?;
            self.syncer
                .alter_login(auth_password, role.role_name, &minted)
                .map_err(|e| {
                    unavailable(&format!(
                        "postgres service role credential: alter live role: {e}"
                    ))
                })?;
            self.write_secret(role.role_name, &minted).map_err(|_| {
                unavailable("postgres service role credential: persist rotated secret")
            })?;
            active = minted;
        }
        // `127.0.0.1:55432:central:<role>:<pw>\n` — the fixed
        // five-field passfile shape the broker's purpose validators
        // pin.
        let passfile = format!(
            "{POSTGRES_LOOPBACK_HOST_PORT}:{POSTGRES_DATABASE}:{}:{}\n",
            role.role_name, active
        );
        self.broker
            .bind_postgres_service_role(&self.instance_id, role.purpose, passfile.as_bytes())
            .map_err(|_| unavailable("postgres service role credential: bind broker binding"))
    }

    /// `ensureProtectedDir` — `protected_dir` exists at mode 0700 and
    /// is a real directory (never a symlink).
    fn ensure_protected_dir(&self) -> Result<(), Failure> {
        std::fs::create_dir_all(&self.protected_dir)
            .map_err(|_| unavailable("postgres service role credential: protected directory"))?;
        std::fs::set_permissions(&self.protected_dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| unavailable("postgres service role credential: protected directory"))?;
        let stat = std::fs::symlink_metadata(&self.protected_dir)
            .map_err(|_| unavailable("postgres service role credential: protected directory"))?;
        if !stat.is_dir() || stat.file_type().is_symlink() {
            return Err(unavailable(
                "postgres service role credential: protected directory is not a directory",
            ));
        }
        Ok(())
    }

    /// `secretPath` — `<protectedDir>/<roleName>`.
    fn secret_path(&self, role_name: &str) -> PathBuf {
        self.protected_dir.join(role_name)
    }

    /// `readSecret` — a present-and-valid secret, or the read error.
    fn read_secret(&self, role_name: &str) -> std::io::Result<String> {
        let value = std::fs::read_to_string(self.secret_path(role_name))?;
        if !valid_postgres_superuser_password(&value) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "postgres service role credential: stored secret is malformed",
            ));
        }
        Ok(value)
    }

    /// `writeSecret` — the service-role store's simpler sibling of
    /// the superuser's durable write: deterministic `<role>.tmp` at
    /// mode 0400, rename, directory fsync.
    fn write_secret(&self, role_name: &str, value: &str) -> Result<(), Failure> {
        if !valid_postgres_superuser_password(value) {
            return Err(unavailable(
                "postgres service role credential: refusing to persist a malformed secret",
            ));
        }
        let tmp = self.protected_dir.join(format!("{role_name}.tmp"));
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o400)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&tmp)
            .and_then(|mut f| f.write_all(value.as_bytes()))
            .map_err(|_| unavailable("postgres service role credential: write secret"))?;
        std::fs::rename(&tmp, self.secret_path(role_name))
            .map_err(|_| unavailable("postgres service role credential: write secret"))?;
        sync_directory_path(&self.protected_dir)
    }
}

// ---------------------------------------------------------------------------
// `productionPostgresAdminCredentialManager` — ADR 0014 §5's
// single-use passfile for `postgres-throughput-provision`.
// ---------------------------------------------------------------------------

/// `productionPostgresAdminCredentialManager` — the root-helper-owned,
/// single-use materialization of the `postgres_server_admin_v1`
/// passfile: it writes the exact five-field passfile format
/// central-local-infra's postgres-provision mode validates and owns
/// removal after the operation.
///
/// Single-use and concurrency: this manager relies on its caller
/// already serializing one probe operation at a time
/// (`ProductionBackupThroughputGate` holds its mutex for the whole
/// `require_backup_throughput` call), rather than building a second,
/// redundant fencing mechanism. `materialize_with_password` must run
/// at most once per operation, immediately before the
/// postgres-throughput-provision container starts, and `cleanup`
/// unconditionally afterward.
pub(crate) struct ProductionPostgresAdminCredentialManager {
    instance_id: String,
}

impl ProductionPostgresAdminCredentialManager {
    /// `newProductionPostgresAdminCredentialManager`.
    pub(crate) fn new_production(
        composition: &crate::broker::daemon::ProductionInstanceComposition,
    ) -> Result<Self, Failure> {
        if composition.instance_id.is_empty() {
            return Err(unavailable(
                "postgres admin credential composition unavailable",
            ));
        }
        Ok(Self {
            instance_id: composition.instance_id.clone(),
        })
    }

    /// `passfilePath` — the fixed, instance-scoped host source
    /// `addPostgresAdminPassfileMount` bind-mounts read-only into
    /// postgres-throughput-provision.
    fn passfile_path(&self) -> PathBuf {
        Path::new("/run/central-infra")
            .join(&self.instance_id)
            .join("secrets")
            .join("postgres-admin-passfile")
    }

    /// `MaterializeWithPassword` — writes the container passfile
    /// carrying an exact, caller-supplied password (in production,
    /// the value `RotateForOperation` just made live). Content is the
    /// fixed five fields `postgres:5432:*:central:<password>` plus a
    /// single trailing newline; owner `65532:65532`, mode 0400,
    /// atomic rename.
    pub(crate) fn materialize_with_password(
        &self,
        operation_id: uuid::Uuid,
        password: &str,
    ) -> Result<(), Failure> {
        if operation_id.is_nil() || operation_id.get_version_num() != 7 {
            return Err(unavailable(
                "postgres admin credential materialization unavailable",
            ));
        }
        if password.len() != 43 {
            return Err(unavailable(
                "postgres admin credential: unexpected password length",
            ));
        }
        let secrets_dir = format!("/run/central-infra/{}/secrets", self.instance_id);
        validate_root_owned_directory(&secrets_dir)
            .map_err(|_| unavailable("postgres admin credential: secrets directory"))?;
        let content = format!("postgres:5432:*:{POSTGRES_ADMIN_PASSFILE_USER}:{password}\n");
        write_owned_passfile_atomic(
            &self.passfile_path(),
            content.as_bytes(),
            POSTGRES_THROUGHPUT_PROVISION_UID,
            POSTGRES_THROUGHPUT_PROVISION_GID,
        )
        .map_err(|_| unavailable("postgres admin credential: write passfile"))
    }

    /// `Cleanup` — removes the materialized passfile. Idempotent: a
    /// passfile already absent is not an error.
    pub(crate) fn cleanup(&self, operation_id: uuid::Uuid) -> Result<(), Failure> {
        if operation_id.is_nil() || operation_id.get_version_num() != 7 {
            return Err(unavailable("postgres admin credential cleanup unavailable"));
        }
        match std::fs::remove_file(self.passfile_path()) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(unavailable("postgres admin credential: remove passfile")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    /// A unique scratch directory under `std::env::temp_dir` — the
    /// same convention `helper::migration`'s tests use.
    fn temp_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("pg-svc-roles-{tag}-{}", uuid::Uuid::now_v7()))
    }

    /// 43 `a`s — `valid_postgres_superuser_password`'s exact shape,
    /// like upstream's test fixture.
    const ACTIVE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    /// `fakeServiceRoleSyncer` — `roleName -> currently-live
    /// password` plus recorded calls, upstream's test double.
    #[derive(Default)]
    struct FakeServiceRoleSyncer {
        live: Mutex<BTreeMap<String, String>>,
        verify_calls: Mutex<Vec<String>>,
        alter_calls: Mutex<Vec<String>>,
    }

    impl ServiceRoleSyncer for FakeServiceRoleSyncer {
        fn verify_as(&self, role_name: &str, password: &str) -> Result<(), Failure> {
            self.verify_calls
                .lock()
                .unwrap()
                .push(format!("{role_name}:{password}"));
            match self.live.lock().unwrap().get(role_name) {
                Some(live) if live == password => Ok(()),
                _ => Err(unavailable("authentication failed")),
            }
        }

        fn alter_login(
            &self,
            auth_password: &str,
            role_name: &str,
            new_password: &str,
        ) -> Result<(), Failure> {
            self.alter_calls
                .lock()
                .unwrap()
                .push(format!("{role_name}:{auth_password}:{new_password}"));
            self.live
                .lock()
                .unwrap()
                .insert(role_name.to_owned(), new_password.to_owned());
            Ok(())
        }
    }

    /// `fakeServiceRoleBroker`.
    #[derive(Default)]
    struct FakeServiceRoleBroker {
        binds: Mutex<Vec<(String, String, String)>>,
        err: Mutex<Option<String>>,
    }

    impl PostgresServiceRoleBroker for FakeServiceRoleBroker {
        fn bind_postgres_service_role(
            &self,
            instance_id: &str,
            purpose: &str,
            value: &[u8],
        ) -> Result<(), Failure> {
            if let Some(e) = self.err.lock().unwrap().clone() {
                return Err(unavailable(&e));
            }
            self.binds.lock().unwrap().push((
                instance_id.to_owned(),
                purpose.to_owned(),
                String::from_utf8_lossy(value).into_owned(),
            ));
            Ok(())
        }
    }

    /// `testSuperuserStoreWithActivePassword` — a real superuser
    /// store rooted in the scratch dir with `active` written durably.
    fn superuser_store(dir: &Path, active: &str) -> ProductionPostgresSuperuserCredentialStore {
        let store = ProductionPostgresSuperuserCredentialStore {
            protected_dir: dir.join("postgres-server-admin"),
            secrets_dir: dir.join("secrets"),
            init_script_path: dir.join("init.sql"),
            syncer: PostgresSuperuserSyncer::new(),
            passfile_uid: POSTGRES_DAEMON_UID,
            passfile_gid: POSTGRES_DAEMON_GID,
        };
        store.ensure_protected_dir().unwrap();
        store
            .write_secret(POSTGRES_SUPERUSER_ACTIVE_FILE_NAME, active)
            .unwrap();
        store
    }

    /// `testServiceRoleStore` — the store wired to fakes and the
    /// scratch-dir protected root.
    fn service_role_store(
        dir: &Path,
        superuser: Arc<ProductionPostgresSuperuserCredentialStore>,
        syncer: Arc<dyn ServiceRoleSyncer>,
        broker: Arc<dyn PostgresServiceRoleBroker>,
    ) -> ProductionPostgresServiceRoleCredentialStore {
        ProductionPostgresServiceRoleCredentialStore {
            instance_id: "test-instance".to_owned(),
            protected_dir: dir.join("postgres-service-roles"),
            superuser,
            broker,
            syncer,
        }
    }

    /// `TestServiceRoleSyncFirstRunMintsAltersAndBinds` — on an
    /// instance with no locally-recorded service-role password,
    /// `sync` mints one, grants LOGIN with it live, and registers it
    /// as the broker's active binding for all three roles.
    #[test]
    fn service_role_sync_first_run_mints_alters_and_binds() {
        let dir = temp_dir("first");
        let superuser = Arc::new(superuser_store(&dir, ACTIVE));
        let syncer = Arc::new(FakeServiceRoleSyncer::default());
        let broker = Arc::new(FakeServiceRoleBroker::default());
        let store = service_role_store(&dir, superuser, syncer.clone(), broker.clone());

        store.sync().unwrap();

        let alters = syncer.alter_calls.lock().unwrap();
        assert_eq!(
            alters.len(),
            3,
            "want one ALTER per service role: {alters:?}"
        );
        for role in &POSTGRES_SERVICE_ROLES {
            // `<role>:<superuser's live password>:<minted>` — the
            // admin credential is the superuser's, never a new one.
            assert!(
                alters
                    .iter()
                    .any(|c| c.starts_with(&format!("{}:{ACTIVE}:", role.role_name))),
                "missing ALTER for {}: {alters:?}",
                role.role_name
            );
        }
        let binds = broker.binds.lock().unwrap();
        assert_eq!(
            binds.len(),
            3,
            "want one broker bind per service role: {binds:?}"
        );
        let mut purposes: Vec<&str> = binds.iter().map(|(_, p, _)| p.as_str()).collect();
        purposes.sort_unstable();
        assert_eq!(
            purposes,
            [
                "postgres_migration_v1",
                "postgres_outbox_v1",
                "postgres_runtime_v1"
            ]
        );
        for (instance_id, purpose, value) in binds.iter() {
            assert_eq!(instance_id, "test-instance");
            let role = POSTGRES_SERVICE_ROLES
                .iter()
                .find(|r| r.purpose == purpose.as_str())
                .unwrap()
                .role_name;
            // `127.0.0.1:55432:central:<role>:<pw>\n` — the fixed
            // five-field passfile, byte shape pinned.
            assert_eq!(value.matches('\n').count(), 1);
            let password = value
                .strip_prefix(&format!("127.0.0.1:55432:central:{role}:"))
                .and_then(|rest| rest.strip_suffix('\n'));
            assert!(
                password.is_some(),
                "bind value is not the passfile shape: {value:?}"
            );
            assert!(valid_postgres_superuser_password(password.unwrap()));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `TestServiceRoleSyncSecondRunSkipsAlterButRebinds` — once a
    /// role's recorded password still authenticates live, a second
    /// `sync` must not mint or `ALTER` again, but must still
    /// re-register the broker binding so its lease gets renewed.
    #[test]
    fn service_role_sync_second_run_skips_alter_but_rebinds() {
        let dir = temp_dir("second");
        let superuser = Arc::new(superuser_store(&dir, ACTIVE));
        let syncer = Arc::new(FakeServiceRoleSyncer::default());
        let broker = Arc::new(FakeServiceRoleBroker::default());
        let store = service_role_store(&dir, superuser, syncer.clone(), broker.clone());

        store.sync().unwrap();
        let first_alters = syncer.alter_calls.lock().unwrap().len();
        let first_binds = broker.binds.lock().unwrap().len();

        store.sync().unwrap();
        assert_eq!(
            syncer.alter_calls.lock().unwrap().len(),
            first_alters,
            "second sync issued more ALTERs; recorded password still authenticates live"
        );
        assert_eq!(
            broker.binds.lock().unwrap().len(),
            first_binds + 3,
            "second sync must rebind every role (lease renewal)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `TestServiceRoleSyncRotatesWhenLocalPasswordNoLongerAuthenticates`
    /// — drift recovery: a role whose recorded password the live
    /// server no longer accepts is re-rotated, not left broken.
    #[test]
    fn service_role_sync_rotates_on_drift() {
        let dir = temp_dir("drift");
        let superuser = Arc::new(superuser_store(&dir, ACTIVE));
        let syncer = Arc::new(FakeServiceRoleSyncer::default());
        // The live server moved on without our durable record.
        syncer.live.lock().unwrap().insert(
            "central_runtime".to_owned(),
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
        );
        let broker = Arc::new(FakeServiceRoleBroker::default());
        let store = service_role_store(&dir, superuser, syncer.clone(), broker.clone());
        store.ensure_protected_dir().unwrap();
        store
            .write_secret(
                "central_runtime",
                "ccccccccccccccccccccccccccccccccccccccccccc",
            )
            .unwrap();

        store.sync().unwrap();

        let alters = syncer.alter_calls.lock().unwrap();
        let runtime = alters.iter().find(|c| c.starts_with("central_runtime:"));
        assert!(
            runtime.is_some(),
            "central_runtime was not re-rotated: {alters:?}"
        );
        let minted = runtime.unwrap().rsplit(':').next().unwrap();
        assert_ne!(minted, "ccccccccccccccccccccccccccccccccccccccccccc");
        assert_ne!(minted, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        // The minted value is now the durable record.
        assert_eq!(store.read_secret("central_runtime").unwrap(), minted);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `readSecret`/`writeSecret` round trip, mode `0400`, and the
    /// `valid_postgres_superuser_password` gate on both directions.
    #[test]
    fn service_role_secret_round_trip_and_malformed_refusal() {
        let dir = temp_dir("secret");
        let superuser = Arc::new(superuser_store(&dir, ACTIVE));
        let syncer = Arc::new(FakeServiceRoleSyncer::default());
        let broker = Arc::new(FakeServiceRoleBroker::default());
        let store = service_role_store(&dir, superuser, syncer, broker);
        store.ensure_protected_dir().unwrap();

        store.write_secret("central_runtime", ACTIVE).unwrap();
        assert_eq!(store.read_secret("central_runtime").unwrap(), ACTIVE);
        let mode = std::fs::metadata(store.secret_path("central_runtime"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o400);

        // Malformed values refuse on write...
        let err = store.write_secret("central_runtime", "short").unwrap_err();
        assert_eq!(
            err.message(),
            "postgres service role credential: refusing to persist a malformed secret"
        );
        assert!(
            store
                .write_secret("central_runtime", &"'".repeat(43))
                .is_err()
        );
        // ...and on read of a stored malformed value...
        std::fs::write(store.secret_path("central_outbox"), "not-a-secret").unwrap();
        assert!(store.read_secret("central_outbox").is_err());
        // ...and a missing secret reads as an error (rotation signal).
        assert!(store.read_secret("central_migration").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `ensureProtectedDir` refuses a symlinked protected directory —
    /// the same not-a-real-directory refusal upstream's `Lstat` gate
    /// gives.
    #[test]
    fn service_role_protected_dir_refuses_symlink() {
        let dir = temp_dir("symlink");
        let superuser = Arc::new(superuser_store(&dir, ACTIVE));
        let syncer = Arc::new(FakeServiceRoleSyncer::default());
        let broker = Arc::new(FakeServiceRoleBroker::default());
        let store = service_role_store(&dir, superuser, syncer, broker);
        let real = dir.join("real");
        std::fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, dir.join("postgres-service-roles")).unwrap();

        let err = store.ensure_protected_dir().unwrap_err();
        assert_eq!(
            err.message(),
            "postgres service role credential: protected directory is not a directory"
        );
        assert!(store.sync().is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `errors.Join` — one role's failure must not stop the others,
    /// and the joined refusal names every failed role.
    #[test]
    fn service_role_sync_joins_per_role_failures() {
        let dir = temp_dir("join");
        let superuser = Arc::new(superuser_store(&dir, ACTIVE));
        let syncer = Arc::new(FakeServiceRoleSyncer::default());
        let broker = Arc::new(FakeServiceRoleBroker::default());
        *broker.err.lock().unwrap() = Some("bind refused".to_owned());
        let store = service_role_store(&dir, superuser, syncer.clone(), broker);

        let err = store.sync().unwrap_err();
        for role in &POSTGRES_SERVICE_ROLES {
            assert!(
                err.message().contains(role.role_name),
                "joined error missing {}: {}",
                role.role_name,
                err.message()
            );
        }
        // Every role still ran its rotate pass before the bind failed.
        assert_eq!(syncer.alter_calls.lock().unwrap().len(), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `newProductionPostgresServiceRoleCredentialStore` — an empty
    /// instance id refuses composition (upstream's nil checks are the
    /// `Arc` parameters' non-nullability).
    #[test]
    fn service_role_new_production_refuses_empty_instance() {
        let dir = temp_dir("empty");
        let empty = crate::broker::daemon::ProductionInstanceComposition {
            instance_id: String::new(),
            config_binding: String::new(),
            authoritative_state_root: String::new(),
            dependency_root: String::new(),
            lifecycle_root: String::new(),
            role_roots: central_backup::backup::capacity::RoleRoots::default(),
            backup_repository_root: String::new(),
            compose_path: String::new(),
            object_store_bucket: String::new(),
            backup_policy_digest: String::new(),
            restore_policy_digest: String::new(),
            import_policy_digest: String::new(),
        };
        let err = ProductionPostgresServiceRoleCredentialStore::new_production(
            &empty,
            Arc::new(superuser_store(&dir, ACTIVE)),
            Arc::new(FakeServiceRoleBroker::default()),
        )
        .err()
        .unwrap();
        assert_eq!(
            err.message(),
            "postgres service role credential composition unavailable"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
