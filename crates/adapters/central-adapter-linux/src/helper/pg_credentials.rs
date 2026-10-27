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

use central_foundation::failure::Failure;

use crate::helper::pg_wire::{PostgresSuperuserSyncer, valid_postgres_superuser_password};
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
/// other credential write in this daemon.
fn tempfile_in(dir: &Path, prefix: &str) -> Result<(std::fs::File, PathBuf), Failure> {
    for _ in 0..16 {
        let mut raw = [0u8; 8];
        rustix::rand::getrandom(&mut raw, rustix::rand::GetRandomFlags::empty())
            .map_err(|_| unavailable("postgres admin credential: write passfile"))?;
        let path = dir.join(format!(
            "{}{}",
            prefix,
            crate::broker::wire::b64_raw_encode(&raw)
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
        .map_err(|_| unavailable("postgres superuser credential: sync directory"))
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
    #[allow(dead_code)]
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
    /// Materialize` inside the helper lifecycle composition — which
    /// this codebase still serves as `LIFECYCLE_SERVICE_UNAVAILABLE`
    /// (the B01 evaluator seam is deferred with it). The store API is
    /// complete so the decorator wiring is a one-line call when the
    /// lifecycle composition lands.
    #[allow(dead_code)]
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
    #[allow(dead_code)]
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
    #[allow(dead_code)] // consumed by the service-role store's port, not this slice's
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
