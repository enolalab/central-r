//! `cmd/central/local_init_genesis_linux.go` — the genesis core:
//! the only production code that creates an instance (install spec
//! B1, decision 6). The root helper runs it behind the init
//! ceremony, and the reference-host harness runs it as root with no
//! helper. It never removes anything.
//!
//! The handler composition (`local_init_helper_linux.go`) lives in
//! `helper::init`; this module is the env, the state machine, the
//! layout, the record, and the config commit — every step upstream
//! performs, in upstream order.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::DirBuilderExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use central_infra::authority::{
    CENTRAL_BROWSER_GID, CENTRAL_BROWSER_UID, CENTRAL_RUNTIME_GID, CENTRAL_RUNTIME_UID,
};
use central_infra::config::defaults::Instance;
use rustix::fs::{
    FileType, Mode, OFlags, fchmod, fchown, flock, fstat, mkdirat, open, openat, renameat_with,
    statfs,
};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};

use crate::broker::daemon::{
    load_production_instance_composition_for_owner, production_broker_root_at,
};
use crate::infra::prepare::{OpDeadline, ensure_version_zero_receipt, store::CandidateStore};

pub const GENESIS_RECORD_NAME: &str = "genesis.json";
pub const GENESIS_RECORD_SCHEMA: &str = "central.genesis/v1";
pub const GENESIS_LOCK_NAME: &str = ".genesis.lock";
pub const GENESIS_CONFIG_TEMP_NAME: &str = ".config.json.genesis";
pub const GENESIS_MINIMUM_FREE_BYTES: u64 = 40 << 30;
pub const MAXIMUM_GENESIS_RECORD_BYTES: i64 = 4096;

/// `genesisCeremonyPhysicalTTY` — fresh PAM plus the init phrase at
/// the operator's physical console.
pub const GENESIS_CEREMONY_PHYSICAL_TTY: &str = "physical_tty";
/// `genesisCeremonyReferenceHostHarness` — the root reference-host
/// harness: no ceremony ran, and the record says so.
pub const GENESIS_CEREMONY_REFERENCE_HOST_HARNESS: &str = "reference_host_harness";
/// `genesisCeremonyGrant` — a pre-instance init grant authorized
/// genesis: no console took part.
pub const GENESIS_CEREMONY_GRANT: &str = "grant";

/// `grantStoreDirName` — the instance's grant store directory.
const GRANT_STORE_DIR_NAME: &str = "grants";

/// `genesisRoots` — the two host roots genesis writes under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisRoots {
    pub state_root: String,
    pub protected_root: String,
}

impl GenesisRoots {
    pub fn production() -> Self {
        GenesisRoots {
            state_root: "/var/lib/central-state/v1".to_owned(),
            protected_root: "/var/lib/central-protected/v1".to_owned(),
        }
    }

    pub fn instances_root(&self) -> PathBuf {
        Path::new(&self.state_root).join("instances")
    }

    pub fn protected_instances_root(&self) -> PathBuf {
        Path::new(&self.protected_root).join("instances")
    }

    pub fn lock_path(&self) -> PathBuf {
        Path::new(&self.state_root).join(GENESIS_LOCK_NAME)
    }

    /// `ancestors` — the directories genesis reaches the instance
    /// through by path and that the ancestor rule covers: the state
    /// root's parent, the state root, and the protected root's
    /// parent. The protected root itself has the stricter exact rule.
    pub fn ancestors(&self) -> [PathBuf; 3] {
        let state = PathBuf::from(&self.state_root);
        let protected = PathBuf::from(&self.protected_root);
        [
            state
                .parent()
                .map_or_else(|| PathBuf::from("/"), Path::to_path_buf),
            state,
            protected
                .parent()
                .map_or_else(|| PathBuf::from("/"), Path::to_path_buf),
        ]
    }
}

/// `genesisOwners` — the two identities the layout is owned by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenesisOwners {
    pub root_uid: u32,
    pub root_gid: u32,
    pub runtime_uid: u32,
    pub runtime_gid: u32,
}

impl GenesisOwners {
    pub const fn production() -> Self {
        GenesisOwners {
            root_uid: 0,
            root_gid: 0,
            runtime_uid: CENTRAL_RUNTIME_UID,
            runtime_gid: CENTRAL_RUNTIME_GID,
        }
    }
}

/// `genesisState` — the host's classification before genesis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenesisState {
    /// The two instances roots are each missing or an empty
    /// root-owned `0700` directory.
    Absent,
    /// Exactly one instance resolves through the production loader,
    /// its protected root passes the broker's root check, it has an
    /// active dependency receipt, and its genesis record is valid.
    Present,
    /// Anything else; genesis never touches a broken host.
    Broken,
}

impl GenesisState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Present => "present",
            Self::Broken => "broken",
        }
    }
}

/// `genesisRecord` — `<instance dir>/genesis.json`, the source of the
/// three IDs `central local init` reports, also when it answers
/// "already initialized".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisRecord {
    pub schema_version: String,
    pub instance_id: String,
    pub config_binding_id: String,
    pub init_operation_id: String,
    pub created_at: String,
    pub ceremony: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub grant_nonce: String,
}

/// `genesisOutcome` — the instance's record plus whether this call
/// created it.
#[derive(Debug, Clone)]
pub struct GenesisOutcome {
    pub record: GenesisRecord,
    pub created: bool,
}

/// `genesisFailure` — the closed set of ways genesis refuses or fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenesisFailure {
    /// Less than 40 GiB free on the state filesystem; nothing written.
    Capacity,
    /// Another genesis held the lock too long.
    LockTimeout,
    /// The host refused a pre-acceptance step, or the caller gave up
    /// waiting for the lock.
    Unavailable,
    /// The host is neither absent nor present.
    Broken,
    /// A step after the accepted point failed; cleanup names the
    /// paths the operator removes by hand.
    Mutation,
    /// The authoritative config was renamed into place but the
    /// instance could not be confirmed; nothing is to be removed.
    Unconfirmed,
}

/// `genesisError` — the failure class, the console-only cleanup
/// paths, and the cause.
#[derive(Debug)]
pub struct GenesisError {
    pub failure: GenesisFailure,
    pub cleanup: Vec<PathBuf>,
    pub cause: String,
}

impl GenesisError {
    fn new(failure: GenesisFailure, cause: impl Into<String>) -> Self {
        GenesisError {
            failure,
            cleanup: Vec::new(),
            cause: cause.into(),
        }
    }
}

impl std::fmt::Display for GenesisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "genesis: {}", self.cause)
    }
}

impl std::error::Error for GenesisError {}

// ---------------------------------------------------------------------------
// Locked identities (D4 — `ensure_identity` from packaging/install/install.sh)
// ---------------------------------------------------------------------------

/// One system identity genesis ensures: the account name, its
/// allocated uid:gid, shell and home — `authority.LockedIdentity`
/// made concrete. The three D4 identities run `--system` at fixed
/// ids: `central-runtime` `501:501` (`authority.CentralRuntimeUID`),
/// `central-agent` `502:502` (`sandbox::envelope::AGENT_UID`), and
/// `central-browser` `503:503` (the next allocation in the domain's
/// `UidGidMap` order). `central-migrate` (`986`) stays a domain
/// template: upstream allocates it in the package installer, not in
/// genesis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenesisIdentity {
    pub name: &'static str,
    pub uid: u32,
    pub gid: u32,
    pub home: &'static str,
    pub shell: &'static str,
}

/// The D4 identities `ensureLockedIdentities` walks, in domain order.
pub const GENESIS_IDENTITIES: [GenesisIdentity; 3] = [
    GenesisIdentity {
        name: "central-runtime",
        uid: CENTRAL_RUNTIME_UID,
        gid: CENTRAL_RUNTIME_GID,
        home: "/nonexistent",
        shell: "/usr/sbin/nologin",
    },
    GenesisIdentity {
        name: "central-agent",
        uid: crate::sandbox::envelope::AGENT_UID,
        gid: crate::sandbox::envelope::AGENT_GID,
        home: "/nonexistent",
        shell: "/usr/sbin/nologin",
    },
    GenesisIdentity {
        name: "central-browser",
        uid: CENTRAL_BROWSER_UID,
        gid: CENTRAL_BROWSER_GID,
        home: "/var/lib/central-browser",
        shell: "/usr/sbin/nologin",
    },
];

/// `ensure_identity`'s exact argv — the installer's two lines,
/// verbatim: `groupadd --system --gid <id> <name>` then
/// `useradd --system --no-create-home --home-dir <home>
/// --shell <shell> --uid <id> --gid <id> <name>`.
pub fn ensure_identity_argv(identity: &GenesisIdentity) -> [Vec<String>; 2] {
    [
        vec![
            "groupadd".to_owned(),
            "--system".to_owned(),
            "--gid".to_owned(),
            identity.gid.to_string(),
            identity.name.to_owned(),
        ],
        vec![
            "useradd".to_owned(),
            "--system".to_owned(),
            "--no-create-home".to_owned(),
            "--home-dir".to_owned(),
            identity.home.to_owned(),
            "--shell".to_owned(),
            identity.shell.to_owned(),
            "--uid".to_owned(),
            identity.uid.to_string(),
            "--gid".to_owned(),
            identity.gid.to_string(),
            identity.name.to_owned(),
        ],
    ]
}

/// `/etc/passwd`'s uid → name probe.
fn passwd_uid_owner(path: &str) -> impl Fn(&str, u32) -> Option<String> + Send + Sync {
    let path = path.to_owned();
    move |table, id| {
        if table != "uid" {
            return None;
        }
        std::fs::read_to_string(&path).ok().and_then(|raw| {
            raw.lines().find_map(|line| {
                let mut fields = line.split(':');
                let name = fields.next()?;
                fields.next()?; // password
                let uid: u32 = fields.next()?.parse().ok()?;
                (uid == id).then(|| name.to_owned())
            })
        })
    }
}

/// `/etc/group`'s gid → name probe.
fn group_gid_owner(path: &str) -> impl Fn(&str, u32) -> Option<String> + Send + Sync {
    let path = path.to_owned();
    move |table, id| {
        if table != "gid" {
            return None;
        }
        std::fs::read_to_string(&path).ok().and_then(|raw| {
            raw.lines().find_map(|line| {
                let mut fields = line.split(':');
                let name = fields.next()?;
                fields.next()?; // password
                let gid: u32 = fields.next()?.parse().ok()?;
                (gid == id).then(|| name.to_owned())
            })
        })
    }
}

/// The `Command` boundary — `argv[0]` exec'd with `argv[1..]`,
/// succeeding on exit 0. Only the root helper ever constructs the
/// production executor (D4).
pub type IdentityExec = Arc<dyn Fn(&[String]) -> Result<(), String> + Send + Sync>;

/// The `real_gid_owner`/`real_uid_owner` probe shape.
pub type IdentityLookup = Arc<dyn Fn(&str, u32) -> Option<String> + Send + Sync>;

/// The production executor: `std::process::Command`, no shell, the
/// argv exactly as `ensure_identity_argv` renders it.
fn run_identity_command(argv: &[String]) -> Result<(), String> {
    let Some((program, args)) = argv.split_first() else {
        return Err("identity: empty argv".to_owned());
    };
    let status = std::process::Command::new(program)
        .args(args)
        .status()
        .map_err(|e| format!("identity: exec {program}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("identity: {program} exited {status}"))
    }
}

/// `ensure_identity`'s probe-then-create for the whole D4 set. A uid
/// already owned by the identity's name is reported present and left
/// untouched — the installer's idempotent shape exactly.
pub fn ensure_locked_identities_with(
    lookup: &IdentityLookup,
    exec: &IdentityExec,
) -> Result<(), String> {
    for identity in &GENESIS_IDENTITIES {
        let [group_argv, user_argv] = ensure_identity_argv(identity);
        if lookup("gid", identity.gid).as_deref() != Some(identity.name) {
            exec(&group_argv)?;
        }
        if lookup("uid", identity.uid).as_deref() != Some(identity.name) {
            exec(&user_argv)?;
        }
    }
    Ok(())
}

/// The production `ensure_locked_identities`: real passwd/group
/// probes plus the real `groupadd`/`useradd` exec.
pub fn ensure_locked_identities() -> Result<(), String> {
    let uid_lookup = passwd_uid_owner("/etc/passwd");
    let gid_lookup = group_gid_owner("/etc/group");
    let lookup: IdentityLookup = Arc::new(move |table, id| {
        if table == "uid" {
            uid_lookup(table, id)
        } else {
            gid_lookup(table, id)
        }
    });
    let exec: IdentityExec = Arc::new(run_identity_command);
    ensure_locked_identities_with(&lookup, &exec)
}

// ---------------------------------------------------------------------------
// genesisEnv — everything genesis reads from the host
// ---------------------------------------------------------------------------

type FreeBytes = Arc<dyn Fn(&Path) -> Result<u64, String> + Send + Sync>;
type NowFn = Arc<dyn Fn() -> time::OffsetDateTime + Send + Sync>;
type ConfigFn = Arc<dyn Fn(&Instance) -> Result<Vec<u8>, String> + Send + Sync>;
type FchownFn = Arc<dyn for<'a> Fn(BorrowedFd<'a>, u32, u32) -> Result<(), Errno> + Send + Sync>;
type FsyncFn = Arc<dyn for<'a> Fn(BorrowedFd<'a>) -> Result<(), Errno> + Send + Sync>;
type IdentitiesFn = Arc<dyn Fn() -> Result<(), String> + Send + Sync>;

/// `genesisEnv` — roots, owners, and the seams tests replace:
/// `free_bytes`, `now`, `config`, `lock_wait`, `fchown`,
/// `fsync_dir`, and `ensure_identities` (production: statfs, the
/// wall clock, the embedded defaults, `fchown(2)`, `fsync(2)`, and
/// the real `useradd`/`groupadd` provisioner).
#[derive(Clone)]
pub struct GenesisEnv {
    pub roots: GenesisRoots,
    pub owners: GenesisOwners,
    pub free_bytes: FreeBytes,
    pub now: NowFn,
    pub config: ConfigFn,
    pub lock_wait: Duration,
    pub fchown: FchownFn,
    pub fsync_dir: FsyncFn,
    pub ensure_identities: IdentitiesFn,
}

impl GenesisEnv {
    /// `productionGenesisEnv`.
    pub fn production() -> Self {
        GenesisEnv {
            roots: GenesisRoots::production(),
            owners: GenesisOwners::production(),
            free_bytes: Arc::new(statfs_available_bytes),
            now: Arc::new(time::OffsetDateTime::now_utc),
            config: Arc::new(|instance| {
                central_infra::config::defaults::config(instance).map_err(|e| e.to_string())
            }),
            lock_wait: Duration::from_secs(30),
            fchown: Arc::new(|fd: BorrowedFd<'_>, uid, gid| {
                fchown(
                    fd,
                    Some(rustix::process::Uid::from_raw(uid)),
                    Some(rustix::process::Gid::from_raw(gid)),
                )
            }),
            fsync_dir: Arc::new(|fd: BorrowedFd<'_>| rustix::fs::fsync(fd)),
            ensure_identities: Arc::new(ensure_locked_identities),
        }
    }

    /// A test env over `state`/`protected` roots on a scratch
    /// filesystem with both owners set to the caller's euid — the
    /// shape upstream's genesis tests use.
    #[cfg(test)]
    pub fn test(state_root: &Path, protected_root: &Path, uid: u32, gid: u32) -> Self {
        let mut env = Self::production();
        env.roots = GenesisRoots {
            state_root: state_root.to_string_lossy().into_owned(),
            protected_root: protected_root.to_string_lossy().into_owned(),
        };
        env.owners = GenesisOwners {
            root_uid: uid,
            root_gid: gid,
            runtime_uid: uid,
            runtime_gid: gid,
        };
        env.lock_wait = Duration::from_secs(2);
        env.ensure_identities = Arc::new(|| Ok(()));
        // A scratch filesystem does not promise 40 GiB; capacity has
        // its own test over the seam.
        env.free_bytes = Arc::new(|_| Ok(u64::MAX));
        env
    }

    fn chown(&self, fd: BorrowedFd<'_>, uid: u32, gid: u32) -> Result<(), Errno> {
        (self.fchown)(fd, uid, gid)
    }

    fn sync_dir(&self, fd: BorrowedFd<'_>) -> Result<(), Errno> {
        (self.fsync_dir)(fd)
    }

    /// `state` — classifies the host. Reads only. The error string is
    /// the `INSTANCE_BROKEN` cause the helper journals.
    pub fn state(&self) -> (GenesisState, Option<GenesisRecord>, Option<String>) {
        for path in self.roots.ancestors() {
            if let Err(e) = genesis_ancestor_missing_or_root_owned(&path, self.owners.root_uid) {
                return (GenesisState::Broken, None, Some(e));
            }
        }
        if let Err(e) = protected_genesis_root_missing_or_exact(
            &PathBuf::from(&self.roots.protected_root),
            self.owners.root_uid,
            self.owners.root_gid,
        ) {
            return (GenesisState::Broken, None, Some(e));
        }
        let state_empty = match empty_genesis_root_or_missing(
            &self.roots.instances_root(),
            self.owners.root_uid,
            self.owners.root_gid,
        ) {
            Ok(empty) => empty,
            Err(e) => return (GenesisState::Broken, None, Some(e)),
        };
        let protected_empty = match empty_genesis_root_or_missing(
            &self.roots.protected_instances_root(),
            self.owners.root_uid,
            self.owners.root_gid,
        ) {
            Ok(empty) => empty,
            Err(e) => return (GenesisState::Broken, None, Some(e)),
        };
        if state_empty && protected_empty {
            return (GenesisState::Absent, None, None);
        }
        if state_empty {
            return (
                GenesisState::Broken,
                None,
                Some(format!(
                    "protected state under {} has no state instance under {}",
                    self.roots.protected_instances_root().display(),
                    self.roots.instances_root().display()
                )),
            );
        }
        match self.present_record() {
            Ok(record) => (GenesisState::Present, Some(record), None),
            Err(e) => (GenesisState::Broken, None, Some(e)),
        }
    }

    /// `presentRecord` — the present host's record through the real
    /// loaders: the production composition, the broker's protected
    /// root check, the active dependency receipt, and the genesis
    /// record naming the same instance.
    fn present_record(&self) -> Result<GenesisRecord, String> {
        let instances_root = self.roots.instances_root();
        let composition = load_production_instance_composition_for_owner(
            &instances_root.to_string_lossy(),
            self.owners.root_uid,
            self.owners.root_gid,
            self.owners.runtime_uid,
            self.owners.runtime_gid,
        )
        .map_err(|e| {
            format!(
                "the instance under {} does not resolve through the production loader: {e}",
                instances_root.display()
            )
        })?;
        production_broker_root_at(
            &composition,
            &self.roots.protected_instances_root().to_string_lossy(),
            self.owners.root_uid,
            self.owners.root_gid,
        )
        .map_err(|e| {
            format!(
                "instance {} has no valid protected root under {}: {e}",
                composition.instance_id,
                self.roots.protected_instances_root().display()
            )
        })?;
        CandidateStore::new(None, PathBuf::from(&composition.dependency_root))
            .active(OpDeadline::NONE)
            .map_err(|e| {
                format!(
                    "instance {} has no active dependency receipt: {}",
                    composition.instance_id,
                    e.message()
                )
            })?;
        let record = read_genesis_record(
            &PathBuf::from(&composition.authoritative_state_root),
            self.owners.root_uid,
            self.owners.root_gid,
        )
        .map_err(|e| {
            format!(
                "instance {} has no valid genesis record: {e}",
                composition.instance_id
            )
        })?;
        if record.instance_id != composition.instance_id {
            return Err(format!(
                "the genesis record of instance {} names instance {}",
                composition.instance_id, record.instance_id
            ));
        }
        Ok(record)
    }

    /// `checkCapacity` — refuse under 40 GiB free on the state
    /// filesystem. Reads only.
    pub fn check_capacity(&self) -> Result<(), GenesisError> {
        let path = nearest_existing_path(Path::new(&self.roots.state_root));
        let free = (self.free_bytes)(&path).map_err(|e| {
            GenesisError::new(
                GenesisFailure::Unavailable,
                format!("free space of {}: {e}", path.display()),
            )
        })?;
        if free < GENESIS_MINIMUM_FREE_BYTES {
            return Err(GenesisError::new(
                GenesisFailure::Capacity,
                format!(
                    "{} has {free} bytes free, genesis needs {GENESIS_MINIMUM_FREE_BYTES}",
                    path.display()
                ),
            ));
        }
        Ok(())
    }

    /// `create` — capacity, then the lock, then the absent re-check
    /// under it, then the install. A present host returns its record
    /// with `created` false; a broken host is refused untouched.
    pub fn create(
        &self,
        deadline: Instant,
        ceremony: &str,
        grant_nonce: &str,
    ) -> Result<GenesisOutcome, GenesisError> {
        self.check_capacity()?;
        let _unlock = self.lock(deadline)?;
        let (state, record, err) = self.state();
        match state {
            GenesisState::Present => {
                let Some(record) = record else {
                    return Err(GenesisError::new(
                        GenesisFailure::Broken,
                        "a present state carries no record",
                    ));
                };
                return Ok(GenesisOutcome {
                    record,
                    created: false,
                });
            }
            GenesisState::Absent => {}
            GenesisState::Broken => {
                return Err(GenesisError::new(
                    GenesisFailure::Broken,
                    err.unwrap_or_else(|| "the host is broken".to_owned()),
                ));
            }
        }
        // The accepted point: capacity checked, lock held, host
        // absent. From here every failure leaves a broken host the
        // operator cleans by hand.
        let record = self.install(deadline, ceremony, grant_nonce)?;
        Ok(GenesisOutcome {
            record,
            created: true,
        })
    }

    /// `lock` — the exclusive genesis lock `<state root>/
    /// .genesis.lock` (root `0600`), waiting at most `lock_wait`.
    /// RAII: the returned guard unlocks and closes on drop.
    fn lock(&self, deadline: Instant) -> Result<GenesisLock, GenesisError> {
        // A state root (or its parent) another identity owns or can
        // write is refused before anything is written into it, the
        // lock file included.
        let state_root = PathBuf::from(&self.roots.state_root);
        for path in [
            state_root
                .parent()
                .map_or_else(|| PathBuf::from("/"), Path::to_path_buf),
            state_root.clone(),
        ] {
            if let Err(e) = genesis_ancestor_missing_or_root_owned(&path, self.owners.root_uid) {
                return Err(GenesisError::new(GenesisFailure::Unavailable, e));
            }
        }
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&state_root)
            .map_err(|e| {
                GenesisError::new(
                    GenesisFailure::Unavailable,
                    format!("state root {}: {e}", state_root.display()),
                )
            })?;
        let lock_path = self.roots.lock_path();
        let fd = open(
            &lock_path,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|e| {
            GenesisError::new(
                GenesisFailure::Unavailable,
                format!("genesis lock {}: {e}", lock_path.display()),
            )
        })?;
        // Only a regular file with one link is ever re-owned.
        let stat = fstat(&fd).map_err(|_| {
            GenesisError::new(
                GenesisFailure::Unavailable,
                format!("genesis lock {} cannot be inspected", lock_path.display()),
            )
        })?;
        if !FileType::from_raw_mode(stat.st_mode).is_file() || stat.st_nlink != 1 {
            return Err(GenesisError::new(
                GenesisFailure::Unavailable,
                format!(
                    "genesis lock {} is not a regular file with one link",
                    lock_path.display()
                ),
            ));
        }
        self.chown(fd.as_fd(), self.owners.root_uid, self.owners.root_gid)
            .map_err(|e| {
                GenesisError::new(
                    GenesisFailure::Unavailable,
                    format!("genesis lock owner: {e}"),
                )
            })?;
        fchmod(&fd, Mode::from_raw_mode(0o600)).map_err(|e| {
            GenesisError::new(
                GenesisFailure::Unavailable,
                format!("genesis lock mode: {e}"),
            )
        })?;
        let until = Instant::now() + self.lock_wait;
        loop {
            match flock(&fd, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => return Ok(GenesisLock { fd }),
                Err(Errno::WOULDBLOCK) => {}
                Err(e) => {
                    return Err(GenesisError::new(
                        GenesisFailure::Unavailable,
                        format!("genesis lock: {e}"),
                    ));
                }
            }
            if Instant::now() >= deadline {
                return Err(GenesisError::new(
                    GenesisFailure::Unavailable,
                    "gave up waiting for the genesis lock: the operation timed out",
                ));
            }
            if Instant::now() >= until {
                return Err(GenesisError::new(
                    GenesisFailure::LockTimeout,
                    "another genesis holds the genesis lock",
                ));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// `install` — spec decision 6's steps 2-7. Every directory is
    /// created relative to its parent's descriptor and re-owned
    /// through its own descriptor, never by path. The instance
    /// directory stays root-owned `0700` until its subtree, its
    /// dependency receipt and its genesis record exist; only then is
    /// it handed to `central-runtime`, and only then is the
    /// authoritative config written into it, last, by rename — the
    /// commit point.
    fn install(
        &self,
        deadline: Instant,
        ceremony: &str,
        grant_nonce: &str,
    ) -> Result<GenesisRecord, GenesisError> {
        let ids: Vec<String> = (0..3).map(|_| uuid::Uuid::now_v7().to_string()).collect();
        let instance_id = ids[0].clone();
        let owners = self.owners;
        let state_root = self.roots.instances_root().join(&instance_id);
        let protected_instance = self.roots.protected_instances_root().join(&instance_id);
        // `fail` names, for the operator to remove, only the paths of
        // the instance's two directories this genesis got as far as
        // creating.
        let fail = |step: &str, cause: String| {
            let mut err = GenesisError::new(GenesisFailure::Mutation, format!("{step}: {cause}"));
            err.cleanup = existing_genesis_paths(&[state_root.clone(), protected_instance.clone()]);
            err
        };
        // (0) D4: the locked identities, before any directory work —
        // the instance directory's hand-off names `central-runtime`'s
        // uid, and the sandbox/browser runtimes name the other two.
        (self.ensure_identities)().map_err(|e| fail("locked identities", e))?;

        let mut open_fds: Vec<OwnedFd> = Vec::new();
        // `dir` creates (or verifies) `fds[parent_i]/name` and pushes
        // its descriptor; the parent is passed by index so the fd
        // vector stays borrowable.
        let dir = |step: &'static str,
                   parent_i: usize,
                   name: &str,
                   uid: u32,
                   gid: u32,
                   may_exist: bool,
                   fds: &mut Vec<OwnedFd>|
         -> Result<usize, GenesisError> {
            let parent = fds[parent_i]
                .try_clone()
                .map_err(|e| fail(step, e.to_string()))?;
            match self.genesis_dir_at(parent.as_fd(), name, uid, gid, may_exist) {
                Ok(fd) => {
                    fds.push(fd);
                    Ok(fds.len() - 1)
                }
                Err(e) => Err(fail(step, e)),
            }
        };
        let open_path = |step: &'static str,
                         path: &Path,
                         fds: &mut Vec<OwnedFd>|
         -> Result<usize, GenesisError> {
            match open(
                path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(fd) => {
                    fds.push(fd);
                    Ok(fds.len() - 1)
                }
                Err(e) => Err(fail(step, e.to_string())),
            }
        };

        // (2) The roots, each root-owned `0700`.
        let protected_root = PathBuf::from(&self.roots.protected_root);
        let protected_parent = protected_root
            .parent()
            .map_or_else(|| PathBuf::from("/"), Path::to_path_buf);
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&protected_parent)
            .map_err(|e| fail("protected root parent", e.to_string()))?;
        let protected_parent_i =
            open_path("protected root parent", &protected_parent, &mut open_fds)?;
        let basename = protected_root
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let protected_root_i = dir(
            "protected root",
            protected_parent_i,
            &basename,
            owners.root_uid,
            owners.root_gid,
            true,
            &mut open_fds,
        )?;
        let protected_instances_i = dir(
            "protected instances root",
            protected_root_i,
            "instances",
            owners.root_uid,
            owners.root_gid,
            true,
            &mut open_fds,
        )?;
        let state_parent_i = open_path(
            "state root",
            Path::new(&self.roots.state_root),
            &mut open_fds,
        )?;
        let instances_i = dir(
            "instances root",
            state_parent_i,
            "instances",
            owners.root_uid,
            owners.root_gid,
            true,
            &mut open_fds,
        )?;

        // The instance directory, root-owned `0700` while genesis
        // builds it.
        let instance_i = dir(
            "instance directory",
            instances_i,
            &instance_id,
            owners.root_uid,
            owners.root_gid,
            false,
            &mut open_fds,
        )?;
        let data_i = dir(
            "data",
            instance_i,
            "data",
            owners.root_uid,
            owners.root_gid,
            false,
            &mut open_fds,
        )?;
        for (parent_i, name) in [
            (data_i, "postgres"),
            (data_i, "minio"),
            (instance_i, "dependencies"),
            (instance_i, "lifecycle"),
        ] {
            dir(
                name,
                parent_i,
                name,
                owners.root_uid,
                owners.root_gid,
                false,
                &mut open_fds,
            )?;
        }
        // SC-DEF-30: the backup repository is central_runtime's.
        let backups_i = dir(
            "backups",
            instance_i,
            "backups",
            owners.runtime_uid,
            owners.runtime_gid,
            false,
            &mut open_fds,
        )?;
        // SC-DEF-31: its binding.json, bound to this instance.
        crate::backup_repository::initialize_repository_binding(
            open_fds[backups_i].as_fd(),
            &instance_id,
        )
        .map_err(|e| fail("backup repository binding", e.message().to_owned()))?;
        // (3) ADR 0020: the version-zero dependency receipt, while
        // the instance directory is still root-owned.
        ensure_version_zero_receipt(OpDeadline(Some(deadline)), &state_root.join("dependencies"))
            .map_err(|e| fail("version-zero dependency receipt", e.message().to_owned()))?;
        // (4) The instance's protected directories, root-owned `0700`
        // at every level the broker checks.
        let protected_instance_i = dir(
            "protected instance",
            protected_instances_i,
            &instance_id,
            owners.root_uid,
            owners.root_gid,
            false,
            &mut open_fds,
        )?;
        dir(
            "protected directory",
            protected_instance_i,
            "protected",
            owners.root_uid,
            owners.root_gid,
            false,
            &mut open_fds,
        )?;
        // (5) The genesis record, also before the hand-off.
        let record = GenesisRecord {
            schema_version: GENESIS_RECORD_SCHEMA.to_owned(),
            instance_id: instance_id.clone(),
            config_binding_id: ids[1].clone(),
            init_operation_id: ids[2].clone(),
            created_at: crate::broker::wire::format_rfc3339_nano((self.now)()),
            ceremony: ceremony.to_owned(),
            grant_nonce: grant_nonce.to_owned(),
        };
        self.write_genesis_record(open_fds[instance_i].as_fd(), &record)
            .map_err(|e| fail("genesis record", e))?;
        // (5b) Grant mode from birth: the ceremony-mode file and the
        // instance's grant store, exactly as `central grant mode
        // grant` leaves them.
        if ceremony == GENESIS_CEREMONY_GRANT {
            crate::helper::grant::write_ceremony_mode(
                &state_root.to_string_lossy(),
                crate::helper::grant::CeremonyMode::Grant,
            )
            .map_err(|e| fail("grant ceremony mode", e.message().to_owned()))?;
            dir(
                "instance grant store",
                instance_i,
                GRANT_STORE_DIR_NAME,
                owners.root_uid,
                owners.root_gid,
                false,
                &mut open_fds,
            )?;
        }
        let raw = (self.config)(&Instance::new(
            instance_id.clone(),
            state_root.to_string_lossy().into_owned(),
        ))
        .map_err(|e| fail("authoritative config", e))?;
        // The hand-off: the instance directory becomes
        // central_runtime's.
        self.chown(
            open_fds[instance_i].as_fd(),
            owners.runtime_uid,
            owners.runtime_gid,
        )
        .map_err(|e| fail("instance directory owner", e.to_string()))?;
        fchmod(&open_fds[instance_i], Mode::from_raw_mode(0o700))
            .map_err(|e| fail("instance directory mode", e.to_string()))?;
        // (6) The authoritative config, last, by rename: the commit
        // point.
        match self.commit_genesis_config(open_fds[instance_i].as_fd(), &raw) {
            Ok(()) => {}
            Err(ConfigCommitError::Unsynced(cause)) => {
                return Err(GenesisError::new(
                    GenesisFailure::Unconfirmed,
                    format!(
                        "instance {instance_id}: {cause}; run central local init again or check central local status, and remove nothing"
                    ),
                ));
            }
            Err(ConfigCommitError::Io(cause)) => {
                return Err(fail("commit authoritative config", cause));
            }
        }
        // (7) Done only when the host is present with this instance.
        let (state, present, err) = self.state();
        match (state, present) {
            (GenesisState::Present, Some(present)) if present.instance_id == instance_id => {
                Ok(present)
            }
            _ => Err(GenesisError::new(
                GenesisFailure::Unconfirmed,
                format!(
                    "instance {instance_id}: the host is {} after the commit ({}); run central local init again or check central local status, and remove nothing",
                    state.as_str(),
                    err.unwrap_or_else(|| "no state error".to_owned())
                ),
            )),
        }
    }

    /// `genesisDirAt` — create (or, for a root, verify) `parent/name`
    /// as `uid:gid` `0700` and keep its descriptor open. Owner and
    /// mode are set through the descriptor, opened `O_NOFOLLOW`, so a
    /// swapped entry is never followed.
    fn genesis_dir_at(
        &self,
        parent: BorrowedFd<'_>,
        name: &str,
        uid: u32,
        gid: u32,
        may_exist: bool,
    ) -> Result<OwnedFd, String> {
        let created = match mkdirat(parent, name, Mode::from_raw_mode(0o700)) {
            Ok(()) => true,
            Err(Errno::EXIST) if may_exist => false,
            Err(e) => return Err(e.to_string()),
        };
        let fd = openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| format!("{name} is not a directory: {e}"))?;
        if !created {
            if !exact_owned_directory(&fd, uid, gid, 0o700) {
                return Err(format!("{name} is not {uid}:{gid} 0700"));
            }
            return Ok(fd);
        }
        self.chown(fd.as_fd(), uid, gid)
            .map_err(|e| e.to_string())?;
        fchmod(&fd, Mode::from_raw_mode(0o700)).map_err(|e| e.to_string())?;
        Ok(fd)
    }

    /// `writeGenesisRecord` — `genesis.json` into the instance
    /// directory descriptor, root-owned `0600`, synced.
    fn write_genesis_record(
        &self,
        instance_fd: BorrowedFd<'_>,
        record: &GenesisRecord,
    ) -> Result<(), String> {
        let raw = serde_json::to_vec(record).map_err(|e| e.to_string())?;
        let fd = openat(
            instance_fd,
            GENESIS_RECORD_NAME,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|e| e.to_string())?;
        self.chown(fd.as_fd(), self.owners.root_uid, self.owners.root_gid)
            .map_err(|e| e.to_string())?;
        fchmod(&fd, Mode::from_raw_mode(0o600)).map_err(|e| e.to_string())?;
        let mut file = std::fs::File::from(fd);
        use std::io::Write as _;
        let mut payload = raw;
        payload.push(b'\n');
        file.write_all(&payload).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())
    }

    /// `commitGenesisConfig` — the temp file owned by
    /// `central-runtime` `0600`, fsync, `RENAME_NOREPLACE` to
    /// `config.json`, directory fsync. A failed directory fsync after
    /// the rename is [`ConfigCommitError::Unsynced`].
    fn commit_genesis_config(
        &self,
        dir_fd: BorrowedFd<'_>,
        raw: &[u8],
    ) -> Result<(), ConfigCommitError> {
        let io = |e: Errno| ConfigCommitError::Io(e.to_string());
        let tmp_fd = openat(
            dir_fd,
            GENESIS_CONFIG_TEMP_NAME,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(io)?;
        let result = (|| -> Result<(), ConfigCommitError> {
            self.chown(
                tmp_fd.as_fd(),
                self.owners.runtime_uid,
                self.owners.runtime_gid,
            )
            .map_err(io)?;
            fchmod(&tmp_fd, Mode::from_raw_mode(0o600)).map_err(io)?;
            let mut file = std::fs::File::from(
                tmp_fd
                    .try_clone()
                    .map_err(|e| ConfigCommitError::Io(e.to_string()))?,
            );
            use std::io::Write as _;
            file.write_all(raw)
                .map_err(|e| ConfigCommitError::Io(e.to_string()))?;
            file.sync_all()
                .map_err(|e| ConfigCommitError::Io(e.to_string()))?;
            drop(file);
            renameat_with(
                dir_fd,
                GENESIS_CONFIG_TEMP_NAME,
                dir_fd,
                "config.json",
                rustix::fs::RenameFlags::NOREPLACE,
            )
            .map_err(io)?;
            self.sync_dir(dir_fd).map_err(|e| {
                ConfigCommitError::Unsynced(format!(
                    "the authoritative config was committed but the instance directory could not be synced: {e}"
                ))
            })
        })();
        drop(tmp_fd);
        result
    }
}

/// `errGenesisConfigUnsynced` vs the ordinary commit failure.
#[derive(Debug)]
enum ConfigCommitError {
    Io(String),
    /// The rename happened; only the durability fsync failed —
    /// upstream's `errGenesisConfigUnsynced`.
    Unsynced(String),
}

/// `GenesisLock` — the held lock file; unlocks and closes on drop.
struct GenesisLock {
    fd: OwnedFd,
}

impl Drop for GenesisLock {
    fn drop(&mut self) {
        let _ = flock(&self.fd, rustix::fs::FlockOperation::Unlock);
    }
}

// ---------------------------------------------------------------------------
// Free-standing helpers — the file's leaf functions, upstream order
// ---------------------------------------------------------------------------

/// `exactOwnedDirectory` — `fstat` on the descriptor: a directory of
/// exactly `mode`, owned `uid:gid`.
fn exact_owned_directory<Fd: AsFd>(fd: Fd, uid: u32, gid: u32, mode: u32) -> bool {
    let Ok(st) = fstat(fd) else {
        return false;
    };
    FileType::from_raw_mode(st.st_mode).is_dir()
        && st.st_uid == uid
        && st.st_gid == gid
        && st.st_mode & 0o7777 == mode
}

/// `genesisAncestorMissingOrRootOwned` — missing, or a real directory
/// owned by `uid` that is neither group- nor other-writable. Reads
/// only.
pub fn genesis_ancestor_missing_or_root_owned(path: &Path, uid: u32) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("{} cannot be inspected: {e}", path.display())),
        Ok(_) => {}
    }
    let fd = match open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(_) => return Err(format!("{} is not a directory", path.display())),
    };
    let stat = fstat(&fd).map_err(|e| format!("{} cannot be inspected: {e}", path.display()))?;
    if stat.st_uid != uid || stat.st_mode & 0o022 != 0 {
        return Err(format!(
            "{} is not owned by {uid} or is group- or other-writable",
            path.display()
        ));
    }
    Ok(())
}

/// `protectedGenesisRootMissingOrExact` — missing, or a real
/// `uid:gid` `0700` directory. Reads only.
pub fn protected_genesis_root_missing_or_exact(
    path: &Path,
    uid: u32,
    gid: u32,
) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("{} cannot be inspected: {e}", path.display())),
        Ok(_) => {}
    }
    let fd = match open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(_) => return Err(format!("{} is not a directory", path.display())),
    };
    if !exact_owned_directory(fd, uid, gid, 0o700) {
        return Err(format!("{} is not {uid}:{gid} 0700", path.display()));
    }
    Ok(())
}

/// `emptyGenesisRootOrMissing` — `Ok(true)` missing or an empty
/// `uid:gid` `0700` directory; `Ok(false)` that shape but non-empty;
/// `Err` anything else.
pub fn empty_genesis_root_or_missing(path: &Path, uid: u32, gid: u32) -> Result<bool, String> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(e) => return Err(format!("{} cannot be inspected: {e}", path.display())),
        Ok(_) => {}
    }
    let fd = match open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(_) => return Err(format!("{} is not a directory", path.display())),
    };
    if !exact_owned_directory(&fd, uid, gid, 0o700) {
        return Err(format!("{} is not {uid}:{gid} 0700", path.display()));
    }
    let dir = rustix::fs::Dir::read_from(&fd)
        .map_err(|e| format!("{} cannot be listed: {e}", path.display()))?;
    for entry in dir {
        match entry {
            Ok(entry) => {
                let name = entry.file_name().to_bytes();
                if name != b"." && name != b".." {
                    return Ok(false);
                }
            }
            Err(e) => return Err(format!("{} cannot be listed: {e}", path.display())),
        }
    }
    Ok(true)
}

/// `ensureGenesisInitStore` — creates `dir` (the genesis grant
/// store) when missing: every existing ancestor must be root-owned
/// and not group/other-writable, and the protected root itself must
/// be exactly `root:root` `0700`. A pre-existing store dir is left
/// untouched — `OpenGrantStore` refuses it below when it is not
/// exactly right; it is never repaired.
pub fn ensure_genesis_init_store(env: &GenesisEnv, dir: &Path) -> Result<(), String> {
    let uid = env.owners.root_uid;
    let protected = PathBuf::from(&env.roots.protected_root);
    let parent = protected
        .parent()
        .map_or_else(|| PathBuf::from("/"), Path::to_path_buf);
    genesis_ancestor_missing_or_root_owned(&parent, uid)?;
    genesis_ancestor_missing_or_root_owned(&protected, uid)?;
    // The protected root itself, when present, must be exactly
    // root:root 0700 (fd-based, no path TOCTOU — the same pattern
    // `emptyGenesisRootOrMissing` uses).
    match open(
        &protected,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => {
            if !exact_owned_directory(fd, uid, env.owners.root_gid, 0o700) {
                return Err(format!(
                    "grant: {} must be exactly root:root 0700",
                    env.roots.protected_root
                ));
            }
        }
        Err(e) if e == Errno::NOENT => {}
        Err(e) => return Err(format!("grant: protected root: {e}")),
    }
    // `MkdirAll` honors umask: enforce the exact mode on what WE
    // create. `os.Lstat` recorded existence first so only the
    // entries this call makes are chmodded.
    let protected_missing = matches!(
        std::fs::symlink_metadata(&protected),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound
    );
    let store_missing = matches!(
        std::fs::symlink_metadata(dir),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound
    );
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| format!("grant: create store: {e}"))?;
    if protected_missing {
        std::fs::set_permissions(
            &protected,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .map_err(|e| format!("grant: create store: {e}"))?;
    }
    if store_missing {
        std::fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .map_err(|e| format!("grant: create store: {e}"))?;
    }
    Ok(())
}

/// `readGenesisRecord` — `O_NONBLOCK` open (a planted FIFO must not
/// hold the open), the regular-file/single-link/owner/mode/size
/// `fstat` gate, the strict decode, and every field validation.
pub fn read_genesis_record(state_root: &Path, uid: u32, gid: u32) -> Result<GenesisRecord, String> {
    let path = state_root.join(GENESIS_RECORD_NAME);
    let fd = open(
        &path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    let stat = fstat(&fd).map_err(|_| "genesis record is not a root-owned 0600 file".to_owned())?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_uid != uid
        || stat.st_gid != gid
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
        || stat.st_size <= 0
        || stat.st_size > MAXIMUM_GENESIS_RECORD_BYTES
    {
        return Err("genesis record is not a root-owned 0600 file".to_owned());
    }
    let mut file = std::fs::File::from(fd);
    let mut raw = Vec::new();
    use std::io::Read as _;
    (&mut file)
        .take((MAXIMUM_GENESIS_RECORD_BYTES + 1) as u64)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    if raw.is_empty() || raw.len() as i64 > MAXIMUM_GENESIS_RECORD_BYTES {
        return Err("genesis record is not a root-owned 0600 file".to_owned());
    }
    let mut de = serde_json::Deserializer::from_slice(&raw);
    let record: GenesisRecord = Deserialize::deserialize(&mut de).map_err(|e| e.to_string())?;
    de.end()
        .map_err(|_| "genesis record has trailing data".to_owned())?;
    if record.schema_version != GENESIS_RECORD_SCHEMA {
        return Err("genesis record has an unknown schema".to_owned());
    }
    if record.ceremony != GENESIS_CEREMONY_PHYSICAL_TTY
        && record.ceremony != GENESIS_CEREMONY_REFERENCE_HOST_HARNESS
        && record.ceremony != GENESIS_CEREMONY_GRANT
    {
        return Err("genesis record names an unknown ceremony".to_owned());
    }
    // The nonce links a grant install to the genesis store's consumed
    // record: required and well-formed for grant installs (32 raw
    // bytes, base64url without padding), forbidden otherwise.
    if record.ceremony == GENESIS_CEREMONY_GRANT {
        match crate::broker::wire::b64_url_raw_decode(&record.grant_nonce) {
            Some(decoded) if decoded.len() == 32 => {}
            _ => return Err("genesis record carries a malformed grant nonce".to_owned()),
        }
    } else if !record.grant_nonce.is_empty() {
        return Err("genesis record carries a grant nonce for a non-grant ceremony".to_owned());
    }
    time::OffsetDateTime::parse(
        &record.created_at,
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|_| "genesis record created_at is not RFC 3339".to_owned())?;
    for id in [
        &record.instance_id,
        &record.config_binding_id,
        &record.init_operation_id,
    ] {
        match uuid::Uuid::parse_str(id) {
            Ok(parsed)
                if parsed.get_version() == Some(uuid::Version::SortRand)
                    && parsed.to_string() == *id => {}
            _ => {
                return Err("genesis record carries an id that is not a UUIDv7".to_owned());
            }
        }
    }
    Ok(record)
}

/// `existingGenesisPaths` — the subset that exists (a dangling
/// symlink included).
fn existing_genesis_paths(paths: &[PathBuf]) -> Vec<PathBuf> {
    paths
        .iter()
        .filter(|p| std::fs::symlink_metadata(p).is_ok())
        .cloned()
        .collect()
}

/// `statfsAvailableBytes` — `f_bavail * f_bsize` at `path`.
pub fn statfs_available_bytes(path: &Path) -> Result<u64, String> {
    let stat = statfs(path).map_err(|e| e.to_string())?;
    genesis_available_bytes(stat.f_bavail, stat.f_bsize)
}

/// `genesisAvailableBytes` — refuses a non-positive block size and an
/// overflowing product.
pub fn genesis_available_bytes(available: u64, block_size: i64) -> Result<u64, String> {
    if block_size <= 0 {
        return Err(format!("statfs reports block size {block_size}"));
    }
    let size = block_size as u64;
    available
        .checked_mul(size)
        .ok_or_else(|| "statfs free space overflows 64 bits".to_owned())
}

/// `nearestExistingPath` — `path` or its closest existing ancestor.
pub fn nearest_existing_path(path: &Path) -> PathBuf {
    let mut path = path.to_path_buf();
    loop {
        if std::fs::symlink_metadata(&path).is_ok() {
            return path;
        }
        let parent = path
            .parent()
            .map_or_else(|| PathBuf::from("/"), Path::to_path_buf);
        if parent == path {
            return path;
        }
        path = parent;
    }
}

// ---------------------------------------------------------------------------
// Tests — the T13 matrix: state classification, the exact inventory,
// identity argv/idempotency, the record's validation gate, capacity,
// the lock, and the idempotent re-run.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt as _;
    use std::sync::Mutex;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "central-genesis-test-{}-{tag}-{}",
            std::process::id(),
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir_all(&dir).expect("scratch root");
        dir
    }

    /// `mkdir -p` with every created component at `0700` — the shape
    /// genesis's own `DirBuilder` calls produce (Rust applies `mode`
    /// recursively, like Go's `MkdirAll`).
    fn create_all_700(path: &Path) {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .expect("create_all_700");
    }

    fn euid() -> u32 {
        rustix::process::getuid().as_raw()
    }

    fn egid() -> u32 {
        rustix::process::getgid().as_raw()
    }

    /// An env over `base/{state,protected}/v1` owned end to end by
    /// the test euid — upstream's `genesisTestEnv` shape.
    fn test_env(base: &Path) -> GenesisEnv {
        GenesisEnv::test(
            &base.join("state/v1"),
            &base.join("protected/v1"),
            euid(),
            egid(),
        )
    }

    fn assert_dir(path: &Path, uid: u32, gid: u32, mode: u32) {
        let meta = std::fs::symlink_metadata(path).expect("stat dir");
        assert!(meta.is_dir(), "{} is not a directory", path.display());
        assert_eq!(meta.uid(), uid, "{} uid", path.display());
        assert_eq!(meta.gid(), gid, "{} gid", path.display());
        assert_eq!(meta.mode() & 0o7777, mode, "{} mode", path.display());
    }

    fn assert_file(path: &Path, uid: u32, gid: u32, mode: u32) {
        let meta = std::fs::symlink_metadata(path).expect("stat file");
        assert!(meta.is_file(), "{} is not a file", path.display());
        assert_eq!(meta.uid(), uid, "{} uid", path.display());
        assert_eq!(meta.gid(), gid, "{} gid", path.display());
        assert_eq!(meta.mode() & 0o7777, mode, "{} mode", path.display());
    }

    /// The complete T13 inventory assertion — upstream's exact
    /// hierarchy, owners, and modes under the test euid.
    fn assert_instance_inventory(env: &GenesisEnv, instance_id: &str) {
        let (uid, gid) = (euid(), egid());
        let state = env.roots.instances_root().join(instance_id);
        // The roots themselves.
        assert_dir(Path::new(&env.roots.state_root), uid, gid, 0o700);
        assert_dir(&env.roots.instances_root(), uid, gid, 0o700);
        assert_dir(Path::new(&env.roots.protected_root), uid, gid, 0o700);
        assert_dir(&env.roots.protected_instances_root(), uid, gid, 0o700);
        // The instance dir — runtime-owned after the hand-off (the
        // test env's runtime == euid).
        assert_dir(&state, uid, gid, 0o700);
        for dir in [
            "data",
            "data/postgres",
            "data/minio",
            "dependencies",
            "lifecycle",
        ] {
            assert_dir(&state.join(dir), uid, gid, 0o700);
        }
        assert_dir(&state.join("backups"), uid, gid, 0o700);
        // SC-DEF-31's repository contents.
        for file in [
            "backups/binding.json",
            "backups/backup-repository.lock",
            "backups/repository-manifest.json",
        ] {
            assert_file(&state.join(file), uid, gid, 0o600);
        }
        // The version-zero receipt is live.
        let candidate_store = CandidateStore::new(None, state.join("dependencies"));
        candidate_store
            .active(OpDeadline::NONE)
            .expect("version-zero dependency receipt resolves");
        // The protected side.
        let protected = env.roots.protected_instances_root().join(instance_id);
        assert_dir(&protected, uid, gid, 0o700);
        assert_dir(&protected.join("protected"), uid, gid, 0o700);
        // genesis.json root-owned 0600 (root == euid in the test env).
        assert_file(&state.join(GENESIS_RECORD_NAME), uid, gid, 0o600);
        // config.json runtime-owned 0600.
        assert_file(&state.join("config.json"), uid, gid, 0o600);
        // The lock file stays behind, root-owned 0600.
        assert_file(&env.roots.lock_path(), uid, gid, 0o600);
        // The temp config never leaks.
        assert!(
            state
                .join(GENESIS_CONFIG_TEMP_NAME)
                .symlink_metadata()
                .is_err()
        );
        // The real loaders see it: the production composition, the
        // broker's protected root, the record — `state()` itself is
        // the proof, but name each hop for the report.
        let composition = load_production_instance_composition_for_owner(
            &env.roots.instances_root().to_string_lossy(),
            uid,
            gid,
            uid,
            gid,
        )
        .expect("production composition resolves");
        assert_eq!(composition.instance_id, instance_id);
        production_broker_root_at(
            &composition,
            &env.roots.protected_instances_root().to_string_lossy(),
            uid,
            gid,
        )
        .expect("broker protected root resolves");
        let record = read_genesis_record(&state, uid, gid).expect("genesis record reads");
        assert_eq!(record.instance_id, instance_id);
    }

    fn uuidv7_canonical(id: &str) -> bool {
        match uuid::Uuid::parse_str(id) {
            Ok(u) => u.get_version() == Some(uuid::Version::SortRand) && u.to_string() == id,
            Err(_) => false,
        }
    }

    #[test]
    fn install_creates_the_exact_inventory_then_rerun_is_idempotent() {
        let base = scratch("inventory");
        let env = test_env(&base);
        // Absent first.
        let (state, _, err) = env.state();
        assert_eq!(state, GenesisState::Absent, "pre-state: {err:?}");
        let outcome = env
            .create(
                Instant::now() + Duration::from_secs(60),
                GENESIS_CEREMONY_PHYSICAL_TTY,
                "",
            )
            .expect("genesis installs");
        assert!(outcome.created);
        let record = &outcome.record;
        assert_eq!(record.schema_version, GENESIS_RECORD_SCHEMA);
        assert_eq!(record.ceremony, GENESIS_CEREMONY_PHYSICAL_TTY);
        assert!(record.grant_nonce.is_empty());
        for id in [
            &record.instance_id,
            &record.config_binding_id,
            &record.init_operation_id,
        ] {
            assert!(uuidv7_canonical(id), "id {id} is not a canonical UUIDv7");
        }
        assert_instance_inventory(&env, &record.instance_id);
        // The host is present afterwards.
        let (state, present, err) = env.state();
        assert_eq!(state, GenesisState::Present, "post-state: {err:?}");
        assert_eq!(present.unwrap().instance_id, record.instance_id);
        // The re-run is the no-op: created == false, identical IDs —
        // the wire layer turns this into ALREADY_INITIALIZED.
        let rerun = env
            .create(
                Instant::now() + Duration::from_secs(60),
                GENESIS_CEREMONY_PHYSICAL_TTY,
                "",
            )
            .expect("genesis re-run");
        assert!(!rerun.created, "re-run must not create");
        assert_eq!(&rerun.record, record);
        // The inventory is untouched by the re-run.
        assert_instance_inventory(&env, &record.instance_id);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn capacity_below_40gib_refuses_before_mutation() {
        let base = scratch("capacity");
        let mut env = test_env(&base);
        env.free_bytes = Arc::new(|_| Ok(1 << 30));
        let err = env
            .create(
                Instant::now() + Duration::from_secs(60),
                GENESIS_CEREMONY_PHYSICAL_TTY,
                "",
            )
            .expect_err("capacity must refuse");
        assert_eq!(err.failure, GenesisFailure::Capacity);
        // Nothing was written — not even the state root.
        assert!(!Path::new(&env.roots.state_root).exists());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn broken_host_protected_without_state_is_untouched() {
        let base = scratch("broken");
        let env = test_env(&base);
        // Plant a protected instance directory with no state peer —
        // upstream's "protected state has no state instance" broken
        // branch.
        let planted = env
            .roots
            .protected_instances_root()
            .join("00000000-0000-7000-8000-000000000000");
        // The whole protected chain at 0700, so the refusal is the
        // instance-pair branch upstream names, not an earlier
        // owner/mode gate.
        create_all_700(&planted);
        let (state, _, err) = env.state();
        assert_eq!(state, GenesisState::Broken);
        assert!(err.unwrap_or_default().contains("has no state instance"));
        let err = env
            .create(
                Instant::now() + Duration::from_secs(60),
                GENESIS_CEREMONY_PHYSICAL_TTY,
                "",
            )
            .expect_err("a broken host must refuse");
        assert_eq!(err.failure, GenesisFailure::Broken);
        // Genesis touched nothing.
        assert!(!env.roots.instances_root().exists());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn held_genesis_lock_times_out() {
        let base = scratch("lock");
        let mut env = test_env(&base);
        env.lock_wait = Duration::from_millis(150);
        // Pre-create the state root and hold the lock file.
        create_all_700(Path::new(&env.roots.state_root));
        let held = open(
            env.roots.lock_path(),
            OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .expect("open lock");
        flock(&held, rustix::fs::FlockOperation::LockExclusive).expect("hold lock");
        let err = env
            .create(
                Instant::now() + Duration::from_secs(60),
                GENESIS_CEREMONY_PHYSICAL_TTY,
                "",
            )
            .expect_err("a held lock must time out");
        assert_eq!(err.failure, GenesisFailure::LockTimeout);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn ensure_identity_argv_is_the_installers_exact_shape() {
        // D4: `groupadd --system --gid <id> <name>` then
        // `useradd --system --no-create-home --home-dir <home>
        // --shell <shell> --uid <id> --gid <id> <name>`, verbatim.
        for identity in &GENESIS_IDENTITIES {
            let [group, user] = ensure_identity_argv(identity);
            assert_eq!(
                group,
                vec![
                    "groupadd",
                    "--system",
                    "--gid",
                    identity.gid.to_string().as_str(),
                    identity.name
                ],
                "{} group argv",
                identity.name
            );
            assert_eq!(
                user,
                vec![
                    "useradd",
                    "--system",
                    "--no-create-home",
                    "--home-dir",
                    identity.home,
                    "--shell",
                    identity.shell,
                    "--uid",
                    identity.uid.to_string().as_str(),
                    "--gid",
                    identity.gid.to_string().as_str(),
                    identity.name
                ],
                "{} user argv",
                identity.name
            );
        }
        // The D4 set itself — runtime 501, agent 502, browser 503,
        // every identity locked no-login.
        let names: Vec<_> = GENESIS_IDENTITIES.iter().map(|i| i.name).collect();
        assert_eq!(
            names,
            ["central-runtime", "central-agent", "central-browser"]
        );
        for identity in &GENESIS_IDENTITIES {
            assert_eq!(identity.shell, "/usr/sbin/nologin");
            assert!(identity.uid != 0);
        }
    }

    #[test]
    fn ensure_locked_identities_creates_once_then_probes() {
        // A recording exec and a table-driven lookup — the D4
        // idempotency contract without touching the host's tables.
        let calls: Arc<Mutex<Vec<Vec<String>>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded = calls.clone();
        let exec: IdentityExec = Arc::new(move |argv| {
            recorded.lock().unwrap().push(argv.to_vec());
            Ok(())
        });
        let absent: IdentityLookup = Arc::new(|_, _| None);
        // Fresh host: every identity is provisioned — six argv calls
        // in domain order (group then user per identity).
        ensure_locked_identities_with(&absent, &exec).expect("provision");
        {
            let calls = calls.lock().unwrap();
            assert_eq!(calls.len(), GENESIS_IDENTITIES.len() * 2);
            for (i, identity) in GENESIS_IDENTITIES.iter().enumerate() {
                let [group, user] = ensure_identity_argv(identity);
                assert_eq!(calls[i * 2], group, "{} groupadd", identity.name);
                assert_eq!(calls[i * 2 + 1], user, "{} useradd", identity.name);
            }
        }
        // Fully provisioned host (the re-run): zero calls.
        let present: IdentityLookup = Arc::new(|_, _| Some("central-runtime".to_owned()));
        let calls2: Arc<Mutex<Vec<Vec<String>>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded2 = calls2.clone();
        let exec2: IdentityExec = Arc::new(move |argv| {
            recorded2.lock().unwrap().push(argv.to_vec());
            Ok(())
        });
        // The lookup must answer with each probed identity's own
        // name: build a name table instead of a blanket answer.
        let present: IdentityLookup = Arc::new(move |table, id| {
            let _ = present;
            GENESIS_IDENTITIES
                .iter()
                .find(|i| (table == "uid" && i.uid == id) || (table == "gid" && i.gid == id))
                .map(|i| i.name.to_owned())
        });
        ensure_locked_identities_with(&present, &exec2).expect("re-run");
        assert!(
            calls2.lock().unwrap().is_empty(),
            "idempotent re-run exec'd"
        );
        // A uid owned by a *different* account re-runs the useradd —
        // upstream reports present only on the identity's own name.
        let foreign: IdentityLookup = Arc::new(|table, id| {
            if table == "gid" {
                GENESIS_IDENTITIES
                    .iter()
                    .find(|i| i.gid == id)
                    .map(|i| i.name.to_owned())
            } else {
                Some("someone-else".to_owned())
            }
        });
        ensure_locked_identities_with(&foreign, &exec2).expect("foreign owner");
        assert_eq!(calls2.lock().unwrap().len(), GENESIS_IDENTITIES.len());
        // An exec failure propagates and stops the walk.
        let failing: IdentityExec = Arc::new(|_| Err("useradd: boom".to_owned()));
        let err = ensure_locked_identities_with(&absent, &failing)
            .expect_err("exec failure must surface");
        assert_eq!(err, "useradd: boom");
    }

    #[test]
    fn genesis_record_gate_validates_every_field() {
        let base = scratch("record");
        let env = test_env(&base);
        let outcome = env
            .create(
                Instant::now() + Duration::from_secs(60),
                GENESIS_CEREMONY_PHYSICAL_TTY,
                "",
            )
            .expect("genesis");
        let state_root = env.roots.instances_root().join(&outcome.record.instance_id);
        // Round-trip through the strict reader.
        let record = read_genesis_record(&state_root, euid(), egid()).expect("round-trip");
        assert_eq!(record, outcome.record);
        // A wrong-owner read refuses (nobody's uid, practically
        // unreachable — the refusal is owner-exact).
        assert!(read_genesis_record(&state_root, euid(), egid().wrapping_add(1)).is_err());
        // Trailing data refuses.
        let record_path = state_root.join(GENESIS_RECORD_NAME);
        let mut tampered = std::fs::read(&record_path).unwrap();
        tampered.extend_from_slice(b" {}");
        let _ = std::fs::remove_file(&record_path);
        std::fs::write(&record_path, &tampered).unwrap();
        assert!(read_genesis_record(&state_root, euid(), egid()).is_err());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn genesis_available_bytes_and_nearest_existing_path() {
        assert_eq!(genesis_available_bytes(4, 4096).unwrap(), 16384);
        assert!(genesis_available_bytes(4, 0).is_err());
        assert!(genesis_available_bytes(4, -2).is_err());
        assert!(genesis_available_bytes(u64::MAX, 4096).is_err());
        let base = scratch("nearest");
        let deep = base.join("a/b/c");
        assert_eq!(nearest_existing_path(&deep), base);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn empty_genesis_root_classification() {
        let base = scratch("empty");
        let (uid, gid) = (euid(), egid());
        // Missing → empty.
        let missing = base.join("missing");
        assert!(empty_genesis_root_or_missing(&missing, uid, gid).unwrap());
        // A non-directory refuses.
        let file = base.join("file");
        std::fs::write(&file, b"x").unwrap();
        assert!(empty_genesis_root_or_missing(&file, uid, gid).is_err());
        // A wrong-mode directory refuses — 0755 fails the exact-0700
        // gate.
        let loose = base.join("loose");
        std::fs::create_dir(&loose).unwrap();
        assert!(empty_genesis_root_or_missing(&loose, uid, gid).is_err());
        // An exact, non-empty root reports non-empty.
        let full = base.join("full");
        std::fs::create_dir(&full).unwrap();
        rustix::fs::chmod(&full, Mode::from_raw_mode(0o700)).unwrap();
        std::fs::write(full.join("entry"), b"x").unwrap();
        assert!(!empty_genesis_root_or_missing(&full, uid, gid).unwrap());
        // The ancestor rule: group-writable is refused.
        let group_w = base.join("groupw");
        std::fs::create_dir(&group_w).unwrap();
        rustix::fs::chmod(&group_w, Mode::from_raw_mode(0o770)).unwrap();
        assert!(genesis_ancestor_missing_or_root_owned(&group_w, uid).is_err());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn state_absent_on_fresh_roots_and_malformed_entries_break() {
        let base = scratch("state");
        let env = test_env(&base);
        // Nothing exists → absent.
        assert_eq!(env.state().0, GenesisState::Absent);
        // Empty exact roots → still absent. The protected root needs
        // its `0700` exactness, so chmod the whole created chain.
        for root in [
            env.roots.instances_root(),
            env.roots.protected_instances_root(),
        ] {
            create_all_700(&root);
        }
        let (dbg_state, _, dbg_err) = env.state();
        assert_eq!(dbg_state, GenesisState::Absent, "post-roots: {dbg_err:?}");
        // A non-uuid entry under the state instances root is broken,
        // never mistaken for absent.
        let state_entry = env.roots.instances_root().join("not-a-uuid");
        std::fs::create_dir(&state_entry).unwrap();
        assert_eq!(env.state().0, GenesisState::Broken);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn genesis_record_json_gate() {
        // The strict reader's field-level refusals, exercised through
        // the on-disk shape directly.
        let base = scratch("json-gate");
        let dir = base.join("instance");
        std::fs::create_dir(&dir).unwrap();
        let write_record = |raw: &str| {
            let path = dir.join(GENESIS_RECORD_NAME);
            if path.exists() {
                std::fs::remove_file(&path).unwrap();
            }
            std::fs::write(&path, raw).unwrap();
            // 0600 + euid-owned, matching the gate.
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        };
        let id1 = uuid::Uuid::now_v7().to_string();
        let id2 = uuid::Uuid::now_v7().to_string();
        let id3 = uuid::Uuid::now_v7().to_string();
        let good = format!(
            r#"{{"schema_version":"central.genesis/v1","instance_id":"{id1}","config_binding_id":"{id2}","init_operation_id":"{id3}","created_at":"2026-10-23T00:00:00Z","ceremony":"physical_tty"}}"#
        );
        write_record(&good);
        assert!(read_genesis_record(&dir, euid(), egid()).is_ok());
        for (label, raw) in [
            ("unknown schema", good.replace("central.genesis/v1", "x/v9")),
            ("unknown ceremony", good.replace("physical_tty", "ssh")),
            (
                "non-v7 instance id",
                good.replace(&id1, &uuid::Uuid::new_v4().to_string()),
            ),
            (
                "bad created_at",
                good.replace("2026-10-23T00:00:00Z", "not-a-time"),
            ),
            (
                "nonce on non-grant",
                good.replace(
                    "\"ceremony\":\"physical_tty\"",
                    "\"ceremony\":\"physical_tty\",\"grant_nonce\":\"abc\"",
                ),
            ),
            (
                "malformed grant nonce",
                good.replace(
                    "\"ceremony\":\"physical_tty\"",
                    "\"ceremony\":\"grant\",\"grant_nonce\":\"abc\"",
                ),
            ),
            ("trailing data", format!("{good}}}{{")),
        ] {
            write_record(&raw);
            assert!(
                read_genesis_record(&dir, euid(), egid()).is_err(),
                "{label} must refuse"
            );
        }
        let _ = std::fs::remove_dir_all(&base);
    }
}
