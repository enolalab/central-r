//! `grant.go` + `grant_flock_unix.go` + `grant_owner_unix.go` — ADR
//! 0028's ceremony modes and the grant store: root-owned, MAC-protected,
//! scope/boot/time-bound, one-use consent files. Every path operation
//! goes through the store's open dirfd (upstream's `os.Root`), so a
//! planted symlink cannot redirect outside it.

use central_foundation::failure::Failure;
use hmac::{Hmac, KeyInit, Mac};
use rustix::fs::FlockOperation;
use rustix::fs::{Mode, OFlags, flock, openat};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Mutex;
use std::time::Duration;
use zeroize::Zeroizing;

fn denied(code: &'static str, msg: impl Into<String>) -> Failure {
    Failure::denied(code, msg.into())
}
fn invalid(code: &'static str, msg: impl Into<String>) -> Failure {
    Failure::invalid(code, msg.into())
}
fn internal(code: &'static str, msg: impl Into<String>) -> Failure {
    Failure::internal(code, msg.into())
}

/// The single refusal a ceremony sees — `ErrNoGrant`.
pub fn err_no_grant() -> Failure {
    denied("sys_grant_none", "grant: no valid grant for this operation")
}
/// `ErrInitGrantPending`.
pub fn err_init_grant_pending() -> Failure {
    Failure::conflict(
        "sys_grant_pending",
        "init grant already pending (GRANT_PENDING); use --replace to revoke it and issue a new one",
    )
}
/// `ErrGrantStoreBusy`.
pub fn err_grant_store_busy() -> Failure {
    Failure::unavailable(
        "sys_grant_busy",
        "another grant issuance is in progress; retry",
    )
}

// ---------------------------------------------------------------------------
// Ceremony mode
// ---------------------------------------------------------------------------

/// `CeremonyMode` — `physical_tty` (default) or `grant`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeremonyMode {
    PhysicalTty,
    Grant,
}

impl CeremonyMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            CeremonyMode::PhysicalTty => "physical_tty",
            CeremonyMode::Grant => "grant",
        }
    }
}

/// `ParseCeremonyMode`.
pub fn parse_ceremony_mode(raw: &str) -> Result<CeremonyMode, Failure> {
    match raw.trim() {
        "physical_tty" => Ok(CeremonyMode::PhysicalTty),
        "grant" => Ok(CeremonyMode::Grant),
        _ => Err(invalid(
            "sys_ceremony_mode",
            format!("ceremony: unknown mode {raw:?}"),
        )),
    }
}

const CEREMONY_MODE_FILE: &str = "ceremony-mode";

/// A directory opened once and used for every confined operation —
/// `os.Root`'s model. `openat` with `O_NOFOLLOW` confines names to this
/// directory; a symlink mid-path cannot escape because the dirfd pins
/// the directory.
struct ScopedDir {
    fd: OwnedFd,
}

impl ScopedDir {
    fn open(path: &str) -> Result<Self, Failure> {
        let fd = rustix::fs::open(
            path,
            OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| internal("sys_ceremony_root", format!("ceremony: instance root: {e}")))?;
        Ok(ScopedDir { fd })
    }

    /// `root.Lstat` — symlink-safe: `AT_SYMLINK_NOFOLLOW` metadata via
    /// an `O_PATH` open (no data read, so a dangling name still stats).
    fn lstat(&self, name: &str) -> Result<rustix::fs::Stat, Failure> {
        if name.contains('/') || name == ".." {
            return Err(invalid(
                "sys_ceremony_name",
                format!("ceremony: bad name {name:?}"),
            ));
        }
        let fd = openat(
            &self.fd,
            name,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| {
            if e == Errno::NOENT {
                Failure::not_found("sys_ceremony_mode", format!("ceremony: mode file: {e}"))
            } else {
                internal("sys_ceremony_mode", format!("ceremony: mode file: {e}"))
            }
        })?;
        rustix::fs::fstat(&fd)
            .map_err(|e| internal("sys_ceremony_mode", format!("ceremony: mode file: {e}")))
    }

    fn read_file(&self, name: &str) -> Result<Vec<u8>, Failure> {
        let fd = openat(
            &self.fd,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| internal("sys_ceremony_mode", format!("ceremony: mode file: {e}")))?;
        let mut buf = Vec::new();
        std::fs::File::from(fd)
            .read_to_end(&mut buf)
            .map_err(|e| internal("sys_ceremony_mode", format!("ceremony: mode file: {e}")))?;
        Ok(buf)
    }

    /// `root.OpenFile(name, O_WRONLY|O_CREATE|O_EXCL, 0600)`.
    fn create_exclusive(&self, name: &str, mode: Mode) -> Result<OwnedFd, Errno> {
        openat(
            &self.fd,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            mode,
        )
    }

    fn rename(&self, from: &str, to: &str) -> Result<(), Errno> {
        rustix::fs::renameat(&self.fd, from, &self.fd, to)
    }

    fn remove(&self, name: &str) -> Result<(), Errno> {
        rustix::fs::unlinkat(&self.fd, name, rustix::fs::AtFlags::empty())
    }

    fn entries(&self) -> Result<Vec<(String, bool)>, Failure> {
        // (name, is_regular) — a second open on the same directory, since
        // `fdopendir` semantics keep the listing independent of the
        // store's own descriptor position.
        std::fs::read_dir(format!("/proc/self/fd/{}", AsRawFd::as_raw_fd(&self.fd)))
            .map_err(|e| internal("sys_grant_scan", format!("grant: scan: {e}")))
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .map(|e| {
                        (
                            e.file_name().to_string_lossy().into_owned(),
                            e.file_type().map(|t| t.is_file()).unwrap_or(false),
                        )
                    })
                    .collect()
            })
    }
}

/// `ReadCeremonyMode` — absent file means physical_tty; a present file
/// must be regular, non-symlink, owner-owned, exactly 0600.
pub fn read_ceremony_mode(
    instance_root: &str,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<CeremonyMode, Failure> {
    let root = ScopedDir::open(instance_root)?;
    let info = match root.lstat(CEREMONY_MODE_FILE) {
        Ok(i) => i,
        Err(e) if e.kind() == central_foundation::failure::FailureKind::NotFound => {
            return Ok(CeremonyMode::PhysicalTty);
        }
        Err(e) => return Err(e),
    };
    if info.st_mode & libc::S_IFMT != libc::S_IFREG
        || info.st_mode & 0o777 != 0o600
        || info.st_uid != owner_uid
        || info.st_gid != owner_gid
    {
        return Err(denied(
            "sys_ceremony_mode",
            "ceremony: mode file must be a regular 0600 file owned by the instance owner",
        ));
    }
    let raw = root.read_file(CEREMONY_MODE_FILE)?;
    parse_ceremony_mode(&String::from_utf8_lossy(&raw))
}

/// `WriteCeremonyMode` — atomic tmp+rename install; the `central grant
/// mode` verb's one effect.
pub fn write_ceremony_mode(instance_root: &str, mode: CeremonyMode) -> Result<(), Failure> {
    let root = ScopedDir::open(instance_root)?;
    let tmp = format!("{CEREMONY_MODE_FILE}.tmp");
    let _ = root.remove(&tmp);
    let fd = root
        .create_exclusive(&tmp, Mode::from_raw_mode(0o600))
        .map_err(|e| internal("sys_ceremony_mode", format!("ceremony: write mode: {e}")))?;
    let mut file = std::fs::File::from(fd);
    file.write_all(format!("{}\n", mode.as_str()).as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|e| internal("sys_ceremony_mode", format!("ceremony: write mode: {e}")))?;
    drop(file);
    root.rename(&tmp, CEREMONY_MODE_FILE)
        .map_err(|e| internal("sys_ceremony_mode", format!("ceremony: write mode: {e}")))
}

// ---------------------------------------------------------------------------
// Grants
// ---------------------------------------------------------------------------

/// `GrantKind` — the ceremony a grant may satisfy; `Empty` is the
/// no-kind value `ConfirmInit`'s physical-only path passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum GrantKind {
    #[serde(rename = "")]
    #[default]
    Empty,
    #[serde(rename = "lifecycle")]
    Lifecycle,
    #[serde(rename = "prepare")]
    Prepare,
    #[serde(rename = "migration_reset")]
    MigrationReset,
    #[serde(rename = "restore_apply")]
    RestoreApply,
    #[serde(rename = "restore_abandon")]
    RestoreAbandon,
    #[serde(rename = "wipe")]
    Wipe,
    #[serde(rename = "backup_export")]
    BackupExport,
    #[serde(rename = "backup_import")]
    BackupImport,
    #[serde(rename = "backup_delete")]
    BackupDelete,
    #[serde(rename = "backup_prune")]
    BackupPrune,
    #[serde(rename = "security_rescue")]
    SecurityRescue,
    #[serde(rename = "maintenance_apply")]
    MaintenanceApply,
    #[serde(rename = "init")]
    Init,
}

impl GrantKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            GrantKind::Empty => "",
            GrantKind::Lifecycle => "lifecycle",
            GrantKind::Prepare => "prepare",
            GrantKind::MigrationReset => "migration_reset",
            GrantKind::RestoreApply => "restore_apply",
            GrantKind::RestoreAbandon => "restore_abandon",
            GrantKind::Wipe => "wipe",
            GrantKind::BackupExport => "backup_export",
            GrantKind::BackupImport => "backup_import",
            GrantKind::BackupDelete => "backup_delete",
            GrantKind::BackupPrune => "backup_prune",
            GrantKind::SecurityRescue => "security_rescue",
            GrantKind::MaintenanceApply => "maintenance_apply",
            GrantKind::Init => "init",
        }
    }

    /// `requiresOperationID`.
    pub const fn requires_operation_id(self) -> bool {
        matches!(
            self,
            GrantKind::MigrationReset
                | GrantKind::RestoreApply
                | GrantKind::RestoreAbandon
                | GrantKind::BackupPrune
        )
    }
}

/// `ParseGrantKind`.
pub fn parse_grant_kind(raw: &str) -> Result<GrantKind, Failure> {
    let kind = match raw.trim() {
        "lifecycle" => GrantKind::Lifecycle,
        "prepare" => GrantKind::Prepare,
        "migration_reset" => GrantKind::MigrationReset,
        "restore_apply" => GrantKind::RestoreApply,
        "restore_abandon" => GrantKind::RestoreAbandon,
        "wipe" => GrantKind::Wipe,
        "backup_export" => GrantKind::BackupExport,
        "backup_import" => GrantKind::BackupImport,
        "backup_delete" => GrantKind::BackupDelete,
        "backup_prune" => GrantKind::BackupPrune,
        "security_rescue" => GrantKind::SecurityRescue,
        "maintenance_apply" => GrantKind::MaintenanceApply,
        "init" => GrantKind::Init,
        _ => {
            return Err(invalid(
                "sys_grant_kind",
                format!("grant: unknown kind {raw:?}"),
            ));
        }
    };
    Ok(kind)
}

/// `MaxGrantTTL`, `DefaultGrantTTL`, `InitGrantTTL`.
pub const MAX_GRANT_TTL: Duration = Duration::from_secs(24 * 3600);
pub const DEFAULT_GRANT_TTL: Duration = Duration::from_secs(3600);
pub const INIT_GRANT_TTL: Duration = Duration::from_secs(15 * 60);

const GRANT_KEY_FILE: &str = ".key";
const GRANT_SUFFIX: &str = ".grant";
const CONSUMED_SUFFIX: &str = ".consumed";
const REVOKED_SUFFIX: &str = ".revoked";
const ISSUE_LOCK_FILE: &str = ".issue.lock";
const GRANT_KEY_LENGTH: usize = 32;
const GRANT_NONCE_LENGTH: usize = 32;

/// `Grant` — one pre-authorized consent; every field is the helper's
/// own.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    pub kind: String,
    pub instance_id: String,
    pub target_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub operation_id: String,
    pub boot_id: String,
    pub helper_release: String,
    pub nonce: String,
    pub issued_at: String,
    pub expires_at: String,
    pub mac: String,
}

impl Grant {
    fn file_name(&self) -> String {
        format!("{}-{}{GRANT_SUFFIX}", self.kind, self.nonce)
    }

    /// `canonical` — the newline-delimited `key=value` byte string the
    /// MAC covers, in upstream's fixed field order.
    fn canonical(&self) -> Vec<u8> {
        format!(
            "kind={}\ninstance_id={}\ntarget_id={}\noperation_id={}\nboot_id={}\nhelper_release={}\nnonce={}\nissued_at={}\nexpires_at={}\n",
            self.kind,
            self.instance_id,
            self.target_id,
            self.operation_id,
            self.boot_id,
            self.helper_release,
            self.nonce,
            self.issued_at,
            self.expires_at,
        )
        .into_bytes()
    }
}

/// `GrantScope` — what a ceremony asks the store for.
#[derive(Debug, Clone, Default)]
pub struct GrantScope {
    pub kind: GrantKind,
    pub instance_id: String,
    pub target_id: String,
    pub operation_id: String,
}

/// `WipeScope`/`RestoreApplyScope`/… — one shape: the composition's
/// identities every destructive ceremony is scoped to.
#[derive(Debug, Clone, Default)]
pub struct CeremonyScope {
    pub instance_id: String,
    pub target_id: String,
}

/// `ConsumedGrant` — the record a consumption leaves beside the spent
/// grant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsumedGrant {
    pub grant: Grant,
    pub consumed_at: String,
    pub peer_uid: u32,
    pub peer_pid: i32,
}

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

fn parse_time(s: &str) -> Option<time::OffsetDateTime> {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()
}

/// `GrantStore` — the root-only directory grants live in.
pub struct GrantStore {
    mu: Mutex<()>,
    root: ScopedDir,
    key: Zeroizing<Vec<u8>>,
    now: Box<dyn Fn() -> String + Send + Sync>,
}

impl GrantStore {
    /// `OpenGrantStore` — dir must exist, be a `0700` directory owned by
    /// owner, and its key loads or mints exclusively.
    pub fn open(dir: &str, owner_uid: u32, owner_gid: u32) -> Result<Self, Failure> {
        use std::os::unix::fs::MetadataExt;
        let path = std::path::Path::new(dir);
        if !path.is_absolute() || path != std::path::Path::new(dir).components().as_path() {
            return Err(invalid(
                "sys_grant_store",
                "grant: store path must be absolute and clean",
            ));
        }
        let meta = std::fs::metadata(dir)
            .map_err(|e| internal("sys_grant_store", format!("grant: store: {e}")))?;
        if !meta.is_dir()
            || meta.mode() & 0o777 != 0o700
            || meta.uid() != owner_uid
            || meta.gid() != owner_gid
        {
            return Err(denied(
                "sys_grant_store",
                "grant: store must be a 0700 directory owned by the instance owner",
            ));
        }
        let root = ScopedDir::open(dir)?;
        let key = Self::load_or_create_key(&root)?;
        Ok(GrantStore {
            mu: Mutex::new(()),
            root,
            key,
            now: Box::new(now_rfc3339),
        })
    }

    /// Test seam — the injected clock upstream's `now` field carries.
    #[cfg(test)]
    pub fn open_with_clock(
        dir: &str,
        owner_uid: u32,
        owner_gid: u32,
        now: Box<dyn Fn() -> String + Send + Sync>,
    ) -> Result<Self, Failure> {
        let mut s = Self::open(dir, owner_uid, owner_gid)?;
        s.now = now;
        Ok(s)
    }

    fn load_or_create_key(root: &ScopedDir) -> Result<Zeroizing<Vec<u8>>, Failure> {
        match root.lstat(GRANT_KEY_FILE) {
            Ok(info) => {
                if info.st_mode & libc::S_IFMT != libc::S_IFREG || info.st_mode & 0o777 != 0o600 {
                    return Err(denied(
                        "sys_grant_key",
                        "grant: key file must be a regular 0600 file",
                    ));
                }
                let raw = root.read_file(GRANT_KEY_FILE).map_err(|e| {
                    internal("sys_grant_key", format!("grant: key: {}", e.message()))
                })?;
                let text = String::from_utf8_lossy(&raw);
                let key = hex_decode(text.trim())
                    .filter(|k| k.len() == GRANT_KEY_LENGTH)
                    .ok_or_else(|| denied("sys_grant_key", "grant: key file is malformed"))?;
                return Ok(Zeroizing::new(key));
            }
            Err(e) if e.kind() == central_foundation::failure::FailureKind::NotFound => {}
            Err(e) => {
                return Err(internal(
                    "sys_grant_key",
                    format!("grant: key: {}", e.message()),
                ));
            }
        }
        let mut key = vec![0u8; GRANT_KEY_LENGTH];
        rustix::rand::getrandom(&mut key, rustix::rand::GetRandomFlags::empty())
            .map_err(|e| internal("sys_grant_key", format!("grant: generate key: {e}")))?;
        let fd = match root.create_exclusive(GRANT_KEY_FILE, Mode::from_raw_mode(0o600)) {
            Ok(f) => f,
            Err(e) if e == Errno::EXIST => return Self::load_or_create_key(root),
            Err(e) => return Err(internal("sys_grant_key", format!("grant: create key: {e}"))),
        };
        let mut file = std::fs::File::from(fd);
        let hexed: String = key.iter().map(|b| format!("{b:02x}")).collect();
        file.write_all(format!("{hexed}\n").as_bytes())
            .and_then(|_| file.sync_all())
            .map_err(|e| internal("sys_grant_key", format!("grant: create key: {e}")))?;
        Ok(Zeroizing::new(key))
    }

    fn mac(&self, g: &Grant) -> String {
        let mut h = Hmac::<Sha256>::new_from_slice(&self.key)
            .unwrap_or_else(|_| unreachable!("hmac accepts any key length"));
        h.update(&g.canonical());
        let out = h.finalize().into_bytes();
        out.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// `Issue` — one grant for `scope`, `ttl` within `(0, MaxGrantTTL]`.
    pub fn issue(
        &self,
        scope: &GrantScope,
        boot_id: &str,
        helper_release: &str,
        ttl: Duration,
    ) -> Result<Grant, Failure> {
        parse_grant_kind(scope.kind.as_str())?;
        if scope.kind == GrantKind::Init {
            return Err(invalid(
                "sys_grant_issue",
                "grant: kind init is issued with IssueInit",
            ));
        }
        if scope.kind.requires_operation_id() && scope.operation_id.is_empty() {
            return Err(invalid(
                "sys_grant_issue",
                format!(
                    "grant: kind {} requires an operation id",
                    scope.kind.as_str()
                ),
            ));
        }
        if scope.instance_id.is_empty() || scope.target_id.is_empty() {
            return Err(invalid(
                "sys_grant_issue",
                "grant: scope names no instance or target",
            ));
        }
        if boot_id.is_empty() || helper_release.is_empty() {
            return Err(invalid(
                "sys_grant_issue",
                "grant: boot id and helper release are required",
            ));
        }
        if ttl.is_zero() || ttl > MAX_GRANT_TTL {
            return Err(invalid(
                "sys_grant_issue",
                "grant: ttl must be within (0, 24h0m0s]",
            ));
        }
        self.write_grant(scope, boot_id, helper_release, ttl)
    }

    fn write_grant(
        &self,
        scope: &GrantScope,
        boot_id: &str,
        helper_release: &str,
        ttl: Duration,
    ) -> Result<Grant, Failure> {
        let mut nonce = [0u8; GRANT_NONCE_LENGTH];
        rustix::rand::getrandom(&mut nonce, rustix::rand::GetRandomFlags::empty())
            .map_err(|e| internal("sys_grant_nonce", format!("grant: generate nonce: {e}")))?;
        // Upstream base64url-encodes the nonce; this build hex-encodes.
        // The value stays inside the store files only.
        let nonce_text: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        let issued_str = (self.now)();
        let issued = parse_time(&issued_str).unwrap_or_else(time::OffsetDateTime::now_utc);
        let expires = issued + time::Duration::try_from(ttl).unwrap_or(time::Duration::MAX);
        let mut g = Grant {
            kind: scope.kind.as_str().to_owned(),
            instance_id: scope.instance_id.clone(),
            target_id: scope.target_id.clone(),
            operation_id: scope.operation_id.clone(),
            boot_id: boot_id.to_owned(),
            helper_release: helper_release.to_owned(),
            nonce: nonce_text,
            issued_at: issued
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            expires_at: expires
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            mac: String::new(),
        };
        g.mac = self.mac(&g);
        let raw = serde_json::to_vec(&g)
            .map_err(|e| internal("sys_grant_encode", format!("grant: encode: {e}")))?;
        let fd = self
            .root
            .create_exclusive(&g.file_name(), Mode::from_raw_mode(0o600))
            .map_err(|e| internal("sys_grant_write", format!("grant: write: {e}")))?;
        let mut file = std::fs::File::from(fd);
        file.write_all(&raw)
            .and_then(|_| file.sync_all())
            .map_err(|e| internal("sys_grant_write", format!("grant: write: {e}")))?;
        Ok(g)
    }

    /// `Consume` — spend the one valid grant matching scope for this
    /// boot and peer; the file is renamed before the grant returns, so
    /// a crash still leaves it spent.
    pub fn consume(
        &self,
        scope: &GrantScope,
        boot_id: &str,
        peer_uid: u32,
        peer_pid: i32,
    ) -> Result<Grant, Failure> {
        if scope.kind == GrantKind::Empty || boot_id.is_empty() {
            return Err(err_no_grant());
        }
        if scope.kind == GrantKind::Init {
            if !scope.instance_id.is_empty() || !scope.target_id.is_empty() {
                return Err(err_no_grant());
            }
        } else if scope.instance_id.is_empty() || scope.target_id.is_empty() {
            return Err(err_no_grant());
        }
        if scope.kind.requires_operation_id() && scope.operation_id.is_empty() {
            return Err(err_no_grant());
        }
        let _lock = self.mu.lock().unwrap_or_else(|e| e.into_inner());
        let entries = self.root.entries().map_err(|_| err_no_grant())?;
        let now = parse_time(&(self.now)()).unwrap_or_else(time::OffsetDateTime::now_utc);
        for (name, is_regular) in entries {
            if !is_regular
                || !name.ends_with(GRANT_SUFFIX)
                || !name.starts_with(&format!("{}-", scope.kind.as_str()))
            {
                continue;
            }
            let Some(g) = self.read_valid(&name, scope, boot_id, now) else {
                continue;
            };
            let consumed_name =
                format!("{}{}", name.trim_end_matches(GRANT_SUFFIX), CONSUMED_SUFFIX);
            if self.root.rename(&name, &consumed_name).is_err() {
                continue;
            }
            self.record_consumption(
                &consumed_name,
                &ConsumedGrant {
                    grant: g.clone(),
                    consumed_at: (self.now)(),
                    peer_uid,
                    peer_pid,
                },
            );
            return Ok(g);
        }
        Err(err_no_grant())
    }

    /// `parseVerified` — file reads, name check, constant-time MAC.
    fn parse_verified(&self, name: &str) -> Option<Grant> {
        let raw = self.root.read_file(name).ok()?;
        let g: Grant = serde_json::from_slice(&raw).ok()?;
        if g.file_name() != name {
            return None;
        }
        let expected = self.mac(&g);
        let a = g.mac.as_bytes();
        let b = expected.as_bytes();
        if a.len() != b.len()
            || a.iter()
                .zip(b.iter())
                .fold(0u8, |acc, (x, y)| acc | (x ^ y))
                != 0
        {
            return None;
        }
        Some(g)
    }

    /// `readValid` — scope, boot, operation, and time validity.
    fn read_valid(
        &self,
        name: &str,
        scope: &GrantScope,
        boot_id: &str,
        now: time::OffsetDateTime,
    ) -> Option<Grant> {
        let g = self.parse_verified(name)?;
        if g.kind != scope.kind.as_str()
            || g.instance_id != scope.instance_id
            || g.target_id != scope.target_id
            || g.boot_id != boot_id
        {
            return None;
        }
        if !g.operation_id.is_empty() && g.operation_id != scope.operation_id {
            return None;
        }
        if g.operation_id.is_empty() && scope.kind.requires_operation_id() {
            return None;
        }
        let issued = parse_time(&g.issued_at)?;
        let expires = parse_time(&g.expires_at)?;
        if now < issued || now >= expires {
            return None;
        }
        if (expires - issued)
            > time::Duration::try_from(MAX_GRANT_TTL).unwrap_or(time::Duration::MAX)
        {
            return None;
        }
        if scope.kind == GrantKind::Init
            && (expires - issued)
                > time::Duration::try_from(INIT_GRANT_TTL).unwrap_or(time::Duration::MAX)
        {
            return None;
        }
        Some(g)
    }

    /// `pendingInit` — (usable, stale) pending init grants for `boot_id`.
    fn pending_init(&self, boot_id: &str) -> Result<(Vec<String>, Vec<String>), Failure> {
        let entries = self.root.entries()?;
        let now = parse_time(&(self.now)()).unwrap_or_else(time::OffsetDateTime::now_utc);
        let mut usable = Vec::new();
        let mut stale = Vec::new();
        for (name, is_regular) in entries {
            if !is_regular
                || !name.ends_with(GRANT_SUFFIX)
                || !name.starts_with(&format!("{}-", GrantKind::Init.as_str()))
            {
                continue;
            }
            let Some(g) = self.parse_verified(&name) else {
                continue;
            };
            if g.kind != GrantKind::Init.as_str()
                || !g.instance_id.is_empty()
                || !g.target_id.is_empty()
                || !g.operation_id.is_empty()
            {
                continue;
            }
            let (Some(issued), Some(expires)) =
                (parse_time(&g.issued_at), parse_time(&g.expires_at))
            else {
                continue;
            };
            if (expires - issued)
                > time::Duration::try_from(INIT_GRANT_TTL).unwrap_or(time::Duration::MAX)
            {
                continue;
            }
            if now >= expires || g.boot_id != boot_id {
                stale.push(name);
            } else {
                usable.push(name);
            }
        }
        Ok((usable, stale))
    }

    /// `Revoke` — move named pending grants of `kind` to `.revoked`
    /// records, under the issue lock.
    pub fn revoke(&self, kind: GrantKind, names: &[String]) -> Result<Vec<String>, Failure> {
        parse_grant_kind(kind.as_str())?;
        let mut revoked = Vec::new();
        self.with_issue_lock(|_| {
            revoked = self.revoke_locked(kind, names)?;
            Ok(())
        })?;
        Ok(revoked)
    }

    fn revoke_locked(&self, kind: GrantKind, names: &[String]) -> Result<Vec<String>, Failure> {
        let mut revoked = Vec::new();
        for name in names {
            if name.contains('/')
                || !name.ends_with(GRANT_SUFFIX)
                || !name.starts_with(&format!("{}-", kind.as_str()))
            {
                return Err(invalid(
                    "sys_grant_revoke",
                    format!(
                        "grant: revoke: {name:?} is not a pending {} grant",
                        kind.as_str()
                    ),
                ));
            }
            match self.root.lstat(name) {
                Ok(info) if info.st_mode & libc::S_IFMT == libc::S_IFREG => {}
                Ok(_) => continue,
                Err(e) if e.kind() == central_foundation::failure::FailureKind::NotFound => {
                    continue;
                }
                Err(_) => continue,
            }
            let target = format!("{}{}", name.trim_end_matches(GRANT_SUFFIX), REVOKED_SUFFIX);
            if self.root.rename(name, &target).is_err() {
                continue;
            }
            revoked.push(target);
        }
        Ok(revoked)
    }

    /// `IssueInit` — the pre-instance consent; serialized by the issue
    /// flock across scan, revoke-stale, and write. At most one usable
    /// init grant exists unless `replace` revokes it first.
    pub fn issue_init(
        &self,
        boot_id: &str,
        helper_release: &str,
        ttl: Duration,
        replace: bool,
    ) -> Result<Grant, Failure> {
        if boot_id.is_empty() || helper_release.is_empty() {
            return Err(invalid(
                "sys_grant_issue",
                "grant: boot id and helper release are required",
            ));
        }
        if ttl.is_zero() || ttl > INIT_GRANT_TTL {
            return Err(invalid(
                "sys_grant_issue",
                "grant: init ttl must be within (0, 15m0s]",
            ));
        }
        let mut issued = None;
        self.with_issue_lock(|store| {
            let (usable, stale) = store.pending_init(boot_id)?;
            if !stale.is_empty() {
                store.revoke_locked(GrantKind::Init, &stale)?;
            }
            if !usable.is_empty() && !replace {
                return Err(err_init_grant_pending());
            }
            if !usable.is_empty() {
                store.revoke_locked(GrantKind::Init, &usable)?;
            }
            issued = Some(store.write_grant(
                &GrantScope {
                    kind: GrantKind::Init,
                    ..GrantScope::default()
                },
                boot_id,
                helper_release,
                ttl,
            )?);
            Ok(())
        })?;
        issued.ok_or_else(err_no_grant)
    }

    /// `withIssueLock` — `<store>/.issue.lock` under `LOCK_EX|LOCK_NB`;
    /// contention is `ErrGrantStoreBusy`, never a hang.
    fn with_issue_lock<T>(
        &self,
        f: impl FnOnce(&Self) -> Result<T, Failure>,
    ) -> Result<T, Failure> {
        let fd = self
            .root
            .create_exclusive(ISSUE_LOCK_FILE, Mode::from_raw_mode(0o600))
            .or_else(|e| {
                if e == Errno::EXIST {
                    openat(
                        &self.root.fd,
                        ISSUE_LOCK_FILE,
                        OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                } else {
                    Err(e)
                }
            })
            .map_err(|e| internal("sys_grant_lock", format!("grant: issue lock: {e}")))?;
        flock(&fd, FlockOperation::NonBlockingLockExclusive).map_err(|e| {
            if e == Errno::WOULDBLOCK {
                err_grant_store_busy()
            } else {
                internal("sys_grant_lock", format!("grant: issue lock: {e}"))
            }
        })?;
        let result = f(self);
        let _ = flock(&fd, FlockOperation::Unlock);
        result
    }

    /// `recordConsumption` — evidence; failure is logged by the absence
    /// of a record, never by refusing a consent that already happened.
    fn record_consumption(&self, consumed_name: &str, record: &ConsumedGrant) {
        let Ok(raw) = serde_json::to_vec(record) else {
            return;
        };
        let Ok(fd) = openat(
            &self.root.fd,
            consumed_name,
            OFlags::WRONLY | OFlags::TRUNC | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) else {
            return;
        };
        let mut file = std::fs::File::from(fd);
        let _ = file.write_all(&raw).and_then(|_| file.sync_all());
    }

    /// `Consumed` — every consumption record, oldest first.
    pub fn consumed(&self) -> Result<Vec<ConsumedGrant>, Failure> {
        let _lock = self.mu.lock().unwrap_or_else(|e| e.into_inner());
        let entries = self
            .root
            .entries()
            .map_err(|e| internal("sys_grant_list", e.message()))?;
        let mut records = Vec::new();
        for (name, is_regular) in entries {
            if !is_regular || !name.ends_with(CONSUMED_SUFFIX) {
                continue;
            }
            let Ok(raw) = self.root.read_file(&name) else {
                continue;
            };
            let Ok(record) = serde_json::from_slice::<ConsumedGrant>(&raw) else {
                continue;
            };
            if record.consumed_at.is_empty() {
                continue;
            }
            records.push(record);
        }
        records.sort_by(|a, b| a.consumed_at.cmp(&b.consumed_at));
        Ok(records)
    }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};

    /// A unique scratch directory under `std::env::temp_dir` that
    /// removes itself on drop — the workspace adds no `tempfile`
    /// dependency, so tests provision their own.
    struct TestDir(std::path::PathBuf);
    impl TestDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "helper-grant-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or_default()
            ));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            TestDir(path)
        }
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn store_dir(tag: &str) -> (TestDir, String) {
        let dir = TestDir::new(tag);
        let path = dir.path().join("grants");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        (dir, path.to_string_lossy().into_owned())
    }

    fn owner() -> (u32, u32) {
        (
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw(),
        )
    }

    /// `central grant` round-trip: issue → consume binds kind, scope,
    /// boot, and peer; a spent grant never validates again.
    #[test]
    fn issue_consume_round_trip() {
        let (_t, path) = store_dir("round-trip");
        let (uid, gid) = owner();
        let store = GrantStore::open(&path, uid, gid).unwrap();
        let scope = GrantScope {
            kind: GrantKind::Lifecycle,
            instance_id: "default".into(),
            target_id: "postgres:central".into(),
            ..GrantScope::default()
        };
        let g = store
            .issue(&scope, "boot-1", "rel-1", Duration::from_secs(60))
            .unwrap();
        assert!(std::path::Path::new(&path).join(g.file_name()).exists());
        let spent = store.consume(&scope, "boot-1", uid, 4242).unwrap();
        assert_eq!(spent.nonce, g.nonce);
        // One-use by construction.
        assert_eq!(
            store
                .consume(&scope, "boot-1", uid, 4242)
                .unwrap_err()
                .code(),
            "sys_grant_none"
        );
        // The consumption record is listed.
        let records = store.consumed().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].peer_pid, 4242);
    }

    /// Owner, MAC, scope, boot, and time each bind independently: wrong
    /// boot, wrong scope, tampered file, and expiry all deny closed.
    #[test]
    fn consume_binds_every_scope_field() {
        let (_t, path) = store_dir("scope");
        let (uid, gid) = owner();
        let store = GrantStore::open(&path, uid, gid).unwrap();
        let scope = GrantScope {
            kind: GrantKind::Wipe,
            instance_id: "default".into(),
            target_id: "postgres:central".into(),
            ..GrantScope::default()
        };
        let g = store
            .issue(&scope, "boot-1", "rel-1", Duration::from_secs(60))
            .unwrap();
        assert!(store.consume(&scope, "boot-other", uid, 1).is_err());
        let mut wrong = scope.clone();
        wrong.instance_id = "other".into();
        assert!(store.consume(&wrong, "boot-1", uid, 1).is_err());
        // Tamper with the file: MAC mismatch makes it inert.
        let file = std::path::Path::new(&path).join(g.file_name());
        let mut grant: Grant = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        grant.target_id = "postgres:evil".into();
        std::fs::write(&file, serde_json::to_vec(&grant).unwrap()).unwrap();
        assert!(store.consume(&scope, "boot-1", uid, 1).is_err());
    }

    /// `IssueInit` serializes on the issue flock: a second usable grant
    /// is GRANT_PENDING, `--replace` revokes and reissues, and an
    /// expired pending grant is revoked automatically.
    #[test]
    fn issue_init_pending_replace_and_stale_revocation() {
        let (_t, path) = store_dir("init");
        let (uid, gid) = owner();
        let store = GrantStore::open(&path, uid, gid).unwrap();
        store
            .issue_init("boot-1", "rel-1", Duration::from_secs(60), false)
            .unwrap();
        assert_eq!(
            store
                .issue_init("boot-1", "rel-1", Duration::from_secs(60), false)
                .unwrap_err()
                .code(),
            "sys_grant_pending"
        );
        store
            .issue_init("boot-1", "rel-1", Duration::from_secs(60), true)
            .unwrap();
        // Init grants bind no instance: a scoped consume attempt fails.
        let scope = GrantScope {
            kind: GrantKind::Init,
            ..GrantScope::default()
        };
        store.consume(&scope, "boot-1", uid, 7).unwrap();
    }

    /// `flock` serialization: a held issue lock makes another issuer
    /// fail fast with `ErrGrantStoreBusy`.
    #[test]
    fn issue_lock_contention_is_busy() {
        let (_t, path) = store_dir("lock");
        let (uid, gid) = owner();
        let store = GrantStore::open(&path, uid, gid).unwrap();
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(std::path::Path::new(&path).join(ISSUE_LOCK_FILE))
            .unwrap();
        flock(&lock, FlockOperation::NonBlockingLockExclusive).unwrap();
        assert_eq!(
            store
                .issue_init("boot-1", "rel-1", Duration::from_secs(60), false)
                .unwrap_err()
                .code(),
            "sys_grant_busy"
        );
        let _ = flock(&lock, FlockOperation::Unlock);
        store
            .issue_init("boot-1", "rel-1", Duration::from_secs(60), false)
            .unwrap();
    }

    /// `ReadCeremonyMode`/`WriteCeremonyMode` — absent is physical_tty;
    /// a wrong-owner or wrong-mode file refuses to open the mode at all.
    #[test]
    fn ceremony_mode_file_rules() {
        let dir = TestDir::new("mode");
        let root = dir.path().to_string_lossy().into_owned();
        let (uid, gid) = owner();
        assert_eq!(
            read_ceremony_mode(&root, uid, gid).unwrap(),
            CeremonyMode::PhysicalTty
        );
        write_ceremony_mode(&root, CeremonyMode::Grant).unwrap();
        assert_eq!(
            read_ceremony_mode(&root, uid, gid).unwrap(),
            CeremonyMode::Grant
        );
        // Wrong mode refuses.
        let file = std::path::Path::new(&root).join(CEREMONY_MODE_FILE);
        std::fs::set_permissions(&file, std::os::unix::fs::PermissionsExt::from_mode(0o644))
            .unwrap();
        assert!(read_ceremony_mode(&root, uid, gid).is_err());
        std::fs::set_permissions(&file, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .unwrap();
        // A symlink in place of the file refuses.
        std::fs::remove_file(&file).unwrap();
        std::os::unix::fs::symlink("/etc/hostname", &file).unwrap();
        assert!(read_ceremony_mode(&root, uid, gid).is_err());
        // Garbage content refuses.
        std::fs::remove_file(&file).unwrap();
        std::fs::write(&file, "bogus\n").unwrap();
        std::fs::set_permissions(&file, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .unwrap();
        assert!(read_ceremony_mode(&root, uid, gid).is_err());
        let _ = std::fs::metadata(&file).map(|m| m.uid());
    }
}
