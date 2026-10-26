//! `internal/adapter/authority/helper` — the root helper: newline-JSON
//! over a socket-activated Unix listener, a closed operation matrix,
//! peer-credential admission, and the PAM/TTY/grant ceremonies (ADR 0023,
//! 0028). R5 task 8 ports the R5 slice; every later verb is registered
//! and answered `UNSUPPORTED_IN_THIS_SLICE`.
#![forbid(unsafe_code)]

pub mod audit;
pub mod browser;
pub mod browser_runtime;
pub mod client;
pub mod daemon;
pub mod grant;
pub mod init;
pub mod lifecycle;
pub mod matrix;
pub mod migration;
pub mod migration_launch;
pub mod pam_ceremony;
pub mod prepare;
pub mod protocol;
pub mod server;
pub mod tty_ceremony;

pub use matrix::{Matrix, Operation};
pub use protocol::{Request, Response};
pub use server::{PeerPolicy, Server, SocketPolicy};

/// `authority.HelperVerb` — the closed verb vocabulary, byte-exact.
pub mod verb {
    pub const INIT: &str = "init";
    pub const INIT_STATUS: &str = "init-status";
    pub const INIT_RESUME: &str = "init-resume";
    pub const INIT_ABANDON: &str = "init-abandon";
    pub const PREPARE: &str = "prepare";
    pub const SECURITY_UPDATE: &str = "security-update";
    pub const TRUST_INSTALL: &str = "trust-install";
    pub const BROWSER_OPEN: &str = "browser-open";
    pub const RUNTIME_STAGE: &str = "runtime-stage";
    pub const RUNTIME_START: &str = "runtime-start";
    pub const RUNTIME_STOP: &str = "runtime-stop";
    pub const UP: &str = "up";
    pub const DOWN: &str = "down";
    pub const STATUS: &str = "status";
    pub const DOCTOR: &str = "doctor";
    pub const WIPE: &str = "wipe";
    pub const BOOTSTRAP_SHOW: &str = "bootstrap-show";
    /// Upstream `HelperSecurityRescue` — `security-rescue-cleanup`.
    pub const SECURITY_RESCUE_CLEANUP: &str = "security-rescue-cleanup";
    pub const MIGRATE_LAUNCH: &str = "migrate-launch";
    pub const MIGRATE_READ_OUTCOME: &str = "migrate-read-outcome";
    pub const BACKUP_CREATE: &str = "backup-create";
    pub const BACKUP_VERIFY: &str = "backup-verify";
    pub const BACKUP_STATUS: &str = "backup-status";
    pub const RESTORE_VERIFY: &str = "restore-verify";
    pub const RESTORE_APPLY: &str = "restore-apply";
    pub const RESTORE_RESUME: &str = "restore-resume";
    pub const RESTORE_ABANDON: &str = "restore-abandon";
    pub const BACKUP_EXPORT: &str = "backup-export";
    pub const BACKUP_IMPORT: &str = "backup-import";
    pub const BACKUP_DELETE: &str = "backup-delete";
    pub const BACKUP_PRUNE: &str = "backup-prune";
    pub const STATE_AUDIT: &str = "state-audit";
    /// Upstream `HelperDenySafeRescue` — `security-rescue`.
    pub const SECURITY_RESCUE: &str = "security-rescue";
    pub const MAINTENANCE_PLAN: &str = "maintenance-plan";
    pub const MAINTENANCE_APPLY: &str = "maintenance-apply";
}

/// `authority.ErrDenied` — the collapsed authority refusal the browser
/// and bootstrap-show paths return; no detail crosses.
pub fn err_denied() -> central_foundation::failure::Failure {
    central_foundation::failure::Failure::denied("helper_authority_denied", "authority denied")
}

/// `authority.LifecycleAuthorizationRequest` — the complete scope bound
/// to a one-use lifecycle authorization before the helper may reach the
/// lifecycle service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleAuthorizationRequest {
    pub instance_id: String,
    pub operation: String,
    pub request_digest: String,
    pub peer_uid: u32,
    pub peer_pid: i32,
}

/// `authority.LifecycleAuthorization` — the broker-issued one-use claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleAuthorization {
    pub nonce: String,
    pub instance_id: String,
    pub operation: String,
    pub request_digest: String,
    pub peer_uid: u32,
    pub peer_pid: i32,
    pub caller_fingerprint: String,
    pub expires_at: String,
}

/// The kernel-reported socket peer, travelling where upstream's
/// `withLifecyclePeer` context value did: into every ceremony and
/// authorization binding. `pid <= 0` means unavailable — the same gate
/// `lifecyclePeerFromContext` applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerIdentity {
    pub uid: u32,
    pub gid: u32,
    pub pid: i32,
}

impl PeerIdentity {
    pub const fn available(&self) -> bool {
        self.pid > 0
    }
}

/// `/proc/sys/kernel/random/boot_id` — the binding nothing in userspace
/// can choose (upstream `readBootID`, `ReadBootID`).
pub fn read_boot_id() -> Result<String, central_foundation::failure::Failure> {
    let raw = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|e| {
        central_foundation::failure::Failure::internal(
            "helper_boot_id",
            format!("helper: read boot id: {e}"),
        )
    })?;
    let boot = raw.trim();
    if boot.is_empty() {
        return Err(central_foundation::failure::Failure::internal(
            "helper_boot_id",
            "helper: kernel reported an empty boot id",
        ));
    }
    Ok(boot.to_owned())
}
