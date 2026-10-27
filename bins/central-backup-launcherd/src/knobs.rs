//! Compile-time-fixed daemon identity — production constants live
//! here; `test-build`-only `CBL_TEST_*` environment overrides mirror
//! upstream's `-DSOCKET_PATH`/`-DBACKUP_PATH`/
//! `-DCENTRAL_BACKUP_LAUNCHER_TEST_PEER_UID` … build defines. A
//! production binary reads none of the environment: every accessor is
//! a constant behind `#[cfg(not(feature = "test-build"))]`, so no
//! `CBL_TEST_*` name reaches it.

/// `SOCKET_PATH` — the launcher seqpacket socket the broker dials.
#[cfg(not(feature = "test-build"))]
pub const SOCKET_PATH: &str = "/run/central/backup-launcher.sock";

/// `BACKUP_PATH` — the only executable the launcher may `exec`.
#[cfg(not(feature = "test-build"))]
pub const BACKUP_PATH: &str = "/usr/lib/central/central-backup";

/// `BACKUP_UID`.
#[cfg(not(feature = "test-build"))]
pub const BACKUP_UID: u32 = 501;
/// `BACKUP_GID`.
#[cfg(not(feature = "test-build"))]
pub const BACKUP_GID: u32 = 501;

/// `LAUNCH_TIMEOUT_SECONDS` — the uncommitted-launch deadline.
#[cfg(not(feature = "test-build"))]
pub const LAUNCH_TIMEOUT_S: u64 = 30;

/// `RESULT_RETENTION_SECONDS` — how long a finished, waiterless
/// launch record remains inspectable.
#[cfg(not(feature = "test-build"))]
pub const RESULT_RETENTION_S: u64 = 300;

/// `BACKUP_DEADLINE_SECONDS` — a create-mode launch's hard deadline.
#[cfg(not(feature = "test-build"))]
pub const BACKUP_DEADLINE_S: u64 = 7200;

/// `PROBE_DEADLINE_SECONDS` — a probe-mode launch's hard deadline.
#[cfg(not(feature = "test-build"))]
pub const PROBE_DEADLINE_S: u64 = 300;

/// `CONNECTION_RECEIVE_TIMEOUT_MS` — the request receive window.
#[cfg(not(feature = "test-build"))]
pub const RECEIVE_TIMEOUT_MS: i64 = 100;

/// `REQUIRED_PEER_UID` — only root may dial the launcher.
#[cfg(not(feature = "test-build"))]
pub const REQUIRED_PEER_UID: u32 = 0;

/// `OFFLINE_PERMIT_LOCK_A_PATH`/`OFFLINE_PERMIT_LOCK_B_PATH` — the
/// offline-mutation permit pair each launch holds for its life.
#[cfg(not(feature = "test-build"))]
pub const PERMIT_PATHS: [&str; 2] = [
    "/run/central/offline-mutation-1.lock",
    "/run/central/offline-mutation-2.lock",
];

/// `OFFLINE_PERMIT_OWNER_UID`/`OFFLINE_PERMIT_OWNER_GID` — the
/// permits are the root identity's own files in production.
#[cfg(not(feature = "test-build"))]
pub const PERMIT_UID: u32 = 0;
/// See [`PERMIT_UID`].
#[cfg(not(feature = "test-build"))]
pub const PERMIT_GID: u32 = 0;

/// The loopback peer port the retained target-lock socket must be
/// connected to — upstream's `peer.sin_port != htons(55432)` check.
/// It is not a knob: upstream compiles no override for it, and the
/// PostgreSQL target lock is pinned to that port product-wide.
pub const RETAINED_PEER_PORT: u16 = 55432;

#[cfg(feature = "test-build")]
fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

#[cfg(feature = "test-build")]
fn env_u32(key: &str, default: u32) -> u32 {
    env(key)
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(default)
}

#[cfg(feature = "test-build")]
fn env_u64(key: &str, default: u64) -> u64 {
    env(key)
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

#[cfg(feature = "test-build")]
fn env_i64(key: &str, default: i64) -> i64 {
    env(key)
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(default)
}

/// The daemon's socket path — `CBL_TEST_SOCKET` in a test build.
#[cfg(feature = "test-build")]
pub fn socket_path() -> String {
    env("CBL_TEST_SOCKET").unwrap_or_else(|| "/run/central/backup-launcher.sock".to_owned())
}

/// The backup executable path — `CBL_TEST_BACKUP_PATH`.
#[cfg(feature = "test-build")]
pub fn backup_path() -> String {
    env("CBL_TEST_BACKUP_PATH").unwrap_or_else(|| "/usr/lib/central/central-backup".to_owned())
}

/// The worker/monitor target uid — `CBL_TEST_BACKUP_UID`.
#[cfg(feature = "test-build")]
pub fn backup_uid() -> u32 {
    env_u32("CBL_TEST_BACKUP_UID", 501)
}

/// The worker/monitor target gid — `CBL_TEST_BACKUP_GID`.
#[cfg(feature = "test-build")]
pub fn backup_gid() -> u32 {
    env_u32("CBL_TEST_BACKUP_GID", 501)
}

/// The uncommitted-launch timeout — `CBL_TEST_TIMEOUT_S`.
#[cfg(feature = "test-build")]
pub fn launch_timeout_s() -> u64 {
    env_u64("CBL_TEST_TIMEOUT_S", 30)
}

/// The finished-record retention — `CBL_TEST_RETENTION_S`.
#[cfg(feature = "test-build")]
pub fn result_retention_s() -> u64 {
    env_u64("CBL_TEST_RETENTION_S", 300)
}

/// The create-mode hard deadline — `CBL_TEST_BACKUP_DEADLINE_S`.
#[cfg(feature = "test-build")]
pub fn backup_deadline_s() -> u64 {
    env_u64("CBL_TEST_BACKUP_DEADLINE_S", 7200)
}

/// The probe-mode hard deadline — `CBL_TEST_PROBE_DEADLINE_S`.
#[cfg(feature = "test-build")]
pub fn probe_deadline_s() -> u64 {
    env_u64("CBL_TEST_PROBE_DEADLINE_S", 300)
}

/// The request receive window — `CBL_TEST_RECV_TIMEOUT_MS`.
#[cfg(feature = "test-build")]
pub fn receive_timeout_ms() -> i64 {
    env_i64("CBL_TEST_RECV_TIMEOUT_MS", 100)
}

/// The admitted peer uid — `CBL_TEST_PEER_UID` mirrors upstream's
/// `-DCENTRAL_BACKUP_LAUNCHER_TEST_PEER_UID` define: a test build
/// admits the tester's uid instead of root.
#[cfg(feature = "test-build")]
pub fn required_peer_uid() -> u32 {
    env_u32("CBL_TEST_PEER_UID", 0)
}

/// Whether the `setgroups(0, NULL)` drop is compiled in — upstream
/// wraps only that one call in `#ifndef
/// CENTRAL_BACKUP_LAUNCHER_TEST_PEER_UID`; `setgid`/`setuid` run in
/// every build (a test build points `BACKUP_UID`/`BACKUP_GID` at the
/// tester through the uid/gid knobs).
#[cfg(feature = "test-build")]
pub fn test_peer_build() -> bool {
    env("CBL_TEST_PEER_UID").is_some()
}

/// The two permit paths — `CBL_TEST_PERMIT_A`/`CBL_TEST_PERMIT_B`.
#[cfg(feature = "test-build")]
pub fn permit_paths() -> [String; 2] {
    [
        env("CBL_TEST_PERMIT_A")
            .unwrap_or_else(|| "/run/central/offline-mutation-1.lock".to_owned()),
        env("CBL_TEST_PERMIT_B")
            .unwrap_or_else(|| "/run/central/offline-mutation-2.lock".to_owned()),
    ]
}

/// The permit owner uid — `CBL_TEST_PERMIT_UID`.
#[cfg(feature = "test-build")]
pub fn permit_uid() -> u32 {
    env_u32("CBL_TEST_PERMIT_UID", 0)
}

/// The permit owner gid — `CBL_TEST_PERMIT_GID`.
#[cfg(feature = "test-build")]
pub fn permit_gid() -> u32 {
    env_u32("CBL_TEST_PERMIT_GID", 0)
}
