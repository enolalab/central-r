//! Compile-time-fixed daemon identity — production constants live
//! here; `test-build`-only `CML_TEST_*` environment overrides mirror
//! upstream's `-DSOCKET_PATH`/`-DCENTRAL_LAUNCHER_TEST_PEER_UID` …
//! build defines. A production binary reads none of the environment:
//! every accessor is a constant behind `#[cfg(not(feature =
//! "test-build"))]`, so no `CML_TEST_*` name reaches it.

/// `SOCKET_PATH` — the launcher seqpacket socket the helper dials.
#[cfg(not(feature = "test-build"))]
pub const SOCKET_PATH: &str = "/run/central/migration-launcher.sock";

/// `MIGRATE_PATH` — the only executable the launcher may `exec`.
#[cfg(not(feature = "test-build"))]
pub const MIGRATE_PATH: &str = "/usr/lib/central/central-migrate";

/// `CENTRAL_MIGRATE_UID`.
#[cfg(not(feature = "test-build"))]
pub const MIGRATE_UID: u32 = 986;
/// `CENTRAL_MIGRATE_GID`.
#[cfg(not(feature = "test-build"))]
pub const MIGRATE_GID: u32 = 986;

/// `LAUNCH_TIMEOUT_SECONDS`.
#[cfg(not(feature = "test-build"))]
pub const LAUNCH_TIMEOUT_S: u64 = 30;

/// `REQUIRED_PEER_UID` — only root may dial the launcher.
#[cfg(not(feature = "test-build"))]
pub const REQUIRED_PEER_UID: u32 = 0;

/// The permit files the daemon must hold open for the process's whole
/// life — the offline-mutation gate upstream opens at startup and
/// hands to no child until launch.
#[cfg(not(feature = "test-build"))]
pub const PERMIT_PATHS: [&str; 2] = [
    "/run/central/offline-mutation-1.lock",
    "/run/central/offline-mutation-2.lock",
];

/// `PERMIT_OWNER_UID`/`PERMIT_OWNER_GID` — the permits are the root
/// identity's own files in production.
#[cfg(not(feature = "test-build"))]
pub const PERMIT_UID: u32 = 0;
/// See [`PERMIT_UID`].
#[cfg(not(feature = "test-build"))]
pub const PERMIT_GID: u32 = 0;

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

/// The daemon's socket path — `CML_TEST_SOCKET` in a test build.
#[cfg(feature = "test-build")]
pub fn socket_path() -> String {
    env("CML_TEST_SOCKET").unwrap_or_else(|| "/run/central/migration-launcher.sock".to_owned())
}

/// The migration executable path — `CML_TEST_MIGRATE_PATH`.
#[cfg(feature = "test-build")]
pub fn migrate_path() -> String {
    env("CML_TEST_MIGRATE_PATH").unwrap_or_else(|| "/usr/lib/central/central-migrate".to_owned())
}

/// The operator's target uid — `CML_TEST_MIGRATE_UID`.
#[cfg(feature = "test-build")]
pub fn migrate_uid() -> u32 {
    env_u32("CML_TEST_MIGRATE_UID", 986)
}

/// The operator's target gid — `CML_TEST_MIGRATE_GID`.
#[cfg(feature = "test-build")]
pub fn migrate_gid() -> u32 {
    env_u32("CML_TEST_MIGRATE_GID", 986)
}

/// The uncommitted-launch timeout — `CML_TEST_TIMEOUT_S`.
#[cfg(feature = "test-build")]
pub fn launch_timeout_s() -> u64 {
    env_u64("CML_TEST_TIMEOUT_S", 30)
}

/// The admitted peer uid — `CML_TEST_PEER_UID` mirrors upstream's
/// `-DCENTRAL_LAUNCHER_TEST_PEER_UID` define: a test build admits the
/// tester's uid instead of root.
#[cfg(feature = "test-build")]
pub fn required_peer_uid() -> u32 {
    env_u32("CML_TEST_PEER_UID", 0)
}

/// Whether the `setgroups(0, NULL)` drop is compiled in — upstream
/// wraps only that one call in `#ifndef
/// CENTRAL_LAUNCHER_TEST_PEER_UID`; `setgid`/`setuid` run in every
/// build (a test build points `MIGRATE_UID`/`MIGRATE_GID` at the
/// tester through the uid/gid knobs).
#[cfg(feature = "test-build")]
pub fn test_peer_build() -> bool {
    env("CML_TEST_PEER_UID").is_some()
}

/// The two permit paths — `CML_TEST_PERMIT_A`/`CML_TEST_PERMIT_B`.
#[cfg(feature = "test-build")]
pub fn permit_paths() -> [String; 2] {
    [
        env("CML_TEST_PERMIT_A")
            .unwrap_or_else(|| "/run/central/offline-mutation-1.lock".to_owned()),
        env("CML_TEST_PERMIT_B")
            .unwrap_or_else(|| "/run/central/offline-mutation-2.lock".to_owned()),
    ]
}

/// The permit owner uid — `CML_TEST_PERMIT_UID`.
#[cfg(feature = "test-build")]
pub fn permit_uid() -> u32 {
    env_u32("CML_TEST_PERMIT_UID", 0)
}

/// The permit owner gid — `CML_TEST_PERMIT_GID`.
#[cfg(feature = "test-build")]
pub fn permit_gid() -> u32 {
    env_u32("CML_TEST_PERMIT_GID", 0)
}
