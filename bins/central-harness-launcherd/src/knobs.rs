//! Test knobs (upstream chl.h): every `CHL_TEST_*` is a weakening of a
//! check, so none may reach a production binary — upstream compiles them
//! only into test builds, and so does this port: every name below is read
//! only under the `test-build` cargo feature. A production build has no
//! code path that reads any `CHL_TEST_*` variable.

#[cfg(feature = "test-build")]
mod imp {
    use std::ffi::OsString;
    use std::sync::OnceLock;

    fn env(name: &str) -> Option<OsString> {
        std::env::var_os(name).filter(|v| !v.is_empty())
    }

    fn env_u64(name: &str) -> Option<u64> {
        env(name)?.to_str()?.parse().ok()
    }

    /// `CHL_TEST_NO_ISOLATION` — the no-isolation build: fake cgroup,
    /// no namespaces/mounts/identity change (upstream -DCHL_TEST_NO_ISOLATION).
    pub fn no_isolation() -> bool {
        static V: OnceLock<bool> = OnceLock::new();
        *V.get_or_init(|| env("CHL_TEST_NO_ISOLATION").is_some())
    }

    /// `CHL_TEST_VALIDATE_ONLY` — the validate-only build answers every
    /// valid LAUNCH ok without starting a session.
    pub fn validate_only() -> bool {
        static V: OnceLock<bool> = OnceLock::new();
        *V.get_or_init(|| env("CHL_TEST_VALIDATE_ONLY").is_some())
    }

    /// `CHL_TEST_PEER_UID` — the forced admitted peer uid
    /// (upstream -DCHL_TEST_PEER_UID=<uid>).
    pub fn peer_uid() -> Option<u32> {
        static V: OnceLock<Option<u32>> = OnceLock::new();
        *V.get_or_init(|| env_u64("CHL_TEST_PEER_UID").map(|v| v as u32))
    }

    /// `CHL_TEST_CONFIG_OWNER_UID` — the forced config owner
    /// (upstream -DCHL_TEST_CONFIG_OWNER_UID=<uid>).
    pub fn config_owner_uid() -> Option<u32> {
        static V: OnceLock<Option<u32>> = OnceLock::new();
        *V.get_or_init(|| env_u64("CHL_TEST_CONFIG_OWNER_UID").map(|v| v as u32))
    }

    /// `CHL_TEST_CONFIG` — the config file path of a test fixture.
    pub fn config_path() -> Option<OsString> {
        env("CHL_TEST_CONFIG")
    }

    /// `CHL_TEST_LOGIN_DEFS` — the login.defs path of a test fixture
    /// (upstream -DCHL_LOGIN_DEFS_PATH).
    pub fn login_defs_path() -> Option<OsString> {
        env("CHL_TEST_LOGIN_DEFS")
    }

    /// `CHL_TEST_CGROUP_ROOT` — the cgroup root of a test fixture
    /// (upstream -DCHL_CGROUP_FS is fixed; this is the read per request).
    pub fn cgroup_root() -> Option<OsString> {
        env("CHL_TEST_CGROUP_ROOT")
    }

    /// `CHL_TEST_HOME` — the forced operator home of a test fixture.
    pub fn test_home() -> Option<OsString> {
        env("CHL_TEST_HOME")
    }

    /// `CHL_TEST_TREE_OWNER_UID` — the uid the worktree/program trees
    /// must be owned by.
    pub fn tree_owner_uid() -> Option<u32> {
        static V: OnceLock<Option<u32>> = OnceLock::new();
        *V.get_or_init(|| env_u64("CHL_TEST_TREE_OWNER_UID").map(|v| v as u32))
    }

    /// `CHL_TEST_TRUSTED_DIR` — components at or above it in the tree
    /// walk are trusted (owner/mode unjudged).
    pub fn trusted_dir() -> Option<OsString> {
        env("CHL_TEST_TRUSTED_DIR")
    }

    /// `CHL_TEST_LANDLOCK_ABI` — the faked Landlock ABI probe result.
    pub fn landlock_abi() -> Option<i32> {
        static V: OnceLock<Option<i32>> = OnceLock::new();
        *V.get_or_init(|| env_u64("CHL_TEST_LANDLOCK_ABI").map(|v| v as i32))
    }

    /// `CHL_TEST_SOCKET` — the test listener path.
    pub fn socket_path() -> Option<OsString> {
        env("CHL_TEST_SOCKET")
    }

    /// A bounded-wait override in milliseconds; the env name matches
    /// upstream's -D knob (e.g. CHL_TEST_RECEIVE_TIMEOUT_MS).
    fn timeout(name: &str, default: i32) -> i32 {
        static V_RECEIVE: OnceLock<i32> = OnceLock::new();
        static V_CLEAN: OnceLock<i32> = OnceLock::new();
        static V_SETUP: OnceLock<i32> = OnceLock::new();
        static V_DRAIN: OnceLock<i32> = OnceLock::new();
        static V_INIT_WAIT: OnceLock<i32> = OnceLock::new();
        static V_SWEEP: OnceLock<i32> = OnceLock::new();
        let slot = match name {
            "CHL_TEST_RECEIVE_TIMEOUT_MS" => &V_RECEIVE,
            "CHL_TEST_CLEAN_TIMEOUT_MS" => &V_CLEAN,
            "CHL_TEST_SETUP_TIMEOUT_MS" => &V_SETUP,
            "CHL_TEST_DRAIN_TIMEOUT_MS" => &V_DRAIN,
            "CHL_TEST_INIT_WAIT_TIMEOUT_MS" => &V_INIT_WAIT,
            _ => &V_SWEEP,
        };
        *slot.get_or_init(|| env_u64(name).map(|v| v as i32).unwrap_or(default))
    }

    /// `CHL_TEST_RECEIVE_TIMEOUT_MS` (default 500).
    pub fn receive_timeout_ms() -> i32 {
        timeout("CHL_TEST_RECEIVE_TIMEOUT_MS", 500)
    }

    /// `CHL_TEST_CLEAN_TIMEOUT_MS` (default 60000).
    pub fn clean_timeout_ms() -> i32 {
        timeout("CHL_TEST_CLEAN_TIMEOUT_MS", 60_000)
    }

    /// `CHL_TEST_SETUP_TIMEOUT_MS` (default 30000).
    pub fn setup_timeout_ms() -> i32 {
        timeout("CHL_TEST_SETUP_TIMEOUT_MS", 30_000)
    }

    /// `CHL_TEST_DRAIN_TIMEOUT_MS` (default 10000).
    pub fn drain_timeout_ms() -> i32 {
        timeout("CHL_TEST_DRAIN_TIMEOUT_MS", 10_000)
    }

    /// `CHL_TEST_INIT_WAIT_TIMEOUT_MS` (default 30000).
    pub fn init_wait_timeout_ms() -> i32 {
        timeout("CHL_TEST_INIT_WAIT_TIMEOUT_MS", 30_000)
    }

    /// `CHL_TEST_SWEEP_TIMEOUT_MS` (default 10000).
    pub fn sweep_timeout_ms() -> i32 {
        timeout("CHL_TEST_SWEEP_TIMEOUT_MS", 10_000)
    }
}

#[cfg(feature = "test-build")]
pub use imp::*;

/* A production build: constants; none of the names above is ever read
 * (the compiler still sees them, hence `dead_code` is expected). */
#[cfg(not(feature = "test-build"))]
#[allow(dead_code)]
mod production {
    pub const fn no_isolation() -> bool {
        false
    }
    pub const fn validate_only() -> bool {
        false
    }
    pub const fn peer_uid() -> Option<u32> {
        None
    }
    pub const fn config_owner_uid() -> Option<u32> {
        None
    }
    pub const fn config_path() -> Option<std::ffi::OsString> {
        None
    }
    pub const fn login_defs_path() -> Option<std::ffi::OsString> {
        None
    }
    pub const fn cgroup_root() -> Option<std::ffi::OsString> {
        None
    }
    pub const fn test_home() -> Option<std::ffi::OsString> {
        None
    }
    pub const fn tree_owner_uid() -> Option<u32> {
        None
    }
    pub const fn trusted_dir() -> Option<std::ffi::OsString> {
        None
    }
    pub const fn landlock_abi() -> Option<i32> {
        None
    }
    pub const fn socket_path() -> Option<std::ffi::OsString> {
        None
    }
    pub const fn receive_timeout_ms() -> i32 {
        500
    }
    pub const fn clean_timeout_ms() -> i32 {
        60_000
    }
    pub const fn setup_timeout_ms() -> i32 {
        30_000
    }
    pub const fn drain_timeout_ms() -> i32 {
        10_000
    }
    pub const fn init_wait_timeout_ms() -> i32 {
        30_000
    }
    pub const fn sweep_timeout_ms() -> i32 {
        10_000
    }
}
#[cfg(not(feature = "test-build"))]
pub use production::*;

/// Upstream `CHL_TEST_MARKER` (chl.h:30): a byte string embedded in the
/// binary that packaging greps for to refuse shipping a test build.
/// `#[used]` keeps it after LTO/strip.
#[cfg(feature = "test-build")]
#[used]
static TEST_BUILD_MARKER: &[u8] =
    b"CHL-TEST-BUILD-MARKER: a test build of central-harness-launcherd; never install it";
