//! A07 — path races and state-tree denials (threats T17/T23, upstream
//! `openat2` sandbox policy, `grant_flock_unix_test.go`,
//! `genesis` ancestor/record gates, `seal_linux.go`).
//!
//! `openat2` `RESOLVE_BENEATH | NO_SYMLINKS | NO_MAGICLINKS | NO_XDEV`
//! is the kernel-side answer to the TOCTOU shape: a path swapped for
//! a symlink between check and open can never resolve outside the
//! root. The genesis ancestor/root/record gates, the workspace
//! sealer's clone verification, and the grant store's path checks
//! are the same refusal at higher layers — every one is asserted on
//! real directories.

// `allow-*-in-tests` only reaches `#[test]` fns — the fixture helpers
// in this binary unwrap/expect deliberately: an unbuildable fixture
// is the failure.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod a07;

use a07::*;
use central_adapter_linux::genesis;
use central_adapter_linux::sys::openat2;
use central_adapter_linux::workspace_seal::LinuxWorkspaceSealer;
use central_foundation::failure::FailureKind;
use central_foundation::identity::RunId;
use central_harness::app::ports::WorkspaceSealer;
use rustix::fs::{Mode, OFlags, open};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;

fn dirfd(path: &Path) -> OwnedFd {
    open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .expect("dir fd")
}

// ---------------------------------------------------------------------------
// openat2 — the path-race boundary
// ---------------------------------------------------------------------------

/// `..` reaching above the root refuses `EXDEV` (`RESOLVE_BENEATH`);
/// a symlink in the path refuses `ELOOP` (`NO_SYMLINKS`); a magic
/// link (`/proc/self/fd/...`) refuses too.
#[test]
fn openat2_refuses_escape_symlink_and_magiclink() {
    let scratch = Scratch::new("openat2");
    scratch.dir("root/inner", 0o700);
    scratch.file("root/inner/secret.txt", b"secret", 0o600);
    scratch.file("outside.txt", b"escape", 0o600);
    let root = dirfd(&scratch.join("root"));

    // Above the root: `..` is EXDEV with RESOLVE_BENEATH.
    let err = openat2::resolve_with(
        &root,
        Path::new("../outside.txt"),
        OFlags::RDONLY,
        openat2::RESOLVE_FLAGS,
    )
    .unwrap_err();
    assert_eq!(err, rustix::io::Errno::XDEV, ".. escape must be EXDEV");

    // A symlink inside the root: ELOOP.
    std::os::unix::fs::symlink("../outside.txt", scratch.join("root/link")).expect("symlink");
    let err = openat2::resolve_with(
        &root,
        Path::new("link"),
        OFlags::RDONLY,
        openat2::RESOLVE_FLAGS,
    )
    .unwrap_err();
    assert_eq!(
        err,
        rustix::io::Errno::LOOP,
        "in-root symlink must be ELOOP"
    );

    // A magic link: /proc/self/fd/N — NO_MAGICLINKS refuses what
    // NO_SYMLINKS alone would let through.
    let target = format!("/proc/self/fd/{}", std::process::id() % 2);
    std::os::unix::fs::symlink(&target, scratch.join("root/magic")).expect("magiclink");
    let err = openat2::resolve_with(
        &root,
        Path::new("magic"),
        OFlags::RDONLY,
        openat2::RESOLVE_FLAGS,
    )
    .unwrap_err();
    assert!(
        err == rustix::io::Errno::LOOP || err == rustix::io::Errno::XDEV,
        "magic link must refuse, got {err}"
    );

    // The honest file still opens — refusal is by shape, not by path.
    let fd = openat2::resolve_regular_file(&root, Path::new("inner/secret.txt"))
        .expect("real file resolves");
    assert!(fd.as_raw_fd() >= 0);
}

/// The TOCTOU shape upstream's `openat2` choice answers: a component
/// swapped from a real directory to a symlink between checks can
/// never be followed — the kernel resolves the swap atomically at
/// open time, so after the swap the resolution fails `ELOOP`, and it
/// can never yield the outside file.
#[test]
fn openat2_rename_swap_never_follows_the_escape() {
    let scratch = Scratch::new("openat2-race");
    scratch.dir("root/real", 0o700);
    scratch.file("root/real/item.txt", b"safe", 0o600);
    scratch.file("escape/item.txt", b"ESCAPE", 0o600);
    let root = dirfd(&scratch.join("root"));

    // Before the swap the real file resolves.
    let fd = openat2::resolve_with(
        &root,
        Path::new("real/item.txt"),
        OFlags::RDONLY,
        openat2::RESOLVE_FLAGS,
    )
    .expect("pre-swap resolve");
    drop(fd);

    // The swap: `real` becomes a symlink to the escape tree — the
    // classic check→use window a naive lstat+open would lose.
    std::fs::rename(scratch.join("root/real"), scratch.join("root/real-moved"))
        .expect("rename away");
    std::os::unix::fs::symlink(scratch.join("escape"), scratch.join("root/real"))
        .expect("symlink in");

    let err = openat2::resolve_with(
        &root,
        Path::new("real/item.txt"),
        OFlags::RDONLY,
        openat2::RESOLVE_FLAGS,
    )
    .unwrap_err();
    assert_eq!(err, rustix::io::Errno::LOOP, "swapped symlink must refuse");

    // Repeat the swap a few times: every resolution is either the
    // real file or a refusal — never the escape payload.
    for _ in 0..4 {
        std::fs::remove_file(scratch.join("root/real")).ok();
        std::fs::rename(scratch.join("root/real-moved"), scratch.join("root/real"))
            .expect("rename back");
        let ok = openat2::resolve_with(
            &root,
            Path::new("real/item.txt"),
            OFlags::RDONLY,
            openat2::RESOLVE_FLAGS,
        );
        std::fs::rename(scratch.join("root/real"), scratch.join("root/real-moved"))
            .expect("rename away");
        std::os::unix::fs::symlink(scratch.join("escape"), scratch.join("root/real"))
            .expect("symlink in");
        let refuse = openat2::resolve_with(
            &root,
            Path::new("real/item.txt"),
            OFlags::RDONLY,
            openat2::RESOLVE_FLAGS,
        );
        assert!(ok.is_ok(), "real path must keep resolving");
        assert_eq!(
            refuse.unwrap_err(),
            rustix::io::Errno::LOOP,
            "swapped path must refuse"
        );
    }
}

/// Type denials: a directory is not a regular file; a regular file is
/// not a directory.
#[test]
fn openat2_type_denials() {
    let scratch = Scratch::new("openat2-types");
    scratch.dir("root/dir", 0o700);
    scratch.file("root/file", b"x", 0o600);
    let root = dirfd(&scratch.join("root"));

    let err = openat2::resolve_regular_file(&root, Path::new("dir")).unwrap_err();
    assert_denial(
        &err,
        FailureKind::Denied,
        "sys_openat2_denied",
        "not a regular file",
    );

    let err = openat2::resolve_directory(&root, Path::new("file")).unwrap_err();
    assert_eq!(err.code(), "sys_openat2_os");
}

// ---------------------------------------------------------------------------
// genesis — the state-tree shape gates
// ---------------------------------------------------------------------------

/// The ancestor gate: every ancestor must be missing-or-exactly
/// owned — a group/other-writable ancestor is refused; a non-
/// directory is refused.
#[test]
fn genesis_ancestor_denies_writable_or_non_dir() {
    let scratch = Scratch::new("gen-anc");
    let writable = scratch.dir("writable", 0o777);
    let err = genesis::genesis_ancestor_missing_or_root_owned(&writable, euid()).unwrap_err();
    assert!(err.contains("writable"), "writable ancestor: {err}");

    let file = scratch.file("notdir", b"x", 0o600);
    let err = genesis::genesis_ancestor_missing_or_root_owned(&file, euid()).unwrap_err();
    assert!(err.contains("directory"), "non-dir ancestor: {err}");

    let strict = scratch.dir("strict", 0o755);
    genesis::genesis_ancestor_missing_or_root_owned(&strict, euid()).expect("0755 is fine");
    genesis::genesis_ancestor_missing_or_root_owned(&scratch.join("missing"), euid())
        .expect("missing is fine");
}

/// The protected/state roots must be `uid:gid 0700` exactly, and
/// instance roots must be empty — the owned-but-wrong-mode path the
/// init ladder refuses.
#[test]
fn genesis_root_shape_denials() {
    let scratch = Scratch::new("gen-roots");
    let loose = scratch.dir("loose", 0o755);
    let err = genesis::protected_genesis_root_missing_or_exact(&loose, euid(), egid()).unwrap_err();
    assert!(err.contains("0700"), "wrong mode: {err}");

    let file = scratch.file("notdir", b"x", 0o600);
    let err = genesis::protected_genesis_root_missing_or_exact(&file, euid(), egid()).unwrap_err();
    assert!(err.contains("directory"), "non-dir root: {err}");

    let nonempty = scratch.dir("nonempty", 0o700);
    scratch.file("nonempty/entry", b"x", 0o600);
    assert_eq!(
        genesis::empty_genesis_root_or_missing(&nonempty, euid(), egid()),
        Ok(false),
        "a populated root is not the absent host"
    );
}

/// The genesis record is a root-owned `0600` JSON of the pinned
/// schema — a wrong-mode file or a corrupt payload refuses before
/// anything trusts it.
#[test]
fn genesis_record_denials() {
    let scratch = Scratch::new("gen-record");
    // Wrong mode: 0644.
    let state = scratch.dir("state", 0o700);
    scratch.file("state/genesis.json", b"{}", 0o644);
    let err = genesis::read_genesis_record(&state, euid(), egid()).unwrap_err();
    assert_eq!(err, "genesis record is not a root-owned 0600 file");

    // Corrupt payload at the right mode.
    scratch.file("state/genesis.json", b"{corrupt", 0o600);
    let err = genesis::read_genesis_record(&state, euid(), egid()).unwrap_err();
    assert!(!err.is_empty(), "corrupt record must refuse");

    // A record that parses but lies about its schema refuses — the
    // trailing-data refusal likewise only fires behind a fully valid
    // record, so both ride on the same well-formed fixture.
    let good = format!(
        r#"{{"schema_version":"central.genesis/v1","instance_id":"{i1}","config_binding_id":"{i2}","init_operation_id":"{i3}","created_at":"2026-10-23T00:00:00Z","ceremony":"physical_tty"}}"#,
        i1 = uuid::Uuid::now_v7(),
        i2 = uuid::Uuid::now_v7(),
        i3 = uuid::Uuid::now_v7(),
    );
    scratch.file("state/genesis.json", good.as_bytes(), 0o600);
    genesis::read_genesis_record(&state, euid(), egid()).expect("well-formed record");

    scratch.file(
        "state/genesis.json",
        good.replace("central.genesis/v1", "x/v9").as_bytes(),
        0o600,
    );
    assert!(
        genesis::read_genesis_record(&state, euid(), egid()).is_err(),
        "an unknown schema version must refuse"
    );

    // Trailing data is refused — the record is one JSON value.
    scratch.file(
        "state/genesis.json",
        format!("{good}}}{{").as_bytes(),
        0o600,
    );
    let err = genesis::read_genesis_record(&state, euid(), egid()).unwrap_err();
    assert_eq!(err, "genesis record has trailing data");
}

/// `env.state()` classification on handcrafted trees: absent roots →
/// `Absent`; a protected instance with no state peer → `Broken`
/// (init's `INSTANCE_BROKEN` exit 3 rides on this verdict).
#[test]
fn genesis_env_state_classification() {
    let scratch = Scratch::new("gen-state");
    let env = genesis::GenesisEnv {
        roots: genesis::GenesisRoots {
            state_root: scratch.join("state/v1").to_string_lossy().into_owned(),
            protected_root: scratch.join("protected/v1").to_string_lossy().into_owned(),
        },
        owners: genesis::GenesisOwners {
            root_uid: euid(),
            root_gid: egid(),
            runtime_uid: euid(),
            runtime_gid: egid(),
        },
        ..genesis::GenesisEnv::production()
    };
    let (state, _, _) = env.state();
    assert_eq!(
        state,
        genesis::GenesisState::Absent,
        "empty roots are absent"
    );

    // A protected instance with no state peer: the broken shape.
    // Every ancestor the gate inspects is exactly root-owned.
    scratch.dir("protected", 0o700);
    scratch.dir("protected/v1", 0o700);
    scratch.dir("protected/v1/instances", 0o700);
    scratch.dir("protected/v1/instances/inst-1", 0o700);
    let (state, _, err) = env.state();
    assert_eq!(state, genesis::GenesisState::Broken);
    assert!(
        err.as_deref()
            .unwrap_or_default()
            .contains("no state instance"),
        "{err:?}"
    );
}

// ---------------------------------------------------------------------------
// workspace_seal — the untrusted clone never escapes its root
// ---------------------------------------------------------------------------

/// `verify_clone` on a missing Run directory: `openat2` beneath the
/// data root can't open it — `WORKSPACE_UNAVAILABLE`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn workspace_verify_clone_missing_run_denied() {
    let scratch = Scratch::new("ws-missing");
    let sealer = LinuxWorkspaceSealer::new(scratch.path().to_path_buf(), euid(), euid(), 0);
    let run = RunId::new();
    let err = sealer.verify_clone(run).await.unwrap_err();
    assert_eq!(err.code(), "harness_app_workspace_unavailable");
    assert!(
        err.message().contains("open the run directory"),
        "{}",
        err.message()
    );
}

/// A symlinked Run directory is the traversal smuggle — `openat2`
/// `BENEATH|NO_SYMLINKS` refuses it before any content is read.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn workspace_verify_clone_symlink_run_denied() {
    let scratch = Scratch::new("ws-symlink");
    let real = scratch.dir("real-target", 0o700);
    let run = RunId::new();
    let runs = scratch.dir("worktrees/runs", 0o700);
    std::os::unix::fs::symlink(&real, runs.join(run.to_string())).expect("symlink run");
    let sealer = LinuxWorkspaceSealer::new(scratch.path().to_path_buf(), euid(), euid(), 0);
    let err = sealer.verify_clone(run).await.unwrap_err();
    assert_eq!(err.code(), "harness_app_workspace_unavailable");
    assert!(
        err.message().contains("open the run directory"),
        "{}",
        err.message()
    );
}

/// A Run directory owned by someone other than the runtime uid is
/// refused on the opened descriptor's `fstat` — the ownership check
/// is on the descriptor, never the path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn workspace_verify_clone_wrong_owner_denied() {
    let scratch = Scratch::new("ws-owner");
    let run = RunId::new();
    scratch.dir(&format!("worktrees/runs/{run}"), 0o750);
    // The sealer believes the runtime uid is *not* us.
    let sealer = LinuxWorkspaceSealer::new(scratch.path().to_path_buf(), euid(), euid() + 1, 0);
    let err = sealer.verify_clone(run).await.unwrap_err();
    assert_eq!(err.code(), "harness_app_workspace_unavailable");
    assert!(
        err.message().contains("not a runtime-owned directory"),
        "{}",
        err.message()
    );
}

/// `seal` on a Run without a clone root refuses the capture —
/// `CAPTURE_FAILED` — and never yields a half-verified handle.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn workspace_seal_missing_clone_denied() {
    let scratch = Scratch::new("ws-seal");
    let run = RunId::new();
    scratch.dir(&format!("worktrees/runs/{run}"), 0o750);
    let sealer = LinuxWorkspaceSealer::new(scratch.path().to_path_buf(), euid(), euid(), 0);
    let err = sealer
        .seal(run)
        .await
        .err()
        .expect("a run without a clone root must refuse");
    assert_eq!(err.code(), "harness_app_capture_failed");
}

/// A symlinked `repo` inside the Run is refused identically — the
/// clone root must be a real directory beneath the Run descriptor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn workspace_seal_symlink_clone_denied() {
    let scratch = Scratch::new("ws-seal-link");
    let run = RunId::new();
    let run_dir = scratch.dir(&format!("worktrees/runs/{run}"), 0o750);
    std::os::unix::fs::symlink("/etc", run_dir.join("repo")).expect("repo symlink");
    let sealer = LinuxWorkspaceSealer::new(scratch.path().to_path_buf(), euid(), euid(), 0);
    let err = sealer
        .seal(run)
        .await
        .err()
        .expect("a symlinked clone root must refuse");
    assert_eq!(err.code(), "harness_app_capture_failed");
}

// ---------------------------------------------------------------------------
// Grant store — the path is part of the authority
// ---------------------------------------------------------------------------

/// `GrantStore::open` shape denials: a relative path is `invalid`; a
/// store directory that isn't `0700` or isn't owned by the instance
/// owner is refused — a tampered store must not silently authorize.
#[test]
fn grant_store_path_shape_denied() {
    use central_adapter_linux::helper::grant::GrantStore;
    let scratch = Scratch::new("grant-open");

    let err = GrantStore::open("relative/path", euid(), egid())
        .err()
        .expect("a relative store path must refuse");
    assert_eq!(err.code(), "sys_grant_store");
    assert_eq!(err.kind(), FailureKind::Invalid);

    let loose = scratch.dir("loose", 0o755);
    let err = GrantStore::open(loose.to_str().unwrap(), euid(), egid())
        .err()
        .expect("a group-readable store must refuse");
    assert_denial(&err, FailureKind::Denied, "sys_grant_store", "0700");

    let owned = scratch.dir("owned", 0o700);
    let err = GrantStore::open(owned.to_str().unwrap(), euid() + 1, egid())
        .err()
        .expect("a store owned by another uid must refuse");
    assert_denial(&err, FailureKind::Denied, "sys_grant_store", "owned");
}
