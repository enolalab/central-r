//! CHL1 v1 request handling for the daemon (upstream `protocol.c`).
//!
//! The wire codec itself is `central_adapter_harness::launcher::protocol`,
//! shared with the client; what lives here is only what upstream keeps in
//! protocol.c for the daemon: the "usable header" gate
//! ([`header_opcode`], step 1 of PROTOCOL.md §3.1.1), the scope's
//! canonical string, the reason table and the fixed-name launch-failure
//! step table behind [`step_name`].

use std::io::Write;

use central_adapter_harness::launcher::protocol as wire;
use wire::{Opcode, Reason, Scope};

/// `chl_header_opcode`: the opcode of a frame with a usable header
/// (size, magic, version, opcode 1-3), or `None`. A frame without one is
/// closed silently — there is no opcode to answer with.
pub fn header_opcode(frame: &[u8]) -> Option<Opcode> {
    if frame.len() < wire::HEADER_SIZE
        || frame[..4] != *b"CHL1"
        || frame[4] != wire::PROTOCOL_VERSION
    {
        return None;
    }
    match frame[5] {
        1 => Some(Opcode::Launch),
        2 => Some(Opcode::Alive),
        3 => Some(Opcode::Kill),
        _ => None,
    }
}

/// `chl_scope_string` — the canonical lower-case form.
pub fn scope_string(scope: &Scope) -> String {
    scope.to_string()
}

/// `chl_reason_name` — the wire name (PROTOCOL.md §5).
pub fn reason_name(reason: Reason) -> &'static str {
    reason.as_str()
}

/// `chl_log` — `central-harness-launcherd: <event> reason=<name>
/// scope=<uuid|->`. Never a request value (spec section 6).
pub fn log(event: &str, reason: Reason, scope: Option<&Scope>) {
    let text = scope.map_or_else(|| "-".to_string(), scope_string);
    let line = format!(
        "central-harness-launcherd: {event} reason={} scope={text}\n",
        reason_name(reason)
    );
    let mut err = std::io::stderr().lock();
    // A log line may fail; logging is never fatal.
    let _ = err.write_all(line.as_bytes());
    let _ = err.flush();
}

/// `chl_log_step` — [`log`] plus ` step=<name> errno=<n>`.
pub fn log_step(event: &str, reason: Reason, scope: Option<&Scope>, step: i32, err: i32) {
    let text = scope.map_or_else(|| "-".to_string(), scope_string);
    let line = format!(
        "central-harness-launcherd: {event} reason={} scope={text} step={} errno={err}\n",
        reason_name(reason),
        step_name(step)
    );
    let mut err = std::io::stderr().lock();
    let _ = err.write_all(line.as_bytes());
    let _ = err.flush();
}

/* ---- launch failure diagnostics (upstream chl.h enum chl_step) ---- */

pub const STEP_NONE: i32 = 0;
pub const STEP_SCOPE_TABLE: i32 = 1;
pub const STEP_PLAN_ALLOC: i32 = 2;
pub const STEP_SCOPE_CREATE: i32 = 3;
pub const STEP_CONTROL_SOCKET: i32 = 4;
pub const STEP_MONITOR_FORK: i32 = 5;
pub const STEP_MONITOR_FDS: i32 = 6;
pub const STEP_CGROUP_REOPEN: i32 = 7;
pub const STEP_MONITOR_PIPE: i32 = 8;
pub const STEP_SCOPE_OPEN: i32 = 9;
pub const STEP_CLONE3: i32 = 10;
pub const STEP_STATUS_CHANNEL: i32 = 11;
pub const STEP_SETUP_TIMEOUT: i32 = 12;
pub const STEP_SETUP_POLL: i32 = 13;
pub const STEP_LIFELINE_LOST: i32 = 14;
pub const STEP_INIT_FDS: i32 = 15;
pub const STEP_MOUNT_SLAVE: i32 = 16;
pub const STEP_WORKTREE_ROOT: i32 = 17;
pub const STEP_WORKTREE_IDENTITY: i32 = 18;
pub const STEP_OPEN_HOME: i32 = 19;
pub const STEP_HARNESS_HOME: i32 = 20;
pub const STEP_SOURCE_CLONE: i32 = 21;
pub const STEP_MAKE_RO: i32 = 22;
pub const STEP_WORKTREE_CLONE: i32 = 23;
pub const STEP_HIDE_ROOT: i32 = 24;
pub const STEP_HIDE_RUN_USER: i32 = 25;
pub const STEP_HIDE_TMP: i32 = 26;
pub const STEP_HIDE_VAR_TMP: i32 = 27;
pub const STEP_HIDE_DEV_SHM: i32 = 28;
pub const STEP_HIDE_HOME_PARENT: i32 = 29;
pub const STEP_WORKTREE_HIDE: i32 = 30;
pub const STEP_PROC_MOUNT: i32 = 31;
pub const STEP_DEVPTS_OPEN: i32 = 32;
pub const STEP_DEVPTS_CONFIG: i32 = 33;
pub const STEP_DEVPTS_MOUNT: i32 = 34;
pub const STEP_PTMX_BIND: i32 = 35;
pub const STEP_ATTACH_HOME: i32 = 36;
pub const STEP_ATTACH_ENTRY: i32 = 37;
pub const STEP_ATTACH_WORKTREE: i32 = 38;
pub const STEP_INIT_NNP: i32 = 39;
pub const STEP_INIT_LANDLOCK: i32 = 40;
pub const STEP_ERROR_PIPE: i32 = 41;
pub const STEP_HARNESS_FORK: i32 = 42;
pub const STEP_HARNESS_REPORT: i32 = 43;
pub const STEP_INIT_DROP: i32 = 44;
pub const STEP_HARNESS_FD: i32 = STEP_INIT_DROP + DROP_COUNT;
pub const STEP_CWD_LENGTH: i32 = STEP_HARNESS_FD + 1;
pub const STEP_HARNESS_DROP: i32 = STEP_CWD_LENGTH + 1;
pub const STEP_CHDIR: i32 = STEP_HARNESS_DROP + DROP_COUNT;
pub const STEP_EXEC: i32 = STEP_CHDIR + 1;
pub const STEP_COUNT: i32 = STEP_EXEC + 1;

/* upstream enum drop_step — the drop sequence has the same slots in the
 * init's and the harness's run. */
pub const DROP_CAPBSET: i32 = 0;
pub const DROP_AMBIENT: i32 = 1;
pub const DROP_SECUREBITS: i32 = 2;
pub const DROP_SETGROUPS: i32 = 3;
pub const DROP_SETID: i32 = 4;
pub const DROP_CAPSET: i32 = 5;
pub const DROP_CAPS_LEFT: i32 = 6;
pub const DROP_NNP_DUMPABLE: i32 = 7;
pub const DROP_LANDLOCK: i32 = 8;
pub const DROP_COUNT: i32 = 9;

/// `chl_step_name` — the fixed step names of upstream protocol.c.
pub fn step_name(step: i32) -> &'static str {
    const NAMES: &[&str] = &[
        "none",
        "scope_table",
        "plan_alloc",
        "scope_create",
        "control_socket",
        "monitor_fork",
        "monitor_fds",
        "cgroup_reopen",
        "monitor_pipe",
        "scope_open",
        "clone3",
        "status_channel",
        "setup_timeout",
        "setup_poll",
        "lifeline_lost",
        "init_fds",
        "mount_slave",
        "worktree_root",
        "worktree_identity",
        "open_home",
        "harness_home",
        "source_clone",
        "make_ro",
        "worktree_clone",
        "hide_root",
        "hide_run_user",
        "hide_tmp",
        "hide_var_tmp",
        "hide_dev_shm",
        "hide_home_parent",
        "worktree_hide",
        "proc_mount",
        "devpts_open",
        "devpts_config",
        "devpts_mount",
        "ptmx_bind",
        "attach_home",
        "attach_entry",
        "attach_worktree",
        "init_nnp",
        "init_landlock",
        "error_pipe",
        "harness_fork",
        "harness_report",
        "init_capbset",
        "init_ambient",
        "init_securebits",
        "init_setgroups",
        "init_setid",
        "init_capset",
        "init_caps_left",
        "init_nnp_dumpable",
        "init_landlock",
        "harness_fd",
        "cwd_length",
        "harness_capbset",
        "harness_ambient",
        "harness_securebits",
        "harness_setgroups",
        "harness_setid",
        "harness_capset",
        "harness_caps_left",
        "harness_nnp_dumpable",
        "harness_landlock",
        "chdir",
        "exec",
    ];
    if !(0..STEP_COUNT).contains(&step) {
        return "unknown";
    }
    NAMES[step as usize]
}

/// `init_ended` — the monitor's extra line for an init that ended without
/// reporting (upstream `launch_failed` helper).
pub fn log_init_ended(scope: &Scope, code: i32) {
    let line = format!(
        "central-harness-launcherd: init_ended reason=launch_failed scope={scope} code={code}\n",
        scope = scope_string(scope)
    );
    let mut err = std::io::stderr().lock();
    let _ = err.write_all(line.as_bytes());
    let _ = err.flush();
}
