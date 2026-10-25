//! `daemon_linux.go` — `ServeLauncher` + `handleLaunchConn`, ported
//! descriptor-bound (R5 task 9 / A06).
//!
//! Upstream reads a plain `bufio` line and launches whatever arrives.
//! The port binds every request to its descriptor: one `recvmsg`
//! frame of ≤ [`MAX_FRAME_BYTES`] bytes carrying one JSON line
//! *and* exactly one `SCM_RIGHTS` descriptor — the workspace root —
//! plus these refusals upstream never performed:
//!
//! | check                        | denial                                   |
//! |------------------------------|------------------------------------------|
//! | `SO_PEERCRED` uid not root / | `authority denied`                       |
//! |   `runtime_uid` (501)        |                                          |
//! | frame without exactly 1 fd   | `sys_scm_rights_denied`                  |
//! | fd not a directory           | `sandbox: workspace root is not a dir…`  |
//! | `env` non-empty              | `sandbox: request env is not admitted`   |
//! | arg with `/`-absolute or     | `sandbox: argument … not admitted`       |
//! |   `..` component             |                                          |
//! | `deadline_ms` > 600 s / < 0  | `sandbox: deadline …`                    |
//! | `exec_binary` not the        | `sandbox: unknown executable class…`     |
//! |   `central-agent` class      |                                          |
//! | unknown JSON field (incl. a  | `sandbox: invalid launch request: …`     |
//! |   forged `workspace_root_fd`)|                                          |
//!
//! Each denied request still gets the upstream `{"outcome":"error",
//! "reason":…}` response line — the denial is observable, never a
//! silent close — and each accepted request is launched by
//! [`launcher::launch`] in its own worker thread, upstream's
//! `go handleLaunchConn` shape.

use std::io::Write;
use std::os::fd::OwnedFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use central_foundation::failure::Failure;
use central_infra::authority::CENTRAL_RUNTIME_UID;
use serde::Serialize;

use super::domain::{LaunchEvidence, LaunchRequest};
use super::envelope::effective_deadline;
use super::launcher::{LauncherConfig, launch};
use crate::sys::{peercred, scm_rights};

/// Upstream `scanner.Buffer(65536, 65536)` — one request line is at
/// most 64 KiB. The port receives the line and its descriptor in the
/// same `recvmsg` frame, so the frame bound is the byte bound.
pub const MAX_FRAME_BYTES: usize = 65536;

/// The request read bound — a peer that opens a connection and never
/// frames must not pin a worker forever. Upstream leaves the read
/// unbounded; 30 s is the port's defensive bound (documented
/// divergence, fail-closed).
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// The launcher service — upstream's daemon-level state. `runtime_uid`
/// is the `SO_PEERCRED` admission peer (`isRuntimeOrRootPeer`'s same
/// root-or-runtime rule); `launcher` carries the agent identity and
/// settle grace.
#[derive(Debug, Clone)]
pub struct LauncherService {
    /// The peer uid the daemon admits beside root — the central
    /// runtime identity (ADR 0013).
    pub runtime_uid: u32,
    /// The launcher's own knobs.
    pub launcher: LauncherConfig,
}

impl LauncherService {
    /// The production shape — runtime uid 501, agent 502:502, the
    /// 10 s settle grace.
    #[must_use]
    pub fn production() -> Self {
        Self {
            runtime_uid: CENTRAL_RUNTIME_UID,
            launcher: LauncherConfig::default(),
        }
    }
}

fn denied(msg: impl Into<String>) -> Failure {
    Failure::denied("sandbox_denied", msg.into())
}

/// The response shape — upstream's `map[string]any` marshals keys
/// alphabetically: `evidence`, `outcome`, `reason`.
#[derive(Serialize)]
struct LaunchResponse<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence: Option<&'a LaunchEvidence>,
    outcome: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

/// Write the one JSON response line — upstream's
/// `conn.Write(append(marshal(resp), '\n'))`, best-effort the same
/// way (the connection is closing anyway).
fn respond(
    conn: &mut UnixStream,
    outcome: &'static str,
    reason: Option<String>,
    evidence: Option<&LaunchEvidence>,
) {
    let resp = LaunchResponse {
        evidence,
        outcome,
        reason,
    };
    if let Ok(mut line) = serde_json::to_string(&resp) {
        line.push('\n');
        let _ = conn.write_all(line.as_bytes());
    }
}

/// `handleLaunchConn` — one connection, one descriptor-bound request,
/// one response. Returns `Err` for every refusal after having written
/// the error response the peer can observe (upstream's silent-close
/// on parse failure becomes the observable `{"outcome":"error"}`
/// line — strictly more informative, same denial).
///
/// # Errors
/// `sys_peercred_*`/`sys_scm_rights_*`/`sandbox_denied` on every
/// refusal; `sandbox_os` when the launch machinery itself fails.
pub fn handle_launch_conn(conn: &mut UnixStream, svc: &LauncherService) -> Result<(), Failure> {
    let _ = conn.set_read_timeout(Some(REQUEST_READ_TIMEOUT));

    // `SO_PEERCRED` first — the kernel-attested caller gate runs
    // before a single request byte is admitted (the broker's
    // `isRuntimeOrRootPeer` rule: root or the runtime uid).
    let peer = peercred::peercred(&*conn)?;
    if !(peer.uid.is_root() || peer.uid.as_raw() == svc.runtime_uid) {
        respond(conn, "error", Some("authority denied".to_owned()), None);
        return Err(denied(format!("sandbox: denied UID {}", peer.uid.as_raw())));
    }

    // The descriptor-bound frame: one recvmsg — the JSON line and its
    // workspace-root descriptor arrive together or not at all.
    let mut buf = vec![0u8; MAX_FRAME_BYTES + 1];
    let (n, workspace_root) = match scm_rights::recv_one(&*conn, &mut buf) {
        Ok(pair) => pair,
        Err(e) => {
            respond(conn, "error", Some(e.message().to_owned()), None);
            return Err(e);
        }
    };
    let req = match parse_request(&buf[..n]) {
        Ok(r) => r,
        Err(e) => {
            respond(conn, "error", Some(e.message().to_owned()), None);
            return Err(e);
        }
    };
    let deadline = match validate_request(&req) {
        Ok(d) => d,
        Err(e) => {
            respond(conn, "error", Some(e.message().to_owned()), None);
            return Err(e);
        }
    };

    match launch(&svc.launcher, &req, deadline, &workspace_root) {
        Ok(ev) => {
            respond(conn, "ok", None, Some(&ev));
            Ok(())
        }
        Err(e) => {
            respond(conn, "error", Some(e.message().to_owned()), None);
            Err(e)
        }
    }
}

/// The frame's payload → `LaunchRequest`: must be a single
/// newline-terminated line within [`MAX_FRAME_BYTES`]; serde's
/// `deny_unknown_fields` makes a forged `workspace_root_fd` (or any
/// invented field) a named refusal. Bytes past the first newline are
/// ignored, upstream's one-line-scan shape.
fn parse_request(frame: &[u8]) -> Result<LaunchRequest, Failure> {
    if frame.is_empty() || frame.len() > MAX_FRAME_BYTES {
        return Err(denied(
            "sandbox: request frame outside the 65536-byte bound",
        ));
    }
    let Some(end) = frame.iter().position(|b| *b == b'\n') else {
        return Err(denied("sandbox: request missing newline terminator"));
    };
    serde_json::from_slice::<LaunchRequest>(&frame[..end]).map_err(|e| {
        Failure::invalid(
            "sandbox_invalid",
            format!("sandbox: invalid launch request: {e}"),
        )
    })
}

/// The request-level denials upstream never had — env injection,
/// path-shaped arguments, the deadline cap — folded around
/// [`effective_deadline`].
fn validate_request(req: &LaunchRequest) -> Result<Duration, Failure> {
    // Environment injection is an ambient-authority route: upstream
    // passed `req.Env` to `cmd.Env` unchecked; the port admits only an
    // absent or empty field. The sandboxed child gets a clean,
    // empty environment — never caller bytes.
    if !req.env.is_empty() {
        return Err(denied("sandbox: request env is not admitted"));
    }
    // Absolute paths and parent-directory components in argv are the
    // same ambient-authority shape the binary class check closes for
    // argv[0] — an absolute-path escape attempt or a `../` traversal
    // in an argument is refused before resolution could matter.
    for arg in &req.args {
        if arg.starts_with('/') {
            return Err(denied(format!(
                "sandbox: absolute-path argument is not admitted: {arg:?}"
            )));
        }
        // `..` must never appear as a path segment anywhere in the
        // arg — including after a `=` (`--flag=../x` is the same
        // traversal wearing a flag's clothes).
        if arg.split(['/', '=']).any(|seg| seg == "..") {
            return Err(denied(format!(
                "sandbox: parent-directory argument is not admitted: {arg:?}"
            )));
        }
    }
    if req.deadline_ms < 0 {
        return Err(denied("sandbox: deadline must not be negative"));
    }
    #[allow(clippy::cast_sign_loss)]
    let deadline = Duration::from_nanos(req.deadline_ms as u64);
    effective_deadline(deadline)
}

/// `ServeLauncher` — accept on the activated listener until
/// `shutdown` fires; each connection is a worker thread, upstream's
/// `go handleLaunchConn` shape. Nonblocking accept at a 10 ms cadence
/// so the loop observes the flag (the broker's `serve` idiom).
///
/// # Errors
/// `sandbox` internal on a listener or accept failure.
pub fn serve_launcher(
    listen: OwnedFd,
    svc: &Arc<LauncherService>,
    shutdown: Arc<AtomicBool>,
) -> Result<(), Failure> {
    let listener = UnixListener::from(listen);
    listener.set_nonblocking(true).map_err(|e| {
        Failure::internal("sandbox_os", format!("sandbox-daemon: file listener: {e}"))
    })?;
    while !shutdown.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((mut conn, _)) => {
                let svc = Arc::clone(svc);
                let _ = std::thread::Builder::new()
                    .name("sandbox-conn".to_owned())
                    .spawn(move || {
                        if let Err(e) = handle_launch_conn(&mut conn, &svc) {
                            eprintln!("sandbox: connection error: {}", e.message());
                        }
                    });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                return Err(Failure::internal(
                    "sandbox_os",
                    format!("sandbox-daemon: accept: {e}"),
                ));
            }
        }
    }
    Ok(())
}

/// `signal.NotifyContext(SIGINT, SIGTERM)` — an `AtomicBool` a tokio
/// signal-waiter thread flips (tokio is the workspace's signal owner,
/// the helper daemon's shape).
fn shutdown_flag() -> Arc<AtomicBool> {
    let flag = Arc::new(AtomicBool::new(false));
    let writer = Arc::clone(&flag);
    let _ = std::thread::Builder::new()
        .name("sandbox-signal".to_owned())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(_) => return,
            };
            rt.block_on(async {
                let mut int =
                    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                    {
                        Ok(s) => s,
                        Err(_) => return,
                    };
                let mut term =
                    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    {
                        Ok(s) => s,
                        Err(_) => return,
                    };
                tokio::select! {
                    _ = int.recv() => {}
                    _ = term.recv() => {}
                }
            });
            writer.store(true, Ordering::Release);
        });
    flag
}

/// `runSandboxDaemon` — upstream `cmd/central/main.go`: `LISTEN_FDS`
/// admission, then `ServeLauncher` on fd 3. `env` is the seam the
/// grammar-level tests drive; `stderr` is the journal line writer.
/// Returns the process exit code (3 for every startup/serve failure,
/// 0 on a clean signal shutdown).
pub fn run_sandbox_daemon(env: &dyn Fn(&str) -> Option<String>, stderr: &mut dyn Write) -> u8 {
    // `strconv.Atoi(os.Getenv("LISTEN_FDS"))` must parse to >= 1.
    let raw = env("LISTEN_FDS").unwrap_or_default();
    let count = raw.parse::<i64>().unwrap_or(-1);
    if count < 1 {
        let _ = writeln!(stderr, "sandbox: no socket fd (LISTEN_FDS={raw:?})");
        return 3;
    }
    let listen = match crate::sys::audited::socket_activation_fd(0) {
        Ok(fd) => fd,
        Err(e) => {
            let _ = writeln!(stderr, "sandbox: socket fd 3: {e}");
            return 3;
        }
    };
    let svc = Arc::new(LauncherService::production());
    if let Err(e) = serve_launcher(listen, &svc, shutdown_flag()) {
        let _ = writeln!(stderr, "sandbox: {}", e.message());
        return 3;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;
    use std::os::fd::AsFd as _;

    use rustix::fs::{Mode, OFlags, open};
    use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair};

    fn pair() -> (UnixStream, UnixStream) {
        let (a, b) = socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("socketpair");
        (UnixStream::from(a), UnixStream::from(b))
    }

    fn dir_fd(path: &std::path::Path) -> OwnedFd {
        open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("dir fd")
    }

    /// A service admitting this test process (runtime uid = euid).
    fn test_service() -> LauncherService {
        LauncherService {
            runtime_uid: rustix::process::geteuid().as_raw(),
            launcher: LauncherConfig::default(),
        }
    }

    /// Send one descriptor-bound request frame and read the response
    /// line.
    fn exchange(
        conn: &mut UnixStream,
        json: &str,
        fds: &[std::os::fd::BorrowedFd<'_>],
    ) -> serde_json::Value {
        let mut frame = String::from(json);
        frame.push('\n');
        scm_rights::send(&*conn, frame.as_bytes(), fds).expect("send");
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        while conn.read(&mut byte).expect("read") == 1 {
            if byte[0] == b'\n' {
                break;
            }
            line.push(byte[0]);
            assert!(line.len() <= 4096, "response line unbounded");
        }
        serde_json::from_slice(&line).expect("json response")
    }

    /// The workspace fd every test request needs — a real directory.
    fn workspace() -> OwnedFd {
        dir_fd(std::path::Path::new("/tmp"))
    }

    /// The peer gate: a uid that is neither root nor the runtime uid
    /// is refused before a request byte is read — `authority denied`.
    #[test]
    fn wrong_caller_is_denied() {
        if rustix::process::geteuid().is_root() {
            return; // root is always admitted — the wrong-caller shape needs a non-root peer
        }
        let svc = LauncherService {
            runtime_uid: rustix::process::geteuid().as_raw() + 1,
            launcher: LauncherConfig::default(),
        };
        let (mut server_side, mut client) = pair();
        let handle = std::thread::spawn(move || handle_launch_conn(&mut server_side, &svc));
        let ws = workspace();
        let resp = exchange(
            &mut client,
            r#"{"exec_binary":"central-agent"}"#,
            &[ws.as_fd()],
        );
        assert_eq!(resp["outcome"], "error");
        assert_eq!(resp["reason"], "authority denied");
        let err = handle.join().expect("join").unwrap_err();
        assert_eq!(err.code(), "sandbox_denied");
        assert!(err.message().contains("denied UID"));
    }

    /// A frame with *no* descriptor is the path-only launch attempt —
    /// `sys_scm_rights_denied`.
    #[test]
    fn missing_descriptor_is_denied() {
        let svc = test_service();
        let (mut server_side, mut client) = pair();
        let handle = std::thread::spawn(move || handle_launch_conn(&mut server_side, &svc));
        let resp = exchange(&mut client, r#"{"exec_binary":"central-agent"}"#, &[]);
        assert_eq!(resp["outcome"], "error");
        assert!(
            resp["reason"].as_str().unwrap().contains("SCM_RIGHTS"),
            "got: {resp}"
        );
        let err = handle.join().expect("join").unwrap_err();
        assert_eq!(err.code(), "sys_scm_rights_denied");
    }

    /// Two descriptors — the extra-fd shape the strict receiver
    /// refuses.
    #[test]
    fn extra_descriptors_are_denied() {
        let svc = test_service();
        let (mut server_side, mut client) = pair();
        let handle = std::thread::spawn(move || handle_launch_conn(&mut server_side, &svc));
        let ws1 = workspace();
        let ws2 = workspace();
        let resp = exchange(
            &mut client,
            r#"{"exec_binary":"central-agent"}"#,
            &[ws1.as_fd(), ws2.as_fd()],
        );
        assert_eq!(resp["outcome"], "error");
        let err = handle.join().expect("join").unwrap_err();
        assert_eq!(err.code(), "sys_scm_rights_denied");
        assert!(err.message().contains("single descriptor"));
    }

    /// A non-directory descriptor is the descriptor-replay/substitution
    /// refusal.
    #[test]
    fn non_directory_descriptor_is_denied() {
        let svc = test_service();
        let (mut server_side, mut client) = pair();
        let path = std::env::temp_dir().join(format!("central-d-{}", std::process::id()));
        std::fs::write(&path, b"x").expect("file");
        let file_fd: OwnedFd = std::fs::File::open(&path).expect("open").into();
        let handle = std::thread::spawn(move || handle_launch_conn(&mut server_side, &svc));
        let resp = exchange(
            &mut client,
            r#"{"exec_binary":"central-agent","resource_limits":{"cpu":0.5}}"#,
            &[file_fd.as_fd()],
        );
        assert_eq!(resp["outcome"], "error");
        assert_eq!(resp["reason"], "sandbox: workspace root is not a directory");
        let err = handle.join().expect("join").unwrap_err();
        assert_eq!(err.code(), "sandbox_denied");
        std::fs::remove_file(&path).ok();
    }

    /// `env` injection — a caller-supplied `KEY=VALUE` list is the
    /// ambient-authority route the port closes.
    #[test]
    fn env_injection_is_denied() {
        let svc = test_service();
        let (mut server_side, mut client) = pair();
        let handle = std::thread::spawn(move || handle_launch_conn(&mut server_side, &svc));
        let ws = workspace();
        let resp = exchange(
            &mut client,
            r#"{"exec_binary":"central-agent","env":["PATH=/evil","LD_PRELOAD=/x.so"]}"#,
            &[ws.as_fd()],
        );
        assert_eq!(resp["outcome"], "error");
        assert_eq!(resp["reason"], "sandbox: request env is not admitted");
        let err = handle.join().expect("join").unwrap_err();
        assert_eq!(err.code(), "sandbox_denied");
    }

    /// Absolute-path escapes — in `exec_binary` (the unknown-class
    /// refusal) and in argv (the absolute-path argument refusal).
    #[test]
    fn absolute_path_escapes_are_denied() {
        let svc = test_service();
        // exec_binary path
        let (mut s1, mut c1) = pair();
        let h1 = std::thread::spawn(move || handle_launch_conn(&mut s1, &svc));
        let ws = workspace();
        let resp = exchange(&mut c1, r#"{"exec_binary":"/etc/passwd"}"#, &[ws.as_fd()]);
        assert_eq!(resp["outcome"], "error");
        assert_eq!(
            resp["reason"],
            "sandbox: unknown executable class: \"/etc/passwd\""
        );
        h1.join().expect("join").unwrap_err();

        // argv path
        let svc = test_service();
        let (mut s2, mut c2) = pair();
        let h2 = std::thread::spawn(move || handle_launch_conn(&mut s2, &svc));
        let ws = workspace();
        let resp = exchange(
            &mut c2,
            r#"{"exec_binary":"central-agent","args":["/etc/shadow"]}"#,
            &[ws.as_fd()],
        );
        assert_eq!(resp["outcome"], "error");
        assert!(
            resp["reason"].as_str().unwrap().contains("absolute-path"),
            "got: {resp}"
        );
        h2.join().expect("join").unwrap_err();
    }

    /// `../` components in argv — the traversal shape.
    #[test]
    fn parent_directory_arguments_are_denied() {
        for bad in ["../escape", "a/../b", "--flag=../x"] {
            let svc = test_service();
            let (mut server_side, mut client) = pair();
            let handle = std::thread::spawn(move || handle_launch_conn(&mut server_side, &svc));
            let ws = workspace();
            let resp = exchange(
                &mut client,
                &format!(r#"{{"exec_binary":"central-agent","args":["{bad}"]}}"#),
                &[ws.as_fd()],
            );
            assert_eq!(resp["outcome"], "error", "{bad}");
            assert!(
                resp["reason"]
                    .as_str()
                    .unwrap()
                    .contains("parent-directory"),
                "{bad}: {resp}"
            );
            handle.join().expect("join").unwrap_err();
        }
    }

    /// A forged numeric `workspace_root_fd` JSON field — the
    /// path-in-payload escape — is an unknown-field refusal.
    #[test]
    fn forged_workspace_field_is_denied() {
        let svc = test_service();
        let (mut server_side, mut client) = pair();
        let handle = std::thread::spawn(move || handle_launch_conn(&mut server_side, &svc));
        let ws = workspace();
        let resp = exchange(
            &mut client,
            r#"{"exec_binary":"central-agent","workspace_root_fd":7}"#,
            &[ws.as_fd()],
        );
        assert_eq!(resp["outcome"], "error");
        assert!(
            resp["reason"]
                .as_str()
                .unwrap()
                .contains("invalid launch request"),
            "got: {resp}"
        );
        let err = handle.join().expect("join").unwrap_err();
        assert_eq!(err.code(), "sandbox_invalid");
    }

    /// Deadline outside the cap — upstream `LaunchService`'s 600 s
    /// bound, plus the negative-value refusal.
    #[test]
    fn deadline_outside_bounds_is_denied() {
        for ms in [601_000_000_000i64, -1] {
            let svc = test_service();
            let (mut server_side, mut client) = pair();
            let handle = std::thread::spawn(move || handle_launch_conn(&mut server_side, &svc));
            let ws = workspace();
            let resp = exchange(
                &mut client,
                &format!(r#"{{"exec_binary":"central-agent","deadline_ms":{ms}}}"#),
                &[ws.as_fd()],
            );
            assert_eq!(resp["outcome"], "error", "{ms}");
            assert!(
                resp["reason"].as_str().unwrap().contains("deadline"),
                "{ms}: {resp}"
            );
            handle.join().expect("join").unwrap_err();
        }
    }

    /// The end-to-end admit path as a non-root caller: peer ok, one
    /// dir fd, well-formed request — the launch reaches the privileged
    /// cgroup step and fails there (`sandbox: cgroup:`), proving every
    /// admission gate passed.
    #[test]
    fn well_formed_request_reaches_the_launch_path() {
        if rustix::process::geteuid().is_root() {
            return; // root would pass the cgroup step — different outcome
        }
        let svc = test_service();
        let (mut server_side, mut client) = pair();
        let handle = std::thread::spawn(move || handle_launch_conn(&mut server_side, &svc));
        let ws = workspace();
        let resp = exchange(
            &mut client,
            r#"{"operation_id":"op-t9","exec_binary":"central-agent","args":["--check"],"resource_limits":{"cpu":0.5,"memory_bytes":268435456,"max_processes":32,"max_file_descriptors":64}}"#,
            &[ws.as_fd()],
        );
        assert_eq!(resp["outcome"], "error");
        assert!(
            resp["reason"]
                .as_str()
                .unwrap()
                .starts_with("sandbox: cgroup:"),
            "want cgroup-stage refusal, got: {resp}"
        );
        handle.join().expect("join").unwrap_err();
    }

    /// `run_sandbox_daemon`'s own `LISTEN_FDS` check — unset,
    /// malformed, zero: upstream's line at exit 3.
    #[test]
    fn missing_listen_fds_exits_3() {
        use std::collections::HashMap;
        for raw in ["", "abc", "0", "-1"] {
            let map: HashMap<String, String> = [("LISTEN_FDS".to_owned(), raw.to_owned())]
                .into_iter()
                .collect();
            let env = |k: &str| map.get(k).cloned();
            let mut stderr = Vec::new();
            assert_eq!(run_sandbox_daemon(&env, &mut stderr), 3, "{raw:?}");
            assert_eq!(
                String::from_utf8(stderr).unwrap(),
                format!("sandbox: no socket fd (LISTEN_FDS={raw:?})\n")
            );
        }
    }
}
