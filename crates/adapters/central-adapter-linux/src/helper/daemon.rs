//! `runHelperDaemon` (`cmd/central/main.go`) — the `--helper` mode's
//! whole body after the mode gates: `LISTEN_FDS` admission, the
//! genesis/instance branch, `helperPeerPolicyFromEnvironment`, signal
//! cancellation, and `Serve`/`ServeGenesis` on the systemd-supplied
//! descriptor 3.
//!
//! What this slice composes is deliberately the protocol shell: the
//! peer and socket policies, the closed matrix, the genesis transport
//! (init admitted, everything else denied), and `prepare`'s explicit
//! unavailable answer. The handlers that need the T13 genesis core,
//! the infralifecycle service, the advisory evaluator, or the broker
//! are the later tasks' composition; their verbs keep upstream's
//! unconfigured-handler answers, never a made-up success.

use super::PeerIdentity;
use super::client::PRODUCTION_SOCKET_PATH;
use super::init::{INIT_REASON_HELPER_UNAVAILABLE, InitHandler, InitRequest, new_init_denial};
use super::prepare::UnavailablePrepareHandler;
use super::protocol::Response;
use super::server::{GenesisServer, PeerPolicy, Server, SocketPolicy, serve, serve_genesis};
use std::io::Write;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// `helperPeerPolicyFromEnvironment` — operator ids from
/// `CENTRAL_OPERATOR_UID`/`CENTRAL_OPERATOR_GID` (nonzero `ParseUint`
/// results only); the daemon uid is 0 and the socket policy names the
/// configured socket path, owner root, operator group, 0660.
///
/// Upstream's `strconv.ParseUint(_, 10, 32)` accepts a leading `+`
/// but no whitespace or sign-minus; nonzero required.
fn parse_u32_strict(raw: &str) -> Option<u32> {
    if raw.is_empty() {
        return None;
    }
    let digits = raw.strip_prefix('+').unwrap_or(raw);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u32>().ok()
}

pub fn helper_peer_policy_from_env(
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<(PeerPolicy, SocketPolicy), String> {
    let uid = env("CENTRAL_OPERATOR_UID")
        .and_then(|v| parse_u32_strict(&v))
        .filter(|v| *v != 0);
    let Some(uid) = uid else {
        return Err("operator UID policy is not provisioned".to_owned());
    };
    let gid = env("CENTRAL_OPERATOR_GID")
        .and_then(|v| parse_u32_strict(&v))
        .filter(|v| *v != 0);
    let Some(gid) = gid else {
        return Err("operator GID policy is not provisioned".to_owned());
    };
    Ok((
        PeerPolicy {
            daemon_uid: 0,
            operator_uid: uid,
            operator_gid: gid,
        },
        SocketPolicy {
            path: helper_socket_path(env),
            owner_uid: 0,
            group_gid: gid,
            mode: 0o660,
        },
    ))
}

/// `helperSocketPath` — `CENTRAL_HELPER_SOCKET` or the production path.
pub fn helper_socket_path(env: &dyn Fn(&str) -> Option<String>) -> String {
    env("CENTRAL_HELPER_SOCKET")
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| PRODUCTION_SOCKET_PATH.to_owned())
}

/// The init answer the genesis transport installs before the T13
/// genesis core exists: `HELPER_UNAVAILABLE` at exit 3, the closed
/// refusal upstream's `helperUnavailable` class produces. The
/// transport — admission, the init-only allowlist, the stop rules —
/// is real; the genesis core it would call is the deferred part.
struct UnavailableInitHandler;

impl InitHandler for UnavailableInitHandler {
    fn init(&self, _peer: PeerIdentity, _deadline: Instant, request: InitRequest) -> Response {
        let _ = &request;
        new_init_denial(&request.operation_id, 3, INIT_REASON_HELPER_UNAVAILABLE)
    }
}

/// The daemon's shared accept-loop budget — `60 * time.Second`,
/// upstream's `Serve(ctx, 3, srv, 60*time.Second)`.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// `runHelperDaemon` — returns the process exit code; `stderr` is the
/// daemon's journal line writer. `env` is the environment seam so the
/// grammar-level tests can exercise the failure arms without systemd.
/// `genesis_absent` is the mode split upstream takes from
/// `productionGenesisEnv().state(ctx)`; a broken state lands on the
/// instance branch, exactly as `helperModeFor` decides.
pub fn run_helper_daemon(
    genesis_absent: bool,
    env: &dyn Fn(&str) -> Option<String>,
    stderr: &mut dyn Write,
) -> u8 {
    // `strconv.Atoi(os.Getenv("LISTEN_FDS"))` must parse to >= 1: the
    // activated descriptor count, with fd 3 the socket.
    let raw = env("LISTEN_FDS").unwrap_or_default();
    let count = raw.parse::<i64>().unwrap_or(-1);
    if count < 1 {
        let _ = writeln!(stderr, "helper: no socket fd (LISTEN_FDS={raw:?})");
        return 3;
    }
    let (peer, socket) = match helper_peer_policy_from_env(env) {
        Ok(ok) => ok,
        Err(e) => {
            let which = if genesis_absent {
                "genesis composition"
            } else {
                "composition"
            };
            let _ = writeln!(stderr, "helper: {which}: {e}");
            return 6;
        }
    };
    let (cancel, _waiter) = match cancel_on_signal() {
        Ok(pair) => pair,
        Err(e) => {
            let _ = writeln!(stderr, "{e}");
            return 3;
        }
    };
    // fd 3 = activation index 0, proven open by F_GETFD before the
    // audited wrapper claims ownership.
    let listen = match crate::sys::audited::socket_activation_fd(0) {
        Ok(fd) => fd,
        Err(e) => {
            let _ = writeln!(stderr, "helper: socket fd 3: {e}");
            return 3;
        }
    };
    if genesis_absent {
        let srv = Arc::new(GenesisServer {
            peer_policy: Some(peer),
            socket: Some(socket),
            init: Box::new(UnavailableInitHandler),
            auditor: None,
        });
        if let Err(e) = serve_genesis(listen, &srv, IDLE_TIMEOUT, cancel) {
            let _ = writeln!(stderr, "helper: {e}");
            return 3;
        }
        return 0;
    }
    let srv = Arc::new(Server {
        peer_policy: Some(peer),
        socket: Some(socket),
        // A host that cannot compose the prepare graph still serves
        // every other verb; it refuses explicitly rather than being
        // left unset — upstream's `unavailablePrepareHandler`. The real
        // pipeline exists at `infra::prepare::new_prepare_handler`
        // (service + handler, `PreparePamConfirmer` implemented on
        // `PamConfirmer`); what this daemon still lacks is a production
        // `EvaluateService` (advisory evaluation is a later task's
        // seam), so the handler stays the explicit refusal until that
        // composition can complete — upstream's rule verbatim.
        prepare: Some(Box::new(UnavailablePrepareHandler)),
        ..Server::new()
    });
    if let Err(e) = serve(listen, &srv, IDLE_TIMEOUT, cancel) {
        let _ = writeln!(stderr, "helper: {e}");
        return 3;
    }
    0
}

/// `signal.NotifyContext(SIGINT, SIGTERM)` — an eventfd that becomes
/// readable when either signal arrives, via a current-thread tokio
/// runtime on a spawned waiter (tokio is the workspace's signal
/// owner). The write end is a duplicated descriptor so the waiter may
/// outlive the server's return path without keeping it alive.
fn cancel_on_signal() -> Result<(OwnedFd, std::thread::JoinHandle<()>), String> {
    let efd = rustix::event::eventfd(0, rustix::event::EventfdFlags::CLOEXEC)
        .map_err(|e| format!("helper: cancel fd: {e}"))?;
    let writer = efd
        .try_clone()
        .map_err(|e| format!("helper: cancel fd: {e}"))?;
    let waiter = std::thread::Builder::new()
        .name("helper-signal".to_owned())
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
            let _ = rustix::io::write(&writer, &1u64.to_ne_bytes());
        })
        .map_err(|e| format!("helper: cancel waiter: {e}"))?;
    Ok((efd, waiter))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| map.get(k).cloned()
    }

    /// `helperPeerPolicyFromEnvironment` — unset, malformed, and zero
    /// collapse to the two provisioned-policy messages; `+1` parses
    /// like upstream `ParseUint`.
    #[test]
    fn peer_policy_from_env() {
        let empty = env_of(&[]);
        assert_eq!(
            helper_peer_policy_from_env(&empty).unwrap_err(),
            "operator UID policy is not provisioned"
        );
        for bad in ["", "abc", "-1", " 1", "0", "4294967296"] {
            let env = env_of(&[("CENTRAL_OPERATOR_UID", bad), ("CENTRAL_OPERATOR_GID", "1")]);
            assert_eq!(
                helper_peer_policy_from_env(&env).unwrap_err(),
                "operator UID policy is not provisioned",
                "{bad:?}"
            );
        }
        let no_gid = env_of(&[("CENTRAL_OPERATOR_UID", "1000")]);
        assert_eq!(
            helper_peer_policy_from_env(&no_gid).unwrap_err(),
            "operator GID policy is not provisioned"
        );
        let env = env_of(&[
            ("CENTRAL_OPERATOR_UID", "+1000"),
            ("CENTRAL_OPERATOR_GID", "1001"),
        ]);
        let (peer, socket) = helper_peer_policy_from_env(&env).unwrap();
        assert_eq!(peer.daemon_uid, 0);
        assert_eq!(peer.operator_uid, 1000);
        assert_eq!(peer.operator_gid, 1001);
        assert_eq!(socket.path, PRODUCTION_SOCKET_PATH);
        assert_eq!(socket.owner_uid, 0);
        assert_eq!(socket.group_gid, 1001);
        assert_eq!(socket.mode & 0o777, 0o660);
    }

    /// The env socket override wins; the production path is the default.
    #[test]
    fn socket_path_env_override() {
        let env = env_of(&[("CENTRAL_HELPER_SOCKET", "/run/test/helper.sock")]);
        assert_eq!(helper_socket_path(&env), "/run/test/helper.sock");
        let env = env_of(&[("CENTRAL_HELPER_SOCKET", "")]);
        assert_eq!(helper_socket_path(&env), PRODUCTION_SOCKET_PATH);
    }

    /// `runHelperDaemon`'s own LISTEN_FDS check: unset, malformed, and
    /// zero each print upstream's `no socket fd` line and exit 3 —
    /// before any composition is attempted.
    #[test]
    fn missing_listen_fds_exits_3() {
        for raw in ["", "abc", "0", "-1"] {
            let env = env_of(&[("LISTEN_FDS", raw)]);
            let mut stderr = Vec::new();
            assert_eq!(run_helper_daemon(true, &env, &mut stderr), 3, "{raw:?}");
            assert_eq!(
                String::from_utf8(stderr).unwrap(),
                format!("helper: no socket fd (LISTEN_FDS={raw:?})\n")
            );
        }
        // With LISTEN_FDS present but no operator ids: composition
        // fails at 6 on the right branch name.
        let env = env_of(&[("LISTEN_FDS", "1")]);
        let mut stderr = Vec::new();
        assert_eq!(run_helper_daemon(true, &env, &mut stderr), 6);
        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            "helper: genesis composition: operator UID policy is not provisioned\n"
        );
        let env = env_of(&[("LISTEN_FDS", "1")]);
        let mut stderr = Vec::new();
        assert_eq!(run_helper_daemon(false, &env, &mut stderr), 6);
        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            "helper: composition: operator UID policy is not provisioned\n"
        );
    }
}
