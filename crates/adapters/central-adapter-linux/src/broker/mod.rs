//! The protected broker — the R5 Task 6 port of upstream
//! `internal/adapter/authority/broker`: wire protocol, socket-activated
//! server, authority-transition journal, `protected_file_v1` backend,
//! payload-epoch store, provisioning records, and the proof/lifecycle
//! services.
//!
//! Every module in this tree is `#[forbid(unsafe_code)]`: the only
//! `unsafe` this broker ever needs is the audited syscall boundary in
//! [`crate::sys`] (SCM_RIGHTS, memfd, `openat2`, `SO_PEERCRED`, the
//! socket-activation fd claim) — and the descriptor transports re-use
//! those primitives rather than re-implementing them.
//!
//! Slice boundary: B04/B05/B10 secret-bootstrap internals (the
//! bootstrap session, launch-evidence stores, MinIO runtime binding,
//! recovery journal, TLS authority) and the entire backup/restore/
//! migration-launch surface are R6; [`server::Service::dispatch`]
//! registers those purposes as closed denials so the wire contract is
//! complete before the machinery lands.

/// `broker.ProductionSocketPath` — where
/// `packaging/systemd/central-broker.socket` binds the protected
/// broker for the runtime's `BootstrapActivator`/presenter clients
/// (upstream `internal/adapter/authority/broker/socket_path.go`).
/// `CENTRAL_BROKER_SOCKET` overrides it for the reference-host test
/// composition; the kernel names the env once in
/// `harness_compose::ENV_BROKER_SOCKET`.
pub const PRODUCTION_SOCKET_PATH: &str = "/run/central-broker/broker.sock";

pub mod bootstrap_session;
pub mod daemon;
pub(crate) mod deadline;
pub(crate) mod durable;
pub mod export_token;
pub mod handoff;
pub mod journal;
pub mod lifecycle;
pub mod lifecycle_client;
pub mod payload_epoch;
pub mod proof;
pub mod protected_file;
pub mod protocol;
pub mod provisioning;
pub mod secret_bootstrap;
pub mod server;
pub mod signing;
pub mod tls;
pub(crate) mod wire;
// No `xdg` module: the signed XDG-view surface is upstream's
// `central.view-signature/v1` envelope (`internal/config/view.go`),
// already ported at `central_infra::config::view` (R5 Task 2). The
// broker emits no projections in this slice — a custom schema here
// would be dead code carrying an unverified authority claim, so the
// surface stays closed until a consumer needs it.

#[cfg(test)]
pub(crate) mod testutil {
    use std::path::{Path, PathBuf};

    /// `t.TempDir` — a unique scratch root removed on drop.
    pub(crate) struct TempDir(PathBuf);

    impl TempDir {
        pub(crate) fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "central-broker-{tag}-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    impl std::ops::Deref for TempDir {
        type Target = Path;
        fn deref(&self) -> &Path {
            &self.0
        }
    }

    /// A `Service` whose peer gates admit this test process: the
    /// runtime uid is the effective uid, exactly as production binds
    /// `CENTRAL_RUNTIME_UID`.
    pub(crate) fn service(dir: &Path) -> super::server::Service {
        super::server::Service::new(dir.to_path_buf(), rustix::process::geteuid().as_raw()).unwrap()
    }
}
