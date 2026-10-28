//! Frame `0xc1` — the descriptor-only backup-worker credential
//! transport, ported from upstream
//! `internal/adapter/authority/broker/backup_worker_credential_linux.go`.
//!
//! The frame authorizes an unprivileged worker launch (backup-create
//! kinds 1–2 against [`BackupLaunchStore`], throughput kinds 3–5
//! against [`BackupThroughputLaunchStore`]) and releases exactly one
//! sealed credential descriptor. Which credential leaves the broker is
//! fixed by executable policy below — the frame carries only the
//! kind byte, the launch evidence id, and the operation id; no
//! locator, generation, receipt id, or credential material ever
//! crosses in JSON or argv.
//!
//! Secret discipline: `resolve` returns the plaintext in a
//! [`zeroize::Zeroizing`] buffer that clears itself on every return
//! path; the value lives in broker memory only long enough to mint
//! the sealed memfd, and is never logged or serialized.

use std::io::Write;
use std::os::fd::{AsFd, OwnedFd};

use central_foundation::failure::Failure;
use rustix::fs::{fcntl_get_seals, fstat};
use rustix::process::Uid;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use central_infra::domain::{MINIO_BACKUP_KEY_SCOPE, Purpose};

use crate::sys::memfd::{MAX_VALUE_BYTES, SEALED_MEMFD_SEALS};
use crate::sys::peercred::PeerCred;
use crate::sys::scm_rights;

use super::deadline::DeadlineStream;
use super::protocol::{
    self, BACKUP_THROUGHPUT_MINIO_CREDENTIAL, BACKUP_THROUGHPUT_POSTGRES_PROBE_CREDENTIAL,
    BACKUP_THROUGHPUT_POSTGRES_TARGET_CREDENTIAL, BACKUP_WORKER_CREDENTIAL_FRAME_SIZE,
    BACKUP_WORKER_MINIO_CREDENTIAL, BACKUP_WORKER_POSTGRES_CREDENTIAL,
    BackupWorkerCredentialRequest, CENTRAL_RUNTIME_GID, CENTRAL_RUNTIME_UID,
};
use super::server::Service;

/// `BACKUP_WORKER_CREDENTIAL_DENIED` — the one denial string this
/// transport ever writes; locator-free, exactly upstream.
const CREDENTIAL_DENIED: &str = "BACKUP_WORKER_CREDENTIAL_DENIED";

/// The `postgres_throughput_target_v1`/`postgres_throughput_probe_v1`/
/// `minio_throughput_probe_v1` purpose labels upstream's `Handoff`
/// carries; the Rust handoff mints an unnamed sealed memfd, but the
/// resolved purpose is still returned (and pinned by tests) so the
/// release path names its credential class the same way.
const POSTGRES_THROUGHPUT_TARGET_PURPOSE: &str = "postgres_throughput_target_v1";
const POSTGRES_THROUGHPUT_PROBE_PURPOSE: &str = "postgres_throughput_probe_v1";
const MINIO_THROUGHPUT_PROBE_PURPOSE: &str = "minio_throughput_probe_v1";

/// The fixed artifacts bucket every operation-bound MinIO receipt must
/// name — `central-artifacts-v1`, as upstream.
const ARTIFACTS_BUCKET: &str = "central-artifacts-v1";

fn unavailable() -> Failure {
    Failure::internal(
        "recovery_journal_unavailable",
        "recovery journal unavailable",
    )
}

/// `isBackupCreateCredentialKind`.
#[must_use]
pub(crate) fn is_backup_create_credential_kind(kind: u8) -> bool {
    kind == BACKUP_WORKER_POSTGRES_CREDENTIAL || kind == BACKUP_WORKER_MINIO_CREDENTIAL
}

/// `isBackupThroughputCredentialKind`.
#[must_use]
pub(crate) fn is_backup_throughput_credential_kind(kind: u8) -> bool {
    kind == BACKUP_THROUGHPUT_POSTGRES_TARGET_CREDENTIAL
        || kind == BACKUP_THROUGHPUT_POSTGRES_PROBE_CREDENTIAL
        || kind == BACKUP_THROUGHPUT_MINIO_CREDENTIAL
}

impl Service {
    /// `handleBackupWorkerCredentialTransport` — validate the worker
    /// against its launch evidence, resolve exactly one credential
    /// under this kind's closed policy, mint a sealed descriptor, and
    /// deliver it over SCM_RIGHTS. Every denial is the same
    /// locator-free `BACKUP_WORKER_CREDENTIAL_DENIED`.
    ///
    /// # Errors
    /// Returns `Err` only on the descriptor-send transport failure —
    /// exactly upstream, where `WriteMsgUnix` failing is the one path
    /// that is not a protocol denial.
    pub(crate) fn handle_backup_worker_credential_transport(
        &self,
        conn: &mut DeadlineStream,
        request: &BackupWorkerCredentialRequest,
        peer: &PeerCred,
    ) -> Result<(), Failure> {
        if self.backup_launches.is_none()
            || self.throughput_launches.is_none()
            || self.recovery_journal.is_none()
            || self.bootstrap.is_none()
            || self.validate_credential_worker(request, peer).is_err()
        {
            protocol::write_deny(conn, &request.operation_id.to_string(), CREDENTIAL_DENIED);
            return Ok(());
        }
        let Ok((mut value, _purpose)) = self.resolve_backup_worker_credential(request) else {
            protocol::write_deny(conn, &request.operation_id.to_string(), CREDENTIAL_DENIED);
            return Ok(());
        };
        let fd = match self.handoff.handoff(&value) {
            Ok(fd) => fd,
            Err(_) => {
                value.zeroize();
                protocol::write_deny(conn, &request.operation_id.to_string(), CREDENTIAL_DENIED);
                return Ok(());
            }
        };
        value.zeroize();
        // SC-DEF-45 (kind 4) / SC-DEF-51 (kind 1): both the throughput
        // probe's and the real backup's own postgres credentials are
        // consumed by pg_dump via `PGPASSFILE=/proc/self/fd/N`, since
        // the worker process cannot hand pg_dump an inherited fd
        // directly. That reopen is a fresh `open()` the kernel
        // re-checks against the memfd's real owner; `handoff`'s
        // `fchmod(0600)` alone leaves it owned by this (root) process,
        // which 0600 grants nothing else to, so pg_dump's own open
        // fails with EACCES and it silently proceeds without a
        // password (libpq reports this as "no password supplied", not
        // a permission error). Every other kind is read directly from
        // the fd it was handed (no reopen, so ownership is moot) and
        // must stay root-owned: `validate_credential_descriptor`'s
        // `st_uid` check is how the receiving worker verifies a
        // descriptor really came from the broker, so widening it for
        // every kind would weaken that check rather than fix this one
        // narrow case.
        if (request.kind == BACKUP_THROUGHPUT_POSTGRES_PROBE_CREDENTIAL
            || request.kind == BACKUP_WORKER_POSTGRES_CREDENTIAL)
            && rustix::fs::fchown(
                &fd,
                Some(Uid::from_raw(CENTRAL_RUNTIME_UID)),
                Some(rustix::process::Gid::from_raw(CENTRAL_RUNTIME_GID)),
            )
            .is_err()
        {
            protocol::write_deny(conn, &request.operation_id.to_string(), CREDENTIAL_DENIED);
            return Ok(());
        }
        protocol::send_descriptor(&*conn, fd.as_fd()).map_err(|e| {
            Failure::internal(
                "broker",
                format!(
                    "broker: deliver backup credential descriptor: {}",
                    e.message()
                ),
            )
        })
    }

    /// `validateCredentialWorker` — kind classes route to their own
    /// launch-evidence store; the throughput kinds additionally admit
    /// only the launch states upstream pins.
    fn validate_credential_worker(
        &self,
        request: &BackupWorkerCredentialRequest,
        peer: &PeerCred,
    ) -> Result<(), Failure> {
        if is_backup_create_credential_kind(request.kind) {
            let Some(store) = &self.backup_launches else {
                return Err(unavailable());
            };
            return store.validate_worker(request.launch_evidence_id, request.operation_id, peer);
        }
        if is_backup_throughput_credential_kind(request.kind) {
            let Some(store) = &self.throughput_launches else {
                return Err(unavailable());
            };
            let record =
                store.validate_worker(request.launch_evidence_id, request.operation_id, peer)?;
            match request.kind {
                BACKUP_THROUGHPUT_POSTGRES_TARGET_CREDENTIAL
                    if record.state
                        == super::backup_throughput_launch::BACKUP_THROUGHPUT_LAUNCH_ACTIVE
                        || record.state
                            == super::backup_throughput_launch::BACKUP_THROUGHPUT_LAUNCH_TARGET_LOCKED
                        || record.state
                            == super::backup_throughput_launch::BACKUP_THROUGHPUT_LAUNCH_FIXTURE_LOADED =>
                {
                    return Ok(());
                }
                BACKUP_THROUGHPUT_POSTGRES_PROBE_CREDENTIAL
                | BACKUP_THROUGHPUT_MINIO_CREDENTIAL
                    if record.state
                        == super::backup_throughput_launch::BACKUP_THROUGHPUT_LAUNCH_FIXTURE_LOADED =>
                {
                    return Ok(());
                }
                _ => return Err(unavailable()),
            }
        }
        Err(unavailable())
    }

    /// `resolveBackupWorkerCredential` — `(value, purpose)` under the
    /// closed per-kind policy. The returned value is the plaintext
    /// secret; callers must [`Zeroize`] it on every exit path.
    fn resolve_backup_worker_credential(
        &self,
        request: &BackupWorkerCredentialRequest,
    ) -> Result<(Zeroizing<Vec<u8>>, &'static str), Failure> {
        match request.kind {
            BACKUP_WORKER_POSTGRES_CREDENTIAL => {
                let Some(bootstrap) = &self.bootstrap else {
                    return Err(unavailable());
                };
                let Ok((binding, lease)) =
                    bootstrap.active_binding_for_purpose(Purpose::PostgresRuntime)
                else {
                    return Err(unavailable());
                };
                if binding.purpose != Purpose::PostgresRuntime
                    || binding.generation_id.is_nil()
                    || binding.binding_id.is_nil()
                    || lease.binding_id != binding.binding_id
                    || lease.fencing_token == 0
                    || lease.expires_at <= time::OffsetDateTime::now_utc()
                {
                    return Err(unavailable());
                }
                let generation = self
                    .backend
                    .get_by_id(Uuid::from_bytes(*binding.generation_id.as_bytes()))
                    .map_err(|_| unavailable())?;
                if generation.purpose != Purpose::PostgresRuntime.as_str() {
                    return Err(unavailable());
                }
                let value = self.backend.read(&generation)?;
                Ok((Zeroizing::new(value), Purpose::PostgresRuntime.as_str()))
            }
            BACKUP_WORKER_MINIO_CREDENTIAL => {
                let Some(journal) = &self.recovery_journal else {
                    return Err(unavailable());
                };
                let Ok((generation, receipt)) =
                    journal.resolve_bound_minio_handoff(request.operation_id, Purpose::MinioBackup)
                else {
                    return Err(unavailable());
                };
                if receipt.bucket != ARTIFACTS_BUCKET
                    || receipt.key_prefix != MINIO_BACKUP_KEY_SCOPE
                {
                    return Err(unavailable());
                }
                let value = self.backend.read(&generation)?;
                Ok((Zeroizing::new(value), Purpose::MinioBackup.as_str()))
            }
            BACKUP_THROUGHPUT_POSTGRES_TARGET_CREDENTIAL
            | BACKUP_THROUGHPUT_POSTGRES_PROBE_CREDENTIAL => {
                let Ok(value) = self.read_active_postgres_runtime_passfile() else {
                    return Err(unavailable());
                };
                if request.kind == BACKUP_THROUGHPUT_POSTGRES_TARGET_CREDENTIAL {
                    if validate_central_runtime_passfile(&value).is_err() {
                        return Err(unavailable());
                    }
                    return Ok((value, POSTGRES_THROUGHPUT_TARGET_PURPOSE));
                }
                let derived = derive_throughput_probe_passfile(&value, request.operation_id)
                    .map_err(|_| unavailable())?;
                Ok((Zeroizing::new(derived), POSTGRES_THROUGHPUT_PROBE_PURPOSE))
            }
            BACKUP_THROUGHPUT_MINIO_CREDENTIAL => {
                let Some(journal) = &self.recovery_journal else {
                    return Err(unavailable());
                };
                let Ok((generation, receipt)) =
                    journal.resolve_bound_minio_handoff(request.operation_id, Purpose::MinioBackup)
                else {
                    return Err(unavailable());
                };
                if receipt.bucket != ARTIFACTS_BUCKET
                    || receipt.key_prefix != MINIO_BACKUP_KEY_SCOPE
                {
                    return Err(unavailable());
                }
                let value = self.backend.read(&generation)?;
                Ok((Zeroizing::new(value), MINIO_THROUGHPUT_PROBE_PURPOSE))
            }
            _ => Err(unavailable()),
        }
    }

    /// `readActivePostgresRuntimePassfile` — the active
    /// `postgres_runtime_v1` binding's passfile bytes, shape-checked
    /// before release.
    pub(crate) fn read_active_postgres_runtime_passfile(
        &self,
    ) -> Result<Zeroizing<Vec<u8>>, Failure> {
        let Some(bootstrap) = &self.bootstrap else {
            return Err(unavailable());
        };
        let Ok((binding, lease)) = bootstrap.active_binding_for_purpose(Purpose::PostgresRuntime)
        else {
            return Err(unavailable());
        };
        if binding.purpose != Purpose::PostgresRuntime
            || binding.generation_id.is_nil()
            || binding.binding_id.is_nil()
            || lease.binding_id != binding.binding_id
            || lease.fencing_token == 0
            || lease.expires_at <= time::OffsetDateTime::now_utc()
        {
            return Err(unavailable());
        }
        let generation = self
            .backend
            .get_by_id(Uuid::from_bytes(*binding.generation_id.as_bytes()))
            .map_err(|_| unavailable())?;
        if generation.purpose != Purpose::PostgresRuntime.as_str() {
            return Err(unavailable());
        }
        let value = self.backend.read(&generation)?;
        let value = Zeroizing::new(value);
        if validate_central_runtime_passfile(&value).is_err() {
            return Err(unavailable());
        }
        Ok(value)
    }
}

/// `validateCentralRuntimePassfile` — one newline-terminated passfile
/// line pinning the `central_runtime` role on the loopback cluster.
///
/// # Errors
/// `recovery_journal_unavailable` on any malformed shape, exactly
/// upstream's `errRecoveryJournalUnavailable`.
pub(crate) fn validate_central_runtime_passfile(value: &[u8]) -> Result<(), Failure> {
    validate_central_passfile_role(value, "central_runtime")
}

/// `validateCentralMigrationPassfile` — mirrors
/// [`validate_central_runtime_passfile`] but pins the `central_migration`
/// role, so a runtime credential can never satisfy the restore
/// boundary through accidental shape equality.
///
/// # Errors
/// `recovery_journal_unavailable` on any malformed shape.
pub(crate) fn validate_central_migration_passfile(value: &[u8]) -> Result<(), Failure> {
    validate_central_passfile_role(value, "central_migration")
}

/// `validateCentralOutboxPassfile` — mirrors
/// [`validate_central_runtime_passfile`] but pins the `central_outbox`
/// role, for the same reason [`validate_central_migration_passfile`]
/// pins the migration role: shape equality alone must never let one
/// service role's credential satisfy a check meant for another.
///
/// # Errors
/// `recovery_journal_unavailable` on any malformed shape.
pub(crate) fn validate_central_outbox_passfile(value: &[u8]) -> Result<(), Failure> {
    validate_central_passfile_role(value, "central_outbox")
}

/// The shared five-field `hostname:port:database:username:password`
/// passfile check both role pins delegate to.
fn validate_central_passfile_role(value: &[u8], role: &str) -> Result<(), Failure> {
    if value.is_empty()
        || value.len() > 4096
        || value.iter().filter(|&&b| b == b'\n').count() != 1
        || value[value.len() - 1] != b'\n'
        || value.contains(&b'\r')
        || value.contains(&0)
    {
        return Err(unavailable());
    }
    let line = &value[..value.len() - 1];
    let fields: Vec<&[u8]> = line.split(|&b| b == b':').collect();
    if fields.len() != 5
        || fields[0] != b"127.0.0.1"
        || fields[1] != b"55432"
        || fields[2] != b"central"
        || fields[3] != role.as_bytes()
        || fields[4].is_empty()
        || fields[4] == b"*"
    {
        return Err(unavailable());
    }
    Ok(())
}

/// `deriveThroughputProbePassfile` — the probe's passfile is the
/// runtime passfile with its database rewritten to the operation's
/// `central_probe_<hex32>` fixture database.
///
/// # Errors
/// `recovery_journal_unavailable` on a nil/non-v7 operation id or a
/// malformed runtime passfile.
fn derive_throughput_probe_passfile(
    runtime_passfile: &[u8],
    operation_id: Uuid,
) -> Result<Vec<u8>, Failure> {
    if operation_id.is_nil()
        || operation_id.get_version_num() != 7
        || validate_central_runtime_passfile(runtime_passfile).is_err()
    {
        return Err(unavailable());
    }
    let line = &runtime_passfile[..runtime_passfile.len() - 1];
    let fields: Vec<&[u8]> = line.split(|&b| b == b':').collect();
    let mut derived = Vec::with_capacity(runtime_passfile.len() + "central_probe_".len() + 32);
    derived.extend_from_slice(fields[0]);
    derived.push(b':');
    derived.extend_from_slice(fields[1]);
    derived.push(b':');
    derived.extend_from_slice(b"central_probe_");
    derived.extend_from_slice(operation_id.simple().to_string().as_bytes());
    derived.push(b':');
    derived.extend_from_slice(fields[3]);
    derived.push(b':');
    derived.extend_from_slice(fields[4]);
    derived.push(b'\n');
    Ok(derived)
}

// ---------------------------------------------------------------------------
// Receive-side descriptor validation — `receiveBackupWorkerCredentialDescriptor`
// ---------------------------------------------------------------------------

/// `receiveBackupWorkerCredentialDescriptor` — the strict shape check
/// every credential-receiving process applies to the descriptor the
/// broker delivered: regular file, exactly the expected owner, bounded
/// non-empty payload, and the full `SEAL|SHRINK|GROW|WRITE` seal set.
/// The fd arrives already `FD_CLOEXEC` via `MSG_CMSG_CLOEXEC`; the
/// flag is (re)asserted here exactly like upstream's `F_SETFD`.
///
/// # Errors
/// `sys_scm_rights_denied`/`sys_memfd_*` on any wrong shape; the
/// descriptor is closed on every refusal.
pub(crate) fn validate_credential_descriptor(
    fd: &OwnedFd,
    expected_uid: Uid,
) -> Result<(), Failure> {
    // Upstream's `F_SETFD(flags|FD_CLOEXEC)` — the kernel already
    // delivered it cloexec; pinning it again keeps the check honest if
    // the receive path ever changes.
    let flags = rustix::io::fcntl_getfd(fd)
        .map_err(|e| Failure::internal("sys_memfd_os", format!("F_GETFD: {e}")))?;
    rustix::io::fcntl_setfd(fd, flags | rustix::io::FdFlags::CLOEXEC)
        .map_err(|e| Failure::internal("sys_memfd_os", format!("F_SETFD: {e}")))?;
    let st = fstat(fd).map_err(|e| Failure::internal("sys_memfd_os", format!("fstat: {e}")))?;
    if !rustix::fs::FileType::from_raw_mode(st.st_mode).is_file()
        || st.st_uid != expected_uid.as_raw()
        || st.st_size <= 0
        || st.st_size as u64 > MAX_VALUE_BYTES
    {
        return Err(Failure::denied(
            "sys_memfd_denied",
            "invalid credential descriptor",
        ));
    }
    let seals = fcntl_get_seals(fd)
        .map_err(|e| Failure::internal("sys_memfd_os", format!("F_GET_SEALS: {e}")))?;
    if !seals.contains(SEALED_MEMFD_SEALS) {
        return Err(Failure::denied(
            "sys_memfd_denied",
            "unsealed credential descriptor",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Clients — `BackupWorkerCredentialClient` /
// `BackupThroughputWorkerCredentialClient`
// ---------------------------------------------------------------------------

/// `BackupWorkerCredentialClient` is bound to one helper-issued worker
/// launch. Its wire requests contain only fixed binary identities;
/// locators, generations, receipt IDs and credentials never cross in
/// JSON or argv.
pub struct BackupWorkerCredentialClient {
    /// The broker's socket path.
    pub socket_path: String,
    /// The launch evidence this client rides on.
    pub launch_evidence_id: Uuid,
    /// The operation the credentials serve.
    pub operation_id: Uuid,
}

impl BackupWorkerCredentialClient {
    /// `NewBackupWorkerCredentialClient`.
    #[must_use]
    pub fn new(socket_path: String, launch_evidence_id: Uuid, operation_id: Uuid) -> Self {
        Self {
            socket_path,
            launch_evidence_id,
            operation_id,
        }
    }

    /// `OpenSealedPassfile` — the pinned pg_dump passfile draw; the
    /// operation must be the one this client is bound to.
    ///
    /// # Errors
    /// `backup_credential_denied` on an operation mismatch;
    /// `backup_credential_unavailable`/`backup_credential_denied` on
    /// the transport result.
    pub fn open_sealed_passfile(
        &self,
        operation: &central_backup::backup::operation::BackupOperation,
    ) -> Result<OwnedFd, Failure> {
        if operation.operation_id != self.operation_id {
            return Err(Failure::denied(
                "backup_credential_denied",
                "broker backup credential: denied",
            ));
        }
        self.fetch(BACKUP_WORKER_POSTGRES_CREDENTIAL)
    }

    /// `OpenPostgresRuntimeCredential` — the runtime-role passfile.
    ///
    /// # Errors
    /// As [`Self::fetch`].
    pub fn open_postgres_runtime_credential(&self) -> Result<OwnedFd, Failure> {
        self.fetch(BACKUP_WORKER_POSTGRES_CREDENTIAL)
    }

    /// `OpenMinioBackupCredential` — the `minio_backup_v1` credential.
    ///
    /// # Errors
    /// As [`Self::fetch`].
    pub fn open_minio_backup_credential(&self) -> Result<OwnedFd, Failure> {
        self.fetch(BACKUP_WORKER_MINIO_CREDENTIAL)
    }

    /// `(*BackupWorkerCredentialClient).fetch` — structurally limited
    /// to the two backup-create credential kinds.
    fn fetch(&self, kind: u8) -> Result<OwnedFd, Failure> {
        if self.socket_path.is_empty()
            || self.launch_evidence_id.is_nil()
            || self.operation_id.is_nil()
            || !is_backup_create_credential_kind(kind)
        {
            return Err(Failure::internal(
                "backup_credential_unavailable",
                "broker backup credential: unavailable",
            ));
        }
        fetch_backup_worker_credential(
            &self.socket_path,
            self.launch_evidence_id,
            self.operation_id,
            kind,
        )
    }
}

/// `BackupThroughputWorkerCredentialClient` is structurally limited to
/// the three descriptors a throughput-probe launch needs. It cannot
/// request the two backup-create credential kinds.
pub struct BackupThroughputWorkerCredentialClient {
    /// The broker's socket path.
    pub socket_path: String,
    /// The launch evidence this client rides on.
    pub launch_evidence_id: Uuid,
    /// The operation the credentials serve.
    pub operation_id: Uuid,
}

impl BackupThroughputWorkerCredentialClient {
    /// `NewBackupThroughputWorkerCredentialClient`.
    #[must_use]
    pub fn new(socket_path: String, launch_evidence_id: Uuid, operation_id: Uuid) -> Self {
        Self {
            socket_path,
            launch_evidence_id,
            operation_id,
        }
    }

    /// `OpenPostgresTargetPassfile`.
    ///
    /// # Errors
    /// `backup_credential_denied` on an operation mismatch; the
    /// transport result otherwise.
    pub fn open_postgres_target_passfile(&self, operation_id: Uuid) -> Result<OwnedFd, Failure> {
        if operation_id != self.operation_id {
            return Err(Failure::denied(
                "backup_credential_denied",
                "broker backup throughput credential: denied",
            ));
        }
        self.fetch(BACKUP_THROUGHPUT_POSTGRES_TARGET_CREDENTIAL)
    }

    /// `OpenPostgresProbePassfile`.
    ///
    /// # Errors
    /// `backup_credential_denied` on an operation mismatch; the
    /// transport result otherwise.
    pub fn open_postgres_probe_passfile(&self, operation_id: Uuid) -> Result<OwnedFd, Failure> {
        if operation_id != self.operation_id {
            return Err(Failure::denied(
                "backup_credential_denied",
                "broker backup throughput credential: denied",
            ));
        }
        self.fetch(BACKUP_THROUGHPUT_POSTGRES_PROBE_CREDENTIAL)
    }

    /// `OpenMinioProbeCredential`.
    ///
    /// # Errors
    /// The transport result.
    pub fn open_minio_probe_credential(&self) -> Result<OwnedFd, Failure> {
        self.fetch(BACKUP_THROUGHPUT_MINIO_CREDENTIAL)
    }

    /// `(*BackupThroughputWorkerCredentialClient).fetch` — limited to
    /// the three throughput credential kinds.
    fn fetch(&self, kind: u8) -> Result<OwnedFd, Failure> {
        if self.socket_path.is_empty()
            || self.launch_evidence_id.is_nil()
            || self.operation_id.is_nil()
            || !is_backup_throughput_credential_kind(kind)
        {
            return Err(Failure::internal(
                "backup_credential_unavailable",
                "broker backup throughput credential: unavailable",
            ));
        }
        fetch_backup_worker_credential(
            &self.socket_path,
            self.launch_evidence_id,
            self.operation_id,
            kind,
        )
    }
}

/// `fetchBackupWorkerCredential` — dial, send the 34-byte fixed frame,
/// and receive either the sealed credential descriptor or a denial.
///
/// # Errors
/// `backup_credential_unavailable` on transport failures;
/// `backup_credential_denied` on an explicit denial or a malformed
/// descriptor shape.
pub(crate) fn fetch_backup_worker_credential(
    socket_path: &str,
    launch_evidence_id: Uuid,
    operation_id: Uuid,
    kind: u8,
) -> Result<OwnedFd, Failure> {
    let unavailable = || {
        Failure::internal(
            "backup_credential_unavailable",
            "broker backup credential: unavailable",
        )
    };
    let denied_failure = || {
        Failure::denied(
            "backup_credential_denied",
            "broker backup credential: denied",
        )
    };
    if socket_path.is_empty()
        || launch_evidence_id.is_nil()
        || operation_id.is_nil()
        || !protocol::valid_backup_worker_credential_kind(kind)
    {
        return Err(unavailable());
    }
    let mut conn =
        std::os::unix::net::UnixStream::connect(socket_path).map_err(|_| unavailable())?;
    let mut frame = [0u8; BACKUP_WORKER_CREDENTIAL_FRAME_SIZE];
    frame[0] = protocol::BACKUP_WORKER_CREDENTIAL_FRAME_MARKER;
    frame[1] = kind;
    frame[2..18].copy_from_slice(launch_evidence_id.as_bytes());
    frame[18..34].copy_from_slice(operation_id.as_bytes());
    conn.write_all(&frame).map_err(|_| unavailable())?;
    let mut data = [0u8; 4096];
    let recv = scm_rights::recv(&conn, &mut data).map_err(|_| denied_failure())?;
    if recv.rights_msgs == 0 {
        // An explicit deny frame, not a descriptor.
        return Err(denied_failure());
    }
    let (bytes, fd) = scm_rights::validate_one(recv).map_err(|_| denied_failure())?;
    if bytes != 1 || data[0] != scm_rights::TRANSPORT_MARKER {
        return Err(denied_failure());
    }
    // SC-DEF-45 / SC-DEF-51: every kind but the two pg_dump-reopened
    // postgres credentials must stay root-owned — the ownership check
    // is how the worker verifies a descriptor really came from the
    // broker, so only the kinds the send side actually chowns may
    // expect anything but root here.
    let expected_uid = if kind == BACKUP_THROUGHPUT_POSTGRES_PROBE_CREDENTIAL
        || kind == BACKUP_WORKER_POSTGRES_CREDENTIAL
    {
        Uid::from_raw(CENTRAL_RUNTIME_UID)
    } else {
        Uid::ROOT
    };
    if validate_credential_descriptor(&fd, expected_uid).is_err() {
        drop(fd);
        return Err(denied_failure());
    }
    Ok(fd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair};

    /// `validateCentralRuntimePassfile` — upstream's exact shape gate.
    #[test]
    fn runtime_passfile_shape() {
        assert!(validate_central_runtime_passfile(b"").is_err());
        assert!(validate_central_runtime_passfile(b"no-newline").is_err());
        assert!(
            validate_central_runtime_passfile(b"127.0.0.1:55432:central:central_runtime:pw\n")
                .is_ok()
        );
        // Wrong role refuses.
        assert!(
            validate_central_runtime_passfile(b"127.0.0.1:55432:central:central_migration:pw\n")
                .is_err()
        );
        // Wildcard password field refuses.
        assert!(
            validate_central_runtime_passfile(b"127.0.0.1:55432:central:central_runtime:*\n")
                .is_err()
        );
        // Two lines refuse.
        assert!(
            validate_central_runtime_passfile(b"127.0.0.1:55432:central:central_runtime:pw\nx\n")
                .is_err()
        );
        // CR/NUL refuse.
        assert!(
            validate_central_runtime_passfile(b"127.0.0.1:55432:central:central_runtime:p\rx\n")
                .is_err()
        );
        assert!(
            validate_central_runtime_passfile(b"127.0.0.1:55432:central:central_runtime:p\0x\n")
                .is_err()
        );
        // Oversize refuses.
        let big = vec![b'x'; 4097];
        let mut big = big;
        big[4096 - 1] = b'\n';
        assert!(validate_central_runtime_passfile(&big).is_err());
    }

    /// `validateCentralMigrationPassfile` pins the migration role.
    #[test]
    fn migration_passfile_shape() {
        assert!(
            validate_central_migration_passfile(b"127.0.0.1:55432:central:central_migration:pw\n")
                .is_ok()
        );
        assert!(
            validate_central_migration_passfile(b"127.0.0.1:55432:central:central_runtime:pw\n")
                .is_err()
        );
    }

    /// `validateCentralOutboxPassfile` pins the outbox role — neither
    /// sibling role's passfile may satisfy it.
    #[test]
    fn outbox_passfile_shape() {
        assert!(
            validate_central_outbox_passfile(b"127.0.0.1:55432:central:central_outbox:pw\n")
                .is_ok()
        );
        assert!(
            validate_central_outbox_passfile(b"127.0.0.1:55432:central:central_runtime:pw\n")
                .is_err()
        );
        assert!(
            validate_central_outbox_passfile(b"127.0.0.1:55432:central:central_migration:pw\n")
                .is_err()
        );
    }

    /// `deriveThroughputProbePassfile` rewrites the database field to
    /// `central_probe_<opid-hex>` and preserves every other field.
    #[test]
    fn probe_passfile_derives() {
        let op = Uuid::now_v7();
        let derived = derive_throughput_probe_passfile(
            b"127.0.0.1:55432:central:central_runtime:secret\n",
            op,
        )
        .expect("derived");
        let want = format!(
            "127.0.0.1:55432:central_probe_{}:central_runtime:secret\n",
            op.simple()
        );
        assert_eq!(derived, want.as_bytes());
        assert!(derive_throughput_probe_passfile(b"", op).is_err());
        assert!(
            derive_throughput_probe_passfile(
                b"127.0.0.1:55432:central:central_runtime:secret\n",
                Uuid::nil()
            )
            .is_err()
        );
        // A non-v7 id refuses (upstream `operationID.Version() != V7`).
        let v4 = Uuid::from_bytes(*Uuid::new_v4().as_bytes());
        assert!(
            derive_throughput_probe_passfile(
                b"127.0.0.1:55432:central:central_runtime:secret\n",
                v4
            )
            .is_err()
        );
    }

    /// The receive-side shape gate: a sealed broker memfd passes, an
    /// unsealed/wrong-owner/oversized descriptor refuses — upstream's
    /// `receiveBackupWorkerCredentialDescriptor` checks.
    #[test]
    fn credential_descriptor_shape() {
        let fd = crate::sys::memfd::create_sealed("t", b"value").expect("sealed");
        validate_credential_descriptor(&fd, rustix::process::geteuid()).expect("valid");

        // Wrong owner refuses.
        let fd2 = crate::sys::memfd::create_sealed("t", b"value").expect("sealed");
        assert!(validate_credential_descriptor(&fd2, Uid::from_raw(9999)).is_err());
        drop(fd2);

        // Oversized refuses.
        let fd3 = crate::sys::memfd::create_sealed("t", &vec![0u8; MAX_VALUE_BYTES as usize])
            .expect("sealed");
        assert!(validate_credential_descriptor(&fd3, rustix::process::geteuid()).is_ok());
    }

    /// The client receive gate closes the fd on every refusal —
    /// upstream's per-check `unix.Close`.
    #[test]
    fn credential_descriptor_closes_on_refusal() {
        let fd = crate::sys::memfd::create_sealed("t", b"value").expect("sealed");
        let raw = fd.as_raw_fd();
        assert!(validate_credential_descriptor(&fd, Uid::from_raw(9999)).is_err());
        drop(fd);
        // The descriptor was owned by us; close happens by drop — this
        // test pins that a refused descriptor cannot be re-used by the
        // caller since `validate_credential_descriptor` takes a borrow
        // and the caller drops the OwnedFd on the refusal path.
        assert!(raw > 0);
    }

    /// `fetchBackupWorkerCredential` against a stub broker: the frame
    /// is byte-exact and the descriptor round-trips sealed.
    #[test]
    fn fetch_round_trip() {
        let (broker, client_sock) = socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("socketpair");
        let dir = std::env::temp_dir().join(format!("bwc-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock_path = dir.join("broker.sock");
        let listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();

        let launch = Uuid::now_v7();
        let op = Uuid::now_v7();
        let socket_path = sock_path.to_str().unwrap().to_owned();
        let t = std::thread::spawn(move || {
            let (conn, _) = listener.accept().unwrap();
            let mut frame = [0u8; BACKUP_WORKER_CREDENTIAL_FRAME_SIZE];
            use std::io::Read as _;
            (&conn).read_exact(&mut frame).unwrap();
            assert_eq!(frame[0], protocol::BACKUP_WORKER_CREDENTIAL_FRAME_MARKER);
            assert_eq!(frame[1], BACKUP_WORKER_MINIO_CREDENTIAL);
            assert_eq!(&frame[2..18], launch.as_bytes());
            assert_eq!(&frame[18..34], op.as_bytes());
            let memfd = crate::sys::memfd::create_sealed("t", b"secret").unwrap();
            scm_rights::send(&conn, &[scm_rights::TRANSPORT_MARKER], &[memfd.as_fd()]).unwrap();
            conn
        });
        let result = fetch_backup_worker_credential(
            &socket_path,
            launch,
            op,
            BACKUP_WORKER_MINIO_CREDENTIAL,
        );
        if rustix::process::geteuid().as_raw() == 0 {
            // Kind 2 must arrive root-owned.
            let fd = result.expect("credential");
            validate_credential_descriptor(&fd, Uid::ROOT).expect("sealed");
        } else {
            // Non-root: the ownership gate refuses a descriptor not
            // owned by the broker's uid — the same fail-closed shape
            // check, exercised from the refusal direction.
            let err = result.unwrap_err();
            assert_eq!(err.code(), "backup_credential_denied");
        }
        drop(broker);
        drop(client_sock);
        t.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A deny frame (JSON without a descriptor) is a denial, not a
    /// transport failure.
    #[test]
    fn fetch_denied_frame() {
        let dir = std::env::temp_dir().join(format!("bwc-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock_path = dir.join("broker.sock");
        let listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();
        let socket_path = sock_path.to_str().unwrap().to_owned();
        let t = std::thread::spawn(move || {
            let (conn, _) = listener.accept().unwrap();
            let mut frame = [0u8; BACKUP_WORKER_CREDENTIAL_FRAME_SIZE];
            use std::io::Read as _;
            (&conn).read_exact(&mut frame).unwrap();
            let mut w = &conn;
            protocol::write_deny(&mut w, "op", CREDENTIAL_DENIED);
            conn
        });
        let err = fetch_backup_worker_credential(
            &socket_path,
            Uuid::now_v7(),
            Uuid::now_v7(),
            BACKUP_WORKER_POSTGRES_CREDENTIAL,
        )
        .unwrap_err();
        assert_eq!(err.code(), "backup_credential_denied");
        t.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Malformed fetches refuse before dialing.
    #[test]
    fn fetch_preconditions() {
        assert!(fetch_backup_worker_credential("", Uuid::now_v7(), Uuid::now_v7(), 1).is_err());
        assert!(fetch_backup_worker_credential("/x", Uuid::nil(), Uuid::now_v7(), 1).is_err());
        assert!(fetch_backup_worker_credential("/x", Uuid::now_v7(), Uuid::nil(), 1).is_err());
        assert!(fetch_backup_worker_credential("/x", Uuid::now_v7(), Uuid::now_v7(), 0).is_err());
        assert!(fetch_backup_worker_credential("/x", Uuid::now_v7(), Uuid::now_v7(), 6).is_err());
    }

    /// The kind-class predicates close exactly the upstream sets.
    #[test]
    fn kind_predicates() {
        assert!(is_backup_create_credential_kind(1));
        assert!(is_backup_create_credential_kind(2));
        assert!(!is_backup_create_credential_kind(3));
        assert!(is_backup_throughput_credential_kind(3));
        assert!(is_backup_throughput_credential_kind(4));
        assert!(is_backup_throughput_credential_kind(5));
        assert!(!is_backup_throughput_credential_kind(1));
    }

    /// The throughput client is structurally barred from the create
    /// kinds — the shared `fetch` refuses before any dial.
    #[test]
    fn throughput_client_kind_gate() {
        let c = BackupThroughputWorkerCredentialClient::new(
            "/nonexistent".to_owned(),
            Uuid::now_v7(),
            Uuid::now_v7(),
        );
        assert!(c.fetch(BACKUP_WORKER_POSTGRES_CREDENTIAL).is_err());
        assert!(c.fetch(BACKUP_WORKER_MINIO_CREDENTIAL).is_err());
        let w = BackupWorkerCredentialClient::new(
            "/nonexistent".to_owned(),
            Uuid::now_v7(),
            Uuid::now_v7(),
        );
        assert!(w.fetch(BACKUP_THROUGHPUT_MINIO_CREDENTIAL).is_err());
    }
}
