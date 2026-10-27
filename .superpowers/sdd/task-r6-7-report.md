# R6 Task 7 — WIP report (reconnaissance complete, implementation not started)

Branch: `r6-backup-restore-maintenance` @ `2881d44`. No commits added by this session.

## Status

Upstream sources fully mapped; no Rust files written yet. The port is ~9.3k upstream
lines across 7 broker + 2 helper files — too large for one session; split below.

## Implementation map (verified against upstream)

1. `broker/recovery_journal.rs` ← `recovery_journal.go` (2.3k). File-backed
   `RestoreJournalStore`+`RestoreBarrierInspector`. Records under `recovery-journal/`:
   tickets, apply/abandon authorizations, restore-operations, minio-handoffs,
   backup-operations, seal-companions, bootstrap-drafts. Lifecycle `issued → consuming
   → consumed`; per-record `.lock` via `durable::open_lock`; `write_exclusive_json` /
   `replace_json`; HMAC via `signing.fingerprint(domain, canonical)`. Ticket check =
   `ticket.verify_hmac(key)`/fingerprint over `ticket.canonical_payload()`. Barrier =
   scan ops dir, fail closed on corrupt, one non-terminal op. `abandon` always
   succeeds-semantics; stale `consuming`/`consumed` crash recovery; MinIO
   handoff-generation release (SC-DEF-69). `take_activated_recovery_bootstrap` needed
   by `dispatch_present_bootstrap` fallback (server.rs comment).
2. `broker/backup_launch.rs` ← `backup_launch.go`. Dir `backup-launches`, HMAC domain
   `slice-c-backup-launch-v1`, states `issued/active/reaped/completed`.
   Issue/ValidateWorker/MarkReaped/RequireReaped/MarkCompleted.
3. `broker/restore_launch.rs` ← `restore_launch.go`+`restore_launch_issuer.go`.
   Single record `restore-launch/current.json`, engine + helper identity binding,
   `ValidatePeer`/`ValidateHelperPeer`/`InspectLiveness`; `restore_issue_launch` RPC.
   Engine path `/usr/lib/central/central-restore`; helper path = self `/proc/self/exe`.
4. `broker/throughput_journal.rs` ← `throughput_journal.go`. Dir `backup-throughput`,
   `operations/`, `active-receipt.json`, `state.lock`; phases `accepted →
   measurement_pending → completion_pending → completed|failed|cleanup_required`;
   active receipt only after cleanup attested; cleanup needs fresh all-zero census.
5. `broker/backup_authority.rs` ← `backup_authority_rpc.go`+`backup_payload_epoch_rpc.go`.
   Dispatch arms + clients for `backup_issue_*`, `backup_seal_for_launch`,
   `backup_mark_launch_reaped`, `backup_complete_attested_seal`, `backup_verify_seal`,
   `backup_read_status`, `backup_worker_*`, `backup_ensure_payload_epoch`
   (`payload_epoch.rs` has `create_and_activate`/`read_active`).
6. `broker/recovery_authority.rs` ← `recovery_authority_rpc.go`. Dispatch+clients for
   `issue_restore_{apply,resume,abandon}_authorization`, `abandon_restore`,
   `inspect_restore_barrier`, `inspect_restore_ticket_barrier`,
   `prepare_recovery_broker_authority`, `activate_recovery_bootstrap`.
7. `broker/backup_worker_credential.rs` ← `backup_worker_credential_linux.go`.
   0xc1 handler: `validate_credential_worker` (kinds 1-2 → backup_launches, 3-5 →
   throughput launches state gates), `resolve_backup_worker_credential`
   (passfile/handoff/probe-derivation), `fchown` to runtime UID only for kinds 1+4,
   sealed memfd send; client `fetch` + `receive_backup_worker_credential_descriptor`.
8. `helper/backup.rs` ← `backup_launch.go`+`backup_read.go`. `BackupCreateHandler`
   (PAM → throughput gate → repo descriptor → launcherd Launch → IssueBackupLaunch →
   PrepareBackupMinio → Commit → WaitAndReap → AssertTargetLockRetained → MarkReaped →
   attest → seal complete → ReleaseAndReap) + `BackupReadHandler` verify/status.
   `backuplauncher` client codec = R6-6 `internal/backuplauncher` mirror.
9. `helper/restore.rs` ← `restore_{apply,verify,refusal,abandon}.go` +
   `restore_operator_client_linux.go`. PAM-gated apply authorization issue;
   verify runner w/ refusal allowlist (`RESTORE_NO_LIVE_OPERATION`,
   `RESTORE_LIVE_OPERATION_AMBIGUOUS`, `RESTORE_NO_ADMISSIBLE_BACKUP`,
   `RESTORE_BACKUP_CANDIDATE_AMBIGUOUS` + `RestoreRefusalReason::valid`);
   abandon ceremony → `issue_restore_abandon_authorization` → `abandon_restore`.

## server.rs wiring required

- New `Service` fields: `recovery_journal`, `backup_launches`, `throughput_launches`,
  `restore_launches`, `throughput`, `payload_epochs`.
- `dispatch_json`: replace closed denials — worker purposes route per-purpose with
  `peer` (upstream server.go:186-216); backup-helper purposes via root gate; restore
  `restore_issue_launch` gets `peer`; recovery-authority purposes need migrate peer.
- `handle_conn`: 0xc1 → `read_backup_worker_credential_request` then
  `handle_backup_worker_credential_transport`; 0xc2 stays denied pending
  `restore_migration_credential` port (needed by central-restore engine, T9-adjacent);
  0xc3–0xc5 stay denied (T8 C02).
- `dispatch_present_bootstrap`: add `take_activated_recovery_bootstrap` fallback.

## Denial → implemented flips (≤10 lines)

Not yet flipped: all `is_r6_purpose` purposes still `migration_denied("unsupported in
this slice")`; 0xc1 denies `BACKUP_WORKER_CREDENTIAL_DENIED`; 0xc2 `RESTORE_CREDENTIAL_DENIED`.
T8 still owns: restore-capacity admission (0xc3–0xc5, `restore_capacity_*`,
`IssueRestoreTicket`'s reserve path, sweep, `assertRestoreCapacity`), throughput-probe
launch RPCs may land T7/8 boundary per plan, restore engine credential frame 0xc2
(`restore_migration_credential_linux.go`, needed for restore apply/resume/verify e2e).

## Verification

Not run — no code written.

---

# Slice (a) — implementation complete (this session)

Files added/changed:
- `crates/adapters/central-adapter-linux/src/broker/recovery_journal.rs` (new, ~4.4k)
  `RecoveryJournalStore`: restore tickets, ticket-launch carries, apply/abandon
  authorizations, restore operations + CAS, barrier inspect, MinIO handoffs
  (issue/bind/resolve/SC-DEF-69 release), backup operations + seal records
  (`SealBackup`/`CompleteAttestedBackupSeal`/`VerifyBackupSeal`), broker-reset
  records, bootstrap draft/registration/activation + `take_activated_recovery_bootstrap`
  presented-once/release; `RestoreJournalStore`+`RestoreBarrierInspector`+
  `BackupJournalStore`+`BackupSealer`/`BackupSealVerifier` port impls.
- `crates/adapters/central-adapter-linux/src/broker/backup_launch.rs` (new, ~1.1k)
  `BackupLaunchStore`: Issue/WorkerAuthority/ValidateWorker/ValidateWorkerOperation/
  MarkReaped/RequireReaped/MarkCompleted; `issued→active→reaped→completed`,
  exact /proc process identity, HMAC `slice-c-backup-launch-v1`.
- `crates/adapters/central-adapter-linux/src/broker/restore_launch.rs` (new, ~1k)
  `RestoreLaunchStore` (`restore-launch/current.json`, engine exe+start+ppid and
  helper exe+start binding, StateInvalid single-flight refusal) +
  `RestoreLaunchIssuer` client (`restore_issue_launch`, `RESTORE_LAUNCH_DENIED: ` parse).
- `crates/capabilities/central-backup/src/repository.rs`:
  `BackupTargetLockAttestation` (+2 tests).
- `crates/adapters/central-adapter-linux/src/broker/mod.rs`: module registration.

Verification (all run, this session):
- `cargo test -p central-adapter-linux` — 616 lib + 91 integration = 707 pass, 0 fail.
- `cargo fmt --all -- --check` — clean.
- `cargo clippy -p central-adapter-linux --all-targets -- -D warnings` — clean.
- `cargo check --workspace` — clean.

Production-backed: ticket/authorization/operation issue+consume+CAS+abandon; barrier;
backup seal commit+attested completion; MinIO handoff lifecycle; bootstrap
take/release; launch issue/validate/reap/complete; restore single-flight issue +
issuer client. Remaining slices: (b) throughput journal, authority RPC wiring,
worker/restore credentials (0xc1–0xc5); (c) helper backup/restore paths +
server.rs dispatch integration.

## R6-7(b) progress — Service wiring + wire parity fixes (this commit)

- `Service` now owns the five R6 stores upstream `newServiceWithHelperExecutable`
  composes: `recovery_journal` (Arc, shared), `backup_launches`,
  `restore_launches`, `throughput` (Arc, default recovery profile),
  `throughput_launches`; `payload_epochs` became `Arc<PayloadEpochStore>`
  for the same sharing. `runtime_gid` follows upstream: `getgid()` unless
  `runtime_uid == 501`, then fixed 501/501.
- `dispatch_present_bootstrap` gained upstream's required fallback:
  `recovery_journal.take_activated_recovery_bootstrap()` before the
  `BOOTSTRAP_NOT_STAGED` denial (one-use take preserved).
- Wire parity fixes: `BackupAcceptedFactsWire` and `BackupSealProposalWire`
  `PayloadEpochID` now serialize as `payload_epoch_id` (upstream's lone
  JSON tag on those structs).
- Still pending for slice (b): the 33 R6 dispatch functions
  (backup_authority/recovery_authority/throughput/payload-epoch), the
  JSON-route peer-gate rewiring, `0xc1`/`0xc2` credential transports,
  and `[32]byte` number-array fixes for seal/attestation/binding digests
  currently serialized as b64.
