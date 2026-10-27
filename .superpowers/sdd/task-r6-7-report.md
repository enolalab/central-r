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

## R6-7(b) complete — authority dispatch + digest wire parity (this commit)

- `broker/wire.rs`: `digest32` serde adapter — Go `[32]byte` marshals as a
  fixed 32-number array (golden verified against go1.26 `json.Marshal`);
  decode mirrors `json.Unmarshal` (short arrays zero-pad, long truncate,
  `null` zeroes). `go_json_escape` reproduces `encoding/json`'s
  `<`/`>`/`&`/U+2028/U+2029 escaping for the byte-equality canonical
  re-marshal upstream's `decodeExactBrokerPayload` enforces.
- `authority.rs`: `BrokerResponse.result` → `Option<Box<RawValue>>` —
  verbatim JSON passthrough, preserving upstream's absent/null/result
  distinction with no double encoding.
- `broker/backup_authority.rs` (new): all backup RPC dispatches —
  helper routes (issue_launch, issue_minio_handoff, mark_reaped,
  complete_attested_seal, verify_seal, read_status, throughput
  launch/journal/ensure-payload-epoch) and worker routes
  (seal_for_launch, worker_context, active_payload_epoch,
  read_throughput, create/read/CAS operation, throughput
  context/target/stage). Strict `decode_exact_broker_payload` (one
  `"request"` key, `deny_unknown_fields`, canonical byte-equality).
- `broker/recovery_authority.rs` (new): restore authorization/abandon/
  barrier dispatches (tolerant `json.Unmarshal` decode, `Some(empty)`
  vs `None` payload distinction preserved), `restore_issue_launch`
  (socket-PID parent binding, bare success envelope),
  `PrepareRecoveryBrokerAuthority`, `ActivateRecoveryBootstrap`,
  `ResetBootstrapAuthority` (session reset + zeroed staged plaintext +
  enumerate/delete every recovery-bootstrap generation).
- `Service::dispatch` reordered to upstream's `service.go` switch;
  `dispatch_json` rewired to upstream `HandleConn`'s full gate ladder
  (bootstrap-migration denial → worker UID/GID → postgres/advisory
  root gates → backup-helper root → restore-helper root → recovery
  migration peer → runtime/root-or-migration → launch validation →
  migration-outcome → generic dispatch).
- `is_r6_purpose` now contains only `bind_postgres_service_role` and
  `append_advisory_evaluation` — the sole purposes this slice leaves
  closed. Connection-only purposes answer upstream's `default`
  (`"unknown purpose"`) through generic `dispatch`, exactly as
  upstream's `Dispatch` does.

Verification (all run, this session):
- `cargo test -p central-adapter-linux` — 626 lib + 91 integration =
  717 pass, 0 fail (includes 15 new focused tests: digest shape + Go
  golden, exact-decode refusals, `dispatch_json` peer-gate routing,
  envelope shapes).
- `cargo fmt --all -- --check` — clean.
- `cargo clippy -p central-adapter-linux --all-targets -- -D warnings` — clean.
- `cargo check --workspace` — clean.
- `cargo deny check` — ok.

Live vs denied: helper/worker/recovery/restore-launch purposes are live
under their upstream peer gates; `bind_postgres_service_role` +
`append_advisory_evaluation` remain `UNSUPPORTED_IN_THIS_SLICE`;
slice (c) still needs the `0xc1`–`0xc5` credential transports and the
helper backup/restore file operations.

## Slice (c) part 1 — `0xc1`/`0xc2` credential transports + CBL1 client

Files changed:
- `crates/adapters/central-adapter-linux/src/broker/backup_worker_credential.rs` (new)
- `crates/adapters/central-adapter-linux/src/broker/restore_credential.rs` (new)
- `crates/adapters/central-adapter-linux/src/backup_launcher.rs` (new)
- `crates/adapters/central-adapter-linux/src/broker/protocol.rs`
- `crates/adapters/central-adapter-linux/src/broker/server.rs`
- `crates/adapters/central-adapter-linux/src/broker/mod.rs`
- `crates/adapters/central-adapter-linux/src/lib.rs`

Live vs denied (<=8 lines):
1. `0xc1` live: backup-worker Postgres/MinIO + throughput
   Postgres-target/probe/MinIO credentials via sealed memfd + SCM_RIGHTS,
   parse-before-peer-check preserving upstream operation-ID echo.
2. `0xc2` live for kinds 2-6 (runtime, MinIO restore, audit migration,
   MinIO import, import migration) behind root-helper peer + mode/phase
   admission + closed `RestoreRefusalReason` sanitization.
3. Kind 1 restore migration credential stays fail-closed: T8's capacity
   gate is the only thing that unblocks it.
4. `0xc3`/`0xc4`/`0xc5` capacity transports remain UNSUPPORTED.
5. CBL1 client (launch/commit/abort/wait/assert-retained/census/release)
   ported; helper `backup.rs`/`restore.rs` + verb-matrix flip remain
   for part 2.
6. Runtime-owned passfile ownership preserved for kinds 1/4; all other
   credentials stay root-owned for broker-provenance checks.
7. Credential bytes bounded + zeroized; malformed frames deny as
   "unknown"; arbitrary errors never cross the helper boundary.
8. Non-T7 helper verbs still deny `UNSUPPORTED_IN_THIS_SLICE`.

Verification (run this session):
- `cargo test -p central-adapter-linux --lib` focused credential +
  launcher filters: 32 tests pass (27 broker credential + 5 CBL1
  client), 0 fail.
- `cargo clippy -p central-adapter-linux --all-targets -- -D warnings` — clean.
- `cargo check -p central-adapter-linux` — clean.
- `cargo fmt -p central-adapter-linux` — applied; clean after format.

R6-T7 part 2 (helper backup/restore slice) — commit a2d3b94.
Changed: helper/{backup,restore,daemon,matrix,server,protocol,migration_launch,mod}.rs + broker/{backup_authority,recovery_authority,recovery_journal,lifecycle_client}.rs (12 files, +3825).
Backup: CBL1 create launch, throughput gate, evidence→reap→attest seal chain, descriptor-bound repository, verify/status read path; restore: verify/apply/resume/abandon with fresh per-verb PAM+TTY + one-use authorizations; RESTORE_*/BACKUP_* refusal codes verbatim.
Matrix: exactly 7 maintenance verbs implemented (15 total); server dispatch + per-verb deadlines + operator peer arm wired.
Tests: 659/659 adapter lib pass; fmt, clippy -D warnings, cargo check --workspace, cargo deny check all clean.
T7 complete. T8 still required: restore verify/apply/resume stay unconfigured (unavailable, not success); kind-1 migration + 0xc3–0xc5 capacity transports remain fail-closed.
