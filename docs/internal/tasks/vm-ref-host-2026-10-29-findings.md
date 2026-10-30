# Findings from the `central-ref` VirtualBox bring-up (2026-10-29)

A Ubuntu 24.04.4 reference-profile VM (`~/VMs/central-ref`, SSH
`central@127.0.0.1:2222`) was provisioned per
`docs/operations/local-prerequisites.md`: pinned Docker 29.6.1 + Compose
plugin 5.3.1 with the containerd image store, `pg_dump` 16.14, quota,
apparmor, libnss3-tools, Go 1.26.6, buildctl, `central-runtime` (501) and
`central_migrate` (986), `/var/lib/central-browser` on a dedicated ext4 with
`prjquota` enabled via fstab, upstream helper/broker socket units, PAM
`central-helper`, and a `--dev-admission`-equivalent `helper.env`.

What works: `central local init` (via `grant issue --kind init`, grant
consumed correctly), `local status` -> `STOPPED`, `local init` idempotent
`ALREADY_INITIALIZED`, helper logs the designed keyless import-only note.

## Task V1 — production grant environment is unimplemented — RESOLVED (grant-ceremony-fix)

`bins/central/src/grant_cli.rs` `production_grant_environment()` was a
hard-coded `Err("production instance authority unavailable")`. Fixed on
`grant-ceremony-fix`: the env now resolves
`resolve_production_instance_composition()` + the ceremony owner, and
`issue`/`mode`/`list` are wired through `read_ceremony_mode`,
`write_ceremony_mode`, and the instance grant store (upstream
`grantIssue`/`grantMode`/`grantList` ports). Verified live on the VM:
`grant mode grant` -> `ceremony mode: grant`, `grant issue --kind
lifecycle|prepare` mints grants, `grant list` shows consumed records, and
`local up` then runs past `AUTHORITY_DENIED` to the honest
`ADMISSION_FAILED`/`RUN_CENTRAL_LOCAL_PREPARE` refusal (no staged
dependency). With grant mode the host has a working admission path; V2
below no longer gates it.

## Task V2 — physical-console ceremony denies instantly on `local up` — DIAGNOSED (not a code bug)

Diagnosis (grant-ceremony-fix): the physical_tty ceremony is CORRECT.
Reproduced live on the VM by running the client with a real VT stdin
(`setsid … </dev/tty5`): `Central PAM password:` prompt appeared on
tty5, the password was accepted, the `CONFIRM <code>` phrase printed,
and `local up` then proceeded to the honest
`ADMISSION_FAILED`/`RUN_CENTRAL_LOCAL_PREPARE` refusal.

The earlier instant denials came from clients that did NOT own a
usable physical console: SSH sessions (fd/0 = `/dev/pts/*`, refused by
`open_physical_tty` by design) and tty1 after `ubuntu-desktop-minimal`
installed gdm (the GNOME greeter owns tty1 — keystrokes went to the
greeter, not a getty). Correct runbook: use a real text VT
(Ctrl+Alt+F2+ on a desktop host) and run the `central` client there
with stdin on `/dev/ttyN`.

Small helper-side diagnostics were added (eprintln the confirm Failure
code on the AUTHORITY_DENIED branches) so future refusals are
identifiable from `journalctl -u central-helper` without strace.

## Notes

- Host-side correctness of `central local doctor --host-prerequisites` is
  questionable: it reports `ok` on a 26.04 host (observation-only today).
- `central local doctor` inside the VM reports only OS-release facts.
- V1 is resolved (see above); V2 remains — the physical-TTY ceremony
  still denies instantly. Grant mode is now the usable admission path on
  this host; V2 only matters for `physical_tty` instances and Tier-3
  console-ceremony evidence.

## Task V3 — `local up` hangs indefinitely after lock/journal — RESOLVED (stderr lock)

Symptom: lifecycle ops reached `started` and never settled; every retry
ended in a silent in-process park. `eu-stack` on the helper showed the
operation thread inside `__eprint → lock_contended`: `bins/central` main
held `std::io::stderr().lock()` for the whole process lifetime, so any
worker-thread `eprintln!` blocked forever on the stderr mutex. The
earlier denial eprintlns only surfaced because they flushed when the
service stopped (main returned, releasing the lock).

Fix: `main.rs` now passes `std::io::stderr()` (per-write locking — the
handle upstream's `os.Stderr` models) instead of the process-lifetime
`StderrLock`, and the debug eprintlns added during diagnosis were
removed from the helper path. `local up` went from infinite hang to a
deterministic failure in ~20 s.

## Task V4 — `START_DAEMONS_FAILED: alter live role` — RESOLVED (SCRAM frame parse)

Postgres was up and healthy, the superuser `active` password matched
the passfile, and a manual `ALTER ROLE` over `psql` succeeded — but
rotate-then-sync failed for `central_migration`/`central_runtime`/
`central_outbox`. The custom `pg_wire` client passed the full
AuthenticationSASLContinue/SASLFinal backend payload (which includes
the 4-byte auth-code prefix) to the SCRAM exchange: `respond_to` then
parsed `\0\0\0\x0Br=…` and died with `malformed server-first`.

Fix: `pg_wire.rs` slices `msg.payload[4..]` for codes 11 and 12 (code
10 was already sliced). Rotation then ran live and `START_DAEMONS`
passed. `pg_credentials.rs` now also surfaces the inner wire error in
the `alter live role` reason instead of discarding it.

## Task V5 — broker SIGSYS on `kill`/`statx` — RESOLVED (re-aim, no list widening)

Audit showed the broker dying `SIGSYS` on syscall 62 (`kill`) during
`verify_dead_owner`, then 332 (`statx`) in the B04 handoff path. First
reaction was to admit both numbers; the pin tests then proved that was
the wrong move — upstream's hardened broker never calls them:

- `unix.Kill(pid, 0)` in Go emits `tgkill` (234 — already allow-listed
  for the runtime's SIGURG preemption). `rustix::process::test_kill_process`
  emits `SYS_KILL` instead, so the port gained
  `sys::audited::tgkill_liveness` — a single audited `libc::syscall` —
  and `broker::lifecycle::verify_dead_owner` uses it.
- `std::fs::canonicalize("/proc/<pid>/exe")` in
  `migration_launch::verify_peer_process` resolves multi-component
  paths via `statx`; upstream does the same lookup with
  `EvalSymlinks` → `readlinkat` (267, admitted under SC-DEF-36). The
  port now calls `rustix::fs::readlinkat` directly.

`ALLOWED_SYSCALLS` is upstream-equal again (64 entries;
`allowlist_matches_upstream` and `broker_surface_and_old_shape_probes`
green). All remaining `std::fs` metadata/canonicalize/set_permissions
uses in `broker/*.rs` are test-only code — production paths go through
`durable::*` (newfstatat/openat/fchmod primitives).

## Task V6 — `PROVISION_MINIO_FAILED: delivery failed` — RESOLVED (B10 port)

The MinIO provisioner ran, connected to the hard-linked broker
rendezvous socket, and exited 1. Its embedded receipt (now surfaced in
the failure reason via `run_with_input_output`) read
`outcome=failed, reason=delivery failed`: both B10 transports were
deliberate `UNSUPPORTED_IN_THIS_SLICE` stubs —
`handle_b10_minio_runtime_transport` always denied and
`handle_b10_minio_provisioned_transport` denied after the peer check.

Fix (upstream `service.go` + `b10_runtime_binding.go` port):

- `broker/minio_runtime.rs` — the durable binding/consumption
  authority: `bind` (create-only scope record), `consume` (scope +
  fence check → O_EXCL one-shot consumption record, `ERR_CONSUMED`
  on replay, `ERR_FENCE_STALE` on stale token), `record_delivery`
  (pending→delivered/reconciliation, atomic rename, never rewrites a
  settled disposition).
- `broker/minio_runtime_wire.rs` — wire decode of
  `MinioRuntimeUseRequest` into the domain type for `validate(now)`.
- `server.rs` — full `handle_b10_minio_runtime_transport`
  (request → peer-cred + op-id gates → consume → generation read →
  sealed-memfd `WriteMsgUnix` → `RecordDelivery` → broker-side copy
  delete → HMAC fingerprints → handoff journal → receipt) and
  `handle_b10_minio_provisioned_transport` (peer/descriptor gates →
  `readSealedValue` → `BindMinioRuntimeSecret` = backend `create` +
  store `bind` → `writeAccept`), plus `recordMinioRuntimeFailure`
  reconciliation and the `minio-runtime-handoff` journal stream.

Validated: `local up` → `completed` (`MIGRATION_REQUIRED`), the
`central-artifacts-v1` bucket is created by the provisioner,
`local status` → `PROVISIONED`, `local down` → clean teardown.

## Task V7 — stale runtime artifacts breaking fail-closed checks — OPERATIONAL

Not code bugs, but reproducible operator traps on this host:

- Docker bind-mounts auto-create *directories* at missing source paths
  (`secrets/minio-root-password`, `secrets/postgres-admin-passfile`,
  `broker/minio-provision.sock`) when Compose is run manually — later
  lifecycle runs then fail `File exists`/`untrusted rendezvous`/`File
  exists`. Cleanup: `rmdir` the bogus directories; never run
  `docker compose` by hand against the rendered file (use `local
  down` for teardown).
- `local up` against an already-`PROVISIONED` instance refuses with
  `B01 is not current` — expected: down→up is the cycle.
- Dependency-lock divergence: the GHCR `central-local-infra` image is
  private (`denied` without a token). For validation the VM lock was
  repointed at the locally-built image digest
  (`52df63e8…`) — **VM-only state, not committed**; the repository
  keeps the upstream pin.
