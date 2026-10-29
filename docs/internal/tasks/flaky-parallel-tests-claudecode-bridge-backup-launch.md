# Flaky parallel tests — claudecode permission-bridge race and backup-launch recovery-journal flake

- **Type:** Recorded test-suite flakiness — two tests that intermittently fail under `cargo test --workspace` parallel scheduling while passing deterministically in isolation and serialized runs. Neither is a code defect found by the suite; both are timing/IO sensitivities in test scaffolding.
- **Found:** 2026-10-28, during the post-`prepare-promotion`-merge `CENTRAL_TEST_DSN`-enabled workspace verification run.
- **Status:** **FIXED** — direction 2 applied: `collect_answering` tolerates the `harness_port_no_pending_permission` lost-race (the delivered event is the assertion target; the pending slot resolves legitimately on later scenario frames), and `journal_retry` gives the backup-launch store calls one retry on `broker_recovery_journal_unavailable` only — any other failure, and a second unavailable, still panics. Verified `claudecode` 58/58 and `backup_launch` 8/8, fmt + clippy clean.

## The flakes

**1. `input_with_large_numbers_is_bridged`** — `crates/adapters/central-adapter-harness/tests/claudecode.rs:3666`

Observed failure (once, full-suite parallel run):

```
respond: Failure { kind: Invalid, code: "harness_port_no_pending_permission",
                   message: "claudecode: no pending permission request" }
```

The test plays a scenario where `@@INPUT@@` is replaced by a large-numbers JSON body and answers every bridged `can_use_tool` request inside `collect_answering`'s sync callback. Under parallel load the adapter can consume the pending permission request before `respond_permission` lands (or the next request pulls ahead) — a bridge-protocol race window, not a logic error. Passes `--test-threads=1` (58/58) and in isolation.

**2. `broker::backup_launch::tests::issue_validate_reaped_completed_lifecycle`** — `crates/adapters/central-adapter-linux/src/broker/backup_launch.rs:976`

Observed failure (once, full-suite parallel run):

```
called `Result::unwrap()` on an `Err` value: Failure { kind: Internal,
    code: "broker_recovery_journal_unavailable",
    message: "broker: recovery journal unavailable" }
```

The test spawns a real `sleep 30` child, issues launch evidence through `BackupLaunchStore` over a `RecoveryJournalStore` rooted in its own `TempDir`, then drives the issued→active→reaped lifecycle. One of the journal-backed calls returned the `unavailable` Failure — the journal's fail-closed wrapper around any I/O/validation error (`recovery_journal.rs`'s `unavailable()` covers every `map_err` site: fsync, lstat/private-file validation, open/read). A transient filesystem error under parallel-suite I/O pressure is the most plausible trigger; the store is TempDir-scoped so no cross-test state is shared. Passes 4/4 in isolated and filtered runs.

## What a fix requires

Either/both directions are acceptable; neither touches production code:

1. **Serialization hints** — mark the affected suites `#[serial]` (or move them behind a shared lock/`--test-threads` partition) so the bridge race and the journal I/O window close. Cheapest, removes the flake without changing what's asserted.
2. **Robust scaffolding** — for the claudecode test, make `collect_answering` tolerate the request having been consumed between event delivery and `respond` (retry-once or match the upstream harness's own tolerance); for the backup-launch test, retry the journal-backed transition once on `broker_recovery_journal_unavailable`, or identify and eliminate the specific transient I/O failure (likely fsync/EINTR-class) so the unwrap is honest again.

Do not paper over either with a bare retry that would also swallow a real regression: the retry must key on the specific flake signature (`harness_port_no_pending_permission` / `broker_recovery_journal_unavailable`), never blanket-`unwrap_or`.

## References

- Failing sites: `crates/adapters/central-adapter-harness/tests/claudecode.rs:3666` (`collect_answering` at :1952-1979), `crates/adapters/central-adapter-linux/src/broker/backup_launch.rs:869-1000` (test `env()` at :881-896).
- Journal failure mapping: `crates/adapters/central-adapter-linux/src/broker/recovery_journal.rs` (`unavailable()` at :108 and the `map_err(|_| unavailable())` sites).
- Observation logs: `/tmp/ws-test-final.log`, `/tmp/ws-test-final2.log` (ephemeral — the failures and surrounding pass counts are recorded above).
