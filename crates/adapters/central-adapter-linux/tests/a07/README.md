# A07 — the host-authority denial suite

Every boundary the Linux adapter enforces is a fail-closed gate. This
suite exercises the *denial* half of each surface — the shapes an
attacker riding the same uid, a forged descriptor plane, a spoofed
TTY, a raced path, or a damaged journal must produce — and pins the
exact codes and wire tokens upstream's Go tests pin. A weakened
check fails this suite; a silent success path is never acceptable
evidence.

## Running

```bash
cargo test -p central-adapter-linux --test 'a07_*'      # all seven binaries
CENTRAL_TIER3=1 cargo test -p central-adapter-linux --test a07_tier3  # as root
```

The portable legs run as any user on any Linux host. Tier 3 legs
print an explicit `SKIP [a07] <scenario>: <reason>` and return —
they are skipped evidence, never hidden passes.

## Tier gating

| Tier | Requirements | What it covers |
| ---- | ------------ | -------------- |
| Portable | none | Every denial reachable from the test process's own identity: peer-policy predicates, wire-level helper/broker denials as our own `SO_PEERCRED`, `SCM_RIGHTS`/`memfd`/`pidfd` shape gates, `openat2` confinement under a scratch root, genesis/grant/lifecycle/journal denials, TTY preconditions over pipes/`/dev/null`/PTYs. |
| Tier 3 | `CENTRAL_TIER3=1`, euid 0, Ubuntu ≥ 24.04 x86_64 | Multi-UID `SO_PEERCRED` denial via a real `uid(9999)` child; root-owned/foreign-owned/writable ancestor refusal; `TIOCEXCL` exclusive lease on a real VT; live PAM `central-helper` denial. |

## Threat coverage (docs/security/threat-model.md)

- **T17** (same-UID processes): `a07_peers`, `a07_descriptors`,
  `a07_authority` — peer arm matrix, closed-unanswered gates,
  descriptor smuggling, closed verb matrix, deny-safe gate, grant
  one-use/scope/MAC rules, collapsed `authority denied`.
- **T19** (TTY forgery, PTY, replay): `a07_tty`, `a07_tier3` — pipe /
  `/dev/null` / PTY refusal (`sys_tty_not_console`), scoped-ceremony
  preconditions, bounded attempts, one-use unforgeable tokens, live
  console lease.
- **T23** (state/audit forgery below root-owned parents):
  `a07_paths`, `a07_journal`, `a07_tier3` — `openat2`
  `BENEATH|NO_SYMLINKS|NO_MAGICLINKS|NO_XDEV` refusals, root-owned
  `0700`/`0600` record shape, trailing-JSON rejection, workspace-seal
  confinement, journal corruption/exactness/settlement, foreign-owner
  traversal.
- Descriptor plane (B04/B10 handoff): `a07_descriptors`,
  `a07_peers` — exact `sys_scm_rights_denied` messages, sealed-memfd
  shape, `B10_*_DENIED`/`B04_HANDOFF_DENIED` wire tokens.
- Crash/recovery: `a07_journal` — torn appends recover as
  `prepared`-never-`issued`, corrupt records are skipped not
  reinterpreted, committed records are immutable, `broker_journal`
  code on every failure.

## Files → coverage → upstream parity (Go, `github.com/enolalab/central`)

| Test binary | Covers | Upstream anchors |
| ----------- | ------ | ---------------- |
| `a07_peers.rs` (14) | `PeerPolicy::allows` arm matrix; helper closed-unanswered arms; `SO_PEERCRED` mismatch; broker peer predicates + `0xB0/0xB1/0xB2/0xB4/0xB5` frame gates; `0xc1–0xc5` closed transports; dispatch purpose ladder | `internal/adapter/authority/helper/prepare_peer_context_linux_test.go`, `helper_authority_test.go`, `restore_peer_admission_test.go`, `cmd/central/broker_serve_test.go` |
| `a07_descriptors.rs` (12) | `SCM_RIGHTS` extra/missing/non-rights/truncated shapes; `validate_one` fabricated `Recv` gate; transport marker; sealed-memfd owner/fs/seals/bounds/destination; `pidfd` kind+liveness | `hardening_filter_test.go` descriptor cases, upstream `extractSingleDescriptor`/`validateReceivedDescriptor`, `memfd_linux.go` checks |
| `a07_tty.rs` (14) | `open_physical_tty` pipe/null/PTY refusal; ceremony peer availability + scope; init dialog bounds/attempts/mismatch/budget; phrase equality; PAM credential prechecks + confirmer grant-mode; token single-use | `tty_ceremony_read_linux_test.go`, `init_confirm_portable_test.go`, `init_test.go` (helper) |
| `a07_paths.rs` (13) | `openat2` escape/symlink/magic-link + rename-swap confinement + type gates; genesis ancestor/root/record/state classification; workspace-seal verify/seal refusals; grant-store path/owner/mode | `protected_file_test.go`, `protected_file_linux_test.go`, `internal/sandbox/path_resolve_read_test.go`, upstream `genesis_linux.go`/`seal_linux.go` checks |
| `a07_journal.rs` (7) | Broker journal torn-append recovery, corrupt record skipping, committed-record immutability, prepare-record gating, proof-target + HMAC fingerprint tamper evidence | `recovery_journal_test.go`, `advisory_evaluation_journal_test.go`, `recovery_journal_minio_release_test.go` |
| `a07_authority.rs` (26) | Closed helper matrix (registered/unregistered, both arms); implemented-but-unwired arms; invalid payloads; deny-safe gate; init reason ladder; grant TTL/one-use/scope/MAC/pending; lifecycle barrier/capacity/admission/binding; sandbox envelope; socket policy; collapsed authority denial | `helper_authority_test.go`, `denysafe_gate_test.go`, `internal/advisory/denysafe_test.go`, `grant_flock_unix_test.go`, `init_test.go`, `delete_test.go`, upstream `hardening.go` |
| `a07_tier3.rs` (5) | Multi-UID wire denial; foreign-owned/writable ancestor; `TIOCEXCL` lease + real-VT `open_physical_tty`; live PAM denial | upstream's root-gated `authority` platform tests (`*_linux_test.go` skipping as non-root — same skip contract) |

## Invariants the suite pins

1. **Exact denial identifiers.** Codes (`sys_scm_rights_denied`,
   `sys_tty_not_console`, `BARRIER_CONFLICT`, `BROKER_AUTHORITY_DENIED`,
   `sys_grant_*`, `sys_pam_auth`, …) and wire tokens
   (`UNSUPPORTED_IN_THIS_SLICE` exit 5, `AUTHORITY_DENIED` exit 7,
   `DENY_SAFE_ACTIVE`, `authority denied`) are asserted byte-exact
   where upstream pins them.
2. **Fail-closed order.** Peer admission precedes payload parsing;
   shape gates precede content checks; a corrupt grant/journal/deny-
   safe record is a denial, never a permissive default.
3. **No ambient authority.** A same-UID peer, a smuggled descriptor,
   a spoofed TTY, or a raced path never upgrades what the kernel
   attests.
4. **Honest skips.** Tier 3 conditions that cannot be manufactured
   print `SKIP [a07]` with the reason; every adaptive arm asserts the
   denial that actually applies to the running identity.
