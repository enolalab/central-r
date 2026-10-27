# R6 Task 8 — restore-capacity admission, transports, and the kind-1 gate

Branch: `r6-backup-restore-maintenance` (on `4fe2e9f`)

## Commits

| Commit | Scope |
|--------|-------|
| `845ef60` | **8a** — receipt ledger, protected reserve store, device-store resolver, `0xc4` receipt frame |
| `227b874` | **8b** — reserve allocation, inspection, sweep, helper authority, reserve objects, admission gate, live `0xc3`–`0xc5` transports, kind-1 `0xc2` gate call |
| `dcc8f67` | **8c** — production role-roots composition, A07 matrix for the live transports |

## Changed files

All under `crates/adapters/central-adapter-linux/` unless noted.

New (8b): `src/broker/restore_capacity/{allocation,object,inspection,sweep,helper,reserve_frame,gate}.rs`
Modified (8a+8b): `src/broker/restore_capacity/{mod,frame,receipt,store,store_path}.rs`,
`src/broker/{server,restore_credential,recovery_journal}.rs`,
`src/helper/daemon.rs`, `src/infra/capacity_roles.rs`
Modified (8c): `src/broker/daemon.rs`, `tests/{a07_authority,a07_peers}.rs`,
`.superpowers/sdd/task-r6-7-report.md` (T7 addendum)

## What landed

- **Allocation (`allocation.rs`)** — per-role `measure_root` (statfs
  allowlist, fsid fingerprint, authoritative `st_dev`), `collapse`
  deduping the four roles onto physical devices with both directions
  of identity disagreement refused, `pre_allocation_floor` /
  `post_allocation_floor` over `restore_admission_margin`,
  `MAX_OBJECTS_PER_HOST`/`MAX_HOST_BYTES` caps, `AtomicBool`
  single-live-set guard, `ReservePlan` member-intent generation, and
  `fallocate` extent allocation with per-device cleanup on failure.
- **Objects (`object.rs`, `store_path.rs`)** — one `<fingerprint>.reserve`
  per device under the anchor role's `.central-restore-capacity-reserve`
  store; descriptor traversal, `O_NOFOLLOW`, ownership/mode checks;
  physical truth is `st_blocks × 512`, never `st_size`.
- **Inspection (`inspection.rs`)** — locator-free, quantity-bucketed
  (`none`/`one`/`several`) digest, HMAC-protected; never exposes exact
  bytes, `st_dev`, inode, path, observed free bytes, or reserve keys.
- **Sweep (`sweep.rs`) + helper (`helper.rs`)** — root-helper-only
  reconciliation (expiry, terminal, receipt-window lapsed, orphan
  objects) with `SweepCaller::{HelperStartup, HelperRestoreLauncher}`;
  the narrow `ReserveHelperAuthority` keeps the root helper off the
  full broker surface; `sweep_and_publish` pairs the pass with the
  inspection digest. Helper daemon runs the startup sweep before
  serving and reports-and-continues on failure.
- **Gate (`gate.rs`)** — the kind-1 `0xc2` preconditions in order:
  ticket-launch carry → committed unexpired set bound to this
  operation and the *issuing* launch → dump bytes/artifact count
  re-derived from the daemon's own seal (object bytes carried per the
  ADR-0018 residual) → member records + receipt-ledger spend proof →
  per-device collapse → post-allocation floor/margin → daemon-side
  `fstat` requiring `allocated ≥ SURVIVAL_RESERVE_BYTES` and `≥
  reserved_bytes` → `Allocated → Verified` commit. Expiry bounds entry
  only: a committed set is re-admitted past `absolute_expires_at`
  through the identical unrelaxed checks. Refusal vocabulary is
  exactly `RESTORE_STATE_INVALID` (evidence) and
  `RESTORE_CAPACITY_INSUFFICIENT` (arithmetic/extent).
- **`restore_credential.rs`** — kind 1 calls the gate before reading
  the migration passfile; a service without capacity stores fails
  closed `STATE_INVALID`. Kinds 2 and 3 are unchanged.
- **`daemon.rs`** — production composition derives `RoleRoots` via
  `infra::capacity_roles::role_roots(instance)` and installs them on
  the broker service; the hardened daemon never enumerates reserve
  directories (0xc5 reads one fixed-name digest).

## `0xc*` arm status (≤8 lines)

- `0xc2` kind 1: **live** — capacity gate, then passfile; kinds 2/3 unchanged.
- `0xc3`: **live** — helper reserve write path (`RESTORE_RESERVE_*` refusals).
- `0xc4`: **live** — engine receipt draw/consume/bind (`RESTORE_RECEIPT_*`).
- `0xc5`: **live** — root-only inspection digest (`RESTORE_INSPECTION_*`).
- Unauthorized peer on any arm: arm-specific `*_PEER_DENIED`; malformed
  body past the peer gate: arm-specific `*_FRAME_INVALID`.
- No restore-capacity arm answers `UNSUPPORTED_IN_THIS_SLICE` anymore.

## Verification (all run this session)

- `cargo fmt --all -- --check` — clean.
- `cargo clippy -p central-adapter-linux --all-targets -- -D warnings` — clean.
- `cargo check --workspace` — clean.
- `cargo deny check` — advisories/bans/licenses/sources ok.
- `cargo test -p central-adapter-linux --lib` — **742/742 pass**
  (86 restore-capacity tests; +17 allocation tests, +15 gate tests).
- `cargo test -p central-adapter-linux --test a07_authority` — **26/26**.
- `cargo test -p central-adapter-linux --test a07_peers` — **14/14**.
- Root-only/`CENTRAL_TIER3` variants skip as non-root — expected.

Gate tests cover: helper-evidence admission, missing/unspent/unbound
sets, issuing-launch vs backup misbinding, expiry as entry-not-
continuation bound, seal disagreement, reserved-figure bounds and
per-device disagreement (invalid, not insufficient), anchor-role
agreement with the helper collapse, per-device demand dedup,
identity disagreement both directions, sparse/missing extents, spend
from another launch, drifted operation pointer, and fail-closed
surfaces without stores/roots.

## Carried gaps

- Upstream's second/third sweep call sites sit inside the production
  restore-engine launcher (`cmd/central/restore_engine_launcher.go`),
  which stays deferred: `restore_verify`/`restore_apply`/
  `restore_resume` remain unconfigured (their upstream
  `*_UNAVAILABLE` answers, never success). `ReserveHelperAuthority`
  + `SweepCaller::HelperRestoreLauncher` are in place so the wiring
  lands with that launcher.
- Upstream's ~160 restore-capacity tests remain materially broader;
  the Rust suite now holds 86 in this area including the ported
  refusal/extent/collapse matrix.
