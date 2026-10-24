# R3-D1 — `ProtectedBootstrap` port lives in `central-session`; R3 ships only the dev-gated file implementation in `central-adapter-linux`

- **Type:** Open-decision resolution record (R3 plan Open Decision D1), not a defect — recorded per the R3 plan's "record in `docs/internal/tasks/`" instruction.
- **Decided:** 2026-10-23 in the R3 plan (`docs/internal/superpowers/plans/2026-10-23-phase-r3-harness-control-plane-and-serve.md`, Open Decisions table, D1); implemented in Task 10 on branch `r3-harness-control-plane-and-serve`.
- **Question:** Bootstrap token authority lives in the R5 protected broker. Does R3 ship `ProtectedBootstrap` as a port plus a file-backed dev implementation behind the same dev gate as `localexec`?
- **Decision:** Yes.

## What the decision fixes

- The `ProtectedBootstrap` port trait is owned by `central-session::port` (`crates/capabilities/central-session/src/port.rs`) — the capability owns its interface per the application-boundary matrix (`docs/architecture/rust-application-boundaries.md` §Linux platform row, which already names this exact port for `central-adapter-linux`).
- The dev implementation is `DevFileProtectedBootstrap` in `crates/adapters/central-adapter-linux/src/dev_bootstrap.rs` — the crate that later hosts the broker-backed implementation — **never** in `central-adapter-postgres`. It persists only opaque candidate-binding state (`candidate_id`, `generation`, hex `digest`, `activated`) to `bootstrap-candidate-state.json` with write-tmp/fsync/rename/fsync-dir atomicity, mirrors upstream `internal/adapter/authority/broker/bootstrap_session.go`, and keeps every refusal collapsed to `FailureClass::AuthorityDenied` + `Sentinel::AuthorityDenied`.
- Construction fails closed unless `CENTRAL_LOCALEXEC=1` — the same `DEV_GATE_ENV` variable `central-adapter-harness::localexec::DEV_GATE_ENV` uses (issue-120 dev-gate contract). `central-adapter-linux` defines its own constant because adapters must not import other adapters.
- The broker-backed implementation lands in R5 (R5 plan Task 5/14: "session bootstrap uses broker `ProtectedBootstrap`; R3 `central-adapter-linux::dev_bootstrap` only behind the dev gate"; R5 D5 carry-forward list).

## Why this shape

- Putting the trait in the capability keeps the session slice end-to-end runnable in R3 (two-phase exchange → delivery → activate → validate) without the broker, and keeps the R5 replacement a pure adapter swap with no capability API churn.
- The dev gate keeps the file-backed authority out of any production composition path: constructing it without the gate returns `AuthorityDenied`, and the kernel is not wired to it.
- Persisting only opaque binding evidence (no plaintext bootstrap values, no verifier material) keeps the dev file consistent with the leak-proofing contract even though it is dev-only.

## Anchors

- Port trait: `crates/capabilities/central-session/src/port.rs` (`ProtectedBootstrap`).
- Dev implementation: `crates/adapters/central-adapter-linux/src/dev_bootstrap.rs` (`DevFileProtectedBootstrap`, `DEV_GATE_ENV`).
- Upstream reference: `$CENTRAL_SRC/internal/adapter/authority/broker/bootstrap_session.go`.
- R5 replacement: `docs/internal/superpowers/plans/2026-10-23-phase-r5-host-authority-broker-compose.md` (D5 carry-forward, Task 5 step 1, Task 14).
