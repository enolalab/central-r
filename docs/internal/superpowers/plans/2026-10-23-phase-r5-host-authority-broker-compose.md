# Phase R5 — Host Authority, Protected Broker & Compose Topology (Slice A & B01–B07 Parity) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the complete Phase R5 vertical slice in `$CENTRAL_RUST_SRC` per [rust-vertical-slice-roadmap.md](../../../implementation/rust-vertical-slice-roadmap.md) §8: implement the audited `central-adapter-linux` OS boundary (`memfd`, `SCM_RIGHTS`, `SO_PEERCRED`, `openat2`, `pidfd`, hardening, PAM/TTY, namespaces/cgroups), the socket-activated `central-protected-broker` (protected state, sealed descriptor delivery, signing, local TLS authority, export tokens, signed XDG projections, authoritative transition journal), the root helper with its closed operation matrix and PAM/TTY + ADR 0028 `grant` ceremonies, the `central-sandbox-launcher`, and `central-infra` (strict `central.config/v1`, instance genesis, advisory consumer, dependency prepare, six-service Compose lifecycle); make `central local init|prepare|up|down|doctor|status` work end to end; replace every R3 dev-gated stand-in (bootstrap authority, workspace seal, launcher syscalls) with the real boundary; pass the A07 denial suite on the reference host plus the §7 fail-fast pipeline.

**Architecture:**
- **Crate roles ([rust-application-boundaries.md](../../../architecture/rust-application-boundaries.md) §2, lines 58, 87, 151, 844):**
  - `central-infra` (capability) owns typed local-operator commands — init, prepare, up/down, doctor, status, advisory — plus `config` (`central.config/v1`) and `authority` (instance genesis, locked service identities). Depends only on `central-foundation`, `serde`, `serde_json`, `sha2`, `ed25519-dalek`, `time`, `trait-variant`. **Never calls Docker, Compose, `pg_*`, or S3 directly**: every infrastructure action is a helper-protocol request through a port.
  - `central-adapter-linux` is the single audited `unsafe` site among library crates. It implements `central-infra`/`central-authorization` platform ports and hosts the broker, helper, and sandbox-launcher server logic. `rustix` safe wrappers first; raw `unsafe` only where `rustix` has no wrapper (PAM FFI, seccomp install), each block in one `unsafe_audit.rs`-style module with a `// SAFETY:` proof and a test.
  - Protected execution modes of `bins/central` (`helper`, `central-protected-broker`, `central-sandbox-launcher`) are thin entrypoints: parse mode → compose `central-adapter-linux` server → run. They are the only bins besides launcher daemons allowed to link `central-adapter-linux`.
  - `bins/central local *` → `central-infra` service → helper protocol client. The unprivileged `central` process never holds root, protected state, or plaintext secrets.
- **Scope split with R6:** broker/helper operations for backup, restore, restore-capacity reserve, migration launch, recovery, wipe, export/import, prune, delete, rescue, maintenance, and security-update are **R6**. In R5 they exist only as closed matrix entries that deny with the exact upstream "unsupported in this slice" outcome.
- **Already delivered earlier (not re-done here):** A01 workspace scaffold (R1), B05 migration baseline (R1), B07 task lifecycle (R1), B08–B12 runtime (R1–R3).

**Tech Stack:** pinned — `rustix =1.1.5` (`fs`, `net`, `process`, `shm`, `mm`), `ed25519-dalek =3.0.0`, `hmac =0.13.0`, `rand =0.10.3`, `zeroize =1.9.1`, `rustls =0.23.46`, `sha2`, `serde`/`serde_json`, `tokio`, `tracing`. **New dependencies — approved by the maintainer on 2026-10-23 (D2, D3, D7).** Each is added to `[workspace.dependencies]` with an exact pin in the task that first uses it, and each is confined to the listed crate (record the scope in the `Cargo.toml` comment block, matching the existing style):
- `libc = "=0.2.191"`: `central-adapter-linux` only (seccomp install); already in `Cargo.lock` transitively.
- `rcgen = { version = "=0.14.10", default-features = false, features = ["ring", "pem"] }`: `central-adapter-linux` only (TLS authority); `ring` is already in `Cargo.lock` via `sqlx`.
- `tar = "=0.4.46"` and `flate2 = "=1.1.10"` (default `miniz_oxide` backend): `central-adapter-linux` only in R5; R6 reuses them for export bundles.

Each addition must pass `cargo deny check` in the same task. A license or advisory failure stops the task and is escalated; `deny.toml` is never edited to get past it. RFC 8785 JSON canonicalization (upstream `github.com/gowebpki/jcs`, used by `internal/config/*`, `internal/advisory/verify.go`, `internal/dependencyprepare/lock.go`) is proposed as a hand-written `central-foundation::jcs` module with no new crate (D6); R6 reuses it for backup manifests, reseed, export bundles, and `central-advisory-sign`.

## Global Constraints

- **Source of truth:** `$CENTRAL_SRC` (read-only) — `internal/adapter/authority/{broker,helper}`, `internal/{authority,sandbox,secretbootstrap,infralifecycle,config,advisory,dependencyprepare,audit,cli}`, `internal/adapter/{infralifecycle,advisory,dependencyprepare}`, `cmd/central/{modes,broker_serve,local_init_*,prepare_helper_linux,grant_cli,init_client,lifecycle_broker_rendezvous,postgres_*_credential}.go`. Compose topology comes from the pinned `$CENTRAL_INFRA_SRC` (upstream pin: `ci/update-infra-pin.sh`, `internal/adapter/infralifecycle/assets/compose-policy.json`).
- **Wire parity:** broker frames (incl. frame `0xB1` peer authorization widened to the runtime UID, ADR 0013), helper protocol frames, journal record encoding, signature payloads, `central.config/v1` schema, and `central.local-result/v1` outputs are byte-identical to upstream fixtures. Changing any of them requires a Proposed ADR (AGENTS.md D3 rule 2).
- **No weakened checks:** peer-credential checks, closed operation matrix, PAM/TTY physical-console requirement, and ADR 0028 ceremony stay exactly as strict as upstream. A test that cannot pass without relaxing a check is a blocker, not a fix.
- **Secrets:** plaintext secrets exist only in sealed `memfd`s or `zeroize`d buffers; never in logs, `Display`, argv, environment, or files outside `protected_file_v1`.
- **`unsafe` discipline:** only in `central-adapter-linux`, launcher daemons, and protected-mode bins; each block has a `// SAFETY:` comment and a test. `unsafe_code = "forbid"` stays on every other crate.
- **Test tiers:** portable tests run everywhere; root/reference-host tests skip automatically as non-root or off the pinned host (expected, not a failure). Tier 3 runs on the reference host before closeout.
- **Every task ends green:** `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test -p <touched crates>` (+ `cargo test --workspace` when a port trait or a `central-foundation` type changes), then commit.

---

## Open Decisions

| ID | Question | Gates | Default if no ruling |
| --- | --- | --- | --- |
| D1 | PAM: upstream uses cgo `-lpam`. Hand-written audited FFI in `central-adapter-linux` (`build.rs` emits `cargo:rustc-link-lib=pam`, no new crate) vs a `pam-*` crate. | Task 5 | Hand-written FFI, minimal surface (`pam_start`, `pam_authenticate`, `pam_acct_mgmt`, `pam_end`, conversation callback) |
| D2 | Seccomp: `rustix` has no seccomp-filter install. | Task 4 | **Decided 2026-10-23:** `libc =0.2.191` as a direct dependency of `central-adapter-linux` only |
| D3 | X.509 issuance for the local TLS authority (upstream Go `crypto/x509`). | Task 7 | **Decided 2026-10-23:** `rcgen =0.14.10`, `default-features = false`, features `ring` + `pem`, in `central-adapter-linux` only |
| D4 | Identity creation (`central-runtime`, `central-agent`, `central-browser`) and Compose invocation: exec system tools as upstream does (`useradd`, `docker compose`) from the helper only? | Tasks 12–13 | Yes, exact upstream argv, from the root helper only |
| D5 | Where do the R3 carry-forwards move (R3 D1 dev bootstrap, D2 workspace seal, D3 launcherd syscalls)? | Task 14 | Into `central-adapter-linux`; R3 dev implementations deleted or kept only behind the dev gate for tests |
| D6 | RFC 8785 JSON canonicalization (upstream `gowebpki/jcs`) for config digests, advisory signature payloads, and the dependency lock: a hand-written `central-foundation::jcs` module vs a crate (e.g. `serde_jcs`). Shared with R6 (backup manifests, reseed, export bundle, `central-advisory-sign`). | Tasks 2, 10, 11 | Hand-written over `serde_json::Value`: sorted keys by UTF-16 code units, ECMAScript number formatting, minimal string escaping; verified against the RFC 8785 test vectors plus byte-equality with upstream Go fixtures. No new crate |
| D7 | `tar` + gzip for dependency prepare (upstream `archive/tar` + `compress/gzip` in `internal/adapter/dependencyprepare/{fetch,buildkit,release_stage}_linux.go`): shared with R6 export bundles. | Task 11 | **Decided 2026-10-23:** `tar =0.4.46` + `flate2 =1.1.10` (default `miniz_oxide` backend; yanked 1.1.6/1.1.7 avoided), in `central-adapter-linux` only |

---

## File Structure

```text
central-rust/
├── crates/
│   ├── capabilities/central-infra/src/
│   │   ├── lib.rs, domain.rs, port.rs, query.rs, app.rs
│   │   ├── config/{mod,schema,strict_json,defaults,view}.rs      # central.config/v1 (A05)
│   │   ├── authority.rs                                          # genesis, locked identities (A03)
│   │   ├── advisory.rs                                           # B01 consumer
│   │   ├── prepare.rs                                            # B02 dependency prepare
│   │   └── lifecycle.rs                                          # B03/B04 compose lifecycle + preflight
│   └── adapters/central-adapter-linux/
│       ├── build.rs                                              # link libpam (D1)
│       └── src/
│           ├── lib.rs
│           ├── sys/{memfd,scm_rights,peercred,openat2,pidfd,hardening,seccomp,tty,pam,cgroup,namespace}.rs
│           ├── broker/{protocol,server,journal,protected_file,signing,tls,secret_bootstrap,
│           │          bootstrap_session,handoff,export_token,payload_epoch,provisioning,proof}.rs
│           │          # no xdg.rs — signed views are central-infra::config::view
│           │          # (central.view-signature/v1), not a broker-side schema
│           ├── helper/{protocol,server,client,matrix,init,prepare,grant,pam_ceremony,tty_ceremony,
│           │          browser,audit,lifecycle}.rs
│           ├── sandbox/{envelope,launcher,daemon,path_resolve}.rs
│           ├── infra/{compose,lifecycle,capacity_roles,advisory_fetch,dependency_prepare}.rs
│           └── workspace_seal.rs                                 # adopted from R3 D2
└── bins/central/src/
    ├── modes.rs, broker_mode.rs, helper_mode.rs, sandbox_mode.rs
    └── local_cli.rs, grant_cli.rs
```

---

## Milestone A — Pure foundations (A02, A03, A05)

### Task 1: Command census & exit matrix audit (A02)

**Files:** Modify `bins/central/src/main.rs`; create `bins/central/src/{modes,local_cli,grant_cli}.rs` (dispatch skeletons only).

**Reference:** `cmd/central/{main,modes}.go`, `internal/cli/{exit,result,tty}.go` + tests; dossier `slice-a-host-authority-foundation.md` §A02.

- [ ] **Step 1:** Port upstream census tests: every registered verb, closed grammar, unknown verb → usage error, deferred verbs → exact `exit 5` `UNSUPPORTED_IN_THIS_SLICE` envelope, protected modes reachable only by exact mode argv.
- [ ] **Step 2:** Register `local init|prepare|up|down|doctor|status`, `grant`, and the three protected modes; R6 verbs remain fail-closed.
- [ ] **Step 3:** `cargo test -p central` PASS → commit `feat(cli): complete A02 command census for R5 verbs and protected modes`.

### Task 2: `central-infra::config` — strict `central.config/v1` (A05)

**Files:** Create `crates/central-foundation/src/jcs.rs` (D6); create `crates/capabilities/central-infra/src/config/{mod,schema,strict_json,defaults,view}.rs`; modify `crates/central-foundation/src/lib.rs`, `central-infra/src/lib.rs`, `Cargo.toml`.

**Reference:** `internal/config/{schema,strictjson,view,defaults/defaults}.go` + tests; `vendor/github.com/gowebpki/jcs` (behavior reference only); RFC 8785 Appendix test vectors; `docs/security/local-configuration-and-protected-state.md`.

- [ ] **Step 0 (D6):** Write failing tests for `central_foundation::jcs::canonicalize(&serde_json::Value) -> Result<Vec<u8>, JcsError>`: RFC 8785 vectors (key order by UTF-16 code units, number serialization incl. `1e21`, `-0`, `5e-324`, string escapes), rejection of non-finite numbers, and byte-equality with canonical outputs captured from upstream Go fixtures. Implement, run `cargo test -p central-foundation` → PASS, then `cargo test --workspace` (shared foundation type). Commit `feat(foundation): add RFC 8785 JSON canonicalization`.
- [ ] **Step 1:** Port tests: unknown field rejection, duplicate keys rejected, cross-field validation, hard caps, signed authority-transition consumption, XDG projection is non-authoritative, no flag/env override of authority fields → FAIL.
- [ ] **Step 2:** Implement strict JSON decoding (reject duplicates/unknowns), schema types, defaults, `ConfigView`; every config digest and signed-transition payload is computed over `central_foundation::jcs::canonicalize` output.
- [ ] **Step 3:** PASS → commit `feat(infra): add strict central.config/v1 loader and validation`.

### Task 3: `central-infra` domain — authority, ports, app skeleton (A03 domain)

**Files:** Create `central-infra/src/{domain,authority,port,query,app}.rs`.

**Reference:** `internal/authority/{domain,genesis,identity}.go`, `port/*.go`, `app/genesis_service.go`; `internal/infralifecycle/{domain,port/lifecycle_port}.go`; `internal/secretbootstrap/{domain,minio_*_policy}.go`.

- [ ] **Step 0:** Confirm crate placement against boundaries §2 (authority domain in `central-infra` vs `central-authorization`); record the choice in the commit body.
- [ ] **Step 1:** Port domain tests: instance genesis record, locked identity specs (no login, no Docker/broker group), secret-bootstrap policies (MinIO runtime/recovery), lifecycle state machine → FAIL.
- [ ] **Step 2:** Implement pure domain and the port traits (`HelperClient`, `BrokerClient`, `GenesisPort`, `LifecyclePort`, `AdvisoryFetch`, `DependencyStore`).
- [ ] **Step 3:** PASS; `cargo test --workspace` (new ports) → commit `feat(infra): port host-authority domain and platform ports`.

## Milestone B — Audited OS boundary & privileged servers (A03, A04, A06)

### Task 4: `central-adapter-linux::sys` primitives (D2)

**Files:** Create `src/sys/{memfd,scm_rights,peercred,openat2,pidfd,hardening,seccomp,cgroup,namespace}.rs`; modify `Cargo.toml` (`[lints]` override documented), `lib.rs`.

**Reference:** `internal/adapter/authority/broker/{hardening,handoff_linux,protected_file_linux}.go`, `hardening_filter_test.go`; `internal/sandbox/{envelope_linux,launcher_linux,path_resolve}.go`.

- [ ] **Step 1:** Failing tests: sealed `memfd` (`F_SEAL_SEAL|SHRINK|GROW|WRITE`) round-trip, reject unsealed/empty/wrong-size descriptors; `SCM_RIGHTS` send/recv over a socketpair, extra-fd rejection; `SO_PEERCRED` UID/PID/GID; `openat2` with `RESOLVE_BENEATH|NO_SYMLINKS|NO_MAGICLINKS` blocks `..`/symlink escapes; `pidfd` liveness; `PR_SET_DUMPABLE=0`, `PR_SET_NO_NEW_PRIVS`, capability bounding-set drop.
- [ ] **Step 2:** Implement with `rustix`; seccomp default-deny filter per upstream syscall list, installed via `libc` (`prctl(PR_SET_SECCOMP)`/`seccomp(2)` with a `sock_fprog`) inside one audited `unsafe` block (D2). Add `libc = "=0.2.191"` to `[workspace.dependencies]` and to `central-adapter-linux` only. A failed install aborts broker start (fail closed). Add a test that a denied syscall kills or `EPERM`s a forked child.
- [ ] **Step 3:** `cargo test -p central-adapter-linux` PASS (root-only cases skip) → commit `feat(adapter-linux): add audited memfd, SCM_RIGHTS, peercred, openat2, pidfd, hardening primitives`.

### Task 5: PAM & TTY physical-console boundary (D1)

**Files:** Create `build.rs`, `src/sys/{pam,tty}.rs`.

**Reference:** `internal/adapter/authority/helper/{pam_linux,pam,tty_ceremony_read_linux,confirmation_phrase,init_ceremony_prompt}.go` + tests.

- [ ] **Step 1:** Failing tests: conversation callback answers only echo-off password prompts; PAM error codes map to closed outcomes; TTY check rejects non-console/pseudo-terminal per upstream rules; confirmation phrase read is exact-match and `zeroize`d.
- [ ] **Step 2:** Implement minimal FFI (every `unsafe` block with `// SAFETY:`) and TTY reader.
- [ ] **Step 3:** PASS (PAM integration skips without a test PAM service) → commit `feat(adapter-linux): add audited PAM and TTY physical-console boundary`.

### Task 6: Broker core — protocol, server, journal, `protected_file_v1` (A04 part 1)

**Files:** Create `src/broker/{protocol,server,journal,protected_file,payload_epoch,provisioning,proof}.rs`.

**Reference:** `internal/adapter/authority/broker/{server,service,journal,protected_file,protected_file_linux,payload_epoch_store_linux,provisioning_store,proof_service,lifecycle,lifecycle_client}.go` + tests (excluding backup/restore/migration/recovery files → R6); ADRs 0012, 0013.

- [ ] **Step 1:** Port tests: frame codec golden vectors, frame `0xB1` peer authorization admits the runtime UID and nothing else, unknown op → closed denial, journal append-only + crash recovery (torn tail truncated, never reinterpreted), `protected_file_v1` atomic write/rename with `openat2`, epoch fencing → FAIL.
- [ ] **Step 2:** Implement single-threaded socket-activated server loop (`LISTEN_FDS`), journal, protected store, proof service; R6 ops registered as closed denials.
- [ ] **Step 3:** PASS → commit `feat(adapter-linux): add protected broker protocol, server, journal, and protected_file_v1`.

### Task 7: Broker custody — signing, TLS, secret bootstrap, handoff, XDG, export tokens (A04 part 2, D3)

**Files:** Create `src/broker/{signing,tls,secret_bootstrap,bootstrap_session,handoff,xdg,export_token}.rs`.

**Reference:** `broker/{signing,tls_authority,tls_persistent,secret_bootstrap,secret_bootstrap_transport_linux,bootstrap_session,handoff,handoff_linux,b10_runtime_binding,minio_runtime_client_linux}.go` + tests.

- [ ] **Step 1:** Port tests: Ed25519 signatures over exact upstream payloads, TLS leaf issuance + persistence/rotation, secret bootstrap delivers a sealed `memfd` via `SCM_RIGHTS` to the authorized peer only, session bootstrap tokens (the real `central-session::port::ProtectedBootstrap`), signed XDG views, export-token signing/verification → FAIL.
- [ ] **Step 2:** Implement. Do TLS leaf/CA issuance with `rcgen =0.14.10` (`ring` backend, D3) inside `central-adapter-linux::broker::tls`. Private keys stay in `zeroize`d buffers or sealed `memfd`s, and no `rcgen` type crosses the adapter boundary. The test must check that issued certificates' fields (subject, SAN `127.0.0.1`, validity, key usage) match the upstream Go fixtures.
- [ ] **Step 3:** PASS → commit `feat(adapter-linux): add broker signing, TLS authority, secret bootstrap, and signed projections`.

### Task 8: Root helper — protocol, closed matrix, ceremonies, `grant` (A03 + ADR 0028)

**Files:** Create `src/helper/{protocol,server,client,matrix,init,prepare,grant,pam_ceremony,tty_ceremony,browser,audit,lifecycle}.rs`; port `internal/audit/audit.go` into `helper/audit.rs`.

**Reference:** `internal/adapter/authority/helper/{server,protocol,client_linux,matrix,init,init_client_linux,prepare,prepare_confirmation,grant,grant_owner_unix,grant_flock_unix,browser,audit,production_lifecycle}.go` + tests; ADR 0028; `docs/operations/local-security-authority.md`.

- [ ] **Step 1:** Port tests: closed operation matrix (every op × caller identity → exact allow/deny; R6 ops deny with "unsupported in this slice"), fresh-PAM requirement per op, `grant` ceremony (owner check, `flock`, context-independent verdict), browser profile launch as `central-browser`, audit record per decision → FAIL.
- [ ] **Step 2:** Implement server/client and in-scope ops (init, prepare, up/down/status/doctor, grant, browser).
- [ ] **Step 3:** PASS → commit `feat(adapter-linux): add root helper with closed operation matrix and grant ceremony`.

### Task 9: Sandbox launcher (A06) + protected-mode entrypoints

**Files:** Create `src/sandbox/{envelope,launcher,daemon,path_resolve}.rs`; `bins/central/src/{broker_mode,helper_mode,sandbox_mode}.rs`.

**Reference:** `internal/sandbox/*.go` + tests; `cmd/central/{modes,broker_serve,lifecycle_broker_rendezvous}.go`.

- [ ] **Step 1:** Port tests: descriptor-bound request only, `central-agent` identity, resource envelope (cgroup limits, namespaces), denial matrix (absolute path escapes, extra fds, wrong caller, env injection) → FAIL.
- [ ] **Step 2:** Implement launcher and the three mode entrypoints (each composes one server, no other capability).
- [ ] **Step 3:** PASS → commit `feat(adapter-linux): add sandbox launcher and protected execution modes`.

## Milestone C — Local environment (B01–B04, B06)

### Task 10: Advisory consumer (B01)

**Files:** Create `central-infra/src/advisory.rs`, `central-adapter-linux/src/infra/advisory_fetch.rs`.

**Reference:** `internal/advisory/*`, `internal/adapter/advisory/*` + tests; `docs/operations/release-authority-custody.md`.

- [ ] **Step 1:** Port tests: Ed25519 verification against the accepted public key over the JCS-canonical payload (D6, exact upstream bytes), compatibility-matrix evaluation, unsupported host rejected before any prepare step → FAIL.
- [ ] **Step 2:** Implement using `central_foundation::jcs`; PASS → commit `feat(infra): add signed release-advisory consumer and admission gate`.

### Task 11: `central local prepare` (B02)

**Files:** Create `central-infra/src/prepare.rs`, `central-adapter-linux/src/infra/dependency_prepare.rs`, `bins/central/src/local_cli.rs` (prepare).

**Reference:** `internal/dependencyprepare/*` (incl. `assets/dependency-lock.json`), `internal/adapter/dependencyprepare/*`, `cmd/central/prepare_helper_linux.go` + tests; dossier B02.

- [ ] **Step 1:** Port portable tests: JCS-canonical `dependency-lock.json` digest (D6), PostgreSQL 16.14 OCI index/platform/config digest verification, MinIO archive SHA-256 + pinned commit, refusal on any mismatch, confirmation prompt → FAIL.
- [ ] **Step 2:** Implement lock/digest verification (all Docker/build actions run inside the helper); PASS → commit `feat(infra): add verified dependency lock and digest checks`.
- [ ] **Step 3 (D7):** Port `fetch_linux`/`buildkit_linux`/`release_stage_linux` tests: gzip-tar archive streaming with SHA-256 verification, path-traversal and symlink entries rejected, build-context tar staged byte-identically → FAIL → add `tar = "=0.4.46"` + `flate2 = "=1.1.10"` to `[workspace.dependencies]` and `central-adapter-linux` only, implement, and run `cargo deny check` → PASS → commit `feat(adapter-linux): add verified archive fetch and build staging for local prepare`.

### Task 12: Six-service Compose lifecycle + credentials (B03, B04, D4)

**Files:** Create `central-infra/src/lifecycle.rs`, `central-adapter-linux/src/infra/{compose,lifecycle,capacity_roles}.rs`; extend `local_cli.rs` (up/down/status/doctor).

**Reference:** `internal/infralifecycle/{domain,app/service,preflight/harness}.go`, `internal/adapter/infralifecycle/{compose_linux,lifecycle_linux,capacity_roles_linux}.go` + `assets/compose-policy.json`, `cmd/central/{postgres_service_role_credential,postgres_superuser_credential,postgres_service_role_compose_runner}.go`; pinned `central-local-infra`; dossiers B03/B04.

- [ ] **Step 1:** Port the portable semantic lifecycle suite: exact topology (`postgres-fs-init`, `minio-fs-init`, `postgres`, `minio`, `postgres-provision`, `minio-provision`), digest-qualified images, `pull_policy: never`, `restart: "no"`, single internal `infra` network, ordered one-shot/daemon/provisioner lifecycle, denial paths, recovery, redaction; B04 durable credential creation/handoff via broker `memfd` → FAIL.
- [ ] **Step 2:** Implement; `doctor`/`status` are read-only.
- [ ] **Step 3:** PASS → commit `feat(infra): add six-service compose lifecycle and durable credential handoff`.

### Task 13: `central local init` — instance genesis (A03, D4)

**Files:** Extend `central-infra/src/app.rs`, `central-adapter-linux/src/helper/init.rs`, `local_cli.rs` (init).

**Reference:** `cmd/central/{local_init_genesis_linux,local_init_helper_linux,init_client}.go`, `helper/{init,init_client_linux,init_ceremony_prompt}.go` + tests.

- [ ] **Step 1:** Failing tests: fresh PAM + TTY ceremony, instance identity + locked identities created idempotently, directories with exact owner/mode, initial protected state via broker, re-run on an initialized host is a no-op with the upstream result code.
- [ ] **Step 2:** Implement; PASS → commit `feat(infra): add local init instance genesis`.

### Task 14: Serve hardening (B06) + R3 carry-forward adoption (D5)

**Files:** Modify `crates/central-kernel/src/{serve,session_compose,harness_compose}.rs`, `central-transport-http` listener config, `central-adapter-linux/src/{workspace_seal,dev_bootstrap}.rs`, `bins/central-harness-launcherd/src/*`. No change to `central-adapter-harness`.

**Reference:** dossier B06; `cmd/central/browser_runtime.go`; R3 plan Open Decisions D1–D3.

- [ ] **Step 1:** Failing tests: serve binds only `127.0.0.1:8080`, TLS 1.3 only, instance cert from broker; browser profile opens via helper as `central-browser`; session bootstrap uses broker `ProtectedBootstrap` (R3 `central-adapter-linux::dev_bootstrap` only behind the dev gate); the R3 `central-adapter-linux::workspace_seal` (injected by the kernel through the harness `WorkspaceSealer` port, so `central-adapter-harness` never imports `central-adapter-linux`) and `central-harness-launcherd` move onto the shared `central-adapter-linux::sys` primitives.
- [ ] **Step 2:** Implement; `cargo test --workspace` PASS → commit `feat(kernel): serve over broker TLS and adopt the linux boundary for R3 stand-ins`.

## Milestone D — Acceptance

### Task 15: A07 denial suite + Tier 3 reference host

**Files:** Create `crates/adapters/central-adapter-linux/tests/a07_*.rs`.

**Reference:** dossier §A07; upstream A07 tests under `internal/adapter/authority/**/_test.go`; `docs/security/threat-model.md`, `docs/security/capability-policy.md`.

- [ ] **Step 1:** Implement scenarios: same-UID attacker denied, descriptor smuggling, TTY spoofing, path races (`openat2`), broker crash mid-transition (journal recovery), every authority denial path.
- [ ] **Step 2:** Run portable subset locally; run full Tier 3 on the reference host and record the evidence path.
- [ ] **Step 3:** Commit `test(adapter-linux): add A07 host-authority denial suite`.

### Task 16: R5 closeout

**Files:** Modify `docs/implementation/current-phase.md`; operations docs only if behavior differs.

- [ ] **Step 1:** `cargo sqlx prepare --check --workspace -- --all-targets && cargo fmt --all -- --check && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo deny check && cargo test --workspace`
- [ ] **Step 2:** End-to-end on a clean host: `central local init` → `prepare` → `up` → `status` → `doctor` → `serve` → `down`.
- [ ] **Step 3:** Mark R5 Complete, R6 Active → commit `docs(phase-r5): mark Phase R5 complete and advance active slice to Phase R6`.

---

## Self-review notes

- **Roadmap §8 coverage:** sealed `memfd` via `SCM_RIGHTS` (T4/T7), TLS leaf + export-token signing (T7), signed XDG views (T7), PAM/TTY ceremonies (T5/T8/T13), ADR 0028 `grant` (T8), helper closed matrix (T8), sandbox denial matrix (T9), `local init|prepare|up|down|doctor|status` (T11–T13), digest-pinned six-service topology (T12), Tier 3 (T15).
- **Size warning:** upstream authority adapter alone is ~40.7k lines; about half (restore/backup/migration/recovery RPC) is R6. This is the riskiest slice — every `unsafe` block and every privileged op needs review.
- **Dependency decisions:** D2 (`libc =0.2.191`), D3 (`rcgen =0.14.10` + `ring`), and D7 (`tar =0.4.46`, `flate2 =1.1.10`) were approved on 2026-10-23; D6 (JCS) is hand-written with no crate. No R5 task is blocked on a maintainer dependency ruling. Remaining risk: `cargo deny check` on each addition.
