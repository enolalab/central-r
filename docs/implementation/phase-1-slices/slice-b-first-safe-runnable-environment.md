# Slice B — First Safe Runnable Environment

- **Slice ID:** B
- **Dossier:** `slice-b-first-safe-runnable-environment.md`
- **Packets:** B01–B12
- **Dependency:** A07 (Slice A complete)
- **First value:** Complete when B12 acceptance passes

Slice B delivers `Local MVP Preview` at B12: one bounded read-only repository-analysis Task completes from browser submission to a verified required Markdown Artifact, exposes PostgreSQL-authoritative progress, supports durable cancel/retry, and survives application restart. B12 also documents an unscheduled operator-invoked `pg_dump` plus `mc mirror` backup bridge. Central-managed backup/restore, quarantine, resume, and authority reset remain Slice C capabilities.

## B01

### Identity and outcome

Implement the local advisory consumer: fetch the signed release-advisory bundle, verify its Ed25519 signature against the accepted public key, evaluate the local environment against the advisory's compatibility matrix, and gate all subsequent admission. B01 must reject an unsupported host before B02 can proceed.

### Implementation boundary

The advisory consumer reads the signed advisory bundle from the accepted distribution path. Signature verification uses the Ed25519 public key embedded in the binary at compile time. The compatibility matrix checks OS release, kernel version, Docker version, Compose version, and PostgreSQL client version against the advisory's declared ranges. A mismatch produces a structured rejection with the exact failing check. Release-security exclusions: B01 does not perform key rotation, signing ceremony, emergency response, or advisory publication.

### Durable data and migration

Advisory evaluation result is recorded in the protected state directory as an authority transition (A05). No PostgreSQL dependency.

### Security and authority

Advisory verification is the first trust establishment in Slice B. An expired or hard-expired advisory rejects admission. The public key is compile-time constant and never read from an untrusted source. Advisory consumer does not fetch over the network during evaluation; the advisory bundle is provisioned via the accepted operator trust-install procedure.

### Failure, retry, cancellation, and recovery

Unsigned advisory, signature mismatch, expired advisory, or incompatible host stops admission with a structured error. Recovery requires a valid signed advisory and a compatible host.

### Verification and evidence

- Valid signed advisory produces passing evaluation with exact host facts recorded
- Expired advisory rejects admission with `ADVISORY_EXPIRED` error
- Hard-expired advisory rejects admission with `ADVISORY_HARD_EXPIRED` error
- Signature mismatch rejects admission with `ADVISORY_SIGNATURE_INVALID`
- Incompatible host (wrong OS, kernel, Docker version) rejects with exact failing check
- Future test suite: `go test ./internal/advisory/...`
- Evidence artifact: `slice-b-advisory-evaluation.json`

### Scope control

B01 owns advisory evaluation. It must not perform key rotation, signing, emergency response, or advisory publication. It gates B02 but does not start services.

### Definition of Done

Advisory consumer verifies signature, evaluates host compatibility, and gates admission. Valid advisory passes; expired, hard-expired, unsigned, or incompatible host fails with structured errors.

## B02

B02 implements explicit `central local prepare` only. It verifies the accepted PostgreSQL 16.14 Bookworm OCI index/platform/config digests and builds the selected MinIO commit `9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a` from archive SHA-256 `be6d0bd3696c3a13a35f02d3a0280b64319c67918b4501c5c3d87f96d000085c` using the hermetic two-clean-builder reproducibility contract. It records exact release/configuration manifests for offline daily operation. It performs no tag-based pull, starts no service, runs no health check, and creates no schema or bucket.

**Status:** Accepted on 2026-07-19 with 191/191 portable and 224/224 reference-host scenarios passing. See acceptance evidence (upstream `central` record: `docs/internal/superpowers/reviews/2026-07-19-phase-1-b02-dependency-prepare-acceptance.md`).

## B03

B03 realizes the exact six-service Compose topology—`postgres-fs-init`, `minio-fs-init`, `postgres`, `minio`, `postgres-provision`, and `minio-provision`—with digest-qualified images, `pull_policy: never`, `restart: "no"`, one internal `infra` network, ordered one-shot/daemon/provisioner lifecycle, loopback-only published ports, three health layers, crash detection, and `up/down/status`. Central remains a host process and is never a Compose service.

**Status:** Accepted on 2026-07-20 on the portable semantic lifecycle suite, which is B03's sole acceptance input and verifies the injected lifecycle service, topology policy, denial paths, recovery, redaction, and structured errors. Reference-host preflight and platform-version gates were deliberately disabled for B03, so no reference-host acceptance count exists for it; the previously recorded "56/56 portable and 6/6 reference-host" figures have no source and are withdrawn. The acceptance decision was committed on 2026-08-12; see B03 acceptance decision (upstream `central` record: `docs/internal/superpowers/reviews/2026-08-12-b03-compose-lifecycle-acceptance-decision.md`) and [B03 evidence reconciliation](../current-phase.md#b03-evidence-reconciliation). Acceptance is semantic: every assertion runs against fakes, and B03's real Compose Render/ComposeRunner path remains unexercised by any acceptance suite.

`local up` and `local down` require a Linux helper built with `CGO_ENABLED=1` and the explicit `pam` build tag against the installed `central-helper` PAM service. The helper authenticates the Unix-socket peer through PAM and reads a fresh fixed confirmation phrase from that peer's physical console TTY; non-PAM builds deny lifecycle mutation. Broker lifecycle nonces are atomically persisted before the lifecycle service is invoked, so replay remains denied after a broker restart. `local down` keeps the MinIO handoff intact until Compose teardown has produced stopped proof for every service; failed proof settles failure evidence and leaves the handoff for safe recovery.

## B04

> **Canonical authority:** B04 Durable Proof Design (upstream `central` record: `docs/internal/superpowers/specs/2026-07-20-phase-1-b04-durable-proof-design.md`) supersedes every conflicting B04 credential creation, handoff, recovery, and acceptance statement below. B04 adopts and materializes only the existing B03 `minio_root_v1` generation; all other registered purposes are declaration-only for their owning later packets.

**Status:** Accepted on 2026-07-21. Portable CI, Linux build, and root reference-host B04 verification passed; see canonical acceptance evidence (upstream `central` record: `docs/internal/superpowers/reviews/2026-07-20-phase-1-b04-canonical-acceptance.md`).

### Identity and outcome

B04 asks the A04 protected broker to create cryptographically random, create-only credential generations for PostgreSQL roles, MinIO identities, and provider/session-related protected values required by accepted configuration. Values are not derivable from instance, Workspace, repository, operator, or configuration inputs. Durable records contain SecretReference identity, backend, generation, purpose, scope, state, and fingerprints—not plaintext.

At use time, the registered destination-specific adapter acquires the single-use authorization fence, revalidates policy/grant/Task/secret generation, and asks the broker for an operation-bound descriptor handoff. Plaintext is available only within the trusted adapter boundary for that invocation and is never returned to the coordinator, agent, generic tool, UI, log, command argument, environment variable, XDG view, Workspace file, or configuration file. Revocation or descriptor replay fails closed.

### Implementation boundary

B04 asks the A04 protected broker to create cryptographically random, create-only credential generations for PostgreSQL roles, MinIO identities, and provider/session-related protected values required by accepted configuration. Values are not derivable from instance, Workspace, repository, operator, or configuration inputs. Durable records contain SecretReference identity, backend, generation, purpose, scope, state, and fingerprints—not plaintext.

At use time, the registered destination-specific adapter acquires the single-use authorization fence, revalidates policy/grant/Task/secret generation, and asks the broker for an operation-bound descriptor handoff. Plaintext is available only within the trusted adapter boundary for that invocation and is never returned to the coordinator, agent, generic tool, UI, log, command argument, environment variable, XDG view, Workspace file, or configuration file. Revocation or descriptor replay fails closed.

### Durable data and migration

B04 asks the A04 protected broker to create cryptographically random, create-only credential generations for PostgreSQL roles, MinIO identities, and provider/session-related protected values required by accepted configuration. Values are not derivable from instance, Workspace, repository, operator, or configuration inputs. Durable records contain SecretReference identity, backend, generation, purpose, scope, state, and fingerprints—not plaintext.

At use time, the registered destination-specific adapter acquires the single-use authorization fence, revalidates policy/grant/Task/secret generation, and asks the broker for an operation-bound descriptor handoff. Plaintext is available only within the trusted adapter boundary for that invocation and is never returned to the coordinator, agent, generic tool, UI, log, command argument, environment variable, XDG view, Workspace file, or configuration file. Revocation or descriptor replay fails closed.

### Security and authority

B04 asks the A04 protected broker to create cryptographically random, create-only credential generations for PostgreSQL roles, MinIO identities, and provider/session-related protected values required by accepted configuration. Values are not derivable from instance, Workspace, repository, operator, or configuration inputs. Durable records contain SecretReference identity, backend, generation, purpose, scope, state, and fingerprints—not plaintext.

At use time, the registered destination-specific adapter acquires the single-use authorization fence, revalidates policy/grant/Task/secret generation, and asks the broker for an operation-bound descriptor handoff. Plaintext is available only within the trusted adapter boundary for that invocation and is never returned to the coordinator, agent, generic tool, UI, log, command argument, environment variable, XDG view, Workspace file, or configuration file. Revocation or descriptor replay fails closed.

### Failure, retry, cancellation, and recovery

B04 asks the A04 protected broker to create cryptographically random, create-only credential generations for PostgreSQL roles, MinIO identities, and provider/session-related protected values required by accepted configuration. Values are not derivable from instance, Workspace, repository, operator, or configuration inputs. Durable records contain SecretReference identity, backend, generation, purpose, scope, state, and fingerprints—not plaintext.

At use time, the registered destination-specific adapter acquires the single-use authorization fence, revalidates policy/grant/Task/secret generation, and asks the broker for an operation-bound descriptor handoff. Plaintext is available only within the trusted adapter boundary for that invocation and is never returned to the coordinator, agent, generic tool, UI, log, command argument, environment variable, XDG view, Workspace file, or configuration file. Revocation or descriptor replay fails closed.

### Verification and evidence

B04 asks the A04 protected broker to create cryptographically random, create-only credential generations for PostgreSQL roles, MinIO identities, and provider/session-related protected values required by accepted configuration. Values are not derivable from instance, Workspace, repository, operator, or configuration inputs. Durable records contain SecretReference identity, backend, generation, purpose, scope, state, and fingerprints—not plaintext.

At use time, the registered destination-specific adapter acquires the single-use authorization fence, revalidates policy/grant/Task/secret generation, and asks the broker for an operation-bound descriptor handoff. Plaintext is available only within the trusted adapter boundary for that invocation and is never returned to the coordinator, agent, generic tool, UI, log, command argument, environment variable, XDG view, Workspace file, or configuration file. Revocation or descriptor replay fails closed.

B04 verification must include:

- Random-generation inequality: two create-only generations for the same purpose produce different cryptographic values
- Direct-open denial for operator/runtime/agent: no identity outside the trusted adapter boundary can open or read a protected value
- Descriptor replay/substitution denial: a stale or substituted operation-bound descriptor is rejected
- Revocation-race denial: a revoked generation cannot be used even under concurrent access
- Redaction scans over logs, configuration, XDG views, Workspace files, and process arguments confirm no plaintext value is present
- Future test suite: `go test ./internal/secrets/...`
- Evidence artifact: `slice-b-secret-bootstrap.json`

### Scope control

B04 asks the A04 protected broker to create cryptographically random, create-only credential generations for PostgreSQL roles, MinIO identities, and provider/session-related protected values required by accepted configuration. Values are not derivable from instance, Workspace, repository, operator, or configuration inputs. Durable records contain SecretReference identity, backend, generation, purpose, scope, state, and fingerprints—not plaintext.

At use time, the registered destination-specific adapter acquires the single-use authorization fence, revalidates policy/grant/Task/secret generation, and asks the broker for an operation-bound descriptor handoff. Plaintext is available only within the trusted adapter boundary for that invocation and is never returned to the coordinator, agent, generic tool, UI, log, command argument, environment variable, XDG view, Workspace file, or configuration file. Revocation or descriptor replay fails closed.

### Definition of Done

B04 asks the A04 protected broker to create cryptographically random, create-only credential generations for PostgreSQL roles, MinIO identities, and provider/session-related protected values required by accepted configuration. Values are not derivable from instance, Workspace, repository, operator, or configuration inputs. Durable records contain SecretReference identity, backend, generation, purpose, scope, state, and fingerprints—not plaintext.

At use time, the registered destination-specific adapter acquires the single-use authorization fence, revalidates policy/grant/Task/secret generation, and asks the broker for an operation-bound descriptor handoff. Plaintext is available only within the trusted adapter boundary for that invocation and is never returned to the coordinator, agent, generic tool, UI, log, command argument, environment variable, XDG view, Workspace file, or configuration file. Revocation or descriptor replay fails closed.

## B05

B05 performs read-only inspection first, provisions external `initializing`, binds the exact bootstrap candidate, consumes a sealed one-use `VerifiedEmptyTarget`, and executes one Central-owned baseline transaction in one database session. Later migrations use golang-migrate orchestration through Central's same-session driver, forward-only checksums, verified backup/checkpoint evidence, and exact dirty-data-backfill resume without `Force`. Serve never auto-migrates and no down migration is generated.

## B06

B06 serves only `https://127.0.0.1:8080` with TLS 1.3 and the instance certificate, opens the managed `central-browser` profile through the helper, and renders first-run/workspace creation plus restart/session-recovery surfaces. Phase 1 has no login, access token, or per-session authentication; host-user trust and numeric-loopback HTTPS are the authorization boundary. State-changing requests still enforce same-origin, CSRF (double-submit cookie pattern), Origin/Host, `Content-Security-Policy: frame-ancestors 'none'`, `X-Frame-Options: DENY`, security-epoch, and typed input validation. The server never binds a non-loopback address.

## B07

- **B07:** Workspace and Task identity plus canonical Task lifecycle transitions only through the Task domain service. Current state and its Event append commit atomically. Cancellation first persists intent and enters canonical settling behavior; retry creates a new Run while preserving the Task and immutable prior evidence. Cursor pagination uses stable keyset ordering, never unbounded OFFSET.

## B08

- **B08:** Run, Step, immutable StepAttempt/ToolCallAttempt evidence, authorization decisions, execution ownership lease, checkpoints, append-only Events/outbox, quotas, and bounded previews. Provider/tool effects follow prepare → invoke outside transaction → settle. An expired lease proves staleness only; ambiguous outcomes enter reconciliation and are not blindly replayed.

## B09

B09 implements ADR 0004's provider-agnostic `agent/port` and one sequential coordinator. Deterministic release assertions use a generic agent adapter, tool, policy, resolver, clock, and object-store adapters. Formal B09 acceptance remains gated by generic agent adapter delivery and composition, trusted Central-to-agent dispatch, durable invocation outcomes, ToolCall persistence, serving composition, live PostgreSQL evidence, restart/recovery, and Docker-backed recovery evidence.

The only Preview Tool is one ordered, batched, read-only Workspace filesystem operation per Step. It resolves paths beneath the Workspace root with symlink following disabled, rejects post-resolution escape, and enforces path count 10,000 default/50,000 hard, total bytes 100 MB/500 MB, per-file 1 MB/10 MB, turns 20/32, and wall clock 300 s/600 s. No repository write, mutation-capable shell, or general outbound HTTP Tool is in Preview scope. The external agent adapter alone receives bounded destination-specific egress and resolves its SecretReference just in time.

## B10

B10 report materialization receives its source from an external agent adapter and fails closed when that source is absent; see the B09 Agent Adapter Boundary Design (upstream `central` record: `docs/internal/superpowers/specs/2026-08-03-b09-agent-adapter-boundary-design.md`).

B10 durably reserves an Artifact and unique UUIDv4 staging generation, streams the body to an opaque staging key, computes and verifies full-body size plus SHA-256, promotes to an opaque ready key without overwrite, re-verifies the promoted body, and atomically finalizes PostgreSQL metadata, lineage, and the required-Artifact completion contribution. Keys contain only version markers and application-generated opaque IDs; no filename, repository path, Task text, media type, secret, or backend locator appears in a key. The required Markdown report is capped at 1 MB by default and 10 MB hard; exceeding the hard cap fails the StepAttempt. Deletion, retention mutation, and prune are absent until D04.

## B11

The server-rendered UI projects exactly seven operator-visible projections over authoritative Task, Run, attempt, Event, and Artifact evidence. Semantic HTML, deterministic keyboard and focus behavior, visible focus, status/error announcements, and non-color-only contrast-safe status cues are required throughout.

| Projection | Canonical Task status(es) | Visible evidence and actions | Polling |
| --- | --- | --- | --- |
| Empty | no Task | validated Workspace/repository/provider/Task form | 10 s; manual refresh resets interval |
| Queued | `queued` | durable intent and execution bounds; eligible cancel | 10 s, adaptive after identical responses |
| Running | `running` | current immutable attempt, Event/Step timeline, bounded progress; cancel | 2 s, doubles after 5 identical responses, max 30 s |
| Waiting | `waiting` | typed blocker, retry delay/reconciliation evidence, next safe action; only contract-permitted actions | 10 s, adaptive after identical responses |
| Settling | `cancelling` or external boundary settling | cancellation reason and boundary-settling progress; no new work | 2 s, max 30 s |
| Unsuccessful | `failed` or `cancelled` | terminal reason, produced Artifacts/log, retry creates a new Run | 10 s; manual refresh available |
| Completed | `completed` | verified required/produced Artifacts, sanitized Markdown preview/download, immutable history | 10 s; manual refresh available |

Restart reconciliation is an instance-level persistent banner and barrier over affected Tasks, never a Task state. Delete and prune do not render. Markdown passes through a sanitizing processor that strips raw HTML, `javascript:`/`data:` URLs, and script-capable attributes. Polling updates use semantic focus management and `aria-live="polite"`. Browser acceptance covers Firefox ≥115 and Chromium ≥115, while Safari ≥16 remains a compatibility target.

## B12

B12 proves restart-safe end-to-end Preview acceptance: browser submission → durable Task/Run/attempt/Event evidence → bounded repository reads → one required Markdown report plus produced execution log → stage/verify/promote/finalize → atomic completion/Event → restart reconciliation → authoritative UI. B12 injects agent-adapter invocation ambiguity, Tool, PostgreSQL, MinIO, cancellation-race, checksum/size, symlink-escape, secret-leak, and Markdown-XSS failures and verifies each produces durable structured evidence and correct terminal or reconciliation behavior. Acceptance uses the same authority chain as the production flow; no test-only authority bypass is permitted.

B12 documents an unscheduled operator-invoked Preview backup bridge using `pg_dump` for PostgreSQL state and `mc mirror` for MinIO Artifact bodies. The bridge is not a Central-managed backup/restore capability, does not claim verified restore/quarantine/resume, and does not satisfy C06 recovery acceptance.

## Slice B acceptance

Slice B is complete when:

1. B01–B12 contracts are verified with passing tests
2. Advisory consumer gates admission and rejects unsafe hosts (B01)
3. Compose services start in order, report healthy (B02, B03)
4. Secrets are SecretReference-indirected and broker-custodied (B04)
5. Version-zero migration provisions baseline schema with crash-safe resume (B05)
6. HTTP server renders bootstrap session with security headers (B06)
7. Task domain persists with ordered events and keyset-paginated listing (B07)
8. Agent executes a task with tool calls, bounds enforced (B08, B09)
9. Verified artifacts are stored with correct metadata, lineage, and checksums (B10)
10. All seven UI projections render correctly with accessibility requirements (B11)
11. End-to-end acceptance: browser submission → durable state → verified artifacts → restart → authoritative UI (B12)

Slice B must not claim Slice C capabilities or produce backup/restore, destructive, or maintenance operations. ADR 0011 creates one narrow exception: B05 may perform exact failed-version-zero `migrate reset` only with fresh PAM, helper-owned TTY confirmation, full lock revalidation, and an operation-bound journal; it is not a general wipe, repair, or maintenance operation.
