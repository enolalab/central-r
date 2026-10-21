# Phase 1 Local Security Threat Model

## Authority and status

This document is the canonical Phase 1 local threat register defined by the [approved Gate 2 security design](../internal/superpowers/specs/2026-07-13-phase-0-security-baseline-secret-reference-design.md). It becomes an adopted architecture contract only after ADR 0003 is Accepted and Gate 2 validation passes. Phase 0 defines these controls but does not claim they are implemented.

**Status for public readers.** This register records both enforced controls and accepted *design intent*. Entries marked "effective only when ADR 0009 is Accepted" describe the Gate 8 trust-elevation design — they are documentary commitments, **not** runtime-enforced guarantees today. The Actors table below is the attacker model; "Explicit exclusions" are the non-goals. The full controls inventory lives in [capability-policy.md](capability-policy.md); vulnerability reporting and current limitations are in SECURITY.md (upstream `central` record: `SECURITY.md`).

**Coverage notes.** Two surfaces are secured by implementation rather than register entries and are named here for completeness: install-script integrity (`packaging/install/install.sh` — the script refuses modified re-runs and is truncation-safe; release signing ships in a later phase, see the open-source epic), and HTML output-encoding, which rests on `html/template` contextual auto-escaping in `internal/transport/http/gintransport/rendering/renderer.go`. Prompt-injection via artifacts is mitigated by the untrusted-data class plus artifact sanitization and approval gates (T01, T11) — residual risk is real and documented, not eliminated.

## Scope and assumptions

Phase 1 runs one local Central instance for one trusted operating-system account. Its HTTP surface is loopback-only. Central may send explicitly selected context to a hosted model provider, but local read authority never implies provider egress.

The trusted computing base is:

- the local operator using the trusted OS account;
- Central policy and domain services;
- registered, least-privileged system adapters;
- protected deployment configuration that binds opaque SecretReference IDs to a resolver backend.

The following remain untrusted data and have no authority:

- Task and prompt text;
- repository, document, file, database, and Artifact content;
- model, tool, network, and external-service output;
- filenames, URLs, command text, and display metadata supplied by a user or agent.

Compromise of the trusted OS account, root, a database administrator, the Central binary, or a configured external provider is outside Phase 1's defensive claim. Policy gating is not by itself a process sandbox.

### Gate 8 trust elevation (ADR 0009)

All Gate 8 concrete topology additions in this document are documentary until and unless ADR 0009 is Accepted. They map the accepted Gate 2 authority model onto locked host identities, a root-owned infrastructure helper, a root-owned protected-broker, a distinct sandbox-launcher, a managed browser profile with ext4 project quota, broker-HMAC authority-transition journaling, XDG broker-signed safe views, and container-writable-path contracts. While ADR 0009 remains Proposed, these entries describe the security intent of the approved Gate 8 design without claiming runtime enforcement or superseding any Accepted ADR's runtime semantics. Each entry is marked **"effective only when ADR 0009 is Accepted."**

## Assets

| Asset | Required property |
| --- | --- |
| Workspace repositories, files, documents, and data | Confidentiality, integrity, and Workspace isolation |
| Task, Run, Step, ToolCall, Approval, Checkpoint, and Event state | Durable integrity, attribution, and safe recovery |
| Artifact bodies and metadata | Integrity, lineage, confidentiality, and safe presentation |
| Policy, grants, Approval evidence, and security audit | Integrity, freshness, exact binding, and traceability |
| Provider credentials and other secrets | Non-disclosure, purpose limitation, rotation, and revocation |
| Model prompts and selected context | Explicit egress, minimization, and provider binding |
| PostgreSQL, MinIO, and the local host | Least privilege, availability, and separation from agent authority |

## Actors

| Actor or source | Trust | Permitted authority |
| --- | --- | --- |
| Authenticated local operator | Trusted actor | Submit intent, decide Approval, revoke grants, and use configured maintainer actions |
| Central policy and domain services | Trusted computing base | Validate and persist authority; never derive it from content |
| Registered system adapter | Trusted least-privileged component | Perform only its registered purpose with exact Central authorization context |
| Model or agent | Untrusted decision aid | Propose actions only |
| Task, repository, document, tool output, network response, or Artifact | Untrusted data | None |
| Hosted provider or external service | External trust domain | Receive only explicitly authorized data and return untrusted data |
| Other local process, web origin, or LAN client | Potential attacker | None |

## Trust boundaries

1. Local browser to loopback HTTP transport and authenticated session.
2. Untrusted Task, model, repository, document, and tool content to the policy kernel.
3. Workspace root to paths outside that Workspace and to another Workspace.
4. Runtime intent to filesystem, process, network, database, model, and secret-aware adapters.
5. Approval UI decision to the canonical authorization request it permits.
6. SecretReference resolver and protected binding to one authorized adapter operation.
7. Runtime to hosted model provider and every other external destination.
8. Agent-requested traffic to system-owned PostgreSQL, MinIO, provider, and control connections.
9. PostgreSQL durable metadata to S3-compatible Artifact bodies.
10. Untrusted Artifact body to browser download or preview.
11. Protected external restore/security epoch barrier to the PostgreSQL and object-store state being restored.
12. Operator UID, same-UID processes, and Docker socket to the root-owned infrastructure helper boundary — effective only when ADR 0009 is Accepted.
13. `central-runtime` descriptor-only sandbox to the root-owned broker, helper, sandbox-launcher, and protected-state boundaries — effective only when ADR 0009 is Accepted.
14. Managed browser profile to loopback HTTPS origin, broker-owned TLS leaf, and root-managed trust store — effective only when ADR 0009 is Accepted.
15. Authoritative state and protected broker journal to XDG broker-signed operator views — effective only when ADR 0009 is Accepted.

## Threat register

| ID | Threat | Required control | Residual risk and blocking owner |
| --- | --- | --- | --- |
| T01 | Prompt injection requests a tool, data disclosure, or policy change | Untrusted content has no authority; canonical policy evaluation and durable Approval precede invocation | An operator can approve a malicious but accurately disclosed action; approval UI owner before Gate 3 UI design |
| T02 | Path traversal, symlink replacement, or cross-Workspace reference escapes isolation | Canonical Workspace roots, Workspace-scoped IDs, symlink-safe resolution, protected paths, and use-time adapter revalidation | OS races remain without descriptor-relative or equivalent operations; filesystem adapter owner before implementation |
| T03 | Approved input, destination, capability, or scope is substituted or replayed | Approval binds normalized input hash, operation key, scope, policy version, and security context | Canonicalization bugs can create semantic gaps; Gate 3 policy-contract owner before adapter implementation |
| T04 | Secret leaks through prompt, Event, log, checkpoint, key, Artifact metadata, command, or generic process | Opaque references, just-in-time secret-aware resolution, no raw reveal, source redaction, and sentinel tests | An authorized external service can mishandle a credential; secret-aware adapter owner before implementation |
| T05 | Local data is silently sent to a hosted model | Separate `model_context × send` authority with provider, resource scope, sensitivity, and disclosure | The selected provider controls authorized data after receipt; local operator owns provider and scope choice |
| T06 | Network and secret capabilities compose into exfiltration | Independent capabilities, strictest composition, destination and purpose binding, redirect reevaluation, and agent-network default deny | Destination ownership can change; network adapter owner must resolve DNS pinning before implementation |
| T07 | Agent reaches PostgreSQL, MinIO, loopback, private services, or metadata endpoints | Separate system authority plane; agent destinations resolving to loopback, private, link-local, multicast, unspecified, or metadata ranges fail closed | Registered local adapters remain trusted; infrastructure owner must use least-privileged service identities |
| T08 | Database action mutates or destroys sensitive data | Read, mutate, and admin classification; parameterization; per-action mutation approval; protected production override | Ambiguous query classification must deny; database adapter owner before implementation |
| T09 | Crash or timeout repeats a privileged external effect | Persist decision and prepared attempt before invocation; stable in-Run operation key; ambiguous result enters reconciliation | External systems without idempotency or outcome lookup can require operator resolution; Gate 3 reconciliation owner |
| T10 | Another origin or local process submits, frames, or induces approval of work | Loopback bind, browser-reachable bootstrap exchange, bounded session, CSRF and Host/Origin validation, CSP `frame-ancestors 'none'`, `X-Frame-Options: DENY`, and configured-engine anti-framing tests on all HTML outcomes | Malware under the trusted OS account is out of scope; local UI/API owner before implementation |
| T11 | Malicious Artifact executes active content or spoofs type | Treat Artifact as untrusted, sanitize metadata, disable MIME sniffing, safe download by default, and sanitize allowlisted previews | Sanitizer defects remain; Artifact and UI owners before preview implementation |
| T12 | Tool, provider, output, or Artifact exhausts CPU, memory, disk, network, or spend | Per-adapter timeouts, size and output limits, concurrency, budget, and bounded retry | Exact limits depend on Gate 3 runtime design; runtime owner before execution implementation |
| T13 | Audit or telemetry becomes a secondary secret store | Minimal structured records, source redaction, safe keyed fingerprints, bounded labels, and no unrestricted payloads | A database administrator can alter evidence and is out of scope; stronger tamper evidence requires a later ADR |
| T14 | Grant remains usable after expiry, revocation, policy tightening, Task completion/cancellation, or while Task is failed | Reevaluate immediately before use; separate historical Approval from effective grant; fail closed on stale policy | Adapter check/use races must be closed by Gate 3 authorization protocol design |
| T15 | Restoring historical state resurrects sessions, bootstrap credentials, grants, SecretReferences, claims, leases, or fencing authority | External target-bound restore/security epochs; non-ready restore barrier; mandatory authority reset; fresh bootstrap/login; exact epoch checks on every authority predicate | Protected operator-state integrity and concrete topology are owned by Gate 8; executable restore/rollback security tests block Phase 1 exit |
| T16 | Crash during first provisioning leaves PostgreSQL, external epoch state, or bootstrap authority independently ready or permanently orphaned | External `initializing` precedes database mutation; exact operation/target/baseline/candidate binding; atomic baseline registration; exact candidate activation; idempotent resume; readiness only after epoch-zero match; no baseline auto-adoption | Protected operator-state/bootstrap realization is owned by Gate 8; failure injection at every cross-store boundary blocks the first migration slice |
| T17 | Same-UID repository process compromises protected state, Docker, broker, or runtime | Operator UID is not a Docker group member and has no Docker-socket ACL; authoritative state lives below root-owned parents outside XDG/repository/Workspace; broker, helper, sandbox-launcher, and protected roots are not searchable by the operator UID; every privileged operation crosses explicit PAM plus helper/broker confirmation — effective only when ADR 0009 is Accepted | A compromised same-UID process that gains operator credentials can still approve or reject pending Approvals through the authenticated browser session; post-restore authority reset requires fresh bootstrap and operator decision — operator session owner before Gate 9 UI/policy implementation |
| T18 | Root-owned helper binary or Docker daemon is replaced or its embedded authority is subverted | Helper is an immutable root-owned copy at a fixed absolute path; embedded authority digest is verified before every mutation; Docker daemon is a host prerequisite verified by `doctor`; helper refuses to operate with mismatched Docker/Compose identity; every helper operation independently recomputes embedded authority from held descriptors — effective only when ADR 0009 is Accepted | Root compromise, kernel compromise, or a compromised Docker daemon after the helper's start-acknowledgement check is outside Phase 1's defensive claim; helper release integrity depends on the administrator's root trust transition — release-security owner |
| T19 | TTY forgery — a caller-created PTY, remote/SSH session, or process replay mimics the operator physical-seat confirmation | Helper requires active local logind/Wayland session and physical-seat TTY ancestry; takes exclusive terminal lease with `vhangup`/reopen to invalidate prior same-UID terminal descriptors; applies `TIOCEXCL` and temporarily makes device root-only; reads the fixed confirmation phrase on the helper-owned TTY; controller stdin, flags, environment, redirected input, and replay are rejected — effective only when ADR 0009 is Accepted | A kernel-level TTY or logind compromise is outside Phase 1 scope; a malicious compositor on the same physical seat remains a residual risk — PAM/session owner before Gate 9 Slice A |
| T20 | ptrace, `/proc/<pid>/mem`, `/proc/<pid>/fd`, or inherited-descriptor replay intercepts runtime, broker, or sandbox-launcher memory or descriptors | Runtime is launched with `PR_SET_DUMPABLE=0` and no supplementary groups; agent is launched in a private PID/mount namespace non-dumpable; broker authenticates runtime by kernel credentials, launch/stage receipt, executable identity, boot ID, pidfd, and nonce; shutdown revokes sessions before settlement; bridge descriptors are closed/sealed per command and unknown extras abort — effective only when ADR 0009 is Accepted | A compromised runtime that has already received an authorized secret in bounded adapter memory may leak that secret; Central does not claim protection after authorized plaintext enters the runtime — Gate 9 sandbox-launcher security-test owner |
| T21 | Browser profile is tampered to install extensions, weaken trust stores, redirect navigation, or a counterfeit loopback origin intercepts the bootstrap token | Browser profile lives at `/var/lib/central-browser/v1/<instance-id>/` beneath a root-owned `0700` parent invisible to operator/runtime/agent UIDs; extensions, developer tools/protocol, password storage, sync, external URL handlers, service workers, background mode, and non-loopback navigation are disabled; instance-bound TLS with SAN IP `127.0.0.1` only; CA public certificate is installed in system and browser NSS trust stores by the helper; download directory and arbitrary profile are forbidden — effective only when ADR 0009 is Accepted | Browser vulnerabilities, Wayland compositor compromise, or kernel-level memory access can still extract session tokens; the browser is cgroup/scope-capped but not a custom sandbox — browser/Wayland trust owner before Gate 9 Slice B |
| T22 | XDG rollback — an attacker replaces broker-signed XDG views with older versions to mask protected-state changes or trick operator into believing stale state | XDG contains only broker-signed non-authoritative views; every mutating helper resolves the signed binding to authoritative config and requires byte equality before use; changed/deleted/forged view or signature is `CONFIG_INVALID`; no command adopts view bytes as authority; snapshot readers verify the Ed25519 signature with the root-installed public key and report age — effective only when ADR 0009 is Accepted | A view generated during a genuine stale period is indistinguishable by signature alone; staleness age is reported prominently — XDG view-signing owner before Gate 9 observability integration |
| T23 | State, audit, or backup forgery — a same-UID process modifies authoritative state trees, receipts, audit records, or backup seal evidence through filesystem access | Authoritative state lives below root-owned parent `0700` with instance directories owned by locked `central-runtime`; operator and `central-agent` cannot traverse the root parent; every authoritative transition is an immutable sequence-specific payload plus `central.authority-transition/v1` HMAC envelope in `authority-records/`; materialized projections are never authority; backup seal requires the live accepted backup operation, target-exclusive lock proof, current payload epoch, completed checkpoints, exact repository descriptor, and broker HMAC — effective only when ADR 0009 is Accepted | A compromised `central-runtime` process after authorization can write valid transitions within its permitted stream; the broker-HMAC contract limits reach but does not eliminate post-authorization risk — Gate 9 authority-journal attack-test owner |
| T24 | Cold-copy scratch exposure — rescue backup cold-copy scratch roots leak confidential state or are reused without authorization | `/var/lib/central-rescue/v1` parents are root-owned `0700` outside XDG, Workspace, export, authoritative payload, backup, and protected roots; each operation root is create-only, descriptor/binding/operation/mount/handle/capacity/audit-bound, and non-searchable by operator/runtime/agent/browser UIDs; rescue backup creates exactly one marked current-epoch seal from operation-owned cold copies using conservative admission; rescue backup never mounts authoritative payload roots writable — effective only when ADR 0009 is Accepted | A compromised helper or Docker daemon during rescue can expose scratch data; scratch is on a host-local filesystem, not network storage — rescue-backup owner before Gate 9 Slice D |
| T25 | Advisory outage, rollback, or emergency deny — the signed security-advisory bundle expires, is missing, rolled back, or blocks operations; an attacker exploits the stale period to admit known-vulnerable dependencies | Release-signed Ed25519 `central.security-advisory/v1` bundle with at-most-seven-day expiry; current/stale-admitted (30-day grace)/hard-expired/deny behavior; missing bundle or CVSS ≥ 7.0/CISA KEV/emergency-deny blocks admission; immutable `central.security-admission/v1` receipt binds exact installed identities; emergency bundle update requires dependencies stopped; no renewable risk-acceptance override or clock rollback — effective only when ADR 0009 is Accepted | Stale-admitted installation may serve known-vulnerable pinned digests for up to 30 days; the release-security owner, not Gate 9 runtime code, owns the advisory compiler, offline signing ceremony, and emergency response — release-security owner |
| T26 | Build provenance — build reproducibility is compromised; the two-clean-builder contract fails to produce bit-identical outputs, or a single-builder result is accepted | Hermetic MinIO build contract with exact BuildKit release, built-in frontend only, `network=none` after base import, two independently created builder state roots with no shared cache; byte-identical OCI layouts required; separate SPDX SBOM, license report, and SLSA provenance generated after OCI result; signed advisory must admit every locked input and output identity — effective only when ADR 0009 is Accepted | Deterministic-build toolchain bugs, Go-linker non-determinism, or upstream archive mutation between fetches can cause false mismatch; the two isolated content stores eliminate ambient state but not build-toolchain defects — build-provenance owner before Gate 9 Slice B `prepare` |
| T27 | Mount replacement — a filesystem mount is replaced beneath a held descriptor, redirecting reads or writes to an attacker-controlled location | Every root descriptor is opened with `openat2(RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS)`; held `O_PATH` descriptors record `statx` device, inode, mode, owner, link count, and `STATX_MNT_ID`; descendant access uses `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV)`; helper parses `/proc/self/mountinfo`, rejects nested mounts, compares mount IDs plus `name_to_handle_at` filesystem handles, and reopens/revalidates at every mutation boundary; Docker bind uses `/proc/<helper-pid>/fd/<fixed-fd>` transient source — effective only when ADR 0009 is Accepted | A kernel bug that returns consistent but falsified `STATX_MNT_ID`, mount ID, or filesystem-handle evidence across every check boundary can defeat revalidation; the Gate 9 attack-test harness must exercise mount-under and bind-substitution scenarios — mount-validation owner before Gate 9 Slice A |
| T28 | Capacity exhaustion — disk, memory, inode, journal, or project-quota capacity is exhausted, causing protected-state corruption, incomplete transition commits, or denial of service | Fixed 4-GiB survival reserve and 1-GiB free floor per writable device; 8-MiB maximum write quantum between checks; broker authority-store hard ceilings (2 GiB total, 64 MiB settlement reserve, 512 MiB uncheckpointed) with `MAINTENANCE_REQUIRED` at 75% and `CLEANUP_REQUIRED` on reserve exhaustion; browser ext4 project hard quota of 1 GiB/50,000 inodes; 8-GiB reference-host aggregate memory envelope with mutually exclusive profiles and 512 MiB headroom; all tmpfs caps are exact — effective only when ADR 0009 is Accepted | A sustained operations backlog can fill the settlement reserve before maintenance completes, requiring operator intervention; kernel-level filesystem corruption or underlying device failure is outside scope — capacity-accounting owner before Gate 9 Slice C |

## Control principles

- Authority originates only from installed policy, explicit local-user intent, and durable unexpired grants.
- Policy returns only `allow`, `require_approval`, or `deny`; unknown security state fails closed.
- The strictest result controls an action that composes capabilities.
- Workspace isolation, raw-secret prohibition, and unsafe-canonicalization denies cannot be profile-overridden.
- Policy decision and prepared ToolCallAttempt are persisted before adapter invocation.
- External effects never occur inside an open PostgreSQL transaction.
- Ambiguous effect enters durable `reconciliation` and is never retried blindly.
- Model context egress is independent from Workspace read authority.
- System-owned connections never become agent authority.
- Security evidence is append-only at the application layer and excludes plaintext secrets and unrestricted content.
- The operator UID has no Docker-socket ACL, no Docker group membership, and no direct access to protected values, broker socket, or authoritative state — effective only when ADR 0009 is Accepted.
- Every infrastructure mutation requires fresh PAM authentication through the root-owned helper, which independently revalidates embedded authority, held descriptors, and mount/binding/provenance evidence before accepting the operation — effective only when ADR 0009 is Accepted.
- Destructive operations (wipe, restore apply, hard-expired rescue backup, backup/export deletion or pruning, trust removal, and dependency-upgrade apply/resume) additionally require the helper to open `/dev/tty` itself, display independently recomputed safe operation/target/plan IDs, read the fixed confirmation phrase with echo disabled, and bind a one-use confirmation digest — effective only when ADR 0009 is Accepted.
- Authoritative state and protected broker state live below separate root-owned parents outside XDG, repository, and every Workspace root; operator and agent UIDs cannot traverse or enumerate these roots — effective only when ADR 0009 is Accepted.
- Runtime receives only descriptor-only boundaries with no repository, Workspace, Docker socket, helper socket, or root traversal; agent receives only delegated Workspace descriptors in a private PID/mount namespace with `PR_SET_DUMPABLE=0` — effective only when ADR 0009 is Accepted.
- The managed browser profile is root-owned, invisible to operator/runtime/agent, cgroup-scoped, ext4 project-quota-capped, and launched only by the helper in the active local Wayland session with no extension/devtool/sync/download authority — effective only when ADR 0009 is Accepted.
- Every authoritative transition is an immutable sequence-specific payload plus chained broker-HMAC envelope; materialized projections are replaceable convenience views and are never authority — effective only when ADR 0009 is Accepted.
- Build reproducibility requires two independently created, cache-isolated BuildKit state roots producing byte-identical OCI layouts; a single-builder result is never accepted — effective only when ADR 0009 is Accepted.
- Signed seven-day advisory authority with current/stale-admitted/hard-expired/deny behavior; a missing bundle, expired bundle beyond stale grace, or any denied identity blocks admission and, after hard expiry, blocks serve and all mutations — effective only when ADR 0009 is Accepted.

## Explicit exclusions

- Workflow graphs, parallel subagents, distributed workers, and multi-worker scheduling;
- plugin marketplace, third-party extension trust, and a general plugin sandbox;
- Central Server, Online Mode, LAN access, remote control, and node identity;
- multi-user authentication, RBAC, SSO, tenant isolation, and enterprise policy administration;
- cryptographic audit integrity against a database administrator;
- runtime enforcement during Phase 0.

## Required validation scenarios

| Scenario | Expected security result |
| --- | --- |
| Repository text instructs the model to upload files | Content grants no authority; egress or network is denied or waits for exact approval |
| An allowed local file is added to hosted-provider context | Separate model egress decision discloses provider, resource scope, and sensitivity |
| Approved write target becomes a symlink | Adapter revalidation denies escape without an outside-Workspace write |
| Approval is replayed with another destination or input | Canonical binding mismatch denies and requires a new Approval |
| Public URL redirects or resolves to a private address | Destination change is reevaluated and private access is denied |
| Agent asks shell to print a provider credential | Generic process cannot resolve SecretReference and raw reveal is denied |
| Secret rotates during a Task | Stable reference resolves current version after revalidation and audit records a safe fingerprint |
| Secret is revoked before next use | Use-time check fails closed with operator repair or structured failure |
| Production database update appears in a profile | Profile cannot bundle it; exact operation requires per-action approval |
| Provider call times out after uncertain delivery | Operation enters reconciliation rather than blind retry |
| Malicious HTML Artifact is opened | Safe download or sanitized allowlisted preview prevents direct active execution |
| A hostile loopback origin frames an authenticated Approval or maintainer page | Every HTML success, redirect, and error denies framing through CSP and `X-Frame-Options`; no privileged UI can be embedded |
| Provisioning crashes before or after external state, bootstrap candidate, PostgreSQL baseline commit, candidate activation, or ready promotion | Only the exact `initializing` operation resumes; partial/mismatched state remains non-ready; no independent store or orphan candidate grants authority |
| A backup containing formerly valid sessions, bootstrap credentials, grants, SecretReferences, claims, leases, and fencing tokens is restored | External barrier remains non-ready; restored authority fails the new security epoch; reset revokes or suspends it; only a fresh bootstrap/login and new operator decisions can become effective before readiness |
| A same-UID process without Docker group membership attempts to open the Docker socket, broker socket, or traverse the authoritative-state root | `EACCES`/`EPERM` on socket; `openat2` returns `EXDEV` or `ENOENT` for root traversal; helper-auth `sudoers` policy with `env_reset` and no shell/arbitrary arguments denies escalation — effective only when ADR 0009 is Accepted |
| A caller-created PTY or redirected stdin attempts to satisfy the wipe confirmation phrase | Helper requires physical-seat TTY ancestry with `logind` session verification, opens `/dev/tty` itself after `vhangup`/`TIOCEXCL`, and rejects caller PTY, environment, and stdin as `AUTHORITY_DENIED` — effective only when ADR 0009 is Accepted |
| A same-UID process ptrace-attaches the runtime or reads `/proc/<runtime-pid>/mem` while a secret-aware adapter is active | Runtime `PR_SET_DUMPABLE=0` prevents ptrace; broker-socket authentication requires kernel credentials, pidfd, and nonce; agent uses private PID namespace — effective only when ADR 0009 is Accepted |
| A counterfeit `https://127.0.0.1:8080` origin with a self-signed certificate attempts to intercept the bootstrap token | Browser profile uses root-managed NSS trust store with only the helper-installed instance CA; TLS leaf has SAN IP `127.0.0.1` only; browser extensions and developer tools are disabled; counterfeit origin produces certificate-verification failure — effective only when ADR 0009 is Accepted |
| An older broker-signed XDG view is substituted for the current view to hide a SecretReference revocation | View signature includes generation and creation time; snapshot reader reports age and `signature_state`; mutating command independently resolves authoritative config binding and requires byte equality — effective only when ADR 0009 is Accepted |
| A same-UID process rewrites a materialized projection or receipt under the authoritative state tree | Projections are convenience views; every authoritative transition is an immutable sequence-specific payload plus HMAC envelope under `authority-records/`; readers verify projection against committed journal head; mismatch makes projection stale and is never adopted as authority — effective only when ADR 0009 is Accepted |
| Rescue backup cold-copy scratch is mounted or read by an unauthorized process | Rescue root parents are root-owned `0700`, non-searchable by operator/runtime/agent/browser UIDs, and reachable only by the helper through held descriptors; rescue operation never mounts authoritative payload roots writable — effective only when ADR 0009 is Accepted |
| The security-advisory bundle expires and a CISA KEV-listed vulnerability is published for the pinned PostgreSQL 16.14 image | At expiry + 30 days, `SECURITY_AUTHORITY_HARD_EXPIRED` blocks `serve` and all mutations; `local security update` can admit a new signed bundle; rescue backup and status/explain/export remain — effective only when ADR 0009 is Accepted |
| A single-builder MinIO build produces an OCI layout; a second empty-state builder is skipped | Two independently created BuildKit state roots with distinct sockets and no shared cache are required; acceptance requires byte-identical OCI layouts; one builder or `buildctl build` without the second independent run is `INCOMPATIBLE` — effective only when ADR 0009 is Accepted |
| A bind mount is substituted beneath the held PostgreSQL data directory descriptor before container start | Helper resecures `O_PATH` descriptors with `name_to_handle_at` handles and `STATX_MNT_ID` comparison at pre-Docker validation, container-side initializer acknowledgement, and post-start inspection; mount-ID or handle mismatch is `DRIFTED` — effective only when ADR 0009 is Accepted |
| Broker journal approaches the 2 GiB hard ceiling during a sustained backup/create/export workload | At 75% of the uncheckpointed limit (384 MiB) or total ceiling (1.5 GiB), new non-settlement mutations return `MAINTENANCE_REQUIRED`; checkpoint reclaims only checkpoint-covered old directories; settlement reserve (64 MiB) preserves current transition completion; exhaustion is `CLEANUP_REQUIRED` — effective only when ADR 0009 is Accepted |

## Follow-up ownership

| Decision | Owner | Due | Blocks |
| --- | --- | --- | --- |
| Filesystem descriptor-relative or equivalent enforcement | Filesystem adapter specification owner | 2026-07-20 | Filesystem adapter implementation plan |
| DNS pinning and canonical destination algorithm | Network adapter specification owner | 2026-07-20 | Network adapter implementation plan |
| Adapter time, size, concurrency, and spend defaults | Gate 3 runtime specification owner | 2026-07-20 | Execution-loop implementation plan |
| Artifact preview allowlist and sanitizers | Artifact and UI specification owners | 2026-07-20 | Artifact preview implementation plan |
| Same-UID process and locked-identity attack validation | Gate 9 sandbox-launcher and broker security-test owners | 2026-07-20 (documentary; effective only when ADR 0009 is Accepted) | Gate 9 Slice A host-authority foundation |
| Helper TTY confirmation, PAM ceremony, and `vhangup`/`TIOCEXCL` enforcement | Helper security-test owner | 2026-07-20 (documentary; effective only when ADR 0009 is Accepted) | Gate 9 Slice A host-authority foundation |
| Managed browser profile, ext4 project quota, Wayland launch, and trust-store integration | Browser security-test owner | 2026-07-20 (documentary; effective only when ADR 0009 is Accepted) | Gate 9 Slice B first safe runnable environment |
| XDG broker-signed view, snapshot staleness, and view-rollback validation | XDG view-signing and observability owners | 2026-07-20 (documentary; effective only when ADR 0009 is Accepted) | Gate 9 observability integration |
| Authority-transition journal, HMAC chaining, checkpoint compaction, and projection verification | Broker authority-journal owner | 2026-07-20 (documentary; effective only when ADR 0009 is Accepted) | Gate 9 Slice A host-authority foundation |
| Rescue backup cold-copy scratch isolation and settlement-only cleanup | Rescue-backup owner | 2026-07-20 (documentary; effective only when ADR 0009 is Accepted) | Gate 9 Slice D destructive and portable operations |
| Advisory bundle compiler, offline signing ceremony, key custody, emergency response, and publication | Release-security owner | 2026-07-20 (documentary; effective only when ADR 0009 is Accepted) | Gate 9 Slice E dependency maintenance |
| Hermetic two-clean-builder reproducibility, offline module mirror, and SLSA provenance | Build-provenance owner | 2026-07-20 (documentary; effective only when ADR 0009 is Accepted) | Gate 9 Slice B `prepare` |
| Mount-validation `name_to_handle_at`, `STATX_MNT_ID`, and descriptor-relative revalidation | Mount-validation security-test owner | 2026-07-20 (documentary; effective only when ADR 0009 is Accepted) | Gate 9 Slice A host-authority foundation |
| Capacity accounting, survival reserve, broker journal ceilings, and project-quota hard limits | Capacity-accounting owner | 2026-07-20 (documentary; effective only when ADR 0009 is Accepted) | Gate 9 Slice C required recovery |
