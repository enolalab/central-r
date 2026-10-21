# Phase 1 Capability and Approval Policy

## Authority and status

This document is the canonical Phase 1 local authority contract defined by the [approved Gate 2 security design](../internal/superpowers/specs/2026-07-13-phase-0-security-baseline-secret-reference-design.md) and constrained by the [Phase 1 threat model](threat-model.md). It becomes adopted architecture only after ADR 0003 is Accepted and Gate 2 validation passes. Phase 0 does not claim runtime enforcement.

The Gate 8 sections documenting helper, broker, sandbox-launcher, browser, and infrastructure operations as system-owned authority planes are documentary until and unless ADR 0009 is Accepted. They describe the security intent of the approved Gate 8 design — system-owned authority that is not agent-requestable, not Approval-based, not generic process execution, and not ambient privilege — without claiming runtime enforcement or superseding ADR 0003's capability-model authority while ADR 0009 remains Proposed. Each Gate 8 subsection is marked **"effective only when ADR 0009 is Accepted."**

## Authority principle

Agent, model, Task, repository, document, tool, network, and Artifact content can propose an action but cannot authorize it. Authority originates only from installed policy, explicit authenticated local-user intent, and durable unexpired grants.

Every privileged request has the canonical form:

`resource × effect × scope`

Policy returns exactly one outcome:

- `allow` — current policy and effective grants authorize the exact request;
- `require_approval` — a local user can authorize the exact request through durable Approval;
- `deny` — a hard rule, invalid request, missing authority, or prohibited combination forbids invocation.

For composed actions, `deny` is stricter than `require_approval`, which is stricter than `allow`. The strictest component controls the operation.

## Canonical authorization request

| Field | Required meaning |
| --- | --- |
| Workspace ID | Ownership and isolation boundary |
| Task and current Run IDs | Stable intent and current execution context |
| Step, ToolCall, and operation key | Exact logical action and idempotency boundary when applicable |
| Actor and requester type | User, runtime, policy service, or registered adapter |
| Resource | Protected resource class |
| Effect | Requested observation, mutation, execution, connection, send, or use |
| Scope | Canonical resource selector and requested grant lifetime |
| Sensitivity | `local`, `dev`, `staging`, or `prod` |
| Adapter | Registered component permitted to carry out the operation |
| Destination and purpose | Exact external target and declared reason when applicable |
| Normalized input hash | Immutable semantic request identity |
| SecretReference IDs | Opaque reference identities when applicable; never values |
| Policy version | Policy state used to evaluate the request |

Missing fields, unknown resource or effect, unsafe canonicalization, stale policy, scope mismatch, or unknown sensitivity fail closed. Unknown sensitivity receives the strictest applicable rule.

## Capability classes

| Resource | Effects | Canonical scope dimensions |
| --- | --- | --- |
| `filesystem` | `read`, `create`, `modify`, `delete`, `set_executable` | Workspace root, canonical path or path set, recursion, protected-path class |
| `process` | `execute` | Executable identity, working directory, argument envelope, environment policy, time and output bounds |
| `network` | `connect`, `listen` | Protocol, canonical host, resolved-address class, port, purpose, redirect policy, response bounds |
| `database` | `read`, `mutate`, `admin` | Connection identity, database, schema, relation, operation class, sensitivity |
| `model_context` | `send` | Provider, model class when material, Workspace resource scope, sensitivity, purpose |
| `secret` | `use` | SecretReference ID, adapter, destination, purpose |

Effects never imply one another:

- `filesystem.read` does not imply `model_context.send`;
- `process.execute` does not imply filesystem, network, database, model, or secret authority;
- `network.connect` does not imply `secret.use`;
- `secret.use` does not imply raw reveal, arbitrary destination use, or data egress;
- `database.read` does not imply mutation or administration.

`network.listen` is denied for agent-requested operations in Phase 1. Registered loopback service startup is a system-owned operation.

## Evaluation order

1. Validate Workspace ownership and request shape.
2. Canonicalize resource selectors, destination, purpose, sensitivity, and SecretReference IDs.
3. Compute or verify normalized input hash and operation key.
4. Expand any versioned profile into visible atomic capabilities.
5. Evaluate hard denies, installed baseline policy, explicit Task intent, effective grants, and current policy version.
6. Evaluate every composed capability independently and select the strictest result.
7. Persist requested capability and decision before adapter invocation.
8. On `require_approval`, create Approval and the existing durable `approval` wait atomically.
9. Before protected use, recheck expiry, revocation, policy, scope, sensitivity, adapter, destination, and relevant reference status.
10. Give the adapter only the exact authorization context needed for that operation.

An adapter cannot infer missing authority or accept a caller-provided Boolean as proof of authorization.

## Versioned profiles

A profile is a named, versioned UX bundle. It is not an authority source.

- A Task policy snapshot records profile version and expanded atomic capabilities.
- UI displays the complete expansion before submission or approval.
- Profiles contain no wildcard authority.
- Updating a profile never broadens an existing Task silently.
- A changed expansion creates new policy state and requires reevaluation.
- Production mutation and per-action-only effects cannot become Task grants through a profile.
- No `approve_all` capability exists.

## Default policy matrix

| Operation | Default | Maximum reusable scope |
| --- | --- | --- |
| Read inside canonical Workspace roots | Allow from explicit Task-submission grant | Current Task, no more than 24 hours, exact Workspace roots |
| Read outside Workspace or across Workspace | Deny | None |
| Create or modify an ordinary Workspace file | Require approval | Current Task, no more than 24 hours, canonical path scope |
| Delete file, change executable bit, or touch protected path | Require approval | One operation key |
| Execute arbitrary shell or process | Require approval | One operation key |
| Execute bounded process in an enforcing environment | Require approval | Current Task, no more than 24 hours, exact executable, cwd, argument envelope, and auxiliary capabilities |
| Agent-requested network connection | Deny without a specific exception | One operation by default; bounded Task grant only for exact protocol, destination, port, and purpose |
| Agent-requested network listener | Deny | None |
| Database read | Require approval | Current Task, no more than 24 hours, exact connection and resource scope |
| Database mutation | Require approval | One operation key |
| DDL, administration, or destructive database action | Deny unless protected maintainer override permits exact action | One operation key |
| Send selected context to hosted model | Require explicit provider selection and egress disclosure | Current Task, no more than 24 hours, exact provider and resource scope |
| Use selected provider credential | Derived from explicit provider selection | Current Task, no more than 24 hours, exact provider adapter, destination, and purpose |
| Use another SecretReference | Require approval | Current Task, no more than 24 hours, exact reference, adapter, destination, and purpose |
| Reveal plaintext secret | Deny | None |
| Mutate production resource | Require approval | One operation key; never bundle-opened |
| Unknown or unclassifiable operation | Deny | None |

## Approval and effective grant

Approval is the durable historical aggregate defined by the approved domain lifecycle. Its statuses remain:

- `requested`
- `approved`
- `rejected`
- `cancelled`

An approved decision may establish an effective grant. Grant validity is separate from historical Approval state. Expiry, revocation, Task state, scope change, or policy tightening never rewrites an Approval and never adds another Approval status.

A durable effective-grant record must identify:

- the Approval or explicit Task-submission choice that established it;
- subject Workspace and Task;
- atomic capabilities and canonical scopes;
- normalized intent and policy binding;
- issuance, expiry, revocation, and structured reason;
- task-scoped or per-action class;
- policy version last validated.

Every task-scoped grant has `expires_at` no more than 24 hours after issuance.

### Retry, failed Task, and rerun

- A Task grant ends when its Task completes or is cancelled, or earlier on expiry, revocation, scope or intent change, or stricter policy.
- A failed Task cannot exercise a grant.
- If the authenticated local user explicitly retries the same failed Task before its authorization basis expires, Central may establish a newly revalidated effective grant for the new Run when Task intent, subject, scope, and policy remain valid.
- The new Run records a fresh authorization decision linked to the original Approval or explicit Task choice.
- Per-action Approval remains bound to one operation key and does not transfer to a new Run.
- A retry of the same logical ToolCall inside one Run can reuse its operation key only after full revalidation.
- Running a cancelled Task creates a new derived Task and inherits no grant.
- Reconciliation authority can inspect or settle the same ambiguous operation; it cannot authorize another side effect.

## Approval binding and display

Every Approval request binds and displays:

- Workspace, Task, current Run, ToolCall, and operation key where applicable;
- adapter, resource, effect, and canonical scope;
- normalized input hash;
- sensitivity and protected-resource classification;
- destination, protocol, port, redirect rule, and purpose where applicable;
- model provider and egress resource scope where applicable;
- non-sensitive SecretReference label and opaque ID where applicable;
- policy version and requested grant lifetime;
- composed auxiliary capabilities and strictest resulting decision.

A changed input hash, operation key, capability, scope, destination, adapter, SecretReference, purpose, sensitivity, or materially changed policy cannot consume the old per-action authorization.

## Maintainer override

A maintainer override:

- is disabled unless protected local configuration enables its specific class;
- requires an authenticated local maintainer action, exact operation, reason, and short expiry;
- is always per-action and creates dedicated audit evidence;
- cannot enable raw-secret reveal, cross-Workspace access, unsafe canonicalization, silent policy mutation, or a reusable production grant.

## Filesystem rules

- Workspace roots are canonical protected configuration, not user-controlled display paths.
- Every resource carries Workspace identity and is revalidated by the filesystem adapter at use.
- `..`, absolute or device paths, alternate separators, case-folding ambiguity, mount escape, symlink traversal, and replacement races fail closed unless the target-platform mechanism proves containment.
- Cross-Workspace object references fail even for the same local OS user.
- Protected paths, deletion, and executable-bit changes are per-action.
- User filenames never form object-storage keys and are sanitized before display.

## Process rules

- Direct executable invocation is distinct from a shell or interpreter command string.
- Shell interpreters, command strings, dynamic executable lookup, unbounded arguments, or uncontrolled environment are arbitrary and per-action.
- A bounded envelope identifies exact executable, canonical working directory, argument structure, environment policy, timeout, output bound, and every auxiliary capability.
- Generic process receives no secret through argument, environment, stdin, file, or inherited descriptor in Phase 1.
- If the execution environment cannot mediate ambient filesystem or network access, policy evaluates and UI discloses that ambient composite privilege or denies the operation.

## Network rules

- Agent network is denied unless a policy exception identifies protocol, destination, port, purpose, request bounds, and redirect behavior.
- Redirect to another origin, protocol, or port requires a new evaluation.
- Connection-time DNS answers must stay inside the approved destination class.
- Loopback, private, link-local, multicast, unspecified, and infrastructure-metadata destinations are denied to the agent plane.
- Selected model-provider traffic still requires `model_context.send` and `secret.use`; system transport classification never bypasses egress consent.

## Database rules

- Database connections are registered resources with sensitivity and a secret-aware adapter.
- Queries use parameters for data values; credentials and sensitive parameters do not enter generic logs or Events.
- Adapter classifies operations as read, mutate, or admin before invocation and denies unknown classification.
- Read needs a bounded Task grant; mutation needs per-action Approval.
- DDL, privilege changes, bulk destructive statements, and production administration need explicitly configured per-action maintainer override.
- Permissions are never weakened to make a test or Task pass.

## Model-context egress

- Hosted-provider choice is explicit authenticated user intent.
- Egress request declares provider, Workspace resource scope, sensitivity, and purpose.
- Local read never silently adds data to provider context.
- Context construction excludes plaintext secrets by design; scanning is defense in depth.
- Provider response is untrusted and cannot broaden capability.
- Provider, destination, resource scope, or material sensitivity change requires reevaluation.

## Local UI authentication

This establishes the intended local operator session; it is not RBAC.

- Bind only `127.0.0.1` and `::1`; wildcard and LAN binding are rejected under Phase 1 topology.
- Exchange a high-entropy bootstrap token from protected configuration or a permission-restricted file for a bounded session.
- Bootstrap token never appears in URL, referrer, log, Event, or HTML Artifact.
- Session cookie is `HttpOnly`, `SameSite=Strict`, path-scoped, bounded, and `Secure` when TLS is used.
- Every request validates loopback source and the exact expected Host. Unsafe/state-changing methods require one exact non-null matching Origin and CSRF where applicable; safe GET/HEAD permits absent Origin but validates and rejects any malformed, multiple, null, or non-matching value when present.
- Approval and override endpoints require authenticated local session and exact operation binding.
- Authentication failure never downgrades to anonymous access.

### Post-restore authority reset

A restore never revives the authority captured in its backup. Before restored work can be served or claimed, Central advances a target-scoped security epoch held in protected operator state and installs the same epoch in PostgreSQL. All session validation, bootstrap exchange, effective-grant use, SecretReference use, and execution/outbox claim or lease conditions bind the current epoch; a stale epoch fails closed.

The post-restore reset transaction revokes every restored active or pending session, consumes/cancels every restored bootstrap exchange and generation, expires all claims, leases, and fencing tokens, suspends every restored effective capability grant with `restore_review_required`, and disables every restored SecretReference pending reconciliation. Historical Approval, revocation, and use evidence remains immutable but cannot become effective authority. Reconciliation checks only opaque reference identity and safe version/fingerprint against the current protected binding/resolver; it never reads a secret into application state. A restored grant or SecretReference can become effective only through a fresh authenticated operator decision under the new epoch.

Restore stages and registers a cryptographically new bootstrap generation through the normal protected-store protocol; no restored bootstrap verifier is accepted. The restore barrier remains non-ready until the new generation is registered and activated, all reset mutations and safe evidence commit, and the external and database security epochs match. No session is created by restore: the operator must perform a fresh bootstrap exchange and login before reevaluating grants or SecretReferences.

## System and agent authority planes

Registered PostgreSQL, MinIO, provider, and control connections use fixed adapter purposes and least-privileged service identities. Agent authority cannot obtain their handles, reuse their credentials, reach internal services because Central can, turn model egress into generic network authority, or turn `secret.use` into arbitrary credential use.

### System-owned authority planes (Gate 8 topology)

*This subsection and its children are effective only when ADR 0009 is Accepted. They document the concrete Gate 8 system-owned authority planes that realize the abstract Gate 2 system-agent separation.*

The Gate 8 topology defines five distinct system-owned authority planes. Each plane is owned by a locked host identity or root-owned daemon and is reachable only through a closed, versioned protocol with exact PAM or kernel-credential authentication. None of these planes is:

- an agent-requestable capability in the `resource × effect × scope` matrix;
- an Approval-gated operation that the operator can authorize through the browser session;
- a generic process execution that the `process.execute` capability can invoke; or
- ambient privilege that a capability grant implicitly carries.

#### Infrastructure helper plane

The root-owned, release-pinned infrastructure helper is a closed internal mode of the Central release artifact. It mediates all Docker authority and host-level trust operations through a fixed operation matrix:

| Operation | Required authentication | Confirmation required | Agent-requestable |
| --- | --- | --- | --- |
| `init` / `init-status` / `init-resume` / `init-abandon` | Fresh PAM | No (abandon limited to unaccepted empty reservation) | No |
| `prepare` | Fresh PAM | No | No |
| `security-update` | Fresh PAM | No | No |
| `dependency-upgrade-plan` | Fresh PAM | No | No |
| `dependency-upgrade-apply` / `dependency-upgrade-resume` | Fresh PAM | Yes (physical-seat TTY confirmation phrase) | No |
| `trust-install` / `trust-remove` | Fresh PAM | Yes for remove (physical-seat TTY confirmation phrase) | No |
| `browser-open` | Fresh PAM | No | No |
| `browser-clear` / `browser-clear-resume` | Fresh PAM | No | No |
| `runtime-stage` | Fresh PAM plus helper-displayed digest confirmation | Yes | No |
| `runtime-start` / `runtime-stop` / `operator-mode-start` | Fresh PAM | No | No |
| `security-rescue-cleanup` | Fresh PAM | No | No |
| `bootstrap-show` | Fresh PAM plus ready-server proof | No | No |
| `up` / `status` / `doctor` / `down` | Fresh PAM (except unprivileged status/security-status which read only broker-signed XDG views) | No | No |
| `wipe` | Fresh PAM | Yes (physical-seat TTY `WIPE <instance-id> <target-id> POSTGRES+MINIO` confirmation phrase) | No |

The helper request protocol is versioned and closed: it contains operation, invoking UID, instance/binding/config/lock identities, exact operation or confirmation identity, and safe correlation ID — but no plaintext secret, secret pathname, container UID/GID, Compose fragment, image, socket, or executable argument. The invoking UID is authenticated by a root-owned `sudoers` policy with `env_reset`, `timestamp_timeout=0`, a fixed executable, `secure_path`, and no shell or arbitrary arguments.

The ordinary operator UID is not a Docker group member and has no Docker-socket ACL. The `central-runtime` serving process, migration/bootstrap/backup/restore adapters, broker, and `central-agent` executions cannot invoke the infrastructure helper.

Physical-seat TTY confirmation additionally requires the helper to independently open `/dev/tty`, display recomputed safe operation/target/plan IDs, read the fixed confirmation phrase with echo disabled, and bind a one-use confirmation digest. Controller-created PTYs, stdin, flags, environment, redirected input, and replay are rejected as `AUTHORITY_DENIED`.

#### Protected broker plane

The root-owned, socket-activated `central-protected-broker` mediates all secret-value access, TLS private-key signing, HMAC fingerprinting, XDG view signing, and authority-transition journaling. It is activated through a fixed `0600` Unix socket accessible only through one descriptor preopened for an authenticated `central-runtime` process. The broker has no network, Docker, shell, package, Workspace, arbitrary-path, or caller-executable authority and exits after the fixed idle deadline.

The broker performs these closed operations:

| Operation | Protocol | Agent-requestable |
| --- | --- | --- |
| Secret resolution (memfd) | Authenticated runtime session; revalidates authorization-use fence, active pointer, binding lock; copies generation to sealed memfd; transfers descriptor to adapter | No — only registered secret-aware adapters receive memfd descriptors; runtime never sees plaintext |
| Dependency secret handoff | Mutually authenticated helper+broker operation; broker writes bounded value directly to helper-supplied tmpfs descriptor | No — helper never sees plaintext, cannot enumerate another binding |
| TLS leaf signing (`crypto.Signer`) | Authenticated runtime session; broker signs only the exact digest with the locked leaf key; returns signature only | No — CA key never signs an arbitrary digest |
| TLS CA offline rotation | Lifecycle-exclusive; CA key signs only the fixed leaf-rotation object with exact instance/binding/fingerprint constraints | No |
| HMAC fingerprinting | Authenticated runtime session; uses domain-separated HMAC key; returns safe opaque fingerprint | No |
| XDG view signing | Broker signs bounded non-authoritative operator views with domain-separated Ed25519 view-signing key | No |
| Authority-transition journaling | Closed prepared/issued/committed protocol; broker alone writes and synchronizes HMAC-enveloped transition records | No |
| Bootstrap presentation | After fresh PAM and ready-server proof; broker rotates and writes exactly one presentation generation directly to helper-owned TTY | No |

The broker rejects anonymous requests, requests from non-authenticated UIDs, requests for unregistered purposes, enumeration of bindings or generations, raw pathname or directory-descriptor requests, and cross-purpose secret use. Every operation is purpose-specific and non-enumerating.

#### Sandbox-launcher plane

The root-owned, socket-activated `central-sandbox-launcher` has no Docker, network, secret, config-mutation, arbitrary-path, or shell authority. Only an authenticated `central-runtime` launch session may call it.

A closed request contains exactly:

- one persisted Gate 3 authorization-use ID (established by the capability policy evaluation and persisted before invocation);
- one registered Workspace-root binding ID;
- a fixed adapter/executable class (not an arbitrary path or command string);
- relative capability paths within the registered Workspace root;
- a resource envelope (CPU, memory, PID, timeout); and
- a correlation ID.

The launcher:
1. Reopens the registered operator-owned Workspace root with `openat2`/binding/handle checks under the operator fsuid.
2. Verifies the broker-MAC authorization token and current database authorization epoch supplied through the runtime session.
3. Opens only the allowed Workspace/artifact descriptors.
4. Creates a private PID/mount namespace and drops permanently to `central-agent` (no-login, no supplementary groups, `PR_SET_DUMPABLE=0`).
5. Returns pidfd and control pipes to the runtime; retains a minimal parent supervisor until child reaping.

No request contains an absolute path, UID, mount, executable, environment, or namespace flag. The authorization-use ID is the bridge between the Gate 3 capability policy and the concrete execution environment: the launcher maps a policy-evaluated, persisted authorization decision into a bounded launch without turning kernel credentials (`setuid`, `CLONE_NEWNS`, `unshare`) into business authority. Agent exit revokes descriptors and the authorization token; launcher crash kills the namespace.

This plane is not a `process.execute` capability, not an Approval, not generic process execution, and not ambient privilege. The `process.execute` capability in the Gate 2 matrix governs only whether an action may be proposed, and only after policy approval does the authorization-use ID reach the sandbox-launcher.

#### Managed browser plane

The managed browser profile at `/var/lib/central-browser/v1/<instance-id>/` is root-owned `0700` and invisible to operator, runtime, and agent UIDs. The helper launches the browser as `central-browser` in a systemd scope with one CPU, 512 MiB `MemoryMax`, PID limit 256, ext4 project hard quota of 1 GiB/50,000 inodes, and a 256 MiB disk-cache ceiling.

Browser operations are system-owned:

| Operation | Protocol | Agent-requestable |
| --- | --- | --- |
| `browser-open` | Helper validates active local logind Wayland seat, opens the exact compositor socket, passes only that connected descriptor as `WAYLAND_SOCKET`, launches browser at fixed `https://127.0.0.1:8080` | No |
| `browser-clear` | Helper takes lifecycle/runtime locks exclusively, requires `serve` and browser scope stopped, launches runtime maintenance mode to revoke all sessions and bootstrap presentation, renames old profile to quarantine, creates fresh root-policy/trust scaffold | No |
| TLS trust integration | Helper validates CA constraints, installs public certificate in system and browser NSS trust stores | No |

Downloads, extensions, developer tools/protocol, password storage, sync, external URL handlers, service workers, background mode, and non-loopback navigation are disabled by root-managed policy. The browser is never launched with a caller URL, flags, extension, proxy, or alternate profile.

This plane is not a `network.connect` capability, not an Approval, and not ambient privilege. The browser is a fixed system component that the operator initiates but never configures at runtime.

#### Infrastructure service plane

PostgreSQL, MinIO, and their filesystem initializers and logical provisioners are Compose-managed services on an internal `infra` network. They use exact digest-qualified images with `pull_policy: never` and `restart: "no"`. Central itself is not a Compose service.

Infrastructure operations are system-owned:

| Operation | Owner | Agent-requestable |
| --- | --- | --- |
| `postgres-fs-init` / `minio-fs-init` | Root-owned `central-local-infra` one-shot containers with `CAP_DAC_OVERRIDE|CAP_CHOWN|CAP_FOWNER` only; no network | No |
| `postgres` / `minio` daemons | Non-root locked UID/GID from dependency lock; read-only rootfs; bounded tmpfs; all capabilities dropped; `no-new-privileges` | No |
| `postgres-provision` / `minio-provision` | Non-root locked UID/GID; network only `infra`; bounded tmpfs | No |
| `wipe` | Root-owned `central-local-infra` one-off container with AppArmor `central-local-infra-wipe-v1` profile; no network; sequential one-root-at-a-time; seccomp-sandboxed | No |

Container secret handoff never exposes values in Compose YAML, image metadata, environment variables, command arguments, or Docker labels. The helper and broker mutually authenticate each operation; the broker writes bounded values directly to service-scoped tmpfs descriptors.

These services are not `database.read`/`database.mutate`/`database.admin` capabilities, not Approvals, and not generic process execution. They are the fixed dependency layer that the capability policy protects but never grants to agents.

### Authorization-use ID to sandbox-launcher mapping

*This subsection is effective only when ADR 0009 is Accepted.*

When the Gate 3 capability policy evaluates a `process.execute` request and returns `allow` or `require_approval` (followed by an approved durable decision), the runtime persists a canonical authorization-use record before any adapter invocation. This record contains:

- the authorization-use ID (UUIDv7);
- the Workspace, Task, Run, Step, ToolCall, and operation key;
- the canonical capability set: `process.execute` with exact executable identity, working directory, argument envelope, environment policy, and resource bounds;
- any auxiliary capabilities needed (e.g., `filesystem.read` for the Workspace root);
- the effective grant or Approval reference;
- the current policy version; and
- the authorization-use fence deadline.

The sandbox-launcher request maps this record to a concrete launch:

| Authorization-use field | Sandbox-launcher request field | Constraint |
| --- | --- | --- |
| `authorization-use-id` | `authorization_use_id` | Exact UUIDv7 match; launcher verifies broker-MAC token and database epoch |
| Workspace root from `filesystem.read` scope | `workspace_root_binding_id` | Launcher reopens with `openat2`/binding/handle checks under operator fsuid |
| `process.execute` executable identity | `adapter_class` | Fixed enum (e.g., `bounded_shell_v1`); not an arbitrary path |
| Canonical working directory and argument envelope | `capability_paths` | Relative paths within the validated Workspace root; no absolute, `..`, or symlink traversal |
| Resource bounds (timeout, output, memory, CPU) | `resource_envelope` | Inherited from capability grant; launcher enforces but cannot widen |
| Current authorization epoch | `authorization_epoch` | Must match the broker-MAC-supplied epoch; stale epoch fails closed |

The launcher never receives a raw capability decision, a pathname outside the registered Workspace root, an executable identity different from the registered adapter class, or a UID/GID/mount/namespace flag. It receives only the closed mapping above, authenticated through the runtime's broker session.

A kernel credential (`setuid` to `central-agent`, `CLONE_NEWNS`, `unshare`) is a mechanism the launcher uses to enforce the authorization decision; it is not itself business authority. The authorization-use ID remains the sole business-authority token. The launcher cannot widen the authorization, launch without a valid authorization-use ID, or accept a caller-supplied executable path. The `process.execute` capability in the Gate 2 matrix governs whether the action may be proposed; the authorization-use ID proves it was approved; the sandbox-launcher enforces it within kernel boundaries that the capability model declares but does not itself implement.

## Durable flow

1. Agent proposes an untrusted action.
2. Central creates canonical ToolCall identity, input hash, operation key, and complete capability set.
3. Policy decision is persisted before adapter invocation.
4. `deny` records structured outcome and invokes nothing.
5. `require_approval` creates Approval and durable `approval` wait atomically.
6. Authenticated local decision is persisted and the exact request is reevaluated.
7. Central persists prepared ToolCallAttempt before invocation outside the transaction.
8. Adapter performs only the authorized operation after use-time checks.
9. Known result, retry, or `reconciliation` state and append-only Events are persisted.

## Audit and redaction

Security evidence records safe IDs, actor, timestamp, capability, scope or keyed fingerprint, sensitivity, decision, reason, policy version, Approval or grant reference, destination class, SecretReference ID and opaque version, correlation, and outcome.

Required event families are:

- authorization requested, allowed, approval-required, and denied;
- Approval requested, approved, rejected, cancelled, expired-effective-grant, and revoked-effective-grant;
- maintainer override requested and used;
- model-context egress;
- SecretReference resolve success or failure, rotation, revocation, and deletion;
- adapter invocation prepared, known success, known failure, ambiguous outcome, retry, and reconciliation.

Expired-effective-grant and revoked-effective-grant are audit events about grant invalidation; they do not add Approval statuses or rewrite the historical Approval decision.

It never records plaintext secret, bootstrap or session token, auth header, backend locator, unrestricted prompt/tool/network/Artifact body, raw database parameters, command environment, unsafe URL query, or unbounded user-controlled metric label.

Redaction occurs before data enters generic error, Event, log, metric, or trace types. Debug mode cannot disable credential redaction. Suspected disclosure produces structured security failure and rotation guidance.

## Artifact and resource safety

- Artifact bodies remain untrusted regardless of producer.
- Object keys contain opaque IDs only; original filenames are sanitized display metadata and never become object keys.
- Browser delivery uses an explicit content type, disables MIME sniffing, and defaults to safe download disposition.
- Inline preview is restricted to allowlisted formats after format-specific sanitization; executable or active content is never rendered directly.
- Adapters enforce configured timeouts, maximum input, output, and response sizes, concurrency bounds, and budget limits.
- Limit violations produce structured failures and never silently truncate security-relevant decisions.
- Exact limits and quotas remain Gate 3 or adapter-specification decisions and must be fixed before dependent implementation plans.

## Contract validation

- canonical equivalents share security identity and semantic changes do not;
- missing capability, malformed scope, cross-Workspace identity, unsafe path, and unknown sensitivity fail closed;
- strictest composition wins;
- profile cannot override per-action rules;
- grant expiry, revocation, Task completion/cancellation, failed-state suspension, and stricter policy block use;
- retry, new Run, and cancelled-Task rerun follow the stated grant boundary;
- filesystem, process, network, database, model egress, local auth, system-plane abuse, and historical-restore authority-resurrection scenarios map to threat IDs T01–T15.

## Follow-up ownership

| Decision | Owner | Due | Blocks |
| --- | --- | --- | --- |
| Capability request, decision, and grant Go/API serialization | Gate 3 runtime specification owner | 2026-07-20 | Agent/tool runtime implementation plan |
| Bootstrap entropy, storage, exchange, idle, and absolute session limits | Local UI/API specification owner | 2026-07-20 | Local UI implementation plan |
| Security audit retention | Persistence and security specification owners | 2026-07-20 | Security schema and cleanup implementation plan |
| Infrastructure helper closed-operation matrix, PAM/confirm requirements, and TTY-forgery denial | Helper security specification owner | 2026-07-20 (documentary; effective only when ADR 0009 is Accepted) | Gate 9 Slice A host-authority foundation |
| Protected broker operation inventory, memfd/dependency-handoff protocol, and purpose-class enforcement | Broker security specification owner | 2026-07-20 (documentary; effective only when ADR 0009 is Accepted) | Gate 9 Slice A host-authority foundation |
| Sandbox-launcher authorization-use ID mapping, workspace-root validation, and adapter-class enforcement | Sandbox-launcher security specification owner | 2026-07-20 (documentary; effective only when ADR 0009 is Accepted) | Gate 9 Slice B first safe runnable environment |
| Managed browser profile policy, Wayland launch, and trust-store integration as system-owned plane | Browser security specification owner | 2026-07-20 (documentary; effective only when ADR 0009 is Accepted) | Gate 9 Slice B first safe runnable environment |
| Infrastructure service plane container-writable-path contract, capability/seccomp/AppArmor policies, and secret-handoff isolation | Infrastructure security specification owner | 2026-07-20 (documentary; effective only when ADR 0009 is Accepted) | Gate 9 Slice B first safe runnable environment |
