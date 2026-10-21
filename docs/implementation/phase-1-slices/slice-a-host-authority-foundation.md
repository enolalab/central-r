# Slice A — Host Authority Foundation

- **Slice ID:** A
- **Dossier:** `slice-a-host-authority-foundation.md`
- **Packets:** A01–A07
- **Dependency:** None (foundational)
- **Accepts:** All subsequent slices

Slice A establishes the prerequisite parser/result substrate, closed A–E command registry, locked `central-runtime`/`central-agent`/`central-browser` identities, root-owned helper with fresh-PAM physical-seat confirmation, root-owned protected broker with `protected_file_v1` and local TLS authority, root-owned sandbox launcher, strict configuration/signed projections, and adversarial authority evidence. It does not prepare dependencies, create Compose topology, start services, run migrations, serve the product UI, persist Tasks, or execute an agent workflow.

## A01

### Identity and outcome

Bootstrap the single Go module, pin the foundation toolchain and dependencies, implement architecture-import checks, and establish the reproducible build substrate. A01 produces the `go.mod`, `go.sum`, pinned toolchain version, `sqlc` configuration, and the architecture-import-guard binary that every subsequent slice depends on.

### Implementation boundary

One Go module at the repository root. Toolchain pinned via `go.mod` `toolchain` directive and `go.sum`. Dependencies include `github.com/gin-gonic/gin`, `github.com/jackc/pgx/v5`, `github.com/sqlc-dev/sqlc`, and `github.com/minio/minio-go/v7` at exact pinned versions. The import-guard enforces the capability-owned boundary: no `infrastructure` import in `domain` or `usecase`, no `controller` import in `usecase` or `domain`, and no cross-capability import without explicit dependency declaration. Build is `go build ./...` with `-trimpath` and `-buildvcs=true`. The guard runs before compilation; a violation fails the build.

### Durable data and migration

No database or migration in A01. The package tree and import rules are the durable artifacts.

### Security and authority

No runtime credentials. The import-guard is a static analysis tool, not a runtime enforcement mechanism. Pinned dependency versions are recorded in `go.sum`; `govulncheck` runs on every build.

### Failure, retry, cancellation, and recovery

Build failure is addressed by correcting the violating import or pinning the correct dependency version. No runtime recovery scope.

### Verification and evidence

- `go build ./...` succeeds with `-trimpath -buildvcs=true`
- Architecture-import check passes against the accepted capability-owned boundary
- `govulncheck ./...` reports zero known vulnerabilities at pinned versions
- Every dependency has an exact version in `go.sum`; no `replace` directive without accepted ADR rationale

### Scope control

A01 creates the module and toolchain foundation. It must not define any runtime process, HTTP handler, database connection, or artifact store client.

### Definition of Done

Single Go module at repository root with pinned toolchain, exact dependency versions, passing architecture-import checks, passing vulnerability scan, and a `go build ./...` that completes without error. The import-guard rejects cross-boundary imports before compilation.

## A02

### Identity and outcome

Define the complete A–E command census, closed grammar, deferred dispatcher, exact exit-code-5 result matrix, and activation replacement rule. A02 owns the command registry that every subsequent slice extends; no slice may introduce an unregistered command.

### Implementation boundary

Commands are enumerated in a closed `command.go` registry with verb/subcommand grammar. The deferred dispatcher resolves commands to handlers by slice activation status: an unimplemented-slice command returns `exit 5` / `UNSUPPORTED_IN_THIS_SLICE` without mutation. The activation replacement rule is: when a later slice activates, its commands replace the `exit 5` stubs with registered handlers. The exit-code-5 matrix enumerates every command from every slice and its pre-activation behavior.

### Durable data and migration

The command registry is compiled into the binary. No database storage for the registry.

### Security and authority

Command dispatch is gated by slice activation, not by runtime permissions. A02 does not enforce capability or approval policy.

### Failure, retry, cancellation, and recovery

An unimplemented command returns `exit 5` and a structured error. No retry or recovery for unregistered commands.

### Verification and evidence

- Every A–E command has a non-empty entry in the registry with verb, subcommand grammar, and owning slice
- Dispatch maps `exit 5` for every command whose owning slice is not activated
- The exit-code-5 matrix is closed and exhaustive
- `go test ./...` covers registry enumeration and dispatch behavior

### Scope control

A02 owns the command registry and dispatcher. It must not implement any command handler, database operation, or HTTP endpoint.

### Definition of Done

Closed command registry, deferred dispatcher, exit-code-5 matrix, and activation replacement rule implemented and test-covered. Every Phase 1 command is registered; every unimplemented-slice command returns `exit 5` without mutation.

## A03

### Identity and outcome

Implement instance genesis, locked service identities, and helper/PAM binding. A03 creates the instance identity and the no-login `central-runtime`, `central-agent`, and `central-browser` identities without granting Docker, broker, protected-state, or plaintext-secret authority.

### Implementation boundary

Genesis records one immutable instance identity in a root-owned parent outside the repository, every Workspace, and operator XDG paths. It binds the installed release, host identity, and locked UID/GID allocation; it is not a credential or a credential-derivation source. The root-owned release-pinned helper exposes only its closed operation matrix. Each mutating helper operation requires fresh PAM authentication and physical-seat TTY confirmation. The operator is not a Docker-group member and receives neither Docker socket nor helper bypass.

### Durable data and migration

The instance record, helper binding receipt, PAM policy binding, and UID/GID allocation receipt are immutable authority-transition inputs, not PostgreSQL state. Re-running successful genesis returns the existing identity and never replaces authoritative records.

### Security and authority

`central-runtime`, `central-agent`, and `central-browser` are no-login identities. Runtime receives no repository, Workspace, Docker, helper-socket, or plaintext-secret authority; agent is usable only through the later launcher protocol; browser owns only its managed profile. The helper verifies its release identity before binding, and protected files are never operator-owned.

### Failure, retry, cancellation, and recovery

Missing locked identities, helper mismatch, failed PAM, absent physical-seat TTY, or conflicting instance state fail closed before mutation. Interrupted genesis resumes only after validating durable prior receipt evidence; it never generates a different identity or silently repairs host accounts.

### Verification and evidence

- One installed host resolves to one stable non-secret instance identity
- Locked identities are no-login and have only accepted ownership/path access
- Helper release identity and PAM binding verify before mutation
- Missing TTY, stale PAM, Docker-group membership, and direct helper-socket access are denied
- Repeated genesis is idempotent and interrupted genesis resumes from durable receipts
- Future test suite: `go test ./internal/authority/...`
- Evidence artifact: `slice-a-instance-genesis.json`

### Scope control

A03 owns identities, genesis, helper binding, and PAM ceremony only. It does not create broker values/TLS keys, Compose topology, dependencies, database state, or a sandbox.

### Definition of Done

Instance genesis, locked identities, and helper/PAM binding are durably evidenced, idempotent, and fail closed. No unprivileged identity receives protected, Docker, or plaintext-secret authority.

## A04

### Identity and outcome

Establish the socket-activated root-owned protected broker, `protected_file_v1` backend, local TLS authority, signing services, and authoritative transition journal. A04 is the only Slice A owner of protected-state and secret/TLS private-value custody.

### Implementation boundary

The broker has no network, Docker, arbitrary shell, or arbitrary-path authority. `protected_file_v1` stores create-only protected generations below a root-owned parent, changes its selector atomically, and retains prior generations immutably. The broker generates/retains instance CA and leaf private keys, signs TLS and authority records, computes HMAC fingerprints, and performs narrow descriptor handoff. It exposes no generic plaintext-secret read operation and does not create Compose topology; B02/B03 own dependency preparation and lifecycle.

### Durable data and migration

Protected generations, selectors, TLS public metadata, and signed `central.authority-transition/v1` journal entries are authoritative root-owned records. XDG views are not authoritative. PostgreSQL is not required for broker bootstrap, and no plaintext value appears in config, log, journal, or evidence.

### Security and authority

Only the broker may enumerate/open protected values and TLS private keys. Operator, runtime, and agent direct opens are denied. Leaf certificates have only SAN IP `127.0.0.1` and the application boundary requires TLS 1.3. Future adapter handoff is operation-bound and descriptor-only; it cannot return a bearer secret.

### Failure, retry, cancellation, and recovery

Generation creation, selector activation, signing, and handoff are idempotent only for a durable operation identity. Broker crash, malformed request, stale/replayed descriptor, signature failure, or private-key denial fails closed with safe evidence. Startup validates signed journal and selector; ambiguous prior state is reconciled rather than overwritten.

### Verification and evidence

- Broker has no network, Docker, shell, or arbitrary-path authority
- Protected generations are create-only, atomically selected, and inaccessible by operator/runtime/agent direct open
- TLS leaf has only the `127.0.0.1` IP SAN and TLS 1.3 succeeds through broker authority
- Authority-transition signatures and HMAC fingerprints verify; altered records are denied
- Descriptor replay/substitution and broker-crash recovery fail closed without plaintext disclosure
- Future test suite: `go test ./internal/authority/...`
- Evidence artifact: `slice-a-protected-broker.json`

### Scope control

A04 owns protected broker, protected-state, TLS, and authority-transition custody. It does not derive credentials from instance inputs, start dependencies, run migrations, serve HTTP, or implement Task/runtime behavior.

### Definition of Done

The broker provides durable root-owned generation custody, local TLS/signing authority, and fail-closed narrow handoffs. No untrusted identity can enumerate, open, or receive a general plaintext protected value.

## A05

### Identity and outcome

Implement strict `central.config/v1` loading, cross-field validation, signed authority-transition consumption, and non-authoritative XDG projections. A05 gives later components one versioned configuration authority without allowing runtime flag/environment topology override.

### Implementation boundary

The parser accepts an absolute selected path or unambiguous XDG discovery and rejects unknown schema versions, missing fields, duplicate sources, relative protected paths, non-loopback binds, and cross-field violations. It validates identity, paths, HTTP, PostgreSQL, object store, protected store, bootstrap/session, Artifact, operator-mode, tool, runtime, and observability sections. Environment variables and flags cannot override topology. The broker signs XDG views; consumers treat them as projections, not authority.

### Durable data and migration

Authoritative config and immutable transition payloads remain below root-owned protected parents. Revisions are linked by signed `central.authority-transition/v1` records and selected atomically. A05 creates no PostgreSQL state or secret generation; sensitive fields are SecretReference/descriptor identities, not plaintext.

### Security and authority

Configuration rejects operator-writable replacement of authoritative paths and unsigned view/transition data. Views omit secret values, TLS private-key locations, and protected backend locators unnecessary for recipients. Consumers verify signature, schema version, instance identity, and transition sequence before use.

### Failure, retry, cancellation, and recovery

Invalid syntax, missing/unknown field, signature/sequence failure, conflicting discovery, unsafe path, or invalid cross-field value returns a typed error before startup. A failed projection is never authority. Recovery accepts a new signed generation or resumes a known completed transition; it never edits prior authority in place.

### Verification and evidence

- Valid `central.config/v1` and every required section/cross-field constraint are exercised
- Invalid bind, path, discovery, version, signature, and transition sequence are rejected with typed safe reasons
- Signed XDG view resolves on the reference host and cannot supersede protected authority
- No view, configuration output, or diagnostic exposes a plaintext secret, private key, or protected backend locator
- Future test suite: `go test ./internal/config/...`
- Evidence artifact: `slice-a-configuration-authority.json`

### Scope control

A05 owns configuration authority/projections. It does not mutate protected values, start Compose, create database state, render HTTP, or execute agent/tool operations.

### Definition of Done

Strict configuration and signed projections are validated before use, reject unsafe overrides, preserve authority history, and expose no plaintext protected value.

## A06

### Identity and outcome

Implement the distinct root-owned `central-sandbox-launcher` that starts locked `central-agent` from a narrow descriptor-bound request. A06 establishes launcher authority and the resource envelope for later read-only Workspace Tools; it does not implement the Tool loop.

### Implementation boundary

The launcher accepts only an authenticated `central-runtime` operation-bound request and delegated Workspace descriptors. It has no request fields for arbitrary UID, executable, network, secret, Docker, arbitrary path, or mount. It runs only as `central-agent` in private PID/mount namespaces, closes unrelated descriptors, disables a controlling TTY, and uses no shared network namespace. Descriptor-relative path resolution disables symlink following and rejects Workspace escape before any read. Defaults are 0.5 CPU, 256 MiB, 32 processes, 64 file descriptors, and 300 seconds; hard maxima are 1 CPU, 512 MiB, 32 processes, 64 file descriptors, and 600 seconds.

### Durable data and migration

The launcher consumes the A05 validated envelope and emits bounded safe launch/settlement evidence with operation identity, limits, exit classification, and cleanup result. Process state is ephemeral and not PostgreSQL authority; evidence contains no secret, arbitrary host path, or Workspace content.

### Security and authority

The launcher is separate from the broker and has no Docker, network, protected-value, or general shell authority. It rejects descriptor replay/substitution, arbitrary mount/exec/UID requests, ptrace, namespace escape, and inheritance of runtime/helper/broker sockets. Deadline settlement uses SIGTERM, bounded grace, SIGKILL only when required, and verified cgroup/namespace cleanup.

### Failure, retry, cancellation, and recovery

Malformed request, authorization failure, bound violation, descriptor/path denial, namespace/cgroup failure, OOM, deadline, launcher crash, or cleanup failure returns a typed safe outcome. Retry uses a new operation identity only after evidence proves prior attempt did not start or settled; unknown launcher outcome remains reconcilable. Crash cleanup fails closed and leaves no inherited authority.

### Verification and evidence

- Only runtime can submit a schema-valid descriptor-bound launch; arbitrary path, UID, executable, mount, network, and secret requests are rejected
- Child is `central-agent`, has no controlling TTY, and inherits no broker/helper/runtime protected descriptor
- CPU, memory, process, fd, and deadline defaults are enforced; over-hard-cap requests are rejected
- Symlink escape, path replacement, ptrace, namespace escape, descriptor replay, and substitution are denied with no partial read
- OOM, deadline, launcher crash, and broker unavailability settle with bounded cleanup and no residual authority
- Future test suite: `go test ./internal/sandbox/...`
- Evidence artifact: `slice-a-sandbox-verification.json`

### Scope control

A06 owns launcher authority/enforcement only. It does not choose provider/tool behavior, open general network access, read arbitrary repository paths, create Task/Run, or invoke a model.

### Definition of Done

The launcher is descriptor-bound, fails closed, enforces accepted bounds, cleans up boundedly, and cannot widen host, network, Docker, or protected-value authority.

## A07

### Identity and outcome

Prove same-UID, descriptor, TTY, path-race, broker-crash, and authority denial behavior. A07 validates the complete host authority foundation before Slice B begins.

### Implementation boundary

A07 is a verification suite, not a runtime component. It exercises A03–A06 against the accepted adversarial scenarios and explicitly verifies:

1. same-UID and wrong-UID socket denial;
2. fresh-PAM physical-seat confirmation and no controlling TTY in the sandbox;
3. descriptor replay, descriptor substitution, and path-replacement denial;
4. direct-open and ptrace denial for protected values and TLS private keys;
5. symlink escape and Workspace-boundary denial with no partial read;
6. broker crash and launcher crash fail closed without widening authority;
7. unsigned/wrong-release helper and authority-transition denial;
8. every B–E command still returns `exit 5` / `UNSUPPORTED_IN_THIS_SLICE` without mutation.

### Durable data and migration

None. A07 is a verification suite.

### Security and authority

A07 exercises negative security scenarios. It must not weaken A03–A06's authority checks. Test fixture keys and configurations are test-only and never committed as accepted authority.

### Failure, retry, cancellation, and recovery

A verification failure is a gate failure, not a runtime event. The failing scenario identifies the exact contract violation.

### Verification and evidence

- Every scenario produces deterministic pass/fail evidence
- Same-UID/wrong-UID: socket connection from the same UID or a wrong UID is denied
- Fresh-PAM physical-seat: sandbox launch requires fresh PAM confirmation and has no controlling TTY
- Descriptor replay/substitution/path-replacement: all three denial paths reject the protected value
- Direct-open/ptrace: protected values and TLS private keys cannot be opened or ptraced
- Symlink escape/Workspace-boundary: symlink escape is denied with no partial read across the Workspace boundary
- Broker/launcher crash: broker and launcher crash fail closed without widening authority
- Unsigned/wrong-release helper and authority-transition: both are denied
- B–E commands: every B–E command returns `exit 5` / `UNSUPPORTED_IN_THIS_SLICE` without mutation
- Future test suite: `go test ./internal/authority/...`
- Evidence artifact: `slice-a-authority-verification.json`

### Scope control

A07 is a verification suite. It must not implement new runtime components or modify A03–A06 behavior.

### Definition of Done

All eight adversarial scenarios pass deterministically. Every authority check in A03–A06 is exercised. Slice A acceptance is complete when A07 evidence is verified.

## Slice A acceptance

Slice A is complete when:

1. A01–A07 contracts are verified with passing tests
2. The architecture-import guard rejects cross-boundary imports (A01)
3. Every A–E command returns `exit 5` before slice activation (A02)
4. Instance identity is deterministic and survives restart (A03)
5. Broker TLS is valid for localhost with correct permissions (A04)
6. Configuration parses with signed authority transitions (A05)
7. Sandbox enforces every accepted bound and guarantees cleanup (A06)
8. A07 verifies all eight adversarial authority scenarios
9. The complete Slice A acceptance evidence is durably recorded

Slice A must not claim Slice B capabilities or produce any runtime behavior beyond host authority initialization.
