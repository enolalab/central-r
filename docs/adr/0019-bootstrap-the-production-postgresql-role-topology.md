# ADR 0019: Bootstrap the production PostgreSQL role topology and admin credential chain

- **Number:** 0019
- **Title:** Bootstrap the production PostgreSQL role topology and admin credential chain
- **Status:** Accepted
- **Created:** 2026-08-17
- **Owners:** Central maintainer
- **Decision due:** 2026-08-24
- **Decision due history:** None
- **Implementation blocked at:** Any change to the postgres daemon or
  postgres-provision service environment in `compose-policy.json`, any
  extension of the compose renderer's credential-mount tables, the rendered
  first-boot init script, and the helper-side rotate-then-sync credential
  protocol. All were blocked pending this decision; this ADR authorizes them.
- **Decided by:** hieuntg81 (decision-making delegated 2026-08-17 to the
  session agent with explicit instruction to decide; recorded per the same
  delegation as `docs/internal/superpowers/reviews/2026-08-17-sc-g0-record-withdrawal.md`)
- **Decision date:** 2026-08-17
- **Decision record:** Git status-transition commit
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** ADR 0014 (supplies the server-side prerequisite its
  postgres-throughput-provision container assumed)
- **Amended by:** None
- **Related:** ADR 0014 (the per-operation admin passfile whose role this
  bootstrap creates); the B03 acceptance decision's scope boundary
  (`docs/internal/superpowers/reviews/2026-08-12-b03-compose-lifecycle-acceptance-decision.md`
  — "the shipped six-service Compose lifecycle has no committed evidence of a
  successful real bring-up"); `cmd/central/backup_postgres_admin_credential.go`
  whose own comment names this exact gap.

## Context

The production Compose topology cannot produce a working PostgreSQL server,
and the gap sits below every Slice C scenario that needs a sealed backup:

1. **The daemon cannot complete first boot.** The `postgres` service runs the
   unmodified upstream `postgres:16.14-bookworm` image with only `PGDATA` in
   its environment. On an empty data directory the official entrypoint
   refuses to run `initdb` without `POSTGRES_PASSWORD` (or an explicit
   auth-method override). No environment, secret, or init script supplies
   one, so a fresh instance's database never initializes. This is one
   concrete face of the operational gap the B03 acceptance decision recorded:
   the real Compose bring-up has never been exercised.
2. **The role `central` exists nowhere in production.** ADR 0014's
   postgres-throughput-provision container connects as
   `postgres://central@postgres:5432` with a password read from the
   root-helper-materialized one-use passfile
   (`postgres:5432:*:central:<minted>`), and the B03-designed
   `postgres-provision` service already declares `PGUSER: central`. The only
   place the role is ever created is inside one reference-host test's own
   disposable setup, per an explicit narrow-scope maintainer decision that it
   be created there "and nowhere else" pending this ADR.
3. **No mechanism syncs any minted or stored password into the live server.**
   `productionPostgresAdminCredentialManager` mints a fresh random password
   per operation and writes the container-side passfile, and its own comment
   records that changing the live `central` role's password is "a separate,
   currently-undocumented prerequisite that the existing
   `central_migration`/`central_runtime` roles also depend on without any
   committed bootstrap mechanism."

The durable half of the chain already exists: `postgres_server_admin_v1` is a
registered secret purpose, and `postgres.bindings.server_admin` is a
mandatory config binding. What is missing is every step that turns that
binding into a live server whose roles and passwords match it.

## Decision

**Option A — the server's initdb superuser is `central`, backed by the
protected store; roles are created at first boot without passwords; every
password reaches the server only through the root helper's rotate-then-sync
protocol.** Concretely:

1. **First boot.** The `postgres` daemon service gains
   `POSTGRES_USER: central`, `POSTGRES_DB: central`, and
   `POSTGRES_PASSWORD_FILE: /run/secrets/postgres-superuser-passfile`. The
   passfile's host source is
   `/run/central-infra/<instance>/secrets/postgres-superuser-passfile`,
   root-helper-materialized from the protected store's
   `postgres_server_admin_v1` secret. The credential-mount table — the
   ADR-gated closed set that admits `_FILE` destinations — extends by exactly
   one row: (`postgres`, `POSTGRES_PASSWORD_FILE`,
   `/run/secrets/postgres-superuser-passfile`). `initdb` therefore creates
   superuser `central` on the first boot of an empty data directory, and a
   populated data directory ignores the variables, so the row is inert after
   first boot.
2. **Why `central` is the superuser rather than a second, narrower admin.**
   `initdb` must create a superuser under some name; every existing surface —
   the provision service's `PGUSER`, the compiled five-field passfile format
   in `central-local-infra`'s postgres-provision mode, the reference-host
   test — already names `central` as the connecting admin identity. A
   separate non-superuser admin would still leave an unmanaged superuser
   secret behind it, adding a credential without removing one.
3. **Role topology at first boot.** A rendered, read-only
   `docker-entrypoint-initdb.d` init script — produced by the same compose
   renderer that owns every other rendered artifact, and containing **no
   password material** — creates `central_migration`, `central_runtime`, and
   `central_outbox` as `NOLOGIN NOINHERIT` roles and applies their
   least-privilege grants. A role that exists but cannot log in is inert
   until its password is synced.
4. **Password sync, uniformly rotate-then-sync.** The root helper is the only
   writer of live PostgreSQL passwords, connecting as `central` with the
   protected store's current server-admin secret. For each managed role
   (including `central` itself, and including ADR 0014's per-operation
   minted passfile value) the order is fixed: durably record the minted
   value as the binding's **candidate** in the protected store; `ALTER ROLE`
   on the live server; promote the candidate to active. Recovery after a
   crash between steps tries the candidate, then the previous active value —
   the protected store's existing candidate/retire semantics carry this
   without a new mechanism. Role passwords therefore never appear in any
   rendered file, environment value, or log; the only password-bearing files
   are the two root-owned passfiles under
   `/run/central-infra/<instance>/secrets/`.
5. **ADR 0014's per-operation flow becomes complete.** Before the
   postgres-throughput-provision container starts, the helper rotates
   `central`'s live password to the minted value through step 4 and writes
   the container passfile the existing manager already produces. The
   manager's documented out-of-scope note is closed by this mechanism, not
   widened into the manager.

### Implementation refinement, 2026-08-17 (same delegated authority)

Implementation moved the superuser secret's durable home from the broker's
B04-style protected store to **the root helper's own protected instance
root** (`/var/lib/central-protected/v1/instances/<id>/postgres-server-admin/`,
`active`/`candidate` files, root-only) — the same mechanism that already
holds the restore capacity reserve helper's durable signing key. The reason
is not convenience: the B04 handoff ceremony exists to move a secret across
a privilege boundary to a less privileged peer under proofs, and this secret
crosses no boundary — it is minted by root, stored by root, and consumed by
root (the daemon's first-boot passfile and the per-operation container
passfile are both root-written). A broker ceremony for a root-held,
root-consumed secret adds protocol surface without adding a guarantee.
Everything else in §Decision stands as written, including the fixed
rotate-then-sync order and its recovery rule.

One §4 item is explicitly deferred with its own reason: syncing the
**`central_migration`/`central_runtime`/`central_outbox`** role passwords
into the live server. Their durable values are broker-domain (B05's
materialization resolves `postgres_migration_v1` from the broker's store),
so a helper-side ALTER would desynchronize the broker's copy; that sync
genuinely needs broker coordination and lands as its own task under this
ADR's authority. Until it does, those roles exist NOLOGIN from first boot —
inert, exactly as §3 designed — and nothing regresses: no mechanism synced
them before this ADR either.

### Residuals surfaced by the first live bring-up (2026-08-17)

Two consequences of making first boot actually work, recorded rather than
absorbed — the first needs a maintainer ruling:

1. **RESOLVED 2026-08-17 — the host-access network denies egress.** The
   root helper runs rotate-then-sync on the host and connects to the daemon
   at `127.0.0.1:55432`, and the config schema pins these loopback ports.
   Docker silently drops host-port publishing for a container attached only
   to an `internal: true` network (verified empirically), so the publishing
   services (postgres, minio) are dual-homed onto a companion network. That
   network is non-internal — so DNAT port publishing works — but sets
   `com.docker.network.bridge.enable_ip_masquerade=false`, which removes the
   outbound return path: DNAT for the published loopback ports is independent
   of masquerade, so inbound keeps working while the containers get no
   internet egress. Verified both directions empirically (inbound reaches the
   port; outbound to the internet is blocked) and asserted from inside the
   running daemon by the first-boot reference-host test. The denial is
   declared in the rendered compose file itself — no host iptables, no
   external tooling. No maintainer ruling is outstanding on this item.

2. **Known limitation, low severity, fail-safe — rotate recovery treats
   "server unreachable" and "auth failed" alike.** `RotateForOperation`'s
   crash recovery probes the live server with the active and candidate
   passwords; a transient connection failure during recovery is
   indistinguishable from an auth mismatch and fails the operation closed
   (retryable on the next attempt with the server up). It never guesses wrong
   or corrupts state, so it is left as-is; a future refinement can split
   "unreachable → retry" from "auth mismatch → refuse."

## Alternatives considered

- **Option B — keep superuser `postgres`, create `central` as a
  `CREATEDB CREATEROLE` non-superuser in the init script.** Rejected: the
  superuser's password must then be managed too, so the credential chain
  gains a member that no existing binding, purpose, or consumer names, and
  the provision service's `PGUSER: central` would authenticate as a role
  whose grants must forever chase what provisioning actually needs.
- **Option C — trust or peer auth on the internal Compose network.**
  Rejected outright: the network hosts every service, and B10's broker-scoped
  credential model exists precisely because network position must never be an
  authority.
- **Option D — bake an init SQL with passwords from rendered secrets.**
  Rejected: rendered artifacts are long-lived and debuggable; a password in
  one outlives its rotation.

## Consequences

- A fresh instance's database initializes unattended, with roles and
  passwords converging to the protected store's bindings; a rebooted host
  re-materializes the same passfiles from the same durable source.
- The credential-mount closed set grows by one audited row, under this ADR's
  authority, keeping the "no new service, key, or target without a new ADR"
  invariant true rather than eroded.
- The `central_migration`/`central_runtime`/`central_outbox` sync gap the
  admin-credential manager documented is closed by the same mechanism, not
  by a parallel one.
- **This authorizes implementation; it accepts nothing.** No packet or gate
  changes status. The implementation lands under Slice C's plan discipline
  with its own tests (compose render/validate rows, init-script rendering,
  rotate-then-sync unit and crash-order tests, and a reference-host case),
  and SC-G1's clean-host evidence remains the only thing that can prove the
  chain end to end.
