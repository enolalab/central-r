# ADR 0014: Authorize PostgreSQL throughput fixture provisioner mode

- **Number:** 0014
- **Title:** Authorize PostgreSQL throughput fixture provisioner mode
- **Status:** Accepted
- **Created:** 2026-08-10
- **Owners:** Central maintainer
- **Decision due:** 2026-08-17
- **Decision due history:** None
- **Implementation blocked at:** C02 production Compose and image-inventory changes that add `postgres-throughput-provision`, add its fixed read-only administrative passfile mount, materialize `postgres_server_admin_v1` for that service, wire the fixed request/receipt protocol, or claim production/acceptance coverage for that path. External `central-local-infra` prototypes and Central coordinator interfaces may continue while this ADR is Proposed, but they are not production wiring or acceptance evidence.
- **Decided by:** hieuntg81
- **Decision date:** 2026-08-10
- **Decision record:** Git status-transition commit
- **Supersedes:** ADR 0011
- **Superseded by:** None
- **Amends:** ADR 0008, ADR 0012
- **Amended by:** 0019 (supplies the server-side role bootstrap and
  password-sync prerequisite this ADR's container flow assumed)
- **Related:** [ADR 0012 — Extend root credential mount and add minio-provision mode](0012-extend-root-credential-mount-and-add-minio-provision-mode.md), [ADR 0011 — Amend local topology for dedicated migration operator](0011-amend-local-topology-for-dedicated-migration-operator.md), [ADR 0008 — Adopt capability-owned Go application boundaries](0008-adopt-capability-owned-go-application-boundaries.md), [Slice C required recovery design](../internal/superpowers/specs/2026-08-09-slice-c-required-recovery-design.md), [central-local-infra design](../internal/superpowers/specs/2026-08-05-central-local-infra-design.md), [ADR governance](README.md)

## Context

C02's accepted throughput admission requires a disposable PostgreSQL fixture database. A privileged provisioner creates and loads the operation-bound fixture, closes before the unprivileged `pg_dump` worker runs, and later reopens independently to verify or drop only that fixture. The active production Compose topology already contains an ordinary one-shot service named `postgres-provision`, backed by the locked upstream `library/postgres:16.14-bookworm` image. That service owns B03's normal PostgreSQL prerequisite provisioning; replacing it or overloading its lifecycle with C02 work would conflate two authorities and could regress an already accepted bring-up path.

The [central-local-infra design](../internal/superpowers/specs/2026-08-05-central-local-infra-design.md) originally closed that image's mode census at `fs-init` and `wipe`. ADR 0012 authorized a third mode, `minio-provision`, and required fresh SB-G2-style delivery acceptance for the enlarged candidate. C02 now needs the same kind of narrow, auditable executable boundary for PostgreSQL fixture administration. An upstream general-purpose PostgreSQL image plus caller-composed `psql` or shell commands would leave command text, connection selection, output shape, and administrative behavior open.

The active topology inherited through ADR 0011's replacement amendment of ADR 0008 fixes six Compose services. Adding a separate probe-only service is a partial change to ADR 0008's effective topology and overlaps ADR 0011 as its current active amendment. Under ADR governance, this proposal therefore supersedes ADR 0011 and becomes the replacement amendment of ADR 0008; it retains every ADR 0011 decision while changing only the Compose service census from six to seven. It also amends ADR 0012 by extending the accepted `central-local-infra` mode census and its fresh-delivery-evidence rule. It does not semantically edit either decided record while Proposed.

`postgres_server_admin_v1` is currently declaration-only and non-materializable. The probe-only service cannot create or drop a database without a narrowly delivered administrative credential. Authorizing its materialization, even only into a fixed helper-owned tmpfs handoff, is an independent secret-access and privileged-database boundary that must be explicit rather than inferred from the service decision.

The change therefore crosses deployment, secret-access, privileged-database, and supply-chain trust boundaries. Production wiring and any claim that C02 has an accepted PostgreSQL fixture provisioner require a durable decision.

## Decision

If accepted, this ADR makes the following bounded amendment.

1. **Authorize a fourth `central-local-infra` mode named `postgres-provision`.** The closed mode census becomes `fs-init`, `wipe`, `minio-provision`, and `postgres-provision`. The new image mode is not the existing Compose service of the same old name; it is the fixed entrypoint selected only by the new `postgres-throughput-provision` service described below. It is not a general PostgreSQL client, SQL runner, migration runner, shell, package-manager surface, or arbitrary network tool. For C02 it accepts only the closed one-shot fixture actions `create_load_v1`, `verify_v1`, and `drop_v1`. Each invocation handles exactly one action and exits; no provisioner process or administrative session remains alive across the `pg_dump` interval.

2. **Add one seventh, probe-only Compose service named `postgres-throughput-provision`.** The existing six services, including ordinary B03 `postgres-provision`, remain present and unchanged in image, UID, mounts, entrypoint, lifecycle, receipt, and authority. The new service alone uses a digest-pinned, freshly accepted `central-local-infra` candidate. Its fixed entrypoint receives exactly one argument, the literal mode `postgres-provision`, and no additional argv. It is started only for a C02 one-shot request, uses `restart: "no"`, and is not part of ordinary B03 prerequisite provisioning. No other service or image mapping changes under this decision.

3. **Fix the C02 database and target in executable policy.** The provisioner connects only to Compose DNS target `postgres:5432`. Neither argv nor stdin can supply or override host, port, user, connection options, SQL, database name, schema, table, file path, or executable. The disposable database name is derived only from the validated C02 UUIDv7 operation ID by the closed rule already used by the throughput worker: `central_probe_` followed by the lowercase UUID without hyphens. `create_load_v1` creates that database and loads the fixed deterministic throughput fixture; `verify_v1` checks the exact operation-bound database and fixture shape without widening or repairing it; `drop_v1` removes only that database. Cross-operation substitution, an unexpected existing database or fixture, partial state, and any identity mismatch fail closed. Cleanup remains coordinator-owned: after dump success, failure, timeout, or cancellation, the coordinator invokes the independent `drop_v1` action and treats an unverified drop as `CLEANUP_REQUIRED`.

4. **Narrowly authorize materialization of `postgres_server_admin_v1`.** The root helper may resolve and materialize that otherwise declaration-only purpose only for one validated C02 provisioner operation, only into the fixed root-helper-owned private tmpfs passfile source, and only for read-only mounting into `postgres-throughput-provision` at `/run/secrets/postgres-admin-passfile`. The helper binds the materialization to the exact instance, operation UUIDv7, action, service identity, fencing token, candidate identity, and expiry. It is single-use: replay, concurrent reuse, stale fencing, expired material, substitution, or a second consumer is denied. The helper owns removal on container exit, failed start, timeout, cancellation, receipt failure, and coordinator loss; cleanup failure is terminal and blocks reuse. Credential bytes never appear in argv, stdin, stdout, environment values, Compose render output, receipts, or plaintext logs. The only provisioner-specific environment value is the fixed non-secret endpoint `CENTRAL_LOCAL_INFRA_POSTGRES_ADMIN_ENDPOINT=postgres:5432`; the passfile locator is compiled into the closed executable policy and cannot be selected through environment or request data.

5. **Constrain the fixed passfile mount and execution identity.** The mount is read-only, non-interpolated, instance- and operation-scoped, and accepted only for the exact `postgres-throughput-provision` service/key/target tuple. The root helper owns the private tmpfs directory and the passfile lifecycle, creates the passfile inode as exact UID/GID `65532:65532` with mode `0400`, and validates its tmpfs ancestry, ownership, mode, inode/device identity, non-symlink path, mount flags, and post-use removal; a root-owned passfile inode, alternate UID/GID, alternate source, target, service, writable mount, or persistence outside that tmpfs fails closed. The service runs as fixed non-root UID/GID `65532:65532`, with no login shell, added Linux capabilities, Docker access, host networking, or host-path authority beyond that explicit mount. Network access is limited to the existing internal `infra` network and the fixed `postgres:5432` target. Any UID/GID, entrypoint, mount, target, capability, or network drift fails acceptance.

6. **Do not deliver the administrative credential to Central or the backup worker.** `central serve`, the CLI/coordinator, the root helper's unprivileged worker launch, `central-backup`, `pg_dump`, ordinary `postgres-provision`, and other runtime/worker processes receive neither the administrative credential bytes nor its path, mount, environment, or descriptor. The throughput worker continues to receive only its separately scoped dump credential through its accepted sealed-descriptor contract. Central may ask the helper to orchestrate one of the three closed provisioner actions and consume a safe receipt; it may not resolve the purpose, read the material, mount the passfile, or perform the privileged SQL itself.

7. **Use exact argv, strict stdin requests, and strict stdout receipts.** The container entrypoint receives only the fixed `postgres-provision` mode argv. The provisioner accepts one bounded, versioned canonical request document on stdin and rejects duplicate keys, unknown keys, missing fields, invalid UUIDv7 identifiers, trailing documents or bytes, oversized input, unsupported actions, and caller-controlled selectors. It writes exactly one bounded, versioned canonical receipt document to stdout and no diagnostic prose. A receipt binds the instance, operation, requested action, fixed fixture identity, fencing token, candidate/protocol identity, terminal outcome, safe reason code, and bounded verification facts needed by the coordinator; it contains no credential, passfile or host path, raw SQL, server error, or unrestricted database metadata. Failure uses a nonzero exit status and a fail-closed receipt when safely possible; stderr is bounded and secret-free. Success is action-specific: `create_load_v1` proves the exact fixture was loaded, `verify_v1` proves it remains exact, and `drop_v1` proves the operation-bound database is absent. Receipt parsing, provenance, fencing, or binding failure is not success.

8. **Require fresh SB-G2 delivery evidence before production use.** Evidence accepted for the earlier three-mode candidate does not accept this fourth-mode candidate. The new immutable source revision and exact OCI candidate must repeat the applicable independent SB-G2 controls: reproducible clean builds with byte-identical OCI records from two isolated builders, signed manifest/config/layer and provenance evidence, SBOM and vulnerability admission, syscall and AppArmor policy digests, clean-host runtime and denial tests, fixed-UID/mount/network/target inspection, strict protocol negative tests, one-use/expiry/fencing/cleanup tests, credential non-observation by Central and the worker, and independent PASS review. Production Compose/image inventory/mount wiring and C02 acceptance claims remain blocked until both this ADR and that fresh evidence are accepted.

All other ADR 0012 decisions remain in force. In particular, `minio-provision` retains its separately authorized root-credential boundary and protocol; this proposal neither shares PostgreSQL administration with it nor widens any MinIO authority. This proposal retains all ADR 0011 decisions concerning the dedicated migration operator, migration credential handoff, and version-zero reset. It changes ADR 0008's effective local topology only by adding the seventh probe-only service described here.

## Consequences

### Benefits

- C02 gets a narrow, independently inspectable database-administration component instead of handing arbitrary SQL or an administrative credential to Central or its backup worker.
- Separating `postgres-throughput-provision` preserves ordinary B03 `postgres-provision` unchanged and prevents probe lifecycle or credential handling from coupling to local bring-up.
- The `create_load_v1`/dump/`drop_v1` lifecycle preserves session separation: administrative provisioner sessions end before the dump worker runs, while cleanup can be retried independently and proven through a bound receipt.
- Fixed UID, mount, endpoint, database derivation, protocol, image digest, one-use materialization, and fencing make substitution and privilege expansion observable and fail closed.
- Repeating SB-G2 evidence ties the newly enlarged executable surface to a specific reproducible candidate rather than inheriting acceptance from a smaller image.

### Costs and limitations

- The local topology grows from six services to seven, so Compose census, lifecycle, inventory, policy, status/inspection, clean-host, and denial tests require explicit updates while all six existing service contracts remain stable.
- `central-local-infra` gains privileged PostgreSQL client logic and a fourth closed mode, so its build, syscall policy, AppArmor policy, SBOM, provenance, vulnerability result, and clean-host evidence must all be regenerated and independently reviewed.
- `postgres_server_admin_v1` gains one narrowly materializable consumer. The helper's one-use handoff, expiry, fencing, tmpfs ownership, mount validation, crash cleanup, and non-observation properties become acceptance-critical security controls.
- C02 must persist enough operation state to resume cleanup safely; a successful dump does not excuse a missing or unverifiable `drop` receipt.
- This decision does not authorize arbitrary fixture size, SQL, database selection, remote PostgreSQL targets, schema migration, repair, or general operator administration.
- A Proposed ADR and prototype interfaces are not production acceptance. Until the decision and fresh evidence are durable, no seventh production service or materialization path is authorized and C02 cannot claim the PostgreSQL provisioner path complete.

## Alternatives considered

### Reuse ordinary B03 `postgres-provision`

Rejected. That existing upstream-image service owns local prerequisite provisioning and its established B03 receipt/lifecycle. Overloading or remapping it would mix probe-only create/drop authority with ordinary bring-up and could regress an already accepted path.

### Keep an upstream PostgreSQL image and send `psql` or shell commands

Rejected. It would leave command construction and administrative behavior outside a closed, attestable executable contract, make strict receipt semantics difficult to enforce, and retain a broad client/tool surface where C02 needs only three fixed actions.

### Deliver the administrative passfile to Central or the backup worker

Rejected. The coordinator only needs to select a closed action and consume a safe receipt; the dump worker needs only its scoped read credential. Giving either process server-admin material would unnecessarily widen the most sensitive PostgreSQL authority and make worker compromise materially more damaging.

### Keep one provisioner alive across create, dump, and drop

Rejected. It would retain the administrative credential and database session while an unprivileged tool runs, complicate reaping and crash recovery, and conflict with the accepted create/load-session-close, dump-reap, and independent-drop ordering.

### Reuse the previously accepted `central-local-infra` candidate and evidence

Rejected. Adding PostgreSQL client code, a new privileged credential mount, a networked database mode, and a new protocol changes the candidate's attack surface and OCI contents. Acceptance evidence for the smaller mode census cannot establish these new properties.

## Follow-ups

- **Central maintainer, due 2026-08-17:** accept or reject this proposal and resolve its replacement-amendment relationships against ADR 0011, ADR 0008, and ADR 0012 before production work crosses the blocking point.
- **C02 and local-infrastructure owners, after acceptance:** align the detailed C02, secret-reference, and local-infrastructure specifications, including exact canonical request/receipt schemas, retry/idempotency rules, fixed passfile source lifecycle, and compatibility of all six pre-existing service contracts. Those documents are not changed by this proposal.
- **`central-local-infra` delivery owner, after acceptance:** implement the fourth mode and produce a fresh immutable candidate plus complete independent SB-G2 delivery and denial evidence.
- **Central composition and helper owners, after acceptance and candidate PASS:** add only `postgres-throughput-provision`, its inventory entry, fixed UID/network/mount policy, operation-bound `postgres_server_admin_v1` materialization, three one-shot coordinator calls, and clean-host create/verify/dump/drop/crash/expiry/cleanup tests.
- On acceptance, update ADR 0011, ADR 0008, ADR 0012, and every affected index relationship atomically as ADR governance requires. No decided record is modified while this proposal remains Proposed.
- External image prototypes, fixture generators, protocol parsers, and coordinator interfaces may be developed while Proposed, provided they do not alter production Compose/image inventory/mount wiring or make production/acceptance claims.

## References

- [ADR 0012 — Extend root credential mount and add minio-provision mode](0012-extend-root-credential-mount-and-add-minio-provision-mode.md)
- [ADR 0011 — Amend local topology for dedicated migration operator](0011-amend-local-topology-for-dedicated-migration-operator.md)
- [ADR 0008 — Adopt capability-owned Go application boundaries](0008-adopt-capability-owned-go-application-boundaries.md)
- [Slice C required recovery design](../internal/superpowers/specs/2026-08-09-slice-c-required-recovery-design.md)
- [central-local-infra design](../internal/superpowers/specs/2026-08-05-central-local-infra-design.md)
- [Local backup and restore](../operations/local-backup-and-restore.md)
- [Central Local Infra Delivery Requirements](../operations/central-local-infra-delivery-requirements.md)
- [ADR governance and index](README.md)
