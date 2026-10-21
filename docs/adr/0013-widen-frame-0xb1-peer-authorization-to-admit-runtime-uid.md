# ADR 0013: Widen frame 0xb1 peer authorization to admit Central's runtime UID

- **Number:** 0013
- **Title:** Widen frame 0xb1 peer authorization to admit Central's runtime UID
- **Status:** Accepted
- **Created:** 2026-08-07
- **Owners:** Central maintainer
- **Decision due:** 2026-08-14
- **Implementation blocked at:** SB-G3 plan Task 11a (`internal/adapter/authority/broker/server.go`'s frame `0xb1` peer-credential gate and `internal/secretbootstrap/domain.go`'s `Purpose.ValidateDependency`/`MinioRuntimeUseRequest.Validate()` for `PurposeMinioRuntime`), which declares itself explicitly blocked on this ADR's acceptance in its own plan header ("Blocked on ADR 0013 (Accepted)").
- **Decision due history:** None
- **Decided by:** hieuntg81
- **Decision date:** 2026-08-07
- **Decision record:** Git status-transition commit
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** None
- **Amended by:** None
- **Related:** [ADR 0012 — Extend root credential mount and add minio-provision mode](0012-extend-root-credential-mount-and-add-minio-provision-mode.md), [SB-G3 MinIO Runtime Provisioning Design](../internal/superpowers/specs/2026-08-06-sb-g3-minio-runtime-provisioning-design.md), [SB-G3 MinIO Runtime Provisioning Implementation Plan](../internal/superpowers/plans/2026-08-06-sb-g3-minio-runtime-provisioning.md), [ADR governance](README.md)

## Context

B10's outbound broker transport hands a previously-bound `minio_runtime_v1`
credential to a connecting client over frame `0xb1`. Two independent gates
must both pass before that handoff is authorized, and both were built,
before this task, requiring the connecting peer's UID:GID to be exactly
`1000:1000` — `secretbootstrap.MinioProvisionerUID`/`MinioProvisionerGID`,
the `minio-provision` identity:

1. `internal/adapter/authority/broker/server.go`'s `HandleConn`, on the
   `b10MinioRuntimeFrameMarker` (`0xb1`) branch:
   ```go
   if peerCred.Uid != secretbootstrap.MinioProvisionerUID || peerCred.Gid != secretbootstrap.MinioProvisionerGID {
       writeDeny(conn, req.OperationID, "authority denied")
       return fmt.Errorf("broker: denied B10 minio runtime peer %d:%d", peerCred.Uid, peerCred.Gid)
   }
   ```
   (`internal/adapter/authority/broker/server.go:93`). This is the kernel
   `SO_PEERCRED`-derived check on the actual connecting OS process.

2. `internal/secretbootstrap/domain.go`'s `Purpose.ValidateDependency`, in
   the `PurposeMinioRuntime` case:
   ```go
   case PurposeMinioRuntime:
       if service != "minio-provision" || target != "sealed_memfd" || uid != MinioProvisionerUID || gid != MinioProvisionerGID {
           return fmt.Errorf("%w: minio_runtime_v1 requires the registered minio-provision descriptor peer", ErrCrossServicePurpose)
       }
       return nil
   ```
   (`internal/secretbootstrap/domain.go:102-106`), reached from
   `MinioRuntimeUseRequest.Validate()` (`internal/secretbootstrap/domain.go:144-164`,
   which calls `ValidateDependency` at line 163) and invoked a second time,
   independently of the `SO_PEERCRED` gate, inside
   `handleB10MinioRuntimeTransport`
   (`internal/adapter/authority/broker/service.go:815`) before any credential
   is read or handed off.

Central's own serving process — the intended real consumer of this
transport, since B10's `runtimeArtifactObjectStore()` needs exactly this
delivered credential to construct a real object-storage client — runs under
a different, fixed UID: `runtimeUID = 501` in `cmd/central/main.go`, the
same identity the broker's plain protocol already recognizes as "the
runtime peer" through `isRuntimeOrRootPeer`:
```go
func isRuntimeOrRootPeer(svc *Service, peerCred *unix.Ucred) bool {
    return peerCred.Uid == 0 || peerCred.Uid == uint32(svc.runtimeUID)
}
```
(`internal/adapter/authority/broker/server.go:180-182`), already used to gate
frame `0xb4` (`server.go:69`) and the plain-protocol dispatch path
(`server.go:132`).

No such root-or-`runtimeUID` bypass exists on frame `0xb1`. The result,
discovered while building SB-G3 Task 11's `MinioRuntimeClient`
(`internal/adapter/authority/broker/minio_runtime_client_linux.go`) and
confirmed by two independent reviewers: no single OS process can
simultaneously present `runtimeUID` (the identity Central's serving process
actually runs as) and `MinioProvisionerUID:GID` (the identity both frame
`0xb1` gates hard-require). The transport is correctly built and unit-tested
against the real handler (`minio_runtime_client_linux_test.go`), but it is
structurally unreachable by the only process authorized, by every other
part of this system, to be "the runtime" — a load-bearing caveat the client
file's own doc comment already records
(`internal/adapter/authority/broker/minio_runtime_client_linux.go:44-67`).

This is a pre-existing gap, not one this task's design created: nothing
exercised frame `0xb1`'s consumption path in production before Task 11, so
the gap was latent until the first real client was built against it. Fixing
it is a security/trust-boundary change to a broker peer-authorization gate,
which ADR governance's "when an ADR is required" list names explicitly
(security or trust boundaries; privileged-capability and secret-access
models) and is distinct from ADR 0012's decision, which concerns the root
credential mount and the new `minio-provision` compose mode, not broker peer
authorization on this transport.

Frame `0xb2` (`b10ProvisionedFrameMarker`), Task 8's separate INBOUND path
where `minio-provision` delivers a freshly minted credential into the
broker, has an identically shaped gate at `server.go:103` and is not
affected by this gap: `minio-provision` is a real, non-root, narrowly
scoped process that already runs at `1000:1000` per the B03 compose policy,
so it satisfies its own gate today. That direction's whole point is proving
the credential really came from the real provisioner, not from Central's
own process claiming to be one, so its gate is not a candidate for the same
fix.

## Decision

Widen frame `0xb1`'s two peer-authorization gates — and only frame
`0xb1`'s — to accept either the existing `minio-provision` identity or
Central's own runtime identity, mirroring `isRuntimeOrRootPeer`'s existing
two-branch pattern rather than inventing a new one:

1. In `server.go`'s `HandleConn`, the `0xb1` branch's peer check
   (`server.go:93`) becomes: accept the peer if
   `(peerCred.Uid == secretbootstrap.MinioProvisionerUID && peerCred.Gid == secretbootstrap.MinioProvisionerGID) || peerCred.Uid == uint32(svc.runtimeUID)`.
2. In `domain.go`'s `Purpose.ValidateDependency`, the `PurposeMinioRuntime`
   case (`domain.go:102-106`) is widened identically, so the declared
   `service`/`uid`/`gid` triple it validates accepts either the
   `minio-provision` triple it accepts today or the runtime-UID
   equivalent. Both gates must stay in agreement: they run as independent,
   defense-in-depth checks against the same authorization decision, and if
   only one gate widens, the narrower one becomes the effective (and now
   inconsistent) boundary — the exact failure mode this decision must not
   introduce.

Frame `0xb2` (`server.go:99-113`, the inbound Task 8 path) is explicitly
**not** changed by this decision. Its peer check continues to require the
`minio-provision` identity exactly, with no `runtimeUID` or root
alternative. Central's own process is never an authorized sender of a
freshly minted credential into the broker; only `minio-provision` is.

The exact widened boundary condition — which UID/GID pair(s) frame `0xb1`
accepts — and the corresponding boundary in `domain.go` are the only changes
this decision authorizes. It does not authorize any other broker frame,
transport, or purpose to adopt a similar widening; each such change remains
its own trust-boundary decision under ADR governance.

## Consequences

### Benefits

- Closes the last gap blocking B10's real credential retrieval: with both
  gates widened, Central's own serving process, dialing as `runtimeUID`,
  can complete the frame `0xb1` exchange `MinioRuntimeClient` already
  implements, and `runtimeArtifactObjectStore()` can finally be constructed
  from a real, broker-delivered credential instead of remaining a permanent
  zero-value stub.
- Reuses `isRuntimeOrRootPeer`'s existing, already-tested pattern instead of
  inventing a new authorization shape for this one transport — the same
  two-branch structure already governs frame `0xb4` and the plain protocol,
  so this is a known, reviewed shape applied to one more path, not a new
  kind of check.
- Keeps `handleB10MinioRuntimeTransport`'s real authorization —
  the durable, one-shot binding-consumption check in
  `minioRuntimeBindingStore` described in that function's own doc comment
  (`service.go:796-807`) — unchanged. The peer-credential gates this
  decision widens were already documented as "necessary but weak on their
  own"; the binding consumption, fencing-token, and one-shot-delivery
  invariants that actually bound the handoff are untouched.

### Costs and limitations

- Widens the set of identities that may successfully claim "I am an
  authorized recipient of this transport" from exactly one non-root
  identity (`minio-provision`, `1000:1000`) to two (`minio-provision` or
  `runtimeUID = 501`). This is a real widening of who can complete the
  frame `0xb1` exchange, and it must be weighed as such — but it is a
  narrowing compared to the plain protocol's existing `isRuntimeOrRootPeer`
  pattern (root OR `runtimeUID`, no restriction to a single non-root UID at
  all), so this decision does not set an unusual precedent; it brings one
  transport's peer check in line with a pattern this file already uses
  elsewhere, with a narrower accepted set than that pattern already allows
  (no root bypass is added here).
- The two gates (`server.go` and `domain.go`) must be kept in lockstep by
  construction, not merely by convention: any future change to one without
  the matching change to the other silently reintroduces an inconsistent,
  effective-narrower boundary. Task 11a's own test plan (adding a
  `RuntimeUID`-named test asserting frame `0xb1` accepts `runtimeUID` and a
  companion test asserting frame `0xb2` still rejects it) is the durable
  guard against that regression, not this ADR text alone.
- `MinioRuntimeClient`'s current request construction
  (`minio_runtime_client_linux.go:92-106`) still declares
  `UID: secretbootstrap.MinioProvisionerUID` and
  `GID: secretbootstrap.MinioProvisionerGID` in the payload it sends,
  independent of the actual OS peer UID the socket carries; making that
  declared-identity field agree with the connecting process's real
  `runtimeUID` (so `handleB10MinioRuntimeTransport`'s own
  `use.UID != peerCred.Uid` check at `service.go:827` passes) is
  implementation work this decision authorizes but does not itself
  perform — it is Task 11a's responsibility, not a second trust-boundary
  decision.

## Alternatives considered

### Build a separate delivery channel instead of widening the socket's peer check

Instead of widening frame `0xb1`'s peer authorization, deliver the credential
to Central's runtime through a different mechanism entirely — for example, a
file mount `minio-provision` writes to and Central's serving process reads
from directly, bypassing the broker socket for this one hop. Not selected:
it would require designing, implementing, and independently securing a
second delivery mechanism (mount path validation, ownership, cleanup,
one-shot-consumption semantics equivalent to `minioRuntimeBindingStore`)
duplicating guarantees the existing sealed-descriptor SCM_RIGHTS handoff
already provides and B10's tests already exercise. The existing transport is
correctly built, already unit-tested against the real handler, and the only
defect is which peers it authorizes — reusing it via the same
`isRuntimeOrRootPeer` pattern already established elsewhere in this file
closes the gap with a small, reviewable, already-precedented change, instead
of standing up and re-proving an entirely new credential-delivery mechanism.

## Follow-ups

- SB-G3 plan Task 11a implements the widened gates in `server.go` and
  `domain.go`, adds the `RuntimeUID`-named tests proving frame `0xb1` now
  accepts `runtimeUID` while frame `0xb2` continues to reject it, and
  re-verifies whether `MinioRuntimeClient`'s existing client test can now
  exercise the real runtime-UID path without root. Task 11a may not land
  before this ADR reaches Accepted, per its own plan header.

## References

- [SB-G3 MinIO Runtime Provisioning Implementation Plan — Task 11a](../internal/superpowers/plans/2026-08-06-sb-g3-minio-runtime-provisioning.md)
- [SB-G3 MinIO Runtime Provisioning Design](../internal/superpowers/specs/2026-08-06-sb-g3-minio-runtime-provisioning-design.md)
- [ADR 0012 — Extend root credential mount and add minio-provision mode](0012-extend-root-credential-mount-and-add-minio-provision-mode.md)
- `internal/adapter/authority/broker/server.go` (frame `0xb1`/`0xb2` dispatch, `isRuntimeOrRootPeer`)
- `internal/secretbootstrap/domain.go` (`Purpose.ValidateDependency`, `MinioRuntimeUseRequest.Validate()`)
- `internal/adapter/authority/broker/service.go` (`handleB10MinioRuntimeTransport`, `handleB10MinioProvisionedTransport`)
- `internal/adapter/authority/broker/minio_runtime_client_linux.go` (`MinioRuntimeClient`, the doc comment recording the gap)
