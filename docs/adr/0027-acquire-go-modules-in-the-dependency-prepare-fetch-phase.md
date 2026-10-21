# ADR 0027: Acquire Go modules in the dependency-prepare fetch phase

- **Number:** 0027
- **Title:** Acquire Go modules in the dependency-prepare fetch phase
- **Status:** Accepted
- **Created:** 2026-08-20
- **Owners:** Central maintainer
- **Decision due:** None set
- **Decision due history:** None
- **Implementation blocked at:** Nothing further. This ADR authorizes the
  recipe correction, the fetch-phase module acquisition, and the two lock edits
  it names — the `fetch_capability.gomodules` entry and the recomputed
  `recipe_digest` — and nothing wider. In particular it does **not** authorize
  network in the build step, any further allowlist host, or any change to the
  two-builder comparison, the attestation, or settlement.
- **Decided by:** hieuntg81 (Central maintainer and ADR owner, 2026-08-20)
- **Decision date:** 2026-08-20
- **Decision record:** Git status-transition commit
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** The B02 hermetic build contract as shipped
- **Amended by:** None
- **Related:** ADR 0020 §1 (lock governance); ADR 0024 (the `minio` mode
  identity this unblocks); `docs/internal/tasks/sc-def-09-minio-recipe-cannot-build.md`

## Context

The shipped MinIO build recipe cannot produce an image. This was invisible
until 2026-08-20 because `internal/adapter/dependencyprepare/buildkit_linux.go`
was a fake until that day: nothing had ever executed the recipe, so nothing
could discover that it does not describe a runnable build.

The first real `central local prepare` — reachable only after SC-DEF-08 —
surfaced **three** independent defects, each masking the next. All three were
measured on the Slice C VM against the staged source, not reasoned about:

1. **The pinned toolchain cannot parse the pinned source.** The recipe pins
   `go_version: "1.22"`; the pinned commit's `go.mod` declares `go 1.24.0` and
   uses a `tool (...)` block, which is Go 1.24 syntax:
   `go.mod:8: unknown block type: tool`. The source's own `toolchain go1.24.8`
   line cannot rescue this, because the build step has no network to fetch a
   toolchain with.

2. **The build step has no network and the source vendors nothing.** With the
   Go version corrected the parse error disappears and every dependency fails
   to resolve: `golang.org/x/crypto@v0.37.0: ... network is unreachable`, and so
   on for the whole module graph. The pinned MinIO source has no `vendor/`
   directory. No Go version fixes this.

3. **`build.target` cannot produce one binary.** With modules available the
   build reaches the compiler and stops at
   `go: cannot write multiple packages to non-directory /out-app` — the recipe
   pairs `target: "./..."` with `-o /out/app`, and `./...` covers more than one
   main package. MinIO's binary is the module root.

Defect 2 is the one that needs a decision; 1 and 3 are settled by measurement.

## Decision

Move Go module acquisition into the **fetch phase**, and leave the build step
`--network=none`.

The fetch phase is the right home for it: it already has network, it already
runs under `fetch_capability` (host allowlist, address policy, TLS policy, byte
ceiling, deadline), and it is already the phase that retrieves and verifies
third-party bytes against a pinned digest. `StageSource` already exists to place
verified material into the build context; the module cache is more of exactly
that.

Concretely:

- The fetcher populates a module cache during fetch and stages it alongside the
  source. The build step mounts it and stays `--network=none`.
- A new lock entry `fetch_capability.gomodules` admits **`proxy.golang.org`
  only**, `https`, port 443, `address_policy: public-unicast`,
  `tls_policy: system-roots`, with `max_bytes` set from the measured cache size
  (1,119,744,196 bytes for MinIO; the entry is set to 2 GiB to leave headroom
  without being unbounded).
- `GOPROXY` is pinned to that single host. **`direct` is not permitted** — it
  would let the module graph reach arbitrary hosts and would make the allowlist
  meaningless.
- `GOSUMDB=off`, with integrity resting on the source's own `go.sum`.
- The recipe's `go_version` becomes `1.24` and its `target` becomes `.`.

### Why `GOSUMDB=off` is the stronger option here, not the weaker one

It reads like a downgrade and is not. The checksum database is a second network
host (`sum.golang.org`) and a second trust root. The alternative it would guard
against — a module whose hash is not already pinned — cannot arise here: the
source archive is itself verified against `archive_sha256` from the lock before
anything is staged, and `go.sum` is inside that archive. So every module hash is
transitively pinned by a digest the lock already carries, and `go build` fails
closed on any mismatch.

Allowing `sum.golang.org` would add a host to the allowlist to re-derive
assurance the lock already provides. Turning it off keeps the allowlist to one
host and keeps the trust anchored in the lock.

## What this does not authorize

- **It does not permit network in the build step.** `buildkit_linux.go:78`
  refuses `NetworkAfterImport` with `ErrBuilderIsolation: network after import
  is not allowed`, and that refusal stands unchanged. That was the rejected
  option: it is the smallest diff and it buys a passing build by deleting a
  stated isolation guarantee.
- It does not authorize any other new `fetch_capability` host.
- It does not authorize `GOFLAGS`, `GOPRIVATE`, or any other module-resolution
  escape that could reach a host outside the entry.
- It does not change the two-builder comparison, the attestation, or the
  settlement path.

## Consequences

- `dependency-lock.json` gains one `fetch_capability` entry and a recomputed
  `recipe_digest`. Both are lock edits and both are why this is an ADR.
- Prepare acquires roughly 1.1 GB over the network for MinIO on a cold host,
  once, in a phase that is already the network phase. Disk and time cost land
  there rather than in the build.
- The hermetic property is preserved end to end and is now, for the first time,
  actually exercised: measured on the VM, `go mod download` populated the cache
  and the subsequent `--network=none` build of MinIO completed in 101 seconds
  with exit 0.

## Evidence

All figures from the Slice C VM, 2026-08-20, against the staged context of
operation `prepare-1787235520945245191-minio`:

| step | result |
|---|---|
| `go mod download`, `GOSUMDB=off`, proxy only | exit 0 |
| resulting module cache | 1,119,744,196 bytes |
| `go build -o /out/app ./...` offline | fails: multiple packages |
| `go build -o /out/app .` offline, cache mounted, `--network=none` | **exit 0**, 101s |
| whole module cache | 1,119,744,196 bytes, 34,804 files |
| download cache alone (`cache/download`) | 234,332,933 bytes, 1,920 files |
| offline build from the download cache alone | **exit 0** |

Only `cache/download` is staged into the build context. Go reconstructs the
extracted tree from the zips, so the build wants nothing more, and the context
BuildKit transfers — once per builder, twice per prepare, inside one pipeline
deadline — is a fifth of the bytes and an eighteenth of the files. Both shapes
were built offline to exit 0 before the narrower one was chosen.

## What is enforced by Central, and what is not

Stated plainly, because the capability entry looks like it promises more than
the implementation can deliver and a reader should not have to discover that.

`go mod download` runs inside the pinned toolchain image and does its own
networking, so Central's own dialer — the one that enforces the address policy
for archive fetches — is not in the path.

| capability field | enforced by |
|---|---|
| `host`, `scheme`, `port`, `path_prefix` | Central, via a `GOPROXY` built from the entry with **no `direct` fallback**, so no other endpoint is reachable |
| `max_bytes` | Central, measured after the download; an over-ceiling cache is deleted rather than left for a later run to reuse |
| `deadline_ms` | Central, as the context timeout on the acquisition |
| `tls_policy` | the Go toolchain's own verification against the image's system roots — *not* Central's dialer |
| `address_policy` | **nothing.** Central does not resolve or dial here, so `public-unicast` is not checked on this path |

The two unenforced rows are worth their honesty: with `GOPROXY` pinned to a
single host and no fallback, the endpoint is fixed regardless, so what the
address policy would add is a defence against that host resolving to a private
address. That gap is recorded here rather than papered over, and closing it
would mean resolving and pinning the address before handing the toolchain a
proxy URL.
