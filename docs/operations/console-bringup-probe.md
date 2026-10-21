# Attended bring-up probe at the physical console

A runbook for answering the `central local up` ceremony yourself on the
`ubuntu-sc-g1` VM, and for reading the result honestly.

Two automated bring-up attempts on 2026-08-20 cleared every machine-side
blocker and stopped exactly here, at the PAM authentication and physical-TTY
confirmation. That refusal is the control working, not a defect: the ceremony
exists to establish that a human is present at a real console, and an agent
answering it would certify the opposite of what the record would claim.

## Read this before you start: what this run can and cannot establish

**It is a probe, not acceptance evidence.** Two independent reasons, and each
is sufficient on its own:

1. **The delivery has no independent verdict.** The `central-local-infra` build
   this exercises (`6984351`, manifest `sha256:22c32c81…`) passed its own
   clean-host acceptance — 37/37 scenarios, 7/7 prerequisites, two builders
   byte-identical — but no independent reviewer has signed it. ADR 0020 §1
   permits updating the lock's mode inventories only from an **accepted**
   delivery, which is why the shipped lock still pins the older digests.
2. **SC-G1 needs an independent verdict of its own**, from someone outside the
   implementation lineage, bound to an immutable candidate and a conforming
   `central.slice-c-acceptance/v1` manifest.

So nothing you learn here changes any packet's status. What it does give you is
the answer to a question no test can reach: **does the chain work past the
ceremony, on a real host, with a real human?** Every phase after the
confirmation has never once been executed.

**Expect it to stop again, further along.** With the shipped lock, `fs-init`
will run the *older* delivery image, whose fs-init still `Fstat`s an inherited
descriptor that `docker compose run` never passes — the defect ADR 0025 Option B
fixes in the newer image. See "Optional: exercise the new fs-init path" below if
you want to get past that too.

## The prerequisites, already true on `ubuntu-sc-g1`

Root, Docker with the containerd image store, `pg_dump` 16.14,
`/etc/pam.d/central-helper` (`pam_unix.so` in all four groups), and the delivery
image loaded and tagged `central-local-infra:6984351`. If you are on a different
host, check those first.

## 1. Open the console — and it must be this one

VirtualBox Manager → select `ubuntu-sc-g1` → **Show**. Log in as `ubuntu`.

**Not SSH.** `openPhysicalTTY` reads the calling process's own
`/proc/<pid>/fd/0`, requires it to begin `/dev/tty`, and explicitly rejects
`/dev/pts/*`. An SSH session is a pty, so it is refused by construction — which
is precisely why no agent can stand in for you here.

## 2. Run the setup

```bash
cd ~/central
sudo ./scripts/console-bringup-probe.sh
```

It builds the binary with `CGO_ENABLED=1 -tags=pam` (both load-bearing — without
them the helper compiles the stub confirmer, which refuses instead of
prompting), installs a production-shaped instance through the C06 harness,
starts the broker and helper under socket activation, and verifies that
`central local status` answers. It stops there and hands back to you.

If `status` fails, the ceremony is not the problem — read `/tmp/helper.log`.

## 3. Answer the ceremony

At the same console:

```bash
central local up
```

You will be asked for the operator account's PAM password, and then shown:

```
Central privileged action. Type "CONFIRM <operation-id>" to continue:
```

Type that line back exactly, including the operation id it prints, and press
Enter. The id is minted inside the command at run time, so it cannot be
prepared in advance — a present human, not a script, authorises the action.

## 4. Record what happened

Whatever the outcome, capture it — a photo of the console is fine. Useful to
note:

- whether the PAM prompt appeared at all (if not, the ceremony never started —
  most likely the binary lacks `-tags=pam`, or the console is not a real tty);
- whether the confirmation was accepted;
- what the **next** failure was, with its reason code. That is the real product
  of this run: the first look at any phase past the ceremony.

## Optional: exercise the new fs-init path

To get past the older image's fs-init defect, point the lock's four external
modes at the new delivery before running the setup:

- index `sha256:213b45103c2f5208120529e9ebf25563a99aaf9e5c3bf902c008750c03a00b11`
- manifest `sha256:22c32c81f7535b2eecb2645721f6e9a47426ad54b5b92f00ae7f530c1dd25b23`
- config `sha256:075540ca7822fff9c764a2373930c77bd221abb90b415e12254185f0c2b83213`

in `internal/dependencyprepare/assets/dependency-lock.json` (leave the two
postgres modes alone — they point at the upstream postgres image, correctly).

**Revert it afterwards and do not commit it.** A lock edited by hand is a probe
fixture; committing it would put an unreviewed delivery into the trust anchor,
which is the "candidate presented as accepted" failure this repository has
already had to withdraw a record over.

## What you must not do, and why it is worth saying

Do not have anything type the confirmation for you — not a script, not an
agent, not `VBoxManage controlvm ... keyboardputstring`, not a serial device
wired to a host-readable pipe. The runbook for Slice C is explicit that faking
this "produces a false certification, not an accepted Slice C", and SC-G0's
acceptance record was withdrawn on 2026-08-17 for recording a claim nothing
supported.

This VM was built so its console is reachable only by you: its serial port is
deliberately left `disconnected`, and the only way in is the VirtualBox display
window. That property is what makes your answer here mean something.

## After this

Two things still need a second person, and neither is code:

- **An independent verdict for the delivery** `22c32c81…`, from an identity
  that is not `hieuntg81` and not an agent. Only then may the lock be updated
  from it under ADR 0020 §1.
- **The SC-G1 verdict itself**, on the same independence rule that had SC-G0's
  earlier record withdrawn.

## References

- `scripts/console-bringup-probe.sh` — the setup this runbook drives.
- `docs/operations/slice-c-maintainer-tasks.md` — Task B, the acceptance-run
  shape this probe rehearses.
- `docs/adr/0023-…` — why this VM's console is isolated from the agent.
- `docs/adr/0025-…` — the fs-init attestation the newer delivery image carries.
- `internal/adapter/authority/helper/pam_linux.go` — `openPhysicalTTY`,
  `PerformTTYCeremony`, and the prompt text quoted above.

## Step 0 — `central local prepare` must have run at least once

Added 2026-08-20, after the first bring-up that got past the ceremony reached
admission and was refused there.

`central local up` cannot pass admission on a host where no prepare has ever
run. Admission re-inspects the active B02 receipt and requires every mode in it
to resolve to an image present locally. A host that has only ever been
provisioned carries the *version-zero* receipt, which inherits its mode
identities from the shipped lock — and the lock's `minio` mode is
`central-minio@sha256:5e4a6ac5…`, a placeholder that corresponds to no image
that exists anywhere. It is not loadable, because there is nothing to load. Only
a real prepare replaces it, by writing the identity of the MinIO image it
actually builds.

Observed, from the diagnostic build:

```
ADMISSION_FAILED: lifecycle admission: B02 receipt reinspection:
  receipt inspector: mode postgres-fs-init is unavailable locally
```

The mode named in that message is whichever one the inspector reaches first; the
`minio` placeholder is behind it and cannot be resolved by any host-side action.

So the order is **prepare, then up** — on every fresh host, once.

`central local prepare` is itself a privileged operation and runs the same
PAM/TTY ceremony as `up` (`internal/adapter/authority/helper/prepare.go:404`),
so it must be answered at the physical console too. It is not a quick command:
it runs the hermetic two-builder BuildKit build for real.

Prerequisites, all confirmed present on the Slice C VM on 2026-08-20:
`buildctl`, `buildkitd`, `docker`, network egress, and free disk (17G).

It also needs the attestation signing key at
`/root/.local/state/central/dev-trust/dependency-attestation-key.json`
(override: `CENTRAL_DEPENDENCY_ATTESTATION_KEY`). Without it the helper does not
merely disable prepare — it refuses to start at all:

```
helper: dependency prepare is unavailable on this host: prepare handler:
  factory: attestation signing key (...): open attestation signing key:
  no such file or directory
```

The key must be the pair whose public half the lock pins under
`attestation_trust`. ADR 0020 §1 governs mode inventories: those are updated
only from an accepted external delivery, never by hand. The trust anchor
itself is different — it is maintainer-issued key material, not a delivered
artifact — and ADR 0030 governs it: a rotation is authorized by its own ADR,
generated with `central attest keygen --key-id ID --out PATH` (root; never
overwrites an existing file), and the printed `key_id`/`public_key` pair is
what goes into `attestation_trust.keys` in the lock. The private half is a
deployment secret: hold it outside every repository, at the path
`AttestationKeyPath()` resolves (override: `CENTRAL_DEPENDENCY_ATTESTATION_KEY`),
and keep a second copy somewhere that survives the loss of any one machine —
ADR 0030 exists because the original dev-local key had no such second copy.

### What `central local prepare` will do, and how long to give it

Added after ADR 0027, so the run is not abandoned halfway on a guess.

It is not a quick command and it is not silent. Expect, in order: a PAM password
prompt, the `CONFIRM <operation-id>` phrase, a ~45s module download, then **two**
hermetic builds of MinIO — the two-builder comparison is the point of B02, so the
whole build happens twice.

Rough shape on the Slice C VM: the MinIO build alone measured 101s per builder,
plus a build-context transfer per builder, plus the OCI export and comparison.
Budget something in the region of ten minutes and do not close the console.

The pipeline deadline is 20 minutes from the operation's creation. That should
be enough and is not enormously more than enough; if a run ever ends on a
deadline rather than a failure, that ceiling is the first thing to look at, not
the build.

Disk: the module cache is about 1.1 GB under
`<state>/dependency-prepare/fetches/gomodcache/`, of which 234 MB is hardlinked
into each build context. It is acquired once and reused, so a second prepare on
the same host does not re-download it.

Progress is written to the helper's log as `prepare.progress` events with a
phase and counters. If a run fails, the operator's line carries only a reason
code; the full text — including the entire builder output — is in
`<state>/dependency-prepare/journal/<operation-id>.json`. Read that, not the
console line.
