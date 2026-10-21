# Slice C — tasks that require you (maintainer / human)

This is the runbook for the parts of Slice C acceptance that an agent cannot
do, by design. Everything code-side is done, merged, and pushed; what remains
is exactly two kinds of human act, and they are the substance of what
"accepted" certifies:

1. an **independent verdict** — a judgement by someone who did **not** author
   the candidate code (governance §5.2–§5.3); and
2. **physical-console consent** — a person present at a real console approving
   each irreversible recovery operation (ADR 0015/0016, spec A03).

Neither can be automated away without turning "accepted" into a false record —
the exact failure this repository withdrew from SC-G0 on 2026-08-17.

> **Amended 2026-09-10.** Governance §5 (upstream `central` record: `docs/internal/superpowers/specs/2026-08-14-slice-c-acceptance-governance.md`)
> was amended: this repository's independent human reviewer is no longer
> active, and the maintainer (`hieuntg81`) is now its sole contributor. From
> SC-G1 onward, item 1 above no longer applies as written — an AI agent,
> including the same session that authored the candidate, may issue a
> verdict on its own work, recorded as **Accepted (self-issued)** rather
> than plain **Accepted**. Task A below predates the amendment and is
> unaffected (SC-G0 already has a genuinely independent verdict). Item 2
> (physical-console consent) is untouched by this amendment; Tasks B–D's
> console requirement, and their unattended-grant alternative, stand as
> written.

> **Status at a glance (2026-08-18):** 0 of 4 Slice C gates passed.
> Code + evidence for SC-G0 are archived in-tree; SC-G0 needs only its
> verdict. SC-G1–SC-G3 need real recovery runs with console consent, then a
> verdict each. Already done and on `origin/main` (central `b9b949b`,
> central-local-infra `5d5fbdd`): ADR 0019/0020 implemented and proven live,
> the SC-G0 re-run and its evidence, and all review fixes. **You do not need
> to merge or push anything.**

> **Rehearsal update (2026-09-09):** a dev-admission rehearsal against a
> maintainer-provisioned VM (`ceremony_mode: grant`, **not** a physical
> console — this is not SC-G1/SC-G2/SC-G3 evidence and issues no verdict)
> drove `restore verify → apply` end to end for the first time and reached
> `phase=ready, checkpoint=authority_reset`. Exactly as the note under Task B
> below predicted, the run surfaced product defects — eight of them,
> `docs/internal/tasks/sc-def-59-*.md` through `docs/internal/tasks/sc-def-65-*.md`, spanning apply's
> ticket resolver, `pg_restore --clean` vs. the SC-DEF-52-excluded table,
> post-restore runtime grants, the audit/C05 write path's database role,
> that path's broker credential window, and the missing MinIO-restore
> credential and bootstrap-registrations-table recreation `VerifyInventory`
> and C05 need — all found and fixed. One item, `docs/internal/tasks/sc-def-66-*.md`, is
> recorded but unconfirmed: a single 2-hour hang immediately after the first
> MinIO broker-rendezvous hardlink was created, not reproduced on retry.
> **This means Task B/C/D's real acceptance runs are now rehearsing against
> a chain that has actually completed once**, not a dormant one — worth
> knowing before you schedule console time.

---

## Task A — Issue the SC-G0 independent verdict  ★ do this first

**Needs:** a person who is **not** the candidate author, and a terminal in a
clone of this repo. **No root, no Docker, no hardware.** ~15 minutes.

**Who may sign.** The candidate commits were authored by
`34208688+hieuntg81@users.noreply.github.com`. Governance §5 requires the reviewer identity to differ.
The SB-G2/SB-G3 precedent used `34208688+hieuntg81@users.noreply.github.com`. **You (hieuntg81) cannot be
the SC-G0 reviewer** — it must be a second person / identity, and the verdict
commit must be authored under that identity.

Do these steps in order. Copy-paste each block.

### A1. Get a clean, current checkout

```bash
cd ~/code/central
git checkout main && git pull
```

### A2. Run the one verification command and read the result

```bash
./scripts/verify-sc-g0-evidence.sh
```

Every line should read `PASS`, ending with `mechanical checks: 13 passed, 0
failed`. It also prints, as `INFO`, the candidate author
(`34208688+hieuntg81@users.noreply.github.com`) — **confirm that is not your identity.** If any line
reads `FAIL`, stop and tell the agent; do not sign.

### A3. Read the report and make exactly three decisions

Open the review report:

```bash
less docs/internal/superpowers/reviews/2026-08-17-sc-g0-review-report.md
```

The mechanical checks are done (A2). Only three things need *your judgement* —
find them under "the three load-bearing findings" and decide **ACCEPT** or
**BLOCK** for each:

- **F1** — the bound manifest was committed one commit *after* its evidence
  commit. This is structurally forced (the manifest carries the evidence
  commit's own hash, so it cannot be inside it). Accept, or block?
- **F2** — the archived compose fixtures reference container images by mutable
  tag; their tag→digest resolution appears only in the manifest, not in an
  archived log. Accept, or block?
- **F3** — the external delivery's own acceptance (in `central-local-infra`)
  is a *maintainer decision*, not an independent review, and it binds an older
  commit (`3e716a2`) than the emitter the SC-G0 run built. A strict reading of
  governance §6.3 (the external delivery must carry its **own** independently
  reviewed SB-G2-style acceptance) may fail here. Accept, or block?

If you **BLOCK** any of them → skip to "If a finding is rejected" below.

### A4. Write the verdict (only if you accepted all three)

Start from the prepared skeleton and fill it in:

```bash
git mv docs/internal/superpowers/reviews/2026-08-17-sc-g0-acceptance.SKELETON.md \
       docs/internal/superpowers/reviews/2026-08-17-sc-g0-acceptance.md
$EDITOR docs/internal/superpowers/reviews/2026-08-17-sc-g0-acceptance.md
```

In that file, make exactly these edits:
1. Delete the top "REVIEWER SKELETON (NOT A VERDICT)" banner block.
2. Set `Status: Accepted`.
3. Set `Reviewer identity:` to your identity (e.g. `34208688+hieuntg81@users.noreply.github.com`) and
   confirm in one line that you re-derived the candidate author from the
   immutable commit and it differs from yours.
4. Under each of F1/F2/F3 write `Ruling: ACCEPT` with a one-line reason.
5. In the final "Verdict" section write: **Accepted**, bound to candidate
   `2ce2c3c` and manifest SHA-256
   `2a00163af0d82a1af9a2b5c9b16ebf49199165a280b71cbf72f3d022aa9dc69e`.

Commit it **under the reviewer identity** (substitute the real name):

```bash
git -c user.email=34208688+hieuntg81@users.noreply.github.com -c user.name="Independent Reviewer" \
    commit -am "review: SC-G0 accepted (independent verdict) bound to 2ce2c3c / manifest 2a00163a"
```

### A5. Flip the status surfaces — the agent does this for you

The verdict and the status change must be **separate commits** (§5.1). Once
A4 is committed, tell the agent: *"the SC-G0 verdict is committed, prepare the
status-flip commit."* The agent will update the five surfaces
(`docs/product/roadmap.md`, `docs/implementation/current-phase.md`,
`docs/implementation/phase-1-vertical-slice-backlog.md`, `docs/README.md`,
`docs/prototypes/roadmap-status.html`) from "SC-G0 open" to "SC-G0 Accepted"
and hand it back for your push. **SC-G0 is passed at that point.**

### If a finding is rejected

SC-G0 stays open. The usual cause is F3 (the external delivery needs its own
independent SB-G2-style review). Tell the agent what you rejected and why; it
will drive the fix and re-run the SC-G0 pipeline
(`/var/tmp/scg0-acceptance/run-scg0.sh`), then hand you a fresh skeleton to
review again.

---

## Task B — SC-G1 acceptance run (C01 backup, C02 admission)

**Prerequisite:** Task A verdict committed (SC-G1 names SC-G0 as its
prerequisite, rule E-11). Do not start Task B until SC-G0 is accepted.

Your side of Task B is small: **provide a suitable host, then type one
confirmation phrase when prompted.** The agent does everything else.

**Unattended alternative (ADR 0028).** If the instance is installed with
`central grant mode grant` (root, once), B1's console requirement and B3's
typed confirmation are replaced by a root-issued, one-use grant naming the
exact operation: `central grant issue --kind restore_apply --operation <id>`
(kinds: `lifecycle`, `prepare`, `migration_reset`, `restore_apply`,
`restore_abandon`; `--ttl` defaults to 1h, max 24h). The helper spends the
grant instead of prompting. Everything else in Tasks B–D is unchanged, and
the resulting gate is recorded as **Accepted (unattended profile)** — field
16 records `ceremony_mode: grant`, field 21 carries the grant consumption
records from `central grant list`, and the run must never claim a physical
TTY. The rest of this section describes the `physical_tty` default.

**B1 gates only B3.** If you don't have a qualifying host yet, that blocks
only B3 — the single console confirmation. Developing or debugging B2's
automation (build, install, bring-up, `central backup create`, evidence
archival) and B4's manifest/skeleton preparation needs no physical console at
all; iterate on that against any `testdata/*-reference-host` compose fixture
on any host, same as ordinary development. See ADR 0023 if you have no
qualifying host and want options, including a locally-run VM whose console
only you can reach (no cost beyond hardware you likely already own).

### B1. Check the host is ready (copy-paste; all must say OK)

```bash
[ "$(id -u)" = 0 ] && echo "OK root" || echo "MISSING: must run as root"
command -v docker >/dev/null && docker version --format '{{.Server.Version}}' >/dev/null 2>&1 && echo "OK docker" || echo "MISSING: docker"
docker compose version >/dev/null 2>&1 && echo "OK compose" || echo "MISSING: docker compose"
[ -f /etc/pam.d/central-helper ] && echo "OK pam" || echo "MISSING: /etc/pam.d/central-helper"
[ -c /dev/ttyS4 ] && echo "OK console /dev/ttyS4" || echo "MISSING: a real physical console (serial /dev/ttyS*)"
```

`/etc/pam.d/central-helper` should be `pam_unix.so` in all four groups
(`auth account password session`). The console must be a **real** serial/vt
device — a pty (`/dev/pts/*`) is rejected by design.

**The console line above is hardcoded to `/dev/ttyS4`; treat that as an
example, not a portable check.** Two traps found while provisioning an
Option C (ADR 0023) VM host:

- **A device node existing doesn't mean it's backed by anything.** Linux
  pre-creates `/dev/ttyS0`–`/dev/ttyS31`-ish nodes for the 8250 driver's
  address range regardless of whether real hardware answers at that port.
  `[ -c /dev/ttyS4 ]` can print `OK` on a device nobody could ever type
  into. Confirm the port was actually probed before trusting it:
  `dmesg | grep -i ttyS` — only a port that shows up there (e.g.
  `ttyS0 at I/O 0x3f8 ... is a 16550A`) is real, and even then it still
  needs something wired to the far end to receive input.
- **On a VM host, the qualifying console is usually `/dev/tty1`, not a
  serial device.** The channel the maintainer reaches through the
  hypervisor's own display/console window (e.g. VirtualBox Manager → *Show*)
  is the guest's framebuffer console, `/dev/tty1` — that's what
  `openPhysicalTTY` sees when you type there, and it needs no serial port
  configuration at all. Only wire up a virtual serial port if you
  specifically want to use one instead, and if you do, confirm with `dmesg`
  as above that it's real before relying on it.

### B2. Tell the agent to start the run

Say: *"start the SC-G1 acceptance run."* The agent installs the
production-shaped instance, brings up the real broker daemon + PostgreSQL +
MinIO, and drives `central backup create` through the real helper.

### B3. Your one action — approve at the console

When the ceremony reaches the destructive step, **your physical console
(`/dev/ttyS4`) prints**:

```
Central privileged action. Type "CONFIRM <operation-id>" to continue:
```

Type exactly that line (the agent will also echo the exact phrase to you) and
press Enter. The operation id is minted inside the command at run time, so it
cannot be pre-filled — a present human, not a script, authorises the
irreversible action. That is the whole guarantee.

### B4. The agent finishes and hands off

After your consent the agent archives the evidence and emits
`slice-c-backup-creation.json` and `slice-c-capacity-admission.json`, then
prepares the SC-G1 evidence + skeleton the way SC-G0 was prepared. An
independent reviewer then issues the SC-G1 verdict (Task A shape, bound to
C01+C02), and the agent prepares the status-flip commit.

> Expect the first real end-to-end run to surface product defects — every
> prior first-live Slice C run did, and finding them is the run doing its job.
> The agent fixes what it can and reports what needs you.

---

## Task C — SC-G2 (C03/C04/C05)

Same shape as Task B, larger: the full `verify → apply → resume` recovery
sequence with a restart injected at every durable boundary. Each
destructive step (`restore apply`, `resume`, `abandon`) prompts its own
console confirmation — **you at `/dev/ttyS4` again** — and the gate ends
with a verdict. It runs only after SC-G1 is accepted.

---

## Task D — SC-G3 (C06) physical-console run

> **Status (2026-10-05):** SC-G3 is already **Accepted (Docker profile)
> (self-issued)** — see Task E. This task is the physical track that
> upgrades that verdict to plain **Accepted**. The historical blocker
> (SC-DEF-72, `restore resume` dead after a postgres password rotation)
> is fixed at `f751f5e`. Nothing about this run has been automated away;
> it needs you at the console.

Same C06 scope as the Docker profile, different evidence profile: the
continuous `backup → corruption → verify → apply/resume → quarantine
resolution → authority reset → fresh bootstrap` demonstration on a real
reference host, with console consent for every destructive step.

### D1. Host prerequisites (copy-paste check; every line must say OK)

A fresh Ubuntu 24.04 amd64 VM (the `ubuntu-sc-g1` reference host or a new
one):

```bash
[ -c /dev/tty1 ] && echo "OK physical console" || echo "MISSING: need real /dev/tty1"
passwd -S root | grep -q ' P ' && echo "OK root has a PAM password" || echo "MISSING: unlock/set root password (pam_unix authenticates the in-process operator)"
id -u c06op >/dev/null 2>&1 && echo "OK operator account" || echo "MISSING: useradd c06op (child-process ceremonies run as uid 1001)"
dpkg-query -W postgresql-client-16 | grep -q 16.14 && echo "OK pg tools 16.14" || echo "MISSING: pin via PGDG — apt-get install postgresql-client-16=16.14-1.pgdg24.04+1 (the suite hard-rejects anything but 16.14)"
docker image inspect minio/minio:RELEASE.2025-04-22T22-12-26Z >/dev/null 2>&1 && echo "OK MinIO image" || echo "MISSING: docker pull quay.io/minio/minio:RELEASE.2025-04-22T22-12-26Z && docker tag quay.io/minio/minio:RELEASE.2025-04-22T22-12-26Z minio/minio:RELEASE.2025-04-22T22-12-26Z (Docker Hub no longer serves the pinned tag)"
```

### D2. The one non-obvious requirement: fd 0 on the console

Scenario 1's `central backup create` is dispatched **in-process**, so the
ceremony reads the *test process's* fd 0 — over SSH that is a pipe and
`openPhysicalTTY` refuses it. Compile the suite and run it with stdin on
the physical console:

```bash
go test -c -tags pam -o c06.test ./cmd/central/
# on the VM's physical console (Ctrl-Alt-F1), as root:
./c06.test -test.v -test.run 'TestC06' < /dev/tty1
```

`CENTRAL_C06_OPERATOR_UID/GID` point the child-process ceremonies at
`c06op`; the in-process operator is the test process's uid (root), which
is why root needs the PAM password.

### D3. Trust-anchor disclosure (mandatory in the verdict)

The candidate's compiled-in release key is a **VM-generated test
keypair** (`KEY_ID` `central-release-authority/v1`; private half at
`~/.sc-g3-release-key.json`, 0600, VM-only — see
`tasks/sc-g3-release-authority-key-substitution-2026-09-23.md`). Bundles
admitted prove the B01 mechanism end to end, **not** the production trust
anchor. The verdict must carry this limitation next to
`ceremony_mode: physical_tty`.

### D4. Known environment traps (learned 2026-09-13/17, both records in `docs/internal/tasks/`)

- **KVM:** `-enable-kvm -cpu host` can fail `KVM: entry failed, hardware
  error 0x0` on this host (reproduced 3/3). Emulation works but is slow —
  the C02 throughput-gate image build may not finish inside one session.
  Prefer hardware KVM on a healthy host.
- **Fresh instance for the continuous scenario:** `central restore
  verify` refuses `RESTORE_BACKUP_CANDIDATE_AMBIGUOUS` when two sealed
  backups exist. A full pass needs a freshly installed instance with
  exactly one sealed backup — run the corruption cycle on a clean
  genesis, or abandon leftover operations first.

### D5. Post-run hygiene

- `central restore abandon` any operation left open by a failed leg —
  a real `central serve` refuses to start behind `RESTORE_RESUME_REQUIRED`
  while one exists.
- Back up `~/.sc-g3-release-key.json` before destroying the host — it is
  the only copy of the candidate's trust anchor private half.
- Hand the evidence to the verdict issuer; label per governance §5.3a.

---

## Task E — SC-G3 Docker profile (ADR 0031, no console needed)

Same C06 scope as Task D, different evidence profile: the full continuous
sequence runs grant-mode unattended against Docker-provided infrastructure
instead of a reference host, and the verdict is recorded as **Accepted
(Docker profile)** — never plain Accepted. The physical-console track stays
open; a later physical run upgrades the label.

Your side is smaller than Task B: **no console typing at all.** What you do
provide:

1. **A Docker host with a clean port plan.** C06 needs `127.0.0.1:55432`
   (PostgreSQL) and `127.0.0.1:59000` (MinIO) free, plus no volume/name
   collisions with the `central-<instance-id>` composition. Coexisting
   containers are allowed but recorded in the manifest (governance field
   16); stop them during measurement phases if the plan says so.
2. **Root for privileged steps.** Instance install, service users
   (`central_runtime`, `central_migrate`), launcherd units, `/etc/pam.d`
   service file if the plan needs one, and the broker/helper sockets all
   need uid 0. The agent drives them via your approval, or you hand it a
   root shell.
3. **The release-authority private key** (or its custody decision). The
   candidate's compiled-in key must have its private half available to mint
   the advisory envelope — see the key-substitution record for the current
   candidate. Back it up before the host is destroyed.

Everything else — `grant mode grant` once, one-use grant per ceremony,
bring-up, the C06 run, the five evidence artifacts, the manifest, the
self-issued Docker-profile verdict draft — the agent does and hands you for
review. What the run does NOT prove (no human presence, no
systemd/PAM/multi-user/device fidelity) is part of the verdict, not an
appendix.

---

## What the agent will do for you (just ask)

- Prepare the Task-A status-flip commit once the verdict exists.
- Drive every automated part of Tasks B–D: build, install, bring-up, run,
  evidence archival, manifest emission and binding — and hand you the exact
  console prompt to answer.
- Re-run the SC-G0 pipeline if the reviewer rejects a finding.

## What the agent will not do (and why)

- **Write or sign any gate verdict from the implementing session**, or act as
  the independent reviewer there — it is in the implementation lineage;
  self-issuing the verdict is fabrication and is what got SC-G0 withdrawn. An
  agent verdict is admissible only from a context-independent session under
  governance §5.3a (ADR 0028 D2), and it carries the unattended-profile label.
- **Fake or bypass the physical-console consent** — `openPhysicalTTY` refuses a
  pty by design; defeating it defeats the guarantee Slice C exists to build.
  Under `ceremony_mode: grant` there is no console consent to bypass; the
  evidence says so, and must never claim one.
- **Record a `grant`-mode run as a physical-TTY run**, or drop the
  unattended-profile label — that produces a false certification, not an
  accepted Slice C.

## A legitimate alternative, if the controls are genuinely wrong

If you conclude the physical-console ceremony is the wrong control on its
merits (not merely inconvenient), that is a real architectural decision you
own: reconsider it in a new ADR with the trade-offs recorded, and amend the
governance deliberately. The agent will help design and analyse that. Even
then, the independence of the verdict (a reviewer who did not write the code)
is a separate guarantee and cannot be self-issued by the implementer.
