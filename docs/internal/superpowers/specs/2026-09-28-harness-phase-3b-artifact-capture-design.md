# Harness Phase 3b — Artifact Capture Design

- **Date:** 2026-09-28
- **Status:** Draft. Brainstormed with the recommended option taken for each question, per the maintainer's workflow. Revised after the focused spec review (`docs/superpowers/reviews/2026-09-28-harness-phase-3b-spec-review.md`).
- **Governing decisions:**
  - [ADR 0035](../../../adr/0035-freeze-b09-loop-coordinator-and-adopt-harness-session-boundary.md);
  - [ADR 0036](../../../adr/0036-add-a-separate-harness-launcher-for-operator-harness-sessions.md) (Accepted);
  - ADR 0004 (prepare → invoke → persist);
  - ADR 0005 (the Artifact lifecycle, implemented by B10 in `internal/artifact`).
- **Governing spec:** [Harness Adapter Boundary Design](2026-09-27-harness-adapter-boundary-design.md), §10 (workspace and artifacts) and §14 (phase 3).
- **Builds on:** [phase 3a](2026-09-28-harness-phase-3a-serve-wiring-design.md). 3a runs a submitted Task as one Claude Code attempt in a Central-owned per-Run clone. It declares no artifacts and defers them here (§1, §11 "Constraint carried to 3b").

## 1. Goal

A harness Run ends with its work captured as durable Artifacts, and the task detail page shows them:

| Artifact | Role | Content |
|---|---|---|
| Report | `harness.report` | The attempt's final assistant message (Markdown). |
| Patch | `harness.patch` | A unified diff of the final clone state (commits plus uncommitted and untracked files) against the base SHA recorded at `prepared`. |
| Commits | `harness.commits` | Before HEAD (the base SHA), after HEAD, and the commits the harness made. |

A Run **succeeds only when all three are ready**. The report commits atomically with the success settlement, through the same B10 finalize-plus-completion path B09 uses. This meets the hard rule that a Task is done only after its artifacts and final state are durably persisted.

### Non-goals (deferred, with reasons)

- **Raw event stream export (NDJSON).** Every event is already durable in `harness_events` (phase 1b). Exporting it as an object is a read projection, not capture, and `Raw` is sensitive. It is deferred to a later phase that decides on redaction.
- **Harness transcript snapshot** (Claude Code session JSONL). The transcript lives in the harness home, owned by the operator's UID with mode 0600. `central-runtime` cannot read it, and reading it would need the launcher to act on the runtime's behalf. That is a new ADR 0036 capability, so it is deferred.
- Capturing binary file contents. The patch names changed binary files but omits their bytes (decision 5). The clone is retained, as it is in 3a.
- Resuming an interrupted capture after a serve restart (decision 9).
- Clone cleanup and retention (still governing §15 Q4).
- Everything already assigned to 3c (Bridge approvals, AutoAllow, budgets, the resolution UI, retries).

## 2. Findings that shape the design

- **B10 has no generic Artifact class.** Its one class is the required report:
  - text only (`text/markdown` or `text/plain`; a NUL byte means binary, which is rejected);
  - at most `HardRequiredReportMaxBytes` = 10 MiB;
  - a secret-disclosure classifier that rejects the body.

  `MaterializeRequiredReport` drives reserve → stage → verify → classify → promote → finalize, idempotent under a stable `OperationID`.
- **The finalize commit accepts an execution change set with no settlement.** `CommitArtifact` checks `b10SupportedExecutionChange`, which returns nil when `Settlements` is empty. `ResumeVerifying` already commits with `execution.ExecutionChangeSet{}`. A ready Artifact can therefore be committed without a Task transition. This is how the patch and commits are stored.
- **B10 outcomes are not all final.** `MaterializeRequiredReport` returns `Ready`, `Terminal`, `Retryable` or `Reconciliation`. `Reconciliation` means the finalize commit's outcome is unknown. It is "reconciliation work, never a blind retry", and B09 answers it with `execution.Reconcile`. A second in-process call under the same `OperationID` after partial progress is **not** a replay. The replayed reservation returns the row in its current state, and `BeginUpload` then refuses it with `INVALID_TRANSITION`.
- **B09 already does atomic report completion.** `internal/agent/app/coordinator.go` builds a settle candidate and validates it with `execution/app.Service.ValidateCompletionChangeSet`. It then passes the candidate as `Completion` to the report materialization, inside a heartbeat. 3b reuses that exact sequence.
- **Roles are free text.** `central.artifacts.required_role` is a nullable text column with no uniqueness on `(run_id, required_role)`. Three roles per Run need **no migration**.
- **Task detail shows one Artifact.** `TaskDetail.RequiredArtifactID` is the Run's most recently updated ready Artifact. The preview and download routes take an Artifact ID and are workspace-scoped. With three Artifacts per Run, "most recent" would be arbitrary.
- **After a crash, B08 recovery settles from the completion receipt.** 3a records a succeeded receipt before `Settle`, so after a crash B08 recovery settles the StepAttempt from that receipt. If 3b kept that order, a Run could settle succeeded with no report (decision 9). The harness attempt row is already terminal (`succeeded`) before settlement. The 3a reconciler scans only non-terminal rows, and `succeeded` has no outgoing transition.
- **The operator can swap the clone root.** 3a grants the operator `rwX` on `runs/<run-id>` itself, and ACLs are UID-based. The harness can therefore replace `repo` with a symlink, or turn `repo/.git/objects` or its `info/alternates` into a symlink. The spec review reproduced both: a patch that contained a file only the runtime could read, and a log of a foreign repository. A FIFO at `.git/HEAD` or at a nested repository's `HEAD` blocks a plain `open` or `git add` indefinitely. A work-tree `.gitattributes` with `-diff`, `binary`, `text`, `eol`, `ident` or `working-tree-encoding` changes diff output with no configured driver. `*.go -diff`, for example, hides a code change as `Binary files differ`.
- **The clone is untrusted after launch.** The harness can write every file under `runs/<run-id>/repo`, `.git` included (`config`, `hooks/`, `info/attributes`, `objects/info/alternates`, `HEAD`, refs). Any git command that reads that `.git` as its repository runs under harness-controlled config. `core.fsmonitor`, filter drivers, `diff.external` and textconv are code-execution vectors that would run as `central-runtime` (3a §11).
- **Files the harness creates with mode 0600 are unreadable to the runtime.** On a file that has a default ACL, the mask comes from the create mode's group bits. A file created 0600 therefore gets mask `---`, and the runtime's named ACL entry grants nothing.

## 3. Decisions

| # | Question | Decision | Why |
|---|---|---|---|
| 1 | Which artifacts in 3b? | Report, patch and commits (§1). Event stream and transcript are deferred (§1 non-goals). | These three are what an operator reviews. The deferred two need a redaction policy or a new launcher capability. |
| 2 | Required or supporting? | All three are required for success. The report is the *completing* Artifact: its finalize commits the success settlement atomically. The patch and commits are finalized first, each in its own commit with an empty execution change set. | A Task is "done" only after its artifacts are durable. One atomic completing commit keeps the B08/B10 contract unchanged. |
| 3 | B10 changes? | None to the lifecycle, the classifier or the schema. All three bodies are text within the report class and go through `MaterializeRequiredReport`, each with its own role, operation ID and declared media type: report `text/markdown`, patch and commits `text/plain`. The patch and commits pass a zero `Completion` (no Task transition), which `ResumeVerifying` already does. | Reuses the audited lifecycle: idempotency, quota, secret classifier, reconciliation of incomplete uploads, workspace-scoped delivery. |
| 4 | How is git run safely? | Capture runs only after the attempt's launcher scope has been released, so no harness process is left.<br><br>**Seal the Run.**<br>1. Remove the operator's ACL entries from `runs/<run-id>` itself (runtime-owned; `0700` while sealed, §9 item 11). The subtree is then unreachable to the operator UID.<br>2. Open `runs/<run-id>/repo` with `openat2(RESOLVE_NO_SYMLINKS\|RESOLVE_BENEATH)` from `data_root`, and require a real directory owned by `central-runtime` (the clone created it). A swapped or symlinked root → `artifact_capture_failed`.<br>3. The startup probe requires `fs.protected_hardlinks=1`, so the harness cannot hardlink a file it cannot read into the work tree.<br><br>**Shadow repository.** All capture git runs with `data_root/capture/<run-id>.git`, created by `central-runtime` with mode `0700` after sealing. The clone's `.git` is never used as the repository, so its `config`, `hooks`, `info/attributes` and refs are never read by git.<br>• The work tree is the sealed `repo`, passed explicitly (`--git-dir`, `--work-tree`).<br>• `objects/info/alternates` lists **only** the Workspace source's objects (trusted, runtime-owned).<br>• The clone's objects are **copied** into the shadow by a Go walker rooted at `repo/.git/objects`. It opens with `openat2(RESOLVE_NO_SYMLINKS\|RESOLVE_BENEATH)` and `O_NONBLOCK`, accepts only `fstat` regular files, skips `info/`, and applies per-file and total byte caps.<br>• The shadow's `info/attributes` is `* !diff !text !eol !ident !filter !working-tree-encoding !merge !crlf`, with `core.attributesFile=/dev/null`. Work-tree `.gitattributes` therefore cannot change conversion or diff output.<br>• The environment is empty except for:<br>&nbsp;&nbsp;– `GIT_CONFIG_NOSYSTEM=1`;<br>&nbsp;&nbsp;– `GIT_CONFIG_GLOBAL=/dev/null`;<br>&nbsp;&nbsp;– `GIT_TERMINAL_PROMPT=0`;<br>&nbsp;&nbsp;– `GIT_OPTIONAL_LOCKS=0`;<br>&nbsp;&nbsp;– `GIT_INDEX_FILE` = a runtime temp file.<br>• Command-line config: `core.hooksPath=/dev/null`, `core.fsmonitor=false`, `core.untrackedCache=false`, `core.autocrlf=false`, `core.symlinks=true`, `log.mailmap=false`.<br>• Diffs use `--no-ext-diff --no-textconv`.<br>• Every command has a timeout and a `WaitDelay`, and the whole capture (walkers plus git) runs under one deadline, `CaptureTimeout` = 2 minutes. Exceeding it → `artifact_capture_failed`. | Nothing harness-controlled is read as config, attributes or a path to follow, and nothing the harness wrote can redirect the runtime outside the Run. Filter drivers, external diff and textconv exist only when configured, and only Central's config is read. |
| 5 | Patch content? | Start from an empty temp index, then `add -A` over the work tree, then `diff --cached <base>`, run against the shadow repository.<br>• The patch covers commits, uncommitted and untracked files.<br>• `.gitignore`-ignored files are excluded (disclosed).<br>• Binary files appear as `Binary files … differ` (git's default without `--binary`).<br>• Symlinks are recorded as links, never followed.<br>• Nested repositories: a pre-walk (the same no-follow walker) finds every `.git` entry below the root. Each containing directory is excluded with a literal exclude pathspec, and the patch opens with a fixed header line listing the excluded paths. `add -A` then never reads a nested `HEAD` or gitfile.<br>• An empty diff is valid: the patch body then states "no changes" in a fixed line, so the body is never zero bytes. | Text-only fits the report class. Ignored build outputs stay out. The clone keeps the full bytes for the operator. |
| 6 | Commits content? | Before HEAD = the base SHA. After HEAD is parsed **by Go**, not git, from the sealed clone's `.git/HEAD` and its loose ref or `packed-refs`:<br>• every path component is resolved with `openat2(RESOLVE_NO_SYMLINKS\|RESOLVE_BENEATH)` from `repo`;<br>• opened with `O_NONBLOCK`, and must be an `fstat` regular file;<br>• size caps: 4 KiB for `HEAD` and loose refs, 1 MiB for `packed-refs`;<br>• strict hex SHA and ref-name grammar;<br>• read under the capture deadline.<br>If `.git` is not a real directory, a file fails any check, after HEAD cannot be parsed, or its object is missing from the shadow, the artifact says `after HEAD: unavailable` and lists no commits. Otherwise `log --format=<fixed fields using %an/%ae, never mailmap-aware %aN> --no-show-signature <base>..<after>` runs against the shadow repository, capped at 1,000 commits with a truncation line. | Reading refs never needs harness config, never follows a planted path, and cannot block. A rewritten or corrupt history degrades the list, not the Run. |
| 7 | Report content? | The text of the attempt's last complete (non-partial) assistant `Message`, tracked by the event loop in memory.<br>• An empty or missing final message fails the Run with `harness_report_missing`.<br>• A message over the report limit (1 MiB, decision 14) fails it with `artifact_too_large`. | Claude Code always ends a successful `-p` run with result text. Fabricating a placeholder report would misstate the outcome. |
| 8 | Order and failure semantics on a **succeeded** terminal? | The heartbeat stays live throughout.<br>1. Seal and capture the patch and the commits into runtime temp files.<br>2. Materialize the patch.<br>3. Materialize the commits.<br>4. Build and validate the success settle candidate.<br>5. Materialize the report with that candidate as `Completion`.<br>**No completion receipt is recorded before step 5.** `Store` and `CompleteWithReport` are **never retried in-process** (§2).<br><br>Outcome mapping follows B09:<br>• **`Ready`:** continue. After step 5, the Task and Run are completed.<br>• **A capture error, or `Terminal`/`Retryable` from B10:** fail the Run through `RecordCompletion` + `Settle` with a bounded reason:<br>&nbsp;&nbsp;– `artifact_capture_failed`: a git or I/O error, a sealing failure, the deadline;<br>&nbsp;&nbsp;– `artifact_rejected`: the classifier, a secret or the media type;<br>&nbsp;&nbsp;– `artifact_too_large`;<br>&nbsp;&nbsp;– `artifact_quota_exceeded`;<br>&nbsp;&nbsp;– `harness_report_missing`.<br>• **`Reconciliation`, an unclassified error or a missing outcome:** the StepAttempt goes to B08 reconciliation through a new `RunLifecycle.Reconcile`, the same move as B09's `execution.Reconcile`. The Task then waits for the operator's 3a resolve action. The Run is never failed blindly: the completing commit may have landed.<br>• **Cancellation** seen by the heartbeat during capture stops capture and goes to `SettleCancellation`. A candidate or commit refused because the Task is cancelling is never an Artifact failure.<br><br>Artifacts that became ready before a failure stay attached to the Run. The harness attempt row keeps its `succeeded` terminal; only the Run and Task fail. | Fail closed: success means durable artifacts. An ambiguous commit is reconciled, never guessed. The reason tells the operator what to fix, and the retained clone holds the work. |
| 9 | Serve stops mid-capture? | The success path writes no receipt before the completing commit (decision 8), so B08 recovery finds an invoked StepAttempt with no receipt and puts it in **reconciliation**. It never settles succeeded. The harness row is already terminal (`succeeded`), so the 3a reconciler skips it. The operator resolves the Task with the 3a action, which accepts terminal rows. Artifacts that were in flight either become ready without a settlement (B10's reconciler) or are cleaned up. Either way they are orphaned on the Run, and that is harmless. Resuming capture is deferred. | No new recovery path. Nothing can settle succeeded without a durable report. |
| 10 | Non-success terminals? | Failed, max_turns, budget, interrupted and killed seal the Run and capture **patch and commits best-effort** before `RecordCompletion` + `Settle`. Capture errors are logged and projected as the milestone `artifacts_partial`, and the settle reason stays the terminal's. No report is materialized. Cancellation (`SettleCancellation`) and pre-launch abandonment capture nothing. | Partial work is visible for debugging without changing why the Run failed. |
| 11 | Where does the code live? | • **`internal/harness/app`** gains two ports it owns:<br>&nbsp;&nbsp;– `WorkspaceCapture`: `Capture(ctx, ws harness.Workspace, run identity.RunID) (Capture, error)`, where `Capture` holds temp-file paths plus after HEAD;<br>&nbsp;&nbsp;– `ArtifactSink`: `Store(ctx, run ClaimedRun, role, body) (ArtifactOutcome, error)` for supporting Artifacts.<br>&nbsp;&nbsp;`RunLifecycle` gains `CompleteWithReport(ctx, run, body) (ArtifactOutcome, error)` and `Reconcile(ctx, run) error`, the latter implemented over `execution/app.Service.EnterReconciliation`.<br>• **`internal/adapter/workspace/gitclone`** implements `WorkspaceCapture`, with the shadow repository and the ref parser.<br>• The composition adapter in `cmd/central` implements `ArtifactSink` and `CompleteWithReport` over `artifact/app.Service` and `execution/app.Service`, following B09's candidate → validate → materialize sequence.<br>• Execution adds the new bounded `FailureReason` values.<br>• Archguard `harness-app-boundary` still forbids `internal/harness/app` from importing `internal/artifact`. | Domain packages own their interfaces, and adapters do not leak (3a decision 17). |
| 12 | Operation identities? | Each operation ID is derived from the harness attempt ID and the role (for example `harness:<attempt-id>:patch`). Artifact ID and staging generation come from `artifact.DeriveReservationIdentity`. | The receipts stay idempotent across restarts and B10 reconciliation. This is not an in-process retry mechanism (decision 8). |
| 13 | Task detail? | `TaskDetail` gains `Artifacts []ArtifactRef{ID, Role, VerifiedSize}`: every ready, not-delete-pending Artifact of the current Run, ordered report, patch, commits, then any other role by creation time. The template renders one row per Artifact, with a fixed label per role and the existing preview and download links. `RequiredArtifactID` becomes a role priority: the Run's ready `harness.report` Artifact if one exists, otherwise the most recent ready Artifact, as today for B09. No harness-Task detection is needed. | One page shows all three. The existing, security-reviewed delivery routes are reused unchanged. |
| 14 | Limits? | All three use `artifact.DefaultLimits()` (1 MiB) except the patch, which uses `HardRequiredReportMaxBytes` (10 MiB). Capture refuses to buffer beyond its limit: output is streamed to a temp file with a byte cap, and exceeding the cap is `artifact_too_large`. Temp files live under `data_root/capture/tmp` (runtime, `0700`) and are removed after the Run settles. | Bounded disk and memory, and no unbounded read of harness-controlled output. |

## 4. Flow (succeeded terminal)

1. The event loop sees the terminal as in 3a. The heartbeat keeps running.
2. `WorkspaceCapture.Capture` runs once the scope is released. It:
   - seals the Run (decision 4);
   - creates `capture/<run-id>.git`, with the source alternate and the attributes file;
   - copies the clone's objects;
   - builds the patch and commits into temp files.
3. `ArtifactSink.Store(harness.patch)`, then `Store(harness.commits)`. Outcomes are mapped as in decision 8.
4. `RunLifecycle.CompleteWithReport(report)` builds and validates the settle candidate, then materializes the report with `Completion`. Ready means the Task and Run are completed atomically with the report.
5. The milestone `artifacts_captured` is recorded, and the temp files and shadow repository are removed.

## 5. Security properties

- No git command uses the clone's `.git` as its repository, and no config other than Central's is read. The shadow's `info/attributes` overrides every work-tree attribute that affects conversion or diff output.
- Before capture, the Run is sealed. The operator UID loses access to `runs/<run-id>`, and the `repo` root must be a real, runtime-owned directory. No path is followed through a symlink: git records symlinks as links, and the Go walkers and the ref reader use `RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH`.
- Non-regular files (FIFOs, devices) are never opened by Central's code, and all capture work shares one deadline, so a planted FIFO cannot hang serve.
- The clone's objects are copied as data, never listed as an alternate, so a planted `alternates` file is never followed. `fs.protected_hardlinks=1` stops the harness from hardlinking unreadable files into the work tree.
- After HEAD is parsed without following any symlink, non-blocking, with size caps.
- Every body passes B10's secret classifier. A patch that contains a credential is rejected, so it is not stored.
- Git output never reaches logs. Only bounded reason codes and sizes are logged.

## 6. Testing

- **`gitclone` capture**, with real temp repositories:
  - A malicious `.git/config` (`core.fsmonitor`, a `filter.x.clean` driver plus `.gitattributes`, `diff.external`, hooks) creates no marker file.
  - Uncommitted, untracked and ignored files; binary files; symlinks; a nested repository.
  - Commits on a branch, and a detached HEAD.
  - A garbage, symlinked, FIFO or oversized `HEAD`.
  - `repo` replaced by a symlink to a runtime-readable directory → `artifact_capture_failed`, and nothing from it is captured.
  - A symlinked `.git/objects` and a planted `info/alternates` are not followed.
  - `*.go -diff` and `text`/`eol`/`ident` in `.gitattributes` do not change the patch.
  - A nested repository, including one whose `HEAD` is a FIFO or whose `.git` is a gitfile, is excluded and listed, and nothing blocks.
  - The capture deadline gives `artifact_capture_failed`.
  - An unreadable 0600 file gives `artifact_capture_failed`.
  - The output cap gives `artifact_too_large`.
- **Orchestrator, with fakes:**
  - The success order is patch, commits, then report with completion, and no receipt is written before the report.
  - Each failure maps to its reason.
  - Non-success terminals capture best-effort and keep their reason.
  - Cancellation before the terminal captures nothing.
  - A cancel seen during capture goes to `SettleCancellation`.
  - A `Reconciliation` outcome, or an error from the completing commit, goes to `Reconcile`, not `Settle`.
  - `Store` is never called twice for one role.
  - A restart mid-capture leaves the StepAttempt in reconciliation, never succeeded (live PostgreSQL).
- **Composition adapter, against live PostgreSQL:** a supporting Artifact commits ready with no Task transition. The report commits the Task and Run completed atomically, and a replay under the same operation ID is idempotent.
- **`cmd/central` e2e** (the 3a harness e2e with the fake adapter): a succeeded Run has three ready Artifacts and a completed Task, and task detail renders three rows. A secret in the patch fails the Run with `artifact_rejected`.
- **Web:** the task detail template covers the list, and `RequiredArtifactID` resolves to the report for harness Tasks.

## 7. Acceptance

1. A succeeded harness Run leaves exactly three ready Artifacts (`harness.report`, `harness.patch`, `harness.commits`) linked to its Workspace, Task, Run, Step and StepAttempt, and the Task is `completed`.
2. No code path settles a harness Run succeeded unless its report is ready in the same transaction.
3. A capture or Artifact failure fails the Run with one of the bounded reasons in decision 8.
4. The malicious-repository tests prove three things: no harness-controlled config, hook or attribute takes effect during capture; no planted symlink, alternates file or FIFO redirects or blocks it; and no runtime-only file reaches an Artifact.
5. No harness Run settles succeeded after a restart mid-capture. It waits in reconciliation.
6. Task detail lists the three Artifacts with working preview and download.
7. Checks pass: `go vet ./...`, `gofmt`, the touched packages' tests, and archguard.

## 8. Open items for planning

1. Confirm that `harness-app-boundary` needs no rule change for the two new ports.
2. Name the orchestrator signal that the launcher scope has been released: the persisted terminal after `Wait` returns, or the launcher's `EXIT`. Use whichever 3a already exposes.
3. Add `fs.protected_hardlinks` and the `capture/` directory (`central-runtime`, `0700`) to `setup.sh` and the startup probe.

## 9. Changes from the verified draft (accepted)

A verified draft implementation (branch `draft/harness-3b`, the source of the plan's patches) settled the following. They take precedence over the decisions above where they differ.

1. **Port shapes.**
   - `WorkspaceCapture.Capture(ctx, ws identity.WorkspaceID, workspace harness.Workspace, run identity.RunID)`: the Workspace ID locates the source-objects alternate. `WorkspaceCapture.Release(ctx, run)` cleans the temp files and the shadow repository.
   - `ArtifactSink.Store` takes the body as a runtime temp-file **path**, because archguard's `harness-boundary` forbids `os` in `internal/harness/**`.
   - `CompleteWithReport` takes an `io.Reader`.
2. **B10 composes without B09.** `composeArtifactCapability` builds the lifecycle service, reconciler and recovery hook whenever the object store is configured. The B09 `ReportMaterializer` is built only when an agent report source exists, so B09 stays fail-closed as before.
   - Serve refuses `CENTRAL_HARNESS_ENABLED=1` (`CONFIG_INVALID`) without a configured object store.
   - Enabling harness on a host therefore also needs the broker-delivered MinIO runtime credential (the SB-G3 chain). The production broker-socket rendezvous gap recorded in `current-phase.md` still applies, and the runbook says so.
3. **Seal only while capturing.** `seal` records the Run directory's ACL, and `unseal` restores it byte-for-byte once every capture git command has exited, on success and on every error path. The operator can then inspect and fetch the retained clone as in 3a.
   - A failed unseal does not fail the Run.
   - A serve stop mid-capture leaves that Run sealed, and the runbook gives the `setfacl` command to restore access.
4. **B10 lock order** (a bug found by the e2e, fixed in Task 4): the report's reserve and finalize commit deadlocked (40P01) with the concurrent lease heartbeat.
   - `queryLockWorkspaceQuota` now takes `FOR NO KEY UPDATE`.
   - `CommitArtifact` takes the workspace event counter first, which is execution's order.
5. **Report checks** run after the patch and commits are stored, so those stay attached. The object-copy caps (1 GiB per file, 2 GiB total) map to `artifact_capture_failed`; only output caps map to `artifact_too_large`.
6. **Scope released** means `session.Wait` returned, with a 10 s budget. If it does not return, a succeeded terminal fails with `artifact_capture_failed`, and a non-success terminal skips capture. A launch failure captures nothing.
7. **Events.** A success on the B10 path writes `task.completed` through the report commit, with no `attempt_settled` event and no completion receipt. The milestones are written after the commit.
8. **Known limit.** The download route buffers at most 2 MiB, so a larger patch is stored but can only be previewed (truncated) or fetched from the unsealed clone. The runbook says so.
9. **`setup.sh`** checks `fs.protected_hardlinks=1` and refuses to proceed otherwise. It does not set or persist the sysctl.
10. **Plan-review hardening** (`docs/superpowers/reviews/2026-09-28-harness-phase-3b-plan-review.md`):
    - The shadow's config adds `core.multiPackIndex=false`, `core.commitGraph=false`, `pack.useBitmaps=false`, `core.useReplaceRefs=false`, `gc.auto=0`, `core.packedGitLimit=1g` and `core.packedGitWindowSize=256m`.
    - The object copy is an allowlist: loose `objects/<2 hex>/<38 or 62 hex>`, and `objects/pack/pack-<hex>.{pack,idx,rev}`. A loose object is skipped when its header is malformed, its type is unknown, or it is a commit, tag or tree declared above 16 MiB.
    - Every capture git child gets `RLIMIT_AS` = 4 GiB through `prlimit` right after start. If that fails, the child is killed and capture fails.
    - Capture requires a confirmed launcher `EXIT`: `Wait` returned nil **and** the exit code is set.
    - A B10 lease-fence refusal maps to lease lost.
    - A report commit that landed despite an error is detected by the fresh read and treated as ready.
11. **Execution-review hardening.** Found by the per-task reviews during implementation. These items take precedence over decisions 4–6.
    - **Two shadows.**
      - The patch is built in `capture/<run-id>.git`, which holds **no clone object**: only what `add` writes, plus the source alternate. Git does not verify object hashes on read, so a planted clone object under a work-tree file's id, or under the base blob's id, would otherwise rewrite or hide the patch.
      - The clone's objects are copied only into a separate log shadow, `capture/<run-id>-log.git` (same config and alternate). Only `cat-file -t`, `rev-list --count` and `log` read it, and only after the patch is written.
      - That walk reads every object reachable through parent lines, a planted blob included, so it is bounded by `RLIMIT_AS` and the deadline.
    - **Degraded commit list.** When the log walk exits non-zero before the deadline (a rewritten or corrupt history, or an ancestor the copy skipped), the commits Artifact keeps before HEAD and after HEAD and replaces the count with `commits: unavailable`. The Run is not failed (decision 6). Deadline and caps keep their mapping.
    - **Seal mode.** While sealed, the Run directory is `0700`, not `0750`. The chmod happens before the ACL xattrs are removed, and unseal restores the recorded ACL and mode.
    - **Bounded directory reads.** Directory listings are read against the remaining entry budget and the deadline.
    - **Unreadable entries.** An unreadable work-tree directory fails capture (`artifact_capture_failed`), because `git add` only warns about one. The object copy still skips unreadable entries, which only degrades the commit list.
    - **Diff pathspecs.** `diff --cached` gets the same exclude pathspecs as `add`, so an excluded nested repository never shows its base files as deleted.
    - **`Release` signature.** `gitclone.Provisioner.Release(run)` takes no context; the `harnessCapture` adapter bridges it to `WorkspaceCapture.Release(ctx, run)`.
