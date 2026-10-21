# Harness execution (phases 3a to 3h)

`central serve` can run a submitted Task as one Claude Code session through the root `central-harness-launcher` (ADR 0035, ADR 0036; designs: [harness phase 3a serve wiring](../internal/superpowers/specs/2026-09-28-harness-phase-3a-serve-wiring-design.md), [harness phase 3b artifact capture](../internal/superpowers/specs/2026-09-28-harness-phase-3b-artifact-capture-design.md), [harness phase 3c permission approvals](../internal/superpowers/specs/2026-09-29-harness-phase-3c-permission-approvals-design.md), [harness phase 3d budgets](../internal/superpowers/specs/2026-09-29-harness-phase-3d-budgets-design.md), [harness phase 3e cancel and recovery](../internal/superpowers/specs/2026-09-29-harness-phase-3e-cancel-and-recovery-design.md), [harness phase 3f epoch resume and prepared cancel](../internal/superpowers/specs/2026-09-29-harness-phase-3f-epoch-resume-and-prepared-cancel-design.md), [harness phase 3g resume of an ambiguous attempt](../internal/superpowers/specs/2026-09-30-harness-phase-3g-resume-ambiguous-attempt-design.md), [harness phase 3h Resume honours the eligibility floor](../internal/superpowers/specs/2026-09-30-harness-phase-3h-resume-eligibility-guard-design.md)). This runbook installs it, enables it, and covers the operator actions it needs.

It is **off by default**. With it off, serve behaves as before, except that the startup recovery gate also reconciles harness attempt rows (a no-op when there are none).

What it does and does not do:

- One Task = one Claude Code attempt, in a Central-owned clone of the Workspace's source repository, under `/var/lib/central-harness/worktrees/runs/<run-id>/repo`.
- Every harness event is persisted; milestones appear in the task's activity; the Task ends `completed` or `failed` with a fixed reason code.
- **Cancel** works on a started harness Task: within one heartbeat (10 s) the harness is interrupted, killed after 30 s if it does not stop, its terminal is recorded, and the Task ends `cancelled` ("Settling" is shown meanwhile). A Task cancelled before it started (still queued, its Run never claimed) ends `cancelled` at once, in one commit, and is never dispatched (3e). A Task left "Settling" by an earlier release without ever having started shows **Finish cancelling**. If serve stops in the middle of a cancel, the Task stays "Settling" with the explanation "Settling: the harness stopped when serve stopped. Confirm it is not running, then Mark cancelled." (§8); a cancel that came before the harness was launched is finished by the next start by itself, or at once with **Finish cancelling** on the task's page (3f, §8).
- Each Task has a **permission policy**, chosen when it is submitted (§4a): **Deny** (the default: the harness may use only the tools your Claude Code settings already allow, see step 3), **Bridge** (you answer each tool permission request on the task's detail page) or **Auto-allow** (every tool runs without asking).
- A Run **succeeds only with its three Artifacts** (3b): the report (the harness's final message), a patch and a commits list (§6). They appear on the task's detail page. While Central captures them, the Run directory is briefly **sealed** (at most 2 minutes); your access to the retained clone returns as soon as capture ends.
- Each Run is bounded by a **cost limit** and a **wall clock** (3d, §4b): chosen per Task when it is submitted, or serve's defaults. Optionally, `CENTRAL_HARNESS_MAX_TOKENS` also caps the tokens of each attempt (3l, §4b). A Run stopped by a bound fails with a reason that names it.
- A failed Task can be **retried** and a cancelled one **rerun** (§8a). A Task whose attempt was left **ambiguous** by a serve stop can be **resumed** (3g, §8): the same Claude Code session continues in the same clone, as a new attempt of the same Run, under an attempt ceiling and a Run-wide cost budget (§4b); since phase 3h Resume is neither offered nor accepted for a Task created before `CENTRAL_HARNESS_ELIGIBLE_AFTER` (§8). Run clones are never cleaned automatically.

## 1. Prerequisites

1. Central is installed and `central-runtime` exists.
2. Claude Code is installed for the operator (the login that owns the work) and **logged in**: run `claude` once as the operator.
3. Build the launcher daemon from the checkout: `make native-harness-launcherd` (writes `build/central-harness-launcherd`). `setup.sh` refuses to run (exit 1, nothing changed) until it is built.
4. Packages: `git` ≥ 2.46.0 (or ≥ 2.45.3 on the 2.45 line) and `acl` (`setfacl`, used once by the installer). The harness home trusts `safe.directory = …/runs/*`, and a `/*` entry (leading-path matching) needs that git; `setup.sh` checks `git --version` and refuses an older one.
5. `fs.protected_hardlinks = 1` (the default on current distributions): otherwise a harness could hardlink a file only `central-runtime` can read into its clone, for capture to copy into an Artifact. `setup.sh` checks it before changing anything and serve refuses to start harness execution without it. Check with `sysctl fs.protected_hardlinks`.
6. **The B10 Artifact object store.** A harness Run succeeds only with its Artifacts, so serve refuses to start with `CENTRAL_HARNESS_ENABLED=1` when B10 is not configured (`CONFIG_INVALID`: "harness execution requires the artifact object store"). B10 no longer needs a B09 report source to compose, and serve now has a production credential path: run the campaign broker and transcribe the binding reference per `campaign-serve-bringup.md`, then set `CENTRAL_MINIO_RUNTIME_BINDING_REF` (a stale or consumed reference fails closed to the same `CONFIG_INVALID`, never silent).

## 2. Install (idempotent)

From the checkout, as the operator:

```bash
sudo packaging/harness/setup.sh            # --dry-run first to see every change
```

It shows the harness commit identity (taken from your global `git config user.name/user.email`, or `--git-name`/`--git-email`) and asks you to confirm (`--yes` skips the question; without a terminal on stdin it refuses and asks for `--yes`). The operator must be a login user (UID ≥ `UID_MIN` from `/etc/login.defs`, default 1000). It then:

| Step | Result |
|---|---|
| group | `central-harness`, with the operator added. **Log in again** (or `newgrp central-harness`) before your first push. |
| data root | `/var/lib/central-harness` and `worktrees/` (root, `0755`), `sources/` (`central-runtime:central-harness`, `2770`), `worktrees/runs` (`central-runtime`, `0750`, ACL `u:<operator>:--x`), `capture/` (`central-runtime`, `0700`: each Run's shadow repository and capture temp files) |
| harness home | `~<operator>/.local/state/central/harness-home/claude` with its `.claude` and `.local/share/claude` mount points and a `.gitconfig` holding the commit identity. Written **as the operator** (`sudo -u`), never as root. |
| git trust | only the harness home's `.gitconfig`: `safe.directory = /var/lib/central-harness/worktrees/runs/*` and `safe.bareRepository = explicit`, so the harness's own git can commit in its Run clone. Nothing system-wide: no `/etc/gitconfig` entry, so neither root nor your own sessions trust a Run clone (§5). |
| launcher | `/usr/lib/central/central-harness-launcherd`, the systemd units, `central-harness-launcher.socket` enabled and started |
| launcher config | `/etc/central/harness-launcher.conf`, **created only if absent** |

Rerunning it changes nothing on an installed host (`--dry-run` then prints no `+ ` line). If `/etc/central/harness-launcher.conf` exists and differs from what the script would write, it prints the diff and **exits 3 without touching it**: reconcile the file by hand (or move it aside) and rerun.

`safe.bareRepository = explicit` matters because git discovers a bare repository in any directory shaped like a git dir, not only in a real `.git`: a harness could plant one under `runs/<run-id>/repo` (say, a directory holding its own `config` with `core.fsmonitor` or `core.hooksPath`) and have an unscoped git command pick it up without ever touching the clone's actual `.git`. `explicit` refuses that discovery unless a bare repository is named with `--git-dir` or `GIT_DIR`. Verify it after install:

```bash
git config --file ~<operator>/.local/state/central/harness-home/claude/.gitconfig safe.bareRepository
# explicit
```

## 3. Allow the tools the harness needs (Deny policy)

Under Deny, Claude Code runs in `dontAsk` mode: a tool call that is not pre-allowed is denied and shows up in the task's activity as `harness.permission denied`. Allow the minimum in the operator's `~/.claude/settings.json` (it is mounted into the harness home). The recommended rules, and exactly the ones the reference-host check (§10) needs, are path-scoped **and deny each clone's `.git`**:

```json
{ "permissions": {
  "allow": [
    "Edit(//var/lib/central-harness/worktrees/runs/**)",
    "Bash(git add:*)",
    "Bash(git commit:*)"
  ],
  "deny": [
    "Edit(//var/lib/central-harness/worktrees/runs/**/.git)",
    "Edit(//var/lib/central-harness/worktrees/runs/**/.git/**)"
  ]
} }
```

- **Deny rules take precedence over allow rules.** Claude Code evaluates deny, then ask, then allow, and the first match decides; rule specificity does not change the order, so an allow rule cannot carve an exception out of a deny rule (Claude Code docs, "Configure permissions" → "Manage permissions"). The deny rules therefore hold although `runs/**` also matches `.git`.
- **Why `.git` must be denied.** `runs/**` includes each clone's `.git/`. A harness that writes `.git/hooks/*` or `.git/config` (`core.hooksPath`, `core.fsmonitor`, aliases) gets that code run by the allowed `git add`/`git commit`. It runs inside the harness sandbox, but **any code execution inside the sandbox reaches your real `~/.claude`**, because it is mounted read-write: it could rewrite `~/.claude/settings.json` (allow rules, `hooks`), which then applies, unsandboxed, to every Claude Code session you start. Path-scoping is not enough: **every rule set that allows writes under `runs/**` must also deny `.git`.** (Claude Code also lists `.git` among its protected paths, which `dontAsk` denies; do not rely on that alone.)
- **`Edit` covers all file writes.** Current Claude Code docs say file permissions are checked against `Edit(path)` rules only, including Bash redirects (`>`, `>>`) and other non-`Edit`-tool writes; `Write(path)` rules are accepted but not consulted (and warned about at startup) from v2.1.210, so they are omitted here.
- **Verify on the pinned Claude Code (2.1.283) before enabling**, from your own session, never through a harness. If any check fails, do not enable harness execution.
  1. The `//` form: a `Write` to a file under `/var/lib/central-harness/worktrees/runs/` is allowed and one elsewhere still asks.
  2. `.git`: a `Write` or `Edit` to `runs/<any>/repo/.git/config` or `runs/<any>/repo/.git/hooks/pre-commit` is refused.
  3. Symlinks: the docs say an allow rule applies only when both the requested path and the file it resolves to match, and a deny rule when either does. Check that a write through a symlink under `runs/` pointing at `~/.claude/settings.json` (or into a `.git/`) is not allowed. A repository you push can contain such a symlink, so the maintainer must confirm this on 2.1.283 before enabling.
- **These rules also apply to your own sessions.** User-level allow rules are not harness-only: every Claude Code session you run gets them. Keep them path-scoped, with the `.git` deny rules.
- **Never allow an unscoped `Edit` or `Write`**, and never drop the `.git` deny rules: either would let a harness rewrite your Claude Code settings, including these rules.

## 4. Enable it in serve

Add to serve's environment (the drop-in or environment file of the unit that starts `central serve`); `setup.sh` prints these values:

```bash
CENTRAL_HARNESS_ENABLED=1
CENTRAL_HARNESS_ELIGIBLE_AFTER=2026-09-28T09:00:00Z   # only Tasks created at/after this run
CENTRAL_HARNESS_OPERATOR_UID=1000                     # the operator's uid (Run clone ACLs)
CENTRAL_HARNESS_DATA_ROOT=/var/lib/central-harness    # default
CENTRAL_HARNESS_PATH=/usr/local/bin:/usr/bin:/bin     # the harness PATH; absolute directories only
# optional: CENTRAL_HARNESS_WALL_CLOCK=30m (1m–24h; the default wall clock, §4b),
#           CENTRAL_HARNESS_MAX_COST_USD=5.00 (0.01–1000, at most 2 decimals; the default cost limit, §4b),
#           CENTRAL_HARNESS_TASK_COST_CAP_USD=25.00 (0.01–100000, at least MAX_COST_USD; default 5 × MAX_COST_USD;
#                                              the cost cap of one Task across its Retries, §4b),
#           CENTRAL_HARNESS_MAX_TOKENS (100000–1000000000, a plain whole number, for example 2000000; unset: no ceiling;
#                                       the billed-token ceiling of one attempt, §4b),
#           CENTRAL_HARNESS_MAX_ATTEMPTS=3 (1–10; the attempt ceiling of a Run, §8),
#           CENTRAL_HARNESS_CONCURRENCY=1 (1–4),
#           CENTRAL_HARNESS_MIN_FREE=2GiB, CENTRAL_HARNESS_CLAUDE_VERSION=2.1.283,
#           CENTRAL_HARNESS_APPROVAL_TIMEOUT=10m (30s–24h; §4a)
```

- `ELIGIBLE_AFTER` keeps the existing backlog out: Tasks submitted before it are never run. Set it to "now" when you first enable.
- An invalid value refuses the start (`CONFIG_INVALID`, the message names the variable).
- `CENTRAL_HARNESS_MAX_ATTEMPTS` (3g) is the attempt ceiling of one Run: the highest number of Steps a Run may reach, and so at most `N - 1` resumes. Default `3`, range 1–10; **`1` disables Resume** (the task page then shows "Resume is unavailable: attempt limit reached" in place of the button, §8). It counts the Steps of one Run, not the attempts across Retries (a Retry is a new Run with its own count). Like every harness variable it is read and validated only while `CENTRAL_HARNESS_ENABLED=1`: a value outside 1–10 or a non-number then refuses the start (`CONFIG_INVALID` naming the variable), and while harness execution is off the variable is ignored and Resume is not offered.
- The claude version is pinned: a different installed version fails each attempt `harness_launch_failed` until you set `CENTRAL_HARNESS_CLAUDE_VERSION` (after checking it is compatible). See "After updating Claude Code" below.
- Restart serve. Check `curl -s http://127.0.0.1:9090/health/harness`:
  `{"state":"running","active":0,"lost_runs":[],"settle_failed_runs":[],"needs_restart":false}`.

To disable, remove `CENTRAL_HARNESS_ENABLED` (or set it to `0`) and restart. Attempts that were running are reconciled at that start anyway.

### After updating Claude Code

An update installs a new executable (a new path under `~/.local/share/claude/`), while the launcher still runs the old one and serve still pins the old version.

1. Rerun `sudo packaging/harness/setup.sh --yes`. It prints the diff of the `harness claude <path>` line and exits 3 without changing anything.
2. Edit that one line of `/etc/central/harness-launcher.conf` to the new path from the diff (the launcher rereads the file on every request).
3. Check the new version is compatible, set `CENTRAL_HARNESS_CLAUDE_VERSION` to it in serve's environment, and restart serve.
4. Rerun `setup.sh`: it now reports `harness-launcher.conf is current`.

## 4a. Permission policies (phase 3c)

While harness execution is enabled, the submit form offers **Tool permissions**. With it disabled the form has no choice and every Task is Deny; a submission that asks for another policy then fails with 400. The policy is recorded on the Task (`tasks.permission_policy`), shown on its detail page, and never changes: a Retry keeps it and a Rerun copies it.

| Policy | Claude Code runs with | A tool that is not pre-allowed |
|---|---|---|
| **Deny** (default) | `--permission-mode dontAsk` | is denied; the task log shows `harness.permission denied` |
| **Bridge** | `--permission-mode manual --permission-prompts host --permission-prompt-tool stdio` | waits for your Allow or Deny on the task's detail page |
| **Auto-allow** | `--permission-mode bypassPermissions` | runs without asking |

**Auto-allow** needs the acknowledgement checkbox (without it the submission fails with 400), and its detail page carries the warning "Auto-allow: the harness runs every tool without asking, and can change your own Claude Code settings." The sandbox, egress policy and event recording apply as for any Run.

### Answering a Bridge request

1. Every `/app` page shows "N harness permission request(s) waiting" while any request of your Workspace is pending; the link opens the Task of the oldest one. A new request appears within one poll of the detail page.
2. The detail page's **Permission request** panel shows the tool, the tool call id, the resources the harness named, the input size, the time left and **the whole input**: never truncated, each top-level field in its own box under its own name with its line count and size, its key shown JSON-quoted, each top-level string decoded (a Bash `command` with its real newlines), HTML-escaped, shown left to right in the order it was written, and every invisible or direction-changing character shown as a marker such as `⟦U+202E⟧` (controls, every Unicode default-ignorable character including the variation selectors and the tag characters, and the line and paragraph separators) in both keys and values; a literal `⟦` is itself shown as `⟦U+27E6⟧`, so input text cannot pass for a marker. Read it all before you answer. An input that repeats a member name, or that is not one well-formed JSON value (trailing data, say), is ambiguous: Claude Code's adapter refuses it (the Task fails with `permission_bridge_unavailable`), and should the page ever see one it can only be denied. The page does not refresh itself while the panel is shown.
3. Press **Allow** or **Deny**. The decision is recorded as `operator-session:<your session principal>` and the harness continues. Requests are answered one at a time; a request that arrives meanwhile waits and gets its own panel.
4. "This request is no longer pending." means your decision no longer applied: the request expired, was already answered, the Run lost its lease, ended or is stopping, serve restarted since the page was loaded, or the page showed an older input. Nothing reached the harness: Allow and Deny alike are accepted only while this serve process still waits to deliver the answer. In a rare race, when the Run starts stopping between that check and the database write, a decision can be recorded (the page may even accept it and the history list it) that the harness never received. That case fails safe: nothing runs on it, and the Run is stopping.

Without an answer, the request is denied after `CENTRAL_HARNESS_APPROVAL_TIMEOUT` (default `10m`, `30s`–`24h`; an out-of-range value refuses the start). The Run's wall clock (§4b) keeps running meanwhile. The history under the panel lists the Run's last 20 requests with their outcome (`allowed`, `denied`, `expired`, `superseded`), who decided and when.

- **The input is never stored.** It lives only in serve's memory while its request is pending. PostgreSQL holds its size and an HMAC-SHA256 under a random key serve creates at start and never stores; the task log records only the tool name and the outcome.
- **`harness_events.raw_sha256` is keyed too.** Since 3c the column holds HMAC-SHA256 of each raw harness frame under that same per-process key, for every event, not the frame's plain SHA-256: a frame can carry a tool input, a tool result or a message with a secret, and a plain hash would let anyone who reads the database confirm a guessed one. The column keeps its name. The digest only identifies a frame within the serve process that recorded it; nothing compares it across restarts.
- **An input over 256 KiB is never bridged:** the adapter denies it at once (`harness.permission denied`, reason `input_too_large`).
- **The task detail page's response cap is 8 MiB** (`web.TaskDetailResponseCap`), so any bridged input of up to 256 KiB renders in full.
- **Allow is bound to what you saw:** the decision carries the input's MAC, and the adapter checks the exact bytes it sends back to Claude Code against it.
- **Deny as well as Allow needs the request to be held by the running serve.** After a serve restart or a lost lease, a pending request cannot be answered: the panel says "Waiting for restart reconciliation, or the run is stopping" with no buttons. At the next start the recovery gate marks the attempt ambiguous and the request `superseded`; resolve the Task with §8.
- **Once a cancel or a budget bound (§4b) stops the Run**, its pending request can no longer be answered either (the same panel text, no buttons): the harness is being stopped, and the terminal write marks the request `superseded`.
- **Fail closed.** If a request cannot be recorded or answered safely (the approval cannot be written, the answer cannot be delivered or does not match the shown input, more than 16 requests queue up, Claude Code sends a malformed or duplicate request, or Claude Code resolves a request Central never answered or one that was still queued), the harness is stopped and the Task fails with `permission_bridge_unavailable`. Nothing is ever allowed on a failure. Check the serve log and PostgreSQL, then resubmit.

### Your own Claude Code settings still apply (residual risk)

Claude Code runs with `--setting-sources user`, so your `~/.claude/settings.json` applies to every policy; Central does not relocate or rewrite it (governing design §9). The submit form says so next to the choice: "Your own ~/.claude permission rules and hooks also apply."

According to the Claude Code documentation (this was not re-checked live on 2.1.283; the maintainer must verify it on the pinned version before relying on it):

- **`permissions.allow` rules** decide before the permission prompt: a tool call they match runs without a `can_use_tool` request, under Bridge (`manual`) and under Deny (`dontAsk`) alike. `permissions.deny` rules deny without asking, and `ask` rules prompt (Bridge) or deny (Deny).
- **`PreToolUse` hooks** run before the rules and the prompt; a hook that answers "allow" lets the tool run without asking, under every policy. A hook that answers "deny" blocks it.
- **`defaultMode`** does not apply: the command-line `--permission-mode` overrides it, and the adapter refuses a session whose reported mode is not the policy's.

So a tool you pre-allowed, or a hook that allows it, never reaches the bridge and runs even under Deny. **The integrity of those files is not protected in 3c:** an allowed `Write`, `Edit` or `Bash`, or any Auto-allow Run, can change them for later Tasks and for your interactive sessions (see step 3). Keep the allow rules path-scoped with the `.git` deny rules, avoid allowing hooks you do not control, and prefer Bridge over Auto-allow. A read-only mount of the settings files is a follow-up that needs a launcher change (ADR 0036).

## 4b. Budgets (phase 3d)

Every harness Run has two bounds. You set them per Task in the submit form, which is shown above the task list (both fields are optional and appear only while harness execution is enabled); an empty field takes serve's default:

| Bound | Submit field | Serve default | Range | Enforced by |
|---|---|---|---|---|
| Cost | "Cost limit (USD)", a dollar amount with at most 2 decimals | `CENTRAL_HARNESS_MAX_COST_USD`, default `5.00` | 0.01–1000 | Claude Code itself (`--max-budget-usd`), and Central's backstop for harnesses that report cost while running |
| Wall clock | "Wall clock (minutes)", whole minutes | `CENTRAL_HARNESS_WALL_CLOCK`, default `30m` | 1 minute–24 hours (the variable accepts `1m`–`24h`) | Central's timer: interrupt, then kill after 30 s |

- An out-of-range or malformed `CENTRAL_HARNESS_MAX_COST_USD` refuses the start while harness execution is enabled (`CONFIG_INVALID`); while it is disabled the variable is ignored, like every harness variable. A malformed or out-of-range form value is refused (400), and so is any budget value while harness execution is disabled.
- The limits a Run ran under are **recorded on its attempt** when it starts, marked "(default)" when inherited. Changing a serve default later never changes what an earlier Task's detail page shows.
- Task detail shows the Run's limits and its usage: tokens in, tokens out, cache read, cache write and cost. Claude Code reports cost and cache reads only with each result (the last one at the end of the Run), so they appear then; since phase 3l its tokens in, tokens out and cache write also appear while it runs (a lower bound until the end, see "A token ceiling per attempt" below). **Since phase 3m the page never shows a placeholder as spend.** Until a result has arrived (no attempt of the Run has a cost or cache read above 0, and the latest attempt has not succeeded) the Cache read line is hidden and the Cost line reads "not reported yet (Claude Code reports cost and cache reads with each result)" while the latest attempt is still live, and "not reported (Claude Code sent no cost or cache reads before the attempt ended)" once it has ended (terminal, or `ambiguous`). An attempt that ends without a result (Central killed it after the grace, a `budget_tokens` stop included, or it was left ambiguous) therefore says "not reported" although it may have spent money, when no attempt of the chain reported cost or cache reads; if an earlier attempt of the same chain did report cost, the page shows the chain total instead, and that total leaves out the latest attempt's cost (it is not reported). The cost chain rule and the Task cost cap still count that attempt as 0 (the under-count described below). A result that carries cost 0 and cache read 0 on an attempt that did not succeed reads the same way: the page states what was received, not why the attempt ended. "estimated" means the harness says the cost is its own estimate.
- **Subscription logins:** the cost is Claude Code's own estimate, a proxy for your quota use, not a charge. The same note is shown next to the form fields.

When a bound stops a Run, the Task fails with one of four reasons, shown in words on task detail (the harness attempt ends `budget_exhausted`):

| Reason | Shown as | What happened |
|---|---|---|
| `harness_budget` | The harness stopped at its budget limit | the harness reached `--max-budget-usd` and ended with `error_max_budget_usd`. **Before 3d this reason also covered the wall clock**, so an older Task that shows it may have hit its wall clock instead |
| `budget_cost` | Central stopped the Run: the reported cost reached the limit | Central's backstop: a harness that reports cost while it runs reported at least the limit, and Central stopped it (not reachable with Claude Code, which reports cost only with its final result) |
| `budget_wall_clock` | Central stopped the Run: the wall clock limit was reached | Central's timer expired and it stopped the harness |
| `budget_tokens` | Central stopped the Run: the billed tokens reached the token ceiling | the attempt's billed tokens reached `CENTRAL_HARNESS_MAX_TOKENS` while it ran, and Central stopped it (see "A token ceiling per attempt" below) |

- **A Run can exceed its cost limit by about one API call.** Claude Code checks its limit between API calls, so the call that crosses it still completes and is billed (or counted against your quota). One call of a large model with a large context can cost tens of cents on its own: at a US$0.01 limit, the plan-stage check on 2.1.284 ended at an estimated US$0.36.
- **A success over the limit stays a success.** If the harness finishes successfully and only its final report puts it over the limit, the Run succeeds with its Artifacts; task detail marks the cost "over the limit".
- A harness failure of its own (for example `harness_api_error`) keeps its reason even when the reported cost is over the limit; only a stop Central caused becomes `budget_cost`, `budget_tokens` or `budget_wall_clock`.
- As with every non-success terminal, the patch and commits are captured best effort (§6), so the partial work stays inspectable.
- Tokens are capped only by the optional token ceiling of each attempt (below). There is no per-Workspace or daily spend limit.
- **A hung process is still reaped.** If a stop finds the session already ended but the process still hanging (a child holding its output open), Central kills it after the same 30 s grace; that late kill does not turn the harness's own result into a budget stop.

### Budgets across a resumed Run (phase 3g)

A Run that is resumed (§8) has **one cost budget for the whole chain of attempts**, not one per attempt:

- **The budget is the first attempt's.** The limits recorded on the Run's first harness attempt (cost limit, wall clock, and their "(default)" flags) are the chain's. Changing a `CENTRAL_HARNESS_*` default and restarting serve does not change them mid-Run.
- **Each resume runs under what is left.** The resumed attempt's recorded cost limit, which is also the `--max-budget-usd` Claude Code is given, is the first attempt's cost limit minus the cost recorded by every earlier attempt of the Run. Money does not multiply with resumes.
- **The floor is US$0.01.** With less than US$0.01 left, Resume is refused; the task page shows "Resume is unavailable: budget used up" and no button.
- **The wall clock is per attempt.** Each resumed attempt gets the first attempt's wall clock again; the attempt ceiling (`CENTRAL_HARNESS_MAX_ATTEMPTS`, §4) bounds the total.
- **Task detail shows the chain.** Limits are the first attempt's; tokens and cost are summed over the Run's attempts, and the cost line says "(across N attempts)" once there is more than one.
- **Known under-count.** Claude Code reports its **cost** only with its final result (see above); since phase 3l the tokens of the main conversation are recorded while the Run is live, from the usage of each response, but the cost is still recorded only from the final result. An attempt that ended ambiguous, because serve stopped before the result arrived, recorded **no cost**, though it may have spent money. The chain counts recorded cost only, so that spend is not subtracted from what a resume may use. The attempt ceiling and the wall clock bound it; nothing more exact exists.
- **Not yet verified on a real host: whether a resumed process starts its cost counter at zero.** The rule above assumes each Claude Code process reports its own cost from zero (the sanitized `resume.ndjson` fixture suggests so). If it instead continued from the earlier total, the sum would over-count and Resume would stop earlier than needed, and a resumed attempt could stop at its budget sooner than the remaining amount suggests: the failure is on the safe side, never an overspend. The maintainer check in §10 (phase 3g, item b) settles which holds; this paragraph is updated with the answer.

### A cost cap per Task across Retries (phase 3j)

A Retry (§8a) starts a new Run of the same Task with the per-Run budget again. `CENTRAL_HARNESS_TASK_COST_CAP_USD` bounds what all Runs of one Task may record together:

- **Default: five times the per-Run default** (`CENTRAL_HARNESS_MAX_COST_USD`), so US$25.00 with the default US$5.00; it follows the per-Run default when you change that. Range 0.01–100000, at most two decimals. A value below `CENTRAL_HARNESS_MAX_COST_USD` refuses the start (`CONFIG_INVALID` naming the variable), so the cap never shrinks the first Run of a Task that uses the serve default. Like every harness variable it is read only while harness execution is enabled; while it is disabled there is no cap and Retry is not gated.
- **What counts:** the cost recorded on every harness attempt of every Run of the Task, resumed attempts included. While harness execution is enabled, task detail shows `Task cost used: US$<used> of US$<cap>`.
- **Retry is gated.** With less than US$0.01 of the cap left, a failed Task shows `Retry is unavailable: this Task has used its cost cap` instead of the Retry button, and a Retry request is refused (409 `TASK_ACTION_FAILED`, nothing is written). The overview still lists such a Task as "Retry available"; its page explains. Resume, Mark failed, Mark cancelled and submitting are not affected. **Rerun is not capped by it:** a Rerun is a new Task and starts with its own cap; the cap does not follow a Rerun's lineage.
- **Each Run is clamped to what is left.** When a Run is claimed, its recorded cost limit (the `--max-budget-usd` Claude Code is given) is the smaller of its per-Run limit and what is left of the cap, and never below US$0.01. So a Retry after earlier spend runs under less than the per-Run limit; task detail shows that clamped figure as the cost limit, still marked "(default)" when the per-Run value came from the serve default, and the "Task cost used" line shows why. A Task that asked for more than the cap is clamped to the cap. As with any cost limit, a Run can overshoot by about one API call (see above), and a Run claimed with less than US$0.01 left (possible when the cap was lowered after the Retry was accepted, or when the Retry was accepted while harness execution was off or before phase 3j) still runs under the US$0.01 floor, so the cap can be exceeded by up to that much plus the overshoot.
- **Known under-count.** As for the resume chain (above), an attempt that ended without Claude Code's final result (serve stopped, the process was killed) recorded no cost, so the cap counts less than was spent.
- **If the cost read fails** when a Run is claimed, the Run is not started: it stays queued (a prepared successor stays prepared), and the dispatcher tries it again after its back-off (serve logs "harness run could not be started"). On the task page a failed read hides Retry without a message; a Retry request then answers 500 `TASK_ACTION_FAILED` and writes nothing.

### A token ceiling per attempt (phase 3l)

`CENTRAL_HARNESS_MAX_TOKENS` sets an optional ceiling on the tokens one harness attempt may use. Unset (the default) there is no token ceiling, as before.

- **What counts: billed tokens** = tokens in + tokens out + cache write, as recorded on the attempt and shown on task detail. Cache reads are not counted: every API call re-reads the whole context, so their sum grows with the length of the session without being new work.
- **The value** is a plain whole number from 100000 to 1000000000, without separators (`2000000`, not `2,000,000` or `2_000_000`). An out-of-range or malformed value refuses the start while harness execution is enabled (`CONFIG_INVALID` naming the variable); while it is disabled the variable is ignored, like every harness variable. **A fresh first response already costs about 30,000 to 35,000 billed tokens** (Claude Code writes its system prompt and tools to the cache), so a ceiling near the minimum stops a Run after its first few responses.
- **How it is enforced.** Claude Code has no token limit of its own. Central reads the usage Claude Code reports with each response while it runs and, once the attempt's billed tokens reach the ceiling, stops it the way the cost backstop does: it stops answering permission requests, interrupts the harness and kills it after 30 s. The Task fails `budget_tokens`, the attempt ends `budget_exhausted`, and the patch and commits are captured best effort (§6). The outcome rules are the other bounds': a success stays a success, a failure the harness reached on its own keeps its reason, the first bound that fired names the reason, and a cancel wins.
- **It can overshoot.** The check runs between API responses, and the stop then takes the interrupt and up to 30 s of grace, so an attempt can use one more response (and what it does during the grace) past the ceiling. The recorded tokens, which include Claude Code's final report, can therefore be above the ceiling.
- **The live count is a lower bound.** While the Run is live Central counts the main conversation only: tokens a subagent (the Task tool) uses are not counted until the final result, if at all, and a response's output tokens are reported only partially while it streams. So the ceiling can fire late, never early. An assistant frame whose content blocks the adapter cannot decode is not counted live either, like subagent frames and frames without a message id, so the count can only be low, never high. The recorded usage is the larger of the live count and the final result's figures, still marked "estimated".
- **Per attempt, not per Run.** A resumed attempt (§8) is a new Claude Code process and gets the full ceiling again, so a Run can use up to `CENTRAL_HARNESS_MAX_ATTEMPTS` times the ceiling, and each Retry is a new Run. The cost limit, the chain budget and the Task cost cap still bound the money across them. The ceiling is not recorded on the attempt and there is no per-Task token limit: a changed value applies to the attempts serve starts after its restart.

### Upgrading to phase 3d

- **A cost cap of US$5.00 now applies to every Run**, including Tasks submitted without a limit. Long or large-context Runs that finished before may now stop at it: raise `CENTRAL_HARNESS_MAX_COST_USD` (up to 1000) or set the limit per Task.
- **The wall-clock reason is renamed** from `harness_budget` to `budget_wall_clock`. History keeps the old name (see the table above).
- **Migration v32 is one-way.** It adds the budget columns to `tasks` (nullable) and to `harness_attempts` (required), and backfills every existing attempt with US$5.00 and 30 minutes, flagged "(default)". Those numbers were **not enforced** on the Runs that already ran: before 3d there was no cost cap, and the wall clock may have been configured differently. There is no down step, an older binary refuses the v32 chain, and recovery is a backup taken before migrating: take one first.
- An attempt that was prepared but never launched before the upgrade, and is adopted after it, runs with its backfilled US$5.00 and 30 minutes, not with the current `CENTRAL_HARNESS_WALL_CLOCK`. Attempts that had launched become ambiguous on restart (§8) and get no timer.
- The launcher accepts one more argument, `--max-budget-usd <amount>`, after `--model` (two decimals, `0.01`–`1000.00`). **Install the new launcher (`central-harness-launcherd`) together with the new serve**: an old launcher refuses the new argv and every Run fails at launch.

## 5. Give each Workspace a source repository

The harness never sees your working copy. Each Workspace has a bare source repository that you push to; a Run clones its default branch.

```bash
sudo packaging/harness/setup.sh --workspace <workspace-id>
# then, in your project, from your normal session:
git config --global --add safe.directory /var/lib/central-harness/sources/<workspace-id>.git   # once per source
git remote add central /var/lib/central-harness/sources/<workspace-id>.git
git push central HEAD:main
```

The repository is created by `central-runtime` with `core.sharedRepository=0664`, so every object you push is readable by the runtime whatever your umask. A source created by an earlier `setup.sh` (`--shared=group`) can be repaired once with `sudo -u central-runtime -H git --git-dir=/var/lib/central-harness/sources/<workspace-id>.git config core.sharedRepository 0664 && sudo chmod -R o+rX /var/lib/central-harness/sources/<workspace-id>.git`.

The source is owned by `central-runtime`, so git refuses it until you trust it. Trust exactly that path in your own `~/.gitconfig`, as above; `git -c safe.directory=…` does not work here (git does not pass it to the local receiving side). Only you and the runtime can write a source repository.

The local-first instance has one Workspace: `019fdc8d-e33a-76ed-9ef0-a0d9fe92e54a`. A Task whose Workspace has no source (or an empty one) fails `workspace_unavailable`.

The harness's commits stay in the Run clone, and its work also reaches you as Artifacts (§6). **Treat the clone's `.git` as untrusted**: the harness wrote it, and its config (`core.fsmonitor`, `core.pager`, hooks, aliases) would run commands as whoever runs git inside it. So:

- never `cd` into a Run clone (a shell prompt with git integration runs `git status` on its own), never run `git -C <clone> …`, and never open it in an editor with git integration;
- inspect it only from your own checkout, by fetching (upload-pack reads the clone without running its config):

```bash
# in your project checkout, from your normal session:
git fetch /var/lib/central-harness/worktrees/runs/<run-id>/repo HEAD:refs/harness/<run-id>
git log -p main..refs/harness/<run-id>      # review
git merge refs/harness/<run-id>             # or cherry-pick, then push as usual
```

Plain files can be read with `cat`/`less`, never with git inside the clone. Root must not run git there either.

While Central captures a Run's Artifacts (from the harness's end until the clone has been read, at most the 2-minute capture deadline), the Run directory is **sealed**: your ACL entry on `runs/<run-id>` is removed and the directory is `0700`, so a fetch then fails with "Permission denied". Retry once the task shows its final status: capture restores exactly the access the installation granted, on success and on failure alike. Only a serve stop in the middle of a capture leaves a Run sealed; restore it with `sudo setfacl -m u:<operator>:rwx,u:central-runtime:rwx,d:u:<operator>:rwx,d:u:central-runtime:rwx,d:m::rwx /var/lib/central-harness/worktrees/runs/<run-id>`. The patch Artifact is an alternative to fetching: download it from the detail page and `git apply` it at the base commit (the commits Artifact's "before HEAD").

## 6. Artifacts and failure reasons

When the harness reports success, Central, in order: seals the Run (the operator's access to `runs/<run-id>` is removed for the capture's duration and the clone root must be a real, runtime-owned directory); builds the patch in a shadow repository `capture/<run-id>.git` it owns, which holds none of the clone's objects, and reads the commit list through a second shadow `capture/<run-id>-log.git` that holds copies of them (the clone's `.git` config, hooks and attributes are never used, and no symlink is followed); stores the **patch** and then the **commits** Artifact; and finally stores the **report** Artifact, whose commit also completes the Task and Run. The operator's access to the Run is restored as soon as the clone has been read. The task log shows `harness.artifacts captured`. The capture files are removed once the Run settles.

| Artifact | Content | Limit |
|---|---|---|
| Report | the harness's last complete assistant message (Markdown) | 1 MiB |
| Patch | `diff` of the final clone (commits, uncommitted and untracked files) against the base | 10 MiB |
| Commits | before HEAD (the base), after HEAD (or `unavailable`) and up to 1,000 harness commits; a history git cannot walk shows `commits: unavailable` instead of the list, and the Run is not failed | 1 MiB |

Known limit: the detail page's download route buffers at most 2 MiB and its preview at most 128 KiB, so a patch larger than 2 MiB is stored but cannot be downloaded from the page yet.

Every body passes the Artifact classifier: a body that discloses a credential (a private key, `AWS_SECRET_ACCESS_KEY=`, a provider token, …) is **rejected and not stored**. If anything fails, the Run and Task end `failed` with one of these reasons (the harness attempt itself stays `succeeded`, and Artifacts already stored stay attached):

| Reason | Meaning | What to do |
|---|---|---|
| `artifact_capture_failed` | sealing, git or I/O failed, or capture exceeded its 2-minute deadline (for example a FIFO the harness left in the clone, or a file or directory only the harness can read) | inspect the retained clone as root (plain files), fix the cause, resubmit |
| `artifact_rejected` | the classifier refused a body (suspected secret, binary content, or text that is not UTF-8) | remove the secret from the work and resubmit; rotate the credential if it was real |
| `artifact_too_large` | the patch, commits or report exceeded its limit | split the work into smaller Tasks |
| `artifact_quota_exceeded` | the Workspace's Artifact quota has no room | free Artifacts, or raise the quota |
| `harness_report_missing` | the harness ended without a final message | resubmit |
| `permission_bridge_unavailable` | a Bridge request could not be recorded or answered safely, so the attempt failed closed (§4a) | check the serve log and PostgreSQL, then resubmit |
| `harness_budget` | the harness stopped at its own budget limit (§4b; before 3d it also covered the wall clock) | resubmit with a higher cost limit (or a longer wall clock for an older Task), or split the work |
| `budget_cost` | Central stopped the Run because the reported cost reached the limit (§4b) | resubmit with a higher cost limit, or split the work |
| `budget_wall_clock` | Central stopped the Run at its wall clock limit (§4b) | resubmit with a longer wall clock, or split the work |
| `budget_tokens` | Central stopped the attempt because its billed tokens reached `CENTRAL_HARNESS_MAX_TOKENS` (§4b) | raise or unset the ceiling and retry, or split the work |

The four budget reasons are not capture failures: the harness attempt ends `budget_exhausted`, and the patch and commits are captured best effort as below.

Capture's pre-walk of the clone also walks `.gitignore`d trees (for example a checked-out `node_modules`); those entries still count towards the 1,048,576-entry limit and the 2-minute deadline, so a very large ignored tree can fail capture with `artifact_capture_failed` even though git itself would never see it. A base gitlink whose submodule was never initialised shows as `-Subproject commit <sha>` in the patch, not as a diff of the submodule's contents.

When an Artifact's outcome is unknown (an object-store or database error at the commit), Central never guesses: the Task becomes `waiting (reconciliation)`, as after a serve stop mid-capture, and you resolve it with §8.

For a failed, interrupted, killed or over-budget attempt, the patch and commits are captured **best effort**; the Run keeps the harness's own reason (for a budget stop, the reason that names the bound, §4b), and a capture problem only shows as `harness.artifacts partial` in the task log. A cancelled Task captures nothing.

## 7. Pause states

The dispatcher probes Claude Code before claiming work. When it cannot run, it **pauses**: it claims nothing and fails nothing, and it re-checks every 30 s. Every `/app` page shows a banner, `/health/harness` shows `"state":"paused"` and the reason, and each waiting Task's activity shows `harness.dispatch paused` (then `harness.dispatch resumed`).

| Reason | Fix |
|---|---|
| `not_logged_in` | run `claude` as the operator and log in |
| `launcher_unreachable` | `systemctl status central-harness-launcher.socket central-harness-launcher.service`; `journalctl -u central-harness-launcher` |
| `low_disk` | free space under `/var/lib/central-harness` (below `CENTRAL_HARNESS_MIN_FREE`); see §9 |

`lost_runs` in `/health/harness` lists Runs whose lease was lost while serve kept running (for example a long PostgreSQL stall), and Runs whose start may have committed without serve seeing the result (for example a connection drop at commit); `settle_failed_runs` lists Runs whose terminal settlement write failed permanently. `needs_restart` is `true` whenever either list is non-empty, and the `/app` banner then shows "N harness run(s) need a serve restart to be reconciled." Both sets stay as they are until the next serve start reconciles them (§8).

## 8. Ambiguous attempts

When serve stops (or loses a Run's lease) while a harness runs, Central cannot know whether the harness finished. The launcher kills the session when serve's connection closes. At the next start the recovery gate makes the Task `waiting (reconciliation)` and the attempt `ambiguous`; nothing retries it. A serve stop during artifact capture, or an Artifact commit whose outcome is unknown (§6), also leaves the Task `waiting (reconciliation)`; the attempt then stays `succeeded`, and the same actions apply.

The task's detail page then shows the **Harness attempt** panel and hides Cancel. Its buttons are, in this order, **Resume** (only when it is available, see below), **Mark failed**, **Mark failed and rerun** (only when it is available, see below) and **Mark cancelled**. Each says "By marking, you confirm that the harness is no longer running." (Resume says "By resuming, you confirm that the harness is no longer running."):

- **Resume** (3g): continue the same Claude Code session, in the same clone, as a new attempt of the same Run. See "Resume" below.

- **Mark failed (operator resolved)**: the Task and Run end `failed` with reason `operator_resolved`. Retry it (§8a) if you want it run again.
- **Mark failed and rerun (operator resolved)** (3k): Mark failed, then Retry, in one action: the same Task runs again as a new Run, in a fresh clone. See "Mark failed and rerun" below.
- **Mark cancelled (operator resolved)**: the Task and Run end `cancelled`; Rerun it (§8a) if you want it run again. This requests the cancellation and resolves the attempt in one action (two commits: if the second fails, the Task is left "Settling" with the same button, and pressing it again finishes it).

After Mark failed or Mark cancelled the attempt is `resolved (abandon)`; after Resume it is `resolved (resume)`; after Mark failed and rerun it is `resolved (rerun)`. Before any of them:

1. Fetch the Run clone into your own checkout and keep what you want, exactly as in §5 (never run git inside the clone), or use any Artifact already listed on the detail page. A Run whose capture a serve stop interrupted is still sealed: restore your access first (§5).
2. Make sure the harness is not running (the launcher killed it when serve stopped; the next dispatcher start also kills any surviving scope).

### Mark failed and rerun (phase 3k)

**What `resolved (rerun)` means.** The operator resolved the ambiguous attempt by running the same Task again as a **new Run**: a Retry, with a fresh clone from the source repository's HEAD and no session continuity. It is the counterpart of `resolved (resume)` (the same Run continues the same session, see "Resume" below) and of `resolved (abandon)` (the attempt is closed and nothing follows). The adapter-boundary design's "rerun (new Run)" is this meaning. It is **not** the Task-level **Rerun** of a cancelled Task (§8a), which creates a new Task: that one still follows Mark cancelled, whose attempt is recorded `resolved (abandon)`.

**When the button shows.** All of these hold, read fresh each time the page renders:

- harness execution is on (with it off nothing would claim the new Run);
- the Task is `waiting (reconciliation)` (never a `cancelling` or `cancelled` Task) and the Run's harness attempt row is `ambiguous` (an attempt that stayed `succeeded` after a capture stop, §6, can only be marked);
- no unexpired lease holds the Run;
- the Task was created at or after `CENTRAL_HARNESS_ELIGIBLE_AFTER` (§4), else the dispatcher would never claim the new Run;
- at least US$0.01 of the Task cost cap is left (§4b "A cost cap per Task across Retries"), exactly as for Retry.

Otherwise the button is simply absent (no message); Mark failed and Mark cancelled stay.

**What it does.** Pressing it (`POST /app/tasks/harness/resolve` with `action=rerun`, the same POST prelude and the same attestation as Mark failed; the operator authority is the session's principal, `operator-session:<principal>`) re-checks every condition above and then runs three steps in this order: (a) the commit of Mark failed (`ResolveReconciliation` with `ConfirmFailed`, idempotency key `harness:rerun:<attempt id>`): the Task and Run end `failed` with reason `operator_resolved`; (b) a Retry of the Task through the task domain, exactly as the Retry button commits it (key `harness:rerun-retry:<attempt id>`): a new Run of the same Task (the next Run index) is `queued`, with the Task's permission policy and budget, clamped by the Task cost cap; (c) the old harness attempt row becomes `resolved (rerun)`, decided by `operator-session:<principal>`. The page then shows the Task `queued` and the dispatcher claims the new Run.

**Refusals and failures.** Once the request is admitted (a wrong Origin or CSRF token is still 403 and a malformed form 400), every answer other than success is a plain 409 `TASK_ACTION_FAILED` (the resolve route answers 409 for every error, a live lease included); reload the page. A condition that no longer holds (the eligibility floor, the cost cap, a lease, a second tab or a double click that already used it, a Task cancelled meanwhile) is refused **before anything is written**. If step (a) fails, nothing changed, unless the request was aborted after (a) committed but before the reply: the Task is then already `failed` with reason `operator_resolved`, the state described next. If step (b) fails after (a), the Task is `failed` with reason `operator_resolved` and the ordinary **Retry** button applies; the attempt stays `ambiguous` until the next serve start, whose reconciliation records it `resolved (abandon)`. If step (c) fails after (b), serve only logs it (`harness rerun: the Task was retried but the harness attempt row was not recorded resolved(rerun); ...`) and the new Run proceeds.

**Known label caveat.** Step (c) is written last, so the label is only written once the new Run exists. If serve stops between (b) and (c), the next start's reconciliation records the old attempt `resolved (abandon)` although the Task was rerun; Central does not relabel it. The Run history on the Task page still shows the new Run.

### Resume (phase 3g)

**When the button shows.** All of these hold, read fresh each time the page renders:

- harness execution is on and `CENTRAL_HARNESS_MAX_ATTEMPTS` (§4) is at least 2;
- the Task is `waiting (reconciliation)` (never a `cancelling` Task, which can only be marked cancelled);
- the Run's harness attempt row is `ambiguous` **and has a recorded session id** (an attempt that died before Claude Code reported its session has none: no Resume button, and no message either, only Mark failed and Mark cancelled);
- no unexpired lease holds the Run (a serve that is still running the attempt, or a lease that has not yet expired);
- the attempt ceiling and the chain budget allow it (§4b).

An attempt whose serve stopped during artifact capture, or whose Artifact commit was unknown (§6), stays `succeeded`, not `ambiguous`: it cannot be resumed, only marked.

**When the only obstacle is the eligibility floor, the ceiling or the budget**, the panel shows one line in place of the button, and the obstacles are checked in this order: `Resume is unavailable: this Task was created before harness execution was enabled` (phase 3h: the Task is older than `CENTRAL_HARNESS_ELIGIBLE_AFTER`), then `Resume is unavailable: attempt limit reached` (the new Step would exceed `CENTRAL_HARNESS_MAX_ATTEMPTS`; with the value `1` you always see this line), then `Resume is unavailable: budget used up` (less than US$0.01 of the chain budget left). Mark failed and Mark cancelled stay available.

**What it does.** Pressing Resume (`POST /app/tasks/harness/resume`, the same POST prelude as Mark failed: same-origin, the session's CSRF token, an active session, and serve's recovery-claimability gate; the operator authority is the session's principal, `operator-session:<principal>`, never a form field) commits, in one transaction: the old Step and attempt end `failed` with the reconciliation disposition `resume` and your attestation; a **new Step** (sequence + 1) holds a new attempt in `prepared` state whose predecessor is the old one; the Task and Run go back to `running`. The Run and its ownership are kept; nothing is re-queued. Afterwards the old harness attempt row becomes `resolved (resume)`. The dispatcher then claims the new attempt and launches `claude --resume <session id>` **in the same clone**, with one fixed prompt, `Continue the task from where the previous run stopped. When finished, give the final report.` The Task's original instruction is not sent again, and nothing you type reaches the harness. The clone is reopened without running git and without reading its content; Central never provisions it again, so your retained work is not deleted. The resumed attempt runs under the Task's permission policy and under the remaining chain budget (§4b).

**`CENTRAL_HARNESS_ELIGIBLE_AFTER` (phase 3h).** The dispatcher only lists Runs whose Task was created at or after `CENTRAL_HARNESS_ELIGIBLE_AFTER` (§4), for a resumed attempt (`prepared_successor`) as well as for a queued one. Resume is therefore neither offered nor accepted for a Task created before that time: the panel says `Resume is unavailable: this Task was created before harness execution was enabled`, a forced POST is refused as a plain 409 and writes nothing, and Mark failed and Mark cancelled stay available. **Remaining limitation:** if `CENTRAL_HARNESS_ELIGIBLE_AFTER` is moved later after a Resume has committed and before its attempt is claimed, that Task stays `running` and unclaimed, because the dispatcher no longer lists it. The way out is Cancel, then **Finish cancelling** (3f, below).

**A live lease.** If a lease still holds the Run, nothing is written and the answer is a plain 409 with the text "The harness is still starting. Try again in a moment.": wait for the lease to expire and press it again. Any other refusal (the Task moved on or was cancelled meanwhile, a second tab or a double click already used it, the eligibility floor, the ceiling or the budget) is a plain 409 `TASK_ACTION_FAILED`; reload the page. **An unexpected error inside Central** (for example the database is unreachable) is, since phase 3i, a plain **500** `TASK_ACTION_FAILED` with no detail, not a 409: reload the page; if the Task is `running`, the Resume went through; if it is still `waiting (reconciliation)`, press Resume again. Mark failed and Mark cancelled are unchanged and still answer 409 for any failure.

**If the harness row write fails after the commit.** The commit is what matters: the Task is already `running`. If the write of `resolved (resume)` on the old harness row fails, serve only logs it (`harness resume: the execution side committed but the harness attempt row was not recorded resolved(resume); ...`) and the page still redirects normally. The claim of the new attempt completes that write before it launches, or the next serve start's reconciliation does.

**A restart before the launch loses nothing.** If serve stops between the commit and the claim, or after the resumed attempt's row was created and before it was launched, recovery keeps the prepared attempt and the next claim resumes the same session in the same clone. A Cancel before the claim goes through the ordinary cancel of a claimed Run: it shows **Finish cancelling** (3f, above).

**After a resume it is an ordinary attempt.** It can succeed (report, patch and commits are captured as in §6), fail, hit its budget (§4b), be cancelled (3e), or go `ambiguous` again after another serve stop (then Resume again, up to the ceiling). Its Step is the one the page and the attempt ceiling count. A failed resumed attempt leaves the Task `failed`, and **Retry remains** (§8a; a Retry starts a fresh Run, with a fresh clone and a fresh attempt count).

**Failure behaviour you may see:**

| What happened | What you see |
|---|---|
| The Run's clone is missing, replaced, sealed by a capture that died half-way, or the free space under the data root is below `CENTRAL_HARNESS_MIN_FREE` | the resumed attempt is abandoned `workspace_unavailable` and the Task fails; Retry remains. Central never repairs or re-creates the clone for a resume |
| The chain budget was found used up at the claim (a race with the page, or spend recorded after you pressed Resume) | the attempt is abandoned `budget_cost` and the Task fails; Retry remains |
| The recorded session cannot be found (the session file is gone, or `--resume` does not behave as recorded in the 2a spec) | `claude --resume` exits non-zero and the attempt fails like any attempt; the Task fails with the reason the page shows; Retry remains |
| The adapter cannot resume, or a later Step has no resumable predecessor (an internal inconsistency) | the attempt is abandoned `execution_failed` and the Task fails; Retry remains |

**Resume relies on two things that only the maintainer's reference-host check proves** (§10, phase 3g items a to c): that the session file survives in the launcher's harness home (§2) between one launch and the next, so `--resume` finds it after serve restarted; and that `--resume` behaves as the 2a spec records. The fake-harness tests prove Central's side only. If either fails on your host, you will not see a special error: the resumed attempt fails as in the table above and the Task shows `failed`. Retry starts over from a fresh clone.

**Cancelling and ambiguous.** If you pressed Cancel while the harness ran and serve stopped before the cancel settled (or you cancelled a Task that was already `waiting (reconciliation)`), the next start leaves the Task "Settling" (`cancelling`) with its attempt `ambiguous`; recovery no longer quarantines the Workspace for it (3e). The page shows "Settling: the harness stopped when serve stopped. Confirm it is not running, then Mark cancelled." and only **Mark cancelled (operator resolved)**. A cancelling Task's staged report is never promoted: cancel wins.

**Cancelled before the harness launched (3f).** A Task you cancelled while its attempt was claimed but never invoked shows **Finish cancelling**, for example a Task whose serve stopped before the harness launched and which waits for re-dispatch (a *prepared successor*). The button ends the attempt, Step, Task and Run `cancelled` in one commit. It runs the execution `Cancel` command as a Workspace operator (principal `operator-session:<your session principal>`, the same POST prelude as Cancel). The harness attempt row, if one exists, becomes `failed (harness_not_launched)`. Nothing was launched, so no attestation is needed. If the dispatcher is claiming that attempt at that moment, the page answers "The harness is still starting. Try again in a moment."; press it again a few seconds later. If the attempt was invoked meanwhile, the harness is running: its own cancel settles it within one heartbeat, and after a serve restart it becomes the "Cancelling and ambiguous" case above. Until then, pressing the button answers a plain 409 and the page shows "Settling".

Pressing **Mark cancelled** on a Task that is already cancelled (a second tab, a double click) shows "Already cancelled."; a Cancel that loses the race with the dispatcher's start shows "The Task started. Press Cancel again.".

Authority: Resume, Mark failed, Mark failed and rerun and Mark cancelled are each a same-origin POST with the session's CSRF token, like Cancel. The disposition of the Mark actions comes from the Task's durable status (a `cancelling` Task can only be marked cancelled), never from the form. Mark failed, Mark failed and rerun and Mark cancelled run the execution `ResolveReconciliation` command as a Workspace operator whose principal is `operator-session:<your session principal>`, derived only from the validated session, with that operator's attestation; Mark failed and rerun then commits the Retry through the task domain, as the Retry button does. Resume runs its own command, `ResumeReconciledAttempt`, under the same operator authority and attestation. All four are refused while a live lease still holds the Run. Central never offers "confirm succeeded": a harness Run completes only with its report Artifact.

## 8a. Retry and Rerun

- **Retry** (a `failed` Task, whatever its reason, including `operator_resolved` and the budget reasons) creates a new Run of the same Task. The new Run gets a **fresh clone** from the source repository's HEAD: the earlier Run's work is not continued (that is what Resume, §8, is for), and its clone and attempt are kept as they were (fetch from them as in §5). On a `waiting (reconciliation)` Task with an ambiguous attempt, **Mark failed and rerun** (§8) marks it failed and retries it in one action.
- **Rerun** (a `cancelled` Task) creates a new Task linked to the cancelled one. It copies the permission policy and the budget.
- Each Run gets the Task's **per-Run budget** again (§4b), **clamped to what is left of the Task cost cap** (`CENTRAL_HARNESS_TASK_COST_CAP_USD`, default five times the per-Run default; §4b "A cost cap per Task across Retries"). Once less than US$0.01 of the cap is left, Retry is unavailable: the page shows `Retry is unavailable: this Task has used its cost cap` and a Retry request is refused (409). The attempt ceiling and the chain budget of §4b are per Run; the cap is per Task, and a Rerun starts a new Task with its own cap.
- A retried Task keeps its original creation time. A Task created before `CENTRAL_HARNESS_ELIGIBLE_AFTER` is queued by the Retry but never dispatched; resubmit it instead.

### Upgrading to phase 3e

No migration. Start with this check, because it decides what the rest of this list means:

1. **Is any Workspace already quarantined?** Look in serve's start log for the line `recovery epoch <generation> is degraded; to resume set ...` (serve writes it at every start with a degraded or failed epoch), or ask the database for the newest recovery epoch: `SELECT epoch_generation, state, retry_attempt FROM central.recovery_epochs ORDER BY epoch_generation DESC LIMIT 1;` (`degraded` or `failed` means quarantined). `/health` does not expose the recovery epoch. A recovery epoch that an earlier release already degraded **stays degraded**: recovery reopens a degraded epoch only through the fenced, operator-acknowledged resume (B08), and a start does not clear it. While it is degraded, the Workspace's older Runs stay barred, the task page shows only "Restart barrier active" with **no buttons**, and every action on them is refused. From phase 3f you resume it yourself: see "Recovery epoch resume (phase 3f)" below. The 3e recovery only stops **new** quarantines from a cancel; such a Workspace can exist only where a Task was cancelled with an invoked harness attempt, so the harness must have run.
2. **If no Workspace is quarantined, or after the epoch has been resumed**, the first start of the 3e binary does this:
   - An old Task cancelled while queued (never started) shows **Finish cancelling**; press it to end it `cancelled`.
   - An old `cancelling` Task whose attempt was prepared but never launched (or had a prepared successor) is ended `cancelled` by the start itself; its attempt shows `failed (harness_not_launched)`.
   - An old `cancelling` Task whose attempt was invoked waits "Settling" with an `ambiguous` attempt: use **Mark cancelled** (§8). Once the epoch is resumed, the whole batch that the old recovery had rolled back is reconciled at once.
3. The report of a harness Run is now the final answer of the `result` frame (the top-level agent), no longer the last text block, which could come from a subagent.
4. **Do not run the pre-3e binary again** while a Task is `cancelling` with an ambiguous attempt: the old recovery would degrade that Workspace's epoch again. Roll back only from a backup taken before the upgrade.
5. A Task that is `cancelling` with a claimed Run and no attempt cannot arise through the harness (a claim and its attempt are one commit), so it needs no control. If one ever appears (for example from a hand-edited database), it stays "Settling"; report it as a bug.

### Recovery epoch resume (phase 3f)

A recovery epoch that an earlier release degraded stays degraded until you acknowledge it. At every start with a degraded or failed epoch, serve logs the exact values to set (the log says `failed` instead of `degraded` when the epoch is `failed`):

`recovery epoch 7 is degraded; to resume set CENTRAL_RECOVERY_RESUME=7:2 and CENTRAL_RECOVERY_RESUME_REASON=...`

1. Take the pair from that log line, or read it in SQL: `SELECT epoch_generation, state, retry_attempt FROM central.recovery_epochs ORDER BY epoch_generation DESC LIMIT 1;` (`state` `degraded` or `failed` means quarantined). `/health` does not show it. Make sure you understand why the epoch degraded, for example the pre-3e cancel behaviour (see "Upgrading to phase 3e").
2. Add both variables to serve's environment, together, in the same place as §4:

   ```bash
   CENTRAL_RECOVERY_RESUME=7:2    # <generation>:<retry_attempt>, exactly as the log line or the SQL shows them
   CENTRAL_RECOVERY_RESUME_REASON="pre-3e cancel quarantine, upgraded to 3f"
   ```
3. Restart serve. The startup gate resumes the epoch under serve's own recovery lease and drains it in the same start, before serve accepts traffic. Check that:
   - the newest epoch is `completed` in the SQL above (this is the check that decides success: the `to resume set` hint is logged before the drain, so a re-degraded epoch is not visible in that start's log);
   - the log shows `recovery epoch 7 resumed at retry attempt 3; ...`;
   - the Workspace's older queued Tasks are dispatched.
4. **Remove both variables.** Until you do, they do nothing: after the resume the epoch's retry count is higher, so the pair no longer matches.

Rules:

- **Both or neither.** Serve refuses to start (`CONFIG_INVALID`, the message names the variable) in each of these cases, even with harness execution off:
  - one variable is set without the other;
  - the pair is not `<generation>:<retry_attempt>`;
  - the reason is blank or over 500 characters;
  - the reason contains a control or formatting character: tab, newline, zero-width, direction marks, U+2028, U+2029.
- **A pair that does not match does nothing.** This covers other numbers, and an epoch that is running or completed. The log says `recovery resume not applied: epoch is <state> at <generation>:<retry>`.
- **The reason is stored and logged.** It is kept in the `execution.recovery.resumed` event and its outbox row, retained like any event, and it is written to the log. **Never put a secret in it.** Central appends the affected Workspace ids: at most 50, then `(+N more)`. The event is recorded under the lowest of those Workspaces, with principal `serve:recovery-resume-ack`.
- **The pair is not bound to a database.** After a restore from backup, or after pointing serve at another database (a changed DSN), a leftover pair applies again if that database has a degraded epoch with the same numbers. Remove the variables after the resumed start.
- **A downgrade to phase 3e ignores the variables.** A 3e serve does not read them.
- **If a Workspace's rescan fails again**, the epoch degrades again with a higher retry count. The old pair is then stale, the Runs stay quarantined, and the next start's log names the new pair (or read it in the SQL above). Find the cause before you acknowledge again.
- **Safety does not rest on the pair.** A Workspace's older Runs become claimable only after its rescan succeeds and the harness reconcile has run, both before serve accepts traffic.
- **The resume is a deployment act.** There is no web button and no CLI verb for it, and a web session cannot trigger it.

### Upgrading to phase 3f

No migration. Nothing changes at start unless you set the two variables above. A Task left `cancelling` with an attempt that was never invoked now shows **Finish cancelling** (§8). Earlier releases showed only "Settling" until the next start.

### Upgrading to phase 3h

No migration and no new setup step. Resume now honours `CENTRAL_HARNESS_ELIGIBLE_AFTER`: a Task created before it no longer shows Resume (it shows `Resume is unavailable: this Task was created before harness execution was enabled`), and a Resume request for it is refused. Nothing else changes.

### Upgrading to phase 3j

No migration and no new setup step. While harness execution is enabled, every Task now has a cost cap across its Runs: five times `CENTRAL_HARNESS_MAX_COST_USD` (US$25.00 by default), or `CENTRAL_HARNESS_TASK_COST_CAP_USD` if you set it (at least `CENTRAL_HARNESS_MAX_COST_USD`, or serve refuses to start). The cost Tasks recorded before the upgrade counts: a failed Task that has already recorded the cap shows `Retry is unavailable: this Task has used its cost cap` (§4b). A Retry that was queued before the upgrade is claimed with its cost limit clamped to what is left. Resume, Rerun, Mark failed, Mark cancelled and submitting behave exactly as before.

### Upgrading to phase 3k

No migration and no new setup step. While harness execution is enabled, a Task that is `waiting (reconciliation)` with an `ambiguous` attempt now also shows **Mark failed and rerun** (§8), including Tasks left that way by an earlier release, when the eligibility floor and the Task cost cap allow a Retry. Attempts resolved before the upgrade keep their `resolved (abandon)` label. Mark failed, Mark cancelled, Resume, Retry, Rerun and submitting behave exactly as before.

### Upgrading to phase 3l

No migration and no new setup step. Nothing is capped unless you set `CENTRAL_HARNESS_MAX_TOKENS` (§4b). Claude Code Runs now report their tokens as each response arrives, so task detail shows tokens in, tokens out and cache write while a Run is live (the Cache read line stays hidden and the Cost line says "not reported yet" until a result arrives, and "not reported" for good on an attempt that ends without one, unless an earlier attempt of the chain reported cost, in which case the page shows the chain total without the latest attempt's cost: phase 3m, §4b), and each attempt records roughly one more `usage_report` harness event per response. Every other bound and action behaves exactly as before.

### Upgrading to phase 3g

No migration and no new setup step. Nothing changes at start unless you want a different ceiling: `CENTRAL_HARNESS_MAX_ATTEMPTS` defaults to 3 (§4), so a Run may be resumed twice. Set it to `1` to switch Resume off. Every Task that is `waiting (reconciliation)` with an `ambiguous` attempt that recorded a session id now shows **Resume** beside Mark failed and Mark cancelled, including Tasks left that way by an earlier release (if their clone is gone, the resumed attempt fails `workspace_unavailable` and Retry remains). Mark failed, Mark cancelled, Retry, Rerun and the first attempt of a Run behave exactly as before.

## 9. Cleaning Run clones (root)

Central never deletes Run clones. The harness writes files as the operator, so cleanup needs root. Remove clones only for Runs in a terminal state (`succeeded`, `failed`, `cancelled`):

```bash
# list terminal Runs older than 7 days; <DSN> is any role with SELECT on central.runs
runs="$(mktemp)"
psql '<DSN>' -Atc "SELECT id FROM central.runs WHERE status IN ('succeeded','failed','cancelled') AND updated_at < now() - interval '7 days'" > "$runs"
uuid='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
while read -r run; do
  [[ "$run" =~ $uuid ]] || { echo "skipping unexpected line: $run" >&2; continue; }
  sudo rm -rf --one-file-system "/var/lib/central-harness/worktrees/runs/$run" \
    "/var/lib/central-harness/capture/$run.git" "/var/lib/central-harness/capture/$run-log.git" \
    "/var/lib/central-harness/capture/tmp/$run"
done < "$runs"
rm -f "$runs"
```

The list goes to a private `mktemp` file, and only a line shaped like a Run id reaches `sudo rm`. The three `capture/` paths exist only if serve stopped mid-capture; a settled Run's capture files are already gone.

Never remove the directory of a Run that is `running` or `waiting`.

## 9a. The opencode backend (issue #126)

Serve can run harness Tasks on OpenCode instead of Claude Code: one Task = one `opencode run --format json` session in the Run clone, through the same launcher, lifecycle, capture and Artifacts as §§1–9. The backend is serve-wide: every harness Task on the host uses the same one. Everything in §§1–9 applies except where this section says otherwise; the spec is [the issue #126 adapter design](../internal/superpowers/specs/2026-10-10-issue-126-opencode-adapter-design.md).

**Install exactly the pinned version, 1.18.32**, as the operator (a different version fails every attempt `harness_launch_failed` until you move the pin; see below):

```bash
curl -fsSL https://opencode.ai/install | bash -s -- --version 1.18.32
~/.opencode/bin/opencode --version
# 1.18.32
```

The installer puts the binary at `~/.opencode/bin/opencode`, which is where `setup.sh` looks for it. If your install lives elsewhere, pass its resolved path:

```bash
sudo packaging/harness/setup.sh --opencode-program /path/to/opencode --yes
```

Without the flag and without the default install, `setup.sh` leaves opencode unconfigured and the launcher stays claude-only; adding opencode later takes the §2 differs path (exit 3, reconcile by hand). Rerunning with opencode configured adds the `harness opencode` lines, the `harness-home/opencode` home (`.config/opencode`, `.local/share/opencode`, `.cache/opencode`, `.opencode/bin` mount points, the same `.gitconfig` trust block as the claude home) to the install.

**Log in each provider you will use**, as the operator: `opencode auth login` (per provider; `auth` is the `providers` alias on 1.18.32). OpenCode has no single login state: free models answer with no credentials at all, and an auth failure surfaces per model, when a Run uses it, as `harness_api_error` (below). Central never handles these credentials: they stay in the operator's `~/.local/share/opencode/auth.json`, mounted into the harness home like the rest of the opencode state.

**Enable it** with the standard §4 variables plus the backend switch (default `claude-code`):

```bash
CENTRAL_HARNESS_BACKEND=opencode
# optional: CENTRAL_HARNESS_OPENCODE_VERSION=1.18.32 (default; must look like 1.2.3)
```

An invalid value refuses the start (`CONFIG_INVALID`, the message names the variable), like every harness variable.

**Permissions are Deny-only.** `opencode run` exposes no bridge channel and no scoped auto-allow: the default run auto-rejects every permission ask, and that is the only policy Central expresses. Submitting with Bridge or Auto-allow while the backend is opencode fails with 400; the submit form and the detail page say the backend is deny-only. In particular:

- Reads of `*.env` and other asks the default rules do not pre-allow end as **denied** tool results; the Run continues and can still succeed with its Artifacts.
- A worktree whose root carries `opencode.json`, `opencode.jsonc` or `.opencode/` refuses the launch fail-closed — Central cannot make opencode ignore project configuration — and the attempt fails `harness_launch_failed` with `opencode: invalid launch: worktree contains <name>`. Keep project configuration out of the source repositories of Workspaces that run on this backend.

**Cost and tokens** (§4b) work as shown, with two differences. OpenCode reports USD cost with each step, so the cost line fills in while the Run is live (free-tier models report 0). And opencode has no native cost limit: the per-Run limit is enforced by Central's backstop only, so `budget_cost` ("Central stopped the Run: the reported cost reached the limit") is reachable on this backend, and "A Run can exceed its cost limit by about one API call" becomes "by about one step". Cancel, the wall clock and the token ceiling kill the opencode process at once — there is no soft interrupt — and the Task ends with the same reasons as on Claude Code.

**Troubleshooting.**

| Symptom | Meaning |
|---|---|
| `harness_launch_failed`, pinned-vs-found versions named | the installed opencode is not `CENTRAL_HARNESS_OPENCODE_VERSION`; install the pinned version or move the pin (below) |
| `harness_launch_failed`, `worktree contains …` | project configuration in the source repository (above) |
| `harness_api_error` | the model API failed the Run (bad credentials, a deprecated or unknown model, provider outage, free-tier refusal). The reason never carries the harness's message; the attempt's harness events keep what the API returned |
| `harness_exited_without_result` after a Resume | opencode no longer knows the session (`Session not found` on its stderr, exit 1): resume the Task from an earlier attempt or Mark failed and retry |
| `harness_session_mismatch` | the stream changed session id mid-Run; the attempt fails fail-closed |
| `harness_protocol_error` | the stream broke framing (an over-long line); retry the Task |

**Version-pin update flow.** The adapter's protocol mapping is captured from 1.18.32; a new opencode may change the `run --format json` stream. To move the pin:

1. Install the new version for the operator and run the conformance suite against it: `CENTRAL_TEST_OPENCODE=1 CENTRAL_TEST_OPENCODE_MODEL=<a free model> go test ./internal/adapter/harness/localexec/ -run TestLiveOpencode` (plus the rehearsal, `TestHarnessOpencodeRehearsalRunsToSucceeded`, on a scratch database). Every assertion must pass unmodified: probe, tiny run, `.env` deny, full rehearsal.
2. Bump `DefaultPinnedVersion` in `internal/adapter/harness/opencode/opencode.go` (the serve default follows it) and this runbook's `1.18.32`s.
3. Rerun `sudo packaging/harness/setup.sh --yes` and reconcile the `harness opencode <path>` line if the install moved (§2).
4. Re-run the live tests and the rehearsal, and record the new version, the model used and the outputs in the task log.

## 9b. The codex backend (issue #128)

Serve can run harness Tasks on Codex instead of Claude Code: one Task = one `codex exec --json` session in the Run clone, through the same launcher, lifecycle, capture and Artifacts as §§1–9. The backend is serve-wide: every harness Task on the host uses the same one. Everything in §§1–9 applies except where this section says otherwise; the spec is [the issue #128 adapter design](../internal/superpowers/specs/2026-10-10-issue-128-codex-adapter-design.md).

**Install exactly the pinned version, 0.162.1**, as the operator (a different version fails every attempt `harness_launch_failed` until you move the pin; see below). Codex has no canonical installer path, so either supported layout works: the pinned release binary (verify the checksum) into `~/.codex-bin/codex`, or a pinned npm install whose prefix is outside HOME (root-owned tree) —

```bash
# layout (a): release binary under the read-only mount
mkdir -p ~/.codex-bin && curl -fsSL -o ~/.codex-bin/codex <the rust-v0.162.1 linux-x86_64 asset> && chmod 0755 ~/.codex-bin/codex
# layout (b): pinned npm, outside-HOME prefix
npm install --prefix /usr/local --global @openai/codex@0.162.1
~/.codex-bin/codex --version # or: codex --version
# codex-cli 0.162.1
```

— then point `setup.sh` at the resolved binary (there is no default to resolve; without the flag codex stays unconfigured and the launcher stays claude-only):

```bash
sudo packaging/harness/setup.sh --codex-program ~/.codex-bin/codex --yes
# or: sudo packaging/harness/setup.sh --codex-program /usr/local/bin/codex --yes
```

A `--codex-program` under HOME but outside `~/.codex-bin` is refused (the launcher cannot see it); adding codex later takes the §2 differs path (exit 3, reconcile by hand). Rerunning with codex configured adds the `harness codex` lines, the `harness-home/codex` home (the `.codex` data mount, plus the `.codex-bin` read-only mount when the program lives beneath it, and the same `.gitconfig` trust block as the claude home) to the install. `setup.sh` also ensures the operator's `~/.codex` exists, so setup may come before or after login.

**Log in as the operator**: `codex login` (ChatGPT or API key; check with `codex login status`). The login must be file-backed for headless runs — keyring-backed auth has no session bus under the launcher, so the probe reports not-logged-in and the dispatcher pauses. There is no free tier: a per-model or auth failure surfaces, when a Run uses it, as `harness_api_error` (below). Central never handles these credentials: they stay in the operator's `~/.codex/auth.json`, mounted into the harness home like the rest of the codex state. The probe reads the login state from the exit code of `login status` only; its output is never logged.

**Enable it** with the standard §4 variables plus the backend switch (default `claude-code`):

```bash
CENTRAL_HARNESS_BACKEND=codex
# optional: CENTRAL_HARNESS_CODEX_VERSION=0.162.1 (default; must look like 1.2.3)
```

An invalid value refuses the start (`CONFIG_INVALID`, the message names the variable), like every harness variable.

**Permissions are Deny-only.** `codex exec` forces its approval policy to Never and rejects every approval ask (command, file change, user input) without ever prompting; that plus the workspace-write sandbox is the only policy Central expresses. Submitting with Bridge or Auto-allow while the backend is codex fails with 400; the submit form and the detail page say the backend is deny-only. In particular:

- Escalations never leave the sandbox: a command the sandbox denies fails as an **error** tool result (never retried unsandboxed), dangerous commands are forbidden outright, and a model-initiated approval ask is rejected. The Run continues on tool errors and can still succeed with its Artifacts.
- The sandbox needs its Linux backend (landlock; a missing `bwrap` only warns on the operator's terminal). If the platform cannot enforce the sandbox, sandboxed commands fail rather than run free.
- A worktree whose root carries `.codex/` refuses the launch fail-closed — project layers carry full config power (providers, MCP, hooks, sandbox options, rules) when trusted, and Central cannot make codex ignore them — and the attempt fails `harness_launch_failed` with `codex: invalid launch: worktree contains .codex`. Keep project configuration out of the source repositories of Workspaces that run on this backend. (`AGENTS.md` stays allowed: instructions only, like any repo content.)
- Enterprise-managed (MDM/managed) codex configuration wins over CLI flags by design: an org profile can widen the sandbox. That is the operator organisation's responsibility, not Central's.

**Cost and tokens** (§4b) differ more than on the siblings. Codex reports token usage but **no cost**, so Central cannot enforce a cost limit on this backend: setting `CENTRAL_HARNESS_MAX_COST_USD` or `CENTRAL_HARNESS_TASK_COST_CAP_USD` refuses the start (`CONFIG_INVALID`, naming the variable), and filling the submit form's cost field fails with 400 (the field is disabled). Spend is bounded by the token ceiling (`CENTRAL_HARNESS_MAX_TOKENS`, which you should always set on this backend) and the wall clock. Two usage notes: usage arrives once, when the turn completes — failed or killed attempts record no usage (attempts stay bounded by MaxAttempts + wall clock) and the live display updates once per attempt; and the reported total is cumulative for the session, so a resumed attempt over-attributes the earlier turns' tokens to itself (conservative for ceilings). Cancel kills the codex process at once — there is no soft interrupt through the port — and the Task ends with the same reasons as on Claude Code.

**Troubleshooting.**

| Symptom | Meaning |
|---|---|
| `harness_launch_failed`, pinned-vs-found versions named | the installed codex is not `CENTRAL_HARNESS_CODEX_VERSION`; install the pinned version or move the pin (below) |
| `harness_launch_failed`, `worktree contains .codex` | project configuration in the source repository (above) |
| `harness_api_error` | the model API failed the Run (no/expired login, an unknown model, provider outage). The reason never carries the harness's message; the attempt's harness events keep what the API returned |
| `harness_exited_without_result` after a Resume | codex no longer knows the session (`no rollout found` on its stderr, exit 1): resume the Task from an earlier attempt or Mark failed and retry |
| `harness_exited_without_result` on a fresh Run | the Run clone is not a git checkout (`Not inside a trusted directory` on its stderr, exit 1), or the stream ended with no terminal event |
| `harness_session_mismatch` | the stream changed session id mid-Run; the attempt fails fail-closed |
| `harness_protocol_error` | the stream broke framing (an over-long line); retry the Task |
| `CONFIG_INVALID` naming a cost variable | explicit cost controls are refused on this backend (above); unset the variable or switch backend |
| dispatcher pauses, probe not authenticated | `codex login` as the operator (file-backed), then the dispatcher resumes |

**Version-pin update flow.** The adapter's protocol mapping is captured from 0.162.1; a new codex may change the `exec --json` stream, the resume flags or the config precedence the Deny construction relies on. To move the pin:

1. Install the new version for the operator and run the conformance suite against it: `CENTRAL_TEST_CODEX=1 CENTRAL_TEST_CODEX_BIN=<the binary> go test ./internal/adapter/harness/localexec/ -run TestLiveCodex` (plus the rehearsal, `TestHarnessCodexRehearsalRunsToSucceeded`, on a scratch database). Every assertion must pass unmodified: probe (version + login state), tiny run, full rehearsal. If the new codex changed an argv form, a JSONL event, a status string or a default policy, update the adapter, the daemon grammar and this runbook first — never the test expectations alone.
2. Bump `DefaultPinnedVersion` in `internal/adapter/harness/codex/codex.go` (the serve default follows it) and this runbook's `0.162.1`s.
3. Rerun `sudo packaging/harness/setup.sh --codex-program <path> --yes` and reconcile the `harness codex <path>` line if the install moved (§2).
4. Re-run the live tests and the rehearsal, and record the new version, the model used and the outputs in the task log.

## 9c. The antigravity backend (issue #129)

Serve can run harness Tasks on Antigravity instead of Claude Code: one Task = one `agy --input-format stream-json --output-format stream-json` session in the Run clone, through the same launcher, lifecycle, capture and Artifacts as §§1–9. The backend is serve-wide: every harness Task on the host uses the same one. Everything in §§1–9 applies except where this section says otherwise; the spec is [the issue #129 adapter design](../internal/superpowers/specs/2026-10-11-issue-129-antigravity-adapter-design.md).

**Install exactly the pinned version, 1.3.3**, as the operator (a different version fails every attempt `harness_launch_failed` until you move the pin; see below):

```bash
# official installer (Antigravity CLI); verify the version afterwards
agy --version
# 1.3.3
```

The installer puts the binary at `~/.local/bin/agy`, which is where `setup.sh` looks for it. If your install lives elsewhere, pass its resolved path:

```bash
sudo packaging/harness/setup.sh --antigravity-program /path/to/agy --yes
```

Without the flag and without the default install, `setup.sh` leaves antigravity unconfigured and the launcher stays claude-only; adding antigravity later takes the §2 differs path (exit 3, reconcile by hand). Rerunning with antigravity configured adds the `harness antigravity` lines, the `harness-home/antigravity` home (the `.gemini/antigravity-cli` data mount, the `.local/bin` read-only mount when the program lives beneath it, and the same `.gitconfig` trust block as the claude home) to the install. `setup.sh` also ensures the operator's `~/.gemini/antigravity-cli` exists, so setup may come before or after login.

**The self-updater is held back by Central.** `agy` silently replaces its own binary on launch; every Central launch and probe sets `AGY_CLI_DISABLE_AUTO_UPDATE=1` (the only `AGY_*` variable ever passed), and the read-only program mount pins the binary further. Never run `agy update` on a host whose pin you have not moved (below): a version skew fails every attempt until the pin follows.

**Log in as the operator**: run `agy` once and complete its interactive auth flow; the login must precede any Run. Antigravity has no probeable login state: an auth failure surfaces per model, when a Run uses it, as `harness_api_error` (below), never as a paused dispatcher. Central never handles these credentials: they stay in the operator's `~/.gemini/antigravity-cli`, mounted into the harness home like the rest of the agy state.

**Enable it** with the standard §4 variables plus the backend switch (default `claude-code`):

```bash
CENTRAL_HARNESS_BACKEND=antigravity
# optional: CENTRAL_HARNESS_ANTIGRAVITY_VERSION=1.3.3 (default; must look like 1.2.3)
```

An invalid value refuses the start (`CONFIG_INVALID`, the message names the variable), like every harness variable.

**Permissions are Deny-only.** Headless agy exposes no prompt channel (it reports it "cannot prompt for" permissions) and no scoped auto-allow: tools it cannot prompt for are auto-denied by default, and that default is the only policy Central expresses. Submitting with Bridge or Auto-allow while the backend is antigravity fails with 400; the submit form and the detail page say the backend is deny-only. In particular:

- An auto-denied turn still succeeds: the denied tool's step is indistinguishable from success, and only the turn-level `denied_actions` array reports it — Central surfaces that as a `harness auto-denied tool actions` Warning on the attempt. A turn whose every tool was denied carries an empty report and follows the normal report-missing path (§6).
- Never pass `--dangerously-skip-permissions` semantics through Central: there is no flag for it, by design.
- A worktree whose root carries `.agent/`, `_agent/`, `.agents/`, `_agents/`, `codeium.yaml`, `.codeium.yaml`, `codeium.yml`, `.codeium.yml` or `.citc/` refuses the launch fail-closed — agy loads custom agents, rules and workspace identity from the worktree root and Central cannot make it ignore them — and the attempt fails `harness_launch_failed` with `antigravity: invalid launch: worktree contains <name>`. Keep project configuration out of the source repositories of Workspaces that run on this backend.
- Your operator-owned `~/.gemini/antigravity-cli/settings.json` (`permissions.allow` rules, default model, trusted workspaces) applies by design: an allow-rule can widen headless behavior past the auto-deny default. That is the operator's responsibility, not Central's, which never reads or writes that file.
- Prompts starting with `/` are delivered literally (Central passes `--disable-slash-commands`): no slash-command expansion can reinterpret task text.

**Cost and tokens** (§4b) work as on the codex backend. Antigravity reports token usage but **no cost**, so Central cannot enforce a cost limit on this backend: setting `CENTRAL_HARNESS_MAX_COST_USD` or `CENTRAL_HARNESS_TASK_COST_CAP_USD` refuses the start (`CONFIG_INVALID`, naming the variable), and filling the submit form's cost field fails with 400 (the field is disabled). Spend is bounded by the token ceiling (`CENTRAL_HARNESS_MAX_TOKENS`, which you should always set on this backend) and the wall clock. Two usage notes: usage streams per step, so failed or killed attempts may record partial usage from completed steps (never assumed zero), and billed output folds thinking tokens into output tokens. Cancel kills the agy process at once — there is no soft interrupt — and the Task ends `killed`, never `interrupted`: agy answers the signal with an `interrupted` error result of its own, and Central's own stop wins over that self-report.

**Troubleshooting.**

| Symptom | Meaning |
|---|---|
| `harness_launch_failed`, pinned-vs-found versions named | the installed agy is not `CENTRAL_HARNESS_ANTIGRAVITY_VERSION` (perhaps the self-updater moved it — hold it back per above); install the pinned version or move the pin (below) |
| `harness_launch_failed`, `worktree contains …` | project configuration in the source repository (above) |
| `harness_api_error` | the model API failed the Run (bad credentials, an unknown model, provider outage). The reason never carries the harness's message; the attempt's harness events keep what the API returned |
| `harness_session_mismatch` after a Resume | agy no longer knows the conversation: it starts a fresh one instead of failing, so Central refuses the switched id fail-closed — resume the Task from an earlier attempt or Mark failed and retry. Never a silent fresh session |
| `harness_session_mismatch` mid-Run | the stream changed conversation id; the attempt fails fail-closed |
| `harness_protocol_error` | the stream broke framing (an over-long line); retry the Task |
| `CONFIG_INVALID` naming a cost variable | explicit cost controls are refused on this backend (above); unset the variable or switch backend |

**Version-pin update flow.** The adapter's protocol mapping is captured from 1.3.3; a new agy may change the stream-json events, the resume flags, the headless permission behavior or the self-updater surface the pin relies on. To move the pin:

1. Install the new version for the operator and run the conformance suite against it: `CENTRAL_TEST_ANTIGRAVITY=1 CENTRAL_TEST_ANTIGRAVITY_MODEL=<a cheap model> go test ./internal/adapter/harness/localexec/ -run TestLiveAntigravity` (plus the rehearsal, `TestHarnessAntigravityRehearsalRunsToSucceeded`, on a scratch database). Every assertion must pass unmodified: probe, tiny run, `rm` deny, full rehearsal. If the new agy changed an argv form, a stream-json event, a status string, a default policy or the updater behavior, update the adapter, the daemon grammar and this runbook first — never the test expectations alone.
2. Bump `DefaultPinnedVersion` in `internal/adapter/harness/antigravity/antigravity.go` (the serve default follows it) and this runbook's `1.3.3`s.
3. Rerun `sudo packaging/harness/setup.sh --antigravity-program <path> --yes` and reconcile the `harness antigravity <path>` line if the install moved (§2).
4. Re-run the live tests and the rehearsal, and record the new version, the model used and the outputs in the task log.

## 10. Reference-host checks (maintainer)

**Required before you first set `CENTRAL_HARNESS_ENABLED=1`** on a host. Phase 3a merged with harness execution off by default; these checks are the acceptance gate for turning it on.

`cmd/central/harness_referencehost_test.go` (`-tags referencehost`, gated by `CENTRAL_TEST_HARNESS_E2E=1` and `CENTRAL_TEST_CLAUDE=1`; the header lists the full command) checks, against the installed launcher and the real Claude Code. It **spends tokens**: each run makes a few real Claude Code turns on the operator's account. It needs the §3 allow and deny rules. It checks:

- the fixture prompt "create hello.txt containing hi and commit it" ends `completed`, with a commit by the configured identity in the clone and three ready Artifacts (report, patch, commits), and the operator can fetch it once capture has unsealed the Run (never running git inside the clone) and push it to the source;
- a harness told to edit the clone's `.git/config` and create `.git/hooks/pre-commit` is refused (`harness.permission_denied` in the task log), and both files are as the clone left them (read as plain files, never with git);
- killing serve mid-attempt then restarting gives `waiting (reconciliation)`, an `ambiguous` attempt and a dead scope, and "Mark failed" gives `failed (operator_resolved)`;
- `setup.sh` rerun is a no-op;
- budgets (3d, §4b), with the login you actually use (subscription or API key, and say which):
  - a Task with a cost limit of US$0.05 and a prompt whose first response is a Write tool call ends `failed` with `harness_budget`, `--max-budget-usd` really fired, the reported cost is non-zero, and the patch and commits are ready (one API call can cost more than US$0.05, so the first response must already have produced the file);
  - a Task with a 1-minute wall clock and a long prompt ends `failed` with `budget_wall_clock`, and the kill ladder ended it (not `aborted`);
  - a Task without limits shows the serve defaults marked "(default)", and changing `CENTRAL_HARNESS_MAX_COST_USD` and restarting serve does not change what that page shows;
  - upgrade a copy of a real v31 database: run `central-migrate`, start serve so the baseline check passes, and see historic attempts show US$5.00 and 30 minutes "(default)";
  - a second Task can be submitted while the first is still listed (the submit form stays shown);
- with the launcher stopped, the recovery gate passes and the dispatcher pauses `launcher_unreachable`;
- phase 3e, with the pinned real Claude Code:
  - the report Artifact of a completed Task equals the `result` field of the session's final `result` frame (the top-level agent's final text; check it in the task's events); to see that a subagent's text does not win, use a prompt that makes the session call a subagent (the Task tool) and then answer in its own words: the report must be the top-level answer;
  - first check for an existing quarantine (the `to resume set` line in the start log, or a `degraded` or `failed` epoch in `SELECT epoch_generation, state, retry_attempt FROM central.recovery_epochs ORDER BY epoch_generation DESC LIMIT 1;`; a host degraded by an earlier release would fail this check and look like a 3e regression; see "Upgrading to phase 3e");
  - stop serve in the middle of a cancel (press Cancel, then stop serve **within 10 seconds**, because the orchestrator notices the cancel on its next heartbeat), then start it again: the log has no `to resume set` line, the newest epoch is not `degraded` or `failed`, the Task is "Settling" with the settling text and **Mark cancelled**; press it and the Task ends `cancelled`; a Task queued before the restart is still dispatched; Rerun of the cancelled Task completes;
  - cancel a Task while it is queued (for example with harness execution disabled, or with the dispatcher paused): it ends `cancelled` at once and is never dispatched.
- phase 3f:
  - on the host that has the degraded epoch (never start serve on a copy of its database next to the live serve: a resumed copy would dispatch the older queued Runs as real harness sessions; on a copy use a separate host or leave harness execution off, and check that the Run is claimable by SQL instead of waiting for a dispatch): start serve without the variables and see the log line naming the pair. Set a wrong pair and see `recovery resume not applied`. Set the right pair and a reason, then restart. The newest epoch must be `completed` (`SELECT epoch_generation, state, retry_attempt FROM central.recovery_epochs ORDER BY epoch_generation DESC LIMIT 1;`), and the Workspace's older queued Task must be dispatched. Restart once more with the variables still set: there must be no second `execution.recovery.resumed` event. Then remove the variables;
  - set only `CENTRAL_RECOVERY_RESUME` and see serve refuse to start with `CONFIG_INVALID` naming `CENTRAL_RECOVERY_RESUME_REASON`, with harness execution on and with it off;
  - if you meet a `cancelling` Task whose attempt is `prepared`, its page shows **Finish cancelling** with "This task was cancelled before its harness was launched."; press it: the Task ends `cancelled`, the harness row (if any) `failed (harness_not_launched)`, and Rerun completes. The fake-harness tests cover this case end to end; on a real host it needs a serve stop between the claim and the launch, so check it when it happens rather than forcing it.
- phase 3g, with the pinned real Claude Code (spec acceptance 7). These checks are the **only proof** that Resume works against a real `claude`: the fake-harness tests prove Central's side, not the session file's survival or `--resume`'s behaviour. Check first for an existing quarantine (see the 3e item above), then:
  - **(a) The session survives.** Start a Task with a prompt that takes a few minutes, stop serve in the middle of the attempt and start it again: the Task is `waiting (reconciliation)`, the attempt is `ambiguous` and the page shows **Resume** (wait until the old lease has expired if it answers "The harness is still starting"). Press it: the resumed attempt launches `claude --resume` and finds the session in the launcher's harness home (§2); the session id the new attempt reveals equals the old one (compare `harness_session_id` of the old and new rows in `central.harness_attempts`, and the new attempt's `resume_of` and `resume_session_id`);
  - **(b) Cost counter.** Read the cost the resumed attempt reports (its `total_cost_usd`, in its `result` event and in the row's usage) and record whether it starts at zero (per process) or continues from the old attempt's total (cumulative). Write the answer into §4b ("Not yet verified on a real host"). The chain rule is fail-safe either way; record which login you used (subscription or API key);
  - **(c) The resumed Run completes.** Let it finish: the Task ends `completed` with the report, patch and commits Artifacts (§6) covering the work of both attempts, and the Task page shows the cost "across 2 attempts";
  - **(d) Ceiling.** With `CENTRAL_HARNESS_MAX_ATTEMPTS=2`, resume once, stop serve mid-attempt again, restart: the page shows `Resume is unavailable: attempt limit reached` and Mark failed still works;
  - **(e) The earlier checks still pass.** The 3e and 3f items above (Mark failed, Mark cancelled, Finish cancelling, epoch resume) behave as before.
- phase 3l, with the pinned real Claude Code. This is the **only proof** that the live token count reads a real stream: the adapter tests use sanitized fixtures, and none of them has a subagent. Start serve with `CENTRAL_HARNESS_MAX_TOKENS=100000` and submit a Task that needs more than that (for example "read every file under docs/ and summarise each one, without using subagents"): it ends `failed` with `budget_tokens` and task detail shows "Central stopped the Run: the billed tokens reached the token ceiling"; the attempt is `budget_exhausted`; its recorded billed tokens (tokens in + tokens out + cache write on task detail) are at least 100,000; and its harness events show a `usage_report` for the attempt (the final result also sends one, so this line alone proves nothing; the `budget_tokens` ending is the proof). Record the billed figure, by how much it passed the ceiling, and the login you used (subscription or API key). A Run that delegates to a subagent may legitimately not stop, because subagent tokens are not counted while the Run is live; that is not a failure of the check, so submit the Task again with a prompt that keeps the work in the main conversation.
