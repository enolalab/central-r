#!/usr/bin/env python3
"""Generate the R0–R6 roadmap and progress dashboard (self-contained HTML).

Sources of truth (read-only):
  - docs/implementation/rust-vertical-slice-roadmap.md  (phases, crates, migrations, acceptance)
  - docs/implementation/current-phase.md                (phase status)
  - docs/internal/superpowers/plans/*phase-r<N>*.md     (tasks and `- [x]` / `- [ ]` steps)
  - docs/internal/superpowers/reviews/*.md              (review reports)
  - crates/**, bins/**                                  (Rust LOC per crate)
  - git log                                             (commit activity)

Usage:
  python3 scripts/roadmap-dashboard.py [--out docs/implementation/roadmap-dashboard.html]

Stdlib only; the generated HTML has no external dependencies and works offline.
Re-run after ticking plan checkboxes or committing to refresh the dashboard.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ROADMAP = ROOT / "docs/implementation/rust-vertical-slice-roadmap.md"
CURRENT = ROOT / "docs/implementation/current-phase.md"
PLANS = ROOT / "docs/internal/superpowers/plans"
REVIEWS = ROOT / "docs/internal/superpowers/reviews"
SCAFFOLD_LOC = 50  # crates below this many lines of Rust are treated as placeholders

PHASE_RE = re.compile(r"^## \d+\. Phase (R\d) — (.+)$")
TASK_RE = re.compile(r"^### Task (\d+): (.+)$")
STEP_RE = re.compile(r"^- \[( |x|X)\] (.+)$")
CRATE_RE = re.compile(r"`((?:bins/)?central[a-z0-9-]*)`")


def strip_md(text: str) -> str:
    """Drop markdown links/bold but keep inline code backticks for rendering."""
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    return text.replace("**", "").strip()


def parse_roadmap() -> list[dict]:
    phases: list[dict] = []
    current: dict | None = None
    in_acceptance = False
    for line in ROADMAP.read_text(encoding="utf-8").splitlines():
        m = PHASE_RE.match(line)
        if m:
            current = {
                "id": m.group(1),
                "title": strip_md(m.group(2)),
                "crates": [],
                "migrations": "",
                "acceptance": [],
            }
            phases.append(current)
            in_acceptance = False
            continue
        if line.startswith("## "):
            current = None
            continue
        if current is None:
            continue
        if line.startswith("- **Owning crates:**"):
            seen = current["crates"]
            for name in CRATE_RE.findall(line):
                if name not in seen:
                    seen.append(name)
            in_acceptance = False
        elif line.startswith("- **Migration authority:**"):
            current["migrations"] = strip_md(line.split(":**", 1)[1])
            in_acceptance = False
        elif line.startswith("- **Acceptance criteria"):
            in_acceptance = True
            # Handles both "- **Acceptance criteria:** ..." and "- **Acceptance criteria** (spec §7): ...".
            rest = strip_md(line.partition(":")[2]).lstrip("* ").strip()
            if rest:
                current["acceptance"].extend(
                    s.strip() for s in re.split(r";\s+", rest) if s.strip()
                )
        elif in_acceptance and line.startswith("  - "):
            current["acceptance"].append(strip_md(line[4:]))
        elif line.startswith("- **"):
            in_acceptance = False
    return phases


def parse_status() -> dict[str, str]:
    text = CURRENT.read_text(encoding="utf-8")
    status: dict[str, str] = {}
    for m in re.finditer(r"^## Completed: Phase (R\d)", text, re.M):
        status[m.group(1)] = "complete"
    for m in re.finditer(r"^## Active slice: Phase (R\d)", text, re.M):
        status[m.group(1)] = "active"
    for m in re.finditer(r"^\| (R\d) \|.*\|\s*\**([A-Za-z]+)\**\s*\|$", text, re.M):
        status.setdefault(m.group(1), m.group(2).lower())
    return status


def parse_plan(path: Path) -> dict:
    tasks: list[dict] = []
    goal = ""
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("**Goal:**") and not goal:
            goal = strip_md(line[len("**Goal:**"):])
        m = TASK_RE.match(line)
        if m:
            tasks.append({"n": int(m.group(1)), "title": strip_md(m.group(2)), "steps": []})
            continue
        s = STEP_RE.match(line)
        if s and tasks:
            tasks[-1]["steps"].append({"done": s.group(1) != " ", "text": strip_md(s.group(2))})
    # Drop duplicate task headings (e.g. a File Structure section repeating a title).
    unique: dict[int, dict] = {}
    for t in tasks:
        if t["n"] not in unique or len(t["steps"]) > len(unique[t["n"]]["steps"]):
            unique[t["n"]] = t
    return {
        "file": str(path.relative_to(ROOT)),
        "goal": goal,
        "tasks": [unique[k] for k in sorted(unique)],
    }


def find_plans() -> dict[str, dict]:
    plans: dict[str, dict] = {}
    for path in sorted(PLANS.glob("*.md")):
        m = re.search(r"phase-(r\d)", path.name)
        if m:
            plans[m.group(1).upper()] = parse_plan(path)
    return plans


def find_reviews() -> list[dict]:
    out = []
    for path in sorted(REVIEWS.glob("*.md")):
        first = path.read_text(encoding="utf-8").splitlines()[:1]
        title = first[0].lstrip("# ").strip() if first else path.stem
        m = re.search(r"phase-(r\d)", path.name)
        out.append({
            "file": str(path.relative_to(ROOT)),
            "title": title,
            # Pre-R1 documentation/architecture reviews gate the R0 baseline.
            "phase": m.group(1).upper() if m else ("R0" if "documentation" in path.name else None),
            "date": path.name[:10],
        })
    return out


def crate_loc() -> dict[str, int]:
    loc: dict[str, int] = {}
    for cargo in sorted(ROOT.glob("**/Cargo.toml")):
        crate_dir = cargo.parent
        if crate_dir == ROOT or "target" in crate_dir.parts:
            continue
        src = crate_dir / "src"
        if not src.is_dir():
            continue
        lines = 0
        for rs in src.rglob("*.rs"):
            lines += sum(1 for _ in rs.open(encoding="utf-8", errors="replace"))
        tests = crate_dir / "tests"
        if tests.is_dir():
            for rs in tests.rglob("*.rs"):
                lines += sum(1 for _ in rs.open(encoding="utf-8", errors="replace"))
        rel = crate_dir.relative_to(ROOT)
        name = f"bins/{rel.name}" if rel.parts[0] == "bins" else rel.name
        loc[name] = lines
    return loc


def git_log() -> list[dict]:
    try:
        raw = subprocess.run(
            ["git", "log", "--format=%h%x1f%ad%x1f%s", "--date=short"],
            cwd=ROOT, check=True, capture_output=True, text=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return []
    commits = []
    for line in raw.splitlines():
        parts = line.split("\x1f")
        if len(parts) == 3:
            commits.append({"hash": parts[0], "date": parts[1], "subject": parts[2]})
    return commits


def post_slices(commits: list[dict]) -> list[dict]:
    """Post-R6 slices: `*-lifecycle-composition.md` plan, `### LC-T<n> — title`, done = an `lc-<n>` commit exists."""
    out = []
    for path in sorted(PLANS.glob("*lifecycle-composition*.md")):
        tasks = []
        for m in re.finditer(r"^### LC-T(\d+) — (.+)$", path.read_text(encoding="utf-8"), re.M):
            n = int(m.group(1))
            hit = [c["hash"] for c in commits if re.search(rf"\(lc-{n}\)|\blc-{n}\b", c["subject"])]
            tasks.append({"n": n, "title": strip_md(m.group(2)), "done": bool(hit), "commits": hit})
        out.append({"id": "LC", "title": "Lifecycle composition (post-R6)", "file": str(path.relative_to(ROOT)), "tasks": tasks})
    return out


def build_data() -> dict:
    phases = parse_roadmap()
    status = parse_status()
    plans = find_plans()
    loc = crate_loc()
    owner: dict[str, str] = {}
    for p in phases:
        for c in p["crates"]:
            owner.setdefault(c, p["id"])
    for p in phases:
        p["status"] = status.get(p["id"], "pending")
        p["plan"] = plans.get(p["id"])
        steps = [s for t in (p["plan"] or {}).get("tasks", []) for s in t["steps"]]
        done = sum(s["done"] for s in steps)
        if p["status"] == "complete":
            pct = 100.0
        elif steps:
            pct = 100.0 * done / len(steps)
        else:
            pct = 0.0
        p["steps_total"], p["steps_done"], p["percent"] = len(steps), done, round(pct, 1)
    crates = [
        {"name": n, "loc": l, "phase": owner.get(n), "scaffold": l < SCAFFOLD_LOC}
        for n, l in sorted(loc.items(), key=lambda kv: (-kv[1], kv[0]))
    ]
    commits = git_log()
    return {
        "generated": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "phases": phases,
        "crates": crates,
        "commits": commits,
        "post": post_slices(commits),
        "reviews": find_reviews(),
        "root": str(ROOT),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default="docs/implementation/roadmap-dashboard.html")
    args = ap.parse_args()
    template = (Path(__file__).parent / "roadmap-dashboard.template.html").read_text(encoding="utf-8")
    payload = json.dumps(build_data(), ensure_ascii=False).replace("</", "<\\/")
    out = ROOT / args.out
    out.write_text(template.replace("/*__DATA__*/null", payload), encoding="utf-8")
    print(f"wrote {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
