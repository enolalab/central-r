# R6-T14 — `copy_tree` never creates the destination root, so `backup import` fails on readdir order

- **Type:** Porting fidelity defect — upstream's `filepath.WalkDir` invariant (the walk visits `src` itself first, so the destination root is created before any child copy) was lost when the port iterated `read_dir(src)` children only; surfaced while porting the D07 Slice-D acceptance suite (`d07_scenarios_test.go` S3) during R6 Task 14.
- **Found:** 2026-10-28, while running `cargo test -p central --test d07_acceptance` scenario S3 (export → wipe → import staging) — the import failed closed with `IMPORT_CONFIRM_FAILED` from `write_restore_plan`'s `copy_tree(payload/backup → work/db/backup)` call.
- **Found by:** tracing the closed refusal — `IMPORT_CONFIRM_FAILED` narrows to `bootstrap_protected_state` or `write_restore_plan`; the plan writer's `fs::copy(entry, work/db/backup/<name>)` returns `ENOENT` whenever `readdir` yields a top-level regular file (`binding.json`, `root-manifest.json`, `seal-companion.json`) before the `database/` directory entry that would have created `work/db/backup` via `create_dir_all`. Whether a given `backup/<id>` tree fails is therefore hash-dependent on the filesystem, not on any authored condition.
- **Severity:** Medium and silent: the same latent failure sits in `bootstrap_protected_state`'s `lifecycle-records` copy (destination `state_root/lifecycle/imported`, also never pre-created). Export staging is unaffected only because its `backup_stage`/`protected_stage` destinations are created before the call.
- **Status:** Fixed 2026-10-28, direction 1 of "What a fix requires", under the ADR 0028 §D3 delegation — all four criteria hold.

## Root cause

Upstream `internal/adapter/authority/helper/export.go:461`:

```go
func copyTree(dst, src string) error {
	return filepath.WalkDir(src, func(path string, entry fs.DirEntry, err error) error {
		...
		target := filepath.Join(dst, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		...
	})
}
```

`WalkDir` visits `src` itself as the first entry: `rel = "."`, `IsDir() == true`, so `os.MkdirAll(dst, 0o700)` runs before any file copy. The Rust port pushed `src` onto a stack and iterated `fs::read_dir`, which yields children only — the root-visit side effect was dropped, and `fs::copy` (unlike upstream's `os.WriteFile` into a `MkdirAll`'d tree) does not create parent directories.

## Fix

`crates/adapters/central-adapter-linux/src/helper/export.rs::copy_tree` now runs `fs::create_dir_all(dst)` before the child loop — restoring the root-visit invariant upstream's `MkdirAll(dst)` provided at `rel = "."`. Call sites whose destinations already exist are unchanged (`create_dir_all` on an existing dir is a no-op).

## What a fix requires

The ADR 0028 §D3 delegation permits an agent-applied fix only when all four criteria hold:

1. **It does not weaken any permission, peer-authorization, or ceremony check.** The change only creates a directory the upstream algorithm always created anyway; the symlink/special-file refusals and the closed `Result<(), ()>` failure shape are untouched. ✓
2. **It does not change a wire format or an Accepted ADR's decision.** Internal staging helper; no request/response, evidence, or journal shape moves. ✓
3. **It is covered by a test that fails before and passes after.** `bins/central/tests/d07_acceptance` scenario S3 exercises the real `backup export` → `local wipe` → `backup import` chain over the helper socket; the import's `write_restore_plan` hit the missing-`backup/`-root failure deterministically on this filesystem (a top-level `binding.json` precedes `database/` in readdir order here) and passes after. ✓
4. **It is recorded under `docs/internal/tasks/` with this analysis.** This file. ✓

Directions considered:

1. **Create `dst` inside `copy_tree` (applied).** One line, restores the upstream invariant for every caller — including `bootstrap_protected_state`'s `lifecycle-records` copy that shared the same latent gap.
2. **Create `work/db/backup` at the `write_restore_plan` call site.** Rejected: fixes only the observed site, leaves the `lifecycle/imported` copy with the identical latent defect, and drifts the helper's contract away from upstream's "the copy owns its destination root".
3. **Sort `read_dir` entries dirs-first.** Rejected: hides the real defect behind traversal order instead of restoring the invariant; upstream guarantees the destination root regardless of walk order.

## References

- `crates/adapters/central-adapter-linux/src/helper/export.rs:768` — `copy_tree`, the fixed site.
- `crates/adapters/central-adapter-linux/src/helper/import.rs:512` (`bootstrap_protected_state`'s `lifecycle-records` copy), `:655-705` (`write_restore_plan`'s `backup/` copy).
- `bins/central/tests/d07_acceptance/scenarios.rs` — S3 `export_import`, the failing-before coverage.
- Upstream: `internal/adapter/authority/helper/export.go:461` (`copyTree` root-visit semantics), `internal/adapter/authority/helper/import.go` (`writeRestorePlan`/`bootstrapProtectedState` call sites).
- `docs/adr/0028-adopt-a-pre-authorized-grant-ceremony-and-context-independent-verdicts.md` §D3 — the delegation rule this fix was applied under.
