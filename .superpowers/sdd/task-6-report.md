# Task 6 Report — `central-execution` capability crate

## Status

Implemented the `central-execution` capability crate on branch
`r1-workspace-durable-core`, porting `internal/execution/{domain,
harness_run,resume}.go`, `internal/execution/port/port.go`,
`internal/execution/app/{service,recovery}.go`,
`internal/execution/app/query/turn_activity.go`, and
`internal/task/app/query/claimability_decorator.go` from the Go
upstream (read-only reference — `$CENTRAL_SRC` was
never written to).

## Files

| File | Contents |
| --- | --- |
| `crates/capabilities/central-execution/Cargo.toml` | Workspace deps: `central-foundation`, `central-task`, `serde`, `serde_json`, `sha2`, `time`, `trait-variant`, `uuid` |
| `src/lib.rs` | Module wiring + crate docs |
| `src/domain.rs` (~4000 lines) | Capabilities/`TrustedScope`, `RequestFingerprint` (SHA-256 over Go-canonical JSON), closed state machines (`Step`, `Attempt`, `ToolCall`, `Approval`, reconciliation dispositions/reasons), all domain records, payload limits + sanitizer with Go `encoding/json` escaping, `CommandEnvelope`/`ExpectedVersions`/`EvaluationMetadata`/`ExecutionState`, `ExecutionChangeSet` + `build_execution_change_set` validation (identity cardinality, successor pairs, tool hierarchy, attempt assertions, settlement consistency, task-transition binding), event/outbox catalog + `with_evidence`/`with_tool_evidence`, all 15 core evaluators, `describe_reconciliation_actions`, `describe_approval_successor_action`, retention policy |
| `src/harness_run.rs` | Bounded `FailureReason` vocabulary (24 reasons), `new_settlement_outcome`, `CompletionReceipt` + `B09References`, `start_harness_run`, `abandon_prepared`, `settle_cancellation`, `evaluate_recovery` (B08 successor minting), `evaluate_recovery_completion` (receipt-bound settlement), `evaluate_recovery_cancellation` |
| `src/resume.rs` | `RecoveryEpoch`/`RecoveryWorkspaceWork`/coordinator fence, `recovery_claimability` (watermark quarantine), `recovery_completion_state` (degradation never auto-clears), `resume_reconciled_attempt` evaluator, `ResumeRecoveryEpochCommand` + canonical `recovery_resume_fingerprint`, epoch/workspace claim+complete evaluators |
| `src/port.rs` | `CompositeStore` (single atomic commit seam), `CompositeExecutionStore` (read + receipt + commit), `ExecutionRead`, `LeaseCredentialValidator`, `CompletionChangeSetStore`, `OutboxStore`, `B09EvidenceStore`, `RecoveryStore` (epoch/coordinator/workspace/artifact-work contracts), `RecoveryClaimabilityReader`, `Clock`, request/result/`DurableResult` types |
| `src/query.rs` | `RunTurnActivityRequest` validation + page-size normalization, `TurnActivity` rows, `ClaimabilityDecorator` (fails closed `RECOVERY_STATUS_UNAVAILABLE`) |
| `src/app.rs` | `Service::execute` pipeline — metadata gate → receipt lookup (replay returns the durable result without minting a credential) → authoritative read → lease-credential validation (fail-closed) → domain evaluation → one composite commit; `complete_with_receipt` routes typed B09 evidence through `B09EvidenceStore`; `RecoveryCoordinatorService` (start/acquire/claim/complete/resume epoch, failed-workspaces listing, artifact-work claims) with fingerprint drift rejected **before** store access |

## Evaluator count

21 command evaluators + helpers: prepare, claim, heartbeat,
mark_invoked, schedule_retry, enter_reconciliation, settle_cancellation,
prepare_tool_call, mark_tool_call_invoked, settle_tool_call, settle,
cancel, record_checkpoint, record_approval, resolve_approval,
expire_approval, create_approval_successor, resolve_reconciliation,
start_harness_run, abandon_prepared, resume_reconciled_attempt — plus
the B08 recovery evaluators (`evaluate_recovery`,
`evaluate_recovery_completion`, `evaluate_recovery_cancellation`) and
recovery-epoch evaluators (`evaluate_resume_recovery_epoch`,
`evaluate_recovery_workspace_claim`, `evaluate_recovery_workspace_complete`).

## Tests

20 tests in `src/tests.rs` port the upstream scenarios: closed
transition tables, 256-bit lease credentials, claim generation
fencing (mint gen 1, active-lease conflict, expired-row gen+1, stale
guess → `STALE_LEASE_FENCE`), settle releasing the lease + completing
the task, fenced-lease requirements, cancel prepared vs. invoked
(`RECONCILIATION_REQUIRED`), failure-reason vocabulary bounds,
harness-run fusion, abandon + settle-cancellation (incl.
executor-stopped reconciliation), B08 successor minting with lease
assertions, recovery cancellation + completion receipts, resume
successor pair + limits (`RESUME_BUDGET_EXHAUSTED`,
`RESUME_ATTEMPT_LIMIT_REACHED`, `INVALID_RESUME_LIMIT`), recovery
claimability watermark quarantine, epoch completion semantics,
resume-epoch fingerprint drift, reconciliation resolution
(dispositions, evidence required), action descriptors (operator vs.
executor, fence vs. no-lease assertion), retention windows, and
payload sanitization.

## Gates (all executed)

- `cargo fmt --all -- --check` — clean
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` — clean
- `cargo test -p central-execution` — 20/20 pass
- `cargo test --workspace` — 173 tests, all pass

## Non-1:1 mappings / concerns

1. **B09 stays a narrow border.** `B09EvidenceStore` is a typed port
   and `B09References` carries only allowlisted evidence kinds
   (provider-turn ids, filesystem page hashes). `complete_with_receipt`
   routes evidence through it, but no B09 runtime/storage adapter is
   wired — matching upstream where B09 storage is a dedicated lane.
2. **Foundation IDs vs. `uuid.Nil`.** Foundation identity newtypes have
   no `Default`/nil by design; the port reconstructs Go's zero
   sentinel via `from_trusted_db_bytes([0;16])` as `NIL_*` constants.
   Execution-owned ids (`LogicalOperationId`, `PhysicalAttemptId`,
   `InvocationId`, `ProviderTurnId`) are byte-array newtypes with
   nil-able `Default`.
3. **Cancelled attempts retain `invocation_id`.** Upstream
   `validateIdentity` only forbids a non-nil invocation on
   `prepared`; settled/cancelled-after-invoke rows keep it as
   evidence — the validator encodes exactly that (not a blanket
   "non-requiring ⇒ nil" rule).
4. **Resolve-reconciliation runs against a running task.**
   `reconciliationTaskTransition` maps confirm_succeeded → task
   `Complete`, which requires `Running`; upstream tests use the same
   running-aggregate fixture. The reconciliation-*waiting* aggregate
   is the `resume_reconciled` lane.
5. **Clock injection.** `Service::execute` stamps `meta.now` from the
   injected `Clock`; callers never set time (facade's documented
   divergence — domain never reads a clock).
6. **Request fingerprints.** Command fingerprints serialize a
   fixed-field struct through `serde_json` + Go-compatible escaping
   before SHA-256 — byte-compatible with upstream's canonical form.
7. **Fencing on commits.** `CommitRequest` carries credential,
   generation, `assert_no_active_lease`, and
   `require_recovery_claimable` so the adapter asserts all guards
   inside the same transaction.
