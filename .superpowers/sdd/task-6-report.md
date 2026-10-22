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

26 tests port the upstream scenarios. `src/tests.rs` (20): closed
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
payload sanitization. `src/app_tests.rs` (6) ports the critical
`service_test.go` lanes with upstream fixture shapes
(`authorizedRouteFixture` + `fakeCompositeStore`/`fakeExecutionRead`):
the 16-row fence-provenance/absence-assertion commit table, mandatory
recovery admission on `execution.claim` vs. its absence on heartbeat,
exact-receipt replay skipping state read + commit, receipt-fingerprint
conflict before evaluation, and evaluation failure never committing.

## Post-review fixes (upstream anchors re-verified)

Reviewer findings were corrected by faithful ports — no
"improvements":

1. **Quarantine predicate** (`resume.rs`): `recovery_claimability`
   quarantines only unverified pre-watermark runs in a non-completed
   epoch; completed work and reconciled generations stay claimable;
   watermark ordered by `created_at` + run-id tie-break
   (`resume.go`).
2. **Commit fence provenance** (`app.rs`): `evaluated_lease_fence`
   exports a fence only from evaluator-produced change-set evidence
   (matching `LeaseRelease` or the closed active-lease event set);
   caller envelope equality never confers provenance
   (`service.go`).
3. **Recovery-claim admission** (`app.rs`): `require_recovery_claimable`
   is set only for `execution.claim` and `execution.start_harness_run`
   — the lease-granting commands (`service.go`).
4. **Recovery completion state** (`resume.rs`): degradation never
   auto-clears; completion requires zero incomplete workspace rows
   (`resume.go`).
5. **Change-set gates** (`domain.rs`): `build_execution_change_set`
   restored identity/cardinality/hierarchy validation, settlement +
   reconciliation evidence/disposition checks, lease release/assertion
   conflict detection, checkpoint checksum + canonical sanitization,
   event/outbox catalog + payload gates, and task-transition linkage
   (`domain.go` `BuildExecutionChangeSet`).
6. **Recovery coordinator contract** (`app.rs`, `port.rs`, `resume.rs`):
   `central.execution.recovery.v1` domain binding, `InstanceId`
   coordinator identity, generation fences, raw 32-byte claim tokens
   with hash-only persistence (`recovery.go`, `port.go`).
7. **Closed vocabularies** (`domain.rs`): `ReconciliationEvidenceKind`
   (4 kinds), `ReconciliationDisposition` (4), recovery epoch/workspace
   state strings (`open|running|degraded|failed|completed`,
   `pending|claimed|completed|failed`), `ProviderReconciliationReason`
   (3 reasons) — all compile-time closed.
8. **Service surface** (`app.rs`, `port.rs`): `issue_lease_credential`
   mints raw bearers outside persistence; `CommitResult.replayed`;
   `validate_lease` fails closed without an authoritative validator;
   `create_approval_successor` returns the persisted B11 descriptor
   (replayed included); `validate_completion_change_set` reloads
   authoritative state and re-derives the task transition
   (`service.go`).
9. **Payload sanitization** (`domain.rs`): schema-allowlist traversal
   replacing generic key filtering — metadata/event/outbox/outcome/
   context/checkpoint schemas with sensitive-key rejection and Go
   `encoding/json` canonical form.
10. **Resume reconciliation** (`resume.rs`): no lease granted; asserts
    no active lease; predecessor identity preserved; successor step +
    prepared attempt minted through `central_task::execution_facade`.

### Test-inventory delta

`src/tests.rs` 20 → 20 (two expectation corrections to match upstream:
`INVALID_PAYLOAD` for non-object payloads, `INVALID_TRANSITION` for
closed-table rejections); `src/app_tests.rs` 0 → 6; crate total
20 → 26; workspace 173 → 191.

## Gates (all executed)

- `cargo fmt --all -- --check` — clean
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` — clean
- `cargo test -p central-execution` — 26/26 pass
- `cargo test --workspace` — 191 tests, all pass

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
