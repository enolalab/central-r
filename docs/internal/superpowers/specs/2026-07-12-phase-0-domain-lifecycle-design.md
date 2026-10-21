# Phase 0 Domain Model and Durable Lifecycle Design

- **Status:** Approved
- **Approved:** 2026-07-12
- **Date:** 2026-07-12
- **Phase:** Phase 0 — Architecture and foundations
- **Implementation target:** Phase 1 — Local Central MVP

## Context

Central is currently a documentation-only repository. Phase 0 establishes an implementation-ready architecture; executable Go code, Docker Compose, migrations, and runtime behavior begin in Phase 1.

This is the first of several Phase 0 specifications. It defines the stable domain vocabulary, ownership boundaries, lifecycle state machines, retry and recovery semantics, and the durability invariants that later persistence, artifact, API, runtime, and UI specifications must preserve.

Related documents:

- [Product vision](../../../product/vision.md)
- [Phase definitions](../../../product/phases.md)
- [Roadmap](../../../product/roadmap.md)
- [Architecture overview](../../../architecture/overview.md)
- [Durable execution](../../../architecture/durable-execution.md)
- [Current phase](../../../implementation/current-phase.md)
- [Specification and planning guide](../../../implementation/spec-and-plan-guide.md)

## Objective

Define one domain model that lets Phase 1 implement a single durable local task without inventing new meanings for Workspace, Task, Run, Step, attempt, approval, checkpoint, event, or artifact.

The design is successful when:

- each core term has one definition and one owner;
- every lifecycle transition has an actor, guard, durable effect, and failure behavior;
- retry never overwrites prior evidence;
- ambiguous side effects are reconciled rather than repeated blindly;
- task completion is impossible before required artifacts are verified and durably recorded;
- current state and append-only history remain transactionally consistent;
- the model supports four representative workflows without adding another core entity.

## Phase boundary

Phase 0 is a design-only gate. It delivers approved specifications, ADRs, and a Phase 1 backlog. It does not deliver an executable bootstrap.

Phase 0 is decomposed into independently reviewable specifications. This document covers the domain and lifecycle foundation only.

### In scope

- Workspace, Task, Run, Step, attempt, ToolCall, Approval, Checkpoint, Artifact, and Event vocabulary
- aggregate and ownership boundaries
- identifier and lineage rules needed by the domain
- Task, Run, Step, StepAttempt, ToolCall, ToolCallAttempt, and Approval lifecycle semantics
- waiting, cancellation, retry, reconciliation, and restart behavior
- transaction boundaries between domain state and events
- completion barriers involving PostgreSQL and S3-compatible object storage
- domain-level security and observability requirements
- test strategy and Phase 0 validation scenarios

### Out of scope

- Go packages or executable code
- PostgreSQL tables, columns, migrations, and concrete queries
- Docker Compose, PostgreSQL, or MinIO setup
- concrete HTTP routes, HTML templates, or UI layout
- model-provider and tool protocol details
- a workflow graph, dependencies, fan-out, or parallel subagents
- distributed scheduling, fairness, or multi-worker coordination
- artifact retention and deletion policy
- full approval-policy configuration
- cloud control plane and Online Mode

The omitted details belong to follow-up Phase 0 specifications and ADRs. They must conform to the invariants in this document.

## Decisions

1. **Workspace is the only top-level ownership and isolation boundary in Phase 0 and Phase 1.**
2. **Project is not a core entity.** It may be introduced later only when a demonstrated workflow requires a second organizational boundary.
3. **Workflow is a conceptual future graph, not a persisted aggregate before Phase 2.**
4. **Task represents stable user intent.**
5. **Each whole-task execution or retry uses a separate Run; terminal Run evidence is never overwritten.**
6. **Step represents a logical unit of durable work within one Run.**
7. **Each Step retry creates a new immutable StepAttempt.**
8. **ToolCall represents one logical tool action owned by a Step.**
9. **Each physical invocation is a ToolCallAttempt linked to a StepAttempt.**
10. **Approval is a durable entity.**
11. **PostgreSQL normalized rows are authoritative for current state.**
12. **Every accepted transition appends an immutable Event in the same PostgreSQL transaction as the current-state update.**
13. **Central does not use pure event sourcing in Phase 1.**
14. **Artifact bodies live in S3-compatible storage; PostgreSQL stores lifecycle, metadata, checksum, and lineage.**
15. **External calls never occur inside an open PostgreSQL transaction.**
16. **A Task is complete only after required artifacts are verified and completion metadata, state, and events commit atomically in PostgreSQL.**

## Approaches considered

### Selected: transactional aggregates plus append-only events

Domain services validate commands. An application service commits normalized current state and an append-only Event in one PostgreSQL transaction. Current state supports scheduling and UI queries; Events provide immutable audit and recovery evidence.

This approach provides strong durability without requiring event replay, projection rebuilding, or event schema upcasting for the first local runtime.

### Rejected: pure event sourcing

Events would be the only canonical data and projections would reconstruct current state. This provides powerful replay and temporal analysis, but adds projection consistency, upcasting, migration, and operational complexity before Central has a working local vertical slice.

### Rejected: current-state tables only

This is the simplest persistence model but cannot provide sufficient transition evidence, failure diagnosis, retry history, or recovery auditability.

## Domain vocabulary

| Term | Definition | Ownership and relationship |
| --- | --- | --- |
| Workspace | The top-level local isolation boundary for tasks, credentials, policy, and artifacts. | Owns Tasks and all data reachable from them. |
| Task | A durable user request with stable identity, normalized input, current lifecycle, policy, and final outcome. | Aggregate root. Belongs to one Workspace. |
| Run | One whole-task execution attempt. | Aggregate root. Belongs to one Task. Prior terminal Runs are immutable. |
| Step | One logical resumable unit of work within a Run. | Aggregate root. Belongs to one Run. |
| StepAttempt | One physical execution attempt for a Step. | Entity owned by a Step. Immutable after an outcome is recorded. |
| ToolCall | One logical requested tool action with stable input identity and operation key. | Owned by a Step. Survives StepAttempt retries within the same Run. |
| ToolCallAttempt | One physical delivery of a ToolCall to a tool adapter. | Linked to one ToolCall and one StepAttempt. |
| Approval | A durable request for an actor to allow or reject a privileged action. | Aggregate root linked to its Task, Run, Step, and ToolCall target where applicable. |
| Checkpoint | A verified continuation boundary describing completed logical work and the next safe action. | Produced by a StepAttempt; belongs to Task, Run, and Step. |
| Artifact | A durable output whose body is in object storage and whose metadata and lineage are in PostgreSQL. | Separate artifact-domain aggregate linked to Workspace, Task, Run, Step, and producer. |
| Event | An immutable fact about an accepted transition or durable execution outcome. | Appended with the normalized state change; not the sole source of current state. |
| Execution ownership | Persisted temporary authority for an executor instance to advance a Run or Step. | Represented by owner identity and expiry information; does not prove external side-effect outcome. |
| Waiting reason | A typed explanation for why executable progress is blocked. | Required whenever Task, Run, or Step is waiting. |

Project has no Phase 0 or Phase 1 table, foreign key, API, or domain interface.

Workflow may be described in product language as a future reusable or ad hoc graph. It has no Phase 1 persisted identity or lifecycle. A single submitted unit of work is a Task.

## Identifier and lineage rules

- Every persistent entity uses an application-generated UUIDv7.
- IDs are immutable, globally unique, and serialized as canonical lowercase UUID strings.
- Database-generated sequential IDs are not exposed as domain identity.
- User-visible labels are mutable metadata and never form storage keys.
- Every Run has a monotonically increasing attempt number unique within its Task.
- Every StepAttempt has a monotonically increasing attempt number unique within its Step.
- A rerun of a cancelled Task creates a new Task with an explicit derived-from Task lineage reference.
- A retry of a failed Task keeps the Task identity and creates a new Run.
- Artifact and checkpoint lineage records producer identity and all available Workspace, Task, Run, Step, and attempt IDs.

## Ownership and transaction boundaries

### Workspace boundary

Workspace defines ownership and isolation. Domain commands must reject cross-Workspace references. Infrastructure adapters must include Workspace scope in reads and writes even in the single-user Phase 1 deployment.

### Task aggregate

Task owns:

- stable user intent and normalized input reference;
- current Task status and typed waiting reason;
- current Run reference when a non-terminal Run exists;
- retry and cancellation policy references;
- version used for concurrency control;
- final result and failure summary.

Task does not contain the full history of Runs, Steps, Events, or Artifacts in memory.

### Run aggregate

Run owns one whole-task attempt, its status, attempt number, execution ownership, retry budget, timing, failure summary, and current Step reference.

Only one non-terminal Run may exist for a Task. The persistence specification must enforce this invariant.

### Step aggregate

Step owns one logical unit of work, its status, normalized input reference, retry policy, checkpoint reference, and ordered StepAttempts.

Step can be resumed inside the same Run when persisted evidence proves that completed logical work does not need to repeat.

### ToolCall and attempts

ToolCall is the logical side-effect boundary. It owns:

- canonical tool identity;
- normalized input hash;
- stable operation key;
- requested capability and approval requirement;
- current known logical outcome.

ToolCallAttempt records one adapter invocation, timing, executor, provider request reference, response or failure reference, and whether its external outcome is known.

This separation keeps the operation key stable while preserving every invocation attempt.

### Approval

Approval is a separate durable aggregate because its decision can arrive after a process restart and can be made by an actor different from the executor.

### Domain and application responsibilities

- The Task domain service validates every Task transition and cross-aggregate lifecycle invariant.
- Run and Step domain services validate their own transitions and attempt rules.
- Application services coordinate domain commands and invoke a domain-owned transaction or unit-of-work interface.
- PostgreSQL, object-storage, HTTP, and provider adapters implement interfaces owned by the relevant domain package.
- Infrastructure types never appear in domain APIs.

### Transaction rule

One accepted domain command commits all of the following atomically where applicable:

- normalized aggregate updates;
- related aggregate updates needed to preserve lifecycle invariants;
- the immutable Event for each accepted transition;
- an outbox delivery reference when asynchronous publication is required;
- version increments and uniqueness checks.

Model, tool, network, filesystem, shell, and object-storage calls occur only after the transaction that records their intent has committed.

## Common transition rules

Every transition command includes:

- command identity for deduplication;
- Workspace and aggregate identity;
- expected aggregate version;
- actor identity and actor type;
- reason and correlation identity;
- request timestamp;
- normalized command input or an immutable reference to it.

Every accepted transition records:

- prior and next state;
- aggregate version;
- Task, Run, Step, and attempt identity where applicable;
- actor and reason;
- correlation and causation identity;
- event schema version;
- commit timestamp.

An invalid transition returns a typed domain error and writes no partial state or Event.

## Waiting semantics

Task, Run, and Step use one waiting status with a required persisted waiting reason.

Initial waiting reasons are:

- **approval:** a durable approval decision is required;
- **external_input:** user or external input is required;
- **retry_delay:** a bounded retry is scheduled for a future time;
- **dependency:** a future Phase 2 dependency blocks progress; this value is reserved and is not emitted by Phase 1;
- **reconciliation:** an external side effect has an ambiguous outcome.

Each waiting record also stores:

- what condition resolves the wait;
- the entity responsible for resolving it;
- the earliest eligible resume time when applicable;
- the related Approval, ToolCall, dependency, or reconciliation reference;
- cancellation behavior;
- timeout behavior when a policy defines one.

Resolving a wait returns the same non-terminal Run to queued unless a terminal Run retry is being scheduled. A worker must claim queued work before it returns to running.

## Task lifecycle

Task statuses are:

- **queued**
- **running**
- **waiting**
- **cancelling**
- **completed**
- **failed**
- **cancelled**

There is no draft or pending Task status in Phase 1. A valid submission atomically creates a queued Task and Run number one. Invalid submission is rejected without a partial Task.

| Command | From | To | Actor | Guards and durable effects |
| --- | --- | --- | --- | --- |
| SubmitTask | none | queued | user or trusted local API | Workspace and normalized input are valid. Create Task, Run number one, current-state rows, and creation events atomically. |
| ClaimCurrentRun | queued | running | executor | Current Run is queued and claimable. Persist ownership and transition Task and Run with Events. |
| Wait | running | waiting | runtime or domain service | A typed waiting reason and resolution condition are present. Update affected Run and Step consistently. |
| ResumeSameRun | waiting | queued | scheduler, approval service, external-input service, or reconciler | Resolution evidence is durable. Keep the same Run and requeue safe continuation work. |
| ScheduleRunRetry | running or waiting | waiting | retry service | Current Run becomes failed; retry policy permits another Run. Clear the current Run reference, then persist retry-delay reason and next eligible time. |
| ActivateScheduledRun | waiting | queued | scheduler | Retry time has arrived and policy remains valid. Create the next Run atomically and set it current. |
| CompleteTask | running | completed | Task domain service | Current Run succeeds; all required Artifacts are ready and verified; completion state, metadata, and Events commit atomically. |
| FailTask | running or waiting | failed | Task domain service | Current Run is failed and no automatic retry remains, or a deterministic terminal failure is recorded. |
| RequestCancellation | queued, running, or waiting | cancelling | user or authorized policy | Persist cancellation request before signaling execution. Prevent new work from starting. |
| SettleCancellation | cancelling | cancelled | runtime or reconciler | Execution ownership is released and in-flight outcomes are recorded and reconciled. |
| RetryFailedTask | failed | queued | user or authorized policy | Create a new Run with the next attempt number. Preserve the failed Run and all prior evidence. |

Completed and cancelled Tasks never reopen.

Running a cancelled Task again creates a new Task with derived-from lineage. This prevents cancellation history from being rewritten.

## Run lifecycle

Run statuses are:

- **queued**
- **running**
- **waiting**
- **cancelling**
- **succeeded**
- **failed**
- **cancelled**

| Command | From | To | Actor | Guards and durable effects |
| --- | --- | --- | --- | --- |
| CreateRun | none | queued | Task domain service | Assign the next Task-scoped attempt number and persist the policy snapshot. |
| ClaimRun | queued | running | executor | Acquire execution ownership atomically and transition the parent Task. |
| WaitRun | running | waiting | runtime or domain service | Persist a typed wait state and release execution ownership. |
| RequeueRun | waiting | queued | scheduler, approval service, external-input service, or reconciler | Require durable resolution evidence; ownership remains empty until a new claim. |
| SucceedRun | running | succeeded | Run domain service | All required Steps succeeded and required Artifacts are verified. Parent Task completes in the same transaction. |
| FailRun | running or waiting | failed | Run domain service | Persist failure class, message, recoverability, and retry evidence; release ownership. |
| RequestRunCancellation | queued, running, or waiting | cancelling | Task domain service | Stop future claims and propagate cancellation to active work. |
| SettleRunCancellation | cancelling | cancelled | runtime or reconciler | Ownership is released and active operation outcomes are resolved. |

Succeeded, failed, and cancelled Runs are immutable. Retrying a failed Run creates another Run; it never reopens the terminal Run.

An automatic whole-Run retry first makes the old Run failed and the Task waiting with retry-delay. The next Run is created only when the retry becomes eligible.

### Parent-state consistency

Task and current-Run status changes are synchronous invariants, not eventually consistent projections:

- a queued, running, waiting, or cancelling current Run gives the parent Task the corresponding status;
- Run success and Task completion commit together;
- Run failure and either Task failure or Task retry-delay waiting commit together;
- Run cancellation and Task cancellation commit together;
- a Task waiting for a future whole-Run retry has no current non-terminal Run;
- Step waiting propagates waiting to its Run and Task, while Step resumption requeues the same Run and Task;
- Step success does not finish the Run unless all Run completion guards pass.

## Step and StepAttempt lifecycle

Step statuses are:

- **queued**
- **running**
- **waiting**
- **cancelling**
- **succeeded**
- **failed**
- **cancelled**

| Command | From | To | Actor | Guards and durable effects |
| --- | --- | --- | --- | --- |
| CreateStep | none | queued | runtime | Run is non-terminal and permits another Step. Persist normalized Step input and creation Event. |
| ClaimStep | queued | running | executor | Parent Run is running and no conflicting StepAttempt is active. Create the next StepAttempt atomically. |
| WaitStep | running | waiting | runtime or domain service | Persist a typed waiting reason, retry evidence, or reconciliation reference. |
| RequeueStep | waiting | queued | scheduler, approval service, external-input service, or reconciler | Durable resolution evidence exists and the parent Run is requeued. |
| SucceedStep | running | succeeded | Step domain service | Current StepAttempt succeeded and required Step outputs are durable. |
| FailStep | running or waiting | failed | Step domain service | Current attempt failed and Step retry policy is exhausted or forbids retry. |
| RequestStepCancellation | queued, running, or waiting | cancelling | Task domain service | Parent cancellation is durable and no new ToolCallAttempt may start. |
| SettleStepCancellation | cancelling | cancelled | runtime or reconciler | Active attempt outcome is recorded and no ambiguous operation remains unresolved. |

StepAttempt begins in running after its creation and ends with exactly one immutable outcome:

- **succeeded**
- **failed**
- **cancelled**
- **ambiguous**

StepAttempt running means the attempt is non-terminal; the parent Step, Run, and Task statuses determine whether execution is actively claimable or durably waiting.

A transient StepAttempt failure may place the Step, Run, and Task into waiting with retry-delay. When eligible, Central creates a new StepAttempt for the same Step and Run.

Completed Steps and verified Artifacts are not repeated.

An ambiguous StepAttempt remains immutable. Reconciliation writes new evidence and Events rather than rewriting the historical attempt outcome.

Reconciliation has three permitted resolutions:

1. **confirmed success:** record the logical ToolCall outcome as succeeded and continue without invoking the tool again;
2. **confirmed failure with no side effect:** record the outcome and allow policy to create a new attempt;
3. **still unknown:** remain waiting for reconciliation, require explicit operator input, or end according to policy.

## ToolCall and ToolCallAttempt lifecycle

ToolCall statuses are:

- **planned**
- **awaiting_approval**
- **ready**
- **running**
- **retry_wait**
- **reconciliation**
- **succeeded**
- **failed**
- **denied**
- **cancelled**

| Command | From | To | Actor | Guards and durable effects |
| --- | --- | --- | --- | --- |
| CreateToolCall | none | planned | runtime | Persist canonical tool identity, normalized input hash, capability, and operation key. |
| RequireApproval | planned | awaiting_approval | policy service | Create the requested Approval and place parent execution in waiting atomically. |
| MakeReady | planned or awaiting_approval | ready | policy or approval service | No approval is required, or a durable approval exists. |
| DenyToolCall | awaiting_approval | denied | approval service | Persist the rejection; the external adapter is never invoked. |
| BeginToolCallAttempt | ready | running | executor | Create a prepared ToolCallAttempt before invoking the adapter. Only one non-terminal invocation may exist. |
| RecordToolSuccess | running or reconciliation | succeeded | runtime or reconciler | Persist known external success and the invocation or reconciliation evidence. |
| ScheduleToolRetry | running or reconciliation | retry_wait | runtime or reconciler | A known-safe failure is retryable; persist attempt count and next eligible time. |
| ActivateToolRetry | retry_wait | ready | scheduler | Retry time has arrived and policy permits another ToolCallAttempt. |
| RecordToolFailure | running or reconciliation | failed | runtime or reconciler | Failure is known and retry policy is exhausted or forbids retry. |
| RequireReconciliation | running | reconciliation | runtime or startup reconciler | External outcome is ambiguous; block further invocation. |
| CancelToolCall | planned, awaiting_approval, ready, running, retry_wait, or reconciliation | cancelled | Task domain service | Parent cancellation is durable, any active ToolCallAttempt has a recorded cancelled outcome, and no invocation is in flight. |

Succeeded, failed, denied, and cancelled ToolCalls are terminal. Reconciliation is non-terminal but cannot start another invocation.

ToolCallAttempt statuses are:

- **prepared**
- **succeeded**
- **failed**
- **cancelled**
- **ambiguous**

A prepared ToolCallAttempt is persisted before adapter invocation. If its executor disappears before a terminal outcome is committed, recovery treats the attempt as ambiguous unless adapter evidence proves that delivery did not occur.

Succeeded, failed, cancelled, and ambiguous ToolCallAttempts are immutable. A retry creates another ToolCallAttempt for the same ToolCall and operation key.

### Idempotency rules

The stable operation key is scoped to Workspace, Task, Run, Step, and logical action identity. It excludes StepAttempt and ToolCallAttempt identity.

Consequences:

- retries of the same logical action inside one Run reuse the same operation key;
- a whole-Run retry creates a different operation key;
- request input is canonicalized and hashed;
- reusing one operation key with a different input hash is a domain error;
- adapters pass the key to external systems that support idempotency;
- Central records every invocation even when the external system deduplicates it;
- ambiguous outcomes block further invocation until reconciliation resolves them.

## Approval lifecycle

Approval statuses are:

- **requested**
- **approved**
- **rejected**
- **cancelled**

Creating an Approval and transitioning execution to waiting with reason approval occur in one transaction.

| Command | From | To | Actor | Guards and durable effects |
| --- | --- | --- | --- | --- |
| RequestApproval | none | requested | policy service | Target ToolCall requires approval. Create Approval and waiting state atomically. |
| Approve | requested | approved | authorized user | Record actor, reason, policy snapshot, and decision Event; make the ToolCall ready. |
| Reject | requested | rejected | authorized user | Record actor, reason, policy snapshot, and denied ToolCall outcome. |
| CancelApproval | requested | cancelled | Task domain service | Parent Task cancellation is already durable. |

Approval decisions are idempotent:

- repeating the same decision returns the prior result;
- a conflicting second decision is rejected;
- an approval decision records actor, reason, timestamp, target action, and policy snapshot.

Approval or rejection resolves the wait and requeues the same Run. Rejection records a denied ToolCall outcome; it does not automatically cancel the entire Task. The runtime may continue with an alternative safe path or fail according to domain policy.

A separate Task cancellation can cancel a requested Approval.

## Current state, Events, and outbox

Normalized PostgreSQL rows are authoritative for current scheduling, lifecycle, and UI state.

Events are append-only audit and recovery evidence. Central does not rebuild all current state from Events in Phase 1.

Each Event includes:

- Event ID;
- Workspace ID;
- entity type and entity ID;
- related Task, Run, Step, and attempt IDs;
- event type and schema version;
- prior and next state when applicable;
- aggregate version and aggregate-local sequence;
- actor, reason, correlation ID, and causation ID;
- timestamp;
- a redacted structured payload or durable payload reference.

Events never contain plaintext credentials or unrestricted tool output.

When an Event must be published asynchronously, the same transaction creates a separate outbox delivery record referencing the Event. Delivery status does not mutate the Event.

## Concurrency and execution ownership

- Every mutable aggregate has a monotonically increasing version.
- Transition writes compare the expected version and fail on conflict.
- The database enforces at most one non-terminal Run per Task.
- Claiming executable work and recording execution ownership are atomic.
- Ownership records include executor instance, acquisition time, lease expiry, and last heartbeat.
- Lease expiry proves only that ownership is stale; it does not prove that an external side effect failed.

Phase 1 uses this persisted ownership contract for single-local-runtime restart recovery. Phase 2 extends the same contract with multiple workers, scheduling, fairness, and parallel task graphs.

## Durable data flows

### Submit

1. The transport validates request shape and resolves actor and Workspace.
2. The application service invokes SubmitTask.
3. One PostgreSQL transaction creates the queued Task, Run number one, normalized input reference, Events, and required outbox references.
4. The response is returned only after commit.

### Execute

1. An executor atomically claims the queued Run.
2. Task and Run transition to running in the claim transaction.
3. Central persists the intended Step, StepAttempt, ToolCall, capability decision, and operation key.
4. If approval is required, Central creates the Approval and durable waiting state, then stops until the decision is recorded and the same Run is requeued.
5. Once the ToolCall is ready, Central creates a prepared ToolCallAttempt in a new transaction.
6. The transaction commits before adapter invocation.
7. The runtime invokes the model or tool.
8. Central persists the known outcome, retry state, checkpoint, usage, and Events in a new transaction.

### Wait for approval

1. Central creates a requested Approval and transitions affected execution state to waiting with reason approval.
2. The transaction commits before UI notification.
3. An authorized actor approves or rejects.
4. Central records the decision and requeues the same Run atomically.
5. The runtime consumes the durable decision after a new claim.

### Finalize an Artifact

1. PostgreSQL reserves Artifact metadata in staging state and allocates an opaque object key.
2. The transaction commits.
3. The artifact body is uploaded to S3-compatible storage while Central computes SHA-256 and size.
4. Central verifies the stored object against expected checksum and size.
5. One PostgreSQL transaction marks the Artifact ready, records lineage, and appends Events. The same transaction may also succeed the producing Step, Run, and Task only when their completion guards pass.

The initial object key shape is:

    workspaces/{workspace-id}/tasks/{task-id}/runs/{run-id}/artifacts/{artifact-id}/body

Object keys contain IDs only. Original filenames may be stored as sanitized display metadata and never form the key.

S3 has no shared transaction with PostgreSQL. A crash after upload but before finalization leaves a staging Artifact and object. Recovery verifies the object and either finalizes it or applies the artifact cleanup policy.

## Failure classification and retry

| Failure class | Example | Automatic behavior |
| --- | --- | --- |
| Validation or deterministic user error | Invalid normalized input | Reject submission or fail without automatic retry. |
| Permission denial | Policy forbids a capability | Record structured denial; do not retry without a changed policy or explicit action. |
| Approval wait | Privileged ToolCall needs a decision | Wait durably; do not invoke until approved. |
| Transient infrastructure | Temporary database, object-store, or network failure | Bounded exponential backoff with jitter when the operation is known safe to retry. |
| Provider throttling or temporary model failure | Rate limit or provider timeout before a known side effect | Retry according to persisted policy and next eligible time. |
| Deterministic tool failure | Invalid arguments or stable command failure | Fail the attempt; retry only when policy explicitly permits corrected input. |
| Cancellation | Authorized cancellation request | Persist request, stop future work, settle in-flight outcomes, then cancel. |
| Ambiguous external side effect | Connection lost after request delivery | Wait for reconciliation; never retry blindly. |
| Executor loss | Process crash or expired ownership | Inspect persisted evidence, checkpoint, and operation status before deciding. |

Retry policy persists:

- maximum attempts;
- current attempt count;
- failure classes eligible for retry;
- backoff algorithm and bounds;
- next eligible time;
- timeout;
- exhausted-policy behavior.

## Startup reconciliation

On startup, Central scans:

- non-terminal Runs and Steps with stale execution ownership;
- retry waits whose eligibility time has arrived;
- staging Artifacts;
- incomplete or ambiguous ToolCalls;
- pending cancellation requests;
- requested Approvals.

For each item it deterministically chooses one action:

- resume from a valid checkpoint in the same Run;
- requeue safe work;
- create an eligible new Run;
- reconcile an external side effect;
- verify and finalize or clean up a staging Artifact;
- settle cancellation;
- fail when policy forbids recovery.

Every recovery decision updates normalized state and appends a recovery Event in one transaction.

## Cancellation semantics

Cancellation is a command, not an immediate assertion that execution stopped.

1. Persist the cancellation request and transition Task and active Run to cancelling.
2. Prevent new Steps and ToolCallAttempts from starting.
3. Signal the current executor after commit.
4. Record the outcome of in-flight work.
5. Reconcile any ambiguous side effect.
6. Release execution ownership.
7. Transition to cancelled and append Events.

Central must not report cancelled while an unrecorded external outcome can still affect correctness.

## Completion semantics

CompleteTask succeeds only when:

- the current Run is eligible to succeed;
- every required Step is succeeded;
- every required Artifact is ready;
- each required Artifact has verified size and SHA-256;
- artifact lineage includes Workspace, Task, Run, and producer identity;
- no required Approval, reconciliation, or cancellation is unresolved;
- completion state, Artifact metadata, and Events can commit atomically in PostgreSQL.

If any guard fails, the Task remains non-terminal.

## Security baseline

- All reads and writes are Workspace-scoped.
- Shell, filesystem, network, and database tools are privileged capabilities.
- Privileged ToolCalls require policy evaluation and, where configured, a durable Approval.
- Secret values are referenced, not embedded in Task input, Events, object keys, or logs.
- Tool input and output are redacted or moved to protected Artifact storage when large or sensitive.
- Object keys use opaque IDs and never expose raw filenames or secrets.
- Actor identity and permission decision are recorded for transitions and approvals.
- Phase 1 may assume one local user, but adapters must not bypass Workspace or capability checks.

## Observability

Structured logs include correlation ID, Event ID, Workspace, Task, Run, Step, attempt, actor type, transition, and failure class where applicable.

Required metrics include:

- Task and Run counts by status;
- transition failures and concurrency conflicts;
- retry count and delay;
- waiting count by reason;
- cancellation latency;
- stale ownership and recovery decisions;
- ambiguous operations;
- artifact staging age, verification failures, and orphan cleanup;
- time to terminal outcome.

Logs and metrics must not contain secrets or unrestricted artifact bodies.

## Test strategy

### Domain unit tests

- table-driven allowed and rejected transitions for every state machine;
- Task and Run terminal immutability;
- one non-terminal Run invariant;
- Step retry creates a new StepAttempt;
- whole-task retry creates a new Run;
- failed Task retry versus cancelled Task rerun lineage;
- waiting reason and resolution validation;
- Approval decision idempotency;
- operation-key stability across StepAttempts;
- operation-key change across Runs;
- completion barrier guards.

### PostgreSQL integration tests

- normalized state and Event commit or roll back together;
- expected-version conflicts reject stale transitions;
- database constraint prevents two non-terminal Runs;
- aggregate-local Event sequence is monotonic;
- command deduplication is atomic;
- ToolCall input hash cannot change under one operation key;
- claim and ownership update are atomic;
- recovery transition and Event are atomic;
- migrations preserve constraints and rollback behavior.

### MinIO integration tests

- reserve, upload, verify, and finalize;
- checksum mismatch;
- size mismatch;
- upload failure;
- database finalization rollback after successful upload;
- staging Artifact recovery;
- immutable ready Artifact behavior;
- object key contains only permitted opaque IDs.

### Failure-injection tests

- process exits after Run claim;
- process exits after ToolCall delivery but before outcome commit;
- process exits after checkpoint commit;
- process exits after Artifact upload but before finalization;
- lease expiry;
- duplicate delivery;
- provider timeout;
- retry budget exhaustion;
- cancellation during a ToolCall;
- ambiguous ToolCall outcome;
- approval decision across restart;
- database transaction rollback.

## Representative workflow validation

### Software development task

A Task creates one Run, executes sequential Steps, requests approval for privileged shell or filesystem actions, and produces verified patch, test, and report Artifacts. No Project or Workflow entity is required.

### Private document research

A Task references local input documents, executes resumable analysis Steps, and produces a cited report Artifact. Input and output remain Workspace-scoped. No additional core entity is required.

### File and data automation

A Task performs logical ToolCalls with stable operation keys, records each invocation attempt, and produces a verified structured Artifact. Duplicate delivery does not duplicate the logical side effect.

### Interrupted long-running task

A Task records checkpoints across Steps. After process restart, stale ownership is detected, completed Steps remain complete, safe work resumes in the same Run, ambiguous effects wait for reconciliation, and the final Artifact completes only after verification.

Passing the walkthrough means each scenario can be described entirely with the vocabulary and transitions in this specification.

## Documentation changes implied by this design

Follow-up documentation work must:

- remove Project from the Phase 0 and Phase 1 core model unless a later approved ADR introduces it;
- describe Workflow as conceptual until Phase 2;
- replace the preliminary pending-based Task lifecycle in the architecture overview;
- add Run, Step, StepAttempt, ToolCall, and Approval state semantics;
- strengthen durable-execution wording so normalized state plus append-only Events is a decision, not an option;
- define operation-key scope as stable across StepAttempts and distinct across Runs;
- record this design in the ADR index once ADR governance exists.

## Follow-up Phase 0 specifications

This design is followed by independently approved specifications for:

1. PostgreSQL schema, constraints, migrations, locking, and repository contracts;
2. Artifact storage, finalization, lineage, retention, and reconciliation;
3. Event schema, outbox, API conventions, and compatibility;
4. Go repository, package, dependency, configuration, and dependency-injection boundaries;
5. security threat model, capability policy, approvals, and secret references;
6. local development environment with PostgreSQL and MinIO;
7. Phase 1 capability map, vertical slices, and acceptance backlog.

## Follow-up decisions with owners and blocking points

| Decision | Owner | Must be resolved before |
| --- | --- | --- |
| PostgreSQL major version, migration tool, and rollback policy | Central maintainer | PostgreSQL persistence implementation plan |
| Concrete Go UUIDv7 library and validation rules | Go foundation specification owner | Go bootstrap implementation plan |
| Default lease duration, heartbeat interval, and clock-skew tolerance | Runtime specification owner | restart-recovery implementation plan |
| Default retry limits, backoff bounds, and jitter algorithm | Runtime specification owner | execution-loop implementation plan |
| Artifact retention, staging expiry, and orphan cleanup policy | Artifact specification owner | artifact implementation plan |
| Privileged capability matrix and approval policy defaults | Security specification owner | tool-safety implementation plan |

These decisions do not change the domain meanings or lifecycle invariants in this document.

## Acceptance criteria for this specification

- Every core term has one definition and owner.
- Project and persisted Workflow are explicitly excluded from Phase 1.
- Task, Run, Step, StepAttempt, ToolCall, ToolCallAttempt, and Approval semantics are internally consistent.
- Every lifecycle transition identifies actor, guard, durable writes, and failure behavior.
- Retry preserves previous Runs, Steps, attempts, Events, and Artifacts.
- Idempotency scope is stable across StepAttempts and distinct across Runs.
- Ambiguous side effects enter durable reconciliation.
- Current state and Events commit atomically.
- Artifact finalization respects the cross-store completion barrier.
- Cancellation does not claim success before in-flight outcomes are resolved.
- All four representative workflows use the model without a new core entity.
- Follow-up decisions have owners and explicit blocking points.

## Risks

- Defining basic execution ownership in Phase 1 can be mistaken for delivering the Phase 2 scheduler. The implementation plans must keep multi-worker scheduling and task graphs out of scope.
- Cross-aggregate transactions can become broad. Each command must update only the aggregates required for one lifecycle invariant.
- Event payloads can become an accidental second state model. Events remain audit evidence with versioned, minimal payloads.
- Approval rejection may require agent-specific continuation behavior. The domain records a denied ToolCall outcome and leaves alternate-path behavior to the runtime contract.
- Artifact reconciliation can leak storage without a concrete expiry policy. The artifact specification must resolve cleanup before implementation.
