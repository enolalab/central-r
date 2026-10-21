# Phase Definitions

This document expands the product roadmap into implementation-planning boundaries. Each phase defines outcomes, capabilities, major workstreams, required specifications, non-goals, dependencies, risks, validation, and exit criteria.

A phase is complete only when its exit criteria are demonstrated. Completing a list of tasks is not sufficient.

## Common planning model

Each phase should be converted into one or more vertical slices. Every slice must identify:

- user or operator outcome
- domain behavior and invariants
- API, event, and storage changes
- failure, retry, cancellation, and recovery behavior
- security and permission implications
- observability requirements
- tests and acceptance scenarios
- migration and compatibility impact
- artifacts and documentation produced

The implementation plan should order slices so that each delivers a testable end-to-end capability.

---

## Phase 0 — Architecture and foundations

### Outcome

Create an implementation-ready technical foundation and a stable vocabulary for Local Central. At the end of this phase, contributors and coding agents must be able to write scoped specifications without inventing core concepts independently.

### Primary users

- maintainers defining product and architecture
- engineers implementing the initial runtime
- coding agents working from repository instructions

### Capabilities and decisions

1. **Domain model**
   - workspace, task, run, step, step attempt, agent, subagent, worker, tool call, tool call attempt, checkpoint, event, artifact, approval, and secret reference
   - Project is excluded from Phase 0 and Phase 1; Workflow graphs and executable subagent relationships begin in Phase 2
   - identifier strategy and ownership boundaries
   - aggregate roots and transactional boundaries
   - task, run, step, tool-call, and approval lifecycle state machines

2. **Execution model**
   - command submission and dispatch
   - process ownership and worker responsibilities
   - durable state versus ephemeral state
   - cancellation, timeout, retry, and resume semantics
   - idempotency model

3. **Persistence model**
   - PostgreSQL as source of truth for durable metadata and execution state
   - migration strategy
   - transaction and locking strategy
   - S3-compatible object storage for artifact bodies
   - checksum, media type, size, lineage, retention, and object-key rules

4. **Application boundaries**
   - Go package structure
   - domain interfaces and infrastructure adapters
   - HTTP and internal service boundaries
   - server-rendered web UI boundary
   - configuration and dependency injection approach

5. **Security baseline**
   - trust boundaries
   - privileged tool categories
   - local authentication assumptions
   - secret handling
   - filesystem, shell, network, and database access policy

6. **Engineering workflow**
   - repository layout
   - `AGENTS.md`
   - task and specification templates
   - build, test, lint, migration, and local-development commands
   - ADR process and Definition of Done

### Required specifications

- product vision and prioritized use cases
- domain glossary and entity relationship model
- task and run state-machine specification
- durable execution semantics
- artifact storage and lineage specification
- initial API and event contract conventions
- repository and package architecture
- threat model and permission baseline
- local development environment specification
- initial implementation backlog grouped into vertical slices

### Non-goals

- production-ready multi-agent scheduling
- cloud control plane
- multi-tenancy and billing
- plugin marketplace
- final optimization or scale decisions

### Validation

- architecture review against at least four representative workflows: code task, document research, file automation, and interrupted long-running task
- every core term has one definition and owner
- every state transition identifies allowed actor, persistence behavior, and failure behavior
- a new engineer can derive Phase 1 tasks without introducing new foundational concepts

### Exit criteria

- foundational specifications and ADRs are approved
- initial PostgreSQL and object-storage models are sufficiently defined to implement migrations and adapters
- Phase 1 is decomposed into implementation-ready vertical slices with acceptance criteria
- unresolved architectural decisions are explicitly recorded with an owner, an ISO `YYYY-MM-DD` decision due date, and a concrete implementation blocking point

---

## Phase 1 — Local Central MVP

### Outcome

Deliver a single-user, local-first application that runs one durable agent Task end to end, persists state and artifacts, exposes progress through a web UI, and recovers after application restart.

### Primary users

- a developer or technical user running Central on one machine
- a maintainer debugging workflows locally

### Core user journeys

1. bootstrap Central with PostgreSQL and MinIO
2. create a workspace and submit a task
3. select or configure one agent and model provider
4. execute a bounded set of tools
5. observe status, logs, events, and artifacts
6. cancel a Task or retry a failed Task by creating a new Run
7. restart Central and continue or inspect the durable run

### Major workstreams

1. **Application bootstrap**
   - Go service lifecycle and graceful shutdown
   - configuration loading and validation
   - PostgreSQL and MinIO connectivity
   - migrations and health checks
   - protected bootstrap-token exchange, bounded local sessions, and post-restore security reset

2. **Workspace and task management**
   - single local user assumption
   - workspace creation and selection
   - task creation, listing, detail, cancellation, and retry
   - initial task and run state transitions

3. **Single-agent runtime**
   - agent definition and execution contract
   - model-provider abstraction with one initial provider
   - prompt and context persistence
   - sequential tool-call loop
   - token, duration, and error recording

4. **Initial tools**
   - sandboxed workspace filesystem
   - shell command execution with explicit limits
   - optional outbound HTTP tool
   - tool input and output persistence

5. **Artifacts**
   - upload and download through S3-compatible storage
   - metadata in PostgreSQL
   - checksum verification
   - association with task, run, and producing step

6. **Web UI**
   - server-rendered task list and task detail
   - live or polling-based status updates
   - event and log view
   - artifact list and download
   - cancel and retry controls

7. **Restart recovery**
   - mark or reconcile interrupted runs during startup
   - continue from the latest safe durable boundary or expose a retry action
   - never report completion unless final state and required artifacts are durable

8. **Operational baseline**
   - structured logs
   - basic metrics
   - executable local backup create/verify/status/resume and restore verify/apply/status/resume
   - protected restore barrier, fresh bootstrap, and authority reconciliation
   - reproducible minimum-profile performance/resource acceptance suite
   - deterministic development setup

### Required specifications

- service bootstrap and configuration spec
- workspace/task/run API spec
- initial database schema and migrations
- single-agent execution-loop spec
- tool contract and sandbox constraints
- artifact upload and metadata spec
- web routes and UI-state spec
- restart reconciliation and recovery spec
- provider credential and secret-handling spec
- local backup/restore and protected operator-state spec
- reference workload, resource-cap, and benchmark acceptance spec

### Non-goals

- parallel subagents
- distributed workers
- arbitrary plugins
- multi-user authorization
- hosted server or remote control
- enterprise policy engine

### Acceptance scenarios

- a task produces at least one stored artifact and completes successfully
- a failed tool call records a structured error and supports retry
- cancellation stops future work and results in a durable terminal state
- a restart during execution does not lose task history, events, or completed artifacts
- corrupted or incomplete artifact upload is detected by checksum or finalization rules
- the UI accurately reflects database state after restart
- a verified local backup restores PostgreSQL and object state, blocks serving through interruption/quarantine, and requires a fresh bootstrap/security epoch
- the complete reference workload satisfies the Phase 1 latency, pool-wait, memory, connection, and admission caps on the minimum profile

### Exit criteria

- one representative workflow completes end to end from the web UI
- all required task, run, event, tool-call, and artifact data survives restart
- the application can be installed and started from documented commands
- core domain, persistence, and recovery tests pass in CI
- local backup/restore recovery scenarios and the complete reference performance/resource suite pass

---

## Phase 2 — Durable multi-agent orchestration

### Outcome

Transform Central from a single-agent runner into a durable orchestration engine that coordinates dependent and parallel subagents, recovers from process or worker failure, and avoids repeating completed durable work.

### Core user journeys

- a parent agent decomposes work into child tasks
- independent child tasks run in parallel
- dependent tasks wait for required outputs
- failed tasks retry according to policy
- paused or interrupted workflows resume from checkpoints
- operators inspect the task graph, lineage, and failure history

### Major workstreams

1. **Workflow graph model**
   - parent-child relationships
   - dependency edges and cycle prevention
   - graph readiness calculation
   - fan-out, fan-in, and aggregation

2. **Scheduler**
   - queue model and leasing
   - concurrency limits
   - fairness and prioritization baseline
   - atomic claim and acknowledgment
   - duplicate-dispatch protection

3. **Workers**
   - worker registration and capabilities
   - heartbeat and lease renewal
   - worker-loss detection
   - abandoned-run reconciliation

4. **Checkpointing**
   - checkpoint schema and versioning
   - safe checkpoint boundaries
   - resume token and compatibility validation
   - checkpoint garbage collection

5. **Retry and failure policy**
   - retryable versus terminal errors
   - exponential backoff and attempt limits
   - timeout hierarchy
   - compensation or cleanup hooks where required

6. **Idempotency and consistency**
   - idempotency keys for commands and steps
   - transactional outbox or equivalent event publication strategy
   - exactly-once effects where feasible and at-least-once execution elsewhere
   - artifact finalization and duplicate prevention

7. **Event history and lineage**
   - immutable execution events
   - task and run reconstruction
   - prompt, model, tool, and configuration versioning
   - artifact parent/child lineage

8. **Graph UI and operations**
   - task graph visualization
   - attempt history
   - blocked dependency reasons
   - retry, resume, pause, and cancel controls

### Required specifications

- workflow graph and scheduling spec
- task leasing and worker protocol
- checkpoint and resume format
- retry, timeout, and error taxonomy
- idempotency and consistency model
- event schema and reconstruction rules
- artifact lineage model
- concurrency and resource-limit policy
- recovery test matrix

### Non-goals

- internet-scale scheduling
- third-party plugin ecosystem
- cloud tenancy and billing
- multi-region execution

### Acceptance scenarios

- a workflow with parallel and dependent children produces a correct final result
- killing the application or worker does not lose completed child outputs
- expired leases cause safe reassignment without duplicate durable effects
- repeated commands with the same idempotency key do not create duplicate tasks or artifacts
- incompatible checkpoints fail safely with an actionable reason
- cancelling a parent propagates according to documented child-cancellation policy

### Exit criteria

- representative multi-agent workflows survive injected process, network, provider, and worker failures
- task graph and event history explain how every final artifact was produced
- retry and recovery behavior is deterministic and covered by failure-path tests

---

## Phase 3 — Extensibility and developer platform

### Outcome

Allow developers to add agents, tools, model providers, and workflow templates without changing the kernel, while preserving isolation, permissions, compatibility, and observability.

### Major workstreams

- agent SDK and manifest
- tool SDK and typed input/output schemas
- model-provider adapter SDK
- plugin discovery, installation, enablement, and versioning
- compatibility and capability negotiation
- MCP client integration for tools and data sources
- execution sandbox and resource limits
- permission grants and approval requirements
- secret references and scoped credential access
- developer CLI, scaffolding, validation, and local test harness
- workflow import, export, templates, and versioning

### Required specifications

- extension manifest schema
- SDK lifecycle and compatibility policy
- plugin trust and installation model
- capability and permission model
- sandbox architecture
- secret-access contract
- MCP integration boundaries
- workflow package format
- developer CLI commands and diagnostics

### Non-goals

- public marketplace economics
- unrestricted native code execution
- enterprise organization policy
- cloud-hosted execution fleet

### Exit criteria

- an external developer can create, test, install, and run an agent and tool without kernel modification
- incompatible or over-privileged extensions fail safely
- extension behavior is observable and attributable by version

---

## Phase 4 — Central Server and Online Mode

### Outcome

Introduce a hosted control plane and enable Local Central to connect outbound as a managed execution node, without requiring a public inbound IP and without sacrificing local data-control options.

### Deployment modes

- fully local
- cloud control with local execution
- selective cloud offload
- fully cloud execution

### Major workstreams

1. **Identity and registration**
   - account, device, and local-node enrollment
   - short-lived credentials and rotation
   - revocation and trust establishment

2. **Connection protocol**
   - outbound persistent connection
   - authentication and session establishment
   - command delivery and acknowledgment
   - ordered event streaming where required
   - reconnect, backoff, and session resume
   - protocol version negotiation

3. **Offline behavior**
   - local command and event buffering
   - conflict and duplicate handling
   - bounded storage and backpressure

4. **Artifact transfer**
   - policy-controlled local-only, metadata-only, or uploaded artifacts
   - multipart transfer, checksum, resume, and encryption
   - signed URLs or brokered transfer

5. **Control and execution planes**
   - task routing
   - node capability advertisement
   - remote execution policies
   - control-plane availability behavior

6. **Server UI and operations**
   - connected nodes
   - remote task submission
   - event and artifact visibility according to policy
   - audit trail for remote commands

### Required specifications

- Online Mode threat model
- node enrollment and credential lifecycle
- wire protocol and state machine
- delivery, acknowledgment, ordering, and deduplication semantics
- offline queue and reconciliation behavior
- artifact transfer and locality policy
- cloud/local source-of-truth rules
- protocol compatibility and rollout strategy
- outage and degraded-mode behavior

### Non-goals

- full enterprise RBAC and SSO
- global multi-region scheduler
- marketplace

### Acceptance scenarios

- Local Central connects from behind NAT without inbound ports
- transient disconnection resumes the session without duplicate durable work
- revoked nodes cannot reconnect or receive commands
- local-only artifact policy prevents payload upload
- server outage does not corrupt local execution state

### Exit criteria

- a user can submit and observe an allowed task remotely
- Local Central can operate through disconnection and reconcile safely
- data locality behavior is explicit, enforceable, and auditable

---

## Phase 5 — Enterprise readiness

### Outcome

Make Central suitable for controlled enterprise pilots with strong tenancy, identity, governance, security, reliability, and operational controls.

### Major workstreams

- organizations, workspaces, projects, and tenant isolation
- users, groups, service accounts, and API credentials
- RBAC and resource-scoped authorization
- OIDC and SAML SSO, lifecycle provisioning where required
- immutable audit logs
- approval workflows for sensitive actions
- policy engine for models, tools, data locality, and network access
- quotas, budgets, usage metering, and rate limits
- encryption, key management, retention, deletion, and legal-hold controls
- observability with metrics, logs, traces, and SLOs
- backup, restore, disaster recovery, and business-continuity testing
- private networking and private deployment options
- administrative APIs and support diagnostics

### Required specifications

- tenancy and isolation model
- authorization matrix
- enterprise identity integration
- audit-event schema and retention
- approval and policy evaluation model
- metering and quota semantics
- data lifecycle and residency model
- backup, restore, RPO, and RTO targets
- observability and SLO specification
- deployment and upgrade strategy

### Exit criteria

- tenant-isolation tests pass
- sensitive actions are authorized, auditable, and optionally approval-gated
- backup and restore are demonstrated
- enterprise deployment, upgrade, and incident procedures are documented
- at least one controlled pilot can operate under agreed security and reliability requirements

---

## Phase 6 — Ecosystem and scale

### Outcome

Evolve Central into a scalable platform with reusable ecosystem assets, advanced scheduling, optimization, collaboration, public APIs, and commercial operations.

### Major workstreams

- agent, tool, and workflow registry or marketplace
- package signing, provenance, moderation, and trust signals
- team collaboration, sharing, comments, and workflow version history
- evaluation datasets, regression suites, and quality gates
- model routing by capability, cost, privacy, and latency
- distributed scheduler and heterogeneous worker pools
- autoscaling, GPU scheduling, placement, and capacity management
- multi-region execution and disaster isolation
- public API, webhooks, SDKs, and integration ecosystem
- usage billing, plans, entitlements, invoices, and commercial controls

### Required specifications

- registry and package-provenance model
- marketplace governance and security model
- evaluation framework and quality metrics
- distributed scheduling and placement model
- autoscaling and capacity policy
- multi-region consistency and failover model
- public API lifecycle and rate limits
- billing ledger and entitlement model

### Exit criteria

- ecosystem packages can be distributed and verified safely
- scheduler meets defined scale and reliability targets
- model routing demonstrates measurable quality, cost, or latency improvements
- public integrations and billing operate with auditable usage records

---

## Cross-phase gates

A later phase must not bypass these gates:

1. **Durability gate:** durable state and artifact behavior must be defined before adding concurrency or distribution.
2. **Security gate:** a capability must have a permission and trust model before being exposed to extensions or remote control.
3. **Observability gate:** every asynchronous operation must be diagnosable before scale is increased.
4. **Compatibility gate:** persisted schemas, checkpoints, manifests, and protocols require versioning before external adoption.
5. **Validation gate:** each phase requires failure-path and recovery testing, not only happy-path demos.
6. **Scope gate:** future-phase abstractions should be introduced early only when a current vertical slice proves they are required.
