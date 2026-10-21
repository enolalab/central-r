# Product Vision

## Definition

Central is a local-first durable AI workspace that lets agents and subagents perform long-running work on local data, tools, and infrastructure with observable state, checkpoints, resumability, and managed artifacts.

Central is not primarily a chat interface. Its core abstraction is a durable task or workflow with explicit lifecycle, tools, outputs, and recovery behavior.

## Product principles

1. **Local first:** users can operate without a hosted control plane, and sensitive resources can remain on their machines or networks.
2. **Durable by default:** important work survives process, worker, model, and network failures.
3. **Observable execution:** users can inspect plans, steps, logs, state transitions, artifacts, failures, and costs.
4. **Controlled agency:** privileged tools are permissioned, scoped, and subject to approval policies.
5. **Portable integrations:** models, agents, and tools should be replaceable through stable contracts.
6. **Cloud optionality:** the same concepts can later support hybrid and fully hosted execution.

## Core differentiators

- Task lifecycle rather than ephemeral chat turns
- Multi-agent orchestration and dependency graphs
- Persisted checkpoints and resumable runs
- Artifact metadata, lineage, and object storage
- Local access to repositories, files, databases, and internal services
- Approval boundaries for risky operations
- A future hybrid mode with cloud control and local execution

## Initial users

The initial product should serve technical users and small teams that need reliable local automation for software development, document research, data processing, and repository-scale migration work.

## Non-goals for the first release

- General-purpose enterprise multi-tenancy
- Marketplace and billing
- Kubernetes-first distributed scheduling
- Autonomous production changes without approval
- A complex frontend framework
