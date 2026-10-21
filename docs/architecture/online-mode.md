# Online Mode

Online Mode connects Local Central to a future Central Server without requiring the local machine to expose a public IP address.

## Deployment modes

- **Local only:** execution, state, and artifacts remain on the user's machine or network.
- **Cloud control, local execution:** the server coordinates work while local Central accesses private tools and data.
- **Selective cloud offload:** sensitive tasks remain local while permitted workloads run on cloud workers.
- **Fully hosted:** control, execution, data, and artifacts live in the hosted environment.

## Connection model

Local Central establishes an authenticated outbound, long-lived connection to Central Server. Candidate transports include WebSocket or bidirectional gRPC/Connect streaming. Centrifuge can be useful for realtime event distribution and UI updates, but worker coordination should retain explicit protocol semantics for acknowledgement, leases, retries, and session recovery.

The connection protocol should support:

- device and worker registration
- short-lived authentication and rotation
- command delivery with unique IDs
- acknowledgement and deduplication
- event streaming with sequence numbers
- heartbeat and lease renewal
- reconnection and session resume
- offline command and event buffering
- backpressure and flow control
- protocol version negotiation

## Data ownership

Every task must declare where inputs, execution state, logs, and artifacts may be stored. Hybrid mode must not silently upload local data. Policies should distinguish metadata, redacted output, full artifacts, and secrets.

Artifact transfer should use checksums, resumable multipart transfer where appropriate, explicit encryption, and server-issued scoped credentials or signed URLs.

## Control and execution planes

The Central Server should separate:

- control plane: identity, workspace, policy, orchestration, quota, and billing
- execution plane: agent runtimes and workers
- data plane: PostgreSQL, object storage, logs, and artifact services
- connection plane: authenticated sessions to local and remote workers

## Security requirements

- outbound-only local connectivity by default
- mutual authentication and device revocation
- least-privilege task capabilities
- workspace and organization isolation
- audit logs for commands, approvals, and artifact movement
- no cloud access to local files except through explicitly authorized tools

## Delivery boundary

Online Mode belongs after the local runtime proves durable task completion, recovery, and artifact reproducibility. Cloud connectivity must reuse local execution contracts rather than introduce a second task model.
