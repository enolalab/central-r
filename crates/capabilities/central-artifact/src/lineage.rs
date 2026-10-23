//! Artifact lineage — the pure synchronous port of
//! `central/internal/artifact/lineage.go` (the Phase-2 / b34 provenance
//! model layered on top of the B10 lifecycle).
//!
//! Two journaled edge kinds explain how every final artifact of a run was
//! produced and consumed:
//!
//! - a produce edge `(producing node, attempt) -> artifact`, materialized
//!   exactly once when the artifact reaches the finalized state (B10's
//!   `ready`; the mapping is 1:1 per the lineage spec)
//! - a read edge `(reader node, attempt) -> artifact`, journaled by
//!   `central artifact read` when bytes are released, carrying the
//!   declared|undeclared classification and the finalized checksum the
//!   read bound to
//!
//! This module owns the pure edge model, the failure reason-code
//! taxonomy, the read-scope parser, and the journaled-edge projection
//! types. It never imports a store, a clock, or object storage: the
//! async record/authorize/walk operations consume these types from
//! `app.rs`, persistence lives behind the `crate::port` traits, and every
//! timestamp arrives as caller-supplied durable evidence — the same rule
//! `domain.rs` follows.

use central_foundation::identity::{
    ArtifactId, ContentGeneration, ProduceEdgeId, ReadEdgeId, RunId, SessionAttemptId,
    WorkflowNodeId, WorkspaceId,
};
use time::OffsetDateTime;

use crate::domain::{Failure, FailureClass, State};

// ---------------------------------------------------------------------------
// Failure reason codes (spec: phase-2 artifact lineage, failure semantics)
// ---------------------------------------------------------------------------

/// Refuses a read of an artifact that has not reached the finalized
/// (`ready`) state. It is a scheduling signal, not corruption: the reader
/// may retry after finalization.
pub const REASON_ARTIFACT_NOT_FINALIZED: &str = "ARTIFACT_NOT_FINALIZED";
/// Refuses a read outside the attempt's authorized scope. It is never
/// auto-retried.
pub const REASON_ARTIFACT_SCOPE_DENIED: &str = "ARTIFACT_SCOPE_DENIED";
/// Refuses a read whose id or (producer node key, name) selector resolves
/// to nothing or to more than one artifact.
pub const REASON_ARTIFACT_READ_UNRESOLVED: &str = "ARTIFACT_READ_UNRESOLVED";
/// Flags an authorized read outside the declared artifact in-edge set.
/// Default policy is flag, never refuse: the read succeeds and the
/// journaled edge carries `declared = false`.
pub const REASON_LINEAGE_READ_UNDECLARED: &str = "LINEAGE_READ_UNDECLARED";
/// Fails a read closed when the delivered bytes fail SHA-256 verification
/// against the finalized metadata. Bad bytes are never handed over.
pub const REASON_ARTIFACT_BODY_INTEGRITY: &str = "ARTIFACT_BODY_INTEGRITY";
/// Marks an authorized read whose outcome is unknown (disconnect
/// mid-stream). The edge is completed once known and never
/// double-counted, per the attempt-scoped dedupe.
pub const REASON_ARTIFACT_READ_AMBIGUOUS: &str = "ARTIFACT_READ_AMBIGUOUS";

/// The store handle required for a lineage operation was absent — the
/// caller wired a `None`/missing port.
pub const REASON_LINEAGE_STORE_UNAVAILABLE: &str = "LINEAGE_STORE_UNAVAILABLE";
/// A node-scoped lineage query arrived without a node identity.
pub const REASON_LINEAGE_NODE_REQUIRED: &str = "LINEAGE_NODE_REQUIRED";
/// An artifact-scoped lineage query arrived without an artifact identity.
pub const REASON_LINEAGE_ARTIFACT_REQUIRED: &str = "LINEAGE_ARTIFACT_REQUIRED";
/// A run-scoped lineage query arrived without a run identity.
pub const REASON_LINEAGE_RUN_REQUIRED: &str = "LINEAGE_RUN_REQUIRED";
/// A produce edge is missing one of its required identities.
pub const REASON_LINEAGE_PRODUCE_EDGE_INCOMPLETE: &str = "LINEAGE_PRODUCE_EDGE_INCOMPLETE";
/// A read edge is missing one of its required identities.
pub const REASON_LINEAGE_READ_EDGE_INCOMPLETE: &str = "LINEAGE_READ_EDGE_INCOMPLETE";
/// The `(reader_node_id, attempt_id)` pair of a read edge is half-present:
/// an attempt-scoped edge names both, the operator reader names neither
/// (mirrors the b34 `artifact_read_edges_reader_pair_check`).
pub const REASON_LINEAGE_READ_EDGE_READER_PAIR_MISMATCH: &str =
    "LINEAGE_READ_EDGE_READER_PAIR_MISMATCH";
/// A read edge's checksum is not the finalized 64-character lowercase hex
/// SHA-256 the read binds to.
pub const REASON_LINEAGE_READ_EDGE_CHECKSUM_REQUIRED: &str = "LINEAGE_READ_EDGE_CHECKSUM_REQUIRED";
/// A `CENTRAL_ATTEMPT_SCOPE` value is not a well-formed
/// `"<run_id>:<node_id>:<attempt_id>"` triple.
pub const REASON_ATTEMPT_SCOPE_INVALID: &str = "ATTEMPT_SCOPE_INVALID";

/// Wraps a closed reason code in the artifact domain's typed failure
/// surface (upstream `lineageFailure`): the class stays inside the
/// existing closed set, the reason carries the lineage vocabulary.
const fn lineage_failure(class: FailureClass, reason: &'static str) -> Failure {
    Failure::new(class, reason)
}

// ---------------------------------------------------------------------------
// Edges
// ---------------------------------------------------------------------------

/// Journals that `(node, attempt)` of `run_id` produced `artifact_id`
/// when it finalized. Exactly one produce edge ever exists per artifact:
/// a replayed finalization dedupes on `artifact_id` and returns the
/// journaled edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProduceEdge {
    /// The journaled edge identity (UUIDv4 — `artifact_produce_edges.id`).
    pub id: ProduceEdgeId,
    /// The run the producer executed under.
    pub run_id: RunId,
    /// The producing workflow node (`workflow_nodes.id`).
    pub node_id: WorkflowNodeId,
    /// The producing session attempt.
    pub attempt_id: SessionAttemptId,
    /// The produced artifact — unique across all produce edges.
    pub artifact_id: ArtifactId,
    /// The durable journal timestamp (`DEFAULT now()` at insert).
    pub created_at: OffsetDateTime,
}

impl ProduceEdge {
    /// Fails with [`REASON_LINEAGE_PRODUCE_EDGE_INCOMPLETE`] when any
    /// required identity is nil (upstream `ProduceEdge.validate`).
    ///
    /// Nil identities are unreachable through `new`/`parse` — this check
    /// exists because a corrupted `from_trusted_db_bytes` row can smuggle
    /// a nil past the type boundary, exactly the gate upstream's
    /// `uuid.Nil` comparison performs.
    pub fn validate(&self) -> Result<(), Failure> {
        if self.id.is_nil()
            || self.run_id.is_nil()
            || self.node_id.is_nil()
            || self.attempt_id.is_nil()
            || self.artifact_id.is_nil()
        {
            return Err(lineage_failure(
                FailureClass::Invalid,
                REASON_LINEAGE_PRODUCE_EDGE_INCOMPLETE,
            ));
        }
        Ok(())
    }
}

/// Journals that `(reader node, attempt)` of `run_id` read `artifact_id`,
/// binding the finalized checksum (content generation) actually read and
/// the declared|undeclared classification. `reader_node_id` and
/// `attempt_id` are `None` together for the synthetic operator reader
/// (spec OQ-5): an operator read outside any node context is still
/// journaled, attributed to no node.
#[derive(Debug, Clone, PartialEq)]
pub struct ReadEdge {
    /// The journaled edge identity (UUIDv4 — `artifact_read_edges.id`).
    pub id: ReadEdgeId,
    /// The run the edge files under — the reader's run for an attempt
    /// scope, the artifact's own run for the operator reader.
    pub run_id: RunId,
    /// The reading workflow node; `None` iff `attempt_id` is `None`.
    pub reader_node_id: Option<WorkflowNodeId>,
    /// The reading session attempt; `None` iff `reader_node_id` is `None`.
    pub attempt_id: Option<SessionAttemptId>,
    /// The read artifact.
    pub artifact_id: ArtifactId,
    /// Whether the read was inside the node's declared artifact in-edge
    /// set (`false` = the flagged undeclared classification).
    pub declared: bool,
    /// The finalized 64-character lowercase hex SHA-256 checksum the read
    /// bound to.
    pub checksum: String,
    /// The durable journal timestamp (`DEFAULT now()` at insert).
    pub created_at: OffsetDateTime,
}

/// Reports whether `checksum` is exactly the finalized SHA-256 hex form a
/// journaled read edge binds to: 64 lowercase hex characters. The b34
/// `checksum text NOT NULL` column stores hex, never raw bytes.
fn is_sha256_hex(checksum: &str) -> bool {
    checksum.len() == 64
        && checksum
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl ReadEdge {
    /// Validates the journaled-edge invariants (upstream
    /// `ReadEdge.validate`, with the pair and checksum causes split into
    /// their own closed reason codes):
    ///
    /// - every required identity is non-nil —
    ///   [`REASON_LINEAGE_READ_EDGE_INCOMPLETE`];
    /// - the `(reader_node_id, attempt_id)` pair is all-or-nothing —
    ///   [`REASON_LINEAGE_READ_EDGE_READER_PAIR_MISMATCH`];
    /// - `checksum` is the finalized 64-char lowercase hex SHA-256 —
    ///   [`REASON_LINEAGE_READ_EDGE_CHECKSUM_REQUIRED`].
    pub fn validate(&self) -> Result<(), Failure> {
        if self.id.is_nil() || self.run_id.is_nil() || self.artifact_id.is_nil() {
            return Err(lineage_failure(
                FailureClass::Invalid,
                REASON_LINEAGE_READ_EDGE_INCOMPLETE,
            ));
        }
        // The NULL pair is all-or-nothing (mirrors the b34
        // artifact_read_edges_reader_pair_check): an attempt-scoped edge
        // names both node and attempt, the operator reader names neither.
        if self.reader_node_id.is_none() != self.attempt_id.is_none() {
            return Err(lineage_failure(
                FailureClass::Invalid,
                REASON_LINEAGE_READ_EDGE_READER_PAIR_MISMATCH,
            ));
        }
        if self.reader_node_id.is_some_and(|node_id| node_id.is_nil())
            || self
                .attempt_id
                .is_some_and(|attempt_id| attempt_id.is_nil())
        {
            return Err(lineage_failure(
                FailureClass::Invalid,
                REASON_LINEAGE_READ_EDGE_INCOMPLETE,
            ));
        }
        if !is_sha256_hex(&self.checksum) {
            return Err(lineage_failure(
                FailureClass::Invalid,
                REASON_LINEAGE_READ_EDGE_CHECKSUM_REQUIRED,
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Read authorization (the `central artifact read` decision)
// ---------------------------------------------------------------------------

/// Binds a read to its authorizing identity (upstream `ReadScope`). The
/// `Attempt` scope is the `(run, node, attempt)` triple the dispatcher
/// injects via `CENTRAL_ATTEMPT_SCOPE`; `Operator` is the synthetic
/// operator reader of spec OQ-5 when the variable is absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadScope {
    /// One dispatched attempt's credential.
    Attempt {
        /// The run the attempt executes under.
        run_id: RunId,
        /// The node the attempt executes as.
        node_id: WorkflowNodeId,
        /// The session attempt identity.
        attempt_id: SessionAttemptId,
    },
    /// The synthetic operator reader — authorized for any finalized
    /// artifact, always journaled undeclared.
    Operator,
}

impl ReadScope {
    /// Whether this is the operator scope (no attempt credential).
    #[must_use]
    pub const fn is_operator(&self) -> bool {
        matches!(self, Self::Operator)
    }

    /// Fails with [`REASON_ATTEMPT_SCOPE_INVALID`] when an `Attempt`
    /// scope carries a nil identity (upstream `ReadScope.validate`).
    /// `Operator` is always valid.
    pub fn validate(&self) -> Result<(), Failure> {
        match *self {
            Self::Attempt {
                run_id,
                node_id,
                attempt_id,
            } => {
                if run_id.is_nil() || node_id.is_nil() || attempt_id.is_nil() {
                    return Err(lineage_failure(
                        FailureClass::Invalid,
                        REASON_ATTEMPT_SCOPE_INVALID,
                    ));
                }
                Ok(())
            }
            Self::Operator => Ok(()),
        }
    }
}

/// Parses the `CENTRAL_ATTEMPT_SCOPE` value
/// `"<run_id>:<node_id>:<attempt_id>"` (upstream `ParseAttemptScope`). An
/// empty input yields the operator scope — no attempt credential is
/// injected outside a dispatched attempt.
///
/// Each part is parsed through the strict identity newtype parsers
/// (canonical lowercase RFC 9562 text, version 7, non-nil) — stricter
/// than upstream's version-agnostic `uuid.FromString`, which is correct:
/// the dispatcher mints every scope identity as UUIDv7.
pub fn parse_attempt_scope(value: &str) -> Result<ReadScope, Failure> {
    if value.is_empty() {
        return Ok(ReadScope::Operator);
    }
    let invalid = || lineage_failure(FailureClass::Invalid, REASON_ATTEMPT_SCOPE_INVALID);
    let parts: Vec<&str> = value.split(':').collect();
    if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) {
        return Err(invalid());
    }
    let run_id = RunId::parse(parts[0]).map_err(|_| invalid())?;
    let node_id = WorkflowNodeId::parse(parts[1]).map_err(|_| invalid())?;
    let attempt_id = SessionAttemptId::parse(parts[2]).map_err(|_| invalid())?;
    Ok(ReadScope::Attempt {
        run_id,
        node_id,
        attempt_id,
    })
}

/// The minimal projection of `central.artifacts` the read path
/// authorizes against (upstream `LineageArtifact`): identity, lifecycle
/// state, the opaque ready key the body lives under, and the finalized
/// checksum the read binds to.
#[derive(Debug, Clone, PartialEq)]
pub struct LineageArtifact {
    /// The artifact identity.
    pub id: ArtifactId,
    /// Owning workspace.
    pub workspace_id: WorkspaceId,
    /// The run that produced the artifact.
    pub run_id: RunId,
    /// Current lifecycle state — only [`State::Ready`] is readable.
    pub state: State,
    /// The opaque ready key (`v1/ready/...`), empty until promoted.
    pub ready_key: String,
    /// The finalized SHA-256 hex checksum; empty until verified.
    pub checksum: String,
}

/// How a [`ReadRequest`] selects its artifact (upstream's
/// `ArtifactID`-or-`FromNodeKey`+`Name` request shape, made
/// unrepresentable-when-invalid as an enum).
#[derive(Debug, Clone, PartialEq)]
pub enum ReadSelector {
    /// Resolve by artifact identity directly.
    ByArtifactId(ArtifactId),
    /// Resolve inside the run's graph by the producing node's key and the
    /// required-role name.
    ByProduced {
        /// The producer node's key.
        from_node_key: String,
        /// The required-output role name.
        name: String,
    },
}

/// Selects one artifact for one scope (upstream `ReadRequest`). Exactly
/// one resolution mode applies, enforced by [`ReadSelector`].
#[derive(Debug, Clone, PartialEq)]
pub struct ReadRequest {
    /// The authorizing read scope.
    pub scope: ReadScope,
    /// The artifact selector.
    pub selector: ReadSelector,
}

impl ReadRequest {
    /// Validates the embedded scope (upstream's `req.Scope.validate()`);
    /// the selector needs no check — `ByProduced` cannot exist without
    /// both halves, and `ByArtifactId` nil-ness is caught at resolution.
    pub fn validate(&self) -> Result<(), Failure> {
        self.scope.validate()
    }
}

/// The approved read decision (upstream `ReadAuthorization`): the
/// resolved artifact and the declared classification the journaled edge
/// will carry.
#[derive(Debug, Clone, PartialEq)]
pub struct ReadAuthorization {
    /// The resolved artifact projection.
    pub artifact: LineageArtifact,
    /// The authorizing read scope.
    pub scope: ReadScope,
    /// Whether the artifact is inside the reader's declared set.
    pub declared: bool,
}

impl ReadAuthorization {
    /// Builds the journaled read edge for this authorization bound to the
    /// finalized checksum (upstream `ReadAuthorization.Edge`), minting a
    /// fresh [`ReadEdgeId`]. The run the edge files under is the reader's
    /// run for an attempt scope (an `input_artifact_refs` read can
    /// legitimately cross runs, spec OQ-3) and the artifact's own run for
    /// the operator reader.
    ///
    /// `created_at` is caller-supplied durable evidence — the domain
    /// never reads a clock. The persisted row's timestamp is assigned by
    /// the store's `DEFAULT now()` column; this value is the edge's
    /// carried projection.
    #[must_use]
    pub fn edge(&self, created_at: OffsetDateTime) -> ReadEdge {
        let (run_id, reader_node_id, attempt_id) = match self.scope {
            ReadScope::Attempt {
                run_id,
                node_id,
                attempt_id,
            } => (run_id, Some(node_id), Some(attempt_id)),
            ReadScope::Operator => (self.artifact.run_id, None, None),
        };
        ReadEdge {
            id: ReadEdgeId::new(),
            run_id,
            reader_node_id,
            attempt_id,
            artifact_id: self.artifact.id,
            declared: self.declared,
            checksum: self.artifact.checksum.clone(),
            created_at,
        }
    }
}

/// The closure explaining every final artifact of a run (upstream
/// `RunLineage`): all journaled produce and read edges. It is what the
/// graph UI renders and what the Phase-2 exit audit consumes; undeclared
/// reads arrive flagged, never hidden.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RunLineage {
    /// Every produce edge journaled inside the run.
    pub produced: Vec<ProduceEdge>,
    /// Every read edge journaled inside the run.
    pub read: Vec<ReadEdge>,
}

// ---------------------------------------------------------------------------
// Attempt-scoped finalization (spec-5 section 5)
// ---------------------------------------------------------------------------

/// A nil identity or empty name in a finalize command (upstream
/// `INVALID_FINALIZE_INPUT`, `FailureInvalid`).
pub const REASON_INVALID_FINALIZE_INPUT: &str = "INVALID_FINALIZE_INPUT";
/// The `(attempt_id, artifact_name)` key row already names a different
/// checksum, or the artifact's produce edge was journaled under a
/// different attempt (upstream `ARTIFACT_ALREADY_FINALIZED`,
/// `FailureConflict`).
pub const REASON_ARTIFACT_ALREADY_FINALIZED: &str = "ARTIFACT_ALREADY_FINALIZED";
/// The artifact row's stored `checksum_value` does not equal the
/// caller's verified body digest (upstream
/// `ARTIFACT_CHECKSUM_MISMATCH`, `FailureConflict`).
pub const REASON_ARTIFACT_CHECKSUM_MISMATCH: &str = "ARTIFACT_CHECKSUM_MISMATCH";
/// The artifact's producer chain — `workspace_id`, `run_id`, or
/// `required_role` — does not match the producing attempt's durable
/// coordinates (upstream `PRODUCER_CHAIN_MISMATCH`, `FailureDenied`).
pub const REASON_PRODUCER_CHAIN_MISMATCH: &str = "PRODUCER_CHAIN_MISMATCH";
/// The producing attempt id does not name a `central.session_attempts`
/// row (upstream `ATTEMPT_NOT_FOUND`, `FailureConflict`).
pub const REASON_ATTEMPT_NOT_FOUND: &str = "ATTEMPT_NOT_FOUND";
/// The artifact id does not name a `central.artifacts` row (upstream
/// `ARTIFACT_NOT_FOUND`, `FailureConflict`).
pub const REASON_FINALIZE_ARTIFACT_NOT_FOUND: &str = "ARTIFACT_NOT_FOUND";

/// The raw attempt-scoped finalize command (upstream
/// `FinalizeAttemptArtifact`'s parameter list plus the coordinates the
/// change set must carry): the caller — the attempt-outcome path the
/// scheduler owns — binds the artifact it verified and promoted,
/// including the producing attempt's run/node coordinates and the
/// artifact's `content_generation`, so the commit can re-validate them
/// against durable state instead of trusting a mid-flight snapshot.
#[derive(Debug, Clone, PartialEq)]
pub struct FinalizeAttemptInput {
    /// The producing attempt (the key row's `attempt_id` half).
    pub attempt_id: SessionAttemptId,
    /// `artifacts.required_role` — the name the artifact resolves under
    /// for `central artifact read --from <node_key> --name <name>` (the
    /// key row's `artifact_name` half).
    pub artifact_name: String,
    /// The artifact row to transition `verifying` → `ready`.
    pub artifact_id: ArtifactId,
    /// The run the producing attempt belongs to; re-validated against
    /// `session_attempts.run_id` inside the commit.
    pub run_id: RunId,
    /// The workflow node the producing attempt belongs to; re-validated
    /// against `session_attempts.node_id` inside the commit.
    pub node_id: WorkflowNodeId,
    /// The verified body SHA-256 the artifacts row already carries
    /// (`checksum_value`); a mismatch aborts the commit as
    /// [`REASON_ARTIFACT_CHECKSUM_MISMATCH`].
    pub checksum: [u8; 32],
    /// The canonical-command fingerprint stored on the key row for
    /// audit (32-byte SHA-256 width enforced by the type).
    pub payload_fingerprint: [u8; 32],
    /// The content generation the B10 promote stage recorded;
    /// re-validated against `artifacts.content_generation` inside the
    /// commit so a stale promotion binding cannot finalize.
    pub content_generation: ContentGeneration,
}

/// The artifact-owned change set [`attempt_finalization`] produces —
/// what `port::AttemptFinalizationStore` maps in one transaction to the
/// `artifact_finalizations` key row, the `verifying` → `ready`
/// transition, the journaled produce edge, and the `artifact_finalized`
/// run event.
///
/// `central-artifact` deliberately holds no journal types: the run-event
/// envelope is the adapter's mapping, keeping the capability free of
/// the `central-eventjournal` edge.
#[derive(Debug, Clone, PartialEq)]
pub struct AttemptFinalization {
    /// See [`FinalizeAttemptInput`].
    pub attempt_id: SessionAttemptId,
    /// See [`FinalizeAttemptInput`].
    pub artifact_name: String,
    /// See [`FinalizeAttemptInput`].
    pub artifact_id: ArtifactId,
    /// See [`FinalizeAttemptInput`].
    pub run_id: RunId,
    /// See [`FinalizeAttemptInput`].
    pub node_id: WorkflowNodeId,
    /// See [`FinalizeAttemptInput`].
    pub checksum: [u8; 32],
    /// See [`FinalizeAttemptInput`].
    pub payload_fingerprint: [u8; 32],
    /// See [`FinalizeAttemptInput`].
    pub content_generation: ContentGeneration,
}

/// Evaluates the caller's finalize command into the validated
/// [`AttemptFinalization`] change set — the capability's half of
/// upstream `FinalizeAttemptArtifact`'s input guard. `checksum` and
/// `payload_fingerprint` are 32 bytes by construction (`[u8; 32]` —
/// upstream's `INVALID_CHECKSUM`/`INVALID_FINGERPRINT` length guards are
/// unreachable in Rust); nil identities, a nil content generation, or an
/// empty artifact name is [`REASON_INVALID_FINALIZE_INPUT`].
pub fn attempt_finalization(input: &FinalizeAttemptInput) -> Result<AttemptFinalization, Failure> {
    if input.attempt_id.is_nil()
        || input.artifact_id.is_nil()
        || input.run_id.is_nil()
        || input.node_id.is_nil()
        || input.artifact_name.is_empty()
        || input.content_generation.is_nil()
    {
        return Err(lineage_failure(
            FailureClass::Invalid,
            REASON_INVALID_FINALIZE_INPUT,
        ));
    }
    Ok(AttemptFinalization {
        attempt_id: input.attempt_id,
        artifact_name: input.artifact_name.clone(),
        artifact_id: input.artifact_id,
        run_id: input.run_id,
        node_id: input.node_id,
        checksum: input.checksum,
        payload_fingerprint: input.payload_fingerprint,
        content_generation: input.content_generation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed valid UUIDv7 for deterministic ids.
    const V7_A: &str = "018f3b2a-1c4d-7e9f-8a1b-2c3d4e5f6a7b";
    /// A second fixed valid UUIDv7.
    const V7_B: &str = "0190a1b2-c3d4-7e5f-9a8b-7c6d5e4f3a2b";
    /// A third fixed valid UUIDv7.
    const V7_C: &str = "0177eeff-ddcc-7baa-8998-776655443322";
    /// A fixed valid UUIDv4 for edge identities.
    const V4_A: &str = "550e8400-e29b-41d4-a716-446655440000";
    /// A second fixed valid UUIDv4.
    const V4_B: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    /// A valid 64-char lowercase SHA-256 hex checksum.
    const SHA256_HEX: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    fn run_id() -> RunId {
        RunId::parse(V7_A).unwrap()
    }

    fn node_id() -> WorkflowNodeId {
        WorkflowNodeId::parse(V7_B).unwrap()
    }

    fn attempt_id() -> SessionAttemptId {
        SessionAttemptId::parse(V7_C).unwrap()
    }

    fn artifact_id() -> ArtifactId {
        ArtifactId::parse(V7_C).unwrap()
    }

    fn timestamp() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    fn produce_edge() -> ProduceEdge {
        ProduceEdge {
            id: ProduceEdgeId::parse(V4_A).unwrap(),
            run_id: run_id(),
            node_id: node_id(),
            attempt_id: attempt_id(),
            artifact_id: artifact_id(),
            created_at: timestamp(),
        }
    }

    fn read_edge() -> ReadEdge {
        ReadEdge {
            id: ReadEdgeId::parse(V4_B).unwrap(),
            run_id: run_id(),
            reader_node_id: Some(node_id()),
            attempt_id: Some(attempt_id()),
            artifact_id: artifact_id(),
            declared: true,
            checksum: SHA256_HEX.to_owned(),
            created_at: timestamp(),
        }
    }

    fn ready_artifact() -> LineageArtifact {
        LineageArtifact {
            id: artifact_id(),
            workspace_id: WorkspaceId::parse(V7_A).unwrap(),
            run_id: run_id(),
            state: State::Ready,
            ready_key: "v1/ready-key".to_owned(),
            checksum: SHA256_HEX.to_owned(),
        }
    }

    // --- reason codes ---------------------------------------------------

    /// The lineage reason-code vocabulary is closed and exact (upstream
    /// `TestLineageReasonCodesAreClosed`).
    #[test]
    fn lineage_reason_codes_are_closed() {
        assert_eq!(REASON_ARTIFACT_NOT_FINALIZED, "ARTIFACT_NOT_FINALIZED");
        assert_eq!(REASON_ARTIFACT_SCOPE_DENIED, "ARTIFACT_SCOPE_DENIED");
        assert_eq!(REASON_ARTIFACT_READ_UNRESOLVED, "ARTIFACT_READ_UNRESOLVED");
        assert_eq!(REASON_LINEAGE_READ_UNDECLARED, "LINEAGE_READ_UNDECLARED");
        assert_eq!(REASON_ARTIFACT_BODY_INTEGRITY, "ARTIFACT_BODY_INTEGRITY");
        assert_eq!(REASON_ARTIFACT_READ_AMBIGUOUS, "ARTIFACT_READ_AMBIGUOUS");
    }

    // --- ProduceEdge::validate ------------------------------------------

    #[test]
    fn produce_edge_validates_complete_edge() {
        produce_edge().validate().unwrap();
    }

    #[test]
    fn produce_edge_rejects_nil_identity() {
        for edge in [
            ProduceEdge {
                id: ProduceEdgeId::from_trusted_db_bytes([0; 16]),
                ..produce_edge()
            },
            ProduceEdge {
                run_id: RunId::from_trusted_db_bytes([0; 16]),
                ..produce_edge()
            },
            ProduceEdge {
                node_id: WorkflowNodeId::from_trusted_db_bytes([0; 16]),
                ..produce_edge()
            },
            ProduceEdge {
                attempt_id: SessionAttemptId::from_trusted_db_bytes([0; 16]),
                ..produce_edge()
            },
            ProduceEdge {
                artifact_id: ArtifactId::from_trusted_db_bytes([0; 16]),
                ..produce_edge()
            },
        ] {
            let failure = edge.validate().unwrap_err();
            assert_eq!(failure.class, FailureClass::Invalid);
            assert_eq!(failure.reason, REASON_LINEAGE_PRODUCE_EDGE_INCOMPLETE);
        }
    }

    // --- ReadEdge::validate ---------------------------------------------

    #[test]
    fn read_edge_validates_attempt_and_operator_edges() {
        read_edge().validate().unwrap();
        // The operator edge: both reader pair halves absent.
        let operator = ReadEdge {
            reader_node_id: None,
            attempt_id: None,
            ..read_edge()
        };
        operator.validate().unwrap();
    }

    /// The NULL pair is all-or-nothing (upstream
    /// `TestRecordReadNullPairAllOrNothing`): a node without an attempt —
    /// or an attempt without a node — violates the pair check.
    #[test]
    fn read_edge_rejects_half_present_reader_pair() {
        for edge in [
            ReadEdge {
                attempt_id: None,
                ..read_edge()
            },
            ReadEdge {
                reader_node_id: None,
                ..read_edge()
            },
        ] {
            let failure = edge.validate().unwrap_err();
            assert_eq!(failure.class, FailureClass::Invalid);
            assert_eq!(
                failure.reason,
                REASON_LINEAGE_READ_EDGE_READER_PAIR_MISMATCH
            );
        }
    }

    #[test]
    fn read_edge_rejects_nil_identity() {
        for edge in [
            ReadEdge {
                id: ReadEdgeId::from_trusted_db_bytes([0; 16]),
                ..read_edge()
            },
            ReadEdge {
                run_id: RunId::from_trusted_db_bytes([0; 16]),
                ..read_edge()
            },
            ReadEdge {
                artifact_id: ArtifactId::from_trusted_db_bytes([0; 16]),
                ..read_edge()
            },
            ReadEdge {
                reader_node_id: Some(WorkflowNodeId::from_trusted_db_bytes([0; 16])),
                ..read_edge()
            },
            ReadEdge {
                attempt_id: Some(SessionAttemptId::from_trusted_db_bytes([0; 16])),
                ..read_edge()
            },
        ] {
            let failure = edge.validate().unwrap_err();
            assert_eq!(failure.reason, REASON_LINEAGE_READ_EDGE_INCOMPLETE);
        }
    }

    /// The journaled checksum must be the finalized 64-char lowercase hex
    /// SHA-256 — empty, short, long, uppercase, and non-hex all reject.
    #[test]
    fn read_edge_rejects_non_sha256_checksums() {
        for checksum in [
            "",
            "x",
            "deadbeef",
            "abc123",
            &SHA256_HEX[..63],
            &format!("{SHA256_HEX}0"),
            &SHA256_HEX.to_uppercase(),
            &SHA256_HEX.replacen('9', "g", 1),
        ] {
            let edge = ReadEdge {
                checksum: checksum.to_owned(),
                ..read_edge()
            };
            let failure = edge.validate().unwrap_err();
            assert_eq!(failure.class, FailureClass::Invalid);
            assert_eq!(failure.reason, REASON_LINEAGE_READ_EDGE_CHECKSUM_REQUIRED);
        }
    }

    // --- parse_attempt_scope ---------------------------------------------

    /// An empty `CENTRAL_ATTEMPT_SCOPE` yields the operator scope
    /// (upstream `TestParseAttemptScopeOperator`).
    #[test]
    fn parse_attempt_scope_empty_is_operator() {
        let scope = parse_attempt_scope("").unwrap();
        assert!(scope.is_operator());
        scope.validate().unwrap();
    }

    /// A well-formed triple parses into the attempt scope (upstream
    /// `TestParseAttemptScopeAttempt`).
    #[test]
    fn parse_attempt_scope_parses_triple() {
        let raw = format!("{V7_A}:{V7_B}:{V7_C}");
        let scope = parse_attempt_scope(&raw).unwrap();
        assert!(!scope.is_operator());
        assert_eq!(
            scope,
            ReadScope::Attempt {
                run_id: run_id(),
                node_id: node_id(),
                attempt_id: attempt_id(),
            }
        );
        scope.validate().unwrap();
    }

    /// Malformed scope values are rejected (upstream
    /// `TestParseAttemptScopeRejectsMalformed`).
    #[test]
    fn parse_attempt_scope_rejects_malformed() {
        for bad in [
            "not-a-uuid",
            V7_A,
            &format!("{V7_A}:{V7_B}"),
            &format!("{V7_A}:{V7_B}:zzz"),
            &format!("{V7_A}:{V7_B}:{V7_C}:extra"),
            &format!(":{V7_A}:"),
            "::",
            &format!("{V7_A}::{V7_C}"),
        ] {
            let failure = parse_attempt_scope(bad).unwrap_err();
            assert_eq!(failure.class, FailureClass::Invalid);
            assert_eq!(failure.reason, REASON_ATTEMPT_SCOPE_INVALID);
        }
    }

    /// A version-4 part fails the strict identity parse even though
    /// upstream's version-agnostic `uuid.FromString` would accept it: the
    /// dispatcher only ever injects UUIDv7 identities.
    #[test]
    fn parse_attempt_scope_rejects_wrong_uuid_version() {
        let failure = parse_attempt_scope(&format!("{V4_A}:{V7_B}:{V7_C}")).unwrap_err();
        assert_eq!(failure.reason, REASON_ATTEMPT_SCOPE_INVALID);
    }

    #[test]
    fn read_scope_validate_rejects_nil_attempt_identity() {
        let scope = ReadScope::Attempt {
            run_id: RunId::from_trusted_db_bytes([0; 16]),
            node_id: node_id(),
            attempt_id: attempt_id(),
        };
        let failure = scope.validate().unwrap_err();
        assert_eq!(failure.reason, REASON_ATTEMPT_SCOPE_INVALID);
    }

    // --- ReadAuthorization::edge ----------------------------------------

    /// The attempt edge carries the reader node and attempt and files
    /// under the reader's run (upstream `TestAuthorizeReadByIDDeclared`'s
    /// edge assertions).
    #[test]
    fn edge_for_attempt_scope_carries_reader_pair() {
        let auth = ReadAuthorization {
            artifact: ready_artifact(),
            scope: ReadScope::Attempt {
                run_id: run_id(),
                node_id: node_id(),
                attempt_id: attempt_id(),
            },
            declared: true,
        };
        let edge = auth.edge(timestamp());
        assert!(!edge.id.is_nil());
        assert_eq!(edge.reader_node_id, Some(node_id()));
        assert_eq!(edge.attempt_id, Some(attempt_id()));
        assert_eq!(edge.run_id, run_id());
        assert_eq!(edge.artifact_id, artifact_id());
        assert!(edge.declared);
        assert_eq!(edge.checksum, SHA256_HEX);
        edge.validate().unwrap();
    }

    /// The operator edge files under the artifact's own run and carries
    /// the NULL reader/attempt pair (upstream
    /// `TestAuthorizeReadFromSelectorResolves`'s edge assertions).
    #[test]
    fn edge_for_operator_scope_files_under_artifact_run() {
        let auth = ReadAuthorization {
            artifact: ready_artifact(),
            scope: ReadScope::Operator,
            declared: false,
        };
        let edge = auth.edge(timestamp());
        assert_eq!(edge.reader_node_id, None);
        assert_eq!(edge.attempt_id, None);
        assert_eq!(edge.run_id, auth.artifact.run_id);
        assert!(!edge.declared);
        edge.validate().unwrap();
    }
}
