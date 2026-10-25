//! Pure sync root for the issue-#122 run-submission saga — the port of
//! `internal/runsubmit/runsubmit.go`'s constants, request/result shapes,
//! request bounds, fixed task-input marker, and child-spec batches.
//!
//! Everything here is deterministic: no clock reads, no I/O. The saga
//! ([`crate::app::Service`]) calls [`validate_request`] and
//! [`prevalidate`] before the first durable commit so a refused
//! submission writes nothing.

use std::collections::BTreeSet;

use central_foundation::failure::Failure;
use central_foundation::identity::{TaskId, WorkflowNodeId, WorkspaceId};
use central_workflow::domain::{
    BudgetCeiling, Caps, ChildSpec, ChildSpecNode, NodeStatus, WorkspaceKind,
};
use central_workflow::validate::{self, HarnessRegistry, Rejection};

/// `OwnerPhase2` — the claim owner a submitted run carries: it excludes
/// the run from Phase-1 dispatch case (a) while leaving the Phase-2
/// scheduler path untouched.
pub const OWNER_PHASE2: &str = "phase2";

/// `LeaderKey` — the root node key of every submitted run.
pub const LEADER_KEY: &str = "leader";

/// `MinWorkers` — the lower bound of the child fan-out.
pub const MIN_WORKERS: i64 = 1;
/// `MaxWorkers` — the upper bound of the child fan-out.
pub const MAX_WORKERS: i64 = 8;
/// `MaxTitleRunes` — bounds the operator title (displayed, escaped).
pub const MAX_TITLE_RUNES: usize = 200;
/// `MaxRunKeyBytes` — bounds the optional dedup key (`runs.run_key` is
/// unbounded text; the service enforces the bound on both surfaces).
pub const MAX_RUN_KEY_BYTES: usize = 128;
/// `HarnessName` — the only launchable harness (serve parity).
pub const HARNESS_NAME: &str = "claude-code";

/// Stable failure codes this capability raises.
pub mod codes {
    /// A request-shape refusal — the Rust `ValidationError` marker.
    /// Surfaces map it to a generic usage outcome (CLI `RUN_USAGE`
    /// exit 2, HTTP 400); the message names the field token, never
    /// the offending value.
    pub const REQUEST_VALIDATION: &str = "runsubmit_request_validation";
    /// An internal saga invariant surprise (commit fan-out or a node
    /// that fails to read `ready` after the flip) — upstream's plain
    /// `fmt.Errorf` path, reported to surfaces as a terminal failure.
    pub const INVARIANT: &str = "runsubmit_invariant";
    /// The spec-5 replay-conflict token the `run_key` coordinate
    /// shares with the `node_key` coordinate — the recorded row
    /// stands. Carries upstream's exact string.
    pub const DUPLICATE_IDEMPOTENCY_KEY: &str =
        central_workflow::domain::REASON_DUPLICATE_IDEMPOTENCY_KEY;
    /// `SPEC_VALIDATION_FAILED` — a prevalidation or emit-batch
    /// rejection surfaced as the shared invalid-spec failure
    /// (upstream `workflow.ReasonSpecValidationFailed`).
    pub const SPEC_VALIDATION_FAILED: &str = "SPEC_VALIDATION_FAILED";
}

/// `SubmitRequest` — one submission. `workspace_id` has no default:
/// the operator pins the exact workspace (the #110 pin names the
/// sentinel). `run_key: None` disables replay lookup (fresh run every
/// call); `idempotency_key: None` is minted per call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitRequest {
    /// The exact workspace the run submits under.
    pub workspace_id: WorkspaceId,
    /// The operator-facing label.
    pub title: String,
    /// The flat worker fan-out (`1..=8`).
    pub workers: i64,
    /// The spec-5 keyed-resubmit coordinate (`Some` = resumable).
    pub run_key: Option<String>,
    /// The task-scope command-receipt key; minted per call when `None`.
    pub idempotency_key: Option<String>,
}

/// `SubmittedNode` — one committed node of the result (post-ready
/// states).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmittedNode {
    /// The node identity.
    pub node_id: WorkflowNodeId,
    /// The leader-chosen slug.
    pub node_key: String,
    /// The post-`recompute_ready` state the readback asserted.
    pub state: NodeStatus,
}

/// `SubmitResult` — the saga outcome. `deduped` reports a `run_key`
/// replay resume (recorded run adopted, no second nodes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitResult {
    /// The committed task.
    pub task_id: TaskId,
    /// The committed run.
    pub run_id: central_foundation::identity::RunId,
    /// The ready nodes, leader first then workers lexically ordered.
    pub nodes: Vec<SubmittedNode>,
    /// Whether the recorded `run_key` run was adopted.
    pub deduped: bool,
}

/// `ValidationError{Field}` — a request-shape refusal that never
/// carries the offending value: `runsubmit: invalid <field>`.
fn validation(field: &'static str) -> Failure {
    Failure::invalid(
        codes::REQUEST_VALIDATION,
        format!("runsubmit: invalid {field}"),
    )
}

/// `validateRequest` — the request bounds shared by the CLI and the
/// web surface. Every refusal is a [`codes::REQUEST_VALIDATION`]
/// invalid failure.
pub fn validate_request(req: &SubmitRequest) -> Result<(), Failure> {
    if req.workspace_id.is_nil() {
        return Err(validation("workspace"));
    }
    // `utf8.RuneCountInString` — chars are the Rust rune count on a
    // valid UTF-8 `String`.
    let title_runes = req.title.chars().count();
    if !(1..=MAX_TITLE_RUNES).contains(&title_runes) {
        return Err(validation("title"));
    }
    if !(MIN_WORKERS..=MAX_WORKERS).contains(&req.workers) {
        return Err(validation("workers"));
    }
    if req.run_key.as_deref().map_or(0, str::len) > MAX_RUN_KEY_BYTES {
        return Err(validation("run_key"));
    }
    Ok(())
}

/// `submitInput` — the fixed task-input marker: provenance for the
/// operator, never executed (the run carries no steps). The JSON is
/// byte-identical to the Go struct marshal (field order fixed by
/// declaration).
#[must_use]
pub fn submit_input(workers: i64, keyed: bool) -> String {
    #[derive(serde::Serialize)]
    struct SubmitInput {
        schema_version: &'static str,
        workers: i64,
        run_key_present: bool,
    }
    serde_json::to_string(&SubmitInput {
        schema_version: "central.phase2-run-submit/v1",
        workers,
        run_key_present: keyed,
    })
    .unwrap_or_default()
}

/// `childNode` — one `claude-code`/`directory` spec child with no
/// prerequisites and no declared extras.
fn child_node(key: &str) -> ChildSpecNode {
    ChildSpecNode {
        node_key: key.to_string(),
        depends_on: Vec::new(),
        harness: HARNESS_NAME.to_string(),
        workspace_kind: WorkspaceKind::Directory.as_str().to_string(),
        input_artifact_refs: Vec::new(),
        budget: None,
        on_terminal_failure: String::new(),
        node_timeout_seconds: None,
        session_timeout_seconds: None,
        max_attempts: std::collections::BTreeMap::new(),
        max_attempts_total: None,
    }
}

/// `leaderBatch` — emit batch 1: the root, no prerequisites.
#[must_use]
pub fn leader_batch() -> ChildSpec {
    ChildSpec {
        version: central_workflow::domain::CHILD_SPEC_VERSION.to_string(),
        children: vec![child_node(LEADER_KEY)],
    }
}

/// `workerBatch` — emit batch 2: flat workers (no `depends_on` so
/// every node flips ready in one `recompute_ready`); the caller
/// parents them to the leader via the batch `parent_id` for lineage.
#[must_use]
pub fn worker_batch(n: i64) -> ChildSpec {
    ChildSpec {
        version: central_workflow::domain::CHILD_SPEC_VERSION.to_string(),
        children: (1..=n)
            .map(|i| child_node(&format!("worker-{i}")))
            .collect(),
    }
}

/// `prevalidate` — runs [`validate::validate_batch`] over both submit
/// batches against empty run state BEFORE the first commit (spec D8):
/// a rejection fails the submit with `SPEC_VALIDATION_FAILED` and
/// commits nothing.
#[must_use]
pub fn prevalidate(workers: i64) -> Option<Rejection> {
    // `launchableHarness` — the serve-parity claude-code-only rule; the
    // artifact checker is `None`: batches carry no input refs, so the
    // rule loop never calls it.
    let launchable = |name: &str| name == HARNESS_NAME;
    let registry: &dyn HarnessRegistry = &launchable;
    if let Some(rej) = validate::validate_batch(
        &BTreeSet::new(),
        &[],
        &leader_batch(),
        Caps::locked(),
        BudgetCeiling::default(),
        Some(registry),
        None,
    ) {
        return Some(rej);
    }
    let mut existing = BTreeSet::new();
    existing.insert(LEADER_KEY.to_string());
    validate::validate_batch(
        &existing,
        &[],
        &worker_batch(workers),
        Caps::locked(),
        BudgetCeiling::default(),
        Some(registry),
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use central_foundation::failure::FailureKind;

    fn sentinel_workspace() -> WorkspaceId {
        WorkspaceId::parse("019fdc8d-e33a-76ed-9ef0-a0d9fe92e54a").unwrap()
    }

    fn good() -> SubmitRequest {
        SubmitRequest {
            workspace_id: sentinel_workspace(),
            title: "demo".to_string(),
            workers: 2,
            run_key: Some("k".to_string()),
            idempotency_key: None,
        }
    }

    fn is_validation(err: &Failure, field: &str) -> bool {
        err.kind() == FailureKind::Invalid
            && err.code() == codes::REQUEST_VALIDATION
            && err.message() == format!("runsubmit: invalid {field}")
    }

    /// `TestValidateRequestBounds` — every bound refuses with the
    /// request-validation marker; keyless is valid.
    #[test]
    fn validate_request_bounds() {
        validate_request(&good()).unwrap();
        let mut req = good();
        req.title.clear();
        assert!(is_validation(&validate_request(&req).unwrap_err(), "title"));
        req = good();
        req.title = "x".repeat(201);
        assert!(is_validation(&validate_request(&req).unwrap_err(), "title"));
        req = good();
        req.workers = 0;
        assert!(is_validation(
            &validate_request(&req).unwrap_err(),
            "workers"
        ));
        req = good();
        req.workers = 9;
        assert!(is_validation(
            &validate_request(&req).unwrap_err(),
            "workers"
        ));
        req = good();
        req.run_key = Some("k".repeat(129));
        assert!(is_validation(
            &validate_request(&req).unwrap_err(),
            "run_key"
        ));
        // Keyless is valid (fresh run every call).
        req = good();
        req.run_key = None;
        validate_request(&req).unwrap();
    }

    /// `TestBatchesPrevalidateClean` — both fan-out extremes pass the
    /// shared child-spec validator.
    #[test]
    fn batches_prevalidate_clean() {
        assert!(prevalidate(3).is_none());
        assert!(prevalidate(8).is_none());
    }

    /// `TestWorkerBatchKeys` — flat worker keys, claude-code/directory
    /// shape, no prerequisites; the leader batch is the single root.
    #[test]
    fn worker_batch_keys() {
        let b = worker_batch(2);
        assert_eq!(b.children.len(), 2);
        assert_eq!(b.children[0].node_key, "worker-1");
        assert_eq!(b.children[1].node_key, "worker-2");
        for child in &b.children {
            assert_eq!(child.harness, "claude-code");
            assert_eq!(child.workspace_kind, "directory");
            assert!(child.depends_on.is_empty());
        }
        let l = leader_batch();
        assert_eq!(l.children.len(), 1);
        assert_eq!(l.children[0].node_key, "leader");
    }

    /// `TestSubmitInputIsFixedShape` — the provenance marker is the
    /// byte-exact Go marshal.
    #[test]
    fn submit_input_is_fixed_shape() {
        assert_eq!(
            submit_input(2, true),
            r#"{"schema_version":"central.phase2-run-submit/v1","workers":2,"run_key_present":true}"#
        );
        assert_eq!(
            submit_input(1, false),
            r#"{"schema_version":"central.phase2-run-submit/v1","workers":1,"run_key_present":false}"#
        );
    }
}
