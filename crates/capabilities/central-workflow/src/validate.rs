//! `central.child-spec/v1` batch validation — pure synchronous port of
//! `central/internal/workflow/validate.go` (Phase-2 Slice 2A, P2A02).
//!
//! [`validate_batch`] evaluates one child-spec emission against the
//! committed run state and returns `None` on acceptance or the atomic
//! [`Rejection`] of the first violated rule. Rules run in the spec order
//! — schema, unique `node_key`, `depends_on` resolution, acyclicity,
//! depth, launchable harness, finalized input refs, budget vs parent
//! remaining, `max_nodes_per_run` — so the rejection names the earliest
//! rule a replayed check would also hit.
//!
//! Depth is evaluated batch-internally: a proposed node whose
//! `depends_on` all resolve to committed keys sits at depth 1 (one level
//! below the emitting parent), and each co-emitted dependency adds one
//! level. The emit-time caller composes the absolute depth by adding the
//! emitting node's recorded depth; the cap check here bounds the depth a
//! single batch may introduce regardless of attachment point.

use std::collections::{BTreeMap, BTreeSet};

use central_foundation::identity::{ArtifactId, WorkflowNodeId};
use central_retry::domain as retry;

use crate::domain::{
    ACTOR_EMIT, BudgetCeiling, CHILD_SPEC_VERSION, Caps, ChildSpec, ChildSpecNode, Edge,
    GraphEventIntent, GraphEventKind, WorkspaceKind,
};

/// The only `reason_code` a `child_spec_rejected` event carries
/// (spec-1): schema, cycle, duplicate key, depth, capability, budget and
/// artifact-ref violations share the code; the rejection detail names
/// the offending keys and the specific rule.
///
/// Alias of [`retry::ReasonCode::SpecValidationFailed`] — the taxonomy
/// owns the code; the alias keeps call sites reading like upstream's
/// `ReasonSpecValidationFailed`.
pub const REASON_SPEC_VALIDATION_FAILED: retry::ReasonCode =
    retry::ReasonCode::SpecValidationFailed;

// Rule codes named inside Rejection::detail, pinned by the concurrency
// spec's failure semantics on `child_spec_rejected`. Other rules carry
// no spec-pinned code: their detail is descriptive text plus the keys.

/// `BUDGET_EXCEEDS_PARENT` — a declared child ceiling above the
/// parent's remaining budget.
pub const DETAIL_BUDGET_EXCEEDS_PARENT: &str = "BUDGET_EXCEEDS_PARENT";
/// `MAX_DEPTH_EXCEEDED` — the deepest proposed node past `max_depth`.
pub const DETAIL_MAX_DEPTH_EXCEEDED: &str = "MAX_DEPTH_EXCEEDED";
/// `MAX_NODES_PER_RUN_REACHED` — a batch that would push the run past
/// `max_nodes_per_run`.
pub const DETAIL_MAX_NODES_PER_RUN_REACHED: &str = "MAX_NODES_PER_RUN_REACHED";

// ---------------------------------------------------------------------------
// Validation seams
// ---------------------------------------------------------------------------

/// The domain-facing seam over the set of harness adapters Central can
/// launch (spec-1 validation rule "harness names an adapter Central can
/// launch"). Implemented by an adapter-side registry; the domain never
/// sees adapter types. `None` at the call site is fail-closed: a rule
/// that cannot ask cannot pass.
pub trait HarnessRegistry: Send + Sync {
    /// Whether `name` is a harness adapter Central can launch.
    fn launchable(&self, name: &str) -> bool;
}

/// Any `Fn(&str) -> bool` is a [`HarnessRegistry`] — the closure form of
/// upstream's `HarnessLaunchable` func seam.
impl<F> HarnessRegistry for F
where
    F: Fn(&str) -> bool + Send + Sync,
{
    fn launchable(&self, name: &str) -> bool {
        self(name)
    }
}

/// The domain-facing seam over artifact finalization state (spec-1
/// validation rule "`input_artifact_refs` reference finalized artifacts
/// the run may read"). Implemented by the artifact store; the domain
/// never sees adapter types. `None` at the call site is fail-closed.
pub trait ArtifactFinalizedChecker: Send + Sync {
    /// Whether the artifact exists, is finalized, and carries exactly
    /// this checksum.
    fn finalized(&self, artifact_id: ArtifactId, checksum: &str) -> bool;
}

/// Any `Fn(ArtifactId, &str) -> bool` is an
/// [`ArtifactFinalizedChecker`] — the closure form of upstream's
/// `ArtifactFinalized` func seam.
impl<F> ArtifactFinalizedChecker for F
where
    F: Fn(ArtifactId, &str) -> bool + Send + Sync,
{
    fn finalized(&self, artifact_id: ArtifactId, checksum: &str) -> bool {
        self(artifact_id, checksum)
    }
}

// ---------------------------------------------------------------------------
// Rejection
// ---------------------------------------------------------------------------

/// The atomic refusal of a child-spec batch. It is a value, not an
/// error: the caller journals it as a `child_spec_rejected` event and
/// the leader may emit a corrected batch. `reason_code` is always
/// [`REASON_SPEC_VALIDATION_FAILED`]; `offending_keys` names the node
/// keys the violated rule points at (sorted, unique); `detail`
/// describes the specific rule, carrying the spec-pinned rule code
/// where the concurrency spec declares one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    /// Always `SPEC_VALIDATION_FAILED`.
    pub reason_code: retry::ReasonCode,
    /// The node keys the violated rule points at — sorted and unique.
    pub offending_keys: Vec<String>,
    /// The specific rule description (starts with the spec-pinned rule
    /// code where one exists).
    pub detail: String,
}

impl Rejection {
    /// The `child_spec_rejected` event intent the committing store
    /// journals (upstream `rejectBatch` payload shape):
    /// `{"offending_keys": …, "detail": …}` under actor `leader`,
    /// `node_id` bound to the emitting parent.
    #[must_use]
    pub fn to_event_intent(&self, parent_node_id: Option<WorkflowNodeId>) -> GraphEventIntent {
        GraphEventIntent {
            node_id: parent_node_id,
            attempt_id: None,
            kind: GraphEventKind::ChildSpecRejected,
            actor: ACTOR_EMIT.to_string(),
            reason_code: Some(self.reason_code.as_str().to_string()),
            payload: serde_json::json!({
                "offending_keys": self.offending_keys,
                "detail": self.detail,
            }),
        }
    }
}

/// Builds a [`Rejection`]: offending keys deduplicated and sorted
/// (upstream `reject` + `sort.Strings`).
fn reject(detail: String, keys: &[&str]) -> Rejection {
    let offending_keys: Vec<String> = keys
        .iter()
        .map(|k| (*k).to_string())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    Rejection {
        reason_code: REASON_SPEC_VALIDATION_FAILED,
        offending_keys,
        detail,
    }
}

// ---------------------------------------------------------------------------
// validate_batch
// ---------------------------------------------------------------------------

/// Evaluates one `central.child-spec/v1` emission against the committed
/// run state (upstream `ValidateBatch`): `None` on acceptance, the
/// atomic [`Rejection`] of the first violated rule otherwise.
///
/// `existing_keys` is the run's committed `node_key` set. `batch` is
/// the post-partition emission: the committing store removes children
/// whose `(run_id, node_key)` already recorded an equal spec
/// fingerprint (they dedupe as replays) before calling — passing the
/// raw emission would falsely reject an exact replay on the unique-key
/// rule.
///
/// `edges` is the committed edge set: `validate_batch` does not need it to decide
/// acyclicity — an append-only graph can never cycle across the batch
/// boundary, because a proposed node is only ever a dependent of
/// committed nodes, never their prerequisite — but the argument is part
/// of the contract so callers pass the evidence the journal records and
/// later cross-batch rules consume it without a signature change.
///
/// `caps` is the effective cap set — the emit-time caller shifts
/// `max_depth` by the emitting parent's absolute depth when the batch is
/// attached below a recorded node (upstream `effective.MaxDepth =
/// caps.MaxDepth - parentDepth`). `parent_remaining` is the emitting
/// parent's remaining budget envelope; unset fields are unbounded.
///
/// `registry`/`finalized` as `None` are fail-closed: a rule that cannot
/// ask cannot pass.
#[must_use]
pub fn validate_batch(
    existing_keys: &BTreeSet<String>,
    edges: &[Edge],
    batch: &ChildSpec,
    caps: Caps,
    parent_remaining: BudgetCeiling,
    registry: Option<&dyn HarnessRegistry>,
    finalized: Option<&dyn ArtifactFinalizedChecker>,
) -> Option<Rejection> {
    let _ = edges; // reserved for cross-batch rules; see contract doc above.

    // --- schema: version, nonempty batch, nonempty unique-able keys,
    // closed workspace_kind vocabulary, no duplicated depends_on
    // entries, positive declared budget bounds.
    if batch.version != CHILD_SPEC_VERSION {
        return Some(reject(
            format!(
                "unsupported child-spec version {:?} (want {:?})",
                batch.version, CHILD_SPEC_VERSION
            ),
            &child_keys(batch),
        ));
    }
    if batch.children.is_empty() {
        return Some(reject(
            format!("{CHILD_SPEC_VERSION} declares no children"),
            &[],
        ));
    }
    for child in &batch.children {
        if child.node_key.is_empty() {
            return Some(reject("child carries an empty node_key".to_string(), &[]));
        }
        if WorkspaceKind::parse(&child.workspace_kind).is_none() {
            return Some(reject(
                format!(
                    "node {:?} declares unknown workspace_kind {:?}",
                    child.node_key, child.workspace_kind
                ),
                &[&child.node_key],
            ));
        }
        if let Some(dup) = duplicated_dep(&child.depends_on) {
            return Some(reject(
                format!("node {:?} lists depends_on {dup:?} twice", child.node_key),
                &[&child.node_key],
            ));
        }
        if let Some(budget) = &child.budget {
            if let Some(v) = budget.wall_clock_seconds
                && v <= 0
            {
                return Some(reject(
                    format!(
                        "node {:?} declares non-positive budget wall_clock_seconds {v}",
                        child.node_key
                    ),
                    &[&child.node_key],
                ));
            }
            if let Some(v) = budget.cost_micro_usd
                && v <= 0
            {
                return Some(reject(
                    format!(
                        "node {:?} declares non-positive budget cost_micro_usd {v}",
                        child.node_key
                    ),
                    &[&child.node_key],
                ));
            }
        }
        if let Some(rejection) = validate_retry_envelope(child) {
            return Some(rejection);
        }
    }

    let in_batch: BTreeSet<&str> = batch
        .children
        .iter()
        .map(|child| child.node_key.as_str())
        .collect();

    // --- unique node_key within the run (existing plus in-batch).
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for child in &batch.children {
        if existing_keys.contains(&child.node_key) || seen.contains(child.node_key.as_str()) {
            return Some(reject(
                format!(
                    "node_key {:?} is already declared in this run or batch",
                    child.node_key
                ),
                &[&child.node_key],
            ));
        }
        seen.insert(child.node_key.as_str());
    }

    // --- depends_on resolves only to existing or co-emitted keys.
    for child in &batch.children {
        let mut missing: Vec<&str> = child
            .depends_on
            .iter()
            .filter(|dep| !existing_keys.contains(dep.as_str()) && !in_batch.contains(dep.as_str()))
            .map(String::as_str)
            .collect();
        if !missing.is_empty() {
            missing.sort_unstable();
            return Some(reject(
                format!(
                    "node {:?} depends_on keys not existing or co-emitted: {}",
                    child.node_key,
                    missing.join(",")
                ),
                &[&child.node_key],
            ));
        }
    }

    // --- acyclicity on the batch-internal depends_on graph. (Edges to
    // committed keys cannot close a cycle: the committed graph predates
    // the batch.)
    if let Some(cycle) = first_cycle(batch) {
        return Some(reject(
            format!("depends_on cycle inside the batch: {}", cycle.join(" -> ")),
            &cycle.iter().map(String::as_str).collect::<Vec<_>>(),
        ));
    }

    // --- depth of the deepest proposed node within the cap.
    let depths = batch_depths(batch);
    let too_deep: Vec<&str> = batch
        .children
        .iter()
        .filter(|child| depths.get(child.node_key.as_str()).copied().unwrap_or(0) > caps.max_depth)
        .map(|child| child.node_key.as_str())
        .collect();
    if !too_deep.is_empty() {
        return Some(reject(
            format!(
                "{DETAIL_MAX_DEPTH_EXCEEDED}: deepest proposed node exceeds max_depth {}",
                caps.max_depth
            ),
            &too_deep,
        ));
    }

    // --- harness names an adapter Central can launch.
    for child in &batch.children {
        let launchable = registry.is_some_and(|reg| reg.launchable(&child.harness));
        if !launchable {
            return Some(reject(
                format!(
                    "node {:?} names harness {:?} that is not launchable",
                    child.node_key, child.harness
                ),
                &[&child.node_key],
            ));
        }
    }

    // --- input_artifact_refs reference finalized artifacts.
    for child in &batch.children {
        for artifact_ref in &child.input_artifact_refs {
            let ok = finalized
                .is_some_and(|fin| fin.finalized(artifact_ref.artifact_id, &artifact_ref.checksum));
            if !ok {
                return Some(reject(
                    format!(
                        "node {:?} reads artifact {} that is not finalized with the declared checksum",
                        child.node_key, artifact_ref.artifact_id
                    ),
                    &[&child.node_key],
                ));
            }
        }
    }

    // --- declared child budget must not exceed the parent's remaining
    // budget; an omitted ceiling inherits and is never a violation.
    for child in &batch.children {
        let Some(budget) = &child.budget else {
            continue;
        };
        if let Some(over) = exceeds_parent(budget, &parent_remaining) {
            return Some(reject(
                format!(
                    "{DETAIL_BUDGET_EXCEEDS_PARENT}: node {:?} declares {over} above the parent's remaining budget",
                    child.node_key
                ),
                &[&child.node_key],
            ));
        }
    }

    // --- max_nodes_per_run.
    if existing_keys.len() + batch.children.len() > caps.max_nodes_per_run as usize {
        return Some(reject(
            format!(
                "{DETAIL_MAX_NODES_PER_RUN_REACHED}: {} committed nodes + {} proposed exceed max_nodes_per_run {}",
                existing_keys.len(),
                batch.children.len(),
                caps.max_nodes_per_run
            ),
            &child_keys(batch),
        ));
    }

    None
}

fn child_keys(batch: &ChildSpec) -> Vec<&str> {
    batch
        .children
        .iter()
        .map(|child| child.node_key.as_str())
        .collect()
}

/// The first duplicated `depends_on` entry (upstream `duplicatedDep`).
fn duplicated_dep(deps: &[String]) -> Option<&str> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for dep in deps {
        if !seen.insert(dep.as_str()) {
            return Some(dep.as_str());
        }
    }
    None
}

/// The node-key members of the first `depends_on` cycle found inside
/// the batch (in traversal order), or `None` when the batch-internal
/// graph is acyclic (upstream `firstCycle`). `depends_on` entries
/// resolving to committed keys never participate.
fn first_cycle(batch: &ChildSpec) -> Option<Vec<String>> {
    const WHITE: u8 = 0;
    const GRAY: u8 = 1;
    const BLACK: u8 = 2;

    let in_batch: BTreeSet<&str> = batch
        .children
        .iter()
        .map(|child| child.node_key.as_str())
        .collect();
    let deps_of = deps_index(batch);

    fn visit<'a>(
        key: &'a str,
        deps_of: &BTreeMap<&'a str, &'a [String]>,
        in_batch: &BTreeSet<&'a str>,
        color: &mut BTreeMap<&'a str, u8>,
        stack: &mut Vec<&'a str>,
        on_stack: &mut BTreeSet<&'a str>,
        cycle: &mut Option<Vec<String>>,
    ) {
        if cycle.is_some() {
            return;
        }
        color.insert(key, GRAY);
        stack.push(key);
        on_stack.insert(key);
        if let Some(deps) = deps_of.get(key) {
            for dep in deps.iter().map(String::as_str) {
                if !in_batch.contains(dep) {
                    continue;
                }
                if on_stack.contains(dep) {
                    let start = stack.iter().position(|k| *k == dep).unwrap_or(0);
                    *cycle = Some(stack[start..].iter().map(|k| (*k).to_string()).collect());
                    return;
                }
                if color.get(dep).copied().unwrap_or(WHITE) == WHITE {
                    visit(dep, deps_of, in_batch, color, stack, on_stack, cycle);
                    if cycle.is_some() {
                        return;
                    }
                }
            }
        }
        stack.pop();
        on_stack.remove(key);
        color.insert(key, BLACK);
    }

    let mut color: BTreeMap<&str, u8> = BTreeMap::new();
    let mut stack: Vec<&str> = Vec::new();
    let mut on_stack: BTreeSet<&str> = BTreeSet::new();
    let mut cycle: Option<Vec<String>> = None;
    for child in &batch.children {
        if cycle.is_some() {
            break;
        }
        if color.get(child.node_key.as_str()).copied().unwrap_or(WHITE) == WHITE {
            visit(
                child.node_key.as_str(),
                &deps_of,
                &in_batch,
                &mut color,
                &mut stack,
                &mut on_stack,
                &mut cycle,
            );
        }
    }
    cycle
}

/// `node_key → depends_on` slice index for the batch.
fn deps_index(batch: &ChildSpec) -> BTreeMap<&str, &[String]> {
    batch
        .children
        .iter()
        .map(|child| (child.node_key.as_str(), child.depends_on.as_slice()))
        .collect()
}

/// Each proposed node's batch-internal depth (the same measure the
/// depth-cap rule evaluates — upstream `BatchDepths`): `1` for a child
/// whose `depends_on` entries all resolve to committed keys, plus one
/// level per co-emitted dependency hop. The emit-time caller composes
/// the absolute depth by adding the emitting parent's depth. Call only
/// on a batch that passed acyclicity — e.g. after [`validate_batch`]
/// returned `None`.
#[must_use]
pub fn batch_depths(batch: &ChildSpec) -> BTreeMap<String, u32> {
    let in_batch: BTreeSet<&str> = batch
        .children
        .iter()
        .map(|child| child.node_key.as_str())
        .collect();
    let deps_of = deps_index(batch);

    fn depth<'a>(
        key: &'a str,
        deps_of: &BTreeMap<&'a str, &'a [String]>,
        in_batch: &BTreeSet<&'a str>,
        depths: &mut BTreeMap<&'a str, u32>,
    ) -> u32 {
        if let Some(&d) = depths.get(key) {
            return d;
        }
        let mut deepest = 0;
        if let Some(deps) = deps_of.get(key) {
            for dep in deps.iter().map(String::as_str) {
                if !in_batch.contains(dep) {
                    continue;
                }
                let d = depth(dep, deps_of, in_batch, depths);
                if d > deepest {
                    deepest = d;
                }
            }
        }
        depths.insert(key, deepest + 1);
        deepest + 1
    }

    let mut depths: BTreeMap<&str, u32> = BTreeMap::new();
    for child in &batch.children {
        depth(child.node_key.as_str(), &deps_of, &in_batch, &mut depths);
    }
    depths
        .into_iter()
        .map(|(key, d)| (key.to_string(), d))
        .collect()
}

/// Checks one child's Slice-2D retry/timeout fields (spec-4, upstream
/// `validateRetryEnvelope`): timeouts are positive when declared, and
/// declared attempt limits must be positive and no higher than the
/// locked policy defaults — a leader may tighten its nodes' retry
/// budget but never inflate it past the run ceiling (slice-d security
/// rule). `max_attempts` keys must name retryable classes; anything
/// else fails closed. `on_terminal_failure` admits every value —
/// unmanaged kinds are journaled, not rejected.
fn validate_retry_envelope(child: &ChildSpecNode) -> Option<Rejection> {
    if let Some(v) = child.node_timeout_seconds
        && v < 1
    {
        return Some(reject(
            format!(
                "node {:?} declares non-positive node_timeout_seconds {v}",
                child.node_key
            ),
            &[&child.node_key],
        ));
    }
    if let Some(v) = child.session_timeout_seconds
        && v < 1
    {
        return Some(reject(
            format!(
                "node {:?} declares non-positive session_timeout_seconds {v}",
                child.node_key
            ),
            &[&child.node_key],
        ));
    }
    let policy = retry::RetryPolicy::default();
    if let Some(v) = child.max_attempts_total {
        if v < 1 {
            return Some(reject(
                format!(
                    "node {:?} declares non-positive max_attempts_total {v}",
                    child.node_key
                ),
                &[&child.node_key],
            ));
        }
        if v > i64::from(policy.max_attempts_total) {
            return Some(reject(
                format!(
                    "node {:?} declares max_attempts_total {v} above the run ceiling {}",
                    child.node_key, policy.max_attempts_total
                ),
                &[&child.node_key],
            ));
        }
    }
    // BTreeMap iteration is the upstream `sort.Strings(names)` —
    // deterministic first rejection.
    for (name, limit) in &child.max_attempts {
        let Some(class) = retry::FailureClass::parse(name).filter(|class| class.retryable()) else {
            return Some(reject(
                format!(
                    "node {:?} declares max_attempts for non-retryable class {name:?}",
                    child.node_key
                ),
                &[&child.node_key],
            ));
        };
        if *limit < 1 {
            return Some(reject(
                format!(
                    "node {:?} declares non-positive max_attempts[{name:?}] {limit}",
                    child.node_key
                ),
                &[&child.node_key],
            ));
        }
        let ceiling = i64::from(policy.per_class_limits.get(&class).copied().unwrap_or(0));
        if *limit > ceiling {
            return Some(reject(
                format!(
                    "node {:?} declares max_attempts[{name:?}] {limit} above the run ceiling {ceiling}",
                    child.node_key
                ),
                &[&child.node_key],
            ));
        }
    }
    None
}

/// The first child ceiling that exceeds the parent's remaining budget
/// (upstream `exceedsParent`), or `None` when every declared bound
/// fits. A `None` bound on either side is unbounded for that dimension.
fn exceeds_parent(child: &BudgetCeiling, parent_remaining: &BudgetCeiling) -> Option<String> {
    if let (Some(child_wall), Some(parent_wall)) = (
        child.wall_clock_seconds,
        parent_remaining.wall_clock_seconds,
    ) && child_wall > parent_wall
    {
        return Some(format!("wall_clock_seconds {child_wall} > {parent_wall}"));
    }
    if let (Some(child_cost), Some(parent_cost)) =
        (child.cost_micro_usd, parent_remaining.cost_micro_usd)
        && child_cost > parent_cost
    {
        return Some(format!("cost_micro_usd {child_cost} > {parent_cost}"));
    }
    None
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    // -- upstream validate_test.go fixtures ---------------------------

    // UUIDv7 — foundation identity newtypes enforce the v7 version
    // nibble upstream's `uuid.MustParse` did not.
    const ARTIFACT_A: &str = "018f3b2a-1c4d-7e9f-8a1b-2c3d4e5f00a1";
    const ARTIFACT_BAD: &str = "018f3b2a-1c4d-7e9f-8a1b-2c3d4e5f00a2";

    fn artifact_a() -> ArtifactId {
        ArtifactId::parse(ARTIFACT_A).unwrap()
    }

    fn artifact_bad() -> ArtifactId {
        ArtifactId::parse(ARTIFACT_BAD).unwrap()
    }

    /// upstream `refKey`: the fake checker matches (id, checksum) pairs.
    fn ref_key(id: ArtifactId, checksum: &str) -> (ArtifactId, String) {
        (id, checksum.to_string())
    }

    /// upstream `fakeFinalized` — a set of finalized (id, checksum)
    /// pairs behind the `ArtifactFinalizedChecker` seam.
    struct FakeFinalized(BTreeSet<(ArtifactId, String)>);

    impl ArtifactFinalizedChecker for FakeFinalized {
        fn finalized(&self, artifact_id: ArtifactId, checksum: &str) -> bool {
            self.0.contains(&(artifact_id, checksum.to_string()))
        }
    }

    fn valid_batch() -> ChildSpec {
        ChildSpec {
            version: CHILD_SPEC_VERSION.to_string(),
            children: vec![ChildSpecNode {
                node_key: "child-1".to_string(),
                depends_on: vec!["root".to_string()],
                harness: "claude-code".to_string(),
                workspace_kind: "worktree".to_string(),
                input_artifact_refs: vec![],
                budget: None,
                on_terminal_failure: String::new(),
                node_timeout_seconds: None,
                session_timeout_seconds: None,
                max_attempts: BTreeMap::new(),
                max_attempts_total: None,
            }],
        }
    }

    fn child(node_key: &str) -> ChildSpecNode {
        ChildSpecNode {
            node_key: node_key.to_string(),
            depends_on: vec![],
            harness: "claude-code".to_string(),
            workspace_kind: "worktree".to_string(),
            input_artifact_refs: vec![],
            budget: None,
            on_terminal_failure: String::new(),
            node_timeout_seconds: None,
            session_timeout_seconds: None,
            max_attempts: BTreeMap::new(),
            max_attempts_total: None,
        }
    }

    fn default_parent() -> BudgetCeiling {
        BudgetCeiling {
            wall_clock_seconds: Some(3600),
            cost_micro_usd: Some(500_000),
        }
    }

    fn existing_root() -> BTreeSet<String> {
        BTreeSet::from(["root".to_string()])
    }

    fn claude_launchable(name: &str) -> bool {
        name == "claude-code"
    }

    fn sha_ok_finalized() -> FakeFinalized {
        FakeFinalized(BTreeSet::from([ref_key(artifact_a(), "sha256-ok")]))
    }

    /// upstream `mustReject`: asserts the shared reason code, the named
    /// keys, and the detail substrings.
    fn must_reject(
        rejection: Option<Rejection>,
        want_keys: &[&str],
        detail_substrings: &[&str],
    ) -> Rejection {
        let rejection = rejection.expect("batch accepted; want rejection");
        assert_eq!(
            rejection.reason_code, REASON_SPEC_VALIDATION_FAILED,
            "reason_code"
        );
        if !want_keys.is_empty() {
            assert_eq!(rejection.offending_keys, want_keys, "offending_keys");
        }
        for sub in detail_substrings {
            assert!(
                rejection.detail.contains(sub),
                "detail {:?} missing {sub:?}",
                rejection.detail
            );
        }
        rejection
    }

    // -- upstream: TestValidateBatchAccepts ----------------------------

    /// A schema-valid batch with resolvable deps, launchable harness,
    /// finalized refs and fitting budget passes.
    #[test]
    fn validate_batch_accepts() {
        let mut batch = valid_batch();
        batch.children[0].input_artifact_refs = vec![crate::domain::ArtifactRef {
            artifact_id: artifact_a(),
            checksum: "sha256-ok".to_string(),
        }];
        batch.children[0].budget = Some(BudgetCeiling {
            wall_clock_seconds: Some(1800),
            cost_micro_usd: Some(250_000),
        });
        let rejection = validate_batch(
            &existing_root(),
            &[],
            &batch,
            Caps::locked(),
            default_parent(),
            Some(&claude_launchable),
            Some(&sha_ok_finalized()),
        );
        assert!(rejection.is_none(), "valid batch rejected: {rejection:?}");
    }

    // -- upstream: TestValidateBatchAcceptsInheritanceAndDepthThree ---

    /// A `None` budget inherits the parent ceiling and a three-level
    /// chain sits at the cap.
    #[test]
    fn validate_batch_accepts_inheritance_and_depth_three() {
        let batch = ChildSpec {
            version: CHILD_SPEC_VERSION.to_string(),
            children: vec![
                ChildSpecNode {
                    workspace_kind: "directory".to_string(),
                    depends_on: vec!["root".to_string()],
                    ..child("l1")
                },
                ChildSpecNode {
                    workspace_kind: "directory".to_string(),
                    depends_on: vec!["l1".to_string()],
                    ..child("l2")
                },
                ChildSpecNode {
                    workspace_kind: "directory".to_string(),
                    depends_on: vec!["l2".to_string()],
                    ..child("l3")
                },
            ],
        };
        let rejection = validate_batch(
            &existing_root(),
            &[],
            &batch,
            Caps::locked(),
            default_parent(),
            Some(&claude_launchable),
            Some(&FakeFinalized(BTreeSet::new())),
        );
        assert!(rejection.is_none(), "depth-3 batch rejected: {rejection:?}");
        assert_eq!(batch_depths(&batch)["l3"], 3);
    }

    // -- upstream: TestValidateBatchRejections -------------------------

    /// Each rule in the spec order; every violation yields
    /// `SPEC_VALIDATION_FAILED` naming the offending keys.
    #[test]
    fn validate_batch_rejections() {
        let existing63 = || -> BTreeSet<String> { (0..63).map(|i| format!("k{i:02}")).collect() };

        struct Case {
            name: &'static str,
            batch: ChildSpec,
            existing: Option<BTreeSet<String>>,
            registry: Option<&'static dyn HarnessRegistry>,
            finalized: Option<&'static dyn ArtifactFinalizedChecker>,
            want_keys: &'static [&'static str],
            detail_substrings: &'static [&'static str],
        }

        let versioned = |children: Vec<ChildSpecNode>| ChildSpec {
            version: CHILD_SPEC_VERSION.to_string(),
            children,
        };

        let cases: &[Case] = &[
            Case {
                name: "wrong version",
                batch: ChildSpec {
                    version: "central.child-spec/v0".to_string(),
                    children: vec![child("child-1")],
                },
                existing: None,
                registry: Some(&claude_launchable),
                finalized: None,
                want_keys: &["child-1"],
                detail_substrings: &["version"],
            },
            Case {
                name: "empty batch",
                batch: ChildSpec {
                    version: CHILD_SPEC_VERSION.to_string(),
                    children: vec![],
                },
                existing: None,
                registry: Some(&claude_launchable),
                finalized: None,
                want_keys: &[],
                detail_substrings: &["no children"],
            },
            Case {
                name: "empty node key",
                batch: versioned(vec![child("")]),
                existing: None,
                registry: Some(&claude_launchable),
                finalized: None,
                want_keys: &[],
                detail_substrings: &["empty node_key"],
            },
            Case {
                name: "unknown workspace kind",
                batch: versioned(vec![ChildSpecNode {
                    workspace_kind: "volume".to_string(),
                    ..child("child-1")
                }]),
                existing: None,
                registry: Some(&claude_launchable),
                finalized: None,
                want_keys: &["child-1"],
                detail_substrings: &["workspace_kind"],
            },
            Case {
                name: "duplicated depends_on entry",
                batch: versioned(vec![ChildSpecNode {
                    depends_on: vec!["root".to_string(), "root".to_string()],
                    ..child("child-1")
                }]),
                existing: None,
                registry: Some(&claude_launchable),
                finalized: None,
                want_keys: &["child-1"],
                detail_substrings: &["twice"],
            },
            Case {
                name: "non-positive declared budget",
                batch: versioned(vec![ChildSpecNode {
                    budget: Some(BudgetCeiling {
                        wall_clock_seconds: Some(0),
                        cost_micro_usd: None,
                    }),
                    ..child("child-1")
                }]),
                existing: None,
                registry: Some(&claude_launchable),
                finalized: None,
                want_keys: &["child-1"],
                detail_substrings: &["non-positive"],
            },
            Case {
                name: "duplicate key inside batch",
                batch: versioned(vec![child("dup"), child("dup")]),
                existing: None,
                registry: Some(&claude_launchable),
                finalized: None,
                want_keys: &["dup"],
                detail_substrings: &["already declared"],
            },
            Case {
                name: "key already exists in run",
                batch: versioned(vec![child("root")]),
                existing: None,
                registry: Some(&claude_launchable),
                finalized: None,
                want_keys: &["root"],
                detail_substrings: &["already declared"],
            },
            Case {
                name: "depends_on resolves nowhere",
                batch: versioned(vec![ChildSpecNode {
                    depends_on: vec!["ghost".to_string()],
                    ..child("child-1")
                }]),
                existing: None,
                registry: Some(&claude_launchable),
                finalized: None,
                want_keys: &["child-1"],
                detail_substrings: &["ghost"],
            },
            Case {
                name: "self dependency is a cycle",
                batch: versioned(vec![ChildSpecNode {
                    depends_on: vec!["child-1".to_string()],
                    ..child("child-1")
                }]),
                existing: None,
                registry: Some(&claude_launchable),
                finalized: None,
                want_keys: &["child-1"],
                detail_substrings: &["cycle"],
            },
            Case {
                name: "cycle across co-emitted nodes",
                batch: versioned(vec![
                    ChildSpecNode {
                        depends_on: vec!["c".to_string()],
                        ..child("a")
                    },
                    ChildSpecNode {
                        depends_on: vec!["a".to_string()],
                        ..child("b")
                    },
                    ChildSpecNode {
                        depends_on: vec!["b".to_string()],
                        ..child("c")
                    },
                ]),
                existing: None,
                registry: Some(&claude_launchable),
                finalized: None,
                want_keys: &["a", "b", "c"],
                detail_substrings: &["cycle"],
            },
            Case {
                name: "depth four exceeds cap three",
                batch: versioned(vec![
                    ChildSpecNode {
                        depends_on: vec!["root".to_string()],
                        ..child("l1")
                    },
                    ChildSpecNode {
                        depends_on: vec!["l1".to_string()],
                        ..child("l2")
                    },
                    ChildSpecNode {
                        depends_on: vec!["l2".to_string()],
                        ..child("l3")
                    },
                    ChildSpecNode {
                        depends_on: vec!["l3".to_string()],
                        ..child("l4")
                    },
                ]),
                existing: None,
                registry: Some(&claude_launchable),
                finalized: None,
                want_keys: &["l4"],
                detail_substrings: &[DETAIL_MAX_DEPTH_EXCEEDED],
            },
            Case {
                name: "harness not launchable",
                batch: versioned(vec![ChildSpecNode {
                    harness: "unknown-harness".to_string(),
                    ..child("child-1")
                }]),
                existing: None,
                registry: Some(&claude_launchable),
                finalized: None,
                want_keys: &["child-1"],
                detail_substrings: &["unknown-harness"],
            },
            Case {
                name: "input ref not finalized",
                batch: versioned(vec![ChildSpecNode {
                    input_artifact_refs: vec![crate::domain::ArtifactRef {
                        artifact_id: artifact_bad(),
                        checksum: "sha256-ok".to_string(),
                    }],
                    ..child("child-1")
                }]),
                existing: None,
                registry: Some(&claude_launchable),
                finalized: None,
                want_keys: &["child-1"],
                detail_substrings: &["not finalized"],
            },
            Case {
                name: "input ref checksum mismatch is not finalized",
                batch: versioned(vec![ChildSpecNode {
                    input_artifact_refs: vec![crate::domain::ArtifactRef {
                        artifact_id: artifact_a(),
                        checksum: "sha256-wrong".to_string(),
                    }],
                    ..child("child-1")
                }]),
                existing: None,
                registry: Some(&claude_launchable),
                finalized: None,
                want_keys: &["child-1"],
                detail_substrings: &["checksum"],
            },
            Case {
                name: "child wall clock exceeds parent remaining",
                batch: versioned(vec![ChildSpecNode {
                    budget: Some(BudgetCeiling {
                        wall_clock_seconds: Some(7200),
                        cost_micro_usd: None,
                    }),
                    ..child("child-1")
                }]),
                existing: None,
                registry: Some(&claude_launchable),
                finalized: None,
                want_keys: &["child-1"],
                detail_substrings: &[DETAIL_BUDGET_EXCEEDS_PARENT, "wall_clock_seconds"],
            },
            Case {
                name: "child cost exceeds parent remaining",
                batch: versioned(vec![ChildSpecNode {
                    budget: Some(BudgetCeiling {
                        wall_clock_seconds: None,
                        cost_micro_usd: Some(900_000),
                    }),
                    ..child("child-1")
                }]),
                existing: None,
                registry: Some(&claude_launchable),
                finalized: None,
                want_keys: &["child-1"],
                detail_substrings: &[DETAIL_BUDGET_EXCEEDS_PARENT, "cost_micro_usd"],
            },
            Case {
                name: "batch pushes run past max nodes",
                batch: versioned(vec![child("n1"), child("n2")]),
                existing: Some(existing63()),
                registry: Some(&claude_launchable),
                finalized: None,
                want_keys: &["n1", "n2"],
                detail_substrings: &[DETAIL_MAX_NODES_PER_RUN_REACHED],
            },
            Case {
                name: "nil registry fails closed",
                batch: versioned(vec![child("child-1")]),
                existing: None,
                registry: None,
                finalized: None,
                want_keys: &["child-1"],
                detail_substrings: &["not launchable"],
            },
            Case {
                name: "nil checker fails closed on refs",
                batch: versioned(vec![ChildSpecNode {
                    input_artifact_refs: vec![crate::domain::ArtifactRef {
                        artifact_id: artifact_a(),
                        checksum: "sha256-ok".to_string(),
                    }],
                    ..child("child-1")
                }]),
                existing: None,
                registry: Some(&claude_launchable),
                finalized: None,
                want_keys: &["child-1"],
                detail_substrings: &["not finalized"],
            },
        ];

        let accepting = FakeFinalized(BTreeSet::from([ref_key(artifact_a(), "sha256-ok")]));
        for case in cases {
            let existing = case.existing.clone().unwrap_or_else(existing_root);
            // Upstream: every case but the explicitly-nil seams gets the
            // accepting fakes; "nil … fails closed" cases pass None.
            let registry = case.registry;
            let finalized = if case.name == "nil checker fails closed on refs" {
                None
            } else {
                case.finalized.or(Some(&accepting))
            };
            let rejection = validate_batch(
                &existing,
                &[],
                &case.batch,
                Caps::locked(),
                default_parent(),
                registry,
                finalized,
            );
            must_reject(rejection, case.want_keys, case.detail_substrings);
        }
    }

    // -- upstream: TestValidateBatchRuleOrder --------------------------

    /// The earliest violated rule reports: a batch failing schema (bad
    /// version) and uniqueness still rejects on version.
    #[test]
    fn validate_batch_rule_order() {
        let batch = ChildSpec {
            version: "bogus".to_string(),
            children: vec![child("root"), child("root")],
        };
        let rejection = validate_batch(
            &existing_root(),
            &[],
            &batch,
            Caps::locked(),
            default_parent(),
            Some(&claude_launchable),
            Some(&FakeFinalized(BTreeSet::new())),
        );
        must_reject(rejection, &[], &["version"]);
    }

    // -- upstream: TestValidateBatchMaxNodesAtCap ----------------------

    /// The boundary: exactly at `max_nodes_per_run` passes.
    #[test]
    fn validate_batch_max_nodes_at_cap() {
        let existing: BTreeSet<String> = (0..63).map(|i| format!("k{i:02}")).collect();
        let batch = ChildSpec {
            version: CHILD_SPEC_VERSION.to_string(),
            children: vec![child("last")],
        };
        let rejection = validate_batch(
            &existing,
            &[],
            &batch,
            Caps::locked(),
            default_parent(),
            Some(&claude_launchable),
            Some(&FakeFinalized(BTreeSet::new())),
        );
        assert!(
            rejection.is_none(),
            "batch at the cap rejected: {rejection:?}"
        );
    }

    // -- upstream: TestValidateBatchUnboundedParent --------------------

    /// A `None` parent bound never trips the budget rule.
    #[test]
    fn validate_batch_unbounded_parent() {
        let mut batch = valid_batch();
        batch.children[0].budget = Some(BudgetCeiling {
            wall_clock_seconds: Some(999_999),
            cost_micro_usd: None,
        });
        let rejection = validate_batch(
            &existing_root(),
            &[],
            &batch,
            Caps::locked(),
            BudgetCeiling::default(),
            Some(&claude_launchable),
            Some(&FakeFinalized(BTreeSet::new())),
        );
        assert!(
            rejection.is_none(),
            "unbounded parent rejected a child ceiling: {rejection:?}"
        );
    }

    // -- upstream: TestValidateBatchRetryEnvelopeAccepts ---------------

    /// A fully-declared Slice-2D retry/timeout envelope inside the
    /// policy ceilings passes validation.
    #[test]
    fn validate_batch_retry_envelope_accepts() {
        let mut batch = valid_batch();
        batch.children[0].on_terminal_failure = "cleanup_workspace".to_string();
        batch.children[0].node_timeout_seconds = Some(1800);
        batch.children[0].session_timeout_seconds = Some(600);
        batch.children[0].max_attempts = BTreeMap::from([
            ("transient".to_string(), 2),
            ("dispatch_infra".to_string(), 5),
            ("session_timeout".to_string(), 1),
        ]);
        batch.children[0].max_attempts_total = Some(5);
        let rejection = validate_batch(
            &existing_root(),
            &[],
            &batch,
            Caps::locked(),
            default_parent(),
            Some(&claude_launchable),
            Some(&FakeFinalized(BTreeSet::new())),
        );
        assert!(
            rejection.is_none(),
            "retry-envelope batch rejected: {rejection:?}"
        );
    }

    // -- upstream: TestValidateBatchRetryEnvelopeRejections ------------

    /// Each spec-4 range rule: non-positive timeouts, non-retryable
    /// `max_attempts` classes, and limits above the locked run ceiling
    /// all reject fail-closed.
    #[test]
    fn validate_batch_retry_envelope_rejections() {
        struct Case {
            name: &'static str,
            mutate: fn(&mut ChildSpecNode),
            detail_substrings: &'static [&'static str],
        }
        let cases: &[Case] = &[
            Case {
                name: "zero node_timeout_seconds",
                mutate: |c| c.node_timeout_seconds = Some(0),
                detail_substrings: &["node_timeout_seconds"],
            },
            Case {
                name: "negative node_timeout_seconds",
                mutate: |c| c.node_timeout_seconds = Some(-30),
                detail_substrings: &["node_timeout_seconds"],
            },
            Case {
                name: "zero session_timeout_seconds",
                mutate: |c| c.session_timeout_seconds = Some(0),
                detail_substrings: &["session_timeout_seconds"],
            },
            Case {
                name: "max_attempts unknown class",
                mutate: |c| {
                    c.max_attempts = BTreeMap::from([("bogus".to_string(), 2)]);
                },
                detail_substrings: &["non-retryable class", "bogus"],
            },
            Case {
                name: "max_attempts terminal class",
                mutate: |c| {
                    c.max_attempts = BTreeMap::from([("terminal".to_string(), 2)]);
                },
                detail_substrings: &["non-retryable class", "terminal"],
            },
            Case {
                name: "max_attempts node_timeout bound is not retryable",
                mutate: |c| {
                    c.max_attempts = BTreeMap::from([("node_timeout".to_string(), 2)]);
                },
                detail_substrings: &["non-retryable class", "node_timeout"],
            },
            Case {
                name: "max_attempts zero",
                mutate: |c| {
                    c.max_attempts = BTreeMap::from([("transient".to_string(), 0)]);
                },
                detail_substrings: &["non-positive max_attempts"],
            },
            Case {
                name: "max_attempts above run ceiling",
                mutate: |c| {
                    c.max_attempts = BTreeMap::from([("transient".to_string(), 4)]);
                },
                detail_substrings: &["above the run ceiling", "transient"],
            },
            Case {
                name: "max_attempts_total zero",
                mutate: |c| c.max_attempts_total = Some(0),
                detail_substrings: &["non-positive max_attempts_total"],
            },
            Case {
                name: "max_attempts_total above run ceiling",
                mutate: |c| c.max_attempts_total = Some(6),
                detail_substrings: &["above the run ceiling", "max_attempts_total"],
            },
        ];
        for case in cases {
            let mut batch = ChildSpec {
                version: CHILD_SPEC_VERSION.to_string(),
                children: vec![ChildSpecNode {
                    depends_on: vec!["root".to_string()],
                    ..child("child-1")
                }],
            };
            (case.mutate)(&mut batch.children[0]);
            let rejection = validate_batch(
                &existing_root(),
                &[],
                &batch,
                Caps::locked(),
                default_parent(),
                Some(&claude_launchable),
                Some(&FakeFinalized(BTreeSet::new())),
            );
            assert!(
                rejection.is_some(),
                "case {:?} produced no rejection",
                case.name
            );
            must_reject(rejection, &["child-1"], case.detail_substrings);
        }
    }

    // -- Rust-side additions -------------------------------------------

    /// The rejection journals `child_spec_rejected` under actor
    /// `leader` with the upstream payload shape and reason code.
    #[test]
    fn rejection_event_intent_matches_upstream_payload() {
        let rejection = reject("rule broke".to_string(), &["b", "a", "a"]);
        assert_eq!(rejection.offending_keys, ["a", "b"]);
        let intent = rejection.to_event_intent(None);
        assert_eq!(intent.kind, GraphEventKind::ChildSpecRejected);
        assert_eq!(intent.actor, ACTOR_EMIT);
        assert_eq!(
            intent.reason_code.as_deref(),
            Some("SPEC_VALIDATION_FAILED")
        );
        assert_eq!(
            intent.payload,
            serde_json::json!({"offending_keys": ["a", "b"], "detail": "rule broke"})
        );
    }

    /// `batch_depths` composes one level per co-emitted hop; committed
    /// deps close the chain without adding depth.
    #[test]
    fn batch_depths_counts_only_co_emitted_hops() {
        let batch = ChildSpec {
            version: CHILD_SPEC_VERSION.to_string(),
            children: vec![
                ChildSpecNode {
                    depends_on: vec!["root".to_string()],
                    ..child("l1")
                },
                ChildSpecNode {
                    depends_on: vec!["l1".to_string(), "root".to_string()],
                    ..child("l2")
                },
            ],
        };
        let depths = batch_depths(&batch);
        assert_eq!(depths["l1"], 1);
        assert_eq!(depths["l2"], 2);
    }
}
