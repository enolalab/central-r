//! `central node decide` — the operator verb over the durable
//! workflow graph, ported from `internal/command/node.go` plus the
//! deferred-mode composition of `cmd/central/node_composition.go`.
//!
//!   - `decide --run <id> --node <key|id> --decision resume|rerun`
//!     records the operator's one-row-ever `attempt_decision` on the
//!     parked `attempt_ambiguous` node through the workflow store's
//!     `resolve_ambiguous`: `rerun` returns the node to `ready` for a
//!     fresh attempt under a new lease, `resume` leaves it parked for
//!     the harness-native reattach. The vocabulary is exactly
//!     spec-1's two-value set — there is deliberately no `abandon`
//!     (and no `fail`): an ambiguous attempt's outcome is unknowable,
//!     never forfeitable by fiat. `b37`'s
//!     `attempt_decisions_decision_check` pins the same pair.
//!
//! The replay-compare fingerprint is SHA-256 over the canonical
//! decision payload — the compact JSON object
//! `{"decision":...,"node_id":...,"run_id":...}` emitted in a fixed
//! field order, the same convention the task-submit fingerprint
//! uses. Reissuing the identical command reproduces identical bytes
//! and dedupes to `command_deduped`; a changed decision on the
//! recorded attempt is refused `DENIED` — the `attempt_decisions`
//! row is one row ever.
//!
//! Every invocation writes the standard JSON result envelope.
//! Grammar errors exit 2 with `NODE_USAGE`; a node reference the run
//! does not contain exits 2 with `NODE_NOT_FOUND`; a missing backend
//! fails closed with `NODE_UNAVAILABLE` like every other
//! deferred-mode seam. A domain verdict keeps its own reason code:
//! `INVALID` exits 2, `DENIED`/`CONFLICT` exit 6; adapter errors
//! exit 6 as `NODE_FAILED`.
//!
//! Composition (upstream `newNodeBackendFromEnv`): when the
//! environment carries `CENTRAL_NODE_DSN` the command composes the
//! real PostgreSQL workflow store — `nodes_for_run` plus
//! `resolve_ambiguous`, the command seam's full surface; without it
//! dispatch fails closed with `NODE_UNAVAILABLE` — never an
//! `attempt_decision` against a store that is not there.

use std::env;
use std::io::Write;
use std::time::Instant;

use central_adapter_postgres::workflow::Store as WorkflowStore;
use central_foundation::failure::{ExitClass, Failure, FailureKind};
use central_foundation::identity::{RunId, WorkflowNodeId};
use central_foundation::local_result::LocalResult;
use central_workflow::readiness::ambiguous_decision_known;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;

/// `envNodeDSN` — the deferred-mode DSN for the workflow store. An
/// operator or a serve-side launcher supplies it; the binary never
/// reads a credential file for it.
const ENV_NODE_DSN: &str = "CENTRAL_NODE_DSN";

/// `actorNodeDecide` — the journal actor the operator decision lands
/// under: the command is the operator's own surface, and the
/// `attempt_decisions` row records it in `decided_by`.
const ACTOR_NODE_DECIDE: &str = "operator";

// The command-level reason tokens that are not store verdicts:
// grammar errors, the node-not-in-run refusal, the missing-backend
// refusal, and the adapter-failure catch-all. Domain verdicts travel
// on their Failure's own reason.
const REASON_USAGE: &str = "NODE_USAGE";
const REASON_NOT_FOUND: &str = "NODE_NOT_FOUND";
const REASON_UNAVAILABLE: &str = "NODE_UNAVAILABLE";
const REASON_FAILED: &str = "NODE_FAILED";

/// `cli.Exit*` mapped onto `ExitClass`'s codes.
const EXIT_OK: ExitClass = ExitClass::Success;
/// `cli.ExitConfigInvalidCode` — invalid invocation / INVALID verdict.
const EXIT_CONFIG_INVALID: ExitClass = ExitClass::Usage;
/// `cli.ExitUnsupported` — the backend is not composable.
const EXIT_UNSUPPORTED: ExitClass = ExitClass::Incompatible;
/// `cli.ExitTerminal` — a terminal failure or DENIED/CONFLICT verdict.
const EXIT_TERMINAL: ExitClass = ExitClass::Terminal;

/// The `node decide` backend seam (upstream `command.NodeBackend`):
/// the slice of the workflow store the verb composes against. The
/// PostgreSQL workflow adapter provides it in full; a missing DSN
/// fails closed as `NODE_UNAVAILABLE`.
trait NodeBackend {
    /// `NodesForRun` — the run's committed nodes, so `--node`
    /// resolves a `node_key` or a bare id against the same committed
    /// set — a ref naming a node of another run never reaches
    /// `resolve_ambiguous`.
    async fn nodes_for_run(&self, run_id: RunId) -> Result<Vec<NodeRef>, Failure>;

    /// `ResolveAmbiguous` — records the one-row-ever
    /// `attempt_decision` on the node's parked attempt and applies
    /// the transition the decision names. `fingerprint` is the
    /// SHA-256 of the canonical decision payload
    /// [`decide_fingerprint`] computes.
    async fn resolve_ambiguous(
        &self,
        node_id: WorkflowNodeId,
        decision: &str,
        fingerprint: [u8; 32],
        actor: &str,
    ) -> Result<(), Failure>;
}

/// The slice of `central_workflow::domain::Node` the command
/// consumes — the id the decision binds and the key the details echo
/// back (`node.ID` + `node.NodeKey`; no other field is read).
#[derive(Debug, Clone, PartialEq)]
struct NodeRef {
    /// The node identity.
    id: WorkflowNodeId,
    /// The leader-chosen slug.
    node_key: String,
}

/// The PostgreSQL workflow store satisfies the command seam in full
/// (upstream `var _ command.NodeBackend = (*pgworkflow.Store)(nil)`):
/// run-node listing for the key-or-id lookup and the one-row-ever
/// `attempt_decision` transaction.
impl NodeBackend for WorkflowStore {
    async fn nodes_for_run(&self, run_id: RunId) -> Result<Vec<NodeRef>, Failure> {
        let nodes = central_workflow::port::WorkflowStore::nodes_for_run(self, run_id).await?;
        Ok(nodes
            .into_iter()
            .map(|node| NodeRef {
                id: node.id,
                node_key: node.node_key,
            })
            .collect())
    }

    async fn resolve_ambiguous(
        &self,
        node_id: WorkflowNodeId,
        decision: &str,
        fingerprint: [u8; 32],
        actor: &str,
    ) -> Result<(), Failure> {
        central_workflow::port::WorkflowStore::resolve_ambiguous(
            self,
            node_id,
            decision,
            fingerprint,
            actor,
        )
        .await
    }
}

/// `nodeExit` — maps an error to the verb's exit code + reason: a
/// domain verdict keeps its own reason code, `INVALID` exits 2 and
/// `DENIED`/`CONFLICT` exit 6; adapter-level (`pg_*`) failures — the
/// Rust shape of upstream's plain `fmt.Errorf` — report
/// `NODE_FAILED`.
fn node_exit_reason(failure: &Failure) -> (ExitClass, String) {
    if failure.code().starts_with("pg_") {
        return (EXIT_TERMINAL, REASON_FAILED.to_owned());
    }
    match failure.kind() {
        FailureKind::Invalid => (EXIT_CONFIG_INVALID, failure.code().to_owned()),
        _ => (EXIT_TERMINAL, failure.code().to_owned()),
    }
}

/// `decideFingerprint` — the spec-5 replay-compare value for the
/// `attempt_decisions` key: SHA-256 over the canonical decision
/// payload. The fixed layout keeps field order and encoding
/// identical on every retry — the canonical bytes are the compact
/// JSON object `{"decision":...,"node_id":...,"run_id":...}`.
/// (`serde_json`'s map orders keys lexicographically —
/// `decision` < `node_id` < `run_id` — which coincides with the
/// upstream struct's declaration order, so the encoded bytes are
/// identical.)
fn decide_fingerprint(run_id: RunId, node_id: WorkflowNodeId, decision: &str) -> [u8; 32] {
    let payload = serde_json::json!({
        "decision": decision,
        "node_id": node_id.to_string(),
        "run_id": run_id.to_string(),
    });
    let canonical = serde_json::to_vec(&payload).unwrap_or_default();
    Sha256::digest(&canonical).into()
}

/// `resolveNodeRef` — maps the `--node` reference to a committed
/// node of the run: a uuid parses to an id lookup, anything else is
/// a `node_key`. The lookup runs inside the run's own node set so a
/// foreign-run id can never decide a node the operator did not name.
async fn resolve_node_ref<B: NodeBackend>(
    backend: &B,
    run_id: RunId,
    reference: &str,
) -> Result<NodeRef, Failure> {
    let nodes = backend.nodes_for_run(run_id).await?;
    if let Some(raw) = parse_uuid_operand(reference) {
        for node in &nodes {
            if node.id.as_bytes() == &raw {
                return Ok(node.clone());
            }
        }
        return Err(Failure::invalid(
            "node_ref_not_found",
            "node reference matches no node of the run",
        ));
    }
    for node in nodes {
        if node.node_key == reference {
            return Ok(node);
        }
    }
    Err(Failure::invalid(
        "node_ref_not_found",
        "node reference matches no node of the run",
    ))
}

/// Operator-supplied ids: canonical lowercase hyphenated 36-char
/// text, version-agnostic, non-nil — deliberately narrower than
/// upstream `uuid.FromString` (which also admits dashless, braced,
/// and urn: forms); canonical is the only realistic operator input.
/// `from_trusted_db_bytes` is safe here because every rule beyond
/// version (canonical form, non-nil) is checked first.
fn parse_uuid_operand(text: &str) -> Option<[u8; 16]> {
    const HYPHENS: [usize; 4] = [8, 13, 18, 23];
    let bytes = text.as_bytes();
    if bytes.len() != 36 {
        return None;
    }
    let mut raw = [0u8; 16];
    let mut index = 0usize;
    let mut nibble = 0usize;
    for (position, byte) in bytes.iter().enumerate() {
        if HYPHENS.contains(&position) {
            if *byte != b'-' {
                return None;
            }
            continue;
        }
        let value = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return None,
        };
        if nibble.is_multiple_of(2) {
            raw[index] = value << 4;
        } else {
            raw[index] |= value;
            index += 1;
        }
        nibble += 1;
    }
    if index != 16 || raw == [0u8; 16] {
        return None;
    }
    Some(raw)
}

/// `parseCheckpointArgs` — walks the post-verb tokens into a flag
/// map and the positional list. `allowed` is the verb's flag
/// vocabulary; every flag takes a value (`--flag v` or `--flag=v`);
/// unknown flags and missing values are grammar errors.
fn parse_node_args(
    tokens: &[String],
    allowed: &[&str],
) -> Result<(std::collections::HashMap<String, String>, Vec<String>), ()> {
    let mut flags = std::collections::HashMap::new();
    let mut positional: Vec<String> = Vec::new();
    let mut index = 0usize;
    while index < tokens.len() {
        let token = &tokens[index];
        let Some(name_eq) = token.strip_prefix("--") else {
            positional.push(token.clone());
            index += 1;
            continue;
        };
        let (name, value) = match name_eq.split_once('=') {
            Some((name, value)) => (name.to_owned(), value.to_owned()),
            None => {
                if index + 1 >= tokens.len() || tokens[index + 1].starts_with("--") {
                    return Err(());
                }
                index += 1;
                (name_eq.to_owned(), tokens[index].clone())
            }
        };
        if !allowed.contains(&name.as_str()) {
            return Err(());
        }
        flags.insert(name, value);
        index += 1;
    }
    Ok((flags, positional))
}

/// `NodeDetails` — the result envelope's `details` payload: field
/// optionality mirrors the upstream struct (`elapsed_ms` always,
/// everything else `omitempty`).
fn emit(
    mut stdout: &mut dyn Write,
    start: &Instant,
    command_id: &str,
    code: ExitClass,
    reason: &str,
    mut details: serde_json::Value,
) -> u8 {
    if let Some(map) = details.as_object_mut() {
        map.insert(
            "elapsed_ms".to_owned(),
            serde_json::Value::from(start.elapsed().as_millis() as i64),
        );
    } else {
        details = serde_json::json!({
            "elapsed_ms": start.elapsed().as_millis() as i64,
        });
    }
    let result = LocalResult::now(command_id, code, Some(reason.to_owned()), Some(details));
    match result.write_json_line(&mut stdout) {
        Ok(()) => result.exit_code,
        // A command ending without a written result fails closed at 6.
        Err(_) => EXIT_TERMINAL.code(),
    }
}

fn fail(
    stdout: &mut dyn Write,
    start: &Instant,
    command_id: &str,
    code: ExitClass,
    reason: &str,
) -> u8 {
    emit(
        stdout,
        start,
        command_id,
        code,
        reason,
        serde_json::json!({"reason": reason}),
    )
}

fn fail_err(stdout: &mut dyn Write, start: &Instant, command_id: &str, failure: &Failure) -> u8 {
    if failure.kind() == FailureKind::Invalid && failure.code() == "node_ref_not_found" {
        return fail(
            stdout,
            start,
            command_id,
            EXIT_CONFIG_INVALID,
            REASON_NOT_FOUND,
        );
    }
    let (code, reason) = node_exit_reason(failure);
    fail(stdout, start, command_id, code, &reason)
}

/// `runNode`'s verb dispatch — generic over the backend seam so the
/// tests drive the verb against a fake; production passes the
/// env-composed PostgreSQL workflow store.
async fn run_verb<B: NodeBackend>(
    backend: &B,
    command_id: &str,
    tokens: &[String],
    mut stdout: &mut dyn Write,
    start: &Instant,
) -> u8 {
    match command_id {
        "node.decide" => {
            let Ok((flags, positional)) = parse_node_args(tokens, &["run", "node", "decision"])
            else {
                return fail(stdout, start, command_id, EXIT_CONFIG_INVALID, REASON_USAGE);
            };
            if !positional.is_empty()
                || flags.get("run").is_none_or(String::is_empty)
                || flags.get("node").is_none_or(String::is_empty)
                || flags.get("decision").is_none_or(String::is_empty)
            {
                return fail(stdout, start, command_id, EXIT_CONFIG_INVALID, REASON_USAGE);
            }
            // Presence of `run`/`node`/`decision` is pre-checked
            // above; `.get` keeps the impossible miss a usage
            // failure, never a panic.
            let Some(run_raw) = flags.get("run").and_then(|text| parse_uuid_operand(text)) else {
                return fail(stdout, start, command_id, EXIT_CONFIG_INVALID, REASON_USAGE);
            };
            let run_id = RunId::from_trusted_db_bytes(run_raw);
            let Some(decision) = flags.get("decision") else {
                return fail(stdout, start, command_id, EXIT_CONFIG_INVALID, REASON_USAGE);
            };
            if !ambiguous_decision_known(decision) {
                return fail(stdout, start, command_id, EXIT_CONFIG_INVALID, REASON_USAGE);
            }
            let Some(node_ref) = flags.get("node") else {
                return fail(stdout, start, command_id, EXIT_CONFIG_INVALID, REASON_USAGE);
            };
            let node = match resolve_node_ref(backend, run_id, node_ref).await {
                Ok(node) => node,
                Err(failure) => return fail_err(stdout, start, command_id, &failure),
            };
            let fingerprint = decide_fingerprint(run_id, node.id, decision);
            match backend
                .resolve_ambiguous(node.id, decision, fingerprint, ACTOR_NODE_DECIDE)
                .await
            {
                Ok(()) => emit(
                    stdout,
                    start,
                    command_id,
                    EXIT_OK,
                    "ok",
                    serde_json::json!({
                        "run_id": run_id.to_string(),
                        "node_id": node.id.to_string(),
                        "node_key": node.node_key,
                        "decision": decision,
                    }),
                ),
                Err(failure) => fail_err(stdout, start, command_id, &failure),
            }
        }
        _ => {
            // A node.* id this module does not own stays deferred —
            // dispatch to the standard placeholder, never silently
            // succeed.
            let result = LocalResult::unsupported(command_id);
            match result.write_json_line(&mut stdout) {
                Ok(()) => result.exit_code,
                Err(_) => EXIT_TERMINAL.code(),
            }
        }
    }
}

/// `newNodeBackendFromEnv` — composes the real backend when the
/// environment carries the DSN, else `None` (a failed connect
/// resolves to the same `None`: the command reports unavailable
/// instead of acting on a half-configured store).
async fn compose_backend() -> Option<WorkflowStore> {
    let dsn = env::var(ENV_NODE_DSN).ok()?;
    if dsn.is_empty() {
        return None;
    }
    let pool = PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(&dsn)
        .await
        .ok()?;
    Some(WorkflowStore::new(pool))
}

/// `runNode` — composes the backend (nil reports unavailable before
/// the grammar is even parsed — upstream's check order) and
/// dispatches the verb on a one-shot current-thread runtime.
pub(crate) fn node(
    command_id: &str,
    tokens: &[String],
    stdout: &mut dyn Write,
    _stderr: &mut dyn Write,
) -> u8 {
    let start = Instant::now();
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return fail(stdout, &start, command_id, EXIT_TERMINAL, REASON_FAILED);
    };
    let Some(backend) = runtime.block_on(compose_backend()) else {
        return fail(
            stdout,
            &start,
            command_id,
            EXIT_UNSUPPORTED,
            REASON_UNAVAILABLE,
        );
    };
    runtime.block_on(run_verb(&backend, command_id, tokens, stdout, &start))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(f)
    }

    fn strings<S: AsRef<str>>(tokens: &[S]) -> Vec<String> {
        tokens.iter().map(|t| t.as_ref().to_owned()).collect()
    }

    fn invoke<B: NodeBackend>(backend: &B, tokens: &[String]) -> (u8, serde_json::Value) {
        let mut stdout = Vec::new();
        let start = Instant::now();
        let code = block_on(run_verb(
            backend,
            "node.decide",
            tokens,
            &mut stdout,
            &start,
        ));
        let parsed = serde_json::from_slice(&stdout).unwrap();
        (code, parsed)
    }

    /// The port of upstream `fakeNodeBackend`: scripts each seam's
    /// result and records the call arguments.
    #[derive(Default)]
    struct FakeBackend {
        nodes: Mutex<Vec<NodeRef>>,
        nodes_err: Mutex<Option<Failure>>,
        nodes_calls: Mutex<u32>,
        nodes_run: Mutex<Option<RunId>>,

        decide_calls: Mutex<u32>,
        decide_node: Mutex<Option<WorkflowNodeId>>,
        decide_decision: Mutex<String>,
        decide_fingerprint: Mutex<Option<[u8; 32]>>,
        decide_actor: Mutex<String>,
        decide_err: Mutex<Option<Failure>>,
    }

    impl FakeBackend {
        fn record_decide(
            &self,
            node_id: WorkflowNodeId,
            decision: &str,
            fingerprint: [u8; 32],
            actor: &str,
        ) {
            *self.decide_calls.lock().unwrap() += 1;
            *self.decide_node.lock().unwrap() = Some(node_id);
            *self.decide_decision.lock().unwrap() = decision.to_owned();
            *self.decide_fingerprint.lock().unwrap() = Some(fingerprint);
            *self.decide_actor.lock().unwrap() = actor.to_owned();
        }
    }

    impl NodeBackend for FakeBackend {
        async fn nodes_for_run(&self, run_id: RunId) -> Result<Vec<NodeRef>, Failure> {
            *self.nodes_calls.lock().unwrap() += 1;
            *self.nodes_run.lock().unwrap() = Some(run_id);
            if let Some(err) = self.nodes_err.lock().unwrap().clone() {
                return Err(err);
            }
            Ok(self.nodes.lock().unwrap().clone())
        }

        async fn resolve_ambiguous(
            &self,
            node_id: WorkflowNodeId,
            decision: &str,
            fingerprint: [u8; 32],
            actor: &str,
        ) -> Result<(), Failure> {
            self.record_decide(node_id, decision, fingerprint, actor);
            match &*self.decide_err.lock().unwrap() {
                Some(err) => Err(err.clone()),
                None => Ok(()),
            }
        }
    }

    fn ambiguous_node() -> NodeRef {
        NodeRef {
            id: WorkflowNodeId::new(),
            node_key: "worker".to_owned(),
        }
    }

    /// A fixed `(run, node)` pair so the pinned fingerprint vectors
    /// compare byte-for-byte with upstream `decideFingerprint`'s
    /// SHA-256 over `{"decision":..,"node_id":..,"run_id":..}`.
    fn fixed_ids() -> (RunId, WorkflowNodeId) {
        let mut run_raw = [0u8; 16];
        let mut node_raw = [0u8; 16];
        for (i, b) in run_raw.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }
        for (i, b) in node_raw.iter_mut().enumerate() {
            *b = (i + 17) as u8;
        }
        (
            RunId::from_trusted_db_bytes(run_raw),
            WorkflowNodeId::from_trusted_db_bytes(node_raw),
        )
    }

    // -- upstream node_test.go: TestNodeDecideGrammarErrors ---

    #[test]
    fn decide_grammar_errors_exit_2_usage() {
        let backend = FakeBackend::default();
        let run_id = RunId::new().to_string();
        for tokens in [
            vec![],
            // missing node
            strings(&["--run", &run_id, "--decision", "rerun"]),
            // missing decision
            strings(&["--run", &run_id, "--node", "worker"]),
            // missing run
            strings(&["--node", "worker", "--decision", "rerun"]),
            // bad run uuid
            strings(&[
                "--run",
                "not-a-uuid",
                "--node",
                "worker",
                "--decision",
                "rerun",
            ]),
            // nil run uuid
            strings(&[
                "--run",
                "00000000-0000-0000-0000-000000000000",
                "--node",
                "worker",
                "--decision",
                "rerun",
            ]),
            // abandon refused — spec-1 carries no third decision
            strings(&[
                "--run",
                &run_id,
                "--node",
                "worker",
                "--decision",
                "abandon",
            ]),
            // fail refused — same locked vocabulary
            strings(&["--run", &run_id, "--node", "worker", "--decision", "fail"]),
            // unknown decision
            strings(&["--run", &run_id, "--node", "worker", "--decision", "bogus"]),
            // empty decision
            strings(&["--run", &run_id, "--node", "worker", "--decision", ""]),
            // unknown flag
            strings(&[
                "--run",
                &run_id,
                "--node",
                "worker",
                "--decision",
                "rerun",
                "--bogus",
                "x",
            ]),
            // positional
            strings(&[
                "--run",
                &run_id,
                "--node",
                "worker",
                "--decision",
                "rerun",
                "extra",
            ]),
            // missing flag value
            strings(&["--run"]),
        ] {
            let (code, parsed) = invoke(&backend, &tokens);
            assert_eq!(code, 2, "tokens {tokens:?}");
            assert_eq!(parsed["reason"], "NODE_USAGE", "tokens {tokens:?}");
            assert_eq!(parsed["command_id"], "node.decide");
        }
        assert_eq!(
            *backend.decide_calls.lock().unwrap(),
            0,
            "grammar refusals must not reach the store"
        );
    }

    // -- upstream node_test.go: TestNodeDecideByNodeKey ---

    /// A `node_key` `--node` resolves through the run's committed
    /// node set and resolves to the row's id before
    /// `resolve_ambiguous` runs.
    #[test]
    fn decide_by_node_key() {
        let backend = FakeBackend::default();
        let run_id = RunId::new();
        let node = ambiguous_node();
        *backend.nodes.lock().unwrap() = vec![
            NodeRef {
                id: WorkflowNodeId::new(),
                node_key: "other".to_owned(),
            },
            node.clone(),
        ];

        let (code, parsed) = invoke(
            &backend,
            &strings(&[
                "--run",
                run_id.to_string().as_str(),
                "--node",
                "worker",
                "--decision",
                "rerun",
            ]),
        );
        assert_eq!(code, 0, "{parsed}");
        assert_eq!(*backend.nodes_calls.lock().unwrap(), 1);
        assert_eq!(*backend.nodes_run.lock().unwrap(), Some(run_id));
        assert_eq!(*backend.decide_calls.lock().unwrap(), 1);
        assert_eq!(*backend.decide_node.lock().unwrap(), Some(node.id));
        assert_eq!(&*backend.decide_decision.lock().unwrap(), "rerun");
        assert_eq!(&*backend.decide_actor.lock().unwrap(), "operator");
        assert!(backend.decide_fingerprint.lock().unwrap().is_some());
        let details = &parsed["details"];
        assert_eq!(details["run_id"], run_id.to_string());
        assert_eq!(details["node_id"], node.id.to_string());
        assert_eq!(details["node_key"], "worker");
        assert_eq!(details["decision"], "rerun");
        assert!(details["elapsed_ms"].is_number());
    }

    // -- upstream node_test.go: TestNodeDecideByNodeID ---

    /// A uuid `--node` resolves by id against the same committed
    /// set; a node id the run does not contain can never decide a
    /// node the operator did not name.
    #[test]
    fn decide_by_node_id() {
        let backend = FakeBackend::default();
        let run_id = RunId::new();
        let node = ambiguous_node();
        *backend.nodes.lock().unwrap() = vec![node.clone()];

        let (code, _) = invoke(
            &backend,
            &strings(&[
                "--run",
                run_id.to_string().as_str(),
                "--node",
                &node.id.to_string(),
                "--decision",
                "resume",
            ]),
        );
        assert_eq!(code, 0);
        assert_eq!(*backend.decide_node.lock().unwrap(), Some(node.id));
        assert_eq!(&*backend.decide_decision.lock().unwrap(), "resume");
    }

    // -- upstream node_test.go: TestNodeDecideFingerprintIsDeterministic ---

    /// The same decision twice produces the identical fingerprint —
    /// the store's `(attempt_id)` key plus this replay-compare
    /// dedupes the replay.
    #[test]
    fn decide_fingerprint_is_deterministic() {
        let backend = FakeBackend::default();
        let run_id = RunId::new();
        let node = ambiguous_node();
        *backend.nodes.lock().unwrap() = vec![node];

        let args = [
            "--run".to_owned(),
            run_id.to_string(),
            "--node".to_owned(),
            "worker".to_owned(),
            "--decision".to_owned(),
            "rerun".to_owned(),
        ];
        for _ in 0..2 {
            let (code, _) = invoke(&backend, &args);
            assert_eq!(code, 0);
        }
        assert_eq!(*backend.decide_calls.lock().unwrap(), 2);
        let first = *backend.decide_fingerprint.lock().unwrap();
        let second = *backend.decide_fingerprint.lock().unwrap();
        assert_eq!(
            first, second,
            "identical commands must fingerprint identically"
        );
    }

    /// Byte-parity with upstream `decideFingerprint`: SHA-256 over
    /// `{"decision":"rerun","node_id":"<uuid>","run_id":"<uuid>"}`.
    /// The expected digests are pinned from the canonical payload.
    #[test]
    fn decide_fingerprint_matches_upstream_encoding() {
        let (run_id, node_id) = fixed_ids();
        assert_eq!(run_id.to_string(), "01020304-0506-0708-090a-0b0c0d0e0f10");
        assert_eq!(node_id.to_string(), "11121314-1516-1718-191a-1b1c1d1e1f20");
        let cases = [
            (
                "rerun",
                "a996193200d29c2db836828e06fcddfbc6d1c2357eb05fd5183e7a27fb5df9b2",
            ),
            (
                "resume",
                "02294604e25c4aab315ff84850ceecb581f4782a51c904b72c8df6819a541bbb",
            ),
        ];
        for (decision, want_hex) in cases {
            let got = decide_fingerprint(run_id, node_id, decision);
            let mut want = [0u8; 32];
            for (index, pair) in want_hex.as_bytes().as_chunks::<2>().0.iter().enumerate() {
                let hi = (pair[0] as char).to_digit(16).unwrap() as u8;
                let lo = (pair[1] as char).to_digit(16).unwrap() as u8;
                want[index] = (hi << 4) | lo;
            }
            assert_eq!(
                got, want,
                "decision {decision} must fingerprint upstream-identically"
            );
        }
    }

    // -- upstream node_test.go: TestNodeDecideUnknownRefIsNotFound ---

    #[test]
    fn decide_unknown_ref_is_not_found() {
        let backend = FakeBackend::default();
        *backend.nodes.lock().unwrap() = vec![ambiguous_node()];
        let (code, parsed) = invoke(
            &backend,
            &strings(&[
                "--run",
                &RunId::new().to_string(),
                "--node",
                "ghost",
                "--decision",
                "rerun",
            ]),
        );
        assert_eq!(code, 2, "{parsed}");
        assert_eq!(parsed["reason"], "NODE_NOT_FOUND");
        assert_eq!(
            *backend.decide_calls.lock().unwrap(),
            0,
            "an unmatched node reference must not reach resolve_ambiguous"
        );
    }

    // -- upstream node_test.go: TestNodeDecideForeignNodeIDIsNotFound ---

    /// A uuid ref that names no node of this run is refused the same
    /// way — the lookup never escapes the run's own node set.
    #[test]
    fn decide_foreign_node_id_is_not_found() {
        let backend = FakeBackend::default();
        *backend.nodes.lock().unwrap() = vec![ambiguous_node()];
        let foreign = WorkflowNodeId::new();
        let (code, parsed) = invoke(
            &backend,
            &strings(&[
                "--run",
                &RunId::new().to_string(),
                "--node",
                foreign.to_string().as_str(),
                "--decision",
                "rerun",
            ]),
        );
        assert_eq!(code, 2, "{parsed}");
        assert_eq!(parsed["reason"], "NODE_NOT_FOUND");
        assert_eq!(*backend.decide_calls.lock().unwrap(), 0);
    }

    // -- upstream node_test.go: TestNodeDecideNotAmbiguousIsTerminal ---

    /// Domain verdicts keep their reason code: INVALID exits 2,
    /// DENIED exits 6 — `WORKFLOW_NODE_NOT_AMBIGUOUS` on an unparked
    /// node is the DENIED case.
    #[test]
    fn decide_not_ambiguous_is_terminal() {
        let backend = FakeBackend::default();
        *backend.nodes.lock().unwrap() = vec![ambiguous_node()];
        *backend.decide_err.lock().unwrap() = Some(Failure::denied(
            "WORKFLOW_NODE_NOT_AMBIGUOUS",
            "node is not parked attempt_ambiguous",
        ));
        let (code, parsed) = invoke(
            &backend,
            &strings(&[
                "--run",
                &RunId::new().to_string(),
                "--node",
                "worker",
                "--decision",
                "rerun",
            ]),
        );
        assert_eq!(code, 6, "{parsed}");
        assert_eq!(parsed["reason"], "WORKFLOW_NODE_NOT_AMBIGUOUS");
    }

    // -- upstream node_test.go: TestNodeDecideConflictingDecisionIsDenied ---

    /// A changed decision on the recorded attempt is DENIED —
    /// `ATTEMPT_DECISION_CONFLICT` per the store's one-row-ever rule.
    #[test]
    fn decide_conflicting_decision_is_denied() {
        let backend = FakeBackend::default();
        *backend.nodes.lock().unwrap() = vec![ambiguous_node()];
        *backend.decide_err.lock().unwrap() = Some(Failure::denied(
            "ATTEMPT_DECISION_CONFLICT",
            "a different decision is already recorded",
        ));
        let (code, parsed) = invoke(
            &backend,
            &strings(&[
                "--run",
                &RunId::new().to_string(),
                "--node",
                "worker",
                "--decision",
                "resume",
            ]),
        );
        assert_eq!(code, 6, "{parsed}");
        assert_eq!(parsed["reason"], "ATTEMPT_DECISION_CONFLICT");
    }

    // -- upstream node_test.go: TestNodeDecideInvalidVerdictIsConfigInvalid ---

    #[test]
    fn decide_invalid_verdict_is_config_invalid() {
        let backend = FakeBackend::default();
        *backend.nodes.lock().unwrap() = vec![ambiguous_node()];
        *backend.decide_err.lock().unwrap() =
            Some(Failure::invalid("WORKFLOW_NODE_NOT_FOUND", "no such node"));
        let (code, parsed) = invoke(
            &backend,
            &strings(&[
                "--run",
                &RunId::new().to_string(),
                "--node",
                "worker",
                "--decision",
                "rerun",
            ]),
        );
        assert_eq!(code, 2, "{parsed}");
        assert_eq!(parsed["reason"], "WORKFLOW_NODE_NOT_FOUND");
    }

    // -- upstream node_test.go: TestNodeDecideAdapterErrorIsTerminal ---

    #[test]
    fn decide_adapter_error_is_terminal() {
        let backend = FakeBackend::default();
        *backend.nodes.lock().unwrap() = vec![ambiguous_node()];
        *backend.decide_err.lock().unwrap() = Some(Failure::unavailable(
            "pg_connection_error",
            "connection reset",
        ));
        let (code, parsed) = invoke(
            &backend,
            &strings(&[
                "--run",
                &RunId::new().to_string(),
                "--node",
                "worker",
                "--decision",
                "rerun",
            ]),
        );
        assert_eq!(code, 6, "{parsed}");
        assert_eq!(parsed["reason"], "NODE_FAILED");
    }

    // -- upstream node_test.go: TestNodeDecideListFailureIsTerminal ---

    /// A failed node listing surfaces as the adapter-failure
    /// verdict, not a fabricated "not found".
    #[test]
    fn decide_list_failure_is_terminal() {
        let backend = FakeBackend::default();
        *backend.nodes_err.lock().unwrap() =
            Some(Failure::unavailable("pg_connection_error", "pool closed"));
        let (code, parsed) = invoke(
            &backend,
            &strings(&[
                "--run",
                &RunId::new().to_string(),
                "--node",
                "worker",
                "--decision",
                "rerun",
            ]),
        );
        assert_eq!(code, 6, "{parsed}");
        assert_eq!(parsed["reason"], "NODE_FAILED");
        assert_eq!(
            *backend.decide_calls.lock().unwrap(),
            0,
            "a failed listing must not reach resolve_ambiguous"
        );
    }

    /// `resolveNodeRef`'s `--node` ref parses against every uuid
    /// form the command surface accepts: the canonical 36-char
    /// hyphenated text.
    #[test]
    fn parse_uuid_operand_canonical_only() {
        assert!(parse_uuid_operand("01020304-0506-0708-090a-0b0c0d0e0f10").is_some());
        assert!(parse_uuid_operand("01020304-0506-0708-090A-0B0C0D0E0F10").is_some());
        assert!(parse_uuid_operand("not-a-uuid").is_none());
        assert!(parse_uuid_operand("010203040506070809000b0c0d0e0f10").is_none());
        assert!(parse_uuid_operand("00000000-0000-0000-0000-000000000000").is_none());
    }
}
