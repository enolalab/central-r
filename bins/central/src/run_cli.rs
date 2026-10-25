//! `central run submit` — the run-submission verb over the durable
//! workflow graph (issue #122), ported from `internal/command/run.go`
//! plus the deferred-mode composition of
//! `cmd/central/run_composition.go`.
//!
//!   central run submit --workspace <uuid> --title <text> --workers <n> [--run-key <k>]
//!
//! submits one leader + N flat workers through
//! [`central_runsubmit::app::Service`]: a queued task+run is created
//! and self-claimed (owner `phase2`, excluding the run from Phase-1
//! dispatch), the leader batch emits, the worker batch emits parented
//! to the leader, and every node flips ready for the scheduler. With
//! `--run-key` the call is resumable: a replay adopts the recorded run
//! (fingerprint-compared) and converges instead of duplicating.
//!
//! Exit mapping mirrors `central node decide`: grammar errors exit 2
//! with `RUN_USAGE`; a missing backend fails closed with
//! `RUN_UNAVAILABLE`; domain failures keep their own reason (`INVALID`
//! exits 2, `DENIED`/`CONFLICT` exit 6); adapter errors exit 6 as
//! `RUN_FAILED`. `RUN_*` tokens are envelope reasons only, never
//! journaled.
//!
//! Composition (upstream `newRunBackendFromEnv`): when the environment
//! carries `CENTRAL_NODE_DSN` the command composes the real service —
//! the task change-set store plus the workflow graph store over one
//! pool, with the graph store's harness-registry seam set to the
//! serve-parity claude-code-only rule (the shared serve store leaves
//! it unset and would reject every emit). Without the DSN the seam
//! stays absent and dispatch fails closed `RUN_UNAVAILABLE` — before
//! the grammar is even parsed, like upstream's check order.

use std::env;
use std::io::Write;
use std::sync::Arc;
use std::time::Instant;

use central_adapter_postgres::task::{
    DetailStore as PgTaskDetailStore, ListStore as PgTaskListStore, Store as PgTaskStore,
};
use central_adapter_postgres::workflow::Store as PgWorkflowStore;
use central_foundation::failure::{ExitClass, Failure, FailureKind};
use central_foundation::identity::WorkspaceId;
use central_foundation::local_result::LocalResult;
use central_runsubmit::app::{Service, TaskCommands};
use central_runsubmit::domain::{SubmitRequest, SubmitResult};
use sqlx::postgres::PgPoolOptions;

/// `envNodeDSN` — the deferred-mode DSN the run and node verbs share.
/// An operator or a serve-side launcher supplies it; the binary never
/// reads a credential file for it.
const ENV_NODE_DSN: &str = "CENTRAL_NODE_DSN";

// The command-level reason tokens that are not store verdicts:
// grammar errors, the missing-backend refusal, and the adapter-failure
// catch-all. Domain verdicts travel on their Failure's own reason.
const REASON_USAGE: &str = "RUN_USAGE";
const REASON_UNAVAILABLE: &str = "RUN_UNAVAILABLE";
const REASON_FAILED: &str = "RUN_FAILED";

/// `cli.Exit*` mapped onto `ExitClass`'s codes.
const EXIT_OK: ExitClass = ExitClass::Success;
/// `cli.ExitConfigInvalidCode` — invalid invocation / INVALID verdict.
const EXIT_CONFIG_INVALID: ExitClass = ExitClass::Usage;
/// `cli.ExitUnsupported` — the backend is not composable.
const EXIT_UNSUPPORTED: ExitClass = ExitClass::Incompatible;
/// `cli.ExitTerminal` — a terminal failure or DENIED/CONFLICT verdict.
const EXIT_TERMINAL: ExitClass = ExitClass::Terminal;

/// `command.RunBackend` — the command's dependency seam: the
/// runsubmit service itself. Absent fails closed `RUN_UNAVAILABLE`.
trait RunBackend {
    /// `Submit` — one submission through the shared saga.
    async fn submit(&self, req: SubmitRequest) -> Result<SubmitResult, Failure>;
}

/// The composed runsubmit [`Service`] satisfies the command seam
/// (upstream `var _ command.RunBackend = (*runsubmit.Service)(nil)`).
impl<T, L, R, G> RunBackend for Service<T, L, R, G>
where
    T: TaskCommands,
    L: central_task::port::AggregateLoader,
    R: central_task::port::RunByKeyReader,
    G: central_runsubmit::app::GraphStore,
{
    async fn submit(&self, req: SubmitRequest) -> Result<SubmitResult, Failure> {
        Service::submit(self, req).await
    }
}

/// The composed service's concrete instantiation — the pg task
/// change-set store behind `central_task`'s app service, the same
/// store as both read seams, and the pg workflow graph store.
type ComposedService = Service<
    central_task::app::TaskService<PgTaskStore, PgTaskListStore, PgTaskDetailStore>,
    PgTaskStore,
    PgTaskStore,
    PgWorkflowStore,
>;

/// `runExit` — maps an error to exit code + reason: request-shape
/// refusals are usage errors; domain failures keep their own reason;
/// anything else is a terminal adapter failure. Failure details never
/// echo operator input: reasons are fixed tokens or closed domain
/// vocabularies.
fn run_exit_reason(failure: &Failure) -> (ExitClass, String) {
    // `ValidationError` — the runsubmit request-shape marker.
    if failure.code() == central_runsubmit::domain::codes::REQUEST_VALIDATION {
        return (EXIT_CONFIG_INVALID, REASON_USAGE.to_owned());
    }
    if failure.code().starts_with("pg_") {
        return (EXIT_TERMINAL, REASON_FAILED.to_owned());
    }
    match failure.kind() {
        FailureKind::Invalid => (EXIT_CONFIG_INVALID, failure.code().to_owned()),
        // Upstream's plain `fmt.Errorf` paths — internal saga
        // invariants — collapse to RUN_FAILED; unavailable/ambiguous
        // adapter classes are terminal, not typed domain verdicts.
        FailureKind::Internal | FailureKind::Ambiguous | FailureKind::Unavailable => {
            (EXIT_TERMINAL, REASON_FAILED.to_owned())
        }
        _ => (EXIT_TERMINAL, failure.code().to_owned()),
    }
}

/// `parseCheckpointArgs` — walks the post-verb tokens into a flag map
/// and the positional list (same grammar walker `node_cli` shares):
/// every flag takes a value (`--flag v` or `--flag=v`); unknown flags
/// and missing values are grammar errors.
fn parse_run_args(
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

/// `RunDetails` — the result envelope's `details` payload: field
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
    let (code, reason) = run_exit_reason(failure);
    fail(stdout, start, command_id, code, &reason)
}

/// `runSubmit` — the verb body, generic over the backend seam so the
/// tests drive it against a fake; production passes the env-composed
/// runsubmit service.
async fn run_verb<B: RunBackend>(
    backend: &B,
    command_id: &str,
    tokens: &[String],
    mut stdout: &mut dyn Write,
    start: &Instant,
) -> u8 {
    match command_id {
        "run.submit" => {
            let Ok((flags, positional)) =
                parse_run_args(tokens, &["workspace", "title", "workers", "run-key"])
            else {
                return fail(stdout, start, command_id, EXIT_CONFIG_INVALID, REASON_USAGE);
            };
            if !positional.is_empty()
                || flags.get("workspace").is_none_or(String::is_empty)
                || flags.get("title").is_none_or(String::is_empty)
                || flags.get("workers").is_none_or(String::is_empty)
            {
                return fail(stdout, start, command_id, EXIT_CONFIG_INVALID, REASON_USAGE);
            }
            let workspace_raw = flags.get("workspace").map_or("", String::as_str);
            let Ok(workspace_id) = WorkspaceId::parse(workspace_raw) else {
                return fail(stdout, start, command_id, EXIT_CONFIG_INVALID, REASON_USAGE);
            };
            if workspace_id.is_nil() {
                return fail(stdout, start, command_id, EXIT_CONFIG_INVALID, REASON_USAGE);
            }
            let workers_raw = flags.get("workers").map_or("", String::as_str);
            let Ok(workers) = workers_raw.parse::<i64>() else {
                return fail(stdout, start, command_id, EXIT_CONFIG_INVALID, REASON_USAGE);
            };
            // Range errors (workers out of 1..8, title/run-key bounds)
            // belong to the service: it refuses with the
            // request-validation marker, mapped to RUN_USAGE by
            // `run_exit_reason`, so CLI and HTTP share one bound
            // implementation. `idempotency_key` stays unset — the
            // service mints one internally.
            let title = flags.get("title").cloned().unwrap_or_default();
            let req = SubmitRequest {
                workspace_id,
                title,
                workers,
                run_key: flags.get("run-key").cloned().filter(|k| !k.is_empty()),
                idempotency_key: None,
            };
            match backend.submit(req).await {
                Ok(res) => {
                    let nodes: Vec<serde_json::Value> = res
                        .nodes
                        .iter()
                        .map(|n| {
                            serde_json::json!({
                                "node_id": n.node_id.to_string(),
                                "node_key": n.node_key,
                                "state": n.state.as_str(),
                            })
                        })
                        .collect();
                    emit(
                        stdout,
                        start,
                        command_id,
                        EXIT_OK,
                        "ok",
                        serde_json::json!({
                            "run_id": res.run_id.to_string(),
                            "task_id": res.task_id.to_string(),
                            "nodes": nodes,
                            "deduped": res.deduped,
                        }),
                    )
                }
                Err(failure) => fail_err(stdout, start, command_id, &failure),
            }
        }
        _ => {
            // A run.* id this module does not own stays deferred —
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

/// `newRunBackendFromEnv` — composes the real backend when the
/// environment carries the DSN, else `None` (a failed connect
/// resolves to the same `None`: the command reports unavailable
/// instead of acting on a half-configured store). The graph store's
/// harness-registry seam is the serve-parity claude-code-only rule —
/// without it every emit would refuse.
async fn compose_backend() -> Option<ComposedService> {
    let dsn = env::var(ENV_NODE_DSN).ok()?;
    if dsn.is_empty() {
        return None;
    }
    let pool = PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(&dsn)
        .await
        .ok()?;
    let tasks = PgTaskStore::new(pool.clone());
    let mut graph = PgWorkflowStore::new(pool.clone());
    graph.harness_registry = Some(Arc::new(|name: &str| {
        name == central_runsubmit::domain::HARNESS_NAME
    }));
    Some(Service::new(
        central_task::app::TaskService::new(
            PgTaskStore::new(pool.clone()),
            PgTaskListStore::new(pool.clone()),
            PgTaskDetailStore::new(pool.clone()),
        ),
        tasks.clone(),
        tasks,
        graph,
    ))
}

/// `runSubmit`'s dispatcher entry — composes the backend (absent
/// reports unavailable before the grammar is even parsed — upstream's
/// check order) and runs the verb on a one-shot current-thread
/// runtime.
pub(crate) fn run(
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

    const WS: &str = "019fdc8d-e33a-76ed-9ef0-a0d9fe92e54a";

    struct FakeBackend {
        requests: Mutex<Vec<SubmitRequest>>,
        result: Mutex<Result<SubmitResult, Failure>>,
    }

    impl FakeBackend {
        fn ok() -> Self {
            Self {
                requests: Mutex::new(Vec::new()),
                result: Mutex::new(Ok(SubmitResult {
                    task_id: central_foundation::identity::TaskId::new(),
                    run_id: central_foundation::identity::RunId::new(),
                    nodes: vec![central_runsubmit::domain::SubmittedNode {
                        node_id: central_foundation::identity::WorkflowNodeId::new(),
                        node_key: "leader".to_string(),
                        state: central_workflow::domain::NodeStatus::Ready,
                    }],
                    deduped: false,
                })),
            }
        }
    }

    impl RunBackend for FakeBackend {
        async fn submit(&self, req: SubmitRequest) -> Result<SubmitResult, Failure> {
            self.requests.lock().unwrap().push(req);
            self.result.lock().unwrap().clone()
        }
    }

    fn invoke<B: RunBackend>(backend: &B, tokens: &[&str]) -> (u8, serde_json::Value) {
        let mut out = Vec::<u8>::new();
        let tokens: Vec<String> = tokens.iter().map(|s| (*s).to_owned()).collect();
        let start = Instant::now();
        let code = block_on(run_verb(backend, "run.submit", &tokens, &mut out, &start));
        let parsed: serde_json::Value =
            serde_json::from_str(String::from_utf8(out).unwrap().trim_end()).unwrap();
        (code, parsed)
    }

    /// Grammar refuseals: missing flags, positionals, unknown flags,
    /// bad workspace, nonnumeric workers — all RUN_USAGE at exit 2
    /// before any backend call.
    #[test]
    fn submit_grammar_errors_exit_2_usage() {
        for tokens in [
            &[][..],
            &["positional"][..],
            &["--workspace", WS, "--title", "t", "--workers", "2", "extra"][..],
            &["--title", "t", "--workers", "2"][..],
            &["--workspace", WS, "--workers", "2"][..],
            &["--workspace", WS, "--title", "t"][..],
            &[
                "--workspace",
                "not-a-uuid",
                "--title",
                "t",
                "--workers",
                "2",
            ][..],
            &["--workspace", WS, "--title", "t", "--workers", "x"][..],
            &[
                "--workspace",
                WS,
                "--title",
                "t",
                "--workers",
                "2",
                "--bogus",
                "1",
            ][..],
            &["--workspace", WS, "--title", "t", "--workers"][..],
        ] {
            let backend = FakeBackend::ok();
            let (code, env) = invoke(&backend, tokens);
            assert_eq!(code, 2, "tokens {tokens:?}");
            assert_eq!(env["reason"], "RUN_USAGE", "tokens {tokens:?}");
            assert_eq!(env["exit_code"], 2);
            assert!(backend.requests.lock().unwrap().is_empty());
        }
    }

    /// The success envelope carries the run/task ids, node details,
    /// deduped flag, and elapsed_ms.
    #[test]
    fn submit_success_envelope() {
        let backend = FakeBackend::ok();
        let (code, env) = invoke(
            &backend,
            &[
                "--workspace",
                WS,
                "--title",
                "demo",
                "--workers",
                "2",
                "--run-key",
                "k1",
            ],
        );
        assert_eq!(code, 0);
        assert_eq!(env["schema_version"], "central.local-result/v1");
        assert_eq!(env["command_id"], "run.submit");
        assert_eq!(env["reason"], "ok");
        let details = &env["details"];
        assert_eq!(details["task_id"].as_str().unwrap().len(), 36);
        assert_eq!(details["run_id"].as_str().unwrap().len(), 36);
        assert_eq!(details["nodes"].as_array().unwrap().len(), 1);
        assert_eq!(details["nodes"][0]["node_key"], "leader");
        assert_eq!(details["nodes"][0]["state"], "ready");
        assert_eq!(details["deduped"], false);
        assert!(details["elapsed_ms"].as_i64().is_some());
        // The request reached the service verbatim.
        let reqs = backend.requests.lock().unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].title, "demo");
        assert_eq!(reqs[0].workers, 2);
        assert_eq!(reqs[0].run_key.as_deref(), Some("k1"));
    }

    /// Empty `--run-key` normalizes to keyless.
    #[test]
    fn submit_empty_run_key_is_keyless() {
        let backend = FakeBackend::ok();
        let (code, _) = invoke(
            &backend,
            &[
                "--workspace",
                WS,
                "--title",
                "t",
                "--workers",
                "1",
                "--run-key",
                "",
            ],
        );
        assert_eq!(code, 0);
        assert!(backend.requests.lock().unwrap()[0].run_key.is_none());
    }

    /// The request-validation marker maps to RUN_USAGE at exit 2 —
    /// the service's own bounds reach the CLI as usage errors.
    #[test]
    fn submit_validation_maps_to_usage() {
        let backend = FakeBackend::ok();
        *backend.result.lock().unwrap() = Err(Failure::invalid(
            central_runsubmit::domain::codes::REQUEST_VALIDATION,
            "runsubmit: invalid workers",
        ));
        let (code, env) = invoke(
            &backend,
            &["--workspace", WS, "--title", "t", "--workers", "9"],
        );
        assert_eq!(code, 2);
        assert_eq!(env["reason"], "RUN_USAGE");
    }

    /// Domain verdicts keep their own reason: Invalid exits 2 with
    /// the code; Conflict exits 6 with the code.
    #[test]
    fn submit_domain_verdicts_keep_reason() {
        let backend = FakeBackend::ok();
        *backend.result.lock().unwrap() = Err(Failure::invalid(
            central_runsubmit::domain::codes::SPEC_VALIDATION_FAILED,
            "child spec rejected",
        ));
        let (code, env) = invoke(
            &backend,
            &["--workspace", WS, "--title", "t", "--workers", "2"],
        );
        assert_eq!(code, 2);
        assert_eq!(env["reason"], "SPEC_VALIDATION_FAILED");

        *backend.result.lock().unwrap() = Err(Failure::conflict(
            central_runsubmit::domain::codes::DUPLICATE_IDEMPOTENCY_KEY,
            "recorded row stands",
        ));
        let (code, env) = invoke(
            &backend,
            &["--workspace", WS, "--title", "t", "--workers", "2"],
        );
        assert_eq!(code, 6);
        assert_eq!(env["reason"], "DUPLICATE_IDEMPOTENCY_KEY");
    }

    /// Adapter failures (pg_*) and internal invariants collapse to
    /// RUN_FAILED at exit 6.
    #[test]
    fn submit_adapter_and_internal_failures_map_to_run_failed() {
        let backend = FakeBackend::ok();
        *backend.result.lock().unwrap() = Err(Failure::internal("pg_connect", "db gone"));
        let (code, env) = invoke(
            &backend,
            &["--workspace", WS, "--title", "t", "--workers", "2"],
        );
        assert_eq!(code, 6);
        assert_eq!(env["reason"], "RUN_FAILED");

        *backend.result.lock().unwrap() = Err(Failure::internal(
            central_runsubmit::domain::codes::INVARIANT,
            "runsubmit: leader emit committed 0 nodes",
        ));
        let (code, env) = invoke(
            &backend,
            &["--workspace", WS, "--title", "t", "--workers", "2"],
        );
        assert_eq!(code, 6);
        assert_eq!(env["reason"], "RUN_FAILED");
    }
}
