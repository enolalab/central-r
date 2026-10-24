//! `central harness resume|rerun|cancel` — the harness operator
//! verbs (Phase R3 task 13). Upstream exposes these actions through
//! the `/app` operator surface ([`web::harness::HarnessOperator`]);
//! the CLI verbs run the SAME composed [`ServeHarnessOperator`]
//! against the same durable stores — never a second authority.
//!
//! Composition mirrors `central serve` minus the listeners and the
//! dispatcher: the execution store/service, the harness attempt and
//! recovery stores, the recovery-authority [`Resolver`], and the
//! [`ServeTaskService`] task surface (rerun's task retry leg).
//! The orchestrator's approval registry is absent (no in-process
//! bridge exists outside a running serve), so permission decisions
//! fail closed exactly as they do while serve's dispatcher is down.
//!
//! Flags (all required unless noted):
//!
//! ```text
//! --workspace <uuid> --task <uuid> --run <uuid>
//! [--run-version <n>]     expected run version; loaded durably when
//!                         omitted (the operator re-checks before
//!                         every mutation either way)
//! [--principal <name>]    the operator principal; default `cli`
//! ```
//!
//! DSN: `CENTRAL_HARNESS_DSN` (verb-scoped, like
//! `CENTRAL_ARTIFACT_READ_DSN`), then `CENTRAL_DSN`.
//!
//! Exactly one `central.local-result/v1` envelope per invocation; a
//! write failure fails closed at exit `6`.

use std::io::Write;
use std::sync::Arc;

use central_adapter_postgres::execution::Store as PgExecutionStore;
use central_adapter_postgres::harness::PgHarnessStore;
use central_adapter_postgres::task::{
    DetailStore as PgTaskDetailStore, EventLogStore as PgTaskEventLogStore,
    ListStore as PgTaskListStore, Store as PgTaskStore,
};
use central_execution::app::{NoB09, Service as ExecutionService};
use central_foundation::failure::{ExitClass, Failure};
use central_foundation::identity::{RunId, TaskId, WorkspaceId};
use central_foundation::local_result::LocalResult;
use central_harness::app::dispatcher;
use central_harness::app::reconciler::Resolver;
use central_kernel::harness_compose::HarnessConfig;
use central_kernel::serve_lifecycle::ServeResolveStore;
use central_kernel::serve_operator::{ServeHarnessOperator, ServeHarnessOperatorDeps};
use central_kernel::serve_support::TokioClock;
use central_kernel::serve_tasks::ServeTaskService;
use central_transport_http::ports::TaskService as _;
use central_transport_http::web::harness::{HarnessOperator, HarnessResolveRequest};
use sqlx::postgres::PgPoolOptions;

const ENV_HARNESS_DSN: &str = "CENTRAL_HARNESS_DSN";
const ENV_SERVE_DSN: &str = "CENTRAL_DSN";

/// The operator principal the CLI runs under — the
/// `operator-session:<principal>` form the operator surface asserts.
const DEFAULT_PRINCIPAL: &str = "cli";

/// The verb entry point — `command_id` is `harness.resume`,
/// `harness.rerun`, or `harness.cancel`.
pub fn harness(
    command_id: &str,
    tokens: &[String],
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> u8 {
    let action = match command_id {
        "harness.resume" => Action::Resume,
        "harness.rerun" => Action::Rerun,
        "harness.cancel" => Action::Cancel,
        // Defensive: main routes only the three ids here. Anything
        // else stays a fail-closed deferred verb.
        _ => {
            let result = LocalResult::unsupported(command_id);
            return match result.write_json_line(stdout) {
                Ok(()) => result.exit_code,
                Err(err) => io_failure(stderr, &err),
            };
        }
    };
    let parsed = match Flags::parse(tokens) {
        Ok(f) => f,
        Err(msg) => {
            return emit(
                command_id,
                stdout,
                stderr,
                ExitClass::Usage,
                Some("HARNESS_USAGE"),
                Some(serde_json::json!({ "detail": msg })),
            );
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            return emit(
                command_id,
                stdout,
                stderr,
                ExitClass::Terminal,
                Some("HARNESS_RUNTIME_UNAVAILABLE"),
                Some(serde_json::json!({ "detail": e.to_string() })),
            );
        }
    };
    match runtime.block_on(run(action, parsed)) {
        Ok(details) => emit(
            command_id,
            stdout,
            stderr,
            ExitClass::Success,
            None,
            Some(details),
        ),
        // `Failure::exit_class` carries the envelope's exit class —
        // `lifecycle::exit_code` only classifies `ExitError`, which a
        // bare `Failure` never is, so it would collapse every refusal
        // to exit 6.
        Err(f) => emit(
            command_id,
            stdout,
            stderr,
            f.exit_class(),
            Some(f.code()),
            None,
        ),
    }
}

enum Action {
    Resume,
    Rerun,
    Cancel,
}

struct Flags {
    workspace: WorkspaceId,
    task: TaskId,
    run: RunId,
    run_version: Option<i64>,
    principal: String,
}

impl Flags {
    fn parse(tokens: &[String]) -> Result<Self, String> {
        let mut workspace = None;
        let mut task = None;
        let mut run = None;
        let mut run_version = None;
        let mut principal = DEFAULT_PRINCIPAL.to_string();
        let mut it = tokens.iter();
        while let Some(t) = it.next() {
            let (name, inline) = match t.split_once('=') {
                Some((n, v)) => (n, Some(v.to_string())),
                None => (t.as_str(), None),
            };
            let mut take = |name: &str, inline: Option<String>| -> Result<String, String> {
                match inline {
                    Some(v) if !v.is_empty() => Ok(v),
                    _ => it
                        .next()
                        .cloned()
                        .ok_or_else(|| format!("{name} requires a value")),
                }
            };
            match name {
                "--workspace" => {
                    let v = take(name, inline)?;
                    workspace = Some(
                        v.parse::<WorkspaceId>()
                            .map_err(|_| format!("--workspace {v:?} is not a UUID"))?,
                    );
                }
                "--task" => {
                    let v = take(name, inline)?;
                    task = Some(
                        v.parse::<TaskId>()
                            .map_err(|_| format!("--task {v:?} is not a UUID"))?,
                    );
                }
                "--run" => {
                    let v = take(name, inline)?;
                    run = Some(
                        v.parse::<RunId>()
                            .map_err(|_| format!("--run {v:?} is not a UUID"))?,
                    );
                }
                "--run-version" => {
                    let v = take(name, inline)?;
                    run_version = Some(
                        v.parse::<i64>()
                            .map_err(|_| format!("--run-version {v:?} is not an integer"))?,
                    );
                }
                "--principal" => principal = take(name, inline)?,
                other => return Err(format!("unknown flag {other}")),
            }
        }
        Ok(Self {
            workspace: workspace.ok_or("--workspace is required")?,
            task: task.ok_or("--task is required")?,
            run: run.ok_or("--run is required")?,
            run_version,
            principal,
        })
    }
}

/// Composes the operator minus serve's listeners/dispatcher, then
/// runs the verb.
async fn run(action: Action, flags: Flags) -> Result<serde_json::Value, Failure> {
    let dsn = std::env::var(ENV_HARNESS_DSN)
        .ok()
        .filter(|d| !d.trim().is_empty())
        .or_else(|| {
            std::env::var(ENV_SERVE_DSN)
                .ok()
                .filter(|d| !d.trim().is_empty())
        })
        .ok_or_else(|| {
            Failure::unavailable(
                "HARNESS_UNAVAILABLE",
                format!("neither {ENV_HARNESS_DSN} nor {ENV_SERVE_DSN} is set"),
            )
        })?;
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&dsn)
        .await
        .map_err(|e| Failure::unavailable("HARNESS_UNAVAILABLE", format!("runtime pool: {e}")))?;

    let exec_store = Arc::new(PgExecutionStore::new(pool.clone()));
    let execution: Arc<ExecutionService<PgExecutionStore, PgExecutionStore, TokioClock, NoB09>> =
        Arc::new(ExecutionService::new(
            PgExecutionStore::new(pool.clone()),
            PgExecutionStore::new(pool.clone()),
            TokioClock,
        ));
    let harness_store = Arc::new(PgHarnessStore::new(pool.clone()));
    let resolver = Arc::new(Resolver::new(
        Arc::new(ServeResolveStore::new(
            harness_store.clone(),
            harness_store.clone(),
        )),
        Arc::new(TokioClock),
    ));
    let tasks = Arc::new(ServeTaskService::new(
        Arc::new(central_task::app::TaskService::new(
            PgTaskStore::new(pool.clone()),
            PgTaskListStore::new(pool.clone()),
            PgTaskDetailStore::new(pool.clone()),
        )),
        Arc::new(PgTaskStore::new(pool.clone())),
        Arc::new(PgTaskEventLogStore::new(pool.clone())),
    ));

    let cfg = HarnessConfig::load(|name| std::env::var(name).unwrap_or_default())
        .map_err(|f| Failure::invalid("CONFIG_INVALID", format!("harness config: {}", f.code())))?;
    let operator = ServeHarnessOperator::new(ServeHarnessOperatorDeps {
        // No dispatcher exists outside serve — the banner reports the
        // disabled lifecycle, matching upstream's harness-off wiring.
        status: Arc::new(dispatcher::Status::default),
        reads: exec_store.clone(),
        commands: execution.clone(),
        tasks: Some(tasks.clone()),
        rerun_tasks: Some(tasks.clone()),
        attempts: harness_store.clone(),
        bridge: None,
        policies_enabled: cfg.enabled,
        backend: cfg.backend.as_str(),
        budget_defaults: central_transport_http::web::harness::HarnessBudgetDefaults {
            cost_micro_usd: cfg.max_cost_micro_usd,
            wall_clock: cfg.wall_clock.unsigned_abs(),
        },
        max_attempts: if cfg.enabled { cfg.max_attempts } else { 0 },
        eligible_after: if cfg.enabled {
            cfg.eligible_after
        } else {
            time::OffsetDateTime::UNIX_EPOCH
        },
        task_cost_cap_micro_usd: if cfg.enabled {
            cfg.task_cost_cap_micro_usd
        } else {
            0
        },
        resolver,
        clock: Arc::new(TokioClock),
    });

    // The run version the page would have loaded — resolved durably
    // when the flag is omitted (the operator still re-checks before
    // every mutation).
    let expected_run_version = match flags.run_version {
        Some(v) => v,
        None => tasks
            .load_aggregate(flags.workspace, flags.task)
            .await?
            .run_version
            .ok_or_else(|| Failure::invalid("HARNESS_RUN_ABSENT", "the task has no current run"))?,
    };
    let req = HarnessResolveRequest {
        workspace_id: flags.workspace,
        task_id: flags.task,
        run_id: flags.run,
        expected_run_version,
        principal: format!("operator-session:{}", flags.principal),
    };
    match action {
        Action::Resume => operator.resume(req).await?,
        Action::Rerun => operator.resolve_rerun(req).await?,
        Action::Cancel => operator.resolve_cancelled(req).await?,
    }
    Ok(serde_json::json!({
        "workspace_id": flags.workspace.to_string(),
        "task_id": flags.task.to_string(),
        "run_id": flags.run.to_string(),
        "expected_run_version": expected_run_version,
    }))
}

fn emit(
    command_id: &str,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
    class: ExitClass,
    reason: Option<&str>,
    details: Option<serde_json::Value>,
) -> u8 {
    let result = LocalResult::now(command_id, class, reason.map(str::to_string), details);
    match result.write_json_line(stdout) {
        Ok(()) => result.exit_code,
        Err(err) => io_failure(stderr, &err),
    }
}

fn io_failure(stderr: &mut impl Write, err: &std::io::Error) -> u8 {
    let _ = writeln!(stderr, "central: could not write result envelope");
    let _ = err;
    ExitClass::Terminal.code()
}
