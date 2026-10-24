//! `central serve` — the serving verb (Phase R3 task 13). Upstream
//! `runCentralServe` composes `openServeDeps` + `kernel.Config` and
//! runs the supervised profile until an intentional stop or a
//! terminal failure; the Rust verb loads
//! [`central_kernel::serve::ServeConfig`], composes
//! [`central_kernel::serve::compose_serve`], and drives the profile
//! on a multi-thread tokio runtime until SIGINT/SIGTERM.
//!
//! Exactly one `central.local-result/v1` envelope is emitted per
//! invocation — on the refusal path before the profile starts
//! (configuration/dependency), or once when the profile exits. A
//! write failure fails closed at exit `6`, the same rule every verb
//! shares.

use std::io::Write;

use central_foundation::failure::ExitClass;
use central_foundation::local_result::LocalResult;
use central_kernel::serve::{ServeConfig, compose_serve};

/// The verb entry point — owns its tokio runtime like every other
/// landed verb (`artifact_cli`/`checkpoint_cli` pattern, except serve
/// wants `rt-multi-thread` for the two listeners).
pub fn serve(_tokens: &[String], stdout: &mut impl Write, stderr: &mut impl Write) -> u8 {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            return emit(
                "serve",
                stdout,
                stderr,
                ExitClass::Terminal,
                Some("SERVE_RUNTIME_UNAVAILABLE"),
                Some(serde_json::json!({ "detail": e.to_string() })),
            );
        }
    };
    let result = runtime.block_on(run_serve());
    match result {
        Ok(()) => emit("serve", stdout, stderr, ExitClass::Success, None, None),
        Err(err) => emit(
            "serve",
            stdout,
            stderr,
            err.class(),
            Some(err.reason()),
            Some(serde_json::json!({ "remediation": err.remediation() })),
        ),
    }
}

/// Composes and runs the profile until SIGINT or SIGTERM — the
/// upstream signal-relay stop.
async fn run_serve() -> Result<(), central_kernel::lifecycle::ExitError> {
    let config = ServeConfig::from_env()?;
    let mut composition = compose_serve(&config).await?;
    composition.profile.run(stop_signal()).await
}

/// `Signals` — first of SIGINT or SIGTERM resolves the stop future.
async fn stop_signal() {
    let sigint = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    let sigterm = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            let _ = s.recv().await;
        } else {
            std::future::pending::<()>().await;
        }
    };
    tokio::select! {
        () = sigint => {},
        () = sigterm => {},
    }
}

/// Emits the single result envelope; a write failure collapses to
/// exit `6` (upstream `cli.ResultExitCode`).
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
        Err(_) => {
            let _ = writeln!(stderr, "central: could not write result envelope");
            ExitClass::Terminal.code()
        }
    }
}
