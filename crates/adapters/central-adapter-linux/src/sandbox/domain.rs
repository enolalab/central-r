//! `domain.go` — the request/evidence wire shapes. JSON field order in
//! [`LaunchEvidence`] follows upstream's struct declaration order (Go
//! marshals struct fields in declaration order); the response map the
//! daemon writes is alphabetical, as Go map keys marshal.
//!
//! Wire contract change vs upstream (`workspace_root_fd`): upstream
//! carries a numeric fd field in the JSON that the Linux launcher
//! never reads. The port is descriptor-bound (A06): the workspace
//! root arrives as the request frame's one `SCM_RIGHTS` descriptor —
//! no numeric field exists, so [`LaunchRequest`] pins
//! `deny_unknown_fields` to keep a forged `workspace_root_fd` (or any
//! other invented field) a named refusal instead of a silently
//! ignored override.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// `LaunchRequest` — one sandboxed launch. The workspace root is *not*
/// a field: it is the frame's attached descriptor (see module docs).
///
/// `env` stays a declared field so the denial can name it — a request
/// that sets it is refused by the daemon (environment injection is a
/// denied ambient-authority route, A06); upstream passes it to
/// `cmd.Env` unchecked, which is exactly the route the refusal closes.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchRequest {
    /// The caller's operation identity for the evidence record.
    #[serde(default)]
    pub operation_id: String,
    /// `exec.CommandContext`'s first argument — a closed class name
    /// (`central-agent`), never a path. The launcher resolves it.
    pub exec_binary: String,
    /// argv past argv[0].
    #[serde(default)]
    pub args: Vec<String>,
    /// Upstream's `cmd.Env` — must be absent or empty: caller-supplied
    /// environment is a denied ambient-authority route.
    #[serde(default)]
    pub env: Vec<String>,
    /// The requested resource envelope (zero fields mean "hard cap",
    /// upstream's convention).
    #[serde(default)]
    pub resource_limits: ResourceLimits,
    /// `deadline_ms` — Go serializes `time.Duration` as its int64
    /// nanosecond count, so despite the suffix the wire value is
    /// nanoseconds. `0` means the daemon's default deadline.
    #[serde(default)]
    pub deadline_ms: i64,
}

/// `ResourceLimits` — hard upper bounds on the sandbox's resources.
/// `cpu`, `memory_bytes` and `max_processes` are the cgroup-backed
/// fields; `max_file_descriptors` is installed as `RLIMIT_NOFILE`
/// (upstream validates it but never applies it — the port applies it).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    /// CPU cores (fractional); `cpu.max` is written as
    /// `"<cpu*100000> 100000"`.
    #[serde(default)]
    pub cpu: f64,
    /// Memory ceiling in bytes; `memory.max`.
    #[serde(default)]
    pub memory_bytes: i64,
    /// Process count ceiling; `pids.max`.
    #[serde(default)]
    pub max_processes: i32,
    /// Descriptor ceiling; `RLIMIT_NOFILE` in the child.
    #[serde(default)]
    pub max_file_descriptors: i32,
}

/// `LaunchEvidence` — the durable record: operation id, pid, the
/// limits actually applied, start/settle timestamps, exit code/class,
/// and the cleanup result. Field order is upstream's declaration
/// order — Go marshals struct fields in declaration order, so the
/// JSON a reader sees is byte-ordered identically.
#[derive(Debug, Clone, Serialize)]
pub struct LaunchEvidence {
    /// The request's operation id, echoed.
    pub operation_id: String,
    /// The spawned pid (in the launcher's namespace).
    pub pid: i32,
    /// The envelope the launch was admitted under.
    pub resource_limits: ResourceLimits,
    /// RFC 3339 start time (Go's `time.Time` marshal).
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    /// RFC 3339 settle time — `omitempty` like upstream's `*time.Time`.
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub settled_at: Option<OffsetDateTime>,
    /// The process's exit code — `omitempty` (upstream leaves it nil
    /// on the deadline arm).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// `normal` | `error` | `deadline` — upstream's `ExitClass`.
    pub exit_class: String,
    /// `clean` | `unclean` — upstream hard-codes `clean`; the port
    /// reports `unclean` when the cgroup subtree refused removal.
    pub cleanup_result: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The request's closed schema: the upstream numeric
    /// `workspace_root_fd` field — and any other invented key — is a
    /// named refusal, never a silently ignored override.
    #[test]
    fn request_rejects_unknown_fields() {
        let err = serde_json::from_str::<LaunchRequest>(
            r#"{"exec_binary":"central-agent","workspace_root_fd":7}"#,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("unknown field"),
            "want unknown-field refusal, got: {err}"
        );
    }

    /// The declared schema parses with defaults — `env`/`args`/limits
    /// absent, the descriptor doing the workspace binding off-band.
    #[test]
    fn request_parses_declared_fields() {
        let req = serde_json::from_str::<LaunchRequest>(
            r#"{"operation_id":"op-1","exec_binary":"central-agent",
                "args":["--task","t1"],"deadline_ms":30000000000}"#,
        )
        .expect("parse");
        assert_eq!(req.operation_id, "op-1");
        assert_eq!(req.exec_binary, "central-agent");
        assert_eq!(req.args, ["--task", "t1"]);
        assert!(req.env.is_empty());
        assert_eq!(req.deadline_ms, 30_000_000_000);
    }

    /// Evidence marshals in upstream declaration order with
    /// `omitempty` semantics — the deadline arm's absent `exit_code`
    /// and the always-present `settled_at` after settlement.
    #[test]
    fn evidence_marshals_upstream_shape() {
        let ev = LaunchEvidence {
            operation_id: "op-1".to_owned(),
            pid: 1234,
            resource_limits: ResourceLimits {
                cpu: 0.5,
                memory_bytes: 256 << 20,
                max_processes: 32,
                max_file_descriptors: 64,
            },
            started_at: time::OffsetDateTime::UNIX_EPOCH,
            settled_at: Some(time::OffsetDateTime::UNIX_EPOCH),
            exit_code: None,
            exit_class: "deadline".to_owned(),
            cleanup_result: "clean".to_owned(),
        };
        let json = serde_json::to_string(&ev).expect("marshal");
        // Go struct order: operation_id, pid, resource_limits,
        // started_at, settled_at, exit_code, exit_class, cleanup_result
        // — exit_code omitted per upstream's nil-pointer omitempty.
        let order: Vec<&str> = [
            "operation_id",
            "pid",
            "resource_limits",
            "started_at",
            "settled_at",
            "exit_class",
            "cleanup_result",
        ]
        .into_iter()
        .collect();
        let positions: Vec<usize> = order
            .iter()
            .map(|k| json.find(&format!("\"{k}\"")).expect("field present"))
            .collect();
        assert!(positions.windows(2).all(|w| w[0] < w[1]), "{json}");
        assert!(!json.contains("exit_code"), "deadline arm omits exit_code");
    }
}
