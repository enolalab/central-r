//! Shared leaf helpers for the task stores: row shapes, row→domain
//! reconstruction, the `input_spec` JSONB codec, and the command
//! receipt fingerprint/expectation encodings.
//!
//! `internal/adapter/postgres/task/queries.go` declares the SQL text;
//! here every statement sits inline at its `sqlx::query!` /
//! `query_as!` call site (the compile-checked macros require string
//! literals), so this module carries the shared *row* contract the
//! statements all scan into. Every task-statement SELECT projects the
//! upstream `scanTask` column list; every run-statement SELECT
//! projects `scanRun`.

use central_foundation::failure::Failure;
use central_foundation::identity::{RunId, TaskId, WorkspaceId};
use central_task::domain::{
    Budget, PermissionPolicy, Run, RunStatus, Task, TaskChangeSet, TaskEventIntent, TaskStatus,
    WaitingReason,
};
use sha2::Digest;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::store_support::PG_DATA_CORRUPT;

fn corrupt(what: &'static str) -> Failure {
    Failure::internal(PG_DATA_CORRUPT, what)
}

/// One `central.tasks` row — the upstream `scanTask` column list,
/// except the uuid columns decode as `uuid`, not `::text`.
pub(crate) struct TaskRow {
    pub id: uuid::Uuid,
    pub workspace_id: uuid::Uuid,
    pub version: i64,
    pub status: String,
    pub current_run_id: Option<uuid::Uuid>,
    pub last_run_index: i64,
    pub retry_count: i64,
    pub retry_eligible_at: Option<OffsetDateTime>,
    pub waiting_reason: String,
    pub failure_reason: String,
    pub input_spec: String,
    pub title: String,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub parent_task_id: Option<uuid::Uuid>,
    pub permission_policy: String,
    pub budget_cost_micro_usd: i64,
    pub budget_wall_clock_seconds: i32,
}

/// One `central.runs` row — the upstream `scanRun` column list.
pub(crate) struct RunRow {
    pub id: uuid::Uuid,
    pub workspace_id: uuid::Uuid,
    pub task_id: uuid::Uuid,
    pub version: i64,
    pub status: String,
    pub run_index: i64,
    pub waiting_reason: String,
    pub failure_reason: String,
    pub ownership_token: String,
    pub run_key: Option<String>,
    pub request_fingerprint: Option<Vec<u8>>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// `decodeTaskInput` — the inverse of [`encode_task_input`]: a JSON
/// string scalar unwraps; anything else returns the raw `jsonb::text`.
pub(crate) fn decode_task_input(raw: &str) -> String {
    serde_json::from_str::<String>(raw).unwrap_or_else(|_| raw.to_owned())
}

/// `encodeTaskInput` — the conditional wrap migration v21 documents:
/// a JSON document that is not a bare string is stored verbatim;
/// every other payload is stored as a JSON string scalar so the
/// `jsonb` column accepts it and [`decode_task_input`] unwraps it.
pub(crate) fn encode_task_input(input: &str) -> String {
    if serde_json::from_str::<serde_json::Value>(input).is_ok_and(|v| !v.is_string()) {
        return input.to_owned();
    }
    serde_json::to_string(input).unwrap_or_else(|_| "\"\"".to_owned())
}

pub(crate) fn waiting_reason_of(text: &str) -> Result<Option<WaitingReason>, Failure> {
    if text.is_empty() {
        return Ok(None);
    }
    WaitingReason::parse(text)
        .map(Some)
        .map_err(|_| corrupt("a stored waiting_reason is outside the domain vocabulary"))
}

/// `scanTask` → domain [`Task`]; drifted vocabularies are
/// `pg_data_corrupt`, never a caller failure.
pub(crate) fn task_from_row(row: TaskRow) -> Result<Task, Failure> {
    let policy = PermissionPolicy::parse(&row.permission_policy);
    if !policy.known() {
        return Err(corrupt(
            "a stored permission_policy is outside the declared vocabulary",
        ));
    }
    let budget = Budget {
        cost_micro_usd: row.budget_cost_micro_usd,
        wall_clock_seconds: row.budget_wall_clock_seconds,
    };
    if budget.validate().is_err() {
        return Err(corrupt("a stored task budget fails domain validation"));
    }
    Ok(Task {
        id: TaskId::from_trusted_db_bytes(*row.id.as_bytes()),
        workspace_id: WorkspaceId::from_trusted_db_bytes(*row.workspace_id.as_bytes()),
        version: row.version,
        status: TaskStatus::parse(&row.status)
            .map_err(|_| corrupt("a stored task status is outside the domain vocabulary"))?,
        current_run_id: row
            .current_run_id
            .map(|u| RunId::from_trusted_db_bytes(*u.as_bytes())),
        parent_task_id: row
            .parent_task_id
            .map(|u| TaskId::from_trusted_db_bytes(*u.as_bytes())),
        last_run_index: row.last_run_index,
        retry_count: row.retry_count,
        retry_eligible_at: row.retry_eligible_at,
        waiting_reason: waiting_reason_of(&row.waiting_reason)?,
        failure_reason: row.failure_reason,
        input: decode_task_input(&row.input_spec),
        title: row.title,
        permission_policy: policy,
        budget,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

/// `scanRun` → domain [`Run`].
pub(crate) fn run_from_row(row: RunRow) -> Result<Run, Failure> {
    let request_fingerprint = row
        .request_fingerprint
        .map(|bytes| {
            <[u8; 32]>::try_from(bytes.as_slice())
                .map_err(|_| corrupt("a stored request_fingerprint is not 32 bytes"))
        })
        .transpose()?;
    Ok(Run {
        id: RunId::from_trusted_db_bytes(*row.id.as_bytes()),
        task_id: TaskId::from_trusted_db_bytes(*row.task_id.as_bytes()),
        workspace_id: WorkspaceId::from_trusted_db_bytes(*row.workspace_id.as_bytes()),
        version: row.version,
        status: RunStatus::parse(&row.status)
            .map_err(|_| corrupt("a stored run status is outside the domain vocabulary"))?,
        index: row.run_index,
        waiting_reason: waiting_reason_of(&row.waiting_reason)?,
        failure_reason: row.failure_reason,
        ownership_token: row.ownership_token,
        run_key: row.run_key,
        request_fingerprint,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

/// `waitingReasonValue` — `None` writes `''` (upstream's sentinel; the
/// column is `text NULL` and `COALESCE(..., '')` reads it back).
pub(crate) fn waiting_reason_value(reason: Option<WaitingReason>) -> &'static str {
    reason.map_or("", WaitingReason::as_str)
}

// ---------------------------------------------------------------------------
// Command receipt fingerprints (upstream commandInputFingerprint /
// expectedAggregateVersions — the same canonical JSON shape).
// ---------------------------------------------------------------------------

/// Formats an instant the way Go's `json.Marshal(time.Time)` renders
/// it: RFC 3339 with up to nine fractional digits (trailing zeros
/// trimmed) and `Z` for UTC. Upstream fingerprints marshal
/// `RetryEligibleAt` directly; the domain's `Option` uses `None` for
/// Go's zero `time.Time` (`"0001-01-01T00:00:00Z"`).
fn go_rfc3339(t: OffsetDateTime) -> String {
    let t = t.to_offset(time::UtcOffset::UTC);
    let base = t
        .format(&Rfc3339)
        .unwrap_or_default()
        .replace("+00:00", "Z");
    // `format(&Rfc3339)` emits whole-second precision; when the
    // instant carries sub-second precision Go appends the fraction.
    let nanos = t.nanosecond();
    if nanos == 0 {
        return base;
    }
    let mut frac = format!("{nanos:09}");
    while frac.ends_with('0') {
        frac.pop();
    }
    base.replace('Z', &format!(".{frac}Z"))
}

fn go_rfc3339_opt(t: Option<OffsetDateTime>) -> String {
    t.map_or_else(|| "0001-01-01T00:00:00Z".to_owned(), go_rfc3339)
}

/// `commandInputFingerprint` — the SHA-256 of the canonical change-set
/// summary a `(workspace, scope, key)` receipt compares on replay.
pub(crate) fn command_input_fingerprint(change_set: &TaskChangeSet) -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct RunFingerprint {
        id: String,
        v: i64,
        s: String,
        i: i64,
    }
    #[derive(serde::Serialize)]
    struct TaskFingerprint {
        v: i64,
        s: String,
        rc: i64,
        re: String,
    }
    #[derive(serde::Serialize)]
    struct Payload {
        task_id: String,
        workspace: String,
        task: TaskFingerprint,
        runs: Vec<RunFingerprint>,
    }
    let mut runs: Vec<RunFingerprint> = change_set
        .runs
        .iter()
        .map(|r| RunFingerprint {
            id: r.id.to_string(),
            v: r.version,
            s: r.status.as_str().to_owned(),
            i: r.index,
        })
        .collect();
    // Upstream sorts by the canonical uuid text; RunId's `Ord` is the
    // same lexicographic byte order.
    runs.sort_by(|a, b| a.id.cmp(&b.id));
    let payload = Payload {
        task_id: change_set.task.id.to_string(),
        workspace: change_set.task.workspace_id.to_string(),
        task: TaskFingerprint {
            v: change_set.task.version,
            s: change_set.task.status.as_str().to_owned(),
            rc: change_set.task.retry_count,
            re: go_rfc3339_opt(change_set.task.retry_eligible_at),
        },
        runs,
    };
    let bytes = serde_json::to_vec(&payload).unwrap_or_default();
    sha2::Sha256::digest(&bytes).to_vec()
}

/// `expectedAggregateVersions` — the stored JSON record of the CAS
/// guards a receipt replay must satisfy.
pub(crate) fn expected_aggregate_versions(change_set: &TaskChangeSet) -> serde_json::Value {
    let mut runs: Vec<serde_json::Value> = change_set
        .run_expected_versions
        .iter()
        .map(|(id, version)| serde_json::json!({"id": id.to_string(), "v": version}))
        .collect();
    runs.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    serde_json::json!({
        "task": change_set.expected_task_version,
        "runs": runs,
    })
}

// ---------------------------------------------------------------------------
// Task event intent payloads (upstream `json.Marshal(evt)` — PascalCase
// keys, the shape the Go writer stamps into central.events.payload).
// ---------------------------------------------------------------------------

/// Marshals one event intent into the stored payload envelope —
/// `{"Kind","TaskID","RunID","Reason","Detail","OccurredAt"}` matching
/// the Go `json.Marshal(TaskEventIntent)` field names.
pub(crate) fn event_intent_payload(intent: &TaskEventIntent) -> serde_json::Value {
    let run_id = intent.run_id.map_or_else(
        || "00000000-0000-0000-0000-000000000000".to_owned(),
        |r| r.to_string(),
    );
    serde_json::json!({
        "Kind": intent.kind.as_str(),
        "TaskID": intent.task_id.to_string(),
        "RunID": run_id,
        "Reason": intent.reason.map_or("", WaitingReason::as_str),
        "Detail": intent.detail,
        "OccurredAt": go_rfc3339(intent.occurred_at),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_input_codec_round_trips() {
        // A JSON document is stored verbatim and decodes unchanged.
        assert_eq!(encode_task_input("{\"a\":1}"), "{\"a\":1}");
        assert_eq!(decode_task_input("{\"a\":1}"), "{\"a\":1}");
        // A bare string / JSON-string document is stored as a scalar
        // and unwraps on read.
        assert_eq!(encode_task_input("in.yaml"), "\"in.yaml\"");
        assert_eq!(decode_task_input("\"in.yaml\""), "in.yaml");
        assert_eq!(
            decode_task_input(&encode_task_input("\"quoted\"")),
            "\"quoted\""
        );
    }
}
