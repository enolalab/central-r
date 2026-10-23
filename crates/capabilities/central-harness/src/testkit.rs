//! Test helpers shared by the ported upstream `internal/harness` suites:
//! the fixed clock bases, the shared execution-lease fence, the canonical
//! `prepareInput`, the default effective budget, the digest/MAC keys, the
//! unsafe-free immediate-ready `block_on` for `#[trait_variant]` futures,
//! and nil-identity constructors standing in for Go zero values.

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use central_foundation::failure::Failure;
use central_foundation::identity::{
    HarnessAttemptId, HarnessPermissionApprovalId, RunId, StepAttemptId, TaskId, WorkspaceId,
};
use time::macros::datetime;
use time::{Duration, OffsetDateTime};

use crate::approval::{self, PermissionApproval};
use crate::attempt::{Attempt, PrepareInput};
use crate::budget::Budget;
use crate::domain::{Fence, Kind, PermissionPolicy, Workspace};

/// The fixed clock base the upstream suites share (`t0`).
pub(crate) fn t0() -> OffsetDateTime {
    datetime!(2026-09-27 10:00:00 UTC)
}

/// The approval suite's clock base (`approvalT0`).
pub(crate) fn approval_t0() -> OffsetDateTime {
    datetime!(2026-09-29 10:00:00 UTC)
}

/// The fence the upstream suites share (`fence`).
pub(crate) const FENCE: Fence = Fence { generation: 1 };

/// The default effective budget (`testBudget`).
pub(crate) fn test_budget() -> Budget {
    Budget {
        cost_micro_usd: 2_500_000,
        wall_clock: Duration::minutes(10),
        cost_defaulted: false,
        wall_clock_defaulted: true,
    }
}

/// The digest key the event-record tests share (`testDigestKey`).
pub(crate) const TEST_DIGEST_KEY: &[u8] = b"event-test-digest-key-0123456789";

/// The shared workspace id of upstream's package-level `workspaceID`
/// var (`identity.NewWorkspaceID()` evaluated once): every
/// `prepare_input()` call carries it, so an input copies `prev`'s
/// linkage by construction. A fixed valid UUIDv7 — version nibble `7`
/// at byte 6, RFC 9562 variant bits `10` at byte 8.
pub(crate) const WORKSPACE_ID: WorkspaceId = WorkspaceId::from_trusted_db_bytes([
    0x01, 0x9a, 0x3c, 0x5e, 0x9b, 0x0e, 0x7f, 0x3a, 0x9b, 0x0e, 0x9b, 0x0e, 0x9b, 0x0e, 0x9b, 0x0e,
]);

/// The approval suite's MAC key (`testMACKey`).
pub(crate) fn test_mac_key() -> &'static [u8] {
    b"0123456789abcdef0123456789abcdef"
}

/// Unwraps a mutator result, failing the test on error — upstream's
/// `ok(t)(a.Launch(...))`.
pub(crate) fn ok<T>(r: Result<T, Failure>) -> T {
    r.unwrap()
}

/// Drives an immediate-ready `#[trait_variant]`-style future to
/// completion on the calling thread. Contract fakes never park: a
/// `Poll::Pending` just yields and polls again. Unsafe-free — the same
/// shape `central-retry`'s testkit uses.
pub(crate) fn block_on<F: Future>(future: F) -> F::Output {
    let mut context = Context::from_waker(Waker::noop());
    let mut future = pin!(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

/// A canonical `prepareInput` (`identity.New*` → `*Id::new()`).
pub(crate) fn prepare_input() -> PrepareInput {
    PrepareInput {
        id: HarnessAttemptId::new(),
        workspace_id: WORKSPACE_ID,
        run_id: RunId::new(),
        kind: Kind::new("claude-code"),
        adapter_version: "0.1.0".to_string(),
        workspace: Workspace {
            path: "/srv/central/worktrees/r1".to_string(),
            base_sha: "abc123".to_string(),
        },
        permission: PermissionPolicy::Bridge,
        fence: FENCE,
        budget: test_budget(),
        at: t0(),
    }
}

/// A prepared → launched → session-revealed running attempt
/// (`running(t)`).
pub(crate) fn running() -> Attempt {
    let a = ok(Attempt::prepare(prepare_input()));
    let a = ok(a.launch(FENCE, "scope-1", "2.1.0", t0()));
    ok(a.reveal_session(FENCE, "sess-1", t0()))
}

/// A structurally zero attempt (`harness.Attempt{}` in the upstream
/// suites) for struct-update literals in the budget tests — the zero
/// value never validates.
pub(crate) fn bare_attempt() -> Attempt {
    Attempt {
        id: HarnessAttemptId::from_trusted_db_bytes([0; 16]),
        workspace_id: WorkspaceId::from_trusted_db_bytes([0; 16]),
        run_id: RunId::from_trusted_db_bytes([0; 16]),
        kind: Kind::new(""),
        adapter_version: String::new(),
        harness_version: String::new(),
        harness_session_id: String::new(),
        resume_of: None,
        resume_session_id: String::new(),
        workspace: Workspace {
            path: String::new(),
            base_sha: String::new(),
        },
        permission: PermissionPolicy::Unset,
        sandbox_scope_id: String::new(),
        fence: Fence { generation: 0 },
        version: 0,
        state: crate::domain::State::Unset,
        pending_permission: String::new(),
        terminal: crate::domain::Terminal::default(),
        resolution: crate::domain::Resolution::default(),
        ambiguity_reason: String::new(),
        last_event_seq: 0,
        usage: crate::event::Usage::default(),
        budget: Budget {
            cost_micro_usd: 0,
            wall_clock: Duration::ZERO,
            cost_defaulted: false,
            wall_clock_defaulted: false,
        },
        prepared_at: crate::domain::ZERO_TIME,
        updated_at: crate::domain::ZERO_TIME,
        ended_at: None,
    }
}

/// A pending approval on fresh identities (`pendingApproval(t)`).
pub(crate) fn pending_approval() -> PermissionApproval {
    let mac = ok(approval::compute_input_mac(
        test_mac_key(),
        b"{\"command\":\"ls\"}",
    ));
    ok(PermissionApproval::open(approval::OpenApprovalInput {
        id: HarnessPermissionApprovalId::new(),
        workspace_id: WorkspaceId::new(),
        attempt_id: HarnessAttemptId::new(),
        task_id: TaskId::new(),
        run_id: RunId::new(),
        request_id: "req-1".to_string(),
        tool_call_id: "toolu_1".to_string(),
        tool_name: "Bash".to_string(),
        input_mac: mac,
        input_size: 16,
        requested_at: approval_t0(),
        expires_at: approval_t0() + Duration::minutes(10),
    }))
}

/// The operator decider the approval suite uses (`operator(t)`).
pub(crate) fn operator() -> String {
    approval::operator_decider("principal-1").unwrap()
}

/// Nil `HarnessAttemptId` — the Go zero value `HarnessAttemptID{}`.
pub(crate) fn nil_attempt_id() -> HarnessAttemptId {
    HarnessAttemptId::from_trusted_db_bytes([0; 16])
}

/// Nil `HarnessPermissionApprovalId` — the Go zero value.
pub(crate) fn nil_approval_id() -> HarnessPermissionApprovalId {
    HarnessPermissionApprovalId::from_trusted_db_bytes([0; 16])
}

/// Nil `WorkspaceId` — the Go zero value.
pub(crate) fn nil_workspace_id() -> WorkspaceId {
    WorkspaceId::from_trusted_db_bytes([0; 16])
}

/// Nil `RunId` — the Go zero value.
pub(crate) fn nil_run_id() -> RunId {
    RunId::from_trusted_db_bytes([0; 16])
}

/// Nil `TaskId` — the Go zero value.
pub(crate) fn nil_task_id() -> TaskId {
    TaskId::from_trusted_db_bytes([0; 16])
}

/// Nil `StepAttemptId` — the Go zero value.
pub(crate) fn nil_step_attempt_id() -> StepAttemptId {
    StepAttemptId::from_trusted_db_bytes([0; 16])
}

/// Asserts a failure carries an upstream sentinel's machine code — the
/// `errors.Is(err, harness.ErrX)` port.
pub(crate) fn is_code(err: &Failure, code: &'static str) -> bool {
    err.code() == code
}

/// `(name, mutator)` case rows keep clippy's `type_complexity` quiet.
pub(crate) type Mutation<T> = (&'static str, fn(&mut T));

/// `(name, mutator)` rows for mutators returning `Result`s.
pub(crate) type FallibleMutation<'a, T> =
    (&'static str, &'a (dyn Fn(&T) -> Result<T, Failure> + 'a));
