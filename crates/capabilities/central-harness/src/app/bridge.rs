//! The permission bridge's shared machinery — the port of
//! `internal/harness/app/bridge.go`: the serve-memory approval registry
//! (the request input and the wake-up signal of every open bridged
//! request), the queue bookkeeping, and the bounded `decided_by`
//! vocabulary. The attempt-side bridge methods that drive one session
//! live in `super::orchestrator`'s `impl AttemptRun`.
//!
//! The registry never persists or prints an input — it exists so the
//! operator's page can be rendered and so a landed decision can wake
//! the attempt that waits for it (3c decisions 5, 8, 13).

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Poll, Waker};

use central_foundation::failure::Failure;
use central_foundation::identity::{HarnessAttemptId, HarnessPermissionApprovalId, WorkspaceId};
use time::Duration;

use crate::approval::{PermissionApproval, is_operator_decider};
use crate::event::PermissionRequested;
use crate::port::PortFuture;

/// `app.DecidedByPolicyDeny` — the `decided_by` of the orchestrator's
/// automatic deny answer under the Deny policy.
pub const DECIDED_BY_POLICY_DENY: &str = "policy:deny";

/// `app.DefaultApprovalTimeout` — a bridged request expires this long
/// after it was requested.
pub const DEFAULT_APPROVAL_TIMEOUT: Duration = Duration::seconds(10 * 60);
/// `app.DefaultApprovalRecheck` — the approval row is re-read at most
/// this often; the signal wakes a decision earlier.
pub const DEFAULT_APPROVAL_RECHECK: Duration = Duration::seconds(2);
/// `app.MaxQueuedPermissions` — the bound on requests queued behind the
/// pending one; the next one fails the attempt closed (3c decision 4).
pub const MAX_QUEUED_PERMISSIONS: usize = 16;

/// `decidedByCode` — the bounded milestone reason of a permission
/// answer's `decided_by` (decision 14): one of a fixed set of codes,
/// never text the harness reported.
#[must_use]
pub fn decided_by_code(decided_by: &str) -> &'static str {
    if is_operator_decider(decided_by) {
        "operator"
    } else {
        match decided_by {
            crate::approval::DECIDED_BY_TIMEOUT => "timeout",
            crate::approval::DECIDED_BY_INPUT_TOO_LARGE => "input_too_large",
            DECIDED_BY_POLICY_DENY => "deny",
            _ => "policy",
        }
    }
}

/// `errBridgeUnavailable` — wraps an error so the bridge's caller maps
/// it to `PERMISSION_BRIDGE_UNAVAILABLE` (fail closed, decision 10).
pub(crate) fn bridge_failure(e: Failure) -> Failure {
    Failure::new(
        e.kind(),
        super::ports::codes::BRIDGE_UNAVAILABLE,
        e.message(),
    )
}

/// `bridgeFailure` for a fresh message — `fmt.Errorf("%w: msg")`.
pub(crate) fn bridge_failure_msg(message: impl Into<String>) -> Failure {
    Failure::internal(super::ports::codes::BRIDGE_UNAVAILABLE, message.into())
}

/// A cell that parks `wait()` futures until `notify()` — the Rust form
/// of the upstream's `signal chan struct{}` (buffered 1): `notify` is
/// `signal <- struct{}{}` (non-blocking, remembered), `wait` is
/// `<-signal`.
#[derive(Debug)]
pub(crate) struct SignalCell {
    state: Mutex<SignalState>,
}

#[derive(Debug, Default)]
struct SignalState {
    notified: bool,
    wakers: Vec<Waker>,
}

impl SignalCell {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(SignalState::default()),
        })
    }

    /// `signal <- struct{}{}` — wakes every parked waiter and every
    /// future `wait()` on this cell (a buffered signal is remembered).
    pub(crate) fn notify(&self) {
        let wakers = {
            let mut st = match self.state.lock() {
                Ok(st) => st,
                Err(poisoned) => poisoned.into_inner(),
            };
            if st.notified {
                return;
            }
            st.notified = true;
            std::mem::take(&mut st.wakers)
        };
        for w in wakers {
            w.wake();
        }
    }

    /// `<-signal` — resolves once `notify` ran (immediately if it did).
    pub(crate) fn wait(self: &Arc<Self>) -> PortFuture<'static, ()> {
        let cell = Arc::clone(self);
        Box::pin(std::future::poll_fn(move |cx| {
            let mut st = match cell.state.lock() {
                Ok(st) => st,
                Err(poisoned) => poisoned.into_inner(),
            };
            if st.notified {
                Poll::Ready(())
            } else {
                st.wakers.push(cx.waker().clone());
                Poll::Pending
            }
        }))
    }
}

/// `approvalEntry` — one open bridged request held in serve memory:
/// the input and resources the operator is shown (never persisted or
/// logged) and the decision's wake-up.
pub(crate) struct ApprovalEntry {
    /// The owning workspace (`lookup`/`signal` scope to it).
    pub workspace: WorkspaceId,
    /// The attempt that asked.
    pub attempt: HarnessAttemptId,
    /// The request input — never printed or persisted.
    pub input: Vec<u8>,
    /// The resources the harness named — never printed.
    pub resources: Vec<String>,
    /// The decision signal.
    pub signal: Arc<SignalCell>,
}

impl fmt::Debug for ApprovalEntry {
    /// `String`/`GoString`: never the input or the resources.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "app.approvalEntry{{Attempt:{} Input:<redacted {} bytes> Resources:<redacted {}>}}",
            self.attempt,
            self.input.len(),
            self.resources.len()
        )
    }
}

/// `approvalRegistry` — serve memory only: the tool input of every
/// bridged request whose approval is open (decisions 5 and 13), and the
/// signal that wakes the drive loop waiting on it (decision 8). Entries
/// are dropped once their request is answered, and all of an attempt's
/// when its orchestration ends.
#[derive(Debug, Default, Clone)]
pub struct ApprovalRegistry {
    entries: Arc<Mutex<HashMap<HarnessPermissionApprovalId, Arc<ApprovalEntry>>>>,
}

impl ApprovalRegistry {
    /// `add` — registers `a`'s request with its input and resources;
    /// returns the decision signal for the drive loop's arm.
    pub(crate) fn add(
        &self,
        a: &PermissionApproval,
        input: &[u8],
        resources: &[String],
    ) -> Arc<SignalCell> {
        let entry = Arc::new(ApprovalEntry {
            workspace: a.workspace_id,
            attempt: a.attempt_id,
            input: input.to_vec(),
            resources: resources.to_vec(),
            signal: SignalCell::new(),
        });
        let signal = entry.signal.clone();
        if let Ok(mut entries) = self.entries.lock() {
            entries.insert(a.id, entry);
        }
        signal
    }

    /// `drop` — forgets `id` (a waiter's cell stays unnotified; the
    /// recheck is the fallback, as upstream's drop is a plain delete).
    pub(crate) fn drop(&self, id: HarnessPermissionApprovalId) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.remove(&id);
        }
    }

    /// `dropAttempt` — forgets every entry of `attempt` (`stopAnswering`,
    /// `dropBridge`).
    pub(crate) fn drop_attempt(&self, attempt: HarnessAttemptId) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.retain(|_, e| e.attempt != attempt);
        }
    }

    /// `lookup` — the entry of `id` scoped to `ws`.
    fn lookup(
        &self,
        ws: WorkspaceId,
        id: HarnessPermissionApprovalId,
    ) -> Option<Arc<ApprovalEntry>> {
        let entries = self.entries.lock().ok()?;
        entries.get(&id).filter(|e| e.workspace == ws).cloned()
    }

    /// `PendingRequest` — what the operator is shown of an open approval
    /// this process bridges (decision 13).
    pub fn pending_request(
        &self,
        ws: WorkspaceId,
        id: HarnessPermissionApprovalId,
    ) -> Option<PendingRequest> {
        self.lookup(ws, id).map(|e| PendingRequest {
            input: e.input.clone(),
            resources: e.resources.clone(),
        })
    }

    /// `SignalDecision` — wakes the drive loop waiting on `id` of `ws`
    /// once the operator's decision is durable. Returns whether a
    /// waiter was found; a lost signal only delays until the re-read.
    pub fn signal_decision(&self, ws: WorkspaceId, id: HarnessPermissionApprovalId) -> bool {
        match self.lookup(ws, id) {
            Some(e) => {
                e.signal.notify();
                true
            }
            None => false,
        }
    }

    /// `len` — for tests.
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.entries.lock().map(|e| e.len()).unwrap_or(0)
    }
}

/// `PendingRequest` — what the operator is shown of an open approval
/// (decision 13): the tool input and the resources the harness named;
/// held in memory only, never printed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRequest {
    /// The request input — never printed.
    pub input: Vec<u8>,
    /// The resources — never printed.
    pub resources: Vec<String>,
}

impl fmt::Display for PendingRequest {
    /// `String`/`GoString`: never the input or the resources.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "app.PendingRequest{{Input:<redacted {} bytes> Resources:<redacted {}>}}",
            self.input.len(),
            self.resources.len()
        )
    }
}

/// `openApproval` — the attempt's pending approval: the head of its
/// queue. `expiry` lives on the drive arms in this port.
#[derive(Debug)]
pub(crate) struct OpenApproval {
    /// The durable approval row.
    pub approval: PermissionApproval,
    /// The full request input — needed to bind an allow; never
    /// persisted or printed.
    pub input: Vec<u8>,
    /// The wake-up cell — `None` while the Run is stopping (no decision
    /// may then be taken, so no waiter is registered). Read by tests
    /// asserting the registered waiter; the drive loop's arm lives on
    /// the orchestrator's `DriveArms`.
    #[allow(dead_code)]
    pub signal: Option<Arc<SignalCell>>,
    /// `answered` — `RespondPermission` accepted the answer (or the
    /// session is over); the `PermissionResolved` event closes it.
    pub answered: bool,
}

/// `bridge` — one attempt's permission bridge state (decision 7): at
/// most one open approval, and a FIFO queue of requests behind it.
#[derive(Debug, Default)]
pub(crate) struct BridgeState {
    /// The open request.
    pub open: Option<OpenApproval>,
    /// The requests waiting behind the open one.
    pub queue: VecDeque<PermissionRequested>,
    /// How many approvals this attempt opened (tests assert the bound).
    pub opened: AtomicUsize,
}

impl BridgeState {
    /// `stopping` lives on `AttemptRun` (it consults cancel/budget
    /// state); this reports only the queue side.
    pub(crate) fn queue_len(&self) -> usize {
        self.queue.len()
    }

    /// `closeOpen` — forget the open approval (its request resolved).
    pub(crate) fn close_open(&mut self) -> Option<OpenApproval> {
        self.open.take()
    }

    /// `dropBridge` — forget everything (the orchestration ended).
    /// Reserved for the ported bridge tests.
    #[allow(dead_code)]
    pub(crate) fn drop_all(&mut self) -> Vec<HarnessPermissionApprovalId> {
        let mut ids = Vec::new();
        if let Some(open) = self.open.take() {
            ids.push(open.approval.id);
        }
        self.queue.clear();
        ids
    }

    /// Opened-approval count (the bound's counter, for tests).
    #[allow(dead_code)]
    pub(crate) fn opened_count(&self) -> usize {
        self.opened.load(Ordering::Relaxed)
    }
}
