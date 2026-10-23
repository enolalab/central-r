//! `session.go` — one live `agy` process. One reader task parses
//! bounded NDJSON frames from stdout; one writer task writes queued
//! lines to stdin in order (the prompt first, then `Send` user
//! events); events go through an unbounded in-order channel so the
//! reader never blocks on a slow event consumer. The channel is
//! drained only by reading it: callers must read until `None`
//! (port.Session.Events).
//!
//! Lock order matches upstream: `state` (mu), then `wq` (wmu). The
//! writer takes `wq` only and holds no lock while it writes, so a
//! harness that stops reading stdin blocks neither the reader nor
//! `Send`. `on_fail` callbacks run with no lock held.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};

use central_foundation::failure::{Failure, FailureKind};
use central_foundation::identity::HarnessAttemptId;
use central_harness::domain::{Terminal, TerminalStatus};
use central_harness::event::{
    Event, EventPayload, Message, MessageRole, SessionStarted, TerminalReported, ToolCall,
    ToolResult, UsageReport, Warning,
};
use central_harness::port::{
    OperatorInput, PermissionDecision, PortFuture, Process, Session, SessionRef,
};
use time::OffsetDateTime;
use tokio::sync::{Notify, mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::json::push_json_string;
use crate::process::{EXIT_GRACE, FrameReader, Outcome, Stream, drain_discard, wait_exit};

use super::protocol::{self, FrameKind, StepState, StepType, decode_frame};
use super::reasons;

/// Fixed texts the adapter emits; never harness text.
const WARN_UNRECOGNIZED: &str = "unrecognized harness message";
const WARN_MALFORMED: &str = "malformed harness frame";
const WARN_PROMPT_FAILED: &str = "delivering the prompt failed";

/// `ErrInterruptUnsupported` — `port.ErrUnsupported` upstream.
fn unsupported() -> Failure {
    Failure::new(
        FailureKind::Invalid,
        central_harness::port::codes::UNSUPPORTED,
        "antigravity: unsupported",
    )
}

/// `ErrSessionEnded` — `port.ErrSessionEnded` upstream: returned by
/// Send and Interrupt once the session has recorded its terminal.
fn session_ended() -> Failure {
    Failure::new(
        FailureKind::Invalid,
        central_harness::port::codes::SESSION_ENDED,
        "antigravity: session ended",
    )
}

/// `ErrNoPendingPermission` — `port.ErrNoPendingPermission` upstream.
fn no_pending_permission() -> Failure {
    Failure::new(
        FailureKind::Invalid,
        central_harness::port::codes::NO_PENDING_PERMISSION,
        "antigravity: no pending permission request",
    )
}

/// `sessionConfig` — everything a session needs that is fixed at open.
pub(crate) struct SessionCfg {
    pub attempt: HarnessAttemptId,
    /// `resumeID` — the id a resumed session must keep; `""` for a
    /// fresh session, whose first event reveals the id.
    pub resume_id: String,
    /// `probedVersion` — the version `SessionStarted` reports.
    pub probed_version: String,
    pub model: String,
}

/// `writeReq` — one line queued for stdin.
struct WriteReq {
    line: Vec<u8>,
    /// `done`, when set, receives the write's outcome.
    done: Option<oneshot::Sender<Result<(), Failure>>>,
    /// `on_fail`, when set, runs on a failed write with no lock held.
    on_fail: Option<Box<dyn FnOnce() + Send>>,
}

/// `pendingTool` — a tool step awaiting its terminal frame.
struct PendingTool {
    id: String,
}

/// The `mu` state — every field the upstream session mutates under
/// its one state mutex, in the same order.
struct State {
    seq: u64,
    session_id: String,
    revealed: bool,
    /// The recorded terminal of a `result` event.
    result: Option<Terminal>,
    result_raw: Vec<u8>,
    saw_result_err: bool,
    kill_requested: bool,
    stop_reason: Option<&'static str>,
    finished: bool,
    terminal: Terminal,
    /// `pending` — tool steps awaiting their terminal frame, by step
    /// index.
    pending: HashMap<i64, PendingTool>,
    /// `texts` — per-step text accumulators for buffered deltas.
    texts: HashMap<i64, String>,
    /// Adapter-initiated kills in flight.
    kills: Vec<JoinHandle<()>>,
    /// The event send half — `None` once the terminal event is queued.
    events_tx: Option<mpsc::UnboundedSender<Event>>,
    /// The ref send half — sent once on reveal, or dropped at finish
    /// when no id was ever revealed.
    ref_tx: Option<oneshot::Sender<SessionRef>>,
}

/// The `wmu` state — the stdin write queue.
struct WriteQueue {
    queue: VecDeque<WriteReq>,
    /// Popped by the writer, not yet written.
    inflight: usize,
    closed: bool,
}

/// The shared internals of one session.
struct Inner {
    cfg: SessionCfg,
    proc: Arc<dyn Process>,
    state: Mutex<State>,
    /// `wmu` + `wcond`: the write queue and its wakeup.
    wq: Mutex<WriteQueue>,
    wq_notify: Notify,
    events_rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<Event>>,
    /// One-shot `Ref()` — the first caller resolves it; later callers
    /// see the closed channel upstream would hand them.
    ref_rx: Mutex<Option<oneshot::Receiver<SessionRef>>>,
    writer_done: Mutex<Option<JoinHandle<()>>>,
    /// `done` — set once with the terminal.
    done: Outcome<Terminal>,
}

impl Inner {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn wq(&self) -> MutexGuard<'_, WriteQueue> {
        self.wq.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// `emit` — assigns the next sequence number and queues the event.
    /// Callers hold `state`, which is what keeps sequence order equal
    /// to channel order.
    fn emit_locked(&self, st: &mut State, payload: EventPayload, raw: &[u8]) {
        st.seq += 1;
        let e = Event {
            attempt: self.cfg.attempt,
            seq: st.seq,
            at: OffsetDateTime::now_utc(),
            harness_session_id: st.session_id.clone(),
            raw: raw.to_vec(),
            payload: Some(payload),
        };
        if let Some(tx) = st.events_tx.as_ref() {
            let _ = tx.send(e);
        }
    }

    fn warning(message: &'static str) -> EventPayload {
        EventPayload::Warning(Warning {
            message: message.to_string(),
        })
    }

    /// `ended` — whether no more input may be written. Callers hold
    /// `state`.
    fn ended_locked(st: &State) -> bool {
        st.finished || st.result.is_some() || st.stop_reason.is_some()
    }

    /// `stop` — records an adapter-initiated stop and kills the tree.
    fn stop(&self, reason: &'static str) {
        let mut st = self.state();
        self.stop_locked(&mut st, reason);
    }

    /// `stopLocked`. Callers hold `state`.
    fn stop_locked(&self, st: &mut State, reason: &'static str) {
        if st.stop_reason.is_some() || st.result.is_some() || st.finished {
            return;
        }
        st.stop_reason = Some(reason);
        self.kill_async_locked(st);
    }

    /// `killAsync` — kills the tree without blocking the reader, which
    /// must keep draining stdout meanwhile. Callers hold `state`;
    /// finish waits for every kill it started, so none outlives the
    /// session.
    fn kill_async_locked(&self, st: &mut State) {
        if st.finished {
            return;
        }
        let proc = self.proc.clone();
        st.kills.push(tokio::spawn(async move {
            let _ = proc.kill().await;
        }));
    }

    /// `enqueue` — queues one line for the writer. It fails once
    /// stdin is closing.
    fn enqueue(&self, req: WriteReq) -> Result<(), Failure> {
        let mut wq = self.wq();
        if wq.closed {
            return Err(session_ended());
        }
        wq.queue.push_back(req);
        drop(wq);
        self.wq_notify.notify_one();
        Ok(())
    }

    /// `closeStdin` — stops accepting lines; the writer closes stdin
    /// once every line queued before it is written. Takes `wq` only,
    /// so it is safe under `state` (lock order state, then wq).
    fn close_stdin(&self) {
        let mut wq = self.wq();
        wq.closed = true;
        drop(wq);
        self.wq_notify.notify_one();
    }

    /// `queued` — whether `Send` lines are still undelivered: queued
    /// or popped-but-blocked in a write. A result arriving while a
    /// follow-up is anywhere in the pipeline ends only its turn.
    /// Callers hold `state`; takes `wq` briefly.
    fn queued(&self) -> bool {
        let wq = self.wq();
        !wq.queue.is_empty() || wq.inflight > 0
    }

    /// `writer` — the single stdin writer. It holds no lock while it
    /// writes. Exits once the queue is drained and stdin is closing.
    /// The `wq` guard is scoped to the pop check so it never lives
    /// across an `.await`; the `Notified` is enabled before the check
    /// so a `notify_one` in the gap still wakes the wait.
    async fn writer(self: &Arc<Self>) {
        /// The pop outcome.
        enum Pop {
            Req(WriteReq),
            Closed,
            Wait,
        }
        loop {
            let notified = self.wq_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let pop = {
                let mut wq = self.wq();
                if let Some(r) = wq.queue.pop_front() {
                    wq.inflight += 1;
                    Pop::Req(r)
                } else if wq.closed {
                    Pop::Closed
                } else {
                    Pop::Wait
                }
            };
            let req = match pop {
                Pop::Req(r) => r,
                Pop::Closed => {
                    let _ = self.proc.close_stdin().await;
                    return;
                }
                Pop::Wait => {
                    notified.await;
                    continue;
                }
            };
            let result = self
                .proc
                .write_stdin(&req.line)
                .await
                .map(|_| ())
                .map_err(|e| {
                    Failure::new(
                        e.kind(),
                        e.code(),
                        format!("antigravity: write to harness: {}", e.message()),
                    )
                });
            {
                let mut wq = self.wq();
                wq.inflight -= 1;
            }
            if result.is_err()
                && let Some(on_fail) = req.on_fail
            {
                on_fail();
            }
            if let Some(done) = req.done {
                let _ = done.send(result);
            }
        }
    }

    /// `run` — the single reader task: frames, then stdin close, then
    /// stderr drain, `waitExit`, the writer's join, and `finish`.
    async fn run(self: &Arc<Self>) {
        let proc = self.proc.clone();
        let stderr_done = tokio::spawn(async move {
            // Stderr is drained and discarded: it may carry account
            // details and harness diagnostics.
            let _ = drain_discard(&*proc, Stream::Stderr).await;
        });
        let mut reader = FrameReader::new();
        loop {
            match reader.next(&*self.proc).await {
                Ok(Some(line)) => {
                    if !line.is_empty() {
                        self.handle(&line);
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    self.stop(reasons::HARNESS_PROTOCOL_ERROR);
                    let _ = drain_discard(&*self.proc, Stream::Stdout).await;
                    break;
                }
            }
        }
        self.close_stdin();
        let _ = stderr_done.await;
        let status = wait_exit(&*self.proc, EXIT_GRACE).await;
        // The tree is gone, so a write still in flight fails; closing
        // stdin also frees one whose pipe is somehow still open.
        // Waiting for the writer keeps its failure warning ahead of
        // the terminal event.
        let _ = self.proc.close_stdin().await;
        let writer = self
            .writer_done
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        if let Some(w) = writer {
            let _ = w.await;
        }
        self.finish(status).await;
    }

    /// `handle` — classifies one stdout line. Callers hold no lock;
    /// handle takes `state` for the whole line. After an
    /// adapter-initiated stop, a recorded session result, or the
    /// finish, frames are drained and dropped: nothing past the
    /// terminal may reach the attempt, and a dying stream warns no
    /// further.
    fn handle(&self, line: &[u8]) {
        let mut st = self.state();
        if st.stop_reason.is_some() || st.result.is_some() || st.finished {
            return;
        }
        let f = match decode_frame(line) {
            Ok(f) if !f.event.is_empty() => f,
            _ => {
                self.emit_locked(&mut st, Self::warning(WARN_MALFORMED), line);
                return;
            }
        };
        let kind = f.kind();
        if kind == FrameKind::Unknown {
            self.emit_locked(&mut st, Self::warning(WARN_UNRECOGNIZED), line);
            return;
        }
        let id = f.id();
        if id.is_empty() {
            // Only a result may arrive without an id, and only before
            // any session bound (the pre-init harness failure): it is
            // the harness's final word with no session to mismatch
            // against. Anything else idless is malformed, and an
            // idless result after binding violates stream integrity.
            match kind {
                FrameKind::Result if !st.revealed => {
                    // Processed below without binding.
                }
                FrameKind::Result => {
                    self.stop_locked(&mut st, reasons::HARNESS_SESSION_MISMATCH);
                    return;
                }
                _ => {
                    self.emit_locked(&mut st, Self::warning(WARN_MALFORMED), line);
                    return;
                }
            }
        } else if !self.cfg.resume_id.is_empty() {
            if id != self.cfg.resume_id {
                self.stop_locked(&mut st, reasons::HARNESS_SESSION_MISMATCH);
                return;
            }
        } else if st.revealed && id != st.session_id {
            self.stop_locked(&mut st, reasons::HARNESS_SESSION_MISMATCH);
            return;
        }
        if !st.revealed && !id.is_empty() {
            st.revealed = true;
            st.session_id = id.clone();
            self.emit_locked(
                &mut st,
                EventPayload::SessionStarted(SessionStarted {
                    harness_session_id: id.clone(),
                    harness_version: self.cfg.probed_version.clone(),
                    model: self.cfg.model.clone(),
                    tools: Vec::new(),
                    reported_capabilities: Vec::new(),
                }),
                line,
            );
            if let Some(tx) = st.ref_tx.take() {
                let _ = tx.send(SessionRef {
                    harness_session_id: id,
                });
            }
        }
        match kind {
            FrameKind::Init => {
                // No content; the id binding above is the whole effect.
            }
            FrameKind::Step => self.on_step(&mut st, f.step_update.as_deref(), line),
            FrameKind::Result => self.on_result(&mut st, f.result.as_deref(), line),
            FrameKind::Unknown => {}
        }
    }

    /// `onStep` — decodes one step_update body. Callers hold `state`.
    fn on_step(&self, st: &mut State, raw: Option<&[u8]>, line: &[u8]) {
        let Some(raw) = raw else {
            self.emit_locked(st, Self::warning(WARN_MALFORMED), line);
            return;
        };
        let (d, usable) = protocol::decode_step(raw);
        if !usable {
            // A malformed terminal tool frame still ends its step:
            // drop the pending call so a later same-index frame
            // cannot misattribute a result to it.
            if d.typ == StepType::Tool && matches!(d.state, StepState::Done | StepState::Error) {
                st.pending.remove(&d.index);
            }
            self.emit_locked(st, Self::warning(WARN_MALFORMED), line);
            return;
        }
        match d.typ {
            StepType::UserInput => {
                // No content; the id binding is the whole effect.
            }
            StepType::AgentResponse => self.on_text(st, &d, line),
            StepType::Tool => self.on_tool(st, &d, line),
            StepType::Unknown => {}
        }
    }

    /// `onText` — buffers ACTIVE deltas and emits DONE steps.
    /// Callers hold `state`.
    fn on_text(&self, st: &mut State, d: &protocol::StepData, line: &[u8]) {
        match d.state {
            StepState::Active => {
                if let Some(delta) = &d.text_delta {
                    st.texts.entry(d.index).or_default().push_str(delta);
                }
            }
            StepState::Done => {
                if let Some(delta) = &d.text_delta {
                    st.texts.entry(d.index).or_default().push_str(delta);
                }
                let text = st.texts.remove(&d.index).unwrap_or_default();
                if !text.trim().is_empty() {
                    self.emit_locked(
                        st,
                        EventPayload::Message(Message {
                            role: MessageRole::Assistant,
                            text,
                            partial: false,
                        }),
                        line,
                    );
                }
                if d.usage_unusable {
                    self.emit_locked(st, Self::warning(WARN_MALFORMED), line);
                } else if let Some(usage) = d.usage {
                    self.emit_locked(st, EventPayload::UsageReport(UsageReport { usage }), line);
                }
            }
            StepState::Error => {
                st.texts.remove(&d.index);
                self.emit_locked(st, Self::warning(WARN_MALFORMED), line);
            }
            StepState::Unknown => {}
        }
    }

    /// `onTool` — emits ToolCall/ToolResult halves. `step_index` is
    /// unique per process (a resume resets it per process), hence
    /// per attempt. Callers hold `state`.
    fn on_tool(&self, st: &mut State, d: &protocol::StepData, line: &[u8]) {
        let id = format!("step-{}", d.index);
        match d.state {
            StepState::Active => {
                let input = d
                    .tool_info
                    .as_ref()
                    .map(|ti| ti.parameters.clone())
                    .unwrap_or_default();
                st.pending.insert(d.index, PendingTool { id: id.clone() });
                self.emit_locked(
                    st,
                    EventPayload::ToolCall(ToolCall {
                        id,
                        parent_id: String::new(),
                        name: d.tool_name.clone(),
                        input,
                    }),
                    line,
                );
            }
            StepState::Done | StepState::Error => {
                let Some(p) = st.pending.remove(&d.index) else {
                    self.emit_locked(st, Self::warning(WARN_MALFORMED), line);
                    return;
                };
                let (status, output) = if d.state == StepState::Error {
                    (
                        protocol::tool_status(d.state),
                        tool_error_output(d.tool_info.as_ref().and_then(|ti| ti.error.as_ref())),
                    )
                } else {
                    (
                        protocol::tool_status(d.state),
                        d.tool_info
                            .as_ref()
                            .and_then(|ti| ti.output.clone())
                            .map(|s| s.into_bytes())
                            .unwrap_or_default(),
                    )
                };
                self.emit_locked(
                    st,
                    EventPayload::ToolResult(ToolResult {
                        id: p.id,
                        status,
                        output,
                    }),
                    line,
                );
            }
            StepState::Unknown => {}
        }
    }

    /// `onResult` — accounts one result event. A result with `Send`
    /// lines still queued ends only its turn: stdin stays open
    /// because the harness runs the queued turns next. The result
    /// with nothing queued ends the session: its terminal is
    /// recorded and stdin closes, which ends the harness process
    /// (exit 0). Callers hold `state`; `close_stdin` takes `wq` only.
    fn on_result(&self, st: &mut State, raw: Option<&[u8]>, line: &[u8]) {
        let r = raw.and_then(protocol::decode_result);
        let Some(r) = r else {
            self.emit_locked(st, Self::warning(WARN_MALFORMED), line);
            return;
        };
        if r.denied {
            self.emit_locked(st, Self::warning(protocol::WARN_DENIED), line);
        }
        if self.queued() {
            if r.ok && !r.response.trim().is_empty() {
                self.emit_locked(
                    st,
                    EventPayload::Message(Message {
                        role: MessageRole::Assistant,
                        text: r.response.clone(),
                        partial: false,
                    }),
                    line,
                );
            }
            if !r.ok {
                st.saw_result_err = true;
                st.result_raw = line.to_vec();
            }
            return;
        }
        if r.ok && !r.response.trim().is_empty() {
            // The last successful result's response is the final
            // answer, emitted as the last assistant Message so the
            // orchestrator's last-Message-wins rule takes the report
            // from it.
            self.emit_locked(
                st,
                EventPayload::Message(Message {
                    role: MessageRole::Assistant,
                    text: r.response.clone(),
                    partial: false,
                }),
                line,
            );
        }
        let t = if r.ok {
            Terminal {
                status: TerminalStatus::Succeeded,
                ..Terminal::default()
            }
        } else {
            Terminal {
                status: TerminalStatus::Failed,
                reason: reasons::HARNESS_API_ERROR.to_string(),
                ..Terminal::default()
            }
        };
        st.result = Some(t);
        st.result_raw = line.to_vec();
        // Closing stdin after the result ends the harness process.
        // This takes `wq` only, so it is safe under `state` (lock
        // order state, wq).
        self.close_stdin();
    }

    /// `finish` — computes the terminal (spec D4), emits it and
    /// releases waiters.
    async fn finish(self: &Arc<Self>, status: Result<central_harness::port::ExitStatus, Failure>) {
        let kills = {
            let mut st = self.state();
            std::mem::take(&mut st.kills)
        };
        // The process has exited, so these kills return promptly; none
        // of them takes the lock.
        for k in kills {
            let _ = k.await;
        }
        let mut st = self.state();
        let mut t = if let Some(reason) = st.stop_reason {
            Terminal {
                status: TerminalStatus::Failed,
                reason: reason.to_string(),
                ..Terminal::default()
            }
        } else if st.kill_requested {
            // Central's own stop wins over the harness's self-report:
            // agy answers SIGTERM with an ERROR/interrupted result,
            // and a Central stop must settle killed, never failed.
            Terminal {
                status: TerminalStatus::Killed,
                ..Terminal::default()
            }
        } else if let Some(ref r) = st.result {
            r.clone()
        } else if st.saw_result_err {
            Terminal {
                status: TerminalStatus::Failed,
                reason: reasons::HARNESS_API_ERROR.to_string(),
                ..Terminal::default()
            }
        } else if matches!(status, Ok(ref s) if s.code == 0) {
            Terminal {
                status: TerminalStatus::Succeeded,
                ..Terminal::default()
            }
        } else {
            Terminal {
                status: TerminalStatus::Failed,
                reason: reasons::HARNESS_EXITED_WITHOUT_RESULT.to_string(),
                ..Terminal::default()
            }
        };
        if let Ok(ref s) = status {
            t.exit_code = Some(s.code);
        }
        let raw = if st.result_raw.is_empty() {
            central_raw(t.status.as_str(), &t.reason)
        } else {
            st.result_raw.clone()
        };
        st.finished = true;
        st.terminal = t.clone();
        if !st.revealed {
            st.ref_tx.take();
        }
        self.emit_locked(
            &mut st,
            EventPayload::TerminalReported(TerminalReported {
                terminal: t.clone(),
            }),
            &raw,
        );
        st.events_tx.take();
        drop(st);
        self.done.set(t);
    }
}

/// `toolErrorOutput` — the `tool_info.error` detail: the message when
/// present, else the compacted error object, else empty.
fn tool_error_output(detail: Option<&protocol::ToolErrorData>) -> Vec<u8> {
    match detail {
        None => Vec::new(),
        Some(d) => match &d.message {
            Some(m) => m.clone().into_bytes(),
            None => d.raw.clone(),
        },
    }
}

/// `promptRaw` — the Raw of a prompt-delivery warning: a host-side
/// failure has no source frame.
fn prompt_raw() -> Vec<u8> {
    central_raw("prompt_undelivered", "")
}

/// `centralRaw` — the Raw of a host-computed event.
fn central_raw(status: &str, reason: &str) -> Vec<u8> {
    let mut b = Vec::with_capacity(80);
    b.extend_from_slice(b"{\"type\":\"central_stream_ended\",\"status\":");
    push_json_string(&mut b, status);
    if !reason.is_empty() {
        b.extend_from_slice(b",\"reason\":");
        push_json_string(&mut b, reason);
    }
    b.push(b'}');
    b
}

/// `session` — one live agy process.
pub(crate) struct AntigravitySession {
    inner: Arc<Inner>,
}

impl AntigravitySession {
    /// `newSession` + `begin` — spawns the writer and reader tasks,
    /// then queues the prompt as the first stdin user event.
    pub(crate) fn spawn(cfg: SessionCfg, proc: Box<dyn Process>, prompt: &str) -> Self {
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        let (ref_tx, ref_rx) = oneshot::channel();
        let inner = Arc::new(Inner {
            cfg,
            proc: Arc::from(proc),
            state: Mutex::new(State {
                seq: 0,
                session_id: String::new(),
                revealed: false,
                result: None,
                result_raw: Vec::new(),
                saw_result_err: false,
                kill_requested: false,
                stop_reason: None,
                finished: false,
                terminal: Terminal::default(),
                pending: HashMap::new(),
                texts: HashMap::new(),
                kills: Vec::new(),
                events_tx: Some(events_tx),
                ref_tx: Some(ref_tx),
            }),
            wq: Mutex::new(WriteQueue {
                queue: VecDeque::new(),
                inflight: 0,
                closed: false,
            }),
            wq_notify: Notify::new(),
            events_rx: tokio::sync::Mutex::new(events_rx),
            ref_rx: Mutex::new(Some(ref_rx)),
            writer_done: Mutex::new(None),
            done: Outcome::new(),
        });
        let w = inner.clone();
        *inner.writer_done.lock().unwrap_or_else(|p| p.into_inner()) =
            Some(tokio::spawn(async move { w.writer().await }));
        let r = inner.clone();
        tokio::spawn(async move { r.run().await });
        let line = protocol::encode_user_event(prompt);
        // A failed prompt write means the process is gone or its
        // stdin is broken; the session warns (fixed text, synthesized
        // raw) and the terminal still comes from the exit.
        let weak = Arc::downgrade(&inner);
        if inner
            .enqueue(WriteReq {
                line,
                done: None,
                on_fail: Some(Box::new(move || {
                    if let Some(inner) = weak.upgrade() {
                        let mut st = inner.state();
                        if !st.finished {
                            inner.emit_locked(
                                &mut st,
                                Inner::warning(WARN_PROMPT_FAILED),
                                &prompt_raw(),
                            );
                        }
                    }
                })),
            })
            .is_err()
        {
            let mut st = inner.state();
            inner.kill_async_locked(&mut st);
        }
        Self { inner }
    }
}

impl Session for AntigravitySession {
    /// `Ref() <-chan SessionRef` — the revealed harness session id, or
    /// `None` once the session ended without revealing it.
    fn session_ref(&self) -> PortFuture<'_, Option<SessionRef>> {
        let rx = self
            .inner
            .ref_rx
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        Box::pin(async move {
            match rx {
                Some(rx) => rx.await.ok(),
                None => None,
            }
        })
    }

    /// `Events() <-chan Event` — the next normalized event; `None`
    /// once the stream closes after the terminal event.
    fn next_event(&self) -> PortFuture<'_, Option<Event>> {
        Box::pin(async move { self.inner.events_rx.lock().await.recv().await })
    }

    /// `Send` — queues operator-authored follow-up text as a user
    /// event. A Send that races the final result either lands (the
    /// result ends only its turn) or is refused with
    /// `ErrSessionEnded`.
    fn send<'a>(&'a self, input: OperatorInput) -> PortFuture<'a, Result<(), Failure>> {
        Box::pin(async move {
            let line = protocol::encode_user_event(&input.text);
            let (done_tx, done_rx) = oneshot::channel();
            {
                let st = self.inner.state();
                if Inner::ended_locked(&st) {
                    return Err(session_ended());
                }
                self.inner.enqueue(WriteReq {
                    line,
                    done: Some(done_tx),
                    on_fail: None,
                })?;
            }
            match done_rx.await {
                Ok(r) => r,
                Err(_) => Err(Failure::internal(
                    "E_INTERNAL",
                    "antigravity: writer ended before the write resolved",
                )),
            }
        })
    }

    /// `Interrupt` — unsupported before the terminal: agy has no
    /// soft-interrupt seam (a signal ends it), so the orchestrator
    /// kills the scope at once on this error. After the terminal it
    /// reports session-ended like any ended session.
    fn interrupt(&self) -> PortFuture<'_, Result<(), Failure>> {
        Box::pin(async move {
            let st = self.inner.state();
            if st.finished || st.result.is_some() || st.stop_reason.is_some() {
                return Err(session_ended());
            }
            Err(unsupported())
        })
    }

    /// `RespondPermission` — always reports no pending request: this
    /// session never emits one.
    fn respond_permission<'a>(
        &'a self,
        _decision: PermissionDecision,
    ) -> PortFuture<'a, Result<(), Failure>> {
        Box::pin(async move { Err(no_pending_permission()) })
    }

    /// `Kill` — stops the process tree through the launcher's kill
    /// ladder.
    fn kill(&self) -> PortFuture<'_, Result<(), Failure>> {
        Box::pin(async move {
            {
                let mut st = self.inner.state();
                if st.finished {
                    return Ok(());
                }
                st.kill_requested = true;
            }
            self.inner.proc.kill().await
        })
    }

    /// `Wait` — the terminal once the reader and the process are both
    /// done.
    fn wait(&self) -> PortFuture<'_, Result<Terminal, Failure>> {
        Box::pin(async move { Ok(self.inner.done.wait().await) })
    }
}
