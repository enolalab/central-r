//! `session.go` — one live `opencode` process. One reader task parses
//! bounded NDJSON frames from stdout; one writer task delivers the
//! prompt to stdin and closes it; events go through an unbounded
//! in-order channel so the reader never blocks on a slow event
//! consumer. The channel is drained only by reading it: callers must
//! read until `None` (port.Session.Events).
//!
//! `opencode run` is one-shot: no streaming input, no soft interrupt,
//! no permission requests. Lock order matches upstream's one `mu`.

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
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::json::push_json_string_html;
use crate::process::{EXIT_GRACE, FrameReader, Outcome, Stream, drain_discard, wait_exit};

use super::protocol::{self, FrameKind, decode_frame};
use super::reasons;

/// Fixed texts the adapter emits; never harness text.
const WARN_UNRECOGNIZED: &str = "unrecognized harness message";
const WARN_MALFORMED: &str = "malformed harness frame";
const WARN_PROMPT_FAILED: &str = "delivering the prompt failed";

/// `ErrInterruptUnsupported` — `port.ErrUnsupported` upstream: before
/// the terminal the orchestrator kills the scope at once.
fn unsupported() -> Failure {
    Failure::new(
        FailureKind::Invalid,
        central_harness::port::codes::UNSUPPORTED,
        "opencode: unsupported",
    )
}

/// `ErrSessionEnded` — `port.ErrSessionEnded` upstream: returned by
/// Interrupt once the terminal is recorded — the session is exiting on
/// its own and must not be killed at once.
fn session_ended() -> Failure {
    Failure::new(
        FailureKind::Invalid,
        central_harness::port::codes::SESSION_ENDED,
        "opencode: session ended",
    )
}

/// `ErrNoPendingPermission` — `port.ErrNoPendingPermission` upstream:
/// the session never emits a permission request, so none is pending.
fn no_pending_permission() -> Failure {
    Failure::new(
        FailureKind::Invalid,
        central_harness::port::codes::NO_PENDING_PERMISSION,
        "opencode: no pending permission request",
    )
}

/// `sessionConfig` — everything a session needs that is fixed at open.
pub(crate) struct SessionCfg {
    pub attempt: HarnessAttemptId,
    /// `resumeID` — the id a resumed session must keep; `""` for a
    /// fresh session, whose first frame reveals the id instead.
    pub resume_id: String,
    /// `probedVersion` — the version `SessionStarted` reports.
    pub probed_version: String,
    pub model: String,
}

/// The `mu` state — every field the upstream session mutates under its
/// one mutex, in the same order.
struct State {
    seq: u64,
    session_id: String,
    revealed: bool,
    saw_error: bool,
    saw_error_raw: Vec<u8>,
    kill_requested: bool,
    stop_reason: Option<&'static str>,
    finished: bool,
    terminal: Terminal,
    /// Adapter-initiated kills in flight.
    kills: Vec<JoinHandle<()>>,
    /// The event send half — `None` once the terminal event is queued
    /// (the upstream `close(s.events)` after it is delivered).
    events_tx: Option<mpsc::UnboundedSender<Event>>,
    /// The ref send half — sent once on reveal, or dropped at finish
    /// when no id was ever revealed.
    ref_tx: Option<oneshot::Sender<SessionRef>>,
}

/// The shared internals of one session.
struct Inner {
    cfg: SessionCfg,
    proc: Arc<dyn Process>,
    state: Mutex<State>,
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

    /// `stop` — records an adapter-initiated stop and kills the tree.
    fn stop(&self, reason: &'static str) {
        let mut st = self.state();
        self.stop_locked(&mut st, reason);
    }

    /// `stopLocked`. Callers hold `state`.
    fn stop_locked(&self, st: &mut State, reason: &'static str) {
        if st.stop_reason.is_some() || st.finished {
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

    /// `writer` — delivers the prompt and closes stdin. A failed write
    /// means the child already exited; it warns (fixed text,
    /// synthesized raw) instead of failing anything: the terminal
    /// still comes from the exit. A close error after a complete write
    /// is not a delivery failure.
    async fn writer(self: &Arc<Self>, prompt: String) {
        let werr = self.proc.write_stdin(prompt.as_bytes()).await;
        let _ = self.proc.close_stdin().await;
        if werr.is_ok() {
            return;
        }
        let mut st = self.state();
        if !st.finished {
            self.emit_locked(&mut st, Self::warning(WARN_PROMPT_FAILED), &prompt_raw());
        }
    }

    /// `run` — the single reader task: frames, then stderr drain, then
    /// `waitExit`, then the writer's close, then `finish`.
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
    /// adapter-initiated stop, frames are drained and dropped: nothing
    /// from a mismatched session may reach the attempt, and a dying
    /// stream warns no further.
    fn handle(&self, line: &[u8]) {
        let mut st = self.state();
        if st.stop_reason.is_some() || st.finished {
            return;
        }
        let f = match decode_frame(line) {
            Ok(f) if !f.typ.is_empty() => f,
            _ => {
                self.emit_locked(&mut st, Self::warning(WARN_MALFORMED), line);
                return;
            }
        };
        if f.session_id.is_empty() {
            self.emit_locked(&mut st, Self::warning(WARN_MALFORMED), line);
            return;
        }
        if !self.cfg.resume_id.is_empty() {
            if f.session_id != self.cfg.resume_id {
                self.stop_locked(&mut st, reasons::HARNESS_SESSION_MISMATCH);
                return;
            }
        } else if st.revealed && f.session_id != st.session_id {
            self.stop_locked(&mut st, reasons::HARNESS_SESSION_MISMATCH);
            return;
        }
        if !st.revealed {
            st.revealed = true;
            st.session_id = f.session_id.clone();
            self.emit_locked(
                &mut st,
                EventPayload::SessionStarted(SessionStarted {
                    harness_session_id: f.session_id.clone(),
                    harness_version: self.cfg.probed_version.clone(),
                    model: self.cfg.model.clone(),
                    tools: Vec::new(),
                    reported_capabilities: Vec::new(),
                }),
                line,
            );
            if let Some(tx) = st.ref_tx.take() {
                let _ = tx.send(SessionRef {
                    harness_session_id: f.session_id.clone(),
                });
            }
        }
        match f.kind() {
            FrameKind::StepStart | FrameKind::Reasoning => {
                // No content; the id binding above is the whole effect.
            }
            FrameKind::Text => match protocol::decode_text(f.part.as_deref()) {
                Some(text) => {
                    if text.is_empty() {
                        return;
                    }
                    self.emit_locked(
                        &mut st,
                        EventPayload::Message(Message {
                            role: MessageRole::Assistant,
                            text,
                            partial: false,
                        }),
                        line,
                    );
                }
                None => {
                    self.emit_locked(&mut st, Self::warning(WARN_MALFORMED), line);
                }
            },
            FrameKind::Tool => match protocol::decode_tool(f.part.as_deref()) {
                Some((call, result)) => {
                    self.emit_locked(
                        &mut st,
                        EventPayload::ToolCall(ToolCall {
                            id: call.id,
                            parent_id: String::new(),
                            name: call.name,
                            input: call.input,
                        }),
                        line,
                    );
                    self.emit_locked(
                        &mut st,
                        EventPayload::ToolResult(ToolResult {
                            id: result.id,
                            status: result.status,
                            output: result.output,
                        }),
                        line,
                    );
                }
                None => {
                    self.emit_locked(&mut st, Self::warning(WARN_MALFORMED), line);
                }
            },
            FrameKind::StepFinish => match protocol::decode_step(f.part.as_deref()) {
                Some(usage) => {
                    self.emit_locked(
                        &mut st,
                        EventPayload::UsageReport(UsageReport { usage }),
                        line,
                    );
                }
                None => {
                    self.emit_locked(&mut st, Self::warning(WARN_MALFORMED), line);
                }
            },
            FrameKind::Error => {
                if !f.has_error_body() {
                    self.emit_locked(&mut st, Self::warning(WARN_MALFORMED), line);
                    return;
                }
                st.saw_error = true;
                st.saw_error_raw = line.to_vec();
            }
            FrameKind::Unknown => {
                self.emit_locked(&mut st, Self::warning(WARN_UNRECOGNIZED), line);
            }
        }
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
        } else if st.saw_error {
            Terminal {
                status: TerminalStatus::Failed,
                reason: reasons::HARNESS_API_ERROR.to_string(),
                ..Terminal::default()
            }
        } else if st.kill_requested {
            Terminal {
                status: TerminalStatus::Killed,
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
        let raw = if st.saw_error_raw.is_empty() {
            central_raw(t.status.as_str(), &t.reason)
        } else {
            st.saw_error_raw.clone()
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

/// `promptRaw` — the Raw of a prompt-delivery warning: a host-side
/// failure has no source frame.
fn prompt_raw() -> Vec<u8> {
    central_raw("prompt_undelivered", "")
}

/// `centralRaw` — the Raw of a host-computed event:
/// `{"type":"central_stream_ended","status":"…","reason":"…"}` with
/// `reason` omitted when empty (upstream's `,omitempty`). Status and
/// reason carry closed vocabularies only, so no Go HTML escaping is
/// ever observable.
fn central_raw(status: &str, reason: &str) -> Vec<u8> {
    let mut b = Vec::with_capacity(80);
    b.extend_from_slice(b"{\"type\":\"central_stream_ended\",\"status\":");
    push_json_string_html(&mut b, status);
    if !reason.is_empty() {
        b.extend_from_slice(b",\"reason\":");
        push_json_string_html(&mut b, reason);
    }
    b.push(b'}');
    b
}

/// `session` — one live opencode process.
pub(crate) struct OpenCodeSession {
    inner: Arc<Inner>,
}

impl OpenCodeSession {
    /// `newSession` + `begin` — spawns the writer (which delivers the
    /// prompt to stdin) and the reader task.
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
                saw_error: false,
                saw_error_raw: Vec::new(),
                kill_requested: false,
                stop_reason: None,
                finished: false,
                terminal: Terminal::default(),
                kills: Vec::new(),
                events_tx: Some(events_tx),
                ref_tx: Some(ref_tx),
            }),
            events_rx: tokio::sync::Mutex::new(events_rx),
            ref_rx: Mutex::new(Some(ref_rx)),
            writer_done: Mutex::new(None),
            done: Outcome::new(),
        });
        let w = inner.clone();
        let prompt = prompt.to_string();
        *inner.writer_done.lock().unwrap_or_else(|p| p.into_inner()) =
            Some(tokio::spawn(async move { w.writer(prompt).await }));
        let r = inner.clone();
        tokio::spawn(async move { r.run().await });
        Self { inner }
    }
}

impl Session for OpenCodeSession {
    /// `Ref() <-chan SessionRef` — the revealed harness session id, or
    /// `None` once the session ended without revealing it (upstream's
    /// closed channel). A second call sees the channel's closed read.
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

    /// `Send` — unsupported: `opencode run` is one-shot and reads no
    /// follow-up input.
    fn send<'a>(&'a self, _input: OperatorInput) -> PortFuture<'a, Result<(), Failure>> {
        Box::pin(async move { Err(unsupported()) })
    }

    /// `Interrupt` — unsupported before the terminal: `opencode run`
    /// has no soft-interrupt seam (a signal kills it), so the
    /// orchestrator kills the scope at once on this error. After the
    /// terminal it reports session-ended like any ended session.
    fn interrupt(&self) -> PortFuture<'_, Result<(), Failure>> {
        Box::pin(async move {
            let st = self.inner.state();
            if st.finished || st.stop_reason.is_some() {
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
