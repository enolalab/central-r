//! `session.go` — one live `claude` process. One reader task parses
//! bounded NDJSON frames from stdout; one writer task writes queued
//! lines to stdin in order; events go through an unbounded in-order
//! channel so neither the reader nor a caller answering a permission
//! ever blocks on a slow event consumer. No lock is held across a stdin
//! write, so a harness that stops reading stdin blocks only the writer
//! (and callers waiting on their own line), never `kill` or the reader.
//! The event stream is drained only by reading it — callers must read
//! until `None`, as `port.Session.Events` requires upstream.
//!
//! A `system/init` frame must come first: it is where the session id,
//! the permission mode and the Claude version are verified. An
//! `assistant`, `user` or `result` frame, or a `can_use_tool` request,
//! that arrives before a verified init fails the session closed with
//! [`reasons::HARNESS_PROTOCOL_ERROR`].
//!
//! Lock order: `state` (`mu` upstream), then `wq` (`wmu`). The writer
//! takes `state` only while holding no other lock.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::SystemTime;

use central_foundation::failure::{Failure, FailureKind};
use central_foundation::identity::HarnessAttemptId;
use central_harness::approval::{DECIDED_BY_INPUT_TOO_LARGE, MAX_BRIDGED_INPUT_BYTES};
use central_harness::domain::{PermissionPolicy, Terminal, TerminalStatus};
use central_harness::event::{
    Event, EventPayload, Message, MessageRole, PermissionOutcome, PermissionRequested,
    PermissionResolved, Reasoning, Retry, SessionStarted, TerminalReported, ToolCall, ToolResult,
    ToolStatus, Usage, UsageReport, Warning,
};
use central_harness::port::{
    OperatorInput, PermissionDecision, PortFuture, Process, Session, SessionRef,
};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tokio::sync::{Notify, mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::process::{EXIT_GRACE, FrameReader, Outcome, Stream, drain_discard, wait_exit};

use super::protocol::{
    self, ControlRequest, Frame, LiveTokens, add_counter, add_turn, decode_frame, initialize_line,
    interrupt_line, map_result, permission_response_frame, unsupported_response_frame,
    user_message_line,
};
use super::reasons;

/// Fixed texts the adapter writes or emits; never harness text.
const DENY_BY_OPERATOR: &str = "Denied by the operator.";
const DENY_BY_POLICY: &str =
    "Denied: this task's permission policy does not bridge permission requests.";
const DENY_INPUT_TOO_LARGE: &str = "Denied: the tool input is too large to show the operator.";
const WARN_UNRECOGNIZED: &str = "unrecognized harness message";
const WARN_MALFORMED: &str = "malformed harness frame";
const WARN_POLICY_DENIED: &str = "permission request under a non-bridge policy was denied";
const WARN_UNSUPPORTED_REQ: &str = "unsupported harness control request was refused";
const WARN_ANSWER_FAILED: &str = "answering a harness control request failed";

/// `ErrSessionEnded` — `port.ErrSessionEnded` upstream.
fn session_ended() -> Failure {
    Failure::new(
        FailureKind::Invalid,
        central_harness::port::codes::SESSION_ENDED,
        "claudecode: session ended",
    )
}

/// `ErrNoPendingPermission` — `port.ErrNoPendingPermission` upstream.
fn no_pending_permission() -> Failure {
    Failure::new(
        FailureKind::Invalid,
        central_harness::port::codes::NO_PENDING_PERMISSION,
        "claudecode: no pending permission request",
    )
}

/// `port.ErrPermissionBinding` — an allow that does not bind the echoed
/// input bytes.
fn permission_binding() -> Failure {
    Failure::new(
        FailureKind::Invalid,
        central_harness::port::codes::PERMISSION_BINDING,
        "claudecode: permission binding",
    )
}

/// `write to harness failed` — the `claudecode: write to harness: %w`
/// wrap, reduced to the process-io code.
fn write_failed() -> Failure {
    Failure::internal(
        crate::process::codes::PROCESS_IO,
        "claudecode: write to harness failed",
    )
}

/// `sessionConfig` — everything a session needs that is fixed at open.
pub(crate) struct SessionCfg {
    pub attempt: HarnessAttemptId,
    pub policy: PermissionPolicy,
    pub expected_id: String,
    pub expected_mode: String,
    /// The `claude_code_version` init must report; empty under
    /// `AllowUnpinned`.
    pub pinned_version: String,
}

/// `pendingPermission` — one bridged `can_use_tool` request. `input` is
/// the compact tool input: exactly the bytes an allow echoes as
/// `updatedInput` and the bytes `PermissionRequested.input` carries
/// (harness phase 3c decision 5).
#[derive(Clone)]
struct PendingPermission {
    tool_use_id: String,
    input: Vec<u8>,
}

/// `writeReq` — one line queued for stdin.
struct WriteReq {
    line: Vec<u8>,
    /// The write's outcome, when a caller waits for it.
    done: Option<oneshot::Sender<Result<(), Failure>>>,
    /// Runs on a failed write with no lock held.
    on_fail: Option<Box<dyn FnOnce() + Send>>,
}

/// The writer queue state (`wmu` upstream).
struct Wq {
    queue: VecDeque<WriteReq>,
    /// `stdinClosed` — no more lines are queued; stdin closes once
    /// drained.
    closed: bool,
}

/// The `mu` state — every field the upstream session mutates under its
/// one mutex, in the same order.
struct State {
    seq: u64,
    session_id: String,
    revealed: bool,
    pending: HashMap<String, PendingPermission>,
    denied: HashSet<String>,
    auth_failed: bool,
    interrupt_requested: bool,
    /// Interrupt request ids the harness has not acknowledged yet.
    interrupts: HashSet<String>,
    /// The running session total of every result so far — never raised
    /// to a live figure (harness phase 3l decision 4).
    usage: Usage,
    /// Per main-thread assistant message (keyed by the SHA-256 of its
    /// id, so a long id costs no memory) the largest billed counters
    /// seen; `live` is their sum (phase 3l decision 3).
    messages: HashMap<[u8; 32], LiveTokens>,
    live: LiveTokens,
    /// The last `UsageReport` emitted; no later report lowers a counter
    /// (phase 3l decision 4).
    reported: Usage,
    kill_requested: bool,
    stop_reason: Option<&'static str>,
    result: Option<Terminal>,
    result_raw: Option<Vec<u8>>,
    finished: bool,
    /// Adapter-initiated kills in flight.
    kills: Vec<JoinHandle<()>>,
    /// The event send half — `None` once the terminal event is queued
    /// (the upstream `close(s.events)` after it is delivered).
    events_tx: Option<mpsc::UnboundedSender<Event>>,
    /// The ref send half — sent once on init, or dropped at finish
    /// when init never arrived.
    ref_tx: Option<oneshot::Sender<SessionRef>>,
}

/// `ended` — no more input may be written. Callers hold `state`.
fn ended(st: &State) -> bool {
    st.finished || st.result.is_some() || st.stop_reason.is_some()
}

/// The shared internals of one session.
struct Inner {
    cfg: SessionCfg,
    proc: Arc<dyn Process>,
    state: Mutex<State>,
    wq: Mutex<Wq>,
    wnotify: Notify,
    events_rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<Event>>,
    /// One-shot `Ref()` — the first caller resolves it; later callers
    /// see the closed channel upstream would hand them.
    ref_rx: Mutex<Option<oneshot::Receiver<SessionRef>>>,
    writer_done: Mutex<Option<JoinHandle<()>>>,
    /// `done` — set once with the terminal.
    done: Outcome<Terminal>,
    /// A weak self for write-failure callbacks, so a queued request
    /// never keeps the session alive.
    me: Weak<Inner>,
}

impl Inner {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn wq(&self) -> MutexGuard<'_, Wq> {
        self.wq.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// `ended()` under the guard.
    fn stopped_or_result(st: &State) -> bool {
        st.stop_reason.is_some() || st.result.is_some()
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

    /// `emitUnlessStopped` — drops events after an adapter-initiated
    /// stop: frames from a mismatched session must not reach the
    /// attempt.
    fn emit_unless_stopped_locked(&self, st: &mut State, payload: EventPayload, raw: &[u8]) {
        if st.stop_reason.is_none() {
            self.emit_locked(st, payload, raw);
        }
    }

    fn warning(message: &'static str) -> EventPayload {
        EventPayload::Warning(Warning {
            message: message.to_string(),
        })
    }

    /// `enqueue` — queues one line for the writer; fails once stdin is
    /// closing.
    fn enqueue(&self, r: WriteReq) -> Result<(), Failure> {
        let mut g = self.wq();
        if g.closed {
            return Err(session_ended());
        }
        g.queue.push_back(r);
        self.wnotify.notify_one();
        Ok(())
    }

    /// `closeStdin` — stops accepting lines; the writer closes stdin
    /// once every line queued before it is written.
    fn close_stdin(&self) {
        self.wq().closed = true;
        self.wnotify.notify_one();
    }

    /// `stop` — records an adapter-initiated stop and kills the tree.
    fn stop(&self, reason: &'static str) {
        let mut st = self.state();
        self.stop_locked(&mut st, reason);
    }

    /// `stopLocked`. Callers hold `state`.
    fn stop_locked(&self, st: &mut State, reason: &'static str) {
        if st.stop_reason.is_some() || st.result.is_some() {
            return;
        }
        st.stop_reason = Some(reason);
        st.pending.clear();
        self.kill_async_locked(st);
    }

    /// `killAsync` — kills the tree without blocking the reader, which
    /// must keep draining stdout meanwhile. `finish` waits for every
    /// kill started, so none outlives the session. Callers hold `state`.
    fn kill_async_locked(&self, st: &mut State) {
        if st.finished {
            return;
        }
        let proc = self.proc.clone();
        st.kills.push(tokio::spawn(async move {
            let _ = proc.kill().await;
        }));
    }

    /// `beforeInitLocked` — fails the session closed when a frame that
    /// needs a verified init arrives before one. Callers hold `state`.
    fn before_init_locked(&self, st: &mut State) -> bool {
        if st.revealed {
            return false;
        }
        self.stop_locked(st, reasons::HARNESS_PROTOCOL_ERROR);
        true
    }

    /// `answerLocked` — queues the reply to a harness control request
    /// without waiting, so the reader never blocks on stdin. A reply
    /// that cannot be queued or written is reported as a fixed warning
    /// carrying `raw`, the request it answers. Callers hold `state`.
    fn answer_locked(&self, st: &mut State, frame: Vec<u8>, raw: &[u8]) {
        let raw = raw.to_vec();
        let on_fail_raw = raw.clone();
        let me = self.me.clone();
        let req = WriteReq {
            line: protocol::encode_line(frame),
            done: None,
            on_fail: Some(Box::new(move || {
                let Some(inner) = me.upgrade() else { return };
                let mut st = inner.state();
                if !st.finished {
                    inner.emit_unless_stopped_locked(
                        &mut st,
                        Self::warning(WARN_ANSWER_FAILED),
                        &on_fail_raw,
                    );
                }
            })),
        };
        if self.enqueue(req).is_err() {
            self.emit_unless_stopped_locked(st, Self::warning(WARN_ANSWER_FAILED), &raw);
        }
    }

    /// `countLiveLocked` — folds one main-thread assistant frame's
    /// billed tokens into the live sum and reports it when that raises
    /// a reported counter (phase 3l decision 3). A message is repeated
    /// once per content block: per counter the largest value seen for
    /// its id counts, once. Callers hold `state`.
    fn count_live_locked(&self, st: &mut State, id: &str, tokens: LiveTokens, raw: &[u8]) {
        if st.stop_reason.is_some() || st.result.is_some() {
            return;
        }
        let key: [u8; 32] = Sha256::digest(id.as_bytes()).into();
        let seen = st.messages.get(&key).copied().unwrap_or_default();
        let next = LiveTokens {
            tokens_in: seen.tokens_in.max(tokens.tokens_in),
            tokens_out: seen.tokens_out.max(tokens.tokens_out),
            cache_write: seen.cache_write.max(tokens.cache_write),
        };
        st.messages.insert(key, next);
        st.live = LiveTokens {
            tokens_in: add_counter(st.live.tokens_in, next.tokens_in - seen.tokens_in),
            tokens_out: add_counter(st.live.tokens_out, next.tokens_out - seen.tokens_out),
            cache_write: add_counter(st.live.cache_write, next.cache_write - seen.cache_write),
        };
        let report = self.raised_locked(
            st,
            Usage {
                tokens_in: st.live.tokens_in,
                tokens_out: st.live.tokens_out,
                cache_write: st.live.cache_write,
                ..Usage::default()
            },
        );
        if report == st.reported {
            return;
        }
        st.reported = report;
        self.emit_locked(
            st,
            EventPayload::UsageReport(UsageReport { usage: report }),
            raw,
        );
    }

    /// `raisedLocked` — `u` with each counter raised to what the
    /// session already reported, so no report ever lowers one and the
    /// domain's fold never refuses it (phase 3l decision 4). Callers
    /// hold `state`.
    fn raised_locked(&self, st: &State, u: Usage) -> Usage {
        Usage {
            tokens_in: st.reported.tokens_in.max(u.tokens_in),
            tokens_out: st.reported.tokens_out.max(u.tokens_out),
            cache_read: st.reported.cache_read.max(u.cache_read),
            cache_write: st.reported.cache_write.max(u.cache_write),
            cost_micro_usd: st.reported.cost_micro_usd.max(u.cost_micro_usd),
            scope: central_harness::event::UsageScope::SessionCumulative,
            estimated: true,
        }
    }

    /// `handle` — one decoded line's dispatch.
    fn handle(self: &Arc<Self>, line: &[u8]) {
        let f = match decode_frame(line) {
            Err(_) => {
                let mut st = self.state();
                self.emit_unless_stopped_locked(&mut st, Self::warning(WARN_MALFORMED), line);
                return;
            }
            Ok(f) => f,
        };
        match f.typ.as_str() {
            "system" => match f.subtype.as_str() {
                "init" => self.on_init(&f, line),
                "permission_denied" => {
                    let mut st = self.state();
                    if !f.tool_use_id.is_empty() {
                        st.denied.insert(f.tool_use_id.clone());
                    }
                }
                "api_retry" => {
                    let mut st = self.state();
                    self.emit_unless_stopped_locked(
                        &mut st,
                        EventPayload::Retry(Retry {
                            reason: "api_retry".to_string(),
                        }),
                        line,
                    );
                }
                // Other system subtypes (hook_*, status,
                // thinking_tokens, ...) stay in the raw stream only.
                _ => {}
            },
            "assistant" => self.on_assistant(&f, line),
            "user" => self.on_user(&f, line),
            "control_request" => self.on_control_request(&f, line),
            "result" => self.on_result(&f, line),
            "control_response" => self.on_control_response(&f),
            "rate_limit_event" | "stream_event" => {
                // Informational frames are not emitted.
            }
            _ => {
                let mut st = self.state();
                self.emit_unless_stopped_locked(&mut st, Self::warning(WARN_UNRECOGNIZED), line);
            }
        }
    }

    /// `onInit` — the first frame must carry the expected session id,
    /// permission mode and (unless unpinned) version; a mismatch is a
    /// fail-closed stop.
    fn on_init(&self, f: &Frame, line: &[u8]) {
        let mut st = self.state();
        if st.stop_reason.is_some() {
            return;
        }
        if !self.cfg.pinned_version.is_empty() && f.claude_code_version != self.cfg.pinned_version {
            // The pre-launch version probe is a separate exec; the
            // running process must be the version the protocol mapping
            // was verified on.
            self.stop_locked(&mut st, reasons::HARNESS_PROTOCOL_ERROR);
            return;
        }
        if f.session_id != self.cfg.expected_id {
            self.stop_locked(&mut st, reasons::HARNESS_SESSION_MISMATCH);
            return;
        }
        if f.permission_mode != self.cfg.expected_mode {
            self.stop_locked(&mut st, reasons::HARNESS_POLICY_MISMATCH);
            return;
        }
        if st.revealed {
            return;
        }
        st.revealed = true;
        st.session_id = f.session_id.clone();
        self.emit_locked(
            &mut st,
            EventPayload::SessionStarted(SessionStarted {
                harness_session_id: f.session_id.clone(),
                harness_version: f.claude_code_version.clone(),
                model: f.model.clone(),
                tools: f.tools.clone(),
                reported_capabilities: f.capabilities.clone(),
            }),
            line,
        );
        if let Some(tx) = st.ref_tx.take() {
            let _ = tx.send(SessionRef {
                harness_session_id: f.session_id.clone(),
            });
        }
    }

    /// `onAssistant`.
    fn on_assistant(&self, f: &Frame, line: &[u8]) {
        let blocks = f.blocks();
        let counted = f.main_thread_usage();
        let mut st = self.state();
        if self.before_init_locked(&mut st) {
            return;
        }
        let Ok(blocks) = blocks else {
            self.emit_unless_stopped_locked(&mut st, Self::warning(WARN_MALFORMED), line);
            return;
        };
        if f.error == "authentication_failed" {
            st.auth_failed = true;
        }
        if let Some((id, tokens)) = counted {
            // The report precedes the frame's content events, so
            // Central sees the usage before a tool call of the same
            // message.
            self.count_live_locked(&mut st, &id, tokens, line);
        }
        let parent = f.parent_tool_use_id.clone().unwrap_or_default();
        for b in &blocks {
            match b.typ.as_str() {
                "text" => self.emit_unless_stopped_locked(
                    &mut st,
                    EventPayload::Message(Message {
                        role: MessageRole::Assistant,
                        text: b.text.clone(),
                        partial: false,
                    }),
                    line,
                ),
                "thinking" => self.emit_unless_stopped_locked(
                    &mut st,
                    EventPayload::Reasoning(Reasoning {
                        text: b.thinking.clone(),
                    }),
                    line,
                ),
                "tool_use" => {
                    if b.id.is_empty() || b.name.is_empty() {
                        self.emit_unless_stopped_locked(
                            &mut st,
                            Self::warning(WARN_MALFORMED),
                            line,
                        );
                        continue;
                    }
                    self.emit_unless_stopped_locked(
                        &mut st,
                        EventPayload::ToolCall(ToolCall {
                            id: b.id.clone(),
                            parent_id: parent.clone(),
                            name: b.name.clone(),
                            input: b.input.clone(),
                        }),
                        line,
                    );
                }
                _ => {}
            }
        }
    }

    /// `onUser` — `tool_result` blocks only.
    fn on_user(&self, f: &Frame, line: &[u8]) {
        let blocks = f.blocks();
        let mut st = self.state();
        if self.before_init_locked(&mut st) {
            return;
        }
        let Ok(blocks) = blocks else {
            self.emit_unless_stopped_locked(&mut st, Self::warning(WARN_MALFORMED), line);
            return;
        };
        for b in &blocks {
            if b.typ != "tool_result" {
                continue;
            }
            if b.tool_use_id.is_empty() {
                self.emit_unless_stopped_locked(&mut st, Self::warning(WARN_MALFORMED), line);
                continue;
            }
            let status = if st.denied.contains(&b.tool_use_id) {
                ToolStatus::Denied
            } else if b.is_error {
                ToolStatus::Error
            } else {
                ToolStatus::Ok
            };
            self.emit_unless_stopped_locked(
                &mut st,
                EventPayload::ToolResult(ToolResult {
                    id: b.tool_use_id.clone(),
                    status,
                    output: b.content.clone(),
                }),
                line,
            );
        }
    }

    /// `onControlRequest`.
    fn on_control_request(&self, f: &Frame, line: &[u8]) {
        let req = f.can_use_tool();
        let mut st = self.state();
        if Self::stopped_or_result(&st) {
            // After a stop or the last result stdin is closing: nothing
            // can be answered, so nothing is bridged either.
            return;
        }
        let req = match req {
            Err(_) => Err(()),
            Ok(_) if f.request_id.is_empty() => Err(()),
            Ok(r) => Ok(r),
        };
        let Ok(req) = req else {
            // Still answer, so the harness never waits on it.
            if !f.request_id.is_empty() {
                self.answer_locked(&mut st, unsupported_response_frame(&f.request_id), line);
            }
            self.emit_locked(&mut st, Self::warning(WARN_MALFORMED), line);
            return;
        };
        if req.subtype != "can_use_tool" {
            // The adapter registers no hooks or SDK MCP servers, so any
            // other request is unexpected; answer it so the harness
            // never waits.
            self.answer_locked(&mut st, unsupported_response_frame(&f.request_id), line);
            self.emit_locked(&mut st, Self::warning(WARN_UNSUPPORTED_REQ), line);
            return;
        }
        if self.before_init_locked(&mut st) {
            // Never answer, let alone bridge, a permission request
            // before the session id and mode are verified.
            return;
        }
        if self.cfg.policy != PermissionPolicy::Bridge {
            // deny and auto_allow never bridge: answer deny and warn.
            if !req.tool_use_id.is_empty() {
                st.denied.insert(req.tool_use_id.clone());
            }
            self.answer_locked(
                &mut st,
                permission_response_frame(&f.request_id, false, &[], DENY_BY_POLICY),
                line,
            );
            self.emit_locked(&mut st, Self::warning(WARN_POLICY_DENIED), line);
            return;
        }
        self.bridge_locked(&mut st, &f.request_id, &req, line);
    }

    /// `bridgeLocked` — one `can_use_tool` under the bridge policy
    /// becomes a `PermissionRequested` (phase 3c decisions 5, 7 and
    /// 13). A request with a harness-controlled field out of bounds,
    /// whose id is already pending, or whose tool input repeats an
    /// object member name at any depth (compared after decoding) is a
    /// protocol error: the session fails closed and the request is
    /// never answered, so no answer can ever carry another request's
    /// input. An input over `MAX_BRIDGED_INPUT_BYTES` is denied at once
    /// and never bridged. Callers hold `state`.
    fn bridge_locked(&self, st: &mut State, request_id: &str, req: &ControlRequest, raw: &[u8]) {
        let resources: Vec<String> = if req.blocked_path.is_empty() {
            Vec::new()
        } else {
            vec![req.blocked_path.clone()]
        };
        let duplicate = st.pending.contains_key(request_id);
        if duplicate || !protocol::bounded_request(request_id, req, &resources) {
            self.stop_locked(st, reasons::PERMISSION_BRIDGE_UNAVAILABLE);
            return;
        }
        let input = match crate::json::echoed_input(&req.input) {
            Ok(input) => input,
            Err(_) => {
                self.stop_locked(st, reasons::PERMISSION_BRIDGE_UNAVAILABLE);
                return;
            }
        };
        if input.len() > MAX_BRIDGED_INPUT_BYTES {
            if !req.tool_use_id.is_empty() {
                st.denied.insert(req.tool_use_id.clone());
            }
            self.answer_locked(
                st,
                permission_response_frame(request_id, false, &[], DENY_INPUT_TOO_LARGE),
                raw,
            );
            self.emit_locked(
                st,
                EventPayload::PermissionResolved(PermissionResolved {
                    request_id: request_id.to_string(),
                    decision: PermissionOutcome::Denied,
                    decided_by: DECIDED_BY_INPUT_TOO_LARGE.to_string(),
                }),
                raw,
            );
            return;
        }
        st.pending.insert(
            request_id.to_string(),
            PendingPermission {
                tool_use_id: req.tool_use_id.clone(),
                input: input.clone(),
            },
        );
        self.emit_locked(
            st,
            EventPayload::PermissionRequested(PermissionRequested {
                request_id: request_id.to_string(),
                tool_call_id: req.tool_use_id.clone(),
                tool: req.tool_name.clone(),
                resources,
                options: Vec::new(),
                input,
            }),
            raw,
        );
    }

    /// `onControlResponse` — an interrupt's acknowledgement is
    /// recorded; responses are never emitted.
    fn on_control_response(&self, f: &Frame) {
        let id = f.response_request_id();
        if id.is_empty() {
            return;
        }
        let mut st = self.state();
        st.interrupts.remove(&id);
    }

    /// `onResult` — every result's usage folds into the running totals,
    /// each counter raised to what live reports already carried (phase
    /// 3l decision 4). A result with queued turns left ends only its
    /// turn; only the last result ends the session.
    fn on_result(&self, f: &Frame, line: &[u8]) {
        let mut st = self.state();
        if st.stop_reason.is_some() || st.result.is_some() || self.before_init_locked(&mut st) {
            return;
        }
        st.usage = add_turn(st.usage, f.usage());
        st.reported = self.raised_locked(&st, st.usage);
        let usage = st.reported;
        self.emit_locked(
            &mut st,
            EventPayload::UsageReport(UsageReport { usage }),
            line,
        );
        if !f.last_result() {
            // An interrupt aborts only the running turn: queued turns
            // survive it, and the harness acknowledges the interrupt
            // before the aborted turn's result. So an acknowledged
            // interrupt is spent on the turn this result ends and must
            // not turn a later turn's unrelated error_during_execution
            // into Interrupted. One not yet acknowledged applies to the
            // next.
            let unacked = !st.interrupts.is_empty();
            st.interrupt_requested = unacked;
            return;
        }
        let t = map_result(f, st.auth_failed, st.interrupt_requested);
        // Phase 3e decision 8: the last successful result's text is the
        // top-level agent's final answer, emitted as the last assistant
        // Message so the orchestrator's last-Message-wins rule takes
        // the report from it and never from a subagent's text block.
        // An error result, or one without text, adds nothing.
        if t.status == TerminalStatus::Succeeded && !f.result.trim().is_empty() {
            self.emit_locked(
                &mut st,
                EventPayload::Message(Message {
                    role: MessageRole::Assistant,
                    text: f.result.clone(),
                    partial: false,
                }),
                line,
            );
        }
        st.result = Some(t);
        st.result_raw = Some(line.to_vec());
        st.pending.clear();
        drop(st);
        // Closing stdin after the result ends the harness process.
        self.close_stdin();
    }

    /// `run` — the single reader task.
    async fn run(self: &Arc<Self>) {
        let proc = self.proc.clone();
        let stderr = tokio::spawn(async move {
            // Stderr is drained and discarded: it may carry account
            // details.
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
        let _ = stderr.await;
        let status = wait_exit(&*self.proc, EXIT_GRACE).await;
        // The tree is gone, so a write still in flight fails; closing
        // stdin also frees one whose pipe is somehow still open.
        // Waiting for the writer keeps its failure warnings ahead of
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

    /// `writer` — the single stdin writer; it holds no lock while it
    /// writes.
    async fn writer(self: &Arc<Self>) {
        loop {
            let req = loop {
                {
                    let mut g = self.wq();
                    if let Some(r) = g.queue.pop_front() {
                        break Some(r);
                    }
                    if g.closed {
                        break None;
                    }
                }
                // `notify_one` stores a permit when no task waits, so a
                // push between the unlock and this await is not lost.
                self.wnotify.notified().await;
            };
            match req {
                None => {
                    let _ = self.proc.close_stdin().await;
                    return;
                }
                Some(r) => {
                    let res = match self.proc.write_stdin(&r.line).await {
                        Ok(n) if n == r.line.len() => Ok(()),
                        Ok(_) | Err(_) => Err(write_failed()),
                    };
                    if res.is_err()
                        && let Some(on_fail) = r.on_fail
                    {
                        on_fail();
                    }
                    if let Some(done) = r.done {
                        let _ = done.send(res);
                    }
                }
            }
        }
    }

    /// `finish` — computes the terminal, emits it and releases waiters.
    async fn finish(&self, status: Result<central_harness::port::ExitStatus, Failure>) {
        let kills = {
            let mut st = self.state();
            std::mem::take(&mut st.kills)
        };
        // The process has exited, so these joins return promptly; none
        // of them takes `state`.
        for k in kills {
            let _ = k.await;
        }
        let mut st = self.state();
        let mut t = if let Some(t) = st.result.clone() {
            t
        } else if let Some(reason) = st.stop_reason {
            Terminal {
                status: TerminalStatus::Failed,
                reason: reason.to_string(),
                ..Terminal::default()
            }
        } else if st.kill_requested {
            Terminal {
                status: TerminalStatus::Killed,
                ..Terminal::default()
            }
        } else {
            Terminal {
                status: TerminalStatus::Failed,
                reason: reasons::HARNESS_EXITED_WITHOUT_RESULT.to_string(),
                ..Terminal::default()
            }
        };
        if let Ok(status) = status {
            t.exit_code = Some(status.code);
        }
        let raw = st
            .result_raw
            .clone()
            .unwrap_or_else(|| stream_ended_frame(&t));
        st.pending.clear();
        st.finished = true;
        if !st.revealed {
            // `close(s.ref)`: a caller still waiting on the ref sees the
            // channel end.
            st.ref_tx.take();
        }
        self.emit_locked(
            &mut st,
            EventPayload::TerminalReported(TerminalReported {
                terminal: t.clone(),
            }),
            &raw,
        );
        // The terminal is queued last; dropping the sender lets the
        // receiver drain the buffer and then observe `None`.
        st.events_tx.take();
        drop(st);
        self.done.set(t);
    }
}

/// `{"type":"central_stream_ended","status":"…","reason":"…"}` — the
/// synthetic raw of a terminal that never saw a result frame;
/// `reason,omitempty` drops the field when empty.
fn stream_ended_frame(t: &Terminal) -> Vec<u8> {
    let mut b = Vec::with_capacity(96);
    b.extend_from_slice(b"{\"type\":\"central_stream_ended\",\"status\":");
    crate::json::push_json_string_html(&mut b, t.status.as_str());
    if !t.reason.is_empty() {
        b.extend_from_slice(b",\"reason\":");
        crate::json::push_json_string_html(&mut b, &t.reason);
    }
    b.push(b'}');
    b
}

/// `newRequestID` — a random RFC 4122 version 4 UUID. `/dev/urandom`
/// first; a hashed time/pid/counter mix is the fallback so the id is
/// always well-formed.
fn new_request_id() -> String {
    let mut b = [0u8; 16];
    let filled = std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .is_ok();
    if !filled {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let h = Sha256::digest(
            format!(
                "central-claudecode-{}-{}-{}",
                std::process::id(),
                nanos,
                SEQ.fetch_add(1, Ordering::Relaxed)
            )
            .as_bytes(),
        );
        b.copy_from_slice(&h[..16]);
    }
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    fn hex(b: &[u8]) -> String {
        b.iter().map(|c| format!("{c:02x}")).collect()
    }
    format!(
        "{}-{}-{}-{}-{}",
        hex(&b[0..4]),
        hex(&b[4..6]),
        hex(&b[6..8]),
        hex(&b[8..10]),
        hex(&b[10..16])
    )
}

/// `port::Session` — the live `claude` session handle.
pub(crate) struct ClaudeCodeSession {
    inner: Arc<Inner>,
}

impl ClaudeCodeSession {
    /// `newSession` + `begin` — constructs the state, spawns reader and
    /// writer, then queues the initialize request and the prompt. A
    /// failed write means the process is gone or its stdin is broken;
    /// stopping it lets the reader see EOF and report how the stream
    /// ended.
    pub(crate) fn spawn(cfg: SessionCfg, proc: Box<dyn Process>, prompt: &str) -> Self {
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        let (ref_tx, ref_rx) = oneshot::channel();
        let inner = Arc::new_cyclic(|me| Inner {
            cfg,
            proc: Arc::from(proc),
            state: Mutex::new(State {
                seq: 0,
                session_id: String::new(),
                revealed: false,
                pending: HashMap::new(),
                denied: HashSet::new(),
                auth_failed: false,
                interrupt_requested: false,
                interrupts: HashSet::new(),
                usage: Usage::default(),
                messages: HashMap::new(),
                live: LiveTokens::default(),
                // A report equal to this one raises nothing and is not
                // emitted live.
                reported: Usage {
                    scope: central_harness::event::UsageScope::SessionCumulative,
                    estimated: true,
                    ..Usage::default()
                },
                kill_requested: false,
                stop_reason: None,
                result: None,
                result_raw: None,
                finished: false,
                kills: Vec::new(),
                events_tx: Some(events_tx),
                ref_tx: Some(ref_tx),
            }),
            wq: Mutex::new(Wq {
                queue: VecDeque::new(),
                closed: false,
            }),
            wnotify: Notify::new(),
            events_rx: tokio::sync::Mutex::new(events_rx),
            ref_rx: Mutex::new(Some(ref_rx)),
            writer_done: Mutex::new(None),
            done: Outcome::new(),
            me: me.clone(),
        });
        let w = inner.clone();
        *inner.writer_done.lock().unwrap_or_else(|p| p.into_inner()) =
            Some(tokio::spawn(async move { w.writer().await }));
        let r = inner.clone();
        tokio::spawn(async move { r.run().await });
        {
            let mut st = inner.state();
            let me = inner.me.clone();
            let kill = move || {
                let Some(inner) = me.upgrade() else { return };
                let mut st = inner.state();
                inner.kill_async_locked(&mut st);
            };
            for line in [
                initialize_line(&new_request_id()),
                user_message_line(prompt),
            ] {
                match inner.enqueue(WriteReq {
                    line,
                    done: None,
                    on_fail: Some(Box::new(kill.clone())),
                }) {
                    Ok(()) => {}
                    Err(_) => {
                        inner.kill_async_locked(&mut st);
                        break;
                    }
                }
            }
        }
        Self { inner }
    }
}

impl Session for ClaudeCodeSession {
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

    /// `Events() <-chan Event` — the next normalized event; `None` once
    /// the stream closes after the terminal event.
    fn next_event(&self) -> PortFuture<'_, Option<Event>> {
        Box::pin(async move { self.inner.events_rx.lock().await.recv().await })
    }

    /// `Send` — operator follow-up text as a user message. The wait
    /// bounds only this caller: the queued line may still reach the
    /// harness if the future is dropped.
    fn send<'a>(&'a self, input: OperatorInput) -> PortFuture<'a, Result<(), Failure>> {
        Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            {
                let st = self.inner.state();
                if ended(&st) {
                    return Err(session_ended());
                }
                self.inner.enqueue(WriteReq {
                    line: user_message_line(&input.text),
                    done: Some(tx),
                    on_fail: None,
                })?;
            }
            match rx.await {
                Ok(r) => r,
                Err(_) => Err(write_failed()),
            }
        })
    }

    /// `Interrupt` — the harness-native cancel; `SESSION_ENDED` means
    /// the session already ended.
    fn interrupt(&self) -> PortFuture<'_, Result<(), Failure>> {
        Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            {
                let mut st = self.inner.state();
                if ended(&st) {
                    return Err(session_ended());
                }
                let id = new_request_id();
                st.interrupt_requested = true;
                st.interrupts.insert(id.clone());
                self.inner.enqueue(WriteReq {
                    line: interrupt_line(&id),
                    done: Some(tx),
                    on_fail: None,
                })?;
            }
            match rx.await {
                Ok(r) => r,
                Err(_) => Err(write_failed()),
            }
        })
    }

    /// `RespondPermission` — answers a pending `can_use_tool`. An allow
    /// binds `input_sha256` to the exact echoed bytes (phase 3c
    /// decision 8); a mismatch writes nothing and leaves the request
    /// pending. `PermissionResolved` is emitted when the answer is
    /// queued, not written: the harness can react only after reading
    /// the answer, and the reader needs `state` to report that
    /// reaction, so the resolution precedes it.
    fn respond_permission<'a>(
        &'a self,
        decision: PermissionDecision,
    ) -> PortFuture<'a, Result<(), Failure>> {
        Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            {
                let mut st = self.inner.state();
                let p = match st.pending.get(&decision.request_id) {
                    Some(p) if !ended(&st) => p.clone(),
                    _ => return Err(no_pending_permission()),
                };
                if decision.allow {
                    let digest: [u8; 32] = Sha256::digest(&p.input).into();
                    if !ct_eq(&digest, &decision.input_sha256) {
                        return Err(permission_binding());
                    }
                }
                st.pending.remove(&decision.request_id);
                let line = protocol::encode_line(permission_response_frame(
                    &decision.request_id,
                    decision.allow,
                    &p.input,
                    DENY_BY_OPERATOR,
                ));
                self.inner.enqueue(WriteReq {
                    line: line.clone(),
                    done: Some(tx),
                    on_fail: None,
                })?;
                let outcome = if decision.allow {
                    PermissionOutcome::Allowed
                } else {
                    st.denied.insert(p.tool_use_id.clone());
                    PermissionOutcome::Denied
                };
                self.inner.emit_locked(
                    &mut st,
                    EventPayload::PermissionResolved(PermissionResolved {
                        request_id: decision.request_id.clone(),
                        decision: outcome,
                        decided_by: decision.decided_by.clone(),
                    }),
                    &line,
                );
            }
            match rx.await {
                Ok(r) => r,
                Err(_) => Err(write_failed()),
            }
        })
    }

    /// `Wait` — the terminal once reader and process are both done.
    fn wait(&self) -> PortFuture<'_, Result<Terminal, Failure>> {
        Box::pin(async move { Ok(self.inner.done.wait().await) })
    }

    /// `Kill` — ends the process tree through the launcher's kill
    /// ladder. `state` is never held across a stdin write, so a stuck
    /// write cannot delay it; killing the tree fails that write.
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
}

/// `subtle.ConstantTimeCompare` for two digests.
fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut d = 0u8;
    for i in 0..32 {
        d |= a[i] ^ b[i];
    }
    d == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use central_harness::approval::{
        MAX_PERMISSION_REQUEST_ID_BYTES, MAX_PERMISSION_RESOURCE_BYTES, MAX_PERMISSION_RESOURCES,
        MAX_TOOL_CALL_ID_BYTES, MAX_TOOL_NAME_BYTES,
    };
    use central_harness::domain::TerminalStatus;

    /// `stream_ended_frame` byte shape (the synthetic raw of a
    /// result-less terminal).
    #[test]
    fn stream_ended_frames() {
        let t = Terminal {
            status: TerminalStatus::Failed,
            reason: reasons::HARNESS_EXITED_WITHOUT_RESULT.to_string(),
            ..Terminal::default()
        };
        assert_eq!(
            stream_ended_frame(&t),
            br#"{"type":"central_stream_ended","status":"failed","reason":"harness_exited_without_result"}"#
        );
        let t = Terminal {
            status: TerminalStatus::Killed,
            ..Terminal::default()
        };
        assert_eq!(
            stream_ended_frame(&t),
            br#"{"type":"central_stream_ended","status":"killed"}"#
        );
    }

    /// `boundedRequest`'s decision-5 bounds.
    #[test]
    fn bounded_request_bounds() {
        let req = |name: &str, tuid: &str| ControlRequest {
            tool_name: name.to_string(),
            tool_use_id: tuid.to_string(),
            ..ControlRequest::default()
        };
        assert!(protocol::bounded_request("r1", &req("Bash", "t1"), &[]));
        assert!(!protocol::bounded_request(
            &"r".repeat(MAX_PERMISSION_REQUEST_ID_BYTES + 1),
            &req("Bash", "t1"),
            &[]
        ));
        assert!(!protocol::bounded_request(
            "r1",
            &req("Bash", &"t".repeat(MAX_TOOL_CALL_ID_BYTES + 1)),
            &[]
        ));
        assert!(!protocol::bounded_request(
            "r1",
            &req(&"n".repeat(MAX_TOOL_NAME_BYTES + 1), "t1"),
            &[]
        ));
        assert!(!protocol::bounded_request("r1", &req("Ba\nsh", "t1"), &[]));
        assert!(!protocol::bounded_request(
            "r1",
            &req("Bash", "t1"),
            &vec![String::new(); MAX_PERMISSION_RESOURCES + 1]
        ));
        assert!(!protocol::bounded_request(
            "r1",
            &req("Bash", "t1"),
            &["x".repeat(MAX_PERMISSION_RESOURCE_BYTES + 1)]
        ));
        assert!(protocol::bounded_request(
            "r1",
            &req("Bash", "t1"),
            &["/p".to_string()]
        ));
    }

    /// `TestBoundedRequestAcceptsEveryFieldExactlyAtItsLimit` — the
    /// resources-array companion of the black-box at-limit bridging
    /// tests: the real wire protocol only ever sends one blocked_path,
    /// so the multi-resource bounds are exercised here directly, at
    /// every phase 3c bound at once.
    #[test]
    fn bounded_request_accepts_every_field_exactly_at_its_limit() {
        let req = ControlRequest {
            tool_name: "n".repeat(MAX_TOOL_NAME_BYTES),
            tool_use_id: "t".repeat(MAX_TOOL_CALL_ID_BYTES),
            ..ControlRequest::default()
        };
        let resources = vec!["p".repeat(MAX_PERMISSION_RESOURCE_BYTES); MAX_PERMISSION_RESOURCES];
        let request_id = "r".repeat(MAX_PERMISSION_REQUEST_ID_BYTES);
        assert!(
            protocol::bounded_request(&request_id, &req, &resources),
            "a request exactly at every phase 3c bound was rejected"
        );
        assert!(
            !protocol::bounded_request(&format!("{request_id}r"), &req, &resources),
            "a request id one byte over the limit was accepted"
        );
        let mut one_too_many = resources.clone();
        one_too_many.push("one too many".to_string());
        assert!(
            !protocol::bounded_request(&request_id, &req, &one_too_many),
            "one resource over the limit count was accepted"
        );
    }

    /// `echoedInput` — compact form, `{}` for absent, and the decoded
    /// duplicate-key refusal at every depth.
    #[test]
    fn echoed_input_rules() {
        use crate::json::{JsonError, echoed_input};
        assert_eq!(echoed_input(b"").unwrap(), b"{}");
        assert_eq!(
            echoed_input(b"{ \"cmd\" : \"ls\" }").unwrap(),
            br#"{"cmd":"ls"}"#
        );
        // Numbers keep their literal spelling (UseNumber upstream).
        assert_eq!(echoed_input(b"{\"n\":1e999}").unwrap(), br#"{"n":1e999}"#);
        // Duplicate keys — including escape-spelling collisions and
        // nested ones — are refused.
        assert_eq!(
            echoed_input(br#"{"a":1,"a":2}"#),
            Err(JsonError::DuplicateKey)
        );
        // An escaped member-name spelling ("a") collides with
        // "a" once decoded — the scan compares decoded names.
        assert_eq!(
            echoed_input(b"{\"a\":1,\"\\u0061\":2}"),
            Err(JsonError::DuplicateKey)
        );
        assert_eq!(
            echoed_input(br#"{"o":{"x":1,"x":2}}"#),
            Err(JsonError::DuplicateKey)
        );
        assert_eq!(echoed_input(b"not json"), Err(JsonError::Malformed));
    }

    /// `new_request_id` shape.
    #[test]
    fn request_id_is_uuid4() {
        let id = new_request_id();
        assert_eq!(id.len(), 36);
        assert_eq!(id.as_bytes()[14], b'4');
        assert!(matches!(id.as_bytes()[19], b'8' | b'9' | b'a' | b'b'));
    }
}
