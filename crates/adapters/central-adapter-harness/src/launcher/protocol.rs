//! The CHL1 v1 frame codec — byte-for-byte
//! `cmd/central-harness-launcherd/PROTOCOL.md` (ADR 0036, phase 2b spec
//! decisions 5, 6 and 15), a pure port of upstream
//! `internal/harnesslauncher/protocol.go`.
//!
//! This module performs no I/O and owns no socket: it is the codec both
//! the launcher client ([`super::client`]) and `central-harness-launcherd`
//! share. Every encode applies the caps and shape rules the daemon
//! enforces; every failure carries a stable code from [`codes`] — the
//! `errors.Is` surface upstream callers match on.

use std::collections::HashSet;
use std::fmt;
use std::time::Duration;

use central_foundation::failure::Failure;

// Wire constants (PROTOCOL.md §1–§3).
/// The CHL1 protocol version byte.
pub const PROTOCOL_VERSION: u8 = 1;
/// Every frame's header size.
pub const HEADER_SIZE: usize = 8;
/// Every daemon response size.
pub const RESPONSE_SIZE: usize = 12;
/// The exact ALIVE request size.
pub const ALIVE_REQUEST_SIZE: usize = 24;
/// The exact KILL request size.
pub const KILL_REQUEST_SIZE: usize = 28;
/// A whole request datagram cap (spec decision 5).
pub const MAX_FRAME: usize = 64 * 1024;

/// The `harness` id length cap.
pub const MAX_HARNESS: usize = 32;
/// The workdir length cap.
pub const MAX_WORK_DIR: usize = 4096;
/// The argv count cap.
pub const MAX_ARGS: usize = 64;
/// One argv entry's length cap.
pub const MAX_ARG: usize = 4096;
/// The env entry count cap.
pub const MAX_ENV: usize = 64;
/// One env entry's length cap.
pub const MAX_ENV_ENTRY: usize = 8192;
/// KILL's grace cap in whole milliseconds (spec decision 5):
/// `MaxKillGrace` = 30 s.
pub const MAX_KILL_GRACE_MS: u32 = 30_000;
/// KILL's grace cap as a duration — `MaxKillGrace`.
pub const MAX_KILL_GRACE: Duration = Duration::from_millis(MAX_KILL_GRACE_MS as u64);

const MAGIC: [u8; 4] = *b"CHL1";

/// Stable machine codes standing in for the upstream `Err*` sentinels —
/// the `errors.Is` surface of `internal/harnesslauncher`.
pub mod codes {
    /// `ErrPeerDenied`.
    pub const PEER_DENIED: &str = "harnesslauncher_peer_denied";
    /// `ErrConfigInvalid`.
    pub const CONFIG_INVALID: &str = "harnesslauncher_config_invalid";
    /// `ErrRequestMalformed`.
    pub const REQUEST_MALFORMED: &str = "harnesslauncher_request_malformed";
    /// `ErrUnknownHarness`.
    pub const UNKNOWN_HARNESS: &str = "harnesslauncher_unknown_harness";
    /// `ErrWorkdirInvalid`.
    pub const WORKDIR_INVALID: &str = "harnesslauncher_workdir_invalid";
    /// `ErrArgvRefused`.
    pub const ARGV_REFUSED: &str = "harnesslauncher_argv_refused";
    /// `ErrEnvRefused`.
    pub const ENV_REFUSED: &str = "harnesslauncher_env_refused";
    /// `ErrScopeBusy`.
    pub const SCOPE_BUSY: &str = "harnesslauncher_scope_busy";
    /// `ErrOperatorInvalid`.
    pub const OPERATOR_INVALID: &str = "harnesslauncher_operator_invalid";
    /// `ErrLaunchFailed`.
    pub const LAUNCH_FAILED: &str = "harnesslauncher_launch_failed";
    /// `ErrMalformedResponse` — a daemon frame that breaks PROTOCOL.md.
    pub const MALFORMED_RESPONSE: &str = "harnesslauncher_malformed_response";
    /// `ErrPeerNotRoot` — the socket's peer is not the root daemon
    /// (client-side check, upstream `client_linux.go`).
    pub const PEER_NOT_ROOT: &str = "harnesslauncher_peer_not_root";
    /// `ErrBadDescriptors` — a started LAUNCH did not carry exactly the
    /// three pipe ends and the pidfd of PROTOCOL.md §3.1.2.
    pub const BAD_DESCRIPTORS: &str = "harnesslauncher_bad_descriptors";
    /// `ErrLifelineLost` — the lifeline ended with no EXIT: the launcher
    /// itself ended the session.
    pub const LIFELINE_LOST: &str = "harnesslauncher_lifeline_lost";
    /// `ErrClosed` — the launch was closed before its EXIT was read.
    pub const CLOSED: &str = "harnesslauncher_closed";
    /// Generic client transport failures (dial, write, receive) — the
    /// upstream `"harness launcher: <op>: %w"` wraps.
    pub const TRANSPORT: &str = "harnesslauncher_transport";
}

fn malformed(msg: impl Into<String>) -> Failure {
    Failure::invalid(codes::REQUEST_MALFORMED, msg)
}

fn malformed_response(msg: impl Into<String>) -> Failure {
    Failure::internal(codes::MALFORMED_RESPONSE, msg)
}

/// A frame's operation — upstream `Opcode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum Opcode {
    /// `OpLaunch` — client → daemon, and its response.
    #[default]
    Launch = 1,
    /// `OpAlive` — client → daemon, and its response.
    Alive = 2,
    /// `OpKill` — client → daemon, and its response.
    Kill = 3,
    /// `OpExit` — daemon → client only, on a LAUNCH connection.
    Exit = 4,
}

impl Opcode {
    fn from_byte(b: u8) -> Self {
        match b {
            1 => Self::Launch,
            2 => Self::Alive,
            3 => Self::Kill,
            _ => Self::Exit,
        }
    }
}

/// A response status — upstream `Reason`. [`Reason::Ok`] or one of the
/// fixed reason codes of PROTOCOL.md §5; the daemon never echoes a
/// request value with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum Reason {
    /// Status 0.
    #[default]
    Ok = 0,
    /// `peer_denied`.
    PeerDenied = 1,
    /// `config_invalid`.
    ConfigInvalid = 2,
    /// `request_malformed`.
    RequestMalformed = 3,
    /// `unknown_harness`.
    UnknownHarness = 4,
    /// `workdir_invalid`.
    WorkdirInvalid = 5,
    /// `argv_refused`.
    ArgvRefused = 6,
    /// `env_refused`.
    EnvRefused = 7,
    /// `scope_busy`.
    ScopeBusy = 8,
    /// `operator_invalid`.
    OperatorInvalid = 9,
    /// `launch_failed`.
    LaunchFailed = 10,
}

impl Reason {
    fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            0 => Self::Ok,
            1 => Self::PeerDenied,
            2 => Self::ConfigInvalid,
            3 => Self::RequestMalformed,
            4 => Self::UnknownHarness,
            5 => Self::WorkdirInvalid,
            6 => Self::ArgvRefused,
            7 => Self::EnvRefused,
            8 => Self::ScopeBusy,
            9 => Self::OperatorInvalid,
            10 => Self::LaunchFailed,
            _ => return None,
        })
    }

    /// The reason's wire name — PROTOCOL.md §5.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::PeerDenied => "peer_denied",
            Self::ConfigInvalid => "config_invalid",
            Self::RequestMalformed => "request_malformed",
            Self::UnknownHarness => "unknown_harness",
            Self::WorkdirInvalid => "workdir_invalid",
            Self::ArgvRefused => "argv_refused",
            Self::EnvRefused => "env_refused",
            Self::ScopeBusy => "scope_busy",
            Self::OperatorInvalid => "operator_invalid",
            Self::LaunchFailed => "launch_failed",
        }
    }

    /// Upstream `Reason.Err()`: the sentinel [`Failure`] for the reason,
    /// or `None` for [`Reason::Ok`]. An unknown reason maps onto
    /// [`codes::MALFORMED_RESPONSE`], but every [`Reason`] is known by
    /// construction — kept for upstream API parity.
    #[must_use]
    pub fn err(self) -> Option<Failure> {
        let (kind, code) = match self {
            Self::Ok => return None,
            Self::PeerDenied => (
                central_foundation::failure::FailureKind::Denied,
                codes::PEER_DENIED,
            ),
            Self::ConfigInvalid => (
                central_foundation::failure::FailureKind::Internal,
                codes::CONFIG_INVALID,
            ),
            Self::RequestMalformed => (
                central_foundation::failure::FailureKind::Invalid,
                codes::REQUEST_MALFORMED,
            ),
            Self::UnknownHarness => (
                central_foundation::failure::FailureKind::NotFound,
                codes::UNKNOWN_HARNESS,
            ),
            Self::WorkdirInvalid => (
                central_foundation::failure::FailureKind::Invalid,
                codes::WORKDIR_INVALID,
            ),
            Self::ArgvRefused => (
                central_foundation::failure::FailureKind::Denied,
                codes::ARGV_REFUSED,
            ),
            Self::EnvRefused => (
                central_foundation::failure::FailureKind::Denied,
                codes::ENV_REFUSED,
            ),
            Self::ScopeBusy => (
                central_foundation::failure::FailureKind::Conflict,
                codes::SCOPE_BUSY,
            ),
            Self::OperatorInvalid => (
                central_foundation::failure::FailureKind::Internal,
                codes::OPERATOR_INVALID,
            ),
            Self::LaunchFailed => (
                central_foundation::failure::FailureKind::Internal,
                codes::LAUNCH_FAILED,
            ),
        };
        Some(Failure::new(
            kind,
            code,
            format!("harness launcher: {}", self.as_str()),
        ))
    }
}

/// A launch scope id — upstream `Scope`: a non-nil UUID sent as 16 raw
/// bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Scope(pub [u8; 16]);

impl Scope {
    fn is_nil(&self) -> bool {
        self.0 == [0u8; 16]
    }
}

/// Upstream `ParseScope`: accepts only the canonical lower-case
/// 8-4-4-4-12 form of a non-nil UUID.
pub fn parse_scope(s: &str) -> Result<Scope, Failure> {
    let bad = |msg: &str| Failure::invalid(codes::REQUEST_MALFORMED, msg.to_string());
    let b = s.as_bytes();
    if b.len() != 36 {
        return Err(bad("scope is not a canonical UUID"));
    }
    let mut out = [0u8; 16];
    let mut j = 0usize;
    let mut i = 0usize;
    while i < 36 {
        match i {
            8 | 13 | 18 | 23 => {
                if b[i] != b'-' {
                    return Err(bad("scope is not a canonical UUID"));
                }
                i += 1;
            }
            _ => {
                let (Some(hi), Some(lo)) = (hex_nibble(b[i]), hex_nibble(b[i + 1])) else {
                    return Err(bad("scope is not a canonical UUID"));
                };
                out[j] = hi << 4 | lo;
                j += 1;
                i += 2;
            }
        }
    }
    let scope = Scope(out);
    if scope.is_nil() {
        return Err(bad("scope is the nil UUID"));
    }
    Ok(scope)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

impl fmt::Display for Scope {
    /// The canonical lower-case form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(36);
        for (i, b) in self.0.iter().enumerate() {
            if matches!(i, 4 | 6 | 8 | 10) {
                out.push('-');
            }
            out.push(DIGITS[(b >> 4) as usize] as char);
            out.push(DIGITS[(b & 0x0f) as usize] as char);
        }
        f.write_str(&out)
    }
}

/// The whole caller-controlled LAUNCH surface (spec decision 6) —
/// upstream `LaunchRequest`. Env entries are `NAME=value`; the daemon
/// re-validates them. `Debug` redacts like [`fmt::Display`]: argv,
/// workdir and env values are never printed (they can carry secrets).
#[derive(Clone, PartialEq, Eq, Default)]
pub struct LaunchRequest {
    /// The scope id.
    pub scope: Scope,
    /// The symbolic harness id the daemon resolves.
    pub harness: String,
    /// The workdir: relative to `worktree_root`, or empty for a probe.
    pub work_dir: String,
    /// The argv entries — never printed.
    pub argv: Vec<String>,
    /// The `NAME=value` env entries — values never printed.
    pub env: Vec<String>,
}

impl fmt::Display for LaunchRequest {
    /// Upstream `String`/`GoString`: never argv or env values.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "harnesslauncher.LaunchRequest{{Scope:{} Harness:{} WorkDirBytes:{} Args:<{}> Env:<{}>}}",
            self.scope,
            self.harness,
            self.work_dir.len(),
            self.argv.len(),
            self.env.len()
        )
    }
}

impl fmt::Debug for LaunchRequest {
    /// `GoString` — the same redaction `Display` applies.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// One decoded request frame — upstream `Request`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Request {
    /// The frame's opcode.
    pub op: Opcode,
    /// The decoded LAUNCH surface ([`Opcode::Launch`] only).
    pub launch: LaunchRequest,
    /// The scope (`Opcode::Alive`/`Opcode::Kill`, and `launch.scope` for
    /// `Opcode::Launch`).
    pub scope: Scope,
    /// KILL's grace in whole milliseconds (`Opcode::Kill` only).
    pub grace_ms: u32,
}

/// The harness's end as the daemon reports it (spec decision 4) —
/// upstream `Exit`. `signaled` is `true` when a signal ended it; `code`
/// is then `128 + signal`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Exit {
    /// The exit code 0–255, or `128 + signal` when `signaled`.
    pub code: i32,
    /// Whether a signal ended the process.
    pub signaled: bool,
}

/// One decoded daemon frame — upstream `Response`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Response {
    /// The frame's opcode.
    pub op: Opcode,
    /// The reason code.
    pub status: Reason,
    /// The ALIVE bit ([`Opcode::Alive`] with [`Reason::Ok`]).
    pub alive: bool,
    /// The EXIT payload ([`Opcode::Exit`]).
    pub exit: Exit,
}

fn header(op: Opcode) -> Vec<u8> {
    let mut frame = Vec::with_capacity(64);
    frame.extend_from_slice(&MAGIC);
    frame.push(PROTOCOL_VERSION);
    frame.push(op as u8);
    frame.push(0);
    frame.push(0);
    frame
}

fn valid_harness(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= MAX_HARNESS
        && h.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

/// `validateLaunch` — every per-field cap and shape rule of PROTOCOL.md
/// §3.1 except the total size, which needs the encoding.
fn validate_launch(r: &LaunchRequest) -> Result<(), Failure> {
    if r.scope.is_nil() {
        return Err(malformed("nil scope"));
    }
    if !valid_harness(&r.harness) {
        return Err(malformed(format!(
            "harness id must be 1-{MAX_HARNESS} bytes of [a-z0-9-]"
        )));
    }
    if r.work_dir.len() > MAX_WORK_DIR || r.work_dir.as_bytes().contains(&0) {
        return Err(malformed(format!(
            "workdir exceeds {MAX_WORK_DIR} bytes or holds NUL"
        )));
    }
    if r.argv.len() > MAX_ARGS {
        return Err(malformed(format!("more than {MAX_ARGS} args")));
    }
    for (i, a) in r.argv.iter().enumerate() {
        if a.len() > MAX_ARG || a.as_bytes().contains(&0) {
            return Err(malformed(format!(
                "arg {i} exceeds {MAX_ARG} bytes or holds NUL"
            )));
        }
    }
    if r.env.len() > MAX_ENV {
        return Err(malformed(format!("more than {MAX_ENV} env entries")));
    }
    let mut names: HashSet<&str> = HashSet::with_capacity(r.env.len());
    for (i, e) in r.env.iter().enumerate() {
        if e.is_empty() || e.len() > MAX_ENV_ENTRY || e.as_bytes().contains(&0) {
            return Err(malformed(format!(
                "env entry {i} is empty, exceeds {MAX_ENV_ENTRY} bytes or holds NUL"
            )));
        }
        let Some(eq) = e.find('=') else {
            return Err(malformed(format!("env entry {i} has no '='")));
        };
        if !names.insert(&e[..eq]) {
            return Err(malformed(format!("env entry {i} repeats a name")));
        }
    }
    Ok(())
}

/// Upstream `EncodeLaunch`: the LAUNCH frame, or a
/// [`codes::REQUEST_MALFORMED`] failure when `r` breaks a cap or rule the
/// daemon enforces.
pub fn encode_launch(r: &LaunchRequest) -> Result<Vec<u8>, Failure> {
    validate_launch(r)?;
    let mut frame = header(Opcode::Launch);
    frame.extend_from_slice(&r.scope.0);
    frame.push(r.harness.len() as u8);
    frame.extend_from_slice(r.harness.as_bytes());
    frame.extend_from_slice(&(r.work_dir.len() as u16).to_be_bytes());
    frame.extend_from_slice(r.work_dir.as_bytes());
    frame.push(r.argv.len() as u8);
    for a in &r.argv {
        frame.extend_from_slice(&(a.len() as u16).to_be_bytes());
        frame.extend_from_slice(a.as_bytes());
    }
    frame.push(r.env.len() as u8);
    for e in &r.env {
        frame.extend_from_slice(&(e.len() as u16).to_be_bytes());
        frame.extend_from_slice(e.as_bytes());
    }
    if frame.len() > MAX_FRAME {
        return Err(malformed(format!(
            "frame is {} bytes, over the {MAX_FRAME}-byte cap",
            frame.len()
        )));
    }
    Ok(frame)
}

/// Upstream `EncodeAlive`: the ALIVE frame.
pub fn encode_alive(scope: Scope) -> Result<Vec<u8>, Failure> {
    if scope.is_nil() {
        return Err(malformed("nil scope"));
    }
    let mut frame = header(Opcode::Alive);
    frame.extend_from_slice(&scope.0);
    Ok(frame)
}

/// Upstream `EncodeKill`: the KILL frame. `grace` is sent in whole
/// milliseconds and must lie in `[0, MAX_KILL_GRACE]`.
pub fn encode_kill(scope: Scope, grace: Duration) -> Result<Vec<u8>, Failure> {
    if scope.is_nil() {
        return Err(malformed("nil scope"));
    }
    if grace > MAX_KILL_GRACE {
        return Err(malformed(format!(
            "kill grace outside [0, {}ms]",
            MAX_KILL_GRACE_MS
        )));
    }
    let mut frame = header(Opcode::Kill);
    frame.extend_from_slice(&scope.0);
    frame.extend_from_slice(&(grace.as_millis() as u32).to_be_bytes());
    Ok(frame)
}

fn valid_request_header(frame: &[u8]) -> Result<Opcode, Failure> {
    if frame.len() < HEADER_SIZE {
        return Err(malformed("frame shorter than the header"));
    }
    if frame.len() > MAX_FRAME {
        return Err(malformed(format!("frame over the {MAX_FRAME}-byte cap")));
    }
    if frame[..4] != MAGIC || frame[4] != PROTOCOL_VERSION || frame[6] != 0 || frame[7] != 0 {
        return Err(malformed("bad magic, version or reserved header byte"));
    }
    Ok(Opcode::from_byte(frame[5]))
}

/// `reader` walks a LAUNCH body; any overrun marks it failed.
struct Reader<'a> {
    b: &'a [u8],
    bad: bool,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> &'a [u8] {
        if self.bad || n > self.b.len() {
            self.bad = true;
            return &[];
        }
        let (out, rest) = self.b.split_at(n);
        self.b = rest;
        out
    }

    fn u8(&mut self) -> usize {
        let b = self.take(1);
        if self.bad {
            return 0;
        }
        usize::from(b[0])
    }

    fn u16(&mut self) -> usize {
        let b = self.take(2);
        if self.bad {
            return 0;
        }
        usize::from(u16::from_be_bytes([b[0], b[1]]))
    }
}

/// Upstream `DecodeRequest`: parses a request frame exactly as the
/// daemon does. Every failure carries [`codes::REQUEST_MALFORMED`].
pub fn decode_request(frame: &[u8]) -> Result<Request, Failure> {
    let op = valid_request_header(frame)?;
    match op {
        Opcode::Alive => {
            if frame.len() != ALIVE_REQUEST_SIZE {
                return Err(malformed(format!(
                    "ALIVE frame is not {ALIVE_REQUEST_SIZE} bytes"
                )));
            }
            let mut s = Scope::default();
            s.0.copy_from_slice(&frame[8..24]);
            if s.is_nil() {
                return Err(malformed("nil scope"));
            }
            return Ok(Request {
                op,
                scope: s,
                ..Request::default()
            });
        }
        Opcode::Kill => {
            if frame.len() != KILL_REQUEST_SIZE {
                return Err(malformed(format!(
                    "KILL frame is not {KILL_REQUEST_SIZE} bytes"
                )));
            }
            let mut s = Scope::default();
            s.0.copy_from_slice(&frame[8..24]);
            let grace = u32::from_be_bytes([frame[24], frame[25], frame[26], frame[27]]);
            if s.is_nil() || grace > MAX_KILL_GRACE_MS {
                return Err(malformed("nil scope or kill grace over the cap"));
            }
            return Ok(Request {
                op,
                scope: s,
                grace_ms: grace,
                ..Request::default()
            });
        }
        Opcode::Launch => {}
        Opcode::Exit => {
            return Err(malformed(format!("unknown request opcode {}", frame[5])));
        }
    }
    let mut r = Reader {
        b: &frame[HEADER_SIZE..],
        bad: false,
    };
    let mut l = LaunchRequest::default();
    // A short take copies a prefix, as Go's `copy` does; the frame is
    // then refused as truncated below.
    let scope_bytes = r.take(16);
    l.scope.0[..scope_bytes.len()].copy_from_slice(scope_bytes);
    // Reads past a marked-bad reader stay empty, exactly as upstream's
    // `take` returning nil leaves zero values.
    let hlen = r.u8();
    l.harness = String::from_utf8_lossy(r.take(hlen)).into_owned();
    let wlen = r.u16();
    l.work_dir = String::from_utf8_lossy(r.take(wlen)).into_owned();
    let argc = r.u8();
    if argc > MAX_ARGS {
        return Err(malformed(format!("more than {MAX_ARGS} args")));
    }
    for _ in 0..argc {
        if r.bad {
            break;
        }
        let alen = r.u16();
        l.argv
            .push(String::from_utf8_lossy(r.take(alen)).into_owned());
    }
    let envc = r.u8();
    if envc > MAX_ENV {
        return Err(malformed(format!("more than {MAX_ENV} env entries")));
    }
    for _ in 0..envc {
        if r.bad {
            break;
        }
        let elen = r.u16();
        l.env
            .push(String::from_utf8_lossy(r.take(elen)).into_owned());
    }
    if r.bad {
        return Err(malformed("LAUNCH frame is truncated"));
    }
    if !r.b.is_empty() {
        return Err(malformed(format!(
            "LAUNCH frame has {} trailing bytes",
            r.b.len()
        )));
    }
    validate_launch(&l)?;
    Ok(Request {
        op,
        scope: l.scope,
        launch: l,
        grace_ms: 0,
    })
}

fn valid_exit(e: Exit) -> bool {
    if e.signaled {
        e.code > 128 && e.code <= 128 + 64
    } else {
        (0..=255).contains(&e.code)
    }
}

/// Upstream `EncodeResponse`: a 12-byte daemon frame. Used by tests and
/// fakes; the daemon is the only real producer.
pub fn encode_response(r: &Response) -> Result<Vec<u8>, Failure> {
    // `Reason` is a closed enum — every value is known by construction.
    let mut frame = header(r.op);
    frame[6] = r.status as u8;
    frame.extend_from_slice(&[0, 0, 0, 0]);
    match r.op {
        Opcode::Launch | Opcode::Kill => {}
        Opcode::Alive => {
            if r.alive && r.status == Reason::Ok {
                frame[8] = 1;
            }
        }
        Opcode::Exit => {
            if r.status != Reason::Ok || !valid_exit(r.exit) {
                return Err(malformed_response("invalid EXIT"));
            }
            if r.exit.signaled {
                frame[8] = 1;
            }
            frame[10..12].copy_from_slice(&(r.exit.code as u16).to_be_bytes());
        }
    }
    Ok(frame)
}

/// Upstream `DecodeResponse`: parses a daemon frame whose opcode must be
/// `want`. Every failure carries [`codes::MALFORMED_RESPONSE`].
pub fn decode_response(frame: &[u8], want: Opcode) -> Result<Response, Failure> {
    let bad = |what: &str| Err(malformed_response(what.to_string()));
    if frame.len() != RESPONSE_SIZE {
        return bad("response is not 12 bytes");
    }
    if frame[..4] != MAGIC || frame[4] != PROTOCOL_VERSION || frame[7] != 0 {
        return bad("bad magic, version or reserved byte");
    }
    if Opcode::from_byte(frame[5]) != want {
        return bad("unexpected opcode");
    }
    let Some(status) = Reason::from_byte(frame[6]) else {
        return bad("unknown reason code");
    };
    let mut r = Response {
        op: want,
        status,
        alive: false,
        exit: Exit::default(),
    };
    let payload = &frame[8..12];
    match want {
        Opcode::Launch | Opcode::Kill => {
            if payload[0] | payload[1] | payload[2] | payload[3] != 0 {
                return bad("non-zero payload");
            }
        }
        Opcode::Alive => {
            if payload[1] | payload[2] | payload[3] != 0
                || payload[0] > 1
                || (payload[0] == 1 && status != Reason::Ok)
            {
                return bad("invalid ALIVE payload");
            }
            r.alive = payload[0] == 1;
        }
        Opcode::Exit => {
            if status != Reason::Ok || payload[0] > 1 || payload[1] != 0 {
                return bad("invalid EXIT header");
            }
            r.exit = Exit {
                signaled: payload[0] == 1,
                code: i32::from(u16::from_be_bytes([payload[2], payload[3]])),
            };
            if !valid_exit(r.exit) {
                return bad("EXIT code out of range");
            }
        }
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SCOPE: Scope = Scope([
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef,
    ]);

    fn is_code(err: &Failure, code: &str) -> bool {
        err.code() == code
    }

    fn session_request() -> LaunchRequest {
        LaunchRequest {
            scope: TEST_SCOPE,
            harness: "claude".to_string(),
            work_dir: "attempt-1/repo".to_string(),
            argv: vec![
                "-p".to_string(),
                "--verbose".to_string(),
                "--output-format".to_string(),
                "stream-json".to_string(),
                "--input-format".to_string(),
                "stream-json".to_string(),
                "--setting-sources".to_string(),
                "user".to_string(),
                "--session-id".to_string(),
                "0e5c1f7a-3b1d-4c89-9a51-6c2f04b7d3e8".to_string(),
                "--permission-mode".to_string(),
                "dontAsk".to_string(),
                "--permission-prompts".to_string(),
                "none".to_string(),
                "--model".to_string(),
                "haiku".to_string(),
            ],
            env: vec!["LANG=C.UTF-8".to_string(), "PATH=/usr/bin:/bin".to_string()],
        }
    }

    /// Upstream `TestParseScopeAcceptsOnlyCanonicalNonNilUUIDs`.
    #[test]
    fn parse_scope_accepts_only_canonical_non_nil_uuids() {
        let s = parse_scope("01234567-89ab-cdef-0123-456789abcdef").unwrap();
        assert_eq!(s, TEST_SCOPE);
        assert_eq!(s.to_string(), "01234567-89ab-cdef-0123-456789abcdef");
        for bad in [
            "",
            "01234567-89AB-cdef-0123-456789abcdef",
            "0123456789abcdef0123456789abcdef",
            "01234567-89ab-cdef-0123-456789abcde",
            "01234567-89ab-cdef-0123-456789abcdeff",
            "01234567_89ab-cdef-0123-456789abcdef",
            "0123456g-89ab-cdef-0123-456789abcdef",
            "00000000-0000-0000-0000-000000000000",
            "live-probe-0123",
        ] {
            let err = parse_scope(bad).unwrap_err();
            assert!(
                is_code(&err, codes::REQUEST_MALFORMED),
                "ParseScope({bad:?}) err = {err}"
            );
        }
    }

    /// Upstream `TestLaunchRoundTripAndExactLayout`.
    #[test]
    fn launch_round_trip_and_exact_layout() {
        let req = session_request();
        let frame = encode_launch(&req).unwrap();
        assert_eq!(&frame[..8], b"CHL1\x01\x01\x00\x00", "header = {frame:x?}");
        assert_eq!(&frame[8..24], &TEST_SCOPE.0[..]);
        assert_eq!(frame[24], 6);
        assert_eq!(&frame[25..31], b"claude");
        assert_eq!(
            u16::from_be_bytes([frame[31], frame[32]]) as usize,
            req.work_dir.len()
        );
        let got = decode_request(&frame).unwrap();
        assert_eq!(got.op, Opcode::Launch);
        assert_eq!(got.scope, TEST_SCOPE);
        assert_eq!(got.launch, req);

        let probe = LaunchRequest {
            scope: TEST_SCOPE,
            harness: "claude".to_string(),
            argv: vec!["--version".to_string()],
            ..LaunchRequest::default()
        };
        let frame = encode_launch(&probe).unwrap();
        let want = 8 + 16 + 1 + 6 + 2 + 1 + 2 + 9 + 1;
        assert_eq!(frame.len(), want, "probe frame = {} bytes", frame.len());
        let got = decode_request(&frame).unwrap();
        assert_eq!(got.launch.work_dir, "");
        assert_eq!(got.launch.argv, probe.argv);
        assert!(got.launch.env.is_empty());
    }

    /// Upstream `TestLaunchRequestStringHidesValues`.
    #[test]
    fn launch_request_display_hides_values() {
        let mut req = session_request();
        req.env.push("LC_SECRETISH=hunter2".to_string());
        let s = format!("{req}");
        let d = format!("{req:?}");
        for s in [s, d] {
            assert!(
                !s.contains("hunter2") && !s.contains("haiku") && !s.contains("attempt-1"),
                "Display leaks a value: {s}"
            );
        }
    }

    /// Upstream `envEntries`.
    fn env_entries(n: usize) -> Vec<String> {
        (0..n)
            .map(|i| format!("LC_{}=v", "X".repeat(i + 1)))
            .collect()
    }

    /// Upstream `rawLaunch`: encodes with no validation. Reports `None`
    /// when a length does not fit its wire field.
    fn raw_launch(r: &LaunchRequest) -> Option<Vec<u8>> {
        if r.harness.len() > 255
            || r.work_dir.len() > 65535
            || r.argv.len() > 255
            || r.env.len() > 255
        {
            return None;
        }
        let mut frame = b"CHL1\x01\x01\x00\x00".to_vec();
        frame.extend_from_slice(&r.scope.0);
        frame.push(r.harness.len() as u8);
        frame.extend_from_slice(r.harness.as_bytes());
        frame.extend_from_slice(&(r.work_dir.len() as u16).to_be_bytes());
        frame.extend_from_slice(r.work_dir.as_bytes());
        frame.push(r.argv.len() as u8);
        for a in &r.argv {
            frame.extend_from_slice(&(a.len() as u16).to_be_bytes());
            frame.extend_from_slice(a.as_bytes());
        }
        frame.push(r.env.len() as u8);
        for e in &r.env {
            frame.extend_from_slice(&(e.len() as u16).to_be_bytes());
            frame.extend_from_slice(e.as_bytes());
        }
        Some(frame)
    }

    /// Upstream `TestLaunchCapBoundaries`.
    #[test]
    fn launch_cap_boundaries() {
        let fill = |n: usize| "a".repeat(n);
        type Mutate = Box<dyn Fn(&mut LaunchRequest)>;
        let cases: Vec<(&str, Mutate, Mutate)> = vec![
            (
                "harness length",
                Box::new(|r: &mut LaunchRequest| r.harness = "h".repeat(32)),
                Box::new(|r: &mut LaunchRequest| r.harness = "h".repeat(33)),
            ),
            (
                "harness empty",
                Box::new(|r: &mut LaunchRequest| r.harness = "a".to_string()),
                Box::new(|r: &mut LaunchRequest| r.harness = String::new()),
            ),
            (
                "harness charset",
                Box::new(|r: &mut LaunchRequest| r.harness = "open-code-2".to_string()),
                Box::new(|r: &mut LaunchRequest| r.harness = "Claude".to_string()),
            ),
            (
                "harness path",
                Box::new(|r: &mut LaunchRequest| r.harness = "claude".to_string()),
                Box::new(|r: &mut LaunchRequest| r.harness = "../claude".to_string()),
            ),
            (
                "workdir length",
                Box::new(move |r: &mut LaunchRequest| r.work_dir = fill(4096)),
                Box::new(move |r: &mut LaunchRequest| r.work_dir = fill(4097)),
            ),
            (
                "workdir NUL",
                Box::new(|r: &mut LaunchRequest| r.work_dir = "a/b".to_string()),
                Box::new(|r: &mut LaunchRequest| r.work_dir = "a\0b".to_string()),
            ),
            (
                "arg count",
                Box::new(|r: &mut LaunchRequest| r.argv = vec![String::new(); 64]),
                Box::new(|r: &mut LaunchRequest| r.argv = vec![String::new(); 65]),
            ),
            (
                "arg length",
                Box::new(move |r: &mut LaunchRequest| r.argv = vec![fill(4096)]),
                Box::new(move |r: &mut LaunchRequest| r.argv = vec![fill(4097)]),
            ),
            (
                "arg NUL",
                Box::new(|r: &mut LaunchRequest| r.argv = vec![String::new()]),
                Box::new(|r: &mut LaunchRequest| r.argv = vec!["--x\0".to_string()]),
            ),
            (
                "env count",
                Box::new(|r: &mut LaunchRequest| r.env = env_entries(64)),
                Box::new(|r: &mut LaunchRequest| r.env = env_entries(65)),
            ),
            (
                "env length",
                Box::new(move |r: &mut LaunchRequest| r.env = vec![format!("A={}", fill(8190))]),
                Box::new(move |r: &mut LaunchRequest| r.env = vec![format!("A={}", fill(8191))]),
            ),
            (
                "env shape",
                Box::new(|r: &mut LaunchRequest| r.env = vec!["=x".to_string()]),
                Box::new(|r: &mut LaunchRequest| r.env = vec!["PATH".to_string()]),
            ),
            (
                "env empty entry",
                Box::new(|r: &mut LaunchRequest| r.env = vec!["A=".to_string()]),
                Box::new(|r: &mut LaunchRequest| r.env = vec![String::new()]),
            ),
            (
                "env NUL",
                Box::new(|r: &mut LaunchRequest| r.env = vec!["A=b".to_string()]),
                Box::new(|r: &mut LaunchRequest| r.env = vec!["A=b\0c".to_string()]),
            ),
            (
                "env duplicate name",
                Box::new(|r: &mut LaunchRequest| {
                    r.env = vec!["A=1".to_string(), "AB=2".to_string()]
                }),
                Box::new(|r: &mut LaunchRequest| {
                    r.env = vec!["A=1".to_string(), "A=2".to_string()]
                }),
            ),
            (
                "nil scope",
                Box::new(|r: &mut LaunchRequest| r.scope.0[15] = 1),
                Box::new(|r: &mut LaunchRequest| r.scope = Scope::default()),
            ),
        ];
        for (name, ok_m, bad_m) in cases {
            let (mut ok, mut bad) = (session_request(), session_request());
            ok_m(&mut ok);
            bad_m(&mut bad);
            let frame =
                encode_launch(&ok).unwrap_or_else(|e| unreachable!("{name}: at the cap: {e}"));
            match decode_request(&frame) {
                Ok(got) => assert_eq!(got.launch, ok, "{name}: decode at the cap"),
                Err(e) => unreachable!("{name}: decode at the cap: {e}"),
            }
            let err = encode_launch(&bad).unwrap_err();
            assert!(
                is_code(&err, codes::REQUEST_MALFORMED),
                "{name}: over the cap: err = {err}"
            );
            // The decoder refuses what the encoder refuses: build the
            // bad frame by hand from the good one's shape.
            if let Some(frame) = raw_launch(&bad) {
                let err = decode_request(&frame).unwrap_err();
                assert!(
                    is_code(&err, codes::REQUEST_MALFORMED),
                    "{name}: decoder accepted the over-cap frame: {err}"
                );
            }
        }
    }

    /// Upstream `totalSized`: a request whose frame is exactly `n` bytes.
    fn total_sized(n: usize) -> LaunchRequest {
        let mut r = LaunchRequest {
            scope: TEST_SCOPE,
            harness: "claude".to_string(),
            ..LaunchRequest::default()
        };
        for _ in 0..15 {
            r.argv.push("a".repeat(MAX_ARG));
        }
        let base = raw_launch(&r).unwrap();
        // One env entry of length L adds 2+L bytes.
        let l = n - base.len() - 2;
        assert!(
            (2..=MAX_ENV_ENTRY).contains(&l),
            "cannot size a frame to {n} bytes (entry {l})"
        );
        r.env = vec![format!("A={}", "v".repeat(l - 2))];
        let frame = raw_launch(&r).unwrap();
        assert_eq!(
            frame.len(),
            n,
            "sized frame = {} bytes, want {n}",
            frame.len()
        );
        r
    }

    /// Upstream `TestLaunchTotalFrameCap`.
    #[test]
    fn launch_total_frame_cap() {
        let at = total_sized(MAX_FRAME);
        let frame = encode_launch(&at).unwrap();
        assert_eq!(frame.len(), MAX_FRAME);
        decode_request(&frame).unwrap();
        let over = total_sized(MAX_FRAME + 1);
        let err = encode_launch(&over).unwrap_err();
        assert!(
            is_code(&err, codes::REQUEST_MALFORMED),
            "encode over the cap: {err}"
        );
        let raw = raw_launch(&over).unwrap();
        let err = decode_request(&raw).unwrap_err();
        assert!(
            is_code(&err, codes::REQUEST_MALFORMED),
            "decode over the cap: {err}"
        );
    }

    /// Upstream `TestDecodeRequestRefusesEveryTruncationAndTrailingBytes`.
    #[test]
    fn decode_request_refuses_every_truncation_and_trailing_bytes() {
        let frame = encode_launch(&session_request()).unwrap();
        for n in 0..frame.len() {
            let err = decode_request(&frame[..n]).unwrap_err();
            assert!(
                is_code(&err, codes::REQUEST_MALFORMED),
                "truncated to {n} bytes: err = {err}"
            );
        }
        let mut trailed = frame.clone();
        trailed.push(0);
        let err = decode_request(&trailed).unwrap_err();
        assert!(
            is_code(&err, codes::REQUEST_MALFORMED),
            "trailing byte: {err}"
        );
        let alive = encode_alive(TEST_SCOPE).unwrap();
        let kill = encode_kill(TEST_SCOPE, Duration::from_secs(1)).unwrap();
        for f in [&alive, &kill] {
            for n in 0..f.len() {
                let err = decode_request(&f[..n]).unwrap_err();
                assert!(
                    is_code(&err, codes::REQUEST_MALFORMED),
                    "truncated {f:x?}: err = {err}"
                );
            }
            let mut trailed = f.clone();
            trailed.push(0);
            let err = decode_request(&trailed).unwrap_err();
            assert!(
                is_code(&err, codes::REQUEST_MALFORMED),
                "trailing byte on {f:x?}: {err}"
            );
        }
    }

    /// Upstream `TestDecodeRequestRefusesBadHeaders`.
    #[test]
    fn decode_request_refuses_bad_headers() {
        let good = encode_alive(TEST_SCOPE).unwrap();
        let mut i = 0usize;
        let mut check = |mutate: &dyn Fn(&mut Vec<u8>)| {
            let mut f = good.clone();
            mutate(&mut f);
            let err = decode_request(&f).unwrap_err();
            assert!(
                is_code(&err, codes::REQUEST_MALFORMED),
                "mutation {i}: err = {err}"
            );
            i += 1;
        };
        check(&|f: &mut Vec<u8>| f[0] = b'X');
        check(&|f: &mut Vec<u8>| f[3] = b'2');
        check(&|f: &mut Vec<u8>| f[4] = 2);
        check(&|f: &mut Vec<u8>| f[5] = 0);
        check(&|f: &mut Vec<u8>| f[5] = Opcode::Exit as u8);
        check(&|f: &mut Vec<u8>| f[5] = 9);
        check(&|f: &mut Vec<u8>| f[6] = 1);
        check(&|f: &mut Vec<u8>| f[7] = 1);
        check(&|f: &mut Vec<u8>| f[8..24].copy_from_slice(&[0u8; 16]));
    }

    /// Upstream `TestAliveAndKillRoundTripAndGraceCap`.
    #[test]
    fn alive_and_kill_round_trip_and_grace_cap() {
        let alive = encode_alive(TEST_SCOPE).unwrap();
        assert_eq!(alive.len(), ALIVE_REQUEST_SIZE);
        let got = decode_request(&alive).unwrap();
        assert_eq!(got.op, Opcode::Alive);
        assert_eq!(got.scope, TEST_SCOPE);

        let kill = encode_kill(TEST_SCOPE, MAX_KILL_GRACE).unwrap();
        assert_eq!(kill.len(), KILL_REQUEST_SIZE);
        assert_eq!(
            u32::from_be_bytes([kill[24], kill[25], kill[26], kill[27]]),
            30000
        );
        let got = decode_request(&kill).unwrap();
        assert_eq!(got.op, Opcode::Kill);
        assert_eq!(got.scope, TEST_SCOPE);
        assert_eq!(got.grace_ms, 30000);

        let err = encode_kill(TEST_SCOPE, MAX_KILL_GRACE + Duration::from_millis(1)).unwrap_err();
        assert!(
            is_code(&err, codes::REQUEST_MALFORMED),
            "grace over the cap: {err}"
        );

        let mut over = kill.clone();
        over[24..28].copy_from_slice(&30001u32.to_be_bytes());
        let err = decode_request(&over).unwrap_err();
        assert!(
            is_code(&err, codes::REQUEST_MALFORMED),
            "decoded grace over the cap: {err}"
        );

        let err = encode_alive(Scope::default()).unwrap_err();
        assert!(
            is_code(&err, codes::REQUEST_MALFORMED),
            "nil scope alive: {err}"
        );
        let err = encode_kill(Scope::default(), Duration::ZERO).unwrap_err();
        assert!(
            is_code(&err, codes::REQUEST_MALFORMED),
            "nil scope kill: {err}"
        );
    }

    /// Upstream `TestResponseRoundTrips`.
    #[test]
    fn response_round_trips() {
        let cases = vec![
            Response {
                op: Opcode::Launch,
                status: Reason::Ok,
                ..Response::default()
            },
            Response {
                op: Opcode::Launch,
                status: Reason::ScopeBusy,
                ..Response::default()
            },
            Response {
                op: Opcode::Alive,
                status: Reason::Ok,
                alive: true,
                ..Response::default()
            },
            Response {
                op: Opcode::Alive,
                status: Reason::Ok,
                ..Response::default()
            },
            Response {
                op: Opcode::Alive,
                status: Reason::PeerDenied,
                ..Response::default()
            },
            Response {
                op: Opcode::Kill,
                status: Reason::Ok,
                ..Response::default()
            },
            Response {
                op: Opcode::Kill,
                status: Reason::LaunchFailed,
                ..Response::default()
            },
            Response {
                op: Opcode::Exit,
                exit: Exit {
                    code: 0,
                    signaled: false,
                },
                ..Response::default()
            },
            Response {
                op: Opcode::Exit,
                exit: Exit {
                    code: 1,
                    signaled: false,
                },
                ..Response::default()
            },
            Response {
                op: Opcode::Exit,
                exit: Exit {
                    code: 255,
                    signaled: false,
                },
                ..Response::default()
            },
            Response {
                op: Opcode::Exit,
                exit: Exit {
                    code: 143,
                    signaled: true,
                },
                ..Response::default()
            },
            Response {
                op: Opcode::Exit,
                exit: Exit {
                    code: 137,
                    signaled: true,
                },
                ..Response::default()
            },
        ];
        for want in cases {
            let frame = encode_response(&want).unwrap();
            assert_eq!(frame.len(), RESPONSE_SIZE);
            let got = decode_response(&frame, want.op).unwrap();
            assert_eq!(got, want, "{want:?} round trip");
        }
        let exit = encode_response(&Response {
            op: Opcode::Exit,
            exit: Exit {
                code: 143,
                signaled: true,
            },
            ..Response::default()
        })
        .unwrap();
        assert_eq!(
            exit,
            b"CHL1\x01\x04\x00\x00\x01\x00\x00\x8f".to_vec(),
            "EXIT layout = {exit:x?}"
        );
    }

    /// Upstream `TestDecodeResponseRefusesMalformedFrames`.
    #[test]
    fn decode_response_refuses_malformed_frames() {
        let ok_alive = encode_response(&Response {
            op: Opcode::Alive,
            ..Response::default()
        })
        .unwrap();
        let ok_exit = encode_response(&Response {
            op: Opcode::Exit,
            ..Response::default()
        })
        .unwrap();
        let mut i = 0usize;
        let mut check = |frame: &[u8], op: Opcode, mutate: &dyn Fn(&mut Vec<u8>)| {
            let mut f = frame.to_vec();
            mutate(&mut f);
            let err = decode_response(&f, op).unwrap_err();
            assert!(
                is_code(&err, codes::MALFORMED_RESPONSE),
                "case {i}: err = {err}"
            );
            i += 1;
        };
        check(&ok_alive, Opcode::Alive, &|f: &mut Vec<u8>| f[0] = b'X');
        check(&ok_alive, Opcode::Alive, &|f: &mut Vec<u8>| f[4] = 2);
        check(&ok_alive, Opcode::Alive, &|f: &mut Vec<u8>| {
            f[5] = Opcode::Kill as u8
        });
        check(&ok_alive, Opcode::Alive, &|f: &mut Vec<u8>| f[6] = 11);
        check(&ok_alive, Opcode::Alive, &|f: &mut Vec<u8>| f[7] = 1);
        check(&ok_alive, Opcode::Alive, &|f: &mut Vec<u8>| f[8] = 2);
        check(&ok_alive, Opcode::Alive, &|f: &mut Vec<u8>| f[9] = 1);
        check(&ok_alive, Opcode::Alive, &|f: &mut Vec<u8>| {
            f[6] = Reason::ScopeBusy as u8;
            f[8] = 1;
        });
        check(&ok_exit, Opcode::Exit, &|f: &mut Vec<u8>| {
            f[6] = Reason::LaunchFailed as u8
        });
        check(&ok_exit, Opcode::Exit, &|f: &mut Vec<u8>| f[8] = 2);
        check(&ok_exit, Opcode::Exit, &|f: &mut Vec<u8>| f[9] = 1);
        check(&ok_exit, Opcode::Exit, &|f: &mut Vec<u8>| {
            f[10..12].copy_from_slice(&256u16.to_be_bytes())
        });
        check(&ok_exit, Opcode::Exit, &|f: &mut Vec<u8>| {
            f[8] = 1;
            f[10..12].copy_from_slice(&128u16.to_be_bytes());
        });
        check(&ok_exit, Opcode::Exit, &|f: &mut Vec<u8>| {
            f[8] = 1;
            f[10..12].copy_from_slice(&193u16.to_be_bytes());
        });
        for n in 0..RESPONSE_SIZE {
            let err = decode_response(&ok_alive[..n], Opcode::Alive).unwrap_err();
            assert!(
                is_code(&err, codes::MALFORMED_RESPONSE),
                "truncated to {n}: err = {err}"
            );
        }
        let mut oversize = ok_alive.clone();
        oversize.push(0);
        let err = decode_response(&oversize, Opcode::Alive).unwrap_err();
        assert!(is_code(&err, codes::MALFORMED_RESPONSE), "oversize: {err}");
        let mut launch_with_payload = encode_response(&Response {
            op: Opcode::Launch,
            ..Response::default()
        })
        .unwrap();
        launch_with_payload[11] = 1;
        let err = decode_response(&launch_with_payload, Opcode::Launch).unwrap_err();
        assert!(
            is_code(&err, codes::MALFORMED_RESPONSE),
            "LAUNCH payload: {err}"
        );
    }

    /// Upstream `TestReasonCodesMapToSentinels`.
    #[test]
    fn reason_codes_map_to_sentinels() {
        let want: [(Reason, &str); 10] = [
            (Reason::PeerDenied, codes::PEER_DENIED),
            (Reason::ConfigInvalid, codes::CONFIG_INVALID),
            (Reason::RequestMalformed, codes::REQUEST_MALFORMED),
            (Reason::UnknownHarness, codes::UNKNOWN_HARNESS),
            (Reason::WorkdirInvalid, codes::WORKDIR_INVALID),
            (Reason::ArgvRefused, codes::ARGV_REFUSED),
            (Reason::EnvRefused, codes::ENV_REFUSED),
            (Reason::ScopeBusy, codes::SCOPE_BUSY),
            (Reason::OperatorInvalid, codes::OPERATOR_INVALID),
            (Reason::LaunchFailed, codes::LAUNCH_FAILED),
        ];
        for (r, code) in want {
            let err = r.err().unwrap();
            assert!(is_code(&err, code), "reason {r:?} -> {err}");
            assert!(
                err.message().ends_with(r.as_str()),
                "reason {r:?} message = {err}"
            );
        }
        assert!(Reason::Ok.err().is_none(), "ReasonOK has an error");
    }
}
