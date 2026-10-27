//! CBL1/CBW1 wire codec — a byte-faithful port of
//! `cmd/central-backup-launcherd/main.c`'s frame layouts and
//! `internal/backuplauncher/protocol_linux.go`'s expectations.
//!
//! ```text
//! magic    [4] "CBL1"     version [1] 0x02
//! opcode   [1] launch(1) commit(2) abort(3) wait(4)
//!              assert-retained(5) release(6) census(7)
//!
//! launch   [6]=mode(1..=2) [7]=0  op-uuid[8..24]      = 24 + 1 fd
//! commit   [6]=0 [7]=0  launch-id[8..24] evidence-id[24..40] = 40
//! id ops   [6]=0 [7]=0  launch-id[8..24]            = 24
//! ```
//!
//! Responses keep upstream's five shapes:
//!
//! - common 12-byte `magic|version|opcode|status|reserved(4) + pid(4)`
//!   — the pid field is written on launch-denial paths too (as 0).
//! - launch 28-byte: `|mode|pid(be)|launch-id(16)` plus the worker's
//!   pidfd over `SCM_RIGHTS` — status DENIED carries mode=0.
//! - wait 48-byte: `|outcome|exit-code(be)|signal(be)|proof(32)` —
//!   DENIED is all zeros after the status byte.
//! - retained 44-byte: `|reserved(5)|proof(32)` at offset 12.
//! - census 16-byte: `|reserved(1)|live(be4)|held-permits(be4)`.
//!
//! The worker→monitor `CBW1` handoff frame is 40 bytes:
//! `magic|0x01|offer(1)|status|reserved|proof(32)` plus exactly one
//! `SCM_RIGHTS` descriptor; the monitor's acknowledgement is the same
//! shape with `offer=2` and the proof echoed.
//!
//! The monitor→daemon channel is an in-process pipe (both ends are
//! this binary): `monitor_startup` is two native-endian i32
//! `{worker_pid, error_number}` (8 bytes) and `monitor_event` is
//! `{kind, outcome, reserved(2), exit(i32), signal(i32), proof(32)}`
//! (44 bytes) — upstream's `struct monitor_startup`/`struct
//! monitor_event` layouts verbatim.

/// `CBL1`.
pub const MAGIC: [u8; 4] = *b"CBL1";
/// `CBL_VERSION`.
pub const VERSION: u8 = 2;
/// `CBW1`.
pub const WORKER_MAGIC: [u8; 4] = *b"CBW1";
/// `CBW_VERSION`.
pub const WORKER_VERSION: u8 = 1;
/// The worker's offer message (`frame[5] == 1`).
pub const WORKER_OFFER: u8 = 1;
/// The monitor's acknowledgement message (`frame[5] == 2`).
pub const WORKER_ACK: u8 = 2;

/// `OP_LAUNCH`.
pub const OP_LAUNCH: u8 = 1;
/// `OP_COMMIT`.
pub const OP_COMMIT: u8 = 2;
/// `OP_ABORT`.
pub const OP_ABORT: u8 = 3;
/// `OP_WAIT`.
pub const OP_WAIT: u8 = 4;
/// `OP_ASSERT_RETAINED`.
pub const OP_ASSERT_RETAINED: u8 = 5;
/// `OP_RELEASE`.
pub const OP_RELEASE: u8 = 6;
/// `OP_CENSUS`.
pub const OP_CENSUS: u8 = 7;

/// `MODE_BACKUP_CREATE` — `central-backup create <op-uuid>`.
pub const MODE_BACKUP_CREATE: u8 = 1;
/// `MODE_THROUGHPUT_PROBE` — `central-backup throughput-probe <op-uuid>`.
pub const MODE_THROUGHPUT_PROBE: u8 = 2;

/// `STATUS_OK`.
pub const STATUS_OK: u8 = 0;
/// `STATUS_DENIED`.
pub const STATUS_DENIED: u8 = 1;

/// `WORKER_SUCCEEDED`.
pub const WORKER_SUCCEEDED: u8 = 0;
/// `WORKER_EXITED`.
pub const WORKER_EXITED: u8 = 1;
/// `WORKER_SIGNALED`.
pub const WORKER_SIGNALED: u8 = 2;

/// `MONITOR_RETAINED` — the monitor holds the validated target-lock
/// socket; the launch is retained until release/abort/deadline.
pub const MONITOR_RETAINED: u8 = 1;
/// `MONITOR_FINAL` — the monitor reaped the tree and exited.
pub const MONITOR_FINAL: u8 = 2;

/// `MONITOR_ABORT` control command (daemon → monitor).
pub const MONITOR_ABORT: u8 = 1;
/// `MONITOR_RELEASE` control command (daemon → monitor).
pub const MONITOR_RELEASE: u8 = 2;
/// `MONITOR_ASSERT` control command (daemon → monitor).
pub const MONITOR_ASSERT: u8 = 3;

/// `launch` request size.
pub const LAUNCH_REQUEST_SIZE: usize = 24;
/// `commit` request size.
pub const COMMIT_REQUEST_SIZE: usize = 40;
/// The shared 24-byte id-request size (abort/wait/assert/release/census).
pub const ID_REQUEST_SIZE: usize = 24;
/// The common 12-byte acknowledgement.
pub const COMMON_RESPONSE_SIZE: usize = 12;
/// The launch response.
pub const LAUNCH_RESPONSE_SIZE: usize = 28;
/// The wait response.
pub const WAIT_RESPONSE_SIZE: usize = 48;
/// The assert-retained response.
pub const RETAINED_RESPONSE_SIZE: usize = 44;
/// The census response.
pub const CENSUS_RESPONSE_SIZE: usize = 16;
/// The worker handoff frame (`CBW1`).
pub const WORKER_FRAME_SIZE: usize = 40;
/// `sizeof(struct monitor_event)` — upstream's `_Static_assert(44)`.
pub const MONITOR_EVENT_SIZE: usize = 44;
/// `sizeof(struct monitor_startup)`.
pub const MONITOR_STARTUP_SIZE: usize = 8;
/// The receive buffer — upstream reads `sizeof(frame)` = 41 and a
/// datagram that fills it is itself malformed.
pub const REQUEST_BUFFER: usize = 41;
/// `MAX_RECEIVED_FDS` — upstream keeps at most two descriptors.
pub const MAX_RECEIVED_FDS: usize = 2;

/// `zero_uuid`.
pub fn zero_uuid(id: &[u8]) -> bool {
    id.iter().all(|b| *b == 0)
}

/// `zero_digest`.
pub fn zero_digest(digest: &[u8]) -> bool {
    digest.iter().all(|b| *b == 0)
}

/// `valid_mode`.
pub fn valid_mode(mode: u8) -> bool {
    mode == MODE_BACKUP_CREATE || mode == MODE_THROUGHPUT_PROBE
}

/// `valid_header` — `frame[6]`/`frame[7]` must both be zero (for a
/// launch the mode lives at `[6]`, so launch uses the prefix form).
fn valid_header(frame: &[u8], op: u8) -> bool {
    frame.len() >= 8
        && frame[0..4] == MAGIC
        && frame[4] == VERSION
        && frame[5] == op
        && frame[6] == 0
        && frame[7] == 0
}

/// `launch_header_prefix` — a launch-shaped frame; the mode byte is
/// not validated here (upstream validates it in the launch branch).
fn launch_header_prefix(frame: &[u8]) -> bool {
    frame.len() >= 8
        && frame[0..4] == MAGIC
        && frame[4] == VERSION
        && frame[5] == OP_LAUNCH
        && frame[7] == 0
}

/// A decoded request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    /// Launch — `mode` validated `1..=2`; one repository dir fd must
    /// accompany the frame.
    Launch {
        /// The mode byte (`MODE_BACKUP_CREATE`/`MODE_THROUGHPUT_PROBE`).
        mode: u8,
        /// The operation UUID.
        operation_id: [u8; 16],
    },
    /// Commit — write the evidence id to the record's evidence write end.
    Commit {
        /// The launch record id.
        launch_id: [u8; 16],
        /// The broker-issued evidence UUID.
        evidence_id: [u8; 16],
    },
    /// Abort — terminate the monitored tree (always ACKs OK; upstream
    /// SC-DEF-38: an unknown id has nothing left to abort).
    Abort {
        /// The launch record id.
        launch_id: [u8; 16],
    },
    /// Wait — immediate outcome or become the launch's waiter.
    Wait {
        /// The launch record id.
        launch_id: [u8; 16],
    },
    /// Assert-retained — prove the monitor still owns the target lock.
    AssertRetained {
        /// The launch record id.
        launch_id: [u8; 16],
    },
    /// Release — close the retained target lock, reap the monitor.
    Release {
        /// The launch record id.
        launch_id: [u8; 16],
    },
    /// Census — counts excluding the named launch; never denies.
    Census {
        /// The launch record id to exclude.
        launch_id: [u8; 16],
    },
}

/// What a received frame decides — separating "deny on the wire" from
/// "close silently" the way upstream's `if/else if` ladder does.
pub enum Outcome {
    /// A well-formed request.
    Request(Request),
    /// A refused launch — send the 28-byte `STATUS_DENIED` launch reply.
    LaunchDenied,
    /// Malformed — close without bytes.
    Silent,
}

/// `handle_connection`'s frame ladder. `fd_count` is the number of
/// descriptors the datagram carried — a launch wants exactly one, every
/// other opcode wants zero.
pub fn decode(frame: &[u8], fd_count: usize) -> Outcome {
    if launch_header_prefix(frame) {
        let mode = frame[6];
        if frame.len() != LAUNCH_REQUEST_SIZE
            || !valid_mode(mode)
            || zero_uuid(&frame[8..24])
            || fd_count != 1
        {
            return Outcome::LaunchDenied;
        }
        let mut operation_id = [0u8; 16];
        operation_id.copy_from_slice(&frame[8..24]);
        return Outcome::Request(Request::Launch { mode, operation_id });
    }
    if fd_count != 0 {
        // Upstream closes received fds then the connection — a
        // non-launch datagram carrying descriptors is malformed.
        return Outcome::Silent;
    }
    for (op, id_offset_req) in [
        (OP_COMMIT, COMMIT_REQUEST_SIZE),
        (OP_ABORT, ID_REQUEST_SIZE),
        (OP_WAIT, ID_REQUEST_SIZE),
        (OP_ASSERT_RETAINED, ID_REQUEST_SIZE),
        (OP_RELEASE, ID_REQUEST_SIZE),
        (OP_CENSUS, ID_REQUEST_SIZE),
    ] {
        if valid_header(frame, op) && frame.len() == id_offset_req && !zero_uuid(&frame[8..24]) {
            let mut launch_id = [0u8; 16];
            launch_id.copy_from_slice(&frame[8..24]);
            if op == OP_COMMIT {
                if zero_uuid(&frame[24..40]) {
                    return Outcome::Silent;
                }
                let mut evidence_id = [0u8; 16];
                evidence_id.copy_from_slice(&frame[24..40]);
                return Outcome::Request(Request::Commit {
                    launch_id,
                    evidence_id,
                });
            }
            let req = match op {
                OP_ABORT => Request::Abort { launch_id },
                OP_WAIT => Request::Wait { launch_id },
                OP_ASSERT_RETAINED => Request::AssertRetained { launch_id },
                OP_RELEASE => Request::Release { launch_id },
                _ => Request::Census { launch_id },
            };
            return Outcome::Request(req);
        }
    }
    Outcome::Silent
}

/// `send_response` — the common 12-byte reply (`pid` stays 0 on the
/// non-launch paths; upstream writes `htonl(pid)` regardless).
pub fn encode_common(opcode: u8, status: u8) -> [u8; COMMON_RESPONSE_SIZE] {
    let mut frame = [0u8; COMMON_RESPONSE_SIZE];
    frame[0..4].copy_from_slice(&MAGIC);
    frame[4] = VERSION;
    frame[5] = opcode;
    frame[6] = status;
    frame
}

/// `send_launch_response` — 28 bytes: pid as big-endian u32 at offset
/// 8, launch id at offset 12, mode acknowledged at offset 7. A denial
/// passes mode 0 / pid 0 / a nil id.
pub fn encode_launch(
    status: u8,
    pid: i32,
    launch_id: &[u8; 16],
    mode: u8,
) -> [u8; LAUNCH_RESPONSE_SIZE] {
    let mut frame = [0u8; LAUNCH_RESPONSE_SIZE];
    frame[0..4].copy_from_slice(&MAGIC);
    frame[4] = VERSION;
    frame[5] = OP_LAUNCH;
    frame[6] = status;
    frame[7] = mode;
    frame[8..12].copy_from_slice(&pid.to_be_bytes());
    frame[12..28].copy_from_slice(launch_id);
    frame
}

/// `send_wait_response` — 48 bytes: outcome at 7, exit code and
/// signal as big-endian u32 at 8/12, the retained proof at 16..48
/// (zeros for a denial or a non-retained outcome).
pub fn encode_wait(
    status: u8,
    outcome: u8,
    exit_code: i32,
    signal: i32,
    proof: Option<&[u8; 32]>,
) -> [u8; WAIT_RESPONSE_SIZE] {
    let mut frame = [0u8; WAIT_RESPONSE_SIZE];
    frame[0..4].copy_from_slice(&MAGIC);
    frame[4] = VERSION;
    frame[5] = OP_WAIT;
    frame[6] = status;
    frame[7] = outcome;
    frame[8..12].copy_from_slice(&exit_code.to_be_bytes());
    frame[12..16].copy_from_slice(&signal.to_be_bytes());
    if let Some(p) = proof {
        frame[16..48].copy_from_slice(p);
    }
    frame
}

/// `send_retained_response` — 44 bytes: proof at offset 12 (zeros on
/// a denial).
pub fn encode_retained(status: u8, proof: Option<&[u8; 32]>) -> [u8; RETAINED_RESPONSE_SIZE] {
    let mut frame = [0u8; RETAINED_RESPONSE_SIZE];
    frame[0..4].copy_from_slice(&MAGIC);
    frame[4] = VERSION;
    frame[5] = OP_ASSERT_RETAINED;
    frame[6] = status;
    if let Some(p) = proof {
        frame[12..44].copy_from_slice(p);
    }
    frame
}

/// `send_census_response` — 16 bytes: live-process and held-permit
/// counts as big-endian u32 at offsets 8 and 12.
pub fn encode_census(
    status: u8,
    live_processes: u32,
    held_permits: u32,
) -> [u8; CENSUS_RESPONSE_SIZE] {
    let mut frame = [0u8; CENSUS_RESPONSE_SIZE];
    frame[0..4].copy_from_slice(&MAGIC);
    frame[4] = VERSION;
    frame[5] = OP_CENSUS;
    frame[6] = status;
    frame[8..12].copy_from_slice(&live_processes.to_be_bytes());
    frame[12..16].copy_from_slice(&held_permits.to_be_bytes());
    frame
}

/// `send_worker_handoff_ack` — 40 bytes: `CBW1|0x01|0x02|status|0|proof`.
pub fn encode_worker_ack(status: u8, proof: Option<&[u8; 32]>) -> [u8; WORKER_FRAME_SIZE] {
    let mut frame = [0u8; WORKER_FRAME_SIZE];
    frame[0..4].copy_from_slice(&WORKER_MAGIC);
    frame[4] = WORKER_VERSION;
    frame[5] = WORKER_ACK;
    frame[6] = status;
    if let Some(p) = proof {
        frame[8..40].copy_from_slice(p);
    }
    frame
}

/// The worker→monitor offer's header validation —
/// `receive_worker_handoff`'s byte checks (the descriptor count and
/// the socket shape are the caller's).
pub fn valid_worker_offer(frame: &[u8]) -> bool {
    frame.len() == WORKER_FRAME_SIZE
        && frame[0..4] == WORKER_MAGIC
        && frame[4] == WORKER_VERSION
        && frame[5] == WORKER_OFFER
        && frame[6] == 0
        && frame[7] == 0
        && !zero_digest(&frame[8..40])
}

/// `struct monitor_startup` — the monitor's one-shot spawn report.
#[derive(Debug, Clone, Copy, Default)]
pub struct MonitorStartup {
    /// The worker's pid (0 when `error_number` is set).
    pub worker_pid: i32,
    /// `errno` when the spawn or the monitor's own identity drop failed.
    pub error_number: i32,
}

impl MonitorStartup {
    /// The 8-byte native-endian encoding (in-process channel).
    pub fn encode(&self) -> [u8; MONITOR_STARTUP_SIZE] {
        let mut b = [0u8; MONITOR_STARTUP_SIZE];
        b[0..4].copy_from_slice(&self.worker_pid.to_ne_bytes());
        b[4..8].copy_from_slice(&self.error_number.to_ne_bytes());
        b
    }

    /// The inverse of [`Self::encode`].
    pub fn decode(b: &[u8; MONITOR_STARTUP_SIZE]) -> Self {
        Self {
            worker_pid: i32::from_ne_bytes([b[0], b[1], b[2], b[3]]),
            error_number: i32::from_ne_bytes([b[4], b[5], b[6], b[7]]),
        }
    }
}

/// `struct monitor_event` — the monitor's 44-byte completion report.
#[derive(Debug, Clone, Copy)]
pub struct MonitorEvent {
    /// `MONITOR_RETAINED` or `MONITOR_FINAL`.
    pub kind: u8,
    /// `WORKER_SUCCEEDED`/`WORKER_EXITED`/`WORKER_SIGNALED`.
    pub outcome: u8,
    /// `reserved[2]` — must stay zero (`valid_monitor_event`).
    pub reserved: [u8; 2],
    /// The worker's exit status (`WORKER_EXITED`).
    pub exit_code: i32,
    /// The terminating signal (`WORKER_SIGNALED`).
    pub signal: i32,
    /// The target-lock proof (`MONITOR_RETAINED` only).
    pub proof: [u8; 32],
}

impl MonitorEvent {
    /// A blank `MONITOR_FINAL` — the shape terminate/defaulted paths emit.
    pub fn new_final() -> Self {
        Self {
            kind: MONITOR_FINAL,
            outcome: 0,
            reserved: [0u8; 2],
            exit_code: 0,
            signal: 0,
            proof: [0u8; 32],
        }
    }

    /// The 44-byte native-endian encoding (in-process channel),
    /// upstream's field order verbatim: kind, outcome, reserved(2),
    /// exit, signal, proof.
    pub fn encode(&self) -> [u8; MONITOR_EVENT_SIZE] {
        let mut b = [0u8; MONITOR_EVENT_SIZE];
        b[0] = self.kind;
        b[1] = self.outcome;
        b[2] = self.reserved[0];
        b[3] = self.reserved[1];
        b[4..8].copy_from_slice(&self.exit_code.to_ne_bytes());
        b[8..12].copy_from_slice(&self.signal.to_ne_bytes());
        b[12..44].copy_from_slice(&self.proof);
        b
    }

    /// The inverse of [`Self::encode`].
    pub fn decode(b: &[u8; MONITOR_EVENT_SIZE]) -> Self {
        let mut proof = [0u8; 32];
        proof.copy_from_slice(&b[12..44]);
        Self {
            kind: b[0],
            outcome: b[1],
            reserved: [b[2], b[3]],
            exit_code: i32::from_ne_bytes([b[4], b[5], b[6], b[7]]),
            signal: i32::from_ne_bytes([b[8], b[9], b[10], b[11]]),
            proof,
        }
    }
}

/// `valid_monitor_event` — the cross-consistency checks: reserved
/// bytes zero, kind in {RETAINED, FINAL}, outcome fields internally
/// consistent, and the proof present exactly on a retained-success.
pub fn valid_monitor_event(e: &MonitorEvent) -> bool {
    if e.reserved[0] != 0
        || e.reserved[1] != 0
        || (e.kind != MONITOR_RETAINED && e.kind != MONITOR_FINAL)
    {
        return false;
    }
    match e.outcome {
        WORKER_SUCCEEDED => {
            if e.exit_code != 0 || e.signal != 0 {
                return false;
            }
        }
        WORKER_EXITED => {
            if e.exit_code <= 0 || e.signal != 0 {
                return false;
            }
        }
        WORKER_SIGNALED => {
            if e.exit_code != 0 || e.signal <= 0 {
                return false;
            }
        }
        _ => return false,
    }
    let has_proof = !zero_digest(&e.proof);
    if e.kind == MONITOR_RETAINED {
        e.outcome == WORKER_SUCCEEDED && has_proof
    } else {
        !has_proof
    }
}

/// `set_worker_outcome` — the raw wait-status to outcome mapping.
pub fn worker_outcome(wait_status: i32) -> (u8, i32, i32) {
    if libc::WIFEXITED(wait_status) {
        let code = libc::WEXITSTATUS(wait_status);
        (
            if code == 0 {
                WORKER_SUCCEEDED
            } else {
                WORKER_EXITED
            },
            code,
            0,
        )
    } else if libc::WIFSIGNALED(wait_status) {
        (WORKER_SIGNALED, 0, libc::WTERMSIG(wait_status))
    } else {
        (WORKER_EXITED, 255, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id_frame(op: u8, launch_id: &[u8; 16]) -> Vec<u8> {
        let mut f = vec![0u8; 24];
        f[0..4].copy_from_slice(&MAGIC);
        f[4] = VERSION;
        f[5] = op;
        f[8..24].copy_from_slice(launch_id);
        f
    }

    fn launch_frame(mode: u8, op: &[u8; 16]) -> Vec<u8> {
        let mut f = vec![0u8; 24];
        f[0..4].copy_from_slice(&MAGIC);
        f[4] = VERSION;
        f[5] = OP_LAUNCH;
        f[6] = mode;
        f[8..24].copy_from_slice(op);
        f
    }

    #[test]
    fn decode_launch() {
        let mut op = [0u8; 16];
        op[0] = 0xaa;
        op[15] = 0xbb;
        for mode in [MODE_BACKUP_CREATE, MODE_THROUGHPUT_PROBE] {
            match decode(&launch_frame(mode, &op), 1) {
                Outcome::Request(Request::Launch {
                    mode: m,
                    operation_id,
                }) => {
                    assert_eq!(m, mode);
                    assert_eq!(operation_id, op);
                }
                _ => unreachable!("launch decode"),
            }
        }
    }

    #[test]
    fn launch_refusals() {
        let mut op = [0u8; 16];
        op[3] = 9;
        // mode 0 / 3, nil uuid, wrong size, wrong fd count → a denied
        // launch response, not a silent close.
        for bad in [
            decode(&launch_frame(0, &op), 1),
            decode(&launch_frame(3, &op), 1),
            decode(&launch_frame(1, &[0u8; 16]), 1),
            decode(&launch_frame(1, &op), 0),
            decode(&launch_frame(1, &op), 2),
        ] {
            assert!(matches!(bad, Outcome::LaunchDenied));
        }
        let mut short = launch_frame(1, &op);
        short.truncate(23);
        assert!(matches!(decode(&short, 1), Outcome::LaunchDenied));
    }

    #[test]
    fn decode_commit() {
        let mut f = vec![0u8; 40];
        f[0..4].copy_from_slice(&MAGIC);
        f[4] = VERSION;
        f[5] = OP_COMMIT;
        f[8] = 0x11;
        f[24] = 0x22;
        match decode(&f, 0) {
            Outcome::Request(Request::Commit {
                launch_id,
                evidence_id,
            }) => {
                assert_eq!(launch_id[0], 0x11);
                assert_eq!(evidence_id[0], 0x22);
            }
            _ => unreachable!("commit decode"),
        }
        // A nil id makes the frame malformed → silent close.
        let mut nil = f.clone();
        nil[8] = 0;
        assert!(matches!(decode(&nil, 0), Outcome::Silent));
        let mut nil = f.clone();
        nil[24] = 0;
        assert!(matches!(decode(&nil, 0), Outcome::Silent));
    }

    #[test]
    fn decode_id_ops() {
        let mut id = [0u8; 16];
        id[9] = 0x33;
        let cases = [
            (OP_ABORT, Request::Abort { launch_id: id }),
            (OP_WAIT, Request::Wait { launch_id: id }),
            (
                OP_ASSERT_RETAINED,
                Request::AssertRetained { launch_id: id },
            ),
            (OP_RELEASE, Request::Release { launch_id: id }),
            (OP_CENSUS, Request::Census { launch_id: id }),
        ];
        for (op, want) in cases {
            match decode(&id_frame(op, &id), 0) {
                Outcome::Request(r) => assert_eq!(r, want),
                _ => unreachable!("id op decode"),
            }
        }
        // A nil launch id is malformed → silent.
        assert!(matches!(
            decode(&id_frame(OP_ABORT, &[0u8; 16]), 0),
            Outcome::Silent
        ));
        // A descriptor on a non-launch frame is malformed → silent.
        assert!(matches!(
            decode(&id_frame(OP_ABORT, &id), 1),
            Outcome::Silent
        ));
    }

    #[test]
    fn silent_refusals() {
        assert!(matches!(decode(&[], 0), Outcome::Silent));
        assert!(matches!(decode(&[0u8; 7], 0), Outcome::Silent));
        // Bad magic / version / unknown opcode → silent.
        let mut f = launch_frame(1, &[9u8; 16]);
        f[0] = b'X';
        assert!(matches!(decode(&f, 1), Outcome::Silent));
        let mut f = launch_frame(1, &[9u8; 16]);
        f[4] = 1;
        assert!(matches!(decode(&f, 1), Outcome::Silent));
        let mut f = launch_frame(1, &[9u8; 16]);
        f[5] = 9;
        assert!(matches!(decode(&f, 0), Outcome::Silent));
        // A launch prefix with a nonzero reserved byte is no launch at
        // all → falls through to silent.
        let mut f = launch_frame(1, &[9u8; 16]);
        f[7] = 1;
        assert!(matches!(decode(&f, 1), Outcome::Silent));
    }

    #[test]
    fn encode_shapes() {
        let c = encode_common(OP_COMMIT, STATUS_OK);
        assert_eq!(&c[0..4], b"CBL1");
        assert_eq!(c[4], 2);
        assert_eq!(c[5], OP_COMMIT);
        assert_eq!(c[6], 0);
        assert_eq!(&c[7..12], &[0u8; 5]);

        let mut id = [0u8; 16];
        id[0] = 0x42;
        let l = encode_launch(STATUS_OK, 4321, &id, MODE_BACKUP_CREATE);
        assert_eq!(&l[0..4], b"CBL1");
        assert_eq!(l[4], 2);
        assert_eq!(l[5], OP_LAUNCH);
        assert_eq!(l[7], MODE_BACKUP_CREATE);
        assert_eq!(u32::from_be_bytes([l[8], l[9], l[10], l[11]]), 4321);
        assert_eq!(l[12], 0x42);
        // The denied launch response: mode byte 0, zeroed tail.
        let d = encode_launch(STATUS_DENIED, 0, &[0u8; 16], 0);
        assert_eq!(d[6], STATUS_DENIED);
        assert_eq!(d[7], 0);
        assert_eq!(&d[8..28], &[0u8; 20]);

        let mut proof = [0u8; 32];
        proof[31] = 7;
        let w = encode_wait(STATUS_OK, WORKER_SUCCEEDED, 0, 0, Some(&proof));
        assert_eq!(w[5], OP_WAIT);
        assert_eq!(w[7], WORKER_SUCCEEDED);
        assert_eq!(&w[8..16], &[0u8; 8]);
        assert_eq!(w[47], 7);
        let dw = encode_wait(STATUS_DENIED, 0, 0, 0, None);
        assert_eq!(&dw[7..48], &[0u8; 41]);

        let r = encode_retained(STATUS_OK, Some(&proof));
        assert_eq!(r[5], OP_ASSERT_RETAINED);
        assert_eq!(&r[7..12], &[0u8; 5]);
        assert_eq!(r[43], 7);

        let n = encode_census(STATUS_OK, 3, 1);
        assert_eq!(n[5], OP_CENSUS);
        assert_eq!(u32::from_be_bytes([n[8], n[9], n[10], n[11]]), 3);
        assert_eq!(u32::from_be_bytes([n[12], n[13], n[14], n[15]]), 1);

        let a = encode_worker_ack(STATUS_OK, Some(&proof));
        assert_eq!(&a[0..4], b"CBW1");
        assert_eq!(a[4], 1);
        assert_eq!(a[5], 2);
        assert_eq!(a[39], 7);
    }

    #[test]
    fn worker_offer_shape() {
        let mut f = [0u8; 40];
        f[0..4].copy_from_slice(&WORKER_MAGIC);
        f[4] = WORKER_VERSION;
        f[5] = WORKER_OFFER;
        f[8] = 0xee;
        assert!(valid_worker_offer(&f));
        f[5] = WORKER_ACK;
        assert!(!valid_worker_offer(&f));
        f[5] = WORKER_OFFER;
        f[8..40].fill(0);
        assert!(!valid_worker_offer(&f));
        let short = &f[..39];
        assert!(!valid_worker_offer(short));
    }

    #[test]
    fn monitor_wire() {
        let s = MonitorStartup {
            worker_pid: 4242,
            error_number: 0,
        };
        let d = MonitorStartup::decode(&s.encode());
        assert_eq!(d.worker_pid, 4242);
        assert_eq!(d.error_number, 0);

        let mut e = MonitorEvent::new_final();
        e.outcome = WORKER_EXITED;
        e.exit_code = 9;
        let raw = e.encode();
        assert_eq!(raw.len(), MONITOR_EVENT_SIZE);
        assert_eq!(raw[0], MONITOR_FINAL);
        let d = MonitorEvent::decode(&raw);
        assert!(valid_monitor_event(&d));
        assert_eq!(d.exit_code, 9);

        // A retained event must be a success with a proof; a final one
        // must carry none.
        let mut r = MonitorEvent::new_final();
        r.kind = MONITOR_RETAINED;
        r.outcome = WORKER_SUCCEEDED;
        assert!(!valid_monitor_event(&r));
        r.proof[5] = 1;
        assert!(valid_monitor_event(&r));
        let mut bad = r;
        bad.kind = MONITOR_FINAL;
        assert!(!valid_monitor_event(&bad));
    }

    #[test]
    fn wait_status_mapping() {
        // exit(0) → succeeded; exit(9) → exited; SIGKILL → signaled.
        assert_eq!(worker_outcome(0), (WORKER_SUCCEEDED, 0, 0));
        assert_eq!(worker_outcome(9 << 8), (WORKER_EXITED, 9, 0));
        assert_eq!(worker_outcome(9), (WORKER_SIGNALED, 0, 9));
    }
}
