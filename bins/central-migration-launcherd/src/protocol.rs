//! CML1 wire codec — a byte-faithful port of `main.c`'s frame layout
//! and `internal/migrationlauncher/protocol_linux.go`'s framing.
//!
//! ```text
//! magic    [4] "CML1"     version [1] 0x01
//! opcode   [1] launch(1) commit(2) abort(3)
//!
//! launch   [6]=command(1..=5) [7]=0  op-uuid[8..24]        = 24 bytes
//! commit   [6]=0 [7]=0  launch-id[8..24] evidence-id[24..40] = 40
//! abort    [6]=0 [7]=0  launch-id[8..24]                  = 24
//! ```
//!
//! Responses keep upstream's two shapes: the common 12-byte
//! `magic|version|opcode|status|reserved(4)` and the 28-byte launch
//! response with `pid` (u32 **big-endian** at offset 8) and the
//! 16-byte launch id at offset 12.
//!
//! The dispatch reproduces upstream's refusal ladder exactly:
//!
//! - `size < 8` or a frame filling the whole receive buffer → the
//!   connection closes without a response.
//! - A launch-shaped header (`magic|ver|OP_LAUNCH|frame[7]==0`) with
//!   the wrong size, a command outside `1..=5`, or a nil operation id
//!   → a `STATUS_DENIED` launch response.
//! - Commit/abort are handled only when the full `valid_header` +
//!   size + non-nil-id predicates all hold; anything else falls
//!   through to a silent close — a commit with a nil id is malformed,
//!   not denied.

/// `PROTOCOL_MAGIC`.
pub const MAGIC: [u8; 4] = *b"CML1";
/// `CML1_VERSION`.
pub const VERSION: u8 = 1;
/// `OP_LAUNCH`.
pub const OP_LAUNCH: u8 = 1;
/// `OP_COMMIT`.
pub const OP_COMMIT: u8 = 2;
/// `OP_ABORT`.
pub const OP_ABORT: u8 = 3;
/// `STATUS_OK`.
pub const STATUS_OK: u8 = 0;
/// `STATUS_DENIED`.
pub const STATUS_DENIED: u8 = 1;

/// `LAUNCH_REQUEST_SIZE`.
pub const LAUNCH_REQUEST_SIZE: usize = 24;
/// `COMMIT_REQUEST_SIZE`.
pub const COMMIT_REQUEST_SIZE: usize = 40;
/// `ABORT_REQUEST_SIZE`.
pub const ABORT_REQUEST_SIZE: usize = 24;
/// `COMMON_RESPONSE_SIZE`.
pub const COMMON_RESPONSE_SIZE: usize = 12;
/// `LAUNCH_RESPONSE_SIZE`.
pub const LAUNCH_RESPONSE_SIZE: usize = 28;
/// The receive buffer — upstream reads `sizeof(frame)` = 41 and a
/// frame that fills it is itself malformed.
pub const REQUEST_BUFFER: usize = 41;

/// The closed launch grammar — `commands[]` indices 1..=5.
pub const COMMANDS: [&str; 6] = ["", "up", "resume", "status", "verify", "reset"];

fn zero_uuid(id: &[u8]) -> bool {
    id.iter().all(|b| *b == 0)
}

/// A decoded request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    /// Launch — `command` is a validated `commands[]` index (1..=5).
    Launch {
        /// The `commands[]` index the frame named.
        command: u8,
        /// The operation UUID.
        operation_id: [u8; 16],
    },
    /// Commit — write the evidence id to the record's FD3 write end.
    Commit {
        /// The launch record id.
        launch_id: [u8; 16],
        /// The broker-issued evidence UUID.
        evidence_id: [u8; 16],
    },
    /// Abort — kill+reap an uncommitted launch.
    Abort {
        /// The launch record id.
        launch_id: [u8; 16],
    },
}

/// What a received frame decides — separating "deny on the wire" from
/// "close silently" the way upstream's `if/else if` ladder does.
pub enum Outcome {
    /// A well-formed request.
    Request(Request),
    /// A refused launch — send `STATUS_DENIED` with this opcode.
    Denied(u8),
    /// Malformed — close without bytes.
    Silent,
}

fn valid_header(frame: &[u8], op: u8) -> bool {
    frame.len() >= 8
        && frame[0..4] == MAGIC
        && frame[4] == VERSION
        && frame[5] == op
        && frame[6] == 0
        && frame[7] == 0
}

/// `handle_connection`'s frame ladder.
pub fn decode(frame: &[u8]) -> Outcome {
    if frame.len() < 8 || frame.len() == REQUEST_BUFFER {
        return Outcome::Silent;
    }
    if frame[0..4] == MAGIC && frame[4] == VERSION && frame[5] == OP_LAUNCH && frame[7] == 0 {
        let mut op = [0u8; 16];
        if frame.len() >= 24 {
            op.copy_from_slice(&frame[8..24]);
        }
        if frame.len() != LAUNCH_REQUEST_SIZE || frame[6] == 0 || frame[6] > 5 || zero_uuid(&op) {
            return Outcome::Denied(OP_LAUNCH);
        }
        return Outcome::Request(Request::Launch {
            command: frame[6],
            operation_id: op,
        });
    }
    if valid_header(frame, OP_COMMIT)
        && frame.len() == COMMIT_REQUEST_SIZE
        && !zero_uuid(&frame[8..24])
        && !zero_uuid(&frame[24..40])
    {
        let mut launch_id = [0u8; 16];
        let mut evidence_id = [0u8; 16];
        launch_id.copy_from_slice(&frame[8..24]);
        evidence_id.copy_from_slice(&frame[24..40]);
        return Outcome::Request(Request::Commit {
            launch_id,
            evidence_id,
        });
    }
    if valid_header(frame, OP_ABORT)
        && frame.len() == ABORT_REQUEST_SIZE
        && !zero_uuid(&frame[8..24])
    {
        let mut launch_id = [0u8; 16];
        launch_id.copy_from_slice(&frame[8..24]);
        return Outcome::Request(Request::Abort { launch_id });
    }
    Outcome::Silent
}

/// `send_response` — the common 12-byte reply.
pub fn encode_common(opcode: u8, status: u8) -> [u8; COMMON_RESPONSE_SIZE] {
    let mut frame = [0u8; COMMON_RESPONSE_SIZE];
    frame[0..4].copy_from_slice(&MAGIC);
    frame[4] = VERSION;
    frame[5] = opcode;
    frame[6] = status;
    frame
}

/// `send_response` for a launch — pid as big-endian u32 at offset 8,
/// launch id at offset 12.
pub fn encode_launch(status: u8, pid: i32, launch_id: &[u8; 16]) -> [u8; LAUNCH_RESPONSE_SIZE] {
    let mut frame = [0u8; LAUNCH_RESPONSE_SIZE];
    frame[0..4].copy_from_slice(&MAGIC);
    frame[4] = VERSION;
    frame[5] = OP_LAUNCH;
    frame[6] = status;
    frame[8..12].copy_from_slice(&pid.to_be_bytes());
    frame[12..28].copy_from_slice(launch_id);
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    fn launch_frame(command: u8, op: &[u8; 16]) -> Vec<u8> {
        let mut f = vec![0u8; 24];
        f[0..4].copy_from_slice(&MAGIC);
        f[4] = 1;
        f[5] = 1;
        f[6] = command;
        f[8..24].copy_from_slice(op);
        f
    }

    #[test]
    fn decode_launch() {
        let mut op = [0u8; 16];
        op[0] = 0xaa;
        op[15] = 0xbb;
        match decode(&launch_frame(2, &op)) {
            Outcome::Request(Request::Launch {
                command,
                operation_id,
            }) => {
                assert_eq!(command, 2);
                assert_eq!(operation_id, op);
            }
            _ => unreachable!("launch decode"),
        }
    }

    #[test]
    fn launch_refusals() {
        let mut op = [0u8; 16];
        op[3] = 9;
        // command 0 / 6, nil uuid, wrong size → denied, not silent.
        assert!(matches!(
            decode(&launch_frame(0, &op)),
            Outcome::Denied(OP_LAUNCH)
        ));
        assert!(matches!(
            decode(&launch_frame(6, &op)),
            Outcome::Denied(OP_LAUNCH)
        ));
        assert!(matches!(
            decode(&launch_frame(1, &[0u8; 16])),
            Outcome::Denied(OP_LAUNCH)
        ));
        let mut short = launch_frame(1, &op);
        short.truncate(23);
        assert!(matches!(decode(&short), Outcome::Denied(OP_LAUNCH)));
    }

    #[test]
    fn decode_commit() {
        let mut f = vec![0u8; 40];
        f[0..4].copy_from_slice(&MAGIC);
        f[4] = 1;
        f[5] = 2;
        f[8] = 0x11;
        f[24] = 0x22;
        match decode(&f) {
            Outcome::Request(Request::Commit {
                launch_id,
                evidence_id,
            }) => {
                assert_eq!(launch_id[0], 0x11);
                assert_eq!(evidence_id[0], 0x22);
            }
            _ => unreachable!("commit decode"),
        }
        // A nil launch id makes the frame malformed → silent close.
        let mut nil = f.clone();
        nil[8] = 0;
        assert!(matches!(decode(&nil), Outcome::Silent));
        // A nil evidence id likewise.
        let mut nil = f.clone();
        nil[24] = 0;
        assert!(matches!(decode(&nil), Outcome::Silent));
    }

    #[test]
    fn decode_abort() {
        let mut f = vec![0u8; 24];
        f[0..4].copy_from_slice(&MAGIC);
        f[4] = 1;
        f[5] = 3;
        f[8] = 0x33;
        match decode(&f) {
            Outcome::Request(Request::Abort { launch_id }) => assert_eq!(launch_id[0], 0x33),
            _ => unreachable!("abort decode"),
        }
    }

    #[test]
    fn silent_refusals() {
        assert!(matches!(decode(&[]), Outcome::Silent));
        assert!(matches!(decode(&[0u8; 7]), Outcome::Silent));
        assert!(matches!(decode(&[0u8; 41]), Outcome::Silent));
        // Bad magic / version / unknown opcode → silent.
        let mut f = launch_frame(1, &[9u8; 16]);
        f[0] = b'X';
        assert!(matches!(decode(&f), Outcome::Silent));
        let mut f = launch_frame(1, &[9u8; 16]);
        f[4] = 2;
        assert!(matches!(decode(&f), Outcome::Silent));
        let mut f = launch_frame(1, &[9u8; 16]);
        f[5] = 9;
        assert!(matches!(decode(&f), Outcome::Silent));
    }

    #[test]
    fn encode_shapes() {
        let c = encode_common(OP_COMMIT, STATUS_OK);
        assert_eq!(&c[0..4], b"CML1");
        assert_eq!(c[4], 1);
        assert_eq!(c[5], 2);
        assert_eq!(c[6], 0);
        let mut id = [0u8; 16];
        id[0] = 0x42;
        let l = encode_launch(STATUS_OK, 4321, &id);
        assert_eq!(&l[0..4], b"CML1");
        assert_eq!(l[5], OP_LAUNCH);
        assert_eq!(u32::from_be_bytes([l[8], l[9], l[10], l[11]]), 4321);
        assert_eq!(l[12], 0x42);
    }
}
