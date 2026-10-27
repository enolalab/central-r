//! Per-launch sessions — upstream `main.c`'s `struct launch_record`
//! state machine, `spawn_supervised_child`, `monitor_worker`, and
//! `spawn_worker`.
//!
//! Each LAUNCH forks a **monitor** — its own `PR_SET_CHILD_SUBREAPER`
//! — which forks the **worker** (`central-backup` at the fixed path,
//! fixed argv/env, fixed descriptor layout). The daemon talks to the
//! monitor over three pipes (startup result, completion events,
//! control commands); the worker talks to the monitor over a
//! `SOCK_SEQPACKET` handoff socketpair (its fixed FD5), through which
//! it offers exactly one connected, validated target-lock socket plus
//! its 32-byte proof (`CBW1`).
//!
//! Worker-side fixed descriptors (upstream `spawn_worker`):
//!
//! - FD3 — evidence read end; OP_COMMIT writes the 16-byte evidence id.
//! - FD4 — the repository directory descriptor from the launch frame.
//! - FD5 — the `CBW1` target-lock handoff socket (seqpacket).
//! - FD6 — the pre-exec errno report (`O_CLOEXEC`: EOF on exec success).
//!
//! Monitor-side fixed descriptors (upstream `spawn_supervised_child`):
//!
//! - FD3 — repository dir, FD4 — evidence read end (both only to hand
//!   to the worker), FD5 — startup write end, FD6 — completion write
//!   end, FD7 — control read end.

use std::ffi::CString;
use std::io::IoSliceMut;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, IntoRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::io::Errno;
use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendFlags,
    SocketFlags, SocketType, recvmsg, send, socketpair,
};
use rustix::pipe::PipeFlags;

use crate::policy::{self, PermitHold};
use crate::protocol::{self, MonitorEvent, MonitorStartup};
use crate::sys;

/// `MAX_LAUNCHES`.
pub const MAX_LAUNCHES: usize = 32;

static MONITOR_ABORT: AtomicBool = AtomicBool::new(false);

extern "C" fn on_monitor_abort(_sig: libc::c_int) {
    MONITOR_ABORT.store(true, Ordering::SeqCst);
}

fn ms_timespec(ms: i64) -> Timespec {
    Timespec {
        tv_sec: ms / 1000,
        tv_nsec: (ms % 1000) * 1_000_000,
    }
}

/// An `Errno` as a raw `errno` value (the startup frame carries the
/// plain integer).
fn errno_i32(e: Errno) -> i32 {
    std::io::Error::from(e).raw_os_error().unwrap_or(libc::EIO)
}

/// A raw `errno` back as an `Errno`.
fn errno_from_i32(e: i32) -> Errno {
    Errno::from_io_error(&std::io::Error::from_raw_os_error(e)).unwrap_or(Errno::IO)
}

/// `read_exact` — exactly `buf.len()` bytes; EOF or error fails.
fn read_exact<Fd: AsFd>(fd: Fd, buf: &mut [u8]) -> Result<(), Errno> {
    let mut got = 0usize;
    while got < buf.len() {
        match rustix::io::read(&fd, &mut buf[got..]) {
            Ok(0) => return Err(Errno::IO),
            Ok(n) => got += n,
            Err(Errno::INTR) => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// `write_exact`.
fn write_exact<Fd: AsFd>(fd: Fd, buf: &[u8]) -> Result<(), Errno> {
    let mut done = 0usize;
    while done < buf.len() {
        match rustix::io::write(&fd, &buf[done..]) {
            Ok(0) => return Err(Errno::IO),
            Ok(n) => done += n,
            Err(Errno::INTR) => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// `receive_packet` — one `SOCK_SEQPACKET` datagram plus its
/// `SCM_RIGHTS` descriptors, `MSG_DONTWAIT | MSG_CMSG_CLOEXEC`. The
/// buffer is upstream's 41 bytes (a datagram that fills it is itself
/// malformed) with room for upstream's `MAX_RECEIVED_FDS` descriptors;
/// a message carrying more marks itself truncated, like upstream.
pub struct Packet {
    /// The datagram bytes buffer (only `frame[..len]` is valid).
    pub frame: [u8; protocol::REQUEST_BUFFER],
    /// The datagram's byte count.
    pub len: usize,
    /// The received descriptors (≤ [`protocol::MAX_RECEIVED_FDS`]).
    pub fds: Vec<OwnedFd>,
}

pub fn recv_packet<Fd: AsFd>(conn: Fd) -> Result<Packet, ()> {
    let mut frame = [0u8; protocol::REQUEST_BUFFER];
    let mut iov = [IoSliceMut::new(&mut frame)];
    let mut space =
        [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(protocol::MAX_RECEIVED_FDS))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let msg = recvmsg(
        conn,
        &mut iov,
        &mut control,
        RecvFlags::DONTWAIT | RecvFlags::CMSG_CLOEXEC,
    )
    .map_err(|_| ())?;
    let mut fds: Vec<OwnedFd> = Vec::new();
    let mut over = false;
    let mut foreign = false;
    for m in control.drain() {
        match m {
            RecvAncillaryMessage::ScmRights(rights) => {
                for fd in rights {
                    if fds.len() >= protocol::MAX_RECEIVED_FDS {
                        // Upstream closes the excess descriptor and
                        // flags the message CTRUNC → refused.
                        over = true;
                        drop(fd);
                    } else {
                        fds.push(fd);
                    }
                }
            }
            // Any non-rights ancillary is upstream's EPROTO refusal.
            _ => foreign = true,
        }
    }
    if foreign
        || over
        || msg
            .flags
            .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
        || msg.bytes == protocol::REQUEST_BUFFER
    {
        return Err(());
    }
    Ok(Packet {
        frame,
        len: msg.bytes,
        fds,
    })
}

/// `uuid_string` — lowercase hyphenated UUID text.
pub fn uuid_text(b: &[u8; 16]) -> String {
    let mut out = String::with_capacity(36);
    for (i, v) in b.iter().enumerate() {
        if i == 4 || i == 6 || i == 8 || i == 10 {
            out.push('-');
        }
        out.push_str(&format!("{v:02x}"));
    }
    out
}

/// `random_uuid` — 16 `getrandom` bytes, non-nil, version/variant
/// bits set the way upstream sets them (`|0x70` / `|0x80`).
pub fn random_uuid() -> Result<[u8; 16], Errno> {
    let mut b = [0u8; 16];
    rustix::rand::getrandom(&mut b, rustix::rand::GetRandomFlags::empty())?;
    if b.iter().all(|v| *v == 0) {
        return Err(Errno::INVAL);
    }
    b[6] = (b[6] & 0x0f) | 0x70;
    b[8] = (b[8] & 0x3f) | 0x80;
    Ok(b)
}

/* ---- the launch record (upstream `struct launch_record`) ---- */

/// `struct launch_record` — one supervised launch.
pub struct Record {
    /// `mode` — `MODE_BACKUP_CREATE`/`MODE_THROUGHPUT_PROBE`.
    pub mode: u8,
    /// `id` — the launch id the broker addresses.
    pub id: [u8; 16],
    /// `operation_id` — kept for record-layout parity; the worker
    /// already consumed it in argv.
    #[allow(dead_code)]
    pub operation_id: [u8; 16],
    /// `evidence_id` — set on commit; the idempotence comparison.
    pub evidence_id: [u8; 16],
    /// `pid` — the worker (the launch response carries it; the
    /// monitor owns every kill/reap after that).
    #[allow(dead_code)]
    pub pid: i32,
    /// `pidfd` — the worker's descriptor handle.
    pub pidfd: Option<OwnedFd>,
    /// `monitor_pid` — the launch's monitor.
    pub monitor_pid: i32,
    /// `monitor_pidfd`.
    pub monitor_pidfd: Option<OwnedFd>,
    /// `evidence_fd` — the daemon's write end of the worker's FD3
    /// pipe; `None` once commit has written+closed it.
    pub evidence_fd: Option<OwnedFd>,
    /// `completion_fd` — the monitor's event channel read end.
    pub completion_fd: Option<OwnedFd>,
    /// `control_fd` — the monitor's command channel write end.
    pub control_fd: Option<OwnedFd>,
    /// `waiter_fd` — a stored OP_WAIT connection, owned until
    /// `notify_waiter` answers it.
    pub waiter: Option<OwnedFd>,
    /// `permit_fd_a`/`permit_fd_b` — the held flock pair.
    pub permits: Option<PermitHold>,
    /// `worker_outcome`.
    pub worker_outcome: u8,
    /// `exit_code`.
    pub exit_code: i32,
    /// `signal_number`.
    pub signal_number: i32,
    /// `target_lock_proof`.
    pub target_lock_proof: [u8; 32],
    /// `deadline` — the uncommitted-launch timeout.
    pub deadline: Instant,
    /// `hard_deadline` — the launch's absolute ceiling.
    pub hard_deadline: Instant,
    /// `finished_at` — result-retention base.
    pub finished_at: Instant,
    /// `committed`.
    pub committed: bool,
    /// `finished` — the monitor is reaped and the outcome final.
    pub finished: bool,
    /// `worker_finished` — the worker's outcome is known.
    pub worker_finished: bool,
    /// `aborted`.
    pub aborted: bool,
    /// `reap_proven` — the monitor proved the tree is reaped.
    pub reap_proven: bool,
    /// `retained` — the monitor holds the validated target lock.
    pub retained: bool,
    /// `released` — release ran to completion once.
    pub released: bool,
}

impl Record {
    /// A fresh record over a `spawn_supervised` result — the shape
    /// `handle_connection` builds before filling `deadline`/
    /// `hard_deadline`.
    pub fn new(
        mode: u8,
        operation_id: [u8; 16],
        spawned: Supervised,
        permits: PermitHold,
        pidfd: Option<OwnedFd>,
        monitor_pidfd: Option<OwnedFd>,
        id: [u8; 16],
    ) -> Self {
        Self {
            mode,
            id,
            operation_id,
            evidence_id: [0u8; 16],
            pid: spawned.worker_pid,
            pidfd,
            monitor_pid: spawned.monitor_pid,
            monitor_pidfd,
            evidence_fd: Some(spawned.evidence),
            completion_fd: Some(spawned.completion),
            control_fd: Some(spawned.control),
            waiter: None,
            permits: Some(permits),
            worker_outcome: 0,
            exit_code: 0,
            signal_number: 0,
            target_lock_proof: [0u8; 32],
            deadline: Instant::now(),
            hard_deadline: Instant::now(),
            finished_at: Instant::now(),
            committed: false,
            finished: false,
            worker_finished: false,
            aborted: false,
            reap_proven: false,
            retained: false,
            released: false,
        }
    }

    /// `notify_waiter` — answer a stored wait connection (OK only when
    /// the outcome is reaped, un-aborted, and a success is retained).
    fn notify_waiter(&mut self) {
        if self.waiter.is_none() || !self.worker_finished {
            return;
        }
        let Some(fd) = self.waiter.take() else {
            return;
        };
        let success_ready = self.worker_outcome != protocol::WORKER_SUCCEEDED || self.retained;
        let frame = if self.reap_proven && !self.aborted && success_ready {
            let proof = if self.worker_outcome == protocol::WORKER_SUCCEEDED && self.retained {
                Some(&self.target_lock_proof)
            } else {
                None
            };
            protocol::encode_wait(
                protocol::STATUS_OK,
                self.worker_outcome,
                self.exit_code,
                self.signal_number,
                proof,
            )
        } else {
            protocol::encode_wait(protocol::STATUS_DENIED, 0, 0, 0, None)
        };
        let _ = send(&fd, &frame, SendFlags::NOSIGNAL);
    }

    /// `complete_record` — reap the monitor, fold the final event in,
    /// release the permit pair, mark finished, answer the waiter.
    fn complete(&mut self, event: &MonitorEvent, aborted: bool, reap_proven: bool) {
        let _ = sys::wait_pid(self.monitor_pid, false);
        self.worker_outcome = event.outcome;
        self.exit_code = event.exit_code;
        self.signal_number = event.signal;
        self.worker_finished = true;
        self.pidfd = None;
        self.monitor_pidfd = None;
        self.evidence_fd = None;
        self.completion_fd = None;
        self.control_fd = None;
        self.permits = None;
        self.finished = true;
        self.aborted = aborted;
        self.reap_proven = reap_proven;
        self.retained = false;
        self.finished_at = Instant::now();
        self.notify_waiter();
    }

    /// `accept_retained_event` — the monitor holds the validated
    /// target lock; the launch stays open (not `finished`) until a
    /// release, abort, or the hard deadline.
    fn accept_retained(&mut self, event: &MonitorEvent) {
        self.worker_outcome = event.outcome;
        self.exit_code = event.exit_code;
        self.signal_number = event.signal;
        self.target_lock_proof = event.proof;
        self.worker_finished = true;
        self.reap_proven = true;
        self.retained = true;
        self.pidfd = None;
        self.evidence_fd = None;
        self.notify_waiter();
    }

    /// `terminate_record` — close the evidence channel, order the
    /// monitor to kill and reap the tree, and consume its final event.
    /// A monitor that cannot prove cleanup is SIGKILLed and the result
    /// marked `reap_proven = false` — never a successful wait boundary.
    pub fn terminate(&mut self, aborted: bool) {
        if self.finished {
            if aborted {
                self.aborted = true;
            }
            return;
        }
        self.evidence_fd = None;
        if let Some(ctl) = self.control_fd.as_ref() {
            let _ = write_exact(ctl, &[protocol::MONITOR_ABORT]);
        }
        let mut completion = MonitorEvent::new_final();
        let mut proven = true;
        let mut raw = [0u8; protocol::MONITOR_EVENT_SIZE];
        let read_ok = match self.completion_fd.as_ref() {
            Some(fd) => read_exact(fd, &mut raw).is_ok(),
            None => false,
        };
        if !read_ok {
            // Upstream: pidfd signal when the pidfd exists, `kill`
            // otherwise — an else-if, not a fallback chain.
            if let Some(pfd) = self.monitor_pidfd.as_ref() {
                let _ = sys::pidfd_send_signal(pfd.as_raw_fd(), libc::SIGKILL);
            } else if self.monitor_pid > 0 {
                let _ = sys::kill_pid(self.monitor_pid, libc::SIGKILL);
            }
            // Upstream's read-failure shape: FINAL/EXITED/255.
            completion.outcome = protocol::WORKER_EXITED;
            completion.exit_code = 255;
            proven = false;
        } else {
            let decoded = MonitorEvent::decode(&raw);
            // Upstream still folds a syntactically-read but invalid
            // event's fields in — `valid_monitor_event` only feeds
            // `reap_proven`.
            completion = decoded;
            if !protocol::valid_monitor_event(&decoded) {
                proven = false;
            }
        }
        self.complete(&completion, aborted, proven);
    }

    /// `release_record` — order the monitor to drop the retained
    /// socket and consume its `MONITOR_FINAL`.
    pub fn release(&mut self) -> Result<(), ()> {
        if !protocol::valid_mode(self.mode)
            || !self.retained
            || !self.worker_finished
            || self.finished
            || self.aborted
        {
            return Err(());
        }
        match self.control_fd.as_ref() {
            Some(fd) if write_exact(fd, &[protocol::MONITOR_RELEASE]).is_ok() => {}
            _ => return Err(()),
        }
        let mut raw = [0u8; protocol::MONITOR_EVENT_SIZE];
        match self.completion_fd.as_ref() {
            Some(fd) if read_exact(fd, &mut raw).is_ok() => {}
            _ => return Err(()),
        }
        let event = MonitorEvent::decode(&raw);
        if !protocol::valid_monitor_event(&event) || event.kind != protocol::MONITOR_FINAL {
            return Err(());
        }
        self.complete(&event, false, true);
        self.released = true;
        Ok(())
    }

    /// `assert_record_retained` — order a fresh retention assertion;
    /// the monitor must echo a `MONITOR_RETAINED` event carrying the
    /// same proof.
    pub fn assert_retained(&mut self, proof_out: &mut [u8; 32]) -> Result<(), ()> {
        if !protocol::valid_mode(self.mode)
            || !self.retained
            || !self.worker_finished
            || self.finished
            || self.aborted
        {
            return Err(());
        }
        match self.control_fd.as_ref() {
            Some(fd) if write_exact(fd, &[protocol::MONITOR_ASSERT]).is_ok() => {}
            _ => return Err(()),
        }
        let mut raw = [0u8; protocol::MONITOR_EVENT_SIZE];
        match self.completion_fd.as_ref() {
            Some(fd) if read_exact(fd, &mut raw).is_ok() => {}
            _ => return Err(()),
        }
        let event = MonitorEvent::decode(&raw);
        if !protocol::valid_monitor_event(&event)
            || event.kind != protocol::MONITOR_RETAINED
            || event.proof != self.target_lock_proof
        {
            return Err(());
        }
        *proof_out = event.proof;
        Ok(())
    }
}

/// `find_record` — the slot index of the named launch.
pub fn find_record(records: &[Record], id: &[u8; 16]) -> Option<usize> {
    records.iter().position(|r| &r.id == id)
}

/// `free_record` — `true` when a slot is free or a finished,
/// waiterless record can be evicted (the oldest one is, upstream's
/// pick).
pub fn ensure_slot(records: &mut Vec<Record>) -> bool {
    if records.len() < MAX_LAUNCHES {
        return true;
    }
    let mut oldest: Option<usize> = None;
    for (i, r) in records.iter().enumerate() {
        if !r.finished || r.waiter.is_some() {
            continue;
        }
        if oldest.is_none_or(|o| r.finished_at < records[o].finished_at) {
            oldest = Some(i);
        }
    }
    match oldest {
        Some(i) => {
            records.swap_remove(i);
            true
        }
        None => false,
    }
}

fn completion_readable(fd: &OwnedFd) -> bool {
    let mut fds = [PollFd::new(fd, PollFlags::IN | PollFlags::HUP)];
    const ZERO: Timespec = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    match rustix::event::poll(&mut fds, Some(&ZERO)) {
        Ok(n) => n > 0 && fds[0].revents().intersects(PollFlags::IN | PollFlags::HUP),
        Err(_) => false,
    }
}

/// `reap_records` — drain monitor events; kill uncommitted launches at
/// their deadline and every launch at its hard deadline; expire
/// finished records past `RESULT_RETENTION_SECONDS`.
pub fn reap_records(records: &mut Vec<Record>, retention_s: u64) {
    let now = Instant::now();
    let mut i = 0;
    while i < records.len() {
        if !records[i].finished {
            let ready = match records[i].completion_fd.as_ref() {
                Some(fd) => completion_readable(fd),
                None => false,
            };
            if ready {
                let mut raw = [0u8; protocol::MONITOR_EVENT_SIZE];
                let event = match records[i].completion_fd.as_ref() {
                    Some(fd) if read_exact(fd, &mut raw).is_ok() => {
                        let e = MonitorEvent::decode(&raw);
                        if protocol::valid_monitor_event(&e) {
                            Some(e)
                        } else {
                            None
                        }
                    }
                    _ => None,
                };
                match event {
                    None => records[i].terminate(false),
                    Some(e)
                        if e.kind == protocol::MONITOR_RETAINED && !records[i].worker_finished =>
                    {
                        records[i].accept_retained(&e);
                    }
                    Some(e) => records[i].complete(&e, false, true),
                }
            } else if !records[i].committed && now >= records[i].deadline {
                records[i].terminate(true);
            } else if now >= records[i].hard_deadline {
                records[i].terminate(false);
            }
            i += 1;
        } else if records[i].waiter.is_none()
            && now >= records[i].finished_at + Duration::from_secs(retention_s)
        {
            records.swap_remove(i);
        } else {
            i += 1;
        }
    }
}

/* ---- the monitor side (upstream `monitor_worker`/`spawn_worker`) ---- */

/// The monitor's fixed descriptors — `spawn_supervised_child`'s map.
const FD_REPO: RawFd = 3;
const FD_EVIDENCE: RawFd = 4;
const FD_STARTUP: RawFd = 5;
const FD_COMPLETION: RawFd = 6;
const FD_CONTROL: RawFd = 7;

/// What a launch needs that isn't request-supplied — the fixed
/// executable, identity, and socket shape.
pub struct SpawnSpec {
    /// `BACKUP_PATH`.
    pub backup_path: CString,
    /// `BACKUP_UID`.
    pub backup_uid: u32,
    /// `BACKUP_GID`.
    pub backup_gid: u32,
    /// Upstream's `CENTRAL_BACKUP_LAUNCHER_TEST_PEER_UID` build flag —
    /// `setgroups` is skipped and the uid/gid are the tester's.
    pub test_peer: bool,
    /// `htons(55432)` — the retained target's fixed peer port.
    pub retained_port: u16,
}

/// `direct_children` — `/proc/self/task/<pid>/children`.
fn direct_children() -> Result<Vec<i32>, Errno> {
    let path = format!(
        "/proc/self/task/{}/children",
        rustix::process::getpid().as_raw_nonzero()
    );
    let text = std::fs::read_to_string(&path).map_err(|_| Errno::IO)?;
    let mut out = Vec::new();
    for word in text.split_ascii_whitespace() {
        let v = word.parse::<i32>().map_err(|_| Errno::PROTO)?;
        if v <= 0 {
            return Err(Errno::PROTO);
        }
        out.push(v);
    }
    Ok(out)
}

/// `kill_and_reap_owned_descendants` — each direct child observed
/// belongs to exactly this launch (the monitor is a subreaper);
/// killing one adopts its descendants for the next loop.
fn kill_and_reap_owned_descendants() -> Result<(), Errno> {
    loop {
        let children = direct_children()?;
        if children.is_empty() {
            match sys::wait_any_nohang() {
                Ok(Some(_)) => continue,
                Ok(None) => return Ok(()),
                Err(Errno::INTR) => continue,
                Err(e) => return Err(e),
            }
        }
        for &c in &children {
            let _ = sys::kill_pid(c, libc::SIGKILL);
        }
        for &c in &children {
            sys::wait_pid(c, false)?;
        }
    }
}

/// `send_worker_handoff_ack` — the `CBW1` acknowledgement.
fn send_worker_handoff_ack<Fd: AsFd>(
    conn: Fd,
    status: u8,
    proof: Option<&[u8; 32]>,
) -> Result<(), ()> {
    let frame = protocol::encode_worker_ack(status, proof);
    match send(conn, &frame, SendFlags::NOSIGNAL) {
        Ok(n) if n == frame.len() => Ok(()),
        _ => Err(()),
    }
}

/// `receive_worker_handoff` — the worker's one shot at handing over
/// its validated target lock. Exactly one 40-byte `CBW1` offer plus
/// exactly one descriptor shaped like the retained target; anything
/// else is a denied acknowledgement and `handoff_invalid` upstream.
fn receive_worker_handoff<Fd: AsFd>(
    conn: Fd,
    already_retained: bool,
    retained_port: u16,
) -> Result<(OwnedFd, [u8; 32]), ()> {
    let packet = recv_packet(&conn).map_err(|_| ())?;
    let valid = packet.len == protocol::WORKER_FRAME_SIZE
        && packet.fds.len() == 1
        && protocol::valid_worker_offer(&packet.frame[..packet.len])
        && !already_retained
        && policy::valid_retained_target_socket(&packet.fds[0], retained_port);
    if !valid {
        drop(packet.fds);
        let _ = send_worker_handoff_ack(conn, protocol::STATUS_DENIED, None);
        return Err(());
    }
    let mut it = packet.fds.into_iter();
    let Some(fd) = it.next() else {
        return Err(());
    };
    let mut proof = [0u8; 32];
    proof.copy_from_slice(&packet.frame[8..40]);
    if send_worker_handoff_ack(conn, protocol::STATUS_OK, Some(&proof)).is_err() {
        return Err(());
    }
    Ok((fd, proof))
}

/// `spawn_worker` — the worker launch inside the monitor. The child
/// reports its pre-exec `errno` over the CLOEXEC diagnostics fd; EOF
/// means `execve` won.
#[allow(clippy::too_many_arguments)]
fn spawn_worker(
    mode: u8,
    operation_id: &[u8; 16],
    repository_fd: RawFd,
    evidence_read_fd: RawFd,
    lock_handoff_fd: RawFd,
    spec: &SpawnSpec,
) -> Result<i32, Errno> {
    let (err_read, err_write) = rustix::pipe::pipe_with(PipeFlags::CLOEXEC)?;
    let expected_parent = rustix::process::getpid().as_raw_nonzero().get();

    // argv/envp are built here but consumed only in the child.
    let op_text = sys::bytes_cstring(uuid_text(operation_id).as_bytes()).ok_or(Errno::INVAL)?;
    let verb: &std::ffi::CStr = if mode == protocol::MODE_BACKUP_CREATE {
        c"create"
    } else {
        c"throughput-probe"
    };
    let argv_ptrs: [*const libc::c_char; 4] = [
        c"central-backup".as_ptr(),
        verb.as_ptr(),
        op_text.as_ptr(),
        std::ptr::null(),
    ];
    let envp: [*const libc::c_char; 4] = [
        c"PATH=/usr/sbin:/usr/bin:/sbin:/bin".as_ptr(),
        c"LANG=C".as_ptr(),
        c"LC_ALL=C".as_ptr(),
        std::ptr::null(),
    ];

    let err_r = err_read.as_raw_fd();
    let err_w = err_write.as_raw_fd();
    match sys::fork() {
        Err(e) => Err(e),
        Ok(sys::Fork::Child) => {
            // Pre-exec: only syscall shuffles, ending in execve or
            // _exit — no Rust-managed state.
            sys::close(err_r);
            let mut report_fd = err_w;
            let errno = worker_child(
                repository_fd,
                evidence_read_fd,
                lock_handoff_fd,
                &mut report_fd,
                expected_parent,
                spec,
                &argv_ptrs,
                &envp,
            );
            let code = errno_i32(errno);
            let _ = sys::write_raw(report_fd, &code.to_ne_bytes());
            sys::exit(127);
        }
        Ok(sys::Fork::Parent(pid)) => {
            drop(err_write);
            // Upstream: one read retried on EINTR — EOF means `execve`
            // won (the fd is CLOEXEC); any bytes are the child's errno.
            let mut report = [0u8; 4];
            let bytes = loop {
                match rustix::io::read(&err_read, &mut report) {
                    Err(Errno::INTR) => continue,
                    other => break other,
                }
            };
            drop(err_read);
            match bytes {
                Ok(0) => Ok(pid),
                Ok(_) | Err(_) => {
                    let saved = match bytes {
                        Ok(_) => errno_from_i32(i32::from_ne_bytes(report)),
                        Err(e) => e,
                    };
                    let _ = sys::kill_pgroup(pid, libc::SIGKILL);
                    let _ = sys::kill_pid(pid, libc::SIGKILL);
                    let _ = sys::wait_pid(pid, false);
                    Err(saved)
                }
            }
        }
    }
}

/// The worker child's pre-exec sequence — every step fails by
/// reporting `errno` on `*report_fd` (the fixed FD6 once it exists).
#[allow(clippy::too_many_arguments)]
fn worker_child(
    repository_fd: RawFd,
    evidence_read_fd: RawFd,
    lock_handoff_fd: RawFd,
    report_fd: &mut RawFd,
    expected_parent: i32,
    spec: &SpawnSpec,
    argv_ptrs: &[*const libc::c_char],
    envp: &[*const libc::c_char],
) -> Errno {
    if sys::set_pdeathsig(libc::SIGKILL).is_err() {
        return sys::last_errno();
    }
    if rustix::process::getppid().map(|p| p.as_raw_nonzero().get()) != Some(expected_parent) {
        return Errno::CHILD;
    }
    if sys::setsid().is_err() {
        return sys::last_errno();
    }
    // Duplicate the sources first so a low-numbered original can
    // never collide with a fixed target (upstream's F_DUPFD_CLOEXEC).
    let evidence_source = match sys::dupfd_cloexec(evidence_read_fd, 10) {
        Ok(f) => f,
        Err(e) => return e,
    };
    let repository_source = match sys::dupfd_cloexec(repository_fd, 10) {
        Ok(f) => f,
        Err(e) => return e,
    };
    let handoff_source = match sys::dupfd_cloexec(lock_handoff_fd, 10) {
        Ok(f) => f,
        Err(e) => return e,
    };
    let error_source = match sys::dupfd_cloexec(*report_fd, 10) {
        Ok(f) => f,
        Err(e) => return e,
    };
    if sys::dup3(evidence_source.as_raw_fd(), 3, false).is_err()
        || sys::dup3(repository_source.as_raw_fd(), 4, false).is_err()
        || sys::dup3(handoff_source.as_raw_fd(), 5, false).is_err()
        || sys::dup3(error_source.as_raw_fd(), 6, true).is_err()
    {
        return sys::last_errno();
    }
    *report_fd = 6;
    sys::close_from(7);
    let null_fd = match sys::open_rdwr_cloexec(c"/dev/null") {
        Ok(f) => f,
        Err(e) => return e,
    };
    if sys::dup2(null_fd, 0).is_err()
        || sys::dup2(null_fd, 1).is_err()
        || sys::dup2(null_fd, 2).is_err()
    {
        return sys::last_errno();
    }
    if null_fd > 2 {
        sys::close(null_fd);
    }
    if !spec.test_peer && sys::set_groups_none().is_err() {
        return sys::last_errno();
    }
    if sys::drop_to(spec.backup_uid, spec.backup_gid).is_err() {
        return sys::last_errno();
    }
    sys::execve(&spec.backup_path, argv_ptrs, envp)
}

/// `monitor_worker` — the monitor's whole life on its fixed
/// descriptors. Returns upstream's `0`/`-1`; the caller `_exit`s it.
fn monitor_worker(
    mode: u8,
    operation_id: &[u8; 16],
    spec: &SpawnSpec,
    expected_parent: i32,
) -> i32 {
    sys::sigaction_handler(libc::SIGTERM, on_monitor_abort as *const () as usize);
    sys::sigaction_handler(libc::SIGINT, on_monitor_abort as *const () as usize);
    if sys::set_pdeathsig(libc::SIGTERM).is_err()
        || rustix::process::getppid().map(|p| p.as_raw_nonzero().get()) != Some(expected_parent)
        || sys::set_child_subreaper().is_err()
    {
        return -1;
    }
    if !protocol::valid_mode(mode) {
        return -1;
    }
    let (handoff_m, handoff_w) = match socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    ) {
        Ok(p) => p,
        Err(_) => return -1,
    };
    let worker_pid = match spawn_worker(
        mode,
        operation_id,
        FD_REPO,
        FD_EVIDENCE,
        handoff_w.as_raw_fd(),
        spec,
    ) {
        Ok(p) => p,
        Err(e) => {
            let startup = MonitorStartup {
                worker_pid: 0,
                error_number: errno_i32(e),
            };
            let _ = write_exact(sys::borrow(FD_STARTUP), &startup.encode());
            return -1;
        }
    };
    drop(handoff_w);
    let mut error_number = 0;
    if !spec.test_peer
        && let Err(e) = sys::set_groups_none()
    {
        error_number = errno_i32(e);
    }
    if error_number == 0
        && let Err(e) = sys::drop_to(spec.backup_uid, spec.backup_gid)
    {
        error_number = errno_i32(e);
    }
    if error_number == 0
        && (sys::set_pdeathsig(libc::SIGTERM).is_err()
            || rustix::process::getppid().map(|p| p.as_raw_nonzero().get())
                != Some(expected_parent))
    {
        error_number = libc::ECHILD;
    }
    if error_number != 0 {
        let _ = sys::kill_pgroup(worker_pid, libc::SIGKILL);
        let _ = sys::kill_pid(worker_pid, libc::SIGKILL);
        let _ = sys::wait_pid(worker_pid, false);
        let _ = kill_and_reap_owned_descendants();
        let startup = MonitorStartup {
            worker_pid: 0,
            error_number,
        };
        let _ = write_exact(sys::borrow(FD_STARTUP), &startup.encode());
        return -1;
    }
    let startup = MonitorStartup {
        worker_pid,
        error_number: 0,
    };
    if write_exact(sys::borrow(FD_STARTUP), &startup.encode()).is_err() {
        MONITOR_ABORT.store(true, Ordering::SeqCst);
    }
    sys::close(FD_STARTUP);
    sys::close(FD_REPO);
    sys::close(FD_EVIDENCE);

    let mut worker_status = 0;
    let mut worker_waited = false;
    let mut handoff_invalid = false;
    let mut retained: Option<OwnedFd> = None;
    let mut retained_proof = [0u8; 32];
    while !worker_waited && !MONITOR_ABORT.load(Ordering::SeqCst) {
        match sys::wait_pid(worker_pid, true) {
            Ok(Some(status)) => {
                worker_status = status;
                worker_waited = true;
                break;
            }
            Ok(None) => {}
            Err(_) => {
                MONITOR_ABORT.store(true, Ordering::SeqCst);
                break;
            }
        }
        let control_fd = sys::borrow(FD_CONTROL);
        let mut descriptors = [
            PollFd::new(&control_fd, PollFlags::IN | PollFlags::HUP),
            PollFd::new(&handoff_m, PollFlags::IN | PollFlags::HUP),
        ];
        let ready = rustix::event::poll(&mut descriptors, Some(&ms_timespec(100)));
        if let Ok(n) = ready
            && n > 0
            && descriptors[0]
                .revents()
                .intersects(PollFlags::IN | PollFlags::HUP)
        {
            let mut command = [0u8; 1];
            let _ = rustix::io::read(sys::borrow(FD_CONTROL), &mut command);
            MONITOR_ABORT.store(true, Ordering::SeqCst);
        }
        // SC-DEF-47: after a successful handoff the worker closing its
        // end delivers POLLIN (EOF) alongside POLLHUP — expected, not a
        // second message. Only accept a handoff attempt while none has
        // been retained yet.
        if let Ok(n) = ready
            && n > 0
            && retained.is_none()
            && descriptors[1].revents().contains(PollFlags::IN)
        {
            match receive_worker_handoff(&handoff_m, false, spec.retained_port) {
                Ok((fd, proof)) => {
                    retained = Some(fd);
                    retained_proof = proof;
                }
                Err(()) => handoff_invalid = true,
            }
        } else if let Ok(n) = ready
            && n > 0
            && retained.is_none()
            && descriptors[1].revents().contains(PollFlags::HUP)
        {
            handoff_invalid = true;
        }
        if let Err(e) = ready
            && e != Errno::INTR
        {
            MONITOR_ABORT.store(true, Ordering::SeqCst);
        }
    }
    if !worker_waited {
        let _ = sys::kill_pgroup(worker_pid, libc::SIGKILL);
        let _ = sys::kill_pid(worker_pid, libc::SIGKILL);
        loop {
            match sys::wait_pid(worker_pid, false) {
                Ok(Some(status)) => {
                    worker_status = status;
                    worker_waited = true;
                    break;
                }
                Ok(None) => continue,
                Err(Errno::INTR) => continue,
                Err(_) => break,
            }
        }
    }
    let mut completion = MonitorEvent::new_final();
    if worker_waited {
        let (outcome, exit_code, signal) = protocol::worker_outcome(worker_status);
        completion.outcome = outcome;
        completion.exit_code = exit_code;
        completion.signal = signal;
    } else {
        completion.outcome = protocol::WORKER_EXITED;
        completion.exit_code = 255;
    }
    if kill_and_reap_owned_descendants().is_err() {
        return -1;
    }
    if !sys::pgroup_gone(worker_pid) {
        return -1;
    }
    drop(handoff_m);
    if completion.outcome != protocol::WORKER_SUCCEEDED
        || MONITOR_ABORT.load(Ordering::SeqCst)
        || handoff_invalid
        || retained.is_none()
        || protocol::zero_digest(&retained_proof)
    {
        if completion.outcome == protocol::WORKER_SUCCEEDED {
            completion.outcome = protocol::WORKER_EXITED;
            completion.exit_code = 255;
        }
        drop(retained);
        if write_exact(sys::borrow(FD_COMPLETION), &completion.encode()).is_err() {
            return -1;
        }
        return 0;
    }
    completion.kind = protocol::MONITOR_RETAINED;
    completion.proof = retained_proof;
    if write_exact(sys::borrow(FD_COMPLETION), &completion.encode()).is_err() {
        return -1;
    }
    let Some(retained_fd) = retained else {
        return -1;
    };
    while !MONITOR_ABORT.load(Ordering::SeqCst) {
        let control_fd = sys::borrow(FD_CONTROL);
        let mut descriptors = [
            PollFd::new(&control_fd, PollFlags::IN | PollFlags::HUP),
            PollFd::new(
                &retained_fd,
                PollFlags::ERR | PollFlags::HUP | PollFlags::RDHUP,
            ),
        ];
        let ready = rustix::event::poll(&mut descriptors, None);
        if let Ok(n) = ready
            && n > 0
            && descriptors[1]
                .revents()
                .intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::RDHUP)
        {
            MONITOR_ABORT.store(true, Ordering::SeqCst);
            break;
        }
        if let Ok(n) = ready
            && n > 0
            && descriptors[0]
                .revents()
                .intersects(PollFlags::IN | PollFlags::HUP)
        {
            let mut command = [0u8; 1];
            let bytes = loop {
                match rustix::io::read(sys::borrow(FD_CONTROL), &mut command) {
                    Err(Errno::INTR) => continue,
                    other => break other,
                }
            };
            let got = matches!(bytes, Ok(n) if n > 0);
            if !got
                || command[0] == protocol::MONITOR_ABORT
                || command[0] == protocol::MONITOR_RELEASE
            {
                break;
            }
            if command[0] == protocol::MONITOR_ASSERT
                && policy::valid_retained_target_socket(&retained_fd, spec.retained_port)
            {
                if write_exact(sys::borrow(FD_COMPLETION), &completion.encode()).is_err() {
                    MONITOR_ABORT.store(true, Ordering::SeqCst);
                }
            } else {
                MONITOR_ABORT.store(true, Ordering::SeqCst);
            }
        } else if let Err(e) = ready
            && e != Errno::INTR
        {
            MONITOR_ABORT.store(true, Ordering::SeqCst);
        }
    }
    drop(retained_fd);
    let mut final_event = MonitorEvent::new_final();
    final_event.outcome = protocol::WORKER_SUCCEEDED;
    if write_exact(sys::borrow(FD_COMPLETION), &final_event.encode()).is_err()
        && !MONITOR_ABORT.load(Ordering::SeqCst)
    {
        return -1;
    }
    0
}

/// `spawn_supervised_child` — fork the monitor over a fresh set of
/// pipes; on success return the parent's channel ends.
pub struct Supervised {
    /// The worker's pid (as reported by the monitor's startup write).
    pub worker_pid: i32,
    /// The monitor's pid.
    pub monitor_pid: i32,
    /// The evidence write end (the record's `evidence_fd`).
    pub evidence: OwnedFd,
    /// The completion read end (the record's `completion_fd`).
    pub completion: OwnedFd,
    /// The control write end (the record's `control_fd`).
    pub control: OwnedFd,
}

/// `spawn_supervised_child`. `permit_fds` are closed inside the child
/// (`close_permits_in_child`); the parent keeps its `PermitHold`.
#[allow(clippy::too_many_arguments)]
pub fn spawn_supervised(
    mode: u8,
    operation_id: &[u8; 16],
    repository_fd: RawFd,
    permit_fds: (RawFd, RawFd),
    spec: &SpawnSpec,
) -> Result<Supervised, Errno> {
    let (evidence_r, evidence_w) = rustix::pipe::pipe_with(PipeFlags::CLOEXEC)?;
    let (startup_r, startup_w) = rustix::pipe::pipe_with(PipeFlags::CLOEXEC)?;
    let (completion_r, completion_w) = rustix::pipe::pipe_with(PipeFlags::CLOEXEC)?;
    let (control_r, control_w) = rustix::pipe::pipe_with(PipeFlags::CLOEXEC)?;
    let expected_parent = rustix::process::getpid().as_raw_nonzero().get();
    let op_id = *operation_id;
    match sys::fork() {
        Err(e) => Err(e),
        Ok(sys::Fork::Child) => {
            // Pre-monitor: only syscall shuffles, ending in _exit.
            sys::close(permit_fds.0);
            sys::close(permit_fds.1);
            let originals = [
                repository_fd,
                evidence_r.as_raw_fd(),
                startup_w.as_raw_fd(),
                completion_w.as_raw_fd(),
                control_r.as_raw_fd(),
            ];
            let mut sources = [0i32; 5];
            let mut ok = true;
            for (i, o) in originals.iter().enumerate() {
                match sys::dupfd_cloexec(*o, 20) {
                    Ok(f) => sources[i] = f.into_raw_fd(),
                    Err(_) => {
                        ok = false;
                        break;
                    }
                }
            }
            if ok {
                for (i, s) in sources.iter().enumerate() {
                    if sys::dup3(*s, 3 + i as RawFd, true).is_err() {
                        ok = false;
                        break;
                    }
                }
            }
            if !ok {
                sys::exit(127);
            }
            sys::close_from(8);
            let result = monitor_worker(mode, &op_id, spec, expected_parent);
            sys::exit(if result == 0 { 0 } else { 127 });
        }
        Ok(sys::Fork::Parent(monitor_pid)) => {
            drop(evidence_r);
            drop(startup_w);
            drop(completion_w);
            drop(control_r);
            let mut raw = [0u8; protocol::MONITOR_STARTUP_SIZE];
            let startup = if read_exact(&startup_r, &mut raw).is_ok() {
                MonitorStartup::decode(&raw)
            } else {
                MonitorStartup {
                    worker_pid: 0,
                    error_number: libc::EIO,
                }
            };
            drop(startup_r);
            if startup.worker_pid <= 0 || startup.error_number != 0 {
                drop(evidence_w);
                drop(completion_r);
                drop(control_w);
                let _ = sys::kill_pid(monitor_pid, libc::SIGKILL);
                let _ = sys::wait_pid(monitor_pid, false);
                // `startup_result.error_number == 0 → EIO` upstream.
                return Err(errno_from_i32(startup.error_number));
            }
            Ok(Supervised {
                worker_pid: startup.worker_pid,
                monitor_pid,
                evidence: evidence_w,
                completion: completion_r,
                control: control_w,
            })
        }
    }
}
