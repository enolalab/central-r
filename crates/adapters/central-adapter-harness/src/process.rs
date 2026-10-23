//! Shared process-boundary helpers used by this crate's launchers and
//! the harness session adapters built on them: the bounded NDJSON frame
//! reader (`bufio.Scanner` with `maxFrameBytes` upstream), the probe
//! read cap, the drained-stderr discard, the wait-after-close exit
//! grace, the detached kill ladder, and single-assignment result cells.
//!
//! Everything here is bounded: a frame can never grow past
//! [`MAX_FRAME_BYTES`], a probe read never past `cap + 1`, and a kill
//! ladder runs to completion once started regardless of caller
//! cancellation — matching upstream `internal/adapter/harness`
//! semantics.

use std::future::Future;
use std::path::{Component, Path, PathBuf};
use std::sync::Once;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use central_foundation::failure::Failure;
use central_harness::port::{ExitStatus, PortFuture, Process};

/// `maxFrameBytes` — bounds one NDJSON line from the harness
/// (16 MiB, mirroring upstream claudecode/opencode/codex/antigravity).
pub const MAX_FRAME_BYTES: usize = 16 << 20;

/// `probeOutputCap` — bounds one probe's captured stdout
/// (64 KiB, spec decision 12).
pub const PROBE_OUTPUT_CAP: usize = 64 << 10;

/// `exitGrace` — how long a session waits for the process to exit after
/// its stdout closed before killing the tree (10 s upstream).
pub const EXIT_GRACE: Duration = Duration::from_secs(10);

/// Stable machine codes for the shared process helpers.
pub(crate) mod codes {
    /// A read, write or signal against a child process failed — the
    /// upstream `"<adapter>: <op>: %w"` os-error wraps. The message
    /// carries only a closed reason token, never the OS error text.
    pub const PROCESS_IO: &str = "harness_adapter_process_io";
    /// A harness frame exceeded [`MAX_FRAME_BYTES`] — upstream's
    /// `bufio.ErrTooLong` path (`ReasonProtocolError` in the sessions).
    pub const FRAME_TOO_LONG: &str = "harness_adapter_frame_too_long";
    /// The kill ladder's own failure (a group that survived SIGKILL, or
    /// a signal that could not be sent).
    pub const KILL_LADDER: &str = "harness_adapter_kill_ladder";
}

/// Which of a process's output streams a helper reads — the upstream
/// `Stdout()`/`Stderr()` pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    /// The process's stdout.
    Stdout,
    /// The process's stderr.
    Stderr,
}

async fn read_stream(proc: &dyn Process, stream: Stream, buf: &mut [u8]) -> Result<usize, Failure> {
    match stream {
        Stream::Stdout => proc.read_stdout(buf).await,
        Stream::Stderr => proc.read_stderr(buf).await,
    }
}

/// `FrameReader` pulls bounded NDJSON lines from a [`Process`]'s
/// stdout — the `bufio.Scanner` of the upstream session loops with a
/// `maxFrameBytes` cap. A line that grows past the cap is refused with
/// [`codes::FRAME_TOO_LONG`], as `bufio.ErrTooLong` is upstream. The
/// final line is emitted even without a trailing newline, matching the
/// scanner's last-token rule. Empty lines are returned to the caller —
/// the session loop skips them, as upstream does.
pub struct FrameReader {
    buf: Vec<u8>,
    pos: usize,
    eof: bool,
}

impl FrameReader {
    /// A reader over `proc`'s stdout.
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(64 << 10),
            pos: 0,
            eof: false,
        }
    }

    /// The next line, `None` at EOF. Never returns more than
    /// [`MAX_FRAME_BYTES`] plus one read chunk of buffered input.
    pub async fn next(&mut self, proc: &dyn Process) -> Result<Option<Vec<u8>>, Failure> {
        let mut chunk = vec![0u8; 64 << 10];
        loop {
            if let Some(nl) = self.buf[self.pos..].iter().position(|b| *b == b'\n') {
                // The newline does not rescue an over-cap line: the
                // token cap is on bytes scanned, not on reads —
                // `bufio.ErrTooLong` upstream. A token of exactly
                // `maxFrameBytes` is already too long: upstream's
                // scanner reports ErrTooLong at
                // `len(buffer) >= maxTokenSize` — the newline could
                // never be read into a full buffer.
                if nl >= MAX_FRAME_BYTES {
                    return Err(Failure::invalid(
                        codes::FRAME_TOO_LONG,
                        "harness frame exceeds the 16 MiB cap",
                    ));
                }
                let line = self.buf[self.pos..self.pos + nl].to_vec();
                self.pos += nl + 1;
                if self.pos == self.buf.len() {
                    self.buf.clear();
                    self.pos = 0;
                }
                return Ok(Some(line));
            }
            if self.eof {
                // An unterminated tail is a token too: upstream's scanner
                // reports ErrTooLong when the buffer reaches the cap even
                // though no newline ever arrives.
                if self.buf.len() - self.pos >= MAX_FRAME_BYTES {
                    return Err(Failure::invalid(
                        codes::FRAME_TOO_LONG,
                        "harness frame exceeds the 16 MiB cap",
                    ));
                }
                if self.pos < self.buf.len() {
                    let line = self.buf[self.pos..].to_vec();
                    self.pos = self.buf.len();
                    return Ok(Some(line));
                }
                return Ok(None);
            }
            if self.buf.len() - self.pos >= MAX_FRAME_BYTES {
                return Err(Failure::invalid(
                    codes::FRAME_TOO_LONG,
                    "harness frame exceeds the 16 MiB cap",
                ));
            }
            if self.pos > 0 {
                self.buf.drain(..self.pos);
                self.pos = 0;
            }
            match proc.read_stdout(&mut chunk).await {
                Ok(0) => self.eof = true,
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e) => return Err(e),
            }
        }
    }
}

/// `drain_discard` reads `stream` to EOF discarding every byte — the
/// `io.Copy(io.Discard, proc.Stderr())` of the upstream session and
/// probe loops. Stderr in particular may carry account details and is
/// never stored. Read errors are returned for the caller to ignore or
/// handle, matching upstream's `_, _ =` convention at the call site.
pub async fn drain_discard(proc: &dyn Process, stream: Stream) -> Result<(), Failure> {
    let mut buf = [0u8; 8192];
    loop {
        match read_stream(proc, stream, &mut buf).await {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(e) => return Err(e),
        }
    }
}

/// `read_capped` reads a process's stdout to EOF, keeping at most
/// `cap + 1` bytes — upstream's
/// `io.ReadAll(io.LimitReader(proc.Stdout(), cap+1))` followed by the
/// discard drain. The caller compares `out.len()` against `cap` exactly
/// as upstream does: `cap + 1` means "over". A read error is reported
/// after the rest of the stream is drained, as upstream's goroutine
/// does.
pub async fn read_capped(proc: &dyn Process, cap: usize) -> Result<Vec<u8>, Failure> {
    let mut out: Vec<u8> = Vec::with_capacity(cap.saturating_add(1).min(1 << 20));
    let mut buf = [0u8; 8192];
    loop {
        match proc.read_stdout(&mut buf).await {
            Ok(0) => return Ok(out),
            Ok(n) => {
                let room = cap.saturating_add(1).saturating_sub(out.len());
                let take = room.min(n);
                out.extend_from_slice(&buf[..take]);
                // `take < n` means the cap is exceeded: keep reading to
                // drain the pipe but store nothing more, exactly as
                // upstream keeps draining after the limit is hit.
            }
            Err(e) => {
                let _ = drain_discard(proc, Stream::Stdout).await;
                return Err(e);
            }
        }
    }
}

/// `wait_exit` — the upstream sessions' `waitExit`: wait up to `grace`
/// for the process after its stdout closed; on timeout or error, kill
/// the tree and wait again without a deadline.
pub async fn wait_exit(proc: &dyn Process, grace: Duration) -> Result<ExitStatus, Failure> {
    if let Ok(Ok(status)) = tokio::time::timeout(grace, proc.wait()).await {
        return Ok(status);
    }
    let _ = proc.kill().await;
    proc.wait().await
}

/// `Outcome` — a single-assignment result cell shared by the kill
/// ladder and a process's wait channel: the producer [`set`]s it once,
/// every [`wait`]er receives the stored value no matter when it calls.
/// Implemented on `tokio::sync::watch` so a waiter never misses a value
/// published before it subscribed.
pub(crate) struct Outcome<T> {
    tx: tokio::sync::watch::Sender<Option<T>>,
    rx: tokio::sync::watch::Receiver<Option<T>>,
}

impl<T: Clone> Outcome<T> {
    /// An unset cell.
    pub(crate) fn new() -> Self {
        let (tx, rx) = tokio::sync::watch::channel(None);
        Self { tx, rx }
    }

    /// Publishes the value. Later calls overwrite; producers set it
    /// once.
    pub(crate) fn set(&self, value: T) {
        let _ = self.tx.send(Some(value));
    }

    /// A second handle on the same cell, for a producer that must be
    /// moved into a spawned task.
    pub(crate) fn sender(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            rx: self.rx.clone(),
        }
    }

    /// Resolves with the stored value once set.
    pub(crate) async fn wait(&self) -> T {
        let mut rx = self.rx.clone();
        loop {
            if let Some(v) = rx.borrow().clone() {
                return v;
            }
            if rx.changed().await.is_err() {
                // The cell owns one sender, so this is unreachable while
                // `self` lives; park rather than spin if it somehow is.
                std::future::pending::<()>().await;
            }
        }
    }
}

/// `KillLadder` — the detached kill run shared by the launchers'
/// `Process::kill`: `start` fires the ladder exactly once, in a spawned
/// task so it always runs to completion even when the caller's future
/// is dropped (upstream's detached goroutine); `wait` reports the same
/// result to every caller, now and later (upstream's `killDone`
/// channel + `killOnce`).
pub(crate) struct KillLadder {
    once: Once,
    outcome: Outcome<Result<(), Failure>>,
}

impl KillLadder {
    /// An unstarted ladder.
    pub(crate) fn new() -> Self {
        Self {
            once: Once::new(),
            outcome: Outcome::new(),
        }
    }

    /// Starts the ladder detached on the first call; later calls do
    /// nothing — upstream `killOnce.Do`. Must be called inside a Tokio
    /// runtime (every `port::Process` method is).
    pub(crate) fn start<F, Fut>(&self, f: F)
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), Failure>> + Send + 'static,
    {
        self.once.call_once(|| {
            let outcome_tx = self.outcome.sender();
            tokio::spawn(async move {
                let result = f().await;
                outcome_tx.set(result);
            });
        });
    }

    /// Resolves with the ladder's result once it finishes — upstream's
    /// `<-p.killDone; return p.killErr`.
    pub(crate) async fn wait(&self) -> Result<(), Failure> {
        self.outcome.wait().await
    }
}

// The workspace pins tokio without `io-util`, so the `*Ext` helpers are
// unavailable; the core `AsyncRead`/`AsyncWrite` traits are. These are
// their `read`/`write`/`shutdown` shorthands over `poll_fn`.

/// `r.read(buf)` on the core `AsyncRead` trait.
pub(crate) async fn async_read<R>(r: &mut R, buf: &mut [u8]) -> std::io::Result<usize>
where
    R: tokio::io::AsyncRead + Unpin,
{
    std::future::poll_fn(|cx| {
        let mut rb = tokio::io::ReadBuf::new(buf);
        match std::pin::Pin::new(&mut *r).poll_read(cx, &mut rb) {
            std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok(rb.filled().len())),
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    })
    .await
}

/// `w.write(buf)` on the core `AsyncWrite` trait.
pub(crate) async fn async_write<W>(w: &mut W, buf: &[u8]) -> std::io::Result<usize>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    std::future::poll_fn(|cx| std::pin::Pin::new(&mut *w).poll_write(cx, buf)).await
}

/// `w.shutdown()` on the core `AsyncWrite` trait.
pub(crate) async fn async_shutdown<W>(w: &mut W) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    std::future::poll_fn(|cx| std::pin::Pin::new(&mut *w).poll_shutdown(cx)).await
}

/// `read_end` — a pipe read end that is dropped once it reports EOF or
/// an error, so a drained pipe never leaks its descriptor: the
/// `closeOnEOF`/`closeOnError` wrappers of upstream hostlauncher and
/// localexec.
pub(crate) struct ReadEnd<R> {
    inner: Option<R>,
}

impl<R> ReadEnd<R> {
    /// Wraps the read end.
    pub(crate) fn new(inner: R) -> Self {
        Self { inner: Some(inner) }
    }

    /// Reads into `buf`; `Ok(0)` is EOF. On EOF or error the end is
    /// dropped so the descriptor closes, then the result is reported —
    /// the upstream `Read` semantics exactly.
    pub(crate) async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Failure>
    where
        R: tokio::io::AsyncRead + Unpin,
    {
        let Some(r) = self.inner.as_mut() else {
            return Ok(0);
        };
        match async_read(r, buf).await {
            Ok(0) => {
                self.inner = None;
                Ok(0)
            }
            Ok(n) => Ok(n),
            Err(_) => {
                self.inner = None;
                Err(Failure::internal(
                    codes::PROCESS_IO,
                    "process stream read failed",
                ))
            }
        }
    }
}

/// `filepath.Clean` for an absolute path — keeps `RootDir`/`Normal`
/// components only. Shared by the launchers' path rules (localexec's
/// program table, hostlauncher's config and workdir checks).
pub(crate) fn clean_path(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::RootDir => out.push(c.as_os_str()),
            Component::Normal(n) => out.push(n),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Prefix(_) => {}
        }
    }
    out
}

/// `GroupGone` — the shared "the process group was observed gone"
/// record of upstream localexec's `groupGone` atomic: set once a
/// reaper, kill ladder or liveness probe observes the group empty, so a
/// recycled pgid can never be read as the scope being alive.
pub(crate) type GroupGone = std::sync::Arc<AtomicBool>;

/// A new cleared flag.
pub(crate) fn group_gone() -> GroupGone {
    std::sync::Arc::new(AtomicBool::new(false))
}

/// Whether the group is already known gone.
pub(crate) fn is_gone(g: &GroupGone) -> bool {
    g.load(Ordering::SeqCst)
}

/// Records the group as gone.
pub(crate) fn mark_gone(g: &GroupGone) {
    g.store(true, Ordering::SeqCst);
}

/// `await_group_gone` — poll `alive` until it reports the group empty
/// or `deadline` passes; reports whether the group is gone. The 20 ms
/// ticker matches upstream localexec's `awaitGroupGone`.
pub(crate) async fn await_group_gone(alive: impl Fn() -> bool + Send, deadline: Instant) -> bool {
    let mut ticker = tokio::time::interval(Duration::from_millis(20));
    loop {
        if !alive() {
            return true;
        }
        if Instant::now() > deadline {
            return false;
        }
        ticker.tick().await;
    }
}

impl<T: Clone> Default for Outcome<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for KillLadder {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for FrameReader {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)]
fn _port_future_marker(f: PortFuture<'_, ()>) -> PortFuture<'_, ()> {
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;

    /// `scriptProc` — a `port::Process` fake that plays scripted stdout
    /// bytes, resolves `wait` from an [`Outcome`] (so `kill` can flip a
    /// late exit), and records `kill` calls.
    struct ScriptProc {
        stdout: tokio::sync::Mutex<VecDeque<u8>>,
        wait_out: Outcome<ExitStatus>,
        kills: AtomicUsize,
    }

    impl ScriptProc {
        fn output(bytes: &[u8]) -> Self {
            Self {
                stdout: tokio::sync::Mutex::new(bytes.iter().copied().collect()),
                wait_out: Outcome::new(),
                kills: AtomicUsize::new(0),
            }
        }

        fn exits(&self, status: ExitStatus) {
            self.wait_out.set(status);
        }

        fn killed(&self) -> usize {
            self.kills.load(Ordering::SeqCst)
        }
    }

    impl Process for ScriptProc {
        fn scope_id(&self) -> &str {
            "scope-test"
        }

        fn write_stdin<'a>(&'a self, buf: &'a [u8]) -> PortFuture<'a, Result<usize, Failure>> {
            let n = buf.len();
            Box::pin(async move { Ok(n) })
        }

        fn close_stdin(&self) -> PortFuture<'_, Result<(), Failure>> {
            Box::pin(async { Ok(()) })
        }

        fn read_stdout<'a>(&'a self, buf: &'a mut [u8]) -> PortFuture<'a, Result<usize, Failure>> {
            Box::pin(async move {
                let mut q = self.stdout.lock().await;
                let n = buf.len().min(q.len());
                for b in buf.iter_mut().take(n) {
                    *b = q.pop_front().unwrap_or(0);
                }
                Ok(n)
            })
        }

        fn read_stderr<'a>(&'a self, buf: &'a mut [u8]) -> PortFuture<'a, Result<usize, Failure>> {
            Box::pin(async move {
                let _ = buf;
                Ok(0)
            })
        }

        fn wait(&self) -> PortFuture<'_, Result<ExitStatus, Failure>> {
            Box::pin(async move { Ok(self.wait_out.wait().await) })
        }

        fn kill(&self) -> PortFuture<'_, Result<(), Failure>> {
            Box::pin(async move {
                self.kills.fetch_add(1, Ordering::SeqCst);
                self.wait_out.set(ExitStatus {
                    code: 137,
                    signaled: true,
                });
                Ok(())
            })
        }
    }

    /// `TestFrameReaderLines` — newline-split frames, the last
    /// unterminated line, then EOF (`bufio.Scanner` semantics).
    #[tokio::test]
    async fn frame_reader_splits_lines_and_eof() {
        let p = ScriptProc::output(b"one\ntwo\n\nlast-no-newline");
        let mut r = FrameReader::new();
        let mut got = Vec::new();
        while let Some(line) = r.next(&p).await.unwrap_or(None) {
            got.push(line);
        }
        assert_eq!(
            got,
            vec![
                b"one".to_vec(),
                b"two".to_vec(),
                Vec::<u8>::new(),
                b"last-no-newline".to_vec()
            ]
        );
        assert_eq!(r.next(&p).await.unwrap_or(Some(vec![9])), None);
    }

    /// A frame that grows past `maxFrameBytes` is refused —
    /// `bufio.ErrTooLong` upstream.
    #[tokio::test]
    async fn frame_reader_refuses_over_cap_line() {
        let mut data = vec![b'x'; MAX_FRAME_BYTES + 8];
        data.push(b'\n');
        let p = ScriptProc::output(&data);
        let mut r = FrameReader::new();
        let err = r
            .next(&p)
            .await
            .err()
            .unwrap_or_else(|| unreachable!("over-cap frame must fail"));
        assert_eq!(err.code(), codes::FRAME_TOO_LONG);
    }

    /// A token of exactly `maxFrameBytes` is already too long —
    /// `bufio.Scanner` reports ErrTooLong at `len(buffer) >=
    /// maxTokenSize` (the newline could never fit in the buffer).
    /// One byte under scans.
    #[tokio::test]
    async fn frame_reader_refuses_a_cap_sized_line() {
        let mut data = vec![b'y'; MAX_FRAME_BYTES];
        data.push(b'\n');
        let p = ScriptProc::output(&data);
        let mut r = FrameReader::new();
        let err = r
            .next(&p)
            .await
            .err()
            .unwrap_or_else(|| unreachable!("cap-sized frame must fail"));
        assert_eq!(err.code(), codes::FRAME_TOO_LONG);

        let mut data = vec![b'y'; MAX_FRAME_BYTES - 1];
        data.push(b'\n');
        let p = ScriptProc::output(&data);
        let mut r = FrameReader::new();
        let line = r.next(&p).await.unwrap_or(None).unwrap_or_default();
        assert_eq!(line.len(), MAX_FRAME_BYTES - 1);
    }

    /// An unterminated tail of exactly `maxFrameBytes` at EOF is
    /// refused like a capped newline-terminated frame — upstream's
    /// `bufio.Scanner` reports ErrTooLong the moment the buffer reaches
    /// the cap, whether or not a newline ever arrives.
    #[tokio::test]
    async fn frame_reader_refuses_an_unterminated_cap_sized_eof_tail() {
        let data = vec![b'z'; MAX_FRAME_BYTES];
        let p = ScriptProc::output(&data);
        let mut r = FrameReader::new();
        let err = r
            .next(&p)
            .await
            .err()
            .unwrap_or_else(|| unreachable!("cap-sized EOF tail must fail"));
        assert_eq!(err.code(), codes::FRAME_TOO_LONG);

        // One byte under still returns as the final unterminated frame.
        let data = vec![b'z'; MAX_FRAME_BYTES - 1];
        let p = ScriptProc::output(&data);
        let mut r = FrameReader::new();
        let line = r.next(&p).await.unwrap_or(None).unwrap_or_default();
        assert_eq!(line.len(), MAX_FRAME_BYTES - 1);
    }

    /// `probeOutputCap`: `read_capped` keeps `cap + 1` bytes and drains
    /// the rest.
    #[tokio::test]
    async fn read_capped_keeps_cap_plus_one_and_drains() {
        let p = ScriptProc::output(&vec![b'z'; 7000]);
        let out = read_capped(&p, 4096).await.unwrap_or_default();
        assert_eq!(out.len(), 4097);
        // The rest was discarded, not truncated mid-stream: nothing is
        // left to read.
        let mut buf = [0u8; 16];
        assert_eq!(p.read_stdout(&mut buf).await.unwrap_or(1), 0);
    }

    /// `waitExit` — a process that exits inside the grace is never
    /// killed.
    #[tokio::test]
    async fn wait_exit_returns_a_quick_exit() {
        let p = ScriptProc::output(b"");
        p.exits(ExitStatus {
            code: 3,
            signaled: false,
        });
        let st = wait_exit(&p, Duration::from_secs(1))
            .await
            .unwrap_or_default();
        assert_eq!(st.code, 3);
        assert_eq!(p.killed(), 0);
    }

    /// `waitExit` — past the grace the helper kills the tree, then
    /// reports that exit.
    #[tokio::test]
    async fn wait_exit_kills_a_late_exit() {
        let p = ScriptProc::output(b"");
        let st = wait_exit(&p, Duration::from_millis(5))
            .await
            .unwrap_or_default();
        assert_eq!(st.code, 137);
        assert!(st.signaled);
        assert_eq!(p.killed(), 1);
    }

    /// `closeOnEOF` — a read end drops its descriptor at EOF and keeps
    /// answering EOF afterwards.
    #[tokio::test]
    async fn read_end_closes_on_eof() {
        // `pipe()` yields (write end, read end).
        let (mut tx, rx) =
            tokio::net::unix::pipe::pipe().unwrap_or_else(|e| unreachable!("pipe: {e}"));
        assert_eq!(async_write(&mut tx, b"abc").await.unwrap_or(0), 3);
        drop(tx);
        let mut end = ReadEnd::new(rx);
        let mut buf = [0u8; 8];
        assert_eq!(end.read(&mut buf).await.unwrap_or(0), 3);
        assert_eq!(&buf[..3], b"abc");
        assert_eq!(end.read(&mut buf).await.unwrap_or(1), 0);
        assert_eq!(end.read(&mut buf).await.unwrap_or(1), 0);
    }

    /// `Outcome` — one producer, every waiter gets the stored value.
    #[tokio::test]
    async fn outcome_is_single_assignment_and_reusable() {
        let o = Outcome::<u32>::new();
        let sender = o.sender();
        tokio::spawn(async move { sender.set(7) })
            .await
            .unwrap_or_else(|e| unreachable!("producer: {e}"));
        assert_eq!(o.wait().await, 7);
        assert_eq!(o.wait().await, 7);
    }

    /// `killOnce` + `killDone` — the ladder body runs once; every
    /// caller sees the same result.
    #[tokio::test]
    async fn kill_ladder_runs_once_and_shares_result() {
        let ladder = KillLadder::new();
        let calls = Arc::new(AtomicUsize::new(0));
        for _ in 0..3 {
            let calls = calls.clone();
            ladder.start(move || {
                let calls = calls.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            });
        }
        ladder
            .wait()
            .await
            .unwrap_or_else(|e| unreachable!("ladder: {e}"));
        ladder
            .wait()
            .await
            .unwrap_or_else(|e| unreachable!("ladder wait again: {e}"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
