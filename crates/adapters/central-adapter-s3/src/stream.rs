//! Bounded streaming primitives (port of upstream `progressReader`,
//! `runBounded`, and `permitStream`).
//!
//! Every transfer is bounded three ways: a byte ceiling that trips one byte
//! past the declared limit, an idle watchdog that fires when no byte makes
//! progress for the idle timeout, and a total transfer deadline. Transfers
//! that outlive their callers are abandoned, not stopped mid-flight: their
//! permit stays held until the transfer actually settles, so
//! `MAX_CONCURRENT_TRANSFERS` remains a true bound.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use aws_sdk_s3::primitives::ByteStream;
use central_artifact::port::{ByteStream as PortByteStream, ByteStreamFuture};
use central_foundation::failure::Failure as PortFailure;
use tokio::sync::{Notify, OwnedSemaphorePermit, mpsc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::error::{FailureClass, Reason, fail};

// ---------------------------------------------------------------------------
// Progress accounting
// ---------------------------------------------------------------------------

/// Byte-progress accounting shared between a transfer and its watchdog
/// (upstream `progressReader`'s `count`/`last` fields). Progress is recorded
/// at delivery — the transfer task consuming a chunk — matching upstream,
/// where `Read` fires only when the SDK pulls bytes.
pub(crate) struct Progress {
    count: AtomicI64,
    /// Milliseconds since `start` at the last byte of progress.
    last_ms: AtomicI64,
    /// The limit-plus-one ceiling tripped.
    over: AtomicBool,
    start: Instant,
}

impl Progress {
    pub(crate) fn new() -> Self {
        Self {
            count: AtomicI64::new(0),
            last_ms: AtomicI64::new(0),
            over: AtomicBool::new(false),
            start: Instant::now(),
        }
    }

    pub(crate) fn record(&self, bytes: i64) {
        self.count.fetch_add(bytes, Ordering::Relaxed);
        self.last_ms
            .store(self.start.elapsed().as_millis() as i64, Ordering::SeqCst);
    }

    pub(crate) fn mark_over(&self) {
        self.over.store(true, Ordering::SeqCst);
    }

    pub(crate) fn is_over(&self) -> bool {
        self.over.load(Ordering::SeqCst)
    }

    pub(crate) fn count(&self) -> i64 {
        self.count.load(Ordering::Relaxed)
    }

    /// Time since the last byte of progress (upstream `idleFor`).
    pub(crate) fn idle_for(&self) -> Duration {
        let elapsed = self.start.elapsed();
        let last = Duration::from_millis(self.last_ms.load(Ordering::SeqCst) as u64);
        elapsed.saturating_sub(last)
    }
}

// ---------------------------------------------------------------------------
// Body pump — caller reader → bounded chunk channel
// ---------------------------------------------------------------------------

/// The closed set of ways a body pump ends without clean EOF. An
/// `io::Error` is never carried out of the pump — the transfer reports the
/// closed `TransferIncomplete` reason instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PumpError {
    /// The caller's reader errored mid-body.
    Io,
    /// The body exceeded its declared ceiling; the transfer must not
    /// commit it.
    OverLimit,
}

/// Spawns the blocking pump thread that turns a caller-owned
/// `std::io::Read` into `part_size`-bounded chunks. The channel bound of 1
/// plus the in-flight chunk caps a transfer at roughly two part buffers
/// (~10 MiB at [`STAGING_PART_SIZE_BYTES`](crate::STAGING_PART_SIZE_BYTES)).
///
/// The pump reads at most `max_bytes + 1` bytes in total — the upstream
/// `io.LimitReader` sentinel — and reports [`PumpError::OverLimit`]
/// *instead of* the chunk that crossed the ceiling, so an over-limit body
/// is never uploaded.
///
/// Reader ownership mirrors upstream: the pump thread owns `reader` until
/// the transfer settles. A reader parked inside `read` cannot be
/// interrupted; the transfer task keeps the permit until the pump thread
/// exits (the `JoinHandle` returned here is joined from inside the
/// transfer's spawned task).
/// The pump's outputs: the chunk channel the transfer task consumes and
/// the thread handle the task joins on its settle path.
pub(crate) type Pump = (
    mpsc::Receiver<Result<Vec<u8>, PumpError>>,
    std::thread::JoinHandle<()>,
);

pub(crate) fn spawn_pump(
    mut reader: Box<dyn io::Read + Send>,
    max_bytes: i64,
    part_size: usize,
    progress: Arc<Progress>,
) -> Result<Pump, crate::error::Failure> {
    let (tx, rx) = mpsc::channel::<Result<Vec<u8>, PumpError>>(1);
    let spawned = std::thread::Builder::new()
        .name("central-s3-body-pump".to_owned())
        .spawn(move || {
            // The ceiling sentinel: the pump reads at most max_bytes+1
            // bytes, so read_total > max_bytes can only mean the cap was
            // consumed — the body is over limit.
            let cap = max_bytes.saturating_add(1);
            let mut read_total: i64 = 0;
            loop {
                let want = i64::min(part_size as i64, cap - read_total).max(0) as usize;
                if want == 0 {
                    progress.mark_over();
                    let _ = tx.blocking_send(Err(PumpError::OverLimit));
                    return;
                }
                let mut buf = vec![0u8; want];
                let mut filled = 0usize;
                let mut eof = false;
                while filled < want {
                    match reader.read(&mut buf[filled..]) {
                        Ok(0) => {
                            eof = true;
                            break;
                        }
                        Ok(n) => filled += n,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(_) => {
                            let _ = tx.blocking_send(Err(PumpError::Io));
                            return;
                        }
                    }
                }
                read_total += filled as i64;
                if read_total > max_bytes {
                    progress.mark_over();
                    let _ = tx.blocking_send(Err(PumpError::OverLimit));
                    return;
                }
                if filled > 0 {
                    buf.truncate(filled);
                    if tx.blocking_send(Ok(buf)).is_err() {
                        return; // consumer abandoned the transfer
                    }
                }
                if eof {
                    return;
                }
            }
        });
    match spawned {
        Ok(handle) => Ok((rx, handle)),
        Err(_) => Err(fail(
            "upload",
            FailureClass::Unavailable,
            Reason::UpstreamRejected,
        )),
    }
}

// ---------------------------------------------------------------------------
// PermitStream — the read-direction bounded stream
// ---------------------------------------------------------------------------

const STREAM_FAILURE_NONE: u8 = 0;
const STREAM_FAILURE_IDLE: u8 = 1;
const STREAM_FAILURE_DEADLINE: u8 = 2;
const STREAM_FAILURE_CANCELED: u8 = 3;

/// State shared between a [`PermitStream`] and its watchdog task.
struct Shared {
    /// The terminal failure the watchdog recorded (`STREAM_FAILURE_*`).
    failure: AtomicU8,
    /// Whether terminal cleanup (body drop + permit release) already ran.
    settled: AtomicBool,
    /// Byte progress signal — resets the watchdog's idle timer.
    progress: Notify,
    /// Caller `close` — exits the watchdog without a failure.
    stop: Notify,
    /// Wakes an in-flight `body.next()` poll on termination.
    cancel: CancellationToken,
    /// The response body — taken and dropped by whoever settles first.
    body: tokio::sync::Mutex<Option<ByteStream>>,
    /// The held transfer permit — released exactly once.
    permit: Mutex<Option<OwnedSemaphorePermit>>,
}

fn lock_poisoned<'a, T>(mutex: &'a Mutex<T>) -> MutexGuard<'a, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

impl Shared {
    /// Terminal cleanup, run exactly once — cancel in-flight reads, drop
    /// the body (closing the connection), then release the permit. Order
    /// matters: the body is dropped before the permit is released, so the
    /// connection is closed before a new transfer can start.
    async fn settle(&self) {
        if self.settled.swap(true, Ordering::SeqCst) {
            return;
        }
        self.cancel.cancel();
        drop(self.body.lock().await.take());
        drop(lock_poisoned(&self.permit).take());
    }

    /// The watchdog's terminal path (upstream `terminate`): record the
    /// failure (only while none is recorded — a caller `close` clears the
    /// flag deliberately) and settle.
    async fn terminate(&self, failure: u8) {
        let _ = self.failure.compare_exchange(
            STREAM_FAILURE_NONE,
            failure,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        self.settle().await;
    }

    fn recorded_failure(&self) -> u8 {
        self.failure.load(Ordering::SeqCst)
    }
}

/// The watchdog task (upstream `permitStream.watch`): exits on `stop`,
/// resets its idle timer on every byte of progress, and terminates the
/// stream on the idle timeout or the total deadline — whichever first.
async fn watch(shared: Arc<Shared>, idle_timeout: Duration, deadline: Instant) {
    let deadline = tokio::time::Instant::from_std(deadline);
    loop {
        tokio::select! {
            _ = shared.stop.notified() => return,
            _ = shared.progress.notified() => continue,
            _ = tokio::time::sleep(idle_timeout) => {
                shared.terminate(STREAM_FAILURE_IDLE).await;
                return;
            }
            _ = tokio::time::sleep_until(deadline) => {
                shared.terminate(STREAM_FAILURE_DEADLINE).await;
                return;
            }
        }
    }
}

/// A read-side stream holding one transfer permit until `close` (or
/// watchdog termination) — upstream `permitStream`. Implements the
/// capability-owned [`PortByteStream`]: `read_chunk` returns `Ok(0)` at
/// end of stream (upstream `io.EOF`).
///
/// A caller that abandons the stream without closing still cannot starve
/// the process of permits: the watchdog fires at the idle deadline and
/// settles the transfer (upstream
/// `TestReadIdleWatchdogClosesStalledBodyAndReturnsPermit`).
pub struct PermitStream {
    op: &'static str,
    shared: Arc<Shared>,
    watchdog: JoinHandle<()>,
    /// Already-received bytes not yet handed to the caller.
    pending: Vec<u8>,
    pending_off: usize,
    eof: bool,
    closed: bool,
}

impl PermitStream {
    pub(crate) fn new(
        op: &'static str,
        body: ByteStream,
        permit: OwnedSemaphorePermit,
        idle_timeout: Duration,
        deadline: Instant,
    ) -> Self {
        let shared = Arc::new(Shared {
            failure: AtomicU8::new(STREAM_FAILURE_NONE),
            settled: AtomicBool::new(false),
            progress: Notify::new(),
            stop: Notify::new(),
            cancel: CancellationToken::new(),
            body: tokio::sync::Mutex::new(Some(body)),
            permit: Mutex::new(Some(permit)),
        });
        let watchdog = tokio::spawn(watch(Arc::clone(&shared), idle_timeout, deadline));
        Self {
            op,
            shared,
            watchdog,
            pending: Vec::new(),
            pending_off: 0,
            eof: false,
            closed: false,
        }
    }

    /// Maps the recorded terminal state (or a bare transport error) to the
    /// closed failure vocabulary — upstream's switch on `p.failure`.
    fn stream_failure(&self, transport_error: bool) -> PortFailure {
        let reason = match self.shared.recorded_failure() {
            STREAM_FAILURE_IDLE => Reason::IdleTimeout,
            STREAM_FAILURE_DEADLINE => Reason::TotalDeadline,
            STREAM_FAILURE_CANCELED => Reason::Canceled,
            // A transport error with no recorded watchdog state (or a read
            // raced with an in-flight termination) is ambiguous by
            // construction; a read after `close` reports Canceled.
            _ if transport_error => Reason::TransferIncomplete,
            _ => Reason::Canceled,
        };
        fail(self.op, FailureClass::Ambiguous, reason).into()
    }
}

impl PortByteStream for PermitStream {
    fn read_chunk<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> ByteStreamFuture<'a, Result<usize, PortFailure>> {
        Box::pin(async move {
            if self.eof || buf.is_empty() {
                return Ok(0);
            }
            loop {
                if self.pending_off < self.pending.len() {
                    let n = usize::min(buf.len(), self.pending.len() - self.pending_off);
                    buf[..n].copy_from_slice(&self.pending[self.pending_off..self.pending_off + n]);
                    self.pending_off += n;
                    if self.pending_off == self.pending.len() {
                        self.pending.clear();
                        self.pending_off = 0;
                    }
                    return Ok(n);
                }

                let mut guard = self.shared.body.lock().await;
                let Some(body) = guard.as_mut() else {
                    drop(guard);
                    return Err(self.stream_failure(false));
                };
                let next = tokio::select! {
                    biased;
                    _ = self.shared.cancel.cancelled() => None,
                    chunk = body.next() => Some(chunk),
                };
                drop(guard);

                match next {
                    None => return Err(self.stream_failure(false)),
                    Some(None) => {
                        self.eof = true;
                        return Ok(0);
                    }
                    Some(Some(Err(_))) => return Err(self.stream_failure(true)),
                    Some(Some(Ok(chunk))) => {
                        if chunk.is_empty() {
                            continue;
                        }
                        self.shared.progress.notify_one();
                        self.pending = chunk.to_vec();
                    }
                }
            }
        })
    }

    fn close<'a>(&'a mut self) -> ByteStreamFuture<'a, Result<(), PortFailure>> {
        Box::pin(async move {
            if self.closed {
                return Ok(());
            }
            self.closed = true;
            // Order mirrors upstream Close: stop the watchdog, clear the
            // recorded failure so a racing terminate cannot misreport a
            // close-induced read error, then settle (drop body, release
            // permit) exactly once.
            self.shared.stop.notify_one();
            self.shared
                .failure
                .store(STREAM_FAILURE_NONE, Ordering::SeqCst);
            self.shared.settle().await;
            self.watchdog.abort();
            Ok(())
        })
    }
}

impl Drop for PermitStream {
    fn drop(&mut self) {
        if self.closed {
            return;
        }
        // An unclosed stream still returns its permit: wake the watchdog so
        // it exits, cancel any in-flight read, and settle immediately rather
        // than waiting for the idle watchdog.
        self.shared.stop.notify_one();
        self.shared.cancel.cancel();
        self.watchdog.abort();
        if self.shared.settled.swap(true, Ordering::SeqCst) {
            return;
        }
        if let Ok(mut body) = self.shared.body.try_lock() {
            drop(body.take());
        }
        drop(lock_poisoned(&self.shared.permit).take());
    }
}
