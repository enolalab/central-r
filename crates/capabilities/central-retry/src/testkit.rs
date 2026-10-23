//! Test-only shared fakes — the unsafe-free `block_on` every async
//! test drives (`central-scheduler`'s/`central-eventjournal`'s
//! `testkit` precedent: the fake ports never yield, so a no-op waker
//! suffices and no `tokio` enters the capability crate).

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

/// Runs an immediately-ready future to completion (the fakes never
/// yield). `Waker::noop` keeps this unsafe-free.
pub(crate) fn block_on<F: Future>(future: F) -> F::Output {
    let mut context = Context::from_waker(Waker::noop());
    let mut future = pin!(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}
