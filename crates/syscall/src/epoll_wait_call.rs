// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `epoll_wait(2)` / `epoll_pwait(2)` syscall handlers.
//!
//! `epoll_wait` blocks the calling thread until one or more file descriptors in
//! the interest list become ready, a timeout expires, or a signal is delivered.
//! `epoll_pwait` is the signal-mask variant — it atomically sets a signal mask
//! while waiting, matching the POSIX pattern established by `pselect`/`ppoll`.
//!
//! # Linux man page
//!
//! `epoll_wait(2)`, `epoll_pwait(2)`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Event flags (re-exported for callers)
// ---------------------------------------------------------------------------

/// Data available to read.
pub const EPOLLIN: u32 = 0x0000_0001;
/// Priority data available.
pub const EPOLLPRI: u32 = 0x0000_0002;
/// Write space available.
pub const EPOLLOUT: u32 = 0x0000_0004;
/// Peer closed connection or half-shutdown write.
pub const EPOLLRDHUP: u32 = 0x0000_2000;
/// Error condition.
pub const EPOLLERR: u32 = 0x0000_0008;
/// Hang-up.
pub const EPOLLHUP: u32 = 0x0000_0010;

// ---------------------------------------------------------------------------
// Timeout sentinel
// ---------------------------------------------------------------------------

/// Infinite wait — no timeout.
pub const EPOLL_WAIT_INDEFINITE: i32 = -1;
/// Return immediately; do not block.
pub const EPOLL_WAIT_NOWAIT: i32 = 0;

// ---------------------------------------------------------------------------
// Ready event
// ---------------------------------------------------------------------------

/// A single ready event returned by `epoll_wait`.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EpollEvent {
    /// Which events fired (bitmask of `EPOLL*` flags).
    pub events: u32,
    /// User data associated with the fd in `epoll_ctl`.
    pub data: u64,
}

impl EpollEvent {
    /// Create a ready event.
    pub fn new(events: u32, data: u64) -> Self {
        Self { events, data }
    }

    /// Interpret `data` as a file descriptor.
    pub fn data_fd(&self) -> i32 {
        self.data as i32
    }

    /// Returns `true` if the read-ready bit is set.
    pub fn is_readable(&self) -> bool {
        self.events & EPOLLIN != 0
    }

    /// Returns `true` if the write-ready bit is set.
    pub fn is_writable(&self) -> bool {
        self.events & EPOLLOUT != 0
    }

    /// Returns `true` if an error or hang-up bit is set.
    pub fn has_error(&self) -> bool {
        self.events & (EPOLLERR | EPOLLHUP) != 0
    }
}

// ---------------------------------------------------------------------------
// Epoll wait request
// ---------------------------------------------------------------------------

/// Parsed `epoll_wait` / `epoll_pwait` request.
#[derive(Debug, Clone, Copy)]
pub struct EpollWaitRequest {
    /// epoll instance file descriptor.
    pub epfd: i32,
    /// Maximum number of events to return.
    pub maxevents: i32,
    /// Timeout in milliseconds; -1 = infinite, 0 = nowait.
    pub timeout_ms: i32,
    /// Optional signal mask for `epoll_pwait`.
    pub sigmask: Option<u64>,
}

impl EpollWaitRequest {
    /// Create a plain `epoll_wait` request.
    pub fn new(epfd: i32, maxevents: i32, timeout_ms: i32) -> Self {
        Self {
            epfd,
            maxevents,
            timeout_ms,
            sigmask: None,
        }
    }

    /// Create an `epoll_pwait` request with a signal mask.
    pub fn with_sigmask(epfd: i32, maxevents: i32, timeout_ms: i32, sigmask: u64) -> Self {
        Self {
            epfd,
            maxevents,
            timeout_ms,
            sigmask: Some(sigmask),
        }
    }

    /// Returns `true` if the call will block indefinitely.
    pub fn is_blocking(&self) -> bool {
        self.timeout_ms == EPOLL_WAIT_INDEFINITE
    }

    /// Returns `true` if the call is a non-blocking poll.
    pub fn is_nowait(&self) -> bool {
        self.timeout_ms == EPOLL_WAIT_NOWAIT
    }
}

// ---------------------------------------------------------------------------
// Epoll wait result
// ---------------------------------------------------------------------------

/// Outcome of an `epoll_wait` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpollWaitResult {
    /// `count` events are ready.
    Ready(usize),
    /// The timeout expired before any event became ready.
    TimedOut,
    /// A signal was delivered while waiting (`epoll_pwait` only).
    Interrupted,
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate `epoll_wait` arguments.
///
/// # Errors
///
/// | `Error`           | Condition                              |
/// |-------------------|----------------------------------------|
/// | `InvalidArgument` | `epfd` < 0 or `maxevents` <= 0         |
pub fn validate_epoll_wait_args(epfd: i32, maxevents: i32) -> Result<()> {
    if epfd < 0 {
        return Err(Error::InvalidArgument);
    }
    if maxevents <= 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Core handlers
// ---------------------------------------------------------------------------

/// Handler for `epoll_wait(2)`.
///
/// Validates arguments and builds an `EpollWaitRequest`.  The scheduler /
/// event loop then blocks the thread until events arrive, the timeout fires,
/// or a signal is received.
///
/// # Arguments
///
/// - `epfd`      — epoll instance fd
/// - `maxevents` — size of the caller's event array (must be > 0)
/// - `timeout_ms`— milliseconds to wait; -1 = infinite, 0 = return immediately
///
/// # Errors
///
/// | `Error`           | Condition                          |
/// |-------------------|------------------------------------|
/// | `InvalidArgument` | `epfd` < 0 or `maxevents` <= 0     |
/// | `Interrupted`     | Signal arrived during wait          |
pub fn do_epoll_wait(epfd: i32, maxevents: i32, timeout_ms: i32) -> Result<EpollWaitRequest> {
    validate_epoll_wait_args(epfd, maxevents)?;
    Ok(EpollWaitRequest::new(epfd, maxevents, timeout_ms))
}

/// Handler for `epoll_pwait(2)`.
///
/// Identical to `epoll_wait` but atomically replaces the calling thread's
/// signal mask with `sigmask` for the duration of the wait.
///
/// # Arguments
///
/// - `epfd`      — epoll instance fd
/// - `maxevents` — size of the caller's event array
/// - `timeout_ms`— milliseconds to wait
/// - `sigmask`   — signal mask to apply during wait
///
/// # Errors
///
/// Same as [`do_epoll_wait`].
pub fn do_epoll_pwait(
    epfd: i32,
    maxevents: i32,
    timeout_ms: i32,
    sigmask: u64,
) -> Result<EpollWaitRequest> {
    validate_epoll_wait_args(epfd, maxevents)?;
    Ok(EpollWaitRequest::with_sigmask(
        epfd, maxevents, timeout_ms, sigmask,
    ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wait_ok() {
        let req = do_epoll_wait(3, 64, -1).unwrap();
        assert_eq!(req.epfd, 3);
        assert_eq!(req.maxevents, 64);
        assert!(req.is_blocking());
        assert!(req.sigmask.is_none());
    }

    #[test]
    fn wait_nowait() {
        let req = do_epoll_wait(3, 1, 0).unwrap();
        assert!(req.is_nowait());
    }

    #[test]
    fn pwait_has_sigmask() {
        let req = do_epoll_pwait(3, 10, 500, 0xFFFF).unwrap();
        assert_eq!(req.sigmask, Some(0xFFFF));
    }

    #[test]
    fn negative_epfd_rejected() {
        assert_eq!(do_epoll_wait(-1, 10, 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn zero_maxevents_rejected() {
        assert_eq!(do_epoll_wait(3, 0, 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn negative_maxevents_rejected() {
        assert_eq!(do_epoll_wait(3, -1, 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn epoll_event_readable() {
        let ev = EpollEvent::new(EPOLLIN | EPOLLHUP, 5);
        assert!(ev.is_readable());
        assert!(ev.has_error());
        assert!(!ev.is_writable());
    }

    #[test]
    fn epoll_event_data_fd() {
        let ev = EpollEvent::new(EPOLLOUT, 42);
        assert_eq!(ev.data_fd(), 42);
    }
}
