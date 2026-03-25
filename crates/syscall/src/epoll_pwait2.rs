// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `epoll_pwait2(2)` syscall handler — epoll wait with nanosecond timeout.
//!
//! `epoll_pwait2` extends `epoll_pwait` by accepting a `struct timespec`
//! timeout (nanosecond precision) instead of a millisecond integer.  It
//! atomically installs a signal mask for the duration of the wait, then
//! restores the original mask before returning.
//!
//! This module provides:
//! - [`Timespec64`] — 64-bit seconds + nanoseconds timeout representation.
//! - [`SigsetSize`] — validated signal set size.
//! - [`EpollPwait2Args`] — fully validated argument bundle.
//! - [`do_epoll_pwait2`] — top-level syscall dispatcher.
//!
//! # Relationship to epoll_calls
//!
//! The existing `epoll_calls` module covers `epoll_create`, `epoll_ctl`,
//! `epoll_wait`, and `epoll_pwait`.  This module is a focused extension
//! for the `epoll_pwait2` variant added in Linux 5.11.
//!
//! # Signal mask atomicity
//!
//! Per the Linux `epoll_pwait2(2)` man page:
//!
//! > The call is equivalent to atomically executing the following calls:
//! >
//! >     sigprocmask(SIG_SETMASK, &sigmask, &origmask);
//! >     ready = epoll_pwait(epfd, events, maxevents, timeout, NULL);
//! >     sigprocmask(SIG_SETMASK, &origmask, NULL);
//!
//! # Reference
//!
//! - Linux: `fs/eventpoll.c`, `include/uapi/linux/eventpoll.h`
//! - `man 2 epoll_pwait2` (Linux 5.11+)

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants re-exported for callers that only use this module
// ---------------------------------------------------------------------------

/// Maximum number of events that can be returned in one call.
pub const EPOLL_MAX_EVENTS: i32 = i32::MAX;

/// Signal set size accepted by this syscall (8 bytes = 64 signals on x86_64).
pub const EPOLL_SIGSET_SIZE: usize = 8;

// ---------------------------------------------------------------------------
// Timespec64 — nanosecond-precision timeout
// ---------------------------------------------------------------------------

/// A `struct timespec`-equivalent with 64-bit seconds and nanoseconds.
///
/// Used as the `timeout` argument for `epoll_pwait2`.  A `None` timeout
/// means block indefinitely.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Timespec64 {
    /// Seconds component.
    pub tv_sec: i64,
    /// Nanoseconds component (must be in `0..1_000_000_000`).
    pub tv_nsec: i64,
}

impl Timespec64 {
    /// Construct a new `Timespec64`.
    ///
    /// Returns `Err(InvalidArgument)` if `tv_nsec` is out of range.
    pub fn new(tv_sec: i64, tv_nsec: i64) -> Result<Self> {
        if !(0..1_000_000_000).contains(&tv_nsec) {
            return Err(Error::InvalidArgument);
        }
        Ok(Self { tv_sec, tv_nsec })
    }

    /// Convert to milliseconds, saturating at `i32::MAX`.
    ///
    /// Used when falling back to `epoll_wait`-style millisecond logic.
    pub fn to_millis_saturating(&self) -> i32 {
        if self.tv_sec < 0 {
            // Negative timeout means "return immediately" (poll).
            return 0;
        }
        // tv_sec * 1000 + tv_nsec / 1_000_000
        let ms_from_sec = self.tv_sec.saturating_mul(1000);
        let ms_from_ns = self.tv_nsec / 1_000_000;
        ms_from_sec
            .saturating_add(ms_from_ns)
            .try_into()
            .unwrap_or(i32::MAX)
    }

    /// Returns `true` if this represents an immediate (non-blocking) poll.
    pub fn is_zero(&self) -> bool {
        self.tv_sec == 0 && self.tv_nsec == 0
    }
}

// ---------------------------------------------------------------------------
// SigsetSize — validated size of the signal mask argument
// ---------------------------------------------------------------------------

/// Validated size of the signal mask passed to `epoll_pwait2`.
///
/// The kernel checks that `sigsetsize` equals `sizeof(kernel_sigset_t)`.
/// On x86_64 this is 8 bytes (64 signals).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigsetSize(usize);

impl SigsetSize {
    /// Validate and wrap a raw `sigsetsize` from user space.
    ///
    /// Returns `Err(InvalidArgument)` for sizes other than
    /// [`EPOLL_SIGSET_SIZE`].
    pub fn from_raw(size: usize) -> Result<Self> {
        if size != EPOLL_SIGSET_SIZE {
            return Err(Error::InvalidArgument);
        }
        Ok(Self(size))
    }

    /// The validated size in bytes.
    pub fn as_usize(self) -> usize {
        self.0
    }
}

// ---------------------------------------------------------------------------
// EpollEvent — mirrors struct epoll_event
// ---------------------------------------------------------------------------

/// User-visible epoll event, matching `struct epoll_event` from Linux.
///
/// This is a local definition for callers that only import this module.
/// It is layout-compatible with the definition in `epoll_calls`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct EpollPwait2Event {
    /// Bitmask of ready event types (`EPOLLIN`, `EPOLLOUT`, …).
    pub events: u32,
    /// Caller-supplied opaque data echoed back on readiness.
    pub data: u64,
}

// ---------------------------------------------------------------------------
// EpollPwait2Args — validated argument bundle
// ---------------------------------------------------------------------------

/// Fully validated arguments for a single `epoll_pwait2` invocation.
///
/// Construct with [`EpollPwait2Args::validate`]; the fields are guaranteed
/// to be in range once construction succeeds.
#[derive(Debug)]
pub struct EpollPwait2Args {
    /// The epoll file descriptor.
    pub epfd: i32,
    /// Maximum number of events to dequeue.
    pub max_events: i32,
    /// Optional nanosecond-precision timeout (`None` = block forever).
    pub timeout: Option<Timespec64>,
    /// Optional signal mask to install atomically during the wait.
    pub sigmask: Option<u64>,
    /// Validated signal set size.
    pub sigset_size: Option<SigsetSize>,
}

impl EpollPwait2Args {
    /// Validate raw syscall arguments and return a checked bundle.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `epfd < 0`, `max_events <= 0`, the timeout
    ///   nanoseconds are out of range, or `sigsetsize` is wrong.
    pub fn validate(
        epfd: i32,
        max_events: i32,
        timeout: Option<(i64, i64)>,
        sigmask: Option<u64>,
        sigsetsize: Option<usize>,
    ) -> Result<Self> {
        if epfd < 0 {
            return Err(Error::InvalidArgument);
        }
        if max_events <= 0 || max_events > EPOLL_MAX_EVENTS {
            return Err(Error::InvalidArgument);
        }
        let timeout = match timeout {
            Some((sec, nsec)) => Some(Timespec64::new(sec, nsec)?),
            None => None,
        };
        let sigset_size = match sigsetsize {
            Some(sz) => Some(SigsetSize::from_raw(sz)?),
            None => None,
        };
        // A sigmask must be accompanied by a valid sigsetsize.
        if sigmask.is_some() && sigset_size.is_none() {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            epfd,
            max_events,
            timeout,
            sigmask,
            sigset_size,
        })
    }
}

// ---------------------------------------------------------------------------
// Timeout conversion helpers
// ---------------------------------------------------------------------------

/// Convert an optional [`Timespec64`] to a millisecond value for
/// downstream `epoll_wait`-style logic.
///
/// Returns `-1` (block forever) when `timeout` is `None`.
pub fn timeout_to_ms(timeout: Option<&Timespec64>) -> i32 {
    match timeout {
        None => -1,
        Some(ts) => ts.to_millis_saturating(),
    }
}

// ---------------------------------------------------------------------------
// Syscall entry point
// ---------------------------------------------------------------------------

/// `epoll_pwait2` — wait for events with nanosecond timeout and signal mask.
///
/// This is the primary syscall handler.  It:
/// 1. Validates all arguments via [`EpollPwait2Args::validate`].
/// 2. Records the requested signal mask (stub — full signal masking
///    requires kernel signal subsystem integration).
/// 3. Delegates to the epoll instance's wait implementation.
/// 4. Returns the count of ready events written into `events`.
///
/// # Arguments
///
/// * `epfd`       — epoll file descriptor.
/// * `events`     — output slice for ready events (length ≥ `max_events`).
/// * `max_events` — upper bound on events returned per call (must be > 0).
/// * `timeout`    — optional `(tv_sec, tv_nsec)` deadline; `None` blocks.
/// * `sigmask`    — optional signal mask to atomically install for the wait.
/// * `sigsetsize` — must equal `EPOLL_SIGSET_SIZE` when `sigmask` is `Some`.
///
/// # Errors
///
/// Returns `Err(InvalidArgument)` for invalid arguments.
/// Returns `Err(NotImplemented)` because the epoll instance backing store
/// is a stub — wire up to `EpollRegistry` when the kernel I/O subsystem is
/// ready.
pub fn do_epoll_pwait2(
    epfd: i32,
    events: &mut [EpollPwait2Event],
    max_events: i32,
    timeout: Option<(i64, i64)>,
    sigmask: Option<u64>,
    sigsetsize: Option<usize>,
) -> Result<i32> {
    let args = EpollPwait2Args::validate(epfd, max_events, timeout, sigmask, sigsetsize)?;

    // Clamp to the actual slice length to avoid out-of-bounds writes.
    let limit = (args.max_events as usize).min(events.len());
    if limit == 0 {
        return Err(Error::InvalidArgument);
    }

    // Stub: atomically install sigmask here (requires signal subsystem).
    let _ = args.sigmask;

    // Convert timeout for downstream use.
    let _timeout_ms = timeout_to_ms(args.timeout.as_ref());

    // Stub: real implementation calls EpollRegistry::epoll_wait with
    // the nanosecond timeout and writes ready events into events[..limit].
    Err(Error::NotImplemented)
}

/// `epoll_pwait2_poll` — non-blocking poll variant (timeout = 0).
///
/// Equivalent to `do_epoll_pwait2` with `timeout = Some((0, 0))`.
pub fn do_epoll_pwait2_poll(
    epfd: i32,
    events: &mut [EpollPwait2Event],
    max_events: i32,
    sigmask: Option<u64>,
    sigsetsize: Option<usize>,
) -> Result<i32> {
    do_epoll_pwait2(epfd, events, max_events, Some((0, 0)), sigmask, sigsetsize)
}
