// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `epoll_pwait` and `epoll_pwait2` syscall implementations.
//!
//! `epoll_pwait` extends `epoll_wait` with an atomic signal mask update,
//! allowing a process to safely wait for I/O events while blocking signals.
//! `epoll_pwait2` further extends with nanosecond-precision timeouts.
//!
//! POSIX Reference: Not directly in POSIX, but signal-mask semantics follow
//! POSIX.1-2024 pselect() model (susv5 functions/pselect.html).

use oncrix_lib::{Error, Result};

/// Maximum number of events returned in a single epoll_pwait call.
pub const EPOLL_PWAIT_MAX_EVENTS: u32 = 1024;

/// Signal mask size in bytes for x86_64.
pub const SIGSET_SIZE: usize = 8;

/// Epoll event structure as passed from user space.
///
/// The layout matches the kernel ABI for x86_64 with packed alignment.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct EpollEvent {
    /// Event bitmask (EPOLLIN, EPOLLOUT, EPOLLERR, etc.).
    pub events: u32,
    /// User data associated with the event (fd, pointer, or custom value).
    pub data: u64,
}

impl EpollEvent {
    /// Create a new epoll event with given flags and data.
    pub const fn new(events: u32, data: u64) -> Self {
        Self { events, data }
    }

    /// Check if the EPOLLIN flag is set.
    pub fn is_readable(&self) -> bool {
        (self.events & EpollFlags::EPOLLIN) != 0
    }

    /// Check if the EPOLLOUT flag is set.
    pub fn is_writable(&self) -> bool {
        (self.events & EpollFlags::EPOLLOUT) != 0
    }

    /// Check if an error condition is signaled.
    pub fn has_error(&self) -> bool {
        (self.events & EpollFlags::EPOLLERR) != 0
    }
}

/// Epoll event flags for use with epoll_pwait.
pub struct EpollFlags;

impl EpollFlags {
    /// Available for read.
    pub const EPOLLIN: u32 = 0x0001;
    /// Available for write.
    pub const EPOLLOUT: u32 = 0x0004;
    /// Error condition (always monitored).
    pub const EPOLLERR: u32 = 0x0008;
    /// Hang up (peer closed connection).
    pub const EPOLLHUP: u32 = 0x0010;
    /// Edge-triggered behavior.
    pub const EPOLLET: u32 = 0x8000_0000;
    /// One-shot: disable after one event.
    pub const EPOLLONESHOT: u32 = 0x4000_0000;
    /// Wake up from epoll_wait even if process is about to be suspended.
    pub const EPOLLWAKEUP: u32 = 0x2000_0000;
    /// Exclusive wakeup.
    pub const EPOLLEXCLUSIVE: u32 = 0x1000_0000;
}

/// Signal mask for epoll_pwait, matching `sigset_t` ABI.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SigSet {
    /// Bitmask of blocked signals (64 signals on x86_64).
    pub bits: u64,
}

impl SigSet {
    /// Create an empty (no signals blocked) signal set.
    pub const fn empty() -> Self {
        Self { bits: 0 }
    }

    /// Create a full signal set (all signals blocked).
    pub const fn full() -> Self {
        Self { bits: u64::MAX }
    }

    /// Check if signal `sig` (1-based) is in the set.
    pub fn contains(&self, sig: u32) -> bool {
        if sig == 0 || sig > 64 {
            return false;
        }
        (self.bits >> (sig - 1)) & 1 != 0
    }
}

impl Default for SigSet {
    fn default() -> Self {
        Self::empty()
    }
}

/// Timespec with nanosecond resolution for epoll_pwait2.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TimeSpec {
    /// Seconds component.
    pub tv_sec: i64,
    /// Nanoseconds component (0..999_999_999).
    pub tv_nsec: i64,
}

impl TimeSpec {
    /// Create a zero-duration timespec (immediate return).
    pub const fn zero() -> Self {
        Self {
            tv_sec: 0,
            tv_nsec: 0,
        }
    }

    /// Create a timespec from milliseconds.
    pub const fn from_millis(ms: u64) -> Self {
        Self {
            tv_sec: (ms / 1000) as i64,
            tv_nsec: ((ms % 1000) * 1_000_000) as i64,
        }
    }

    /// Check if this timespec is valid (nsec in range).
    pub fn is_valid(&self) -> bool {
        self.tv_nsec >= 0 && self.tv_nsec < 1_000_000_000
    }
}

/// Arguments for the `epoll_pwait` syscall.
#[derive(Debug)]
pub struct EpollPwaitArgs {
    /// Epoll file descriptor.
    pub epfd: i32,
    /// Pointer to user-space event buffer.
    pub events_ptr: usize,
    /// Maximum events to return.
    pub maxevents: i32,
    /// Timeout in milliseconds (-1 = block forever, 0 = poll).
    pub timeout_ms: i32,
    /// Pointer to signal mask (NULL means no mask change).
    pub sigmask_ptr: usize,
    /// Size of the signal mask structure.
    pub sigsetsize: usize,
}

/// Arguments for the `epoll_pwait2` syscall.
#[derive(Debug)]
pub struct EpollPwait2Args {
    /// Epoll file descriptor.
    pub epfd: i32,
    /// Pointer to user-space event buffer.
    pub events_ptr: usize,
    /// Maximum events to return.
    pub maxevents: i32,
    /// Pointer to nanosecond-precision timeout (NULL = block forever).
    pub timeout_ptr: usize,
    /// Pointer to signal mask (NULL means no mask change).
    pub sigmask_ptr: usize,
    /// Size of the signal mask structure.
    pub sigsetsize: usize,
}

/// Validate epoll_pwait / epoll_pwait2 arguments.
///
/// Checks that the epfd is non-negative, maxevents is within bounds,
/// events_ptr is non-null, and sigmask size matches the ABI.
pub fn validate_epoll_pwait_args(epfd: i32, events_ptr: usize, maxevents: i32) -> Result<()> {
    if epfd < 0 {
        return Err(Error::InvalidArgument);
    }
    if events_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    if maxevents <= 0 || (maxevents as u32) > EPOLL_PWAIT_MAX_EVENTS {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validate the sigset_size for epoll_pwait.
///
/// The kernel requires sigsetsize == sizeof(kernel_sigset_t).
pub fn validate_sigset_size(sigsetsize: usize) -> Result<()> {
    if sigsetsize != SIGSET_SIZE {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Handle the `epoll_pwait` syscall.
///
/// Atomically replaces the calling thread's signal mask with `sigmask`
/// (if non-NULL) before blocking, then restores it. This ensures no
/// signals are lost between the mask update and the wait.
///
/// Returns the number of events ready, 0 on timeout, or an error.
pub fn sys_epoll_pwait(args: &EpollPwaitArgs) -> Result<i64> {
    validate_epoll_pwait_args(args.epfd, args.events_ptr, args.maxevents)?;

    if args.sigmask_ptr != 0 {
        validate_sigset_size(args.sigsetsize)?;
    }

    // Validate timeout range.
    if args.timeout_ms < -1 {
        return Err(Error::InvalidArgument);
    }

    // Stub: real implementation would:
    // 1. copy_from_user the sigmask if sigmask_ptr != 0
    // 2. atomically swap the thread signal mask
    // 3. call into the epoll wait path
    // 4. restore the original signal mask on return
    Err(Error::NotImplemented)
}

/// Handle the `epoll_pwait2` syscall.
///
/// Same as `epoll_pwait` but accepts a `struct timespec` pointer for
/// nanosecond-precision timeout instead of a millisecond integer.
///
/// If timeout_ptr is NULL, blocks indefinitely.
///
/// Returns the number of events ready, 0 on timeout, or an error.
pub fn sys_epoll_pwait2(args: &EpollPwait2Args) -> Result<i64> {
    validate_epoll_pwait_args(args.epfd, args.events_ptr, args.maxevents)?;

    if args.sigmask_ptr != 0 {
        validate_sigset_size(args.sigsetsize)?;
    }

    // Validate timeout if provided.
    if args.timeout_ptr != 0 {
        // In a real implementation, copy_from_user and validate.
        // TimeSpec validation happens after copy.
    }

    // Stub: real implementation would:
    // 1. copy_from_user the timespec if timeout_ptr != 0
    // 2. validate TimeSpec::is_valid()
    // 3. copy_from_user the sigmask if sigmask_ptr != 0
    // 4. atomically swap signal mask
    // 5. call epoll wait path with nanosecond timeout
    // 6. restore signal mask on return
    Err(Error::NotImplemented)
}

/// Convert millisecond timeout to nanosecond TimeSpec.
///
/// Special case: -1 ms means infinite wait (represented as None).
pub fn ms_to_timespec(timeout_ms: i32) -> Option<TimeSpec> {
    if timeout_ms < 0 {
        None
    } else {
        Some(TimeSpec::from_millis(timeout_ms as u64))
    }
}
