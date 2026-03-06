// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `io_pgetevents` syscall implementation.
//!
//! `io_pgetevents` is equivalent to `io_getevents` with an additional
//! atomic signal mask update, matching the pselect/ppoll pattern.
//! It waits for AIO completion events while atomically blocking signals.
//!
//! Linux-specific. Introduced in Linux 4.18.

use oncrix_lib::{Error, Result};

/// Maximum AIO events returned per call.
pub const IO_PGETEVENTS_MAX: u32 = 4096;

/// Signal mask size for x86_64 (one u64 bitmask).
pub const SIGSET_SIZE: usize = 8;

/// AIO context identifier type.
pub type AioContext = u64;

/// AIO completion event as returned to user space.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IoEvent {
    /// User data from the original iocb.
    pub data: u64,
    /// Pointer to the iocb that completed.
    pub obj: u64,
    /// Result code (bytes transferred, or negative errno).
    pub res: i64,
    /// Second result code (implementation-defined).
    pub res2: i64,
}

impl IoEvent {
    /// Create an empty IoEvent.
    pub const fn new() -> Self {
        Self {
            data: 0,
            obj: 0,
            res: 0,
            res2: 0,
        }
    }

    /// Check if the event represents a successful completion.
    pub fn is_success(&self) -> bool {
        self.res >= 0
    }

    /// Return the error code for failed events (positive errno value).
    pub fn error_code(&self) -> Option<i64> {
        if self.res < 0 { Some(-self.res) } else { None }
    }
}

/// Timespec for the io_pgetevents timeout.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TimeSpec {
    /// Seconds.
    pub tv_sec: i64,
    /// Nanoseconds (0..999_999_999).
    pub tv_nsec: i64,
}

impl TimeSpec {
    /// Create a zero timeout (poll mode).
    pub const fn zero() -> Self {
        Self {
            tv_sec: 0,
            tv_nsec: 0,
        }
    }

    /// Check that nanoseconds are within valid range.
    pub fn is_valid(&self) -> bool {
        self.tv_nsec >= 0 && self.tv_nsec < 1_000_000_000
    }
}

/// Signal mask for io_pgetevents, matching `sigset_t` ABI.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SigSet {
    /// 64-bit bitmask of blocked signals.
    pub bits: u64,
}

impl SigSet {
    /// Create an empty signal set (no signals blocked).
    pub const fn empty() -> Self {
        Self { bits: 0 }
    }
}

/// Arguments for the `io_pgetevents` syscall.
#[derive(Debug)]
pub struct IoPgeteventsArgs {
    /// AIO context to wait on.
    pub ctx_id: AioContext,
    /// Minimum number of events to wait for.
    pub min_nr: u32,
    /// Maximum number of events to return.
    pub nr: u32,
    /// Pointer to user-space IoEvent array.
    pub events_ptr: usize,
    /// Pointer to timeout timespec (NULL = block indefinitely).
    pub timeout_ptr: usize,
    /// Pointer to signal mask structure (NULL = no mask change).
    pub sigmask_ptr: usize,
    /// Size of the signal mask structure.
    pub sigsetsize: usize,
}

/// Validate `io_pgetevents` arguments.
///
/// Checks that ctx_id is non-zero, nr is within bounds, events_ptr is
/// non-null, and sigsetsize matches the ABI if sigmask_ptr is given.
pub fn validate_io_pgetevents_args(args: &IoPgeteventsArgs) -> Result<()> {
    if args.ctx_id == 0 {
        return Err(Error::InvalidArgument);
    }
    if args.events_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    if args.nr == 0 || args.nr > IO_PGETEVENTS_MAX {
        return Err(Error::InvalidArgument);
    }
    if args.min_nr > args.nr {
        return Err(Error::InvalidArgument);
    }
    if args.sigmask_ptr != 0 && args.sigsetsize != SIGSET_SIZE {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Handle the `io_pgetevents` syscall.
///
/// Waits for at least `min_nr` AIO completions on `ctx_id` and writes
/// up to `nr` events to `events_ptr`. If `sigmask_ptr` is non-null,
/// atomically replaces the thread's signal mask before waiting and
/// restores it on return (like pselect/ppoll).
///
/// Returns the number of events collected, or an error.
pub fn sys_io_pgetevents(args: &IoPgeteventsArgs) -> Result<i64> {
    validate_io_pgetevents_args(args)?;
    // Stub: real implementation would:
    // 1. Resolve ctx_id to an AIO ring context.
    // 2. If sigmask_ptr != 0: copy_from_user the sigmask and swap.
    // 3. If timeout_ptr != 0: copy_from_user the timeout.
    // 4. Block until min_nr events are ready or timeout elapses.
    // 5. copy_to_user the IoEvent array.
    // 6. Restore signal mask.
    // 7. Return event count.
    Err(Error::NotImplemented)
}

/// Validate a timeout timespec copied from user space.
pub fn validate_timeout(ts: &TimeSpec) -> Result<()> {
    if !ts.is_valid() {
        return Err(Error::InvalidArgument);
    }
    if ts.tv_sec < 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Convert a minimum event count and total count to a wait policy string.
pub fn wait_policy_str(min_nr: u32, nr: u32) -> &'static str {
    if min_nr == 0 {
        "non-blocking"
    } else if min_nr == nr {
        "wait-all"
    } else {
        "wait-partial"
    }
}
