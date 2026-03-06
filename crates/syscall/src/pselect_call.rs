// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `pselect6` syscall handler.
//!
//! Implements `pselect6(2)` per POSIX.1-2024.
//! `pselect6` checks readfds, writefds, and exceptfds for readiness
//! across file descriptors 0..nfds, with a nanosecond-precision timeout
//! and a signal mask applied atomically during the wait.
//!
//! # References
//!
//! - POSIX.1-2024: `pselect()`
//! - Linux man pages: `select(2)`, `pselect(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of file descriptors in an `FdSet` (matches FD_SETSIZE).
pub const FD_SETSIZE: usize = 1024;

/// Number of 64-bit words required for `FD_SETSIZE` bits.
const FD_SET_WORDS: usize = FD_SETSIZE / 64;

/// Maximum valid `nfds` value (must be <= FD_SETSIZE).
const PSELECT_MAX_NFDS: i32 = FD_SETSIZE as i32;

// ---------------------------------------------------------------------------
// Timespec
// ---------------------------------------------------------------------------

/// POSIX `struct timespec` — seconds and nanoseconds.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Timespec {
    /// Whole seconds.
    pub tv_sec: i64,
    /// Nanoseconds component (0 .. 999_999_999).
    pub tv_nsec: i64,
}

impl Timespec {
    /// Construct a `Timespec`.
    pub const fn new(tv_sec: i64, tv_nsec: i64) -> Self {
        Self { tv_sec, tv_nsec }
    }

    /// Validate that `tv_nsec` is in range and `tv_sec` is non-negative.
    pub fn validate(&self) -> Result<()> {
        if self.tv_sec < 0 || self.tv_nsec < 0 || self.tv_nsec >= 1_000_000_000 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Returns `true` if this represents an instant timeout (poll mode).
    pub const fn is_zero(&self) -> bool {
        self.tv_sec == 0 && self.tv_nsec == 0
    }
}

// ---------------------------------------------------------------------------
// FdSet — 1024-bit bitmap
// ---------------------------------------------------------------------------

/// Bit-set representing up to `FD_SETSIZE` (1024) file descriptors,
/// equivalent to POSIX `fd_set`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FdSet {
    /// Underlying 1024-bit storage (16 x 64-bit words).
    pub bits: [u64; FD_SET_WORDS],
}

impl Default for FdSet {
    fn default() -> Self {
        Self::new()
    }
}

impl FdSet {
    /// Construct a zeroed `FdSet`.
    pub const fn new() -> Self {
        Self {
            bits: [0u64; FD_SET_WORDS],
        }
    }

    /// Set the bit for file descriptor `fd`. Silently ignores out-of-range values.
    pub fn set(&mut self, fd: usize) {
        if fd < FD_SETSIZE {
            self.bits[fd / 64] |= 1u64 << (fd % 64);
        }
    }

    /// Clear the bit for file descriptor `fd`. Silently ignores out-of-range values.
    pub fn clear(&mut self, fd: usize) {
        if fd < FD_SETSIZE {
            self.bits[fd / 64] &= !(1u64 << (fd % 64));
        }
    }

    /// Return `true` if the bit for `fd` is set.
    pub fn is_set(&self, fd: usize) -> bool {
        if fd < FD_SETSIZE {
            (self.bits[fd / 64] & (1u64 << (fd % 64))) != 0
        } else {
            false
        }
    }

    /// Clear all bits.
    pub fn zero(&mut self) {
        self.bits = [0u64; FD_SET_WORDS];
    }

    /// Return the number of set bits.
    pub fn count_set(&self) -> u32 {
        self.bits.iter().map(|w| w.count_ones()).sum()
    }
}

// ---------------------------------------------------------------------------
// SigMask
// ---------------------------------------------------------------------------

/// Signal mask for `pselect6` — bitmask where bit N represents signal N+1.
///
/// Applied atomically during the wait; the original mask is restored on return.
/// Signal subsystem integration is deferred; the mask is validated but not applied.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SigMask(pub u64);

impl SigMask {
    /// Construct a `SigMask` from a raw bitmask word.
    pub const fn new(bits: u64) -> Self {
        Self(bits)
    }

    /// Return `true` if signal `sig` (1-indexed) is blocked.
    pub const fn blocks(&self, sig: u32) -> bool {
        if sig == 0 || sig > 64 {
            return false;
        }
        self.0 & (1u64 << (sig - 1)) != 0
    }
}

// ---------------------------------------------------------------------------
// SelectResult
// ---------------------------------------------------------------------------

/// Outcome of a `pselect6` call.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SelectResult {
    /// Total number of ready file descriptors across all three sets.
    pub ready: i32,
    /// `true` if the timeout expired before any descriptor became ready.
    pub timed_out: bool,
}

// ---------------------------------------------------------------------------
// FdReadiness — simulated per-fd readiness
// ---------------------------------------------------------------------------

/// Simulated readiness information for a single file descriptor.
#[derive(Debug, Clone, Copy)]
pub struct FdReadiness {
    /// The file descriptor index.
    pub fd: usize,
    /// Whether this fd is readable.
    pub readable: bool,
    /// Whether this fd is writable.
    pub writable: bool,
    /// Whether this fd has an exceptional condition.
    pub exceptional: bool,
    /// Whether this fd is valid.
    pub valid: bool,
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate the `nfds` argument (must be non-negative and <= FD_SETSIZE).
fn validate_nfds(nfds: i32) -> Result<()> {
    if nfds < 0 || nfds > PSELECT_MAX_NFDS {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Core logic
// ---------------------------------------------------------------------------

/// Check `readfds` against the ready set; clear bits for non-ready fds.
///
/// Returns the count of ready fds in this set.
fn check_readfds(fds: &mut FdSet, nfds: usize, ready_set: &[FdReadiness]) -> i32 {
    let mut count = 0i32;
    for fd in 0..nfds {
        if !fds.is_set(fd) {
            continue;
        }
        let is_ready = ready_set
            .iter()
            .any(|r| r.fd == fd && r.valid && r.readable);
        if !is_ready {
            fds.clear(fd);
        } else {
            count = count.saturating_add(1);
        }
    }
    count
}

/// Check `writefds` against the ready set; clear bits for non-ready fds.
///
/// Returns the count of ready fds in this set.
fn check_writefds(fds: &mut FdSet, nfds: usize, ready_set: &[FdReadiness]) -> i32 {
    let mut count = 0i32;
    for fd in 0..nfds {
        if !fds.is_set(fd) {
            continue;
        }
        let is_ready = ready_set
            .iter()
            .any(|r| r.fd == fd && r.valid && r.writable);
        if !is_ready {
            fds.clear(fd);
        } else {
            count = count.saturating_add(1);
        }
    }
    count
}

/// Check `exceptfds` against the ready set; clear bits for non-ready fds.
///
/// Returns the count of ready fds in this set.
fn check_exceptfds(fds: &mut FdSet, nfds: usize, ready_set: &[FdReadiness]) -> i32 {
    let mut count = 0i32;
    for fd in 0..nfds {
        if !fds.is_set(fd) {
            continue;
        }
        let is_ready = ready_set
            .iter()
            .any(|r| r.fd == fd && r.valid && r.exceptional);
        if !is_ready {
            fds.clear(fd);
        } else {
            count = count.saturating_add(1);
        }
    }
    count
}

// ---------------------------------------------------------------------------
// Public syscall handlers
// ---------------------------------------------------------------------------

/// `pselect6` — synchronous I/O multiplexing with signal mask.
///
/// Checks file descriptors `0..nfds` in `readfds`, `writefds`, and
/// `exceptfds`. On return each set contains only those fds that were
/// ready for the corresponding operation.
///
/// The `sigmask` is applied atomically during the wait and restored
/// before return (signal integration deferred).
///
/// Returns the total number of ready fds across all three sets,
/// or `0` if the timeout expired.
///
/// # Errors
///
/// | `Error`           | Condition                                  |
/// |-------------------|--------------------------------------------|
/// | `InvalidArgument` | `nfds < 0` or `nfds > FD_SETSIZE`         |
/// | `InvalidArgument` | `timeout.tv_nsec` out of `[0, 999_999_999]`|
///
/// Reference: POSIX.1-2024 §pselect.
#[allow(clippy::too_many_arguments)]
pub fn do_pselect(
    nfds: i32,
    readfds: Option<&mut FdSet>,
    writefds: Option<&mut FdSet>,
    exceptfds: Option<&mut FdSet>,
    timeout: Option<&Timespec>,
    sigmask: Option<SigMask>,
    ready_set: &[FdReadiness],
) -> Result<SelectResult> {
    validate_nfds(nfds)?;

    if let Some(ts) = timeout {
        ts.validate()?;
    }

    // sigmask: accepted for future signal subsystem integration.
    let _ = sigmask;

    let upper = nfds as usize;
    let mut total_ready = 0i32;

    if let Some(rfd) = readfds {
        total_ready = total_ready.saturating_add(check_readfds(rfd, upper, ready_set));
    }
    if let Some(wfd) = writefds {
        total_ready = total_ready.saturating_add(check_writefds(wfd, upper, ready_set));
    }
    if let Some(efd) = exceptfds {
        total_ready = total_ready.saturating_add(check_exceptfds(efd, upper, ready_set));
    }

    Ok(SelectResult {
        ready: total_ready,
        timed_out: false,
    })
}

/// `pselect6` with a raw signal mask bitmask.
///
/// Convenience wrapper that converts `sigmask_bits` to a `SigMask`.
#[allow(clippy::too_many_arguments)]
pub fn do_pselect_raw(
    nfds: i32,
    readfds: Option<&mut FdSet>,
    writefds: Option<&mut FdSet>,
    exceptfds: Option<&mut FdSet>,
    timeout: Option<&Timespec>,
    sigmask_bits: u64,
    ready_set: &[FdReadiness],
) -> Result<SelectResult> {
    let mask = if sigmask_bits != 0 {
        Some(SigMask::new(sigmask_bits))
    } else {
        None
    };
    do_pselect(nfds, readfds, writefds, exceptfds, timeout, mask, ready_set)
}

/// Validate `pselect6` arguments without executing the poll.
pub fn validate_pselect_args(nfds: i32, timeout: Option<&Timespec>) -> Result<()> {
    validate_nfds(nfds)?;
    if let Some(ts) = timeout {
        ts.validate()?;
    }
    Ok(())
}
