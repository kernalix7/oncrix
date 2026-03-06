// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! POSIX poll/ppoll/select syscall handlers.
//!
//! Implements `poll`, `ppoll`, and `select` per POSIX.1-2024
//! (IEEE Std 1003.1-2024).  These provide I/O multiplexing so a
//! process can monitor multiple file descriptors for readiness.

use crate::clock::Timespec;
use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Poll event constants (i16)
// ---------------------------------------------------------------------------

/// Data other than high-priority data may be read without blocking.
pub const POLLIN: i16 = 0x0001;

/// High-priority data may be read without blocking.
pub const POLLPRI: i16 = 0x0002;

/// Normal data may be written without blocking.
pub const POLLOUT: i16 = 0x0004;

/// An error has occurred on the device or stream (revents only).
pub const POLLERR: i16 = 0x0008;

/// The device has been disconnected (revents only).
pub const POLLHUP: i16 = 0x0010;

/// The specified fd value is invalid (revents only).
pub const POLLNVAL: i16 = 0x0020;

/// Normal data may be read without blocking.
pub const POLLRDNORM: i16 = 0x0040;

/// Priority data may be read without blocking.
pub const POLLRDBAND: i16 = 0x0080;

/// Equivalent to [`POLLOUT`].
pub const POLLWRNORM: i16 = 0x0100;

/// Priority data may be written without blocking.
pub const POLLWRBAND: i16 = 0x0200;

/// Mask of events that may be requested in `events`.
const POLL_REQUESTABLE: i16 =
    POLLIN | POLLPRI | POLLOUT | POLLRDNORM | POLLRDBAND | POLLWRNORM | POLLWRBAND;

/// Maximum number of file descriptors for a single poll call.
const POLL_MAX_FDS: u32 = 256;

/// Maximum file descriptors tracked by [`FdSet`] (matches FD_SETSIZE).
const FD_SETSIZE: usize = 1024;

/// Number of `u64` words required for [`FD_SETSIZE`] bits.
const FD_SET_WORDS: usize = FD_SETSIZE / 64;

// ---------------------------------------------------------------------------
// PollFd
// ---------------------------------------------------------------------------

/// POSIX `struct pollfd` — describes a single file descriptor to poll.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PollFd {
    /// File descriptor to poll (negative means ignore).
    pub fd: i32,
    /// Requested events (bitmask of `POLL*` constants).
    pub events: i16,
    /// Returned events (filled in by the kernel).
    pub revents: i16,
}

impl PollFd {
    /// Create a new `PollFd` monitoring `fd` for `events`.
    pub const fn new(fd: i32, events: i16) -> Self {
        Self {
            fd,
            events,
            revents: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// FdSet — 1024-bit bitmap for select()
// ---------------------------------------------------------------------------

/// Bit-set representing up to [`FD_SETSIZE`] (1024) file descriptors,
/// equivalent to POSIX `fd_set`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FdSet {
    /// Underlying 1024-bit storage (16 × 64-bit words).
    pub bits: [u64; FD_SET_WORDS],
}

impl Default for FdSet {
    fn default() -> Self {
        Self::new()
    }
}

impl FdSet {
    /// Create a zeroed `FdSet`.
    pub const fn new() -> Self {
        Self {
            bits: [0u64; FD_SET_WORDS],
        }
    }

    /// Set the bit for file descriptor `fd`.
    ///
    /// Does nothing if `fd` is out of range.
    pub fn set(&mut self, fd: usize) {
        if fd < FD_SETSIZE {
            self.bits[fd / 64] |= 1u64 << (fd % 64);
        }
    }

    /// Clear the bit for file descriptor `fd`.
    ///
    /// Does nothing if `fd` is out of range.
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
}

// ---------------------------------------------------------------------------
// PollTable — internal bookkeeping for a poll operation
// ---------------------------------------------------------------------------

/// Internal state for poll operations.
///
/// Validates arguments and dispatches readiness checks.
/// Supports up to [`POLL_MAX_FDS`] (256) descriptors per call.
#[derive(Debug, Clone, Copy, Default)]
pub struct PollTable {
    _private: (),
}

impl PollTable {
    /// Create a new `PollTable`.
    pub const fn new() -> Self {
        Self { _private: () }
    }

    /// Perform a poll operation over `fds`.
    ///
    /// `timeout_ms` semantics match POSIX `poll()`:
    /// - negative → block indefinitely
    /// - 0 → return immediately
    /// - positive → wait up to that many milliseconds
    ///
    /// Returns the number of descriptors with non-zero `revents`.
    pub fn poll(&mut self, fds: &mut [PollFd], nfds: u32, timeout_ms: i32) -> Result<i32> {
        self.validate_nfds(nfds)?;
        let _ = timeout_ms;

        let n = fds.iter_mut().take(nfds as usize).fold(0i32, |ready, pfd| {
            if pfd.fd < 0 {
                pfd.revents = 0;
                return ready;
            }
            let rev = check_fd(pfd.fd, pfd.events);
            pfd.revents = rev;
            if rev != 0 { ready + 1 } else { ready }
        });
        Ok(n)
    }

    /// Perform a ppoll operation (timeout as `Timespec`, with
    /// optional signal mask).
    ///
    /// If `timeout` is `None` the call blocks indefinitely (stub:
    /// returns immediately).  `sigmask` is accepted but not yet
    /// applied (requires signal subsystem integration).
    pub fn ppoll(
        &mut self,
        fds: &mut [PollFd],
        nfds: u32,
        timeout: Option<&Timespec>,
        sigmask: u64,
    ) -> Result<i32> {
        self.validate_nfds(nfds)?;

        // Validate timespec if provided.
        if let Some(ts) = timeout {
            if ts.tv_nsec < 0 || ts.tv_nsec >= 1_000_000_000 {
                return Err(Error::InvalidArgument);
            }
        }

        let _ = sigmask;

        let n = fds.iter_mut().take(nfds as usize).fold(0i32, |ready, pfd| {
            if pfd.fd < 0 {
                pfd.revents = 0;
                return ready;
            }
            let rev = check_fd(pfd.fd, pfd.events);
            pfd.revents = rev;
            if rev != 0 { ready + 1 } else { ready }
        });
        Ok(n)
    }

    /// Perform a select operation over read/write/except fd sets.
    ///
    /// `nfds` is the highest fd number + 1 (capped at
    /// [`FD_SETSIZE`]).  Returns the total number of ready
    /// descriptors across all three sets.
    #[allow(clippy::too_many_arguments)]
    pub fn select(
        &mut self,
        nfds: i32,
        readfds: Option<&mut FdSet>,
        writefds: Option<&mut FdSet>,
        exceptfds: Option<&mut FdSet>,
        timeout: Option<&mut Timespec>,
    ) -> Result<i32> {
        if nfds < 0 || nfds as usize > FD_SETSIZE {
            return Err(Error::InvalidArgument);
        }

        if let Some(ts) = timeout.as_deref() {
            if ts.tv_nsec < 0 || ts.tv_nsec >= 1_000_000_000 {
                return Err(Error::InvalidArgument);
            }
        }

        let upper = nfds as usize;
        let mut ready: i32 = 0;

        // Check readfds.
        if let Some(rfd) = readfds {
            for fd in 0..upper {
                if rfd.is_set(fd) {
                    let rev = check_fd(fd as i32, POLLIN);
                    if rev & (POLLIN | POLLERR | POLLHUP) != 0 {
                        ready += 1;
                    } else {
                        rfd.clear(fd);
                    }
                }
            }
        }

        // Check writefds.
        if let Some(wfd) = writefds {
            for fd in 0..upper {
                if wfd.is_set(fd) {
                    let rev = check_fd(fd as i32, POLLOUT);
                    if rev & (POLLOUT | POLLERR) != 0 {
                        ready += 1;
                    } else {
                        wfd.clear(fd);
                    }
                }
            }
        }

        // Check exceptfds.
        if let Some(efd) = exceptfds {
            for fd in 0..upper {
                if efd.is_set(fd) {
                    let rev = check_fd(fd as i32, POLLPRI);
                    if rev & POLLPRI != 0 {
                        ready += 1;
                    } else {
                        efd.clear(fd);
                    }
                }
            }
        }

        Ok(ready)
    }

    /// Validate that `nfds` is within the allowed range.
    fn validate_nfds(&self, nfds: u32) -> Result<()> {
        if nfds > POLL_MAX_FDS {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Readiness check helper
// ---------------------------------------------------------------------------

/// Simulate a readiness check for file descriptor `fd` against the
/// requested `events`.
///
/// A real kernel implementation would query the underlying file
/// object (socket, pipe, device, etc.) for its current readiness
/// state.  This stub returns `POLLNVAL` for all descriptors
/// because no file table exists yet.
pub fn check_fd(fd: i32, events: i16) -> i16 {
    if fd < 0 {
        return 0;
    }

    // Stub: no file table — every fd is invalid.
    // Real implementation would look up the fd in the process
    // file table and query the underlying object's poll method.
    let _ = events & POLL_REQUESTABLE;
    POLLNVAL
}

// ---------------------------------------------------------------------------
// Syscall handler functions
// ---------------------------------------------------------------------------

/// `poll` — wait for events on a set of file descriptors.
///
/// Examines each entry in `fds` (up to `nfds`) for the events
/// specified in its `events` field.  On return, the `revents`
/// field of each entry is updated.
///
/// `timeout_ms` semantics:
/// - `-1` — block indefinitely
/// - `0`  — return immediately (poll mode)
/// - `>0` — wait up to `timeout_ms` milliseconds
///
/// Returns the number of descriptors with non-zero `revents`, or
/// `0` if the timeout expired.
pub fn do_poll(fds: &mut [PollFd], nfds: u32, timeout_ms: i32) -> Result<i32> {
    let mut table = PollTable::new();
    table.poll(fds, nfds, timeout_ms)
}

/// `ppoll` — wait for events on a set of file descriptors, with
/// nanosecond-precision timeout and optional signal mask.
///
/// If `timeout` is `None`, the call blocks indefinitely.
/// `sigmask` is the signal mask to apply atomically during the
/// wait (stub: not yet functional).
pub fn do_ppoll(
    fds: &mut [PollFd],
    nfds: u32,
    timeout: Option<&Timespec>,
    sigmask: u64,
) -> Result<i32> {
    let mut table = PollTable::new();
    table.ppoll(fds, nfds, timeout, sigmask)
}

/// `select` — synchronous I/O multiplexing.
///
/// Examines file descriptors `0..nfds` across the three optional
/// sets (`readfds`, `writefds`, `exceptfds`).  On return, each
/// set contains only those descriptors that are ready for the
/// corresponding operation.
///
/// Returns the total number of ready descriptors across all sets.
pub fn do_select(
    nfds: i32,
    readfds: Option<&mut FdSet>,
    writefds: Option<&mut FdSet>,
    exceptfds: Option<&mut FdSet>,
    timeout: Option<&mut Timespec>,
) -> Result<i32> {
    let mut table = PollTable::new();
    table.select(nfds, readfds, writefds, exceptfds, timeout)
}
