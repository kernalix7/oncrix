// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! poll/select I/O multiplexing subsystem.
//!
//! Provides the classic POSIX `poll()` and `select()` interfaces for
//! monitoring multiple file descriptors for readiness. These are the
//! traditional I/O multiplexing mechanisms predating `epoll`.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────┐
//! │             poll() interface                  │
//! │  ┌─────────┐ ┌─────────┐     ┌─────────┐   │
//! │  │ PollFd  │ │ PollFd  │ ... │ PollFd  │   │
//! │  │ fd=3    │ │ fd=7    │     │ fd=12   │   │
//! │  │ POLLIN  │ │ POLLOUT │     │ POLLIN  │   │
//! │  └─────────┘ └─────────┘     └─────────┘   │
//! └──────────────────────────────────────────────┘
//!
//! ┌──────────────────────────────────────────────┐
//! │           select() interface                  │
//! │  readfds:   [bits 0..1023]                   │
//! │  writefds:  [bits 0..1023]                   │
//! │  exceptfds: [bits 0..1023]                   │
//! └──────────────────────────────────────────────┘
//! ```
//!
//! # POSIX Reference
//!
//! - `poll()`: POSIX.1-2024, XSH §poll
//! - `select()`/`pselect()`: POSIX.1-2024, XSH §pselect
//!
//! Both interfaces scan file descriptors for readiness. `poll()` uses
//! a flat array of [`PollFd`] structs; `select()` uses three bitmaps
//! ([`FdSet`]) for read/write/except conditions.

use oncrix_lib::{Error, Result};

// ── Poll event flags ─────────────────────────────────────────────

/// Data (other than high-priority) may be read without blocking.
pub const POLLIN: i16 = 0x001;

/// Priority data may be read without blocking.
pub const POLLPRI: i16 = 0x002;

/// Normal data may be written without blocking.
pub const POLLOUT: i16 = 0x004;

/// An error has occurred on the device or stream (output only).
pub const POLLERR: i16 = 0x008;

/// The device has been disconnected (output only).
pub const POLLHUP: i16 = 0x010;

/// Invalid file descriptor (output only).
pub const POLLNVAL: i16 = 0x020;

// ── PollFd ───────────────────────────────────────────────────────

/// User-facing poll descriptor, compatible with `struct pollfd`.
///
/// Passed to `poll()` to specify a file descriptor and events of
/// interest. On return, `revents` indicates which conditions hold.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PollFd {
    /// File descriptor to monitor (negative values are ignored).
    pub fd: i32,
    /// Requested events bitmask (`POLLIN`, `POLLOUT`, etc.).
    pub events: i16,
    /// Returned events bitmask (set by the kernel).
    pub revents: i16,
}

impl PollFd {
    /// Create a new poll descriptor for the given fd and events.
    pub const fn new(fd: i32, events: i16) -> Self {
        Self {
            fd,
            events,
            revents: 0,
        }
    }
}

// ── do_poll ──────────────────────────────────────────────────────

/// Maximum number of file descriptors that `do_poll` accepts.
const MAX_POLL_FDS: usize = 1024;

/// Scan file descriptors for I/O readiness (poll semantics).
///
/// Iterates over `fds`, checks each file descriptor for readiness
/// matching the requested `events`, and writes the result into
/// `revents`. Returns the number of descriptors with non-zero
/// `revents`.
///
/// # Arguments
///
/// - `fds`: slice of [`PollFd`] entries to scan
/// - `timeout_ms`: timeout in milliseconds (-1 = block indefinitely,
///   0 = return immediately). Currently only immediate mode (0) is
///   fully supported; blocking requires scheduler integration.
///
/// # Errors
///
/// Returns `Err(InvalidArgument)` if `fds` exceeds
/// [`MAX_POLL_FDS`].
///
/// # POSIX reference
///
/// See `.TheOpenGroup/susv5-html/functions/poll.html`.
pub fn do_poll(fds: &mut [PollFd], timeout_ms: i32) -> Result<usize> {
    if fds.len() > MAX_POLL_FDS {
        return Err(Error::InvalidArgument);
    }

    let _ = timeout_ms; // Blocking requires scheduler integration.

    let mut ready_count: usize = 0;

    for pollfd in fds.iter_mut() {
        pollfd.revents = 0;

        // Negative fd: skip this entry (POSIX behaviour).
        if pollfd.fd < 0 {
            continue;
        }

        // Validate fd range.
        if pollfd.fd > 255 {
            pollfd.revents = POLLNVAL;
            ready_count = ready_count.saturating_add(1);
            continue;
        }

        // Stub: In a full implementation, query the fd's backing
        // object (pipe, socket, file, device) for current readiness.
        // For now, mark all valid fds as ready for their requested
        // events. The unconditional flags (ERR, HUP, NVAL) are
        // always reported regardless of the events mask.
        //
        // When VFS/driver integration is available:
        //   1. Look up fd in the current process's FdTable
        //   2. Call the file's poll_readiness() method
        //   3. Set revents = readiness & (events | POLLERR | POLLHUP)
        let readiness = pollfd.events;
        pollfd.revents = readiness;

        if pollfd.revents != 0 {
            ready_count = ready_count.saturating_add(1);
        }
    }

    Ok(ready_count)
}

// ── FdSet ────────────────────────────────────────────────────────

/// Maximum number of file descriptors in an [`FdSet`].
///
/// Matches the traditional `FD_SETSIZE` of 1024.
pub const FD_SETSIZE: usize = 1024;

/// Number of `u64` words needed to hold [`FD_SETSIZE`] bits.
const FD_SET_WORDS: usize = FD_SETSIZE / 64;

/// Bitmap of file descriptors for the `select()` interface.
///
/// Compatible with the POSIX `fd_set` type. Stores up to
/// [`FD_SETSIZE`] (1024) file descriptor bits in a compact
/// array of 16 `u64` words.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FdSet {
    /// Bit array: bit `n` is set if fd `n` is in the set.
    pub bits: [u64; FD_SET_WORDS],
}

impl Default for FdSet {
    fn default() -> Self {
        Self::new()
    }
}

impl FdSet {
    /// Create an empty fd set (all bits cleared).
    pub const fn new() -> Self {
        Self {
            bits: [0; FD_SET_WORDS],
        }
    }

    /// Clear all bits in the set (`FD_ZERO`).
    pub fn zero(&mut self) {
        self.bits = [0; FD_SET_WORDS];
    }

    /// Add a file descriptor to the set (`FD_SET`).
    ///
    /// Returns `Err(InvalidArgument)` if `fd` >= [`FD_SETSIZE`].
    pub fn set(&mut self, fd: usize) -> Result<()> {
        if fd >= FD_SETSIZE {
            return Err(Error::InvalidArgument);
        }
        let word = fd / 64;
        let bit = fd % 64;
        self.bits[word] |= 1u64 << bit;
        Ok(())
    }

    /// Remove a file descriptor from the set (`FD_CLR`).
    ///
    /// Returns `Err(InvalidArgument)` if `fd` >= [`FD_SETSIZE`].
    pub fn clear(&mut self, fd: usize) -> Result<()> {
        if fd >= FD_SETSIZE {
            return Err(Error::InvalidArgument);
        }
        let word = fd / 64;
        let bit = fd % 64;
        self.bits[word] &= !(1u64 << bit);
        Ok(())
    }

    /// Test whether a file descriptor is in the set (`FD_ISSET`).
    ///
    /// Returns `Err(InvalidArgument)` if `fd` >= [`FD_SETSIZE`].
    pub fn is_set(&self, fd: usize) -> Result<bool> {
        if fd >= FD_SETSIZE {
            return Err(Error::InvalidArgument);
        }
        let word = fd / 64;
        let bit = fd % 64;
        Ok(self.bits[word] & (1u64 << bit) != 0)
    }
}

// ── do_select ────────────────────────────────────────────────────

/// Scan file descriptors for readiness (select semantics).
///
/// Examines file descriptors 0 through `nfds - 1` across the three
/// optional fd sets (read, write, except). On return, each set
/// contains only the fds that are ready for the corresponding
/// condition. Returns the total number of ready fds across all sets.
///
/// # Arguments
///
/// - `nfds`: one more than the highest fd to check (must be
///   <= [`FD_SETSIZE`])
/// - `readfds`: fds to check for read readiness (may be `None`)
/// - `writefds`: fds to check for write readiness (may be `None`)
/// - `exceptfds`: fds to check for exceptional conditions
///   (may be `None`)
///
/// # Errors
///
/// Returns `Err(InvalidArgument)` if `nfds` > [`FD_SETSIZE`] or
/// if all three fd sets are `None`.
///
/// # POSIX reference
///
/// See `.TheOpenGroup/susv5-html/functions/pselect.html`.
pub fn do_select(
    nfds: usize,
    mut readfds: Option<&mut FdSet>,
    mut writefds: Option<&mut FdSet>,
    mut exceptfds: Option<&mut FdSet>,
) -> Result<usize> {
    if nfds > FD_SETSIZE {
        return Err(Error::InvalidArgument);
    }
    if readfds.is_none() && writefds.is_none() && exceptfds.is_none() {
        return Err(Error::InvalidArgument);
    }

    let mut ready_count: usize = 0;

    // We need to scan each fd once and update all three sets.
    // To avoid borrow issues, process each set independently.

    // Process readfds.
    if let Some(ref mut rset) = readfds {
        let mut result = FdSet::new();
        for fd in 0..nfds {
            if rset.is_set(fd)? {
                // Validate fd range.
                if fd > 255 {
                    return Err(Error::InvalidArgument);
                }
                // Stub: query fd for read readiness.
                // For now, report all valid fds as ready.
                result.set(fd)?;
                ready_count = ready_count.saturating_add(1);
            }
        }
        **rset = result;
    }

    // Process writefds.
    if let Some(ref mut wset) = writefds {
        let mut result = FdSet::new();
        for fd in 0..nfds {
            if wset.is_set(fd)? {
                if fd > 255 {
                    return Err(Error::InvalidArgument);
                }
                // Stub: query fd for write readiness.
                result.set(fd)?;
                ready_count = ready_count.saturating_add(1);
            }
        }
        **wset = result;
    }

    // Process exceptfds.
    if let Some(ref mut eset) = exceptfds {
        let result = FdSet::new();
        for fd in 0..nfds {
            if eset.is_set(fd)? && fd > 255 {
                return Err(Error::InvalidArgument);
            }
        }
        **eset = result;
    }

    Ok(ready_count)
}
