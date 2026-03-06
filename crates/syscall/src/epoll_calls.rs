// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! epoll syscall handlers.
//!
//! Wraps the kernel epoll subsystem with POSIX / Linux-compatible
//! syscall entry points: `epoll_create`, `epoll_create1`,
//! `epoll_ctl`, `epoll_wait`, `epoll_pwait`, and `epoll_pwait2`.

use oncrix_lib::{Error, Result};

use crate::clock::Timespec;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Close-on-exec flag for `epoll_create1`.
pub const EPOLL_CLOEXEC: i32 = 0x80000;

/// `epoll_ctl` operation: register a new file descriptor.
pub const EPOLL_CTL_ADD: i32 = 1;

/// `epoll_ctl` operation: remove a file descriptor.
pub const EPOLL_CTL_DEL: i32 = 2;

/// `epoll_ctl` operation: modify an existing registration.
pub const EPOLL_CTL_MOD: i32 = 3;

// ---------------------------------------------------------------------------
// EpollCtlOp
// ---------------------------------------------------------------------------

/// Control operations for `epoll_ctl`, with repr values matching
/// the Linux `EPOLL_CTL_*` constants.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum EpollCtlOp {
    /// Register a new file descriptor on the epoll instance.
    #[default]
    Add = 1,
    /// Remove a file descriptor from the epoll instance.
    Del = 2,
    /// Modify the events mask for an already-registered fd.
    Mod = 3,
}

impl EpollCtlOp {
    /// Convert a raw `i32` operation code to an [`EpollCtlOp`].
    ///
    /// Returns `Err(InvalidArgument)` for unrecognised values.
    pub fn from_raw(raw: i32) -> Result<Self> {
        match raw {
            1 => Ok(Self::Add),
            2 => Ok(Self::Del),
            3 => Ok(Self::Mod),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ---------------------------------------------------------------------------
// EpollEvent
// ---------------------------------------------------------------------------

/// User-facing epoll event, mirrors `struct epoll_event` from
/// Linux.
///
/// Passed to `epoll_ctl` to specify interest and returned by
/// `epoll_wait` to report readiness.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct EpollEvent {
    /// Bitmask of event flags (`EPOLLIN`, `EPOLLOUT`, etc.).
    pub events: u32,
    /// Opaque user data returned alongside readiness
    /// notifications.
    pub data: u64,
}

// ---------------------------------------------------------------------------
// SyscallEpollArgs — argument validation helper
// ---------------------------------------------------------------------------

/// Helper for validating and converting raw syscall arguments
/// into checked epoll parameters.
#[derive(Debug, Default)]
pub struct SyscallEpollArgs {
    /// The epoll file descriptor.
    pub epfd: i32,
    /// Maximum number of events to return.
    pub max_events: i32,
    /// Timeout in milliseconds (-1 = block indefinitely).
    pub timeout_ms: i32,
}

impl SyscallEpollArgs {
    /// Validate common `epoll_wait` arguments.
    ///
    /// `epfd` must be non-negative and `max_events` must be
    /// positive.
    pub fn validate_wait(epfd: i32, max_events: i32) -> Result<()> {
        if epfd < 0 {
            return Err(Error::InvalidArgument);
        }
        if max_events <= 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Validate an epoll file descriptor (non-negative).
    pub fn validate_epfd(epfd: i32) -> Result<()> {
        if epfd < 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Validate a target file descriptor (non-negative).
    pub fn validate_fd(fd: i32) -> Result<()> {
        if fd < 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Syscall handlers
// ---------------------------------------------------------------------------

/// `epoll_create` — create a new epoll instance.
///
/// The `flags` parameter accepts `EPOLL_CLOEXEC` (0x80000) to set
/// close-on-exec on the returned file descriptor. Any other flag
/// bits cause `InvalidArgument`.
///
/// Returns an epoll file descriptor on success.
pub fn do_epoll_create(flags: i32) -> Result<i32> {
    // Only EPOLL_CLOEXEC is valid.
    if flags & !EPOLL_CLOEXEC != 0 {
        return Err(Error::InvalidArgument);
    }

    let _cloexec = flags & EPOLL_CLOEXEC != 0;

    // Stub: real implementation allocates via EpollRegistry and
    // returns the instance ID cast to an fd.
    Err(Error::NotImplemented)
}

/// `epoll_create1` — create a new epoll instance (extended).
///
/// Alias for [`do_epoll_create`] with the same flag semantics.
pub fn do_epoll_create1(flags: i32) -> Result<i32> {
    do_epoll_create(flags)
}

/// `epoll_ctl` — control an epoll instance.
///
/// Adds, modifies, or removes a file descriptor registration on
/// the epoll instance identified by `epfd`.
///
/// `op` must be one of [`EPOLL_CTL_ADD`], [`EPOLL_CTL_DEL`], or
/// [`EPOLL_CTL_MOD`].
pub fn do_epoll_ctl(epfd: i32, op: i32, fd: i32, event: &EpollEvent) -> Result<()> {
    SyscallEpollArgs::validate_epfd(epfd)?;
    SyscallEpollArgs::validate_fd(fd)?;

    let _ctl_op = EpollCtlOp::from_raw(op)?;
    let _ = event;

    // Stub: real implementation delegates to
    // EpollRegistry::epoll_ctl(epfd, ctl_op, fd, event).
    Err(Error::NotImplemented)
}

/// `epoll_wait` — wait for events on an epoll instance.
///
/// Blocks until at least one event is available or `timeout_ms`
/// milliseconds have elapsed. A timeout of -1 blocks indefinitely;
/// a timeout of 0 returns immediately.
///
/// Returns the number of ready events written into `events`.
pub fn do_epoll_wait(
    epfd: i32,
    events: &mut [EpollEvent],
    max_events: i32,
    timeout_ms: i32,
) -> Result<i32> {
    SyscallEpollArgs::validate_wait(epfd, max_events)?;

    let limit = (max_events as usize).min(events.len());
    if limit == 0 {
        return Err(Error::InvalidArgument);
    }

    let _ = timeout_ms;

    // Stub: real implementation calls EpollRegistry::epoll_wait
    // and copies kernel events into the user-space slice.
    Err(Error::NotImplemented)
}

/// `epoll_pwait` — wait for events with a signal mask.
///
/// Atomically replaces the signal mask with `sigmask`, waits for
/// events, and restores the original mask.
///
/// Returns the number of ready events written into `events`.
pub fn do_epoll_pwait(
    epfd: i32,
    events: &mut [EpollEvent],
    max_events: i32,
    timeout_ms: i32,
    sigmask: u64,
) -> Result<i32> {
    let _ = sigmask;

    // Signal mask handling is a stub; delegate to epoll_wait.
    do_epoll_wait(epfd, events, max_events, timeout_ms)
}

/// `epoll_pwait2` — wait for events with nanosecond timeout and
/// signal mask.
///
/// Similar to [`do_epoll_pwait`] but accepts an optional
/// [`Timespec`] for nanosecond-precision timeout instead of a
/// millisecond integer.
///
/// Returns the number of ready events written into `events`.
pub fn do_epoll_pwait2(
    epfd: i32,
    events: &mut [EpollEvent],
    max_events: i32,
    timeout: Option<&Timespec>,
    sigmask: u64,
) -> Result<i32> {
    SyscallEpollArgs::validate_wait(epfd, max_events)?;

    let limit = (max_events as usize).min(events.len());
    if limit == 0 {
        return Err(Error::InvalidArgument);
    }

    let _ = sigmask;
    let _ = timeout;

    // Stub: real implementation converts Timespec to kernel
    // timeout and delegates to EpollRegistry::epoll_wait.
    Err(Error::NotImplemented)
}
