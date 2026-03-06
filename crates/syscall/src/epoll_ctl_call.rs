// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `epoll_ctl(2)` syscall handler — control an epoll interest list.
//!
//! `epoll_ctl` adds, modifies, or removes file descriptors from an epoll
//! instance's interest list.  Each registered fd is associated with an event
//! mask and a user-defined 64-bit data word.
//!
//! # POSIX reference
//!
//! Linux-specific: no direct POSIX equivalent.  Described in `epoll_ctl(2)`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Operation constants
// ---------------------------------------------------------------------------

/// Add a new file descriptor to the interest list.
pub const EPOLL_CTL_ADD: i32 = 1;
/// Remove a file descriptor from the interest list.
pub const EPOLL_CTL_DEL: i32 = 2;
/// Modify the event mask for a registered file descriptor.
pub const EPOLL_CTL_MOD: i32 = 3;

// ---------------------------------------------------------------------------
// Event flag bits
// ---------------------------------------------------------------------------

/// Data available to read.
pub const EPOLLIN: u32 = 0x0000_0001;
/// Urgent data available (out-of-band).
pub const EPOLLPRI: u32 = 0x0000_0002;
/// Write space available.
pub const EPOLLOUT: u32 = 0x0000_0004;
/// Stream socket peer closed connection or half-shutdown of writing half.
pub const EPOLLRDHUP: u32 = 0x0000_2000;
/// Error condition on the descriptor.
pub const EPOLLERR: u32 = 0x0000_0008;
/// Hang-up event.
pub const EPOLLHUP: u32 = 0x0000_0010;
/// Edge-triggered mode.
pub const EPOLLET: u32 = 0x8000_0000;
/// One-shot mode — auto-disable after first event.
pub const EPOLLONESHOT: u32 = 0x4000_0000;
/// Wake even if the thread is waiting in `epoll_wait` with no events.
pub const EPOLLWAKEUP: u32 = 0x2000_0000;
/// Exclusive wakeup mode (thundering-herd prevention).
pub const EPOLLEXCLUSIVE: u32 = 0x1000_0000;

/// All valid event flags combined.
const VALID_EVENTS: u32 = EPOLLIN
    | EPOLLPRI
    | EPOLLOUT
    | EPOLLRDHUP
    | EPOLLERR
    | EPOLLHUP
    | EPOLLET
    | EPOLLONESHOT
    | EPOLLWAKEUP
    | EPOLLEXCLUSIVE;

// ---------------------------------------------------------------------------
// EpollEvent
// ---------------------------------------------------------------------------

/// Mirrors `struct epoll_event` from `<sys/epoll.h>`.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EpollEvent {
    /// Requested events (bitmask of `EPOLL*` flags).
    pub events: u32,
    /// User data associated with this event.
    pub data: u64,
}

impl EpollEvent {
    /// Create an event with a given mask and fd as data.
    pub fn with_fd(events: u32, fd: i32) -> Self {
        Self {
            events,
            data: fd as u64,
        }
    }

    /// Create an event with a given mask and pointer as data.
    pub fn with_ptr(events: u32, ptr: u64) -> Self {
        Self { events, data: ptr }
    }

    /// Return the data interpreted as a file descriptor.
    pub fn data_fd(&self) -> i32 {
        self.data as i32
    }
}

// ---------------------------------------------------------------------------
// Epoll operation
// ---------------------------------------------------------------------------

/// Validated epoll control operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpollOp {
    /// Add `fd` to the interest list.
    Add,
    /// Delete `fd` from the interest list.
    Delete,
    /// Modify the event mask for `fd`.
    Modify,
}

impl EpollOp {
    /// Parse from the raw `op` integer.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidArgument` for unknown operations.
    pub fn from_raw(op: i32) -> Result<Self> {
        match op {
            EPOLL_CTL_ADD => Ok(Self::Add),
            EPOLL_CTL_DEL => Ok(Self::Delete),
            EPOLL_CTL_MOD => Ok(Self::Modify),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ---------------------------------------------------------------------------
// EpollCtlRequest
// ---------------------------------------------------------------------------

/// Parsed `epoll_ctl` request.
#[derive(Debug, Clone, Copy)]
pub struct EpollCtlRequest {
    /// epoll instance file descriptor.
    pub epfd: i32,
    /// Operation to perform.
    pub op: EpollOp,
    /// Target file descriptor.
    pub fd: i32,
    /// Event specification (may be `None` for `EPOLL_CTL_DEL`).
    pub event: Option<EpollEvent>,
}

impl EpollCtlRequest {
    /// Create a new request.
    pub fn new(epfd: i32, op: EpollOp, fd: i32, event: Option<EpollEvent>) -> Self {
        Self {
            epfd,
            op,
            fd,
            event,
        }
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate `epoll_ctl` event flags.
///
/// `EPOLLEXCLUSIVE` and `EPOLLONESHOT` are mutually exclusive.
///
/// # Errors
///
/// | `Error`           | Condition                                     |
/// |-------------------|-----------------------------------------------|
/// | `InvalidArgument` | Unknown event bits or incompatible flag combo |
pub fn validate_epoll_events(events: u32) -> Result<()> {
    if events & !VALID_EVENTS != 0 {
        return Err(Error::InvalidArgument);
    }
    if events & EPOLLEXCLUSIVE != 0 && events & EPOLLONESHOT != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `epoll_ctl(2)`.
///
/// Validates all arguments and returns an `EpollCtlRequest`.  The caller
/// applies the operation to the epoll instance's interest table.
///
/// For `EPOLL_CTL_DEL` the `event` pointer is ignored by Linux (though POSIX
/// recommends passing it for portability).  Here it is accepted as `None`.
///
/// # Arguments
///
/// - `epfd`  — epoll instance file descriptor
/// - `op`    — one of `EPOLL_CTL_ADD`, `EPOLL_CTL_DEL`, `EPOLL_CTL_MOD`
/// - `fd`    — target file descriptor
/// - `event` — event specification (required for ADD/MOD, optional for DEL)
///
/// # Errors
///
/// | `Error`           | Condition                                         |
/// |-------------------|---------------------------------------------------|
/// | `InvalidArgument` | Invalid fd, unknown op, bad event flags, epfd==fd |
/// | `AlreadyExists`   | EPOLL_CTL_ADD on already-registered fd             |
/// | `NotFound`        | EPOLL_CTL_DEL/MOD on fd not in interest list       |
pub fn do_epoll_ctl(
    epfd: i32,
    op: i32,
    fd: i32,
    event: Option<EpollEvent>,
) -> Result<EpollCtlRequest> {
    if epfd < 0 || fd < 0 {
        return Err(Error::InvalidArgument);
    }
    if epfd == fd {
        // POSIX: epoll fd cannot monitor itself.
        return Err(Error::InvalidArgument);
    }
    let operation = EpollOp::from_raw(op)?;
    if let Some(ev) = &event {
        validate_epoll_events(ev.events)?;
    }
    // DEL does not require an event.
    if operation != EpollOp::Delete && event.is_none() {
        return Err(Error::InvalidArgument);
    }
    Ok(EpollCtlRequest::new(epfd, operation, fd, event))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_ok() {
        let ev = EpollEvent::with_fd(EPOLLIN | EPOLLET, 5);
        let req = do_epoll_ctl(3, EPOLL_CTL_ADD, 5, Some(ev)).unwrap();
        assert_eq!(req.op, EpollOp::Add);
        assert_eq!(req.fd, 5);
    }

    #[test]
    fn del_no_event_ok() {
        let req = do_epoll_ctl(3, EPOLL_CTL_DEL, 5, None).unwrap();
        assert_eq!(req.op, EpollOp::Delete);
        assert!(req.event.is_none());
    }

    #[test]
    fn mod_ok() {
        let ev = EpollEvent::with_fd(EPOLLOUT, 5);
        let req = do_epoll_ctl(3, EPOLL_CTL_MOD, 5, Some(ev)).unwrap();
        assert_eq!(req.op, EpollOp::Modify);
    }

    #[test]
    fn epfd_equals_fd_rejected() {
        let ev = EpollEvent::with_fd(EPOLLIN, 3);
        assert_eq!(
            do_epoll_ctl(3, EPOLL_CTL_ADD, 3, Some(ev)),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn bad_op_rejected() {
        let ev = EpollEvent::with_fd(EPOLLIN, 5);
        assert_eq!(
            do_epoll_ctl(3, 99, 5, Some(ev)),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn exclusive_and_oneshot_rejected() {
        let ev = EpollEvent::with_fd(EPOLLIN | EPOLLEXCLUSIVE | EPOLLONESHOT, 5);
        assert_eq!(
            do_epoll_ctl(3, EPOLL_CTL_ADD, 5, Some(ev)),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn add_without_event_rejected() {
        assert_eq!(
            do_epoll_ctl(3, EPOLL_CTL_ADD, 5, None),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn data_fd_roundtrip() {
        let ev = EpollEvent::with_fd(EPOLLIN, 42);
        assert_eq!(ev.data_fd(), 42);
    }
}
