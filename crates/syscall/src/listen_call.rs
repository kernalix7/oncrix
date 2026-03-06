// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `listen(2)` syscall handler — mark a socket as passive.
//!
//! `listen` transitions a bound socket into the listening state, establishing
//! the accept queue for incoming connection requests.  It is valid only for
//! connection-oriented sockets (`SOCK_STREAM`, `SOCK_SEQPACKET`).
//!
//! # POSIX reference
//!
//! POSIX.1-2024 `listen()` — `susv5-html/functions/listen.html`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Backlog limits
// ---------------------------------------------------------------------------

/// System-wide maximum connection backlog.
pub const SOMAXCONN: i32 = 4096;
/// Minimum effective backlog (kernel floor).
pub const BACKLOG_MIN: i32 = 1;

// ---------------------------------------------------------------------------
// Socket type flags
// ---------------------------------------------------------------------------

/// Sequenced, reliable, connection-based byte streams.
pub const SOCK_STREAM: i32 = 1;
/// Sequenced, reliable, connection-based datagrams.
pub const SOCK_SEQPACKET: i32 = 5;
/// Mask covering the base socket type (low 4 bits).
pub const SOCK_TYPE_MASK: i32 = 0xF;

// ---------------------------------------------------------------------------
// Listen request
// ---------------------------------------------------------------------------

/// Validated arguments for a `listen` call.
#[derive(Debug, Clone, Copy)]
pub struct ListenRequest {
    /// Socket file descriptor.
    pub sockfd: i32,
    /// Requested backlog queue depth.
    pub backlog: i32,
    /// Effective (clamped) backlog.
    pub effective_backlog: i32,
}

impl ListenRequest {
    /// Create a listen request, clamping `backlog` to `[BACKLOG_MIN, SOMAXCONN]`.
    pub fn new(sockfd: i32, backlog: i32) -> Self {
        let effective_backlog = backlog.max(BACKLOG_MIN).min(SOMAXCONN);
        Self {
            sockfd,
            backlog,
            effective_backlog,
        }
    }
}

// ---------------------------------------------------------------------------
// Socket listen state
// ---------------------------------------------------------------------------

/// State of a listening socket's accept queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenState {
    /// Not yet in listening state.
    Idle,
    /// Actively accepting connections.
    Listening,
}

/// Kernel representation of a listening socket's accept queue entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BacklogEntry {
    /// Sequence number of this connection attempt.
    pub seq: u32,
    /// Source IPv4 address (network byte order).
    pub src_addr: u32,
    /// Source port (network byte order).
    pub src_port: u16,
}

impl BacklogEntry {
    /// Create a new backlog entry.
    pub fn new(seq: u32, src_addr: u32, src_port: u16) -> Self {
        Self {
            seq,
            src_addr,
            src_port,
        }
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate arguments to `listen(2)`.
///
/// # Errors
///
/// | `Error`           | Condition                                     |
/// |-------------------|-----------------------------------------------|
/// | `InvalidArgument` | `sockfd` < 0                                  |
/// | `InvalidArgument` | `sock_type` is not connection-oriented        |
pub fn validate_listen_args(sockfd: i32, sock_type: i32) -> Result<()> {
    if sockfd < 0 {
        return Err(Error::InvalidArgument);
    }
    let base_type = sock_type & SOCK_TYPE_MASK;
    if base_type != SOCK_STREAM && base_type != SOCK_SEQPACKET {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `listen(2)`.
///
/// Validates the socket descriptor and type, clamps the backlog, and returns
/// a `ListenRequest` ready to be submitted to the networking subsystem.
///
/// A backlog of 0 is replaced with `BACKLOG_MIN` (POSIX leaves implementation-
/// defined the behavior for backlog < 1, but Linux uses 0 as "use system
/// minimum").  Values exceeding `SOMAXCONN` are silently clamped.
///
/// # Arguments
///
/// - `sockfd`    — socket file descriptor
/// - `backlog`   — maximum pending connection queue depth
/// - `sock_type` — socket type bits from the socket's creation flags
///
/// # Errors
///
/// | `Error`           | Condition                                        |
/// |-------------------|--------------------------------------------------|
/// | `InvalidArgument` | Invalid fd or non-connection-oriented socket type |
pub fn do_listen(sockfd: i32, backlog: i32, sock_type: i32) -> Result<ListenRequest> {
    validate_listen_args(sockfd, sock_type)?;
    Ok(ListenRequest::new(sockfd, backlog))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listen_stream_ok() {
        let req = do_listen(3, 128, SOCK_STREAM).unwrap();
        assert_eq!(req.sockfd, 3);
        assert_eq!(req.effective_backlog, 128);
    }

    #[test]
    fn listen_seqpacket_ok() {
        let req = do_listen(4, 10, SOCK_SEQPACKET).unwrap();
        assert_eq!(req.effective_backlog, 10);
    }

    #[test]
    fn listen_negative_fd() {
        assert_eq!(do_listen(-1, 5, SOCK_STREAM), Err(Error::InvalidArgument));
    }

    #[test]
    fn listen_dgram_rejected() {
        // SOCK_DGRAM = 2
        assert_eq!(do_listen(3, 5, 2), Err(Error::InvalidArgument));
    }

    #[test]
    fn backlog_clamped_to_max() {
        let req = do_listen(3, 100_000, SOCK_STREAM).unwrap();
        assert_eq!(req.effective_backlog, SOMAXCONN);
    }

    #[test]
    fn backlog_zero_becomes_min() {
        let req = do_listen(3, 0, SOCK_STREAM).unwrap();
        assert_eq!(req.effective_backlog, BACKLOG_MIN);
    }

    #[test]
    fn backlog_negative_becomes_min() {
        let req = do_listen(3, -5, SOCK_STREAM).unwrap();
        assert_eq!(req.effective_backlog, BACKLOG_MIN);
    }

    #[test]
    fn backlog_entry_fields() {
        let entry = BacklogEntry::new(1, 0x7f000001, 54321);
        assert_eq!(entry.seq, 1);
        assert_eq!(entry.src_port, 54321);
    }
}
