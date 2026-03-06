// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `listen(2)` syscall handler.
//!
//! Marks a socket as passive — ready to accept incoming connections.  The
//! socket must already be bound to a local address before `listen` is called.
//! After a successful `listen` call the socket transitions to `LISTENING`
//! state and the kernel begins queuing incoming connection requests up to
//! the specified `backlog`.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `listen()` specification.  Key behaviours:
//! - `EINVAL` if the socket is not bound or is already connected.
//! - `EOPNOTSUPP` for socket types that do not support `listen` (e.g. `SOCK_DGRAM`).
//! - `backlog` is silently clamped to `SOMAXCONN` (128 here).
//! - Calling `listen` on an already-listening socket updates the backlog.
//!
//! # References
//!
//! - POSIX.1-2024: `listen()`
//! - Linux man pages: `listen(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// System-wide maximum connection backlog (`SOMAXCONN`).
///
/// Linux default is 4096; we use a conservative 128 to keep stack overhead
/// minimal in the no-std environment.
pub const SOMAXCONN: i32 = 128;

/// Socket type: stream (supports `listen`).
pub const SOCK_STREAM: i32 = 1;
/// Socket type: sequenced packet (supports `listen`).
pub const SOCK_SEQPACKET: i32 = 5;

// ---------------------------------------------------------------------------
// Socket state
// ---------------------------------------------------------------------------

/// Lifecycle state of a socket with respect to the listen/accept pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketState {
    /// Newly created, no address assigned.
    Unbound,
    /// Bound to a local address, not yet listening.
    Bound,
    /// Passively listening for incoming connections.
    Listening,
    /// Active connection established.
    Connected,
    /// Socket has been shut down or closed.
    Closed,
}

/// Mutable state associated with a socket relevant to `listen(2)`.
#[derive(Debug)]
pub struct ListenSocket {
    /// Socket type (stream / seqpacket).
    pub sock_type: i32,
    /// Current socket lifecycle state.
    pub state: SocketState,
    /// Active backlog limit (clamped to [`SOMAXCONN`]).
    pub backlog: i32,
    /// Number of connections currently in the accept queue.
    pub queued: i32,
}

impl ListenSocket {
    /// Create a new socket in the `Bound` state ready to be listened on.
    pub const fn new_bound(sock_type: i32) -> Self {
        Self {
            sock_type,
            state: SocketState::Bound,
            backlog: 0,
            queued: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `listen(2)`.
///
/// Transitions `sock` to `LISTENING` state and sets the accept-queue backlog.
///
/// # Errors
///
/// | `Error`       | Condition                                              |
/// |---------------|--------------------------------------------------------|
/// | `InvalidArg`  | Socket is not bound (`EINVAL`)                         |
/// | `InvalidArg`  | Socket is already connected (`EINVAL`)                 |
/// | `NotSupported`| Socket type does not support `listen` (`EOPNOTSUPP`)   |
pub fn do_listen(sock: &mut ListenSocket, backlog: i32) -> Result<()> {
    // Only stream and seqpacket sockets support listen.
    if sock.sock_type != SOCK_STREAM && sock.sock_type != SOCK_SEQPACKET {
        return Err(Error::NotImplemented);
    }

    match sock.state {
        SocketState::Unbound => return Err(Error::InvalidArgument),
        SocketState::Connected => return Err(Error::InvalidArgument),
        SocketState::Closed => return Err(Error::InvalidArgument),
        SocketState::Bound | SocketState::Listening => {}
    }

    // Clamp backlog to [1, SOMAXCONN].
    let clamped = if backlog <= 0 {
        1
    } else if backlog > SOMAXCONN {
        SOMAXCONN
    } else {
        backlog
    };

    sock.state = SocketState::Listening;
    sock.backlog = clamped;
    Ok(())
}

/// Returns `true` if the accept queue has room for another connection.
///
/// Used by the TCP stack when a SYN arrives to decide whether to queue or
/// reject the connection.
pub fn accept_queue_has_room(sock: &ListenSocket) -> bool {
    sock.state == SocketState::Listening && sock.queued < sock.backlog
}

/// Simulate enqueueing a connection (called from TCP SYN handler).
///
/// Returns `Err(WouldBlock)` when the backlog is full.
pub fn enqueue_connection(sock: &mut ListenSocket) -> Result<()> {
    if sock.state != SocketState::Listening {
        return Err(Error::InvalidArgument);
    }
    if sock.queued >= sock.backlog {
        return Err(Error::WouldBlock);
    }
    sock.queued += 1;
    Ok(())
}

/// Simulate dequeueing a connection (called from `accept`).
///
/// Returns `Err(WouldBlock)` when the queue is empty.
pub fn dequeue_connection(sock: &mut ListenSocket) -> Result<()> {
    if sock.queued == 0 {
        return Err(Error::WouldBlock);
    }
    sock.queued -= 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listen_bound_stream_ok() {
        let mut s = ListenSocket::new_bound(SOCK_STREAM);
        assert!(do_listen(&mut s, 10).is_ok());
        assert_eq!(s.state, SocketState::Listening);
        assert_eq!(s.backlog, 10);
    }

    #[test]
    fn listen_clamps_backlog() {
        let mut s = ListenSocket::new_bound(SOCK_STREAM);
        assert!(do_listen(&mut s, 9999).is_ok());
        assert_eq!(s.backlog, SOMAXCONN);
    }

    #[test]
    fn listen_unbound_fails() {
        let mut s = ListenSocket {
            sock_type: SOCK_STREAM,
            state: SocketState::Unbound,
            backlog: 0,
            queued: 0,
        };
        assert_eq!(do_listen(&mut s, 5), Err(Error::InvalidArgument));
    }

    #[test]
    fn listen_dgram_fails() {
        let mut s = ListenSocket {
            sock_type: 2, // SOCK_DGRAM
            state: SocketState::Bound,
            backlog: 0,
            queued: 0,
        };
        assert_eq!(do_listen(&mut s, 5), Err(Error::NotImplemented));
    }

    #[test]
    fn backlog_full_rejects() {
        let mut s = ListenSocket::new_bound(SOCK_STREAM);
        do_listen(&mut s, 2).unwrap();
        enqueue_connection(&mut s).unwrap();
        enqueue_connection(&mut s).unwrap();
        assert_eq!(enqueue_connection(&mut s), Err(Error::WouldBlock));
    }
}
