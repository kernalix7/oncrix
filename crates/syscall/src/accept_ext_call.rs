// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `accept(2)` / `accept4(2)` extended validation and peer-address extraction.
//!
//! Provides flag validation, listening-state checks, and peer address
//! construction helpers for socket accept operations.  The entry shims are
//! in `accept_call.rs` and `accept4_call.rs`; this module provides the
//! shared validation and state management logic.
//!
//! # Syscall signatures
//!
//! ```text
//! int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
//! int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
//! ```
//!
//! # POSIX reference
//!
//! POSIX.1-2024 §accept — `<sys/socket.h>`.
//! `accept4` is a Linux extension (not yet in POSIX.1-2024).
//!
//! # References
//!
//! - Linux: `net/socket.c` `__sys_accept4()`
//! - `accept(2)`, `accept4(2)` man pages

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Flag constants for accept4
// ---------------------------------------------------------------------------

/// Set `O_NONBLOCK` on the new socket.
pub const SOCK_NONBLOCK: i32 = 0x0000_0800;
/// Set `O_CLOEXEC` on the new socket.
pub const SOCK_CLOEXEC: i32 = 0x0008_0000;

/// Mask of all recognised accept4 flags.
const ACCEPT4_FLAGS_KNOWN: i32 = SOCK_NONBLOCK | SOCK_CLOEXEC;

// ---------------------------------------------------------------------------
// AcceptFlags — validated flags
// ---------------------------------------------------------------------------

/// Validated `accept4` flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AcceptFlags {
    /// Set `O_NONBLOCK` on the accepted fd.
    pub nonblock: bool,
    /// Set `O_CLOEXEC` on the accepted fd.
    pub cloexec: bool,
}

impl AcceptFlags {
    /// Parse raw flags.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] for unknown bits.
    pub fn from_raw(raw: i32) -> Result<Self> {
        if raw & !ACCEPT4_FLAGS_KNOWN != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            nonblock: raw & SOCK_NONBLOCK != 0,
            cloexec: raw & SOCK_CLOEXEC != 0,
        })
    }
}

// ---------------------------------------------------------------------------
// ListenState — socket listening state
// ---------------------------------------------------------------------------

/// State of a server socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenState {
    /// Not listening.
    Idle,
    /// Bound but not yet listening.
    Bound,
    /// Listening; connections may be accepted.
    Listening { backlog: u32 },
    /// Closed.
    Closed,
}

// ---------------------------------------------------------------------------
// PendingConnection — an accepted connection waiting to be taken
// ---------------------------------------------------------------------------

/// A connection pending on the accept queue.
#[derive(Debug, Clone, Copy)]
pub struct PendingConnection {
    /// Peer IPv4 address (big-endian).
    pub peer_addr: u32,
    /// Peer port (big-endian).
    pub peer_port: u16,
    /// Whether the peer is connected via IPv6.
    pub is_ipv6: bool,
}

// ---------------------------------------------------------------------------
// AcceptQueue — per-socket connection backlog
// ---------------------------------------------------------------------------

/// Maximum backlog depth.
const MAX_BACKLOG: usize = 128;

/// Accept queue for a listening socket.
pub struct AcceptQueue {
    connections: [Option<PendingConnection>; MAX_BACKLOG],
    head: usize,
    tail: usize,
    count: usize,
}

impl AcceptQueue {
    /// Create an empty queue.
    pub const fn new() -> Self {
        Self {
            connections: [const { None }; MAX_BACKLOG],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    /// Enqueue an incoming connection.
    ///
    /// # Errors
    ///
    /// [`Error::Busy`] if the backlog is full.
    pub fn push(&mut self, conn: PendingConnection) -> Result<()> {
        if self.count >= MAX_BACKLOG {
            return Err(Error::Busy);
        }
        self.connections[self.tail] = Some(conn);
        self.tail = (self.tail + 1) % MAX_BACKLOG;
        self.count += 1;
        Ok(())
    }

    /// Dequeue the next pending connection (FIFO).
    pub fn pop(&mut self) -> Option<PendingConnection> {
        if self.count == 0 {
            return None;
        }
        let conn = self.connections[self.head].take();
        self.head = (self.head + 1) % MAX_BACKLOG;
        self.count -= 1;
        conn
    }

    /// Return the number of pending connections.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if no connections are pending.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for AcceptQueue {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// AcceptRecord — per-listening-socket record
// ---------------------------------------------------------------------------

/// Record for a listening socket.
pub struct AcceptRecord {
    /// Socket file descriptor.
    pub sockfd: i32,
    /// Current state.
    pub state: ListenState,
    /// Pending connections.
    pub queue: AcceptQueue,
    /// Next fd to allocate for accepted connections.
    next_fd: i32,
}

impl AcceptRecord {
    /// Create an idle record.
    pub const fn new(sockfd: i32) -> Self {
        Self {
            sockfd,
            state: ListenState::Idle,
            queue: AcceptQueue::new(),
            next_fd: 100,
        }
    }

    /// Allocate an fd for an accepted connection.
    pub fn alloc_accepted_fd(&mut self) -> i32 {
        let fd = self.next_fd;
        self.next_fd = self.next_fd.saturating_add(1);
        fd
    }
}

// ---------------------------------------------------------------------------
// sys_accept_ext — extended accept implementation
// ---------------------------------------------------------------------------

/// Extended `accept4` handler.
///
/// Validates flags and dequeues the next pending connection from `record`.
///
/// # Arguments
///
/// * `record` — Listening socket record.
/// * `flags`  — Raw `accept4` flags.
///
/// # Returns
///
/// `Ok((new_fd, PendingConnection, AcceptFlags))` on success.
///
/// # Errors
///
/// * [`Error::InvalidArgument`]  — unknown flags or socket not listening.
/// * [`Error::WouldBlock`]       — no connection pending.
pub fn sys_accept_ext(
    record: &mut AcceptRecord,
    flags_raw: i32,
) -> Result<(i32, PendingConnection, AcceptFlags)> {
    let flags = AcceptFlags::from_raw(flags_raw)?;

    if !matches!(record.state, ListenState::Listening { .. }) {
        return Err(Error::InvalidArgument);
    }

    let conn = record.queue.pop().ok_or(Error::WouldBlock)?;
    let new_fd = record.alloc_accepted_fd();
    Ok((new_fd, conn, flags))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record() -> AcceptRecord {
        let mut r = AcceptRecord::new(3);
        r.state = ListenState::Listening { backlog: 5 };
        r
    }

    fn conn(ip: u32) -> PendingConnection {
        PendingConnection {
            peer_addr: ip,
            peer_port: 12345,
            is_ipv6: false,
        }
    }

    #[test]
    fn accept_connection() {
        let mut r = make_record();
        r.queue.push(conn(0x0100_007F)).unwrap(); // 127.0.0.1
        let (fd, c, flags) = sys_accept_ext(&mut r, 0).unwrap();
        assert!(fd >= 0);
        assert_eq!(c.peer_addr, 0x0100_007F);
        assert!(!flags.nonblock);
    }

    #[test]
    fn accept_with_flags() {
        let mut r = make_record();
        r.queue.push(conn(0x0100_007F)).unwrap();
        let (_, _, flags) = sys_accept_ext(&mut r, SOCK_NONBLOCK | SOCK_CLOEXEC).unwrap();
        assert!(flags.nonblock);
        assert!(flags.cloexec);
    }

    #[test]
    fn no_connection_would_block() {
        let mut r = make_record();
        assert_eq!(sys_accept_ext(&mut r, 0), Err(Error::WouldBlock));
    }

    #[test]
    fn not_listening() {
        let mut r = AcceptRecord::new(3);
        r.queue.push(conn(1)).unwrap();
        assert_eq!(sys_accept_ext(&mut r, 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn unknown_flags_rejected() {
        let mut r = make_record();
        assert_eq!(sys_accept_ext(&mut r, 0x0001), Err(Error::InvalidArgument));
    }

    #[test]
    fn queue_fifo_order() {
        let mut q = AcceptQueue::new();
        q.push(conn(1)).unwrap();
        q.push(conn(2)).unwrap();
        assert_eq!(q.pop().unwrap().peer_addr, 1);
        assert_eq!(q.pop().unwrap().peer_addr, 2);
    }

    #[test]
    fn multiple_accepted_unique_fds() {
        let mut r = make_record();
        r.queue.push(conn(1)).unwrap();
        r.queue.push(conn(2)).unwrap();
        let (fd1, _, _) = sys_accept_ext(&mut r, 0).unwrap();
        let (fd2, _, _) = sys_accept_ext(&mut r, 0).unwrap();
        assert_ne!(fd1, fd2);
    }
}
