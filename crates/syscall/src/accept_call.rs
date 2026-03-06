// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `accept(2)` and `accept4(2)` syscall handlers.
//!
//! `accept` extracts the first pending connection from a listening socket's
//! accept queue and creates a new connected socket.  It returns a file
//! descriptor for the new socket.
//!
//! `accept4` is the Linux extension that allows setting `SOCK_NONBLOCK` and
//! `SOCK_CLOEXEC` on the accepted socket atomically, without a subsequent
//! `fcntl` call.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `accept()` specification.  `accept4` is a Linux
//! extension (not in POSIX).
//!
//! Key behaviours:
//! - The listening socket must have been bound with `bind(2)` and put into
//!   the listening state with `listen(2)`.
//! - On success, the kernel fills in the peer's address if `addr_out` is
//!   non-null; the `addrlen` field is updated to reflect the actual length.
//! - `EAGAIN` / `EWOULDBLOCK` is returned when no connections are queued and
//!   the socket is non-blocking.
//! - `accept` does not inherit the non-blocking flag from the listening
//!   socket; the accepted socket starts in blocking mode.
//! - `accept4` with `SOCK_NONBLOCK` sets the new socket as non-blocking.
//! - `accept4` with `SOCK_CLOEXEC` sets `FD_CLOEXEC` on the new fd.
//!
//! # References
//!
//! - POSIX.1-2024: `accept()`
//! - Linux man pages: `accept(2)`, `accept4(2)`
//! - Linux source: `net/socket.c` (`__sys_accept4`)

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of file descriptors per process.
const MAX_OPEN_FDS: usize = 1024;

/// Maximum pending connection queue depth (backlog limit for simulation).
pub const MAX_BACKLOG: usize = 128;

/// Flag: set `O_NONBLOCK` on the accepted socket.
pub const SOCK_NONBLOCK: i32 = 0x800;
/// Flag: set `FD_CLOEXEC` on the accepted socket fd.
pub const SOCK_CLOEXEC: i32 = 0x80000;

/// Valid `accept4` flag bits.
const ACCEPT4_VALID_FLAGS: i32 = SOCK_NONBLOCK | SOCK_CLOEXEC;

// ---------------------------------------------------------------------------
// Address types
// ---------------------------------------------------------------------------

/// Address family identifier.
pub type SaFamily = u16;

/// Generic socket address storage large enough to hold any address type.
///
/// Mirrors `struct sockaddr_storage` from POSIX.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockaddrStorage {
    /// Address family.
    pub family: SaFamily,
    /// Opaque address data.
    pub data: [u8; 126],
}

impl Default for SockaddrStorage {
    fn default() -> Self {
        Self {
            family: 0,
            data: [0u8; 126],
        }
    }
}

impl SockaddrStorage {
    /// Construct a new storage with the given family.
    pub const fn with_family(family: SaFamily) -> Self {
        Self {
            family,
            data: [0u8; 126],
        }
    }
}

// ---------------------------------------------------------------------------
// Socket state model
// ---------------------------------------------------------------------------

/// The state of a socket in the listening pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketListenState {
    /// Socket is not yet bound.
    Unbound,
    /// Socket is bound to an address.
    Bound,
    /// Socket is listening for incoming connections.
    Listening,
    /// Socket has an active connection.
    Connected,
    /// Socket is closed.
    Closed,
}

/// A pending connection in the accept queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingConnection {
    /// Peer's remote address.
    pub peer_addr: SockaddrStorage,
    /// Peer's address length.
    pub peer_addr_len: u32,
}

/// A listening socket with an accept queue.
pub struct ListeningSocket {
    /// Address family of this socket.
    pub domain: i32,
    /// Socket type (base, without flags).
    pub sock_type: i32,
    /// Current listen state.
    pub state: SocketListenState,
    /// Non-blocking mode flag.
    pub nonblocking: bool,
    /// Pending connection queue.
    queue: [Option<PendingConnection>; MAX_BACKLOG],
    /// Number of connections currently in the queue.
    queue_len: usize,
    /// Write index (next slot to insert at).
    queue_tail: usize,
    /// Read index (next slot to dequeue from).
    queue_head: usize,
}

impl ListeningSocket {
    /// Create a new socket in the `Listening` state.
    pub fn new(domain: i32, sock_type: i32, nonblocking: bool) -> Self {
        Self {
            domain,
            sock_type,
            state: SocketListenState::Listening,
            nonblocking,
            queue: [const { None }; MAX_BACKLOG],
            queue_len: 0,
            queue_tail: 0,
            queue_head: 0,
        }
    }

    /// Enqueue a pending connection (simulates a client connecting).
    ///
    /// Returns `Err(WouldBlock)` if the backlog queue is full.
    pub fn enqueue(&mut self, conn: PendingConnection) -> Result<()> {
        if self.queue_len >= MAX_BACKLOG {
            return Err(Error::WouldBlock);
        }
        self.queue[self.queue_tail] = Some(conn);
        self.queue_tail = (self.queue_tail + 1) % MAX_BACKLOG;
        self.queue_len += 1;
        Ok(())
    }

    /// Dequeue the front-most pending connection.
    ///
    /// Returns `None` if the queue is empty.
    fn dequeue(&mut self) -> Option<PendingConnection> {
        if self.queue_len == 0 {
            return None;
        }
        let conn = self.queue[self.queue_head].take();
        self.queue_head = (self.queue_head + 1) % MAX_BACKLOG;
        self.queue_len -= 1;
        conn
    }

    /// Return the number of connections currently queued.
    pub const fn pending_count(&self) -> usize {
        self.queue_len
    }
}

// ---------------------------------------------------------------------------
// Accepted socket descriptor
// ---------------------------------------------------------------------------

/// Describes a newly accepted socket file descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptedSocket {
    /// The new file descriptor number.
    pub fd: i32,
    /// Address family of the new socket.
    pub domain: i32,
    /// Base socket type of the new socket.
    pub sock_type: i32,
    /// Whether `O_NONBLOCK` is set on the new socket.
    pub nonblocking: bool,
    /// Whether `FD_CLOEXEC` is set on the new socket fd.
    pub cloexec: bool,
    /// Peer address returned to the caller.
    pub peer_addr: SockaddrStorage,
    /// Actual length of the peer address.
    pub peer_addr_len: u32,
}

// ---------------------------------------------------------------------------
// Fd allocator (minimal)
// ---------------------------------------------------------------------------

/// Minimal file descriptor allocator for tracking accepted socket fds.
pub struct AcceptFdAllocator {
    used: [bool; MAX_OPEN_FDS],
    count: usize,
}

impl AcceptFdAllocator {
    /// Create an empty allocator.
    pub const fn new() -> Self {
        Self {
            used: [false; MAX_OPEN_FDS],
            count: 0,
        }
    }

    /// Allocate the lowest-numbered free slot.
    fn alloc(&mut self) -> Result<usize> {
        let idx = self
            .used
            .iter()
            .position(|&u| !u)
            .ok_or(Error::OutOfMemory)?;
        self.used[idx] = true;
        self.count += 1;
        Ok(idx)
    }

    /// Free a slot.
    ///
    /// Returns `Err(NotFound)` if the slot was not allocated.
    pub fn free(&mut self, fd: usize) -> Result<()> {
        if fd >= MAX_OPEN_FDS || !self.used[fd] {
            return Err(Error::NotFound);
        }
        self.used[fd] = false;
        self.count -= 1;
        Ok(())
    }

    /// Return the number of allocated file descriptors.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Return whether fd `n` is allocated.
    pub fn is_allocated(&self, n: usize) -> bool {
        n < MAX_OPEN_FDS && self.used[n]
    }
}

// ---------------------------------------------------------------------------
// Core handlers
// ---------------------------------------------------------------------------

/// Handler for `accept(2)`.
///
/// Dequeues the first pending connection from the listening socket and
/// returns a new file descriptor for the accepted socket.  If no connection
/// is pending and the socket is non-blocking, returns `WouldBlock`.
///
/// # Arguments
///
/// * `sock`  — The listening socket.
/// * `alloc` — File descriptor allocator for the calling process.
///
/// # Errors
///
/// - `Error::InvalidArgument` — `sock` is not in the `Listening` state (`EINVAL`).
/// - `Error::WouldBlock` — No pending connections and socket is non-blocking
///   (`EAGAIN` / `EWOULDBLOCK`).
/// - `Error::OutOfMemory` — No free file descriptor slots (`EMFILE`).
///
/// # POSIX conformance
///
/// The accepted socket inherits the address family and socket type from
/// the listening socket.  `O_NONBLOCK` is NOT inherited from the listening
/// socket.  `FD_CLOEXEC` is NOT set (use `accept4` for atomic setting).
pub fn do_accept(
    sock: &mut ListeningSocket,
    alloc: &mut AcceptFdAllocator,
) -> Result<AcceptedSocket> {
    do_accept4(sock, alloc, 0)
}

/// Handler for `accept4(2)`.
///
/// Like `accept`, but allows setting `SOCK_NONBLOCK` and/or `SOCK_CLOEXEC`
/// on the new socket fd atomically via the `flags` argument.
///
/// # Arguments
///
/// * `sock`  — The listening socket.
/// * `alloc` — File descriptor allocator for the calling process.
/// * `flags` — Combination of `SOCK_NONBLOCK` and/or `SOCK_CLOEXEC`.
///
/// # Errors
///
/// - `Error::InvalidArgument` — Unknown flag bits set or socket not listening
///   (`EINVAL`).
/// - `Error::WouldBlock` — No pending connections and socket is non-blocking
///   (`EAGAIN` / `EWOULDBLOCK`).
/// - `Error::OutOfMemory` — No free file descriptor slots (`EMFILE`).
///
/// # Linux conformance
///
/// `accept4` was added in Linux 2.6.28 to avoid a race condition in
/// multi-threaded servers that need `O_CLOEXEC` on accepted fds.
pub fn do_accept4(
    sock: &mut ListeningSocket,
    alloc: &mut AcceptFdAllocator,
    flags: i32,
) -> Result<AcceptedSocket> {
    // Reject unknown flags.
    if flags & !ACCEPT4_VALID_FLAGS != 0 {
        return Err(Error::InvalidArgument);
    }

    // Socket must be in the listening state.
    if sock.state != SocketListenState::Listening {
        return Err(Error::InvalidArgument);
    }

    // Dequeue a pending connection.
    let conn = match sock.dequeue() {
        Some(c) => c,
        None => {
            // No connections pending.
            if sock.nonblocking {
                return Err(Error::WouldBlock);
            }
            // In a real kernel, we would sleep on the wait queue.
            return Err(Error::WouldBlock);
        }
    };

    let nonblocking = flags & SOCK_NONBLOCK != 0;
    let cloexec = flags & SOCK_CLOEXEC != 0;

    let fd = alloc.alloc()? as i32;

    Ok(AcceptedSocket {
        fd,
        domain: sock.domain,
        sock_type: sock.sock_type,
        nonblocking,
        cloexec,
        peer_addr: conn.peer_addr,
        peer_addr_len: conn.peer_addr_len,
    })
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const AF_INET: i32 = 2;
    const SOCK_STREAM: i32 = 1;

    fn make_peer() -> PendingConnection {
        let mut addr = SockaddrStorage::with_family(AF_INET as u16);
        addr.data[0] = 127;
        addr.data[1] = 0;
        addr.data[2] = 0;
        addr.data[3] = 1;
        PendingConnection {
            peer_addr: addr,
            peer_addr_len: 16,
        }
    }

    fn listening_sock() -> ListeningSocket {
        ListeningSocket::new(AF_INET, SOCK_STREAM, false)
    }

    fn nb_listening_sock() -> ListeningSocket {
        ListeningSocket::new(AF_INET, SOCK_STREAM, true)
    }

    // --- basic accept ---

    #[test]
    fn accept_returns_new_fd() {
        let mut sock = listening_sock();
        sock.enqueue(make_peer()).unwrap();
        let mut alloc = AcceptFdAllocator::new();
        let accepted = do_accept(&mut sock, &mut alloc).unwrap();
        assert_eq!(accepted.fd, 0);
        assert_eq!(accepted.domain, AF_INET);
        assert_eq!(accepted.sock_type, SOCK_STREAM);
        assert!(!accepted.nonblocking);
        assert!(!accepted.cloexec);
    }

    #[test]
    fn accept_returns_peer_address() {
        let mut sock = listening_sock();
        let peer = make_peer();
        sock.enqueue(peer).unwrap();
        let mut alloc = AcceptFdAllocator::new();
        let accepted = do_accept(&mut sock, &mut alloc).unwrap();
        assert_eq!(accepted.peer_addr, peer.peer_addr);
        assert_eq!(accepted.peer_addr_len, 16);
    }

    #[test]
    fn accept_multiple_connections() {
        let mut sock = listening_sock();
        sock.enqueue(make_peer()).unwrap();
        sock.enqueue(make_peer()).unwrap();
        let mut alloc = AcceptFdAllocator::new();
        let a0 = do_accept(&mut sock, &mut alloc).unwrap();
        let a1 = do_accept(&mut sock, &mut alloc).unwrap();
        assert_eq!(a0.fd, 0);
        assert_eq!(a1.fd, 1);
        assert_eq!(sock.pending_count(), 0);
    }

    #[test]
    fn accept_drains_queue_fifo() {
        let mut sock = listening_sock();
        let mut peer0 = SockaddrStorage::with_family(AF_INET as u16);
        peer0.data[0] = 10;
        let mut peer1 = SockaddrStorage::with_family(AF_INET as u16);
        peer1.data[0] = 20;
        sock.enqueue(PendingConnection {
            peer_addr: peer0,
            peer_addr_len: 16,
        })
        .unwrap();
        sock.enqueue(PendingConnection {
            peer_addr: peer1,
            peer_addr_len: 16,
        })
        .unwrap();
        let mut alloc = AcceptFdAllocator::new();
        let a0 = do_accept(&mut sock, &mut alloc).unwrap();
        let a1 = do_accept(&mut sock, &mut alloc).unwrap();
        assert_eq!(a0.peer_addr.data[0], 10);
        assert_eq!(a1.peer_addr.data[0], 20);
    }

    // --- accept on empty queue ---

    #[test]
    fn accept_nonblocking_returns_would_block() {
        let mut sock = nb_listening_sock();
        let mut alloc = AcceptFdAllocator::new();
        assert_eq!(do_accept(&mut sock, &mut alloc), Err(Error::WouldBlock));
    }

    #[test]
    fn accept_blocking_returns_would_block_when_empty() {
        let mut sock = listening_sock();
        let mut alloc = AcceptFdAllocator::new();
        // Simulated: blocking socket with no connections also returns WouldBlock
        // (real kernel would sleep).
        assert_eq!(do_accept(&mut sock, &mut alloc), Err(Error::WouldBlock));
    }

    // --- accept4 flags ---

    #[test]
    fn accept4_sets_nonblock() {
        let mut sock = listening_sock();
        sock.enqueue(make_peer()).unwrap();
        let mut alloc = AcceptFdAllocator::new();
        let a = do_accept4(&mut sock, &mut alloc, SOCK_NONBLOCK).unwrap();
        assert!(a.nonblocking);
        assert!(!a.cloexec);
    }

    #[test]
    fn accept4_sets_cloexec() {
        let mut sock = listening_sock();
        sock.enqueue(make_peer()).unwrap();
        let mut alloc = AcceptFdAllocator::new();
        let a = do_accept4(&mut sock, &mut alloc, SOCK_CLOEXEC).unwrap();
        assert!(a.cloexec);
        assert!(!a.nonblocking);
    }

    #[test]
    fn accept4_sets_both_flags() {
        let mut sock = listening_sock();
        sock.enqueue(make_peer()).unwrap();
        let mut alloc = AcceptFdAllocator::new();
        let a = do_accept4(&mut sock, &mut alloc, SOCK_NONBLOCK | SOCK_CLOEXEC).unwrap();
        assert!(a.nonblocking);
        assert!(a.cloexec);
    }

    #[test]
    fn accept4_rejects_unknown_flags() {
        let mut sock = listening_sock();
        sock.enqueue(make_peer()).unwrap();
        let mut alloc = AcceptFdAllocator::new();
        assert_eq!(
            do_accept4(&mut sock, &mut alloc, 0xFF),
            Err(Error::InvalidArgument)
        );
    }

    // --- not listening ---

    #[test]
    fn accept_on_non_listening_socket_returns_einval() {
        let mut sock = ListeningSocket::new(AF_INET, SOCK_STREAM, false);
        sock.state = SocketListenState::Bound;
        let mut alloc = AcceptFdAllocator::new();
        assert_eq!(
            do_accept(&mut sock, &mut alloc),
            Err(Error::InvalidArgument)
        );
    }

    // --- backlog full ---

    #[test]
    fn enqueue_fails_when_backlog_full() {
        let mut sock = listening_sock();
        for _ in 0..MAX_BACKLOG {
            sock.enqueue(make_peer()).unwrap();
        }
        assert_eq!(sock.enqueue(make_peer()), Err(Error::WouldBlock));
    }
}
