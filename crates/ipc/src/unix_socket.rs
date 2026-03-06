// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Unix domain socket implementation.
//!
//! Provides local inter-process communication via stream and datagram
//! sockets, following the POSIX `AF_UNIX` / `AF_LOCAL` semantics.
//! Sockets are identified by filesystem-style path addresses (up to
//! 108 bytes, matching `struct sockaddr_un`).
//!
//! This is a kernel-internal implementation; the actual syscall layer
//! maps `socket(AF_UNIX, ...)`, `bind`, `listen`, `accept`, `connect`,
//! `send`, and `recv` onto these primitives.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum path length for a Unix socket address (matches `sockaddr_un.sun_path`).
const UNIX_PATH_MAX: usize = 108;

/// Data ring buffer size per socket (4 KiB).
const RING_BUFFER_SIZE: usize = 4096;

/// Maximum number of sockets in the registry.
const MAX_SOCKETS: usize = 64;

/// Maximum number of pending connections in a listen backlog.
const MAX_BACKLOG: usize = 8;

// ---------------------------------------------------------------------------
// SocketType
// ---------------------------------------------------------------------------

/// Type of a Unix domain socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketType {
    /// Connection-oriented byte stream (`SOCK_STREAM`).
    Stream,
    /// Connectionless datagram (`SOCK_DGRAM`).
    Datagram,
}

// ---------------------------------------------------------------------------
// SocketState
// ---------------------------------------------------------------------------

/// Lifecycle state of a Unix domain socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketState {
    /// Newly created, no address bound.
    Unbound,
    /// Bound to a local address.
    Bound,
    /// Listening for incoming connections (stream only).
    Listening,
    /// Connected to a peer.
    Connected,
    /// Socket has been closed.
    Closed,
}

// ---------------------------------------------------------------------------
// SocketAddr
// ---------------------------------------------------------------------------

/// A Unix domain socket address (path-based).
///
/// Mirrors `struct sockaddr_un` with a path of up to [`UNIX_PATH_MAX`]
/// bytes. The path is stored as raw bytes; a length field tracks the
/// actual number of valid bytes.
#[derive(Clone)]
pub struct SocketAddr {
    /// Raw path bytes.
    path: [u8; UNIX_PATH_MAX],
    /// Number of valid bytes in `path`.
    len: usize,
}

impl SocketAddr {
    /// Create an empty (unnamed) socket address.
    pub const fn empty() -> Self {
        Self {
            path: [0u8; UNIX_PATH_MAX],
            len: 0,
        }
    }

    /// Create a socket address from a byte slice.
    ///
    /// Returns `InvalidArgument` if the path is empty or exceeds
    /// [`UNIX_PATH_MAX`] bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > UNIX_PATH_MAX {
            return Err(Error::InvalidArgument);
        }
        let mut addr = Self::empty();
        addr.path[..bytes.len()].copy_from_slice(bytes);
        addr.len = bytes.len();
        Ok(addr)
    }

    /// Return the path as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.path[..self.len]
    }

    /// Return the length of the path in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Return `true` if the address is unnamed (zero-length path).
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl PartialEq for SocketAddr {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for SocketAddr {}

impl core::fmt::Debug for SocketAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SocketAddr")
            .field("len", &self.len)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// RingBuffer
// ---------------------------------------------------------------------------

/// Fixed-size ring buffer for socket data.
struct RingBuffer {
    /// Raw data storage.
    data: [u8; RING_BUFFER_SIZE],
    /// Write position.
    head: usize,
    /// Read position.
    tail: usize,
    /// Number of valid bytes.
    count: usize,
}

impl RingBuffer {
    /// Create an empty ring buffer.
    const fn new() -> Self {
        Self {
            data: [0u8; RING_BUFFER_SIZE],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    /// Write bytes into the buffer.
    ///
    /// Returns the number of bytes actually written (may be less than
    /// `src.len()` if the buffer is nearly full).
    fn write(&mut self, src: &[u8]) -> usize {
        let available = RING_BUFFER_SIZE - self.count;
        let to_write = src.len().min(available);

        for &byte in &src[..to_write] {
            self.data[self.head] = byte;
            self.head = (self.head + 1) % RING_BUFFER_SIZE;
        }
        self.count += to_write;
        to_write
    }

    /// Read bytes from the buffer into `dst`.
    ///
    /// Returns the number of bytes actually read (may be less than
    /// `dst.len()` if the buffer has fewer bytes available).
    fn read(&mut self, dst: &mut [u8]) -> usize {
        let to_read = dst.len().min(self.count);

        for slot in dst.iter_mut().take(to_read) {
            *slot = self.data[self.tail];
            self.tail = (self.tail + 1) % RING_BUFFER_SIZE;
        }
        self.count -= to_read;
        to_read
    }

    /// Return `true` if the buffer contains readable data.
    fn has_data(&self) -> bool {
        self.count > 0
    }

    /// Return `true` if the buffer has room for at least one more byte.
    fn has_space(&self) -> bool {
        self.count < RING_BUFFER_SIZE
    }
}

// ---------------------------------------------------------------------------
// ListenBacklog
// ---------------------------------------------------------------------------

/// Queue of pending connection requests for a listening socket.
///
/// Stores socket IDs of peers that have called `connect` but have not
/// yet been accepted. The maximum depth is [`MAX_BACKLOG`].
pub struct ListenBacklog {
    /// Pending peer socket IDs.
    pending: [u64; MAX_BACKLOG],
    /// Number of valid entries.
    count: usize,
}

impl ListenBacklog {
    /// Create an empty backlog queue.
    const fn new() -> Self {
        Self {
            pending: [0u64; MAX_BACKLOG],
            count: 0,
        }
    }

    /// Push a pending connection.
    ///
    /// Returns `WouldBlock` if the backlog is full.
    pub fn push(&mut self, peer_id: u64) -> Result<()> {
        if self.count >= MAX_BACKLOG {
            return Err(Error::WouldBlock);
        }
        self.pending[self.count] = peer_id;
        self.count += 1;
        Ok(())
    }

    /// Pop the oldest pending connection.
    ///
    /// Returns `WouldBlock` if no connections are pending.
    pub fn pop(&mut self) -> Result<u64> {
        if self.count == 0 {
            return Err(Error::WouldBlock);
        }
        let id = self.pending[0];
        // Shift remaining entries forward.
        let remaining = self.count - 1;
        for i in 0..remaining {
            self.pending[i] = self.pending[i + 1];
        }
        self.pending[remaining] = 0;
        self.count -= 1;
        Ok(id)
    }

    /// Return the number of pending connections.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if no connections are pending.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Return `true` if the backlog is at capacity.
    pub fn is_full(&self) -> bool {
        self.count >= MAX_BACKLOG
    }
}

// ---------------------------------------------------------------------------
// UnixSocket
// ---------------------------------------------------------------------------

/// A Unix domain socket.
///
/// Supports both stream (connection-oriented) and datagram
/// (connectionless) communication. Data is buffered in a 4 KiB ring
/// buffer. Stream sockets go through the full `bind` / `listen` /
/// `accept` / `connect` lifecycle; datagram sockets can send and
/// receive without establishing a connection.
pub struct UnixSocket {
    /// Socket type (stream or datagram).
    socket_type: SocketType,
    /// Current lifecycle state.
    state: SocketState,
    /// Local (bound) address, if any.
    local_addr: SocketAddr,
    /// Connected peer socket ID, if any.
    peer_id: Option<u64>,
    /// Data ring buffer.
    buffer: RingBuffer,
    /// Listen backlog (only meaningful in `Listening` state).
    backlog: ListenBacklog,
}

impl UnixSocket {
    /// Create a new, unbound socket of the given type.
    pub fn new(socket_type: SocketType) -> Self {
        Self {
            socket_type,
            state: SocketState::Unbound,
            local_addr: SocketAddr::empty(),
            peer_id: None,
            buffer: RingBuffer::new(),
            backlog: ListenBacklog::new(),
        }
    }

    /// Return the socket type.
    pub fn socket_type(&self) -> SocketType {
        self.socket_type
    }

    /// Return the current socket state.
    pub fn state(&self) -> SocketState {
        self.state
    }

    /// Return a reference to the local address.
    pub fn local_addr(&self) -> &SocketAddr {
        &self.local_addr
    }

    /// Return the connected peer's socket ID, if any.
    pub fn peer_id(&self) -> Option<u64> {
        self.peer_id
    }

    /// Bind the socket to a local address.
    ///
    /// The socket must be in the `Unbound` state. Returns
    /// `InvalidArgument` if the socket is already bound or the address
    /// is empty.
    pub fn bind(&mut self, addr: SocketAddr) -> Result<()> {
        if self.state != SocketState::Unbound {
            return Err(Error::InvalidArgument);
        }
        if addr.is_empty() {
            return Err(Error::InvalidArgument);
        }
        self.local_addr = addr;
        self.state = SocketState::Bound;
        Ok(())
    }

    /// Mark the socket as listening for incoming connections.
    ///
    /// Only valid for stream sockets in the `Bound` state.  The
    /// `_backlog` parameter is accepted for POSIX compatibility but
    /// the actual maximum is capped at [`MAX_BACKLOG`].
    pub fn listen(&mut self, _backlog: u32) -> Result<()> {
        if self.socket_type != SocketType::Stream {
            return Err(Error::InvalidArgument);
        }
        if self.state != SocketState::Bound {
            return Err(Error::InvalidArgument);
        }
        self.state = SocketState::Listening;
        Ok(())
    }

    /// Accept a pending connection from the listen backlog.
    ///
    /// Returns the socket ID of the connecting peer. The socket must
    /// be in the `Listening` state; returns `WouldBlock` if no
    /// connections are pending.
    pub fn accept(&mut self) -> Result<u64> {
        if self.state != SocketState::Listening {
            return Err(Error::InvalidArgument);
        }
        self.backlog.pop()
    }

    /// Enqueue a pending connection from `peer_id` into the backlog.
    ///
    /// Called internally by the registry when a peer connects to a
    /// listening socket. Returns `WouldBlock` if the backlog is full.
    pub fn enqueue_connection(&mut self, peer_id: u64) -> Result<()> {
        if self.state != SocketState::Listening {
            return Err(Error::InvalidArgument);
        }
        self.backlog.push(peer_id)
    }

    /// Connect to a peer socket (by peer socket ID).
    ///
    /// For stream sockets, the socket must be `Unbound` or `Bound`.
    /// For datagram sockets, connect simply records the default peer.
    pub fn connect(&mut self, peer_id: u64) -> Result<()> {
        match self.socket_type {
            SocketType::Stream => {
                if self.state != SocketState::Unbound && self.state != SocketState::Bound {
                    return Err(Error::InvalidArgument);
                }
            }
            SocketType::Datagram => {
                if self.state == SocketState::Closed {
                    return Err(Error::InvalidArgument);
                }
            }
        }
        self.peer_id = Some(peer_id);
        self.state = SocketState::Connected;
        Ok(())
    }

    /// Send data through the socket.
    ///
    /// The socket must be in the `Connected` state (or datagram with a
    /// default peer). Returns the number of bytes written into the
    /// ring buffer, or `WouldBlock` if the buffer is full.
    pub fn send(&mut self, data: &[u8]) -> Result<usize> {
        if self.state != SocketState::Connected {
            return Err(Error::InvalidArgument);
        }
        if data.is_empty() {
            return Ok(0);
        }
        if !self.buffer.has_space() {
            return Err(Error::WouldBlock);
        }
        Ok(self.buffer.write(data))
    }

    /// Receive data from the socket.
    ///
    /// Returns the number of bytes read into `buf`, or `WouldBlock`
    /// if no data is available.
    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.state != SocketState::Connected {
            return Err(Error::InvalidArgument);
        }
        if buf.is_empty() {
            return Ok(0);
        }
        if !self.buffer.has_data() {
            return Err(Error::WouldBlock);
        }
        Ok(self.buffer.read(buf))
    }

    /// Close the socket.
    ///
    /// After closing, no further operations are valid.
    pub fn close(&mut self) {
        self.state = SocketState::Closed;
        self.peer_id = None;
    }

    /// Return `true` if the socket has data available for reading.
    pub fn is_readable(&self) -> bool {
        self.state == SocketState::Connected && self.buffer.has_data()
    }

    /// Return `true` if the socket can accept data for writing.
    pub fn is_writable(&self) -> bool {
        self.state == SocketState::Connected && self.buffer.has_space()
    }
}

// ---------------------------------------------------------------------------
// UnixSocketRegistry
// ---------------------------------------------------------------------------

/// System-wide registry of Unix domain sockets.
///
/// Manages up to [`MAX_SOCKETS`] sockets, each identified by a unique
/// `u64` socket ID. The registry supports creation, lookup (by ID or
/// by bound address), and removal.
pub struct UnixSocketRegistry {
    /// Socket slots, indexed by position. The `u64` is the socket ID.
    slots: [(u64, Option<UnixSocket>); MAX_SOCKETS],
    /// Monotonically increasing ID counter.
    next_id: u64,
    /// Number of active sockets.
    count: usize,
}

impl Default for UnixSocketRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl UnixSocketRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        const EMPTY: (u64, Option<UnixSocket>) = (0, None);
        Self {
            slots: [EMPTY; MAX_SOCKETS],
            next_id: 1,
            count: 0,
        }
    }

    /// Create a new socket and return its unique ID.
    ///
    /// Returns `OutOfMemory` if the registry is full.
    pub fn create(&mut self, socket_type: SocketType) -> Result<u64> {
        if self.count >= MAX_SOCKETS {
            return Err(Error::OutOfMemory);
        }
        let id = self.next_id;
        for slot in self.slots.iter_mut() {
            if slot.1.is_none() {
                *slot = (id, Some(UnixSocket::new(socket_type)));
                self.next_id += 1;
                self.count += 1;
                return Ok(id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Look up a socket by ID.
    pub fn get(&self, id: u64) -> Option<&UnixSocket> {
        self.slots
            .iter()
            .find(|(sid, sock)| *sid == id && sock.is_some())
            .and_then(|(_, sock)| sock.as_ref())
    }

    /// Look up a mutable socket by ID.
    pub fn get_mut(&mut self, id: u64) -> Option<&mut UnixSocket> {
        self.slots
            .iter_mut()
            .find(|(sid, sock)| *sid == id && sock.is_some())
            .and_then(|(_, sock)| sock.as_mut())
    }

    /// Remove a socket by ID.
    ///
    /// Returns `NotFound` if the ID does not exist.
    pub fn remove(&mut self, id: u64) -> Result<()> {
        for slot in self.slots.iter_mut() {
            if slot.0 == id && slot.1.is_some() {
                slot.1 = None;
                slot.0 = 0;
                self.count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Find the socket ID bound to a given address.
    ///
    /// Returns `None` if no socket is bound to that address.
    pub fn find_by_addr(&self, addr: &SocketAddr) -> Option<u64> {
        self.slots
            .iter()
            .find(|(_, sock)| sock.as_ref().is_some_and(|s| s.local_addr() == addr))
            .map(|(id, _)| *id)
    }

    /// Return the number of active sockets.
    pub fn count(&self) -> usize {
        self.count
    }
}
