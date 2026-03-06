// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Unix domain socket abstraction layer for the ONCRIX kernel.
//!
//! Provides kernel-level Unix domain socket primitives with real data
//! transfer via ring buffers. This module implements the full socket
//! lifecycle: create, bind, listen, accept, connect, send, recv,
//! close, shutdown, and socketpair.
//!
//! # Data flow
//!
//! Each socket owns a receive ring buffer (4 KiB). For connected
//! stream sockets, `send` writes into the **peer's** buffer and
//! `recv` reads from the **local** buffer. This avoids the need for
//! a shared buffer between two sockets.
//!
//! # Non-blocking semantics
//!
//! All I/O operations are non-blocking. `send` returns `WouldBlock`
//! when the peer's buffer is full; `recv` returns `WouldBlock` when
//! the local buffer is empty. Sending to a closed peer returns
//! `IoError` (representing `EPIPE` / broken pipe).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Ring buffer capacity in bytes (4 KiB, matching `PIPE_BUF`).
const BUFFER_SIZE: usize = 4096;

/// Maximum path length for a Unix socket address (`sun_path`).
const UNIX_PATH_MAX: usize = 108;

/// Maximum number of sockets in the registry.
const MAX_SOCKETS: usize = 128;

/// Maximum number of pending connections in a listen backlog.
const MAX_BACKLOG: usize = 16;

// -------------------------------------------------------------------
// UnixSocketType
// -------------------------------------------------------------------

/// Type of a Unix domain socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UnixSocketType {
    /// Connection-oriented byte stream (`SOCK_STREAM`).
    #[default]
    Stream,
    /// Connectionless datagram (`SOCK_DGRAM`).
    Dgram,
    /// Connection-oriented, message-preserving (`SOCK_SEQPACKET`).
    SeqPacket,
}

// -------------------------------------------------------------------
// UnixAddr
// -------------------------------------------------------------------

/// Unix domain socket address, matching `struct sockaddr_un`.
///
/// Contains a filesystem path of up to [`UNIX_PATH_MAX`] (108)
/// bytes. The `len` field records how many bytes of `path` are
/// valid.
#[derive(Clone, Copy)]
pub struct UnixAddr {
    /// Socket path (null-padded, up to 108 bytes).
    pub path: [u8; UNIX_PATH_MAX],
    /// Number of valid bytes in `path`.
    pub len: u8,
}

impl Default for UnixAddr {
    fn default() -> Self {
        Self {
            path: [0u8; UNIX_PATH_MAX],
            len: 0,
        }
    }
}

impl UnixAddr {
    /// Create a new address from a byte slice.
    ///
    /// Returns `InvalidArgument` if `src` is empty or exceeds
    /// [`UNIX_PATH_MAX`] bytes.
    pub fn from_bytes(src: &[u8]) -> Result<Self> {
        if src.is_empty() || src.len() > UNIX_PATH_MAX {
            return Err(Error::InvalidArgument);
        }
        let mut addr = Self::default();
        addr.path[..src.len()].copy_from_slice(src);
        addr.len = src.len() as u8;
        Ok(addr)
    }

    /// Return the valid path bytes as a slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.path[..self.len as usize]
    }

    /// Return `true` if this address has no path set.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

// -------------------------------------------------------------------
// UnixSocketState
// -------------------------------------------------------------------

/// Lifecycle state of a Unix domain socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UnixSocketState {
    /// Newly created, no address bound.
    #[default]
    Unbound,
    /// Bound to a local path address.
    Bound,
    /// Listening for incoming connections (stream/seqpacket only).
    Listening,
    /// Connected to a peer.
    Connected,
    /// Socket has been closed.
    Closed,
}

// -------------------------------------------------------------------
// UnixSocketBuffer
// -------------------------------------------------------------------

/// Fixed-size ring buffer for socket data transfer.
///
/// Implements a circular byte buffer of [`BUFFER_SIZE`] bytes.
/// Supports partial writes and reads: callers receive the actual
/// number of bytes transferred, which may be less than requested
/// when the buffer is nearly full or nearly empty.
pub struct UnixSocketBuffer {
    /// Raw data storage.
    data: [u8; BUFFER_SIZE],
    /// Read position (next byte will be read from here).
    read_pos: usize,
    /// Write position (next byte will be written here).
    write_pos: usize,
    /// Number of valid bytes currently in the buffer.
    count: usize,
}

impl Default for UnixSocketBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl UnixSocketBuffer {
    /// Create an empty ring buffer.
    pub const fn new() -> Self {
        Self {
            data: [0u8; BUFFER_SIZE],
            read_pos: 0,
            write_pos: 0,
            count: 0,
        }
    }

    /// Write data into the buffer.
    ///
    /// Returns the number of bytes actually written, which may be
    /// less than `data.len()` if the buffer does not have enough
    /// free space. Returns `WouldBlock` if the buffer is completely
    /// full and no bytes can be written.
    pub fn write(&mut self, data: &[u8]) -> Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        let free = self.space();
        if free == 0 {
            return Err(Error::WouldBlock);
        }
        let to_write = data.len().min(free);

        for &byte in &data[..to_write] {
            self.data[self.write_pos] = byte;
            self.write_pos = (self.write_pos + 1) % BUFFER_SIZE;
        }
        self.count += to_write;
        Ok(to_write)
    }

    /// Read data from the buffer into `buf`.
    ///
    /// Returns the number of bytes actually read, which may be less
    /// than `buf.len()` if the buffer has fewer bytes available.
    /// Returns `WouldBlock` if the buffer is empty and no bytes can
    /// be read.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.count == 0 {
            return Err(Error::WouldBlock);
        }
        let to_read = buf.len().min(self.count);

        for slot in buf.iter_mut().take(to_read) {
            *slot = self.data[self.read_pos];
            self.read_pos = (self.read_pos + 1) % BUFFER_SIZE;
        }
        self.count -= to_read;
        Ok(to_read)
    }

    /// Return the number of bytes available for reading.
    pub fn available(&self) -> usize {
        self.count
    }

    /// Return the number of bytes of free space for writing.
    pub fn space(&self) -> usize {
        BUFFER_SIZE - self.count
    }

    /// Return `true` if the buffer contains no data.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Return `true` if the buffer is completely full.
    pub fn is_full(&self) -> bool {
        self.count >= BUFFER_SIZE
    }
}

// -------------------------------------------------------------------
// UnixSocket
// -------------------------------------------------------------------

/// A Unix domain socket with actual data transfer capability.
///
/// Each socket owns a receive ring buffer. For connected sockets,
/// the `send` path writes into the **peer's** buffer (via the
/// registry), and `recv` reads from the **local** buffer.
pub struct UnixSocket {
    /// Unique socket identifier.
    pub id: u64,
    /// Socket type (stream, datagram, or seqpacket).
    pub socket_type: UnixSocketType,
    /// Current lifecycle state.
    pub state: UnixSocketState,
    /// Bound address.
    pub addr: UnixAddr,
    /// Connected peer's socket ID.
    pub peer_id: Option<u64>,
    /// Receive ring buffer (data written by peer, read by us).
    pub buffer: UnixSocketBuffer,
    /// Pending connection backlog (IDs of connecting sockets).
    pub backlog: [u64; MAX_BACKLOG],
    /// Number of pending connections in the backlog.
    pub backlog_count: usize,
    /// PID of the process that owns this socket.
    pub owner_pid: u64,
}

impl UnixSocket {
    /// Create a new, unbound socket of the given type.
    pub const fn new(id: u64, socket_type: UnixSocketType, owner_pid: u64) -> Self {
        Self {
            id,
            socket_type,
            state: UnixSocketState::Unbound,
            addr: UnixAddr {
                path: [0u8; UNIX_PATH_MAX],
                len: 0,
            },
            peer_id: None,
            buffer: UnixSocketBuffer::new(),
            backlog: [0u64; MAX_BACKLOG],
            backlog_count: 0,
            owner_pid,
        }
    }
}

// -------------------------------------------------------------------
// ShutdownHow
// -------------------------------------------------------------------

/// Shutdown mode for [`UnixSocketRegistry::shutdown`].
///
/// Corresponds to the `how` argument of `shutdown(2)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownHow {
    /// Shut down the read half (`SHUT_RD`).
    Read = 0,
    /// Shut down the write half (`SHUT_WR`).
    Write = 1,
    /// Shut down both halves (`SHUT_RDWR`).
    Both = 2,
}

impl ShutdownHow {
    /// Convert a raw integer to a [`ShutdownHow`].
    ///
    /// Returns `InvalidArgument` for unrecognised values.
    pub fn from_raw(v: i32) -> Result<Self> {
        match v {
            0 => Ok(Self::Read),
            1 => Ok(Self::Write),
            2 => Ok(Self::Both),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// -------------------------------------------------------------------
// UnixSocketRegistry
// -------------------------------------------------------------------

/// Registry managing up to [`MAX_SOCKETS`] Unix domain sockets.
///
/// Provides the full socket lifecycle: socket, bind, listen, accept,
/// connect, send, recv, close, socketpair, and shutdown. Socket IDs
/// are monotonically increasing `u64` values; internally each socket
/// occupies a slot in a fixed-size array.
pub struct UnixSocketRegistry {
    /// Socket slots.
    slots: [Option<UnixSocket>; MAX_SOCKETS],
    /// Monotonically increasing ID counter.
    next_id: u64,
}

impl Default for UnixSocketRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl UnixSocketRegistry {
    /// Create an empty registry with no sockets.
    pub const fn new() -> Self {
        const NONE: Option<UnixSocket> = None;
        Self {
            slots: [NONE; MAX_SOCKETS],
            next_id: 1,
        }
    }

    // -- helpers ----------------------------------------------------

    /// Find a free slot and return its index.
    fn alloc_slot(&self) -> Result<usize> {
        self.slots
            .iter()
            .position(Option::is_none)
            .ok_or(Error::OutOfMemory)
    }

    /// Find the slot index of a socket by its unique ID.
    fn slot_of(&self, id: u64) -> Result<usize> {
        self.slots
            .iter()
            .position(|s| matches!(s, Some(sock) if sock.id == id))
            .ok_or(Error::NotFound)
    }

    /// Return a reference to the socket with the given ID.
    pub fn get(&self, id: u64) -> Option<&UnixSocket> {
        self.slots.iter().flatten().find(|s| s.id == id)
    }

    /// Return a mutable reference to the socket with the given ID.
    fn get_mut(&mut self, id: u64) -> Result<&mut UnixSocket> {
        self.slots
            .iter_mut()
            .flatten()
            .find(|s| s.id == id)
            .ok_or(Error::NotFound)
    }

    /// Find the ID of a socket bound to the given address.
    fn find_by_addr(&self, addr: &UnixAddr) -> Option<u64> {
        let needle = addr.as_bytes();
        self.slots
            .iter()
            .flatten()
            .find(|sock| !sock.addr.is_empty() && sock.addr.as_bytes() == needle)
            .map(|sock| sock.id)
    }

    // -- public API -------------------------------------------------

    /// Return the number of active sockets in the registry.
    pub fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }

    /// Return `true` when no sockets are active.
    pub fn is_empty(&self) -> bool {
        self.slots.iter().all(Option::is_none)
    }

    /// Create a new socket of the given type, owned by `pid`.
    ///
    /// Returns the socket's unique ID on success, or `OutOfMemory`
    /// if the registry is full.
    pub fn socket(&mut self, sock_type: UnixSocketType, pid: u64) -> Result<u64> {
        let slot = self.alloc_slot()?;
        let id = self.next_id;
        self.next_id += 1;
        self.slots[slot] = Some(UnixSocket::new(id, sock_type, pid));
        Ok(id)
    }

    /// Bind a socket to a filesystem path address.
    ///
    /// The socket must be in the `Unbound` state. The address must
    /// not already be bound by another socket.
    pub fn bind(&mut self, id: u64, addr: UnixAddr) -> Result<()> {
        if addr.is_empty() {
            return Err(Error::InvalidArgument);
        }

        // Check state first.
        {
            let sock = self.get_mut(id)?;
            if sock.state != UnixSocketState::Unbound {
                return Err(Error::InvalidArgument);
            }
        }

        // Check uniqueness.
        if self.find_by_addr(&addr).is_some() {
            return Err(Error::AlreadyExists);
        }

        // Perform bind.
        let sock = self.get_mut(id)?;
        sock.addr = addr;
        sock.state = UnixSocketState::Bound;
        Ok(())
    }

    /// Set a bound socket to the listening state.
    ///
    /// Only valid for stream or seqpacket sockets that are already
    /// bound. The `_backlog` parameter is accepted for POSIX
    /// compatibility but the actual limit is [`MAX_BACKLOG`].
    pub fn listen(&mut self, id: u64, _backlog: usize) -> Result<()> {
        let sock = self.get_mut(id)?;
        match sock.socket_type {
            UnixSocketType::Stream | UnixSocketType::SeqPacket => {}
            UnixSocketType::Dgram => {
                return Err(Error::InvalidArgument);
            }
        }
        if sock.state != UnixSocketState::Bound {
            return Err(Error::InvalidArgument);
        }
        sock.state = UnixSocketState::Listening;
        Ok(())
    }

    /// Accept a pending connection on a listening socket.
    ///
    /// Dequeues the oldest pending client from the backlog, creates
    /// a new server-side socket, cross-links it with the client, and
    /// returns the new socket's ID. Both the new server socket and
    /// the client transition to `Connected`.
    pub fn accept(&mut self, id: u64) -> Result<u64> {
        // Pop the first pending client from the backlog.
        let (client_id, server_pid, sock_type) = {
            let sock = self.get_mut(id)?;
            if sock.state != UnixSocketState::Listening {
                return Err(Error::InvalidArgument);
            }
            if sock.backlog_count == 0 {
                return Err(Error::WouldBlock);
            }

            let first = sock.backlog[0];
            let remaining = sock.backlog_count - 1;

            // Shift remaining entries forward.
            let mut i = 0;
            while i < remaining {
                sock.backlog[i] = sock.backlog[i + 1];
                i += 1;
            }
            if remaining < MAX_BACKLOG {
                sock.backlog[remaining] = 0;
            }
            sock.backlog_count = remaining;

            (first, sock.owner_pid, sock.socket_type)
        };

        // Create a new server-side socket.
        let new_id = self.socket(sock_type, server_pid)?;

        // Cross-link: new socket <-> client.
        {
            let new_sock = self.get_mut(new_id)?;
            new_sock.peer_id = Some(client_id);
            new_sock.state = UnixSocketState::Connected;
        }
        {
            let client = self.get_mut(client_id)?;
            client.peer_id = Some(new_id);
            client.state = UnixSocketState::Connected;
        }

        Ok(new_id)
    }

    /// Connect a client socket to a listening server identified by
    /// its bound address.
    ///
    /// Finds the server socket bound to `addr`, verifies it is
    /// listening, and enqueues the client's ID into the server's
    /// backlog. The client remains in its current state until the
    /// server calls `accept`.
    pub fn connect(&mut self, id: u64, addr: UnixAddr) -> Result<()> {
        if addr.is_empty() {
            return Err(Error::InvalidArgument);
        }

        // Client must be unbound or bound (not yet connected).
        {
            let client = self.get_mut(id)?;
            match client.state {
                UnixSocketState::Unbound | UnixSocketState::Bound => {}
                _ => return Err(Error::InvalidArgument),
            }
        }

        // Find the listening server.
        let server_id = self.find_by_addr(&addr).ok_or(Error::NotFound)?;

        // Verify server is listening and has room in the backlog.
        let server = self.get_mut(server_id)?;
        if server.state != UnixSocketState::Listening {
            return Err(Error::InvalidArgument);
        }
        if server.backlog_count >= MAX_BACKLOG {
            return Err(Error::WouldBlock);
        }

        // Enqueue client into the server's backlog.
        server.backlog[server.backlog_count] = id;
        server.backlog_count += 1;
        Ok(())
    }

    /// Send data through a connected socket.
    ///
    /// Writes data into the **peer's** receive buffer so that the
    /// peer can read it via [`recv`](Self::recv). Returns the number
    /// of bytes written. Returns `IoError` (broken pipe) if the peer
    /// is closed, or `WouldBlock` if the peer's buffer is full.
    pub fn send(&mut self, id: u64, data: &[u8]) -> Result<usize> {
        // Verify sender is connected and get peer ID.
        let peer_id = {
            let sock = self.get_mut(id)?;
            if sock.state != UnixSocketState::Connected {
                return Err(Error::InvalidArgument);
            }
            sock.peer_id.ok_or(Error::InvalidArgument)?
        };

        // Check peer state — broken pipe if closed.
        let peer_slot = self.slot_of(peer_id);
        if peer_slot.is_err() {
            return Err(Error::IoError); // peer gone
        }

        if data.is_empty() {
            return Ok(0);
        }

        // Write into the peer's receive buffer.
        let peer = self.get_mut(peer_id)?;
        if peer.state == UnixSocketState::Closed {
            return Err(Error::IoError); // EPIPE
        }
        peer.buffer.write(data)
    }

    /// Receive data from a connected socket.
    ///
    /// Reads data from the socket's **own** receive buffer. Returns
    /// the number of bytes read. Returns `WouldBlock` if no data is
    /// available, or `Ok(0)` (EOF) if the peer is closed and the
    /// buffer has been drained.
    pub fn recv(&mut self, id: u64, buf: &mut [u8]) -> Result<usize> {
        let slot_idx = self.slot_of(id)?;

        // Read from local buffer if data is available.
        let (is_empty, peer_id) = {
            let sock = self.slots[slot_idx].as_ref().ok_or(Error::NotFound)?;
            if sock.state != UnixSocketState::Connected {
                return Err(Error::InvalidArgument);
            }
            (sock.buffer.is_empty(), sock.peer_id)
        };

        if buf.is_empty() {
            return Ok(0);
        }

        if !is_empty {
            let sock = self.slots[slot_idx].as_mut().ok_or(Error::NotFound)?;
            return sock.buffer.read(buf);
        }

        // Buffer empty — check if peer is gone (EOF / broken pipe).
        let peer_closed = match peer_id {
            Some(pid) => self
                .get(pid)
                .map(|p| p.state == UnixSocketState::Closed)
                .unwrap_or(true),
            None => true,
        };

        if peer_closed {
            return Ok(0); // EOF
        }

        Err(Error::WouldBlock)
    }

    /// Close a socket and release its slot.
    ///
    /// The socket is marked `Closed` and its slot is freed. The peer
    /// (if any) will receive `IoError` on the next `send` and
    /// `Ok(0)` (EOF) on `recv` once the buffer is drained.
    pub fn close(&mut self, id: u64) -> Result<()> {
        let slot = self.slot_of(id)?;
        self.slots[slot] = None;
        Ok(())
    }

    /// Create a pair of connected sockets (`socketpair(2)`).
    ///
    /// Both sockets are of the given type, unnamed, and immediately
    /// connected to each other. Returns `(id_a, id_b)` on success.
    pub fn socketpair(&mut self, sock_type: UnixSocketType, pid: u64) -> Result<(u64, u64)> {
        // Allocate socket A.
        let id_a = self.socket(sock_type, pid)?;

        // Allocate socket B.
        let id_b = match self.socket(sock_type, pid) {
            Ok(id) => id,
            Err(e) => {
                let _ = self.close(id_a);
                return Err(e);
            }
        };

        // Cross-link: A <-> B, both Connected.
        {
            let sock_a = self.get_mut(id_a)?;
            sock_a.peer_id = Some(id_b);
            sock_a.state = UnixSocketState::Connected;
        }
        {
            let sock_b = self.get_mut(id_b)?;
            sock_b.peer_id = Some(id_a);
            sock_b.state = UnixSocketState::Connected;
        }

        Ok((id_a, id_b))
    }

    /// Shut down part or all of a connected socket.
    ///
    /// `how` specifies which direction to shut down:
    /// - `Read` — discard unread data from the local buffer.
    /// - `Write` — signal the peer that no more data will be sent.
    /// - `Both` — equivalent to `Read` followed by `Write`.
    ///
    /// The socket transitions to `Closed` on `Write` or `Both`.
    pub fn shutdown(&mut self, id: u64, how: ShutdownHow) -> Result<()> {
        let sock = self.get_mut(id)?;
        if sock.state != UnixSocketState::Connected {
            return Err(Error::InvalidArgument);
        }

        match how {
            ShutdownHow::Read => {
                // Discard any unread data.
                sock.buffer = UnixSocketBuffer::new();
            }
            ShutdownHow::Write => {
                sock.state = UnixSocketState::Closed;
            }
            ShutdownHow::Both => {
                sock.buffer = UnixSocketBuffer::new();
                sock.state = UnixSocketState::Closed;
            }
        }
        Ok(())
    }
}
