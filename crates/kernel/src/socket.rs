// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Unix domain socket (AF_LOCAL) support for the ONCRIX kernel.
//!
//! Provides the kernel-facing socket API that maps POSIX `socket(2)`,
//! `bind(2)`, `listen(2)`, `accept(2)`, `connect(2)`, `sendto(2)`,
//! `recvfrom(2)`, `socketpair(2)`, and `close(2)` onto the IPC
//! crate's [`UnixSocketRegistry`].
//!
//! # Socket domains
//!
//! Only `AF_LOCAL` (`AF_UNIX`, domain = 1) is currently supported.
//! Network socket families (AF_INET, AF_INET6) will be added when the
//! networking stack is implemented.
//!
//! # Design
//!
//! The [`SocketRegistry`] wraps [`oncrix_ipc::unix_socket::UnixSocketRegistry`]
//! and exposes a flat ID-based interface suitable for syscall handlers.
//! Internally, data flows through per-socket ring buffers (4 KiB each,
//! matching `PIPE_BUF`). For connected stream sockets, `send` writes
//! into the **peer's** buffer and `recv` reads from the **local** buffer.

use oncrix_ipc::unix_socket::{SocketAddr, SocketType, UnixSocketRegistry};
use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// SocketDomain
// ---------------------------------------------------------------------------

/// Socket address family (domain).
///
/// Corresponds to the first argument of `socket(2)`.
/// Currently only local (Unix) sockets are implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SocketDomain {
    /// Local (Unix domain) socket — `AF_LOCAL` / `AF_UNIX`.
    Local = 1,
}

impl SocketDomain {
    /// Convert a raw integer to a `SocketDomain`.
    ///
    /// Returns `InvalidArgument` for unsupported domains.
    pub fn from_raw(raw: u32) -> Result<Self> {
        match raw {
            1 => Ok(Self::Local),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ---------------------------------------------------------------------------
// SockType (wrapper)
// ---------------------------------------------------------------------------

/// Socket type (second argument to `socket(2)`).
///
/// Maps raw POSIX constants to [`SocketType`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SockType {
    /// `SOCK_STREAM` (1) — connection-oriented byte stream.
    Stream = 1,
    /// `SOCK_DGRAM` (2) — connectionless datagram.
    Dgram = 2,
}

impl SockType {
    /// Convert a raw integer to a `SockType`.
    ///
    /// Returns `InvalidArgument` for unsupported types.
    pub fn from_raw(raw: u32) -> Result<Self> {
        match raw {
            1 => Ok(Self::Stream),
            2 => Ok(Self::Dgram),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Convert to the IPC crate's [`SocketType`].
    fn to_ipc(self) -> SocketType {
        match self {
            Self::Stream => SocketType::Stream,
            Self::Dgram => SocketType::Datagram,
        }
    }
}

// ---------------------------------------------------------------------------
// SocketRegistry
// ---------------------------------------------------------------------------

/// Maximum number of sockets managed by this registry.
const MAX_SOCKETS: usize = 64;

/// Kernel-level socket registry.
///
/// Wraps the IPC crate's [`UnixSocketRegistry`] and provides the full
/// POSIX socket lifecycle: `create`, `bind`, `listen`, `accept`,
/// `connect`, `send`, `recv`, `close`, and `socketpair`.
///
/// Socket IDs are `usize` indices into a flat array. Each slot records
/// the domain and delegates to the appropriate backend registry.
pub struct SocketRegistry {
    /// The underlying Unix socket registry (from the IPC crate).
    unix: UnixSocketRegistry,
    /// Maps our socket IDs to Unix registry IDs.
    ///
    /// `id_map[local_id] = Some(unix_registry_id)` when the slot is in use.
    id_map: [Option<u64>; MAX_SOCKETS],
}

impl Default for SocketRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SocketRegistry {
    /// Create an empty socket registry.
    pub const fn new() -> Self {
        const NONE: Option<u64> = None;
        Self {
            unix: UnixSocketRegistry::new(),
            id_map: [NONE; MAX_SOCKETS],
        }
    }

    // -- helpers ----------------------------------------------------------

    /// Find a free local slot index.
    fn alloc_slot(&self) -> Result<usize> {
        for (i, slot) in self.id_map.iter().enumerate() {
            if slot.is_none() {
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Resolve a local socket ID to the Unix registry ID.
    fn resolve(&self, id: usize) -> Result<u64> {
        self.id_map
            .get(id)
            .copied()
            .flatten()
            .ok_or(Error::NotFound)
    }

    // -- public API -------------------------------------------------------

    /// Create a new socket.
    ///
    /// `domain` must be [`SocketDomain::Local`]; `sock_type` selects
    /// stream or datagram mode. Returns a local socket ID on success.
    pub fn create(&mut self, domain: SocketDomain, sock_type: SockType) -> Result<usize> {
        if domain != SocketDomain::Local {
            return Err(Error::InvalidArgument);
        }
        let slot = self.alloc_slot()?;
        let unix_id = self.unix.create(sock_type.to_ipc())?;
        self.id_map[slot] = Some(unix_id);
        Ok(slot)
    }

    /// Bind a socket to a local address.
    ///
    /// The socket must be unbound. The address must not already be in
    /// use by another socket.
    pub fn bind(&mut self, id: usize, addr: SocketAddr) -> Result<()> {
        // Check for address conflicts first.
        if self.unix.find_by_addr(&addr).is_some() {
            return Err(Error::AlreadyExists);
        }
        let unix_id = self.resolve(id)?;
        let sock = self.unix.get_mut(unix_id).ok_or(Error::NotFound)?;
        sock.bind(addr)
    }

    /// Mark a socket as listening for incoming connections.
    ///
    /// Only valid for stream sockets that have been bound.
    pub fn listen(&mut self, id: usize, backlog: u32) -> Result<()> {
        let unix_id = self.resolve(id)?;
        let sock = self.unix.get_mut(unix_id).ok_or(Error::NotFound)?;
        sock.listen(backlog)
    }

    /// Accept a pending connection on a listening socket.
    ///
    /// Returns the local socket ID of a newly created connected socket
    /// that is paired with the connecting peer. The listening socket
    /// remains in the `Listening` state.
    pub fn accept(&mut self, id: usize) -> Result<usize> {
        let unix_id = self.resolve(id)?;

        // Pop the pending peer from the backlog.
        let peer_unix_id = {
            let sock = self.unix.get_mut(unix_id).ok_or(Error::NotFound)?;
            sock.accept()?
        };

        // Create a new server-side socket, already connected to the peer.
        let peer_type = {
            let peer = self.unix.get(peer_unix_id).ok_or(Error::NotFound)?;
            peer.socket_type()
        };
        let server_unix_id = self.unix.create(peer_type)?;

        // Connect both ends to each other.
        {
            let server_sock = self.unix.get_mut(server_unix_id).ok_or(Error::NotFound)?;
            server_sock.connect(peer_unix_id)?;
        }

        // Also mark the peer as connected to the server socket.
        {
            let peer_sock = self.unix.get_mut(peer_unix_id).ok_or(Error::NotFound)?;
            peer_sock.connect(server_unix_id)?;
        }

        // Allocate a local slot for the new server socket.
        let slot = self.alloc_slot()?;
        self.id_map[slot] = Some(server_unix_id);
        Ok(slot)
    }

    /// Connect a socket to a remote address.
    ///
    /// Looks up the target socket by address, enqueues a connection
    /// request into the target's listen backlog, and transitions this
    /// socket to the connecting state.
    pub fn connect(&mut self, id: usize, addr: SocketAddr) -> Result<()> {
        let unix_id = self.resolve(id)?;

        // Find the listening socket bound to the target address.
        let target_unix_id = self.unix.find_by_addr(&addr).ok_or(Error::NotFound)?;

        // Enqueue this socket into the target's backlog.
        {
            let target = self.unix.get_mut(target_unix_id).ok_or(Error::NotFound)?;
            target.enqueue_connection(unix_id)?;
        }

        Ok(())
    }

    /// Send data through a connected socket.
    ///
    /// Writes data into the **peer's** ring buffer so that the peer
    /// can read it via [`recv`](Self::recv). Returns the number of
    /// bytes written, or `WouldBlock` if the peer's buffer is full.
    pub fn send(&mut self, id: usize, data: &[u8]) -> Result<usize> {
        let unix_id = self.resolve(id)?;

        // Get the peer ID from our socket.
        let peer_unix_id = {
            let sock = self.unix.get(unix_id).ok_or(Error::NotFound)?;
            sock.peer_id().ok_or(Error::InvalidArgument)?
        };

        // Write into the peer's buffer.
        let peer = self.unix.get_mut(peer_unix_id).ok_or(Error::NotFound)?;
        peer.send(data)
    }

    /// Receive data from a connected socket.
    ///
    /// Reads data from the **local** ring buffer. Returns the number
    /// of bytes read, or `WouldBlock` if no data is available.
    pub fn recv(&mut self, id: usize, buf: &mut [u8]) -> Result<usize> {
        let unix_id = self.resolve(id)?;
        let sock = self.unix.get_mut(unix_id).ok_or(Error::NotFound)?;
        sock.recv(buf)
    }

    /// Close a socket and release its resources.
    ///
    /// The socket is marked as closed and removed from the registry.
    pub fn close(&mut self, id: usize) -> Result<()> {
        let unix_id = self.resolve(id)?;
        {
            let sock = self.unix.get_mut(unix_id).ok_or(Error::NotFound)?;
            sock.close();
        }
        self.unix.remove(unix_id)?;
        self.id_map[id] = None;
        Ok(())
    }

    /// Create a pair of connected sockets (`socketpair(2)`).
    ///
    /// Both sockets are stream-type, unnamed, and immediately
    /// connected to each other. Returns `(id_a, id_b)`.
    pub fn socketpair(&mut self, sock_type: SockType) -> Result<(usize, usize)> {
        // Allocate two local slots.
        let slot_a = self.alloc_slot()?;
        let unix_id_a = self.unix.create(sock_type.to_ipc())?;
        self.id_map[slot_a] = Some(unix_id_a);

        let slot_b = match self.alloc_slot() {
            Ok(s) => s,
            Err(e) => {
                // Roll back slot_a.
                self.id_map[slot_a] = None;
                let _ = self.unix.remove(unix_id_a);
                return Err(e);
            }
        };
        let unix_id_b = match self.unix.create(sock_type.to_ipc()) {
            Ok(id) => id,
            Err(e) => {
                // Roll back slot_a.
                self.id_map[slot_a] = None;
                let _ = self.unix.remove(unix_id_a);
                return Err(e);
            }
        };
        self.id_map[slot_b] = Some(unix_id_b);

        // Connect A → B.
        if let Err(e) = self
            .unix
            .get_mut(unix_id_a)
            .ok_or(Error::NotFound)
            .and_then(|s| s.connect(unix_id_b))
        {
            self.id_map[slot_a] = None;
            self.id_map[slot_b] = None;
            let _ = self.unix.remove(unix_id_a);
            let _ = self.unix.remove(unix_id_b);
            return Err(e);
        }

        // Connect B → A.
        if let Err(e) = self
            .unix
            .get_mut(unix_id_b)
            .ok_or(Error::NotFound)
            .and_then(|s| s.connect(unix_id_a))
        {
            self.id_map[slot_a] = None;
            self.id_map[slot_b] = None;
            let _ = self.unix.remove(unix_id_a);
            let _ = self.unix.remove(unix_id_b);
            return Err(e);
        }

        Ok((slot_a, slot_b))
    }

    /// Return the number of active sockets.
    pub fn count(&self) -> usize {
        self.id_map.iter().filter(|s| s.is_some()).count()
    }
}
