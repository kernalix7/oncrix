// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Socket filesystem (sockfs) — pseudo-filesystem for socket inodes.
//!
//! The socket filesystem provides a VFS home for socket file descriptors.
//! When a socket is created via `socket(2)`, it receives an inode in sockfs
//! so that the file descriptor infrastructure (open-file table, poll, select,
//! epoll) can work uniformly on sockets.
//!
//! Unlike disk-based filesystems, sockfs never persists data; every inode
//! lives only for the lifetime of the socket.  No directories, no dentries
//! on disk, no superblock persistence.
//!
//! # Linux reference
//! `net/socket.c` — `sock_alloc()`, `sockfs_magic`, `socket_file_ops`
//! `fs/filesystems.c` — filesystem registration
//!
//! # POSIX reference
//! POSIX.1-2024 `socket(2)`, `socketpair(2)` — socket creation semantics.

use crate::inode::{FileMode, FileType, InodeNumber};
use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Magic number identifying the socket filesystem.
pub const SOCKFS_MAGIC: u32 = 0x534F_434B;

/// Maximum number of simultaneous sockets.
const MAX_SOCKETS: usize = 256;

/// Maximum number of pending connections in a listen backlog.
pub const SOCKFS_BACKLOG_MAX: usize = 128;

/// Socket send/receive buffer size (64 KiB).
const SOCK_BUF_SIZE: usize = 65536;

// ── Address families ──────────────────────────────────────────────────────────

/// Address family (AF_* constants).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AddressFamily {
    /// Unspecified.
    Unspec = 0,
    /// Unix domain (local) sockets.
    Unix = 1,
    /// IPv4 internet sockets.
    Inet = 2,
    /// IPv6 internet sockets.
    Inet6 = 10,
    /// Netlink sockets.
    Netlink = 16,
    /// Packet sockets (raw network-layer access).
    Packet = 17,
}

impl AddressFamily {
    /// Parse an `AF_*` constant into an `AddressFamily`.
    pub fn from_raw(raw: u16) -> Result<Self> {
        match raw {
            0 => Ok(Self::Unspec),
            1 => Ok(Self::Unix),
            2 => Ok(Self::Inet),
            10 => Ok(Self::Inet6),
            16 => Ok(Self::Netlink),
            17 => Ok(Self::Packet),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ── Socket type ───────────────────────────────────────────────────────────────

/// Socket type (SOCK_* constants).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SocketType {
    /// Reliable, sequenced byte stream (TCP-like).
    Stream = 1,
    /// Unreliable datagram (UDP-like).
    Dgram = 2,
    /// Raw protocol access.
    Raw = 3,
    /// Reliably-delivered messages.
    Rdm = 4,
    /// Sequenced, reliable, connection-based datagrams.
    SeqPacket = 5,
}

impl SocketType {
    /// Parse a `SOCK_*` constant (low bits, ignoring SOCK_CLOEXEC/SOCK_NONBLOCK).
    pub fn from_raw(raw: u32) -> Result<Self> {
        match raw & 0xF {
            1 => Ok(Self::Stream),
            2 => Ok(Self::Dgram),
            3 => Ok(Self::Raw),
            4 => Ok(Self::Rdm),
            5 => Ok(Self::SeqPacket),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ── Socket state ──────────────────────────────────────────────────────────────

/// Lifecycle state of a socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketState {
    /// Newly created, not yet bound or connected.
    Unconnected,
    /// `bind(2)` has been called; address is assigned.
    Bound,
    /// `listen(2)` has been called; accepting connections.
    Listening,
    /// `connect(2)` is in progress (non-blocking).
    Connecting,
    /// Connection fully established.
    Connected,
    /// `shutdown(2)` or `close(2)` in progress.
    Disconnecting,
    /// Socket has been closed and its resources freed.
    Dead,
}

// ── Socket address storage ────────────────────────────────────────────────────

/// Maximum size of a socket address (matches `sockaddr_storage`).
const SOCKADDR_STORAGE_LEN: usize = 128;

/// Opaque socket address buffer.
#[derive(Debug, Clone, Copy)]
pub struct SockAddrStorage {
    /// Raw address bytes.
    pub data: [u8; SOCKADDR_STORAGE_LEN],
    /// Number of valid bytes in `data`.
    pub len: usize,
}

impl Default for SockAddrStorage {
    fn default() -> Self {
        Self {
            data: [0u8; SOCKADDR_STORAGE_LEN],
            len: 0,
        }
    }
}

// ── Receive / send ring buffer ────────────────────────────────────────────────

/// Fixed-size ring buffer used for socket receive/send queues.
struct RingBuf {
    buf: [u8; SOCK_BUF_SIZE],
    read_pos: usize,
    write_pos: usize,
    count: usize,
}

impl RingBuf {
    const fn new() -> Self {
        Self {
            buf: [0u8; SOCK_BUF_SIZE],
            read_pos: 0,
            write_pos: 0,
            count: 0,
        }
    }

    /// Number of bytes available to read.
    fn readable(&self) -> usize {
        self.count
    }

    /// Number of bytes that can still be written.
    fn writable(&self) -> usize {
        SOCK_BUF_SIZE - self.count
    }

    /// Write bytes into the ring; returns bytes actually written.
    fn write(&mut self, data: &[u8]) -> usize {
        let to_write = data.len().min(self.writable());
        for &b in &data[..to_write] {
            self.buf[self.write_pos] = b;
            self.write_pos = (self.write_pos + 1) % SOCK_BUF_SIZE;
        }
        self.count += to_write;
        to_write
    }

    /// Read bytes from the ring; returns bytes actually read.
    fn read(&mut self, out: &mut [u8]) -> usize {
        let to_read = out.len().min(self.readable());
        for slot in &mut out[..to_read] {
            *slot = self.buf[self.read_pos];
            self.read_pos = (self.read_pos + 1) % SOCK_BUF_SIZE;
        }
        self.count -= to_read;
        to_read
    }
}

// ── Socket object ─────────────────────────────────────────────────────────────

/// A kernel socket object in sockfs.
pub struct Socket {
    /// Inode number assigned to this socket (unique within sockfs).
    pub ino: InodeNumber,
    /// Address family.
    pub family: AddressFamily,
    /// Socket type.
    pub sock_type: SocketType,
    /// Protocol number (0 = default for the type).
    pub protocol: u32,
    /// Current state.
    pub state: SocketState,
    /// Local address.
    pub local_addr: SockAddrStorage,
    /// Peer address (valid in Connected state).
    pub peer_addr: SockAddrStorage,
    /// Receive buffer.
    recv_buf: RingBuf,
    /// Send buffer.
    send_buf: RingBuf,
    /// Whether the socket is set non-blocking.
    pub non_blocking: bool,
    /// Whether `SO_REUSEADDR` is set.
    pub reuse_addr: bool,
    /// Whether `SO_KEEPALIVE` is set.
    pub keep_alive: bool,
    /// Receive timeout in milliseconds (0 = no timeout).
    pub recv_timeout_ms: u64,
    /// Send timeout in milliseconds (0 = no timeout).
    pub send_timeout_ms: u64,
    /// Pending-connection count (listen queue).
    pub backlog_count: usize,
    /// Maximum pending-connection backlog.
    pub backlog_max: usize,
    /// Reference count.
    ref_count: u32,
}

impl Socket {
    /// Create a new unconnected socket with the given parameters.
    pub fn new(
        ino: InodeNumber,
        family: AddressFamily,
        sock_type: SocketType,
        protocol: u32,
    ) -> Self {
        Self {
            ino,
            family,
            sock_type,
            protocol,
            state: SocketState::Unconnected,
            local_addr: SockAddrStorage::default(),
            peer_addr: SockAddrStorage::default(),
            recv_buf: RingBuf::new(),
            send_buf: RingBuf::new(),
            non_blocking: false,
            reuse_addr: false,
            keep_alive: false,
            recv_timeout_ms: 0,
            send_timeout_ms: 0,
            backlog_count: 0,
            backlog_max: SOCKFS_BACKLOG_MAX,
            ref_count: 1,
        }
    }

    /// Increment the reference count.
    pub fn get(&mut self) {
        self.ref_count = self.ref_count.saturating_add(1);
    }

    /// Decrement the reference count; returns `true` if the socket should be freed.
    pub fn put(&mut self) -> bool {
        if self.ref_count > 0 {
            self.ref_count -= 1;
        }
        self.ref_count == 0
    }

    /// Bind the socket to the given address bytes.
    ///
    /// Transitions from `Unconnected` to `Bound`.
    pub fn bind(&mut self, addr: &[u8]) -> Result<()> {
        if addr.len() > SOCKADDR_STORAGE_LEN {
            return Err(Error::InvalidArgument);
        }
        match self.state {
            SocketState::Unconnected => {}
            SocketState::Bound => return Err(Error::AlreadyExists),
            _ => return Err(Error::InvalidArgument),
        }
        self.local_addr.data[..addr.len()].copy_from_slice(addr);
        self.local_addr.len = addr.len();
        self.state = SocketState::Bound;
        Ok(())
    }

    /// Put the socket in listening mode.
    ///
    /// Transitions from `Bound` to `Listening`.  Only valid for `Stream`
    /// and `SeqPacket` socket types.
    pub fn listen(&mut self, backlog: usize) -> Result<()> {
        match self.sock_type {
            SocketType::Stream | SocketType::SeqPacket => {}
            _ => return Err(Error::InvalidArgument),
        }
        match self.state {
            SocketState::Bound => {}
            SocketState::Listening => return Ok(()), // idempotent
            _ => return Err(Error::InvalidArgument),
        }
        self.backlog_max = backlog.min(SOCKFS_BACKLOG_MAX);
        self.state = SocketState::Listening;
        Ok(())
    }

    /// Mark the socket as connected to `peer`.
    pub fn mark_connected(&mut self, peer: &[u8]) -> Result<()> {
        if peer.len() > SOCKADDR_STORAGE_LEN {
            return Err(Error::InvalidArgument);
        }
        self.peer_addr.data[..peer.len()].copy_from_slice(peer);
        self.peer_addr.len = peer.len();
        self.state = SocketState::Connected;
        Ok(())
    }

    /// Write data into the socket's receive buffer (simulating incoming data).
    ///
    /// Returns the number of bytes actually written (may be less than `data.len()`
    /// if the buffer is full).
    pub fn enqueue_recv(&mut self, data: &[u8]) -> usize {
        self.recv_buf.write(data)
    }

    /// Read data from the socket's receive buffer.
    ///
    /// Returns `WouldBlock` if no data is available and the socket is
    /// non-blocking.
    pub fn recv(&mut self, out: &mut [u8]) -> Result<usize> {
        if self.recv_buf.readable() == 0 {
            if self.non_blocking {
                return Err(Error::WouldBlock);
            }
            return Err(Error::WouldBlock);
        }
        Ok(self.recv_buf.read(out))
    }

    /// Send data — appends to the send buffer.
    ///
    /// Returns the number of bytes accepted, or `WouldBlock` if the send
    /// buffer is full and the socket is non-blocking.
    pub fn send(&mut self, data: &[u8]) -> Result<usize> {
        if self.state != SocketState::Connected
            && self.state != SocketState::Bound
            && self.state != SocketState::Unconnected
        {
            return Err(Error::InvalidArgument);
        }
        if self.send_buf.writable() == 0 {
            if self.non_blocking {
                return Err(Error::WouldBlock);
            }
            return Err(Error::WouldBlock);
        }
        Ok(self.send_buf.write(data))
    }

    /// Drain data from the send buffer (called by the network layer).
    pub fn drain_send(&mut self, out: &mut [u8]) -> usize {
        self.send_buf.read(out)
    }

    /// Close the socket, marking it as `Dead`.
    pub fn close(&mut self) {
        self.state = SocketState::Dead;
    }

    /// Returns the number of bytes available in the receive buffer.
    pub fn recv_available(&self) -> usize {
        self.recv_buf.readable()
    }

    /// Returns the free space in the send buffer.
    pub fn send_space(&self) -> usize {
        self.send_buf.writable()
    }
}

// ── Sockfs superblock ─────────────────────────────────────────────────────────

/// The socket filesystem superblock: owns all socket inodes.
pub struct SockFs {
    /// All allocated socket slots.
    sockets: [Option<Socket>; MAX_SOCKETS],
    /// Next inode number to assign.
    next_ino: u64,
    /// Number of live sockets.
    socket_count: usize,
}

impl SockFs {
    /// Initialise an empty sockfs instance.
    pub const fn new() -> Self {
        Self {
            sockets: [const { None }; MAX_SOCKETS],
            next_ino: 1,
            socket_count: 0,
        }
    }

    /// Allocate a new socket and return its inode number.
    ///
    /// Returns `OutOfMemory` if the socket table is full.
    pub fn alloc_socket(
        &mut self,
        family: AddressFamily,
        sock_type: SocketType,
        protocol: u32,
    ) -> Result<InodeNumber> {
        if self.socket_count >= MAX_SOCKETS {
            return Err(Error::OutOfMemory);
        }
        let ino = InodeNumber(self.next_ino);
        self.next_ino += 1;
        let slot = self
            .sockets
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(Error::OutOfMemory)?;
        *slot = Some(Socket::new(ino, family, sock_type, protocol));
        self.socket_count += 1;
        Ok(ino)
    }

    /// Look up a socket by inode number (immutable).
    pub fn get(&self, ino: InodeNumber) -> Option<&Socket> {
        self.sockets
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|s| s.ino == ino)
    }

    /// Look up a socket by inode number (mutable).
    pub fn get_mut(&mut self, ino: InodeNumber) -> Option<&mut Socket> {
        self.sockets
            .iter_mut()
            .filter_map(|s| s.as_mut())
            .find(|s| s.ino == ino)
    }

    /// Release a socket by inode number, decrementing its reference count.
    ///
    /// The slot is freed when the reference count reaches zero.
    /// Returns `NotFound` if no socket with `ino` exists.
    pub fn release(&mut self, ino: InodeNumber) -> Result<()> {
        for slot in &mut self.sockets {
            if let Some(sock) = slot {
                if sock.ino == ino {
                    let should_free = sock.put();
                    if should_free {
                        *slot = None;
                        self.socket_count -= 1;
                    }
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Build a VFS-compatible inode view for the given socket.
    ///
    /// Sockets appear as `S_IFSOCK | 0o777` in the VFS layer.
    pub fn make_inode(ino: InodeNumber) -> SockfsInode {
        SockfsInode {
            ino,
            mode: FileMode(0o140_777),
            file_type: FileType::Socket,
        }
    }

    /// Number of live sockets.
    pub fn socket_count(&self) -> usize {
        self.socket_count
    }

    /// Filesystem magic number.
    pub fn magic() -> u32 {
        SOCKFS_MAGIC
    }
}

// ── VFS inode wrapper ─────────────────────────────────────────────────────────

/// Lightweight inode descriptor used when sockfs integrates with the VFS layer.
#[derive(Debug, Clone, Copy)]
pub struct SockfsInode {
    /// Inode number.
    pub ino: InodeNumber,
    /// File mode (always `S_IFSOCK | 0o777`).
    pub mode: FileMode,
    /// File type (always `Socket`).
    pub file_type: FileType,
}

// ── Socket-level option handling ──────────────────────────────────────────────

/// Socket-level (`SOL_SOCKET`) option identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SockOpt {
    /// `SO_REUSEADDR` — allow binding to a port in TIME_WAIT.
    ReuseAddr = 2,
    /// `SO_KEEPALIVE` — enable TCP keep-alive probes.
    KeepAlive = 9,
    /// `SO_RCVTIMEO` — receive timeout.
    RecvTimeout = 20,
    /// `SO_SNDTIMEO` — send timeout.
    SendTimeout = 21,
    /// `SO_RCVBUF` — receive buffer size hint (informational only).
    RecvBuf = 8,
    /// `SO_SNDBUF` — send buffer size hint (informational only).
    SendBuf = 7,
}

impl SockOpt {
    /// Parse a `SO_*` constant.
    pub fn from_raw(raw: u32) -> Result<Self> {
        match raw {
            2 => Ok(Self::ReuseAddr),
            9 => Ok(Self::KeepAlive),
            20 => Ok(Self::RecvTimeout),
            21 => Ok(Self::SendTimeout),
            8 => Ok(Self::RecvBuf),
            7 => Ok(Self::SendBuf),
            _ => Err(Error::InvalidArgument),
        }
    }
}

/// Apply a `SOL_SOCKET` level option to a socket.
///
/// `value` carries the raw option bytes (e.g., a `u32` for boolean opts,
/// or a `timeval`-encoded millisecond value for timeouts).
pub fn setsockopt(sock: &mut Socket, opt: SockOpt, value: &[u8]) -> Result<()> {
    let int_val = if value.len() >= 4 {
        u32::from_ne_bytes([value[0], value[1], value[2], value[3]])
    } else {
        0
    };
    match opt {
        SockOpt::ReuseAddr => sock.reuse_addr = int_val != 0,
        SockOpt::KeepAlive => sock.keep_alive = int_val != 0,
        SockOpt::RecvTimeout => sock.recv_timeout_ms = u64::from(int_val),
        SockOpt::SendTimeout => sock.send_timeout_ms = u64::from(int_val),
        SockOpt::RecvBuf | SockOpt::SendBuf => {} // informational only
    }
    Ok(())
}

/// Read a `SOL_SOCKET` level option from a socket.
///
/// Writes the option value into `out` and returns the number of bytes written.
pub fn getsockopt(sock: &Socket, opt: SockOpt, out: &mut [u8]) -> Result<usize> {
    if out.len() < 4 {
        return Err(Error::InvalidArgument);
    }
    let val: u32 = match opt {
        SockOpt::ReuseAddr => sock.reuse_addr as u32,
        SockOpt::KeepAlive => sock.keep_alive as u32,
        SockOpt::RecvTimeout => sock.recv_timeout_ms as u32,
        SockOpt::SendTimeout => sock.send_timeout_ms as u32,
        SockOpt::RecvBuf | SockOpt::SendBuf => SOCK_BUF_SIZE as u32,
    };
    out[..4].copy_from_slice(&val.to_ne_bytes());
    Ok(4)
}

// ── Shutdown handling ─────────────────────────────────────────────────────────

/// Shutdown direction flags (as in `shutdown(2)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ShutdownHow {
    /// No further receives.
    Rd = 0,
    /// No further sends.
    Wr = 1,
    /// No further sends or receives.
    RdWr = 2,
}

impl ShutdownHow {
    /// Parse a `SHUT_*` constant.
    pub fn from_raw(raw: u32) -> Result<Self> {
        match raw {
            0 => Ok(Self::Rd),
            1 => Ok(Self::Wr),
            2 => Ok(Self::RdWr),
            _ => Err(Error::InvalidArgument),
        }
    }
}

/// Initiate a socket shutdown.
///
/// Transitions the socket toward `Disconnecting` and records which
/// directions have been shut down.  The actual state change to `Dead`
/// happens on the final `close(2)`.
pub fn shutdown(sock: &mut Socket, how: ShutdownHow) -> Result<()> {
    match sock.state {
        SocketState::Dead => return Err(Error::InvalidArgument),
        SocketState::Unconnected => return Err(Error::InvalidArgument),
        _ => {}
    }
    match how {
        ShutdownHow::Rd | ShutdownHow::Wr | ShutdownHow::RdWr => {
            sock.state = SocketState::Disconnecting;
        }
    }
    Ok(())
}
