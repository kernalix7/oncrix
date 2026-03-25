// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel Connection Multiplexor (KCM).
//!
//! KCM provides message-based multiplexing over a pool of TCP connections.
//! It exposes a socket-like interface (`AF_KCM`) that presents a stream of
//! framed messages to user-space, while internally managing a set of
//! underlying TCP sockets.
//!
//! # Architecture
//!
//! ```text
//!  User-space
//!  ┌────────────────────────────────────┐
//!  │  sendmsg(kcm_fd, msg)              │
//!  │  recvmsg(kcm_fd, msg)              │
//!  └─────────────┬──────────────────────┘
//!                │  AF_KCM socket
//!  ┌─────────────▼──────────────────────┐
//!  │  KCM mux (this module)             │
//!  │  ┌──────────────────────────────┐  │
//!  │  │  Connection pool             │  │
//!  │  │  [TCP sock 0] [TCP sock 1]…  │  │
//!  │  └──────────────────────────────┘  │
//!  │  BPF parser: find message boundary │
//!  └────────────────────────────────────┘
//! ```
//!
//! # Message framing
//!
//! KCM uses a BPF program (or a built-in length-prefix parser) to determine
//! message boundaries in the TCP byte stream. Once a complete message is
//! assembled, it is delivered as a single `recvmsg` result with `MSG_EOR`.
//!
//! # Sockets
//!
//! - `KCM_MUXFD`: the multiplexor socket.
//! - `KCM_CLONEFD`: a clone of the mux; each clone shares the same pool.
//! - Attaching a TCP socket: `ioctl(kcm_fd, SIOCKCMATTACH, &kcmattach)`.
//! - Detaching a TCP socket: `ioctl(kcm_fd, SIOCKCMUNATTACH, &kcmattach)`.
//!
//! # References
//!
//! - Linux: `net/kcm/kcmsock.c`, `net/kcm/kcmproc.c`
//! - Linux: `include/uapi/linux/kcm.h`
//! - `AF_KCM` = 41

use oncrix_lib::{Error, Result};

extern crate alloc;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// `AF_KCM` address family number (Linux).
pub const AF_KCM: u32 = 41;

/// Maximum number of TCP connections in a KCM pool.
pub const KCM_MAX_CONNECTIONS: usize = 64;

/// Maximum number of KCM mux clones per multiplexor.
pub const KCM_MAX_CLONES: usize = 128;

/// Maximum message size supported by the KCM layer (16 MiB).
pub const KCM_MAX_MSG_SIZE: usize = 16 * 1024 * 1024;

/// Default maximum receive buffer size per TCP connection (256 KiB).
pub const KCM_RECV_BUF_SIZE: usize = 256 * 1024;

/// ioctl: attach a TCP socket to the KCM mux.
pub const SIOCKCMATTACH: u32 = 0x89E0;

/// ioctl: detach a TCP socket from the KCM mux.
pub const SIOCKCMUNATTACH: u32 = 0x89E1;

/// ioctl: clone a KCM socket.
pub const SIOCKCMCLONE: u32 = 0x89E2;

// ---------------------------------------------------------------------------
// KcmAttach — ioctl argument for ATTACH/UNATTACH
// ---------------------------------------------------------------------------

/// Argument structure for `SIOCKCMATTACH` and `SIOCKCMUNATTACH`.
///
/// Mirrors `struct kcm_attach` from `include/uapi/linux/kcm.h`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KcmAttach {
    /// The TCP socket file descriptor to attach/detach.
    pub fd: i32,
    /// File descriptor of the BPF program for message framing.
    /// Use 0 for the built-in length-prefix parser.
    pub bpf_fd: i32,
}

// ---------------------------------------------------------------------------
// KcmClone — ioctl argument for CLONE
// ---------------------------------------------------------------------------

/// Argument structure for `SIOCKCMCLONE`.
///
/// Mirrors `struct kcm_clone` from `include/uapi/linux/kcm.h`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KcmClone {
    /// Receives the new KCM socket fd on success.
    pub fd: i32,
}

// ---------------------------------------------------------------------------
// TcpState — tracked state of an attached TCP connection
// ---------------------------------------------------------------------------

/// Liveness state of a TCP connection managed by KCM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    /// Connection is healthy and available for use.
    Connected,
    /// Connection is being drained (no new messages assigned).
    Draining,
    /// Connection has been closed remotely or locally.
    Closed,
}

// ---------------------------------------------------------------------------
// FramingMode — how message boundaries are detected
// ---------------------------------------------------------------------------

/// Strategy for finding message boundaries in the TCP stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FramingMode {
    /// User-supplied BPF program (identified by fd).
    Bpf(i32),
    /// Built-in: first 4 bytes are a big-endian u32 message length.
    LengthPrefix,
    /// No framing — each TCP read is a message (for testing).
    RawRead,
}

// ---------------------------------------------------------------------------
// KcmConnection — one TCP socket in the pool
// ---------------------------------------------------------------------------

/// A single TCP connection managed by the KCM mux.
#[derive(Debug)]
pub struct KcmConnection {
    /// The underlying TCP socket file descriptor.
    pub tcp_fd: i32,
    /// Current TCP connection state.
    pub state: TcpState,
    /// Framing mode for this connection.
    pub framing: FramingMode,
    /// Number of messages received on this connection.
    pub rx_count: u64,
    /// Number of messages sent on this connection.
    pub tx_count: u64,
    /// Number of bytes received.
    pub rx_bytes: u64,
    /// Number of bytes sent.
    pub tx_bytes: u64,
}

impl KcmConnection {
    /// Create a new connection entry.
    pub const fn new(tcp_fd: i32, framing: FramingMode) -> Self {
        Self {
            tcp_fd,
            state: TcpState::Connected,
            framing,
            rx_count: 0,
            tx_count: 0,
            rx_bytes: 0,
            tx_bytes: 0,
        }
    }

    /// Return `true` if the connection is available for sending.
    pub const fn is_available(&self) -> bool {
        matches!(self.state, TcpState::Connected)
    }
}

// ---------------------------------------------------------------------------
// KcmMessage — a framed message from the TCP stream
// ---------------------------------------------------------------------------

/// A fully assembled KCM message.
///
/// In the kernel, the payload would be an `sk_buff` chain.
/// Here we represent it as a length + opaque byte count for
/// validation purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KcmMessage {
    /// Source TCP connection index in the pool.
    pub conn_idx: usize,
    /// Message payload length in bytes.
    pub len: u32,
    /// Whether `MSG_EOR` should be set on delivery.
    pub eor: bool,
}

impl KcmMessage {
    /// Create a new message descriptor.
    pub const fn new(conn_idx: usize, len: u32) -> Self {
        Self {
            conn_idx,
            len,
            eor: true,
        }
    }
}

// ---------------------------------------------------------------------------
// KcmMux — the multiplexor
// ---------------------------------------------------------------------------

/// A KCM multiplexor holding a pool of TCP connections.
///
/// The mux is the core object; KCM sockets are clones that share the
/// same pool.
pub struct KcmMux {
    /// Attached TCP connections.
    connections: [Option<KcmConnection>; KCM_MAX_CONNECTIONS],
    /// Number of active connections.
    conn_count: usize,
    /// Total messages received across all connections.
    pub total_rx: u64,
    /// Total messages sent across all connections.
    pub total_tx: u64,
    /// Next connection index to use for round-robin sending.
    send_cursor: usize,
}

impl KcmMux {
    /// Create a new empty multiplexor.
    pub const fn new() -> Self {
        Self {
            connections: [const { None }; KCM_MAX_CONNECTIONS],
            conn_count: 0,
            total_rx: 0,
            total_tx: 0,
            send_cursor: 0,
        }
    }

    /// Return the number of active connections.
    pub const fn connection_count(&self) -> usize {
        self.conn_count
    }

    /// Attach a TCP socket to the mux.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] — `tcp_fd` is negative or already attached.
    /// - [`Error::OutOfMemory`]     — Pool is full.
    pub fn attach(&mut self, attach: &KcmAttach) -> Result<()> {
        if attach.fd < 0 {
            return Err(Error::InvalidArgument);
        }
        // Check for duplicate attachment.
        for slot in self.connections.iter().flatten() {
            if slot.tcp_fd == attach.fd {
                return Err(Error::InvalidArgument);
            }
        }
        if self.conn_count >= KCM_MAX_CONNECTIONS {
            return Err(Error::OutOfMemory);
        }

        let framing = if attach.bpf_fd > 0 {
            FramingMode::Bpf(attach.bpf_fd)
        } else {
            FramingMode::LengthPrefix
        };

        // Find empty slot.
        for slot in self.connections.iter_mut() {
            if slot.is_none() {
                *slot = Some(KcmConnection::new(attach.fd, framing));
                self.conn_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Detach a TCP socket from the mux.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] — `tcp_fd` is not attached.
    pub fn detach(&mut self, tcp_fd: i32) -> Result<()> {
        for slot in self.connections.iter_mut() {
            if let Some(conn) = slot {
                if conn.tcp_fd == tcp_fd {
                    *slot = None;
                    self.conn_count -= 1;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Find an available connection for sending (round-robin).
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] — No connected (non-draining) TCP socket available.
    pub fn find_send_connection(&mut self) -> Result<usize> {
        let n = KCM_MAX_CONNECTIONS;
        for i in 0..n {
            let idx = (self.send_cursor + i) % n;
            if let Some(conn) = &self.connections[idx] {
                if conn.is_available() {
                    self.send_cursor = (idx + 1) % n;
                    return Ok(idx);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Simulate sending a message over the mux.
    ///
    /// Picks the next available connection via round-robin, updates
    /// per-connection counters, and returns the connection index used.
    ///
    /// # Arguments
    ///
    /// - `msg_len` — Length of the message payload in bytes.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] — `msg_len` exceeds [`KCM_MAX_MSG_SIZE`].
    /// - [`Error::NotFound`]        — No available connection.
    pub fn send_msg(&mut self, msg_len: usize) -> Result<usize> {
        if msg_len > KCM_MAX_MSG_SIZE {
            return Err(Error::InvalidArgument);
        }
        if msg_len == 0 {
            return Err(Error::InvalidArgument);
        }

        let idx = self.find_send_connection()?;
        if let Some(conn) = self.connections[idx].as_mut() {
            conn.tx_count += 1;
            conn.tx_bytes += msg_len as u64;
            self.total_tx += 1;
        }
        Ok(idx)
    }

    /// Simulate receiving a message on the mux.
    ///
    /// Marks the connection as having received a message and increments
    /// counters.
    ///
    /// # Arguments
    ///
    /// - `conn_idx` — Index of the connection the message arrived on.
    /// - `msg_len`  — Length of the received message.
    ///
    /// # Returns
    ///
    /// A [`KcmMessage`] descriptor on success.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] — `conn_idx` is out of range or
    ///   `msg_len` exceeds [`KCM_MAX_MSG_SIZE`].
    /// - [`Error::NotFound`]        — No connection at `conn_idx`.
    pub fn recv_msg(&mut self, conn_idx: usize, msg_len: u32) -> Result<KcmMessage> {
        if conn_idx >= KCM_MAX_CONNECTIONS {
            return Err(Error::InvalidArgument);
        }
        if msg_len as usize > KCM_MAX_MSG_SIZE {
            return Err(Error::InvalidArgument);
        }

        match self.connections[conn_idx].as_mut() {
            Some(conn) => {
                if conn.state == TcpState::Closed {
                    return Err(Error::NotFound);
                }
                conn.rx_count += 1;
                conn.rx_bytes += msg_len as u64;
                self.total_rx += 1;
                Ok(KcmMessage::new(conn_idx, msg_len))
            }
            None => Err(Error::NotFound),
        }
    }

    /// Mark a connection as draining (no new messages assigned to it).
    ///
    /// A draining connection finishes in-flight messages, then can be
    /// detached.
    pub fn drain_connection(&mut self, tcp_fd: i32) -> Result<()> {
        for slot in self.connections.iter_mut().flatten() {
            if slot.tcp_fd == tcp_fd {
                slot.state = TcpState::Draining;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Mark a connection as closed (remote or local teardown).
    pub fn close_connection(&mut self, tcp_fd: i32) -> Result<()> {
        for slot in self.connections.iter_mut().flatten() {
            if slot.tcp_fd == tcp_fd {
                slot.state = TcpState::Closed;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Return a reference to a connection by TCP fd.
    pub fn get_connection(&self, tcp_fd: i32) -> Option<&KcmConnection> {
        self.connections
            .iter()
            .find_map(|s| s.as_ref().filter(|c| c.tcp_fd == tcp_fd))
    }

    /// Return statistics for all connections.
    pub fn stats(&self) -> KcmMuxStats {
        let mut stats = KcmMuxStats {
            total_connections: self.conn_count,
            available_connections: 0,
            draining_connections: 0,
            closed_connections: 0,
            total_rx: self.total_rx,
            total_tx: self.total_tx,
        };
        for slot in self.connections.iter().flatten() {
            match slot.state {
                TcpState::Connected => stats.available_connections += 1,
                TcpState::Draining => stats.draining_connections += 1,
                TcpState::Closed => stats.closed_connections += 1,
            }
        }
        stats
    }
}

impl Default for KcmMux {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// KcmMuxStats
// ---------------------------------------------------------------------------

/// Aggregate statistics for a KCM multiplexor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KcmMuxStats {
    /// Total number of attached connections.
    pub total_connections: usize,
    /// Connections in `Connected` state.
    pub available_connections: usize,
    /// Connections in `Draining` state.
    pub draining_connections: usize,
    /// Connections in `Closed` state.
    pub closed_connections: usize,
    /// Total messages received.
    pub total_rx: u64,
    /// Total messages sent.
    pub total_tx: u64,
}

// ---------------------------------------------------------------------------
// BPF message boundary parser (stub)
// ---------------------------------------------------------------------------

/// Parsed message boundary returned by a BPF program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfMsgBoundary {
    /// Byte offset from the start of the stream to the end of the message.
    pub end_offset: u32,
    /// Number of header bytes to strip (e.g. length prefix).
    pub header_len: u32,
}

/// Stub BPF message parser.
///
/// In a real kernel, the BPF verifier loads and JIT-compiles the program.
/// Here we provide a fixed-header parser for testing.
///
/// The default policy: first 4 bytes = big-endian u32 message length.
/// Returns the total frame size (4 header bytes + payload).
pub fn bpf_parse_msg(data: &[u8]) -> Option<BpfMsgBoundary> {
    if data.len() < 4 {
        return None; // need more data
    }
    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let total = (4u64 + len as u64).min(u32::MAX as u64) as u32;
    if data.len() < total as usize {
        return None; // incomplete message
    }
    Some(BpfMsgBoundary {
        end_offset: total,
        header_len: 4,
    })
}

// ---------------------------------------------------------------------------
// KcmSocket — user-facing socket descriptor
// ---------------------------------------------------------------------------

/// The type of a KCM socket descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KcmSocketType {
    /// Primary mux socket (created by `socket(AF_KCM, SOCK_DGRAM, 0)`).
    Mux,
    /// Clone socket (created via `SIOCKCMCLONE`).
    Clone,
}

/// A KCM socket handle.
///
/// Multiple sockets may reference the same [`KcmMux`] pool.
#[derive(Debug)]
pub struct KcmSocket {
    /// Socket type.
    pub kind: KcmSocketType,
    /// File descriptor number for this socket.
    pub fd: i32,
    /// Whether the socket is in non-blocking mode.
    pub nonblocking: bool,
}

impl KcmSocket {
    /// Create a new KCM mux socket.
    pub const fn new_mux(fd: i32) -> Self {
        Self {
            kind: KcmSocketType::Mux,
            fd,
            nonblocking: false,
        }
    }

    /// Create a clone socket.
    pub const fn new_clone(fd: i32) -> Self {
        Self {
            kind: KcmSocketType::Clone,
            fd,
            nonblocking: false,
        }
    }

    /// Set non-blocking mode.
    pub fn set_nonblocking(&mut self, nonblocking: bool) {
        self.nonblocking = nonblocking;
    }
}

// ---------------------------------------------------------------------------
// do_kcm_attach / do_kcm_detach — ioctl handlers
// ---------------------------------------------------------------------------

/// Handle `SIOCKCMATTACH` ioctl.
///
/// Validates the arguments and attaches `attach.fd` (a TCP socket) to `mux`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `tcp_fd` already attached or negative.
/// - [`Error::OutOfMemory`]     — Connection pool is full.
pub fn do_kcm_attach(mux: &mut KcmMux, attach: &KcmAttach) -> Result<()> {
    mux.attach(attach)
}

/// Handle `SIOCKCMUNATTACH` ioctl.
///
/// Detaches `attach.fd` from `mux`. The TCP connection is not closed.
///
/// # Errors
///
/// - [`Error::NotFound`] — `tcp_fd` is not attached to the mux.
pub fn do_kcm_unattach(mux: &mut KcmMux, tcp_fd: i32) -> Result<()> {
    mux.detach(tcp_fd)
}

// ---------------------------------------------------------------------------
// do_kcm_sendmsg / do_kcm_recvmsg
// ---------------------------------------------------------------------------

/// Handle a `sendmsg(2)` on a KCM socket.
///
/// Selects a TCP connection via round-robin and records the send.
///
/// # Arguments
///
/// - `mux`     — The KCM mux.
/// - `msg_len` — Length of the message to send.
///
/// # Returns
///
/// The number of bytes sent (= `msg_len`).
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — Zero length or exceeds [`KCM_MAX_MSG_SIZE`].
/// - [`Error::NotFound`]        — No available TCP connection.
pub fn do_kcm_sendmsg(mux: &mut KcmMux, msg_len: usize) -> Result<usize> {
    mux.send_msg(msg_len)?;
    Ok(msg_len)
}

/// Handle a `recvmsg(2)` on a KCM socket.
///
/// In the real kernel, this dequeues a completed message from the receive
/// queue (assembled from the TCP stream by the BPF parser).
///
/// # Arguments
///
/// - `mux`      — The KCM mux.
/// - `conn_idx` — Connection index the message arrived on.
/// - `msg_len`  — Length of the received message.
///
/// # Returns
///
/// A [`KcmMessage`] descriptor describing the received message.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — Bad `conn_idx` or `msg_len`.
/// - [`Error::NotFound`]        — No connection at `conn_idx` or connection closed.
pub fn do_kcm_recvmsg(mux: &mut KcmMux, conn_idx: usize, msg_len: u32) -> Result<KcmMessage> {
    mux.recv_msg(conn_idx, msg_len)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn attach(fd: i32) -> KcmAttach {
        KcmAttach { fd, bpf_fd: 0 }
    }

    fn attach_bpf(fd: i32, bpf_fd: i32) -> KcmAttach {
        KcmAttach { fd, bpf_fd }
    }

    // --- attach / detach ---

    #[test]
    fn attach_single_connection() {
        let mut mux = KcmMux::new();
        do_kcm_attach(&mut mux, &attach(10)).unwrap();
        assert_eq!(mux.connection_count(), 1);
        assert!(mux.get_connection(10).is_some());
    }

    #[test]
    fn attach_multiple_connections() {
        let mut mux = KcmMux::new();
        for fd in 1..=5 {
            do_kcm_attach(&mut mux, &attach(fd)).unwrap();
        }
        assert_eq!(mux.connection_count(), 5);
    }

    #[test]
    fn attach_negative_fd_fails() {
        let mut mux = KcmMux::new();
        assert_eq!(
            do_kcm_attach(&mut mux, &attach(-1)),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn attach_duplicate_fd_fails() {
        let mut mux = KcmMux::new();
        do_kcm_attach(&mut mux, &attach(5)).unwrap();
        assert_eq!(
            do_kcm_attach(&mut mux, &attach(5)),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn detach_existing_connection() {
        let mut mux = KcmMux::new();
        do_kcm_attach(&mut mux, &attach(7)).unwrap();
        do_kcm_unattach(&mut mux, 7).unwrap();
        assert_eq!(mux.connection_count(), 0);
        assert!(mux.get_connection(7).is_none());
    }

    #[test]
    fn detach_non_existent_fails() {
        let mut mux = KcmMux::new();
        assert_eq!(do_kcm_unattach(&mut mux, 42), Err(Error::NotFound));
    }

    // --- framing mode ---

    #[test]
    fn attach_bpf_framing() {
        let mut mux = KcmMux::new();
        do_kcm_attach(&mut mux, &attach_bpf(3, 9)).unwrap();
        let conn = mux.get_connection(3).unwrap();
        assert_eq!(conn.framing, FramingMode::Bpf(9));
    }

    #[test]
    fn attach_length_prefix_framing_default() {
        let mut mux = KcmMux::new();
        do_kcm_attach(&mut mux, &attach(4)).unwrap();
        let conn = mux.get_connection(4).unwrap();
        assert_eq!(conn.framing, FramingMode::LengthPrefix);
    }

    // --- sendmsg ---

    #[test]
    fn sendmsg_basic() {
        let mut mux = KcmMux::new();
        do_kcm_attach(&mut mux, &attach(10)).unwrap();
        let sent = do_kcm_sendmsg(&mut mux, 256).unwrap();
        assert_eq!(sent, 256);
        assert_eq!(mux.total_tx, 1);
    }

    #[test]
    fn sendmsg_round_robin() {
        let mut mux = KcmMux::new();
        for fd in 1..=3 {
            do_kcm_attach(&mut mux, &attach(fd)).unwrap();
        }
        // Three sends should use each of the three connections.
        let mut used = alloc::vec![0usize; KCM_MAX_CONNECTIONS];
        for _ in 0..3 {
            let idx = mux.find_send_connection().unwrap();
            used[idx] += 1;
        }
        // Each connection used exactly once.
        let active: alloc::vec::Vec<usize> = used.iter().copied().filter(|&c| c > 0).collect();
        assert_eq!(active.len(), 3);
        for c in &active {
            assert_eq!(*c, 1);
        }
    }

    #[test]
    fn sendmsg_zero_len_fails() {
        let mut mux = KcmMux::new();
        do_kcm_attach(&mut mux, &attach(1)).unwrap();
        assert_eq!(do_kcm_sendmsg(&mut mux, 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn sendmsg_too_large_fails() {
        let mut mux = KcmMux::new();
        do_kcm_attach(&mut mux, &attach(1)).unwrap();
        assert_eq!(
            do_kcm_sendmsg(&mut mux, KCM_MAX_MSG_SIZE + 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn sendmsg_no_connections_fails() {
        let mut mux = KcmMux::new();
        assert_eq!(do_kcm_sendmsg(&mut mux, 64), Err(Error::NotFound));
    }

    // --- recvmsg ---

    #[test]
    fn recvmsg_basic() {
        let mut mux = KcmMux::new();
        do_kcm_attach(&mut mux, &attach(5)).unwrap();
        let msg = do_kcm_recvmsg(&mut mux, 0, 512).unwrap();
        assert_eq!(msg.len, 512);
        assert!(msg.eor);
        assert_eq!(mux.total_rx, 1);
    }

    #[test]
    fn recvmsg_invalid_conn_idx_fails() {
        let mut mux = KcmMux::new();
        assert_eq!(
            do_kcm_recvmsg(&mut mux, KCM_MAX_CONNECTIONS, 64),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn recvmsg_empty_slot_fails() {
        let mut mux = KcmMux::new();
        assert_eq!(do_kcm_recvmsg(&mut mux, 1, 64), Err(Error::NotFound));
    }

    #[test]
    fn recvmsg_closed_connection_fails() {
        let mut mux = KcmMux::new();
        do_kcm_attach(&mut mux, &attach(6)).unwrap();
        mux.close_connection(6).unwrap();
        assert_eq!(do_kcm_recvmsg(&mut mux, 0, 100), Err(Error::NotFound));
    }

    // --- drain ---

    #[test]
    fn drain_removes_from_round_robin() {
        let mut mux = KcmMux::new();
        do_kcm_attach(&mut mux, &attach(1)).unwrap();
        do_kcm_attach(&mut mux, &attach(2)).unwrap();
        mux.drain_connection(1).unwrap();
        // Only fd=2 is available.
        let idx = mux.find_send_connection().unwrap();
        let conn = mux.connections[idx].as_ref().unwrap();
        assert_eq!(conn.tcp_fd, 2);
    }

    // --- stats ---

    #[test]
    fn stats_reflect_state() {
        let mut mux = KcmMux::new();
        do_kcm_attach(&mut mux, &attach(1)).unwrap();
        do_kcm_attach(&mut mux, &attach(2)).unwrap();
        do_kcm_attach(&mut mux, &attach(3)).unwrap();
        mux.drain_connection(2).unwrap();
        mux.close_connection(3).unwrap();
        do_kcm_sendmsg(&mut mux, 100).unwrap();

        let s = mux.stats();
        assert_eq!(s.total_connections, 3);
        assert_eq!(s.available_connections, 1);
        assert_eq!(s.draining_connections, 1);
        assert_eq!(s.closed_connections, 1);
        assert_eq!(s.total_tx, 1);
    }

    // --- BPF parser ---

    #[test]
    fn bpf_parse_complete_message() {
        // 4-byte big-endian length = 8, followed by 8 payload bytes.
        let mut data = alloc::vec![0u8; 12];
        data[0..4].copy_from_slice(&8u32.to_be_bytes());
        let boundary = bpf_parse_msg(&data).unwrap();
        assert_eq!(boundary.end_offset, 12);
        assert_eq!(boundary.header_len, 4);
    }

    #[test]
    fn bpf_parse_incomplete_header() {
        let data = [0u8; 3]; // not enough for 4-byte length
        assert!(bpf_parse_msg(&data).is_none());
    }

    #[test]
    fn bpf_parse_incomplete_payload() {
        let mut data = alloc::vec![0u8; 5]; // header + 1 byte of payload
        data[0..4].copy_from_slice(&100u32.to_be_bytes()); // expects 100 bytes
        assert!(bpf_parse_msg(&data).is_none());
    }

    // --- KcmSocket ---

    #[test]
    fn kcm_socket_mux_type() {
        let s = KcmSocket::new_mux(10);
        assert_eq!(s.kind, KcmSocketType::Mux);
        assert!(!s.nonblocking);
    }

    #[test]
    fn kcm_socket_clone_type() {
        let s = KcmSocket::new_clone(11);
        assert_eq!(s.kind, KcmSocketType::Clone);
    }

    #[test]
    fn kcm_socket_set_nonblocking() {
        let mut s = KcmSocket::new_mux(12);
        s.set_nonblocking(true);
        assert!(s.nonblocking);
    }
}
