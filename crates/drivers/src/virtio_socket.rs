// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Virtio vsock transport driver.
//!
//! Implements the virtio socket device (vsock) per the
//! VirtIO specification v1.2, section 5.10.  Provides a
//! connection-oriented AF_VSOCK communication channel between
//! the guest and host (or peer VMs).
//!
//! # Architecture
//!
//! - `VsockPacket` — wire-format header for vsock messages.
//! - `VirtqPair` — RX / TX virtqueue pair per socket.
//! - `VsockDevice` — top-level device managing connections.
//! - `VsockConnection` — per-connection state machine.

extern crate alloc;
use alloc::vec::Vec;

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Virtio device ID for vsock.
pub const VIRTIO_ID_VSOCK: u32 = 19;

/// Context ID of the host.
pub const VMADDR_CID_HOST: u64 = 2;

/// Any CID (wildcard for bind).
pub const VMADDR_CID_ANY: u64 = u64::MAX;

/// Maximum number of simultaneous vsock connections.
const MAX_CONNECTIONS: usize = 32;

/// Maximum packet payload size (64 KiB).
const MAX_PAYLOAD: u32 = 65536;

/// Virtqueue index: receive queue.
const VQ_RX: usize = 0;
/// Virtqueue index: transmit queue.
const VQ_TX: usize = 1;
/// Virtqueue index: event queue.
const VQ_EVENT: usize = 2;

// ── VSOCK_OP types ───────────────────────────────────────────────────────────

/// Vsock operation codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum VsockOp {
    /// Invalid (not used).
    Invalid = 0,
    /// Request a new connection.
    Request = 1,
    /// Response to a connection request (accepted).
    Response = 2,
    /// Reset / reject connection.
    Rst = 3,
    /// Graceful shutdown.
    Shutdown = 4,
    /// Data payload.
    Rw = 5,
    /// Credit update (flow control).
    CreditUpdate = 6,
    /// Credit request.
    CreditRequest = 7,
}

impl VsockOp {
    /// Decode from a raw u16 value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] for unknown opcodes.
    pub fn from_raw(v: u16) -> Result<Self> {
        match v {
            1 => Ok(Self::Request),
            2 => Ok(Self::Response),
            3 => Ok(Self::Rst),
            4 => Ok(Self::Shutdown),
            5 => Ok(Self::Rw),
            6 => Ok(Self::CreditUpdate),
            7 => Ok(Self::CreditRequest),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ── Socket type ──────────────────────────────────────────────────────────────

/// Vsock socket type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum VsockType {
    /// Stream (connection-oriented, reliable, ordered).
    Stream = 1,
    /// SeqPacket (connection-oriented, reliable, message-based).
    SeqPacket = 2,
}

// ── VsockPacket ──────────────────────────────────────────────────────────────

/// Vsock wire-format packet header (44 bytes, little-endian).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct VsockPacket {
    /// Source context ID (CID).
    pub src_cid: u64,
    /// Destination context ID.
    pub dst_cid: u64,
    /// Source port number.
    pub src_port: u32,
    /// Destination port number.
    pub dst_port: u32,
    /// Data length in bytes (payload follows the header).
    pub len: u32,
    /// Socket type (`VsockType` encoded as u16).
    pub socket_type: u16,
    /// Operation code (`VsockOp` encoded as u16).
    pub op: u16,
    /// Flags (e.g. SHUTDOWN_RCV=1, SHUTDOWN_SEND=2).
    pub flags: u32,
    /// Peer's receive buffer size (flow control).
    pub buf_alloc: u32,
    /// Peer's forwarded receive data (credit used).
    pub fwd_cnt: u32,
}

impl VsockPacket {
    /// Create a new zeroed packet header.
    pub const fn new() -> Self {
        Self {
            src_cid: 0,
            dst_cid: 0,
            src_port: 0,
            dst_port: 0,
            len: 0,
            socket_type: VsockType::Stream as u16,
            op: VsockOp::Invalid as u16,
            flags: 0,
            buf_alloc: 0,
            fwd_cnt: 0,
        }
    }

    /// Build a connection-request packet.
    pub fn connect(
        src_cid: u64,
        src_port: u32,
        dst_cid: u64,
        dst_port: u32,
        buf_alloc: u32,
    ) -> Self {
        Self {
            src_cid,
            dst_cid,
            src_port,
            dst_port,
            len: 0,
            socket_type: VsockType::Stream as u16,
            op: VsockOp::Request as u16,
            flags: 0,
            buf_alloc,
            fwd_cnt: 0,
        }
    }

    /// Build a data-write packet.
    pub fn data(
        src_cid: u64,
        src_port: u32,
        dst_cid: u64,
        dst_port: u32,
        len: u32,
        fwd_cnt: u32,
    ) -> Self {
        Self {
            src_cid,
            dst_cid,
            src_port,
            dst_port,
            len,
            socket_type: VsockType::Stream as u16,
            op: VsockOp::Rw as u16,
            flags: 0,
            buf_alloc: MAX_PAYLOAD,
            fwd_cnt,
        }
    }

    /// Build a RST packet.
    pub fn rst(src_cid: u64, src_port: u32, dst_cid: u64, dst_port: u32) -> Self {
        Self {
            src_cid,
            dst_cid,
            src_port,
            dst_port,
            len: 0,
            socket_type: VsockType::Stream as u16,
            op: VsockOp::Rst as u16,
            flags: 0,
            buf_alloc: 0,
            fwd_cnt: 0,
        }
    }

    /// Size of the header in bytes.
    pub const fn header_size() -> usize {
        core::mem::size_of::<Self>()
    }
}

// ── Connection state ──────────────────────────────────────────────────────────

/// Per-connection state in the vsock state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnState {
    /// Slot is free.
    Free,
    /// Local side initiated a connection (sent REQUEST).
    Connecting,
    /// Connection established (received RESPONSE or sent RESPONSE).
    Connected,
    /// Local side sent SHUTDOWN; awaiting peer RST.
    ShuttingDown,
    /// Connection closed.
    Closed,
    /// Connection awaiting incoming accept.
    Listening,
}

/// A single vsock connection.
#[derive(Debug, Clone, Copy)]
pub struct VsockConnection {
    /// Local CID.
    pub local_cid: u64,
    /// Remote CID.
    pub remote_cid: u64,
    /// Local port.
    pub local_port: u32,
    /// Remote port.
    pub remote_port: u32,
    /// Connection state.
    pub state: ConnState,
    /// Our receive buffer allocation.
    pub buf_alloc: u32,
    /// Data forwarded to remote (credit used by remote).
    pub fwd_cnt: u32,
    /// Peer's buffer allocation.
    pub peer_buf_alloc: u32,
    /// Peer's forwarded count.
    pub peer_fwd_cnt: u32,
}

impl VsockConnection {
    /// Create an empty (free) connection slot.
    pub const fn new() -> Self {
        Self {
            local_cid: 0,
            remote_cid: 0,
            local_port: 0,
            remote_port: 0,
            state: ConnState::Free,
            buf_alloc: MAX_PAYLOAD,
            fwd_cnt: 0,
            peer_buf_alloc: 0,
            peer_fwd_cnt: 0,
        }
    }

    /// Return the number of bytes the peer can still send us.
    pub fn peer_credit(&self) -> u32 {
        self.buf_alloc
            .saturating_sub(self.fwd_cnt.wrapping_sub(self.peer_fwd_cnt))
    }
}

impl Default for VsockConnection {
    fn default() -> Self {
        Self::new()
    }
}

// ── VirtqPair ────────────────────────────────────────────────────────────────

/// Simulated virtqueue pair (RX / TX) for vsock.
///
/// In a full implementation this would interface with the virtio
/// ring shared with the hypervisor via DMA-mapped memory.
#[derive(Debug, Default)]
pub struct VirtqPair {
    /// Index of this queue pair.
    pub index: u16,
    /// Pending outgoing packets (simulated TX ring).
    pub tx_pending: Vec<VsockPacket>,
    /// Received packets not yet delivered (simulated RX ring).
    pub rx_ready: Vec<VsockPacket>,
}

impl VirtqPair {
    /// Create a new virtqueue pair.
    pub fn new(index: u16) -> Self {
        Self {
            index,
            tx_pending: Vec::new(),
            rx_ready: Vec::new(),
        }
    }

    /// Enqueue a packet for transmission.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the TX ring is full (>256 pending).
    pub fn enqueue_tx(&mut self, pkt: VsockPacket) -> Result<()> {
        if self.tx_pending.len() >= 256 {
            return Err(Error::OutOfMemory);
        }
        self.tx_pending.push(pkt);
        Ok(())
    }

    /// Dequeue a received packet from the RX ring.
    ///
    /// Returns `None` if no packet is ready.
    pub fn dequeue_rx(&mut self) -> Option<VsockPacket> {
        if self.rx_ready.is_empty() {
            None
        } else {
            Some(self.rx_ready.remove(0))
        }
    }

    /// Inject a received packet into the RX ring (used by the interrupt handler).
    pub fn inject_rx(&mut self, pkt: VsockPacket) {
        self.rx_ready.push(pkt);
    }

    /// Drain all pending TX packets.
    pub fn flush_tx(&mut self) -> Vec<VsockPacket> {
        let mut drained = Vec::new();
        core::mem::swap(&mut self.tx_pending, &mut drained);
        drained
    }
}

// ── VsockDevice ──────────────────────────────────────────────────────────────

/// Virtio vsock device.
pub struct VsockDevice {
    /// Guest context ID (CID).
    pub guest_cid: u64,
    /// Virtqueue pairs: RX, TX, event.
    pub vqs: [Option<VirtqPair>; 3],
    /// Active connections.
    connections: [VsockConnection; MAX_CONNECTIONS],
    /// Number of active connections.
    conn_count: usize,
}

impl VsockDevice {
    /// Create an uninitialised vsock device.
    pub const fn new() -> Self {
        Self {
            guest_cid: 0,
            vqs: [const { None }; 3],
            connections: [const { VsockConnection::new() }; MAX_CONNECTIONS],
            conn_count: 0,
        }
    }

    /// Initialise the vsock device with the given guest CID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `guest_cid` is 0.
    pub fn init(&mut self, guest_cid: u64) -> Result<()> {
        if guest_cid == 0 {
            return Err(Error::InvalidArgument);
        }
        self.guest_cid = guest_cid;
        self.vqs[VQ_RX] = Some(VirtqPair::new(VQ_RX as u16));
        self.vqs[VQ_TX] = Some(VirtqPair::new(VQ_TX as u16));
        self.vqs[VQ_EVENT] = Some(VirtqPair::new(VQ_EVENT as u16));
        Ok(())
    }

    /// Open a new connection to `dst_cid:dst_port`.
    ///
    /// Returns the connection index on success.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if no connection slots remain.
    /// - [`Error::InvalidArgument`] if the device is not initialised.
    pub fn connect(&mut self, dst_cid: u64, dst_port: u32, local_port: u32) -> Result<usize> {
        if self.guest_cid == 0 {
            return Err(Error::InvalidArgument);
        }
        let slot = self.alloc_conn_slot().ok_or(Error::OutOfMemory)?;
        self.connections[slot] = VsockConnection {
            local_cid: self.guest_cid,
            remote_cid: dst_cid,
            local_port,
            remote_port: dst_port,
            state: ConnState::Connecting,
            buf_alloc: MAX_PAYLOAD,
            fwd_cnt: 0,
            peer_buf_alloc: 0,
            peer_fwd_cnt: 0,
        };
        self.conn_count += 1;

        let pkt = VsockPacket::connect(self.guest_cid, local_port, dst_cid, dst_port, MAX_PAYLOAD);
        self.enqueue_tx(pkt)?;

        Ok(slot)
    }

    /// Begin listening on `local_port` for incoming connections.
    ///
    /// Returns the connection slot index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if no slots remain.
    pub fn listen(&mut self, local_port: u32) -> Result<usize> {
        let slot = self.alloc_conn_slot().ok_or(Error::OutOfMemory)?;
        self.connections[slot] = VsockConnection {
            local_cid: self.guest_cid,
            remote_cid: VMADDR_CID_ANY,
            local_port,
            remote_port: 0,
            state: ConnState::Listening,
            buf_alloc: MAX_PAYLOAD,
            fwd_cnt: 0,
            peer_buf_alloc: 0,
            peer_fwd_cnt: 0,
        };
        self.conn_count += 1;
        Ok(slot)
    }

    /// Process a received packet from the RX virtqueue.
    ///
    /// Updates connection state machines.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] for unrecognised opcodes.
    pub fn recv_packet(&mut self, pkt: VsockPacket) -> Result<()> {
        let op = VsockOp::from_raw(pkt.op)?;
        // Find matching connection.
        for i in 0..MAX_CONNECTIONS {
            let conn = &mut self.connections[i];
            if conn.state == ConnState::Free {
                continue;
            }
            if conn.local_port == pkt.dst_port
                && conn.remote_cid == pkt.src_cid
                && (conn.remote_port == pkt.src_port || conn.state == ConnState::Listening)
            {
                match op {
                    VsockOp::Response => {
                        if conn.state == ConnState::Connecting {
                            conn.state = ConnState::Connected;
                            conn.peer_buf_alloc = pkt.buf_alloc;
                            conn.peer_fwd_cnt = pkt.fwd_cnt;
                        }
                    }
                    VsockOp::Request => {
                        if conn.state == ConnState::Listening {
                            conn.remote_cid = pkt.src_cid;
                            conn.remote_port = pkt.src_port;
                            conn.state = ConnState::Connected;
                            conn.peer_buf_alloc = pkt.buf_alloc;
                            // Send RESPONSE.
                            let resp = VsockPacket {
                                src_cid: self.guest_cid,
                                dst_cid: pkt.src_cid,
                                src_port: pkt.dst_port,
                                dst_port: pkt.src_port,
                                len: 0,
                                socket_type: VsockType::Stream as u16,
                                op: VsockOp::Response as u16,
                                flags: 0,
                                buf_alloc: MAX_PAYLOAD,
                                fwd_cnt: 0,
                            };
                            self.enqueue_tx(resp)?;
                        }
                    }
                    VsockOp::Rst | VsockOp::Shutdown => {
                        conn.state = ConnState::Closed;
                    }
                    VsockOp::CreditUpdate => {
                        conn.peer_buf_alloc = pkt.buf_alloc;
                        conn.peer_fwd_cnt = pkt.fwd_cnt;
                    }
                    _ => {}
                }
                return Ok(());
            }
        }
        // Unmatched packet — send RST.
        let rst = VsockPacket::rst(self.guest_cid, pkt.dst_port, pkt.src_cid, pkt.src_port);
        self.enqueue_tx(rst)?;
        Ok(())
    }

    /// Return a reference to connection slot `index`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if index is out of range.
    pub fn connection(&self, index: usize) -> Result<&VsockConnection> {
        if index >= MAX_CONNECTIONS {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.connections[index])
    }

    /// Return the number of active connections.
    pub fn conn_count(&self) -> usize {
        self.conn_count
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    fn alloc_conn_slot(&self) -> Option<usize> {
        for i in 0..MAX_CONNECTIONS {
            if self.connections[i].state == ConnState::Free {
                return Some(i);
            }
        }
        None
    }

    fn enqueue_tx(&mut self, pkt: VsockPacket) -> Result<()> {
        let vq = self.vqs[VQ_TX].as_mut().ok_or(Error::InvalidArgument)?;
        vq.enqueue_tx(pkt)
    }
}

impl Default for VsockDevice {
    fn default() -> Self {
        Self::new()
    }
}
