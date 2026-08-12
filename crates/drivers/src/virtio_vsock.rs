// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Virtio vsock VM sockets driver.
//!
//! Implements the virtio-vsock device as specified in the VirtIO 1.2
//! specification (Section 5.10). AF_VSOCK allows bidirectional, connection-
//! oriented communication between a guest virtual machine and its host
//! hypervisor (and optionally between guest VMs on the same host).
//!
//! # Architecture
//!
//! - **Guest CID** — 32-bit Context Identifier assigned by the hypervisor.
//!   The host is always CID 2; the guest is assigned CID ≥ 3.
//! - **Virtqueues** — three queues:
//!   - **RX (queue 0)** — host-to-guest data packets.
//!   - **TX (queue 1)** — guest-to-host data packets.
//!   - **Event (queue 2)** — transport events (e.g., credit updates).
//! - **Packet header** — `VsockPacketHeader` precedes all payload bytes.
//! - **Credit flow control** — each side advertises buffer space so the
//!   peer knows how much data it may send.
//!
//! # Connection State Machine
//!
//! ```text
//! CLOSED → LISTEN → SYN_SENT → ESTABLISHED → CLOSING → CLOSED
//!                 ↑                        ↓
//!              SYN_RECV ────────────────────
//! ```
//!
//! # Supported Operations
//!
//! - Send/receive connection requests (CONNECT/RESPONSE)
//! - Data transfer (RW packets)
//! - Graceful teardown (SHUTDOWN/RST)
//! - Credit update packets for flow control
//!
//! Reference: VirtIO 1.2 Specification §5.10.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Virtqueue index for RX (host→guest) traffic.
const VQ_RX: usize = 0;
/// Virtqueue index for TX (guest→host) traffic.
const VQ_TX: usize = 1;
/// Virtqueue index for transport events.
const VQ_EVENT: usize = 2;

/// Number of virtqueues.
const NUM_VQS: usize = 3;

/// Vsock packet header size in bytes.
pub const VSOCK_PKT_HDR_SIZE: usize = 44;

/// Maximum number of simultaneous vsock connections.
const MAX_CONNECTIONS: usize = 64;

/// Maximum number of vsock devices.
const MAX_VSOCK_DEVICES: usize = 2;

/// Receive virtqueue depth (number of descriptors).
const RX_QUEUE_SIZE: u16 = 128;

/// Transmit virtqueue depth.
const TX_QUEUE_SIZE: u16 = 128;

/// Event virtqueue depth.
const EVENT_QUEUE_SIZE: u16 = 8;

/// Maximum payload size per packet (64 KiB - 1).
pub const VSOCK_MAX_PKT_DATA: u32 = 65_535;

/// Host CID (always 2).
pub const VSOCK_HOST_CID: u64 = 2;

/// Maximum number of simultaneously bound local ports.
const MAX_BOUND_PORTS: usize = 32;

/// Sane upper bound for the peer credit window (4 MiB).
///
/// Even if the host advertises a larger `buf_alloc`, we cap the credit
/// we extend at this value so that a malicious host cannot trick the
/// driver into sending unbounded data.
const MAX_CREDIT_WINDOW: u32 = 4 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Vsock Packet Types (op field)
// ---------------------------------------------------------------------------

/// Packet type: Invalid / unset.
pub const VSOCK_OP_INVALID: u16 = 0;
/// Packet type: Payload data.
pub const VSOCK_OP_RW: u16 = 1;
/// Packet type: Connection request.
pub const VSOCK_OP_REQUEST: u16 = 2;
/// Packet type: Connection response (accept).
pub const VSOCK_OP_RESPONSE: u16 = 3;
/// Packet type: Reset connection.
pub const VSOCK_OP_RST: u16 = 4;
/// Packet type: Shutdown half of a connection.
pub const VSOCK_OP_SHUTDOWN: u16 = 5;
/// Packet type: Credit update (flow control).
pub const VSOCK_OP_CREDIT_UPDATE: u16 = 6;
/// Packet type: Credit request.
pub const VSOCK_OP_CREDIT_REQUEST: u16 = 7;

// ---------------------------------------------------------------------------
// Vsock Packet Type (transport type field)
// ---------------------------------------------------------------------------

/// Transport type: stream (SOCK_STREAM).
pub const VSOCK_TYPE_STREAM: u16 = 1;
/// Transport type: seqpacket (SOCK_SEQPACKET).
pub const VSOCK_TYPE_SEQPACKET: u16 = 2;

// ---------------------------------------------------------------------------
// Shutdown flags
// ---------------------------------------------------------------------------

/// Shutdown receive (RCV_SHUTDOWN).
pub const VSOCK_SHUTDOWN_RCV: u32 = 1;
/// Shutdown send (SEND_SHUTDOWN).
pub const VSOCK_SHUTDOWN_SEND: u32 = 2;

// ---------------------------------------------------------------------------
// VirtIO feature bits relevant to vsock
// ---------------------------------------------------------------------------

/// Feature bit: VIRTIO_VSOCK_F_SEQPACKET (seqpacket support).
const _VIRTIO_VSOCK_F_SEQPACKET: u32 = 1;

// ---------------------------------------------------------------------------
// Vsock Packet Header
// ---------------------------------------------------------------------------

/// Vsock packet header as transmitted on the virtqueue.
///
/// All fields are little-endian. The header immediately precedes any payload.
///
/// `packed` is load-bearing: virtio-vsock defines this header as exactly 44
/// wire bytes, but the two leading `u64`s give plain `repr(C)` an alignment of
/// 8, which rounds the size up to 48. Any descriptor length or payload offset
/// derived from `size_of` would then be 4 bytes past the real header, shifting
/// every field the device reads. `packet_header_size` guards the invariant.
#[derive(Clone, Copy, Default)]
#[repr(C, packed)]
pub struct VsockPacketHeader {
    /// Source context ID (sender's CID).
    pub src_cid: u64,
    /// Destination context ID (receiver's CID).
    pub dst_cid: u64,
    /// Source port number.
    pub src_port: u32,
    /// Destination port number.
    pub dst_port: u32,
    /// Length of the data payload that follows this header (bytes).
    pub data_len: u32,
    /// Transport type: `VSOCK_TYPE_STREAM` or `VSOCK_TYPE_SEQPACKET`.
    pub vsock_type: u16,
    /// Operation code (e.g., `VSOCK_OP_RW`).
    pub op: u16,
    /// Flags (e.g., shutdown bits).
    pub flags: u32,
    /// Buffer allocation advertised by sender (bytes available for receive).
    pub buf_alloc: u32,
    /// Forward credit: number of bytes consumed since last credit update.
    pub fwd_cnt: u32,
}

// ---------------------------------------------------------------------------
// Connection state
// ---------------------------------------------------------------------------

/// States of a vsock connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnectionState {
    /// Not connected.
    #[default]
    Closed,
    /// Listening for incoming connections.
    Listen,
    /// SYN sent, waiting for RESPONSE.
    SynSent,
    /// SYN received, sending RESPONSE.
    SynRecv,
    /// Connection established, data may flow.
    Established,
    /// Shutdown initiated, waiting for peer to close.
    Closing,
}

// ---------------------------------------------------------------------------
// VsockConnection
// ---------------------------------------------------------------------------

/// A single vsock connection entry.
#[derive(Debug, Clone, Copy, Default)]
pub struct VsockConnection {
    /// Connection state.
    pub state: ConnectionState,
    /// Local CID (this guest's CID).
    pub local_cid: u64,
    /// Peer CID.
    pub peer_cid: u64,
    /// Local port number.
    pub local_port: u32,
    /// Peer port number.
    pub peer_port: u32,
    /// Transport type.
    pub vsock_type: u16,
    /// Our receive buffer allocation.
    pub buf_alloc: u32,
    /// Bytes forwarded to us since last credit update (wraps per spec).
    pub fwd_cnt: u32,
    /// Peer's advertised buffer allocation (capped to `MAX_CREDIT_WINDOW`).
    pub peer_buf_alloc: u32,
    /// Peer's forward count (wraps per spec).
    pub peer_fwd_cnt: u32,
}

impl VsockConnection {
    /// Returns the number of bytes we may still send to the peer.
    ///
    /// The VirtIO vsock spec uses wrapping u32 arithmetic for the protocol
    /// counters. The *in-flight* byte count is `peer_fwd_cnt` subtracted from
    /// our own `fwd_cnt` using wrapping semantics, capped to the peer's
    /// advertised window. We additionally clamp `peer_buf_alloc` to
    /// `MAX_CREDIT_WINDOW` so a malicious host cannot grant unbounded credit.
    pub fn peer_credit(&self) -> u32 {
        // Clamp the peer window to our self-imposed maximum so a host
        // advertising a huge buf_alloc cannot trick us into over-sending.
        let window = self.peer_buf_alloc.min(MAX_CREDIT_WINDOW);
        // in_flight = bytes sent by us but not yet acknowledged by peer.
        // Both counters wrap per protocol; saturating_sub prevents underflow
        // when the wrapping difference exceeds the window.
        let in_flight = self.fwd_cnt.wrapping_sub(self.peer_fwd_cnt);
        window.saturating_sub(in_flight)
    }

    /// Returns `true` if the connection is in an active data-transfer state.
    pub fn is_established(&self) -> bool {
        self.state == ConnectionState::Established
    }
}

// ---------------------------------------------------------------------------
// Virtqueue descriptor (minimal representation)
// ---------------------------------------------------------------------------

/// Minimal virtqueue descriptor for driver use.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct VirtqDesc {
    /// Guest-physical address of the buffer.
    pub addr: u64,
    /// Length of the buffer in bytes.
    pub len: u32,
    /// Flags: NEXT (1), WRITE (2), INDIRECT (4).
    pub flags: u16,
    /// Next descriptor index (valid if NEXT flag set).
    pub next: u16,
}

/// Virtqueue descriptor flag: chain continues in `next`.
pub const VRING_DESC_F_NEXT: u16 = 1;
/// Virtqueue descriptor flag: device writes to this buffer (write-only).
pub const VRING_DESC_F_WRITE: u16 = 2;

// ---------------------------------------------------------------------------
// Virtqueue state (simplified)
// ---------------------------------------------------------------------------

/// Tracks basic virtqueue state.
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtqueueState {
    /// Queue size (number of descriptors).
    pub size: u16,
    /// Last used index seen by the driver.
    pub last_used_idx: u16,
    /// Available ring index (next entry to write).
    pub avail_idx: u16,
}

impl VirtqueueState {
    /// Creates a new state for a queue of the given size.
    pub const fn new(size: u16) -> Self {
        Self {
            size,
            last_used_idx: 0,
            avail_idx: 0,
        }
    }

    /// Returns `true` if there are unconsumed used entries.
    pub fn has_used_entries(&self, used_idx: u16) -> bool {
        self.last_used_idx != used_idx
    }
}

// ---------------------------------------------------------------------------
// VirtioVsock Device
// ---------------------------------------------------------------------------

/// Driver for the virtio-vsock device.
pub struct VirtioVsock {
    /// MMIO base address of the virtio device control registers.
    mmio_base: u64,
    /// Guest Context ID assigned by the hypervisor.
    guest_cid: u64,
    /// Whether the device has been initialised.
    initialized: bool,
    /// Virtqueue states indexed by `VQ_*` constants.
    vqs: [VirtqueueState; NUM_VQS],
    /// Connection table.
    connections: [VsockConnection; MAX_CONNECTIONS],
    /// Number of active connections (includes Closed slots that have been
    /// compacted; see `free_connection`).
    connection_count: usize,
    /// Set of local ports that have been explicitly bound (have a listener).
    bound_ports: [u32; MAX_BOUND_PORTS],
    /// Number of entries in `bound_ports`.
    bound_port_count: usize,
}

impl VirtioVsock {
    /// Creates a new (uninitialised) vsock driver.
    ///
    /// `mmio_base` is the guest-physical address of the virtio MMIO region.
    pub const fn new(mmio_base: u64) -> Self {
        Self {
            mmio_base,
            guest_cid: 0,
            initialized: false,
            vqs: [
                VirtqueueState::new(RX_QUEUE_SIZE),
                VirtqueueState::new(TX_QUEUE_SIZE),
                VirtqueueState::new(EVENT_QUEUE_SIZE),
            ],
            connections: [const {
                VsockConnection {
                    state: ConnectionState::Closed,
                    local_cid: 0,
                    peer_cid: 0,
                    local_port: 0,
                    peer_port: 0,
                    vsock_type: VSOCK_TYPE_STREAM,
                    buf_alloc: 0,
                    fwd_cnt: 0,
                    peer_buf_alloc: 0,
                    peer_fwd_cnt: 0,
                }
            }; MAX_CONNECTIONS],
            connection_count: 0,
            bound_ports: [0u32; MAX_BOUND_PORTS],
            bound_port_count: 0,
        }
    }

    /// Initialises the vsock device.
    ///
    /// Reads the guest CID from the device configuration space, negotiates
    /// features, and sets up the virtqueues.
    pub fn init(&mut self) -> Result<()> {
        // Read guest CID from device config (offset 0 in vsock config space).
        self.guest_cid = self.read_config_u64(0);
        if self.guest_cid < 3 {
            // CID 0 = any, 1 = loopback, 2 = host. Guest must be ≥ 3.
            return Err(Error::InvalidArgument);
        }

        // Acknowledge device and driver feature negotiation (simplified).
        self.write_mmio32(0x014, 0); // VIRTIO_MMIO_DRIVER_FEATURES = 0 (no extras)
        self.write_mmio32(0x00C, 0x0F); // VIRTIO_STATUS: ACKNOWLEDGE|DRIVER|FEATURES_OK|DRIVER_OK

        self.initialized = true;
        Ok(())
    }

    /// Returns the guest CID.
    pub fn guest_cid(&self) -> u64 {
        self.guest_cid
    }

    /// Binds a local port so that inbound `VSOCK_OP_REQUEST` packets targeting
    /// that port will be accepted.
    ///
    /// Returns `Error::AlreadyExists` if the port is already bound, or
    /// `Error::OutOfMemory` if the bound-port table is full.
    pub fn bind(&mut self, local_port: u32) -> Result<()> {
        for i in 0..self.bound_port_count {
            if self.bound_ports[i] == local_port {
                return Err(Error::AlreadyExists);
            }
        }
        if self.bound_port_count >= MAX_BOUND_PORTS {
            return Err(Error::OutOfMemory);
        }
        self.bound_ports[self.bound_port_count] = local_port;
        self.bound_port_count += 1;
        Ok(())
    }

    /// Unbinds a previously bound local port.
    ///
    /// Returns `Error::NotFound` if the port was not bound.
    pub fn unbind(&mut self, local_port: u32) -> Result<()> {
        for i in 0..self.bound_port_count {
            if self.bound_ports[i] == local_port {
                // Swap-remove to keep the array compact.
                let last = self.bound_port_count - 1;
                self.bound_ports[i] = self.bound_ports[last];
                self.bound_port_count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Initiates an outgoing connection to (`peer_cid`, `peer_port`) from
    /// `local_port`.
    ///
    /// Sends a `VSOCK_OP_REQUEST` packet and records the connection as
    /// `SynSent`.
    pub fn connect(&mut self, local_port: u32, peer_cid: u64, peer_port: u32) -> Result<usize> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        if self.connection_count >= MAX_CONNECTIONS {
            return Err(Error::OutOfMemory);
        }
        // Ensure no duplicate (local_port, peer_cid, peer_port).
        for i in 0..self.connection_count {
            let c = &self.connections[i];
            if c.local_port == local_port
                && c.peer_cid == peer_cid
                && c.peer_port == peer_port
                && c.state != ConnectionState::Closed
            {
                return Err(Error::AlreadyExists);
            }
        }
        let idx = self.connection_count;
        self.connections[idx] = VsockConnection {
            state: ConnectionState::SynSent,
            local_cid: self.guest_cid,
            peer_cid,
            local_port,
            peer_port,
            vsock_type: VSOCK_TYPE_STREAM,
            buf_alloc: 65536,
            fwd_cnt: 0,
            peer_buf_alloc: 0,
            peer_fwd_cnt: 0,
        };
        self.connection_count += 1;

        // Build and send REQUEST packet.
        let hdr = self.build_header(
            local_port,
            peer_cid,
            peer_port,
            VSOCK_OP_REQUEST,
            VSOCK_TYPE_STREAM,
            0,
            0,
        );
        self.transmit_header(&hdr)?;
        Ok(idx)
    }

    /// Processes an incoming packet header received on the RX queue.
    ///
    /// `received_payload_len` is the number of payload bytes actually present
    /// in the DMA buffer for this descriptor (i.e., the descriptor length minus
    /// the header size). It is used to bound the `data_len` field supplied by
    /// the host so that an over-large value cannot cause an OOB copy.
    ///
    /// Updates connection state and returns a description of what happened.
    pub fn receive_packet(
        &mut self,
        hdr: &VsockPacketHeader,
        received_payload_len: u32,
    ) -> Result<RxAction> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        match hdr.op {
            VSOCK_OP_REQUEST => self.handle_request(hdr),
            VSOCK_OP_RESPONSE => self.handle_response(hdr),
            VSOCK_OP_RST => self.handle_rst(hdr),
            VSOCK_OP_SHUTDOWN => self.handle_shutdown(hdr),
            VSOCK_OP_RW => self.handle_rw(hdr, received_payload_len),
            VSOCK_OP_CREDIT_UPDATE => self.handle_credit_update(hdr),
            VSOCK_OP_CREDIT_REQUEST => self.handle_credit_request(hdr),
            _ => Ok(RxAction::Unknown),
        }
    }

    /// Sends `data_len` bytes of application payload on connection `conn_idx`.
    ///
    /// The caller is responsible for supplying the physical address of the
    /// buffer via `buf_phys`. This method only transmits the header; DMA
    /// chaining of the payload is left to the virtqueue layer.
    pub fn send(&mut self, conn_idx: usize, data_len: u32) -> Result<VsockPacketHeader> {
        if conn_idx >= self.connection_count {
            return Err(Error::NotFound);
        }
        let conn = &self.connections[conn_idx];
        if conn.state != ConnectionState::Established {
            return Err(Error::IoError);
        }
        if data_len > conn.peer_credit() {
            return Err(Error::WouldBlock);
        }
        let hdr = self.build_header(
            conn.local_port,
            conn.peer_cid,
            conn.peer_port,
            VSOCK_OP_RW,
            conn.vsock_type,
            data_len,
            0,
        );
        self.transmit_header(&hdr)?;
        Ok(hdr)
    }

    /// Closes the connection at `conn_idx` by sending a SHUTDOWN then RST.
    pub fn close(&mut self, conn_idx: usize) -> Result<()> {
        if conn_idx >= self.connection_count {
            return Err(Error::NotFound);
        }
        {
            let conn = &self.connections[conn_idx];
            let hdr = self.build_header(
                conn.local_port,
                conn.peer_cid,
                conn.peer_port,
                VSOCK_OP_SHUTDOWN,
                conn.vsock_type,
                0,
                VSOCK_SHUTDOWN_RCV | VSOCK_SHUTDOWN_SEND,
            );
            self.transmit_header(&hdr)?;
        }
        self.connections[conn_idx].state = ConnectionState::Closing;
        // Tear down the slot so the table slot can be reused.
        self.free_connection(conn_idx);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Private: packet handlers
    // -----------------------------------------------------------------------

    fn handle_request(&mut self, hdr: &VsockPacketHeader) -> Result<RxAction> {
        // Only accept a REQUEST whose destination port has a bound listener.
        // An unbound port gets an immediate RST rather than a silent connection.
        if !self.is_port_bound(hdr.dst_port) {
            let rst = self.build_header(
                hdr.dst_port,
                hdr.src_cid,
                hdr.src_port,
                VSOCK_OP_RST,
                hdr.vsock_type,
                0,
                0,
            );
            self.transmit_header(&rst)?;
            return Ok(RxAction::Rejected);
        }

        if self.connection_count >= MAX_CONNECTIONS {
            // Send RST: no room.
            let rst = self.build_header(
                hdr.dst_port,
                hdr.src_cid,
                hdr.src_port,
                VSOCK_OP_RST,
                hdr.vsock_type,
                0,
                0,
            );
            self.transmit_header(&rst)?;
            return Ok(RxAction::Rejected);
        }
        let idx = self.connection_count;
        self.connections[idx] = VsockConnection {
            state: ConnectionState::SynRecv,
            local_cid: self.guest_cid,
            peer_cid: hdr.src_cid,
            local_port: hdr.dst_port,
            peer_port: hdr.src_port,
            vsock_type: hdr.vsock_type,
            buf_alloc: 65536,
            fwd_cnt: 0,
            // Cap incoming peer credit advertisement to our self-imposed window.
            peer_buf_alloc: hdr.buf_alloc.min(MAX_CREDIT_WINDOW),
            peer_fwd_cnt: hdr.fwd_cnt,
        };
        self.connection_count += 1;
        // Send RESPONSE to accept.
        let resp = self.build_header(
            hdr.dst_port,
            hdr.src_cid,
            hdr.src_port,
            VSOCK_OP_RESPONSE,
            hdr.vsock_type,
            0,
            0,
        );
        self.transmit_header(&resp)?;
        self.connections[idx].state = ConnectionState::Established;
        Ok(RxAction::NewConnection(idx))
    }

    fn handle_response(&mut self, hdr: &VsockPacketHeader) -> Result<RxAction> {
        let conn_idx = self.find_connection(hdr.dst_port, hdr.src_cid, hdr.src_port)?;
        let conn = &mut self.connections[conn_idx];
        if conn.state != ConnectionState::SynSent {
            return Ok(RxAction::Unknown);
        }
        conn.state = ConnectionState::Established;
        // Cap the peer's advertised credit to our self-imposed window.
        conn.peer_buf_alloc = hdr.buf_alloc.min(MAX_CREDIT_WINDOW);
        conn.peer_fwd_cnt = hdr.fwd_cnt;
        Ok(RxAction::Connected(conn_idx))
    }

    fn handle_rst(&mut self, hdr: &VsockPacketHeader) -> Result<RxAction> {
        let conn_idx = self
            .find_connection(hdr.dst_port, hdr.src_cid, hdr.src_port)
            .unwrap_or(usize::MAX);
        if conn_idx < self.connection_count {
            // Free the slot so the table can be reused; this also decrements
            // connection_count, preventing the host from exhausting the table.
            self.free_connection(conn_idx);
        }
        Ok(RxAction::Reset(conn_idx))
    }

    fn handle_shutdown(&mut self, hdr: &VsockPacketHeader) -> Result<RxAction> {
        let conn_idx = self.find_connection(hdr.dst_port, hdr.src_cid, hdr.src_port)?;
        self.connections[conn_idx].state = ConnectionState::Closing;
        // Acknowledge with RST.
        let rst = {
            let conn = &self.connections[conn_idx];
            self.build_header(
                conn.local_port,
                conn.peer_cid,
                conn.peer_port,
                VSOCK_OP_RST,
                conn.vsock_type,
                0,
                0,
            )
        };
        self.transmit_header(&rst)?;
        // Free the slot so it can be reused.
        self.free_connection(conn_idx);
        Ok(RxAction::Disconnected(conn_idx))
    }

    /// Handles an inbound RW (data) packet.
    ///
    /// `received_payload_len` is the actual number of payload bytes in the
    /// DMA buffer (descriptor length minus header). The host-supplied
    /// `hdr.data_len` is clamped to this value and to `VSOCK_MAX_PKT_DATA`
    /// before being forwarded to callers, preventing OOB copies.
    fn handle_rw(
        &mut self,
        hdr: &VsockPacketHeader,
        received_payload_len: u32,
    ) -> Result<RxAction> {
        let conn_idx = self.find_connection(hdr.dst_port, hdr.src_cid, hdr.src_port)?;

        // Clamp data_len to:
        //   1. The protocol maximum (VSOCK_MAX_PKT_DATA).
        //   2. The actual payload bytes present in the descriptor buffer.
        // A host lying about data_len (larger than the buffer) would otherwise
        // cause an OOB read in the copy path.
        let safe_data_len = hdr
            .data_len
            .min(VSOCK_MAX_PKT_DATA)
            .min(received_payload_len);

        let conn = &mut self.connections[conn_idx];
        // fwd_cnt is a wrapping protocol counter (intentional per spec).
        conn.fwd_cnt = conn.fwd_cnt.wrapping_add(safe_data_len);
        // Cap incoming peer credit advertisement.
        conn.peer_buf_alloc = hdr.buf_alloc.min(MAX_CREDIT_WINDOW);
        conn.peer_fwd_cnt = hdr.fwd_cnt;
        Ok(RxAction::Data {
            conn_idx,
            data_len: safe_data_len,
        })
    }

    fn handle_credit_update(&mut self, hdr: &VsockPacketHeader) -> Result<RxAction> {
        let conn_idx = self.find_connection(hdr.dst_port, hdr.src_cid, hdr.src_port)?;
        let conn = &mut self.connections[conn_idx];
        // Cap incoming peer credit advertisement.
        conn.peer_buf_alloc = hdr.buf_alloc.min(MAX_CREDIT_WINDOW);
        conn.peer_fwd_cnt = hdr.fwd_cnt;
        Ok(RxAction::CreditUpdate(conn_idx))
    }

    fn handle_credit_request(&mut self, hdr: &VsockPacketHeader) -> Result<RxAction> {
        let conn_idx = self.find_connection(hdr.dst_port, hdr.src_cid, hdr.src_port)?;
        let update = {
            let conn = &self.connections[conn_idx];
            self.build_header(
                conn.local_port,
                conn.peer_cid,
                conn.peer_port,
                VSOCK_OP_CREDIT_UPDATE,
                conn.vsock_type,
                0,
                0,
            )
        };
        self.transmit_header(&update)?;
        Ok(RxAction::CreditUpdate(conn_idx))
    }

    // -----------------------------------------------------------------------
    // Private: helpers
    // -----------------------------------------------------------------------

    fn find_connection(&self, local_port: u32, peer_cid: u64, peer_port: u32) -> Result<usize> {
        for i in 0..self.connection_count {
            let c = &self.connections[i];
            if c.local_port == local_port
                && c.peer_cid == peer_cid
                && c.peer_port == peer_port
                && c.state != ConnectionState::Closed
            {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }

    /// Returns `true` if `port` has been explicitly bound via [`bind`].
    fn is_port_bound(&self, port: u32) -> bool {
        for i in 0..self.bound_port_count {
            if self.bound_ports[i] == port {
                return true;
            }
        }
        false
    }

    /// Frees a connection slot by swap-removing it and decrementing the count.
    ///
    /// This keeps the active connection array compact so `find_connection`
    /// always scans only live entries and RST/close cannot exhaust the table.
    fn free_connection(&mut self, idx: usize) {
        if idx >= self.connection_count {
            return;
        }
        self.connections[idx].state = ConnectionState::Closed;
        let last = self.connection_count.saturating_sub(1);
        if idx != last {
            self.connections[idx] = self.connections[last];
        }
        self.connections[last] = VsockConnection {
            state: ConnectionState::Closed,
            local_cid: 0,
            peer_cid: 0,
            local_port: 0,
            peer_port: 0,
            vsock_type: VSOCK_TYPE_STREAM,
            buf_alloc: 0,
            fwd_cnt: 0,
            peer_buf_alloc: 0,
            peer_fwd_cnt: 0,
        };
        self.connection_count = last;
    }

    fn build_header(
        &self,
        local_port: u32,
        peer_cid: u64,
        peer_port: u32,
        op: u16,
        vsock_type: u16,
        data_len: u32,
        flags: u32,
    ) -> VsockPacketHeader {
        VsockPacketHeader {
            src_cid: self.guest_cid,
            dst_cid: peer_cid,
            src_port: local_port,
            dst_port: peer_port,
            data_len,
            vsock_type,
            op,
            flags,
            buf_alloc: 65536,
            fwd_cnt: 0,
        }
    }

    /// Writes a packet header to the TX virtqueue.
    ///
    /// In a real driver this would chain a virtqueue descriptor and kick
    /// the device; here we write to the MMIO queue notify register.
    fn transmit_header(&self, _hdr: &VsockPacketHeader) -> Result<()> {
        // Kick TX queue.
        self.write_mmio32(0x050, VQ_TX as u32);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Private: MMIO accessors
    // -----------------------------------------------------------------------

    /// Reads a 32-bit MMIO register at `offset` from the device base.
    fn read_mmio32(&self, offset: u64) -> u32 {
        let addr = (self.mmio_base + offset) as *const u32;
        // SAFETY: `addr` is a valid MMIO address within the device's BAR,
        // verified during device discovery. Volatile read prevents elision.
        unsafe { core::ptr::read_volatile(addr) }
    }

    /// Writes a 32-bit value to an MMIO register.
    fn write_mmio32(&self, offset: u64, value: u32) {
        let addr = (self.mmio_base + offset) as *mut u32;
        // SAFETY: Same rationale as `read_mmio32`.
        unsafe { core::ptr::write_volatile(addr, value) }
    }

    /// Reads a 64-bit value from the device configuration space.
    fn read_config_u64(&self, offset: u64) -> u64 {
        // Virtio MMIO config space starts at offset 0x100.
        let lo = self.read_mmio32(0x100 + offset) as u64;
        let hi = self.read_mmio32(0x100 + offset + 4) as u64;
        lo | (hi << 32)
    }
}

// ---------------------------------------------------------------------------
// RxAction
// ---------------------------------------------------------------------------

/// Describes the outcome of processing a received vsock packet.
#[derive(Debug, Clone, Copy)]
pub enum RxAction {
    /// A new inbound connection was accepted; connection index returned.
    NewConnection(usize),
    /// An outbound connection was accepted by the peer.
    Connected(usize),
    /// Data received; includes connection index and payload length.
    ///
    /// `data_len` is the validated, clamped payload size — it is safe to use
    /// as a copy length against the descriptor buffer.
    Data { conn_idx: usize, data_len: u32 },
    /// Peer reset the connection.
    Reset(usize),
    /// Connection was gracefully closed.
    Disconnected(usize),
    /// Credit update received.
    CreditUpdate(usize),
    /// Incoming connection was rejected (no room or no listener).
    Rejected,
    /// Unknown or unhandled packet type.
    Unknown,
}

// ---------------------------------------------------------------------------
// Device registry
// ---------------------------------------------------------------------------

/// Registry of virtio-vsock devices.
pub struct VsockRegistry {
    devices: [VirtioVsock; MAX_VSOCK_DEVICES],
    count: usize,
}

impl VsockRegistry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            devices: [const { VirtioVsock::new(0) }; MAX_VSOCK_DEVICES],
            count: 0,
        }
    }

    /// Registers a vsock device at `mmio_base` and initialises it.
    pub fn register(&mut self, mmio_base: u64) -> Result<usize> {
        if self.count >= MAX_VSOCK_DEVICES {
            return Err(Error::OutOfMemory);
        }
        let mut dev = VirtioVsock::new(mmio_base);
        dev.init()?;
        let idx = self.count;
        self.devices[idx] = dev;
        self.count += 1;
        Ok(idx)
    }

    /// Returns a mutable reference to the device at `index`.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut VirtioVsock> {
        if index < self.count {
            Some(&mut self.devices[index])
        } else {
            None
        }
    }

    /// Returns the number of registered devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no devices are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for VsockRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Queue index constants (re-exported for callers)
// ---------------------------------------------------------------------------

/// VQ_RX constant re-export.
pub const VSOCK_VQ_RX: usize = VQ_RX;
/// VQ_TX constant re-export.
pub const VSOCK_VQ_TX: usize = VQ_TX;
/// VQ_EVENT constant re-export.
pub const VSOCK_VQ_EVENT: usize = VQ_EVENT;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Owned, 4-byte-aligned stand-in for the device's MMIO window.
    ///
    /// `VirtioVsock::new(0)` with a hand-set `initialized` is a state `init()`
    /// never produces. Any path that reaches `transmit_header` then writes the
    /// TX doorbell at address `0x050` and takes down the whole test binary with
    /// a SIGSEGV, taking every other test in the crate with it. Point
    /// `mmio_base` at real memory instead of the null page.
    struct FakeMmio {
        words: [u32; 1024],
    }

    impl FakeMmio {
        fn new() -> Self {
            Self { words: [0; 1024] }
        }

        fn base(&mut self) -> u64 {
            self.words.as_mut_ptr() as u64
        }
    }

    #[test]
    fn packet_header_size() {
        assert_eq!(
            core::mem::size_of::<VsockPacketHeader>(),
            VSOCK_PKT_HDR_SIZE
        );
    }

    #[test]
    fn vsock_registry_empty() {
        let reg = VsockRegistry::new();
        assert!(reg.is_empty());
    }

    #[test]
    fn connection_peer_credit_zero() {
        let conn = VsockConnection::default();
        assert_eq!(conn.peer_credit(), 0);
    }

    #[test]
    fn connection_not_established_by_default() {
        let conn = VsockConnection::default();
        assert!(!conn.is_established());
    }

    #[test]
    fn virtqueue_state_new() {
        let vq = VirtqueueState::new(128);
        assert_eq!(vq.size, 128);
        assert!(!vq.has_used_entries(0));
        assert!(vq.has_used_entries(1));
    }

    /// A host advertising an enormous buf_alloc must not exceed MAX_CREDIT_WINDOW.
    #[test]
    fn peer_credit_clamped_to_max_window() {
        let mut conn = VsockConnection::default();
        conn.peer_buf_alloc = u32::MAX;
        conn.peer_fwd_cnt = 0;
        conn.fwd_cnt = 0;
        assert_eq!(conn.peer_credit(), MAX_CREDIT_WINDOW);
    }

    /// If in_flight equals the window, credit must be zero.
    #[test]
    fn peer_credit_zero_when_window_full() {
        let mut conn = VsockConnection::default();
        conn.peer_buf_alloc = 1024;
        conn.peer_fwd_cnt = 0;
        conn.fwd_cnt = 1024; // we sent 1024 bytes not yet acked
        assert_eq!(conn.peer_credit(), 0);
    }

    /// Wrapping in_flight must not grant negative (unbounded) credit.
    #[test]
    fn peer_credit_no_wrap_grant() {
        let mut conn = VsockConnection::default();
        conn.peer_buf_alloc = 512;
        conn.peer_fwd_cnt = 100;
        // fwd_cnt < peer_fwd_cnt would make wrapping_sub large; credit = 0.
        conn.fwd_cnt = 50;
        // in_flight = 50u32.wrapping_sub(100) = u32::MAX - 49, >> window → 0
        assert_eq!(conn.peer_credit(), 0);
    }

    /// Free-connection must decrement connection_count.
    #[test]
    fn free_connection_decrements_count() {
        let mut dev = VirtioVsock::new(0);
        dev.connection_count = 1;
        dev.connections[0] = VsockConnection {
            state: ConnectionState::Established,
            local_port: 1000,
            peer_cid: 2,
            peer_port: 2000,
            ..VsockConnection::default()
        };
        dev.free_connection(0);
        assert_eq!(dev.connection_count, 0);
    }

    /// handle_rw must clamp data_len to received_payload_len.
    #[test]
    fn handle_rw_clamps_data_len() {
        let mut dev = VirtioVsock::new(0);
        dev.initialized = true;
        dev.guest_cid = 3;
        // Manually insert an established connection.
        dev.connections[0] = VsockConnection {
            state: ConnectionState::Established,
            local_cid: 3,
            peer_cid: 2,
            local_port: 5000,
            peer_port: 1234,
            vsock_type: VSOCK_TYPE_STREAM,
            buf_alloc: 65536,
            fwd_cnt: 0,
            peer_buf_alloc: 65536,
            peer_fwd_cnt: 0,
        };
        dev.connection_count = 1;

        let hdr = VsockPacketHeader {
            src_cid: 2,
            dst_cid: 3,
            src_port: 1234,
            dst_port: 5000,
            data_len: 9000, // host lies: claims 9000 bytes
            vsock_type: VSOCK_TYPE_STREAM,
            op: VSOCK_OP_RW,
            flags: 0,
            buf_alloc: 65536,
            fwd_cnt: 0,
        };
        // Only 256 bytes are actually in the buffer.
        let result = dev.receive_packet(&hdr, 256);
        match result {
            Ok(RxAction::Data { data_len, .. }) => {
                assert_eq!(
                    data_len, 256,
                    "data_len must be clamped to received_payload_len"
                );
            }
            other => panic!("unexpected result: {:?}", other),
        }
    }

    /// handle_request must reject packets for unbound ports.
    #[test]
    fn handle_request_rejects_unbound_port() {
        let mut mmio = FakeMmio::new();
        let mut dev = VirtioVsock::new(mmio.base());
        dev.initialized = true;
        dev.guest_cid = 3;

        let hdr = VsockPacketHeader {
            src_cid: 2,
            dst_cid: 3,
            src_port: 9999,
            dst_port: 8080, // not bound
            data_len: 0,
            vsock_type: VSOCK_TYPE_STREAM,
            op: VSOCK_OP_REQUEST,
            flags: 0,
            buf_alloc: 65536,
            fwd_cnt: 0,
        };
        let result = dev.receive_packet(&hdr, 0);
        assert!(
            matches!(result, Ok(RxAction::Rejected)),
            "unbound port must be rejected"
        );
        assert_eq!(dev.connection_count, 0, "no connection must be created");
    }

    /// After binding a port, handle_request must accept the connection.
    #[test]
    fn handle_request_accepts_bound_port() {
        let mut mmio = FakeMmio::new();
        let mut dev = VirtioVsock::new(mmio.base());
        dev.initialized = true;
        dev.guest_cid = 3;
        dev.bind(8080).unwrap();

        let hdr = VsockPacketHeader {
            src_cid: 2,
            dst_cid: 3,
            src_port: 9999,
            dst_port: 8080,
            data_len: 0,
            vsock_type: VSOCK_TYPE_STREAM,
            op: VSOCK_OP_REQUEST,
            flags: 0,
            buf_alloc: 65536,
            fwd_cnt: 0,
        };
        let result = dev.receive_packet(&hdr, 0);
        assert!(
            matches!(result, Ok(RxAction::NewConnection(_))),
            "bound port must be accepted"
        );
        assert_eq!(dev.connection_count, 1);
    }
}
